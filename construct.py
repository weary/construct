import argparse
import json
import socket
import logging
import re
import time
import traceback
import base64
import hashlib
import os
from collections import defaultdict
from functools import wraps
from copy import copy

from construct_database import ConstructDatabase
from construct_consts import \
		guestlevel, registeredlevel, confirmedlevel, operlevel, \
		banrole, allowrole, operrole

log = logging.getLogger('construct')

# FIXME: Should keep profiles/roles in database
# FIXME: Think of a secure way to keep user-registrations acros restarts

pingre = re.compile("PING :(.*)".replace(' ', '\s+'))
passre = re.compile("PASS (\S+) TS.*".replace(' ', '\s+'))
serverre = re.compile("SERVER (\S+) 1 :(.*)".replace(' ', '\s+'))
killre = re.compile(":\S+ KILL (\S+) :(.*)".replace(' ', '\s+'))

nickre = re.compile("NICK (\S+) \d+ \d+ \+[a-z]* \S* \S* \S* :.*".replace(' ', '\s+'))
nickchangere = re.compile(":(\S+) NICK (\S+) :\d+".replace(' ', '\s+'))
sjoinre = re.compile(':\S+ SJOIN \d+ (#\S+) \+[a-z]* :(.*)'.replace(' ', '\s+'))
partre = re.compile(':(\S+) PART (\S+)'.replace(' ', '\s+'))
kickre = re.compile(':\S+ KICK (\S+) (\S+) :(.*)'.replace(' ', '\s+'))
#modere = re.compile(":\S+ MODE .*".replace(' ', '\s+'))
modere = re.compile(':\S+ MODE (\S+) ([-+]\S+) (\S+)'.replace(' ', '\s+'))
quitre = re.compile(":(\S+) QUIT :(.*)".replace(' ', '\s+'))
privmsgre = re.compile(":(\S+) PRIVMSG (\S+) :(.*)".replace(' ', '\s+'))

def level_as_text(level):
	if level is guestlevel:
		return "guest"
	elif level is registeredlevel:
		return "registered"
	elif level is confirmedlevel:
		return "confirmed"
	elif level is operlevel:
		return "server operator"
	else:
		assert False

def role_as_text(role):
	if role is banrole:
		return "banned"
	elif role is allowrole:
		return "allowed"
	elif role is operrole:
		return "oper"
	else:
		assert False

def capitalize(msg):
	return msg[:1].upper() + msg[1:]

def sort(container):
	c = copy(container)
	c.sort()
	return c

# helper taken from pietbot
# maak lijst gescheiden door ,'s, behalve tussen laatste 2 items, waar "en" komt
def make_list(items, sep="en"):
  items = list(items)
  if not(items):
    return ""
  elif len(items) == 1:
    return items[0]
  
  prefix = items[:-1]
  postfix = items[-1]
  return ", ".join(prefix) + " " + sep + " " + postfix


class IrcMsgException(Exception):
	""" an exception that is told to the user """
	def __init__(self, user, msg):
		super(IrcMsgException, self).__init__(
				"IrcMsg(%s, %s)" % (user.nick, msg))
		self.user = user
		self.msg = msg

class OperMsgException(Exception):
	""" an exception that is told to all online server operators """
	def __init__(self, msg):
		super(OperMsgException, self).__init__(
				"OperMsg(%s)" % msg)
		self.msg = msg

class CommandDenied(IrcMsgException):
	""" thrown by construct if user tries to use a
	command he is not supposed to """
	def __init__(self, user, cmd, reason):
		log.info("User '%s' denied command %s: %s" % (
			user.nick, cmd, reason))
		super(CommandDenied, self).__init__(
				user,
				"Access denied to command %s, %s" % (cmd, reason))


class RestartException(Exception):
	""" thrown to force full restart """
	def __init__(self):
		super(RestartException, self).__init__("restart exception")


class ChannelDB(object):
	def __init__(self):
		super(ChannelDB, self).__init__()
		self.channels = dict()  # name -> channel

	def rehash(self):  # re-read registered channels from db
		old = self.channels
		self.channels = dict()

		for name, guests, policy in self.db.get_channels():
			chan = old.pop(name, None)
			if not chan:
				log.info("Rehash: new registered channel: %s" % name)
				chan = Channel(self, name)
			chan.registered = True
			chan.allow_guests = guests
			chan.default_policy_allow = policy
			self.channels[name] = chan

		# other channels are not registered
		for name, chan in old.iteritems():
			if chan.registered:
				log.info("Rehash: channel %s is no longer registered" % name)
				chan.registered = False
			if chan.users:
				self.channels[name] = chan

		roles = defaultdict(dict)
		for chan, profileid, role in self.db.get_roles():
			roles[chan][profileid] = role
		for chan, roledict in roles.iteritems():
			self.channels[chan].roles = roledict

	def get_channel(self, channelname):
		channelname = channelname.lower()
		return self.channels.get(channelname)

	def get_or_create_channel(self, channelname):
		channelname = channelname.lower()
		channel = self.channels.get(channelname)
		if not channel:
			log.info("creating channel %s" % channelname)
			channel = Channel(self, channelname)
			self.channels[channelname] = channel
		return channel

	def get_channels_with_user(self, user):
		return [
				chan for chan in self.channels.values()
				if chan.has_user(user)]

	def channel_empty(self, channel):
		if not channel.registered:
			del self.channels[channel.name]

	def channel_user_quit(self, user):
		# note, this makes a copy of the channels, as 'quit' can make
		# channels disappear
		for chan in self.get_channels_with_user(user):
			if chan.has_user(user):
				chan.quit(user)

	def fix_user_on_all_channels(self, user):
		for chan in self.get_channels_with_user(user):
			if chan.has_user(user):
				chan.fix_user_to_role(user)

	def get_all_channels(self):
		return self.channels.values()


def channel_registered(func):
	@wraps(func)
	def wrapper(self, user, *args):
		if not self.registered:
			raise IrcMsgException(
					user,
					"Channel %s is not registered" % self.name)
		return func(self, user, *args)
	return wrapper


class Channel(object):
	# FIXME: this class should not be case-sensitive
	def __init__(self, parent, name):
		# generic
		self.parent = parent  # the channeldb

		# settings
		self.name = name
		self.registered = False
		self.allow_guests = True
		self.default_policy_allow = True
		self.roles = dict()  # profileid -> role

		# for current run
		self.users = dict()  # user->mode

	def register(self):
		self.registered = True
		self.parent.db.create_channel(
				self.name, self.allow_guests, self.default_policy_allow)

	def unregister(self):
		if not self.registered:
			return

		self.registered = False
		self.parent.db.delete_channel(self.name)
		if not self.users:
			self.parent.channel_empty(self)

	def has_user(self, user):
		return user in self.users

	def usercount(self):
		return len(self.users)

	@channel_registered
	def set_allow_guests(self, oper, allow_):
		self.allow_guests = allow_
		self.parent.db.update_channel(
				self.name, self.allow_guests, self.default_policy_allow)

	@channel_registered
	def set_policy(self, oper, newpolicy):
		if newpolicy.lower() == "allow":
			self.default_policy_allow = True
		elif newpolicy.lower() == "deny":
			self.default_policy_allow = False
		else:
			raise IrcMsgException(
					oper,
					"Invalid channel policy '%s'" % newpolicy)
		self.parent.db.update_channel(
				self.name, self.allow_guests, self.default_policy_allow)

	@channel_registered
	def set_role(self, oper, profile, role):
		if not profile:
			raise IrcMsgException(oper, "Guest users cannot have roles, must register first")
		if role:
			is_new = profile.profileid in self.roles
			self.roles[profile.profileid] = role
			if is_new:
				self.parent.db.create_role(self.name, profile.profileid, role)
			else:
				self.parent.db.update_role(self.name, profile.profileid, role)
		else:
			del self.roles[profile.profileid]
			self.parent.db.delete_role(self.name, profile.profileid)

	def del_role(self, oper, profile):
		self.set_role(oper, profile, None)

	@channel_registered
	def get_roles(self, oper):
		out = []
		for profileid, role in self.roles.iteritems():
			profile = self.parent.find_profile_by_id(profileid)
			out.append((profile, role))

		return out

	@channel_registered
	def get_role_for_profile(self, profile):
		r = self.roles.get(profile.profileid)
		return r

	def fix_all_users(self):
		users = list(self.users)
		for user in users:
			self.fix_user_to_role(user)

	def fix_user_to_role(self, user):
		print "fixing %s on %s" % (user.nick, self.name)
		print "known users:", ", ".join(u.nick for u in self.users)
		# check if a user (who is currently in the channel) is
		# allowed and has the right mode. And correct if wrong

		if not self.registered:
			print "fixing - not registered"
			return  # not doing anything for channels nobody cares about

		if not self.allow_guests and not user.profile:
			print "fixing - guests not allowed"
			self.remove_user(user, "guests not allowed")

		role = self.find_role(user)
		mode = self.users.get(user)
		if mode is None:
			print "fixing - user not in channel"
			return

		print "fixing - role =", role_as_text(role), ", mode =", mode
		if role is banrole:
			self.remove_user(user, "user not allowed")
		elif role is allowrole:
			if 'o' in mode:
				self.deop_user(user)
		elif role is operrole:
			if not 'o' in mode:
				self.op_user(user)

	def find_role(self, user, defaultrole=None):
		assert self.registered

		if defaultrole is None:
			if self.default_policy_allow == True:
				defaultrole = allowrole
			else:
				defaultrole = banrole

		profile = user.profile
		if not profile:
			print "find_role - no profile -> default"
			return defaultrole

		# server-operator overides all
		if profile.level is operlevel:
			return operrole

		role = self.roles.get(profile.profileid)
		if not role:
			return defaultrole
		return role

	def is_channel_operator(self, user):
		return self.find_role(user) is operrole

	def join(self, user, initial_mode):
		if user in self.users:
			log.warn("User %s was already joined to channel %s" % (
				user.nick, self.name))
			return
		self.users[user] = initial_mode
		log.debug("%s: %s joined: %s" % (
			self.name, user.nick, ', '.join(u.nick for u in self.users)))

		self.fix_user_to_role(user)
		# FIXME: tell user he should identify or register

	def part(self, user):
		if not user in self.users:
			log.warn("User %s parted but was not on channel %s" % (
				user.nick, self.name))
			return

		del self.users[user]
		log.debug("%s: %s parted: %s" % (
			self.name, user.nick, ', '.join(u.nick for u in self.users)))
		if not self.users:
			self.parent.channel_empty(self)

	def kick(self, user):
		if not user in self.users:
			log.warn("User %s was kicked but was not on channel %s" % (
				user.nick, self.name))
			return

		del self.users[user]
		log.debug("%s: %s kicked: %s" % (
			self.name, user.nick, ', '.join(u.nick for u in self.users)))
		if not self.users:
			self.parent.channel_empty(self)

	def quit(self, user):
		if user in self.users:
			del self.users[user]
			log.debug("%s: %s logged out, leftover: %s" % (
				self.name, user.nick, ', '.join(u.nick for u in self.users)))
		if not self.users:
			self.parent.channel_empty(self)

	def mode(self, user, modechange):
		oldmode = self.users[user]
		if modechange[0] == '-':
			newmode = ''.join(set(oldmode) - set(modechange[1:]))
		elif modechange[0] == '+':
			newmode = ''.join(set(oldmode).union(set(modechange[1:])))
		else:
			raise Exception("Invalid mode-change '%s' for %s on %s" %(
				modechange, user.nick, self.name))
		self.users[user] = newmode

		self.fix_user_to_role(user)

	def op_user(self, user):
		assert self.registered
		log.debug("%s opped %s" % (self.name, user.nick))
		self.send("MODE %s +o %s" % (self.name, user.nick))
		self.mode(user, "+o")

	def deop_user(self, user):
		assert self.registered
		log.debug("%s de-opped %s" % (self.name, user.nick))
		self.send("MODE %s -o %s" % (self.name, user.nick))
		self.mode(user, "-o")

	def remove_user(self, user, reason):
		assert self.registered
		if not user in self.users:
			log.warn("User %s not on channel %s, cannot remove" % (user.nick, self.name))
		log.debug("%s removed %s for %s" % (self.name, user.nick, reason))
		if reason:
			reason = ', ' + reason
		self.send("KICK %s %s :Restricted channel%s" % (self.name, user.nick, reason))
		# FIXME: need temporary ban here, to prevent auto-rejoin
		del self.users[user]

	def send(self, msg):
		self.parent.construct.send(msg)


class Profile(object):
	def __init__(self, parent, id_, nickname, password):
		self.parent = parent
		self.profileid = id_
		self.register_nick = nickname
		self.level = registeredlevel  # if we have a profile we are registered
		self.password = None
		self.last_password_guess_time = 0
		self.realname = None
		self.email = None
		if password[:3] == '$C$':
			self.password = password
		else:
			log.warning("Password for %s was not encrypted. fixing.." % nickname)
			self.reset_password(password)

	@staticmethod
	def getDigest(password, salt=None):
		if not salt:
			salt = base64.b64encode(os.urandom(32))
		digest = hashlib.sha256(salt + password).hexdigest()
		for x in range(0, 100001):
			digest = hashlib.sha256(digest).hexdigest()
		return salt, digest

	def test_password(self, testpass, caller, msg=None):
		""" will throw on invalid password """
		now = time.time()
		timeout = self.parent.password_timeout
		if now - self.last_password_guess_time < timeout:
			raise IrcMsgException(
					caller,
					"Error, wait %s seconds between password guess attempts" % timeout)
		self.last_password_guess_time = now
		assert self.password[:3] == '$C$'
		salt, digest = self.password[3:].split('$', 1)
		if digest != Profile.getDigest(testpass, salt)[1]:
			if msg is None:
				msg = "Error, invalid password for '%s'" % self.register_nick
			raise IrcMsgException(caller, msg)

	def reset_password(self, newpass):
		if newpass[:3] != '$C$':
			newpass = '$C$' + '$'.join(Profile.getDigest(newpass))
		if newpass != self.password:
			self.password = newpass
			self.update_db()

	def confirm(self, realname, email):
		if not self.level is operlevel:
			self.level = confirmedlevel
		self.realname = realname
		self.email = email
		self.update_db()

	def unconfirm(self):
		self.level = registeredlevel
		self.realname = None
		self.email = None
		self.update_db()

	def is_confirmed(self):
		return self.level is operlevel or self.level is confirmedlevel

	def update_db(self):
		self.parent.db.update_profile(
				self.profileid, self.register_nick, self.level, self.password,
				self.realname, self.email)


class ProfileDB(object):
	def __init__(self):
		super(ProfileDB, self).__init__()
		self.profiles = list()
		self.next_id = 1

	def rehash(self):
		old = {p.profileid:p for p in self.profiles}
		self.profiles = list()
		self.next_id = 1
		for id_, nick, lvl, pwd, rn, email in self.db.get_profiles():
			if id_ >= self.next_id:
				self.next_id = id_ + 1
			prof = old.pop(id_, None)
			if not prof:
				log.info("Rehash: new registered profile: %s" % nick)
				prof = Profile(self, id_, nick, pwd)
			prof.register_nick = nick
			prof.level = lvl
			prof.reset_password(pwd)
			prof.realname = rn
			prof.email = email
			self.profiles.append(prof)

		# any profiles lost from database?
		for prof in old.itervalues():
			log.info("Rehash: removed profile %s" % prof.register_nick)
			user = self.server.get_user_for_profile(prof)
			if user:
				log.info("Rehash: user %s unidentified due to lost profile" % user.nick)
				user.unidentify()

	def find_profile_by_nickname(self, nickname):
		nickname = nickname.lower()
		for p in self.profiles:
			if p.register_nick.lower() == nickname:
				return p

		return None

	def find_profile_by_id(self, profileid):
		for p in self.profiles:
			if p.profileid == profileid:
				return p
		return None

	def create_profile(self, nickname, password):
		id_ = self.next_id
		self.next_id += 1
		p = Profile(self, id_, nickname, password)
		self.profiles.append(p)
		self.db.create_profile(
				p.profileid, p.register_nick, p.level, p.password)
		return p

	def drop_profile(self, profile):
		self.profiles = [p for p in self.profiles
				if p != profile]
		self.db.delete_profile(profile.profileid)

	def get_all_profiles(self):
		return self.profiles


class UserDB(object):
	def __init__(self):
		super(UserDB, self).__init__()
		self.users = list()

	def get_user(self, needednick, defaultval=None):
		#print "looking for user '%s', current users: %s" % (
		#		needednick, ', '.join(u.nick for u in self.users))
		needednick = needednick.lower()
		for user in self.users:
			if user.nick.lower() == needednick:
				return user
		return defaultval

	def create_user(self, newnick):
		assert self.get_user(newnick) is None
		user = User(newnick)
		self.users.append(user)
		#print "created user '%s', current users: %s" % (
		#		user.nick, ', '.join(u.nick for u in self.users))
		return user

	def remove_user(self, user):
		self.users.remove(user)
		#print "removed user '%s', current users: %s" % (
		#		nick, ', '.join(u.nick for u in self.users))

	def get_serveropers(self):
		out = []
		for user in self.users:
			profile = user.profile
			if not profile:
				continue
			if profile.level is operlevel:
				out.append(user)
		return out

	def get_user_for_profile(self, profile):
		assert profile
		out = []
		for user in self.users:
			if profile == user.profile:
				out.append(user)
		if not out:
			return None
		assert len(out) == 1
		return out[0]

	def privmsg_serverops(self, msg):
		for user in self.get_serveropers():
			self.construct.privmsg(user, msg)

	def notice_serverops(self, msg):
		for user in self.get_serveropers():
			self.construct.notice(user, msg)

	def kill_user(self, user, reason):
		log.info("User %s killed, %s", user.nick, reason)
		self.send("KILL %s :HOP %s" % (user.nick, reason))
		self.remove_user(user)


class User(object):
	def __init__(self, nick):
		self.nick = nick
		self.profile = None

	def nickchange(self, newnick):
		log.debug("%s nickchanged to %s" % (self.nick, newnick))
		self.nick = newnick

	def identify(self, profile):
		self.profile = profile

	def unidentify(self):
		self.profile = None

	def is_confirmed(self):  # is user at least confirmed
		profile = self.profile
		return profile and profile.is_confirmed()


class Server(UserDB, ChannelDB, ProfileDB):
	def __init__(self, conf):
		super(Server, self).__init__()
		self.name = conf['name']
		if self.name.find('.') < 0:
			raise Exception("server name('%s') must contain a dot" % self.name)
		self.description = conf.get('description', '')
		self.handler = None
		self.construct = None
		self.db = ConstructDatabase("construct.db")
		self.password_timeout = conf.get('password_timeout', 30)

	def rehash(self):
		log.info("Starting rehash")
		ChannelDB.rehash(self)
		ProfileDB.rehash(self)
		for chan in self.get_all_channels():
			chan.fix_all_users()
		log.info("Done rehash")

	def set_handler(self, han):
		self.handler = han

	def set_construct(self, construct):
		self.construct = construct

	def send_server_string(self):
		self.handler.send(
				"SERVER %s 1 :%s" % (
					self.name, self.description))

	def send(self, msg):
		self.handler.send(":%s %s" % (self.name, msg))


class IrcLineConnection(object):
	def __init__(self, host, port):
		self.host = host
		self.port = port
		self.socket = None
		self.writelinecache = ''
		self.readlinecache = []

	def connect(self):
		# FIXME: allow ssl
		self.socket = socket.create_connection(
				(self.host, self.port))

	def disconnect(self):
		self.socket.close()
		self.socket = None

	def write(self, line):
		lines = line
		if self.writelinecache:
			lines = self.writelinecache + line
			self.writelinecache = None

		lines = lines.split('\n')
		self.writelinecache = lines[-1]
		lines = lines[:-1]

		for l in lines:
			log.debug("w: %s" % l)
			self.socket.send(l + '\r\n')

	def __iter__(self):
		return self

	def next(self):
		while len(self.readlinecache) < 2:
			newdata = self.socket.recv(100)
			data = newdata
			if self.readlinecache:
				data = self.readlinecache[0] + newdata

			self.readlinecache = data.split('\n')

			if newdata == '':
				self.readlinecache.append(None)
				self.readlinecache.append(None)

		r = self.readlinecache[0]
		del self.readlinecache[0]
		if r == None:
			raise StopIteration()
		log.debug("r: %s" % r)
		return r


class Handler(object):
	def __init__(
			self,
			server,
			send_password,
			accept_password,
			host, port
			):
		self.con = IrcLineConnection(host, port)
		self.server = server
		server.set_handler(self)
		self.accept_password = accept_password
		self.send_password = send_password
		self.serverstate = None

		self.msgs = (
				(pingre, self.msg_ping),
				(passre, self.msg_pass),
				(serverre, self.msg_server),
				(killre, self.msg_kill),

				(nickre, self.msg_nick),
				(nickchangere, self.msg_nickchange),
				(sjoinre, self.msg_sjoin),
				(partre, self.msg_part),
				(kickre, self.msg_kick),
				(modere, self.msg_mode),
				(quitre, self.msg_quit),
				(privmsgre, self.msg_privmsg)
				)

	def send(self, msg):
		print >>self.con, msg

	def connect(self):
		self.con.connect()
		self.send("PASS %s :TS" % self.send_password)
		self.server.send_server_string()

	def disconnect(self):
		self.con.disconnect()
		self.con = None

	def msg_ping(self, who):
		self.send("PONG :" + who)

	def msg_pass(self, pass_):
		if pass_ != self.accept_password:
			raise Exception("Server sent invalid password")
		if not self.serverstate is None:
			raise Exception("Got pass from server but not expecting")
		self.serverstate = "seen_pass"

	def msg_server(self, name, desc):
		if self.serverstate != "seen_pass":
			raise Exception("Server introduced himself, but haven't seen pass")
		log.info("Connected to %s, %s" % (name, desc))
		self.serverstate = "connected"

	def msg_kill(self, who, reason):
		if who == self.server.construct.nick:
			raise Exception("Server killed our construct: %s" % reason)

	def msg_nick(self, newnick):
		user = self.server.get_user(newnick)
		if user:
			raise OperMsgException(
					"User %s already known" % newnick)
		self.server.create_user(newnick)

	def msg_nickchange(self, oldnick, newnick):
		user = self.server.get_user(oldnick)
		if not user:
			raise OperMsgException(
					"no such user %s" % oldnick)
		user.nickchange(newnick)

	def msg_sjoin(self, channame, nicks):
		chan = self.server.get_or_create_channel(channame)
		for nick in nicks.split():
			mode = ''
			if '@' in nick:
				mode += 'o'
				nick = nick.replace('@', '')
			if '+' in nick:
				mode += 'v'
				nick = nick.replace('+', '')
			user = self.server.get_user(nick)
			if not user:
				raise OperMsgException(
						"joining user %s does not exist" % nick)
			chan.join(user, mode)

	def msg_part(self, nick, channame):
		chan = self.server.get_channel(channame)
		if not chan:
			raise OperMsgException(
					"no such channel '%s' where user %s parts from" % (
						channame, nick))
		user = self.server.get_user(nick)
		if not user:
			raise OperMsgException(
					"parting user %s does not exist" % nick)
		chan.part(user)

	def msg_kick(self, channame, nick, reason):
		chan = self.server.get_channel(channame)
		if not chan:
			raise OperMsgException(
					"no such channel '%s' where user %s is kicked from" % (
						channame, nick))
		user = self.server.get_user(nick)
		if not user:
			raise OperMsgException(
					"parting user %s does not exist" % nick)
		chan.kick(user)

	def msg_mode(self, channame, modechange, nick):
		chan = self.server.get_channel(channame)
		if not chan:
			raise OperMsgException(
					"no such channel '%s' where user %s is mode-changed" % (
						channame, nick))
		user = self.server.get_user(nick)
		if not user:
			raise OperMsgException(
					"mode-change for non-existing user %s" % nick)
		chan.mode(user, modechange)

	def msg_quit(self, who, reason):
		user = self.server.get_user(who)
		self.server.channel_user_quit(user)
		self.server.remove_user(user)

	def msg_privmsg(self, fromnick, tonick, msg):
		construct = self.server.construct
		if tonick == construct.nick:
			user = self.server.get_user(fromnick)
			construct.recv(user, msg)
		else:
			raise IrcMsgException(fromnick, "No such nick, '%s'" % tonick)

	def parse_line(self, line):
		try:
			for reg, func in self.msgs:
				r = reg.match(line)
				if r:
					func(*r.groups())
					return
			raise OperMsgException("Unparsed line: %s" % line)
		except RestartException:
			raise  # pass upwards
		except IrcMsgException, e:
			if e.user:
				self.server.construct.notice(e.user, e.msg)
			else:
				log.warning("Unknown user caused exception: %s" % e.msg)
		except OperMsgException, e:
			log.warning(e.msg)
			self.server.privmsg_serverops(
					"Exception: %s" % e.msg)
		except Exception:
			lines = traceback.format_exc()
			for line in lines.split('\n'):
				log.error(line)
			for line in lines.split('\n'):
				self.server.privmsg_serverops(line)

	def read_all(self):
		# read lines until disconnected
		for line in self.con:
			self.parse_line(line)

	def read_until_server_connect(self):
		for line in self.con:
			self.parse_line(line)
			if self.serverstate == "connected":
				return
		else:
			raise Exception("Lost connection, while connecting")

# decorator
def needs_profile(func):
	@wraps(func)
	def find_profile(self, user, *args):
		profile = user.profile
		if not profile:
			raise IrcMsgException(
					user,
					"No profiles registered for %s, " % user.nick +
					"not identified")
		func(self, user, profile, *args)
	return find_profile

def needs_channel(func):
	@wraps(func)
	def find_channel(self, user, cmd, args):
		chan, rest = self.extract_channel_from_args(user, args)
		func(self, user, chan, cmd, rest)
	return find_channel

def fix_user_on_channels_afterwards(func):
	@wraps(func)
	def fix_user_afterwards_wrapper(self, user, *args):
		func(self, user, *args)
		self.server.fix_user_on_all_channels(user)
	return fix_user_afterwards_wrapper

def no_leftover_arguments(func):
	@wraps(func)
	def no_leftover_arguments_wrap(self, user, *args):
		if args[-1].strip():
			raise IrcMsgException(user, "Invalid extra arguments: %s" % args[-1])
		args = args[:-1]
		func(self, user, *args)
	return no_leftover_arguments_wrap

class Construct(object):
	def __init__(self, server, nick, description):
		self.server = server
		self.nick = nick
		self.description = description

		server.set_construct(self)

		# all chanoper command have a first argument specifying a
		# channel. user must be chanop on that channel
		self.chanoper = object()

		# find commands and documentation
		self.commands = []  # [(command, minauth, func, help)]
		for funcname, func in self.__class__.__dict__.iteritems():
			if funcname.startswith("cmd_"):
				cmdname = funcname[4:]
				docstr = func.__doc__
				if not docstr:
					log.warn("Ignoring command '%s', no docstring" % cmdname)
					continue
				r = re.match(" (guest|registered|confirmed|oper|chanoper) (.*\S) ".replace(' ', '\s*'), docstr, re.DOTALL)
				if not r:
					log.warn("Ignoring command '%s', could not find authorisation in docstring" % cmdname)
					continue
				minauthstr, docu = r.groups()
				minauth = {
						"guest": guestlevel,
						"registered": registeredlevel,
						"confirmed": confirmedlevel,
						"oper": operlevel,
						"chanoper": self.chanoper}[minauthstr]
				log.info("Registered command %s for authorisation %s" % (cmdname, minauthstr))
				self.commands.append((cmdname, minauth, func, docu))
		self.commands.sort()

		server.rehash()  # read initial state from database

	def introduce(self):
		handler = self.server.handler
		now = int(time.time())
		servername = self.server.name
		msg = "NICK %s 1 %d +io %s %s %s :%s" % (
				self.nick, now, "-", "-",
				servername, self.description)
		handler.send(msg)

	def notice(self, who, msg):
		if not msg:
			msg = '\002\002'
		self.send("NOTICE %s :%s" % (who.nick, msg))

	def privmsg(self, who, msg):
		if not msg:
			msg = '\002\002'
		self.send("PRIVMSG %s :%s" % (who.nick, msg))

	def send(self, msg):
		handler = self.server.handler
		msg = ":%s %s" % (self.nick, msg)
		handler.send(msg)

	def find_a_profile_for_nick(self, asker, nick):
		user = self.server.get_user(nick)
		profile = self.server.find_profile_by_nickname(nick)
		if user and profile:
			if user.profile is profile:
				return profile  # identified user
			raise IrcMsgException(asker,
					"Conflicting profile and logged-in user found for '%s'" % nick)
		if profile:
			return profile
		if user and user.profile:
			return user.profile
		raise IrcMsgException(asker, "No profile found for '%s'" % nick)


	@fix_user_on_channels_afterwards
	def cmd_identify(self, user, cmd, args):
		""" guest
		identify [<nick>] <password>
		Tell the server who you are, binding an earlier
		registered profile to your current session """
		args = [arg.strip() for arg in args.split()]
		if len(args) == 2:
			nick, pwd = args
		elif len(args) == 1:
			nick, pwd = user.nick, args[0]
		else:
			raise IrcMsgException(user, "Invalid arguments, need (optionally) a username and a password")

		profile = self.server.find_profile_by_nickname(nick)
		if not profile:
			raise IrcMsgException(user, "No profile for %s, please register first" % nick)
		profile.test_password(pwd, user)

		self.notice(user, "Successfully identified as %s" %
				profile.realname or profile.register_nick)

		# someone else already using this profile??
		user_ = self.server.get_user_for_profile(profile)
		if user_ and not user_ is user:
			self.server.kill_user(user_, "Ghosted by %s" % user.nick)

		user.identify(profile)
		if profile.level is operlevel:
			self.server.notice_serverops(
					"%s just became server operator" % user.nick)

	@fix_user_on_channels_afterwards
	@no_leftover_arguments
	def cmd_unidentify(self, user, cmd):
		""" registered
		unidentify
		Stop associating your current profile with this
		session. Probably only usefull in debugging """
		user.unidentify()

	def cmd_reidentify(self, user, cmd, args):
		""" registered
		reidentify [<nick>] <password>
		identify as a different user, short for unidentify/identify """
		user.unidentify()
		self.cmd_identify(user, cmd, args)

	@fix_user_on_channels_afterwards
	def cmd_register_user(self, user, cmd, args):
		""" guest
		register_user <password>
		Create a new profile for the current user """
		profile = self.server.find_profile_by_nickname(user.nick)
		if profile:
			raise IrcMsgException(user, "User %s already registered" % user.nick)

		password = args.strip()
		if not password:
			raise IrcMsgException(user, "Please specify password")
		if password.find(' ') >= 0:
			raise IrcMsgException(user, "No spaces allowed in password")
		newprofile = self.server.create_profile(user.nick, password)
		self.notice(user, "Successfully registered %s, please remember your password to identify next time" % user.nick)
		user.identify(newprofile)
		# FIXME: tell user he can now register channels, etc

	@needs_profile
	def cmd_unregister_user(self, caller, callerprofile, cmd, args):
		""" registered
		unregister_user [<nick>] [<password>]
		Destroy registered profile. Does an implicit unidentify.
		Only server operator can unregister others. """

		args = args.split()
		if callerprofile.level is operlevel:
			if len(args) != 1:
				raise IrcMsgException(caller, "Server operators should only specify a nickname")
			profile = self.find_a_profile_for_nick(caller, args[0])
			if profile is callerprofile:
				raise IrcMsgException(caller, "Server operators cannot unregister their own profile")
		else:
			if len(args) == 2:
				pwd = args[1]
				profile = self.find_a_profile_for_nick(caller, args[0])
				if not profile is callerprofile:
					raise IrcMsgException(caller, "You can only unregister your own profile")
			else:
				pwd = args[0]
				profile = callerprofile
			if not profile.test_password(pwd):
				raise IrcMsgException("Password invalid")

		# FIXME: make sure we don't throw away the last server oper
		user = self.server.get_user_for_profile(profile)
		if user:
			user.unidentify()
		self.server.drop_profile(profile)
		if user:
			self.server.fix_user_on_all_channels(user)
		
	def cmd_reset_pass(self, oper, cmd, args):
		""" oper
		reset_pass <nick> <newpass>
		Change password for a profile """
		try:
			nick, newpass = args.strip().split(' ')
		except ValueError:
			raise IrcMsgException("Invalid arguments, need nickname and new password")

		profile = self.find_profile_by_nickname(nick)
		if not profile:
			raise IrcMsgException("No profile found for '%s'" % nick)
		profile.reset_password(newpass)

	@needs_profile
	def cmd_passwd(self, user, profile, cmd, args):
		""" registered
		passwd <oldpass> <newpass>
		Change password for current profile """
		try:
			oldpass, newpass = args.split(' ')
		except ValueError:
			raise IrcMsgException("Need old password and new password")
		profile.test_password(oldpass, user, "Error, old password invalid")
		profile.reset_password(newpass)

	def cmd_confirm(self, oper, cmd, args):
		""" oper
		confirm <nick> <realname> <email>
		Confirm a registered user really is who he says he is """
		# FIXME: allow last argument to specify serveroper
		r = re.match('(\S+)\s+(.*)\s+(\S+@\S+)', args.strip())
		if not r:
			raise IrcMsgException(oper, "need: <nick> <realname> <email>")
		nick, realname, email = r.groups()
		if realname[:1] == realname [-1:] and realname[:1] in "\"'":
			realname = realname[1:-1]

		profile = self.find_a_profile_for_nick(oper, nick)
		profile.confirm(realname, email)
		user = self.server.get_user(nick)
		if user:
			self.server.fix_user_on_all_channels(user)

	def cmd_unconfirm(self, oper, cmd, args):
		""" oper
		unconfirm <nick>
		For undoing 'confirm' """
		# FIXME: check if we are not downgrading last serveroper
		nick = args.strip()
		profile = self.find_a_profile_for_nick(oper, nick)

		profile.unconfirm()

		user = self.server.get_user(nick)
		if user:
			self.server.fix_user_on_all_channels(user)

	def online_or_offline(self, profile):
		user = self.server.get_user_for_profile(profile)
		if user:
			if user.nick == profile.register_nick:
				return "online"
			else:
				return "online as %s" % user.nick
		else:
			return "offline"

	def rolesline(self, profile):
		roles = defaultdict(list)
		for chan in self.server.get_all_channels():
			if not chan.registered:
				continue
			role = chan.get_role_for_profile(profile)
			if not role is None:
				roles[role].append(chan.name)

		if roles:
			roles = make_list(
						(role_as_text(role) + " in " + make_list(sort(channels), "and")
							for role, channels in roles.iteritems())
					, "and")
		else:
			roles = "no defined roles on channels"
		return roles

	def cmd_whois(self, user, cmd, args):
		""" registered
		whois [<nick>]
		Show the profile currently associated with your session. """
		nick = args.strip()
		if nick and user.is_confirmed():
			profile = self.find_a_profile_for_nick(user, nick)

			status = self.online_or_offline(profile)
			firstline = "%s is %s and " % (nick, status)
			leveltxt = level_as_text(profile.level)
			firstline += leveltxt + " as " + profile.register_nick
		else:
			if args and nick.lower() != user.nick.lower():
				raise IrcMsgException(user, "You must have a confirmed account to view others")
			profile = user.profile
			leveltxt = level_as_text(profile.level)
			firstline = "You are %s, %s" % (user.nick, leveltxt)
			if user.nick != profile.register_nick:
				firstline += " as " + profile.register_nick
		firstline += ", " + self.rolesline(profile)
		self.notice(user, firstline)
		if profile.is_confirmed():
			self.notice(user, "Real name: " + (profile.realname or ''))
			self.notice(user, "Email: " + (profile.email or ''))

	@no_leftover_arguments
	def cmd_whoami(self, user, cmd):
		""" guest
		whoami
		Show who you are """
		if user.profile:
			self.cmd_whois(user, cmd, "")
		else:
			self.notice(user, "You are %s, an unregistered guest" % user.nick)

	@needs_channel
	@no_leftover_arguments
	def cmd_register_channel(self, user, chan, cmd):
		""" registered
		register_channel <chan>
		Register an unregistered channel and make you it's channel operator """
		if chan.registered:
			raise IrcMsgException(user, "Channel '%s' is already registered" % chan.name)
		chan.register()
		chan.set_role(user, user.profile, operrole)
		chan.fix_all_users()

	@needs_channel
	@no_leftover_arguments
	def cmd_unregister_channel(self, user, chan, cmd):
		""" chanoper
		unregister_channel <chan>
		Undo register_channel """
		if not chan.registered:
			raise IrcMsgException(user, "Channel '%s' is not registered" % chan.name)
		chan.unregister()

	@needs_channel
	@no_leftover_arguments
	def cmd_roles(self, oper, chan, cmd):
		""" chanoper
		roles <chan>
		Show the current known roles for channel """
		roles = chan.get_roles(oper)
		if not roles:
			raise IrcMsgException(oper, "No roles defined for %s" % chan.name)

		if chan.allow_guests:
			guesttxt = "allows"
		else:
			guesttxt = "denies"
			self.notice(oper, "%s denies guests" % chan.name)
			self.notice(oper, "%s allows guests" % chan.name)

		if chan.default_policy_allow:
			poltxt = "allows"
		else:
			poltxt = "denies"

		self.notice(oper, "%s %s guests and channel policy %s registered users" % (
			chan.name, guesttxt, poltxt))

		for profile, role in roles:
			status = self.online_or_offline(profile)
			role = role_as_text(role)
			self.notice(oper, "- %s %s (%s)" % (
				profile.register_nick, role, status))
		self.notice(oper, "total %d role(s) defined for %s" % (
			len(roles), chan.name))

	@needs_channel
	def cmd_add(self, oper, chan, cmd, args):
		""" chanoper
		add <chan> <nick> ban|allow|oper
		Allow <nick> on <chan> (if policy is set to deny)
		or ban <nick> from <chan> (if policy is set to accept)
		or make <nick> a channel operator on <chan>"""
		r = re.match("\s*(\S*)\s+(ban|allow|oper)\s*$", args)
		if not r:
			raise IrcMsgException(oper, "Argument error, need nick and 'ban', 'allow' or 'oper'")
		nick, newrole = r.groups()
		profile = self.find_a_profile_for_nick(oper, nick)
		newrole = {'ban': banrole, 'allow': allowrole, 'oper': operrole}[newrole]
		chan.set_role(oper, profile, newrole)
		user = self.server.get_user_for_profile(profile)
		if user:
			chan.fix_user_to_role(user)

	@needs_channel
	def cmd_del(self, oper, chan, cmd, args):
		""" chanoper
		del <chan> <nick>
		delete a role for a given user from a channel"""
		nick = args.strip()
		profile = self.find_a_profile_for_nick(oper, nick)
		chan.del_role(oper, profile)
		user = self.server.get_user_for_profile(profile)
		if user:
			chan.fix_user_to_role(user)

	def cmd_mod(self, oper, cmd, args):
		""" chanoper
		mod <chan> <nick> ban|allow|oper
		modify a role for a given user for a channel"""
		self.cmd_add(oper, cmd, args)

	@needs_channel
	def cmd_guests(self, oper, chan, cmd, args):
		""" chanoper
		guests #chan allow|deny
		Are unregistered users allowed to join this channel """
		allowstr = args.strip().lower()
		if allowstr == "allow":
			allow = True
		elif allowstr == "deny":
			allow = False
		else:
			raise IrcMsgException(oper, "please use 'allow' or 'deny'. not '%s'" % allowstr)

		# FIXME, this command does not work
		chan.set_allow_guests(oper, allow)
		chan.fix_all_users()

	@needs_channel
	def cmd_policy(self, oper, chan, cmd, args):
		""" chanoper
		policy <chan> allow|deny
		Are users without explicit role in the channel allowed or kept out """
		allowstr = args.strip().lower()
		if allowstr not in ("allow", "deny"):
			raise IrcMsgException(oper, "please use 'allow' or 'deny'. not '%s'" % allowstr)

		chan.set_policy(oper, allowstr)
		chan.fix_all_users()

	@no_leftover_arguments
	def cmd_profiles(self, oper, cmd):
		""" oper
		profiles
		Show registered profiles """
		all_profiles = self.server.get_all_profiles()
		for prof in all_profiles:
			status = self.online_or_offline(prof)
			level = level_as_text(prof.level)
			msg = "%s, %s, %s" % (prof.register_nick, status, level)
			if prof.is_confirmed():
				msg += ", %s, %s" % (prof.realname or '', prof.email or '')
			self.notice(oper, "- %s" % msg)
		self.notice(oper, "Total %d registered profiles" % len(all_profiles))

	@no_leftover_arguments
	def cmd_channels(self, user, cmd):
		""" oper
		channels
		Show known channels """
		channels = self.server.get_all_channels()
		if not channels:
			raise IrcMsgException(user, "No channels found!")
		for chan in channels:
			if chan.registered:
				registered = "registered"
			else:
				registered = "not registered"
			self.notice(user, "- %s %d users (%s)" % (
				chan.name, chan.usercount(), registered))

	@no_leftover_arguments
	def cmd_restart(self, user, cmd):
		""" oper
		restart
		Restart the construct. Use with care. """
		raise RestartException()

	def cmd_kill(self, oper, cmd, args):
		""" oper
		kill <nick>
		Remove someone from the irc server (beware of auto-reconnect) """
		if args.find(' ') >= 0:
			raise IrcMsgException("Too many arguments, expected only a nickname")
		nick = args
		user = self.server.get_user(nick)
		if not user:
			raise IrcMsgException(oper, "No such nick '%s'" % nick)
		self.server.kill_user(user, "killed by %s" % oper.nick)

	@no_leftover_arguments
	def cmd_rehash(self, user, cmd):
		""" oper
		rehash
		re-read profiles/channels/roles from database and update state """
		self.server.rehash()

	def cmd_help(self, user, cmd, args):
		""" guest
		help [<command>]
		Show all commands or show description for specified command.
		"""
		neededcmd = args.strip().lower()
		found = False
		for cmd, minauth, func, docu in self.commands:
			if minauth is self.chanoper:
				minauth = " (for channel operators)"
			elif minauth is guestlevel:
				minauth = ''
			else:
				minauth = " (must be %s)" % level_as_text(minauth)
			lines = docu.split('\n')
			if not neededcmd:
				self.notice(user, "%s%s" % (lines[0], minauth))
			elif cmd.lower().startswith(neededcmd):
				found = True
				self.notice(user, lines[0] + minauth)
				for line in lines[1:]:
					self.notice(user, line.strip())
		if neededcmd and not found:
			raise IrcMsgException(user, "Command not found: %s" % neededcmd)


	def extract_channel_from_args(self, user, args):
		argssplit = args.strip().split(' ', 1)
		if len(argssplit) == 0:
			raise IrcMsgException(user, "Missing channelname")
		elif len(argssplit) == 1:
			channame, rest = argssplit[0], ''
		else:
			channame, rest = argssplit

		if not channame:
			raise IrcMsgException(user, "No channel specified")

		chan = self.server.get_channel(channame)
		if not chan:
			raise IrcMsgException(user, "Unknown channel '%s'" % channame)
		return (chan, rest)

	def test_authorisation(self, user, minlevel, cmd, args):
		if minlevel is guestlevel:
			return  # everyone is at least guest

		profile = user.profile
		if not profile:
			raise CommandDenied(user, cmd, "not registered, no profile")
		userlevel = profile.level
		assert (
				profile.level is registeredlevel or
				profile.level is confirmedlevel or
				profile.level is operlevel)

		if minlevel is self.chanoper:
			# chanoper is special. it is allowed if the first argument is
			# the correct channel (or user is serveroper)
			# even for serveroper's the channel must be known
			chan, rest = self.extract_channel_from_args(user, args)
			result = userlevel is operlevel or chan.is_channel_operator(user)
			if not result:
				raise CommandDenied(user, cmd, "not channel operator for %s" % chan.name)
			return

		if userlevel is operlevel:
			return  # serverops get all

		if minlevel is confirmedlevel and \
				userlevel is registeredlevel:
			raise CommandDenied(user, cmd, "profile not confirmed")

		if minlevel is operlevel and \
				not userlevel is operlevel:
			raise CommandDenied(user, cmd, "not server operator")

		# it's OK

	def recv(self, user, msg):
		msg = msg.strip().split(' ', 1)
		if len(msg) > 1:
			cmd, args = msg
		else:
			cmd, args = msg[0], ''
		cmd = cmd.lower()

		if len(cmd) < 2:
			raise IrcMsgException(user, "Unknown command (and very short..)")

		funcs = [tup for tup in self.commands if tup[0].startswith(cmd)]
		if len(funcs) == 0:
			raise IrcMsgException(user, "Unknown command '%s'" % cmd)
		elif len(funcs) > 1:
			raise IrcMsgException(user, "Non-unique command, choose: " + make_list(
				(tup[0] for tup in funcs), "or"))

		cmd_, minlevel, func, docu = funcs[0]
		self.test_authorisation(user, minlevel, cmd_, args)

		func(self, user, cmd, args.strip())

		self.notice(user, "OK")


def main(configfile):
	# FIXME: would like to have the configfile in a similar format as ircd.conf
	# FIXME: at least some format that allows comments
	config = json.load(open(configfile))
	server = Server(config['server'])

	hand = Handler(server, **config['connect'])
	hand.connect()
	try:
		hand.read_until_server_connect()

		construct = Construct(server, **config['construct'])
		construct.introduce()

		if 'oper' in config:  # insert initial user into database
			oper = config['oper']
			profile = server.find_profile_by_nickname(oper['nick'])
			if not profile:
				profile = server.create_profile(oper['nick'], oper['password'])
			profile.level = operlevel
			profile.realname = oper['realname']
			profile.reset_password(oper['password'])
			profile.update_db()

		hand.read_all()
	finally:
		hand.disconnect()


if __name__ == "__main__":
	FORMAT = '#%(message)s'
	logging.basicConfig(level=logging.INFO, format=FORMAT)

	parser = argparse.ArgumentParser(description='(More) secure irc user management')
	parser.add_argument('--config', '-c', type=str, help='config file', required=True)
	args = parser.parse_args()

	starting = True
	while starting:
		starting = False
		try:
			main(args.config)
		except RestartException:
			starting = True



