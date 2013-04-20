import base64
import hashlib
import json
import logging
import os
import re
import socket
import time
import traceback
from collections import defaultdict
from copy import copy
from functools import wraps

from .database import ConstructDatabase
from .commandcontainer import CommandContainer, ParseException
from .consts import \
		guestlevel, registeredlevel, confirmedlevel, operlevel, \
		banrole, allowrole, operrole
from .irc_connection import IrcConnection

log = logging.getLogger('main')

# FIXME: Think of a secure way to keep user-registrations accros restarts

pingre = re.compile("PING :(.*)".replace(' ', '\s+'))
passre = re.compile("PASS (\S+) TS.*".replace(' ', '\s+'))
serverre = re.compile("SERVER (\S+) 1 :(.*)".replace(' ', '\s+'))
killre = re.compile(":\S+ KILL (\S+) :(.*)".replace(' ', '\s+'))

nickre = re.compile("NICK (\S+) \d+ \d+ \+[a-z]* (\S*) (\S*) \S* :.*".replace(' ', '\s+'))
nickchangere = re.compile(":(\S+) NICK (\S+) :\d+".replace(' ', '\s+'))
sjoinre = re.compile(':\S+ SJOIN \d+ (#\S+) \+[a-z]* :(.*)'.replace(' ', '\s+'))
partre = re.compile(':(\S+) PART (\S+)'.replace(' ', '\s+'))
kickre = re.compile(':\S+ KICK (\S+) (\S+) :(.*)'.replace(' ', '\s+'))
#modere = re.compile(":\S+ MODE .*".replace(' ', '\s+'))
modere = re.compile(':(\S+) MODE (\S+) ([-+]\S+) (\S+(?: \S+)*)'.replace(' ', '\s+'))
quitre = re.compile(":(\S+) QUIT :(.*)".replace(' ', '\s+'))
privmsgre = re.compile(":(\S+) PRIVMSG (\S+) :(.*)".replace(' ', '\s+'))

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
	def __init__(self, core):
		self.core = core
		self.channels = dict()  # name -> channel

	def rehash(self):  # re-read registered channels from db
		old = self.channels
		self.channels = dict()

		for name, guests, policy in self.core.db.get_channels():
			name = name.lower()
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
		for chan, profileid, role in self.core.db.get_roles():
			roles[chan][profileid] = role
		for chan in self.get_all_channels():
			chan.roles = roles.get(chan.name, {})

	def get_channel(self, channelname):
		channelname = channelname.lower()
		return self.channels.get(channelname)

	def get_or_create_channel(self, channelname):
		channelname = channelname.lower()
		channel = self.channels.get(channelname)
		if not channel:
			log.debug("creating channel %s" % channelname)
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
		self.parent.core.db.create_channel(
				self.name, self.allow_guests, self.default_policy_allow)

	def unregister(self):
		if not self.registered:
			return

		self.registered = False
		self.parent.core.db.delete_channel(self.name)
		if not self.users:
			self.parent.channel_empty(self)

	def has_user(self, user):
		return user in self.users

	def usercount(self):
		return len(self.users)

	@channel_registered
	def set_allow_guests(self, oper, allow_):
		self.allow_guests = allow_
		self.parent.core.db.update_channel(
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
		self.parent.core.db.update_channel(
				self.name, self.allow_guests, self.default_policy_allow)

	@channel_registered
	def set_role(self, oper, profile, role):
		if not profile:
			raise IrcMsgException(oper, "Guest users cannot have roles, must register first")
		if role:
			self.roles[profile.profileid] = role
			self.parent.core.db.create_role(self.name, profile.profileid, role)
		else:
			del self.roles[profile.profileid]
			self.parent.core.db.delete_role(self.name, profile.profileid)

	def del_role(self, oper, profile):
		self.set_role(oper, profile, None)

	@channel_registered
	def get_roles(self, oper):
		out = []
		for profileid, role in self.roles.iteritems():
			profile = self.parent.core.profiles.find_profile_by_id(profileid)
			if not profile:
				raise Exception("self.roles broken in channel %s" % self.name)
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
		# check if a user (who is currently in the channel) is
		# allowed and has the right mode. And correct if wrong

		if not self.registered:
			log.debug("not fixing %s on %s, channel not registered" % (
				user.nick, self.name))
			return  # not doing anything for channels nobody cares about

		if not self.allow_guests and not user.profile:
			log.debug("removing %s from %s, guests not allowed on channel" % (
				user.nick, self.name))
			self.remove_user(user, "guests not allowed")
			return

		role = self.find_role(user)
		mode = self.users.get(user)
		if mode is None:
			log.debug("not fixing %s on %s, user is not in channel" % (
				user.nick, self.name))
			return

		if role is banrole:
			log.debug("removing %s from %s, user is banned" % (
				user.nick, self.name))
			self.remove_user(user, "user not allowed")
		elif role is allowrole:
			if 'o' in mode:
				log.debug("user %s is not operator on %s, fixing" % (
					user.nick, self.name))
				self.deop_user(user)
		elif role is operrole:
			if not 'o' in mode:
				log.debug("user %s is operator on %s, fixing" % (
					user.nick, self.name))
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
			if self.allow_guests:
				return defaultrole
			else:
				return banrole

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

	def mode(self, whodidit, user, modechange):
		oldmode = self.users[user]
		if modechange[0] == '-':
			newmode = ''.join(set(oldmode) - set(modechange[1:]))
		elif modechange[0] == '+':
			newmode = ''.join(set(oldmode).union(set(modechange[1:])))
		else:
			raise Exception("Invalid mode-change '%s' for %s on %s" %(
				modechange, user.nick, self.name))
		self.users[user] = newmode

		try:
			if whodidit and 'o' in modechange and self.registered:
				if self.is_channel_operator(whodidit) and user.profile:
					if modechange[0] == '+':
						self.set_role(whodidit, user.profile, operrole)
					elif modechange[0] == '-' and self.is_channel_operator(user):
						if self.default_policy_allow:
							self.set_role(whodidit, user.profile, None)
						else:
							self.set_role(whodidit, user.profile, allowrole)
		except IrcMsgException:
			pass

	def op_user(self, user):
		assert self.registered
		log.debug("%s opped %s" % (self.name, user.nick))
		self.send("MODE %s +o %s" % (self.name, user.nick))
		self.mode(None, user, "+o")
		self.fix_user_to_role(user)

	def deop_user(self, user):
		assert self.registered
		log.debug("%s de-opped %s" % (self.name, user.nick))
		self.send("MODE %s -o %s" % (self.name, user.nick))
		self.mode(None, user, "-o")
		self.fix_user_to_role(user)

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
		self.parent.core.avatar.send(msg)

	def __str__(self):
		return "Channel(%s)" % self.name


class Profile(object):
	def __init__(self, parent, id_, nickname, password):
		self.parent = parent
		self.profileid = id_
		self.register_nick = nickname
		self.level = registeredlevel  # if we have a profile we are registered
		self.password = None
		self.last_password_failed_time = 0
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
		timeout = self.parent.core.password_timeout
		if now - self.last_password_failed_time < timeout:
			raise IrcMsgException(
					caller,
					"error, wait %s seconds between password guess attempts" % timeout)
		assert self.password[:3] == '$C$'
		salt, digest = self.password[3:].split('$', 1)
		if digest != Profile.getDigest(testpass, salt)[1]:
			self.last_password_failed_time = now
			if msg is None:
				msg = "error, invalid password for '%s'" % self.register_nick
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
		self.parent.core.db.update_profile(
				self.profileid, self.register_nick, self.level, self.password,
				self.realname, self.email)


class ProfileDB(object):
	def __init__(self, core):
		self.core = core
		self.profiles = list()
		self.next_id = 1

	def rehash(self):
		old = {p.profileid:p for p in self.profiles}
		self.profiles = list()
		self.next_id = 1
		for id_, nick, lvl, pwd, rn, email in self.core.db.get_profiles():
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
			user = self.core.users.get_user_for_profile(prof)
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
		self.core.db.create_profile(
				p.profileid, p.register_nick, p.level, p.password)
		return p

	def drop_profile(self, profile):
		self.profiles = [p for p in self.profiles
				if p != profile]
		self.core.db.delete_profile(profile.profileid)

	def get_all_profiles(self):
		return self.profiles


class UserDB(object):
	def __init__(self, core):
		self.core = core
		self.users = list()

	def get_user(self, needednick, defaultval=None):
		#print "looking for user '%s', current users: %s" % (
		#		needednick, ', '.join(u.nick for u in self.users))
		needednick = needednick.lower()
		for user in self.users:
			if user.nick.lower() == needednick:
				return user
		return defaultval

	def create_user(self, newnick, username, hostname):
		assert self.get_user(newnick) is None
		user = User(newnick, username, hostname)
		self.users.append(user)
		register_nick = self.core.can_auto_identify(newnick)
		if not register_nick is None:
			log.info("startup: user '%s' automatically identified with profile '%s'" % (
				newnick, register_nick))
			profile = self.find_profile_by_nickname(register_nick)
			user.identify(profile)
		return user

	def remove_user(self, user):
		self.users.remove(user)

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

	def get_identified_users(self):
		return [
				(user.nick, user.profile.register_nick)
				for user in self.users
				if user.profile]

	def privmsg_serverops(self, msg):
		for user in self.get_serveropers():
			self.core.avatar.privmsg(user, msg)

	def notice_serverops(self, msg):
		for user in self.get_serveropers():
			self.core.avatar.notice(user, msg)

	def kill_user(self, user, reason):
		log.info("User %s killed, %s", user.nick, reason)
		self.core.shandler.send("KILL %s :HOP %s" % (user.nick, reason))
		self.remove_user(user)


class User(object):
	def __init__(self, nick, username, hostname):
		self.nick = nick
		self.profile = None
		self.username = username
		self.hostname = hostname

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

	def level(self):
		if not self.profile:
			return guestlevel
		else:
			return self.profile.level


class Core(object):
	def __init__(self, conf, initial_identified):
		self.shandler = ServerHandler(
				self,
				conf['connect']['send_password'],
				conf['connect']['accept_password'],
				conf['connect']['host'],
				conf['connect']['port'],
				conf['server']['name'],
				conf['server'].get('description', ''))
		self.channels = ChannelDB(self)
		self.profiles = ProfileDB(self)
		self.users = UserDB(self)

		self.db = ConstructDatabase(conf.get('db', "construct.db"))
		self.password_timeout = conf.get('password_timeout', 30)
		self.initial_identified = dict(initial_identified)

		self.avatar = Avatar(
				self,
				conf['service']['nick'],
				conf['service'].get('description'))

		self.rehash()  # read initial state from database

		for oper in conf.get('opers', []):  # insert initial user into database
			profile = self.profiles.find_profile_by_nickname(oper['nick'])
			if not profile:
				profile = self.profiles.create_profile(oper['nick'], oper['password'])
			profile.level = operlevel
			profile.realname = oper.get('realname', '')
			profile.reset_password(oper['password'])
			profile.update_db()

	def run(self):
		self.in_startup_timer = time.time()

		self.shandler.connect()
		try:
			self.shandler.read_until_server_connect()
			log.info("server connected")

			self.avatar.introduce()

			self.shandler.read_all()
		except RestartException, e:
			e.identified_users = self.users.get_identified_users()
			raise
		finally:
			self.shandler.disconnect()

	def in_startup(self):
		if self.in_startup_timer is None:
			return False
		if time.time() > self.in_startup_timer + 10:
			self.finish_startup()
			return False
		return True

	def can_auto_identify(self, newnick):
		""" returns registered_nick from profile if allowed, None otherwise """
		if not self.in_startup():
			return None
		return self.initial_identified.get(newnick)

	def finish_startup(self):
		self.in_startup_timer = None
		msg = "finished starting"
		msg += ", received %d users and %d channels from server" % (
				len(self.users.users), len(self.channels.channels))
		initial = len(self.users.get_identified_users())
		if initial:
			msg += ", %d users already identified" % initial
		self.users.notice_serverops(msg)

	def rehash(self):
		log.info("Starting rehash")
		self.channels.rehash()
		self.profiles.rehash()
		for chan in self.channels.get_all_channels():
			chan.fix_all_users()
		log.info("Done rehash")



class ServerHandler(object):
	def __init__(
			self,
			core,
			send_password,
			accept_password,
			host, port,  # remote
			name, description  # us
			):
		self.con = IrcConnection(host, port)
		self.core = core
		self.accept_password = accept_password
		self.send_password = send_password
		self.serverstate = None

		self.name = name
		if self.name.find('.') < 0:
			raise Exception("server name('%s') must contain a dot" % self.name)
		self.description = description

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
		self.send("SERVER %s 1 :%s" % (self.name, self.description))

	def disconnect(self):
		self.con.disconnect()
		self.con = None

	def msg_ping(self, who):
		self.send("PONG :" + who)
		if self.core.in_startup():
			self.core.finish_startup()

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
		if who == self.core.avatar.nick:
			raise Exception("Server killed our construct: %s" % reason)

	def msg_nick(self, newnick, username, hostname):
		user = self.core.users.get_user(newnick)
		if user:
			raise OperMsgException(
					"User %s already known" % newnick)
		user = self.core.users.create_user(newnick, username, hostname)
		self.core.channels.fix_user_on_all_channels(user)

	def msg_nickchange(self, oldnick, newnick):
		user = self.core.users.get_user(oldnick)
		if not user:
			raise OperMsgException(
					"no such user %s" % oldnick)
		user.nickchange(newnick)
		self.core.channels.fix_user_on_all_channels(user)

	def msg_sjoin(self, channame, nicks):
		chan = self.core.channels.get_or_create_channel(channame)
		for nick in nicks.split():
			mode = ''
			if '@' in nick:
				mode += 'o'
				nick = nick.replace('@', '')
			if '+' in nick:
				mode += 'v'
				nick = nick.replace('+', '')
			user = self.core.users.get_user(nick)
			if not user:
				raise OperMsgException(
						"joining user %s does not exist" % nick)
			chan.join(user, mode)

	def msg_part(self, nick, channame):
		chan = self.core.channels.get_channel(channame)
		if not chan:
			raise OperMsgException(
					"no such channel '%s' where user %s parts from" % (
						channame, nick))
		user = self.core.users.get_user(nick)
		if not user:
			raise OperMsgException(
					"parting user %s does not exist" % nick)
		chan.part(user)

	def msg_kick(self, channame, nick, reason):
		chan = self.core.channels.get_channel(channame)
		if not chan:
			raise OperMsgException(
					"no such channel '%s' where user %s is kicked from" % (
						channame, nick))
		user = self.core.users.get_user(nick)
		if not user:
			raise OperMsgException(
					"parting user %s does not exist" % nick)
		chan.kick(user)

	def msg_mode(self, chanoper, channame, modechange, nicks):
		chan = self.core.channels.get_channel(channame)
		if not chan:
			raise OperMsgException(
					"no such channel '%s' where user(s) %s are mode-changed" % (
						channame, nicks))
		chanoper = self.core.users.get_user(chanoper)
		for nick in nicks.split():
			user = self.core.users.get_user(nick)
			if not user:
				raise OperMsgException(
						"mode-change for non-existing user %s" %
						nick)
			chan.mode(chanoper, user, modechange)
		chan.fix_all_users()

	def msg_quit(self, who, reason):
		user = self.core.users.get_user(who)
		self.core.channels.channel_user_quit(user)
		self.core.users.remove_user(user)

	def msg_privmsg(self, fromnick, tonick, msg):
		avatar = self.core.avatar
		if tonick == avatar.nick:
			user = self.core.users.get_user(fromnick)
			avatar.recv(user, msg)
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
				self.core.avatar.notice(e.user, e.msg)
			else:
				log.warning("Unknown user caused exception: %s" % e.msg)
		except OperMsgException, e:
			log.warning(e.msg)
			self.core.users.privmsg_serverops(
					"Exception: %s" % e.msg)
		except Exception:
			lines = traceback.format_exc()
			for line in lines.split('\n'):
				log.error(line)
			for line in lines.split('\n'):
				self.core.users.privmsg_serverops(line)

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


def fix_caller_afterwards(func):
	@wraps(func)
	def fix_user_afterwards_wrapper(self, user, *args1, **args2):
		func(self, user, *args1, **args2)
		self.core.channels.fix_user_on_all_channels(user)
	return fix_user_afterwards_wrapper


class Avatar(object):
	def __init__(self, core, nick, description):
		self.core = core
		self.nick = nick
		self.description = description

		# find commands and documentation
		self.commands = CommandContainer()
		for funcname, func in self.__class__.__dict__.iteritems():
			if funcname.startswith("cmd_"):
				funcname = funcname[4:].replace('_', ' ')
				try:
					self.commands.register_command(funcname, func)
				except Exception, e:
					log.warn("Ignoring command '%s', %s" % (funcname, e))
		self.commands.register_chapter(1, "general commands")
		self.commands.register_chapter(2, "channel commands")
		self.commands.register_chapter(3, "server operator commands")
		self.commands.register_access_test(self.test_access)

	def test_access(self, cmd, args, user, forhelp):
		""" test if user has access to command.
		side-effect: if a channel was specified in args, replace it with the
		channel object """
		if args and 'chan' in args:
			chan = self.core.channels.get_channel(args['chan'])
			if not chan:
				raise IrcMsgException(user, "unknown channel '%s'" % args['chan'])
			args['chan'] = chan

		if cmd.minauth is guestlevel:
			return # everyone is at least guest

		userlevel = user.level()
		if userlevel is guestlevel:
			raise IrcMsgException(user, "guests access not allowed, please identify/register")
		assert (
				userlevel is registeredlevel or
				userlevel is confirmedlevel or
				userlevel is operlevel)

		if cmd.minauth is self.commands.chanoper:
			if not forhelp:
				assert not args is None
				# chanoper is special. it is allowed if the first argument is
				# the correct channel (or user is serveroper)
				# even for serveroper's the channel must be known
				chan = args.get('chan')
				if not chan:
					raise Exception("no channel found in arguments")
				if not chan.registered:
					raise IrcMsgException(user, "'%s' is not a registered channel" %
						chan.name)
				if not chan.find_role(user) is operrole:
					raise IrcMsgException(user, "'%s' is not a channel operator on '%s'" % (
						user.nick, chan.name))
			else:  # for help
				assert args is None
				# when serving help pages, we list the channel commands if the user is
				# channel operator on any channel
				if not userlevel is operlevel and \
						not any(chan.registered and chan.find_role(user) is operrole
								for chan in self.core.channels.get_channels_with_user(user)):
					raise IrcMsgException(user, "user is not channel operator on any channel")
			return  # ok

		if userlevel is operlevel:
			return  # serverops get all

		if cmd.minauth is confirmedlevel and \
				userlevel is registeredlevel:
			raise IrcMsgException(user, "profile not confirmed")

		if cmd.minauth is operlevel and \
				not userlevel is operlevel:
			raise IrcMsgException(user, "not server operator")

		# it's OK

	def introduce(self):
		shandler = self.core.shandler
		now = int(time.time())
		servername = shandler.name
		msg = "NICK %s 1 %d +io %s %s %s :%s" % (
				self.nick, now, "-", "-",
				servername, self.description)
		shandler.send(msg)

	def notice(self, who, msg):
		if not msg:
			msg = '\002\002'
		self.send("NOTICE %s :%s" % (who.nick, msg))

	def privmsg(self, who, msg):
		if not msg:
			msg = '\002\002'
		self.send("PRIVMSG %s :%s" % (who.nick, msg))

	def send(self, msg):
		shandler = self.core.shandler
		msg = ":%s %s" % (self.nick, msg)
		shandler.send(msg)

	def find_a_profile_for_nick(self, asker, nick):
		user = self.core.users.get_user(nick)
		profile = self.core.profiles.find_profile_by_nickname(nick)
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

	def online_or_offline(self, profile):
		user = self.core.users.get_user_for_profile(profile)
		if user:
			if user.nick == profile.register_nick:
				return "online"
			else:
				return "online as %s" % user.nick
		else:
			return "offline"

	def rolesline(self, profile):
		roles = defaultdict(list)
		for chan in self.core.channels.get_all_channels():
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

	@fix_caller_afterwards
	def cmd_identify(self, caller, cmd, nick, password):
		""" guest
		1.1 identify [<nick>] <password>
		Tell the server who you are, binding an earlier
		registered profile to your current session """

		if caller.profile:
			raise IrcMsgException(caller, "already identified as %s" %
					caller.profile.register_nick)

		nick = nick or caller.nick
		profile = self.core.profiles.find_profile_by_nickname(nick)
		if not profile:
			raise IrcMsgException(caller, "No profile for %s, please register first" % nick)
		profile.test_password(password, caller)

		self.notice(caller, "Successfully identified as %s" %
				(profile.realname or profile.register_nick))

		# someone else already using this profile??
		user_ = self.core.users.get_user_for_profile(profile)
		if user_ and not user_ is caller:
			self.core.users.kill_user(user_, "ghosted by %s" % caller.nick)

		caller.identify(profile)
		if profile.level is operlevel:
			self.core.users.notice_serverops(
					"%s just became server operator" % caller.nick)
		assert caller.level() != guestlevel

	def cmd_reidentify(self, caller, cmd, nick, password):
		""" registered
		1.2 reidentify [<nick>] <password>
		identify as a different user, short for unidentify/identify """
		caller.unidentify()
		try:
			self.cmd_identify(caller, cmd, nick, password)
		except:
			self.notice(caller, "you are now not identified")
			raise

	@fix_caller_afterwards
	def cmd_unidentify(self, caller, cmd):
		""" registered
		1.3 unidentify
		Stop associating your current profile with this
		session. Probably only usefull in debugging """
		caller.unidentify()

	@fix_caller_afterwards
	def cmd_register(self, caller, cmd, password):
		""" guest
		1.4 register <password>
		Create a new profile for the current user """
		if self.core.channels.get_channel(password):
			raise IrcMsgException(caller, "Trying to register a channel? try the 'register channel' command")

		profile = self.core.profiles.find_profile_by_nickname(caller.nick)
		if profile:
			raise IrcMsgException(caller, "User %s already registered" % caller.nick)

		if not password:
			raise IrcMsgException(caller, "Please specify password")
		if password.find(' ') >= 0:
			raise IrcMsgException(caller, "No spaces allowed in password")
		newprofile = self.core.profiles.create_profile(caller.nick, password)
		self.notice(caller, ("Successfully registered %s, please remember your " +
				"password to identify next time") % caller.nick)
		caller.identify(newprofile)
		# FIXME: tell caller he can now register channels, etc

	def cmd_unregister(self, caller, cmd, nick, password):
		""" registered
		1.5 unregister [<nick>] [<password>]
		Destroy registered profile. Does an implicit unidentify.
		Only server operator can unregister others. """

		if caller.level() is operlevel:
			if password and not nick:  # parser might have gotten it wrong
				nick, password = password, nick
			if password:
				raise IrcMsgException(caller, "Server operators should only specify a nickname")
			if not nick:
				raise IrcMsgException(caller, "Server operators must specify a nickname")
			profile = self.find_a_profile_for_nick(caller, nick)
			if profile is caller.profile:
				raise IrcMsgException(caller, "Server operators cannot unregister their own profile")
		else:
			if nick and password:
				profile = self.find_a_profile_for_nick(caller, nick)
				if not profile is caller.profile:
					raise IrcMsgException(caller, "You can only unregister your own profile")
			else:
				if nick and not password:  # parser might have gotten it wrong
					nick, password = password, nick
				profile = caller.profile
			profile.test_password(password)

		user = self.core.users.get_user_for_profile(profile)
		if user:
			user.unidentify()
		self.core.profiles.drop_profile(profile)
		if user:
			self.core.channels.fix_user_on_all_channels(user)

	def cmd_passwd(self, caller, cmd, oldpass, newpass):
		""" registered
		1.6 passwd <oldpass> <newpass>
		Change password for current profile """
		profile = self.core.profiles.find_profile_by_nickname(caller.nick)
		if not profile:
			raise IrcMsgException(caller, "No profile associated with your nick, please identify or register first")
		profile.test_password(oldpass, caller, "error, old password invalid")
		profile.reset_password(newpass)

	def cmd_whoami(self, caller, cmd):
		""" guest
		1.7 whoami
		Show who you are """
		if caller.level() is guestlevel:
			self.notice(caller, "You are %s, an unregistered guest" % caller.nick)
		else:
			self.cmd_whois(caller, cmd, None)

	def cmd_whois(self, caller, cmd, nick):
		""" registered
		1.8 whois [<nick>]
		Show the profile currently associated with your session. """
		if nick and caller.is_confirmed():
			profile = self.find_a_profile_for_nick(caller, nick)

			status = self.online_or_offline(profile)
			firstline = "%s is %s and " % (nick, status)
			leveltxt = str(profile.level)
			firstline += leveltxt + " as " + profile.register_nick
		else:
			if nick and nick.lower() != caller.nick.lower():
				raise IrcMsgException(caller, "You must have a confirmed account to view others")
			profile = caller.profile
			leveltxt = str(profile.level)
			firstline = "You are %s, %s" % (caller.nick, leveltxt)
			if caller.nick != profile.register_nick:
				firstline += " as " + profile.register_nick
		firstline += ", " + self.rolesline(profile)
		self.notice(caller, firstline)
		if profile.is_confirmed():
			self.notice(caller, "Real name: " + (profile.realname or ''))
			self.notice(caller, "Email: " + (profile.email or ''))

	def cmd_help(self, caller, cmd, command, verbose):
		""" guest
		1.9 help [verbose=verbose] [<command*>] 
		Show all commands or show description for specified command.
		"""
		try:
			if command:
				cmd, args = self.commands.parse_cmdline(command, caller, forhelp=True)
				self.notice(caller, cmd.shorthelp + ' ' + str(cmd.args))
				for line in cmd.longhelp.split('\n'):
					self.notice(caller, line.strip())
			else:
				for line in self.commands.get_helplist(caller, bool(verbose)):
					self.notice(caller, line.strip())
		except ParseException, e:
			raise IrcMsgException(caller, str(e))
		except Exception, e:
			import traceback
			traceback.print_exc()
			raise IrcMsgException(caller, str(e))

	def cmd_channel_register(self, caller, cmd, chan):
		""" registered
		2.1 channel register <chan>
		Register an unregistered channel and make you it's channel operator """
		if chan.registered:
			raise IrcMsgException(caller, "Channel '%s' is already registered" % chan.name)
		chan.register()
		chan.set_role(caller, caller.profile, operrole)
		chan.fix_all_users()

	def cmd_channel_unregister(self, caller, cmd, chan):
		""" chanoper
		2.2 channel unregister <chan>
		Undo register_channel """
		if not chan.registered:
			raise IrcMsgException(caller, "Channel '%s' is not registered" % chan.name)
		chan.unregister()

	def cmd_channel_allow(self, oper, cmd, chan, nick):
		""" chanoper
		2.3 channel allow <chan> <nick>
		Allow <nick> on <chan> (only useful if channel policy is set to deny) """
		profile = self.find_a_profile_for_nick(oper, nick)
		chan.set_role(oper, profile, allowrole)
		user = self.core.users.get_user_for_profile(profile)
		if user:
			chan.fix_user_to_role(user)

	def cmd_channel_ban(self, oper, cmd, chan, nick):
		""" chanoper
		2.4 channel ban <chan> <nick>
		Deny <nick> access to <chan> (only useful if channel policy is set to allow) """
		profile = self.find_a_profile_for_nick(oper, nick)
		chan.set_role(oper, profile, banrole)
		user = self.core.users.get_user_for_profile(profile)
		if user:
			chan.fix_user_to_role(user)

	def cmd_channel_oper(self, oper, cmd, chan, nick):
		""" chanoper
		2.5 channel oper <chan> <nick>
		Make <nick> a channel opperator on <chan> """
		profile = self.find_a_profile_for_nick(oper, nick)
		chan.set_role(oper, profile, operrole)
		user = self.core.users.get_user_for_profile(profile)
		if user:
			chan.fix_user_to_role(user)

	def cmd_channel_reset(self, oper, cmd, chan, nick):
		""" chanoper
		2.6 channel reset <chan> <nick>
		Remove any roles for <nick> on <chan> """
		profile = self.find_a_profile_for_nick(oper, nick)
		chan.set_role(oper, profile, None)
		user = self.core.users.get_user_for_profile(profile)
		if user:
			chan.fix_user_to_role(user)

	def cmd_channel_policy(self, oper, cmd, chan, policy):
		""" chanoper
		2.7 channel policy <chan> policy=allow|deny
		Can users without explicit role join or is access denied """

		chan.set_policy(oper, policy)
		chan.fix_all_users()

	def cmd_channel_guests(self, oper, cmd, chan, policy):
		""" chanoper
		2.8 channel guests <chan> policy=allow|deny
		Are unregistered users allowed to join this channel. Guests are allowed on
		a channel if both the channel policy and this setting are 'allow' """
		allow = {"allow":True, "deny":False}[policy]

		# FIXME, this command does not work
		chan.set_allow_guests(oper, allow)
		chan.fix_all_users()

	def cmd_channel_roles(self, oper, cmd, chan):
		""" chanoper
		2.9 channel roles <chan>
		Show the current known roles for channel """
		roles = chan.get_roles(oper)
		if not roles:
			raise IrcMsgException(oper, "No roles defined for %s" % chan.name)

		if chan.allow_guests and chan.default_policy_allow:
			self.notice(
					oper, "%s policy is set to allow and guests are also allowed" %
					chan.name)
		elif not chan.allow_guests and chan.default_policy_allow:
			self.notice(
					oper, "%s policy is set to allow but guests are denied" %
					chan.name)
		elif not chan.default_policy_allow:
			self.notice(
					oper, "%s policy is set to deny" %
					chan.name)

		for profile, role in roles:
			status = self.online_or_offline(profile)
			role = role_as_text(role)
			self.notice(oper, "- %s %s (%s)" % (
				profile.register_nick, role, status))
		self.notice(oper, "total %d role(s) defined for %s" % (
			len(roles), chan.name))

	def cmd_list_channels(self, oper, cmd):
		""" oper
		3.1 list channels
		Show known channels """
		channels = self.core.channels.get_all_channels()
		if not channels:
			raise IrcMsgException(oper, "No channels found!")
		for chan in channels:
			if chan.registered:
				registered = "registered"
			else:
				registered = "not registered"
			self.notice(oper, "- %s %d users (%s)" % (
				chan.name, chan.usercount(), registered))

	def cmd_list_profiles(self, oper, cmd):
		""" oper
		3.2 list profiles
		Show registered profiles """
		all_profiles = self.core.profiles.get_all_profiles()
		for prof in all_profiles:
			status = self.online_or_offline(prof)
			msg = "%s, %s, %s" % (prof.register_nick, status, prof.level)
			if prof.is_confirmed():
				msg += ", %s, %s" % (prof.realname or '', prof.email or '')
			self.notice(oper, "- %s" % msg)
		self.notice(oper, "Total %d registered profiles" % len(all_profiles))

	def cmd_confirm(self, oper, cmd, nick, realname, email):
		""" oper
		3.3 confirm <nick> <realname*> <email>
		Confirm a registered user really is who he says he is """
		profile = self.find_a_profile_for_nick(oper, nick)
		profile.confirm(realname, email)
		user = self.core.users.get_user(nick)
		if user:
			self.core.channels.fix_user_on_all_channels(user)

	def cmd_unconfirm(self, oper, cmd, nick):
		""" oper
		3.4 unconfirm <nick>
		For undoing 'confirm' """
		# FIXME: check if we are not downgrading last serveroper
		profile = self.find_a_profile_for_nick(oper, nick)

		profile.unconfirm()

		user = self.core.users.get_user(nick)
		if user:
			self.core.channels.fix_user_on_all_channels(user)

	def cmd_kill(self, oper, cmd, nick):
		""" oper
		3.5 kill <nick>
		Disconnect someone from the irc server (beware of auto-reconnect) """
		user = self.core.users.get_user(nick)
		if not user:
			raise IrcMsgException(oper, "No such nick '%s'" % nick)
		self.core.users.kill_user(user, "killed by %s" % oper.nick)

	def cmd_reset_pass(self, oper, cmd, nick, newpass):
		""" oper
		3.6 reset pass <nick> <newpass>
		Reset password for a profile """
		profile = self.core.profiles.find_profile_by_nickname(nick)
		if not profile:
			raise IrcMsgException("No profile found for '%s'" % nick)
		profile.reset_password(newpass)

	def cmd_rehash(self, oper, cmd):
		""" oper
		3.7 rehash
		re-read profiles/channels/roles from database and update state """
		self.core.users.notice_serverops("re-reading database")
		self.core.rehash()

	def cmd_restart(self, oper, cmd):
		""" oper
		3.8 restart
		Restart the construct. Use with care. """
		self.core.users.notice_serverops("%s issued restart, brb" % oper.nick)
		raise RestartException()

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

		chan = self.core.channels.get_channel(channame)
		if not chan:
			raise IrcMsgException(user, "Unknown channel '%s'" % channame)
		return (chan, rest)

	def recv(self, caller, msg):
		assert isinstance(caller, User)
		msg = msg.strip()
		try:
			cmd, args = self.commands.parse_cmdline(msg, caller, forhelp=False)
		except ParseException, e:
			raise IrcMsgException(caller, "syntax error, " + str(e))
		except IrcMsgException:
			raise
		except Exception, e:
			log.info("%s failed command %s: %s" % (caller.nick, msg, e))
			self.notice(caller,"internal error")
			raise

		log.debug("%s used command %s(%s)" % (caller.nick, cmd.funcname,
			', '.join("%s=%s" % tup for tup in args.iteritems())))

		cmd.func(self, caller, cmd, **args)
		self.notice(caller, "OK")


def main(configfilename, initial_identified):
	# FIXME: would like to have the configfile in a similar format as ircd.conf
	# FIXME: at least some format that allows comments
	config = json.load(open(configfilename))

	core = Core(config, initial_identified)
	core.run()

