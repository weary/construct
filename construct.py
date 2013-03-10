import argparse
import json
import socket
import logging
import re
import time
import traceback
from functools import wraps
log = logging.getLogger('construct')

# for profile's
guestlevel = object()
registeredlevel = object()
confirmedlevel = object()
operlevel = object()

# for channels
banrole = object()
allowrole = object()
operrole = object()

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
		return "ban"
	elif role is allowrole:
		return "allow"
	elif role is operrole:
		return "oper"
	else:
		assert False

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


class Channel(object):
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

	def unregister(self):
		self.registered = False
		if not self.users:
			self.parent.channel_empty(self)

	def has_user(self, user):
		return user in self.users

	def usercount(self):
		return len(self.users)

	def set_allow_guests(self, oper, allow_):
		if not self.registered:
			raise IrcMsgException(
					oper,
					"Channel is not registered")

		self.allow_guests = allow_

		#self.fix_all_users()

	def set_policy(self, oper, newpolicy):
		if not self.registered:
			raise IrcMsgException(
					oper,
					"Channel is not registered")

		if newpolicy.lower() == "allow":
			self.default_policy_allow = True
		elif newpolicy.lower() == "deny":
			self.default_policy_allow = False
		else:
			raise IrcMsgException(
					oper,
					"Invalid channel policy '%s'" % newpolicy)

		#self.fix_all_users()

	def set_role(self, oper, user, role):
		if not self.registered:
			raise IrcMsgException(
					oper,
					"Channel %s is not registered" % self.name)

		profile = user.profile
		if not profile:
			raise IrcMsgException(oper, "Guest users cannot have roles, %s must register first" % user.nick)
		self.roles[profile.profileid] = role
		#self.fix_user_to_role(user)

	def del_role(self, oper, user):
		self.set_role(user, None)

	def get_roles(self, oper):
		if not self.registered:
			raise IrcMsgException(
					oper,
					"Channel %s is not registered" % self.name)

		out = []
		for profileid, role in self.roles.iteritems():
			profile = self.parent.find_profile_by_id(profileid)
			out.append((profile, role))

		return out

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

		role = self.find_role(user)
		mode = self.users.get(user)
		if mode is None:
			print "fixing - user not in channel"
			return

		print "fixing - role =", role_as_text(role)
		print "fixing - mode =", mode
		if role is banrole:
			self.remove_user(user)
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

		self.users.discard(user)
		log.debug("%s: %s kicked: %s" % (
			self.name, user.nick, ', '.join(u.nick for u in self.users)))
		if not self.users:
			self.parent.channel_empty(self)

	def quit(self, user):
		if user in self.users:
			self.users.discard(user)
			log.debug("%s: %s logged out: %s" % (
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

	def remove_user(self, user):
		assert self.registered
		log.debug("%s removed %s" % (self.name, user.nick))
		self.send("KICK %s %s :Restricted Channel" % (self.name, user.nick))
		self.users.discard(user)

	def send(self, msg):
		self.parent.construct.send(msg)


class Profile(object):
	def __init__(self, id_, nickname, password):
		self.profileid = id_
		self.aliasses = set([nickname])
		self.level = registeredlevel  # if we have a profile we are registered
		self.password = password
		self.realname = nickname  # best guess we have
		self.email = ''

	def test_password(self, password):
		return self.password == password

	def reset_password(self, newpass):
		self.password = newpass

	def confirm(self, realname, email):
		self.level = confirmedlevel
		self.realname = realname
		self.email = email

	def unconfirm(self):
		self.level = registeredlevel
		self.realname = self.aliasses[0]
		self.email = ''


class ProfileDB(object):
	def __init__(self):
		super(ProfileDB, self).__init__()
		self.profiles = list()

		self.next_id = 1

	def find_profile(self, nickname):
		for p in self.profiles:
			if nickname in p.aliasses:
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
		p = Profile(id_, nickname, password)
		self.profiles.append(p)
		return p

	def drop_profile(self, profile):
		self.profiles = [p for p in self.profiles
				if p != profile]

	def get_all_profiles(self):
		return self.profiles


class UserDB(object):
	# FIXME: this class should not be case-sensitive
	def __init__(self):
		super(UserDB, self).__init__()
		self.users = list()

	def get_user(self, needednick, defaultval=None):
		#print "looking for user '%s', current users: %s" % (
		#		needednick, ', '.join(u.nick for u in self.users))
		for user in self.users:
			if user.nick == needednick:
				return user
		return defaultval

	def create_user(self, newnick):
		assert self.get_user(newnick) is None
		user = User(newnick)
		self.users.append(user)
		#print "created user '%s', current users: %s" % (
		#		user.nick, ', '.join(u.nick for u in self.users))
		return user

	def remove_user(self, nick):
		assert not self.get_user(nick) is None
		self.users = [
				user for user in self.users
				if user.nick != nick]
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

	def kill_user(self, user):
		self.send("KILL %s :ghost" % user.nick)
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


class Server(UserDB, ChannelDB, ProfileDB):
	def __init__(self, name, description):
		super(Server, self).__init__()
		self.name = name
		if name.find('.') < 0:
			raise Exception("server name('%s') must contain a dot" % name)
		self.description = description
		self.handler = None
		self.construct = None

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
		self.socket = socket.create_connection(
				(self.host, self.port))

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
		self.server.channel_user_quit(who)
		self.server.remove_user(who)

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

# decorator
def needs_profile(func):
	@wraps(func)
	def find_profile(self, user, *args):
		profile = self.server.find_profile(user.nick)
		if not profile:
			raise IrcMsgException(user, "No profiles registered for %s" % user.nick)
		func(self, user, profile, *args)
	return find_profile

def needs_channel(func):
	@wraps(func)
	def find_channel(self, user, cmd, args):
		chan, rest = self.extract_channel_from_args(user, args)
		func(self, user, chan, cmd, rest)
	return find_channel

def test_arg_as_password(func):
	@wraps(func)
	def test_arg_password(self, user, profile, cmd, args):
		if not profile.test_password(args.strip()):
			# FIXME: set timeout before retry
			raise IrcMsgException(user, "Invalid password")
		func(self, user, profile, cmd)
	return test_arg_password

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

	@needs_profile
	@test_arg_as_password
	@fix_user_on_channels_afterwards
	def cmd_identify(self, user, profile, cmd):
		""" guest identify <password>
		Tell the server who you are, binding an earlier
		registered profile to your current session """
		self.notice(user, "Successfully identified as %s" % profile.realname)

		# someone else already using this profile??
		user_ = self.server.get_user_for_profile(profile)
		if user_ and not user_ is user:
			self.server.kill(user_, "new user identified")

		user.identify(profile)
		if profile.level is operlevel:
			self.server.notice_serverops(
					"%s just became server operator" % user.nick)

	@fix_user_on_channels_afterwards
	@no_leftover_arguments
	def cmd_unidentify(self, user, cmd):
		""" registered
		unidentify <password>
		Stop associating your current profile with this
		session. Probably only usefull in debugging """
		user.unidentify()

	@fix_user_on_channels_afterwards
	def cmd_register_user(self, user, cmd, args):
		""" guest
		register_user <password>
		Create a new profile for the current user """
		profile = self.server.find_profile(user.nick)
		if profile:
			raise IrcMsgException(user, "User %s already registered" % user.nick)

		password = args.strip()
		if not password:
			raise IrcMsgException(user, "Please specify password")
		newprofile = self.server.create_profile(user.nick, password)
		self.notice(user, "Successfully registered %s, please remember your password to identify next time" % user.nick)
		user.identify(newprofile)

	@needs_profile
	@test_arg_as_password
	@fix_user_on_channels_afterwards
	def cmd_unregister_user(self, user, profile, cmd):
		""" registered
		unregister_user <password>
		Destroy registered profile. Does an implicit unidentify"""

		assert user == self.server.get_user_for_profile(profile)
		user.unidentify()
		self.server.drop_profile(profile)
		
	def cmd_force_unregister(self, oper, cmd, args):
		""" oper
		force_unregister <nick>
		Destroy profile for given user """
		nick = args.strip()
		if not nick:
			raise IrcMsgException(oper, "Missing nickname")
		profile = self.server.find_profile(nick)
		if not profile:
			raise IrcMsgException(oper, "No profile found for '%s'" % nick)

		user_ = self.server.get_user_for_profile(profile)
		if user_:
			user_.unidentify()
			self.server.fix_user_on_all_channels(user_)
		self.server.drop_profile(profile)

	def cmd_reset_pass(self, oper, cmd, args):
		""" oper
		reset_pass <nick> <newpass>
		Change password for a profile """
		try:
			nick, newpass = args.strip().split(' ')
		except ValueError:
			raise IrcMsgException("Invalid arguments, need nickname and new password")

		profile = self.server.find_profile(nick)
		if not profile:
			raise IrcMsgException("No profile found for '%s'" % nick)
		profile.reset_password(newpass)

	@needs_profile
	def cmd_passwd(self, user, profile, cmd, args):
		""" registered
		passwd <oldpass> <newpass>
		Change password for current profile """
		profile = user.profile
		try:
			oldpass, newpass = args.split(' ')
		except ValueError:
			raise IrcMsgException("Need old password and new password")
		if not profile.test_password(oldpass):
			raise IrcMsgException("Old password invalid")
		profile.reset_password(newpass)

	def cmd_confirm(self, oper, cmd, args):
		""" oper
		confirm <nick> <realname> <email>
		Confirm a registered user really is who he says he is """
		r = re.match('(\S+)\s+(.*)\s+(\S+@\S+)', args.strip())
		if not r:
			raise IrcMsgException(oper, "need: <nick> <realname> <email>")
		nick, realname, email = r.groups()

		profile = self.server.find_profile(nick)
		if not profile:
			raise IrcMsgException(oper, "No profile found for '%s'" % nick)

		profile.confirm(realname, email)
		user = self.server.get_user(nick)
		if user:
			self.server.fix_user_on_all_channels(user)

	def cmd_unconfirm(self, oper, cmd, args):
		""" oper
		unconfirm <nick>
		For undoing 'confirm' """
		nick = args.strip()
		profile = self.server.find_profile(nick)
		if not profile:
			raise IrcMsgException(oper, "No profile found for '%s'" % nick)

		profile.unconfirm()

		user = self.server.get_user(nick)
		if user:
			self.server.fix_user_on_all_channels(user)

	def cmd_show_profile(self, user, cmd, args):
		""" registered
		show_profile [<nick>]
		Show the profile currently associated with your session. Server operators
		can use the extended version of this command and specify a nick """
		nick = args.strip()
		if user.profile.level is operlevel and nick:
			profile = self.server.find_profile(nick)
			if not profile:
				raise IrcMsgException(user, "No profile for nick '%s'" % nick)
			self.notice(user, "Profile for %s:" % nick)
		else:
			if args:
				raise IrcMsgException(user, "Too many arguments, you are not allowed to specify a nickname")
			profile = user.profile
			self.notice(user, "Your profile:")
		self.notice(user, "Known aliasses: " + make_list(profile.aliasses, "and"))
		self.notice(user, "Level: " + level_as_text(profile.level))
		self.notice(user, "Real name: " + profile.realname)
		self.notice(user, "Email: " + profile.realname)

	@no_leftover_arguments
	def cmd_restart(self, user, cmd):
		""" oper
		restart
		Restart the construct. Use with care. """
		raise RestartException()

	@needs_channel
	@no_leftover_arguments
	def cmd_register_channel(self, user, chan, cmd):
		""" registered
		register_channel <chan>
		Register an unregistered channel and make you it's channel operator """
		if chan.registered:
			raise IrcMsgException(user, "Channel '%s' is already registered" % chan.name)
		chan.register()
		chan.set_role(user, user, operrole)
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
	def cmd_roles(self, user, chan, cmd):
		""" chanoper
		roles <chan>
		Show the current known roles for channel """
		roles = chan.get_roles(user)
		if not roles:
			raise IrcMsgException(user, "No roles defined for %s" % chan.name)

		for profile, role in roles:
			user = self.server.get_user_for_profile(profile)
			if user:
				nick = user.nick
				online = "online"
			else:
				nick = profile.aliasses[0]
				online = "offline"
			role = role_as_text(role)
			self.notice(user, "%s %s %s (%s)" % (chan.name, nick, role, online))

	@needs_channel
	def cmd_add(self, oper, chan, cmd, args):
		""" chanoper
		add <chan> <nick> ban|allow|oper
		Allow <nick> on <chan> (if policy is set to deny)
		or ban <nick> from <chan> (if policy is set to accept)
		or make <nick> a channel operator on <chan>"""
		r = re.match(args, "\s*(\S*)\s+(ban|allow|oper)\s*$", args)
		if not r:
			raise IrcMsgException(oper, "Argument error, need nick and 'ban', 'allow' or 'oper'")
		nick, newrole = r.groups()
		user = self.server.get_user(nick)
		if not user:
			raise IrcMsgException(oper, "No such nick '%s'" % nick)
		newrole = {'ban': banrole, 'allow': allowrole, 'oper': operrole}[newrole]
		chan.set_role(oper, user, newrole)
		chan.fix_user_to_role(user)

	@needs_channel
	def cmd_del(self, oper, chan, cmd, args):
		""" chanoper
		del <chan> <nick>
		delete a role for a given user from a channel"""
		nick = args.strip()
		user = self.server.get_user(nick)
		if not user:
			raise IrcMsgException(oper, "No such nick '%s'" % nick)
		chan.del_role(oper, user)
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

		chan.set_allow_guests(oper, allow)
		chan.fix_all_users()

	def cmd_chan_policy(self, user, chan, args):
		pass

	def cmd_profiles(self, user, args):
		for prof in self.server.get_all_profiles():
			user = self.server.get_user_for_profile(profile)
			if user:
				nick = user.nick
				online = "online"
			else:
				nick = profile.aliasses[0]
				online = "offline"
			level = level_as_text(prof.level)
			self.notice(user, "- %s %s (%s)" % (nick, level, online))

	def cmd_channels(self, user, args):
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
			raise IrcMsgException(user, "Unknown command")
		elif len(funcs) > 1:
			raise IrcMsgException(user, "Non-unique command, choose: " + make_list(
				(tup[0] for tup in funcs), "or"))

		cmd_, minlevel, func, docu = funcs[0]
		self.test_authorisation(user, minlevel, cmd_, args)

		func(self, user, cmd, args.strip())

		self.notice(user, "OK")


if __name__ == "__main__":
	FORMAT = '#%(message)s'
	logging.basicConfig(level=logging.DEBUG, format=FORMAT)

	parser = argparse.ArgumentParser(description='(More) secure irc user management')
	parser.add_argument('--config', '-c', type=str, help='config file', required=True)
	args = parser.parse_args()

	config = json.load(open(args.config))
	server = Server(**config['server'])

	profile = server.create_profile("weary", "aap")
	profile.realname = "Hylke"
	profile.level = operlevel

	hand = Handler(server, **config['connect'])
	hand.connect()
	hand.read_until_server_connect()

	construct = Construct(server, **config['construct'])
	construct.introduce()
	hand.read_all()


