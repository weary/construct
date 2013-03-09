import argparse
import json
import socket
import logging
import re
import time
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


class ChannelDB(object):
	def __init__(self):
		super(ChannelDB, self).__init__()
		self.channels = dict()  # name -> channel

	def get_or_create_channel(self, channelname):
		channel = self.channels.get(channelname)
		if not channel:
			log.info("creating channel %s" % channelname)
			channel = Channel(self, channelname)
			self.channels[channelname] = channel
		return channel

	def channel_empty(self, channel):
		if not channel.registered:
			del self.channels[channel.name]

	def channel_user_quit(self, user):
		channels = list(self.channels.values())
		for chan in channels:
			chan.quit(user)


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

	def set_allow_guests(self, oper, allow_):
		if not self.registered:
			raise IrcMsgException(
					oper.nick,
					"Channel is not registered")

		self.allow_guests = allow_

		self.fix_all_users()

	def set_policy(self, oper, newpolicy):
		if not self.registered:
			raise IrcMsgException(
					oper.nick,
					"Channel is not registered")

		if newpolicy.lower() == "allow":
			self.default_policy_allow = True
		elif newpolicy.lower() == "deny":
			self.default_policy_allow = False
		else:
			raise IrcMsgException(
					oper.nick,
					"Invalid channel policy '%s'" % newpolicy)

		self.fix_all_users()

	def set_role(self, oper, user, role):
		if not self.registered:
			raise IrcMsgException(
					oper.nick,
					"Channel %s is not registered" % self.name)

		profile = user.profile
		if not profile:
			raise IrcMsgException("Guest users cannot have roles, %s must register first" % user.nick)
		self.roles[profile.profileid] = role
		self.fix_user_to_role(user)

	def del_role(self, oper, user):
		self.set_role(user, None)

	def fix_all_users(self):
		users = list(self.users)
		for user in users:
			self.fix_user_to_role(user)

	def fix_user_to_role(self, user):
		# check if a user (who is currently in the channel) is
		# allowed and has the right mode. And correct if wrong

		if not self.registered:
			return

		role = self.find_role(user)
		mode = self.users[user]

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
			return defaultrole
		role = self.roles.get(profile.profileid)
		if not role:
			return defaultrole
		return role

	#def is_allowed(self, user):
	#	# returns (False, reason) or (True, mode)
	#	if not self.allow_guests and user.level is guestlevel:
	#		return (False, "No guests allowed, please register")

	#	role = self.find_role(user)
	#	if role is banrole:
	#		return (False, "Banned")
	#	elif role is allowrole:
	#		return (True, '')
	#	elif role is operrole:
	#		return (True, '+o')
	#	assert False
		
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
		log.debug("%s: %s opped %s" % (self.name, user.nick))
		self.send("MODE %s +o %s" % (self.name, user.nick))

	def deop_user(self, user):
		assert self.registered
		log.debug("%s: %s de-opped %s" % (self.name, user.nick))
		self.send("MODE %s -o %s" % (self.name, user.nick))

	def remove_user(self, user):
		assert self.registered
		log.debug("%s: %s removed %s" % (self.name, user.nick))
		self.send("KICK %s %s :Restricted Channel" % (self.name, user.nick))

	def send(self, msg):
		self.parent.server.construct.send(msg)


class Profile(object):
	def __init__(self, id_, nickname, password):
		self.profileid = id_
		self.aliasses = set([nickname])
		self.level = guestlevel
		self.password = password
		self.realname = nickname  # best guess we have


class ProfileDB(object):
	def __init__(self):
		super(ProfileDB, self).__init__()
		self.profiles = list()

		self.next_id = 1

	def find_profile(self, nickname):
		print "looking for '%s'" % nickname
		for p in self.profiles:
			print "aliasses:", ', '.join(p.aliasses)
			if nickname in p.aliasses:
				return p

		return None

	def create_profile(self, nickname, password):
		id_ = self.next_id
		self.next_id += 1
		p = Profile(id_, nickname, password)
		self.profiles.append(p)
		return p


class UserDB(object):
	def __init__(self):
		super(UserDB, self).__init__()
		self.users = list()

	def get_user(self, needednick, defaultval=None):
		for user in self.users:
			if user.nick == needednick:
				return user
		return defaultval

	def create_user(self, newnick):
		assert self.get_user(newnick) is None
		user = User(newnick)
		self.users.append(user)
		return user

	def remove_user(self, nick):
		assert not self.get_user(nick) is None
		self.users = [
				user for user in self.users
				if user.nick != nick]

	def get_serveropers(self):
		out = []
		for user in self.users:
			profile = user.profile
			if not profile:
				continue
			if profile.level is operlevel:
				out.append(user)
		return out


class User(object):
	def __init__(self, nick):
		self.nick = nick
		self.profile = None

	def nickchange(self, newnick):
		log.debug("%s nickchanged to %s" % (self.nick, newnick))
		self.nick = newnick

	def identify(self, profile):
		if self.profile:
			raise IrcMsgException(
					self.nick,
					"Already identified")
		self.profile = profile


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
			print repr(self.readlinecache)
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

	def msg_sjoin(self, chan, nicks):
		chan = self.server.get_or_create_channel(chan)
		for nick in nicks.split():
			mode = ''
			if nick[:1] == '@':
				mode = 'o'
				nick = nick[1:]
			user = self.server.get_user(nick)
			if not user:
				raise OperMsgException(
						"joining user %s does not exist" % nick)
			chan.join(user, mode)

	def msg_part(self, nick, chan):
		chan = self.server.get_or_create_channel(chan)
		user = self.server.get_user(nick)
		if not user:
			raise OperMsgException(
					"parting user %s does not exist" % nick)
		chan.part(user)

	def msg_kick(self, chan, nick, reason):
		chan = self.server.get_or_create_channel(chan)
		user = self.server.get_user(nick)
		if not user:
			raise OperMsgException(
					"parting user %s does not exist" % nick)
		chan.kick(user)

	def msg_mode(self, chan, modechange, nick):
		chan = self.server.get_or_create_channel(chan)
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
				self.server.construct.tell(e.user, e.msg)
			else:
				log.warning("Unknown user caused exception: %s" % e.msg)
		except OperMsgException, e:
			log.warning(e.msg)
			for user in self.server.get_serveropers():
				user.tell("Exception: %s" % e.msg)

	def read_all(self):
		# read lines until disconnected
		for line in self.con:
			self.parse_line(line)

	def read_until_server_connect(self):
		for line in self.con:
			self.parse_line(line)
			if self.serverstate == "connected":
				return


class Construct(object):
	def __init__(self, server):
		print "creating construct"
		self.server = server
		self.nick = "construct"
		self.description = "Bad ass"

		server.set_construct(self)
		self.commands = (
				("identify", self.cmd_identify),
				("register", self.cmd_register))

	def introduce(self):
		print "introducing construct"
		handler = self.server.handler
		now = int(time.time())
		servername = self.server.name
		msg = "NICK %s 1 %d +io %s %s %s :%s" % (
				self.nick, now, "-", "-",
				servername, self.description)
		handler.send(msg)

	def tell(self, who, msg):
		self.send("NOTICE %s :%s" % (who.nick, msg))

	def send(self, msg):
		handler = self.server.handler
		msg = ":%s %s" % (self.nick, msg)
		handler.send(msg)

	def cmd_identify(self, user, args):
		profile = self.server.find_profile(user.nick)
		if not profile:
			raise IrcMsgException(user, "No profiles registered for %s" % user.nick)
		if profile.password != args.strip():
			print "'%s' and '%s'" % (profile.password,args.strip())
			raise IrcMsgException(user, "Invalid password")
			# FIXME: set timeout before retry
		user.identify(profile)
		self.tell(user, "Successfully identified as %s" % profile.realname)

	def cmd_register(self, user, args):
		profile = self.server.find_profile(user.nick)
		if profile:
			raise IrcMsgException(user, "User %s already registered" % user.nick)
		password = args.strip()
		newprofile = self.server.create_profile(user.nick, password)
		user.identify(newprofile)
		self.tell(user, "Successfully registered %s, please remember your password to identify next time" % user.nick)

	def recv(self, user, msg):
		msg = msg.strip().split(' ', 1)
		if len(msg) > 1:
			cmd, args = msg
		else:
			cmd, args = msg[0], ''
		cmd = cmd.lower()
		for cmd_, func in self.commands:
			if cmd == cmd_:
				func(user, args.strip())
				return
		self.tell(user, "nah")


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
	print "after connect"

	construct = Construct(server)
	construct.introduce()
	hand.read_all()


