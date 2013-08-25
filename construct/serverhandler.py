import logging
import re
import traceback

from .irc_connection import IrcConnection
from .restartexception import RestartException


log = logging.getLogger('main')


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
usermodere = re.compile(':(\S+) MODE (\S+) ([-+]\S+) (\S+(?: \S+)*)'.replace(' ', '\s+'))
chanmodere = re.compile(':(\S+) MODE (\S+) ([-+]\S+)'.replace(' ', '\s+'))
quitre = re.compile(":(\S+) QUIT :(.*)".replace(' ', '\s+'))
privmsgre = re.compile(":(\S+) PRIVMSG (\S+) :(.*)".replace(' ', '\s+'))
topicre = re.compile(":(\S+) TOPIC (\S+) (.*)".replace(' ', '\s+'))
awayre = re.compile(":(\S+) AWAY(.*)".replace(' ', '\s+'))


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
				(usermodere, self.msg_usermode),
				(chanmodere, lambda x, y, z: 1),
				(quitre, self.msg_quit),
				(privmsgre, self.msg_privmsg),
				(topicre, lambda x, y, z: 1),
				(awayre, lambda x, y: 1)
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

	def msg_usermode(self, chanoper, channame, modechange, nicks):
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


