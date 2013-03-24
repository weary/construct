
import socket
import thread
import time
import sys

server = ('127.0.0.1', 6667)

class TestUser(object):
	def __init__(self, nick, username, realname):
		self.socket = socket.create_connection(server)
		self.nick = nick
		self.username = username
		self.disco = False

		self.out = open("%s.log" % nick, "w")
		self.lines = []
		self.linelock = thread.allocate_lock()
		self.printlock = thread.allocate_lock()
		thread.start_new_thread(self.recv, ())

		self.send("USER %s %s %s %s" % (
			username, 'testhost', server[0], realname))
		self.send("NICK %s" % self.nick)
		self.wait_for_line(":sin 001")

	def send(self, line):
		printline = "<- %s: %s" % (self.nick, line)
		print >>self.out, printline
		self.out.flush()
		with self.printlock:
			print printline
		self.socket.send(line + '\n')

	def recv(self):
		try:
			olddata = ''
			while 1:
				newdata = self.socket.recv(100)
				data = olddata + newdata

				lines = data.split('\n')
				olddata = lines[-1]
				del lines[-1]
				lines = [l.rstrip('\r') for l in lines]
				for l in lines:
					print >>self.out, "-> %s: %s" % (self.nick, l)
				self.out.flush()
				#with self.printlock:
				#	for l in lines:
				#		print "-> %s: %s" % (self.nick, l)
				with self.linelock:
					#for line in lines:
					#	print >>self.out, "adding line:", line
					self.lines.extend(lines)

				if newdata == '':
					break
		finally:
			print "%s read thread terminated" % self.nick
			self.disco = True

	def msg(self, who, what):
		self.send(":%s PRIVMSG %s :%s" % (
			self.nick, who, what))

	def nickchange(self, newnick):
		self.send(":%s NICK %s" % (
			self.nick, newnick))
		self.nick = newnick

	def quit(self, reason):
		self.clearlines()
		self.send(":%s QUIT :%s" % (self.nick, reason))

	def join(self, channel):
		self.clearlines()
		self.send(":%s JOIN %s" % (self.nick, channel))
		self.wait_for_line(":%s!%s@i.love.debian.org JOIN :%s" % (
			self.nick, self.username, channel))

	def part(self, channel):
		self.clearlines()
		self.send(":%s PART %s" % (self.nick, channel))

	def kick(self, channel, who):
		self.clearlines()
		self.send(":%s KICK %s :%s" % (self.nick, channel, who))

	def clearlines(self):
		with self.linelock:
			#for line in self.lines:
			#	print >>self.out, "throwing out:", line
			self.lines = []

	def cmd(self, cmd, ignore_result=False):
		self.clearlines()
		self.send(":%s PRIVMSG construct :%s" % (self.nick, cmd))
		if not ignore_result:
			prefix = ":construct!-@- NOTICE %s :OK" % self.nick
			self.wait_for_line(prefix)

	def names(self, channel):
		self.clearlines()
		self.send(":%s NAMES %s" % (self.nick, channel))
		prefix = ":sin 353 %s = %s :" % (self.nick, channel)
		result = self.wait_for_line(prefix)
		result = set(result[len(prefix):].split(' '))
		return result

	def wait_for_line(self, linestart):
		prev_linecount = 0
		print >>self.out, "looking for:", linestart
		while 1:
			time.sleep(0.1)
			with self.linelock:
				for i in xrange(prev_linecount, len(self.lines)):
					line = self.lines[i]
					#print >>self.out, "checking:", line
					if line.startswith(linestart):
						#print >>self.out, "match!"
						del self.lines[i]
						return line
				prev_linecount = len(self.lines)

	def wait(self):
		while not self.disco:
			time.sleep(0.1)

def assert_set(s1, s2):
	if s1 != s2:
		print s1, "!=", s2
	assert s1 == s2

if __name__ == "__main__":
	print "remember! you need to have a 'serveroper' profile with password 'serveroperpass'"
	serveroper = TestUser("sErveroper", "serverope1", "ServerOper")

	serveroper.cmd("id serveroperpass")
	serveroper.cmd("unregister user chanoper", True)
	serveroper.wait_for_line(":construct!-@- NOTICE %s :" % serveroper.nick)
	serveroper.cmd("unregister user allowed", True)
	serveroper.wait_for_line(":construct!-@- NOTICE %s :" % serveroper.nick)
	serveroper.cmd("unregister user banned", True)
	serveroper.wait_for_line(":construct!-@- NOTICE %s :" % serveroper.nick)
	serveroper.cmd("channel unregister #testchan", True)
	serveroper.wait_for_line(":construct!-@- NOTICE %s :" % serveroper.nick)

	chanoper = TestUser("cHanoper", "chanoper1", "ChanOper")
	guest = TestUser("gUest", "guest1", "Guest")
	allowed = TestUser("aLlowed", "allowed1", "Allowed")
	banned = TestUser("bAnned", "banned1", "Banned")
	everyone = [serveroper, chanoper, guest, allowed, banned]

	serveroper.join("#soonempty")
	serveroper.part("#soonempty")

	allowed.cmd("register user allowedpass")
	banned.cmd("register user bannedpass")

	chanoper.cmd("register user chanoperpass")
	serveroper.cmd("confirm %s Channel -Confirmed- Operator chanoper@someemail" % chanoper.nick)
	chanoper.cmd("whoami")
	chanoper.wait_for_line(":construct!-@- NOTICE cHanoper :You are cHanoper, confirmed, no defined roles")
	chanoper.wait_for_line(":construct!-@- NOTICE cHanoper :Real name: Channel -Confirmed- Operator")
	chanoper.wait_for_line(":construct!-@- NOTICE cHanoper :Email: chanoper@someemail")
	chanoper.cmd("whois chanoper")
	chanoper.wait_for_line(":construct!-@- NOTICE cHanoper :chanoper is online and confirmed as cHanoper, no defined roles")
	chanoper.wait_for_line(":construct!-@- NOTICE cHanoper :Real name: Channel -Confirmed- Operator")
	chanoper.wait_for_line(":construct!-@- NOTICE cHanoper :Email: chanoper@someemail")

	chanoper2 = TestUser("chAnoper_", "chanoper2", "ChanOper")
	chanoper2.cmd("id chanoper chanoperpass")
	everyone.append(chanoper2)
	chanoper = chanoper2
	chanoper.nickchange("cHanoper")

	serveroper.cmd("confirm %s stomme naam fout@email" % allowed.nick)
	serveroper.cmd("unconfirm %s" % allowed.nick)

	chanoper.join("#testchan")
	chanoper.cmd("channel register #testchan")

	# no roles/policy/etc, everyone can join
	guest.join('#testchan')
	chanoper.wait_for_line(":gUest!guest1@i.love.debian.org JOIN :#testchan")
	allowed.join('#testchan')
	chanoper.wait_for_line(":aLlowed!allowed1@i.love.debian.org JOIN :#testchan")
	banned.join('#testchan')
	chanoper.wait_for_line(":bAnned!banned1@i.love.debian.org JOIN :#testchan")
	assert chanoper.names('#testchan') == set(
			['gUest', 'aLlowed', 'bAnned', '@cHanoper'])

	chanoper.part('#testchan')
	chanoper.join('#testchan')
	chanoper.wait_for_line(":construct!-@- MODE #testchan +o cHanoper")
	assert chanoper.names('#testchan') == set(
			['gUest', 'aLlowed', 'bAnned', '@cHanoper'])

	chanoper.kick('#testchan', chanoper.nick)
	chanoper.join('#testchan')

	chanoper.cmd("channel guests #testchan deny")
	guest.wait_for_line(":construct!-@- KICK #testchan gUest :Restricted channel")
	chanoper.wait_for_line(":construct!-@- KICK #testchan gUest :Restricted channel")
	guest.join('#testchan')
	guest.wait_for_line(":construct!-@- KICK #testchan gUest :Restricted channel")
	chanoper.wait_for_line(":construct!-@- KICK #testchan gUest :Restricted channel")

	chanoper.cmd("channel ban #testchan banned")
	banned.wait_for_line(":construct!-@- KICK #testchan bAnned :Restricted channel")
	chanoper.wait_for_line(":construct!-@- KICK #testchan bAnned :Restricted channel")
	banned.join('#testchan')
	banned.wait_for_line(":construct!-@- KICK #testchan bAnned :Restricted channel")
	chanoper.wait_for_line(":construct!-@- KICK #testchan bAnned :Restricted channel")

	chanoper.cmd("channel policy #testchan deny")
	allowed.wait_for_line(":construct!-@- KICK #testchan aLlowed :Restricted channel")
	chanoper.wait_for_line(":construct!-@- KICK #testchan aLlowed :Restricted channel")
	assert chanoper.names('#testchan') == set(['@cHanoper'])
	chanoper.cmd("channel allow #testchan allowed")
	allowed.join('#testchan')
	chanoper.wait_for_line(":aLlowed!allowed1@i.love.debian.org JOIN :#testchan")
	assert chanoper.names('#testchan') == set(['@cHanoper', 'aLlowed'])
	chanoper.cmd("channel oper #testchan allowed")
	chanoper.cmd("channel allow #testchan chanoper")
	chanoper.wait_for_line(":construct!-@- MODE #testchan -o cHanoper")
	serveroper.cmd("whois chanoper")
	serveroper.wait_for_line(":construct!-@- NOTICE sErveroper :chanoper is online and confirmed as cHanoper, allowed in #testchan")
	serveroper.cmd("whois allowed")
	serveroper.wait_for_line(":construct!-@- NOTICE sErveroper :allowed is online and registered as aLlowed, oper in #testchan")
	serveroper.cmd("whois banned")
	serveroper.wait_for_line(":construct!-@- NOTICE sErveroper :banned is online and registered as bAnned, banned in #testchan")
	allowed.cmd("channel reset #testchan chanoper")

	serveroper.cmd("list profiles")
	serveroper.cmd("list channels")
	serveroper.wait_for_line(":construct!-@- NOTICE sErveroper :- #testchan 1 users (registered)")
	serveroper.cmd("channel roles #testchan")
	chanoper.cmd("channel roles #testchan", True)
	chanoper.wait_for_line(":construct!-@- NOTICE cHanoper :'cHanoper' is not channel operator on '#testchan'")

	allowed.cmd("channel roles #testchan")
	assert allowed.names('#testchan') == set(['@aLlowed'])

	allowed.cmd("channel unregister #testchan")
	serveroper.cmd("list channels")
	serveroper.wait_for_line(":construct!-@- NOTICE sErveroper :- #testchan 1 users (not registered)")


	serveroper.cmd("kill banned")

	serveroper.cmd("help")
	serveroper.cmd("help list channels")


	print
	print "---------------end---------------------"
	print
	for u in everyone:
		u.quit("end of test")
	for u in everyone:
		u.wait()
	sys.exit(0)
	user2 = TestUser("user2", "testuser2", "TestUser2")
	user2.wait_for_line(":sin 001")
	user2.msg("construct", "register otherpass")

	time.sleep(0.5)
	print "-----------------------"

	user1 = TestUser("user1", "testuser1", "TestUser1")
	user1.wait_for_line(":sin 001")
	user1.msg(user2.nick, "hoi! ik ben er ook!")
	user1.msg("construct", "identify mypass")
	user1.msg("construct", "add #aap2 user2 ban")
	user1.join("#aap2")
	user1.msg("#aap2", "ik mag er weer in!")
	user1.quit("no reason again")

	time.sleep(0.5)
	print "-----------------------"

	user2.join("#aap2")
	time.sleep(0.5)
	user2.msg("#aap2", "maar ik mag er ook in")
	user2.quit("bla")

