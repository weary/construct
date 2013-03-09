
import socket
import thread
import time

server = ('127.0.0.1', 6667)

class TestUser(object):
	def __init__(self, nick, username, realname):
		self.socket = socket.create_connection(server)
		self.nick = nick
		self.disco = False

		self.lines = []
		self.linelock = thread.allocate_lock()
		thread.start_new_thread(self.recv, ())

		self.send("USER %s %s %s %s" % (
			username, 'testhost', server[0], realname))
		self.send("NICK %s" % self.nick)

	def send(self, line):
		print "<- %s: %s" % (self.nick, line)
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
					print "-> %s: %s" % (self.nick, l)
				with self.linelock:
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
		self.send(":%s QUIT :%s" % (self.nick, reason))

	def join(self, channel):
		self.send(":%s JOIN %s" % (self.nick, channel))

	def part(self, channel):
		self.send(":%s PART %s" % (self.nick, channel))

	def wait_for_line(self, linestart):
		while 1:
			time.sleep(0.1)
			with self.linelock:
				while self.lines:
					line = self.lines[0]
					del self.lines[0]
					if line.startswith(linestart):
						return

	def wait(self):
		while not self.disco:
			time.sleep(0.1)


if __name__ == "__main__":
	user1 = TestUser("user1", "testuser1", "Test User 1")
	user1.wait_for_line(":sin 001")
	user1.msg("construct", "register mypass")
	user1.msg("construct", "register-channel #aap2")
	user1.join("#aap2")
	user1.msg("#aap2", "ik mag er in!")
	user1.part("#aap2")
	user1.quit("no reason")
	user1.wait()

	user2 = TestUser("user2", "testuser2", "Test User 2")
	user2.wait_for_line(":sin 001")
	user2.msg("construct", "register otherpass")

	time.sleep(0.5)
	print "-----------------------"

	user1 = TestUser("user1", "testuser1", "Test User 1")
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

