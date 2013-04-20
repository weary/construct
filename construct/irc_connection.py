import logging
import socket


log = logging.getLogger('connection')


class IrcConnection(object):
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

