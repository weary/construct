import logging

from .consts import guestlevel, operlevel


log = logging.getLogger('users')


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
			profile = self.core.profiles.find_profile_by_nickname(register_nick)
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

