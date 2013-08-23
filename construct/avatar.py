from collections import defaultdict
from copy import copy
from functools import wraps
import logging
import time

from .commandcontainer import CommandContainer, ParseException
from .consts import \
		guestlevel, registeredlevel, confirmedlevel, operlevel, \
		banrole, allowrole, operrole
from .restartexception import RestartException
from .serverhandler import IrcMsgException


log = logging.getLogger('avatar')

def role_as_text(role):
	if role is banrole:
		return "banned"
	elif role is allowrole:
		return "allowed"
	elif role is operrole:
		return "oper"
	else:
		assert False

def sort(container):
	c = copy(container)
	c.sort()
	return c

def fix_caller_afterwards(func):
	@wraps(func)
	def fix_user_afterwards_wrapper(self, user, *args1, **args2):
		func(self, user, *args1, **args2)
		self.core.channels.fix_user_on_all_channels(user)
	return fix_user_afterwards_wrapper

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
		for chan in self.core.channels.get_registered_channels():
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
			profile.test_password(password, caller)

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
		if user:  # this shouln'd change anything
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
		for chan in self.core.channels.get_registered_channels():
			chan.fix_all_users()

	def cmd_restart(self, oper, cmd):
		""" oper
		3.8 restart
		Restart the construct. Use with care. """
		self.core.users.notice_serverops("%s issued restart, brb" % oper.nick)
		raise RestartException()

	def recv(self, caller, msg):
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

