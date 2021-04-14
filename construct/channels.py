from collections import defaultdict
from functools import wraps
import logging

from .consts import operlevel, banrole, allowrole, operrole
from .serverhandler import IrcMsgException


log = logging.getLogger('channels')


def channel_registered(func):
    @wraps(func)
    def wrapper(self, user, *args):
        if not self.registered:
            raise IrcMsgException(
                user, "Channel %s is not registered" % self.name)
        return func(self, user, *args)
    return wrapper


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
        for name, chan in old.items():
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
        return [chan for chan in list(self.channels.values()) if chan.has_user(user)]

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
        return list(self.channels.values())

    def get_registered_channels(self):
        return list(c for c in self.channels.values() if c.registered)


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
                oper, "Invalid channel policy '%s'" % newpolicy)
        self.parent.core.db.update_channel(
            self.name, self.allow_guests, self.default_policy_allow)

    @channel_registered
    def set_role(self, oper, profile, role):
        if not profile:
            raise IrcMsgException(
                oper, "Guest users cannot have roles, must register first")
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
        for profileid, role in self.roles.items():
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
            log.debug(
                "not fixing %s on %s, channel not registered" % (
                    user.nick, self.name))
            return  # not doing anything for channels nobody cares about

        if not self.allow_guests and not user.profile:
            log.debug(
                "removing %s from %s, guests not allowed on channel"
                % (user.nick, self.name))
            self.remove_user(user, "guests not allowed")
            return

        role = self.find_role(user)
        mode = self.users.get(user)
        if mode is None:
            log.debug(
                "not fixing %s on %s, user is not in channel" % (
                    user.nick, self.name))
            return

        if role is banrole:
            log.debug("removing %s from %s, user is banned" %
                      (user.nick, self.name))
            self.remove_user(user, "user not allowed")
        elif role is allowrole:
            if 'o' in mode:
                log.debug(
                    "user %s is not operator on %s, fixing" % (
                        user.nick, self.name))
                self.deop_user(user)
        elif role is operrole:
            if 'o' not in mode:
                log.debug("user %s is operator on %s, fixing" %
                          (user.nick, self.name))
                self.op_user(user)

    def find_role(self, user):
        assert self.registered

        defaultrole = banrole
        if self.default_policy_allow:
            defaultrole = allowrole

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
            log.warn(
                "User %s was already joined to channel %s" % (
                    user.nick, self.name))
            return
        self.users[user] = initial_mode
        log.debug(
            "%s: %s joined: %s"
            % (self.name, user.nick, ', '.join(u.nick for u in self.users)))

        self.fix_user_to_role(user)
        # FIXME: tell user he should identify or register

    def part(self, user):
        if user not in self.users:
            log.warn(
                "User %s parted but was not on channel %s" % (
                    user.nick, self.name))
            return

        del self.users[user]
        log.debug(
            "%s: %s parted: %s"
            % (self.name, user.nick, ', '.join(u.nick for u in self.users)))
        if not self.users:
            self.parent.channel_empty(self)

    def kick(self, user):
        if user not in self.users:
            log.warn(
                "User %s was kicked but was not on channel %s" % (
                    user.nick, self.name))
            return

        del self.users[user]
        log.debug(
            "%s: %s kicked: %s"
            % (self.name, user.nick, ', '.join(u.nick for u in self.users)))
        if not self.users:
            self.parent.channel_empty(self)

    def quit(self, user):
        if user in self.users:
            del self.users[user]
            log.debug(
                "%s: %s logged out, leftover: %s"
                % (self.name, user.nick, ', '.join(u.nick for u in self.users)))
        if not self.users:
            self.parent.channel_empty(self)

    def mode(self, whodidit, user, modechange):
        usermode = set(self.users[user])
        direction = None
        for c in modechange:
            if c in "-+":
                direction = c
                continue
            if direction == '+':
                usermode.add(c)
            elif direction == '-':
                usermode.remove(c)
            else:
                raise Exception(
                    "Invalid mode-pattern '%s' for %s on %s"
                    % (modechange, user.nick, self.name))
        self.users[user] = ''.join(usermode)
        isoper = 'o' in usermode

        try:
            if whodidit and 'o' in modechange and self.registered:
                if self.is_channel_operator(whodidit) and user.profile:
                    if isoper and not self.is_channel_operator(user):
                        self.set_role(whodidit, user.profile, operrole)
                    elif not isoper and self.is_channel_operator(user):
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
        if user not in self.users:
            log.warn(
                "User %s not on channel %s, cannot remove" % (
                    user.nick, self.name))
        log.debug("%s removed %s for %s" % (self.name, user.nick, reason))
        if reason:
            reason = ', ' + reason
        self.send("KICK %s %s :Restricted channel%s" %
                  (self.name, user.nick, reason))
        # FIXME: need temporary ban here, to prevent auto-rejoin
        del self.users[user]

    def send(self, msg):
        self.parent.core.avatar.send(msg)

    def __str__(self):
        return "Channel(%s)" % self.name
