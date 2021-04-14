import logging

from .consts import guestlevel, operlevel


log = logging.getLogger('users')


class UserDB(object):
    def __init__(self, core):
        self.core = core
        self.users = list()

    def get_user_by_uid(self, needed_uid, defaultval=None):
        print("XXXXX needed_uid = %r" % needed_uid)
        assert needed_uid.startswith("0")
        for user in self.users:
            if user.uid == needed_uid:
                return user
        return defaultval

    def get_user_by_nick_yes_really(self, needednick, defaultval=None):
        # irc supports sending messages to users on specific networks. we
        # don't
        needednick = needednick.split("@")[0]

        needednick = needednick.lower()
        for user in self.users:
            print("%r == %r" % (user.nick, needednick))
            if user.nick.lower() == needednick:
                return user
        return defaultval

    def create_user(self, newnick, username, uid):
        assert self.get_user_by_uid(uid) is None
        user = User(newnick, username, uid)
        self.users.append(user)
        register_nick = self.core.can_auto_identify(newnick)
        if register_nick is not None:
            log.info(
                "startup: user '%s' automatically identified with profile '%s'"
                % (newnick, register_nick))
            profile = self.core.profiles.find_profile_by_nickname(
                register_nick)
            user.identify(profile)
        return user

    def remove_user(self, user):
        assert isinstance(user, User)
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
            if user.profile
        ]

    def privmsg_serverops(self, msg):
        for user in self.get_serveropers():
            self.core.avatar.privmsg(user, msg)

    def notice_serverops(self, msg):
        log.info("notice_serverops: %s", msg)
        for user in self.get_serveropers():
            self.core.avatar.notice(user, msg)

    def kill_user(self, user, reason):
        log.info("User %s killed, %s", user.nick, reason)
        self.core.shandler.send("KILL %s :HOP %s" % (user.nick, reason))
        self.remove_user(user)


class User(object):
    def __init__(self, nick, username, uid):
        assert isinstance(nick, str)
        assert isinstance(username, str)
        assert isinstance(uid, str)
        self.nick = nick
        self.profile = None
        self.username = username
        self.uid = uid

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
