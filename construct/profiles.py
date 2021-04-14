import base64
import hashlib
import logging
import os
import time

from .consts import registeredlevel, confirmedlevel, operlevel
from .serverhandler import IrcMsgException


log = logging.getLogger('profiles')


class ProfileDB(object):
    def __init__(self, core):
        self.core = core
        self.profiles = list()
        self.next_id = 1

    def rehash(self):
        old = {p.profileid: p for p in self.profiles}
        self.profiles = list()
        self.next_id = 1
        for id_, nick, lvl, pwd, rn, email in self.core.db.get_profiles():
            if id_ >= self.next_id:
                self.next_id = id_ + 1
            prof = old.pop(id_, None)
            if not prof:
                log.info("Rehash: new registered profile: %s" % nick)
                prof = Profile(self, id_, nick, pwd)
            prof.register_nick = nick
            prof.level = lvl
            prof.reset_password(pwd)
            prof.realname = rn
            prof.email = email
            self.profiles.append(prof)

        # any profiles lost from database?
        for prof in old.values():
            log.info("Rehash: removed profile %s" % prof.register_nick)
            user = self.core.users.get_user_for_profile(prof)
            if user:
                log.info(
                    "Rehash: user %s unidentified due to lost profile" % user.nick)
                user.unidentify()

    def find_profile_by_nickname(self, nickname):
        nickname = nickname.lower()
        for p in self.profiles:
            if p.register_nick.lower() == nickname:
                return p

        return None

    def find_profile_by_id(self, profileid):
        for p in self.profiles:
            if p.profileid == profileid:
                return p
        return None

    def create_profile(self, nickname, password):
        assert isinstance(password, str)
        id_ = self.next_id
        self.next_id += 1
        p = Profile(self, id_, nickname, password)
        self.profiles.append(p)
        self.core.db.create_profile(
            p.profileid, p.register_nick, p.level, p.password)
        return p

    def drop_profile(self, profile):
        self.profiles = [p for p in self.profiles if p != profile]
        self.core.db.delete_profile(profile.profileid)

    def get_all_profiles(self):
        return self.profiles


class Profile(object):
    def __init__(self, parent, id_, nickname, password):
        self.parent = parent
        self.profileid = id_
        self.register_nick = nickname
        self.level = registeredlevel  # if we have a profile we are registered
        self.password = None
        self.last_password_failed_time = 0
        self.realname = None
        self.email = None
        assert isinstance(password, str)
        if password[:3] == '$C$':
            self.password = password
        else:
            log.warning(
                "Password for %s was not encrypted. fixing.." % nickname)
            self.reset_password(password)

    @staticmethod
    def getDigest(password, salt=None):
        if not salt:
            salt = base64.b64encode(os.urandom(32)).decode("utf-8")
        assert isinstance(salt, str)
        assert isinstance(password, str)
        if not salt.isascii() or not password.isascii():
            raise Exception("salt and password must be ascii")

        saltbytes = salt.encode("utf-8", "replace")
        password = password.encode("utf-8", "replace")

        digest = hashlib.sha256(saltbytes + password).hexdigest()
        for x in range(0, 100001):
            # yes, we re-hash the hex-encoded value. Leaving this bug to keep
            # old passwords valid
            assert digest.isascii()
            digest = digest.encode("utf-8")
            digest = hashlib.sha256(digest).hexdigest()

        assert isinstance(salt, str)
        assert isinstance(digest, str)
        return salt, digest

    def test_password(self, testpass, caller, msg=None):
        """ will throw on invalid password """
        assert isinstance(testpass, str)
        if not testpass.isascii():
            raise IrcMsgException(caller, "password must be ascii")
        now = time.time()
        timeout = self.parent.core.password_timeout
        if now - self.last_password_failed_time < timeout:
            raise IrcMsgException(
                caller,
                "error, wait %s seconds between password guess attempts" % timeout)
        assert self.password[:3] == '$C$'
        salt, digest = self.password[3:].split('$', 1)
        if digest != Profile.getDigest(testpass, salt)[1]:
            self.last_password_failed_time = now
            if msg is None:
                msg = "error, invalid password for '%s'" % self.register_nick
            raise IrcMsgException(caller, msg)

    def reset_password(self, newpass):
        assert isinstance(newpass, str)
        if newpass[:3] != "$C$":
            salt, hexdigest = Profile.getDigest(newpass)
            newpass = "$C$" + salt + "$" + hexdigest
        if newpass != self.password:
            self.password = newpass
            self.update_db()

    def confirm(self, realname, email):
        if self.level is not operlevel:
            self.level = confirmedlevel
        self.realname = realname
        self.email = email
        self.update_db()

    def unconfirm(self):
        self.level = registeredlevel
        self.realname = None
        self.email = None
        self.update_db()

    def is_confirmed(self):
        return self.level is operlevel or self.level is confirmedlevel

    def update_db(self):
        self.parent.core.db.update_profile(
            self.profileid,
            self.register_nick,
            self.level,
            self.password,
            self.realname,
            self.email)
