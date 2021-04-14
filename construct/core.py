import logging
import time

from .avatar import Avatar
from .channels import ChannelDB
from .consts import operlevel
from .database import ConstructDatabase
from .profiles import ProfileDB
from .restartexception import RestartException
from .serverhandler import ServerHandler
from .users import UserDB


log = logging.getLogger('core')


class Core(object):
    def __init__(self, conf, initial_identified):
        self.shandler = ServerHandler(
            self,
            conf['connect']['send_password'],
            conf['connect']['accept_password'],
            conf['connect']['host'],
            conf['connect']['port'],
            conf['server']['name'],
            conf['server'].get('serverid', '0CO'),
            conf['server'].get('description', ''))
        self.channels = ChannelDB(self)
        self.profiles = ProfileDB(self)
        self.users = UserDB(self)

        self.db = ConstructDatabase(conf.get('db', "construct.db"))
        self.password_timeout = conf.get('password_timeout', 30)
        self.initial_identified = dict(initial_identified)

        self.avatar = Avatar(
            self,
            conf['service']['nick'],
            conf['service'].get('description'))

        self.rehash()  # read initial state from database

        for oper in conf.get('opers', []):  # insert initial user into database
            profile = self.profiles.find_profile_by_nickname(oper['nick'])
            if not profile:
                profile = self.profiles.create_profile(
                    oper['nick'], oper['password'])
            profile.level = operlevel
            profile.realname = oper.get('realname', '')
            password = oper['password']
            profile.reset_password(password)
            profile.update_db()

    def run(self):
        self.in_startup_timer = time.time()

        self.shandler.connect()
        try:
            self.shandler.read_until_server_connect()
            log.info("server connected")

            # server has told us all current operators/bans, now fix them
            for chan in self.channels.get_registered_channels():
                chan.fix_all_users()
            log.info("initial fix for known channels/users done")

            # ok, lets join in
            self.avatar.introduce()

            self.shandler.read_all()
        except RestartException as e:
            e.identified_users = self.users.get_identified_users()
            raise
        finally:
            self.shandler.disconnect()

    def in_startup(self):
        if self.in_startup_timer is None:
            return False
        if time.time() > self.in_startup_timer + 10:
            self.finish_startup()
            return False
        return True

    def can_auto_identify(self, newnick):
        """ returns registered_nick from profile if allowed, None otherwise """
        if not self.in_startup():
            return None
        return self.initial_identified.get(newnick)

    def finish_startup(self):
        self.in_startup_timer = None
        msg = "finished starting"
        msg += ", received %d users and %d channels from server" % (
            len(self.users.users), len(self.channels.channels))
        initial = len(self.users.get_identified_users())
        if initial:
            msg += ", %d users already identified" % initial
        self.users.notice_serverops(msg)

    def rehash(self):
        log.info("Starting rehash")
        self.channels.rehash()
        self.profiles.rehash()
        for chan in self.channels.get_all_channels():
            chan.fix_all_users()
        log.info("Done rehash")
