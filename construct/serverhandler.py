import logging
import re
import traceback
from enum import Enum

from .irc_connection import IrcConnection
from .restartexception import RestartException


log = logging.getLogger('main')


def compile_spaced(regexstr):
    return re.compile(regexstr.replace(' ', r'\s+'))


pingre = compile_spaced(r'PING :(.*)')
passre = compile_spaced(r'PASS (\S+) TS (\d+) (\S+)')
serverre = compile_spaced(r'SERVER (\S+) 1 :(.*)')
killre = compile_spaced(r':\S+ KILL (\S+) :(.*)')

uidre = compile_spaced(
    r':(\S+) UID (\S+) \d+ \d+ \S+ (\S+) \S+ \S+ (\S+) \S+ :.*')
nickchangere = compile_spaced(r':(\S+) NICK (\S+) :\d+')
joinre = compile_spaced(r':(\S+) JOIN \d+ (#\S+) (\+)')
sjoinre = compile_spaced(r':\S+ SJOIN \d+ (#\S+) \+[a-z]* :(.*)')
partre = compile_spaced(r':(\S+) PART (\S+)')
kickre = compile_spaced(r':\S+ KICK (\S+) (\S+) :(.*)')
# modere = compile_spaced(':\S+ MODE .*')
usermodere = compile_spaced(
    r':(\S+) TMODE \d+ (\S+) ((?:[-+]\S+)+) (\S+(?: \S+)*)')
serverusermodere = compile_spaced(r':\S+ MODE (\S+) :([-+]\S+)')
chanmodere = compile_spaced(r':(\S+) TMODE \d+ (\S+) ([-+]\S+)')
quitre = compile_spaced(r':(\S+) QUIT :(.*)')
privmsgre = compile_spaced(r':(\S+) PRIVMSG (\S+) :(.*)')
topicre = compile_spaced(r':(\S+) TOPIC (\S+) (.*)')
awayre = compile_spaced(r':(\S+) AWAY(.*)')
noticere = compile_spaced(r':(\S+) NOTICE (\S+) :(.*)')


# remote_serverid_re = compile_spaced(r"^:(\S+) (.*)")

# technical specification version used, see ts6.txt
TS_VERSION = 6


class IrcMsgException(Exception):
    """ an exception that is told to the user """

    def __init__(self, user, msg):
        assert isinstance(user.nick, str)
        assert isinstance(msg, str)
        super(IrcMsgException, self).__init__(
            "IrcMsg(%s, %s)" % (user.nick, msg))
        self.user = user
        self.msg = msg


class OperMsgException(Exception):
    """ an exception that is told to all online server operators """

    def __init__(self, msg):
        assert isinstance(msg, str)
        super(OperMsgException, self).__init__("OperMsg(%s)" % msg)
        self.msg = msg


class ServerState(Enum):
    STARTUP = 1
    SEEN_PASS = 2
    CONNECTED = 3


class LineOrigin(Enum):
    SERVER = 1
    USER = 2


class ServerHandler(object):
    def __init__(
        self,
        core,
        send_password,
        accept_password,
        host, port,  # remote
        name, our_serverid, description,  # us
    ):
        self.con = IrcConnection(host, port)
        self.core = core
        self.accept_password = accept_password
        self.send_password = send_password
        self.serverstate = ServerState.STARTUP

        self.name = name
        if self.name.find('.') < 0:
            raise Exception("server name('%s') must contain a dot" % self.name)
        try:
            str_our_serverid = our_serverid
        except UnicodeDecodeError:
            raise Exception("invalid server id, must be ascii")
        if not str_our_serverid[0].isnumeric():
            raise Exception("invalid server id, must start with digit")
        self.our_serverid = our_serverid
        self.description = description
        self.remote_serverid = None
        self.remote_serverid_re = None

        assert isinstance(self.send_password, str)
        assert isinstance(self.accept_password, str)
        assert isinstance(self.our_serverid, str)

        self.msgs = (
            (pingre, self.msg_ping),
            (passre, self.msg_pass),
            (serverre, self.msg_server),
            (killre, self.msg_kill),
            (uidre, self.msg_uid),
            (nickchangere, self.msg_nickchange),
            (joinre, self.msg_join),
            (sjoinre, self.msg_sjoin),
            (partre, self.msg_part),
            (kickre, self.msg_kick),
            (usermodere, self.msg_usermode),
            (serverusermodere, self.msg_serverusermode),
            (chanmodere, lambda x, y, z: 1),
            (quitre, self.msg_quit),
            (privmsgre, self.msg_privmsg),
            (topicre, lambda x, y, z: 1),
            (awayre, lambda x, y: 1),
            (noticere, self.msg_notice))

    def send(self, msg):
        assert isinstance(msg, str)
        self.con.write(msg + "\n")

    def connect(self):
        self.con.connect()
        self.send(
            "PASS %s TS %d :%s" % (
                self.send_password, TS_VERSION, self.our_serverid))
        # self.send("CAPAB :...")
        HOPCOUNT = 1
        self.send(
            "SERVER %s %d %s + :%s"
            % (self.name, HOPCOUNT, self.our_serverid, self.description))

    def disconnect(self):
        self.con.disconnect()
        self.con = None

    def msg_ping(self, who):
        self.send("PONG :" + who)
        if self.core.in_startup():
            self.core.finish_startup()

    def msg_pass(self, pass_, ts_version, remote_serverid):
        #   sendto_one(client_p, "PASS %s TS %u %s", conf->spasswd, TS_CURRENT, me.id);
        if pass_ != self.accept_password:
            raise Exception("Server sent invalid password")
        if self.serverstate != ServerState.STARTUP:
            raise Exception("Got pass from server but not expecting")
        self.remote_serverid = remote_serverid
        self.serverstate = ServerState.SEEN_PASS

    def msg_server(self, name, desc):
        if self.serverstate != ServerState.SEEN_PASS:
            raise Exception("Server introduced himself, but haven't seen pass")
        log.info("Connected to %s as %s, %s" %
                 (name, self.remote_serverid, desc))
        self.serverstate = ServerState.CONNECTED

    def msg_kill(self, who, reason):
        if who == self.core.avatar.nick:
            raise Exception("Server killed our construct: %s" % reason)

    # def msg_nick(self, newnick, username, hostname):
    #     user = self.core.users.get_user(newnick)
    #     if user:
    #         raise OperMsgException("User %s already known" % newnick)
    #     user = self.core.users.create_user(newnick, username, hostname)
    #     self.core.channels.fix_user_on_all_channels(user)

    def msg_uid(self, serverid, newnick, username, uid):
        user = self.core.users.get_user_by_uid(uid)
        if user:
            raise OperMsgException(
                "User %s(%s) already known for %s" % (uid, newnick, user.nick))
        user = self.core.users.create_user(newnick, username, uid)
        self.core.channels.fix_user_on_all_channels(user)
        log.info("New user %s with nick %s" % (uid, newnick))

    def msg_notice(self, serverid, something, msg):
        if self.remote_serverid and serverid != self.remote_serverid:
            raise Exception("Received NOTICE with invalid serverid")
        log.info("NOTICE: %s" % msg)

    def msg_nickchange(self, oldnick, newnick):
        user = self.core.users.get_user_by_uid(oldnick)
        if not user:
            raise OperMsgException("no such user %s" % oldnick)
        user.nickchange(newnick)
        self.core.channels.fix_user_on_all_channels(user)

    def msg_join(self, uid, channame, mode):
        chan = self.core.channels.get_or_create_channel(channame)
        user = self.core.users.get_user_by_uid(uid)
        if not user:
            raise OperMsgException("joining user %s does not exist" % uid)
        chan.join(user, mode)

    def msg_sjoin(self, channame, uids):
        chan = self.core.channels.get_or_create_channel(channame)
        for uid in uids.split():
            mode = ''
            if '@' == uid[:1]:
                mode += 'o'
                uid = uid[1:]
            if '+' == uid[:1]:
                mode += 'v'
                uid = uid[1:]
            user = self.core.users.get_user_by_uid(uid)
            if not user:
                raise OperMsgException("joining user %s does not exist" % uid)
            chan.join(user, mode)

    def msg_part(self, uid, channame):
        chan = self.core.channels.get_channel(channame)
        if not chan:
            raise OperMsgException(
                "no such channel '%s' where user %s parts from" % (
                    channame, uid))
        user = self.core.users.get_user_by_uid(uid)
        if not user:
            raise OperMsgException("parting user %s does not exist" % uid)
        chan.part(user)

    def msg_kick(self, channame, uid, reason):
        chan = self.core.channels.get_channel(channame)
        if not chan:
            raise OperMsgException(
                "no such channel '%s' where user %s is kicked from" % (
                    channame, uid))
        user = self.core.users.get_user_by_uid(uid)
        if not user:
            raise OperMsgException("parting user %s does not exist" % uid)
        chan.kick(user)

    def msg_usermode(self, chanoper, channame, modechange, nicks):
        chan = self.core.channels.get_channel(channame)
        if not chan:
            raise OperMsgException(
                "no such channel '%s' where user(s) %s are mode-changed"
                % (channame, nicks))
        chanoper = self.core.users.get_user_by_uid(chanoper)
        for nick in nicks.split():
            user = self.core.users.get_user_by_uid(nick)
            if not user:
                raise OperMsgException(
                    "mode-change for non-existing user %s" % nick)
            chan.mode(chanoper, user, modechange)
        chan.fix_all_users()

    def msg_serverusermode(self, user, modechange):
        self.core.users.privmsg_serverops(
            "Global mode-change for user %s: %s" % (user, modechange))

    def msg_quit(self, uid, reason):
        user = self.core.users.get_user_by_uid(uid)
        self.core.channels.channel_user_quit(user)
        self.core.users.remove_user(user)

    def msg_privmsg(self, fromuid, touid, msg):
        avatar = self.core.avatar
        user = self.core.users.get_user_by_uid(fromuid)
        if touid == avatar.uid:
            avatar.recv(user, msg)
        else:
            raise IrcMsgException(user, "No such nick, '%s'" % touid)

    def parse_line(self, line):
        assert isinstance(line, str)
        try:
            # mob = remote_serverid_re.match(line)
            # if mob:
            #     serverid, line = mob.groups()
            #     if self.remote_serverid and serverid != self.remote_serverid:
            #         raise Exception(
            #             "Invalid remote serverid, "
            #             + "expected '%s' but got '%s'"
            #             % (self.remote_serverid, serverid)
            #         )

            for reg, func in self.msgs:
                r = reg.match(line)
                if r:
                    func(*r.groups())
                    return
            raise OperMsgException("Unparsed line: %s" % line)
        except RestartException:
            raise  # pass upwards
        except IrcMsgException as e:
            if e.user:
                self.core.avatar.notice(e.user, e.msg)
            else:
                log.warning("Unknown user caused exception: %s" % e.msg)
        except OperMsgException as e:
            log.warning(e.msg)
            self.core.users.privmsg_serverops("Exception: %s" % e.msg)
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
            if self.serverstate == ServerState.CONNECTED:
                return
        else:
            raise Exception("Lost connection, while connecting")
