from collections import namedtuple
from construct.serverhandler import LineOrigin
import re
import traceback
import socket
import _thread
import time
import sys
import queue
import os

server = (b'127.0.0.1', 6667)

ServerLine = namedtuple("ServerLine", "from_ to origin what remainder")


def create_serverline(from_=None, to=None, what=None, remainder=None):
    return ServerLine(
        from_=from_, to=to, origin=LineOrigin.SERVER, what=what, remainder=remainder)


def create_userline(from_=None, to=None, what=None, remainder=None):
    return ServerLine(
        from_=from_, to=to, origin=LineOrigin.USER, what=what, remainder=remainder)


def to_bytes(line, check=False):
    isbytes = isinstance(line, bytes)
    if check and isbytes:
        return line
    assert not isbytes
    return line.encode("utf-8")


class TestUser(object):
    def __init__(self, nick, username, realname):
        assert isinstance(nick, bytes)
        assert isinstance(username, bytes)
        assert isinstance(realname, bytes)
        self.socket = None
        self.nick = nick
        self.username = username
        self.realname = realname
        self.disco = False
        self.servername = None

        self.out = None

        self.lines = []

    def connect(self):
        self.out = open(b"%s.log" % self.nick, "w")

        self.socket = socket.create_connection(server)
        self.recv_queue = queue.Queue()
        _thread.start_new_thread(self.recv_threat, (self.recv_queue,))

        self.send(
            b"USER %s %s %s %s" % (
                self.username, b"testhost", server[0], self.realname))
        self.send(b"NICK %s" % self.nick)
        lin = self.recv(create_serverline(to=self.nick, what=b"001"))
        self.servername = lin.from_
        print("servername = %s" % self.servername.decode("ascii"))
        # wait for end-of-motd
        self.recv(create_serverline(to=self.nick, what=b"376"))
        self.clearlines()
        return self

    def send(self, line):
        assert isinstance(line, bytes)
        self.print_tee("<- %s: %s" % (self.nick.decode("ascii", errors="replace"),
                                      line.decode("ascii", errors="replace")))
        self.socket.send(line + b'\n')

    def recv_threat(self, q):
        try:
            olddata = b""
            while 1:
                newdata = self.socket.recv(1000)

                data = olddata + newdata

                lines = data.split(b"\n")
                olddata = lines[-1]
                del lines[-1]
                for lin in lines:
                    lin = lin.rstrip(b"\r")
                    q.put(lin)

                if newdata == b"":
                    break
        except Exception:
            etype, value, traceback = sys.exc_info()
            assert isinstance(etype, Exception)
            q.put((etype, value, traceback))
        finally:
            q.put(None)
            print("%s read thread terminated" % self.nick.decode("ascii"))

    def parse_serverline(self, line):
        assert isinstance(line, bytes)
        print("XXXXXX", repr(line))
        if line.startswith(b":"):
            from_, line = line.split(b" ", 1)
            from_ = from_[1:]
            print("from = %r" % from_)
        else:
            from_ = b""

        what, line = line.split(b" ", 1)
        print("what = %r" % what)

        if line.startswith(b":") or b" " not in line:
            to = line
            remainder = b""
            if to.startswith(b":"):
                to = to[1:]
        else:
            to, remainder = line.split(b" ", 1)
            if remainder.startswith(b":"):
                remainder = remainder[1:]

        if b"!" in from_:
            from_ = from_.split(b"!", 1)[0]
            origin = LineOrigin.USER
        else:
            origin = LineOrigin.SERVER

        return ServerLine(from_, to, origin, what, remainder)

    def match_serverline(self, needed, line):
        """return True if needed is the same as line, but:
        if needed.field is None it is not checked.
        if needed.field is a regex it is matched
        """
        assert isinstance(needed, ServerLine)
        assert isinstance(line, ServerLine)
        print("matching %r" % (needed,))
        print("to       %r" % (line,))
        for n, l, fieldname in zip(needed, line, ServerLine._fields):
            if isinstance(n, re.Pattern):
                if not (n.match(l)):
                    print("mismatch in regex for %s" % fieldname)
                    return False
            elif n is None:
                pass
            elif callable(n):
                if not n(l):
                    print("mismatch in callable for %s" % fieldname)
                    return False
            elif isinstance(n, (list, tuple)):
                assert all(type(i) == type(l) for i in n)
                for i in n:
                    if i == l:
                        break
                else:
                    print("mismatch in %s (%r not in %r)" % (fieldname, l, n))
                    return False
            else:
                assert type(n) == type(l)
                if n != l:
                    print("mismatch in %s (%r != %r)" % (fieldname, l, n))
                    return False
        return True

    def print_tee(self, printline):
        print(printline, file=self.out)
        self.out.flush()
        print(printline)

    def recv(self, needed):
        if not isinstance(needed, ServerLine):
            assert isinstance(needed, (str, list, tuple, re.Pattern))
            if isinstance(needed, str):
                needed = to_bytes(needed)
            elif isinstance(needed, (list, tuple)):
                needed = list(to_bytes(i, check=True) for i in needed)
            needed = ServerLine(
                from_=b"construct",
                to=self.nick,
                origin=LineOrigin.USER,
                what=b"NOTICE",
                remainder=needed,)

        assert isinstance(needed, ServerLine)
        print("looking for %r" % (needed,))

        # check if we already have the needed line
        for idx, lin in enumerate(self.lines):
            if self.match_serverline(needed, lin):
                del self.lines[idx]
                return lin

        while 1:
            lin = self.recv_queue.get()
            if lin is None:
                self.disco = True
                return None
            elif isinstance(lin, tuple) and isinstance(lin[0], Exception):
                traceback.print_exception(
                    lin[0], lin[1], lin[2], file=self.out)

            self.print_tee("-> %s: %s " % (self.nick.decode("ascii", errors="replace"),
                                           lin.decode("ascii", errors="replace")))

            try:
                lin = self.parse_serverline(lin)
            except AttributeError:
                print("(= invalid server response)", file=self.out)
                print("invalid server response")
                continue

            if self.match_serverline(needed, lin):
                return lin

            # wrong line, put in history
            self.lines.append(lin)

    def msg(self, who, what):
        assert isinstance(who, bytes)
        assert isinstance(what, bytes)
        self.send(b":%s PRIVMSG %s :%s" % (self.nick, who, what))

    def nickchange(self, newnick):
        assert isinstance(newnick, bytes)
        self.clearlines()
        self.send(b":%s NICK %s" % (self.nick, newnick))
        self.recv(create_userline(self.nick, newnick,
                  what=b"NICK", remainder=b""))
        self.nick = newnick

    def quit(self, reason):
        assert isinstance(reason, bytes)
        self.clearlines()
        self.send(b":%s QUIT :%s" % (self.nick, reason))

    # def sendcmd(self, cmd):
    #     assert isinstance(cmd, bytes)
    #     self.clearlines()
    #     self.send(b":%s %s" % (self.nick, cmd))

    def topic(self, channel, newtopic):
        self.clearlines()
        channel = to_bytes(channel)
        newtopic = to_bytes(newtopic, check=True)
        self.send(b"TOPIC %s %s" % (channel, newtopic))
        self.recv(create_userline(from_=self.nick, to=channel,
                                  what=b"TOPIC", remainder=newtopic))

    def join(self, channel):
        channel = to_bytes(channel)
        self.svrcmd(
            b"JOIN %s" % channel,
            expected_result=create_userline(
                from_=self.nick,
                to=channel,
                what=b"JOIN",
                remainder=b"",),)

    def part(self, channel):
        assert isinstance(channel, str)
        self.svrcmd(
            b"PART %s" % to_bytes(channel),
            expected_result=create_userline(
                from_=self.nick, to=b"#soonempty", what=b"PART", remainder=b""),)

    def kick(self, channel, who):
        assert isinstance(channel, str)
        assert isinstance(who, bytes)
        self.sendcmd(b"KICK %s :%s" % (to_bytes(channel), who))

    def chanmode(self, channel, modechange, ignore_result=False):
        self.clearlines()
        channel = to_bytes(channel)
        modechange = to_bytes(modechange)
        expected_result = None
        if not ignore_result:
            def match_remainder(x):
                return x.strip(b" ") == modechange

            expected_result = create_userline(from_=self.nick, to=channel,
                                              what=b"MODE", remainder=match_remainder)
        self.svrcmd(b"MODE %s %s" % (channel, modechange),
                    expected_result=expected_result)

    def usermode(self, channel, who, modechange):
        channel = to_bytes(channel)
        who = to_bytes(who, check=True)
        modechange = to_bytes(modechange)
        self.clearlines()
        self.svrcmd(b"MODE %s %s %s" % (channel, modechange, who),
                    create_userline(from_=self.nick, to=channel,
                                    what=b"MODE", remainder=b"%s %s" % (modechange, who)))

    def clearlines(self):
        for line in self.lines:
            print("XXXXX clearlines erasing: %s" % (line,))

        self.lines = []

    def svrcmd(self, rawcmd, expected_result):
        self.clearlines()
        self.send(rawcmd)
        if expected_result:
            self.recv(expected_result)

    def cmd(self, cmd, expected_result):
        """ send a command to construct """
        assert isinstance(cmd, str)
        print("XXXXX" * 10 + "testcase using " + cmd)
        self.clearlines()
        to = b"construct"
        # if specify_server:
        #     to += b"@test.local"
        self.send(b":%s PRIVMSG %s :%s" % (self.nick, to, to_bytes(cmd)))
        if expected_result is not None:
            self.recv(expected_result)

    def names(self, channel):
        # assert isinstance(channel, bytes)
        # self.sendcmd(b"NAMES %s" % channel)
        # prefix = b"%s = %s :" % (self.nick, channel)
        # result = self.wait_for_server_cmd(b"353", prefix)
        # result = set(result[len(prefix):].split(" "))
        # return result

        self.clearlines()
        channel = to_bytes(channel)
        self.send(b"NAMES %s" % channel)
        outnames = set()

        def parse_names(rem):
            crap, rem = rem.split(b":", 1)
            assert channel in crap
            outnames.update(rem.split())
            return True

        self.recv(create_serverline(from_=self.servername, to=self.nick,
                                    what=b"353", remainder=parse_names))
        return outnames

    # def wait_for_line_lambda(self, func):
    #     prev_linecount = 0
    #     print("wait_for_line_lambda")
    #     while 1:
    #         time.sleep(0.1)
    #         # print("checking")
    #         with self.linelock:
    #             # print("have lock")
    #             print(
    #                 "prev_linecount = %d, current lines = %d"
    #                 % (prev_linecount, len(self.lines))
    #             )
    #             for idx, line in enumerate(self.lines):
    #                 print(
    #                     "line %d: %r"
    #                     % (
    #                         idx,
    #                         line,
    #                     )
    #                 )
    #             print(
    #                 "range: %r" % list(range(prev_linecount, len(self.lines))),
    #             )
    #             for i in range(prev_linecount, len(self.lines)):
    #                 line = self.lines[i]
    #                 print("checking %r" % line)
    #                 print("checking:", line, file=self.out)
    #                 if func(line):
    #                     print("match!", file=self.out)
    #                     del self.lines[i]
    #                     return line
    #             prev_linecount = len(self.lines)
    #         if self.disco:
    #             return None

    # def wait_for_line(self, linestart):
    #     assert isinstance(linestart, bytes)
    #     print("looking for:", linestart, file=self.out)
    #     return self.wait_for_line_lambda(lambda line: line.startswith(linestart))

    # def wait_for_server_cmd(self, cmd, extra=None):
    #     assert isinstance(cmd, bytes) and len(cmd) == 3
    #     assert isinstance(extra, (bytes, type(None)))
    #     print("waiting for server cmd %r" % cmd)

    #     def check(line):
    #         # print("line = %r" % line)
    #         mob = re.match(b":([^ ]*) ([0-9]{3})( .*)?", line)
    #         if not mob:
    #             print("wrong format", file=self.out)
    #             return False

    #         if self.servername:
    #             if self.servername != mob.group(1):
    #                 print(
    #                     "wrong servername (expected %r got %r)"
    #                     % (self.servername, mob.group(1)),
    #                     file=self.out,
    #                 )
    #                 return False
    #         else:
    #             self.servername = mob.group(1)
    #             print(
    #                 "server name is %s" % self.servername.decode("ascii"), file=self.out
    #             )
    #         if cmd != mob.group(2):
    #             print(
    #                 "wrong opcode (expected %r got %r)" % (cmd, mob.group(2)),
    #                 file=self.out,
    #             )
    #         if extra:
    #             return mob.group(3) == b" " + extra
    #         return True

    #     return self.wait_for_line_lambda(check)

    def wait(self):
        while not self.disco:
            time.sleep(0.1)


def assert_set(s1, s2):
    if s1 != s2:
        print(s1, "!=", s2)
    assert s1 == s2


if __name__ == "__main__":
    print(
        "remember! "
        "you need to have a 'serveroper' profile with password 'serveroperpass'")
    serveroper = TestUser(b"sErveroper", b"serverope1",
                          b"ServerOper").connect()
    serveroper.cmd("id serveroperpass", expected_result="OK")

    # cleanup old testusers and channels
    for olduser in ("chanoper", "allowed", "banned"):
        serveroper.cmd(
            "unregister " + olduser,
            expected_result=["OK", "No profile found for " % s"" % olduser],)
    serveroper.cmd(
        "channel unregister #testchan",
        expected_result=["OK", "unknown channel "  # testchan""],)

    serveroper.cmd(
        "id serveroperpass",
        expected_result="already identified as serveroper",)
    serveroper.cmd(
        "reid serveroperpass", expected_result="Successfully identified as serveroper")

    # if this fails you might need to tweak throttle_time in your ircd.conf
    chanoper=TestUser(b"cHanoper", b"chanoper1", b"ChanOper").connect()
    guest=TestUser(b"gUest", b"guest1", b"Guest").connect()
    allowed=TestUser(b"aLlowed", b"allowed1", b"Allowed").connect()
    banned=TestUser(b"bAnned", b"banned1", b"Banned").connect()
    everyone=[serveroper, chanoper, guest, allowed, banned]

    serveroper.join("#soonempty")
    serveroper.part("#soonempty")

    allowed.cmd("register dumbpass", expected_result="OK")
    allowed.cmd("register dumbpass",
                expected_result="User aLlowed already registered")
    banned.cmd("register bannedpass", expected_result="OK")

    allowed.cmd("passwd dumbpass allowedpass", expected_result="OK")

    chanoper.cmd("register chanoperpass", expected_result="OK")
    serveroper.cmd(
        "confirm %s Channel -Confirmed- Operator chanoper@someemail"
        % chanoper.nick.decode("utf-8"),
        expected_result="OK",)

    chanoper.cmd("whoami", expected_result=None)
    chanoper.recv("You are cHanoper, confirmed, no defined roles on channels")
    chanoper.recv("Real name: Channel -Confirmed- Operator")
    chanoper.recv("Email: chanoper@someemail")
    chanoper.recv("OK")

    chanoper.cmd("whois chanoper", expected_result=None)
    chanoper.recv(
        "chanoper is online and confirmed as cHanoper, no defined roles on channels")
    chanoper.recv("Real name: Channel -Confirmed- Operator")
    chanoper.recv("Email: chanoper@someemail")
    chanoper.recv("OK")

    # ghost chanoper by re-login using same account
    chanoper2=TestUser(b"chAnoper_", b"chanoper2", b"ChanOper").connect()
    chanoper2.cmd("id chanoper chanoperpass", expected_result="OK")
    everyone.append(chanoper2)
    chanoper=chanoper2
    chanoper.nickchange(b"cHanoper")
    chanoper.cmd("whoami", expected_result=None)
    chanoper.recv("You are cHanoper, confirmed, no defined roles on channels")

    serveroper.cmd("rehash", expected_result="OK")
    serveroper.cmd("restart", expected_result=re.compile(
        b"finished starting, .*"))

    serveroper.cmd(
        "confirm %s stomme naam fout@email" % allowed.nick.decode("utf-8"),
        expected_result="OK",)
    serveroper.cmd("unconfirm %s" %
                   allowed.nick.decode("utf-8"), expected_result="OK")

    chanoper.join("#testchan")
    chanoper.cmd(
        "register #testchan",
        expected_result=re.compile(b"Trying to register a channel?.*"),)
    chanoper.cmd("channel register #testchan", expected_result="OK")

    # this used to give an exception in sending unicode to the serveroper
    chanoper.topic("#testchan", b"\xd9\x87\xd9\x86\xd8\xa7")
    chanoper.chanmode("#testchan", "-pisnt", ignore_result=True)
    chanoper.chanmode("#testchan", "+pisnt")
    chanoper.chanmode("#testchan", "-pisnt")
    # should make sure serveroper doesn"t receive anything from that, but hard to test

    # no roles/policy/etc, everyone can join
    guest.join("#testchan")
    allowed.join("#testchan")
    banned.join("#testchan")
    assert chanoper.names("#testchan") == set(
        [b"gUest", b"aLlowed", b"bAnned", b"@cHanoper"])

    chanoper.usermode("#testchan", allowed.nick, "+o")
    # chanoper.cmd("channel roles #testchan", expected_result=None)
    chanoper.recv("- aLlowed oper")
    chanoper.recv("total 2 role(s) defined for #testchan")
    # lijkt er op dat de "+o" niet aan komt bij construct
    sys.exit(1)
    chanoper.usermode("#testchan", allowed.nick, "+m-o")
    allowed.wait_for_line(
        ":cHanoper!chanoper2@127.0.0.1 MODE #testchan +m-o aLlowed")
    chanoper.cmd("channel roles #testchan", True)
    chanoper.wait_for_line(
        ":construct!-@- NOTICE cHanoper :total 1 role(s) defined for #testchan")

    chanoper.part('#testchan')
    chanoper.join('#testchan')
    chanoper.wait_for_line(":construct!-@- MODE #testchan +o cHanoper")
    assert chanoper.names('#testchan') == set(
        ['gUest', 'aLlowed', 'bAnned', '@cHanoper'])

    chanoper.kick('#testchan', chanoper.nick)
    chanoper.join('#testchan')

    chanoper.cmd("channel guests #testchan deny")
    guest.wait_for_line(
        ":construct!-@- KICK #testchan gUest :Restricted channel")
    chanoper.wait_for_line(
        ":construct!-@- KICK #testchan gUest :Restricted channel")
    guest.join('#testchan')
    guest.wait_for_line(
        ":construct!-@- KICK #testchan gUest :Restricted channel")
    chanoper.wait_for_line(
        ":construct!-@- KICK #testchan gUest :Restricted channel")

    chanoper.cmd("channel ban #testchan banned")
    banned.wait_for_line(
        ":construct!-@- KICK #testchan bAnned :Restricted channel")
    chanoper.wait_for_line(
        ":construct!-@- KICK #testchan bAnned :Restricted channel")
    banned.join('#testchan')
    banned.wait_for_line(
        ":construct!-@- KICK #testchan bAnned :Restricted channel")
    chanoper.wait_for_line(
        ":construct!-@- KICK #testchan bAnned :Restricted channel")

    chanoper.cmd("channel policy #testchan deny")
    allowed.wait_for_line(
        ":construct!-@- KICK #testchan aLlowed :Restricted channel")
    chanoper.wait_for_line(
        ":construct!-@- KICK #testchan aLlowed :Restricted channel")
    assert chanoper.names('#testchan') == set(['@cHanoper'])
    chanoper.cmd("channel allow #testchan allowed")
    allowed.join('#testchan')
    chanoper.wait_for_line(":aLlowed!allowed1@127.0.0.1 JOIN :#testchan")
    assert chanoper.names('#testchan') == set(['@cHanoper', 'aLlowed'])
    chanoper.cmd("channel oper #testchan allowed")
    chanoper.cmd("channel allow #testchan chanoper")
    chanoper.wait_for_line(":construct!-@- MODE #testchan -o cHanoper")
    serveroper.cmd("whois chanoper")
    serveroper.wait_for_line(
        ":construct!-@- NOTICE sErveroper :chanoper is online and confirmed as "
        "cHanoper, allowed in #testchan")
    serveroper.cmd("whois allowed")
    serveroper.wait_for_line(
        ":construct!-@- NOTICE sErveroper :allowed is online and registered as "
        "aLlowed, oper in #testchan")
    serveroper.cmd("whois banned")
    serveroper.wait_for_line(
        ":construct!-@- NOTICE sErveroper :banned is online and registered as bAnned, "
        "banned in #testchan")
    allowed.cmd("channel reset #testchan chanoper")

    serveroper.cmd("list profiles")
    serveroper.cmd("list channels")
    serveroper.wait_for_line(
        ":construct!-@- NOTICE sErveroper :- #testchan 1 users (registered)")
    serveroper.cmd("channel roles #testchan")
    chanoper.cmd("channel roles #testchan", True)
    chanoper.wait_for_line(
        ":construct!-@- NOTICE cHanoper :'cHanoper' is not a channel operator on "
        "'#testchan'")

    allowed.cmd("channel roles #testchan")
    assert allowed.names('#testchan') == set(['@aLlowed'])

    allowed.cmd("channel unregister #testchan")
    serveroper.cmd("list channels")
    serveroper.wait_for_line(
        ":construct!-@- NOTICE sErveroper :- #testchan 1 users (not registered)")

    chanoper.cmd("unregister banned aap", True)
    chanoper.wait_for_line(
        ":construct!-@- NOTICE cHanoper :You can only unregister your own profile")
    chanoper.cmd("unregister chanoper", True)
    chanoper.wait_for_line(
        ":construct!-@- NOTICE cHanoper :error, invalid password for 'cHanoper'")
    serveroper.cmd("unregister allowed")

    serveroper.cmd("kill banned")

    serveroper.cmd("help")
    serveroper.cmd("help list channels")
    serveroper.cmd("unid")

    print()
    print("---------------end---------------------")
    print()
    for u in everyone:
        u.quit("end of test")
    for u in everyone:
        u.wait()
    sys.exit(0)
    user2=TestUser("user2", "testuser2", "TestUser2")
    user2.wait_for_line(":sin 001")
    user2.msg("construct", "register otherpass")

    time.sleep(0.5)
    print("-----------------------")

    user1=TestUser("user1", "testuser1", "TestUser1")
    user1.wait_for_line(":sin 001")
    user1.msg(user2.nick, "hoi! ik ben er ook!")
    user1.msg("construct", "identify mypass")
    user1.msg("construct", "add #aap2 user2 ban")
    user1.join("#aap2")
    user1.msg("#aap2", "ik mag er weer in!")
    user1.quit("no reason again")

    time.sleep(0.5)
    print("-----------------------")

    user2.join("#aap2")
    time.sleep(0.5)
    user2.msg("#aap2", "maar ik mag er ook in")
    user2.quit("bla")


def test_parse_serverline():
    testlines=(
        (
            b":wry.test NOTICE * :*** No Ident response",
            create_serverline(
                from_=b"wry.test",
                what=b"NOTICE",
                to=b"*",
                remainder=b"*** No Ident response",),),
        # b":wry.test NOTICE * :*** Found your hostname",
        # b":wry.test NOTICE bAnned :*** You are exempt from flood protection",
        # b":wry.test 001 bAnned :Welcome to the mynet Internet Relay Chat Network bAnned!banned1@luckybargee.space",
        (
            b":construct!construct@test.local NOTICE sErveroper :sErver..",
            create_userline(
                from_=b"construct",
                what=b"NOTICE",
                to=b"sErveroper",
                remainder=b"sErver..",),),
        # b":construct!construct@test.local NOTICE sErveroper :OK",
        # b":sErveroper!serverope1@luckybargee.space JOIN :#soonempty",
        # b":wry.test MODE #soonempty +nt",
        # b":wry.test 353 sErveroper = #soonempty :@sErveroper",
        # b":wry.test 366 sErveroper #soonempty :End of /NAMES list.",
        (
            b":sErveroper!serverope1@luckybargee.space PART #soonempty",
            create_userline(
                from_=b"sErveroper", what=b"PART", to=b"#soonempty", remainder=b""),),
        (
            b"PING :wry.test",
            create_serverline(from_=b"", what=b"PING",
                              to=b"wry.test", remainder=b""),),
        (
            b":wry.test 004 sErveroper wry.test hybrid-1:8.2.26+dfsg.1-1 y T bh",
            create_serverline(
                from_=b"wry.test",
                what=b"004",
                to=b"sErveroper",
                remainder=b"wry.test hybrid-1:8.2.26+dfsg.1-1 y T bh",),),)
    for tline, exp in testlines:
        print("expect:", exp)
        tu=TestUser(b"", b"", b"")
        out=tu.parse_serverline(tline)
        print("got:   ", out)
        assert out == exp
