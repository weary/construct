import pytest

from construct.commandcontainer import (
    Arguments,
    CommandContainer,
    guestlevel,
    registeredlevel,
    confirmedlevel,
    operlevel,
    ParseException,
)


def test_arguments_parse_1():
    a = Arguments("<arg1> [<arg2>] arg3=locked [<arg4>]")
    assert a.parse("val1 locked val4".split()) == {
        "arg1": "val1",
        "arg2": None,
        "arg3": "locked",
        "arg4": "val4",
    }


def test_arguments_parse_2():
    options = "option1|option2|option3"
    b = Arguments("[arg1=" + options + "] arg2=locked [arg3=" + options + "]")
    assert b.parse("locked option3".split()) == {
        "arg1": None,
        "arg2": "locked",
        "arg3": "option3",
    }


def test_arguments_parse_3():
    c = Arguments("<arg1> <arg2*> <arg3>")
    assert c.parse("aap beer".split()) == {
        "arg1": "aap",
        "arg2": "",
        "arg3": "beer",
    }
    assert c.parse("aap stuk1 beer".split()) == {
        "arg1": "aap",
        "arg2": "stuk1",
        "arg3": "beer",
    }
    assert c.parse("aap stuk 1 beer".split()) == {
        "arg1": "aap",
        "arg2": "stuk 1",
        "arg3": "beer",
    }


def test_command_container():
    class DummyUser(object):
        def __init__(self, my_level):
            self.levelvar = my_level

        def level(self):
            return self.levelvar

    def cmd_my_func(aap, beer, fruit):
        """chanoper
        1.1 my func <aap> [<beer>] fruit=banana|appel
        something scathing"""
        return True

    def cmd_my_other_func(arg1):
        """oper
        1.2 my other func [<arg1>]
        something friendly"""
        return True

    def cmd_my_guest_func():
        """guest
        2.1 my guest func
        something friendly"""
        return True

    def auth_callback(cmd, args, user, forhelp):
        # small test example. guest can only access guest-commands
        print("XXXX auth_callback %r %r" % (user.level(), cmd.minauth))
        if user.level() == guestlevel and cmd.minauth != guestlevel:
            raise Exception("not allowed")

    cc = CommandContainer()
    cc.register_command("my func", cmd_my_func)
    cc.register_command("my other func", cmd_my_other_func)
    cc.register_command("my guest func", cmd_my_guest_func)
    cc.register_access_test(auth_callback)

    oper = DummyUser(operlevel)
    guest = DummyUser(guestlevel)
    cmd, args = cc.parse_cmdline("my func bla bla banana", user=oper, forhelp=False)
    assert cmd.func == cmd_my_func
    assert cmd.func(**args)

    cmd, args = cc.parse_cmdline("my other func", user=oper, forhelp=False)
    assert cmd.func == cmd_my_other_func
    assert cmd.func(**args)

    cmd, args = cc.parse_cmdline("m o f o", user=oper, forhelp=False)
    assert cmd.func == cmd_my_other_func
    assert cmd.func(**args)

    cmd, args = cc.parse_cmdline("m g f", user=oper, forhelp=False)
    assert cmd.func == cmd_my_guest_func
    assert cmd.func(**args)

    # auth is checked after the multiple-commands-match check, so expect ambiguous
    # command independent of caller
    with pytest.raises(ParseException):
        cc.parse_cmdline("my", user=oper, forhelp=False)
    with pytest.raises(ParseException):
        cc.parse_cmdline("my", user=guest, forhelp=False)
    # help also returns everything
    with pytest.raises(ParseException):
        cc.parse_cmdline("my", user=guest, forhelp=True)

    # guest cannot access "my other function"
    with pytest.raises(Exception):
        cc.parse_cmdline("m o f o", user=guest, forhelp=False)

    for lvl in (guestlevel, registeredlevel, confirmedlevel, operlevel):
        helptext = cc.get_helplist(user=DummyUser(lvl), verbose=True)
        for line in helptext:
            print(line)

    for line in cc.get_helplist(user=cc.chanoper, verbose=False):
        print(line)
