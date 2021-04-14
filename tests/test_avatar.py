from construct.serverhandler import IrcMsgException
from construct.consts import (
    registeredlevel,
    guestlevel,
    confirmedlevel,
    operlevel,
    allowrole,
    banrole,
    operrole,
)
import pytest
from construct.avatar import Avatar
from mock import Mock
from itertools import product


def make_mock_cmd(funcname, minauth):
    cmd = Mock()
    cmd.funcname = funcname
    cmd.minauth = minauth
    return cmd


def test_access_levels():
    core = Mock()
    core.shandler.our_serverid = "99"
    user = Mock()
    av = Avatar(core, "testnick", "test description")

    levels = {0: guestlevel, 1: registeredlevel, 2: confirmedlevel, 3: operlevel}
    for cmdminauth, userauth in product(levels, levels):
        cmd, user = Mock(), Mock()
        cmd.funcname = "aap"
        cmd.minauth = levels[cmdminauth]
        user.level.return_value = levels[userauth]
        args = {}
        expected_access = cmdminauth <= userauth
        try:
            av.test_access(cmd, args, user, False)
            have_access = True
        except Exception:
            have_access = False
        assert have_access == expected_access


def test_access_chan():
    core = Mock()
    core.shandler.our_serverid = "99"

    # testuser is server operator, should not overrule chanoper
    user = Mock()
    user.nick = "mynick"
    user.level.return_value = operlevel

    av = Avatar(core, "testnick", "test description")

    # 'chanoper' is not accessible, so use register_command
    def mock_chan_cmd(self, oper, cmd, chan, nick):
        """chanoper
        9.9 mock_chan_cmd <chan> <something>
        Only channel operator can do this command"""
        pass

    av.commands.register_command("mock_chan_cmd", mock_chan_cmd)
    cmd = av.commands.commands[-1]

    args = {"chan": "mychan"}

    # channel does not exist
    core.channels.get_channel.return_value = None
    with pytest.raises(IrcMsgException) as excinfo:
        av.test_access(cmd, args, user, False)
    core.channels.get_channel.assert_called_once_with("mychan")
    assert "unknown channel" in str(excinfo.value)

    # from now on the channel exists
    chan = Mock()
    core.channels.get_channel.return_value = chan
    chan.name = "mychan"

    # test channel not registered
    chan.registered = False
    with pytest.raises(IrcMsgException) as excinfo:
        av.test_access(cmd, args, user, False)
    assert "'mychan' is not a registered channel" in str(excinfo.value)

    # channel registered, but user not channel operator
    chan.registered = True
    for role in (banrole, allowrole):
        chan.find_role.reset_mock()
        chan.find_role.return_value = role
        with pytest.raises(IrcMsgException) as excinfo:
            av.test_access(cmd, args, user, False)
        chan.find_role.assert_called_once_with(user)
        assert "'mynick' is not a channel operator on 'mychan'" in str(excinfo.value)

    # user is actuelly channel operator
    chan.find_role.reset_mock()
    chan.find_role.return_value = operrole
    av.test_access(cmd, args, user, False)
    chan.find_role.assert_called_once_with(user)
