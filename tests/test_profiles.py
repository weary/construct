from construct.serverhandler import IrcMsgException
import pytest
import mock

from construct.profiles import Profile


def test_profile_getDigest():
    # verify salt and pwd are ascii

    # salt, digest = Profile.getDigest("AA")
    # assert salt.isascii()
    # assert digest.isascii()

    with pytest.raises(Exception):
        Profile.getDigest("\xff")

    with pytest.raises(Exception):
        Profile.getDigest("AA", "\xff")

    for pwd, salt, ref in (
        (
            "AA",
            "somesalt",
            "088098b5890a2e15dfa2c760f0d39e71acc5c4b54c7cb61e9ef03ff0098447f7",
        ),
        (
            "\x00\x7f",
            "somesalt",
            "c4b394ae2d792db6f569d468184ee242de893baf72f0a1d52e7a952ee2bf77f6",
        ),
        (
            "AA",
            "\x00\x7f",
            "a7166dad81b3da051bca3971a69940d2ab861f7ebc2bb7a75c492f4090218c7d",
        ),
    ):
        outsalt, digest = Profile.getDigest(pwd, salt)
        assert salt == outsalt
        assert digest == ref


def test_profile_reset_password():
    p = Profile(mock.Mock(), "myid", "mynick", "$C$mypassword")
    p.parent.core.db.update_profile.assert_not_called()
    p.reset_password("newpass")
    assert p.password.startswith("$C$")
    p.parent.core.db.update_profile.assert_called()

    p = Profile(mock.Mock(), "myid", "mynick", "mypassword")
    p.parent.core.db.update_profile.assert_called()


def test_profile_testpassword():
    p = Profile(mock.Mock(), "myid", "mynick", "mypassword")
    mockcaller = mock.Mock()
    mockcaller.nick = "mocknick"
    p.parent.core.password_timeout = 60

    # assert not throwing
    p.test_password("mypassword", mockcaller)

    p.test_password("mypassword", mockcaller)

    with pytest.raises(IrcMsgException) as excinfo:
        p.test_password("mypassword2", mockcaller)
    assert "invalid password" in str(excinfo.value)

    # test password timeout
    with pytest.raises(IrcMsgException) as excinfo:
        p.test_password("mypassword2", mockcaller)
    assert "wait" in str(excinfo.value)
