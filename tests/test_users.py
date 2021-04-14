from construct.users import User, UserDB
import pytest
import mock


@pytest.fixture
def users_fix():
    class DummyCore(object):
        pass

    udb = UserDB(core=DummyCore)
    udb.users.extend(
        [
            User("banaan", "Test User Banaan", "012345"),
            User("aap", "Test User Aap", "04756"),
        ]
    )
    return udb


def test_get_user_by_uid(users_fix):
    assert users_fix.get_user_by_uid("012345").username == "Test User Banaan"
    assert users_fix.get_user_by_uid("04756").username == "Test User Aap"
    assert users_fix.get_user_by_uid("012346", 1) == 1


def test_get_user_by_nick(users_fix):
    assert (
        users_fix.get_user_by_nick_yes_really("banaan").username == "Test User Banaan"
    )
    assert users_fix.get_user_by_nick_yes_really("aap").username == "Test User Aap"
    assert users_fix.get_user_by_nick_yes_really("klaas", 1) == 1


def test_create_user(users_fix):
    users_fix.core.can_auto_identify = mock.Mock(return_value=None)
    user = users_fix.create_user("newnick", "New User", "0123")
    assert user.username == "New User"
