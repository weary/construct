import logging
import sqlite3

from .consts import (
    registeredlevel,
    confirmedlevel,
    operlevel,
    banrole,
    allowrole,
    operrole)


def db_to_level(s):
    return {
        'registered': registeredlevel,
        'confirmed': confirmedlevel,
        'oper': operlevel,
    }[s]


def level_to_db(s):
    return {
        registeredlevel: 'registered',
        confirmedlevel: 'confirmed',
        operlevel: 'oper'
    }[s]


def db_to_role(s):
    return {'ban': banrole, 'allow': allowrole, 'chanoper': operrole}[s]


def role_to_db(s):
    return {banrole: 'ban', allowrole: 'allow', operrole: 'chanoper'}[s]


log = logging.getLogger('db')

schema = (
    (
        'profiles',
        """CREATE TABLE profiles (
        id INTEGER NOT NULL,
        register_nick VARCHAR NOT NULL,
        level VARCHAR(10) NOT NULL,
        password VARCHAR NOT NULL,
        realname VARCHAR,
        email VARCHAR,
        PRIMARY KEY (id),
        UNIQUE (register_nick),
        CHECK (level IN ('registered', 'confirmed', 'oper')))""",),
    (
        'channels',
        """CREATE TABLE channels (
        name VARCHAR NOT NULL,
        allow_guests BOOLEAN NOT NULL,
        policy VARCHAR(5) NOT NULL,
        PRIMARY KEY (name),
        CHECK (allow_guests IN (0, 1)),
        CHECK (policy IN ('allow', 'deny')))""",),
    (
        'roles',
        """CREATE TABLE roles (
        profile INTEGER NOT NULL,
        channel VARCHAR NOT NULL,
        type VARCHAR(8) NOT NULL,
        PRIMARY KEY (profile, channel),
        FOREIGN KEY(profile) REFERENCES profiles (id) ON DELETE CASCADE,
        FOREIGN KEY(channel) REFERENCES channels (name) ON DELETE CASCADE,
        CHECK (type IN ('ban', 'allow', 'chanoper')))""",))


class ConstructDatabase(object):
    def __init__(self, filename):
        self.conn = sqlite3.connect(filename)
        self.conn.execute("pragma foreign_keys=ON")
        self.conn.commit()

        for tablename, tschema in schema:
            r = self.conn.execute("PRAGMA table_info(%s)" % tablename)
            if not r.fetchall():
                log.info("Creating table '%s'" % tablename)
                self.conn.execute(tschema)
        self.conn.commit()
        log.info("Database created/checked")

    def qry(self, stmt, args=()):
        log.debug("Query: %s, %r" % (stmt, args))
        r = self.conn.execute(stmt, args)
        if stmt[0].lower() in "iud":
            self.conn.commit()

        return r

    def get_channels(self):
        return [
            (row[0], row[1] != 0, row[2] == 'allow')
            for row in self.qry("select name, allow_guests, policy from channels")
        ]

    def create_channel(self, name, allow_guests, default_policy_allow):
        self.qry(
            "insert into channels values(?, ?, ?)",
            (name, allow_guests and 1 or 0,
             default_policy_allow and "allow" or "deny"))

    def update_channel(self, name, allow_guests, default_policy_allow):
        self.qry(
            "update channels set allow_guests=?, policy=? where name=?",
            (allow_guests and 1 or 0, default_policy_allow and "allow" or "deny", name))

    def delete_channel(self, name):
        self.qry("delete from channels where name=?", (name,))

    def get_profiles(self):
        def to_ascii(x):
            """for some reason passwords are sametimes 'str' and
            sometimes 'bytes'"""
            if type(x) == bytes:
                return x.decode("utf-8", "replace")
            return x

        return [
            (
                row[0],
                row[1],
                db_to_level(row[2]),
                to_ascii(row[3]),  # password
                row[4],
                row[5])
            for row in self.qry(
                "select id, register_nick, level, password, realname, email "
                + "from profiles")
        ]

    def create_profile(self, id_, nick, level, pwd):
        self.qry(
            "insert into profiles(id, register_nick, level, password) "
            + "values(?, ?, ?, ?)",
            (id_, nick, level_to_db(level), pwd),)

    def update_profile(self, id_, nick, level, pwd, name, email):
        self.qry(
            "update profiles set "
            + "register_nick=?, level=?, password=?, realname=?, email=? "
            + "where id=?",
            (nick, level_to_db(level), pwd, name, email, id_),)

    def delete_profile(self, id_):
        self.qry("delete from profiles where id=?", (id_,))

    def get_roles(self):
        return [
            (row[0], row[1], db_to_role(row[2]))
            for row in self.qry("select channel, profile, type from roles")
        ]

    def create_role(self, channel, profile, roletype):
        self.qry(
            "insert or replace into roles(channel, profile, type) values(?, ?, ?)",
            ((channel, profile, role_to_db(roletype))))

    def delete_role(self, channel, profile):
        self.qry("delete from roles where channel=? and profile=?",
                 (channel, profile))


def main():
    FORMAT = '#%(message)s'
    logging.basicConfig(level=logging.DEBUG, format=FORMAT)
    cdb = ConstructDatabase("test.db")
    cdb.qry("delete from channels")
    cdb.qry("delete from profiles")
    cdb.qry("delete from roles")
    cdb.create_channel("#aap", True, True)
    cdb.update_channel("#aap", False, False)
    cdb.get_channels()
    cdb.create_profile(5, "jaap", registeredlevel, "aa")
    cdb.update_profile(5, "jaap", confirmedlevel, "aa", "jaap aap", "jaap@aap")
    cdb.get_profiles()
    cdb.create_role("#aap", 5, banrole)
    cdb.update_role("#aap", 5, operrole)
    cdb.get_roles()
    cdb.delete_channel("#aap")
    cdb.delete_profile(5)


if __name__ == "__main__":
    main()
