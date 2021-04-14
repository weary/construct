import argparse
import json
import logging

from .core import Core


def realmain(configfilename, initial_identified):
    FORMAT = "#%(message)s"
    logging.basicConfig(level=logging.DEBUG, format=FORMAT)

    # FIXME: would like to have the configfile in a similar format as ircd.conf
    # FIXME: at least some format that allows comments
    config = json.load(open(configfilename, "r"))

    core = Core(config, initial_identified)
    core.run()


def main():
    parser = argparse.ArgumentParser(
        description="(More) secure irc user management")
    parser.add_argument("--config", "-c", type=str,
                        help="config file", required=True)
    args = parser.parse_args()

    starting = True
    initial_identified = []
    while starting:
        construct = __import__("construct")
        starting = False
        try:
            realmain(args.config, initial_identified)
        except construct.restartexception.RestartException as e:
            initial_identified = e.identified_users
            starting = True
