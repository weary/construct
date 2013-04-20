import json
import logging

from .core import Core


def main(configfilename, initial_identified):
	FORMAT = '#%(message)s'
	logging.basicConfig(level=logging.INFO, format=FORMAT)

	# FIXME: would like to have the configfile in a similar format as ircd.conf
	# FIXME: at least some format that allows comments
	config = json.load(open(configfilename))

	core = Core(config, initial_identified)
	core.run()

