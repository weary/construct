import json
import logging

from .core import Core

def no_unicode(c):
	""" encode all unicode in a dict/list combo """
	if isinstance(c, dict):
		return {no_unicode(k): no_unicode(v) for k, v in c.iteritems()}
	elif isinstance(c, list):
		return [no_unicode(k) for k in c]
	elif isinstance(c, unicode):
		return c.encode('utf-8')
	else:
		return c


def main(configfilename, initial_identified):
	FORMAT = '#%(message)s'
	logging.basicConfig(level=logging.INFO, format=FORMAT)

	# FIXME: would like to have the configfile in a similar format as ircd.conf
	# FIXME: at least some format that allows comments
	config = json.load(open(configfilename))
	config = no_unicode(config)

	core = Core(config, initial_identified)
	core.run()

