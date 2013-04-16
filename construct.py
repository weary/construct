#!/usr/bin/python

import argparse
import logging
import construct.main

if __name__ == "__main__":
	FORMAT = '#%(message)s'
	logging.basicConfig(level=logging.INFO, format=FORMAT)

	parser__ = argparse.ArgumentParser(description='(More) secure irc user management')
	parser__.add_argument('--config', '-c', type=str, help='config file', required=True)
	args__ = parser__.parse_args()

	starting = True
	initial_identified = []
	while starting:
		reload(construct.main)
		starting = False
		try:
			construct.main.main(args__.config, initial_identified)
		except construct.main.RestartException, e:
			initial_identified = e.identified_users
			starting = True




