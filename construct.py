#!/usr/bin/python

import argparse

if __name__ == "__main__":
	parser__ = argparse.ArgumentParser(description='(More) secure irc user management')
	parser__.add_argument('--config', '-c', type=str, help='config file', required=True)
	args__ = parser__.parse_args()

	starting = True
	initial_identified = []
	while starting:
		construct = __import__('construct')
		starting = False
		try:
			construct.main(args__.config, initial_identified)
		except construct.restartexception.RestartException, e:
			initial_identified = e.identified_users
			starting = True




