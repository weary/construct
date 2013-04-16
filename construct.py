#!/usr/bin/python

import argparse
import logging
from construct.main import main, RestartException

if __name__ == "__main__":
	FORMAT = '#%(message)s'
	logging.basicConfig(level=logging.INFO, format=FORMAT)

	parser__ = argparse.ArgumentParser(description='(More) secure irc user management')
	parser__.add_argument('--config', '-c', type=str, help='config file', required=True)
	args__ = parser__.parse_args()

	starting = True
	initial_identified = []
	while starting:
		starting = False
		try:
			main(args__.config)
		except RestartException:
			starting = True




