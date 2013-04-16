
import logging
import re
from collections import namedtuple

from .consts import ConstructLevel, \
		guestlevel, registeredlevel, confirmedlevel, operlevel

log = logging.getLogger('cmdhandling')

class ParseException(Exception):
	pass

class ArgumentTerminator(object):
	def __str__(self):
		return ''

	def parse(self, remainder, argumentlist):
		assert not argumentlist
		if remainder:
			raise ParseException("too many arguments")
		return {}

class ArgumentChoice(object):
	def __init__(self, args):
		self.keyw, sep, self.choices = args.partition('=')
		if not self.choices:
			raise Exception("invalid choices in docstr for %s" % self.keyw)
		assert self.choices
		self.choices = set(self.choices.lower().split('|'))

	def __str__(self):
		return '|'.join(self.choices)

	def parse(self, remainder, argumentlist):
		if not remainder:
			raise ParseException("not enough arguments")
		cur = remainder[0]
		if cur.lower() not in self.choices:
			raise ParseException("invalid option '%s', not one of %s" % (
				cur, '|'.join(self.choices)))
		out = argumentlist[0].parse(remainder[1:], argumentlist[1:])
		out[self.keyw] = cur
		return out


class ArgumentSingle(object):
	def __init__(self, keyw):
		self.keyw = keyw

	def __str__(self):
		if self.keyw == 'chan':
			return "#<chan>"
		return '<%s>' % self.keyw

	def parse(self, remainder, argumentlist):
		if not remainder:
			raise ParseException("not enough arguments")
		cur = remainder[0]
		out = argumentlist[0].parse(remainder[1:], argumentlist[1:])
		out[self.keyw] = cur
		return out


class ArgumentOptional(object):
	def __init__(self, args):
		if args[0] == '<' and args[-2:] == '*>':
			self.sub = ArgumentMultiple(args[1:-2])
		elif args[0] == '<' and args[-1] == '>':
			self.sub = ArgumentSingle(args[1:-1])
		else:
			self.sub = ArgumentChoice(args)

	def __str__(self):
		return '[%s]' % self.sub

	def parse(self, remainder, argumentlist):
		try:
			out = self.sub.parse(remainder, argumentlist)
		except Exception:
			out = argumentlist[0].parse(remainder, argumentlist[1:])
			out[self.sub.keyw] = None
		return out
			
class ArgumentMultiple(ArgumentSingle):
	def parse(self, remainder, argumentlist):
		for l in xrange(len(remainder), -1, -1):
			try:
				cur = remainder[:l]
				out = argumentlist[0].parse(remainder[l:], argumentlist[1:])
				out[self.keyw] = ' '.join(cur)
				return out
			except ParseException:
				pass
		raise ParseException("could not match multi-argument")


class Arguments(object):
	def __init__(self, args):
		self.args = []
		for arg in args.strip().split():
			if arg[0] == '[' and arg[-1] == ']':
				self.args.append(ArgumentOptional(arg[1:-1]))
			elif arg[0] == '<' and arg[-2:] == '*>':
				self.args.append(ArgumentMultiple(arg[1:-2]))
			elif arg[0] == '<' and arg[-1] == '>':
				self.args.append(ArgumentSingle(arg[1:-1]))
			else:
				self.args.append(ArgumentChoice(arg))
		self.args.append(ArgumentTerminator())

	def __str__(self):
		return ' '.join(str(i) for i in self.args).strip()

	def parse(self, argstringlist):
		try:
			return self.args[0].parse(argstringlist, self.args[1:])
		except ParseException, e:
			if len(self.args) > 1:
				raise ParseException(str(e) + ", expected " + str(self))
			else:
				raise ParseException(str(e) + ", expected no arguments")



ConstructCommand = namedtuple(
	'ConstructCommand', [
		'chapter', 'funcname', 'args', 'minauth', 'func', 'shorthelp', 'longhelp'])

class CommandContainer(object):
	def __init__(self):
		self.commands = []
		class ChanOperLevel(ConstructLevel):
			val=25
			def __str__(self):
				return "channel operator"
		self.chanoper = ChanOperLevel()
		self.chaptername = {}

		def dummy(cmd, args, user, forhelp):
			raise Exception("register_access_test not called")
		self.access_test = dummy

	def register_chapter(self, nr, name):
		self.chaptername[nr] = name

	def register_access_test(self, callback):
		self.access_test = callback

	def register_command(self, funcname, func):
		docstr = func.__doc__
		if not docstr:
			raise Exception("No docstring")
		try:
			minauthstr, short, longhelp = docstr.split('\n', 2)
			minauth = {
					"guest": guestlevel,
					"registered": registeredlevel,
					"confirmed": confirmedlevel,
					"oper": operlevel,
					"chanoper": self.chanoper}[minauthstr.strip()]
		except ValueError:
			raise Exception("not enough lines in docstring")
		except KeyError:
			raise Exception("invalid auth level '%s' in docstring" % minauthstr)

		regex = " (\d+)[.](\d+) %s ((?:\s*\S+)*) $".replace(' ', '\s*') % funcname
		r = re.match(regex, short)
		if not r:
			raise Exception("function short description missing chapter designation " +
			"or functionname mismatch")
		chaptermaj, chaptermin, args = r.groups()
		chapter = (int(chaptermaj), int(chaptermin))
		shorthelp = funcname
		longhelp = longhelp.strip()
		log.info("Registered command '%s' for authorisation %s" % (
			funcname, minauth))
		self.commands.append(ConstructCommand(
			chapter, funcname, Arguments(args), minauth, func, shorthelp, longhelp))

	def _get_matching_commands(self, cmdline):
		""" note: returned argument string is split, and has
		empty tokens removed """
		tup2 = tuple(i for i in cmdline.split() if i)
		for cmd in self.commands:
			tup1 = cmd.funcname.split()
			if not all(ref.startswith(act.lower())
					for ref, act in zip(tup1, tup2)):
				continue

			yield (cmd, tup2[len(tup1):])

	def parse_cmdline(self, cmdline, user, forhelp):
		possible = list(self._get_matching_commands(cmdline))
		if not possible:
			raise ParseException("unknown command")
		if len(possible) > 1:
			raise ParseException("ambiguous command, choose from: " +
					', '.join(cmd.funcname for cmd, args in possible))
		cmd, args = possible[0]

		if forhelp:
			args = None
		else:
			args = cmd.args.parse(args)
			self.access_test(cmd, args, user, forhelp)
		return (cmd, args)

	def get_helplist(self, user, verbose):
		out = []
		if verbose:
			cmds = self.commands
		else:
			cmds = []
			for cmd in self.commands:
				try:
					self.access_test(cmd, args=None, user=user, forhelp=True)
					cmds.append(cmd)
				except:
					pass
		cmds.sort()  # sort on chapter
		prev_maj_ch = 0
		for cmd in cmds:
			maj_ch = cmd.chapter[0]
			if maj_ch != prev_maj_ch:
				prev_maj_ch = maj_ch
				title = self.chaptername.get(
						maj_ch, "chapter %d" % maj_ch)
				if out:
					out.append('')
				out.extend(
						('-'*len(title), title, '-'*len(title), ''))
			out.append(cmd.funcname)
			if str(cmd.args):
				out[-1] += ' ' + str(cmd.args)
			if verbose:
				out[-1] += ' (' + str(cmd.minauth) + ')'
		return out

if __name__ == "__main__":
	#from pprint import pprint

	a = Arguments("<arg1> [<arg2>] arg3=locked [<arg4>]")
	print str(a)
	assert a.parse("val1 locked val4".split()) == \
			{'arg1':'val1', 'arg2':None, 'arg3':'locked', 'arg4':'val4'}
	options = 'option1|option2|option3'
	b = Arguments('[arg1=' + options + "] arg2=locked [arg3=" + options + ']')
	assert b.parse("locked option3".split()) == \
			{'arg1':None, 'arg2':'locked', 'arg3':'option3'}

	c = Arguments('<arg1> <arg2*> <arg3>')
	assert c.parse("aap beer".split()) == {'arg1':'aap', 'arg2':'', 'arg3':'beer'}
	assert c.parse("aap stuk1 beer".split()) == {'arg1':'aap', 'arg2':'stuk1', 'arg3':'beer'}
	assert c.parse("aap stuk 1 beer".split()) == {'arg1':'aap', 'arg2':'stuk 1', 'arg3':'beer'}

	cc = CommandContainer()

	def cmd_my_func(aap, beer, fruit):
		""" chanoper
		1.1 my func <aap> [<beer>] fruit=banana|appel
		something scathing """
		return True

	def cmd_my_other_func(arg1):
		""" oper
		1.2 my other func [<arg1>]
		something friendly """
		return True

	def cmd_my_guest_func():
		""" guest
		2.1 my guest func
		something friendly """
		return True

	def auth_callback(cmd, args, user, forhelp):
		return True

	cc.register_command("my func", cmd_my_func)
	cc.register_command("my other func", cmd_my_other_func)
	cc.register_command("my guest func", cmd_my_guest_func)
	cc.register_access_test(auth_callback)
	cmd, args = cc.parse_cmdline("my func bla bla banana", user=None)
	assert cmd.func(**args)
	cmd, args = cc.parse_cmdline("my other func", user=None)
	assert cmd.func(**args)
	cmd, args = cc.parse_cmdline("m o f o", user=None)
	assert cmd.func(**args)
	cmd, args = cc.parse_cmdline("m g f", user=None)
	assert cmd.func(**args)
	print
	class DummyUser(object):
		def __init__(self, l):
			self.l = l
		def level(self):
			return self.l

	for lvl in (guestlevel, registeredlevel, confirmedlevel, operlevel):
		print "XXXXXXXXXXXXXXXXX", str(lvl)
		for line in cc.get_helplist(user=DummyUser(lvl), verbose=True):
			print line


	print "XXXXXXXXXXXXXXXXX"
	for line in cc.get_helplist(user=cc.chanoper, verbose=False):
		print line
	print "XXXXXXXXXXXXXXXXX"


