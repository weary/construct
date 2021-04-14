from collections import namedtuple
import logging
import re

from .consts import (
    ConstructLevel,
    guestlevel,
    registeredlevel,
    confirmedlevel,
    operlevel)


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
            raise ParseException(
                "invalid option '%s', not one of %s" %
                (cur, '|'.join(self.choices)))
        out = argumentlist[0].parse(remainder[1:], argumentlist[1:])
        out[self.keyw] = remainder[0]
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
        for lll in range(len(remainder), -1, -1):
            try:
                cur = remainder[:lll]
                out = argumentlist[0].parse(remainder[lll:], argumentlist[1:])
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

    def parse(self, argslist):
        assert all(isinstance(i, str) for i in argslist)
        try:
            return self.args[0].parse(argslist, self.args[1:])
        except ParseException as e:
            if len(self.args) > 1:
                raise ParseException(str(e) + ", expected " + str(self))
            else:
                raise ParseException(str(e) + ", expected no arguments")


ConstructCommand = namedtuple('ConstructCommand',
                              ['chapter', 'funcname', 'args', 'minauth',
                               'func', 'shorthelp', 'longhelp'])


class CommandContainer(object):
    def __init__(self):
        self.commands = []

        class ChanOperLevel(ConstructLevel):
            val = 25

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
            raise Exception(
                "invalid auth level '%s' in docstring" % minauthstr)

        regex = r" (\d+)[.](\d+) %s ((?:\s*\S+)*) $".replace(' ',
                                                             r'\s*') % funcname
        r = re.match(regex, short)
        if not r:
            raise Exception(
                "function short description missing chapter designation " +
                "or functionname mismatch")
        chaptermaj, chaptermin, args = r.groups()
        chapter = (int(chaptermaj), int(chaptermin))
        shorthelp = funcname
        longhelp = longhelp.strip()
        log.info("Registered command '%s' for authorisation %s" %
                 (funcname, minauth))
        self.commands.append(
            ConstructCommand(
                chapter, funcname, Arguments(
                    args), minauth, func, shorthelp, longhelp))

    def _get_matching_commands(self, cmdline):
        """note: returned argument string is split, and has
        empty tokens removed"""
        cmdlinesplit = tuple(i for i in cmdline.split() if i)
        for cmd in self.commands:
            funcname = cmd.funcname.split()
            if not all(ref.startswith(act.lower()) for ref,
                       act in zip(funcname, cmdlinesplit)):
                continue

            yield (cmd, cmdlinesplit[len(funcname):])

    def parse_cmdline(self, cmdline, user, forhelp):
        ''' returns tuple of (cmd, arg-dict) if forhelp=False, (cmd, None) otherwise '''
        possible = list(self._get_matching_commands(cmdline))
        if not possible:
            raise ParseException("unknown command")
        if len(possible) > 1:
            # TODO: we throw this exception even if the user only has access to one
            # of the functions (ie, access-check is too late). But fixing is
            # non-trivial due to commandline might be invalid (which is valid for
            # forhelp=True)
            raise ParseException(
                "ambiguous command, choose from: " + ', '.join(
                    cmd.funcname for cmd, args in possible))
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
                except Exception:
                    pass
        cmds.sort()  # sort on chapter
        prev_maj_ch = 0
        for cmd in cmds:
            maj_ch = cmd.chapter[0]
            if maj_ch != prev_maj_ch:
                prev_maj_ch = maj_ch
                title = self.chaptername.get(maj_ch, "chapter %d" % maj_ch)
                if out:
                    out.append('')
                out.extend(('-' * len(title), title, '-' * len(title), ''))
            out.append(cmd.funcname)
            if str(cmd.args):
                out[-1] += ' ' + str(cmd.args)
            if verbose:
                out[-1] += ' (' + str(cmd.minauth) + ')'
        return out
