/*
 * Xchat (and probably other clients) do not send PRIVMSG commands when
 * addressing a service, but have hardcoded 'NICKSERV'. This module redirects
 * NICKSERV to construct.
 * Note, this module conflicts with the default m_service module in ircd-hybrid
 *
 * build instructions:
 * change 'construct_service' below to the value you configured in construct.conf, in server.name
 * gcc m_construct.c -Wall -fPIC -O3 -shared -o m_construct.so -I <ircd-hybrid-source>/include
 * where <ircd-hybrid-source> is a checkout from the irc server source that is ./configure'd
 *
 * install:
 * copy m_construct.so to /usr/lib/ircd-hybrid/modules/autoload
 *
 * This file is based on m_services.c from ircd-hybrid. This file is GPL.
 */


// set to server.name (e.g. "test.local") to for explicit service check
const char *construct_service = NULL;

#include "handlers.h"
#include "client.h"
#include "hash.h"
#include "numeric.h"
#include "send.h"
#include "msg.h"
#include "parse.h"
#include "sprintf_irc.h"


// taken from ircd-hybrid
static void
get_string(int parc, char *parv[], char *buf)
{
  int ii = 0;
  int bw = 0;

  for (; ii < parc; ++ii)
    bw += ircsprintf(buf+bw, "%s ", parv[ii]);
  buf[bw-1] = '\0';
}

// taken and adapted from ircd-hybrid
static void m_construct(struct Client *client_p, struct Client *source_p, int parc, char *parv[])
{
	struct Client *target_p = NULL;
	char buf[IRCD_BUFSIZE] = { '\0' };

	if (parc < 2 || *parv[1] == '\0')
	{
		sendto_one(source_p, form_str(ERR_NEEDMOREPARAMS),
				me.name, source_p->name, "NICKSERV");
		return;
	}

	if (construct_service && !(target_p = find_server(construct_service)))
		sendto_one(source_p, form_str(ERR_SERVICESDOWN),
				me.name, source_p->name);
	else
	{
		get_string(parc - 1, parv + 1, buf);
		if (construct_service)
			sendto_one(target_p, ":%s PRIVMSG construct@%s :%s",
					source_p->name, construct_service, buf);
		else
			sendto_one(target_p, ":%s PRIVMSG construct :%s",
					source_p->name, buf);
	}
}


struct Message construct_msgtab = {
  "NICKSERV", 0, 0, 1, 0, MFLG_SLOW, 0,
  {m_unregistered, m_construct, m_ignore, m_ignore, m_construct, m_ignore}
};
void _modinit(void) { mod_add_cmd(&construct_msgtab); }
void _moddeinit(void) { mod_del_cmd(&construct_msgtab); }

