/**
 * Purple is the legal property of its developers, whose names are too numerous
 * to list here.  Please refer to the COPYRIGHT file distributed with this
 * source distribution.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02111-1301  USA
 */

#include "internal.h"
#include "debug.h"
#include "jingleinfo.h"

static void
jabber_google_stun_lookup_cb(GSList *hosts, gpointer data,
	const char *error_message)
{
	JabberStream *js = (JabberStream *) data;

	if (error_message) {
		purple_debug_error("jabber", "Google STUN lookup failed: %s\n",
			error_message);
		g_slist_free(hosts);
		js->stun_query = NULL;
		return;
	}

	if (hosts && g_slist_next(hosts)) {
		struct sockaddr *addr = g_slist_next(hosts)->data;
		char dst[INET6_ADDRSTRLEN];
		int port;

		if (addr->sa_family == AF_INET6) {
			inet_ntop(addr->sa_family, &((struct sockaddr_in6 *) addr)->sin6_addr,
				dst, sizeof(dst));
			port = ntohs(((struct sockaddr_in6 *) addr)->sin6_port);
		} else {
			inet_ntop(addr->sa_family, &((struct sockaddr_in *) addr)->sin_addr,
				dst, sizeof(dst));
			port = ntohs(((struct sockaddr_in *) addr)->sin_port);
		}

		if (js->stun_ip)
			g_free(js->stun_ip);
		js->stun_ip = g_strdup(dst);
		js->stun_port = port;

		purple_debug_info("jabber", "set Google STUN IP/port address: "
		                  "%s:%d\n", dst, port);

		/* unmark ongoing query */
		js->stun_query = NULL;
	}

	while (hosts != NULL) {
		hosts = g_slist_delete_link(hosts, hosts);
		/* Free the address */
		g_free(hosts->data);
		hosts = g_slist_delete_link(hosts, hosts);
	}
}

static void
jabber_google_jingle_info_common(JabberStream *js, const char *from,
                                 JabberIqType type, xmlnode *query)
{
	const xmlnode *stun = xmlnode_get_child(query, "stun");
	const xmlnode *relay = xmlnode_get_child(query, "relay");
	gchar *my_bare_jid;

	/*
	 * Make sure that random people aren't sending us STUN servers. Per
	 * http://code.google.com/apis/talk/jep_extensions/jingleinfo.html, these
	 * stanzas are stamped from our bare JID.
	 */
	if (from) {
		my_bare_jid = g_strdup_printf("%s@%s", js->user->node, js->user->domain);
		if (!purple_strequal(from, my_bare_jid)) {
			purple_debug_warning("jabber", "got google:jingleinfo with invalid from (%s)\n",
			                  from);
			g_free(my_bare_jid);
			return;
		}

		g_free(my_bare_jid);
	}

	if (type == JABBER_IQ_ERROR || type == JABBER_IQ_GET)
		return;

	purple_debug_info("jabber", "got google:jingleinfo\n");

	if (stun) {
		xmlnode *server = xmlnode_get_child(stun, "server");

		if (server) {
			const gchar *host = xmlnode_get_attrib(server, "host");
			const gchar *udp = xmlnode_get_attrib(server, "udp");

			if (host && udp) {
				PurpleAccount *account;
				int port = atoi(udp);
				/* if there, would already be an ongoing query,
				 cancel it */
				if (js->stun_query)
					purple_dnsquery_destroy(js->stun_query);

				account = purple_connection_get_account(js->gc);
				js->stun_query = purple_dnsquery_a_account(account, host, port,
					jabber_google_stun_lookup_cb, js);
			}
		}
	}

	if (relay) {
		xmlnode *token = xmlnode_get_child(relay, "token");
		xmlnode *server = xmlnode_get_child(relay, "server");

		if (token) {
			gchar *relay_token = xmlnode_get_data(token);

			/* we let js own the string returned from xmlnode_get_data */
			js->google_relay_token = relay_token;
		}

		if (server) {
			js->google_relay_host =
				g_strdup(xmlnode_get_attrib(server, "host"));
		}
	}
}

static void
jabber_google_jingle_info_cb(JabberStream *js, const char *from,
                             JabberIqType type, const char *id,
                             xmlnode *packet, gpointer data)
{
	xmlnode *query = xmlnode_get_child_with_namespace(packet, "query",
			NS_GOOGLE_JINGLE_INFO);

	if (query)
		jabber_google_jingle_info_common(js, from, type, query);
	else
		purple_debug_warning("jabber", "Got invalid google:jingleinfo\n");
}

void
jabber_google_handle_jingle_info(JabberStream *js, const char *from,
                                 JabberIqType type, const char *id,
                                 xmlnode *child)
{
	jabber_google_jingle_info_common(js, from, type, child);
}

void
jabber_google_send_jingle_info(JabberStream *js)
{
	JabberIq *jingle_info =
		jabber_iq_new_query(js, JABBER_IQ_GET, NS_GOOGLE_JINGLE_INFO);

	jabber_iq_set_callback(jingle_info, jabber_google_jingle_info_cb,
		NULL);
	purple_debug_info("jabber", "sending google:jingleinfo query\n");
	jabber_iq_send(jingle_info);
}
