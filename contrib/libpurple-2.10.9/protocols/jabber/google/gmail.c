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
#include "jabber.h"
#include "gmail.h"

static void
jabber_gmail_parse(JabberStream *js, const char *from,
                   JabberIqType type, const char *id,
                   xmlnode *packet, gpointer nul)
{
	xmlnode *child;
	xmlnode *message;
	const char *to, *url;
	const char *in_str;
	char *to_name;

	int i, count = 1, returned_count;

	const char **tos, **froms, **urls;
	char **subjects;

	if (type == JABBER_IQ_ERROR)
		return;

	child = xmlnode_get_child(packet, "mailbox");
	if (!child)
		return;

	in_str = xmlnode_get_attrib(child, "total-matched");
	if (in_str && *in_str)
		count = atoi(in_str);

	/* If Gmail doesn't tell us who the mail is to, let's use our JID */
	to = xmlnode_get_attrib(packet, "to");

	message = xmlnode_get_child(child, "mail-thread-info");

	if (count == 0 || !message) {
		if (count > 0) {
			char *bare_jid = jabber_get_bare_jid(to);
			const char *default_tos[2] = { bare_jid };

			purple_notify_emails(js->gc, count, FALSE, NULL, NULL, default_tos, NULL, NULL, NULL);
			g_free(bare_jid);
		} else {
			purple_notify_emails(js->gc, count, FALSE, NULL, NULL, NULL, NULL, NULL, NULL);
		}

		return;
	}

	/* Loop once to see how many messages were returned so we can allocate arrays
	 * accordingly */
	for (returned_count = 0; message; returned_count++, message=xmlnode_get_next_twin(message));

	froms    = g_new0(const char* , returned_count + 1);
	tos      = g_new0(const char* , returned_count + 1);
	subjects = g_new0(char* , returned_count + 1);
	urls     = g_new0(const char* , returned_count + 1);

	to = xmlnode_get_attrib(packet, "to");
	to_name = jabber_get_bare_jid(to);
	url = xmlnode_get_attrib(child, "url");
	if (!url || !*url)
		url = "http://www.gmail.com";

	message= xmlnode_get_child(child, "mail-thread-info");
	for (i=0; message; message = xmlnode_get_next_twin(message), i++) {
		xmlnode *sender_node, *subject_node;
		const char *from, *tid;
		char *subject;

		subject_node = xmlnode_get_child(message, "subject");
		sender_node  = xmlnode_get_child(message, "senders");
		sender_node  = xmlnode_get_child(sender_node, "sender");

		while (sender_node && (!xmlnode_get_attrib(sender_node, "unread") ||
		       !strcmp(xmlnode_get_attrib(sender_node, "unread"),"0")))
			sender_node = xmlnode_get_next_twin(sender_node);

		if (!sender_node) {
			i--;
			continue;
		}

		from = xmlnode_get_attrib(sender_node, "name");
		if (!from || !*from)
			from = xmlnode_get_attrib(sender_node, "address");
		subject = xmlnode_get_data(subject_node);
		/*
		 * url = xmlnode_get_attrib(message, "url");
		 */
		tos[i] = (to_name != NULL ?  to_name : "");
		froms[i] = (from != NULL ?  from : "");
		subjects[i] = (subject != NULL ? subject : g_strdup(""));
		urls[i] = url;

		tid = xmlnode_get_attrib(message, "tid");
		if (tid &&
		    (js->gmail_last_tid == NULL || strcmp(tid, js->gmail_last_tid) > 0)) {
			g_free(js->gmail_last_tid);
			js->gmail_last_tid = g_strdup(tid);
		}
	}

	if (i>0)
		purple_notify_emails(js->gc, count, count == i, (const char**) subjects, froms, tos,
				urls, NULL, NULL);

	g_free(to_name);
	g_free(tos);
	g_free(froms);
	for (i = 0; i < returned_count; i++)
		g_free(subjects[i]);
	g_free(subjects);
	g_free(urls);

	in_str = xmlnode_get_attrib(child, "result-time");
	if (in_str && *in_str) {
		g_free(js->gmail_last_time);
		js->gmail_last_time = g_strdup(in_str);
	}
}

void
jabber_gmail_poke(JabberStream *js, const char *from, JabberIqType type,
                  const char *id, xmlnode *new_mail)
{
	xmlnode *query;
	JabberIq *iq;

	/* bail if the user isn't interested */
	if (!purple_account_get_check_mail(js->gc->account))
		return;

	/* Is this an initial incoming mail notification? If so, send a request for more info */
	if (type != JABBER_IQ_SET)
		return;

	/* Acknowledge the notification */
	iq = jabber_iq_new(js, JABBER_IQ_RESULT);
	if (from)
		xmlnode_set_attrib(iq->node, "to", from);
	xmlnode_set_attrib(iq->node, "id", id);
	jabber_iq_send(iq);

	purple_debug_misc("jabber",
		   "Got new mail notification. Sending request for more info\n");

	iq = jabber_iq_new_query(js, JABBER_IQ_GET, NS_GOOGLE_MAIL_NOTIFY);
	jabber_iq_set_callback(iq, jabber_gmail_parse, NULL);
	query = xmlnode_get_child(iq->node, "query");

	if (js->gmail_last_time)
		xmlnode_set_attrib(query, "newer-than-time", js->gmail_last_time);
	if (js->gmail_last_tid)
		xmlnode_set_attrib(query, "newer-than-tid", js->gmail_last_tid);

	jabber_iq_send(iq);
	return;
}

void jabber_gmail_init(JabberStream *js) {
	JabberIq *iq;
	xmlnode *usersetting, *mailnotifications;

	if (!purple_account_get_check_mail(purple_connection_get_account(js->gc)))
		return;

	/*
	 * Quoting http://code.google.com/apis/talk/jep_extensions/usersettings.html:
	 * To ensure better compatibility with other clients, rather than
	 * setting this value to "false" to turn off notifications, it is
	 * recommended that a client set this to "true" and filter incoming
	 * email notifications itself.
	 */
	iq = jabber_iq_new(js, JABBER_IQ_SET);
	usersetting = xmlnode_new_child(iq->node, "usersetting");
	xmlnode_set_namespace(usersetting, "google:setting");
	mailnotifications = xmlnode_new_child(usersetting, "mailnotifications");
	xmlnode_set_attrib(mailnotifications, "value", "true");
	jabber_iq_send(iq);

	iq = jabber_iq_new_query(js, JABBER_IQ_GET, NS_GOOGLE_MAIL_NOTIFY);
	jabber_iq_set_callback(iq, jabber_gmail_parse, NULL);
	jabber_iq_send(iq);
}
