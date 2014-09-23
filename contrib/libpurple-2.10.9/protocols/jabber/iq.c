/*
 * purple - Jabber Protocol Plugin
 *
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
 *
 */
#include "internal.h"
#include "core.h"
#include "debug.h"
#include "prefs.h"
#include "util.h"

#include "buddy.h"
#include "disco.h"
#include "google/gmail.h"
#include "google/google.h"
#include "google/jingleinfo.h"
#include "google/google_session.h"
#include "iq.h"
#include "jingle/jingle.h"
#include "oob.h"
#include "roster.h"
#include "si.h"
#include "ping.h"
#include "adhoccommands.h"
#include "data.h"
#include "ibb.h"

#ifdef _WIN32
#include "utsname.h"
#endif

static GHashTable *iq_handlers = NULL;
static GHashTable *signal_iq_handlers = NULL;

struct _JabberIqCallbackData {
	JabberIqCallback *callback;
	gpointer data;
	JabberID *to;
};

void jabber_iq_callbackdata_free(JabberIqCallbackData *jcd)
{
	jabber_id_free(jcd->to);
	g_free(jcd);
}

JabberIq *jabber_iq_new(JabberStream *js, JabberIqType type)
{
	JabberIq *iq;

	iq = g_new0(JabberIq, 1);

	iq->type = type;

	iq->node = xmlnode_new("iq");
	switch(iq->type) {
		case JABBER_IQ_SET:
			xmlnode_set_attrib(iq->node, "type", "set");
			break;
		case JABBER_IQ_GET:
			xmlnode_set_attrib(iq->node, "type", "get");
			break;
		case JABBER_IQ_ERROR:
			xmlnode_set_attrib(iq->node, "type", "error");
			break;
		case JABBER_IQ_RESULT:
			xmlnode_set_attrib(iq->node, "type", "result");
			break;
		case JABBER_IQ_NONE:
			/* this shouldn't ever happen */
			break;
	}

	iq->js = js;

	if(type == JABBER_IQ_GET || type == JABBER_IQ_SET) {
		iq->id = jabber_get_next_id(js);
		xmlnode_set_attrib(iq->node, "id", iq->id);
	}

	return iq;
}

JabberIq *jabber_iq_new_query(JabberStream *js, JabberIqType type,
		const char *xmlns)
{
	JabberIq *iq = jabber_iq_new(js, type);
	xmlnode *query;

	query = xmlnode_new_child(iq->node, "query");
	xmlnode_set_namespace(query, xmlns);

	return iq;
}

void
jabber_iq_set_callback(JabberIq *iq, JabberIqCallback *callback, gpointer data)
{
	iq->callback = callback;
	iq->callback_data = data;
}

void jabber_iq_set_id(JabberIq *iq, const char *id)
{
	g_free(iq->id);

	if(id) {
		xmlnode_set_attrib(iq->node, "id", id);
		iq->id = g_strdup(id);
	} else {
		xmlnode_remove_attrib(iq->node, "id");
		iq->id = NULL;
	}
}

void jabber_iq_send(JabberIq *iq)
{
	JabberIqCallbackData *jcd;
	g_return_if_fail(iq != NULL);

	jabber_send(iq->js, iq->node);

	if(iq->id && iq->callback) {
		jcd = g_new0(JabberIqCallbackData, 1);
		jcd->callback = iq->callback;
		jcd->data = iq->callback_data;
		jcd->to = jabber_id_new(xmlnode_get_attrib(iq->node, "to"));

		g_hash_table_insert(iq->js->iq_callbacks, g_strdup(iq->id), jcd);
	}

	jabber_iq_free(iq);
}

void jabber_iq_free(JabberIq *iq)
{
	g_return_if_fail(iq != NULL);

	g_free(iq->id);
	xmlnode_free(iq->node);
	g_free(iq);
}

static void jabber_iq_last_parse(JabberStream *js, const char *from,
                                 JabberIqType type, const char *id,
                                 xmlnode *packet)
{
	JabberIq *iq;
	xmlnode *query;
	char *idle_time;

	if(type == JABBER_IQ_GET) {
		iq = jabber_iq_new_query(js, JABBER_IQ_RESULT, NS_LAST_ACTIVITY);
		jabber_iq_set_id(iq, id);
		if (from)
			xmlnode_set_attrib(iq->node, "to", from);

		query = xmlnode_get_child(iq->node, "query");

		idle_time = g_strdup_printf("%ld", js->idle ? time(NULL) - js->idle : 0);
		xmlnode_set_attrib(query, "seconds", idle_time);
		g_free(idle_time);

		jabber_iq_send(iq);
	}
}

static void jabber_time_parse(JabberStream *js, const char *from,
                              JabberIqType type, const char *id,
                              xmlnode *child)
{
	JabberIq *iq;
	time_t now_t;
	struct tm *tm;

	time(&now_t);

	if(type == JABBER_IQ_GET) {
		xmlnode *tzo, *utc;
		const char *date, *tz;

		iq = jabber_iq_new(js, JABBER_IQ_RESULT);
		jabber_iq_set_id(iq, id);
		if (from)
			xmlnode_set_attrib(iq->node, "to", from);

		child = xmlnode_new_child(iq->node, child->name);
		xmlnode_set_namespace(child, NS_ENTITY_TIME);

		/* <tzo>-06:00</tzo> */
		tm = localtime(&now_t);
		tz = purple_get_tzoff_str(tm, TRUE);
		tzo = xmlnode_new_child(child, "tzo");
		xmlnode_insert_data(tzo, tz, -1);

		/* <utc>2006-12-19T17:58:35Z</utc> */
		tm = gmtime(&now_t);
		date = purple_utf8_strftime("%Y-%m-%dT%H:%M:%SZ", tm);
		utc = xmlnode_new_child(child, "utc");
		xmlnode_insert_data(utc, date, -1);

		jabber_iq_send(iq);
	} else {
		/* TODO: Errors */
	}
}

static void jabber_iq_version_parse(JabberStream *js, const char *from,
                                    JabberIqType type, const char *id,
                                    xmlnode *packet)
{
	JabberIq *iq;
	xmlnode *query;

	if(type == JABBER_IQ_GET) {
		GHashTable *ui_info;
		const char *ui_name = NULL, *ui_version = NULL;
#if 0
		char *os = NULL;
		if(!purple_prefs_get_bool("/plugins/prpl/jabber/hide_os")) {
			struct utsname osinfo;

			uname(&osinfo);
			os = g_strdup_printf("%s %s %s", osinfo.sysname, osinfo.release,
					osinfo.machine);
		}
#endif

		iq = jabber_iq_new_query(js, JABBER_IQ_RESULT, "jabber:iq:version");
		if (from)
			xmlnode_set_attrib(iq->node, "to", from);
		jabber_iq_set_id(iq, id);

		query = xmlnode_get_child(iq->node, "query");

		ui_info = purple_core_get_ui_info();

		if(NULL != ui_info) {
			ui_name = g_hash_table_lookup(ui_info, "name");
			ui_version = g_hash_table_lookup(ui_info, "version");
		}

		if(NULL != ui_name && NULL != ui_version) {
			char *version_complete = g_strdup_printf("%s (libpurple " VERSION ")", ui_version);
			xmlnode_insert_data(xmlnode_new_child(query, "name"), ui_name, -1);
			xmlnode_insert_data(xmlnode_new_child(query, "version"), version_complete, -1);
			g_free(version_complete);
		} else {
			xmlnode_insert_data(xmlnode_new_child(query, "name"), "libpurple", -1);
			xmlnode_insert_data(xmlnode_new_child(query, "version"), VERSION, -1);
		}

#if 0
		if(os) {
			xmlnode_insert_data(xmlnode_new_child(query, "os"), os, -1);
			g_free(os);
		}
#endif

		jabber_iq_send(iq);
	}
}

void jabber_iq_remove_callback_by_id(JabberStream *js, const char *id)
{
	g_hash_table_remove(js->iq_callbacks, id);
}

/**
 * Verify that the 'from' attribute of an IQ reply is a valid match for
 * a given IQ request. The expected behavior is outlined in section
 * 8.1.2.1 of the XMPP CORE spec (RFC 6120). We consider the reply to
 * be a valid match if any of the following is true:
 * - Request 'to' matches reply 'from' (including the case where
 *   neither are set).
 * - Request 'to' was empty and reply 'from' is server JID.
 * - Request 'to' was empty and reply 'from' is my JID. The spec says
 *   we should only allow bare JID, but we also allow full JID for
 *   compatibility with some servers.
 *
 * These rules should allow valid IQ replies while preventing spoofed
 * ones.
 *
 * For more discussion see the "Spoofing of iq ids and misbehaving
 * servers" email thread from January 2014 on the jdev and security
 * mailing lists.
 *
 * @return TRUE if this reply is valid for the given request.
 */
static gboolean does_reply_from_match_request_to(JabberStream *js, JabberID *to, JabberID *from)
{
	if (jabber_id_equal(to, from)) {
		/* Request 'to' matches reply 'from' */
		return TRUE;
	}

	if (!to && purple_strequal(from->domain, js->user->domain)) {
		/* Request 'to' is empty and reply 'from' domain matches our domain */

		if (!from->node && !from->resource) {
			/* Reply 'from' is server bare JID */
			return TRUE;
		}

		if (purple_strequal(from->node, js->user->node)
				&& (!from->resource || purple_strequal(from->resource, js->user->resource))) {
			/* Reply 'from' is my full or bare JID */
			return TRUE;
		}
	}

	return FALSE;
}

void jabber_iq_parse(JabberStream *js, xmlnode *packet)
{
	JabberIqCallbackData *jcd;
	xmlnode *child, *error, *x;
	const char *xmlns;
	const char *iq_type, *id, *from;
	JabberIqType type = JABBER_IQ_NONE;
	gboolean signal_return;
	JabberID *from_id;

	from = xmlnode_get_attrib(packet, "from");
	id = xmlnode_get_attrib(packet, "id");
	iq_type = xmlnode_get_attrib(packet, "type");

	/*
	 * Ensure the 'from' attribute is valid. No point in handling a stanza
	 * of which we don't understand where it came from.
	 */
	from_id = jabber_id_new(from);

	if (from && !from_id) {
		purple_debug_error("jabber", "Received an iq with an invalid from: %s\n", from);
		return;
	}

	/*
	 * child will be either the first tag child or NULL if there is no child.
	 * Historically, we used just the 'query' subchild, but newer XEPs use
	 * differently named children. Grabbing the first child is (for the time
	 * being) sufficient.
	 */
	for (child = packet->child; child; child = child->next) {
		if (child->type == XMLNODE_TYPE_TAG)
			break;
	}

	if (iq_type) {
		if (!strcmp(iq_type, "get"))
			type = JABBER_IQ_GET;
		else if (!strcmp(iq_type, "set"))
			type = JABBER_IQ_SET;
		else if (!strcmp(iq_type, "result"))
			type = JABBER_IQ_RESULT;
		else if (!strcmp(iq_type, "error"))
			type = JABBER_IQ_ERROR;
	}

	if (type == JABBER_IQ_NONE) {
		purple_debug_error("jabber", "IQ with invalid type ('%s') - ignoring.\n",
						   iq_type ? iq_type : "(null)");
		jabber_id_free(from_id);
		return;
	}

	/* All IQs must have an ID, so send an error for a set/get that doesn't */
	if(!id || !*id) {

		if(type == JABBER_IQ_SET || type == JABBER_IQ_GET) {
			JabberIq *iq = jabber_iq_new(js, JABBER_IQ_ERROR);

			xmlnode_free(iq->node);
			iq->node = xmlnode_copy(packet);
			if (from) {
				xmlnode_set_attrib(iq->node, "to", from);
				xmlnode_remove_attrib(iq->node, "from");
			}

			xmlnode_set_attrib(iq->node, "type", "error");
			/* This id is clearly not useful, but we must put something there for a valid stanza */
			iq->id = jabber_get_next_id(js);
			xmlnode_set_attrib(iq->node, "id", iq->id);
			error = xmlnode_new_child(iq->node, "error");
			xmlnode_set_attrib(error, "type", "modify");
			x = xmlnode_new_child(error, "bad-request");
			xmlnode_set_namespace(x, NS_XMPP_STANZAS);

			jabber_iq_send(iq);
		} else
			purple_debug_error("jabber", "IQ of type '%s' missing id - ignoring.\n",
			                   iq_type);

		jabber_id_free(from_id);
		return;
	}

	signal_return = GPOINTER_TO_INT(purple_signal_emit_return_1(purple_connection_get_prpl(js->gc),
			"jabber-receiving-iq", js->gc, iq_type, id, from, packet));
	if (signal_return) {
		jabber_id_free(from_id);
		return;
	}

	/* First, lets see if a special callback got registered */
	if(type == JABBER_IQ_RESULT || type == JABBER_IQ_ERROR) {
		jcd = g_hash_table_lookup(js->iq_callbacks, id);
		if (jcd) {
			if (does_reply_from_match_request_to(js, jcd->to, from_id)) {
				jcd->callback(js, from, type, id, packet, jcd->data);
				jabber_iq_remove_callback_by_id(js, id);
				jabber_id_free(from_id);
				return;
			} else {
				char *expected_to;

				if (jcd->to) {
					expected_to = jabber_id_get_full_jid(jcd->to);
				} else {
					expected_to = jabber_id_get_bare_jid(js->user);
				}

				purple_debug_error("jabber", "Got a result iq with id %s from %s instead of expected %s!\n", id, from ? from : "(null)", expected_to);

				g_free(expected_to);
			}
		}
	}

	/*
	 * Apparently not, so let's see if we have a pre-defined handler
	 * or if an outside plugin is interested.
	 */
	if(child && (xmlns = xmlnode_get_namespace(child))) {
		char *key = g_strdup_printf("%s %s", child->name, xmlns);
		JabberIqHandler *jih = g_hash_table_lookup(iq_handlers, key);
		int signal_ref = GPOINTER_TO_INT(g_hash_table_lookup(signal_iq_handlers, key));
		g_free(key);

		if (signal_ref > 0) {
			signal_return = GPOINTER_TO_INT(purple_signal_emit_return_1(purple_connection_get_prpl(js->gc), "jabber-watched-iq",
					js->gc, iq_type, id, from, child));
			if (signal_return) {
				jabber_id_free(from_id);
				return;
			}
		}

		if(jih) {
			jih(js, from, type, id, child);
			jabber_id_free(from_id);
			return;
		}
	}

	purple_debug_misc("jabber", "Unhandled IQ with id %s\n", id);

	/* If we get here, send the default error reply mandated by XMPP-CORE */
	if(type == JABBER_IQ_SET || type == JABBER_IQ_GET) {
		JabberIq *iq = jabber_iq_new(js, JABBER_IQ_ERROR);

		xmlnode_free(iq->node);
		iq->node = xmlnode_copy(packet);
		if (from) {
			xmlnode_set_attrib(iq->node, "to", from);
			xmlnode_remove_attrib(iq->node, "from");
		}

		xmlnode_set_attrib(iq->node, "type", "error");
		error = xmlnode_new_child(iq->node, "error");
		xmlnode_set_attrib(error, "type", "cancel");
		xmlnode_set_attrib(error, "code", "501");
		x = xmlnode_new_child(error, "feature-not-implemented");
		xmlnode_set_namespace(x, NS_XMPP_STANZAS);

		jabber_iq_send(iq);
	}

	jabber_id_free(from_id);
}

void jabber_iq_register_handler(const char *node, const char *xmlns, JabberIqHandler *handlerfunc)
{
	/*
	 * This is valid because nodes nor namespaces cannot have spaces in them
	 * (see http://www.w3.org/TR/2006/REC-xml-20060816/ and
	 * http://www.w3.org/TR/REC-xml-names/)
	 */
	char *key = g_strdup_printf("%s %s", node, xmlns);
	g_hash_table_replace(iq_handlers, key, handlerfunc);
}

void jabber_iq_signal_register(const gchar *node, const gchar *xmlns)
{
	gchar *key;
	int ref;

	g_return_if_fail(node != NULL && *node != '\0');
	g_return_if_fail(xmlns != NULL && *xmlns != '\0');

	key = g_strdup_printf("%s %s", node, xmlns);
	ref = GPOINTER_TO_INT(g_hash_table_lookup(signal_iq_handlers, key));
	if (ref == 0) {
		g_hash_table_insert(signal_iq_handlers, key, GINT_TO_POINTER(1));
	} else {
		g_hash_table_insert(signal_iq_handlers, key, GINT_TO_POINTER(ref + 1));
		g_free(key);
	}
}

void jabber_iq_signal_unregister(const gchar *node, const gchar *xmlns)
{
	gchar *key;
	int ref;

	g_return_if_fail(node != NULL && *node != '\0');
	g_return_if_fail(xmlns != NULL && *xmlns != '\0');

	key = g_strdup_printf("%s %s", node, xmlns);
	ref = GPOINTER_TO_INT(g_hash_table_lookup(signal_iq_handlers, key));

	if (ref == 1) {
		g_hash_table_remove(signal_iq_handlers, key);
	} else if (ref > 1) {
		g_hash_table_insert(signal_iq_handlers, key, GINT_TO_POINTER(ref - 1));
	}

	g_free(key);
}

void jabber_iq_init(void)
{
	iq_handlers = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
	signal_iq_handlers = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);

	jabber_iq_register_handler("jingle", JINGLE, jingle_parse);
	jabber_iq_register_handler("mailbox", NS_GOOGLE_MAIL_NOTIFY,
			jabber_gmail_poke);
	jabber_iq_register_handler("new-mail", NS_GOOGLE_MAIL_NOTIFY,
			jabber_gmail_poke);
	jabber_iq_register_handler("ping", NS_PING, jabber_ping_parse);
	jabber_iq_register_handler("query", NS_GOOGLE_JINGLE_INFO,
			jabber_google_handle_jingle_info);
	jabber_iq_register_handler("query", NS_BYTESTREAMS,
			jabber_bytestreams_parse);
	jabber_iq_register_handler("query", NS_DISCO_INFO, jabber_disco_info_parse);
	jabber_iq_register_handler("query", NS_DISCO_ITEMS, jabber_disco_items_parse);
	jabber_iq_register_handler("query", NS_LAST_ACTIVITY, jabber_iq_last_parse);
	jabber_iq_register_handler("query", NS_OOB_IQ_DATA, jabber_oob_parse);
	jabber_iq_register_handler("query", "jabber:iq:register",
			jabber_register_parse);
	jabber_iq_register_handler("query", "jabber:iq:roster",
			jabber_roster_parse);
	jabber_iq_register_handler("query", "jabber:iq:version",
			jabber_iq_version_parse);
#ifdef USE_VV
	jabber_iq_register_handler("session", NS_GOOGLE_SESSION,
		jabber_google_session_parse);
#endif
	jabber_iq_register_handler("block", NS_SIMPLE_BLOCKING, jabber_blocklist_parse_push);
	jabber_iq_register_handler("unblock", NS_SIMPLE_BLOCKING, jabber_blocklist_parse_push);
	jabber_iq_register_handler("time", NS_ENTITY_TIME, jabber_time_parse);

}

void jabber_iq_uninit(void)
{
	g_hash_table_destroy(iq_handlers);
	g_hash_table_destroy(signal_iq_handlers);
	iq_handlers = signal_iq_handlers = NULL;
}
