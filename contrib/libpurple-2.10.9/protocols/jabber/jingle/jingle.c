/*
 * @file jingle.c
 *
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
#include "network.h"

#include "content.h"
#include "debug.h"
#include "jingle.h"
#include "session.h"
#include "iceudp.h"
#include "rawudp.h"
#include "rtp.h"

#include <string.h>
#ifdef USE_VV
#include <gst/gst.h>
#endif

GType
jingle_get_type(const gchar *type)
{
	if (type == NULL)
		return G_TYPE_NONE;

	if (!strcmp(type, JINGLE_TRANSPORT_RAWUDP))
		return JINGLE_TYPE_RAWUDP;
	else if (!strcmp(type, JINGLE_TRANSPORT_ICEUDP))
		return JINGLE_TYPE_ICEUDP;
#if 0
	else if (!strcmp(type, JINGLE_TRANSPORT_SOCKS))
		return JINGLE_TYPE_SOCKS;
	else if (!strcmp(type, JINGLE_TRANSPORT_IBB))
		return JINGLE_TYPE_IBB;
#endif
#ifdef USE_VV
	else if (!strcmp(type, JINGLE_APP_RTP))
		return JINGLE_TYPE_RTP;
#endif
#if 0
	else if (!strcmp(type, JINGLE_APP_FT))
		return JINGLE_TYPE_FT;
	else if (!strcmp(type, JINGLE_APP_XML))
		return JINGLE_TYPE_XML;
#endif
	else
		return G_TYPE_NONE;
}

static void
jingle_handle_unknown_type(JingleSession *session, xmlnode *jingle)
{
	/* Send error */
}

static void
jingle_handle_content_accept(JingleSession *session, xmlnode *jingle)
{
	xmlnode *content = xmlnode_get_child(jingle, "content");
	jabber_iq_send(jingle_session_create_ack(session, jingle));

	for (; content; content = xmlnode_get_next_twin(content)) {
		const gchar *name = xmlnode_get_attrib(content, "name");
		const gchar *creator = xmlnode_get_attrib(content, "creator");
		jingle_session_accept_content(session, name, creator);
		/* signal here */
	}
}

static void
jingle_handle_content_add(JingleSession *session, xmlnode *jingle)
{
	xmlnode *content = xmlnode_get_child(jingle, "content");
	jabber_iq_send(jingle_session_create_ack(session, jingle));

	for (; content; content = xmlnode_get_next_twin(content)) {
		JingleContent *pending_content =
				jingle_content_parse(content);
		if (pending_content == NULL) {
			purple_debug_error("jingle",
					"Error parsing \"content-add\" content.\n");
			jabber_iq_send(jingle_session_terminate_packet(session,
				"unsupported-applications"));
		} else {
			jingle_session_add_pending_content(session,
					pending_content);
		}
	}

	/* XXX: signal here */
}

static void
jingle_handle_content_modify(JingleSession *session, xmlnode *jingle)
{
	xmlnode *content = xmlnode_get_child(jingle, "content");
	jabber_iq_send(jingle_session_create_ack(session, jingle));

	for (; content; content = xmlnode_get_next_twin(content)) {
		const gchar *name = xmlnode_get_attrib(content, "name");
		const gchar *creator = xmlnode_get_attrib(content, "creator");
		JingleContent *local_content = jingle_session_find_content(session, name, creator);

		if (local_content != NULL) {
			const gchar *senders = xmlnode_get_attrib(content, "senders");
			gchar *local_senders = jingle_content_get_senders(local_content);
			if (!purple_strequal(senders, local_senders))
				jingle_content_modify(local_content, senders);
			g_free(local_senders);
		} else {
			purple_debug_error("jingle", "content_modify: unknown content\n");
			jabber_iq_send(jingle_session_terminate_packet(session,
				"unknown-applications"));
		}
	}
}

static void
jingle_handle_content_reject(JingleSession *session, xmlnode *jingle)
{
	xmlnode *content = xmlnode_get_child(jingle, "content");
	jabber_iq_send(jingle_session_create_ack(session, jingle));

	for (; content; content = xmlnode_get_next_twin(content)) {
		const gchar *name = xmlnode_get_attrib(content, "name");
		const gchar *creator = xmlnode_get_attrib(content, "creator");
		jingle_session_remove_pending_content(session, name, creator);
		/* signal here */
	}
}

static void
jingle_handle_content_remove(JingleSession *session, xmlnode *jingle)
{
	xmlnode *content = xmlnode_get_child(jingle, "content");

	jabber_iq_send(jingle_session_create_ack(session, jingle));

	for (; content; content = xmlnode_get_next_twin(content)) {
		const gchar *name = xmlnode_get_attrib(content, "name");
		const gchar *creator = xmlnode_get_attrib(content, "creator");
		jingle_session_remove_content(session, name, creator);
	}
}

static void
jingle_handle_description_info(JingleSession *session, xmlnode *jingle)
{
	xmlnode *content = xmlnode_get_child(jingle, "content");

	jabber_iq_send(jingle_session_create_ack(session, jingle));

	jingle_session_accept_session(session);

	for (; content; content = xmlnode_get_next_twin(content)) {
		const gchar *name = xmlnode_get_attrib(content, "name");
		const gchar *creator = xmlnode_get_attrib(content, "creator");
		JingleContent *parsed_content =
				jingle_session_find_content(session, name, creator);
		if (parsed_content == NULL) {
			purple_debug_error("jingle", "Error parsing content\n");
			jabber_iq_send(jingle_session_terminate_packet(session,
				"unsupported-applications"));
		} else {
			jingle_content_handle_action(parsed_content, content,
					JINGLE_DESCRIPTION_INFO);
		}
	}
}

static void
jingle_handle_security_info(JingleSession *session, xmlnode *jingle)
{
	jabber_iq_send(jingle_session_create_ack(session, jingle));
}

static void
jingle_handle_session_accept(JingleSession *session, xmlnode *jingle)
{
	xmlnode *content = xmlnode_get_child(jingle, "content");

	jabber_iq_send(jingle_session_create_ack(session, jingle));

	jingle_session_accept_session(session);

	for (; content; content = xmlnode_get_next_twin(content)) {
		const gchar *name = xmlnode_get_attrib(content, "name");
		const gchar *creator = xmlnode_get_attrib(content, "creator");
		JingleContent *parsed_content =
				jingle_session_find_content(session, name, creator);
		if (parsed_content == NULL) {
			purple_debug_error("jingle", "Error parsing content\n");
			jabber_iq_send(jingle_session_terminate_packet(session,
				"unsupported-applications"));
		} else {
			jingle_content_handle_action(parsed_content, content,
					JINGLE_SESSION_ACCEPT);
		}
	}
}

static void
jingle_handle_session_info(JingleSession *session, xmlnode *jingle)
{
	jabber_iq_send(jingle_session_create_ack(session, jingle));
	/* XXX: call signal */
}

static void
jingle_handle_session_initiate(JingleSession *session, xmlnode *jingle)
{
	xmlnode *content = xmlnode_get_child(jingle, "content");

	for (; content; content = xmlnode_get_next_twin(content)) {
		JingleContent *parsed_content = jingle_content_parse(content);
		if (parsed_content == NULL) {
			purple_debug_error("jingle", "Error parsing content\n");
			jabber_iq_send(jingle_session_terminate_packet(session,
				"unsupported-applications"));
		} else {
			jingle_session_add_content(session, parsed_content);
			jingle_content_handle_action(parsed_content, content,
					JINGLE_SESSION_INITIATE);
		}
	}

	jabber_iq_send(jingle_session_create_ack(session, jingle));
}

static void
jingle_handle_session_terminate(JingleSession *session, xmlnode *jingle)
{
	jabber_iq_send(jingle_session_create_ack(session, jingle));

	jingle_session_handle_action(session, jingle,
			JINGLE_SESSION_TERMINATE);
	/* display reason? */
	g_object_unref(session);
}

static void
jingle_handle_transport_accept(JingleSession *session, xmlnode *jingle)
{
	xmlnode *content = xmlnode_get_child(jingle, "content");

	jabber_iq_send(jingle_session_create_ack(session, jingle));

	for (; content; content = xmlnode_get_next_twin(content)) {
		const gchar *name = xmlnode_get_attrib(content, "name");
		const gchar *creator = xmlnode_get_attrib(content, "creator");
		JingleContent *content = jingle_session_find_content(session, name, creator);
		jingle_content_accept_transport(content);
	}
}

static void
jingle_handle_transport_info(JingleSession *session, xmlnode *jingle)
{
	xmlnode *content = xmlnode_get_child(jingle, "content");

	jabber_iq_send(jingle_session_create_ack(session, jingle));

	for (; content; content = xmlnode_get_next_twin(content)) {
		const gchar *name = xmlnode_get_attrib(content, "name");
		const gchar *creator = xmlnode_get_attrib(content, "creator");
		JingleContent *parsed_content =
				jingle_session_find_content(session, name, creator);
		if (parsed_content == NULL) {
			purple_debug_error("jingle", "Error parsing content\n");
			jabber_iq_send(jingle_session_terminate_packet(session,
				"unsupported-applications"));
		} else {
			jingle_content_handle_action(parsed_content, content,
					JINGLE_TRANSPORT_INFO);
		}
	}
}

static void
jingle_handle_transport_reject(JingleSession *session, xmlnode *jingle)
{
	xmlnode *content = xmlnode_get_child(jingle, "content");

	jabber_iq_send(jingle_session_create_ack(session, jingle));

	for (; content; content = xmlnode_get_next_twin(content)) {
		const gchar *name = xmlnode_get_attrib(content, "name");
		const gchar *creator = xmlnode_get_attrib(content, "creator");
		JingleContent *content = jingle_session_find_content(session, name, creator);
		jingle_content_remove_pending_transport(content);
	}
}

static void
jingle_handle_transport_replace(JingleSession *session, xmlnode *jingle)
{
	xmlnode *content = xmlnode_get_child(jingle, "content");

	jabber_iq_send(jingle_session_create_ack(session, jingle));

	for (; content; content = xmlnode_get_next_twin(content)) {
		const gchar *name = xmlnode_get_attrib(content, "name");
		const gchar *creator = xmlnode_get_attrib(content, "creator");
		xmlnode *xmltransport = xmlnode_get_child(content, "transport");
		JingleTransport *transport = jingle_transport_parse(xmltransport);
		JingleContent *content = jingle_session_find_content(session, name, creator);

		jingle_content_set_pending_transport(content, transport);
	}
}

typedef struct {
	const char *name;
	void (*handler)(JingleSession*, xmlnode*);
} JingleAction;

static const JingleAction jingle_actions[] = {
	{"unknown-type",	jingle_handle_unknown_type},
	{"content-accept",	jingle_handle_content_accept},
	{"content-add",		jingle_handle_content_add},
	{"content-modify",	jingle_handle_content_modify},
	{"content-reject",	jingle_handle_content_reject},
	{"content-remove",	jingle_handle_content_remove},
	{"description-info",	jingle_handle_description_info},
	{"security-info",	jingle_handle_security_info},
	{"session-accept",	jingle_handle_session_accept},
	{"session-info",	jingle_handle_session_info},
	{"session-initiate",	jingle_handle_session_initiate},
	{"session-terminate",	jingle_handle_session_terminate},
	{"transport-accept",	jingle_handle_transport_accept},
	{"transport-info",	jingle_handle_transport_info},
	{"transport-reject",	jingle_handle_transport_reject},
	{"transport-replace",	jingle_handle_transport_replace},
};

const gchar *
jingle_get_action_name(JingleActionType action)
{
	return jingle_actions[action].name;
}

JingleActionType
jingle_get_action_type(const gchar *action)
{
	static const int num_actions =
			sizeof(jingle_actions)/sizeof(JingleAction);
	/* Start at 1 to skip the unknown-action type */
	int i = 1;
	for (; i < num_actions; ++i) {
		if (!strcmp(action, jingle_actions[i].name))
			return i;
	}
	return JINGLE_UNKNOWN_TYPE;
}

void
jingle_parse(JabberStream *js, const char *from, JabberIqType type,
             const char *id, xmlnode *jingle)
{
	const gchar *action;
	const gchar *sid;
	JingleActionType action_type;
	JingleSession *session;

	if (type != JABBER_IQ_SET) {
		/* TODO: send iq error here */
		return;
	}

	if (!(action = xmlnode_get_attrib(jingle, "action"))) {
		/* TODO: send iq error here */
		return;
	}

	action_type = jingle_get_action_type(action);

	purple_debug_info("jabber", "got Jingle package action = %s\n",
			  action);

	if (!(sid = xmlnode_get_attrib(jingle, "sid"))) {
		/* send iq error here */
		return;
	}

	if (!(session = jingle_session_find_by_sid(js, sid))
			&& strcmp(action, "session-initiate")) {
		purple_debug_error("jingle", "jabber_jingle_session_parse couldn't find session\n");
		/* send iq error here */
		return;
	}

	if (action_type == JINGLE_SESSION_INITIATE) {
		if (session) {
			/* This should only happen if you start a session with yourself */
			purple_debug_error("jingle", "Jingle session with "
					"id={%s} already exists\n", sid);
			/* send iq error */
			return;
		} else {
			char *own_jid = g_strdup_printf("%s@%s/%s", js->user->node,
					js->user->domain, js->user->resource);
			session = jingle_session_create(js, sid, own_jid, from, FALSE);
			g_free(own_jid);
		}
	}

	jingle_actions[action_type].handler(session, jingle);
}

static void
jingle_terminate_sessions_gh(gpointer key, gpointer value, gpointer user_data)
{
	g_object_unref(value);
}

void
jingle_terminate_sessions(JabberStream *js)
{
	if (js->sessions)
		g_hash_table_foreach(js->sessions,
				jingle_terminate_sessions_gh, NULL);
}

#ifdef USE_VV
static GValueArray *
jingle_create_relay_info(const gchar *ip, guint port, const gchar *username,
	const gchar *password, const gchar *relay_type, GValueArray *relay_info)
{
	GValue value;
	GstStructure *turn_setup = gst_structure_new("relay-info",
		"ip", G_TYPE_STRING, ip,
		"port", G_TYPE_UINT, port,
		"username", G_TYPE_STRING, username,
		"password", G_TYPE_STRING, password,
		"relay-type", G_TYPE_STRING, relay_type,
		NULL);
	purple_debug_info("jabber", "created gst_structure %" GST_PTR_FORMAT "\n",
		turn_setup);
	if (turn_setup) {
		memset(&value, 0, sizeof(GValue));
		g_value_init(&value, GST_TYPE_STRUCTURE);
		gst_value_set_structure(&value, turn_setup);
		relay_info = g_value_array_append(relay_info, &value);
		gst_structure_free(turn_setup);
	}
	return relay_info;
}

GParameter *
jingle_get_params(JabberStream *js, const gchar *relay_ip, guint relay_udp,
	guint relay_tcp, guint relay_ssltcp, const gchar *relay_username,
    const gchar *relay_password, guint *num)
{
	/* don't set a STUN server if one is set globally in prefs, in that case
	 this will be handled in media.c */
	gboolean has_account_stun = js->stun_ip && !purple_network_get_stun_ip();
	guint num_params = has_account_stun ?
		(relay_ip ? 3 : 2) : (relay_ip ? 1 : 0);
	GParameter *params = NULL;
	int next_index = 0;

	if (num_params > 0) {
		params = g_new0(GParameter, num_params);

		if (has_account_stun) {
			purple_debug_info("jabber",
				"setting param stun-ip for stream using Google auto-config: %s\n",
				js->stun_ip);
			params[next_index].name = "stun-ip";
			g_value_init(&params[next_index].value, G_TYPE_STRING);
			g_value_set_string(&params[next_index].value, js->stun_ip);
			purple_debug_info("jabber",
				"setting param stun-port for stream using Google auto-config: %d\n",
				js->stun_port);
			next_index++;
			params[next_index].name = "stun-port";
			g_value_init(&params[next_index].value, G_TYPE_UINT);
			g_value_set_uint(&params[next_index].value, js->stun_port);
			next_index++;
		}

		if (relay_ip) {
			GValueArray *relay_info = g_value_array_new(0);

			if (relay_udp) {
				relay_info =
					jingle_create_relay_info(relay_ip, relay_udp, relay_username,
						relay_password, "udp", relay_info);
			}
			if (relay_tcp) {
				relay_info =
					jingle_create_relay_info(relay_ip, relay_tcp, relay_username,
						relay_password, "tcp", relay_info);
			}
			if (relay_ssltcp) {
				relay_info =
					jingle_create_relay_info(relay_ip, relay_ssltcp, relay_username,
						relay_password, "tls", relay_info);
			}
			params[next_index].name = "relay-info";
			g_value_init(&params[next_index].value, G_TYPE_VALUE_ARRAY);
			g_value_set_boxed(&params[next_index].value, relay_info);
			g_value_array_free(relay_info);
		}
	}

	*num = num_params;
	return params;
}
#endif

