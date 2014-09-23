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
#include "debug.h"
#include "prpl.h" /* for proto_chat_entry */
#include "notify.h"
#include "request.h"
#include "roomlist.h"
#include "util.h"

#include "chat.h"
#include "iq.h"
#include "message.h"
#include "presence.h"
#include "xdata.h"
#include "data.h"

GList *jabber_chat_info(PurpleConnection *gc)
{
	GList *m = NULL;
	struct proto_chat_entry *pce;

	pce = g_new0(struct proto_chat_entry, 1);
	pce->label = _("_Room:");
	pce->identifier = "room";
	pce->required = TRUE;
	m = g_list_append(m, pce);

	pce = g_new0(struct proto_chat_entry, 1);
	pce->label = _("_Server:");
	pce->identifier = "server";
	pce->required = TRUE;
	m = g_list_append(m, pce);

	pce = g_new0(struct proto_chat_entry, 1);
	pce->label = _("_Handle:");
	pce->identifier = "handle";
	pce->required = TRUE;
	m = g_list_append(m, pce);

	pce = g_new0(struct proto_chat_entry, 1);
	pce->label = _("_Password:");
	pce->identifier = "password";
	pce->secret = TRUE;
	m = g_list_append(m, pce);

	return m;
}

GHashTable *jabber_chat_info_defaults(PurpleConnection *gc, const char *chat_name)
{
	GHashTable *defaults;
	JabberStream *js = gc->proto_data;

	defaults = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);

	g_hash_table_insert(defaults, "handle", g_strdup(js->user->node));

	if (js->chat_servers)
		g_hash_table_insert(defaults, "server", g_strdup(js->chat_servers->data));

	if (chat_name != NULL) {
		JabberID *jid = jabber_id_new(chat_name);
		if(jid) {
			g_hash_table_insert(defaults, "room", g_strdup(jid->node));
			if(jid->domain)
				g_hash_table_replace(defaults, "server", g_strdup(jid->domain));
			if(jid->resource)
				g_hash_table_replace(defaults, "handle", g_strdup(jid->resource));
			jabber_id_free(jid);
		}
	}

	return defaults;
}

JabberChat *jabber_chat_find(JabberStream *js, const char *room,
		const char *server)
{
	JabberChat *chat = NULL;

	g_return_val_if_fail(room != NULL, NULL);
	g_return_val_if_fail(server != NULL, NULL);

	if(NULL != js->chats)
	{
		char *room_jid = g_strdup_printf("%s@%s", room, server);

		chat = g_hash_table_lookup(js->chats, room_jid);
		g_free(room_jid);
	}

	return chat;
}

struct _find_by_id_data {
	int id;
	JabberChat *chat;
};

static void find_by_id_foreach_cb(gpointer key, gpointer value, gpointer user_data)
{
	JabberChat *chat = value;
	struct _find_by_id_data *fbid = user_data;

	if(chat->id == fbid->id)
		fbid->chat = chat;
}

JabberChat *jabber_chat_find_by_id(JabberStream *js, int id)
{
	JabberChat *chat;
	struct _find_by_id_data *fbid = g_new0(struct _find_by_id_data, 1);
	fbid->id = id;
	g_hash_table_foreach(js->chats, find_by_id_foreach_cb, fbid);
	chat = fbid->chat;
	g_free(fbid);
	return chat;
}

JabberChat *jabber_chat_find_by_conv(PurpleConversation *conv)
{
	PurpleAccount *account = purple_conversation_get_account(conv);
	PurpleConnection *gc = purple_account_get_connection(account);
	JabberStream *js;
	int id;
	if (!gc)
		return NULL;
	js = gc->proto_data;
	id = purple_conv_chat_get_id(PURPLE_CONV_CHAT(conv));
	return jabber_chat_find_by_id(js, id);
}

void jabber_chat_invite(PurpleConnection *gc, int id, const char *msg,
		const char *name)
{
	JabberStream *js = gc->proto_data;
	JabberChat *chat;
	xmlnode *message, *body, *x, *invite;
	char *room_jid;

	chat = jabber_chat_find_by_id(js, id);
	if(!chat)
		return;

	message = xmlnode_new("message");

	room_jid = g_strdup_printf("%s@%s", chat->room, chat->server);

	if(chat->muc) {
		xmlnode_set_attrib(message, "to", room_jid);
		x = xmlnode_new_child(message, "x");
		xmlnode_set_namespace(x, "http://jabber.org/protocol/muc#user");
		invite = xmlnode_new_child(x, "invite");
		xmlnode_set_attrib(invite, "to", name);
		if (msg) {
			body = xmlnode_new_child(invite, "reason");
			xmlnode_insert_data(body, msg, -1);
		}
	} else {
		xmlnode_set_attrib(message, "to", name);
		/*
		 * Putting the reason into the body was an 'undocumented protocol,
		 * ...not part of "groupchat 1.0"'.
		 * http://xmpp.org/extensions/attic/jep-0045-1.16.html#invite
		 *
		 * Left here for compatibility.
		 */
		if (msg) {
			body = xmlnode_new_child(message, "body");
			xmlnode_insert_data(body, msg, -1);
		}

		x = xmlnode_new_child(message, "x");
		xmlnode_set_attrib(x, "jid", room_jid);

		/* The better place for it! XEP-0249 style. */
		if (msg)
			xmlnode_set_attrib(x, "reason", msg);
		xmlnode_set_namespace(x, "jabber:x:conference");
	}

	jabber_send(js, message);
	xmlnode_free(message);
	g_free(room_jid);
}

void jabber_chat_member_free(JabberChatMember *jcm);

char *jabber_get_chat_name(GHashTable *data) {
	char *room, *server, *chat_name = NULL;

	room = g_hash_table_lookup(data, "room");
	server = g_hash_table_lookup(data, "server");

	if (room && server) {
		chat_name = g_strdup_printf("%s@%s", room, server);
	}
	return chat_name;
}

static void insert_in_hash_table(gpointer key, gpointer value, gpointer user_data)
{
	GHashTable *hash_table = (GHashTable *)user_data;
	g_hash_table_insert(hash_table, g_strdup(key), g_strdup(value));
}

static JabberChat *jabber_chat_new(JabberStream *js, const char *room,
                                   const char *server, const char *handle,
                                   const char *password, GHashTable *data)
{
	JabberChat *chat;
	char *jid;

	if (jabber_chat_find(js, room, server) != NULL)
		return NULL;

	chat = g_new0(JabberChat, 1);
	chat->js = js;
	chat->joined = 0;

	chat->room = g_strdup(room);
	chat->server = g_strdup(server);
	chat->handle = g_strdup(handle);

	/* Copy the data hash table to chat->components */
	chat->components = g_hash_table_new_full(g_str_hash, g_str_equal,
			g_free, g_free);
	if (data == NULL) {
		g_hash_table_insert(chat->components, g_strdup("handle"), g_strdup(handle));
		g_hash_table_insert(chat->components, g_strdup("room"), g_strdup(room));
		g_hash_table_insert(chat->components, g_strdup("server"), g_strdup(server));
		/* g_hash_table_insert(chat->components, g_strdup("password"), g_strdup(server)); */
	} else {
		g_hash_table_foreach(data, insert_in_hash_table, chat->components);
	}

	chat->members = g_hash_table_new_full(g_str_hash, g_str_equal, NULL,
			(GDestroyNotify)jabber_chat_member_free);

	jid = g_strdup_printf("%s@%s", room, server);
	g_hash_table_insert(js->chats, jid, chat);

	return chat;
}

JabberChat *jabber_join_chat(JabberStream *js, const char *room,
                             const char *server, const char *handle,
                             const char *password, GHashTable *data)
{
	JabberChat *chat;

	PurpleConnection *gc;
	PurpleAccount *account;
	PurpleStatus *status;

	xmlnode *presence, *x;
	JabberBuddyState state;
	char *msg;
	int priority;

	char *jid;

	char *history_maxchars;
	char *history_maxstanzas;
	char *history_seconds;
	char *history_since;

	struct tm history_since_datetime;
	const char *history_since_string = NULL;

	chat = jabber_chat_new(js, room, server, handle, password, data);
	if (chat == NULL)
		return NULL;

	gc = js->gc;
	account = purple_connection_get_account(gc);
	status = purple_account_get_active_status(account);
	purple_status_to_jabber(status, &state, &msg, &priority);

	presence = jabber_presence_create_js(js, state, msg, priority);
	g_free(msg);

	jid = g_strdup_printf("%s@%s/%s", room, server, handle);
	xmlnode_set_attrib(presence, "to", jid);
	g_free(jid);

	history_maxchars   = g_hash_table_lookup(data, "history_maxchars");
	history_maxstanzas = g_hash_table_lookup(data, "history_maxstanzas");
	history_seconds    = g_hash_table_lookup(data, "history_seconds");
	history_since      = g_hash_table_lookup(data, "history_since");

	if (history_since) {
		if (purple_str_to_time(history_since, TRUE, &history_since_datetime, NULL, NULL) != 0) {
			history_since_string = purple_utf8_strftime("%Y-%m-%dT%H:%M:%SZ", &history_since_datetime);
		} else {
			history_since_string = NULL;

			purple_debug_error("jabber", "Invalid date format for history_since"
			                             " while requesting history: %s", history_since);
		}
	}

	x = xmlnode_new_child(presence, "x");
	xmlnode_set_namespace(x, "http://jabber.org/protocol/muc");

	if (password && *password) {
		xmlnode *p = xmlnode_new_child(x, "password");
		xmlnode_insert_data(p, password, -1);
	}

	if ((history_maxchars && *history_maxchars)
	    || (history_maxstanzas && *history_maxstanzas)
	    || (history_seconds && *history_seconds)
	    || (history_since_string && *history_since_string)) {

		xmlnode *history = xmlnode_new_child(x, "history");

		if (history_maxchars && *history_maxchars) {
			xmlnode_set_attrib(history, "maxchars", history_maxchars);
		}
		if (history_maxstanzas && *history_maxstanzas) {
			xmlnode_set_attrib(history, "maxstanzas", history_maxstanzas);
		}
		if (history_seconds && *history_seconds) {
			xmlnode_set_attrib(history, "seconds", history_seconds);
		}
		if (history_since_string && *history_since_string) {
			xmlnode_set_attrib(history, "since", history_since_string);
		}
	}

	jabber_send(js, presence);
	xmlnode_free(presence);

	return chat;
}

void jabber_chat_join(PurpleConnection *gc, GHashTable *data)
{
	char *room, *server, *handle, *passwd;
	JabberID *jid;
	JabberStream *js = gc->proto_data;
	char *tmp;

	room = g_hash_table_lookup(data, "room");
	server = g_hash_table_lookup(data, "server");
	handle = g_hash_table_lookup(data, "handle");
	passwd = g_hash_table_lookup(data, "password");

	if(!room || !server)
		return;

	if(!handle)
		handle = js->user->node;

	if(!jabber_nodeprep_validate(room)) {
		char *buf = g_strdup_printf(_("%s is not a valid room name"), room);
		purple_notify_error(gc, _("Invalid Room Name"), _("Invalid Room Name"),
				buf);
		purple_serv_got_join_chat_failed(gc, data);
		g_free(buf);
		return;
	} else if(!jabber_domain_validate(server)) {
		char *buf = g_strdup_printf(_("%s is not a valid server name"), server);
		purple_notify_error(gc, _("Invalid Server Name"),
				_("Invalid Server Name"), buf);
		purple_serv_got_join_chat_failed(gc, data);
		g_free(buf);
		return;
	} else if(!jabber_resourceprep_validate(handle)) {
		char *buf = g_strdup_printf(_("%s is not a valid room handle"), handle);
		purple_notify_error(gc, _("Invalid Room Handle"),
				_("Invalid Room Handle"), buf);
		purple_serv_got_join_chat_failed(gc, data);
		g_free(buf);
		return;
	}

	/* Normalize the room and server parameters */
	tmp = g_strdup_printf("%s@%s", room, server);
	jid = jabber_id_new(tmp);
	g_free(tmp);

	if (jid == NULL) {
		/* TODO: Error message */

		g_return_if_reached();
	}

	/*
	 * Now that we've done all that nice core-interface stuff, let's join
	 * this room!
	 */
	jabber_join_chat(js, jid->node, jid->domain, handle, passwd, data);
	jabber_id_free(jid);
}

void jabber_chat_leave(PurpleConnection *gc, int id)
{
	JabberStream *js = gc->proto_data;
	JabberChat *chat = jabber_chat_find_by_id(js, id);


	if(!chat)
		return;

	jabber_chat_part(chat, NULL);

	chat->left = TRUE;
}

void jabber_chat_destroy(JabberChat *chat)
{
	JabberStream *js = chat->js;
	char *room_jid = g_strdup_printf("%s@%s", chat->room, chat->server);

	g_hash_table_remove(js->chats, room_jid);
	g_free(room_jid);
}

void jabber_chat_free(JabberChat *chat)
{
	if(chat->config_dialog_handle)
		purple_request_close(chat->config_dialog_type, chat->config_dialog_handle);

	g_free(chat->room);
	g_free(chat->server);
	g_free(chat->handle);
	g_hash_table_destroy(chat->members);
	g_hash_table_destroy(chat->components);
	g_free(chat);
}

gboolean jabber_chat_find_buddy(PurpleConversation *conv, const char *name)
{
	return purple_conv_chat_find_user(PURPLE_CONV_CHAT(conv), name);
}

char *jabber_chat_buddy_real_name(PurpleConnection *gc, int id, const char *who)
{
	JabberStream *js = gc->proto_data;
	JabberChat *chat;
	JabberChatMember *jcm;

	chat = jabber_chat_find_by_id(js, id);

	if(!chat)
		return NULL;

	jcm = g_hash_table_lookup(chat->members, who);
	if (jcm != NULL && jcm->jid)
		return g_strdup(jcm->jid);


	return g_strdup_printf("%s@%s/%s", chat->room, chat->server, who);
}

static void jabber_chat_room_configure_x_data_cb(JabberStream *js, xmlnode *result, gpointer data)
{
	JabberChat *chat = data;
	xmlnode *query;
	JabberIq *iq;
	char *to = g_strdup_printf("%s@%s", chat->room, chat->server);

	iq = jabber_iq_new_query(js, JABBER_IQ_SET, "http://jabber.org/protocol/muc#owner");
	xmlnode_set_attrib(iq->node, "to", to);
	g_free(to);

	query = xmlnode_get_child(iq->node, "query");

	xmlnode_insert_child(query, result);

	jabber_iq_send(iq);
}

static void jabber_chat_room_configure_cb(JabberStream *js, const char *from,
                                          JabberIqType type, const char *id,
                                          xmlnode *packet, gpointer data)
{
	xmlnode *query, *x;
	char *msg;
	JabberChat *chat;
	JabberID *jid;

	if (!from)
		return;

	if (type == JABBER_IQ_RESULT) {
		jid = jabber_id_new(from);

		if(!jid)
			return;

		chat = jabber_chat_find(js, jid->node, jid->domain);
		jabber_id_free(jid);

		if(!chat)
			return;

		if(!(query = xmlnode_get_child(packet, "query")))
			return;

		for(x = xmlnode_get_child(query, "x"); x; x = xmlnode_get_next_twin(x)) {
			const char *xmlns;
			if(!(xmlns = xmlnode_get_namespace(x)))
				continue;

			if(!strcmp(xmlns, "jabber:x:data")) {
				chat->config_dialog_type = PURPLE_REQUEST_FIELDS;
				chat->config_dialog_handle = jabber_x_data_request(js, x, jabber_chat_room_configure_x_data_cb, chat);
				return;
			}
		}
	} else if (type == JABBER_IQ_ERROR) {
		char *msg = jabber_parse_error(js, packet, NULL);

		purple_notify_error(js->gc, _("Configuration error"), _("Configuration error"), msg);

		if(msg)
			g_free(msg);
		return;
	}

	msg = g_strdup_printf("Unable to configure room %s", from);

	purple_notify_info(js->gc, _("Unable to configure"), _("Unable to configure"), msg);
	g_free(msg);

}

void jabber_chat_request_room_configure(JabberChat *chat) {
	JabberIq *iq;
	char *room_jid;

	if(!chat)
		return;

	chat->config_dialog_handle = NULL;

	if(!chat->muc) {
		purple_notify_error(chat->js->gc, _("Room Configuration Error"), _("Room Configuration Error"),
				_("This room is not capable of being configured"));
		return;
	}

	iq = jabber_iq_new_query(chat->js, JABBER_IQ_GET,
			"http://jabber.org/protocol/muc#owner");
	room_jid = g_strdup_printf("%s@%s", chat->room, chat->server);

	xmlnode_set_attrib(iq->node, "to", room_jid);

	jabber_iq_set_callback(iq, jabber_chat_room_configure_cb, NULL);

	jabber_iq_send(iq);

	g_free(room_jid);
}

void jabber_chat_create_instant_room(JabberChat *chat) {
	JabberIq *iq;
	xmlnode *query, *x;
	char *room_jid;

	if(!chat)
		return;

	chat->config_dialog_handle = NULL;

	iq = jabber_iq_new_query(chat->js, JABBER_IQ_SET,
			"http://jabber.org/protocol/muc#owner");
	query = xmlnode_get_child(iq->node, "query");
	x = xmlnode_new_child(query, "x");
	room_jid = g_strdup_printf("%s@%s", chat->room, chat->server);

	xmlnode_set_attrib(iq->node, "to", room_jid);
	xmlnode_set_namespace(x, "jabber:x:data");
	xmlnode_set_attrib(x, "type", "submit");

	jabber_iq_send(iq);

	g_free(room_jid);
}

static void
jabber_chat_register_x_data_result_cb(JabberStream *js, const char *from,
                                      JabberIqType type, const char *id,
                                      xmlnode *packet, gpointer data)
{
	if (type == JABBER_IQ_ERROR) {
		char *msg = jabber_parse_error(js, packet, NULL);

		purple_notify_error(js->gc, _("Registration error"), _("Registration error"), msg);

		if(msg)
			g_free(msg);
		return;
	}
}

static void jabber_chat_register_x_data_cb(JabberStream *js, xmlnode *result, gpointer data)
{
	JabberChat *chat = data;
	xmlnode *query;
	JabberIq *iq;
	char *to = g_strdup_printf("%s@%s", chat->room, chat->server);

	iq = jabber_iq_new_query(js, JABBER_IQ_SET, "jabber:iq:register");
	xmlnode_set_attrib(iq->node, "to", to);
	g_free(to);

	query = xmlnode_get_child(iq->node, "query");

	xmlnode_insert_child(query, result);

	jabber_iq_set_callback(iq, jabber_chat_register_x_data_result_cb, NULL);

	jabber_iq_send(iq);
}

static void jabber_chat_register_cb(JabberStream *js, const char *from,
                                    JabberIqType type, const char *id,
                                    xmlnode *packet, gpointer data)
{
	xmlnode *query, *x;
	char *msg;
	JabberChat *chat;
	JabberID *jid;

	if (!from)
		return;

	if (type == JABBER_IQ_RESULT) {
		jid = jabber_id_new(from);

		if(!jid)
			return;

		chat = jabber_chat_find(js, jid->node, jid->domain);
		jabber_id_free(jid);

		if(!chat)
			return;

		if(!(query = xmlnode_get_child(packet, "query")))
			return;

		for(x = xmlnode_get_child(query, "x"); x; x = xmlnode_get_next_twin(x)) {
			const char *xmlns;

			if(!(xmlns = xmlnode_get_namespace(x)))
				continue;

			if(!strcmp(xmlns, "jabber:x:data")) {
				jabber_x_data_request(js, x, jabber_chat_register_x_data_cb, chat);
				return;
			}
		}
	} else if (type == JABBER_IQ_ERROR) {
		char *msg = jabber_parse_error(js, packet, NULL);

		purple_notify_error(js->gc, _("Registration error"), _("Registration error"), msg);

		if(msg)
			g_free(msg);
		return;
	}

	msg = g_strdup_printf("Unable to configure room %s", from);

	purple_notify_info(js->gc, _("Unable to configure"), _("Unable to configure"), msg);
	g_free(msg);

}

void jabber_chat_register(JabberChat *chat)
{
	JabberIq *iq;
	char *room_jid;

	if(!chat)
		return;

	room_jid = g_strdup_printf("%s@%s", chat->room, chat->server);

	iq = jabber_iq_new_query(chat->js, JABBER_IQ_GET, "jabber:iq:register");
	xmlnode_set_attrib(iq->node, "to", room_jid);
	g_free(room_jid);

	jabber_iq_set_callback(iq, jabber_chat_register_cb, NULL);

	jabber_iq_send(iq);
}

/* merge this with the function below when we get everyone on the same page wrt /commands */
void jabber_chat_change_topic(JabberChat *chat, const char *topic)
{
	JabberMessage *jm;

	jm = g_new0(JabberMessage, 1);
	jm->js = chat->js;
	jm->type = JABBER_MESSAGE_GROUPCHAT;
	jm->to = g_strdup_printf("%s@%s", chat->room, chat->server);

	if (topic && *topic)
		jm->subject = g_strdup(topic);
	else
		jm->subject = g_strdup("");

	jabber_message_send(jm);
	jabber_message_free(jm);
}

void jabber_chat_set_topic(PurpleConnection *gc, int id, const char *topic)
{
	JabberStream *js = purple_connection_get_protocol_data(gc);
	JabberChat *chat = jabber_chat_find_by_id(js, id);

	if(!chat)
		return;

	jabber_chat_change_topic(chat, topic);
}


gboolean jabber_chat_change_nick(JabberChat *chat, const char *nick)
{
	xmlnode *presence;
	char *full_jid;
	PurpleAccount *account;
	PurpleStatus *status;
	JabberBuddyState state;
	char *msg;
	int priority;

	if(!chat->muc) {
		purple_conv_chat_write(PURPLE_CONV_CHAT(chat->conv), "",
				_("Nick changing not supported in non-MUC chatrooms"),
				PURPLE_MESSAGE_SYSTEM, time(NULL));
		return FALSE;
	}

	account = purple_connection_get_account(chat->js->gc);
	status = purple_account_get_active_status(account);

	purple_status_to_jabber(status, &state, &msg, &priority);

	presence = jabber_presence_create_js(chat->js, state, msg, priority);
	full_jid = g_strdup_printf("%s@%s/%s", chat->room, chat->server, nick);
	xmlnode_set_attrib(presence, "to", full_jid);
	g_free(full_jid);
	g_free(msg);

	jabber_send(chat->js, presence);
	xmlnode_free(presence);

	return TRUE;
}

void jabber_chat_part(JabberChat *chat, const char *msg)
{
	char *room_jid;
	xmlnode *presence;

	room_jid = g_strdup_printf("%s@%s/%s", chat->room, chat->server,
			chat->handle);
	presence = xmlnode_new("presence");
	xmlnode_set_attrib(presence, "to", room_jid);
	xmlnode_set_attrib(presence, "type", "unavailable");
	if(msg) {
		xmlnode *status = xmlnode_new_child(presence, "status");
		xmlnode_insert_data(status, msg, -1);
	}
	jabber_send(chat->js, presence);

	xmlnode_free(presence);
	g_free(room_jid);
}

static void roomlist_disco_result_cb(JabberStream *js, const char *from,
                                     JabberIqType type, const char *id,
                                     xmlnode *packet, gpointer data)
{
	xmlnode *query;
	xmlnode *item;

	if(!js->roomlist)
		return;

	if (type == JABBER_IQ_ERROR) {
		char *err = jabber_parse_error(js, packet, NULL);
		purple_notify_error(js->gc, _("Error"),
				_("Error retrieving room list"), err);
		purple_roomlist_set_in_progress(js->roomlist, FALSE);
		purple_roomlist_unref(js->roomlist);
		js->roomlist = NULL;
		g_free(err);
		return;
	}

	if(!(query = xmlnode_get_child(packet, "query"))) {
		char *err = jabber_parse_error(js, packet, NULL);
		purple_notify_error(js->gc, _("Error"),
				_("Error retrieving room list"), err);
		purple_roomlist_set_in_progress(js->roomlist, FALSE);
		purple_roomlist_unref(js->roomlist);
		js->roomlist = NULL;
		g_free(err);
		return;
	}

	for(item = xmlnode_get_child(query, "item"); item;
			item = xmlnode_get_next_twin(item)) {
		const char *name;
		PurpleRoomlistRoom *room;
		JabberID *jid;

		if(!(jid = jabber_id_new(xmlnode_get_attrib(item, "jid"))))
			continue;
		name = xmlnode_get_attrib(item, "name");


		room = purple_roomlist_room_new(PURPLE_ROOMLIST_ROOMTYPE_ROOM, jid->node, NULL);
		purple_roomlist_room_add_field(js->roomlist, room, jid->node);
		purple_roomlist_room_add_field(js->roomlist, room, jid->domain);
		purple_roomlist_room_add_field(js->roomlist, room, name ? name : "");
		purple_roomlist_room_add(js->roomlist, room);

		jabber_id_free(jid);
	}
	purple_roomlist_set_in_progress(js->roomlist, FALSE);
	purple_roomlist_unref(js->roomlist);
	js->roomlist = NULL;
}

static void roomlist_cancel_cb(JabberStream *js, const char *server) {
	if(js->roomlist) {
		purple_roomlist_set_in_progress(js->roomlist, FALSE);
		purple_roomlist_unref(js->roomlist);
		js->roomlist = NULL;
	}
}

static void roomlist_ok_cb(JabberStream *js, const char *server)
{
	JabberIq *iq;

	if(!js->roomlist)
		return;

	if(!server || !*server) {
		purple_notify_error(js->gc, _("Invalid Server"), _("Invalid Server"), NULL);
		purple_roomlist_set_in_progress(js->roomlist, FALSE);
		return;
	}

	purple_roomlist_set_in_progress(js->roomlist, TRUE);

	iq = jabber_iq_new_query(js, JABBER_IQ_GET, NS_DISCO_ITEMS);

	xmlnode_set_attrib(iq->node, "to", server);

	jabber_iq_set_callback(iq, roomlist_disco_result_cb, NULL);

	jabber_iq_send(iq);
}

char *jabber_roomlist_room_serialize(PurpleRoomlistRoom *room)
{

	return g_strdup_printf("%s@%s", (char*)room->fields->data, (char*)room->fields->next->data);
}

PurpleRoomlist *jabber_roomlist_get_list(PurpleConnection *gc)
{
	JabberStream *js = gc->proto_data;
	GList *fields = NULL;
	PurpleRoomlistField *f;

	if(js->roomlist)
		purple_roomlist_unref(js->roomlist);

	js->roomlist = purple_roomlist_new(purple_connection_get_account(js->gc));

	f = purple_roomlist_field_new(PURPLE_ROOMLIST_FIELD_STRING, "", "room", TRUE);
	fields = g_list_append(fields, f);

	f = purple_roomlist_field_new(PURPLE_ROOMLIST_FIELD_STRING, "", "server", TRUE);
	fields = g_list_append(fields, f);

	f = purple_roomlist_field_new(PURPLE_ROOMLIST_FIELD_STRING, _("Description"), "description", FALSE);
	fields = g_list_append(fields, f);

	purple_roomlist_set_fields(js->roomlist, fields);


	purple_request_input(gc, _("Enter a Conference Server"), _("Enter a Conference Server"),
			_("Select a conference server to query"),
			js->chat_servers ? js->chat_servers->data : NULL,
			FALSE, FALSE, NULL,
			_("Find Rooms"), PURPLE_CALLBACK(roomlist_ok_cb),
			_("Cancel"), PURPLE_CALLBACK(roomlist_cancel_cb),
			purple_connection_get_account(gc), NULL, NULL,
			js);

	return js->roomlist;
}

void jabber_roomlist_cancel(PurpleRoomlist *list)
{
	PurpleConnection *gc;
	JabberStream *js;

	gc = purple_account_get_connection(list->account);
	js = gc->proto_data;

	purple_roomlist_set_in_progress(list, FALSE);

	if (js->roomlist == list) {
		js->roomlist = NULL;
		purple_roomlist_unref(list);
	}
}

void jabber_chat_member_free(JabberChatMember *jcm)
{
	g_free(jcm->handle);
	g_free(jcm->jid);
	g_free(jcm);
}

void jabber_chat_track_handle(JabberChat *chat, const char *handle,
		const char *jid, const char *affiliation, const char *role)
{
	JabberChatMember *jcm = g_new0(JabberChatMember, 1);

	jcm->handle = g_strdup(handle);
	jcm->jid = g_strdup(jid);

	g_hash_table_replace(chat->members, jcm->handle, jcm);

	/* XXX: keep track of role and affiliation */
}

void jabber_chat_remove_handle(JabberChat *chat, const char *handle)
{
	g_hash_table_remove(chat->members, handle);
}

gboolean jabber_chat_ban_user(JabberChat *chat, const char *who, const char *why)
{
	JabberChatMember *jcm;
	const char *jid;
	char *to;
	JabberIq *iq;
	xmlnode *query, *item, *reason;

	jcm = g_hash_table_lookup(chat->members, who);
	if (jcm && jcm->jid)
		jid = jcm->jid;
	else if (strchr(who, '@') != NULL)
		jid = who;
	else
		return FALSE;

	iq = jabber_iq_new_query(chat->js, JABBER_IQ_SET,
			"http://jabber.org/protocol/muc#admin");

	to = g_strdup_printf("%s@%s", chat->room, chat->server);
	xmlnode_set_attrib(iq->node, "to", to);
	g_free(to);

	query = xmlnode_get_child(iq->node, "query");
	item = xmlnode_new_child(query, "item");
	xmlnode_set_attrib(item, "jid", jid);
	xmlnode_set_attrib(item, "affiliation", "outcast");
	if(why) {
		reason = xmlnode_new_child(item, "reason");
		xmlnode_insert_data(reason, why, -1);
	}

	jabber_iq_send(iq);

	return TRUE;
}

gboolean jabber_chat_affiliate_user(JabberChat *chat, const char *who, const char *affiliation)
{
	JabberChatMember *jcm;
	const char *jid;
	char *to;
	JabberIq *iq;
	xmlnode *query, *item;

	jcm = g_hash_table_lookup(chat->members, who);
	if (jcm && jcm->jid)
		jid = jcm->jid;
	else if (strchr(who, '@') != NULL)
		jid = who;
	else
		return FALSE;

	iq = jabber_iq_new_query(chat->js, JABBER_IQ_SET,
			"http://jabber.org/protocol/muc#admin");

	to = g_strdup_printf("%s@%s", chat->room, chat->server);
	xmlnode_set_attrib(iq->node, "to", to);
	g_free(to);

	query = xmlnode_get_child(iq->node, "query");
	item = xmlnode_new_child(query, "item");
	xmlnode_set_attrib(item, "jid", jid);
	xmlnode_set_attrib(item, "affiliation", affiliation);

	jabber_iq_send(iq);

	return TRUE;
}

static void
jabber_chat_affiliation_list_cb(JabberStream *js, const char *from,
                                JabberIqType type, const char *id,
                                xmlnode *packet, gpointer data)
{
	JabberChat *chat;
	xmlnode *query, *item;
	int chat_id = GPOINTER_TO_INT(data);
	GString *buf;

	if(!(chat = jabber_chat_find_by_id(js, chat_id)))
		return;

	if (type == JABBER_IQ_ERROR)
		return;

	if(!(query = xmlnode_get_child(packet, "query")))
		return;

	buf = g_string_new(_("Affiliations:"));

	item = xmlnode_get_child(query, "item");
	if (item) {
		for( ; item; item = xmlnode_get_next_twin(item)) {
			const char *jid = xmlnode_get_attrib(item, "jid");
			const char *affiliation = xmlnode_get_attrib(item, "affiliation");
			if (jid && affiliation)
				g_string_append_printf(buf, "\n%s %s", jid, affiliation);
		}
    } else {
		buf = g_string_append_c(buf, '\n');
		buf = g_string_append_len(buf, _("No users found"), -1);
	}

	purple_conv_chat_write(PURPLE_CONV_CHAT(chat->conv), "", buf->str,
    	PURPLE_MESSAGE_SYSTEM | PURPLE_MESSAGE_NO_LOG, time(NULL));

	g_string_free(buf, TRUE);
}

gboolean jabber_chat_affiliation_list(JabberChat *chat, const char *affiliation)
{
	JabberIq *iq;
	char *room_jid;
	xmlnode *query, *item;

	iq = jabber_iq_new_query(chat->js, JABBER_IQ_GET,
			"http://jabber.org/protocol/muc#admin");

	room_jid = g_strdup_printf("%s@%s", chat->room, chat->server);
	xmlnode_set_attrib(iq->node, "to", room_jid);

	query = xmlnode_get_child(iq->node, "query");
	item = xmlnode_new_child(query, "item");
	xmlnode_set_attrib(item, "affiliation", affiliation);

	jabber_iq_set_callback(iq, jabber_chat_affiliation_list_cb, GINT_TO_POINTER(chat->id));
	jabber_iq_send(iq);

	return TRUE;
}

gboolean jabber_chat_role_user(JabberChat *chat, const char *who,
                               const char *role, const char *why)
{
	char *to;
	JabberIq *iq;
	xmlnode *query, *item;
	JabberChatMember *jcm;

	jcm = g_hash_table_lookup(chat->members, who);

	if (!jcm || !jcm->handle)
		return FALSE;

	iq = jabber_iq_new_query(chat->js, JABBER_IQ_SET,
	                         "http://jabber.org/protocol/muc#admin");

	to = g_strdup_printf("%s@%s", chat->room, chat->server);
	xmlnode_set_attrib(iq->node, "to", to);
	g_free(to);

	query = xmlnode_get_child(iq->node, "query");
	item = xmlnode_new_child(query, "item");
	xmlnode_set_attrib(item, "nick", jcm->handle);
	xmlnode_set_attrib(item, "role", role);
	if (why) {
		xmlnode *reason = xmlnode_new_child(item, "reason");
		xmlnode_insert_data(reason, why, -1);
	}

	jabber_iq_send(iq);

	return TRUE;
}

static void jabber_chat_role_list_cb(JabberStream *js, const char *from,
                                     JabberIqType type, const char *id,
                                     xmlnode *packet, gpointer data)
{
	JabberChat *chat;
	xmlnode *query, *item;
	int chat_id = GPOINTER_TO_INT(data);
	GString *buf;

	if(!(chat = jabber_chat_find_by_id(js, chat_id)))
		return;

	if (type == JABBER_IQ_ERROR)
		return;

	if(!(query = xmlnode_get_child(packet, "query")))
		return;

	buf = g_string_new(_("Roles:"));

	item = xmlnode_get_child(query, "item");
	if (item) {
		for( ; item; item = xmlnode_get_next_twin(item)) {
			const char *jid  = xmlnode_get_attrib(item, "jid");
			const char *role = xmlnode_get_attrib(item, "role");
			if (jid && role)
				g_string_append_printf(buf, "\n%s %s", jid, role);
	    }
	} else {
		buf = g_string_append_c(buf, '\n');
		buf = g_string_append_len(buf, _("No users found"), -1);
	}

	purple_conv_chat_write(PURPLE_CONV_CHAT(chat->conv), "", buf->str,
    	PURPLE_MESSAGE_SYSTEM | PURPLE_MESSAGE_NO_LOG, time(NULL));

	g_string_free(buf, TRUE);
}

gboolean jabber_chat_role_list(JabberChat *chat, const char *role)
{
	JabberIq *iq;
	char *room_jid;
	xmlnode *query, *item;

	iq = jabber_iq_new_query(chat->js, JABBER_IQ_GET,
			"http://jabber.org/protocol/muc#admin");

	room_jid = g_strdup_printf("%s@%s", chat->room, chat->server);
	xmlnode_set_attrib(iq->node, "to", room_jid);

	query = xmlnode_get_child(iq->node, "query");
	item = xmlnode_new_child(query, "item");
	xmlnode_set_attrib(item, "role", role);

	jabber_iq_set_callback(iq, jabber_chat_role_list_cb, GINT_TO_POINTER(chat->id));
	jabber_iq_send(iq);

	return TRUE;
}

static void jabber_chat_disco_traffic_cb(JabberStream *js, const char *from,
                                         JabberIqType type, const char *id,
                                         xmlnode *packet, gpointer data)
{
	JabberChat *chat;
#if 0
	xmlnode *query, *x;
#endif
	int chat_id = GPOINTER_TO_INT(data);

	if(!(chat = jabber_chat_find_by_id(js, chat_id)))
		return;

	/* defaults, in case the conference server doesn't
	 * support this request */
	chat->xhtml = TRUE;

	/* disabling this until more MUC servers support
	 * announcing this */
#if 0
	if (type == JABBER_IQ_ERROR) {
		return;
	}

	if(!(query = xmlnode_get_child(packet, "query")))
		return;

	chat->xhtml = FALSE;

	for(x = xmlnode_get_child(query, "feature"); x; x = xmlnode_get_next_twin(x)) {
		const char *var = xmlnode_get_attrib(x, "var");

		if(var && !strcmp(var, NS_XHTML_IM)) {
			chat->xhtml = TRUE;
		}
	}
#endif
}

void jabber_chat_disco_traffic(JabberChat *chat)
{
	JabberIq *iq;
	xmlnode *query;
	char *room_jid;

	room_jid = g_strdup_printf("%s@%s", chat->room, chat->server);

	iq = jabber_iq_new_query(chat->js, JABBER_IQ_GET, NS_DISCO_INFO);

	xmlnode_set_attrib(iq->node, "to", room_jid);

	query = xmlnode_get_child(iq->node, "query");

	xmlnode_set_attrib(query, "node", "http://jabber.org/protocol/muc#traffic");

	jabber_iq_set_callback(iq, jabber_chat_disco_traffic_cb, GINT_TO_POINTER(chat->id));

	jabber_iq_send(iq);

	g_free(room_jid);
}

typedef struct {
	const gchar *cap;
	gboolean *all_support;
	JabberBuddy *jb;
} JabberChatCapsData;

static void
jabber_chat_all_participants_have_capability_foreach(gpointer key,
                                                     gpointer value,
                                                     gpointer user_data)
{
	const gchar *cap = ((JabberChatCapsData *) user_data)->cap;
	gboolean *all_support = ((JabberChatCapsData *) user_data)->all_support;
	JabberBuddy *jb = ((JabberChatCapsData *) user_data)->jb;
	JabberChatMember *member = (JabberChatMember *) value;
	const gchar *resource = member->handle;
	JabberBuddyResource *jbr = jabber_buddy_find_resource(jb, resource);

	if (jbr) {
		*all_support &= jabber_resource_has_capability(jbr, cap);
	} else {
		*all_support = FALSE;
	}
}

gboolean
jabber_chat_all_participants_have_capability(const JabberChat *chat,
	const gchar *cap)
{
	gchar *chat_jid = NULL;
	JabberBuddy *jb = NULL;
	gboolean all_support = TRUE;
	JabberChatCapsData data;

	chat_jid = g_strdup_printf("%s@%s", chat->room, chat->server);
	jb = jabber_buddy_find(chat->js, chat_jid, FALSE);

	if (jb) {
		data.cap = cap;
		data.all_support = &all_support;
		data.jb = jb;

		g_hash_table_foreach(chat->members,
			jabber_chat_all_participants_have_capability_foreach, &data);
	} else {
		all_support = FALSE;
	}
	g_free(chat_jid);
	return all_support;
}

guint
jabber_chat_get_num_participants(const JabberChat *chat)
{
	return g_hash_table_size(chat->members);
}
