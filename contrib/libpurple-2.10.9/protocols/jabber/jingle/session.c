/**
 * @file session.c
 *
 * purple
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
 */

#include "internal.h"

#include "content.h"
#include "debug.h"
#include "session.h"
#include "jingle.h"

#include <string.h>

struct _JingleSessionPrivate
{
	gchar *sid;
	JabberStream *js;
	gchar *remote_jid;
	gchar *local_jid;
	gboolean is_initiator;
	gboolean state;
	GList *contents;
	GList *pending_contents;
};

#define JINGLE_SESSION_GET_PRIVATE(obj) (G_TYPE_INSTANCE_GET_PRIVATE((obj), JINGLE_TYPE_SESSION, JingleSessionPrivate))

static void jingle_session_class_init (JingleSessionClass *klass);
static void jingle_session_init (JingleSession *session);
static void jingle_session_finalize (GObject *object);
static void jingle_session_get_property (GObject *object, guint prop_id, GValue *value, GParamSpec *pspec);
static void jingle_session_set_property (GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec);

static GObjectClass *parent_class = NULL;

enum {
	PROP_0,
	PROP_SID,
	PROP_JS,
	PROP_REMOTE_JID,
	PROP_LOCAL_JID,
	PROP_IS_INITIATOR,
	PROP_STATE,
	PROP_CONTENTS,
	PROP_PENDING_CONTENTS,
};

GType
jingle_session_get_type()
{
	static GType type = 0;

	if (type == 0) {
		static const GTypeInfo info = {
			sizeof(JingleSessionClass),
			NULL,
			NULL,
			(GClassInitFunc) jingle_session_class_init,
			NULL,
			NULL,
			sizeof(JingleSession),
			0,
			(GInstanceInitFunc) jingle_session_init,
			NULL
		};
		type = g_type_register_static(G_TYPE_OBJECT, "JingleSession", &info, 0);
	}
	return type;
}

static void
jingle_session_class_init (JingleSessionClass *klass)
{
	GObjectClass *gobject_class = (GObjectClass*)klass;
	parent_class = g_type_class_peek_parent(klass);

	gobject_class->finalize = jingle_session_finalize;
	gobject_class->set_property = jingle_session_set_property;
	gobject_class->get_property = jingle_session_get_property;

	g_object_class_install_property(gobject_class, PROP_SID,
			g_param_spec_string("sid",
			"Session ID",
			"The unique session ID of the Jingle Session.",
			NULL,
			G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE));

	g_object_class_install_property(gobject_class, PROP_JS,
			g_param_spec_pointer("js",
			"JabberStream",
			"The Jabber stream associated with this session.",
			G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE));

	g_object_class_install_property(gobject_class, PROP_REMOTE_JID,
			g_param_spec_string("remote-jid",
			"Remote JID",
			"The JID of the remote participant.",
			NULL,
			G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE));

	g_object_class_install_property(gobject_class, PROP_LOCAL_JID,
			g_param_spec_string("local-jid",
			"Local JID",
			"The JID of the local participant.",
			NULL,
			G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE));

	g_object_class_install_property(gobject_class, PROP_IS_INITIATOR,
			g_param_spec_boolean("is-initiator",
			"Is Initiator",
			"Whether or not the local JID is the initiator of the session.",
			FALSE,
			G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE));

	g_object_class_install_property(gobject_class, PROP_STATE,
			g_param_spec_boolean("state",
			"State",
			"The state of the session (PENDING=FALSE, ACTIVE=TRUE).",
			FALSE,
			G_PARAM_READABLE));

	g_object_class_install_property(gobject_class, PROP_CONTENTS,
			g_param_spec_pointer("contents",
			"Contents",
			"The active contents contained within this session",
			G_PARAM_READABLE));

	g_object_class_install_property(gobject_class, PROP_PENDING_CONTENTS,
			g_param_spec_pointer("pending-contents",
			"Pending contents",
			"The pending contents contained within this session",
			G_PARAM_READABLE));

	g_type_class_add_private(klass, sizeof(JingleSessionPrivate));
}

static void
jingle_session_init (JingleSession *session)
{
	session->priv = JINGLE_SESSION_GET_PRIVATE(session);
	memset(session->priv, 0, sizeof(*session->priv));
}

static void
jingle_session_finalize (GObject *session)
{
	JingleSessionPrivate *priv = JINGLE_SESSION_GET_PRIVATE(session);
	purple_debug_info("jingle","jingle_session_finalize\n");

	g_hash_table_remove(priv->js->sessions, priv->sid);

	g_free(priv->sid);
	g_free(priv->remote_jid);
	g_free(priv->local_jid);

	for (; priv->contents; priv->contents =
			g_list_delete_link(priv->contents, priv->contents)) {
		g_object_unref(priv->contents->data);
	}
	for (; priv->pending_contents; priv->pending_contents =
			g_list_delete_link(priv->pending_contents, priv->pending_contents)) {
		g_object_unref(priv->pending_contents->data);
	}

	parent_class->finalize(session);
}

static void
jingle_session_set_property (GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec)
{
	JingleSession *session;

	g_return_if_fail(object != NULL);
	g_return_if_fail(JINGLE_IS_SESSION(object));

	session = JINGLE_SESSION(object);

	switch (prop_id) {
		case PROP_SID:
			g_free(session->priv->sid);
			session->priv->sid = g_value_dup_string(value);
			break;
		case PROP_JS:
			session->priv->js = g_value_get_pointer(value);
			break;
		case PROP_REMOTE_JID:
			g_free(session->priv->remote_jid);
			session->priv->remote_jid = g_value_dup_string(value);
			break;
		case PROP_LOCAL_JID:
			g_free(session->priv->local_jid);
			session->priv->local_jid = g_value_dup_string(value);
			break;
		case PROP_IS_INITIATOR:
			session->priv->is_initiator = g_value_get_boolean(value);
			break;
		case PROP_STATE:
			session->priv->state = g_value_get_boolean(value);
			break;
		case PROP_CONTENTS:
			session->priv->contents = g_value_get_pointer(value);
			break;
		case PROP_PENDING_CONTENTS:
			session->priv->pending_contents = g_value_get_pointer(value);
			break;
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
			break;
	}
}

static void
jingle_session_get_property (GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
	JingleSession *session;

	g_return_if_fail(object != NULL);
	g_return_if_fail(JINGLE_IS_SESSION(object));

	session = JINGLE_SESSION(object);

	switch (prop_id) {
		case PROP_SID:
			g_value_set_string(value, session->priv->sid);
			break;
		case PROP_JS:
			g_value_set_pointer(value, session->priv->js);
			break;
		case PROP_REMOTE_JID:
			g_value_set_string(value, session->priv->remote_jid);
			break;
		case PROP_LOCAL_JID:
			g_value_set_string(value, session->priv->local_jid);
			break;
		case PROP_IS_INITIATOR:
			g_value_set_boolean(value, session->priv->is_initiator);
			break;
		case PROP_STATE:
			g_value_set_boolean(value, session->priv->state);
			break;
		case PROP_CONTENTS:
			g_value_set_pointer(value, session->priv->contents);
			break;
		case PROP_PENDING_CONTENTS:
			g_value_set_pointer(value, session->priv->pending_contents);
			break;
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
			break;
	}
}


JingleSession *
jingle_session_create(JabberStream *js, const gchar *sid,
			const gchar *local_jid, const gchar *remote_jid,
			gboolean is_initiator)
{
	JingleSession *session = g_object_new(jingle_session_get_type(),
			"js", js,
			"sid", sid,
			"local-jid", local_jid,
			"remote-jid", remote_jid,
			"is_initiator", is_initiator,
			NULL);

	/* insert it into the hash table */
	if (!js->sessions) {
		purple_debug_info("jingle",
				"Creating hash table for sessions\n");
		js->sessions = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
	}
	purple_debug_info("jingle",
			"inserting session with key: %s into table\n", sid);
	g_hash_table_insert(js->sessions, g_strdup(sid), session);

	return session;
}

JabberStream *
jingle_session_get_js(JingleSession *session)
{
	JabberStream *js;
	g_object_get(session, "js", &js, NULL);
	return js;
}

gchar *
jingle_session_get_sid(JingleSession *session)
{
	gchar *sid;
	g_object_get(session, "sid", &sid, NULL);
	return sid;
}

gchar *
jingle_session_get_local_jid(JingleSession *session)
{
	gchar *local_jid;
	g_object_get(session, "local-jid", &local_jid, NULL);
	return local_jid;
}

gchar *
jingle_session_get_remote_jid(JingleSession *session)
{
	gchar *remote_jid;
	g_object_get(session, "remote-jid", &remote_jid, NULL);
	return remote_jid;
}

gboolean
jingle_session_is_initiator(JingleSession *session)
{
	gboolean is_initiator;
	g_object_get(session, "is-initiator", &is_initiator, NULL);
	return is_initiator;
}

gboolean
jingle_session_get_state(JingleSession *session)
{
	gboolean state;
	g_object_get(session, "state", &state, NULL);
	return state;
}

GList *
jingle_session_get_contents(JingleSession *session)
{
	GList *contents;
	g_object_get(session, "contents", &contents, NULL);
	return contents;
}

GList *
jingle_session_get_pending_contents(JingleSession *session)
{
	GList *pending_contents;
	g_object_get(session, "pending-contents", &pending_contents, NULL);
	return pending_contents;
}

JingleSession *
jingle_session_find_by_sid(JabberStream *js, const gchar *sid)
{
	JingleSession *session = NULL;

	if (js->sessions)
		session = g_hash_table_lookup(js->sessions, sid);

	purple_debug_info("jingle", "find_by_id %s\n", sid);
	purple_debug_info("jingle", "lookup: %p\n", session);

	return session;
}

static gboolean find_by_jid_ghr(gpointer key,
		gpointer value, gpointer user_data)
{
	JingleSession *session = (JingleSession *)value;
	const gchar *jid = user_data;
	gboolean use_bare = strchr(jid, '/') == NULL;
	gchar *remote_jid = jingle_session_get_remote_jid(session);
	gchar *cmp_jid = use_bare ? jabber_get_bare_jid(remote_jid)
				  : g_strdup(remote_jid);
	g_free(remote_jid);
	if (g_str_equal(jid, cmp_jid)) {
		g_free(cmp_jid);
		return TRUE;
	}
	g_free(cmp_jid);

	return FALSE;
}

JingleSession *
jingle_session_find_by_jid(JabberStream *js, const gchar *jid)
{
	return js->sessions != NULL ?
			g_hash_table_find(js->sessions,
			find_by_jid_ghr, (gpointer)jid) : NULL;
}

static xmlnode *
jingle_add_jingle_packet(JingleSession *session,
			 JabberIq *iq, JingleActionType action)
{
	xmlnode *jingle = iq ?
			xmlnode_new_child(iq->node, "jingle") :
			xmlnode_new("jingle");
	gchar *local_jid = jingle_session_get_local_jid(session);
	gchar *remote_jid = jingle_session_get_remote_jid(session);
	gchar *sid = jingle_session_get_sid(session);

	xmlnode_set_namespace(jingle, JINGLE);
	xmlnode_set_attrib(jingle, "action", jingle_get_action_name(action));

	if (jingle_session_is_initiator(session)) {
		xmlnode_set_attrib(jingle, "initiator", local_jid);
		xmlnode_set_attrib(jingle, "responder", remote_jid);
	} else {
		xmlnode_set_attrib(jingle, "initiator", remote_jid);
		xmlnode_set_attrib(jingle, "responder", local_jid);
	}

	xmlnode_set_attrib(jingle, "sid", sid);

	g_free(local_jid);
	g_free(remote_jid);
	g_free(sid);

	return jingle;
}

JabberIq *
jingle_session_create_ack(JingleSession *session, const xmlnode *jingle)
{
	JabberIq *result = jabber_iq_new(
			jingle_session_get_js(session),
			JABBER_IQ_RESULT);
	xmlnode *packet = xmlnode_get_parent(jingle);
	jabber_iq_set_id(result, xmlnode_get_attrib(packet, "id"));
	xmlnode_set_attrib(result->node, "from", xmlnode_get_attrib(packet, "to"));
	xmlnode_set_attrib(result->node, "to", xmlnode_get_attrib(packet, "from"));
	return result;
}

static JabberIq *
jingle_create_iq(JingleSession *session)
{
	JabberStream *js = jingle_session_get_js(session);
	JabberIq *result = jabber_iq_new(js, JABBER_IQ_SET);
	gchar *from = jingle_session_get_local_jid(session);
	gchar *to = jingle_session_get_remote_jid(session);

	xmlnode_set_attrib(result->node, "from", from);
	xmlnode_set_attrib(result->node, "to", to);

	g_free(from);
	g_free(to);
	return result;
}

xmlnode *
jingle_session_to_xml(JingleSession *session, xmlnode *jingle, JingleActionType action)
{
	if (action != JINGLE_SESSION_INFO && action != JINGLE_SESSION_TERMINATE) {
		GList *iter;
		if (action == JINGLE_CONTENT_ACCEPT
				|| action == JINGLE_CONTENT_ADD
				|| action == JINGLE_CONTENT_REMOVE)
			iter = jingle_session_get_pending_contents(session);
		else
			iter = jingle_session_get_contents(session);

		for (; iter; iter = g_list_next(iter)) {
			jingle_content_to_xml(iter->data, jingle, action);
		}
	}
	return jingle;
}

JabberIq *
jingle_session_to_packet(JingleSession *session, JingleActionType action)
{
	JabberIq *iq = jingle_create_iq(session);
	xmlnode *jingle = jingle_add_jingle_packet(session, iq, action);
	jingle_session_to_xml(session, jingle, action);
	return iq;
}

void jingle_session_handle_action(JingleSession *session, xmlnode *jingle, JingleActionType action)
{
	GList *iter;
	if (action == JINGLE_CONTENT_ADD || action == JINGLE_CONTENT_REMOVE)
		iter = jingle_session_get_pending_contents(session);
	else
		iter = jingle_session_get_contents(session);

	for (; iter; iter = g_list_next(iter)) {
		jingle_content_handle_action(iter->data, jingle, action);
	}
}

JingleContent *
jingle_session_find_content(JingleSession *session, const gchar *name, const gchar *creator)
{
	GList *iter;

	if (name == NULL)
		return NULL;

	iter = session->priv->contents;
	for (; iter; iter = g_list_next(iter)) {
		JingleContent *content = iter->data;
		gchar *cname = jingle_content_get_name(content);
		gboolean result = g_str_equal(name, cname);
		g_free(cname);

		if (creator != NULL) {
			gchar *ccreator = jingle_content_get_creator(content);
			result = (result && !strcmp(creator, ccreator));
			g_free(ccreator);
		}

		if (result == TRUE)
			return content;
	}
	return NULL;
}

JingleContent *
jingle_session_find_pending_content(JingleSession *session, const gchar *name, const gchar *creator)
{
	GList *iter;

	if (name == NULL)
		return NULL;

	iter = session->priv->pending_contents;
	for (; iter; iter = g_list_next(iter)) {
		JingleContent *content = iter->data;
		gchar *cname = jingle_content_get_name(content);
		gboolean result = g_str_equal(name, cname);
		g_free(cname);

		if (creator != NULL) {
			gchar *ccreator = jingle_content_get_creator(content);
			result = (result && !strcmp(creator, ccreator));
			g_free(ccreator);
		}

		if (result == TRUE)
			return content;
	}
	return NULL;
}

void
jingle_session_add_content(JingleSession *session, JingleContent* content)
{
	session->priv->contents =
			g_list_append(session->priv->contents, content);
	jingle_content_set_session(content, session);
}

void
jingle_session_remove_content(JingleSession *session, const gchar *name, const gchar *creator)
{
	JingleContent *content =
			jingle_session_find_content(session, name, creator);

	if (content) {
		session->priv->contents =
				g_list_remove(session->priv->contents, content);
		g_object_unref(content);
	}
}

void
jingle_session_add_pending_content(JingleSession *session, JingleContent* content)
{
	session->priv->pending_contents =
			g_list_append(session->priv->pending_contents, content);
	jingle_content_set_session(content, session);
}

void
jingle_session_remove_pending_content(JingleSession *session, const gchar *name, const gchar *creator)
{
	JingleContent *content = jingle_session_find_pending_content(session, name, creator);

	if (content) {
		session->priv->pending_contents =
				g_list_remove(session->priv->pending_contents, content);
		g_object_unref(content);
	}
}

void
jingle_session_accept_content(JingleSession *session, const gchar *name, const gchar *creator)
{
	JingleContent *content = jingle_session_find_pending_content(session, name, creator);

	if (content) {
		g_object_ref(content);
		jingle_session_remove_pending_content(session, name, creator);
		jingle_session_add_content(session, content);
	}
}

void
jingle_session_accept_session(JingleSession *session)
{
	session->priv->state = TRUE;
}

JabberIq *
jingle_session_terminate_packet(JingleSession *session, const gchar *reason)
{
	JabberIq *iq = jingle_session_to_packet(session,
			JINGLE_SESSION_TERMINATE);
	xmlnode *jingle = xmlnode_get_child(iq->node, "jingle");

	if (reason != NULL) {
		xmlnode *reason_node;
		reason_node = xmlnode_new_child(jingle, "reason");
		xmlnode_new_child(reason_node, reason);
	}
	return iq;
}

JabberIq *
jingle_session_redirect_packet(JingleSession *session, const gchar *sid)
{
	JabberIq *iq = jingle_session_terminate_packet(session,
			"alternative-session");
	xmlnode *alt_session;

	if (sid == NULL)
		return iq;

	alt_session = xmlnode_get_child(iq->node,
			"jingle/reason/alternative-session");

	if (alt_session != NULL) {
		xmlnode *sid_node = xmlnode_new_child(alt_session, "sid");
		xmlnode_insert_data(sid_node, sid, -1);
	}
	return iq;
}

