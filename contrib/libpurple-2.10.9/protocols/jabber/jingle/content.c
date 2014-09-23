/**
 * @file content.c
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

#include "debug.h"
#include "content.h"
#include "jingle.h"

#include <string.h>

struct _JingleContentPrivate
{
	JingleSession *session;
	gchar *description_type;
	gchar *creator;
	gchar *disposition;
	gchar *name;
	gchar *senders;
	JingleTransport *transport;
	JingleTransport *pending_transport;
};

#define JINGLE_CONTENT_GET_PRIVATE(obj) (G_TYPE_INSTANCE_GET_PRIVATE((obj), JINGLE_TYPE_CONTENT, JingleContentPrivate))

static void jingle_content_class_init (JingleContentClass *klass);
static void jingle_content_init (JingleContent *content);
static void jingle_content_finalize (GObject *object);
static void jingle_content_get_property (GObject *object, guint prop_id, GValue *value, GParamSpec *pspec);
static void jingle_content_set_property (GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec);
static xmlnode *jingle_content_to_xml_internal(JingleContent *content, xmlnode *jingle, JingleActionType action);
static JingleContent *jingle_content_parse_internal(xmlnode *content);

static GObjectClass *parent_class = NULL;

enum {
	PROP_0,
	PROP_SESSION,
	PROP_CREATOR,
	PROP_DISPOSITION,
	PROP_NAME,
	PROP_SENDERS,
	PROP_TRANSPORT,
	PROP_PENDING_TRANSPORT,
};

GType
jingle_content_get_type()
{
	static GType type = 0;

	if (type == 0) {
		static const GTypeInfo info = {
			sizeof(JingleContentClass),
			NULL,
			NULL,
			(GClassInitFunc) jingle_content_class_init,
			NULL,
			NULL,
			sizeof(JingleContent),
			0,
			(GInstanceInitFunc) jingle_content_init,
			NULL
		};
		type = g_type_register_static(G_TYPE_OBJECT, "JingleContent", &info, 0);
	}
	return type;
}

static void
jingle_content_class_init (JingleContentClass *klass)
{
	GObjectClass *gobject_class = (GObjectClass*)klass;
	parent_class = g_type_class_peek_parent(klass);

	gobject_class->finalize = jingle_content_finalize;
	gobject_class->set_property = jingle_content_set_property;
	gobject_class->get_property = jingle_content_get_property;
	klass->to_xml = jingle_content_to_xml_internal;
	klass->parse = jingle_content_parse_internal;

	g_object_class_install_property(gobject_class, PROP_SESSION,
			g_param_spec_object("session",
			"Jingle Session",
			"The jingle session parent of this content.",
			JINGLE_TYPE_SESSION,
			G_PARAM_READWRITE));

	g_object_class_install_property(gobject_class, PROP_CREATOR,
			g_param_spec_string("creator",
			"Creator",
			"The participant that created this content.",
			NULL,
			G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE));

	g_object_class_install_property(gobject_class, PROP_DISPOSITION,
			g_param_spec_string("disposition",
			"Disposition",
			"The disposition of the content.",
			NULL,
			G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE));

	g_object_class_install_property(gobject_class, PROP_NAME,
			g_param_spec_string("name",
			"Name",
			"The name of this content.",
			NULL,
			G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE));

	g_object_class_install_property(gobject_class, PROP_SENDERS,
			g_param_spec_string("senders",
			"Senders",
			"The sender of this content.",
			NULL,
			G_PARAM_CONSTRUCT | G_PARAM_READWRITE));

	g_object_class_install_property(gobject_class, PROP_TRANSPORT,
			g_param_spec_object("transport",
			"transport",
			"The transport of this content.",
			JINGLE_TYPE_TRANSPORT,
			G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE));

	g_object_class_install_property(gobject_class, PROP_PENDING_TRANSPORT,
			g_param_spec_object("pending-transport",
			"Pending transport",
			"The pending transport contained within this content",
			JINGLE_TYPE_TRANSPORT,
			G_PARAM_READWRITE));

	g_type_class_add_private(klass, sizeof(JingleContentPrivate));
}

static void
jingle_content_init (JingleContent *content)
{
	content->priv = JINGLE_CONTENT_GET_PRIVATE(content);
	memset(content->priv, 0, sizeof(*content->priv));
}

static void
jingle_content_finalize (GObject *content)
{
	JingleContentPrivate *priv = JINGLE_CONTENT_GET_PRIVATE(content);
	purple_debug_info("jingle","jingle_content_finalize\n");

	g_free(priv->description_type);
	g_free(priv->creator);
	g_free(priv->disposition);
	g_free(priv->name);
	g_free(priv->senders);
	g_object_unref(priv->transport);
	if (priv->pending_transport)
		g_object_unref(priv->pending_transport);

	parent_class->finalize(content);
}

static void
jingle_content_set_property (GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec)
{
	JingleContent *content;

	g_return_if_fail(object != NULL);
	g_return_if_fail(JINGLE_IS_CONTENT(object));

	content = JINGLE_CONTENT(object);

	switch (prop_id) {
		case PROP_SESSION:
			content->priv->session = g_value_get_object(value);
			break;
		case PROP_CREATOR:
			g_free(content->priv->creator);
			content->priv->creator = g_value_dup_string(value);
			break;
		case PROP_DISPOSITION:
			g_free(content->priv->disposition);
			content->priv->disposition = g_value_dup_string(value);
			break;
		case PROP_NAME:
			g_free(content->priv->name);
			content->priv->name = g_value_dup_string(value);
			break;
		case PROP_SENDERS:
			g_free(content->priv->senders);
			content->priv->senders = g_value_dup_string(value);
			break;
		case PROP_TRANSPORT:
			if (content->priv->transport)
				g_object_unref(content->priv->transport);
			content->priv->transport = g_value_get_object(value);
			break;
		case PROP_PENDING_TRANSPORT:
			if (content->priv->pending_transport)
				g_object_unref(content->priv->pending_transport);
			content->priv->pending_transport = g_value_get_object(value);
			break;
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
			break;
	}
}

static void
jingle_content_get_property (GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
	JingleContent *content;

	g_return_if_fail(object != NULL);
	g_return_if_fail(JINGLE_IS_CONTENT(object));

	content = JINGLE_CONTENT(object);

	switch (prop_id) {
		case PROP_SESSION:
			g_value_set_object(value, content->priv->session);
			break;
		case PROP_CREATOR:
			g_value_set_string(value, content->priv->creator);
			break;
		case PROP_DISPOSITION:
			g_value_set_string(value, content->priv->disposition);
			break;
		case PROP_NAME:
			g_value_set_string(value, content->priv->name);
			break;
		case PROP_SENDERS:
			g_value_set_string(value, content->priv->senders);
			break;
		case PROP_TRANSPORT:
			g_value_set_object(value, content->priv->transport);
			break;
		case PROP_PENDING_TRANSPORT:
			g_value_set_object(value, content->priv->pending_transport);
			break;
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
			break;
	}
}

JingleContent *
jingle_content_create(const gchar *type, const gchar *creator,
		const gchar *disposition, const gchar *name,
		const gchar *senders, JingleTransport *transport)
{


	JingleContent *content = g_object_new(jingle_get_type(type),
			"creator", creator,
			"disposition", disposition != NULL ? disposition : "session",
			"name", name,
			"senders", senders != NULL ? senders : "both",
			"transport", transport,
			NULL);
	return content;
}

JingleSession *jingle_content_get_session(JingleContent *content)
{
	JingleSession *session;
	g_object_get(content, "session", &session, NULL);
	return session;
}

const gchar *
jingle_content_get_description_type(JingleContent *content)
{
	return JINGLE_CONTENT_GET_CLASS(content)->description_type;
}

gchar *
jingle_content_get_creator(JingleContent *content)
{
	gchar *creator;
	g_object_get(content, "creator", &creator, NULL);
	return creator;
}

gchar *
jingle_content_get_disposition(JingleContent *content)
{
	gchar *disposition;
	g_object_get(content, "disposition", &disposition, NULL);
	return disposition;
}

gchar *
jingle_content_get_name(JingleContent *content)
{
	gchar *name;
	g_object_get(content, "name", &name, NULL);
	return name;
}

gchar *
jingle_content_get_senders(JingleContent *content)
{
	gchar *senders;
	g_object_get(content, "senders", &senders, NULL);
	return senders;
}

JingleTransport *
jingle_content_get_transport(JingleContent *content)
{
	JingleTransport *transport;
	g_object_get(content, "transport", &transport, NULL);
	return transport;
}

void
jingle_content_set_session(JingleContent *content, JingleSession *session)
{
	g_return_if_fail(JINGLE_IS_CONTENT(content));
	g_return_if_fail(JINGLE_IS_SESSION(session));
	g_object_set(content, "session", session, NULL);
}

JingleTransport *
jingle_content_get_pending_transport(JingleContent *content)
{
	JingleTransport *pending_transport;
	g_object_get(content, "pending_transport", &pending_transport, NULL);
	return pending_transport;
}

void
jingle_content_set_pending_transport(JingleContent *content, JingleTransport *transport)
{
	g_object_set(content, "pending-transport", transport, NULL);
}

void
jingle_content_accept_transport(JingleContent *content)
{
	if (content->priv->transport)
		g_object_unref(content->priv->transport);
	content->priv->transport = content->priv->pending_transport;
	content->priv->pending_transport = NULL;
}

void
jingle_content_remove_pending_transport(JingleContent *content)
{
	if (content->priv->pending_transport) {
		g_object_unref(content->priv->pending_transport);
		content->priv->pending_transport = NULL;
	}
}

void
jingle_content_modify(JingleContent *content, const gchar *senders)
{
	g_object_set(content, "senders", senders, NULL);
}

static JingleContent *
jingle_content_parse_internal(xmlnode *content)
{
	xmlnode *description = xmlnode_get_child(content, "description");
	const gchar *type = xmlnode_get_namespace(description);
	const gchar *creator = xmlnode_get_attrib(content, "creator");
	const gchar *disposition = xmlnode_get_attrib(content, "disposition");
	const gchar *senders = xmlnode_get_attrib(content, "senders");
	const gchar *name = xmlnode_get_attrib(content, "name");
	JingleTransport *transport =
			jingle_transport_parse(xmlnode_get_child(content, "transport"));
	if (transport == NULL)
		return NULL;

	if (senders == NULL)
		senders = "both";

	return jingle_content_create(type, creator, disposition, name, senders, transport);
}

JingleContent *
jingle_content_parse(xmlnode *content)
{
	const gchar *type = xmlnode_get_namespace(xmlnode_get_child(content, "description"));
	GType jingle_type = jingle_get_type(type);

	if (jingle_type != G_TYPE_NONE) {
		return JINGLE_CONTENT_CLASS(g_type_class_ref(jingle_type))->parse(content);
	} else {
		return NULL;
	}
}

static xmlnode *
jingle_content_to_xml_internal(JingleContent *content, xmlnode *jingle, JingleActionType action)
{
	xmlnode *node = xmlnode_new_child(jingle, "content");
	gchar *creator = jingle_content_get_creator(content);
	gchar *name = jingle_content_get_name(content);
	gchar *senders = jingle_content_get_senders(content);
	gchar *disposition = jingle_content_get_disposition(content);

	xmlnode_set_attrib(node, "creator", creator);
	xmlnode_set_attrib(node, "name", name);
	xmlnode_set_attrib(node, "senders", senders);
	if (strcmp("session", disposition))
		xmlnode_set_attrib(node, "disposition", disposition);

	g_free(disposition);
	g_free(senders);
	g_free(name);
	g_free(creator);

	if (action != JINGLE_CONTENT_REMOVE) {
		JingleTransport *transport;

		if (action != JINGLE_TRANSPORT_ACCEPT &&
				action != JINGLE_TRANSPORT_INFO &&
				action != JINGLE_TRANSPORT_REJECT &&
				action != JINGLE_TRANSPORT_REPLACE) {
			xmlnode *description = xmlnode_new_child(node, "description");

			xmlnode_set_namespace(description,
					jingle_content_get_description_type(content));
		}

		if (action != JINGLE_TRANSPORT_REJECT && action == JINGLE_TRANSPORT_REPLACE)
			transport = jingle_content_get_pending_transport(content);
		else
			transport = jingle_content_get_transport(content);

		jingle_transport_to_xml(transport, node, action);
		g_object_unref(transport);
	}

	return node;
}

xmlnode *
jingle_content_to_xml(JingleContent *content, xmlnode *jingle, JingleActionType action)
{
	g_return_val_if_fail(content != NULL, NULL);
	g_return_val_if_fail(JINGLE_IS_CONTENT(content), NULL);
	return JINGLE_CONTENT_GET_CLASS(content)->to_xml(content, jingle, action);
}

void
jingle_content_handle_action(JingleContent *content, xmlnode *xmlcontent, JingleActionType action)
{
	g_return_if_fail(content != NULL);
	g_return_if_fail(JINGLE_IS_CONTENT(content));
	JINGLE_CONTENT_GET_CLASS(content)->handle_action(content, xmlcontent, action);
}

