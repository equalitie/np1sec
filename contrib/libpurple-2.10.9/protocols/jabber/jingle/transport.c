/**
 * @file transport.c
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

#include "transport.h"
#include "jingle.h"
#include "debug.h"

#include <string.h>

struct _JingleTransportPrivate
{
	void *dummy;
};

#define JINGLE_TRANSPORT_GET_PRIVATE(obj) (G_TYPE_INSTANCE_GET_PRIVATE((obj), JINGLE_TYPE_TRANSPORT, JingleTransportPrivate))

static void jingle_transport_class_init (JingleTransportClass *klass);
static void jingle_transport_init (JingleTransport *transport);
static void jingle_transport_finalize (GObject *object);
static void jingle_transport_get_property (GObject *object, guint prop_id, GValue *value, GParamSpec *pspec);
static void jingle_transport_set_property (GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec);
JingleTransport *jingle_transport_parse_internal(xmlnode *transport);
xmlnode *jingle_transport_to_xml_internal(JingleTransport *transport, xmlnode *content, JingleActionType action);

static GObjectClass *parent_class = NULL;

enum {
	PROP_0,
};

GType
jingle_transport_get_type()
{
	static GType type = 0;

	if (type == 0) {
		static const GTypeInfo info = {
			sizeof(JingleTransportClass),
			NULL,
			NULL,
			(GClassInitFunc) jingle_transport_class_init,
			NULL,
			NULL,
			sizeof(JingleTransport),
			0,
			(GInstanceInitFunc) jingle_transport_init,
			NULL
		};
		type = g_type_register_static(G_TYPE_OBJECT, "JingleTransport", &info, 0);
	}
	return type;
}

static void
jingle_transport_class_init (JingleTransportClass *klass)
{
	GObjectClass *gobject_class = (GObjectClass*)klass;
	parent_class = g_type_class_peek_parent(klass);

	gobject_class->finalize = jingle_transport_finalize;
	gobject_class->set_property = jingle_transport_set_property;
	gobject_class->get_property = jingle_transport_get_property;
	klass->to_xml = jingle_transport_to_xml_internal;
	klass->parse = jingle_transport_parse_internal;

	g_type_class_add_private(klass, sizeof(JingleTransportPrivate));
}

static void
jingle_transport_init (JingleTransport *transport)
{
	transport->priv = JINGLE_TRANSPORT_GET_PRIVATE(transport);
	transport->priv->dummy = NULL;
}

static void
jingle_transport_finalize (GObject *transport)
{
	/* JingleTransportPrivate *priv = JINGLE_TRANSPORT_GET_PRIVATE(transport); */
	purple_debug_info("jingle","jingle_transport_finalize\n");

	parent_class->finalize(transport);
}

static void
jingle_transport_set_property (GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec)
{
	g_return_if_fail(object != NULL);
	g_return_if_fail(JINGLE_IS_TRANSPORT(object));

	switch (prop_id) {
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
			break;
	}
}

static void
jingle_transport_get_property (GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
	g_return_if_fail(object != NULL);
	g_return_if_fail(JINGLE_IS_TRANSPORT(object));

	switch (prop_id) {
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
			break;
	}
}

JingleTransport *
jingle_transport_create(const gchar *type)
{
	return g_object_new(jingle_get_type(type), NULL);
}

const gchar *
jingle_transport_get_transport_type(JingleTransport *transport)
{
	return JINGLE_TRANSPORT_GET_CLASS(transport)->transport_type;
}

JingleTransport *
jingle_transport_parse_internal(xmlnode *transport)
{
	const gchar *type = xmlnode_get_namespace(transport);
	return jingle_transport_create(type);
}

xmlnode *
jingle_transport_to_xml_internal(JingleTransport *transport, xmlnode *content, JingleActionType action)
{
	xmlnode *node = xmlnode_new_child(content, "transport");
	xmlnode_set_namespace(node, jingle_transport_get_transport_type(transport));
	return node;
}

JingleTransport *
jingle_transport_parse(xmlnode *transport)
{
	const gchar *type_name = xmlnode_get_namespace(transport);
	GType type = jingle_get_type(type_name);
	if (type == G_TYPE_NONE)
		return NULL;
	
	return JINGLE_TRANSPORT_CLASS(g_type_class_ref(type))->parse(transport);
}

xmlnode *
jingle_transport_to_xml(JingleTransport *transport, xmlnode *content, JingleActionType action)
{
	g_return_val_if_fail(transport != NULL, NULL);
	g_return_val_if_fail(JINGLE_IS_TRANSPORT(transport), NULL);
	return JINGLE_TRANSPORT_GET_CLASS(transport)->to_xml(transport, content, action);
}

