/**
 * @file rawudp.c
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

#include "rawudp.h"
#include "jingle.h"
#include "debug.h"

#include <string.h>

struct _JingleRawUdpPrivate
{
	GList *local_candidates;
	GList *remote_candidates;
};

#define JINGLE_RAWUDP_GET_PRIVATE(obj) (G_TYPE_INSTANCE_GET_PRIVATE((obj), JINGLE_TYPE_RAWUDP, JingleRawUdpPrivate))

static void jingle_rawudp_class_init (JingleRawUdpClass *klass);
static void jingle_rawudp_init (JingleRawUdp *rawudp);
static void jingle_rawudp_finalize (GObject *object);
static void jingle_rawudp_get_property (GObject *object, guint prop_id, GValue *value, GParamSpec *pspec);
static void jingle_rawudp_set_property (GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec);
static JingleTransport *jingle_rawudp_parse_internal(xmlnode *rawudp);
static xmlnode *jingle_rawudp_to_xml_internal(JingleTransport *transport, xmlnode *content, JingleActionType action);

static JingleTransportClass *parent_class = NULL;

enum {
	PROP_0,
	PROP_LOCAL_CANDIDATES,
	PROP_REMOTE_CANDIDATES,
};

static JingleRawUdpCandidate *
jingle_rawudp_candidate_copy(JingleRawUdpCandidate *candidate)
{
	JingleRawUdpCandidate *new_candidate = g_new0(JingleRawUdpCandidate, 1);
	new_candidate->generation = candidate->generation;
	new_candidate->component = candidate->component;
	new_candidate->id = g_strdup(candidate->id);
	new_candidate->ip = g_strdup(candidate->ip);
	new_candidate->port = candidate->port;

	new_candidate->rem_known = candidate->rem_known;
	return new_candidate;
}

static void
jingle_rawudp_candidate_free(JingleRawUdpCandidate *candidate)
{
	g_free(candidate->id);
	g_free(candidate->ip);
}

GType
jingle_rawudp_candidate_get_type()
{
	static GType type = 0;

	if (type == 0) {
		type = g_boxed_type_register_static("JingleRawUdpCandidate",
				(GBoxedCopyFunc)jingle_rawudp_candidate_copy,
				(GBoxedFreeFunc)jingle_rawudp_candidate_free);
	}
	return type;
}

JingleRawUdpCandidate *
jingle_rawudp_candidate_new(const gchar *id, guint generation, guint component, const gchar *ip, guint port)
{
	JingleRawUdpCandidate *candidate = g_new0(JingleRawUdpCandidate, 1);
	candidate->generation = generation;
	candidate->component = component;
	candidate->id = g_strdup(id);
	candidate->ip = g_strdup(ip);
	candidate->port = port;

	candidate->rem_known = FALSE;
	return candidate;
}

GType
jingle_rawudp_get_type()
{
	static GType type = 0;

	if (type == 0) {
		static const GTypeInfo info = {
			sizeof(JingleRawUdpClass),
			NULL,
			NULL,
			(GClassInitFunc) jingle_rawudp_class_init,
			NULL,
			NULL,
			sizeof(JingleRawUdp),
			0,
			(GInstanceInitFunc) jingle_rawudp_init,
			NULL
		};
		type = g_type_register_static(JINGLE_TYPE_TRANSPORT, "JingleRawUdp", &info, 0);
	}
	return type;
}

static void
jingle_rawudp_class_init (JingleRawUdpClass *klass)
{
	GObjectClass *gobject_class = (GObjectClass*)klass;
	parent_class = g_type_class_peek_parent(klass);

	gobject_class->finalize = jingle_rawudp_finalize;
	gobject_class->set_property = jingle_rawudp_set_property;
	gobject_class->get_property = jingle_rawudp_get_property;
	klass->parent_class.to_xml = jingle_rawudp_to_xml_internal;
	klass->parent_class.parse = jingle_rawudp_parse_internal;
	klass->parent_class.transport_type = JINGLE_TRANSPORT_RAWUDP;

	g_object_class_install_property(gobject_class, PROP_LOCAL_CANDIDATES,
			g_param_spec_pointer("local-candidates",
			"Local candidates",
			"The local candidates for this transport.",
			G_PARAM_READABLE));

	g_object_class_install_property(gobject_class, PROP_REMOTE_CANDIDATES,
			g_param_spec_pointer("remote-candidates",
			"Remote candidates",
			"The remote candidates for this transport.",
			G_PARAM_READABLE));

	g_type_class_add_private(klass, sizeof(JingleRawUdpPrivate));
}

static void
jingle_rawudp_init (JingleRawUdp *rawudp)
{
	rawudp->priv = JINGLE_RAWUDP_GET_PRIVATE(rawudp);
	rawudp->priv->local_candidates = NULL;
	rawudp->priv->remote_candidates = NULL;
}

static void
jingle_rawudp_finalize (GObject *rawudp)
{
/*	JingleRawUdpPrivate *priv = JINGLE_RAWUDP_GET_PRIVATE(rawudp); */
	purple_debug_info("jingle","jingle_rawudp_finalize\n");

	G_OBJECT_CLASS(parent_class)->finalize(rawudp);
}

static void
jingle_rawudp_set_property (GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec)
{
	JingleRawUdp *rawudp;

	g_return_if_fail(object != NULL);
	g_return_if_fail(JINGLE_IS_RAWUDP(object));

	rawudp = JINGLE_RAWUDP(object);

	switch (prop_id) {
		case PROP_LOCAL_CANDIDATES:
			rawudp->priv->local_candidates =
					g_value_get_pointer(value);
			break;
		case PROP_REMOTE_CANDIDATES:
			rawudp->priv->remote_candidates =
					g_value_get_pointer(value);
			break;
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
			break;
	}
}

static void
jingle_rawudp_get_property (GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
	JingleRawUdp *rawudp;

	g_return_if_fail(object != NULL);
	g_return_if_fail(JINGLE_IS_RAWUDP(object));

	rawudp = JINGLE_RAWUDP(object);

	switch (prop_id) {
		case PROP_LOCAL_CANDIDATES:
			g_value_set_pointer(value, rawudp->priv->local_candidates);
			break;
		case PROP_REMOTE_CANDIDATES:
			g_value_set_pointer(value, rawudp->priv->remote_candidates);
			break;
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
			break;
	}
}

void
jingle_rawudp_add_local_candidate(JingleRawUdp *rawudp, JingleRawUdpCandidate *candidate)
{
	GList *iter = rawudp->priv->local_candidates;

	for (; iter; iter = g_list_next(iter)) {
		JingleRawUdpCandidate *c = iter->data;
		if (!strcmp(c->id, candidate->id)) {
			guint generation = c->generation + 1;

			g_boxed_free(JINGLE_TYPE_RAWUDP_CANDIDATE, c);
			rawudp->priv->local_candidates = g_list_delete_link(
					rawudp->priv->local_candidates, iter);

			candidate->generation = generation;

			rawudp->priv->local_candidates = g_list_append(
					rawudp->priv->local_candidates, candidate);
			return;
		}
	}

	rawudp->priv->local_candidates = g_list_append(
			rawudp->priv->local_candidates, candidate);
}

GList *
jingle_rawudp_get_remote_candidates(JingleRawUdp *rawudp)
{
	return g_list_copy(rawudp->priv->remote_candidates);
}

static JingleRawUdpCandidate *
jingle_rawudp_get_remote_candidate_by_id(JingleRawUdp *rawudp, gchar *id)
{
	GList *iter = rawudp->priv->remote_candidates;
	for (; iter; iter = g_list_next(iter)) {
		JingleRawUdpCandidate *candidate = iter->data;
		if (!strcmp(candidate->id, id)) {
			return candidate;
		}
	}
	return NULL;
}

static void
jingle_rawudp_add_remote_candidate(JingleRawUdp *rawudp, JingleRawUdpCandidate *candidate)
{
	JingleRawUdpPrivate *priv = JINGLE_RAWUDP_GET_PRIVATE(rawudp);
	JingleRawUdpCandidate *rawudp_candidate =
			jingle_rawudp_get_remote_candidate_by_id(rawudp, candidate->id);
	if (rawudp_candidate != NULL) {
		priv->remote_candidates = g_list_remove(
				priv->remote_candidates, rawudp_candidate);
		g_boxed_free(JINGLE_TYPE_RAWUDP_CANDIDATE, rawudp_candidate);
	}
	priv->remote_candidates = g_list_append(priv->remote_candidates, candidate);
}

static JingleTransport *
jingle_rawudp_parse_internal(xmlnode *rawudp)
{
	JingleTransport *transport = parent_class->parse(rawudp);
	JingleRawUdpPrivate *priv = JINGLE_RAWUDP_GET_PRIVATE(transport);
	xmlnode *candidate = xmlnode_get_child(rawudp, "candidate");
	JingleRawUdpCandidate *rawudp_candidate = NULL;

	for (; candidate; candidate = xmlnode_get_next_twin(candidate)) {
		const gchar *id = xmlnode_get_attrib(candidate, "id");
		const gchar *generation = xmlnode_get_attrib(candidate, "generation");
		const gchar *component = xmlnode_get_attrib(candidate, "component");
		const gchar *ip = xmlnode_get_attrib(candidate, "ip");
		const gchar *port = xmlnode_get_attrib(candidate, "port");

		if (!id || !generation || !component || !ip || !port)
			continue;

		rawudp_candidate = jingle_rawudp_candidate_new(
				id,
				atoi(generation),
				atoi(component),
				ip,
				atoi(port));
		rawudp_candidate->rem_known = TRUE;
		jingle_rawudp_add_remote_candidate(JINGLE_RAWUDP(transport), rawudp_candidate);
	}

	if (rawudp_candidate != NULL &&
			g_list_length(priv->remote_candidates) == 1) {
		/* manufacture rtcp candidate */
		rawudp_candidate = g_boxed_copy(JINGLE_TYPE_RAWUDP_CANDIDATE, rawudp_candidate);
		rawudp_candidate->component = 2;
		rawudp_candidate->port = rawudp_candidate->port + 1;
		rawudp_candidate->rem_known = TRUE;
		jingle_rawudp_add_remote_candidate(JINGLE_RAWUDP(transport), rawudp_candidate);
	}

	return transport;
}

static xmlnode *
jingle_rawudp_to_xml_internal(JingleTransport *transport, xmlnode *content, JingleActionType action)
{
	xmlnode *node = parent_class->to_xml(transport, content, action);

	if (action == JINGLE_SESSION_INITIATE ||
			action == JINGLE_TRANSPORT_INFO ||
			action == JINGLE_SESSION_ACCEPT) {
		JingleRawUdpPrivate *priv = JINGLE_RAWUDP_GET_PRIVATE(transport);
		GList *iter = priv->local_candidates;

		for (; iter; iter = g_list_next(iter)) {
			JingleRawUdpCandidate *candidate = iter->data;
			xmlnode *xmltransport;
			gchar *generation, *component, *port;

			if (candidate->rem_known == TRUE)
				continue;
			candidate->rem_known = TRUE;

			xmltransport = xmlnode_new_child(node, "candidate");
			generation = g_strdup_printf("%d", candidate->generation);
			component = g_strdup_printf("%d", candidate->component);
			port = g_strdup_printf("%d", candidate->port);

			xmlnode_set_attrib(xmltransport, "generation", generation);
			xmlnode_set_attrib(xmltransport, "component", component);
			xmlnode_set_attrib(xmltransport, "id", candidate->id);
			xmlnode_set_attrib(xmltransport, "ip", candidate->ip);
			xmlnode_set_attrib(xmltransport, "port", port);

			g_free(port);
			g_free(generation);
		}
	}

	return node;
}

