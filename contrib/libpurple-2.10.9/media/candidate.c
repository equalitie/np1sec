/**
 * @file candidate.c Candidate for Media API
 * @ingroup core
 */

/* purple
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

#include "candidate.h"

/** @copydoc _PurpleMediaCandidateClass */
typedef struct _PurpleMediaCandidateClass PurpleMediaCandidateClass;
/** @copydoc _PurpleMediaCandidatePrivate */
typedef struct _PurpleMediaCandidatePrivate PurpleMediaCandidatePrivate;

#define PURPLE_MEDIA_CANDIDATE_GET_PRIVATE(obj) \
		(G_TYPE_INSTANCE_GET_PRIVATE((obj), \
		PURPLE_TYPE_MEDIA_CANDIDATE, \
		PurpleMediaCandidatePrivate))


struct _PurpleMediaCandidateClass
{
	GObjectClass parent_class;
};

struct _PurpleMediaCandidate
{
	GObject parent;
};

G_DEFINE_TYPE(PurpleMediaCandidate, purple_media_candidate, G_TYPE_OBJECT);

struct _PurpleMediaCandidatePrivate
{
	gchar *foundation;
	guint component_id;
	gchar *ip;
	guint16 port;
	gchar *base_ip;
	guint16 base_port;
	PurpleMediaNetworkProtocol proto;
	guint32 priority;
	PurpleMediaCandidateType type;
	gchar *username;
	gchar *password;
	guint ttl;
};

enum {
	PROP_CANDIDATE_0,
	PROP_FOUNDATION,
	PROP_COMPONENT_ID,
	PROP_IP,
	PROP_PORT,
	PROP_BASE_IP,
	PROP_BASE_PORT,
	PROP_PROTOCOL,
	PROP_PRIORITY,
	PROP_TYPE,
	PROP_USERNAME,
	PROP_PASSWORD,
	PROP_TTL,
};

static void
purple_media_candidate_init(PurpleMediaCandidate *info)
{
	PurpleMediaCandidatePrivate *priv =
			PURPLE_MEDIA_CANDIDATE_GET_PRIVATE(info);
	priv->foundation = NULL;
	priv->component_id = 0;
	priv->ip = NULL;
	priv->port = 0;
	priv->base_ip = NULL;
	priv->proto = PURPLE_MEDIA_NETWORK_PROTOCOL_UDP;
	priv->priority = 0;
	priv->type = PURPLE_MEDIA_CANDIDATE_TYPE_HOST;
	priv->username = NULL;
	priv->password = NULL;
	priv->ttl = 0;
}

static void
purple_media_candidate_finalize(GObject *info)
{
	PurpleMediaCandidatePrivate *priv =
			PURPLE_MEDIA_CANDIDATE_GET_PRIVATE(info);

	g_free(priv->foundation);
	g_free(priv->ip);
	g_free(priv->base_ip);
	g_free(priv->username);
	g_free(priv->password);
}

static void
purple_media_candidate_set_property (GObject *object, guint prop_id,
		const GValue *value, GParamSpec *pspec)
{
	PurpleMediaCandidatePrivate *priv;
	g_return_if_fail(PURPLE_IS_MEDIA_CANDIDATE(object));

	priv = PURPLE_MEDIA_CANDIDATE_GET_PRIVATE(object);

	switch (prop_id) {
		case PROP_FOUNDATION:
			g_free(priv->foundation);
			priv->foundation = g_value_dup_string(value);
			break;
		case PROP_COMPONENT_ID:
			priv->component_id = g_value_get_uint(value);
			break;
		case PROP_IP:
			g_free(priv->ip);
			priv->ip = g_value_dup_string(value);
			break;
		case PROP_PORT:
			priv->port = g_value_get_uint(value);
			break;
		case PROP_BASE_IP:
			g_free(priv->base_ip);
			priv->base_ip = g_value_dup_string(value);
			break;
		case PROP_BASE_PORT:
			priv->base_port = g_value_get_uint(value);
			break;
		case PROP_PROTOCOL:
			priv->proto = g_value_get_enum(value);
			break;
		case PROP_PRIORITY:
			priv->priority = g_value_get_uint(value);
			break;
		case PROP_TYPE:
			priv->type = g_value_get_enum(value);
			break;
		case PROP_USERNAME:
			g_free(priv->username);
			priv->username = g_value_dup_string(value);
			break;
		case PROP_PASSWORD:
			g_free(priv->password);
			priv->password = g_value_dup_string(value);
			break;
		case PROP_TTL:
			priv->ttl = g_value_get_uint(value);
			break;
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID(
					object, prop_id, pspec);
			break;
	}
}

static void
purple_media_candidate_get_property (GObject *object, guint prop_id,
		GValue *value, GParamSpec *pspec)
{
	PurpleMediaCandidatePrivate *priv;
	g_return_if_fail(PURPLE_IS_MEDIA_CANDIDATE(object));

	priv = PURPLE_MEDIA_CANDIDATE_GET_PRIVATE(object);

	switch (prop_id) {
		case PROP_FOUNDATION:
			g_value_set_string(value, priv->foundation);
			break;
		case PROP_COMPONENT_ID:
			g_value_set_uint(value, priv->component_id);
			break;
		case PROP_IP:
			g_value_set_string(value, priv->ip);
			break;
		case PROP_PORT:
			g_value_set_uint(value, priv->port);
			break;
		case PROP_BASE_IP:
			g_value_set_string(value, priv->base_ip);
			break;
		case PROP_BASE_PORT:
			g_value_set_uint(value, priv->base_port);
			break;
		case PROP_PROTOCOL:
			g_value_set_enum(value, priv->proto);
			break;
		case PROP_PRIORITY:
			g_value_set_uint(value, priv->priority);
			break;
		case PROP_TYPE:
			g_value_set_enum(value, priv->type);
			break;
		case PROP_USERNAME:
			g_value_set_string(value, priv->username);
			break;
		case PROP_PASSWORD:
			g_value_set_string(value, priv->password);
			break;
		case PROP_TTL:
			g_value_set_uint(value, priv->ttl);
			break;
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID(
					object, prop_id, pspec);
			break;
	}
}

static void
purple_media_candidate_class_init(PurpleMediaCandidateClass *klass)
{
	GObjectClass *gobject_class = (GObjectClass*)klass;

	gobject_class->finalize = purple_media_candidate_finalize;
	gobject_class->set_property = purple_media_candidate_set_property;
	gobject_class->get_property = purple_media_candidate_get_property;

	g_object_class_install_property(gobject_class, PROP_FOUNDATION,
			g_param_spec_string("foundation",
			"Foundation",
			"The foundation of the candidate.",
			NULL,
			G_PARAM_READWRITE));

	g_object_class_install_property(gobject_class, PROP_COMPONENT_ID,
			g_param_spec_uint("component-id",
			"Component ID",
			"The component id of the candidate.",
			0, G_MAXUINT, 0,
			G_PARAM_READWRITE));

	g_object_class_install_property(gobject_class, PROP_IP,
			g_param_spec_string("ip",
			"IP Address",
			"The IP address of the candidate.",
			NULL,
			G_PARAM_READWRITE));

	g_object_class_install_property(gobject_class, PROP_PORT,
			g_param_spec_uint("port",
			"Port",
			"The port of the candidate.",
			0, G_MAXUINT16, 0,
			G_PARAM_READWRITE));

	g_object_class_install_property(gobject_class, PROP_BASE_IP,
			g_param_spec_string("base-ip",
			"Base IP",
			"The internal IP address of the candidate.",
			NULL,
			G_PARAM_READWRITE));

	g_object_class_install_property(gobject_class, PROP_BASE_PORT,
			g_param_spec_uint("base-port",
			"Base Port",
			"The internal port of the candidate.",
			0, G_MAXUINT16, 0,
			G_PARAM_READWRITE));

	g_object_class_install_property(gobject_class, PROP_PROTOCOL,
			g_param_spec_enum("protocol",
			"Protocol",
			"The protocol of the candidate.",
			PURPLE_TYPE_MEDIA_NETWORK_PROTOCOL,
			PURPLE_MEDIA_NETWORK_PROTOCOL_UDP,
			G_PARAM_READWRITE));

	g_object_class_install_property(gobject_class, PROP_PRIORITY,
			g_param_spec_uint("priority",
			"Priority",
			"The priority of the candidate.",
			0, G_MAXUINT32, 0,
			G_PARAM_READWRITE));

	g_object_class_install_property(gobject_class, PROP_TYPE,
			g_param_spec_enum("type",
			"Type",
			"The type of the candidate.",
			PURPLE_TYPE_MEDIA_CANDIDATE_TYPE,
			PURPLE_MEDIA_CANDIDATE_TYPE_HOST,
			G_PARAM_READWRITE));

	g_object_class_install_property(gobject_class, PROP_USERNAME,
			g_param_spec_string("username",
			"Username",
			"The username used to connect to the candidate.",
			NULL,
			G_PARAM_READWRITE));

	g_object_class_install_property(gobject_class, PROP_PASSWORD,
			g_param_spec_string("password",
			"Password",
			"The password use to connect to the candidate.",
			NULL,
			G_PARAM_READWRITE));

	g_object_class_install_property(gobject_class, PROP_TTL,
			g_param_spec_uint("ttl",
			"TTL",
			"The TTL of the candidate.",
			0, G_MAXUINT, 0,
			G_PARAM_READWRITE));

	g_type_class_add_private(klass, sizeof(PurpleMediaCandidatePrivate));
}

PurpleMediaCandidate *
purple_media_candidate_new(const gchar *foundation, guint component_id,
		PurpleMediaCandidateType type,
		PurpleMediaNetworkProtocol proto,
		const gchar *ip, guint port)
{
	return g_object_new(PURPLE_TYPE_MEDIA_CANDIDATE,
			"foundation", foundation,
			"component-id", component_id,
			"type", type,
			"protocol", proto,
			"ip", ip,
			"port", port, NULL);
}

PurpleMediaCandidate *
purple_media_candidate_copy(PurpleMediaCandidate *candidate)
{
	PurpleMediaCandidatePrivate *priv;
	PurpleMediaCandidate *new_candidate;

	if (candidate == NULL)
		return NULL;

	priv = PURPLE_MEDIA_CANDIDATE_GET_PRIVATE(candidate);

	new_candidate = purple_media_candidate_new(priv->foundation,
			priv->component_id, priv->type, priv->proto,
			priv->ip, priv->port);
	g_object_set(new_candidate,
			"base-ip", priv->base_ip,
			"base-port", priv->base_port,
			"priority", priv->priority,
			"username", priv->username,
			"password", priv->password,
			"ttl", priv->ttl, NULL);
	return new_candidate;
}

GList *
purple_media_candidate_list_copy(GList *candidates)
{
	GList *new_list = NULL;

	for (; candidates; candidates = g_list_next(candidates)) {
		new_list = g_list_prepend(new_list,
				purple_media_candidate_copy(candidates->data));
	}

	new_list = g_list_reverse(new_list);
	return new_list;
}

void
purple_media_candidate_list_free(GList *candidates)
{
	for (; candidates; candidates =
			g_list_delete_link(candidates, candidates)) {
		g_object_unref(candidates->data);
	}
}

gchar *
purple_media_candidate_get_foundation(PurpleMediaCandidate *candidate)
{
	gchar *foundation;
	g_return_val_if_fail(PURPLE_IS_MEDIA_CANDIDATE(candidate), NULL);
	g_object_get(candidate, "foundation", &foundation, NULL);
	return foundation;
}

guint
purple_media_candidate_get_component_id(PurpleMediaCandidate *candidate)
{
	guint component_id;
	g_return_val_if_fail(PURPLE_IS_MEDIA_CANDIDATE(candidate), 0);
	g_object_get(candidate, "component-id", &component_id, NULL);
	return component_id;
}

gchar *
purple_media_candidate_get_ip(PurpleMediaCandidate *candidate)
{
	gchar *ip;
	g_return_val_if_fail(PURPLE_IS_MEDIA_CANDIDATE(candidate), NULL);
	g_object_get(candidate, "ip", &ip, NULL);
	return ip;
}

guint16
purple_media_candidate_get_port(PurpleMediaCandidate *candidate)
{
	guint port;
	g_return_val_if_fail(PURPLE_IS_MEDIA_CANDIDATE(candidate), 0);
	g_object_get(candidate, "port", &port, NULL);
	return port;
}

gchar *
purple_media_candidate_get_base_ip(PurpleMediaCandidate *candidate)
{
	gchar *base_ip;
	g_return_val_if_fail(PURPLE_IS_MEDIA_CANDIDATE(candidate), NULL);
	g_object_get(candidate, "base-ip", &base_ip, NULL);
	return base_ip;
}

guint16
purple_media_candidate_get_base_port(PurpleMediaCandidate *candidate)
{
	guint base_port;
	g_return_val_if_fail(PURPLE_IS_MEDIA_CANDIDATE(candidate), 0);
	g_object_get(candidate, "base_port", &base_port, NULL);
	return base_port;
}

PurpleMediaNetworkProtocol
purple_media_candidate_get_protocol(PurpleMediaCandidate *candidate)
{
	PurpleMediaNetworkProtocol protocol;
	g_return_val_if_fail(PURPLE_IS_MEDIA_CANDIDATE(candidate),
			PURPLE_MEDIA_NETWORK_PROTOCOL_UDP);
	g_object_get(candidate, "protocol", &protocol, NULL);
	return protocol;
}

guint32
purple_media_candidate_get_priority(PurpleMediaCandidate *candidate)
{
	guint priority;
	g_return_val_if_fail(PURPLE_IS_MEDIA_CANDIDATE(candidate), 0);
	g_object_get(candidate, "priority", &priority, NULL);
	return priority;
}

PurpleMediaCandidateType
purple_media_candidate_get_candidate_type(PurpleMediaCandidate *candidate)
{
	PurpleMediaCandidateType type;
	g_return_val_if_fail(PURPLE_IS_MEDIA_CANDIDATE(candidate),
			PURPLE_MEDIA_CANDIDATE_TYPE_HOST);
	g_object_get(candidate, "type", &type, NULL);
	return type;
}

gchar *
purple_media_candidate_get_username(PurpleMediaCandidate *candidate)
{
	gchar *username;
	g_return_val_if_fail(PURPLE_IS_MEDIA_CANDIDATE(candidate), NULL);
	g_object_get(candidate, "username", &username, NULL);
	return username;
}

gchar *
purple_media_candidate_get_password(PurpleMediaCandidate *candidate)
{
	gchar *password;
	g_return_val_if_fail(PURPLE_IS_MEDIA_CANDIDATE(candidate), NULL);
	g_object_get(candidate, "password", &password, NULL);
	return password;
}

guint
purple_media_candidate_get_ttl(PurpleMediaCandidate *candidate)
{
	guint ttl;
	g_return_val_if_fail(PURPLE_IS_MEDIA_CANDIDATE(candidate), 0);
	g_object_get(candidate, "ttl", &ttl, NULL);
	return ttl;
}

