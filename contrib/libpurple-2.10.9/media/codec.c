/**
 * @file codec.c Codec for Media API
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

#include "codec.h"

/** @copydoc _PurpleMediaCodecClass */
typedef struct _PurpleMediaCodecClass PurpleMediaCodecClass;
/** @copydoc _PurpleMediaCodecPrivate */
typedef struct _PurpleMediaCodecPrivate PurpleMediaCodecPrivate;

#define PURPLE_MEDIA_CODEC_GET_PRIVATE(obj) \
		(G_TYPE_INSTANCE_GET_PRIVATE((obj), \
		PURPLE_TYPE_MEDIA_CODEC, PurpleMediaCodecPrivate))

struct _PurpleMediaCodecClass
{
	GObjectClass parent_class;
};

struct _PurpleMediaCodec
{
	GObject parent;
};

G_DEFINE_TYPE(PurpleMediaCodec, purple_media_codec, G_TYPE_OBJECT);

struct _PurpleMediaCodecPrivate
{
	gint id;
	char *encoding_name;
	PurpleMediaSessionType media_type;
	guint clock_rate;
	guint channels;
	GList *optional_params;
};

enum {
	PROP_CODEC_0,
	PROP_ID,
	PROP_ENCODING_NAME,
	PROP_MEDIA_TYPE,
	PROP_CLOCK_RATE,
	PROP_CHANNELS,
	PROP_OPTIONAL_PARAMS,
};

static void
purple_media_codec_init(PurpleMediaCodec *info)
{
	PurpleMediaCodecPrivate *priv =
			PURPLE_MEDIA_CODEC_GET_PRIVATE(info);
	priv->encoding_name = NULL;
	priv->optional_params = NULL;
}

static void
purple_media_codec_finalize(GObject *info)
{
	PurpleMediaCodecPrivate *priv =
			PURPLE_MEDIA_CODEC_GET_PRIVATE(info);
	g_free(priv->encoding_name);
	for (; priv->optional_params; priv->optional_params =
			g_list_delete_link(priv->optional_params, priv->optional_params)) {
		PurpleKeyValuePair *param = priv->optional_params->data;
		g_free(param->key);
		g_free(param->value);
		g_free(param);
	}
}

static void
purple_media_codec_set_property (GObject *object, guint prop_id,
		const GValue *value, GParamSpec *pspec)
{
	PurpleMediaCodecPrivate *priv;
	g_return_if_fail(PURPLE_IS_MEDIA_CODEC(object));

	priv = PURPLE_MEDIA_CODEC_GET_PRIVATE(object);

	switch (prop_id) {
		case PROP_ID:
			priv->id = g_value_get_uint(value);
			break;
		case PROP_ENCODING_NAME:
			g_free(priv->encoding_name);
			priv->encoding_name = g_value_dup_string(value);
			break;
		case PROP_MEDIA_TYPE:
			priv->media_type = g_value_get_flags(value);
			break;
		case PROP_CLOCK_RATE:
			priv->clock_rate = g_value_get_uint(value);
			break;
		case PROP_CHANNELS:
			priv->channels = g_value_get_uint(value);
			break;
		case PROP_OPTIONAL_PARAMS:
			priv->optional_params = g_value_get_pointer(value);
			break;
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID(
					object, prop_id, pspec);
			break;
	}
}

static void
purple_media_codec_get_property (GObject *object, guint prop_id,
		GValue *value, GParamSpec *pspec)
{
	PurpleMediaCodecPrivate *priv;
	g_return_if_fail(PURPLE_IS_MEDIA_CODEC(object));

	priv = PURPLE_MEDIA_CODEC_GET_PRIVATE(object);

	switch (prop_id) {
		case PROP_ID:
			g_value_set_uint(value, priv->id);
			break;
		case PROP_ENCODING_NAME:
			g_value_set_string(value, priv->encoding_name);
			break;
		case PROP_MEDIA_TYPE:
			g_value_set_flags(value, priv->media_type);
			break;
		case PROP_CLOCK_RATE:
			g_value_set_uint(value, priv->clock_rate);
			break;
		case PROP_CHANNELS:
			g_value_set_uint(value, priv->channels);
			break;
		case PROP_OPTIONAL_PARAMS:
			g_value_set_pointer(value, priv->optional_params);
			break;
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID(
					object, prop_id, pspec);
			break;
	}
}

static void
purple_media_codec_class_init(PurpleMediaCodecClass *klass)
{
	GObjectClass *gobject_class = (GObjectClass*)klass;

	gobject_class->finalize = purple_media_codec_finalize;
	gobject_class->set_property = purple_media_codec_set_property;
	gobject_class->get_property = purple_media_codec_get_property;

	g_object_class_install_property(gobject_class, PROP_ID,
			g_param_spec_uint("id",
			"ID",
			"The numeric identifier of the codec.",
			0, G_MAXUINT, 0,
			G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE));

	g_object_class_install_property(gobject_class, PROP_ENCODING_NAME,
			g_param_spec_string("encoding-name",
			"Encoding Name",
			"The name of the codec.",
			NULL,
			G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE));

	g_object_class_install_property(gobject_class, PROP_MEDIA_TYPE,
			g_param_spec_flags("media-type",
			"Media Type",
			"Whether this is an audio of video codec.",
			PURPLE_TYPE_MEDIA_SESSION_TYPE,
			PURPLE_MEDIA_NONE,
			G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE));

	g_object_class_install_property(gobject_class, PROP_CLOCK_RATE,
			g_param_spec_uint("clock-rate",
			"Create Callback",
			"The function called to create this element.",
			0, G_MAXUINT, 0,
			G_PARAM_READWRITE));

	g_object_class_install_property(gobject_class, PROP_CHANNELS,
			g_param_spec_uint("channels",
			"Channels",
			"The number of channels in this codec.",
			0, G_MAXUINT, 0,
			G_PARAM_READWRITE));
	g_object_class_install_property(gobject_class, PROP_OPTIONAL_PARAMS,
			g_param_spec_pointer("optional-params",
			"Optional Params",
			"A list of optional parameters for the codec.",
			G_PARAM_READWRITE));

	g_type_class_add_private(klass, sizeof(PurpleMediaCodecPrivate));
}

PurpleMediaCodec *
purple_media_codec_new(int id, const char *encoding_name,
		PurpleMediaSessionType media_type, guint clock_rate)
{
	PurpleMediaCodec *codec =
			g_object_new(PURPLE_TYPE_MEDIA_CODEC,
			"id", id,
			"encoding_name", encoding_name,
			"media_type", media_type,
			"clock-rate", clock_rate, NULL);
	return codec;
}

guint
purple_media_codec_get_id(PurpleMediaCodec *codec)
{
	guint id;
	g_return_val_if_fail(PURPLE_IS_MEDIA_CODEC(codec), 0);
	g_object_get(codec, "id", &id, NULL);
	return id;
}

gchar *
purple_media_codec_get_encoding_name(PurpleMediaCodec *codec)
{
	gchar *name;
	g_return_val_if_fail(PURPLE_IS_MEDIA_CODEC(codec), NULL);
	g_object_get(codec, "encoding-name", &name, NULL);
	return name;
}

guint
purple_media_codec_get_clock_rate(PurpleMediaCodec *codec)
{
	guint clock_rate;
	g_return_val_if_fail(PURPLE_IS_MEDIA_CODEC(codec), 0);
	g_object_get(codec, "clock-rate", &clock_rate, NULL);
	return clock_rate;
}

guint
purple_media_codec_get_channels(PurpleMediaCodec *codec)
{
	guint channels;
	g_return_val_if_fail(PURPLE_IS_MEDIA_CODEC(codec), 0);
	g_object_get(codec, "channels", &channels, NULL);
	return channels;
}

GList *
purple_media_codec_get_optional_parameters(PurpleMediaCodec *codec)
{
	GList *optional_params;
	g_return_val_if_fail(PURPLE_IS_MEDIA_CODEC(codec), NULL);
	g_object_get(codec, "optional-params", &optional_params, NULL);
	return optional_params;
}

void
purple_media_codec_add_optional_parameter(PurpleMediaCodec *codec,
		const gchar *name, const gchar *value)
{
	PurpleMediaCodecPrivate *priv;
	PurpleKeyValuePair *new_param;

	g_return_if_fail(codec != NULL);
	g_return_if_fail(name != NULL && value != NULL);

	priv = PURPLE_MEDIA_CODEC_GET_PRIVATE(codec);

	new_param = g_new0(PurpleKeyValuePair, 1);
	new_param->key = g_strdup(name);
	new_param->value = g_strdup(value);
	priv->optional_params = g_list_append(
			priv->optional_params, new_param);
}

void
purple_media_codec_remove_optional_parameter(PurpleMediaCodec *codec,
		PurpleKeyValuePair *param)
{
	PurpleMediaCodecPrivate *priv;

	g_return_if_fail(codec != NULL && param != NULL);

	priv = PURPLE_MEDIA_CODEC_GET_PRIVATE(codec);

	g_free(param->key);
	g_free(param->value);

	priv->optional_params =
			g_list_remove(priv->optional_params, param);
	g_free(param);
}

PurpleKeyValuePair *
purple_media_codec_get_optional_parameter(PurpleMediaCodec *codec,
		const gchar *name, const gchar *value)
{
	PurpleMediaCodecPrivate *priv;
	GList *iter;

	g_return_val_if_fail(codec != NULL, NULL);
	g_return_val_if_fail(name != NULL, NULL);

	priv = PURPLE_MEDIA_CODEC_GET_PRIVATE(codec);

	for (iter = priv->optional_params; iter; iter = g_list_next(iter)) {
		PurpleKeyValuePair *param = iter->data;
		if (!g_ascii_strcasecmp(param->key, name) &&
				(value == NULL ||
				!g_ascii_strcasecmp(param->value, value)))
			return param;
	}

	return NULL;
}

PurpleMediaCodec *
purple_media_codec_copy(PurpleMediaCodec *codec)
{
	PurpleMediaCodecPrivate *priv;
	PurpleMediaCodec *new_codec;
	GList *iter;

	if (codec == NULL)
		return NULL;

	priv = PURPLE_MEDIA_CODEC_GET_PRIVATE(codec);

	new_codec = purple_media_codec_new(priv->id, priv->encoding_name,
			priv->media_type, priv->clock_rate);
	g_object_set(codec, "channels", priv->channels, NULL);

	for (iter = priv->optional_params; iter; iter = g_list_next(iter)) {
		PurpleKeyValuePair *param =
				(PurpleKeyValuePair*)iter->data;
		purple_media_codec_add_optional_parameter(new_codec,
				param->key, param->value);
	}

	return new_codec;
}

GList *
purple_media_codec_list_copy(GList *codecs)
{
	GList *new_list = NULL;

	for (; codecs; codecs = g_list_next(codecs)) {
		new_list = g_list_prepend(new_list,
				purple_media_codec_copy(codecs->data));
	}

	new_list = g_list_reverse(new_list);
	return new_list;
}

void
purple_media_codec_list_free(GList *codecs)
{
	for (; codecs; codecs =
			g_list_delete_link(codecs, codecs)) {
		g_object_unref(codecs->data);
	}
}

gchar *
purple_media_codec_to_string(const PurpleMediaCodec *codec)
{
	PurpleMediaCodecPrivate *priv;
	GString *string = NULL;
	GList *item;
	gchar *charstring;
	const gchar *media_type_str = NULL;

	if (codec == NULL)
		return g_strdup("(NULL)");

	priv = PURPLE_MEDIA_CODEC_GET_PRIVATE(codec);

	string = g_string_new("");

	if (priv->media_type & PURPLE_MEDIA_AUDIO)
		media_type_str = "audio";
	else if (priv->media_type & PURPLE_MEDIA_VIDEO)
		media_type_str = "video";

	g_string_printf(string, "%d: %s %s clock:%d channels:%d", priv->id,
			media_type_str, priv->encoding_name,
			priv->clock_rate, priv->channels);

	for (item = priv->optional_params; item; item = g_list_next (item)) {
		PurpleKeyValuePair *param = item->data;
		g_string_append_printf (string, " %s=%s",
				param->key, (gchar *)param->value);
	}

	charstring = string->str;
	g_string_free (string, FALSE);

	return charstring;
}

