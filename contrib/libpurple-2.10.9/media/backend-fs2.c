/**
 * @file backend-fs2.c Farstream backend for media API
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

#include "internal.h"

#include "backend-fs2.h"

#ifdef USE_VV
#include "backend-iface.h"
#include "debug.h"
#include "network.h"
#include "media-gst.h"

#ifdef HAVE_FARSIGHT
#include <gst/farsight/fs-conference-iface.h>
#include <gst/farsight/fs-element-added-notifier.h>
#else
#include <farstream/fs-conference.h>
#include <farstream/fs-element-added-notifier.h>
#include <farstream/fs-utils.h>
#endif

/** @copydoc _PurpleMediaBackendFs2Class */
typedef struct _PurpleMediaBackendFs2Class PurpleMediaBackendFs2Class;
/** @copydoc _PurpleMediaBackendFs2Private */
typedef struct _PurpleMediaBackendFs2Private PurpleMediaBackendFs2Private;
/** @copydoc _PurpleMediaBackendFs2Session */
typedef struct _PurpleMediaBackendFs2Session PurpleMediaBackendFs2Session;
/** @copydoc _PurpleMediaBackendFs2Stream */
typedef struct _PurpleMediaBackendFs2Stream PurpleMediaBackendFs2Stream;

#define PURPLE_MEDIA_BACKEND_FS2_GET_PRIVATE(obj) \
		(G_TYPE_INSTANCE_GET_PRIVATE((obj), \
		PURPLE_TYPE_MEDIA_BACKEND_FS2, PurpleMediaBackendFs2Private))

static void purple_media_backend_iface_init(PurpleMediaBackendIface *iface);

static gboolean
gst_bus_cb(GstBus *bus, GstMessage *msg, PurpleMediaBackendFs2 *self);
static void
state_changed_cb(PurpleMedia *media, PurpleMediaState state,
		gchar *sid, gchar *name, PurpleMediaBackendFs2 *self);
static void
stream_info_cb(PurpleMedia *media, PurpleMediaInfoType type,
		gchar *sid, gchar *name, gboolean local,
		PurpleMediaBackendFs2 *self);

static gboolean purple_media_backend_fs2_add_stream(PurpleMediaBackend *self,
		const gchar *sess_id, const gchar *who,
		PurpleMediaSessionType type, gboolean initiator,
		const gchar *transmitter,
		guint num_params, GParameter *params);
static void purple_media_backend_fs2_add_remote_candidates(
		PurpleMediaBackend *self,
		const gchar *sess_id, const gchar *participant,
		GList *remote_candidates);
static gboolean purple_media_backend_fs2_codecs_ready(PurpleMediaBackend *self,
		const gchar *sess_id);
static GList *purple_media_backend_fs2_get_codecs(PurpleMediaBackend *self,
		const gchar *sess_id);
static GList *purple_media_backend_fs2_get_local_candidates(
		PurpleMediaBackend *self,
		const gchar *sess_id, const gchar *participant);
static gboolean purple_media_backend_fs2_set_remote_codecs(
		PurpleMediaBackend *self,
		const gchar *sess_id, const gchar *participant,
		GList *codecs);
static gboolean purple_media_backend_fs2_set_send_codec(
		PurpleMediaBackend *self, const gchar *sess_id,
		PurpleMediaCodec *codec);
static void purple_media_backend_fs2_set_params(PurpleMediaBackend *self,
		guint num_params, GParameter *params);
static const gchar **purple_media_backend_fs2_get_available_params(void);

static void free_stream(PurpleMediaBackendFs2Stream *stream);
static void free_session(PurpleMediaBackendFs2Session *session);

struct _PurpleMediaBackendFs2Class
{
	GObjectClass parent_class;
};

struct _PurpleMediaBackendFs2
{
	GObject parent;
};

G_DEFINE_TYPE_WITH_CODE(PurpleMediaBackendFs2, purple_media_backend_fs2,
		G_TYPE_OBJECT, G_IMPLEMENT_INTERFACE(
		PURPLE_TYPE_MEDIA_BACKEND, purple_media_backend_iface_init));

struct _PurpleMediaBackendFs2Stream
{
	PurpleMediaBackendFs2Session *session;
	gchar *participant;
	FsStream *stream;

#ifndef HAVE_FARSIGHT
	gboolean supports_add;
#endif

	GstElement *src;
	GstElement *tee;
	GstElement *volume;
	GstElement *level;
	GstElement *fakesink;
	GstElement *queue;

	GList *local_candidates;
	GList *remote_candidates;

	guint connected_cb_id;
};

struct _PurpleMediaBackendFs2Session
{
	PurpleMediaBackendFs2 *backend;
	gchar *id;
	FsSession *session;

	GstElement *src;
	GstElement *tee;
	GstElement *srcvalve;

	GstPad *srcpad;

	PurpleMediaSessionType type;
};

struct _PurpleMediaBackendFs2Private
{
	PurpleMedia *media;
	GstElement *confbin;
	FsConference *conference;
	gchar *conference_type;

#ifndef HAVE_FARSIGHT
	FsElementAddedNotifier *notifier;
#endif

	GHashTable *sessions;
	GHashTable *participants;

	GList *streams;

	gdouble silence_threshold;
};

enum {
	PROP_0,
	PROP_CONFERENCE_TYPE,
	PROP_MEDIA,
};

static void
purple_media_backend_fs2_init(PurpleMediaBackendFs2 *self)
{}

static gboolean
event_probe_cb(GstPad *srcpad, GstEvent *event, gboolean release_pad)
{
	if (GST_EVENT_TYPE(event) == GST_EVENT_CUSTOM_DOWNSTREAM
		&& gst_event_has_name(event, "purple-unlink-tee")) {

		const GstStructure *s = gst_event_get_structure(event);

		gst_pad_unlink(srcpad, gst_pad_get_peer(srcpad));

		gst_pad_remove_event_probe(srcpad,
			g_value_get_uint(gst_structure_get_value(s, "handler-id")));

		if (g_value_get_boolean(gst_structure_get_value(s, "release-pad")))
			gst_element_release_request_pad(GST_ELEMENT_PARENT(srcpad), srcpad);

		return FALSE;
	}

	return TRUE;
}

static void
unlink_teepad_dynamic(GstPad *srcpad, gboolean release_pad)
{
	guint id = gst_pad_add_event_probe(srcpad, G_CALLBACK(event_probe_cb), NULL);

	if (GST_IS_GHOST_PAD(srcpad))
		srcpad = gst_ghost_pad_get_target(GST_GHOST_PAD(srcpad));

	gst_element_send_event(gst_pad_get_parent_element(srcpad),
		gst_event_new_custom(GST_EVENT_CUSTOM_DOWNSTREAM,
			gst_structure_new("purple-unlink-tee",
				"release-pad", G_TYPE_BOOLEAN, release_pad,
				"handler-id", G_TYPE_UINT, id,
				NULL)));
}

static void
purple_media_backend_fs2_dispose(GObject *obj)
{
	PurpleMediaBackendFs2Private *priv =
			PURPLE_MEDIA_BACKEND_FS2_GET_PRIVATE(obj);
	GList *iter = NULL;

	purple_debug_info("backend-fs2", "purple_media_backend_fs2_dispose\n");

#ifndef HAVE_FARSIGHT
	if (priv->notifier) {
		g_object_unref(priv->notifier);
		priv->notifier = NULL;
	}
#endif

	if (priv->confbin) {
		GstElement *pipeline;

		pipeline = purple_media_manager_get_pipeline(
				purple_media_get_manager(priv->media));

		/* All connections to media sources should be blocked before confbin is
		 * removed, to prevent freezing of any other simultaneously running
		 * media calls. */
		if (priv->sessions) {
			GList *sessions = g_hash_table_get_values(priv->sessions);
			for (; sessions; sessions =
					g_list_delete_link(sessions, sessions)) {
				PurpleMediaBackendFs2Session *session = sessions->data;
				if (session->srcpad) {
					unlink_teepad_dynamic(session->srcpad, FALSE);
					gst_object_unref(session->srcpad);
					session->srcpad = NULL;
				}
			}
		}

		gst_element_set_locked_state(priv->confbin, TRUE);
		gst_element_set_state(GST_ELEMENT(priv->confbin),
				GST_STATE_NULL);

		if (pipeline) {
			GstBus *bus;
			gst_bin_remove(GST_BIN(pipeline), priv->confbin);
			bus = gst_pipeline_get_bus(GST_PIPELINE(pipeline));
			g_signal_handlers_disconnect_matched(G_OBJECT(bus),
					G_SIGNAL_MATCH_FUNC |
					G_SIGNAL_MATCH_DATA,
					0, 0, 0, gst_bus_cb, obj);
			gst_object_unref(bus);
		} else {
			purple_debug_warning("backend-fs2", "Unable to "
					"properly dispose the conference. "
					"Couldn't get the pipeline.\n");
		}

		priv->confbin = NULL;
		priv->conference = NULL;

	}

	if (priv->sessions) {
		GList *sessions = g_hash_table_get_values(priv->sessions);

		for (; sessions; sessions =
				g_list_delete_link(sessions, sessions)) {
			PurpleMediaBackendFs2Session *session =
					sessions->data;

			if (session->session) {
				g_object_unref(session->session);
				session->session = NULL;
			}
		}
	}

	if (priv->participants) {
		g_hash_table_destroy(priv->participants);
		priv->participants = NULL;
	}

	for (iter = priv->streams; iter; iter = g_list_next(iter)) {
		PurpleMediaBackendFs2Stream *stream = iter->data;
		if (stream->stream) {
			g_object_unref(stream->stream);
			stream->stream = NULL;
		}
	}

	if (priv->media) {
		g_object_remove_weak_pointer(G_OBJECT(priv->media),
				(gpointer*)&priv->media);
		priv->media = NULL;
	}

	G_OBJECT_CLASS(purple_media_backend_fs2_parent_class)->dispose(obj);
}

static void
purple_media_backend_fs2_finalize(GObject *obj)
{
	PurpleMediaBackendFs2Private *priv =
			PURPLE_MEDIA_BACKEND_FS2_GET_PRIVATE(obj);

	purple_debug_info("backend-fs2", "purple_media_backend_fs2_finalize\n");

	g_free(priv->conference_type);

	for (; priv->streams; priv->streams =
			g_list_delete_link(priv->streams, priv->streams)) {
		PurpleMediaBackendFs2Stream *stream = priv->streams->data;
		free_stream(stream);
	}

	if (priv->sessions) {
		GList *sessions = g_hash_table_get_values(priv->sessions);

		for (; sessions; sessions =
				g_list_delete_link(sessions, sessions)) {
			PurpleMediaBackendFs2Session *session =
					sessions->data;
			free_session(session);
		}

		g_hash_table_destroy(priv->sessions);
	}

	G_OBJECT_CLASS(purple_media_backend_fs2_parent_class)->finalize(obj);
}

static void
purple_media_backend_fs2_set_property(GObject *object, guint prop_id,
		const GValue *value, GParamSpec *pspec)
{
	PurpleMediaBackendFs2Private *priv;
	g_return_if_fail(PURPLE_IS_MEDIA_BACKEND_FS2(object));

	priv = PURPLE_MEDIA_BACKEND_FS2_GET_PRIVATE(object);

	switch (prop_id) {
		case PROP_CONFERENCE_TYPE:
			priv->conference_type = g_value_dup_string(value);
			break;
		case PROP_MEDIA:
			priv->media = g_value_get_object(value);

			if (priv->media == NULL)
				break;

			g_object_add_weak_pointer(G_OBJECT(priv->media),
					(gpointer*)&priv->media);

			g_signal_connect(G_OBJECT(priv->media),
					"state-changed",
					G_CALLBACK(state_changed_cb),
					PURPLE_MEDIA_BACKEND_FS2(object));
			g_signal_connect(G_OBJECT(priv->media), "stream-info",
					G_CALLBACK(stream_info_cb),
					PURPLE_MEDIA_BACKEND_FS2(object));
			break;
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID(
					object, prop_id, pspec);
			break;
	}
}

static void
purple_media_backend_fs2_get_property(GObject *object, guint prop_id,
		GValue *value, GParamSpec *pspec)
{
	PurpleMediaBackendFs2Private *priv;
	g_return_if_fail(PURPLE_IS_MEDIA_BACKEND_FS2(object));

	priv = PURPLE_MEDIA_BACKEND_FS2_GET_PRIVATE(object);

	switch (prop_id) {
		case PROP_CONFERENCE_TYPE:
			g_value_set_string(value, priv->conference_type);
			break;
		case PROP_MEDIA:
			g_value_set_object(value, priv->media);
			break;
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID(
					object, prop_id, pspec);
			break;
	}
}

static void
purple_media_backend_fs2_class_init(PurpleMediaBackendFs2Class *klass)
{
	GObjectClass *gobject_class = (GObjectClass*)klass;

	gobject_class->dispose = purple_media_backend_fs2_dispose;
	gobject_class->finalize = purple_media_backend_fs2_finalize;
	gobject_class->set_property = purple_media_backend_fs2_set_property;
	gobject_class->get_property = purple_media_backend_fs2_get_property;

	g_object_class_override_property(gobject_class, PROP_CONFERENCE_TYPE,
			"conference-type");
	g_object_class_override_property(gobject_class, PROP_MEDIA, "media");

	g_type_class_add_private(klass, sizeof(PurpleMediaBackendFs2Private));
}

static void
purple_media_backend_iface_init(PurpleMediaBackendIface *iface)
{
	iface->add_stream = purple_media_backend_fs2_add_stream;
	iface->add_remote_candidates =
			purple_media_backend_fs2_add_remote_candidates;
	iface->codecs_ready = purple_media_backend_fs2_codecs_ready;
	iface->get_codecs = purple_media_backend_fs2_get_codecs;
	iface->get_local_candidates =
			purple_media_backend_fs2_get_local_candidates;
	iface->set_remote_codecs = purple_media_backend_fs2_set_remote_codecs;
	iface->set_send_codec = purple_media_backend_fs2_set_send_codec;
	iface->set_params = purple_media_backend_fs2_set_params;
	iface->get_available_params = purple_media_backend_fs2_get_available_params;
}

static FsMediaType
session_type_to_fs_media_type(PurpleMediaSessionType type)
{
	if (type & PURPLE_MEDIA_AUDIO)
		return FS_MEDIA_TYPE_AUDIO;
	else if (type & PURPLE_MEDIA_VIDEO)
		return FS_MEDIA_TYPE_VIDEO;
	else
		return 0;
}

static FsStreamDirection
session_type_to_fs_stream_direction(PurpleMediaSessionType type)
{
	if ((type & PURPLE_MEDIA_AUDIO) == PURPLE_MEDIA_AUDIO ||
			(type & PURPLE_MEDIA_VIDEO) == PURPLE_MEDIA_VIDEO)
		return FS_DIRECTION_BOTH;
	else if ((type & PURPLE_MEDIA_SEND_AUDIO) ||
			(type & PURPLE_MEDIA_SEND_VIDEO))
		return FS_DIRECTION_SEND;
	else if ((type & PURPLE_MEDIA_RECV_AUDIO) ||
			(type & PURPLE_MEDIA_RECV_VIDEO))
		return FS_DIRECTION_RECV;
	else
		return FS_DIRECTION_NONE;
}

static PurpleMediaSessionType
session_type_from_fs(FsMediaType type, FsStreamDirection direction)
{
	PurpleMediaSessionType result = PURPLE_MEDIA_NONE;
	if (type == FS_MEDIA_TYPE_AUDIO) {
		if (direction & FS_DIRECTION_SEND)
			result |= PURPLE_MEDIA_SEND_AUDIO;
		if (direction & FS_DIRECTION_RECV)
			result |= PURPLE_MEDIA_RECV_AUDIO;
	} else if (type == FS_MEDIA_TYPE_VIDEO) {
		if (direction & FS_DIRECTION_SEND)
			result |= PURPLE_MEDIA_SEND_VIDEO;
		if (direction & FS_DIRECTION_RECV)
			result |= PURPLE_MEDIA_RECV_VIDEO;
	}
	return result;
}

static FsCandidate *
candidate_to_fs(PurpleMediaCandidate *candidate)
{
	FsCandidate *fscandidate;
	gchar *foundation;
	guint component_id;
	gchar *ip;
	guint port;
	gchar *base_ip;
	guint base_port;
	PurpleMediaNetworkProtocol proto;
	guint32 priority;
	PurpleMediaCandidateType type;
	gchar *username;
	gchar *password;
	guint ttl;

	if (candidate == NULL)
		return NULL;

	g_object_get(G_OBJECT(candidate),
			"foundation", &foundation,
			"component-id", &component_id,
			"ip", &ip,
			"port", &port,
			"base-ip", &base_ip,
			"base-port", &base_port,
			"protocol", &proto,
			"priority", &priority,
			"type", &type,
			"username", &username,
			"password", &password,
			"ttl", &ttl,
			NULL);

	fscandidate = fs_candidate_new(foundation,
			component_id, type,
			proto, ip, port);

	fscandidate->base_ip = base_ip;
	fscandidate->base_port = base_port;
	fscandidate->priority = priority;
	fscandidate->username = username;
	fscandidate->password = password;
	fscandidate->ttl = ttl;

	g_free(foundation);
	g_free(ip);
	return fscandidate;
}

static GList *
candidate_list_to_fs(GList *candidates)
{
	GList *new_list = NULL;

	for (; candidates; candidates = g_list_next(candidates)) {
		new_list = g_list_prepend(new_list,
				candidate_to_fs(candidates->data));
	}

	new_list = g_list_reverse(new_list);
	return new_list;
}

static PurpleMediaCandidate *
candidate_from_fs(FsCandidate *fscandidate)
{
	PurpleMediaCandidate *candidate;

	if (fscandidate == NULL)
		return NULL;

	candidate = purple_media_candidate_new(fscandidate->foundation,
		fscandidate->component_id, fscandidate->type,
		fscandidate->proto, fscandidate->ip, fscandidate->port);
	g_object_set(candidate,
			"base-ip", fscandidate->base_ip,
			"base-port", fscandidate->base_port,
			"priority", fscandidate->priority,
			"username", fscandidate->username,
			"password", fscandidate->password,
			"ttl", fscandidate->ttl, NULL);
	return candidate;
}

static GList *
candidate_list_from_fs(GList *candidates)
{
	GList *new_list = NULL;

	for (; candidates; candidates = g_list_next(candidates)) {
		new_list = g_list_prepend(new_list,
			candidate_from_fs(candidates->data));
	}

	new_list = g_list_reverse(new_list);
	return new_list;
}

static FsCodec *
codec_to_fs(const PurpleMediaCodec *codec)
{
	FsCodec *new_codec;
	gint id;
	char *encoding_name;
	PurpleMediaSessionType media_type;
	guint clock_rate;
	guint channels;
	GList *iter;

	if (codec == NULL)
		return NULL;

	g_object_get(G_OBJECT(codec),
			"id", &id,
			"encoding-name", &encoding_name,
			"media-type", &media_type,
			"clock-rate", &clock_rate,
			"channels", &channels,
			"optional-params", &iter,
			NULL);

	new_codec = fs_codec_new(id, encoding_name,
			session_type_to_fs_media_type(media_type),
			clock_rate);
	new_codec->channels = channels;

	for (; iter; iter = g_list_next(iter)) {
		PurpleKeyValuePair *param = (PurpleKeyValuePair*)iter->data;
		fs_codec_add_optional_parameter(new_codec,
				param->key, param->value);
	}

	g_free(encoding_name);
	return new_codec;
}

static PurpleMediaCodec *
codec_from_fs(const FsCodec *codec)
{
	PurpleMediaCodec *new_codec;
	GList *iter;

	if (codec == NULL)
		return NULL;

	new_codec = purple_media_codec_new(codec->id, codec->encoding_name,
			session_type_from_fs(codec->media_type,
			FS_DIRECTION_BOTH), codec->clock_rate);
	g_object_set(new_codec, "channels", codec->channels, NULL);

	for (iter = codec->optional_params; iter; iter = g_list_next(iter)) {
		FsCodecParameter *param = (FsCodecParameter*)iter->data;
		purple_media_codec_add_optional_parameter(new_codec,
				param->name, param->value);
	}

	return new_codec;
}

static GList *
codec_list_from_fs(GList *codecs)
{
	GList *new_list = NULL;

	for (; codecs; codecs = g_list_next(codecs)) {
		new_list = g_list_prepend(new_list,
				codec_from_fs(codecs->data));
	}

	new_list = g_list_reverse(new_list);
	return new_list;
}

static GList *
codec_list_to_fs(GList *codecs)
{
	GList *new_list = NULL;

	for (; codecs; codecs = g_list_next(codecs)) {
		new_list = g_list_prepend(new_list,
				codec_to_fs(codecs->data));
	}

	new_list = g_list_reverse(new_list);
	return new_list;
}

static PurpleMediaBackendFs2Session *
get_session(PurpleMediaBackendFs2 *self, const gchar *sess_id)
{
	PurpleMediaBackendFs2Private *priv;
	PurpleMediaBackendFs2Session *session = NULL;

	g_return_val_if_fail(PURPLE_IS_MEDIA_BACKEND_FS2(self), NULL);

	priv = PURPLE_MEDIA_BACKEND_FS2_GET_PRIVATE(self);

	if (priv->sessions != NULL)
		session = g_hash_table_lookup(priv->sessions, sess_id);

	return session;
}

static FsParticipant *
get_participant(PurpleMediaBackendFs2 *self, const gchar *name)
{
	PurpleMediaBackendFs2Private *priv;
	FsParticipant *participant = NULL;

	g_return_val_if_fail(PURPLE_IS_MEDIA_BACKEND_FS2(self), NULL);

	priv = PURPLE_MEDIA_BACKEND_FS2_GET_PRIVATE(self);

	if (priv->participants != NULL)
		participant = g_hash_table_lookup(priv->participants, name);

	return participant;
}

static PurpleMediaBackendFs2Stream *
get_stream(PurpleMediaBackendFs2 *self,
		const gchar *sess_id, const gchar *name)
{
	PurpleMediaBackendFs2Private *priv;
	GList *streams;

	g_return_val_if_fail(PURPLE_IS_MEDIA_BACKEND_FS2(self), NULL);

	priv = PURPLE_MEDIA_BACKEND_FS2_GET_PRIVATE(self);
	streams = priv->streams;

	for (; streams; streams = g_list_next(streams)) {
		PurpleMediaBackendFs2Stream *stream = streams->data;
		if (!strcmp(stream->session->id, sess_id) &&
				!strcmp(stream->participant, name))
			return stream;
	}

	return NULL;
}

static GList *
get_streams(PurpleMediaBackendFs2 *self,
		const gchar *sess_id, const gchar *name)
{
	PurpleMediaBackendFs2Private *priv;
	GList *streams, *ret = NULL;

	g_return_val_if_fail(PURPLE_IS_MEDIA_BACKEND_FS2(self), NULL);

	priv = PURPLE_MEDIA_BACKEND_FS2_GET_PRIVATE(self);
	streams = priv->streams;

	for (; streams; streams = g_list_next(streams)) {
		PurpleMediaBackendFs2Stream *stream = streams->data;

		if (sess_id != NULL && strcmp(stream->session->id, sess_id))
			continue;
		else if (name != NULL && strcmp(stream->participant, name))
			continue;
		else
			ret = g_list_prepend(ret, stream);
	}

	ret = g_list_reverse(ret);
	return ret;
}

static PurpleMediaBackendFs2Session *
get_session_from_fs_stream(PurpleMediaBackendFs2 *self, FsStream *stream)
{
	PurpleMediaBackendFs2Private *priv =
			PURPLE_MEDIA_BACKEND_FS2_GET_PRIVATE(self);
	FsSession *fssession;
	GList *values;

	g_return_val_if_fail(PURPLE_IS_MEDIA_BACKEND_FS2(self), NULL);
	g_return_val_if_fail(FS_IS_STREAM(stream), NULL);

	g_object_get(stream, "session", &fssession, NULL);

	values = g_hash_table_get_values(priv->sessions);

	for (; values; values = g_list_delete_link(values, values)) {
		PurpleMediaBackendFs2Session *session = values->data;

		if (session->session == fssession) {
			g_list_free(values);
			g_object_unref(fssession);
			return session;
		}
	}

	g_object_unref(fssession);
	return NULL;
}

static gdouble
gst_msg_db_to_percent(GstMessage *msg, gchar *value_name)
{
	const GValue *list;
	const GValue *value;
	gdouble value_db;
	gdouble percent;

	list = gst_structure_get_value(
				gst_message_get_structure(msg), value_name);
	value = gst_value_list_get_value(list, 0);
	value_db = g_value_get_double(value);
	percent = pow(10, value_db / 20);
	return (percent > 1.0) ? 1.0 : percent;
}

static void
gst_handle_message_element(GstBus *bus, GstMessage *msg,
		PurpleMediaBackendFs2 *self)
{
	PurpleMediaBackendFs2Private *priv =
			PURPLE_MEDIA_BACKEND_FS2_GET_PRIVATE(self);
	GstElement *src = GST_ELEMENT(GST_MESSAGE_SRC(msg));
	static guint level_id = 0;

	if (level_id == 0)
		level_id = g_signal_lookup("level", PURPLE_TYPE_MEDIA);

	if (gst_structure_has_name(msg->structure, "level")) {
		GstElement *src = GST_ELEMENT(GST_MESSAGE_SRC(msg));
		gchar *name;
		gchar *participant = NULL;
		PurpleMediaBackendFs2Session *session = NULL;
		gdouble percent;

		if (!PURPLE_IS_MEDIA(priv->media) ||
				GST_ELEMENT_PARENT(src) != priv->confbin)
			return;

		name = gst_element_get_name(src);

		if (!strncmp(name, "sendlevel_", 10)) {
			session = get_session(self, name+10);
			if (priv->silence_threshold > 0) {
				percent = gst_msg_db_to_percent(msg, "decay");
				g_object_set(session->srcvalve,
						"drop", (percent < priv->silence_threshold), NULL);
			}
		}

		g_free(name);

		if (!g_signal_has_handler_pending(priv->media, level_id, 0, FALSE))
			return;

		if (!session) {
			GList *iter = priv->streams;
			PurpleMediaBackendFs2Stream *stream;
			for (; iter; iter = g_list_next(iter)) {
				stream = iter->data;
				if (stream->level == src) {
					session = stream->session;
					participant = stream->participant;
					break;
				}
			}
		}

		if (!session)
			return;

		percent = gst_msg_db_to_percent(msg, "rms");

		g_signal_emit(priv->media, level_id, 0,
				session->id, participant, percent);
		return;
	}

	if (!FS_IS_CONFERENCE(src) || !PURPLE_IS_MEDIA_BACKEND(self) ||
			priv->conference != FS_CONFERENCE(src))
		return;

#ifdef HAVE_FARSIGHT
	if (gst_structure_has_name(msg->structure, "farsight-error")) {
#else
	if (gst_structure_has_name(msg->structure, "farstream-error")) {
#endif
		FsError error_no;
		gst_structure_get_enum(msg->structure, "error-no",
				FS_TYPE_ERROR, (gint*)&error_no);
		switch (error_no) {
			case FS_ERROR_NO_CODECS:
				purple_media_error(priv->media, _("No codecs"
						" found. Install some"
						" GStreamer codecs found"
						" in GStreamer plugins"
						" packages."));
				purple_media_end(priv->media, NULL, NULL);
				break;
#ifdef HAVE_FARSIGHT
			case FS_ERROR_NO_CODECS_LEFT:
				purple_media_error(priv->media, _("No codecs"
						" left. Your codec"
						" preferences in"
						" fs-codecs.conf are too"
						" strict."));
				purple_media_end(priv->media, NULL, NULL);
				break;
			case FS_ERROR_UNKNOWN_CNAME:
				/*
				 * Unknown CName is only a problem for the
				 * multicast transmitter which isn't used.
				 * It is also deprecated.
				 */
				break;
#endif
			default:
				purple_debug_error("backend-fs2",
#ifdef HAVE_FARSIGHT
						"farsight-error: %i: %s\n",
#else
						"farstream-error: %i: %s\n",
#endif
						error_no,
						gst_structure_get_string(
						msg->structure, "error-msg"));
				break;
		}

		if (FS_ERROR_IS_FATAL(error_no)) {
#ifdef HAVE_FARSIGHT
			purple_media_error(priv->media, _("A non-recoverable "
					"Farsight2 error has occurred."));
#else
			purple_media_error(priv->media, _("A non-recoverable "
					"Farstream error has occurred."));
#endif
			purple_media_end(priv->media, NULL, NULL);
		}
	} else if (gst_structure_has_name(msg->structure,
#ifdef HAVE_FARSIGHT
			"farsight-new-local-candidate")) {
#else
			"farstream-new-local-candidate")) {
#endif
		const GValue *value;
		FsStream *stream;
		FsCandidate *local_candidate;
		PurpleMediaCandidate *candidate;
		FsParticipant *participant;
		PurpleMediaBackendFs2Session *session;
		PurpleMediaBackendFs2Stream *media_stream;
		gchar *name;

		value = gst_structure_get_value(msg->structure, "stream");
		stream = g_value_get_object(value);
		value = gst_structure_get_value(msg->structure, "candidate");
		local_candidate = g_value_get_boxed(value);

		session = get_session_from_fs_stream(self, stream);

		purple_debug_info("backend-fs2",
				"got new local candidate: %s\n",
				local_candidate->foundation);

		g_object_get(stream, "participant", &participant, NULL);
		g_object_get(participant, "cname", &name, NULL);
		g_object_unref(participant);

		media_stream = get_stream(self, session->id, name);
		media_stream->local_candidates = g_list_append(
				media_stream->local_candidates,
				fs_candidate_copy(local_candidate));

		candidate = candidate_from_fs(local_candidate);
		g_signal_emit_by_name(self, "new-candidate",
				session->id, name, candidate);
		g_object_unref(candidate);
	} else if (gst_structure_has_name(msg->structure,
#ifdef HAVE_FARSIGHT
			"farsight-local-candidates-prepared")) {
#else
			"farstream-local-candidates-prepared")) {
#endif
		const GValue *value;
		FsStream *stream;
		FsParticipant *participant;
		PurpleMediaBackendFs2Session *session;
		gchar *name;

		value = gst_structure_get_value(msg->structure, "stream");
		stream = g_value_get_object(value);
		session = get_session_from_fs_stream(self, stream);

		g_object_get(stream, "participant", &participant, NULL);
		g_object_get(participant, "cname", &name, NULL);
		g_object_unref(participant);

		g_signal_emit_by_name(self, "candidates-prepared",
				session->id, name);
	} else if (gst_structure_has_name(msg->structure,
#ifdef HAVE_FARSIGHT
			"farsight-new-active-candidate-pair")) {
#else
			"farstream-new-active-candidate-pair")) {
#endif
		const GValue *value;
		FsStream *stream;
		FsCandidate *local_candidate;
		FsCandidate *remote_candidate;
		FsParticipant *participant;
		PurpleMediaBackendFs2Session *session;
		PurpleMediaCandidate *lcandidate, *rcandidate;
		gchar *name;

		value = gst_structure_get_value(msg->structure, "stream");
		stream = g_value_get_object(value);
		value = gst_structure_get_value(msg->structure,
				"local-candidate");
		local_candidate = g_value_get_boxed(value);
		value = gst_structure_get_value(msg->structure,
				"remote-candidate");
		remote_candidate = g_value_get_boxed(value);

		g_object_get(stream, "participant", &participant, NULL);
		g_object_get(participant, "cname", &name, NULL);
		g_object_unref(participant);

		session = get_session_from_fs_stream(self, stream);

		lcandidate = candidate_from_fs(local_candidate);
		rcandidate = candidate_from_fs(remote_candidate);

		g_signal_emit_by_name(self, "active-candidate-pair",
				session->id, name, lcandidate, rcandidate);

		g_object_unref(lcandidate);
		g_object_unref(rcandidate);
	} else if (gst_structure_has_name(msg->structure,
#ifdef HAVE_FARSIGHT
			"farsight-recv-codecs-changed")) {
#else
			"farstream-recv-codecs-changed")) {
#endif
		const GValue *value;
		GList *codecs;
		FsCodec *codec;

		value = gst_structure_get_value(msg->structure, "codecs");
		codecs = g_value_get_boxed(value);
		codec = codecs->data;

		purple_debug_info("backend-fs2",
#ifdef HAVE_FARSIGHT
				"farsight-recv-codecs-changed: %s\n",
#else
				"farstream-recv-codecs-changed: %s\n",
#endif
				codec->encoding_name);
	} else if (gst_structure_has_name(msg->structure,
#ifdef HAVE_FARSIGHT
			"farsight-component-state-changed")) {
#else
			"farstream-component-state-changed")) {
#endif
		const GValue *value;
		FsStreamState fsstate;
		guint component;
		const gchar *state;

		value = gst_structure_get_value(msg->structure, "state");
		fsstate = g_value_get_enum(value);
		value = gst_structure_get_value(msg->structure, "component");
		component = g_value_get_uint(value);

		switch (fsstate) {
			case FS_STREAM_STATE_FAILED:
				state = "FAILED";
				break;
			case FS_STREAM_STATE_DISCONNECTED:
				state = "DISCONNECTED";
				break;
			case FS_STREAM_STATE_GATHERING:
				state = "GATHERING";
				break;
			case FS_STREAM_STATE_CONNECTING:
				state = "CONNECTING";
				break;
			case FS_STREAM_STATE_CONNECTED:
				state = "CONNECTED";
				break;
			case FS_STREAM_STATE_READY:
				state = "READY";
				break;
			default:
				state = "UNKNOWN";
				break;
		}

		purple_debug_info("backend-fs2",
#ifdef HAVE_FARSIGHT
				"farsight-component-state-changed: "
#else
				"farstream-component-state-changed: "
#endif
				"component: %u state: %s\n",
				component, state);
	} else if (gst_structure_has_name(msg->structure,
#ifdef HAVE_FARSIGHT
			"farsight-send-codec-changed")) {
#else
			"farstream-send-codec-changed")) {
#endif
		const GValue *value;
		FsCodec *codec;
		gchar *codec_str;

		value = gst_structure_get_value(msg->structure, "codec");
		codec = g_value_get_boxed(value);
		codec_str = fs_codec_to_string(codec);

		purple_debug_info("backend-fs2",
#ifdef HAVE_FARSIGHT
				"farsight-send-codec-changed: codec: %s\n",
#else
				"farstream-send-codec-changed: codec: %s\n",
#endif
				codec_str);

		g_free(codec_str);
	} else if (gst_structure_has_name(msg->structure,
#ifdef HAVE_FARSIGHT
			"farsight-codecs-changed")) {
#else
			"farstream-codecs-changed")) {
#endif
		const GValue *value;
		FsSession *fssession;
		GList *sessions;

		value = gst_structure_get_value(msg->structure, "session");
		fssession = g_value_get_object(value);
		sessions = g_hash_table_get_values(priv->sessions);

		for (; sessions; sessions =
				g_list_delete_link(sessions, sessions)) {
			PurpleMediaBackendFs2Session *session = sessions->data;
			gchar *session_id;

			if (session->session != fssession)
				continue;

			session_id = g_strdup(session->id);
			g_signal_emit_by_name(self, "codecs-changed",
					session_id);
			g_free(session_id);
			g_list_free(sessions);
			break;
		}
	}
}

static void
gst_handle_message_error(GstBus *bus, GstMessage *msg,
		PurpleMediaBackendFs2 *self)
{
	PurpleMediaBackendFs2Private *priv =
			PURPLE_MEDIA_BACKEND_FS2_GET_PRIVATE(self);
	GstElement *element = GST_ELEMENT(GST_MESSAGE_SRC(msg));
	GstElement *lastElement = NULL;
	GList *sessions;

	GError *error = NULL;
	gchar *debug_msg = NULL;

	gst_message_parse_error(msg, &error, &debug_msg);
	purple_debug_error("backend-fs2", "gst error %s\ndebugging: %s\n",
			error->message, debug_msg);

	g_error_free(error);
	g_free(debug_msg);

	while (element && !GST_IS_PIPELINE(element)) {
		if (element == priv->confbin)
			break;

		lastElement = element;
		element = GST_ELEMENT_PARENT(element);
	}

	if (!element || !GST_IS_PIPELINE(element))
		return;

	sessions = purple_media_get_session_ids(priv->media);

	for (; sessions; sessions = g_list_delete_link(sessions, sessions)) {
		if (purple_media_get_src(priv->media, sessions->data)
				!= lastElement)
			continue;

		if (purple_media_get_session_type(priv->media, sessions->data)
				& PURPLE_MEDIA_AUDIO)
			purple_media_error(priv->media,
					_("Error with your microphone"));
		else
			purple_media_error(priv->media,
					_("Error with your webcam"));

		break;
	}

	g_list_free(sessions);

	purple_media_error(priv->media, _("Conference error"));
	purple_media_end(priv->media, NULL, NULL);
}

static gboolean
gst_bus_cb(GstBus *bus, GstMessage *msg, PurpleMediaBackendFs2 *self)
{
	switch(GST_MESSAGE_TYPE(msg)) {
		case GST_MESSAGE_ELEMENT:
			gst_handle_message_element(bus, msg, self);
			break;
		case GST_MESSAGE_ERROR:
			gst_handle_message_error(bus, msg, self);
			break;
		default:
			break;
	}

	return TRUE;
}

static void
remove_element(GstElement *element)
{
	if (element) {
		gst_element_set_locked_state(element, TRUE);
		gst_element_set_state(element, GST_STATE_NULL);
		gst_bin_remove(GST_BIN(GST_ELEMENT_PARENT(element)), element);
	}
}

static void
state_changed_cb(PurpleMedia *media, PurpleMediaState state,
		gchar *sid, gchar *name, PurpleMediaBackendFs2 *self)
{
	if (state == PURPLE_MEDIA_STATE_END) {
		PurpleMediaBackendFs2Private *priv =
				PURPLE_MEDIA_BACKEND_FS2_GET_PRIVATE(self);

		if (sid && name) {
			PurpleMediaBackendFs2Stream *stream = get_stream(self, sid, name);
			gst_object_unref(stream->stream);

			priv->streams = g_list_remove(priv->streams, stream);

			remove_element(stream->src);
			remove_element(stream->tee);
			remove_element(stream->volume);
			remove_element(stream->level);
			remove_element(stream->fakesink);
			remove_element(stream->queue);

			free_stream(stream);
		} else if (sid && !name) {
			PurpleMediaBackendFs2Session *session = get_session(self, sid);
			GstPad *pad;

			g_object_get(session->session, "sink-pad", &pad, NULL);
			gst_pad_unlink(GST_PAD_PEER(pad), pad);
			gst_object_unref(pad);

			gst_object_unref(session->session);
			g_hash_table_remove(priv->sessions, session->id);

			pad = gst_pad_get_peer(session->srcpad);
			gst_element_remove_pad(GST_ELEMENT_PARENT(pad), pad);
			gst_object_unref(pad);
			gst_object_unref(session->srcpad);

			remove_element(session->srcvalve);
			remove_element(session->tee);

			free_session(session);
		}

		purple_media_manager_remove_output_windows(
				purple_media_get_manager(media), media, sid, name);
	}
}

static void
stream_info_cb(PurpleMedia *media, PurpleMediaInfoType type,
		gchar *sid, gchar *name, gboolean local,
		PurpleMediaBackendFs2 *self)
{
	if (type == PURPLE_MEDIA_INFO_ACCEPT && sid != NULL && name != NULL) {
		PurpleMediaBackendFs2Stream *stream =
				get_stream(self, sid, name);
		GError *err = NULL;

		g_object_set(G_OBJECT(stream->stream), "direction",
				session_type_to_fs_stream_direction(
				stream->session->type), NULL);

		if (stream->remote_candidates == NULL ||
				purple_media_is_initiator(media, sid, name))
			return;

#ifdef HAVE_FARSIGHT
		fs_stream_set_remote_candidates(stream->stream,
				stream->remote_candidates, &err);
#else
		if (stream->supports_add)
			fs_stream_add_remote_candidates(stream->stream,
					stream->remote_candidates, &err);
		else
			fs_stream_force_remote_candidates(stream->stream,
					stream->remote_candidates, &err);
#endif

		if (err == NULL)
			return;

		purple_debug_error("backend-fs2", "Error adding "
				"remote candidates: %s\n",
				err->message);
		g_error_free(err);
	} else if (local == TRUE && (type == PURPLE_MEDIA_INFO_MUTE ||
			type == PURPLE_MEDIA_INFO_UNMUTE)) {
		PurpleMediaBackendFs2Private *priv =
				PURPLE_MEDIA_BACKEND_FS2_GET_PRIVATE(self);
		gboolean active = (type == PURPLE_MEDIA_INFO_MUTE);
		GList *sessions;

		if (sid == NULL)
			sessions = g_hash_table_get_values(priv->sessions);
		else
			sessions = g_list_prepend(NULL,
					get_session(self, sid));

		purple_debug_info("media", "Turning mute %s\n",
				active ? "on" : "off");

		for (; sessions; sessions = g_list_delete_link(
				sessions, sessions)) {
			PurpleMediaBackendFs2Session *session =
					sessions->data;

			if (session->type & PURPLE_MEDIA_SEND_AUDIO) {
				gchar *name = g_strdup_printf("volume_%s",
						session->id);
				GstElement *volume = gst_bin_get_by_name(
						GST_BIN(priv->confbin), name);
				g_free(name);
				g_object_set(volume, "mute", active, NULL);
			}
		}
	} else if (local == TRUE && (type == PURPLE_MEDIA_INFO_HOLD ||
			type == PURPLE_MEDIA_INFO_UNHOLD)) {
		gboolean active = (type == PURPLE_MEDIA_INFO_HOLD);
		GList *streams = get_streams(self, sid, name);
		for (; streams; streams =
				g_list_delete_link(streams, streams)) {
			PurpleMediaBackendFs2Stream *stream = streams->data;
			if (stream->session->type & PURPLE_MEDIA_SEND_AUDIO) {
				g_object_set(stream->stream, "direction",
						session_type_to_fs_stream_direction(
						stream->session->type & ((active) ?
						~PURPLE_MEDIA_SEND_AUDIO :
						PURPLE_MEDIA_AUDIO)), NULL);
			}
		}
	} else if (local == TRUE && (type == PURPLE_MEDIA_INFO_PAUSE ||
			type == PURPLE_MEDIA_INFO_UNPAUSE)) {
		gboolean active = (type == PURPLE_MEDIA_INFO_PAUSE);
		GList *streams = get_streams(self, sid, name);
		for (; streams; streams =
				g_list_delete_link(streams, streams)) {
			PurpleMediaBackendFs2Stream *stream = streams->data;
			if (stream->session->type & PURPLE_MEDIA_SEND_VIDEO) {
				g_object_set(stream->stream, "direction",
						session_type_to_fs_stream_direction(
						stream->session->type & ((active) ?
						~PURPLE_MEDIA_SEND_VIDEO :
						PURPLE_MEDIA_VIDEO)), NULL);
			}
		}
	}
}

static gboolean
init_conference(PurpleMediaBackendFs2 *self)
{
	PurpleMediaBackendFs2Private *priv =
			PURPLE_MEDIA_BACKEND_FS2_GET_PRIVATE(self);
	GstElement *pipeline;
	GstBus *bus;
	gchar *name;
#ifndef HAVE_FARSIGHT
	GKeyFile *default_props;
#endif

	priv->conference = FS_CONFERENCE(
			gst_element_factory_make(priv->conference_type, NULL));

	if (priv->conference == NULL) {
		purple_debug_error("backend-fs2", "Conference == NULL\n");
		return FALSE;
	}

	if (purple_account_get_silence_suppression(
				purple_media_get_account(priv->media)))
		priv->silence_threshold = purple_prefs_get_int(
				"/purple/media/audio/silence_threshold") / 100.0;
	else
		priv->silence_threshold = 0;

	pipeline = purple_media_manager_get_pipeline(
			purple_media_get_manager(priv->media));

	if (pipeline == NULL) {
		purple_debug_error("backend-fs2",
				"Couldn't retrieve pipeline.\n");
		return FALSE;
	}

	name = g_strdup_printf("conf_%p", priv->conference);
	priv->confbin = gst_bin_new(name);
	if (priv->confbin == NULL) {
		purple_debug_error("backend-fs2",
				"Couldn't create confbin.\n");
		return FALSE;
	}

	g_free(name);

	bus = gst_pipeline_get_bus(GST_PIPELINE(pipeline));
	if (bus == NULL) {
		purple_debug_error("backend-fs2",
				"Couldn't get the pipeline's bus.\n");
		return FALSE;
	}

#ifndef HAVE_FARSIGHT
	default_props = fs_utils_get_default_element_properties(GST_ELEMENT(priv->conference));
	if (default_props != NULL) {
		priv->notifier = fs_element_added_notifier_new();
		fs_element_added_notifier_add(priv->notifier,
				GST_BIN(priv->confbin));
		fs_element_added_notifier_set_properties_from_keyfile(priv->notifier, default_props);
	}
#endif

	g_signal_connect(G_OBJECT(bus), "message",
			G_CALLBACK(gst_bus_cb), self);
	gst_object_unref(bus);

	if (!gst_bin_add(GST_BIN(pipeline),
			GST_ELEMENT(priv->confbin))) {
		purple_debug_error("backend-fs2", "Couldn't add confbin "
				"element to the pipeline\n");
		return FALSE;
	}

	if (!gst_bin_add(GST_BIN(priv->confbin),
			GST_ELEMENT(priv->conference))) {
		purple_debug_error("backend-fs2", "Couldn't add conference "
				"element to the confbin\n");
		return FALSE;
	}

	if (gst_element_set_state(GST_ELEMENT(priv->confbin),
			GST_STATE_PLAYING) == GST_STATE_CHANGE_FAILURE) {
		purple_debug_error("backend-fs2",
				"Failed to start conference.\n");
		return FALSE;
	}

	return TRUE;
}

static void
gst_element_added_cb(FsElementAddedNotifier *self,
		GstBin *bin, GstElement *element, gpointer user_data)
{
	/*
	 * Hack to make H264 work with Gmail video.
	 */
	if (!strncmp(GST_ELEMENT_NAME(element), "x264", 4)) {
		g_object_set(GST_OBJECT(element), "cabac", FALSE, NULL);
	}
}

static gboolean
create_src(PurpleMediaBackendFs2 *self, const gchar *sess_id,
		PurpleMediaSessionType type)
{
	PurpleMediaBackendFs2Private *priv =
			PURPLE_MEDIA_BACKEND_FS2_GET_PRIVATE(self);
	PurpleMediaBackendFs2Session *session;
	PurpleMediaSessionType session_type;
	FsMediaType media_type = session_type_to_fs_media_type(type);
	FsStreamDirection type_direction =
			session_type_to_fs_stream_direction(type);
	GstElement *src;
	GstPad *sinkpad, *srcpad;
	GstPad *ghost = NULL;

	if ((type_direction & FS_DIRECTION_SEND) == 0)
		return TRUE;

	session_type = session_type_from_fs(
			media_type, FS_DIRECTION_SEND);
	src = purple_media_manager_get_element(
			purple_media_get_manager(priv->media),
			session_type, priv->media, sess_id, NULL);

	if (!GST_IS_ELEMENT(src)) {
		purple_debug_error("backend-fs2",
				"Error creating src for session %s\n",
				sess_id);
		return FALSE;
	}

	session = get_session(self, sess_id);

	if (session == NULL) {
		purple_debug_warning("backend-fs2",
				"purple_media_set_src: trying to set"
				" src on non-existent session\n");
		return FALSE;
	}

	if (session->src)
		gst_object_unref(session->src);

	session->src = src;
	gst_element_set_locked_state(session->src, TRUE);

	session->tee = gst_element_factory_make("tee", NULL);
	gst_bin_add(GST_BIN(priv->confbin), session->tee);

	/* This supposedly isn't necessary, but it silences some warnings */
	if (GST_ELEMENT_PARENT(priv->confbin)
			== GST_ELEMENT_PARENT(session->src)) {
		GstPad *pad = gst_element_get_static_pad(session->tee, "sink");
		ghost = gst_ghost_pad_new(NULL, pad);
		gst_object_unref(pad);
		gst_pad_set_active(ghost, TRUE);
		gst_element_add_pad(priv->confbin, ghost);
	}

	gst_element_set_state(session->tee, GST_STATE_PLAYING);
	gst_element_link(session->src, priv->confbin);
	if (ghost)
		session->srcpad = gst_pad_get_peer(ghost);

	g_object_get(session->session, "sink-pad", &sinkpad, NULL);
	if (session->type & PURPLE_MEDIA_SEND_AUDIO) {
		gchar *name = g_strdup_printf("volume_%s", session->id);
		GstElement *level;
		GstElement *volume = gst_element_factory_make("volume", name);
		double input_volume = purple_prefs_get_int(
				"/purple/media/audio/volume/input")/10.0;
		g_free(name);
		name = g_strdup_printf("sendlevel_%s", session->id);
		level = gst_element_factory_make("level", name);
		g_free(name);
		session->srcvalve = gst_element_factory_make("valve", NULL);
		gst_bin_add(GST_BIN(priv->confbin), volume);
		gst_bin_add(GST_BIN(priv->confbin), level);
		gst_bin_add(GST_BIN(priv->confbin), session->srcvalve);
		gst_element_set_state(level, GST_STATE_PLAYING);
		gst_element_set_state(volume, GST_STATE_PLAYING);
		gst_element_set_state(session->srcvalve, GST_STATE_PLAYING);
		gst_element_link(level, session->srcvalve);
		gst_element_link(volume, level);
		gst_element_link(session->tee, volume);
		srcpad = gst_element_get_static_pad(session->srcvalve, "src");
		g_object_set(volume, "volume", input_volume, NULL);
	} else {
		srcpad = gst_element_get_request_pad(session->tee, "src%d");
	}

	purple_debug_info("backend-fs2", "connecting pad: %s\n",
			  gst_pad_link(srcpad, sinkpad) == GST_PAD_LINK_OK
			  ? "success" : "failure");
	gst_element_set_locked_state(session->src, FALSE);
	gst_object_unref(session->src);
	gst_object_unref(sinkpad);

	gst_element_set_state(session->src, GST_STATE_PLAYING);

	purple_media_manager_create_output_window(purple_media_get_manager(
			priv->media), priv->media, sess_id, NULL);

	return TRUE;
}

static gboolean
create_session(PurpleMediaBackendFs2 *self, const gchar *sess_id,
		PurpleMediaSessionType type, gboolean initiator,
		const gchar *transmitter)
{
	PurpleMediaBackendFs2Private *priv =
			PURPLE_MEDIA_BACKEND_FS2_GET_PRIVATE(self);
	PurpleMediaBackendFs2Session *session;
	GError *err = NULL;
	GList *codec_conf = NULL, *iter = NULL;
	gchar *filename = NULL;
	gboolean is_nice = !strcmp(transmitter, "nice");

	session = g_new0(PurpleMediaBackendFs2Session, 1);

	session->session = fs_conference_new_session(priv->conference,
			session_type_to_fs_media_type(type), &err);

	if (err != NULL) {
		purple_media_error(priv->media,
				_("Error creating session: %s"),
				err->message);
		g_error_free(err);
		g_free(session);
		return FALSE;
	}

	filename = g_build_filename(purple_user_dir(), "fs-codec.conf", NULL);
	codec_conf = fs_codec_list_from_keyfile(filename, &err);
	g_free(filename);

	if (err != NULL) {
		if (err->code == 4)
			purple_debug_info("backend-fs2", "Couldn't read "
					"fs-codec.conf: %s\n",
					err->message);
		else
			purple_debug_error("backend-fs2", "Error reading "
					"fs-codec.conf: %s\n",
					err->message);
		g_error_free(err);
	}

	/*
	 * Add SPEEX if the configuration file doesn't exist or
	 * there isn't a speex entry.
	 */
	for (iter = codec_conf; iter; iter = g_list_next(iter)) {
		FsCodec *codec = iter->data;
		if (!g_ascii_strcasecmp(codec->encoding_name, "speex"))
			break;
	}

	if (iter == NULL) {
		codec_conf = g_list_prepend(codec_conf,
				fs_codec_new(FS_CODEC_ID_ANY,
				"SPEEX", FS_MEDIA_TYPE_AUDIO, 8000));
		codec_conf = g_list_prepend(codec_conf,
				fs_codec_new(FS_CODEC_ID_ANY,
				"SPEEX", FS_MEDIA_TYPE_AUDIO, 16000));
	}

	fs_session_set_codec_preferences(session->session, codec_conf, NULL);
	fs_codec_list_destroy(codec_conf);

	/*
	 * Removes a 5-7 second delay before
	 * receiving the src-pad-added signal.
	 * Only works for non-multicast FsRtpSessions.
	 */
	if (!!strcmp(transmitter, "multicast"))
		g_object_set(G_OBJECT(session->session),
				"no-rtcp-timeout", 0, NULL);

	/*
	 * Hack to make x264 work with Gmail video.
	 */
	if (is_nice && !strcmp(sess_id, "google-video")) {
		FsElementAddedNotifier *notifier =
				fs_element_added_notifier_new();
		g_signal_connect(G_OBJECT(notifier), "element-added",
				G_CALLBACK(gst_element_added_cb), NULL);
		fs_element_added_notifier_add(notifier,
				GST_BIN(priv->conference));
	}

	session->id = g_strdup(sess_id);
	session->backend = self;
	session->type = type;

	if (!priv->sessions) {
		purple_debug_info("backend-fs2",
				"Creating hash table for sessions\n");
		priv->sessions = g_hash_table_new_full(g_str_hash, g_str_equal,
		                                       g_free, NULL);
	}

	g_hash_table_insert(priv->sessions, g_strdup(session->id), session);

	if (!create_src(self, sess_id, type)) {
		purple_debug_info("backend-fs2", "Error creating the src\n");
		return FALSE;
	}

	return TRUE;
}

static void
free_session(PurpleMediaBackendFs2Session *session)
{
	g_free(session->id);
	g_free(session);
}

static gboolean
create_participant(PurpleMediaBackendFs2 *self, const gchar *name)
{
	PurpleMediaBackendFs2Private *priv =
			PURPLE_MEDIA_BACKEND_FS2_GET_PRIVATE(self);
	FsParticipant *participant;
	GError *err = NULL;

	participant = fs_conference_new_participant(
#ifdef HAVE_FARSIGHT
			priv->conference, name, &err);
#else
			priv->conference, &err);
#endif

	if (err) {
		purple_debug_error("backend-fs2",
				"Error creating participant: %s\n",
				err->message);
		g_error_free(err);
		return FALSE;
	}

#ifndef HAVE_FARSIGHT
	if (g_object_class_find_property(G_OBJECT_GET_CLASS(participant),
			"cname")) {
		g_object_set(participant, "cname", name, NULL);
	}
#endif

	if (!priv->participants) {
		purple_debug_info("backend-fs2",
				"Creating hash table for participants\n");
		priv->participants = g_hash_table_new_full(g_str_hash,
				g_str_equal, g_free, g_object_unref);
	}

	g_hash_table_insert(priv->participants, g_strdup(name), participant);

	return TRUE;
}

static gboolean
src_pad_added_cb_cb(PurpleMediaBackendFs2Stream *stream)
{
	PurpleMediaBackendFs2Private *priv;

	g_return_val_if_fail(stream != NULL, FALSE);

	priv = PURPLE_MEDIA_BACKEND_FS2_GET_PRIVATE(stream->session->backend);
	stream->connected_cb_id = 0;

	purple_media_manager_create_output_window(
			purple_media_get_manager(priv->media), priv->media,
			stream->session->id, stream->participant);

	g_signal_emit_by_name(priv->media, "state-changed",
			PURPLE_MEDIA_STATE_CONNECTED,
			stream->session->id, stream->participant);
	return FALSE;
}

static void
src_pad_added_cb(FsStream *fsstream, GstPad *srcpad,
		FsCodec *codec, PurpleMediaBackendFs2Stream *stream)
{
	PurpleMediaBackendFs2Private *priv;
	GstPad *sinkpad;

	g_return_if_fail(FS_IS_STREAM(fsstream));
	g_return_if_fail(stream != NULL);

	priv = PURPLE_MEDIA_BACKEND_FS2_GET_PRIVATE(stream->session->backend);

	if (stream->src == NULL) {
		GstElement *sink = NULL;

		if (codec->media_type == FS_MEDIA_TYPE_AUDIO) {
			double output_volume = purple_prefs_get_int(
					"/purple/media/audio/volume/output")/10.0;
			/*
			 * Should this instead be:
			 *  audioconvert ! audioresample ! liveadder !
			 *   audioresample ! audioconvert ! realsink
			 */
			stream->queue = gst_element_factory_make("queue", NULL);
			stream->volume = gst_element_factory_make(
					"volume", NULL);
			g_object_set(stream->volume, "volume",
					output_volume, NULL);
			stream->level = gst_element_factory_make(
					"level", NULL);
			stream->src = gst_element_factory_make(
					"liveadder", NULL);
			sink = purple_media_manager_get_element(
					purple_media_get_manager(priv->media),
					PURPLE_MEDIA_RECV_AUDIO, priv->media,
					stream->session->id,
					stream->participant);
			gst_bin_add(GST_BIN(priv->confbin), stream->queue);
			gst_bin_add(GST_BIN(priv->confbin), stream->volume);
			gst_bin_add(GST_BIN(priv->confbin), stream->level);
			gst_bin_add(GST_BIN(priv->confbin), sink);
			gst_element_set_state(sink, GST_STATE_PLAYING);
			gst_element_set_state(stream->level, GST_STATE_PLAYING);
			gst_element_set_state(stream->volume, GST_STATE_PLAYING);
			gst_element_set_state(stream->queue, GST_STATE_PLAYING);
			gst_element_link(stream->level, sink);
			gst_element_link(stream->volume, stream->level);
			gst_element_link(stream->queue, stream->volume);
			sink = stream->queue;
		} else if (codec->media_type == FS_MEDIA_TYPE_VIDEO) {
			stream->src = gst_element_factory_make(
					"fsfunnel", NULL);
			sink = gst_element_factory_make(
					"fakesink", NULL);
			g_object_set(G_OBJECT(sink), "async", FALSE, NULL);
			gst_bin_add(GST_BIN(priv->confbin), sink);
			gst_element_set_state(sink, GST_STATE_PLAYING);
			stream->fakesink = sink;
		}
		stream->tee = gst_element_factory_make("tee", NULL);
		gst_bin_add_many(GST_BIN(priv->confbin),
				stream->src, stream->tee, NULL);
		gst_element_set_state(stream->tee, GST_STATE_PLAYING);
		gst_element_set_state(stream->src, GST_STATE_PLAYING);
		gst_element_link_many(stream->src, stream->tee, sink, NULL);
	}

	sinkpad = gst_element_get_request_pad(stream->src, "sink%d");
	gst_pad_link(srcpad, sinkpad);
	gst_object_unref(sinkpad);

	stream->connected_cb_id = purple_timeout_add(0,
			(GSourceFunc)src_pad_added_cb_cb, stream);
}

static GValueArray *
append_relay_info(GValueArray *relay_info, const gchar *ip, gint port,
	const gchar *username, const gchar *password, const gchar *type)
{
	GValue value;
	GstStructure *turn_setup = gst_structure_new("relay-info",
				"ip", G_TYPE_STRING, ip,
				"port", G_TYPE_UINT, port,
				"username", G_TYPE_STRING, username,
				"password", G_TYPE_STRING, password,
				"relay-type", G_TYPE_STRING, type,
				NULL);

	if (turn_setup) {
		memset(&value, 0, sizeof(GValue));
		g_value_init(&value, GST_TYPE_STRUCTURE);
		gst_value_set_structure(&value, turn_setup);
		relay_info = g_value_array_append(relay_info, &value);
		gst_structure_free(turn_setup);
	}

	return relay_info;
}

static gboolean
create_stream(PurpleMediaBackendFs2 *self,
		const gchar *sess_id, const gchar *who,
		PurpleMediaSessionType type, gboolean initiator,
		const gchar *transmitter,
		guint num_params, GParameter *params)
{
	PurpleMediaBackendFs2Private *priv =
			PURPLE_MEDIA_BACKEND_FS2_GET_PRIVATE(self);
	GError *err = NULL;
	FsStream *fsstream = NULL;
	const gchar *stun_ip = purple_network_get_stun_ip();
	const gchar *turn_ip = purple_network_get_turn_ip();
	guint _num_params = num_params;
	GParameter *_params;
	FsStreamDirection type_direction =
			session_type_to_fs_stream_direction(type);
	PurpleMediaBackendFs2Session *session;
	PurpleMediaBackendFs2Stream *stream;
	FsParticipant *participant;
	/* check if the prpl has already specified a relay-info
	  we need to do this to allow them to override when using non-standard
	  TURN modes, like Google f.ex. */
	gboolean got_turn_from_prpl = FALSE;
	int i;

	session = get_session(self, sess_id);

	if (session == NULL) {
		purple_debug_error("backend-fs2",
				"Couldn't find session to create stream.\n");
		return FALSE;
	}

	participant = get_participant(self, who);

	if (participant == NULL) {
		purple_debug_error("backend-fs2", "Couldn't find "
				"participant to create stream.\n");
		return FALSE;
	}

#ifndef HAVE_FARSIGHT
	fsstream = fs_session_new_stream(session->session, participant,
			initiator == TRUE ? type_direction :
			(type_direction & FS_DIRECTION_RECV), &err);

	if (fsstream == NULL) {
		if (err) {
			purple_debug_error("backend-fs2",
					"Error creating stream: %s\n",
					err && err->message ?
					err->message : "NULL");
			g_error_free(err);
		} else
			purple_debug_error("backend-fs2",
					"Error creating stream\n");
		return FALSE;
	}
#endif

	for (i = 0 ; i < num_params ; i++) {
		if (purple_strequal(params[i].name, "relay-info")) {
			got_turn_from_prpl = TRUE;
			break;
		}
	}

	_params = g_new0(GParameter, num_params + 3);
	memcpy(_params, params, sizeof(GParameter) * num_params);

	/* set the controlling mode parameter */
	_params[_num_params].name = "controlling-mode";
	g_value_init(&_params[_num_params].value, G_TYPE_BOOLEAN);
	g_value_set_boolean(&_params[_num_params].value, initiator);
	++_num_params;

	if (stun_ip) {
		purple_debug_info("backend-fs2",
			"Setting stun-ip on new stream: %s\n", stun_ip);

		_params[_num_params].name = "stun-ip";
		g_value_init(&_params[_num_params].value, G_TYPE_STRING);
		g_value_set_string(&_params[_num_params].value, stun_ip);
		++_num_params;
	}

	if (turn_ip && !strcmp("nice", transmitter) && !got_turn_from_prpl) {
		GValueArray *relay_info = g_value_array_new(0);
		gint port;
		const gchar *username =	purple_prefs_get_string(
				"/purple/network/turn_username");
		const gchar *password = purple_prefs_get_string(
				"/purple/network/turn_password");

		/* UDP */
		port = purple_prefs_get_int("/purple/network/turn_port");
		if (port > 0) {
			relay_info = append_relay_info(relay_info, turn_ip, port, username,
				password, "udp");
		}
		
		/* TCP */
		port = purple_prefs_get_int("/purple/network/turn_port_tcp");
		if (port > 0) {
			relay_info = append_relay_info(relay_info, turn_ip, port, username,
				password, "tcp");
		}

		/* TURN over SSL is only supported by libnice for Google's "psuedo" SSL mode
			at this time */

		purple_debug_info("backend-fs2",
			"Setting relay-info on new stream\n");
		_params[_num_params].name = "relay-info";
		g_value_init(&_params[_num_params].value,
			G_TYPE_VALUE_ARRAY);
		g_value_set_boxed(&_params[_num_params].value,
			relay_info);
		g_value_array_free(relay_info);
		_num_params++;
	}

#ifdef HAVE_FARSIGHT
	fsstream = fs_session_new_stream(session->session, participant,
			initiator == TRUE ? type_direction :
			(type_direction & FS_DIRECTION_RECV), transmitter,
			_num_params, _params, &err);
	g_free(_params);

	if (fsstream == NULL) {
		if (err) {
			purple_debug_error("backend-fs2",
					"Error creating stream: %s\n",
					err && err->message ?
					err->message : "NULL");
			g_error_free(err);
		} else
			purple_debug_error("backend-fs2",
					"Error creating stream\n");
		return FALSE;
	}
#else
	if (!fs_stream_set_transmitter(fsstream, transmitter,
			_params, _num_params, &err)) {
		purple_debug_error("backend-fs2",
				"Could not set transmitter %s: %s.\n",
				transmitter, err->message);
		g_clear_error(&err);
		g_free(_params);
		return FALSE;
	}
	g_free(_params);
#endif

	stream = g_new0(PurpleMediaBackendFs2Stream, 1);
	stream->participant = g_strdup(who);
	stream->session = session;
	stream->stream = fsstream;
#ifndef HAVE_FARSIGHT
	stream->supports_add = !strcmp(transmitter, "nice");
#endif

	priv->streams =	g_list_append(priv->streams, stream);

	g_signal_connect(G_OBJECT(fsstream), "src-pad-added",
			G_CALLBACK(src_pad_added_cb), stream);

	return TRUE;
}

static void
free_stream(PurpleMediaBackendFs2Stream *stream)
{
	/* Remove the connected_cb timeout */
	if (stream->connected_cb_id != 0)
		purple_timeout_remove(stream->connected_cb_id);

	g_free(stream->participant);

	if (stream->local_candidates)
		fs_candidate_list_destroy(stream->local_candidates);

	if (stream->remote_candidates)
		fs_candidate_list_destroy(stream->remote_candidates);

	g_free(stream);
}

static gboolean
purple_media_backend_fs2_add_stream(PurpleMediaBackend *self,
		const gchar *sess_id, const gchar *who,
		PurpleMediaSessionType type, gboolean initiator,
		const gchar *transmitter,
		guint num_params, GParameter *params)
{
	PurpleMediaBackendFs2 *backend = PURPLE_MEDIA_BACKEND_FS2(self);
	PurpleMediaBackendFs2Private *priv =
			PURPLE_MEDIA_BACKEND_FS2_GET_PRIVATE(backend);
	PurpleMediaBackendFs2Stream *stream;

	if (priv->conference == NULL && !init_conference(backend)) {
		purple_debug_error("backend-fs2",
				"Error initializing the conference.\n");
		return FALSE;
	}

	if (get_session(backend, sess_id) == NULL &&
			!create_session(backend, sess_id, type,
			initiator, transmitter)) {
		purple_debug_error("backend-fs2",
				"Error creating the session.\n");
		return FALSE;
	}

	if (get_participant(backend, who) == NULL &&
			!create_participant(backend, who)) {
		purple_debug_error("backend-fs2",
				"Error creating the participant.\n");
		return FALSE;
	}

	stream = get_stream(backend, sess_id, who);

	if (stream != NULL) {
		FsStreamDirection type_direction =
				session_type_to_fs_stream_direction(type);

		if (session_type_to_fs_stream_direction(
				stream->session->type) != type_direction) {
			/* change direction */
			g_object_set(stream->stream, "direction",
					type_direction, NULL);
		}
	} else if (!create_stream(backend, sess_id, who, type,
			initiator, transmitter, num_params, params)) {
		purple_debug_error("backend-fs2",
				"Error creating the stream.\n");
		return FALSE;
	}

	return TRUE;
}

static void
purple_media_backend_fs2_add_remote_candidates(PurpleMediaBackend *self,
		const gchar *sess_id, const gchar *participant,
		GList *remote_candidates)
{
	PurpleMediaBackendFs2Private *priv;
	PurpleMediaBackendFs2Stream *stream;
	GError *err = NULL;

	g_return_if_fail(PURPLE_IS_MEDIA_BACKEND_FS2(self));

	priv = PURPLE_MEDIA_BACKEND_FS2_GET_PRIVATE(self);
	stream = get_stream(PURPLE_MEDIA_BACKEND_FS2(self),
			sess_id, participant);

	if (stream == NULL) {
		purple_debug_error("backend-fs2",
				"purple_media_add_remote_candidates: "
				"couldn't find stream %s %s.\n",
				sess_id ? sess_id : "(null)",
				participant ? participant : "(null)");
		return;
	}

	stream->remote_candidates = g_list_concat(stream->remote_candidates,
			candidate_list_to_fs(remote_candidates));

	if (purple_media_is_initiator(priv->media, sess_id, participant) ||
			purple_media_accepted(
			priv->media, sess_id, participant)) {
#ifdef HAVE_FARSIGHT
		fs_stream_set_remote_candidates(stream->stream,
				stream->remote_candidates, &err);
#else
		if (stream->supports_add)
			fs_stream_add_remote_candidates(stream->stream,
					stream->remote_candidates, &err);
		else
			fs_stream_force_remote_candidates(stream->stream,
					stream->remote_candidates, &err);
#endif

		if (err) {
			purple_debug_error("backend-fs2", "Error adding remote"
					" candidates: %s\n", err->message);
			g_error_free(err);
		}
	}
}

static gboolean
purple_media_backend_fs2_codecs_ready(PurpleMediaBackend *self,
		const gchar *sess_id)
{
	PurpleMediaBackendFs2Private *priv;
	gboolean ret = FALSE;

	g_return_val_if_fail(PURPLE_IS_MEDIA_BACKEND_FS2(self), FALSE);

	priv = PURPLE_MEDIA_BACKEND_FS2_GET_PRIVATE(self);

	if (sess_id != NULL) {
		PurpleMediaBackendFs2Session *session = get_session(
				PURPLE_MEDIA_BACKEND_FS2(self), sess_id);

		if (session == NULL)
			return FALSE;

		if (session->type & (PURPLE_MEDIA_SEND_AUDIO |
				PURPLE_MEDIA_SEND_VIDEO)) {
#ifdef HAVE_FARSIGHT
			g_object_get(session->session,
					"codecs-ready", &ret, NULL);	
#else
			GList *codecs = NULL;

			g_object_get(session->session,
					"codecs", &codecs, NULL);
			if (codecs) {
				fs_codec_list_destroy (codecs);
				ret = TRUE;
			}
#endif
		} else
			ret = TRUE;
	} else {
		GList *values = g_hash_table_get_values(priv->sessions);

		for (; values; values = g_list_delete_link(values, values)) {
			PurpleMediaBackendFs2Session *session = values->data;

			if (session->type & (PURPLE_MEDIA_SEND_AUDIO |
					PURPLE_MEDIA_SEND_VIDEO)) {
#ifdef HAVE_FARSIGHT
				g_object_get(session->session,
						"codecs-ready", &ret, NULL);
				if (ret == FALSE)
					break;
#else
				GList *codecs = NULL;

				g_object_get(session->session,
						"codecs", &codecs, NULL);
				if (codecs) {
					fs_codec_list_destroy (codecs);
					ret = TRUE;
				} else {
					ret = FALSE;
					break;
				}
#endif
			} else
				ret = TRUE;
		}

		if (values != NULL)
			g_list_free(values);
	}

	return ret;
}

static GList *
purple_media_backend_fs2_get_codecs(PurpleMediaBackend *self,
		const gchar *sess_id)
{
	PurpleMediaBackendFs2Session *session;
	GList *fscodecs;
	GList *codecs;

	g_return_val_if_fail(PURPLE_IS_MEDIA_BACKEND_FS2(self), NULL);

	session = get_session(PURPLE_MEDIA_BACKEND_FS2(self), sess_id);

	if (session == NULL)
		return NULL;

	g_object_get(G_OBJECT(session->session),
		     "codecs", &fscodecs, NULL);
	codecs = codec_list_from_fs(fscodecs);
	fs_codec_list_destroy(fscodecs);

	return codecs;
}

static GList *
purple_media_backend_fs2_get_local_candidates(PurpleMediaBackend *self,
		const gchar *sess_id, const gchar *participant)
{
	PurpleMediaBackendFs2Stream *stream;
	GList *candidates = NULL;

	g_return_val_if_fail(PURPLE_IS_MEDIA_BACKEND_FS2(self), NULL);

	stream = get_stream(PURPLE_MEDIA_BACKEND_FS2(self),
			sess_id, participant);

	if (stream != NULL)
		candidates = candidate_list_from_fs(
				stream->local_candidates);
	return candidates;
}

static gboolean
purple_media_backend_fs2_set_remote_codecs(PurpleMediaBackend *self,
		const gchar *sess_id, const gchar *participant,
		GList *codecs)
{
	PurpleMediaBackendFs2Stream *stream;
	GList *fscodecs;
	GError *err = NULL;

	g_return_val_if_fail(PURPLE_IS_MEDIA_BACKEND_FS2(self), FALSE);
	stream = get_stream(PURPLE_MEDIA_BACKEND_FS2(self),
			sess_id, participant);

	if (stream == NULL)
		return FALSE;

	fscodecs = codec_list_to_fs(codecs);
	fs_stream_set_remote_codecs(stream->stream, fscodecs, &err);
	fs_codec_list_destroy(fscodecs);

	if (err) {
		purple_debug_error("backend-fs2",
				"Error setting remote codecs: %s\n",
				err->message);
		g_error_free(err);
		return FALSE;
	}

	return TRUE;
}

static gboolean
purple_media_backend_fs2_set_send_codec(PurpleMediaBackend *self,
		const gchar *sess_id, PurpleMediaCodec *codec)
{
	PurpleMediaBackendFs2Session *session;
	FsCodec *fscodec;
	GError *err = NULL;

	g_return_val_if_fail(PURPLE_IS_MEDIA_BACKEND_FS2(self), FALSE);

	session = get_session(PURPLE_MEDIA_BACKEND_FS2(self), sess_id);

	if (session == NULL)
		return FALSE;

	fscodec = codec_to_fs(codec);
	fs_session_set_send_codec(session->session, fscodec, &err);
	fs_codec_destroy(fscodec);

	if (err) {
		purple_debug_error("media", "Error setting send codec\n");
		g_error_free(err);
		return FALSE;
	}

	return TRUE;
}

static void
purple_media_backend_fs2_set_params(PurpleMediaBackend *self,
		guint num_params, GParameter *params)
{
	PurpleMediaBackendFs2Private *priv;
	const gchar **supported = purple_media_backend_fs2_get_available_params();
	const gchar **p;
	guint i;

	g_return_if_fail(PURPLE_IS_MEDIA_BACKEND_FS2(self));

	priv = PURPLE_MEDIA_BACKEND_FS2_GET_PRIVATE(self);

	if (priv->conference == NULL &&
		!init_conference(PURPLE_MEDIA_BACKEND_FS2(self))) {
		purple_debug_error("backend-fs2",
				"Error initializing the conference.\n");
		return;
	}

	for (i = 0; i != num_params; ++i) {
		for (p = supported; *p != NULL; ++p) {
			if (!strcmp(params[i].name, *p)) {
				g_object_set(priv->conference,
						params[i].name, g_value_get_string(&params[i].value),
						NULL);
				break;
			}
		}
	}
}

static const gchar **
purple_media_backend_fs2_get_available_params(void)
{
	static const gchar *supported_params[] = {
		"sdes-cname", "sdes-email", "sdes-location", "sdes-name", "sdes-note",
		"sdes-phone", "sdes-tool", NULL
	};

	return supported_params;
}
#else
GType
purple_media_backend_fs2_get_type(void)
{
	return G_TYPE_NONE;
}
#endif /* USE_VV */

#ifdef USE_GSTREAMER
GstElement *
purple_media_backend_fs2_get_src(PurpleMediaBackendFs2 *self,
		const gchar *sess_id)
{
#ifdef USE_VV
	PurpleMediaBackendFs2Session *session = get_session(self, sess_id);
	return session != NULL ? session->src : NULL;
#else
	return NULL;
#endif
}

GstElement *
purple_media_backend_fs2_get_tee(PurpleMediaBackendFs2 *self,
		const gchar *sess_id, const gchar *who)
{
#ifdef USE_VV
	if (sess_id != NULL && who == NULL) {
		PurpleMediaBackendFs2Session *session =
				get_session(self, sess_id);
		return (session != NULL) ? session->tee : NULL;
	} else if (sess_id != NULL && who != NULL) {
		PurpleMediaBackendFs2Stream *stream =
				get_stream(self, sess_id, who);
		return (stream != NULL) ? stream->tee : NULL;
	}

#endif /* USE_VV */
	g_return_val_if_reached(NULL);
}

void
purple_media_backend_fs2_set_input_volume(PurpleMediaBackendFs2 *self,
		const gchar *sess_id, double level)
{
#ifdef USE_VV
	PurpleMediaBackendFs2Private *priv;
	GList *sessions;

	g_return_if_fail(PURPLE_IS_MEDIA_BACKEND_FS2(self));

	priv = PURPLE_MEDIA_BACKEND_FS2_GET_PRIVATE(self);

	purple_prefs_set_int("/purple/media/audio/volume/input", level);

	if (sess_id == NULL)
		sessions = g_hash_table_get_values(priv->sessions);
	else
		sessions = g_list_append(NULL, get_session(self, sess_id));

	for (; sessions; sessions = g_list_delete_link(sessions, sessions)) {
		PurpleMediaBackendFs2Session *session = sessions->data;

		if (session->type & PURPLE_MEDIA_SEND_AUDIO) {
			gchar *name = g_strdup_printf("volume_%s",
					session->id);
			GstElement *volume = gst_bin_get_by_name(
					GST_BIN(priv->confbin), name);
			g_free(name);
			g_object_set(volume, "volume", level/10.0, NULL);
		}
	}
#endif /* USE_VV */
}

void
purple_media_backend_fs2_set_output_volume(PurpleMediaBackendFs2 *self,
		const gchar *sess_id, const gchar *who, double level)
{
#ifdef USE_VV
	GList *streams;

	g_return_if_fail(PURPLE_IS_MEDIA_BACKEND_FS2(self));

	purple_prefs_set_int("/purple/media/audio/volume/output", level);

	streams = get_streams(self, sess_id, who);

	for (; streams; streams = g_list_delete_link(streams, streams)) {
		PurpleMediaBackendFs2Stream *stream = streams->data;

		if (stream->session->type & PURPLE_MEDIA_RECV_AUDIO
				&& GST_IS_ELEMENT(stream->volume)) {
			g_object_set(stream->volume, "volume",
					level/10.0, NULL);
		}
	}
#endif /* USE_VV */
}
#endif /* USE_GSTREAMER */
