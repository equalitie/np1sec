/**
 * @file media.c Media API
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

#include "account.h"
#include "media.h"
#include "media/backend-iface.h"
#include "mediamanager.h"

#include "debug.h"

#ifdef USE_GSTREAMER
#include "media/backend-fs2.h"
#include "marshallers.h"
#include "media-gst.h"
#endif

#ifdef USE_VV

/** @copydoc _PurpleMediaSession */
typedef struct _PurpleMediaSession PurpleMediaSession;
/** @copydoc _PurpleMediaStream */
typedef struct _PurpleMediaStream PurpleMediaStream;
/** @copydoc _PurpleMediaClass */
typedef struct _PurpleMediaClass PurpleMediaClass;
/** @copydoc _PurpleMediaPrivate */
typedef struct _PurpleMediaPrivate PurpleMediaPrivate;

/** The media class */
struct _PurpleMediaClass
{
	GObjectClass parent_class;     /**< The parent class. */
};

/** The media class's private data */
struct _PurpleMedia
{
	GObject parent;                /**< The parent of this object. */
	PurpleMediaPrivate *priv;      /**< The private data of this object. */
};

struct _PurpleMediaSession
{
	gchar *id;
	PurpleMedia *media;
	PurpleMediaSessionType type;
	gboolean initiator;
};

struct _PurpleMediaStream
{
	PurpleMediaSession *session;
	gchar *participant;

	GList *local_candidates;
	GList *remote_candidates;

	gboolean initiator;
	gboolean accepted;
	gboolean candidates_prepared;

	GList *active_local_candidates;
	GList *active_remote_candidates;
};
#endif

struct _PurpleMediaPrivate
{
#ifdef USE_VV
	PurpleMediaManager *manager;
	PurpleAccount *account;
	PurpleMediaBackend *backend;
	gchar *conference_type;
	gboolean initiator;
	gpointer prpl_data;

	GHashTable *sessions;	/* PurpleMediaSession table */
	GList *participants;
	GList *streams;		/* PurpleMediaStream table */
#else
	gpointer dummy;
#endif
};

#ifdef USE_VV
#define PURPLE_MEDIA_GET_PRIVATE(obj) (G_TYPE_INSTANCE_GET_PRIVATE((obj), PURPLE_TYPE_MEDIA, PurpleMediaPrivate))

static void purple_media_class_init (PurpleMediaClass *klass);
static void purple_media_init (PurpleMedia *media);
static void purple_media_dispose (GObject *object);
static void purple_media_finalize (GObject *object);
static void purple_media_get_property (GObject *object, guint prop_id, GValue *value, GParamSpec *pspec);
static void purple_media_set_property (GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec);

static void purple_media_new_local_candidate_cb(PurpleMediaBackend *backend,
		const gchar *sess_id, const gchar *participant,
		PurpleMediaCandidate *candidate, PurpleMedia *media);
static void purple_media_candidates_prepared_cb(PurpleMediaBackend *backend,
		const gchar *sess_id, const gchar *name, PurpleMedia *media);
static void purple_media_candidate_pair_established_cb(
		PurpleMediaBackend *backend,
		const gchar *sess_id, const gchar *name,
		PurpleMediaCandidate *local_candidate,
		PurpleMediaCandidate *remote_candidate,
		PurpleMedia *media);
static void purple_media_codecs_changed_cb(PurpleMediaBackend *backend,
		const gchar *sess_id, PurpleMedia *media);

static GObjectClass *parent_class = NULL;



enum {
	S_ERROR,
	CANDIDATES_PREPARED,
	CODECS_CHANGED,
	LEVEL,
	NEW_CANDIDATE,
	STATE_CHANGED,
	STREAM_INFO,
	LAST_SIGNAL
};
static guint purple_media_signals[LAST_SIGNAL] = {0};

enum {
	PROP_0,
	PROP_MANAGER,
	PROP_BACKEND,
	PROP_ACCOUNT,
	PROP_CONFERENCE_TYPE,
	PROP_INITIATOR,
	PROP_PRPL_DATA,
};
#endif


GType
purple_media_get_type()
{
#ifdef USE_VV
	static GType type = 0;

	if (type == 0) {
		static const GTypeInfo info = {
			sizeof(PurpleMediaClass),
			NULL,
			NULL,
			(GClassInitFunc) purple_media_class_init,
			NULL,
			NULL,
			sizeof(PurpleMedia),
			0,
			(GInstanceInitFunc) purple_media_init,
			NULL
		};
		type = g_type_register_static(G_TYPE_OBJECT, "PurpleMedia", &info, 0);
	}
	return type;
#else
	return G_TYPE_NONE;
#endif
}

#ifdef USE_VV
static void
purple_media_class_init (PurpleMediaClass *klass)
{
	GObjectClass *gobject_class = (GObjectClass*)klass;
	parent_class = g_type_class_peek_parent(klass);

	gobject_class->dispose = purple_media_dispose;
	gobject_class->finalize = purple_media_finalize;
	gobject_class->set_property = purple_media_set_property;
	gobject_class->get_property = purple_media_get_property;

	g_object_class_install_property(gobject_class, PROP_MANAGER,
			g_param_spec_object("manager",
			"Purple Media Manager",
			"The media manager that contains this media session.",
			PURPLE_TYPE_MEDIA_MANAGER,
			G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE));

	/*
	 * This one should be PURPLE_TYPE_MEDIA_BACKEND, but it doesn't
	 * like interfaces because they "aren't GObjects"
	 */
	g_object_class_install_property(gobject_class, PROP_BACKEND,
			g_param_spec_object("backend",
			"Purple Media Backend",
			"The backend object this media object uses.",
			G_TYPE_OBJECT,
			G_PARAM_READABLE));

	g_object_class_install_property(gobject_class, PROP_ACCOUNT,
			g_param_spec_pointer("account",
			"PurpleAccount",
			"The account this media session is on.",
			G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE));

	g_object_class_install_property(gobject_class, PROP_CONFERENCE_TYPE,
			g_param_spec_string("conference-type",
			"Conference Type",
			"The type of conference that this media object "
			"has been created to provide.",
			NULL,
			G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE));

	g_object_class_install_property(gobject_class, PROP_INITIATOR,
			g_param_spec_boolean("initiator",
			"initiator",
			"If the local user initiated the conference.",
			FALSE,
			G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE));

	g_object_class_install_property(gobject_class, PROP_PRPL_DATA,
			g_param_spec_pointer("prpl-data",
			"gpointer",
			"Data the prpl plugin set on the media session.",
			G_PARAM_READWRITE));

	purple_media_signals[S_ERROR] = g_signal_new("error", G_TYPE_FROM_CLASS(klass),
					 G_SIGNAL_RUN_LAST, 0, NULL, NULL,
					 g_cclosure_marshal_VOID__STRING,
					 G_TYPE_NONE, 1, G_TYPE_STRING);
	purple_media_signals[CANDIDATES_PREPARED] = g_signal_new("candidates-prepared", G_TYPE_FROM_CLASS(klass),
					 G_SIGNAL_RUN_LAST, 0, NULL, NULL,
					 purple_smarshal_VOID__STRING_STRING,
					 G_TYPE_NONE, 2, G_TYPE_STRING,
					 G_TYPE_STRING);
	purple_media_signals[CODECS_CHANGED] = g_signal_new("codecs-changed", G_TYPE_FROM_CLASS(klass),
					 G_SIGNAL_RUN_LAST, 0, NULL, NULL,
					 g_cclosure_marshal_VOID__STRING,
					 G_TYPE_NONE, 1, G_TYPE_STRING);
	purple_media_signals[LEVEL] = g_signal_new("level", G_TYPE_FROM_CLASS(klass),
					 G_SIGNAL_RUN_LAST, 0, NULL, NULL,
					 purple_smarshal_VOID__STRING_STRING_DOUBLE,
					 G_TYPE_NONE, 3, G_TYPE_STRING,
					 G_TYPE_STRING, G_TYPE_DOUBLE);
	purple_media_signals[NEW_CANDIDATE] = g_signal_new("new-candidate", G_TYPE_FROM_CLASS(klass),
					 G_SIGNAL_RUN_LAST, 0, NULL, NULL,
					 purple_smarshal_VOID__POINTER_POINTER_OBJECT,
					 G_TYPE_NONE, 3, G_TYPE_POINTER,
					 G_TYPE_POINTER, PURPLE_TYPE_MEDIA_CANDIDATE);
	purple_media_signals[STATE_CHANGED] = g_signal_new("state-changed", G_TYPE_FROM_CLASS(klass),
					 G_SIGNAL_RUN_LAST, 0, NULL, NULL,
					 purple_smarshal_VOID__ENUM_STRING_STRING,
					 G_TYPE_NONE, 3, PURPLE_MEDIA_TYPE_STATE,
					 G_TYPE_STRING, G_TYPE_STRING);
	purple_media_signals[STREAM_INFO] = g_signal_new("stream-info", G_TYPE_FROM_CLASS(klass),
					 G_SIGNAL_RUN_LAST, 0, NULL, NULL,
					 purple_smarshal_VOID__ENUM_STRING_STRING_BOOLEAN,
					 G_TYPE_NONE, 4, PURPLE_MEDIA_TYPE_INFO_TYPE,
					 G_TYPE_STRING, G_TYPE_STRING, G_TYPE_BOOLEAN);
	g_type_class_add_private(klass, sizeof(PurpleMediaPrivate));
}


static void
purple_media_init (PurpleMedia *media)
{
	media->priv = PURPLE_MEDIA_GET_PRIVATE(media);
	memset(media->priv, 0, sizeof(*media->priv));
}

static void
purple_media_stream_free(PurpleMediaStream *stream)
{
	if (stream == NULL)
		return;

	g_free(stream->participant);

	if (stream->local_candidates)
		purple_media_candidate_list_free(stream->local_candidates);
	if (stream->remote_candidates)
		purple_media_candidate_list_free(stream->remote_candidates);

	if (stream->active_local_candidates)
		purple_media_candidate_list_free(
				stream->active_local_candidates);
	if (stream->active_remote_candidates)
		purple_media_candidate_list_free(
				stream->active_remote_candidates);

	g_free(stream);
}

static void
purple_media_session_free(PurpleMediaSession *session)
{
	if (session == NULL)
		return;

	g_free(session->id);
	g_free(session);
}

static void
purple_media_dispose(GObject *media)
{
	PurpleMediaPrivate *priv = PURPLE_MEDIA_GET_PRIVATE(media);

	purple_debug_info("media","purple_media_dispose\n");

	purple_media_manager_remove_media(priv->manager, PURPLE_MEDIA(media));

	if (priv->backend) {
		g_object_unref(priv->backend);
		priv->backend = NULL;
	}

	if (priv->manager) {
		g_object_unref(priv->manager);
		priv->manager = NULL;
	}

	G_OBJECT_CLASS(parent_class)->dispose(media);
}

static void
purple_media_finalize(GObject *media)
{
	PurpleMediaPrivate *priv = PURPLE_MEDIA_GET_PRIVATE(media);
	purple_debug_info("media","purple_media_finalize\n");

	for (; priv->streams; priv->streams = g_list_delete_link(priv->streams, priv->streams))
		purple_media_stream_free(priv->streams->data);

	for (; priv->participants; priv->participants = g_list_delete_link(
			priv->participants, priv->participants))
		g_free(priv->participants->data);

	if (priv->sessions) {
		GList *sessions = g_hash_table_get_values(priv->sessions);
		for (; sessions; sessions = g_list_delete_link(sessions, sessions)) {
			purple_media_session_free(sessions->data);
		}
		g_hash_table_destroy(priv->sessions);
	}

	G_OBJECT_CLASS(parent_class)->finalize(media);
}

static void
purple_media_set_property (GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec)
{
	PurpleMedia *media;
	g_return_if_fail(PURPLE_IS_MEDIA(object));

	media = PURPLE_MEDIA(object);

	switch (prop_id) {
		case PROP_MANAGER:
			media->priv->manager = g_value_dup_object(value);
			break;
		case PROP_ACCOUNT:
			media->priv->account = g_value_get_pointer(value);
			break;
		case PROP_CONFERENCE_TYPE:
			media->priv->conference_type =
					g_value_dup_string(value);
			media->priv->backend = g_object_new(
					purple_media_manager_get_backend_type(
					purple_media_manager_get()),
					"conference-type",
					media->priv->conference_type,
					"media", media,
					NULL);
			g_signal_connect(media->priv->backend,
					"active-candidate-pair",
					G_CALLBACK(
					purple_media_candidate_pair_established_cb),
					media);
			g_signal_connect(media->priv->backend,
					"candidates-prepared",
					G_CALLBACK(
					purple_media_candidates_prepared_cb),
					media);
			g_signal_connect(media->priv->backend,
					"codecs-changed",
					G_CALLBACK(
					purple_media_codecs_changed_cb),
					media);
			g_signal_connect(media->priv->backend,
					"new-candidate",
					G_CALLBACK(
					purple_media_new_local_candidate_cb),
					media);
			break;
		case PROP_INITIATOR:
			media->priv->initiator = g_value_get_boolean(value);
			break;
		case PROP_PRPL_DATA:
			media->priv->prpl_data = g_value_get_pointer(value);
			break;
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
			break;
	}
}

static void
purple_media_get_property (GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
	PurpleMedia *media;
	g_return_if_fail(PURPLE_IS_MEDIA(object));

	media = PURPLE_MEDIA(object);

	switch (prop_id) {
		case PROP_MANAGER:
			g_value_set_object(value, media->priv->manager);
			break;
		case PROP_BACKEND:
			g_value_set_object(value, media->priv->backend);
			break;
		case PROP_ACCOUNT:
			g_value_set_pointer(value, media->priv->account);
			break;
		case PROP_CONFERENCE_TYPE:
			g_value_set_string(value,
					media->priv->conference_type);
			break;
		case PROP_INITIATOR:
			g_value_set_boolean(value, media->priv->initiator);
			break;
		case PROP_PRPL_DATA:
			g_value_set_pointer(value, media->priv->prpl_data);
			break;
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
			break;
	}

}

static PurpleMediaSession*
purple_media_get_session(PurpleMedia *media, const gchar *sess_id)
{
	g_return_val_if_fail(PURPLE_IS_MEDIA(media), NULL);
	return (PurpleMediaSession*) (media->priv->sessions) ?
			g_hash_table_lookup(media->priv->sessions, sess_id) : NULL;
}

static PurpleMediaStream*
purple_media_get_stream(PurpleMedia *media, const gchar *session, const gchar *participant)
{
	GList *streams;

	g_return_val_if_fail(PURPLE_IS_MEDIA(media), NULL);

	streams = media->priv->streams;

	for (; streams; streams = g_list_next(streams)) {
		PurpleMediaStream *stream = streams->data;
		if (!strcmp(stream->session->id, session) &&
				!strcmp(stream->participant, participant))
			return stream;
	}

	return NULL;
}

static GList *
purple_media_get_streams(PurpleMedia *media, const gchar *session,
		const gchar *participant)
{
	GList *streams;
	GList *ret = NULL;

	g_return_val_if_fail(PURPLE_IS_MEDIA(media), NULL);

	streams = media->priv->streams;

	for (; streams; streams = g_list_next(streams)) {
		PurpleMediaStream *stream = streams->data;
		if ((session == NULL ||
				!strcmp(stream->session->id, session)) &&
				(participant == NULL ||
				!strcmp(stream->participant, participant)))
			ret = g_list_append(ret, stream);
	}

	return ret;
}

static void
purple_media_add_session(PurpleMedia *media, PurpleMediaSession *session)
{
	g_return_if_fail(PURPLE_IS_MEDIA(media));
	g_return_if_fail(session != NULL);

	if (!media->priv->sessions) {
		purple_debug_info("media", "Creating hash table for sessions\n");
		media->priv->sessions = g_hash_table_new_full(g_str_hash, g_str_equal,
		                                              g_free, NULL);
	}
	g_hash_table_insert(media->priv->sessions, g_strdup(session->id), session);
}

#if 0
static gboolean
purple_media_remove_session(PurpleMedia *media, PurpleMediaSession *session)
{
	g_return_val_if_fail(PURPLE_IS_MEDIA(media), FALSE);
	return g_hash_table_remove(media->priv->sessions, session->id);
}
#endif

static PurpleMediaStream *
purple_media_insert_stream(PurpleMediaSession *session,
		const gchar *name, gboolean initiator)
{
	PurpleMediaStream *media_stream;

	g_return_val_if_fail(session != NULL, NULL);

	media_stream = g_new0(PurpleMediaStream, 1);
	media_stream->participant = g_strdup(name);
	media_stream->session = session;
	media_stream->initiator = initiator;

	session->media->priv->streams =
			g_list_append(session->media->priv->streams, media_stream);

	return media_stream;
}

static void
purple_media_insert_local_candidate(PurpleMediaSession *session, const gchar *name,
				     PurpleMediaCandidate *candidate)
{
	PurpleMediaStream *stream;

	g_return_if_fail(session != NULL);

	stream = purple_media_get_stream(session->media, session->id, name);
	stream->local_candidates = g_list_append(stream->local_candidates, candidate);
}
#endif

GList *
purple_media_get_session_ids(PurpleMedia *media)
{
#ifdef USE_VV
	g_return_val_if_fail(PURPLE_IS_MEDIA(media), NULL);
	return media->priv->sessions != NULL ?
			g_hash_table_get_keys(media->priv->sessions) : NULL;
#else
	return NULL;
#endif
}

#ifdef USE_GSTREAMER
GstElement *
purple_media_get_src(PurpleMedia *media, const gchar *sess_id)
{
#ifdef USE_VV
	g_return_val_if_fail(PURPLE_IS_MEDIA(media), NULL);

	if (PURPLE_IS_MEDIA_BACKEND_FS2(media->priv->backend))
		return purple_media_backend_fs2_get_src(
				PURPLE_MEDIA_BACKEND_FS2(
				media->priv->backend), sess_id);

	g_return_val_if_reached(NULL);
#else
	return NULL;
#endif
}
#endif /* USE_GSTREAMER */

PurpleAccount *
purple_media_get_account(PurpleMedia *media)
{
#ifdef USE_VV
	PurpleAccount *account;
	g_return_val_if_fail(PURPLE_IS_MEDIA(media), NULL);
	g_object_get(G_OBJECT(media), "account", &account, NULL);
	return account;
#else
	return NULL;
#endif
}

gpointer
purple_media_get_prpl_data(PurpleMedia *media)
{
#ifdef USE_VV
	gpointer prpl_data;
	g_return_val_if_fail(PURPLE_IS_MEDIA(media), NULL);
	g_object_get(G_OBJECT(media), "prpl-data", &prpl_data, NULL);
	return prpl_data;
#else
	return NULL;
#endif
}

void
purple_media_set_prpl_data(PurpleMedia *media, gpointer prpl_data)
{
#ifdef USE_VV
	g_return_if_fail(PURPLE_IS_MEDIA(media));
	g_object_set(G_OBJECT(media), "prpl-data", prpl_data, NULL);
#endif
}

void
purple_media_error(PurpleMedia *media, const gchar *error, ...)
{
#ifdef USE_VV
	va_list args;
	gchar *message;

	g_return_if_fail(PURPLE_IS_MEDIA(media));

	va_start(args, error);
	message = g_strdup_vprintf(error, args);
	va_end(args);

	purple_debug_error("media", "%s\n", message);
	g_signal_emit(media, purple_media_signals[S_ERROR], 0, message);

	g_free(message);
#endif
}

void
purple_media_end(PurpleMedia *media,
		const gchar *session_id, const gchar *participant)
{
#ifdef USE_VV
	GList *iter, *sessions = NULL, *participants = NULL;

	g_return_if_fail(PURPLE_IS_MEDIA(media));

	iter = purple_media_get_streams(media, session_id, participant);

	/* Free matching streams */
	for (; iter; iter = g_list_delete_link(iter, iter)) {
		PurpleMediaStream *stream = iter->data;

		g_signal_emit(media, purple_media_signals[STATE_CHANGED],
				0, PURPLE_MEDIA_STATE_END,
				stream->session->id, stream->participant);

		media->priv->streams =
				g_list_remove(media->priv->streams, stream);

		if (g_list_find(sessions, stream->session) == NULL)
			sessions = g_list_prepend(sessions, stream->session);

		if (g_list_find_custom(participants, stream->participant,
				(GCompareFunc)strcmp) == NULL)
			participants = g_list_prepend(participants,
					g_strdup(stream->participant));

		purple_media_stream_free(stream);
	}

	iter = media->priv->streams;

	/* Reduce to list of sessions to remove */
	for (; iter; iter = g_list_next(iter)) {
		PurpleMediaStream *stream = iter->data;

		sessions = g_list_remove(sessions, stream->session);
	}

	/* Free sessions with no streams left */
	for (; sessions; sessions = g_list_delete_link(sessions, sessions)) {
		PurpleMediaSession *session = sessions->data;

		g_signal_emit(media, purple_media_signals[STATE_CHANGED],
				0, PURPLE_MEDIA_STATE_END,
				session->id, NULL);

		g_hash_table_remove(media->priv->sessions, session->id);
		purple_media_session_free(session);
	}

	iter = media->priv->streams;

	/* Reduce to list of participants to remove */
	for (; iter; iter = g_list_next(iter)) {
		PurpleMediaStream *stream = iter->data;
		GList *tmp;

		tmp = g_list_find_custom(participants,
				stream->participant, (GCompareFunc)strcmp);

		if (tmp != NULL) {
			g_free(tmp->data);
			participants = g_list_delete_link(participants,	tmp);
		}
	}

	/* Remove participants with no streams left (just emit the signal) */
	for (; participants; participants =
			g_list_delete_link(participants, participants)) {
		gchar *participant = participants->data;
		GList *link = g_list_find_custom(media->priv->participants,
				participant, (GCompareFunc)strcmp);

		g_signal_emit(media, purple_media_signals[STATE_CHANGED],
				0, PURPLE_MEDIA_STATE_END,
				NULL, participant);

		if (link != NULL) {
			g_free(link->data);
			media->priv->participants = g_list_delete_link(
					media->priv->participants, link);
		}

		g_free(participant);
	}

	/* Free the conference if no sessions left */
	if (media->priv->sessions != NULL &&
			g_hash_table_size(media->priv->sessions) == 0) {
		g_signal_emit(media, purple_media_signals[STATE_CHANGED],
				0, PURPLE_MEDIA_STATE_END,
				NULL, NULL);
		g_object_unref(media);
		return;
	}
#endif
}

void
purple_media_stream_info(PurpleMedia *media, PurpleMediaInfoType type,
		const gchar *session_id, const gchar *participant,
		gboolean local)
{
#ifdef USE_VV
	g_return_if_fail(PURPLE_IS_MEDIA(media));

	if (type == PURPLE_MEDIA_INFO_ACCEPT) {
		GList *streams, *sessions = NULL, *participants = NULL;

		g_return_if_fail(PURPLE_IS_MEDIA(media));

		streams = purple_media_get_streams(media,
				session_id, participant);

		/* Emit stream acceptance */
		for (; streams; streams =
				g_list_delete_link(streams, streams)) {
			PurpleMediaStream *stream = streams->data;

			stream->accepted = TRUE;

			g_signal_emit(media,
					purple_media_signals[STREAM_INFO],
					0, type, stream->session->id,
					stream->participant, local);

			if (g_list_find(sessions, stream->session) == NULL)
				sessions = g_list_prepend(sessions,
						stream->session);

			if (g_list_find_custom(participants,
					stream->participant,
					(GCompareFunc)strcmp) == NULL)
				participants = g_list_prepend(participants,
						g_strdup(stream->participant));
		}

		/* Emit session acceptance */
		for (; sessions; sessions =
				g_list_delete_link(sessions, sessions)) {
			PurpleMediaSession *session = sessions->data;

			if (purple_media_accepted(media, session->id, NULL))
				g_signal_emit(media, purple_media_signals[
						STREAM_INFO], 0,
						PURPLE_MEDIA_INFO_ACCEPT,
						session->id, NULL, local);
		}

		/* Emit participant acceptance */
		for (; participants; participants = g_list_delete_link(
				participants, participants)) {
			gchar *participant = participants->data;

			if (purple_media_accepted(media, NULL, participant))
				g_signal_emit(media, purple_media_signals[
						STREAM_INFO], 0,
						PURPLE_MEDIA_INFO_ACCEPT,
						NULL, participant, local);

			g_free(participant);
		}

		/* Emit conference acceptance */
		if (purple_media_accepted(media, NULL, NULL))
			g_signal_emit(media,
					purple_media_signals[STREAM_INFO],
					0, PURPLE_MEDIA_INFO_ACCEPT,
					NULL, NULL, local);

		return;
	} else if (type == PURPLE_MEDIA_INFO_HANGUP ||
			type == PURPLE_MEDIA_INFO_REJECT) {
		GList *streams;

		g_return_if_fail(PURPLE_IS_MEDIA(media));

		streams = purple_media_get_streams(media,
				session_id, participant);

		/* Emit for stream */
		for (; streams; streams =
				g_list_delete_link(streams, streams)) {
			PurpleMediaStream *stream = streams->data;

			g_signal_emit(media,
					purple_media_signals[STREAM_INFO],
					0, type, stream->session->id,
					stream->participant, local);
		}

		if (session_id != NULL && participant != NULL) {
			/* Everything that needs to be emitted has been */
		} else if (session_id == NULL && participant == NULL) {
			/* Emit for everything in the conference */
			GList *sessions = NULL;
			GList *participants = media->priv->participants;

			if (media->priv->sessions != NULL)
				sessions = g_hash_table_get_values(
					media->priv->sessions);

			/* Emit for sessions */
			for (; sessions; sessions = g_list_delete_link(
					sessions, sessions)) {
				PurpleMediaSession *session = sessions->data;

				g_signal_emit(media, purple_media_signals[
						STREAM_INFO], 0, type,
						session->id, NULL, local);
			}

			/* Emit for participants */
			for (; participants; participants =
					g_list_next(participants)) {
				gchar *participant = participants->data;

				g_signal_emit(media, purple_media_signals[
						STREAM_INFO], 0, type,
						NULL, participant, local);
			}

			/* Emit for conference */
			g_signal_emit(media,
					purple_media_signals[STREAM_INFO],
					0, type, NULL, NULL, local);
		} else if (session_id != NULL) {
			/* Emit just the specific session */
			PurpleMediaSession *session =
					purple_media_get_session(
					media, session_id);

			if (session == NULL) {
				purple_debug_warning("media",
						"Couldn't find session"
						" to hangup/reject.\n");
			} else {
				g_signal_emit(media, purple_media_signals[
						STREAM_INFO], 0, type,
						session->id, NULL, local);
			}
		} else if (participant != NULL) {
			/* Emit just the specific participant */
			if (!g_list_find_custom(media->priv->participants,
					participant, (GCompareFunc)strcmp)) {
				purple_debug_warning("media",
						"Couldn't find participant"
						" to hangup/reject.\n");
			} else {
				g_signal_emit(media, purple_media_signals[
						STREAM_INFO], 0, type, NULL,
						participant, local);
			}
		}

		purple_media_end(media, session_id, participant);
		return;
	}

	g_signal_emit(media, purple_media_signals[STREAM_INFO],
			0, type, session_id, participant, local);
#endif
}

void
purple_media_set_params(PurpleMedia *media,
		guint num_params, GParameter *params)
{
#ifdef USE_VV
	g_return_if_fail(PURPLE_IS_MEDIA(media));

	purple_media_backend_set_params(media->priv->backend, num_params, params);
#endif
}

const gchar **
purple_media_get_available_params(PurpleMedia *media)
{
	static const gchar *NULL_ARRAY[] = { NULL };
#ifdef USE_VV
	g_return_val_if_fail(PURPLE_IS_MEDIA(media), NULL_ARRAY);

	return purple_media_backend_get_available_params(media->priv->backend);
#else
	return NULL_ARRAY;
#endif
}

gboolean
purple_media_param_is_supported(PurpleMedia *media, const gchar *param)
{
#ifdef USE_VV
	const gchar **params;

	g_return_val_if_fail(PURPLE_IS_MEDIA(media), FALSE);
	g_return_val_if_fail(param != NULL, FALSE);

	params = purple_media_backend_get_available_params(media->priv->backend);
	for (; *params != NULL; ++params)
		if (!strcmp(*params, param))
			return TRUE;
#endif
	return FALSE;
}

#ifdef USE_VV
static void
purple_media_new_local_candidate_cb(PurpleMediaBackend *backend,
		const gchar *sess_id, const gchar *participant,
		PurpleMediaCandidate *candidate, PurpleMedia *media)
{
	PurpleMediaSession *session =
			purple_media_get_session(media, sess_id);

	purple_media_insert_local_candidate(session, participant,
			purple_media_candidate_copy(candidate));

	g_signal_emit(session->media, purple_media_signals[NEW_CANDIDATE],
		      0, session->id, participant, candidate);
}

static void
purple_media_candidates_prepared_cb(PurpleMediaBackend *backend,
		const gchar *sess_id, const gchar *name, PurpleMedia *media)
{
	PurpleMediaStream *stream_data;

	g_return_if_fail(PURPLE_IS_MEDIA(media));

	stream_data = purple_media_get_stream(media, sess_id, name);
	stream_data->candidates_prepared = TRUE;

	g_signal_emit(media, purple_media_signals[CANDIDATES_PREPARED],
			0, sess_id, name);
}

/* callback called when a pair of transport candidates (local and remote)
 * has been established */
static void
purple_media_candidate_pair_established_cb(PurpleMediaBackend *backend,
		const gchar *sess_id, const gchar *name,
		PurpleMediaCandidate *local_candidate,
		PurpleMediaCandidate *remote_candidate,
		PurpleMedia *media)
{
	PurpleMediaStream *stream;
	GList *iter;
	guint id;

	g_return_if_fail(PURPLE_IS_MEDIA(media));

	stream = purple_media_get_stream(media, sess_id, name);
	id = purple_media_candidate_get_component_id(local_candidate);

	iter = stream->active_local_candidates;
	for(; iter; iter = g_list_next(iter)) {
		PurpleMediaCandidate *c = iter->data;
		if (id == purple_media_candidate_get_component_id(c)) {
			g_object_unref(c);
			stream->active_local_candidates =
					g_list_delete_link(iter, iter);
			stream->active_local_candidates = g_list_prepend(
					stream->active_local_candidates,
					purple_media_candidate_copy(
					local_candidate));
			break;
		}
	}
	if (iter == NULL)
		stream->active_local_candidates = g_list_prepend(
				stream->active_local_candidates,
				purple_media_candidate_copy(
				local_candidate));

	id = purple_media_candidate_get_component_id(local_candidate);

	iter = stream->active_remote_candidates;
	for(; iter; iter = g_list_next(iter)) {
		PurpleMediaCandidate *c = iter->data;
		if (id == purple_media_candidate_get_component_id(c)) {
			g_object_unref(c);
			stream->active_remote_candidates =
					g_list_delete_link(iter, iter);
			stream->active_remote_candidates = g_list_prepend(
					stream->active_remote_candidates,
					purple_media_candidate_copy(
					remote_candidate));
			break;
		}
	}
	if (iter == NULL)
		stream->active_remote_candidates = g_list_prepend(
				stream->active_remote_candidates,
				purple_media_candidate_copy(
				remote_candidate));

	purple_debug_info("media", "candidate pair established\n");
}

static void
purple_media_codecs_changed_cb(PurpleMediaBackend *backend,
		const gchar *sess_id, PurpleMedia *media)
{
	g_signal_emit(media, purple_media_signals[CODECS_CHANGED], 0, sess_id);
}
#endif  /* USE_VV */

gboolean
purple_media_add_stream(PurpleMedia *media, const gchar *sess_id,
		const gchar *who, PurpleMediaSessionType type,
		gboolean initiator, const gchar *transmitter,
		guint num_params, GParameter *params)
{
#ifdef USE_VV
	PurpleMediaSession *session;

	g_return_val_if_fail(PURPLE_IS_MEDIA(media), FALSE);

	if (!purple_media_backend_add_stream(media->priv->backend,
			sess_id, who, type, initiator, transmitter,
			num_params, params)) {
		purple_debug_error("media", "Error adding stream.\n");
		return FALSE;
	}

	session = purple_media_get_session(media, sess_id);

	if (!session) {
		session = g_new0(PurpleMediaSession, 1);
		session->id = g_strdup(sess_id);
		session->media = media;
		session->type = type;
		session->initiator = initiator;

		purple_media_add_session(media, session);
		g_signal_emit(media, purple_media_signals[STATE_CHANGED],
				0, PURPLE_MEDIA_STATE_NEW,
				session->id, NULL);
	}

	if (!g_list_find_custom(media->priv->participants,
			who, (GCompareFunc)strcmp)) {
		media->priv->participants = g_list_prepend(
				media->priv->participants, g_strdup(who));

		g_signal_emit_by_name(media, "state-changed",
				PURPLE_MEDIA_STATE_NEW, NULL, who);
	}

	if (purple_media_get_stream(media, sess_id, who) == NULL) {
		purple_media_insert_stream(session, who, initiator);

		g_signal_emit(media, purple_media_signals[STATE_CHANGED],
				0, PURPLE_MEDIA_STATE_NEW,
				session->id, who);
	}

	return TRUE;
#else
	return FALSE;
#endif  /* USE_VV */
}

PurpleMediaManager *
purple_media_get_manager(PurpleMedia *media)
{
	PurpleMediaManager *ret;
	g_return_val_if_fail(PURPLE_IS_MEDIA(media), NULL);
	g_object_get(media, "manager", &ret, NULL);
	return ret;
}

PurpleMediaSessionType
purple_media_get_session_type(PurpleMedia *media, const gchar *sess_id)
{
#ifdef USE_VV
	PurpleMediaSession *session;
	g_return_val_if_fail(PURPLE_IS_MEDIA(media), PURPLE_MEDIA_NONE);
	session = purple_media_get_session(media, sess_id);
	return session->type;
#else
	return PURPLE_MEDIA_NONE;
#endif
}
/* XXX: Should wait until codecs-ready is TRUE before using this function */
GList *
purple_media_get_codecs(PurpleMedia *media, const gchar *sess_id)
{
#ifdef USE_VV
	g_return_val_if_fail(PURPLE_IS_MEDIA(media), NULL);

	return purple_media_backend_get_codecs(media->priv->backend, sess_id);
#else
	return NULL;
#endif
}

GList *
purple_media_get_local_candidates(PurpleMedia *media, const gchar *sess_id,
                                  const gchar *participant)
{
#ifdef USE_VV
	g_return_val_if_fail(PURPLE_IS_MEDIA(media), NULL);

	return purple_media_backend_get_local_candidates(media->priv->backend,
			sess_id, participant);
#else
	return NULL;
#endif
}

void
purple_media_add_remote_candidates(PurpleMedia *media, const gchar *sess_id,
                                   const gchar *participant,
                                   GList *remote_candidates)
{
#ifdef USE_VV
	PurpleMediaStream *stream;

	g_return_if_fail(PURPLE_IS_MEDIA(media));
	stream = purple_media_get_stream(media, sess_id, participant);

	if (stream == NULL) {
		purple_debug_error("media",
				"purple_media_add_remote_candidates: "
				"couldn't find stream %s %s.\n",
				sess_id ? sess_id : "(null)",
				participant ? participant : "(null)");
		return;
	}

	stream->remote_candidates = g_list_concat(stream->remote_candidates,
			purple_media_candidate_list_copy(remote_candidates));

	purple_media_backend_add_remote_candidates(media->priv->backend,
			sess_id, participant, remote_candidates);
#endif
}

GList *
purple_media_get_active_local_candidates(PurpleMedia *media,
		const gchar *sess_id, const gchar *participant)
{
#ifdef USE_VV
	PurpleMediaStream *stream;
	g_return_val_if_fail(PURPLE_IS_MEDIA(media), NULL);
	stream = purple_media_get_stream(media, sess_id, participant);
	return purple_media_candidate_list_copy(
			stream->active_local_candidates);
#else
	return NULL;
#endif
}

GList *
purple_media_get_active_remote_candidates(PurpleMedia *media,
		const gchar *sess_id, const gchar *participant)
{
#ifdef USE_VV
	PurpleMediaStream *stream;
	g_return_val_if_fail(PURPLE_IS_MEDIA(media), NULL);
	stream = purple_media_get_stream(media, sess_id, participant);
	return purple_media_candidate_list_copy(
			stream->active_remote_candidates);
#else
	return NULL;
#endif
}

gboolean
purple_media_set_remote_codecs(PurpleMedia *media, const gchar *sess_id,
                               const gchar *participant, GList *codecs)
{
#ifdef USE_VV
	g_return_val_if_fail(PURPLE_IS_MEDIA(media), FALSE);

	return purple_media_backend_set_remote_codecs(media->priv->backend,
			sess_id, participant, codecs);
#else
	return FALSE;
#endif
}

gboolean
purple_media_candidates_prepared(PurpleMedia *media,
		const gchar *session_id, const gchar *participant)
{
#ifdef USE_VV
	GList *streams;
	gboolean prepared = TRUE;

	g_return_val_if_fail(PURPLE_IS_MEDIA(media), FALSE);

	streams = purple_media_get_streams(media, session_id, participant);

	for (; streams; streams = g_list_delete_link(streams, streams)) {
		PurpleMediaStream *stream = streams->data;
		if (stream->candidates_prepared == FALSE) {
			g_list_free(streams);
			prepared = FALSE;
			break;
		}
	}

	return prepared;
#else
	return FALSE;
#endif
}

gboolean
purple_media_set_send_codec(PurpleMedia *media, const gchar *sess_id, PurpleMediaCodec *codec)
{
#ifdef USE_VV
	g_return_val_if_fail(PURPLE_IS_MEDIA(media), FALSE);

	return purple_media_backend_set_send_codec(
			media->priv->backend, sess_id, codec);
#else
	return FALSE;
#endif
}

gboolean
purple_media_codecs_ready(PurpleMedia *media, const gchar *sess_id)
{
#ifdef USE_VV
	g_return_val_if_fail(PURPLE_IS_MEDIA(media), FALSE);

	return purple_media_backend_codecs_ready(
			media->priv->backend, sess_id);
#else
	return FALSE;
#endif
}

gboolean
purple_media_is_initiator(PurpleMedia *media,
		const gchar *sess_id, const gchar *participant)
{
#ifdef USE_VV
	g_return_val_if_fail(PURPLE_IS_MEDIA(media), FALSE);

	if (sess_id == NULL && participant == NULL)
		return media->priv->initiator;
	else if (sess_id != NULL && participant == NULL) {
		PurpleMediaSession *session =
				purple_media_get_session(media, sess_id);
		return session != NULL ? session->initiator : FALSE;
	} else if (sess_id != NULL && participant != NULL) {
		PurpleMediaStream *stream = purple_media_get_stream(
				media, sess_id, participant);
		return stream != NULL ? stream->initiator : FALSE;
	}
#endif
	return FALSE;
}

gboolean
purple_media_accepted(PurpleMedia *media, const gchar *sess_id,
		const gchar *participant)
{
#ifdef USE_VV
	gboolean accepted = TRUE;

	g_return_val_if_fail(PURPLE_IS_MEDIA(media), FALSE);

	if (sess_id == NULL && participant == NULL) {
		GList *streams = media->priv->streams;

		for (; streams; streams = g_list_next(streams)) {
			PurpleMediaStream *stream = streams->data;
			if (stream->accepted == FALSE) {
				accepted = FALSE;
				break;
			}
		}
	} else if (sess_id != NULL && participant == NULL) {
		GList *streams = purple_media_get_streams(
				media, sess_id, NULL);
		for (; streams; streams =
				g_list_delete_link(streams, streams)) {
			PurpleMediaStream *stream = streams->data;
			if (stream->accepted == FALSE) {
				g_list_free(streams);
				accepted = FALSE;
				break;
			}
		}
	} else if (sess_id != NULL && participant != NULL) {
		PurpleMediaStream *stream = purple_media_get_stream(
				media, sess_id, participant);
		if (stream == NULL || stream->accepted == FALSE)
			accepted = FALSE;
	}

	return accepted;
#else
	return FALSE;
#endif
}

void purple_media_set_input_volume(PurpleMedia *media,
		const gchar *session_id, double level)
{
#ifdef USE_VV
	g_return_if_fail(PURPLE_IS_MEDIA(media));
	g_return_if_fail(PURPLE_IS_MEDIA_BACKEND_FS2(media->priv->backend));

	purple_media_backend_fs2_set_input_volume(
			PURPLE_MEDIA_BACKEND_FS2(
			media->priv->backend),
			session_id, level);
#endif
}

void purple_media_set_output_volume(PurpleMedia *media,
		const gchar *session_id, const gchar *participant,
		double level)
{
#ifdef USE_VV
	g_return_if_fail(PURPLE_IS_MEDIA(media));
	g_return_if_fail(PURPLE_IS_MEDIA_BACKEND_FS2(media->priv->backend));

	purple_media_backend_fs2_set_output_volume(
			PURPLE_MEDIA_BACKEND_FS2(
			media->priv->backend),
			session_id, participant, level);
#endif
}

gulong
purple_media_set_output_window(PurpleMedia *media, const gchar *session_id,
		const gchar *participant, gulong window_id)
{
#ifdef USE_VV
	g_return_val_if_fail(PURPLE_IS_MEDIA(media), FALSE);

	return purple_media_manager_set_output_window(media->priv->manager,
			media, session_id, participant, window_id);
#else
	return 0;
#endif
}

void
purple_media_remove_output_windows(PurpleMedia *media)
{
#ifdef USE_VV
	GList *iter = media->priv->streams;
	for (; iter; iter = g_list_next(iter)) {
		PurpleMediaStream *stream = iter->data;
		purple_media_manager_remove_output_windows(
				media->priv->manager, media,
				stream->session->id, stream->participant);
	}

	iter = purple_media_get_session_ids(media);
	for (; iter; iter = g_list_delete_link(iter, iter)) {
		gchar *session_name = iter->data;
		purple_media_manager_remove_output_windows(
				media->priv->manager, media,
				session_name, NULL);
	}
#endif
}

#ifdef USE_GSTREAMER
GstElement *
purple_media_get_tee(PurpleMedia *media,
		const gchar *session_id, const gchar *participant)
{
#ifdef USE_VV
	g_return_val_if_fail(PURPLE_IS_MEDIA(media), NULL);

	if (PURPLE_IS_MEDIA_BACKEND_FS2(media->priv->backend))
		return purple_media_backend_fs2_get_tee(
				PURPLE_MEDIA_BACKEND_FS2(
				media->priv->backend),
				session_id, participant);
	g_return_val_if_reached(NULL);
#else
	return NULL;
#endif
}
#endif /* USE_GSTREAMER */

