/**
 * @file rtp.c
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

#include "config.h"

#ifdef USE_VV

#include "jabber.h"
#include "jingle.h"
#include "media.h"
#include "mediamanager.h"
#include "iceudp.h"
#include "rawudp.h"
#include "rtp.h"
#include "session.h"
#include "debug.h"

#include <string.h>

struct _JingleRtpPrivate
{
	gchar *media_type;
	gchar *ssrc;
};

#define JINGLE_RTP_GET_PRIVATE(obj) (G_TYPE_INSTANCE_GET_PRIVATE((obj), JINGLE_TYPE_RTP, JingleRtpPrivate))

static void jingle_rtp_class_init (JingleRtpClass *klass);
static void jingle_rtp_init (JingleRtp *rtp);
static void jingle_rtp_finalize (GObject *object);
static void jingle_rtp_get_property (GObject *object, guint prop_id, GValue *value, GParamSpec *pspec);
static void jingle_rtp_set_property (GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec);
static JingleContent *jingle_rtp_parse_internal(xmlnode *rtp);
static xmlnode *jingle_rtp_to_xml_internal(JingleContent *rtp, xmlnode *content, JingleActionType action);
static void jingle_rtp_handle_action_internal(JingleContent *content, xmlnode *jingle, JingleActionType action);

static PurpleMedia *jingle_rtp_get_media(JingleSession *session);

static JingleContentClass *parent_class = NULL;
#if 0
enum {
	LAST_SIGNAL
};
static guint jingle_rtp_signals[LAST_SIGNAL] = {0};
#endif

enum {
	PROP_0,
	PROP_MEDIA_TYPE,
	PROP_SSRC,
};

GType
jingle_rtp_get_type()
{
	static GType type = 0;

	if (type == 0) {
		static const GTypeInfo info = {
			sizeof(JingleRtpClass),
			NULL,
			NULL,
			(GClassInitFunc) jingle_rtp_class_init,
			NULL,
			NULL,
			sizeof(JingleRtp),
			0,
			(GInstanceInitFunc) jingle_rtp_init,
			NULL
		};
		type = g_type_register_static(JINGLE_TYPE_CONTENT, "JingleRtp", &info, 0);
	}
	return type;
}

static void
jingle_rtp_class_init (JingleRtpClass *klass)
{
	GObjectClass *gobject_class = (GObjectClass*)klass;
	parent_class = g_type_class_peek_parent(klass);

	gobject_class->finalize = jingle_rtp_finalize;
	gobject_class->set_property = jingle_rtp_set_property;
	gobject_class->get_property = jingle_rtp_get_property;
	klass->parent_class.to_xml = jingle_rtp_to_xml_internal;
	klass->parent_class.parse = jingle_rtp_parse_internal;
	klass->parent_class.description_type = JINGLE_APP_RTP;
	klass->parent_class.handle_action = jingle_rtp_handle_action_internal;

	g_object_class_install_property(gobject_class, PROP_MEDIA_TYPE,
			g_param_spec_string("media-type",
			"Media Type",
			"The media type (\"audio\" or \"video\") for this rtp session.",
			NULL,
			G_PARAM_READWRITE));
	g_object_class_install_property(gobject_class, PROP_SSRC,
			g_param_spec_string("ssrc",
			"ssrc",
			"The ssrc for this rtp session.",
			NULL,
			G_PARAM_READWRITE));

	g_type_class_add_private(klass, sizeof(JingleRtpPrivate));
}

static void
jingle_rtp_init (JingleRtp *rtp)
{
	rtp->priv = JINGLE_RTP_GET_PRIVATE(rtp);
	memset(rtp->priv, 0, sizeof(*rtp->priv));
}

static void
jingle_rtp_finalize (GObject *rtp)
{
	JingleRtpPrivate *priv = JINGLE_RTP_GET_PRIVATE(rtp);
	purple_debug_info("jingle-rtp","jingle_rtp_finalize\n");

	g_free(priv->media_type);
	g_free(priv->ssrc);

	G_OBJECT_CLASS(parent_class)->finalize(rtp);
}

static void
jingle_rtp_set_property (GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec)
{
	JingleRtp *rtp;
	g_return_if_fail(JINGLE_IS_RTP(object));

	rtp = JINGLE_RTP(object);

	switch (prop_id) {
		case PROP_MEDIA_TYPE:
			g_free(rtp->priv->media_type);
			rtp->priv->media_type = g_value_dup_string(value);
			break;
		case PROP_SSRC:
			g_free(rtp->priv->ssrc);
			rtp->priv->ssrc = g_value_dup_string(value);
			break;
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
			break;
	}
}

static void
jingle_rtp_get_property (GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
	JingleRtp *rtp;
	g_return_if_fail(JINGLE_IS_RTP(object));

	rtp = JINGLE_RTP(object);

	switch (prop_id) {
		case PROP_MEDIA_TYPE:
			g_value_set_string(value, rtp->priv->media_type);
			break;
		case PROP_SSRC:
			g_value_set_string(value, rtp->priv->ssrc);
			break;
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
			break;
	}
}

gchar *
jingle_rtp_get_media_type(JingleContent *content)
{
	gchar *media_type;
	g_object_get(content, "media-type", &media_type, NULL);
	return media_type;
}

gchar *
jingle_rtp_get_ssrc(JingleContent *content)
{
	gchar *ssrc;
	g_object_get(content, "ssrc", &ssrc, NULL);
	return ssrc;
}

static PurpleMedia *
jingle_rtp_get_media(JingleSession *session)
{
	JabberStream *js = jingle_session_get_js(session);
	PurpleMedia *media = NULL;
	GList *iter = purple_media_manager_get_media_by_account(
			purple_media_manager_get(),
			purple_connection_get_account(js->gc));

	for (; iter; iter = g_list_delete_link(iter, iter)) {
		JingleSession *media_session =
				purple_media_get_prpl_data(iter->data);
		if (media_session == session) {
			media = iter->data;
			break;
		}
	}
	if (iter != NULL)
		g_list_free(iter);

	return media;
}

static JingleRawUdpCandidate *
jingle_rtp_candidate_to_rawudp(JingleSession *session, guint generation,
		PurpleMediaCandidate *candidate)
{
	gchar *id = jabber_get_next_id(jingle_session_get_js(session));
	gchar *ip = purple_media_candidate_get_ip(candidate);
	JingleRawUdpCandidate *rawudp_candidate =
			jingle_rawudp_candidate_new(id, generation,
			purple_media_candidate_get_component_id(candidate),
			ip, purple_media_candidate_get_port(candidate));
	g_free(ip);
	g_free(id);
	return rawudp_candidate;
}

static JingleIceUdpCandidate *
jingle_rtp_candidate_to_iceudp(JingleSession *session, guint generation,
		PurpleMediaCandidate *candidate)
{
	gchar *id = jabber_get_next_id(jingle_session_get_js(session));
	gchar *ip = purple_media_candidate_get_ip(candidate);
	gchar *username = purple_media_candidate_get_username(candidate);
	gchar *password = purple_media_candidate_get_password(candidate);
	PurpleMediaCandidateType type =
			purple_media_candidate_get_candidate_type(candidate);

	JingleIceUdpCandidate *iceudp_candidate = jingle_iceudp_candidate_new(
			purple_media_candidate_get_component_id(candidate),
			purple_media_candidate_get_foundation(candidate),
			generation, id, ip, 0,
			purple_media_candidate_get_port(candidate),
			purple_media_candidate_get_priority(candidate), "udp",
			type == PURPLE_MEDIA_CANDIDATE_TYPE_HOST ? "host" :
			type == PURPLE_MEDIA_CANDIDATE_TYPE_SRFLX ? "srflx" :
			type == PURPLE_MEDIA_CANDIDATE_TYPE_PRFLX ? "prflx" :
			type == PURPLE_MEDIA_CANDIDATE_TYPE_RELAY ? "relay" :
			"", username, password);
	iceudp_candidate->reladdr =
			purple_media_candidate_get_base_ip(candidate);
	iceudp_candidate->relport =
			purple_media_candidate_get_base_port(candidate);
	g_free(password);
	g_free(username);
	g_free(ip);
	g_free(id);
	return iceudp_candidate;
}

static JingleTransport *
jingle_rtp_candidates_to_transport(JingleSession *session, GType type, guint generation, GList *candidates)
{
	if (type == JINGLE_TYPE_RAWUDP) {
		JingleTransport *transport = jingle_transport_create(JINGLE_TRANSPORT_RAWUDP);
		JingleRawUdpCandidate *rawudp_candidate;
		for (; candidates; candidates = g_list_next(candidates)) {
			PurpleMediaCandidate *candidate = candidates->data;
			rawudp_candidate = jingle_rtp_candidate_to_rawudp(
					session, generation, candidate);
			jingle_rawudp_add_local_candidate(
					JINGLE_RAWUDP(transport),
					rawudp_candidate);
		}
		return transport;
	} else if (type == JINGLE_TYPE_ICEUDP) {
		JingleTransport *transport = jingle_transport_create(JINGLE_TRANSPORT_ICEUDP);
		JingleIceUdpCandidate *iceudp_candidate;
		for (; candidates; candidates = g_list_next(candidates)) {
			PurpleMediaCandidate *candidate = candidates->data;
			iceudp_candidate = jingle_rtp_candidate_to_iceudp(
					session, generation, candidate);
			jingle_iceudp_add_local_candidate(
					JINGLE_ICEUDP(transport),
					iceudp_candidate);
		}
		return transport;
	} else {
		return NULL;
	}
}

static GList *
jingle_rtp_transport_to_candidates(JingleTransport *transport)
{
	const gchar *type = jingle_transport_get_transport_type(transport);
	GList *ret = NULL;
	if (!strcmp(type, JINGLE_TRANSPORT_RAWUDP)) {
		GList *candidates = jingle_rawudp_get_remote_candidates(JINGLE_RAWUDP(transport));

		for (; candidates; candidates = g_list_delete_link(candidates, candidates)) {
			JingleRawUdpCandidate *candidate = candidates->data;
			ret = g_list_append(ret, purple_media_candidate_new(
					"", candidate->component,
					PURPLE_MEDIA_CANDIDATE_TYPE_SRFLX,
					PURPLE_MEDIA_NETWORK_PROTOCOL_UDP,
					candidate->ip, candidate->port));
		}

		return ret;
	} else if (!strcmp(type, JINGLE_TRANSPORT_ICEUDP)) {
		GList *candidates = jingle_iceudp_get_remote_candidates(JINGLE_ICEUDP(transport));

		for (; candidates; candidates = g_list_delete_link(candidates, candidates)) {
			JingleIceUdpCandidate *candidate = candidates->data;
			PurpleMediaCandidate *new_candidate = purple_media_candidate_new(
					candidate->foundation, candidate->component,
					!strcmp(candidate->type, "host") ?
					PURPLE_MEDIA_CANDIDATE_TYPE_HOST :
					!strcmp(candidate->type, "srflx") ?
					PURPLE_MEDIA_CANDIDATE_TYPE_SRFLX :
					!strcmp(candidate->type, "prflx") ?
					PURPLE_MEDIA_CANDIDATE_TYPE_PRFLX :
					!strcmp(candidate->type, "relay") ?
					PURPLE_MEDIA_CANDIDATE_TYPE_RELAY : 0,
					PURPLE_MEDIA_NETWORK_PROTOCOL_UDP,
					candidate->ip, candidate->port);
			g_object_set(new_candidate,
					"base-ip", candidate->reladdr,
					"base-port", candidate->relport,
					"username", candidate->username,
					"password", candidate->password,
					"priority", candidate->priority, NULL);
			ret = g_list_append(ret, new_candidate);
		}

		return ret;
	} else {
		return NULL;
	}
}

static void jingle_rtp_ready(JingleSession *session);

static void
jingle_rtp_candidates_prepared_cb(PurpleMedia *media,
		gchar *sid, gchar *name, JingleSession *session)
{
	JingleContent *content = jingle_session_find_content(
			session, sid, NULL);
	JingleTransport *oldtransport, *transport;
	GList *candidates;

	purple_debug_info("jingle-rtp", "jingle_rtp_candidates_prepared_cb\n");

	if (content == NULL) {
		purple_debug_error("jingle-rtp",
				"jingle_rtp_candidates_prepared_cb: "
				"Can't find session %s\n", sid);
		return;
	}

	oldtransport = jingle_content_get_transport(content);
	candidates = purple_media_get_local_candidates(media, sid, name);
	transport = JINGLE_TRANSPORT(jingle_rtp_candidates_to_transport(
			session, JINGLE_IS_RAWUDP(oldtransport) ?
				JINGLE_TYPE_RAWUDP : JINGLE_TYPE_ICEUDP,
			0, candidates));

	g_list_free(candidates);
	g_object_unref(oldtransport);

	jingle_content_set_pending_transport(content, transport);
	jingle_content_accept_transport(content);

	jingle_rtp_ready(session);
}

static void
jingle_rtp_codecs_changed_cb(PurpleMedia *media, gchar *sid,
		JingleSession *session)
{
	purple_debug_info("jingle-rtp", "jingle_rtp_codecs_changed_cb: "
			"session_id: %s jingle_session: %p\n", sid, session);
	jingle_rtp_ready(session);
}

static void
jingle_rtp_new_candidate_cb(PurpleMedia *media, gchar *sid, gchar *name, PurpleMediaCandidate *candidate, JingleSession *session)
{
	JingleContent *content = jingle_session_find_content(
			session, sid, NULL);
	JingleTransport *transport;

	purple_debug_info("jingle-rtp", "jingle_rtp_new_candidate_cb\n");

	if (content == NULL) {
		purple_debug_error("jingle-rtp",
				"jingle_rtp_new_candidate_cb: "
				"Can't find session %s\n", sid);
		return;
	}

	transport = jingle_content_get_transport(content);

	if (JINGLE_IS_ICEUDP(transport))
		jingle_iceudp_add_local_candidate(JINGLE_ICEUDP(transport),
				jingle_rtp_candidate_to_iceudp(
				session, 1, candidate));
	else if (JINGLE_IS_RAWUDP(transport))
		jingle_rawudp_add_local_candidate(JINGLE_RAWUDP(transport),
				jingle_rtp_candidate_to_rawudp(
				session, 1, candidate));

	g_object_unref(transport);

	jabber_iq_send(jingle_session_to_packet(session,
			JINGLE_TRANSPORT_INFO));
}

static void
jingle_rtp_initiate_ack_cb(JabberStream *js, const char *from,
                           JabberIqType type, const char *id,
                           xmlnode *packet, gpointer data)
{
	JingleSession *session = data;

	if (type == JABBER_IQ_ERROR || xmlnode_get_child(packet, "error")) {
		purple_media_end(jingle_rtp_get_media(session), NULL, NULL);
		g_object_unref(session);
		return;
	}
}

static void
jingle_rtp_state_changed_cb(PurpleMedia *media, PurpleMediaState state,
		gchar *sid, gchar *name, JingleSession *session)
{
	purple_debug_info("jingle-rtp", "state-changed: state %d "
			"id: %s name: %s\n", state, sid ? sid : "(null)",
			name ? name : "(null)");
}

static void
jingle_rtp_stream_info_cb(PurpleMedia *media, PurpleMediaInfoType type,
		gchar *sid, gchar *name, gboolean local,
		JingleSession *session)
{
	purple_debug_info("jingle-rtp", "stream-info: type %d "
			"id: %s name: %s\n", type, sid ? sid : "(null)",
			name ? name : "(null)");

	g_return_if_fail(JINGLE_IS_SESSION(session));

	if (type == PURPLE_MEDIA_INFO_HANGUP ||
			type == PURPLE_MEDIA_INFO_REJECT) {
		jabber_iq_send(jingle_session_terminate_packet(
				session, type == PURPLE_MEDIA_INFO_HANGUP ?
				"success" : "decline"));

		g_signal_handlers_disconnect_by_func(G_OBJECT(media),
				G_CALLBACK(jingle_rtp_state_changed_cb),
				session);
		g_signal_handlers_disconnect_by_func(G_OBJECT(media),
				G_CALLBACK(jingle_rtp_stream_info_cb),
				session);
		g_signal_handlers_disconnect_by_func(G_OBJECT(media),
				G_CALLBACK(jingle_rtp_new_candidate_cb),
				session);

		g_object_unref(session);
	} else if (type == PURPLE_MEDIA_INFO_ACCEPT &&
			jingle_session_is_initiator(session) == FALSE) {
		jingle_rtp_ready(session);
	}
}

static void
jingle_rtp_ready(JingleSession *session)
{
	PurpleMedia *media = jingle_rtp_get_media(session);

	if (purple_media_candidates_prepared(media, NULL, NULL) &&
			purple_media_codecs_ready(media, NULL) &&
			(jingle_session_is_initiator(session) == TRUE ||
			purple_media_accepted(media, NULL, NULL))) {
		if (jingle_session_is_initiator(session)) {
			JabberIq *iq = jingle_session_to_packet(
					session, JINGLE_SESSION_INITIATE);
			jabber_iq_set_callback(iq,
					jingle_rtp_initiate_ack_cb, session);
			jabber_iq_send(iq);
		} else {
			jabber_iq_send(jingle_session_to_packet(session,
					JINGLE_SESSION_ACCEPT));
		}

		g_signal_handlers_disconnect_by_func(G_OBJECT(media),
				G_CALLBACK(jingle_rtp_candidates_prepared_cb),
				session);
		g_signal_handlers_disconnect_by_func(G_OBJECT(media),
				G_CALLBACK(jingle_rtp_codecs_changed_cb),
				session);
		g_signal_connect(G_OBJECT(media), "new-candidate",
				G_CALLBACK(jingle_rtp_new_candidate_cb),
				session);
	}
}

static PurpleMedia *
jingle_rtp_create_media(JingleContent *content)
{
	JingleSession *session = jingle_content_get_session(content);
	JabberStream *js = jingle_session_get_js(session);
	gchar *remote_jid = jingle_session_get_remote_jid(session);

	PurpleMedia *media = purple_media_manager_create_media(
			purple_media_manager_get(),
			purple_connection_get_account(js->gc),
			"fsrtpconference", remote_jid,
			jingle_session_is_initiator(session));
	g_free(remote_jid);

	if (!media) {
		purple_debug_error("jingle-rtp", "Couldn't create media session\n");
		return NULL;
	}

	purple_media_set_prpl_data(media, session);

	/* connect callbacks */
	g_signal_connect(G_OBJECT(media), "candidates-prepared",
				 G_CALLBACK(jingle_rtp_candidates_prepared_cb), session);
	g_signal_connect(G_OBJECT(media), "codecs-changed",
				 G_CALLBACK(jingle_rtp_codecs_changed_cb), session);
	g_signal_connect(G_OBJECT(media), "state-changed",
				 G_CALLBACK(jingle_rtp_state_changed_cb), session);
	g_signal_connect(G_OBJECT(media), "stream-info",
			G_CALLBACK(jingle_rtp_stream_info_cb), session);

	g_object_unref(session);
	return media;
}

static gboolean
jingle_rtp_init_media(JingleContent *content)
{
	JingleSession *session = jingle_content_get_session(content);
	PurpleMedia *media = jingle_rtp_get_media(session);
	gchar *creator;
	gchar *media_type;
	gchar *remote_jid;
	gchar *senders;
	gchar *name;
	const gchar *transmitter;
	gboolean is_audio;
	gboolean is_creator;
	PurpleMediaSessionType type;
	JingleTransport *transport;
	GParameter *params = NULL;
	guint num_params;

	/* maybe this create ought to just be in initiate and handle initiate */
	if (media == NULL) {
		media = jingle_rtp_create_media(content);

		if (media == NULL)
			return FALSE;
	}

	name = jingle_content_get_name(content);
	media_type = jingle_rtp_get_media_type(content);
	remote_jid = jingle_session_get_remote_jid(session);
	senders = jingle_content_get_senders(content);
	transport = jingle_content_get_transport(content);

	if (media_type == NULL) {
		g_free(name);
		g_free(remote_jid);
		g_free(senders);
		g_free(params);
		g_object_unref(transport);
		g_object_unref(session);
		return FALSE;
	}

	if (JINGLE_IS_RAWUDP(transport))
		transmitter = "rawudp";
	else if (JINGLE_IS_ICEUDP(transport))
		transmitter = "nice";
	else
		transmitter = "notransmitter";
	g_object_unref(transport);

	is_audio = g_str_equal(media_type, "audio");

	if (purple_strequal(senders, "both"))
		type = is_audio ? PURPLE_MEDIA_AUDIO
				: PURPLE_MEDIA_VIDEO;
	else if (purple_strequal(senders, "initiator") ==
			jingle_session_is_initiator(session))
		type = is_audio ? PURPLE_MEDIA_SEND_AUDIO
				: PURPLE_MEDIA_SEND_VIDEO;
	else
		type = is_audio ? PURPLE_MEDIA_RECV_AUDIO
				: PURPLE_MEDIA_RECV_VIDEO;

	params =
		jingle_get_params(jingle_session_get_js(session), NULL, 0, 0, 0,
			NULL, NULL, &num_params);

	creator = jingle_content_get_creator(content);
	if (creator == NULL) {
		g_free(name);
		g_free(media_type);
		g_free(remote_jid);
		g_free(senders);
		g_free(params);
		g_object_unref(session);
		return FALSE;
	}

	if (g_str_equal(creator, "initiator"))
		is_creator = jingle_session_is_initiator(session);
	else
		is_creator = !jingle_session_is_initiator(session);
	g_free(creator);

	if(!purple_media_add_stream(media, name, remote_jid,
			type, is_creator, transmitter, num_params, params)) {
		purple_media_end(media, NULL, NULL);
		/* TODO: How much clean-up is necessary here? (does calling
		         purple_media_end lead to cleaning up Jingle structs?) */
		return FALSE;
	}

	g_free(name);
	g_free(media_type);
	g_free(remote_jid);
	g_free(senders);
	g_free(params);
	g_object_unref(session);

	return TRUE;
}

static GList *
jingle_rtp_parse_codecs(xmlnode *description)
{
	GList *codecs = NULL;
	xmlnode *codec_element = NULL;
	const char *encoding_name,*id, *clock_rate;
	PurpleMediaCodec *codec;
	const gchar *media = xmlnode_get_attrib(description, "media");
	PurpleMediaSessionType type;

	if (media == NULL) {
		purple_debug_warning("jingle-rtp", "missing media type\n");
		return NULL;
	}

	if (g_str_equal(media, "video")) {
		type = PURPLE_MEDIA_VIDEO;
	} else if (g_str_equal(media, "audio")) {
		type = PURPLE_MEDIA_AUDIO;
	} else {
		purple_debug_warning("jingle-rtp", "unknown media type: %s\n",
				media);
		return NULL;
	}

	for (codec_element = xmlnode_get_child(description, "payload-type") ;
		 codec_element ;
		 codec_element = xmlnode_get_next_twin(codec_element)) {
		xmlnode *param;
		gchar *codec_str;
		encoding_name = xmlnode_get_attrib(codec_element, "name");

		id = xmlnode_get_attrib(codec_element, "id");
		clock_rate = xmlnode_get_attrib(codec_element, "clockrate");

		codec = purple_media_codec_new(atoi(id), encoding_name,
				     type,
				     clock_rate ? atoi(clock_rate) : 0);

		for (param = xmlnode_get_child(codec_element, "parameter");
				param; param = xmlnode_get_next_twin(param)) {
			purple_media_codec_add_optional_parameter(codec,
					xmlnode_get_attrib(param, "name"),
					xmlnode_get_attrib(param, "value"));
		}

		codec_str = purple_media_codec_to_string(codec);
		purple_debug_info("jingle-rtp", "received codec: %s\n", codec_str);
		g_free(codec_str);

		codecs = g_list_append(codecs, codec);
	}
	return codecs;
}

static JingleContent *
jingle_rtp_parse_internal(xmlnode *rtp)
{
	JingleContent *content = parent_class->parse(rtp);
	xmlnode *description = xmlnode_get_child(rtp, "description");
	const gchar *media_type = xmlnode_get_attrib(description, "media");
	const gchar *ssrc = xmlnode_get_attrib(description, "ssrc");
	purple_debug_info("jingle-rtp", "rtp parse\n");
	g_object_set(content, "media-type", media_type, NULL);
	if (ssrc != NULL)
		g_object_set(content, "ssrc", ssrc, NULL);
	return content;
}

static void
jingle_rtp_add_payloads(xmlnode *description, GList *codecs)
{
	for (; codecs ; codecs = codecs->next) {
		PurpleMediaCodec *codec = (PurpleMediaCodec*)codecs->data;
		GList *iter = purple_media_codec_get_optional_parameters(codec);
		gchar *id, *name, *clockrate, *channels;
		gchar *codec_str;
		xmlnode *payload = xmlnode_new_child(description, "payload-type");

		id = g_strdup_printf("%d",
				purple_media_codec_get_id(codec));
		name = purple_media_codec_get_encoding_name(codec);
		clockrate = g_strdup_printf("%d",
				purple_media_codec_get_clock_rate(codec));
		channels = g_strdup_printf("%d",
				purple_media_codec_get_channels(codec));

		xmlnode_set_attrib(payload, "name", name);
		xmlnode_set_attrib(payload, "id", id);
		xmlnode_set_attrib(payload, "clockrate", clockrate);
		xmlnode_set_attrib(payload, "channels", channels);

		g_free(channels);
		g_free(clockrate);
		g_free(name);
		g_free(id);

		for (; iter; iter = g_list_next(iter)) {
			PurpleKeyValuePair *mparam = iter->data;
			xmlnode *param = xmlnode_new_child(payload, "parameter");
			xmlnode_set_attrib(param, "name", mparam->key);
			xmlnode_set_attrib(param, "value", mparam->value);
		}

		codec_str = purple_media_codec_to_string(codec);
		purple_debug_info("jingle", "adding codec: %s\n", codec_str);
		g_free(codec_str);
	}
}

static xmlnode *
jingle_rtp_to_xml_internal(JingleContent *rtp, xmlnode *content, JingleActionType action)
{
	xmlnode *node = parent_class->to_xml(rtp, content, action);
	xmlnode *description = xmlnode_get_child(node, "description");
	if (description != NULL) {
		JingleSession *session = jingle_content_get_session(rtp);
		PurpleMedia *media = jingle_rtp_get_media(session);
		gchar *media_type = jingle_rtp_get_media_type(rtp);
		gchar *ssrc = jingle_rtp_get_ssrc(rtp);
		gchar *name = jingle_content_get_name(rtp);
		GList *codecs = purple_media_get_codecs(media, name);

		xmlnode_set_attrib(description, "media", media_type);

		if (ssrc != NULL)
			xmlnode_set_attrib(description, "ssrc", ssrc);

		g_free(media_type);
		g_free(name);
		g_object_unref(session);

		jingle_rtp_add_payloads(description, codecs);
		purple_media_codec_list_free(codecs);
	}
	return node;
}

static void
jingle_rtp_handle_action_internal(JingleContent *content, xmlnode *xmlcontent, JingleActionType action)
{
	switch (action) {
		case JINGLE_SESSION_ACCEPT:
		case JINGLE_SESSION_INITIATE: {
			JingleSession *session;
			JingleTransport *transport;
			xmlnode *description;
			GList *candidates;
			GList *codecs;
			gchar *name;
			gchar *remote_jid;
			PurpleMedia *media;

			session = jingle_content_get_session(content);

			if (action == JINGLE_SESSION_INITIATE &&
					!jingle_rtp_init_media(content)) {
				/* XXX: send error */
				jabber_iq_send(jingle_session_terminate_packet(
						session, "general-error"));
				g_object_unref(session);
				break;
			}

			transport = jingle_transport_parse(
					xmlnode_get_child(xmlcontent, "transport"));
			description = xmlnode_get_child(xmlcontent, "description");
			candidates = jingle_rtp_transport_to_candidates(transport);
			codecs = jingle_rtp_parse_codecs(description);
			name = jingle_content_get_name(content);
			remote_jid = jingle_session_get_remote_jid(session);

			media = jingle_rtp_get_media(session);
			purple_media_set_remote_codecs(media,
					name, remote_jid, codecs);
			purple_media_add_remote_candidates(media,
					name, remote_jid, candidates);

			if (action == JINGLE_SESSION_ACCEPT)
				purple_media_stream_info(media,
						PURPLE_MEDIA_INFO_ACCEPT,
						name, remote_jid, FALSE);

			g_free(remote_jid);
			g_free(name);
			g_object_unref(session);
			break;
		}
		case JINGLE_SESSION_TERMINATE: {
			JingleSession *session = jingle_content_get_session(content);
			PurpleMedia *media = jingle_rtp_get_media(session);

			if (media != NULL) {
				purple_media_end(media, NULL, NULL);
			}

			g_object_unref(session);
			break;
		}
		case JINGLE_TRANSPORT_INFO: {
			JingleSession *session = jingle_content_get_session(content);
			JingleTransport *transport = jingle_transport_parse(
					xmlnode_get_child(xmlcontent, "transport"));
			GList *candidates = jingle_rtp_transport_to_candidates(transport);
			gchar *name = jingle_content_get_name(content);
			gchar *remote_jid =
					jingle_session_get_remote_jid(session);

			purple_media_add_remote_candidates(
					jingle_rtp_get_media(session),
					name, remote_jid, candidates);

			g_free(remote_jid);
			g_free(name);
			g_object_unref(session);
			break;
		}
		case JINGLE_DESCRIPTION_INFO: {
			JingleSession *session =
					jingle_content_get_session(content);
			xmlnode *description = xmlnode_get_child(
					xmlcontent, "description");
			GList *codecs, *iter, *iter2, *remote_codecs =
					jingle_rtp_parse_codecs(description);
			gchar *name = jingle_content_get_name(content);
			gchar *remote_jid =
					jingle_session_get_remote_jid(session);
			PurpleMedia *media;

			media = jingle_rtp_get_media(session);

			/*
			 * This may have problems if description-info is
			 * received without the optional parameters for a
			 * codec with configuration info (such as THEORA
			 * or H264). The local configuration info may be
			 * set for the remote codec.
			 *
			 * As of 2.6.3 there's no API to support getting
			 * the remote codecs specifically, just the
			 * intersection. Another option may be to cache
			 * the remote codecs received in initiate/accept.
			 */
			codecs = purple_media_get_codecs(media, name);

			for (iter = codecs; iter; iter = g_list_next(iter)) {
				guint id;

				id = purple_media_codec_get_id(iter->data);
				iter2 = remote_codecs;

				for (; iter2; iter2 = g_list_next(iter2)) {
					if (purple_media_codec_get_id(
							iter2->data) != id)
						continue;

					g_object_unref(iter->data);
					iter->data = iter2->data;
					remote_codecs = g_list_delete_link(
							remote_codecs, iter2);
					break;
				}
			}

			codecs = g_list_concat(codecs, remote_codecs);

			purple_media_set_remote_codecs(media,
					name, remote_jid, codecs);

			purple_media_codec_list_free (codecs);
			g_free(remote_jid);
			g_free(name);
			g_object_unref(session);
			break;
		}
		default:
			break;
	}
}

gboolean
jingle_rtp_initiate_media(JabberStream *js, const gchar *who,
		      PurpleMediaSessionType type)
{
	/* create content negotiation */
	JingleSession *session;
	JingleContent *content;
	JingleTransport *transport;
	JabberBuddy *jb;
	JabberBuddyResource *jbr;
	const gchar *transport_type;

	gchar *resource = NULL, *me = NULL, *sid = NULL;

	/* construct JID to send to */
	jb = jabber_buddy_find(js, who, FALSE);
	if (!jb) {
		purple_debug_error("jingle-rtp", "Could not find Jabber buddy\n");
		return FALSE;
	}

	resource = jabber_get_resource(who);
	jbr = jabber_buddy_find_resource(jb, resource);
	g_free(resource);

	if (!jbr) {
		purple_debug_error("jingle-rtp", "Could not find buddy's resource - %s\n", resource);
		return FALSE;
	}

	if (jabber_resource_has_capability(jbr, JINGLE_TRANSPORT_ICEUDP)) {
		transport_type = JINGLE_TRANSPORT_ICEUDP;
	} else if (jabber_resource_has_capability(jbr, JINGLE_TRANSPORT_RAWUDP)) {
		transport_type = JINGLE_TRANSPORT_RAWUDP;
	} else {
		purple_debug_error("jingle-rtp", "Resource doesn't support "
				"the same transport types\n");
		return FALSE;
	}

	/* set ourselves as initiator */
	me = g_strdup_printf("%s@%s/%s", js->user->node, js->user->domain, js->user->resource);

	sid = jabber_get_next_id(js);
	session = jingle_session_create(js, sid, me, who, TRUE);
	g_free(sid);


	if (type & PURPLE_MEDIA_AUDIO) {
		transport = jingle_transport_create(transport_type);
		content = jingle_content_create(JINGLE_APP_RTP, "initiator",
				"session", "audio-session", "both", transport);
		jingle_session_add_content(session, content);
		JINGLE_RTP(content)->priv->media_type = g_strdup("audio");
		jingle_rtp_init_media(content);
	}
	if (type & PURPLE_MEDIA_VIDEO) {
		transport = jingle_transport_create(transport_type);
		content = jingle_content_create(JINGLE_APP_RTP, "initiator",
				"session", "video-session", "both", transport);
		jingle_session_add_content(session, content);
		JINGLE_RTP(content)->priv->media_type = g_strdup("video");
		jingle_rtp_init_media(content);
	}

	g_free(me);

	if (jingle_rtp_get_media(session) == NULL) {
		return FALSE;
	}

	return TRUE;
}

void
jingle_rtp_terminate_session(JabberStream *js, const gchar *who)
{
	JingleSession *session;
/* XXX: This may cause file transfers and xml sessions to stop as well */
	session = jingle_session_find_by_jid(js, who);

	if (session) {
		PurpleMedia *media = jingle_rtp_get_media(session);
		if (media) {
			purple_debug_info("jingle-rtp", "hanging up media\n");
			purple_media_stream_info(media,
					PURPLE_MEDIA_INFO_HANGUP,
					NULL, NULL, TRUE);
		}
	}
}

#endif /* USE_VV */

