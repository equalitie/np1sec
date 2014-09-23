/**
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
#include "google_session.h"
#include "relay.h"

#include "jingle/jingle.h"

#ifdef USE_VV

typedef struct {
	PurpleMedia *media;
	gboolean video;
	GList *remote_audio_candidates; /* list of PurpleMediaCandidate */
	GList *remote_video_candidates; /* list of PurpleMediaCandidate */
	gboolean added_streams;		/* this indicates if the streams have been
	 							   to media (ie. after getting relay credentials */
} GoogleAVSessionData;

static gboolean
google_session_id_equal(gconstpointer a, gconstpointer b)
{
	GoogleSessionId *c = (GoogleSessionId*)a;
	GoogleSessionId *d = (GoogleSessionId*)b;

	return !strcmp(c->id, d->id) && !strcmp(c->initiator, d->initiator);
}

static void
google_session_destroy(GoogleSession *session)
{
	GoogleAVSessionData *session_data =
		(GoogleAVSessionData *) session->session_data;
	g_free(session->id.id);
	g_free(session->id.initiator);
	g_free(session->remote_jid);

	if (session_data->remote_audio_candidates)
		purple_media_candidate_list_free(session_data->remote_audio_candidates);

	if (session_data->remote_video_candidates)
		purple_media_candidate_list_free(session_data->remote_video_candidates);

	if (session->description)
		xmlnode_free(session->description);

	g_free(session->session_data);
	g_free(session);
}

static xmlnode *
google_session_create_xmlnode(GoogleSession *session, const char *type)
{
	xmlnode *node = xmlnode_new("session");
	xmlnode_set_namespace(node, NS_GOOGLE_SESSION);
	xmlnode_set_attrib(node, "id", session->id.id);
	xmlnode_set_attrib(node, "initiator", session->id.initiator);
	xmlnode_set_attrib(node, "type", type);
	return node;
}

static void
google_session_send_candidates(PurpleMedia *media, gchar *session_id,
		gchar *participant, GoogleSession *session)
{
	PurpleMedia *session_media =
		((GoogleAVSessionData *) session->session_data)->media;
	GList *candidates =
		purple_media_get_local_candidates(session_media, session_id,
		    session->remote_jid);
	GList *iter;
	PurpleMediaCandidate *transport;
	gboolean video = FALSE;

	if (!strcmp(session_id, "google-video"))
		video = TRUE;

	for (iter = candidates; iter; iter = iter->next) {
		JabberIq *iq;
		gchar *ip, *port, *username, *password;
		gchar pref[16];
		PurpleMediaCandidateType type;
		xmlnode *sess;
		xmlnode *candidate;
		guint component_id;
		transport = PURPLE_MEDIA_CANDIDATE(iter->data);
		component_id = purple_media_candidate_get_component_id(
				transport);

		iq = jabber_iq_new(session->js, JABBER_IQ_SET);
		sess = google_session_create_xmlnode(session, "candidates");
		xmlnode_insert_child(iq->node, sess);
		xmlnode_set_attrib(iq->node, "to", session->remote_jid);

		candidate = xmlnode_new("candidate");

		ip = purple_media_candidate_get_ip(transport);
		port = g_strdup_printf("%d",
				purple_media_candidate_get_port(transport));
		g_ascii_dtostr(pref, 16,
			purple_media_candidate_get_priority(transport) / 1000.0);
		username = purple_media_candidate_get_username(transport);
		password = purple_media_candidate_get_password(transport);
		type = purple_media_candidate_get_candidate_type(transport);

		xmlnode_set_attrib(candidate, "address", ip);
		xmlnode_set_attrib(candidate, "port", port);
		xmlnode_set_attrib(candidate, "name",
				component_id == PURPLE_MEDIA_COMPONENT_RTP ?
				video ? "video_rtp" : "rtp" :
				component_id == PURPLE_MEDIA_COMPONENT_RTCP ?
				video ? "video_rtcp" : "rtcp" : "none");
		xmlnode_set_attrib(candidate, "username", username);
		/*
		 * As of this writing, Farsight 2 in Google compatibility
		 * mode doesn't provide a password. The Gmail client
		 * requires this to be set.
		 */
		xmlnode_set_attrib(candidate, "password",
				password != NULL ? password : "");
		xmlnode_set_attrib(candidate, "preference", pref);
		xmlnode_set_attrib(candidate, "protocol",
				purple_media_candidate_get_protocol(transport)
				== PURPLE_MEDIA_NETWORK_PROTOCOL_UDP ?
				"udp" : "tcp");
		xmlnode_set_attrib(candidate, "type", type ==
				PURPLE_MEDIA_CANDIDATE_TYPE_HOST ? "local" :
						      type ==
				PURPLE_MEDIA_CANDIDATE_TYPE_SRFLX ? "stun" :
					       	      type ==
				PURPLE_MEDIA_CANDIDATE_TYPE_RELAY ? "relay" :
				NULL);
		xmlnode_set_attrib(candidate, "generation", "0");
		xmlnode_set_attrib(candidate, "network", "0");
		xmlnode_insert_child(sess, candidate);

		g_free(ip);
		g_free(port);
		g_free(username);
		g_free(password);

		jabber_iq_send(iq);
	}
	purple_media_candidate_list_free(candidates);
}

static void
google_session_ready(GoogleSession *session)
{
	PurpleMedia *media =
		((GoogleAVSessionData *)session->session_data)->media;
	gboolean video =
		((GoogleAVSessionData *)session->session_data)->video;
	if (purple_media_codecs_ready(media, NULL) &&
			purple_media_candidates_prepared(media, NULL, NULL)) {
		gchar *me = g_strdup_printf("%s@%s/%s",
				session->js->user->node,
				session->js->user->domain,
				session->js->user->resource);
		JabberIq *iq;
		xmlnode *sess, *desc, *payload;
		GList *codecs, *iter;
		gboolean is_initiator = !strcmp(session->id.initiator, me);

		if (!is_initiator &&
				!purple_media_accepted(media, NULL, NULL)) {
			g_free(me);
			return;
		}

		iq = jabber_iq_new(session->js, JABBER_IQ_SET);

		if (is_initiator) {
			xmlnode_set_attrib(iq->node, "to", session->remote_jid);
			xmlnode_set_attrib(iq->node, "from", session->id.initiator);
			sess = google_session_create_xmlnode(session, "initiate");
		} else {
			google_session_send_candidates(media,
					"google-voice", session->remote_jid,
					session);
			google_session_send_candidates(media,
					"google-video", session->remote_jid,
					session);
			xmlnode_set_attrib(iq->node, "to", session->remote_jid);
			xmlnode_set_attrib(iq->node, "from", me);
			sess = google_session_create_xmlnode(session, "accept");
		}
		xmlnode_insert_child(iq->node, sess);
		desc = xmlnode_new_child(sess, "description");
		if (video)
			xmlnode_set_namespace(desc, NS_GOOGLE_SESSION_VIDEO);
		else
			xmlnode_set_namespace(desc, NS_GOOGLE_SESSION_PHONE);

		codecs = purple_media_get_codecs(media, "google-video");

		for (iter = codecs; iter; iter = g_list_next(iter)) {
			PurpleMediaCodec *codec = (PurpleMediaCodec*)iter->data;
			gchar *id = g_strdup_printf("%d",
					purple_media_codec_get_id(codec));
			gchar *encoding_name =
					purple_media_codec_get_encoding_name(codec);
			payload = xmlnode_new_child(desc, "payload-type");
			xmlnode_set_attrib(payload, "id", id);
			xmlnode_set_attrib(payload, "name", encoding_name);
			xmlnode_set_attrib(payload, "width", "320");
			xmlnode_set_attrib(payload, "height", "200");
			xmlnode_set_attrib(payload, "framerate", "30");
			g_free(encoding_name);
			g_free(id);
		}
		purple_media_codec_list_free(codecs);

		codecs = purple_media_get_codecs(media, "google-voice");

		for (iter = codecs; iter; iter = g_list_next(iter)) {
			PurpleMediaCodec *codec = (PurpleMediaCodec*)iter->data;
			gchar *id = g_strdup_printf("%d",
					purple_media_codec_get_id(codec));
			gchar *encoding_name =
					purple_media_codec_get_encoding_name(codec);
			gchar *clock_rate = g_strdup_printf("%d",
					purple_media_codec_get_clock_rate(codec));
			payload = xmlnode_new_child(desc, "payload-type");
			if (video)
				xmlnode_set_namespace(payload, NS_GOOGLE_SESSION_PHONE);
			xmlnode_set_attrib(payload, "id", id);
			/*
			 * Hack to make Gmail accept speex as the codec.
			 * It shouldn't have to be case sensitive.
			 */
			if (purple_strequal(encoding_name, "SPEEX"))
				xmlnode_set_attrib(payload, "name", "speex");
			else
				xmlnode_set_attrib(payload, "name", encoding_name);
			xmlnode_set_attrib(payload, "clockrate", clock_rate);
			g_free(clock_rate);
			g_free(encoding_name);
			g_free(id);
		}
		purple_media_codec_list_free(codecs);

		jabber_iq_send(iq);

		if (is_initiator) {
			google_session_send_candidates(media,
					"google-voice", session->remote_jid,
					session);
			google_session_send_candidates(media,
					"google-video", session->remote_jid,
					session);
		}

		g_signal_handlers_disconnect_by_func(G_OBJECT(media),
				G_CALLBACK(google_session_ready), session);
	}
}

static void
google_session_state_changed_cb(PurpleMedia *media, PurpleMediaState state,
		gchar *sid, gchar *name, GoogleSession *session)
{
	if (sid == NULL && name == NULL) {
		if (state == PURPLE_MEDIA_STATE_END) {
			google_session_destroy(session);
		}
	}
}

static void
google_session_stream_info_cb(PurpleMedia *media, PurpleMediaInfoType type,
		gchar *sid, gchar *name, gboolean local,
		GoogleSession *session)
{
	if (sid != NULL || name != NULL)
		return;

	if (type == PURPLE_MEDIA_INFO_HANGUP) {
		xmlnode *sess;
		JabberIq *iq = jabber_iq_new(session->js, JABBER_IQ_SET);

		xmlnode_set_attrib(iq->node, "to", session->remote_jid);
		sess = google_session_create_xmlnode(session, "terminate");
		xmlnode_insert_child(iq->node, sess);

		jabber_iq_send(iq);
	} else if (type == PURPLE_MEDIA_INFO_REJECT) {
		xmlnode *sess;
		JabberIq *iq = jabber_iq_new(session->js, JABBER_IQ_SET);

		xmlnode_set_attrib(iq->node, "to", session->remote_jid);
		sess = google_session_create_xmlnode(session, "reject");
		xmlnode_insert_child(iq->node, sess);

		jabber_iq_send(iq);
	} else if (type == PURPLE_MEDIA_INFO_ACCEPT && local == TRUE) {
		google_session_ready(session);
	}
}

static GParameter *
jabber_google_session_get_params(JabberStream *js, const gchar *relay_ip,
	guint16 relay_udp, guint16 relay_tcp, guint16 relay_ssltcp,
    const gchar *relay_username, const gchar *relay_password, guint *num)
{
	guint num_params;
	GParameter *params =
		jingle_get_params(js, relay_ip, relay_udp, relay_tcp, relay_ssltcp,
	    	relay_username, relay_password, &num_params);
	GParameter *new_params = g_new0(GParameter, num_params + 1);

	memcpy(new_params, params, sizeof(GParameter) * num_params);

	purple_debug_info("jabber", "setting Google jingle compatibility param\n");
	new_params[num_params].name = "compatibility-mode";
	g_value_init(&new_params[num_params].value, G_TYPE_UINT);
	g_value_set_uint(&new_params[num_params].value, 1); /* NICE_COMPATIBILITY_GOOGLE */

	g_free(params);
	*num = num_params + 1;
	return new_params;
}


static void
jabber_google_relay_response_session_initiate_cb(GoogleSession *session,
    const gchar *relay_ip, guint relay_udp, guint relay_tcp, guint relay_ssltcp,
    const gchar *relay_username, const gchar *relay_password)
{
	GParameter *params;
	guint num_params;
	JabberStream *js = session->js;
	GoogleAVSessionData *session_data =
		(GoogleAVSessionData *) session->session_data;

	session_data->media = purple_media_manager_create_media(
			purple_media_manager_get(),
			purple_connection_get_account(js->gc),
			"fsrtpconference", session->remote_jid, TRUE);

	purple_media_set_prpl_data(session_data->media, session);

	g_signal_connect_swapped(G_OBJECT(session_data->media),
			"candidates-prepared",
			G_CALLBACK(google_session_ready), session);
	g_signal_connect_swapped(G_OBJECT(session_data->media), "codecs-changed",
			G_CALLBACK(google_session_ready), session);
	g_signal_connect(G_OBJECT(session_data->media), "state-changed",
			G_CALLBACK(google_session_state_changed_cb), session);
	g_signal_connect(G_OBJECT(session_data->media), "stream-info",
			G_CALLBACK(google_session_stream_info_cb), session);

	params =
		jabber_google_session_get_params(js, relay_ip, relay_udp, relay_tcp,
			relay_ssltcp, relay_username, relay_password, &num_params);

	if (purple_media_add_stream(session_data->media, "google-voice",
			session->remote_jid, PURPLE_MEDIA_AUDIO,
			TRUE, "nice", num_params, params) == FALSE ||
			(session_data->video && purple_media_add_stream(
			session_data->media, "google-video",
			session->remote_jid, PURPLE_MEDIA_VIDEO,
			TRUE, "nice", num_params, params) == FALSE)) {
		purple_media_error(session_data->media, "Error adding stream.");
		purple_media_end(session_data->media, NULL, NULL);
	} else {
		session_data->added_streams = TRUE;
	}

	g_free(params);
}


gboolean
jabber_google_session_initiate(JabberStream *js, const gchar *who, PurpleMediaSessionType type)
{
	GoogleSession *session;
	JabberBuddy *jb;
	JabberBuddyResource *jbr;
	gchar *jid;
	GoogleAVSessionData *session_data = NULL;

	/* construct JID to send to */
	jb = jabber_buddy_find(js, who, FALSE);
	if (!jb) {
		purple_debug_error("jingle-rtp",
				"Could not find Jabber buddy\n");
		return FALSE;
	}
	jbr = jabber_buddy_find_resource(jb, NULL);
	if (!jbr) {
		purple_debug_error("jingle-rtp",
				"Could not find buddy's resource\n");
	}

	if ((strchr(who, '/') == NULL) && jbr && (jbr->name != NULL)) {
		jid = g_strdup_printf("%s/%s", who, jbr->name);
	} else {
		jid = g_strdup(who);
	}

	session = g_new0(GoogleSession, 1);
	session->id.id = jabber_get_next_id(js);
	session->id.initiator = g_strdup_printf("%s@%s/%s", js->user->node,
			js->user->domain, js->user->resource);
	session->state = SENT_INITIATE;
	session->js = js;
	session->remote_jid = jid;
	session_data = g_new0(GoogleAVSessionData, 1);
	session->session_data = session_data;

	if (type & PURPLE_MEDIA_VIDEO)
		session_data->video = TRUE;

	/* if we got a relay token and relay host in google:jingleinfo, issue an
	 HTTP request to get that data */
	if (js->google_relay_host && js->google_relay_token) {
		jabber_google_do_relay_request(js, session,
			jabber_google_relay_response_session_initiate_cb);
	} else {
		jabber_google_relay_response_session_initiate_cb(session, NULL, 0, 0, 0,
			NULL, NULL);
	}

	/* we don't actually know yet wether it succeeded... maybe this is very
	 wrong... */
	return TRUE;
}

static void
jabber_google_relay_response_session_handle_initiate_cb(GoogleSession *session,
    const gchar *relay_ip, guint relay_udp, guint relay_tcp, guint relay_ssltcp,
    const gchar *relay_username, const gchar *relay_password)
{
	GParameter *params;
	guint num_params;
	JabberStream *js = session->js;
	xmlnode *codec_element;
	const gchar *xmlns;
	PurpleMediaCodec *codec;
	GList *video_codecs = NULL;
	GList *codecs = NULL;
	JabberIq *result;
	GoogleAVSessionData *session_data =
		(GoogleAVSessionData *) session->session_data;

	params =
		jabber_google_session_get_params(js, relay_ip, relay_udp, relay_tcp,
	    	relay_ssltcp, relay_username, relay_password, &num_params);

	if (purple_media_add_stream(session_data->media, "google-voice",
			session->remote_jid, PURPLE_MEDIA_AUDIO, FALSE,
			"nice", num_params, params) == FALSE ||
			(session_data->video && purple_media_add_stream(
			session_data->media, "google-video",
			session->remote_jid, PURPLE_MEDIA_VIDEO,
			FALSE, "nice", num_params, params) == FALSE)) {
		purple_media_error(session_data->media, "Error adding stream.");
		purple_media_stream_info(session_data->media,
				PURPLE_MEDIA_INFO_REJECT, NULL, NULL, TRUE);
	} else {
		/* successfully added stream(s) */
		session_data->added_streams = TRUE;

		if (session_data->remote_audio_candidates) {
			purple_media_add_remote_candidates(session_data->media,
				"google-voice", session->remote_jid,
			    session_data->remote_audio_candidates);
			purple_media_candidate_list_free(session_data->remote_audio_candidates);
			session_data->remote_audio_candidates = NULL;
		}
		if (session_data->remote_video_candidates) {
			purple_media_add_remote_candidates(session_data->media,
				"google-video", session->remote_jid,
			    session_data->remote_video_candidates);
			purple_media_candidate_list_free(session_data->remote_video_candidates);
			session_data->remote_video_candidates = NULL;
		}
	}

	g_free(params);

	for (codec_element = xmlnode_get_child(session->description, "payload-type");
	     codec_element; codec_element = codec_element->next) {
		const char *id, *encoding_name,  *clock_rate;
		gboolean video;
		if (codec_element->name &&
				strcmp(codec_element->name, "payload-type"))
			continue;

		xmlns = xmlnode_get_namespace(codec_element);
		encoding_name = xmlnode_get_attrib(codec_element, "name");
		id = xmlnode_get_attrib(codec_element, "id");

		if (!session_data->video ||
				(xmlns && !strcmp(xmlns, NS_GOOGLE_SESSION_PHONE))) {
			clock_rate = xmlnode_get_attrib(
					codec_element, "clockrate");
			video = FALSE;
		} else {
			/*width = xmlnode_get_attrib(codec_element, "width");
			height = xmlnode_get_attrib(codec_element, "height");
			framerate = xmlnode_get_attrib(
					codec_element, "framerate");*/
			clock_rate = "90000";
			video = TRUE;
		}

		if (id) {
			codec = purple_media_codec_new(atoi(id), encoding_name,
					video ?	PURPLE_MEDIA_VIDEO :
					PURPLE_MEDIA_AUDIO,
					clock_rate ? atoi(clock_rate) : 0);
			if (video)
				video_codecs = g_list_append(
						video_codecs, codec);
			else
				codecs = g_list_append(codecs, codec);
		}
	}

	if (codecs)
		purple_media_set_remote_codecs(session_data->media, "google-voice",
				session->remote_jid, codecs);
	if (video_codecs)
		purple_media_set_remote_codecs(session_data->media, "google-video",
				session->remote_jid, video_codecs);

	purple_media_codec_list_free(codecs);
	purple_media_codec_list_free(video_codecs);

	result = jabber_iq_new(js, JABBER_IQ_RESULT);
	jabber_iq_set_id(result, session->iq_id);
	xmlnode_set_attrib(result->node, "to", session->remote_jid);
	jabber_iq_send(result);
}

static gboolean
google_session_handle_initiate(JabberStream *js, GoogleSession *session, xmlnode *sess, const char *iq_id)
{
	const gchar *xmlns;
	GoogleAVSessionData *session_data =
		(GoogleAVSessionData *) session->session_data;

	if (session->state != UNINIT) {
		purple_debug_error("jabber", "Received initiate for active session.\n");
		return FALSE;
	}

	session->description = xmlnode_copy(xmlnode_get_child(sess, "description"));
	xmlns = xmlnode_get_namespace(session->description);

	if (purple_strequal(xmlns, NS_GOOGLE_SESSION_PHONE))
		session_data->video = FALSE;
	else if (purple_strequal(xmlns, NS_GOOGLE_SESSION_VIDEO))
		session_data->video = TRUE;
	else {
		purple_debug_error("jabber", "Received initiate with "
				"invalid namespace %s.\n", xmlns);
		return FALSE;
	}

	session_data->media = purple_media_manager_create_media(
			purple_media_manager_get(),
			purple_connection_get_account(js->gc),
			"fsrtpconference", session->remote_jid, FALSE);

	purple_media_set_prpl_data(session_data->media, session);

	g_signal_connect_swapped(G_OBJECT(session_data->media),
			"candidates-prepared",
			G_CALLBACK(google_session_ready), session);
	g_signal_connect_swapped(G_OBJECT(session_data->media), "codecs-changed",
			G_CALLBACK(google_session_ready), session);
	g_signal_connect(G_OBJECT(session_data->media), "state-changed",
			G_CALLBACK(google_session_state_changed_cb), session);
	g_signal_connect(G_OBJECT(session_data->media), "stream-info",
			G_CALLBACK(google_session_stream_info_cb), session);

	session->iq_id = g_strdup(iq_id);

	if (js->google_relay_host && js->google_relay_token) {
		jabber_google_do_relay_request(js, session,
			jabber_google_relay_response_session_handle_initiate_cb);
	} else {
		jabber_google_relay_response_session_handle_initiate_cb(session, NULL,
			0, 0, 0, NULL, NULL);
	}

	return TRUE;
}


static void
google_session_handle_candidates(JabberStream  *js, GoogleSession *session, xmlnode *sess, const char *iq_id)
{
	JabberIq *result;
	GList *list = NULL, *video_list = NULL;
	xmlnode *cand;
	static int name = 0;
	char n[4];
	GoogleAVSessionData *session_data =
		(GoogleAVSessionData *) session->session_data;

	for (cand = xmlnode_get_child(sess, "candidate"); cand;
			cand = xmlnode_get_next_twin(cand)) {
		PurpleMediaCandidate *info;
		const gchar *cname = xmlnode_get_attrib(cand, "name");
		const gchar *type = xmlnode_get_attrib(cand, "type");
		const gchar *protocol = xmlnode_get_attrib(cand, "protocol");
		const gchar *address = xmlnode_get_attrib(cand, "address");
		const gchar *port = xmlnode_get_attrib(cand, "port");
		const gchar *preference = xmlnode_get_attrib(cand, "preference");
		guint component_id;

		if (cname && type && address && port) {
			PurpleMediaCandidateType candidate_type;
			guint prio = preference ? g_ascii_strtod(preference, NULL) * 1000 : 0;

			g_snprintf(n, sizeof(n), "S%d", name++);

			if (g_str_equal(type, "local"))
				candidate_type = PURPLE_MEDIA_CANDIDATE_TYPE_HOST;
			else if (g_str_equal(type, "stun"))
				candidate_type = PURPLE_MEDIA_CANDIDATE_TYPE_PRFLX;
			else if (g_str_equal(type, "relay"))
				candidate_type = PURPLE_MEDIA_CANDIDATE_TYPE_RELAY;
			else
				candidate_type = PURPLE_MEDIA_CANDIDATE_TYPE_HOST;

			if (purple_strequal(cname, "rtcp") ||
					purple_strequal(cname, "video_rtcp"))
				component_id = PURPLE_MEDIA_COMPONENT_RTCP;
			else
				component_id = PURPLE_MEDIA_COMPONENT_RTP;

			info = purple_media_candidate_new(n, component_id,
					candidate_type,
					purple_strequal(protocol, "udp") ?
							PURPLE_MEDIA_NETWORK_PROTOCOL_UDP :
							PURPLE_MEDIA_NETWORK_PROTOCOL_TCP,
					address,
					atoi(port));
			g_object_set(info, "username", xmlnode_get_attrib(cand, "username"),
					"password", xmlnode_get_attrib(cand, "password"),
			        "priority", prio, NULL);
			if (!strncmp(cname, "video_", 6)) {
				if (session_data->added_streams) {
					video_list = g_list_append(video_list, info);
				} else {
					session_data->remote_video_candidates =
						g_list_append(session_data->remote_video_candidates,
							info);
				}
			} else {
				if (session_data->added_streams) {
					list = g_list_append(list, info);
				} else {
					session_data->remote_audio_candidates =
						g_list_append(session_data->remote_audio_candidates,
							info);
				}
			}
		}
	}

	if (list) {
		purple_media_add_remote_candidates(session_data->media, "google-voice",
			session->remote_jid, list);
		purple_media_candidate_list_free(list);
	}
	if (video_list) {
		purple_media_add_remote_candidates(session_data->media, "google-video",
			session->remote_jid, video_list);
		purple_media_candidate_list_free(video_list);
	}

	result = jabber_iq_new(js, JABBER_IQ_RESULT);
	jabber_iq_set_id(result, iq_id);
	xmlnode_set_attrib(result->node, "to", session->remote_jid);
	jabber_iq_send(result);
}

static void
google_session_handle_accept(JabberStream *js, GoogleSession *session, xmlnode *sess, const char *iq_id)
{
	xmlnode *desc_element = xmlnode_get_child(sess, "description");
	xmlnode *codec_element = xmlnode_get_child(
			desc_element, "payload-type");
	GList *codecs = NULL, *video_codecs = NULL;
	JabberIq *result = NULL;
	const gchar *xmlns = xmlnode_get_namespace(desc_element);
	gboolean video = (xmlns && !strcmp(xmlns, NS_GOOGLE_SESSION_VIDEO));
	GoogleAVSessionData *session_data =
		(GoogleAVSessionData *) session->session_data;

	for (; codec_element; codec_element = codec_element->next) {
		const gchar *xmlns, *encoding_name, *id,
				*clock_rate;
		gboolean video_codec = FALSE;

		if (!purple_strequal(codec_element->name, "payload-type"))
			continue;

		xmlns = xmlnode_get_namespace(codec_element);
		encoding_name =	xmlnode_get_attrib(codec_element, "name");
		id = xmlnode_get_attrib(codec_element, "id");

		if (!video || purple_strequal(xmlns, NS_GOOGLE_SESSION_PHONE))
			clock_rate = xmlnode_get_attrib(
					codec_element, "clockrate");
		else {
			clock_rate = "90000";
			/*width = xmlnode_get_attrib(codec_element, "width");
			height = xmlnode_get_attrib(codec_element, "height");
			framerate = xmlnode_get_attrib(
					codec_element, "framerate");*/
			video_codec = TRUE;
		}

		if (id && encoding_name) {
			PurpleMediaCodec *codec = purple_media_codec_new(
					atoi(id), encoding_name,
					video_codec ? PURPLE_MEDIA_VIDEO :
					PURPLE_MEDIA_AUDIO,
					clock_rate ? atoi(clock_rate) : 0);
			if (video_codec)
				video_codecs = g_list_append(
						video_codecs, codec);
			else
				codecs = g_list_append(codecs, codec);
		}
	}

	if (codecs)
		purple_media_set_remote_codecs(session_data->media, "google-voice",
				session->remote_jid, codecs);
	if (video_codecs)
		purple_media_set_remote_codecs(session_data->media, "google-video",
				session->remote_jid, video_codecs);

	purple_media_stream_info(session_data->media, PURPLE_MEDIA_INFO_ACCEPT,
			NULL, NULL, FALSE);

	result = jabber_iq_new(js, JABBER_IQ_RESULT);
	jabber_iq_set_id(result, iq_id);
	xmlnode_set_attrib(result->node, "to", session->remote_jid);
	jabber_iq_send(result);
}

static void
google_session_handle_reject(JabberStream *js, GoogleSession *session, xmlnode *sess)
{
	GoogleAVSessionData *session_data =
		(GoogleAVSessionData *) session->session_data;
	purple_media_end(session_data->media, NULL, NULL);
}

static void
google_session_handle_terminate(JabberStream *js, GoogleSession *session, xmlnode *sess)
{
	GoogleAVSessionData *session_data =
		(GoogleAVSessionData *) session->session_data;
	purple_media_end(session_data->media, NULL, NULL);
}

static void
google_session_parse_iq(JabberStream *js, GoogleSession *session, xmlnode *sess, const char *iq_id)
{
	const char *type = xmlnode_get_attrib(sess, "type");

	if (!strcmp(type, "initiate")) {
		google_session_handle_initiate(js, session, sess, iq_id);
	} else if (!strcmp(type, "accept")) {
		google_session_handle_accept(js, session, sess, iq_id);
	} else if (!strcmp(type, "reject")) {
		google_session_handle_reject(js, session, sess);
	} else if (!strcmp(type, "terminate")) {
		google_session_handle_terminate(js, session, sess);
	} else if (!strcmp(type, "candidates")) {
		google_session_handle_candidates(js, session, sess, iq_id);
	}
}

void
jabber_google_session_parse(JabberStream *js, const char *from,
                            JabberIqType type, const char *iq_id,
                            xmlnode *session_node)
{
	GoogleSession *session = NULL;
	GoogleSessionId id;

	xmlnode *desc_node;

	GList *iter = NULL;

	if (type != JABBER_IQ_SET)
		return;

	id.id = (gchar*)xmlnode_get_attrib(session_node, "id");
	if (!id.id)
		return;

	id.initiator = (gchar*)xmlnode_get_attrib(session_node, "initiator");
	if (!id.initiator)
		return;

	iter = purple_media_manager_get_media_by_account(
			purple_media_manager_get(),
			purple_connection_get_account(js->gc));
	for (; iter; iter = g_list_delete_link(iter, iter)) {
		GoogleSession *gsession =
				purple_media_get_prpl_data(iter->data);
		if (google_session_id_equal(&(gsession->id), &id)) {
			session = gsession;
			break;
		}
	}
	if (iter != NULL) {
		g_list_free(iter);
	}

	if (session) {
		google_session_parse_iq(js, session, session_node, iq_id);
		return;
	}

	/* If the session doesn't exist, this has to be an initiate message */
	if (strcmp(xmlnode_get_attrib(session_node, "type"), "initiate"))
		return;
	desc_node = xmlnode_get_child(session_node, "description");
	if (!desc_node)
		return;
	session = g_new0(GoogleSession, 1);
	session->id.id = g_strdup(id.id);
	session->id.initiator = g_strdup(id.initiator);
	session->state = UNINIT;
	session->js = js;
	session->remote_jid = g_strdup(session->id.initiator);
	session->session_data = g_new0(GoogleAVSessionData, 1);

	google_session_handle_initiate(js, session, session_node, iq_id);
}
#endif /* USE_VV */


