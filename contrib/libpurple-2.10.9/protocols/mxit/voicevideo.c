/*
 *					MXit Protocol libPurple Plugin
 *
 *						-- voice & video --
 *
 *				Andrew Victor	<libpurple@mxit.com>
 *
 *			(C) Copyright 2010	MXit Lifestyle (Pty) Ltd.
 *				<http://www.mxitlifestyle.com>
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

#include "mxit.h"
#include "roster.h"
#include "voicevideo.h"

#if defined(USE_VV) && defined(MXIT_DEV_VV)

#warning "MXit VV support enabled."

/*------------------------------------------------------------------------
 * Does this client support Voice?
 */
gboolean mxit_audio_enabled(void)
{
    PurpleMediaManager *manager = purple_media_manager_get();
    PurpleMediaCaps caps = purple_media_manager_get_ui_caps(manager);

    return (caps & PURPLE_MEDIA_CAPS_AUDIO);
}

/*------------------------------------------------------------------------
 * Does this client support Voice and Video?
 */
gboolean mxit_video_enabled(void)
{
    PurpleMediaManager *manager = purple_media_manager_get();
    PurpleMediaCaps caps = purple_media_manager_get_ui_caps(manager);

    return (caps & PURPLE_MEDIA_CAPS_VIDEO);
}

/*------------------------------------------------------------------------
 * Return the list of media capabilities this contact supports.
 *
 *  @param account		The MXit account object
 *  @param who			The username of the contact.
 *  @return				The media capabilities supported
 */
PurpleMediaCaps mxit_media_caps(PurpleAccount *account, const char *who)
{
	struct MXitSession*	session	= purple_connection_get_protocol_data(purple_account_get_connection(account));
	PurpleBuddy*		buddy;
	struct contact*		contact;
	PurpleMediaCaps		capa	= PURPLE_MEDIA_CAPS_NONE;

	purple_debug_info(MXIT_PLUGIN_ID, "mxit_media_caps: buddy '%s'\n", who);

	/* We need to have a voice/video server */
	if (strlen(session->voip_server) == 0)
		return PURPLE_MEDIA_CAPS_NONE;

	/* find the buddy information for this contact (reference: "libpurple/blist.h") */
	buddy = purple_find_buddy(account, who);
	if (!buddy) {
		purple_debug_warning(MXIT_PLUGIN_ID, "mxit_media_caps: unable to find the buddy '%s'\n", who);
		return PURPLE_MEDIA_CAPS_NONE;
	}

	contact = purple_buddy_get_protocol_data(buddy);
	if (!contact)
		return PURPLE_MEDIA_CAPS_NONE;

	/* can only communicate with MXit users */
	if (contact->type != MXIT_TYPE_MXIT)
		return PURPLE_MEDIA_CAPS_NONE;

	/* and only with contacts in the 'Both' subscription state */
	if (contact->subtype != MXIT_SUBTYPE_BOTH)
		return PURPLE_MEDIA_CAPS_NONE;

	/* and only when they're online */
	if (contact->presence == MXIT_PRESENCE_OFFLINE)
		return PURPLE_MEDIA_CAPS_NONE;

	/* they support voice-only */
	if (contact->capabilities & MXIT_PFLAG_VOICE)
		capa |= PURPLE_MEDIA_CAPS_AUDIO;

	/* they support voice-and-video */
	if (contact->capabilities & MXIT_PFLAG_VIDEO)
		capa |= (PURPLE_MEDIA_CAPS_AUDIO | PURPLE_MEDIA_CAPS_VIDEO | PURPLE_MEDIA_CAPS_AUDIO_VIDEO);

	return capa;
}


static void mxit_candidates_prepared_cb(PurpleMedia* media, gchar* sessionid, gchar* who, void* session)
{
	purple_debug_info(MXIT_PLUGIN_ID, "mxit_candidates_prepared_cb: buddy '%s', session '%s'\n", who, sessionid);

	if (purple_media_is_initiator(media, sessionid, who)) {
		// TODO: Send INVITE via SIP.
	}
	else {
		// TODO: ??
	}
}

static void mxit_stream_info_cb(PurpleMedia* media, PurpleMediaInfoType type, char* sessionid, gchar* who, gboolean local, void* session)
{
	purple_debug_info(MXIT_PLUGIN_ID, "mxit_stream_info_cb: buddy '%s', session '%s', info %d \n", who, sessionid, type);

	switch (type) {
		case PURPLE_MEDIA_INFO_HANGUP:
			break;
		case PURPLE_MEDIA_INFO_ACCEPT:
			break;
		case PURPLE_MEDIA_INFO_REJECT:
			break;
		case PURPLE_MEDIA_INFO_MUTE:
			break;
		case PURPLE_MEDIA_INFO_UNMUTE:
			break;
		case PURPLE_MEDIA_INFO_PAUSE:
			break;
		case PURPLE_MEDIA_INFO_UNPAUSE:
			break;
		case PURPLE_MEDIA_INFO_HOLD:
			break;
		case PURPLE_MEDIA_INFO_UNHOLD:
			break;
	}
}

static void mxit_state_changed_cb(PurpleMedia* media, PurpleMediaState state, gchar* sessionid, char* who, void* session)
{
	purple_debug_info(MXIT_PLUGIN_ID, "mxit_state_changed_cb: buddy '%s', session '%s', state %d\n", who, sessionid, state);

	switch (state) {
		case PURPLE_MEDIA_STATE_NEW:
			break;
		case PURPLE_MEDIA_STATE_CONNECTED:
			break;
		case PURPLE_MEDIA_STATE_END:
			break;
	}
}


/*------------------------------------------------------------------------
 * Initiate a voice/video session with a contact.
 *
 *  @param account		The MXit account object
 *  @param who			The username of the contact.
 *  @param type			The type of media session to initiate
 *  @return				TRUE if session was initiated
 */
gboolean mxit_media_initiate(PurpleAccount *account, const char *who, PurpleMediaSessionType type)
{
	gchar* transmitter = "rawudp";
	PurpleMedia* media = NULL;

	purple_debug_info(MXIT_PLUGIN_ID, "mxit_media_initiate: buddy '%s'\n", who);

	media = purple_media_manager_create_media(
		purple_media_manager_get(),
		account,
		"fsrtpconference",
		who,
		TRUE
	);

	if (!media) {
		purple_debug_info(MXIT_PLUGIN_ID, "mxit_media_initiate: could not create media session\n");
		return FALSE;
	}

	/* attach callbacks */
	g_signal_connect(G_OBJECT(media), "candidates-prepared", G_CALLBACK(mxit_candidates_prepared_cb), NULL);
	g_signal_connect(G_OBJECT(media), "stream-info", G_CALLBACK(mxit_stream_info_cb), NULL);
	g_signal_connect(G_OBJECT(media), "state-changed", G_CALLBACK(mxit_state_changed_cb), NULL);

	/* initiate audio session */
	if ((type & PURPLE_MEDIA_AUDIO) &&
			(!purple_media_add_stream(media, "audio", who, PURPLE_MEDIA_AUDIO, TRUE, transmitter, 0, NULL))) {
		purple_media_end(media, NULL, NULL);
		return FALSE;
	}

	/* initiate video session */
	if ((type & PURPLE_MEDIA_VIDEO) &&
			(!purple_media_add_stream(media, "video", who, PURPLE_MEDIA_VIDEO, TRUE, transmitter, 0, NULL))) {
		purple_media_end(media, NULL, NULL);
		return FALSE;
	}

	return TRUE;
}

#else

/*
 * Voice and Video not supported.
 */

gboolean mxit_audio_enabled(void)
{
    return FALSE;
}

gboolean mxit_video_enabled(void)
{
	return FALSE;
}

PurpleMediaCaps mxit_media_caps(PurpleAccount *account, const char *who)
{
	return PURPLE_MEDIA_CAPS_NONE;
}

gboolean mxit_media_initiate(PurpleAccount *account, const char *who, PurpleMediaSessionType type)
{
	return FALSE;
}

#endif

