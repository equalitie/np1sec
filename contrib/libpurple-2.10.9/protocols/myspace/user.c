/* MySpaceIM Protocol Plugin, header file
 *
 * Copyright (C) 2007, Jeff Connelly <jeff2@soc.pidgin.im>
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

#include "myspace.h"

static void msim_check_username_availability_cb(PurpleConnection *gc, const char *username_to_check);

static char *msim_username_to_set;

/**
 * Format the "now playing" indicator, showing the artist and song.
 *
 * @return Return a new string (must be g_free()'d), or NULL.
 */
static gchar *
msim_format_now_playing(const gchar *band, const gchar *song)
{
	if ((band && *band) || (song && *song)) {
		return g_strdup_printf("%s - %s",
			(band && *band) ? band : "Unknown Artist",
			(song && *song) ? song : "Unknown Song");
	} else {
		return NULL;
	}
}

/**
 * Get the MsimUser from a PurpleBuddy, optionally creating it if needed.
 */
MsimUser *
msim_get_user_from_buddy(PurpleBuddy *buddy, gboolean create)
{
	MsimUser *user;

	if (!buddy) {
		return NULL;
	}

	user = purple_buddy_get_protocol_data(buddy);
	if (create && !user) {
		PurpleBlistNode *node = PURPLE_BLIST_NODE(buddy);

		/* No MsimUser for this buddy; make one. */

		user = g_new0(MsimUser, 1);
		user->buddy = buddy;
		user->id = purple_blist_node_get_int(node, "UserID");
		purple_buddy_set_protocol_data(buddy, user);
	}

	return user;
}

void msim_user_free(MsimUser *user)
{
	if (!user)
		return;

	if (user->url_data != NULL)
		purple_util_fetch_url_cancel(user->url_data);

	g_free(user->client_info);
	g_free(user->gender);
	g_free(user->location);
	g_free(user->headline);
	g_free(user->display_name);
	g_free(user->username);
	g_free(user->band_name);
	g_free(user->song_name);
	g_free(user->image_url);
	g_free(user);
}

/**
 * Find and return an MsimUser * representing a user on the buddy list, or NULL.
 */
MsimUser *
msim_find_user(MsimSession *session, const gchar *username)
{
	PurpleBuddy *buddy;

	buddy = purple_find_buddy(session->account, username);
	if (!buddy) {
		return NULL;
	}

	return msim_get_user_from_buddy(buddy, TRUE);
}

/**
 * Append user information to a PurpleNotifyUserInfo, given an MsimUser.
 * Used by msim_tooltip_text() and msim_get_info_cb() to show a user's profile.
 */
void
msim_append_user_info(MsimSession *session, PurpleNotifyUserInfo *user_info, MsimUser *user, gboolean full)
{
	PurplePresence *presence;
	gchar *str;
	guint cv;

	/* Useful to identify the account the tooltip refers to.
	 *  Other prpls show this. */
	if (user->username) {
		purple_notify_user_info_add_pair(user_info, _("User"), user->username);
	}

	/* a/s/l...the vitals */
	if (user->age) {
		char age[16];
		g_snprintf(age, sizeof(age), "%d", user->age);
		purple_notify_user_info_add_pair(user_info, _("Age"), age);
	}

	if (user->gender && *user->gender) {
		purple_notify_user_info_add_pair(user_info, _("Gender"), user->gender);
	}

	if (user->location && *user->location) {
		purple_notify_user_info_add_pair(user_info, _("Location"), user->location);
	}

	/* Other information */
	if (user->headline && *user->headline) {
		purple_notify_user_info_add_pair(user_info, _("Headline"), user->headline);
	}

	if (user->buddy != NULL) {
		presence = purple_buddy_get_presence(user->buddy);

		if (purple_presence_is_status_primitive_active(presence, PURPLE_STATUS_TUNE)) {
			PurpleStatus *status;
			const char *artist, *title;

			status = purple_presence_get_status(presence, "tune");
			title = purple_status_get_attr_string(status, PURPLE_TUNE_TITLE);
			artist = purple_status_get_attr_string(status, PURPLE_TUNE_ARTIST);

			str = msim_format_now_playing(artist, title);
			if (str && *str) {
				purple_notify_user_info_add_pair(user_info, _("Song"), str);
			}
			g_free(str);
		}
	}

	/* Note: total friends only available if looked up by uid, not username. */
	if (user->total_friends) {
		char friends[16];
		g_snprintf(friends, sizeof(friends), "%d", user->total_friends);
		purple_notify_user_info_add_pair(user_info, _("Total Friends"), friends);
	}

	if (full) {
		/* Client information */
		char *client = NULL;

		str = user->client_info;
		cv = user->client_cv;

		if (str && cv != 0) {
			client = g_strdup_printf("%s (build %d)", str, cv);
		} else if (str) {
			client = g_strdup(str);
		} else if (cv) {
			client = g_strdup_printf("Build %d", cv);
		}
		if (client && *client)
			purple_notify_user_info_add_pair(user_info, _("Client Version"), client);
		g_free(client);
	}

	if (full && user->id) {
		/* TODO: link to username, if available */
		char *profile;
		purple_notify_user_info_add_section_break(user_info);
		if (user->buddy != NULL)
			profile = g_strdup_printf("<a href=\"http://myspace.com/%s\">%s</a>",
					purple_buddy_get_name(user->buddy), _("View web profile"));
		else
			profile = g_strdup_printf("<a href=\"http://myspace.com/%d\">%s</a>",
					user->id, _("View web profile"));
		purple_notify_user_info_add_pair(user_info, NULL, profile);
		g_free(profile);
	}
}

/**
 * Callback for when a buddy icon finished being downloaded.
 */
static void
msim_downloaded_buddy_icon(PurpleUtilFetchUrlData *url_data,
		gpointer user_data,
		const gchar *url_text,
		gsize len,
		const gchar *error_message)
{
	MsimUser *user = (MsimUser *)user_data;
	const char *name = purple_buddy_get_name(user->buddy);
	PurpleAccount *account;

	user->url_data = NULL;

	purple_debug_info("msim_downloaded_buddy_icon",
			"Downloaded %" G_GSIZE_FORMAT " bytes\n", len);

	if (!url_text) {
		purple_debug_info("msim_downloaded_buddy_icon",
				"failed to download icon for %s",
				name);
		return;
	}

	account = purple_buddy_get_account(user->buddy);
	purple_buddy_icons_set_for_user(account, name,
			g_memdup((gchar *)url_text, len), len,
			/* Use URL itself as buddy icon "checksum" (TODO: ETag) */
			user->image_url);		/* checksum */
}

/**
 * Set the currently playing song artist and or title.
 *
 * @param user User associated with the now playing information.
 *
 * @param new_artist New artist to set, or NULL/empty to not change artist.
 *
 * @param new_title New title to set, or NULL/empty to not change title.
 *
 * If new_artist and new_title are NULL/empty, deactivate PURPLE_STATUS_TUNE.
 *
 * This function is useful because it lets you set the artist or title
 * individually, which purple_prpl_got_user_status() doesn't do.
 */
static void msim_set_artist_or_title(MsimUser *user, const char *new_artist, const char *new_title)
{
	PurplePresence *presence;
	PurpleAccount *account;
	const char *prev_artist, *prev_title;
	const char *name;

	if (user->buddy == NULL)
		/* User not on buddy list so nothing to do */
		return;

	prev_artist = NULL;
	prev_title = NULL;

	if (new_artist && !*new_artist)
		new_artist = NULL;
	if (new_title && !*new_title)
		new_title = NULL;

	account = purple_buddy_get_account(user->buddy);
	name = purple_buddy_get_name(user->buddy);

	if (!new_artist && !new_title) {
		purple_prpl_got_user_status_deactive(account, name, "tune");
		return;
	}

	presence = purple_buddy_get_presence(user->buddy);

	if (purple_presence_is_status_primitive_active(presence, PURPLE_STATUS_TUNE)) {
		PurpleStatus *status;

		status = purple_presence_get_status(presence, "tune");
		prev_title = purple_status_get_attr_string(status, PURPLE_TUNE_TITLE);
		prev_artist = purple_status_get_attr_string(status, PURPLE_TUNE_ARTIST);
	}

	if (!new_artist)
		new_artist = prev_artist;

	if (!new_title)
		new_title = prev_title;

	purple_prpl_got_user_status(account, name, "tune",
			PURPLE_TUNE_TITLE, new_title,
			PURPLE_TUNE_ARTIST, new_artist,
			NULL);
}

/**
 * Store a field of information about a buddy.
 *
 * @param key_str Key to store.
 * @param value_str Value string, either user takes ownership of this string
 *                  or it is freed if MsimUser doesn't store the string.
 * @param user User to store data in. Existing data will be replaced.
 */
static void
msim_store_user_info_each(const gchar *key_str, gchar *value_str, MsimUser *user)
{
	const char *name = user->buddy ? purple_buddy_get_name(user->buddy) : NULL;

	if (g_str_equal(key_str, "UserID") || g_str_equal(key_str, "ContactID")) {
		/* Save to buddy list, if it exists, for quick cached uid lookup with msim_uid2username_from_blist(). */
		user->id = atol(value_str);
		g_free(value_str);
		if (user->buddy)
		{
			purple_debug_info("msim", "associating uid %s with username %s\n", key_str, name);
			purple_blist_node_set_int(PURPLE_BLIST_NODE(user->buddy), "UserID", user->id);
		}
		/* Need to store in MsimUser, too? What if not on blist? */
	} else if (g_str_equal(key_str, "Age")) {
		user->age = atol(value_str);
		g_free(value_str);
	} else if (g_str_equal(key_str, "Gender")) {
		g_free(user->gender);
		user->gender = value_str;
	} else if (g_str_equal(key_str, "Location")) {
		g_free(user->location);
		user->location = value_str;
	} else if (g_str_equal(key_str, "TotalFriends")) {
		user->total_friends = atol(value_str);
		g_free(value_str);
	} else if (g_str_equal(key_str, "DisplayName")) {
		g_free(user->display_name);
		user->display_name = value_str;
	} else if (g_str_equal(key_str, "BandName")) {
		msim_set_artist_or_title(user, value_str, NULL);
		g_free(value_str);
	} else if (g_str_equal(key_str, "SongName")) {
		msim_set_artist_or_title(user, NULL, value_str);
		g_free(value_str);
	} else if (g_str_equal(key_str, "UserName") || g_str_equal(key_str, "IMName") || g_str_equal(key_str, "NickName")) {
		/* Ignore because PurpleBuddy knows this already */
		g_free(value_str);
	} else if (g_str_equal(key_str, "ImageURL") || g_str_equal(key_str, "AvatarURL")) {
		const gchar *previous_url;

		if (user->temporary_user) {
			/* This user will be destroyed soon; don't try to look up its image or avatar,
			 * since that won't return immediately and we will end up accessing freed data.
			 */
			g_free(value_str);
			return;
		}

		g_free(user->image_url);

		user->image_url = value_str;

		/* Instead of showing 'no photo' picture, show nothing. */
		if (g_str_equal(user->image_url, "http://x.myspace.com/images/no_pic.gif"))
		{
			purple_buddy_icons_set_for_user(purple_buddy_get_account(user->buddy),
				name, NULL, 0, NULL);
			return;
		}

		/* TODO: use ETag for checksum */
		previous_url = purple_buddy_icons_get_checksum_for_user(user->buddy);

		/* Only download if URL changed */
		if (!previous_url || !g_str_equal(previous_url, user->image_url)) {
			if (user->url_data != NULL)
				purple_util_fetch_url_cancel(user->url_data);
			user->url_data = purple_util_fetch_url(user->image_url, TRUE, NULL, TRUE, msim_downloaded_buddy_icon, (gpointer)user);
		}
	} else if (g_str_equal(key_str, "LastImageUpdated")) {
		/* TODO: use somewhere */
		user->last_image_updated = atol(value_str);
		g_free(value_str);
	} else if (g_str_equal(key_str, "Headline")) {
		g_free(user->headline);
		user->headline = value_str;
	} else {
		/* TODO: other fields in MsimUser */
		gchar *msg;

		msg = g_strdup_printf("msim_store_user_info_each: unknown field %s=%s",
				key_str, value_str);
		g_free(value_str);

		msim_unrecognized(NULL, NULL, msg);

		g_free(msg);
	}
}

/**
 * Save buddy information to the buddy list from a user info reply message.
 *
 * @param session
 * @param msg The user information reply, with any amount of information.
 * @param user The structure to save to, or NULL to save in PurpleBuddy->proto_data.
 *
 * Variable information is saved to the passed MsimUser structure. Permanent
 * information (UserID) is stored in the blist node of the buddy list (and
 * ends up in blist.xml, persisted to disk) if it exists.
 *
 * If the function has no buddy information, this function
 * is a no-op (and returns FALSE).
 */
gboolean
msim_store_user_info(MsimSession *session, const MsimMessage *msg, MsimUser *user)
{
	gchar *username;
	MsimMessage *body, *body_node;

	g_return_val_if_fail(msg != NULL, FALSE);

	body = msim_msg_get_dictionary(msg, "body");
	if (!body) {
		return FALSE;
	}

	if (msim_msg_get_integer(msg, "dsn") == MG_OWN_IM_INFO_DSN &&
		msim_msg_get_integer(msg, "lid") == MG_OWN_IM_INFO_LID)
	{
		/*
		 * Some of this info will be available on the buddy list if the
		 * user has themselves as their own buddy.
		 *
		 * Much of the info is already available in MsimSession,
		 * stored in msim_we_are_logged_on().
		 */
		gchar *tmpstr;

		tmpstr = msim_msg_get_string(body, "ShowOnlyToList");
		if (tmpstr != NULL) {
			session->show_only_to_list = g_str_equal(tmpstr, "True");
			g_free(tmpstr);
		}

		session->privacy_mode = msim_msg_get_integer(body, "PrivacyMode");
		session->offline_message_mode = msim_msg_get_integer(body, "OfflineMessageMode");

		msim_send(session,
				"blocklist", MSIM_TYPE_BOOLEAN, TRUE,
				"sesskey", MSIM_TYPE_INTEGER, session->sesskey,
				"idlist", MSIM_TYPE_STRING,
						g_strdup_printf("w%d|c%d",
								session->show_only_to_list ? 1 : 0,
								session->privacy_mode & 1),
				NULL);
	} else if (msim_msg_get_integer(msg, "dsn") == MG_OWN_MYSPACE_INFO_DSN &&
			msim_msg_get_integer(msg, "lid") == MG_OWN_MYSPACE_INFO_LID) {
		/* TODO: same as above, but for MySpace info. */
	}

	username = msim_msg_get_string(body, "UserName");

	if (!username) {
		purple_debug_info("msim",
			"msim_process_reply: not caching body, no UserName\n");
		msim_msg_free(body);
		g_free(username);
		return FALSE;
	}

	/* Null user = find and store in PurpleBuddy's proto_data */
	if (!user) {
		user = msim_find_user(session, username);
		if (!user) {
			msim_msg_free(body);
			g_free(username);
			return FALSE;
		}
	}

	/* TODO: make looping over MsimMessage's easier. */
	for (body_node = body;
		body_node != NULL;
		body_node = msim_msg_get_next_element_node(body_node))
	{
		const gchar *key_str;
		gchar *value_str;
		MsimMessageElement *elem;

		elem = (MsimMessageElement *)body_node->data;
		key_str = elem->name;

		value_str = msim_msg_get_string_from_element(elem);
		msim_store_user_info_each(key_str, value_str, user);
	}

	msim_msg_free(body);
	g_free(username);

	return TRUE;
}

#if 0
/**
 * Return whether a given username is syntactically valid.
 * Note: does not actually check that the user exists.
 */
static gboolean
msim_is_valid_username(const gchar *user)
{
	return !msim_is_userid(user) &&  /* Not all numeric */
		strlen(user) <= MSIM_MAX_USERNAME_LENGTH
		&& strspn(user, "0123456789"
			"abcdefghijklmnopqrstuvwxyz"
			"_"
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ") == strlen(user);
}
#endif

/**
 * Check if a string is a userid (all numeric).
 *
 * @param user The user id, email, or name.
 *
 * @return TRUE if is userid, FALSE if not.
 */
gboolean
msim_is_userid(const gchar *user)
{
	g_return_val_if_fail(user != NULL, FALSE);

	return strspn(user, "0123456789") == strlen(user);
}

/**
 * Check if a string is an email address (contains an @).
 *
 * @param user The user id, email, or name.
 *
 * @return TRUE if is an email, FALSE if not.
 *
 * This function is not intended to be used as a generic
 * means of validating email addresses, but to distinguish
 * between a user represented by an email address from
 * other forms of identification.
 */
static gboolean
msim_is_email(const gchar *user)
{
	g_return_val_if_fail(user != NULL, FALSE);

	return strchr(user, '@') != NULL;
}

/**
 * Asynchronously lookup user information, calling callback when receive result.
 *
 * @param session
 * @param user The user id, email address, or username. Not freed.
 * @param cb Callback, called with user information when available.
 * @param data An arbitray data pointer passed to the callback.
 */
/* TODO: change to not use callbacks */
void
msim_lookup_user(MsimSession *session, const gchar *user, MSIM_USER_LOOKUP_CB cb, gpointer data)
{
	MsimMessage *body;
	gchar *field_name;
	guint rid, dsn, lid;

	g_return_if_fail(user != NULL);
	/* Callback can be null to not call anything, just lookup & store information. */
	/*g_return_if_fail(cb != NULL);*/

	purple_debug_info("msim", "msim_lookup_userid: "
			"asynchronously looking up <%s>\n", user);

	/* Setup callback. Response will be associated with request using 'rid'. */
	rid = msim_new_reply_callback(session, cb, data);

	/* Send request */

	if (msim_is_userid(user)) {
		field_name = "UserID";
		dsn = MG_MYSPACE_INFO_BY_ID_DSN;
		lid = MG_MYSPACE_INFO_BY_ID_LID;
	} else if (msim_is_email(user)) {
		field_name = "Email";
		dsn = MG_MYSPACE_INFO_BY_STRING_DSN;
		lid = MG_MYSPACE_INFO_BY_STRING_LID;
	} else {
		field_name = "UserName";
		dsn = MG_MYSPACE_INFO_BY_STRING_DSN;
		lid = MG_MYSPACE_INFO_BY_STRING_LID;
	}

	body = msim_msg_new(
			field_name, MSIM_TYPE_STRING, g_strdup(user),
			NULL);

	g_return_if_fail(msim_send(session,
			"persist", MSIM_TYPE_INTEGER, 1,
			"sesskey", MSIM_TYPE_INTEGER, session->sesskey,
			"cmd", MSIM_TYPE_INTEGER, MSIM_CMD_GET,
			"dsn", MSIM_TYPE_INTEGER, dsn,
			"uid", MSIM_TYPE_INTEGER, session->userid,
			"lid", MSIM_TYPE_INTEGER, lid,
			"rid", MSIM_TYPE_INTEGER, rid,
			"body", MSIM_TYPE_DICTIONARY, body,
			NULL));
}

/**
 * Called after username is set.
 */
static void msim_username_is_set_cb(MsimSession *session, const MsimMessage *userinfo, gpointer data)
{
	gchar *username;
	const gchar *errmsg;
	MsimMessage *body;

	guint rid;
	gint cmd,dsn,uid,lid,code;
	/* \persistr\\cmd\258\dsn\9\uid\204084363\lid\14\rid\369\body\UserName=TheAlbinoRhino1.Code=0\final\ */

	purple_debug_info("msim","username_is_set made\n");

	cmd = msim_msg_get_integer(userinfo, "cmd");
	dsn = msim_msg_get_integer(userinfo, "dsn");
	uid = msim_msg_get_integer(userinfo, "uid");
	lid = msim_msg_get_integer(userinfo, "lid");
	body = msim_msg_get_dictionary(userinfo, "body");
	errmsg = _("An error occurred while trying to set the username.  "
			"Please try again, or visit http://editprofile.myspace.com/index.cfm?"
			"fuseaction=profile.username to set your username.");

	if (!body) {
		purple_debug_info("msim_username_is_set_cb", "No body");
		/* Error: No body! */
		purple_connection_error_reason(session->gc, PURPLE_CONNECTION_ERROR_OTHER_ERROR, errmsg);
	}
	username = msim_msg_get_string(body, "UserName");
	code = msim_msg_get_integer(body,"Code");

	msim_msg_free(body);

	purple_debug_info("msim_username_is_set_cb",
			"cmd = %d, dsn = %d, lid = %d, code = %d, username = %s\n",
			cmd, dsn, lid, code, username);

	if (cmd == (MSIM_CMD_BIT_REPLY | MSIM_CMD_PUT)
			&& dsn == MC_SET_USERNAME_DSN
			&& lid == MC_SET_USERNAME_LID)
	{
		purple_debug_info("msim_username_is_set_cb", "Proper cmd,dsn,lid for username_is_set!\n");
		purple_debug_info("msim_username_is_set_cb", "Username Set with return code %d\n",code);
		if (code == 0) {
			/* Good! */
			session->username = username;
			msim_we_are_logged_on(session);
		} else {
			purple_debug_info("msim_username_is_set", "code is %d",code);
			/* TODO: what to do here? */
		}
	} else if (cmd == (MSIM_CMD_BIT_REPLY | MSIM_CMD_GET)
			&& dsn == MG_MYSPACE_INFO_BY_STRING_DSN
			&& lid == MG_MYSPACE_INFO_BY_STRING_LID) {
		/* Not quite done... ONE MORE STEP :) */
		rid = msim_new_reply_callback(session, msim_username_is_set_cb, data);
		body = msim_msg_new("UserName", MSIM_TYPE_STRING, g_strdup(username), NULL);
		if (!msim_send(session, "persist", MSIM_TYPE_INTEGER, 1,
					"sesskey", MSIM_TYPE_INTEGER, session->sesskey,
					"cmd", MSIM_TYPE_INTEGER, MSIM_CMD_PUT,
					"dsn", MSIM_TYPE_INTEGER, MC_SET_USERNAME_DSN,
					"uid", MSIM_TYPE_INTEGER, session->userid,
					"lid", MSIM_TYPE_INTEGER, MC_SET_USERNAME_LID,
					"rid", MSIM_TYPE_INTEGER, rid,
					"body", MSIM_TYPE_DICTIONARY, body,
					NULL)) {
			/* Error! */
			/* Can't set... Disconnect */
			purple_connection_error_reason(session->gc, PURPLE_CONNECTION_ERROR_OTHER_ERROR, errmsg);
		}

	} else {
		/* Error! */
		purple_debug_info("msim","username_is_set Error: Invalid cmd/dsn/lid combination");
		purple_connection_error_reason(session->gc, PURPLE_CONNECTION_ERROR_OTHER_ERROR, errmsg);
	}
}

/**
 * Asynchronously set new username, calling callback when receive result.
 *
 * @param session
 * @param username The username we're setting for ourselves. Not freed.
 * @param cb Callback, called with user information when available.
 * @param data An arbitray data pointer passed to the callback.
 */
static void
msim_set_username(MsimSession *session, const gchar *username,
		MSIM_USER_LOOKUP_CB cb, gpointer data)
{
	MsimMessage *body;
	guint rid;

	g_return_if_fail(username != NULL);
	g_return_if_fail(cb != NULL);

	purple_debug_info("msim", "msim_set_username: "
			"Setting username %s\n", username);

	/* Setup callback. Response will be associated with request using 'rid'. */
	rid = msim_new_reply_callback(session, cb, data);

	/* TODO: I dont know if the ContactType is -/ALWAYS/- 1 */

	body = msim_msg_new("UserName", MSIM_TYPE_STRING, g_strdup(username),NULL);
/* \setinfo\\sesskey\469958979\info\Age=21.AvatarUrl=.BandName=.ContactType=1.DisplayName=Msim.Gender=M.ImageURL=http:/1/1x.myspace.com/1images/1no_pic.gif.LastLogin=128335268400000000.Location=US.ShowAvatar=False.SongName=.TotalFriends=1.UserName=msimprpl2\final\
*/

	/* Send request */
	g_return_if_fail(msim_send(session,
			 "setinfo", MSIM_TYPE_BOOLEAN, TRUE,
			 "sesskey", MSIM_TYPE_INTEGER, session->sesskey,
			 "info", MSIM_TYPE_DICTIONARY, body,
			 NULL));
	body = msim_msg_new("UserName", MSIM_TYPE_STRING, g_strdup(username),NULL);
	g_return_if_fail(msim_send(session,
			 "persist", MSIM_TYPE_INTEGER, 1,
			 "sesskey", MSIM_TYPE_INTEGER, session->sesskey,
			 "cmd", MSIM_TYPE_INTEGER, MSIM_CMD_GET,
			 "dsn", MSIM_TYPE_INTEGER, MG_MYSPACE_INFO_BY_STRING_DSN,
			 "uid", MSIM_TYPE_INTEGER, session->userid,
			 "lid", MSIM_TYPE_INTEGER, MG_MYSPACE_INFO_BY_STRING_LID,
			 "rid", MSIM_TYPE_INTEGER, rid,
			 "body", MSIM_TYPE_DICTIONARY, body,
			 NULL));
}

/**
 * They've confirmed that username that was available, Lets make the call to set it
 */
static void msim_set_username_confirmed_cb(PurpleConnection *gc)
{
	MsimMessage *user_msg;
	MsimSession *session;

	g_return_if_fail(gc != NULL);

	session = (MsimSession *)gc->proto_data;

	user_msg = msim_msg_new(
			"user", MSIM_TYPE_STRING, g_strdup(msim_username_to_set),
			NULL);

	purple_debug_info("msim_set_username_confirmed_cb", "Setting username to %s\n", msim_username_to_set);

	/* Sets our username... keep your fingers crossed :) */
	msim_set_username(session, msim_username_to_set, msim_username_is_set_cb, user_msg);
	g_free(msim_username_to_set);
}

/**
 * This is where we do a bit more than merely prompt the user.
 * Now we have some real data to tell us the state of their requested username
 * \persistr\\cmd\257\dsn\5\uid\204084363\lid\7\rid\367\body\UserName=TheAlbinoRhino1\final\
 */
static void msim_username_is_available_cb(MsimSession *session, const MsimMessage *userinfo, gpointer data)
{
	MsimMessage *msg;
	gchar *username;
	MsimMessage *body;
	gint userid;

	purple_debug_info("msim_username_is_available_cb", "Look up username callback made\n");

	msg = (MsimMessage *)data;
	g_return_if_fail(msg != NULL);

	username = msim_msg_get_string(msg, "user");
	body = msim_msg_get_dictionary(userinfo, "body");

	if (!body) {
		purple_debug_info("msim_username_is_available_cb", "No body for %s?!\n", username);
		purple_connection_error_reason(session->gc, PURPLE_CONNECTION_ERROR_OTHER_ERROR,
				_("An error occurred while trying to set the username.  "
				"Please try again, or visit http://editprofile.myspace.com/index.cfm?"
				"fuseaction=profile.username to set your username."));
		return;
	}

	userid = msim_msg_get_integer(body, "UserID");

	purple_debug_info("msim_username_is_available_cb", "Returned username is %s and userid is %d\n", username, userid);
	msim_msg_free(body);
	msim_msg_free(msg);

	/* The response for a free username will ONLY have the UserName in it..
	 * thus making UserID return 0 when we msg_get_integer it */
	if (userid == 0) {
		/* This username is currently unused */
		purple_debug_info("msim_username_is_available_cb", "Username available. Prompting to Confirm.\n");
		msim_username_to_set = g_strdup(username);
		g_free(username);
		purple_request_yes_no(session->gc,
			_("MySpaceIM - Username Available"),
			_("This username is available. Would you like to set it?"),
			_("ONCE SET, THIS CANNOT BE CHANGED!"),
			0,
			session->account,
			NULL,
			NULL,
			session->gc,
			G_CALLBACK(msim_set_username_confirmed_cb),
			G_CALLBACK(msim_do_not_set_username_cb));
	} else {
		/* Looks like its in use or we have an invalid response */
		purple_debug_info("msim_username_is_available_cb", "Username unavaiable. Prompting for new entry.\n");
		purple_request_input(session->gc, _("MySpaceIM - Please Set a Username"),
			_("This username is unavailable."),
				_("Please try another username:"),
				"", FALSE, FALSE, NULL,
				_("OK"), G_CALLBACK(msim_check_username_availability_cb),
				_("Cancel"), G_CALLBACK(msim_do_not_set_username_cb),
				session->account,
				NULL,
				NULL,
				session->gc);
	}
}

/**
 * Once they've submitted their desired new username,
 * check if it is available here.
 */
static void msim_check_username_availability_cb(PurpleConnection *gc, const char *username_to_check)
{
	MsimMessage *user_msg;
	MsimSession *session;

	g_return_if_fail(gc != NULL);

	session = (MsimSession *)gc->proto_data;

	purple_debug_info("msim_check_username_availability_cb", "Checking username: %s\n", username_to_check);

	user_msg = msim_msg_new(
			"user", MSIM_TYPE_STRING, g_strdup(username_to_check),
			NULL);

	/* 25 characters: letters, numbers, underscores */
	/* TODO: VERIFY ABOVE */

	/* \persist\1\sesskey\288500516\cmd\1\dsn\5\uid\204084363\lid\7\rid\367\body\UserName=Jaywalker\final\ */
	/* Official client uses a standard lookup... So do we! */
	msim_lookup_user(session, username_to_check, msim_username_is_available_cb, user_msg);
}

/***
 * If they hit cancel or no at any point in the Setting Username process,
 * we come here.  Currently we're safe letting them get by without
 * setting it, unless we hear otherwise.  So for now give them a menu.
 * If this becomes an issue with the official client then boot them here.
 */
void msim_do_not_set_username_cb(PurpleConnection *gc)
{
	purple_debug_info("msim", "Don't set username");

	/* Protocol won't log in now without a username set.. Disconnect */
	purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, _("No username set"));
}

/**
 * They've decided to set a username! Yay!
 */
void msim_set_username_cb(PurpleConnection *gc)
{
	g_return_if_fail(gc != NULL);
	purple_debug_info("msim","Set username\n");
	purple_request_input(gc, _("MySpaceIM - Please Set a Username"),
			_("Please enter a username to check its availability:"),
			NULL,
			"", FALSE, FALSE, NULL,
			_("OK"), G_CALLBACK(msim_check_username_availability_cb),
			_("Cancel"), G_CALLBACK(msim_do_not_set_username_cb),
			purple_connection_get_account(gc),
			NULL,
			NULL,
			gc);
}
