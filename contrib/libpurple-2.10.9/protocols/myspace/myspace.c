/**
 * MySpaceIM Protocol Plugin
 *
 * \author Jeff Connelly
 *
 * Copyright (C) 2007, Jeff Connelly <jeff2@soc.pidgin.im>
 *
 * Based on Purple's "C Plugin HOWTO" hello world example.
 *
 * Code also drawn from mockprpl:
 *  http://snarfed.org/space/purple+mock+protocol+plugin
 *  Copyright (C) 2004-2007, Ryan Barrett <mockprpl@ryanb.org>
 *
 * and some constructs also based on existing Purple plugins, which are:
 *   Copyright (C) 2003, Robbert Haarman <purple@inglorion.net>
 *   Copyright (C) 2003, Ethan Blanton <eblanton@cs.purdue.edu>
 *   Copyright (C) 2000-2003, Rob Flynn <rob@tgflinux.com>
 *   Copyright (C) 1998-1999, Mark Spencer <markster@marko.net>
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

#define PURPLE_PLUGIN

#include "myspace.h"

#include "privacy.h"

static void msim_set_status(PurpleAccount *account, PurpleStatus *status);
static void msim_set_idle(PurpleConnection *gc, int time);

/**
 * Perform actual postprocessing on a message, adding userid as specified.
 *
 * @param msg The message to postprocess.
 * @param uid_before Name of field where to insert new field before, or NULL for end.
 * @param uid_field_name Name of field to add uid to.
 * @param uid The userid to insert.
 *
 * If the field named by uid_field_name already exists, then its string contents will
 * be used for the field, except "<uid>" will be replaced by the userid.
 *
 * If the field named by uid_field_name does not exist, it will be added before the
 * field named by uid_before, as an integer, with the userid.
 *
 * Does not handle sending, or scheduling userid lookup. For that, see msim_postprocess_outgoing().
 */
static MsimMessage *
msim_do_postprocessing(MsimMessage *msg, const gchar *uid_before,
		const gchar *uid_field_name, guint uid)
{
	MsimMessageElement *elem;

	/* First, check - if the field already exists, replace <uid> within it */
	if ((elem = msim_msg_get(msg, uid_field_name)) != NULL) {
		gchar *fmt_string;
		gchar *uid_str, *new_str;

		/* Get the packed element, flattening it. This allows <uid> to be
		 * replaced within nested data structures, since the replacement is done
		 * on the linear, packed data, not on a complicated data structure.
		 *
		 * For example, if the field was originally a dictionary or a list, you
		 * would have to iterate over all the items in it to see what needs to
		 * be replaced. But by packing it first, the <uid> marker is easily replaced
		 * just by a string replacement.
		 */
		fmt_string = msim_msg_pack_element_data(elem);

		uid_str = g_strdup_printf("%d", uid);
		new_str = purple_strreplace(fmt_string, "<uid>", uid_str);
		g_free(uid_str);
		g_free(fmt_string);

		/* Free the old element data */
		msim_msg_free_element_data(elem->data);

		/* Replace it with our new data */
		elem->data = new_str;
		elem->type = MSIM_TYPE_RAW;

	} else {
		/* Otherwise, insert new field into outgoing message. */
		msg = msim_msg_insert_before(msg, uid_before, uid_field_name, MSIM_TYPE_INTEGER, GUINT_TO_POINTER(uid));
	}

	return msg;
}

/**
 * Callback for msim_postprocess_outgoing() to add a userid to a message, and send it (once receiving userid).
 *
 * @param session
 * @param userinfo The user information reply message, containing the user ID
 * @param data The message to postprocess and send.
 *
 * The data message should contain these fields:
 *
 *  _uid_field_name: string, name of field to add with userid from userinfo message
 *  _uid_before: string, name of field before field to insert, or NULL for end
 */
static void
msim_postprocess_outgoing_cb(MsimSession *session, const MsimMessage *userinfo,
		gpointer data)
{
	gchar *uid_field_name, *uid_before, *username;
	guint uid;
	MsimMessage *msg, *body;

	msg = (MsimMessage *)data;

	/* Obtain userid from userinfo message. */
	body = msim_msg_get_dictionary(userinfo, "body");
	g_return_if_fail(body != NULL);

	uid = msim_msg_get_integer(body, "UserID");
	msim_msg_free(body);

	username = msim_msg_get_string(msg, "_username");

	if (!uid) {
		gchar *msg;

		msg = g_strdup_printf(_("No such user: %s"), username);
		if (!purple_conv_present_error(username, session->account, msg)) {
			purple_notify_error(NULL, NULL, _("User lookup"), msg);
		}

		g_free(msg);
		g_free(username);
		/* TODO: free
		 * msim_msg_free(msg);
		 */
		return;
	}

	uid_field_name = msim_msg_get_string(msg, "_uid_field_name");
	uid_before = msim_msg_get_string(msg, "_uid_before");

	msg = msim_do_postprocessing(msg, uid_before, uid_field_name, uid);

	/* Send */
	if (!msim_msg_send(session, msg)) {
		msim_msg_dump("msim_postprocess_outgoing_cb: sending failed for message: %s\n", msg);
	}


	/* Free field names AFTER sending message, because MsimMessage does NOT copy
	 * field names - instead, treats them as static strings (which they usually are).
	 */
	g_free(uid_field_name);
	g_free(uid_before);
	g_free(username);
	/* TODO: free
	 * msim_msg_free(msg);
	 */
}

/**
 * Postprocess and send a message.
 *
 * @param session
 * @param msg Message to postprocess. Will NOT be freed.
 * @param username Username to resolve. Assumed to be a static string (will not be freed or copied).
 * @param uid_field_name Name of new field to add, containing uid of username. Static string.
 * @param uid_before Name of existing field to insert username field before. Static string.
 *
 * @return TRUE if successful.
 */
static gboolean
msim_postprocess_outgoing(MsimSession *session, MsimMessage *msg,
		const gchar *username, const gchar *uid_field_name,
		const gchar *uid_before)
{
	PurpleBuddy *buddy;
	guint uid;
	gboolean rc;

	g_return_val_if_fail(msg != NULL, FALSE);

	/* Store information for msim_postprocess_outgoing_cb(). */
	msg = msim_msg_append(msg, "_username", MSIM_TYPE_STRING, g_strdup(username));
	msg = msim_msg_append(msg, "_uid_field_name", MSIM_TYPE_STRING, g_strdup(uid_field_name));
	msg = msim_msg_append(msg, "_uid_before", MSIM_TYPE_STRING, g_strdup(uid_before));

	/* First, try the most obvious. If numeric userid is given, use that directly. */
	if (msim_is_userid(username)) {
		uid = atol(username);
	} else {
		/* Next, see if on buddy list and know uid. */
		buddy = purple_find_buddy(session->account, username);
		if (buddy) {
			uid = purple_blist_node_get_int(PURPLE_BLIST_NODE(buddy), "UserID");
		} else {
			uid = 0;
		}

		if (!buddy || !uid) {
			/* Don't have uid offhand - need to ask for it, and wait until hear back before sending. */
			purple_debug_info("msim", ">>> msim_postprocess_outgoing: couldn't find username %s in blist\n",
					username ? username : "(NULL)");
			msim_lookup_user(session, username, msim_postprocess_outgoing_cb, msim_msg_clone(msg));
			return TRUE;       /* not sure of status yet - haven't sent! */
		}
	}

	/* Already have uid, postprocess and send msg immediately. */
	purple_debug_info("msim", "msim_postprocess_outgoing: found username %s has uid %d\n",
			username ? username : "(NULL)", uid);

	msg = msim_do_postprocessing(msg, uid_before, uid_field_name, uid);

	rc = msim_msg_send(session, msg);

	/* TODO: free
	 * msim_msg_free(msg);
	 */

	return rc;
}

/**
 * Send a buddy message of a given type.
 *
 * @param session
 * @param who Username to send message to.
 * @param text Message text to send. Not freed; will be copied.
 * @param type A MSIM_BM_* constant.
 *
 * @return TRUE if success, FALSE if fail.
 *
 * Buddy messages ('bm') include instant messages, action messages, status messages, etc.
 */
gboolean
msim_send_bm(MsimSession *session, const gchar *who, const gchar *text,
		int type)
{
	gboolean rc;
	MsimMessage *msg;
	const gchar *from_username;

	g_return_val_if_fail(who != NULL, FALSE);
	g_return_val_if_fail(text != NULL, FALSE);

	from_username = session->account->username;

	g_return_val_if_fail(from_username != NULL, FALSE);

	purple_debug_info("msim", "sending %d message from %s to %s: %s\n",
				  type, from_username, who, text);

	msg = msim_msg_new(
			"bm", MSIM_TYPE_INTEGER, GUINT_TO_POINTER(type),
			"sesskey", MSIM_TYPE_INTEGER, GUINT_TO_POINTER(session->sesskey),
			/* 't' will be inserted here */
			"cv", MSIM_TYPE_INTEGER, GUINT_TO_POINTER(MSIM_CLIENT_VERSION),
			"msg", MSIM_TYPE_STRING, g_strdup(text),
			NULL);

	rc = msim_postprocess_outgoing(session, msg, who, "t", "cv");

	msim_msg_free(msg);

	return rc;
}

/**
 * Lookup a username by userid, from buddy list.
 *
 * @param wanted_uid
 *
 * @return Username of wanted_uid, if on blist, or NULL.
 *         This is a static string, so don't free it. Copy it if needed.
 *
 */
static const gchar *
msim_uid2username_from_blist(PurpleAccount *account, guint wanted_uid)
{
	GSList *buddies, *cur;
	const gchar *ret;

	buddies = purple_find_buddies(account, NULL);

	if (!buddies)
	{
		purple_debug_info("msim", "msim_uid2username_from_blist: no buddies?\n");
		return NULL;
	}

	ret = NULL;

	for (cur = buddies; cur != NULL; cur = g_slist_next(cur))
	{
		PurpleBuddy *buddy;
		guint uid;
		const gchar *name;

		/* See finch/gnthistory.c */
		buddy = cur->data;

		uid = purple_blist_node_get_int(PURPLE_BLIST_NODE(buddy), "UserID");
		name = purple_buddy_get_name(buddy);

		if (uid == wanted_uid)
		{
			ret = name;
			break;
		}
	}

	g_slist_free(buddies);
	return ret;
}

/**
 * Setup a callback, to be called when a reply is received with the returned rid.
 *
 * @param cb The callback, an MSIM_USER_LOOKUP_CB.
 * @param data Arbitrary user data to be passed to callback (probably an MsimMessage *).
 *
 * @return The request/reply ID, used to link replies with requests, or -1.
 *          Put the rid in your request, 'rid' field.
 *
 * TODO: Make more generic and more specific:
 * 1) MSIM_USER_LOOKUP_CB - make it for PERSIST_REPLY, not just user lookup
 * 2) data - make it an MsimMessage?
 */
guint
msim_new_reply_callback(MsimSession *session, MSIM_USER_LOOKUP_CB cb,
		gpointer data)
{
	guint rid;

	rid = session->next_rid++;

	g_hash_table_insert(session->user_lookup_cb, GUINT_TO_POINTER(rid), cb);
	g_hash_table_insert(session->user_lookup_cb_data, GUINT_TO_POINTER(rid), data);

	return rid;
}

/**
 * Return the icon name for a buddy and account.
 *
 * @param acct The account to find the icon for, or NULL for protocol icon.
 * @param buddy The buddy to find the icon for, or NULL for the account icon.
 *
 * @return The base icon name string.
 */
static const gchar *
msim_list_icon(PurpleAccount *acct, PurpleBuddy *buddy)
{
	/* Use a MySpace icon submitted by hbons at
	 * http://developer.pidgin.im/wiki/MySpaceIM. */
	return "myspace";
}

/**
 * Obtain the status text for a buddy.
 *
 * @param buddy The buddy to obtain status text for.
 *
 * @return Status text, or NULL if error. Caller g_free()'s.
 */
static char *
msim_status_text(PurpleBuddy *buddy)
{
	MsimUser *user;
	const gchar *display_name = NULL, *headline = NULL;
	PurpleAccount *account;

	g_return_val_if_fail(buddy != NULL, NULL);

	account = purple_buddy_get_account(buddy);

	user = msim_get_user_from_buddy(buddy, FALSE);
	if (user != NULL) {
		/* Retrieve display name and/or headline, depending on user preference. */
		if (purple_account_get_bool(account, "show_headline", TRUE)) {
			headline = user->headline;
		}

		if (purple_account_get_bool(account, "show_display_name", FALSE)) {
			display_name = user->display_name;
		}
	}

	/* Return appropriate combination of display name and/or headline, or neither. */

	if (display_name && headline) {
		return g_strconcat(display_name, " ", headline, NULL);
	} else if (display_name) {
		return g_strdup(display_name);
	} else if (headline) {
		return g_strdup(headline);
	}

	return NULL;
}

/**
 * Obtain the tooltip text for a buddy.
 *
 * @param buddy Buddy to obtain tooltip text on.
 * @param user_info Variable modified to have the tooltip text.
 * @param full TRUE if should obtain full tooltip text.
 */
static void
msim_tooltip_text(PurpleBuddy *buddy, PurpleNotifyUserInfo *user_info,
		gboolean full)
{
	MsimUser *user;

	g_return_if_fail(buddy != NULL);
	g_return_if_fail(user_info != NULL);

	user = msim_get_user_from_buddy(buddy, TRUE);

	if (PURPLE_BUDDY_IS_ONLINE(buddy)) {
		MsimSession *session;
		PurpleAccount *account = purple_buddy_get_account(buddy);
		PurpleConnection *gc = purple_account_get_connection(account);

		session = (MsimSession *)gc->proto_data;

		/* TODO: if (full), do something different? */

		/* TODO: request information? have to figure out how to do
		 * the asynchronous lookup like oscar does (tooltip shows
		 * 'retrieving...' if not yet available, then changes when it is).
		 *
		 * Right now, only show what we have on hand.
		 */

		/* Show abbreviated user info. */
		msim_append_user_info(session, user_info, user, FALSE);
	}
}

/**
 * Get possible user status types. Based on mockprpl.
 *
 * @return GList of status types.
 */
static GList *
msim_status_types(PurpleAccount *acct)
{
	GList *types;
	PurpleStatusType *status;

	purple_debug_info("myspace", "returning status types\n");

	types = NULL;

	/* Statuses are almost all the same. Define a macro to reduce code repetition. */
#define _MSIM_ADD_NEW_STATUS(prim) status =                         \
	purple_status_type_new_with_attrs(                          \
	prim,   /* PurpleStatusPrimitive */                         \
	NULL,   /* id - use default */                              \
	NULL,   /* name - use default */                            \
	TRUE,   /* saveable */                                      \
	TRUE,   /* user_settable */                                 \
	FALSE,  /* not independent */                               \
	                                                            \
	/* Attributes - each status can have a message. */          \
	"message",                                                  \
	_("Message"),                                               \
	purple_value_new(PURPLE_TYPE_STRING),                       \
	NULL);                                                      \
	                                                            \
	                                                            \
	types = g_list_append(types, status)


	_MSIM_ADD_NEW_STATUS(PURPLE_STATUS_AVAILABLE);
	_MSIM_ADD_NEW_STATUS(PURPLE_STATUS_AWAY);
	_MSIM_ADD_NEW_STATUS(PURPLE_STATUS_OFFLINE);
	_MSIM_ADD_NEW_STATUS(PURPLE_STATUS_INVISIBLE);

	/* Except tune status is different... */
	status = purple_status_type_new_with_attrs(
			PURPLE_STATUS_TUNE,	/* primitive */
			"tune",                 /* ID */
			NULL,                   /* name - use default */
			FALSE,                  /* saveable */
			TRUE,                   /* should be user_settable some day */
			TRUE,                   /* independent */

			PURPLE_TUNE_ARTIST, _("Tune Artist"), purple_value_new(PURPLE_TYPE_STRING),
			PURPLE_TUNE_TITLE, _("Tune Title"), purple_value_new(PURPLE_TYPE_STRING),
			NULL);

	types = g_list_append(types, status);

	return types;
}

/*
 * TODO: This define is stolen from oscar.h.
 *       It's also in yahoo.h.
 *       It should be in libpurple/util.c
 */
#define msim_put32(buf, data) ( \
		(*((buf)) = (unsigned char)((data)>>24)&0xff), \
		(*((buf)+1) = (unsigned char)((data)>>16)&0xff), \
		(*((buf)+2) = (unsigned char)((data)>>8)&0xff), \
		(*((buf)+3) = (unsigned char)(data)&0xff), \
		4)

/**
 * Compute the base64'd login challenge response based on username, password, nonce, and IPs.
 *
 * @param nonce The base64 encoded nonce ('nc') field from the server.
 * @param email User's email address (used as login name).
 * @param password User's cleartext password.
 * @param response_len Will be written with response length.
 *
 * @return Binary login challenge response, ready to send to the server.
 * Must be g_free()'d when finished. NULL if error.
 */
static gchar *
msim_compute_login_response(const gchar nonce[2 * NONCE_SIZE],
		const gchar *email, const gchar *password, guint *response_len)
{
	PurpleCipherContext *key_context;
	PurpleCipher *sha1;
	PurpleCipherContext *rc4;

	guchar hash_pw[HASH_SIZE];
	guchar key[HASH_SIZE];
	gchar *password_truncated, *password_utf16le, *password_utf8_lc;
	GString *data;
	guchar *data_out;
	size_t data_out_len;
	gsize conv_bytes_read, conv_bytes_written;
	GError *conv_error;
#ifdef MSIM_DEBUG_LOGIN_CHALLENGE
	int i;
#endif

	g_return_val_if_fail(nonce != NULL, NULL);
	g_return_val_if_fail(email != NULL, NULL);
	g_return_val_if_fail(password != NULL, NULL);
	g_return_val_if_fail(response_len != NULL, NULL);

	/*
	 * Truncate password to 10 characters.  Their "change password"
	 * web page doesn't let you enter more than 10 characters, but you
	 * can enter more than 10 when logging in on myspace.com and they
	 * truncate it.
	 */
	password_truncated = g_strndup(password, 10);

	/* Convert password to lowercase (required for passwords containing
	 * uppercase characters). MySpace passwords are lowercase,
	 * see ticket #2066. */
	password_utf8_lc = g_utf8_strdown(password_truncated, -1);
	g_free(password_truncated);

	/* Convert ASCII password to UTF16 little endian */
	purple_debug_info("msim", "converting password to UTF-16LE\n");
	conv_error = NULL;
	password_utf16le = g_convert(password_utf8_lc, -1, "UTF-16LE", "UTF-8",
			&conv_bytes_read, &conv_bytes_written, &conv_error);
	g_free(password_utf8_lc);

	if (conv_error != NULL) {
		purple_debug_error("msim",
				"g_convert password UTF8->UTF16LE failed: %s",
				conv_error->message);
		g_error_free(conv_error);
		return NULL;
	}

	/* Compute password hash */
	purple_cipher_digest_region("sha1", (guchar *)password_utf16le,
			conv_bytes_written, sizeof(hash_pw), hash_pw, NULL);
	g_free(password_utf16le);

#ifdef MSIM_DEBUG_LOGIN_CHALLENGE
	purple_debug_info("msim", "pwhash = ");
	for (i = 0; i < sizeof(hash_pw); i++)
		purple_debug_info("msim", "%.2x ", hash_pw[i]);
	purple_debug_info("msim", "\n");
#endif

	/* key = sha1(sha1(pw) + nonce2) */
	sha1 = purple_ciphers_find_cipher("sha1");
	key_context = purple_cipher_context_new(sha1, NULL);
	purple_cipher_context_append(key_context, hash_pw, HASH_SIZE);
	purple_cipher_context_append(key_context, (guchar *)(nonce + NONCE_SIZE), NONCE_SIZE);
	purple_cipher_context_digest(key_context, sizeof(key), key, NULL);
	purple_cipher_context_destroy(key_context);

#ifdef MSIM_DEBUG_LOGIN_CHALLENGE
	purple_debug_info("msim", "key = ");
	for (i = 0; i < sizeof(key); i++) {
		purple_debug_info("msim", "%.2x ", key[i]);
	}
	purple_debug_info("msim", "\n");
#endif

	rc4 = purple_cipher_context_new_by_name("rc4", NULL);

	/* Note: 'key' variable is 0x14 bytes (from SHA-1 hash),
	 * but only first 0x10 used for the RC4 key. */
	purple_cipher_context_set_option(rc4, "key_len", (gpointer)0x10);
	purple_cipher_context_set_key(rc4, key);

	/* rc4 encrypt:
	 * nonce1+email+IP list */

	data = g_string_new(NULL);
	g_string_append_len(data, nonce, NONCE_SIZE);

	/* Include the null terminator */
	g_string_append_len(data, email, strlen(email) + 1);

	while (data->len % 4 != 0)
		g_string_append_c(data, 0xfb);

#ifdef SEND_OUR_IP_ADDRESSES
	/* TODO: Obtain IPs of network interfaces instead of using this hardcoded value */
	g_string_set_size(data, data->len + 4);
	msim_put32(data->str + data->len - 4, MSIM_LOGIN_IP_LIST_LEN);
	g_string_append_len(data, MSIM_LOGIN_IP_LIST, MSIM_LOGIN_IP_LIST_LEN);
#else
	g_string_set_size(data, data->len + 4);
	msim_put32(data->str + data->len - 4, 0);
#endif /* !SEND_OUR_IP_ADDRESSES */

	data_out = g_new0(guchar, data->len);

	purple_cipher_context_encrypt(rc4, (const guchar *)data->str,
			data->len, data_out, &data_out_len);
	purple_cipher_context_destroy(rc4);

	if (data_out_len != data->len) {
		purple_debug_info("msim", "msim_compute_login_response: "
				"data length mismatch: %" G_GSIZE_FORMAT " != %"
				G_GSIZE_FORMAT "\n", data_out_len, data->len);
	}

	g_string_free(data, TRUE);

#ifdef MSIM_DEBUG_LOGIN_CHALLENGE
	purple_debug_info("msim", "response=<%s>\n", data_out);
#endif

	*response_len = data_out_len;

	return (gchar *)data_out;
}

/**
 * Process a login challenge, sending a response.
 *
 * @param session
 * @param msg Login challenge message.
 *
 * @return TRUE if successful, FALSE if not
 */
static gboolean
msim_login_challenge(MsimSession *session, MsimMessage *msg)
{
	PurpleAccount *account;
	gchar *response;
	guint response_len;
	gchar *nc;
	gsize nc_len;
	gboolean ret;

	g_return_val_if_fail(msg != NULL, FALSE);

	g_return_val_if_fail(msim_msg_get_binary(msg, "nc", &nc, &nc_len), FALSE);

	account = session->account;

	g_return_val_if_fail(account != NULL, FALSE);

	purple_connection_update_progress(session->gc, _("Reading challenge"), 1, 4);

	purple_debug_info("msim", "nc is %" G_GSIZE_FORMAT
			" bytes, decoded\n", nc_len);

	if (nc_len != MSIM_AUTH_CHALLENGE_LENGTH) {
		purple_debug_info("msim", "bad nc length: %" G_GSIZE_MODIFIER
				"x != 0x%x\n", nc_len, MSIM_AUTH_CHALLENGE_LENGTH);
		purple_connection_error_reason (session->gc,
			PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
			_("Unexpected challenge length from server"));
		return FALSE;
	}

	purple_connection_update_progress(session->gc, _("Logging in"), 2, 4);

	response_len = 0;
	response = msim_compute_login_response(nc, account->username, account->password, &response_len);

	g_free(nc);

	ret = msim_send(session,
			"login2", MSIM_TYPE_INTEGER, MSIM_AUTH_ALGORITHM,
			/* This is actually user's email address. */
			"username", MSIM_TYPE_STRING, g_strdup(account->username),
			/* GString will be freed in msim_msg_free() in msim_send(). */
			"response", MSIM_TYPE_BINARY, g_string_new_len(response, response_len),
			"clientver", MSIM_TYPE_INTEGER, MSIM_CLIENT_VERSION,
			"langid", MSIM_TYPE_INTEGER, MSIM_LANGUAGE_ID_ENGLISH,
			"imlang", MSIM_TYPE_STRING, g_strdup(MSIM_LANGUAGE_NAME_ENGLISH),
			"reconn", MSIM_TYPE_INTEGER, 0,
			"status", MSIM_TYPE_INTEGER, 100,
			"id", MSIM_TYPE_INTEGER, 1,
			NULL);

	g_free(response);

	return ret;
}

/**
 * Process unrecognized information.
 *
 * @param session
 * @param msg An MsimMessage that was unrecognized, or NULL.
 * @param note Information on what was unrecognized, or NULL.
 */
void
msim_unrecognized(MsimSession *session, MsimMessage *msg, gchar *note)
{
	/* TODO: Some more context, outwardly equivalent to a backtrace,
	 * for helping figure out what this msg is for. What was going on?
	 * But not too much information so that a user
	 * posting this dump reveals confidential information.
	 */

	/* TODO: dump unknown msgs to file, so user can send them to me
	 * if they wish, to help add support for new messages (inspired
	 * by Alexandr Shutko, who maintains OSCAR protocol documentation).
	 *
	 * Filed enhancement ticket for libpurple as #4688.
	 */

	purple_debug_info("msim", "Unrecognized data on account for %s\n",
			(session && session->account && session->account->username) ?
			session->account->username : "(NULL)");
	if (note) {
		purple_debug_info("msim", "(Note: %s)\n", note);
	}

	if (msg) {
		msim_msg_dump("Unrecognized message dump: %s\n", msg);
	}
}

/** Called when the session key arrives to check whether the user
 * has a username, and set one if desired. */
static gboolean
msim_is_username_set(MsimSession *session, MsimMessage *msg)
{
	g_return_val_if_fail(msg != NULL, FALSE);
	g_return_val_if_fail(session->gc != NULL, FALSE);

	session->sesskey = msim_msg_get_integer(msg, "sesskey");
	purple_debug_info("msim", "SESSKEY=<%d>\n", session->sesskey);

	/* What is proof? Used to be uid, but now is 52 base64'd bytes... */

	/* Comes with: proof,profileid,userid,uniquenick -- all same values
	 * some of the time, but can vary. This is our own user ID. */
	session->userid = msim_msg_get_integer(msg, "userid");

	/* Save uid to account so this account can be looked up by uid. */
	purple_account_set_int(session->account, "uid", session->userid);

	/* Not sure what profileid is used for. */
	if (msim_msg_get_integer(msg, "profileid") != session->userid) {
		msim_unrecognized(session, msg,
				"Profile ID didn't match user ID, don't know why");
	}

	/* We now know are our own username, only after we're logged in..
	 * which is weird, but happens because you login with your email
	 * address and not username. Will be freed in msim_session_destroy(). */
	session->username = msim_msg_get_string(msg, "uniquenick");

	/* If user lacks a username, help them get one. */
	if (msim_msg_get_integer(msg, "uniquenick") == session->userid) {
		purple_debug_info("msim_is_username_set", "no username is set\n");
		purple_request_yes_no(session->gc,
			_("MySpaceIM - No Username Set"),
			_("You appear to have no MySpace username."),
			_("Would you like to set one now? (Note: THIS CANNOT BE CHANGED!)"),
			0,
			session->account,
			NULL,
			NULL,
			session->gc,
			G_CALLBACK(msim_set_username_cb),
			G_CALLBACK(msim_do_not_set_username_cb));
		purple_debug_info("msim_is_username_set","'username not set' alert prompted\n");
		return FALSE;
	}
	return TRUE;
}

#ifdef MSIM_USE_KEEPALIVE
/**
 * Check if the connection is still alive, based on last communication.
 */
static gboolean
msim_check_alive(gpointer data)
{
	MsimSession *session;
	time_t delta;

	session = (MsimSession *)data;

	delta = time(NULL) - session->last_comm;

	/* purple_debug_info("msim", "msim_check_alive: delta=%d\n", delta); */
	if (delta >= MSIM_KEEPALIVE_INTERVAL) {
		purple_debug_info("msim",
				"msim_check_alive: %zu > interval of %d, presumed dead\n",
				delta, MSIM_KEEPALIVE_INTERVAL);
		purple_connection_error_reason(session->gc,
				PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
				_("Lost connection with server"));

		return FALSE;
	}

	return TRUE;
}
#endif

/**
 * Handle mail reply checks.
 */
static void
msim_check_inbox_cb(MsimSession *session, const MsimMessage *reply, gpointer data)
{
	MsimMessage *body;
	guint i, n;
	/* Information for each new inbox message type. */
	static struct
	{
		const gchar *key;
		guint bit;
		const gchar *url;
		const gchar *text;
	} message_types[] = {
		{ "Mail", MSIM_INBOX_MAIL, "http://messaging.myspace.com/index.cfm?fuseaction=mail.inbox", NULL },
		{ "BlogComment", MSIM_INBOX_BLOG_COMMENT, "http://blog.myspace.com/index.cfm?fuseaction=blog", NULL },
		{ "ProfileComment", MSIM_INBOX_PROFILE_COMMENT, "http://home.myspace.com/index.cfm?fuseaction=user", NULL },
		{ "FriendRequest", MSIM_INBOX_FRIEND_REQUEST, "http://messaging.myspace.com/index.cfm?fuseaction=mail.friendRequests", NULL },
		{ "PictureComment", MSIM_INBOX_PICTURE_COMMENT, "http://home.myspace.com/index.cfm?fuseaction=user", NULL }
	};
	const gchar *froms[G_N_ELEMENTS(message_types) + 1] = { "" },
		*tos[G_N_ELEMENTS(message_types) + 1] = { "" },
		*urls[G_N_ELEMENTS(message_types) + 1] = { "" },
		*subjects[G_N_ELEMENTS(message_types) + 1] = { "" };

	g_return_if_fail(reply != NULL);

	/* Can't write _()'d strings in array initializers. Workaround. */
	/* khc: then use N_() in the array initializer and use _() when they are
	   used */
	message_types[0].text = _("New mail messages");
	message_types[1].text = _("New blog comments");
	message_types[2].text = _("New profile comments");
	message_types[3].text = _("New friend requests!");
	message_types[4].text = _("New picture comments");

	body = msim_msg_get_dictionary(reply, "body");

	if (body == NULL)
		return;

	n = 0;

	for (i = 0; i < G_N_ELEMENTS(message_types); ++i) {
		const gchar *key;
		guint bit;

		key = message_types[i].key;
		bit = message_types[i].bit;

		if (msim_msg_get(body, key)) {
			/* Notify only on when _changes_ from no mail -> has mail
			 * (edge triggered) */
			if (!(session->inbox_status & bit)) {
				purple_debug_info("msim", "msim_check_inbox_cb: got %s, at %d\n",
						key ? key : "(NULL)", n);

				subjects[n] = message_types[i].text;
				froms[n] = _("MySpace");
				tos[n] = session->username;
				/* TODO: append token, web challenge, so automatically logs in.
				 * Would also need to free strings because they won't be static
				 */
				urls[n] = message_types[i].url;

				++n;
			} else {
				purple_debug_info("msim",
						"msim_check_inbox_cb: already notified of %s\n",
						key ? key : "(NULL)");
			}

			session->inbox_status |= bit;
		}
	}

	if (n) {
		purple_debug_info("msim",
				"msim_check_inbox_cb: notifying of %d\n", n);

		/* TODO: free strings with callback _if_ change to dynamic (w/ token) */
		purple_notify_emails(session->gc,         /* handle */
				n,                        /* count */
				TRUE,                     /* detailed */
				subjects, froms, tos, urls,
				NULL,                     /* PurpleNotifyCloseCallback cb */
				NULL);                    /* gpointer user_data */

	}

	msim_msg_free(body);
}

/**
 * Send request to check if there is new mail.
 */
static gboolean
msim_check_inbox(gpointer data)
{
	MsimSession *session;

	session = (MsimSession *)data;

	purple_debug_info("msim", "msim_check_inbox: checking mail\n");
	g_return_val_if_fail(msim_send(session,
			"persist", MSIM_TYPE_INTEGER, 1,
			"sesskey", MSIM_TYPE_INTEGER, session->sesskey,
			"cmd", MSIM_TYPE_INTEGER, MSIM_CMD_GET,
			"dsn", MSIM_TYPE_INTEGER, MG_CHECK_MAIL_DSN,
			"lid", MSIM_TYPE_INTEGER, MG_CHECK_MAIL_LID,
			"uid", MSIM_TYPE_INTEGER, session->userid,
			"rid", MSIM_TYPE_INTEGER,
				msim_new_reply_callback(session, msim_check_inbox_cb, NULL),
			"body", MSIM_TYPE_STRING, g_strdup(""),
			NULL), TRUE);

	/* Always return true, so that we keep checking for mail. */
	return TRUE;
}

/**
 * Add contact from server to buddy list, after looking up username.
 * Callback from msim_add_contact_from_server().
 *
 * @param data An MsimMessage * of the contact information. Will be freed.
 */
static void
msim_add_contact_from_server_cb(MsimSession *session, const MsimMessage *user_lookup_info, gpointer data)
{
	MsimMessage *contact_info, *user_lookup_info_body;
	PurpleGroup *group;
	PurpleBuddy *buddy;
	MsimUser *user;
	gchar *username, *group_name, *display_name;
	guint uid, visibility;

	contact_info = (MsimMessage *)data;
	purple_debug_info("msim_add_contact_from_server_cb", "contact_info addr=%p\n", contact_info);
	uid = msim_msg_get_integer(contact_info, "ContactID");

	if (!user_lookup_info) {
		username = g_strdup(msim_uid2username_from_blist(session->account, uid));
		display_name = NULL;
		g_return_if_fail(username != NULL);
	} else {
		user_lookup_info_body = msim_msg_get_dictionary(user_lookup_info, "body");
		username = msim_msg_get_string(user_lookup_info_body, "UserName");
		display_name = msim_msg_get_string(user_lookup_info_body, "DisplayName");
		msim_msg_free(user_lookup_info_body);
		g_return_if_fail(username != NULL);
	}

	purple_debug_info("msim_add_contact_from_server_cb",
			"*** about to add/update username=%s\n", username);

	/* 1. Creates a new group, or gets existing group if it exists (or so
	 * the documentation claims). */
	group_name = msim_msg_get_string(contact_info, "GroupName");
	if (!group_name || (*group_name == '\0')) {
		g_free(group_name);
		group_name = g_strdup(_("IM Friends"));
		purple_debug_info("myspace", "No GroupName specified, defaulting to '%s'.\n", group_name);
	}
	group = purple_find_group(group_name);
	if (!group) {
		group = purple_group_new(group_name);
		/* Add group to beginning. See #2752. */
		purple_blist_add_group(group, NULL);
	}
	g_free(group_name);

	visibility = msim_msg_get_integer(contact_info, "Visibility");
	if (visibility == 2) {
		/* This buddy is blocked (and therefore not on our buddy list */
		purple_privacy_deny_add(session->account, username, TRUE);
		msim_msg_free(contact_info);
		g_free(username);
		g_free(display_name);
		return;
	}

	/* 2. Get or create buddy */
	buddy = purple_find_buddy(session->account, username);
	if (!buddy) {
		purple_debug_info("msim_add_contact_from_server_cb",
				"creating new buddy: %s\n", username);
		buddy = purple_buddy_new(session->account, username, NULL);
	}

	/* TODO: use 'Position' in contact_info to take into account where buddy is */
	purple_blist_add_buddy(buddy, NULL, group, NULL /* insertion point */);

	if (strtol(username, NULL, 10) == uid) {
		/*
		 * This user has not set their username!  Set their server
		 * alias to their display name so that we don't see a bunch
		 * of numbers in the buddy list.
		 */
		if (display_name != NULL) {
			purple_blist_node_set_string(PURPLE_BLIST_NODE(buddy), "DisplayName", display_name);
			serv_got_alias(session->gc, username, display_name);
		} else {
			serv_got_alias(session->gc, username,
					purple_blist_node_get_string(PURPLE_BLIST_NODE(buddy), "DisplayName"));
		}
	}
	g_free(display_name);

	/* 3. Update buddy information */
	user = msim_get_user_from_buddy(buddy, TRUE);

	user->id = uid;
	/* Keep track of the user ID across sessions */
	purple_blist_node_set_int(PURPLE_BLIST_NODE(buddy), "UserID", uid);

	/* Stores a few fields in the MsimUser, relevant to the buddy itself.
	 * AvatarURL, Headline, ContactID. */
	msim_store_user_info(session, contact_info, NULL);

	/* TODO: other fields, store in 'user' */
	msim_msg_free(contact_info);

	g_free(username);
}

/**
 * Add first ContactID in contact_info to buddy's list. Used to add
 * server-side buddies to client-side list.
 *
 * @return TRUE if added.
 */
static gboolean
msim_add_contact_from_server(MsimSession *session, MsimMessage *contact_info)
{
	guint uid;
	const gchar *username;

	uid = msim_msg_get_integer(contact_info, "ContactID");
	g_return_val_if_fail(uid != 0, FALSE);

	/* Lookup the username, since NickName and IMName is unreliable */
	username = msim_uid2username_from_blist(session->account, uid);
	if (!username) {
		gchar *uid_str;

		uid_str = g_strdup_printf("%d", uid);
		purple_debug_info("msim_add_contact_from_server",
				"contact_info addr=%p\n", contact_info);
		msim_lookup_user(session, uid_str, msim_add_contact_from_server_cb, (gpointer)msim_msg_clone(contact_info));
		g_free(uid_str);
	} else {
		msim_add_contact_from_server_cb(session, NULL, (gpointer)msim_msg_clone(contact_info));
	}

	/* Say that the contact was added, even if we're still looking up
	 * their username. */
	return TRUE;
}

/**
 * Called when contact list is received from server.
 */
static void
msim_got_contact_list(MsimSession *session, const MsimMessage *reply, gpointer user_data)
{
	MsimMessage *body, *body_node;
	gchar *msg;
	guint buddy_count;

	body = msim_msg_get_dictionary(reply, "body");

	buddy_count = 0;

	for (body_node = body;
		body_node != NULL;
		body_node = msim_msg_get_next_element_node(body_node))
	{
		MsimMessageElement *elem;

		elem = (MsimMessageElement *)body_node->data;

		if (g_str_equal(elem->name, "ContactID"))
		{
			/* Will look for first contact in body_node */
			if (msim_add_contact_from_server(session, body_node)) {
				++buddy_count;
			}
		}
	}

	switch (GPOINTER_TO_UINT(user_data)) {
		case MSIM_CONTACT_LIST_IMPORT_ALL_FRIENDS:
		        msg = g_strdup_printf(ngettext("%d buddy was added or updated from the server (including buddies already on the server-side list)",
						       "%d buddies were added or updated from the server (including buddies already on the server-side list)",
						       buddy_count),
					      buddy_count);
			purple_notify_info(session->account, _("Add contacts from server"), msg, NULL);
			g_free(msg);
			break;

		case MSIM_CONTACT_LIST_IMPORT_TOP_FRIENDS:
			/* TODO */
			break;

		case MSIM_CONTACT_LIST_INITIAL_FRIENDS:
			/* The session is now set up, ready to be connected. This emits the
			 * signedOn signal, so clients can now do anything with msimprpl, and
			 * we're ready for it (session key, userid, username all setup). */
			purple_connection_update_progress(session->gc, _("Connected"), 3, 4);
			purple_connection_set_state(session->gc, PURPLE_CONNECTED);
			break;
	}

	msim_msg_free(body);
}

/**
 * Get contact list, calling msim_got_contact_list() with
 * what_to_do_after as user_data gpointer.
 *
 * @param what_to_do_after should be one of the MSIM_CONTACT_LIST_* #defines.
 */
static gboolean
msim_get_contact_list(MsimSession *session, int what_to_do_after)
{
	return msim_send(session,
			"persist", MSIM_TYPE_INTEGER, 1,
			"sesskey", MSIM_TYPE_INTEGER, session->sesskey,
			"cmd", MSIM_TYPE_INTEGER, MSIM_CMD_GET,
			"dsn", MSIM_TYPE_INTEGER, MG_LIST_ALL_CONTACTS_DSN,
			"lid", MSIM_TYPE_INTEGER, MG_LIST_ALL_CONTACTS_LID,
			"uid", MSIM_TYPE_INTEGER, session->userid,
			"rid", MSIM_TYPE_INTEGER,
				msim_new_reply_callback(session, msim_got_contact_list, GUINT_TO_POINTER(what_to_do_after)),
			"body", MSIM_TYPE_STRING, g_strdup(""),
			NULL);
}

/** Called after username is set, if necessary and we're open for business. */
gboolean msim_we_are_logged_on(MsimSession *session)
{
	MsimMessage *body;

	/* Set display name to username (otherwise will show email address) */
	purple_connection_set_display_name(session->gc, session->username);

	body = msim_msg_new(
			"UserID", MSIM_TYPE_INTEGER, session->userid,
			NULL);

	/* Request IM info about ourself. */
	msim_send(session,
			"persist", MSIM_TYPE_INTEGER, 1,
			"sesskey", MSIM_TYPE_INTEGER, session->sesskey,
			"cmd", MSIM_TYPE_INTEGER, MSIM_CMD_GET,
			"dsn", MSIM_TYPE_INTEGER, MG_OWN_MYSPACE_INFO_DSN,
			"lid", MSIM_TYPE_INTEGER, MG_OWN_MYSPACE_INFO_LID,
			"rid", MSIM_TYPE_INTEGER, session->next_rid++,
			"UserID", MSIM_TYPE_INTEGER, session->userid,
			"body", MSIM_TYPE_DICTIONARY, body,
			NULL);

	/* Request MySpace info about ourself. */
	msim_send(session,
			"persist", MSIM_TYPE_INTEGER, 1,
			"sesskey", MSIM_TYPE_INTEGER, session->sesskey,
			"cmd", MSIM_TYPE_INTEGER, MSIM_CMD_GET,
			"dsn", MSIM_TYPE_INTEGER, MG_OWN_IM_INFO_DSN,
			"lid", MSIM_TYPE_INTEGER, MG_OWN_IM_INFO_LID,
			"rid", MSIM_TYPE_INTEGER, session->next_rid++,
			"body", MSIM_TYPE_STRING, g_strdup(""),
			NULL);

	/* TODO: set options (persist cmd=514,dsn=1,lid=10) */
	/* TODO: set blocklist */

	/* Notify servers of our current status. */
	purple_debug_info("msim", "msim_we_are_logged_on: notifying servers of status\n");
	msim_set_status(session->account,
			purple_account_get_active_status(session->account));

	/* TODO: setinfo */
	/*
	body = msim_msg_new(
		"TotalFriends", MSIM_TYPE_INTEGER, 666,
		NULL);
	msim_send(session,
			"setinfo", MSIM_TYPE_BOOLEAN, TRUE,
			"sesskey", MSIM_TYPE_INTEGER, session->sesskey,
			"info", MSIM_TYPE_DICTIONARY, body,
			NULL);
			*/

	/* Disable due to problems with timeouts. TODO: fix. */
#ifdef MSIM_USE_KEEPALIVE
	purple_timeout_add_seconds(MSIM_KEEPALIVE_INTERVAL_CHECK,
			(GSourceFunc)msim_check_alive, session);
#endif

	/* Check mail if they want to. */
	if (purple_account_get_check_mail(session->account)) {
		session->inbox_handle = purple_timeout_add(MSIM_MAIL_INTERVAL_CHECK,
				(GSourceFunc)msim_check_inbox, session);
		msim_check_inbox(session);
	}

	msim_get_contact_list(session, MSIM_CONTACT_LIST_INITIAL_FRIENDS);

	return TRUE;
}

/**
 * Record the client version in the buddy list, from an incoming message.
 */
static gboolean
msim_incoming_bm_record_cv(MsimSession *session, MsimMessage *msg)
{
	gchar *username, *cv;
	gboolean ret;
	MsimUser *user;

	username = msim_msg_get_string(msg, "_username");
	cv = msim_msg_get_string(msg, "cv");

	g_return_val_if_fail(username != NULL, FALSE);
	if (!cv) {
		/* No client version to record, don't worry about it. */
		g_free(username);
		return FALSE;
	}

	user = msim_find_user(session, username);

	if (user) {
		user->client_cv = atol(cv);
		ret = TRUE;
	} else {
		ret = FALSE;
	}

	g_free(username);
	g_free(cv);

	return ret;
}

#ifdef MSIM_SEND_CLIENT_VERSION
/**
 * Send our client version to another unofficial client that understands it.
 */
static gboolean
msim_send_unofficial_client(MsimSession *session, gchar *username)
{
	gchar *our_info;
	gboolean ret;

	our_info = g_strdup_printf("Libpurple %d.%d.%d - msimprpl %s",
			PURPLE_MAJOR_VERSION,
			PURPLE_MINOR_VERSION,
			PURPLE_MICRO_VERSION,
			MSIM_PRPL_VERSION_STRING);

	ret = msim_send_bm(session, username, our_info, MSIM_BM_UNOFFICIAL_CLIENT);

	return ret;
}
#endif
/**
 * Process incoming status mood messages.
 *
 * @param session
 * @param msg Status mood update message. Caller frees.
 *
 * @return TRUE if successful.
 */
static gboolean
msim_incoming_status_mood(MsimSession *session, MsimMessage *msg) {
	/* TODO: I dont know too much about this yet,
	 * so until I see how the official client handles
	 * this and decide if libpurple should as well,
	 * well just say we used it
	 */
	gchar *ss;
	ss = msim_msg_get_string(msg, "msg");
	purple_debug_info("msim", "Incoming Status Message: %s", ss ? ss : "(NULL)");
	g_free(ss);
	return TRUE;
}

/**
 * Process incoming status messages.
 *
 * @param session
 * @param msg Status update message. Caller frees.
 *
 * @return TRUE if successful.
 */
static gboolean
msim_incoming_status(MsimSession *session, MsimMessage *msg)
{
	MsimUser *user;
	GList *list;
	gchar *status_headline, *status_headline_escaped;
	gint status_code, purple_status_code;
	gchar *username;
	gchar *unrecognized_msg;

	g_return_val_if_fail(msg != NULL, FALSE);

	/* Helpfully looked up by msim_incoming_resolve() for us. */
	username = msim_msg_get_string(msg, "_username");
	g_return_val_if_fail(username != NULL, FALSE);

	{
		gchar *ss;

		ss = msim_msg_get_string(msg, "msg");
		purple_debug_info("msim",
				"msim_status: updating status for <%s> to <%s>\n",
				username, ss ? ss : "(NULL)");
		g_free(ss);
	}

	/* Example fields:
	 *  |s|0|ss|Offline
	 *  |s|1|ss|:-)|ls||ip|0|p|0
	 */
	list = msim_msg_get_list(msg, "msg");

	status_code = msim_msg_get_integer_from_element(g_list_nth_data(list, MSIM_STATUS_ORDINAL_ONLINE));
	purple_debug_info("msim", "msim_status: %s's status code = %d\n", username, status_code);
	status_headline = msim_msg_get_string_from_element(g_list_nth_data(list, MSIM_STATUS_ORDINAL_HEADLINE));

	/* Add buddy if not found.
	 * TODO: Could this be responsible for #3444? */
	user = msim_find_user(session, username);
	if (!user) {
		PurpleBuddy *buddy;

		purple_debug_info("msim",
				"msim_status: making new buddy for %s\n", username);
		buddy = purple_buddy_new(session->account, username, NULL);
		purple_blist_add_buddy(buddy, NULL, NULL, NULL);

		user = msim_get_user_from_buddy(buddy, TRUE);
		user->id = msim_msg_get_integer(msg, "f");

		/* Keep track of the user ID across sessions */
		purple_blist_node_set_int(PURPLE_BLIST_NODE(buddy), "UserID", user->id);

		msim_store_user_info(session, msg, NULL);
	} else {
		purple_debug_info("msim", "msim_status: found buddy %s\n", username);
	}

	if (status_headline && strcmp(status_headline, "") != 0) {
		/* The status headline is plaintext, but libpurple treats it as HTML,
		 * so escape any HTML characters to their entity equivalents. */
		status_headline_escaped = g_markup_escape_text(status_headline, -1);
	} else {
		status_headline_escaped = NULL;
	}

	g_free(status_headline);

	/* don't copy; let the MsimUser own the headline, memory-wise */
	g_free(user->headline);
	user->headline = status_headline_escaped;

	/* Set user status */
	switch (status_code) {
		case MSIM_STATUS_CODE_OFFLINE_OR_HIDDEN:
			purple_status_code = PURPLE_STATUS_OFFLINE;
			break;

		case MSIM_STATUS_CODE_ONLINE:
			purple_status_code = PURPLE_STATUS_AVAILABLE;
			break;

		case MSIM_STATUS_CODE_AWAY:
			purple_status_code = PURPLE_STATUS_AWAY;
			break;

		case MSIM_STATUS_CODE_IDLE:
			/* Treat idle as an available status. */
			purple_status_code = PURPLE_STATUS_AVAILABLE;
			break;

		default:
			purple_debug_info("msim", "msim_incoming_status for %s, unknown status code %d, treating as available\n",
						username, status_code);
			purple_status_code = PURPLE_STATUS_AVAILABLE;

			unrecognized_msg = g_strdup_printf("msim_incoming_status, unrecognized status code: %d\n",
					status_code);
			msim_unrecognized(session, NULL, unrecognized_msg);
			g_free(unrecognized_msg);
	}

	purple_prpl_got_user_status(session->account, username, purple_primitive_get_id_from_type(purple_status_code), NULL);

	if (status_code == MSIM_STATUS_CODE_IDLE) {
		purple_debug_info("msim", "msim_status: got idle: %s\n", username);
		purple_prpl_got_user_idle(session->account, username, TRUE, 0);
	} else {
		/* All other statuses indicate going back to non-idle. */
		purple_prpl_got_user_idle(session->account, username, FALSE, 0);
	}

#ifdef MSIM_SEND_CLIENT_VERSION
	if (status_code == MSIM_STATUS_CODE_ONLINE) {
		/* Secretly whisper to unofficial clients our own version as they come online */
		msim_send_unofficial_client(session, username);
	}
#endif

	if (status_code != MSIM_STATUS_CODE_OFFLINE_OR_HIDDEN) {
		/* Get information when they come online.
		 * TODO: periodically refresh?
		 */
		purple_debug_info("msim_incoming_status", "%s came online, looking up\n", username);
		msim_lookup_user(session, username, NULL, NULL);
	}

	g_free(username);
	msim_msg_list_free(list);

	return TRUE;
}

/**
 * Handle an incoming instant message.
 *
 * @param session The session
 * @param msg Message from the server, containing 'f' (userid from) and 'msg'.
 *               Should also contain username in _username from preprocessing.
 *
 * @return TRUE if successful.
 */
static gboolean
msim_incoming_im(MsimSession *session, MsimMessage *msg, const gchar *username)
{
	gchar *msg_msim_markup, *msg_purple_markup;
	gchar *userid;
	time_t time_received;
	PurpleConversation *conv;

	/* I know this isn't really a string... but we need it to be one for
	 * purple_find_conversation_with_account(). */
	userid = msim_msg_get_string(msg, "f");

	purple_debug_info("msim_incoming_im", "UserID is %s", userid);

	if (msim_is_userid(username)) {
		purple_debug_info("msim", "Ignoring message from spambot (%s) on account %s\n",
				username, purple_account_get_username(session->account));
		return FALSE;
	}

	/* See if a conversation with their UID already exists...*/
	conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, userid, session->account);
	if (conv) {
		/* Since the conversation exists... We need to normalize it */
		purple_conversation_set_name(conv, username);
	}

	msg_msim_markup = msim_msg_get_string(msg, "msg");
	g_return_val_if_fail(msg_msim_markup != NULL, FALSE);

	msg_purple_markup = msim_markup_to_html(session, msg_msim_markup);
	g_free(msg_msim_markup);

	time_received = msim_msg_get_integer(msg, "date");
	if (!time_received) {
		purple_debug_info("msim_incoming_im", "date in message not set.\n");
		time_received = time(NULL);
	}

	serv_got_im(session->gc, username, msg_purple_markup, PURPLE_MESSAGE_RECV, time_received);

	g_free(msg_purple_markup);

	return TRUE;
}

/**
 * Handle an incoming action message or an IM.
 *
 * @param session
 * @param msg
 *
 * @return TRUE if successful.
 */
static gboolean
msim_incoming_action_or_im(MsimSession *session, MsimMessage *msg)
{
	gchar *msg_text, *username;
	gboolean rc;

	g_return_val_if_fail(msg != NULL, FALSE);

	msg_text = msim_msg_get_string(msg, "msg");
	g_return_val_if_fail(msg_text != NULL, FALSE);

	username = msim_msg_get_string(msg, "_username");
	g_return_val_if_fail(username != NULL, FALSE);

	purple_debug_info("msim",
			"msim_incoming_action_or_im: action <%s> from <%s>\n",
			msg_text, username);

	if (g_str_equal(msg_text, "%typing%")) {
		serv_got_typing(session->gc, username, 0, PURPLE_TYPING);
		rc = TRUE;
	} else if (g_str_equal(msg_text, "%stoptyping%")) {
		serv_got_typing_stopped(session->gc, username);
		rc = TRUE;
	} else if (strstr(msg_text, "!!!ZAP_SEND!!!=RTE_BTN_ZAPS_")) {
		rc = msim_incoming_zap(session, msg);
	} else if (strstr(msg_text, "!!!GroupCount=")) {
		/* TODO: support group chats. I think the number in msg_text has
		 * something to do with the 'gid' field. */
		purple_debug_info("msim",
				"msim_incoming_action_or_im: "
				"TODO: implement #4691, group chats: %s\n", msg_text);

		rc = TRUE;
	} else if (strstr(msg_text, "!!!Offline=")) {
		/* TODO: support group chats. This one might mean a user
		 * went offline or exited the chat. */
		purple_debug_info("msim", "msim_incoming_action_or_im: "
				"TODO: implement #4691, group chats: %s\n", msg_text);

		rc = TRUE;
	} else if (msim_msg_get_integer(msg, "aid") != 0) {
		purple_debug_info("msim", "TODO: implement #4691, group chat from %d on %d: %s\n",
				msim_msg_get_integer(msg, "aid"),
				msim_msg_get_integer(msg, "f"),
				msg_text);

		rc = TRUE;
	} else {
		rc = msim_incoming_im(session, msg, username);
	}

	g_free(msg_text);
	g_free(username);

	return rc;
}

/**
 * Process an incoming media (message background?) message.
 */
static gboolean
msim_incoming_media(MsimSession *session, MsimMessage *msg)
{
	gchar *username, *text;

	username = msim_msg_get_string(msg, "_username");
	text = msim_msg_get_string(msg, "msg");

	g_return_val_if_fail(username != NULL, FALSE);
	g_return_val_if_fail(text != NULL, FALSE);

	purple_debug_info("msim", "msim_incoming_media: from %s, got msg=%s\n", username, text);

	/* Media messages are sent when the user opens a window to someone.
	 * Tell libpurple they started typing and stopped typing, to inform the Psychic
	 * Mode plugin so it too can open a window to the user. */
	serv_got_typing(session->gc, username, 0, PURPLE_TYPING);
	serv_got_typing_stopped(session->gc, username);

	g_free(username);

	return TRUE;
}

/**
 * Process an incoming "unofficial client" message. The plugin for
 * Miranda IM sends this message with the plugin information.
 */
static gboolean
msim_incoming_unofficial_client(MsimSession *session, MsimMessage *msg)
{
	MsimUser *user;
	gchar *username, *client_info;

	username = msim_msg_get_string(msg, "_username");
	client_info = msim_msg_get_string(msg, "msg");

	g_return_val_if_fail(username != NULL, FALSE);
	g_return_val_if_fail(client_info != NULL, FALSE);

	purple_debug_info("msim", "msim_incoming_unofficial_client: %s is using client %s\n",
		username, client_info);

	user = msim_find_user(session, username);

	g_return_val_if_fail(user != NULL, FALSE);

	if (user->client_info) {
		g_free(user->client_info);
	}
	user->client_info = client_info;

	g_free(username);
	/* Do not free client_info - the MsimUser now owns it. */

	return TRUE;
}

/**
 * Handle an incoming buddy message.
 */
static gboolean
msim_incoming_bm(MsimSession *session, MsimMessage *msg)
{
	guint bm;

	bm = msim_msg_get_integer(msg, "bm");

	msim_incoming_bm_record_cv(session, msg);

	switch (bm) {
		case MSIM_BM_STATUS:
			return msim_incoming_status(session, msg);
		case MSIM_BM_ACTION_OR_IM_DELAYABLE:
		case MSIM_BM_ACTION_OR_IM_INSTANT:
			return msim_incoming_action_or_im(session, msg);
		case MSIM_BM_MEDIA:
			return msim_incoming_media(session, msg);
		case MSIM_BM_UNOFFICIAL_CLIENT:
			return msim_incoming_unofficial_client(session, msg);
		case MSIM_BM_STATUS_MOOD:
			return msim_incoming_status_mood(session, msg);
		default:
			/*
			 * Unknown message type!  We used to call
			 *   msim_incoming_action_or_im(session, msg);
			 * for these, but that doesn't help anything, and it means
			 * we'll show broken gibberish if MySpace starts sending us
			 * other message types.
			 */
			purple_debug_warning("myspace", "Received unknown imcoming "
					"message, bm=%u\n", bm);
			return TRUE;
	}
}

/**
 * Process the initial server information from the server.
 */
static gboolean
msim_process_server_info(MsimSession *session, MsimMessage *msg)
{
	MsimMessage *body;

	body = msim_msg_get_dictionary(msg, "body");
	g_return_val_if_fail(body != NULL, FALSE);

	/* Example body:
AdUnitRefreshInterval=10.
AlertPollInterval=360.
AllowChatRoomEmoticonSharing=False.
ChatRoomUserIDs=78744676;163733130;1300326231;123521495;142663391.
CurClientVersion=673.
EnableIMBrowse=True.
EnableIMStuffAvatars=False.
EnableIMStuffZaps=False.
MaxAddAllFriends=100.
MaxContacts=1000.
MinClientVersion=594.
MySpaceIM_ENGLISH=78744676.
MySpaceNowTimer=720.
PersistenceDataTimeout=900.
UseWebChallenge=1.
WebTicketGoHome=False

	Anything useful? TODO: use what is useful, and use it.
*/
	purple_debug_info("msim_process_server_info",
			"maximum contacts: %d\n",
			msim_msg_get_integer(body, "MaxContacts"));

	session->server_info = body;
	/* session->server_info freed in msim_session_destroy */

	return TRUE;
}

/**
 * Process a web challenge, used to login to the web site.
 */
static gboolean
msim_web_challenge(MsimSession *session, MsimMessage *msg)
{
	/* TODO: web challenge, store token. #2659. */
	return FALSE;
}

/**
 * Process a persistance message reply from the server.
 *
 * @param session
 * @param msg Message reply from server.
 *
 * @return TRUE if successful.
 *
 * msim_lookup_user sets callback for here
 */
static gboolean
msim_process_reply(MsimSession *session, MsimMessage *msg)
{
	MSIM_USER_LOOKUP_CB cb;
	gpointer data;
	guint rid, cmd, dsn, lid;

	g_return_val_if_fail(msg != NULL, FALSE);

	msim_store_user_info(session, msg, NULL);

	rid = msim_msg_get_integer(msg, "rid");
	cmd = msim_msg_get_integer(msg, "cmd");
	dsn = msim_msg_get_integer(msg, "dsn");
	lid = msim_msg_get_integer(msg, "lid");

	/* Unsolicited messages */
	if (cmd == (MSIM_CMD_BIT_REPLY | MSIM_CMD_GET)) {
		if (dsn == MG_SERVER_INFO_DSN && lid == MG_SERVER_INFO_LID) {
			return msim_process_server_info(session, msg);
		} else if (dsn == MG_WEB_CHALLENGE_DSN && lid == MG_WEB_CHALLENGE_LID) {
			return msim_web_challenge(session, msg);
		}
	}

	/* If a callback is registered for this userid lookup, call it. */
	cb = g_hash_table_lookup(session->user_lookup_cb, GUINT_TO_POINTER(rid));
	data = g_hash_table_lookup(session->user_lookup_cb_data, GUINT_TO_POINTER(rid));

	if (cb) {
		purple_debug_info("msim", "msim_process_reply: calling callback now\n");
		/* Clone message, so that the callback 'cb' can use it (needs to free it also). */
		cb(session, msg, data);
		g_hash_table_remove(session->user_lookup_cb, GUINT_TO_POINTER(rid));
		g_hash_table_remove(session->user_lookup_cb_data, GUINT_TO_POINTER(rid));
	} else {
		purple_debug_info("msim",
				"msim_process_reply: no callback for rid %d\n", rid);
	}

	return TRUE;
}

/**
 * Handle an error from the server.
 *
 * @param session
 * @param msg The message.
 *
 * @return TRUE if successfully reported error.
 */
static gboolean
msim_error(MsimSession *session, MsimMessage *msg)
{
	gchar *errmsg, *full_errmsg;
	guint err;

	g_return_val_if_fail(msg != NULL, FALSE);

	err = msim_msg_get_integer(msg, "err");
	errmsg = msim_msg_get_string(msg, "errmsg");

	full_errmsg = g_strdup_printf(_("Protocol error, code %d: %s"), err,
			errmsg ? errmsg : "no 'errmsg' given");

	g_free(errmsg);

	purple_debug_info("msim", "msim_error (sesskey=%d): %s\n",
			session->sesskey, full_errmsg);

	/* Destroy session if fatal. */
	if (msim_msg_get(msg, "fatal")) {
		PurpleConnectionError reason = PURPLE_CONNECTION_ERROR_NETWORK_ERROR;
		purple_debug_info("msim", "fatal error, closing\n");

		switch (err) {
			case MSIM_ERROR_INCORRECT_PASSWORD: /* Incorrect password */
				reason = PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED;
				if (!purple_account_get_remember_password(session->account))
					purple_account_set_password(session->account, NULL);
#ifdef MSIM_MAX_PASSWORD_LENGTH
				if (session->account->password && (strlen(session->account->password) > MSIM_MAX_PASSWORD_LENGTH)) {
					gchar *suggestion;

					suggestion = g_strdup_printf(_("%s Your password is "
							"%zu characters, which is longer than the "
							"maximum length of %d.  Please shorten your "
							"password at http://profileedit.myspace.com/index.cfm?fuseaction=accountSettings.changePassword and try again."),
							full_errmsg,
							strlen(session->account->password),
							MSIM_MAX_PASSWORD_LENGTH);

					/* Replace full_errmsg. */
					g_free(full_errmsg);
					full_errmsg = suggestion;
				} else {
					g_free(full_errmsg);
					full_errmsg = g_strdup(_("Incorrect username or password"));
				}
#endif
				break;
			case MSIM_ERROR_LOGGED_IN_ELSEWHERE: /* Logged in elsewhere */
				reason = PURPLE_CONNECTION_ERROR_NAME_IN_USE;
				if (!purple_account_get_remember_password(session->account))
					purple_account_set_password(session->account, NULL);
				break;
		}
		purple_connection_error_reason(session->gc, reason, full_errmsg);
	} else {
		purple_notify_error(session->account, _("MySpaceIM Error"), full_errmsg, NULL);
	}

	g_free(full_errmsg);

	return TRUE;
}

/**
 * Process a message.
 *
 * @param session
 * @param msg A message from the server, ready for processing (possibly with resolved username information attached). Caller frees.
 *
 * @return TRUE if successful. FALSE if processing failed.
 */
static gboolean
msim_process(MsimSession *session, MsimMessage *msg)
{
	g_return_val_if_fail(session != NULL, FALSE);
	g_return_val_if_fail(msg != NULL, FALSE);

	if (msim_msg_get_integer(msg, "lc") == 1) {
		return msim_login_challenge(session, msg);
	} else if (msim_msg_get_integer(msg, "lc") == 2) {
		/* return msim_we_are_logged_on(session, msg); */
		if (msim_is_username_set(session, msg)) {
			return msim_we_are_logged_on(session);
		} else {
			/* No username is set... We'll wait for the callbacks to do their work */
			/* When they're all done, the last one will call msim_we_are_logged_on() and pick up where we left off */
			return FALSE;
		}
	} else if (msim_msg_get(msg, "bm"))  {
		return msim_incoming_bm(session, msg);
	} else if (msim_msg_get(msg, "rid")) {
		return msim_process_reply(session, msg);
	} else if (msim_msg_get(msg, "error")) {
		return msim_error(session, msg);
	} else if (msim_msg_get(msg, "ka")) {
		return TRUE;
	} else {
		msim_unrecognized(session, msg, "in msim_process");
		return FALSE;
	}
}

/**
 * After a uid is resolved to username, tag it with the username and submit for processing.
 *
 * @param session
 * @param userinfo Response messsage to resolving request.
 * @param data MsimMessage *, the message to attach information to.
 */
static void
msim_incoming_resolved(MsimSession *session, const MsimMessage *userinfo,
		gpointer data)
{
	gchar *username;
	MsimMessage *msg, *body;

	g_return_if_fail(userinfo != NULL);

	body = msim_msg_get_dictionary(userinfo, "body");
	g_return_if_fail(body != NULL);

	username = msim_msg_get_string(body, "UserName");
	g_return_if_fail(username != NULL);
	/* Note: username will be owned by 'msg' below. */

	msg = (MsimMessage *)data;
	g_return_if_fail(msg != NULL);

	/* TODO: more elegant solution than below. attach whole message? */
	/* Special elements name beginning with '_', we'll use internally within the
	 * program (did not come directly from the wire). */
	msg = msim_msg_append(msg, "_username", MSIM_TYPE_STRING, username); /* This makes 'msg' the owner of 'username' */

	/* TODO: attach more useful information, like ImageURL */

	msim_process(session, msg);

	msim_msg_free(msg);
	msim_msg_free(body);
}

/**
 * Preprocess incoming messages, resolving as needed, calling
 * msim_process() when ready to process.
 *
 * @param session
 * @param msg MsimMessage *, freed by caller.
 */
static gboolean
msim_preprocess_incoming(MsimSession *session, MsimMessage *msg)
{
	g_return_val_if_fail(msg != NULL, FALSE);

	if (msim_msg_get(msg, "bm") && msim_msg_get(msg, "f")) {
		guint uid;
		const gchar *username;

		/* 'f' = userid message is from, in buddy messages */
		uid = msim_msg_get_integer(msg, "f");

		username = msim_uid2username_from_blist(session->account, uid);

		if (username) {
			/* Know username already, use it. */
			purple_debug_info("msim", "msim_preprocess_incoming: tagging with _username=%s\n",
					username);
			msg = msim_msg_append(msg, "_username", MSIM_TYPE_STRING, g_strdup(username));
			return msim_process(session, msg);

		} else {
			gchar *from;

			/* Send lookup request. */
			/* XXX: where is msim_msg_get_string() freed? make _strdup and _nonstrdup. */
			purple_debug_info("msim", "msim_incoming: sending lookup, setting up callback\n");
			from = msim_msg_get_string(msg, "f");
			msim_lookup_user(session, from, msim_incoming_resolved, msim_msg_clone(msg));
			g_free(from);

			/* indeterminate */
			return TRUE;
		}
	} else {
		/* Nothing to resolve - send directly to processing. */
		return msim_process(session, msg);
	}
}

/**
 * Callback when input available.
 *
 * @param gc_uncasted A PurpleConnection pointer.
 * @param source File descriptor.
 * @param cond PURPLE_INPUT_READ
 *
 * Reads the input, and calls msim_preprocess_incoming() to handle it.
 */
static void
msim_input_cb(gpointer gc_uncasted, gint source, PurpleInputCondition cond)
{
	PurpleConnection *gc;
	MsimSession *session;
	gchar *end;
	int n;

	g_return_if_fail(gc_uncasted != NULL);
	g_return_if_fail(source >= 0);  /* Note: 0 is a valid fd */

	gc = (PurpleConnection *)(gc_uncasted);
	session = gc->proto_data;

	/* libpurple/eventloop.h only defines these two */
	if (cond != PURPLE_INPUT_READ && cond != PURPLE_INPUT_WRITE) {
		purple_debug_info("msim_input_cb", "unknown condition=%d\n", cond);
		purple_connection_error_reason (gc,
			PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
			_("Invalid input condition"));
		return;
	}

	g_return_if_fail(cond == PURPLE_INPUT_READ);

	/* Mark down that we got data, so we don't timeout. */
	session->last_comm = time(NULL);

	/* If approaching end of buffer, reallocate some more memory. */
	if (session->rxsize < session->rxoff + MSIM_READ_BUF_SIZE) {
		purple_debug_info("msim",
			"msim_input_cb: %d-byte read buffer full, rxoff=%d, " "growing by %d bytes\n",
			session->rxsize, session->rxoff, MSIM_READ_BUF_SIZE);
			session->rxsize += MSIM_READ_BUF_SIZE;
			session->rxbuf = g_realloc(session->rxbuf, session->rxsize);

		return;
	}

	purple_debug_info("msim", "dynamic buffer at %d (max %d), reading up to %d\n",
			session->rxoff, session->rxsize,
			MSIM_READ_BUF_SIZE - session->rxoff - 1);

	/* Read into buffer. On Win32, need recv() not read(). session->fd also holds
	 * the file descriptor, but it sometimes differs from the 'source' parameter.
	 */
	n = recv(session->fd,
		 session->rxbuf + session->rxoff,
		 session->rxsize - session->rxoff - 1, 0);

	if (n < 0) {
		gchar *tmp;

		if (errno == EAGAIN)
			/* No worries */
			return;

		tmp = g_strdup_printf(_("Lost connection with server: %s"),
				g_strerror(errno));
		purple_connection_error_reason(gc,
				PURPLE_CONNECTION_ERROR_NETWORK_ERROR, tmp);
		g_free(tmp);
		return;
	} else if (n == 0) {
		purple_connection_error_reason(gc,
				PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
				_("Server closed the connection"));
		return;
	}

	/* Null terminate */
	purple_debug_info("msim", "msim_input_cb: going to null terminate "
			"at n=%d\n", n);
	session->rxbuf[session->rxoff + n] = 0;

#ifdef MSIM_CHECK_EMBEDDED_NULLS
	/* Check for embedded NULs. I don't handle them, and they shouldn't occur. */
	if (strlen(session->rxbuf + session->rxoff) != n) {
		/* Occurs after login, but it is not a null byte. */
		purple_debug_info("msim", "msim_input_cb: strlen=%d, but read %d bytes"
				"--null byte encountered?\n",
				strlen(session->rxbuf + session->rxoff), n);
		/*purple_connection_error_reason (gc,
				PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
				"Invalid message - null byte on input"); */
		return;
	}
#endif

	session->rxoff += n;
	purple_debug_info("msim", "msim_input_cb: read=%d\n", n);

#ifdef MSIM_DEBUG_RXBUF
	purple_debug_info("msim", "buf=<%s>\n", session->rxbuf);
#endif

	/* Look for \\final\\ end markers. If found, process message. */
	while((end = strstr(session->rxbuf, MSIM_FINAL_STRING))) {
		MsimMessage *msg;

#ifdef MSIM_DEBUG_RXBUF
		purple_debug_info("msim", "in loop: buf=<%s>\n", session->rxbuf);
#endif
		*end = 0;
		msg = msim_parse(session->rxbuf);
		if (!msg) {
			purple_debug_info("msim", "msim_input_cb: couldn't parse rxbuf\n");
			purple_connection_error_reason (gc,
				PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
				_("Unable to parse message"));
			break;
		} else {
			/* Process message and then free it (processing function should
			 * clone message if it wants to keep it afterwards.) */
			if (!msim_preprocess_incoming(session, msg)) {
				msim_msg_dump("msim_input_cb: preprocessing message failed on msg: %s\n", msg);
			}
			msim_msg_free(msg);
		}

		/* Move remaining part of buffer to beginning. */
		session->rxoff -= strlen(session->rxbuf) + strlen(MSIM_FINAL_STRING);
		memmove(session->rxbuf, end + strlen(MSIM_FINAL_STRING),
				session->rxsize - (end + strlen(MSIM_FINAL_STRING) - session->rxbuf));

		/* Clear end of buffer
		 * memset(end, 0, MSIM_READ_BUF_SIZE - (end - session->rxbuf));
		 */
	}
}

/**
 * Callback when connected. Sets up input handlers.
 *
 * @param data A PurpleConnection pointer.
 * @param source File descriptor.
 * @param error_message
 */
static void
msim_connect_cb(gpointer data, gint source, const gchar *error_message)
{
	PurpleConnection *gc;
	MsimSession *session;

	g_return_if_fail(data != NULL);

	gc = (PurpleConnection *)data;
	session = (MsimSession *)gc->proto_data;

	if (source < 0) {
		gchar *tmp = g_strdup_printf(_("Unable to connect: %s"),
				error_message);
		purple_connection_error_reason (gc,
			PURPLE_CONNECTION_ERROR_NETWORK_ERROR, tmp);
			g_free(tmp);
		return;
	}

	session->fd = source;

	gc->inpa = purple_input_add(source, PURPLE_INPUT_READ, msim_input_cb, gc);
}

/**
 * Start logging in to the MSIM servers.
 *
 * @param acct Account information to use to login.
 */
static void
msim_login(PurpleAccount *acct)
{
	PurpleConnection *gc;
	const gchar *host;
	int port;

	g_return_if_fail(acct != NULL);
	g_return_if_fail(acct->username != NULL);

	purple_debug_info("msim", "logging in %s\n", acct->username);

	gc = purple_account_get_connection(acct);
	gc->proto_data = msim_session_new(acct);
	gc->flags |= PURPLE_CONNECTION_HTML | PURPLE_CONNECTION_NO_URLDESC;

	/*
	 * Lets wipe out our local list of blocked buddies.  We'll get a
	 * list of all blocked buddies from the server, and we shouldn't
	 * have stuff in the local list that isn't on the server list.
	 */
	while (acct->deny != NULL)
		purple_privacy_deny_remove(acct, acct->deny->data, TRUE);

	/* 1. connect to server */
	purple_connection_update_progress(gc, _("Connecting"),
								  0,   /* which connection step this is */
								  4);  /* total number of steps */

	host = purple_account_get_string(acct, "server", MSIM_SERVER);
	port = purple_account_get_int(acct, "port", MSIM_PORT);

	/* From purple.sf.net/api:
	 * """Note that this function name can be misleading--although it is called
	 * "proxy connect," it is used for establishing any outgoing TCP connection,
	 * whether through a proxy or not.""" */

	/* Calls msim_connect_cb when connected. */
	if (!purple_proxy_connect(gc, acct, host, port, msim_connect_cb, gc)) {
		/* TODO: try other ports if in auto mode, then save
		 * working port and try that first next time. */
		purple_connection_error_reason (gc,
			PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
			_("Unable to connect"));
		return;
	}
}

static void
msim_buddy_free(PurpleBuddy *buddy)
{
	msim_user_free(purple_buddy_get_protocol_data(buddy));
	purple_buddy_set_protocol_data(buddy, NULL);
}

/**
 * Close the connection.
 *
 * @param gc The connection.
 */
static void
msim_close(PurpleConnection *gc)
{
	GSList *buddies;
	MsimSession *session;

	if (gc == NULL) {
		return;
	}

	/*
	 * Free our protocol-specific buddy data.  It almost seems like libpurple
	 * should call our buddy_free prpl callback so that we don't need to do
	 * this... but it doesn't, so we do.
	 */
	buddies = purple_find_buddies(purple_connection_get_account(gc), NULL);
	while (buddies != NULL) {
		msim_buddy_free(buddies->data);
		buddies = g_slist_delete_link(buddies, buddies);
	}

	session = (MsimSession *)gc->proto_data;
	if (session == NULL)
		return;

	gc->proto_data = NULL;

	if (session->gc->inpa) {
		purple_input_remove(session->gc->inpa);
	}
	if (session->fd >= 0) {
		close(session->fd);
		session->fd = -1;
	}

	msim_session_destroy(session);
}

/**
 * Schedule an IM to be sent once the user ID is looked up.
 *
 * @param gc Connection.
 * @param who A user id, email, or username to send the message to.
 * @param message Instant message text to send.
 * @param flags Flags.
 *
 * @return 1 if successful or postponed, -1 if failed
 *
 * Allows sending to a user by username, email address, or userid. If
 * a username or email address is given, the userid must be looked up.
 * This function does that by calling msim_postprocess_outgoing().
 */
static int
msim_send_im(PurpleConnection *gc, const gchar *who, const gchar *message,
		PurpleMessageFlags flags)
{
	MsimSession *session;
	gchar *message_msim;
	int rc;

	g_return_val_if_fail(gc != NULL, -1);
	g_return_val_if_fail(who != NULL, -1);
	g_return_val_if_fail(message != NULL, -1);

	/* 'flags' has many options, not used here. */

	session = (MsimSession *)gc->proto_data;

	message_msim = html_to_msim_markup(session, message);

	if (msim_send_bm(session, who, message_msim, MSIM_BM_ACTION_OR_IM_DELAYABLE)) {
		/* Return 1 to have Purple show this IM as being sent, 0 to not. I always
		 * return 1 even if the message could not be sent, since I don't know if
		 * it has failed yet--because the IM is only sent after the userid is
		 * retrieved from the server (which happens after this function returns).
		 * If an error does occur, it should be logged to the IM window.
		 */
		rc = 1;
	} else {
		rc = -1;
	}

	g_free(message_msim);

	return rc;
}

/**
 * Handle when our user starts or stops typing to another user.
 *
 * @param gc
 * @param name The buddy name to which our user is typing to
 * @param state PURPLE_TYPING, PURPLE_TYPED, PURPLE_NOT_TYPING
 *
 * @return 0
 */
static unsigned int
msim_send_typing(PurpleConnection *gc, const gchar *name,
		PurpleTypingState state)
{
	const gchar *typing_str;
	MsimSession *session;

	g_return_val_if_fail(gc != NULL, 0);
	g_return_val_if_fail(name != NULL, 0);

	session = (MsimSession *)gc->proto_data;

	switch (state) {
		case PURPLE_TYPING:
			typing_str = "%typing%";
			break;

		case PURPLE_TYPED:
		case PURPLE_NOT_TYPING:
		default:
			typing_str = "%stoptyping%";
			break;
	}

	purple_debug_info("msim", "msim_send_typing(%s): %d (%s)\n", name, state, typing_str);
	msim_send_bm(session, name, typing_str, MSIM_BM_ACTION_OR_IM_INSTANT);
	return 0;
}

/**
 * Callback for msim_get_info(), for when user info is received.
 */
static void
msim_get_info_cb(MsimSession *session, const MsimMessage *user_info_msg,
		gpointer data)
{
	MsimMessage *msg;
	gchar *username;
	PurpleNotifyUserInfo *user_info;
	MsimUser *user;

	/* Get user{name,id} from msim_get_info, passed as an MsimMessage for
	   orthogonality. */
	msg = (MsimMessage *)data;
	g_return_if_fail(msg != NULL);

	username = msim_msg_get_string(msg, "user");
	if (!username) {
		purple_debug_info("msim", "msim_get_info_cb: no 'user' in msg\n");
		return;
	}

	msim_msg_free(msg);
	purple_debug_info("msim", "msim_get_info_cb: got for user: %s\n", username);

	user = msim_find_user(session, username);

	if (!user) {
		/* User isn't on blist, create a temporary user to store info. */
		user = g_new0(MsimUser, 1);
		user->temporary_user = TRUE;
	}

	/* Update user structure with new information */
	msim_store_user_info(session, user_info_msg, user);

	user_info = purple_notify_user_info_new();

	/* Append data from MsimUser to PurpleNotifyUserInfo for display, full */
	msim_append_user_info(session, user_info, user, TRUE);

	purple_notify_userinfo(session->gc, username, user_info, NULL, NULL);
	purple_debug_info("msim", "msim_get_info_cb: username=%s\n", username);

	purple_notify_user_info_destroy(user_info);

	if (user->temporary_user)
		msim_user_free(user);
	g_free(username);
}

/**
 * Retrieve a user's profile.
 * @param username Username, user ID, or email address to lookup.
 */
static void
msim_get_info(PurpleConnection *gc, const gchar *username)
{
	MsimSession *session;
	MsimUser *user;
	gchar *user_to_lookup;
	MsimMessage *user_msg;

	g_return_if_fail(gc != NULL);
	g_return_if_fail(username != NULL);

	session = (MsimSession *)gc->proto_data;

	/* Obtain uid of buddy. */
	user = msim_find_user(session, username);

	/* If is on buddy list, lookup by uid since it is faster. */
	if (user && user->id) {
		user_to_lookup = g_strdup_printf("%d", user->id);
	} else {
		/* Looking up buddy not on blist. Lookup by whatever user entered. */
		user_to_lookup = g_strdup(username);
	}

	/* Pass the username to msim_get_info_cb(), because since we lookup
	 * by userid, the userinfo message will only contain the uid (not
	 * the username) but it would be useful to display the username too.
	 */
	user_msg = msim_msg_new(
			"user", MSIM_TYPE_STRING, g_strdup(username),
			NULL);
	purple_debug_info("msim", "msim_get_info, setting up lookup, user=%s\n", username);

	msim_lookup_user(session, user_to_lookup, msim_get_info_cb, user_msg);

	g_free(user_to_lookup);
}

/**
 * Set status using an MSIM_STATUS_CODE_* value.
 * @param status_code An MSIM_STATUS_CODE_* value.
 * @param statstring Status string, must be a dynamic string (will be freed by msim_send).
 */
static void
msim_set_status_code(MsimSession *session, guint status_code, gchar *statstring)
{
	g_return_if_fail(statstring != NULL);

	purple_debug_info("msim", "msim_set_status_code: going to set status to code=%d,str=%s\n",
			status_code, statstring);

	if (!msim_send(session,
			"status", MSIM_TYPE_INTEGER, status_code,
			"sesskey", MSIM_TYPE_INTEGER, session->sesskey,
			"statstring", MSIM_TYPE_STRING, statstring,
			"locstring", MSIM_TYPE_STRING, g_strdup(""),
			NULL))
	{
		purple_debug_info("msim", "msim_set_status: failed to set status\n");
	}
}

/**
 * Set your status - callback for when user manually sets it.
 */
static void
msim_set_status(PurpleAccount *account, PurpleStatus *status)
{
	PurpleStatusType *type;
	PurplePresence *pres;
	MsimSession *session;
	guint status_code;
	const gchar *message;
	gchar *stripped;
	gchar *unrecognized_msg;

	session = (MsimSession *)account->gc->proto_data;

	type = purple_status_get_type(status);
	pres = purple_status_get_presence(status);

	switch (purple_status_type_get_primitive(type)) {
		case PURPLE_STATUS_AVAILABLE:
			purple_debug_info("msim", "msim_set_status: available (%d->%d)\n", PURPLE_STATUS_AVAILABLE,
					MSIM_STATUS_CODE_ONLINE);
			status_code = MSIM_STATUS_CODE_ONLINE;
			break;

		case PURPLE_STATUS_INVISIBLE:
			purple_debug_info("msim", "msim_set_status: invisible (%d->%d)\n", PURPLE_STATUS_INVISIBLE,
					MSIM_STATUS_CODE_OFFLINE_OR_HIDDEN);
			status_code = MSIM_STATUS_CODE_OFFLINE_OR_HIDDEN;
			break;

		case PURPLE_STATUS_AWAY:
			purple_debug_info("msim", "msim_set_status: away (%d->%d)\n", PURPLE_STATUS_AWAY,
					MSIM_STATUS_CODE_AWAY);
			status_code = MSIM_STATUS_CODE_AWAY;
			break;

		default:
			purple_debug_info("msim", "msim_set_status: unknown "
					"status interpreting as online");
			status_code = MSIM_STATUS_CODE_ONLINE;

			unrecognized_msg = g_strdup_printf("msim_set_status, unrecognized status type: %d\n",
					purple_status_type_get_primitive(type));
			msim_unrecognized(session, NULL, unrecognized_msg);
			g_free(unrecognized_msg);

			break;
	}

	message = purple_status_get_attr_string(status, "message");

	/* Status strings are plain text. */
	if (message != NULL)
		stripped = purple_markup_strip_html(message);
	else
		stripped = g_strdup("");

	msim_set_status_code(session, status_code, stripped);

	/* If we should be idle, set that status. Time is irrelevant here. */
	if (purple_presence_is_idle(pres) && status_code != MSIM_STATUS_CODE_OFFLINE_OR_HIDDEN)
		msim_set_idle(account->gc, 1);
}

/**
 * Go idle.
 */
static void
msim_set_idle(PurpleConnection *gc, int time)
{
	MsimSession *session;
	PurpleStatus *status;

	g_return_if_fail(gc != NULL);

	session = (MsimSession *)gc->proto_data;

	status = purple_account_get_active_status(session->account);

	if (time == 0) {
		/* Going back from idle. In msim, idle is mutually exclusive
		 * from the other states (you can only be away or idle, but not
		 * both, for example), so by going non-idle I go back to what
		 * libpurple says I should be.
		 */
		msim_set_status(session->account, status);
	} else {
		const gchar *message;
		gchar *stripped;

		/* Set the idle message to the status message from the real
		 * current status.
		 */
		message = purple_status_get_attr_string(status, "message");
		if (message != NULL)
			stripped = purple_markup_strip_html(message);
		else
			stripped = g_strdup("");

		/* msim doesn't support idle time, so just go idle */
		msim_set_status_code(session, MSIM_STATUS_CODE_IDLE, stripped);
	}
}

/**
 * @return TRUE if everything was ok, FALSE if something went awry.
 */
static gboolean
msim_update_blocklist_for_buddy(MsimSession *session, const char *name, gboolean allow, gboolean block)
{
	MsimMessage *msg;
	GList *list;

	list = NULL;
	list = g_list_prepend(list, allow ? "a+" : "a-");
	list = g_list_prepend(list, "<uid>");
	list = g_list_prepend(list, block ? "b+" : "b-");
	list = g_list_prepend(list, "<uid>");
	list = g_list_reverse(list);

	msg = msim_msg_new(
			"blocklist", MSIM_TYPE_BOOLEAN, TRUE,
			"sesskey", MSIM_TYPE_INTEGER, session->sesskey,
			/* TODO: MsimMessage lists. Currently <uid> isn't replaced in lists. */
			/* "idlist", MSIM_TYPE_STRING, g_strdup("a-|<uid>|b-|<uid>"), */
			"idlist", MSIM_TYPE_LIST, list,
			NULL);

	if (!msim_postprocess_outgoing(session, msg, name, "idlist", NULL)) {
		purple_debug_error("myspace",
				"blocklist command failed for %s, allow=%d, block=%d\n",
				name, allow, block);
		msim_msg_free(msg);
		return FALSE;
	}

	msim_msg_free(msg);

	return TRUE;
}

/**
 * Add a buddy to user's buddy list.
 */
static void
msim_add_buddy(PurpleConnection *gc, PurpleBuddy *buddy, PurpleGroup *group)
{
	MsimSession *session;
	MsimMessage *msg;
	MsimMessage *msg_persist;
	MsimMessage *body;
	const char *name, *gname;

	session = (MsimSession *)gc->proto_data;
	name = purple_buddy_get_name(buddy);
	gname = group ? purple_group_get_name(group) : NULL;

	if (msim_get_user_from_buddy(buddy, FALSE) != NULL)
		return;

	purple_debug_info("msim", "msim_add_buddy: want to add %s to %s\n",
			name, gname ? gname : "(no group)");

	msg = msim_msg_new(
			"addbuddy", MSIM_TYPE_BOOLEAN, TRUE,
			"sesskey", MSIM_TYPE_INTEGER, session->sesskey,
			/* "newprofileid" will be inserted here with uid. */
			"reason", MSIM_TYPE_STRING, g_strdup(""),
			NULL);

	if (!msim_postprocess_outgoing(session, msg, name, "newprofileid", "reason")) {
		purple_notify_error(NULL, NULL, _("Failed to add buddy"), _("'addbuddy' command failed."));
		msim_msg_free(msg);
		return;
	}
	msim_msg_free(msg);

	/* TODO: if addbuddy fails ('error' message is returned), delete added buddy from
	 * buddy list since Purple adds it locally. */

	body = msim_msg_new(
			"ContactID", MSIM_TYPE_STRING, g_strdup("<uid>"),
			"GroupName", MSIM_TYPE_STRING, g_strdup(gname),
			"Position", MSIM_TYPE_INTEGER, 1000,
			"Visibility", MSIM_TYPE_INTEGER, 1,
			"NickName", MSIM_TYPE_STRING, g_strdup(""),
			"NameSelect", MSIM_TYPE_INTEGER, 0,
			NULL);

	/* TODO: Update blocklist. */

	msg_persist = msim_msg_new(
		"persist", MSIM_TYPE_INTEGER, 1,
		"sesskey", MSIM_TYPE_INTEGER, session->sesskey,
		"cmd", MSIM_TYPE_INTEGER, MSIM_CMD_BIT_ACTION | MSIM_CMD_PUT,
		"dsn", MSIM_TYPE_INTEGER, MC_CONTACT_INFO_DSN,
		"uid", MSIM_TYPE_INTEGER, session->userid,
		"lid", MSIM_TYPE_INTEGER, MC_CONTACT_INFO_LID,
		/* TODO: Use msim_new_reply_callback to get rid. */
		"rid", MSIM_TYPE_INTEGER, session->next_rid++,
		"body", MSIM_TYPE_DICTIONARY, body,
		NULL);

	if (!msim_postprocess_outgoing(session, msg_persist, name, "body", NULL))
	{
		purple_notify_error(NULL, NULL, _("Failed to add buddy"), _("persist command failed"));
		msim_msg_free(msg_persist);
		return;
	}
	msim_msg_free(msg_persist);

	/* Add to allow list, remove from block list */
	msim_update_blocklist_for_buddy(session, name, TRUE, FALSE);
}

/**
 * Remove a buddy from the user's buddy list.
 */
static void
msim_remove_buddy(PurpleConnection *gc, PurpleBuddy *buddy, PurpleGroup *group)
{
	MsimSession *session;
	MsimMessage *delbuddy_msg;
	MsimMessage *persist_msg;
	const char *name;

	session = (MsimSession *)gc->proto_data;
	name = purple_buddy_get_name(buddy);

	delbuddy_msg = msim_msg_new(
				"delbuddy", MSIM_TYPE_BOOLEAN, TRUE,
				"sesskey", MSIM_TYPE_INTEGER, session->sesskey,
				/* 'delprofileid' with uid will be inserted here. */
				NULL);

	if (!msim_postprocess_outgoing(session, delbuddy_msg, name, "delprofileid", NULL)) {
		purple_notify_error(NULL, NULL, _("Failed to remove buddy"), _("'delbuddy' command failed"));
		msim_msg_free(delbuddy_msg);
		return;
	}
	msim_msg_free(delbuddy_msg);

	persist_msg = msim_msg_new(
			"persist", MSIM_TYPE_INTEGER, 1,
			"sesskey", MSIM_TYPE_INTEGER, session->sesskey,
			"cmd", MSIM_TYPE_INTEGER, MSIM_CMD_BIT_ACTION | MSIM_CMD_DELETE,
			"dsn", MSIM_TYPE_INTEGER, MD_DELETE_BUDDY_DSN,
			"lid", MSIM_TYPE_INTEGER, MD_DELETE_BUDDY_LID,
			"uid", MSIM_TYPE_INTEGER, session->userid,
			"rid", MSIM_TYPE_INTEGER, session->next_rid++,
			/* <uid> will be replaced by postprocessing */
			"body", MSIM_TYPE_STRING, g_strdup("ContactID=<uid>"),
			NULL);

	if (!msim_postprocess_outgoing(session, persist_msg, name, "body", NULL)) {
		purple_notify_error(NULL, NULL, _("Failed to remove buddy"), _("persist command failed"));
		msim_msg_free(persist_msg);
		return;
	}
	msim_msg_free(persist_msg);

	/*
	 * Remove from our approve list and from our block list (this
	 * doesn't seem like it would be necessary, but the official client
	 * does it)
	 */
	if (!msim_update_blocklist_for_buddy(session, name, FALSE, FALSE)) {
		purple_notify_error(NULL, NULL,
				_("Failed to remove buddy"), _("blocklist command failed"));
		return;
	}
	msim_buddy_free(buddy);
}

/**
 * Remove a buddy from the user's buddy list and add them to the block list.
 */
static void
msim_add_deny(PurpleConnection *gc, const char *name)
{
	MsimSession *session;
	MsimMessage *msg, *body;

	session = (MsimSession *)gc->proto_data;

	/* Remove from buddy list */
	msg = msim_msg_new(
			"delbuddy", MSIM_TYPE_BOOLEAN, TRUE,
			"sesskey", MSIM_TYPE_INTEGER, session->sesskey,
			/* 'delprofileid' with uid will be inserted here. */
			NULL);
	if (!msim_postprocess_outgoing(session, msg, name, "delprofileid", NULL))
		purple_debug_error("myspace", "delbuddy command failed\n");
	msim_msg_free(msg);

	/* Remove from our approve list and add to our block list */
	msim_update_blocklist_for_buddy(session, name, FALSE, TRUE);

	/*
	 * Add the buddy to our list of blocked contacts, so we know they
	 * are blocked if we log in with another client
	 */
	body = msim_msg_new(
			"ContactID", MSIM_TYPE_STRING, g_strdup("<uid>"),
			"Visibility", MSIM_TYPE_INTEGER, 2,
			NULL);
	msg = msim_msg_new(
			"persist", MSIM_TYPE_INTEGER, 1,
			"sesskey", MSIM_TYPE_INTEGER, session->sesskey,
			"cmd", MSIM_TYPE_INTEGER, MSIM_CMD_BIT_ACTION | MSIM_CMD_PUT,
			"dsn", MSIM_TYPE_INTEGER, MC_CONTACT_INFO_DSN,
			"lid", MSIM_TYPE_INTEGER, MC_CONTACT_INFO_LID,
			"rid", MSIM_TYPE_INTEGER, session->next_rid++,
			"body", MSIM_TYPE_DICTIONARY, body,
			NULL);
	if (!msim_postprocess_outgoing(session, msg, name, "body", NULL))
		purple_debug_error("myspace", "add to block list command failed\n");
	msim_msg_free(msg);

	/*
	 * TODO: MySpace doesn't allow blocked buddies on our buddy list,
	 *       do they?  If not then we need to remove the buddy from
	 *       libpurple's buddy list.
	 */
}

/**
 * Remove a buddy from the user's block list.
 */
static void
msim_rem_deny(PurpleConnection *gc, const char *name)
{
	MsimSession *session;
	MsimMessage *msg, *body;

	session = (MsimSession *)gc->proto_data;

	/*
	 * Remove from our list of blocked contacts, so we know they
	 * are no longer blocked if we log in with another client
	 */
	body = msim_msg_new(
			"ContactID", MSIM_TYPE_STRING, g_strdup("<uid>"),
			NULL);
	msg = msim_msg_new(
			"persist", MSIM_TYPE_INTEGER, 1,
			"sesskey", MSIM_TYPE_INTEGER, session->sesskey,
			"cmd", MSIM_TYPE_INTEGER, MSIM_CMD_BIT_ACTION | MSIM_CMD_DELETE,
			"dsn", MSIM_TYPE_INTEGER, MC_DELETE_CONTACT_INFO_DSN,
			"lid", MSIM_TYPE_INTEGER, MC_DELETE_CONTACT_INFO_LID,
			"rid", MSIM_TYPE_INTEGER, session->next_rid++,
			"body", MSIM_TYPE_DICTIONARY, body,
			NULL);
	if (!msim_postprocess_outgoing(session, msg, name, "body", NULL))
		purple_debug_error("myspace", "remove from block list command failed\n");
	msim_msg_free(msg);

	/* Remove from our approve list and our block list */
	msim_update_blocklist_for_buddy(session, name, FALSE, FALSE);
}

/**
 * Returns a string of a username in canonical form. Basically removes all the
 * spaces, lowercases the string, and looks up user IDs to usernames.
 * Normalizing tom, TOM, Tom, and 6221 wil all return 'tom'.
 *
 * Borrowed this code from oscar_normalize. Added checking for
 * "if userid, get name before normalizing"
 */
static const char *msim_normalize(const PurpleAccount *account, const char *str) {
	static char normalized[BUF_LEN];
	char *tmp1, *tmp2;
	int i, j;
	guint id;

	g_return_val_if_fail(str != NULL, NULL);

	if (msim_is_userid(str)) {
		/* Have user ID, we need to get their username first :) */
		const char *username;

		/* If the account does not exist, we can't look up the user. */
		if (!account || !account->gc)
			return str;

		id = atol(str);
		username = msim_uid2username_from_blist((PurpleAccount *)account, id);
		if (!username) {
			/* Not in buddy list... scheisse... TODO: Manual Lookup! Bug #4631 */
			/* Note: manual lookup using msim_lookup_user() is a problem inside
			 * msim_normalize(), because msim_lookup_user() calls a callback function
			 * when the user information has been looked up, but msim_normalize() expects
			 * the result immediately. */
			strncpy(normalized, str, BUF_LEN);
		} else {
			strncpy(normalized, username, BUF_LEN);
		}
	} else {
		/* Have username. */
		strncpy(normalized, str, BUF_LEN);
	}

	/* Strip spaces. */
	for (i=0, j=0; normalized[j]; j++) {
		if (normalized[j] != ' ')
			normalized[i++] = normalized[j];
	}
	normalized[i] = '\0';

	/* Lowercase and perform UTF-8 normalization. */
	tmp1 = g_utf8_strdown(normalized, -1);
	tmp2 = g_utf8_normalize(tmp1, -1, G_NORMALIZE_DEFAULT);
	g_snprintf(normalized, sizeof(normalized), "%s", tmp2);
	g_free(tmp2);
	g_free(tmp1);

	/* TODO: re-add caps and spacing back to what the user wanted.
	 * User can format their own names, for example 'msimprpl' is shown
	 * as 'MsIm PrPl' in the official client.
	 *
	 * TODO: file a ticket to add this enhancement.
	 */

	return normalized;
}

/**
 * Return whether the buddy can be messaged while offline.
 *
 * The protocol supports offline messages in just the same way as online
 * messages.
 */
static gboolean
msim_offline_message(const PurpleBuddy *buddy)
{
	return TRUE;
}

/**
 * Send raw data to the server, possibly with embedded NULs.
 *
 * Used in prpl_info struct, so that plugins can have the most possible
 * control of what is sent over the connection. Inside this prpl,
 * msim_send_raw() is used, since it sends NUL-terminated strings (easier).
 *
 * @param gc PurpleConnection
 * @param buf Buffer to send
 * @param total_bytes Size of buffer to send
 *
 * @return Bytes successfully sent, or -1 on error.
 */
/*
 * TODO: This needs to do non-blocking writes and use a watcher to check
  *      when the fd is available to be written to.
 */
static int
msim_send_really_raw(PurpleConnection *gc, const char *buf, int total_bytes)
{
	int total_bytes_sent;
	MsimSession *session;

	g_return_val_if_fail(gc != NULL, -1);
	g_return_val_if_fail(buf != NULL, -1);
	g_return_val_if_fail(total_bytes >= 0, -1);

	session = (MsimSession *)gc->proto_data;

	/* Loop until all data is sent, or a failure occurs. */
	total_bytes_sent = 0;
	do {
		int bytes_sent;

		bytes_sent = send(session->fd, buf + total_bytes_sent,
				total_bytes - total_bytes_sent, 0);

		if (bytes_sent < 0) {
			purple_debug_info("msim", "msim_send_raw(%s): send() failed: %s\n",
					buf, g_strerror(errno));
			return total_bytes_sent;
		}
		total_bytes_sent += bytes_sent;

	} while(total_bytes_sent < total_bytes);

	return total_bytes_sent;
}

/**
 * Send raw data (given as a NUL-terminated string) to the server.
 *
 * @param session
 * @param msg The raw data to send, in a NUL-terminated string.
 *
 * @return TRUE if succeeded, FALSE if not.
 *
 */
gboolean
msim_send_raw(MsimSession *session, const gchar *msg)
{
	size_t len;

	g_return_val_if_fail(msg != NULL, FALSE);

	purple_debug_info("msim", "msim_send_raw: writing <%s>\n", msg);
	len = strlen(msg);

	return msim_send_really_raw(session->gc, msg, len) == len;
}

static GHashTable *
msim_get_account_text_table(PurpleAccount *unused)
{
	GHashTable *table;

	table = g_hash_table_new(g_str_hash, g_str_equal);

	g_hash_table_insert(table, "login_label", (gpointer)_("Email Address..."));

	return table;
}

/**
 * Callbacks called by Purple, to access this plugin.
 */
static PurplePluginProtocolInfo prpl_info = {
	/* options */
	  OPT_PROTO_USE_POINTSIZE        /* specify font size in sane point size */
	| OPT_PROTO_MAIL_CHECK,

	/* | OPT_PROTO_IM_IMAGE - TODO: direct images. */
	NULL,              /* user_splits */
	NULL,              /* protocol_options */
	NO_BUDDY_ICONS,    /* icon_spec - TODO: eventually should add this */
	msim_list_icon,    /* list_icon */
	NULL,              /* list_emblems */
	msim_status_text,  /* status_text */
	msim_tooltip_text, /* tooltip_text */
	msim_status_types, /* status_types */
	msim_blist_node_menu,  /* blist_node_menu */
	NULL,              /* chat_info */
	NULL,              /* chat_info_defaults */
	msim_login,        /* login */
	msim_close,        /* close */
	msim_send_im,      /* send_im */
	NULL,              /* set_info */
	msim_send_typing,  /* send_typing */
	msim_get_info,     /* get_info */
	msim_set_status,   /* set_status */
	msim_set_idle,     /* set_idle */
	NULL,              /* change_passwd */
	msim_add_buddy,    /* add_buddy */
	NULL,              /* add_buddies */
	msim_remove_buddy, /* remove_buddy */
	NULL,              /* remove_buddies */
	NULL,              /* add_permit */
	msim_add_deny,     /* add_deny */
	NULL,              /* rem_permit */
	msim_rem_deny,     /* rem_deny */
	NULL,              /* set_permit_deny */
	NULL,              /* join_chat */
	NULL,              /* reject chat invite */
	NULL,              /* get_chat_name */
	NULL,              /* chat_invite */
	NULL,              /* chat_leave */
	NULL,              /* chat_whisper */
	NULL,              /* chat_send */
	NULL,              /* keepalive */
	NULL,              /* register_user */
	NULL,              /* get_cb_info */
	NULL,              /* get_cb_away */
	NULL,              /* alias_buddy */
	NULL,              /* group_buddy */
	NULL,              /* rename_group */
	msim_buddy_free,   /* buddy_free */
	NULL,              /* convo_closed */
	msim_normalize,    /* normalize */
	NULL,              /* set_buddy_icon */
	NULL,              /* remove_group */
	NULL,              /* get_cb_real_name */
	NULL,              /* set_chat_topic */
	NULL,              /* find_blist_chat */
	NULL,              /* roomlist_get_list */
	NULL,              /* roomlist_cancel */
	NULL,              /* roomlist_expand_category */
	NULL,              /* can_receive_file */
	NULL,              /* send_file */
	NULL,              /* new_xfer */
	msim_offline_message,  /* offline_message */
	NULL,              /* whiteboard_prpl_ops */
	msim_send_really_raw,  /* send_raw */
	NULL,                  /* roomlist_room_serialize */
	NULL,                  /* unregister_user */
	msim_send_attention,   /* send_attention */
	msim_attention_types,  /* attention_types */
	sizeof(PurplePluginProtocolInfo), /* struct_size */
	msim_get_account_text_table,              /* get_account_text_table */
	NULL,                   /* initiate_media */
	NULL,                   /* get_media_caps */
	NULL,                   /* get_moods */
	NULL,                   /* set_public_alias */
	NULL,                   /* get_public_alias */
	NULL,                   /* add_buddy_with_invite */
	NULL                    /* add_buddies_with_invite */
};

/**
 * Load the plugin.
 */
static gboolean
msim_load(PurplePlugin *plugin)
{
	/* If compiled to use RC4 from libpurple, check if it is really there. */
	if (!purple_ciphers_find_cipher("rc4")) {
		purple_debug_error("msim", "rc4 not in libpurple, but it is required - not loading MySpaceIM plugin!\n");
		purple_notify_error(plugin, _("Missing Cipher"),
				_("The RC4 cipher could not be found"),
				_("Upgrade "
					"to a libpurple with RC4 support (>= 2.0.1). MySpaceIM "
					"plugin will not be loaded."));
		return FALSE;
	}
	return TRUE;
}

/**
 * Called when friends have been imported to buddy list on server.
 */
static void
msim_import_friends_cb(MsimSession *session, const MsimMessage *reply, gpointer user_data)
{
	MsimMessage *body;
	gchar *completed;

	/* Check if the friends were imported successfully. */
	body = msim_msg_get_dictionary(reply, "body");
	g_return_if_fail(body != NULL);
	completed = msim_msg_get_string(body, "Completed");
	msim_msg_free(body);
	g_return_if_fail(completed != NULL);
	if (!g_str_equal(completed, "True"))
	{
		purple_debug_info("msim_import_friends_cb",
				"failed to import friends: %s", completed);
		purple_notify_error(session->account, _("Add friends from MySpace.com"),
				_("Importing friends failed"), NULL);
		g_free(completed);
		return;
	}
	g_free(completed);

	purple_debug_info("msim_import_friends_cb",
			"added friends to server-side buddy list, requesting new contacts from server");

	msim_get_contact_list(session, MSIM_CONTACT_LIST_IMPORT_ALL_FRIENDS);

	/* TODO: show, X friends have been added */
}

/**
 * Import friends from myspace.com.
 */
static void msim_import_friends(PurplePluginAction *action)
{
	PurpleConnection *gc;
	MsimSession *session;
	gchar *group_name;

	gc = (PurpleConnection *)action->context;
	session = (MsimSession *)gc->proto_data;

	group_name = "MySpace Friends";

	g_return_if_fail(msim_send(session,
			"persist", MSIM_TYPE_INTEGER, 1,
			"sesskey", MSIM_TYPE_INTEGER, session->sesskey,
			"cmd", MSIM_TYPE_INTEGER, MSIM_CMD_PUT,
			"dsn", MSIM_TYPE_INTEGER, MC_IMPORT_ALL_FRIENDS_DSN,
			"lid", MSIM_TYPE_INTEGER, MC_IMPORT_ALL_FRIENDS_LID,
			"uid", MSIM_TYPE_INTEGER, session->userid,
			"rid", MSIM_TYPE_INTEGER,
				msim_new_reply_callback(session, msim_import_friends_cb, NULL),
			"body", MSIM_TYPE_STRING,
				g_strdup_printf("GroupName=%s", group_name),
			NULL));
}

/**
 * Actions menu for account.
 */
static GList *
msim_actions(PurplePlugin *plugin, gpointer context /* PurpleConnection* */)
{
	GList *menu;
	PurplePluginAction *act;

	menu = NULL;

#if 0
	/* TODO: find out how */
	act = purple_plugin_action_new(_("Find people..."), msim_);
	menu = g_list_append(menu, act);

	act = purple_plugin_action_new(_("Change IM name..."), NULL);
	menu = g_list_append(menu, act);
#endif

	act = purple_plugin_action_new(_("Add friends from MySpace.com"), msim_import_friends);
	menu = g_list_append(menu, act);

	return menu;
}

/**
 * Based on MSN's plugin info comments.
 */
static PurplePluginInfo info = {
	PURPLE_PLUGIN_MAGIC,
	PURPLE_MAJOR_VERSION,
	PURPLE_MINOR_VERSION,
	PURPLE_PLUGIN_PROTOCOL,                           /**< type           */
	NULL,                                             /**< ui_requirement */
	0,                                                /**< flags          */
	NULL,                                             /**< dependencies   */
	PURPLE_PRIORITY_DEFAULT,                          /**< priority       */

	"prpl-myspace",                                   /**< id             */
	"MySpaceIM",                                      /**< name           */
	MSIM_PRPL_VERSION_STRING,                         /**< version        */
	                                                  /**  summary        */
	"MySpaceIM Protocol Plugin",
	                                                  /**  description    */
	"MySpaceIM Protocol Plugin",
	"Jeff Connelly <jeff2@soc.pidgin.im>",            /**< author         */
	"http://developer.pidgin.im/wiki/MySpaceIM/",     /**< homepage       */

	msim_load,                                        /**< load           */
	NULL,                                             /**< unload         */
	NULL,                                             /**< destroy        */
	NULL,                                             /**< ui_info        */
	&prpl_info,                                       /**< extra_info     */
	NULL,                                             /**< prefs_info     */
	msim_actions,                                     /**< msim_actions   */
	NULL,                                             /**< reserved1      */
	NULL,                                             /**< reserved2      */
	NULL,                                             /**< reserved3      */
	NULL                                              /**< reserved4      */
};

#ifdef MSIM_SELF_TEST
/*
 * Test functions.
 * Used to test or try out the internal workings of msimprpl. If you're reading
 * this code for the first time, these functions can be instructive in learning
 * how msimprpl is architected.
 */

/**
 * Test MsimMessage for basic functionality.
 */
static int
msim_test_msg(void)
{
	MsimMessage *msg, *msg_cloned, *msg2;
	GList *list;
	gchar *packed, *packed_expected, *packed_cloned;
	guint failures;

	failures = 0;

	purple_debug_info("msim", "\n\nTesting MsimMessage\n");
	msg = msim_msg_new(NULL);      /* Create a new, empty message. */

	/* Append some new elements. */
	msg = msim_msg_append(msg, "bx", MSIM_TYPE_BINARY, g_string_new_len("XXX", 3));
	msg = msim_msg_append(msg, "k1", MSIM_TYPE_STRING, g_strdup("v1"));
	msg = msim_msg_append(msg, "k1", MSIM_TYPE_INTEGER, GUINT_TO_POINTER(42));
	msg = msim_msg_append(msg, "k1", MSIM_TYPE_STRING, g_strdup("v43"));
	msg = msim_msg_append(msg, "k1", MSIM_TYPE_STRING, g_strdup("v52/xxx\\yyy"));
	msg = msim_msg_append(msg, "k1", MSIM_TYPE_STRING, g_strdup("v7"));
	msim_msg_dump("msg debug str=%s\n", msg);
	packed = msim_msg_pack(msg);

	purple_debug_info("msim", "msg packed=%s\n", packed);

	packed_expected = "\\bx\\WFhY\\k1\\v1\\k1\\42\\k1"
		"\\v43\\k1\\v52/1xxx/2yyy\\k1\\v7\\final\\";

	if (!g_str_equal(packed, packed_expected)) {
		purple_debug_info("msim", "!!!(%d), msim_msg_pack not what expected: %s != %s\n",
				++failures, packed, packed_expected);
	}


	msg_cloned = msim_msg_clone(msg);
	packed_cloned = msim_msg_pack(msg_cloned);

	purple_debug_info("msim", "msg cloned=%s\n", packed_cloned);
	if (!g_str_equal(packed, packed_cloned)) {
		purple_debug_info("msim", "!!!(%d), msim_msg_pack on cloned message not equal to original: %s != %s\n",
				++failures, packed_cloned, packed);
	}

	g_free(packed);
	g_free(packed_cloned);
	msim_msg_free(msg_cloned);
	msim_msg_free(msg);

	/* Try some of the more advanced functionality */
	list = NULL;

	list = g_list_prepend(list, "item3");
	list = g_list_prepend(list, "item2");
	list = g_list_prepend(list, "item1");
	list = g_list_prepend(list, "item0");

	msg = msim_msg_new(NULL);
	msg = msim_msg_append(msg, "string", MSIM_TYPE_STRING, g_strdup("string value"));
	msg = msim_msg_append(msg, "raw", MSIM_TYPE_RAW, g_strdup("raw value"));
	msg = msim_msg_append(msg, "integer", MSIM_TYPE_INTEGER, GUINT_TO_POINTER(3140));
	msg = msim_msg_append(msg, "boolean", MSIM_TYPE_BOOLEAN, GUINT_TO_POINTER(FALSE));
	msg = msim_msg_append(msg, "list", MSIM_TYPE_LIST, list);

	msim_msg_dump("msg with list=%s\n", msg);
	purple_debug_info("msim", "msg with list packed=%s\n", msim_msg_pack(msg));

	msg2 = msim_msg_new(NULL);
	msg2 = msim_msg_append(msg2, "outer", MSIM_TYPE_STRING, g_strdup("outer value"));
	msg2 = msim_msg_append(msg2, "body", MSIM_TYPE_DICTIONARY, msg);
	msim_msg_dump("msg with dict=%s\n", msg2);      /* msg2 now 'owns' msg */
	purple_debug_info("msim", "msg with dict packed=%s\n", msim_msg_pack(msg2));

	msim_msg_free(msg2);

	return failures;
}

/**
 * Test protocol-level escaping/unescaping.
 */
static int
msim_test_escaping(void)
{
	guint failures;
	gchar *raw, *escaped, *unescaped, *expected;

	failures = 0;

	purple_debug_info("msim", "\n\nTesting escaping\n");

	raw = "hello/world\\hello/world";

	escaped = msim_escape(raw);
	purple_debug_info("msim", "msim_test_escaping: raw=%s, escaped=%s\n", raw, escaped);
	expected = "hello/1world/2hello/1world";
	if (!g_str_equal(escaped, expected)) {
		purple_debug_info("msim", "!!!(%d), msim_escape failed: %s != %s\n",
				++failures, escaped, expected);
	}


	unescaped = msim_unescape(escaped);
	g_free(escaped);
	purple_debug_info("msim", "msim_test_escaping: unescaped=%s\n", unescaped);
	if (!g_str_equal(raw, unescaped)) {
		purple_debug_info("msim", "!!!(%d), msim_unescape failed: %s != %s\n",
				++failures, raw, unescaped);
	}

	return failures;
}

static void
msim_test_all(void)
{
	guint failures;

	failures = 0;
	failures += msim_test_msg();
	failures += msim_test_escaping();

	if (failures) {
		purple_debug_info("msim", "msim_test_all HAD FAILURES: %d\n", failures);
	} else {
		purple_debug_info("msim", "msim_test_all - all tests passed!\n");
	}
	exit(0);
}
#endif

#ifdef MSIM_CHECK_NEWER_VERSION
/**
 * Callback for when a currentversion.txt has been downloaded.
 */
static void
msim_check_newer_version_cb(PurpleUtilFetchUrlData *url_data,
		gpointer user_data,
		const gchar *url_text,
		gsize len,
		const gchar *error_message)
{
	GKeyFile *keyfile;
	GError *error;
	GString *data;
	gchar *newest_filever;

	if (!url_text) {
		purple_debug_info("msim_check_newer_version_cb",
				"got error: %s\n", error_message);
		return;
	}

	purple_debug_info("msim_check_newer_version_cb",
			"url_text=%s\n", url_text ? url_text : "(NULL)");

	/* Prepend [group] so that GKeyFile can parse it (requires a group). */
	data = g_string_new(url_text);
	purple_debug_info("msim", "data=%s\n", data->str
			? data->str : "(NULL)");
	data = g_string_prepend(data, "[group]\n");

	purple_debug_info("msim", "data=%s\n", data->str
			? data->str : "(NULL)");

	/* url_text is variable=data\n...†*/

	/* Check FILEVER, 1.0.716.0. 716 is build, MSIM_CLIENT_VERSION */
	/* New (english) version can be downloaded from SETUPURL+SETUPFILE */

	error = NULL;
	keyfile = g_key_file_new();

	/* Default list seperator is ;, but currentversion.txt doesn't have
	 * these, so set to an unused character to avoid parsing problems. */
	g_key_file_set_list_separator(keyfile, '\0');

	g_key_file_load_from_data(keyfile, data->str, data->len,
				G_KEY_FILE_NONE, &error);
	g_string_free(data, TRUE);

	if (error != NULL) {
		purple_debug_info("msim_check_newer_version_cb",
				"couldn't parse, error: %d %d %s\n",
				error->domain, error->code, error->message);
		g_error_free(error);
		return;
	}

	gchar **ks;
	guint n;
	ks = g_key_file_get_keys(keyfile, "group", &n, NULL);
	purple_debug_info("msim", "n=%d\n", n);
	guint i;
	for (i = 0; ks[i] != NULL; ++i)
	{
		purple_debug_info("msim", "%d=%s\n", i, ks[i]);
	}

	newest_filever = g_key_file_get_string(keyfile, "group",
			"FILEVER", &error);

	purple_debug_info("msim_check_newer_version_cb",
			"newest filever: %s\n", newest_filever ?
			newest_filever : "(NULL)");
	if (error != NULL) {
		purple_debug_info("msim_check_newer_version_cb",
				"error: %d %d %s\n",
				error->domain, error->code, error->message);
		g_error_free(error);
	}

	g_key_file_free(keyfile);

	exit(0);
}
#endif

/**
 Handle a myim:addContact command, after username has been looked up.
 */
static void
msim_uri_handler_addContact_cb(MsimSession *session, MsimMessage *userinfo, gpointer data)
{
	MsimMessage *body;
	gchar *username;

	body = msim_msg_get_dictionary(userinfo, "body");
	username = msim_msg_get_string(body, "UserName");
	msim_msg_free(body);

	if (!username) {
		guint uid;

		uid = msim_msg_get_integer(userinfo, "UserID");
		g_return_if_fail(uid != 0);

		username = g_strdup_printf("%d", uid);
	}

	purple_blist_request_add_buddy(session->account, username, _("Buddies"), NULL);

	g_free(username);
}

/* TODO: move uid->username resolving to IM sending and buddy adding functions,
 * so that user can manually add or IM by userid and username automatically
 * looked up if possible? */

/**
 * Handle a myim:sendIM URI command, after username has been looked up.
 */
static void
msim_uri_handler_sendIM_cb(MsimSession *session, MsimMessage *userinfo, gpointer data)
{
	PurpleConversation *conv;
	MsimMessage *body;
	gchar *username;

	body = msim_msg_get_dictionary(userinfo, "body");
	username = msim_msg_get_string(body, "UserName");
	msim_msg_free(body);

	if (!username) {
		guint uid;

		uid = msim_msg_get_integer(userinfo, "UserID");
		g_return_if_fail(uid != 0);

		username = g_strdup_printf("%d", uid);
	}


	conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, username, session->account);
	if (!conv)  {
		purple_debug_info("msim_uri_handler", "creating new conversation for %s\n", username);
		conv = purple_conversation_new(PURPLE_CONV_TYPE_IM, session->account, username);
	}

	/* Just open the window so the user can send an IM. */
	purple_conversation_present(conv);

	g_free(username);
}

static gboolean
msim_uri_handler(const gchar *proto, const gchar *cmd, GHashTable *params)
{
	PurpleAccount *account;
	MsimSession *session;
	GList *l;
	gchar *uid_str, *cid_str;
	guint uid, cid;

	if (g_ascii_strcasecmp(proto, "myim"))
		return FALSE;

	/* Parameters are case-insensitive. */
	uid_str = g_hash_table_lookup(params, "uid");
	cid_str = g_hash_table_lookup(params, "cid");

	uid = uid_str ? atol(uid_str) : 0;
	cid = cid_str ? atol(cid_str) : 0;

	/* Need a contact. */
	g_return_val_if_fail(cid != 0, FALSE);

	/* TODO: if auto=true, "Add all the people on this page to my IM List!", on
	 * http://collect.myspace.com/index.cfm?fuseaction=im.friendslist. Don't need a cid. */

	/* Convert numeric contact ID back to a string. Needed for looking up. Don't just
	 * directly use cid directly from parameters, because it might not be numeric.
	 * It is trivial to change this to allow cID to be a username, but that's not how
	 * the official MySpaceIM client works, so don't provide that functionality. */
	cid_str = g_strdup_printf("%d", cid);


	/* Find our account with specified user id, or use first connected account if uid=0. */
	account = NULL;
	l = purple_accounts_get_all();
	while (l) {
		if (purple_account_is_connected(l->data) &&
			(uid == 0 || purple_account_get_int(l->data, "uid", 0) == uid)) {
			account = l->data;
			break;
		}
		l = l->next;
	}

	if (!account) {
		purple_notify_error(NULL, _("myim URL handler"),
				_("No suitable MySpaceIM account could be found to open this myim URL."),
				_("Enable the proper MySpaceIM account and try again."));
		g_free(cid_str);
		return FALSE;
	}

	session = (MsimSession *)account->gc->proto_data;
	g_return_val_if_fail(session != NULL, FALSE);

	/* Lookup userid to username. TODO: push this down, to IM sending/contact
	 * adding functions. */

	/* myim:sendIM?uID=USERID&cID=CONTACTID */
	if (!g_ascii_strcasecmp(cmd, "sendIM")) {
		msim_lookup_user(session, cid_str, (MSIM_USER_LOOKUP_CB)msim_uri_handler_sendIM_cb, NULL);
		g_free(cid_str);
		return TRUE;

	/* myim:addContact?uID=USERID&cID=CONTACTID */
	} else if (!g_ascii_strcasecmp(cmd, "addContact")) {
		msim_lookup_user(session, cid_str, (MSIM_USER_LOOKUP_CB)msim_uri_handler_addContact_cb, NULL);
		g_free(cid_str);
		return TRUE;
	}

	return FALSE;
}

/**
 * Initialize plugin.
 */
static void
init_plugin(PurplePlugin *plugin)
{
#ifdef MSIM_SELF_TEST
	msim_test_all();
	exit(0);
#endif /* MSIM_SELF_TEST */

	PurpleAccountOption *option;
	static gboolean initialized = FALSE;

#ifdef MSIM_CHECK_NEWER_VERSION
	/* PROBLEM: MySpace's servers always return Content-Location, and
	 * libpurple redirects to it, infinitely, even though it is the same
	 * location we requested! */
	purple_util_fetch_url("http://im.myspace.com/nsis/currentversion.txt",
			FALSE, /* not full URL */
			"MSIMAutoUpdateAgent", /* user agent */
			TRUE,  /* use HTTP/1.1 */
			msim_check_newer_version_cb, NULL);
#endif

	/* TODO: default to automatically try different ports. Make the user be
	 * able to set the first port to try (like LastConnectedPort in Windows client).  */
	option = purple_account_option_string_new(_("Connect server"), "server", MSIM_SERVER);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	option = purple_account_option_int_new(_("Connect port"), "port", MSIM_PORT);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

#ifdef MSIM_USER_WANTS_TO_CONFIGURE_STATUS_TEXT
	option = purple_account_option_bool_new(_("Show display name in status text"), "show_display_name", TRUE);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	option = purple_account_option_bool_new(_("Show headline in status text"), "show_headline", TRUE);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);
#endif

#ifdef MSIM_USER_WANTS_TO_DISABLE_EMOTICONS
	option = purple_account_option_bool_new(_("Send emoticons"), "emoticons", TRUE);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);
#endif

#ifdef MSIM_USER_REALLY_CARES_ABOUT_PRECISE_FONT_SIZES
	option = purple_account_option_int_new(_("Screen resolution (dots per inch)"), "dpi", MSIM_DEFAULT_DPI);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	option = purple_account_option_int_new(_("Base font size (points)"), "base_font_size", MSIM_BASE_FONT_POINT_SIZE);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);
#endif

	/* Code below only runs once. Based on oscar.c's oscar_init(). */
	if (initialized)
		return;

	initialized = TRUE;

	purple_signal_connect(purple_get_core(), "uri-handler", &initialized,
			PURPLE_CALLBACK(msim_uri_handler), NULL);
}

PURPLE_INIT_PLUGIN(myspace, init_plugin, info);
