/**
 * @file msnslp.c MSNSLP support
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
#include "debug.h"

#include "slp.h"
#include "slpcall.h"
#include "slpmsg.h"
#include "msnutils.h"

#include "object.h"
#include "user.h"
#include "sbconn.h"
#include "directconn.h"
#include "p2p.h"
#include "xfer.h"

/* seconds to delay between sending buddy icon requests to the server. */
#define BUDDY_ICON_DELAY 20

typedef struct {
	MsnSession *session;
	const char *remote_user;
	const char *sha1;
} MsnFetchUserDisplayData;

/**************************************************************************
 * SLP Control
 **************************************************************************/

void
msn_slp_send_ok(MsnSlpCall *slpcall, const char *branch,
		const char *type, const char *content)
{
	MsnSlpLink *slplink;
	MsnSlpMessage *slpmsg;

	slplink = slpcall->slplink;

	/* 200 OK */
	slpmsg = msn_slpmsg_sip_new(slpcall, 1,
								"MSNSLP/1.0 200 OK",
								branch, type, content);

	slpmsg->info = "SLP 200 OK";
	slpmsg->text_body = TRUE;

	msn_slplink_queue_slpmsg(slplink, slpmsg);
}

void
msn_slp_send_decline(MsnSlpCall *slpcall, const char *branch,
			 const char *type, const char *content)
{
	MsnSlpLink *slplink;
	MsnSlpMessage *slpmsg;

	slplink = slpcall->slplink;

	/* 603 Decline */
	slpmsg = msn_slpmsg_sip_new(slpcall, 1,
								"MSNSLP/1.0 603 Decline",
								branch, type, content);

	slpmsg->info = "SLP 603 Decline";
	slpmsg->text_body = TRUE;

	msn_slplink_queue_slpmsg(slplink, slpmsg);
}

/**************************************************************************
 * Msg Callbacks
 **************************************************************************/

/*
 * Called on a timeout from end_user_display(). Frees a buddy icon window slow and dequeues the next
 * buddy icon request if there is one.
 */
static gboolean
msn_release_buddy_icon_request_timeout(gpointer data)
{
	MsnUserList *userlist = (MsnUserList *)data;

	/* Free one window slot */
	userlist->buddy_icon_window++;

	/* Clear the tag for our former request timer */
	userlist->buddy_icon_request_timer = 0;

	msn_release_buddy_icon_request(userlist);

	return FALSE;
}

static void
got_user_display(MsnSlpCall *slpcall,
				 const guchar *data, gsize size)
{
	const char *info;
	PurpleAccount *account;

	g_return_if_fail(slpcall != NULL);

	info = slpcall->data_info;
	if (purple_debug_is_verbose())
		purple_debug_info("msn", "Got User Display: %s\n", slpcall->slplink->remote_user);

	account = slpcall->slplink->session->account;

	purple_buddy_icons_set_for_user(account, slpcall->slplink->remote_user,
								  g_memdup(data, size), size, info);
}

static void
end_user_display(MsnSlpCall *slpcall, MsnSession *session)
{
	MsnUserList *userlist;

	g_return_if_fail(session != NULL);

	if (purple_debug_is_verbose())
		purple_debug_info("msn", "End User Display\n");

	userlist = session->userlist;

	/* If the session is being destroyed we better stop doing anything. */
	if (session->destroying)
		return;

	/* Delay before freeing a buddy icon window slot and requesting the next icon, if appropriate.
	 * If we don't delay, we'll rapidly hit the MSN equivalent of AIM's rate limiting; the server will
	 * send us an error 800 like so:
	 *
	 * C: NS 000: XFR 21 SB
	 * S: NS 000: 800 21
	 */
	if (userlist->buddy_icon_request_timer) {
		/* Free the window slot used by this previous request */
		userlist->buddy_icon_window++;

		/* Clear our pending timeout */
		purple_timeout_remove(userlist->buddy_icon_request_timer);
	}

	/* Wait BUDDY_ICON_DELAY s before freeing our window slot and requesting the next icon. */
	userlist->buddy_icon_request_timer = purple_timeout_add_seconds(BUDDY_ICON_DELAY,
														  msn_release_buddy_icon_request_timeout, userlist);
}

static void
fetched_user_display(PurpleUtilFetchUrlData *url_data, gpointer user_data,
	const gchar *url_text, gsize len, const gchar *error_message)
{
	MsnFetchUserDisplayData *data = user_data;
	MsnSession *session = data->session;

	session->url_datas = g_slist_remove(session->url_datas, url_data);

	if (url_text) {
		purple_buddy_icons_set_for_user(session->account, data->remote_user,
		                                g_memdup(url_text, len), len,
		                                data->sha1);
	}

	end_user_display(NULL, session);

	g_free(user_data);
}

static void
request_own_user_display(MsnUser *user)
{
	PurpleAccount *account;
	MsnSession *session;
	MsnObject *my_obj = NULL;
	gconstpointer data = NULL;
	const char *info = NULL;
	size_t len = 0;

	if (purple_debug_is_verbose())
		purple_debug_info("msn", "Requesting our own user display\n");

	session = user->userlist->session;
	account = session->account;
	my_obj = msn_user_get_object(user);

	if (my_obj != NULL) {
		PurpleStoredImage *img = msn_object_get_image(my_obj);
		data = purple_imgstore_get_data(img);
		len = purple_imgstore_get_size(img);
		info = msn_object_get_sha1(my_obj);
	}

	purple_buddy_icons_set_for_user(account, user->passport, g_memdup(data, len), len, info);

	/* Free one window slot */
	session->userlist->buddy_icon_window++;

	if (purple_debug_is_verbose())
		purple_debug_info("msn", "msn_request_user_display(): buddy_icon_window++ yields =%d\n",
				session->userlist->buddy_icon_window);

	msn_release_buddy_icon_request(session->userlist);
}

void
msn_request_user_display(MsnUser *user)
{
	PurpleAccount *account;
	MsnSession *session;
	MsnSlpLink *slplink;
	MsnObject *obj;
	const char *info;

	session = user->userlist->session;
	account = session->account;

	slplink = msn_session_get_slplink(session, user->passport);

	obj = msn_user_get_object(user);

	info = msn_object_get_sha1(obj);

	if (g_ascii_strcasecmp(user->passport,
						   purple_account_get_username(account)))
	{
		const char *url = msn_object_get_url1(obj);
		if (url) {
			MsnFetchUserDisplayData *data = g_new0(MsnFetchUserDisplayData, 1);
			PurpleUtilFetchUrlData *url_data;
			data->session = session;
			data->remote_user = user->passport;
			data->sha1 = info;
			url_data = purple_util_fetch_url_len(url, TRUE, NULL, TRUE, 200*1024,
			                                     fetched_user_display, data);
			session->url_datas = g_slist_prepend(session->url_datas, url_data);
		} else {
			msn_slplink_request_object(slplink, info, got_user_display,
			                           end_user_display, obj);
		}
	}
	else
		request_own_user_display(user);
}

static void
send_file_cb(MsnSlpCall *slpcall)
{
	MsnSlpMessage *slpmsg;
	PurpleXfer *xfer;

	xfer = (PurpleXfer *)slpcall->xfer;
	if (purple_xfer_get_status(xfer) >= PURPLE_XFER_STATUS_STARTED)
		return;

	purple_xfer_ref(xfer);
	purple_xfer_start(xfer, -1, NULL, 0);
	if (purple_xfer_get_status(xfer) != PURPLE_XFER_STATUS_STARTED) {
		purple_xfer_unref(xfer);
		return;
	}
	purple_xfer_unref(xfer);

	slpmsg = msn_slpmsg_file_new(slpcall, purple_xfer_get_size(xfer));

	msn_slplink_send_slpmsg(slpcall->slplink, slpmsg);
}

static gchar *
gen_context(PurpleXfer *xfer, const char *file_name, const char *file_path)
{
	gsize size = 0;
	MsnFileContext context;
	gchar *u8 = NULL;
	gchar *ret;
	gunichar2 *uni = NULL;
	glong currentChar = 0;
	glong len = 0;
	const char *preview;
	gsize preview_len;

	size = purple_xfer_get_size(xfer);

	purple_xfer_prepare_thumbnail(xfer, "png");

	if (!file_name) {
		gchar *basename = g_path_get_basename(file_path);
		u8 = purple_utf8_try_convert(basename);
		g_free(basename);
		file_name = u8;
	}

	uni = g_utf8_to_utf16(file_name, -1, NULL, &len, NULL);

	if (u8) {
		g_free(u8);
		file_name = NULL;
		u8 = NULL;
	}

	preview = purple_xfer_get_thumbnail(xfer, &preview_len);

	context.length = MSN_FILE_CONTEXT_SIZE;
	context.version = 2; /* V.3 contains additional unnecessary data */
	context.file_size = size;
	if (preview)
		context.type = 0;
	else
		context.type = 1;

	len = MIN(len, MAX_FILE_NAME_LEN);
	for (currentChar = 0; currentChar < len; currentChar++) {
		context.file_name[currentChar] = GUINT16_TO_LE(uni[currentChar]);
	}
	memset(&context.file_name[currentChar], 0x00, (MAX_FILE_NAME_LEN - currentChar) * 2);

	memset(&context.unknown1, 0, sizeof(context.unknown1));
	context.unknown2 = 0xffffffff;

	/* Mind the cast, as in, don't free it after! */
	context.preview = (char *)preview;
	context.preview_len = preview_len;

	u8 = msn_file_context_to_wire(&context);
	ret = purple_base64_encode((const guchar *)u8, MSN_FILE_CONTEXT_SIZE + preview_len);

	g_free(uni);
	g_free(u8);

	return ret;
}

void
msn_request_ft(PurpleXfer *xfer)
{
	MsnSlpCall *slpcall;
	MsnSlpLink *slplink;
	char *context;
	const char *fn;
	const char *fp;

	fn = purple_xfer_get_filename(xfer);
	fp = purple_xfer_get_local_filename(xfer);

	slplink = xfer->data;

	g_return_if_fail(slplink != NULL);
	g_return_if_fail(fp != NULL);

	slpcall = msn_slpcall_new(slplink);
	msn_slpcall_init(slpcall, MSN_SLPCALL_DC);

	slpcall->session_init_cb = send_file_cb;
	slpcall->end_cb = msn_xfer_end_cb;
	slpcall->cb = msn_xfer_completed_cb;
	slpcall->xfer = xfer;
	purple_xfer_ref(slpcall->xfer);

	slpcall->pending = TRUE;

	purple_xfer_set_cancel_send_fnc(xfer, msn_xfer_cancel);
	purple_xfer_set_read_fnc(xfer, msn_xfer_read);
	purple_xfer_set_write_fnc(xfer, msn_xfer_write);

	xfer->data = slpcall;

	context = gen_context(xfer, fn, fp);

	msn_slpcall_invite(slpcall, MSN_FT_GUID, P2P_APPID_FILE, context);
	msn_slplink_unref(slplink);

	g_free(context);
}

