/*
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
 *
 */

#include "internal.h"

#include "account.h"
#include "accountopt.h"
#include "blist.h"
#include "debug.h"
#include "privacy.h"
#include "prpl.h"
#include "proxy.h"
#include "util.h"

#include "libymsg.h"
#include "yahoo_packet.h"
#include "yahoo_friend.h"
#include "yahoo_picture.h"


struct yahoo_fetch_picture_data {
	PurpleConnection *gc;
	char *who;
	int checksum;
};

static void
yahoo_fetch_picture_cb(PurpleUtilFetchUrlData *url_data, gpointer user_data,
		const gchar *pic_data, size_t len, const gchar *error_message)
{
	struct yahoo_fetch_picture_data *d;
	YahooData *yd;

	d = user_data;
	yd = d->gc->proto_data;
	yd->url_datas = g_slist_remove(yd->url_datas, url_data);

	if (error_message != NULL) {
		purple_debug_error("yahoo", "Fetching buddy icon failed: %s\n", error_message);
	} else if (len == 0) {
		purple_debug_error("yahoo", "Fetched an icon with length 0.  Strange.\n");
	} else {
		char *checksum = g_strdup_printf("%i", d->checksum);
		purple_buddy_icons_set_for_user(purple_connection_get_account(d->gc), d->who, g_memdup(pic_data, len), len, checksum);
		g_free(checksum);
	}

	g_free(d->who);
	g_free(d);
}

void yahoo_process_picture(PurpleConnection *gc, struct yahoo_packet *pkt)
{
	YahooData *yd;
	GSList *l = pkt->hash;
	char *who = NULL, *us = NULL;
	gboolean got_icon_info = FALSE, send_icon_info = FALSE;
	char *url = NULL;
	int checksum = 0;

	while (l) {
		struct yahoo_pair *pair = l->data;

		switch (pair->key) {
		case 1:
		case 4:
			if (g_utf8_validate(pair->value, -1, NULL)) {
				who = pair->value;
			} else {
				purple_debug_warning("yahoo", "yahoo_process_picture "
						"got non-UTF-8 string for key %d\n", pair->key);
			}
			break;
		case 5:
			if (g_utf8_validate(pair->value, -1, NULL)) {
				us = pair->value;
			} else {
				purple_debug_warning("yahoo", "yahoo_process_picture "
						"got non-UTF-8 string for key %d\n", pair->key);
			}
			break;
		case 13: {
				int tmp;
				tmp = strtol(pair->value, NULL, 10);
				if (tmp == 1) {
					send_icon_info = TRUE;
				} else if (tmp == 2) {
					got_icon_info = TRUE;
				}
				break;
			}
		case 20:
			if (g_utf8_validate(pair->value, -1, NULL)) {
				url = pair->value;
			} else {
				purple_debug_warning("yahoo", "yahoo_process_picture "
						"got non-UTF-8 string for key %d\n", pair->key);
			}
			break;
		case 192:
			checksum = strtol(pair->value, NULL, 10);
			break;
		}

		l = l->next;
	}

	if (!who)
		return;

	if (!purple_privacy_check(purple_connection_get_account(gc), who)) {
		purple_debug_info("yahoo", "Picture packet from %s dropped.\n", who);
		return;
	}

	/* Yahoo IM 6 spits out 0.png as the URL if the buddy icon is not set */
	if (who && got_icon_info && url && !g_ascii_strncasecmp(url, "http://", 7)) {
		/* TODO: make this work p2p, try p2p before the url */
		PurpleUtilFetchUrlData *url_data;
		struct yahoo_fetch_picture_data *data;
		/* use whole URL if using HTTP Proxy */
		gboolean use_whole_url = yahoo_account_use_http_proxy(gc);

		data = g_new0(struct yahoo_fetch_picture_data, 1);
		data->gc = gc;
		data->who = g_strdup(who);
		data->checksum = checksum;
		/* TODO: Does this need to be MSIE 5.0? */
		url_data = purple_util_fetch_url(url, use_whole_url,
				"Mozilla/4.0 (compatible; MSIE 5.5)", FALSE,
				yahoo_fetch_picture_cb, data);
		if (url_data != NULL) {
			yd = gc->proto_data;
			yd->url_datas = g_slist_prepend(yd->url_datas, url_data);
		}
	} else if (who && send_icon_info) {
		yahoo_send_picture_info(gc, who);
	}
}

void yahoo_process_picture_checksum(PurpleConnection *gc, struct yahoo_packet *pkt)
{
	GSList *l = pkt->hash;
	char *who = NULL;
	int checksum = 0;

	while (l) {
		struct yahoo_pair *pair = l->data;

		switch (pair->key) {
		case 4:
			if (g_utf8_validate(pair->value, -1, NULL)) {
				who = pair->value;
			} else {
				purple_debug_warning("yahoo", "yahoo_process_picture_checksum "
						"got non-UTF-8 string for key %d\n", pair->key);
			}
			break;
		case 5:
			/* us */
			break;
		case 192:
			checksum = strtol(pair->value, NULL, 10);
			break;
		}
		l = l->next;
	}

	if (who) {
		PurpleBuddy *b = purple_find_buddy(gc->account, who);
		const char *locksum = NULL;

		/* FIXME: Cleanup this strtol() stuff if possible. */
		if (b) {
			locksum = purple_buddy_icons_get_checksum_for_user(b);
			if (!locksum || (checksum != strtol(locksum, NULL, 10)))
				yahoo_send_picture_request(gc, who);
		}
	}
}

void yahoo_process_picture_upload(PurpleConnection *gc, struct yahoo_packet *pkt)
{
	PurpleAccount *account = purple_connection_get_account(gc);
	YahooData *yd = gc->proto_data;
	GSList *l = pkt->hash;
	char *url = NULL;

	while (l) {
		struct yahoo_pair *pair = l->data;

		switch (pair->key) {
		case 5:
			/* us */
			break;
		case 27:
			/* filename on our computer. */
			break;
		case 20: /* url at yahoo */
			if (g_utf8_validate(pair->value, -1, NULL)) {
				url = pair->value;
			} else {
				purple_debug_warning("yahoo", "yahoo_process_picture_upload "
						"got non-UTF-8 string for key %d\n", pair->key);
			}
		case 38: /* timestamp */
			break;
		}
		l = l->next;
	}

	if (url) {
		g_free(yd->picture_url);
		yd->picture_url = g_strdup(url);
		purple_account_set_string(account, YAHOO_PICURL_SETTING, url);
		purple_account_set_int(account, YAHOO_PICCKSUM_SETTING, yd->picture_checksum);
		yahoo_send_picture_checksum(gc);
		yahoo_send_picture_update(gc, 2);
	}
}

void yahoo_process_avatar_update(PurpleConnection *gc, struct yahoo_packet *pkt)
{
	GSList *l = pkt->hash;
	char *who = NULL;
	int avatar = 0;

	while (l) {
		struct yahoo_pair *pair = l->data;

		switch (pair->key) {
		case 4:
			if (g_utf8_validate(pair->value, -1, NULL)) {
				who = pair->value;
			} else {
				purple_debug_warning("yahoo", "yahoo_process_avatar_upload "
						"got non-UTF-8 string for key %d\n", pair->key);
			}
			break;
		case 5:
			/* us */
			break;
		case 206:   /* Older versions. Still needed? */
		case 213:   /* Newer versions */
			/*
			 * 0 - No icon or avatar
			 * 1 - Using an avatar
			 * 2 - Using an icon
			 */
			avatar = strtol(pair->value, NULL, 10);
			break;
		}
		l = l->next;
	}

	if (who) {
		if (avatar == 2)
			yahoo_send_picture_request(gc, who);
		else if ((avatar == 0) || (avatar == 1)) {
			YahooFriend *f;
			purple_buddy_icons_set_for_user(gc->account, who, NULL, 0, NULL);
			if ((f = yahoo_friend_find(gc, who)))
				yahoo_friend_set_buddy_icon_need_request(f, TRUE);
			purple_debug_misc("yahoo", "Setting user %s's icon to NULL.\n", who);
		}
	}
}

void yahoo_send_picture_info(PurpleConnection *gc, const char *who)
{
	YahooData *yd = gc->proto_data;
	struct yahoo_packet *pkt;

	if (!yd->picture_url) {
		purple_debug_warning("yahoo", "Attempted to send picture info without a picture\n");
		return;
	}

	pkt = yahoo_packet_new(YAHOO_SERVICE_PICTURE, YAHOO_STATUS_AVAILABLE, yd->session_id);
	yahoo_packet_hash(pkt, "ssssi", 1, purple_connection_get_display_name(gc),
	                  5, who,
	                  13, "2", 20, yd->picture_url, 192, yd->picture_checksum);
	yahoo_packet_send_and_free(pkt, yd);
}

void yahoo_send_picture_request(PurpleConnection *gc, const char *who)
{
	YahooData *yd = gc->proto_data;
	struct yahoo_packet *pkt;

	pkt = yahoo_packet_new(YAHOO_SERVICE_PICTURE, YAHOO_STATUS_AVAILABLE, yd->session_id);
	yahoo_packet_hash_str(pkt, 1, purple_connection_get_display_name(gc)); /* me */
	yahoo_packet_hash_str(pkt, 5, who); /* the other guy */
	yahoo_packet_hash_str(pkt, 13, "1"); /* 1 = request, 2 = reply */
	yahoo_packet_send_and_free(pkt, yd);
}

void yahoo_send_picture_checksum(PurpleConnection *gc)
{
	YahooData *yd = gc->proto_data;
	struct yahoo_packet *pkt;

	pkt = yahoo_packet_new(YAHOO_SERVICE_PICTURE_CHECKSUM, YAHOO_STATUS_AVAILABLE, yd->session_id);
	yahoo_packet_hash(pkt, "ssi", 1, purple_connection_get_display_name(gc),
			  212, "1", 192, yd->picture_checksum);
	yahoo_packet_send_and_free(pkt, yd);
}

void yahoo_send_picture_update_to_user(PurpleConnection *gc, const char *who, int type)
{
	YahooData *yd = gc->proto_data;
	struct yahoo_packet *pkt;

	pkt = yahoo_packet_new(YAHOO_SERVICE_AVATAR_UPDATE, YAHOO_STATUS_AVAILABLE, yd->session_id);
	yahoo_packet_hash(pkt, "si", 3, who, 213, type);
	yahoo_packet_send_and_free(pkt, yd);
}

struct yspufe {
	PurpleConnection *gc;
	int type;
};

static void yahoo_send_picture_update_foreach(gpointer key, gpointer value, gpointer data)
{
	const char *who = key;
	YahooFriend *f = value;
	struct yspufe *d = data;

	if (f->status != YAHOO_STATUS_OFFLINE)
		yahoo_send_picture_update_to_user(d->gc, who, d->type);
}

void yahoo_send_picture_update(PurpleConnection *gc, int type)
{
	YahooData *yd = gc->proto_data;
	struct yspufe data;

	data.gc = gc;
	data.type = type;

	g_hash_table_foreach(yd->friends, yahoo_send_picture_update_foreach, &data);
}

void yahoo_buddy_icon_upload_data_free(struct yahoo_buddy_icon_upload_data *d)
{
	purple_debug_misc("yahoo", "In yahoo_buddy_icon_upload_data_free()\n");

	if (d->str)
		g_string_free(d->str, TRUE);
	g_free(d->filename);
	if (d->watcher)
		purple_input_remove(d->watcher);
	if (d->fd != -1)
		close(d->fd);
	g_free(d);
}

/* we couldn't care less about the server's response, but yahoo gets grumpy if we close before it sends it */
static void yahoo_buddy_icon_upload_reading(gpointer data, gint source, PurpleInputCondition condition)
{
	struct yahoo_buddy_icon_upload_data *d = data;
	PurpleConnection *gc = d->gc;
	char buf[1024];
	int ret;

	if (!PURPLE_CONNECTION_IS_VALID(gc)) {
		yahoo_buddy_icon_upload_data_free(d);
		return;
	}

	ret = read(d->fd, buf, sizeof(buf));

	if (ret < 0 && errno == EAGAIN)
		return;
	else if (ret <= 0) {
		/* There are other problems if d->str->len overflows, so shut up the
		 * warning on 64-bit. */
		purple_debug_info("yahoo", "Buddy icon upload response (%" G_GSIZE_FORMAT ") bytes (> ~400 indicates failure):\n%.*s\n",
			d->str->len, (guint)d->str->len, d->str->str);

		yahoo_buddy_icon_upload_data_free(d);
		return;
	}

	g_string_append_len(d->str, buf, ret);
}

static void yahoo_buddy_icon_upload_pending(gpointer data, gint source, PurpleInputCondition condition)
{
	struct yahoo_buddy_icon_upload_data *d = data;
	PurpleConnection *gc = d->gc;
	gssize wrote;

	if (!PURPLE_CONNECTION_IS_VALID(gc)) {
		yahoo_buddy_icon_upload_data_free(d);
		return;
	}

	wrote = write(d->fd, d->str->str + d->pos, d->str->len - d->pos);
	if (wrote < 0 && errno == EAGAIN)
		return;
	if (wrote <= 0) {
		purple_debug_info("yahoo", "Error uploading buddy icon.\n");
		yahoo_buddy_icon_upload_data_free(d);
		return;
	}
	d->pos += wrote;
	if (d->pos >= d->str->len) {
		purple_debug_misc("yahoo", "Finished uploading buddy icon.\n");
		purple_input_remove(d->watcher);
		/* Clean out the sent buffer and reuse it to read the result */
		g_string_free(d->str, TRUE);
		d->str = g_string_new("");
		d->watcher = purple_input_add(d->fd, PURPLE_INPUT_READ, yahoo_buddy_icon_upload_reading, d);
	}
}

static void yahoo_buddy_icon_upload_connected(gpointer data, gint source, const gchar *error_message)
{
	struct yahoo_buddy_icon_upload_data *d = data;
	struct yahoo_packet *pkt;
	gchar *tmp, *header;
	guchar *pkt_buf;
	const char *host;
	int port;
	gsize pkt_buf_len;
	PurpleConnection *gc = d->gc;
	PurpleAccount *account;
	YahooData *yd;
	/* use whole URL if using HTTP Proxy */
	gboolean use_whole_url = yahoo_account_use_http_proxy(gc);

	account = purple_connection_get_account(gc);
	yd = gc->proto_data;

	/* Buddy icon connect is now complete; clear the PurpleProxyConnectData */
	yd->buddy_icon_connect_data = NULL;

	if (source < 0) {
		purple_debug_error("yahoo", "Buddy icon upload failed: %s\n", error_message);
		yahoo_buddy_icon_upload_data_free(d);
		return;
	}

	pkt = yahoo_packet_new(YAHOO_SERVICE_PICTURE_UPLOAD, YAHOO_STATUS_AVAILABLE, yd->session_id);

	tmp = g_strdup_printf("%" G_GSIZE_FORMAT, d->str->len);
	/* 1 = me, 38 = expire time(?), 0 = me, 28 = size, 27 = filename, 14 = NULL, 29 = data */
	yahoo_packet_hash_str(pkt, 1, purple_connection_get_display_name(gc));
	yahoo_packet_hash_str(pkt, 38, "604800"); /* time til expire */
	purple_account_set_int(account, YAHOO_PICEXPIRE_SETTING, time(NULL) + 604800);
	yahoo_packet_hash_str(pkt, 0, purple_connection_get_display_name(gc));
	yahoo_packet_hash_str(pkt, 28, tmp);
	g_free(tmp);
	yahoo_packet_hash_str(pkt, 27, d->filename);
	yahoo_packet_hash_str(pkt, 14, "");
	/* 4 padding for the 29 key name */
	pkt_buf_len = yahoo_packet_build(pkt, 4, FALSE, yd->jp, &pkt_buf);
	yahoo_packet_free(pkt);

	/* header + packet + "29" + 0xc0 + 0x80) + pictureblob */

	host = purple_account_get_string(account, "xfer_host", yd->jp? YAHOOJP_XFER_HOST : YAHOO_XFER_HOST);
	port = purple_account_get_int(account, "xfer_port", YAHOO_XFER_PORT);
	tmp = g_strdup_printf("%s:%d", host, port);
	header = g_strdup_printf("POST %s%s/notifyft HTTP/1.1\r\n"
		"User-Agent: " YAHOO_CLIENT_USERAGENT "\r\n"
		"Cookie: T=%s; Y=%s\r\n"
		"Host: %s\r\n"
		"Content-Length: %" G_GSIZE_FORMAT "\r\n"
		"Cache-Control: no-cache\r\n\r\n",
		use_whole_url ? "http://" : "", use_whole_url ? tmp : "",
		yd->cookie_t, yd->cookie_y,
		tmp,
		pkt_buf_len + 4 + d->str->len);
	g_free(tmp);

	/* There's no magic here, we just need to prepend in reverse order */
	g_string_prepend(d->str, "29\xc0\x80");

	g_string_prepend_len(d->str, (char *)pkt_buf, pkt_buf_len);
	g_free(pkt_buf);

	g_string_prepend(d->str, header);
	g_free(header);

	/* There are other problems if we're uploading over 4GB of data */
	purple_debug_info("yahoo", "Buddy icon upload data:\n%.*s\n", (guint)d->str->len, d->str->str);

	d->fd = source;
	d->watcher = purple_input_add(d->fd, PURPLE_INPUT_WRITE, yahoo_buddy_icon_upload_pending, d);

	yahoo_buddy_icon_upload_pending(d, d->fd, PURPLE_INPUT_WRITE);
}

void yahoo_buddy_icon_upload(PurpleConnection *gc, struct yahoo_buddy_icon_upload_data *d)
{
	PurpleAccount *account = purple_connection_get_account(gc);
	YahooData *yd = gc->proto_data;

	if (yd->buddy_icon_connect_data != NULL) {
		/* Cancel any in-progress buddy icon upload */
		purple_proxy_connect_cancel(yd->buddy_icon_connect_data);
		yd->buddy_icon_connect_data = NULL;
	}

	yd->buddy_icon_connect_data = purple_proxy_connect(NULL, account,
			purple_account_get_string(account, "xfer_host",
				yd->jp? YAHOOJP_XFER_HOST : YAHOO_XFER_HOST),
			purple_account_get_int(account, "xfer_port", YAHOO_XFER_PORT),
			yahoo_buddy_icon_upload_connected, d);

	if (yd->buddy_icon_connect_data == NULL)
	{
		purple_debug_error("yahoo", "Uploading our buddy icon failed to connect.\n");
		yahoo_buddy_icon_upload_data_free(d);
	}
}

static int yahoo_buddy_icon_calculate_checksum(const guchar *data, gsize len)
{
	/* This code is borrowed from Kopete, which seems to be managing to calculate
	   checksums in such a manner that Yahoo!'s servers are happy */

	const guchar *p = data;
	int checksum = 0, g, i = len;

	while(i--) {
		checksum = (checksum << 4) + *p++;

		if((g = (checksum & 0xf0000000)) != 0)
			checksum ^= g >> 23;

		checksum &= ~g;
	}

	purple_debug_misc("yahoo", "Calculated buddy icon checksum: %d\n", checksum);

	return checksum;
}

void yahoo_set_buddy_icon(PurpleConnection *gc, PurpleStoredImage *img)
{
	YahooData *yd = gc->proto_data;
	PurpleAccount *account = gc->account;

	if (img == NULL) {
		g_free(yd->picture_url);
		yd->picture_url = NULL;

		/* TODO: don't we have to clear it on the server too?! */

		purple_account_set_string(account, YAHOO_PICURL_SETTING, NULL);
		purple_account_set_int(account, YAHOO_PICCKSUM_SETTING, 0);
		purple_account_set_int(account, YAHOO_PICEXPIRE_SETTING, 0);
		if (yd->logged_in)
			/* Tell everyone we ain't got one no more */
			yahoo_send_picture_update(gc, 0);

	} else {
		gconstpointer data = purple_imgstore_get_data(img);
		size_t len = purple_imgstore_get_size(img);
		GString *s = g_string_new_len(data, len);
		struct yahoo_buddy_icon_upload_data *d;
		int oldcksum = purple_account_get_int(account, YAHOO_PICCKSUM_SETTING, 0);
		int expire = purple_account_get_int(account, YAHOO_PICEXPIRE_SETTING, 0);
		const char *oldurl = purple_account_get_string(account, YAHOO_PICURL_SETTING, NULL);

		yd->picture_checksum = yahoo_buddy_icon_calculate_checksum(data, len);

		if ((yd->picture_checksum == oldcksum) &&
			(expire > (time(NULL) + 60*60*24)) && oldurl)
		{
			purple_debug_misc("yahoo", "buddy icon is up to date. Not reuploading.\n");
			g_string_free(s, TRUE);
			g_free(yd->picture_url);
			yd->picture_url = g_strdup(oldurl);
			return;
		}

		/* We use this solely for sending a filename to the server */
		d = g_new0(struct yahoo_buddy_icon_upload_data, 1);
		d->gc = gc;
		d->str = s;
		d->fd = -1;
		d->filename = g_strdup(purple_imgstore_get_filename(img));

		if (!yd->logged_in) {
			yd->picture_upload_todo = d;
			return;
		}

		yahoo_buddy_icon_upload(gc, d);

	}
}
