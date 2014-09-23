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
#include "debug.h"

#include "libymsg.h"
#include "yahoo_packet.h"

struct yahoo_packet *yahoo_packet_new(enum yahoo_service service, enum yahoo_status status, int id)
{
	struct yahoo_packet *pkt = g_new0(struct yahoo_packet, 1);

	pkt->service = service;
	pkt->status = status;
	pkt->id = id;

	return pkt;
}

void yahoo_packet_hash_str(struct yahoo_packet *pkt, int key, const char *value)
{
	struct yahoo_pair *pair;

	g_return_if_fail(value != NULL);

	pair = g_new0(struct yahoo_pair, 1);
	pair->key = key;
	pair->value = g_strdup(value);
	pkt->hash = g_slist_prepend(pkt->hash, pair);
}

void yahoo_packet_hash_int(struct yahoo_packet *pkt, int key, int value)
{
	struct yahoo_pair *pair;

	pair = g_new0(struct yahoo_pair, 1);
	pair->key = key;
	pair->value = g_strdup_printf("%d", value);
	pkt->hash = g_slist_prepend(pkt->hash, pair);
}

void yahoo_packet_hash(struct yahoo_packet *pkt, const char *fmt, ...)
{
	char *strval;
	int key, intval;
	const char *cur;
	va_list ap;

	va_start(ap, fmt);
	for (cur = fmt; *cur; cur++) {
		key = va_arg(ap, int);
		switch (*cur) {
		case 'i':
			intval = va_arg(ap, int);
			yahoo_packet_hash_int(pkt, key, intval);
			break;
		case 's':
			strval = va_arg(ap, char *);
			yahoo_packet_hash_str(pkt, key, strval);
			break;
		default:
			purple_debug_error("yahoo", "Invalid format character '%c'\n", *cur);
			break;
		}
	}
	va_end(ap);
}

size_t yahoo_packet_length(struct yahoo_packet *pkt)
{
	GSList *l;

	size_t len = 0;

	l = pkt->hash;
	while (l) {
		struct yahoo_pair *pair = l->data;
		int tmp = pair->key;
		do {
			tmp /= 10;
			len++;
		} while (tmp);
		len += 2;
		len += strlen(pair->value);
		len += 2;
		l = l->next;
	}

	return len;
}

/*
 * 'len' is the value given to us by the server that is supposed to
 * be the length of 'data'.  But apparently there's a time when this
 * length is incorrect.  Christopher Layne thinks it might be a bug
 * in their server code.
 *
 * The following information is from Christopher:
 *
 * It sometimes happens when Yahoo! sends a packet continuation within
 * chat.  Sometimes when joining a large chatroom the initial
 * SERVICE_CHATJOIN packet will be so large that it will need to be
 * split into multiple packets.  That's fine, except that the length
 * of the second packet is wrong.  The packet has the same length as
 * the first packet, and the length given in the header is the same,
 * however the actual data in the packet is shorter than this length.
 * So half of the packet contains good, valid data, and then the rest
 * of the packet is junk.  Luckily there is a null terminator after
 * the valid data and before the invalid data.
 *
 * What does all this mean?  It means that we parse through the data
 * pulling out key/value pairs until we've parsed 'len' bytes, or until
 * we run into a null terminator, whichever comes first.
 */
void yahoo_packet_read(struct yahoo_packet *pkt, const guchar *data, int len)
{
	int pos = 0;
	char key[64];
	const guchar *delimiter;
	gboolean accept;
	int x;
	struct yahoo_pair *pair;

	while (pos + 1 < len)
	{
		if (data[pos] == '\0')
			break;

		pair = g_new0(struct yahoo_pair, 1);

		x = 0;
		while (pos + 1 < len) {
			if (data[pos] == 0xc0 && data[pos + 1] == 0x80)
				break;
			if (x >= sizeof(key)-1) {
				x++;
				pos++;
				continue;
			}
			key[x++] = data[pos++];
		}
		if (x >= sizeof(key)-1) {
			x = 0;
		}
		key[x] = 0;
		pos += 2;
		pair->key = strtol(key, NULL, 10);
		accept = x; /* if x is 0 there was no key, so don't accept it */

		if (pos + 1 > len) {
			/* Malformed packet! (Truncated--garbage or something) */
			accept = FALSE;
		}

		if (accept) {
			delimiter = (const guchar *)g_strstr_len((const char *)&data[pos], len - pos, "\xc0\x80");
			if (delimiter == NULL)
			{
				/* Malformed packet! (It doesn't end in 0xc0 0x80) */
				g_free(pair);
				pos = len;
				continue;
			}
			x = delimiter - data;
			pair->value = g_strndup((const gchar *)&data[pos], x - pos);
			pos = x;
			pkt->hash = g_slist_prepend(pkt->hash, pair);

			if (purple_debug_is_verbose() || g_getenv("PURPLE_YAHOO_DEBUG")) {
				char *esc;
				esc = g_strescape(pair->value, NULL);
				purple_debug_misc("yahoo", "Key: %d  \tValue: %s\n", pair->key, esc);
				g_free(esc);
			}
		} else {
			g_free(pair);
		}
		pos += 2;

		if (pos + 1 > len) break;

		/* Skip over garbage we've noticed in the mail notifications */
		if (data[0] == '9' && data[pos] == 0x01)
			pos++;
	}

	/*
	 * Originally this function used g_slist_append().  I changed
	 * it to use g_slist_prepend() for improved performance.
	 * Ideally the Yahoo! PRPL code would be indifferent to the
	 * order of the key/value pairs, but I don't know if this is
	 * the case for all incoming messages.  To be on the safe side
	 * we reverse the list.
	 */
	pkt->hash = g_slist_reverse(pkt->hash);
}

void yahoo_packet_write(struct yahoo_packet *pkt, guchar *data)
{
	GSList *l;
	int pos = 0;

	/* This is only called from one place, and the list is
	 * always backwards */

	l = pkt->hash = g_slist_reverse(pkt->hash);

	while (l) {
		struct yahoo_pair *pair = l->data;
		gchar buf[100];

		g_snprintf(buf, sizeof(buf), "%d", pair->key);
		strcpy((char *)&data[pos], buf);
		pos += strlen(buf);
		data[pos++] = 0xc0;
		data[pos++] = 0x80;

		strcpy((char *)&data[pos], pair->value);
		pos += strlen(pair->value);
		data[pos++] = 0xc0;
		data[pos++] = 0x80;

		l = l->next;
	}
}

void yahoo_packet_dump(guchar *data, int len)
{
#ifdef YAHOO_DEBUG
	int i;

	purple_debug_misc("yahoo", "");

	for (i = 0; i + 1 < len; i += 2) {
		if ((i % 16 == 0) && i) {
			purple_debug_misc(NULL, "\n");
			purple_debug_misc("yahoo", "");
		}

		purple_debug_misc(NULL, "%02x%02x ", data[i], data[i + 1]);
	}
	if (i < len)
		purple_debug_misc(NULL, "%02x", data[i]);

	purple_debug_misc(NULL, "\n");
	purple_debug_misc("yahoo", "");

	for (i = 0; i < len; i++) {
		if ((i % 16 == 0) && i) {
			purple_debug_misc(NULL, "\n");
			purple_debug_misc("yahoo", "");
		}

		if (g_ascii_isprint(data[i]))
			purple_debug_misc(NULL, "%c ", data[i]);
		else
			purple_debug_misc(NULL, ". ");
	}

	purple_debug_misc(NULL, "\n");
#endif /* YAHOO_DEBUG */
}

static void
yahoo_packet_send_can_write(gpointer data, gint source, PurpleInputCondition cond)
{
	YahooData *yd = data;
	int ret, writelen;

	writelen = purple_circ_buffer_get_max_read(yd->txbuf);

	if (writelen == 0) {
		purple_input_remove(yd->txhandler);
		yd->txhandler = 0;
		return;
	}

	ret = write(yd->fd, yd->txbuf->outptr, writelen);

	if (ret < 0 && errno == EAGAIN)
		return;
	else if (ret < 0) {
		/* TODO: what to do here - do we really have to disconnect? */
		purple_connection_error_reason(yd->gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
		                               _("Write Error"));
		return;
	}

	purple_circ_buffer_mark_read(yd->txbuf, ret);
}


size_t yahoo_packet_build(struct yahoo_packet *pkt, int pad, gboolean wm,
			 gboolean jp, guchar **buf)
{
	size_t pktlen = yahoo_packet_length(pkt);
	size_t len = YAHOO_PACKET_HDRLEN + pktlen;
	guchar *data;
	int pos = 0;

	data = g_malloc0(len + 1);

	memcpy(data + pos, "YMSG", 4); pos += 4;

	if (wm)
		pos += yahoo_put16(data + pos, YAHOO_WEBMESSENGER_PROTO_VER);
	else if (jp)
		pos += yahoo_put16(data + pos, YAHOO_PROTO_VER_JAPAN);
	else
		pos += yahoo_put16(data + pos, YAHOO_PROTO_VER);
	pos += yahoo_put16(data + pos, 0x0000);
	pos += yahoo_put16(data + pos, pktlen + pad);
	pos += yahoo_put16(data + pos, pkt->service);
	pos += yahoo_put32(data + pos, pkt->status);
	pos += yahoo_put32(data + pos, pkt->id);

	yahoo_packet_write(pkt, data + pos);

	*buf = data;

	return len;
}

int yahoo_packet_send(struct yahoo_packet *pkt, YahooData *yd)
{
	size_t len;
	gssize ret;
	guchar *data;

	if (yd->fd < 0)
		return -1;

	len = yahoo_packet_build(pkt, 0, yd->wm, yd->jp, &data);

	yahoo_packet_dump(data, len);
	if (yd->txhandler == 0)
		ret = write(yd->fd, data, len);
	else {
		ret = -1;
		errno = EAGAIN;
	}

	if (ret < 0 && errno == EAGAIN)
		ret = 0;
	else if (ret <= 0) {
		purple_debug_warning("yahoo", "Only wrote %" G_GSSIZE_FORMAT
				" of %" G_GSIZE_FORMAT " bytes!\n", ret, len);
		g_free(data);
		return ret;
	}

	if (ret < len) {
		if (yd->txhandler == 0)
			yd->txhandler = purple_input_add(yd->fd, PURPLE_INPUT_WRITE,
				yahoo_packet_send_can_write, yd);
		purple_circ_buffer_append(yd->txbuf, data + ret, len - ret);
	}

	g_free(data);

	return ret;
}

int yahoo_packet_send_and_free(struct yahoo_packet *pkt, YahooData *yd)
{
	int ret;

	ret = yahoo_packet_send(pkt, yd);
	yahoo_packet_free(pkt);
	return ret;
}

void yahoo_packet_free(struct yahoo_packet *pkt)
{
	while (pkt->hash) {
		struct yahoo_pair *pair = pkt->hash->data;
		g_free(pair->value);
		g_free(pair);
		pkt->hash = g_slist_delete_link(pkt->hash, pkt->hash);
	}
	g_free(pkt);
}
