/*
 * Purple's oscar protocol plugin
 * This file is the legal property of its developers.
 * Please see the AUTHORS file distributed alongside this file.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02111-1301  USA
*/

/*
 * This file contains all functions needed to use bstreams.
 */

#include "oscar.h"

int byte_stream_new(ByteStream *bs, size_t len)
{
	if (bs == NULL)
		return -1;

	return byte_stream_init(bs, g_malloc(len), len);
}

int byte_stream_init(ByteStream *bs, guint8 *data, size_t len)
{
	if (bs == NULL)
		return -1;

	bs->data = data;
	bs->len = len;
	bs->offset = 0;

	return 0;
}

void byte_stream_destroy(ByteStream *bs)
{
	g_free(bs->data);
}

int byte_stream_bytes_left(ByteStream *bs)
{
	return bs->len - bs->offset;
}

int byte_stream_curpos(ByteStream *bs)
{
	return bs->offset;
}

int byte_stream_setpos(ByteStream *bs, size_t off)
{
	g_return_val_if_fail(off <= bs->len, -1);

	bs->offset = off;
	return off;
}

void byte_stream_rewind(ByteStream *bs)
{
	byte_stream_setpos(bs, 0);
}

/*
 * N can be negative, which can be used for going backwards
 * in a bstream.
 */
int byte_stream_advance(ByteStream *bs, int n)
{
	g_return_val_if_fail(byte_stream_curpos(bs) + n >= 0, 0);
	g_return_val_if_fail(n <= byte_stream_bytes_left(bs), 0);

	bs->offset += n;
	return n;
}

guint8 byte_stream_get8(ByteStream *bs)
{
	g_return_val_if_fail(byte_stream_bytes_left(bs) >= 1, 0);

	bs->offset++;
	return aimutil_get8(bs->data + bs->offset - 1);
}

guint16 byte_stream_get16(ByteStream *bs)
{
	g_return_val_if_fail(byte_stream_bytes_left(bs) >= 2, 0);

	bs->offset += 2;
	return aimutil_get16(bs->data + bs->offset - 2);
}

guint32 byte_stream_get32(ByteStream *bs)
{
	g_return_val_if_fail(byte_stream_bytes_left(bs) >= 4, 0);

	bs->offset += 4;
	return aimutil_get32(bs->data + bs->offset - 4);
}

guint8 byte_stream_getle8(ByteStream *bs)
{
	g_return_val_if_fail(byte_stream_bytes_left(bs) >= 1, 0);

	bs->offset++;
	return aimutil_getle8(bs->data + bs->offset - 1);
}

guint16 byte_stream_getle16(ByteStream *bs)
{
	g_return_val_if_fail(byte_stream_bytes_left(bs) >= 2, 0);

	bs->offset += 2;
	return aimutil_getle16(bs->data + bs->offset - 2);
}

guint32 byte_stream_getle32(ByteStream *bs)
{
	g_return_val_if_fail(byte_stream_bytes_left(bs) >= 4, 0);

	bs->offset += 4;
	return aimutil_getle32(bs->data + bs->offset - 4);
}

static void byte_stream_getrawbuf_nocheck(ByteStream *bs, guint8 *buf, size_t len)
{
	memcpy(buf, bs->data + bs->offset, len);
	bs->offset += len;
}

int byte_stream_getrawbuf(ByteStream *bs, guint8 *buf, size_t len)
{
	g_return_val_if_fail(byte_stream_bytes_left(bs) >= len, 0);

	byte_stream_getrawbuf_nocheck(bs, buf, len);
	return len;
}

guint8 *byte_stream_getraw(ByteStream *bs, size_t len)
{
	guint8 *ob;

	g_return_val_if_fail(byte_stream_bytes_left(bs) >= len, NULL);

	ob = g_malloc(len);
	byte_stream_getrawbuf_nocheck(bs, ob, len);
	return ob;
}

char *byte_stream_getstr(ByteStream *bs, size_t len)
{
	char *ob;

	g_return_val_if_fail(byte_stream_bytes_left(bs) >= len, NULL);

	ob = g_malloc(len + 1);
	byte_stream_getrawbuf_nocheck(bs, (guint8 *)ob, len);
	ob[len] = '\0';
	return ob;
}

int byte_stream_put8(ByteStream *bs, guint8 v)
{
	g_return_val_if_fail(byte_stream_bytes_left(bs) >= 1, 0);

	bs->offset += aimutil_put8(bs->data + bs->offset, v);
	return 1;
}

int byte_stream_put16(ByteStream *bs, guint16 v)
{
	g_return_val_if_fail(byte_stream_bytes_left(bs) >= 2, 0);

	bs->offset += aimutil_put16(bs->data + bs->offset, v);
	return 2;
}

int byte_stream_put32(ByteStream *bs, guint32 v)
{
	g_return_val_if_fail(byte_stream_bytes_left(bs) >= 4, 0);

	bs->offset += aimutil_put32(bs->data + bs->offset, v);
	return 1;
}

int byte_stream_putle8(ByteStream *bs, guint8 v)
{
	g_return_val_if_fail(byte_stream_bytes_left(bs) >= 1, 0);

	bs->offset += aimutil_putle8(bs->data + bs->offset, v);
	return 1;
}

int byte_stream_putle16(ByteStream *bs, guint16 v)
{
	g_return_val_if_fail(byte_stream_bytes_left(bs) >= 2, 0);

	bs->offset += aimutil_putle16(bs->data + bs->offset, v);
	return 2;
}

int byte_stream_putle32(ByteStream *bs, guint32 v)
{
	g_return_val_if_fail(byte_stream_bytes_left(bs) >= 4, 0);

	bs->offset += aimutil_putle32(bs->data + bs->offset, v);
	return 1;
}


int byte_stream_putraw(ByteStream *bs, const guint8 *v, size_t len)
{
	g_return_val_if_fail(byte_stream_bytes_left(bs) >= len, 0);

	memcpy(bs->data + bs->offset, v, len);
	bs->offset += len;
	return len;
}

int byte_stream_putstr(ByteStream *bs, const char *str)
{
	return byte_stream_putraw(bs, (guint8 *)str, strlen(str));
}

int byte_stream_putbs(ByteStream *bs, ByteStream *srcbs, size_t len)
{
	g_return_val_if_fail(byte_stream_bytes_left(srcbs) >= len, 0);
	g_return_val_if_fail(byte_stream_bytes_left(bs) >= len, 0);

	memcpy(bs->data + bs->offset, srcbs->data + srcbs->offset, len);
	bs->offset += len;
	srcbs->offset += len;
	return len;
}

int byte_stream_putuid(ByteStream *bs, OscarData *od)
{
	PurpleAccount *account;

	account = purple_connection_get_account(od->gc);

	return byte_stream_putle32(bs, atoi(purple_account_get_username(account)));
}

void byte_stream_put_bart_asset(ByteStream *bs, guint16 type, ByteStream *data)
{
	byte_stream_put16(bs, type);

	if (data != NULL && data->len > 0) {
		/* Flags. 0x04 means "this asset has data attached to it" */
		byte_stream_put8(bs, 0x04); /* Flags */
		byte_stream_put8(bs, data->len); /* Length */
		byte_stream_rewind(data);
		byte_stream_putbs(bs, data, data->len); /* Data */
	} else {
		byte_stream_put8(bs, 0x00); /* No flags */
		byte_stream_put8(bs, 0x00); /* Length */
		/* No data */
	}
}

void byte_stream_put_bart_asset_str(ByteStream *bs, guint16 type, const char *datastr)
{
	ByteStream data;
	size_t len = datastr != NULL ? strlen(datastr) : 0;

	if (len > 0) {
		byte_stream_new(&data, 2 + len + 2);
		byte_stream_put16(&data, len); /* Length */
		byte_stream_putstr(&data, datastr); /* String */
		byte_stream_put16(&data, 0x0000); /* Unknown */
		byte_stream_put_bart_asset(bs, type, &data);
		byte_stream_destroy(&data);
	} else {
		byte_stream_put_bart_asset(bs, type, NULL);
	}
}
