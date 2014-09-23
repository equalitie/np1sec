/*
 * purple
 *
 * Purple is the legal property of its developers, whose names are too numerous
 * to list here.  Please refer to the COPYRIGHT file distributed with this
 * source distribution.
 *
 * Original md5
 * Copyright (C) 2001-2003  Christophe Devine <c.devine@cr0.net>
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
#include <cipher.h>

#if !GLIB_CHECK_VERSION(2,16,0)

#define MD5_HMAC_BLOCK_SIZE 64

struct MD5Context {
	guint32 total[2];
	guint32 state[4];
	guchar buffer[64];
};

#define MD5_GET_GUINT32(n,b,i) {            \
	(n) = ((guint32)(b) [(i)    ]      )    \
	| ((guint32)(b) [(i) + 1] <<  8)    \
	| ((guint32)(b) [(i) + 2] << 16)    \
	| ((guint32)(b) [(i) + 3] << 24);   \
}
#define MD5_PUT_GUINT32(n,b,i) {            \
	(b)[(i)    ] = (guchar)((n)      );     \
	(b)[(i) + 1] = (guchar)((n) >>  8);     \
	(b)[(i) + 2] = (guchar)((n) >> 16);     \
	(b)[(i) + 3] = (guchar)((n) >> 24);     \
}

static size_t
md5_get_block_size(PurpleCipherContext *context)
{
	/* This does not change (in this case) */
	return MD5_HMAC_BLOCK_SIZE;
}

static void
md5_init(PurpleCipherContext *context, gpointer extra) {
	struct MD5Context *md5_context;

	md5_context = g_new0(struct MD5Context, 1);

	purple_cipher_context_set_data(context, md5_context);

	purple_cipher_context_reset(context, extra);
}

static void
md5_reset(PurpleCipherContext *context, gpointer extra) {
	struct MD5Context *md5_context;

	md5_context = purple_cipher_context_get_data(context);

	md5_context->total[0] = 0;
	md5_context->total[1] = 0;

	md5_context->state[0] = 0x67452301;
	md5_context->state[1] = 0xEFCDAB89;
	md5_context->state[2] = 0x98BADCFE;
	md5_context->state[3] = 0x10325476;

	memset(md5_context->buffer, 0, sizeof(md5_context->buffer));
}

static void
md5_uninit(PurpleCipherContext *context) {
	struct MD5Context *md5_context;

	purple_cipher_context_reset(context, NULL);

	md5_context = purple_cipher_context_get_data(context);
	memset(md5_context, 0, sizeof(*md5_context));

	g_free(md5_context);
	md5_context = NULL;
}

static void
md5_process(struct MD5Context *md5_context, const guchar data[64]) {
	guint32 X[16], A, B, C, D;

	A = md5_context->state[0];
	B = md5_context->state[1];
	C = md5_context->state[2];
	D = md5_context->state[3];

	MD5_GET_GUINT32(X[ 0], data,  0);
	MD5_GET_GUINT32(X[ 1], data,  4);
	MD5_GET_GUINT32(X[ 2], data,  8);
	MD5_GET_GUINT32(X[ 3], data, 12);
	MD5_GET_GUINT32(X[ 4], data, 16);
	MD5_GET_GUINT32(X[ 5], data, 20);
	MD5_GET_GUINT32(X[ 6], data, 24);
	MD5_GET_GUINT32(X[ 7], data, 28);
	MD5_GET_GUINT32(X[ 8], data, 32);
	MD5_GET_GUINT32(X[ 9], data, 36);
	MD5_GET_GUINT32(X[10], data, 40);
	MD5_GET_GUINT32(X[11], data, 44);
	MD5_GET_GUINT32(X[12], data, 48);
	MD5_GET_GUINT32(X[13], data, 52);
	MD5_GET_GUINT32(X[14], data, 56);
	MD5_GET_GUINT32(X[15], data, 60);

#define S(x,n) ((x << n) | ((x & 0xFFFFFFFF) >> (32 - n)))
#define P(a,b,c,d,k,s,t) {      \
	a += F(b,c,d) + X[k] + t;   \
	a = S(a,s) + b;             \
}

	/* first pass */
#define F(x,y,z) (z ^ (x & (y ^ z)))
	P(A, B, C, D,  0,  7, 0xD76AA478);
	P(D, A, B, C,  1, 12, 0xE8C7B756);
	P(C, D, A, B,  2, 17, 0x242070DB);
	P(B, C, D, A,  3, 22, 0xC1BDCEEE);
	P(A, B, C, D,  4,  7, 0xF57C0FAF);
	P(D, A, B, C,  5, 12, 0x4787C62A);
	P(C, D, A, B,  6, 17, 0xA8304613);
	P(B, C, D, A,  7, 22, 0xFD469501);
	P(A, B, C, D,  8,  7, 0x698098D8);
	P(D, A, B, C,  9, 12, 0x8B44F7AF);
	P(C, D, A, B, 10, 17, 0xFFFF5BB1);
	P(B, C, D, A, 11, 22, 0x895CD7BE);
	P(A, B, C, D, 12,  7, 0x6B901122);
	P(D, A, B, C, 13, 12, 0xFD987193);
	P(C, D, A, B, 14, 17, 0xA679438E);
	P(B, C, D, A, 15, 22, 0x49B40821);
#undef F

	/* second pass */
#define F(x,y,z) (y ^ (z & (x ^ y)))
	P(A, B, C, D,  1,  5, 0xF61E2562);
	P(D, A, B, C,  6,  9, 0xC040B340);
	P(C, D, A, B, 11, 14, 0x265E5A51);
	P(B, C, D, A,  0, 20, 0xE9B6C7AA);
	P(A, B, C, D,  5,  5, 0xD62F105D);
	P(D, A, B, C, 10,  9, 0x02441453);
	P(C, D, A, B, 15, 14, 0xD8A1E681);
	P(B, C, D, A,  4, 20, 0xE7D3FBC8);
	P(A, B, C, D,  9,  5, 0x21E1CDE6);
	P(D, A, B, C, 14,  9, 0xC33707D6);
	P(C, D, A, B,  3, 14, 0xF4D50D87);
	P(B, C, D, A,  8, 20, 0x455A14ED);
	P(A, B, C, D, 13,  5, 0xA9E3E905);
	P(D, A, B, C,  2,  9, 0xFCEFA3F8);
	P(C, D, A, B,  7, 14, 0x676F02D9);
	P(B, C, D, A, 12, 20, 0x8D2A4C8A);
#undef F

	/* third pass */
#define F(x,y,z) (x ^ y ^ z)
	P(A, B, C, D,  5,  4, 0xFFFA3942);
	P(D, A, B, C,  8, 11, 0x8771F681);
	P(C, D, A, B, 11, 16, 0x6D9D6122);
	P(B, C, D, A, 14, 23, 0xFDE5380C);
	P(A, B, C, D,  1,  4, 0xA4BEEA44);
	P(D, A, B, C,  4, 11, 0x4BDECFA9);
	P(C, D, A, B,  7, 16, 0xF6BB4B60);
	P(B, C, D, A, 10, 23, 0xBEBFBC70);
	P(A, B, C, D, 13,  4, 0x289B7EC6);
	P(D, A, B, C,  0, 11, 0xEAA127FA);
	P(C, D, A, B,  3, 16, 0xD4EF3085);
	P(B, C, D, A,  6, 23, 0x04881D05);
	P(A, B, C, D,  9,  4, 0xD9D4D039);
	P(D, A, B, C, 12, 11, 0xE6DB99E5);
	P(C, D, A, B, 15, 16, 0x1FA27CF8);
	P(B, C, D, A,  2, 23, 0xC4AC5665);
#undef F

	/* forth pass */
#define F(x,y,z) (y ^ (x | ~z))
	P(A, B, C, D,  0,  6, 0xF4292244);
	P(D, A, B, C,  7, 10, 0x432AFF97);
	P(C, D, A, B, 14, 15, 0xAB9423A7);
	P(B, C, D, A,  5, 21, 0xFC93A039);
	P(A, B, C, D, 12,  6, 0x655B59C3);
	P(D, A, B, C,  3, 10, 0x8F0CCC92);
	P(C, D, A, B, 10, 15, 0xFFEFF47D);
	P(B, C, D, A,  1, 21, 0x85845DD1);
	P(A, B, C, D,  8,  6, 0x6FA87E4F);
	P(D, A, B, C, 15, 10, 0xFE2CE6E0);
	P(C, D, A, B,  6, 15, 0xA3014314);
	P(B, C, D, A, 13, 21, 0x4E0811A1);
	P(A, B, C, D,  4,  6, 0xF7537E82);
	P(D, A, B, C, 11, 10, 0xBD3AF235);
	P(C, D, A, B,  2, 15, 0x2AD7D2BB);
	P(B, C, D, A,  9, 21, 0xEB86D391);
#undef F
#undef P
#undef S

	md5_context->state[0] += A;
	md5_context->state[1] += B;
	md5_context->state[2] += C;
	md5_context->state[3] += D;
	}

static void
md5_append(PurpleCipherContext *context, const guchar *data, size_t len) {
	struct MD5Context *md5_context = NULL;
	guint32 left = 0, fill = 0;

	g_return_if_fail(context != NULL);

	md5_context = purple_cipher_context_get_data(context);
	g_return_if_fail(md5_context != NULL);

	left = md5_context->total[0] & 0x3F;
	fill = 64 - left;

	md5_context->total[0] += len;
	md5_context->total[0] &= 0xFFFFFFFF;

	if(md5_context->total[0] < len)
		md5_context->total[1]++;

	if(left && len >= fill) {
		memcpy((md5_context->buffer + left), data, fill);
		md5_process(md5_context, md5_context->buffer);
		len -= fill;
		data += fill;
		left = 0;
	}

	while(len >= 64) {
		md5_process(md5_context, data);
		len -= 64;
		data += 64;
	}

	if(len) {
		memcpy((md5_context->buffer + left), data, len);
	}
}

	static gboolean
md5_digest(PurpleCipherContext *context, size_t in_len, guchar digest[16],
		size_t *out_len)
{
	struct MD5Context *md5_context = NULL;
	guint32 last, pad;
	guint32 high, low;
	guchar message[8];
	guchar padding[64] = {
		0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	};

	g_return_val_if_fail(in_len >= 16, FALSE);

	md5_context = purple_cipher_context_get_data(context);

	high = (md5_context->total[0] >> 29)
		| (md5_context->total[1] << 3);
	low = (md5_context->total[0] << 3);

	MD5_PUT_GUINT32(low, message, 0);
	MD5_PUT_GUINT32(high, message, 4);

	last = md5_context->total[0] & 0x3F;
	pad = (last < 56) ? (56 - last) : (120 - last);

	md5_append(context, padding, pad);
	md5_append(context, message, 8);

	MD5_PUT_GUINT32(md5_context->state[0], digest, 0);
	MD5_PUT_GUINT32(md5_context->state[1], digest, 4);
	MD5_PUT_GUINT32(md5_context->state[2], digest, 8);
	MD5_PUT_GUINT32(md5_context->state[3], digest, 12);

	if(out_len)
		*out_len = 16;

	return TRUE;
}

static PurpleCipherOps MD5Ops = {
	NULL,			/* Set Option		*/
	NULL,			/* Get Option		*/
	md5_init,		/* init				*/
	md5_reset,		/* reset			*/
	md5_uninit,	/* uninit			*/
	NULL,			/* set iv			*/
	md5_append,	/* append			*/
	md5_digest,		/* digest			*/
	NULL,			/* encrypt			*/
	NULL,			/* decrypt			*/
	NULL,			/* set salt			*/
	NULL,			/* get salt size	*/
	NULL,			/* set key			*/
	NULL,			/* get key size		*/
	NULL,			/* set batch mode */
	NULL,			/* get batch mode */
	md5_get_block_size,	/* get block size */
	NULL			/* set key with len */
};

PurpleCipherOps *
purple_md5_cipher_get_ops(void) {
	return &MD5Ops;
}

#endif /* !GLIB_CHECK_VERSION(2,16,0) */

