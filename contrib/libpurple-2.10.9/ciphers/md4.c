/*
 * purple
 *
 * Purple is the legal property of its developers, whose names are too numerous
 * to list here.  Please refer to the COPYRIGHT file distributed with this
 * source distribution.
 *
 * Original md4 taken from linux kernel
 * MD4 Message Digest Algorithm (RFC1320).
 *
 * Implementation derived from Andrew Tridgell and Steve French's
 * CIFS MD4 implementation, and the cryptoapi implementation
 * originally based on the public domain implementation written
 * by Colin Plumb in 1993.
 *
 * Copyright (c) Andrew Tridgell 1997-1998.
 * Modified by Steve French (sfrench@us.ibm.com) 2002
 * Copyright (c) Cryptoapi developers.
 * Copyright (c) 2002 David S. Miller (davem@redhat.com)
 * Copyright (c) 2002 James Morris <jmorris@intercode.com.au>
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

#define MD4_DIGEST_SIZE     16
#define MD4_HMAC_BLOCK_SIZE 64
#define MD4_BLOCK_WORDS     16
#define MD4_HASH_WORDS      4

struct MD4_Context {
	guint32 hash[MD4_HASH_WORDS];
	guint32 block[MD4_BLOCK_WORDS];
	guint64 byte_count;
};

static inline guint32 lshift(guint32 x, unsigned int s)
{
	x &= 0xFFFFFFFF;
	return ((x << s) & 0xFFFFFFFF) | (x >> (32 - s));
}

static inline guint32 F(guint32 x, guint32 y, guint32 z)
{
	return (x & y) | ((~x) & z);
}

static inline guint32 G(guint32 x, guint32 y, guint32 z)
{
	return (x & y) | (x & z) | (y & z);
}

static inline guint32 H(guint32 x, guint32 y, guint32 z)
{
	return x ^ y ^ z;
}

#define ROUND1(a,b,c,d,k,s) (a = lshift(a + F(b,c,d) + k, s))
#define ROUND2(a,b,c,d,k,s) (a = lshift(a + G(b,c,d) + k + (guint32)0x5A827999,s))
#define ROUND3(a,b,c,d,k,s) (a = lshift(a + H(b,c,d) + k + (guint32)0x6ED9EBA1,s))

static inline void le32_to_cpu_array(guint32 *buf, unsigned int words)
{
	while (words--) {
		*buf=GUINT_FROM_LE(*buf);
		buf++;
	}
}

static inline void cpu_to_le32_array(guint32 *buf, unsigned int words)
{
	while (words--) {
		*buf=GUINT_TO_LE(*buf);
		buf++;
	}
}

static void md4_transform(guint32 *hash, guint32 const *in)
{
	guint32 a, b, c, d;

	a = hash[0];
	b = hash[1];
	c = hash[2];
	d = hash[3];

	ROUND1(a, b, c, d, in[0], 3);
	ROUND1(d, a, b, c, in[1], 7);
	ROUND1(c, d, a, b, in[2], 11);
	ROUND1(b, c, d, a, in[3], 19);
	ROUND1(a, b, c, d, in[4], 3);
	ROUND1(d, a, b, c, in[5], 7);
	ROUND1(c, d, a, b, in[6], 11);
	ROUND1(b, c, d, a, in[7], 19);
	ROUND1(a, b, c, d, in[8], 3);
	ROUND1(d, a, b, c, in[9], 7);
	ROUND1(c, d, a, b, in[10], 11);
	ROUND1(b, c, d, a, in[11], 19);
	ROUND1(a, b, c, d, in[12], 3);
	ROUND1(d, a, b, c, in[13], 7);
	ROUND1(c, d, a, b, in[14], 11);
	ROUND1(b, c, d, a, in[15], 19);

	ROUND2(a, b, c, d,in[ 0], 3);
	ROUND2(d, a, b, c, in[4], 5);
	ROUND2(c, d, a, b, in[8], 9);
	ROUND2(b, c, d, a, in[12], 13);
	ROUND2(a, b, c, d, in[1], 3);
	ROUND2(d, a, b, c, in[5], 5);
	ROUND2(c, d, a, b, in[9], 9);
	ROUND2(b, c, d, a, in[13], 13);
	ROUND2(a, b, c, d, in[2], 3);
	ROUND2(d, a, b, c, in[6], 5);
	ROUND2(c, d, a, b, in[10], 9);
	ROUND2(b, c, d, a, in[14], 13);
	ROUND2(a, b, c, d, in[3], 3);
	ROUND2(d, a, b, c, in[7], 5);
	ROUND2(c, d, a, b, in[11], 9);
	ROUND2(b, c, d, a, in[15], 13);

	ROUND3(a, b, c, d,in[ 0], 3);
	ROUND3(d, a, b, c, in[8], 9);
	ROUND3(c, d, a, b, in[4], 11);
	ROUND3(b, c, d, a, in[12], 15);
	ROUND3(a, b, c, d, in[2], 3);
	ROUND3(d, a, b, c, in[10], 9);
	ROUND3(c, d, a, b, in[6], 11);
	ROUND3(b, c, d, a, in[14], 15);
	ROUND3(a, b, c, d, in[1], 3);
	ROUND3(d, a, b, c, in[9], 9);
	ROUND3(c, d, a, b, in[5], 11);
	ROUND3(b, c, d, a, in[13], 15);
	ROUND3(a, b, c, d, in[3], 3);
	ROUND3(d, a, b, c, in[11], 9);
	ROUND3(c, d, a, b, in[7], 11);
	ROUND3(b, c, d, a, in[15], 15);

	hash[0] += a;
	hash[1] += b;
	hash[2] += c;
	hash[3] += d;
}

static inline void md4_transform_helper(struct MD4_Context *ctx)
{
	le32_to_cpu_array(ctx->block, sizeof(ctx->block) / sizeof(guint32));
	md4_transform(ctx->hash, ctx->block);
}

static void
md4_init(PurpleCipherContext *context, gpointer extra) {
	struct MD4_Context *mctx;
	mctx = g_new0(struct MD4_Context, 1);
	purple_cipher_context_set_data(context, mctx);
	purple_cipher_context_reset(context, extra);

	mctx->hash[0] = 0x67452301;
	mctx->hash[1] = 0xefcdab89;
	mctx->hash[2] = 0x98badcfe;
	mctx->hash[3] = 0x10325476;
	mctx->byte_count = 0;
}

static void
md4_reset(PurpleCipherContext *context, gpointer extra) {
	struct MD4_Context *mctx;

	mctx = purple_cipher_context_get_data(context);

	mctx->hash[0] = 0x67452301;
	mctx->hash[1] = 0xefcdab89;
	mctx->hash[2] = 0x98badcfe;
	mctx->hash[3] = 0x10325476;
	mctx->byte_count = 0;
}

	static void
md4_append(PurpleCipherContext *context, const guchar *data, size_t len)
{
	struct MD4_Context *mctx = purple_cipher_context_get_data(context);
	const guint32 avail = sizeof(mctx->block) - (mctx->byte_count & 0x3f);

	mctx->byte_count += len;

	if (avail > len) {
		memcpy((char *)mctx->block + (sizeof(mctx->block) - avail),
				data, len);
		return;
	}

	memcpy((char *)mctx->block + (sizeof(mctx->block) - avail),
			data, avail);

	md4_transform_helper(mctx);
	data += avail;
	len -= avail;

	while (len >= sizeof(mctx->block)) {
		memcpy(mctx->block, data, sizeof(mctx->block));
		md4_transform_helper(mctx);
		data += sizeof(mctx->block);
		len -= sizeof(mctx->block);
	}

	memcpy(mctx->block, data, len);
}

	static gboolean
md4_digest(PurpleCipherContext *context, size_t in_len, guchar *out,
		size_t *out_len)
{
	struct MD4_Context *mctx = purple_cipher_context_get_data(context);
	const unsigned int offset = mctx->byte_count & 0x3f;
	char *p = (char *)mctx->block + offset;
	int padding = 56 - (offset + 1);


	if(in_len<16) return FALSE;
	if(out_len) *out_len = 16;
	*p++ = 0x80;
	if (padding < 0) {
		memset(p, 0x00, padding + sizeof (guint64));
		md4_transform_helper(mctx);
		p = (char *)mctx->block;
		padding = 56;
	}

	memset(p, 0, padding);
	mctx->block[14] = mctx->byte_count << 3;
	mctx->block[15] = mctx->byte_count >> 29;
	le32_to_cpu_array(mctx->block, (sizeof(mctx->block) -
				sizeof(guint64)) / sizeof(guint32));
	md4_transform(mctx->hash, mctx->block);
	cpu_to_le32_array(mctx->hash, sizeof(mctx->hash) / sizeof(guint32));
	memcpy(out, mctx->hash, sizeof(mctx->hash));
	memset(mctx, 0, sizeof(*mctx));
	return TRUE;
}

static void
md4_uninit(PurpleCipherContext *context) {
	struct MD4_Context *md4_context;

	purple_cipher_context_reset(context, NULL);

	md4_context = purple_cipher_context_get_data(context);
	memset(md4_context, 0, sizeof(*md4_context));

	g_free(md4_context);
	md4_context = NULL;
}

	static size_t
md4_get_block_size(PurpleCipherContext *context)
{
	/* This does not change (in this case) */
	return MD4_HMAC_BLOCK_SIZE;
}

static PurpleCipherOps MD4Ops = {
	NULL,                   /* Set option */
	NULL,                   /* Get option */
	md4_init,               /* init */
	md4_reset,              /* reset */
	md4_uninit,             /* uninit */
	NULL,                   /* set iv */
	md4_append,             /* append */
	md4_digest,             /* digest */
	NULL,                   /* encrypt */
	NULL,                   /* decrypt */
	NULL,                   /* set salt */
	NULL,                   /* get salt size */
	NULL,                   /* set key */
	NULL,                   /* get key size */
	NULL,                   /* set batch mode */
	NULL,                   /* get batch mode */
	md4_get_block_size,     /* get block size */
	NULL                    /* set key with len */
};

PurpleCipherOps *
purple_md4_cipher_get_ops(void) {
	return &MD4Ops;
}

