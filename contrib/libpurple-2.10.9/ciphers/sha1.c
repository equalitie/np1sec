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
 */
#include <cipher.h>
#include <util.h>

#if !GLIB_CHECK_VERSION(2,16,0)

#define SHA1_HMAC_BLOCK_SIZE    64
#define SHA1_ROTL(X,n) ((((X) << (n)) | ((X) >> (32-(n)))) & 0xFFFFFFFF)

struct SHA1Context {
	guint32 H[5];
	guint32 W[80];

	gint lenW;

	guint32 sizeHi;
	guint32 sizeLo;
};

static size_t
sha1_get_block_size(PurpleCipherContext *context)
{
	/* This does not change (in this case) */
	return SHA1_HMAC_BLOCK_SIZE;
}

static void
sha1_hash_block(struct SHA1Context *sha1_ctx) {
	gint i;
	guint32 A, B, C, D, E, T;

	for(i = 16; i < 80; i++) {
		sha1_ctx->W[i] = SHA1_ROTL(sha1_ctx->W[i -  3] ^
				sha1_ctx->W[i -  8] ^
				sha1_ctx->W[i - 14] ^
				sha1_ctx->W[i - 16], 1);
	}

	A = sha1_ctx->H[0];
	B = sha1_ctx->H[1];
	C = sha1_ctx->H[2];
	D = sha1_ctx->H[3];
	E = sha1_ctx->H[4];

	for(i = 0; i < 20; i++) {
		T = (SHA1_ROTL(A, 5) + (((C ^ D) & B) ^ D) + E + sha1_ctx->W[i] + 0x5A827999) & 0xFFFFFFFF;
		E = D;
		D = C;
		C = SHA1_ROTL(B, 30);
		B = A;
		A = T;
	}

	for(i = 20; i < 40; i++) {
		T = (SHA1_ROTL(A, 5) + (B ^ C ^ D) + E + sha1_ctx->W[i] + 0x6ED9EBA1) & 0xFFFFFFFF;
		E = D;
		D = C;
		C = SHA1_ROTL(B, 30);
		B = A;
		A = T;
	}

	for(i = 40; i < 60; i++) {
		T = (SHA1_ROTL(A, 5) + ((B & C) | (D & (B | C))) + E + sha1_ctx->W[i] + 0x8F1BBCDC) & 0xFFFFFFFF;
		E = D;
		D = C;
		C = SHA1_ROTL(B, 30);
		B = A;
		A = T;
	}

	for(i = 60; i < 80; i++) {
		T = (SHA1_ROTL(A, 5) + (B ^ C ^ D) + E + sha1_ctx->W[i] + 0xCA62C1D6) & 0xFFFFFFFF;
		E = D;
		D = C;
		C = SHA1_ROTL(B, 30);
		B = A;
		A = T;
	}

	sha1_ctx->H[0] += A;
	sha1_ctx->H[1] += B;
	sha1_ctx->H[2] += C;
	sha1_ctx->H[3] += D;
	sha1_ctx->H[4] += E;
}

static void
sha1_set_opt(PurpleCipherContext *context, const gchar *name, void *value) {
	struct SHA1Context *ctx;

	ctx = purple_cipher_context_get_data(context);

	if(purple_strequal(name, "sizeHi")) {
		ctx->sizeHi = GPOINTER_TO_INT(value);
	} else if(purple_strequal(name, "sizeLo")) {
		ctx->sizeLo = GPOINTER_TO_INT(value);
	} else if(purple_strequal(name, "lenW")) {
		ctx->lenW = GPOINTER_TO_INT(value);
	}
}

static void *
sha1_get_opt(PurpleCipherContext *context, const gchar *name) {
	struct SHA1Context *ctx;

	ctx = purple_cipher_context_get_data(context);

	if(purple_strequal(name, "sizeHi")) {
		return GINT_TO_POINTER(ctx->sizeHi);
	} else if(purple_strequal(name, "sizeLo")) {
		return GINT_TO_POINTER(ctx->sizeLo);
	} else if(purple_strequal(name, "lenW")) {
		return GINT_TO_POINTER(ctx->lenW);
	}

	return NULL;
}

static void
sha1_init(PurpleCipherContext *context, void *extra) {
	struct SHA1Context *sha1_ctx;

	sha1_ctx = g_new0(struct SHA1Context, 1);

	purple_cipher_context_set_data(context, sha1_ctx);

	purple_cipher_context_reset(context, extra);
}

static void
sha1_reset(PurpleCipherContext *context, void *extra) {
	struct SHA1Context *sha1_ctx;
	gint i;

	sha1_ctx = purple_cipher_context_get_data(context);

	g_return_if_fail(sha1_ctx);

	sha1_ctx->lenW = 0;
	sha1_ctx->sizeHi = 0;
	sha1_ctx->sizeLo = 0;

	sha1_ctx->H[0] = 0x67452301;
	sha1_ctx->H[1] = 0xEFCDAB89;
	sha1_ctx->H[2] = 0x98BADCFE;
	sha1_ctx->H[3] = 0x10325476;
	sha1_ctx->H[4] = 0xC3D2E1F0;

	for(i = 0; i < 80; i++)
		sha1_ctx->W[i] = 0;
}

static void
sha1_uninit(PurpleCipherContext *context) {
	struct SHA1Context *sha1_ctx;

	purple_cipher_context_reset(context, NULL);

	sha1_ctx = purple_cipher_context_get_data(context);

	memset(sha1_ctx, 0, sizeof(struct SHA1Context));

	g_free(sha1_ctx);
	sha1_ctx = NULL;
}

static void
sha1_append(PurpleCipherContext *context, const guchar *data, size_t len) {
	struct SHA1Context *sha1_ctx;
	gint i;

	sha1_ctx = purple_cipher_context_get_data(context);

	g_return_if_fail(sha1_ctx);

	for(i = 0; i < len; i++) {
		sha1_ctx->W[sha1_ctx->lenW / 4] <<= 8;
		sha1_ctx->W[sha1_ctx->lenW / 4] |= data[i];

		if((++sha1_ctx->lenW) % 64 == 0) {
			sha1_hash_block(sha1_ctx);
			sha1_ctx->lenW = 0;
		}

		sha1_ctx->sizeLo += 8;
		sha1_ctx->sizeHi += (sha1_ctx->sizeLo < 8);
	}
}

static gboolean
sha1_digest(PurpleCipherContext *context, size_t in_len, guchar digest[20],
            size_t *out_len)
{
	struct SHA1Context *sha1_ctx;
	guchar pad0x80 = 0x80, pad0x00 = 0x00;
	guchar padlen[8];
	gint i;

	g_return_val_if_fail(in_len >= 20, FALSE);

	sha1_ctx = purple_cipher_context_get_data(context);

	g_return_val_if_fail(sha1_ctx, FALSE);

	padlen[0] = (guchar)((sha1_ctx->sizeHi >> 24) & 255);
	padlen[1] = (guchar)((sha1_ctx->sizeHi >> 16) & 255);
	padlen[2] = (guchar)((sha1_ctx->sizeHi >> 8) & 255);
	padlen[3] = (guchar)((sha1_ctx->sizeHi >> 0) & 255);
	padlen[4] = (guchar)((sha1_ctx->sizeLo >> 24) & 255);
	padlen[5] = (guchar)((sha1_ctx->sizeLo >> 16) & 255);
	padlen[6] = (guchar)((sha1_ctx->sizeLo >> 8) & 255);
	padlen[7] = (guchar)((sha1_ctx->sizeLo >> 0) & 255);

	/* pad with a 1, then zeroes, then length */
	purple_cipher_context_append(context, &pad0x80, 1);
	while(sha1_ctx->lenW != 56)
		purple_cipher_context_append(context, &pad0x00, 1);
	purple_cipher_context_append(context, padlen, 8);

	for(i = 0; i < 20; i++) {
		digest[i] = (guchar)(sha1_ctx->H[i / 4] >> 24);
		sha1_ctx->H[i / 4] <<= 8;
	}

	purple_cipher_context_reset(context, NULL);

	if(out_len)
		*out_len = 20;

	return TRUE;
}

static PurpleCipherOps SHA1Ops = {
	sha1_set_opt,		/* Set Option		*/
	sha1_get_opt,		/* Get Option		*/
	sha1_init,		/* init				*/
	sha1_reset,		/* reset			*/
	sha1_uninit,		/* uninit			*/
	NULL,			/* set iv			*/
	sha1_append,		/* append			*/
	sha1_digest,	/* digest			*/
	NULL,			/* encrypt			*/
	NULL,			/* decrypt			*/
	NULL,			/* set salt			*/
	NULL,			/* get salt size	*/
	NULL,			/* set key			*/
	NULL,			/* get key size		*/
	NULL,			/* set batch mode */
	NULL,			/* get batch mode */
	sha1_get_block_size,	/* get block size */
	NULL			/* set key with len */
};

PurpleCipherOps *
purple_sha1_cipher_get_ops(void) {
	return &SHA1Ops;
}

#endif /* !GLIB_CHECK_VERSION(2,16,0) */

