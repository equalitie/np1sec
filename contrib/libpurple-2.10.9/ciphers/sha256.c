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

#if !GLIB_CHECK_VERSION(2,16,0)

#define SHA256_HMAC_BLOCK_SIZE  64
#define SHA256_ROTR(X,n) ((((X) >> (n)) | ((X) << (32-(n)))) & 0xFFFFFFFF)

static const guint32 sha256_K[64] =
{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

struct SHA256Context {
	guint32 H[8];
	guint32 W[64];

	gint lenW;

	guint32 sizeHi;
	guint32 sizeLo;
};

static size_t
sha256_get_block_size(PurpleCipherContext *context)
{
	/* This does not change (in this case) */
	return SHA256_HMAC_BLOCK_SIZE;
}

static void
sha256_hash_block(struct SHA256Context *sha256_ctx) {
	gint i;
	guint32 A, B, C, D, E, F, G, H, T1, T2;

	for(i = 16; i < 64; i++) {
		sha256_ctx->W[i] =
			  (SHA256_ROTR(sha256_ctx->W[i-2], 17) ^ SHA256_ROTR(sha256_ctx->W[i-2],  19) ^ (sha256_ctx->W[i-2] >> 10))
			+ sha256_ctx->W[i-7]
			+ (SHA256_ROTR(sha256_ctx->W[i-15], 7) ^ SHA256_ROTR(sha256_ctx->W[i-15], 18) ^ (sha256_ctx->W[i-15] >> 3))
			+ sha256_ctx->W[i-16];
	}

	A = sha256_ctx->H[0];
	B = sha256_ctx->H[1];
	C = sha256_ctx->H[2];
	D = sha256_ctx->H[3];
	E = sha256_ctx->H[4];
	F = sha256_ctx->H[5];
	G = sha256_ctx->H[6];
	H = sha256_ctx->H[7];

	for(i = 0; i < 64; i++) {
		T1 = H
			+ (SHA256_ROTR(E, 6) ^ SHA256_ROTR(E, 11) ^ SHA256_ROTR(E, 25))
			+ ((E & F) ^ ((~E) & G))
			+ sha256_K[i] + sha256_ctx->W[i];
		T2 = (SHA256_ROTR(A, 2) ^ SHA256_ROTR(A, 13) ^ SHA256_ROTR(A, 22))
			+ ((A & B) ^ (A & C) ^ (B & C));
		H = G;
		G = F;
		F = E;
		E = D + T1;
		D = C;
		C = B;
		B = A;
		A = T1 + T2;
	}

	sha256_ctx->H[0] += A;
	sha256_ctx->H[1] += B;
	sha256_ctx->H[2] += C;
	sha256_ctx->H[3] += D;
	sha256_ctx->H[4] += E;
	sha256_ctx->H[5] += F;
	sha256_ctx->H[6] += G;
	sha256_ctx->H[7] += H;
}

static void
sha256_set_opt(PurpleCipherContext *context, const gchar *name, void *value) {
	struct SHA256Context *ctx;

	ctx = purple_cipher_context_get_data(context);

	if(!strcmp(name, "sizeHi")) {
		ctx->sizeHi = GPOINTER_TO_INT(value);
	} else if(!strcmp(name, "sizeLo")) {
		ctx->sizeLo = GPOINTER_TO_INT(value);
	} else if(!strcmp(name, "lenW")) {
		ctx->lenW = GPOINTER_TO_INT(value);
	}
}

static void *
sha256_get_opt(PurpleCipherContext *context, const gchar *name) {
	struct SHA256Context *ctx;

	ctx = purple_cipher_context_get_data(context);

	if(!strcmp(name, "sizeHi")) {
		return GINT_TO_POINTER(ctx->sizeHi);
	} else if(!strcmp(name, "sizeLo")) {
		return GINT_TO_POINTER(ctx->sizeLo);
	} else if(!strcmp(name, "lenW")) {
		return GINT_TO_POINTER(ctx->lenW);
	}

	return NULL;
}

static void
sha256_init(PurpleCipherContext *context, void *extra) {
	struct SHA256Context *sha256_ctx;

	sha256_ctx = g_new0(struct SHA256Context, 1);

	purple_cipher_context_set_data(context, sha256_ctx);

	purple_cipher_context_reset(context, extra);
}

static void
sha256_reset(PurpleCipherContext *context, void *extra) {
	struct SHA256Context *sha256_ctx;
	gint i;

	sha256_ctx = purple_cipher_context_get_data(context);

	g_return_if_fail(sha256_ctx);

	sha256_ctx->lenW = 0;
	sha256_ctx->sizeHi = 0;
	sha256_ctx->sizeLo = 0;

	sha256_ctx->H[0] = 0x6a09e667;
	sha256_ctx->H[1] = 0xbb67ae85;
	sha256_ctx->H[2] = 0x3c6ef372;
	sha256_ctx->H[3] = 0xa54ff53a;
	sha256_ctx->H[4] = 0x510e527f;
	sha256_ctx->H[5] = 0x9b05688c;
	sha256_ctx->H[6] = 0x1f83d9ab;
	sha256_ctx->H[7] = 0x5be0cd19;

	for(i = 0; i < 64; i++)
		sha256_ctx->W[i] = 0;
}

static void
sha256_uninit(PurpleCipherContext *context) {
	struct SHA256Context *sha256_ctx;

	purple_cipher_context_reset(context, NULL);

	sha256_ctx = purple_cipher_context_get_data(context);

	memset(sha256_ctx, 0, sizeof(struct SHA256Context));

	g_free(sha256_ctx);
	sha256_ctx = NULL;
}

static void
sha256_append(PurpleCipherContext *context, const guchar *data, size_t len) {
	struct SHA256Context *sha256_ctx;
	gint i;

	sha256_ctx = purple_cipher_context_get_data(context);

	g_return_if_fail(sha256_ctx);

	for(i = 0; i < len; i++) {
		sha256_ctx->W[sha256_ctx->lenW / 4] <<= 8;
		sha256_ctx->W[sha256_ctx->lenW / 4] |= data[i];

		if((++sha256_ctx->lenW) % 64 == 0) {
			sha256_hash_block(sha256_ctx);
			sha256_ctx->lenW = 0;
		}

		sha256_ctx->sizeLo += 8;
		sha256_ctx->sizeHi += (sha256_ctx->sizeLo < 8);
	}
}

static gboolean
sha256_digest(PurpleCipherContext *context, size_t in_len, guchar digest[32],
              size_t *out_len)
{
	struct SHA256Context *sha256_ctx;
	guchar pad0x80 = 0x80, pad0x00 = 0x00;
	guchar padlen[8];
	gint i;

	g_return_val_if_fail(in_len >= 32, FALSE);

	sha256_ctx = purple_cipher_context_get_data(context);

	g_return_val_if_fail(sha256_ctx, FALSE);

	padlen[0] = (guchar)((sha256_ctx->sizeHi >> 24) & 255);
	padlen[1] = (guchar)((sha256_ctx->sizeHi >> 16) & 255);
	padlen[2] = (guchar)((sha256_ctx->sizeHi >> 8) & 255);
	padlen[3] = (guchar)((sha256_ctx->sizeHi >> 0) & 255);
	padlen[4] = (guchar)((sha256_ctx->sizeLo >> 24) & 255);
	padlen[5] = (guchar)((sha256_ctx->sizeLo >> 16) & 255);
	padlen[6] = (guchar)((sha256_ctx->sizeLo >> 8) & 255);
	padlen[7] = (guchar)((sha256_ctx->sizeLo >> 0) & 255);

	/* pad with a 1, then zeroes, then length */
	purple_cipher_context_append(context, &pad0x80, 1);
	while(sha256_ctx->lenW != 56)
		purple_cipher_context_append(context, &pad0x00, 1);
	purple_cipher_context_append(context, padlen, 8);

	for(i = 0; i < 32; i++) {
		digest[i] = (guchar)(sha256_ctx->H[i / 4] >> 24);
		sha256_ctx->H[i / 4] <<= 8;
	}

	purple_cipher_context_reset(context, NULL);

	if(out_len)
		*out_len = 32;

	return TRUE;
}

static PurpleCipherOps SHA256Ops = {
	sha256_set_opt,			/* Set Option		*/
	sha256_get_opt,			/* Get Option		*/
	sha256_init,	/* init				*/
	sha256_reset,	/* reset			*/
	sha256_uninit,	/* uninit			*/
	NULL,			/* set iv			*/
	sha256_append,	/* append			*/
	sha256_digest,	/* digest			*/
	NULL,			/* encrypt			*/
	NULL,			/* decrypt			*/
	NULL,			/* set salt			*/
	NULL,			/* get salt size	*/
	NULL,			/* set key			*/
	NULL,			/* get key size		*/
	NULL,			/* set batch mode */
	NULL,			/* get batch mode */
	sha256_get_block_size,	/* get block size */
	NULL			/* set key with len */
};

PurpleCipherOps *
purple_sha256_cipher_get_ops(void) {
	return &SHA256Ops;
}

#endif /* !GLIB_CHECK_VERSION(2,16,0) */

