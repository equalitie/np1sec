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

struct RC4Context {
	guchar state[256];
	guchar x;
	guchar y;
	gint key_len;
};

static void
rc4_init(PurpleCipherContext *context, void *extra) {
	struct RC4Context *rc4_ctx;
	rc4_ctx = g_new0(struct RC4Context, 1);
	purple_cipher_context_set_data(context, rc4_ctx);
	purple_cipher_context_reset(context, extra);
}


static void
rc4_reset(PurpleCipherContext *context, void *extra) {
	struct RC4Context *rc4_ctx;
	guint i;

	rc4_ctx = purple_cipher_context_get_data(context);

	g_return_if_fail(rc4_ctx);

	for(i = 0; i < 256; i++)
		rc4_ctx->state[i] = i;
	rc4_ctx->x = 0;
	rc4_ctx->y = 0;

	/* default is 5 bytes (40bit key) */
	rc4_ctx->key_len = 5;

}

static void
rc4_uninit(PurpleCipherContext *context) {
	struct RC4Context *rc4_ctx;

	rc4_ctx = purple_cipher_context_get_data(context);
	memset(rc4_ctx, 0, sizeof(*rc4_ctx));

	g_free(rc4_ctx);
	rc4_ctx = NULL;
}



static void
rc4_set_key (PurpleCipherContext *context, const guchar * key) {
	struct RC4Context *ctx;
	guchar *state;
	guchar temp_swap;
	guchar x, y;
	guint i;

	ctx = purple_cipher_context_get_data(context);

	x = 0;
	y = 0;
	state = &ctx->state[0];
	for(i = 0; i < 256; i++)
	{
		y = (key[x] + state[i] + y) % 256;
		temp_swap = state[i];
		state[i] = state[y];
		state[y] = temp_swap;
		x = (x + 1) % ctx->key_len;
	}
}

static void
rc4_set_opt(PurpleCipherContext *context, const gchar *name, void *value) {
	struct RC4Context *ctx;

	ctx = purple_cipher_context_get_data(context);

	if(purple_strequal(name, "key_len")) {
		ctx->key_len = GPOINTER_TO_INT(value);
	}
}

static size_t
rc4_get_key_size (PurpleCipherContext *context)
{
	struct RC4Context *ctx;

	g_return_val_if_fail(context, -1);

	ctx = purple_cipher_context_get_data(context);

	g_return_val_if_fail(ctx, -1);

	return ctx->key_len;
}

static void *
rc4_get_opt(PurpleCipherContext *context, const gchar *name) {
	struct RC4Context *ctx;

	ctx = purple_cipher_context_get_data(context);

	if(purple_strequal(name, "key_len")) {
		return GINT_TO_POINTER(ctx->key_len);
	}

	return NULL;
}

static gint
rc4_encrypt(PurpleCipherContext *context, const guchar data[],
            size_t len, guchar output[], size_t *outlen) {
	struct RC4Context *ctx;
	guchar temp_swap;
	guchar x, y, z;
	guchar *state;
	guint i;

	ctx = purple_cipher_context_get_data(context);

	x = ctx->x;
	y = ctx->y;
	state = &ctx->state[0];

	for(i = 0; i < len; i++)
	{
		x = (x + 1) % 256;
		y = (state[x] + y) % 256;
		temp_swap = state[x];
		state[x] = state[y];
		state[y] = temp_swap;
		z = state[x] + (state[y]) % 256;
		output[i] = data[i] ^ state[z];
	}
	ctx->x = x;
	ctx->y = y;
	if(outlen)
		*outlen = len;

	return 0;
}

static PurpleCipherOps RC4Ops = {
	rc4_set_opt,   /* Set Option    */
	rc4_get_opt,   /* Get Option    */
	rc4_init,      /* init          */
	rc4_reset,     /* reset         */
	rc4_uninit,    /* uninit        */
	NULL,          /* set iv        */
	NULL,          /* append        */
	NULL,          /* digest        */
	rc4_encrypt,   /* encrypt       */
	NULL,          /* decrypt       */
	NULL,          /* set salt      */
	NULL,          /* get salt size */
	rc4_set_key,   /* set key       */
	rc4_get_key_size, /* get key size  */
	NULL,          /* set batch mode */
	NULL,          /* get batch mode */
	NULL,          /* get block size */
	NULL           /* set key with len */
};

PurpleCipherOps *
purple_rc4_cipher_get_ops(void) {
	return &RC4Ops;
}

