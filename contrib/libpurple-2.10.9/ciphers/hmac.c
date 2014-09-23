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

struct HMAC_Context {
	PurpleCipherContext *hash;
	char *name;
	int blocksize;
	guchar *opad;
};

	static void
hmac_init(PurpleCipherContext *context, gpointer extra)
{
	struct HMAC_Context *hctx;
	hctx = g_new0(struct HMAC_Context, 1);
	purple_cipher_context_set_data(context, hctx);
	purple_cipher_context_reset(context, extra);
}

	static void
hmac_reset(PurpleCipherContext *context, gpointer extra)
{
	struct HMAC_Context *hctx;

	hctx = purple_cipher_context_get_data(context);

	g_free(hctx->name);
	hctx->name = NULL;
	if (hctx->hash)
		purple_cipher_context_destroy(hctx->hash);
	hctx->hash = NULL;
	hctx->blocksize = 0;
	g_free(hctx->opad);
	hctx->opad = NULL;
}

	static void
hmac_set_opt(PurpleCipherContext *context, const gchar *name, void *value)
{
	struct HMAC_Context *hctx;

	hctx = purple_cipher_context_get_data(context);

	if (purple_strequal(name, "hash")) {
		g_free(hctx->name);
		if (hctx->hash)
			purple_cipher_context_destroy(hctx->hash);
		hctx->name = g_strdup((char*)value);
		hctx->hash = purple_cipher_context_new_by_name((char *)value, NULL);
		hctx->blocksize = purple_cipher_context_get_block_size(hctx->hash);
	}
}

	static void *
hmac_get_opt(PurpleCipherContext *context, const gchar *name)
{
	struct HMAC_Context *hctx;

	hctx = purple_cipher_context_get_data(context);

	if (purple_strequal(name, "hash")) {
		return hctx->name;
	}

	return NULL;
}

	static void
hmac_append(PurpleCipherContext *context, const guchar *data, size_t len)
{
	struct HMAC_Context *hctx = purple_cipher_context_get_data(context);

	g_return_if_fail(hctx->hash != NULL);

	purple_cipher_context_append(hctx->hash, data, len);
}

	static gboolean
hmac_digest(PurpleCipherContext *context, size_t in_len, guchar *out, size_t *out_len)
{
	struct HMAC_Context *hctx = purple_cipher_context_get_data(context);
	PurpleCipherContext *hash = hctx->hash;
	guchar *inner_hash;
	size_t hash_len;
	gboolean result;

	g_return_val_if_fail(hash != NULL, FALSE);

	inner_hash = g_malloc(100); /* TODO: Should be enough for now... */
	result = purple_cipher_context_digest(hash, 100, inner_hash, &hash_len);

	purple_cipher_context_reset(hash, NULL);

	purple_cipher_context_append(hash, hctx->opad, hctx->blocksize);
	purple_cipher_context_append(hash, inner_hash, hash_len);

	g_free(inner_hash);

	result = result && purple_cipher_context_digest(hash, in_len, out, out_len);

	return result;
}

	static void
hmac_uninit(PurpleCipherContext *context)
{
	struct HMAC_Context *hctx;

	purple_cipher_context_reset(context, NULL);

	hctx = purple_cipher_context_get_data(context);

	g_free(hctx);
}

	static void
hmac_set_key_with_len(PurpleCipherContext *context, const guchar * key, size_t key_len)
{
	struct HMAC_Context *hctx = purple_cipher_context_get_data(context);
	int blocksize, i;
	guchar *ipad;
	guchar *full_key;

	g_return_if_fail(hctx->hash != NULL);

	g_free(hctx->opad);

	blocksize = hctx->blocksize;
	ipad = g_malloc(blocksize);
	hctx->opad = g_malloc(blocksize);

	if (key_len > blocksize) {
		purple_cipher_context_reset(hctx->hash, NULL);
		purple_cipher_context_append(hctx->hash, key, key_len);
		full_key = g_malloc(100); /* TODO: Should be enough for now... */
		purple_cipher_context_digest(hctx->hash, 100, full_key, &key_len);
	} else
		full_key = g_memdup(key, key_len);

	if (key_len < blocksize) {
		full_key = g_realloc(full_key, blocksize);
		memset(full_key + key_len, 0, blocksize - key_len);
	}

	for(i = 0; i < blocksize; i++) {
		ipad[i] = 0x36 ^ full_key[i];
		hctx->opad[i] = 0x5c ^ full_key[i];
	}

	g_free(full_key);

	purple_cipher_context_reset(hctx->hash, NULL);
	purple_cipher_context_append(hctx->hash, ipad, blocksize);
	g_free(ipad);
}

	static void
hmac_set_key(PurpleCipherContext *context, const guchar * key)
{
	hmac_set_key_with_len(context, key, strlen((char *)key));
}

	static size_t
hmac_get_block_size(PurpleCipherContext *context)
{
	struct HMAC_Context *hctx = purple_cipher_context_get_data(context);

	return hctx->blocksize;
}

static PurpleCipherOps HMACOps = {
	hmac_set_opt,           /* Set option */
	hmac_get_opt,           /* Get option */
	hmac_init,               /* init */
	hmac_reset,              /* reset */
	hmac_uninit,             /* uninit */
	NULL,                   /* set iv */
	hmac_append,             /* append */
	hmac_digest,             /* digest */
	NULL,                   /* encrypt */
	NULL,                   /* decrypt */
	NULL,                   /* set salt */
	NULL,                   /* get salt size */
	hmac_set_key,           /* set key */
	NULL,                   /* get key size */
	NULL,                   /* set batch mode */
	NULL,                   /* get batch mode */
	hmac_get_block_size,    /* get block size */
	hmac_set_key_with_len   /* set key with len */
};

PurpleCipherOps *
purple_hmac_cipher_get_ops(void) {
	return &HMACOps;
}

