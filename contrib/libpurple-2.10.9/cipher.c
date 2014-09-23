/*
 * purple
 *
 * Purple is the legal property of its developers, whose names are too numerous
 * to list here.  Please refer to the COPYRIGHT file distributed with this
 * source distribution.
 *
 * Original des taken from gpg
 *
 * des.c - DES and Triple-DES encryption/decryption Algorithm
 *	Copyright (C) 1998 Free Software Foundation, Inc.
 *
 *	Please see below for more legal information!
 *
 *	 According to the definition of DES in FIPS PUB 46-2 from December 1993.
 *	 For a description of triple encryption, see:
 *	   Bruce Schneier: Applied Cryptography. Second Edition.
 *	   John Wiley & Sons, 1996. ISBN 0-471-12845-7. Pages 358 ff.
 *
 *	 This file is part of GnuPG.
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
#include "cipher.h"
#include "dbus-maybe.h"
#include "debug.h"
#include "signals.h"
#include "value.h"

/*******************************************************************************
 * Structs
 ******************************************************************************/
struct _PurpleCipher {
	gchar *name;          /**< Internal name - used for searching */
	PurpleCipherOps *ops; /**< Operations supported by this cipher */
	guint ref;            /**< Reference count */
};

struct _PurpleCipherContext {
	PurpleCipher *cipher; /**< Cipher this context is under */
	gpointer data;        /**< Internal cipher state data */
};

/******************************************************************************
 * Globals
 *****************************************************************************/
static GList *ciphers = NULL;

/******************************************************************************
 * PurpleCipher API
 *****************************************************************************/
const gchar *
purple_cipher_get_name(PurpleCipher *cipher) {
	g_return_val_if_fail(cipher, NULL);

	return cipher->name;
}

guint
purple_cipher_get_capabilities(PurpleCipher *cipher) {
	PurpleCipherOps *ops = NULL;
	guint caps = 0;

	g_return_val_if_fail(cipher, 0);

	ops = cipher->ops;
	g_return_val_if_fail(ops, 0);

	if(ops->set_option)
		caps |= PURPLE_CIPHER_CAPS_SET_OPT;
	if(ops->get_option)
		caps |= PURPLE_CIPHER_CAPS_GET_OPT;
	if(ops->init)
		caps |= PURPLE_CIPHER_CAPS_INIT;
	if(ops->reset)
		caps |= PURPLE_CIPHER_CAPS_RESET;
	if(ops->uninit)
		caps |= PURPLE_CIPHER_CAPS_UNINIT;
	if(ops->set_iv)
		caps |= PURPLE_CIPHER_CAPS_SET_IV;
	if(ops->append)
		caps |= PURPLE_CIPHER_CAPS_APPEND;
	if(ops->digest)
		caps |= PURPLE_CIPHER_CAPS_DIGEST;
	if(ops->encrypt)
		caps |= PURPLE_CIPHER_CAPS_ENCRYPT;
	if(ops->decrypt)
		caps |= PURPLE_CIPHER_CAPS_DECRYPT;
	if(ops->set_salt)
		caps |= PURPLE_CIPHER_CAPS_SET_SALT;
	if(ops->get_salt_size)
		caps |= PURPLE_CIPHER_CAPS_GET_SALT_SIZE;
	if(ops->set_key)
		caps |= PURPLE_CIPHER_CAPS_SET_KEY;
	if(ops->get_key_size)
		caps |= PURPLE_CIPHER_CAPS_GET_KEY_SIZE;
	if(ops->set_batch_mode)
		caps |= PURPLE_CIPHER_CAPS_SET_BATCH_MODE;
	if(ops->get_batch_mode)
		caps |= PURPLE_CIPHER_CAPS_GET_BATCH_MODE;
	if(ops->get_block_size)
		caps |= PURPLE_CIPHER_CAPS_GET_BLOCK_SIZE;
	if(ops->set_key_with_len)
		caps |= PURPLE_CIPHER_CAPS_SET_KEY_WITH_LEN;

	return caps;
}

gboolean
purple_cipher_digest_region(const gchar *name, const guchar *data,
						  size_t data_len, size_t in_len,
						  guchar digest[], size_t *out_len)
{
	PurpleCipher *cipher;
	PurpleCipherContext *context;
	gboolean ret = FALSE;

	g_return_val_if_fail(name, FALSE);
	g_return_val_if_fail(data, FALSE);

	cipher = purple_ciphers_find_cipher(name);

	g_return_val_if_fail(cipher, FALSE);

	if(!cipher->ops->append || !cipher->ops->digest) {
		purple_debug_warning("cipher", "purple_cipher_region failed: "
						"the %s cipher does not support appending and or "
						"digesting.", cipher->name);
		return FALSE;
	}

	context = purple_cipher_context_new(cipher, NULL);
	purple_cipher_context_append(context, data, data_len);
	ret = purple_cipher_context_digest(context, in_len, digest, out_len);
	purple_cipher_context_destroy(context);

	return ret;
}

/******************************************************************************
 * PurpleCiphers API
 *****************************************************************************/
PurpleCipher *
purple_ciphers_find_cipher(const gchar *name) {
	PurpleCipher *cipher;
	GList *l;

	g_return_val_if_fail(name, NULL);

	for(l = ciphers; l; l = l->next) {
		cipher = PURPLE_CIPHER(l->data);

		if(!g_ascii_strcasecmp(cipher->name, name))
			return cipher;
	}

	return NULL;
}

PurpleCipher *
purple_ciphers_register_cipher(const gchar *name, PurpleCipherOps *ops) {
	PurpleCipher *cipher = NULL;

	g_return_val_if_fail(name, NULL);
	g_return_val_if_fail(ops, NULL);
	g_return_val_if_fail(!purple_ciphers_find_cipher(name), NULL);

	cipher = g_new0(PurpleCipher, 1);
	PURPLE_DBUS_REGISTER_POINTER(cipher, PurpleCipher);

	cipher->name = g_strdup(name);
	cipher->ops = ops;

	ciphers = g_list_append(ciphers, cipher);

	purple_signal_emit(purple_ciphers_get_handle(), "cipher-added", cipher);

	return cipher;
}

gboolean
purple_ciphers_unregister_cipher(PurpleCipher *cipher) {
	g_return_val_if_fail(cipher, FALSE);
	g_return_val_if_fail(cipher->ref == 0, FALSE);

	purple_signal_emit(purple_ciphers_get_handle(), "cipher-removed", cipher);

	ciphers = g_list_remove(ciphers, cipher);

	g_free(cipher->name);

	PURPLE_DBUS_UNREGISTER_POINTER(cipher);
	g_free(cipher);

	return TRUE;
}

GList *
purple_ciphers_get_ciphers() {
	return ciphers;
}

/******************************************************************************
 * PurpleCipher Subsystem API
 *****************************************************************************/
gpointer
purple_ciphers_get_handle() {
	static gint handle;

	return &handle;
}

/* These are implemented in the purple-ciphers sublibrary built in the ciphers
 * directory.  We could put a header file in there, but it's less hassle for
 * the developer to just add it here since they have to register it here as
 * well.
 */
PurpleCipherOps *purple_des_cipher_get_ops();
PurpleCipherOps *purple_des3_cipher_get_ops();
PurpleCipherOps *purple_hmac_cipher_get_ops();
PurpleCipherOps *purple_md4_cipher_get_ops();
PurpleCipherOps *purple_md5_cipher_get_ops();
PurpleCipherOps *purple_rc4_cipher_get_ops();
PurpleCipherOps *purple_sha1_cipher_get_ops();
PurpleCipherOps *purple_sha256_cipher_get_ops();

void
purple_ciphers_init() {
	gpointer handle;

	handle = purple_ciphers_get_handle();

	purple_signal_register(handle, "cipher-added",
						 purple_marshal_VOID__POINTER, NULL, 1,
						 purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_CIPHER));
	purple_signal_register(handle, "cipher-removed",
						 purple_marshal_VOID__POINTER, NULL, 1,
						 purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_CIPHER));

	purple_ciphers_register_cipher("md5", purple_md5_cipher_get_ops());
	purple_ciphers_register_cipher("sha1", purple_sha1_cipher_get_ops());
	purple_ciphers_register_cipher("sha256", purple_sha256_cipher_get_ops());
	purple_ciphers_register_cipher("md4", purple_md4_cipher_get_ops());
	purple_ciphers_register_cipher("hmac", purple_hmac_cipher_get_ops());
	purple_ciphers_register_cipher("des", purple_des_cipher_get_ops());
	purple_ciphers_register_cipher("des3", purple_des3_cipher_get_ops());
	purple_ciphers_register_cipher("rc4", purple_rc4_cipher_get_ops());
}

void
purple_ciphers_uninit() {
	PurpleCipher *cipher;
	GList *l, *ll;

	for(l = ciphers; l; l = ll) {
		ll = l->next;

		cipher = PURPLE_CIPHER(l->data);
		purple_ciphers_unregister_cipher(cipher);
	}

	g_list_free(ciphers);

	purple_signals_unregister_by_instance(purple_ciphers_get_handle());
}

/******************************************************************************
 * PurpleCipherContext API
 *****************************************************************************/
void
purple_cipher_context_set_option(PurpleCipherContext *context, const gchar *name,
							   gpointer value)
{
	PurpleCipher *cipher = NULL;

	g_return_if_fail(context);
	g_return_if_fail(name);

	cipher = context->cipher;
	g_return_if_fail(cipher);

	if(cipher->ops && cipher->ops->set_option)
		cipher->ops->set_option(context, name, value);
	else
		purple_debug_warning("cipher", "the %s cipher does not support the "
						"set_option operation\n", cipher->name);
}

gpointer
purple_cipher_context_get_option(PurpleCipherContext *context, const gchar *name) {
	PurpleCipher *cipher = NULL;

	g_return_val_if_fail(context, NULL);
	g_return_val_if_fail(name, NULL);

	cipher = context->cipher;
	g_return_val_if_fail(cipher, NULL);

	if(cipher->ops && cipher->ops->get_option)
		return cipher->ops->get_option(context, name);
	else {
		purple_debug_warning("cipher", "the %s cipher does not support the "
						"get_option operation\n", cipher->name);

		return NULL;
	}
}

PurpleCipherContext *
purple_cipher_context_new(PurpleCipher *cipher, void *extra) {
	PurpleCipherContext *context = NULL;

	g_return_val_if_fail(cipher, NULL);

	cipher->ref++;

	context = g_new0(PurpleCipherContext, 1);
	context->cipher = cipher;

	if(cipher->ops->init)
		cipher->ops->init(context, extra);

	return context;
}

PurpleCipherContext *
purple_cipher_context_new_by_name(const gchar *name, void *extra) {
	PurpleCipher *cipher;

	g_return_val_if_fail(name, NULL);

	cipher = purple_ciphers_find_cipher(name);

	g_return_val_if_fail(cipher, NULL);

	return purple_cipher_context_new(cipher, extra);
}

void
purple_cipher_context_reset(PurpleCipherContext *context, void *extra) {
	PurpleCipher *cipher = NULL;

	g_return_if_fail(context);

	cipher = context->cipher;
	g_return_if_fail(cipher);

	if(cipher->ops && cipher->ops->reset)
		context->cipher->ops->reset(context, extra);
}

void
purple_cipher_context_destroy(PurpleCipherContext *context) {
	PurpleCipher *cipher = NULL;

	g_return_if_fail(context);

	cipher = context->cipher;
	g_return_if_fail(cipher);

	cipher->ref--;

	if(cipher->ops && cipher->ops->uninit)
		cipher->ops->uninit(context);

	memset(context, 0, sizeof(*context));
	g_free(context);
	context = NULL;
}

void
purple_cipher_context_set_iv(PurpleCipherContext *context, guchar *iv, size_t len)
{
	PurpleCipher *cipher = NULL;

	g_return_if_fail(context);
	g_return_if_fail(iv);

	cipher = context->cipher;
	g_return_if_fail(cipher);

	if(cipher->ops && cipher->ops->set_iv)
		cipher->ops->set_iv(context, iv, len);
	else
		purple_debug_warning("cipher", "the %s cipher does not support the set"
						"initialization vector operation\n", cipher->name);
}

void
purple_cipher_context_append(PurpleCipherContext *context, const guchar *data,
								size_t len)
{
	PurpleCipher *cipher = NULL;

	g_return_if_fail(context);

	cipher = context->cipher;
	g_return_if_fail(cipher);

	if(cipher->ops && cipher->ops->append)
		cipher->ops->append(context, data, len);
	else
		purple_debug_warning("cipher", "the %s cipher does not support the append "
						"operation\n", cipher->name);
}

gboolean
purple_cipher_context_digest(PurpleCipherContext *context, size_t in_len,
						   guchar digest[], size_t *out_len)
{
	PurpleCipher *cipher = NULL;

	g_return_val_if_fail(context, FALSE);

	cipher = context->cipher;

	if(cipher->ops && cipher->ops->digest)
		return cipher->ops->digest(context, in_len, digest, out_len);
	else {
		purple_debug_warning("cipher", "the %s cipher does not support the digest "
						"operation\n", cipher->name);
		return FALSE;
	}
}

gboolean
purple_cipher_context_digest_to_str(PurpleCipherContext *context, size_t in_len,
								   gchar digest_s[], size_t *out_len)
{
	/* 8k is a bit excessive, will tweak later. */
	guchar digest[BUF_LEN * 4];
	gint n = 0;
	size_t dlen = 0;

	g_return_val_if_fail(context, FALSE);
	g_return_val_if_fail(digest_s, FALSE);

	if(!purple_cipher_context_digest(context, sizeof(digest), digest, &dlen))
		return FALSE;

	/* in_len must be greater than dlen * 2 so we have room for the NUL. */
	if(in_len <= dlen * 2)
		return FALSE;

	for(n = 0; n < dlen; n++)
		sprintf(digest_s + (n * 2), "%02x", digest[n]);

	digest_s[n * 2] = '\0';

	if(out_len)
		*out_len = dlen * 2;

	return TRUE;
}

gint
purple_cipher_context_encrypt(PurpleCipherContext *context, const guchar data[],
							size_t len, guchar output[], size_t *outlen)
{
	PurpleCipher *cipher = NULL;

	g_return_val_if_fail(context, -1);

	cipher = context->cipher;
	g_return_val_if_fail(cipher, -1);

	if(cipher->ops && cipher->ops->encrypt)
		return cipher->ops->encrypt(context, data, len, output, outlen);
	else {
		purple_debug_warning("cipher", "the %s cipher does not support the encrypt"
						"operation\n", cipher->name);

		if(outlen)
			*outlen = -1;

		return -1;
	}
}

gint
purple_cipher_context_decrypt(PurpleCipherContext *context, const guchar data[],
							size_t len, guchar output[], size_t *outlen)
{
	PurpleCipher *cipher = NULL;

	g_return_val_if_fail(context, -1);

	cipher = context->cipher;
	g_return_val_if_fail(cipher, -1);

	if(cipher->ops && cipher->ops->decrypt)
		return cipher->ops->decrypt(context, data, len, output, outlen);
	else {
		purple_debug_warning("cipher", "the %s cipher does not support the decrypt"
						"operation\n", cipher->name);

		if(outlen)
			*outlen = -1;

		return -1;
	}
}

void
purple_cipher_context_set_salt(PurpleCipherContext *context, guchar *salt) {
	PurpleCipher *cipher = NULL;

	g_return_if_fail(context);

	cipher = context->cipher;
	g_return_if_fail(cipher);

	if(cipher->ops && cipher->ops->set_salt)
		cipher->ops->set_salt(context, salt);
	else
		purple_debug_warning("cipher", "the %s cipher does not support the "
						"set_salt operation\n", cipher->name);
}

size_t
purple_cipher_context_get_salt_size(PurpleCipherContext *context) {
	PurpleCipher *cipher = NULL;

	g_return_val_if_fail(context, -1);

	cipher = context->cipher;
	g_return_val_if_fail(cipher, -1);

	if(cipher->ops && cipher->ops->get_salt_size)
		return cipher->ops->get_salt_size(context);
	else {
		purple_debug_warning("cipher", "the %s cipher does not support the "
						"get_salt_size operation\n", cipher->name);

		return -1;
	}
}

void
purple_cipher_context_set_key(PurpleCipherContext *context, const guchar *key) {
	PurpleCipher *cipher = NULL;

	g_return_if_fail(context);

	cipher = context->cipher;
	g_return_if_fail(cipher);

	if(cipher->ops && cipher->ops->set_key)
		cipher->ops->set_key(context, key);
	else
		purple_debug_warning("cipher", "the %s cipher does not support the "
						"set_key operation\n", cipher->name);
}

size_t
purple_cipher_context_get_key_size(PurpleCipherContext *context) {
	PurpleCipher *cipher = NULL;

	g_return_val_if_fail(context, -1);

	cipher = context->cipher;
	g_return_val_if_fail(cipher, -1);

	if(cipher->ops && cipher->ops->get_key_size)
		return cipher->ops->get_key_size(context);
	else {
		purple_debug_warning("cipher", "the %s cipher does not support the "
						"get_key_size operation\n", cipher->name);

		return -1;
	}
}

void
purple_cipher_context_set_batch_mode(PurpleCipherContext *context,
                                     PurpleCipherBatchMode mode)
{
	PurpleCipher *cipher = NULL;

	g_return_if_fail(context);

	cipher = context->cipher;
	g_return_if_fail(cipher);

	if(cipher->ops && cipher->ops->set_batch_mode)
		cipher->ops->set_batch_mode(context, mode);
	else
		purple_debug_warning("cipher", "The %s cipher does not support the "
		                            "set_batch_mode operation\n", cipher->name);
}

PurpleCipherBatchMode
purple_cipher_context_get_batch_mode(PurpleCipherContext *context)
{
	PurpleCipher *cipher = NULL;

	g_return_val_if_fail(context, -1);

	cipher = context->cipher;
	g_return_val_if_fail(cipher, -1);

	if(cipher->ops && cipher->ops->get_batch_mode)
		return cipher->ops->get_batch_mode(context);
	else {
		purple_debug_warning("cipher", "The %s cipher does not support the "
		                            "get_batch_mode operation\n", cipher->name);
		return -1;
	}
}

size_t
purple_cipher_context_get_block_size(PurpleCipherContext *context)
{
	PurpleCipher *cipher = NULL;

	g_return_val_if_fail(context, -1);

	cipher = context->cipher;
	g_return_val_if_fail(cipher, -1);

	if(cipher->ops && cipher->ops->get_block_size)
		return cipher->ops->get_block_size(context);
	else {
		purple_debug_warning("cipher", "The %s cipher does not support the "
		                            "get_block_size operation\n", cipher->name);
		return -1;
	}
}

void
purple_cipher_context_set_key_with_len(PurpleCipherContext *context,
                                       const guchar *key, size_t len)
{
	PurpleCipher *cipher = NULL;

	g_return_if_fail(context);

	cipher = context->cipher;
	g_return_if_fail(cipher);

	if(cipher->ops && cipher->ops->set_key_with_len)
		cipher->ops->set_key_with_len(context, key, len);
	else
		purple_debug_warning("cipher", "The %s cipher does not support the "
		                            "set_key_with_len operation\n", cipher->name);
}

void
purple_cipher_context_set_data(PurpleCipherContext *context, gpointer data) {
	g_return_if_fail(context);

	context->data = data;
}

gpointer
purple_cipher_context_get_data(PurpleCipherContext *context) {
	g_return_val_if_fail(context, NULL);

	return context->data;
}

gchar *purple_cipher_http_digest_calculate_session_key(
		const gchar *algorithm,
		const gchar *username,
		const gchar *realm,
		const gchar *password,
		const gchar *nonce,
		const gchar *client_nonce)
{
	PurpleCipher *cipher;
	PurpleCipherContext *context;
	gchar hash[33]; /* We only support MD5. */

	g_return_val_if_fail(username != NULL, NULL);
	g_return_val_if_fail(realm    != NULL, NULL);
	g_return_val_if_fail(password != NULL, NULL);
	g_return_val_if_fail(nonce    != NULL, NULL);

	/* Check for a supported algorithm. */
	g_return_val_if_fail(algorithm == NULL ||
						 *algorithm == '\0' ||
						 g_ascii_strcasecmp(algorithm, "MD5") ||
						 g_ascii_strcasecmp(algorithm, "MD5-sess"), NULL);

	cipher = purple_ciphers_find_cipher("md5");
	g_return_val_if_fail(cipher != NULL, NULL);

	context = purple_cipher_context_new(cipher, NULL);

	purple_cipher_context_append(context, (guchar *)username, strlen(username));
	purple_cipher_context_append(context, (guchar *)":", 1);
	purple_cipher_context_append(context, (guchar *)realm, strlen(realm));
	purple_cipher_context_append(context, (guchar *)":", 1);
	purple_cipher_context_append(context, (guchar *)password, strlen(password));

	if (algorithm != NULL && !g_ascii_strcasecmp(algorithm, "MD5-sess"))
	{
		guchar digest[16];

		if (client_nonce == NULL)
		{
			purple_cipher_context_destroy(context);
			purple_debug_error("cipher", "Required client_nonce missing for MD5-sess digest calculation.\n");
			return NULL;
		}

		purple_cipher_context_digest(context, sizeof(digest), digest, NULL);
		purple_cipher_context_destroy(context);

		context = purple_cipher_context_new(cipher, NULL);
		purple_cipher_context_append(context, digest, sizeof(digest));
		purple_cipher_context_append(context, (guchar *)":", 1);
		purple_cipher_context_append(context, (guchar *)nonce, strlen(nonce));
		purple_cipher_context_append(context, (guchar *)":", 1);
		purple_cipher_context_append(context, (guchar *)client_nonce, strlen(client_nonce));
	}

	purple_cipher_context_digest_to_str(context, sizeof(hash), hash, NULL);
	purple_cipher_context_destroy(context);

	return g_strdup(hash);
}

gchar *purple_cipher_http_digest_calculate_response(
		const gchar *algorithm,
		const gchar *method,
		const gchar *digest_uri,
		const gchar *qop,
		const gchar *entity,
		const gchar *nonce,
		const gchar *nonce_count,
		const gchar *client_nonce,
		const gchar *session_key)
{
	PurpleCipher *cipher;
	PurpleCipherContext *context;
	static gchar hash2[33]; /* We only support MD5. */

	g_return_val_if_fail(method      != NULL, NULL);
	g_return_val_if_fail(digest_uri  != NULL, NULL);
	g_return_val_if_fail(nonce       != NULL, NULL);
	g_return_val_if_fail(session_key != NULL, NULL);

	/* Check for a supported algorithm. */
	g_return_val_if_fail(algorithm == NULL ||
						 *algorithm == '\0' ||
						 g_ascii_strcasecmp(algorithm, "MD5") ||
						 g_ascii_strcasecmp(algorithm, "MD5-sess"), NULL);

	/* Check for a supported "quality of protection". */
	g_return_val_if_fail(qop == NULL ||
						 *qop == '\0' ||
						 g_ascii_strcasecmp(qop, "auth") ||
						 g_ascii_strcasecmp(qop, "auth-int"), NULL);

	cipher = purple_ciphers_find_cipher("md5");
	g_return_val_if_fail(cipher != NULL, NULL);

	context = purple_cipher_context_new(cipher, NULL);

	purple_cipher_context_append(context, (guchar *)method, strlen(method));
	purple_cipher_context_append(context, (guchar *)":", 1);
	purple_cipher_context_append(context, (guchar *)digest_uri, strlen(digest_uri));

	if (qop != NULL && !g_ascii_strcasecmp(qop, "auth-int"))
	{
		PurpleCipherContext *context2;
		gchar entity_hash[33];

		if (entity == NULL)
		{
			purple_cipher_context_destroy(context);
			purple_debug_error("cipher", "Required entity missing for auth-int digest calculation.\n");
			return NULL;
		}

		context2 = purple_cipher_context_new(cipher, NULL);
		purple_cipher_context_append(context2, (guchar *)entity, strlen(entity));
		purple_cipher_context_digest_to_str(context2, sizeof(entity_hash), entity_hash, NULL);
		purple_cipher_context_destroy(context2);

		purple_cipher_context_append(context, (guchar *)":", 1);
		purple_cipher_context_append(context, (guchar *)entity_hash, strlen(entity_hash));
	}

	purple_cipher_context_digest_to_str(context, sizeof(hash2), hash2, NULL);
	purple_cipher_context_destroy(context);

	context = purple_cipher_context_new(cipher, NULL);
	purple_cipher_context_append(context, (guchar *)session_key, strlen(session_key));
	purple_cipher_context_append(context, (guchar *)":", 1);
	purple_cipher_context_append(context, (guchar *)nonce, strlen(nonce));
	purple_cipher_context_append(context, (guchar *)":", 1);

	if (qop != NULL && *qop != '\0')
	{
		if (nonce_count == NULL)
		{
			purple_cipher_context_destroy(context);
			purple_debug_error("cipher", "Required nonce_count missing for digest calculation.\n");
			return NULL;
		}

		if (client_nonce == NULL)
		{
			purple_cipher_context_destroy(context);
			purple_debug_error("cipher", "Required client_nonce missing for digest calculation.\n");
			return NULL;
		}

		purple_cipher_context_append(context, (guchar *)nonce_count, strlen(nonce_count));
		purple_cipher_context_append(context, (guchar *)":", 1);
		purple_cipher_context_append(context, (guchar *)client_nonce, strlen(client_nonce));
		purple_cipher_context_append(context, (guchar *)":", 1);

		purple_cipher_context_append(context, (guchar *)qop, strlen(qop));

		purple_cipher_context_append(context, (guchar *)":", 1);
	}

	purple_cipher_context_append(context, (guchar *)hash2, strlen(hash2));
	purple_cipher_context_digest_to_str(context, sizeof(hash2), hash2, NULL);
	purple_cipher_context_destroy(context);

	return g_strdup(hash2);
}
