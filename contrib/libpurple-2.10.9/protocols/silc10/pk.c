/*

  silcpurple_pk.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2004 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#include "silcincludes.h"
#include "silcclient.h"
#include "silcpurple.h"

/************************* Public Key Verification ***************************/

typedef struct {
	SilcClient client;
	SilcClientConnection conn;
	char *filename;
	char *entity;
	char *entity_name;
	char *fingerprint;
	char *babbleprint;
	unsigned char *pk;
	SilcUInt32 pk_len;
	SilcSKEPKType pk_type;
	SilcVerifyPublicKey completion;
	void *context;
	gboolean changed;
} *PublicKeyVerify;

static void silcpurple_verify_ask(const char *entity,
				const char *fingerprint,
				const char *babbleprint,
				PublicKeyVerify verify);

static void silcpurple_verify_cb(PublicKeyVerify verify, gint id)
{
	if (id != 2) {
		if (verify->completion)
			verify->completion(FALSE, verify->context);
	} else {
		if (verify->completion)
			verify->completion(TRUE, verify->context);

		/* Save the key for future checking */
		silc_pkcs_save_public_key_data(verify->filename, verify->pk,
					       verify->pk_len, SILC_PKCS_FILE_PEM);
	}

	silc_free(verify->filename);
	silc_free(verify->entity);
	silc_free(verify->entity_name);
	silc_free(verify->fingerprint);
	silc_free(verify->babbleprint);
	silc_free(verify->pk);
	silc_free(verify);
}

static void silcpurple_verify_details_cb(PublicKeyVerify verify)
{
	/* What a hack.  We have to display the accept dialog _again_
	   because Purple closes the dialog after you press the button.  Purple
	   should have option for the dialogs whether the buttons close them
	   or not. */
	silcpurple_verify_ask(verify->entity, verify->fingerprint,
			    verify->babbleprint, verify);
}

static void silcpurple_verify_details(PublicKeyVerify verify, gint id)
{
	SilcPublicKey public_key;
	PurpleConnection *gc = verify->client->application;
	SilcPurple sg = gc->proto_data;

	silc_pkcs_public_key_decode(verify->pk, verify->pk_len,
				    &public_key);
	silcpurple_show_public_key(sg, verify->entity_name, public_key,
				 G_CALLBACK(silcpurple_verify_details_cb),
				 verify);
	silc_pkcs_public_key_free(public_key);
}

static void silcpurple_verify_ask(const char *entity,
				const char *fingerprint,
				const char *babbleprint,
				PublicKeyVerify verify)
{
	PurpleConnection *gc = verify->client->application;
	char tmp[256], tmp2[256];

	if (verify->changed) {
		g_snprintf(tmp, sizeof(tmp),
			   _("Received %s's public key. Your local copy does not match this "
			     "key. Would you still like to accept this public key?"),
			   entity);
	} else {
		g_snprintf(tmp, sizeof(tmp),
			   _("Received %s's public key. Would you like to accept this "
			     "public key?"), entity);
	}
	g_snprintf(tmp2, sizeof(tmp2),
		   _("Fingerprint and babbleprint for the %s key are:\n\n"
		     "%s\n%s\n"), entity, fingerprint, babbleprint);

	purple_request_action(gc, _("Verify Public Key"), tmp, tmp2,
						PURPLE_DEFAULT_ACTION_NONE,
						purple_connection_get_account(gc), entity, NULL, verify, 3,
			    _("Yes"), G_CALLBACK(silcpurple_verify_cb),
			    _("No"), G_CALLBACK(silcpurple_verify_cb),
			    _("_View..."), G_CALLBACK(silcpurple_verify_details));
}

void silcpurple_verify_public_key(SilcClient client, SilcClientConnection conn,
				const char *name, SilcSocketType conn_type,
				unsigned char *pk, SilcUInt32 pk_len,
				SilcSKEPKType pk_type,
				SilcVerifyPublicKey completion, void *context)
{
	PurpleConnection *gc = client->application;
	int i;
	char file[256], filename[256], filename2[256], *ipf, *hostf = NULL;
	char *fingerprint, *babbleprint;
	struct passwd *pw;
	struct stat st;
	char *entity = ((conn_type == SILC_SOCKET_TYPE_SERVER ||
			 conn_type == SILC_SOCKET_TYPE_ROUTER) ?
			"server" : "client");
	PublicKeyVerify verify;

	if (pk_type != SILC_SKE_PK_TYPE_SILC) {
		purple_notify_error(gc, _("Verify Public Key"),
				  _("Unsupported public key type"), NULL);
		if (completion)
			completion(FALSE, context);
		return;
	}

	pw = getpwuid(getuid());
	if (!pw) {
		if (completion)
			completion(FALSE, context);
		return;
	}

	memset(filename, 0, sizeof(filename));
	memset(filename2, 0, sizeof(filename2));
	memset(file, 0, sizeof(file));

	if (conn_type == SILC_SOCKET_TYPE_SERVER ||
	    conn_type == SILC_SOCKET_TYPE_ROUTER) {
		if (!name) {
			g_snprintf(file, sizeof(file) - 1, "%skey_%s_%d.pub", entity,
				   conn->sock->ip, conn->sock->port);
			g_snprintf(filename, sizeof(filename) - 1,
				   "%s" G_DIR_SEPARATOR_S "%skeys" G_DIR_SEPARATOR_S "%s",
				   silcpurple_silcdir(), entity, file);

			g_snprintf(file, sizeof(file) - 1, "%skey_%s_%d.pub", entity,
				   conn->sock->hostname, conn->sock->port);
			g_snprintf(filename2, sizeof(filename2) - 1,
				   "%s" G_DIR_SEPARATOR_S "%skeys" G_DIR_SEPARATOR_S "%s",
				   silcpurple_silcdir(), entity, file);

			ipf = filename;
			hostf = filename2;
		} else {
			g_snprintf(file, sizeof(file) - 1, "%skey_%s_%d.pub", entity,
				   name, conn->sock->port);
			g_snprintf(filename, sizeof(filename) - 1,
				   "%s" G_DIR_SEPARATOR_S "%skeys" G_DIR_SEPARATOR_S "%s",
				   silcpurple_silcdir(), entity, file);

			ipf = filename;
		}
	} else {
		/* Replace all whitespaces with `_'. */
		fingerprint = silc_hash_fingerprint(NULL, pk, pk_len);
		for (i = 0; i < strlen(fingerprint); i++)
			if (fingerprint[i] == ' ')
				fingerprint[i] = '_';

		g_snprintf(file, sizeof(file) - 1, "%skey_%s.pub", entity, fingerprint);
		g_snprintf(filename, sizeof(filename) - 1,
			   "%s" G_DIR_SEPARATOR_S "%skeys" G_DIR_SEPARATOR_S "%s",
			   silcpurple_silcdir(), entity, file);
		silc_free(fingerprint);

		ipf = filename;
	}

	verify = silc_calloc(1, sizeof(*verify));
	if (!verify)
		return;
	verify->client = client;
	verify->conn = conn;
	verify->filename = strdup(ipf);
	verify->entity = strdup(entity);
	verify->entity_name = (conn_type != SILC_SOCKET_TYPE_CLIENT ?
			       (name ? strdup(name) : strdup(conn->sock->hostname))
			       : NULL);
	verify->pk = silc_memdup(pk, pk_len);
	verify->pk_len = pk_len;
	verify->pk_type = pk_type;
	verify->completion = completion;
	verify->context = context;
	fingerprint = verify->fingerprint = silc_hash_fingerprint(NULL, pk, pk_len);
	babbleprint = verify->babbleprint = silc_hash_babbleprint(NULL, pk, pk_len);

	/* Check whether this key already exists */
	if (g_stat(ipf, &st) < 0 && (!hostf || g_stat(hostf, &st) < 0)) {
		/* Key does not exist, ask user to verify the key and save it */
		silcpurple_verify_ask(name ? name : entity,
				    fingerprint, babbleprint, verify);
		return;
	} else {
		/* The key already exists, verify it. */
		SilcPublicKey public_key;
		unsigned char *encpk;
		SilcUInt32 encpk_len;

		/* Load the key file, try for both IP filename and hostname filename */
		if (!silc_pkcs_load_public_key(ipf, &public_key,
					       SILC_PKCS_FILE_PEM) &&
		    !silc_pkcs_load_public_key(ipf, &public_key,
					       SILC_PKCS_FILE_BIN) &&
		    (!hostf || (!silc_pkcs_load_public_key(hostf, &public_key,
							   SILC_PKCS_FILE_PEM) &&
				!silc_pkcs_load_public_key(hostf, &public_key,
							   SILC_PKCS_FILE_BIN)))) {
			silcpurple_verify_ask(name ? name : entity,
					    fingerprint, babbleprint, verify);
			return;
		}

		/* Encode the key data */
		encpk = silc_pkcs_public_key_encode(public_key, &encpk_len);
		if (!encpk) {
			silcpurple_verify_ask(name ? name : entity,
					    fingerprint, babbleprint, verify);
			return;
		}

		/* Compare the keys */
		if (memcmp(encpk, pk, encpk_len)) {
			/* Ask user to verify the key and save it */
			verify->changed = TRUE;
			silcpurple_verify_ask(name ? name : entity,
					    fingerprint, babbleprint, verify);
			return;
		}

		/* Local copy matched */
		if (completion)
			completion(TRUE, context);
		silc_free(verify->filename);
		silc_free(verify->entity);
		silc_free(verify->entity_name);
		silc_free(verify->pk);
		silc_free(verify->fingerprint);
		silc_free(verify->babbleprint);
		silc_free(verify);
	}
}
