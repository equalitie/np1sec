/**
 * @file nexus.c MSN Nexus functions
 *
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

#include "internal.h"
#include "cipher.h"
#include "debug.h"

#include "msnutils.h"
#include "soap.h"
#include "nexus.h"
#include "notification.h"

/**************************************************************************
 * Valid Ticket Tokens
 **************************************************************************/

#define SSO_VALID_TICKET_DOMAIN 0
#define SSO_VALID_TICKET_POLICY 1
static char *ticket_domains[][2] = {
	/* http://msnpiki.msnfanatic.com/index.php/MSNP15:SSO */
	/* {"Domain", "Policy Ref URI"}, Purpose */
	{"messengerclear.live.com", NULL},       /* Authentication for messenger. */
	{"messenger.msn.com", "?id=507"},        /* Authentication for receiving OIMs. */
	{"contacts.msn.com", "MBI"},             /* Authentication for the Contact server. */
	{"messengersecure.live.com", "MBI_SSL"}, /* Authentication for sending OIMs. */
	{"storage.live.com", "MBI"},             /* Storage REST API */
	{"sup.live.com", "MBI"},                 /* What's New service */
};

/**************************************************************************
 * Main
 **************************************************************************/

MsnNexus *
msn_nexus_new(MsnSession *session)
{
	MsnNexus *nexus;
	int i;

	nexus = g_new0(MsnNexus, 1);
	nexus->session = session;

	nexus->token_len = sizeof(ticket_domains) / sizeof(char *[2]);
	nexus->tokens = g_new0(MsnTicketToken, nexus->token_len);

	for (i = 0; i < nexus->token_len; i++)
		nexus->tokens[i].token = g_hash_table_new_full(g_str_hash, g_str_equal,
		                                               g_free, g_free);

	return nexus;
}

void
msn_nexus_destroy(MsnNexus *nexus)
{
	int i;
	for (i = 0; i < nexus->token_len; i++) {
		g_hash_table_destroy(nexus->tokens[i].token);
		g_free(nexus->tokens[i].secret);
		g_slist_free(nexus->tokens[i].updates);
	}

	g_free(nexus->tokens);
	g_free(nexus->policy);
	g_free(nexus->nonce);
	g_free(nexus->cipher);
	g_free(nexus->secret);
	g_free(nexus);
}

/**************************************************************************
 * RPS/SSO Authentication
 **************************************************************************/

static char *
rps_create_key(const char *key, int key_len, const char *data, size_t data_len)
{
	const guchar magic[] = "WS-SecureConversation";
	const int magic_len = sizeof(magic) - 1;

	PurpleCipherContext *hmac;
	guchar hash1[20], hash2[20], hash3[20], hash4[20];
	char *result;

	hmac = purple_cipher_context_new_by_name("hmac", NULL);

	purple_cipher_context_set_option(hmac, "hash", "sha1");
	purple_cipher_context_set_key_with_len(hmac, (guchar *)key, key_len);
	purple_cipher_context_append(hmac, magic, magic_len);
	purple_cipher_context_append(hmac, (guchar *)data, data_len);
	purple_cipher_context_digest(hmac, sizeof(hash1), hash1, NULL);

	purple_cipher_context_reset(hmac, NULL);
	purple_cipher_context_set_option(hmac, "hash", "sha1");
	purple_cipher_context_set_key_with_len(hmac, (guchar *)key, key_len);
	purple_cipher_context_append(hmac, hash1, 20);
	purple_cipher_context_append(hmac, magic, magic_len);
	purple_cipher_context_append(hmac, (guchar *)data, data_len);
	purple_cipher_context_digest(hmac, sizeof(hash2), hash2, NULL);

	purple_cipher_context_reset(hmac, NULL);
	purple_cipher_context_set_option(hmac, "hash", "sha1");
	purple_cipher_context_set_key_with_len(hmac, (guchar *)key, key_len);
	purple_cipher_context_append(hmac, hash1, 20);
	purple_cipher_context_digest(hmac, sizeof(hash3), hash3, NULL);

	purple_cipher_context_reset(hmac, NULL);
	purple_cipher_context_set_option(hmac, "hash", "sha1");
	purple_cipher_context_set_key_with_len(hmac, (guchar *)key, key_len);
	purple_cipher_context_append(hmac, hash3, sizeof(hash3));
	purple_cipher_context_append(hmac, magic, magic_len);
	purple_cipher_context_append(hmac, (guchar *)data, data_len);
	purple_cipher_context_digest(hmac, sizeof(hash4), hash4, NULL);

	purple_cipher_context_destroy(hmac);

	result = g_malloc(24);
	memcpy(result, hash2, sizeof(hash2));
	memcpy(result + sizeof(hash2), hash4, 4);

	return result;
}

static char *
des3_cbc(const char *key, const char *iv, const char *data, int len, gboolean decrypt)
{
	PurpleCipherContext *des3;
	char *out;
	size_t outlen;

	des3 = purple_cipher_context_new_by_name("des3", NULL);
	purple_cipher_context_set_key(des3, (guchar *)key);
	purple_cipher_context_set_batch_mode(des3, PURPLE_CIPHER_BATCH_MODE_CBC);
	purple_cipher_context_set_iv(des3, (guchar *)iv, 8);

	out = g_malloc(len);
	if (decrypt)
		purple_cipher_context_decrypt(des3, (guchar *)data, len, (guchar *)out, &outlen);
	else
		purple_cipher_context_encrypt(des3, (guchar *)data, len, (guchar *)out, &outlen);

	purple_cipher_context_destroy(des3);

	return out;
}

#define MSN_USER_KEY_SIZE (7*4 + 8 + 20 + 72)
#define CRYPT_MODE_CBC 1
#define CIPHER_TRIPLE_DES 0x6603
#define HASH_SHA1 0x8004
static char *
msn_rps_encrypt(MsnNexus *nexus)
{
	char usr_key_base[MSN_USER_KEY_SIZE], *usr_key;
	const char magic1[] = "SESSION KEY HASH";
	const char magic2[] = "SESSION KEY ENCRYPTION";
	PurpleCipherContext *hmac;
	size_t len;
	guchar *hash;
	char *key1, *key2, *key3;
	gsize key1_len;
	const char *iv;
	char *nonce_fixed;
	char *cipher;
	char *response;

	usr_key = &usr_key_base[0];
	/* Header */
	msn_push32le(usr_key, 28);                  /* Header size */
	msn_push32le(usr_key, CRYPT_MODE_CBC);      /* Crypt mode */
	msn_push32le(usr_key, CIPHER_TRIPLE_DES);   /* Cipher type */
	msn_push32le(usr_key, HASH_SHA1);           /* Hash type */
	msn_push32le(usr_key, 8);                   /* IV size */
	msn_push32le(usr_key, 20);                  /* Hash size */
	msn_push32le(usr_key, 72);                  /* Cipher size */
	/* Data */
	iv = usr_key;
	msn_push32le(usr_key, rand());
	msn_push32le(usr_key, rand());
	hash = (guchar *)usr_key;
	usr_key += 20;  /* Remaining is cipher data */

	key1 = (char *)purple_base64_decode((const char *)nexus->tokens[MSN_AUTH_MESSENGER].secret, &key1_len);
	key2 = rps_create_key(key1, key1_len, magic1, sizeof(magic1) - 1);
	key3 = rps_create_key(key1, key1_len, magic2, sizeof(magic2) - 1);

	len = strlen(nexus->nonce);
	hmac = purple_cipher_context_new_by_name("hmac", NULL);
	purple_cipher_context_set_option(hmac, "hash", "sha1");
	purple_cipher_context_set_key_with_len(hmac, (guchar *)key2, 24);
	purple_cipher_context_append(hmac, (guchar *)nexus->nonce, len);
	purple_cipher_context_digest(hmac, 20, hash, NULL);
	purple_cipher_context_destroy(hmac);

	/* We need to pad this to 72 bytes, apparently */
	nonce_fixed = g_malloc(len + 8);
	memcpy(nonce_fixed, nexus->nonce, len);
	memset(nonce_fixed + len, 0x08, 8);
	cipher = des3_cbc(key3, iv, nonce_fixed, len + 8, FALSE);
	g_free(nonce_fixed);

	memcpy(usr_key, cipher, 72);

	g_free(key1);
	g_free(key2);
	g_free(key3);
	g_free(cipher);

	response = purple_base64_encode((guchar *)usr_key_base, MSN_USER_KEY_SIZE);

	return response;
}

/**************************************************************************
 * Login
 **************************************************************************/

/* Used to specify which token to update when only doing single updates */
typedef struct _MsnNexusUpdateData MsnNexusUpdateData;
struct _MsnNexusUpdateData {
	MsnNexus *nexus;
	int id;
};

typedef struct _MsnNexusUpdateCallback MsnNexusUpdateCallback;
struct _MsnNexusUpdateCallback {
	GSourceFunc cb;
	gpointer data;
};

static gboolean
nexus_parse_token(MsnNexus *nexus, int id, xmlnode *node)
{
	char *token_str, *expiry_str;
	const char *id_str;
	char **elems, **cur, **tokens;
	xmlnode *token = xmlnode_get_child(node, "RequestedSecurityToken/BinarySecurityToken");
	xmlnode *secret = xmlnode_get_child(node, "RequestedProofToken/BinarySecret");
	xmlnode *expires = xmlnode_get_child(node, "LifeTime/Expires");

	if (!token)
		return FALSE;

	/* Use the ID that the server sent us */
	if (id == -1) {
		id_str = xmlnode_get_attrib(token, "Id");
		if (id_str == NULL)
			return FALSE;

		id = atol(id_str + 7) - 1;	/* 'Compact#' or 'PPToken#' */
		if (id >= nexus->token_len)
			return FALSE;	/* Where did this come from? */
	}

	token_str = xmlnode_get_data(token);
	if (token_str == NULL)
		return FALSE;

	g_hash_table_remove_all(nexus->tokens[id].token);

	elems = g_strsplit(token_str, "&", 0);

	for (cur = elems; *cur != NULL; cur++) {
		tokens = g_strsplit(*cur, "=", 2);
		g_hash_table_insert(nexus->tokens[id].token, tokens[0], tokens[1]);
		/* Don't free each of the tokens, only the array. */
		g_free(tokens);
	}
	g_strfreev(elems);
	g_free(token_str);

	if (secret)
		nexus->tokens[id].secret = xmlnode_get_data(secret);
	else
		nexus->tokens[id].secret = NULL;

	/* Yay for MS using ISO-8601 */
	expiry_str = xmlnode_get_data(expires);
	nexus->tokens[id].expiry = purple_str_to_time(expiry_str,
		FALSE, NULL, NULL, NULL);
	g_free(expiry_str);

	purple_debug_info("msn", "Updated ticket for domain '%s', expires at %" G_GINT64_FORMAT ".\n",
	                  ticket_domains[id][SSO_VALID_TICKET_DOMAIN],
	                  (gint64)nexus->tokens[id].expiry);
	return TRUE;
}

static gboolean
nexus_parse_collection(MsnNexus *nexus, int id, xmlnode *collection)
{
	xmlnode *node;
	gboolean result;

	node = xmlnode_get_child(collection, "RequestSecurityTokenResponse");

	if (!node)
		return FALSE;

	result = TRUE;
	for (; node && result; node = node->next) {
		xmlnode *endpoint = xmlnode_get_child(node, "AppliesTo/EndpointReference/Address");
		char *address = xmlnode_get_data(endpoint);

		if (g_str_equal(address, "http://Passport.NET/tb")) {
			/* This node contains the stuff for updating tokens. */
			char *data;
			xmlnode *cipher = xmlnode_get_child(node, "RequestedSecurityToken/EncryptedData/CipherData/CipherValue");
			xmlnode *secret = xmlnode_get_child(node, "RequestedProofToken/BinarySecret");

			g_free(nexus->cipher);
			nexus->cipher = xmlnode_get_data(cipher);
			data = xmlnode_get_data(secret);
			g_free(nexus->secret);
			nexus->secret = (char *)purple_base64_decode(data, NULL);
			g_free(data);

		} else {
			result = nexus_parse_token(nexus, id, node);
		}
		g_free(address);
	}

	return result;
}

static void
nexus_got_response_cb(MsnSoapMessage *req, MsnSoapMessage *resp, gpointer data)
{
	MsnNexus *nexus = data;
	MsnSession *session = nexus->session;
	const char *ticket;
	char *response;

	if (resp == NULL) {
		msn_session_set_error(session, MSN_ERROR_SERVCONN, _("Windows Live ID authentication:Unable to connect"));
		return;
	}

	if (!nexus_parse_collection(nexus, -1,
	                            xmlnode_get_child(resp->xml,
	                                              "Body/RequestSecurityTokenResponseCollection"))) {
		msn_session_set_error(session, MSN_ERROR_SERVCONN, _("Windows Live ID authentication:Invalid response"));
		return;
	}

	ticket = msn_nexus_get_token_str(nexus, MSN_AUTH_MESSENGER);
	response = msn_rps_encrypt(nexus);
	msn_got_login_params(session, ticket, response);
	g_free(response);
}

/*when connect, do the SOAP Style windows Live ID authentication */
void
msn_nexus_connect(MsnNexus *nexus)
{
	MsnSession *session = nexus->session;
	const char *username;
	const char *password;
	char *password_xml;
	GString *domains;
	char *request;
	int i;

	MsnSoapMessage *soap;

	purple_debug_info("msn", "Starting Windows Live ID authentication\n");
	msn_session_set_login_step(session, MSN_LOGIN_STEP_GET_COOKIE);

	username = purple_account_get_username(session->account);
	password = purple_connection_get_password(session->account->gc);
	if (g_utf8_strlen(password, -1) > 16) {
		/* max byte size for 16 utf8 characters is 64 + 1 for the null */
		gchar truncated[65];
		g_utf8_strncpy(truncated, password, 16);
		password_xml = g_markup_escape_text(truncated, -1);
	} else {
		password_xml = g_markup_escape_text(password, -1);
	}

	purple_debug_info("msn", "Logging on %s, with policy '%s', nonce '%s'\n",
	                  username, nexus->policy, nexus->nonce);

	domains = g_string_new(NULL);
	for (i = 0; i < nexus->token_len; i++) {
		g_string_append_printf(domains, MSN_SSO_RST_TEMPLATE,
		                       i+1,
		                       ticket_domains[i][SSO_VALID_TICKET_DOMAIN],
		                       ticket_domains[i][SSO_VALID_TICKET_POLICY] != NULL ?
		                           ticket_domains[i][SSO_VALID_TICKET_POLICY] :
		                           nexus->policy);
	}

	request = g_strdup_printf(MSN_SSO_TEMPLATE, username, password_xml, domains->str);
	g_free(password_xml);
	g_string_free(domains, TRUE);

	soap = msn_soap_message_new(NULL, xmlnode_from_str(request, -1));
	g_free(request);
	msn_soap_message_send(session, soap, MSN_SSO_SERVER, SSO_POST_URL, TRUE,
	                      nexus_got_response_cb, nexus);
}

static void
nexus_got_update_cb(MsnSoapMessage *req, MsnSoapMessage *resp, gpointer data)
{
	MsnNexusUpdateData *ud = data;
	MsnNexus *nexus = ud->nexus;
	char iv[8] = {0,0,0,0,0,0,0,0};
	xmlnode *enckey;
	char *tmp;
	char *nonce;
	gsize len;
	char *key;
	GSList *updates;

#if 0
	char *decrypted_pp;
#endif
	char *decrypted_data;

	if (resp == NULL)
		return;

	purple_debug_info("msn", "Got Update Response for %s.\n", ticket_domains[ud->id][SSO_VALID_TICKET_DOMAIN]);

	enckey = xmlnode_get_child(resp->xml, "Header/Security/DerivedKeyToken");
	while (enckey) {
		if (g_str_equal(xmlnode_get_attrib(enckey, "Id"), "EncKey"))
			break;
		enckey = xmlnode_get_next_twin(enckey);
	}
	if (!enckey) {
		purple_debug_error("msn", "Invalid response in token update.\n");
		return;
	}

	tmp = xmlnode_get_data(xmlnode_get_child(enckey, "Nonce"));
	nonce = (char *)purple_base64_decode(tmp, &len);
	key = rps_create_key(nexus->secret, 24, nonce, len);
	g_free(tmp);
	g_free(nonce);

#if 0
	/* Don't know what this is for yet */
	tmp = xmlnode_get_data(xmlnode_get_child(resp->xml,
		"Header/EncryptedPP/EncryptedData/CipherData/CipherValue"));
	if (tmp) {
		decrypted_pp = des3_cbc(key, iv, tmp, len, TRUE);
		g_free(tmp);
		purple_debug_info("msn", "Got Response Header EncryptedPP: %s\n", decrypted_pp);
		g_free(decrypted_pp);
	}
#endif

	tmp = xmlnode_get_data(xmlnode_get_child(resp->xml,
		"Body/EncryptedData/CipherData/CipherValue"));
	if (tmp) {
		char *unescaped;
		xmlnode *rstresponse;

		unescaped = (char *)purple_base64_decode(tmp, &len);
		g_free(tmp);

		decrypted_data = des3_cbc(key, iv, unescaped, len, TRUE);
		g_free(unescaped);
		purple_debug_info("msn", "Got Response Body EncryptedData: %s\n", decrypted_data);

		rstresponse = xmlnode_from_str(decrypted_data, -1);
		if (g_str_equal(rstresponse->name, "RequestSecurityTokenResponse"))
			nexus_parse_token(nexus, ud->id, rstresponse);
		else
			nexus_parse_collection(nexus, ud->id, rstresponse);
		g_free(decrypted_data);
	}

	updates = nexus->tokens[ud->id].updates;
	nexus->tokens[ud->id].updates = NULL;
	while (updates != NULL) {
		MsnNexusUpdateCallback *update = updates->data;
		if (update->cb)
			purple_timeout_add(0, update->cb, update->data);
		g_free(update);
		updates = g_slist_delete_link(updates, updates);
	}

	g_free(ud);
	g_free(key);
}

void
msn_nexus_update_token(MsnNexus *nexus, int id, GSourceFunc cb, gpointer data)
{
	MsnSession *session = nexus->session;
	MsnNexusUpdateData *ud;
	MsnNexusUpdateCallback *update;
	PurpleCipherContext *sha1;
	PurpleCipherContext *hmac;

	char *key;

	guchar digest[20];

	struct tm *tm;
	time_t now;
	char *now_str;
	char *timestamp;
	char *timestamp_b64;

	char *domain;
	char *domain_b64;

	char *signedinfo;
	gint32 nonce[6];
	int i;
	char *nonce_b64;
	char *signature_b64;
	guchar signature[20];

	char *request;
	MsnSoapMessage *soap;

	update = g_new0(MsnNexusUpdateCallback, 1);
	update->cb = cb;
	update->data = data;

	if (nexus->tokens[id].updates != NULL) {
		/* Update already in progress. Just add to list and return. */
		purple_debug_info("msn",
		                  "Ticket update for user '%s' on domain '%s' in progress. Adding request to queue.\n",
		                  purple_account_get_username(session->account),
		                  ticket_domains[id][SSO_VALID_TICKET_DOMAIN]);
		nexus->tokens[id].updates = g_slist_prepend(nexus->tokens[id].updates,
		                                            update);
		return;
	} else {
		purple_debug_info("msn",
		                  "Updating ticket for user '%s' on domain '%s'\n",
		                  purple_account_get_username(session->account),
		                  ticket_domains[id][SSO_VALID_TICKET_DOMAIN]);
		nexus->tokens[id].updates = g_slist_prepend(nexus->tokens[id].updates,
		                                            update);
	}

	ud = g_new0(MsnNexusUpdateData, 1);
	ud->nexus = nexus;
	ud->id = id;

	sha1 = purple_cipher_context_new_by_name("sha1", NULL);

	domain = g_strdup_printf(MSN_SSO_RST_TEMPLATE,
	                         id,
	                         ticket_domains[id][SSO_VALID_TICKET_DOMAIN],
	                         ticket_domains[id][SSO_VALID_TICKET_POLICY] != NULL ?
	                             ticket_domains[id][SSO_VALID_TICKET_POLICY] :
	                             nexus->policy);
	purple_cipher_context_append(sha1, (guchar *)domain, strlen(domain));
	purple_cipher_context_digest(sha1, 20, digest, NULL);
	domain_b64 = purple_base64_encode(digest, 20);

	now = time(NULL);
	tm = gmtime(&now);
	now_str = g_strdup(purple_utf8_strftime("%Y-%m-%dT%H:%M:%SZ", tm));
	now += 5*60;
	tm = gmtime(&now);
	timestamp = g_strdup_printf(MSN_SSO_TIMESTAMP_TEMPLATE,
	                            now_str,
	                            purple_utf8_strftime("%Y-%m-%dT%H:%M:%SZ", tm));
	purple_cipher_context_reset(sha1, NULL);
	purple_cipher_context_append(sha1, (guchar *)timestamp, strlen(timestamp));
	purple_cipher_context_digest(sha1, 20, digest, NULL);
	timestamp_b64 = purple_base64_encode(digest, 20);
	g_free(now_str);

	purple_cipher_context_destroy(sha1);

	signedinfo = g_strdup_printf(MSN_SSO_SIGNEDINFO_TEMPLATE,
	                             id,
	                             domain_b64,
	                             timestamp_b64);

	for (i = 0; i < 6; i++)
		nonce[i] = rand();
	nonce_b64 = purple_base64_encode((guchar *)&nonce, sizeof(nonce));

	key = rps_create_key(nexus->secret, 24, (char *)nonce, sizeof(nonce));
	hmac = purple_cipher_context_new_by_name("hmac", NULL);
	purple_cipher_context_set_option(hmac, "hash", "sha1");
	purple_cipher_context_set_key_with_len(hmac, (guchar *)key, 24);
	purple_cipher_context_append(hmac, (guchar *)signedinfo, strlen(signedinfo));
	purple_cipher_context_digest(hmac, 20, signature, NULL);
	purple_cipher_context_destroy(hmac);
	signature_b64 = purple_base64_encode(signature, 20);

	request = g_strdup_printf(MSN_SSO_TOKEN_UPDATE_TEMPLATE,
	                          nexus->cipher,
	                          nonce_b64,
	                          timestamp,
	                          signedinfo,
	                          signature_b64,
	                          domain);

	g_free(nonce_b64);
	g_free(domain_b64);
	g_free(timestamp_b64);
	g_free(timestamp);
	g_free(key);
	g_free(signature_b64);
	g_free(signedinfo);
	g_free(domain);

	soap = msn_soap_message_new(NULL, xmlnode_from_str(request, -1));
	g_free(request);
	msn_soap_message_send(session, soap, MSN_SSO_SERVER, SSO_POST_URL, TRUE,
	                      nexus_got_update_cb, ud);
}

GHashTable *
msn_nexus_get_token(MsnNexus *nexus, MsnAuthDomains id)
{
	g_return_val_if_fail(nexus != NULL, NULL);
	g_return_val_if_fail(id < nexus->token_len, NULL);

	return nexus->tokens[id].token;
}

const char *
msn_nexus_get_token_str(MsnNexus *nexus, MsnAuthDomains id)
{
	static char buf[1024];
	GHashTable *token = msn_nexus_get_token(nexus, id);
	const char *msn_t;
	const char *msn_p;
	gint ret;

	g_return_val_if_fail(token != NULL, NULL);

	msn_t = g_hash_table_lookup(token, "t");
	msn_p = g_hash_table_lookup(token, "p");

	g_return_val_if_fail(msn_t != NULL, NULL);
	g_return_val_if_fail(msn_p != NULL, NULL);

	ret = g_snprintf(buf, sizeof(buf) - 1, "t=%s&p=%s", msn_t, msn_p);
	g_return_val_if_fail(ret != -1, NULL);

	return buf;
}

