/*
 * purple - Jabber Protocol Plugin
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
 *
 */
#include "internal.h"

#include "account.h"
#include "debug.h"
#include "cipher.h"
#include "core.h"
#include "conversation.h"
#include "request.h"
#include "sslconn.h"
#include "util.h"
#include "xmlnode.h"

#include "auth.h"
#include "disco.h"
#include "jabber.h"
#include "jutil.h"
#include "iq.h"
#include "notify.h"

static GSList *auth_mechs = NULL;

static void auth_old_result_cb(JabberStream *js, const char *from,
                               JabberIqType type, const char *id,
                               xmlnode *packet, gpointer data);

static void finish_plaintext_authentication(JabberStream *js)
{
	JabberIq *iq;
	xmlnode *query, *x;

	iq = jabber_iq_new_query(js, JABBER_IQ_SET, "jabber:iq:auth");
	query = xmlnode_get_child(iq->node, "query");
	x = xmlnode_new_child(query, "username");
	xmlnode_insert_data(x, js->user->node, -1);
	x = xmlnode_new_child(query, "resource");
	xmlnode_insert_data(x, js->user->resource, -1);
	x = xmlnode_new_child(query, "password");
	xmlnode_insert_data(x, purple_connection_get_password(js->gc), -1);
	jabber_iq_set_callback(iq, auth_old_result_cb, NULL);
	jabber_iq_send(iq);
}

static void allow_plaintext_auth(PurpleAccount *account)
{
	PurpleConnection *gc;
	JabberStream *js;

	purple_account_set_bool(account, "auth_plain_in_clear", TRUE);

	gc = purple_account_get_connection(account);
	js = purple_connection_get_protocol_data(gc);

	finish_plaintext_authentication(js);
}

static void disallow_plaintext_auth(PurpleAccount *account)
{
	purple_connection_error_reason(purple_account_get_connection(account),
		PURPLE_CONNECTION_ERROR_ENCRYPTION_ERROR,
		_("Server requires plaintext authentication over an unencrypted stream"));
}

#ifdef HAVE_CYRUS_SASL
static void
auth_old_pass_cb(PurpleConnection *gc, PurpleRequestFields *fields)
{
	PurpleAccount *account;
	JabberStream *js;
	const char *entry;
	gboolean remember;

	/* The password prompt dialog doesn't get disposed if the account disconnects */
	if (!PURPLE_CONNECTION_IS_VALID(gc))
		return;

	account = purple_connection_get_account(gc);
	js = purple_connection_get_protocol_data(gc);

	entry = purple_request_fields_get_string(fields, "password");
	remember = purple_request_fields_get_bool(fields, "remember");

	if (!entry || !*entry)
	{
		purple_notify_error(account, NULL, _("Password is required to sign on."), NULL);
		return;
	}

	if (remember)
		purple_account_set_remember_password(account, TRUE);

	purple_account_set_password(account, entry);

	/* Restart our connection */
	jabber_auth_start_old(js);
}

static void
auth_no_pass_cb(PurpleConnection *gc, PurpleRequestFields *fields)
{
	/* The password prompt dialog doesn't get disposed if the account disconnects */
	if (!PURPLE_CONNECTION_IS_VALID(gc))
		return;

	/* Disable the account as the user has cancelled connecting */
	purple_account_set_enabled(purple_connection_get_account(gc), purple_core_get_ui(), FALSE);
}
#endif

void
jabber_auth_start(JabberStream *js, xmlnode *packet)
{
	GSList *mechanisms = NULL;
	GSList *l;
	xmlnode *response = NULL;
	xmlnode *mechs, *mechnode;
	JabberSaslState state;
	char *msg = NULL;

	if(js->registration) {
		jabber_register_start(js);
		return;
	}

	mechs = xmlnode_get_child(packet, "mechanisms");
	if(!mechs) {
		purple_connection_error_reason(js->gc,
			PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
			_("Invalid response from server"));
		return;
	}

	for(mechnode = xmlnode_get_child(mechs, "mechanism"); mechnode;
			mechnode = xmlnode_get_next_twin(mechnode))
	{
		char *mech_name = xmlnode_get_data(mechnode);

		if (mech_name && *mech_name)
			mechanisms = g_slist_prepend(mechanisms, mech_name);
		else
			g_free(mech_name);

	}

	for (l = auth_mechs; l; l = l->next) {
		JabberSaslMech *possible = l->data;

		/* Is this the Cyrus SASL mechanism? */
		if (g_str_equal(possible->name, "*")) {
			js->auth_mech = possible;
			break;
		}

		/* Can we find this mechanism in the server's list? */
		if (g_slist_find_custom(mechanisms, possible->name, (GCompareFunc)strcmp)) {
			js->auth_mech = possible;
			break;
		}
	}

	while (mechanisms) {
		g_free(mechanisms->data);
		mechanisms = g_slist_delete_link(mechanisms, mechanisms);
	}

	if (js->auth_mech == NULL) {
		/* Found no good mechanisms... */
		purple_connection_error_reason(js->gc,
				PURPLE_CONNECTION_ERROR_AUTHENTICATION_IMPOSSIBLE,
				_("Server does not use any supported authentication method"));
		return;
	}

	state = js->auth_mech->start(js, mechs, &response, &msg);
	if (state == JABBER_SASL_STATE_FAIL) {
		purple_connection_error_reason(js->gc,
				PURPLE_CONNECTION_ERROR_AUTHENTICATION_IMPOSSIBLE,
				msg ? msg : _("Unknown Error"));
	} else if (response) {
		jabber_send(js, response);
		xmlnode_free(response);
	}

	g_free(msg);
}

static void auth_old_result_cb(JabberStream *js, const char *from,
                               JabberIqType type, const char *id,
                               xmlnode *packet, gpointer data)
{
	if (type == JABBER_IQ_RESULT) {
		jabber_stream_set_state(js, JABBER_STREAM_POST_AUTH);
		jabber_disco_items_server(js);
	} else {
		PurpleAccount *account;
		PurpleConnectionError reason = PURPLE_CONNECTION_ERROR_NETWORK_ERROR;
		char *msg = jabber_parse_error(js, packet, &reason);
		xmlnode *error;
		const char *err_code;

		account = purple_connection_get_account(js->gc);

		/* FIXME: Why is this not in jabber_parse_error? */
		if((error = xmlnode_get_child(packet, "error")) &&
					(err_code = xmlnode_get_attrib(error, "code")) &&
					g_str_equal(err_code, "401")) {
			reason = PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED;
			/* Clear the pasword if it isn't being saved */
			if (!purple_account_get_remember_password(account))
				purple_account_set_password(account, NULL);
		}

		purple_connection_error_reason(js->gc, reason, msg);
		g_free(msg);
	}
}

static void auth_old_cb(JabberStream *js, const char *from,
                        JabberIqType type, const char *id,
                        xmlnode *packet, gpointer data)
{
	JabberIq *iq;
	xmlnode *query, *x;
	const char *pw = purple_connection_get_password(js->gc);

	if (type == JABBER_IQ_ERROR) {
		PurpleConnectionError reason = PURPLE_CONNECTION_ERROR_NETWORK_ERROR;
		char *msg = jabber_parse_error(js, packet, &reason);
		purple_connection_error_reason(js->gc, reason, msg);
		g_free(msg);
	} else if (type == JABBER_IQ_RESULT) {
		query = xmlnode_get_child(packet, "query");
		if (js->stream_id && *js->stream_id &&
				xmlnode_get_child(query, "digest")) {
			char *s, *hash;

			iq = jabber_iq_new_query(js, JABBER_IQ_SET, "jabber:iq:auth");
			query = xmlnode_get_child(iq->node, "query");
			x = xmlnode_new_child(query, "username");
			xmlnode_insert_data(x, js->user->node, -1);
			x = xmlnode_new_child(query, "resource");
			xmlnode_insert_data(x, js->user->resource, -1);

			x = xmlnode_new_child(query, "digest");
			s = g_strdup_printf("%s%s", js->stream_id, pw);
			hash = jabber_calculate_data_hash(s, strlen(s), "sha1");
			xmlnode_insert_data(x, hash, -1);
			g_free(hash);
			g_free(s);
			jabber_iq_set_callback(iq, auth_old_result_cb, NULL);
			jabber_iq_send(iq);
		} else if ((x = xmlnode_get_child(query, "crammd5"))) {
			/* For future reference, this appears to be a custom OS X extension
			 * to non-SASL authentication.
			 */
			const char *challenge;
			gchar digest[33];
			PurpleCipherContext *hmac;

			/* Calculate the MHAC-MD5 digest */
			challenge = xmlnode_get_attrib(x, "challenge");
			hmac = purple_cipher_context_new_by_name("hmac", NULL);
			purple_cipher_context_set_option(hmac, "hash", "md5");
			purple_cipher_context_set_key(hmac, (guchar *)pw);
			purple_cipher_context_append(hmac, (guchar *)challenge, strlen(challenge));
			purple_cipher_context_digest_to_str(hmac, 33, digest, NULL);
			purple_cipher_context_destroy(hmac);

			/* Create the response query */
			iq = jabber_iq_new_query(js, JABBER_IQ_SET, "jabber:iq:auth");
			query = xmlnode_get_child(iq->node, "query");

			x = xmlnode_new_child(query, "username");
			xmlnode_insert_data(x, js->user->node, -1);
			x = xmlnode_new_child(query, "resource");
			xmlnode_insert_data(x, js->user->resource, -1);

			x = xmlnode_new_child(query, "crammd5");

			xmlnode_insert_data(x, digest, 32);

			jabber_iq_set_callback(iq, auth_old_result_cb, NULL);
			jabber_iq_send(iq);

		} else if(xmlnode_get_child(query, "password")) {
			PurpleAccount *account = purple_connection_get_account(js->gc);
			if(!jabber_stream_is_ssl(js) && !purple_account_get_bool(account,
						"auth_plain_in_clear", FALSE)) {
				char *msg = g_strdup_printf(_("%s requires plaintext authentication over an unencrypted connection.  Allow this and continue authentication?"),
											purple_account_get_username(account));
				purple_request_yes_no(js->gc, _("Plaintext Authentication"),
						_("Plaintext Authentication"),
						msg,
						1,
						account, NULL, NULL,
						account, allow_plaintext_auth,
						disallow_plaintext_auth);
				g_free(msg);
				return;
			}
			finish_plaintext_authentication(js);
		} else {
			purple_connection_error_reason(js->gc,
				PURPLE_CONNECTION_ERROR_AUTHENTICATION_IMPOSSIBLE,
				_("Server does not use any supported authentication method"));
			return;
		}
	}
}

void jabber_auth_start_old(JabberStream *js)
{
	PurpleAccount *account;
	JabberIq *iq;
	xmlnode *query, *username;

	account = purple_connection_get_account(js->gc);

	/*
	 * We can end up here without encryption if the server doesn't support
	 * <stream:features/> and we're not using old-style SSL.  If the user
	 * is requiring SSL/TLS, we need to enforce it.
	 */
	if (!jabber_stream_is_ssl(js) &&
			g_str_equal("require_tls",
				purple_account_get_string(account, "connection_security", JABBER_DEFAULT_REQUIRE_TLS))) {
		purple_connection_error_reason(js->gc,
			PURPLE_CONNECTION_ERROR_ENCRYPTION_ERROR,
			_("You require encryption, but it is not available on this server."));
		return;
	}

	if (js->registration) {
		jabber_register_start(js);
		return;
	}

	/*
	 * IQ Auth doesn't have support for resource binding, so we need to pick a
	 * default resource so it will work properly.  jabberd14 throws an error and
	 * iChat server just fails silently.
	 */
	if (!js->user->resource || *js->user->resource == '\0') {
		g_free(js->user->resource);
		js->user->resource = g_strdup("Home");
	}

#ifdef HAVE_CYRUS_SASL
	/* If we have Cyrus SASL, then passwords will have been set
	 * to OPTIONAL for this protocol. So, we need to do our own
	 * password prompting here
	 */

	if (!purple_account_get_password(account)) {
		purple_account_request_password(account, G_CALLBACK(auth_old_pass_cb), G_CALLBACK(auth_no_pass_cb), js->gc);
		return;
	}
#endif
	iq = jabber_iq_new_query(js, JABBER_IQ_GET, "jabber:iq:auth");

	query = xmlnode_get_child(iq->node, "query");
	username = xmlnode_new_child(query, "username");
	xmlnode_insert_data(username, js->user->node, -1);

	jabber_iq_set_callback(iq, auth_old_cb, NULL);

	jabber_iq_send(iq);
}

void
jabber_auth_handle_challenge(JabberStream *js, xmlnode *packet)
{
	const char *ns = xmlnode_get_namespace(packet);

	if (!purple_strequal(ns, NS_XMPP_SASL)) {
		purple_connection_error_reason(js->gc,
			PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
			_("Invalid response from server"));
		return;
	}

	if (js->auth_mech && js->auth_mech->handle_challenge) {
		xmlnode *response = NULL;
		char *msg = NULL;
		JabberSaslState state = js->auth_mech->handle_challenge(js, packet, &response, &msg);
		if (state == JABBER_SASL_STATE_FAIL) {
			purple_connection_error_reason(js->gc,
					PURPLE_CONNECTION_ERROR_AUTHENTICATION_IMPOSSIBLE,
					msg ? msg : _("Invalid challenge from server"));
		} else if (response) {
			jabber_send(js, response);
			xmlnode_free(response);
		}

		g_free(msg);
	} else
		purple_debug_warning("jabber", "Received unexpected (and unhandled) <challenge/>\n");
}

void jabber_auth_handle_success(JabberStream *js, xmlnode *packet)
{
	const char *ns = xmlnode_get_namespace(packet);

	if (!purple_strequal(ns, NS_XMPP_SASL)) {
		purple_connection_error_reason(js->gc,
			PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
			_("Invalid response from server"));
		return;
	}

	if (js->auth_mech && js->auth_mech->handle_success) {
		char *msg = NULL;
		JabberSaslState state = js->auth_mech->handle_success(js, packet, &msg);

		if (state == JABBER_SASL_STATE_FAIL) {
			purple_connection_error_reason(js->gc,
					PURPLE_CONNECTION_ERROR_AUTHENTICATION_IMPOSSIBLE,
					msg ? msg : _("Invalid response from server"));
			return;
		} else if (state == JABBER_SASL_STATE_CONTINUE) {
			purple_connection_error_reason(js->gc,
					PURPLE_CONNECTION_ERROR_AUTHENTICATION_IMPOSSIBLE,
					msg ? msg : _("Server thinks authentication is complete, but client does not"));
			return;
		}

		g_free(msg);
	}

	/*
	 * The stream will be reinitialized later in jabber_recv_cb_ssl() or
	 * jabber_bosh_connection_send.
	 */
	js->reinit = TRUE;
	jabber_stream_set_state(js, JABBER_STREAM_POST_AUTH);
}

void jabber_auth_handle_failure(JabberStream *js, xmlnode *packet)
{
	PurpleConnectionError reason = PURPLE_CONNECTION_ERROR_NETWORK_ERROR;
	char *msg = NULL;

	if (js->auth_mech && js->auth_mech->handle_failure) {
		xmlnode *stanza = NULL;
		JabberSaslState state = js->auth_mech->handle_failure(js, packet, &stanza, &msg);

		if (state != JABBER_SASL_STATE_FAIL) {
			if (stanza) {
				jabber_send(js, stanza);
				xmlnode_free(stanza);
			}

			return;
		}
	}

	if (!msg)
		msg = jabber_parse_error(js, packet, &reason);

	if (!msg) {
		purple_connection_error_reason(js->gc,
			PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
			_("Invalid response from server"));
	} else {
		purple_connection_error_reason(js->gc, reason, msg);
		g_free(msg);
	}
}

static gint compare_mech(gconstpointer a, gconstpointer b)
{
	const JabberSaslMech *mech_a = a;
	const JabberSaslMech *mech_b = b;

	/* higher priority comes *before* lower priority in the list */
	if (mech_a->priority > mech_b->priority)
		return -1;
	else if (mech_a->priority < mech_b->priority)
		return 1;
	/* This really shouldn't happen */
	return 0;
}

void jabber_auth_add_mech(JabberSaslMech *mech)
{
	auth_mechs = g_slist_insert_sorted(auth_mechs, mech, compare_mech);
}

void jabber_auth_remove_mech(JabberSaslMech *mech)
{
	auth_mechs = g_slist_remove(auth_mechs, mech);
}

void jabber_auth_init(void)
{
	JabberSaslMech **tmp;
	gint count, i;

	jabber_auth_add_mech(jabber_auth_get_plain_mech());
	jabber_auth_add_mech(jabber_auth_get_digest_md5_mech());
#ifdef HAVE_CYRUS_SASL
	jabber_auth_add_mech(jabber_auth_get_cyrus_mech());
#endif

	tmp = jabber_auth_get_scram_mechs(&count);
	for (i = 0; i < count; ++i)
		jabber_auth_add_mech(tmp[i]);
}

void jabber_auth_uninit(void)
{
	g_slist_free(auth_mechs);
	auth_mechs = NULL;
}
