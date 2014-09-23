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
#include "core.h"
#include "debug.h"
#include "request.h"

#include "auth.h"
#include "jabber.h"

static JabberSaslState jabber_auth_start_cyrus(JabberStream *js, xmlnode **reply,
                                               char **error);
static void jabber_sasl_build_callbacks(JabberStream *);

static void disallow_plaintext_auth(PurpleAccount *account)
{
	purple_connection_error_reason(purple_account_get_connection(account),
		PURPLE_CONNECTION_ERROR_ENCRYPTION_ERROR,
		_("Server may require plaintext authentication over an unencrypted stream"));
}

static void start_cyrus_wrapper(JabberStream *js)
{
	char *error = NULL;
	xmlnode *response = NULL;
	JabberSaslState state = jabber_auth_start_cyrus(js, &response, &error);

	if (state == JABBER_SASL_STATE_FAIL) {
		purple_connection_error_reason(js->gc,
				PURPLE_CONNECTION_ERROR_AUTHENTICATION_IMPOSSIBLE,
				error);
		g_free(error);
	} else if (response) {
		jabber_send(js, response);
		xmlnode_free(response);
	}
}


/* Callbacks for Cyrus SASL */

static int jabber_sasl_cb_realm(void *ctx, int id, const char **avail, const char **result)
{
	JabberStream *js = ctx;

	if (id != SASL_CB_GETREALM || !result) return SASL_BADPARAM;

	*result = js->user->domain;

	return SASL_OK;
}

static int jabber_sasl_cb_simple(void *ctx, int id, const char **res, unsigned *len)
{
	JabberStream *js = ctx;

	switch(id) {
		case SASL_CB_AUTHNAME:
			*res = js->user->node;
			break;
		case SASL_CB_USER:
			*res = "";
			break;
		default:
			return SASL_BADPARAM;
	}
	if (len) *len = strlen((char *)*res);
	return SASL_OK;
}

static int jabber_sasl_cb_secret(sasl_conn_t *conn, void *ctx, int id, sasl_secret_t **secret)
{
	JabberStream *js = ctx;
	PurpleAccount *account;
	const char *pw;
	size_t len;

	account = purple_connection_get_account(js->gc);
	pw = purple_account_get_password(account);

	if (!conn || !secret || id != SASL_CB_PASS)
		return SASL_BADPARAM;

	len = strlen(pw);
	/* Not an off-by-one because sasl_secret_t defines char data[1] */
	/* TODO: This can probably be moved to glib's allocator */
	js->sasl_secret = malloc(sizeof(sasl_secret_t) + len);
	if (!js->sasl_secret)
		return SASL_NOMEM;

	js->sasl_secret->len = len;
	strcpy((char*)js->sasl_secret->data, pw);

	*secret = js->sasl_secret;
	return SASL_OK;
}

static void allow_cyrus_plaintext_auth(PurpleAccount *account)
{
	PurpleConnection *gc;
	JabberStream *js;

	gc = purple_account_get_connection(account);
	js = purple_connection_get_protocol_data(gc);

	purple_account_set_bool(account, "auth_plain_in_clear", TRUE);

	start_cyrus_wrapper(js);
}

static void auth_pass_cb(PurpleConnection *gc, PurpleRequestFields *fields)
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

	/* Rebuild our callbacks as we now have a password to offer */
	jabber_sasl_build_callbacks(js);

	/* Restart our negotiation */
	start_cyrus_wrapper(js);
}

static void
auth_no_pass_cb(PurpleConnection *gc, PurpleRequestFields *fields)
{
	PurpleAccount *account;

	/* The password prompt dialog doesn't get disposed if the account disconnects */
	if (!PURPLE_CONNECTION_IS_VALID(gc))
		return;

	account = purple_connection_get_account(gc);

	/* Disable the account as the user has cancelled connecting */
	purple_account_set_enabled(account, purple_core_get_ui(), FALSE);
}

static gboolean remove_current_mech(JabberStream *js) {
	char *pos;
	if ((pos = strstr(js->sasl_mechs->str, js->current_mech))) {
		int len = strlen(js->current_mech);
		/* Clean up space that separated this Mech from the one before or after it */
		if (pos > js->sasl_mechs->str && *(pos - 1) == ' ') {
			/* Handle removing space before when current_mech isn't the first mech in the list */
			pos--;
			len++;
		} else if (strlen(pos) > len && *(pos + len) == ' ') {
			/* Handle removing space after */
			len++;
		}
		g_string_erase(js->sasl_mechs, pos - js->sasl_mechs->str, len);
		return TRUE;
	}
	return FALSE;
}

static JabberSaslState
jabber_auth_start_cyrus(JabberStream *js, xmlnode **reply, char **error)
{
	PurpleAccount *account;
	const char *clientout = NULL;
	char *enc_out;
	unsigned coutlen = 0;
	sasl_security_properties_t secprops;
	gboolean again;
	gboolean plaintext = TRUE;

	/* Set up security properties and options */
	secprops.min_ssf = 0;
	secprops.security_flags = SASL_SEC_NOANONYMOUS;

	account = purple_connection_get_account(js->gc);

	if (!jabber_stream_is_ssl(js)) {
		secprops.max_ssf = -1;
		secprops.maxbufsize = 4096;
		plaintext = purple_account_get_bool(account, "auth_plain_in_clear", FALSE);
		if (!plaintext)
			secprops.security_flags |= SASL_SEC_NOPLAINTEXT;
	} else {
		secprops.max_ssf = 0;
		secprops.maxbufsize = 0;
		plaintext = TRUE;
	}
	secprops.property_names = 0;
	secprops.property_values = 0;

	do {
		again = FALSE;

		js->sasl_state = sasl_client_new("xmpp", js->serverFQDN, NULL, NULL, js->sasl_cb, 0, &js->sasl);
		if (js->sasl_state==SASL_OK) {
			sasl_setprop(js->sasl, SASL_SEC_PROPS, &secprops);
			purple_debug_info("sasl", "Mechs found: %s\n", js->sasl_mechs->str);
			js->sasl_state = sasl_client_start(js->sasl, js->sasl_mechs->str, NULL, &clientout, &coutlen, &js->current_mech);
		}
		switch (js->sasl_state) {
			/* Success */
			case SASL_OK:
			case SASL_CONTINUE:
				break;
			case SASL_NOMECH:
				/* No mechanisms have offered to help */

				/* Firstly, if we don't have a password try
				 * to get one
				 */

				if (!purple_account_get_password(account)) {
					purple_account_request_password(account, G_CALLBACK(auth_pass_cb), G_CALLBACK(auth_no_pass_cb), js->gc);
					return JABBER_SASL_STATE_CONTINUE;

				/* If we've got a password, but aren't sending
				 * it in plaintext, see if we can turn on
				 * plaintext auth
				 */
				/* XXX Should we just check for PLAIN/LOGIN being offered mechanisms? */
				} else if (!plaintext) {
					char *msg = g_strdup_printf(_("%s may require plaintext authentication over an unencrypted connection.  Allow this and continue authentication?"),
							purple_account_get_username(account));
					purple_request_yes_no(js->gc, _("Plaintext Authentication"),
							_("Plaintext Authentication"),
							msg,
							1, account, NULL, NULL, account,
							allow_cyrus_plaintext_auth,
							disallow_plaintext_auth);
					g_free(msg);
					return JABBER_SASL_STATE_CONTINUE;

				} else
					js->auth_fail_count++;

				if (js->auth_fail_count == 1 &&
					(js->sasl_mechs->str && g_str_equal(js->sasl_mechs->str, "GSSAPI"))) {
					/* If we tried GSSAPI first, it failed, and it was the only method we had to try, try jabber:iq:auth
					 * for compatibility with iChat 10.5 Server and other jabberd based servers.
					 *
					 * iChat Server 10.5 and certain other corporate servers offer SASL GSSAPI by default, which is often
					 * not configured on the client side, and expects a fallback to jabber:iq:auth when it (predictably) fails.
					 *
					 * Note: xep-0078 points out that using jabber:iq:auth after a sasl failure is wrong. However,
					 * I believe this refers to actual authentication failure, not a simple lack of concordant mechanisms.
					 * Doing otherwise means that simply compiling with SASL support renders the client unable to connect to servers
					 * which would connect without issue otherwise. -evands
					 */
					js->auth_mech = NULL;
					jabber_auth_start_old(js);
					return JABBER_SASL_STATE_CONTINUE;
				}

				break;

				/* Fatal errors. Give up and go home */
			case SASL_BADPARAM:
			case SASL_NOMEM:
				*error = g_strdup(_("SASL authentication failed"));
				break;

				/* For everything else, fail the mechanism and try again */
			default:
				purple_debug_info("sasl", "sasl_state is %d, failing the mech and trying again\n", js->sasl_state);

				js->auth_fail_count++;

				/*
				 * DAA: is this right?
				 * The manpage says that "mech" will contain the chosen mechanism on success.
				 * Presumably, if we get here that isn't the case and we shouldn't try again?
				 * I suspect that this never happens.
				 */
				/*
				 * SXW: Yes, this is right. What this handles is the situation where a
				 * mechanism, say GSSAPI, is tried. If that mechanism fails, it may be
				 * due to mechanism specific issues, so we want to try one of the other
				 * supported mechanisms. This code handles that case
				 */
				if (js->current_mech && *js->current_mech) {
					remove_current_mech(js);
					/* Should we only try again if we've removed the mech? */
					again = TRUE;
				}

				sasl_dispose(&js->sasl);
		}
	} while (again);

	if (js->sasl_state == SASL_CONTINUE || js->sasl_state == SASL_OK) {
		xmlnode *auth = xmlnode_new("auth");
		xmlnode_set_namespace(auth, NS_XMPP_SASL);
		xmlnode_set_attrib(auth, "mechanism", js->current_mech);

		xmlnode_set_attrib(auth, "xmlns:ga", "http://www.google.com/talk/protocol/auth");
		xmlnode_set_attrib(auth, "ga:client-uses-full-bind-result", "true");

		if (clientout) {
			if (coutlen == 0) {
				xmlnode_insert_data(auth, "=", -1);
			} else {
				enc_out = purple_base64_encode((unsigned char*)clientout, coutlen);
				xmlnode_insert_data(auth, enc_out, -1);
				g_free(enc_out);
			}
		}

		*reply = auth;
		return JABBER_SASL_STATE_CONTINUE;
	} else {
		return JABBER_SASL_STATE_FAIL;
	}
}

static int
jabber_sasl_cb_log(void *context, int level, const char *message)
{
	if(level <= SASL_LOG_TRACE)
		purple_debug_info("sasl", "%s\n", message);

	return SASL_OK;
}

static void
jabber_sasl_build_callbacks(JabberStream *js)
{
	PurpleAccount *account;
	int id;

	/* Set up our callbacks structure */
	if (js->sasl_cb == NULL)
		js->sasl_cb = g_new0(sasl_callback_t,6);

	id = 0;
	js->sasl_cb[id].id = SASL_CB_GETREALM;
	js->sasl_cb[id].proc = jabber_sasl_cb_realm;
	js->sasl_cb[id].context = (void *)js;
	id++;

	js->sasl_cb[id].id = SASL_CB_AUTHNAME;
	js->sasl_cb[id].proc = jabber_sasl_cb_simple;
	js->sasl_cb[id].context = (void *)js;
	id++;

	js->sasl_cb[id].id = SASL_CB_USER;
	js->sasl_cb[id].proc = jabber_sasl_cb_simple;
	js->sasl_cb[id].context = (void *)js;
	id++;

	account = purple_connection_get_account(js->gc);
	if (purple_account_get_password(account) != NULL ) {
		js->sasl_cb[id].id = SASL_CB_PASS;
		js->sasl_cb[id].proc = jabber_sasl_cb_secret;
		js->sasl_cb[id].context = (void *)js;
		id++;
	}

	js->sasl_cb[id].id = SASL_CB_LOG;
	js->sasl_cb[id].proc = jabber_sasl_cb_log;
	js->sasl_cb[id].context = (void*)js;
	id++;

	js->sasl_cb[id].id = SASL_CB_LIST_END;
}

static JabberSaslState
jabber_cyrus_start(JabberStream *js, xmlnode *mechanisms,
                   xmlnode **reply, char **error)
{
	xmlnode *mechnode;
	JabberSaslState ret;

	js->sasl_mechs = g_string_new("");

	for(mechnode = xmlnode_get_child(mechanisms, "mechanism"); mechnode;
			mechnode = xmlnode_get_next_twin(mechnode))
	{
		char *mech_name = xmlnode_get_data(mechnode);

		/* Ignore blank mechanisms and EXTERNAL.  External isn't
		 * supported, and Cyrus SASL's mechanism returns
		 * SASL_NOMECH when the caller (us) doesn't configure it.
		 * Except SASL_NOMECH is supposed to mean "no concordant
		 * mechanisms"...  Easiest just to blacklist it (for now).
		 */
		if (!mech_name || !*mech_name ||
				g_str_equal(mech_name, "EXTERNAL")) {
			g_free(mech_name);
			continue;
		}

		g_string_append(js->sasl_mechs, mech_name);
		g_string_append_c(js->sasl_mechs, ' ');
		g_free(mech_name);
	}

	/* Strip off the trailing ' ' */
	if (js->sasl_mechs->len > 1)
		g_string_truncate(js->sasl_mechs, js->sasl_mechs->len - 1);

	jabber_sasl_build_callbacks(js);
	ret = jabber_auth_start_cyrus(js, reply, error);

	/*
	 * Triggered if no overlap between server and client
	 * supported mechanisms.
	 */
	if (ret == JABBER_SASL_STATE_FAIL && *error == NULL)
		*error = g_strdup(_("Server does not use any supported authentication method"));

	return ret;
}

static JabberSaslState
jabber_cyrus_handle_challenge(JabberStream *js, xmlnode *packet,
                              xmlnode **reply, char **error)
{
	char *enc_in = xmlnode_get_data(packet);
	unsigned char *dec_in;
	char *enc_out;
	const char *c_out;
	unsigned int clen;
	gsize declen;

	dec_in = purple_base64_decode(enc_in, &declen);

	js->sasl_state = sasl_client_step(js->sasl, (char*)dec_in, declen,
					  NULL, &c_out, &clen);
	g_free(enc_in);
	g_free(dec_in);
	if (js->sasl_state != SASL_CONTINUE && js->sasl_state != SASL_OK) {
		gchar *tmp = g_strdup_printf(_("SASL error: %s"),
				sasl_errdetail(js->sasl));
		purple_debug_error("jabber", "Error is %d : %s\n",
				js->sasl_state, sasl_errdetail(js->sasl));
		*error = tmp;
		return JABBER_SASL_STATE_FAIL;
	} else {
		xmlnode *response = xmlnode_new("response");
		xmlnode_set_namespace(response, NS_XMPP_SASL);
		if (clen > 0) {
			/* Cyrus SASL 2.1.22 appears to contain code to add the charset
			 * to the response for DIGEST-MD5 but there is no possibility
			 * it will be executed.
			 *
			 * My reading of the digestmd5 plugin indicates the username and
			 * realm are always encoded in UTF-8 (they seem to be the values
			 * we pass in), so we need to ensure charset=utf-8 is set.
			 */
			if (!purple_strequal(js->current_mech, "DIGEST-MD5") ||
					strstr(c_out, ",charset="))
				/* If we're not using DIGEST-MD5 or Cyrus SASL is fixed */
				enc_out = purple_base64_encode((unsigned char*)c_out, clen);
			else {
				char *tmp = g_strdup_printf("%s,charset=utf-8", c_out);
				enc_out = purple_base64_encode((unsigned char*)tmp, clen + 14);
				g_free(tmp);
			}

			xmlnode_insert_data(response, enc_out, -1);
			g_free(enc_out);
		}

		*reply = response;
		return JABBER_SASL_STATE_CONTINUE;
	}
}

static JabberSaslState
jabber_cyrus_handle_success(JabberStream *js, xmlnode *packet,
                            char **error)
{
	const void *x;

	/* The SASL docs say that if the client hasn't returned OK yet, we
	 * should try one more round against it
	 */
	if (js->sasl_state != SASL_OK) {
		char *enc_in = xmlnode_get_data(packet);
		unsigned char *dec_in = NULL;
		const char *c_out;
		unsigned int clen;
		gsize declen = 0;

		if(enc_in != NULL)
			dec_in = purple_base64_decode(enc_in, &declen);

		js->sasl_state = sasl_client_step(js->sasl, (char*)dec_in, declen, NULL, &c_out, &clen);

		g_free(enc_in);
		g_free(dec_in);

		if (js->sasl_state != SASL_OK) {
			/* This happens when the server sends back jibberish
			 * in the "additional data with success" case.
			 * Seen with Wildfire 3.0.1.
			 */
			*error = g_strdup(_("Invalid response from server"));
			return JABBER_SASL_STATE_FAIL;
		}
	}

	/* If we've negotiated a security layer, we need to enable it */
	if (js->sasl) {
		sasl_getprop(js->sasl, SASL_SSF, &x);
		if (*(int *)x > 0) {
			sasl_getprop(js->sasl, SASL_MAXOUTBUF, &x);
			js->sasl_maxbuf = *(int *)x;
		}
	}

	return JABBER_SASL_STATE_OK;
}

static JabberSaslState
jabber_cyrus_handle_failure(JabberStream *js, xmlnode *packet,
                            xmlnode **reply, char **error)
{
	if (js->auth_fail_count++ < 5) {
		if (js->current_mech && *js->current_mech) {
			remove_current_mech(js);
		}

		/* Should we only try again if we've actually removed a mech? */
		if (*js->sasl_mechs->str) {
			/* If we have remaining mechs to try, do so */
			sasl_dispose(&js->sasl);

			return jabber_auth_start_cyrus(js, reply, error);

		} else if ((js->auth_fail_count == 1) &&
				   (js->current_mech && g_str_equal(js->current_mech, "GSSAPI"))) {
			/* If we tried GSSAPI first, it failed, and it was the only method we had to try, try jabber:iq:auth
			 * for compatibility with iChat 10.5 Server and other jabberd based servers.
			 *
			 * iChat Server 10.5 and certain other corporate servers offer SASL GSSAPI by default, which is often
			 * not configured on the client side, and expects a fallback to jabber:iq:auth when it (predictably) fails.
			 *
			 * Note: xep-0078 points out that using jabber:iq:auth after a sasl failure is wrong. However,
			 * I believe this refers to actual authentication failure, not a simple lack of concordant mechanisms.
			 * Doing otherwise means that simply compiling with SASL support renders the client unable to connect to servers
			 * which would connect without issue otherwise. -evands
			 */
			sasl_dispose(&js->sasl);
			js->sasl = NULL;
			js->auth_mech = NULL;
			jabber_auth_start_old(js);
			return JABBER_SASL_STATE_CONTINUE;
		}
	}

	/* Nothing to send */
	return JABBER_SASL_STATE_FAIL;
}

static JabberSaslMech cyrus_mech = {
	100, /* priority */
	"*", /* name; Cyrus provides a bunch of mechanisms, so use an invalid
	      * mechanism name (per rfc4422 3.1). */
	jabber_cyrus_start,
	jabber_cyrus_handle_challenge,
	jabber_cyrus_handle_success,
	jabber_cyrus_handle_failure,
	NULL,
};

JabberSaslMech *jabber_auth_get_cyrus_mech(void)
{
	return &cyrus_mech;
}
