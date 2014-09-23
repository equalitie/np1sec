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
#include "request.h"
#include "util.h"
#include "xmlnode.h"

#include "jabber.h"
#include "auth.h"

static xmlnode *finish_plaintext_authentication(JabberStream *js)
{
	xmlnode *auth;
	GString *response;
	gchar *enc_out;

	auth = xmlnode_new("auth");
	xmlnode_set_namespace(auth, NS_XMPP_SASL);

	xmlnode_set_attrib(auth, "xmlns:ga", "http://www.google.com/talk/protocol/auth");
	xmlnode_set_attrib(auth, "ga:client-uses-full-bind-result", "true");

	response = g_string_new("");
	response = g_string_append_c(response, '\0');
	response = g_string_append(response, js->user->node);
	response = g_string_append_c(response, '\0');
	response = g_string_append(response,
			purple_connection_get_password(js->gc));

	enc_out = purple_base64_encode((guchar *)response->str, response->len);

	xmlnode_set_attrib(auth, "mechanism", "PLAIN");
	xmlnode_insert_data(auth, enc_out, -1);
	g_free(enc_out);
	g_string_free(response, TRUE);

	return auth;
}

static void allow_plaintext_auth(PurpleAccount *account)
{
	PurpleConnection *gc = purple_account_get_connection(account);
	JabberStream *js = purple_connection_get_protocol_data(gc);
	xmlnode *response;

	purple_account_set_bool(account, "auth_plain_in_clear", TRUE);

	response = finish_plaintext_authentication(js);
	jabber_send(js, response);
	xmlnode_free(response);
}

static void disallow_plaintext_auth(PurpleAccount *account)
{
	purple_connection_error_reason(purple_account_get_connection(account),
		PURPLE_CONNECTION_ERROR_ENCRYPTION_ERROR,
		_("Server requires plaintext authentication over an unencrypted stream"));
}

static JabberSaslState
jabber_plain_start(JabberStream *js, xmlnode *packet, xmlnode **response, char **error)
{
	PurpleAccount *account = purple_connection_get_account(js->gc);
	char *msg;

	if (jabber_stream_is_ssl(js) || purple_account_get_bool(account, "auth_plain_in_clear", FALSE)) {
		*response = finish_plaintext_authentication(js);
		return JABBER_SASL_STATE_OK;
	}

	msg = g_strdup_printf(_("%s requires plaintext authentication over an unencrypted connection.  Allow this and continue authentication?"),
			purple_account_get_username(account));
	purple_request_yes_no(js->gc, _("Plaintext Authentication"),
			_("Plaintext Authentication"),
			msg,
			1,
			account, NULL, NULL,
			account, allow_plaintext_auth, disallow_plaintext_auth);
	g_free(msg);
	return JABBER_SASL_STATE_CONTINUE;
}

static JabberSaslMech plain_mech = {
	0, /* priority */
	"PLAIN", /* name */
	jabber_plain_start,
	NULL, /* handle_challenge */
	NULL, /* handle_success */
	NULL, /* handle_failure */
	NULL  /* dispose */
};

JabberSaslMech *jabber_auth_get_plain_mech(void)
{
	return &plain_mech;
}
