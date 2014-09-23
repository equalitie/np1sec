/*
 * Purple's oscar protocol plugin
 * This file is the legal property of its developers.
 * Please see the AUTHORS file distributed alongside this file.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02111-1301  USA
*/

/**
 * This file implements AIM's clientLogin procedure for authenticating
 * users.  This replaces the older MD5-based and XOR-based
 * authentication methods that use SNAC family 0x0017.
 *
 * This doesn't use SNACs or FLAPs at all.  It makes http and https
 * POSTs to AOL to validate the user based on the password they
 * provided to us.  Upon successful authentication we request a
 * connection to the BOS server by calling startOSCARsession.  The
 * AOL server gives us the hostname and port number to use, as well
 * as the cookie to use to authenticate to the BOS server.  And then
 * everything else is the same as with BUCP.
 *
 * For details, see:
 * http://dev.aol.com/aim/oscar/#AUTH
 * http://dev.aol.com/authentication_for_clients
 */

#include "oscar.h"
#include "oscarcommon.h"

#include "cipher.h"
#include "core.h"

#define AIM_LOGIN_HOST "api.screenname.aol.com"
#define ICQ_LOGIN_HOST "api.login.icq.net"

#define AIM_API_HOST "api.oscar.aol.com"
#define ICQ_API_HOST "api.icq.net"

#define CLIENT_LOGIN_PAGE "/auth/clientLogin"
#define START_OSCAR_SESSION_PAGE "/aim/startOSCARSession"

#define HTTPS_FORMAT_URL(host, page) "https://" host page

static const gchar *client_login_urls[] = {
	HTTPS_FORMAT_URL(AIM_LOGIN_HOST, CLIENT_LOGIN_PAGE),
	HTTPS_FORMAT_URL(ICQ_LOGIN_HOST, CLIENT_LOGIN_PAGE),
};

static const gchar *start_oscar_session_urls[] = {
	HTTPS_FORMAT_URL(AIM_API_HOST, START_OSCAR_SESSION_PAGE),
	HTTPS_FORMAT_URL(ICQ_API_HOST, START_OSCAR_SESSION_PAGE),
};

static const gchar *get_client_login_url(OscarData *od)
{
	return client_login_urls[od->icq ? 1 : 0];
}

static const gchar *get_start_oscar_session_url(OscarData *od)
{
	return start_oscar_session_urls[od->icq ? 1 : 0];
}

/*
 * Using clientLogin requires a developer ID.  This key is for libpurple.
 * It is the default key for all libpurple-based clients.  AOL encourages
 * UIs (especially ones with lots of users) to override this with their
 * own key.  This key is owned by the AIM account "markdoliner"
 *
 * Keys can be managed at http://developer.aim.com/manageKeys.jsp
 */
#define DEFAULT_CLIENT_KEY "ma15d7JTxbmVG-RP"

static const char *get_client_key(OscarData *od)
{
	return oscar_get_ui_info_string(
			od->icq ? "prpl-icq-clientkey" : "prpl-aim-clientkey",
			DEFAULT_CLIENT_KEY);
}

static gchar *generate_error_message(xmlnode *resp, const char *url)
{
	xmlnode *text;
	xmlnode *status_code_node;
	gchar *status_code;
	gboolean have_error_code = TRUE;
	gchar *err = NULL;
	gchar *details = NULL;

	status_code_node = xmlnode_get_child(resp, "statusCode");
	if (status_code_node) {
		/* We can get 200 OK here if the server omitted something we think it shouldn't have (see #12783).
		 * No point in showing the "Ok" string to the user.
		 */
		if ((status_code = xmlnode_get_data_unescaped(status_code_node)) && strcmp(status_code, "200") == 0) {
			have_error_code = FALSE;
		}
	}
	if (have_error_code && resp && (text = xmlnode_get_child(resp, "statusText"))) {
		details = xmlnode_get_data(text);
	}

	if (details && *details) {
		err = g_strdup_printf(_("Received unexpected response from %s: %s"), url, details);
	} else {
		err = g_strdup_printf(_("Received unexpected response from %s"), url);
	}

	g_free(details);
	return err;
}

/**
 * @return A null-terminated base64 encoded version of the HMAC
 *         calculated using the given key and data.
 */
static gchar *hmac_sha256(const char *key, const char *message)
{
	PurpleCipherContext *context;
	guchar digest[32];

	context = purple_cipher_context_new_by_name("hmac", NULL);
	purple_cipher_context_set_option(context, "hash", "sha256");
	purple_cipher_context_set_key(context, (guchar *)key);
	purple_cipher_context_append(context, (guchar *)message, strlen(message));
	purple_cipher_context_digest(context, sizeof(digest), digest, NULL);
	purple_cipher_context_destroy(context);

	return purple_base64_encode(digest, sizeof(digest));
}

/**
 * @return A base-64 encoded HMAC-SHA256 signature created using the
 *         technique documented at
 *         http://dev.aol.com/authentication_for_clients#signing
 */
static gchar *generate_signature(const char *method, const char *url, const char *parameters, const char *session_key)
{
	char *encoded_url, *signature_base_string, *signature;
	const char *encoded_parameters;

	encoded_url = g_strdup(purple_url_encode(url));
	encoded_parameters = purple_url_encode(parameters);
	signature_base_string = g_strdup_printf("%s&%s&%s",
			method, encoded_url, encoded_parameters);
	g_free(encoded_url);

	signature = hmac_sha256(session_key, signature_base_string);
	g_free(signature_base_string);

	return signature;
}

static gboolean parse_start_oscar_session_response(PurpleConnection *gc, const gchar *response, gsize response_len, char **host, unsigned short *port, char **cookie, char **tls_certname)
{
	OscarData *od = purple_connection_get_protocol_data(gc);
	xmlnode *response_node, *tmp_node, *data_node;
	xmlnode *host_node = NULL, *port_node = NULL, *cookie_node = NULL, *tls_node = NULL;
	char *tmp;
	guint code;
	const gchar *encryption_type = purple_account_get_string(purple_connection_get_account(gc), "encryption", OSCAR_DEFAULT_ENCRYPTION);

	/* Parse the response as XML */
	response_node = xmlnode_from_str(response, response_len);
	if (response_node == NULL)
	{
		char *msg;
		purple_debug_error("oscar", "startOSCARSession could not parse "
				"response as XML: %s\n", response);
		/* Note to translators: %s in this string is a URL */
		msg = generate_error_message(response_node,
				get_start_oscar_session_url(od));
		purple_connection_error_reason(gc,
				PURPLE_CONNECTION_ERROR_NETWORK_ERROR, msg);
		g_free(msg);
		return FALSE;
	}

	/* Grab the necessary XML nodes */
	tmp_node = xmlnode_get_child(response_node, "statusCode");
	data_node = xmlnode_get_child(response_node, "data");
	if (data_node != NULL) {
		host_node = xmlnode_get_child(data_node, "host");
		port_node = xmlnode_get_child(data_node, "port");
		cookie_node = xmlnode_get_child(data_node, "cookie");
	}

	/* Make sure we have a status code */
	if (tmp_node == NULL || (tmp = xmlnode_get_data_unescaped(tmp_node)) == NULL) {
		char *msg;
		purple_debug_error("oscar", "startOSCARSession response was "
				"missing statusCode: %s\n", response);
		msg = generate_error_message(response_node,
				get_start_oscar_session_url(od));
		purple_connection_error_reason(gc,
				PURPLE_CONNECTION_ERROR_NETWORK_ERROR, msg);
		g_free(msg);
		xmlnode_free(response_node);
		return FALSE;
	}

	/* Make sure the status code was 200 */
	code = atoi(tmp);
	if (code != 200)
	{
		xmlnode *status_detail_node;
		guint status_detail = 0;

		status_detail_node = xmlnode_get_child(response_node,
		                                       "statusDetailCode");
		if (status_detail_node) {
			gchar *data = xmlnode_get_data(status_detail_node);
			if (data) {
				status_detail = atoi(data);
				g_free(data);
			}
		}

		purple_debug_error("oscar", "startOSCARSession response statusCode "
				"was %s: %s\n", tmp, response);

		if ((code == 401 && status_detail != 1014) || code == 607)
			purple_connection_error_reason(gc,
					PURPLE_CONNECTION_ERROR_OTHER_ERROR,
					_("You have been connecting and disconnecting too "
					  "frequently. Wait ten minutes and try again. If "
					  "you continue to try, you will need to wait even "
					  "longer."));
		else {
			char *msg;
			msg = generate_error_message(response_node,
					get_start_oscar_session_url(od));
			purple_connection_error_reason(gc,
					PURPLE_CONNECTION_ERROR_OTHER_ERROR, msg);
			g_free(msg);
		}

		g_free(tmp);
		xmlnode_free(response_node);
		return FALSE;
	}
	g_free(tmp);

	/* Make sure we have everything else */
	if (data_node == NULL || host_node == NULL || port_node == NULL || cookie_node == NULL)
	{
		char *msg;
		purple_debug_error("oscar", "startOSCARSession response was missing "
				"something: %s\n", response);
		msg = generate_error_message(response_node,
				get_start_oscar_session_url(od));
		purple_connection_error_reason(gc,
				PURPLE_CONNECTION_ERROR_NETWORK_ERROR, msg);
		g_free(msg);
		xmlnode_free(response_node);
		return FALSE;
	}

	if (strcmp(encryption_type, OSCAR_NO_ENCRYPTION) != 0) {
		tls_node = xmlnode_get_child(data_node, "tlsCertName");
		if (tls_node != NULL) {
			*tls_certname = xmlnode_get_data_unescaped(tls_node);
		} else {
			if (strcmp(encryption_type, OSCAR_OPPORTUNISTIC_ENCRYPTION) == 0) {
				purple_debug_warning("oscar", "We haven't received a tlsCertName to use. We will not do SSL to BOS.\n");
			} else {
				purple_debug_error("oscar", "startOSCARSession was missing tlsCertName: %s\n", response);
				purple_connection_error_reason(
					gc,
					PURPLE_CONNECTION_ERROR_NO_SSL_SUPPORT,
					_("You required encryption in your account settings, but one of the servers doesn't support it."));
				xmlnode_free(response_node);
				return FALSE;
			}
		}
	}

	/* Extract data from the XML */
	*host = xmlnode_get_data_unescaped(host_node);
	tmp = xmlnode_get_data_unescaped(port_node);
	*cookie = xmlnode_get_data_unescaped(cookie_node);

	if (*host == NULL || **host == '\0' || tmp == NULL || *tmp == '\0' || *cookie == NULL || **cookie == '\0')
	{
		char *msg;
		purple_debug_error("oscar", "startOSCARSession response was missing "
				"something: %s\n", response);
		msg = generate_error_message(response_node,
				get_start_oscar_session_url(od));
		purple_connection_error_reason(gc,
				PURPLE_CONNECTION_ERROR_NETWORK_ERROR, msg);
		g_free(msg);
		g_free(*host);
		g_free(tmp);
		g_free(*cookie);
		xmlnode_free(response_node);
		return FALSE;
	}

	*port = atoi(tmp);
	g_free(tmp);

	return TRUE;
}

static void start_oscar_session_cb(PurpleUtilFetchUrlData *url_data, gpointer user_data, const gchar *url_text, gsize len, const gchar *error_message)
{
	OscarData *od;
	PurpleConnection *gc;
	char *host, *cookie;
	char *tls_certname = NULL;
	unsigned short port;
	guint8 *cookiedata;
	gsize cookiedata_len = 0;

	od = user_data;
	gc = od->gc;

	od->url_data = NULL;

	if (error_message != NULL || len == 0) {
		gchar *tmp;
		/* Note to translators: The first %s is a URL, the second is an
		   error message. */
		tmp = g_strdup_printf(_("Error requesting %s: %s"),
				get_start_oscar_session_url(od), error_message ?
				error_message : _("The server returned an empty response"));
		purple_connection_error_reason(gc,
				PURPLE_CONNECTION_ERROR_NETWORK_ERROR, tmp);
		g_free(tmp);
		return;
	}

	if (!parse_start_oscar_session_response(gc, url_text, len, &host, &port, &cookie, &tls_certname))
		return;

	cookiedata = purple_base64_decode(cookie, &cookiedata_len);
	oscar_connect_to_bos(gc, od, host, port, cookiedata, cookiedata_len, tls_certname);
	g_free(cookiedata);

	g_free(host);
	g_free(cookie);
	g_free(tls_certname);
}

static void send_start_oscar_session(OscarData *od, const char *token, const char *session_key, time_t hosttime)
{
	char *query_string, *signature, *url;
	PurpleAccount *account = purple_connection_get_account(od->gc);
	const gchar *encryption_type = purple_account_get_string(account, "encryption", OSCAR_DEFAULT_ENCRYPTION);

	/*
	 * Construct the GET parameters.  0x00000611 is the distid given to
	 * us by AOL for use as the default libpurple distid.
	 */
	query_string = g_strdup_printf("a=%s"
			"&distId=%d"
			"&f=xml"
			"&k=%s"
			"&ts=%" PURPLE_TIME_T_MODIFIER
			"&useTLS=%d",
			purple_url_encode(token),
			oscar_get_ui_info_int(od->icq ? "prpl-icq-distid" : "prpl-aim-distid", 0x00000611),
			get_client_key(od),
			hosttime,
			strcmp(encryption_type, OSCAR_NO_ENCRYPTION) != 0 ? 1 : 0);
	signature = generate_signature("GET", get_start_oscar_session_url(od),
			query_string, session_key);
	url = g_strdup_printf("%s?%s&sig_sha256=%s", get_start_oscar_session_url(od),
			query_string, signature);
	g_free(query_string);
	g_free(signature);

	/* Make the request */
	od->url_data = purple_util_fetch_url_request_len_with_account(account,
			url, TRUE, NULL, FALSE, NULL, FALSE, -1,
			start_oscar_session_cb, od);
	g_free(url);
}

/**
 * This function parses the given response from a clientLogin request
 * and extracts the useful information.
 *
 * @param gc           The PurpleConnection.  If the response data does
 *                     not indicate then purple_connection_error_reason()
 *                     will be called to close this connection.
 * @param response     The response data from the clientLogin request.
 * @param response_len The length of the above response, or -1 if
 *                     @response is NUL terminated.
 * @param token        If parsing was successful then this will be set to
 *                     a newly allocated string containing the token.  The
 *                     caller should g_free this string when it is finished
 *                     with it.  On failure this value will be untouched.
 * @param secret       If parsing was successful then this will be set to
 *                     a newly allocated string containing the secret.  The
 *                     caller should g_free this string when it is finished
 *                     with it.  On failure this value will be untouched.
 * @param hosttime     If parsing was successful then this will be set to
 *                     the time on the OpenAuth Server in seconds since the
 *                     Unix epoch.  On failure this value will be untouched.
 *
 * @return TRUE if the request was successful and we were able to
 *         extract all info we need.  Otherwise FALSE.
 */
static gboolean parse_client_login_response(PurpleConnection *gc, const gchar *response, gsize response_len, char **token, char **secret, time_t *hosttime)
{
	OscarData *od = purple_connection_get_protocol_data(gc);
	xmlnode *response_node, *tmp_node, *data_node;
	xmlnode *secret_node = NULL, *hosttime_node = NULL, *token_node = NULL, *tokena_node = NULL;
	char *tmp;

	/* Parse the response as XML */
	response_node = xmlnode_from_str(response, response_len);
	if (response_node == NULL)
	{
		char *msg;
		purple_debug_error("oscar", "clientLogin could not parse "
				"response as XML: %s\n", response);
		msg = generate_error_message(response_node,
				get_client_login_url(od));
		purple_connection_error_reason(gc,
				PURPLE_CONNECTION_ERROR_NETWORK_ERROR, msg);
		g_free(msg);
		return FALSE;
	}

	/* Grab the necessary XML nodes */
	tmp_node = xmlnode_get_child(response_node, "statusCode");
	data_node = xmlnode_get_child(response_node, "data");
	if (data_node != NULL) {
		secret_node = xmlnode_get_child(data_node, "sessionSecret");
		hosttime_node = xmlnode_get_child(data_node, "hostTime");
		token_node = xmlnode_get_child(data_node, "token");
		if (token_node != NULL)
			tokena_node = xmlnode_get_child(token_node, "a");
	}

	/* Make sure we have a status code */
	if (tmp_node == NULL || (tmp = xmlnode_get_data_unescaped(tmp_node)) == NULL) {
		char *msg;
		purple_debug_error("oscar", "clientLogin response was "
				"missing statusCode: %s\n", response);
		msg = generate_error_message(response_node,
				get_client_login_url(od));
		purple_connection_error_reason(gc,
				PURPLE_CONNECTION_ERROR_NETWORK_ERROR, msg);
		g_free(msg);
		xmlnode_free(response_node);
		return FALSE;
	}

	/* Make sure the status code was 200 */
	if (strcmp(tmp, "200") != 0)
	{
		int status_code, status_detail_code = 0;

		status_code = atoi(tmp);
		g_free(tmp);
		tmp_node = xmlnode_get_child(response_node, "statusDetailCode");
		if (tmp_node != NULL && (tmp = xmlnode_get_data_unescaped(tmp_node)) != NULL) {
			status_detail_code = atoi(tmp);
			g_free(tmp);
		}

		purple_debug_error("oscar", "clientLogin response statusCode "
				"was %d (%d): %s\n", status_code, status_detail_code, response);

		if (status_code == 330 && status_detail_code == 3011) {
			PurpleAccount *account = purple_connection_get_account(gc);
			if (!purple_account_get_remember_password(account))
				purple_account_set_password(account, NULL);
			purple_connection_error_reason(gc,
					PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED,
					_("Incorrect password"));
		} else if (status_code == 330 && status_detail_code == 3015) {
			purple_connection_error_reason(gc,
					PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED,
					_("Server requested that you fill out a CAPTCHA in order to "
					"sign in, but this client does not currently support CAPTCHAs."));
		} else if (status_code == 401 && status_detail_code == 3019) {
			purple_connection_error_reason(gc,
					PURPLE_CONNECTION_ERROR_OTHER_ERROR,
					_("AOL does not allow your screen name to authenticate here"));
		} else {
			char *msg;
			msg = generate_error_message(response_node,
					get_client_login_url(od));
			purple_connection_error_reason(gc,
					PURPLE_CONNECTION_ERROR_OTHER_ERROR, msg);
			g_free(msg);
		}

		xmlnode_free(response_node);
		return FALSE;
	}
	g_free(tmp);

	/* Make sure we have everything else */
	if (data_node == NULL || secret_node == NULL ||
		token_node == NULL || tokena_node == NULL)
	{
		char *msg;
		purple_debug_error("oscar", "clientLogin response was missing "
				"something: %s\n", response);
		msg = generate_error_message(response_node,
				get_client_login_url(od));
		purple_connection_error_reason(gc,
				PURPLE_CONNECTION_ERROR_NETWORK_ERROR, msg);
		g_free(msg);
		xmlnode_free(response_node);
		return FALSE;
	}

	/* Extract data from the XML */
	*token = xmlnode_get_data_unescaped(tokena_node);
	*secret = xmlnode_get_data_unescaped(secret_node);
	tmp = xmlnode_get_data_unescaped(hosttime_node);
	if (*token == NULL || **token == '\0' || *secret == NULL || **secret == '\0' || tmp == NULL || *tmp == '\0')
	{
		char *msg;
		purple_debug_error("oscar", "clientLogin response was missing "
				"something: %s\n", response);
		msg = generate_error_message(response_node,
				get_client_login_url(od));
		purple_connection_error_reason(gc,
				PURPLE_CONNECTION_ERROR_NETWORK_ERROR, msg);
		g_free(msg);
		g_free(*token);
		g_free(*secret);
		g_free(tmp);
		xmlnode_free(response_node);
		return FALSE;
	}

	*hosttime = strtol(tmp, NULL, 10);
	g_free(tmp);

	xmlnode_free(response_node);

	return TRUE;
}

static void client_login_cb(PurpleUtilFetchUrlData *url_data, gpointer user_data, const gchar *url_text, gsize len, const gchar *error_message)
{
	OscarData *od;
	PurpleConnection *gc;
	char *token, *secret, *session_key;
	time_t hosttime;
	int password_len;
	char *password;

	od = user_data;
	gc = od->gc;

	od->url_data = NULL;

	if (error_message != NULL || len == 0) {
		gchar *tmp;
		tmp = g_strdup_printf(_("Error requesting %s: %s"),
				get_client_login_url(od), error_message ?
				error_message : _("The server returned an empty response"));
		purple_connection_error_reason(gc,
				PURPLE_CONNECTION_ERROR_NETWORK_ERROR, tmp);
		g_free(tmp);
		return;
	}

	if (!parse_client_login_response(gc, url_text, len, &token, &secret, &hosttime))
		return;

	password_len = strlen(purple_connection_get_password(gc));
	password = g_strdup_printf("%.*s",
			od->icq ? MIN(password_len, MAXICQPASSLEN) : password_len,
			purple_connection_get_password(gc));
	session_key = hmac_sha256(password, secret);
	g_free(password);
	g_free(secret);

	send_start_oscar_session(od, token, session_key, hosttime);

	g_free(token);
	g_free(session_key);
}

/**
 * This function sends a request to
 * https://api.screenname.aol.com/auth/clientLogin with the user's
 * username and password and receives the user's session key, which is
 * used to request a connection to the BOSS server.
 */
void send_client_login(OscarData *od, const char *username)
{
	PurpleConnection *gc;
	GString *request, *body;
	const char *tmp;
	char *password;
	int password_len;

	gc = od->gc;

	/*
	 * We truncate ICQ passwords to 8 characters.  There is probably a
	 * limit for AIM passwords, too, but we really only need to do
	 * this for ICQ because older ICQ clients let you enter a password
	 * as long as you wanted and then they truncated it silently.
	 *
	 * And we can truncate based on the number of bytes and not the
	 * number of characters because passwords for AIM and ICQ are
	 * supposed to be plain ASCII (I don't know if this has always been
	 * the case, though).
	 */
	tmp = purple_connection_get_password(gc);
	password_len = strlen(tmp);
	password = g_strndup(tmp, od->icq ? MIN(password_len, MAXICQPASSLEN) : password_len);

	/* Construct the body of the HTTP POST request */
	body = g_string_new("");
	g_string_append_printf(body, "devId=%s", get_client_key(od));
	g_string_append_printf(body, "&f=xml");
	g_string_append_printf(body, "&pwd=%s", purple_url_encode(password));
	g_string_append_printf(body, "&s=%s", purple_url_encode(username));
	g_free(password);

	/* Construct an HTTP POST request */
	request = g_string_new("POST /auth/clientLogin HTTP/1.0\r\n"
			"Connection: close\r\n"
			"Accept: */*\r\n");

	/* Tack on the body */
	g_string_append_printf(request, "Content-Type: application/x-www-form-urlencoded; charset=UTF-8\r\n");
	g_string_append_printf(request, "Content-Length: %" G_GSIZE_FORMAT "\r\n\r\n", body->len);
	g_string_append_len(request, body->str, body->len);
	g_string_free(body, TRUE);

	/* Send the POST request  */
	od->url_data = purple_util_fetch_url_request_len_with_account(
			purple_connection_get_account(gc), get_client_login_url(od),
			TRUE, NULL, FALSE, request->str, FALSE, -1,
			client_login_cb, od);
	g_string_free(request, TRUE);
}
