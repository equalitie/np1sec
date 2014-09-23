/**
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
#include "debug.h"

#include "relay.h"

typedef struct {
	GoogleSession *session;
	JabberGoogleRelayCallback *cb;
} JabberGoogleRelayCallbackData;

static void
jabber_google_relay_parse_response(const gchar *response, gchar **ip,
	guint *udp, guint *tcp, guint *ssltcp, gchar **username, gchar **password)
{
	gchar **lines = g_strsplit(response, "\n", -1);
	int i = 0;

	for (; lines[i] ; i++) {
		gchar *line = lines[i];
		gchar **parts = g_strsplit(line, "=", 2);

		if (parts[0] && parts[1]) {
			if (purple_strequal(parts[0], "relay.ip")) {
				*ip = g_strdup(parts[1]);
			} else if (purple_strequal(parts[0], "relay.udp_port")) {
				*udp = atoi(parts[1]);
			} else if (purple_strequal(parts[0], "relay.tcp_port")) {
				*tcp = atoi(parts[1]);
			} else if (purple_strequal(parts[0], "relay.ssltcp_port")) {
				*ssltcp = atoi(parts[1]);
			} else if (purple_strequal(parts[0], "username")) {
				*username = g_strdup(parts[1]);
			} else if (purple_strequal(parts[0], "password")) {
				*password = g_strdup(parts[1]);
			}
		}
		g_strfreev(parts);
	}

	g_strfreev(lines);
}

static void
jabber_google_relay_remove_url_data(JabberStream *js,
	PurpleUtilFetchUrlData *url_data)
{
	GList *iter = js->google_relay_requests;

	while (iter) {
		if (iter->data == url_data) {
			js->google_relay_requests =
				g_list_delete_link(js->google_relay_requests, iter);
			break;
		}
	}
}

static void
jabber_google_relay_fetch_cb(PurpleUtilFetchUrlData *url_data,
	gpointer user_data, const gchar *url_text, gsize len,
	const gchar *error_message)
{
	JabberGoogleRelayCallbackData *data =
		(JabberGoogleRelayCallbackData *) user_data;
	GoogleSession *session = data->session;
	JabberStream *js = session->js;
	JabberGoogleRelayCallback *cb = data->cb;
	gchar *relay_ip = NULL;
	guint relay_udp = 0;
	guint relay_tcp = 0;
	guint relay_ssltcp = 0;
	gchar *relay_username = NULL;
	gchar *relay_password = NULL;

	g_free(data);

	if (url_data) {
		jabber_google_relay_remove_url_data(js, url_data);
	}

	purple_debug_info("jabber", "got response on HTTP request to relay server\n");

	if (url_text && len > 0) {
		purple_debug_info("jabber", "got Google relay request response:\n%s\n",
			url_text);
		jabber_google_relay_parse_response(url_text, &relay_ip, &relay_udp,
			&relay_tcp, &relay_ssltcp, &relay_username, &relay_password);
	}

	if (cb)
		cb(session, relay_ip, relay_udp, relay_tcp, relay_ssltcp,
		   relay_username, relay_password);

	g_free(relay_ip);
	g_free(relay_username);
	g_free(relay_password);
}

void
jabber_google_do_relay_request(JabberStream *js, GoogleSession *session,
	JabberGoogleRelayCallback cb)
{
	PurpleUtilFetchUrlData *url_data = NULL;
	gchar *url = g_strdup_printf("http://%s", js->google_relay_host);
	/* yes, the relay token is included twice as different request headers,
	   this is apparently needed to make Google's relay servers work... */
	gchar *request =
		g_strdup_printf("GET /create_session HTTP/1.0\r\n"
			            "Host: %s\r\n"
						"X-Talk-Google-Relay-Auth: %s\r\n"
						"X-Google-Relay-Auth: %s\r\n\r\n",
			js->google_relay_host, js->google_relay_token, js->google_relay_token);
	JabberGoogleRelayCallbackData *data = g_new0(JabberGoogleRelayCallbackData, 1);

	data->session = session;
	data->cb = cb;
	purple_debug_info("jabber",
		"sending Google relay request %s to %s\n", request, url);
	url_data =
		purple_util_fetch_url_request(url, FALSE, NULL, FALSE, request, FALSE,
			jabber_google_relay_fetch_cb, data);
	if (url_data) {
		js->google_relay_requests =
			g_list_prepend(js->google_relay_requests, url_data);
	} else {
		purple_debug_error("jabber", "unable to create Google relay request\n");
		jabber_google_relay_fetch_cb(NULL, data, NULL, 0, NULL);
	}
	g_free(url);
	g_free(request);
}