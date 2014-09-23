/**
 * @file soap.c
 * Functions relating to SOAP connections.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,  USA
 */

#include "internal.h"

#include "soap.h"

#include "session.h"

#include "debug.h"
#include "xmlnode.h"

#include <glib.h>
#if !defined(_WIN32) || !defined(_WINERROR_)
#include <error.h>
#endif

#define SOAP_TIMEOUT (5 * 60)

typedef struct _MsnSoapRequest {
	char *path;
	MsnSoapMessage *message;
	gboolean secure;
	MsnSoapCallback cb;
	gpointer cb_data;
} MsnSoapRequest;

typedef struct _MsnSoapConnection {
	MsnSession *session;
	char *host;

	time_t last_used;
	PurpleSslConnection *ssl;
	gboolean connected;

	guint event_handle;
	guint run_timer;
	GString *buf;
	gsize handled_len;
	gsize body_len;
	int response_code;
	gboolean headers_done;
	gboolean close_when_done;

	MsnSoapMessage *message;

	GQueue *queue;
	MsnSoapRequest *current_request;
} MsnSoapConnection;

static gboolean msn_soap_connection_run(gpointer data);

static MsnSoapConnection *
msn_soap_connection_new(MsnSession *session, const char *host)
{
	MsnSoapConnection *conn = g_new0(MsnSoapConnection, 1);
	conn->session = session;
	conn->host = g_strdup(host);
	conn->queue = g_queue_new();
	return conn;
}

static void
msn_soap_message_destroy(MsnSoapMessage *message)
{
	g_slist_foreach(message->headers, (GFunc)g_free, NULL);
	g_slist_free(message->headers);
	g_free(message->action);
	if (message->xml)
		xmlnode_free(message->xml);
	g_free(message);
}

static void
msn_soap_request_destroy(MsnSoapRequest *req, gboolean keep_message)
{
	g_free(req->path);
	if (!keep_message)
		msn_soap_message_destroy(req->message);
	g_free(req);
}

static void
msn_soap_connection_sanitize(MsnSoapConnection *conn, gboolean disconnect)
{
	if (conn->event_handle) {
		purple_input_remove(conn->event_handle);
		conn->event_handle = 0;
	}

	if (conn->run_timer) {
		purple_timeout_remove(conn->run_timer);
		conn->run_timer = 0;
	}

	if (conn->message) {
		msn_soap_message_destroy(conn->message);
		conn->message = NULL;
	}

	if (conn->buf) {
		g_string_free(conn->buf, TRUE);
		conn->buf = NULL;
	}

	if (conn->ssl && (disconnect || conn->close_when_done)) {
		purple_ssl_close(conn->ssl);
		conn->ssl = NULL;
	}

	if (conn->current_request) {
		msn_soap_request_destroy(conn->current_request, FALSE);
		conn->current_request = NULL;
	}
}

static void
msn_soap_connection_destroy_foreach_cb(gpointer item, gpointer data)
{
	MsnSoapRequest *req = item;

	req->cb(req->message, NULL, req->cb_data);

	msn_soap_request_destroy(req, FALSE);
}

static void
msn_soap_connection_destroy(MsnSoapConnection *conn)
{
	if (conn->current_request) {
		MsnSoapRequest *req = conn->current_request;
		conn->current_request = NULL;
		msn_soap_connection_destroy_foreach_cb(req, conn);
	}

	msn_soap_connection_sanitize(conn, TRUE);
	g_queue_foreach(conn->queue, msn_soap_connection_destroy_foreach_cb, conn);
	g_queue_free(conn->queue);

	g_free(conn->host);
	g_free(conn);
}

static gboolean
msn_soap_cleanup_each(gpointer key, gpointer value, gpointer data)
{
	MsnSoapConnection *conn = value;
	time_t *t = data;

	if ((*t - conn->last_used) > SOAP_TIMEOUT * 2) {
		purple_debug_info("soap", "cleaning up soap conn %p\n", conn);
		return TRUE;
	}

	return FALSE;
}

static gboolean
msn_soap_cleanup_for_session(gpointer data)
{
	MsnSession *sess = data;
	time_t t = time(NULL);

	purple_debug_info("soap", "session cleanup timeout\n");

	if (sess->soap_table) {
		g_hash_table_foreach_remove(sess->soap_table, msn_soap_cleanup_each,
			&t);

		if (g_hash_table_size(sess->soap_table) != 0)
			return TRUE;
	}

	sess->soap_cleanup_handle = 0;
	return FALSE;
}

static MsnSoapConnection *
msn_soap_get_connection(MsnSession *session, const char *host)
{
	MsnSoapConnection *conn = NULL;

	if (session->soap_table) {
		conn = g_hash_table_lookup(session->soap_table, host);
	} else {
		session->soap_table = g_hash_table_new_full(g_str_hash, g_str_equal,
			NULL, (GDestroyNotify)msn_soap_connection_destroy);
	}

	if (session->soap_cleanup_handle == 0)
		session->soap_cleanup_handle = purple_timeout_add_seconds(SOAP_TIMEOUT,
			msn_soap_cleanup_for_session, session);

	if (conn == NULL) {
		conn = msn_soap_connection_new(session, host);
		g_hash_table_insert(session->soap_table, conn->host, conn);
	}

	conn->last_used = time(NULL);

	return conn;
}

static void
msn_soap_connection_handle_next(MsnSoapConnection *conn)
{
	msn_soap_connection_sanitize(conn, FALSE);

	conn->run_timer = purple_timeout_add(0, msn_soap_connection_run, conn);
}

static void
msn_soap_message_send_internal(MsnSession *session, MsnSoapMessage *message,
	const char *host, const char *path, gboolean secure,
	MsnSoapCallback cb, gpointer cb_data, gboolean first)
{
	MsnSoapConnection *conn = msn_soap_get_connection(session, host);
	MsnSoapRequest *req = g_new0(MsnSoapRequest, 1);

	req->path = g_strdup(path);
	req->message = message;
	req->secure = secure;
	req->cb = cb;
	req->cb_data = cb_data;

	if (first) {
		g_queue_push_head(conn->queue, req);
	} else {
		g_queue_push_tail(conn->queue, req);
	}

	if (conn->run_timer == 0)
		conn->run_timer = purple_timeout_add(0, msn_soap_connection_run,
			conn);
}

void
msn_soap_message_send(MsnSession *session, MsnSoapMessage *message,
	const char *host, const char *path, gboolean secure,
	MsnSoapCallback cb, gpointer cb_data)
{
	g_return_if_fail(message != NULL);
	g_return_if_fail(cb != NULL);

	msn_soap_message_send_internal(session, message, host, path, secure,
		cb, cb_data, FALSE);
}

static gboolean
msn_soap_handle_redirect(MsnSoapConnection *conn, const char *url)
{
	char *host;
	char *path;

	if (purple_url_parse(url, &host, NULL, &path, NULL, NULL)) {
		MsnSoapRequest *req = conn->current_request;
		conn->current_request = NULL;

		msn_soap_message_send_internal(conn->session, req->message, host, path,
			req->secure, req->cb, req->cb_data, TRUE);

		msn_soap_request_destroy(req, TRUE);

		g_free(host);
		g_free(path);

		return TRUE;
	}

	return FALSE;
}

static gboolean
msn_soap_handle_body(MsnSoapConnection *conn, MsnSoapMessage *response)
{
	xmlnode *body = xmlnode_get_child(response->xml, "Body");
	xmlnode *fault = xmlnode_get_child(response->xml, "Fault");

	if (fault) {
		xmlnode *faultcode = xmlnode_get_child(fault, "faultcode");

		if (faultcode != NULL) {
			char *faultdata = xmlnode_get_data(faultcode);

			if (faultdata && g_str_equal(faultdata, "psf:Redirect")) {
				xmlnode *url = xmlnode_get_child(fault, "redirectUrl");

				if (url) {
					char *urldata = xmlnode_get_data(url);
					if (urldata)
						msn_soap_handle_redirect(conn, urldata);
					g_free(urldata);
				}

				g_free(faultdata);
				msn_soap_message_destroy(response);
				return TRUE;
			} else if (faultdata && g_str_equal(faultdata, "wsse:FailedAuthentication")) {
				xmlnode *reason = xmlnode_get_child(fault, "faultstring");
				char *reasondata = NULL;

				if (reason)
					reasondata = xmlnode_get_data(reason);

				msn_soap_connection_sanitize(conn, TRUE);
				msn_session_set_error(conn->session, MSN_ERROR_AUTH,
					reasondata);

				g_free(reasondata);
				g_free(faultdata);
				msn_soap_message_destroy(response);
				return FALSE;
			}

			g_free(faultdata);
		}
	}

	if (fault || body) {
		if (conn->current_request) {
			MsnSoapRequest *request = conn->current_request;
			conn->current_request = NULL;
			request->cb(request->message, response,
				request->cb_data);
			msn_soap_request_destroy(request, FALSE);
		}
		msn_soap_message_destroy(response);
	}

	return TRUE;
}

static void
msn_soap_message_add_header(MsnSoapMessage *message,
		const char *name, const char *value)
{
	char *header = g_strdup_printf("%s: %s\r\n", name, value);

	message->headers = g_slist_prepend(message->headers, header);
}

static void
msn_soap_process(MsnSoapConnection *conn)
{
	gboolean handled = FALSE;
	char *cursor;
	char *linebreak;

	cursor = conn->buf->str + conn->handled_len;

	if (!conn->headers_done) {
		while ((linebreak = strstr(cursor, "\r\n"))	!= NULL) {
			conn->handled_len = linebreak - conn->buf->str + 2;

			if (conn->response_code == 0) {
				if (sscanf(cursor, "HTTP/1.1 %d", &conn->response_code) != 1) {
					/* something horribly wrong */
					purple_ssl_close(conn->ssl);
					conn->ssl = NULL;
					handled = TRUE;
					break;
				} else if (conn->response_code == 503 && conn->session->login_step < MSN_LOGIN_STEP_END) {
					msn_soap_connection_sanitize(conn, TRUE);
					msn_session_set_error(conn->session, MSN_ERROR_SERV_UNAVAILABLE, NULL);
					return;
				}
			} else if (cursor == linebreak) {
				/* blank line */
				conn->headers_done = TRUE;
				cursor = conn->buf->str + conn->handled_len;
				break;
			} else {
				char *line = g_strndup(cursor, linebreak - cursor);
				char *sep = strstr(line, ": ");
				char *key = line;
				char *value;

				if (sep == NULL) {
					purple_debug_info("soap", "ignoring malformed line: %s\n", line);
					g_free(line);
					goto loop_end;
				}

				value = sep + 2;
				*sep = '\0';
				msn_soap_message_add_header(conn->message, key, value);

				if ((conn->response_code == 301 || conn->response_code == 300)
					&& strcmp(key, "Location") == 0) {

					msn_soap_handle_redirect(conn, value);

					handled = TRUE;
					g_free(line);
					break;
				} else if (conn->response_code == 401 &&
					strcmp(key, "WWW-Authenticate") == 0) {
					char *error = strstr(value, "cbtxt=");

					if (error) {
						error += strlen("cbtxt=");
					}

					msn_soap_connection_sanitize(conn, TRUE);
					msn_session_set_error(conn->session, MSN_ERROR_AUTH,
						error ? purple_url_decode(error) : NULL);

					g_free(line);
					return;
				} else if (strcmp(key, "Content-Length") == 0) {
					if (sscanf(value, "%" G_GSIZE_FORMAT, &(conn->body_len)) != 1)
						purple_debug_error("soap", "Unable to parse Content-Length\n");
				} else if (strcmp(key, "Connection") == 0) {
					if (strcmp(value, "close") == 0) {
						conn->close_when_done = TRUE;
					}
				}
				g_free(line);
			}

		loop_end:
			cursor = conn->buf->str + conn->handled_len;
		}
	}

	if (!handled && conn->headers_done) {
		if (conn->buf->len - conn->handled_len >=
			conn->body_len) {
			xmlnode *node = xmlnode_from_str(cursor, conn->body_len);

			if (node == NULL) {
				purple_debug_info("soap", "Malformed SOAP response: %s\n",
					cursor);
			} else {
				MsnSoapMessage *message = conn->message;
				conn->message = NULL;
				message->xml = node;

				if (!msn_soap_handle_body(conn, message)) {
					return;
				}
			}

			msn_soap_connection_handle_next(conn);
		}

		return;
	}

	if (handled) {
		msn_soap_connection_handle_next(conn);
	}
}

static void
msn_soap_read_cb(gpointer data, gint fd, PurpleInputCondition cond)
{
	MsnSoapConnection *conn = data;
	int count = 0, cnt, perrno;
	/* This buffer needs to be larger than any packets received from
		login.live.com or Adium will fail to receive the packet
		(something weird with the login.live.com server). With NSS it works
		fine, so I believe it's some bug with OS X */
	char buf[16 * 1024];
	gsize cursor;

	if (conn->message == NULL) {
		conn->message = msn_soap_message_new(NULL, NULL);
	}

	if (conn->buf == NULL) {
		conn->buf = g_string_new_len(buf, 0);
	}

	cursor = conn->buf->len;
	while ((cnt = purple_ssl_read(conn->ssl, buf, sizeof(buf))) > 0) {
		purple_debug_info("soap", "read %d bytes\n", cnt);
		count += cnt;
		g_string_append_len(conn->buf, buf, cnt);
	}

	perrno = errno;
	if (cnt < 0 && perrno != EAGAIN)
		purple_debug_info("soap", "read: %s\n", g_strerror(perrno));

	if (conn->current_request && conn->current_request->secure &&
		!purple_debug_is_unsafe())
		purple_debug_misc("soap", "Received secure request.\n");
	else if (count != 0)
		purple_debug_misc("soap", "current %s\n", conn->buf->str + cursor);

	/* && count is necessary for Adium, on OS X the last read always
	   return an error, so we want to proceed anyway. See #5212 for
	   discussion on this and the above buffer size issues */
	if(cnt < 0 && errno == EAGAIN && count == 0)
		return;

	/* msn_soap_process could alter errno */
	msn_soap_process(conn);

	if ((cnt < 0 && perrno != EAGAIN) || cnt == 0) {
		/* It's possible msn_soap_process closed the ssl connection */
		if (conn->ssl) {
			purple_ssl_close(conn->ssl);
			conn->ssl = NULL;
			msn_soap_connection_handle_next(conn);
		}
	}
}

static gboolean
msn_soap_write_cb_internal(gpointer data, gint fd, PurpleInputCondition cond,
		gboolean initial)
{
	MsnSoapConnection *conn = data;
	int written;

	if (cond != PURPLE_INPUT_WRITE)
		return TRUE;

	written = purple_ssl_write(conn->ssl, conn->buf->str + conn->handled_len,
		conn->buf->len - conn->handled_len);

	if (written < 0 && errno == EAGAIN)
		return TRUE;
	else if (written <= 0) {
		purple_ssl_close(conn->ssl);
		conn->ssl = NULL;
		if (!initial)
			msn_soap_connection_handle_next(conn);
		return FALSE;
	}

	conn->handled_len += written;

	if (conn->handled_len < conn->buf->len)
		return TRUE;

	/* we are done! */
	g_string_free(conn->buf, TRUE);
	conn->buf = NULL;
	conn->handled_len = 0;
	conn->body_len = 0;
	conn->response_code = 0;
	conn->headers_done = FALSE;
	conn->close_when_done = FALSE;

	purple_input_remove(conn->event_handle);
	conn->event_handle = purple_input_add(conn->ssl->fd, PURPLE_INPUT_READ,
		msn_soap_read_cb, conn);
	return TRUE;
}

static void
msn_soap_write_cb(gpointer data, gint fd, PurpleInputCondition cond)
{
	msn_soap_write_cb_internal(data, fd, cond, FALSE);
}

static void
msn_soap_error_cb(PurpleSslConnection *ssl, PurpleSslErrorType error,
		gpointer data)
{
	MsnSoapConnection *conn = data;

	/* sslconn already frees the connection in case of error */
	conn->ssl = NULL;

	g_hash_table_remove(conn->session->soap_table, conn->host);
}

static void
msn_soap_connected_cb(gpointer data, PurpleSslConnection *ssl,
		PurpleInputCondition cond)
{
	MsnSoapConnection *conn = data;

	conn->connected = TRUE;

	if (conn->run_timer == 0)
		conn->run_timer = purple_timeout_add(0, msn_soap_connection_run, conn);
}

MsnSoapMessage *
msn_soap_message_new(const char *action, xmlnode *xml)
{
	MsnSoapMessage *message = g_new0(MsnSoapMessage, 1);

	message->action = g_strdup(action);
	message->xml = xml;

	return message;
}

static gboolean
msn_soap_connection_run(gpointer data)
{
	MsnSoapConnection *conn = data;
	MsnSoapRequest *req = g_queue_peek_head(conn->queue);

	conn->run_timer = 0;

	if (req) {
		if (conn->ssl == NULL) {
			conn->ssl = purple_ssl_connect(conn->session->account, conn->host,
				443, msn_soap_connected_cb, msn_soap_error_cb, conn);
		} else if (conn->connected) {
			int len = -1;
			char *body = xmlnode_to_str(req->message->xml, &len);
			GSList *iter;

			g_queue_pop_head(conn->queue);

			conn->buf = g_string_new("");

			g_string_append_printf(conn->buf,
				"POST /%s HTTP/1.1\r\n"
				"SOAPAction: %s\r\n"
				"Content-Type:text/xml; charset=utf-8\r\n"
				"User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n"
				"Accept: */*\r\n"
				"Host: %s\r\n"
				"Content-Length: %d\r\n"
				"Connection: Keep-Alive\r\n"
				"Cache-Control: no-cache\r\n",
				req->path, req->message->action ? req->message->action : "",
				conn->host, len);

			for (iter = req->message->headers; iter; iter = iter->next) {
				g_string_append(conn->buf, (char *)iter->data);
				g_string_append(conn->buf, "\r\n");
			}

			g_string_append(conn->buf, "\r\n");
			g_string_append(conn->buf, body);

			if (req->secure && !purple_debug_is_unsafe())
				purple_debug_misc("soap", "Sending secure request.\n");
			else
				purple_debug_misc("soap", "%s\n", conn->buf->str);

			conn->handled_len = 0;
			conn->current_request = req;

			if (conn->event_handle)
				purple_input_remove(conn->event_handle);
			conn->event_handle = purple_input_add(conn->ssl->fd,
				PURPLE_INPUT_WRITE, msn_soap_write_cb, conn);
			if (!msn_soap_write_cb_internal(conn, conn->ssl->fd, PURPLE_INPUT_WRITE, TRUE)) {
				/* Not connected => reconnect and retry */
				purple_debug_info("soap", "not connected, reconnecting\n");

				conn->connected = FALSE;
				conn->current_request = NULL;
				msn_soap_connection_sanitize(conn, FALSE);

				g_queue_push_head(conn->queue, req);
				conn->run_timer = purple_timeout_add(0, msn_soap_connection_run, conn);
			}

			g_free(body);
		}
	}

	return FALSE;
}
