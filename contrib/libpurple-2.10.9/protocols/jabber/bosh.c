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
#include "circbuffer.h"
#include "core.h"
#include "cipher.h"
#include "debug.h"
#include "prpl.h"
#include "util.h"
#include "xmlnode.h"

#include "bosh.h"

/* The number of HTTP connections to use. This MUST be at least 2. */
#define NUM_HTTP_CONNECTIONS      2
/* How many failed connection attempts before it becomes a fatal error */
#define MAX_FAILED_CONNECTIONS    3
/* How long in seconds to queue up outgoing messages */
#define BUFFER_SEND_IN_SECS       1

typedef struct _PurpleHTTPConnection PurpleHTTPConnection;

typedef void (*PurpleBOSHConnectionConnectFunction)(PurpleBOSHConnection *conn);
typedef void (*PurpleBOSHConnectionReceiveFunction)(PurpleBOSHConnection *conn, xmlnode *node);

static char *bosh_useragent = NULL;

typedef enum {
	PACKET_NORMAL,
	PACKET_TERMINATE,
	PACKET_FLUSH,
} PurpleBOSHPacketType;

struct _PurpleBOSHConnection {
	JabberStream *js;
	PurpleHTTPConnection *connections[NUM_HTTP_CONNECTIONS];

	PurpleCircBuffer *pending;
	PurpleBOSHConnectionConnectFunction connect_cb;
	PurpleBOSHConnectionReceiveFunction receive_cb;

	/* Must be big enough to hold 2^53 - 1 */
	char *sid;
	guint64 rid;

	/* decoded URL */
	char *host;
	char *path;
	guint16 port;

	gboolean pipelining;
	gboolean ssl;

	enum {
		BOSH_CONN_OFFLINE,
		BOSH_CONN_BOOTING,
		BOSH_CONN_ONLINE
	} state;
	guint8 failed_connections;

	int wait;

	int max_requests;
	int requests;

	guint send_timer;
};

struct _PurpleHTTPConnection {
	PurpleBOSHConnection *bosh;
	PurpleSslConnection *psc;

	PurpleCircBuffer *write_buf;
	GString *read_buf;

	gsize handled_len;
	gsize body_len;

	int fd;
	guint readh;
	guint writeh;

	enum {
		HTTP_CONN_OFFLINE,
		HTTP_CONN_CONNECTING,
		HTTP_CONN_CONNECTED
	} state;
	int requests; /* number of outstanding HTTP requests */

	gboolean headers_done;
	gboolean close;
};

static void
debug_dump_http_connections(PurpleBOSHConnection *conn)
{
	int i;

	g_return_if_fail(conn != NULL);

	for (i = 0; i < NUM_HTTP_CONNECTIONS; ++i) {
		PurpleHTTPConnection *httpconn = conn->connections[i];
		if (httpconn == NULL)
			purple_debug_misc("jabber", "BOSH %p->connections[%d] = (nil)\n",
			                  conn, i);
		else
			purple_debug_misc("jabber", "BOSH %p->connections[%d] = %p, state = %d"
			                  ", requests = %d\n", conn, i, httpconn,
			                  httpconn->state, httpconn->requests);
	}
}

static void http_connection_connect(PurpleHTTPConnection *conn);
static void http_connection_send_request(PurpleHTTPConnection *conn,
                                         const GString *req);
static gboolean send_timer_cb(gpointer data);

void jabber_bosh_init(void)
{
	GHashTable *ui_info = purple_core_get_ui_info();
	const char *ui_name = NULL;
	const char *ui_version = NULL;

	if (ui_info) {
		ui_name = g_hash_table_lookup(ui_info, "name");
		ui_version = g_hash_table_lookup(ui_info, "version");
	}

	if (ui_name)
		bosh_useragent = g_strdup_printf("%s%s%s (libpurple " VERSION ")",
		                                 ui_name, ui_version ? " " : "",
		                                 ui_version ? ui_version : "");
	else
		bosh_useragent = g_strdup("libpurple " VERSION);
}

void jabber_bosh_uninit(void)
{
	g_free(bosh_useragent);
	bosh_useragent = NULL;
}

static PurpleHTTPConnection*
jabber_bosh_http_connection_init(PurpleBOSHConnection *bosh)
{
	PurpleHTTPConnection *conn = g_new0(PurpleHTTPConnection, 1);
	conn->bosh = bosh;
	conn->fd = -1;
	conn->state = HTTP_CONN_OFFLINE;

	conn->write_buf = purple_circ_buffer_new(0 /* default grow size */);

	return conn;
}

static void
jabber_bosh_http_connection_destroy(PurpleHTTPConnection *conn)
{
	if (conn->read_buf)
		g_string_free(conn->read_buf, TRUE);

	if (conn->write_buf)
		purple_circ_buffer_destroy(conn->write_buf);
	if (conn->readh)
		purple_input_remove(conn->readh);
	if (conn->writeh)
		purple_input_remove(conn->writeh);
	if (conn->psc)
		purple_ssl_close(conn->psc);
	if (conn->fd >= 0)
		close(conn->fd);

	purple_proxy_connect_cancel_with_handle(conn);

	g_free(conn);
}

PurpleBOSHConnection*
jabber_bosh_connection_init(JabberStream *js, const char *url)
{
	PurpleBOSHConnection *conn;
	char *host, *path, *user, *passwd;
	int port;

	if (!purple_url_parse(url, &host, &port, &path, &user, &passwd)) {
		purple_debug_info("jabber", "Unable to parse given URL.\n");
		return NULL;
	}

	conn = g_new0(PurpleBOSHConnection, 1);
	conn->host = host;
	conn->port = port;
	conn->path = g_strdup_printf("/%s", path);
	g_free(path);
	conn->pipelining = TRUE;

	if (purple_ip_address_is_valid(host))
		js->serverFQDN = g_strdup(js->user->domain);
	else
		js->serverFQDN = g_strdup(host);

	if ((user && user[0] != '\0') || (passwd && passwd[0] != '\0')) {
		purple_debug_info("jabber", "Ignoring unexpected username and password "
		                            "in BOSH URL.\n");
	}

	g_free(user);
	g_free(passwd);

	conn->js = js;

	/*
	 * Random 64-bit integer masked off by 2^52 - 1.
	 *
	 * This should produce a random integer in the range [0, 2^52). It's
	 * unlikely we'll send enough packets in one session to overflow the rid.
	 */
	conn->rid = ((guint64)g_random_int() << 32) | g_random_int();
	conn->rid &= 0xFFFFFFFFFFFFFLL;

	conn->pending = purple_circ_buffer_new(0 /* default grow size */);

	conn->state = BOSH_CONN_OFFLINE;
	if (purple_strcasestr(url, "https://") != NULL)
		conn->ssl = TRUE;
	else
		conn->ssl = FALSE;

	conn->connections[0] = jabber_bosh_http_connection_init(conn);

	return conn;
}

void
jabber_bosh_connection_destroy(PurpleBOSHConnection *conn)
{
	int i;

	g_free(conn->host);
	g_free(conn->path);

	if (conn->send_timer)
		purple_timeout_remove(conn->send_timer);

	purple_circ_buffer_destroy(conn->pending);

	for (i = 0; i < NUM_HTTP_CONNECTIONS; ++i) {
		if (conn->connections[i])
			jabber_bosh_http_connection_destroy(conn->connections[i]);
	}

	g_free(conn);
}

gboolean jabber_bosh_connection_is_ssl(PurpleBOSHConnection *conn)
{
	return conn->ssl;
}

static PurpleHTTPConnection *
find_available_http_connection(PurpleBOSHConnection *conn)
{
	int i;

	if (purple_debug_is_verbose())
		debug_dump_http_connections(conn);

	/* Easy solution: Does everyone involved support pipelining? Hooray! Just use
	 * one TCP connection! */
	if (conn->pipelining)
		return conn->connections[0]->state == HTTP_CONN_CONNECTED ?
				conn->connections[0] : NULL;

	/* First loop, look for a connection that's ready */
	for (i = 0; i < NUM_HTTP_CONNECTIONS; ++i) {
		if (conn->connections[i] &&
				conn->connections[i]->state == HTTP_CONN_CONNECTED &&
				conn->connections[i]->requests == 0)
			return conn->connections[i];
	}

	/* Second loop, is something currently connecting? If so, just queue up. */
	for (i = 0; i < NUM_HTTP_CONNECTIONS; ++i) {
		if (conn->connections[i] &&
				conn->connections[i]->state == HTTP_CONN_CONNECTING)
			return NULL;
	}

	/* Third loop, is something offline that we can connect? */
	for (i = 0; i < NUM_HTTP_CONNECTIONS; ++i) {
		if (conn->connections[i] &&
				conn->connections[i]->state == HTTP_CONN_OFFLINE) {
			purple_debug_info("jabber", "bosh: Reconnecting httpconn "
			                            "(%i, %p)\n", i, conn->connections[i]);
			http_connection_connect(conn->connections[i]);
			return NULL;
		}
	}

	/* Fourth loop, look for one that's NULL and create a new connection */
	for (i = 0; i < NUM_HTTP_CONNECTIONS; ++i) {
		if (!conn->connections[i]) {
			conn->connections[i] = jabber_bosh_http_connection_init(conn);
			purple_debug_info("jabber", "bosh: Creating and connecting new httpconn "
			                            "(%i, %p)\n", i, conn->connections[i]);

			http_connection_connect(conn->connections[i]);
			return NULL;
		}
	}

	purple_debug_warning("jabber", "Could not find a HTTP connection!\n");

	/* None available. */
	return NULL;
}

static void
jabber_bosh_connection_send(PurpleBOSHConnection *conn,
                            const PurpleBOSHPacketType type, const char *data)
{
	PurpleHTTPConnection *chosen;
	GString *packet = NULL;

	if (type != PACKET_FLUSH && type != PACKET_TERMINATE) {
		/*
		 * Unless this is a flush (or session terminate, which needs to be
		 * sent immediately), queue up the data and start a timer to flush
		 * the buffer.
		 */
		if (data)
			purple_circ_buffer_append(conn->pending, data, strlen(data));

		if (purple_debug_is_verbose())
			purple_debug_misc("jabber", "bosh: %p has %" G_GSIZE_FORMAT " bytes in "
			                  "the buffer.\n", conn, conn->pending->bufused);
		if (conn->send_timer == 0)
			conn->send_timer = purple_timeout_add_seconds(BUFFER_SEND_IN_SECS,
					send_timer_cb, conn);
		return;
	}

	chosen = find_available_http_connection(conn);

	if (!chosen) {
		if (type == PACKET_FLUSH)
			return;
		/*
		 * For non-ordinary traffic, we can't 'buffer' it, so use the
		 * first connection.
		 */
		chosen = conn->connections[0];

		if (chosen->state != HTTP_CONN_CONNECTED) {
			purple_debug_warning("jabber", "Unable to find a ready BOSH "
					"connection. Ignoring send of type 0x%02x.\n", type);
			return;
		}
	}

	/* We're flushing the send buffer, so remove the send timer */
	if (conn->send_timer != 0) {
		purple_timeout_remove(conn->send_timer);
		conn->send_timer = 0;
	}

	packet = g_string_new(NULL);

	g_string_printf(packet, "<body "
	                "rid='%" G_GUINT64_FORMAT "' "
	                "sid='%s' "
	                "to='%s' "
	                "xml:lang='en' "
	                "xmlns='" NS_BOSH "' "
	                "xmlns:xmpp='" NS_XMPP_BOSH "'",
	                ++conn->rid,
	                conn->sid,
	                conn->js->user->domain);

	if (conn->js->reinit) {
		packet = g_string_append(packet, " xmpp:restart='true'/>");
		/* TODO: Do we need to wait for a response? */
		conn->js->reinit = FALSE;
	} else {
		gsize read_amt;
		if (type == PACKET_TERMINATE)
			packet = g_string_append(packet, " type='terminate'");

		packet = g_string_append_c(packet, '>');

		while ((read_amt = purple_circ_buffer_get_max_read(conn->pending)) > 0) {
			packet = g_string_append_len(packet, conn->pending->outptr, read_amt);
			purple_circ_buffer_mark_read(conn->pending, read_amt);
		}

		if (data)
			packet = g_string_append(packet, data);
		packet = g_string_append(packet, "</body>");
	}

	http_connection_send_request(chosen, packet);
}

void jabber_bosh_connection_close(PurpleBOSHConnection *conn)
{
	if (conn->state == BOSH_CONN_ONLINE)
		jabber_bosh_connection_send(conn, PACKET_TERMINATE, NULL);
}

static gboolean jabber_bosh_connection_error_check(PurpleBOSHConnection *conn, xmlnode *node) {
	const char *type;

	type = xmlnode_get_attrib(node, "type");

	if (type != NULL && !strcmp(type, "terminate")) {
		conn->state = BOSH_CONN_OFFLINE;
		purple_connection_error_reason(conn->js->gc,
			PURPLE_CONNECTION_ERROR_OTHER_ERROR,
			_("The BOSH connection manager terminated your session."));
		return TRUE;
	}
	return FALSE;
}

static gboolean
send_timer_cb(gpointer data)
{
	PurpleBOSHConnection *bosh;

	bosh = data;
	bosh->send_timer = 0;

	jabber_bosh_connection_send(bosh, PACKET_FLUSH, NULL);

	return FALSE;
}

void
jabber_bosh_connection_send_keepalive(PurpleBOSHConnection *bosh)
{
	if (bosh->send_timer != 0)
		purple_timeout_remove(bosh->send_timer);

	/* clears bosh->send_timer */
	send_timer_cb(bosh);
}

static void
jabber_bosh_disable_pipelining(PurpleBOSHConnection *bosh)
{
	/* Do nothing if it's already disabled */
	if (!bosh->pipelining)
		return;

	purple_debug_info("jabber", "BOSH: Disabling pipelining on conn %p\n",
	                            bosh);
	bosh->pipelining = FALSE;
	if (bosh->connections[1] == NULL) {
		bosh->connections[1] = jabber_bosh_http_connection_init(bosh);
		http_connection_connect(bosh->connections[1]);
	} else {
		/* Shouldn't happen; this should be the only place pipelining
		 * is turned off.
		 */
		g_warn_if_reached();
	}
}

static void jabber_bosh_connection_received(PurpleBOSHConnection *conn, xmlnode *node) {
	xmlnode *child;
	JabberStream *js = conn->js;

	g_return_if_fail(node != NULL);
	if (jabber_bosh_connection_error_check(conn, node))
		return;

	child = node->child;
	while (child != NULL) {
		/* jabber_process_packet might free child */
		xmlnode *next = child->next;
		if (child->type == XMLNODE_TYPE_TAG) {
			const char *xmlns = xmlnode_get_namespace(child);
			/*
			 * Workaround for non-compliant servers that don't stamp
			 * the right xmlns on these packets.  See #11315.
			 */
			if ((xmlns == NULL /* shouldn't happen, but is equally wrong */ ||
					g_str_equal(xmlns, NS_BOSH)) &&
				(g_str_equal(child->name, "iq") ||
				 g_str_equal(child->name, "message") ||
				 g_str_equal(child->name, "presence"))) {
				xmlnode_set_namespace(child, NS_XMPP_CLIENT);
			}
			jabber_process_packet(js, &child);
		}

		child = next;
	}
}

static void boot_response_cb(PurpleBOSHConnection *conn, xmlnode *node) {
	JabberStream *js = conn->js;
	const char *sid, *version;
	const char *inactivity, *requests;
	xmlnode *packet;

	g_return_if_fail(node != NULL);
	if (jabber_bosh_connection_error_check(conn, node))
		return;

	sid = xmlnode_get_attrib(node, "sid");
	version = xmlnode_get_attrib(node, "ver");

	inactivity = xmlnode_get_attrib(node, "inactivity");
	requests = xmlnode_get_attrib(node, "requests");

	if (sid) {
		conn->sid = g_strdup(sid);
	} else {
		purple_connection_error_reason(js->gc,
		        PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
		        _("No session ID given"));
		return;
	}

	if (version) {
		const char *dot = strchr(version, '.');
		int major, minor = 0;

		purple_debug_info("jabber", "BOSH connection manager version %s\n", version);

		major = atoi(version);
		if (dot)
			minor = atoi(dot + 1);

		if (major != 1 || minor < 6) {
			purple_connection_error_reason(js->gc,
			        PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
			        _("Unsupported version of BOSH protocol"));
			return;
		}
	} else {
		purple_debug_info("jabber", "Missing version in BOSH initiation\n");
	}

	if (inactivity) {
		js->max_inactivity = atoi(inactivity);
		if (js->max_inactivity <= 5) {
			purple_debug_warning("jabber", "Ignoring bogusly small inactivity: %s\n",
			                     inactivity);
			/* Leave it at the default */
		} else {
			/* TODO: Can this check fail? It shouldn't */
			js->max_inactivity -= 5; /* rounding */

			if (js->inactivity_timer == 0) {
				purple_debug_misc("jabber", "Starting BOSH inactivity timer "
						"for %d secs (compensating for rounding)\n",
						js->max_inactivity);
				jabber_stream_restart_inactivity_timer(js);
			}
		}
	}

	if (requests)
		conn->max_requests = atoi(requests);

	jabber_stream_set_state(js, JABBER_STREAM_AUTHENTICATING);

	/* FIXME: Depending on receiving features might break with some hosts */
	packet = xmlnode_get_child(node, "features");
	conn->state = BOSH_CONN_ONLINE;
	conn->receive_cb = jabber_bosh_connection_received;
	jabber_stream_features_parse(js, packet);
}

static void jabber_bosh_connection_boot(PurpleBOSHConnection *conn) {
	GString *buf = g_string_new(NULL);

	g_string_printf(buf, "<body content='text/xml; charset=utf-8' "
	                "secure='true' "
	                "to='%s' "
	                "xml:lang='en' "
	                "xmpp:version='1.0' "
	                "ver='1.6' "
	                "xmlns:xmpp='" NS_XMPP_BOSH "' "
	                "rid='%" G_GUINT64_FORMAT "' "
/* TODO: This should be adjusted/adjustable automatically according to
 * realtime network behavior */
	                "wait='60' "
	                "hold='1' "
	                "xmlns='" NS_BOSH "'/>",
	                conn->js->user->domain,
	                ++conn->rid);

	purple_debug_misc("jabber", "SendBOSH Boot %s(%" G_GSIZE_FORMAT "): %s\n",
	                  conn->ssl ? "(ssl)" : "", buf->len, buf->str);
	conn->receive_cb = boot_response_cb;
	http_connection_send_request(conn->connections[0], buf);
	g_string_free(buf, TRUE);
}

/**
 * Handle one complete BOSH response. This is a <body> node containing
 * any number of XMPP stanzas.
 */
static void
http_received_cb(const char *data, int len, PurpleBOSHConnection *conn)
{
	xmlnode *node;
	gchar *message;

	if (conn->failed_connections)
		/* We've got some data, so reset the number of failed connections */
		conn->failed_connections = 0;

	g_return_if_fail(conn->receive_cb);

	node = xmlnode_from_str(data, len);

	message = g_strndup(data, len);
	purple_debug_info("jabber", "RecvBOSH %s(%d): %s\n",
	                  conn->ssl ? "(ssl)" : "", len, message);
	g_free(message);

	if (node) {
		conn->receive_cb(conn, node);
		xmlnode_free(node);
	} else {
		purple_debug_warning("jabber", "BOSH: Received invalid XML\n");
	}
}

void jabber_bosh_connection_send_raw(PurpleBOSHConnection *conn,
                                     const char *data)
{
	jabber_bosh_connection_send(conn, PACKET_NORMAL, data);
}

static void
connection_common_established_cb(PurpleHTTPConnection *conn)
{
	purple_debug_misc("jabber", "bosh: httpconn %p re-connected\n", conn);

	/* Indicate we're ready and reset some variables */
	conn->state = HTTP_CONN_CONNECTED;
	if (conn->requests != 0)
		purple_debug_error("jabber", "bosh: httpconn %p has %d requests, != 0\n",
		                   conn, conn->requests);

	conn->requests = 0;
	if (conn->read_buf) {
		g_string_free(conn->read_buf, TRUE);
		conn->read_buf = NULL;
	}
	conn->close = FALSE;
	conn->headers_done = FALSE;
	conn->handled_len = conn->body_len = 0;

	if (purple_debug_is_verbose())
		debug_dump_http_connections(conn->bosh);

	if (conn->bosh->js->reinit)
		jabber_bosh_connection_send(conn->bosh, PACKET_NORMAL, NULL);
	else if (conn->bosh->state == BOSH_CONN_ONLINE) {
		purple_debug_info("jabber", "BOSH session already exists. Trying to reuse it.\n");
		if (conn->bosh->requests == 0 || conn->bosh->pending->bufused > 0) {
			/* Send the pending data */
			jabber_bosh_connection_send(conn->bosh, PACKET_FLUSH, NULL);
		}
	} else
		jabber_bosh_connection_boot(conn->bosh);
}

static void http_connection_disconnected(PurpleHTTPConnection *conn)
{
	gboolean had_requests = FALSE;
	/*
	 * Well, then. Fine! I never liked you anyway, server! I was cheating on you
	 * with AIM!
	 */
	conn->state = HTTP_CONN_OFFLINE;
	if (conn->psc) {
		purple_ssl_close(conn->psc);
		conn->psc = NULL;
	} else if (conn->fd >= 0) {
		close(conn->fd);
		conn->fd = -1;
	}

	if (conn->readh) {
		purple_input_remove(conn->readh);
		conn->readh = 0;
	}

	if (conn->writeh) {
		purple_input_remove(conn->writeh);
		conn->writeh = 0;
	}

	had_requests = (conn->requests > 0);
	if (had_requests && conn->read_buf->len == 0) {
		purple_debug_error("jabber", "bosh: Adjusting BOSHconn requests (%d) to %d\n",
		                   conn->bosh->requests, conn->bosh->requests - conn->requests);
		conn->bosh->requests -= conn->requests;
		conn->requests = 0;
	}

	if (conn->bosh->pipelining) {
		/* Hmmmm, fall back to multiple connections */
		jabber_bosh_disable_pipelining(conn->bosh);
	}

	if (!had_requests)
		/* If the server disconnected us without any requests, let's
		 * just wait until we have something to send before we reconnect
		 */
		return;

	if (++conn->bosh->failed_connections == MAX_FAILED_CONNECTIONS) {
		purple_connection_error_reason(conn->bosh->js->gc,
				PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
				_("Unable to establish a connection with the server"));
	} else {
		/* No! Please! Take me back. It was me, not you! I was weak! */
		http_connection_connect(conn);
	}
}

void jabber_bosh_connection_connect(PurpleBOSHConnection *bosh) {
	PurpleHTTPConnection *conn = bosh->connections[0];

	g_return_if_fail(bosh->state == BOSH_CONN_OFFLINE);
	bosh->state = BOSH_CONN_BOOTING;

	http_connection_connect(conn);
}

/**
 * @return TRUE if we want to be called again immediately. This happens when
 *         we parse an HTTP response AND there is more data in read_buf. FALSE
 *         if we should not be called again unless more data has been read.
 */
static gboolean
jabber_bosh_http_connection_process(PurpleHTTPConnection *conn)
{
	const char *cursor;

	cursor = conn->read_buf->str + conn->handled_len;

	if (purple_debug_is_verbose())
		purple_debug_misc("jabber", "BOSH server sent: %s\n", cursor);

	/* TODO: Chunked encoding and check response version :/ */
	if (!conn->headers_done) {
		const char *content_length = purple_strcasestr(cursor, "\r\nContent-Length:");
		const char *connection = purple_strcasestr(cursor, "\r\nConnection:");
		const char *end_of_headers = strstr(cursor, "\r\n\r\n");

		/* Make sure Content-Length is in headers, not body */
		if (content_length && (!end_of_headers || content_length < end_of_headers)) {
			int len;

			if (strstr(content_length, "\r\n") == NULL)
				/*
				 * The packet ends in the middle of the Content-Length line.
				 * We'll try again later when we have more.
				 */
				return FALSE;

			len = atoi(content_length + strlen("\r\nContent-Length:"));
			if (len == 0)
				purple_debug_warning("jabber", "Found mangled Content-Length header, or server returned 0-length response.\n");

			conn->body_len = len;
		}

		if (connection && (!end_of_headers || connection < end_of_headers)) {
			const char *tmp;
			if (strstr(connection, "\r\n") == NULL)
				return FALSE;


			tmp = connection + strlen("\r\nConnection:");
			while (*tmp && (*tmp == ' ' || *tmp == '\t'))
				++tmp;

			if (!g_ascii_strncasecmp(tmp, "close", strlen("close"))) {
				conn->close = TRUE;
				jabber_bosh_disable_pipelining(conn->bosh);
			}
		}

		if (end_of_headers) {
			conn->headers_done = TRUE;
			conn->handled_len = end_of_headers - conn->read_buf->str + 4;
		} else {
			conn->handled_len = conn->read_buf->len;
			return FALSE;
		}
	}

	/* Have we handled everything in the buffer? */
	if (conn->handled_len >= conn->read_buf->len)
		return FALSE;

	/* Have we read all that the Content-Length promised us? */
	if (conn->read_buf->len - conn->handled_len < conn->body_len)
		return FALSE;

	--conn->requests;
	--conn->bosh->requests;

	http_received_cb(conn->read_buf->str + conn->handled_len, conn->body_len,
	                 conn->bosh);

	/* Is there another response in the buffer ? */
	if (conn->read_buf->len > conn->body_len + conn->handled_len) {
		g_string_erase(conn->read_buf, 0, conn->handled_len + conn->body_len);
		conn->headers_done = FALSE;
		conn->handled_len = conn->body_len = 0;
		return TRUE;
	}

	/* Connection: Close? */
	if (conn->close && conn->state == HTTP_CONN_CONNECTED) {
		if (purple_debug_is_verbose())
			purple_debug_misc("jabber", "bosh (%p), server sent Connection: "
			                            "close\n", conn);
		http_connection_disconnected(conn);
	}

	if (conn->bosh->state == BOSH_CONN_ONLINE &&
			(conn->bosh->requests == 0 || conn->bosh->pending->bufused > 0)) {
		purple_debug_misc("jabber", "BOSH: Sending an empty request\n");
		jabber_bosh_connection_send(conn->bosh, PACKET_NORMAL, NULL);
	}

	g_string_free(conn->read_buf, TRUE);
	conn->read_buf = NULL;
	conn->headers_done = FALSE;
	conn->handled_len = conn->body_len = 0;

	return FALSE;
}

/*
 * Common code for reading, called from http_connection_read_cb_ssl and
 * http_connection_read_cb.
 */
static void
http_connection_read(PurpleHTTPConnection *conn)
{
	char buffer[1025];
	int cnt;

	if (!conn->read_buf)
		conn->read_buf = g_string_new(NULL);

	do {
		if (conn->psc)
			cnt = purple_ssl_read(conn->psc, buffer, sizeof(buffer));
		else
			cnt = read(conn->fd, buffer, sizeof(buffer));

		if (cnt > 0) {
			g_string_append_len(conn->read_buf, buffer, cnt);
		}
	} while (cnt > 0);

	if (cnt == 0 || (cnt < 0 && errno != EAGAIN)) {
		if (cnt < 0)
			purple_debug_info("jabber", "BOSH (%p) read=%d, errno=%d, error=%s\n",
			                  conn, cnt, errno, g_strerror(errno));
		else
			purple_debug_info("jabber", "BOSH server closed the connection (%p)\n",
			                  conn);

		/*
		 * If the socket is closed, the processing really needs to know about
		 * it. Handle that now.
		 */
		http_connection_disconnected(conn);

		/* Process what we do have */
	}

	if (conn->read_buf->len > 0) {
		while (jabber_bosh_http_connection_process(conn));
	}
}

static void
http_connection_read_cb(gpointer data, gint fd, PurpleInputCondition condition)
{
	PurpleHTTPConnection *conn = data;

	http_connection_read(conn);
}

static void
http_connection_read_cb_ssl(gpointer data, PurpleSslConnection *psc,
                            PurpleInputCondition cond)
{
	PurpleHTTPConnection *conn = data;

	http_connection_read(conn);
}

static void
ssl_connection_established_cb(gpointer data, PurpleSslConnection *psc,
                              PurpleInputCondition cond)
{
	PurpleHTTPConnection *conn = data;

	purple_ssl_input_add(psc, http_connection_read_cb_ssl, conn);
	connection_common_established_cb(conn);
}

static void
ssl_connection_error_cb(PurpleSslConnection *gsc, PurpleSslErrorType error,
                        gpointer data)
{
	PurpleHTTPConnection *conn = data;

	/* sslconn frees the connection on error */
	conn->psc = NULL;

	purple_connection_ssl_error(conn->bosh->js->gc, error);
}

static void
connection_established_cb(gpointer data, gint source, const gchar *error)
{
	PurpleHTTPConnection *conn = data;
	PurpleConnection *gc = conn->bosh->js->gc;

	if (source < 0) {
		gchar *tmp;
		tmp = g_strdup_printf(_("Unable to establish a connection with the server: %s"),
		        error);
		purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, tmp);
		g_free(tmp);
		return;
	}

	conn->fd = source;
	conn->readh = purple_input_add(conn->fd, PURPLE_INPUT_READ,
	        http_connection_read_cb, conn);
	connection_common_established_cb(conn);
}

static void http_connection_connect(PurpleHTTPConnection *conn)
{
	PurpleBOSHConnection *bosh = conn->bosh;
	PurpleConnection *gc = bosh->js->gc;
	PurpleAccount *account = purple_connection_get_account(gc);

	conn->state = HTTP_CONN_CONNECTING;

	if (bosh->ssl) {
		if (purple_ssl_is_supported()) {
			conn->psc = purple_ssl_connect(account, bosh->host, bosh->port,
			                               ssl_connection_established_cb,
			                               ssl_connection_error_cb,
			                               conn);
			if (!conn->psc) {
				purple_connection_error_reason(gc,
					PURPLE_CONNECTION_ERROR_NO_SSL_SUPPORT,
					_("Unable to establish SSL connection"));
			}
		} else {
			purple_connection_error_reason(gc,
			    PURPLE_CONNECTION_ERROR_NO_SSL_SUPPORT,
			    _("SSL support unavailable"));
		}
	} else if (purple_proxy_connect(conn, account, bosh->host, bosh->port,
	                                 connection_established_cb, conn) == NULL) {
		purple_connection_error_reason(gc,
		    PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
		    _("Unable to connect"));
	}
}

static int
http_connection_do_send(PurpleHTTPConnection *conn, const char *data, int len)
{
	int ret;

	if (conn->psc)
		ret = purple_ssl_write(conn->psc, data, len);
	else
		ret = write(conn->fd, data, len);

	if (purple_debug_is_verbose())
		purple_debug_misc("jabber", "BOSH (%p): wrote %d bytes\n", conn, ret);

	return ret;
}

static void
http_connection_send_cb(gpointer data, gint source, PurpleInputCondition cond)
{
	PurpleHTTPConnection *conn = data;
	int ret;
	int writelen = purple_circ_buffer_get_max_read(conn->write_buf);

	if (writelen == 0) {
		purple_input_remove(conn->writeh);
		conn->writeh = 0;
		return;
	}

	ret = http_connection_do_send(conn, conn->write_buf->outptr, writelen);

	if (ret < 0 && errno == EAGAIN)
		return;
	else if (ret <= 0) {
		/*
		 * TODO: Handle this better. Probably requires a PurpleBOSHConnection
		 * buffer that stores what is "being sent" until the
		 * PurpleHTTPConnection reports it is fully sent.
		 */
		gchar *tmp = g_strdup_printf(_("Lost connection with server: %s"),
				g_strerror(errno));
		purple_connection_error_reason(conn->bosh->js->gc,
				PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
				tmp);
		g_free(tmp);
		return;
	}

	purple_circ_buffer_mark_read(conn->write_buf, ret);
}

static void
http_connection_send_request(PurpleHTTPConnection *conn, const GString *req)
{
	char *data;
	int ret;
	size_t len;

	/* Sending something to the server, restart the inactivity timer */
	jabber_stream_restart_inactivity_timer(conn->bosh->js);

	data = g_strdup_printf("POST %s HTTP/1.1\r\n"
	                       "Host: %s\r\n"
	                       "User-Agent: %s\r\n"
	                       "Content-Encoding: text/xml; charset=utf-8\r\n"
	                       "Content-Length: %" G_GSIZE_FORMAT "\r\n\r\n"
	                       "%s",
	                       conn->bosh->path, conn->bosh->host, bosh_useragent,
	                       req->len, req->str);

	len = strlen(data);

	++conn->requests;
	++conn->bosh->requests;

	if (purple_debug_is_unsafe() && purple_debug_is_verbose())
		/* Will contain passwords for SASL PLAIN and is verbose */
		purple_debug_misc("jabber", "BOSH (%p): Sending %s\n", conn, data);
	else if (purple_debug_is_verbose())
		purple_debug_misc("jabber", "BOSH (%p): Sending request of "
		                            "%" G_GSIZE_FORMAT " bytes.\n", conn, len);

	if (conn->writeh == 0)
		ret = http_connection_do_send(conn, data, len);
	else {
		ret = -1;
		errno = EAGAIN;
	}

	if (ret < 0 && errno != EAGAIN) {
		/*
		 * TODO: Handle this better. Probably requires a PurpleBOSHConnection
		 * buffer that stores what is "being sent" until the
		 * PurpleHTTPConnection reports it is fully sent.
		 */
		gchar *tmp = g_strdup_printf(_("Lost connection with server: %s"),
				g_strerror(errno));
		purple_connection_error_reason(conn->bosh->js->gc,
				PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
				tmp);
		g_free(tmp);
		return;
	} else if (ret < len) {
		if (ret < 0)
			ret = 0;
		if (conn->writeh == 0)
			conn->writeh = purple_input_add(conn->psc ? conn->psc->fd : conn->fd,
					PURPLE_INPUT_WRITE, http_connection_send_cb, conn);
		purple_circ_buffer_append(conn->write_buf, data + ret, len - ret);
	}
}

