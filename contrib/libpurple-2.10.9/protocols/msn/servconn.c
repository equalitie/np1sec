/**
 * @file servconn.c Server connection functions
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
#include "debug.h"

#include "servconn.h"
#include "error.h"

static void read_cb(gpointer data, gint source, PurpleInputCondition cond);
static void servconn_timeout_renew(MsnServConn *servconn);

/**************************************************************************
 * Main
 **************************************************************************/

MsnServConn *
msn_servconn_new(MsnSession *session, MsnServConnType type)
{
	MsnServConn *servconn;

	g_return_val_if_fail(session != NULL, NULL);

	servconn = g_new0(MsnServConn, 1);

	servconn->type = type;

	servconn->session = session;
	servconn->cmdproc = msn_cmdproc_new(session);
	servconn->cmdproc->servconn = servconn;

	servconn->httpconn = msn_httpconn_new(servconn);

	servconn->num = session->servconns_count++;

	servconn->tx_buf = purple_circ_buffer_new(MSN_BUF_LEN);
	servconn->tx_handler = 0;
	servconn->timeout_sec = 0;
	servconn->timeout_handle = 0;

	servconn->fd = -1;

	return servconn;
}

void
msn_servconn_destroy(MsnServConn *servconn)
{
	g_return_if_fail(servconn != NULL);

	if (servconn->processing)
	{
		servconn->wasted = TRUE;
		return;
	}

	msn_servconn_disconnect(servconn);

	if (servconn->destroy_cb)
		servconn->destroy_cb(servconn);

	if (servconn->httpconn != NULL)
		msn_httpconn_destroy(servconn->httpconn);

	g_free(servconn->host);

	purple_circ_buffer_destroy(servconn->tx_buf);
	if (servconn->tx_handler > 0)
		purple_input_remove(servconn->tx_handler);
	if (servconn->timeout_handle > 0)
		purple_timeout_remove(servconn->timeout_handle);

	msn_cmdproc_destroy(servconn->cmdproc);
	g_free(servconn);
}

void
msn_servconn_set_connect_cb(MsnServConn *servconn,
							void (*connect_cb)(MsnServConn *))
{
	g_return_if_fail(servconn != NULL);
	servconn->connect_cb = connect_cb;
}

void
msn_servconn_set_disconnect_cb(MsnServConn *servconn,
							   void (*disconnect_cb)(MsnServConn *))
{
	g_return_if_fail(servconn != NULL);

	servconn->disconnect_cb = disconnect_cb;
}

void
msn_servconn_set_destroy_cb(MsnServConn *servconn,
							void (*destroy_cb)(MsnServConn *))
{
	g_return_if_fail(servconn != NULL);

	servconn->destroy_cb = destroy_cb;
}

/**************************************************************************
 * Utility
 **************************************************************************/

void
msn_servconn_got_error(MsnServConn *servconn, MsnServConnError error,
                       const char *reason)
{
	MsnSession *session = servconn->session;
	MsnServConnType type = servconn->type;

	const char *names[] = { "Notification", "Switchboard" };
	const char *name;

	name = names[type];

	if (reason == NULL) {
		switch (error)
		{
			case MSN_SERVCONN_ERROR_CONNECT:
				reason = _("Unable to connect"); break;
			case MSN_SERVCONN_ERROR_WRITE:
				reason = _("Writing error"); break;
			case MSN_SERVCONN_ERROR_READ:
				reason = _("Reading error"); break;
			default:
				reason = _("Unknown error"); break;
		}
	}

	purple_debug_error("msn", "Connection error from %s server (%s): %s\n",
					 name, servconn->host, reason);

	if (type == MSN_SERVCONN_SB)
	{
		MsnSwitchBoard *swboard;
		swboard = servconn->cmdproc->data;
		if (swboard != NULL)
			swboard->error = MSN_SB_ERROR_CONNECTION;
	}

	/* servconn->disconnect_cb may destroy servconn, so don't use it again */
	msn_servconn_disconnect(servconn);

	if (type == MSN_SERVCONN_NS)
	{
		char *tmp = g_strdup_printf(_("Connection error from %s server:\n%s"),
		                            name, reason);
		msn_session_set_error(session, MSN_ERROR_SERVCONN, tmp);
		g_free(tmp);
	}
}

/**************************************************************************
 * Connect
 **************************************************************************/

static void
connect_cb(gpointer data, gint source, const char *error_message)
{
	MsnServConn *servconn;

	servconn = data;
	servconn->connect_data = NULL;

	servconn->fd = source;

	if (source >= 0)
	{
		servconn->connected = TRUE;

		/* Someone wants to know we connected. */
		servconn->connect_cb(servconn);
		servconn->inpa = purple_input_add(servconn->fd, PURPLE_INPUT_READ,
			read_cb, data);
		servconn_timeout_renew(servconn);
	}
	else
	{
		purple_debug_error("msn", "Connection error: %s\n", error_message);
		msn_servconn_got_error(servconn, MSN_SERVCONN_ERROR_CONNECT, error_message);
	}
}

gboolean
msn_servconn_connect(MsnServConn *servconn, const char *host, int port, gboolean force)
{
	MsnSession *session;

	g_return_val_if_fail(servconn != NULL, FALSE);
	g_return_val_if_fail(host     != NULL, FALSE);
	g_return_val_if_fail(port      > 0,    FALSE);

	session = servconn->session;

	if (servconn->connected)
		msn_servconn_disconnect(servconn);

	g_free(servconn->host);
	servconn->host = g_strdup(host);

	if (session->http_method)
	{
		/* HTTP Connection. */

		if (!servconn->httpconn->connected || force)
			if (!msn_httpconn_connect(servconn->httpconn, host, port))
				return FALSE;

		servconn->connected = TRUE;
		servconn->httpconn->virgin = TRUE;
		servconn_timeout_renew(servconn);

		/* Someone wants to know we connected. */
		servconn->connect_cb(servconn);

		return TRUE;
	}

	servconn->connect_data = purple_proxy_connect(NULL, session->account,
			host, port, connect_cb, servconn);

	return (servconn->connect_data != NULL);
}

void
msn_servconn_disconnect(MsnServConn *servconn)
{
	g_return_if_fail(servconn != NULL);

	if (servconn->connect_data != NULL)
	{
		purple_proxy_connect_cancel(servconn->connect_data);
		servconn->connect_data = NULL;
	}

	if (!servconn->connected)
	{
		/* We could not connect. */
		if (servconn->disconnect_cb != NULL)
			servconn->disconnect_cb(servconn);

		return;
	}

	if (servconn->session->http_method)
	{
		/* Fake disconnection. */
		if (servconn->disconnect_cb != NULL)
			servconn->disconnect_cb(servconn);

		return;
	}

	if (servconn->inpa > 0)
	{
		purple_input_remove(servconn->inpa);
		servconn->inpa = 0;
	}

	if (servconn->timeout_handle > 0)
	{
		purple_timeout_remove(servconn->timeout_handle);
		servconn->timeout_handle = 0;
	}

	close(servconn->fd);

	servconn->rx_buf = NULL;
	servconn->rx_len = 0;
	servconn->payload_len = 0;

	servconn->connected = FALSE;

	if (servconn->disconnect_cb != NULL)
		servconn->disconnect_cb(servconn);
}

static gboolean
servconn_idle_timeout_cb(MsnServConn *servconn)
{
	servconn->timeout_handle = 0;
	msn_servconn_disconnect(servconn);
	return FALSE;
}

static void
servconn_timeout_renew(MsnServConn *servconn)
{
	if (servconn->timeout_handle) {
		purple_timeout_remove(servconn->timeout_handle);
		servconn->timeout_handle = 0;
	}

	if (servconn->connected && servconn->timeout_sec) {
		servconn->timeout_handle = purple_timeout_add_seconds(
			servconn->timeout_sec, (GSourceFunc)servconn_idle_timeout_cb, servconn);
	}
}

void
msn_servconn_set_idle_timeout(MsnServConn *servconn, guint seconds)
{
	servconn->timeout_sec = seconds;
	if (servconn->connected)
		servconn_timeout_renew(servconn);
}

static void
servconn_write_cb(gpointer data, gint source, PurpleInputCondition cond)
{
	MsnServConn *servconn = data;
	gssize ret;
	int writelen;

	writelen = purple_circ_buffer_get_max_read(servconn->tx_buf);

	if (writelen == 0) {
		purple_input_remove(servconn->tx_handler);
		servconn->tx_handler = 0;
		return;
	}

	ret = write(servconn->fd, servconn->tx_buf->outptr, writelen);

	if (ret < 0 && errno == EAGAIN)
		return;
	else if (ret <= 0) {
		msn_servconn_got_error(servconn, MSN_SERVCONN_ERROR_WRITE, NULL);
		return;
	}

	purple_circ_buffer_mark_read(servconn->tx_buf, ret);
	servconn_timeout_renew(servconn);
}

gssize
msn_servconn_write(MsnServConn *servconn, const char *buf, size_t len)
{
	gssize ret = 0;

	g_return_val_if_fail(servconn != NULL, 0);

	if (!servconn->session->http_method)
	{
		if (servconn->tx_handler == 0) {
			switch (servconn->type)
			{
				case MSN_SERVCONN_NS:
				case MSN_SERVCONN_SB:
					ret = write(servconn->fd, buf, len);
					break;
#if 0
				case MSN_SERVCONN_DC:
					ret = write(servconn->fd, &buf, sizeof(len));
					ret = write(servconn->fd, buf, len);
					break;
#endif
				default:
					ret = write(servconn->fd, buf, len);
					break;
			}
		} else {
			ret = -1;
			errno = EAGAIN;
		}

		if (ret < 0 && errno == EAGAIN)
			ret = 0;
		if (ret >= 0 && ret < len) {
			if (servconn->tx_handler == 0)
				servconn->tx_handler = purple_input_add(
					servconn->fd, PURPLE_INPUT_WRITE,
					servconn_write_cb, servconn);
			purple_circ_buffer_append(servconn->tx_buf, buf + ret,
				len - ret);
		}
	}
	else
	{
		ret = msn_httpconn_write(servconn->httpconn, buf, len);
	}

	if (ret == -1)
	{
		msn_servconn_got_error(servconn, MSN_SERVCONN_ERROR_WRITE, NULL);
	}

	servconn_timeout_renew(servconn);
	return ret;
}

static void
read_cb(gpointer data, gint source, PurpleInputCondition cond)
{
	MsnServConn *servconn;
	char buf[MSN_BUF_LEN];
	gssize len;

	servconn = data;

	if (servconn->type == MSN_SERVCONN_NS)
		servconn->session->account->gc->last_received = time(NULL);

	len = read(servconn->fd, buf, sizeof(buf) - 1);
	if (len < 0 && errno == EAGAIN)
		return;
	if (len <= 0) {
		purple_debug_error("msn", "servconn %03d read error, "
			"len: %" G_GSSIZE_FORMAT ", errno: %d, error: %s\n",
			servconn->num, len, errno, g_strerror(errno));
		msn_servconn_got_error(servconn, MSN_SERVCONN_ERROR_READ, NULL);

		return;
	}

	buf[len] = '\0';

	servconn->rx_buf = g_realloc(servconn->rx_buf, len + servconn->rx_len + 1);
	memcpy(servconn->rx_buf + servconn->rx_len, buf, len + 1);
	servconn->rx_len += len;

	servconn = msn_servconn_process_data(servconn);
	if (servconn)
		servconn_timeout_renew(servconn);
}

MsnServConn *msn_servconn_process_data(MsnServConn *servconn)
{
	char *cur, *end, *old_rx_buf;
	int cur_len;

	end = old_rx_buf = servconn->rx_buf;

	servconn->processing = TRUE;

	do
	{
		cur = end;

		if (servconn->payload_len)
		{
			if (servconn->payload_len > servconn->rx_len)
				/* The payload is still not complete. */
				break;

			cur_len = servconn->payload_len;
			end += cur_len;
		}
		else
		{
			end = strstr(cur, "\r\n");

			if (end == NULL)
				/* The command is still not complete. */
				break;

			*end = '\0';
			end += 2;
			cur_len = end - cur;
		}

		servconn->rx_len -= cur_len;

		if (servconn->payload_len)
		{
			msn_cmdproc_process_payload(servconn->cmdproc, cur, cur_len);
			servconn->payload_len = 0;
		}
		else
		{
			msn_cmdproc_process_cmd_text(servconn->cmdproc, cur);
			servconn->payload_len = servconn->cmdproc->last_cmd->payload_len;
		}
	} while (servconn->connected && !servconn->wasted && servconn->rx_len > 0);

	if (servconn->connected && !servconn->wasted)
	{
		if (servconn->rx_len > 0)
			servconn->rx_buf = g_memdup(cur, servconn->rx_len);
		else
			servconn->rx_buf = NULL;
	}

	servconn->processing = FALSE;

	if (servconn->wasted) {
		msn_servconn_destroy(servconn);
		servconn = NULL;
	}

	g_free(old_rx_buf);
	return servconn;
}

#if 0
static int
create_listener(int port)
{
	int fd;
	int flags;
	const int on = 1;

#if 0
	struct addrinfo hints;
	struct addrinfo *c, *res;
	char port_str[5];

	snprintf(port_str, sizeof(port_str), "%d", port);

	memset(&hints, 0, sizeof(hints));

	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if (getaddrinfo(NULL, port_str, &hints, &res) != 0)
	{
		purple_debug_error("msn", "Could not get address info: %s.\n",
						 port_str);
		return -1;
	}

	for (c = res; c != NULL; c = c->ai_next)
	{
		fd = socket(c->ai_family, c->ai_socktype, c->ai_protocol);

		if (fd < 0)
			continue;

		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

		if (bind(fd, c->ai_addr, c->ai_addrlen) == 0)
			break;

		close(fd);
	}

	if (c == NULL)
	{
		purple_debug_error("msn", "Could not find socket: %s.\n", port_str);
		return -1;
	}

	freeaddrinfo(res);
#else
	struct sockaddr_in sockin;

	fd = socket(AF_INET, SOCK_STREAM, 0);

	if (fd < 0)
		return -1;

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on)) != 0)
	{
		close(fd);
		return -1;
	}

	memset(&sockin, 0, sizeof(struct sockaddr_in));
	sockin.sin_family = AF_INET;
	sockin.sin_port = htons(port);

	if (bind(fd, (struct sockaddr *)&sockin, sizeof(struct sockaddr_in)) != 0)
	{
		close(fd);
		return -1;
	}
#endif

	if (listen (fd, 4) != 0)
	{
		close (fd);
		return -1;
	}

	flags = fcntl(fd, F_GETFL);
	fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#ifndef _WIN32
	fcntl(fd, F_SETFD, FD_CLOEXEC);
#endif

	return fd;
}
#endif
