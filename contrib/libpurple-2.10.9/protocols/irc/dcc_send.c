/**
 * @file dcc_send.c Functions used in sending files with DCC SEND
 *
 * purple
 *
 * Copyright (C) 2004, Timothy T Ringenbach <omarvo@hotmail.com>
 * Copyright (C) 2003, Robbert Haarman <purple@inglorion.net>
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
#include "irc.h"
#include "debug.h"
#include "ft.h"
#include "notify.h"
#include "network.h"

/***************************************************************************
 * Functions related to receiving files via DCC SEND
 ***************************************************************************/

struct irc_xfer_rx_data {
	gchar *ip;
};

static void irc_dccsend_recv_destroy(PurpleXfer *xfer)
{
	struct irc_xfer_rx_data *xd = xfer->data;

	g_free(xd->ip);
	g_free(xd);
}

/*
 * This function is called whenever data is received.
 * It sends the acknowledgement (in the form of a total byte count as an
 * unsigned 4 byte integer in network byte order)
 */
static void irc_dccsend_recv_ack(PurpleXfer *xfer, const guchar *data, size_t size) {
	guint32 l;
	size_t result;

	l = htonl(xfer->bytes_sent);
	result = write(xfer->fd, &l, sizeof(l));
	if (result != sizeof(l)) {
		purple_debug_error("irc", "unable to send acknowledgement: %s\n", g_strerror(errno));
		/* TODO: We should probably close the connection here or something. */
	}
}

static void irc_dccsend_recv_init(PurpleXfer *xfer) {
	struct irc_xfer_rx_data *xd = xfer->data;

	purple_xfer_start(xfer, -1, xd->ip, xfer->remote_port);
	g_free(xd->ip);
	xd->ip = NULL;
}

/* This function makes the necessary arrangements for receiving files */
void irc_dccsend_recv(struct irc_conn *irc, const char *from, const char *msg) {
	PurpleXfer *xfer;
	struct irc_xfer_rx_data *xd;
	gchar **token;
	struct in_addr addr;
	GString *filename;
	int i = 0;
	guint32 nip;

	token = g_strsplit(msg, " ", 0);
	if (!token[0] || !token[1] || !token[2]) {
		g_strfreev(token);
		return;
	}

	filename = g_string_new("");
	if (token[0][0] == '"') {
		if (!strchr(&(token[0][1]), '"')) {
			g_string_append(filename, &(token[0][1]));
			for (i = 1; token[i]; i++)
				if (!strchr(token[i], '"')) {
					g_string_append_printf(filename, " %s", token[i]);
				} else {
					g_string_append_len(filename, token[i], strlen(token[i]) - 1);
					break;
				}
		} else {
			g_string_append_len(filename, &(token[0][1]), strlen(&(token[0][1])) - 1);
		}
	} else {
		g_string_append(filename, token[0]);
	}

	if (!token[i] || !token[i+1] || !token[i+2]) {
		g_strfreev(token);
		g_string_free(filename, TRUE);
		return;
	}
	i++;

	xfer = purple_xfer_new(irc->account, PURPLE_XFER_RECEIVE, from);
	if (xfer)
	{
		xd = g_new0(struct irc_xfer_rx_data, 1);
		xfer->data = xd;

		purple_xfer_set_filename(xfer, filename->str);
		xfer->remote_port = atoi(token[i+1]);

		nip = strtoul(token[i], NULL, 10);
		if (nip) {
			addr.s_addr = htonl(nip);
			xd->ip = g_strdup(inet_ntoa(addr));
		} else {
			xd->ip = g_strdup(token[i]);
		}
		purple_debug(PURPLE_DEBUG_INFO, "irc", "Receiving file (%s) from %s\n",
			     filename->str, xd->ip);
		purple_xfer_set_size(xfer, token[i+2] ? atoi(token[i+2]) : 0);

		purple_xfer_set_init_fnc(xfer, irc_dccsend_recv_init);
		purple_xfer_set_ack_fnc(xfer, irc_dccsend_recv_ack);

		purple_xfer_set_end_fnc(xfer, irc_dccsend_recv_destroy);
		purple_xfer_set_request_denied_fnc(xfer, irc_dccsend_recv_destroy);
		purple_xfer_set_cancel_recv_fnc(xfer, irc_dccsend_recv_destroy);

		purple_xfer_request(xfer);
	}
	g_strfreev(token);
	g_string_free(filename, TRUE);
}

/*******************************************************************
 * Functions related to sending files via DCC SEND
 *******************************************************************/

struct irc_xfer_send_data {
	PurpleNetworkListenData *listen_data;
	gint inpa;
	int fd;
	guchar *rxqueue;
	guint rxlen;
};

static void irc_dccsend_send_destroy(PurpleXfer *xfer)
{
	struct irc_xfer_send_data *xd = xfer->data;

	if (xd == NULL)
		return;

	if (xd->listen_data != NULL)
		purple_network_listen_cancel(xd->listen_data);
	if (xd->inpa > 0)
		purple_input_remove(xd->inpa);
	if (xd->fd != -1)
		close(xd->fd);

	g_free(xd->rxqueue);

	g_free(xd);
}

/* just in case you were wondering, this is why DCC is gay */
static void irc_dccsend_send_read(gpointer data, int source, PurpleInputCondition cond)
{
	PurpleXfer *xfer = data;
	struct irc_xfer_send_data *xd = xfer->data;
	char buffer[64];
	int len;

	len = read(source, buffer, sizeof(buffer));

	if (len < 0 && errno == EAGAIN)
		return;
	else if (len <= 0) {
		/* XXX: Shouldn't this be canceling the transfer? */
		purple_input_remove(xd->inpa);
		xd->inpa = 0;
		return;
	}

	xd->rxqueue = g_realloc(xd->rxqueue, len + xd->rxlen);
	memcpy(xd->rxqueue + xd->rxlen, buffer, len);
	xd->rxlen += len;

	while (1) {
		size_t acked;

		if (xd->rxlen < 4)
			break;

		acked = ntohl(*((gint32 *)xd->rxqueue));

		xd->rxlen -= 4;
		if (xd->rxlen) {
			unsigned char *tmp = g_memdup(xd->rxqueue + 4, xd->rxlen);
			g_free(xd->rxqueue);
			xd->rxqueue = tmp;
		} else {
			g_free(xd->rxqueue);
			xd->rxqueue = NULL;
		}

		if (acked >= purple_xfer_get_size(xfer)) {
			purple_input_remove(xd->inpa);
			xd->inpa = 0;
			purple_xfer_set_completed(xfer, TRUE);
			purple_xfer_end(xfer);
			return;
		}
	}
}

static gssize irc_dccsend_send_write(const guchar *buffer, size_t size, PurpleXfer *xfer)
{
	gssize s;
	int ret;

	s = MIN(purple_xfer_get_bytes_remaining(xfer), size);
	if (!s)
		return 0;

	ret = write(xfer->fd, buffer, s);

	if (ret < 0 && errno == EAGAIN)
		ret = 0;

	return ret;
}

static void irc_dccsend_send_connected(gpointer data, int source, PurpleInputCondition cond) {
	PurpleXfer *xfer = (PurpleXfer *) data;
	struct irc_xfer_send_data *xd = xfer->data;
	int conn, flags;

	conn = accept(xd->fd, NULL, 0);
	if (conn == -1) {
		/* Accepting the connection failed. This could just be related
		 * to the nonblocking nature of the listening socket, so we'll
		 * just try again next time */
		/* Let's print an error message anyway */
		purple_debug_warning("irc", "accept: %s\n", g_strerror(errno));
		return;
	}

	purple_input_remove(xfer->watcher);
	xfer->watcher = 0;
	close(xd->fd);
	xd->fd = -1;

	flags = fcntl(conn, F_GETFL);
	fcntl(conn, F_SETFL, flags | O_NONBLOCK);
#ifndef _WIN32
	fcntl(conn, F_SETFD, FD_CLOEXEC);
#endif

	xd->inpa = purple_input_add(conn, PURPLE_INPUT_READ, irc_dccsend_send_read, xfer);
	/* Start the transfer */
	purple_xfer_start(xfer, conn, NULL, 0);
}

static void
irc_dccsend_network_listen_cb(int sock, gpointer data)
{
	PurpleXfer *xfer = data;
	struct irc_xfer_send_data *xd;
	PurpleConnection *gc;
	struct irc_conn *irc;
	const char *arg[2];
	char *tmp;
	struct in_addr addr;
	unsigned short int port;

	xd = xfer->data;
	xd->listen_data = NULL;

	if (purple_xfer_get_status(xfer) == PURPLE_XFER_STATUS_CANCEL_LOCAL
			|| purple_xfer_get_status(xfer) == PURPLE_XFER_STATUS_CANCEL_REMOTE) {
		purple_xfer_unref(xfer);
		return;
	}

	xd = xfer->data;
	gc = purple_account_get_connection(purple_xfer_get_account(xfer));
	irc = gc->proto_data;

	purple_xfer_unref(xfer);

	if (sock < 0) {
		purple_notify_error(gc, NULL, _("File Transfer Failed"),
		                    _("Unable to open a listening port."));
		purple_xfer_cancel_local(xfer);
		return;
	}

	xd->fd = sock;

	port = purple_network_get_port_from_fd(sock);
	purple_debug_misc("irc", "port is %hu\n", port);
	/* Monitor the listening socket */
	xfer->watcher = purple_input_add(sock, PURPLE_INPUT_READ,
	                                 irc_dccsend_send_connected, xfer);

	/* Send the intended recipient the DCC request */
	arg[0] = xfer->who;
	inet_aton(purple_network_get_my_ip(irc->fd), &addr);
	arg[1] = tmp = g_strdup_printf("\001DCC SEND \"%s\" %u %hu %" G_GSIZE_FORMAT "\001",
	                               xfer->filename, ntohl(addr.s_addr),
	                               port, xfer->size);

	irc_cmd_privmsg(gc->proto_data, "msg", NULL, arg);
	g_free(tmp);
}

/*
 * This function is called after the user has selected a file to send.
 */
static void irc_dccsend_send_init(PurpleXfer *xfer) {
	PurpleConnection *gc = purple_account_get_connection(purple_xfer_get_account(xfer));
	struct irc_xfer_send_data *xd = xfer->data;

	xfer->filename = g_path_get_basename(xfer->local_filename);

	purple_xfer_ref(xfer);

	/* Create a listening socket */
	xd->listen_data = purple_network_listen_range(0, 0, SOCK_STREAM,
			irc_dccsend_network_listen_cb, xfer);
	if (xd->listen_data == NULL) {
		purple_xfer_unref(xfer);
		purple_notify_error(gc, NULL, _("File Transfer Failed"),
		                    _("Unable to open a listening port."));
		purple_xfer_cancel_local(xfer);
	}

}

PurpleXfer *irc_dccsend_new_xfer(PurpleConnection *gc, const char *who) {
	PurpleXfer *xfer;
	struct irc_xfer_send_data *xd;

	/* Build the file transfer handle */
	xfer = purple_xfer_new(purple_connection_get_account(gc), PURPLE_XFER_SEND, who);
	if (xfer)
	{
		xd = g_new0(struct irc_xfer_send_data, 1);
		xd->fd = -1;
		xfer->data = xd;

		/* Setup our I/O op functions */
		purple_xfer_set_init_fnc(xfer, irc_dccsend_send_init);
		purple_xfer_set_write_fnc(xfer, irc_dccsend_send_write);
		purple_xfer_set_end_fnc(xfer, irc_dccsend_send_destroy);
		purple_xfer_set_request_denied_fnc(xfer, irc_dccsend_send_destroy);
		purple_xfer_set_cancel_send_fnc(xfer, irc_dccsend_send_destroy);
	}

	return xfer;
}

/**
 * Purple calls this function when the user selects Send File from the
 * buddy menu
 * It sets up the PurpleXfer struct and tells Purple to go ahead
 */
void irc_dccsend_send_file(PurpleConnection *gc, const char *who, const char *file) {
	PurpleXfer *xfer = irc_dccsend_new_xfer(gc, who);

	/* Perform the request */
	if (file)
		purple_xfer_request_accepted(xfer, file);
	else
		purple_xfer_request(xfer);
}
