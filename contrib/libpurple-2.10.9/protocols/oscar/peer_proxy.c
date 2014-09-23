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

#ifdef HAVE_CONFIG_H
#include  <config.h>
#endif

#include "oscar.h"
#include "peer.h"

static void
peer_proxy_send(PeerConnection *conn, ProxyFrame *frame)
{
	size_t length;
	ByteStream bs;

	purple_debug_info("oscar", "Outgoing peer proxy frame with "
			"type=0x%04hx, unknown=0x%08x, flags=0x%04hx, and "
			"payload length=%" G_GSIZE_FORMAT "\n",
			frame->type, frame->unknown,
			frame->flags, frame->payload.len);

	length = 12 + frame->payload.len;
	byte_stream_new(&bs, length);
	byte_stream_put16(&bs, length - 2);
	byte_stream_put16(&bs, PEER_PROXY_PACKET_VERSION);
	byte_stream_put16(&bs, frame->type);
	byte_stream_put32(&bs, frame->unknown);
	byte_stream_put16(&bs, frame->flags);
	byte_stream_putraw(&bs, frame->payload.data, frame->payload.len);

	peer_connection_send(conn, &bs);

	byte_stream_destroy(&bs);
}

/**
 * Create a rendezvous "init send" packet and send it on its merry way.
 * This is the first packet sent to the proxy server by the first client
 * to indicate that this will be a proxied connection
 *
 * @param conn The peer connection.
 */
static void
peer_proxy_send_create_new_conn(PeerConnection *conn)
{
	ProxyFrame frame;
	PurpleAccount *account;
	const gchar *bn;
	guint8 bn_length;

	memset(&frame, 0, sizeof(ProxyFrame));
	frame.type = PEER_PROXY_TYPE_CREATE;
	frame.flags = 0x0000;

	account = purple_connection_get_account(conn->od->gc);
	bn = purple_account_get_username(account);
	bn_length = strlen(bn);
	byte_stream_new(&frame.payload, 1 + bn_length + 8 + 20);
	byte_stream_put8(&frame.payload, bn_length);
	byte_stream_putraw(&frame.payload, (const guint8 *)bn, bn_length);
	byte_stream_putraw(&frame.payload, conn->cookie, 8);

	byte_stream_put16(&frame.payload, 0x0001); /* Type */
	byte_stream_put16(&frame.payload, 16); /* Length */
	byte_stream_putcaps(&frame.payload, conn->type); /* Value */

	peer_proxy_send(conn, &frame);

	byte_stream_destroy(&frame.payload);
}

/**
 * Create a rendezvous "init recv" packet and send it on its merry way.
 * This is the first packet sent to the proxy server by the second client
 * involved in this rendezvous proxy session.
 *
 * @param conn The peer connection.
 * @param pin The 2 byte PIN sent to us by the other user.  This acts
 *        as our passcode when establishing the proxy session.
 */
static void
peer_proxy_send_join_existing_conn(PeerConnection *conn, guint16 pin)
{
	ProxyFrame frame;
	PurpleAccount *account;
	const gchar *bn;
	guint8 bn_length;

	memset(&frame, 0, sizeof(ProxyFrame));
	frame.type = PEER_PROXY_TYPE_JOIN;
	frame.flags = 0x0000;

	account = purple_connection_get_account(conn->od->gc);
	bn = purple_account_get_username(account);
	bn_length = strlen(bn);
	byte_stream_new(&frame.payload, 1 + bn_length + 2 + 8 + 20);
	byte_stream_put8(&frame.payload, bn_length);
	byte_stream_putraw(&frame.payload, (const guint8 *)bn, bn_length);
	byte_stream_put16(&frame.payload, pin);
	byte_stream_putraw(&frame.payload, conn->cookie, 8);

	byte_stream_put16(&frame.payload, 0x0001); /* Type */
	byte_stream_put16(&frame.payload, 16); /* Length */
	byte_stream_putcaps(&frame.payload, conn->type); /* Value */

	peer_proxy_send(conn, &frame);

	byte_stream_destroy(&frame.payload);
}

/**
 * Handle an incoming peer proxy negotiation frame.
 */
static void
peer_proxy_recv_frame(PeerConnection *conn, ProxyFrame *frame)
{
	purple_debug_info("oscar", "Incoming peer proxy frame with "
			"type=0x%04hx, unknown=0x%08x, flags=0x%04hx, and "
			"payload length=%" G_GSIZE_FORMAT "\n", frame->type,
			frame->unknown, frame->flags, frame->payload.len);

	if (frame->type == PEER_PROXY_TYPE_CREATED)
	{
		/*
		 * Read in 2 byte port then 4 byte IP and tell the
		 * remote user to connect to it by sending an ICBM.
		 */
		guint16 pin;
		int i;
		guint8 ip[4];

		pin = byte_stream_get16(&frame->payload);
		for (i = 0; i < 4; i++)
			ip[i] = byte_stream_get8(&frame->payload);
		if (conn->type == OSCAR_CAPABILITY_DIRECTIM)
			aim_im_sendch2_odc_requestproxy(conn->od,
					conn->cookie,
					conn->bn, ip, pin, ++conn->lastrequestnumber);
		else if (conn->type == OSCAR_CAPABILITY_SENDFILE)
		{
			aim_im_sendch2_sendfile_requestproxy(conn->od,
					conn->cookie, conn->bn,
					ip, pin, ++conn->lastrequestnumber,
					(const gchar *)conn->xferdata.name,
					conn->xferdata.size, conn->xferdata.totfiles);
		}
	}
	else if (frame->type == PEER_PROXY_TYPE_READY)
	{
		purple_input_remove(conn->watcher_incoming);
		conn->watcher_incoming = 0;

		peer_connection_finalize_connection(conn);
	}
	else if (frame->type == PEER_PROXY_TYPE_ERROR)
	{
		if (byte_stream_bytes_left(&frame->payload) >= 2)
		{
			guint16 error;
			const char *msg;
			error = byte_stream_get16(&frame->payload);
			if (error == 0x000d)
				msg = "bad request";
			else if (error == 0x0010)
				msg = "initial request timed out";
			else if (error == 0x001a)
				msg ="accept period timed out";
			else
				msg = "unknown reason";
			purple_debug_info("oscar", "Proxy negotiation failed with "
					"error 0x%04hx: %s\n", error, msg);
		}
		else
		{
			purple_debug_warning("oscar", "Proxy negotiation failed with "
					"an unknown error\n");
		}
		peer_connection_trynext(conn);
	}
	else
	{
		purple_debug_warning("oscar", "Unknown peer proxy frame type 0x%04hx.\n",
				frame->type);
	}
}

static void
peer_proxy_connection_recv_cb(gpointer data, gint source, PurpleInputCondition cond)
{
	PeerConnection *conn;
	gssize read;
	ProxyFrame *frame;

	conn = data;
	frame = conn->frame;

	/* Start reading a new proxy frame */
	if (frame == NULL)
	{
		/* Read the first 12 bytes (frame length and header) */
		read = recv(conn->fd, conn->proxy_header + conn->proxy_header_received,
				12 - conn->proxy_header_received, 0);

		/* Check if the proxy server closed the connection */
		if (read == 0)
		{
			purple_debug_info("oscar", "Peer proxy server closed connection\n");
			peer_connection_trynext(conn);
			return;
		}

		/* If there was an error then close the connection */
		if (read < 0)
		{
			if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
				/* No worries */
				return;

			purple_debug_info("oscar", "Lost connection with peer proxy server\n");
			peer_connection_trynext(conn);
			return;
		}

		conn->lastactivity = time(NULL);

		/* If we don't even have the first 12 bytes then do nothing */
		conn->proxy_header_received += read;
		if (conn->proxy_header_received < 12)
			return;

		/* We only support a specific version of the proxy protocol */
		if (aimutil_get16(&conn->proxy_header[2]) != PEER_PROXY_PACKET_VERSION)
		{
			purple_debug_warning("oscar", "Expected peer proxy protocol "
				"version %u but received version %u.  Closing "
				"connection.\n", PEER_PROXY_PACKET_VERSION,
				aimutil_get16(&conn->proxy_header[2]));
			peer_connection_trynext(conn);
			return;
		}

		/* Initialize a new temporary ProxyFrame for incoming data */
		frame = g_new0(ProxyFrame, 1);
		frame->payload.len = aimutil_get16(&conn->proxy_header[0]) - 10;
		frame->version = aimutil_get16(&conn->proxy_header[2]);
		frame->type = aimutil_get16(&conn->proxy_header[4]);
		frame->unknown = aimutil_get16(&conn->proxy_header[6]);
		frame->flags = aimutil_get16(&conn->proxy_header[10]);
		if (frame->payload.len > 0)
			frame->payload.data = g_new(guint8, frame->payload.len);
		conn->frame = frame;
	}

	/* If this frame has a payload then attempt to read it */
	if (frame->payload.len - frame->payload.offset > 0)
	{
		/* Read data into the temporary buffer until it is complete */
		read = recv(conn->fd,
					&frame->payload.data[frame->payload.offset],
					frame->payload.len - frame->payload.offset,
					0);

		/* Check if the proxy server closed the connection */
		if (read == 0)
		{
			purple_debug_info("oscar", "Peer proxy server closed connection\n");
			g_free(frame->payload.data);
			g_free(frame);
			conn->frame = NULL;
			peer_connection_trynext(conn);
			return;
		}

		/* If there was an error then close the connection */
		if (read < 0)
		{
			if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
				/* No worries */
				return;

			purple_debug_info("oscar", "Lost connection with peer proxy server\n");
			g_free(frame->payload.data);
			g_free(frame);
			conn->frame = NULL;
			peer_connection_trynext(conn);
			return;
		}

		frame->payload.offset += read;
	}

	conn->lastactivity = time(NULL);
	if (frame->payload.offset < frame->payload.len)
		/* Waiting for more data to arrive */
		return;

	/* We have a complete proxy frame!  Handle it and continue reading */
	conn->frame = NULL;
	byte_stream_rewind(&frame->payload);
	peer_proxy_recv_frame(conn, frame);

	g_free(frame->payload.data);
	g_free(frame);

	conn->proxy_header_received = 0;
}

/**
 * We tried to make an outgoing connection to a proxy server.  It
 * either connected or failed to connect.
 */
void
peer_proxy_connection_established_cb(gpointer data, gint source, const gchar *error_message)
{
	PeerConnection *conn;

	conn = data;

	conn->verified_connect_data = NULL;

	if (source < 0)
	{
		peer_connection_trynext(conn);
		return;
	}

	conn->fd = source;
	conn->watcher_incoming = purple_input_add(conn->fd,
			PURPLE_INPUT_READ, peer_proxy_connection_recv_cb, conn);

	if (conn->proxyip != NULL)
		/* Connect to the session created by the remote user */
		peer_proxy_send_join_existing_conn(conn, conn->port);
	else
		/* Create a new session */
		peer_proxy_send_create_new_conn(conn);
}
