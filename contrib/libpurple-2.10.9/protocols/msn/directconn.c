/**
 * @file directconn.c MSN direct connection functions
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
#include "cipher.h"
#include "debug.h"

#include "msn.h"
#include "msnutils.h"
#include "directconn.h"

#include "slp.h"
#include "slpmsg.h"
#include "p2p.h"

#define DC_MAX_BODY_SIZE      8*1024
#define DC_MAX_PACKET_SIZE    (P2P_PACKET_HEADER_SIZE + DC_MAX_BODY_SIZE)

static void
msn_dc_calculate_nonce_hash(MsnDirectConnNonceType type,
                            const guchar *nonce, gsize nonce_len, gchar nonce_hash[37])
{
	guchar digest[20];

	if (type == DC_NONCE_SHA1) {
		PurpleCipher *cipher = purple_ciphers_find_cipher("sha1");
		PurpleCipherContext *context = purple_cipher_context_new(cipher, NULL);
		purple_cipher_context_append(context, nonce, nonce_len);
		purple_cipher_context_digest(context, sizeof(digest), digest, NULL);
		purple_cipher_context_destroy(context);
	} else if (type == DC_NONCE_PLAIN) {
		memcpy(digest, nonce, nonce_len);
	} else {
		nonce_hash[0] = '\0';
		g_return_if_reached();
	}

	g_sprintf(nonce_hash,
	          "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",

	          digest[3],
	          digest[2],
	          digest[1],
	          digest[0],

	          digest[5],
	          digest[4],

	          digest[7],
	          digest[6],

	          digest[8],
	          digest[9],

	          digest[10],
	          digest[11],
	          digest[12],
	          digest[13],
	          digest[14],
	          digest[15]
	);
}

static void
msn_dc_generate_nonce(MsnDirectConn *dc)
{
	guint32 *nonce;
	int i;

	nonce = (guint32 *)&dc->nonce;
	for (i = 0; i < 4; i++)
		nonce[i] = rand();

	msn_dc_calculate_nonce_hash(dc->nonce_type, dc->nonce, sizeof(dc->nonce), dc->nonce_hash);

	if (purple_debug_is_verbose())
		purple_debug_info("msn", "DC %p generated nonce %s\n", dc, dc->nonce_hash);
}

static MsnDirectConnPacket *
msn_dc_new_packet(guint32 length)
{
	MsnDirectConnPacket	*p;

	p = g_new0(MsnDirectConnPacket, 1);
	p->length = length;
	p->data = g_malloc(length);

	return p;
}

static void
msn_dc_destroy_packet(MsnDirectConnPacket *p)
{
	g_free(p->data);

	if (p->part)
		msn_slpmsgpart_unref(p->part);

	g_free(p);
}

MsnDirectConn *
msn_dc_new(MsnSlpCall *slpcall)
{
	MsnDirectConn *dc;

	g_return_val_if_fail(slpcall != NULL, NULL);

	dc = g_new0(MsnDirectConn, 1);

	if (purple_debug_is_verbose())
		purple_debug_info("msn", "msn_dc_new %p\n", dc);

	dc->slplink = slpcall->slplink;
	dc->slpcall = slpcall;

	if (dc->slplink->dc != NULL)
		purple_debug_warning("msn", "msn_dc_new: slplink already has an allocated DC!\n");

	dc->slplink->dc = dc;

	dc->msg_body = NULL;
	dc->prev_ack = NULL;
	dc->listen_data = NULL;
	dc->connect_data = NULL;
	dc->listenfd = -1;
	dc->listenfd_handle = 0;
	dc->connect_timeout_handle = 0;
	dc->fd = -1;
	dc->recv_handle = 0;
	dc->send_handle = 0;
	dc->state = DC_STATE_CLOSED;
	dc->in_buffer = NULL;
	dc->out_queue = g_queue_new();
	dc->msg_pos = -1;
	dc->send_connection_info_msg_cb = NULL;
	dc->ext_ip = NULL;
	dc->timeout_handle = 0;
	dc->progress = FALSE;
	/*dc->num_calls = 1;*/

	/* TODO: Probably should set this based on buddy caps */
	dc->nonce_type = DC_NONCE_PLAIN;
	msn_dc_generate_nonce(dc);

	return dc;
}

void
msn_dc_destroy(MsnDirectConn *dc)
{
	MsnSlpLink *slplink;

	if (purple_debug_is_verbose())
		purple_debug_info("msn", "msn_dc_destroy %p\n", dc);

	g_return_if_fail(dc != NULL);

	if (dc->slpcall != NULL)
		dc->slpcall->wait_for_socket = FALSE;

	slplink = dc->slplink;
	if (slplink) {
		slplink->dc = NULL;
		if (slplink->swboard == NULL)
			msn_slplink_unref(slplink);
	}

	g_free(dc->msg_body);

	if (dc->prev_ack) {
		msn_slpmsg_destroy(dc->prev_ack);
	}

	if (dc->listen_data != NULL) {
		purple_network_listen_cancel(dc->listen_data);
	}

	if (dc->connect_data != NULL) {
		purple_proxy_connect_cancel(dc->connect_data);
	}

	if (dc->listenfd != -1) {
		purple_network_remove_port_mapping(dc->listenfd);
		close(dc->listenfd);
	}

	if (dc->listenfd_handle != 0) {
		purple_input_remove(dc->listenfd_handle);
	}

	if (dc->connect_timeout_handle != 0) {
		purple_timeout_remove(dc->connect_timeout_handle);
	}

	if (dc->fd != -1) {
		close(dc->fd);
	}

	if (dc->send_handle != 0) {
		purple_input_remove(dc->send_handle);
	}

	if (dc->recv_handle != 0) {
		purple_input_remove(dc->recv_handle);
	}

	g_free(dc->in_buffer);

	if (dc->out_queue != NULL) {
		while (!g_queue_is_empty(dc->out_queue))
			msn_dc_destroy_packet( g_queue_pop_head(dc->out_queue) );

		g_queue_free(dc->out_queue);
	}

	g_free(dc->ext_ip);

	if (dc->timeout_handle != 0) {
		purple_timeout_remove(dc->timeout_handle);
	}

	g_free(dc);
}

/*
void
msn_dc_ref(MsnDirectConn *dc)
{
	g_return_if_fail(dc != NULL);

	dc->num_calls++;
}

void
msn_dc_unref(MsnDirectConn *dc)
{
	g_return_if_fail(dc != NULL);


	if (dc->num_calls > 0) {
		dc->num_calls--;
	}
}
*/

void
msn_dc_send_invite(MsnDirectConn *dc)
{
	MsnSlpCall    *slpcall;
	MsnSlpMessage *msg;
	gchar *header;

	if (purple_debug_is_verbose())
		purple_debug_info("msn", "msn_dc_send_invite %p\n", dc);

	g_return_if_fail(dc != NULL);

	slpcall = dc->slpcall;
	g_return_if_fail(slpcall != NULL);

	header = g_strdup_printf(
		"INVITE MSNMSGR:%s MSNSLP/1.0",
		slpcall->slplink->remote_user
	);

	msg = msn_slpmsg_sip_new(
		slpcall,
		0,
		header,
		slpcall->branch,
		"application/x-msnmsgr-transrespbody",
		dc->msg_body
	);
	msg->info = "DC INVITE";
	msg->text_body = TRUE;
	g_free(header);
	g_free(dc->msg_body);
	dc->msg_body = NULL;

	msn_slplink_queue_slpmsg(slpcall->slplink, msg);
}

void
msn_dc_send_ok(MsnDirectConn *dc)
{
	if (purple_debug_is_verbose())
		purple_debug_info("msn", "msn_dc_send_ok %p\n", dc);

	g_return_if_fail(dc != NULL);

	msn_slp_send_ok(dc->slpcall, dc->slpcall->branch,
		"application/x-msnmsgr-transrespbody", dc->msg_body);
	g_free(dc->msg_body);
	dc->msg_body = NULL;

	msn_slplink_send_slpmsg(dc->slpcall->slplink, dc->prev_ack);
	msn_slpmsg_destroy(dc->prev_ack);
	dc->prev_ack = NULL;
	msn_slplink_send_queued_slpmsgs(dc->slpcall->slplink);
}

void
msn_dc_fallback_to_sb(MsnDirectConn *dc)
{
	MsnSlpLink *slplink;
	MsnSlpCall *slpcall;
	GQueue *queue = NULL;

	purple_debug_info("msn", "msn_dc_fallback_to_sb %p\n", dc);

	g_return_if_fail(dc != NULL);

	slpcall = dc->slpcall;
	slplink = msn_slplink_ref(dc->slplink);
	if (slpcall && !g_queue_is_empty(dc->out_queue)) {
		queue = dc->out_queue;
		dc->out_queue = NULL;
	}

	msn_dc_destroy(dc);

	if (slpcall) {
		msn_slpcall_session_init(slpcall);
		if (queue) {
			while (!g_queue_is_empty(queue)) {
				MsnDirectConnPacket *p = g_queue_pop_head(queue);
				msn_slplink_send_msgpart(slplink, (MsnSlpMessage*)p->part->ack_data);
				msn_dc_destroy_packet(p);
			}
			g_queue_free(queue);
		}
	}
	msn_slplink_unref(slplink);
}

static void
msn_dc_send_cb(gpointer data, gint fd, PurpleInputCondition cond)
{
	MsnDirectConn *dc = data;
	MsnDirectConnPacket *p;
	int bytes_to_send;
	int bytes_sent;

	g_return_if_fail(dc != NULL);
	g_return_if_fail(fd != -1);

	if (g_queue_is_empty(dc->out_queue)) {
		if (dc->send_handle != 0) {
			purple_input_remove(dc->send_handle);
			dc->send_handle = 0;
		}
		return;
	}

	p = g_queue_peek_head(dc->out_queue);

	if (dc->msg_pos < 0) {
		/* First we send the length of the packet */
		guint32 len = GUINT32_TO_LE(p->length);
		bytes_sent = send(fd, &len, 4, 0);
		if (bytes_sent < 0) {
			if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
				return;

			purple_debug_warning("msn", "msn_dc_send_cb: send error\n");
			msn_dc_destroy(dc);
			return;
		}
		dc->msg_pos = 0;
	}

	bytes_to_send = p->length - dc->msg_pos;
	bytes_sent = send(fd, p->data + dc->msg_pos, bytes_to_send, 0);
	if (bytes_sent < 0) {
		if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
			return;

		purple_debug_warning("msn", "msn_dc_send_cb: send error\n");
		msn_dc_destroy(dc);
		return;
	}

	dc->progress = TRUE;

	dc->msg_pos += bytes_sent;
	if (dc->msg_pos == p->length) {
		if (p->sent_cb != NULL)
			p->sent_cb(p);

		g_queue_pop_head(dc->out_queue);
		msn_dc_destroy_packet(p);

		dc->msg_pos = -1;
	}
}

static void
msn_dc_enqueue_packet(MsnDirectConn *dc, MsnDirectConnPacket *p)
{
	gboolean was_empty;

	was_empty = g_queue_is_empty(dc->out_queue);
	g_queue_push_tail(dc->out_queue, p);

	if (was_empty && dc->send_handle == 0) {
		dc->send_handle = purple_input_add(dc->fd, PURPLE_INPUT_WRITE, msn_dc_send_cb, dc);
		msn_dc_send_cb(dc, dc->fd, PURPLE_INPUT_WRITE);
	}
}

static void
msn_dc_send_foo(MsnDirectConn *dc)
{
	MsnDirectConnPacket	*p;

	if (purple_debug_is_verbose())
		purple_debug_info("msn", "msn_dc_send_foo %p\n", dc);

	p = msn_dc_new_packet(4);

	memcpy(p->data, "foo\0", 4);

	msn_dc_enqueue_packet(dc, p);
}

#if 0 /* We don't actually need this */
typedef struct {
	guint32 null;
	guint32 id;
	guint32 null[5];
	guint32 flags;
	guint8  nonce[16];
} MsnDirectConnNoncePacket;
#endif
#define DC_NONCE_PACKET_SIZE (8 * 4 + 16)
#define DC_NONCE_PACKET_NONCE (8 * 4)

static void
msn_dc_send_handshake(MsnDirectConn *dc)
{
	MsnDirectConnPacket *p;
	gchar *h;

	p = msn_dc_new_packet(DC_NONCE_PACKET_SIZE);
	h = (gchar *)p->data;

	msn_push32le(h, 0); /* NUL */

	msn_push32le(h, dc->slpcall->slplink->slp_seq_id++);

	/* More NUL stuff */
	msn_push64le(h, 0);
	msn_push64le(h, 0);
	msn_push32le(h, 0);

	/* Flags */
	msn_push32le(h, P2P_DC_HANDSHAKE);

	/* The real Nonce, yay! */
	memcpy(h, dc->nonce, 16);

	msn_dc_enqueue_packet(dc, p);
}

static gboolean
msn_dc_verify_handshake(MsnDirectConn *dc, guint32 packet_length)
{
	guchar nonce[16];
	gchar  nonce_hash[37];

	if (packet_length != DC_NONCE_PACKET_SIZE)
		return FALSE;

	memcpy(nonce, dc->in_buffer + 4 + DC_NONCE_PACKET_NONCE, sizeof(nonce));

	if (dc->nonce_type == DC_NONCE_PLAIN) {
		if (memcmp(dc->nonce, nonce, sizeof(nonce)) == 0) {
			purple_debug_info("msn",
					"Nonce from buddy request and nonce from DC attempt match, "
					"allowing direct connection\n");
			return TRUE;
		} else {
			purple_debug_warning("msn",
					"Nonce from buddy request and nonce from DC attempt "
					"don't match, ignoring direct connection\n");
			return FALSE;
		}

	} else if (dc->nonce_type == DC_NONCE_SHA1) {
		msn_dc_calculate_nonce_hash(dc->nonce_type, nonce, sizeof(nonce), nonce_hash);

		if (g_str_equal(dc->remote_nonce, nonce_hash)) {
			purple_debug_info("msn",
					"Received nonce %s from buddy request "
					"and calculated nonce %s from DC attempt. "
					"Nonces match, allowing direct connection\n",
					dc->remote_nonce, nonce_hash);
			return TRUE;
		} else {
			purple_debug_warning("msn",
					"Received nonce %s from buddy request "
					"and calculated nonce %s from DC attempt. "
					"Nonces don't match, ignoring direct connection\n",
					dc->remote_nonce, nonce_hash);
			return FALSE;
		}
	} else
		return FALSE;
}

static void
msn_dc_send_packet_cb(MsnDirectConnPacket *p)
{
	if (p->part != NULL && p->part->ack_cb != NULL)
		p->part->ack_cb(p->part, p->part->ack_data);
}

void
msn_dc_enqueue_part(MsnDirectConn *dc, MsnSlpMessagePart *part)
{
	MsnDirectConnPacket *p;
	size_t length;

	p = msn_dc_new_packet(0);
	p->data = (guchar *)msn_slpmsgpart_serialize(part, &length);
	p->length = length - P2P_PACKET_FOOTER_SIZE; /* DC doesn't need footer? */

	p->sent_cb = msn_dc_send_packet_cb;
	p->part = msn_slpmsgpart_ref(part);

	msn_dc_enqueue_packet(dc, p);
}

static int
msn_dc_process_packet(MsnDirectConn *dc, guint32 packet_length)
{
	MsnSlpMessagePart *part;

	g_return_val_if_fail(dc != NULL, DC_PROCESS_ERROR);

	switch (dc->state) {
	case DC_STATE_CLOSED:
		break;

	case DC_STATE_FOO:
		/* FOO message is always 4 bytes long */
		if (packet_length != 4 || memcmp(dc->in_buffer, "\4\0\0\0foo", 8) != 0)
			return DC_PROCESS_FALLBACK;

		dc->state = DC_STATE_HANDSHAKE;
		break;

	case DC_STATE_HANDSHAKE:
		if (!msn_dc_verify_handshake(dc, packet_length))
			return DC_PROCESS_FALLBACK;

		msn_dc_send_handshake(dc);
		dc->state = DC_STATE_ESTABLISHED;

		msn_slpcall_session_init(dc->slpcall);
		dc->slpcall = NULL;
		break;

	case DC_STATE_HANDSHAKE_REPLY:
		if (!msn_dc_verify_handshake(dc, packet_length))
			return DC_PROCESS_FALLBACK;

		dc->state = DC_STATE_ESTABLISHED;

		msn_slpcall_session_init(dc->slpcall);
		dc->slpcall = NULL;
		break;

	case DC_STATE_ESTABLISHED:
		if (packet_length) {
			MsnP2PVersion p2p;
			p2p = msn_slplink_get_p2p_version(dc->slplink);
			part = msn_slpmsgpart_new_from_data(p2p, dc->in_buffer + 4, packet_length);
			if (part) {
				msn_slplink_process_msg(dc->slplink, part);
				msn_slpmsgpart_unref(part);
			}
		}

		/*
		if (dc->num_calls == 0) {
			msn_dc_destroy(dc);

			return DC_PROCESS_CLOSE;
		}
		*/
		break;
	}

	return DC_PROCESS_OK;
}

static void
msn_dc_recv_cb(gpointer data, gint fd, PurpleInputCondition cond)
{
	MsnDirectConn *dc;
	int free_buf_space;
	int bytes_received;
	guint32 packet_length;

	g_return_if_fail(data != NULL);
	g_return_if_fail(fd != -1);

	dc = data;
	free_buf_space = dc->in_size - dc->in_pos;

	bytes_received = recv(fd, dc->in_buffer + dc->in_pos, free_buf_space, 0);
	if (bytes_received < 0) {
		if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
			return;

		purple_debug_warning("msn", "msn_dc_recv_cb: recv error\n");

		if(dc->state != DC_STATE_ESTABLISHED)
			msn_dc_fallback_to_sb(dc);
		else
			msn_dc_destroy(dc);
		return;

	} else if (bytes_received == 0) {
		/* EOF. Remote side closed connection. */
		purple_debug_info("msn", "msn_dc_recv_cb: recv EOF\n");

		if(dc->state != DC_STATE_ESTABLISHED)
			msn_dc_fallback_to_sb(dc);
		else
			msn_dc_destroy(dc);
		return;
	}

	dc->progress = TRUE;

	dc->in_pos += bytes_received;

	/* Wait for packet length */
	while (dc->in_pos >= 4) {
		packet_length = GUINT32_FROM_LE(*((guint32*)dc->in_buffer));

		if (packet_length > DC_MAX_PACKET_SIZE) {
			/* Oversized packet */
			purple_debug_warning("msn", "msn_dc_recv_cb: oversized packet received\n");
			return;
		}

		/* Wait for the whole packet to arrive */
		if (dc->in_pos < 4 + packet_length)
			return;

		switch (msn_dc_process_packet(dc, packet_length)) {
		case DC_PROCESS_CLOSE:
			return;

		case DC_PROCESS_FALLBACK:
			purple_debug_warning("msn", "msn_dc_recv_cb: packet processing error, fall back to SB\n");
			msn_dc_fallback_to_sb(dc);
			return;

		}

		if (dc->in_pos > packet_length + 4) {
			g_memmove(dc->in_buffer, dc->in_buffer + 4 + packet_length, dc->in_pos - packet_length - 4);
		}

		dc->in_pos -= packet_length + 4;
	}
}

static gboolean
msn_dc_timeout(gpointer data)
{
	MsnDirectConn *dc = data;

	g_return_val_if_fail(dc != NULL, FALSE);

	if (dc->progress) {
		dc->progress = FALSE;
		return TRUE;
	} else {
		dc->timeout_handle = 0;
		msn_dc_destroy(dc);
		return FALSE;
	}
}

static void
msn_dc_init(MsnDirectConn *dc)
{
	g_return_if_fail(dc != NULL);

	dc->in_size = DC_MAX_PACKET_SIZE + 4;
	dc->in_pos = 0;
	dc->in_buffer = g_malloc(dc->in_size);

	dc->recv_handle = purple_input_add(dc->fd, PURPLE_INPUT_READ, msn_dc_recv_cb, dc);
	dc->send_handle = purple_input_add(dc->fd, PURPLE_INPUT_WRITE, msn_dc_send_cb, dc);

	dc->timeout_handle = purple_timeout_add_seconds(DC_TIMEOUT, msn_dc_timeout, dc);
}

void
msn_dc_connected_to_peer_cb(gpointer data, gint fd, const gchar *error_msg)
{
	MsnDirectConn *dc = data;

	if (purple_debug_is_verbose())
		purple_debug_info("msn", "msn_dc_connected_to_peer_cb %p\n", dc);

	g_return_if_fail(dc != NULL);

	dc->connect_data = NULL;
	purple_timeout_remove(dc->connect_timeout_handle);
	dc->connect_timeout_handle = 0;

	dc->fd = fd;
	if (dc->fd != -1) {
		msn_dc_init(dc);
		msn_dc_send_foo(dc);
		msn_dc_send_handshake(dc);
		dc->state = DC_STATE_HANDSHAKE_REPLY;
	}
}

/*
 * This callback will be called when we're the server
 * and nobody has connected us in DC_INCOMING_TIMEOUT seconds
 */
static gboolean
msn_dc_incoming_connection_timeout_cb(gpointer data) {
	MsnDirectConn *dc = data;

	if (purple_debug_is_verbose())
		purple_debug_info("msn", "msn_dc_incoming_connection_timeout_cb %p\n", dc);

	g_return_val_if_fail(dc != NULL, FALSE);

	if (dc->listen_data != NULL) {
		purple_network_listen_cancel(dc->listen_data);
		dc->listen_data = NULL;
	}

	if (dc->listenfd_handle != 0) {
		purple_input_remove(dc->listenfd_handle);
		dc->listenfd_handle = 0;
	}

	if (dc->listenfd != -1) {
		purple_network_remove_port_mapping(dc->listenfd);
		close(dc->listenfd);
		dc->listenfd = -1;
	}

	dc->connect_timeout_handle = 0;
	msn_dc_fallback_to_sb(dc);

	return FALSE;
}

/*
 * This callback will be called when we're unable to connect to
 * the remote host in DC_OUTGOING_TIMEOUT seconds.
 */
gboolean
msn_dc_outgoing_connection_timeout_cb(gpointer data)
{
	MsnDirectConn *dc = data;

	purple_debug_info("msn", "msn_dc_outgoing_connection_timeout_cb %p\n", dc);

	g_return_val_if_fail(dc != NULL, FALSE);

	dc->connect_timeout_handle = 0;

	if (dc->connect_data != NULL) {
		purple_proxy_connect_cancel(dc->connect_data);
		dc->connect_data = NULL;
	}

	if (dc->ext_ip && dc->ext_port) {
		/* Try external IP/port if available. */
		dc->connect_data = purple_proxy_connect(
			NULL,
			dc->slpcall->slplink->session->account,
			dc->ext_ip,
			dc->ext_port,
			msn_dc_connected_to_peer_cb,
			dc
		);

		g_free(dc->ext_ip);
		dc->ext_ip = NULL;

		if (dc->connect_data) {
			dc->connect_timeout_handle = purple_timeout_add_seconds(
				DC_OUTGOING_TIMEOUT,
				msn_dc_outgoing_connection_timeout_cb,
				dc
			);
		} else {
			/*
			 * Connection failed
			 * Fall back to SB transfer
			 */
			msn_dc_outgoing_connection_timeout_cb(dc);
		}

	} else {
		/*
		 * Both internal and external connection attempts failed.
		 * Fall back to SB transfer.
		 */
		msn_dc_fallback_to_sb(dc);
	}

	return FALSE;
}

/*
 * This callback will be called when we're the server
 * and somebody has connected to us in DC_INCOMING_TIMEOUT seconds.
 */
static void
msn_dc_incoming_connection_cb(gpointer data, gint listenfd, PurpleInputCondition cond)
{
	MsnDirectConn *dc = data;

	if (purple_debug_is_verbose())
		purple_debug_info("msn", "msn_dc_incoming_connection_cb %p\n", dc);

	g_return_if_fail(dc != NULL);

	if (dc->connect_timeout_handle != 0) {
		purple_timeout_remove(dc->connect_timeout_handle);
		dc->connect_timeout_handle = 0;
	}

	if (dc->listenfd_handle != 0) {
		purple_input_remove(dc->listenfd_handle);
		dc->listenfd_handle = 0;
	}

	dc->fd = accept(listenfd, NULL, 0);

	purple_network_remove_port_mapping(dc->listenfd);
	close(dc->listenfd);
	dc->listenfd = -1;

	if (dc->fd != -1) {
		msn_dc_init(dc);
		dc->state = DC_STATE_FOO;
	}
}

void
msn_dc_listen_socket_created_cb(int listenfd, gpointer data)
{
	MsnDirectConn *dc = data;

	if (purple_debug_is_verbose())
		purple_debug_info("msn", "msn_dc_listen_socket_created_cb %p\n", dc);

	g_return_if_fail(dc != NULL);

	dc->listen_data = NULL;

	if (listenfd != -1) {
		const char *ext_ip;
		const char *int_ip;
		int port;

		ext_ip = purple_network_get_my_ip(listenfd);
		int_ip = purple_network_get_local_system_ip(listenfd);
		port = purple_network_get_port_from_fd(listenfd);

		dc->listenfd = listenfd;
		dc->listenfd_handle = purple_input_add(
			listenfd,
			PURPLE_INPUT_READ,
			msn_dc_incoming_connection_cb,
			dc
		);
		dc->connect_timeout_handle = purple_timeout_add_seconds(
			DC_INCOMING_TIMEOUT,
			msn_dc_incoming_connection_timeout_cb,
			dc
		);

		if (strcmp(int_ip, ext_ip) != 0) {
			dc->msg_body = g_strdup_printf(
				"Bridge: TCPv1\r\n"
				"Listening: true\r\n"
				"%sNonce: {%s}\r\n"
				"IPv4External-Addrs: %s\r\n"
				"IPv4External-Port: %d\r\n"
				"IPv4Internal-Addrs: %s\r\n"
				"IPv4Internal-Port: %d\r\n"
				"\r\n",

				dc->nonce_type != DC_NONCE_PLAIN ? "Hashed-" : "",
				dc->nonce_hash,
				ext_ip,
				port,
				int_ip,
				port
			);

		} else {
			dc->msg_body = g_strdup_printf(
				"Bridge: TCPv1\r\n"
				"Listening: true\r\n"
				"%sNonce: {%s}\r\n"
				"IPv4External-Addrs: %s\r\n"
				"IPv4External-Port: %d\r\n"
				"\r\n",

				dc->nonce_type != DC_NONCE_PLAIN ? "Hashed-" : "",
				dc->nonce_hash,
				ext_ip,
				port
			);
		}

		if (dc->slpcall->wait_for_socket) {
			if (dc->send_connection_info_msg_cb != NULL)
				dc->send_connection_info_msg_cb(dc);

			dc->slpcall->wait_for_socket = FALSE;
		}
	}
}

