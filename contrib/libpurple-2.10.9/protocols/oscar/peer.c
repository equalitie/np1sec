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

/*
 * Functions dealing with peer connections.  This includes the code
 * used to establish a peer connection for both Oscar File transfer
 * (OFT) and Oscar Direct Connect (ODC).  (ODC is also referred to
 * as DirectIM and IM Image.)
 */

#ifdef HAVE_CONFIG_H
#include  <config.h>
#endif

/* From the oscar PRPL */
#include "oscar.h"
#include "peer.h"

/* From Purple */
#include "conversation.h"
#include "ft.h"
#include "network.h"
#include "notify.h"
#include "request.h"
#include "util.h"

#ifndef _WIN32
#include <stdio.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h> /* for inet_ntoa */
#include <limits.h> /* for UINT_MAX */
#endif

#ifdef _WIN32
#include "win32dep.h"
#endif

/*
 * I really want to switch all our networking code to using IPv6 only,
 * but that really isn't a good idea at all.  Evan S. of Adium says
 * OS X sets all connections as "AF_INET6/PF_INET6," even if there is
 * nothing inherently IPv6 about them.  And I feel like Linux kernel
 * 2.6.5 is doing the same thing.  So we REALLY should accept
 * connections if they're showing up as IPv6.  Old OSes (Solaris?)
 * that might not have full IPv6 support yet will fail if we try
 * to use PF_INET6 but it isn't defined.  --Mark Doliner
 */
#ifndef PF_INET6
#define PF_INET6 PF_INET
#endif

PeerConnection *
peer_connection_find_by_type(OscarData *od, const char *bn, guint64 type)
{
	GSList *cur;
	PeerConnection *conn;

	for (cur = od->peer_connections; cur != NULL; cur = cur->next)
	{
		conn = cur->data;
		if ((conn->type == type) && !oscar_util_name_compare(conn->bn, bn))
			return conn;
	}

	return NULL;
}

/**
 * @param cookie This must be exactly 8 characters.
 */
PeerConnection *
peer_connection_find_by_cookie(OscarData *od, const char *bn, const guchar *cookie)
{
	GSList *cur;
	PeerConnection *conn;

	for (cur = od->peer_connections; cur != NULL; cur = cur->next)
	{
		conn = cur->data;
		if (!memcmp(conn->cookie, cookie, 8) && !oscar_util_name_compare(conn->bn, bn))
			return conn;
	}

	return NULL;
}

PeerConnection *
peer_connection_new(OscarData *od, guint64 type, const char *bn)
{
	PeerConnection *conn;
	PurpleAccount *account;

	account = purple_connection_get_account(od->gc);

	conn = g_new0(PeerConnection, 1);
	conn->od = od;
	conn->type = type;
	conn->bn = g_strdup(bn);
	conn->buffer_outgoing = purple_circ_buffer_new(0);
	conn->listenerfd = -1;
	conn->fd = -1;
	conn->lastactivity = time(NULL);
	conn->use_proxy |= purple_account_get_bool(account, "always_use_rv_proxy", FALSE);

	if (type == OSCAR_CAPABILITY_DIRECTIM)
		memcpy(conn->magic, "ODC2", 4);
	else if (type == OSCAR_CAPABILITY_SENDFILE)
		memcpy(conn->magic, "OFT2", 4);

	od->peer_connections = g_slist_prepend(od->peer_connections, conn);

	return conn;
}

static void
peer_connection_close(PeerConnection *conn)
{
	if (conn->type == OSCAR_CAPABILITY_DIRECTIM)
		peer_odc_close(conn);
	else if (conn->type == OSCAR_CAPABILITY_SENDFILE)
		peer_oft_close(conn);

	if (conn->verified_connect_data != NULL)
	{
		purple_proxy_connect_cancel(conn->verified_connect_data);
		conn->verified_connect_data = NULL;
	}

	if (conn->client_connect_data != NULL)
	{
		purple_proxy_connect_cancel(conn->client_connect_data);
		conn->client_connect_data = NULL;
	}

	if (conn->listen_data != NULL)
	{
		purple_network_listen_cancel(conn->listen_data);
		conn->listen_data = NULL;
	}

	if (conn->connect_timeout_timer != 0)
	{
		purple_timeout_remove(conn->connect_timeout_timer);
		conn->connect_timeout_timer = 0;
	}

	if (conn->watcher_incoming != 0)
	{
		purple_input_remove(conn->watcher_incoming);
		conn->watcher_incoming = 0;
	}
	if (conn->watcher_outgoing != 0)
	{
		purple_input_remove(conn->watcher_outgoing);
		conn->watcher_outgoing = 0;
	}
	if (conn->listenerfd >= 0)
	{
		close(conn->listenerfd);
		conn->listenerfd = -1;
	}
	if (conn->fd >= 0)
	{
		close(conn->fd);
		conn->fd = -1;
	}

	g_free(conn->buffer_incoming.data);
	conn->buffer_incoming.data = NULL;
	conn->buffer_incoming.len = 0;
	conn->buffer_incoming.offset = 0;

	purple_circ_buffer_destroy(conn->buffer_outgoing);
	conn->buffer_outgoing = purple_circ_buffer_new(0);

	conn->flags &= ~PEER_CONNECTION_FLAG_IS_INCOMING;
}

static gboolean
peer_connection_destroy_cb(gpointer data)
{
	PeerConnection *conn;

	conn = data;

	purple_request_close_with_handle(conn);

	peer_connection_close(conn);

	if (conn->checksum_data != NULL)
		peer_oft_checksum_destroy(conn->checksum_data);

	if (conn->xfer != NULL)
	{
		PurpleXferStatusType status;
		conn->xfer->data = NULL;
		status = purple_xfer_get_status(conn->xfer);
		if ((status != PURPLE_XFER_STATUS_DONE) &&
			(status != PURPLE_XFER_STATUS_CANCEL_LOCAL) &&
			(status != PURPLE_XFER_STATUS_CANCEL_REMOTE))
		{
			if ((conn->disconnect_reason == OSCAR_DISCONNECT_REMOTE_CLOSED) ||
				(conn->disconnect_reason == OSCAR_DISCONNECT_REMOTE_REFUSED))
				purple_xfer_cancel_remote(conn->xfer);
			else
				purple_xfer_cancel_local(conn->xfer);
		}
		purple_xfer_unref(conn->xfer);
		conn->xfer = NULL;
	}

	g_free(conn->bn);
	g_free(conn->error_message);
	g_free(conn->proxyip);
	g_free(conn->clientip);
	g_free(conn->verifiedip);
	g_free(conn->xferdata.name);
	purple_circ_buffer_destroy(conn->buffer_outgoing);

	conn->od->peer_connections = g_slist_remove(conn->od->peer_connections, conn);

	g_free(conn);

	return FALSE;
}

void
peer_connection_destroy(PeerConnection *conn, OscarDisconnectReason reason, const gchar *error_message)
{
	if (conn->destroy_timeout != 0)
		purple_timeout_remove(conn->destroy_timeout);
	conn->disconnect_reason = reason;
	g_free(conn->error_message);
	conn->error_message = g_strdup(error_message);
	peer_connection_destroy_cb(conn);
}

void
peer_connection_schedule_destroy(PeerConnection *conn, OscarDisconnectReason reason, const gchar *error_message)
{
	if (conn->destroy_timeout != 0)
		/* Already taken care of */
		return;

	purple_debug_info("oscar", "Scheduling destruction of peer connection\n");
	conn->disconnect_reason = reason;
	g_free(conn->error_message);
	conn->error_message = g_strdup(error_message);
	conn->destroy_timeout = purple_timeout_add(0, peer_connection_destroy_cb, conn);
}

/*******************************************************************/
/* Begin code for receiving data on a peer connection                */
/*******************************************************************/

/**
 * This should be used to read ODC and OFT framing info.  It should
 * NOT be used to read the payload sent across the connection (IMs,
 * file data, etc), and it should NOT be used to read proxy negotiation
 * headers.
 *
 * Unlike flap_connection_recv_cb(), this only reads one frame at a
 * time.  This is done so that the watcher can be changed during the
 * handling of the frame.  If the watcher is changed then this
 * function will not read in any more data.  This happens when
 * reading the payload of a direct IM frame, or when we're
 * receiving a file from the remote user.  Once the data has been
 * read, the watcher will be switched back to this function to
 * continue reading the next frame.
 */
void
peer_connection_recv_cb(gpointer data, gint source, PurpleInputCondition cond)
{
	PeerConnection *conn;
	gssize read;

	conn = data;

	/* Start reading a new ODC/OFT frame */
	if (conn->buffer_incoming.data == NULL)
	{
		/* Read the first 6 bytes (magic string and frame length) */
		read = recv(conn->fd, conn->header + conn->header_received,
				6 - conn->header_received, 0);

		/* Check if the remote user closed the connection */
		if (read == 0)
		{
			peer_connection_destroy(conn, OSCAR_DISCONNECT_REMOTE_CLOSED, NULL);
			return;
		}

		/* If there was an error then close the connection */
		if (read < 0)
		{
			if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
				/* No worries */
				return;

			peer_connection_destroy(conn,
					OSCAR_DISCONNECT_LOST_CONNECTION, g_strerror(errno));
			return;
		}

		conn->lastactivity = time(NULL);

		/* If we don't even have the first 6 bytes then do nothing */
		conn->header_received += read;
		if (conn->header_received < 6)
			return;

		/* All ODC/OFT frames must start with a magic string */
		if (memcmp(conn->magic, conn->header, 4))
		{
			purple_debug_warning("oscar", "Expecting magic string to "
				"be %c%c%c%c but received magic string %c%c%c%c.  "
				"Closing connection.\n",
				conn->magic[0], conn->magic[1], conn->magic[2],
				conn->magic[3], conn->header[0], conn->header[1],
				conn->header[2], conn->header[3]);
			peer_connection_destroy(conn, OSCAR_DISCONNECT_INVALID_DATA, NULL);
			return;
		}

		/* Initialize a new temporary ByteStream for incoming data */
		conn->buffer_incoming.len = aimutil_get16(&conn->header[4]) - 6;
		conn->buffer_incoming.data = g_new(guint8, conn->buffer_incoming.len);
		conn->buffer_incoming.offset = 0;
	}

	/* Read data into the temporary buffer until it is complete */
	read = recv(conn->fd,
				&conn->buffer_incoming.data[conn->buffer_incoming.offset],
				conn->buffer_incoming.len - conn->buffer_incoming.offset,
				0);

	/* Check if the remote user closed the connection */
	if (read == 0)
	{
		peer_connection_destroy(conn, OSCAR_DISCONNECT_REMOTE_CLOSED, NULL);
		return;
	}

	if (read < 0)
	{
		if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
			/* No worries */
			return;

		peer_connection_destroy(conn,
				OSCAR_DISCONNECT_LOST_CONNECTION, g_strerror(errno));
		return;
	}

	conn->lastactivity = time(NULL);
	conn->buffer_incoming.offset += read;
	if (conn->buffer_incoming.offset < conn->buffer_incoming.len)
		/* Waiting for more data to arrive */
		return;

	/* We have a complete ODC/OFT frame!  Handle it and continue reading */
	byte_stream_rewind(&conn->buffer_incoming);
	if (conn->type == OSCAR_CAPABILITY_DIRECTIM)
	{
		peer_odc_recv_frame(conn, &conn->buffer_incoming);
	}
	else if (conn->type == OSCAR_CAPABILITY_SENDFILE)
	{
		peer_oft_recv_frame(conn, &conn->buffer_incoming);
	}

	g_free(conn->buffer_incoming.data);
	conn->buffer_incoming.data = NULL;

	conn->header_received = 0;
}

/*******************************************************************/
/* End code for receiving data on a peer connection                */
/*******************************************************************/

/*******************************************************************/
/* Begin code for sending data on a peer connection                */
/*******************************************************************/

static void
send_cb(gpointer data, gint source, PurpleInputCondition cond)
{
	PeerConnection *conn;
	gsize writelen;
	gssize wrotelen;

	conn = data;
	writelen = purple_circ_buffer_get_max_read(conn->buffer_outgoing);

	if (writelen == 0)
	{
		purple_input_remove(conn->watcher_outgoing);
		conn->watcher_outgoing = 0;
		/*
		 * The buffer is currently empty, so reset the current input
		 * and output positions to the start of the buffer.  We do
		 * this so that the next chunk of data that we put into the
		 * buffer can be read back out of the buffer in one fell swoop.
		 * Otherwise it gets fragmented and we have to read from the
		 * second half of the buffer than go back and read the rest of
		 * the chunk from the first half.
		 *
		 * We're using TCP, which is a stream based protocol, so this
		 * isn't supposed to matter.  However, experience has shown
		 * that at least the proxy file transfer code in AIM 6.1.41.2
		 * requires that the entire OFT frame arrive all at once.  If
		 * the frame is fragmented then AIM freaks out and aborts the
		 * file transfer.  Somebody should teach those guys how to
		 * write good TCP code.
		 */
		conn->buffer_outgoing->inptr = conn->buffer_outgoing->buffer;
		conn->buffer_outgoing->outptr = conn->buffer_outgoing->buffer;
		return;
	}

	wrotelen = send(conn->fd, conn->buffer_outgoing->outptr, writelen, 0);
	if (wrotelen <= 0)
	{
		if (wrotelen < 0 && ((errno == EAGAIN) || (errno == EWOULDBLOCK)))
			/* No worries */
			return;

		if (conn->ready)
		{
			purple_input_remove(conn->watcher_outgoing);
			conn->watcher_outgoing = 0;
			close(conn->fd);
			conn->fd = -1;
			peer_connection_schedule_destroy(conn,
					OSCAR_DISCONNECT_LOST_CONNECTION, NULL);
		}
		else
		{
			/*
			 * This could happen when unable to send a negotiation
			 * frame to a peer proxy server.
			 */
			peer_connection_trynext(conn);
		}
		return;
	}

	purple_circ_buffer_mark_read(conn->buffer_outgoing, wrotelen);
	conn->lastactivity = time(NULL);
}

/**
 * This should be called by OFT/ODC code to send a standard OFT or ODC
 * frame across the peer connection along with some payload data.  Or
 * maybe a file.  Anything, really.
 */
void
peer_connection_send(PeerConnection *conn, ByteStream *bs)
{
	/* Add everything to our outgoing buffer */
	purple_circ_buffer_append(conn->buffer_outgoing, bs->data, bs->len);

	/* If we haven't already started writing stuff, then start the cycle */
	if ((conn->watcher_outgoing == 0) && (conn->fd >= 0))
	{
		conn->watcher_outgoing = purple_input_add(conn->fd,
				PURPLE_INPUT_WRITE, send_cb, conn);
		send_cb(conn, conn->fd, 0);
	}
}

/*******************************************************************/
/* End code for sending data on a peer connection                  */
/*******************************************************************/

/*******************************************************************/
/* Begin code for establishing a peer connection                   */
/*******************************************************************/

void
peer_connection_finalize_connection(PeerConnection *conn)
{
	conn->watcher_incoming = purple_input_add(conn->fd,
			PURPLE_INPUT_READ, peer_connection_recv_cb, conn);

	if (conn->type == OSCAR_CAPABILITY_DIRECTIM)
	{
		/*
		 * If we are connecting to them then send our cookie so they
		 * can verify who we are.  Note: This doesn't seem to be
		 * necessary, but it also doesn't seem to hurt.
		 */
		if (!(conn->flags & PEER_CONNECTION_FLAG_IS_INCOMING))
			peer_odc_send_cookie(conn);
	}
	else if (conn->type == OSCAR_CAPABILITY_SENDFILE)
	{
		if (purple_xfer_get_type(conn->xfer) == PURPLE_XFER_SEND)
		{
			peer_oft_send_prompt(conn);
		}
	}

	/*
	 * Tell the remote user that we're connected (which may also imply
	 * that we've accepted their request).
	 */
	if (!(conn->flags & PEER_CONNECTION_FLAG_IS_INCOMING))
		aim_im_sendch2_connected(conn);
}

/**
 * We tried to make an outgoing connection to a remote user.  It
 * either connected or failed to connect.
 */
static void
peer_connection_common_established_cb(gpointer data, gint source, const gchar *error_message, gboolean verified)
{
	PeerConnection *conn;

	conn = data;

	if (verified)
		conn->verified_connect_data = NULL;
	else
		conn->client_connect_data = NULL;

	if (source < 0)
	{
		if ((conn->verified_connect_data == NULL) &&
			(conn->client_connect_data == NULL))
		{
			/* Our parallel connection attemps have both failed. */
			peer_connection_trynext(conn);
		}
		return;
	}

	purple_timeout_remove(conn->connect_timeout_timer);
	conn->connect_timeout_timer = 0;

	if (conn->client_connect_data != NULL)
	{
		purple_proxy_connect_cancel(conn->client_connect_data);
		conn->client_connect_data = NULL;
	}

	if (conn->verified_connect_data != NULL)
	{
		purple_proxy_connect_cancel(conn->verified_connect_data);
		conn->verified_connect_data = NULL;
	}

	conn->fd = source;

	peer_connection_finalize_connection(conn);
}

static void
peer_connection_verified_established_cb(gpointer data, gint source, const gchar *error_message)
{
	peer_connection_common_established_cb(data, source, error_message, TRUE);
}

static void
peer_connection_client_established_cb(gpointer data, gint source, const gchar *error_message)
{
	peer_connection_common_established_cb(data, source, error_message, FALSE);
}

/**
 * This is the watcher callback for any listening socket that is
 * waiting for a peer to connect.  When a peer connects we set the
 * input watcher to start reading data from the peer.
 *
 * To make sure that the connection is with the intended person and
 * not with a malicious middle man, we don't send anything until we've
 * received a peer frame from the remote user and have verified that
 * the cookie in the peer frame matches the cookie that was exchanged
 * in the channel 2 ICBM.
 */
void
peer_connection_listen_cb(gpointer data, gint source, PurpleInputCondition cond)
{
	PeerConnection *conn;
	struct sockaddr addr;
	socklen_t addrlen = sizeof(addr);
	int flags;

	conn = data;

	purple_debug_info("oscar", "Accepting connection on listener socket.\n");

	conn->fd = accept(conn->listenerfd, &addr, &addrlen);
	if (conn->fd < 0)
	{
		if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
			/* No connection yet--no worries */
			/* TODO: Hmm, but they SHOULD be connected if we're here, right? */
			return;

		peer_connection_trynext(conn);
		return;
	}

	if ((addr.sa_family != PF_INET) && (addr.sa_family != PF_INET6))
	{
		/* Invalid connection type?!  Continue waiting. */
		close(conn->fd);
		return;
	}

	flags = fcntl(conn->fd, F_GETFL);
	fcntl(conn->fd, F_SETFL, flags | O_NONBLOCK);
#ifndef _WIN32
	fcntl(conn->fd, F_SETFD, FD_CLOEXEC);
#endif

	purple_input_remove(conn->watcher_incoming);

	peer_connection_finalize_connection(conn);
}

/**
 * We've just opened a listener socket, so we send the remote
 * user an ICBM and ask them to connect to us.
 */
static void
peer_connection_establish_listener_cb(int listenerfd, gpointer data)
{
	PeerConnection *conn;
	OscarData *od;
	PurpleConnection *gc;
	PurpleAccount *account;
	PurpleConversation *conv;
	char *tmp;
	FlapConnection *bos_conn;
	const char *listener_ip;
	const guchar *ip_atoi;
	unsigned short listener_port;

	conn = data;
	conn->listen_data = NULL;

	if (listenerfd < 0)
	{
		/* Could not open listener socket */
		peer_connection_trynext(conn);
		return;
	}

	od = conn->od;
	gc = od->gc;
	account = purple_connection_get_account(gc);
	conn->listenerfd = listenerfd;

	/* Watch for new connections on our listener socket */
	conn->watcher_incoming = purple_input_add(conn->listenerfd,
			PURPLE_INPUT_READ, peer_connection_listen_cb, conn);

	/* Send the "please connect to me!" ICBM */
	bos_conn = flap_connection_findbygroup(od, SNAC_FAMILY_ICBM);
	if (bos_conn == NULL)
	{
		/* Not good */
		peer_connection_trynext(conn);
		return;
	}

	if (bos_conn->gsc)
		listener_ip = purple_network_get_my_ip(bos_conn->gsc->fd);
	else
		listener_ip = purple_network_get_my_ip(bos_conn->fd);

	ip_atoi = purple_network_ip_atoi(listener_ip);
	if (ip_atoi == NULL) {
		/* Could not convert IP to 4 byte array--weird, but this does
		   happen for some users (#4829, Adium #15839).  Maybe they're
		   connecting with IPv6...?  Maybe through a proxy? */
		purple_debug_error("oscar", "Can't ask peer to connect to us "
				"because purple_network_ip_atoi(%s) returned NULL. "
				"fd=%d. is_ssl=%d\n",
				listener_ip ? listener_ip : "(null)",
				bos_conn->gsc ? bos_conn->gsc->fd : bos_conn->fd,
				bos_conn->gsc ? 1 : 0);
		peer_connection_trynext(conn);
		return;
	}

	listener_port = purple_network_get_port_from_fd(conn->listenerfd);

	if (conn->type == OSCAR_CAPABILITY_DIRECTIM)
	{
		aim_im_sendch2_odc_requestdirect(od,
				conn->cookie, conn->bn, ip_atoi,
				listener_port, ++conn->lastrequestnumber);

		/* Print a message to a local conversation window */
		conv = purple_conversation_new(PURPLE_CONV_TYPE_IM, account, conn->bn);
		tmp = g_strdup_printf(_("Asking %s to connect to us at %s:%hu for "
				"Direct IM."), conn->bn, listener_ip, listener_port);
		purple_conversation_write(conv, NULL, tmp, PURPLE_MESSAGE_SYSTEM, time(NULL));
		g_free(tmp);
	}
	else if (conn->type == OSCAR_CAPABILITY_SENDFILE)
	{
		aim_im_sendch2_sendfile_requestdirect(od,
				conn->cookie, conn->bn,
				ip_atoi,
				listener_port, ++conn->lastrequestnumber,
				(const gchar *)conn->xferdata.name,
				conn->xferdata.size, conn->xferdata.totfiles);
	}
}

/**
 * This is a callback function used when we're connecting to a peer
 * using either the client IP or the verified IP and the connection
 * took longer than 5 seconds to complete.  We do this because
 * waiting for the OS to time out the connection attempt is not
 * practical--the default timeout on many OSes can be 3 minutes or
 * more, and users are impatient.
 *
 * Worst case scenario: the user is connected to the Internet using
 * a modem with severe lag.  The peer connections fail and Purple falls
 * back to using a proxied connection.  The lower bandwidth
 * limitations imposed by the proxied connection won't matter because
 * the user is using a modem.
 *
 * I suppose this line of thinking is discriminatory against people
 * with very high lag but decent throughput who are transferring
 * large files.  But we don't care about those people.
 *
 * I (Sean) changed the timeout from 15 to 5 seconds, as 60 seconds is
 * too long for a user to wait to send a file. I'm also parallelizing
 * requests when possible. The longest we should have to wait now is 10
 * seconds. We shouldn't make it shorter than this.
 */
static gboolean
peer_connection_tooktoolong(gpointer data)
{
	PeerConnection *conn;

	conn = data;

	purple_debug_info("oscar", "Peer connection timed out after 5 seconds.  "
			"Trying next method...\n");

	peer_connection_trynext(conn);

	/* Cancel this timer.  It'll be added again, if needed. */
	return FALSE;
}

/**
 * Try to establish the given PeerConnection using a defined
 * sequence of steps.
 */
void
peer_connection_trynext(PeerConnection *conn)
{
	PurpleAccount *account;

	account = purple_connection_get_account(conn->od->gc);

	/*
	 * Close any remnants of a previous failed connection attempt.
	 */
	peer_connection_close(conn);

	/*
	 * 1. Attempt to connect to the remote user using their verifiedip and clientip.
	 *    We try these at the same time and use whichever succeeds first, so we don't
	 *    have to wait for a timeout.
	 */
	if (!(conn->flags & PEER_CONNECTION_FLAG_TRIED_DIRECT) &&
		(conn->verifiedip != NULL) && (conn->port != 0) && (!conn->use_proxy))
	{
		conn->flags |= PEER_CONNECTION_FLAG_TRIED_DIRECT;

		if (conn->type == OSCAR_CAPABILITY_DIRECTIM)
		{
			gchar *tmp;
			PurpleConversation *conv;
			tmp = g_strdup_printf(_("Attempting to connect to %s:%hu."),
					conn->verifiedip, conn->port);
			conv = purple_conversation_new(PURPLE_CONV_TYPE_IM, account, conn->bn);
			purple_conversation_write(conv, NULL, tmp,
					PURPLE_MESSAGE_SYSTEM, time(NULL));
			g_free(tmp);
		}

		conn->verified_connect_data = purple_proxy_connect(NULL, account,
				conn->verifiedip, conn->port,
				peer_connection_verified_established_cb, conn);

		if ((conn->verifiedip == NULL) ||
			strcmp(conn->verifiedip, conn->clientip))
		{
			conn->client_connect_data = purple_proxy_connect(NULL, account,
					conn->clientip, conn->port,
					peer_connection_client_established_cb, conn);
		}

		if ((conn->verified_connect_data != NULL) ||
			(conn->client_connect_data != NULL))
		{
			/* Connecting... */
			conn->connect_timeout_timer = purple_timeout_add_seconds(5,
					peer_connection_tooktoolong, conn);
			return;
		}
	}

	/*
	 * 2. Attempt to have the remote user connect to us (using both
	 *    our verifiedip and our clientip).
	 */
	if (!(conn->flags & PEER_CONNECTION_FLAG_TRIED_INCOMING) &&
		(!conn->use_proxy))
	{
		conn->flags |= PEER_CONNECTION_FLAG_TRIED_INCOMING;

		/*
		 * Remote user is connecting to us, so we'll need to verify
		 * that the user who connected is our friend.
		 */
		conn->flags |= PEER_CONNECTION_FLAG_IS_INCOMING;

		conn->listen_data = purple_network_listen_range(5190, 5290, SOCK_STREAM,
				peer_connection_establish_listener_cb, conn);
		if (conn->listen_data != NULL)
		{
			/* Opening listener socket... */
			return;
		}
	}

	/*
	 * 3. Attempt to have both users connect to an intermediate proxy
	 *    server.
	 */
	if (!(conn->flags & PEER_CONNECTION_FLAG_TRIED_PROXY))
	{
		conn->flags |= PEER_CONNECTION_FLAG_TRIED_PROXY;

		/*
		 * If we initiate the proxy connection, then the remote user
		 * could be anyone, so we need to verify that the user who
		 * connected is our friend.
		 */
		if (!conn->use_proxy)
			conn->flags |= PEER_CONNECTION_FLAG_IS_INCOMING;

		if (conn->type == OSCAR_CAPABILITY_DIRECTIM)
		{
			gchar *tmp;
			PurpleConversation *conv;
			tmp = g_strdup(_("Attempting to connect via proxy server."));
			conv = purple_conversation_new(PURPLE_CONV_TYPE_IM, account, conn->bn);
			purple_conversation_write(conv, NULL, tmp,
					PURPLE_MESSAGE_SYSTEM, time(NULL));
			g_free(tmp);
		}

		conn->verified_connect_data = purple_proxy_connect(NULL, account,
				(conn->proxyip != NULL)
					? conn->proxyip
					: (conn->od->icq ? ICQ_PEER_PROXY_SERVER : AIM_PEER_PROXY_SERVER),
				PEER_PROXY_PORT,
				peer_proxy_connection_established_cb, conn);
		if (conn->verified_connect_data != NULL)
		{
			/* Connecting... */
			return;
		}
	}

	/* Give up! */
	peer_connection_destroy(conn, OSCAR_DISCONNECT_COULD_NOT_CONNECT, NULL);
}

/**
 * Initiate a peer connection with someone.
 */
void
peer_connection_propose(OscarData *od, guint64 type, const char *bn)
{
	PeerConnection *conn;

	if (type == OSCAR_CAPABILITY_DIRECTIM)
	{
		conn = peer_connection_find_by_type(od, bn, type);
		if (conn != NULL)
		{
			if (conn->ready)
			{
				PurpleAccount *account;
				PurpleConversation *conv;

				purple_debug_info("oscar", "Already have a direct IM "
						"session with %s.\n", bn);
				account = purple_connection_get_account(od->gc);
				conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM,
						bn, account);
				if (conv != NULL)
					purple_conversation_present(conv);
				return;
			}

			/* Cancel the old connection and try again */
			peer_connection_destroy(conn, OSCAR_DISCONNECT_RETRYING, NULL);
		}
	}

	conn = peer_connection_new(od, type, bn);
	conn->flags |= PEER_CONNECTION_FLAG_INITIATED_BY_ME;
	conn->flags |= PEER_CONNECTION_FLAG_APPROVED;
	aim_icbm_makecookie(conn->cookie);

	peer_connection_trynext(conn);
}

/**
 * Someone else wants to establish a peer connection with us,
 * and we said yes.
 */
static void
peer_connection_got_proposition_yes_cb(gpointer data, gint id)
{
	PeerConnection *conn;

	conn = data;

	conn->flags |= PEER_CONNECTION_FLAG_APPROVED;
	peer_connection_trynext(conn);
}

/**
 * Someone else wants to establish a peer connection with us,
 * and we said no.
 *
 * "Well, one time my friend asked me if I wanted to play the
 *  piccolo.  But I said no."
 */
static void
peer_connection_got_proposition_no_cb(gpointer data, gint id)
{
	PeerConnection *conn;

	conn = data;

	aim_im_denytransfer(conn->od, conn->bn, conn->cookie,
			AIM_TRANSFER_DENY_DECLINE);
	peer_connection_destroy(conn, OSCAR_DISCONNECT_LOCAL_CLOSED, NULL);
}

/**
 * Someone else wants to establish a peer connection with us.
 */
void
peer_connection_got_proposition(OscarData *od, const gchar *bn, const gchar *message, IcbmArgsCh2 *args)
{
	PurpleConnection *gc;
	PurpleAccount *account;
	PeerConnection *conn;
	gchar *buf;

	gc = od->gc;
	account = purple_connection_get_account(gc);

	/*
	 * If we have a connection with this same cookie then they are
	 * probably just telling us they weren't able to connect to us
	 * and we should try connecting to them, instead.  Or they want
	 * to go through a proxy.
	 */
	conn = peer_connection_find_by_cookie(od, bn, args->cookie);
	if ((conn != NULL) && (conn->type == args->type))
	{
		purple_debug_info("oscar", "Remote user wants to try a "
				"different connection method\n");
		g_free(conn->proxyip);
		g_free(conn->clientip);
		g_free(conn->verifiedip);
		if (args->use_proxy)
			conn->proxyip = g_strdup(args->proxyip);
		else
			conn->proxyip = NULL;
		conn->verifiedip = g_strdup(args->verifiedip);
		conn->clientip = g_strdup(args->clientip);
		conn->port = args->port;
		conn->use_proxy |= args->use_proxy;
		conn->lastrequestnumber++;
		peer_connection_trynext(conn);
		return;
	}

	/* If this is a direct IM, then close any existing session */
	if (args->type == OSCAR_CAPABILITY_DIRECTIM)
	{
		conn = peer_connection_find_by_type(od, bn, args->type);
		if (conn != NULL)
		{
			/* Close the old direct IM and start a new one */
			purple_debug_info("oscar", "Received new direct IM request "
				"from %s.  Destroying old connection.\n", bn);
			peer_connection_destroy(conn, OSCAR_DISCONNECT_REMOTE_CLOSED, NULL);
		}
	}

	/* Check for proper arguments */
	if (args->type == OSCAR_CAPABILITY_SENDFILE)
	{
		if ((args->info.sendfile.filename == NULL) ||
			(args->info.sendfile.totsize == 0) ||
			(args->info.sendfile.totfiles == 0))
		{
			purple_debug_warning("oscar",
					"%s tried to send you a file with incomplete "
					"information.\n", bn);
			return;
		}
	}

	conn = peer_connection_new(od, args->type, bn);
	memcpy(conn->cookie, args->cookie, 8);
	if (args->use_proxy)
		conn->proxyip = g_strdup(args->proxyip);
	conn->clientip = g_strdup(args->clientip);
	conn->verifiedip = g_strdup(args->verifiedip);
	conn->port = args->port;
	conn->use_proxy |= args->use_proxy;
	conn->lastrequestnumber++;

	if (args->type == OSCAR_CAPABILITY_DIRECTIM)
	{
		buf = g_strdup_printf(_("%s has just asked to directly connect to %s"),
				bn, purple_account_get_username(account));

		purple_request_action(conn, NULL, buf,
						_("This requires a direct connection between "
						  "the two computers and is necessary for IM "
						  "Images.  Because your IP address will be "
						  "revealed, this may be considered a privacy "
						  "risk."),
						PURPLE_DEFAULT_ACTION_NONE,
						account, bn, NULL,
						conn, 2,
						_("C_onnect"), G_CALLBACK(peer_connection_got_proposition_yes_cb),
						_("Cancel"), G_CALLBACK(peer_connection_got_proposition_no_cb));
	}
	else if (args->type == OSCAR_CAPABILITY_SENDFILE)
	{
		gchar *filename;

		conn->xfer = purple_xfer_new(account, PURPLE_XFER_RECEIVE, bn);
		if (conn->xfer)
		{
			conn->xfer->data = conn;
			purple_xfer_ref(conn->xfer);
			purple_xfer_set_size(conn->xfer, args->info.sendfile.totsize);

			/* Set the file name */
			if (g_utf8_validate(args->info.sendfile.filename, -1, NULL))
				filename = g_strdup(args->info.sendfile.filename);
			else
				filename = purple_utf8_salvage(args->info.sendfile.filename);

			if (args->info.sendfile.subtype == AIM_OFT_SUBTYPE_SEND_DIR)
			{
				/*
				 * If they are sending us a directory then the last character
				 * of the file name will be an asterisk.  We don't want to
				 * save stuff to a directory named "*" so we remove the
				 * asterisk from the file name.
				 */
				char *tmp = strrchr(filename, '\\');
				if ((tmp != NULL) && (tmp[1] == '*'))
					tmp[0] = '\0';
			}
			purple_xfer_set_filename(conn->xfer, filename);
			g_free(filename);

			/*
			 * Set the message, unless this is the dummy message from an
			 * ICQ client or an empty message from an AIM client.
			 * TODO: Maybe we should strip HTML and then see if strlen>0?
			 */
			if ((message != NULL) &&
				(g_ascii_strncasecmp(message, "<ICQ_COOL_FT>", 13) != 0) &&
				(g_ascii_strcasecmp(message, "<HTML>") != 0))
			{
				purple_xfer_set_message(conn->xfer, message);
			}

			/* Setup our I/O op functions */
			purple_xfer_set_init_fnc(conn->xfer, peer_oft_recvcb_init);
			purple_xfer_set_end_fnc(conn->xfer, peer_oft_recvcb_end);
			purple_xfer_set_request_denied_fnc(conn->xfer, peer_oft_cb_generic_cancel);
			purple_xfer_set_cancel_recv_fnc(conn->xfer, peer_oft_cb_generic_cancel);
			purple_xfer_set_ack_fnc(conn->xfer, peer_oft_recvcb_ack_recv);

			/* Now perform the request */
			purple_xfer_request(conn->xfer);
		}
	}
}

/*******************************************************************/
/* End code for establishing a peer connection                     */
/*******************************************************************/
