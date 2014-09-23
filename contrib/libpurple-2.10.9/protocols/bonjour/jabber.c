/*
 * purple - Bonjour Protocol Plugin
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

#ifndef _WIN32
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#else
#include "libc_interface.h"
#endif
#include <sys/types.h>

/* Solaris */
#if defined (__SVR4) && defined (__sun)
#include <sys/sockio.h>
#endif

#include <glib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>

#ifdef HAVE_GETIFADDRS
#include <ifaddrs.h>
#endif


#include "network.h"
#include "eventloop.h"
#include "connection.h"
#include "blist.h"
#include "xmlnode.h"
#include "debug.h"
#include "notify.h"
#include "util.h"

#include "jabber.h"
#include "parser.h"
#include "bonjour.h"
#include "buddy.h"
#include "bonjour_ft.h"

#ifdef _SIZEOF_ADDR_IFREQ
#  define HX_SIZE_OF_IFREQ(a) _SIZEOF_ADDR_IFREQ(a)
#else
#  define HX_SIZE_OF_IFREQ(a) sizeof(a)
#endif

#define STREAM_END "</stream:stream>"
/* TODO: specify version='1.0' and send stream features */
#define DOCTYPE "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n" \
		"<stream:stream xmlns=\"jabber:client\" xmlns:stream=\"http://etherx.jabber.org/streams\" from=\"%s\" to=\"%s\">"

enum sent_stream_start_types {
	NOT_SENT       = 0,
	PARTIALLY_SENT = 1,
	FULLY_SENT     = 2
};

static void
xep_iq_parse(xmlnode *packet, PurpleBuddy *pb);

static BonjourJabberConversation *
bonjour_jabber_conv_new(PurpleBuddy *pb, PurpleAccount *account, const char *ip) {

	BonjourJabberConversation *bconv = g_new0(BonjourJabberConversation, 1);
	bconv->socket = -1;
	bconv->tx_buf = purple_circ_buffer_new(512);
	bconv->tx_handler = 0;
	bconv->rx_handler = 0;
	bconv->pb = pb;
	bconv->account = account;
	bconv->ip = g_strdup(ip);

	bonjour_parser_setup(bconv);

	return bconv;
}

static const char *
_font_size_ichat_to_purple(int size)
{
	if (size > 24) {
		return "7";
	} else if (size >= 21) {
		return "6";
	} else if (size >= 17) {
		return "5";
	} else if (size >= 14) {
		return "4";
	} else if (size >= 12) {
		return "3";
	} else if (size >= 10) {
		return "2";
	}

	return "1";
}

static gchar *
get_xmlnode_contents(xmlnode *node)
{
	gchar *contents;

	contents = xmlnode_to_str(node, NULL);

	/* we just want the stuff inside <font></font>
	 * There isn't stuff exposed in xmlnode.c to do this more cleanly. */

	if (contents) {
		char *bodystart = strchr(contents, '>');
		char *bodyend = bodystart ? strrchr(bodystart, '<') : NULL;
		if (bodystart && bodyend && (bodystart + 1) != bodyend) {
			*bodyend = '\0';
			memmove(contents, bodystart + 1, (bodyend - bodystart));
		}
	}

	return contents;
}

static void
_jabber_parse_and_write_message_to_ui(xmlnode *message_node, PurpleBuddy *pb)
{
	xmlnode *body_node, *html_node, *events_node;
	PurpleConnection *gc = purple_account_get_connection(purple_buddy_get_account(pb));
	gchar *body = NULL;
	gboolean composing_event = FALSE;

	body_node = xmlnode_get_child(message_node, "body");
	html_node = xmlnode_get_child(message_node, "html");

	if (body_node == NULL && html_node == NULL) {
		purple_debug_error("bonjour", "No body or html node found, discarding message.\n");
		return;
	}

	events_node = xmlnode_get_child_with_namespace(message_node, "x", "jabber:x:event");
	if (events_node != NULL) {
		if (xmlnode_get_child(events_node, "composing") != NULL)
			composing_event = TRUE;
		if (xmlnode_get_child(events_node, "id") != NULL) {
			/* The user is just typing */
			/* TODO: Deal with typing notification */
			return;
		}
	}

	if (html_node != NULL) {
		xmlnode *html_body_node;

		html_body_node = xmlnode_get_child(html_node, "body");
		if (html_body_node != NULL) {
			xmlnode *html_body_font_node;

			html_body_font_node = xmlnode_get_child(html_body_node, "font");
			/* Types of messages sent by iChat */
			if (html_body_font_node != NULL) {
				gchar *html_body;
				const char *font_face, *font_size,
					*ichat_balloon_color, *ichat_text_color;

				font_face = xmlnode_get_attrib(html_body_font_node, "face");
				/* The absolute iChat font sizes should be converted to 1..7 range */
				font_size = xmlnode_get_attrib(html_body_font_node, "ABSZ");
				if (font_size != NULL)
					font_size = _font_size_ichat_to_purple(atoi(font_size));
				/*font_color = xmlnode_get_attrib(html_body_font_node, "color");*/
				ichat_balloon_color = xmlnode_get_attrib(html_body_node, "ichatballooncolor");
				ichat_text_color = xmlnode_get_attrib(html_body_node, "ichattextcolor");

				html_body = get_xmlnode_contents(html_body_font_node);

				if (html_body == NULL)
					/* This is the kind of formatted messages that Purple creates */
					html_body = xmlnode_to_str(html_body_font_node, NULL);

				if (html_body != NULL) {
					GString *str = g_string_new("<font");

					if (font_face)
						g_string_append_printf(str, " face='%s'", font_face);
					if (font_size)
						g_string_append_printf(str, " size='%s'", font_size);
					if (ichat_text_color)
						g_string_append_printf(str, " color='%s'", ichat_text_color);
					if (ichat_balloon_color)
						g_string_append_printf(str, " back='%s'", ichat_balloon_color);
					g_string_append_printf(str, ">%s</font>", html_body);

					body = g_string_free(str, FALSE);

					g_free(html_body);
				}
			}
		}
	}

	/* Compose the message */
	if (body == NULL && body_node != NULL)
		body = xmlnode_get_data(body_node);

	if (body == NULL) {
		purple_debug_error("bonjour", "No html body or regular body found.\n");
		return;
	}

	/* Send the message to the UI */
	serv_got_im(gc, purple_buddy_get_name(pb), body, 0, time(NULL));

	g_free(body);
}

struct _match_buddies_by_address_t {
	const char *address;
	GSList *matched_buddies;
};

static void
_match_buddies_by_address(gpointer value, gpointer data)
{
	PurpleBuddy *pb = value;
	BonjourBuddy *bb = NULL;
	struct _match_buddies_by_address_t *mbba = data;

	bb = purple_buddy_get_protocol_data(pb);

	/*
	 * If the current PurpleBuddy's data is not null, then continue to determine
	 * whether one of the buddies IPs matches the target IP.
	 */
	if (bb != NULL)
	{
		const char *ip;
		GSList *tmp = bb->ips;

		while(tmp) {
			ip = tmp->data;
			if (ip != NULL && g_ascii_strcasecmp(ip, mbba->address) == 0) {
				mbba->matched_buddies = g_slist_prepend(mbba->matched_buddies, pb);
				break;
			}
			tmp = tmp->next;
		}
	}
}

static void
_send_data_write_cb(gpointer data, gint source, PurpleInputCondition cond)
{
	PurpleBuddy *pb = data;
	BonjourBuddy *bb = purple_buddy_get_protocol_data(pb);
	BonjourJabberConversation *bconv = bb->conversation;
	int ret, writelen;

	writelen = purple_circ_buffer_get_max_read(bconv->tx_buf);

	if (writelen == 0) {
		purple_input_remove(bconv->tx_handler);
		bconv->tx_handler = 0;
		return;
	}

	ret = send(bconv->socket, bconv->tx_buf->outptr, writelen, 0);

	if (ret < 0 && errno == EAGAIN)
		return;
	else if (ret <= 0) {
		PurpleConversation *conv = NULL;
		PurpleAccount *account = NULL;
		const char *error = g_strerror(errno);

		purple_debug_error("bonjour", "Error sending message to buddy %s error: %s\n",
				   purple_buddy_get_name(pb), error ? error : "(null)");

		account = purple_buddy_get_account(pb);

		conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, bb->name, account);
		if (conv != NULL)
			purple_conversation_write(conv, NULL,
				  _("Unable to send message."),
				  PURPLE_MESSAGE_SYSTEM, time(NULL));

		bonjour_jabber_close_conversation(bb->conversation);
		bb->conversation = NULL;
		return;
	}

	purple_circ_buffer_mark_read(bconv->tx_buf, ret);
}

static gint
_send_data(PurpleBuddy *pb, char *message)
{
	gint ret;
	int len = strlen(message);
	BonjourBuddy *bb = purple_buddy_get_protocol_data(pb);
	BonjourJabberConversation *bconv = bb->conversation;

	/* If we're not ready to actually send, append it to the buffer */
	if (bconv->tx_handler != 0
			|| bconv->connect_data != NULL
			|| bconv->sent_stream_start != FULLY_SENT
			|| !bconv->recv_stream_start
			|| purple_circ_buffer_get_max_read(bconv->tx_buf) > 0) {
		ret = -1;
		errno = EAGAIN;
	} else {
		ret = send(bconv->socket, message, len, 0);
	}

	if (ret == -1 && errno == EAGAIN)
		ret = 0;
	else if (ret <= 0) {
		PurpleConversation *conv;
		PurpleAccount *account;
		const char *error = g_strerror(errno);

		purple_debug_error("bonjour", "Error sending message to buddy %s error: %s\n",
				   purple_buddy_get_name(pb), error ? error : "(null)");

		account = purple_buddy_get_account(pb);

		conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, bb->name, account);
		if (conv != NULL)
			purple_conversation_write(conv, NULL,
				  _("Unable to send message."),
				  PURPLE_MESSAGE_SYSTEM, time(NULL));

		bonjour_jabber_close_conversation(bb->conversation);
		bb->conversation = NULL;
		return -1;
	}

	if (ret < len) {
		/* Don't interfere with the stream starting */
		if (bconv->sent_stream_start == FULLY_SENT && bconv->recv_stream_start && bconv->tx_handler == 0)
			bconv->tx_handler = purple_input_add(bconv->socket, PURPLE_INPUT_WRITE,
				_send_data_write_cb, pb);
		purple_circ_buffer_append(bconv->tx_buf, message + ret, len - ret);
	}

	return ret;
}

void bonjour_jabber_process_packet(PurpleBuddy *pb, xmlnode *packet) {

	g_return_if_fail(packet != NULL);
	g_return_if_fail(pb != NULL);

	if (!strcmp(packet->name, "message"))
		_jabber_parse_and_write_message_to_ui(packet, pb);
	else if(!strcmp(packet->name, "iq"))
		xep_iq_parse(packet, pb);
	else
		purple_debug_warning("bonjour", "Unknown packet: %s\n", packet->name ? packet->name : "(null)");
}

static void bonjour_jabber_stream_ended(BonjourJabberConversation *bconv) {

	/* Inform the user that the conversation has been closed */
	BonjourBuddy *bb = NULL;
	const gchar *name = bconv->pb ? purple_buddy_get_name(bconv->pb) : "(unknown)";

	purple_debug_info("bonjour", "Received conversation close notification from %s.\n", name);

	if(bconv->pb != NULL)
		bb = purple_buddy_get_protocol_data(bconv->pb);
#if 0
	if(bconv->pb != NULL) {
		PurpleConversation *conv;
		conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, bconv->pb->name, bconv->pb->account);
		if (conv != NULL) {
			char *tmp = g_strdup_printf(_("%s has closed the conversation."), bconv->pb->name);
			purple_conversation_write(conv, NULL, tmp, PURPLE_MESSAGE_SYSTEM, time(NULL));
			g_free(tmp);
		}
	}
#endif
	/* Close the socket, clear the watcher and free memory */
	bonjour_jabber_close_conversation(bconv);
	if(bb)
		bb->conversation = NULL;
}

static void
_client_socket_handler(gpointer data, gint socket, PurpleInputCondition condition)
{
	BonjourJabberConversation *bconv = data;
	gssize len;
	static char message[4096];

	/* Read the data from the socket */
	if ((len = recv(socket, message, sizeof(message) - 1, 0)) < 0) {
		/* There have been an error reading from the socket */
		if (len != -1 || errno != EAGAIN) {
			const char *err = g_strerror(errno);

			purple_debug_warning("bonjour",
					"receive of %" G_GSSIZE_FORMAT " error: %s\n",
					len, err ? err : "(null)");

			bonjour_jabber_close_conversation(bconv);
			if (bconv->pb != NULL) {
				BonjourBuddy *bb = purple_buddy_get_protocol_data(bconv->pb);

				if(bb != NULL)
					bb->conversation = NULL;
			}

			/* I guess we really don't need to notify the user.
			 * If they try to send another message it'll reconnect */
		}
		return;
	} else if (len == 0) { /* The other end has closed the socket */
		const gchar *name = purple_buddy_get_name(bconv->pb);
		purple_debug_warning("bonjour", "Connection closed (without stream end) by %s.\n", (name) ? name : "(unknown)");
		bonjour_jabber_stream_ended(bconv);
		return;
	}

	message[len] = '\0';

	purple_debug_info("bonjour", "Receive: -%s- %" G_GSSIZE_FORMAT " bytes\n", message, len);
	bonjour_parser_process(bconv, message, len);
}

struct _stream_start_data {
	char *msg;
};


static void
_start_stream(gpointer data, gint source, PurpleInputCondition condition)
{
	BonjourJabberConversation *bconv = data;
	struct _stream_start_data *ss = bconv->stream_data;
	int len, ret;

	len = strlen(ss->msg);

	/* Start Stream */
	ret = send(source, ss->msg, len, 0);

	if (ret == -1 && errno == EAGAIN)
		return;
	else if (ret <= 0) {
		const char *err = g_strerror(errno);
		PurpleConversation *conv;
		const char *bname = bconv->buddy_name;
		BonjourBuddy *bb = NULL;

		if(bconv->pb) {
			bb = purple_buddy_get_protocol_data(bconv->pb);
			bname = purple_buddy_get_name(bconv->pb);
		}

		purple_debug_error("bonjour", "Error starting stream with buddy %s at %s error: %s\n",
				   bname ? bname : "(unknown)", bconv->ip, err ? err : "(null)");

		conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, bname, bconv->account);
		if (conv != NULL)
			purple_conversation_write(conv, NULL,
				  _("Unable to send the message, the conversation couldn't be started."),
				  PURPLE_MESSAGE_SYSTEM, time(NULL));

		bonjour_jabber_close_conversation(bconv);
		if(bb != NULL)
			bb->conversation = NULL;

		return;
	}

	/* This is EXTREMELY unlikely to happen */
	if (ret < len) {
		char *tmp = g_strdup(ss->msg + ret);
		g_free(ss->msg);
		ss->msg = tmp;
		return;
	}

	g_free(ss->msg);
	g_free(ss);
	bconv->stream_data = NULL;

	/* Stream started; process the send buffer if there is one */
	purple_input_remove(bconv->tx_handler);
	bconv->tx_handler = 0;
	bconv->sent_stream_start = FULLY_SENT;

	bonjour_jabber_stream_started(bconv);
}

static gboolean bonjour_jabber_send_stream_init(BonjourJabberConversation *bconv, int client_socket)
{
	int ret, len;
	char *stream_start;
	const char *bname = bconv->buddy_name;

	if (bconv->pb != NULL)
		bname = purple_buddy_get_name(bconv->pb);

	/* If we have no idea who "to" is, use an empty string.
	 * If we don't know now, it is because the other side isn't playing nice, so they can't complain. */
	if (bname == NULL)
		bname = "";

	stream_start = g_strdup_printf(DOCTYPE, bonjour_get_jid(bconv->account), bname);
	len = strlen(stream_start);

	bconv->sent_stream_start = PARTIALLY_SENT;

	/* Start the stream */
	ret = send(client_socket, stream_start, len, 0);

	if (ret == -1 && errno == EAGAIN)
		ret = 0;
	else if (ret <= 0) {
		const char *err = g_strerror(errno);

		purple_debug_error("bonjour", "Error starting stream with buddy %s at %s error: %s\n",
				   (*bname) ? bname : "(unknown)", bconv->ip, err ? err : "(null)");

		if (bconv->pb) {
			PurpleConversation *conv;
			conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, bname, bconv->account);
			if (conv != NULL)
				purple_conversation_write(conv, NULL,
					  _("Unable to send the message, the conversation couldn't be started."),
					  PURPLE_MESSAGE_SYSTEM, time(NULL));
		}

		close(client_socket);
		g_free(stream_start);

		return FALSE;
	}

	/* This is unlikely to happen */
	if (ret < len) {
		struct _stream_start_data *ss = g_new(struct _stream_start_data, 1);
		ss->msg = g_strdup(stream_start + ret);
		bconv->stream_data = ss;
		/* Finish sending the stream start */
		bconv->tx_handler = purple_input_add(client_socket,
			PURPLE_INPUT_WRITE, _start_stream, bconv);
	} else
		bconv->sent_stream_start = FULLY_SENT;

	g_free(stream_start);

	return TRUE;
}

/* This gets called when we've successfully sent our <stream:stream />
 * AND when we've received a <stream:stream /> */
void bonjour_jabber_stream_started(BonjourJabberConversation *bconv) {

	if (bconv->sent_stream_start == NOT_SENT && !bonjour_jabber_send_stream_init(bconv, bconv->socket)) {
		const char *err = g_strerror(errno);
		const char *bname = bconv->buddy_name;

		if (bconv->pb)
			bname = purple_buddy_get_name(bconv->pb);

		purple_debug_error("bonjour", "Error starting stream with buddy %s at %s error: %s\n",
				   bname ? bname : "(unknown)", bconv->ip, err ? err : "(null)");

		if (bconv->pb) {
			PurpleConversation *conv;
			conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, bname, bconv->account);
			if (conv != NULL)
				purple_conversation_write(conv, NULL,
					  _("Unable to send the message, the conversation couldn't be started."),
					  PURPLE_MESSAGE_SYSTEM, time(NULL));
		}

		/* We don't want to recieve anything else */
		close(bconv->socket);
		bconv->socket = -1;

		/* This must be asynchronous because it destroys the parser and we
		 * may be in the middle of parsing.
		 */
		async_bonjour_jabber_close_conversation(bconv);
		return;
	}

	/* If the stream has been completely started and we know who we're talking to, we can start doing stuff. */
	/* I don't think the circ_buffer can actually contain anything without a buddy being associated, but lets be explicit. */
	if (bconv->sent_stream_start == FULLY_SENT && bconv->recv_stream_start
			&& bconv->pb && purple_circ_buffer_get_max_read(bconv->tx_buf) > 0) {
		/* Watch for when we can write the buffered messages */
		bconv->tx_handler = purple_input_add(bconv->socket, PURPLE_INPUT_WRITE,
			_send_data_write_cb, bconv->pb);
		/* We can probably write the data right now. */
		_send_data_write_cb(bconv->pb, bconv->socket, PURPLE_INPUT_WRITE);
	}

}

#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif

static void
_server_socket_handler(gpointer data, int server_socket, PurpleInputCondition condition)
{
	BonjourJabber *jdata = data;
	struct sockaddr_storage their_addr; /* connector's address information */
	socklen_t sin_size = sizeof(struct sockaddr_storage);
	int client_socket;
	int flags;
#ifdef HAVE_INET_NTOP
	char addrstr[INET6_ADDRSTRLEN];
#endif
	const char *address_text;
	struct _match_buddies_by_address_t *mbba;
	BonjourJabberConversation *bconv;
	GSList *buddies;

	/* Check that it is a read condition */
	if (condition != PURPLE_INPUT_READ)
		return;

	memset(&their_addr, 0, sin_size);

	if ((client_socket = accept(server_socket, (struct sockaddr*)&their_addr, &sin_size)) == -1)
		return;

	flags = fcntl(client_socket, F_GETFL);
	fcntl(client_socket, F_SETFL, flags | O_NONBLOCK);
#ifndef _WIN32
	fcntl(client_socket, F_SETFD, FD_CLOEXEC);
#endif

	/* Look for the buddy that has opened the conversation and fill information */
#ifdef HAVE_INET_NTOP
	if (their_addr.ss_family == AF_INET6) {
		address_text = inet_ntop(their_addr.ss_family, &((struct sockaddr_in6 *)&their_addr)->sin6_addr,
			addrstr, sizeof(addrstr));

		append_iface_if_linklocal(addrstr,
			((struct sockaddr_in6 *)&their_addr)->sin6_scope_id);
	}
	else
		address_text = inet_ntop(their_addr.ss_family, &((struct sockaddr_in *)&their_addr)->sin_addr,
			addrstr, sizeof(addrstr));
#else
	address_text = inet_ntoa(((struct sockaddr_in *)&their_addr)->sin_addr);
#endif
	purple_debug_info("bonjour", "Received incoming connection from %s.\n", address_text);
	mbba = g_new0(struct _match_buddies_by_address_t, 1);
	mbba->address = address_text;

	buddies = purple_find_buddies(jdata->account, NULL);
	g_slist_foreach(buddies, _match_buddies_by_address, mbba);
	g_slist_free(buddies);

	if (mbba->matched_buddies == NULL) {
		purple_debug_info("bonjour", "We don't like invisible buddies, this is not a superheroes comic\n");
		g_free(mbba);
		close(client_socket);
		return;
	}

	g_slist_free(mbba->matched_buddies);
	g_free(mbba);

	/* We've established that this *could* be from one of our buddies.
	 * Wait for the stream open to see if that matches too before assigning it.
	 */
	bconv = bonjour_jabber_conv_new(NULL, jdata->account, address_text);

	/* We wait for the stream start before doing anything else */
	bconv->socket = client_socket;
	bconv->rx_handler = purple_input_add(client_socket, PURPLE_INPUT_READ, _client_socket_handler, bconv);

}

static int
start_serversocket_listening(int port, int socket, struct sockaddr *addr, size_t addr_size, gboolean ip6, gboolean allow_port_fallback)
{
	int ret_port = port;

	purple_debug_info("bonjour", "Attempting to bind IPv%d socket to port %d.\n", ip6 ? 6 : 4, port);

	/* Try to use the specified port - if it isn't available, use a random port */
	if (bind(socket, addr, addr_size) != 0) {

		purple_debug_info("bonjour", "Unable to bind to specified "
				"port %i: %s\n", port, g_strerror(errno));

		if (!allow_port_fallback) {
			purple_debug_warning("bonjour", "Not attempting random port assignment.\n");
			return -1;
		}
#ifdef PF_INET6
		if (ip6)
			((struct sockaddr_in6 *) addr)->sin6_port = 0;
		else
#endif
		((struct sockaddr_in *) addr)->sin_port = 0;

		if (bind(socket, addr, addr_size) != 0) {
			purple_debug_error("bonjour", "Unable to bind IPv%d socket to port: %s\n", ip6 ? 6 : 4, g_strerror(errno));
			return -1;
		}
		ret_port = purple_network_get_port_from_fd(socket);
	}

	purple_debug_info("bonjour", "Bound IPv%d socket to port %d.\n", ip6 ? 6 : 4, ret_port);

	/* Attempt to listen on the bound socket */
	if (listen(socket, 10) != 0) {
		purple_debug_error("bonjour", "Unable to listen on IPv%d socket: %s\n", ip6 ? 6 : 4, g_strerror(errno));
		return -1;
	}

#if 0
	/* TODO: Why isn't this being used? */
	data->socket = purple_network_listen(jdata->port, SOCK_STREAM);

	if (jdata->socket == -1)
	{
		purple_debug_error("bonjour", "No se ha podido crear el socket\n");
	}
#endif

	return ret_port;
}

gint
bonjour_jabber_start(BonjourJabber *jdata)
{
	int ipv6_port = -1, ipv4_port = -1;

	/* Open a listening socket for incoming conversations */
#ifdef PF_INET6
	jdata->socket6 = socket(PF_INET6, SOCK_STREAM, 0);
#endif
	jdata->socket = socket(PF_INET, SOCK_STREAM, 0);
	if (jdata->socket == -1 && jdata->socket6 == -1) {
		purple_debug_error("bonjour", "Unable to create socket: %s",
				g_strerror(errno));
		return -1;
	}

#ifdef PF_INET6
	if (jdata->socket6 != -1) {
		struct sockaddr_in6 addr6;
#ifdef IPV6_V6ONLY
		int on = 1;
		setsockopt(jdata->socket6, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));
#endif
	        memset(&addr6, 0, sizeof(addr6));
		addr6.sin6_family = AF_INET6;
		addr6.sin6_port = htons(jdata->port);
      		addr6.sin6_addr = in6addr_any;
		ipv6_port = start_serversocket_listening(jdata->port, jdata->socket6, (struct sockaddr *) &addr6, sizeof(addr6), TRUE, TRUE);
		/* Open a watcher in the socket we have just opened */
		if (ipv6_port > 0) {
			jdata->watcher_id6 = purple_input_add(jdata->socket6, PURPLE_INPUT_READ, _server_socket_handler, jdata);
			jdata->port = ipv6_port;
		} else {
			purple_debug_error("bonjour", "Failed to start listening on IPv6 socket.\n");
			close(jdata->socket6);
			jdata->socket6 = -1;
		}
	}
#endif
	if (jdata->socket != -1) {
		struct sockaddr_in addr4;
		memset(&addr4, 0, sizeof(addr4));
		addr4.sin_family = AF_INET;
		addr4.sin_port = htons(jdata->port);
		ipv4_port = start_serversocket_listening(jdata->port, jdata->socket, (struct sockaddr *) &addr4, sizeof(addr4), FALSE, ipv6_port != -1);
		/* Open a watcher in the socket we have just opened */
		if (ipv4_port > 0) {
			jdata->watcher_id = purple_input_add(jdata->socket, PURPLE_INPUT_READ, _server_socket_handler, jdata);
			jdata->port = ipv4_port;
		} else {
			purple_debug_error("bonjour", "Failed to start listening on IPv4 socket.\n");
			close(jdata->socket);
			jdata->socket = -1;
		}
	}

	if (!(ipv6_port > 0 || ipv4_port > 0)) {
		purple_debug_error("bonjour", "Unable to listen on socket: %s",
				g_strerror(errno));
		return -1;
	}

	return jdata->port;
}

static void
_connected_to_buddy(gpointer data, gint source, const gchar *error)
{
	PurpleBuddy *pb = data;
	BonjourBuddy *bb = purple_buddy_get_protocol_data(pb);

	bb->conversation->connect_data = NULL;

	if (source < 0) {
		PurpleConversation *conv = NULL;
		PurpleAccount *account = NULL;
		GSList *tmp = bb->ips;

		purple_debug_error("bonjour", "Error connecting to buddy %s at %s:%d (%s); Trying next IP address\n",
				   purple_buddy_get_name(pb), bb->conversation->ip, bb->port_p2pj, error);

		/* There may be multiple entries for the same IP - one per
		 * presence recieved (e.g. multiple interfaces).
		 * We need to make sure that we find the previously used entry.
		 */
		while (tmp && bb->conversation->ip_link != tmp->data)
			tmp = g_slist_next(tmp);
		if (tmp)
			tmp = g_slist_next(tmp);

		account = purple_buddy_get_account(pb);

		if (tmp != NULL) {
			const gchar *ip;
			PurpleProxyConnectData *connect_data;

			bb->conversation->ip_link = ip = tmp->data;

			purple_debug_info("bonjour", "Starting conversation with %s at %s:%d\n",
					  purple_buddy_get_name(pb), ip, bb->port_p2pj);

			connect_data = purple_proxy_connect(purple_account_get_connection(account),
							    account, ip, bb->port_p2pj, _connected_to_buddy, pb);

			if (connect_data != NULL) {
				g_free(bb->conversation->ip);
				bb->conversation->ip = g_strdup(ip);
				bb->conversation->connect_data = connect_data;

				return;
			}
		}

		purple_debug_error("bonjour", "No more addresses for buddy %s. Aborting", purple_buddy_get_name(pb));

		conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, bb->name, account);
		if (conv != NULL)
			purple_conversation_write(conv, NULL,
				  _("Unable to send the message, the conversation couldn't be started."),
				  PURPLE_MESSAGE_SYSTEM, time(NULL));

		bonjour_jabber_close_conversation(bb->conversation);
		bb->conversation = NULL;
		return;
	}

	if (!bonjour_jabber_send_stream_init(bb->conversation, source)) {
		const char *err = g_strerror(errno);
		PurpleConversation *conv = NULL;
		PurpleAccount *account = NULL;

		purple_debug_error("bonjour", "Error starting stream with buddy %s at %s:%d error: %s\n",
				   purple_buddy_get_name(pb), bb->conversation->ip, bb->port_p2pj, err ? err : "(null)");

		account = purple_buddy_get_account(pb);

		conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, bb->name, account);
		if (conv != NULL)
			purple_conversation_write(conv, NULL,
				  _("Unable to send the message, the conversation couldn't be started."),
				  PURPLE_MESSAGE_SYSTEM, time(NULL));

		close(source);
		bonjour_jabber_close_conversation(bb->conversation);
		bb->conversation = NULL;
		return;
	}

	/* Start listening for the stream acknowledgement */
	bb->conversation->socket = source;
	bb->conversation->rx_handler = purple_input_add(source,
		PURPLE_INPUT_READ, _client_socket_handler, bb->conversation);
}

void
bonjour_jabber_conv_match_by_name(BonjourJabberConversation *bconv) {
	PurpleBuddy *pb = NULL;
	BonjourBuddy *bb = NULL;

	g_return_if_fail(bconv->ip != NULL);
	g_return_if_fail(bconv->pb == NULL);

	pb = purple_find_buddy(bconv->account, bconv->buddy_name);
	if (pb && (bb = purple_buddy_get_protocol_data(pb))) {
		const char *ip;
		GSList *tmp = bb->ips;

		purple_debug_info("bonjour", "Found buddy %s for incoming conversation \"from\" attrib.\n",
			purple_buddy_get_name(pb));

		/* Check that one of the buddy's IPs matches */
		while(tmp) {
			ip = tmp->data;
			if (ip != NULL && g_ascii_strcasecmp(ip, bconv->ip) == 0) {
				BonjourJabber *jdata = ((BonjourData*) bconv->account->gc->proto_data)->jabber_data;

				purple_debug_info("bonjour", "Matched buddy %s to incoming conversation \"from\" attrib and IP (%s)\n",
					purple_buddy_get_name(pb), bconv->ip);

				/* Attach conv. to buddy and remove from pending list */
				jdata->pending_conversations = g_slist_remove(jdata->pending_conversations, bconv);

				/* Check if the buddy already has a conversation and, if so, replace it */
				if(bb->conversation != NULL && bb->conversation != bconv)
					bonjour_jabber_close_conversation(bb->conversation);

				bconv->pb = pb;
				bb->conversation = bconv;

				break;
			}
			tmp = tmp->next;
		}
	}

	/* We've failed to match a buddy - give up */
	if (bconv->pb == NULL) {
		/* This must be asynchronous because it destroys the parser and we
		 * may be in the middle of parsing.
		 */
		async_bonjour_jabber_close_conversation(bconv);
	}
}


void
bonjour_jabber_conv_match_by_ip(BonjourJabberConversation *bconv) {
	BonjourJabber *jdata = ((BonjourData*) bconv->account->gc->proto_data)->jabber_data;
	struct _match_buddies_by_address_t *mbba;
	GSList *buddies;

	mbba = g_new0(struct _match_buddies_by_address_t, 1);
	mbba->address = bconv->ip;

	buddies = purple_find_buddies(jdata->account, NULL);
	g_slist_foreach(buddies, _match_buddies_by_address, mbba);
	g_slist_free(buddies);

	/* If there is exactly one match, use it */
	if(mbba->matched_buddies != NULL) {
		if(mbba->matched_buddies->next != NULL)
			purple_debug_error("bonjour", "More than one buddy matched for ip %s.\n", bconv->ip);
		else {
			PurpleBuddy *pb = mbba->matched_buddies->data;
			BonjourBuddy *bb = purple_buddy_get_protocol_data(pb);

			purple_debug_info("bonjour", "Matched buddy %s to incoming conversation using IP (%s)\n",
				purple_buddy_get_name(pb), bconv->ip);

			/* Attach conv. to buddy and remove from pending list */
			jdata->pending_conversations = g_slist_remove(jdata->pending_conversations, bconv);

			/* Check if the buddy already has a conversation and, if so, replace it */
			if (bb->conversation != NULL && bb->conversation != bconv)
				bonjour_jabber_close_conversation(bb->conversation);

			bconv->pb = pb;
			bb->conversation = bconv;
		}
	} else
		purple_debug_error("bonjour", "No buddies matched for ip %s.\n", bconv->ip);

	/* We've failed to match a buddy - give up */
	if (bconv->pb == NULL) {
		/* This must be asynchronous because it destroys the parser and we
		 * may be in the middle of parsing.
		 */
		async_bonjour_jabber_close_conversation(bconv);
	}

	g_slist_free(mbba->matched_buddies);
	g_free(mbba);
}

static PurpleBuddy *
_find_or_start_conversation(BonjourJabber *jdata, const gchar *to)
{
	PurpleBuddy *pb = NULL;
	BonjourBuddy *bb = NULL;

	g_return_val_if_fail(jdata != NULL, NULL);
	g_return_val_if_fail(to != NULL, NULL);

	pb = purple_find_buddy(jdata->account, to);
	if (pb == NULL || (bb = purple_buddy_get_protocol_data(pb)) == NULL)
		/* You can not send a message to an offline buddy */
		return NULL;

	/* Check if there is a previously open conversation */
	if (bb->conversation == NULL)
	{
		PurpleProxyConnectData *connect_data;
		PurpleProxyInfo *proxy_info;
		const char *ip = bb->ips->data; /* Start with the first IP address. */

		purple_debug_info("bonjour", "Starting conversation with %s at %s:%d\n", to, ip, bb->port_p2pj);

		/* Make sure that the account always has a proxy of "none".
		 * This is kind of dirty, but proxy_connect_none() isn't exposed. */
		proxy_info = purple_account_get_proxy_info(jdata->account);
		if (proxy_info == NULL) {
			proxy_info = purple_proxy_info_new();
			purple_account_set_proxy_info(jdata->account, proxy_info);
		}
		purple_proxy_info_set_type(proxy_info, PURPLE_PROXY_NONE);

		connect_data = purple_proxy_connect(
						    purple_account_get_connection(jdata->account),
						    jdata->account,
						    ip, bb->port_p2pj, _connected_to_buddy, pb);

		if (connect_data == NULL) {
			purple_debug_error("bonjour", "Unable to connect to buddy (%s).\n", to);
			return NULL;
		}

		bb->conversation = bonjour_jabber_conv_new(pb, jdata->account, ip);
		bb->conversation->connect_data = connect_data;
		bb->conversation->ip_link = ip;
		/* We don't want _send_data() to register the tx_handler;
		 * that neeeds to wait until we're actually connected. */
		bb->conversation->tx_handler = 0;
	}
	return pb;
}

int
bonjour_jabber_send_message(BonjourJabber *jdata, const gchar *to, const gchar *body)
{
	xmlnode *message_node, *node, *node2;
	gchar *message, *xhtml;
	PurpleBuddy *pb;
	BonjourBuddy *bb;
	int ret;

	pb = _find_or_start_conversation(jdata, to);
	if (pb == NULL || (bb = purple_buddy_get_protocol_data(pb)) == NULL) {
		purple_debug_info("bonjour", "Can't send a message to an offline buddy (%s).\n", to);
		/* You can not send a message to an offline buddy */
		return -10000;
	}

	purple_markup_html_to_xhtml(body, &xhtml, &message);

	message_node = xmlnode_new("message");
	xmlnode_set_attrib(message_node, "to", bb->name);
	xmlnode_set_attrib(message_node, "from", bonjour_get_jid(jdata->account));
	xmlnode_set_attrib(message_node, "type", "chat");

	/* Enclose the message from the UI within a "font" node */
	node = xmlnode_new_child(message_node, "body");
	xmlnode_insert_data(node, message, strlen(message));
	g_free(message);

	node = xmlnode_new_child(message_node, "html");
	xmlnode_set_namespace(node, "http://www.w3.org/1999/xhtml");

	node = xmlnode_new_child(node, "body");
	message = g_strdup_printf("<font>%s</font>", xhtml);
	node2 = xmlnode_from_str(message, strlen(message));
	g_free(xhtml);
	g_free(message);
	xmlnode_insert_child(node, node2);

	node = xmlnode_new_child(message_node, "x");
	xmlnode_set_namespace(node, "jabber:x:event");
	xmlnode_insert_child(node, xmlnode_new("composing"));

	message = xmlnode_to_str(message_node, NULL);
	xmlnode_free(message_node);

	ret = _send_data(pb, message) >= 0;

	g_free(message);

	return ret;
}

static gboolean
_async_bonjour_jabber_close_conversation_cb(gpointer data) {
	BonjourJabberConversation *bconv = data;
	bonjour_jabber_close_conversation(bconv);
	return FALSE;
}

void
async_bonjour_jabber_close_conversation(BonjourJabberConversation *bconv) {
	BonjourJabber *jdata = ((BonjourData*) bconv->account->gc->proto_data)->jabber_data;

	jdata->pending_conversations = g_slist_remove(jdata->pending_conversations, bconv);

	/* Disconnect this conv. from the buddy here so it can't be disposed of twice.*/
	if(bconv->pb != NULL) {
		BonjourBuddy *bb = purple_buddy_get_protocol_data(bconv->pb);
		if (bb->conversation == bconv)
			bb->conversation = NULL;
	}

	bconv->close_timeout = purple_timeout_add(0, _async_bonjour_jabber_close_conversation_cb, bconv);
}

void
bonjour_jabber_close_conversation(BonjourJabberConversation *bconv)
{
	if (bconv != NULL) {
		BonjourData *bd = NULL;

		if(PURPLE_CONNECTION_IS_VALID(bconv->account->gc)) {
			bd = bconv->account->gc->proto_data;
			bd->jabber_data->pending_conversations = g_slist_remove(bd->jabber_data->pending_conversations, bconv);
		}

		/* Cancel any file transfers that are waiting to begin */
		/* There wont be any transfers if it hasn't been attached to a buddy */
		if (bconv->pb != NULL && bd != NULL) {
			GSList *xfers, *tmp_next;
			xfers = bd->xfer_lists;
			while(xfers != NULL) {
				PurpleXfer *xfer = xfers->data;
				tmp_next = xfers->next;
				/* We only need to cancel this if it hasn't actually started transferring. */
				/* This will change if we ever support IBB transfers. */
				if (strcmp(xfer->who, purple_buddy_get_name(bconv->pb)) == 0
						&& (purple_xfer_get_status(xfer) == PURPLE_XFER_STATUS_NOT_STARTED
							|| purple_xfer_get_status(xfer) == PURPLE_XFER_STATUS_UNKNOWN)) {
					purple_xfer_cancel_remote(xfer);
				}
				xfers = tmp_next;
			}
		}

		/* Close the socket and remove the watcher */
		if (bconv->socket >= 0) {
			/* Send the end of the stream to the other end of the conversation */
			if (bconv->sent_stream_start == FULLY_SENT)
				send(bconv->socket, STREAM_END, strlen(STREAM_END), 0);
			/* TODO: We're really supposed to wait for "</stream:stream>" before closing the socket */
			close(bconv->socket);
		}
		if (bconv->rx_handler != 0)
			purple_input_remove(bconv->rx_handler);
		if (bconv->tx_handler > 0)
			purple_input_remove(bconv->tx_handler);

		/* Free all the data related to the conversation */
		purple_circ_buffer_destroy(bconv->tx_buf);
		if (bconv->connect_data != NULL)
			purple_proxy_connect_cancel(bconv->connect_data);
		if (bconv->stream_data != NULL) {
			struct _stream_start_data *ss = bconv->stream_data;
			g_free(ss->msg);
			g_free(ss);
		}

		if (bconv->context != NULL)
			bonjour_parser_setup(bconv);

		if (bconv->close_timeout != 0)
			purple_timeout_remove(bconv->close_timeout);

		g_free(bconv->buddy_name);
		g_free(bconv->ip);
		g_free(bconv);
	}
}

void
bonjour_jabber_stop(BonjourJabber *jdata)
{
	/* Close the server socket and remove the watcher */
	if (jdata->socket >= 0)
		close(jdata->socket);
	if (jdata->watcher_id > 0)
		purple_input_remove(jdata->watcher_id);
	if (jdata->socket6 >= 0)
		close(jdata->socket6);
	if (jdata->watcher_id6 > 0)
		purple_input_remove(jdata->watcher_id6);

	/* Close all the conversation sockets and remove all the watchers after sending end streams */
	if (jdata->account->gc != NULL) {
		GSList *buddies, *l;

		buddies = purple_find_buddies(jdata->account, NULL);
		for (l = buddies; l; l = l->next) {
			BonjourBuddy *bb = purple_buddy_get_protocol_data((PurpleBuddy*) l->data);
			if (bb && bb->conversation) {
				/* Any ongoing connection attempt is cancelled
				 * by _purple_connection_destroy */
				bb->conversation->connect_data = NULL;
				bonjour_jabber_close_conversation(bb->conversation);
				bb->conversation = NULL;
			}
		}

		g_slist_free(buddies);
	}

	while (jdata->pending_conversations != NULL) {
		bonjour_jabber_close_conversation(jdata->pending_conversations->data);
		jdata->pending_conversations = g_slist_delete_link(jdata->pending_conversations, jdata->pending_conversations);
	}
}

XepIq *
xep_iq_new(void *data, XepIqType type, const char *to, const char *from, const char *id)
{
	xmlnode *iq_node = NULL;
	XepIq *iq = NULL;

	g_return_val_if_fail(data != NULL, NULL);
	g_return_val_if_fail(to != NULL, NULL);
	g_return_val_if_fail(id != NULL, NULL);

	iq_node = xmlnode_new("iq");

	xmlnode_set_attrib(iq_node, "to", to);
	xmlnode_set_attrib(iq_node, "from", from);
	xmlnode_set_attrib(iq_node, "id", id);
	switch (type) {
		case XEP_IQ_SET:
			xmlnode_set_attrib(iq_node, "type", "set");
			break;
		case XEP_IQ_GET:
			xmlnode_set_attrib(iq_node, "type", "get");
			break;
		case XEP_IQ_RESULT:
			xmlnode_set_attrib(iq_node, "type", "result");
			break;
		case XEP_IQ_ERROR:
			xmlnode_set_attrib(iq_node, "type", "error");
			break;
		case XEP_IQ_NONE:
		default:
			xmlnode_set_attrib(iq_node, "type", "none");
			break;
	}

	iq = g_new0(XepIq, 1);
	iq->node = iq_node;
	iq->type = type;
	iq->data = ((BonjourData*)data)->jabber_data;
	iq->to = (char*)to;

	return iq;
}

static gboolean
check_if_blocked(PurpleBuddy *pb)
{
	gboolean blocked = FALSE;
	GSList *l = NULL;
	PurpleAccount *acc = purple_buddy_get_account(pb);

	if(acc == NULL)
		return FALSE;

	acc = purple_buddy_get_account(pb);

	for(l = acc->deny; l != NULL; l = l->next) {
		const gchar *name = purple_buddy_get_name(pb);
		const gchar *username = bonjour_get_jid(acc);

		if(!purple_utf8_strcasecmp(name, (char *)l->data)) {
			purple_debug_info("bonjour", "%s has been blocked by %s.\n", name, username);
			blocked = TRUE;
			break;
		}
	}
	return blocked;
}

static void
xep_iq_parse(xmlnode *packet, PurpleBuddy *pb)
{
	PurpleAccount *account;
	PurpleConnection *gc;

	if(check_if_blocked(pb))
		return;

		account = purple_buddy_get_account(pb);
		gc = purple_account_get_connection(account);

	if (xmlnode_get_child(packet, "si") != NULL || xmlnode_get_child(packet, "error") != NULL)
		xep_si_parse(gc, packet, pb);
	else
		xep_bytestreams_parse(gc, packet, pb);
}

int
xep_iq_send_and_free(XepIq *iq)
{
	int ret = -1;
	PurpleBuddy *pb = NULL;

	/* start the talk, reuse the message socket  */
	pb = _find_or_start_conversation((BonjourJabber*) iq->data, iq->to);
	/* Send the message */
	if (pb != NULL) {
		/* Convert xml node into stream */
		gchar *msg = xmlnode_to_str(iq->node, NULL);
		ret = _send_data(pb, msg);
		g_free(msg);
	}

	xmlnode_free(iq->node);
	iq->node = NULL;
	g_free(iq);

	return (ret >= 0) ? 0 : -1;
}

/* This returns a list containing all non-localhost IPs */
GSList *
bonjour_jabber_get_local_ips(int fd)
{
	GSList *ips = NULL;
	const char *address_text;
	int ret;

#ifdef HAVE_GETIFADDRS /* This is required for IPv6 */
	{
	struct ifaddrs *ifap, *ifa;
	struct sockaddr *addr;
	char addrstr[INET6_ADDRSTRLEN];

	ret = getifaddrs(&ifap);
	if (ret != 0) {
		const char *error = g_strerror(errno);
		purple_debug_error("bonjour", "getifaddrs() error: %s\n", error ? error : "(null)");
		return NULL;
	}

	for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
		if (!(ifa->ifa_flags & IFF_RUNNING) || (ifa->ifa_flags & IFF_LOOPBACK) || ifa->ifa_addr == NULL)
			continue;

		addr = ifa->ifa_addr;
		address_text = NULL;
		switch (addr->sa_family) {
			case AF_INET:
				address_text = inet_ntop(addr->sa_family, &((struct sockaddr_in *)addr)->sin_addr,
					addrstr, sizeof(addrstr));
				break;
#ifdef PF_INET6
			case AF_INET6:
				address_text = inet_ntop(addr->sa_family, &((struct sockaddr_in6 *)addr)->sin6_addr,
					addrstr, sizeof(addrstr));
				break;
#endif
		}

		if (address_text != NULL) {
			if (addr->sa_family == AF_INET)
				ips = g_slist_append(ips, g_strdup(address_text));
			else
				ips = g_slist_prepend(ips, g_strdup(address_text));
		}
	}

	freeifaddrs(ifap);

	}
#else
	{
	char *tmp;
	struct ifconf ifc;
	struct ifreq *ifr;
	char buffer[1024];
	struct sockaddr_in *sinptr;
	int source = fd;

	if (fd < 0)
		source = socket(PF_INET, SOCK_STREAM, 0);

	ifc.ifc_len = sizeof(buffer);
	ifc.ifc_req = (struct ifreq *)buffer;
	ret = ioctl(source, SIOCGIFCONF, &ifc);

	if (fd < 0)
		close(source);

	if (ret < 0) {
		const char *error = g_strerror(errno);
		purple_debug_error("bonjour", "ioctl(SIOCGIFCONF) error: %s\n", error ? error : "(null)");
		return NULL;
	}

	tmp = buffer;
	while (tmp < buffer + ifc.ifc_len) {
		ifr = (struct ifreq *)tmp;
		tmp += HX_SIZE_OF_IFREQ(*ifr);

		if (ifr->ifr_addr.sa_family == AF_INET) {
			sinptr = (struct sockaddr_in *)&ifr->ifr_addr;
			if ((ntohl(sinptr->sin_addr.s_addr) >> 24) != 127) {
				address_text = inet_ntoa(sinptr->sin_addr);
				ips = g_slist_prepend(ips, g_strdup(address_text));
			}
 		}
	}
	}
#endif

	return ips;
}

void
append_iface_if_linklocal(char *ip, guint32 interface_param) {
	struct in6_addr in6_addr;
	int len_remain = INET6_ADDRSTRLEN - strlen(ip);

	if (len_remain <= 1)
		return;

	if (inet_pton(AF_INET6, ip, &in6_addr) != 1 ||
	    !IN6_IS_ADDR_LINKLOCAL(&in6_addr))
		return;

	snprintf(ip + strlen(ip), len_remain, "%%%d",
		 interface_param);
}
