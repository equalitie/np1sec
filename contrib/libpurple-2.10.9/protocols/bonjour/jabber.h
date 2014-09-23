/**
 * @file jabber.h The Purple interface to mDNS and peer to peer Jabber.
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
 *
 */

#ifndef _BONJOUR_JABBER_H_
#define _BONJOUR_JABBER_H_

#include <libxml/parser.h>

#include "xmlnode.h"

#include "account.h"
#include "circbuffer.h"

typedef struct _BonjourJabber
{
	gint port;
	gint socket;
	gint socket6;
	gint watcher_id;
	gint watcher_id6;
	PurpleAccount *account;
	GSList *pending_conversations;
} BonjourJabber;

typedef struct _BonjourJabberConversation
{
	gint socket;
	guint rx_handler;
	guint tx_handler;
	guint close_timeout;
	PurpleCircBuffer *tx_buf;
	int sent_stream_start; /* 0 = Unsent, 1 = Partial, 2 = Complete */
	gboolean recv_stream_start;
	PurpleProxyConnectData *connect_data;
	gpointer stream_data;
	xmlParserCtxt *context;
	xmlnode *current;
	PurpleBuddy *pb;
	PurpleAccount *account;

	/* The following are only needed before attaching to a PurpleBuddy */
	gchar *buddy_name;
	gchar *ip;
	/* This points to a data entry in BonjourBuddy->ips */
	const gchar *ip_link;
} BonjourJabberConversation;

/**
 * Start listening for jabber connections.
 *
 * @return -1 if there was a problem, else returns the listening
 *         port number.
 */
gint bonjour_jabber_start(BonjourJabber *data);

int bonjour_jabber_send_message(BonjourJabber *data, const char *to, const char *body);

void bonjour_jabber_close_conversation(BonjourJabberConversation *bconv);

void async_bonjour_jabber_close_conversation(BonjourJabberConversation *bconv);

void bonjour_jabber_stream_started(BonjourJabberConversation *bconv);

void bonjour_jabber_process_packet(PurpleBuddy *pb, xmlnode *packet);

void bonjour_jabber_stop(BonjourJabber *data);

void bonjour_jabber_conv_match_by_ip(BonjourJabberConversation *bconv);

void bonjour_jabber_conv_match_by_name(BonjourJabberConversation *bconv);

typedef enum {
	XEP_IQ_SET,
	XEP_IQ_GET,
	XEP_IQ_RESULT,
	XEP_IQ_ERROR,
	XEP_IQ_NONE
} XepIqType;

typedef struct _XepIq {
	XepIqType type;
	char *id;
	xmlnode *node;
	char *to;
	void *data;
} XepIq;

XepIq *xep_iq_new(void *data, XepIqType type, const char *to, const char *from, const char *id);
int xep_iq_send_and_free(XepIq *iq);
GSList * bonjour_jabber_get_local_ips(int fd);

void append_iface_if_linklocal(char *ip, guint32 interface_param);

#endif /* _BONJOUR_JABBER_H_ */
