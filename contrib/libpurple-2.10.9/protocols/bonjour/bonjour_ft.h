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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,  USA
 */
#ifndef _BONJOUR_FT_H_
#define _BONJOUR_FT_H_
#include "network.h"
#include "proxy.h"
typedef struct _XepXfer XepXfer;
typedef enum {
	XEP_BYTESTREAMS = 1,
	XEP_IBB = 2,
	XEP_UNKNOWN = 4
} XepSiMode;

struct _XepXfer
{
	void *data;
	char *filename;
	int filesize;
	char *iq_id;
	char *sid;
	char *recv_id;
	char *buddy_ip;
	int mode;
	PurpleNetworkListenData *listen_data;
	int sock5_req_state;
	int rxlen;
	char rx_buf[0x500];
	char tx_buf[0x500];
	PurpleProxyInfo *proxy_info;
	PurpleProxyConnectData *proxy_connection;
	char *jid;
	char *proxy_host;
	int proxy_port;
	xmlnode *streamhost;
	PurpleBuddy *pb;
};

/**
 * Create a new PurpleXfer
 *
 * @param gc The PurpleConnection handle.
 * @param who Who will we be sending it to?
 */
PurpleXfer *bonjour_new_xfer(PurpleConnection *gc, const char *who);

/**
 * Send a file.
 *
 * @param gc The PurpleConnection handle.
 * @param who Who are we sending it to?
 * @param file What file? If NULL, user will choose after this call.
 */
void bonjour_send_file(PurpleConnection *gc, const char *who, const char *file);

void xep_si_parse(PurpleConnection *pc, xmlnode *packet, PurpleBuddy *pb);
void
xep_bytestreams_parse(PurpleConnection *pc, xmlnode *packet, PurpleBuddy *pb);
#endif
