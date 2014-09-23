/**
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

#ifndef JABBER_GOOGLE_RELAY
#define JABBER_GOOGLE_RELAY

#include "google_session.h"

typedef void (JabberGoogleRelayCallback)(GoogleSession *session, const gchar *ip,
    guint udp_port, guint tcp_port, guint tls_port,
    const gchar *username, const gchar *password);

void jabber_google_do_relay_request(JabberStream *js, GoogleSession *session,
	JabberGoogleRelayCallback cb);

#endif /* JABBER_GOOGLE_RELAY */
