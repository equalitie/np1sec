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

#ifndef PURPLE_JABBER_GOOGLE_SESSION_H_
#define PURPLE_JABBER_GOOGLE_SESSION_H_

#include "jabber.h"

typedef struct {
	char *id;
	char *initiator;
} GoogleSessionId;

typedef enum {
	UNINIT,
	SENT_INITIATE,
	RECEIVED_INITIATE,
	IN_PRORESS,
	TERMINATED
} GoogleSessionState;

typedef struct {
	GoogleSessionId id;
	GoogleSessionState state;
	JabberStream *js;
	char *remote_jid;
	char *iq_id;
	xmlnode *description;		/* store incoming description through
	 								relay credential fetching */
	gpointer session_data;
} GoogleSession;

gboolean jabber_google_session_initiate(JabberStream *js, const gchar *who,
    PurpleMediaSessionType type);

void jabber_google_session_parse(JabberStream *js, const char *from,
    JabberIqType type, const char *iq, xmlnode *session);

#endif /* PURPLE_JABBER_GOOGLE_SESSION_H_ */