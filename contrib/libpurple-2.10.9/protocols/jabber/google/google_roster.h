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

#ifndef PURPLE_JABBER_GOOGLE_ROSTER_H_
#define PURPLE_JABBER_GOOGLE_ROSTER_H_

#include "jabber.h"

void jabber_google_roster_outgoing(JabberStream *js, xmlnode *query, xmlnode *item);

/* Returns FALSE if this should short-circuit processing of this roster item, or TRUE
 * if this roster item should continue to be processed
 */
gboolean jabber_google_roster_incoming(JabberStream *js, xmlnode *item);

void jabber_google_roster_add_deny(JabberStream *js, const char *who);
void jabber_google_roster_rem_deny(JabberStream *js, const char *who);


#endif /* PURPLE_JABBER_GOOGLE_ROSTER_H_ */
