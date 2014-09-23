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

#ifndef PURPLE_JABBER_GOOGLE_H_
#define PURPLE_JABBER_GOOGLE_H_

/* This is a place for Google Talk-specific XMPP extensions to live
 * such that they don't intermingle with code for the XMPP RFCs and XEPs :) */

#include "jabber.h"

#define GOOGLE_GROUPCHAT_SERVER "groupchat.google.com"

char *jabber_google_format_to_html(const char *text);

void google_buddy_node_chat(PurpleBlistNode *node, gpointer data);

#endif   /* PURPLE_JABBER_GOOGLE_H_ */
