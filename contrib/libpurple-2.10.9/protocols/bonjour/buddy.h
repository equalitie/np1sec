/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Library General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02111-1301, USA.
 */

#ifndef _BONJOUR_BUDDY
#define _BONJOUR_BUDDY

#include <glib.h>

#include "account.h"
#include "jabber.h"

typedef struct _BonjourBuddy
{
	PurpleAccount *account;

	gchar *name;
	GSList *ips;
	gint port_p2pj;

	gchar *first;
	gchar *phsh;
	gchar *status;
	gchar *email;
	gchar *last;
	gchar *jid;
	gchar *AIM;
	gchar *vc;
	gchar *msg;
	gchar *ext;
	gchar *nick;
	gchar *node;
	gchar *ver;

	BonjourJabberConversation *conversation;

	gpointer mdns_impl_data;
} BonjourBuddy;

static const char *const buddy_TXT_records[] = {
	"1st",
	"email",
	"ext",
	"jid",
	"last",
	"msg",
	"nick",
	"node",
	"phsh",
/*	"port.p2pj", Deprecated - MUST ignore */
	"status",
/*	"txtvers", Deprecated - hardcoded to 1 */
	"vc",
	"ver",
	"AIM", /* non standard */
	NULL
};

/**
 * Creates a new buddy.
 */
BonjourBuddy *bonjour_buddy_new(const gchar *name, PurpleAccount *account);

/**
 * Clear any existing values from the buddy.
 * This is called before updating so that we can notice removals
 */
void clear_bonjour_buddy_values(BonjourBuddy *buddy);

/**
 * Sets a value in the BonjourBuddy struct, destroying the old value
 */
void set_bonjour_buddy_value(BonjourBuddy *buddy, const char *record_key, const char *value, guint32 len);

/**
 * Check if all the compulsory buddy data is present.
 */
gboolean bonjour_buddy_check(BonjourBuddy *buddy);

/**
 * If the buddy doesn't previously exists, it is created. Else, its data is changed (???)
 * purple_buddy is optional; it saves an additional lookup if we already have it
 */
void bonjour_buddy_add_to_purple(BonjourBuddy *bonjour_buddy, PurpleBuddy *purple_buddy);

/**
 * The buddy has signed off Bonjour.
 * If the buddy is being saved, mark as offline, otherwise delete
 */
void bonjour_buddy_signed_off(PurpleBuddy *purple_buddy);

/**
 * We got the buddy icon data; deal with it
 */
void bonjour_buddy_got_buddy_icon(BonjourBuddy *buddy, gconstpointer data, gsize len);

/**
 * Deletes a buddy from memory.
 */
void bonjour_buddy_delete(BonjourBuddy *buddy);

#endif
