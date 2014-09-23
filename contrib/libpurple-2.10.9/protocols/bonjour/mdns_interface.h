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

#ifndef _BONJOUR_MDNS_INTERFACE
#define _BONJOUR_MDNS_INTERFACE

#include "mdns_types.h"
#include "buddy.h"

gboolean _mdns_init_session(BonjourDnsSd *data);

gboolean _mdns_publish(BonjourDnsSd *data, PublishType type, GSList *records);

gboolean _mdns_browse(BonjourDnsSd *data);

void _mdns_stop(BonjourDnsSd *data);

gboolean _mdns_set_buddy_icon_data(BonjourDnsSd *data, gconstpointer avatar_data, gsize avatar_len);

void _mdns_init_buddy(BonjourBuddy *buddy);

void _mdns_delete_buddy(BonjourBuddy *buddy);

void _mdns_retrieve_buddy_icon(BonjourBuddy* buddy);

#endif
