/**
 * @file bonjour.h The Purple interface to mDNS and peer to peer Jabber.
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

#ifndef _BONJOUR_H_
#define _BONJOUR_H_

#include "mdns_common.h"
#include "internal.h"
#include "jabber.h"

#define BONJOUR_GROUP_NAME _("Bonjour")
#define BONJOUR_PROTOCOL_NAME "bonjour"
#define BONJOUR_ICON_NAME "bonjour"

#define BONJOUR_STATUS_ID_OFFLINE   "offline"
#define BONJOUR_STATUS_ID_AVAILABLE "available"
#define BONJOUR_STATUS_ID_AWAY      "away"

#define BONJOUR_DEFAULT_PORT 5298

typedef struct _BonjourData
{
	BonjourDnsSd *dns_sd_data;
	BonjourJabber *jabber_data;
	GSList *xfer_lists;
	gchar *jid;
} BonjourData;

/**
 *  This will always be username@machinename
 */
const char *bonjour_get_jid(PurpleAccount *account);

#endif /* _BONJOUR_H_ */
