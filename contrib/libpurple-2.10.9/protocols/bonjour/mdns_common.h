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

#ifndef _BONJOUR_MDNS_COMMON
#define _BONJOUR_MDNS_COMMON

#include "mdns_types.h"

#include "buddy.h"

/**
 * Allocate space for the dns-sd data.
 */
BonjourDnsSd *bonjour_dns_sd_new(void);

/**
 * Deallocate the space of the dns-sd data.
 */
void bonjour_dns_sd_free(BonjourDnsSd *data);

/**
 * Send a new dns-sd packet updating our status.
 */
void bonjour_dns_sd_send_status(BonjourDnsSd *data, const char *status, const char *status_message);

/**
 * Retrieve the buddy icon blob
 */
void bonjour_dns_sd_retrieve_buddy_icon(BonjourBuddy* buddy);

/**
 * Deal with a buddy icon update
 */
void bonjour_dns_sd_update_buddy_icon(BonjourDnsSd *data);

/**
 * Advertise our presence within the dns-sd daemon and start
 * browsing for other bonjour peers.
 */
gboolean bonjour_dns_sd_start(BonjourDnsSd *data);

/**
 * Unregister the "_presence._tcp" service at the mDNS daemon.
 */
void bonjour_dns_sd_stop(BonjourDnsSd *data);

void bonjour_dns_sd_set_jid(PurpleAccount *account, const char *hostname);

#endif
