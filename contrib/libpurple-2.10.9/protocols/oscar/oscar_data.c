/*
 * Purple's oscar protocol plugin
 * This file is the legal property of its developers.
 * Please see the AUTHORS file distributed alongside this file.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02111-1301  USA
*/

#include "oscar.h"

typedef struct _SnacHandler SnacHandler;

struct _SnacHandler
{
	guint16 family;
	guint16 subtype;
	aim_rxcallback_t handler;
	guint16 flags;
};

/**
 * Allocates a new OscarData and initializes it with default values.
 */
OscarData *
oscar_data_new(void)
{
	OscarData *od;
	aim_module_t *cur;
	GString *msg;

	od = g_new0(OscarData, 1);

	aim_initsnachash(od);
	od->snacid_next = 0x00000001;
	od->buddyinfo = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	od->handlerlist = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);

	/*
	 * Register all the modules for this session...
	 */
	aim__registermodule(od, misc_modfirst); /* load the catch-all first */
	aim__registermodule(od, service_modfirst);
	aim__registermodule(od, locate_modfirst);
	aim__registermodule(od, buddylist_modfirst);
	aim__registermodule(od, msg_modfirst);
	aim__registermodule(od, admin_modfirst);
	aim__registermodule(od, popups_modfirst);
	aim__registermodule(od, bos_modfirst);
	aim__registermodule(od, search_modfirst);
	aim__registermodule(od, stats_modfirst);
	aim__registermodule(od, chatnav_modfirst);
	aim__registermodule(od, chat_modfirst);
	aim__registermodule(od, bart_modfirst);
	/* missing 0x11 - 0x12 */
	aim__registermodule(od, ssi_modfirst);
	/* missing 0x14 */
	aim__registermodule(od, icq_modfirst);
	/* missing 0x16 */
	/* auth_modfirst is only needed if we're connecting with the old-style BUCP login */
	aim__registermodule(od, auth_modfirst);
	aim__registermodule(od, email_modfirst);

	msg = g_string_new("Registered modules: ");
	for (cur = od->modlistv; cur; cur = cur->next) {
		g_string_append_printf(
			msg,
			"%s (family=0x%04x, version=0x%04x, toolid=0x%04x, toolversion=0x%04x), ",
			cur->name,
			cur->family,
			cur->version,
			cur->toolid,
			cur->toolversion);
	}
	purple_debug_misc("oscar", "%s\n", msg->str);
	g_string_free(msg, TRUE);

	return od;
}

/**
 * Logoff and deallocate a session.
 *
 * @param od Session to kill
 */
void
oscar_data_destroy(OscarData *od)
{
	aim_cleansnacs(od, -1);

	/* Only used when connecting with clientLogin */
	if (od->url_data != NULL)
		purple_util_fetch_url_cancel(od->url_data);

	while (od->requesticon)
	{
		g_free(od->requesticon->data);
		od->requesticon = g_slist_delete_link(od->requesticon, od->requesticon);
	}
	g_free(od->email);
	g_free(od->newp);
	g_free(od->oldp);
	if (od->getblisttimer > 0)
		purple_timeout_remove(od->getblisttimer);
	while (od->oscar_connections != NULL)
		flap_connection_destroy(od->oscar_connections->data,
				OSCAR_DISCONNECT_DONE, NULL);

	while (od->peer_connections != NULL)
		peer_connection_destroy(od->peer_connections->data,
				OSCAR_DISCONNECT_LOCAL_CLOSED, NULL);

	aim__shutdownmodules(od);

	g_hash_table_destroy(od->buddyinfo);
	g_hash_table_destroy(od->handlerlist);

	g_free(od);
}

void
oscar_data_addhandler(OscarData *od, guint16 family, guint16 subtype, aim_rxcallback_t newhandler, guint16 flags)
{
	SnacHandler *snac_handler;

	snac_handler = g_new0(SnacHandler, 1);

	snac_handler->family = family;
	snac_handler->subtype = subtype;
	snac_handler->flags = flags;
	snac_handler->handler = newhandler;

	g_hash_table_insert(od->handlerlist,
			GUINT_TO_POINTER((family << 16) + subtype),
			snac_handler);
}

aim_rxcallback_t
aim_callhandler(OscarData *od, guint16 family, guint16 subtype)
{
	SnacHandler *snac_handler;

	snac_handler = g_hash_table_lookup(od->handlerlist, GUINT_TO_POINTER((family << 16) + subtype));

	return snac_handler ? snac_handler->handler : NULL;
}
