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

/*
 * Everything related to OSCAR authorization requests.
 */

#include "oscar.h"
#include "request.h"

/* When you ask other people for authorization */
void
oscar_auth_sendrequest(PurpleConnection *gc, const char *bname, const char *msg)
{
	OscarData *od;
	PurpleAccount *account;
	PurpleBuddy *buddy;
	PurpleGroup *group;
	const char *gname;

	od = purple_connection_get_protocol_data(gc);
	account = purple_connection_get_account(gc);
	buddy = purple_find_buddy(account, bname);
	if (buddy != NULL)
		group = purple_buddy_get_group(buddy);
	else
		group = NULL;

	if (group != NULL)
	{
		gname = purple_group_get_name(group);
		purple_debug_info("oscar", "ssi: adding buddy %s to group %s\n",
				   bname, gname);
		aim_ssi_sendauthrequest(od, bname, msg ? msg : _("Please authorize me so I can add you to my buddy list."));
		if (!aim_ssi_itemlist_finditem(od->ssi.local, gname, bname, AIM_SSI_TYPE_BUDDY))
		{
			aim_ssi_addbuddy(od, bname, gname, NULL, purple_buddy_get_alias_only(buddy), NULL, NULL, TRUE);

			/* Mobile users should always be online */
			if (bname[0] == '+') {
				purple_prpl_got_user_status(account,
						purple_buddy_get_name(buddy),
						OSCAR_STATUS_ID_AVAILABLE, NULL);
				purple_prpl_got_user_status(account,
						purple_buddy_get_name(buddy),
						OSCAR_STATUS_ID_MOBILE, NULL);
			}
		}
	}
}

static void
oscar_auth_grant(gpointer cbdata)
{
	struct name_data *data = cbdata;
	PurpleConnection *gc = data->gc;
	OscarData *od = purple_connection_get_protocol_data(gc);

	aim_ssi_sendauthreply(od, data->name, 0x01, NULL);

	oscar_free_name_data(data);
}

static void
oscar_auth_dontgrant(struct name_data *data, char *msg)
{
	PurpleConnection *gc = data->gc;
	OscarData *od = purple_connection_get_protocol_data(gc);

	aim_ssi_sendauthreply(od, data->name, 0x00, msg ? msg : _("No reason given."));

	oscar_free_name_data(data);
}

static void
oscar_auth_dontgrant_msgprompt(gpointer cbdata)
{
	struct name_data *data = cbdata;
	purple_request_input(data->gc, NULL, _("Authorization Denied Message:"),
					   NULL, _("No reason given."), TRUE, FALSE, NULL,
					   _("_OK"), G_CALLBACK(oscar_auth_dontgrant),
					   _("_Cancel"), G_CALLBACK(oscar_free_name_data),
					   purple_connection_get_account(data->gc), data->name, NULL,
					   data);
}

void
oscar_auth_sendrequest_menu(PurpleBlistNode *node, gpointer ignored)
{
	PurpleBuddy *buddy;
	PurpleConnection *gc;

	g_return_if_fail(PURPLE_BLIST_NODE_IS_BUDDY(node));

	buddy = (PurpleBuddy *) node;
	gc = purple_account_get_connection(purple_buddy_get_account(buddy));
	oscar_auth_sendrequest(gc, purple_buddy_get_name(buddy), NULL);
}

/* When other people ask you for authorization */
void
oscar_auth_recvrequest(PurpleConnection *gc, gchar *name, gchar *nick, gchar *reason)
{
	PurpleAccount* account = purple_connection_get_account(gc);
	struct name_data *data = g_new(struct name_data, 1);

	data->gc = gc;
	data->name = name;
	data->nick = nick;

	purple_account_request_authorization(account, data->name, NULL, data->nick,
		reason, purple_find_buddy(account, data->name) != NULL,
		oscar_auth_grant, oscar_auth_dontgrant_msgprompt, data);
}
