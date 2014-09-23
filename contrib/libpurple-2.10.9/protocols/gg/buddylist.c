/**
 * @file buddylist.c
 *
 * purple
 *
 * Copyright (C) 2005  Bartosz Oler <bartosz@bzimage.us>
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


#include <libgadu.h>

#include "gg.h"
#include "gg-utils.h"
#include "buddylist.h"

#define F_FIRSTNAME 0
#define F_LASTNAME 1
/* #define F_ 2 */
#define F_NICKNAME 3
#define F_PHONE 4
#define F_GROUP 5
#define F_UIN 6

/* void ggp_buddylist_send(PurpleConnection *gc) {{{ */
void ggp_buddylist_send(PurpleConnection *gc)
{
	GGPInfo *info = gc->proto_data;
	PurpleAccount *account = purple_connection_get_account(gc);
	GSList *buddies;
	uin_t *userlist;
	gchar *types;
	int i = 0, ret = 0;
	int size;

	buddies = purple_find_buddies(account, NULL);

	size = g_slist_length(buddies);
	userlist = g_new(uin_t, size);
	types    = g_new(gchar, size);

	for (buddies = purple_find_buddies(account, NULL); buddies;
			buddies = g_slist_delete_link(buddies, buddies), ++i)
	{
		PurpleBuddy *buddy = buddies->data;
		const gchar *name = purple_buddy_get_name(buddy);

		userlist[i] = ggp_str_to_uin(name);
		types[i]    = GG_USER_NORMAL;
		purple_debug_info("gg", "ggp_buddylist_send: adding %d\n",
		                  userlist[i]);
	}

	ret = gg_notify_ex(info->session, userlist, types, size);
	purple_debug_info("gg", "send: ret=%d; size=%d\n", ret, size);

	if (userlist) {
		g_free(userlist);
		g_free(types);
	}
}
/* }}} */

/* void ggp_buddylist_load(PurpleConnection *gc, char *buddylist) {{{ */
void ggp_buddylist_load(PurpleConnection *gc, char *buddylist)
{
	PurpleBuddy *buddy;
	PurpleGroup *group;
	gchar **users_tbl;
	int i;
	char *utf8buddylist = charset_convert(buddylist, "CP1250", "UTF-8");

	/* Don't limit the number of records in a buddylist. */
	users_tbl = g_strsplit(utf8buddylist, "\r\n", -1);

	for (i = 0; users_tbl[i] != NULL; i++) {
		gchar **data_tbl;
		gchar *name, *show, *g;

		if (strlen(users_tbl[i]) == 0)
			continue;

		data_tbl = g_strsplit(users_tbl[i], ";", 8);
		if (ggp_array_size(data_tbl) < 8) {
			purple_debug_warning("gg",
				"Something is wrong on line %d of the buddylist. Skipping.\n",
				i + 1);
			continue;
		}

		show = data_tbl[F_NICKNAME];
		name = data_tbl[F_UIN];
		if ('\0' == *name || !atol(name)) {
			purple_debug_warning("gg",
				"Identifier on line %d of the buddylist is not a number. Skipping.\n",
				i + 1);
			continue;
		}

		if ('\0' == *show) {
			show = name;
		}

		purple_debug_info("gg", "got buddy: name=%s; show=%s\n", name, show);

		if (purple_find_buddy(purple_connection_get_account(gc), name)) {
			g_strfreev(data_tbl);
			continue;
		}

		g = g_strdup("Gadu-Gadu");

		if ('\0' != data_tbl[F_GROUP]) {
			/* XXX: Probably buddy should be added to all the groups. */
			/* Hard limit to at most 50 groups */
			gchar **group_tbl = g_strsplit(data_tbl[F_GROUP], ",", 50);
			if (ggp_array_size(group_tbl) > 0) {
				g_free(g);
				g = g_strdup(group_tbl[0]);
			}
			g_strfreev(group_tbl);
		}

		buddy = purple_buddy_new(purple_connection_get_account(gc), name,
					 strlen(show) ? show : NULL);

		if (!(group = purple_find_group(g))) {
			group = purple_group_new(g);
			purple_blist_add_group(group, NULL);
		}

		purple_blist_add_buddy(buddy, NULL, group, NULL);
		g_free(g);

		g_strfreev(data_tbl);
	}
	g_strfreev(users_tbl);
	g_free(utf8buddylist);

	ggp_buddylist_send(gc);
}
/* }}} */

/* char *ggp_buddylist_dump(PurpleAccount *account) {{{ */
char *ggp_buddylist_dump(PurpleAccount *account)
{
	GSList *buddies;
	GString *buddylist = g_string_sized_new(1024);
	char *ptr;

	for (buddies = purple_find_buddies(account, NULL); buddies;
			buddies = g_slist_delete_link(buddies, buddies)) {
		PurpleBuddy *buddy = buddies->data;
		PurpleGroup *group = purple_buddy_get_group(buddy);
		const char *bname = purple_buddy_get_name(buddy);
		const char *gname = purple_group_get_name(group);
		const char *alias = purple_buddy_get_alias(buddy);

		if (alias == NULL)
			alias = bname;

		g_string_append_printf(buddylist,
				"%s;%s;%s;%s;%s;%s;%s;%s%s\r\n",
				alias, alias, alias, alias,
				"", gname, bname, "", "");
	}

	ptr = charset_convert(buddylist->str, "UTF-8", "CP1250");
	g_string_free(buddylist, TRUE);
	return ptr;
}
/* }}} */


/* vim: set ts=8 sts=0 sw=8 noet: */
