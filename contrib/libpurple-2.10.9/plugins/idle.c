/*
 * idle.c - I'dle Mak'er plugin for Purple
 *
 * This file is part of Purple.
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
 */

#include "internal.h"

#include "connection.h"
#include "debug.h"
#include "notify.h"
#include "plugin.h"
#include "request.h"
#include "server.h"
#include "status.h"
#include "version.h"

/* This plugin no longer depends on gtk */
#define IDLE_PLUGIN_ID "core-idle"

static GList *idled_accts = NULL;

static gboolean
unidle_filter(PurpleAccount *acct)
{
	if (g_list_find(idled_accts, acct))
		return TRUE;

	return FALSE;
}

static gboolean
idleable_filter(PurpleAccount *account)
{
	PurplePlugin *prpl;

	prpl = purple_find_prpl(purple_account_get_protocol_id(account));
	g_return_val_if_fail(prpl != NULL, FALSE);

	return (PURPLE_PLUGIN_PROTOCOL_INFO(prpl)->set_idle != NULL);
}

static void
set_idle_time(PurpleAccount *acct, int mins_idle)
{
	time_t t;
	PurpleConnection *gc = purple_account_get_connection(acct);
	PurplePresence *presence = purple_account_get_presence(acct);

	if (!gc)
		return;

	purple_debug_info("idle",
			"setting idle time for %s to %d\n",
			purple_account_get_username(acct), mins_idle);

	if (mins_idle)
		t = time(NULL) - (60 * mins_idle); /* subtract seconds idle from current time */
	else
		t = 0; /* time idle is irrelevant */

	purple_presence_set_idle(presence, mins_idle ? TRUE : FALSE, t);
}

static void
idle_action_ok(void *ignored, PurpleRequestFields *fields)
{
	int tm = purple_request_fields_get_integer(fields, "mins");
	PurpleAccount *acct = purple_request_fields_get_account(fields, "acct");

	/* only add the account to the GList if it's not already been idled */
	if (!unidle_filter(acct))
	{
		purple_debug_misc("idle",
				"%s hasn't been idled yet; adding to list.\n",
				purple_account_get_username(acct));
		idled_accts = g_list_append(idled_accts, acct);
	}

	set_idle_time(acct, tm);
}

static void
idle_all_action_ok(void *ignored, PurpleRequestFields *fields)
{
	PurpleAccount *acct = NULL;
	GList *list, *iter;
	int tm = purple_request_fields_get_integer(fields, "mins");

	list = purple_accounts_get_all_active();
	for(iter = list; iter; iter = iter->next) {
		acct = (PurpleAccount *)(iter->data);

		if(acct && idleable_filter(acct)) {
			purple_debug_misc("idle", "Idling %s.\n",
					purple_account_get_username(acct));

			set_idle_time(acct, tm);

			if(!g_list_find(idled_accts, acct))
				idled_accts = g_list_append(idled_accts, acct);
		}
	}

	g_list_free(list);
}

static void
unidle_action_ok(void *ignored, PurpleRequestFields *fields)
{
	PurpleAccount *acct = purple_request_fields_get_account(fields, "acct");

	set_idle_time(acct, 0); /* unidle the account */

	/* once the account has been unidled it shouldn't be in the list */
	idled_accts = g_list_remove(idled_accts, acct);
}


static void
idle_action(PurplePluginAction *action)
{
	/* Use the super fancy request API */

	PurpleRequestFields *request;
	PurpleRequestFieldGroup *group;
	PurpleRequestField *field;

	group = purple_request_field_group_new(NULL);

	field = purple_request_field_account_new("acct", _("Account"), NULL);
	purple_request_field_account_set_filter(field, idleable_filter);
	purple_request_field_account_set_show_all(field, FALSE);
	purple_request_field_group_add_field(group, field);

	field = purple_request_field_int_new("mins", _("Minutes"), 10);
	purple_request_field_group_add_field(group, field);

	request = purple_request_fields_new();
	purple_request_fields_add_group(request, group);

	purple_request_fields(action->plugin,
			N_("I'dle Mak'er"),
			_("Set Account Idle Time"),
			NULL,
			request,
			_("_Set"), G_CALLBACK(idle_action_ok),
			_("_Cancel"), NULL,
			NULL, NULL, NULL,
			NULL);
}

static void
unidle_action(PurplePluginAction *action)
{
	PurpleRequestFields *request;
	PurpleRequestFieldGroup *group;
	PurpleRequestField *field;

	if (idled_accts == NULL)
	{
		purple_notify_info(NULL, NULL, _("None of your accounts are idle."), NULL);
		return;
	}

	group = purple_request_field_group_new(NULL);

	field = purple_request_field_account_new("acct", _("Account"), NULL);
	purple_request_field_account_set_filter(field, unidle_filter);
	purple_request_field_account_set_show_all(field, FALSE);
	purple_request_field_group_add_field(group, field);

	request = purple_request_fields_new();
	purple_request_fields_add_group(request, group);

	purple_request_fields(action->plugin,
			N_("I'dle Mak'er"),
			_("Unset Account Idle Time"),
			NULL,
			request,
			_("_Unset"), G_CALLBACK(unidle_action_ok),
			_("_Cancel"), NULL,
			NULL, NULL, NULL,
			NULL);
}

static void
idle_all_action(PurplePluginAction *action)
{
	PurpleRequestFields *request;
	PurpleRequestFieldGroup *group;
	PurpleRequestField *field;

	group = purple_request_field_group_new(NULL);

	field = purple_request_field_int_new("mins", _("Minutes"), 10);
	purple_request_field_group_add_field(group, field);

	request = purple_request_fields_new();
	purple_request_fields_add_group(request, group);

	purple_request_fields(action->plugin,
			N_("I'dle Mak'er"),
			_("Set Idle Time for All Accounts"),
			NULL,
			request,
			_("_Set"), G_CALLBACK(idle_all_action_ok),
			_("_Cancel"), NULL,
			NULL, NULL, NULL,
			NULL);
}

static void
unidle_all_action(PurplePluginAction *action)
{
	GList *l;

	/* freeing the list here will cause segfaults if the user idles an account
	 * after the list is freed */
	for (l = idled_accts; l; l = l->next)
	{
		PurpleAccount *account = l->data;
		set_idle_time(account, 0);
	}

	g_list_free(idled_accts);
	idled_accts = NULL;
}

static GList *
actions(PurplePlugin *plugin, gpointer context)
{
	GList *l = NULL;
	PurplePluginAction *act = NULL;

	act = purple_plugin_action_new(_("Set Account Idle Time"),
			idle_action);
	l = g_list_append(l, act);

	act = purple_plugin_action_new(_("Unset Account Idle Time"),
			unidle_action);
	l = g_list_append(l, act);

	act = purple_plugin_action_new(_("Set Idle Time for All Accounts"),
			idle_all_action);
	l = g_list_append(l, act);

	act = purple_plugin_action_new(
			_("Unset Idle Time for All Idled Accounts"), unidle_all_action);
	l = g_list_append(l, act);

	return l;
}

static void
signing_off_cb(PurpleConnection *gc, void *data)
{
	PurpleAccount *account;

	account = purple_connection_get_account(gc);
	idled_accts = g_list_remove(idled_accts, account);
}

static gboolean
plugin_load(PurplePlugin *plugin)
{
	purple_signal_connect(purple_connections_get_handle(), "signing-off",
						plugin,
						PURPLE_CALLBACK(signing_off_cb), NULL);

	return TRUE;
}

static gboolean
plugin_unload(PurplePlugin *plugin)
{
	unidle_all_action(NULL);

	return TRUE;
}

static PurplePluginInfo info =
{
	PURPLE_PLUGIN_MAGIC,
	PURPLE_MAJOR_VERSION,
	PURPLE_MINOR_VERSION,
	PURPLE_PLUGIN_STANDARD,
	NULL,
	0,
	NULL,
	PURPLE_PRIORITY_DEFAULT,
	IDLE_PLUGIN_ID,

	/* This is a cultural reference.  Dy'er Mak'er is a song by Led Zeppelin.
	   If that doesn't translate well into your language, drop the 's before translating. */
	N_("I'dle Mak'er"),
	DISPLAY_VERSION,
	N_("Allows you to hand-configure how long you've been idle"),
	N_("Allows you to hand-configure how long you've been idle"),
	"Eric Warmenhoven <eric@warmenhoven.org>",
	PURPLE_WEBSITE,
	plugin_load,
	plugin_unload,
	NULL,
	NULL,
	NULL,
	NULL,
	actions,

	/* padding */
	NULL,
	NULL,
	NULL,
	NULL
};

static void
init_plugin(PurplePlugin *plugin)
{
}


PURPLE_INIT_PLUGIN(idle, init_plugin, info)

