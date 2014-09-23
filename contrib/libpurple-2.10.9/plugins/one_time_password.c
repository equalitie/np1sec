/*
 * One Time Password support plugin for libpurple
 *
 * Copyright (C) 2009, Daniel Atallah <datallah@pidgin.im>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02111-1301, USA.
 */
#include "internal.h"
#include "debug.h"
#include "plugin.h"
#include "version.h"
#include "account.h"
#include "accountopt.h"

#define PLUGIN_ID "core-one_time_password"
#define PREF_NAME PLUGIN_ID "_enabled"

static void
signed_on_cb(PurpleConnection *conn, void *data)
{
	PurpleAccount *account = purple_connection_get_account(conn);

	if (purple_account_get_bool(account, PREF_NAME, FALSE)) {
		if(purple_account_get_remember_password(account))
			purple_debug_error("One Time Password",
					   "Unable to enforce one time password for account %s (%s).\n"
					   "Account is set to remember the password.\n",
					   purple_account_get_username(account),
					   purple_account_get_protocol_name(account));
		else {

			purple_debug_info("One Time Password", "Clearing password for account %s (%s).\n",
					  purple_account_get_username(account),
					  purple_account_get_protocol_name(account));

			purple_account_set_password(account, NULL);
			/* TODO: Do we need to somehow clear conn->password ? */
		}
	}
}

static gboolean
plugin_load(PurplePlugin *plugin)
{
	PurplePlugin *prpl;
	PurplePluginProtocolInfo *prpl_info;
	PurpleAccountOption *option;
	GList *l;

	/* Register protocol preference. */
	for (l = purple_plugins_get_protocols(); l != NULL; l = l->next) {
		prpl = (PurplePlugin *)l->data;
		prpl_info = PURPLE_PLUGIN_PROTOCOL_INFO(prpl);
		if (prpl_info != NULL && !(prpl_info->options & OPT_PROTO_NO_PASSWORD)) {
			option = purple_account_option_bool_new(_("One Time Password"),
								PREF_NAME, FALSE);
			prpl_info->protocol_options = g_list_append(prpl_info->protocol_options, option);
		}
	}

	/* Register callback. */
	purple_signal_connect(purple_connections_get_handle(), "signed-on",
			      plugin, PURPLE_CALLBACK(signed_on_cb), NULL);

	return TRUE;
}

static gboolean
plugin_unload(PurplePlugin *plugin)
{
	PurplePlugin *prpl;
	PurplePluginProtocolInfo *prpl_info;
	PurpleAccountOption *option;
	GList *l, *options;

	/* Remove protocol preference. */
	for (l = purple_plugins_get_protocols(); l != NULL; l = l->next) {
		prpl = (PurplePlugin *)l->data;
		prpl_info = PURPLE_PLUGIN_PROTOCOL_INFO(prpl);
		if (prpl_info != NULL && !(prpl_info->options & OPT_PROTO_NO_PASSWORD)) {
			options = prpl_info->protocol_options;
			while (options != NULL) {
				option = (PurpleAccountOption *) options->data;
				if (strcmp(PREF_NAME, purple_account_option_get_setting(option)) == 0) {
					prpl_info->protocol_options = g_list_delete_link(prpl_info->protocol_options, options);
					purple_account_option_destroy(option);
					break;
				}
				options = options->next;
			}
		}
	}

	/* Callback will be automagically unregistered */

	return TRUE;
}

static PurplePluginInfo info =
{
	PURPLE_PLUGIN_MAGIC,
	PURPLE_MAJOR_VERSION,
	PURPLE_MINOR_VERSION,
	PURPLE_PLUGIN_STANDARD,				/**< type           */
	NULL,						/**< ui_requirement */
	0,						/**< flags          */
	NULL,						/**< dependencies   */
	PURPLE_PRIORITY_DEFAULT,			/**< priority       */
	PLUGIN_ID,					/**< id             */
	N_("One Time Password Support"),		/**< name           */
	DISPLAY_VERSION,				/**< version        */
							/**  summary        */
	N_("Enforce that passwords are used only once."),
							/**  description    */
	N_("Allows you to enforce on a per-account basis that passwords not "
	   "being saved are only used in a single successful connection.\n"
	   "Note: The account password must not be saved for this to work."),
	"Daniel Atallah <datallah@pidgin.im>",		/**< author         */
	PURPLE_WEBSITE,					/**< homepage       */
	plugin_load,					/**< load           */
	plugin_unload,					/**< unload         */
	NULL,						/**< destroy        */
	NULL,						/**< ui_info        */
	NULL,						/**< extra_info     */
	NULL,						/**< prefs_info     */
	NULL,						/**< actions        */
	NULL,						/**< reserved 1     */
	NULL,						/**< reserved 2     */
	NULL,						/**< reserved 3     */
	NULL						/**< reserved 4     */
};

static void
init_plugin(PurplePlugin *plugin)
{
}

PURPLE_INIT_PLUGIN(one_time_password, init_plugin, info)
