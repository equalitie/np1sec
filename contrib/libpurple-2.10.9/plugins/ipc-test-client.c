/*
 * IPC test client plugin.
 *
 * Copyright (C) 2003 Christian Hammond.
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

#define IPC_TEST_CLIENT_PLUGIN_ID "core-ipc-test-client"

static gboolean
plugin_load(PurplePlugin *plugin)
{
	PurplePlugin *server_plugin;
	gboolean ok;
	int result;

	server_plugin = purple_plugins_find_with_id("core-ipc-test-server");

	if (server_plugin == NULL)
	{
		purple_debug_error("ipc-test-client",
						 "Unable to locate plugin core-ipc-test-server, "
						 "needed for IPC.\n");

		return TRUE;
	}

	result = (int)purple_plugin_ipc_call(server_plugin, "add", &ok, 36, 6);

	if (!ok)
	{
		purple_debug_error("ipc-test-client",
						 "Unable to call IPC function 'add' in "
						 "core-ipc-test-server plugin.");

		return TRUE;
	}

	purple_debug_info("ipc-test-client", "36 + 6 = %d\n", result);

	result = (int)purple_plugin_ipc_call(server_plugin, "sub", &ok, 50, 8);

	if (!ok)
	{
		purple_debug_error("ipc-test-client",
						 "Unable to call IPC function 'sub' in "
						 "core-ipc-test-server plugin.");

		return TRUE;
	}

	purple_debug_info("ipc-test-client", "50 - 8 = %d\n", result);

	return TRUE;
}

static PurplePluginInfo info =
{
	PURPLE_PLUGIN_MAGIC,
	PURPLE_MAJOR_VERSION,
	PURPLE_MINOR_VERSION,
	PURPLE_PLUGIN_STANDARD,                             /**< type           */
	NULL,                                             /**< ui_requirement */
	0,                                                /**< flags          */
	NULL,                                             /**< dependencies   */
	PURPLE_PRIORITY_DEFAULT,                            /**< priority       */

	IPC_TEST_CLIENT_PLUGIN_ID,                        /**< id             */
	N_("IPC Test Client"),                            /**< name           */
	DISPLAY_VERSION,                                  /**< version        */
	                                                  /**  summary        */
	N_("Test plugin IPC support, as a client."),
	                                                  /**  description    */
	N_("Test plugin IPC support, as a client. This locates the server "
	   "plugin and calls the commands registered."),
	"Christian Hammond <chipx86@gnupdate.org>",       /**< author         */
	PURPLE_WEBSITE,                                     /**< homepage       */

	plugin_load,                                      /**< load           */
	NULL,                                             /**< unload         */
	NULL,                                             /**< destroy        */

	NULL,                                             /**< ui_info        */
	NULL,                                             /**< extra_info     */
	NULL,
	NULL
};

static void
init_plugin(PurplePlugin *plugin)
{
	info.dependencies = g_list_append(info.dependencies,
									  "core-ipc-test-server");
}

PURPLE_INIT_PLUGIN(ipctestclient, init_plugin, info)
