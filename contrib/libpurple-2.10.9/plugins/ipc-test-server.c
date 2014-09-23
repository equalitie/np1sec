/*
 * IPC test server plugin.
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
#define IPC_TEST_SERVER_PLUGIN_ID "core-ipc-test-server"

#include "internal.h"
#include "debug.h"
#include "plugin.h"
#include "version.h"

static int
add_func(int i1, int i2)
{
	purple_debug_misc("ipc-test-server", "Got %d, %d, returning %d\n",
					i1, i2, i1 + i2);
	return i1 + i2;
}

static int
sub_func(int i1, int i2)
{
	purple_debug_misc("ipc-test-server", "Got %d, %d, returning %d\n",
					i1, i2, i1 - i2);
	return i1 - i2;
}

static gboolean
plugin_load(PurplePlugin *plugin)
{
	purple_plugin_ipc_register(plugin, "add", PURPLE_CALLBACK(add_func),
							 purple_marshal_INT__INT_INT,
							 purple_value_new(PURPLE_TYPE_INT), 2,
							 purple_value_new(PURPLE_TYPE_INT),
							 purple_value_new(PURPLE_TYPE_INT));

	purple_plugin_ipc_register(plugin, "sub", PURPLE_CALLBACK(sub_func),
							 purple_marshal_INT__INT_INT,
							 purple_value_new(PURPLE_TYPE_INT), 2,
							 purple_value_new(PURPLE_TYPE_INT),
							 purple_value_new(PURPLE_TYPE_INT));

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

	IPC_TEST_SERVER_PLUGIN_ID,                        /**< id             */
	N_("IPC Test Server"),                            /**< name           */
	DISPLAY_VERSION,                                  /**< version        */
	                                                  /**  summary        */
	N_("Test plugin IPC support, as a server."),
	                                                  /**  description    */
	N_("Test plugin IPC support, as a server. This registers the IPC "
	   "commands."),
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
}

PURPLE_INIT_PLUGIN(ipctestserver, init_plugin, info)
