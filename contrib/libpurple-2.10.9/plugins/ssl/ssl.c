/**
 * @file ssl.c Main SSL plugin
 *
 * purple
 *
 * Copyright (C) 2003 Christian Hammond <chipx86@gnupdate.org>
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
#include "debug.h"
#include "plugin.h"
#include "sslconn.h"
#include "version.h"

#define SSL_PLUGIN_ID "core-ssl"

static PurplePlugin *ssl_plugin = NULL;

static gboolean
probe_ssl_plugins(PurplePlugin *my_plugin)
{
	PurplePlugin *plugin;
	GList *l;

	ssl_plugin = NULL;

	for (l = purple_plugins_get_all(); l != NULL; l = l->next)
	{
		plugin = (PurplePlugin *)l->data;

		if (plugin == my_plugin)
			continue;

		if (plugin->info != NULL && plugin->info->id != NULL &&
			strncmp(plugin->info->id, "ssl-", 4) == 0)
		{
			if (purple_plugin_is_loaded(plugin) || purple_plugin_load(plugin))
			{
				ssl_plugin = plugin;

				break;
			}
		}
	}

	return (ssl_plugin != NULL);
}

static gboolean
plugin_load(PurplePlugin *plugin)
{
	return probe_ssl_plugins(plugin);
}

static gboolean
plugin_unload(PurplePlugin *plugin)
{
	if (ssl_plugin != NULL &&
		g_list_find(purple_plugins_get_loaded(), ssl_plugin) != NULL)
	{
		purple_plugin_unload(ssl_plugin);
	}

	ssl_plugin = NULL;

	return TRUE;
}

static PurplePluginInfo info =
{
	PURPLE_PLUGIN_MAGIC,
	PURPLE_MAJOR_VERSION,
	PURPLE_MINOR_VERSION,
	PURPLE_PLUGIN_STANDARD,                             /**< type           */
    NULL,                                             /**< ui_requirement */
	PURPLE_PLUGIN_FLAG_INVISIBLE,                       /**< flags          */
	NULL,                                             /**< dependencies   */
	PURPLE_PRIORITY_DEFAULT,                            /**< priority       */

	SSL_PLUGIN_ID,                                    /**< id             */
	N_("SSL"),                                        /**< name           */
	DISPLAY_VERSION,                                  /**< version        */
	                                                  /**  summary        */
	N_("Provides a wrapper around SSL support libraries."),
	                                                  /**  description    */
	N_("Provides a wrapper around SSL support libraries."),
	"Christian Hammond <chipx86@gnupdate.org>",
	PURPLE_WEBSITE,                                     /**< homepage       */

	plugin_load,                                      /**< load           */
	plugin_unload,                                    /**< unload         */
	NULL,                                             /**< destroy        */

	NULL,                                             /**< ui_info        */
	NULL,                                             /**< extra_info     */
	NULL,
	NULL,

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

PURPLE_INIT_PLUGIN(ssl, init_plugin, info)
