#include "internal.h"
#include "debug.h"
#include "plugin.h"
#include "version.h"

/** Plugin id : type-author-name (to guarantee uniqueness) */
#define SIMPLE_PLUGIN_ID "core-ewarmenhoven-simple"

static gboolean
plugin_load(PurplePlugin *plugin)
{
	purple_debug(PURPLE_DEBUG_INFO, "simple", "simple plugin loaded.\n");

	return TRUE;
}

static gboolean
plugin_unload(PurplePlugin *plugin)
{
	purple_debug(PURPLE_DEBUG_INFO, "simple", "simple plugin unloaded.\n");

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

	SIMPLE_PLUGIN_ID,                                 /**< id             */
	N_("Simple Plugin"),                              /**< name           */
	DISPLAY_VERSION,                                  /**< version        */
	                                                  /**  summary        */
	N_("Tests to see that most things are working."),
	                                                  /**  description    */
	N_("Tests to see that most things are working."),
	"Eric Warmenhoven <eric@warmenhoven.org>",        /**< author         */
	PURPLE_WEBSITE,                                     /**< homepage       */

	plugin_load,                                      /**< load           */
	plugin_unload,                                    /**< unload         */
	NULL,                                             /**< destroy        */

	NULL,                                             /**< ui_info        */
	NULL,                                             /**< extra_info     */
	NULL,
	NULL,
	/* Padding */
	NULL,
	NULL,
	NULL,
	NULL
};

static void
init_plugin(PurplePlugin *plugin)
{
}

PURPLE_INIT_PLUGIN(simple, init_plugin, info)
