/*
 * Mono Plugin Loader
 *
 * -- Thanks to the perl plugin loader for all the great tips ;-)
 *
 * Eoin Coffey
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "internal.h"
#include "debug.h"
#include "plugin.h"
#include "version.h"
#include "mono-helper.h"

#define MONO_PLUGIN_ID "core-mono"

/******************************************************************************
 * Loader Stuff
 *****************************************************************************/
/* probes the given plugin to determine if its a plugin */
static gboolean probe_mono_plugin(PurplePlugin *plugin)
{
	MonoAssembly *assm;
	MonoMethod *m = NULL;
	MonoObject *plugin_info;
	gboolean found_load = FALSE, found_unload = FALSE, found_destroy = FALSE;
	gpointer iter = NULL;

	PurplePluginInfo *info;
	PurpleMonoPlugin *mplug;

	char *file = plugin->path;

	assm = mono_domain_assembly_open(ml_get_domain(), file);

	if (!assm) {
		return FALSE;
	}

	purple_debug(PURPLE_DEBUG_INFO, "mono", "Probing plugin\n");

	if (ml_is_api_dll(mono_assembly_get_image(assm))) {
		purple_debug_info("mono", "Found our PurpleAPI.dll\n");
		mono_assembly_close(assm);
		return FALSE;
	}

	mplug = g_new0(PurpleMonoPlugin, 1);

	mplug->signal_data = NULL;

	mplug->assm = assm;

	mplug->klass = ml_find_plugin_class(mono_assembly_get_image(mplug->assm));
	if (!mplug->klass) {
		purple_debug(PURPLE_DEBUG_ERROR, "mono", "no plugin class in \'%s\'\n", file);
		mono_assembly_close(assm);
		g_free(mplug);
		return FALSE;
	}

	mplug->obj = mono_object_new(ml_get_domain(), mplug->klass);
	if (!mplug->obj) {
		purple_debug(PURPLE_DEBUG_ERROR, "mono", "obj not valid\n");
		mono_assembly_close(assm);
		g_free(mplug);
		return FALSE;
	}

	mono_runtime_object_init(mplug->obj);

	while ((m = mono_class_get_methods(mplug->klass, &iter))) {
		purple_debug_info("mono", "plugin method: %s\n", mono_method_get_name(m));
		if (strcmp(mono_method_get_name(m), "Load") == 0) {
			mplug->load = m;
			found_load = TRUE;
		} else if (strcmp(mono_method_get_name(m), "Unload") == 0) {
			mplug->unload = m;
			found_unload = TRUE;
		} else if (strcmp(mono_method_get_name(m), "Destroy") == 0) {
			mplug->destroy = m;
			found_destroy = TRUE;
		}
	}

	if (!(found_load && found_unload && found_destroy)) {
		purple_debug(PURPLE_DEBUG_ERROR, "mono", "did not find the required methods\n");
		mono_assembly_close(assm);
		g_free(mplug);
		return FALSE;
	}

	plugin_info = ml_get_info_prop(mplug->obj);

	/* now that the methods are filled out we can populate
	   the info struct with all the needed info */

	info = g_new0(PurplePluginInfo, 1);
	info->id = ml_get_prop_string(plugin_info, "Id");
	info->name = ml_get_prop_string(plugin_info, "Name");
	info->version = ml_get_prop_string(plugin_info, "Version");
	info->summary = ml_get_prop_string(plugin_info, "Summary");
	info->description = ml_get_prop_string(plugin_info, "Description");
	info->author = ml_get_prop_string(plugin_info, "Author");
	info->homepage = ml_get_prop_string(plugin_info, "Homepage");

	info->magic = PURPLE_PLUGIN_MAGIC;
	info->major_version = PURPLE_MAJOR_VERSION;
	info->minor_version = PURPLE_MINOR_VERSION;
	info->type = PURPLE_PLUGIN_STANDARD;

	/* this plugin depends on us; duh */
	info->dependencies = g_list_append(info->dependencies, MONO_PLUGIN_ID);
	mplug->plugin = plugin;

	plugin->info = info;
	info->extra_info = mplug;

	ml_add_plugin(mplug);

	return purple_plugin_register(plugin);
}

/* Loads a Mono Plugin by calling 'load' in the class */
static gboolean load_mono_plugin(PurplePlugin *plugin)
{
	PurpleMonoPlugin *mplug;

	purple_debug(PURPLE_DEBUG_INFO, "mono", "Loading plugin\n");

	mplug = (PurpleMonoPlugin*)plugin->info->extra_info;

	ml_invoke(mplug->load, mplug->obj, NULL);

	return TRUE;
}

/* Unloads a Mono Plugin by calling 'unload' in the class */
static gboolean unload_mono_plugin(PurplePlugin *plugin)
{
	PurpleMonoPlugin *mplug;

	purple_debug(PURPLE_DEBUG_INFO, "mono", "Unloading plugin\n");

	mplug = (PurpleMonoPlugin*)plugin->info->extra_info;

	purple_signals_disconnect_by_handle((gpointer)mplug->klass);
	g_list_foreach(mplug->signal_data, (GFunc)g_free, NULL);
	g_list_free(mplug->signal_data);
	mplug->signal_data = NULL;

	ml_invoke(mplug->unload, mplug->obj, NULL);

	return TRUE;
}

static void destroy_mono_plugin(PurplePlugin *plugin)
{
	PurpleMonoPlugin *mplug;

	purple_debug(PURPLE_DEBUG_INFO, "mono", "Destroying plugin\n");

	mplug = (PurpleMonoPlugin*)plugin->info->extra_info;

	ml_invoke(mplug->destroy, mplug->obj, NULL);

	if (plugin->info) {
		g_free(plugin->info->name);
		g_free(plugin->info->version);
		g_free(plugin->info->summary);
		g_free(plugin->info->description);
		g_free(plugin->info->author);
		g_free(plugin->info->homepage);
	}

	if (mplug) {
		if (mplug->assm) {
			mono_assembly_close(mplug->assm);
		}

		g_free(mplug);
		mplug = NULL;
	}
}

/******************************************************************************
 * Plugin Stuff
 *****************************************************************************/
static void plugin_destroy(PurplePlugin *plugin)
{
	ml_uninit();
}

static PurplePluginLoaderInfo loader_info =
{
	NULL,
	probe_mono_plugin,
	load_mono_plugin,
	unload_mono_plugin,
	destroy_mono_plugin,

	/* padding */
	NULL,
	NULL,
	NULL,
	NULL
};

static PurplePluginInfo info =
{
	PURPLE_PLUGIN_MAGIC,
	PURPLE_MAJOR_VERSION,
	PURPLE_MINOR_VERSION,
	PURPLE_PLUGIN_LOADER,
	NULL,
	0,
	NULL,
	PURPLE_PRIORITY_DEFAULT,
	MONO_PLUGIN_ID,
	N_("Mono Plugin Loader"),
	DISPLAY_VERSION,
	N_("Loads .NET plugins with Mono."),
	N_("Loads .NET plugins with Mono."),
	"Eoin Coffey <ecoffey@simla.colostate.edu>",
	PURPLE_WEBSITE,
	NULL,
	NULL,
	plugin_destroy,
	NULL,
	&loader_info,
	NULL,
	NULL,

	/* padding */
	NULL,
	NULL,
	NULL,
	NULL
};

static void init_plugin(PurplePlugin *plugin)
{
	ml_init();

	loader_info.exts = g_list_append(loader_info.exts, "dll");
}

PURPLE_INIT_PLUGIN(mono, init_plugin, info)
