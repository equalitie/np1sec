/*
 * purple
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
#define _PURPLE_PLUGIN_C_

#include "internal.h"

#include "accountopt.h"
#include "core.h"
#include "dbus-maybe.h"
#include "debug.h"
#include "notify.h"
#include "prefs.h"
#include "prpl.h"
#include "request.h"
#include "signals.h"
#include "util.h"
#include "valgrind.h"
#include "version.h"

typedef struct
{
	GHashTable *commands;
	size_t command_count;

} PurplePluginIpcInfo;

typedef struct
{
	PurpleCallback func;
	PurpleSignalMarshalFunc marshal;

	int num_params;
	PurpleValue **params;
	PurpleValue *ret_value;

} PurplePluginIpcCommand;

static GList *search_paths     = NULL;
static GList *plugins          = NULL;
static GList *loaded_plugins   = NULL;
static GList *protocol_plugins = NULL;
#ifdef PURPLE_PLUGINS
static GList *load_queue       = NULL;
static GList *plugin_loaders   = NULL;
static GList *plugins_to_disable = NULL;
#endif

static void (*probe_cb)(void *) = NULL;
static void *probe_cb_data = NULL;
static void (*load_cb)(PurplePlugin *, void *) = NULL;
static void *load_cb_data = NULL;
static void (*unload_cb)(PurplePlugin *, void *) = NULL;
static void *unload_cb_data = NULL;

#ifdef PURPLE_PLUGINS

static gboolean
has_file_extension(const char *filename, const char *ext)
{
	int len, extlen;

	if (filename == NULL || *filename == '\0' || ext == NULL)
		return 0;

	extlen = strlen(ext);
	len = strlen(filename) - extlen;

	if (len < 0)
		return 0;

	return (strncmp(filename + len, ext, extlen) == 0);
}

static gboolean
is_native(const char *filename)
{
	const char *last_period;

	last_period = strrchr(filename, '.');
	if (last_period == NULL)
		return FALSE;

	return !(strcmp(last_period, ".dll") &
			 strcmp(last_period, ".sl") &
			 strcmp(last_period, ".so"));
}

static char *
purple_plugin_get_basename(const char *filename)
{
	const char *basename;
	const char *last_period;

	basename = strrchr(filename, G_DIR_SEPARATOR);
	if (basename != NULL)
		basename++;
	else
		basename = filename;

	if (is_native(basename) &&
		((last_period = strrchr(basename, '.')) != NULL))
			return g_strndup(basename, (last_period - basename));

	return g_strdup(basename);
}

static gboolean
loader_supports_file(PurplePlugin *loader, const char *filename)
{
	GList *exts;

	for (exts = PURPLE_PLUGIN_LOADER_INFO(loader)->exts; exts != NULL; exts = exts->next) {
		if (has_file_extension(filename, (char *)exts->data)) {
			return TRUE;
		}
	}

	return FALSE;
}

static PurplePlugin *
find_loader_for_plugin(const PurplePlugin *plugin)
{
	PurplePlugin *loader;
	GList *l;

	if (plugin->path == NULL)
		return NULL;

	for (l = purple_plugins_get_loaded(); l != NULL; l = l->next) {
		loader = l->data;

		if (loader->info->type == PURPLE_PLUGIN_LOADER &&
			loader_supports_file(loader, plugin->path)) {

			return loader;
		}

		loader = NULL;
	}

	return NULL;
}

#endif /* PURPLE_PLUGINS */

/**
 * Negative if a before b, 0 if equal, positive if a after b.
 */
static gint
compare_prpl(PurplePlugin *a, PurplePlugin *b)
{
	if(PURPLE_IS_PROTOCOL_PLUGIN(a)) {
		if(PURPLE_IS_PROTOCOL_PLUGIN(b))
			return strcmp(a->info->name, b->info->name);
		else
			return -1;
	} else {
		if(PURPLE_IS_PROTOCOL_PLUGIN(b))
			return 1;
		else
			return 0;
	}
}

PurplePlugin *
purple_plugin_new(gboolean native, const char *path)
{
	PurplePlugin *plugin;

	plugin = g_new0(PurplePlugin, 1);

	plugin->native_plugin = native;
	plugin->path = g_strdup(path);

	PURPLE_DBUS_REGISTER_POINTER(plugin, PurplePlugin);

	return plugin;
}

PurplePlugin *
purple_plugin_probe(const char *filename)
{
#ifdef PURPLE_PLUGINS
	PurplePlugin *plugin = NULL;
	PurplePlugin *loader;
	gpointer unpunned;
	gchar *basename = NULL;
	gboolean (*purple_init_plugin)(PurplePlugin *);

	purple_debug_misc("plugins", "probing %s\n", filename);
	g_return_val_if_fail(filename != NULL, NULL);

	if (!g_file_test(filename, G_FILE_TEST_EXISTS))
		return NULL;

	/* If this plugin has already been probed then exit */
	basename = purple_plugin_get_basename(filename);
	plugin = purple_plugins_find_with_basename(basename);
	g_free(basename);
	if (plugin != NULL)
	{
		if (purple_strequal(filename, plugin->path))
			return plugin;
		else if (!purple_plugin_is_unloadable(plugin))
		{
			purple_debug_warning("plugins", "Not loading %s. "
							"Another plugin with the same name (%s) has already been loaded.\n",
							filename, plugin->path);
			return plugin;
		}
		else
		{
			/* The old plugin was a different file and it was unloadable.
			 * There's no guarantee that this new file with the same name
			 * will be loadable, but unless it fails in one of the silent
			 * ways and the first one didn't, it's not any worse.  The user
			 * will still see a greyed-out plugin, which is what we want. */
			purple_plugin_destroy(plugin);
		}
	}

	plugin = purple_plugin_new(has_file_extension(filename, G_MODULE_SUFFIX), filename);

	if (plugin->native_plugin) {
		const char *error;
#ifdef _WIN32
		/* Suppress error popups for failing to load plugins */
		UINT old_error_mode = SetErrorMode(SEM_FAILCRITICALERRORS);
#endif

		/*
		 * We pass G_MODULE_BIND_LOCAL here to prevent symbols from
		 * plugins being added to the global name space.
		 *
		 * G_MODULE_BIND_LOCAL was added in glib 2.3.3.
		 */
		plugin->handle = g_module_open(filename, G_MODULE_BIND_LOCAL);

		if (plugin->handle == NULL)
		{
			const char *error = g_module_error();
			if (error != NULL && purple_str_has_prefix(error, filename))
			{
				error = error + strlen(filename);

				/* These are just so we don't crash.  If we
				 * got this far, they should always be true. */
				if (*error == ':')
					error++;
				if (*error == ' ')
					error++;
			}

			if (error == NULL || !*error)
			{
				plugin->error = g_strdup(_("Unknown error"));
				purple_debug_error("plugins", "%s is not loadable: Unknown error\n",
						 plugin->path);
			}
			else
			{
				plugin->error = g_strdup(error);
				purple_debug_error("plugins", "%s is not loadable: %s\n",
						 plugin->path, plugin->error);
			}
			plugin->handle = g_module_open(filename, G_MODULE_BIND_LAZY | G_MODULE_BIND_LOCAL);

			if (plugin->handle == NULL)
			{
#ifdef _WIN32
				/* Restore the original error mode */
				SetErrorMode(old_error_mode);
#endif
				purple_plugin_destroy(plugin);
				return NULL;
			}
			else
			{
				/* We were able to load the plugin with lazy symbol binding.
				 * This means we're missing some symbol.  Mark it as
				 * unloadable and keep going so we get the info to display
				 * to the user so they know to rebuild this plugin. */
				plugin->unloadable = TRUE;
			}
		}

		if (!g_module_symbol(plugin->handle, "purple_init_plugin",
							 &unpunned))
		{
			purple_debug_error("plugins", "%s is not usable because the "
							 "'purple_init_plugin' symbol could not be "
							 "found.  Does the plugin call the "
							 "PURPLE_INIT_PLUGIN() macro?\n", plugin->path);

			g_module_close(plugin->handle);
			error = g_module_error();
			if (error != NULL)
				purple_debug_error("plugins", "Error closing module %s: %s\n",
								 plugin->path, error);
			plugin->handle = NULL;

#ifdef _WIN32
			/* Restore the original error mode */
			SetErrorMode(old_error_mode);
#endif
			purple_plugin_destroy(plugin);
			return NULL;
		}
		purple_init_plugin = unpunned;

#ifdef _WIN32
		/* Restore the original error mode */
		SetErrorMode(old_error_mode);
#endif
	}
	else {
		loader = find_loader_for_plugin(plugin);

		if (loader == NULL) {
			purple_plugin_destroy(plugin);
			return NULL;
		}

		purple_init_plugin = PURPLE_PLUGIN_LOADER_INFO(loader)->probe;
	}

	if (!purple_init_plugin(plugin) || plugin->info == NULL)
	{
		purple_plugin_destroy(plugin);
		return NULL;
	}
	else if (plugin->info->ui_requirement &&
			!purple_strequal(plugin->info->ui_requirement, purple_core_get_ui()))
	{
		plugin->error = g_strdup_printf(_("You are using %s, but this plugin requires %s."),
					purple_core_get_ui(), plugin->info->ui_requirement);
		purple_debug_error("plugins", "%s is not loadable: The UI requirement is not met. (%s)\n", plugin->path, plugin->error);
		plugin->unloadable = TRUE;
		return plugin;
	}

	/*
	 * Check to make sure a plugin has defined an id.
	 * Not having this check caused purple_plugin_unload to
	 * enter an infinite loop in certain situations by passing
	 * purple_find_plugin_by_id a NULL value. -- ecoffey
	 */
	if (plugin->info->id == NULL || *plugin->info->id == '\0')
	{
		plugin->error = g_strdup(_("This plugin has not defined an ID."));
		purple_debug_error("plugins", "%s is not loadable: info->id is not defined.\n", plugin->path);
		plugin->unloadable = TRUE;
		return plugin;
	}

	/* Really old plugins. */
	if (plugin->info->magic != PURPLE_PLUGIN_MAGIC)
	{
		if (plugin->info->magic >= 2 && plugin->info->magic <= 4)
		{
			struct _PurplePluginInfo2
			{
				unsigned int api_version;
				PurplePluginType type;
				char *ui_requirement;
				unsigned long flags;
				GList *dependencies;
				PurplePluginPriority priority;

				char *id;
				char *name;
				char *version;
				char *summary;
				char *description;
				char *author;
				char *homepage;

				gboolean (*load)(PurplePlugin *plugin);
				gboolean (*unload)(PurplePlugin *plugin);
				void (*destroy)(PurplePlugin *plugin);

				void *ui_info;
				void *extra_info;
				PurplePluginUiInfo *prefs_info;
				GList *(*actions)(PurplePlugin *plugin, gpointer context);
			} *info2 = (struct _PurplePluginInfo2 *)plugin->info;

			/* This leaks... but only for ancient plugins, so deal with it. */
			plugin->info = g_new0(PurplePluginInfo, 1);

			/* We don't really need all these to display the plugin info, but
			 * I'm copying them all for good measure. */
			plugin->info->magic          = info2->api_version;
			plugin->info->type           = info2->type;
			plugin->info->ui_requirement = info2->ui_requirement;
			plugin->info->flags          = info2->flags;
			plugin->info->dependencies   = info2->dependencies;
			plugin->info->id             = info2->id;
			plugin->info->name           = info2->name;
			plugin->info->version        = info2->version;
			plugin->info->summary        = info2->summary;
			plugin->info->description    = info2->description;
			plugin->info->author         = info2->author;
			plugin->info->homepage       = info2->homepage;
			plugin->info->load           = info2->load;
			plugin->info->unload         = info2->unload;
			plugin->info->destroy        = info2->destroy;
			plugin->info->ui_info        = info2->ui_info;
			plugin->info->extra_info     = info2->extra_info;

			if (info2->api_version >= 3)
				plugin->info->prefs_info = info2->prefs_info;

			if (info2->api_version >= 4)
				plugin->info->actions    = info2->actions;


			plugin->error = g_strdup_printf(_("Plugin magic mismatch %d (need %d)"),
							 plugin->info->magic, PURPLE_PLUGIN_MAGIC);
			purple_debug_error("plugins", "%s is not loadable: Plugin magic mismatch %d (need %d)\n",
					  plugin->path, plugin->info->magic, PURPLE_PLUGIN_MAGIC);
			plugin->unloadable = TRUE;
			return plugin;
		}

		purple_debug_error("plugins", "%s is not loadable: Plugin magic mismatch %d (need %d)\n",
				 plugin->path, plugin->info->magic, PURPLE_PLUGIN_MAGIC);
		purple_plugin_destroy(plugin);
		return NULL;
	}

	if (plugin->info->major_version != PURPLE_MAJOR_VERSION ||
			plugin->info->minor_version > PURPLE_MINOR_VERSION)
	{
		plugin->error = g_strdup_printf(_("ABI version mismatch %d.%d.x (need %d.%d.x)"),
						 plugin->info->major_version, plugin->info->minor_version,
						 PURPLE_MAJOR_VERSION, PURPLE_MINOR_VERSION);
		purple_debug_error("plugins", "%s is not loadable: ABI version mismatch %d.%d.x (need %d.%d.x)\n",
				 plugin->path, plugin->info->major_version, plugin->info->minor_version,
				 PURPLE_MAJOR_VERSION, PURPLE_MINOR_VERSION);
		plugin->unloadable = TRUE;
		return plugin;
	}

	if (plugin->info->type == PURPLE_PLUGIN_PROTOCOL)
	{
		/* If plugin is a PRPL, make sure it implements the required functions */
		if ((PURPLE_PLUGIN_PROTOCOL_INFO(plugin)->list_icon == NULL) ||
		    (PURPLE_PLUGIN_PROTOCOL_INFO(plugin)->login == NULL) ||
		    (PURPLE_PLUGIN_PROTOCOL_INFO(plugin)->close == NULL))
		{
			plugin->error = g_strdup(_("Plugin does not implement all required functions (list_icon, login and close)"));
			purple_debug_error("plugins", "%s is not loadable: %s\n",
					 plugin->path, plugin->error);
			plugin->unloadable = TRUE;
			return plugin;
		}

		/* For debugging, let's warn about prpl prefs. */
		if (plugin->info->prefs_info != NULL)
		{
			purple_debug_error("plugins", "%s has a prefs_info, but is a prpl. This is no longer supported.\n",
			                 plugin->path);
		}
	}

	return plugin;
#else
	return NULL;
#endif /* !PURPLE_PLUGINS */
}

#ifdef PURPLE_PLUGINS
static gint
compare_plugins(gconstpointer a, gconstpointer b)
{
	const PurplePlugin *plugina = a;
	const PurplePlugin *pluginb = b;

	return strcmp(plugina->info->name, pluginb->info->name);
}
#endif /* PURPLE_PLUGINS */

gboolean
purple_plugin_load(PurplePlugin *plugin)
{
#ifdef PURPLE_PLUGINS
	GList *dep_list = NULL;
	GList *l;

	g_return_val_if_fail(plugin != NULL, FALSE);

	if (purple_plugin_is_loaded(plugin))
		return TRUE;

	if (purple_plugin_is_unloadable(plugin))
		return FALSE;

	g_return_val_if_fail(plugin->error == NULL, FALSE);

	/*
	 * Go through the list of the plugin's dependencies.
	 *
	 * First pass: Make sure all the plugins needed are probed.
	 */
	for (l = plugin->info->dependencies; l != NULL; l = l->next)
	{
		const char *dep_name = (const char *)l->data;
		PurplePlugin *dep_plugin;

		dep_plugin = purple_plugins_find_with_id(dep_name);

		if (dep_plugin == NULL)
		{
			char *tmp;

			tmp = g_strdup_printf(_("The required plugin %s was not found. "
			                        "Please install this plugin and try again."),
			                      dep_name);

			purple_notify_error(NULL, NULL,
			                  _("Unable to load the plugin"), tmp);
			g_free(tmp);

			g_list_free(dep_list);

			return FALSE;
		}

		dep_list = g_list_append(dep_list, dep_plugin);
	}

	/* Second pass: load all the required plugins. */
	for (l = dep_list; l != NULL; l = l->next)
	{
		PurplePlugin *dep_plugin = (PurplePlugin *)l->data;

		if (!purple_plugin_is_loaded(dep_plugin))
		{
			if (!purple_plugin_load(dep_plugin))
			{
				char *tmp;

				tmp = g_strdup_printf(_("The required plugin %s was unable to load."),
				                      plugin->info->name);

				purple_notify_error(NULL, NULL,
				                 _("Unable to load your plugin."), tmp);
				g_free(tmp);

				g_list_free(dep_list);

				return FALSE;
			}
		}
	}

	/* Third pass: note that other plugins are dependencies of this plugin.
	 * This is done separately in case we had to bail out earlier. */
	for (l = dep_list; l != NULL; l = l->next)
	{
		PurplePlugin *dep_plugin = (PurplePlugin *)l->data;
		dep_plugin->dependent_plugins = g_list_prepend(dep_plugin->dependent_plugins, plugin->info->id);
	}

	g_list_free(dep_list);

	if (plugin->native_plugin)
	{
		if (plugin->info->load != NULL && !plugin->info->load(plugin))
			return FALSE;
	}
	else {
		PurplePlugin *loader;
		PurplePluginLoaderInfo *loader_info;

		loader = find_loader_for_plugin(plugin);

		if (loader == NULL)
			return FALSE;

		loader_info = PURPLE_PLUGIN_LOADER_INFO(loader);

		if (loader_info->load != NULL)
		{
			if (!loader_info->load(plugin))
				return FALSE;
		}
	}

	loaded_plugins = g_list_insert_sorted(loaded_plugins, plugin, compare_plugins);

	plugin->loaded = TRUE;

	if (load_cb != NULL)
		load_cb(plugin, load_cb_data);

	purple_signal_emit(purple_plugins_get_handle(), "plugin-load", plugin);

	return TRUE;

#else
	return TRUE;
#endif /* !PURPLE_PLUGINS */
}

gboolean
purple_plugin_unload(PurplePlugin *plugin)
{
#ifdef PURPLE_PLUGINS
	GList *l;
	GList *ll;

	g_return_val_if_fail(plugin != NULL, FALSE);
	g_return_val_if_fail(purple_plugin_is_loaded(plugin), FALSE);

	purple_debug_info("plugins", "Unloading plugin %s\n", plugin->info->name);

	/* Unload all plugins that depend on this plugin. */
	for (l = plugin->dependent_plugins; l != NULL; l = ll) {
		const char * dep_name = (const char *)l->data;
		PurplePlugin *dep_plugin;

		/* Store a pointer to the next element in the list.
		 * This is because we'll be modifying this list in the loop. */
		ll = l->next;

		dep_plugin = purple_plugins_find_with_id(dep_name);

		if (dep_plugin != NULL && purple_plugin_is_loaded(dep_plugin))
		{
			if (!purple_plugin_unload(dep_plugin))
			{
				g_free(plugin->error);
				plugin->error = g_strdup_printf(_("%s requires %s, but it failed to unload."),
				                                _(plugin->info->name),
				                                _(dep_plugin->info->name));
				return FALSE;
			}
			else
			{
#if 0
				/* This isn't necessary. This has already been done when unloading dep_plugin. */
				plugin->dependent_plugins = g_list_delete_link(plugin->dependent_plugins, l);
#endif
			}
		}
	}

	/* Remove this plugin from each dependency's dependent_plugins list. */
	for (l = plugin->info->dependencies; l != NULL; l = l->next)
	{
		const char *dep_name = (const char *)l->data;
		PurplePlugin *dependency;

		dependency = purple_plugins_find_with_id(dep_name);

		if (dependency != NULL)
			dependency->dependent_plugins = g_list_remove(dependency->dependent_plugins, plugin->info->id);
		else
			purple_debug_error("plugins", "Unable to remove from dependency list for %s\n", dep_name);
	}

	if (plugin->native_plugin) {
		if (plugin->info->unload && !plugin->info->unload(plugin))
			return FALSE;

		if (plugin->info->type == PURPLE_PLUGIN_PROTOCOL) {
			PurplePluginProtocolInfo *prpl_info;
			GList *l;

			prpl_info = PURPLE_PLUGIN_PROTOCOL_INFO(plugin);

			for (l = prpl_info->user_splits; l != NULL; l = l->next)
				purple_account_user_split_destroy(l->data);

			for (l = prpl_info->protocol_options; l != NULL; l = l->next)
				purple_account_option_destroy(l->data);

			if (prpl_info->user_splits != NULL) {
				g_list_free(prpl_info->user_splits);
				prpl_info->user_splits = NULL;
			}

			if (prpl_info->protocol_options != NULL) {
				g_list_free(prpl_info->protocol_options);
				prpl_info->protocol_options = NULL;
			}
		}
	} else {
		PurplePlugin *loader;
		PurplePluginLoaderInfo *loader_info;

		loader = find_loader_for_plugin(plugin);

		if (loader == NULL)
			return FALSE;

		loader_info = PURPLE_PLUGIN_LOADER_INFO(loader);

		if (loader_info->unload && !loader_info->unload(plugin))
			return FALSE;
	}

	/* cancel any pending dialogs the plugin has */
	purple_request_close_with_handle(plugin);
	purple_notify_close_with_handle(plugin);

	purple_signals_disconnect_by_handle(plugin);
	purple_plugin_ipc_unregister_all(plugin);

	loaded_plugins = g_list_remove(loaded_plugins, plugin);
	if ((plugin->info != NULL) && PURPLE_IS_PROTOCOL_PLUGIN(plugin))
		protocol_plugins = g_list_remove(protocol_plugins, plugin);
	plugins_to_disable = g_list_remove(plugins_to_disable, plugin);
	plugin->loaded = FALSE;

	/* We wouldn't be anywhere near here if the plugin wasn't loaded, so
	 * if plugin->error is set at all, it had to be from a previous
	 * unload failure.  It's obviously okay now.
	 */
	g_free(plugin->error);
	plugin->error = NULL;

	if (unload_cb != NULL)
		unload_cb(plugin, unload_cb_data);

	purple_signal_emit(purple_plugins_get_handle(), "plugin-unload", plugin);

	purple_prefs_disconnect_by_handle(plugin);

	return TRUE;
#else
	return TRUE;
#endif /* PURPLE_PLUGINS */
}

void
purple_plugin_disable(PurplePlugin *plugin)
{
#ifdef PURPLE_PLUGINS
	g_return_if_fail(plugin != NULL);

	if (!g_list_find(plugins_to_disable, plugin))
		plugins_to_disable = g_list_prepend(plugins_to_disable, plugin);
#endif
}

gboolean
purple_plugin_reload(PurplePlugin *plugin)
{
#ifdef PURPLE_PLUGINS
	g_return_val_if_fail(plugin != NULL, FALSE);
	g_return_val_if_fail(purple_plugin_is_loaded(plugin), FALSE);

	if (!purple_plugin_unload(plugin))
		return FALSE;

	if (!purple_plugin_load(plugin))
		return FALSE;

	return TRUE;
#else
	return TRUE;
#endif /* !PURPLE_PLUGINS */
}

void
purple_plugin_destroy(PurplePlugin *plugin)
{
#ifdef PURPLE_PLUGINS
	g_return_if_fail(plugin != NULL);

	if (purple_plugin_is_loaded(plugin))
		purple_plugin_unload(plugin);

	plugins = g_list_remove(plugins, plugin);

	if (load_queue != NULL)
		load_queue = g_list_remove(load_queue, plugin);

	/* true, this may leak a little memory if there is a major version
	 * mismatch, but it's a lot better than trying to free something
	 * we shouldn't, and crashing while trying to load an old plugin */
	if(plugin->info == NULL || plugin->info->magic != PURPLE_PLUGIN_MAGIC ||
			plugin->info->major_version != PURPLE_MAJOR_VERSION)
	{
		if(plugin->handle)
			g_module_close(plugin->handle);

		g_free(plugin->path);
		g_free(plugin->error);

		PURPLE_DBUS_UNREGISTER_POINTER(plugin);

		g_free(plugin);
		return;
	}

	if (plugin->info != NULL)
		g_list_free(plugin->info->dependencies);

	if (plugin->native_plugin)
	{
		if (plugin->info != NULL && plugin->info->type == PURPLE_PLUGIN_LOADER)
		{
			PurplePluginLoaderInfo *loader_info;
			GList *exts, *l, *next_l;
			PurplePlugin *p2;

			loader_info = PURPLE_PLUGIN_LOADER_INFO(plugin);

			if (loader_info != NULL && loader_info->exts != NULL)
			{
				for (exts = PURPLE_PLUGIN_LOADER_INFO(plugin)->exts;
					 exts != NULL;
					 exts = exts->next) {

					for (l = purple_plugins_get_all(); l != NULL; l = next_l)
					{
						next_l = l->next;

						p2 = l->data;

						if (p2->path != NULL &&
							has_file_extension(p2->path, exts->data))
						{
							purple_plugin_destroy(p2);
						}
					}
				}

				g_list_free(loader_info->exts);
				loader_info->exts = NULL;
			}

			plugin_loaders = g_list_remove(plugin_loaders, plugin);
		}

		if (plugin->info != NULL && plugin->info->destroy != NULL)
			plugin->info->destroy(plugin);

		/*
		 * I find it extremely useful to do this when using valgrind, as
		 * it keeps all the plugins open, meaning that valgrind is able to
		 * resolve symbol names in leak traces from plugins.
		 */
		if (!g_getenv("PURPLE_LEAKCHECK_HELP") && !RUNNING_ON_VALGRIND)
		{
			if (plugin->handle != NULL)
				g_module_close(plugin->handle);
		}
	}
	else
	{
		PurplePlugin *loader;
		PurplePluginLoaderInfo *loader_info;

		loader = find_loader_for_plugin(plugin);

		if (loader != NULL)
		{
			loader_info = PURPLE_PLUGIN_LOADER_INFO(loader);

			if (loader_info->destroy != NULL)
				loader_info->destroy(plugin);
		}
	}

	g_free(plugin->path);
	g_free(plugin->error);

	PURPLE_DBUS_UNREGISTER_POINTER(plugin);

	g_free(plugin);
#endif /* !PURPLE_PLUGINS */
}

gboolean
purple_plugin_is_loaded(const PurplePlugin *plugin)
{
	g_return_val_if_fail(plugin != NULL, FALSE);

	return plugin->loaded;
}

gboolean
purple_plugin_is_unloadable(const PurplePlugin *plugin)
{
	g_return_val_if_fail(plugin != NULL, FALSE);

	return plugin->unloadable;
}

const gchar *
purple_plugin_get_id(const PurplePlugin *plugin) {
	g_return_val_if_fail(plugin, NULL);
	g_return_val_if_fail(plugin->info, NULL);

	return plugin->info->id;
}

const gchar *
purple_plugin_get_name(const PurplePlugin *plugin) {
	g_return_val_if_fail(plugin, NULL);
	g_return_val_if_fail(plugin->info, NULL);

	return _(plugin->info->name);
}

const gchar *
purple_plugin_get_version(const PurplePlugin *plugin) {
	g_return_val_if_fail(plugin, NULL);
	g_return_val_if_fail(plugin->info, NULL);

	return plugin->info->version;
}

const gchar *
purple_plugin_get_summary(const PurplePlugin *plugin) {
	g_return_val_if_fail(plugin, NULL);
	g_return_val_if_fail(plugin->info, NULL);

	return _(plugin->info->summary);
}

const gchar *
purple_plugin_get_description(const PurplePlugin *plugin) {
	g_return_val_if_fail(plugin, NULL);
	g_return_val_if_fail(plugin->info, NULL);

	return _(plugin->info->description);
}

const gchar *
purple_plugin_get_author(const PurplePlugin *plugin) {
	g_return_val_if_fail(plugin, NULL);
	g_return_val_if_fail(plugin->info, NULL);

	return _(plugin->info->author);
}

const gchar *
purple_plugin_get_homepage(const PurplePlugin *plugin) {
	g_return_val_if_fail(plugin, NULL);
	g_return_val_if_fail(plugin->info, NULL);

	return plugin->info->homepage;
}

/**************************************************************************
 * Plugin IPC
 **************************************************************************/
static void
destroy_ipc_info(void *data)
{
	PurplePluginIpcCommand *ipc_command = (PurplePluginIpcCommand *)data;
	int i;

	if (ipc_command->params != NULL)
	{
		for (i = 0; i < ipc_command->num_params; i++)
			purple_value_destroy(ipc_command->params[i]);

		g_free(ipc_command->params);
	}

	if (ipc_command->ret_value != NULL)
		purple_value_destroy(ipc_command->ret_value);

	g_free(ipc_command);
}

gboolean
purple_plugin_ipc_register(PurplePlugin *plugin, const char *command,
						 PurpleCallback func, PurpleSignalMarshalFunc marshal,
						 PurpleValue *ret_value, int num_params, ...)
{
	PurplePluginIpcInfo *ipc_info;
	PurplePluginIpcCommand *ipc_command;

	g_return_val_if_fail(plugin  != NULL, FALSE);
	g_return_val_if_fail(command != NULL, FALSE);
	g_return_val_if_fail(func    != NULL, FALSE);
	g_return_val_if_fail(marshal != NULL, FALSE);

	if (plugin->ipc_data == NULL)
	{
		ipc_info = plugin->ipc_data = g_new0(PurplePluginIpcInfo, 1);
		ipc_info->commands = g_hash_table_new_full(g_str_hash, g_str_equal,
												   g_free, destroy_ipc_info);
	}
	else
		ipc_info = (PurplePluginIpcInfo *)plugin->ipc_data;

	ipc_command = g_new0(PurplePluginIpcCommand, 1);
	ipc_command->func       = func;
	ipc_command->marshal    = marshal;
	ipc_command->num_params = num_params;
	ipc_command->ret_value  = ret_value;

	if (num_params > 0)
	{
		va_list args;
		int i;

		ipc_command->params = g_new0(PurpleValue *, num_params);

		va_start(args, num_params);

		for (i = 0; i < num_params; i++)
			ipc_command->params[i] = va_arg(args, PurpleValue *);

		va_end(args);
	}

	g_hash_table_replace(ipc_info->commands, g_strdup(command), ipc_command);

	ipc_info->command_count++;

	return TRUE;
}

void
purple_plugin_ipc_unregister(PurplePlugin *plugin, const char *command)
{
	PurplePluginIpcInfo *ipc_info;

	g_return_if_fail(plugin  != NULL);
	g_return_if_fail(command != NULL);

	ipc_info = (PurplePluginIpcInfo *)plugin->ipc_data;

	if (ipc_info == NULL ||
		g_hash_table_lookup(ipc_info->commands, command) == NULL)
	{
		purple_debug_error("plugins",
						 "IPC command '%s' was not registered for plugin %s\n",
						 command, plugin->info->name);
		return;
	}

	g_hash_table_remove(ipc_info->commands, command);

	ipc_info->command_count--;

	if (ipc_info->command_count == 0)
	{
		g_hash_table_destroy(ipc_info->commands);
		g_free(ipc_info);

		plugin->ipc_data = NULL;
	}
}

void
purple_plugin_ipc_unregister_all(PurplePlugin *plugin)
{
	PurplePluginIpcInfo *ipc_info;

	g_return_if_fail(plugin != NULL);

	if (plugin->ipc_data == NULL)
		return; /* Silently ignore it. */

	ipc_info = (PurplePluginIpcInfo *)plugin->ipc_data;

	g_hash_table_destroy(ipc_info->commands);
	g_free(ipc_info);

	plugin->ipc_data = NULL;
}

gboolean
purple_plugin_ipc_get_params(PurplePlugin *plugin, const char *command,
						   PurpleValue **ret_value, int *num_params,
						   PurpleValue ***params)
{
	PurplePluginIpcInfo *ipc_info;
	PurplePluginIpcCommand *ipc_command;

	g_return_val_if_fail(plugin  != NULL, FALSE);
	g_return_val_if_fail(command != NULL, FALSE);

	ipc_info = (PurplePluginIpcInfo *)plugin->ipc_data;

	if (ipc_info == NULL ||
		(ipc_command = g_hash_table_lookup(ipc_info->commands,
										   command)) == NULL)
	{
		purple_debug_error("plugins",
						 "IPC command '%s' was not registered for plugin %s\n",
						 command, plugin->info->name);

		return FALSE;
	}

	if (num_params != NULL)
		*num_params = ipc_command->num_params;

	if (params != NULL)
		*params = ipc_command->params;

	if (ret_value != NULL)
		*ret_value = ipc_command->ret_value;

	return TRUE;
}

void *
purple_plugin_ipc_call(PurplePlugin *plugin, const char *command,
					 gboolean *ok, ...)
{
	PurplePluginIpcInfo *ipc_info;
	PurplePluginIpcCommand *ipc_command;
	va_list args;
	void *ret_value;

	if (ok != NULL)
		*ok = FALSE;

	g_return_val_if_fail(plugin  != NULL, NULL);
	g_return_val_if_fail(command != NULL, NULL);

	ipc_info = (PurplePluginIpcInfo *)plugin->ipc_data;

	if (ipc_info == NULL ||
		(ipc_command = g_hash_table_lookup(ipc_info->commands,
										   command)) == NULL)
	{
		purple_debug_error("plugins",
						 "IPC command '%s' was not registered for plugin %s\n",
						 command, plugin->info->name);

		return NULL;
	}

	va_start(args, ok);
	ipc_command->marshal(ipc_command->func, args, NULL, &ret_value);
	va_end(args);

	if (ok != NULL)
		*ok = TRUE;

	return ret_value;
}

/**************************************************************************
 * Plugins subsystem
 **************************************************************************/
void *
purple_plugins_get_handle(void) {
	static int handle;

	return &handle;
}

void
purple_plugins_init(void) {
	void *handle = purple_plugins_get_handle();

	purple_plugins_add_search_path(LIBDIR);

	purple_signal_register(handle, "plugin-load",
						 purple_marshal_VOID__POINTER,
						 NULL, 1,
						 purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_PLUGIN));
	purple_signal_register(handle, "plugin-unload",
						 purple_marshal_VOID__POINTER,
						 NULL, 1,
						 purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_PLUGIN));
}

void
purple_plugins_uninit(void)
{
	void *handle = purple_plugins_get_handle();

	purple_signals_disconnect_by_handle(handle);
	purple_signals_unregister_by_instance(handle);

	while (search_paths) {
		g_free(search_paths->data);
		search_paths = g_list_delete_link(search_paths, search_paths);
	}
}

/**************************************************************************
 * Plugins API
 **************************************************************************/
void
purple_plugins_add_search_path(const char *path)
{
	g_return_if_fail(path != NULL);

	if (g_list_find_custom(search_paths, path, (GCompareFunc)strcmp))
		return;

	search_paths = g_list_append(search_paths, g_strdup(path));
}

GList *
purple_plugins_get_search_paths()
{
	return search_paths;
}

void
purple_plugins_unload_all(void)
{
#ifdef PURPLE_PLUGINS

	while (loaded_plugins != NULL)
		purple_plugin_unload(loaded_plugins->data);

#endif /* PURPLE_PLUGINS */
}

void
purple_plugins_unload(PurplePluginType type)
{
#ifdef PURPLE_PLUGINS
	GList *l;

	for (l = plugins; l; l = l->next) {
		PurplePlugin *plugin = l->data;
		if (plugin->info->type == type && purple_plugin_is_loaded(plugin))
			purple_plugin_unload(plugin);
	}

#endif /* PURPLE_PLUGINS */
}

void
purple_plugins_destroy_all(void)
{
#ifdef PURPLE_PLUGINS

	while (plugins != NULL)
		purple_plugin_destroy(plugins->data);

#endif /* PURPLE_PLUGINS */
}

void
purple_plugins_save_loaded(const char *key)
{
#ifdef PURPLE_PLUGINS
	GList *pl;
	GList *files = NULL;

	for (pl = purple_plugins_get_loaded(); pl != NULL; pl = pl->next) {
		PurplePlugin *plugin = pl->data;

		if (plugin->info->type != PURPLE_PLUGIN_PROTOCOL &&
		    plugin->info->type != PURPLE_PLUGIN_LOADER &&
		    !g_list_find(plugins_to_disable, plugin)) {
			files = g_list_append(files, plugin->path);
		}
	}

	purple_prefs_set_path_list(key, files);
	g_list_free(files);
#endif
}

void
purple_plugins_load_saved(const char *key)
{
#ifdef PURPLE_PLUGINS
	GList *f, *files;

	g_return_if_fail(key != NULL);

	files = purple_prefs_get_path_list(key);

	for (f = files; f; f = f->next)
	{
		char *filename;
		char *basename;
		PurplePlugin *plugin;

		if (f->data == NULL)
			continue;

		filename = f->data;

		/*
		 * We don't know if the filename uses Windows or Unix path
		 * separators (because people might be sharing a prefs.xml
		 * file across systems), so we find the last occurrence
		 * of either.
		 */
		basename = strrchr(filename, '/');
		if ((basename == NULL) || (basename < strrchr(filename, '\\')))
			basename = strrchr(filename, '\\');
		if (basename != NULL)
			basename++;

		/* Strip the extension */
		if (basename)
			basename = purple_plugin_get_basename(basename);

		if (((plugin = purple_plugins_find_with_filename(filename)) != NULL) ||
				(basename && (plugin = purple_plugins_find_with_basename(basename)) != NULL) ||
				((plugin = purple_plugin_probe(filename)) != NULL))
		{
			purple_debug_info("plugins", "Loading saved plugin %s\n",
							plugin->path);
			purple_plugin_load(plugin);
		}
		else
		{
			purple_debug_error("plugins", "Unable to find saved plugin %s\n",
							 filename);
		}

		g_free(basename);

		g_free(f->data);
	}

	g_list_free(files);
#endif /* PURPLE_PLUGINS */
}


void
purple_plugins_probe(const char *ext)
{
#ifdef PURPLE_PLUGINS
	GDir *dir;
	const gchar *file;
	gchar *path;
	PurplePlugin *plugin;
	GList *cur;
	const char *search_path;

	if (!g_module_supported())
		return;

	/* Probe plugins */
	for (cur = search_paths; cur != NULL; cur = cur->next)
	{
		search_path = cur->data;

		dir = g_dir_open(search_path, 0, NULL);

		if (dir != NULL)
		{
			while ((file = g_dir_read_name(dir)) != NULL)
			{
				path = g_build_filename(search_path, file, NULL);

				if (ext == NULL || has_file_extension(file, ext))
					purple_plugin_probe(path);

				g_free(path);
			}

			g_dir_close(dir);
		}
	}

	/* See if we have any plugins waiting to load */
	while (load_queue != NULL)
	{
		plugin = (PurplePlugin *)load_queue->data;

		load_queue = g_list_remove(load_queue, plugin);

		if (plugin == NULL || plugin->info == NULL)
			continue;

		if (plugin->info->type == PURPLE_PLUGIN_LOADER)
		{
			/* We'll just load this right now. */
			if (!purple_plugin_load(plugin))
			{
				purple_plugin_destroy(plugin);

				continue;
			}

			plugin_loaders = g_list_append(plugin_loaders, plugin);

			for (cur = PURPLE_PLUGIN_LOADER_INFO(plugin)->exts;
				 cur != NULL;
				 cur = cur->next)
			{
				purple_plugins_probe(cur->data);
			}
		}
		else if (plugin->info->type == PURPLE_PLUGIN_PROTOCOL)
		{
			/* We'll just load this right now. */
			if (!purple_plugin_load(plugin))
			{
				purple_plugin_destroy(plugin);

				continue;
			}

			/* Make sure we don't load two PRPLs with the same name? */
			if (purple_find_prpl(plugin->info->id))
			{
				/* Nothing to see here--move along, move along */
				purple_plugin_destroy(plugin);

				continue;
			}

			protocol_plugins = g_list_insert_sorted(protocol_plugins, plugin,
													(GCompareFunc)compare_prpl);
		}
	}

	if (probe_cb != NULL)
		probe_cb(probe_cb_data);

#endif /* PURPLE_PLUGINS */
}

gboolean
purple_plugin_register(PurplePlugin *plugin)
{
	g_return_val_if_fail(plugin != NULL, FALSE);

	/* If this plugin has been registered already then exit */
	if (g_list_find(plugins, plugin))
		return TRUE;

	/* Ensure the plugin has the requisite information */
	if (plugin->info->type == PURPLE_PLUGIN_LOADER)
	{
		PurplePluginLoaderInfo *loader_info;

		loader_info = PURPLE_PLUGIN_LOADER_INFO(plugin);

		if (loader_info == NULL)
		{
			purple_debug_error("plugins", "%s is not loadable, loader plugin missing loader_info\n",
							   plugin->path);
			return FALSE;
		}
	}
	else if (plugin->info->type == PURPLE_PLUGIN_PROTOCOL)
	{
		PurplePluginProtocolInfo *prpl_info;

		prpl_info = PURPLE_PLUGIN_PROTOCOL_INFO(plugin);

		if (prpl_info == NULL)
		{
			purple_debug_error("plugins", "%s is not loadable, protocol plugin missing prpl_info\n",
							   plugin->path);
			return FALSE;
		}
	}

#ifdef PURPLE_PLUGINS
	/* This plugin should be probed and maybe loaded--add it to the queue */
	load_queue = g_list_append(load_queue, plugin);
#else
	if (plugin->info != NULL)
	{
		if (plugin->info->type == PURPLE_PLUGIN_PROTOCOL)
			protocol_plugins = g_list_insert_sorted(protocol_plugins, plugin,
													(GCompareFunc)compare_prpl);
		if (plugin->info->load != NULL)
			if (!plugin->info->load(plugin))
				return FALSE;
	}
#endif

	plugins = g_list_append(plugins, plugin);

	return TRUE;
}

gboolean
purple_plugins_enabled(void)
{
#ifdef PURPLE_PLUGINS
	return TRUE;
#else
	return FALSE;
#endif
}

void
purple_plugins_register_probe_notify_cb(void (*func)(void *), void *data)
{
	probe_cb = func;
	probe_cb_data = data;
}

void
purple_plugins_unregister_probe_notify_cb(void (*func)(void *))
{
	probe_cb = NULL;
	probe_cb_data = NULL;
}

void
purple_plugins_register_load_notify_cb(void (*func)(PurplePlugin *, void *),
									 void *data)
{
	load_cb = func;
	load_cb_data = data;
}

void
purple_plugins_unregister_load_notify_cb(void (*func)(PurplePlugin *, void *))
{
	load_cb = NULL;
	load_cb_data = NULL;
}

void
purple_plugins_register_unload_notify_cb(void (*func)(PurplePlugin *, void *),
									   void *data)
{
	unload_cb = func;
	unload_cb_data = data;
}

void
purple_plugins_unregister_unload_notify_cb(void (*func)(PurplePlugin *, void *))
{
	unload_cb = NULL;
	unload_cb_data = NULL;
}

PurplePlugin *
purple_plugins_find_with_name(const char *name)
{
	PurplePlugin *plugin;
	GList *l;

	for (l = plugins; l != NULL; l = l->next) {
		plugin = l->data;

		if (purple_strequal(plugin->info->name, name))
			return plugin;
	}

	return NULL;
}

PurplePlugin *
purple_plugins_find_with_filename(const char *filename)
{
	PurplePlugin *plugin;
	GList *l;

	for (l = plugins; l != NULL; l = l->next) {
		plugin = l->data;

		if (purple_strequal(plugin->path, filename))
			return plugin;
	}

	return NULL;
}

PurplePlugin *
purple_plugins_find_with_basename(const char *basename)
{
#ifdef PURPLE_PLUGINS
	PurplePlugin *plugin;
	GList *l;
	char *tmp;

	g_return_val_if_fail(basename != NULL, NULL);

	for (l = plugins; l != NULL; l = l->next)
	{
		plugin = (PurplePlugin *)l->data;

		if (plugin->path != NULL) {
			tmp = purple_plugin_get_basename(plugin->path);
			if (purple_strequal(tmp, basename))
			{
				g_free(tmp);
				return plugin;
			}
			g_free(tmp);
		}
	}

#endif /* PURPLE_PLUGINS */

	return NULL;
}

PurplePlugin *
purple_plugins_find_with_id(const char *id)
{
	PurplePlugin *plugin;
	GList *l;

	g_return_val_if_fail(id != NULL, NULL);

	for (l = plugins; l != NULL; l = l->next)
	{
		plugin = l->data;

		if (purple_strequal(plugin->info->id, id))
			return plugin;
	}

	return NULL;
}

GList *
purple_plugins_get_loaded(void)
{
	return loaded_plugins;
}

GList *
purple_plugins_get_protocols(void)
{
	return protocol_plugins;
}

GList *
purple_plugins_get_all(void)
{
	return plugins;
}


PurplePluginAction *
purple_plugin_action_new(const char* label, void (*callback)(PurplePluginAction *))
{
	PurplePluginAction *act = g_new0(PurplePluginAction, 1);

	act->label = g_strdup(label);
	act->callback = callback;

	return act;
}

void
purple_plugin_action_free(PurplePluginAction *action)
{
	g_return_if_fail(action != NULL);

	g_free(action->label);
	g_free(action);
}
