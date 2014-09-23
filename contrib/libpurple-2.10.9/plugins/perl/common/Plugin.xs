#include "module.h"

MODULE = Purple::Plugin  PACKAGE = Purple::Plugin  PREFIX = purple_plugin_
PROTOTYPES: ENABLE

BOOT:
{
	HV *stash = gv_stashpv("Purple::Plugin::Type", 1);

	static const constiv *civ, const_iv[] = {
#define const_iv(name) {#name, (IV)PURPLE_PLUGIN_##name}
		const_iv(UNKNOWN),
		const_iv(STANDARD),
		const_iv(LOADER),
		const_iv(PROTOCOL),
	};

	for (civ = const_iv + sizeof(const_iv) / sizeof(const_iv[0]); civ-- > const_iv; )
		newCONSTSUB(stash, (char *)civ->name, newSViv(civ->iv));
}

Purple::Plugin
purple_plugin_new(native, path)
	gboolean native
	const char *path

Purple::Plugin
purple_plugin_probe(filename)
	const char *filename

gboolean
purple_plugin_register(plugin)
	Purple::Plugin plugin

gboolean
purple_plugin_load(plugin)
	Purple::Plugin plugin

gboolean
purple_plugin_unload(plugin)
	Purple::Plugin plugin

gboolean
purple_plugin_reload(plugin)
	Purple::Plugin plugin

void
purple_plugin_destroy(plugin)
	Purple::Plugin plugin

gboolean
purple_plugin_is_loaded(plugin)
	Purple::Plugin plugin

gboolean
purple_plugin_is_unloadable(plugin)
	Purple::Plugin plugin

const gchar *
purple_plugin_get_id(plugin)
	Purple::Plugin plugin

const gchar *
purple_plugin_get_name(plugin)
	Purple::Plugin plugin

const gchar *
purple_plugin_get_version(plugin)
	Purple::Plugin plugin

const gchar *
purple_plugin_get_summary(plugin)
	Purple::Plugin plugin

const gchar *
purple_plugin_get_description(plugin)
	Purple::Plugin plugin

const gchar *
purple_plugin_get_author(plugin)
	Purple::Plugin plugin

const gchar *
purple_plugin_get_homepage(plugin)
	Purple::Plugin plugin

MODULE = Purple::Plugin  PACKAGE = Purple::Plugin::IPC  PREFIX = purple_plugin_ipc_

void
purple_plugin_ipc_unregister(plugin, command)
	Purple::Plugin plugin
	const char *command

void
purple_plugin_ipc_unregister_all(plugin)
	Purple::Plugin plugin

MODULE = Purple::Plugin  PACKAGE = Purple::Plugins  PREFIX = purple_plugins_
PROTOTYPES: ENABLE

void
purple_plugins_add_search_path(path)
	const char *path

void
purple_plugins_unload_all()

void
purple_plugins_destroy_all()

void
purple_plugins_load_saved(key)
	const char *key

void
purple_plugins_probe(ext)
	const char *ext

gboolean
purple_plugins_enabled()

Purple::Plugin
purple_plugins_find_with_name(name)
	const char *name

Purple::Plugin
purple_plugins_find_with_filename(filename)
	const char *filename

Purple::Plugin
purple_plugins_find_with_basename(basename)
	const char *basename

Purple::Plugin
purple_plugins_find_with_id(id)
	const char *id

void
purple_plugins_get_loaded()
PREINIT:
	GList *l;
PPCODE:
	for (l = purple_plugins_get_loaded(); l != NULL; l = l->next) {
		XPUSHs(sv_2mortal(purple_perl_bless_object(l->data, "Purple::Plugin")));
	}

void
purple_plugins_get_protocols()
PREINIT:
	GList *l;
PPCODE:
	for (l = purple_plugins_get_protocols(); l != NULL; l = l->next) {
		XPUSHs(sv_2mortal(purple_perl_bless_object(l->data, "Purple::Plugin")));
	}

void
purple_plugins_get_all()
PREINIT:
	GList *l;
PPCODE:
	for (l = purple_plugins_get_all(); l != NULL; l = l->next) {
		XPUSHs(sv_2mortal(purple_perl_bless_object(l->data, "Purple::Plugin")));
	}

Purple::Handle
purple_plugins_get_handle()
