/*
 * Mono Plugin Loader
 *
 * -- Thanks to the perl plugin loader for all the great tips ;-)
 *
 * Eoin Coffey
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib.h>
#include <string.h>
#include "mono-helper.h"
#include "mono-glue.h"
#include "value.h"
#include "debug.h"

static gboolean _runtime_active = FALSE;

gboolean ml_init()
{
	MonoDomain *d;

	g_return_val_if_fail(_runtime_active == FALSE, TRUE);

	d = mono_jit_init("purple");

	if (!d) {
		ml_set_domain(NULL);
		return FALSE;
	}

	ml_set_domain(d);

	ml_init_internal_calls();

	_runtime_active = TRUE;

	return TRUE;
}

void ml_uninit()
{
	g_return_if_fail(_runtime_active == TRUE);

	mono_jit_cleanup(ml_get_domain());

	ml_set_domain(NULL);

	_runtime_active = FALSE;
}

MonoObject* ml_delegate_invoke(MonoObject *method, void **params)
{
	MonoObject *ret, *exception;

	ret = mono_runtime_delegate_invoke(method, params, &exception);
	if (exception) {
		purple_debug(PURPLE_DEBUG_ERROR, "mono", "caught exception: %s\n", mono_class_get_name(mono_object_get_class(exception)));
	}

	return ret;
}

MonoObject* ml_invoke(MonoMethod *method, void *obj, void **params)
{
	MonoObject *ret, *exception;

	ret = mono_runtime_invoke(method, obj, params, &exception);
	if (exception) {
		purple_debug(PURPLE_DEBUG_ERROR, "mono", "caught exception: %s\n", mono_class_get_name(mono_object_get_class(exception)));
	}

	return ret;
}

MonoClass* ml_find_plugin_class(MonoImage *image)
{
	MonoClass *klass, *pklass = NULL;
	int i, total;

	total = mono_image_get_table_rows (image, MONO_TABLE_TYPEDEF);
	for (i = 1; i <= total; ++i) {
		klass = mono_class_get (image, MONO_TOKEN_TYPE_DEF | i);

		pklass = mono_class_get_parent(klass);
		if (pklass) {

			if (strcmp("Plugin", mono_class_get_name(pklass)) == 0)
				return klass;
		}
	}

	return NULL;
}

void ml_set_prop_string(MonoObject *obj, char *field, char *data)
{
	MonoClass *klass;
	MonoProperty *prop;
	MonoString *str;
	gpointer args[1];

	klass = mono_object_get_class(obj);

	prop = mono_class_get_property_from_name(klass, field);

	str = mono_string_new(ml_get_domain(), data);

	args[0] = str;

	mono_property_set_value(prop, obj, args, NULL);
}

gchar* ml_get_prop_string(MonoObject *obj, char *field)
{
	MonoClass *klass;
	MonoProperty *prop;
	MonoString *str;

	klass = mono_object_get_class(obj);

	prop = mono_class_get_property_from_name(klass, field);

	str = (MonoString*)mono_property_get_value(prop, obj, NULL, NULL);

	return mono_string_to_utf8(str);
}

MonoObject* ml_get_info_prop(MonoObject *obj)
{
	MonoClass *klass;
	MonoProperty *prop;

	klass = mono_class_get_parent(mono_object_get_class(obj));

	prop = mono_class_get_property_from_name(klass, "Info");

	return mono_property_get_value(prop, obj, NULL, NULL);
}

gboolean ml_is_api_dll(MonoImage *image)
{
	MonoClass *klass;
	int i, total;

	total = mono_image_get_table_rows (image, MONO_TABLE_TYPEDEF);
	for (i = 1; i <= total; ++i) {
		klass = mono_class_get (image, MONO_TOKEN_TYPE_DEF | i);
		if (strcmp(mono_class_get_name(klass), "Debug") == 0)
			if (strcmp(mono_class_get_namespace(klass), "Purple") == 0) {
				ml_set_api_image(image);
				return TRUE;
			}
	}

	return FALSE;
}

MonoObject* ml_object_from_purple_type(PurpleType type, gpointer data)
{
	return NULL;
}

MonoObject* ml_object_from_purple_subtype(PurpleSubType type, gpointer data)
{
	MonoObject *obj = NULL;

	switch (type) {
		case PURPLE_SUBTYPE_BLIST_BUDDY:
			obj = purple_blist_build_buddy_object(data);
		break;
		case PURPLE_SUBTYPE_STATUS:
			obj = purple_status_build_status_object(data);
		break;
		default:
		break;
	}

	return obj;
}

MonoObject* ml_create_api_object(char *class_name)
{
	MonoObject *obj = NULL;
	MonoClass *klass = NULL;

	klass = mono_class_from_name(ml_get_api_image(), "Purple", class_name);
	if (!klass) {
		purple_debug(PURPLE_DEBUG_FATAL, "mono", "couldn't find the '%s' class\n", class_name);
		return NULL;
	}

	obj = mono_object_new(ml_get_domain(), klass);
	if (!obj) {
		purple_debug(PURPLE_DEBUG_FATAL, "mono", "couldn't create the object from class '%s'\n", class_name);
		return NULL;
	}

	mono_runtime_object_init(obj);

	return obj;
}

static MonoDomain *_domain = NULL;

MonoDomain* ml_get_domain(void)
{
	return _domain;
}

void ml_set_domain(MonoDomain *d)
{
	_domain = d;
}

static MonoImage *_api_image = NULL;

void ml_set_api_image(MonoImage *image)
{
	_api_image = image;
}

MonoImage* ml_get_api_image()
{
	return _api_image;
}

void ml_init_internal_calls(void)
{
	mono_add_internal_call("Purple.Debug::_debug", purple_debug_glue);
	mono_add_internal_call("Purple.Signal::_connect", purple_signal_connect_glue);
	mono_add_internal_call("Purple.BuddyList::_get_handle", purple_blist_get_handle_glue);
}

static GHashTable *plugins_hash = NULL;

void ml_add_plugin(PurpleMonoPlugin *plugin)
{
	if (!plugins_hash)
		plugins_hash = g_hash_table_new(NULL, NULL);

	g_hash_table_insert(plugins_hash, plugin->klass, plugin);
}

gboolean ml_remove_plugin(PurpleMonoPlugin *plugin)
{
	return g_hash_table_remove(plugins_hash, plugin->klass);
}

gpointer ml_find_plugin(PurpleMonoPlugin *plugin)
{
	return g_hash_table_lookup(plugins_hash, plugin->klass);
}

gpointer ml_find_plugin_by_class(MonoClass *klass)
{
	return g_hash_table_lookup(plugins_hash, klass);
}

GHashTable* ml_get_plugin_hash()
{
	return plugins_hash;
}
