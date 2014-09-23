/*
 * ThemeLoaders for libpurple
 *
 * Pidgin is the legal property of its developers, whose names are too numerous
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
#include "theme-loader.h"

#define PURPLE_THEME_LOADER_GET_PRIVATE(PurpleThemeLoader) \
	((PurpleThemeLoaderPrivate *) ((PurpleThemeLoader)->priv))

void purple_theme_loader_set_type_string(PurpleThemeLoader *loader, const gchar *type);

/******************************************************************************
 * Structs
 *****************************************************************************/
typedef struct {
	gchar *type;
} PurpleThemeLoaderPrivate;

/******************************************************************************
 * Globals
 *****************************************************************************/

static GObjectClass *parent_class = NULL;

/******************************************************************************
 * Enums
 *****************************************************************************/

enum {
	PROP_ZERO = 0,
	PROP_TYPE,
};

/******************************************************************************
 * GObject Stuff                                                              *
 *****************************************************************************/

static void
purple_theme_loader_get_property(GObject *obj, guint param_id, GValue *value,
						 GParamSpec *psec)
{
	PurpleThemeLoader *theme_loader = PURPLE_THEME_LOADER(obj);

	switch (param_id) {
		case PROP_TYPE:
			g_value_set_string(value, purple_theme_loader_get_type_string(theme_loader));
			break;
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID(obj, param_id, psec);
			break;
	}
}

static void
purple_theme_loader_set_property(GObject *obj, guint param_id, const GValue *value,
						 GParamSpec *psec)
{
	PurpleThemeLoader *loader = PURPLE_THEME_LOADER(obj);

	switch (param_id) {
		case PROP_TYPE:
			purple_theme_loader_set_type_string(loader, g_value_get_string(value));
			break;
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID(obj, param_id, psec);
			break;
	}
}

static void
purple_theme_loader_init(GTypeInstance *instance,
			gpointer klass)
{
	PurpleThemeLoader *loader = PURPLE_THEME_LOADER(instance);
	loader->priv = g_new0(PurpleThemeLoaderPrivate, 1);
}

static void
purple_theme_loader_finalize(GObject *obj)
{
	PurpleThemeLoader *loader = PURPLE_THEME_LOADER(obj);
	PurpleThemeLoaderPrivate *priv = PURPLE_THEME_LOADER_GET_PRIVATE(loader);

	g_free(priv->type);
	g_free(priv);

	parent_class->finalize(obj);
}

static void
purple_theme_loader_class_init(PurpleThemeLoaderClass *klass)
{
	GObjectClass *obj_class = G_OBJECT_CLASS(klass);
	GParamSpec *pspec;

	parent_class = g_type_class_peek_parent(klass);

	obj_class->get_property = purple_theme_loader_get_property;
	obj_class->set_property = purple_theme_loader_set_property;
	obj_class->finalize = purple_theme_loader_finalize;

	/* TYPE STRING (read only) */
	pspec = g_param_spec_string("type", "Type",
				    "The string representing the type of the theme",
				    NULL,
				    G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY);
	g_object_class_install_property(obj_class, PROP_TYPE, pspec);
}

GType
purple_theme_loader_get_type(void)
{
	static GType type = 0;
	if (type == 0) {
		static const GTypeInfo info = {
			sizeof(PurpleThemeLoaderClass),
			NULL, /* base_init */
			NULL, /* base_finalize */
			(GClassInitFunc)purple_theme_loader_class_init, /* class_init */
			NULL, /* class_finalize */
			NULL, /* class_data */
			sizeof(PurpleThemeLoader),
			0, /* n_preallocs */
			purple_theme_loader_init, /* instance_init */
			NULL, /* value table */
		};
		type = g_type_register_static(G_TYPE_OBJECT,
				"PurpleThemeLoader", &info, G_TYPE_FLAG_ABSTRACT);
	}
	return type;
}

/*****************************************************************************
 * Public API functions
 *****************************************************************************/

const gchar *
purple_theme_loader_get_type_string(PurpleThemeLoader *theme_loader)
{
	PurpleThemeLoaderPrivate *priv = NULL;

	g_return_val_if_fail(PURPLE_IS_THEME_LOADER(theme_loader), NULL);

	priv = PURPLE_THEME_LOADER_GET_PRIVATE(theme_loader);
	return priv->type;
}

/* < private > */
void
purple_theme_loader_set_type_string(PurpleThemeLoader *loader, const gchar *type)
{
	PurpleThemeLoaderPrivate *priv;

	g_return_if_fail(PURPLE_IS_THEME_LOADER(loader));

	priv = PURPLE_THEME_LOADER_GET_PRIVATE(loader);

	g_free(priv->type);
	priv->type = g_strdup(type);
}

PurpleTheme *
purple_theme_loader_build(PurpleThemeLoader *loader, const gchar *dir)
{
	return PURPLE_THEME_LOADER_GET_CLASS(loader)->purple_theme_loader_build(dir);
}
