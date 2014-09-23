/*
 * Themes for libpurple
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
#include "theme.h"
#include "util.h"

#define PURPLE_THEME_GET_PRIVATE(PurpleTheme) \
	((PurpleThemePrivate *) ((PurpleTheme)->priv))

void purple_theme_set_type_string(PurpleTheme *theme, const gchar *type);

/******************************************************************************
 * Structs
 *****************************************************************************/

typedef struct {
	gchar *name;
	gchar *description;
	gchar *author;
	gchar *type;
	gchar *dir;
	gchar *img;
} PurpleThemePrivate;

/******************************************************************************
 * Globals
 *****************************************************************************/

static GObjectClass *parent_class = NULL;

/******************************************************************************
 * Enums
 *****************************************************************************/

enum {
	PROP_ZERO = 0,
	PROP_NAME,
	PROP_DESCRIPTION,
	PROP_AUTHOR,
	PROP_TYPE,
	PROP_DIR,
	PROP_IMAGE
};

/******************************************************************************
 * GObject Stuff
 *****************************************************************************/

static void
purple_theme_get_property(GObject *obj, guint param_id, GValue *value,
		GParamSpec *psec)
{
	PurpleTheme *theme = PURPLE_THEME(obj);

	switch (param_id) {
		case PROP_NAME:
			g_value_set_string(value, purple_theme_get_name(theme));
			break;
		case PROP_DESCRIPTION:
			g_value_set_string(value, purple_theme_get_description(theme));
			break;
		case PROP_AUTHOR:
			g_value_set_string(value, purple_theme_get_author(theme));
			break;
		case PROP_TYPE:
			g_value_set_string(value, purple_theme_get_type_string(theme));
			break;
		case PROP_DIR:
			g_value_set_string(value, purple_theme_get_dir(theme));
			break;
		case PROP_IMAGE:
			g_value_set_string(value, purple_theme_get_image(theme));
			break;
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID(obj, param_id, psec);
			break;
	}
}

static void
purple_theme_set_property(GObject *obj, guint param_id, const GValue *value,
		GParamSpec *psec)
{
	PurpleTheme *theme = PURPLE_THEME(obj);

	switch (param_id) {
		case PROP_NAME:
			purple_theme_set_name(theme, g_value_get_string(value));
			break;
		case PROP_DESCRIPTION:
			purple_theme_set_description(theme, g_value_get_string(value));
			break;
		case PROP_AUTHOR:
			purple_theme_set_author(theme, g_value_get_string(value));
			break;
		case PROP_TYPE:
			purple_theme_set_type_string(theme, g_value_get_string(value));
			break;
		case PROP_DIR:
			purple_theme_set_dir(theme, g_value_get_string(value));
			break;
		case PROP_IMAGE:
			purple_theme_set_image(theme, g_value_get_string(value));
			break;
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID(obj, param_id, psec);
			break;
	}
}

static void
purple_theme_init(GTypeInstance *instance,
		gpointer klass)
{
	PurpleTheme *theme = PURPLE_THEME(instance);
	theme->priv = g_new0(PurpleThemePrivate, 1);
}

static void
purple_theme_finalize(GObject *obj)
{
	PurpleTheme *theme = PURPLE_THEME(obj);
	PurpleThemePrivate *priv = PURPLE_THEME_GET_PRIVATE(theme);

	g_free(priv->name);
	g_free(priv->description);
	g_free(priv->author);
	g_free(priv->type);
	g_free(priv->dir);
	g_free(priv->img);

	G_OBJECT_CLASS (parent_class)->finalize (obj);
}

static void
purple_theme_class_init(PurpleThemeClass *klass)
{
	GObjectClass *obj_class = G_OBJECT_CLASS(klass);
	GParamSpec *pspec;

	parent_class = g_type_class_peek_parent(klass);

	obj_class->get_property = purple_theme_get_property;
	obj_class->set_property = purple_theme_set_property;
	obj_class->finalize = purple_theme_finalize;

	/* NAME */
	pspec = g_param_spec_string("name", "Name",
			"The name of the theme",
			NULL,
			G_PARAM_READWRITE | G_PARAM_CONSTRUCT);
	g_object_class_install_property(obj_class, PROP_NAME, pspec);

	/* DESCRIPTION */
	pspec = g_param_spec_string("description", "Description",
			"The description of the theme",
			NULL,
			G_PARAM_READWRITE | G_PARAM_CONSTRUCT);
	g_object_class_install_property(obj_class, PROP_DESCRIPTION, pspec);

	/* AUTHOR */
	pspec = g_param_spec_string("author", "Author",
			"The author of the theme",
			NULL,
			G_PARAM_READWRITE | G_PARAM_CONSTRUCT);
	g_object_class_install_property(obj_class, PROP_AUTHOR, pspec);

	/* TYPE STRING (read only) */
	pspec = g_param_spec_string("type", "Type",
			"The string representing the type of the theme",
			NULL,
			G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY);
	g_object_class_install_property(obj_class, PROP_TYPE, pspec);

	/* DIRECTORY */
	pspec = g_param_spec_string("directory", "Directory",
			"The directory that contains the theme and all its files",
			NULL,
			G_PARAM_READWRITE | G_PARAM_CONSTRUCT);
	g_object_class_install_property(obj_class, PROP_DIR, pspec);

	/* PREVIEW IMAGE */
	pspec = g_param_spec_string("image", "Image",
			"A preview image of the theme",
			NULL,
			G_PARAM_READWRITE);
	g_object_class_install_property(obj_class, PROP_IMAGE, pspec);
}


GType
purple_theme_get_type(void)
{
	static GType type = 0;
	if (type == 0) {
		static const GTypeInfo info = {
			sizeof(PurpleThemeClass),
			NULL, /* base_init */
			NULL, /* base_finalize */
			(GClassInitFunc)purple_theme_class_init, /* class_init */
			NULL, /* class_finalize */
			NULL, /* class_data */
			sizeof(PurpleTheme),
			0, /* n_preallocs */
			purple_theme_init, /* instance_init */
			NULL, /* value table */
		};
		type = g_type_register_static (G_TYPE_OBJECT,
				"PurpleTheme", &info, G_TYPE_FLAG_ABSTRACT);
	}
	return type;
}

/******************************************************************************
 * Helper Functions
 *****************************************************************************/

static gchar *
theme_clean_text(const gchar *text)
{
	gchar *clean_text = NULL;
	if (text != NULL) {
		clean_text = g_markup_escape_text(text, -1);
		g_strdelimit(clean_text, "\n", ' ');
		purple_str_strip_char(clean_text, '\r');
	}
	return clean_text;
}

/*****************************************************************************
 * Public API function
 *****************************************************************************/

const gchar *
purple_theme_get_name(PurpleTheme *theme)
{
	PurpleThemePrivate *priv;

	g_return_val_if_fail(PURPLE_IS_THEME(theme), NULL);

	priv = PURPLE_THEME_GET_PRIVATE(theme);
	return priv->name;
}

void
purple_theme_set_name(PurpleTheme *theme, const gchar *name)
{
	PurpleThemePrivate *priv;

	g_return_if_fail(PURPLE_IS_THEME(theme));

	priv = PURPLE_THEME_GET_PRIVATE(theme);

	g_free(priv->name);
	priv->name = theme_clean_text(name);
}

const gchar *
purple_theme_get_description(PurpleTheme *theme)
{
	PurpleThemePrivate *priv;

	g_return_val_if_fail(PURPLE_IS_THEME(theme), NULL);

	priv = PURPLE_THEME_GET_PRIVATE(theme);
	return priv->description;
}

void
purple_theme_set_description(PurpleTheme *theme, const gchar *description)
{
	PurpleThemePrivate *priv;

	g_return_if_fail(PURPLE_IS_THEME(theme));

	priv = PURPLE_THEME_GET_PRIVATE(theme);

	g_free(priv->description);
	priv->description = theme_clean_text(description);
}

const gchar *
purple_theme_get_author(PurpleTheme *theme)
{
	PurpleThemePrivate *priv;

	g_return_val_if_fail(PURPLE_IS_THEME(theme), NULL);

	priv = PURPLE_THEME_GET_PRIVATE(theme);
	return priv->author;
}

void
purple_theme_set_author(PurpleTheme *theme, const gchar *author)
{
	PurpleThemePrivate *priv;

	g_return_if_fail(PURPLE_IS_THEME(theme));

	priv = PURPLE_THEME_GET_PRIVATE(theme);

	g_free(priv->author);
	priv->author = theme_clean_text(author);
}

const gchar *
purple_theme_get_type_string(PurpleTheme *theme)
{
	PurpleThemePrivate *priv;

	g_return_val_if_fail(PURPLE_IS_THEME(theme), NULL);

	priv = PURPLE_THEME_GET_PRIVATE(theme);
	return priv->type;
}

/* < private > */
void
purple_theme_set_type_string(PurpleTheme *theme, const gchar *type)
{
	PurpleThemePrivate *priv;

	g_return_if_fail(PURPLE_IS_THEME(theme));

	priv = PURPLE_THEME_GET_PRIVATE(theme);

	g_free(priv->type);
	priv->type = g_strdup(type);
}

const gchar *
purple_theme_get_dir(PurpleTheme *theme)
{
	PurpleThemePrivate *priv;

	g_return_val_if_fail(PURPLE_IS_THEME(theme), NULL);

	priv = PURPLE_THEME_GET_PRIVATE(theme);
	return priv->dir;
}

void
purple_theme_set_dir(PurpleTheme *theme, const gchar *dir)
{
	PurpleThemePrivate *priv;

	g_return_if_fail(PURPLE_IS_THEME(theme));

	priv = PURPLE_THEME_GET_PRIVATE(theme);

	g_free(priv->dir);
	priv->dir = g_strdup(dir);
}

const gchar *
purple_theme_get_image(PurpleTheme *theme)
{
	PurpleThemePrivate *priv;

	g_return_val_if_fail(PURPLE_IS_THEME(theme), NULL);

	priv = PURPLE_THEME_GET_PRIVATE(theme);

	return priv->img;
}

gchar *
purple_theme_get_image_full(PurpleTheme *theme)
{
	const gchar *filename = purple_theme_get_image(theme);

	if (filename)
		return g_build_filename(purple_theme_get_dir(PURPLE_THEME(theme)), filename, NULL);
	else
		return NULL;
}

void
purple_theme_set_image(PurpleTheme *theme, const gchar *img)
{
	PurpleThemePrivate *priv;

	g_return_if_fail(PURPLE_IS_THEME(theme));

	priv = PURPLE_THEME_GET_PRIVATE(theme);

	g_free(priv->img);
	priv->img = g_strdup(img);
}
