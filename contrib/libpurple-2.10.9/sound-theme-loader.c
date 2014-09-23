/*
 * SoundThemeLoader for libpurple
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
#include "sound-theme-loader.h"
#include "sound-theme.h"
#include "util.h"
#include "xmlnode.h"
#include "debug.h"

/*****************************************************************************
 * Sound Theme Builder
 *****************************************************************************/

static PurpleTheme *
purple_sound_loader_build(const gchar *dir)
{
	xmlnode *root_node = NULL, *sub_node;
	gchar *filename_full, *data = NULL;
	PurpleSoundTheme *theme = NULL;
	const gchar *name;

	/* Find the theme file */
	g_return_val_if_fail(dir != NULL, NULL);
	filename_full = g_build_filename(dir, "theme.xml", NULL);

	if (g_file_test(filename_full, G_FILE_TEST_IS_REGULAR))
		root_node = xmlnode_from_file(dir, "theme.xml", "sound themes", "sound-theme-loader");

	g_free(filename_full);
	if (root_node == NULL)
		return NULL;

	name = xmlnode_get_attrib(root_node, "name");

	if (name && purple_strequal(xmlnode_get_attrib(root_node, "type"), "sound")) {
		/* Parse the tree */
		sub_node = xmlnode_get_child(root_node, "description");
		data = xmlnode_get_data(sub_node);

		if (xmlnode_get_attrib(root_node, "name") != NULL) {
			theme = g_object_new(PURPLE_TYPE_SOUND_THEME,
					"type", "sound",
					"name", name,
					"author", xmlnode_get_attrib(root_node, "author"),
					"image", xmlnode_get_attrib(root_node, "image"),
					"directory", dir,
					"description", data, NULL);

			sub_node = xmlnode_get_child(root_node, "event");

			while (sub_node) {
				purple_sound_theme_set_file(theme,
						xmlnode_get_attrib(sub_node, "name"),
						xmlnode_get_attrib(sub_node, "file"));
				sub_node = xmlnode_get_next_twin(sub_node);
			}
		}
	} else purple_debug_warning("sound-theme-loader", "Missing attribute or problem with the root element\n");

	xmlnode_free(root_node);
	g_free(data);
	return PURPLE_THEME(theme);
}

/******************************************************************************
 * GObject Stuff
 *****************************************************************************/

static void
purple_sound_theme_loader_class_init(PurpleSoundThemeLoaderClass *klass)
{
	PurpleThemeLoaderClass *loader_klass = PURPLE_THEME_LOADER_CLASS(klass);

	loader_klass->purple_theme_loader_build = purple_sound_loader_build;
}

GType
purple_sound_theme_loader_get_type(void)
{
	static GType type = 0;
	if (type == 0) {
		static const GTypeInfo info = {
			sizeof(PurpleSoundThemeLoaderClass),
			NULL, /* base_init */
			NULL, /* base_finalize */
			(GClassInitFunc)purple_sound_theme_loader_class_init, /* class_init */
			NULL, /* class_finalize */
			NULL, /* class_data */
			sizeof(PurpleSoundThemeLoader),
			0, /* n_preallocs */
			NULL, /* instance_init */
			NULL, /* value table */
		};
		type = g_type_register_static(PURPLE_TYPE_THEME_LOADER,
				"PurpleSoundThemeLoader", &info, 0);
	}
	return type;
}
