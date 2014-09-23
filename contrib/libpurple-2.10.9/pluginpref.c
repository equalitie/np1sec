/**
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
#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <glib.h>

#include "debug.h"
#include "internal.h"
#include "pluginpref.h"
#include "prefs.h"

struct _PurplePluginPrefFrame
{
	GList *prefs;
};

struct _PurplePluginPref
{
	char *name;
	char *label;

	PurplePluginPrefType type;

	int min;
	int max;
	GList *choices;
	unsigned int max_length;
	gboolean masked;
	PurpleStringFormatType format;
};

PurplePluginPrefFrame *
purple_plugin_pref_frame_new()
{
	PurplePluginPrefFrame *frame;

	frame = g_new0(PurplePluginPrefFrame, 1);

	return frame;
}

void
purple_plugin_pref_frame_destroy(PurplePluginPrefFrame *frame)
{
	g_return_if_fail(frame != NULL);

	g_list_foreach(frame->prefs, (GFunc)purple_plugin_pref_destroy, NULL);
	g_list_free(frame->prefs);
	g_free(frame);
}

void
purple_plugin_pref_frame_add(PurplePluginPrefFrame *frame, PurplePluginPref *pref)
{
	g_return_if_fail(frame != NULL);
	g_return_if_fail(pref  != NULL);

	frame->prefs = g_list_append(frame->prefs, pref);
}

GList *
purple_plugin_pref_frame_get_prefs(PurplePluginPrefFrame *frame)
{
	g_return_val_if_fail(frame        != NULL, NULL);
	g_return_val_if_fail(frame->prefs != NULL, NULL);

	return frame->prefs;
}

PurplePluginPref *
purple_plugin_pref_new()
{
	PurplePluginPref *pref;

	pref = g_new0(PurplePluginPref, 1);

	return pref;
}

PurplePluginPref *
purple_plugin_pref_new_with_name(const char *name)
{
	PurplePluginPref *pref;

	g_return_val_if_fail(name != NULL, NULL);

	pref = g_new0(PurplePluginPref, 1);
	pref->name = g_strdup(name);

	return pref;
}

PurplePluginPref *
purple_plugin_pref_new_with_label(const char *label)
{
	PurplePluginPref *pref;

	g_return_val_if_fail(label != NULL, NULL);

	pref = g_new0(PurplePluginPref, 1);
	pref->label = g_strdup(label);

	return pref;
}

PurplePluginPref *
purple_plugin_pref_new_with_name_and_label(const char *name, const char *label)
{
	PurplePluginPref *pref;

	g_return_val_if_fail(name  != NULL, NULL);
	g_return_val_if_fail(label != NULL, NULL);

	pref = g_new0(PurplePluginPref, 1);
	pref->name = g_strdup(name);
	pref->label = g_strdup(label);

	return pref;
}

void
purple_plugin_pref_destroy(PurplePluginPref *pref)
{
	g_return_if_fail(pref != NULL);

	g_free(pref->name);
	g_free(pref->label);
	g_list_free(pref->choices);
	g_free(pref);
}

void
purple_plugin_pref_set_name(PurplePluginPref *pref, const char *name)
{
	g_return_if_fail(pref != NULL);
	g_return_if_fail(name != NULL);

	g_free(pref->name);
	pref->name = g_strdup(name);
}

const char *
purple_plugin_pref_get_name(PurplePluginPref *pref)
{
	g_return_val_if_fail(pref != NULL, NULL);

	return pref->name;
}

void
purple_plugin_pref_set_label(PurplePluginPref *pref, const char *label)
{
	g_return_if_fail(pref  != NULL);
	g_return_if_fail(label != NULL);

	g_free(pref->label);
	pref->label = g_strdup(label);
}

const char *
purple_plugin_pref_get_label(PurplePluginPref *pref)
{
	g_return_val_if_fail(pref != NULL, NULL);

	return pref->label;
}

void
purple_plugin_pref_set_bounds(PurplePluginPref *pref, int min, int max)
{
	int tmp;

	g_return_if_fail(pref       != NULL);
	g_return_if_fail(pref->name != NULL);

	if (purple_prefs_get_type(pref->name) != PURPLE_PREF_INT)
	{
		purple_debug_warning("pluginpref",
				"purple_plugin_pref_set_bounds: %s is not an integer pref\n",
				pref->name);
		return;
	}

	if (min > max)
	{
		tmp = min;
		min = max;
		max = tmp;
	}

	pref->min = min;
	pref->max = max;
}

void purple_plugin_pref_get_bounds(PurplePluginPref *pref, int *min, int *max)
{
	g_return_if_fail(pref       != NULL);
	g_return_if_fail(pref->name != NULL);

	if (purple_prefs_get_type(pref->name) != PURPLE_PREF_INT)
	{
		purple_debug_warning("pluginpref",
				"purple_plugin_pref_get_bounds: %s is not an integer pref\n",
				pref->name);
		return;
	}

	*min = pref->min;
	*max = pref->max;
}

void
purple_plugin_pref_set_type(PurplePluginPref *pref, PurplePluginPrefType type)
{
	g_return_if_fail(pref != NULL);

	pref->type = type;
}

PurplePluginPrefType
purple_plugin_pref_get_type(PurplePluginPref *pref)
{
	g_return_val_if_fail(pref != NULL, PURPLE_PLUGIN_PREF_NONE);

	return pref->type;
}

void
purple_plugin_pref_add_choice(PurplePluginPref *pref, const char *label, gpointer choice)
{
	g_return_if_fail(pref  != NULL);
	g_return_if_fail(label != NULL);
	g_return_if_fail(choice || purple_prefs_get_type(pref->name) == PURPLE_PREF_INT);

	pref->choices = g_list_append(pref->choices, (gpointer)label);
	pref->choices = g_list_append(pref->choices, choice);
}

GList *
purple_plugin_pref_get_choices(PurplePluginPref *pref)
{
	g_return_val_if_fail(pref != NULL, NULL);

	return pref->choices;
}

void
purple_plugin_pref_set_max_length(PurplePluginPref *pref, unsigned int max_length)
{
	g_return_if_fail(pref != NULL);

	pref->max_length = max_length;
}

unsigned int
purple_plugin_pref_get_max_length(PurplePluginPref *pref)
{
	g_return_val_if_fail(pref != NULL, 0);

	return pref->max_length;
}

void
purple_plugin_pref_set_masked(PurplePluginPref *pref, gboolean masked)
{
	g_return_if_fail(pref != NULL);

	pref->masked = masked;
}

gboolean
purple_plugin_pref_get_masked(PurplePluginPref *pref)
{
	g_return_val_if_fail(pref != NULL, FALSE);

	return pref->masked;
}

void
purple_plugin_pref_set_format_type(PurplePluginPref *pref, PurpleStringFormatType format)
{
	g_return_if_fail(pref != NULL);
	g_return_if_fail(pref->type == PURPLE_PLUGIN_PREF_STRING_FORMAT);

	pref->format = format;
}

PurpleStringFormatType
purple_plugin_pref_get_format_type(PurplePluginPref *pref)
{
	g_return_val_if_fail(pref != NULL, 0);

	if (pref->type != PURPLE_PLUGIN_PREF_STRING_FORMAT)
		return PURPLE_STRING_FORMAT_TYPE_NONE;

	return pref->format;
}

