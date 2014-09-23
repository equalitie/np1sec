/**
 * @file accountopt.c Account Options API
 * @ingroup core
 */

/* purple
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
#include "internal.h"

#include "accountopt.h"
#include "util.h"

PurpleAccountOption *
purple_account_option_new(PurplePrefType type, const char *text,
						const char *pref_name)
{
	PurpleAccountOption *option;

	g_return_val_if_fail(type      != PURPLE_PREF_NONE, NULL);
	g_return_val_if_fail(text      != NULL,           NULL);
	g_return_val_if_fail(pref_name != NULL,           NULL);

	option = g_new0(PurpleAccountOption, 1);

	option->type      = type;
	option->text      = g_strdup(text);
	option->pref_name = g_strdup(pref_name);

	return option;
}

PurpleAccountOption *
purple_account_option_bool_new(const char *text, const char *pref_name,
							 gboolean default_value)
{
	PurpleAccountOption *option;

	option = purple_account_option_new(PURPLE_PREF_BOOLEAN, text, pref_name);

	if (option == NULL)
		return NULL;

	option->default_value.boolean = default_value;

	return option;
}

PurpleAccountOption *
purple_account_option_int_new(const char *text, const char *pref_name,
							int default_value)
{
	PurpleAccountOption *option;

	option = purple_account_option_new(PURPLE_PREF_INT, text, pref_name);

	if (option == NULL)
		return NULL;

	option->default_value.integer = default_value;

	return option;
}

PurpleAccountOption *
purple_account_option_string_new(const char *text, const char *pref_name,
							   const char *default_value)
{
	PurpleAccountOption *option;

	option = purple_account_option_new(PURPLE_PREF_STRING, text, pref_name);

	if (option == NULL)
		return NULL;

	option->default_value.string = g_strdup(default_value);

	return option;
}

PurpleAccountOption *
purple_account_option_list_new(const char *text, const char *pref_name,
							 GList *list)
{
	PurpleAccountOption *option;

	option = purple_account_option_new(PURPLE_PREF_STRING_LIST, text, pref_name);

	if (option == NULL)
		return NULL;

	option->default_value.list = list;

	return option;
}

static void
purple_account_option_list_free(gpointer data, gpointer user_data)
{
	PurpleKeyValuePair *kvp = data;

	g_free(kvp->value);
	g_free(kvp->key);
	g_free(kvp);
}

void
purple_account_option_destroy(PurpleAccountOption *option)
{
	g_return_if_fail(option != NULL);

	g_free(option->text);
	g_free(option->pref_name);

	if (option->type == PURPLE_PREF_STRING)
	{
		g_free(option->default_value.string);
	}
	else if (option->type == PURPLE_PREF_STRING_LIST)
	{
		if (option->default_value.list != NULL)
		{
			g_list_foreach(option->default_value.list, purple_account_option_list_free, NULL);
			g_list_free(option->default_value.list);
		}
	}

	g_free(option);
}

void
purple_account_option_set_default_bool(PurpleAccountOption *option,
									 gboolean value)
{
	g_return_if_fail(option != NULL);
	g_return_if_fail(option->type == PURPLE_PREF_BOOLEAN);

	option->default_value.boolean = value;
}

void
purple_account_option_set_default_int(PurpleAccountOption *option, int value)
{
	g_return_if_fail(option != NULL);
	g_return_if_fail(option->type == PURPLE_PREF_INT);

	option->default_value.integer = value;
}

void
purple_account_option_set_default_string(PurpleAccountOption *option,
									   const char *value)
{
	g_return_if_fail(option != NULL);
	g_return_if_fail(option->type == PURPLE_PREF_STRING);

	g_free(option->default_value.string);
	option->default_value.string = g_strdup(value);
}

void
purple_account_option_set_masked(PurpleAccountOption *option, gboolean masked)
{
	g_return_if_fail(option != NULL);
	g_return_if_fail(option->type == PURPLE_PREF_STRING);

	option->masked = masked;
}


void
purple_account_option_set_list(PurpleAccountOption *option, GList *values)
{
	g_return_if_fail(option != NULL);
	g_return_if_fail(option->type == PURPLE_PREF_STRING_LIST);

	if (option->default_value.list != NULL)
	{
		g_list_foreach(option->default_value.list, purple_account_option_list_free, NULL);
		g_list_free(option->default_value.list);
	}

	option->default_value.list = values;
}

void
purple_account_option_add_list_item(PurpleAccountOption *option,
								  const char *key, const char *value)
{
	PurpleKeyValuePair *kvp;

	g_return_if_fail(option != NULL);
	g_return_if_fail(key    != NULL);
	g_return_if_fail(value  != NULL);
	g_return_if_fail(option->type == PURPLE_PREF_STRING_LIST);

	kvp = g_new0(PurpleKeyValuePair, 1);
	kvp->key = g_strdup(key);
	kvp->value = g_strdup(value);

	option->default_value.list = g_list_append(option->default_value.list,
											   kvp);
}

PurplePrefType
purple_account_option_get_type(const PurpleAccountOption *option)
{
	g_return_val_if_fail(option != NULL, PURPLE_PREF_NONE);

	return option->type;
}

const char *
purple_account_option_get_text(const PurpleAccountOption *option)
{
	g_return_val_if_fail(option != NULL, NULL);

	return option->text;
}

const char *
purple_account_option_get_setting(const PurpleAccountOption *option)
{
	g_return_val_if_fail(option != NULL, NULL);

	return option->pref_name;
}

gboolean
purple_account_option_get_default_bool(const PurpleAccountOption *option)
{
	g_return_val_if_fail(option != NULL, FALSE);
	g_return_val_if_fail(option->type == PURPLE_PREF_BOOLEAN, FALSE);

	return option->default_value.boolean;
}

int
purple_account_option_get_default_int(const PurpleAccountOption *option)
{
	g_return_val_if_fail(option != NULL, -1);
	g_return_val_if_fail(option->type == PURPLE_PREF_INT, -1);

	return option->default_value.integer;
}

const char *
purple_account_option_get_default_string(const PurpleAccountOption *option)
{
	g_return_val_if_fail(option != NULL, NULL);
	g_return_val_if_fail(option->type == PURPLE_PREF_STRING, NULL);

	return option->default_value.string;
}

const char *
purple_account_option_get_default_list_value(const PurpleAccountOption *option)
{
	PurpleKeyValuePair *kvp;

	g_return_val_if_fail(option != NULL, NULL);
	g_return_val_if_fail(option->type == PURPLE_PREF_STRING_LIST, NULL);

	if (option->default_value.list == NULL)
		return NULL;

	kvp = option->default_value.list->data;

	return (kvp ? kvp->value : NULL);
}

gboolean
purple_account_option_get_masked(const PurpleAccountOption *option)
{
	g_return_val_if_fail(option != NULL, FALSE);
	g_return_val_if_fail(option->type == PURPLE_PREF_STRING, FALSE);

	return option->masked;
}

GList *
purple_account_option_get_list(const PurpleAccountOption *option)
{
	g_return_val_if_fail(option != NULL, NULL);
	g_return_val_if_fail(option->type == PURPLE_PREF_STRING_LIST, NULL);

	return option->default_value.list;
}

/**************************************************************************
 * Account User Split API
 **************************************************************************/
PurpleAccountUserSplit *
purple_account_user_split_new(const char *text, const char *default_value,
							char sep)
{
	PurpleAccountUserSplit *split;

	g_return_val_if_fail(text != NULL, NULL);
	g_return_val_if_fail(sep != 0, NULL);

	split = g_new0(PurpleAccountUserSplit, 1);

	split->text = g_strdup(text);
	split->field_sep = sep;
	split->default_value = g_strdup(default_value);
	split->reverse = TRUE;

	return split;
}

void
purple_account_user_split_destroy(PurpleAccountUserSplit *split)
{
	g_return_if_fail(split != NULL);

	g_free(split->text);
	g_free(split->default_value);
	g_free(split);
}

const char *
purple_account_user_split_get_text(const PurpleAccountUserSplit *split)
{
	g_return_val_if_fail(split != NULL, NULL);

	return split->text;
}

const char *
purple_account_user_split_get_default_value(const PurpleAccountUserSplit *split)
{
	g_return_val_if_fail(split != NULL, NULL);

	return split->default_value;
}

char
purple_account_user_split_get_separator(const PurpleAccountUserSplit *split)
{
	g_return_val_if_fail(split != NULL, 0);

	return split->field_sep;
}

gboolean
purple_account_user_split_get_reverse(const PurpleAccountUserSplit *split)
{
	g_return_val_if_fail(split != NULL, FALSE);

	return split->reverse;
}

void
purple_account_user_split_set_reverse(PurpleAccountUserSplit *split, gboolean reverse)
{
	g_return_if_fail(split != NULL);

	split->reverse = reverse;
}
