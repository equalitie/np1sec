/**
 * @file request.c Request API
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
#define _PURPLE_REQUEST_C_

#include "internal.h"

#include "notify.h"
#include "request.h"
#include "debug.h"

static PurpleRequestUiOps *request_ui_ops = NULL;
static GList *handles = NULL;

typedef struct
{
	PurpleRequestType type;
	void *handle;
	void *ui_handle;

} PurpleRequestInfo;


PurpleRequestFields *
purple_request_fields_new(void)
{
	PurpleRequestFields *fields;

	fields = g_new0(PurpleRequestFields, 1);

	fields->fields = g_hash_table_new_full(g_str_hash, g_str_equal,
										   g_free, NULL);

	return fields;
}

void
purple_request_fields_destroy(PurpleRequestFields *fields)
{
	g_return_if_fail(fields != NULL);

	g_list_foreach(fields->groups, (GFunc)purple_request_field_group_destroy, NULL);
	g_list_free(fields->groups);
	g_list_free(fields->required_fields);
	g_hash_table_destroy(fields->fields);
	g_free(fields);
}

void
purple_request_fields_add_group(PurpleRequestFields *fields,
							  PurpleRequestFieldGroup *group)
{
	GList *l;
	PurpleRequestField *field;

	g_return_if_fail(fields != NULL);
	g_return_if_fail(group  != NULL);

	fields->groups = g_list_append(fields->groups, group);

	group->fields_list = fields;

	for (l = purple_request_field_group_get_fields(group);
		 l != NULL;
		 l = l->next) {

		field = l->data;

		g_hash_table_insert(fields->fields,
			g_strdup(purple_request_field_get_id(field)), field);

		if (purple_request_field_is_required(field)) {
			fields->required_fields =
				g_list_append(fields->required_fields, field);
		}

	}
}

GList *
purple_request_fields_get_groups(const PurpleRequestFields *fields)
{
	g_return_val_if_fail(fields != NULL, NULL);

	return fields->groups;
}

gboolean
purple_request_fields_exists(const PurpleRequestFields *fields, const char *id)
{
	g_return_val_if_fail(fields != NULL, FALSE);
	g_return_val_if_fail(id     != NULL, FALSE);

	return (g_hash_table_lookup(fields->fields, id) != NULL);
}

GList *
purple_request_fields_get_required(const PurpleRequestFields *fields)
{
	g_return_val_if_fail(fields != NULL, NULL);

	return fields->required_fields;
}

gboolean
purple_request_fields_is_field_required(const PurpleRequestFields *fields,
									  const char *id)
{
	PurpleRequestField *field;

	g_return_val_if_fail(fields != NULL, FALSE);
	g_return_val_if_fail(id     != NULL, FALSE);

	if ((field = purple_request_fields_get_field(fields, id)) == NULL)
		return FALSE;

	return purple_request_field_is_required(field);
}

gpointer
purple_request_field_get_ui_data(const PurpleRequestField *field)
{
	g_return_val_if_fail(field != NULL, NULL);

	return field->ui_data;
}

void
purple_request_field_set_ui_data(PurpleRequestField *field,
                                 gpointer ui_data)
{
	g_return_if_fail(field != NULL);

	field->ui_data = ui_data;
}

gboolean
purple_request_fields_all_required_filled(const PurpleRequestFields *fields)
{
	GList *l;

	g_return_val_if_fail(fields != NULL, FALSE);

	for (l = fields->required_fields; l != NULL; l = l->next)
	{
		PurpleRequestField *field = (PurpleRequestField *)l->data;

		switch (purple_request_field_get_type(field))
		{
			case PURPLE_REQUEST_FIELD_STRING:
				if (purple_request_field_string_get_value(field) == NULL ||
				    *(purple_request_field_string_get_value(field)) == '\0')
					return FALSE;

				break;

			default:
				break;
		}
	}

	return TRUE;
}

PurpleRequestField *
purple_request_fields_get_field(const PurpleRequestFields *fields, const char *id)
{
	PurpleRequestField *field;

	g_return_val_if_fail(fields != NULL, NULL);
	g_return_val_if_fail(id     != NULL, NULL);

	field = g_hash_table_lookup(fields->fields, id);

	g_return_val_if_fail(field != NULL, NULL);

	return field;
}

const char *
purple_request_fields_get_string(const PurpleRequestFields *fields, const char *id)
{
	PurpleRequestField *field;

	g_return_val_if_fail(fields != NULL, NULL);
	g_return_val_if_fail(id     != NULL, NULL);

	if ((field = purple_request_fields_get_field(fields, id)) == NULL)
		return NULL;

	return purple_request_field_string_get_value(field);
}

int
purple_request_fields_get_integer(const PurpleRequestFields *fields,
								const char *id)
{
	PurpleRequestField *field;

	g_return_val_if_fail(fields != NULL, 0);
	g_return_val_if_fail(id     != NULL, 0);

	if ((field = purple_request_fields_get_field(fields, id)) == NULL)
		return 0;

	return purple_request_field_int_get_value(field);
}

gboolean
purple_request_fields_get_bool(const PurpleRequestFields *fields, const char *id)
{
	PurpleRequestField *field;

	g_return_val_if_fail(fields != NULL, FALSE);
	g_return_val_if_fail(id     != NULL, FALSE);

	if ((field = purple_request_fields_get_field(fields, id)) == NULL)
		return FALSE;

	return purple_request_field_bool_get_value(field);
}

int
purple_request_fields_get_choice(const PurpleRequestFields *fields, const char *id)
{
	PurpleRequestField *field;

	g_return_val_if_fail(fields != NULL, -1);
	g_return_val_if_fail(id     != NULL, -1);

	if ((field = purple_request_fields_get_field(fields, id)) == NULL)
		return -1;

	return purple_request_field_choice_get_value(field);
}

PurpleAccount *
purple_request_fields_get_account(const PurpleRequestFields *fields,
								const char *id)
{
	PurpleRequestField *field;

	g_return_val_if_fail(fields != NULL, NULL);
	g_return_val_if_fail(id     != NULL, NULL);

	if ((field = purple_request_fields_get_field(fields, id)) == NULL)
		return NULL;

	return purple_request_field_account_get_value(field);
}

PurpleRequestFieldGroup *
purple_request_field_group_new(const char *title)
{
	PurpleRequestFieldGroup *group;

	group = g_new0(PurpleRequestFieldGroup, 1);

	group->title = g_strdup(title);

	return group;
}

void
purple_request_field_group_destroy(PurpleRequestFieldGroup *group)
{
	g_return_if_fail(group != NULL);

	g_free(group->title);

	g_list_foreach(group->fields, (GFunc)purple_request_field_destroy, NULL);
	g_list_free(group->fields);

	g_free(group);
}

void
purple_request_field_group_add_field(PurpleRequestFieldGroup *group,
								   PurpleRequestField *field)
{
	g_return_if_fail(group != NULL);
	g_return_if_fail(field != NULL);

	group->fields = g_list_append(group->fields, field);

	if (group->fields_list != NULL)
	{
		g_hash_table_insert(group->fields_list->fields,
							g_strdup(purple_request_field_get_id(field)), field);

		if (purple_request_field_is_required(field))
		{
			group->fields_list->required_fields =
				g_list_append(group->fields_list->required_fields, field);
		}
	}

	field->group = group;

}

const char *
purple_request_field_group_get_title(const PurpleRequestFieldGroup *group)
{
	g_return_val_if_fail(group != NULL, NULL);

	return group->title;
}

GList *
purple_request_field_group_get_fields(const PurpleRequestFieldGroup *group)
{
	g_return_val_if_fail(group != NULL, NULL);

	return group->fields;
}

PurpleRequestField *
purple_request_field_new(const char *id, const char *text,
					   PurpleRequestFieldType type)
{
	PurpleRequestField *field;

	g_return_val_if_fail(id   != NULL, NULL);
	g_return_val_if_fail(type != PURPLE_REQUEST_FIELD_NONE, NULL);

	field = g_new0(PurpleRequestField, 1);

	field->id   = g_strdup(id);
	field->type = type;

	purple_request_field_set_label(field, text);
	purple_request_field_set_visible(field, TRUE);

	return field;
}

void
purple_request_field_destroy(PurpleRequestField *field)
{
	g_return_if_fail(field != NULL);

	g_free(field->id);
	g_free(field->label);
	g_free(field->type_hint);

	if (field->type == PURPLE_REQUEST_FIELD_STRING)
	{
		g_free(field->u.string.default_value);
		g_free(field->u.string.value);
	}
	else if (field->type == PURPLE_REQUEST_FIELD_CHOICE)
	{
		if (field->u.choice.labels != NULL)
		{
			g_list_foreach(field->u.choice.labels, (GFunc)g_free, NULL);
			g_list_free(field->u.choice.labels);
		}
	}
	else if (field->type == PURPLE_REQUEST_FIELD_LIST)
	{
		if (field->u.list.items != NULL)
		{
			g_list_foreach(field->u.list.items, (GFunc)g_free, NULL);
			g_list_free(field->u.list.items);
		}

		if (field->u.list.selected != NULL)
		{
			g_list_foreach(field->u.list.selected, (GFunc)g_free, NULL);
			g_list_free(field->u.list.selected);
		}

		g_hash_table_destroy(field->u.list.item_data);
		g_hash_table_destroy(field->u.list.selected_table);
	}

	g_free(field);
}

void
purple_request_field_set_label(PurpleRequestField *field, const char *label)
{
	g_return_if_fail(field != NULL);

	g_free(field->label);
	field->label = g_strdup(label);
}

void
purple_request_field_set_visible(PurpleRequestField *field, gboolean visible)
{
	g_return_if_fail(field != NULL);

	field->visible = visible;
}

void
purple_request_field_set_type_hint(PurpleRequestField *field,
								 const char *type_hint)
{
	g_return_if_fail(field != NULL);

	g_free(field->type_hint);
	field->type_hint = g_strdup(type_hint);
}

void
purple_request_field_set_required(PurpleRequestField *field, gboolean required)
{
	g_return_if_fail(field != NULL);

	if (field->required == required)
		return;

	field->required = required;

	if (field->group != NULL)
	{
		if (required)
		{
			field->group->fields_list->required_fields =
				g_list_append(field->group->fields_list->required_fields,
							  field);
		}
		else
		{
			field->group->fields_list->required_fields =
				g_list_remove(field->group->fields_list->required_fields,
							  field);
		}
	}
}

PurpleRequestFieldType
purple_request_field_get_type(const PurpleRequestField *field)
{
	g_return_val_if_fail(field != NULL, PURPLE_REQUEST_FIELD_NONE);

	return field->type;
}

PurpleRequestFieldGroup *
purple_request_field_get_group(const PurpleRequestField *field)
{
	g_return_val_if_fail(field != NULL, NULL);

	return field->group;
}

const char *
purple_request_field_get_id(const PurpleRequestField *field)
{
	g_return_val_if_fail(field != NULL, NULL);

	return field->id;
}

const char *
purple_request_field_get_label(const PurpleRequestField *field)
{
	g_return_val_if_fail(field != NULL, NULL);

	return field->label;
}

gboolean
purple_request_field_is_visible(const PurpleRequestField *field)
{
	g_return_val_if_fail(field != NULL, FALSE);

	return field->visible;
}

const char *
purple_request_field_get_type_hint(const PurpleRequestField *field)
{
	g_return_val_if_fail(field != NULL, NULL);

	return field->type_hint;
}

gboolean
purple_request_field_is_required(const PurpleRequestField *field)
{
	g_return_val_if_fail(field != NULL, FALSE);

	return field->required;
}

PurpleRequestField *
purple_request_field_string_new(const char *id, const char *text,
							  const char *default_value, gboolean multiline)
{
	PurpleRequestField *field;

	g_return_val_if_fail(id   != NULL, NULL);
	g_return_val_if_fail(text != NULL, NULL);

	field = purple_request_field_new(id, text, PURPLE_REQUEST_FIELD_STRING);

	field->u.string.multiline = multiline;
	field->u.string.editable  = TRUE;

	purple_request_field_string_set_default_value(field, default_value);
	purple_request_field_string_set_value(field, default_value);

	return field;
}

void
purple_request_field_string_set_default_value(PurpleRequestField *field,
											const char *default_value)
{
	g_return_if_fail(field != NULL);
	g_return_if_fail(field->type == PURPLE_REQUEST_FIELD_STRING);

	g_free(field->u.string.default_value);
	field->u.string.default_value = g_strdup(default_value);
}

void
purple_request_field_string_set_value(PurpleRequestField *field, const char *value)
{
	g_return_if_fail(field != NULL);
	g_return_if_fail(field->type == PURPLE_REQUEST_FIELD_STRING);

	g_free(field->u.string.value);
	field->u.string.value = g_strdup(value);
}

void
purple_request_field_string_set_masked(PurpleRequestField *field, gboolean masked)
{
	g_return_if_fail(field != NULL);
	g_return_if_fail(field->type == PURPLE_REQUEST_FIELD_STRING);

	field->u.string.masked = masked;
}

void
purple_request_field_string_set_editable(PurpleRequestField *field,
									   gboolean editable)
{
	g_return_if_fail(field != NULL);
	g_return_if_fail(field->type == PURPLE_REQUEST_FIELD_STRING);

	field->u.string.editable = editable;
}

const char *
purple_request_field_string_get_default_value(const PurpleRequestField *field)
{
	g_return_val_if_fail(field != NULL, NULL);
	g_return_val_if_fail(field->type == PURPLE_REQUEST_FIELD_STRING, NULL);

	return field->u.string.default_value;
}

const char *
purple_request_field_string_get_value(const PurpleRequestField *field)
{
	g_return_val_if_fail(field != NULL, NULL);
	g_return_val_if_fail(field->type == PURPLE_REQUEST_FIELD_STRING, NULL);

	return field->u.string.value;
}

gboolean
purple_request_field_string_is_multiline(const PurpleRequestField *field)
{
	g_return_val_if_fail(field != NULL, FALSE);
	g_return_val_if_fail(field->type == PURPLE_REQUEST_FIELD_STRING, FALSE);

	return field->u.string.multiline;
}

gboolean
purple_request_field_string_is_masked(const PurpleRequestField *field)
{
	g_return_val_if_fail(field != NULL, FALSE);
	g_return_val_if_fail(field->type == PURPLE_REQUEST_FIELD_STRING, FALSE);

	return field->u.string.masked;
}

gboolean
purple_request_field_string_is_editable(const PurpleRequestField *field)
{
	g_return_val_if_fail(field != NULL, FALSE);
	g_return_val_if_fail(field->type == PURPLE_REQUEST_FIELD_STRING, FALSE);

	return field->u.string.editable;
}

PurpleRequestField *
purple_request_field_int_new(const char *id, const char *text,
						   int default_value)
{
	PurpleRequestField *field;

	g_return_val_if_fail(id   != NULL, NULL);
	g_return_val_if_fail(text != NULL, NULL);

	field = purple_request_field_new(id, text, PURPLE_REQUEST_FIELD_INTEGER);

	purple_request_field_int_set_default_value(field, default_value);
	purple_request_field_int_set_value(field, default_value);

	return field;
}

void
purple_request_field_int_set_default_value(PurpleRequestField *field,
										 int default_value)
{
	g_return_if_fail(field != NULL);
	g_return_if_fail(field->type == PURPLE_REQUEST_FIELD_INTEGER);

	field->u.integer.default_value = default_value;
}

void
purple_request_field_int_set_value(PurpleRequestField *field, int value)
{
	g_return_if_fail(field != NULL);
	g_return_if_fail(field->type == PURPLE_REQUEST_FIELD_INTEGER);

	field->u.integer.value = value;
}

int
purple_request_field_int_get_default_value(const PurpleRequestField *field)
{
	g_return_val_if_fail(field != NULL, 0);
	g_return_val_if_fail(field->type == PURPLE_REQUEST_FIELD_INTEGER, 0);

	return field->u.integer.default_value;
}

int
purple_request_field_int_get_value(const PurpleRequestField *field)
{
	g_return_val_if_fail(field != NULL, 0);
	g_return_val_if_fail(field->type == PURPLE_REQUEST_FIELD_INTEGER, 0);

	return field->u.integer.value;
}

PurpleRequestField *
purple_request_field_bool_new(const char *id, const char *text,
							gboolean default_value)
{
	PurpleRequestField *field;

	g_return_val_if_fail(id   != NULL, NULL);
	g_return_val_if_fail(text != NULL, NULL);

	field = purple_request_field_new(id, text, PURPLE_REQUEST_FIELD_BOOLEAN);

	purple_request_field_bool_set_default_value(field, default_value);
	purple_request_field_bool_set_value(field, default_value);

	return field;
}

void
purple_request_field_bool_set_default_value(PurpleRequestField *field,
										  gboolean default_value)
{
	g_return_if_fail(field != NULL);
	g_return_if_fail(field->type == PURPLE_REQUEST_FIELD_BOOLEAN);

	field->u.boolean.default_value = default_value;
}

void
purple_request_field_bool_set_value(PurpleRequestField *field, gboolean value)
{
	g_return_if_fail(field != NULL);
	g_return_if_fail(field->type == PURPLE_REQUEST_FIELD_BOOLEAN);

	field->u.boolean.value = value;
}

gboolean
purple_request_field_bool_get_default_value(const PurpleRequestField *field)
{
	g_return_val_if_fail(field != NULL, FALSE);
	g_return_val_if_fail(field->type == PURPLE_REQUEST_FIELD_BOOLEAN, FALSE);

	return field->u.boolean.default_value;
}

gboolean
purple_request_field_bool_get_value(const PurpleRequestField *field)
{
	g_return_val_if_fail(field != NULL, FALSE);
	g_return_val_if_fail(field->type == PURPLE_REQUEST_FIELD_BOOLEAN, FALSE);

	return field->u.boolean.value;
}

PurpleRequestField *
purple_request_field_choice_new(const char *id, const char *text,
							  int default_value)
{
	PurpleRequestField *field;

	g_return_val_if_fail(id   != NULL, NULL);
	g_return_val_if_fail(text != NULL, NULL);

	field = purple_request_field_new(id, text, PURPLE_REQUEST_FIELD_CHOICE);

	purple_request_field_choice_set_default_value(field, default_value);
	purple_request_field_choice_set_value(field, default_value);

	return field;
}

void
purple_request_field_choice_add(PurpleRequestField *field, const char *label)
{
	g_return_if_fail(field != NULL);
	g_return_if_fail(label != NULL);
	g_return_if_fail(field->type == PURPLE_REQUEST_FIELD_CHOICE);

	field->u.choice.labels = g_list_append(field->u.choice.labels,
											g_strdup(label));
}

void
purple_request_field_choice_set_default_value(PurpleRequestField *field,
											int default_value)
{
	g_return_if_fail(field != NULL);
	g_return_if_fail(field->type == PURPLE_REQUEST_FIELD_CHOICE);

	field->u.choice.default_value = default_value;
}

void
purple_request_field_choice_set_value(PurpleRequestField *field,
											int value)
{
	g_return_if_fail(field != NULL);
	g_return_if_fail(field->type == PURPLE_REQUEST_FIELD_CHOICE);

	field->u.choice.value = value;
}

int
purple_request_field_choice_get_default_value(const PurpleRequestField *field)
{
	g_return_val_if_fail(field != NULL, -1);
	g_return_val_if_fail(field->type == PURPLE_REQUEST_FIELD_CHOICE, -1);

	return field->u.choice.default_value;
}

int
purple_request_field_choice_get_value(const PurpleRequestField *field)
{
	g_return_val_if_fail(field != NULL, -1);
	g_return_val_if_fail(field->type == PURPLE_REQUEST_FIELD_CHOICE, -1);

	return field->u.choice.value;
}

GList *
purple_request_field_choice_get_labels(const PurpleRequestField *field)
{
	g_return_val_if_fail(field != NULL, NULL);
	g_return_val_if_fail(field->type == PURPLE_REQUEST_FIELD_CHOICE, NULL);

	return field->u.choice.labels;
}

PurpleRequestField *
purple_request_field_list_new(const char *id, const char *text)
{
	PurpleRequestField *field;

	g_return_val_if_fail(id   != NULL, NULL);

	field = purple_request_field_new(id, text, PURPLE_REQUEST_FIELD_LIST);

	field->u.list.item_data = g_hash_table_new_full(g_str_hash, g_str_equal,
													g_free, NULL);

	field->u.list.selected_table =
		g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);

	return field;
}

void
purple_request_field_list_set_multi_select(PurpleRequestField *field,
										 gboolean multi_select)
{
	g_return_if_fail(field != NULL);
	g_return_if_fail(field->type == PURPLE_REQUEST_FIELD_LIST);

	field->u.list.multiple_selection = multi_select;
}

gboolean
purple_request_field_list_get_multi_select(const PurpleRequestField *field)
{
	g_return_val_if_fail(field != NULL, FALSE);
	g_return_val_if_fail(field->type == PURPLE_REQUEST_FIELD_LIST, FALSE);

	return field->u.list.multiple_selection;
}

void *
purple_request_field_list_get_data(const PurpleRequestField *field,
								 const char *text)
{
	g_return_val_if_fail(field != NULL, NULL);
	g_return_val_if_fail(text  != NULL, NULL);
	g_return_val_if_fail(field->type == PURPLE_REQUEST_FIELD_LIST, NULL);

	return g_hash_table_lookup(field->u.list.item_data, text);
}

void
purple_request_field_list_add(PurpleRequestField *field, const char *item,
							void *data)
{
	purple_request_field_list_add_icon(field, item, NULL, data);
}

void
purple_request_field_list_add_icon(PurpleRequestField *field, const char *item, const char* icon_path,
							void *data)
{
	g_return_if_fail(field != NULL);
	g_return_if_fail(item  != NULL);
	g_return_if_fail(data  != NULL);
	g_return_if_fail(field->type == PURPLE_REQUEST_FIELD_LIST);

	if (icon_path)
	{
		if (field->u.list.icons == NULL)
		{
			GList *l;
			for (l = field->u.list.items ; l != NULL ; l = l->next)
			{
				/* Order doesn't matter, because we're just
				 * filing in blank items.  So, we use
				 * g_list_prepend() because it's faster. */
				field->u.list.icons = g_list_prepend(field->u.list.icons, NULL);
			}
		}
		field->u.list.icons = g_list_append(field->u.list.icons, g_strdup(icon_path));
	}
	else if (field->u.list.icons)
	{
		/* Keep this even with the items list. */
		field->u.list.icons = g_list_append(field->u.list.icons, NULL);
	}

	field->u.list.items = g_list_append(field->u.list.items, g_strdup(item));
	g_hash_table_insert(field->u.list.item_data, g_strdup(item), data);
}

void
purple_request_field_list_add_selected(PurpleRequestField *field, const char *item)
{
	g_return_if_fail(field != NULL);
	g_return_if_fail(item  != NULL);
	g_return_if_fail(field->type == PURPLE_REQUEST_FIELD_LIST);

	if (!purple_request_field_list_get_multi_select(field) &&
		field->u.list.selected != NULL)
	{
		purple_debug_warning("request",
						   "More than one item added to non-multi-select "
						   "field %s\n",
						   purple_request_field_get_id(field));
		return;
	}

	field->u.list.selected = g_list_append(field->u.list.selected,
										   g_strdup(item));

	g_hash_table_insert(field->u.list.selected_table, g_strdup(item), NULL);
}

void
purple_request_field_list_clear_selected(PurpleRequestField *field)
{
	g_return_if_fail(field != NULL);
	g_return_if_fail(field->type == PURPLE_REQUEST_FIELD_LIST);

	if (field->u.list.selected != NULL)
	{
		g_list_foreach(field->u.list.selected, (GFunc)g_free, NULL);
		g_list_free(field->u.list.selected);
		field->u.list.selected = NULL;
	}

	g_hash_table_destroy(field->u.list.selected_table);

	field->u.list.selected_table =
		g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
}

void
purple_request_field_list_set_selected(PurpleRequestField *field, GList *items)
{
	GList *l;

	g_return_if_fail(field != NULL);
	g_return_if_fail(items != NULL);
	g_return_if_fail(field->type == PURPLE_REQUEST_FIELD_LIST);

	purple_request_field_list_clear_selected(field);

	if (!purple_request_field_list_get_multi_select(field) &&
		items && items->next)
	{
		purple_debug_warning("request",
						   "More than one item added to non-multi-select "
						   "field %s\n",
						   purple_request_field_get_id(field));
		return;
	}

	for (l = items; l != NULL; l = l->next)
	{
		field->u.list.selected = g_list_append(field->u.list.selected,
					g_strdup(l->data));
		g_hash_table_insert(field->u.list.selected_table,
							g_strdup((char *)l->data), NULL);
	}
}

gboolean
purple_request_field_list_is_selected(const PurpleRequestField *field,
									const char *item)
{
	g_return_val_if_fail(field != NULL, FALSE);
	g_return_val_if_fail(item  != NULL, FALSE);
	g_return_val_if_fail(field->type == PURPLE_REQUEST_FIELD_LIST, FALSE);

	return g_hash_table_lookup_extended(field->u.list.selected_table,
										item, NULL, NULL);
}

GList *
purple_request_field_list_get_selected(const PurpleRequestField *field)
{
	g_return_val_if_fail(field != NULL, NULL);
	g_return_val_if_fail(field->type == PURPLE_REQUEST_FIELD_LIST, NULL);

	return field->u.list.selected;
}

GList *
purple_request_field_list_get_items(const PurpleRequestField *field)
{
	g_return_val_if_fail(field != NULL, NULL);
	g_return_val_if_fail(field->type == PURPLE_REQUEST_FIELD_LIST, NULL);

	return field->u.list.items;
}

GList *
purple_request_field_list_get_icons(const PurpleRequestField *field)
{
	g_return_val_if_fail(field != NULL, NULL);
	g_return_val_if_fail(field->type == PURPLE_REQUEST_FIELD_LIST, NULL);

	return field->u.list.icons;
}

PurpleRequestField *
purple_request_field_label_new(const char *id, const char *text)
{
	PurpleRequestField *field;

	g_return_val_if_fail(id   != NULL, NULL);
	g_return_val_if_fail(text != NULL, NULL);

	field = purple_request_field_new(id, text, PURPLE_REQUEST_FIELD_LABEL);

	return field;
}

PurpleRequestField *
purple_request_field_image_new(const char *id, const char *text, const char *buf, gsize size)
{
	PurpleRequestField *field;

	g_return_val_if_fail(id   != NULL, NULL);
	g_return_val_if_fail(text != NULL, NULL);
	g_return_val_if_fail(buf  != NULL, NULL);
	g_return_val_if_fail(size > 0, NULL);

	field = purple_request_field_new(id, text, PURPLE_REQUEST_FIELD_IMAGE);

	field->u.image.buffer  = g_memdup(buf, size);
	field->u.image.size    = size;
	field->u.image.scale_x = 1;
	field->u.image.scale_y = 1;

	return field;
}

void
purple_request_field_image_set_scale(PurpleRequestField *field, unsigned int x, unsigned int y)
{
	g_return_if_fail(field != NULL);
	g_return_if_fail(field->type == PURPLE_REQUEST_FIELD_IMAGE);

	field->u.image.scale_x = x;
	field->u.image.scale_y = y;
}

const char *
purple_request_field_image_get_buffer(PurpleRequestField *field)
{
	g_return_val_if_fail(field != NULL, NULL);
	g_return_val_if_fail(field->type == PURPLE_REQUEST_FIELD_IMAGE, NULL);

	return field->u.image.buffer;
}

gsize
purple_request_field_image_get_size(PurpleRequestField *field)
{
	g_return_val_if_fail(field != NULL, 0);
	g_return_val_if_fail(field->type == PURPLE_REQUEST_FIELD_IMAGE, 0);

	return field->u.image.size;
}

unsigned int
purple_request_field_image_get_scale_x(PurpleRequestField *field)
{
	g_return_val_if_fail(field != NULL, 0);
	g_return_val_if_fail(field->type == PURPLE_REQUEST_FIELD_IMAGE, 0);

	return field->u.image.scale_x;
}

unsigned int
purple_request_field_image_get_scale_y(PurpleRequestField *field)
{
	g_return_val_if_fail(field != NULL, 0);
	g_return_val_if_fail(field->type == PURPLE_REQUEST_FIELD_IMAGE, 0);

	return field->u.image.scale_y;
}

PurpleRequestField *
purple_request_field_account_new(const char *id, const char *text,
							   PurpleAccount *account)
{
	PurpleRequestField *field;

	g_return_val_if_fail(id   != NULL, NULL);
	g_return_val_if_fail(text != NULL, NULL);

	field = purple_request_field_new(id, text, PURPLE_REQUEST_FIELD_ACCOUNT);

	if (account == NULL && purple_connections_get_all() != NULL)
	{
		account = purple_connection_get_account(
			(PurpleConnection *)purple_connections_get_all()->data);
	}

	purple_request_field_account_set_default_value(field, account);
	purple_request_field_account_set_value(field, account);

	return field;
}

void
purple_request_field_account_set_default_value(PurpleRequestField *field,
											 PurpleAccount *default_value)
{
	g_return_if_fail(field != NULL);
	g_return_if_fail(field->type == PURPLE_REQUEST_FIELD_ACCOUNT);

	field->u.account.default_account = default_value;
}

void
purple_request_field_account_set_value(PurpleRequestField *field,
									 PurpleAccount *value)
{
	g_return_if_fail(field != NULL);
	g_return_if_fail(field->type == PURPLE_REQUEST_FIELD_ACCOUNT);

	field->u.account.account = value;
}

void
purple_request_field_account_set_show_all(PurpleRequestField *field,
										gboolean show_all)
{
	g_return_if_fail(field != NULL);
	g_return_if_fail(field->type == PURPLE_REQUEST_FIELD_ACCOUNT);

	if (field->u.account.show_all == show_all)
		return;

	field->u.account.show_all = show_all;

	if (!show_all)
	{
		if (purple_account_is_connected(field->u.account.default_account))
		{
			purple_request_field_account_set_default_value(field,
				(PurpleAccount *)purple_connections_get_all()->data);
		}

		if (purple_account_is_connected(field->u.account.account))
		{
			purple_request_field_account_set_value(field,
				(PurpleAccount *)purple_connections_get_all()->data);
		}
	}
}

void
purple_request_field_account_set_filter(PurpleRequestField *field,
									  PurpleFilterAccountFunc filter_func)
{
	g_return_if_fail(field != NULL);
	g_return_if_fail(field->type == PURPLE_REQUEST_FIELD_ACCOUNT);

	field->u.account.filter_func = filter_func;
}

PurpleAccount *
purple_request_field_account_get_default_value(const PurpleRequestField *field)
{
	g_return_val_if_fail(field != NULL, NULL);
	g_return_val_if_fail(field->type == PURPLE_REQUEST_FIELD_ACCOUNT, NULL);

	return field->u.account.default_account;
}

PurpleAccount *
purple_request_field_account_get_value(const PurpleRequestField *field)
{
	g_return_val_if_fail(field != NULL, NULL);
	g_return_val_if_fail(field->type == PURPLE_REQUEST_FIELD_ACCOUNT, NULL);

	return field->u.account.account;
}

gboolean
purple_request_field_account_get_show_all(const PurpleRequestField *field)
{
	g_return_val_if_fail(field != NULL, FALSE);
	g_return_val_if_fail(field->type == PURPLE_REQUEST_FIELD_ACCOUNT, FALSE);

	return field->u.account.show_all;
}

PurpleFilterAccountFunc
purple_request_field_account_get_filter(const PurpleRequestField *field)
{
	g_return_val_if_fail(field != NULL, FALSE);
	g_return_val_if_fail(field->type == PURPLE_REQUEST_FIELD_ACCOUNT, FALSE);

	return field->u.account.filter_func;
}

/* -- */

void *
purple_request_input(void *handle, const char *title, const char *primary,
				   const char *secondary, const char *default_value,
				   gboolean multiline, gboolean masked, gchar *hint,
				   const char *ok_text, GCallback ok_cb,
				   const char *cancel_text, GCallback cancel_cb,
				   PurpleAccount *account, const char *who, PurpleConversation *conv,
				   void *user_data)
{
	PurpleRequestUiOps *ops;

	g_return_val_if_fail(ok_text != NULL, NULL);
	g_return_val_if_fail(ok_cb   != NULL, NULL);

	ops = purple_request_get_ui_ops();

	if (ops != NULL && ops->request_input != NULL) {
		PurpleRequestInfo *info;

		info            = g_new0(PurpleRequestInfo, 1);
		info->type      = PURPLE_REQUEST_INPUT;
		info->handle    = handle;
		info->ui_handle = ops->request_input(title, primary, secondary,
											 default_value,
											 multiline, masked, hint,
											 ok_text, ok_cb,
											 cancel_text, cancel_cb,
											 account, who, conv,
											 user_data);

		handles = g_list_append(handles, info);

		return info->ui_handle;
	}

	return NULL;
}

void *
purple_request_choice(void *handle, const char *title, const char *primary,
					const char *secondary, int default_value,
					const char *ok_text, GCallback ok_cb,
					const char *cancel_text, GCallback cancel_cb,
					PurpleAccount *account, const char *who, PurpleConversation *conv,
					void *user_data, ...)
{
	void *ui_handle;
	va_list args;

	g_return_val_if_fail(ok_text != NULL,  NULL);
	g_return_val_if_fail(ok_cb   != NULL,  NULL);

	va_start(args, user_data);
	ui_handle = purple_request_choice_varg(handle, title, primary, secondary,
					     default_value, ok_text, ok_cb,
					     cancel_text, cancel_cb,
					     account, who, conv, user_data, args);
	va_end(args);

	return ui_handle;
}

void *
purple_request_choice_varg(void *handle, const char *title,
			 const char *primary, const char *secondary,
			 int default_value,
			 const char *ok_text, GCallback ok_cb,
			 const char *cancel_text, GCallback cancel_cb,
			 PurpleAccount *account, const char *who, PurpleConversation *conv,
			 void *user_data, va_list choices)
{
	PurpleRequestUiOps *ops;

	g_return_val_if_fail(ok_text != NULL,  NULL);
	g_return_val_if_fail(ok_cb   != NULL,  NULL);
	g_return_val_if_fail(cancel_text != NULL,  NULL);

	ops = purple_request_get_ui_ops();

	if (ops != NULL && ops->request_choice != NULL) {
		PurpleRequestInfo *info;

		info            = g_new0(PurpleRequestInfo, 1);
		info->type      = PURPLE_REQUEST_CHOICE;
		info->handle    = handle;
		info->ui_handle = ops->request_choice(title, primary, secondary,
						      default_value,
						      ok_text, ok_cb,
						      cancel_text, cancel_cb,
							  account, who, conv,
						      user_data, choices);

		handles = g_list_append(handles, info);

		return info->ui_handle;
	}

	return NULL;
}

void *
purple_request_action(void *handle, const char *title, const char *primary,
					const char *secondary, int default_action,
					PurpleAccount *account, const char *who, PurpleConversation *conv,
					void *user_data, size_t action_count, ...)
{
	void *ui_handle;
	va_list args;

	g_return_val_if_fail(action_count > 0, NULL);

	va_start(args, action_count);
	ui_handle = purple_request_action_varg(handle, title, primary, secondary,
										 default_action, account, who, conv,
										 user_data, action_count, args);
	va_end(args);

	return ui_handle;
}

void *
purple_request_action_with_icon(void *handle, const char *title,
					const char *primary,
					const char *secondary, int default_action,
					PurpleAccount *account, const char *who,
					PurpleConversation *conv, gconstpointer icon_data,
					gsize icon_size, void *user_data, size_t action_count, ...)
{
	void *ui_handle;
	va_list args;

	g_return_val_if_fail(action_count > 0, NULL);

	va_start(args, action_count);
	ui_handle = purple_request_action_with_icon_varg(handle, title, primary,
		secondary, default_action, account, who, conv, icon_data, icon_size,
		user_data, action_count, args);
	va_end(args);

	return ui_handle;
}


void *
purple_request_action_varg(void *handle, const char *title,
						 const char *primary, const char *secondary,
						 int default_action,
						 PurpleAccount *account, const char *who, PurpleConversation *conv,
						  void *user_data, size_t action_count, va_list actions)
{
	PurpleRequestUiOps *ops;

	g_return_val_if_fail(action_count > 0, NULL);

	ops = purple_request_get_ui_ops();

	if (ops != NULL && ops->request_action != NULL) {
		PurpleRequestInfo *info;

		info            = g_new0(PurpleRequestInfo, 1);
		info->type      = PURPLE_REQUEST_ACTION;
		info->handle    = handle;
		info->ui_handle = ops->request_action(title, primary, secondary,
											  default_action, account, who, conv,
											  user_data, action_count, actions);

		handles = g_list_append(handles, info);

		return info->ui_handle;
	}

	return NULL;
}

void *
purple_request_action_with_icon_varg(void *handle, const char *title,
						 const char *primary, const char *secondary,
						 int default_action,
						 PurpleAccount *account, const char *who,
						 PurpleConversation *conv, gconstpointer icon_data,
						 gsize icon_size,
						 void *user_data, size_t action_count, va_list actions)
{
	PurpleRequestUiOps *ops;

	g_return_val_if_fail(action_count > 0, NULL);

	ops = purple_request_get_ui_ops();

	if (ops != NULL && ops->request_action_with_icon != NULL) {
		PurpleRequestInfo *info;

		info            = g_new0(PurpleRequestInfo, 1);
		info->type      = PURPLE_REQUEST_ACTION;
		info->handle    = handle;
		info->ui_handle = ops->request_action_with_icon(title, primary, secondary,
											  default_action, account, who, conv,
											  icon_data, icon_size,
											  user_data, action_count, actions);

		handles = g_list_append(handles, info);

		return info->ui_handle;
	} else {
		/* Fall back on the non-icon request if the UI doesn't support icon
		 requests */
		return purple_request_action_varg(handle, title, primary, secondary,
			default_action, account, who, conv, user_data, action_count, actions);
	}

	return NULL;
}


void *
purple_request_fields(void *handle, const char *title, const char *primary,
					const char *secondary, PurpleRequestFields *fields,
					const char *ok_text, GCallback ok_cb,
					const char *cancel_text, GCallback cancel_cb,
					PurpleAccount *account, const char *who, PurpleConversation *conv,
					void *user_data)
{
	PurpleRequestUiOps *ops;

	g_return_val_if_fail(fields  != NULL, NULL);
	g_return_val_if_fail(ok_text != NULL, NULL);
	g_return_val_if_fail(ok_cb   != NULL, NULL);
	g_return_val_if_fail(cancel_text != NULL, NULL);

	ops = purple_request_get_ui_ops();

	if (ops != NULL && ops->request_fields != NULL) {
		PurpleRequestInfo *info;

		info            = g_new0(PurpleRequestInfo, 1);
		info->type      = PURPLE_REQUEST_FIELDS;
		info->handle    = handle;
		info->ui_handle = ops->request_fields(title, primary, secondary,
											  fields, ok_text, ok_cb,
											  cancel_text, cancel_cb,
											  account, who, conv,
											  user_data);

		handles = g_list_append(handles, info);

		return info->ui_handle;
	}

	return NULL;
}

void *
purple_request_file(void *handle, const char *title, const char *filename,
				  gboolean savedialog,
				  GCallback ok_cb, GCallback cancel_cb,
				  PurpleAccount *account, const char *who, PurpleConversation *conv,
				  void *user_data)
{
	PurpleRequestUiOps *ops;

	ops = purple_request_get_ui_ops();

	if (ops != NULL && ops->request_file != NULL) {
		PurpleRequestInfo *info;

		info            = g_new0(PurpleRequestInfo, 1);
		info->type      = PURPLE_REQUEST_FILE;
		info->handle    = handle;
		info->ui_handle = ops->request_file(title, filename, savedialog,
											ok_cb, cancel_cb,
											account, who, conv, user_data);
		handles = g_list_append(handles, info);
		return info->ui_handle;
	}

	return NULL;
}

void *
purple_request_folder(void *handle, const char *title, const char *dirname,
				  GCallback ok_cb, GCallback cancel_cb,
				  PurpleAccount *account, const char *who, PurpleConversation *conv,
				  void *user_data)
{
	PurpleRequestUiOps *ops;

	ops = purple_request_get_ui_ops();

	if (ops != NULL && ops->request_file != NULL) {
		PurpleRequestInfo *info;

		info            = g_new0(PurpleRequestInfo, 1);
		info->type      = PURPLE_REQUEST_FOLDER;
		info->handle    = handle;
		info->ui_handle = ops->request_folder(title, dirname,
											ok_cb, cancel_cb,
											account, who, conv,
											user_data);
		handles = g_list_append(handles, info);
		return info->ui_handle;
	}

	return NULL;
}

static void
purple_request_close_info(PurpleRequestInfo *info)
{
	PurpleRequestUiOps *ops;

	ops = purple_request_get_ui_ops();

	purple_notify_close_with_handle(info->ui_handle);
	purple_request_close_with_handle(info->ui_handle);

	if (ops != NULL && ops->close_request != NULL)
		ops->close_request(info->type, info->ui_handle);

	g_free(info);
}

void
purple_request_close(PurpleRequestType type, void *ui_handle)
{
	GList *l;

	g_return_if_fail(ui_handle != NULL);

	for (l = handles; l != NULL; l = l->next) {
		PurpleRequestInfo *info = l->data;

		if (info->ui_handle == ui_handle) {
			handles = g_list_remove(handles, info);
			purple_request_close_info(info);
			break;
		}
	}
}

void
purple_request_close_with_handle(void *handle)
{
	GList *l, *l_next;

	g_return_if_fail(handle != NULL);

	for (l = handles; l != NULL; l = l_next) {
		PurpleRequestInfo *info = l->data;

		l_next = l->next;

		if (info->handle == handle) {
			handles = g_list_remove(handles, info);
			purple_request_close_info(info);
		}
	}
}

void
purple_request_set_ui_ops(PurpleRequestUiOps *ops)
{
	request_ui_ops = ops;
}

PurpleRequestUiOps *
purple_request_get_ui_ops(void)
{
	return request_ui_ops;
}
