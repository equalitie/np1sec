/*
 * purple - Jabber Protocol Plugin
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
 *
 */
#include "internal.h"
#include "request.h"
#include "server.h"

#include "xdata.h"

typedef enum {
	JABBER_X_DATA_IGNORE = 0,
	JABBER_X_DATA_TEXT_SINGLE,
	JABBER_X_DATA_TEXT_MULTI,
	JABBER_X_DATA_LIST_SINGLE,
	JABBER_X_DATA_LIST_MULTI,
	JABBER_X_DATA_BOOLEAN,
	JABBER_X_DATA_JID_SINGLE
} jabber_x_data_field_type;

struct jabber_x_data_data {
	GHashTable *fields;
	GSList *values;
	jabber_x_data_action_cb cb;
	gpointer user_data;
	JabberStream *js;
	GList *actions;
	PurpleRequestFieldGroup *actiongroup;
};

static void jabber_x_data_ok_cb(struct jabber_x_data_data *data, PurpleRequestFields *fields) {
	xmlnode *result = xmlnode_new("x");
	jabber_x_data_action_cb cb = data->cb;
	gpointer user_data = data->user_data;
	JabberStream *js = data->js;
	GList *groups, *flds;
	char *actionhandle = NULL;
	gboolean hasActions = (data->actions != NULL);

	xmlnode_set_namespace(result, "jabber:x:data");
	xmlnode_set_attrib(result, "type", "submit");

	for(groups = purple_request_fields_get_groups(fields); groups; groups = groups->next) {
		if(groups->data == data->actiongroup) {
			for(flds = purple_request_field_group_get_fields(groups->data); flds; flds = flds->next) {
				PurpleRequestField *field = flds->data;
				const char *id = purple_request_field_get_id(field);
				int handleindex;
				if(strcmp(id, "libpurple:jabber:xdata:actions"))
					continue;
				handleindex = purple_request_field_choice_get_value(field);
				actionhandle = g_strdup(g_list_nth_data(data->actions, handleindex));
				break;
			}
			continue;
		}
		for(flds = purple_request_field_group_get_fields(groups->data); flds; flds = flds->next) {
			xmlnode *fieldnode, *valuenode;
			PurpleRequestField *field = flds->data;
			const char *id = purple_request_field_get_id(field);
			jabber_x_data_field_type type = GPOINTER_TO_INT(g_hash_table_lookup(data->fields, id));

			switch(type) {
				case JABBER_X_DATA_TEXT_SINGLE:
				case JABBER_X_DATA_JID_SINGLE:
					{
					const char *value = purple_request_field_string_get_value(field);
					if (value == NULL)
						break;
					fieldnode = xmlnode_new_child(result, "field");
					xmlnode_set_attrib(fieldnode, "var", id);
					valuenode = xmlnode_new_child(fieldnode, "value");
					if(value)
						xmlnode_insert_data(valuenode, value, -1);
					break;
					}
				case JABBER_X_DATA_TEXT_MULTI:
					{
					char **pieces, **p;
					const char *value = purple_request_field_string_get_value(field);
					if (value == NULL)
						break;
					fieldnode = xmlnode_new_child(result, "field");
					xmlnode_set_attrib(fieldnode, "var", id);

					pieces = g_strsplit(value, "\n", -1);
					for(p = pieces; *p != NULL; p++) {
						valuenode = xmlnode_new_child(fieldnode, "value");
						xmlnode_insert_data(valuenode, *p, -1);
					}
					g_strfreev(pieces);
					}
					break;
				case JABBER_X_DATA_LIST_SINGLE:
				case JABBER_X_DATA_LIST_MULTI:
					{
					GList *selected = purple_request_field_list_get_selected(field);
					char *value;
					fieldnode = xmlnode_new_child(result, "field");
					xmlnode_set_attrib(fieldnode, "var", id);

					while(selected) {
						value = purple_request_field_list_get_data(field, selected->data);
						valuenode = xmlnode_new_child(fieldnode, "value");
						if(value)
							xmlnode_insert_data(valuenode, value, -1);
						selected = selected->next;
					}
					}
					break;
				case JABBER_X_DATA_BOOLEAN:
					fieldnode = xmlnode_new_child(result, "field");
					xmlnode_set_attrib(fieldnode, "var", id);
					valuenode = xmlnode_new_child(fieldnode, "value");
					if(purple_request_field_bool_get_value(field))
						xmlnode_insert_data(valuenode, "1", -1);
					else
						xmlnode_insert_data(valuenode, "0", -1);
					break;
				case JABBER_X_DATA_IGNORE:
					break;
			}
		}
	}

	g_hash_table_destroy(data->fields);
	while(data->values) {
		g_free(data->values->data);
		data->values = g_slist_delete_link(data->values, data->values);
	}
	if (data->actions) {
		GList *action;
		for(action = data->actions; action; action = g_list_next(action)) {
			g_free(action->data);
		}
		g_list_free(data->actions);
	}
	g_free(data);

	if (hasActions)
		cb(js, result, actionhandle, user_data);
	else
		((jabber_x_data_cb)cb)(js, result, user_data);

	g_free(actionhandle);
}

static void jabber_x_data_cancel_cb(struct jabber_x_data_data *data, PurpleRequestFields *fields) {
	xmlnode *result = xmlnode_new("x");
	jabber_x_data_action_cb cb = data->cb;
	gpointer user_data = data->user_data;
	JabberStream *js = data->js;
	gboolean hasActions = FALSE;
	g_hash_table_destroy(data->fields);
	while(data->values) {
		g_free(data->values->data);
		data->values = g_slist_delete_link(data->values, data->values);
	}
	if (data->actions) {
		GList *action;
		hasActions = TRUE;
		for(action = data->actions; action; action = g_list_next(action)) {
			g_free(action->data);
		}
		g_list_free(data->actions);
	}
	g_free(data);

	xmlnode_set_namespace(result, "jabber:x:data");
	xmlnode_set_attrib(result, "type", "cancel");

	if (hasActions)
		cb(js, result, NULL, user_data);
	else
		((jabber_x_data_cb)cb)(js, result, user_data);
}

void *jabber_x_data_request(JabberStream *js, xmlnode *packet, jabber_x_data_cb cb, gpointer user_data)
{
	return jabber_x_data_request_with_actions(js, packet, NULL, 0, (jabber_x_data_action_cb)cb, user_data);
}

void *jabber_x_data_request_with_actions(JabberStream *js, xmlnode *packet, GList *actions, int defaultaction, jabber_x_data_action_cb cb, gpointer user_data)
{
	void *handle;
	xmlnode *fn, *x;
	PurpleRequestFields *fields;
	PurpleRequestFieldGroup *group;
	PurpleRequestField *field = NULL;

	char *title = NULL;
	char *instructions = NULL;

	struct jabber_x_data_data *data = g_new0(struct jabber_x_data_data, 1);

	data->fields = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
	data->user_data = user_data;
	data->cb = cb;
	data->js = js;

	fields = purple_request_fields_new();
	group = purple_request_field_group_new(NULL);
	purple_request_fields_add_group(fields, group);

	for(fn = xmlnode_get_child(packet, "field"); fn; fn = xmlnode_get_next_twin(fn)) {
		xmlnode *valuenode;
		const char *type = xmlnode_get_attrib(fn, "type");
		const char *label = xmlnode_get_attrib(fn, "label");
		const char *var = xmlnode_get_attrib(fn, "var");
		char *value = NULL;

		if(!type)
			type = "text-single";

		if(!var && strcmp(type, "fixed"))
			continue;
		if(!label)
			label = var;

		if(!strcmp(type, "text-private")) {
			if((valuenode = xmlnode_get_child(fn, "value")))
				value = xmlnode_get_data(valuenode);

			field = purple_request_field_string_new(var, label,
					value ? value : "", FALSE);
			purple_request_field_string_set_masked(field, TRUE);
			purple_request_field_group_add_field(group, field);

			g_hash_table_replace(data->fields, g_strdup(var), GINT_TO_POINTER(JABBER_X_DATA_TEXT_SINGLE));

			g_free(value);
		} else if(!strcmp(type, "text-multi") || !strcmp(type, "jid-multi")) {
			GString *str = g_string_new("");

			for(valuenode = xmlnode_get_child(fn, "value"); valuenode;
					valuenode = xmlnode_get_next_twin(valuenode)) {

				if(!(value = xmlnode_get_data(valuenode)))
					continue;

				g_string_append_printf(str, "%s\n", value);
				g_free(value);
			}

			field = purple_request_field_string_new(var, label,
					str->str, TRUE);
			purple_request_field_group_add_field(group, field);

			g_hash_table_replace(data->fields, g_strdup(var), GINT_TO_POINTER(JABBER_X_DATA_TEXT_MULTI));

			g_string_free(str, TRUE);
		} else if(!strcmp(type, "list-single") || !strcmp(type, "list-multi")) {
			xmlnode *optnode;
			GList *selected = NULL;

			field = purple_request_field_list_new(var, label);

			if(!strcmp(type, "list-multi")) {
				purple_request_field_list_set_multi_select(field, TRUE);
				g_hash_table_replace(data->fields, g_strdup(var),
						GINT_TO_POINTER(JABBER_X_DATA_LIST_MULTI));
			} else {
				g_hash_table_replace(data->fields, g_strdup(var),
						GINT_TO_POINTER(JABBER_X_DATA_LIST_SINGLE));
			}

			for(valuenode = xmlnode_get_child(fn, "value"); valuenode;
					valuenode = xmlnode_get_next_twin(valuenode)) {
				char *data = xmlnode_get_data(valuenode);
				if (data != NULL) {
					selected = g_list_prepend(selected, data);
				}
			}

			for(optnode = xmlnode_get_child(fn, "option"); optnode;
					optnode = xmlnode_get_next_twin(optnode)) {
				const char *lbl;

				if(!(valuenode = xmlnode_get_child(optnode, "value")))
					continue;

				if(!(value = xmlnode_get_data(valuenode)))
					continue;

				if(!(lbl = xmlnode_get_attrib(optnode, "label")))
					lbl = value;

				data->values = g_slist_prepend(data->values, value);

				purple_request_field_list_add_icon(field, lbl, NULL, value);
				if(g_list_find_custom(selected, value, (GCompareFunc)strcmp))
					purple_request_field_list_add_selected(field, lbl);
			}
			purple_request_field_group_add_field(group, field);

			while(selected) {
				g_free(selected->data);
				selected = g_list_delete_link(selected, selected);
			}

		} else if(!strcmp(type, "boolean")) {
			gboolean def = FALSE;

			if((valuenode = xmlnode_get_child(fn, "value")))
				value = xmlnode_get_data(valuenode);

			if(value && (!g_ascii_strcasecmp(value, "yes") ||
						!g_ascii_strcasecmp(value, "true") || !g_ascii_strcasecmp(value, "1")))
				def = TRUE;

			field = purple_request_field_bool_new(var, label, def);
			purple_request_field_group_add_field(group, field);

			g_hash_table_replace(data->fields, g_strdup(var), GINT_TO_POINTER(JABBER_X_DATA_BOOLEAN));

			g_free(value);
		} else if(!strcmp(type, "fixed")) {
			if((valuenode = xmlnode_get_child(fn, "value")))
				value = xmlnode_get_data(valuenode);

			if(value != NULL) {
				field = purple_request_field_label_new("", value);
				purple_request_field_group_add_field(group, field);

				g_free(value);
			}
		} else if(!strcmp(type, "hidden")) {
			if((valuenode = xmlnode_get_child(fn, "value")))
				value = xmlnode_get_data(valuenode);

			field = purple_request_field_string_new(var, "", value ? value : "",
					FALSE);
			purple_request_field_set_visible(field, FALSE);
			purple_request_field_group_add_field(group, field);

			g_hash_table_replace(data->fields, g_strdup(var), GINT_TO_POINTER(JABBER_X_DATA_TEXT_SINGLE));

			g_free(value);
		} else { /* text-single, jid-single, and the default */
			if((valuenode = xmlnode_get_child(fn, "value")))
				value = xmlnode_get_data(valuenode);

			field = purple_request_field_string_new(var, label,
					value ? value : "", FALSE);
			purple_request_field_group_add_field(group, field);

			if(!strcmp(type, "jid-single")) {
				purple_request_field_set_type_hint(field, "screenname");
				g_hash_table_replace(data->fields, g_strdup(var), GINT_TO_POINTER(JABBER_X_DATA_JID_SINGLE));
			} else {
				g_hash_table_replace(data->fields, g_strdup(var), GINT_TO_POINTER(JABBER_X_DATA_TEXT_SINGLE));
			}

			g_free(value);
		}

		if(field && xmlnode_get_child(fn, "required"))
			purple_request_field_set_required(field,TRUE);
	}

	if(actions != NULL) {
		PurpleRequestField *actionfield;
		GList *action;
		data->actiongroup = group = purple_request_field_group_new(_("Actions"));
		purple_request_fields_add_group(fields, group);
		actionfield = purple_request_field_choice_new("libpurple:jabber:xdata:actions", _("Select an action"), defaultaction);

		for(action = actions; action; action = g_list_next(action)) {
			JabberXDataAction *a = action->data;

			purple_request_field_choice_add(actionfield, a->name);
			data->actions = g_list_append(data->actions, g_strdup(a->handle));
		}
		purple_request_field_set_required(actionfield,TRUE);
		purple_request_field_group_add_field(group, actionfield);
	}

	if((x = xmlnode_get_child(packet, "title")))
		title = xmlnode_get_data(x);

	if((x = xmlnode_get_child(packet, "instructions")))
		instructions = xmlnode_get_data(x);

	handle = purple_request_fields(js->gc, title, title, instructions, fields,
			_("OK"), G_CALLBACK(jabber_x_data_ok_cb),
			_("Cancel"), G_CALLBACK(jabber_x_data_cancel_cb),
			purple_connection_get_account(js->gc), /* XXX Do we have a who here? */ NULL, NULL,
			data);

	g_free(title);
	g_free(instructions);

	return handle;
}

gchar *
jabber_x_data_get_formtype(const xmlnode *form)
{
	xmlnode *field;

	g_return_val_if_fail(form != NULL, NULL);

	for (field = xmlnode_get_child((xmlnode *)form, "field"); field;
			field = xmlnode_get_next_twin(field)) {
		const char *var = xmlnode_get_attrib(field, "var");
		if (purple_strequal(var, "FORM_TYPE")) {
			xmlnode *value = xmlnode_get_child(field, "value");
			if (value)
				return xmlnode_get_data(value);
			else
				/* An interesting corner case... Looking for a second
				 * FORM_TYPE would be more considerate, but I'm in favor
				 * of not helping broken clients.
				 */
				return NULL;
		}
	}

	/* Erm, none found :( */
	return NULL;
}

