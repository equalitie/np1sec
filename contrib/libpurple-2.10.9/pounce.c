/**
 * @file pounce.c Buddy Pounce API
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
#include "conversation.h"
#include "debug.h"
#include "pounce.h"

#include "debug.h"
#include "pounce.h"
#include "util.h"

typedef struct
{
	GString *buffer;

	PurplePounce *pounce;
	PurplePounceEvent events;
	PurplePounceOption options;

	char *ui_name;
	char *pouncee;
	char *protocol_id;
	char *event_type;
	char *option_type;
	char *action_name;
	char *param_name;
	char *account_name;

} PounceParserData;

typedef struct
{
	char *name;

	gboolean enabled;

	GHashTable *atts;

} PurplePounceActionData;

typedef struct
{
	char *ui;
	PurplePounceCb cb;
	void (*new_pounce)(PurplePounce *);
	void (*free_pounce)(PurplePounce *);

} PurplePounceHandler;


static GHashTable *pounce_handlers = NULL;
static GList      *pounces = NULL;
static guint       save_timer = 0;
static gboolean    pounces_loaded = FALSE;


/*********************************************************************
 * Private utility functions                                         *
 *********************************************************************/

static PurplePounceActionData *
find_action_data(const PurplePounce *pounce, const char *name)
{
	PurplePounceActionData *action;

	g_return_val_if_fail(pounce != NULL, NULL);
	g_return_val_if_fail(name   != NULL, NULL);

	action = g_hash_table_lookup(pounce->actions, name);

	return action;
}

static void
free_action_data(gpointer data)
{
	PurplePounceActionData *action_data = data;

	g_free(action_data->name);

	g_hash_table_destroy(action_data->atts);

	g_free(action_data);
}


/*********************************************************************
 * Writing to disk                                                   *
 *********************************************************************/

static void
action_parameter_to_xmlnode(gpointer key, gpointer value, gpointer user_data)
{
	const char *name, *param_value;
	xmlnode *node, *child;

	name        = (const char *)key;
	param_value = (const char *)value;
	node        = (xmlnode *)user_data;

	child = xmlnode_new_child(node, "param");
	xmlnode_set_attrib(child, "name", name);
	xmlnode_insert_data(child, param_value, -1);
}

static void
action_parameter_list_to_xmlnode(gpointer key, gpointer value, gpointer user_data)
{
	const char *action;
	PurplePounceActionData *action_data;
	xmlnode *node, *child;

	action      = (const char *)key;
	action_data = (PurplePounceActionData *)value;
	node        = (xmlnode *)user_data;

	if (!action_data->enabled)
		return;

	child = xmlnode_new_child(node, "action");
	xmlnode_set_attrib(child, "type", action);

	g_hash_table_foreach(action_data->atts, action_parameter_to_xmlnode, child);
}

static void
add_event_to_xmlnode(xmlnode *node, const char *type)
{
	xmlnode *child;

	child = xmlnode_new_child(node, "event");
	xmlnode_set_attrib(child, "type", type);
}

static void
add_option_to_xmlnode(xmlnode *node, const char *type)
{
	xmlnode *child;

	child = xmlnode_new_child(node, "option");
	xmlnode_set_attrib(child, "type", type);
}

static xmlnode *
pounce_to_xmlnode(PurplePounce *pounce)
{
	xmlnode *node, *child;
	PurpleAccount *pouncer;
	PurplePounceEvent events;
	PurplePounceOption options;

	pouncer = purple_pounce_get_pouncer(pounce);
	events  = purple_pounce_get_events(pounce);
	options = purple_pounce_get_options(pounce);

	node = xmlnode_new("pounce");
	xmlnode_set_attrib(node, "ui", pounce->ui_type);

	child = xmlnode_new_child(node, "account");
	xmlnode_set_attrib(child, "protocol", pouncer->protocol_id);
	xmlnode_insert_data(child,
			purple_normalize(pouncer, purple_account_get_username(pouncer)), -1);

	child = xmlnode_new_child(node, "pouncee");
	xmlnode_insert_data(child, purple_pounce_get_pouncee(pounce), -1);

	/* Write pounce options */
	child = xmlnode_new_child(node, "options");
	if (options & PURPLE_POUNCE_OPTION_AWAY)
		add_option_to_xmlnode(child, "on-away");

	/* Write pounce events */
	child = xmlnode_new_child(node, "events");
	if (events & PURPLE_POUNCE_SIGNON)
		add_event_to_xmlnode(child, "sign-on");
	if (events & PURPLE_POUNCE_SIGNOFF)
		add_event_to_xmlnode(child, "sign-off");
	if (events & PURPLE_POUNCE_AWAY)
		add_event_to_xmlnode(child, "away");
	if (events & PURPLE_POUNCE_AWAY_RETURN)
		add_event_to_xmlnode(child, "return-from-away");
	if (events & PURPLE_POUNCE_IDLE)
		add_event_to_xmlnode(child, "idle");
	if (events & PURPLE_POUNCE_IDLE_RETURN)
		add_event_to_xmlnode(child, "return-from-idle");
	if (events & PURPLE_POUNCE_TYPING)
		add_event_to_xmlnode(child, "start-typing");
	if (events & PURPLE_POUNCE_TYPED)
		add_event_to_xmlnode(child, "typed");
	if (events & PURPLE_POUNCE_TYPING_STOPPED)
		add_event_to_xmlnode(child, "stop-typing");
	if (events & PURPLE_POUNCE_MESSAGE_RECEIVED)
		add_event_to_xmlnode(child, "message-received");

	/* Write pounce actions */
	child = xmlnode_new_child(node, "actions");
	g_hash_table_foreach(pounce->actions, action_parameter_list_to_xmlnode, child);

	if (purple_pounce_get_save(pounce))
		xmlnode_new_child(node, "save");

	return node;
}

static xmlnode *
pounces_to_xmlnode(void)
{
	xmlnode *node, *child;
	GList *cur;

	node = xmlnode_new("pounces");
	xmlnode_set_attrib(node, "version", "1.0");

	for (cur = purple_pounces_get_all(); cur != NULL; cur = cur->next)
	{
		child = pounce_to_xmlnode(cur->data);
		xmlnode_insert_child(node, child);
	}

	return node;
}

static void
sync_pounces(void)
{
	xmlnode *node;
	char *data;

	if (!pounces_loaded)
	{
		purple_debug_error("pounce", "Attempted to save buddy pounces before "
						 "they were read!\n");
		return;
	}

	node = pounces_to_xmlnode();
	data = xmlnode_to_formatted_str(node, NULL);
	purple_util_write_data_to_file("pounces.xml", data, -1);
	g_free(data);
	xmlnode_free(node);
}

static gboolean
save_cb(gpointer data)
{
	sync_pounces();
	save_timer = 0;
	return FALSE;
}

static void
schedule_pounces_save(void)
{
	if (save_timer == 0)
		save_timer = purple_timeout_add_seconds(5, save_cb, NULL);
}


/*********************************************************************
 * Reading from disk                                                 *
 *********************************************************************/

static void
free_parser_data(gpointer user_data)
{
	PounceParserData *data = user_data;

	if (data->buffer != NULL)
		g_string_free(data->buffer, TRUE);

	g_free(data->ui_name);
	g_free(data->pouncee);
	g_free(data->protocol_id);
	g_free(data->event_type);
	g_free(data->option_type);
	g_free(data->action_name);
	g_free(data->param_name);
	g_free(data->account_name);

	g_free(data);
}

static void
start_element_handler(GMarkupParseContext *context,
					  const gchar *element_name,
					  const gchar **attribute_names,
					  const gchar **attribute_values,
					  gpointer user_data, GError **error)
{
	PounceParserData *data = user_data;
	GHashTable *atts;
	int i;

	atts = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

	for (i = 0; attribute_names[i] != NULL; i++) {
		g_hash_table_insert(atts, g_strdup(attribute_names[i]),
							g_strdup(attribute_values[i]));
	}

	if (data->buffer != NULL) {
		g_string_free(data->buffer, TRUE);
		data->buffer = NULL;
	}

	if (purple_strequal(element_name, "pounce")) {
		const char *ui = g_hash_table_lookup(atts, "ui");

		if (ui == NULL) {
			purple_debug(PURPLE_DEBUG_ERROR, "pounce",
					   "Unset 'ui' parameter for pounce!\n");
		}
		else
			data->ui_name = g_strdup(ui);

		data->events = 0;
	}
	else if (purple_strequal(element_name, "account")) {
		const char *protocol_id = g_hash_table_lookup(atts, "protocol");

		if (protocol_id == NULL) {
			purple_debug(PURPLE_DEBUG_ERROR, "pounce",
					   "Unset 'protocol' parameter for account!\n");
		}
		else
			data->protocol_id = g_strdup(protocol_id);
	}
	else if (purple_strequal(element_name, "option")) {
		const char *type = g_hash_table_lookup(atts, "type");

		if (type == NULL) {
			purple_debug(PURPLE_DEBUG_ERROR, "pounce",
					   "Unset 'type' parameter for option!\n");
		}
		else
			data->option_type = g_strdup(type);
	}
	else if (purple_strequal(element_name, "event")) {
		const char *type = g_hash_table_lookup(atts, "type");

		if (type == NULL) {
			purple_debug(PURPLE_DEBUG_ERROR, "pounce",
					   "Unset 'type' parameter for event!\n");
		}
		else
			data->event_type = g_strdup(type);
	}
	else if (purple_strequal(element_name, "action")) {
		const char *type = g_hash_table_lookup(atts, "type");

		if (type == NULL) {
			purple_debug(PURPLE_DEBUG_ERROR, "pounce",
					   "Unset 'type' parameter for action!\n");
		}
		else
			data->action_name = g_strdup(type);
	}
	else if (purple_strequal(element_name, "param")) {
		const char *param_name = g_hash_table_lookup(atts, "name");

		if (param_name == NULL) {
			purple_debug(PURPLE_DEBUG_ERROR, "pounce",
					   "Unset 'name' parameter for param!\n");
		}
		else
			data->param_name = g_strdup(param_name);
	}

	g_hash_table_destroy(atts);
}

static void
end_element_handler(GMarkupParseContext *context, const gchar *element_name,
					gpointer user_data,  GError **error)
{
	PounceParserData *data = user_data;
	gchar *buffer = NULL;

	if (data->buffer != NULL) {
		buffer = g_string_free(data->buffer, FALSE);
		data->buffer = NULL;
	}

	if (purple_strequal(element_name, "account")) {
		char *tmp;
		g_free(data->account_name);
		data->account_name = g_strdup(buffer);
		tmp = data->protocol_id;
		data->protocol_id = g_strdup(_purple_oscar_convert(buffer, tmp));
		g_free(tmp);
	}
	else if (purple_strequal(element_name, "pouncee")) {
		g_free(data->pouncee);
		data->pouncee = g_strdup(buffer);
	}
	else if (purple_strequal(element_name, "option")) {
		if (purple_strequal(data->option_type, "on-away"))
			data->options |= PURPLE_POUNCE_OPTION_AWAY;

		g_free(data->option_type);
		data->option_type = NULL;
	}
	else if (purple_strequal(element_name, "event")) {
		if (purple_strequal(data->event_type, "sign-on"))
			data->events |= PURPLE_POUNCE_SIGNON;
		else if (purple_strequal(data->event_type, "sign-off"))
			data->events |= PURPLE_POUNCE_SIGNOFF;
		else if (purple_strequal(data->event_type, "away"))
			data->events |= PURPLE_POUNCE_AWAY;
		else if (purple_strequal(data->event_type, "return-from-away"))
			data->events |= PURPLE_POUNCE_AWAY_RETURN;
		else if (purple_strequal(data->event_type, "idle"))
			data->events |= PURPLE_POUNCE_IDLE;
		else if (purple_strequal(data->event_type, "return-from-idle"))
			data->events |= PURPLE_POUNCE_IDLE_RETURN;
		else if (purple_strequal(data->event_type, "start-typing"))
			data->events |= PURPLE_POUNCE_TYPING;
		else if (purple_strequal(data->event_type, "typed"))
			data->events |= PURPLE_POUNCE_TYPED;
		else if (purple_strequal(data->event_type, "stop-typing"))
			data->events |= PURPLE_POUNCE_TYPING_STOPPED;
		else if (purple_strequal(data->event_type, "message-received"))
			data->events |= PURPLE_POUNCE_MESSAGE_RECEIVED;

		g_free(data->event_type);
		data->event_type = NULL;
	}
	else if (purple_strequal(element_name, "action")) {
		if (data->pounce != NULL) {
			purple_pounce_action_register(data->pounce, data->action_name);
			purple_pounce_action_set_enabled(data->pounce, data->action_name, TRUE);
		}

		g_free(data->action_name);
		data->action_name = NULL;
	}
	else if (purple_strequal(element_name, "param")) {
		if (data->pounce != NULL) {
			purple_pounce_action_set_attribute(data->pounce, data->action_name,
											 data->param_name, buffer);
		}

		g_free(data->param_name);
		data->param_name = NULL;
	}
	else if (purple_strequal(element_name, "events")) {
		PurpleAccount *account;

		account = purple_accounts_find(data->account_name, data->protocol_id);

		g_free(data->account_name);
		g_free(data->protocol_id);

		data->account_name = NULL;
		data->protocol_id  = NULL;

		if (account == NULL) {
			purple_debug(PURPLE_DEBUG_ERROR, "pounce",
					   "Account for pounce not found!\n");
			/*
			 * This pounce has effectively been removed, so make
			 * sure that we save the changes to pounces.xml
			 */
			schedule_pounces_save();
		}
		else {
			purple_debug(PURPLE_DEBUG_INFO, "pounce",
					   "Creating pounce: %s, %s\n", data->ui_name,
					   data->pouncee);

			data->pounce = purple_pounce_new(data->ui_name, account,
										   data->pouncee, data->events,
										   data->options);
		}

		g_free(data->pouncee);
		data->pouncee = NULL;
	}
	else if (purple_strequal(element_name, "save")) {
		if (data->pounce != NULL)
			purple_pounce_set_save(data->pounce, TRUE);
	}
	else if (purple_strequal(element_name, "pounce")) {
		data->pounce  = NULL;
		data->events  = 0;
		data->options = 0;

		g_free(data->ui_name);
		g_free(data->pouncee);
		g_free(data->protocol_id);
		g_free(data->event_type);
		g_free(data->option_type);
		g_free(data->action_name);
		g_free(data->param_name);
		g_free(data->account_name);

		data->ui_name      = NULL;
		data->pounce       = NULL;
		data->protocol_id  = NULL;
		data->event_type   = NULL;
		data->option_type  = NULL;
		data->action_name  = NULL;
		data->param_name   = NULL;
		data->account_name = NULL;
	}

	g_free(buffer);
}

static void
text_handler(GMarkupParseContext *context, const gchar *text,
			 gsize text_len, gpointer user_data, GError **error)
{
	PounceParserData *data = user_data;

	if (data->buffer == NULL)
		data->buffer = g_string_new_len(text, text_len);
	else
		g_string_append_len(data->buffer, text, text_len);
}

static GMarkupParser pounces_parser =
{
	start_element_handler,
	end_element_handler,
	text_handler,
	NULL,
	NULL
};

gboolean
purple_pounces_load(void)
{
	gchar *filename = g_build_filename(purple_user_dir(), "pounces.xml", NULL);
	gchar *contents = NULL;
	gsize length;
	GMarkupParseContext *context;
	GError *error = NULL;
	PounceParserData *parser_data;

	if (filename == NULL) {
		pounces_loaded = TRUE;
		return FALSE;
	}

	if (!g_file_get_contents(filename, &contents, &length, &error)) {
		purple_debug(PURPLE_DEBUG_ERROR, "pounce",
				   "Error reading pounces: %s\n", error->message);

		g_free(filename);
		g_error_free(error);

		pounces_loaded = TRUE;
		return FALSE;
	}

	parser_data = g_new0(PounceParserData, 1);

	context = g_markup_parse_context_new(&pounces_parser, 0,
										 parser_data, free_parser_data);

	if (!g_markup_parse_context_parse(context, contents, length, NULL)) {
		g_markup_parse_context_free(context);
		g_free(contents);
		g_free(filename);

		pounces_loaded = TRUE;

		return FALSE;
	}

	if (!g_markup_parse_context_end_parse(context, NULL)) {
		purple_debug(PURPLE_DEBUG_ERROR, "pounce", "Error parsing %s\n",
				   filename);

		g_markup_parse_context_free(context);
		g_free(contents);
		g_free(filename);
		pounces_loaded = TRUE;

		return FALSE;
	}

	g_markup_parse_context_free(context);
	g_free(contents);
	g_free(filename);

	pounces_loaded = TRUE;

	return TRUE;
}


PurplePounce *
purple_pounce_new(const char *ui_type, PurpleAccount *pouncer,
				const char *pouncee, PurplePounceEvent event,
				PurplePounceOption option)
{
	PurplePounce *pounce;
	PurplePounceHandler *handler;

	g_return_val_if_fail(ui_type != NULL, NULL);
	g_return_val_if_fail(pouncer != NULL, NULL);
	g_return_val_if_fail(pouncee != NULL, NULL);
	g_return_val_if_fail(event   != 0,    NULL);

	pounce = g_new0(PurplePounce, 1);

	pounce->ui_type  = g_strdup(ui_type);
	pounce->pouncer  = pouncer;
	pounce->pouncee  = g_strdup(pouncee);
	pounce->events   = event;
	pounce->options  = option;

	pounce->actions  = g_hash_table_new_full(g_str_hash, g_str_equal,
											 g_free, free_action_data);

	handler = g_hash_table_lookup(pounce_handlers, pounce->ui_type);

	if (handler != NULL && handler->new_pounce != NULL)
		handler->new_pounce(pounce);

	pounces = g_list_append(pounces, pounce);

	schedule_pounces_save();

	return pounce;
}

void
purple_pounce_destroy(PurplePounce *pounce)
{
	PurplePounceHandler *handler;

	g_return_if_fail(pounce != NULL);

	handler = g_hash_table_lookup(pounce_handlers, pounce->ui_type);

	pounces = g_list_remove(pounces, pounce);

	g_free(pounce->ui_type);
	g_free(pounce->pouncee);

	g_hash_table_destroy(pounce->actions);

	if (handler != NULL && handler->free_pounce != NULL)
		handler->free_pounce(pounce);

	g_free(pounce);

	schedule_pounces_save();
}

void
purple_pounce_destroy_all_by_account(PurpleAccount *account)
{
	PurpleAccount *pouncer;
	PurplePounce *pounce;
	GList *l, *l_next;

	g_return_if_fail(account != NULL);

	for (l = purple_pounces_get_all(); l != NULL; l = l_next)
	{
		pounce = (PurplePounce *)l->data;
		l_next = l->next;

		pouncer = purple_pounce_get_pouncer(pounce);
		if (pouncer == account)
			purple_pounce_destroy(pounce);
	}
}

void
purple_pounce_destroy_all_by_buddy(PurpleBuddy *buddy)
{
	const char *pouncee, *bname;
	PurpleAccount *pouncer, *bacct;
	PurplePounce *pounce;
	GList *l, *l_next;

	g_return_if_fail(buddy != NULL);

	bacct = purple_buddy_get_account(buddy);
	bname = purple_buddy_get_name(buddy);

	for (l = purple_pounces_get_all(); l != NULL; l = l_next) {
		pounce = (PurplePounce *)l->data;
		l_next = l->next;

		pouncer = purple_pounce_get_pouncer(pounce);
		pouncee = purple_pounce_get_pouncee(pounce);

		if ( (pouncer == bacct) && (strcmp(pouncee, bname) == 0) )
			purple_pounce_destroy(pounce);
	}
}

void
purple_pounce_set_events(PurplePounce *pounce, PurplePounceEvent events)
{
	g_return_if_fail(pounce != NULL);
	g_return_if_fail(events != PURPLE_POUNCE_NONE);

	pounce->events = events;

	schedule_pounces_save();
}

void
purple_pounce_set_options(PurplePounce *pounce, PurplePounceOption options)
{
	g_return_if_fail(pounce  != NULL);

	pounce->options = options;

	schedule_pounces_save();
}

void
purple_pounce_set_pouncer(PurplePounce *pounce, PurpleAccount *pouncer)
{
	g_return_if_fail(pounce  != NULL);
	g_return_if_fail(pouncer != NULL);

	pounce->pouncer = pouncer;

	schedule_pounces_save();
}

void
purple_pounce_set_pouncee(PurplePounce *pounce, const char *pouncee)
{
	g_return_if_fail(pounce  != NULL);
	g_return_if_fail(pouncee != NULL);

	g_free(pounce->pouncee);
	pounce->pouncee = g_strdup(pouncee);

	schedule_pounces_save();
}

void
purple_pounce_set_save(PurplePounce *pounce, gboolean save)
{
	g_return_if_fail(pounce != NULL);

	pounce->save = save;

	schedule_pounces_save();
}

void
purple_pounce_action_register(PurplePounce *pounce, const char *name)
{
	PurplePounceActionData *action_data;

	g_return_if_fail(pounce != NULL);
	g_return_if_fail(name   != NULL);

	if (g_hash_table_lookup(pounce->actions, name) != NULL)
		return;

	action_data = g_new0(PurplePounceActionData, 1);

	action_data->name    = g_strdup(name);
	action_data->enabled = FALSE;
	action_data->atts    = g_hash_table_new_full(g_str_hash, g_str_equal,
												 g_free, g_free);

	g_hash_table_insert(pounce->actions, g_strdup(name), action_data);

	schedule_pounces_save();
}

void
purple_pounce_action_set_enabled(PurplePounce *pounce, const char *action,
							   gboolean enabled)
{
	PurplePounceActionData *action_data;

	g_return_if_fail(pounce != NULL);
	g_return_if_fail(action != NULL);

	action_data = find_action_data(pounce, action);

	g_return_if_fail(action_data != NULL);

	action_data->enabled = enabled;

	schedule_pounces_save();
}

void
purple_pounce_action_set_attribute(PurplePounce *pounce, const char *action,
								 const char *attr, const char *value)
{
	PurplePounceActionData *action_data;

	g_return_if_fail(pounce != NULL);
	g_return_if_fail(action != NULL);
	g_return_if_fail(attr   != NULL);

	action_data = find_action_data(pounce, action);

	g_return_if_fail(action_data != NULL);

	if (value == NULL)
		g_hash_table_remove(action_data->atts, attr);
	else
		g_hash_table_insert(action_data->atts, g_strdup(attr),
							g_strdup(value));

	schedule_pounces_save();
}

void
purple_pounce_set_data(PurplePounce *pounce, void *data)
{
	g_return_if_fail(pounce != NULL);

	pounce->data = data;

	schedule_pounces_save();
}

PurplePounceEvent
purple_pounce_get_events(const PurplePounce *pounce)
{
	g_return_val_if_fail(pounce != NULL, PURPLE_POUNCE_NONE);

	return pounce->events;
}

PurplePounceOption
purple_pounce_get_options(const PurplePounce *pounce)
{
	g_return_val_if_fail(pounce != NULL, PURPLE_POUNCE_OPTION_NONE);

	return pounce->options;
}

PurpleAccount *
purple_pounce_get_pouncer(const PurplePounce *pounce)
{
	g_return_val_if_fail(pounce != NULL, NULL);

	return pounce->pouncer;
}

const char *
purple_pounce_get_pouncee(const PurplePounce *pounce)
{
	g_return_val_if_fail(pounce != NULL, NULL);

	return pounce->pouncee;
}

gboolean
purple_pounce_get_save(const PurplePounce *pounce)
{
	g_return_val_if_fail(pounce != NULL, FALSE);

	return pounce->save;
}

gboolean
purple_pounce_action_is_enabled(const PurplePounce *pounce, const char *action)
{
	PurplePounceActionData *action_data;

	g_return_val_if_fail(pounce != NULL, FALSE);
	g_return_val_if_fail(action != NULL, FALSE);

	action_data = find_action_data(pounce, action);

	g_return_val_if_fail(action_data != NULL, FALSE);

	return action_data->enabled;
}

const char *
purple_pounce_action_get_attribute(const PurplePounce *pounce,
								 const char *action, const char *attr)
{
	PurplePounceActionData *action_data;

	g_return_val_if_fail(pounce != NULL, NULL);
	g_return_val_if_fail(action != NULL, NULL);
	g_return_val_if_fail(attr   != NULL, NULL);

	action_data = find_action_data(pounce, action);

	g_return_val_if_fail(action_data != NULL, NULL);

	return g_hash_table_lookup(action_data->atts, attr);
}

void *
purple_pounce_get_data(const PurplePounce *pounce)
{
	g_return_val_if_fail(pounce != NULL, NULL);

	return pounce->data;
}

void
purple_pounce_execute(const PurpleAccount *pouncer, const char *pouncee,
					PurplePounceEvent events)
{
	PurplePounce *pounce;
	PurplePounceHandler *handler;
	PurplePresence *presence;
	GList *l, *l_next;
	char *norm_pouncee;

	g_return_if_fail(pouncer != NULL);
	g_return_if_fail(pouncee != NULL);
	g_return_if_fail(events  != PURPLE_POUNCE_NONE);

	norm_pouncee = g_strdup(purple_normalize(pouncer, pouncee));

	for (l = purple_pounces_get_all(); l != NULL; l = l_next)
	{
		pounce = (PurplePounce *)l->data;
		l_next = l->next;

		presence = purple_account_get_presence(pouncer);

		if ((purple_pounce_get_events(pounce) & events) &&
			(purple_pounce_get_pouncer(pounce) == pouncer) &&
			!purple_utf8_strcasecmp(purple_normalize(pouncer, purple_pounce_get_pouncee(pounce)),
								  norm_pouncee) &&
			(pounce->options == PURPLE_POUNCE_OPTION_NONE ||
			 (pounce->options & PURPLE_POUNCE_OPTION_AWAY &&
			  !purple_presence_is_available(presence))))
		{
			handler = g_hash_table_lookup(pounce_handlers, pounce->ui_type);

			if (handler != NULL && handler->cb != NULL)
			{
				handler->cb(pounce, events, purple_pounce_get_data(pounce));

				if (!purple_pounce_get_save(pounce))
					purple_pounce_destroy(pounce);
			}
		}
	}

	g_free(norm_pouncee);
}

PurplePounce *
purple_find_pounce(const PurpleAccount *pouncer, const char *pouncee,
				 PurplePounceEvent events)
{
	PurplePounce *pounce = NULL;
	GList *l;
	char *norm_pouncee;

	g_return_val_if_fail(pouncer != NULL, NULL);
	g_return_val_if_fail(pouncee != NULL, NULL);
	g_return_val_if_fail(events  != PURPLE_POUNCE_NONE, NULL);

	norm_pouncee = g_strdup(purple_normalize(pouncer, pouncee));

	for (l = purple_pounces_get_all(); l != NULL; l = l->next)
	{
		pounce = (PurplePounce *)l->data;

		if ((purple_pounce_get_events(pounce) & events) &&
			(purple_pounce_get_pouncer(pounce) == pouncer) &&
			!purple_utf8_strcasecmp(purple_normalize(pouncer, purple_pounce_get_pouncee(pounce)),
								  norm_pouncee))
		{
			break;
		}

		pounce = NULL;
	}

	g_free(norm_pouncee);

	return pounce;
}

void
purple_pounces_register_handler(const char *ui, PurplePounceCb cb,
							  void (*new_pounce)(PurplePounce *pounce),
							  void (*free_pounce)(PurplePounce *pounce))
{
	PurplePounceHandler *handler;

	g_return_if_fail(ui != NULL);
	g_return_if_fail(cb != NULL);

	handler = g_new0(PurplePounceHandler, 1);

	handler->ui          = g_strdup(ui);
	handler->cb          = cb;
	handler->new_pounce  = new_pounce;
	handler->free_pounce = free_pounce;

	g_hash_table_insert(pounce_handlers, g_strdup(ui), handler);
}

void
purple_pounces_unregister_handler(const char *ui)
{
	g_return_if_fail(ui != NULL);

	g_hash_table_remove(pounce_handlers, ui);
}

GList *
purple_pounces_get_all(void)
{
	return pounces;
}

GList *purple_pounces_get_all_for_ui(const char *ui)
{
	GList *list = NULL, *iter;
	g_return_val_if_fail(ui != NULL, NULL);

	for (iter = pounces; iter; iter = iter->next) {
		PurplePounce *pounce = iter->data;
		if (purple_strequal(pounce->ui_type, ui))
			list = g_list_prepend(list, pounce);
	}
	list = g_list_reverse(list);
	return list;
}

static void
free_pounce_handler(gpointer user_data)
{
	PurplePounceHandler *handler = (PurplePounceHandler *)user_data;

	g_free(handler->ui);
	g_free(handler);
}

static void
buddy_state_cb(PurpleBuddy *buddy, PurplePounceEvent event)
{
	PurpleAccount *account = purple_buddy_get_account(buddy);
	const gchar *name = purple_buddy_get_name(buddy);

	purple_pounce_execute(account, name, event);
}

static void
buddy_status_changed_cb(PurpleBuddy *buddy, PurpleStatus *old_status,
                        PurpleStatus *status)
{
	PurpleAccount *account = purple_buddy_get_account(buddy);
	const gchar *name = purple_buddy_get_name(buddy);
	gboolean old_available, available;

	available = purple_status_is_available(status);
	old_available = purple_status_is_available(old_status);

	if (available && !old_available)
		purple_pounce_execute(account, name, PURPLE_POUNCE_AWAY_RETURN);
	else if (!available && old_available)
		purple_pounce_execute(account, name, PURPLE_POUNCE_AWAY);
}

static void
buddy_idle_changed_cb(PurpleBuddy *buddy, gboolean old_idle, gboolean idle)
{
	PurpleAccount *account = purple_buddy_get_account(buddy);
	const gchar *name = purple_buddy_get_name(buddy);

	if (idle && !old_idle)
		purple_pounce_execute(account, name, PURPLE_POUNCE_IDLE);
	else if (!idle && old_idle)
		purple_pounce_execute(account, name, PURPLE_POUNCE_IDLE_RETURN);
}

static void
buddy_typing_cb(PurpleAccount *account, const char *name, void *data)
{
	PurpleConversation *conv;

	conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, name, account);
	if (conv != NULL)
	{
		PurpleTypingState state;
		PurplePounceEvent event;

		state = purple_conv_im_get_typing_state(PURPLE_CONV_IM(conv));
		if (state == PURPLE_TYPED)
			event = PURPLE_POUNCE_TYPED;
		else if (state == PURPLE_NOT_TYPING)
			event = PURPLE_POUNCE_TYPING_STOPPED;
		else
			event = PURPLE_POUNCE_TYPING;

		purple_pounce_execute(account, name, event);
	}
}

static void
received_message_cb(PurpleAccount *account, const char *name, void *data)
{
	purple_pounce_execute(account, name, PURPLE_POUNCE_MESSAGE_RECEIVED);
}

void *
purple_pounces_get_handle(void)
{
	static int pounce_handle;

	return &pounce_handle;
}

void
purple_pounces_init(void)
{
	void *handle       = purple_pounces_get_handle();
	void *blist_handle = purple_blist_get_handle();
	void *conv_handle  = purple_conversations_get_handle();

	pounce_handlers = g_hash_table_new_full(g_str_hash, g_str_equal,
											g_free, free_pounce_handler);

	purple_signal_connect(blist_handle, "buddy-idle-changed",
	                    handle, PURPLE_CALLBACK(buddy_idle_changed_cb), NULL);
	purple_signal_connect(blist_handle, "buddy-status-changed",
	                    handle, PURPLE_CALLBACK(buddy_status_changed_cb), NULL);
	purple_signal_connect(blist_handle, "buddy-signed-on",
						handle, PURPLE_CALLBACK(buddy_state_cb),
						GINT_TO_POINTER(PURPLE_POUNCE_SIGNON));
	purple_signal_connect(blist_handle, "buddy-signed-off",
						handle, PURPLE_CALLBACK(buddy_state_cb),
						GINT_TO_POINTER(PURPLE_POUNCE_SIGNOFF));

	purple_signal_connect(conv_handle, "buddy-typing",
						handle, PURPLE_CALLBACK(buddy_typing_cb), NULL);
	purple_signal_connect(conv_handle, "buddy-typed",
						handle, PURPLE_CALLBACK(buddy_typing_cb), NULL);
	purple_signal_connect(conv_handle, "buddy-typing-stopped",
						handle, PURPLE_CALLBACK(buddy_typing_cb), NULL);

	purple_signal_connect(conv_handle, "received-im-msg",
						handle, PURPLE_CALLBACK(received_message_cb), NULL);
}

void
purple_pounces_uninit()
{
	if (save_timer != 0)
	{
		purple_timeout_remove(save_timer);
		save_timer = 0;
		sync_pounces();
	}

	purple_signals_disconnect_by_handle(purple_pounces_get_handle());

	g_hash_table_destroy(pounce_handlers);
	pounce_handlers = NULL;
}
