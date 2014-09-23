/*
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
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <glib.h>
#include "internal.h"
#include "prefs.h"
#include "debug.h"
#include "util.h"

#ifdef _WIN32
#include "win32dep.h"
#endif

struct pref_cb {
	PurplePrefCallback func;
	gpointer data;
	guint id;
	void *handle;
};

/* TODO: This should use PurpleValues? */
struct purple_pref {
	PurplePrefType type;
	char *name;
	union {
		gpointer generic;
		gboolean boolean;
		int integer;
		char *string;
		GList *stringlist;
	} value;
	GSList *callbacks;
	struct purple_pref *parent;
	struct purple_pref *sibling;
	struct purple_pref *first_child;
};


static struct purple_pref prefs = {
	PURPLE_PREF_NONE,
	NULL,
	{ NULL },
	NULL,
	NULL,
	NULL,
	NULL
};

static GHashTable *prefs_hash = NULL;
static guint       save_timer = 0;
static gboolean    prefs_loaded = FALSE;


/*********************************************************************
 * Private utility functions                                         *
 *********************************************************************/

static struct
purple_pref *find_pref(const char *name)
{
	g_return_val_if_fail(name != NULL && name[0] == '/', NULL);

	if (name[1] == '\0')
		return &prefs;
	else
	{
		/* When we're initializing, the debug system is
		 * initialized before the prefs system, but debug
		 * calls will end up calling prefs functions, so we
		 * need to deal cleanly here. */
		if (prefs_hash)
			return g_hash_table_lookup(prefs_hash, name);
		else
			return NULL;
	}
}


/*********************************************************************
 * Writing to disk                                                   *
 *********************************************************************/

/*
 * This function recursively creates the xmlnode tree from the prefs
 * tree structure.  Yay recursion!
 */
static void
pref_to_xmlnode(xmlnode *parent, struct purple_pref *pref)
{
	xmlnode *node, *childnode;
	struct purple_pref *child;
	char buf[21];
	GList *cur;

	/* Create a new node */
	node = xmlnode_new_child(parent, "pref");
	xmlnode_set_attrib(node, "name", pref->name);

	/* Set the type of this node (if type == PURPLE_PREF_NONE then do nothing) */
	if (pref->type == PURPLE_PREF_INT) {
		xmlnode_set_attrib(node, "type", "int");
		g_snprintf(buf, sizeof(buf), "%d", pref->value.integer);
		xmlnode_set_attrib(node, "value", buf);
	}
	else if (pref->type == PURPLE_PREF_STRING) {
		xmlnode_set_attrib(node, "type", "string");
		xmlnode_set_attrib(node, "value", pref->value.string ? pref->value.string : "");
	}
	else if (pref->type == PURPLE_PREF_STRING_LIST) {
		xmlnode_set_attrib(node, "type", "stringlist");
		for (cur = pref->value.stringlist; cur != NULL; cur = cur->next)
		{
			childnode = xmlnode_new_child(node, "item");
			xmlnode_set_attrib(childnode, "value", cur->data ? cur->data : "");
		}
	}
	else if (pref->type == PURPLE_PREF_PATH) {
		char *encoded = g_filename_to_utf8(pref->value.string ? pref->value.string : "", -1, NULL, NULL, NULL);
		xmlnode_set_attrib(node, "type", "path");
		xmlnode_set_attrib(node, "value", encoded);
		g_free(encoded);
	}
	else if (pref->type == PURPLE_PREF_PATH_LIST) {
		xmlnode_set_attrib(node, "type", "pathlist");
		for (cur = pref->value.stringlist; cur != NULL; cur = cur->next)
		{
			char *encoded = g_filename_to_utf8(cur->data ? cur->data : "", -1, NULL, NULL, NULL);
			childnode = xmlnode_new_child(node, "item");
			xmlnode_set_attrib(childnode, "value", encoded);
			g_free(encoded);
		}
	}
	else if (pref->type == PURPLE_PREF_BOOLEAN) {
		xmlnode_set_attrib(node, "type", "bool");
		g_snprintf(buf, sizeof(buf), "%d", pref->value.boolean);
		xmlnode_set_attrib(node, "value", buf);
	}

	/* All My Children */
	for (child = pref->first_child; child != NULL; child = child->sibling)
		pref_to_xmlnode(node, child);
}

static xmlnode *
prefs_to_xmlnode(void)
{
	xmlnode *node;
	struct purple_pref *pref, *child;

	pref = &prefs;

	/* Create the root preference node */
	node = xmlnode_new("pref");
	xmlnode_set_attrib(node, "version", "1");
	xmlnode_set_attrib(node, "name", "/");

	/* All My Children */
	for (child = pref->first_child; child != NULL; child = child->sibling)
		pref_to_xmlnode(node, child);

	return node;
}

static void
sync_prefs(void)
{
	xmlnode *node;
	char *data;

	if (!prefs_loaded)
	{
		/*
		 * TODO: Call schedule_prefs_save()?  Ideally we wouldn't need to.
		 * (prefs.xml should be loaded when purple_prefs_init is called)
		 */
		purple_debug_error("prefs", "Attempted to save prefs before "
						 "they were read!\n");
		return;
	}

	node = prefs_to_xmlnode();
	data = xmlnode_to_formatted_str(node, NULL);
	purple_util_write_data_to_file("prefs.xml", data, -1);
	g_free(data);
	xmlnode_free(node);
}

static gboolean
save_cb(gpointer data)
{
	sync_prefs();
	save_timer = 0;
	return FALSE;
}

static void
schedule_prefs_save(void)
{
	if (save_timer == 0)
		save_timer = purple_timeout_add_seconds(5, save_cb, NULL);
}


/*********************************************************************
 * Reading from disk                                                 *
 *********************************************************************/

static GList *prefs_stack = NULL;

static void
prefs_start_element_handler (GMarkupParseContext *context,
		const gchar *element_name,
		const gchar **attribute_names,
		const gchar **attribute_values,
		gpointer user_data,
		GError **error)
{
	PurplePrefType pref_type = PURPLE_PREF_NONE;
	int i;
	const char *pref_name = NULL, *pref_value = NULL;
	GString *pref_name_full;
	GList *tmp;

	if(!purple_strequal(element_name, "pref") &&
	   !purple_strequal(element_name, "item"))
		return;

	for(i = 0; attribute_names[i]; i++) {
		if(purple_strequal(attribute_names[i], "name")) {
			pref_name = attribute_values[i];
		} else if(purple_strequal(attribute_names[i], "type")) {
			if(purple_strequal(attribute_values[i], "bool"))
				pref_type = PURPLE_PREF_BOOLEAN;
			else if(purple_strequal(attribute_values[i], "int"))
				pref_type = PURPLE_PREF_INT;
			else if(purple_strequal(attribute_values[i], "string"))
				pref_type = PURPLE_PREF_STRING;
			else if(purple_strequal(attribute_values[i], "stringlist"))
				pref_type = PURPLE_PREF_STRING_LIST;
			else if(purple_strequal(attribute_values[i], "path"))
				pref_type = PURPLE_PREF_PATH;
			else if(purple_strequal(attribute_values[i], "pathlist"))
				pref_type = PURPLE_PREF_PATH_LIST;
			else
				return;
		} else if(purple_strequal(attribute_names[i], "value")) {
			pref_value = attribute_values[i];
		}
	}

	if ((pref_type == PURPLE_PREF_BOOLEAN || pref_type == PURPLE_PREF_INT) &&
			pref_value == NULL) {
		/* Missing a value attribute */
		return;
	}

	if(purple_strequal(element_name, "item")) {
		struct purple_pref *pref;

		pref_name_full = g_string_new("");

		for(tmp = prefs_stack; tmp; tmp = tmp->next) {
			pref_name_full = g_string_prepend(pref_name_full, tmp->data);
			pref_name_full = g_string_prepend_c(pref_name_full, '/');
		}

		pref = find_pref(pref_name_full->str);

		if(pref) {
			if(pref->type == PURPLE_PREF_STRING_LIST) {
				pref->value.stringlist = g_list_append(pref->value.stringlist,
						g_strdup(pref_value));
			} else if(pref->type == PURPLE_PREF_PATH_LIST) {
				pref->value.stringlist = g_list_append(pref->value.stringlist,
						g_filename_from_utf8(pref_value, -1, NULL, NULL, NULL));
			}
		}
		g_string_free(pref_name_full, TRUE);
	} else {
		char *decoded;

		if(!pref_name || purple_strequal(pref_name, "/"))
			return;

		pref_name_full = g_string_new(pref_name);

		for(tmp = prefs_stack; tmp; tmp = tmp->next) {
			pref_name_full = g_string_prepend_c(pref_name_full, '/');
			pref_name_full = g_string_prepend(pref_name_full, tmp->data);
		}

		pref_name_full = g_string_prepend_c(pref_name_full, '/');

		switch(pref_type) {
			case PURPLE_PREF_NONE:
				purple_prefs_add_none(pref_name_full->str);
				break;
			case PURPLE_PREF_BOOLEAN:
				purple_prefs_set_bool(pref_name_full->str, atoi(pref_value));
				break;
			case PURPLE_PREF_INT:
				purple_prefs_set_int(pref_name_full->str, atoi(pref_value));
				break;
			case PURPLE_PREF_STRING:
				purple_prefs_set_string(pref_name_full->str, pref_value);
				break;
			case PURPLE_PREF_STRING_LIST:
				purple_prefs_set_string_list(pref_name_full->str, NULL);
				break;
			case PURPLE_PREF_PATH:
				if (pref_value) {
					decoded = g_filename_from_utf8(pref_value, -1, NULL, NULL, NULL);
					purple_prefs_set_path(pref_name_full->str, decoded);
					g_free(decoded);
				} else {
					purple_prefs_set_path(pref_name_full->str, NULL);
				}
				break;
			case PURPLE_PREF_PATH_LIST:
				purple_prefs_set_path_list(pref_name_full->str, NULL);
				break;
		}
		prefs_stack = g_list_prepend(prefs_stack, g_strdup(pref_name));
		g_string_free(pref_name_full, TRUE);
	}
}

static void
prefs_end_element_handler(GMarkupParseContext *context,
						  const gchar *element_name,
						  gpointer user_data, GError **error)
{
	if(prefs_stack && purple_strequal(element_name, "pref")) {
		g_free(prefs_stack->data);
		prefs_stack = g_list_delete_link(prefs_stack, prefs_stack);
	}
}

static GMarkupParser prefs_parser = {
	prefs_start_element_handler,
	prefs_end_element_handler,
	NULL,
	NULL,
	NULL
};

gboolean
purple_prefs_load()
{
	gchar *filename = g_build_filename(purple_user_dir(), "prefs.xml", NULL);
	gchar *contents = NULL;
	gsize length;
	GMarkupParseContext *context;
	GError *error = NULL;

	if (!filename) {
		prefs_loaded = TRUE;
		return FALSE;
	}

	purple_debug_info("prefs", "Reading %s\n", filename);

	if(!g_file_get_contents(filename, &contents, &length, &error)) {
#ifdef _WIN32
		gchar *common_appdata = wpurple_get_special_folder(CSIDL_COMMON_APPDATA);
#endif
		g_free(filename);
		g_error_free(error);

		error = NULL;

#ifdef _WIN32
		filename = g_build_filename(common_appdata ? common_appdata : "", "purple", "prefs.xml", NULL);
		g_free(common_appdata);
#else
		filename = g_build_filename(SYSCONFDIR, "purple", "prefs.xml", NULL);
#endif

		purple_debug_info("prefs", "Reading %s\n", filename);

		if (!g_file_get_contents(filename, &contents, &length, &error)) {
			purple_debug_error("prefs", "Error reading prefs: %s\n",
					error->message);
			g_error_free(error);
			g_free(filename);
			prefs_loaded = TRUE;

			return FALSE;
		}
	}

	context = g_markup_parse_context_new(&prefs_parser, 0, NULL, NULL);

	if(!g_markup_parse_context_parse(context, contents, length, NULL)) {
		g_markup_parse_context_free(context);
		g_free(contents);
		g_free(filename);
		prefs_loaded = TRUE;

		return FALSE;
	}

	if(!g_markup_parse_context_end_parse(context, NULL)) {
		purple_debug_error("prefs", "Error parsing %s\n", filename);
		g_markup_parse_context_free(context);
		g_free(contents);
		g_free(filename);
		prefs_loaded = TRUE;

		return FALSE;
	}

	purple_debug_info("prefs", "Finished reading %s\n", filename);
	g_markup_parse_context_free(context);
	g_free(contents);
	g_free(filename);
	prefs_loaded = TRUE;

	return TRUE;
}



static void
prefs_save_cb(const char *name, PurplePrefType type, gconstpointer val,
			  gpointer user_data)
{

	if(!prefs_loaded)
		return;

	purple_debug_misc("prefs", "%s changed, scheduling save.\n", name);

	schedule_prefs_save();
}

static char *
get_path_dirname(const char *name)
{
	char *c, *str;

	str = g_strdup(name);

	if ((c = strrchr(str, '/')) != NULL) {
		*c = '\0';

		if (*str == '\0') {
			g_free(str);

			str = g_strdup("/");
		}
	}
	else {
		g_free(str);

		str = g_strdup(".");
	}

	return str;
}

static char *
get_path_basename(const char *name)
{
	const char *c;

	if ((c = strrchr(name, '/')) != NULL)
		return g_strdup(c + 1);

	return g_strdup(name);
}

static char *
pref_full_name(struct purple_pref *pref)
{
	GString *name;
	struct purple_pref *parent;

	if(!pref)
		return NULL;

	if(pref == &prefs)
		return g_strdup("/");

	name = g_string_new(pref->name);

	for(parent = pref->parent; parent && parent->name; parent = parent->parent) {
		name = g_string_prepend_c(name, '/');
		name = g_string_prepend(name, parent->name);
	}
	name = g_string_prepend_c(name, '/');
	return g_string_free(name, FALSE);
}

static struct purple_pref *
find_pref_parent(const char *name)
{
	char *parent_name = get_path_dirname(name);
	struct purple_pref *ret = &prefs;

	if(!purple_strequal(parent_name, "/")) {
		ret = find_pref(parent_name);
	}

	g_free(parent_name);
	return ret;
}

static void
free_pref_value(struct purple_pref *pref)
{
	switch(pref->type) {
		case PURPLE_PREF_BOOLEAN:
			pref->value.boolean = FALSE;
			break;
		case PURPLE_PREF_INT:
			pref->value.integer = 0;
			break;
		case PURPLE_PREF_STRING:
		case PURPLE_PREF_PATH:
			g_free(pref->value.string);
			pref->value.string = NULL;
			break;
		case PURPLE_PREF_STRING_LIST:
		case PURPLE_PREF_PATH_LIST:
			{
				g_list_foreach(pref->value.stringlist, (GFunc)g_free, NULL);
				g_list_free(pref->value.stringlist);
			} break;
		case PURPLE_PREF_NONE:
			break;
	}
}

static struct purple_pref *
add_pref(PurplePrefType type, const char *name)
{
	struct purple_pref *parent;
	struct purple_pref *me;
	struct purple_pref *sibling;
	char *my_name;

	parent = find_pref_parent(name);

	if(!parent)
		return NULL;

	my_name = get_path_basename(name);

	for(sibling = parent->first_child; sibling; sibling = sibling->sibling) {
		if(purple_strequal(sibling->name, my_name)) {
			g_free(my_name);
			return NULL;
		}
	}

	me = g_new0(struct purple_pref, 1);
	me->type = type;
	me->name = my_name;

	me->parent = parent;
	if(parent->first_child) {
		/* blatant abuse of a for loop */
		for(sibling = parent->first_child; sibling->sibling;
				sibling = sibling->sibling);
		sibling->sibling = me;
	} else {
		parent->first_child = me;
	}

	g_hash_table_insert(prefs_hash, g_strdup(name), (gpointer)me);

	return me;
}

void
purple_prefs_add_none(const char *name)
{
	add_pref(PURPLE_PREF_NONE, name);
}

void
purple_prefs_add_bool(const char *name, gboolean value)
{
	struct purple_pref *pref = add_pref(PURPLE_PREF_BOOLEAN, name);

	if(!pref)
		return;

	pref->value.boolean = value;
}

void
purple_prefs_add_int(const char *name, int value)
{
	struct purple_pref *pref = add_pref(PURPLE_PREF_INT, name);

	if(!pref)
		return;

	pref->value.integer = value;
}

void
purple_prefs_add_string(const char *name, const char *value)
{
	struct purple_pref *pref;

	if(value != NULL && !g_utf8_validate(value, -1, NULL)) {
		purple_debug_error("prefs", "purple_prefs_add_string: Cannot store invalid UTF8 for string pref %s\n", name);
		return;
	}

	pref = add_pref(PURPLE_PREF_STRING, name);

	if(!pref)
		return;

	pref->value.string = g_strdup(value);
}

void
purple_prefs_add_string_list(const char *name, GList *value)
{
	struct purple_pref *pref = add_pref(PURPLE_PREF_STRING_LIST, name);
	GList *tmp;

	if(!pref)
		return;

	for(tmp = value; tmp; tmp = tmp->next) {
		if(tmp->data != NULL && !g_utf8_validate(tmp->data, -1, NULL)) {
			purple_debug_error("prefs", "purple_prefs_add_string_list: Skipping invalid UTF8 for string list pref %s\n", name);
			continue;
		}
		pref->value.stringlist = g_list_append(pref->value.stringlist,
				g_strdup(tmp->data));
	}
}

void
purple_prefs_add_path(const char *name, const char *value)
{
	struct purple_pref *pref = add_pref(PURPLE_PREF_PATH, name);

	if(!pref)
		return;

	pref->value.string = g_strdup(value);
}

void
purple_prefs_add_path_list(const char *name, GList *value)
{
	struct purple_pref *pref = add_pref(PURPLE_PREF_PATH_LIST, name);
	GList *tmp;

	if(!pref)
		return;

	for(tmp = value; tmp; tmp = tmp->next)
		pref->value.stringlist = g_list_append(pref->value.stringlist,
				g_strdup(tmp->data));
}


static void
remove_pref(struct purple_pref *pref)
{
	char *name;
	GSList *l;

	if(!pref)
		return;

	while(pref->first_child)
		remove_pref(pref->first_child);

	if(pref == &prefs)
		return;

	if(pref->parent->first_child == pref) {
		pref->parent->first_child = pref->sibling;
	} else {
		struct purple_pref *sib = pref->parent->first_child;
		while(sib && sib->sibling != pref)
			sib = sib->sibling;
		if(sib)
			sib->sibling = pref->sibling;
	}

	name = pref_full_name(pref);

	if (prefs_loaded)
		purple_debug_info("prefs", "removing pref %s\n", name);

	g_hash_table_remove(prefs_hash, name);
	g_free(name);

	free_pref_value(pref);

	while((l = pref->callbacks) != NULL) {
		pref->callbacks = pref->callbacks->next;
		g_free(l->data);
		g_slist_free_1(l);
	}
	g_free(pref->name);
	g_free(pref);
}

void
purple_prefs_remove(const char *name)
{
	struct purple_pref *pref = find_pref(name);

	if(!pref)
		return;

	remove_pref(pref);
}

void
purple_prefs_destroy()
{
	purple_prefs_remove("/");
}

static void
do_callbacks(const char* name, struct purple_pref *pref)
{
	GSList *cbs;
	struct purple_pref *cb_pref;
	for(cb_pref = pref; cb_pref; cb_pref = cb_pref->parent) {
		for(cbs = cb_pref->callbacks; cbs; cbs = cbs->next) {
			struct pref_cb *cb = cbs->data;
			cb->func(name, pref->type, pref->value.generic, cb->data);
		}
	}
}

void
purple_prefs_trigger_callback(const char *name)
{
	struct purple_pref *pref = find_pref(name);

	if(!pref) {
		purple_debug_error("prefs",
				"purple_prefs_trigger_callback: Unknown pref %s\n", name);
		return;
	}

	do_callbacks(name, pref);
}

void
purple_prefs_set_generic(const char *name, gpointer value)
{
	struct purple_pref *pref = find_pref(name);

	if(!pref) {
		purple_debug_error("prefs",
				"purple_prefs_set_generic: Unknown pref %s\n", name);
		return;
	}

	pref->value.generic = value;
	do_callbacks(name, pref);
}

void
purple_prefs_set_bool(const char *name, gboolean value)
{
	struct purple_pref *pref = find_pref(name);

	if(pref) {
		if(pref->type != PURPLE_PREF_BOOLEAN) {
			purple_debug_error("prefs",
					"purple_prefs_set_bool: %s not a boolean pref\n", name);
			return;
		}

		if(pref->value.boolean != value) {
			pref->value.boolean = value;
			do_callbacks(name, pref);
		}
	} else {
		purple_prefs_add_bool(name, value);
	}
}

void
purple_prefs_set_int(const char *name, int value)
{
	struct purple_pref *pref = find_pref(name);

	if(pref) {
		if(pref->type != PURPLE_PREF_INT) {
			purple_debug_error("prefs",
					"purple_prefs_set_int: %s not an integer pref\n", name);
			return;
		}

		if(pref->value.integer != value) {
			pref->value.integer = value;
			do_callbacks(name, pref);
		}
	} else {
		purple_prefs_add_int(name, value);
	}
}

void
purple_prefs_set_string(const char *name, const char *value)
{
	struct purple_pref *pref = find_pref(name);

	if(value != NULL && !g_utf8_validate(value, -1, NULL)) {
		purple_debug_error("prefs", "purple_prefs_set_string: Cannot store invalid UTF8 for string pref %s\n", name);
		return;
	}

	if(pref) {
		if(pref->type != PURPLE_PREF_STRING && pref->type != PURPLE_PREF_PATH) {
			purple_debug_error("prefs",
					"purple_prefs_set_string: %s not a string pref\n", name);
			return;
		}

		if (!purple_strequal(pref->value.string, value)) {
			g_free(pref->value.string);
			pref->value.string = g_strdup(value);
			do_callbacks(name, pref);
		}
	} else {
		purple_prefs_add_string(name, value);
	}
}

void
purple_prefs_set_string_list(const char *name, GList *value)
{
	struct purple_pref *pref = find_pref(name);
	if(pref) {
		GList *tmp;

		if(pref->type != PURPLE_PREF_STRING_LIST) {
			purple_debug_error("prefs",
					"purple_prefs_set_string_list: %s not a string list pref\n",
					name);
			return;
		}

		g_list_foreach(pref->value.stringlist, (GFunc)g_free, NULL);
		g_list_free(pref->value.stringlist);
		pref->value.stringlist = NULL;

		for(tmp = value; tmp; tmp = tmp->next) {
			if(tmp->data != NULL && !g_utf8_validate(tmp->data, -1, NULL)) {
				purple_debug_error("prefs", "purple_prefs_set_string_list: Skipping invalid UTF8 for string list pref %s\n", name);
				continue;
			}
			pref->value.stringlist = g_list_prepend(pref->value.stringlist,
					g_strdup(tmp->data));
		}
		pref->value.stringlist = g_list_reverse(pref->value.stringlist);

		do_callbacks(name, pref);

	} else {
		purple_prefs_add_string_list(name, value);
	}
}

void
purple_prefs_set_path(const char *name, const char *value)
{
	struct purple_pref *pref = find_pref(name);

	if(pref) {
		if(pref->type != PURPLE_PREF_PATH) {
			purple_debug_error("prefs",
					"purple_prefs_set_path: %s not a path pref\n", name);
			return;
		}

		if (!purple_strequal(pref->value.string, value)) {
			g_free(pref->value.string);
			pref->value.string = g_strdup(value);
			do_callbacks(name, pref);
		}
	} else {
		purple_prefs_add_path(name, value);
	}
}

void
purple_prefs_set_path_list(const char *name, GList *value)
{
	struct purple_pref *pref = find_pref(name);
	if(pref) {
		GList *tmp;

		if(pref->type != PURPLE_PREF_PATH_LIST) {
			purple_debug_error("prefs",
					"purple_prefs_set_path_list: %s not a path list pref\n",
					name);
			return;
		}

		g_list_foreach(pref->value.stringlist, (GFunc)g_free, NULL);
		g_list_free(pref->value.stringlist);
		pref->value.stringlist = NULL;

		for(tmp = value; tmp; tmp = tmp->next)
			pref->value.stringlist = g_list_prepend(pref->value.stringlist,
					g_strdup(tmp->data));
		pref->value.stringlist = g_list_reverse(pref->value.stringlist);

		do_callbacks(name, pref);

	} else {
		purple_prefs_add_path_list(name, value);
	}
}


gboolean
purple_prefs_exists(const char *name)
{
	struct purple_pref *pref = find_pref(name);

	if (pref != NULL)
		return TRUE;

	return FALSE;
}

PurplePrefType
purple_prefs_get_type(const char *name)
{
	struct purple_pref *pref = find_pref(name);

	if (pref == NULL)
		return PURPLE_PREF_NONE;

	return (pref->type);
}

gboolean
purple_prefs_get_bool(const char *name)
{
	struct purple_pref *pref = find_pref(name);

	if(!pref) {
		purple_debug_error("prefs",
				"purple_prefs_get_bool: Unknown pref %s\n", name);
		return FALSE;
	} else if(pref->type != PURPLE_PREF_BOOLEAN) {
		purple_debug_error("prefs",
				"purple_prefs_get_bool: %s not a boolean pref\n", name);
		return FALSE;
	}

	return pref->value.boolean;
}

int
purple_prefs_get_int(const char *name)
{
	struct purple_pref *pref = find_pref(name);

	if(!pref) {
		purple_debug_error("prefs",
				"purple_prefs_get_int: Unknown pref %s\n", name);
		return 0;
	} else if(pref->type != PURPLE_PREF_INT) {
		purple_debug_error("prefs",
				"purple_prefs_get_int: %s not an integer pref\n", name);
		return 0;
	}

	return pref->value.integer;
}

const char *
purple_prefs_get_string(const char *name)
{
	struct purple_pref *pref = find_pref(name);

	if(!pref) {
		purple_debug_error("prefs",
				"purple_prefs_get_string: Unknown pref %s\n", name);
		return NULL;
	} else if(pref->type != PURPLE_PREF_STRING) {
		purple_debug_error("prefs",
				"purple_prefs_get_string: %s not a string pref\n", name);
		return NULL;
	}

	return pref->value.string;
}

GList *
purple_prefs_get_string_list(const char *name)
{
	struct purple_pref *pref = find_pref(name);
	GList *ret = NULL, *tmp;

	if(!pref) {
		purple_debug_error("prefs",
				"purple_prefs_get_string_list: Unknown pref %s\n", name);
		return NULL;
	} else if(pref->type != PURPLE_PREF_STRING_LIST) {
		purple_debug_error("prefs",
				"purple_prefs_get_string_list: %s not a string list pref\n", name);
		return NULL;
	}

	for(tmp = pref->value.stringlist; tmp; tmp = tmp->next)
		ret = g_list_prepend(ret, g_strdup(tmp->data));
	ret = g_list_reverse(ret);

	return ret;
}

const char *
purple_prefs_get_path(const char *name)
{
	struct purple_pref *pref = find_pref(name);

	if(!pref) {
		purple_debug_error("prefs",
				"purple_prefs_get_path: Unknown pref %s\n", name);
		return NULL;
	} else if(pref->type != PURPLE_PREF_PATH) {
		purple_debug_error("prefs",
				"purple_prefs_get_path: %s not a path pref\n", name);
		return NULL;
	}

	return pref->value.string;
}

GList *
purple_prefs_get_path_list(const char *name)
{
	struct purple_pref *pref = find_pref(name);
	GList *ret = NULL, *tmp;

	if(!pref) {
		purple_debug_error("prefs",
				"purple_prefs_get_path_list: Unknown pref %s\n", name);
		return NULL;
	} else if(pref->type != PURPLE_PREF_PATH_LIST) {
		purple_debug_error("prefs",
				"purple_prefs_get_path_list: %s not a path list pref\n", name);
		return NULL;
	}

	for(tmp = pref->value.stringlist; tmp; tmp = tmp->next)
		ret = g_list_prepend(ret, g_strdup(tmp->data));
	ret = g_list_reverse(ret);

	return ret;
}

static void
purple_prefs_rename_node(struct purple_pref *oldpref, struct purple_pref *newpref)
{
	struct purple_pref *child, *next;
	char *oldname, *newname;

	/* if we're a parent, rename the kids first */
	for(child = oldpref->first_child; child != NULL; child = next)
	{
		struct purple_pref *newchild;
		next = child->sibling;
		for(newchild = newpref->first_child; newchild != NULL; newchild = newchild->sibling)
		{
			if(purple_strequal(child->name, newchild->name))
			{
				purple_prefs_rename_node(child, newchild);
				break;
			}
		}
		if(newchild == NULL) {
			/* no rename happened, we weren't able to find the new pref */
			char *tmpname = pref_full_name(child);
			purple_debug_error("prefs", "Unable to find rename pref for %s\n", tmpname);
			g_free(tmpname);
		}
	}

	oldname = pref_full_name(oldpref);
	newname = pref_full_name(newpref);

	if (oldpref->type != newpref->type)
	{
		purple_debug_error("prefs", "Unable to rename %s to %s: differing types\n", oldname, newname);
		g_free(oldname);
		g_free(newname);
		return;
	}

	purple_debug_info("prefs", "Renaming %s to %s\n", oldname, newname);
	g_free(oldname);

	switch(oldpref->type) {
		case PURPLE_PREF_NONE:
			break;
		case PURPLE_PREF_BOOLEAN:
			purple_prefs_set_bool(newname, oldpref->value.boolean);
			break;
		case PURPLE_PREF_INT:
			purple_prefs_set_int(newname, oldpref->value.integer);
			break;
		case PURPLE_PREF_STRING:
			purple_prefs_set_string(newname, oldpref->value.string);
			break;
		case PURPLE_PREF_STRING_LIST:
			purple_prefs_set_string_list(newname, oldpref->value.stringlist);
			break;
		case PURPLE_PREF_PATH:
			purple_prefs_set_path(newname, oldpref->value.string);
			break;
		case PURPLE_PREF_PATH_LIST:
			purple_prefs_set_path_list(newname, oldpref->value.stringlist);
			break;
	}
	g_free(newname);

	remove_pref(oldpref);
}

void
purple_prefs_rename(const char *oldname, const char *newname)
{
	struct purple_pref *oldpref, *newpref;

	oldpref = find_pref(oldname);

	/* it's already been renamed, call off the dogs */
	if(!oldpref)
		return;

	newpref = find_pref(newname);

	if (newpref == NULL)
	{
		purple_debug_error("prefs", "Unable to rename %s to %s: new pref not created\n", oldname, newname);
		return;
	}

	purple_prefs_rename_node(oldpref, newpref);
}

void
purple_prefs_rename_boolean_toggle(const char *oldname, const char *newname)
{
		struct purple_pref *oldpref, *newpref;

		oldpref = find_pref(oldname);

		/* it's already been renamed, call off the cats */
		if(!oldpref)
			return;

		if (oldpref->type != PURPLE_PREF_BOOLEAN)
		{
			purple_debug_error("prefs", "Unable to rename %s to %s: old pref not a boolean\n", oldname, newname);
			return;
		}

		if (oldpref->first_child != NULL) /* can't rename parents */
		{
			purple_debug_error("prefs", "Unable to rename %s to %s: can't rename parents\n", oldname, newname);
			return;
		}


		newpref = find_pref(newname);

		if (newpref == NULL)
		{
			purple_debug_error("prefs", "Unable to rename %s to %s: new pref not created\n", oldname, newname);
			return;
		}

		if (oldpref->type != newpref->type)
		{
			purple_debug_error("prefs", "Unable to rename %s to %s: differing types\n", oldname, newname);
			return;
		}

		purple_debug_info("prefs", "Renaming and toggling %s to %s\n", oldname, newname);
		purple_prefs_set_bool(newname, !(oldpref->value.boolean));

		remove_pref(oldpref);
}

guint
purple_prefs_connect_callback(void *handle, const char *name, PurplePrefCallback func, gpointer data)
{
	struct purple_pref *pref;
	struct pref_cb *cb;
	static guint cb_id = 0;

	g_return_val_if_fail(name != NULL, 0);
	g_return_val_if_fail(func != NULL, 0);

	pref = find_pref(name);
	if (pref == NULL) {
		purple_debug_error("prefs", "purple_prefs_connect_callback: Unknown pref %s\n", name);
		return 0;
	}

	cb = g_new0(struct pref_cb, 1);

	cb->func = func;
	cb->data = data;
	cb->id = ++cb_id;
	cb->handle = handle;

	pref->callbacks = g_slist_append(pref->callbacks, cb);

	return cb->id;
}

static gboolean
disco_callback_helper(struct purple_pref *pref, guint callback_id)
{
	GSList *cbs;
	struct purple_pref *child;

	if(!pref)
		return FALSE;

	for(cbs = pref->callbacks; cbs; cbs = cbs->next) {
		struct pref_cb *cb = cbs->data;
		if(cb->id == callback_id) {
			pref->callbacks = g_slist_delete_link(pref->callbacks, cbs);
			g_free(cb);
			return TRUE;
		}
	}

	for(child = pref->first_child; child; child = child->sibling) {
		if(disco_callback_helper(child, callback_id))
			return TRUE;
	}

	return FALSE;
}

void
purple_prefs_disconnect_callback(guint callback_id)
{
	disco_callback_helper(&prefs, callback_id);
}

static void
disco_callback_helper_handle(struct purple_pref *pref, void *handle)
{
	GSList *cbs;
	struct purple_pref *child;

	if(!pref)
		return;

	cbs = pref->callbacks;
	while (cbs != NULL) {
		struct pref_cb *cb = cbs->data;
		if(cb->handle == handle) {
			pref->callbacks = g_slist_delete_link(pref->callbacks, cbs);
			g_free(cb);
			cbs = pref->callbacks;
		} else
			cbs = cbs->next;
	}

	for(child = pref->first_child; child; child = child->sibling)
		disco_callback_helper_handle(child, handle);
}

void
purple_prefs_disconnect_by_handle(void *handle)
{
	g_return_if_fail(handle != NULL);

	disco_callback_helper_handle(&prefs, handle);
}

GList *
purple_prefs_get_children_names(const char *name)
{
	GList * list = NULL;
	struct purple_pref *pref = find_pref(name), *child;
	char sep[2] = "\0\0";;

	if (pref == NULL)
		return NULL;

	if (name[strlen(name) - 1] != '/')
		sep[0] = '/';
	for (child = pref->first_child; child; child = child->sibling) {
		list = g_list_append(list, g_strdup_printf("%s%s%s", name, sep, child->name));
	}
	return list;
}

void
purple_prefs_update_old()
{
	purple_prefs_rename("/core", "/purple");

	/* Remove some no-longer-used prefs */
	purple_prefs_remove("/purple/away/auto_response/enabled");
	purple_prefs_remove("/purple/away/auto_response/idle_only");
	purple_prefs_remove("/purple/away/auto_response/in_active_conv");
	purple_prefs_remove("/purple/away/auto_response/sec_before_resend");
	purple_prefs_remove("/purple/away/auto_response");
	purple_prefs_remove("/purple/away/default_message");
	purple_prefs_remove("/purple/buddies/use_server_alias");
	purple_prefs_remove("/purple/conversations/away_back_on_send");
	purple_prefs_remove("/purple/conversations/send_urls_as_links");
	purple_prefs_remove("/purple/conversations/im/show_login");
	purple_prefs_remove("/purple/conversations/chat/show_join");
	purple_prefs_remove("/purple/conversations/chat/show_leave");
	purple_prefs_remove("/purple/conversations/combine_chat_im");
	purple_prefs_remove("/purple/conversations/use_alias_for_title");
	purple_prefs_remove("/purple/logging/log_signon_signoff");
	purple_prefs_remove("/purple/logging/log_idle_state");
	purple_prefs_remove("/purple/logging/log_away_state");
	purple_prefs_remove("/purple/logging/log_own_states");
	purple_prefs_remove("/purple/status/scores/hidden");
	purple_prefs_remove("/plugins/core/autorecon/hide_connected_error");
	purple_prefs_remove("/plugins/core/autorecon/hide_connecting_error");
	purple_prefs_remove("/plugins/core/autorecon/hide_reconnecting_dialog");
	purple_prefs_remove("/plugins/core/autorecon/restore_state");
	purple_prefs_remove("/plugins/core/autorecon");

	/* Convert old sounds while_away pref to new 3-way pref. */
	if (purple_prefs_exists("/purple/sound/while_away") &&
	    purple_prefs_get_bool("/purple/sound/while_away"))
	{
		purple_prefs_set_int("/purple/sound/while_status", 3);
	}
	purple_prefs_remove("/purple/sound/while_away");
}

void *
purple_prefs_get_handle(void)
{
	static int handle;

	return &handle;
}

void
purple_prefs_init(void)
{
	void *handle = purple_prefs_get_handle();

	prefs_hash = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);

	purple_prefs_connect_callback(handle, "/", prefs_save_cb, NULL);

	purple_prefs_add_none("/purple");
	purple_prefs_add_none("/plugins");
	purple_prefs_add_none("/plugins/core");
	purple_prefs_add_none("/plugins/lopl");
	purple_prefs_add_none("/plugins/prpl");

	/* Away */
	purple_prefs_add_none("/purple/away");
	purple_prefs_add_string("/purple/away/idle_reporting", "system");
	purple_prefs_add_bool("/purple/away/away_when_idle", TRUE);
	purple_prefs_add_int("/purple/away/mins_before_away", 5);

	/* Away -> Auto-Reply */
	if (!purple_prefs_exists("/purple/away/auto_response/enabled") ||
	    !purple_prefs_exists("/purple/away/auto_response/idle_only"))
	{
		purple_prefs_add_string("/purple/away/auto_reply", "awayidle");
	}
	else
	{
		if (!purple_prefs_get_bool("/purple/away/auto_response/enabled"))
		{
			purple_prefs_add_string("/purple/away/auto_reply", "never");
		}
		else
		{
			if (purple_prefs_get_bool("/purple/away/auto_response/idle_only"))
			{
				purple_prefs_add_string("/purple/away/auto_reply", "awayidle");
			}
			else
			{
				purple_prefs_add_string("/purple/away/auto_reply", "away");
			}
		}
	}

	/* Buddies */
	purple_prefs_add_none("/purple/buddies");

	/* Contact Priority Settings */
	purple_prefs_add_none("/purple/contact");
	purple_prefs_add_bool("/purple/contact/last_match", FALSE);
	purple_prefs_remove("/purple/contact/offline_score");
	purple_prefs_remove("/purple/contact/away_score");
	purple_prefs_remove("/purple/contact/idle_score");

	purple_prefs_load();
	purple_prefs_update_old();
}

void
purple_prefs_uninit()
{
	if (save_timer != 0)
	{
		purple_timeout_remove(save_timer);
		save_timer = 0;
		sync_prefs();
	}

	purple_prefs_disconnect_by_handle(purple_prefs_get_handle());

	prefs_loaded = FALSE;
	purple_prefs_destroy();
	g_hash_table_destroy(prefs_hash);
	prefs_hash = NULL;

}
