/**
 * @file xmlnode.c XML DOM functions
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

/* A lot of this code at least resembles the code in libxode, but since
 * libxode uses memory pools that we simply have no need for, I decided to
 * write my own stuff.  Also, re-writing this lets me be as lightweight
 * as I want to be.  Thank you libxode for giving me a good starting point */
#define _PURPLE_XMLNODE_C_

#include "internal.h"
#include "debug.h"

#include <libxml/parser.h>
#include <string.h>
#include <glib.h>

#include "dbus-maybe.h"
#include "util.h"
#include "xmlnode.h"

#ifdef _WIN32
# define NEWLINE_S "\r\n"
#else
# define NEWLINE_S "\n"
#endif

static xmlnode*
new_node(const char *name, XMLNodeType type)
{
	xmlnode *node = g_new0(xmlnode, 1);

	node->name = g_strdup(name);
	node->type = type;

	PURPLE_DBUS_REGISTER_POINTER(node, xmlnode);

	return node;
}

xmlnode*
xmlnode_new(const char *name)
{
	g_return_val_if_fail(name != NULL && *name != '\0', NULL);

	return new_node(name, XMLNODE_TYPE_TAG);
}

xmlnode *
xmlnode_new_child(xmlnode *parent, const char *name)
{
	xmlnode *node;

	g_return_val_if_fail(parent != NULL, NULL);
	g_return_val_if_fail(name != NULL && *name != '\0', NULL);

	node = new_node(name, XMLNODE_TYPE_TAG);

	xmlnode_insert_child(parent, node);

	return node;
}

void
xmlnode_insert_child(xmlnode *parent, xmlnode *child)
{
	g_return_if_fail(parent != NULL);
	g_return_if_fail(child != NULL);

	child->parent = parent;

	if(parent->lastchild) {
		parent->lastchild->next = child;
	} else {
		parent->child = child;
	}

	parent->lastchild = child;
}

void
xmlnode_insert_data(xmlnode *node, const char *data, gssize size)
{
	xmlnode *child;
	gsize real_size;

	g_return_if_fail(node != NULL);
	g_return_if_fail(data != NULL);
	g_return_if_fail(size != 0);

	real_size = size == -1 ? strlen(data) : size;

	child = new_node(NULL, XMLNODE_TYPE_DATA);

	child->data = g_memdup(data, real_size);
	child->data_sz = real_size;

	xmlnode_insert_child(node, child);
}

void
xmlnode_remove_attrib(xmlnode *node, const char *attr)
{
	xmlnode *attr_node, *sibling = NULL;

	g_return_if_fail(node != NULL);
	g_return_if_fail(attr != NULL);

	attr_node = node->child;
	while (attr_node) {
		if(attr_node->type == XMLNODE_TYPE_ATTRIB &&
				purple_strequal(attr_node->name, attr))
		{
			if (node->lastchild == attr_node) {
				node->lastchild = sibling;
			}
			if (sibling == NULL) {
				node->child = attr_node->next;
				xmlnode_free(attr_node);
				attr_node = node->child;
			} else {
				sibling->next = attr_node->next;
				sibling = attr_node->next;
				xmlnode_free(attr_node);
				attr_node = sibling;
			}
		}
		else
		{
			attr_node = attr_node->next;
		}
		sibling = attr_node;
	}
}

void
xmlnode_remove_attrib_with_namespace(xmlnode *node, const char *attr, const char *xmlns)
{
	xmlnode *attr_node, *sibling = NULL;

	g_return_if_fail(node != NULL);
	g_return_if_fail(attr != NULL);

	for(attr_node = node->child; attr_node; attr_node = attr_node->next)
	{
		if(attr_node->type == XMLNODE_TYPE_ATTRIB &&
		   purple_strequal(attr,  attr_node->name) &&
		   purple_strequal(xmlns, attr_node->xmlns))
		{
			if(sibling == NULL) {
				node->child = attr_node->next;
			} else {
				sibling->next = attr_node->next;
			}
			if (node->lastchild == attr_node) {
				node->lastchild = sibling;
			}
			xmlnode_free(attr_node);
			return;
		}
		sibling = attr_node;
	}
}

void
xmlnode_set_attrib(xmlnode *node, const char *attr, const char *value)
{
	xmlnode_remove_attrib(node, attr);
	xmlnode_set_attrib_full(node, attr, NULL, NULL, value);
}

void
xmlnode_set_attrib_with_namespace(xmlnode *node, const char *attr, const char *xmlns, const char *value)
{
	xmlnode_set_attrib_full(node, attr, xmlns, NULL, value);
}

void
xmlnode_set_attrib_with_prefix(xmlnode *node, const char *attr, const char *prefix, const char *value)
{
	xmlnode_set_attrib_full(node, attr, NULL, prefix, value);
}

void
xmlnode_set_attrib_full(xmlnode *node, const char *attr, const char *xmlns, const char *prefix, const char *value)
{
	xmlnode *attrib_node;

	g_return_if_fail(node != NULL);
	g_return_if_fail(attr != NULL);
	g_return_if_fail(value != NULL);

	xmlnode_remove_attrib_with_namespace(node, attr, xmlns);
	attrib_node = new_node(attr, XMLNODE_TYPE_ATTRIB);

	attrib_node->data = g_strdup(value);
	attrib_node->xmlns = g_strdup(xmlns);
	attrib_node->prefix = g_strdup(prefix);

	xmlnode_insert_child(node, attrib_node);
}


const char *
xmlnode_get_attrib(const xmlnode *node, const char *attr)
{
	xmlnode *x;

	g_return_val_if_fail(node != NULL, NULL);
	g_return_val_if_fail(attr != NULL, NULL);

	for(x = node->child; x; x = x->next) {
		if(x->type == XMLNODE_TYPE_ATTRIB && purple_strequal(attr, x->name)) {
			return x->data;
		}
	}

	return NULL;
}

const char *
xmlnode_get_attrib_with_namespace(const xmlnode *node, const char *attr, const char *xmlns)
{
	const xmlnode *x;

	g_return_val_if_fail(node != NULL, NULL);
	g_return_val_if_fail(attr != NULL, NULL);

	for(x = node->child; x; x = x->next) {
		if(x->type == XMLNODE_TYPE_ATTRIB &&
		   purple_strequal(attr,  x->name) &&
		   purple_strequal(xmlns, x->xmlns)) {
			return x->data;
		}
	}

	return NULL;
}


void xmlnode_set_namespace(xmlnode *node, const char *xmlns)
{
	g_return_if_fail(node != NULL);

	g_free(node->xmlns);
	node->xmlns = g_strdup(xmlns);
}

const char *xmlnode_get_namespace(xmlnode *node)
{
	g_return_val_if_fail(node != NULL, NULL);

	return node->xmlns;
}

void xmlnode_set_prefix(xmlnode *node, const char *prefix)
{
	g_return_if_fail(node != NULL);

	g_free(node->prefix);
	node->prefix = g_strdup(prefix);
}

const char *xmlnode_get_prefix(const xmlnode *node)
{
	g_return_val_if_fail(node != NULL, NULL);
	return node->prefix;
}

xmlnode *xmlnode_get_parent(const xmlnode *child)
{
	g_return_val_if_fail(child != NULL, NULL);
	return child->parent;
}

void
xmlnode_free(xmlnode *node)
{
	xmlnode *x, *y;

	g_return_if_fail(node != NULL);

	/* if we're part of a tree, remove ourselves from the tree first */
	if(NULL != node->parent) {
		if(node->parent->child == node) {
			node->parent->child = node->next;
			if (node->parent->lastchild == node)
				node->parent->lastchild = node->next;
		} else {
			xmlnode *prev = node->parent->child;
			while(prev && prev->next != node) {
				prev = prev->next;
			}
			if(prev) {
				prev->next = node->next;
				if (node->parent->lastchild == node)
					node->parent->lastchild = prev;
			}
		}
	}

	/* now free our children */
	x = node->child;
	while(x) {
		y = x->next;
		xmlnode_free(x);
		x = y;
	}

	/* now dispose of ourselves */
	g_free(node->name);
	g_free(node->data);
	g_free(node->xmlns);
	g_free(node->prefix);

	if(node->namespace_map)
		g_hash_table_destroy(node->namespace_map);

	PURPLE_DBUS_UNREGISTER_POINTER(node);
	g_free(node);
}

xmlnode*
xmlnode_get_child(const xmlnode *parent, const char *name)
{
	return xmlnode_get_child_with_namespace(parent, name, NULL);
}

xmlnode *
xmlnode_get_child_with_namespace(const xmlnode *parent, const char *name, const char *ns)
{
	xmlnode *x, *ret = NULL;
	char **names;
	char *parent_name, *child_name;

	g_return_val_if_fail(parent != NULL, NULL);
	g_return_val_if_fail(name != NULL, NULL);

	names = g_strsplit(name, "/", 2);
	parent_name = names[0];
	child_name = names[1];

	for(x = parent->child; x; x = x->next) {
		/* XXX: Is it correct to ignore the namespace for the match if none was specified? */
		const char *xmlns = NULL;
		if(ns)
			xmlns = xmlnode_get_namespace(x);

		if(x->type == XMLNODE_TYPE_TAG && purple_strequal(parent_name, x->name)
				&& purple_strequal(ns, xmlns)) {
			ret = x;
			break;
		}
	}

	if(child_name && ret)
		ret = xmlnode_get_child(ret, child_name);

	g_strfreev(names);
	return ret;
}

char *
xmlnode_get_data(const xmlnode *node)
{
	GString *str = NULL;
	xmlnode *c;

	g_return_val_if_fail(node != NULL, NULL);

	for(c = node->child; c; c = c->next) {
		if(c->type == XMLNODE_TYPE_DATA) {
			if(!str)
				str = g_string_new_len(c->data, c->data_sz);
			else
				str = g_string_append_len(str, c->data, c->data_sz);
		}
	}

	if (str == NULL)
		return NULL;

	return g_string_free(str, FALSE);
}

char *
xmlnode_get_data_unescaped(const xmlnode *node)
{
	char *escaped = xmlnode_get_data(node);

	char *unescaped = escaped ? purple_unescape_html(escaped) : NULL;

	g_free(escaped);

	return unescaped;
}

static void
xmlnode_to_str_foreach_append_ns(const char *key, const char *value,
	GString *buf)
{
	if (*key) {
		g_string_append_printf(buf, " xmlns:%s='%s'", key, value);
	} else {
		g_string_append_printf(buf, " xmlns='%s'", value);
	}
}

static char *
xmlnode_to_str_helper(const xmlnode *node, int *len, gboolean formatting, int depth)
{
	GString *text = g_string_new("");
	const char *prefix;
	const xmlnode *c;
	char *node_name, *esc, *esc2, *tab = NULL;
	gboolean need_end = FALSE, pretty = formatting;

	g_return_val_if_fail(node != NULL, NULL);

	if(pretty && depth) {
		tab = g_strnfill(depth, '\t');
		text = g_string_append(text, tab);
	}

	node_name = g_markup_escape_text(node->name, -1);
	prefix = xmlnode_get_prefix(node);

	if (prefix) {
		g_string_append_printf(text, "<%s:%s", prefix, node_name);
	} else {
		g_string_append_printf(text, "<%s", node_name);
	}

	if (node->namespace_map) {
		g_hash_table_foreach(node->namespace_map,
			(GHFunc)xmlnode_to_str_foreach_append_ns, text);
	} else if (node->xmlns) {
		if(!node->parent || !purple_strequal(node->xmlns, node->parent->xmlns))
		{
			char *xmlns = g_markup_escape_text(node->xmlns, -1);
			g_string_append_printf(text, " xmlns='%s'", xmlns);
			g_free(xmlns);
		}
	}
	for(c = node->child; c; c = c->next)
	{
		if(c->type == XMLNODE_TYPE_ATTRIB) {
			const char *aprefix = xmlnode_get_prefix(c);
			esc = g_markup_escape_text(c->name, -1);
			esc2 = g_markup_escape_text(c->data, -1);
			if (aprefix) {
				g_string_append_printf(text, " %s:%s='%s'", aprefix, esc, esc2);
			} else {
				g_string_append_printf(text, " %s='%s'", esc, esc2);
			}
			g_free(esc);
			g_free(esc2);
		} else if(c->type == XMLNODE_TYPE_TAG || c->type == XMLNODE_TYPE_DATA) {
			if(c->type == XMLNODE_TYPE_DATA)
				pretty = FALSE;
			need_end = TRUE;
		}
	}

	if(need_end) {
		g_string_append_printf(text, ">%s", pretty ? NEWLINE_S : "");

		for(c = node->child; c; c = c->next)
		{
			if(c->type == XMLNODE_TYPE_TAG) {
				int esc_len;
				esc = xmlnode_to_str_helper(c, &esc_len, pretty, depth+1);
				text = g_string_append_len(text, esc, esc_len);
				g_free(esc);
			} else if(c->type == XMLNODE_TYPE_DATA && c->data_sz > 0) {
				esc = g_markup_escape_text(c->data, c->data_sz);
				text = g_string_append(text, esc);
				g_free(esc);
			}
		}

		if(tab && pretty)
			text = g_string_append(text, tab);
		if (prefix) {
			g_string_append_printf(text, "</%s:%s>%s", prefix, node_name, formatting ? NEWLINE_S : "");
		} else {
			g_string_append_printf(text, "</%s>%s", node_name, formatting ? NEWLINE_S : "");
		}
	} else {
		g_string_append_printf(text, "/>%s", formatting ? NEWLINE_S : "");
	}

	g_free(node_name);

	g_free(tab);

	if(len)
		*len = text->len;

	return g_string_free(text, FALSE);
}

char *
xmlnode_to_str(const xmlnode *node, int *len)
{
	return xmlnode_to_str_helper(node, len, FALSE, 0);
}

char *
xmlnode_to_formatted_str(const xmlnode *node, int *len)
{
	char *xml, *xml_with_declaration;

	g_return_val_if_fail(node != NULL, NULL);

	xml = xmlnode_to_str_helper(node, len, TRUE, 0);
	xml_with_declaration =
		g_strdup_printf("<?xml version='1.0' encoding='UTF-8' ?>" NEWLINE_S NEWLINE_S "%s", xml);
	g_free(xml);

	if (len)
		*len += sizeof("<?xml version='1.0' encoding='UTF-8' ?>" NEWLINE_S NEWLINE_S) - 1;

	return xml_with_declaration;
}

struct _xmlnode_parser_data {
	xmlnode *current;
	gboolean error;
};

static void
xmlnode_parser_element_start_libxml(void *user_data,
				   const xmlChar *element_name, const xmlChar *prefix, const xmlChar *xmlns,
				   int nb_namespaces, const xmlChar **namespaces,
				   int nb_attributes, int nb_defaulted, const xmlChar **attributes)
{
	struct _xmlnode_parser_data *xpd = user_data;
	xmlnode *node;
	int i, j;

	if(!element_name || xpd->error) {
		return;
	} else {
		if(xpd->current)
			node = xmlnode_new_child(xpd->current, (const char*) element_name);
		else
			node = xmlnode_new((const char *) element_name);

		xmlnode_set_namespace(node, (const char *) xmlns);
		xmlnode_set_prefix(node, (const char *)prefix);

		if (nb_namespaces != 0) {
			node->namespace_map = g_hash_table_new_full(
				g_str_hash, g_str_equal, g_free, g_free);

			for (i = 0, j = 0; i < nb_namespaces; i++, j += 2) {
				const char *key = (const char *)namespaces[j];
				const char *val = (const char *)namespaces[j + 1];
				g_hash_table_insert(node->namespace_map,
					g_strdup(key ? key : ""), g_strdup(val ? val : ""));
			}
		}

		for(i=0; i < nb_attributes * 5; i+=5) {
			const char *name = (const char *)attributes[i];
			const char *prefix = (const char *)attributes[i+1];
			char *txt;
			int attrib_len = attributes[i+4] - attributes[i+3];
			char *attrib = g_strndup((const char *)attributes[i+3], attrib_len);
			txt = attrib;
			attrib = purple_unescape_text(txt);
			g_free(txt);
			xmlnode_set_attrib_full(node, name, NULL, prefix, attrib);
			g_free(attrib);
		}

		xpd->current = node;
	}
}

static void
xmlnode_parser_element_end_libxml(void *user_data, const xmlChar *element_name,
				 const xmlChar *prefix, const xmlChar *xmlns)
{
	struct _xmlnode_parser_data *xpd = user_data;

	if(!element_name || !xpd->current || xpd->error)
		return;

	if(xpd->current->parent) {
		if(!xmlStrcmp((xmlChar*) xpd->current->name, element_name))
			xpd->current = xpd->current->parent;
	}
}

static void
xmlnode_parser_element_text_libxml(void *user_data, const xmlChar *text, int text_len)
{
	struct _xmlnode_parser_data *xpd = user_data;

	if(!xpd->current || xpd->error)
		return;

	if(!text || !text_len)
		return;

	xmlnode_insert_data(xpd->current, (const char*) text, text_len);
}

static void
xmlnode_parser_error_libxml(void *user_data, const char *msg, ...)
{
	struct _xmlnode_parser_data *xpd = user_data;
	char errmsg[2048];
	va_list args;

	xpd->error = TRUE;

	va_start(args, msg);
	vsnprintf(errmsg, sizeof(errmsg), msg, args);
	va_end(args);

	purple_debug_error("xmlnode", "Error parsing xml file: %s", errmsg);
}

static void
xmlnode_parser_structural_error_libxml(void *user_data, xmlErrorPtr error)
{
	struct _xmlnode_parser_data *xpd = user_data;

	if (error && (error->level == XML_ERR_ERROR ||
	              error->level == XML_ERR_FATAL)) {
		xpd->error = TRUE;
		purple_debug_error("xmlnode", "XML parser error for xmlnode %p: "
		                   "Domain %i, code %i, level %i: %s",
		                   user_data, error->domain, error->code, error->level,
		                   error->message ? error->message : "(null)\n");
	} else if (error)
		purple_debug_warning("xmlnode", "XML parser error for xmlnode %p: "
		                     "Domain %i, code %i, level %i: %s",
		                     user_data, error->domain, error->code, error->level,
		                     error->message ? error->message : "(null)\n");
	else
		purple_debug_warning("xmlnode", "XML parser error for xmlnode %p\n",
		                     user_data);
}

static xmlSAXHandler xmlnode_parser_libxml = {
	NULL, /* internalSubset */
	NULL, /* isStandalone */
	NULL, /* hasInternalSubset */
	NULL, /* hasExternalSubset */
	NULL, /* resolveEntity */
	NULL, /* getEntity */
	NULL, /* entityDecl */
	NULL, /* notationDecl */
	NULL, /* attributeDecl */
	NULL, /* elementDecl */
	NULL, /* unparsedEntityDecl */
	NULL, /* setDocumentLocator */
	NULL, /* startDocument */
	NULL, /* endDocument */
	NULL, /* startElement */
	NULL, /* endElement */
	NULL, /* reference */
	xmlnode_parser_element_text_libxml, /* characters */
	NULL, /* ignorableWhitespace */
	NULL, /* processingInstruction */
	NULL, /* comment */
	NULL, /* warning */
	xmlnode_parser_error_libxml, /* error */
	NULL, /* fatalError */
	NULL, /* getParameterEntity */
	NULL, /* cdataBlock */
	NULL, /* externalSubset */
	XML_SAX2_MAGIC, /* initialized */
	NULL, /* _private */
	xmlnode_parser_element_start_libxml, /* startElementNs */
	xmlnode_parser_element_end_libxml,   /* endElementNs   */
	xmlnode_parser_structural_error_libxml, /* serror */
};

xmlnode *
xmlnode_from_str(const char *str, gssize size)
{
	struct _xmlnode_parser_data *xpd;
	xmlnode *ret;
	gsize real_size;

	g_return_val_if_fail(str != NULL, NULL);

	real_size = size < 0 ? strlen(str) : size;
	xpd = g_new0(struct _xmlnode_parser_data, 1);

	if (xmlSAXUserParseMemory(&xmlnode_parser_libxml, xpd, str, real_size) < 0) {
		while(xpd->current && xpd->current->parent)
			xpd->current = xpd->current->parent;
		if(xpd->current)
			xmlnode_free(xpd->current);
		xpd->current = NULL;
	}
	ret = xpd->current;
	if (xpd->error) {
		ret = NULL;
		if (xpd->current)
			xmlnode_free(xpd->current);
	}

	g_free(xpd);
	return ret;
}

xmlnode *
xmlnode_from_file(const char *dir,const char *filename, const char *description, const char *process)
{
	gchar *filename_full;
	GError *error = NULL;
	gchar *contents = NULL;
	gsize length;
	xmlnode *node = NULL;

	g_return_val_if_fail(dir != NULL, NULL);

	purple_debug_info(process, "Reading file %s from directory %s\n",
					filename, dir);

	filename_full = g_build_filename(dir, filename, NULL);

	if (!g_file_test(filename_full, G_FILE_TEST_EXISTS))
	{
		purple_debug_info(process, "File %s does not exist (this is not "
						"necessarily an error)\n", filename_full);
		g_free(filename_full);
		return NULL;
	}

	if (!g_file_get_contents(filename_full, &contents, &length, &error))
	{
		purple_debug_error(process, "Error reading file %s: %s\n",
						 filename_full, error->message);
		g_error_free(error);
	}

	if ((contents != NULL) && (length > 0))
	{
		node = xmlnode_from_str(contents, length);

		/* If we were unable to parse the file then save its contents to a backup file */
		if (node == NULL)
		{
			gchar *filename_temp, *filename_temp_full;

			filename_temp = g_strdup_printf("%s~", filename);
			filename_temp_full = g_build_filename(dir, filename_temp, NULL);

			purple_debug_error("util", "Error parsing file %s.  Renaming old "
							 "file to %s\n", filename_full, filename_temp);
			purple_util_write_data_to_file_absolute(filename_temp_full, contents, length);

			g_free(filename_temp_full);
			g_free(filename_temp);
		}

		g_free(contents);
	}

	/* If we could not parse the file then show the user an error message */
	if (node == NULL)
	{
		gchar *title, *msg;
		title = g_strdup_printf(_("Error Reading %s"), filename);
		msg = g_strdup_printf(_("An error was encountered reading your "
					"%s.  The file has not been loaded, and the old file "
					"has been renamed to %s~."), description, filename_full);
		purple_notify_error(NULL, NULL, title, msg);
		g_free(title);
		g_free(msg);
	}

	g_free(filename_full);

	return node;
}

static void
xmlnode_copy_foreach_ns(gpointer key, gpointer value, gpointer user_data)
{
	GHashTable *ret = (GHashTable *)user_data;
	g_hash_table_insert(ret, g_strdup(key), g_strdup(value));
}

xmlnode *
xmlnode_copy(const xmlnode *src)
{
	xmlnode *ret;
	xmlnode *child;
	xmlnode *sibling = NULL;

	g_return_val_if_fail(src != NULL, NULL);

	ret = new_node(src->name, src->type);
	ret->xmlns = g_strdup(src->xmlns);
	if (src->data) {
		if (src->data_sz) {
			ret->data = g_memdup(src->data, src->data_sz);
			ret->data_sz = src->data_sz;
		} else {
			ret->data = g_strdup(src->data);
		}
	}
	ret->prefix = g_strdup(src->prefix);
	if (src->namespace_map) {
		ret->namespace_map = g_hash_table_new_full(g_str_hash, g_str_equal,
		                                           g_free, g_free);
		g_hash_table_foreach(src->namespace_map, xmlnode_copy_foreach_ns, ret->namespace_map);
	}

	for (child = src->child; child; child = child->next) {
		if (sibling) {
			sibling->next = xmlnode_copy(child);
			sibling = sibling->next;
		} else {
			ret->child = xmlnode_copy(child);
			sibling = ret->child;
		}
		sibling->parent = ret;
	}

	ret->lastchild = sibling;

	return ret;
}

xmlnode *
xmlnode_get_next_twin(xmlnode *node)
{
	xmlnode *sibling;
	const char *ns = xmlnode_get_namespace(node);

	g_return_val_if_fail(node != NULL, NULL);
	g_return_val_if_fail(node->type == XMLNODE_TYPE_TAG, NULL);

	for(sibling = node->next; sibling; sibling = sibling->next) {
		/* XXX: Is it correct to ignore the namespace for the match if none was specified? */
		const char *xmlns = NULL;
		if(ns)
			xmlns = xmlnode_get_namespace(sibling);

		if(sibling->type == XMLNODE_TYPE_TAG && purple_strequal(node->name, sibling->name) &&
				purple_strequal(ns, xmlns))
			return sibling;
	}

	return NULL;
}
