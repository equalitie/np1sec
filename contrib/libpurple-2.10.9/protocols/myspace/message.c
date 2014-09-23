/** MySpaceIM protocol messages
 *
 * \author Jeff Connelly
 *
 * Copyright (C) 2007, Jeff Connelly <jeff2@soc.pidgin.im>
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

#include "myspace.h"
#include "message.h"

static void msim_msg_debug_string_element(gpointer data, gpointer user_data);

/**
 * Escape codes and associated replacement text, used for protocol message
 * escaping and unescaping.
 */
static struct MSIM_ESCAPE_REPLACEMENT {
	gchar *code;
	gchar text;
} msim_escape_replacements[] = {
	{ "/1", '/' },
	{ "/2", '\\' },
	/* { "/3", "|" }, */      /* Not used here -- only for within arrays */
	{ NULL, 0 }
};

/**
 * Escape a protocol message.
 *
 * @return The escaped message. Caller must g_free().
 */
gchar *
msim_escape(const gchar *msg)
{
	GString *gs;
	guint i, j;
	guint msg_len;

	gs = g_string_new("");
	msg_len = strlen(msg);

	for (i = 0; i < msg_len; ++i) {
		struct MSIM_ESCAPE_REPLACEMENT *replacement;
		gchar *replace;

		replace = NULL;

		/* Check for characters that need to be escaped, and escape them. */
		for (j = 0; (replacement = &msim_escape_replacements[j]) &&
				replacement->code != NULL; ++j) {
			if (msg[i] == replacement->text) {
				replace = replacement->code;
				break;
			}
		}

		if (replace) {
			g_string_append(gs, replace);
		} else {
			g_string_append_c(gs, msg[i]);
		}
	}

#ifdef MSIM_DEBUG_ESCAPE
	purple_debug_info("msim", "msim_escape: msg=%s, ret=%s\n", msg, gs->str);
#endif

	return g_string_free(gs, FALSE);
}

/**
 * Unescape a protocol message.
 *
 * @return The unescaped message, caller must g_free().
 */
gchar *
msim_unescape(const gchar *msg)
{
	GString *gs;
	guint i, j;
	guint msg_len;

	gs = g_string_new("");
	msg_len = strlen(msg);

	for (i = 0; i < msg_len; ++i) {
		struct MSIM_ESCAPE_REPLACEMENT *replacement;
		gchar replace;

		replace = msg[i];

		for (j = 0; (replacement = &msim_escape_replacements[j]) &&
				replacement->code != NULL; ++j) {
			if (msg[i] == replacement->code[0] &&
			    i + 1 < msg_len &&
			    msg[i + 1] == replacement->code[1]) {
				replace = replacement->text;
				++i;
				break;
			}
		}

		g_string_append_c(gs, replace);
	}

#ifdef MSIM_DEBUG_ESCAPE
	purple_debug_info("msim", "msim_unescape: msg=%s, ret=%s\n", msg, gs->str);
#endif

	return g_string_free(gs, FALSE);
}

/**
 * Create a new message from va_list and its first argument.
 *
 * @param first_key The first argument (a key), or NULL to take all arguments
 *    from argp.
 * @param argp A va_list of variadic arguments, already started with va_start().
 * @return New MsimMessage *, must be freed with msim_msg_free().
 *
 * For internal use - users probably want msim_msg_new() or msim_send().
 */
static MsimMessage *
msim_msg_new_v(gchar *first_key, va_list argp)
{
	gchar *key, *value;
	MsimMessageType type;
	MsimMessage *msg;
	gboolean first;

	GString *gs;
	GList *gl;
	MsimMessage *dict;

	/* Begin with an empty message. */
	msg = NULL;

	/* First parameter can be given explicitly. */
	first = first_key != NULL;

	/* Read key, type, value triplets until NULL. */
	do {
		if (first) {
			key = first_key;
			first = FALSE;
		} else {
			key = va_arg(argp, gchar *);
			if (!key) {
				break;
			}
		}

		type = va_arg(argp, int);

		/* Interpret variadic arguments. */
		switch (type) {
			case MSIM_TYPE_INTEGER:
			case MSIM_TYPE_BOOLEAN:
				msg = msim_msg_append(msg, key, type, GUINT_TO_POINTER(va_arg(argp, int)));
				break;

			case MSIM_TYPE_STRING:
				value = va_arg(argp, char *);

				g_return_val_if_fail(value != NULL, FALSE);

				msg = msim_msg_append(msg, key, type, value);
				break;

			case MSIM_TYPE_BINARY:
				gs = va_arg(argp, GString *);

				g_return_val_if_fail(gs != NULL, FALSE);

				/* msim_msg_free() will free this GString the caller created. */
				msg = msim_msg_append(msg, key, type, gs);
				break;

			case MSIM_TYPE_LIST:
				gl = va_arg(argp, GList *);

				g_return_val_if_fail(gl != NULL, FALSE);

				msg = msim_msg_append(msg, key, type, gl);
				break;

			case MSIM_TYPE_DICTIONARY:
				dict = va_arg(argp, MsimMessage *);

				g_return_val_if_fail(dict != NULL, FALSE);

				msg = msim_msg_append(msg, key, type, dict);
				break;

			default:
				purple_debug_info("msim", "msim_send: unknown type %d\n", type);
				break;
		}
	} while(key);

	return msg;
}

/**
 * Create a new MsimMessage.
 *
 * @param first_key The first key in the sequence, or NULL for an empty message.
 * @param ... A sequence of gchar* key/type/value triplets, terminated with NULL.
 *
 * See msim_msg_append() documentation for details on types.
 */
MsimMessage *
msim_msg_new(gchar *first_key, ...)
{
	MsimMessage *ret = NULL;
	va_list argp;

	if (first_key) {
		va_start(argp, first_key);
		ret = msim_msg_new_v(first_key, argp);
		va_end(argp);
	}

	return ret;
}

/**
 * Pack a string using the given GFunc and seperator.
 * Used by msim_msg_dump() and msim_msg_pack().
 */
static gchar *
msim_msg_pack_using(MsimMessage *msg,
		GFunc gf,
		const gchar *sep,
		const gchar *begin, const gchar *end)
{
	int num_items;
	gchar **strings;
	gchar **strings_tmp;
	gchar *joined;
	gchar *final;
	int i;

	g_return_val_if_fail(msg != NULL, NULL);

	num_items = g_list_length(msg);

	/* Add one for NULL terminator for g_strjoinv(). */
	strings = (gchar **)g_new0(gchar *, num_items + 1);

	strings_tmp = strings;
	g_list_foreach(msg, gf, &strings_tmp);

	joined = g_strjoinv(sep, strings);
	final = g_strconcat(begin, joined, end, NULL);
	g_free(joined);

	/* Clean up. */
	for (i = 0; i < num_items; ++i) {
		g_free(strings[i]);
	}

	g_free(strings);

	return final;
}

/**
 * Return a human-readable string of the message.
 *
 * @return A new gchar *, must be g_free()'d.
 */
static gchar *
msim_msg_dump_to_str(MsimMessage *msg)
{
	gchar *debug_str;

	if (!msg) {
		debug_str = g_strdup("<MsimMessage: empty>");
	} else {
		debug_str = msim_msg_pack_using(msg, msim_msg_debug_string_element,
				"\n", "<MsimMessage: \n", "\n/MsimMessage>");
	}

	return debug_str;
}

/**
 * Store a human-readable string describing the element.
 *
 * @param data Pointer to an MsimMessageElement.
 * @param user_data
 */
static void
msim_msg_debug_string_element(gpointer data, gpointer user_data)
{
	MsimMessageElement *elem;
	gchar *string;
	GString *gs;
	gchar *binary;
	gchar ***items;  /* wow, a pointer to a pointer to a pointer */

	gchar *s;
	GList *gl;
	guint i;

	elem = (MsimMessageElement *)data;
	items = user_data;

	switch (elem->type) {
		case MSIM_TYPE_INTEGER:
			string = g_strdup_printf("%s(integer): %d", elem->name,
					GPOINTER_TO_UINT(elem->data));
			break;

		case MSIM_TYPE_RAW:
			string = g_strdup_printf("%s(raw): %s", elem->name,
					elem->data ? (gchar *)elem->data : "(NULL)");
			break;

		case MSIM_TYPE_STRING:
			string = g_strdup_printf("%s(string): %s", elem->name,
					elem->data ? (gchar *)elem->data : "(NULL)");
			break;

		case MSIM_TYPE_BINARY:
			gs = (GString *)elem->data;
			binary = purple_base64_encode((guchar*)gs->str, gs->len);
			string = g_strdup_printf("%s(binary, %d bytes): %s", elem->name, (int)gs->len, binary);
			g_free(binary);
			break;

		case MSIM_TYPE_BOOLEAN:
			string = g_strdup_printf("%s(boolean): %s", elem->name,
					elem->data ? "TRUE" : "FALSE");
			break;

		case MSIM_TYPE_DICTIONARY:
			if (!elem->data) {
				s = g_strdup("(NULL)");
			} else {
				s = msim_msg_dump_to_str((MsimMessage *)elem->data);
			}

			if (!s) {
				s = g_strdup("(NULL, couldn't msim_msg_dump_to_str)");
			}

			string = g_strdup_printf("%s(dict): %s", elem->name, s);

			g_free(s);
			break;

		case MSIM_TYPE_LIST:
			gs = g_string_new("");
			g_string_append_printf(gs, "%s(list): \n", elem->name);

			i = 0;
			for (gl = (GList *)elem->data; gl != NULL; gl = g_list_next(gl)) {
				g_string_append_printf(gs, " %d. %s\n", i, (gchar *)(gl->data));
				++i;
			}

			string = g_string_free(gs, FALSE);
			break;

		default:
			string = g_strdup_printf("%s(unknown type %d",
					elem->name ? elem->name : "(NULL)", elem->type);
			break;
	}

	**items = string;
	++(*items);
}

/**
 * Search for and return the node in msg, matching name, or NULL.
 *
 * @param msg Message to search within.
 * @param name Field name to search for.
 *
 * @return The GList * node for the MsimMessageElement with the given name, or NULL if not found or name is NULL.
 *
 * For internal use - users probably want to use msim_msg_get() to
 * access the MsimMessageElement *, instead of the GList * container.
 *
 */
static GList *
msim_msg_get_node(const MsimMessage *msg, const gchar *name)
{
	GList *node;

	if (!name || !msg) {
		return NULL;
	}

	/* Linear search for the given name. O(n) but n is small. */
	for (node = (GList*)msg; node != NULL; node = g_list_next(node)) {
		MsimMessageElement *elem;

		elem = (MsimMessageElement *)node->data;

		g_return_val_if_fail(elem != NULL, NULL);
		g_return_val_if_fail(elem->name != NULL, NULL);

		if (strcmp(elem->name, name) == 0) {
			return node;
		}
	}
	return NULL;
}

/**
 * Create a new MsimMessageElement * - must be g_free()'d.
 *
 * For internal use; users probably want msim_msg_append() or msim_msg_insert_before().
 *
 * @param dynamic_name Whether 'name' should be freed when the message is destroyed.
 */
static MsimMessageElement *
msim_msg_element_new(const gchar *name, MsimMessageType type, gpointer data, gboolean dynamic_name)
{
	MsimMessageElement *elem;

	elem = g_new0(MsimMessageElement, 1);

	elem->name = name;
	elem->dynamic_name = dynamic_name;
	elem->type = type;
	elem->data = data;

	return elem;
}

/**
 * Append a new element to a message.
 *
 * @param name Textual name of element (static string, neither copied nor freed).
 * @param type An MSIM_TYPE_* code.
 * @param data Pointer to data, see below.
 *
 * @return The new message - must be assigned to as with GList*. For example:
 *
 *     msg = msim_msg_append(msg, ...)
 *
 * The data parameter depends on the type given:
 *
 * * MSIM_TYPE_INTEGER: Use GUINT_TO_POINTER(x).
 *
 * * MSIM_TYPE_BINARY: Same as integer, non-zero is TRUE and zero is FALSE.
 *
 * * MSIM_TYPE_STRING: gchar *. The data WILL BE FREED - use g_strdup() if needed.
 *
 * * MSIM_TYPE_RAW: gchar *. The data WILL BE FREED - use g_strdup() if needed.
 *
 * * MSIM_TYPE_BINARY: g_string_new_len(data, length). The data AND GString will be freed.
 *
 * * MSIM_TYPE_DICTIONARY: An MsimMessage *. Freed when message is destroyed.
 *
 * * MSIM_TYPE_LIST: GList * of gchar *. Again, everything will be freed.
 *
 * */
MsimMessage *
msim_msg_append(MsimMessage *msg, const gchar *name,
		MsimMessageType type, gpointer data)
{
	return g_list_append(msg, msim_msg_element_new(name, type, data, FALSE));
}

/**
 * Append a new element, but with a dynamically-allocated name.
 * Exactly the same as msim_msg_append(), except 'name' will be freed when
 * the message is destroyed. Normally, it isn't, because a static string is given.
 */
static MsimMessage *
msim_msg_append_dynamic_name(MsimMessage *msg, gchar *name,
		MsimMessageType type, gpointer data)
{
	return g_list_append(msg, msim_msg_element_new(name, type, data, TRUE));
}

/**
 * Insert a new element into a message, before the given element name.
 *
 * @param name_before Name of the element to insert the new element before. If
 *                    could not be found or NULL, new element will be inserted at end.
 *
 * See msim_msg_append() for usage of other parameters, and an important note about return value.
 */
MsimMessage *
msim_msg_insert_before(MsimMessage *msg, const gchar *name_before,
		const gchar *name, MsimMessageType type, gpointer data)
{
	MsimMessageElement *new_elem;
	GList *node_before;

	new_elem = msim_msg_element_new(name, type, data, FALSE);

	node_before = msim_msg_get_node(msg, name_before);

	return g_list_insert_before(msg, node_before, new_elem);
}

/**
 * Perform a deep copy on a GList * of gchar * strings. Free with msim_msg_list_free().
 */
static GList *
msim_msg_list_copy(const GList *old)
{
	GList *new_list;

	new_list = NULL;

	/* Deep copy (g_list_copy is shallow). Copy each string. */
	for (; old != NULL; old = g_list_next(old)) {
		new_list = g_list_append(new_list, g_strdup(old->data));
	}

	return new_list;
}

/**
 * Clone an individual element.
 *
 * @param data MsimMessageElement * to clone.
 * @param user_data Pointer to MsimMessage * to add cloned element to.
 */
static void
msim_msg_clone_element(gpointer data, gpointer user_data)
{
	MsimMessageElement *elem;
	MsimMessage **new;
	gpointer new_data;

	GString *gs;
	MsimMessage *dict;

	elem = (MsimMessageElement *)data;
	new = (MsimMessage **)user_data;

	switch (elem->type) {
		case MSIM_TYPE_BOOLEAN:
		case MSIM_TYPE_INTEGER:
			new_data = elem->data;
			break;

		case MSIM_TYPE_RAW:
		case MSIM_TYPE_STRING:
			new_data = g_strdup((gchar *)elem->data);
			break;

		case MSIM_TYPE_LIST:
			new_data = (gpointer)msim_msg_list_copy((GList *)(elem->data));
			break;

		case MSIM_TYPE_BINARY:
			gs = (GString *)elem->data;

			new_data = g_string_new_len(gs->str, gs->len);
			break;
		case MSIM_TYPE_DICTIONARY:
			dict = (MsimMessage *)elem->data;

			new_data = msim_msg_clone(dict);
			break;

		default:
			purple_debug_info("msim", "msim_msg_clone_element: unknown type %d\n", elem->type);
			g_return_if_reached();
	}

	/* Append cloned data. Note that the 'name' field is a static string, so it
	 * never needs to be copied nor freed. */
	if (elem->dynamic_name)
		*new = msim_msg_append_dynamic_name(*new, g_strdup(elem->name), elem->type, new_data);
	else
		*new = msim_msg_append(*new, elem->name, elem->type, new_data);
}

/**
 * Clone an existing MsimMessage.
 *
 * @return Cloned message; caller should free with msim_msg_free().
 */
MsimMessage *
msim_msg_clone(MsimMessage *old)
{
	MsimMessage *new;

	if (old == NULL) {
		return NULL;
	}

	new = msim_msg_new(FALSE);

	g_list_foreach(old, msim_msg_clone_element, &new);

	return new;
}

/**
 * Free the data of a message element.
 *
 * @param elem The MsimMessageElement *
 *
 * Note this only frees the element data; you may also want to free the
 * element itself with g_free() (see msim_msg_free_element()).
 */
void
msim_msg_free_element_data(MsimMessageElement *elem)
{
	switch (elem->type) {
		case MSIM_TYPE_BOOLEAN:
		case MSIM_TYPE_INTEGER:
			/* Integer value stored in gpointer - no need to free(). */
			break;

		case MSIM_TYPE_RAW:
		case MSIM_TYPE_STRING:
			/* Always free strings - caller should have g_strdup()'d if
			 * string was static or temporary and not to be freed. */
			g_free(elem->data);
			break;

		case MSIM_TYPE_BINARY:
			/* Free the GString itself and the binary data. */
			g_string_free((GString *)elem->data, TRUE);
			break;

		case MSIM_TYPE_DICTIONARY:
			msim_msg_free((MsimMessage *)elem->data);
			break;

		case MSIM_TYPE_LIST:
			g_list_free((GList *)elem->data);
			break;

		default:
			purple_debug_info("msim", "msim_msg_free_element_data: "
					"not freeing unknown type %d\n", elem->type);
			break;
	}
}

/**
 * Free a GList * of MsimMessageElement *'s.
 */
void
msim_msg_list_free(GList *l)
{

	for (; l != NULL; l = g_list_next(l)) {
		MsimMessageElement *elem;

		elem = (MsimMessageElement *)l->data;

		/* Note that name is almost never dynamically allocated elsewhere;
		 * it is usually a static string, but not in lists. So cast it. */
		g_free((gchar *)elem->name);
		g_free(elem->data);
		g_free(elem);
	}
	g_list_free(l);
}

/**
 * Free an individual message element.
 *
 * @param data MsimMessageElement * to free.
 * @param user_data Not used; required to match g_list_foreach() callback prototype.
 *
 * Frees both the element data and the element itself.
 * Also frees the name if dynamic_name is TRUE.
 */
static void
msim_msg_free_element(gpointer data, gpointer user_data)
{
	MsimMessageElement *elem;

	elem = (MsimMessageElement *)data;

	msim_msg_free_element_data(elem);

	if (elem->dynamic_name)
		/* Need to cast to remove const-ness, because
		 * elem->name is almost always a constant, static
		 * string, but not in this case. */
		g_free((gchar *)elem->name);

	g_free(elem);
}

/**
 * Free a complete message.
 */
void
msim_msg_free(MsimMessage *msg)
{
	if (!msg) {
		/* already free as can be */
		return;
	}

	g_list_foreach(msg, msim_msg_free_element, NULL);
	g_list_free(msg);
}

/**
 * Pack an element into its protocol representation.
 *
 * @param data Pointer to an MsimMessageElement.
 * @param user_data Pointer to a gchar ** array of string items.
 *
 * Called by msim_msg_pack(). Will pack the MsimMessageElement into
 * a part of the protocol string and append it to the array. Caller
 * is responsible for creating array to correct dimensions, and
 * freeing each string element of the array added by this function.
 */
static void
msim_msg_pack_element(gpointer data, gpointer user_data)
{
	MsimMessageElement *elem;
	gchar *string, *data_string;
	gchar ***items;

	elem = (MsimMessageElement *)data;
	items = (gchar ***)user_data;

	/* Exclude elements beginning with '_' from packed protocol messages. */
	if (elem->name[0] == '_') {
		return;
	}

	data_string = msim_msg_pack_element_data(elem);

	switch (elem->type) {
		/* These types are represented by key name/value pairs (converted above). */
		case MSIM_TYPE_INTEGER:
		case MSIM_TYPE_RAW:
		case MSIM_TYPE_STRING:
		case MSIM_TYPE_BINARY:
		case MSIM_TYPE_DICTIONARY:
		case MSIM_TYPE_LIST:
			string = g_strconcat(elem->name, "\\", data_string, NULL);
			break;

		/* Boolean is represented by absence or presence of name. */
		case MSIM_TYPE_BOOLEAN:
			if (GPOINTER_TO_UINT(elem->data)) {
				/* True - leave in, with blank value. */
				string = g_strdup_printf("%s\\", elem->name);
			} else {
				/* False - leave out. */
				string = g_strdup("");
			}
			break;

		default:
			g_free(data_string);
			g_return_if_reached();
			break;
	}

	g_free(data_string);

	**items = string;
	++(*items);
}

/**
 * Pack an element into its protcol representation inside a dictionary.
 *
 * See msim_msg_pack_element().
 */
static void
msim_msg_pack_element_dict(gpointer data, gpointer user_data)
{
	MsimMessageElement *elem;
	gchar *string, *data_string, ***items;

	elem = (MsimMessageElement *)data;
	items = (gchar ***)user_data;

	/* Exclude elements beginning with '_' from packed protocol messages. */
	if (elem->name[0] == '_') {
		return;
	}

	data_string = msim_msg_pack_element_data(elem);

	g_return_if_fail(data_string != NULL);

	switch (elem->type) {
		/* These types are represented by key name/value pairs (converted above). */
		case MSIM_TYPE_INTEGER:
		case MSIM_TYPE_RAW:
		case MSIM_TYPE_STRING:
		case MSIM_TYPE_BINARY:
		case MSIM_TYPE_DICTIONARY:
		case MSIM_TYPE_LIST:
		case MSIM_TYPE_BOOLEAN: /* Boolean is On or Off */
			string = g_strconcat(elem->name, "=", data_string, NULL);
			break;

		default:
			g_free(data_string);
			g_return_if_fail(FALSE);
			break;
	}

	g_free(data_string);

	**items = string;
	++(*items);
}

/**
 * Return a packed string of a message suitable for sending over the wire.
 *
 * @return A string. Caller must g_free().
 */
gchar *
msim_msg_pack(MsimMessage *msg)
{
	g_return_val_if_fail(msg != NULL, NULL);

	return msim_msg_pack_using(msg, msim_msg_pack_element, "\\", "\\", "\\final\\");
}

/**
 * Return a packed string of a dictionary, suitable for embedding in MSIM_TYPE_DICTIONARY.
 *
 * @return A string; caller must g_free().
 */
static gchar *
msim_msg_pack_dict(MsimMessage *msg)
{
	g_return_val_if_fail(msg != NULL, NULL);

	return msim_msg_pack_using(msg, msim_msg_pack_element_dict, "\034", "", "");
}

/**
 * Send an existing MsimMessage.
 */
gboolean
msim_msg_send(MsimSession *session, MsimMessage *msg)
{
	gchar *raw;
	gboolean success;

	raw = msim_msg_pack(msg);
	g_return_val_if_fail(raw != NULL, FALSE);
	success = msim_send_raw(session, raw);
	g_free(raw);

	return success;
}

/**
 * Return a message element data as a new string for a raw protocol message,
 * converting from other types (integer, etc.) if necessary.
 *
 * @return const gchar * The data as a string, or NULL. Caller must g_free().
 *
 * Returns a string suitable for inclusion in a raw protocol message, not necessarily
 * optimal for human consumption. For example, strings are escaped. Use
 * msim_msg_get_string() if you want a string, which in some cases is same as this.
 */
gchar *
msim_msg_pack_element_data(MsimMessageElement *elem)
{
	GString *gs;
	GList *gl;

	g_return_val_if_fail(elem != NULL, NULL);

	switch (elem->type) {
		case MSIM_TYPE_INTEGER:
			return g_strdup_printf("%d", GPOINTER_TO_UINT(elem->data));

		case MSIM_TYPE_RAW:
			/* Not un-escaped - this is a raw element, already escaped if necessary. */
			return (gchar *)g_strdup((gchar *)elem->data);

		case MSIM_TYPE_STRING:
			/* Strings get escaped. msim_escape() creates a new string. */
			g_return_val_if_fail(elem->data != NULL, NULL);
			return elem->data ? msim_escape((gchar *)elem->data) :
				g_strdup("(NULL)");

		case MSIM_TYPE_BINARY:
			gs = (GString *)elem->data;
			/* Do not escape! */
			return purple_base64_encode((guchar *)gs->str, gs->len);

		case MSIM_TYPE_BOOLEAN:
			/* Not used by messages in the wire protocol * -- see msim_msg_pack_element.
			 * Only used by dictionaries, see msim_msg_pack_element_dict. */
			return elem->data ? g_strdup("On") : g_strdup("Off");

		case MSIM_TYPE_DICTIONARY:
			return msim_msg_pack_dict((MsimMessage *)elem->data);

		case MSIM_TYPE_LIST:
			/* Pack using a|b|c|d|... */
			gs = g_string_new("");

			for (gl = (GList *)elem->data; gl != NULL; gl = g_list_next(gl)) {
				g_string_append_printf(gs, "%s", (gchar*)(gl->data));

				/* All but last element is separated by a bar. */
				if (g_list_next(gl))
					g_string_append(gs, "|");
			}

			return g_string_free(gs, FALSE);

		default:
			purple_debug_info("msim", "field %s, unknown type %d\n",
					elem->name ? elem->name : "(NULL)",
					elem->type);
			return NULL;
	}
}

/**
 * Send a message to the server, whose contents is specified using
 * variable arguments.
 *
 * @param session
 * @param ... A sequence of gchar* key/type/value triplets, terminated with NULL.
 *
 * This function exists for coding convenience: it allows a message to be created
 * and sent in one line of code. Internally it calls msim_msg_send().
 *
 * IMPORTANT: See msim_msg_append() documentation for details on element types.
 *
 */
gboolean
msim_send(MsimSession *session, ...)
{
	gboolean success;
	MsimMessage *msg;
	va_list argp;

	va_start(argp, session);
	msg = msim_msg_new_v(NULL, argp);
	va_end(argp);

	/* Actually send the message. */
	success = msim_msg_send(session, msg);

	/* Cleanup. */
	msim_msg_free(msg);

	return success;
}

/**
 * Print a human-readable string of the message to Purple's debug log.
 *
 * @param fmt_string A static string, in which '%s' will be replaced.
 */
void
msim_msg_dump(const gchar *fmt_string, MsimMessage *msg)
{
	gchar *debug_str;

	g_return_if_fail(fmt_string != NULL);

	debug_str = msim_msg_dump_to_str(msg);

	g_return_if_fail(debug_str != NULL);

	purple_debug_info("msim", fmt_string, debug_str);

	g_free(debug_str);
}

/**
 * Parse a raw protocol message string into a MsimMessage *.
 *
 * @param raw The raw message string to parse, will be g_free()'d.
 *
 * @return MsimMessage *. Caller should msim_msg_free() when done.
 */
MsimMessage *
msim_parse(const gchar *raw)
{
	MsimMessage *msg;
	gchar *token;
	gchar **tokens;
	gchar *key;
	gchar *value;
	int i;

	g_return_val_if_fail(raw != NULL, NULL);

	purple_debug_info("msim", "msim_parse: got <%s>\n", raw);

	key = NULL;

	/* All messages begin with a \. */
	if (raw[0] != '\\' || raw[1] == 0) {
		purple_debug_info("msim", "msim_parse: incomplete/bad string, "
				"missing initial backslash: <%s>\n", raw);
		/* XXX: Should we try to recover, and read to first backslash? */

		return NULL;
	}

	msg = msim_msg_new(FALSE);

	for (tokens = g_strsplit(raw + 1, "\\", 0), i = 0;
			(token = tokens[i]);
			i++) {
#ifdef MSIM_DEBUG_PARSE
		purple_debug_info("msim", "tok=<%s>, i%2=%d\n", token, i % 2);
#endif
		if (i % 2) {
			/* Odd-numbered ordinal is a value. */

			value = token;

			/* Incoming protocol messages get tagged as MSIM_TYPE_RAW, which
			 * represents an untyped piece of data. msim_msg_get_* will
			 * convert to appropriate types for caller, and handle unescaping if needed. */
			msg = msim_msg_append_dynamic_name(msg, g_strdup(key), MSIM_TYPE_RAW, g_strdup(value));
#ifdef MSIM_DEBUG_PARSE
			purple_debug_info("msim", "insert string: |%s|=|%s|\n", key, value);
#endif
		} else {
			/* Even numbered indexes are key names. */
			key = token;
		}
	}
	g_strfreev(tokens);

	return msg;
}

/**
 * Return the first MsimMessageElement * with given name in the MsimMessage *.
 *
 * @param name Name to search for.
 *
 * @return MsimMessageElement * matching name, or NULL.
 *
 * Note: useful fields of MsimMessageElement are 'data' and 'type', which
 * you can access directly. But it is often more convenient to use
 * another msim_msg_get_* that converts the data to what type you want.
 */
MsimMessageElement *
msim_msg_get(const MsimMessage *msg, const gchar *name)
{
	GList *node;

	node = msim_msg_get_node(msg, name);
	if (node) {
		return (MsimMessageElement *)node->data;
	} else {
		return NULL;
	}
}

gchar *
msim_msg_get_string_from_element(MsimMessageElement *elem)
{
	g_return_val_if_fail(elem != NULL, NULL);
	switch (elem->type) {
		case MSIM_TYPE_INTEGER:
			return g_strdup_printf("%d", GPOINTER_TO_UINT(elem->data));

		case MSIM_TYPE_RAW:
			/* Raw element from incoming message - if its a string, it'll
			 * be escaped. */
			return msim_unescape((gchar *)elem->data);

		case MSIM_TYPE_STRING:
			/* Already unescaped. */
			return g_strdup((gchar *)elem->data);

		default:
			purple_debug_info("msim", "msim_msg_get_string_element: type %d unknown, name %s\n",
					elem->type, elem->name ? elem->name : "(NULL)");
			return NULL;
	}
}

/**
 * Return the data of an element of a given name, as a string.
 *
 * @param name Name of element.
 *
 * @return gchar * The data as a string, or NULL if not found.
 *     Caller must g_free().
 *
 * Note that msim_msg_pack_element_data() is similar, but returns a string
 * for inclusion into a raw protocol string (escaped and everything).
 * This function unescapes the string for you, if needed.
 */
gchar *
msim_msg_get_string(const MsimMessage *msg, const gchar *name)
{
	MsimMessageElement *elem;

	elem = msim_msg_get(msg, name);
	if (!elem) {
		return NULL;
	}

	return msim_msg_get_string_from_element(elem);
}

/**
 * Parse a |-separated string into a new GList. Free with msim_msg_list_free().
 */
static GList *
msim_msg_list_parse(const gchar *raw)
{
	gchar **array;
	GList *list;
	guint i;

	array = g_strsplit(raw, "|", 0);
	list = NULL;

	/* TODO: escape/unescape /3 <-> | within list elements */

	for (i = 0; array[i] != NULL; ++i) {
		MsimMessageElement *elem;

		/* Freed in msim_msg_list_free() */
		elem = g_new0(MsimMessageElement, 1);

		/* Give the element a name for debugging purposes.
		 * Not supposed to be looked up by this name; instead,
		 * lookup the elements by indexing the array. */
		elem->name = g_strdup_printf("(list item #%d)", i);
		elem->type = MSIM_TYPE_RAW;
		elem->data = g_strdup(array[i]);

		list = g_list_append(list, elem);
	}

	g_strfreev(array);

	return list;
}

static GList *
msim_msg_get_list_from_element(MsimMessageElement *elem)
{
	g_return_val_if_fail(elem != NULL, NULL);
	switch (elem->type) {
		case MSIM_TYPE_LIST:
			return msim_msg_list_copy((GList *)elem->data);

		case MSIM_TYPE_RAW:
			return msim_msg_list_parse((gchar *)elem->data);

		default:
			purple_debug_info("msim_msg_get_list", "type %d unknown, name %s\n",
					elem->type, elem->name ? elem->name : "(NULL)");
			return NULL;
	}
}

/**
 * Return an element as a new list. Caller frees with msim_msg_list_free().
 */
GList *
msim_msg_get_list(const MsimMessage *msg, const gchar *name)
{
	MsimMessageElement *elem;

	elem = msim_msg_get(msg, name);
	if (!elem) {
		return NULL;
	}

	return msim_msg_get_list_from_element(elem);
}

/**
 * Parse a \x1c-separated "dictionary" of key=value pairs into a hash table.
 *
 * @param raw The text of the dictionary to parse. Often the
 *                 value for the 'body' field.
 *
 * @return A new MsimMessage *. Must msim_msg_free() when done.
 */
static MsimMessage *
msim_msg_dictionary_parse(const gchar *raw)
{
	MsimMessage *dict;
	gchar *item;
	gchar **items;
	gchar **elements;
	guint i;

	g_return_val_if_fail(raw != NULL, NULL);

	dict = msim_msg_new(NULL);

	for (items = g_strsplit(raw, "\x1c", 0), i = 0;
		(item = items[i]);
		i++) {
		gchar *key, *value;

		elements = g_strsplit(item, "=", 2);

		key = elements[0];
		if (!key) {
			purple_debug_info("msim", "msim_msg_dictionary_parse(%s): null key\n",
					raw);
			g_strfreev(elements);
			break;
		}

		value = elements[1];
		if (!value) {
			purple_debug_info("msim", "msim_msg_dictionary_prase(%s): null value\n",
					raw);
			g_strfreev(elements);
			break;
		}

#ifdef MSIM_DEBUG_PARSE
		purple_debug_info("msim_msg_dictionary_parse","-- %s: %s\n", key ? key : "(NULL)",
				value ? value : "(NULL)");
#endif
		/* Append with _dynamic_name since g_strdup(key) is dynamic, and
		 * needs to be freed when the message is destroyed. It isn't static as usual. */
		dict = msim_msg_append_dynamic_name(dict, g_strdup(key), MSIM_TYPE_RAW, g_strdup(value));

		g_strfreev(elements);
	}

	g_strfreev(items);

	return dict;
}

static MsimMessage *
msim_msg_get_dictionary_from_element(MsimMessageElement *elem)
{
	g_return_val_if_fail(elem != NULL, NULL);
	switch (elem->type) {
		case MSIM_TYPE_DICTIONARY:
			return msim_msg_clone((MsimMessage *)elem->data);

		case MSIM_TYPE_RAW:
			return msim_msg_dictionary_parse(elem->data);

		default:
			purple_debug_info("msim_msg_get_dictionary", "type %d unknown, name %s\n",
					elem->type, elem->name ? elem->name : "(NULL)");
			return NULL;
	}
}

/**
 * Return an element as a new dictionary. Caller frees with msim_msg_free().
 */
MsimMessage *
msim_msg_get_dictionary(const MsimMessage *msg, const gchar *name)
{
	MsimMessageElement *elem;

	elem = msim_msg_get(msg, name);
	if (!elem) {
		return NULL;
	}

	return msim_msg_get_dictionary_from_element(elem);
}

guint
msim_msg_get_integer_from_element(MsimMessageElement *elem)
{
	g_return_val_if_fail(elem != NULL, 0);
	switch (elem->type) {
		case MSIM_TYPE_INTEGER:
			return GPOINTER_TO_UINT(elem->data);

		case MSIM_TYPE_RAW:
		case MSIM_TYPE_STRING:
			/* TODO: find out if we need larger integers */
			return (guint)atoi((gchar *)elem->data);

		default:
			return 0;
	}
}

/**
 * Return the data of an element of a given name, as an unsigned integer.
 *
 * @param name Name of element.
 *
 * @return guint Numeric representation of data, or 0 if could not be converted / not found.
 *
 * Useful to obtain an element's data if you know it should be an integer,
 * even if it is not stored as an MSIM_TYPE_INTEGER. MSIM_TYPE_STRING will
 * be converted handled correctly, for example.
 */
guint
msim_msg_get_integer(const MsimMessage *msg, const gchar *name)
{
	MsimMessageElement *elem;

	elem = msim_msg_get(msg, name);

	if (!elem) {
		return 0;
	}

	return msim_msg_get_integer_from_element(elem);
}

static gboolean
msim_msg_get_binary_from_element(MsimMessageElement *elem, gchar **binary_data, gsize *binary_length)
{
	GString *gs;

	g_return_val_if_fail(elem != NULL, FALSE);

	switch (elem->type) {
		case MSIM_TYPE_RAW:
			 /* Incoming messages are tagged with MSIM_TYPE_RAW, and
			 * converted appropriately. They can still be "strings", just they won't
			 * be tagged as MSIM_TYPE_STRING (as MSIM_TYPE_STRING is intended to be used
			 * by msimprpl code for things like instant messages - stuff that should be
			 * escaped if needed). DWIM.
			 */

			/* Previously, incoming messages were stored as MSIM_TYPE_STRING.
			 * This was fine for integers and strings, since they can easily be
			 * converted in msim_get_*, as desirable. However, it does not work
			 * well for binary strings. Consider:
			 *
			 * If incoming base64'd elements were tagged as MSIM_TYPE_STRING.
			 * msim_msg_get_binary() sees MSIM_TYPE_STRING, base64 decodes, returns.
			 * everything is fine.
			 * But then, msim_send() is called on the incoming message, which has
			 * a base64'd MSIM_TYPE_STRING that really is encoded binary. The values
			 * will be escaped since strings are escaped, and / becomes /2; no good.
			 *
			 */
			*binary_data = (gchar *)purple_base64_decode((const gchar *)elem->data, binary_length);
			return ((*binary_data) != NULL);

		case MSIM_TYPE_BINARY:
			gs = (GString *)elem->data;

			/* Duplicate data, so caller can g_free() it. */
			*binary_data = g_memdup(gs->str, gs->len);
			*binary_length = gs->len;

			return TRUE;


			/* Rejected because if it isn't already a GString, have to g_new0 it and
			 * then caller has to ALSO free the GString!
			 *
			 * return (GString *)elem->data; */

		default:
			purple_debug_info("msim", "msim_msg_get_binary: unhandled type %d for key %s\n",
					elem->type, elem->name ? elem->name : "(NULL)");
			return FALSE;
	}
}

/**
 * Return the data of an element of a given name, as a binary GString.
 *
 * @param binary_data A pointer to a new pointer, which will be filled in with the binary data. CALLER MUST g_free().
 *
 * @param binary_length A pointer to an integer, which will be set to the binary data length.
 *
 * @return TRUE if successful, FALSE if not.
 */
gboolean
msim_msg_get_binary(const MsimMessage *msg, const gchar *name,
		gchar **binary_data, gsize *binary_length)
{
	MsimMessageElement *elem;

	elem = msim_msg_get(msg, name);
	if (!elem) {
		return FALSE;
	}

	return msim_msg_get_binary_from_element(elem, binary_data, binary_length);
}
