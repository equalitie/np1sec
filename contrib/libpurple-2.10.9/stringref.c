/**
 * @file stringref.c Reference-counted immutable strings
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
 *
 */

#include "internal.h"

#include <string.h>
#include <stdarg.h>

#include "debug.h"
#include "eventloop.h"
#include "stringref.h"

/**
 * The internal representation of a stringref.
 *
 * @note For this structure to be useful, the string contained within
 * it must be immutable -- for this reason, do _not_ access it
 * directly!
 */
struct _PurpleStringref {
	guint32 ref;	/**< The reference count of this string.
					 *   Note that reference counts are only
					 *   31 bits, and the high-order bit
					 *   indicates whether this string is up
					 *   for GC at the next idle handler...
					 *   But you aren't going to touch this
					 *   anyway, right? */
	char value[1];	/**< The string contained in this ref.
					 *   Notice that it is simply "hanging
					 *   off the end" of the ref ... this
					 *   is to save an allocation. */
};

#define REFCOUNT(x) ((x) & 0x7fffffff)

static GList *gclist = NULL;

static void stringref_free(PurpleStringref *stringref);
static gboolean gs_idle_cb(gpointer data);

PurpleStringref *purple_stringref_new(const char *value)
{
	PurpleStringref *newref;
	size_t len;

	if (value == NULL)
		return NULL;

	len = strlen(value);

	newref = g_malloc(sizeof(PurpleStringref) + len);
	/* g_strlcpy() takes the size of the buffer, including the NUL.
	   strlen() returns the length of the string, without the NUL. */
	g_strlcpy(newref->value, value, len + 1);
	newref->ref = 1;

	return newref;
}

PurpleStringref *purple_stringref_new_noref(const char *value)
{
	PurpleStringref *newref;

	if (value == NULL)
		return NULL;

	newref = g_malloc(sizeof(PurpleStringref) + strlen(value));
	strcpy(newref->value, value);
	newref->ref = 0x80000000;

	if (gclist == NULL)
		purple_timeout_add(0, gs_idle_cb, NULL);
	gclist = g_list_prepend(gclist, newref);

	return newref;
}

PurpleStringref *purple_stringref_printf(const char *format, ...)
{
	PurpleStringref *newref;
	va_list ap;

	if (format == NULL)
		return NULL;

	va_start(ap, format);
	newref = g_malloc(sizeof(PurpleStringref) + g_printf_string_upper_bound(format, ap));
	vsprintf(newref->value, format, ap);
	va_end(ap);
	newref->ref = 1;

	return newref;
}

PurpleStringref *purple_stringref_ref(PurpleStringref *stringref)
{
	if (stringref == NULL)
		return NULL;
	stringref->ref++;
	return stringref;
}

void purple_stringref_unref(PurpleStringref *stringref)
{
	if (stringref == NULL)
		return;
	if (REFCOUNT(--(stringref->ref)) == 0) {
		if (stringref->ref & 0x80000000)
			gclist = g_list_remove(gclist, stringref);
		stringref_free(stringref);
	}
}

const char *purple_stringref_value(const PurpleStringref *stringref)
{
	return (stringref == NULL ? NULL : stringref->value);
}

int purple_stringref_cmp(const PurpleStringref *s1, const PurpleStringref *s2)
{
	return (s1 == s2 ? 0 : strcmp(purple_stringref_value(s1), purple_stringref_value(s2)));
}

size_t purple_stringref_len(const PurpleStringref *stringref)
{
	return strlen(purple_stringref_value(stringref));
}

static void stringref_free(PurpleStringref *stringref)
{
#ifdef DEBUG
	if (REFCOUNT(stringref->ref) != 0) {
		purple_debug(PURPLE_DEBUG_ERROR, "stringref", "Free of nonzero (%d) ref stringref!\n", REFCOUNT(stringref->ref));
		return;
	}
#endif /* DEBUG */
	g_free(stringref);
}

static gboolean gs_idle_cb(gpointer data)
{
	PurpleStringref *ref;
	GList *del;

	while (gclist != NULL) {
		ref = gclist->data;
		if (REFCOUNT(ref->ref) == 0) {
			stringref_free(ref);
		}
		del = gclist;
		gclist = gclist->next;
		g_list_free_1(del);
	}

	return FALSE;
}
