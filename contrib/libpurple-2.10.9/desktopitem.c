/**
 * @file purple-desktop-item.c Functions for managing .desktop files
 * @ingroup core
 */

/* Purple is the legal property of its developers, whose names are too numerous
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

/*
 * The following code has been adapted from gnome-desktop-item.[ch],
 * as found on gnome-desktop-2.8.1.
 *
 *   Copyright (C) 2004 by Alceste Scalas <alceste.scalas@gmx.net>.
 *
 * Original copyright notice:
 *
 * Copyright (C) 1999, 2000 Red Hat Inc.
 * Copyright (C) 2001 Sid Vicious
 * All rights reserved.
 *
 * This file is part of the Gnome Library.
 *
 * The Gnome Library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * The Gnome Library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with the Gnome Library; see the file COPYING.LIB.  If not,
 * write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02111-1301, USA.
 */

#include "internal.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "desktopitem.h"

struct _PurpleDesktopItem {
	int refcount;

	/* all languages used */
	GList *languages;

	PurpleDesktopItemType type;

	/* `modified' means that the ditem has been
	 * modified since the last save. */
	gboolean modified;

	/* Keys of the main section only */
	GList *keys;

	GList *sections;

	/* This includes ALL keys, including
	 * other sections, separated by '/' */
	GHashTable *main_hash;

	char *location;

	time_t mtime;
};

typedef struct {
	char *name;
	GList *keys;
} Section;

typedef enum {
	ENCODING_UNKNOWN,
	ENCODING_UTF8,
	ENCODING_LEGACY_MIXED
} Encoding;

/**************************************************************************
 * Private utility functions
 **************************************************************************/
static PurpleDesktopItemType
type_from_string (const char *type)
{
	if (!type)
		return PURPLE_DESKTOP_ITEM_TYPE_NULL;

	switch (type [0]) {
	case 'A':
		if (purple_strequal (type, "Application"))
			return PURPLE_DESKTOP_ITEM_TYPE_APPLICATION;
		break;
	case 'L':
		if (purple_strequal (type, "Link"))
			return PURPLE_DESKTOP_ITEM_TYPE_LINK;
		break;
	case 'F':
		if (purple_strequal (type, "FSDevice"))
			return PURPLE_DESKTOP_ITEM_TYPE_FSDEVICE;
		break;
	case 'M':
		if (purple_strequal (type, "MimeType"))
			return PURPLE_DESKTOP_ITEM_TYPE_MIME_TYPE;
		break;
	case 'D':
		if (purple_strequal (type, "Directory"))
			return PURPLE_DESKTOP_ITEM_TYPE_DIRECTORY;
		break;
	case 'S':
		if (purple_strequal (type, "Service"))
			return PURPLE_DESKTOP_ITEM_TYPE_SERVICE;

		else if (purple_strequal (type, "ServiceType"))
			return PURPLE_DESKTOP_ITEM_TYPE_SERVICE_TYPE;
		break;
	default:
		break;
	}

	return PURPLE_DESKTOP_ITEM_TYPE_OTHER;
}

static Section *
find_section (PurpleDesktopItem *item, const char *section)
{
	GList *li;
	Section *sec;

	if (section == NULL)
		return NULL;
	if (purple_strequal (section, "Desktop Entry"))
		return NULL;

	for (li = item->sections; li != NULL; li = li->next) {
		sec = li->data;
		if (purple_strequal (sec->name, section))
			return sec;
	}

	sec = g_new0 (Section, 1);
	sec->name = g_strdup (section);
	sec->keys = NULL;

	item->sections = g_list_append (item->sections, sec);

	/* Don't mark the item modified, this is just an empty section,
	 * it won't be saved even */

	return sec;
}

static Section *
section_from_key (PurpleDesktopItem *item, const char *key)
{
	char *p;
	char *name;
	Section *sec;

	if (key == NULL)
		return NULL;

	p = strchr (key, '/');
	if (p == NULL)
		return NULL;

	name = g_strndup (key, p - key);

	sec = find_section (item, name);

	g_free (name);

	return sec;
}

static const char *
key_basename (const char *key)
{
	char *p = strrchr (key, '/');
	if (p != NULL)
		return p+1;
	else
		return key;
}

static void
set (PurpleDesktopItem *item, const char *key, const char *value)
{
	Section *sec = section_from_key (item, key);

	if (sec != NULL) {
		if (value != NULL) {
			if (g_hash_table_lookup (item->main_hash, key) == NULL)
				sec->keys = g_list_append
					(sec->keys,
					 g_strdup (key_basename (key)));

			g_hash_table_replace (item->main_hash,
					      g_strdup (key),
					      g_strdup (value));
		} else {
			GList *list = g_list_find_custom
				(sec->keys, key_basename (key),
				 (GCompareFunc)strcmp);
			if (list != NULL) {
				g_free (list->data);
				sec->keys =
					g_list_delete_link (sec->keys, list);
			}
			g_hash_table_remove (item->main_hash, key);
		}
	} else {
		if (value != NULL) {
			if (g_hash_table_lookup (item->main_hash, key) == NULL)
				item->keys = g_list_append (item->keys,
							    g_strdup (key));

			g_hash_table_replace (item->main_hash,
					      g_strdup (key),
					      g_strdup (value));
		} else {
			GList *list = g_list_find_custom
				(item->keys, key, (GCompareFunc)strcmp);
			if (list != NULL) {
				g_free (list->data);
				item->keys =
					g_list_delete_link (item->keys, list);
			}
			g_hash_table_remove (item->main_hash, key);
		}
	}
	item->modified = TRUE;
}


static void
_purple_desktop_item_set_string (PurpleDesktopItem *item,
			       const char *attr,
			       const char *value)
{
	g_return_if_fail (item != NULL);
	g_return_if_fail (item->refcount > 0);
	g_return_if_fail (attr != NULL);

	set (item, attr, value);

	if (purple_strequal (attr, PURPLE_DESKTOP_ITEM_TYPE))
		item->type = type_from_string (value);
}

static PurpleDesktopItem *
_purple_desktop_item_new (void)
{
	PurpleDesktopItem *retval;

	retval = g_new0 (PurpleDesktopItem, 1);

	retval->refcount++;

	retval->main_hash = g_hash_table_new_full (g_str_hash, g_str_equal,
						   (GDestroyNotify) g_free,
						   (GDestroyNotify) g_free);

	/* These are guaranteed to be set */
	_purple_desktop_item_set_string (retval,
				       PURPLE_DESKTOP_ITEM_NAME,
				       _("No name"));
	_purple_desktop_item_set_string (retval,
				       PURPLE_DESKTOP_ITEM_ENCODING,
				       "UTF-8");
	_purple_desktop_item_set_string (retval,
				       PURPLE_DESKTOP_ITEM_VERSION,
				       "1.0");

	return retval;
}

static gpointer
_purple_desktop_item_copy (gpointer boxed)
{
	return purple_desktop_item_copy (boxed);
}

static void
_purple_desktop_item_free (gpointer boxed)
{
	purple_desktop_item_unref (boxed);
}

/* Note, does not include the trailing \n */
static char *
my_fgets (char *buf, gsize bufsize, FILE *df)
{
	int c;
	gsize pos;

	g_return_val_if_fail (buf != NULL, NULL);
	g_return_val_if_fail (df != NULL, NULL);

	pos = 0;
	buf[0] = '\0';

	do {
		c = getc (df);
		if (c == EOF || c == '\n')
			break;
		buf[pos++] = c;
	} while (pos < bufsize-1);

	if (c == EOF && pos == 0)
		return NULL;

	buf[pos] = '\0';

	return buf;
}

static Encoding
get_encoding (FILE *df)
{
	gboolean old_kde = FALSE;
	char     buf [BUFSIZ];
	gboolean all_valid_utf8 = TRUE;

	while (my_fgets (buf, sizeof (buf), df) != NULL) {
		if (strncmp (PURPLE_DESKTOP_ITEM_ENCODING,
			     buf,
			     strlen (PURPLE_DESKTOP_ITEM_ENCODING)) == 0) {
			char *p = &buf[strlen (PURPLE_DESKTOP_ITEM_ENCODING)];
			if (*p == ' ')
				p++;
			if (*p != '=')
				continue;
			p++;
			if (*p == ' ')
				p++;
			if (purple_strequal (p, "UTF-8")) {
				return ENCODING_UTF8;
			} else if (purple_strequal (p, "Legacy-Mixed")) {
				return ENCODING_LEGACY_MIXED;
			} else {
				/* According to the spec we're not supposed
				 * to read a file like this */
				return ENCODING_UNKNOWN;
			}
		} else if (purple_strequal ("[KDE Desktop Entry]", buf)) {
			old_kde = TRUE;
			/* don't break yet, we still want to support
			 * Encoding even here */
		}
		if (all_valid_utf8 && ! g_utf8_validate (buf, -1, NULL))
			all_valid_utf8 = FALSE;
	}

	if (old_kde)
		return ENCODING_LEGACY_MIXED;

	/* A dilemma, new KDE files are in UTF-8 but have no Encoding
	 * info, at this time we really can't tell.  The best thing to
	 * do right now is to just assume UTF-8 if the whole file
	 * validates as utf8 I suppose */

	if (all_valid_utf8)
		return ENCODING_UTF8;
	else
		return ENCODING_LEGACY_MIXED;
}

static char *
snarf_locale_from_key (const char *key)
{
	const char *brace;
	char *locale, *p;

	brace = strchr (key, '[');
	if (brace == NULL)
		return NULL;

	locale = g_strdup (brace + 1);
	if (*locale == '\0') {
		g_free (locale);
		return NULL;
	}
	p = strchr (locale, ']');
	if (p == NULL) {
		g_free (locale);
		return NULL;
	}
	*p = '\0';
	return locale;
}

static gboolean
check_locale (const char *locale)
{
	GIConv cd = g_iconv_open ("UTF-8", locale);
	if ((GIConv)-1 == cd)
		return FALSE;
	g_iconv_close (cd);
	return TRUE;
}

static void
insert_locales (GHashTable *encodings, char *enc, ...)
{
	va_list args;
	char *s;

	va_start (args, enc);
	for (;;) {
		s = va_arg (args, char *);
		if (s == NULL)
			break;
		g_hash_table_insert (encodings, s, enc);
	}
	va_end (args);
}

/* make a standard conversion table from the desktop standard spec */
static GHashTable *
init_encodings (void)
{
	GHashTable *encodings = g_hash_table_new (g_str_hash, g_str_equal);

	/* "C" is plain ascii */
	insert_locales (encodings, "ASCII", "C", NULL);

	insert_locales (encodings, "ARMSCII-8", "by", NULL);
	insert_locales (encodings, "BIG5", "zh_TW", NULL);
	insert_locales (encodings, "CP1251", "be", "bg", NULL);
	if (check_locale ("EUC-CN")) {
		insert_locales (encodings, "EUC-CN", "zh_CN", NULL);
	} else {
		insert_locales (encodings, "GB2312", "zh_CN", NULL);
	}
	insert_locales (encodings, "EUC-JP", "ja", NULL);
	insert_locales (encodings, "EUC-KR", "ko", NULL);
	/*insert_locales (encodings, "GEORGIAN-ACADEMY", NULL);*/
	insert_locales (encodings, "GEORGIAN-PS", "ka", NULL);
	insert_locales (encodings, "ISO-8859-1", "br", "ca", "da", "de", "en", "es", "eu", "fi", "fr", "gl", "it", "nl", "wa", "no", "pt", "pt", "sv", NULL);
	insert_locales (encodings, "ISO-8859-2", "cs", "hr", "hu", "pl", "ro", "sk", "sl", "sq", "sr", NULL);
	insert_locales (encodings, "ISO-8859-3", "eo", NULL);
	insert_locales (encodings, "ISO-8859-5", "mk", "sp", NULL);
	insert_locales (encodings, "ISO-8859-7", "el", NULL);
	insert_locales (encodings, "ISO-8859-9", "tr", NULL);
	insert_locales (encodings, "ISO-8859-13", "lt", "lv", "mi", NULL);
	insert_locales (encodings, "ISO-8859-14", "ga", "cy", NULL);
	insert_locales (encodings, "ISO-8859-15", "et", NULL);
	insert_locales (encodings, "KOI8-R", "ru", NULL);
	insert_locales (encodings, "KOI8-U", "uk", NULL);
	if (check_locale ("TCVN-5712")) {
		insert_locales (encodings, "TCVN-5712", "vi", NULL);
	} else {
		insert_locales (encodings, "TCVN", "vi", NULL);
	}
	insert_locales (encodings, "TIS-620", "th", NULL);
	/*insert_locales (encodings, "VISCII", NULL);*/

	return encodings;
}

static const char *
get_encoding_from_locale (const char *locale)
{
	char lang[3];
	const char *encoding;
	static GHashTable *encodings = NULL;

	if (locale == NULL)
		return NULL;

	/* if locale includes encoding, use it */
	encoding = strchr (locale, '.');
	if (encoding != NULL) {
		return encoding+1;
	}

	if (encodings == NULL)
		encodings = init_encodings ();

	/* first try the entire locale (at this point ll_CC) */
	encoding = g_hash_table_lookup (encodings, locale);
	if (encoding != NULL)
		return encoding;

	/* Try just the language */
	strncpy (lang, locale, 2);
	lang[2] = '\0';
	return g_hash_table_lookup (encodings, lang);
}

static char *
decode_string_and_dup (const char *s)
{
	char *p = g_malloc (strlen (s) + 1);
	char *q = p;

	do {
		if (*s == '\\'){
			switch (*(++s)){
			case 's':
				*p++ = ' ';
				break;
			case 't':
				*p++ = '\t';
				break;
			case 'n':
				*p++ = '\n';
				break;
			case '\\':
				*p++ = '\\';
				break;
			case 'r':
				*p++ = '\r';
				break;
			default:
				*p++ = '\\';
				*p++ = *s;
				break;
			}
		} else {
			*p++ = *s;
		}
	} while (*s++);

	return q;
}

static char *
decode_string (const char *value, Encoding encoding, const char *locale)
{
	char *retval = NULL;

	/* if legacy mixed, then convert */
	if (locale != NULL && encoding == ENCODING_LEGACY_MIXED) {
		const char *char_encoding = get_encoding_from_locale (locale);
		char *utf8_string;
		if (char_encoding == NULL)
			return NULL;
		if (purple_strequal (char_encoding, "ASCII")) {
			return decode_string_and_dup (value);
		}
		utf8_string = g_convert (value, -1, "UTF-8", char_encoding,
					NULL, NULL, NULL);
		if (utf8_string == NULL)
			return NULL;
		retval = decode_string_and_dup (utf8_string);
		g_free (utf8_string);
		return retval;
	/* if utf8, then validate */
	} else if (locale != NULL && encoding == ENCODING_UTF8) {
		if ( ! g_utf8_validate (value, -1, NULL))
			/* invalid utf8, ignore this key */
			return NULL;
		return decode_string_and_dup (value);
	} else {
		/* Meaning this is not a localized string */
		return decode_string_and_dup (value);
	}
}

/************************************************************
 * Parser:                                                  *
 ************************************************************/

static gboolean G_GNUC_CONST
standard_is_boolean (const char * key)
{
	static GHashTable *bools = NULL;

	if (bools == NULL) {
		bools = g_hash_table_new (g_str_hash, g_str_equal);
		g_hash_table_insert (bools,
				     PURPLE_DESKTOP_ITEM_NO_DISPLAY,
				     PURPLE_DESKTOP_ITEM_NO_DISPLAY);
		g_hash_table_insert (bools,
				     PURPLE_DESKTOP_ITEM_HIDDEN,
				     PURPLE_DESKTOP_ITEM_HIDDEN);
		g_hash_table_insert (bools,
				     PURPLE_DESKTOP_ITEM_TERMINAL,
				     PURPLE_DESKTOP_ITEM_TERMINAL);
		g_hash_table_insert (bools,
				     PURPLE_DESKTOP_ITEM_READ_ONLY,
				     PURPLE_DESKTOP_ITEM_READ_ONLY);
	}

	return g_hash_table_lookup (bools, key) != NULL;
}

static gboolean G_GNUC_CONST
standard_is_strings (const char *key)
{
	static GHashTable *strings = NULL;

	if (strings == NULL) {
		strings = g_hash_table_new (g_str_hash, g_str_equal);
		g_hash_table_insert (strings,
				     PURPLE_DESKTOP_ITEM_FILE_PATTERN,
				     PURPLE_DESKTOP_ITEM_FILE_PATTERN);
		g_hash_table_insert (strings,
				     PURPLE_DESKTOP_ITEM_ACTIONS,
				     PURPLE_DESKTOP_ITEM_ACTIONS);
		g_hash_table_insert (strings,
				     PURPLE_DESKTOP_ITEM_MIME_TYPE,
				     PURPLE_DESKTOP_ITEM_MIME_TYPE);
		g_hash_table_insert (strings,
				     PURPLE_DESKTOP_ITEM_PATTERNS,
				     PURPLE_DESKTOP_ITEM_PATTERNS);
		g_hash_table_insert (strings,
				     PURPLE_DESKTOP_ITEM_SORT_ORDER,
				     PURPLE_DESKTOP_ITEM_SORT_ORDER);
	}

	return g_hash_table_lookup (strings, key) != NULL;
}

/* If no need to cannonize, returns NULL */
static char *
cannonize (const char *key, const char *value)
{
	if (standard_is_boolean (key)) {
		if (value[0] == 'T' ||
		    value[0] == 't' ||
		    value[0] == 'Y' ||
		    value[0] == 'y' ||
		    atoi (value) != 0) {
			return g_strdup ("true");
		} else {
			return g_strdup ("false");
		}
	} else if (standard_is_strings (key)) {
		int len = strlen (value);
		if (len == 0 || value[len-1] != ';') {
			return g_strconcat (value, ";", NULL);
		}
	}
	/* XXX: Perhaps we should canonize numeric values as well, but this
	 * has caused some subtle problems before so it needs to be done
	 * carefully if at all */
	return NULL;
}

static void
insert_key (PurpleDesktopItem *item,
	    Section *cur_section,
	    Encoding encoding,
	    const char *key,
	    const char *value,
	    gboolean old_kde,
	    gboolean no_translations)
{
	char *k;
	char *val;
	/* we always store everything in UTF-8 */
	if (cur_section == NULL &&
	    purple_strequal (key, PURPLE_DESKTOP_ITEM_ENCODING)) {
		k = g_strdup (key);
		val = g_strdup ("UTF-8");
	} else {
		char *locale = snarf_locale_from_key (key);
		/* If we're ignoring translations */
		if (no_translations && locale != NULL) {
			g_free (locale);
			return;
		}
		val = decode_string (value, encoding, locale);

		/* Ignore this key, it's whacked */
		if (val == NULL) {
			g_free (locale);
			return;
		}

		g_strchomp (val);

		/* For old KDE entries, we can also split by a comma
		 * on sort order, so convert to semicolons */
		if (old_kde &&
		    cur_section == NULL &&
		    purple_strequal (key, PURPLE_DESKTOP_ITEM_SORT_ORDER) &&
		    strchr (val, ';') == NULL) {
			int i;
			for (i = 0; val[i] != '\0'; i++) {
				if (val[i] == ',')
					val[i] = ';';
			}
		}

		/* Check some types, not perfect, but catches a lot
		 * of things */
		if (cur_section == NULL) {
			char *cannon = cannonize (key, val);
			if (cannon != NULL) {
				g_free (val);
				val = cannon;
			}
		}

		k = g_strdup (key);

		/* Take care of the language part */
		if (locale != NULL &&
		    purple_strequal (locale, "C")) {
			char *p;
			/* Whack C locale */
			p = strchr (k, '[');
			if(p) *p = '\0';
			g_free (locale);
		} else if (locale != NULL) {
			char *p, *brace;

			/* Whack the encoding part */
			p = strchr (locale, '.');
			if (p != NULL)
				*p = '\0';

			if (g_list_find_custom (item->languages, locale,
						(GCompareFunc)strcmp) == NULL) {
				item->languages = g_list_prepend
					(item->languages, locale);
			} else {
				g_free (locale);
			}

			/* Whack encoding from encoding in the key */
			brace = strchr (k, '[');
			if(brace != NULL) {
				p = strchr (brace, '.');
				if (p != NULL) {
					*p = ']';
					*(p+1) = '\0';
				}
			}
		}
	}


	if (cur_section == NULL) {
		/* only add to list if we haven't seen it before */
		if (g_hash_table_lookup (item->main_hash, k) == NULL) {
			item->keys = g_list_prepend (item->keys,
						     g_strdup (k));
		}
		/* later duplicates override earlier ones */
		g_hash_table_replace (item->main_hash, k, val);
	} else {
		char *full = g_strdup_printf
			("%s/%s",
			 cur_section->name, k);
		/* only add to list if we haven't seen it before */
		if (g_hash_table_lookup (item->main_hash, full) == NULL) {
			cur_section->keys =
				g_list_prepend (cur_section->keys, k);
		}
		/* later duplicates override earlier ones */
		g_hash_table_replace (item->main_hash,
				      full, val);
	}
}

static const char *
lookup (const PurpleDesktopItem *item, const char *key)
{
	return g_hash_table_lookup (item->main_hash, key);
}

static void
setup_type (PurpleDesktopItem *item, const char *uri)
{
	const char *type = g_hash_table_lookup (item->main_hash,
						PURPLE_DESKTOP_ITEM_TYPE);
	if (type == NULL && uri != NULL) {
		char *base = g_path_get_basename (uri);
		if (purple_strequal(base, ".directory")) {
			/* This gotta be a directory */
			g_hash_table_replace (item->main_hash,
					      g_strdup (PURPLE_DESKTOP_ITEM_TYPE),
					      g_strdup ("Directory"));
			item->keys = g_list_prepend
				(item->keys, g_strdup (PURPLE_DESKTOP_ITEM_TYPE));
			item->type = PURPLE_DESKTOP_ITEM_TYPE_DIRECTORY;
		} else {
			item->type = PURPLE_DESKTOP_ITEM_TYPE_NULL;
		}
		g_free (base);
	} else {
		item->type = type_from_string (type);
	}
}

static const char *
lookup_locale (const PurpleDesktopItem *item, const char *key, const char *locale)
{
	if (locale == NULL ||
	    purple_strequal (locale, "C")) {
		return lookup (item, key);
	} else {
		const char *ret;
		char *full = g_strdup_printf ("%s[%s]", key, locale);
		ret = lookup (item, full);
		g_free (full);
		return ret;
	}
}

/**
 * Fallback to find something suitable for C locale.
 *
 * @return A newly allocated string which should be g_freed by the caller.
 */
static char *
try_english_key (PurpleDesktopItem *item, const char *key)
{
	char *str = NULL;
	char *locales[] = { "en_US", "en_GB", "en_AU", "en", NULL };
	int i;

	for (i = 0; locales[i] != NULL && str == NULL; i++) {
		str = g_strdup (lookup_locale (item, key, locales[i]));
	}
	if (str != NULL) {
		/* We need a 7-bit ascii string, so whack all
		 * above 127 chars */
		guchar *p;
		for (p = (guchar *)str; *p != '\0'; p++) {
			if (*p > 127)
				*p = '?';
		}
	}
	return str;
}


static void
sanitize (PurpleDesktopItem *item, const char *uri)
{
	const char *type;

	type = lookup (item, PURPLE_DESKTOP_ITEM_TYPE);

	/* understand old gnome style url exec thingies */
	if (purple_strequal(type, "URL")) {
		const char *exec = lookup (item, PURPLE_DESKTOP_ITEM_EXEC);
		set (item, PURPLE_DESKTOP_ITEM_TYPE, "Link");
		if (exec != NULL) {
			/* Note, this must be in this order */
			set (item, PURPLE_DESKTOP_ITEM_URL, exec);
			set (item, PURPLE_DESKTOP_ITEM_EXEC, NULL);
		}
	}

	/* we make sure we have Name, Encoding and Version */
	if (lookup (item, PURPLE_DESKTOP_ITEM_NAME) == NULL) {
		char *name = try_english_key (item, PURPLE_DESKTOP_ITEM_NAME);
		/* If no name, use the basename */
		if (name == NULL && uri != NULL)
			name = g_path_get_basename (uri);
		/* If no uri either, use same default as gnome_desktop_item_new */
		if (name == NULL)
			name = g_strdup (_("No name"));
		g_hash_table_replace (item->main_hash,
				      g_strdup (PURPLE_DESKTOP_ITEM_NAME),
				      name);
		item->keys = g_list_prepend
			(item->keys, g_strdup (PURPLE_DESKTOP_ITEM_NAME));
	}
	if (lookup (item, PURPLE_DESKTOP_ITEM_ENCODING) == NULL) {
		/* We store everything in UTF-8 so write that down */
		g_hash_table_replace (item->main_hash,
				      g_strdup (PURPLE_DESKTOP_ITEM_ENCODING),
				      g_strdup ("UTF-8"));
		item->keys = g_list_prepend
			(item->keys, g_strdup (PURPLE_DESKTOP_ITEM_ENCODING));
	}
	if (lookup (item, PURPLE_DESKTOP_ITEM_VERSION) == NULL) {
		/* this is the version that we follow, so write it down */
		g_hash_table_replace (item->main_hash,
				      g_strdup (PURPLE_DESKTOP_ITEM_VERSION),
				      g_strdup ("1.0"));
		item->keys = g_list_prepend
			(item->keys, g_strdup (PURPLE_DESKTOP_ITEM_VERSION));
	}
}

enum {
	FirstBrace,
	OnSecHeader,
	IgnoreToEOL,
	IgnoreToEOLFirst,
	KeyDef,
	KeyDefOnKey,
	KeyValue
};

static PurpleDesktopItem *
ditem_load (FILE *df,
	    gboolean no_translations,
	    const char *uri)
{
	int state;
	char CharBuffer [1024];
	char *next = CharBuffer;
	int c;
	Encoding encoding;
	PurpleDesktopItem *item;
	Section *cur_section = NULL;
	char *key = NULL;
	gboolean old_kde = FALSE;

	encoding = get_encoding (df);
	if (encoding == ENCODING_UNKNOWN) {
		fclose(df);
		/* spec says, don't read this file */
		printf ("Unknown encoding of .desktop file");

		return NULL;
	}

	/* Rewind since get_encoding goes through the file */
	if (fseek(df, 0L, SEEK_SET)) {
		fclose(df);
		/* spec says, don't read this file */
		printf ("fseek() error on .desktop file");
		return NULL;
	}

	item = _purple_desktop_item_new ();
	item->modified = FALSE;

	/* Note: location and mtime are filled in by the new_from_file
	 * function since it has those values */

#define PURPLE_DESKTOP_ITEM_OVERFLOW (next == &CharBuffer [sizeof(CharBuffer)-1])

	state = FirstBrace;
	while ((c = getc (df)) != EOF) {
		if (c == '\r')		/* Ignore Carriage Return */
			continue;

		switch (state) {

		case OnSecHeader:
			if (c == ']' || PURPLE_DESKTOP_ITEM_OVERFLOW) {
				*next = '\0';
				next = CharBuffer;

				/* keys were inserted in reverse */
				if (cur_section != NULL &&
				    cur_section->keys != NULL) {
					cur_section->keys = g_list_reverse
						(cur_section->keys);
				}
				if (purple_strequal (CharBuffer, "KDE Desktop Entry")) {
					/* Main section */
					cur_section = NULL;
					old_kde = TRUE;
				} else if (purple_strequal(CharBuffer, "Desktop Entry")) {
					/* Main section */
					cur_section = NULL;
				} else {
					cur_section = g_new0 (Section, 1);
					cur_section->name =
						g_strdup (CharBuffer);
					cur_section->keys = NULL;
					item->sections = g_list_prepend
						(item->sections, cur_section);
				}
				state = IgnoreToEOL;
			} else if (c == '[') {
				/* FIXME: probably error out instead of ignoring this */
			} else {
				*next++ = c;
			}
			break;

		case IgnoreToEOL:
		case IgnoreToEOLFirst:
			if (c == '\n'){
				if (state == IgnoreToEOLFirst)
					state = FirstBrace;
				else
					state = KeyDef;
				next = CharBuffer;
			}
			break;

		case FirstBrace:
		case KeyDef:
		case KeyDefOnKey:
			if (c == '#') {
				if (state == FirstBrace)
					state = IgnoreToEOLFirst;
				else
					state = IgnoreToEOL;
				break;
			}

			if (c == '[' && state != KeyDefOnKey){
				state = OnSecHeader;
				next = CharBuffer;
				g_free (key);
				key = NULL;
				break;
			}
			/* On first pass, don't allow dangling keys */
			if (state == FirstBrace)
				break;

			if ((c == ' ' && state != KeyDefOnKey) || c == '\t')
				break;

			if (c == '\n' || PURPLE_DESKTOP_ITEM_OVERFLOW) { /* Abort Definition */
				next = CharBuffer;
				state = KeyDef;
				break;
			}

			if (c == '=' || PURPLE_DESKTOP_ITEM_OVERFLOW){
				*next = '\0';

				g_free (key);
				key = g_strdup (CharBuffer);
				state = KeyValue;
				next = CharBuffer;
			} else {
				*next++ = c;
				state = KeyDefOnKey;
			}
			break;

		case KeyValue:
			if (PURPLE_DESKTOP_ITEM_OVERFLOW || c == '\n'){
				*next = '\0';

				insert_key (item, cur_section, encoding,
					    key, CharBuffer, old_kde,
					    no_translations);

				g_free (key);
				key = NULL;

				state = (c == '\n') ? KeyDef : IgnoreToEOL;
				next = CharBuffer;
			} else {
				*next++ = c;
			}
			break;

		} /* switch */

	} /* while ((c = getc_unlocked (f)) != EOF) */
	if (c == EOF && state == KeyValue) {
		*next = '\0';

		insert_key (item, cur_section, encoding,
			    key, CharBuffer, old_kde,
			    no_translations);

		g_free (key);
		key = NULL;
	}

#undef PURPLE_DESKTOP_ITEM_OVERFLOW

	/* keys were inserted in reverse */
	if (cur_section != NULL &&
	    cur_section->keys != NULL) {
		cur_section->keys = g_list_reverse (cur_section->keys);
	}
	/* keys were inserted in reverse */
	item->keys = g_list_reverse (item->keys);
	/* sections were inserted in reverse */
	item->sections = g_list_reverse (item->sections);

	/* sanitize some things */
	sanitize (item, uri);

	/* make sure that we set up the type */
	setup_type (item, uri);

	fclose (df);

	return item;
}

static void
copy_string_hash (gpointer key, gpointer value, gpointer user_data)
{
	GHashTable *copy = user_data;
	g_hash_table_replace (copy,
			      g_strdup (key),
			      g_strdup (value));
}

static void
free_section (gpointer data, gpointer user_data)
{
	Section *section = data;

	g_free (section->name);
	section->name = NULL;

	g_list_foreach (section->keys, (GFunc)g_free, NULL);
	g_list_free (section->keys);
	section->keys = NULL;

	g_free (section);
}

static Section *
dup_section (Section *sec)
{
	GList *li;
	Section *retval = g_new0 (Section, 1);

	retval->name = g_strdup (sec->name);

	retval->keys = g_list_copy (sec->keys);
	for (li = retval->keys; li != NULL; li = li->next)
		li->data = g_strdup (li->data);

	return retval;
}

/**************************************************************************
 * Public functions
 **************************************************************************/
PurpleDesktopItem *
purple_desktop_item_new_from_file (const char *filename)
{
	PurpleDesktopItem *retval;
	FILE *dfile;

	g_return_val_if_fail (filename != NULL, NULL);

	dfile = g_fopen(filename, "r");
	if (!dfile) {
		printf ("Can't open %s: %s", filename, g_strerror(errno));
		return NULL;
	}

	retval = ditem_load(dfile, FALSE, filename);

	return retval;
}

PurpleDesktopItemType
purple_desktop_item_get_entry_type (const PurpleDesktopItem *item)
{
	g_return_val_if_fail (item != NULL, 0);
	g_return_val_if_fail (item->refcount > 0, 0);

	return item->type;
}

const char *
purple_desktop_item_get_string (const PurpleDesktopItem *item,
			      const char *attr)
{
	g_return_val_if_fail (item != NULL, NULL);
	g_return_val_if_fail (item->refcount > 0, NULL);
	g_return_val_if_fail (attr != NULL, NULL);

	return lookup (item, attr);
}

PurpleDesktopItem *
purple_desktop_item_copy (const PurpleDesktopItem *item)
{
	GList *li;
	PurpleDesktopItem *retval;

	g_return_val_if_fail (item != NULL, NULL);
	g_return_val_if_fail (item->refcount > 0, NULL);

	retval = _purple_desktop_item_new ();

	retval->type = item->type;
	retval->modified = item->modified;
	retval->location = g_strdup (item->location);
	retval->mtime = item->mtime;

	/* Languages */
	retval->languages = g_list_copy (item->languages);
	for (li = retval->languages; li != NULL; li = li->next)
		li->data = g_strdup (li->data);

	/* Keys */
	retval->keys = g_list_copy (item->keys);
	for (li = retval->keys; li != NULL; li = li->next)
		li->data = g_strdup (li->data);

	/* Sections */
	retval->sections = g_list_copy (item->sections);
	for (li = retval->sections; li != NULL; li = li->next)
		li->data = dup_section (li->data);

	retval->main_hash = g_hash_table_new_full (g_str_hash, g_str_equal,
						   (GDestroyNotify) g_free,
						   (GDestroyNotify) g_free);

	g_hash_table_foreach (item->main_hash,
			      copy_string_hash,
			      retval->main_hash);

	return retval;
}

void
purple_desktop_item_unref (PurpleDesktopItem *item)
{
	g_return_if_fail (item != NULL);
	g_return_if_fail (item->refcount > 0);

	item->refcount--;

	if(item->refcount != 0)
		return;

	g_list_foreach (item->languages, (GFunc)g_free, NULL);
	g_list_free (item->languages);
	item->languages = NULL;

	g_list_foreach (item->keys, (GFunc)g_free, NULL);
	g_list_free (item->keys);
	item->keys = NULL;

	g_list_foreach (item->sections, free_section, NULL);
	g_list_free (item->sections);
	item->sections = NULL;

	g_hash_table_destroy (item->main_hash);
	item->main_hash = NULL;

	g_free (item->location);
	item->location = NULL;

	g_free (item);
}

GType
purple_desktop_item_get_type (void)
{
	static GType type = 0;

	if (type == 0) {
		type = g_boxed_type_register_static ("PurpleDesktopItem",
						     _purple_desktop_item_copy,
						     _purple_desktop_item_free);
	}

	return type;
}
