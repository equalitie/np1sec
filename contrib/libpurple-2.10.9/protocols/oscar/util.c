/*
 * Purple's oscar protocol plugin
 * This file is the legal property of its developers.
 * Please see the AUTHORS file distributed alongside this file.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02111-1301  USA
*/

/*
 * A little bit of this
 * A little bit of that
 * It started with a kiss
 * Now we're up to bat
 */

#include "oscar.h"

#include "core.h"

#include <ctype.h>

#ifdef _WIN32
#include "win32dep.h"
#endif

static const char * const msgerrreason[] = {
	N_("Invalid error"),
	N_("Invalid SNAC"),
	N_("Server rate limit exceeded"),
	N_("Client rate limit exceeded"),
	N_("Not logged in"),
	N_("Service unavailable"),
	N_("Service not defined"),
	N_("Obsolete SNAC"),
	N_("Not supported by host"),
	N_("Not supported by client"),
	N_("Refused by client"),
	N_("Reply too big"),
	N_("Responses lost"),
	N_("Request denied"),
	N_("Busted SNAC payload"),
	N_("Insufficient rights"),
	N_("In local permit/deny"),
	N_("Warning level too high (sender)"),
	N_("Warning level too high (receiver)"),
	N_("User temporarily unavailable"),
	N_("No match"),
	N_("List overflow"),
	N_("Request ambiguous"),
	N_("Queue full"),
	N_("Not while on AOL")
};
static const int msgerrreasonlen = G_N_ELEMENTS(msgerrreason);

const char *oscar_get_msgerr_reason(size_t reason)
{
	return (reason < msgerrreasonlen) ? _(msgerrreason[reason]) : _("Unknown reason");
}

int oscar_get_ui_info_int(const char *str, int default_value)
{
	GHashTable *ui_info;

	ui_info = purple_core_get_ui_info();
	if (ui_info != NULL) {
		gpointer value;
		if (g_hash_table_lookup_extended(ui_info, str, NULL, &value))
			return GPOINTER_TO_INT(value);
	}

	return default_value;
}

const char *oscar_get_ui_info_string(const char *str, const char *default_value)
{
	GHashTable *ui_info;
	const char *value = NULL;

	ui_info = purple_core_get_ui_info();
	if (ui_info != NULL)
		value = g_hash_table_lookup(ui_info, str);
	if (value == NULL)
		value = default_value;

	return value;
}

gchar *oscar_get_clientstring(void)
{
	const char *name, *version;

	name = oscar_get_ui_info_string("name", "Purple");
	version = oscar_get_ui_info_string("version", VERSION);

	return g_strdup_printf("%s/%s", name, version);;
}

/**
 * Calculate the checksum of a given icon.
 */
guint16
aimutil_iconsum(const guint8 *buf, int buflen)
{
	guint32 sum;
	int i;

	for (i=0, sum=0; i+1<buflen; i+=2)
		sum += (buf[i+1] << 8) + buf[i];
	if (i < buflen)
		sum += buf[i];
	sum = ((sum & 0xffff0000) >> 16) + (sum & 0x0000ffff);

	return sum;
}

/**
 * Check if the given name is a valid AIM username.
 * Example: BobDole
 * Example: Henry_Ford@mac.com
 * Example: 1KrazyKat@example.com
 *
 * @return TRUE if the name is valid, FALSE if not.
 */
static gboolean
oscar_util_valid_name_aim(const char *name)
{
	int i;

	if (purple_email_is_valid(name))
		return TRUE;

	/* Normal AIM usernames can't start with a number, period or underscore */
	if (isalnum(name[0]) == 0)
		return FALSE;

	for (i = 0; name[i] != '\0'; i++) {
		if (!isalnum(name[i]) && name[i] != ' ' && name[i] != '.' && name[i] != '_')
			return FALSE;
	}

	return TRUE;
}

/**
 * Check if the given name is a valid ICQ username.
 * Example: 1234567
 *
 * @return TRUE if the name is valid, FALSE if not.
 */
gboolean
oscar_util_valid_name_icq(const char *name)
{
	int i;

	for (i = 0; name[i] != '\0'; i++) {
		if (!isdigit(name[i]))
			return FALSE;
	}

	return TRUE;
}

/**
 * Check if the given name is a valid SMS username.
 * Example: +19195551234
 *
 * @return TRUE if the name is valid, FALSE if not.
 */
gboolean
oscar_util_valid_name_sms(const char *name)
{
	int i;

	if (name[0] != '+')
		return FALSE;

	for (i = 1; name[i] != '\0'; i++) {
		if (!isdigit(name[i]))
			return FALSE;
	}

	return TRUE;
}

/**
 * Check if the given name is a valid oscar username.
 *
 * @return TRUE if the name is valid, FALSE if not.
 */
gboolean
oscar_util_valid_name(const char *name)
{
	if ((name == NULL) || (*name == '\0'))
		return FALSE;

	return oscar_util_valid_name_icq(name)
			|| oscar_util_valid_name_sms(name)
			|| oscar_util_valid_name_aim(name);
}

/**
 * This takes two names and compares them using the rules
 * on usernames for AIM/AOL.  Mainly, this means case and space
 * insensitivity (all case differences and spacing differences are
 * ignored, with the exception that usernames can not start with
 * a space).
 *
 * @return 0 if equal, non-0 if different
 */
/* TODO: Do something different for email addresses. */
int
oscar_util_name_compare(const char *name1, const char *name2)
{

	if ((name1 == NULL) || (name2 == NULL))
		return -1;

	do {
		while (*name2 == ' ')
			name2++;
		while (*name1 == ' ')
			name1++;
		if (toupper(*name1) != toupper(*name2))
			return 1;
	} while ((*name1 != '\0') && name1++ && name2++);

	return 0;
}

/**
 * Looks for %n, %d, or %t in a string, and replaces them with the
 * specified name, date, and time, respectively.
 *
 * @param str  The string that may contain the special variables.
 * @param name The sender name.
 *
 * @return A newly allocated string where the special variables are
 *         expanded.  This should be g_free'd by the caller.
 */
gchar *
oscar_util_format_string(const char *str, const char *name)
{
	char *c;
	GString *cpy;
	time_t t;
	struct tm *tme;

	g_return_val_if_fail(str  != NULL, NULL);
	g_return_val_if_fail(name != NULL, NULL);

	/* Create an empty GString that is hopefully big enough for most messages */
	cpy = g_string_sized_new(1024);

	t = time(NULL);
	tme = localtime(&t);

	c = (char *)str;
	while (*c) {
		switch (*c) {
		case '%':
			if (*(c + 1)) {
				switch (*(c + 1)) {
				case 'n':
					/* append name */
					g_string_append(cpy, name);
					c++;
					break;
				case 'd':
					/* append date */
					g_string_append(cpy, purple_date_format_short(tme));
					c++;
					break;
				case 't':
					/* append time */
					g_string_append(cpy, purple_time_format(tme));
					c++;
					break;
				default:
					g_string_append_c(cpy, *c);
				}
			} else {
				g_string_append_c(cpy, *c);
			}
			break;
		default:
			g_string_append_c(cpy, *c);
		}
		c++;
	}

	return g_string_free(cpy, FALSE);
}

gchar *
oscar_format_buddies(GSList *buddies, const gchar *no_buddies_message)
{
	GSList *cur;
	GString *result;
	if (!buddies) {
		return g_strdup_printf("<i>%s</i>", no_buddies_message);
	}
	result = g_string_new("");
	for (cur = buddies; cur != NULL; cur = cur->next) {
		PurpleBuddy *buddy = cur->data;
		const gchar *bname = purple_buddy_get_name(buddy);
		const gchar *alias = purple_buddy_get_alias_only(buddy);
		g_string_append(result, bname);
		if (alias) {
			g_string_append_printf(result, " (%s)", alias);
		}
		g_string_append(result, "<br>");
	}
	return g_string_free(result, FALSE);
}
