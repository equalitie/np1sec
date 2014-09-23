/**
 * @file gg-utils.c
 *
 * purple
 *
 * Copyright (C) 2005  Bartosz Oler <bartosz@bzimage.us>
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


#include "gg-utils.h"


/* uin_t ggp_str_to_uin(const char *str) {{{ */
uin_t ggp_str_to_uin(const char *str)
{
	char *tmp;
	long num;

	if (!str)
		return 0;

	errno = 0;
	num = strtol(str, &tmp, 10);

	if (*str == '\0' || *tmp != '\0')
		return 0;

	if ((errno == ERANGE || (num == LONG_MAX || num == LONG_MIN))
#if (LONG_MAX > UINT_MAX)
	    || num > (long)UINT_MAX
#endif
	    || num < 0)
		return 0;

	return (uin_t) num;
}
/* }}} */

/* unsigned int ggp_array_size(char **array) {{{ */
unsigned int ggp_array_size(char **array)
{
	unsigned int i;

	for (i = 0; array[i] != NULL && i < UINT_MAX; i++)
	{}

	return i;
}
/* }}} */

/* char *charset_convert(const gchar *locstr, const char *encsrc, const char *encdst) {{{ */
char *charset_convert(const gchar *locstr, const char *encsrc, const char *encdst)
{
	gchar *msg;
	GError *err = NULL;

	if (locstr == NULL)
		return NULL;

	msg = g_convert_with_fallback(locstr, strlen(locstr), encdst, encsrc,
				      "?", NULL, NULL, &err);
	if (err != NULL) {
		purple_debug_error("gg", "Error converting from %s to %s: %s\n",
				 encsrc, encdst, err->message);
		g_error_free(err);
	}

	/* Just in case? */
	if (msg == NULL)
		msg = g_strdup(locstr);

	return msg;
}
/* }}} */

/* ggp_get_uin(PurpleAccount *account) {{{ */
uin_t ggp_get_uin(PurpleAccount *account)
{
	return ggp_str_to_uin(purple_account_get_username(account));
}
/* }}} */

/* char *ggp_buddy_get_name(PurpleConnection *gc, const uin_t uin) {{{ */
char *ggp_buddy_get_name(PurpleConnection *gc, const uin_t uin)
{
	PurpleBuddy *buddy;
	gchar *str_uin;

	str_uin = g_strdup_printf("%lu", (unsigned long int)uin);

	buddy = purple_find_buddy(purple_connection_get_account(gc), str_uin);
	if (buddy != NULL) {
		g_free(str_uin);
		return g_strdup(purple_buddy_get_alias(buddy));
	} else {
		return str_uin;
	}
}
/* }}} */

void ggp_status_fake_to_self(PurpleAccount *account)
{
	PurplePresence *presence;
	PurpleStatus *status;
	const char *status_id;
	const char *msg;

	if (! purple_find_buddy(account, purple_account_get_username(account)))
		return;

	presence = purple_account_get_presence(account);
	status = purple_presence_get_active_status(presence);
	msg = purple_status_get_attr_string(status, "message");
	if (msg && !*msg)
		msg = NULL;

	status_id = purple_status_get_id(status);
	if (strcmp(status_id, "invisible") == 0) {
		status_id = "offline";
	}

	if (msg) {
		if (strlen(msg) > GG_STATUS_DESCR_MAXSIZE) {
			msg = purple_markup_slice(msg, 0, GG_STATUS_DESCR_MAXSIZE);
		}
	}
	purple_prpl_got_user_status(account, purple_account_get_username(account),
				    status_id,
				    msg ? "message" : NULL, msg, NULL);
}


/* vim: set ts=8 sts=0 sw=8 noet: */
