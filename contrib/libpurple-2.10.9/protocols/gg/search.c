/**
 * @file search.c
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


#include <libgadu.h>

#include "gg-utils.h"
#include "search.h"


/* GGPSearchForm *ggp_search_form_new() {{{ */
GGPSearchForm *ggp_search_form_new(GGPSearchType st)
{
	GGPSearchForm *form;

	form = g_new0(GGPSearchForm, 1);

	form->search_type = st;
	form->window = NULL;
	form->user_data = NULL;
	form->seq = 0;
	form->page_number = 0;
	form->page_size = 0;

	form->uin = NULL;
	form->lastname = NULL;
	form->firstname = NULL;
	form->nickname = NULL;
	form->city = NULL;
	form->birthyear = NULL;
	form->gender = NULL;
	form->active = NULL;

	return form;
}
/* }}} */

/* void ggp_search_form_destroy(GGPSearchForm *form) {{{ */
void ggp_search_form_destroy(GGPSearchForm *form)
{
	g_return_if_fail(form != NULL);

	form->window = NULL;
	form->user_data = NULL;
	form->seq = 0;
	form->page_number = 0;
	form->page_size = 0;

	g_free(form->uin);
	g_free(form->lastname);
	g_free(form->firstname);
	g_free(form->nickname);
	g_free(form->city);
	g_free(form->birthyear);
	g_free(form->gender);
	g_free(form->active);
	g_free(form);
}
/* }}} */

/* void ggp_search_add(GGPSearches *searches, guint32 seq, GGPSearchForm *form) {{{ */
void ggp_search_add(GGPSearches *searches, guint32 seq, GGPSearchForm *form)
{
	guint32 *tmp;

	g_return_if_fail(searches != NULL);
	g_return_if_fail(form != NULL);

	tmp = g_new0(guint32, 1);
	*tmp = seq;
	form->seq = seq;

	g_hash_table_insert(searches, tmp, form);
}
/* }}} */

/* void ggp_search_remove(GGPSearches *searches, guint32 seq) {{{ */
void ggp_search_remove(GGPSearches *searches, guint32 seq)
{
	g_return_if_fail(searches != NULL);

	g_hash_table_remove(searches, &seq);
}
/* }}} */

/* GGPSearchForm *ggp_search_get(GGPSearches *searches, seq) {{{ */
GGPSearchForm *ggp_search_get(GGPSearches *searches, guint32 seq)
{
	g_return_val_if_fail(searches != NULL, NULL);

	return g_hash_table_lookup(searches, &seq);
}
/* }}} */

/* GGPSearches *ggp_search_new() {{{ */
GGPSearches *ggp_search_new(void)
{
	GGPSearches *searches;

	searches = g_hash_table_new_full(g_int_hash, g_int_equal,
					 g_free, NULL);

	return searches;
}
/* }}} */

/* void ggp_search_destroy(GGPSearches *searches) {{{ */
void ggp_search_destroy(GGPSearches *searches)
{
	g_return_if_fail(searches != NULL);

	g_hash_table_destroy(searches);
}
/* }}} */

/* guint32 ggp_search_start(PurpleConnection *gc, GGPSearchForm *form) {{{ */
guint32 ggp_search_start(PurpleConnection *gc, GGPSearchForm *form)
{
	GGPInfo *info = gc->proto_data;
	gg_pubdir50_t req;
	guint seq, offset;
	gchar *tmp;

	purple_debug_info("gg", "It's time to perform a search...\n");

	if ((req = gg_pubdir50_new(GG_PUBDIR50_SEARCH)) == NULL) {
		purple_debug_error("gg",
			"ggp_bmenu_show_details: Unable to create req variable.\n");
		return 0;
	}

	if (form->uin != NULL) {
		purple_debug_info("gg", "    uin: %s\n", form->uin);
		gg_pubdir50_add(req, GG_PUBDIR50_UIN, form->uin);
	} else {
		if (form->lastname != NULL) {
			purple_debug_info("gg", "    lastname: %s\n", form->lastname);
			gg_pubdir50_add(req, GG_PUBDIR50_LASTNAME, form->lastname);
		}

		if (form->firstname != NULL) {
			purple_debug_info("gg", "    firstname: %s\n", form->firstname);
			gg_pubdir50_add(req, GG_PUBDIR50_FIRSTNAME, form->firstname);
		}

		if (form->nickname != NULL) {
			purple_debug_info("gg", "    nickname: %s\n", form->nickname);
			gg_pubdir50_add(req, GG_PUBDIR50_NICKNAME, form->nickname);
		}

		if (form->city != NULL) {
			purple_debug_info("gg", "    city: %s\n", form->city);
			gg_pubdir50_add(req, GG_PUBDIR50_CITY, form->city);
		}

		if (form->birthyear != NULL) {
			purple_debug_info("gg", "    birthyear: %s\n", form->birthyear);
			gg_pubdir50_add(req, GG_PUBDIR50_BIRTHYEAR, form->birthyear);
		}

		if (form->gender != NULL) {
			purple_debug_info("gg", "    gender: %s\n", form->gender);
			gg_pubdir50_add(req, GG_PUBDIR50_GENDER, form->gender);
		}

		if (form->active != NULL) {
			purple_debug_info("gg", "    active: %s\n", form->active);
			gg_pubdir50_add(req, GG_PUBDIR50_ACTIVE, form->active);
		}
	}

	offset = form->page_size * form->page_number;
	purple_debug_info("gg", "page number: %u, page size: %u, offset: %u\n",
		form->page_number, form->page_size, offset);
	tmp = g_strdup_printf("%u", offset);
	gg_pubdir50_add(req, GG_PUBDIR50_START, tmp);
	g_free(tmp);

	if ((seq = gg_pubdir50(info->session, req)) == 0) {
		purple_debug_warning("gg", "ggp_bmenu_show_details: Search failed.\n");
		gg_pubdir50_free(req);
		return 0;
	}

	purple_debug_info("gg", "search sequence number: %d\n", seq);
	gg_pubdir50_free(req);

	return seq;
}
/* }}} */

/* char *ggp_search_get_result(gg_pubdir50_t res, int num, const char *field) {{{ */
char *ggp_search_get_result(gg_pubdir50_t res, int num, const char *field)
{
	char *tmp;

	tmp = g_strdup(gg_pubdir50_get(res, num, field));

	return (tmp == NULL) ? g_strdup("") : tmp;
}
/* }}} */


/* vim: set ts=8 sts=0 sw=8 noet: */
