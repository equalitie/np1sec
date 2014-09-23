/**
 * @file confer.c
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
#include "gg.h"
#include "gg-utils.h"
#include "confer.h"

/* PurpleConversation *ggp_confer_find_by_name(PurpleConnection *gc, const gchar *name) {{{ */
PurpleConversation *ggp_confer_find_by_name(PurpleConnection *gc, const gchar *name)
{
	g_return_val_if_fail(gc   != NULL, NULL);
	g_return_val_if_fail(name != NULL, NULL);

	return purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT, name,
			purple_connection_get_account(gc));
}
/* }}} */

/* void ggp_confer_participants_add_uin(PurpleConnection *gc, const gchar *chat_name, const uin_t uin) {{{ */
void ggp_confer_participants_add_uin(PurpleConnection *gc, const gchar *chat_name,
							 const uin_t uin)
{
	PurpleConversation *conv;
	GGPInfo *info = gc->proto_data;
	GGPChat *chat;
	GList *l;
	gchar *str_uin;

	for (l = info->chats; l != NULL; l = l->next) {
		chat = l->data;

		if (g_utf8_collate(chat->name, chat_name) != 0)
			continue;

		if (g_list_find(chat->participants, GINT_TO_POINTER(uin)) == NULL) {
			chat->participants = g_list_append(
						chat->participants, GINT_TO_POINTER(uin));

			str_uin = g_strdup_printf("%lu", (unsigned long int)uin);
			conv = ggp_confer_find_by_name(gc, chat_name);
			purple_conv_chat_add_user(PURPLE_CONV_CHAT(conv), str_uin, NULL,
						PURPLE_CBFLAGS_NONE, TRUE);

			g_free(str_uin);
		}
		break;
	}
}
/* }}} */

/* void ggp_confer_participants_add(PurpleConnection *gc, const gchar *chat_name, const uin_t *recipients, int count) {{{ */
void ggp_confer_participants_add(PurpleConnection *gc, const gchar *chat_name,
				 const uin_t *recipients, int count)
{
	GGPInfo *info = gc->proto_data;
	GList *l;
	gchar *str_uin;

	for (l = info->chats; l != NULL; l = l->next) {
		GGPChat *chat = l->data;
		int i;

		if (g_utf8_collate(chat->name, chat_name) != 0)
			continue;

		for (i = 0; i < count; i++) {
			PurpleConversation *conv;

			if (g_list_find(chat->participants,
					GINT_TO_POINTER(recipients[i])) != NULL) {
				continue;
			}

			chat->participants = g_list_append(chat->participants,
							   GINT_TO_POINTER(recipients[i]));

			str_uin = g_strdup_printf("%lu", (unsigned long int)recipients[i]);
			conv = ggp_confer_find_by_name(gc, chat_name);
			purple_conv_chat_add_user(PURPLE_CONV_CHAT(conv),
						str_uin, NULL,
						PURPLE_CBFLAGS_NONE, TRUE);
			g_free(str_uin);
		}
		break;
	}
}
/* }}} */

/* const char *ggp_confer_find_by_participants(PurpleConnection *gc, const uin_t *recipients, int count) {{{ */
const char *ggp_confer_find_by_participants(PurpleConnection *gc,
					    const uin_t *recipients, int count)
{
	GGPInfo *info = gc->proto_data;
	GGPChat *chat = NULL;
	GList *l;
	int matches;

	g_return_val_if_fail(info->chats != NULL, NULL);

	for (l = info->chats; l != NULL; l = l->next) {
		GList *m;

		chat = l->data;
		matches = 0;

		for (m = chat->participants; m != NULL; m = m->next) {
			uin_t uin = GPOINTER_TO_INT(m->data);
			int i;

			for (i = 0; i < count; i++)
				if (uin == recipients[i])
					matches++;
		}

		if (matches == count)
			break;

		chat = NULL;
	}

	if (chat == NULL)
		return NULL;
	else
		return chat->name;
}
/* }}} */

/* const char *ggp_confer_add_new(PurpleConnection *gc, const char *name) {{{ */
const char *ggp_confer_add_new(PurpleConnection *gc, const char *name)
{
	GGPInfo *info = gc->proto_data;
	GGPChat *chat;

	chat = g_new0(GGPChat, 1);

	if (name == NULL)
		chat->name = g_strdup_printf("conf#%d", info->chats_count++);
	else
		chat->name = g_strdup(name);

	chat->participants = NULL;

	info->chats = g_list_append(info->chats, chat);

	return chat->name;
}
/* }}} */

/* vim: set ts=8 sts=0 sw=8 noet: */
