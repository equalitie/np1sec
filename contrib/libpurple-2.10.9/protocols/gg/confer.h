/**
 * @file confer.h
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


#ifndef _PURPLE_GG_CONFER_H
#define _PURPLE_GG_CONFER_H

#include "gg.h"

/**
 * Finds a CHAT conversation for the current account with the specified name.
 *
 * @param gc   PurpleConnection instance.
 * @param name Name of the conversation.
 *
 * @return PurpleConversation or NULL if not found.
 */
PurpleConversation *
ggp_confer_find_by_name(PurpleConnection *gc, const gchar *name);

/**
 * Adds the specified UIN to the specified conversation.
 *
 * @param gc        PurpleConnection.
 * @param chat_name Name of the conversation.
 */
void
ggp_confer_participants_add_uin(PurpleConnection *gc, const gchar *chat_name,
						    const uin_t uin);

/**
 * Add the specified UINs to the specified conversation.
 *
 * @param gc         PurpleConnection.
 * @param chat_name  Name of the conversation.
 * @param recipients List of the UINs.
 * @param count      Number of the UINs.
 */
void
ggp_confer_participants_add(PurpleConnection *gc, const gchar *chat_name,
			    const uin_t *recipients, int count);

/**
 * Finds a conversation in which all the specified recipients participate.
 *
 * TODO: This function should be rewritten to better handle situations when
 * somebody adds more people to the converation.
 *
 * @param gc         PurpleConnection.
 * @param recipients List of the people in the conversation.
 * @param count      Number of people.
 *
 * @return Name of the conversation.
 */
const char*
ggp_confer_find_by_participants(PurpleConnection *gc, const uin_t *recipients,
						    int count);

/**
 * Adds a new conversation to the internal list of conversations.
 * If name is NULL then it will be automagically generated.
 *
 * @param gc   PurpleConnection.
 * @param name Name of the conversation.
 *
 * @return Name of the conversation.
 */
const char*
ggp_confer_add_new(PurpleConnection *gc, const char *name);


#endif /* _PURPLE_GG_CONFER_H */

/* vim: set ts=8 sts=0 sw=8 noet: */
