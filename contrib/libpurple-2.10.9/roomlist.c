/**
 * @file roomlist.c Room List API
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
 */

#include "internal.h"

#include "account.h"
#include "connection.h"
#include "debug.h"
#include "roomlist.h"
#include "server.h"


static PurpleRoomlistUiOps *ops = NULL;

/**************************************************************************/
/** @name Room List API                                                   */
/**************************************************************************/
/*@{*/

void purple_roomlist_show_with_account(PurpleAccount *account)
{
	if (ops && ops->show_with_account)
		ops->show_with_account(account);
}

PurpleRoomlist *purple_roomlist_new(PurpleAccount *account)
{
	PurpleRoomlist *list;

	g_return_val_if_fail(account != NULL, NULL);

	list = g_new0(PurpleRoomlist, 1);
	list->account = account;
	list->rooms = NULL;
	list->fields = NULL;
	list->ref = 1;

	if (ops && ops->create)
		ops->create(list);

	return list;
}

void purple_roomlist_ref(PurpleRoomlist *list)
{
	g_return_if_fail(list != NULL);

	list->ref++;
	purple_debug_misc("roomlist", "reffing list, ref count now %d\n", list->ref);
}

static void purple_roomlist_room_destroy(PurpleRoomlist *list, PurpleRoomlistRoom *r)
{
	GList *l, *j;

	for (l = list->fields, j = r->fields; l && j; l = l->next, j = j->next) {
		PurpleRoomlistField *f = l->data;
		if (f->type == PURPLE_ROOMLIST_FIELD_STRING)
			g_free(j->data);
	}

	g_list_free(r->fields);
	g_free(r->name);
	g_free(r);
}

static void purple_roomlist_field_destroy(PurpleRoomlistField *f)
{
	g_free(f->label);
	g_free(f->name);
	g_free(f);
}

static void purple_roomlist_destroy(PurpleRoomlist *list)
{
	GList *l;

	purple_debug_misc("roomlist", "destroying list %p\n", list);

	if (ops && ops->destroy)
		ops->destroy(list);

	for (l = list->rooms; l; l = l->next) {
		PurpleRoomlistRoom *r = l->data;
		purple_roomlist_room_destroy(list, r);
	}
	g_list_free(list->rooms);

	g_list_foreach(list->fields, (GFunc)purple_roomlist_field_destroy, NULL);
	g_list_free(list->fields);

	g_free(list);
}

void purple_roomlist_unref(PurpleRoomlist *list)
{
	g_return_if_fail(list != NULL);
	g_return_if_fail(list->ref > 0);

	list->ref--;

	purple_debug_misc("roomlist", "unreffing list, ref count now %d\n", list->ref);
	if (list->ref == 0)
		purple_roomlist_destroy(list);
}

void purple_roomlist_set_fields(PurpleRoomlist *list, GList *fields)
{
	g_return_if_fail(list != NULL);

	list->fields = fields;

	if (ops && ops->set_fields)
		ops->set_fields(list, fields);
}

void purple_roomlist_set_in_progress(PurpleRoomlist *list, gboolean in_progress)
{
	g_return_if_fail(list != NULL);

	list->in_progress = in_progress;

	if (ops && ops->in_progress)
		ops->in_progress(list, in_progress);
}

gboolean purple_roomlist_get_in_progress(PurpleRoomlist *list)
{
	g_return_val_if_fail(list != NULL, FALSE);

	return list->in_progress;
}

void purple_roomlist_room_add(PurpleRoomlist *list, PurpleRoomlistRoom *room)
{
	g_return_if_fail(list != NULL);
	g_return_if_fail(room != NULL);

	list->rooms = g_list_append(list->rooms, room);

	if (ops && ops->add_room)
		ops->add_room(list, room);
}

PurpleRoomlist *purple_roomlist_get_list(PurpleConnection *gc)
{
	PurplePlugin *prpl = NULL;
	PurplePluginProtocolInfo *prpl_info = NULL;

	g_return_val_if_fail(gc != NULL, NULL);
	g_return_val_if_fail(PURPLE_CONNECTION_IS_CONNECTED(gc), NULL);

	prpl = purple_connection_get_prpl(gc);

	if(prpl != NULL)
		prpl_info = PURPLE_PLUGIN_PROTOCOL_INFO(prpl);

	if(prpl_info && prpl_info->roomlist_get_list)
		return prpl_info->roomlist_get_list(gc);

	return NULL;
}

void purple_roomlist_cancel_get_list(PurpleRoomlist *list)
{
	PurplePlugin *prpl = NULL;
	PurplePluginProtocolInfo *prpl_info = NULL;
	PurpleConnection *gc;

	g_return_if_fail(list != NULL);

	gc = purple_account_get_connection(list->account);

	g_return_if_fail(gc != NULL);

	if(gc)
		prpl = purple_connection_get_prpl(gc);

	if(prpl)
		prpl_info = PURPLE_PLUGIN_PROTOCOL_INFO(prpl);

	if(prpl_info && prpl_info->roomlist_cancel)
		prpl_info->roomlist_cancel(list);
}

void purple_roomlist_expand_category(PurpleRoomlist *list, PurpleRoomlistRoom *category)
{
	PurplePlugin *prpl = NULL;
	PurplePluginProtocolInfo *prpl_info = NULL;
	PurpleConnection *gc;

	g_return_if_fail(list != NULL);
	g_return_if_fail(category != NULL);
	g_return_if_fail(category->type & PURPLE_ROOMLIST_ROOMTYPE_CATEGORY);

	gc = purple_account_get_connection(list->account);
	g_return_if_fail(gc != NULL);

	if(gc)
		prpl = purple_connection_get_prpl(gc);

	if(prpl)
		prpl_info = PURPLE_PLUGIN_PROTOCOL_INFO(prpl);

	if(prpl_info && prpl_info->roomlist_expand_category)
		prpl_info->roomlist_expand_category(list, category);
}

GList * purple_roomlist_get_fields(PurpleRoomlist *list)
{
	return list->fields;
}

/*@}*/

/**************************************************************************/
/** @name Room API                                                        */
/**************************************************************************/
/*@{*/

PurpleRoomlistRoom *purple_roomlist_room_new(PurpleRoomlistRoomType type, const gchar *name,
                                         PurpleRoomlistRoom *parent)
{
	PurpleRoomlistRoom *room;

	g_return_val_if_fail(name != NULL, NULL);

	room = g_new0(PurpleRoomlistRoom, 1);
	room->type = type;
	room->name = g_strdup(name);
	room->parent = parent;

	return room;
}

void purple_roomlist_room_add_field(PurpleRoomlist *list, PurpleRoomlistRoom *room, gconstpointer field)
{
	PurpleRoomlistField *f;

	g_return_if_fail(list != NULL);
	g_return_if_fail(room != NULL);
	g_return_if_fail(list->fields != NULL);

	/* If this is the first call for this room, grab the first field in
	 * the Roomlist's fields.  Otherwise, grab the field that is one
	 * more than the number of fields already present for the room.
         * (This works because g_list_nth_data() is zero-indexed and
         * g_list_length() is one-indexed.) */
	if (!room->fields)
		f = list->fields->data;
	else
		f = g_list_nth_data(list->fields, g_list_length(room->fields));

	g_return_if_fail(f != NULL);

	switch(f->type) {
		case PURPLE_ROOMLIST_FIELD_STRING:
			room->fields = g_list_append(room->fields, g_strdup(field));
			break;
		case PURPLE_ROOMLIST_FIELD_BOOL:
		case PURPLE_ROOMLIST_FIELD_INT:
			room->fields = g_list_append(room->fields, GINT_TO_POINTER(field));
			break;
	}
}

void purple_roomlist_room_join(PurpleRoomlist *list, PurpleRoomlistRoom *room)
{
	GHashTable *components;
	GList *l, *j;
	PurpleConnection *gc;

	g_return_if_fail(list != NULL);
	g_return_if_fail(room != NULL);

	gc = purple_account_get_connection(list->account);
	if (!gc)
		return;

	components = g_hash_table_new(g_str_hash, g_str_equal);

	g_hash_table_replace(components, "name", room->name);
	for (l = list->fields, j = room->fields; l && j; l = l->next, j = j->next) {
		PurpleRoomlistField *f = l->data;

		g_hash_table_replace(components, f->name, j->data);
	}

	serv_join_chat(gc, components);

	g_hash_table_destroy(components);
}

PurpleRoomlistRoomType purple_roomlist_room_get_type(PurpleRoomlistRoom *room)
{
	return room->type;
}

const char * purple_roomlist_room_get_name(PurpleRoomlistRoom *room)
{
	return room->name;
}

PurpleRoomlistRoom * purple_roomlist_room_get_parent(PurpleRoomlistRoom *room)
{
	return room->parent;
}

GList * purple_roomlist_room_get_fields(PurpleRoomlistRoom *room)
{
	return room->fields;
}

/*@}*/

/**************************************************************************/
/** @name Room Field API                                                  */
/**************************************************************************/
/*@{*/

PurpleRoomlistField *purple_roomlist_field_new(PurpleRoomlistFieldType type,
                                           const gchar *label, const gchar *name,
                                           gboolean hidden)
{
	PurpleRoomlistField *f;

	g_return_val_if_fail(label != NULL, NULL);
	g_return_val_if_fail(name != NULL, NULL);

	f = g_new0(PurpleRoomlistField, 1);

	f->type = type;
	f->label = g_strdup(label);
	f->name = g_strdup(name);
	f->hidden = hidden;

	return f;
}

PurpleRoomlistFieldType purple_roomlist_field_get_type(PurpleRoomlistField *field)
{
	return field->type;
}

const char * purple_roomlist_field_get_label(PurpleRoomlistField *field)
{
	return field->label;
}

gboolean purple_roomlist_field_get_hidden(PurpleRoomlistField *field)
{
	return field->hidden;
}

/*@}*/

/**************************************************************************/
/** @name UI Registration Functions                                       */
/**************************************************************************/
/*@{*/


void purple_roomlist_set_ui_ops(PurpleRoomlistUiOps *ui_ops)
{
	ops = ui_ops;
}

PurpleRoomlistUiOps *purple_roomlist_get_ui_ops(void)
{
	return ops;
}

/*@}*/
