/**
 * @file dbus-bindings.h Purple DBUS Bindings
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

#ifndef _PURPLE_DBUS_BINDINGS_H_
#define _PURPLE_DBUS_BINDINGS_H_

#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <glib.h>

#ifdef __cplusplus
extern "C" {
#endif

gint purple_dbus_pointer_to_id(gconstpointer node);
gpointer purple_dbus_id_to_pointer(gint id, PurpleDBusType *type);
gint  purple_dbus_pointer_to_id_error(gconstpointer ptr, DBusError *error);
gpointer purple_dbus_id_to_pointer_error(gint id, PurpleDBusType *type,
				       const char *typename, DBusError *error);

#define NULLIFY(id) id = empty_to_null(id)

#define CHECK_ERROR(error) if (dbus_error_is_set(error)) return NULL;

#define PURPLE_DBUS_ID_TO_POINTER(ptr, id, type, error)			\
    G_STMT_START {							\
	ptr = (type*) purple_dbus_id_to_pointer_error			\
	    (id, PURPLE_DBUS_TYPE(type), #type, error);			\
	CHECK_ERROR(error);						\
    } G_STMT_END


#define PURPLE_DBUS_POINTER_TO_ID(id, ptr, error)				\
    G_STMT_START {							\
	id = purple_dbus_pointer_to_id_error(ptr,error);			\
	CHECK_ERROR(error);						\
    } G_STMT_END


dbus_bool_t
purple_dbus_message_get_args (DBusMessage     *message,
			    DBusError       *error,
			    int              first_arg_type,
			    ...);
dbus_bool_t
purple_dbus_message_get_args_valist (DBusMessage     *message,
				   DBusError       *error,
				   int              first_arg_type,
				   va_list          var_args);

dbus_bool_t
purple_dbus_message_iter_get_args (DBusMessageIter *iter,
				 DBusError       *error,
				 int              first_arg_type,
				 ...);

dbus_bool_t
purple_dbus_message_iter_get_args_valist (DBusMessageIter *iter,
					DBusError       *error,
					int              first_arg_type,
					va_list          var_args);

dbus_int32_t* purple_dbusify_GList(GList *list, gboolean free_memory,
				 dbus_int32_t *len);
dbus_int32_t* purple_dbusify_GSList(GSList *list, gboolean free_memory,
				  dbus_int32_t *len);
gpointer* purple_GList_to_array(GList *list, gboolean free_memory,
			      dbus_int32_t *len);
gpointer* purple_GSList_to_array(GSList *list, gboolean free_memory,
			      dbus_int32_t *len);
GHashTable *purple_dbus_iter_hash_table(DBusMessageIter *iter, DBusError *error);

const char* empty_to_null(const char *str);
const char* null_to_empty(const char *s);

typedef struct {
    const char *name;
    const char *parameters;
    DBusMessage* (*handler)(DBusMessage *request, DBusError *error);
} PurpleDBusBinding;

void purple_dbus_register_bindings(void *handle, PurpleDBusBinding *bindings);

DBusConnection *purple_dbus_get_connection(void);

#ifdef __cplusplus
}
#endif

#endif
