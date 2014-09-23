/**
 * @file dbus-server.h Purple DBUS Server
 * @ingroup core
 * @see @ref dbus-server-signals
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

#ifndef _PURPLE_DBUS_SERVER_H_
#define _PURPLE_DBUS_SERVER_H_

#include "dbus-purple.h"
#include "value.h"

G_BEGIN_DECLS

/**
   Types of pointers are identified by the ADDRESS of a PurpleDbusType
   object.  This way, plugins can easily access types defined in purple
   proper as well as introduce their own types that will not conflict
   with those introduced by other plugins.

   The structure PurpleDbusType has only one element (PurpleDBusType::parent), a
   contains a pointer to the parent type, or @c NULL if the type has no
   parent.  Parent means the same as the base class in object oriented
   programming.
*/

typedef struct _PurpleDBusType PurpleDBusType;

struct _PurpleDBusType {
    PurpleDBusType *parent;
};

#include "dbus-bindings.h"

/* By convention, the PurpleDBusType variable representing each structure
   PurpleSomeStructure has the name PURPLE_DBUS_TYPE_PurpleSomeStructure.
   The following macros facilitate defining such variables

   #PURPLE_DBUS_DECLARE_TYPE declares an extern variable representing a
   given type, for use in header files.

   #PURPLE_DBUS_DEFINE_TYPE defines a variable representing a given
   type, use in .c files.  It defines a new type without a parent; for
   types with a parent use #PURPLE_DBUS_DEFINE_INHERITING_TYPE.
  */

#define PURPLE_DBUS_TYPE(type) (&PURPLE_DBUS_TYPE_##type)


#define PURPLE_DBUS_DECLARE_TYPE(type) \
    extern PurpleDBusType PURPLE_DBUS_TYPE_##type;

#define PURPLE_DBUS_DEFINE_TYPE(type) \
    PurpleDBusType PURPLE_DBUS_TYPE_##type = { NULL };

#define PURPLE_DBUS_DEFINE_INHERITING_TYPE(type, parent) \
    PurpleDBusType PURPLE_DBUS_TYPE_##type = { PURPLE_DBUS_TYPE(parent) };

#define PURPLE_DBUS_RETURN_FALSE_IF_DISABLED(plugin) \
	if (purple_dbus_get_init_error() != NULL) \
	{ \
		gchar *title; \
		title = g_strdup_printf("Unable to Load %s Plugin", plugin->info->name); \
		purple_notify_error(NULL, title, \
				_("Purple's D-BUS server is not running for the reason listed below"), \
				_(purple_dbus_get_init_error())); \
		g_free(title); \
		return FALSE; \
	}

/**
   Initializes purple dbus pointer registration engine.

   Remote dbus applications need a way of addressing objects exposed
   by purple to the outside world.  In purple itself, these objects (such
   as PurpleBuddy and company) are identified by pointers.  The purple
   dbus pointer registration engine converts pointers to handles and
   back.

   In order for an object to participate in the scheme, it must
   register itself and its type with the engine.  This registration
   allocates an integer id which can be resolved to the pointer and
   back.

   Handles are not persistent.  They are reissued every time purple is
   started.  This is not good; external applications that use purple
   should work even whether purple was restarted in the middle of the
   interaction.

   Pointer registration is only a temporary solution.  When PurpleBuddy
   and similar structures have been converted into gobjects, this
   registration will be done automatically by objects themselves.

   By the way, this kind of object-handle translation should be so
   common that there must be a library (maybe even glib) that
   implements it.  I feel a bit like reinventing the wheel here.
*/
void purple_dbus_init_ids(void);

/**
    Registers a typed pointer.

    @param node   The pointer to register.
    @param type   Type of that pointer.
 */
void purple_dbus_register_pointer(gpointer node, PurpleDBusType *type);

/**
    Unregisters a pointer previously registered with
    purple_dbus_register_pointer.

    @param node   The pointer to register.
 */
void purple_dbus_unregister_pointer(gpointer node);



/**
    Emits a dbus signal.

    @param name        The name of the signal ("bla-bla-blaa")
    @param num_values  The number of parameters.
    @param values      Array of pointers to #PurpleValue objects representing
                       the types of the parameters.
    @param vargs       A va_list containing the actual parameters.
  */
void purple_dbus_signal_emit_purple(const char *name, int num_values,
				PurpleValue **values, va_list vargs);

/**
 * Returns whether Purple's D-BUS subsystem is up and running.  If it's
 * NOT running then purple_dbus_dispatch_init() failed for some reason,
 * and a message should have been purple_debug_error()'ed.
 *
 * Purple plugins that use D-BUS should use the
 * PURPLE_DBUS_RETURN_FALSE_IF_DISABLED macro to short-circuit
 * initialization if Purple's D-BUS subsystem is not running.
 *
 * @return If the D-BUS subsystem started with no problems then this
 *         will return NULL and everything will be hunky dory.  If
 *         there was an error initializing the D-BUS subsystem then
 *         this will return an error message explaining why.
 */
const char *purple_dbus_get_init_error(void);

/**
 * Returns the dbus subsystem handle.
 *
 * @return The dbus subsystem handle.
 */
void *purple_dbus_get_handle(void);

/**
 * Determines whether this instance owns the DBus service name
 *
 * @since 2.1.0
 */
gboolean purple_dbus_is_owner(void);

/**
 * Starts Purple's D-BUS server.  It is responsible for handling DBUS
 * requests from other applications.
 */
void purple_dbus_init(void);

/**
 * Uninitializes Purple's D-BUS server.
 */
void purple_dbus_uninit(void);

/**

 Macro #DBUS_EXPORT expands to nothing.  It is used to indicate to the
 dbus-analyze-functions.py script that the given function should be
 available to other applications through DBUS.  If
 dbus-analyze-functions.py is run without the "--export-only" option,
 this prefix is ignored.

 */

#define DBUS_EXPORT

/*
   Here we include the list of #PURPLE_DBUS_DECLARE_TYPE statements for
   all structs defined in purple.  This file has been generated by the
   #dbus-analyze-types.py script.
*/

#include "dbus-types.h"

G_END_DECLS

#endif	/* _PURPLE_DBUS_SERVER_H_ */
