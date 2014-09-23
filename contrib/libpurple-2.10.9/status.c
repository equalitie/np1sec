/**
 * @file status.c Status API
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
#define _PURPLE_STATUS_C_

#include "internal.h"

#include "blist.h"
#include "core.h"
#include "dbus-maybe.h"
#include "debug.h"
#include "notify.h"
#include "prefs.h"
#include "status.h"

/**
 * A type of status.
 */
struct _PurpleStatusType
{
	PurpleStatusPrimitive primitive;

	char *id;
	char *name;
	char *primary_attr_id;

	gboolean saveable;
	gboolean user_settable;
	gboolean independent;

	GList *attrs;
};

/**
 * A status attribute.
 */
struct _PurpleStatusAttr
{
	char *id;
	char *name;
	PurpleValue *value_type;
};

/**
 * A list of statuses.
 */
struct _PurplePresence
{
	PurplePresenceContext context;

	gboolean idle;
	time_t idle_time;
	time_t login_time;

	GList *statuses;
	GHashTable *status_table;

	PurpleStatus *active_status;

	union
	{
		PurpleAccount *account;

		struct
		{
			PurpleConversation *conv;
			char *user;

		} chat;

		struct
		{
			PurpleAccount *account;
			char *name;
			PurpleBuddy *buddy;

		} buddy;

	} u;
};

/**
 * An active status.
 */
struct _PurpleStatus
{
	PurpleStatusType *type;
	PurplePresence *presence;

	gboolean active;

	/*
	 * The current values of the attributes for this status.  The
	 * key is a string containing the name of the attribute.  It is
	 * a borrowed reference from the list of attrs in the
	 * PurpleStatusType.  The value is a PurpleValue.
	 */
	GHashTable *attr_values;
};

typedef struct
{
	PurpleAccount *account;
	char *name;
} PurpleStatusBuddyKey;

static int primitive_scores[] =
{
	0,      /* unset                    */
	-500,   /* offline                  */
	100,    /* available                */
	-75,    /* unavailable              */
	-50,    /* invisible                */
	-100,   /* away                     */
	-200,   /* extended away            */
	-400,   /* mobile                   */
	0,      /* tune                     */
	0,      /* mood                     */
	-10,    /* idle, special case.      */
	-5,     /* idle time, special case. */
	10      /* Offline messageable      */
};

#define SCORE_IDLE      9
#define SCORE_IDLE_TIME 10
#define SCORE_OFFLINE_MESSAGE 11

/**************************************************************************
 * PurpleStatusPrimitive API
 **************************************************************************/
static struct PurpleStatusPrimitiveMap
{
	PurpleStatusPrimitive type;
	const char *id;
	const char *name;

} const status_primitive_map[] =
{
	{ PURPLE_STATUS_UNSET,           "unset",           N_("Unset")               },
	{ PURPLE_STATUS_OFFLINE,         "offline",         N_("Offline")             },
	{ PURPLE_STATUS_AVAILABLE,       "available",       N_("Available")           },
	{ PURPLE_STATUS_UNAVAILABLE,     "unavailable",     N_("Do not disturb")      },
	{ PURPLE_STATUS_INVISIBLE,       "invisible",       N_("Invisible")           },
	{ PURPLE_STATUS_AWAY,            "away",            N_("Away")                },
	{ PURPLE_STATUS_EXTENDED_AWAY,   "extended_away",   N_("Extended away")       },
	{ PURPLE_STATUS_MOBILE,          "mobile",          N_("Mobile")              },
	{ PURPLE_STATUS_TUNE,            "tune",            N_("Listening to music"), },
	{ PURPLE_STATUS_MOOD,            "mood",            N_("Feeling")             },
};

const char *
purple_primitive_get_id_from_type(PurpleStatusPrimitive type)
{
    int i;

    for (i = 0; i < PURPLE_STATUS_NUM_PRIMITIVES; i++)
    {
		if (type == status_primitive_map[i].type)
			return status_primitive_map[i].id;
    }

    return status_primitive_map[0].id;
}

const char *
purple_primitive_get_name_from_type(PurpleStatusPrimitive type)
{
    int i;

    for (i = 0; i < PURPLE_STATUS_NUM_PRIMITIVES; i++)
    {
	if (type == status_primitive_map[i].type)
		return _(status_primitive_map[i].name);
    }

    return _(status_primitive_map[0].name);
}

PurpleStatusPrimitive
purple_primitive_get_type_from_id(const char *id)
{
    int i;

    g_return_val_if_fail(id != NULL, PURPLE_STATUS_UNSET);

    for (i = 0; i < PURPLE_STATUS_NUM_PRIMITIVES; i++)
    {
		if (purple_strequal(id, status_primitive_map[i].id))
            return status_primitive_map[i].type;
    }

    return status_primitive_map[0].type;
}


/**************************************************************************
 * PurpleStatusType API
 **************************************************************************/
PurpleStatusType *
purple_status_type_new_full(PurpleStatusPrimitive primitive, const char *id,
						  const char *name, gboolean saveable,
						  gboolean user_settable, gboolean independent)
{
	PurpleStatusType *status_type;

	g_return_val_if_fail(primitive != PURPLE_STATUS_UNSET, NULL);

	status_type = g_new0(PurpleStatusType, 1);
	PURPLE_DBUS_REGISTER_POINTER(status_type, PurpleStatusType);

	status_type->primitive     = primitive;
	status_type->saveable      = saveable;
	status_type->user_settable = user_settable;
	status_type->independent   = independent;

	if (id != NULL)
		status_type->id = g_strdup(id);
	else
		status_type->id = g_strdup(purple_primitive_get_id_from_type(primitive));

	if (name != NULL)
		status_type->name = g_strdup(name);
	else
		status_type->name = g_strdup(purple_primitive_get_name_from_type(primitive));

	return status_type;
}

PurpleStatusType *
purple_status_type_new(PurpleStatusPrimitive primitive, const char *id,
					 const char *name, gboolean user_settable)
{
	g_return_val_if_fail(primitive != PURPLE_STATUS_UNSET, NULL);

	return purple_status_type_new_full(primitive, id, name, TRUE,
			user_settable, FALSE);
}

PurpleStatusType *
purple_status_type_new_with_attrs(PurpleStatusPrimitive primitive,
		const char *id, const char *name,
		gboolean saveable, gboolean user_settable,
		gboolean independent, const char *attr_id,
		const char *attr_name, PurpleValue *attr_value,
		...)
{
	PurpleStatusType *status_type;
	va_list args;

	g_return_val_if_fail(primitive  != PURPLE_STATUS_UNSET, NULL);
	g_return_val_if_fail(attr_id    != NULL,              NULL);
	g_return_val_if_fail(attr_name  != NULL,              NULL);
	g_return_val_if_fail(attr_value != NULL,              NULL);

	status_type = purple_status_type_new_full(primitive, id, name, saveable,
			user_settable, independent);

	/* Add the first attribute */
	purple_status_type_add_attr(status_type, attr_id, attr_name, attr_value);

	va_start(args, attr_value);
	purple_status_type_add_attrs_vargs(status_type, args);
	va_end(args);

	return status_type;
}

void
purple_status_type_destroy(PurpleStatusType *status_type)
{
	g_return_if_fail(status_type != NULL);

	g_free(status_type->id);
	g_free(status_type->name);
	g_free(status_type->primary_attr_id);

	g_list_foreach(status_type->attrs, (GFunc)purple_status_attr_destroy, NULL);
	g_list_free(status_type->attrs);

	PURPLE_DBUS_UNREGISTER_POINTER(status_type);
	g_free(status_type);
}

void
purple_status_type_set_primary_attr(PurpleStatusType *status_type, const char *id)
{
	g_return_if_fail(status_type != NULL);

	g_free(status_type->primary_attr_id);
	status_type->primary_attr_id = g_strdup(id);
}

void
purple_status_type_add_attr(PurpleStatusType *status_type, const char *id,
		const char *name, PurpleValue *value)
{
	PurpleStatusAttr *attr;

	g_return_if_fail(status_type != NULL);
	g_return_if_fail(id          != NULL);
	g_return_if_fail(name        != NULL);
	g_return_if_fail(value       != NULL);

	attr = purple_status_attr_new(id, name, value);

	status_type->attrs = g_list_append(status_type->attrs, attr);
}

void
purple_status_type_add_attrs_vargs(PurpleStatusType *status_type, va_list args)
{
	const char *id, *name;
	PurpleValue *value;

	g_return_if_fail(status_type != NULL);

	while ((id = va_arg(args, const char *)) != NULL)
	{
		name = va_arg(args, const char *);
		g_return_if_fail(name != NULL);

		value = va_arg(args, PurpleValue *);
		g_return_if_fail(value != NULL);

		purple_status_type_add_attr(status_type, id, name, value);
	}
}

void
purple_status_type_add_attrs(PurpleStatusType *status_type, const char *id,
		const char *name, PurpleValue *value, ...)
{
	va_list args;

	g_return_if_fail(status_type != NULL);
	g_return_if_fail(id          != NULL);
	g_return_if_fail(name        != NULL);
	g_return_if_fail(value       != NULL);

	/* Add the first attribute */
	purple_status_type_add_attr(status_type, id, name, value);

	va_start(args, value);
	purple_status_type_add_attrs_vargs(status_type, args);
	va_end(args);
}

PurpleStatusPrimitive
purple_status_type_get_primitive(const PurpleStatusType *status_type)
{
	g_return_val_if_fail(status_type != NULL, PURPLE_STATUS_UNSET);

	return status_type->primitive;
}

const char *
purple_status_type_get_id(const PurpleStatusType *status_type)
{
	g_return_val_if_fail(status_type != NULL, NULL);

	return status_type->id;
}

const char *
purple_status_type_get_name(const PurpleStatusType *status_type)
{
	g_return_val_if_fail(status_type != NULL, NULL);

	return status_type->name;
}

gboolean
purple_status_type_is_saveable(const PurpleStatusType *status_type)
{
	g_return_val_if_fail(status_type != NULL, FALSE);

	return status_type->saveable;
}

gboolean
purple_status_type_is_user_settable(const PurpleStatusType *status_type)
{
	g_return_val_if_fail(status_type != NULL, FALSE);

	return status_type->user_settable;
}

gboolean
purple_status_type_is_independent(const PurpleStatusType *status_type)
{
	g_return_val_if_fail(status_type != NULL, FALSE);

	return status_type->independent;
}

gboolean
purple_status_type_is_exclusive(const PurpleStatusType *status_type)
{
	g_return_val_if_fail(status_type != NULL, FALSE);

	return !status_type->independent;
}

gboolean
purple_status_type_is_available(const PurpleStatusType *status_type)
{
	PurpleStatusPrimitive primitive;

	g_return_val_if_fail(status_type != NULL, FALSE);

	primitive = purple_status_type_get_primitive(status_type);

	return (primitive == PURPLE_STATUS_AVAILABLE);
}

const char *
purple_status_type_get_primary_attr(const PurpleStatusType *status_type)
{
	g_return_val_if_fail(status_type != NULL, NULL);

	return status_type->primary_attr_id;
}

PurpleStatusAttr *
purple_status_type_get_attr(const PurpleStatusType *status_type, const char *id)
{
	GList *l;

	g_return_val_if_fail(status_type != NULL, NULL);
	g_return_val_if_fail(id          != NULL, NULL);

	for (l = status_type->attrs; l != NULL; l = l->next)
	{
		PurpleStatusAttr *attr = (PurpleStatusAttr *)l->data;

		if (purple_strequal(purple_status_attr_get_id(attr), id))
			return attr;
	}

	return NULL;
}

GList *
purple_status_type_get_attrs(const PurpleStatusType *status_type)
{
	g_return_val_if_fail(status_type != NULL, NULL);

	return status_type->attrs;
}

const PurpleStatusType *
purple_status_type_find_with_id(GList *status_types, const char *id)
{
	PurpleStatusType *status_type;

	g_return_val_if_fail(id != NULL, NULL);

	while (status_types != NULL)
	{
		status_type = status_types->data;

		if (purple_strequal(id, status_type->id))
			return status_type;

		status_types = status_types->next;
	}

	return NULL;
}


/**************************************************************************
* PurpleStatusAttr API
**************************************************************************/
PurpleStatusAttr *
purple_status_attr_new(const char *id, const char *name, PurpleValue *value_type)
{
	PurpleStatusAttr *attr;

	g_return_val_if_fail(id         != NULL, NULL);
	g_return_val_if_fail(name       != NULL, NULL);
	g_return_val_if_fail(value_type != NULL, NULL);

	attr = g_new0(PurpleStatusAttr, 1);
	PURPLE_DBUS_REGISTER_POINTER(attr, PurpleStatusAttr);

	attr->id         = g_strdup(id);
	attr->name       = g_strdup(name);
	attr->value_type = value_type;

	return attr;
}

void
purple_status_attr_destroy(PurpleStatusAttr *attr)
{
	g_return_if_fail(attr != NULL);

	g_free(attr->id);
	g_free(attr->name);

	purple_value_destroy(attr->value_type);

	PURPLE_DBUS_UNREGISTER_POINTER(attr);
	g_free(attr);
}

const char *
purple_status_attr_get_id(const PurpleStatusAttr *attr)
{
	g_return_val_if_fail(attr != NULL, NULL);

	return attr->id;
}

const char *
purple_status_attr_get_name(const PurpleStatusAttr *attr)
{
	g_return_val_if_fail(attr != NULL, NULL);

	return attr->name;
}

PurpleValue *
purple_status_attr_get_value(const PurpleStatusAttr *attr)
{
	g_return_val_if_fail(attr != NULL, NULL);

	return attr->value_type;
}


/**************************************************************************
* PurpleStatus API
**************************************************************************/
PurpleStatus *
purple_status_new(PurpleStatusType *status_type, PurplePresence *presence)
{
	PurpleStatus *status;
	GList *l;

	g_return_val_if_fail(status_type != NULL, NULL);
	g_return_val_if_fail(presence    != NULL, NULL);

	status = g_new0(PurpleStatus, 1);
	PURPLE_DBUS_REGISTER_POINTER(status, PurpleStatus);

	status->type     = status_type;
	status->presence = presence;

	status->attr_values =
		g_hash_table_new_full(g_str_hash, g_str_equal, NULL,
		(GDestroyNotify)purple_value_destroy);

	for (l = purple_status_type_get_attrs(status_type); l != NULL; l = l->next)
	{
		PurpleStatusAttr *attr = (PurpleStatusAttr *)l->data;
		PurpleValue *value = purple_status_attr_get_value(attr);
		PurpleValue *new_value = purple_value_dup(value);

		g_hash_table_insert(status->attr_values,
							(char *)purple_status_attr_get_id(attr),
							new_value);
	}

	return status;
}

/*
 * TODO: If the PurpleStatus is in a PurplePresence, then
 *       remove it from the PurplePresence?
 */
void
purple_status_destroy(PurpleStatus *status)
{
	g_return_if_fail(status != NULL);

	g_hash_table_destroy(status->attr_values);

	PURPLE_DBUS_UNREGISTER_POINTER(status);
	g_free(status);
}

static void
notify_buddy_status_update(PurpleBuddy *buddy, PurplePresence *presence,
		PurpleStatus *old_status, PurpleStatus *new_status)
{
	if (purple_prefs_get_bool("/purple/logging/log_system"))
	{
		time_t current_time = time(NULL);
		const char *buddy_alias = purple_buddy_get_alias(buddy);
		char *tmp, *logtmp;
		PurpleLog *log;

		if (old_status != NULL)
		{
			tmp = g_strdup_printf(_("%s (%s) changed status from %s to %s"), buddy_alias,
			                      purple_buddy_get_name(buddy),
			                      purple_status_get_name(old_status),
			                      purple_status_get_name(new_status));
			logtmp = g_markup_escape_text(tmp, -1);
		}
		else
		{
			/* old_status == NULL when an independent status is toggled. */

			if (purple_status_is_active(new_status))
			{
				tmp = g_strdup_printf(_("%s (%s) is now %s"), buddy_alias,
				                      purple_buddy_get_name(buddy),
				                      purple_status_get_name(new_status));
				logtmp = g_markup_escape_text(tmp, -1);
			}
			else
			{
				tmp = g_strdup_printf(_("%s (%s) is no longer %s"), buddy_alias,
				                      purple_buddy_get_name(buddy),
				                      purple_status_get_name(new_status));
				logtmp = g_markup_escape_text(tmp, -1);
			}
		}

		log = purple_account_get_log(purple_buddy_get_account(buddy), FALSE);
		if (log != NULL)
		{
			purple_log_write(log, PURPLE_MESSAGE_SYSTEM, buddy_alias,
			               current_time, logtmp);
		}

		g_free(tmp);
		g_free(logtmp);
	}
}

static void
notify_status_update(PurplePresence *presence, PurpleStatus *old_status,
					 PurpleStatus *new_status)
{
	PurplePresenceContext context = purple_presence_get_context(presence);

	if (context == PURPLE_PRESENCE_CONTEXT_ACCOUNT)
	{
		PurpleAccount *account = purple_presence_get_account(presence);
		PurpleAccountUiOps *ops = purple_accounts_get_ui_ops();

		if (purple_account_get_enabled(account, purple_core_get_ui()))
			purple_prpl_change_account_status(account, old_status, new_status);

		if (ops != NULL && ops->status_changed != NULL)
		{
			ops->status_changed(account, new_status);
		}
	}
	else if (context == PURPLE_PRESENCE_CONTEXT_BUDDY)
	{
			notify_buddy_status_update(purple_presence_get_buddy(presence), presence,
					old_status, new_status);
	}
}

static void
status_has_changed(PurpleStatus *status)
{
	PurplePresence *presence;
	PurpleStatus *old_status;

	presence   = purple_status_get_presence(status);

	/*
	 * If this status is exclusive, then we must be setting it to "active."
	 * Since we are setting it to active, we want to set the currently
	 * active status to "inactive."
	 */
	if (purple_status_is_exclusive(status))
	{
		old_status = purple_presence_get_active_status(presence);
		if (old_status != NULL && (old_status != status))
			old_status->active = FALSE;
		presence->active_status = status;
	}
	else
		old_status = NULL;

	notify_status_update(presence, old_status, status);
}

void
purple_status_set_active(PurpleStatus *status, gboolean active)
{
	purple_status_set_active_with_attrs_list(status, active, NULL);
}

/*
 * This used to parse the va_list directly, but now it creates a GList
 * and passes it to purple_status_set_active_with_attrs_list().  That
 * function was created because accounts.c needs to pass a GList of
 * attributes to the status API.
 */
void
purple_status_set_active_with_attrs(PurpleStatus *status, gboolean active, va_list args)
{
	GList *attrs = NULL;
	const gchar *id;
	gpointer data;

	while ((id = va_arg(args, const char *)) != NULL)
	{
		attrs = g_list_append(attrs, (char *)id);
		data = va_arg(args, void *);
		attrs = g_list_append(attrs, data);
	}
	purple_status_set_active_with_attrs_list(status, active, attrs);
	g_list_free(attrs);
}

void
purple_status_set_active_with_attrs_list(PurpleStatus *status, gboolean active,
									   GList *attrs)
{
	gboolean changed = FALSE;
	GList *l;
	GList *specified_attr_ids = NULL;
	PurpleStatusType *status_type;

	g_return_if_fail(status != NULL);

	if (!active && purple_status_is_exclusive(status))
	{
		purple_debug_error("status",
				   "Cannot deactivate an exclusive status (%s).\n",
				   purple_status_get_id(status));
		return;
	}

	if (status->active != active)
	{
		changed = TRUE;
	}

	status->active = active;

	/* Set any attributes */
	l = attrs;
	while (l != NULL)
	{
		const gchar *id;
		PurpleValue *value;

		id = l->data;
		l = l->next;
		value = purple_status_get_attr_value(status, id);
		if (value == NULL)
		{
			purple_debug_warning("status", "The attribute \"%s\" on the status \"%s\" is "
							   "not supported.\n", id, status->type->name);
			/* Skip over the data and move on to the next attribute */
			l = l->next;
			continue;
		}

		specified_attr_ids = g_list_prepend(specified_attr_ids, (gpointer)id);

		if (value->type == PURPLE_TYPE_STRING)
		{
			const gchar *string_data = l->data;
			l = l->next;
			if (purple_strequal(string_data, value->data.string_data))
				continue;
			purple_status_set_attr_string(status, id, string_data);
			changed = TRUE;
		}
		else if (value->type == PURPLE_TYPE_INT)
		{
			int int_data = GPOINTER_TO_INT(l->data);
			l = l->next;
			if (int_data == value->data.int_data)
				continue;
			purple_status_set_attr_int(status, id, int_data);
			changed = TRUE;
		}
		else if (value->type == PURPLE_TYPE_BOOLEAN)
		{
			gboolean boolean_data = GPOINTER_TO_INT(l->data);
			l = l->next;
			if (boolean_data == value->data.boolean_data)
				continue;
			purple_status_set_attr_boolean(status, id, boolean_data);
			changed = TRUE;
		}
		else
		{
			/* We don't know what the data is--skip over it */
			l = l->next;
		}
	}

	/* Reset any unspecified attributes to their default value */
	status_type = purple_status_get_type(status);
	l = purple_status_type_get_attrs(status_type);
	while (l != NULL) {
		PurpleStatusAttr *attr;

		attr = l->data;
		l = l->next;

		if (!g_list_find_custom(specified_attr_ids, attr->id, (GCompareFunc)strcmp)) {
			PurpleValue *default_value;
			default_value = purple_status_attr_get_value(attr);
			if (default_value->type == PURPLE_TYPE_STRING) {
				const char *cur = purple_status_get_attr_string(status, attr->id);
				const char *def = purple_value_get_string(default_value);
				if ((cur == NULL && def == NULL)
				    || (cur != NULL && def != NULL
					&& !strcmp(cur, def))) {
					continue;
				}

				purple_status_set_attr_string(status, attr->id, def);
			} else if (default_value->type == PURPLE_TYPE_INT) {
				int cur = purple_status_get_attr_int(status, attr->id);
				int def = purple_value_get_int(default_value);
				if (cur == def)
					continue;

				purple_status_set_attr_int(status, attr->id, def);
			} else if (default_value->type == PURPLE_TYPE_BOOLEAN) {
				gboolean cur = purple_status_get_attr_boolean(status, attr->id);
				gboolean def = purple_value_get_boolean(default_value);
				if (cur == def)
					continue;

				purple_status_set_attr_boolean(status, attr->id, def);
			}
			changed = TRUE;
		}
	}
	g_list_free(specified_attr_ids);

	if (!changed)
		return;
	status_has_changed(status);
}

void
purple_status_set_attr_boolean(PurpleStatus *status, const char *id,
		gboolean value)
{
	PurpleValue *attr_value;

	g_return_if_fail(status != NULL);
	g_return_if_fail(id     != NULL);

	/* Make sure this attribute exists and is the correct type. */
	attr_value = purple_status_get_attr_value(status, id);
	g_return_if_fail(attr_value != NULL);
	g_return_if_fail(purple_value_get_type(attr_value) == PURPLE_TYPE_BOOLEAN);

	purple_value_set_boolean(attr_value, value);
}

void
purple_status_set_attr_int(PurpleStatus *status, const char *id, int value)
{
	PurpleValue *attr_value;

	g_return_if_fail(status != NULL);
	g_return_if_fail(id     != NULL);

	/* Make sure this attribute exists and is the correct type. */
	attr_value = purple_status_get_attr_value(status, id);
	g_return_if_fail(attr_value != NULL);
	g_return_if_fail(purple_value_get_type(attr_value) == PURPLE_TYPE_INT);

	purple_value_set_int(attr_value, value);
}

void
purple_status_set_attr_string(PurpleStatus *status, const char *id,
		const char *value)
{
	PurpleValue *attr_value;

	g_return_if_fail(status != NULL);
	g_return_if_fail(id     != NULL);

	/* Make sure this attribute exists and is the correct type. */
	attr_value = purple_status_get_attr_value(status, id);
	/* This used to be g_return_if_fail, but it's failing a LOT, so
	 * let's generate a log error for now. */
	/* g_return_if_fail(attr_value != NULL); */
	if (attr_value == NULL) {
		purple_debug_error("status",
				 "Attempted to set status attribute '%s' for "
				 "status '%s', which is not legal.  Fix "
                                 "this!\n", id,
				 purple_status_type_get_name(purple_status_get_type(status)));
		return;
	}
	g_return_if_fail(purple_value_get_type(attr_value) == PURPLE_TYPE_STRING);

	/* XXX: Check if the value has actually changed. If it has, and the status
	 * is active, should this trigger 'status_has_changed'? */
	purple_value_set_string(attr_value, value);
}

PurpleStatusType *
purple_status_get_type(const PurpleStatus *status)
{
	g_return_val_if_fail(status != NULL, NULL);

	return status->type;
}

PurplePresence *
purple_status_get_presence(const PurpleStatus *status)
{
	g_return_val_if_fail(status != NULL, NULL);

	return status->presence;
}

const char *
purple_status_get_id(const PurpleStatus *status)
{
	g_return_val_if_fail(status != NULL, NULL);

	return purple_status_type_get_id(purple_status_get_type(status));
}

const char *
purple_status_get_name(const PurpleStatus *status)
{
	g_return_val_if_fail(status != NULL, NULL);

	return purple_status_type_get_name(purple_status_get_type(status));
}

gboolean
purple_status_is_independent(const PurpleStatus *status)
{
	g_return_val_if_fail(status != NULL, FALSE);

	return purple_status_type_is_independent(purple_status_get_type(status));
}

gboolean
purple_status_is_exclusive(const PurpleStatus *status)
{
	g_return_val_if_fail(status != NULL, FALSE);

	return purple_status_type_is_exclusive(purple_status_get_type(status));
}

gboolean
purple_status_is_available(const PurpleStatus *status)
{
	g_return_val_if_fail(status != NULL, FALSE);

	return purple_status_type_is_available(purple_status_get_type(status));
}

gboolean
purple_status_is_active(const PurpleStatus *status)
{
	g_return_val_if_fail(status != NULL, FALSE);

	return status->active;
}

gboolean
purple_status_is_online(const PurpleStatus *status)
{
	PurpleStatusPrimitive primitive;

	g_return_val_if_fail( status != NULL, FALSE);

	primitive = purple_status_type_get_primitive(purple_status_get_type(status));

	return (primitive != PURPLE_STATUS_UNSET &&
			primitive != PURPLE_STATUS_OFFLINE);
}

PurpleValue *
purple_status_get_attr_value(const PurpleStatus *status, const char *id)
{
	g_return_val_if_fail(status != NULL, NULL);
	g_return_val_if_fail(id     != NULL, NULL);

	return (PurpleValue *)g_hash_table_lookup(status->attr_values, id);
}

gboolean
purple_status_get_attr_boolean(const PurpleStatus *status, const char *id)
{
	const PurpleValue *value;

	g_return_val_if_fail(status != NULL, FALSE);
	g_return_val_if_fail(id     != NULL, FALSE);

	if ((value = purple_status_get_attr_value(status, id)) == NULL)
		return FALSE;

	g_return_val_if_fail(purple_value_get_type(value) == PURPLE_TYPE_BOOLEAN, FALSE);

	return purple_value_get_boolean(value);
}

int
purple_status_get_attr_int(const PurpleStatus *status, const char *id)
{
	const PurpleValue *value;

	g_return_val_if_fail(status != NULL, 0);
	g_return_val_if_fail(id     != NULL, 0);

	if ((value = purple_status_get_attr_value(status, id)) == NULL)
		return 0;

	g_return_val_if_fail(purple_value_get_type(value) == PURPLE_TYPE_INT, 0);

	return purple_value_get_int(value);
}

const char *
purple_status_get_attr_string(const PurpleStatus *status, const char *id)
{
	const PurpleValue *value;

	g_return_val_if_fail(status != NULL, NULL);
	g_return_val_if_fail(id     != NULL, NULL);

	if ((value = purple_status_get_attr_value(status, id)) == NULL)
		return NULL;

	g_return_val_if_fail(purple_value_get_type(value) == PURPLE_TYPE_STRING, NULL);

	return purple_value_get_string(value);
}

gint
purple_status_compare(const PurpleStatus *status1, const PurpleStatus *status2)
{
	PurpleStatusType *type1, *type2;
	int score1 = 0, score2 = 0;

	if ((status1 == NULL && status2 == NULL) ||
			(status1 == status2))
	{
		return 0;
	}
	else if (status1 == NULL)
		return 1;
	else if (status2 == NULL)
		return -1;

	type1 = purple_status_get_type(status1);
	type2 = purple_status_get_type(status2);

	if (purple_status_is_active(status1))
		score1 = primitive_scores[purple_status_type_get_primitive(type1)];

	if (purple_status_is_active(status2))
		score2 = primitive_scores[purple_status_type_get_primitive(type2)];

	if (score1 > score2)
		return -1;
	else if (score1 < score2)
		return 1;

	return 0;
}


/**************************************************************************
* PurplePresence API
**************************************************************************/
PurplePresence *
purple_presence_new(PurplePresenceContext context)
{
	PurplePresence *presence;

	g_return_val_if_fail(context != PURPLE_PRESENCE_CONTEXT_UNSET, NULL);

	presence = g_new0(PurplePresence, 1);
	PURPLE_DBUS_REGISTER_POINTER(presence, PurplePresence);

	presence->context = context;

	presence->status_table =
		g_hash_table_new_full(g_str_hash, g_str_equal,
							  g_free, NULL);

	return presence;
}

PurplePresence *
purple_presence_new_for_account(PurpleAccount *account)
{
	PurplePresence *presence = NULL;
	g_return_val_if_fail(account != NULL, NULL);

	presence = purple_presence_new(PURPLE_PRESENCE_CONTEXT_ACCOUNT);
	presence->u.account = account;
	presence->statuses = purple_prpl_get_statuses(account, presence);

	return presence;
}

PurplePresence *
purple_presence_new_for_conv(PurpleConversation *conv)
{
	PurplePresence *presence;

	g_return_val_if_fail(conv != NULL, NULL);

	presence = purple_presence_new(PURPLE_PRESENCE_CONTEXT_CONV);
	presence->u.chat.conv = conv;
	/* presence->statuses = purple_prpl_get_statuses(conv->account, presence); ? */

	return presence;
}

PurplePresence *
purple_presence_new_for_buddy(PurpleBuddy *buddy)
{
	PurplePresence *presence;
	PurpleAccount *account;

	g_return_val_if_fail(buddy != NULL, NULL);
	account = purple_buddy_get_account(buddy);

	presence = purple_presence_new(PURPLE_PRESENCE_CONTEXT_BUDDY);

	presence->u.buddy.name    = g_strdup(purple_buddy_get_name(buddy));
	presence->u.buddy.account = account;
	presence->statuses = purple_prpl_get_statuses(account, presence);

	presence->u.buddy.buddy = buddy;

	return presence;
}

void
purple_presence_destroy(PurplePresence *presence)
{
	g_return_if_fail(presence != NULL);

	if (purple_presence_get_context(presence) == PURPLE_PRESENCE_CONTEXT_BUDDY)
	{
		g_free(presence->u.buddy.name);
	}
	else if (purple_presence_get_context(presence) == PURPLE_PRESENCE_CONTEXT_CONV)
	{
		g_free(presence->u.chat.user);
	}

	g_list_foreach(presence->statuses, (GFunc)purple_status_destroy, NULL);
	g_list_free(presence->statuses);

	g_hash_table_destroy(presence->status_table);

	PURPLE_DBUS_UNREGISTER_POINTER(presence);
	g_free(presence);
}

void
purple_presence_add_status(PurplePresence *presence, PurpleStatus *status)
{
	g_return_if_fail(presence != NULL);
	g_return_if_fail(status   != NULL);

	presence->statuses = g_list_append(presence->statuses, status);

	g_hash_table_insert(presence->status_table,
	g_strdup(purple_status_get_id(status)), status);
}

void
purple_presence_add_list(PurplePresence *presence, GList *source_list)
{
	GList *l;

	g_return_if_fail(presence    != NULL);
	g_return_if_fail(source_list != NULL);

	for (l = source_list; l != NULL; l = l->next)
		purple_presence_add_status(presence, (PurpleStatus *)l->data);
}

void
purple_presence_set_status_active(PurplePresence *presence, const char *status_id,
		gboolean active)
{
	PurpleStatus *status;

	g_return_if_fail(presence  != NULL);
	g_return_if_fail(status_id != NULL);

	status = purple_presence_get_status(presence, status_id);

	g_return_if_fail(status != NULL);
	/* TODO: Should we do the following? */
	/* g_return_if_fail(active == status->active); */

	if (purple_status_is_exclusive(status))
	{
		if (!active)
		{
			purple_debug_warning("status",
					"Attempted to set a non-independent status "
					"(%s) inactive. Only independent statuses "
					"can be specifically marked inactive.",
					status_id);
			return;
		}
	}

	purple_status_set_active(status, active);
}

void
purple_presence_switch_status(PurplePresence *presence, const char *status_id)
{
	purple_presence_set_status_active(presence, status_id, TRUE);
}

static void
update_buddy_idle(PurpleBuddy *buddy, PurplePresence *presence,
		time_t current_time, gboolean old_idle, gboolean idle)
{
	PurpleBlistUiOps *ops = purple_blist_get_ui_ops();
	PurpleAccount *account = purple_buddy_get_account(buddy);

	if (!old_idle && idle)
	{
		if (purple_prefs_get_bool("/purple/logging/log_system"))
		{
			PurpleLog *log = purple_account_get_log(account, FALSE);

			if (log != NULL)
			{
				char *tmp, *tmp2;
				tmp = g_strdup_printf(_("%s became idle"),
				purple_buddy_get_alias(buddy));
				tmp2 = g_markup_escape_text(tmp, -1);
				g_free(tmp);

				purple_log_write(log, PURPLE_MESSAGE_SYSTEM,
				purple_buddy_get_alias(buddy), current_time, tmp2);
				g_free(tmp2);
			}
		}
	}
	else if (old_idle && !idle)
	{
		if (purple_prefs_get_bool("/purple/logging/log_system"))
		{
			PurpleLog *log = purple_account_get_log(account, FALSE);

			if (log != NULL)
			{
				char *tmp, *tmp2;
				tmp = g_strdup_printf(_("%s became unidle"),
				purple_buddy_get_alias(buddy));
				tmp2 = g_markup_escape_text(tmp, -1);
				g_free(tmp);

				purple_log_write(log, PURPLE_MESSAGE_SYSTEM,
				purple_buddy_get_alias(buddy), current_time, tmp2);
				g_free(tmp2);
			}
		}
	}

	if (old_idle != idle)
		purple_signal_emit(purple_blist_get_handle(), "buddy-idle-changed", buddy,
		                 old_idle, idle);

	purple_contact_invalidate_priority_buddy(purple_buddy_get_contact(buddy));

	/* Should this be done here? It'd perhaps make more sense to
	 * connect to buddy-[un]idle signals and update from there
	 */

	if (ops != NULL && ops->update != NULL)
		ops->update(purple_get_blist(), (PurpleBlistNode *)buddy);
}

void
purple_presence_set_idle(PurplePresence *presence, gboolean idle, time_t idle_time)
{
	gboolean old_idle;
	time_t current_time;

	g_return_if_fail(presence != NULL);

	if (presence->idle == idle && presence->idle_time == idle_time)
		return;

	old_idle            = presence->idle;
	presence->idle      = idle;
	presence->idle_time = (idle ? idle_time : 0);

	current_time = time(NULL);

	if (purple_presence_get_context(presence) == PURPLE_PRESENCE_CONTEXT_BUDDY)
	{
		update_buddy_idle(purple_presence_get_buddy(presence), presence, current_time,
		                  old_idle, idle);
	}
	else if (purple_presence_get_context(presence) == PURPLE_PRESENCE_CONTEXT_ACCOUNT)
	{
		PurpleAccount *account;
		PurpleConnection *gc = NULL;
		PurplePlugin *prpl = NULL;
		PurplePluginProtocolInfo *prpl_info = NULL;

		account = purple_presence_get_account(presence);

		if (purple_prefs_get_bool("/purple/logging/log_system"))
		{
			PurpleLog *log = purple_account_get_log(account, FALSE);

			if (log != NULL)
			{
				char *msg, *tmp;

				if (idle)
					tmp = g_strdup_printf(_("+++ %s became idle"), purple_account_get_username(account));
				else
					tmp = g_strdup_printf(_("+++ %s became unidle"), purple_account_get_username(account));

				msg = g_markup_escape_text(tmp, -1);
				g_free(tmp);
				purple_log_write(log, PURPLE_MESSAGE_SYSTEM,
				                 purple_account_get_username(account),
				                 (idle ? idle_time : current_time), msg);
				g_free(msg);
			}
		}

		gc = purple_account_get_connection(account);

		if(gc)
			prpl = purple_connection_get_prpl(gc);

		if(PURPLE_CONNECTION_IS_CONNECTED(gc) && prpl != NULL)
			prpl_info = PURPLE_PLUGIN_PROTOCOL_INFO(prpl);

		if (prpl_info && prpl_info->set_idle)
			prpl_info->set_idle(gc, (idle ? (current_time - idle_time) : 0));
	}
}

void
purple_presence_set_login_time(PurplePresence *presence, time_t login_time)
{
	g_return_if_fail(presence != NULL);

	if (presence->login_time == login_time)
		return;

	presence->login_time = login_time;
}

PurplePresenceContext
purple_presence_get_context(const PurplePresence *presence)
{
	g_return_val_if_fail(presence != NULL, PURPLE_PRESENCE_CONTEXT_UNSET);

	return presence->context;
}

PurpleAccount *
purple_presence_get_account(const PurplePresence *presence)
{
	PurplePresenceContext context;

	g_return_val_if_fail(presence != NULL, NULL);

	context = purple_presence_get_context(presence);

	g_return_val_if_fail(context == PURPLE_PRESENCE_CONTEXT_ACCOUNT ||
			context == PURPLE_PRESENCE_CONTEXT_BUDDY, NULL);

	return presence->u.account;
}

PurpleConversation *
purple_presence_get_conversation(const PurplePresence *presence)
{
	g_return_val_if_fail(presence != NULL, NULL);
	g_return_val_if_fail(purple_presence_get_context(presence) ==
			PURPLE_PRESENCE_CONTEXT_CONV, NULL);

	return presence->u.chat.conv;
}

const char *
purple_presence_get_chat_user(const PurplePresence *presence)
{
	g_return_val_if_fail(presence != NULL, NULL);
	g_return_val_if_fail(purple_presence_get_context(presence) ==
			PURPLE_PRESENCE_CONTEXT_CONV, NULL);

	return presence->u.chat.user;
}

PurpleBuddy *
purple_presence_get_buddy(const PurplePresence *presence)
{
	g_return_val_if_fail(presence != NULL, NULL);
	g_return_val_if_fail(purple_presence_get_context(presence) ==
			PURPLE_PRESENCE_CONTEXT_BUDDY, NULL);

	return presence->u.buddy.buddy;
}

GList *
purple_presence_get_statuses(const PurplePresence *presence)
{
	g_return_val_if_fail(presence != NULL, NULL);

	return presence->statuses;
}

PurpleStatus *
purple_presence_get_status(const PurplePresence *presence, const char *status_id)
{
	PurpleStatus *status;
	GList *l = NULL;

	g_return_val_if_fail(presence  != NULL, NULL);
	g_return_val_if_fail(status_id != NULL, NULL);

	/* What's the purpose of this hash table? */
	status = (PurpleStatus *)g_hash_table_lookup(presence->status_table,
						   status_id);

	if (status == NULL) {
		for (l = purple_presence_get_statuses(presence);
			 l != NULL && status == NULL; l = l->next)
		{
			PurpleStatus *temp_status = l->data;

			if (purple_strequal(status_id, purple_status_get_id(temp_status)))
				status = temp_status;
		}

		if (status != NULL)
			g_hash_table_insert(presence->status_table,
								g_strdup(purple_status_get_id(status)), status);
	}

	return status;
}

PurpleStatus *
purple_presence_get_active_status(const PurplePresence *presence)
{
	g_return_val_if_fail(presence != NULL, NULL);

	return presence->active_status;
}

gboolean
purple_presence_is_available(const PurplePresence *presence)
{
	PurpleStatus *status;

	g_return_val_if_fail(presence != NULL, FALSE);

	status = purple_presence_get_active_status(presence);

	return ((status != NULL && purple_status_is_available(status)) &&
			!purple_presence_is_idle(presence));
}

gboolean
purple_presence_is_online(const PurplePresence *presence)
{
	PurpleStatus *status;

	g_return_val_if_fail(presence != NULL, FALSE);

	if ((status = purple_presence_get_active_status(presence)) == NULL)
		return FALSE;

	return purple_status_is_online(status);
}

gboolean
purple_presence_is_status_active(const PurplePresence *presence,
		const char *status_id)
{
	PurpleStatus *status;

	g_return_val_if_fail(presence  != NULL, FALSE);
	g_return_val_if_fail(status_id != NULL, FALSE);

	status = purple_presence_get_status(presence, status_id);

	return (status != NULL && purple_status_is_active(status));
}

gboolean
purple_presence_is_status_primitive_active(const PurplePresence *presence,
		PurpleStatusPrimitive primitive)
{
	GList *l;

	g_return_val_if_fail(presence  != NULL,              FALSE);
	g_return_val_if_fail(primitive != PURPLE_STATUS_UNSET, FALSE);

	for (l = purple_presence_get_statuses(presence);
	     l != NULL; l = l->next)
	{
		PurpleStatus *temp_status = l->data;
		PurpleStatusType *type = purple_status_get_type(temp_status);

		if (purple_status_type_get_primitive(type) == primitive &&
		    purple_status_is_active(temp_status))
			return TRUE;
	}
	return FALSE;
}

gboolean
purple_presence_is_idle(const PurplePresence *presence)
{
	g_return_val_if_fail(presence != NULL, FALSE);

	return purple_presence_is_online(presence) && presence->idle;
}

time_t
purple_presence_get_idle_time(const PurplePresence *presence)
{
	g_return_val_if_fail(presence != NULL, 0);

	return presence->idle_time;
}

time_t
purple_presence_get_login_time(const PurplePresence *presence)
{
	g_return_val_if_fail(presence != NULL, 0);

	return purple_presence_is_online(presence) ? presence->login_time : 0;
}

static int
purple_presence_compute_score(const PurplePresence *presence)
{
	GList *l;
	int score = 0;

	for (l = purple_presence_get_statuses(presence); l != NULL; l = l->next) {
		PurpleStatus *status = (PurpleStatus *)l->data;
		PurpleStatusType *type = purple_status_get_type(status);

		if (purple_status_is_active(status)) {
			score += primitive_scores[purple_status_type_get_primitive(type)];
			if (!purple_status_is_online(status)) {
				PurpleBuddy *b = purple_presence_get_buddy(presence);
				if (b && purple_account_supports_offline_message(purple_buddy_get_account(b), b))
					score += primitive_scores[SCORE_OFFLINE_MESSAGE];
			}
		}
	}
	score += purple_account_get_int(purple_presence_get_account(presence), "score", 0);
	if (purple_presence_is_idle(presence))
		score += primitive_scores[SCORE_IDLE];
	return score;
}

gint
purple_presence_compare(const PurplePresence *presence1,
		const PurplePresence *presence2)
{
	time_t idle_time_1, idle_time_2;
	int score1 = 0, score2 = 0;

	if (presence1 == presence2)
		return 0;
	else if (presence1 == NULL)
		return 1;
	else if (presence2 == NULL)
		return -1;

	if (purple_presence_is_online(presence1) &&
			!purple_presence_is_online(presence2))
		return -1;
	else if (purple_presence_is_online(presence2) &&
			!purple_presence_is_online(presence1))
		return 1;

	/* Compute the score of the first set of statuses. */
	score1 = purple_presence_compute_score(presence1);

	/* Compute the score of the second set of statuses. */
	score2 = purple_presence_compute_score(presence2);

	idle_time_1 = time(NULL) - purple_presence_get_idle_time(presence1);
	idle_time_2 = time(NULL) - purple_presence_get_idle_time(presence2);

	if (idle_time_1 > idle_time_2)
		score1 += primitive_scores[SCORE_IDLE_TIME];
	else if (idle_time_1 < idle_time_2)
		score2 += primitive_scores[SCORE_IDLE_TIME];

	if (score1 < score2)
		return 1;
	else if (score1 > score2)
		return -1;

	return 0;
}


/**************************************************************************
* Status subsystem
**************************************************************************/
static void
score_pref_changed_cb(const char *name, PurplePrefType type,
					  gconstpointer value, gpointer data)
{
	int index = GPOINTER_TO_INT(data);

	primitive_scores[index] = GPOINTER_TO_INT(value);
}

void *
purple_status_get_handle(void) {
	static int handle;

	return &handle;
}

void
purple_status_init(void)
{
	void *handle = purple_status_get_handle();

	purple_prefs_add_none("/purple/status");
	purple_prefs_add_none("/purple/status/scores");

	purple_prefs_add_int("/purple/status/scores/offline",
			primitive_scores[PURPLE_STATUS_OFFLINE]);
	purple_prefs_add_int("/purple/status/scores/available",
			primitive_scores[PURPLE_STATUS_AVAILABLE]);
	purple_prefs_add_int("/purple/status/scores/invisible",
			primitive_scores[PURPLE_STATUS_INVISIBLE]);
	purple_prefs_add_int("/purple/status/scores/away",
			primitive_scores[PURPLE_STATUS_AWAY]);
	purple_prefs_add_int("/purple/status/scores/extended_away",
			primitive_scores[PURPLE_STATUS_EXTENDED_AWAY]);
	purple_prefs_add_int("/purple/status/scores/idle",
			primitive_scores[SCORE_IDLE]);
	purple_prefs_add_int("/purple/status/scores/offline_msg",
			primitive_scores[SCORE_OFFLINE_MESSAGE]);

	purple_prefs_connect_callback(handle, "/purple/status/scores/offline",
			score_pref_changed_cb,
			GINT_TO_POINTER(PURPLE_STATUS_OFFLINE));
	purple_prefs_connect_callback(handle, "/purple/status/scores/available",
			score_pref_changed_cb,
			GINT_TO_POINTER(PURPLE_STATUS_AVAILABLE));
	purple_prefs_connect_callback(handle, "/purple/status/scores/invisible",
			score_pref_changed_cb,
			GINT_TO_POINTER(PURPLE_STATUS_INVISIBLE));
	purple_prefs_connect_callback(handle, "/purple/status/scores/away",
			score_pref_changed_cb,
			GINT_TO_POINTER(PURPLE_STATUS_AWAY));
	purple_prefs_connect_callback(handle, "/purple/status/scores/extended_away",
			score_pref_changed_cb,
			GINT_TO_POINTER(PURPLE_STATUS_EXTENDED_AWAY));
	purple_prefs_connect_callback(handle, "/purple/status/scores/idle",
			score_pref_changed_cb,
			GINT_TO_POINTER(SCORE_IDLE));
	purple_prefs_connect_callback(handle, "/purple/status/scores/offline_msg",
			score_pref_changed_cb,
			GINT_TO_POINTER(SCORE_OFFLINE_MESSAGE));

	purple_prefs_trigger_callback("/purple/status/scores/offline");
	purple_prefs_trigger_callback("/purple/status/scores/available");
	purple_prefs_trigger_callback("/purple/status/scores/invisible");
	purple_prefs_trigger_callback("/purple/status/scores/away");
	purple_prefs_trigger_callback("/purple/status/scores/extended_away");
	purple_prefs_trigger_callback("/purple/status/scores/idle");
	purple_prefs_trigger_callback("/purple/status/scores/offline_msg");
}

void
purple_status_uninit(void)
{
	purple_prefs_disconnect_by_handle(purple_prefs_get_handle());
}
