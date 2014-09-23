/**
 * @file savedstatuses.c Saved Status API
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

#include "debug.h"
#include "idle.h"
#include "notify.h"
#include "savedstatuses.h"
#include "dbus-maybe.h"
#include "request.h"
#include "status.h"
#include "util.h"
#include "xmlnode.h"

/**
 * The maximum number of transient statuses to save.  This
 * is used during the shutdown process to clean out old
 * transient statuses.
 */
#define MAX_TRANSIENTS 5

/**
 * The default message to use when the user becomes auto-away.
 */
#define DEFAULT_AUTOAWAY_MESSAGE _("I'm not here right now")

/**
 * The information stores a snap-shot of the statuses of all
 * your accounts.  Basically these are your saved away messages.
 * There is an overall status and message that applies to
 * all your accounts, and then each individual account can
 * optionally have a different custom status and message.
 *
 * The changes to status.xml caused by the new status API
 * are fully backward compatible.  The new status API just
 * adds the optional sub-statuses to the XML file.
 */
struct _PurpleSavedStatus
{
	char *title;
	PurpleStatusPrimitive type;
	char *message;

	/** The timestamp when this saved status was created. This must be unique. */
	time_t creation_time;

	time_t lastused;

	unsigned int usage_count;

	GList *substatuses;      /**< A list of PurpleSavedStatusSub's. */
};

/*
 * TODO: If a PurpleStatusType is deleted, need to also delete any
 *       associated PurpleSavedStatusSub's?
 */
struct _PurpleSavedStatusSub
{
	PurpleAccount *account;
	const PurpleStatusType *type;
	char *message;
};

static GList      *saved_statuses = NULL;
static guint       save_timer = 0;
static gboolean    statuses_loaded = FALSE;

/*
 * This hash table keeps track of which timestamps we've
 * used so that we don't have two saved statuses with the
 * same 'creation_time' timestamp.  The 'created' timestamp
 * is used as a unique identifier.
 *
 * So the key in this hash table is the creation_time and
 * the value is a pointer to the PurpleSavedStatus.
 */
static GHashTable *creation_times;

static void schedule_save(void);

/*********************************************************************
 * Private utility functions                                         *
 *********************************************************************/

static void
free_saved_status_sub(PurpleSavedStatusSub *substatus)
{
	g_return_if_fail(substatus != NULL);

	g_free(substatus->message);
	purple_request_close_with_handle(substatus);
	PURPLE_DBUS_UNREGISTER_POINTER(substatus);
	g_free(substatus);
}

static void
free_saved_status(PurpleSavedStatus *status)
{
	g_return_if_fail(status != NULL);

	g_free(status->title);
	g_free(status->message);

	while (status->substatuses != NULL)
	{
		PurpleSavedStatusSub *substatus = status->substatuses->data;
		status->substatuses = g_list_remove(status->substatuses, substatus);
		free_saved_status_sub(substatus);
	}
	purple_request_close_with_handle(status);
	PURPLE_DBUS_UNREGISTER_POINTER(status);
	g_free(status);
}

/*
 * Set the timestamp for when this saved status was created, and
 * make sure it is unique.
 */
static void
set_creation_time(PurpleSavedStatus *status, time_t creation_time)
{
	g_return_if_fail(status != NULL);

	/* Avoid using 0 because it's an invalid hash key */
	status->creation_time = creation_time != 0 ? creation_time : 1;

	while (g_hash_table_lookup(creation_times, (gconstpointer)status->creation_time) != NULL)
		status->creation_time++;

	g_hash_table_insert(creation_times,
						(gpointer)status->creation_time,
						status);
}

/**
 * A magic number is calculated for each status, and then the
 * statuses are ordered by the magic number.  The magic number
 * is the date the status was last used offset by one day for
 * each time the status has been used (but only by 10 days at
 * the most).
 *
 * The goal is to have recently used statuses at the top of
 * the list, but to also keep frequently used statuses near
 * the top.
 */
static gint
saved_statuses_sort_func(gconstpointer a, gconstpointer b)
{
	const PurpleSavedStatus *saved_status_a = a;
	const PurpleSavedStatus *saved_status_b = b;
	time_t time_a = saved_status_a->lastused +
						(MIN(saved_status_a->usage_count, 10) * 86400);
	time_t time_b = saved_status_b->lastused +
						(MIN(saved_status_b->usage_count, 10) * 86400);
	if (time_a > time_b)
		return -1;
	if (time_a < time_b)
		return 1;
	return 0;
}

/**
 * Transient statuses are added and removed automatically by
 * Purple.  If they're not used for a certain length of time then
 * they'll expire and be automatically removed.  This function
 * does the expiration.
 */
static void
remove_old_transient_statuses(void)
{
	GList *l, *next;
	PurpleSavedStatus *saved_status, *current_status;
	int count;
	time_t creation_time;

	current_status = purple_savedstatus_get_current();

	/*
	 * Iterate through the list of saved statuses.  Delete all
	 * transient statuses except for the first MAX_TRANSIENTS
	 * (remember, the saved statuses are already sorted by popularity).
	 */
	count = 0;
	for (l = saved_statuses; l != NULL; l = next)
	{
		next = l->next;
		saved_status = l->data;
		if (purple_savedstatus_is_transient(saved_status))
		{
			if (count == MAX_TRANSIENTS)
			{
				if (saved_status != current_status)
				{
					saved_statuses = g_list_remove(saved_statuses, saved_status);
					creation_time = purple_savedstatus_get_creation_time(saved_status);
					g_hash_table_remove(creation_times, (gconstpointer)creation_time);
					free_saved_status(saved_status);
				}
			}
			else
				count++;
		}
	}

	if (count == MAX_TRANSIENTS)
		schedule_save();
}

/*********************************************************************
 * Writing to disk                                                   *
 *********************************************************************/

static xmlnode *
substatus_to_xmlnode(PurpleSavedStatusSub *substatus)
{
	xmlnode *node, *child;

	node = xmlnode_new("substatus");

	child = xmlnode_new_child(node, "account");
	xmlnode_set_attrib(child, "protocol", purple_account_get_protocol_id(substatus->account));
	xmlnode_insert_data(child,
			purple_normalize(substatus->account,
				purple_account_get_username(substatus->account)), -1);

	child = xmlnode_new_child(node, "state");
	xmlnode_insert_data(child, purple_status_type_get_id(substatus->type), -1);

	if (substatus->message != NULL)
	{
		child = xmlnode_new_child(node, "message");
		xmlnode_insert_data(child, substatus->message, -1);
	}

	return node;
}

static xmlnode *
status_to_xmlnode(PurpleSavedStatus *status)
{
	xmlnode *node, *child;
	char buf[21];
	GList *cur;

	node = xmlnode_new("status");
	if (status->title != NULL)
	{
		xmlnode_set_attrib(node, "name", status->title);
	}
	else
	{
		/*
		 * Purple 1.5.0 and earlier require a name to be set, so we
		 * do this little hack to maintain backward compatability
		 * in the status.xml file.  Eventually this should be removed
		 * and we should determine if a status is transient by
		 * whether the "name" attribute is set to something or if
		 * it does not exist at all.
		 */
		xmlnode_set_attrib(node, "name", "Auto-Cached");
		xmlnode_set_attrib(node, "transient", "true");
	}

	g_snprintf(buf, sizeof(buf), "%lu", status->creation_time);
	xmlnode_set_attrib(node, "created", buf);

	g_snprintf(buf, sizeof(buf), "%lu", status->lastused);
	xmlnode_set_attrib(node, "lastused", buf);

	g_snprintf(buf, sizeof(buf), "%u", status->usage_count);
	xmlnode_set_attrib(node, "usage_count", buf);

	child = xmlnode_new_child(node, "state");
	xmlnode_insert_data(child, purple_primitive_get_id_from_type(status->type), -1);

	if (status->message != NULL)
	{
		child = xmlnode_new_child(node, "message");
		xmlnode_insert_data(child, status->message, -1);
	}

	for (cur = status->substatuses; cur != NULL; cur = cur->next)
	{
		child = substatus_to_xmlnode(cur->data);
		xmlnode_insert_child(node, child);
	}

	return node;
}

static xmlnode *
statuses_to_xmlnode(void)
{
	xmlnode *node, *child;
	GList *cur;

	node = xmlnode_new("statuses");
	xmlnode_set_attrib(node, "version", "1.0");

	for (cur = saved_statuses; cur != NULL; cur = cur->next)
	{
		child = status_to_xmlnode(cur->data);
		xmlnode_insert_child(node, child);
	}

	return node;
}

static void
sync_statuses(void)
{
	xmlnode *node;
	char *data;

	if (!statuses_loaded)
	{
		purple_debug_error("status", "Attempted to save statuses before they "
						 "were read!\n");
		return;
	}

	node = statuses_to_xmlnode();
	data = xmlnode_to_formatted_str(node, NULL);
	purple_util_write_data_to_file("status.xml", data, -1);
	g_free(data);
	xmlnode_free(node);
}

static gboolean
save_cb(gpointer data)
{
	sync_statuses();
	save_timer = 0;
	return FALSE;
}

static void
schedule_save(void)
{
	if (save_timer == 0)
		save_timer = purple_timeout_add_seconds(5, save_cb, NULL);
}


/*********************************************************************
 * Reading from disk                                                 *
 *********************************************************************/

static PurpleSavedStatusSub *
parse_substatus(xmlnode *substatus)
{
	PurpleSavedStatusSub *ret;
	xmlnode *node;
	char *data;

	ret = g_new0(PurpleSavedStatusSub, 1);

	/* Read the account */
	node = xmlnode_get_child(substatus, "account");
	if (node != NULL)
	{
		char *acct_name;
		const char *protocol;
		acct_name = xmlnode_get_data(node);
		protocol = xmlnode_get_attrib(node, "protocol");
		protocol = _purple_oscar_convert(acct_name, protocol); /* XXX: Remove */
		if ((acct_name != NULL) && (protocol != NULL))
			ret->account = purple_accounts_find(acct_name, protocol);
		g_free(acct_name);
	}

	if (ret->account == NULL)
	{
		g_free(ret);
		return NULL;
	}

	/* Read the state */
	node = xmlnode_get_child(substatus, "state");
	if ((node != NULL) && ((data = xmlnode_get_data(node)) != NULL))
	{
		ret->type = purple_status_type_find_with_id(
							ret->account->status_types, data);
		g_free(data);
	}

	if (ret->type == NULL)
	{
		g_free(ret);
		return NULL;
	}

	/* Read the message */
	node = xmlnode_get_child(substatus, "message");
	if ((node != NULL) && ((data = xmlnode_get_data(node)) != NULL))
	{
		ret->message = data;
	}

	PURPLE_DBUS_REGISTER_POINTER(ret, PurpleSavedStatusSub);
	return ret;
}

/**
 * Parse a saved status and add it to the saved_statuses linked list.
 *
 * Here's an example of the XML for a saved status:
 *   <status name="Girls">
 *       <state>away</state>
 *       <message>I like the way that they walk
 *   And it's chill to hear them talk
 *   And I can always make them smile
 *   From White Castle to the Nile</message>
 *       <substatus>
 *           <account protocol='prpl-aim'>markdoliner</account>
 *           <state>available</state>
 *           <message>The ladies man is here to answer your queries.</message>
 *       </substatus>
 *       <substatus>
 *           <account protocol='prpl-aim'>giantgraypanda</account>
 *           <state>away</state>
 *           <message>A.C. ain't in charge no more.</message>
 *       </substatus>
 *   </status>
 *
 * I know.  Moving, huh?
 */
static PurpleSavedStatus *
parse_status(xmlnode *status)
{
	PurpleSavedStatus *ret;
	xmlnode *node;
	const char *attrib;
	char *data;
	int i;

	ret = g_new0(PurpleSavedStatus, 1);

	attrib = xmlnode_get_attrib(status, "transient");
	if (!purple_strequal(attrib, "true"))
	{
		/* Read the title */
		attrib = xmlnode_get_attrib(status, "name");
		ret->title = g_strdup(attrib);
	}

	if (ret->title != NULL)
	{
		/* Ensure the title is unique */
		i = 2;
		while (purple_savedstatus_find(ret->title) != NULL)
		{
			g_free(ret->title);
			ret->title = g_strdup_printf("%s %d", attrib, i);
			i++;
		}
	}

	/* Read the creation time */
	attrib = xmlnode_get_attrib(status, "created");
	set_creation_time(ret, (attrib != NULL ? atol(attrib) : 0));

	/* Read the last used time */
	attrib = xmlnode_get_attrib(status, "lastused");
	ret->lastused = (attrib != NULL ? atol(attrib) : 0);

	/* Read the usage count */
	attrib = xmlnode_get_attrib(status, "usage_count");
	ret->usage_count = (attrib != NULL ? atol(attrib) : 0);

	/* Read the primitive status type */
	node = xmlnode_get_child(status, "state");
	if ((node != NULL) && ((data = xmlnode_get_data(node)) != NULL))
	{
		ret->type = purple_primitive_get_type_from_id(data);
		g_free(data);
	}

	/* Read the message */
	node = xmlnode_get_child(status, "message");
	if ((node != NULL) && ((data = xmlnode_get_data(node)) != NULL))
	{
		ret->message = data;
	}

	/* Read substatuses */
	for (node = xmlnode_get_child(status, "substatus"); node != NULL;
			node = xmlnode_get_next_twin(node))
	{
		PurpleSavedStatusSub *new;
		new = parse_substatus(node);
		if (new != NULL)
			ret->substatuses = g_list_prepend(ret->substatuses, new);
	}

	PURPLE_DBUS_REGISTER_POINTER(ret, PurpleSavedStatus);
	return ret;
}

/**
 * Read the saved statuses from a file in the Purple user dir.
 *
 * @return TRUE on success, FALSE on failure (if the file can not
 *         be opened, or if it contains invalid XML).
 */
static void
load_statuses(void)
{
	xmlnode *statuses, *status;

	statuses_loaded = TRUE;

	statuses = purple_util_read_xml_from_file("status.xml", _("saved statuses"));

	if (statuses == NULL)
		return;

	for (status = xmlnode_get_child(statuses, "status"); status != NULL;
			status = xmlnode_get_next_twin(status))
	{
		PurpleSavedStatus *new;
		new = parse_status(status);
		saved_statuses = g_list_prepend(saved_statuses, new);
	}
	saved_statuses = g_list_sort(saved_statuses, saved_statuses_sort_func);

	xmlnode_free(statuses);
}


/**************************************************************************
* Saved status API
**************************************************************************/
PurpleSavedStatus *
purple_savedstatus_new(const char *title, PurpleStatusPrimitive type)
{
	PurpleSavedStatus *status;

	/* Make sure we don't already have a saved status with this title. */
	if (title != NULL)
		g_return_val_if_fail(purple_savedstatus_find(title) == NULL, NULL);

	status = g_new0(PurpleSavedStatus, 1);
	PURPLE_DBUS_REGISTER_POINTER(status, PurpleSavedStatus);
	status->title = g_strdup(title);
	status->type = type;
	set_creation_time(status, time(NULL));

	saved_statuses = g_list_insert_sorted(saved_statuses, status, saved_statuses_sort_func);

	schedule_save();

	purple_signal_emit(purple_savedstatuses_get_handle(), "savedstatus-added",
		status);

	return status;
}

void
purple_savedstatus_set_title(PurpleSavedStatus *status, const char *title)
{
	g_return_if_fail(status != NULL);

	/* Make sure we don't already have a saved status with this title. */
	g_return_if_fail(purple_savedstatus_find(title) == NULL);

	g_free(status->title);
	status->title = g_strdup(title);

	schedule_save();

	purple_signal_emit(purple_savedstatuses_get_handle(),
			"savedstatus-modified", status);
}

void
purple_savedstatus_set_type(PurpleSavedStatus *status, PurpleStatusPrimitive type)
{
	g_return_if_fail(status != NULL);

	status->type = type;

	schedule_save();
	purple_signal_emit(purple_savedstatuses_get_handle(),
			"savedstatus-modified", status);
}

void
purple_savedstatus_set_message(PurpleSavedStatus *status, const char *message)
{
	g_return_if_fail(status != NULL);

	g_free(status->message);
	if ((message != NULL) && (*message == '\0'))
		status->message = NULL;
	else
		status->message = g_strdup(message);

	schedule_save();

	purple_signal_emit(purple_savedstatuses_get_handle(),
			"savedstatus-modified", status);
}

void
purple_savedstatus_set_substatus(PurpleSavedStatus *saved_status,
							   const PurpleAccount *account,
							   const PurpleStatusType *type,
							   const char *message)
{
	PurpleSavedStatusSub *substatus;

	g_return_if_fail(saved_status != NULL);
	g_return_if_fail(account      != NULL);
	g_return_if_fail(type         != NULL);

	/* Find an existing substatus or create a new one */
	substatus = purple_savedstatus_get_substatus(saved_status, account);
	if (substatus == NULL)
	{
		substatus = g_new0(PurpleSavedStatusSub, 1);
		PURPLE_DBUS_REGISTER_POINTER(substatus, PurpleSavedStatusSub);
		substatus->account = (PurpleAccount *)account;
		saved_status->substatuses = g_list_prepend(saved_status->substatuses, substatus);
	}

	substatus->type = type;
	g_free(substatus->message);
	substatus->message = g_strdup(message);

	schedule_save();
	purple_signal_emit(purple_savedstatuses_get_handle(),
			"savedstatus-modified", saved_status);
}

void
purple_savedstatus_unset_substatus(PurpleSavedStatus *saved_status,
								 const PurpleAccount *account)
{
	GList *iter;
	PurpleSavedStatusSub *substatus;

	g_return_if_fail(saved_status != NULL);
	g_return_if_fail(account      != NULL);

	for (iter = saved_status->substatuses; iter != NULL; iter = iter->next)
	{
		substatus = iter->data;
		if (substatus->account == account)
		{
			saved_status->substatuses = g_list_delete_link(saved_status->substatuses, iter);
			g_free(substatus->message);
			g_free(substatus);
			return;
		}
	}

	purple_signal_emit(purple_savedstatuses_get_handle(),
			"savedstatus-modified", saved_status);
}

/*
 * This gets called when an account is deleted.  We iterate through
 * all of our saved statuses and delete any substatuses that may
 * exist for this account.
 */
static void
purple_savedstatus_unset_all_substatuses(const PurpleAccount *account,
		gpointer user_data)
{
	GList *iter;
	PurpleSavedStatus *status;

	g_return_if_fail(account != NULL);

	for (iter = saved_statuses; iter != NULL; iter = iter->next)
	{
		status = (PurpleSavedStatus *)iter->data;
		purple_savedstatus_unset_substatus(status, account);
	}
}

void
purple_savedstatus_delete_by_status(PurpleSavedStatus *status)
{
	time_t creation_time, current, idleaway;

	g_return_if_fail(status != NULL);

	saved_statuses = g_list_remove(saved_statuses, status);
	creation_time = purple_savedstatus_get_creation_time(status);
	g_hash_table_remove(creation_times, (gconstpointer)creation_time);
	free_saved_status(status);

	schedule_save();

	/*
	 * If we just deleted our current status or our idleaway status,
	 * then set the appropriate pref back to 0.
	 */
	current = purple_prefs_get_int("/purple/savedstatus/default");
	if (current == creation_time)
		purple_prefs_set_int("/purple/savedstatus/default", 0);

	idleaway = purple_prefs_get_int("/purple/savedstatus/idleaway");
	if (idleaway == creation_time)
		purple_prefs_set_int("/purple/savedstatus/idleaway", 0);

	purple_signal_emit(purple_savedstatuses_get_handle(),
			"savedstatus-deleted", status);
}

gboolean
purple_savedstatus_delete(const char *title)
{
	PurpleSavedStatus *status;

	status = purple_savedstatus_find(title);

	if (status == NULL)
		return FALSE;

	if (purple_savedstatus_get_current() == status)
		return FALSE;

	purple_savedstatus_delete_by_status(status);

	return TRUE;
}

GList *
purple_savedstatuses_get_all(void)
{
	return saved_statuses;
}

GList *
purple_savedstatuses_get_popular(unsigned int how_many)
{
	GList *popular = NULL;
	GList *cur;
	unsigned int i;
	PurpleSavedStatus *next;

	/* Copy 'how_many' elements to a new list. If 'how_many' is 0, then copy all of 'em. */
	if (how_many == 0)
		how_many = (unsigned int) -1;

	i = 0;
	cur = saved_statuses;
	while ((i < how_many) && (cur != NULL))
	{
		next = cur->data;
		if ((!purple_savedstatus_is_transient(next)
			|| purple_savedstatus_get_message(next) != NULL))
		{
			popular = g_list_prepend(popular, next);
			i++;
		}
		cur = cur->next;
	}

	popular = g_list_reverse(popular);

	return popular;
}

PurpleSavedStatus *
purple_savedstatus_get_current(void)
{
	if (purple_savedstatus_is_idleaway())
		return purple_savedstatus_get_idleaway();
	else
		return purple_savedstatus_get_default();
}

PurpleSavedStatus *
purple_savedstatus_get_default()
{
	time_t creation_time;
	PurpleSavedStatus *saved_status = NULL;

	creation_time = purple_prefs_get_int("/purple/savedstatus/default");

	if (creation_time != 0)
		saved_status = g_hash_table_lookup(creation_times, (gconstpointer)creation_time);

	if (saved_status == NULL)
	{
		/*
		 * We don't have a current saved status!  This is either a new
		 * Purple user or someone upgrading from Purple 1.5.0 or older, or
		 * possibly someone who deleted the status they were currently
		 * using?  In any case, add a default status.
		 */
		saved_status = purple_savedstatus_new(NULL, PURPLE_STATUS_AVAILABLE);
		purple_prefs_set_int("/purple/savedstatus/default",
						   purple_savedstatus_get_creation_time(saved_status));
	}

	return saved_status;
}

PurpleSavedStatus *
purple_savedstatus_get_idleaway()
{
	time_t creation_time;
	PurpleSavedStatus *saved_status = NULL;

	creation_time = purple_prefs_get_int("/purple/savedstatus/idleaway");

	if (creation_time != 0)
		saved_status = g_hash_table_lookup(creation_times, (gconstpointer)creation_time);

	if (saved_status == NULL)
	{
		/* We don't have a specified "idle" status!  Weird. */
		saved_status = purple_savedstatus_find_transient_by_type_and_message(
				PURPLE_STATUS_AWAY, DEFAULT_AUTOAWAY_MESSAGE);

		if (saved_status == NULL)
		{
			saved_status = purple_savedstatus_new(NULL, PURPLE_STATUS_AWAY);
			purple_savedstatus_set_message(saved_status, DEFAULT_AUTOAWAY_MESSAGE);
			purple_prefs_set_int("/purple/savedstatus/idleaway",
							   purple_savedstatus_get_creation_time(saved_status));
		}
	}

	return saved_status;
}

gboolean
purple_savedstatus_is_idleaway()
{
	return purple_prefs_get_bool("/purple/savedstatus/isidleaway");
}

void
purple_savedstatus_set_idleaway(gboolean idleaway)
{
	GList *accounts, *node;
	PurpleSavedStatus *old, *saved_status;

	if (purple_savedstatus_is_idleaway() == idleaway)
		/* Don't need to do anything */
		return;

	old = purple_savedstatus_get_current();
	saved_status = idleaway ? purple_savedstatus_get_idleaway()
			: purple_savedstatus_get_default();
	purple_prefs_set_bool("/purple/savedstatus/isidleaway", idleaway);

	/* Changing our status makes us un-idle */
	if (!idleaway)
		purple_idle_touch();

	if (idleaway && (purple_savedstatus_get_type(old) != PURPLE_STATUS_AVAILABLE))
		/* Our global status is already "away," so don't change anything */
		return;

	accounts = purple_accounts_get_all_active();
	for (node = accounts; node != NULL; node = node->next)
	{
		PurpleAccount *account;
		PurplePresence *presence;
		PurpleStatus *status;

		account = node->data;
		presence = purple_account_get_presence(account);
		status = purple_presence_get_active_status(presence);

		if (!idleaway || purple_status_is_available(status))
			purple_savedstatus_activate_for_account(saved_status, account);
	}

	g_list_free(accounts);

	purple_signal_emit(purple_savedstatuses_get_handle(), "savedstatus-changed",
					 saved_status, old);
}

PurpleSavedStatus *
purple_savedstatus_get_startup()
{
	time_t creation_time;
	PurpleSavedStatus *saved_status = NULL;

	creation_time = purple_prefs_get_int("/purple/savedstatus/startup");

	if (creation_time != 0)
		saved_status = g_hash_table_lookup(creation_times, (gconstpointer)creation_time);

	if (saved_status == NULL)
	{
		/*
		 * We don't have a status to apply.
		 * This may be the first login, or the user wants to
		 * restore the "current" status.
		 */
		saved_status = purple_savedstatus_get_current();
	}

	return saved_status;
}


PurpleSavedStatus *
purple_savedstatus_find(const char *title)
{
	GList *iter;
	PurpleSavedStatus *status;

	g_return_val_if_fail(title != NULL, NULL);

	for (iter = saved_statuses; iter != NULL; iter = iter->next)
	{
		status = (PurpleSavedStatus *)iter->data;
		if (purple_strequal(status->title, title))
			return status;
	}

	return NULL;
}

PurpleSavedStatus *
purple_savedstatus_find_by_creation_time(time_t creation_time)
{
	GList *iter;
	PurpleSavedStatus *status;

	for (iter = saved_statuses; iter != NULL; iter = iter->next)
	{
		status = (PurpleSavedStatus *)iter->data;
		if (status->creation_time == creation_time)
			return status;
	}

	return NULL;
}

PurpleSavedStatus *
purple_savedstatus_find_transient_by_type_and_message(PurpleStatusPrimitive type,
													const char *message)
{
	GList *iter;
	PurpleSavedStatus *status;

	for (iter = saved_statuses; iter != NULL; iter = iter->next)
	{
		status = (PurpleSavedStatus *)iter->data;
		if ((status->type == type) && purple_savedstatus_is_transient(status) &&
			!purple_savedstatus_has_substatuses(status) &&
			purple_strequal(status->message, message))
		{
			return status;
		}
	}

	return NULL;
}

gboolean
purple_savedstatus_is_transient(const PurpleSavedStatus *saved_status)
{
	g_return_val_if_fail(saved_status != NULL, TRUE);

	return (saved_status->title == NULL);
}

const char *
purple_savedstatus_get_title(const PurpleSavedStatus *saved_status)
{
	const char *message;

	g_return_val_if_fail(saved_status != NULL, NULL);

	/* If we have a title then return it */
	if (saved_status->title != NULL)
		return saved_status->title;

	/* Otherwise, this is a transient status and we make up a title on the fly */
	message = purple_savedstatus_get_message(saved_status);

	if ((message == NULL) || (*message == '\0'))
	{
		PurpleStatusPrimitive primitive;
		primitive = purple_savedstatus_get_type(saved_status);
		return purple_primitive_get_name_from_type(primitive);
	}
	else
	{
		char *stripped;
		static char buf[64];
		stripped = purple_markup_strip_html(message);
		purple_util_chrreplace(stripped, '\n', ' ');
		strncpy(buf, stripped, sizeof(buf));
		buf[sizeof(buf) - 1] = '\0';
		if ((strlen(stripped) + 1) > sizeof(buf))
		{
			/* Truncate and ellipsize */
			char *tmp = g_utf8_find_prev_char(buf, &buf[sizeof(buf) - 4]);
			strcpy(tmp, "...");
		}
		g_free(stripped);
		return buf;
	}
}

PurpleStatusPrimitive
purple_savedstatus_get_type(const PurpleSavedStatus *saved_status)
{
	g_return_val_if_fail(saved_status != NULL, PURPLE_STATUS_OFFLINE);

	return saved_status->type;
}

const char *
purple_savedstatus_get_message(const PurpleSavedStatus *saved_status)
{
	g_return_val_if_fail(saved_status != NULL, NULL);

	return saved_status->message;
}

time_t
purple_savedstatus_get_creation_time(const PurpleSavedStatus *saved_status)
{
	g_return_val_if_fail(saved_status != NULL, 0);

	return saved_status->creation_time;
}

gboolean
purple_savedstatus_has_substatuses(const PurpleSavedStatus *saved_status)
{
	g_return_val_if_fail(saved_status != NULL, FALSE);

	return (saved_status->substatuses != NULL);
}

PurpleSavedStatusSub *
purple_savedstatus_get_substatus(const PurpleSavedStatus *saved_status,
							   const PurpleAccount *account)
{
	GList *iter;
	PurpleSavedStatusSub *substatus;

	g_return_val_if_fail(saved_status != NULL, NULL);
	g_return_val_if_fail(account      != NULL, NULL);

	for (iter = saved_status->substatuses; iter != NULL; iter = iter->next)
	{
		substatus = iter->data;
		if (substatus->account == account)
			return substatus;
	}

	return NULL;
}

const PurpleStatusType *
purple_savedstatus_substatus_get_type(const PurpleSavedStatusSub *substatus)
{
	g_return_val_if_fail(substatus != NULL, NULL);

	return substatus->type;
}

const char *
purple_savedstatus_substatus_get_message(const PurpleSavedStatusSub *substatus)
{
	g_return_val_if_fail(substatus != NULL, NULL);

	return substatus->message;
}

void
purple_savedstatus_activate(PurpleSavedStatus *saved_status)
{
	GList *accounts, *node;
	PurpleSavedStatus *old = purple_savedstatus_get_current();

	g_return_if_fail(saved_status != NULL);

	/* Make sure our list of saved statuses remains sorted */
	saved_status->lastused = time(NULL);
	saved_status->usage_count++;
	saved_statuses = g_list_remove(saved_statuses, saved_status);
	saved_statuses = g_list_insert_sorted(saved_statuses, saved_status, saved_statuses_sort_func);
	purple_prefs_set_int("/purple/savedstatus/default",
					   purple_savedstatus_get_creation_time(saved_status));

	accounts = purple_accounts_get_all_active();
	for (node = accounts; node != NULL; node = node->next)
	{
		PurpleAccount *account;

		account = node->data;

		purple_savedstatus_activate_for_account(saved_status, account);
	}

	g_list_free(accounts);

	if (purple_savedstatus_is_idleaway()) {
		purple_savedstatus_set_idleaway(FALSE);
	} else {
		purple_signal_emit(purple_savedstatuses_get_handle(), "savedstatus-changed",
					 	   saved_status, old);
	}
}

void
purple_savedstatus_activate_for_account(const PurpleSavedStatus *saved_status,
									  PurpleAccount *account)
{
	const PurpleStatusType *status_type;
	const PurpleSavedStatusSub *substatus;
	const char *message = NULL;

	g_return_if_fail(saved_status != NULL);
	g_return_if_fail(account != NULL);

	substatus = purple_savedstatus_get_substatus(saved_status, account);
	if (substatus != NULL)
	{
		status_type = substatus->type;
		message = substatus->message;
	}
	else
	{
		status_type = purple_account_get_status_type_with_primitive(account, saved_status->type);
		if (status_type == NULL)
			return;
		message = saved_status->message;
	}

	if ((message != NULL) &&
		(purple_status_type_get_attr(status_type, "message")))
	{
		purple_account_set_status(account, purple_status_type_get_id(status_type),
								TRUE, "message", message, NULL);
	}
	else
	{
		purple_account_set_status(account, purple_status_type_get_id(status_type),
								TRUE, NULL);
	}
}

void *
purple_savedstatuses_get_handle(void)
{
	static int handle;

	return &handle;
}

void
purple_savedstatuses_init(void)
{
	void *handle = purple_savedstatuses_get_handle();

	creation_times = g_hash_table_new(g_direct_hash, g_direct_equal);

	/*
	 * Using 0 as the creation_time is a special case.
	 * If someone calls purple_savedstatus_get_current() or
	 * purple_savedstatus_get_idleaway() and either of those functions
	 * sees a creation_time of 0, then it will create a default
	 * saved status and return that to the user.
	 */
	purple_prefs_add_none("/purple/savedstatus");
	purple_prefs_add_int("/purple/savedstatus/default", 0);
	purple_prefs_add_int("/purple/savedstatus/startup", 0);
	purple_prefs_add_bool("/purple/savedstatus/startup_current_status", TRUE);
	purple_prefs_add_int("/purple/savedstatus/idleaway", 0);
	purple_prefs_add_bool("/purple/savedstatus/isidleaway", FALSE);

	load_statuses();

	purple_signal_register(handle, "savedstatus-changed",
					 purple_marshal_VOID__POINTER_POINTER, NULL, 2,
					 purple_value_new(PURPLE_TYPE_SUBTYPE,
									PURPLE_SUBTYPE_SAVEDSTATUS),
					 purple_value_new(PURPLE_TYPE_SUBTYPE,
									PURPLE_SUBTYPE_SAVEDSTATUS));

	purple_signal_register(handle, "savedstatus-added",
		purple_marshal_VOID__POINTER, NULL, 1,
		purple_value_new(PURPLE_TYPE_SUBTYPE,
			PURPLE_SUBTYPE_SAVEDSTATUS));

	purple_signal_register(handle, "savedstatus-deleted",
		purple_marshal_VOID__POINTER, NULL, 1,
		purple_value_new(PURPLE_TYPE_SUBTYPE,
			PURPLE_SUBTYPE_SAVEDSTATUS));

	purple_signal_register(handle, "savedstatus-modified",
		purple_marshal_VOID__POINTER, NULL, 1,
		purple_value_new(PURPLE_TYPE_SUBTYPE,
			PURPLE_SUBTYPE_SAVEDSTATUS));

	purple_signal_connect(purple_accounts_get_handle(), "account-removed",
			handle,
			PURPLE_CALLBACK(purple_savedstatus_unset_all_substatuses),
			NULL);
}

void
purple_savedstatuses_uninit(void)
{
	gpointer handle = purple_savedstatuses_get_handle();

	remove_old_transient_statuses();

	if (save_timer != 0)
	{
		purple_timeout_remove(save_timer);
		save_timer = 0;
		sync_statuses();
	}

	while (saved_statuses != NULL) {
		PurpleSavedStatus *saved_status = saved_statuses->data;
		saved_statuses = g_list_remove(saved_statuses, saved_status);
		free_saved_status(saved_status);
	}

	g_hash_table_destroy(creation_times);
	creation_times = NULL;

	purple_signals_unregister_by_instance(handle);
	purple_signals_disconnect_by_handle(handle);
}

