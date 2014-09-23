/**
 * @file userlist.c MSN user list support
 *
 * purple
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
#include "request.h"

#include "msn.h"
#include "msnutils.h"
#include "userlist.h"

#include "contact.h"

const char *lists[] = { "FL", "AL", "BL", "RL" };

typedef struct
{
	PurpleConnection *gc;
	char *who;
	char *friendly;

} MsnPermitAdd;

/**************************************************************************
 * Callbacks
 **************************************************************************/
static void
msn_accept_add_cb(gpointer data)
{
	MsnPermitAdd *pa = data;

	purple_debug_misc("msn", "Accepted the new buddy: %s\n", pa->who);

	if (PURPLE_CONNECTION_IS_VALID(pa->gc))
	{
		MsnSession *session = pa->gc->proto_data;
		MsnUserList *userlist = session->userlist;
		PurpleAccount *account = purple_connection_get_account(pa->gc);

		msn_userlist_add_buddy_to_list(userlist, pa->who, MSN_LIST_AL);
		purple_privacy_deny_remove(account, pa->who, TRUE);
		purple_privacy_permit_add(account, pa->who, TRUE);

		msn_del_contact_from_list(session, NULL, pa->who, MSN_LIST_PL);
	}

	g_free(pa->who);
	g_free(pa->friendly);
	g_free(pa);
}

static void
msn_cancel_add_cb(gpointer data)
{
	MsnPermitAdd *pa = data;

	purple_debug_misc("msn", "Denied the new buddy: %s\n", pa->who);

	if (PURPLE_CONNECTION_IS_VALID(pa->gc))
	{
		MsnSession *session = pa->gc->proto_data;
		MsnUserList *userlist = session->userlist;
		MsnCallbackState *state = msn_callback_state_new(session);

		msn_callback_state_set_action(state, MSN_DENIED_BUDDY);

		msn_userlist_add_buddy_to_list(userlist, pa->who, MSN_LIST_BL);
		msn_del_contact_from_list(session, state, pa->who, MSN_LIST_PL);
	}

	g_free(pa->who);
	g_free(pa->friendly);
	g_free(pa);
}

static void
got_new_entry(PurpleConnection *gc, const char *passport, const char *friendly, const char *message)
{
	PurpleAccount *acct;
	MsnPermitAdd *pa;

	pa = g_new0(MsnPermitAdd, 1);
	pa->who = g_strdup(passport);
	pa->friendly = g_strdup(friendly);
	pa->gc = gc;

	acct = purple_connection_get_account(gc);
	purple_account_request_authorization(acct, passport, NULL, friendly, message,
										 purple_find_buddy(acct, passport) != NULL,
										 msn_accept_add_cb, msn_cancel_add_cb, pa);

}

/**************************************************************************
 * Server functions
 **************************************************************************/

void
msn_got_lst_user(MsnSession *session, MsnUser *user,
				 MsnListOp list_op, GSList *group_ids)
{
	PurpleConnection *gc;
	PurpleAccount *account;
	const char *passport;
	const char *store;
	const char *message;

	account = session->account;
	gc = purple_account_get_connection(account);

	passport = msn_user_get_passport(user);
	store = msn_user_get_friendly_name(user);
	message = msn_user_get_invite_message(user);

	msn_user_set_op(user, list_op);

	if (list_op & MSN_LIST_FL_OP)
	{
		GSList *c;
		for (c = group_ids; c != NULL; c = g_slist_next(c))
		{
			char *group_id = c->data;
			msn_user_add_group_id(user, group_id);
		}

		/* FIXME: It might be a real alias */
		/* Umm, what? This might fix bug #1385130 */
		serv_got_alias(gc, passport, store);
	}

	if (list_op & MSN_LIST_AL_OP)
	{
		/* These are users who are allowed to see our status. */
		purple_privacy_deny_remove(account, passport, TRUE);
		purple_privacy_permit_add(account, passport, TRUE);
	}

	if (list_op & MSN_LIST_BL_OP)
	{
		/* These are users who are not allowed to see our status. */
		purple_privacy_permit_remove(account, passport, TRUE);
		purple_privacy_deny_add(account, passport, TRUE);
	}

	if (list_op & MSN_LIST_RL_OP)
	{
		/* These are users who have us on their buddy list. */
		/*
		 * TODO: What is store name set to when this happens?
		 *       For one of my accounts "something@hotmail.com"
		 *       the store name was "something."  Maybe we
		 *       should use the friendly name, instead? --KingAnt
		 */

		if (!(list_op & (MSN_LIST_AL_OP | MSN_LIST_BL_OP)))
		{
/*			got_new_entry(gc, passport, store, NULL); */
		}
	}

	if (list_op & MSN_LIST_PL_OP)
	{
		user->authorized = TRUE;
		got_new_entry(gc, passport, store, message);
	}
}

/**************************************************************************
 * UserList functions
 **************************************************************************/

MsnUserList*
msn_userlist_new(MsnSession *session)
{
	MsnUserList *userlist;

	userlist = g_new0(MsnUserList, 1);

	userlist->session = session;
	userlist->buddy_icon_requests = g_queue_new();

	/* buddy_icon_window is the number of allowed simultaneous buddy icon requests.
	 * XXX With smarter rate limiting code, we could allow more at once... 5 was the limit set when
	 * we weren't retrieiving any more than 5 per MSN session. */
	userlist->buddy_icon_window = 1;

	return userlist;
}

void
msn_userlist_destroy(MsnUserList *userlist)
{
	GList *l;

	/*destroy userlist*/
	for (l = userlist->users; l != NULL; l = l->next)
	{
		msn_user_unref(l->data);
	}
	g_list_free(userlist->users);

	/*destroy group list*/
	for (l = userlist->groups; l != NULL; l = l->next)
	{
		msn_group_destroy(l->data);
	}
	g_list_free(userlist->groups);

	g_queue_free(userlist->buddy_icon_requests);

	if (userlist->buddy_icon_request_timer)
		purple_timeout_remove(userlist->buddy_icon_request_timer);

	g_free(userlist);
}

MsnUser *
msn_userlist_find_add_user(MsnUserList *userlist, const char *passport, const char *friendly_name)
{
	MsnUser *user;

	user = msn_userlist_find_user(userlist, passport);
	if (user == NULL)
	{
		user = msn_user_new(userlist, passport, friendly_name);
		msn_userlist_add_user(userlist, user);
		msn_user_unref(user);
	} else {
		msn_user_set_friendly_name(user, friendly_name);
	}
	return user;
}

void
msn_userlist_add_user(MsnUserList *userlist, MsnUser *user)
{
	msn_user_ref(user);
	userlist->users = g_list_prepend(userlist->users, user);
}

void
msn_userlist_remove_user(MsnUserList *userlist, MsnUser *user)
{
	userlist->users = g_list_remove(userlist->users, user);
	g_queue_remove(userlist->buddy_icon_requests, user);
	msn_user_unref(user);
}

MsnUser *
msn_userlist_find_user(MsnUserList *userlist, const char *passport)
{
	GList *l;

	g_return_val_if_fail(passport != NULL, NULL);

	for (l = userlist->users; l != NULL; l = l->next)
	{
		MsnUser *user = (MsnUser *)l->data;

		g_return_val_if_fail(user->passport != NULL, NULL);

		if (!g_ascii_strcasecmp(passport, user->passport)){
			return user;
		}
	}

	return NULL;
}

MsnUser *
msn_userlist_find_user_with_id(MsnUserList *userlist, const char *uid)
{
	GList *l;

	g_return_val_if_fail(uid != NULL, NULL);

	for (l = userlist->users; l != NULL; l = l->next) {
		MsnUser *user = (MsnUser *)l->data;

		if (user->uid == NULL) {
			continue;
		}

		if ( !g_ascii_strcasecmp(uid, user->uid) ) {
			return user;
		}
	}

	return NULL;
}

MsnUser *
msn_userlist_find_user_with_mobile_phone(MsnUserList *userlist, const char *number)
{
	GList *l;

	g_return_val_if_fail(number != NULL, NULL);

	for (l = userlist->users; l != NULL; l = l->next) {
		MsnUser *user = (MsnUser *)l->data;
		const char *user_number = msn_user_get_mobile_phone(user);

		if (user_number && !g_ascii_strcasecmp(number, user_number))
			return user;
	}

	return NULL;
}

void
msn_userlist_add_group(MsnUserList *userlist, MsnGroup *group)
{
	userlist->groups = g_list_append(userlist->groups, group);
}

void
msn_userlist_remove_group(MsnUserList *userlist, MsnGroup *group)
{
	userlist->groups = g_list_remove(userlist->groups, group);
}

MsnGroup *
msn_userlist_find_group_with_id(MsnUserList *userlist, const char * id)
{
	GList *l;

	g_return_val_if_fail(userlist != NULL, NULL);
	g_return_val_if_fail(id       != NULL, NULL);

	for (l = userlist->groups; l != NULL; l = l->next)
	{
		MsnGroup *group = l->data;

		if (!g_ascii_strcasecmp(group->id,id))
			return group;
	}

	return NULL;
}

MsnGroup *
msn_userlist_find_group_with_name(MsnUserList *userlist, const char *name)
{
	GList *l;

	g_return_val_if_fail(userlist != NULL, NULL);
	g_return_val_if_fail(name     != NULL, NULL);

	for (l = userlist->groups; l != NULL; l = l->next)
	{
		MsnGroup *group = l->data;

		if ((group->name != NULL) && !g_ascii_strcasecmp(name, group->name))
			return group;
	}

	return NULL;
}

const char *
msn_userlist_find_group_id(MsnUserList *userlist, const char *group_name)
{
	MsnGroup *group;

	group = msn_userlist_find_group_with_name(userlist, group_name);

	if (group != NULL)
		return msn_group_get_id(group);
	else
		return NULL;
}

const char *
msn_userlist_find_group_name(MsnUserList *userlist, const char * group_id)
{
	MsnGroup *group;

	group = msn_userlist_find_group_with_id(userlist, group_id);

	if (group != NULL)
		return msn_group_get_name(group);
	else
		return NULL;
}

void
msn_userlist_rename_group_id(MsnUserList *userlist, const char * group_id,
							 const char *new_name)
{
	MsnGroup *group;

	group = msn_userlist_find_group_with_id(userlist, group_id);

	if (group != NULL)
		msn_group_set_name(group, new_name);
}

void
msn_userlist_remove_group_id(MsnUserList *userlist, const char * group_id)
{
	MsnGroup *group;

	group = msn_userlist_find_group_with_id(userlist, group_id);

	if (group != NULL)
	{
		msn_userlist_remove_group(userlist, group);
		msn_group_destroy(group);
	}
}

typedef struct {
	MsnSession *session;
	char *uid;
} MsnUserlistABData;

static void
userlist_ab_delete_cb(void *data, int choice)
{
	MsnUserlistABData *ab = (MsnUserlistABData *)data;

	/* msn_delete_contact(ab->session, ab->uid, (gboolean)choice); */

	g_free(ab->uid);
	g_free(ab);
}

void
msn_userlist_rem_buddy(MsnUserList *userlist, const char *who)
{
	MsnUser *user = NULL;

	g_return_if_fail(userlist != NULL);
	g_return_if_fail(userlist->session != NULL);
	g_return_if_fail(who != NULL);

	user = msn_userlist_find_user(userlist, who);

	msn_userlist_rem_buddy_from_list(userlist, who, MSN_LIST_FL);

	/* delete the contact from address book via soap action */
	if (user != NULL) {
		if (0 /*not ready yet*/ && userlist->session->passport_info.email_enabled) {
			MsnUserlistABData *ab = g_new0(MsnUserlistABData, 1);
			ab->session = userlist->session;
			ab->uid = g_strdup(user->uid); /* Not necessary? */
			purple_request_yes_no(userlist->session->account,
				_("Delete Buddy from Address Book?"),
				_("Do you want to delete this buddy from your address book as well?"),
				user->passport, 0, userlist->session->account, user->passport,
				NULL, ab,
				G_CALLBACK(userlist_ab_delete_cb), G_CALLBACK(userlist_ab_delete_cb));
		} else
			msn_delete_contact(userlist->session, user);
	}
}

void
msn_userlist_rem_buddy_from_list(MsnUserList *userlist, const char *who,
				 MsnListId list_id)
{
	MsnUser *user;
	const gchar *list;
	MsnListOp list_op = 1 << list_id;

	user = msn_userlist_find_user(userlist, who);

	g_return_if_fail(user != NULL);

	if ( !msn_user_is_in_list(user, list_id)) {
		list = lists[list_id];
		purple_debug_info("msn", "User %s is not in list %s, not removing.\n", who, list);
		return;
	}

	msn_user_unset_op(user, list_op);

	msn_notification_rem_buddy_from_list(userlist->session->notification, list_id, user);
}

/*add buddy*/
void
msn_userlist_add_buddy(MsnUserList *userlist, const char *who, const char *group_name)
{
	MsnUser *user;
	MsnCallbackState *state = NULL;
	const char *group_id = NULL, *new_group_name;

	new_group_name = group_name == NULL ? MSN_INDIVIDUALS_GROUP_NAME : group_name;

	g_return_if_fail(userlist != NULL);
	g_return_if_fail(userlist->session != NULL);

	purple_debug_info("msn", "Add user: %s to group: %s\n", who, new_group_name);

	if (!msn_email_is_valid(who))
	{
		/* only notify the user about problems adding to the friends list
		 * maybe we should do something else for other lists, but it probably
		 * won't cause too many problems if we just ignore it */

		char *str = g_strdup_printf(_("Unable to add \"%s\"."), who);

		purple_notify_error(NULL, NULL, str,
				  _("The username specified is invalid."));
		g_free(str);

		return;
	}

	state = msn_callback_state_new(userlist->session);
	msn_callback_state_set_who(state, who);
	msn_callback_state_set_new_group_name(state, new_group_name);

	group_id = msn_userlist_find_group_id(userlist, new_group_name);

	if (group_id == NULL)
	{
		/* Whoa, we must add that group first. */
		purple_debug_info("msn", "Adding user %s to a new group, creating group %s first\n", who, new_group_name);

		msn_callback_state_set_action(state, MSN_ADD_BUDDY);

		msn_add_group(userlist->session, state, new_group_name);
		return;
	} else {
		msn_callback_state_set_guid(state, group_id);
	}

	/* XXX: adding user here may not be correct (should add them in the
 	 * ACK to the ADL command), but for now we need to make sure they exist
	 * early enough that the ILN command doesn't screw us up */

	user = msn_userlist_find_add_user(userlist, who, who);

	if ( msn_user_is_in_list(user, MSN_LIST_FL) ) {

		purple_debug_info("msn", "User %s already exists\n", who);

		msn_userlist_rem_buddy_from_list(userlist, who, MSN_LIST_BL);

		if (msn_user_is_in_group(user, group_id)) {
			purple_debug_info("msn", "User %s is already in group %s, returning\n", who, new_group_name);
			msn_callback_state_free(state);
			return;
		}
	}

	purple_debug_info("msn", "Adding user: %s to group id: %s\n", who, group_id);

	msn_callback_state_set_action(state, MSN_ADD_BUDDY);

	/* Add contact in the Contact server with a SOAP request and if
	   successful, send ADL with MSN_LIST_AL and MSN_LIST_FL and a FQY */
	msn_add_contact_to_group(userlist->session, state, who, group_id);
}

void
msn_userlist_add_buddy_to_list(MsnUserList *userlist, const char *who,
							MsnListId list_id)
{
	MsnUser *user = NULL;
	const gchar *list;
	MsnListOp list_op = 1 << list_id;

	g_return_if_fail(userlist != NULL);

	user = msn_userlist_find_add_user(userlist, who, who);

	/* First we're going to check if it's already there. */
	if (msn_user_is_in_list(user, list_id))
	{
		list = lists[list_id];
		purple_debug_info("msn", "User '%s' is already in list: %s\n", who, list);
		return;
	}

	/* XXX: see XXX above, this should really be done when we get the response from
		the server */

	msn_user_set_op(user, list_op);

	msn_notification_add_buddy_to_list(userlist->session->notification, list_id, user);
}

gboolean
msn_userlist_add_buddy_to_group(MsnUserList *userlist, const char *who,
				const char *group_name)
{
	MsnUser *user;
	gchar * group_id;

	g_return_val_if_fail(userlist != NULL, FALSE);
	g_return_val_if_fail(group_name != NULL, FALSE);
	g_return_val_if_fail(who != NULL, FALSE);

	purple_debug_info("msn", "Adding buddy with passport %s to group %s\n", who, group_name);

	if ( (group_id = (gchar *)msn_userlist_find_group_id(userlist, group_name)) == NULL) {
		purple_debug_error("msn", "Group %s has no guid!\n", group_name);
		return FALSE;
	}

	if ( (user = msn_userlist_find_user(userlist, who)) == NULL) {
		purple_debug_error("msn", "User %s not found!\n", who);
		return FALSE;
	}

	msn_user_add_group_id(user, group_id);

	return TRUE;
}


gboolean
msn_userlist_rem_buddy_from_group(MsnUserList *userlist, const char *who,
				const char *group_name)
{
	const gchar * group_id;
	MsnUser *user;

	g_return_val_if_fail(userlist != NULL, FALSE);
	g_return_val_if_fail(group_name != NULL, FALSE);
	g_return_val_if_fail(who != NULL, FALSE);

	purple_debug_info("msn", "Removing buddy with passport %s from group %s\n", who, group_name);

	if ( (group_id = msn_userlist_find_group_id(userlist, group_name)) == NULL) {
		purple_debug_error("msn", "Group %s has no guid!\n", group_name);
		return FALSE;
	}

	if ( (user = msn_userlist_find_user(userlist, who)) == NULL) {
		purple_debug_error("msn", "User %s not found!\n", who);
		return FALSE;
	}

	msn_user_remove_group_id(user, group_id);

	return TRUE;
}

void
msn_userlist_move_buddy(MsnUserList *userlist, const char *who,
			const char *old_group_name, const char *new_group_name)
{
	const char *new_group_id;
	MsnCallbackState *state;

	g_return_if_fail(userlist != NULL);
	g_return_if_fail(userlist->session != NULL);

	state = msn_callback_state_new(userlist->session);
	msn_callback_state_set_who(state, who);
	msn_callback_state_set_action(state, MSN_MOVE_BUDDY);
	msn_callback_state_set_old_group_name(state, old_group_name);
	msn_callback_state_set_new_group_name(state, new_group_name);

	new_group_id = msn_userlist_find_group_id(userlist, new_group_name);

	if (new_group_id == NULL)
	{
		msn_add_group(userlist->session, state, new_group_name);
		return;
	}

	/* add the contact to the new group, and remove it from the old one in
	 * the callback
	*/
	msn_add_contact_to_group(userlist->session, state, who, new_group_id);
}

void
msn_release_buddy_icon_request(MsnUserList *userlist)
{
	MsnUser *user;

	g_return_if_fail(userlist != NULL);

	if (purple_debug_is_verbose())
		purple_debug_info("msn", "Releasing buddy icon request\n");

	if (userlist->buddy_icon_window > 0) {
		GQueue *queue;

		queue = userlist->buddy_icon_requests;

		if (g_queue_is_empty(userlist->buddy_icon_requests))
			return;

		user = g_queue_pop_head(queue);

		userlist->buddy_icon_window--;

		msn_request_user_display(user);

		if (purple_debug_is_verbose())
			purple_debug_info("msn",
			                  "msn_release_buddy_icon_request(): buddy_icon_window-- yields =%d\n",
			                  userlist->buddy_icon_window);
	}
}

/*load userlist from the Blist file cache*/
void
msn_userlist_load(MsnSession *session)
{
	PurpleAccount *account = session->account;
	PurpleConnection *gc = purple_account_get_connection(account);
	GSList *l;
	MsnUser * user;

	g_return_if_fail(gc != NULL);

	for (l = purple_find_buddies(account, NULL); l != NULL;
			l = g_slist_delete_link(l, l)) {
		PurpleBuddy *buddy = l->data;

		user = msn_userlist_find_add_user(session->userlist,
			purple_buddy_get_name(buddy), NULL);
		purple_buddy_set_protocol_data(buddy, user);
		msn_user_set_op(user, MSN_LIST_FL_OP);
	}
	for (l = session->account->permit; l != NULL; l = l->next)
	{
		user = msn_userlist_find_add_user(session->userlist,
						(char *)l->data,NULL);
		msn_user_set_op(user, MSN_LIST_AL_OP);
	}
	for (l = session->account->deny; l != NULL; l = l->next)
	{
		user = msn_userlist_find_add_user(session->userlist,
						(char *)l->data,NULL);
		msn_user_set_op(user, MSN_LIST_BL_OP);
	}

}

