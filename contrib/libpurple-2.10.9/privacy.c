/**
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

#include "account.h"
#include "privacy.h"
#include "server.h"
#include "util.h"

static PurplePrivacyUiOps *privacy_ops = NULL;

gboolean
purple_privacy_permit_add(PurpleAccount *account, const char *who,
						gboolean local_only)
{
	GSList *l;
	char *name;
	PurpleBuddy *buddy;
	PurpleBlistUiOps *blist_ops;

	g_return_val_if_fail(account != NULL, FALSE);
	g_return_val_if_fail(who     != NULL, FALSE);

	name = g_strdup(purple_normalize(account, who));

	for (l = account->permit; l != NULL; l = l->next) {
		if (g_str_equal(name, l->data))
			/* This buddy already exists */
			break;
	}

	if (l != NULL)
	{
		/* This buddy already exists, so bail out */
		g_free(name);
		return FALSE;
	}

	account->permit = g_slist_append(account->permit, name);

	if (!local_only && purple_account_is_connected(account))
		serv_add_permit(purple_account_get_connection(account), who);

	if (privacy_ops != NULL && privacy_ops->permit_added != NULL)
		privacy_ops->permit_added(account, who);

	blist_ops = purple_blist_get_ui_ops();
	if (blist_ops != NULL && blist_ops->save_account != NULL)
		blist_ops->save_account(account);

	/* This lets the UI know a buddy has had its privacy setting changed */
	buddy = purple_find_buddy(account, name);
	if (buddy != NULL) {
		purple_signal_emit(purple_blist_get_handle(),
                "buddy-privacy-changed", buddy);
	}
	return TRUE;
}

gboolean
purple_privacy_permit_remove(PurpleAccount *account, const char *who,
						   gboolean local_only)
{
	GSList *l;
	const char *name;
	PurpleBuddy *buddy;
	char *del;
	PurpleBlistUiOps *blist_ops;

	g_return_val_if_fail(account != NULL, FALSE);
	g_return_val_if_fail(who     != NULL, FALSE);

	name = purple_normalize(account, who);

	for (l = account->permit; l != NULL; l = l->next) {
		if (g_str_equal(name, l->data))
			/* We found the buddy we were looking for */
			break;
	}

	if (l == NULL)
		/* We didn't find the buddy we were looking for, so bail out */
		return FALSE;

	/* We should not free l->data just yet. There can be occasions where
	 * l->data == who. In such cases, freeing l->data here can cause crashes
	 * later when who is used. */
	del = l->data;
	account->permit = g_slist_delete_link(account->permit, l);

	if (!local_only && purple_account_is_connected(account))
		serv_rem_permit(purple_account_get_connection(account), who);

	if (privacy_ops != NULL && privacy_ops->permit_removed != NULL)
		privacy_ops->permit_removed(account, who);

	blist_ops = purple_blist_get_ui_ops();
	if (blist_ops != NULL && blist_ops->save_account != NULL)
		blist_ops->save_account(account);

	buddy = purple_find_buddy(account, name);
	if (buddy != NULL) {
		purple_signal_emit(purple_blist_get_handle(),
                "buddy-privacy-changed", buddy);
	}
	g_free(del);
	return TRUE;
}

gboolean
purple_privacy_deny_add(PurpleAccount *account, const char *who,
					  gboolean local_only)
{
	GSList *l;
	char *name;
	PurpleBuddy *buddy;
	PurpleBlistUiOps *blist_ops;

	g_return_val_if_fail(account != NULL, FALSE);
	g_return_val_if_fail(who     != NULL, FALSE);

	name = g_strdup(purple_normalize(account, who));

	for (l = account->deny; l != NULL; l = l->next) {
		if (g_str_equal(name, l->data))
			/* This buddy already exists */
			break;
	}

	if (l != NULL)
	{
		/* This buddy already exists, so bail out */
		g_free(name);
		return FALSE;
	}

	account->deny = g_slist_append(account->deny, name);

	if (!local_only && purple_account_is_connected(account))
		serv_add_deny(purple_account_get_connection(account), who);

	if (privacy_ops != NULL && privacy_ops->deny_added != NULL)
		privacy_ops->deny_added(account, who);

	blist_ops = purple_blist_get_ui_ops();
	if (blist_ops != NULL && blist_ops->save_account != NULL)
		blist_ops->save_account(account);

	buddy = purple_find_buddy(account, name);
	if (buddy != NULL) {
		purple_signal_emit(purple_blist_get_handle(),
                "buddy-privacy-changed", buddy);
	}
	return TRUE;
}

gboolean
purple_privacy_deny_remove(PurpleAccount *account, const char *who,
						 gboolean local_only)
{
	GSList *l;
	const char *normalized;
	char *name;
	PurpleBuddy *buddy;
	PurpleBlistUiOps *blist_ops;

	g_return_val_if_fail(account != NULL, FALSE);
	g_return_val_if_fail(who     != NULL, FALSE);

	normalized = purple_normalize(account, who);

	for (l = account->deny; l != NULL; l = l->next) {
		if (g_str_equal(normalized, l->data))
			/* We found the buddy we were looking for */
			break;
	}

	if (l == NULL)
		/* We didn't find the buddy we were looking for, so bail out */
		return FALSE;

	buddy = purple_find_buddy(account, normalized);

	name = l->data;
	account->deny = g_slist_delete_link(account->deny, l);

	if (!local_only && purple_account_is_connected(account))
		serv_rem_deny(purple_account_get_connection(account), name);

	if (privacy_ops != NULL && privacy_ops->deny_removed != NULL)
		privacy_ops->deny_removed(account, who);

	if (buddy != NULL) {
		purple_signal_emit(purple_blist_get_handle(),
                "buddy-privacy-changed", buddy);
	}

	g_free(name);

	blist_ops = purple_blist_get_ui_ops();
	if (blist_ops != NULL && blist_ops->save_account != NULL)
		blist_ops->save_account(account);

	return TRUE;
}

/**
 * This makes sure your permit list contains all buddies from your
 * buddy list and ONLY buddies from your buddy list.
 */
static void
add_all_buddies_to_permit_list(PurpleAccount *account, gboolean local)
{
	GSList *list;

	/* Remove anyone in the permit list who is not in the buddylist */
	for (list = account->permit; list != NULL; ) {
		char *person = list->data;
		list = list->next;
		if (!purple_find_buddy(account, person))
			purple_privacy_permit_remove(account, person, local);
	}

	/* Now make sure everyone in the buddylist is in the permit list */
	list = purple_find_buddies(account, NULL);
	while (list != NULL)
	{
		PurpleBuddy *buddy = list->data;
		const gchar *name = purple_buddy_get_name(buddy);

		if (!g_slist_find_custom(account->permit, name, (GCompareFunc)g_utf8_collate))
			purple_privacy_permit_add(account, name, local);
		list = g_slist_delete_link(list, list);
	}
}

/*
 * TODO: All callers of this function pass in FALSE for local and
 *       restore and I don't understand when you would ever want to
 *       use TRUE for either of them.  I think both parameters could
 *       safely be removed in the next major version bump.
 */
void
purple_privacy_allow(PurpleAccount *account, const char *who, gboolean local,
						gboolean restore)
{
	GSList *list;
	PurplePrivacyType type = account->perm_deny;

	switch (account->perm_deny) {
		case PURPLE_PRIVACY_ALLOW_ALL:
			return;
		case PURPLE_PRIVACY_ALLOW_USERS:
			purple_privacy_permit_add(account, who, local);
			break;
		case PURPLE_PRIVACY_DENY_USERS:
			purple_privacy_deny_remove(account, who, local);
			break;
		case PURPLE_PRIVACY_DENY_ALL:
			if (!restore) {
				/* Empty the allow-list. */
				const char *norm = purple_normalize(account, who);
				for (list = account->permit; list != NULL;) {
					char *person = list->data;
					list = list->next;
					if (!purple_strequal(norm, person))
						purple_privacy_permit_remove(account, person, local);
				}
			}
			purple_privacy_permit_add(account, who, local);
			account->perm_deny = PURPLE_PRIVACY_ALLOW_USERS;
			break;
		case PURPLE_PRIVACY_ALLOW_BUDDYLIST:
			if (!purple_find_buddy(account, who)) {
				add_all_buddies_to_permit_list(account, local);
				purple_privacy_permit_add(account, who, local);
				account->perm_deny = PURPLE_PRIVACY_ALLOW_USERS;
			}
			break;
		default:
			g_return_if_reached();
	}

	/* Notify the server if the privacy setting was changed */
	if (type != account->perm_deny && purple_account_is_connected(account))
		serv_set_permit_deny(purple_account_get_connection(account));
}

/*
 * TODO: All callers of this function pass in FALSE for local and
 *       restore and I don't understand when you would ever want to
 *       use TRUE for either of them.  I think both parameters could
 *       safely be removed in the next major version bump.
 */
void
purple_privacy_deny(PurpleAccount *account, const char *who, gboolean local,
					gboolean restore)
{
	GSList *list;
	PurplePrivacyType type = account->perm_deny;

	switch (account->perm_deny) {
		case PURPLE_PRIVACY_ALLOW_ALL:
			if (!restore) {
				/* Empty the deny-list. */
				const char *norm = purple_normalize(account, who);
				for (list = account->deny; list != NULL; ) {
					char *person = list->data;
					list = list->next;
					if (!purple_strequal(norm, person))
						purple_privacy_deny_remove(account, person, local);
				}
			}
			purple_privacy_deny_add(account, who, local);
			account->perm_deny = PURPLE_PRIVACY_DENY_USERS;
			break;
		case PURPLE_PRIVACY_ALLOW_USERS:
			purple_privacy_permit_remove(account, who, local);
			break;
		case PURPLE_PRIVACY_DENY_USERS:
			purple_privacy_deny_add(account, who, local);
			break;
		case PURPLE_PRIVACY_DENY_ALL:
			break;
		case PURPLE_PRIVACY_ALLOW_BUDDYLIST:
			if (purple_find_buddy(account, who)) {
				add_all_buddies_to_permit_list(account, local);
				purple_privacy_permit_remove(account, who, local);
				account->perm_deny = PURPLE_PRIVACY_ALLOW_USERS;
			}
			break;
		default:
			g_return_if_reached();
	}

	/* Notify the server if the privacy setting was changed */
	if (type != account->perm_deny && purple_account_is_connected(account))
		serv_set_permit_deny(purple_account_get_connection(account));
}

gboolean
purple_privacy_check(PurpleAccount *account, const char *who)
{
	GSList *list;

	switch (account->perm_deny) {
		case PURPLE_PRIVACY_ALLOW_ALL:
			return TRUE;

		case PURPLE_PRIVACY_DENY_ALL:
			return FALSE;

		case PURPLE_PRIVACY_ALLOW_USERS:
			who = purple_normalize(account, who);
			for (list=account->permit; list!=NULL; list=list->next) {
				if (g_str_equal(who, list->data))
					return TRUE;
			}
			return FALSE;

		case PURPLE_PRIVACY_DENY_USERS:
			who = purple_normalize(account, who);
			for (list=account->deny; list!=NULL; list=list->next) {
				if (g_str_equal(who, list->data))
					return FALSE;
			}
			return TRUE;

		case PURPLE_PRIVACY_ALLOW_BUDDYLIST:
			return (purple_find_buddy(account, who) != NULL);

		default:
			g_return_val_if_reached(TRUE);
	}
}

void
purple_privacy_set_ui_ops(PurplePrivacyUiOps *ops)
{
	privacy_ops = ops;
}

PurplePrivacyUiOps *
purple_privacy_get_ui_ops(void)
{
	return privacy_ops;
}

void
purple_privacy_init(void)
{
}
