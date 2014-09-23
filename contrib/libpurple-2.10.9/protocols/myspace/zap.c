/* MySpaceIM Protocol Plugin - zap support
 *
 * Copyright (C) 2007, Jeff Connelly <jeff2@soc.pidgin.im>
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

#include "myspace.h"
#include "zap.h"

/** Get zap types. */
GList *
msim_attention_types(PurpleAccount *acct)
{
	static GList *types = NULL;
	PurpleAttentionType* attn;

	if (!types) {
#define _MSIM_ADD_NEW_ATTENTION(icn, ulname, nme, incoming, outgoing) \
		attn = purple_attention_type_new(ulname, nme, incoming, outgoing); \
		purple_attention_type_set_icon_name(attn, icn); \
		types = g_list_append(types, attn);

		/* TODO: icons for each zap */

		/* Lots of comments for translators: */

		/* Zap means "to strike suddenly and forcefully as if with a
		 * projectile or weapon."  This term often has an electrical
		 * connotation, for example, "he was zapped by electricity when
		 * he put a fork in the toaster." */
		_MSIM_ADD_NEW_ATTENTION(NULL, "Zap", _("Zap"), _("%s has zapped you!"),
				_("Zapping %s..."));

		/* Whack means "to hit or strike someone with a sharp blow" */
		_MSIM_ADD_NEW_ATTENTION(NULL, "Whack", _("Whack"),
				_("%s has whacked you!"), _("Whacking %s..."));

		/* Torch means "to set on fire."  Don't worry, this doesn't
		 * make a whole lot of sense in English, either.  Feel free
		 * to translate it literally. */
		_MSIM_ADD_NEW_ATTENTION(NULL, "Torch", _("Torch"),
				_("%s has torched you!"), _("Torching %s..."));

		/* Smooch means "to kiss someone, often enthusiastically" */
		_MSIM_ADD_NEW_ATTENTION(NULL, "Smooch", _("Smooch"),
				_("%s has smooched you!"), _("Smooching %s..."));

		/* A hug is a display of affection; wrapping your arms around someone */
		_MSIM_ADD_NEW_ATTENTION(NULL, "Hug", _("Hug"), _("%s has hugged you!"),
				_("Hugging %s..."));

		/* Slap means "to hit someone with an open/flat hand" */
		_MSIM_ADD_NEW_ATTENTION(NULL, "Slap", _("Slap"),
				_("%s has slapped you!"), _("Slapping %s..."));

		/* Goose means "to pinch someone on their butt" */
		_MSIM_ADD_NEW_ATTENTION(NULL, "Goose", _("Goose"),
				_("%s has goosed you!"), _("Goosing %s..."));

		/* A high-five is when two people's hands slap each other
		 * in the air above their heads.  It is done to celebrate
		 * something, often a victory, or to congratulate someone. */
		_MSIM_ADD_NEW_ATTENTION(NULL, "High-five", _("High-five"),
				_("%s has high-fived you!"), _("High-fiving %s..."));

		/* We're not entirely sure what the MySpace people mean by
		 * this... but we think it's the equivalent of "prank."  Or, for
		 * someone to perform a mischievous trick or practical joke. */
		_MSIM_ADD_NEW_ATTENTION(NULL, "Punk", _("Punk"),
				_("%s has punk'd you!"), _("Punking %s..."));

		/* Raspberry is a slang term for the vibrating sound made
		 * when you stick your tongue out of your mouth with your
		 * lips closed and blow.  It is typically done when
		 * gloating or bragging.  Nowadays it's a pretty silly
		 * gesture, so it does not carry a harsh negative
		 * connotation.  It is generally used in a playful tone
		 * with friends. */
		_MSIM_ADD_NEW_ATTENTION(NULL, "Raspberry", _("Raspberry"),
				_("%s has raspberried you!"), _("Raspberrying %s..."));
	}

	return types;
}

/** Send a zap to a user. */
static gboolean
msim_send_zap(MsimSession *session, const gchar *username, guint code)
{
	gchar *zap_string;
	gboolean rc;

	g_return_val_if_fail(session != NULL, FALSE);
	g_return_val_if_fail(username != NULL, FALSE);

	/* Construct and send the actual zap command. */
	zap_string = g_strdup_printf("!!!ZAP_SEND!!!=RTE_BTN_ZAPS_%d", code);

	if (!msim_send_bm(session, username, zap_string, MSIM_BM_ACTION_OR_IM_INSTANT)) {
		purple_debug_info("msim_send_zap",
				"msim_send_bm failed: zapping %s with %s\n",
				username, zap_string);
		rc = FALSE;
	} else {
		rc = TRUE;
	}

	g_free(zap_string);

	return rc;
}

/** Send a zap */
gboolean
msim_send_attention(PurpleConnection *gc, const gchar *username, guint code)
{
	GList *types;
	MsimSession *session;
	PurpleAttentionType *attn;
	PurpleBuddy *buddy;

	session = (MsimSession *)gc->proto_data;

	/* Look for this attention type, by the code index given. */
	types = msim_attention_types(gc->account);
	attn = (PurpleAttentionType *)g_list_nth_data(types, code);

	if (!attn) {
		purple_debug_info("msim_send_attention", "got invalid zap code %d\n", code);
		return FALSE;
	}

	buddy = purple_find_buddy(session->account, username);
	if (!buddy) {
		return FALSE;
	}

	msim_send_zap(session, username, code);

	return TRUE;
}

/** Zap someone. Callback from msim_blist_node_menu zap menu. */
static void
msim_send_zap_from_menu(PurpleBlistNode *node, gpointer zap_num_ptr)
{
	PurpleBuddy *buddy;
	PurpleAccount *account;
	PurpleConnection *gc;
	MsimSession *session;
	guint zap;

	if (!PURPLE_BLIST_NODE_IS_BUDDY(node)) {
		/* Only know about buddies for now. */
		return;
	}

	g_return_if_fail(PURPLE_BLIST_NODE_IS_BUDDY(node));

	buddy = (PurpleBuddy *)node;

	/* Find the session */
	account = purple_buddy_get_account(buddy);
	gc = purple_account_get_connection(account);
	session = (MsimSession *)gc->proto_data;

	zap = GPOINTER_TO_INT(zap_num_ptr);

	purple_prpl_send_attention(session->gc, purple_buddy_get_name(buddy), zap);
}

/** Return menu, if any, for a buddy list node. */
GList *
msim_blist_node_menu(PurpleBlistNode *node)
{
	GList *menu, *zap_menu;
	GList *types;
	PurpleMenuAction *act;
	guint i;

	if (!PURPLE_BLIST_NODE_IS_BUDDY(node)) {
		/* Only know about buddies for now. */
		return NULL;
	}

	zap_menu = NULL;

	/* TODO: get rid of once is accessible directly in GUI */
	types = msim_attention_types(NULL);
	i = 0;
	do
	{
		PurpleAttentionType *attn;

		attn = (PurpleAttentionType *)types->data;

		act = purple_menu_action_new(purple_attention_type_get_name(attn),
				PURPLE_CALLBACK(msim_send_zap_from_menu), GUINT_TO_POINTER(i), NULL);
		zap_menu = g_list_append(zap_menu, act);

		++i;
	} while ((types = g_list_next(types)));

	act = purple_menu_action_new(_("Zap"), NULL, NULL, zap_menu);
	menu = g_list_append(NULL, act);

	return menu;
}

/** Process an incoming zap. */
gboolean
msim_incoming_zap(MsimSession *session, MsimMessage *msg)
{
	gchar *msg_text, *username;
	gint zap;

	msg_text = msim_msg_get_string(msg, "msg");
	username = msim_msg_get_string(msg, "_username");

	g_return_val_if_fail(msg_text != NULL, FALSE);
	g_return_val_if_fail(username != NULL, FALSE);

	g_return_val_if_fail(sscanf(msg_text, "!!!ZAP_SEND!!!=RTE_BTN_ZAPS_%d", &zap) == 1, FALSE);

	zap = CLAMP(zap, 0, 9);

	purple_prpl_got_attention(session->gc, username, zap);

	g_free(msg_text);
	g_free(username);

	return TRUE;
}
