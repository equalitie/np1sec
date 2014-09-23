/*
 * Signals test plugin.
 *
 * Copyright (C) 2003 Christian Hammond.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02111-1301, USA.
 */
#define SIGNAL_TEST_PLUGIN_ID "core-signals-test"

#include "internal.h"

#include <stdio.h>

#include "cipher.h"
#include "connection.h"
#include "conversation.h"
#include "core.h"
#include "debug.h"
#include "ft.h"
#include "signals.h"
#include "version.h"
#include "status.h"
#include "sound.h"

/**************************************************************************
 * Account subsystem signal callbacks
 **************************************************************************/
static void
account_connecting_cb(PurpleAccount *account, void *data)
{
	purple_debug_misc("signals test", "account-connecting (%s)\n",
					purple_account_get_username(account));
}

static void
account_setting_info_cb(PurpleAccount *account, const char *info, void *data)
{
	purple_debug_misc("signals test", "account-setting-info (%s, %s)\n",
					purple_account_get_username(account), info);
}

static void
account_set_info_cb(PurpleAccount *account, const char *info, void *data)
{
	purple_debug_misc("signals test", "account-set-info (%s, %s)\n",
					purple_account_get_username(account), info);
}

static void
account_status_changed(PurpleAccount *account, PurpleStatus *old, PurpleStatus *new,
						gpointer data)
{
	purple_debug_misc("signals test", "account-status-changed (%s, %s, %s)\n",
					purple_account_get_username(account),
					purple_status_get_name(old),
					purple_status_get_name(new));
}

static void
account_alias_changed(PurpleAccount *account, const char *old, gpointer data)
{
	purple_debug_misc("signals test", "account-alias-changed (%s, %s, %s)\n",
					purple_account_get_username(account),
					old, purple_account_get_alias(account));
}

static int
account_authorization_requested_cb(PurpleAccount *account, const char *user, gpointer data)
{
	purple_debug_misc("signals test", "account-authorization-requested (%s, %s)\n",
			purple_account_get_username(account), user);
	return 0;
}

static void
account_authorization_granted_cb(PurpleAccount *account, const char *user, gpointer data)
{
	purple_debug_misc("signals test", "account-authorization-granted (%s, %s)\n",
			purple_account_get_username(account), user);
}

static void
account_authorization_denied_cb(PurpleAccount *account, const char *user, gpointer data)
{
	purple_debug_misc("signals test", "account-authorization-denied (%s, %s)\n",
			purple_account_get_username(account), user);
}

/**************************************************************************
 * Buddy Icons signal callbacks
 **************************************************************************/
static void
buddy_icon_changed_cb(PurpleBuddy *buddy)
{
	purple_debug_misc("signals test", "buddy icon changed (%s)\n",
					purple_buddy_get_name(buddy));
}

/**************************************************************************
 * Buddy List subsystem signal callbacks
 **************************************************************************/
static void
buddy_status_changed_cb(PurpleBuddy *buddy, PurpleStatus *old_status,
                        PurpleStatus *status, void *data)
{
	purple_debug_misc("signals test", "buddy-status-changed (%s %s to %s)\n",
	                  purple_buddy_get_name(buddy),
	                  purple_status_get_id(old_status),
	                  purple_status_get_id(status));
}

static void
buddy_idle_changed_cb(PurpleBuddy *buddy, gboolean old_idle, gboolean idle,
                      void *data)
{
	purple_debug_misc("signals test", "buddy-idle-changed (%s %s)\n",
	                  purple_buddy_get_name(buddy),
	                  old_idle ? "unidled" : "idled");
}

static void
buddy_signed_on_cb(PurpleBuddy *buddy, void *data)
{
	purple_debug_misc("signals test", "buddy-signed-on (%s)\n",
	                  purple_buddy_get_name(buddy));
}

static void
buddy_signed_off_cb(PurpleBuddy *buddy, void *data)
{
	purple_debug_misc("signals test", "buddy-signed-off (%s)\n",
	                  purple_buddy_get_name(buddy));
}

static void
blist_node_added_cb(PurpleBlistNode *bnode, void *data)
{
	const char *name;
	if (PURPLE_BLIST_NODE_IS_GROUP(bnode))
		name = purple_group_get_name(PURPLE_GROUP(bnode));
	else if (PURPLE_BLIST_NODE_IS_CONTACT(bnode))
		/* Close enough */
		name = purple_contact_get_alias(PURPLE_CONTACT(bnode));
	else if (PURPLE_BLIST_NODE_IS_BUDDY(bnode))
		name = purple_buddy_get_name(PURPLE_BUDDY(bnode));
	else
		name = "(unknown)";

	purple_debug_misc("signals test", "blist_node_added_cb (%s)\n",
	                  name ? name : "(null)");
}

static void
blist_node_removed_cb(PurpleBlistNode *bnode, void *data)
{
	const char *name;
	if (PURPLE_BLIST_NODE_IS_GROUP(bnode))
		name = purple_group_get_name(PURPLE_GROUP(bnode));
	else if (PURPLE_BLIST_NODE_IS_CONTACT(bnode))
		/* Close enough */
		name = purple_contact_get_alias(PURPLE_CONTACT(bnode));
	else if (PURPLE_BLIST_NODE_IS_BUDDY(bnode))
		name = purple_buddy_get_name(PURPLE_BUDDY(bnode));
	else
		name = "(unknown)";

	purple_debug_misc("signals test", "blist_node_removed_cb (%s)\n",
	                  name ? name : "(null)");
}

static void
blist_node_aliased(PurpleBlistNode *node, const char *old_alias)
{
	PurpleContact *p = (PurpleContact *)node;
	PurpleBuddy *b = (PurpleBuddy *)node;
	PurpleChat *c = (PurpleChat *)node;
	PurpleGroup *g = (PurpleGroup *)node;

	if (PURPLE_BLIST_NODE_IS_CONTACT(node)) {
		purple_debug_misc("signals test",
		                  "blist-node-aliased (Contact: %s, %s)\n",
		                  purple_contact_get_alias(p), old_alias);
	} else if (PURPLE_BLIST_NODE_IS_BUDDY(node)) {
		purple_debug_misc("signals test",
		                  "blist-node-aliased (Buddy: %s, %s)\n",
		                  purple_buddy_get_name(b), old_alias);
	} else if (PURPLE_BLIST_NODE_IS_CHAT(node)) {
		purple_debug_misc("signals test",
		                  "blist-node-aliased (Chat: %s, %s)\n",
		                  purple_chat_get_name(c), old_alias);
	} else if (PURPLE_BLIST_NODE_IS_GROUP(node)) {
		purple_debug_misc("signals test",
		                  "blist-node-aliased (Group: %s, %s)\n",
		                  purple_group_get_name(g), old_alias);
	} else {
		purple_debug_misc("signals test",
		                  "blist-node-aliased (UNKNOWN: %d, %s)\n",
		                  purple_blist_node_get_type(node), old_alias);
	}
}

static void
blist_node_extended_menu_cb(PurpleBlistNode *node, void *data)
{
	PurpleContact *p = (PurpleContact *)node;
	PurpleBuddy *b = (PurpleBuddy *)node;
	PurpleChat *c = (PurpleChat *)node;
	PurpleGroup *g = (PurpleGroup *)node;

	if (PURPLE_BLIST_NODE_IS_CONTACT(node)) {
		purple_debug_misc("signals test",
		                  "blist-node-extended-menu (Contact: %s)\n",
		                  purple_contact_get_alias(p));
	} else if (PURPLE_BLIST_NODE_IS_BUDDY(node)) {
		purple_debug_misc("signals test",
		                  "blist-node-extended-menu (Buddy: %s)\n",
		                  purple_buddy_get_name(b));
	} else if (PURPLE_BLIST_NODE_IS_CHAT(node)) {
		purple_debug_misc("signals test",
		                  "blist-node-extended-menu (Chat: %s)\n",
		                  purple_chat_get_name(c));
	} else if (PURPLE_BLIST_NODE_IS_GROUP(node)) {
		purple_debug_misc("signals test",
		                  "blist-node-extended-menu (Group: %s)\n",
		                  purple_group_get_name(g));
	} else {
		purple_debug_misc("signals test",
		                  "blist-node-extended-menu (UNKNOWN: %d)\n",
		                  purple_blist_node_get_type(node));
	}
}


/**************************************************************************
 * Connection subsystem signal callbacks
 **************************************************************************/
static void
signing_on_cb(PurpleConnection *gc, void *data)
{
	purple_debug_misc("signals test", "signing-on (%s)\n",
					purple_account_get_username(purple_connection_get_account(gc)));
}

static void
signed_on_cb(PurpleConnection *gc, void *data)
{
	purple_debug_misc("signals test", "signed-on (%s)\n",
					purple_account_get_username(purple_connection_get_account(gc)));
}

static void
signing_off_cb(PurpleConnection *gc, void *data)
{
	purple_debug_misc("signals test", "signing-off (%s)\n",
					purple_account_get_username(purple_connection_get_account(gc)));
}

static void
signed_off_cb(PurpleConnection *gc, void *data)
{
	purple_debug_misc("signals test", "signed-off (%s)\n",
					purple_account_get_username(purple_connection_get_account(gc)));
}

static void
connection_error_cb(PurpleConnection *gc,
                    PurpleConnectionError err,
                    const gchar *desc,
                    void *data)
{
	const gchar *username =
		purple_account_get_username(purple_connection_get_account(gc));
	purple_debug_misc("signals test", "connection-error (%s, %u, %s)\n",
		username, err, desc);
}

/**************************************************************************
 * Conversation subsystem signal callbacks
 **************************************************************************/
static gboolean
writing_im_msg_cb(PurpleAccount *account, const char *who, char **buffer,
				PurpleConversation *conv, PurpleMessageFlags flags, void *data)
{
	purple_debug_misc("signals test", "writing-im-msg (%s, %s, %s)\n",
					purple_account_get_username(account), purple_conversation_get_name(conv), *buffer);

	return FALSE;

}

static void
wrote_im_msg_cb(PurpleAccount *account, const char *who, const char *buffer,
				PurpleConversation *conv, PurpleMessageFlags flags, void *data)
{
	purple_debug_misc("signals test", "wrote-im-msg (%s, %s, %s)\n",
					purple_account_get_username(account), purple_conversation_get_name(conv), buffer);
}

static void
sending_im_msg_cb(PurpleAccount *account, char *recipient, char **buffer, void *data)
{
	purple_debug_misc("signals test", "sending-im-msg (%s, %s, %s)\n",
					purple_account_get_username(account), recipient, *buffer);

}

static void
sent_im_msg_cb(PurpleAccount *account, const char *recipient, const char *buffer, void *data)
{
	purple_debug_misc("signals test", "sent-im-msg (%s, %s, %s)\n",
					purple_account_get_username(account), recipient, buffer);
}

static gboolean
receiving_im_msg_cb(PurpleAccount *account, char **sender, char **buffer,
				    PurpleConversation *conv, PurpleMessageFlags *flags, void *data)
{
	purple_debug_misc("signals test", "receiving-im-msg (%s, %s, %s, %s, %d)\n",
					purple_account_get_username(account), *sender, *buffer,
					(conv != NULL) ? purple_conversation_get_name(conv) : "(null)", *flags);

	return FALSE;
}

static void
received_im_msg_cb(PurpleAccount *account, char *sender, char *buffer,
				   PurpleConversation *conv, PurpleMessageFlags flags, void *data)
{
	purple_debug_misc("signals test", "received-im-msg (%s, %s, %s, %s, %d)\n",
					purple_account_get_username(account), sender, buffer,
					(conv != NULL) ? purple_conversation_get_name(conv) : "(null)", flags);
}

static gboolean
writing_chat_msg_cb(PurpleAccount *account, const char *who, char **buffer,
				PurpleConversation *conv, PurpleMessageFlags flags, void *data)
{
	purple_debug_misc("signals test", "writing-chat-msg (%s, %s)\n",
					purple_conversation_get_name(conv), *buffer);

	return FALSE;
}

static void
wrote_chat_msg_cb(PurpleAccount *account, const char *who, const char *buffer,
				PurpleConversation *conv, PurpleMessageFlags flags, void *data)
{
	purple_debug_misc("signals test", "wrote-chat-msg (%s, %s)\n",
					purple_conversation_get_name(conv), buffer);
}

static gboolean
sending_chat_msg_cb(PurpleAccount *account, char **buffer, int id, void *data)
{
	purple_debug_misc("signals test", "sending-chat-msg (%s, %s, %d)\n",
					purple_account_get_username(account), *buffer, id);

	return FALSE;
}

static void
sent_chat_msg_cb(PurpleAccount *account, const char *buffer, int id, void *data)
{
	purple_debug_misc("signals test", "sent-chat-msg (%s, %s, %d)\n",
					purple_account_get_username(account), buffer, id);
}

static gboolean
receiving_chat_msg_cb(PurpleAccount *account, char **sender, char **buffer,
					 PurpleConversation *chat, PurpleMessageFlags *flags, void *data)
{
	purple_debug_misc("signals test",
					"receiving-chat-msg (%s, %s, %s, %s, %d)\n",
					purple_account_get_username(account), *sender, *buffer,
					purple_conversation_get_name(chat), *flags);

	return FALSE;
}

static void
received_chat_msg_cb(PurpleAccount *account, char *sender, char *buffer,
					 PurpleConversation *chat, PurpleMessageFlags flags, void *data)
{
	purple_debug_misc("signals test",
					"received-chat-msg (%s, %s, %s, %s, %d)\n",
					purple_account_get_username(account), sender, buffer,
					purple_conversation_get_name(chat), flags);
}

static void
conversation_created_cb(PurpleConversation *conv, void *data)
{
	purple_debug_misc("signals test", "conversation-created (%s)\n",
					purple_conversation_get_name(conv));
}

static void
deleting_conversation_cb(PurpleConversation *conv, void *data)
{
	purple_debug_misc("signals test", "deleting-conversation (%s)\n",
					purple_conversation_get_name(conv));
}

static void
buddy_typing_cb(PurpleAccount *account, const char *name, void *data)
{
	purple_debug_misc("signals test", "buddy-typing (%s, %s)\n",
					purple_account_get_username(account), name);
}

static void
buddy_typing_stopped_cb(PurpleAccount *account, const char *name, void *data)
{
	purple_debug_misc("signals test", "buddy-typing-stopped (%s, %s)\n",
					purple_account_get_username(account), name);
}

static gboolean
chat_buddy_joining_cb(PurpleConversation *conv, const char *user,
					  PurpleConvChatBuddyFlags flags, void *data)
{
	purple_debug_misc("signals test", "chat-buddy-joining (%s, %s, %d)\n",
					purple_conversation_get_name(conv), user, flags);

	return FALSE;
}

static void
chat_buddy_joined_cb(PurpleConversation *conv, const char *user,
					 PurpleConvChatBuddyFlags flags, gboolean new_arrival, void *data)
{
	purple_debug_misc("signals test", "chat-buddy-joined (%s, %s, %d, %d)\n",
					purple_conversation_get_name(conv), user, flags, new_arrival);
}

static void
chat_buddy_flags_cb(PurpleConversation *conv, const char *user,
					PurpleConvChatBuddyFlags oldflags, PurpleConvChatBuddyFlags newflags, void *data)
{
	purple_debug_misc("signals test", "chat-buddy-flags (%s, %s, %d, %d)\n",
					purple_conversation_get_name(conv), user, oldflags, newflags);
}

static gboolean
chat_buddy_leaving_cb(PurpleConversation *conv, const char *user,
					  const char *reason, void *data)
{
	purple_debug_misc("signals test", "chat-buddy-leaving (%s, %s, %s)\n",
					purple_conversation_get_name(conv), user, reason);

	return FALSE;
}

static void
chat_buddy_left_cb(PurpleConversation *conv, const char *user,
				   const char *reason, void *data)
{
	purple_debug_misc("signals test", "chat-buddy-left (%s, %s, %s)\n",
					purple_conversation_get_name(conv), user, reason);
}

static void
chat_inviting_user_cb(PurpleConversation *conv, const char *name,
					  char **reason, void *data)
{
	purple_debug_misc("signals test", "chat-inviting-user (%s, %s, %s)\n",
					purple_conversation_get_name(conv), name, *reason);
}

static void
chat_invited_user_cb(PurpleConversation *conv, const char *name,
					  const char *reason, void *data)
{
	purple_debug_misc("signals test", "chat-invited-user (%s, %s, %s)\n",
					purple_conversation_get_name(conv), name, reason);
}

static gint
chat_invited_cb(PurpleAccount *account, const char *inviter,
				const char *room_name, const char *message,
				const GHashTable *components, void *data)
{
	purple_debug_misc("signals test", "chat-invited (%s, %s, %s, %s)\n",
					purple_account_get_username(account), inviter,
					room_name, message);

	return 0;
}

static void
chat_joined_cb(PurpleConversation *conv, void *data)
{
	purple_debug_misc("signals test", "chat-joined (%s)\n",
					purple_conversation_get_name(conv));
}

static void
chat_left_cb(PurpleConversation *conv, void *data)
{
	purple_debug_misc("signals test", "chat-left (%s)\n",
					purple_conversation_get_name(conv));
}

static void
chat_topic_changed_cb(PurpleConversation *conv, const char *who,
					  const char *topic, void *data)
{
	purple_debug_misc("signals test",
					"chat-topic-changed (%s topic changed to: \"%s\" by %s)\n",
					purple_conversation_get_name(conv), topic,
					(who) ? who : "unknown");
}
/**************************************************************************
 * Ciphers signal callbacks
 **************************************************************************/
static void
cipher_added_cb(PurpleCipher *cipher, void *data) {
	purple_debug_misc("signals test", "cipher %s added\n",
					purple_cipher_get_name(cipher));
}

static void
cipher_removed_cb(PurpleCipher *cipher, void *data) {
	purple_debug_misc("signals test", "cipher %s removed\n",
					purple_cipher_get_name(cipher));
}

/**************************************************************************
 * Core signal callbacks
 **************************************************************************/
static void
quitting_cb(void *data)
{
	purple_debug_misc("signals test", "quitting ()\n");
}

static void
printhash(gpointer key, gpointer value, gpointer data)
{
	char *a = (char *)key;
	char *b = (char *)value;
	GString *str = (GString *)data;
	g_string_append_printf(str, "   [%s] = [%s]\n", a, b ? b : "(null)");
}

static gboolean
uri_handler(const char *proto, const char *cmd, GHashTable *params)
{
	GString *str = g_string_new("\n{\n");
	g_hash_table_foreach(params, printhash, str);
	g_string_append_c(str, '}');
	purple_debug_misc("signals test", "uri handler (%s, %s, %s)\n", proto, cmd, str->str);
	g_string_free(str, TRUE);
	return FALSE;
}

/**************************************************************************
 * File transfer signal callbacks
 **************************************************************************/
static void
ft_recv_accept_cb(PurpleXfer *xfer, gpointer data) {
	purple_debug_misc("signals test", "file receive accepted\n");
}

static void
ft_send_accept_cb(PurpleXfer *xfer, gpointer data) {
	purple_debug_misc("signals test", "file send accepted\n");
}

static void
ft_recv_start_cb(PurpleXfer *xfer, gpointer data) {
	purple_debug_misc("signals test", "file receive started\n");
}

static void
ft_send_start_cb(PurpleXfer *xfer, gpointer data) {
	purple_debug_misc("signals test", "file send started\n");
}

static void
ft_recv_cancel_cb(PurpleXfer *xfer, gpointer data) {
	purple_debug_misc("signals test", "file receive cancelled\n");
}

static void
ft_send_cancel_cb(PurpleXfer *xfer, gpointer data) {
	purple_debug_misc("signals test", "file send cancelled\n");
}

static void
ft_recv_complete_cb(PurpleXfer *xfer, gpointer data) {
	purple_debug_misc("signals test", "file receive completed\n");
}

static void
ft_send_complete_cb(PurpleXfer *xfer, gpointer data) {
	purple_debug_misc("signals test", "file send completed\n");
}

/**************************************************************************
 * Sound signal callbacks
 **************************************************************************/
static int
sound_playing_event_cb(PurpleSoundEventID event, const PurpleAccount *account) {
	if (account != NULL)
		purple_debug_misc("signals test", "sound playing event: %d for account: %s\n",
	    	            event, purple_account_get_username(account));
	else
		purple_debug_misc("signals test", "sound playing event: %d\n", event);

	return 0;
}

/**************************************************************************
 * Notify signals callbacks
 **************************************************************************/
static void
notify_email_cb(char *subject, char *from, char *to, char *url) {
	purple_debug_misc("signals test", "notify email: subject=%s, from=%s, to=%s, url=%s\n",
					subject, from, to, url);
}

static void
notify_emails_cb(char **subjects, char **froms, char **tos, char **urls, guint count) {
	int i;
	purple_debug_misc("signals test", "notify emails: count=%d\n", count);
	for(i=0; i<count && i<5; i++) {
		if(subjects[i]==NULL || froms[i]==NULL || tos[i]==NULL || urls[i]==NULL) continue;
		purple_debug_misc("signals test", "notify emails[%d]: subject=%s, from=%s, to=%s, url=%s\n",
			i, subjects[i], froms[i], tos[i], urls[i]);
	}
}

/**************************************************************************
 * Jabber signals callbacks
 **************************************************************************/
static gboolean
jabber_iq_received(PurpleConnection *pc, const char *type, const char *id,
                   const char *from, xmlnode *iq)
{
	purple_debug_misc("signals test", "jabber IQ (type=%s, id=%s, from=%s) %p\n",
	                  type, id, from ? from : "(null)", iq);

	/* We don't want the plugin to stop processing */
	return FALSE;
}

static gboolean
jabber_message_received(PurpleConnection *pc, const char *type, const char *id,
                        const char *from, const char *to, xmlnode *message)
{
	purple_debug_misc("signals test", "jabber message (type=%s, id=%s, "
	                  "from=%s to=%s) %p\n",
	                  type ? type : "(null)", id ? id : "(null)",
	                  from ? from : "(null)", to ? to : "(null)", message);

	/* We don't want the plugin to stop processing */
	return FALSE;
}

static gboolean
jabber_presence_received(PurpleConnection *pc, const char *type,
                         const char *from, xmlnode *presence)
{
	purple_debug_misc("signals test", "jabber presence (type=%s, from=%s) %p\n",
	                  type ? type : "(null)", from ? from : "(null)", presence);

	/* We don't want the plugin to stop processing */
	return FALSE;
}

static gboolean
jabber_watched_iq(PurpleConnection *pc, const char *type, const char *id,
                  const char *from, xmlnode *child)
{
	purple_debug_misc("signals test", "jabber watched IQ (type=%s, id=%s, from=%s)\n"
	                  "child %p name=%s, namespace=%s\n",
	                  type, id, from, child, child->name,
	                  xmlnode_get_namespace(child));

	if (g_str_equal(type, "get") || g_str_equal(type, "set")) {
		/* Send the requisite reply */
		xmlnode *iq = xmlnode_new("iq");
		xmlnode_set_attrib(iq, "to", from);
		xmlnode_set_attrib(iq, "id", id);
		xmlnode_set_attrib(iq, "type", "result");

		purple_signal_emit(purple_connection_get_prpl(pc),
		                   "jabber-sending-xmlnode", pc, &iq);
		if (iq != NULL)
			xmlnode_free(iq);
	}

	/* Cookie monster eats IQ stanzas; the prpl shouldn't keep processing */
	return TRUE;
}

/**************************************************************************
 * Plugin stuff
 **************************************************************************/
static gboolean
plugin_load(PurplePlugin *plugin)
{
	void *core_handle     = purple_get_core();
	void *blist_handle    = purple_blist_get_handle();
	void *conn_handle     = purple_connections_get_handle();
	void *conv_handle     = purple_conversations_get_handle();
	void *accounts_handle = purple_accounts_get_handle();
	void *ciphers_handle  = purple_ciphers_get_handle();
	void *ft_handle       = purple_xfers_get_handle();
	void *sound_handle    = purple_sounds_get_handle();
	void *notify_handle   = purple_notify_get_handle();
	void *jabber_handle   = purple_plugins_find_with_id("prpl-jabber");

	/* Accounts subsystem signals */
	purple_signal_connect(accounts_handle, "account-connecting",
						plugin, PURPLE_CALLBACK(account_connecting_cb), NULL);
	purple_signal_connect(accounts_handle, "account-setting-info",
						plugin, PURPLE_CALLBACK(account_setting_info_cb), NULL);
	purple_signal_connect(accounts_handle, "account-set-info",
						plugin, PURPLE_CALLBACK(account_set_info_cb), NULL);
	purple_signal_connect(accounts_handle, "account-status-changed",
						plugin, PURPLE_CALLBACK(account_status_changed), NULL);
	purple_signal_connect(accounts_handle, "account-alias-changed",
						plugin, PURPLE_CALLBACK(account_alias_changed), NULL);
	purple_signal_connect(accounts_handle, "account-authorization-requested",
						plugin, PURPLE_CALLBACK(account_authorization_requested_cb), NULL);
	purple_signal_connect(accounts_handle, "account-authorization-denied",
						plugin, PURPLE_CALLBACK(account_authorization_denied_cb), NULL);
	purple_signal_connect(accounts_handle, "account-authorization-granted",
						plugin, PURPLE_CALLBACK(account_authorization_granted_cb), NULL);

	/* Buddy List subsystem signals */
	purple_signal_connect(blist_handle, "buddy-status-changed",
						plugin, PURPLE_CALLBACK(buddy_status_changed_cb), NULL);
	purple_signal_connect(blist_handle, "buddy-idle-changed",
						plugin, PURPLE_CALLBACK(buddy_idle_changed_cb), NULL);
	purple_signal_connect(blist_handle, "buddy-signed-on",
						plugin, PURPLE_CALLBACK(buddy_signed_on_cb), NULL);
	purple_signal_connect(blist_handle, "buddy-signed-off",
						plugin, PURPLE_CALLBACK(buddy_signed_off_cb), NULL);
	purple_signal_connect(blist_handle, "blist-node-added",
						plugin, PURPLE_CALLBACK(blist_node_added_cb), NULL);
	purple_signal_connect(blist_handle, "blist-node-removed",
						plugin, PURPLE_CALLBACK(blist_node_removed_cb), NULL);
	purple_signal_connect(blist_handle, "buddy-icon-changed",
						plugin, PURPLE_CALLBACK(buddy_icon_changed_cb), NULL);
	purple_signal_connect(blist_handle, "blist-node-aliased",
						plugin, PURPLE_CALLBACK(blist_node_aliased), NULL);
	purple_signal_connect(blist_handle, "blist-node-extended-menu",
						plugin, PURPLE_CALLBACK(blist_node_extended_menu_cb), NULL);

	/* Connection subsystem signals */
	purple_signal_connect(conn_handle, "signing-on",
						plugin, PURPLE_CALLBACK(signing_on_cb), NULL);
	purple_signal_connect(conn_handle, "signed-on",
						plugin, PURPLE_CALLBACK(signed_on_cb), NULL);
	purple_signal_connect(conn_handle, "signing-off",
						plugin, PURPLE_CALLBACK(signing_off_cb), NULL);
	purple_signal_connect(conn_handle, "signed-off",
						plugin, PURPLE_CALLBACK(signed_off_cb), NULL);
	purple_signal_connect(conn_handle, "connection-error",
						plugin, PURPLE_CALLBACK(connection_error_cb), NULL);

	/* Conversations subsystem signals */
	purple_signal_connect(conv_handle, "writing-im-msg",
						plugin, PURPLE_CALLBACK(writing_im_msg_cb), NULL);
	purple_signal_connect(conv_handle, "wrote-im-msg",
						plugin, PURPLE_CALLBACK(wrote_im_msg_cb), NULL);
	purple_signal_connect(conv_handle, "sending-im-msg",
						plugin, PURPLE_CALLBACK(sending_im_msg_cb), NULL);
	purple_signal_connect(conv_handle, "sent-im-msg",
						plugin, PURPLE_CALLBACK(sent_im_msg_cb), NULL);
	purple_signal_connect(conv_handle, "receiving-im-msg",
						plugin, PURPLE_CALLBACK(receiving_im_msg_cb), NULL);
	purple_signal_connect(conv_handle, "received-im-msg",
						plugin, PURPLE_CALLBACK(received_im_msg_cb), NULL);
	purple_signal_connect(conv_handle, "writing-chat-msg",
						plugin, PURPLE_CALLBACK(writing_chat_msg_cb), NULL);
	purple_signal_connect(conv_handle, "wrote-chat-msg",
						plugin, PURPLE_CALLBACK(wrote_chat_msg_cb), NULL);
	purple_signal_connect(conv_handle, "sending-chat-msg",
						plugin, PURPLE_CALLBACK(sending_chat_msg_cb), NULL);
	purple_signal_connect(conv_handle, "sent-chat-msg",
						plugin, PURPLE_CALLBACK(sent_chat_msg_cb), NULL);
	purple_signal_connect(conv_handle, "receiving-chat-msg",
						plugin, PURPLE_CALLBACK(receiving_chat_msg_cb), NULL);
	purple_signal_connect(conv_handle, "received-chat-msg",
						plugin, PURPLE_CALLBACK(received_chat_msg_cb), NULL);
	purple_signal_connect(conv_handle, "conversation-created",
						plugin, PURPLE_CALLBACK(conversation_created_cb), NULL);
	purple_signal_connect(conv_handle, "deleting-conversation",
						plugin, PURPLE_CALLBACK(deleting_conversation_cb), NULL);
	purple_signal_connect(conv_handle, "buddy-typing",
						plugin, PURPLE_CALLBACK(buddy_typing_cb), NULL);
	purple_signal_connect(conv_handle, "buddy-typing-stopped",
						plugin, PURPLE_CALLBACK(buddy_typing_stopped_cb), NULL);
	purple_signal_connect(conv_handle, "chat-buddy-joining",
						plugin, PURPLE_CALLBACK(chat_buddy_joining_cb), NULL);
	purple_signal_connect(conv_handle, "chat-buddy-joined",
						plugin, PURPLE_CALLBACK(chat_buddy_joined_cb), NULL);
	purple_signal_connect(conv_handle, "chat-buddy-flags",
						plugin, PURPLE_CALLBACK(chat_buddy_flags_cb), NULL);
	purple_signal_connect(conv_handle, "chat-buddy-leaving",
						plugin, PURPLE_CALLBACK(chat_buddy_leaving_cb), NULL);
	purple_signal_connect(conv_handle, "chat-buddy-left",
						plugin, PURPLE_CALLBACK(chat_buddy_left_cb), NULL);
	purple_signal_connect(conv_handle, "chat-inviting-user",
						plugin, PURPLE_CALLBACK(chat_inviting_user_cb), NULL);
	purple_signal_connect(conv_handle, "chat-invited-user",
						plugin, PURPLE_CALLBACK(chat_invited_user_cb), NULL);
	purple_signal_connect(conv_handle, "chat-invited",
						plugin, PURPLE_CALLBACK(chat_invited_cb), NULL);
	purple_signal_connect(conv_handle, "chat-joined",
						plugin, PURPLE_CALLBACK(chat_joined_cb), NULL);
	purple_signal_connect(conv_handle, "chat-left",
						plugin, PURPLE_CALLBACK(chat_left_cb), NULL);
	purple_signal_connect(conv_handle, "chat-topic-changed",
						plugin, PURPLE_CALLBACK(chat_topic_changed_cb), NULL);

	/* Ciphers signals */
	purple_signal_connect(ciphers_handle, "cipher-added",
						plugin, PURPLE_CALLBACK(cipher_added_cb), NULL);
	purple_signal_connect(ciphers_handle, "cipher-removed",
						plugin, PURPLE_CALLBACK(cipher_removed_cb), NULL);

	/* Core signals */
	purple_signal_connect(core_handle, "quitting",
						plugin, PURPLE_CALLBACK(quitting_cb), NULL);
	purple_signal_connect(core_handle, "uri-handler",
						plugin,	PURPLE_CALLBACK(uri_handler), NULL);

	/* File transfer signals */
	purple_signal_connect(ft_handle, "file-recv-accept",
						plugin, PURPLE_CALLBACK(ft_recv_accept_cb), NULL);
	purple_signal_connect(ft_handle, "file-recv-start",
						plugin, PURPLE_CALLBACK(ft_recv_start_cb), NULL);
	purple_signal_connect(ft_handle, "file-recv-cancel",
						plugin, PURPLE_CALLBACK(ft_recv_cancel_cb), NULL);
	purple_signal_connect(ft_handle, "file-recv-complete",
						plugin, PURPLE_CALLBACK(ft_recv_complete_cb), NULL);
	purple_signal_connect(ft_handle, "file-send-accept",
						plugin, PURPLE_CALLBACK(ft_send_accept_cb), NULL);
	purple_signal_connect(ft_handle, "file-send-start",
						plugin, PURPLE_CALLBACK(ft_send_start_cb), NULL);
	purple_signal_connect(ft_handle, "file-send-cancel",
						plugin, PURPLE_CALLBACK(ft_send_cancel_cb), NULL);
	purple_signal_connect(ft_handle, "file-send-complete",
						plugin, PURPLE_CALLBACK(ft_send_complete_cb), NULL);

	/* Sound signals */
	purple_signal_connect(sound_handle, "playing-sound-event", plugin,
	                    PURPLE_CALLBACK(sound_playing_event_cb), NULL);

	/* Notify signals */
	purple_signal_connect(notify_handle, "displaying-email-notification",
						plugin, PURPLE_CALLBACK(notify_email_cb), NULL);
	purple_signal_connect(notify_handle, "displaying-emails-notification",
						plugin, PURPLE_CALLBACK(notify_emails_cb), NULL);

	/* Jabber signals */
	if (jabber_handle) {
		purple_signal_connect(jabber_handle, "jabber-receiving-iq", plugin,
		                      PURPLE_CALLBACK(jabber_iq_received), NULL);
		purple_signal_connect(jabber_handle, "jabber-receiving-message", plugin,
		                      PURPLE_CALLBACK(jabber_message_received), NULL);
		purple_signal_connect(jabber_handle, "jabber-receiving-presence", plugin,
		                      PURPLE_CALLBACK(jabber_presence_received), NULL);

		/* IQ namespace signals */
		purple_signal_emit(jabber_handle, "jabber-register-namespace-watcher",
		                   "bogus_node", "super-duper-namespace");
		/* The above is equivalent to doing:
			int result = GPOINTER_TO_INT(purple_plugin_ipc_call(jabber_handle, "register_namespace_watcher", &ok, "bogus_node", "super-duper-namespace"));
		 */

		purple_signal_connect(jabber_handle, "jabber-watched-iq", plugin,
		                      PURPLE_CALLBACK(jabber_watched_iq), NULL);
	}

	return TRUE;
}

static gboolean
plugin_unload(PurplePlugin *plugin)
{
	void *jabber_handle = purple_plugins_find_with_id("prpl-jabber");

	purple_signals_disconnect_by_handle(plugin);

	if (jabber_handle) {
		/* Unregister watched namespaces */
		purple_signal_emit(jabber_handle, "jabber-unregister-namespace-watcher",
		                   "bogus_node", "super-duper-namespace");
		/* The above is equivalent to doing:
		   int result = GPOINTER_TO_INT(purple_plugin_ipc_call(jabber_handle, "unregister_namespace_watcher", &ok, "bogus_node", "super-duper-namespace"));
		 */
	}

	return TRUE;
}

static PurplePluginInfo info =
{
	PURPLE_PLUGIN_MAGIC,
	PURPLE_MAJOR_VERSION,
	PURPLE_MINOR_VERSION,
	PURPLE_PLUGIN_STANDARD,                             /**< type           */
	NULL,                                             /**< ui_requirement */
	0,                                                /**< flags          */
	NULL,                                             /**< dependencies   */
	PURPLE_PRIORITY_DEFAULT,                            /**< priority       */

	SIGNAL_TEST_PLUGIN_ID,                            /**< id             */
	N_("Signals Test"),                               /**< name           */
	DISPLAY_VERSION,                                  /**< version        */
	                                                  /**  summary        */
	N_("Test to see that all signals are working properly."),
	                                                  /**  description    */
	N_("Test to see that all signals are working properly."),
	"Christian Hammond <chipx86@gnupdate.org>",       /**< author         */
	PURPLE_WEBSITE,                                     /**< homepage       */

	plugin_load,                                      /**< load           */
	plugin_unload,                                    /**< unload         */
	NULL,                                             /**< destroy        */

	NULL,                                             /**< ui_info        */
	NULL,                                             /**< extra_info     */
	NULL,
	NULL,
	/* Padding */
	NULL,
	NULL,
	NULL,
	NULL
};

static void
init_plugin(PurplePlugin *plugin)
{
}

PURPLE_INIT_PLUGIN(signalstest, init_plugin, info)
