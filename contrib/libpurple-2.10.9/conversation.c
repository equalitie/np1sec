/*
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
#include "blist.h"
#include "cmds.h"
#include "conversation.h"
#include "dbus-maybe.h"
#include "debug.h"
#include "imgstore.h"
#include "notify.h"
#include "prefs.h"
#include "prpl.h"
#include "request.h"
#include "signals.h"
#include "util.h"

#define SEND_TYPED_TIMEOUT_SECONDS 5

static GList *conversations = NULL;
static GList *ims = NULL;
static GList *chats = NULL;
static PurpleConversationUiOps *default_ops = NULL;

/**
 * A hash table used for efficient lookups of conversations by name.
 * struct _purple_hconv => PurpleConversation*
 */
static GHashTable *conversation_cache = NULL;

struct _purple_hconv {
	PurpleConversationType type;
	char *name;
	const PurpleAccount *account;
};

static guint _purple_conversations_hconv_hash(struct _purple_hconv *hc)
{
	return g_str_hash(hc->name) ^ hc->type ^ g_direct_hash(hc->account);
}

static guint _purple_conversations_hconv_equal(struct _purple_hconv *hc1, struct _purple_hconv *hc2)
{
	return (hc1->type == hc2->type &&
	        hc1->account == hc2->account &&
	        g_str_equal(hc1->name, hc2->name));
}

static void _purple_conversations_hconv_free_key(struct _purple_hconv *hc)
{
	g_free(hc->name);
	g_free(hc);
}

static guint _purple_conversation_user_hash(gconstpointer data)
{
	const gchar *name = data;
	gchar *collated;
	guint hash;

	collated = g_utf8_collate_key(name, -1);
	hash     = g_str_hash(collated);
	g_free(collated);
	return hash;
}

static gboolean _purple_conversation_user_equal(gconstpointer a, gconstpointer b)
{
	return !g_utf8_collate(a, b);
}

void
purple_conversations_set_ui_ops(PurpleConversationUiOps *ops)
{
	default_ops = ops;
}

static gboolean
reset_typing_cb(gpointer data)
{
	PurpleConversation *c = (PurpleConversation *)data;
	PurpleConvIm *im;

	im = PURPLE_CONV_IM(c);

	purple_conv_im_set_typing_state(im, PURPLE_NOT_TYPING);
	purple_conv_im_stop_typing_timeout(im);

	return FALSE;
}

static gboolean
send_typed_cb(gpointer data)
{
	PurpleConversation *conv = (PurpleConversation *)data;
	PurpleConnection *gc;
	const char *name;

	g_return_val_if_fail(conv != NULL, FALSE);

	gc   = purple_conversation_get_gc(conv);
	name = purple_conversation_get_name(conv);

	if (gc != NULL && name != NULL) {
		/* We set this to 1 so that PURPLE_TYPING will be sent
		 * if the Purple user types anything else.
		 */
		purple_conv_im_set_type_again(PURPLE_CONV_IM(conv), 1);

		serv_send_typing(gc, name, PURPLE_TYPED);

		purple_debug(PURPLE_DEBUG_MISC, "conversation", "typed...\n");
	}

	return FALSE;
}

static void
common_send(PurpleConversation *conv, const char *message, PurpleMessageFlags msgflags)
{
	PurpleConversationType type;
	PurpleAccount *account;
	PurpleConnection *gc;
	char *displayed = NULL, *sent = NULL;
	int err = 0;

	if (*message == '\0')
		return;

	account = purple_conversation_get_account(conv);
	gc = purple_conversation_get_gc(conv);

	g_return_if_fail(account != NULL);
	g_return_if_fail(gc != NULL);

	type = purple_conversation_get_type(conv);

	/* Always linkfy the text for display, unless we're
	 * explicitly asked to do otheriwse*/
	if (!(msgflags & PURPLE_MESSAGE_INVISIBLE)) {
		if(msgflags & PURPLE_MESSAGE_NO_LINKIFY)
			displayed = g_strdup(message);
		else
			displayed = purple_markup_linkify(message);
	}

	if (displayed && (conv->features & PURPLE_CONNECTION_HTML) &&
		!(msgflags & PURPLE_MESSAGE_RAW)) {
		sent = g_strdup(displayed);
	} else
		sent = g_strdup(message);

	msgflags |= PURPLE_MESSAGE_SEND;

	if (type == PURPLE_CONV_TYPE_IM) {
		PurpleConvIm *im = PURPLE_CONV_IM(conv);

		purple_signal_emit(purple_conversations_get_handle(), "sending-im-msg",
						 account,
						 purple_conversation_get_name(conv), &sent);

		if (sent != NULL && sent[0] != '\0') {

			err = serv_send_im(gc, purple_conversation_get_name(conv),
			                   sent, msgflags);

			if ((err > 0) && (displayed != NULL))
				purple_conv_im_write(im, NULL, displayed, msgflags, time(NULL));

			purple_signal_emit(purple_conversations_get_handle(), "sent-im-msg",
							 account,
							 purple_conversation_get_name(conv), sent);
		}
	}
	else {
		purple_signal_emit(purple_conversations_get_handle(), "sending-chat-msg",
						 account, &sent,
						 purple_conv_chat_get_id(PURPLE_CONV_CHAT(conv)));

		if (sent != NULL && sent[0] != '\0') {
			err = serv_chat_send(gc, purple_conv_chat_get_id(PURPLE_CONV_CHAT(conv)), sent, msgflags);

			purple_signal_emit(purple_conversations_get_handle(), "sent-chat-msg",
							 account, sent,
							 purple_conv_chat_get_id(PURPLE_CONV_CHAT(conv)));
		}
	}

	if (err < 0) {
		const char *who;
		const char *msg;

		who = purple_conversation_get_name(conv);

		if (err == -E2BIG) {
			msg = _("Unable to send message: The message is too large.");

			if (!purple_conv_present_error(who, account, msg)) {
				char *msg2 = g_strdup_printf(_("Unable to send message to %s."), who);
				purple_notify_error(gc, NULL, msg2, _("The message is too large."));
				g_free(msg2);
			}
		}
		else if (err == -ENOTCONN) {
			purple_debug(PURPLE_DEBUG_ERROR, "conversation",
					   "Not yet connected.\n");
		}
		else {
			msg = _("Unable to send message.");

			if (!purple_conv_present_error(who, account, msg)) {
				char *msg2 = g_strdup_printf(_("Unable to send message to %s."), who);
				purple_notify_error(gc, NULL, msg2, NULL);
				g_free(msg2);
			}
		}
	}

	g_free(displayed);
	g_free(sent);
}

static void
open_log(PurpleConversation *conv)
{
	conv->logs = g_list_append(NULL, purple_log_new(conv->type == PURPLE_CONV_TYPE_CHAT ? PURPLE_LOG_CHAT :
							   PURPLE_LOG_IM, conv->name, conv->account,
							   conv, time(NULL), NULL));
}

/* Functions that deal with PurpleConvMessage */

static void
add_message_to_history(PurpleConversation *conv, const char *who, const char *alias,
		const char *message, PurpleMessageFlags flags, time_t when)
{
	PurpleConvMessage *msg;
	PurpleConnection *gc;

	gc = purple_account_get_connection(conv->account);

	if (flags & PURPLE_MESSAGE_SEND) {
		const char *me = NULL;
		if (gc)
			me = purple_connection_get_display_name(gc);
		if (!me)
			me = conv->account->username;
		who = me;
	}

	msg = g_new0(PurpleConvMessage, 1);
	PURPLE_DBUS_REGISTER_POINTER(msg, PurpleConvMessage);
	msg->who = g_strdup(who);
	msg->alias = g_strdup(alias);
	msg->flags = flags;
	msg->what = g_strdup(message);
	msg->when = when;
	msg->conv = conv;

	conv->message_history = g_list_prepend(conv->message_history, msg);
}

static void
free_conv_message(PurpleConvMessage *msg)
{
	g_free(msg->who);
	g_free(msg->alias);
	g_free(msg->what);
	PURPLE_DBUS_UNREGISTER_POINTER(msg);
	g_free(msg);
}

static void
message_history_free(GList *list)
{
	g_list_foreach(list, (GFunc)free_conv_message, NULL);
	g_list_free(list);
}

/**************************************************************************
 * Conversation API
 **************************************************************************/
static void
purple_conversation_chat_cleanup_for_rejoin(PurpleConversation *conv)
{
	const char *disp;
	PurpleAccount *account;
	PurpleConnection *gc;

	account = purple_conversation_get_account(conv);

	purple_conversation_close_logs(conv);
	open_log(conv);

	gc = purple_account_get_connection(account);

	if ((disp = purple_connection_get_display_name(gc)) != NULL)
		purple_conv_chat_set_nick(PURPLE_CONV_CHAT(conv), disp);
	else
	{
		purple_conv_chat_set_nick(PURPLE_CONV_CHAT(conv),
								purple_account_get_username(account));
	}

	purple_conv_chat_clear_users(PURPLE_CONV_CHAT(conv));
	purple_conv_chat_set_topic(PURPLE_CONV_CHAT(conv), NULL, NULL);
	PURPLE_CONV_CHAT(conv)->left = FALSE;

	purple_conversation_update(conv, PURPLE_CONV_UPDATE_CHATLEFT);
}

PurpleConversation *
purple_conversation_new(PurpleConversationType type, PurpleAccount *account,
					  const char *name)
{
	PurpleConversation *conv;
	PurpleConnection *gc;
	PurpleConversationUiOps *ops;
	struct _purple_hconv *hc;

	g_return_val_if_fail(type    != PURPLE_CONV_TYPE_UNKNOWN, NULL);
	g_return_val_if_fail(account != NULL, NULL);
	g_return_val_if_fail(name    != NULL, NULL);

	/* Check if this conversation already exists. */
	if ((conv = purple_find_conversation_with_account(type, name, account)) != NULL)
	{
		if (purple_conversation_get_type(conv) == PURPLE_CONV_TYPE_CHAT &&
				!purple_conv_chat_has_left(PURPLE_CONV_CHAT(conv))) {
			purple_debug_warning("conversation", "Trying to create multiple "
					"chats (%s) with the same name is deprecated and will be "
					"removed in libpurple 3.0.0", name);
		}

		/*
		 * This hack is necessary because some prpls (MSN) have unnamed chats
		 * that all use the same name.  A PurpleConversation for one of those
		 * is only ever re-used if the user has left, so calls to
		 * purple_conversation_new need to fall-through to creating a new
		 * chat.
		 * TODO 3.0.0: Remove this workaround and mandate unique names.
		 */
		if (purple_conversation_get_type(conv) != PURPLE_CONV_TYPE_CHAT ||
				purple_conv_chat_has_left(PURPLE_CONV_CHAT(conv)))
		{
			if (purple_conversation_get_type(conv) == PURPLE_CONV_TYPE_CHAT)
				purple_conversation_chat_cleanup_for_rejoin(conv);

			return conv;
		}
	}

	gc = purple_account_get_connection(account);
	g_return_val_if_fail(gc != NULL, NULL);

	conv = g_new0(PurpleConversation, 1);
	PURPLE_DBUS_REGISTER_POINTER(conv, PurpleConversation);

	conv->type         = type;
	conv->account      = account;
	conv->name         = g_strdup(name);
	conv->title        = g_strdup(name);
	conv->data         = g_hash_table_new_full(g_str_hash, g_str_equal,
											   g_free, NULL);
	/* copy features from the connection. */
	conv->features = gc->flags;

	if (type == PURPLE_CONV_TYPE_IM)
	{
		PurpleBuddyIcon *icon;
		conv->u.im = g_new0(PurpleConvIm, 1);
		conv->u.im->conv = conv;
		PURPLE_DBUS_REGISTER_POINTER(conv->u.im, PurpleConvIm);

		ims = g_list_prepend(ims, conv);
		if ((icon = purple_buddy_icons_find(account, name)))
		{
			purple_conv_im_set_icon(conv->u.im, icon);
			/* purple_conv_im_set_icon refs the icon. */
			purple_buddy_icon_unref(icon);
		}

		if (purple_prefs_get_bool("/purple/logging/log_ims"))
		{
			purple_conversation_set_logging(conv, TRUE);
			open_log(conv);
		}
	}
	else if (type == PURPLE_CONV_TYPE_CHAT)
	{
		const char *disp;

		conv->u.chat = g_new0(PurpleConvChat, 1);
		conv->u.chat->conv = conv;
		conv->u.chat->users = g_hash_table_new_full(_purple_conversation_user_hash,
				_purple_conversation_user_equal, g_free, NULL);
		PURPLE_DBUS_REGISTER_POINTER(conv->u.chat, PurpleConvChat);

		chats = g_list_prepend(chats, conv);

		if ((disp = purple_connection_get_display_name(account->gc)))
			purple_conv_chat_set_nick(conv->u.chat, disp);
		else
			purple_conv_chat_set_nick(conv->u.chat,
									purple_account_get_username(account));

		if (purple_prefs_get_bool("/purple/logging/log_chats"))
		{
			purple_conversation_set_logging(conv, TRUE);
			open_log(conv);
		}
	}

	conversations = g_list_prepend(conversations, conv);

	hc = g_new(struct _purple_hconv, 1);
	hc->name = g_strdup(purple_normalize(account, conv->name));
	hc->account = account;
	hc->type = type;

	g_hash_table_insert(conversation_cache, hc, conv);

	/* Auto-set the title. */
	purple_conversation_autoset_title(conv);

	/* Don't move this.. it needs to be one of the last things done otherwise
	 * it causes mysterious crashes on my system.
	 *  -- Gary
	 */
	ops  = conv->ui_ops = default_ops;
	if (ops != NULL && ops->create_conversation != NULL)
		ops->create_conversation(conv);

	purple_signal_emit(purple_conversations_get_handle(),
					 "conversation-created", conv);

	return conv;
}

void
purple_conversation_destroy(PurpleConversation *conv)
{
	PurplePluginProtocolInfo *prpl_info = NULL;
	PurpleConversationUiOps *ops;
	PurpleConnection *gc;
	const char *name;
	struct _purple_hconv hc;

	g_return_if_fail(conv != NULL);

	purple_request_close_with_handle(conv);

	ops  = purple_conversation_get_ui_ops(conv);
	gc   = purple_conversation_get_gc(conv);
	name = purple_conversation_get_name(conv);

	if (gc != NULL)
	{
		/* Still connected */
		prpl_info = PURPLE_PLUGIN_PROTOCOL_INFO(purple_connection_get_prpl(gc));

		if (purple_conversation_get_type(conv) == PURPLE_CONV_TYPE_IM)
		{
			if (purple_prefs_get_bool("/purple/conversations/im/send_typing"))
				serv_send_typing(gc, name, PURPLE_NOT_TYPING);

			if (gc && prpl_info->convo_closed != NULL)
				prpl_info->convo_closed(gc, name);
		}
		else if (purple_conversation_get_type(conv) == PURPLE_CONV_TYPE_CHAT)
		{
			int chat_id = purple_conv_chat_get_id(PURPLE_CONV_CHAT(conv));
#if 0
			/*
			 * This is unfortunately necessary, because calling
			 * serv_chat_leave() calls this purple_conversation_destroy(),
			 * which leads to two calls here.. We can't just return after
			 * this, because then it'll return on the next pass. So, since
			 * serv_got_chat_left(), which is eventually called from the
			 * prpl that serv_chat_leave() calls, removes this conversation
			 * from the gc's buddy_chats list, we're going to check to see
			 * if this exists in the list. If so, we want to return after
			 * calling this, because it'll be called again. If not, fall
			 * through, because it'll have already been removed, and we'd
			 * be on the 2nd pass.
			 *
			 * Long paragraph. <-- Short sentence.
			 *
			 *   -- ChipX86
			 */

			if (gc && g_slist_find(gc->buddy_chats, conv) != NULL) {
				serv_chat_leave(gc, chat_id);

				return;
			}
#endif
			/*
			 * Instead of all of that, lets just close the window when
			 * the user tells us to, and let the prpl deal with the
			 * internals on it's own time. Don't do this if the prpl already
			 * knows it left the chat.
			 */
			if (!purple_conv_chat_has_left(PURPLE_CONV_CHAT(conv)))
				serv_chat_leave(gc, chat_id);

			/*
			 * If they didn't call serv_got_chat_left by now, it's too late.
			 * So we better do it for them before we destroy the thing.
			 */
			if (!purple_conv_chat_has_left(PURPLE_CONV_CHAT(conv)))
				serv_got_chat_left(gc, chat_id);
		}
	}

	/* remove from conversations and im/chats lists prior to emit */
	conversations = g_list_remove(conversations, conv);

	if(conv->type==PURPLE_CONV_TYPE_IM)
		ims = g_list_remove(ims, conv);
	else if(conv->type==PURPLE_CONV_TYPE_CHAT)
		chats = g_list_remove(chats, conv);

	hc.name = (gchar *)purple_normalize(conv->account, conv->name);
	hc.account = conv->account;
	hc.type = conv->type;

	g_hash_table_remove(conversation_cache, &hc);

	purple_signal_emit(purple_conversations_get_handle(),
					 "deleting-conversation", conv);

	g_free(conv->name);
	g_free(conv->title);

	conv->name = NULL;
	conv->title = NULL;

	if (conv->type == PURPLE_CONV_TYPE_IM) {
		purple_conv_im_stop_typing_timeout(conv->u.im);
		purple_conv_im_stop_send_typed_timeout(conv->u.im);

		purple_buddy_icon_unref(conv->u.im->icon);
		conv->u.im->icon = NULL;

		PURPLE_DBUS_UNREGISTER_POINTER(conv->u.im);
		g_free(conv->u.im);
		conv->u.im = NULL;
	}
	else if (conv->type == PURPLE_CONV_TYPE_CHAT) {
		g_hash_table_destroy(conv->u.chat->users);
		conv->u.chat->users = NULL;

		g_list_foreach(conv->u.chat->in_room, (GFunc)purple_conv_chat_cb_destroy, NULL);
		g_list_free(conv->u.chat->in_room);

		g_list_foreach(conv->u.chat->ignored, (GFunc)g_free, NULL);
		g_list_free(conv->u.chat->ignored);

		conv->u.chat->in_room = NULL;
		conv->u.chat->ignored = NULL;

		g_free(conv->u.chat->who);
		conv->u.chat->who = NULL;

		g_free(conv->u.chat->topic);
		conv->u.chat->topic = NULL;

		g_free(conv->u.chat->nick);

		PURPLE_DBUS_UNREGISTER_POINTER(conv->u.chat);
		g_free(conv->u.chat);
		conv->u.chat = NULL;
	}

	g_hash_table_destroy(conv->data);
	conv->data = NULL;

	if (ops != NULL && ops->destroy_conversation != NULL)
		ops->destroy_conversation(conv);
	conv->ui_data = NULL;

	purple_conversation_close_logs(conv);

	purple_conversation_clear_message_history(conv);

	PURPLE_DBUS_UNREGISTER_POINTER(conv);
	g_free(conv);
	conv = NULL;
}


void
purple_conversation_present(PurpleConversation *conv) {
	PurpleConversationUiOps *ops;

	g_return_if_fail(conv != NULL);

	ops = purple_conversation_get_ui_ops(conv);
	if(ops && ops->present)
		ops->present(conv);
}


void
purple_conversation_set_features(PurpleConversation *conv, PurpleConnectionFlags features)
{
	g_return_if_fail(conv != NULL);

	conv->features = features;

	purple_conversation_update(conv, PURPLE_CONV_UPDATE_FEATURES);
}


PurpleConnectionFlags
purple_conversation_get_features(PurpleConversation *conv)
{
	g_return_val_if_fail(conv != NULL, 0);
	return conv->features;
}


PurpleConversationType
purple_conversation_get_type(const PurpleConversation *conv)
{
	g_return_val_if_fail(conv != NULL, PURPLE_CONV_TYPE_UNKNOWN);

	return conv->type;
}

void
purple_conversation_set_ui_ops(PurpleConversation *conv,
							 PurpleConversationUiOps *ops)
{
	g_return_if_fail(conv != NULL);

	if (conv->ui_ops == ops)
		return;

	if (conv->ui_ops != NULL && conv->ui_ops->destroy_conversation != NULL)
		conv->ui_ops->destroy_conversation(conv);

	conv->ui_data = NULL;

	conv->ui_ops = ops;
}

PurpleConversationUiOps *
purple_conversation_get_ui_ops(const PurpleConversation *conv)
{
	g_return_val_if_fail(conv != NULL, NULL);

	return conv->ui_ops;
}

void
purple_conversation_set_account(PurpleConversation *conv, PurpleAccount *account)
{
	g_return_if_fail(conv != NULL);

	if (account == purple_conversation_get_account(conv))
		return;

	conv->account = account;

	purple_conversation_update(conv, PURPLE_CONV_UPDATE_ACCOUNT);
}

PurpleAccount *
purple_conversation_get_account(const PurpleConversation *conv)
{
	g_return_val_if_fail(conv != NULL, NULL);

	return conv->account;
}

PurpleConnection *
purple_conversation_get_gc(const PurpleConversation *conv)
{
	PurpleAccount *account;

	g_return_val_if_fail(conv != NULL, NULL);

	account = purple_conversation_get_account(conv);

	if (account == NULL)
		return NULL;

	return account->gc;
}

void
purple_conversation_set_title(PurpleConversation *conv, const char *title)
{
	g_return_if_fail(conv  != NULL);
	g_return_if_fail(title != NULL);

	g_free(conv->title);
	conv->title = g_strdup(title);

	purple_conversation_update(conv, PURPLE_CONV_UPDATE_TITLE);
}

const char *
purple_conversation_get_title(const PurpleConversation *conv)
{
	g_return_val_if_fail(conv != NULL, NULL);

	return conv->title;
}

void
purple_conversation_autoset_title(PurpleConversation *conv)
{
	PurpleAccount *account;
	PurpleBuddy *b;
	PurpleChat *chat;
	const char *text = NULL, *name;

	g_return_if_fail(conv != NULL);

	account = purple_conversation_get_account(conv);
	name = purple_conversation_get_name(conv);

	if(purple_conversation_get_type(conv) == PURPLE_CONV_TYPE_IM) {
		if(account && ((b = purple_find_buddy(account, name)) != NULL))
			text = purple_buddy_get_contact_alias(b);
	} else if(purple_conversation_get_type(conv) == PURPLE_CONV_TYPE_CHAT) {
		if(account && ((chat = purple_blist_find_chat(account, name)) != NULL))
			text = purple_chat_get_name(chat);
	}


	if(text == NULL)
		text = name;

	purple_conversation_set_title(conv, text);
}

void
purple_conversation_foreach(void (*func)(PurpleConversation *conv))
{
	PurpleConversation *conv;
	GList *l;

	g_return_if_fail(func != NULL);

	for (l = purple_get_conversations(); l != NULL; l = l->next) {
		conv = (PurpleConversation *)l->data;

		func(conv);
	}
}

void
purple_conversation_set_name(PurpleConversation *conv, const char *name)
{
	struct _purple_hconv *hc;
	g_return_if_fail(conv != NULL);

	hc = g_new(struct _purple_hconv, 1);
	hc->type = conv->type;
	hc->account = conv->account;
	hc->name = (gchar *)purple_normalize(conv->account, conv->name);

	g_hash_table_remove(conversation_cache, hc);
	g_free(conv->name);

	conv->name = g_strdup(name);
	hc->name = g_strdup(purple_normalize(conv->account, conv->name));
	g_hash_table_insert(conversation_cache, hc, conv);

	purple_conversation_autoset_title(conv);
}

const char *
purple_conversation_get_name(const PurpleConversation *conv)
{
	g_return_val_if_fail(conv != NULL, NULL);

	return conv->name;
}

void
purple_conversation_set_logging(PurpleConversation *conv, gboolean log)
{
	g_return_if_fail(conv != NULL);

	if (conv->logging != log)
	{
		conv->logging = log;
		purple_conversation_update(conv, PURPLE_CONV_UPDATE_LOGGING);
	}
}

gboolean
purple_conversation_is_logging(const PurpleConversation *conv)
{
	g_return_val_if_fail(conv != NULL, FALSE);

	return conv->logging;
}

void
purple_conversation_close_logs(PurpleConversation *conv)
{
	g_return_if_fail(conv != NULL);

	g_list_foreach(conv->logs, (GFunc)purple_log_free, NULL);
	g_list_free(conv->logs);
	conv->logs = NULL;
}

PurpleConvIm *
purple_conversation_get_im_data(const PurpleConversation *conv)
{
	g_return_val_if_fail(conv != NULL, NULL);

	if (purple_conversation_get_type(conv) != PURPLE_CONV_TYPE_IM)
		return NULL;

	return conv->u.im;
}

PurpleConvChat *
purple_conversation_get_chat_data(const PurpleConversation *conv)
{
	g_return_val_if_fail(conv != NULL, NULL);

	if (purple_conversation_get_type(conv) != PURPLE_CONV_TYPE_CHAT)
		return NULL;

	return conv->u.chat;
}

void
purple_conversation_set_data(PurpleConversation *conv, const char *key,
						   gpointer data)
{
	g_return_if_fail(conv != NULL);
	g_return_if_fail(key  != NULL);

	g_hash_table_replace(conv->data, g_strdup(key), data);
}

gpointer
purple_conversation_get_data(PurpleConversation *conv, const char *key)
{
	g_return_val_if_fail(conv != NULL, NULL);
	g_return_val_if_fail(key  != NULL, NULL);

	return g_hash_table_lookup(conv->data, key);
}

GList *
purple_get_conversations(void)
{
	return conversations;
}

GList *
purple_get_ims(void)
{
	return ims;
}

GList *
purple_get_chats(void)
{
	return chats;
}


PurpleConversation *
purple_find_conversation_with_account(PurpleConversationType type,
									const char *name,
									const PurpleAccount *account)
{
	PurpleConversation *c = NULL;
	struct _purple_hconv hc;

	g_return_val_if_fail(name != NULL, NULL);

	hc.name = (gchar *)purple_normalize(account, name);
	hc.account = account;
	hc.type = type;

	switch (type) {
		case PURPLE_CONV_TYPE_IM:
		case PURPLE_CONV_TYPE_CHAT:
			c = g_hash_table_lookup(conversation_cache, &hc);
			break;
		case PURPLE_CONV_TYPE_ANY:
			hc.type = PURPLE_CONV_TYPE_IM;
			c = g_hash_table_lookup(conversation_cache, &hc);
			if (!c) {
				hc.type = PURPLE_CONV_TYPE_CHAT;
				c = g_hash_table_lookup(conversation_cache, &hc);
			}
			break;
		default:
			g_return_val_if_reached(NULL);
	}

	return c;
}

void
purple_conversation_write(PurpleConversation *conv, const char *who,
						const char *message, PurpleMessageFlags flags,
						time_t mtime)
{
	PurplePluginProtocolInfo *prpl_info = NULL;
	PurpleConnection *gc = NULL;
	PurpleAccount *account;
	PurpleConversationUiOps *ops;
	const char *alias;
	char *displayed = NULL;
	PurpleBuddy *b;
	int plugin_return;
	PurpleConversationType type;
	/* int logging_font_options = 0; */

	g_return_if_fail(conv    != NULL);
	g_return_if_fail(message != NULL);

	ops = purple_conversation_get_ui_ops(conv);

	account = purple_conversation_get_account(conv);
	type = purple_conversation_get_type(conv);

	if (account != NULL)
		gc = purple_account_get_connection(account);

	if (purple_conversation_get_type(conv) == PURPLE_CONV_TYPE_CHAT &&
		(gc != NULL && !g_slist_find(gc->buddy_chats, conv)))
		return;

	if (purple_conversation_get_type(conv) == PURPLE_CONV_TYPE_IM &&
		!g_list_find(purple_get_conversations(), conv))
		return;

	displayed = g_strdup(message);

	if (who == NULL || *who == '\0')
		who = purple_conversation_get_name(conv);
	alias = who;

	plugin_return =
		GPOINTER_TO_INT(purple_signal_emit_return_1(
			purple_conversations_get_handle(),
			(type == PURPLE_CONV_TYPE_IM ? "writing-im-msg" : "writing-chat-msg"),
			account, who, &displayed, conv, flags));

	if (displayed == NULL)
		return;

	if (plugin_return) {
		g_free(displayed);
		return;
	}

	if (account != NULL) {
		prpl_info = PURPLE_PLUGIN_PROTOCOL_INFO(purple_find_prpl(purple_account_get_protocol_id(account)));

		if (purple_conversation_get_type(conv) == PURPLE_CONV_TYPE_IM ||
			!(prpl_info->options & OPT_PROTO_UNIQUE_CHATNAME)) {

			if (flags & PURPLE_MESSAGE_SEND) {
				b = purple_find_buddy(account,
							purple_account_get_username(account));

				if (purple_account_get_alias(account) != NULL)
					alias = account->alias;
				else if (b != NULL && !purple_strequal(purple_buddy_get_name(b), purple_buddy_get_contact_alias(b)))
					alias = purple_buddy_get_contact_alias(b);
				else if (purple_connection_get_display_name(gc) != NULL)
					alias = purple_connection_get_display_name(gc);
				else
					alias = purple_account_get_username(account);
			}
			else
			{
				b = purple_find_buddy(account, who);

				if (b != NULL)
					alias = purple_buddy_get_contact_alias(b);
			}
		}
	}

	if (!(flags & PURPLE_MESSAGE_NO_LOG) && purple_conversation_is_logging(conv)) {
		GList *log;

		if (conv->logs == NULL)
			open_log(conv);

		log = conv->logs;
		while (log != NULL) {
			purple_log_write((PurpleLog *)log->data, flags, alias, mtime, displayed);
			log = log->next;
		}
	}

	if (ops && ops->write_conv)
		ops->write_conv(conv, who, alias, displayed, flags, mtime);

	add_message_to_history(conv, who, alias, message, flags, mtime);

	purple_signal_emit(purple_conversations_get_handle(),
		(type == PURPLE_CONV_TYPE_IM ? "wrote-im-msg" : "wrote-chat-msg"),
		account, who, displayed, conv, flags);

	g_free(displayed);
}

gboolean
purple_conversation_has_focus(PurpleConversation *conv)
{
	gboolean ret = FALSE;
	PurpleConversationUiOps *ops;

	g_return_val_if_fail(conv != NULL, FALSE);

	ops = purple_conversation_get_ui_ops(conv);

	if (ops != NULL && ops->has_focus != NULL)
		ret = ops->has_focus(conv);

	return ret;
}

/*
 * TODO: Need to make sure calls to this function happen in the core
 * instead of the UI.  That way UIs have less work to do, and the
 * core/UI split is cleaner.  Also need to make sure this is called
 * when chats are added/removed from the blist.
 */
void
purple_conversation_update(PurpleConversation *conv, PurpleConvUpdateType type)
{
	g_return_if_fail(conv != NULL);

	purple_signal_emit(purple_conversations_get_handle(),
					 "conversation-updated", conv, type);
}

/**************************************************************************
 * IM Conversation API
 **************************************************************************/
PurpleConversation *
purple_conv_im_get_conversation(const PurpleConvIm *im)
{
	g_return_val_if_fail(im != NULL, NULL);

	return im->conv;
}

void
purple_conv_im_set_icon(PurpleConvIm *im, PurpleBuddyIcon *icon)
{
	g_return_if_fail(im != NULL);

	if (im->icon != icon)
	{
		purple_buddy_icon_unref(im->icon);

		im->icon = (icon == NULL ? NULL : purple_buddy_icon_ref(icon));
	}

	purple_conversation_update(purple_conv_im_get_conversation(im),
							 PURPLE_CONV_UPDATE_ICON);
}

PurpleBuddyIcon *
purple_conv_im_get_icon(const PurpleConvIm *im)
{
	g_return_val_if_fail(im != NULL, NULL);

	return im->icon;
}

void
purple_conv_im_set_typing_state(PurpleConvIm *im, PurpleTypingState state)
{
	g_return_if_fail(im != NULL);

	if (im->typing_state != state)
	{
		im->typing_state = state;

		switch (state)
		{
			case PURPLE_TYPING:
				purple_signal_emit(purple_conversations_get_handle(),
								   "buddy-typing", im->conv->account, im->conv->name);
				break;
			case PURPLE_TYPED:
				purple_signal_emit(purple_conversations_get_handle(),
								   "buddy-typed", im->conv->account, im->conv->name);
				break;
			case PURPLE_NOT_TYPING:
				purple_signal_emit(purple_conversations_get_handle(),
								   "buddy-typing-stopped", im->conv->account, im->conv->name);
				break;
		}

		purple_conv_im_update_typing(im);
	}
}

PurpleTypingState
purple_conv_im_get_typing_state(const PurpleConvIm *im)
{
	g_return_val_if_fail(im != NULL, 0);

	return im->typing_state;
}

void
purple_conv_im_start_typing_timeout(PurpleConvIm *im, int timeout)
{
	PurpleConversation *conv;

	g_return_if_fail(im != NULL);

	if (im->typing_timeout > 0)
		purple_conv_im_stop_typing_timeout(im);

	conv = purple_conv_im_get_conversation(im);

	im->typing_timeout = purple_timeout_add_seconds(timeout, reset_typing_cb, conv);
}

void
purple_conv_im_stop_typing_timeout(PurpleConvIm *im)
{
	g_return_if_fail(im != NULL);

	if (im->typing_timeout == 0)
		return;

	purple_timeout_remove(im->typing_timeout);
	im->typing_timeout = 0;
}

guint
purple_conv_im_get_typing_timeout(const PurpleConvIm *im)
{
	g_return_val_if_fail(im != NULL, 0);

	return im->typing_timeout;
}

void
purple_conv_im_set_type_again(PurpleConvIm *im, unsigned int val)
{
	g_return_if_fail(im != NULL);

	if (val == 0)
		im->type_again = 0;
	else
		im->type_again = time(NULL) + val;
}

time_t
purple_conv_im_get_type_again(const PurpleConvIm *im)
{
	g_return_val_if_fail(im != NULL, 0);

	return im->type_again;
}

void
purple_conv_im_start_send_typed_timeout(PurpleConvIm *im)
{
	g_return_if_fail(im != NULL);

	im->send_typed_timeout = purple_timeout_add_seconds(SEND_TYPED_TIMEOUT_SECONDS,
	                                                    send_typed_cb,
	                                                    purple_conv_im_get_conversation(im));
}

void
purple_conv_im_stop_send_typed_timeout(PurpleConvIm *im)
{
	g_return_if_fail(im != NULL);

	if (im->send_typed_timeout == 0)
		return;

	purple_timeout_remove(im->send_typed_timeout);
	im->send_typed_timeout = 0;
}

guint
purple_conv_im_get_send_typed_timeout(const PurpleConvIm *im)
{
	g_return_val_if_fail(im != NULL, 0);

	return im->send_typed_timeout;
}

void
purple_conv_im_update_typing(PurpleConvIm *im)
{
	g_return_if_fail(im != NULL);

	purple_conversation_update(purple_conv_im_get_conversation(im),
							 PURPLE_CONV_UPDATE_TYPING);
}

void
purple_conv_im_write(PurpleConvIm *im, const char *who, const char *message,
			  PurpleMessageFlags flags, time_t mtime)
{
	PurpleConversation *c;

	g_return_if_fail(im != NULL);
	g_return_if_fail(message != NULL);

	c = purple_conv_im_get_conversation(im);

	if ((flags & PURPLE_MESSAGE_RECV) == PURPLE_MESSAGE_RECV) {
		purple_conv_im_set_typing_state(im, PURPLE_NOT_TYPING);
	}

	/* Pass this on to either the ops structure or the default write func. */
	if (c->ui_ops != NULL && c->ui_ops->write_im != NULL)
		c->ui_ops->write_im(c, who, message, flags, mtime);
	else
		purple_conversation_write(c, who, message, flags, mtime);
}

gboolean purple_conv_present_error(const char *who, PurpleAccount *account, const char *what)
{
	PurpleConversation *conv;

	g_return_val_if_fail(who != NULL, FALSE);
	g_return_val_if_fail(account !=NULL, FALSE);
	g_return_val_if_fail(what != NULL, FALSE);

	conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_ANY, who, account);
	if (conv != NULL)
		purple_conversation_write(conv, NULL, what, PURPLE_MESSAGE_ERROR, time(NULL));
	else
		return FALSE;

	return TRUE;
}

void
purple_conv_im_send(PurpleConvIm *im, const char *message)
{
	purple_conv_im_send_with_flags(im, message, 0);
}

static void
purple_conv_send_confirm_cb(gpointer *data)
{
	PurpleConversation *conv = data[0];
	char *message = data[1];

	g_free(data);
	common_send(conv, message, 0);
}

void
purple_conv_send_confirm(PurpleConversation *conv, const char *message)
{
	char *text;
	gpointer *data;

	g_return_if_fail(conv != NULL);
	g_return_if_fail(message != NULL);

	if (conv->ui_ops != NULL && conv->ui_ops->send_confirm != NULL)
	{
		conv->ui_ops->send_confirm(conv, message);
		return;
	}

	text = g_strdup_printf("You are about to send the following message:\n%s", message);
	data = g_new0(gpointer, 2);
	data[0] = conv;
	data[1] = (gpointer)message;

	purple_request_action(conv, NULL, _("Send Message"), text, 0,
						  purple_conversation_get_account(conv), NULL, conv,
						  data, 2,
						  _("_Send Message"), G_CALLBACK(purple_conv_send_confirm_cb),
						  _("Cancel"), NULL);
}

void
purple_conv_im_send_with_flags(PurpleConvIm *im, const char *message, PurpleMessageFlags flags)
{
	g_return_if_fail(im != NULL);
	g_return_if_fail(message != NULL);

	common_send(purple_conv_im_get_conversation(im), message, flags);
}

gboolean
purple_conv_custom_smiley_add(PurpleConversation *conv, const char *smile,
                            const char *cksum_type, const char *chksum,
							gboolean remote)
{
	if (conv == NULL || smile == NULL || !*smile) {
		return FALSE;
	}

	/* TODO: check if the icon is in the cache and return false if so */
	/* TODO: add an icon cache (that doesn't suck) */
	if (conv->ui_ops != NULL && conv->ui_ops->custom_smiley_add !=NULL) {
		return conv->ui_ops->custom_smiley_add(conv, smile, remote);
	} else {
		purple_debug_info("conversation", "Could not find add custom smiley function");
		return FALSE;
	}

}

void
purple_conv_custom_smiley_write(PurpleConversation *conv, const char *smile,
                                   const guchar *data, gsize size)
{
	g_return_if_fail(conv != NULL);
	g_return_if_fail(smile != NULL && *smile);

	if (conv->ui_ops != NULL && conv->ui_ops->custom_smiley_write != NULL)
		conv->ui_ops->custom_smiley_write(conv, smile, data, size);
	else
		purple_debug_info("conversation", "Could not find the smiley write function");
}

void
purple_conv_custom_smiley_close(PurpleConversation *conv, const char *smile)
{
	g_return_if_fail(conv != NULL);
	g_return_if_fail(smile != NULL && *smile);

	if (conv->ui_ops != NULL && conv->ui_ops->custom_smiley_close != NULL)
		conv->ui_ops->custom_smiley_close(conv, smile);
	else
		purple_debug_info("conversation", "Could not find custom smiley close function");
}


/**************************************************************************
 * Chat Conversation API
 **************************************************************************/

PurpleConversation *
purple_conv_chat_get_conversation(const PurpleConvChat *chat)
{
	g_return_val_if_fail(chat != NULL, NULL);

	return chat->conv;
}

GList *
purple_conv_chat_set_users(PurpleConvChat *chat, GList *users)
{
	g_return_val_if_fail(chat != NULL, NULL);

	chat->in_room = users;

	return users;
}

GList *
purple_conv_chat_get_users(const PurpleConvChat *chat)
{
	g_return_val_if_fail(chat != NULL, NULL);

	return chat->in_room;
}

void
purple_conv_chat_ignore(PurpleConvChat *chat, const char *name)
{
	g_return_if_fail(chat != NULL);
	g_return_if_fail(name != NULL);

	/* Make sure the user isn't already ignored. */
	if (purple_conv_chat_is_user_ignored(chat, name))
		return;

	purple_conv_chat_set_ignored(chat,
		g_list_append(chat->ignored, g_strdup(name)));
}

void
purple_conv_chat_unignore(PurpleConvChat *chat, const char *name)
{
	GList *item;

	g_return_if_fail(chat != NULL);
	g_return_if_fail(name != NULL);

	/* Make sure the user is actually ignored. */
	if (!purple_conv_chat_is_user_ignored(chat, name))
		return;

	item = g_list_find(purple_conv_chat_get_ignored(chat),
					   purple_conv_chat_get_ignored_user(chat, name));

	purple_conv_chat_set_ignored(chat,
		g_list_remove_link(chat->ignored, item));

	g_free(item->data);
	g_list_free_1(item);
}

GList *
purple_conv_chat_set_ignored(PurpleConvChat *chat, GList *ignored)
{
	g_return_val_if_fail(chat != NULL, NULL);

	chat->ignored = ignored;

	return ignored;
}

GList *
purple_conv_chat_get_ignored(const PurpleConvChat *chat)
{
	g_return_val_if_fail(chat != NULL, NULL);

	return chat->ignored;
}

const char *
purple_conv_chat_get_ignored_user(const PurpleConvChat *chat, const char *user)
{
	GList *ignored;

	g_return_val_if_fail(chat != NULL, NULL);
	g_return_val_if_fail(user != NULL, NULL);

	for (ignored = purple_conv_chat_get_ignored(chat);
		 ignored != NULL;
		 ignored = ignored->next) {

		const char *ign = (const char *)ignored->data;

		if (!purple_utf8_strcasecmp(user, ign) ||
			((*ign == '+' || *ign == '%') && !purple_utf8_strcasecmp(user, ign + 1)))
			return ign;

		if (*ign == '@') {
			ign++;

			if ((*ign == '+' && !purple_utf8_strcasecmp(user, ign + 1)) ||
				(*ign != '+' && !purple_utf8_strcasecmp(user, ign)))
				return ign;
		}
	}

	return NULL;
}

gboolean
purple_conv_chat_is_user_ignored(const PurpleConvChat *chat, const char *user)
{
	g_return_val_if_fail(chat != NULL, FALSE);
	g_return_val_if_fail(user != NULL, FALSE);

	return (purple_conv_chat_get_ignored_user(chat, user) != NULL);
}

void
purple_conv_chat_set_topic(PurpleConvChat *chat, const char *who, const char *topic)
{
	g_return_if_fail(chat != NULL);

	g_free(chat->who);
	g_free(chat->topic);

	chat->who   = g_strdup(who);
	chat->topic = g_strdup(topic);

	purple_conversation_update(purple_conv_chat_get_conversation(chat),
							 PURPLE_CONV_UPDATE_TOPIC);

	purple_signal_emit(purple_conversations_get_handle(), "chat-topic-changed",
					 chat->conv, chat->who, chat->topic);
}

const char *
purple_conv_chat_get_topic(const PurpleConvChat *chat)
{
	g_return_val_if_fail(chat != NULL, NULL);

	return chat->topic;
}

void
purple_conv_chat_set_id(PurpleConvChat *chat, int id)
{
	g_return_if_fail(chat != NULL);

	chat->id = id;
}

int
purple_conv_chat_get_id(const PurpleConvChat *chat)
{
	g_return_val_if_fail(chat != NULL, -1);

	return chat->id;
}

void
purple_conv_chat_write(PurpleConvChat *chat, const char *who, const char *message,
				PurpleMessageFlags flags, time_t mtime)
{
	PurpleAccount *account;
	PurpleConversation *conv;
	PurpleConnection *gc;

	g_return_if_fail(chat != NULL);
	g_return_if_fail(who != NULL);
	g_return_if_fail(message != NULL);

	conv      = purple_conv_chat_get_conversation(chat);
	gc        = purple_conversation_get_gc(conv);
	account   = purple_connection_get_account(gc);

	/* Don't display this if the person who wrote it is ignored. */
	if (purple_conv_chat_is_user_ignored(chat, who))
		return;

	if (mtime < 0) {
		purple_debug_error("conversation",
				"purple_conv_chat_write ignoring negative timestamp\n");
		/* TODO: Would be more appropriate to use a value that indicates
		   that the timestamp is unknown, and surface that in the UI. */
		mtime = time(NULL);
	}

	if (!(flags & PURPLE_MESSAGE_WHISPER)) {
		const char *str;

		str = purple_normalize(account, who);

		if (purple_strequal(str, chat->nick)) {
			flags |= PURPLE_MESSAGE_SEND;
		} else {
			flags |= PURPLE_MESSAGE_RECV;

			if (purple_utf8_has_word(message, chat->nick))
				flags |= PURPLE_MESSAGE_NICK;
		}
	}

	/* Pass this on to either the ops structure or the default write func. */
	if (conv->ui_ops != NULL && conv->ui_ops->write_chat != NULL)
		conv->ui_ops->write_chat(conv, who, message, flags, mtime);
	else
		purple_conversation_write(conv, who, message, flags, mtime);
}

void
purple_conv_chat_send(PurpleConvChat *chat, const char *message)
{
	purple_conv_chat_send_with_flags(chat, message, 0);
}

void
purple_conv_chat_send_with_flags(PurpleConvChat *chat, const char *message, PurpleMessageFlags flags)
{
	g_return_if_fail(chat != NULL);
	g_return_if_fail(message != NULL);

	common_send(purple_conv_chat_get_conversation(chat), message, flags);
}

void
purple_conv_chat_add_user(PurpleConvChat *chat, const char *user,
						const char *extra_msg, PurpleConvChatBuddyFlags flags,
						gboolean new_arrival)
{
	GList *users = g_list_append(NULL, (char *)user);
	GList *extra_msgs = g_list_append(NULL, (char *)extra_msg);
	GList *flags2 = g_list_append(NULL, GINT_TO_POINTER(flags));

	purple_conv_chat_add_users(chat, users, extra_msgs, flags2, new_arrival);

	g_list_free(users);
	g_list_free(extra_msgs);
	g_list_free(flags2);
}

static int
purple_conv_chat_cb_compare(PurpleConvChatBuddy *a, PurpleConvChatBuddy *b)
{
	PurpleConvChatBuddyFlags f1 = 0, f2 = 0;
	char *user1 = NULL, *user2 = NULL;
	gint ret = 0;

	if (a) {
		f1 = a->flags;
		if (a->alias_key)
			user1 = a->alias_key;
		else if (a->name)
			user1 = a->name;
	}

	if (b) {
		f2 = b->flags;
		if (b->alias_key)
			user2 = b->alias_key;
		else if (b->name)
			user2 = b->name;
	}

	if (user1 == NULL || user2 == NULL) {
		if (!(user1 == NULL && user2 == NULL))
			ret = (user1 == NULL) ? -1: 1;
	} else if (f1 != f2) {
		/* sort more important users first */
		ret = (f1 > f2) ? -1 : 1;
	} else if (a->buddy != b->buddy) {
		ret = a->buddy ? -1 : 1;
	} else {
		ret = purple_utf8_strcasecmp(user1, user2);
	}

	return ret;
}

void
purple_conv_chat_add_users(PurpleConvChat *chat, GList *users, GList *extra_msgs,
						 GList *flags, gboolean new_arrivals)
{
	PurpleConversation *conv;
	PurpleConversationUiOps *ops;
	PurpleConvChatBuddy *cbuddy;
	PurpleConnection *gc;
	PurplePluginProtocolInfo *prpl_info;
	GList *ul, *fl;
	GList *cbuddies = NULL;

	g_return_if_fail(chat  != NULL);
	g_return_if_fail(users != NULL);

	conv = purple_conv_chat_get_conversation(chat);
	ops  = purple_conversation_get_ui_ops(conv);

	gc = purple_conversation_get_gc(conv);
	g_return_if_fail(gc != NULL);
	prpl_info = PURPLE_PLUGIN_PROTOCOL_INFO(purple_connection_get_prpl(gc));
	g_return_if_fail(prpl_info != NULL);

	ul = users;
	fl = flags;
	while ((ul != NULL) && (fl != NULL)) {
		const char *user = (const char *)ul->data;
		const char *alias = user;
		gboolean quiet;
		PurpleConvChatBuddyFlags flag = GPOINTER_TO_INT(fl->data);
		const char *extra_msg = (extra_msgs ? extra_msgs->data : NULL);

		if(!(prpl_info->options & OPT_PROTO_UNIQUE_CHATNAME)) {
			if (purple_strequal(chat->nick, purple_normalize(conv->account, user))) {
				const char *alias2 = purple_account_get_alias(conv->account);
				if (alias2 != NULL)
					alias = alias2;
				else
				{
					const char *display_name = purple_connection_get_display_name(gc);
					if (display_name != NULL)
						alias = display_name;
				}
			} else {
				PurpleBuddy *buddy;
				if ((buddy = purple_find_buddy(gc->account, user)) != NULL)
					alias = purple_buddy_get_contact_alias(buddy);
			}
		}

		quiet = GPOINTER_TO_INT(purple_signal_emit_return_1(purple_conversations_get_handle(),
						 "chat-buddy-joining", conv, user, flag)) ||
				purple_conv_chat_is_user_ignored(chat, user);

		cbuddy = purple_conv_chat_cb_new(user, alias, flag);
		cbuddy->buddy = purple_find_buddy(conv->account, user) != NULL;

		chat->in_room = g_list_prepend(chat->in_room, cbuddy);
		g_hash_table_replace(chat->users, g_strdup(cbuddy->name), cbuddy);

		cbuddies = g_list_prepend(cbuddies, cbuddy);

		if (!quiet && new_arrivals) {
			char *alias_esc = g_markup_escape_text(alias, -1);
			char *tmp;

			if (extra_msg == NULL)
				tmp = g_strdup_printf(_("%s entered the room."), alias_esc);
			else {
				char *extra_msg_esc = g_markup_escape_text(extra_msg, -1);
				tmp = g_strdup_printf(_("%s [<I>%s</I>] entered the room."),
				                      alias_esc, extra_msg_esc);
				g_free(extra_msg_esc);
			}
			g_free(alias_esc);

			purple_conversation_write(conv, NULL, tmp,
					PURPLE_MESSAGE_SYSTEM | PURPLE_MESSAGE_NO_LINKIFY,
					time(NULL));
			g_free(tmp);
		}

		purple_signal_emit(purple_conversations_get_handle(),
						 "chat-buddy-joined", conv, user, flag, new_arrivals);
		ul = ul->next;
		fl = fl->next;
		if (extra_msgs != NULL)
			extra_msgs = extra_msgs->next;
	}

	cbuddies = g_list_sort(cbuddies, (GCompareFunc)purple_conv_chat_cb_compare);

	if (ops != NULL && ops->chat_add_users != NULL)
		ops->chat_add_users(conv, cbuddies, new_arrivals);

	g_list_free(cbuddies);
}

void
purple_conv_chat_rename_user(PurpleConvChat *chat, const char *old_user,
						   const char *new_user)
{
	PurpleConversation *conv;
	PurpleConversationUiOps *ops;
	PurpleConnection *gc;
	PurplePluginProtocolInfo *prpl_info;
	PurpleConvChatBuddy *cb;
	PurpleConvChatBuddyFlags flags;
	const char *new_alias = new_user;
	char tmp[BUF_LONG];
	gboolean is_me = FALSE;

	g_return_if_fail(chat != NULL);
	g_return_if_fail(old_user != NULL);
	g_return_if_fail(new_user != NULL);

	conv = purple_conv_chat_get_conversation(chat);
	ops  = purple_conversation_get_ui_ops(conv);

	gc = purple_conversation_get_gc(conv);
	g_return_if_fail(gc != NULL);
	prpl_info = PURPLE_PLUGIN_PROTOCOL_INFO(purple_connection_get_prpl(gc));
	g_return_if_fail(prpl_info != NULL);

	if (purple_strequal(chat->nick, purple_normalize(conv->account, old_user))) {
		const char *alias;

		/* Note this for later. */
		is_me = TRUE;

		if(!(prpl_info->options & OPT_PROTO_UNIQUE_CHATNAME)) {
			alias = purple_account_get_alias(conv->account);
			if (alias != NULL)
				new_alias = alias;
			else
			{
				const char *display_name = purple_connection_get_display_name(gc);
				if (display_name != NULL)
					alias = display_name;
			}
		}
	} else if (!(prpl_info->options & OPT_PROTO_UNIQUE_CHATNAME)) {
		PurpleBuddy *buddy;
		if ((buddy = purple_find_buddy(gc->account, new_user)) != NULL)
			new_alias = purple_buddy_get_contact_alias(buddy);
	}

	flags = purple_conv_chat_user_get_flags(chat, old_user);
	cb = purple_conv_chat_cb_new(new_user, new_alias, flags);
	cb->buddy = purple_find_buddy(conv->account, new_user) != NULL;

	chat->in_room = g_list_prepend(chat->in_room, cb);
	g_hash_table_replace(chat->users, g_strdup(cb->name), cb);

	if (ops != NULL && ops->chat_rename_user != NULL)
		ops->chat_rename_user(conv, old_user, new_user, new_alias);

	cb = purple_conv_chat_cb_find(chat, old_user);

	if (cb) {
		chat->in_room = g_list_remove(chat->in_room, cb);
		g_hash_table_remove(chat->users, cb->name);
		purple_conv_chat_cb_destroy(cb);
	}

	if (purple_conv_chat_is_user_ignored(chat, old_user)) {
		purple_conv_chat_unignore(chat, old_user);
		purple_conv_chat_ignore(chat, new_user);
	}
	else if (purple_conv_chat_is_user_ignored(chat, new_user))
		purple_conv_chat_unignore(chat, new_user);

	if (is_me)
		purple_conv_chat_set_nick(chat, new_user);

	if (purple_prefs_get_bool("/purple/conversations/chat/show_nick_change") &&
	    !purple_conv_chat_is_user_ignored(chat, new_user)) {

		if (is_me) {
			char *escaped = g_markup_escape_text(new_user, -1);
			g_snprintf(tmp, sizeof(tmp),
					_("You are now known as %s"), escaped);
			g_free(escaped);
		} else {
			const char *old_alias = old_user;
			const char *new_alias = new_user;
			char *escaped;
			char *escaped2;

			if (!(prpl_info->options & OPT_PROTO_UNIQUE_CHATNAME)) {
				PurpleBuddy *buddy;

				if ((buddy = purple_find_buddy(gc->account, old_user)) != NULL)
					old_alias = purple_buddy_get_contact_alias(buddy);
				if ((buddy = purple_find_buddy(gc->account, new_user)) != NULL)
					new_alias = purple_buddy_get_contact_alias(buddy);
			}

			escaped = g_markup_escape_text(old_alias, -1);
			escaped2 = g_markup_escape_text(new_alias, -1);
			g_snprintf(tmp, sizeof(tmp),
					_("%s is now known as %s"), escaped, escaped2);
			g_free(escaped);
			g_free(escaped2);
		}

		purple_conversation_write(conv, NULL, tmp,
				PURPLE_MESSAGE_SYSTEM | PURPLE_MESSAGE_NO_LINKIFY,
				time(NULL));
	}
}

void
purple_conv_chat_remove_user(PurpleConvChat *chat, const char *user, const char *reason)
{
	GList *users = g_list_append(NULL, (char *)user);

	purple_conv_chat_remove_users(chat, users, reason);

	g_list_free(users);
}

void
purple_conv_chat_remove_users(PurpleConvChat *chat, GList *users, const char *reason)
{
	PurpleConversation *conv;
	PurpleConnection *gc;
	PurplePluginProtocolInfo *prpl_info;
	PurpleConversationUiOps *ops;
	PurpleConvChatBuddy *cb;
	GList *l;
	gboolean quiet;

	g_return_if_fail(chat  != NULL);
	g_return_if_fail(users != NULL);

	conv = purple_conv_chat_get_conversation(chat);

	gc = purple_conversation_get_gc(conv);
	g_return_if_fail(gc != NULL);
	prpl_info = PURPLE_PLUGIN_PROTOCOL_INFO(purple_connection_get_prpl(gc));
	g_return_if_fail(prpl_info != NULL);

	ops  = purple_conversation_get_ui_ops(conv);

	for (l = users; l != NULL; l = l->next) {
		const char *user = (const char *)l->data;
		quiet = GPOINTER_TO_INT(purple_signal_emit_return_1(purple_conversations_get_handle(),
					"chat-buddy-leaving", conv, user, reason)) |
				purple_conv_chat_is_user_ignored(chat, user);

		cb = purple_conv_chat_cb_find(chat, user);

		if (cb) {
			chat->in_room = g_list_remove(chat->in_room, cb);
			g_hash_table_remove(chat->users, cb->name);
			purple_conv_chat_cb_destroy(cb);
		}

		/* NOTE: Don't remove them from ignored in case they re-enter. */

		if (!quiet) {
			const char *alias = user;
			char *alias_esc;
			char *tmp;

			if (!(prpl_info->options & OPT_PROTO_UNIQUE_CHATNAME)) {
				PurpleBuddy *buddy;

				if ((buddy = purple_find_buddy(gc->account, user)) != NULL)
					alias = purple_buddy_get_contact_alias(buddy);
			}

			alias_esc = g_markup_escape_text(alias, -1);

			if (reason == NULL || !*reason)
				tmp = g_strdup_printf(_("%s left the room."), alias_esc);
			else {
				char *reason_esc = g_markup_escape_text(reason, -1);
				tmp = g_strdup_printf(_("%s left the room (%s)."),
				                      alias_esc, reason_esc);
				g_free(reason_esc);
			}
			g_free(alias_esc);

			purple_conversation_write(conv, NULL, tmp,
					PURPLE_MESSAGE_SYSTEM | PURPLE_MESSAGE_NO_LINKIFY,
					time(NULL));
			g_free(tmp);
		}

		purple_signal_emit(purple_conversations_get_handle(), "chat-buddy-left",
						 conv, user, reason);
	}

	if (ops != NULL && ops->chat_remove_users != NULL)
		ops->chat_remove_users(conv, users);
}

void
purple_conv_chat_clear_users(PurpleConvChat *chat)
{
	PurpleConversation *conv;
	PurpleConversationUiOps *ops;
	GList *users;
	GList *l;
	GList *names = NULL;

	g_return_if_fail(chat != NULL);

	conv  = purple_conv_chat_get_conversation(chat);
	ops   = purple_conversation_get_ui_ops(conv);
	users = chat->in_room;

	if (ops != NULL && ops->chat_remove_users != NULL) {
		for (l = users; l; l = l->next) {
			PurpleConvChatBuddy *cb = l->data;
			names = g_list_prepend(names, cb->name);
		}
		ops->chat_remove_users(conv, names);
		g_list_free(names);
	}

	for (l = users; l; l = l->next)
	{
		PurpleConvChatBuddy *cb = l->data;

		purple_signal_emit(purple_conversations_get_handle(),
						 "chat-buddy-leaving", conv, cb->name, NULL);
		purple_signal_emit(purple_conversations_get_handle(),
						 "chat-buddy-left", conv, cb->name, NULL);

		purple_conv_chat_cb_destroy(cb);
	}

	g_hash_table_remove_all(chat->users);

	g_list_free(users);
	chat->in_room = NULL;
}


gboolean
purple_conv_chat_find_user(PurpleConvChat *chat, const char *user)
{
	g_return_val_if_fail(chat != NULL, FALSE);
	g_return_val_if_fail(user != NULL, FALSE);

	return (purple_conv_chat_cb_find(chat, user) != NULL);
}

void
purple_conv_chat_user_set_flags(PurpleConvChat *chat, const char *user,
							  PurpleConvChatBuddyFlags flags)
{
	PurpleConversation *conv;
	PurpleConversationUiOps *ops;
	PurpleConvChatBuddy *cb;
	PurpleConvChatBuddyFlags oldflags;

	g_return_if_fail(chat != NULL);
	g_return_if_fail(user != NULL);

	cb = purple_conv_chat_cb_find(chat, user);

	if (!cb)
		return;

	if (flags == cb->flags)
		return;

	oldflags = cb->flags;
	cb->flags = flags;

	conv = purple_conv_chat_get_conversation(chat);
	ops = purple_conversation_get_ui_ops(conv);

	if (ops != NULL && ops->chat_update_user != NULL)
		ops->chat_update_user(conv, user);

	purple_signal_emit(purple_conversations_get_handle(),
					 "chat-buddy-flags", conv, user, oldflags, flags);
}

PurpleConvChatBuddyFlags
purple_conv_chat_user_get_flags(PurpleConvChat *chat, const char *user)
{
	PurpleConvChatBuddy *cb;

	g_return_val_if_fail(chat != NULL, 0);
	g_return_val_if_fail(user != NULL, 0);

	cb = purple_conv_chat_cb_find(chat, user);

	if (!cb)
		return PURPLE_CBFLAGS_NONE;

	return cb->flags;
}

void purple_conv_chat_set_nick(PurpleConvChat *chat, const char *nick) {
	g_return_if_fail(chat != NULL);

	g_free(chat->nick);
	chat->nick = g_strdup(purple_normalize(chat->conv->account, nick));
}

const char *purple_conv_chat_get_nick(PurpleConvChat *chat) {
	g_return_val_if_fail(chat != NULL, NULL);

	return chat->nick;
}

PurpleConversation *
purple_find_chat(const PurpleConnection *gc, int id)
{
	GList *l;
	PurpleConversation *conv;

	for (l = purple_get_chats(); l != NULL; l = l->next) {
		conv = (PurpleConversation *)l->data;

		if (purple_conv_chat_get_id(PURPLE_CONV_CHAT(conv)) == id &&
			purple_conversation_get_gc(conv) == gc)
			return conv;
	}

	return NULL;
}

void
purple_conv_chat_left(PurpleConvChat *chat)
{
	g_return_if_fail(chat != NULL);

	chat->left = TRUE;
	purple_conversation_update(chat->conv, PURPLE_CONV_UPDATE_CHATLEFT);
}

static void
invite_user_to_chat(gpointer data, PurpleRequestFields *fields)
{
	PurpleConversation *conv;
	PurpleConvChat *chat;
	const char *user, *message;

	conv = data;
	chat = PURPLE_CONV_CHAT(conv);
	user = purple_request_fields_get_string(fields, "screenname");
	message = purple_request_fields_get_string(fields, "message");

	serv_chat_invite(purple_conversation_get_gc(conv), chat->id, message, user);
}

void purple_conv_chat_invite_user(PurpleConvChat *chat, const char *user,
		const char *message, gboolean confirm)
{
	PurpleAccount *account;
	PurpleConversation *conv;
	PurpleRequestFields *fields;
	PurpleRequestFieldGroup *group;
	PurpleRequestField *field;

	g_return_if_fail(chat);

	if (!user || !*user || !message || !*message)
		confirm = TRUE;

	conv = chat->conv;
	account = conv->account;

	if (!confirm) {
		serv_chat_invite(purple_account_get_connection(account),
				purple_conv_chat_get_id(chat), message, user);
		return;
	}

	fields = purple_request_fields_new();
	group = purple_request_field_group_new(_("Invite to chat"));
	purple_request_fields_add_group(fields, group);

	field = purple_request_field_string_new("screenname", _("Buddy"), user, FALSE);
	purple_request_field_group_add_field(group, field);
	purple_request_field_set_required(field, TRUE);
	purple_request_field_set_type_hint(field, "screenname");

	field = purple_request_field_string_new("message", _("Message"), message, FALSE);
	purple_request_field_group_add_field(group, field);

	purple_request_fields(conv, _("Invite to chat"), NULL,
			_("Please enter the name of the user you wish to invite, "
				"along with an optional invite message."),
			fields,
			_("Invite"), G_CALLBACK(invite_user_to_chat),
			_("Cancel"), NULL,
			account, user, conv,
			conv);
}

gboolean
purple_conv_chat_has_left(PurpleConvChat *chat)
{
	g_return_val_if_fail(chat != NULL, TRUE);

	return chat->left;
}

PurpleConvChatBuddy *
purple_conv_chat_cb_new(const char *name, const char *alias, PurpleConvChatBuddyFlags flags)
{
	PurpleConvChatBuddy *cb;

	g_return_val_if_fail(name != NULL, NULL);

	cb = g_new0(PurpleConvChatBuddy, 1);
	cb->name = g_strdup(name);
	cb->flags = flags;
	cb->alias = g_strdup(alias);
	cb->attributes = g_hash_table_new_full(g_str_hash, g_str_equal,
										   g_free, g_free);

	PURPLE_DBUS_REGISTER_POINTER(cb, PurpleConvChatBuddy);
	return cb;
}

PurpleConvChatBuddy *
purple_conv_chat_cb_find(PurpleConvChat *chat, const char *name)
{
	g_return_val_if_fail(chat != NULL, NULL);
	g_return_val_if_fail(name != NULL, NULL);

	return g_hash_table_lookup(chat->users, name);
}

void
purple_conv_chat_cb_destroy(PurpleConvChatBuddy *cb)
{
	if (cb == NULL)
		return;

	purple_signal_emit(purple_conversations_get_handle(),
			"deleting-chat-buddy", cb);

	g_free(cb->alias);
	g_free(cb->alias_key);
	g_free(cb->name);
	g_hash_table_destroy(cb->attributes);

	PURPLE_DBUS_UNREGISTER_POINTER(cb);
	g_free(cb);
}

const char *
purple_conv_chat_cb_get_name(PurpleConvChatBuddy *cb)
{
	g_return_val_if_fail(cb != NULL, NULL);

	return cb->name;
}

const char *
purple_conv_chat_cb_get_attribute(PurpleConvChatBuddy *cb, const char *key)
{
	g_return_val_if_fail(cb != NULL, NULL);
	g_return_val_if_fail(key != NULL, NULL);
	
	return g_hash_table_lookup(cb->attributes, key);
}

static void
append_attribute_key(gpointer key, gpointer value, gpointer user_data)
{
	GList **list = user_data;
	*list = g_list_prepend(*list, key);
}

GList *
purple_conv_chat_cb_get_attribute_keys(PurpleConvChatBuddy *cb)
{
	GList *keys = NULL;
	
	g_return_val_if_fail(cb != NULL, NULL);
	
	g_hash_table_foreach(cb->attributes, (GHFunc)append_attribute_key, &keys);
	
	return keys;
}

void
purple_conv_chat_cb_set_attribute(PurpleConvChat *chat, PurpleConvChatBuddy *cb, const char *key, const char *value)
{
	PurpleConversation *conv;
	PurpleConversationUiOps *ops;
	
	g_return_if_fail(cb != NULL);
	g_return_if_fail(key != NULL);
	g_return_if_fail(value != NULL);
	
	g_hash_table_replace(cb->attributes, g_strdup(key), g_strdup(value));
	
	conv = purple_conv_chat_get_conversation(chat);
	ops = purple_conversation_get_ui_ops(conv);
	
	if (ops != NULL && ops->chat_update_user != NULL)
		ops->chat_update_user(conv, cb->name);
}

void
purple_conv_chat_cb_set_attributes(PurpleConvChat *chat, PurpleConvChatBuddy *cb, GList *keys, GList *values)
{
	PurpleConversation *conv;
	PurpleConversationUiOps *ops;
	
	g_return_if_fail(cb != NULL);
	g_return_if_fail(keys != NULL);
	g_return_if_fail(values != NULL);
	
	while (keys != NULL && values != NULL) {
		g_hash_table_replace(cb->attributes, g_strdup(keys->data), g_strdup(values->data));
		keys = g_list_next(keys);
		values = g_list_next(values);
	}
	
	conv = purple_conv_chat_get_conversation(chat);
	ops = purple_conversation_get_ui_ops(conv);
	
	if (ops != NULL && ops->chat_update_user != NULL)
		ops->chat_update_user(conv, cb->name);
}

GList *
purple_conversation_get_extended_menu(PurpleConversation *conv)
{
	GList *menu = NULL;

	g_return_val_if_fail(conv != NULL, NULL);

	purple_signal_emit(purple_conversations_get_handle(),
			"conversation-extended-menu", conv, &menu);
	return menu;
}

void purple_conversation_clear_message_history(PurpleConversation *conv)
{
	GList *list = conv->message_history;
	message_history_free(list);
	conv->message_history = NULL;

	purple_signal_emit(purple_conversations_get_handle(),
			"cleared-message-history", conv);
}

GList *purple_conversation_get_message_history(PurpleConversation *conv)
{
	return conv->message_history;
}

const char *purple_conversation_message_get_sender(PurpleConvMessage *msg)
{
	g_return_val_if_fail(msg, NULL);
	return msg->who;
}

const char *purple_conversation_message_get_message(PurpleConvMessage *msg)
{
	g_return_val_if_fail(msg, NULL);
	return msg->what;
}

PurpleMessageFlags purple_conversation_message_get_flags(PurpleConvMessage *msg)
{
	g_return_val_if_fail(msg, 0);
	return msg->flags;
}

time_t purple_conversation_message_get_timestamp(PurpleConvMessage *msg)
{
	g_return_val_if_fail(msg, 0);
	return msg->when;
}

gboolean
purple_conversation_do_command(PurpleConversation *conv, const gchar *cmdline,
				const gchar *markup, gchar **error)
{
	char *mark = (markup && *markup) ? NULL : g_markup_escape_text(cmdline, -1), *err = NULL;
	PurpleCmdStatus status = purple_cmd_do_command(conv, cmdline, mark ? mark : markup, error ? error : &err);
	g_free(mark);
	g_free(err);
	return (status == PURPLE_CMD_STATUS_OK);
}

void *
purple_conversations_get_handle(void)
{
	static int handle;

	return &handle;
}

void
purple_conversations_init(void)
{
	void *handle = purple_conversations_get_handle();

	conversation_cache = g_hash_table_new_full((GHashFunc)_purple_conversations_hconv_hash,
						(GEqualFunc)_purple_conversations_hconv_equal,
						(GDestroyNotify)_purple_conversations_hconv_free_key, NULL);

	/**********************************************************************
	 * Register preferences
	 **********************************************************************/

	/* Conversations */
	purple_prefs_add_none("/purple/conversations");

	/* Conversations -> Chat */
	purple_prefs_add_none("/purple/conversations/chat");
	purple_prefs_add_bool("/purple/conversations/chat/show_nick_change", TRUE);

	/* Conversations -> IM */
	purple_prefs_add_none("/purple/conversations/im");
	purple_prefs_add_bool("/purple/conversations/im/send_typing", TRUE);


	/**********************************************************************
	 * Register signals
	 **********************************************************************/
	purple_signal_register(handle, "writing-im-msg",
						 purple_marshal_BOOLEAN__POINTER_POINTER_POINTER_POINTER_UINT,
						 purple_value_new(PURPLE_TYPE_BOOLEAN), 5,
						 purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_ACCOUNT),
						 purple_value_new(PURPLE_TYPE_STRING),
						 purple_value_new_outgoing(PURPLE_TYPE_STRING),
						 purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_CONVERSATION),
						 purple_value_new(PURPLE_TYPE_UINT));

	purple_signal_register(handle, "wrote-im-msg",
						 purple_marshal_VOID__POINTER_POINTER_POINTER_POINTER_UINT,
						 NULL, 5,
						 purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_ACCOUNT),
						 purple_value_new(PURPLE_TYPE_STRING),
						 purple_value_new(PURPLE_TYPE_STRING),
						 purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_CONVERSATION),
						 purple_value_new(PURPLE_TYPE_UINT));

	purple_signal_register(handle, "sent-attention",
						 purple_marshal_VOID__POINTER_POINTER_POINTER_UINT,
						 NULL, 4,
						 purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_ACCOUNT),
						 purple_value_new(PURPLE_TYPE_STRING),
						 purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_CONVERSATION),
						 purple_value_new(PURPLE_TYPE_UINT));

	purple_signal_register(handle, "got-attention",
						 purple_marshal_VOID__POINTER_POINTER_POINTER_UINT,
						 NULL, 4,
						 purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_ACCOUNT),
						 purple_value_new(PURPLE_TYPE_STRING),
						 purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_CONVERSATION),
						 purple_value_new(PURPLE_TYPE_UINT));

	purple_signal_register(handle, "sending-im-msg",
						 purple_marshal_VOID__POINTER_POINTER_POINTER,
						 NULL, 3,
						 purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_ACCOUNT),
						 purple_value_new(PURPLE_TYPE_STRING),
						 purple_value_new_outgoing(PURPLE_TYPE_STRING));

	purple_signal_register(handle, "sent-im-msg",
						 purple_marshal_VOID__POINTER_POINTER_POINTER,
						 NULL, 3,
						 purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_ACCOUNT),
						 purple_value_new(PURPLE_TYPE_STRING),
						 purple_value_new(PURPLE_TYPE_STRING));

	purple_signal_register(handle, "receiving-im-msg",
						 purple_marshal_BOOLEAN__POINTER_POINTER_POINTER_POINTER_POINTER,
						 purple_value_new(PURPLE_TYPE_BOOLEAN), 5,
						 purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_ACCOUNT),
						 purple_value_new_outgoing(PURPLE_TYPE_STRING),
						 purple_value_new_outgoing(PURPLE_TYPE_STRING),
						 purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_CONVERSATION),
						 purple_value_new_outgoing(PURPLE_TYPE_UINT));

	purple_signal_register(handle, "received-im-msg",
						 purple_marshal_VOID__POINTER_POINTER_POINTER_POINTER_UINT,
						 NULL, 5,
						 purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_ACCOUNT),
						 purple_value_new(PURPLE_TYPE_STRING),
						 purple_value_new(PURPLE_TYPE_STRING),
						 purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_CONVERSATION),
						 purple_value_new(PURPLE_TYPE_UINT));

	purple_signal_register(handle, "blocked-im-msg",
						 purple_marshal_VOID__POINTER_POINTER_POINTER_UINT_UINT,
						 NULL, 5,
						 purple_value_new(PURPLE_TYPE_SUBTYPE,
							 PURPLE_SUBTYPE_ACCOUNT),
						 purple_value_new(PURPLE_TYPE_STRING),
						 purple_value_new(PURPLE_TYPE_STRING),
						 purple_value_new(PURPLE_TYPE_UINT),
						 purple_value_new(PURPLE_TYPE_UINT));

	purple_signal_register(handle, "writing-chat-msg",
						 purple_marshal_BOOLEAN__POINTER_POINTER_POINTER_POINTER_UINT,
						 purple_value_new(PURPLE_TYPE_BOOLEAN), 5,
						 purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_ACCOUNT),
						 purple_value_new(PURPLE_TYPE_STRING),
						 purple_value_new_outgoing(PURPLE_TYPE_STRING),
						 purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_CONVERSATION),
						 purple_value_new(PURPLE_TYPE_UINT));

	purple_signal_register(handle, "wrote-chat-msg",
						 purple_marshal_VOID__POINTER_POINTER_POINTER_POINTER_UINT,
						 NULL, 5,
						 purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_ACCOUNT),
						 purple_value_new(PURPLE_TYPE_STRING),
						 purple_value_new(PURPLE_TYPE_STRING),
						 purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_CONVERSATION),
						 purple_value_new(PURPLE_TYPE_UINT));

	purple_signal_register(handle, "sending-chat-msg",
						 purple_marshal_VOID__POINTER_POINTER_UINT, NULL, 3,
						 purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_ACCOUNT),
						 purple_value_new_outgoing(PURPLE_TYPE_STRING),
						 purple_value_new(PURPLE_TYPE_UINT));

	purple_signal_register(handle, "sent-chat-msg",
						 purple_marshal_VOID__POINTER_POINTER_UINT, NULL, 3,
						 purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_ACCOUNT),
						 purple_value_new(PURPLE_TYPE_STRING),
						 purple_value_new(PURPLE_TYPE_UINT));

	purple_signal_register(handle, "receiving-chat-msg",
						 purple_marshal_BOOLEAN__POINTER_POINTER_POINTER_POINTER_POINTER,
						 purple_value_new(PURPLE_TYPE_BOOLEAN), 5,
						 purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_ACCOUNT),
						 purple_value_new_outgoing(PURPLE_TYPE_STRING),
						 purple_value_new_outgoing(PURPLE_TYPE_STRING),
						 purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_CONVERSATION),
						 purple_value_new_outgoing(PURPLE_TYPE_UINT));

	purple_signal_register(handle, "received-chat-msg",
						 purple_marshal_VOID__POINTER_POINTER_POINTER_POINTER_UINT,
						 NULL, 5,
						 purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_ACCOUNT),
						 purple_value_new(PURPLE_TYPE_STRING),
						 purple_value_new(PURPLE_TYPE_STRING),
						 purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_CONVERSATION),
						 purple_value_new(PURPLE_TYPE_UINT));

	purple_signal_register(handle, "conversation-created",
						 purple_marshal_VOID__POINTER, NULL, 1,
						 purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_CONVERSATION));

	purple_signal_register(handle, "conversation-updated",
						 purple_marshal_VOID__POINTER_UINT, NULL, 2,
						 purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_CONVERSATION),
						 purple_value_new(PURPLE_TYPE_UINT));

	purple_signal_register(handle, "deleting-conversation",
						 purple_marshal_VOID__POINTER, NULL, 1,
						 purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_CONVERSATION));

	purple_signal_register(handle, "buddy-typing",
						 purple_marshal_VOID__POINTER_POINTER, NULL, 2,
						 purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_ACCOUNT),
						 purple_value_new(PURPLE_TYPE_STRING));

	purple_signal_register(handle, "buddy-typed",
						 purple_marshal_VOID__POINTER_POINTER, NULL, 2,
						 purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_ACCOUNT),
						 purple_value_new(PURPLE_TYPE_STRING));

	purple_signal_register(handle, "buddy-typing-stopped",
						 purple_marshal_VOID__POINTER_POINTER, NULL, 2,
						 purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_ACCOUNT),
						 purple_value_new(PURPLE_TYPE_STRING));

	purple_signal_register(handle, "chat-buddy-joining",
						 purple_marshal_BOOLEAN__POINTER_POINTER_UINT,
						 purple_value_new(PURPLE_TYPE_BOOLEAN), 3,
						 purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_CONVERSATION),
						 purple_value_new(PURPLE_TYPE_STRING),
						 purple_value_new(PURPLE_TYPE_UINT));

	purple_signal_register(handle, "chat-buddy-joined",
						 purple_marshal_VOID__POINTER_POINTER_UINT_UINT, NULL, 4,
						 purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_CONVERSATION),
						 purple_value_new(PURPLE_TYPE_STRING),
						 purple_value_new(PURPLE_TYPE_UINT),
						 purple_value_new(PURPLE_TYPE_BOOLEAN));

	purple_signal_register(handle, "chat-buddy-flags",
						 purple_marshal_VOID__POINTER_POINTER_UINT_UINT, NULL, 4,
						 purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_CONVERSATION),
						 purple_value_new(PURPLE_TYPE_STRING),
						 purple_value_new(PURPLE_TYPE_UINT),
						 purple_value_new(PURPLE_TYPE_UINT));

	purple_signal_register(handle, "chat-buddy-leaving",
						 purple_marshal_BOOLEAN__POINTER_POINTER_POINTER,
						 purple_value_new(PURPLE_TYPE_BOOLEAN), 3,
						 purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_CONVERSATION),
						 purple_value_new(PURPLE_TYPE_STRING),
						 purple_value_new(PURPLE_TYPE_STRING));

	purple_signal_register(handle, "chat-buddy-left",
						 purple_marshal_VOID__POINTER_POINTER_POINTER, NULL, 3,
						 purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_CONVERSATION),
						 purple_value_new(PURPLE_TYPE_STRING),
						 purple_value_new(PURPLE_TYPE_STRING));

	purple_signal_register(handle, "deleting-chat-buddy",
						 purple_marshal_VOID__POINTER, NULL, 1,
						 purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_CHATBUDDY));

	purple_signal_register(handle, "chat-inviting-user",
						 purple_marshal_VOID__POINTER_POINTER_POINTER, NULL, 3,
						 purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_CONVERSATION),
						 purple_value_new(PURPLE_TYPE_STRING),
						 purple_value_new_outgoing(PURPLE_TYPE_STRING));

	purple_signal_register(handle, "chat-invited-user",
						 purple_marshal_VOID__POINTER_POINTER_POINTER, NULL, 3,
						 purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_CONVERSATION),
						 purple_value_new(PURPLE_TYPE_STRING),
						 purple_value_new(PURPLE_TYPE_STRING));

	purple_signal_register(handle, "chat-invited",
						 purple_marshal_INT__POINTER_POINTER_POINTER_POINTER_POINTER,
						 purple_value_new(PURPLE_TYPE_INT), 5,
						 purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_ACCOUNT),
						 purple_value_new(PURPLE_TYPE_STRING),
						 purple_value_new(PURPLE_TYPE_STRING),
						 purple_value_new(PURPLE_TYPE_STRING),
						 purple_value_new(PURPLE_TYPE_POINTER));

	purple_signal_register(handle, "chat-invite-blocked",
						 purple_marshal_VOID__POINTER_POINTER_POINTER_POINTER_POINTER,
						 NULL, 5,
						 purple_value_new(PURPLE_TYPE_SUBTYPE,
							 PURPLE_SUBTYPE_ACCOUNT),
						 purple_value_new(PURPLE_TYPE_STRING),
						 purple_value_new(PURPLE_TYPE_STRING),
						 purple_value_new(PURPLE_TYPE_STRING),
						 purple_value_new(PURPLE_TYPE_BOXED, "GHashTable *"));

	purple_signal_register(handle, "chat-joined",
						 purple_marshal_VOID__POINTER, NULL, 1,
						 purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_CONVERSATION));

	purple_signal_register(handle, "chat-join-failed",
						   purple_marshal_VOID__POINTER_POINTER, NULL, 2,
						   purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_CONNECTION),
						   purple_value_new(PURPLE_TYPE_POINTER));

	purple_signal_register(handle, "chat-left",
						 purple_marshal_VOID__POINTER, NULL, 1,
						 purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_CONVERSATION));

	purple_signal_register(handle, "chat-topic-changed",
						 purple_marshal_VOID__POINTER_POINTER_POINTER, NULL, 3,
						 purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_CONVERSATION),
						 purple_value_new(PURPLE_TYPE_STRING),
						 purple_value_new(PURPLE_TYPE_STRING));

	purple_signal_register(handle, "cleared-message-history",
	                       purple_marshal_VOID__POINTER, NULL, 1,
	                       purple_value_new(PURPLE_TYPE_SUBTYPE,
	                                        PURPLE_SUBTYPE_CONVERSATION));

	purple_signal_register(handle, "conversation-extended-menu",
			     purple_marshal_VOID__POINTER_POINTER, NULL, 2,
			     purple_value_new(PURPLE_TYPE_SUBTYPE,
					    PURPLE_SUBTYPE_CONVERSATION),
			     purple_value_new(PURPLE_TYPE_BOXED, "GList **"));
}

void
purple_conversations_uninit(void)
{
	while (conversations)
		purple_conversation_destroy((PurpleConversation*)conversations->data);
	g_hash_table_destroy(conversation_cache);
	purple_signals_unregister_by_instance(purple_conversations_get_handle());
}

