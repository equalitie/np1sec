/*
 * Offline Message Emulation - Save messages sent to an offline user as pounce
 * Copyright (C) 2004
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
#include "internal.h"

#define PLUGIN_ID			"core-plugin_pack-offlinemsg"
#define PLUGIN_NAME			N_("Offline Message Emulation")
#define PLUGIN_STATIC_NAME	offlinemsg
#define PLUGIN_SUMMARY		N_("Save messages sent to an offline user as pounce.")
#define PLUGIN_DESCRIPTION	N_("Save messages sent to an offline user as pounce.")
#define PLUGIN_AUTHOR		"Sadrul H Chowdhury <sadrul@users.sourceforge.net>"

/* Purple headers */
#include <version.h>

#include <blist.h>
#include <conversation.h>
#include <core.h>
#include <debug.h>
#include <pounce.h>
#include <request.h>

#define	PREF_PREFIX		"/plugins/core/" PLUGIN_ID
#define	PREF_ALWAYS		PREF_PREFIX "/always"

typedef struct _OfflineMsg OfflineMsg;

typedef enum
{
	OFFLINE_MSG_NONE,
	OFFLINE_MSG_YES,
	OFFLINE_MSG_NO
} OfflineMessageSetting;

struct _OfflineMsg
{
	PurpleAccount *account;
	PurpleConversation *conv;
	char *who;
	char *message;
};

static void
discard_data(OfflineMsg *offline)
{
	g_free(offline->who);
	g_free(offline->message);
	g_free(offline);
}

static void
cancel_poune(OfflineMsg *offline)
{
	purple_conversation_set_data(offline->conv, "plugin_pack:offlinemsg",
				GINT_TO_POINTER(OFFLINE_MSG_NO));
	purple_conv_im_send_with_flags(PURPLE_CONV_IM(offline->conv), offline->message, 0);
	discard_data(offline);
}

static void
record_pounce(OfflineMsg *offline)
{
	PurplePounce *pounce;
	PurplePounceEvent event;
	PurplePounceOption option;
	PurpleConversation *conv;

	event = PURPLE_POUNCE_SIGNON;
	option = PURPLE_POUNCE_OPTION_NONE;

	pounce = purple_pounce_new(purple_core_get_ui(), offline->account, offline->who,
					event, option);

	purple_pounce_action_set_enabled(pounce, "send-message", TRUE);
	purple_pounce_action_set_attribute(pounce, "send-message", "message", offline->message);

	conv = offline->conv;
	if (!purple_conversation_get_data(conv, "plugin_pack:offlinemsg"))
		purple_conversation_write(conv, NULL, _("The rest of the messages will be saved "
							"as pounces. You can edit/delete the pounce from the `Buddy "
							"Pounce' dialog."),
							PURPLE_MESSAGE_SYSTEM, time(NULL));
	purple_conversation_set_data(conv, "plugin_pack:offlinemsg",
				GINT_TO_POINTER(OFFLINE_MSG_YES));

	purple_conv_im_write(PURPLE_CONV_IM(conv), offline->who, offline->message,
				PURPLE_MESSAGE_SEND, time(NULL));

	discard_data(offline);
}

static void
sending_msg_cb(PurpleAccount *account, const char *who, char **message, gpointer handle)
{
	PurpleBuddy *buddy;
	OfflineMsg *offline;
	PurpleConversation *conv;
	OfflineMessageSetting setting;

	if (message == NULL || *message == NULL ||
			**message == '\0')
		return;

	buddy = purple_find_buddy(account, who);
	if (!buddy)
		return;

	if (purple_presence_is_online(purple_buddy_get_presence(buddy)))
		return;

	if (purple_account_supports_offline_message(account, buddy))
	{
		purple_debug_info("offlinemsg", "Account \"%s\" supports offline messages.\n",
					purple_account_get_username(account));
		return;
	}

	conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM,
					who, account);

	if (!conv)
		return;

	setting = GPOINTER_TO_INT(purple_conversation_get_data(conv, "plugin_pack:offlinemsg"));
	if (setting == OFFLINE_MSG_NO)
		return;

	offline = g_new0(OfflineMsg, 1);
	offline->conv = conv;
	offline->account = account;
	offline->who = g_strdup(who);
	offline->message = *message;
	*message = NULL;

	if (purple_prefs_get_bool(PREF_ALWAYS) || setting == OFFLINE_MSG_YES)
		record_pounce(offline);
	else if (setting == OFFLINE_MSG_NONE)
	{
		char *ask;
		ask = g_strdup_printf(_("\"%s\" is currently offline. Do you want to save the "
						"rest of the messages in a pounce and automatically send them "
						"when \"%s\" logs back in?"), who, who);

		purple_request_action(handle, _("Offline Message"), ask,
					_("You can edit/delete the pounce from the `Buddy Pounces' dialog"),
					0,
					offline->account, offline->who, offline->conv,
					offline, 2,
					_("Yes"), record_pounce,
					_("No"), cancel_poune);
		g_free(ask);
	}
}

static gboolean
plugin_load(PurplePlugin *plugin)
{
	purple_signal_connect_priority(purple_conversations_get_handle(), "sending-im-msg",
					plugin, PURPLE_CALLBACK(sending_msg_cb), plugin, PURPLE_SIGNAL_PRIORITY_HIGHEST);
	return TRUE;
}

static gboolean
plugin_unload(PurplePlugin *plugin)
{
	return TRUE;
}

static PurplePluginPrefFrame *
get_plugin_pref_frame(PurplePlugin *plugin)
{
	PurplePluginPrefFrame *frame;
	PurplePluginPref *pref;

	frame = purple_plugin_pref_frame_new();

	pref = purple_plugin_pref_new_with_label(_("Save offline messages in pounce"));
	purple_plugin_pref_frame_add(frame, pref);

	pref = purple_plugin_pref_new_with_name_and_label(PREF_ALWAYS,
					_("Do not ask. Always save in pounce."));
	purple_plugin_pref_frame_add(frame, pref);

	return frame;
}

static PurplePluginUiInfo prefs_info = {
	get_plugin_pref_frame,
	0,
	NULL,

	/* padding */
	NULL,
	NULL,
	NULL,
	NULL
};

static PurplePluginInfo info =
{
	PURPLE_PLUGIN_MAGIC,			/* Magic				*/
	PURPLE_MAJOR_VERSION,			/* Purple Major Version	*/
	PURPLE_MINOR_VERSION,			/* Purple Minor Version	*/
	PURPLE_PLUGIN_STANDARD,			/* plugin type			*/
	NULL,					/* ui requirement		*/
	0,					/* flags				*/
	NULL,					/* dependencies			*/
	PURPLE_PRIORITY_DEFAULT,			/* priority				*/

	PLUGIN_ID,				/* plugin id			*/
	PLUGIN_NAME,				/* name					*/
	DISPLAY_VERSION,			/* version				*/
	PLUGIN_SUMMARY,				/* summary				*/
	PLUGIN_DESCRIPTION,			/* description			*/
	PLUGIN_AUTHOR,				/* author				*/
	PURPLE_WEBSITE,				/* website				*/

	plugin_load,				/* load					*/
	plugin_unload,				/* unload				*/
	NULL,					/* destroy				*/

	NULL,					/* ui_info				*/
	NULL,					/* extra_info			*/
	&prefs_info,				/* prefs_info			*/
	NULL,					/* actions				*/

	/* padding */
	NULL,
	NULL,
	NULL,
	NULL
};

static void
init_plugin(PurplePlugin *plugin)
{
	purple_prefs_add_none(PREF_PREFIX);
	purple_prefs_add_bool(PREF_ALWAYS, FALSE);
}

PURPLE_INIT_PLUGIN(PLUGIN_STATIC_NAME, init_plugin, info)
