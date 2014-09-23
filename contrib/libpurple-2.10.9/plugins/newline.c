/*
 * Displays messages on a new line, below the nick
 * Copyright (C) 2004 Stu Tomlinson <stu@nosnilmot.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02111-1301, USA.
 */
#include "internal.h"

#include <string.h>

#include <conversation.h>
#include <debug.h>
#include <plugin.h>
#include <signals.h>
#include <util.h>
#include <version.h>

static gboolean
addnewline_msg_cb(PurpleAccount *account, char *sender, char **message,
					 PurpleConversation *conv, int *flags, void *data)
{
	if (((purple_conversation_get_type(conv) == PURPLE_CONV_TYPE_IM) &&
		 !purple_prefs_get_bool("/plugins/core/newline/im")) ||
		((purple_conversation_get_type(conv) == PURPLE_CONV_TYPE_CHAT) &&
		 !purple_prefs_get_bool("/plugins/core/newline/chat")))
		return FALSE;

	if (g_ascii_strncasecmp(*message, "/me ", strlen("/me "))) {
		char *tmp = g_strdup_printf("<br/>%s", *message);
		g_free(*message);
		*message = tmp;
	}

	return FALSE;
}

static PurplePluginPrefFrame *
get_plugin_pref_frame(PurplePlugin *plugin) {
	PurplePluginPrefFrame *frame;
	PurplePluginPref *ppref;

	frame = purple_plugin_pref_frame_new();

	ppref = purple_plugin_pref_new_with_name_and_label(
			"/plugins/core/newline/im", _("Add new line in IMs"));
	purple_plugin_pref_frame_add(frame, ppref);

	ppref = purple_plugin_pref_new_with_name_and_label(
			"/plugins/core/newline/chat", _("Add new line in Chats"));
	purple_plugin_pref_frame_add(frame, ppref);

	return frame;
}


static gboolean
plugin_load(PurplePlugin *plugin)
{
	void *conversation = purple_conversations_get_handle();

	purple_signal_connect(conversation, "writing-im-msg",
						plugin, PURPLE_CALLBACK(addnewline_msg_cb), NULL);
	purple_signal_connect(conversation, "writing-chat-msg",
						plugin, PURPLE_CALLBACK(addnewline_msg_cb), NULL);

	return TRUE;
}

static PurplePluginUiInfo prefs_info = {
	get_plugin_pref_frame,
	0,   /* page_num (Reserved) */
	NULL, /* frame (Reserved) */
	/* Padding */
	NULL,
	NULL,
	NULL,
	NULL
};

static PurplePluginInfo info =
{
	PURPLE_PLUGIN_MAGIC,							/**< magic			*/
	PURPLE_MAJOR_VERSION,							/**< major version	*/
	PURPLE_MINOR_VERSION,							/**< minor version	*/
	PURPLE_PLUGIN_STANDARD,							/**< type			*/
	NULL,											/**< ui_requirement	*/
	0,												/**< flags			*/
	NULL,											/**< dependencies	*/
	PURPLE_PRIORITY_DEFAULT,						/**< priority		*/

	"core-plugin_pack-newline",						/**< id				*/
	N_("New Line"),									/**< name			*/
	DISPLAY_VERSION,								/**< version		*/
	N_("Prepends a newline to displayed message."),	/**< summary		*/
	N_("Prepends a newline to messages so that the "
	   "rest of the message appears below the "
	   "username in the conversation window."),		/**< description	*/
	"Stu Tomlinson <stu@nosnilmot.com>",			/**< author			*/
	PURPLE_WEBSITE,									/**< homepage		*/

	plugin_load,									/**< load			*/
	NULL,											/**< unload			*/
	NULL,											/**< destroy		*/

	NULL,											/**< ui_info		*/
	NULL,											/**< extra_info		*/
	&prefs_info,									/**< prefs_info		*/
	NULL,											/**< actions		*/

	/* padding */
	NULL,
	NULL,
	NULL,
	NULL
};

static void
init_plugin(PurplePlugin *plugin) {
	purple_prefs_add_none("/plugins/core/newline");
	purple_prefs_add_bool("/plugins/core/newline/im", TRUE);
	purple_prefs_add_bool("/plugins/core/newline/chat", TRUE);
}

PURPLE_INIT_PLUGIN(newline, init_plugin, info)
