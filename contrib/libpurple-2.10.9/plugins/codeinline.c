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
#include "plugin.h"
#include "notify.h"
#include "util.h"
#include "version.h"

PurplePlugin *plugin_handle = NULL;

static gboolean outgoing_msg_cb(PurpleAccount *account, const char *who, char **message,
					PurpleConversation *conv, PurpleMessageFlags flags, gpointer null)
{
  char *m;
  char **ms = g_strsplit(*message, "<u>", -1);
  m = g_strjoinv("<font face=\"monospace\" color=\"#00b025\">", ms);
  g_strfreev(ms);

  ms = g_strsplit(m, "</u>", -1);
  g_free(m);
  m = g_strjoinv("</font>", ms);
  g_free(*message);
  *message = m;
  return FALSE;
}

static gboolean
plugin_load(PurplePlugin *plugin)
{
     void *handle = purple_conversations_get_handle();
     plugin_handle = plugin;
     purple_signal_connect(handle, "writing-im-msg", plugin,
                PURPLE_CALLBACK(outgoing_msg_cb), NULL);
     purple_signal_connect(handle, "sending-im-msg", plugin,
		PURPLE_CALLBACK(outgoing_msg_cb), NULL);

     return TRUE;
}


static PurplePluginInfo info =
{
     PURPLE_PLUGIN_MAGIC,
     PURPLE_MAJOR_VERSION,
     PURPLE_MINOR_VERSION,
     PURPLE_PLUGIN_STANDARD,
     NULL,
     0,
     NULL,
     PURPLE_PRIORITY_DEFAULT,
     "codeinline",
     "Code Inline",
     "1.0",
     "Formats text as code",
     "Changes the formatting of any outgoing text such that "
     "anything underlined will be received green and monospace.",
     "Sean Egan <seanegan@gmail.com>",
     PURPLE_WEBSITE,
     plugin_load,
     NULL,
     NULL,
     NULL,
     NULL,
     NULL,
     NULL,
	 /* padding */
     NULL,
     NULL,
     NULL,
     NULL
};

 static void
 init_plugin(PurplePlugin *plugin)
 {
 }

PURPLE_INIT_PLUGIN(codeinline, init_plugin, info)
