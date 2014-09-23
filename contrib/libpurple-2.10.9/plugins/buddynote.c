/*
 * BuddyNote - Store notes on particular buddies
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

#include <debug.h>
#include <notify.h>
#include <request.h>
#include <signals.h>
#include <util.h>
#include <version.h>

static void
dont_do_it_cb(PurpleBlistNode *node, const char *note)
{
}

static void
do_it_cb(PurpleBlistNode *node, const char *note)
{
	purple_blist_node_set_string(node, "notes", note);
}

static void
buddynote_edit_cb(PurpleBlistNode *node, gpointer data)
{
	const char *note;

	note = purple_blist_node_get_string(node, "notes");

	purple_request_input(node, _("Notes"),
					   _("Enter your notes below..."),
					   NULL,
					   note, TRUE, FALSE, "html",
					   _("Save"), G_CALLBACK(do_it_cb),
					   _("Cancel"), G_CALLBACK(dont_do_it_cb),
					   NULL, NULL, NULL,
					   node);
}

static void
buddynote_extended_menu_cb(PurpleBlistNode *node, GList **m)
{
	PurpleMenuAction *bna = NULL;

	if (purple_blist_node_get_flags(node) & PURPLE_BLIST_NODE_FLAG_NO_SAVE)
		return;

	*m = g_list_append(*m, bna);
	bna = purple_menu_action_new(_("Edit Notes..."), PURPLE_CALLBACK(buddynote_edit_cb), NULL, NULL);
	*m = g_list_append(*m, bna);
}

static gboolean
plugin_load(PurplePlugin *plugin)
{

	purple_signal_connect(purple_blist_get_handle(), "blist-node-extended-menu",
						plugin, PURPLE_CALLBACK(buddynote_extended_menu_cb), NULL);

	return TRUE;
}

static PurplePluginInfo info =
{
	PURPLE_PLUGIN_MAGIC,
	PURPLE_MAJOR_VERSION,							/**< major version	*/
	PURPLE_MINOR_VERSION,							/**< minor version	*/
	PURPLE_PLUGIN_STANDARD,							/**< type			*/
	NULL,											/**< ui_requirement	*/
	0,												/**< flags			*/
	NULL,											/**< dependencies	*/
	PURPLE_PRIORITY_DEFAULT,						/**< priority		*/
	"core-plugin_pack-buddynote",					/**< id				*/
	N_("Buddy Notes"),								/**< name			*/
	DISPLAY_VERSION,									/**< version		*/
	N_("Store notes on particular buddies."),		/**< summary		*/
	N_("Adds the option to store notes for buddies "
	   "on your buddy list."),						/**< description	*/
	"Stu Tomlinson <stu@nosnilmot.com>",			/**< author			*/
	PURPLE_WEBSITE,									/**< homepage		*/
	plugin_load,									/**< load			*/
	NULL,											/**< unload			*/
	NULL,											/**< destroy		*/
	NULL,											/**< ui_info		*/
	NULL,											/**< extra_info		*/
	NULL,											/**< prefs_info		*/
	NULL,											/**< actions		*/

	/* padding */
	NULL,
	NULL,
	NULL,
	NULL
};


static void
init_plugin(PurplePlugin *plugin) {
}

PURPLE_INIT_PLUGIN(buddynote, init_plugin, info)
