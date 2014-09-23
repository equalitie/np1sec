/*
 * Autoaccept - Auto-accept file transfers from selected users
 * Copyright (C) 2006
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

#define PLUGIN_ID			"core-plugin_pack-autoaccept"
#define PLUGIN_NAME			N_("Autoaccept")
#define PLUGIN_STATIC_NAME	Autoaccept
#define PLUGIN_SUMMARY		N_("Auto-accept file transfer requests from selected users.")
#define PLUGIN_DESCRIPTION	N_("Auto-accept file transfer requests from selected users.")
#define PLUGIN_AUTHOR		"Sadrul H Chowdhury <sadrul@users.sourceforge.net>"

/* System headers */
#include <glib.h>
#include <glib/gstdio.h>

/* Purple headers */
#include <plugin.h>
#include <version.h>

#include <blist.h>
#include <conversation.h>
#include <ft.h>
#include <request.h>
#include <notify.h>
#include <util.h>

#define PREF_PREFIX		"/plugins/core/" PLUGIN_ID
#define PREF_PATH		PREF_PREFIX "/path"
#define PREF_STRANGER	PREF_PREFIX "/stranger"
#define PREF_NOTIFY		PREF_PREFIX "/notify"
#define PREF_NEWDIR     PREF_PREFIX "/newdir"
#define PREF_ESCAPE     PREF_PREFIX "/escape"

#define PREF_STRANGER_OLD PREF_PREFIX "/reject_stranger"

typedef enum
{
	FT_ASK,
	FT_ACCEPT,
	FT_REJECT
} AutoAcceptSetting;

static gboolean
ensure_path_exists(const char *dir)
{
	if (!g_file_test(dir, G_FILE_TEST_IS_DIR))
	{
		if (purple_build_dir(dir, S_IRUSR | S_IWUSR | S_IXUSR))
			return FALSE;
	}

	return TRUE;
}

static void
auto_accept_complete_cb(PurpleXfer *xfer, PurpleXfer *my)
{
	if (xfer == my && purple_prefs_get_bool(PREF_NOTIFY) &&
			!purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, xfer->who, xfer->account))
	{
		char *message = g_strdup_printf(_("Autoaccepted file transfer of \"%s\" from \"%s\" completed."),
					xfer->filename, xfer->who);
		purple_notify_info(NULL, _("Autoaccept complete"), message, NULL);
		g_free(message);
	}
}

static void
file_recv_request_cb(PurpleXfer *xfer, gpointer handle)
{
	PurpleAccount *account;
	PurpleBlistNode *node;
	const char *pref;
	char *filename;
	char *dirname;

    int accept_setting;

	account = xfer->account;
	node = PURPLE_BLIST_NODE(purple_find_buddy(account, xfer->who));

	/* If person is on buddy list, use the buddy setting; otherwise, use the
	   stranger setting. */
	if (node) {
		node = purple_blist_node_get_parent(node);
		g_return_if_fail(PURPLE_BLIST_NODE_IS_CONTACT(node));
		accept_setting = purple_blist_node_get_int(node, "autoaccept");
	} else {
		accept_setting = purple_prefs_get_int(PREF_STRANGER);
	}

	switch (accept_setting)
	{
		case FT_ASK:
			break;
		case FT_ACCEPT:
            pref = purple_prefs_get_string(PREF_PATH);
			if (ensure_path_exists(pref))
			{
				int count = 1;
				const char *escape;
				gchar **name_and_ext;
				const gchar *name;
				gchar *ext;

				if (purple_prefs_get_bool(PREF_NEWDIR))
					dirname = g_build_filename(pref, purple_normalize(account, xfer->who), NULL);
				else
					dirname = g_build_filename(pref, NULL);

				if (!ensure_path_exists(dirname))
				{
					g_free(dirname);
					break;
				}

				/* Escape filename (if escaping is turned on) */
				if (purple_prefs_get_bool(PREF_ESCAPE)) {
					escape = purple_escape_filename(xfer->filename);
				} else {
					escape = xfer->filename;
				}
				filename = g_build_filename(dirname, escape, NULL);

				/* Split at the first dot, to avoid uniquifying "foo.tar.gz" to "foo.tar-2.gz" */
				name_and_ext = g_strsplit(escape, ".", 2);
				name = name_and_ext[0];
				g_return_if_fail(name != NULL);
				if (name_and_ext[1] != NULL) {
					/* g_strsplit does not include the separator in each chunk. */
					ext = g_strdup_printf(".%s", name_and_ext[1]);
				} else {
					ext = g_strdup("");
				}

				/* Make sure the file doesn't exist. Do we want some better checking than this? */
				/* FIXME: There is a race here: if the newly uniquified file name gets created between
				 *        this g_file_test and the transfer starting, the file created in the meantime
				 *        will be clobbered. But it's not at all straightforward to fix.
				 */
				while (g_file_test(filename, G_FILE_TEST_EXISTS)) {
					char *file = g_strdup_printf("%s-%d%s", name, count++, ext);
					g_free(filename);
					filename = g_build_filename(dirname, file, NULL);
					g_free(file);
				}

				purple_xfer_request_accepted(xfer, filename);

				g_strfreev(name_and_ext);
				g_free(ext);
				g_free(dirname);
				g_free(filename);
			}

			purple_signal_connect(purple_xfers_get_handle(), "file-recv-complete", handle,
								PURPLE_CALLBACK(auto_accept_complete_cb), xfer);
			break;
		case FT_REJECT:
			xfer->status = PURPLE_XFER_STATUS_CANCEL_LOCAL;
			break;
	}
}

static void
save_cb(PurpleBlistNode *node, int choice)
{
	if (PURPLE_BLIST_NODE_IS_BUDDY(node))
		node = purple_blist_node_get_parent(node);
	g_return_if_fail(PURPLE_BLIST_NODE_IS_CONTACT(node));
	purple_blist_node_set_int(node, "autoaccept", choice);
}

static void
set_auto_accept_settings(PurpleBlistNode *node, gpointer plugin)
{
	char *message;

	if (PURPLE_BLIST_NODE_IS_BUDDY(node))
		node = purple_blist_node_get_parent(node);
	g_return_if_fail(PURPLE_BLIST_NODE_IS_CONTACT(node));

	message = g_strdup_printf(_("When a file-transfer request arrives from %s"),
					purple_contact_get_alias((PurpleContact *)node));
	purple_request_choice(plugin, _("Set Autoaccept Setting"), message,
						NULL, purple_blist_node_get_int(node, "autoaccept"),
						_("_Save"), G_CALLBACK(save_cb),
						_("_Cancel"), NULL,
						NULL, NULL, NULL,
						node,
						_("Ask"), FT_ASK,
						_("Auto Accept"), FT_ACCEPT,
						_("Auto Reject"), FT_REJECT,
						NULL, purple_contact_get_alias((PurpleContact *)node), NULL,
						NULL);
	g_free(message);
}

static void
context_menu(PurpleBlistNode *node, GList **menu, gpointer plugin)
{
	PurpleMenuAction *action;

	if (!PURPLE_BLIST_NODE_IS_BUDDY(node) && !PURPLE_BLIST_NODE_IS_CONTACT(node) &&
		!(purple_blist_node_get_flags(node) & PURPLE_BLIST_NODE_FLAG_NO_SAVE))
		return;

	action = purple_menu_action_new(_("Autoaccept File Transfers..."),
					PURPLE_CALLBACK(set_auto_accept_settings), plugin, NULL);
	(*menu) = g_list_prepend(*menu, action);
}

static gboolean
plugin_load(PurplePlugin *plugin)
{
	/* migrate the old pref (we should only care if the plugin is actually *used*) */
	/*
	 * TODO: We should eventually call purple_prefs_remove(PREFS_STRANGER_OLD)
	 *       to clean up after ourselves, but we don't want to do it yet
	 *       so that we don't break users who share a .purple directory
	 *       between old libpurple clients and new libpurple clients.
	 *                                             --Mark Doliner, 2011-01-03
	 */
	if (!purple_prefs_exists(PREF_STRANGER)) {
		if (purple_prefs_get_bool(PREF_STRANGER_OLD))
			purple_prefs_add_int(PREF_STRANGER, FT_REJECT);
		else
			purple_prefs_set_int(PREF_STRANGER, FT_ASK);
	}

	purple_signal_connect(purple_xfers_get_handle(), "file-recv-request", plugin,
						PURPLE_CALLBACK(file_recv_request_cb), plugin);
	purple_signal_connect(purple_blist_get_handle(), "blist-node-extended-menu", plugin,
						PURPLE_CALLBACK(context_menu), plugin);
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

	/* XXX: Is there a better way than this? There really should be. */
	pref = purple_plugin_pref_new_with_name_and_label(PREF_PATH, _("Path to save the files in\n"
								"(Please provide the full path)"));
	purple_plugin_pref_frame_add(frame, pref);

	pref = purple_plugin_pref_new_with_name_and_label(PREF_STRANGER,
					_("When a file-transfer request arrives from a user who is\n"
                      "*not* on your buddy list:"));
	purple_plugin_pref_set_type(pref, PURPLE_PLUGIN_PREF_CHOICE);
	purple_plugin_pref_add_choice(pref, _("Ask"), GINT_TO_POINTER(FT_ASK));
	purple_plugin_pref_add_choice(pref, _("Auto Accept"), GINT_TO_POINTER(FT_ACCEPT));
	purple_plugin_pref_add_choice(pref, _("Auto Reject"), GINT_TO_POINTER(FT_REJECT));
	purple_plugin_pref_frame_add(frame, pref);

	pref = purple_plugin_pref_new_with_name_and_label(PREF_NOTIFY,
					_("Notify with a popup when an autoaccepted file transfer is complete\n"
					  "(only when there's no conversation with the sender)"));
	purple_plugin_pref_frame_add(frame, pref);

	pref = purple_plugin_pref_new_with_name_and_label(PREF_NEWDIR,
			_("Create a new directory for each user"));
	purple_plugin_pref_frame_add(frame, pref);

	pref = purple_plugin_pref_new_with_name_and_label(PREF_ESCAPE,
			_("Escape the filenames"));
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

static PurplePluginInfo info = {
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
init_plugin(PurplePlugin *plugin) {
	char *dirname;

	dirname = g_build_filename(purple_user_dir(), "autoaccept", NULL);
	purple_prefs_add_none(PREF_PREFIX);
	purple_prefs_add_string(PREF_PATH, dirname);
	purple_prefs_add_bool(PREF_NOTIFY, TRUE);
	purple_prefs_add_bool(PREF_NEWDIR, TRUE);
	purple_prefs_add_bool(PREF_ESCAPE, TRUE);
	g_free(dirname);
}

PURPLE_INIT_PLUGIN(PLUGIN_STATIC_NAME, init_plugin, info)
