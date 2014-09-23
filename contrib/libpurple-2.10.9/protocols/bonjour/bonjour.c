/*
 * purple - Bonjour Protocol Plugin
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
#include <glib.h>
#ifndef _WIN32
#include <pwd.h>
#else
#define UNICODE
#include <winsock2.h>
#include <windows.h>
#include <lm.h>
#include "dns_sd_proxy.h"
#endif

#include "internal.h"

#include "account.h"
#include "accountopt.h"
#include "debug.h"
#include "util.h"
#include "version.h"

#include "bonjour.h"
#include "mdns_common.h"
#include "jabber.h"
#include "buddy.h"
#include "bonjour_ft.h"

static char *default_firstname;
static char *default_lastname;

const char *
bonjour_get_jid(PurpleAccount *account)
{
	PurpleConnection *conn = purple_account_get_connection(account);
	BonjourData *bd = conn->proto_data;
	return bd->jid;
}

static void
bonjour_removeallfromlocal(PurpleConnection *conn, PurpleGroup *bonjour_group)
{
	PurpleAccount *account = purple_connection_get_account(conn);
	PurpleBlistNode *cnode, *cnodenext, *bnode, *bnodenext;
	PurpleBuddy *buddy;

	if (bonjour_group == NULL)
		return;

	/* Go through and remove all buddies that belong to this account */
	for (cnode = purple_blist_node_get_first_child((PurpleBlistNode *) bonjour_group); cnode; cnode = cnodenext) {
		cnodenext = purple_blist_node_get_sibling_next(cnode);
		if (!PURPLE_BLIST_NODE_IS_CONTACT(cnode))
			continue;
		for (bnode = purple_blist_node_get_first_child(cnode); bnode; bnode = bnodenext) {
			bnodenext = purple_blist_node_get_sibling_next(bnode);
			if (!PURPLE_BLIST_NODE_IS_BUDDY(bnode))
				continue;
			buddy = (PurpleBuddy *) bnode;
			if (purple_buddy_get_account(buddy) != account)
				continue;
			purple_account_remove_buddy(account, buddy, NULL);
			purple_blist_remove_buddy(buddy);
		}
	}

}

static void
bonjour_login(PurpleAccount *account)
{
	PurpleConnection *gc = purple_account_get_connection(account);
	BonjourData *bd;
	PurpleStatus *status;
	PurplePresence *presence;

#ifdef _WIN32
	if (!dns_sd_available()) {
		purple_connection_error_reason(gc,
				PURPLE_CONNECTION_ERROR_OTHER_ERROR,
				_("Unable to find Apple's \"Bonjour for Windows\" toolkit, see "
				  "http://d.pidgin.im/BonjourWindows for more information."));
		return;
	}
#endif /* _WIN32 */

	gc->flags |= PURPLE_CONNECTION_HTML;
	gc->proto_data = bd = g_new0(BonjourData, 1);

	/* Start waiting for jabber connections (iChat style) */
	bd->jabber_data = g_new0(BonjourJabber, 1);
	bd->jabber_data->socket = -1;
	bd->jabber_data->socket6 = -1;
	bd->jabber_data->port = purple_account_get_int(account, "port", BONJOUR_DEFAULT_PORT);
	bd->jabber_data->account = account;

	if (bonjour_jabber_start(bd->jabber_data) == -1) {
		/* Send a message about the connection error */
		purple_connection_error_reason (gc,
				PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
				_("Unable to listen for incoming IM connections"));
		return;
	}

	/* Connect to the mDNS daemon looking for buddies in the LAN */
	bd->dns_sd_data = bonjour_dns_sd_new();
	bd->dns_sd_data->first = g_strdup(purple_account_get_string(account, "first", default_firstname));
	bd->dns_sd_data->last = g_strdup(purple_account_get_string(account, "last", default_lastname));
	bd->dns_sd_data->port_p2pj = bd->jabber_data->port;
	/* Not engaged in AV conference */
	bd->dns_sd_data->vc = g_strdup("!");

	status = purple_account_get_active_status(account);
	presence = purple_account_get_presence(account);
	if (purple_presence_is_available(presence))
		bd->dns_sd_data->status = g_strdup("avail");
	else if (purple_presence_is_idle(presence))
		bd->dns_sd_data->status = g_strdup("away");
	else
		bd->dns_sd_data->status = g_strdup("dnd");
	bd->dns_sd_data->msg = g_strdup(purple_status_get_attr_string(status, "message"));

	bd->dns_sd_data->account = account;
	if (!bonjour_dns_sd_start(bd->dns_sd_data))
	{
		purple_connection_error_reason (gc,
			PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
			_("Unable to establish connection with the local mDNS server.  Is it running?"));
		return;
	}

	bonjour_dns_sd_update_buddy_icon(bd->dns_sd_data);

	/* Show the buddy list by telling Purple we have already connected */
	purple_connection_set_state(gc, PURPLE_CONNECTED);
}

static void
bonjour_close(PurpleConnection *connection)
{
	PurpleGroup *bonjour_group;
	BonjourData *bd = connection->proto_data;

	bonjour_group = purple_find_group(BONJOUR_GROUP_NAME);

	/* Remove all the bonjour buddies */
	bonjour_removeallfromlocal(connection, bonjour_group);

	/* Stop looking for buddies in the LAN */
	if (bd != NULL && bd->dns_sd_data != NULL)
	{
		bonjour_dns_sd_stop(bd->dns_sd_data);
		bonjour_dns_sd_free(bd->dns_sd_data);
	}

	if (bd != NULL && bd->jabber_data != NULL)
	{
		/* Stop waiting for conversations */
		bonjour_jabber_stop(bd->jabber_data);
		g_free(bd->jabber_data);
	}

	/* Delete the bonjour group
	 * (purple_blist_remove_group will bail out if the group isn't empty)
	 */
	if (bonjour_group != NULL)
		purple_blist_remove_group(bonjour_group);

	/* Cancel any file transfers */
	while (bd != NULL && bd->xfer_lists) {
		purple_xfer_cancel_local(bd->xfer_lists->data);
	}

	if (bd != NULL)
		g_free(bd->jid);
	g_free(bd);
	connection->proto_data = NULL;
}

static const char *
bonjour_list_icon(PurpleAccount *account, PurpleBuddy *buddy)
{
	return BONJOUR_ICON_NAME;
}

static int
bonjour_send_im(PurpleConnection *connection, const char *to, const char *msg, PurpleMessageFlags flags)
{
	if(!to || !msg)
		return 0;

	return bonjour_jabber_send_message(((BonjourData*)(connection->proto_data))->jabber_data, to, msg);
}

static void
bonjour_set_status(PurpleAccount *account, PurpleStatus *status)
{
	PurpleConnection *gc;
	BonjourData *bd;
	PurplePresence *presence;
	const char *message, *bonjour_status;
	gchar *stripped;

	gc = purple_account_get_connection(account);
	bd = gc->proto_data;
	presence = purple_account_get_presence(account);

	message = purple_status_get_attr_string(status, "message");
	if (message == NULL)
		message = "";
	stripped = purple_markup_strip_html(message);

	/*
	 * The three possible status for Bonjour are
	 *   -available ("avail")
	 *   -idle ("away")
	 *   -away ("dnd")
	 * Each of them can have an optional message.
	 */
	if (purple_presence_is_available(presence))
		bonjour_status = "avail";
	else if (purple_presence_is_idle(presence))
		bonjour_status = "away";
	else
		bonjour_status = "dnd";

	bonjour_dns_sd_send_status(bd->dns_sd_data, bonjour_status, stripped);
	g_free(stripped);
}

/*
 * The add_buddy callback removes the buddy from the local list.
 * Bonjour manages buddies for you, and adding someone locally by
 * hand is stupid.  Perhaps we should change libpurple not to allow adding
 * if there is no add_buddy callback.
 */
static void
bonjour_fake_add_buddy(PurpleConnection *pc, PurpleBuddy *buddy, PurpleGroup *group) {
	purple_debug_error("bonjour", "Buddy '%s' manually added; removing.  "
				      "Bonjour buddies must be discovered and not manually added.\n",
			   purple_buddy_get_name(buddy));

	/* I suppose we could alert the user here, but it seems unnecessary. */

	/* If this causes problems, it can be moved to an idle callback */
	purple_blist_remove_buddy(buddy);
}


static void bonjour_remove_buddy(PurpleConnection *pc, PurpleBuddy *buddy, PurpleGroup *group) {
	BonjourBuddy *bb = purple_buddy_get_protocol_data(buddy);
	if (bb) {
		bonjour_buddy_delete(bb);
		purple_buddy_set_protocol_data(buddy, NULL);
	}
}

static GList *
bonjour_status_types(PurpleAccount *account)
{
	GList *status_types = NULL;
	PurpleStatusType *type;

	g_return_val_if_fail(account != NULL, NULL);

	type = purple_status_type_new_with_attrs(PURPLE_STATUS_AVAILABLE,
										   BONJOUR_STATUS_ID_AVAILABLE,
										   NULL, TRUE, TRUE, FALSE,
										   "message", _("Message"),
										   purple_value_new(PURPLE_TYPE_STRING), NULL);
	status_types = g_list_append(status_types, type);

	type = purple_status_type_new_with_attrs(PURPLE_STATUS_AWAY,
										   BONJOUR_STATUS_ID_AWAY,
										   NULL, TRUE, TRUE, FALSE,
										   "message", _("Message"),
										   purple_value_new(PURPLE_TYPE_STRING), NULL);
	status_types = g_list_append(status_types, type);

	type = purple_status_type_new_full(PURPLE_STATUS_OFFLINE,
									 BONJOUR_STATUS_ID_OFFLINE,
									 NULL, TRUE, TRUE, FALSE);
	status_types = g_list_append(status_types, type);

	return status_types;
}

static void
bonjour_convo_closed(PurpleConnection *connection, const char *who)
{
	PurpleBuddy *buddy = purple_find_buddy(connection->account, who);
	BonjourBuddy *bb;

	if (buddy == NULL || (bb = purple_buddy_get_protocol_data(buddy)) == NULL)
	{
		/*
		 * This buddy is not in our buddy list, and therefore does not really
		 * exist, so we won't have any data about them.
		 */
		return;
	}

	bonjour_jabber_close_conversation(bb->conversation);
	bb->conversation = NULL;
}

static
void bonjour_set_buddy_icon(PurpleConnection *conn, PurpleStoredImage *img)
{
	BonjourData *bd = conn->proto_data;
	bonjour_dns_sd_update_buddy_icon(bd->dns_sd_data);
}


static char *
bonjour_status_text(PurpleBuddy *buddy)
{
	const PurplePresence *presence;
	const PurpleStatus *status;
	const char *message;
	gchar *ret = NULL;

	presence = purple_buddy_get_presence(buddy);
	status = purple_presence_get_active_status(presence);

	message = purple_status_get_attr_string(status, "message");

	if (message != NULL) {
		ret = g_markup_escape_text(message, -1);
		purple_util_chrreplace(ret, '\n', ' ');
	}

	return ret;
}

static void
bonjour_tooltip_text(PurpleBuddy *buddy, PurpleNotifyUserInfo *user_info, gboolean full)
{
	PurplePresence *presence;
	PurpleStatus *status;
	BonjourBuddy *bb = purple_buddy_get_protocol_data(buddy);
	const char *status_description;
	const char *message;

	presence = purple_buddy_get_presence(buddy);
	status = purple_presence_get_active_status(presence);
	message = purple_status_get_attr_string(status, "message");

	if (purple_presence_is_available(presence))
		status_description = purple_status_get_name(status);
	else if (purple_presence_is_idle(presence))
		status_description = _("Idle");
	else
		status_description = purple_status_get_name(status);

	purple_notify_user_info_add_pair(user_info, _("Status"), status_description);
	if (message != NULL)
		purple_notify_user_info_add_pair(user_info, _("Message"), message);

	if (bb == NULL) {
		purple_debug_error("bonjour", "Got tooltip request for a buddy without protocol data.\n");
		return;
	}

	/* Only show first/last name if there is a nickname set (to avoid duplication) */
	if (bb->nick != NULL && *bb->nick != '\0') {
		if (bb->first != NULL && *bb->first != '\0')
			purple_notify_user_info_add_pair(user_info, _("First name"), bb->first);
		if (bb->last != NULL && *bb->last != '\0')
			purple_notify_user_info_add_pair(user_info, _("Last name"), bb->last);
	}

	if (bb->email != NULL && *bb->email != '\0')
		purple_notify_user_info_add_pair(user_info, _("Email"), bb->email);

	if (bb->AIM != NULL && *bb->AIM != '\0')
		purple_notify_user_info_add_pair(user_info, _("AIM Account"), bb->AIM);

	if (bb->jid != NULL && *bb->jid != '\0')
		purple_notify_user_info_add_pair(user_info, _("XMPP Account"), bb->jid);
}

static void
bonjour_do_group_change(PurpleBuddy *buddy, const char *new_group) {
	PurpleBlistNodeFlags oldflags;

	if (buddy == NULL)
		return;

	oldflags = purple_blist_node_get_flags((PurpleBlistNode *)buddy);

	/* If we're moving them out of the bonjour group, make them persistent */
	if (purple_strequal(new_group, BONJOUR_GROUP_NAME))
		purple_blist_node_set_flags((PurpleBlistNode *)buddy, oldflags | PURPLE_BLIST_NODE_FLAG_NO_SAVE);
	else
		purple_blist_node_set_flags((PurpleBlistNode *)buddy, oldflags ^ PURPLE_BLIST_NODE_FLAG_NO_SAVE);

}

static void
bonjour_group_buddy(PurpleConnection *connection, const char *who, const char *old_group, const char *new_group)
{
	PurpleBuddy *buddy = purple_find_buddy(connection->account, who);

	bonjour_do_group_change(buddy, new_group);

}

static void
bonjour_rename_group(PurpleConnection *connection, const char *old_name, PurpleGroup *group, GList *moved_buddies)
{
	GList *cur;
	const char *new_group;
	PurpleBuddy *buddy;

	new_group = purple_group_get_name(group);

	for (cur = moved_buddies; cur; cur = cur->next) {
		buddy = cur->data;
		bonjour_do_group_change(buddy, new_group);
	}

}

static gboolean
bonjour_can_receive_file(PurpleConnection *connection, const char *who)
{
	PurpleBuddy *buddy = purple_find_buddy(connection->account, who);

	return (buddy != NULL && purple_buddy_get_protocol_data(buddy) != NULL);
}

static gboolean
plugin_unload(PurplePlugin *plugin)
{
	/* These shouldn't happen here because they are allocated in _init() */

	g_free(default_firstname);
	g_free(default_lastname);

	return TRUE;
}

static PurplePlugin *my_protocol = NULL;

static PurplePluginProtocolInfo prpl_info =
{
	OPT_PROTO_NO_PASSWORD,
	NULL,                                                    /* user_splits */
	NULL,                                                    /* protocol_options */
	{"png,gif,jpeg", 0, 0, 96, 96, 65535, PURPLE_ICON_SCALE_DISPLAY}, /* icon_spec */
	bonjour_list_icon,                                       /* list_icon */
	NULL,                                                    /* list_emblem */
	bonjour_status_text,                                     /* status_text */
	bonjour_tooltip_text,                                    /* tooltip_text */
	bonjour_status_types,                                    /* status_types */
	NULL,                                                    /* blist_node_menu */
	NULL,                                                    /* chat_info */
	NULL,                                                    /* chat_info_defaults */
	bonjour_login,                                           /* login */
	bonjour_close,                                           /* close */
	bonjour_send_im,                                         /* send_im */
	NULL,                                                    /* set_info */
	NULL,                                                    /* send_typing */
	NULL,                                                    /* get_info */
	bonjour_set_status,                                      /* set_status */
	NULL,                                                    /* set_idle */
	NULL,                                                    /* change_passwd */
	bonjour_fake_add_buddy,                                  /* add_buddy */
	NULL,                                                    /* add_buddies */
	bonjour_remove_buddy,                                    /* remove_buddy */
	NULL,                                                    /* remove_buddies */
	NULL,                                                    /* add_permit */
	NULL,                                                    /* add_deny */
	NULL,                                                    /* rem_permit */
	NULL,                                                    /* rem_deny */
	NULL,                                                    /* set_permit_deny */
	NULL,                                                    /* join_chat */
	NULL,                                                    /* reject_chat */
	NULL,                                                    /* get_chat_name */
	NULL,                                                    /* chat_invite */
	NULL,                                                    /* chat_leave */
	NULL,                                                    /* chat_whisper */
	NULL,                                                    /* chat_send */
	NULL,                                                    /* keepalive */
	NULL,                                                    /* register_user */
	NULL,                                                    /* get_cb_info */
	NULL,                                                    /* get_cb_away */
	NULL,                                                    /* alias_buddy */
	bonjour_group_buddy,                                     /* group_buddy */
	bonjour_rename_group,                                    /* rename_group */
	NULL,                                                    /* buddy_free */
	bonjour_convo_closed,                                    /* convo_closed */
	NULL,                                                    /* normalize */
	bonjour_set_buddy_icon,                                  /* set_buddy_icon */
	NULL,                                                    /* remove_group */
	NULL,                                                    /* get_cb_real_name */
	NULL,                                                    /* set_chat_topic */
	NULL,                                                    /* find_blist_chat */
	NULL,                                                    /* roomlist_get_list */
	NULL,                                                    /* roomlist_cancel */
	NULL,                                                    /* roomlist_expand_category */
	bonjour_can_receive_file,                                /* can_receive_file */
	bonjour_send_file,                                       /* send_file */
	bonjour_new_xfer,                                        /* new_xfer */
	NULL,                                                    /* offline_message */
	NULL,                                                    /* whiteboard_prpl_ops */
	NULL,                                                    /* send_raw */
	NULL,                                                    /* roomlist_room_serialize */
	NULL,                                                    /* unregister_user */
	NULL,                                                    /* send_attention */
	NULL,                                                    /* get_attention_types */
	sizeof(PurplePluginProtocolInfo),                        /* struct_size */
	NULL,                                                    /* get_account_text_table */
	NULL,                                                    /* initiate_media */
	NULL,                                                    /* get_media_caps */
	NULL,                                                    /* get_moods */
	NULL,                                                    /* set_public_alias */
	NULL,                                                    /* get_public_alias */
	NULL,                                                    /* add_buddy_with_invite */
	NULL                                                     /* add_buddies_with_invite */
};

static PurplePluginInfo info =
{
	PURPLE_PLUGIN_MAGIC,
	PURPLE_MAJOR_VERSION,
	PURPLE_MINOR_VERSION,
	PURPLE_PLUGIN_PROTOCOL,                           /**< type           */
	NULL,                                             /**< ui_requirement */
	0,                                                /**< flags          */
	NULL,                                             /**< dependencies   */
	PURPLE_PRIORITY_DEFAULT,                          /**< priority       */

	"prpl-bonjour",                                   /**< id             */
	"Bonjour",                                        /**< name           */
	DISPLAY_VERSION,                                  /**< version        */
	                                                  /**  summary        */
	N_("Bonjour Protocol Plugin"),
	                                                  /**  description    */
	N_("Bonjour Protocol Plugin"),
	NULL,                                             /**< author         */
	PURPLE_WEBSITE,                                   /**< homepage       */

	NULL,                                             /**< load           */
	plugin_unload,                                    /**< unload         */
	NULL,                                             /**< destroy        */

	NULL,                                             /**< ui_info        */
	&prpl_info,                                       /**< extra_info     */
	NULL,                                             /**< prefs_info     */
	NULL,

	/* padding */
	NULL,
	NULL,
	NULL,
	NULL
};

#ifdef WIN32
static gboolean
_set_default_name_cb(gpointer data) {
	gchar *fullname = data;
	const char *splitpoint;
	GList *tmp = prpl_info.protocol_options;
	PurpleAccountOption *option;

	if (!fullname) {
		purple_debug_info("bonjour", "Unable to look up First and Last name or Username from system; using defaults.\n");
		return FALSE;
	}

	g_free(default_firstname);
	g_free(default_lastname);

	/* Split the real name into a first and last name */
	splitpoint = strchr(fullname, ' ');
	if (splitpoint != NULL) {
		default_firstname = g_strndup(fullname, splitpoint - fullname);
		default_lastname = g_strdup(&splitpoint[1]);
	} else {
		default_firstname = g_strdup(fullname);
		default_lastname = g_strdup("");
	}
	g_free(fullname);


	for(; tmp != NULL; tmp = tmp->next) {
		option = tmp->data;
		if (strcmp("first", purple_account_option_get_setting(option)) == 0)
			purple_account_option_set_default_string(option, default_firstname);
		else if (strcmp("last", purple_account_option_get_setting(option)) == 0)
			purple_account_option_set_default_string(option, default_lastname);
	}

	return FALSE;
}

static gpointer
_win32_name_lookup_thread(gpointer data) {
	gchar *fullname = NULL;
	wchar_t username[UNLEN + 1];
	DWORD dwLenUsername = UNLEN + 1;

	GetUserNameW((LPWSTR) &username, &dwLenUsername);

	if (username != NULL && *username != '\0') {
		LPBYTE servername = NULL;
		LPBYTE info = NULL;

		NetGetDCName(NULL, NULL, &servername);

		/* purple_debug_info("bonjour", "Looking up the full name from the %s.\n", (servername ? "domain controller" : "local machine")); */

		if (NetUserGetInfo((LPCWSTR) servername, username, 10, &info) == NERR_Success
				&& info != NULL && ((LPUSER_INFO_10) info)->usri10_full_name != NULL
				&& *(((LPUSER_INFO_10) info)->usri10_full_name) != '\0') {
			fullname = g_utf16_to_utf8(
				((LPUSER_INFO_10) info)->usri10_full_name,
				-1, NULL, NULL, NULL);
		}
		/* Fall back to the local machine if we didn't get the full name from the domain controller */
		else if (servername != NULL) {
			/* purple_debug_info("bonjour", "Looking up the full name from the local machine"); */

			if (info != NULL) NetApiBufferFree(info);
			info = NULL;

			if (NetUserGetInfo(NULL, username, 10, &info) == NERR_Success
					&& info != NULL && ((LPUSER_INFO_10) info)->usri10_full_name != NULL
					&& *(((LPUSER_INFO_10) info)->usri10_full_name) != '\0') {
				fullname = g_utf16_to_utf8(
					((LPUSER_INFO_10) info)->usri10_full_name,
					-1, NULL, NULL, NULL);
			}
		}

		if (info != NULL) NetApiBufferFree(info);
		if (servername != NULL) NetApiBufferFree(servername);

		if (!fullname)
			fullname = g_utf16_to_utf8(username, -1, NULL, NULL, NULL);
	}

	purple_timeout_add(0, _set_default_name_cb, fullname);

	return NULL;
}
#endif

static void
initialize_default_account_values(void)
{
#ifndef _WIN32
	struct passwd *info;
#endif
	const char *fullname = NULL, *splitpoint, *tmp;
	gchar *conv = NULL;

#ifndef _WIN32
	/* Try to figure out the user's real name */
	info = getpwuid(getuid());
	if ((info != NULL) && (info->pw_gecos != NULL) && (info->pw_gecos[0] != '\0'))
		fullname = info->pw_gecos;
	else if ((info != NULL) && (info->pw_name != NULL) && (info->pw_name[0] != '\0'))
		fullname = info->pw_name;
	else if (((fullname = getlogin()) != NULL) && (fullname[0] == '\0'))
		fullname = NULL;
#else
	/* The Win32 username lookup functions are synchronous so we do it in a thread */
	g_thread_create(_win32_name_lookup_thread, NULL, FALSE, NULL);
#endif

	/* Make sure fullname is valid UTF-8.  If not, try to convert it. */
	if (fullname != NULL && !g_utf8_validate(fullname, -1, NULL)) {
		fullname = conv = g_locale_to_utf8(fullname, -1, NULL, NULL, NULL);
		if (conv == NULL || *conv == '\0')
			fullname = NULL;
	}

	if (fullname == NULL)
		fullname = _("Purple Person");

	/* Split the real name into a first and last name */
	splitpoint = strchr(fullname, ' ');
	if (splitpoint != NULL) {
		default_firstname = g_strndup(fullname, splitpoint - fullname);
		tmp = &splitpoint[1];

		/* The last name may be followed by a comma and additional data.
		 * Only use the last name itself.
		 */
		splitpoint = strchr(tmp, ',');
		if (splitpoint != NULL)
			default_lastname = g_strndup(tmp, splitpoint - tmp);
		else
			default_lastname = g_strdup(tmp);
	} else {
		default_firstname = g_strdup(fullname);
		default_lastname = g_strdup("");
	}

	g_free(conv);
}

static void
init_plugin(PurplePlugin *plugin)
{
	PurpleAccountOption *option;

	initialize_default_account_values();

	/* Creating the options for the protocol */
	option = purple_account_option_int_new(_("Local Port"), "port", BONJOUR_DEFAULT_PORT);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	option = purple_account_option_string_new(_("First name"), "first", default_firstname);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	option = purple_account_option_string_new(_("Last name"), "last", default_lastname);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	option = purple_account_option_string_new(_("Email"), "email", "");
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	option = purple_account_option_string_new(_("AIM Account"), "AIM", "");
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	option = purple_account_option_string_new(_("XMPP Account"), "jid", "");
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	my_protocol = plugin;
}

PURPLE_INIT_PLUGIN(bonjour, init_plugin, info);
