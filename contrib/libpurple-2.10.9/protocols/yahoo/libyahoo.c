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
 *
 */

#include "internal.h"

#include <account.h>
#include <core.h>

#include "libymsg.h"
#include "yahoochat.h"
#include "yahoo_aliases.h"
#include "yahoo_doodle.h"
#include "yahoo_filexfer.h"
#include "yahoo_picture.h"

static PurplePlugin *my_protocol = NULL;

static void yahoo_register_commands(void)
{
	purple_cmd_register("join", "s", PURPLE_CMD_P_PRPL,
	                  PURPLE_CMD_FLAG_IM | PURPLE_CMD_FLAG_CHAT |
	                  PURPLE_CMD_FLAG_PRPL_ONLY,
	                  "prpl-yahoo", yahoopurple_cmd_chat_join,
	                  _("join &lt;room&gt;:  Join a chat room on the Yahoo network"), NULL);
	purple_cmd_register("list", "", PURPLE_CMD_P_PRPL,
	                  PURPLE_CMD_FLAG_IM | PURPLE_CMD_FLAG_CHAT |
	                  PURPLE_CMD_FLAG_PRPL_ONLY,
	                  "prpl-yahoo", yahoopurple_cmd_chat_list,
	                  _("list: List rooms on the Yahoo network"), NULL);
	purple_cmd_register("buzz", "", PURPLE_CMD_P_PRPL,
	                  PURPLE_CMD_FLAG_IM | PURPLE_CMD_FLAG_PRPL_ONLY,
	                  "prpl-yahoo", yahoopurple_cmd_buzz,
	                  _("buzz: Buzz a user to get their attention"), NULL);
	purple_cmd_register("doodle", "", PURPLE_CMD_P_PRPL,
	                  PURPLE_CMD_FLAG_IM | PURPLE_CMD_FLAG_PRPL_ONLY,
	                  "prpl-yahoo", yahoo_doodle_purple_cmd_start,
	                 _("doodle: Request user to start a Doodle session"), NULL);
}

static PurpleAccount *find_acct(const char *prpl, const char *acct_id)
{
	PurpleAccount *acct = NULL;

	/* If we have a specific acct, use it */
	if (acct_id) {
		acct = purple_accounts_find(acct_id, prpl);
		if (acct && !purple_account_is_connected(acct))
			acct = NULL;
	} else { /* Otherwise find an active account for the protocol */
		GList *l = purple_accounts_get_all();
		while (l) {
			if (!strcmp(prpl, purple_account_get_protocol_id(l->data))
					&& purple_account_is_connected(l->data)) {
				acct = l->data;
				break;
			}
			l = l->next;
		}
	}

	return acct;
}

/* This may not be the best way to do this, but we find the first key w/o a value
 * and assume it is the buddy name */
static void yahoo_find_uri_novalue_param(gpointer key, gpointer value, gpointer user_data)
{
	char **retval = user_data;

	if (value == NULL && *retval == NULL) {
		*retval = key;
	}
}

static gboolean yahoo_uri_handler(const char *proto, const char *cmd, GHashTable *params)
{
	char *acct_id = g_hash_table_lookup(params, "account");
	PurpleAccount *acct;

	if (g_ascii_strcasecmp(proto, "ymsgr"))
		return FALSE;

	acct = find_acct(purple_plugin_get_id(my_protocol), acct_id);

	if (!acct)
		return FALSE;

	/* ymsgr:SendIM?screename&m=The+Message */
	if (!g_ascii_strcasecmp(cmd, "SendIM")) {
		char *sname = NULL;
		g_hash_table_foreach(params, yahoo_find_uri_novalue_param, &sname);
		if (sname) {
			char *message = g_hash_table_lookup(params, "m");

			PurpleConversation *conv = purple_find_conversation_with_account(
				PURPLE_CONV_TYPE_IM, sname, acct);
			if (conv == NULL)
				conv = purple_conversation_new(PURPLE_CONV_TYPE_IM, acct, sname);
			purple_conversation_present(conv);

			if (message) {
				/* Spaces are encoded as '+' */
				g_strdelimit(message, "+", ' ');
				purple_conv_send_confirm(conv, message);
			}
		}
		/* else
			**If pidgindialogs_im() was in the core, we could use it here.
			 * It is all purple_request_* based, but I'm not sure it really belongs in the core
			pidgindialogs_im(); */

		return TRUE;
	}
	/* ymsgr:Chat?roomname */
	else if (!g_ascii_strcasecmp(cmd, "Chat")) {
		char *rname = NULL;
		g_hash_table_foreach(params, yahoo_find_uri_novalue_param, &rname);
		if (rname) {
			/* This is somewhat hacky, but the params aren't useful after this command */
			g_hash_table_insert(params, g_strdup("room"), g_strdup(rname));
			g_hash_table_insert(params, g_strdup("type"), g_strdup("Chat"));
			serv_join_chat(purple_account_get_connection(acct), params);
		}
		/* else
			** Same as above (except that this would have to be re-written using purple_request_*)
			pidgin_blist_joinchat_show(); */

		return TRUE;
	}
	/* ymsgr:AddFriend?name */
	else if (!g_ascii_strcasecmp(cmd, "AddFriend")) {
		char *name = NULL;
		g_hash_table_foreach(params, yahoo_find_uri_novalue_param, &name);
		purple_blist_request_add_buddy(acct, name, NULL, NULL);
		return TRUE;
	}

	return FALSE;
}

static GHashTable *
yahoo_get_account_text_table(PurpleAccount *account)
{
	GHashTable *table;
	table = g_hash_table_new(g_str_hash, g_str_equal);
	g_hash_table_insert(table, "login_label", (gpointer)_("Yahoo ID..."));
	return table;
}

static gboolean yahoo_unload_plugin(PurplePlugin *plugin)
{
	yahoo_dest_colorht();

	return TRUE;
}

static PurpleWhiteboardPrplOps yahoo_whiteboard_prpl_ops =
{
	yahoo_doodle_start,
	yahoo_doodle_end,
	yahoo_doodle_get_dimensions,
	NULL,
	yahoo_doodle_get_brush,
	yahoo_doodle_set_brush,
	yahoo_doodle_send_draw_list,
	yahoo_doodle_clear,

	/* padding */
	NULL,
	NULL,
	NULL,
	NULL
};

static PurplePluginProtocolInfo prpl_info =
{
	OPT_PROTO_MAIL_CHECK | OPT_PROTO_CHAT_TOPIC,
	NULL, /* user_splits */
	NULL, /* protocol_options */
	{"png,gif,jpeg", 96, 96, 96, 96, 0, PURPLE_ICON_SCALE_SEND},
	yahoo_list_icon,
	yahoo_list_emblem,
	yahoo_status_text,
	yahoo_tooltip_text,
	yahoo_status_types,
	yahoo_blist_node_menu,
	yahoo_c_info,
	yahoo_c_info_defaults,
	yahoo_login,
	yahoo_close,
	yahoo_send_im,
	NULL, /* set info */
	yahoo_send_typing,
	yahoo_get_info,
	yahoo_set_status,
	yahoo_set_idle,
	NULL, /* change_passwd*/
	yahoo_add_buddy,
	NULL, /* add_buddies */
	yahoo_remove_buddy,
	NULL, /* remove_buddies */
	NULL, /* add_permit */
	yahoo_add_deny,
	NULL, /* rem_permit */
	yahoo_rem_deny,
	yahoo_set_permit_deny,
	yahoo_c_join,
	NULL, /* reject chat invite */
	yahoo_get_chat_name,
	yahoo_c_invite,
	yahoo_c_leave,
	NULL, /* chat whisper */
	yahoo_c_send,
	yahoo_keepalive,
	NULL, /* register_user */
	NULL, /* get_cb_info */
	NULL, /* get_cb_away */
	yahoo_update_alias, /* alias_buddy */
	yahoo_change_buddys_group,
	yahoo_rename_group,
	NULL, /* buddy_free */
	NULL, /* convo_closed */
	purple_normalize_nocase, /* normalize */
	yahoo_set_buddy_icon,
	NULL, /* void (*remove_group)(PurpleConnection *gc, const char *group);*/
	NULL, /* char *(*get_cb_real_name)(PurpleConnection *gc, int id, const char *who); */
	NULL, /* set_chat_topic */
	NULL, /* find_blist_chat */
	yahoo_roomlist_get_list,
	yahoo_roomlist_cancel,
	yahoo_roomlist_expand_category,
	yahoo_can_receive_file, /* can_receive_file */
	yahoo_send_file,
	yahoo_new_xfer,
	yahoo_offline_message, /* offline_message */
	&yahoo_whiteboard_prpl_ops,
	NULL, /* send_raw */
	NULL, /* roomlist_room_serialize */
	NULL, /* unregister_user */

	yahoo_send_attention,
	yahoo_attention_types,

	sizeof(PurplePluginProtocolInfo),       /* struct_size */
	yahoo_get_account_text_table,    /* get_account_text_table */
	NULL, /* initiate_media */
	NULL,  /* get_media_caps */
	NULL,  /* get_moods */
	NULL,  /* set_public_alias */
	NULL,  /* get_public_alias */
	NULL,  /* add_buddy_with_invite */
	NULL   /* add_buddies_with_invite */
};

static PurplePluginInfo info =
{
	PURPLE_PLUGIN_MAGIC,
	PURPLE_MAJOR_VERSION,
	PURPLE_MINOR_VERSION,
	PURPLE_PLUGIN_PROTOCOL,                             /**< type           */
	NULL,                                             /**< ui_requirement */
	0,                                                /**< flags          */
	NULL,                                             /**< dependencies   */
	PURPLE_PRIORITY_DEFAULT,                            /**< priority       */
	"prpl-yahoo",                                     /**< id             */
	"Yahoo",	                                      /**< name           */
	DISPLAY_VERSION,                                  /**< version        */
	                                                  /**  summary        */
	N_("Yahoo! Protocol Plugin"),
	                                                  /**  description    */
	N_("Yahoo! Protocol Plugin"),
	NULL,                                             /**< author         */
	PURPLE_WEBSITE,                                     /**< homepage       */
	NULL,                                             /**< load           */
	yahoo_unload_plugin,                              /**< unload         */
	NULL,                                             /**< destroy        */
	NULL,                                             /**< ui_info        */
	&prpl_info,                                       /**< extra_info     */
	NULL,
	yahoo_actions,

	/* padding */
	NULL,
	NULL,
	NULL,
	NULL
};

static void
init_plugin(PurplePlugin *plugin)
{
	PurpleAccountOption *option;

	option = purple_account_option_int_new(_("Pager port"), "port", YAHOO_PAGER_PORT);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	option = purple_account_option_string_new(_("File transfer server"), "xfer_host", YAHOO_XFER_HOST);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	option = purple_account_option_int_new(_("File transfer port"), "xfer_port", YAHOO_XFER_PORT);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	option = purple_account_option_string_new(_("Chat room locale"), "room_list_locale", YAHOO_ROOMLIST_LOCALE);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	option = purple_account_option_string_new(_("Encoding"), "local_charset", "UTF-8");
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	option = purple_account_option_bool_new(_("Ignore conference and chatroom invitations"), "ignore_invites", FALSE);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	option = purple_account_option_bool_new(_("Use account proxy for HTTP and HTTPS connections"), "proxy_ssl", FALSE);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

#if 0
	option = purple_account_option_string_new(_("Chat room list URL"), "room_list", YAHOO_ROOMLIST_URL);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);
#endif

	my_protocol = plugin;
	yahoo_register_commands();
	yahoo_init_colorht();

	purple_signal_connect(purple_get_core(), "uri-handler", plugin,
		PURPLE_CALLBACK(yahoo_uri_handler), NULL);
}

PURPLE_INIT_PLUGIN(yahoo, init_plugin, info);
