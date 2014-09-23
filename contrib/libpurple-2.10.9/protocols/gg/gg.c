/**
 * @file gg.c Gadu-Gadu protocol plugin
 *
 * purple
 *
 * Copyright (C) 2005  Bartosz Oler <bartosz@bzimage.us>
 *
 * Some parts of the code are adapted or taken from the previous implementation
 * of this plugin written by Arkadiusz Miskiewicz <misiek@pld.org.pl>
 * Some parts Copyright (C) 2009  Krzysztof Klinikowski <grommasher@gmail.com>
 *
 * Thanks to Google's Summer of Code Program.
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
#include "version.h"
#include "notify.h"
#include "status.h"
#include "blist.h"
#include "accountopt.h"
#include "debug.h"
#include "util.h"
#include "request.h"
#include "xmlnode.h"

#include <libgadu.h>

#include "gg.h"
#include "confer.h"
#include "search.h"
#include "buddylist.h"
#include "gg-utils.h"

#define DISABLE_AVATARS 1

static PurplePlugin *my_protocol = NULL;

/* Prototypes */
static void ggp_set_status(PurpleAccount *account, PurpleStatus *status);
static int ggp_to_gg_status(PurpleStatus *status, char **msg);

/* ---------------------------------------------------------------------- */
/* ----- EXTERNAL CALLBACKS --------------------------------------------- */
/* ---------------------------------------------------------------------- */


/* ----- HELPERS -------------------------------------------------------- */

static PurpleInputCondition
ggp_tcpsocket_inputcond_gg_to_purple(enum gg_check_t check)
{
	PurpleInputCondition cond = 0;

	if (check & GG_CHECK_READ)
		cond |= PURPLE_INPUT_READ;
	if (check & GG_CHECK_WRITE)
		cond |= PURPLE_INPUT_WRITE;

	return cond;
}

/**
 * Set up libgadu's proxy.
 *
 * @param account Account for which to set up the proxy.
 *
 * @return Zero if proxy setup is valid, otherwise -1.
 */
static int ggp_setup_proxy(PurpleAccount *account)
{
	PurpleProxyInfo *gpi;

	gpi = purple_proxy_get_setup(account);

	if ((purple_proxy_info_get_type(gpi) != PURPLE_PROXY_NONE) &&
	    (purple_proxy_info_get_host(gpi) == NULL ||
	     purple_proxy_info_get_port(gpi) <= 0)) {

		gg_proxy_enabled = 0;
		purple_notify_error(NULL, NULL, _("Invalid proxy settings"),
				  _("Either the host name or port number specified for your given proxy type is invalid."));
		return -1;
	} else if (purple_proxy_info_get_type(gpi) != PURPLE_PROXY_NONE) {
		gg_proxy_enabled = 1;
		gg_proxy_host = g_strdup(purple_proxy_info_get_host(gpi));
		gg_proxy_port = purple_proxy_info_get_port(gpi);
		gg_proxy_username = g_strdup(purple_proxy_info_get_username(gpi));
		gg_proxy_password = g_strdup(purple_proxy_info_get_password(gpi));
	} else {
		gg_proxy_enabled = 0;
	}

	return 0;
}

/* }}} */

/* ---------------------------------------------------------------------- */

static void ggp_callback_buddylist_save_ok(PurpleConnection *gc, const char *filename)
{
	PurpleAccount *account = purple_connection_get_account(gc);

	char *buddylist = ggp_buddylist_dump(account);

	purple_debug_info("gg", "Saving...\n");
	purple_debug_info("gg", "file = %s\n", filename);

	if (buddylist == NULL) {
		purple_notify_info(account, _("Save Buddylist..."),
			 _("Your buddylist is empty, nothing was written to the file."),
			 NULL);
		return;
	}

	if(purple_util_write_data_to_file_absolute(filename, buddylist, -1)) {
		purple_notify_info(account, _("Save Buddylist..."),
			 _("Buddylist saved successfully!"), NULL);
	} else {
		gchar *primary = g_strdup_printf(
			_("Couldn't write buddy list for %s to %s"),
			purple_account_get_username(account), filename);
		purple_notify_error(account, _("Save Buddylist..."),
			primary, NULL);
		g_free(primary);
	}

	g_free(buddylist);
}

static void ggp_callback_buddylist_load_ok(PurpleConnection *gc, gchar *file)
{
	PurpleAccount *account = purple_connection_get_account(gc);
	GError *error = NULL;
	char *buddylist = NULL;
	gsize length;

	purple_debug_info("gg", "file_name = %s\n", file);

	if (!g_file_get_contents(file, &buddylist, &length, &error)) {
		purple_notify_error(account,
				_("Couldn't load buddylist"),
				_("Couldn't load buddylist"),
				error->message);

		purple_debug_error("gg",
			"Couldn't load buddylist. file = %s; error = %s\n",
			file, error->message);

		g_error_free(error);

		return;
	}

	ggp_buddylist_load(gc, buddylist);
	g_free(buddylist);

	purple_notify_info(account,
			 _("Load Buddylist..."),
			 _("Buddylist loaded successfully!"), NULL);
}
/* }}} */

/*
 */
/* static void ggp_action_buddylist_save(PurplePluginAction *action) {{{ */
static void ggp_action_buddylist_save(PurplePluginAction *action)
{
	PurpleConnection *gc = (PurpleConnection *)action->context;

	purple_request_file(action, _("Save buddylist..."), NULL, TRUE,
			G_CALLBACK(ggp_callback_buddylist_save_ok), NULL,
			purple_connection_get_account(gc), NULL, NULL,
			gc);
}

static void ggp_action_buddylist_load(PurplePluginAction *action)
{
	PurpleConnection *gc = (PurpleConnection *)action->context;

	purple_request_file(action, _("Load buddylist from file..."), NULL,
			FALSE,
			G_CALLBACK(ggp_callback_buddylist_load_ok), NULL,
			purple_connection_get_account(gc), NULL, NULL,
			gc);
}

/* ----- PUBLIC DIRECTORY SEARCH ---------------------------------------- */

static void ggp_callback_show_next(PurpleConnection *gc, GList *row, gpointer user_data)
{
	GGPInfo *info = gc->proto_data;
	GGPSearchForm *form = user_data;
	guint32 seq;

	form->page_number++;

	ggp_search_remove(info->searches, form->seq);
	purple_debug_info("gg", "ggp_callback_show_next(): Removed seq %u\n",
		form->seq);

	seq = ggp_search_start(gc, form);
	ggp_search_add(info->searches, seq, form);
	purple_debug_info("gg", "ggp_callback_show_next(): Added seq %u\n",
		seq);
}

static void ggp_callback_add_buddy(PurpleConnection *gc, GList *row, gpointer user_data)
{
	purple_blist_request_add_buddy(purple_connection_get_account(gc),
				     g_list_nth_data(row, 0), NULL, NULL);
}

static void ggp_callback_im(PurpleConnection *gc, GList *row, gpointer user_data)
{
	PurpleAccount *account;
	PurpleConversation *conv;
	char *name;

	account = purple_connection_get_account(gc);

	name = g_list_nth_data(row, 0);
	conv = purple_conversation_new(PURPLE_CONV_TYPE_IM, account, name);
	purple_conversation_present(conv);
}

static void ggp_callback_find_buddies(PurpleConnection *gc, PurpleRequestFields *fields)
{
	GGPInfo *info = gc->proto_data;
	GGPSearchForm *form;
	guint32 seq;

	form = ggp_search_form_new(GGP_SEARCH_TYPE_FULL);

	form->user_data = info;
	form->lastname = g_strdup(
		purple_request_fields_get_string(fields, "lastname"));
	form->firstname = g_strdup(
		purple_request_fields_get_string(fields, "firstname"));
	form->nickname = g_strdup(
		purple_request_fields_get_string(fields, "nickname"));
	form->city = g_strdup(
		purple_request_fields_get_string(fields, "city"));
	form->birthyear = g_strdup(
		purple_request_fields_get_string(fields, "year"));

	switch (purple_request_fields_get_choice(fields, "gender")) {
		case 1:
			form->gender = g_strdup(GG_PUBDIR50_GENDER_MALE);
			break;
		case 2:
			form->gender = g_strdup(GG_PUBDIR50_GENDER_FEMALE);
			break;
		default:
			form->gender = NULL;
			break;
	}

	form->active = purple_request_fields_get_bool(fields, "active")
				   ? g_strdup(GG_PUBDIR50_ACTIVE_TRUE) : NULL;

	seq = ggp_search_start(gc, form);
	ggp_search_add(info->searches, seq, form);
	purple_debug_info("gg", "ggp_callback_find_buddies(): Added seq %u\n",
		seq);
}

static void ggp_find_buddies(PurplePluginAction *action)
{
	PurpleConnection *gc = (PurpleConnection *)action->context;

	PurpleRequestFields *fields;
	PurpleRequestFieldGroup *group;
	PurpleRequestField *field;

	fields = purple_request_fields_new();
	group = purple_request_field_group_new(NULL);
	purple_request_fields_add_group(fields, group);

	field = purple_request_field_string_new("lastname",
			_("Last name"), NULL, FALSE);
	purple_request_field_string_set_masked(field, FALSE);
	purple_request_field_group_add_field(group, field);

	field = purple_request_field_string_new("firstname",
			_("First name"), NULL, FALSE);
	purple_request_field_string_set_masked(field, FALSE);
	purple_request_field_group_add_field(group, field);

	field = purple_request_field_string_new("nickname",
			_("Nickname"), NULL, FALSE);
	purple_request_field_string_set_masked(field, FALSE);
	purple_request_field_group_add_field(group, field);

	field = purple_request_field_string_new("city",
			_("City"), NULL, FALSE);
	purple_request_field_string_set_masked(field, FALSE);
	purple_request_field_group_add_field(group, field);

	field = purple_request_field_string_new("year",
			_("Year of birth"), NULL, FALSE);
	purple_request_field_group_add_field(group, field);

	field = purple_request_field_choice_new("gender", _("Gender"), 0);
	purple_request_field_choice_add(field, _("Male or female"));
	purple_request_field_choice_add(field, _("Male"));
	purple_request_field_choice_add(field, _("Female"));
	purple_request_field_group_add_field(group, field);

	field = purple_request_field_bool_new("active",
			_("Only online"), FALSE);
	purple_request_field_group_add_field(group, field);

	purple_request_fields(gc,
		_("Find buddies"),
		_("Find buddies"),
		_("Please, enter your search criteria below"),
		fields,
		_("OK"), G_CALLBACK(ggp_callback_find_buddies),
		_("Cancel"), NULL,
		purple_connection_get_account(gc), NULL, NULL,
		gc);
}

/* ----- CHANGE STATUS BROADCASTING ------------------------------------------------ */

static void ggp_action_change_status_broadcasting_ok(PurpleConnection *gc, PurpleRequestFields *fields)
{
	GGPInfo *info = gc->proto_data;
	int selected_field;
	PurpleAccount *account = purple_connection_get_account(gc);
	PurpleStatus *status;

	selected_field = purple_request_fields_get_choice(fields, "status_broadcasting");
	
	if (selected_field == 0)
		info->status_broadcasting = TRUE;
	else
		info->status_broadcasting = FALSE;
	
	status = purple_account_get_active_status(account);
	
	ggp_set_status(account, status);
}

static void ggp_action_change_status_broadcasting(PurplePluginAction *action)
{
	PurpleConnection *gc = (PurpleConnection *)action->context;
	GGPInfo *info = gc->proto_data;
	
	PurpleRequestFields *fields;
	PurpleRequestFieldGroup *group;
	PurpleRequestField *field;

	fields = purple_request_fields_new();
	group = purple_request_field_group_new(NULL);
	purple_request_fields_add_group(fields, group);
	
	field = purple_request_field_choice_new("status_broadcasting", _("Show status to:"), 0);
	purple_request_field_choice_add(field, _("All people"));
	purple_request_field_choice_add(field, _("Only buddies"));
	purple_request_field_group_add_field(group, field);

	if (info->status_broadcasting)
		purple_request_field_choice_set_default_value(field, 0);
	else
		purple_request_field_choice_set_default_value(field, 1);

	purple_request_fields(gc,
		_("Change status broadcasting"),
		_("Change status broadcasting"),
		_("Please, select who can see your status"),
		fields,
		_("OK"), G_CALLBACK(ggp_action_change_status_broadcasting_ok),
		_("Cancel"), NULL,
		purple_connection_get_account(gc), NULL, NULL,
		gc);
}

/* ----- CONFERENCES ---------------------------------------------------- */

static void ggp_callback_add_to_chat_ok(PurpleBuddy *buddy, PurpleRequestFields *fields)
{
	PurpleConnection *conn;
	PurpleRequestField *field;
	GList *sel;

	conn = purple_account_get_connection(purple_buddy_get_account(buddy));

	g_return_if_fail(conn != NULL);

	field = purple_request_fields_get_field(fields, "name");
	sel = purple_request_field_list_get_selected(field);

	if (sel == NULL) {
		purple_debug_error("gg", "No chat selected\n");
		return;
	}

	ggp_confer_participants_add_uin(conn, sel->data,
					ggp_str_to_uin(purple_buddy_get_name(buddy)));
}

static void ggp_bmenu_add_to_chat(PurpleBlistNode *node, gpointer ignored)
{
	PurpleBuddy *buddy;
	PurpleConnection *gc;
	GGPInfo *info;

	PurpleRequestFields *fields;
	PurpleRequestFieldGroup *group;
	PurpleRequestField *field;

	GList *l;
	gchar *msg;

	buddy = (PurpleBuddy *)node;
	gc = purple_account_get_connection(purple_buddy_get_account(buddy));
	info = gc->proto_data;

	fields = purple_request_fields_new();
	group = purple_request_field_group_new(NULL);
	purple_request_fields_add_group(fields, group);

	field = purple_request_field_list_new("name", "Chat name");
	for (l = info->chats; l != NULL; l = l->next) {
		GGPChat *chat = l->data;
		purple_request_field_list_add(field, chat->name, chat->name);
	}
	purple_request_field_group_add_field(group, field);

	msg = g_strdup_printf(_("Select a chat for buddy: %s"),
			      purple_buddy_get_alias(buddy));
	purple_request_fields(gc,
			_("Add to chat..."),
			_("Add to chat..."),
			msg,
			fields,
			_("Add"), G_CALLBACK(ggp_callback_add_to_chat_ok),
			_("Cancel"), NULL,
			purple_connection_get_account(gc), NULL, NULL,
			buddy);
	g_free(msg);
}

/* ----- BLOCK BUDDIES -------------------------------------------------- */

static void ggp_add_deny(PurpleConnection *gc, const char *who)
{
	GGPInfo *info = gc->proto_data;
	uin_t uin = ggp_str_to_uin(who);
	
	purple_debug_info("gg", "ggp_add_deny: %u\n", uin);
	
	gg_remove_notify_ex(info->session, uin, GG_USER_NORMAL);
	gg_add_notify_ex(info->session, uin, GG_USER_BLOCKED);
}

static void ggp_rem_deny(PurpleConnection *gc, const char *who)
{
	GGPInfo *info = gc->proto_data;
	uin_t uin = ggp_str_to_uin(who);
	
	purple_debug_info("gg", "ggp_rem_deny: %u\n", uin);
	
	gg_remove_notify_ex(info->session, uin, GG_USER_BLOCKED);
	gg_add_notify_ex(info->session, uin, GG_USER_NORMAL);
}

/* ---------------------------------------------------------------------- */
/* ----- INTERNAL CALLBACKS --------------------------------------------- */
/* ---------------------------------------------------------------------- */

#if !DISABLE_AVATARS

struct gg_fetch_avatar_data
{
	PurpleConnection *gc;
	gchar *uin;
	gchar *avatar_url;
};


static void gg_fetch_avatar_cb(PurpleUtilFetchUrlData *url_data, gpointer user_data,
               const gchar *data, size_t len, const gchar *error_message) {
	struct gg_fetch_avatar_data *d = user_data;
	PurpleAccount *account;
	PurpleBuddy *buddy;
	gpointer buddy_icon_data;

	purple_debug_info("gg", "gg_fetch_avatar_cb: got avatar image for %s\n",
		d->uin);

	/* FIXME: This shouldn't be necessary */
	if (!PURPLE_CONNECTION_IS_VALID(d->gc)) {
		g_free(d->uin);
		g_free(d->avatar_url);
		g_free(d);
		g_return_if_reached();
	}

	account = purple_connection_get_account(d->gc);
	buddy = purple_find_buddy(account, d->uin);

	if (buddy == NULL)
		goto out;

	buddy_icon_data = g_memdup(data, len);

	purple_buddy_icons_set_for_user(account, purple_buddy_get_name(buddy),
			buddy_icon_data, len, d->avatar_url);
	purple_debug_info("gg", "gg_fetch_avatar_cb: UIN %s should have avatar "
		"now\n", d->uin);

out:
	g_free(d->uin);
	g_free(d->avatar_url);
	g_free(d);
}

static void gg_get_avatar_url_cb(PurpleUtilFetchUrlData *url_data, gpointer user_data,
               const gchar *url_text, size_t len, const gchar *error_message) {
	struct gg_fetch_avatar_data *data;
	PurpleConnection *gc = user_data;
	PurpleAccount *account;
	PurpleBuddy *buddy;
	const char *uin;
	const char *is_blank;
	const char *checksum;

	gchar *bigavatar = NULL;
	xmlnode *xml = NULL;
	xmlnode *xmlnode_users;
	xmlnode *xmlnode_user;
	xmlnode *xmlnode_avatars;
	xmlnode *xmlnode_avatar;
	xmlnode *xmlnode_bigavatar;

	g_return_if_fail(PURPLE_CONNECTION_IS_VALID(gc));
	account = purple_connection_get_account(gc);

	if (error_message != NULL)
		purple_debug_error("gg", "gg_get_avatars_cb error: %s\n", error_message);
	else if (len > 0 && url_text && *url_text) {
		xml = xmlnode_from_str(url_text, -1);
		if (xml == NULL)
			goto out;

		xmlnode_users = xmlnode_get_child(xml, "users");
		if (xmlnode_users == NULL)
			goto out;

		xmlnode_user = xmlnode_get_child(xmlnode_users, "user");
		if (xmlnode_user == NULL)
			goto out;

		uin = xmlnode_get_attrib(xmlnode_user, "uin");

		xmlnode_avatars = xmlnode_get_child(xmlnode_user, "avatars");
		if (xmlnode_avatars == NULL)
			goto out;

		xmlnode_avatar = xmlnode_get_child(xmlnode_avatars, "avatar");
		if (xmlnode_avatar == NULL)
			goto out;

		xmlnode_bigavatar = xmlnode_get_child(xmlnode_avatar, "originBigAvatar");
		if (xmlnode_bigavatar == NULL)
			goto out;

		is_blank = xmlnode_get_attrib(xmlnode_avatar, "blank");
		bigavatar = xmlnode_get_data(xmlnode_bigavatar);

		purple_debug_info("gg", "gg_get_avatar_url_cb: UIN %s, IS_BLANK %s, "
		                        "URL %s\n",
		                  uin ? uin : "(null)", is_blank ? is_blank : "(null)",
		                  bigavatar ? bigavatar : "(null)");

		if (uin != NULL && bigavatar != NULL) {
			buddy = purple_find_buddy(account, uin);
			if (buddy == NULL)
				goto out;

			checksum = purple_buddy_icons_get_checksum_for_user(buddy);

			if (purple_strequal(is_blank, "1")) {
				purple_buddy_icons_set_for_user(account,
						purple_buddy_get_name(buddy), NULL, 0, NULL);
			} else if (!purple_strequal(checksum, bigavatar)) {
				data = g_new0(struct gg_fetch_avatar_data, 1);
				data->gc = gc;
				data->uin = g_strdup(uin);
				data->avatar_url = g_strdup(bigavatar);

				purple_debug_info("gg", "gg_get_avatar_url_cb: "
					"requesting avatar for %s\n", uin);
				url_data = purple_util_fetch_url_request_len_with_account(account,
						bigavatar, TRUE, "Mozilla/4.0 (compatible; MSIE 5.0)",
						FALSE, NULL, FALSE, -1, gg_fetch_avatar_cb, data);
			}
		}
	}

out:
	if (xml)
		xmlnode_free(xml);
	g_free(bigavatar);
}

#endif

/**
 * Try to update avatar of the buddy.
 *
 * @param gc     PurpleConnection
 * @param uin    UIN of the buddy.
 */
static void ggp_update_buddy_avatar(PurpleConnection *gc, uin_t uin)
{
#if DISABLE_AVATARS
	purple_debug_warning("gg", "ggp_update_buddy_avatar: disabled, please "
		"update to 3.0.0, when available\n");
#else
	gchar *avatarurl;
	PurpleUtilFetchUrlData *url_data;

	purple_debug_info("gg", "ggp_update_buddy_avatar(gc, %u)\n", uin);

	avatarurl = g_strdup_printf("http://api.gadu-gadu.pl/avatars/%u/0.xml", uin);

	url_data = purple_util_fetch_url_request_len_with_account(
			purple_connection_get_account(gc), avatarurl, TRUE,
			"Mozilla/4.0 (compatible; MSIE 5.5)", FALSE, NULL, FALSE, -1,
			gg_get_avatar_url_cb, gc);

	g_free(avatarurl);
#endif
}

/**
 * Handle change of the status of the buddy.
 *
 * @param gc     PurpleConnection
 * @param uin    UIN of the buddy.
 * @param status ID of the status.
 * @param descr  Description.
 */
static void ggp_generic_status_handler(PurpleConnection *gc, uin_t uin,
				       int status, const char *descr)
{
	gchar *from;
	const char *st;
	char *status_msg = NULL;

	ggp_update_buddy_avatar(gc, uin);

	from = g_strdup_printf("%u", uin);

	switch (status) {
		case GG_STATUS_NOT_AVAIL:
		case GG_STATUS_NOT_AVAIL_DESCR:
			st = purple_primitive_get_id_from_type(PURPLE_STATUS_OFFLINE);
			break;
		case GG_STATUS_FFC:
		case GG_STATUS_FFC_DESCR:
			st = purple_primitive_get_id_from_type(PURPLE_STATUS_AVAILABLE);
			break;
		case GG_STATUS_AVAIL:
		case GG_STATUS_AVAIL_DESCR:
			st = purple_primitive_get_id_from_type(PURPLE_STATUS_AVAILABLE);
			break;
		case GG_STATUS_BUSY:
		case GG_STATUS_BUSY_DESCR:
			st = purple_primitive_get_id_from_type(PURPLE_STATUS_AWAY);
			break;
		case GG_STATUS_DND:
		case GG_STATUS_DND_DESCR:
			st = purple_primitive_get_id_from_type(PURPLE_STATUS_UNAVAILABLE);
			break;
		case GG_STATUS_BLOCKED:
			/* user is blocking us.... */
			st = "blocked";
			break;
		default:
			st = purple_primitive_get_id_from_type(PURPLE_STATUS_AVAILABLE);
			purple_debug_info("gg",
				"GG_EVENT_NOTIFY: Unknown status: %d\n", status);
			break;
	}

	if (descr != NULL) {
		status_msg = g_strdup(descr);
		g_strstrip(status_msg);
		if (status_msg[0] == '\0') {
			g_free(status_msg);
			status_msg = NULL;
		}
	}

	purple_debug_info("gg", "status of %u is %s [%s]\n", uin, st,
		status_msg ? status_msg : "");
	if (status_msg == NULL) {
		purple_prpl_got_user_status(purple_connection_get_account(gc),
			from, st, NULL);
	} else {
		purple_prpl_got_user_status(purple_connection_get_account(gc),
			from, st, "message", status_msg, NULL);
		g_free(status_msg);
	}
	g_free(from);
}

static void ggp_sr_close_cb(gpointer user_data)
{
	GGPSearchForm *form = user_data;
	GGPInfo *info = form->user_data;

	ggp_search_remove(info->searches, form->seq);
	purple_debug_info("gg", "ggp_sr_close_cb(): Removed seq %u\n",
		form->seq);
	ggp_search_form_destroy(form);
}

/**
 * Translate a status' ID to a more user-friendly name.
 *
 * @param id The ID of the status.
 *
 * @return The user-friendly name of the status.
 */
static const char *ggp_status_by_id(unsigned int id)
{
	const char *st;

	purple_debug_info("gg", "ggp_status_by_id: %d\n", id);
	switch (id) {
		case GG_STATUS_NOT_AVAIL:
		case GG_STATUS_NOT_AVAIL_DESCR:
			st = _("Offline");
			break;
		case GG_STATUS_AVAIL:
		case GG_STATUS_AVAIL_DESCR:
			st = _("Available");
			break;
		case GG_STATUS_FFC:
		case GG_STATUS_FFC_DESCR:
			return _("Chatty");
		case GG_STATUS_DND:
		case GG_STATUS_DND_DESCR:
			return _("Do Not Disturb");
		case GG_STATUS_BUSY:
		case GG_STATUS_BUSY_DESCR:
			st = _("Away");
			break;
		default:
			st = _("Unknown");
			break;
	}

	return st;
}

static void ggp_pubdir_handle_info(PurpleConnection *gc, gg_pubdir50_t req,
				   GGPSearchForm *form)
{
	PurpleNotifyUserInfo *user_info;
	PurpleBuddy *buddy;
	char *val, *who;

	user_info = purple_notify_user_info_new();

	val = ggp_search_get_result(req, 0, GG_PUBDIR50_STATUS);
	/* XXX: Use of ggp_str_to_uin() is an ugly hack! */
	purple_notify_user_info_add_pair(user_info, _("Status"), ggp_status_by_id(ggp_str_to_uin(val)));
	g_free(val);

	who = ggp_search_get_result(req, 0, GG_PUBDIR50_UIN);
	purple_notify_user_info_add_pair(user_info, _("UIN"), who);

	val = ggp_search_get_result(req, 0, GG_PUBDIR50_FIRSTNAME);
	purple_notify_user_info_add_pair(user_info, _("First Name"), val);
	g_free(val);

	val = ggp_search_get_result(req, 0, GG_PUBDIR50_NICKNAME);
	purple_notify_user_info_add_pair(user_info, _("Nickname"), val);
	g_free(val);

	val = ggp_search_get_result(req, 0, GG_PUBDIR50_CITY);
	purple_notify_user_info_add_pair(user_info, _("City"), val);
	g_free(val);

	val = ggp_search_get_result(req, 0, GG_PUBDIR50_BIRTHYEAR);
	if (strncmp(val, "0", 1)) {
		purple_notify_user_info_add_pair(user_info, _("Birth Year"), val);
	}
	g_free(val);

	/*
	 * Include a status message, if exists and buddy is in the blist.
	 */
	buddy = purple_find_buddy(purple_connection_get_account(gc), who);
	if (NULL != buddy) {
		PurpleStatus *status;
		const char *msg;
		char *text;

		status = purple_presence_get_active_status(purple_buddy_get_presence(buddy));
		msg = purple_status_get_attr_string(status, "message");

		if (msg != NULL) {
			text = g_markup_escape_text(msg, -1);
			purple_notify_user_info_add_pair(user_info, _("Message"), text);
			g_free(text);
		}
	}

	purple_notify_userinfo(gc, who, user_info, ggp_sr_close_cb, form);
	g_free(who);
	purple_notify_user_info_destroy(user_info);
}

static void ggp_pubdir_handle_full(PurpleConnection *gc, gg_pubdir50_t req,
				   GGPSearchForm *form)
{
	PurpleNotifySearchResults *results;
	PurpleNotifySearchColumn *column;
	int res_count;
	int start;
	int i;

	g_return_if_fail(form != NULL);

	res_count = gg_pubdir50_count(req);
	res_count = (res_count > PUBDIR_RESULTS_MAX) ? PUBDIR_RESULTS_MAX : res_count;
	if (form->page_size == 0)
		form->page_size = res_count;

	results = purple_notify_searchresults_new();

	if (results == NULL) {
		purple_debug_error("gg", "ggp_pubdir_reply_handler: "
				 "Unable to display the search results.\n");
		purple_notify_error(gc, NULL,
				  _("Unable to display the search results."),
				  NULL);
		if (form->window == NULL)
			ggp_sr_close_cb(form);
		return;
	}

	column = purple_notify_searchresults_column_new(_("UIN"));
	purple_notify_searchresults_column_add(results, column);

	column = purple_notify_searchresults_column_new(_("First Name"));
	purple_notify_searchresults_column_add(results, column);

	column = purple_notify_searchresults_column_new(_("Nickname"));
	purple_notify_searchresults_column_add(results, column);

	column = purple_notify_searchresults_column_new(_("City"));
	purple_notify_searchresults_column_add(results, column);

	column = purple_notify_searchresults_column_new(_("Birth Year"));
	purple_notify_searchresults_column_add(results, column);

	purple_debug_info("gg", "Going with %d entries\n", res_count);

	start = (int)ggp_str_to_uin(gg_pubdir50_get(req, 0, GG_PUBDIR50_START));
	purple_debug_info("gg", "start = %d\n", start);

	for (i = 0; i < res_count; i++) {
		GList *row = NULL;
		char *birth = ggp_search_get_result(req, i, GG_PUBDIR50_BIRTHYEAR);

		/* TODO: Status will be displayed as an icon. */
		/* row = g_list_append(row, ggp_search_get_result(req, i, GG_PUBDIR50_STATUS)); */
		row = g_list_append(row, ggp_search_get_result(req, i,
							GG_PUBDIR50_UIN));
		row = g_list_append(row, ggp_search_get_result(req, i,
							GG_PUBDIR50_FIRSTNAME));
		row = g_list_append(row, ggp_search_get_result(req, i,
							GG_PUBDIR50_NICKNAME));
		row = g_list_append(row, ggp_search_get_result(req, i,
							GG_PUBDIR50_CITY));
		row = g_list_append(row,
			(birth && strncmp(birth, "0", 1)) ? birth : g_strdup("-"));

		purple_notify_searchresults_row_add(results, row);
	}

	purple_notify_searchresults_button_add(results, PURPLE_NOTIFY_BUTTON_CONTINUE,
					     ggp_callback_show_next);
	purple_notify_searchresults_button_add(results, PURPLE_NOTIFY_BUTTON_ADD,
					     ggp_callback_add_buddy);
	purple_notify_searchresults_button_add(results, PURPLE_NOTIFY_BUTTON_IM,
					     ggp_callback_im);

	if (form->window == NULL) {
		void *h = purple_notify_searchresults(gc,
				_("Gadu-Gadu Public Directory"),
				_("Search results"), NULL, results,
				(PurpleNotifyCloseCallback)ggp_sr_close_cb,
				form);

		if (h == NULL) {
			purple_debug_error("gg", "ggp_pubdir_reply_handler: "
					 "Unable to display the search results.\n");
			purple_notify_error(gc, NULL,
					  _("Unable to display the search results."),
					  NULL);
			return;
		}

		form->window = h;
	} else {
		purple_notify_searchresults_new_rows(gc, results, form->window);
	}
}

static void ggp_pubdir_reply_handler(PurpleConnection *gc, gg_pubdir50_t req)
{
	GGPInfo *info = gc->proto_data;
	GGPSearchForm *form;
	int res_count;
	guint32 seq;

	seq = gg_pubdir50_seq(req);
	form = ggp_search_get(info->searches, seq);
	purple_debug_info("gg",
		"ggp_pubdir_reply_handler(): seq %u --> form %p\n", seq, form);
	/*
	 * this can happen when user will request more results
	 * and close the results window before they arrive.
	 */
	g_return_if_fail(form != NULL);

	res_count = gg_pubdir50_count(req);
	if (res_count < 1) {
		purple_debug_info("gg", "GG_EVENT_PUBDIR50_SEARCH_REPLY: Nothing found\n");
		purple_notify_error(gc, NULL,
			_("No matching users found"),
			_("There are no users matching your search criteria."));
		if (form->window == NULL)
			ggp_sr_close_cb(form);
		return;
	}

	switch (form->search_type) {
		case GGP_SEARCH_TYPE_INFO:
			ggp_pubdir_handle_info(gc, req, form);
			break;
		case GGP_SEARCH_TYPE_FULL:
			ggp_pubdir_handle_full(gc, req, form);
			break;
		default:
			purple_debug_warning("gg", "Unknown search_type!\n");
			break;
	}
}

static void ggp_recv_image_handler(PurpleConnection *gc, const struct gg_event *ev)
{
	gint imgid = 0;
	GGPInfo *info = gc->proto_data;
	GList *entry = g_list_first(info->pending_richtext_messages);
	gchar *handlerid = g_strdup_printf("IMGID_HANDLER-%i", ev->event.image_reply.crc32);

	imgid = purple_imgstore_add_with_id(
		g_memdup(ev->event.image_reply.image, ev->event.image_reply.size),
		ev->event.image_reply.size,
		ev->event.image_reply.filename);

	purple_debug_info("gg", "ggp_recv_image_handler: got image with crc32: %u\n", ev->event.image_reply.crc32);

	while(entry) {
		if (strstr((gchar *)entry->data, handlerid) != NULL) {
			gchar **split = g_strsplit((gchar *)entry->data, handlerid, 3);
			gchar *text = g_strdup_printf("%s%i%s", split[0], imgid, split[1]);
			purple_debug_info("gg", "ggp_recv_image_handler: found message matching crc32: %s\n", (gchar *)entry->data);
			g_strfreev(split);
			info->pending_richtext_messages = g_list_remove(info->pending_richtext_messages, entry->data);
			/* We don't have any more images to download */
			if (strstr(text, "<IMG ID=\"IMGID_HANDLER") == NULL) {
				gchar *buf = g_strdup_printf("%lu", (unsigned long int)ev->event.image_reply.sender);
				serv_got_im(gc, buf, text, PURPLE_MESSAGE_IMAGES, time(NULL));
				g_free(buf);
				purple_debug_info("gg", "ggp_recv_image_handler: richtext message: %s\n", text);
				g_free(text);
				break;
			}
			info->pending_richtext_messages = g_list_append(info->pending_richtext_messages, text);
			break;
		}
		entry = g_list_next(entry);
	}
	g_free(handlerid);

	return;
}


/**
 * Dispatch a message received from a buddy.
 *
 * @param gc PurpleConnection.
 * @param ev Gadu-Gadu event structure.
 *
 * Image receiving, some code borrowed from Kadu http://www.kadu.net
 */
static void ggp_recv_message_handler(PurpleConnection *gc, const struct gg_event *ev)
{
	GGPInfo *info = gc->proto_data;
	PurpleConversation *conv;
	gchar *from;
	gchar *msg;
	gchar *tmp;

	if (ev->event.msg.message == NULL)
	{
		purple_debug_warning("gg", "ggp_recv_message_handler: NULL as message pointer\n");
		return;
	}

	from = g_strdup_printf("%lu", (unsigned long int)ev->event.msg.sender);

	/*
	tmp = charset_convert((const char *)ev->event.msg.message,
			      "CP1250", "UTF-8");
	*/
	tmp = g_strdup_printf("%s", ev->event.msg.message);
	purple_str_strip_char(tmp, '\r');
	msg = g_markup_escape_text(tmp, -1);
	g_free(tmp);

	/* We got richtext message */
	if (ev->event.msg.formats_length)
	{
		gboolean got_image = FALSE, bold = FALSE, italic = FALSE, under = FALSE;
		char *cformats = (char *)ev->event.msg.formats;
		char *cformats_end = cformats + ev->event.msg.formats_length;
		gint increased_len = 0;
		struct gg_msg_richtext_format *actformat;
		struct gg_msg_richtext_image *actimage;
		GString *message = g_string_new(msg);
		gchar *handlerid;

		purple_debug_info("gg", "ggp_recv_message_handler: richtext msg from (%s): %s %i formats\n", from, msg, ev->event.msg.formats_length);

		while (cformats < cformats_end)
		{
			gint byteoffset;
			actformat = (struct gg_msg_richtext_format *)cformats;
			cformats += sizeof(struct gg_msg_richtext_format);
			byteoffset = g_utf8_offset_to_pointer(message->str, actformat->position + increased_len) - message->str;

			if(actformat->position == 0 && actformat->font == 0) {
				purple_debug_warning("gg", "ggp_recv_message_handler: bogus formatting (inc: %i)\n", increased_len);
				continue;
			}
			purple_debug_info("gg", "ggp_recv_message_handler: format at pos: %i, image:%i, bold:%i, italic: %i, under:%i (inc: %i)\n",
				actformat->position,
				(actformat->font & GG_FONT_IMAGE) != 0,
				(actformat->font & GG_FONT_BOLD) != 0,
				(actformat->font & GG_FONT_ITALIC) != 0,
				(actformat->font & GG_FONT_UNDERLINE) != 0,
				increased_len);

			if (actformat->font & GG_FONT_IMAGE) {
				got_image = TRUE;
				actimage = (struct gg_msg_richtext_image*)(cformats);
				cformats += sizeof(struct gg_msg_richtext_image);
				purple_debug_info("gg", "ggp_recv_message_handler: image received, size: %d, crc32: %i\n", actimage->size, actimage->crc32);

				/* Checking for errors, image size shouldn't be
				 * larger than 255.000 bytes */
				if (actimage->size > 255000) {
					purple_debug_warning("gg", "ggp_recv_message_handler: received image large than 255 kb\n");
					continue;
				}

				gg_image_request(info->session, ev->event.msg.sender,
					actimage->size, actimage->crc32);

				handlerid = g_strdup_printf("<IMG ID=\"IMGID_HANDLER-%i\">", actimage->crc32);
				g_string_insert(message, byteoffset, handlerid);
				increased_len += strlen(handlerid);
				g_free(handlerid);
				continue;
			}

			if (actformat->font & GG_FONT_BOLD) {
				if (bold == FALSE) {
					g_string_insert(message, byteoffset, "<b>");
					increased_len += 3;
					bold = TRUE;
				}
			} else if (bold) {
				g_string_insert(message, byteoffset, "</b>");
				increased_len += 4;
				bold = FALSE;
			}

			if (actformat->font & GG_FONT_ITALIC) {
				if (italic == FALSE) {
					g_string_insert(message, byteoffset, "<i>");
					increased_len += 3;
					italic = TRUE;
				}
			} else if (italic) {
				g_string_insert(message, byteoffset, "</i>");
				increased_len += 4;
				italic = FALSE;
			}

			if (actformat->font & GG_FONT_UNDERLINE) {
				if (under == FALSE) {
					g_string_insert(message, byteoffset, "<u>");
					increased_len += 3;
					under = TRUE;
				}
			} else if (under) {
				g_string_insert(message, byteoffset, "</u>");
				increased_len += 4;
				under = FALSE;
			}

			if (actformat->font & GG_FONT_COLOR) {
				cformats += sizeof(struct gg_msg_richtext_color);
			}
		}

		msg = message->str;
		g_string_free(message, FALSE);

		if (got_image) {
			info->pending_richtext_messages = g_list_append(info->pending_richtext_messages, msg);
			return;
		}
	}

	purple_debug_info("gg", "ggp_recv_message_handler: msg from (%s): %s (class = %d; rcpt_count = %d)\n",
			from, msg, ev->event.msg.msgclass,
			ev->event.msg.recipients_count);

	if (ev->event.msg.recipients_count == 0) {
		serv_got_im(gc, from, msg, 0, ev->event.msg.time);
	} else {
		const char *chat_name;
		int chat_id;
		char *buddy_name;

		chat_name = ggp_confer_find_by_participants(gc,
				ev->event.msg.recipients,
				ev->event.msg.recipients_count);

		if (chat_name == NULL) {
			chat_name = ggp_confer_add_new(gc, NULL);
			serv_got_joined_chat(gc, info->chats_count, chat_name);

			ggp_confer_participants_add_uin(gc, chat_name,
							ev->event.msg.sender);

			ggp_confer_participants_add(gc, chat_name,
						    ev->event.msg.recipients,
						    ev->event.msg.recipients_count);
		}
		conv = ggp_confer_find_by_name(gc, chat_name);
		chat_id = purple_conv_chat_get_id(PURPLE_CONV_CHAT(conv));

		buddy_name = ggp_buddy_get_name(gc, ev->event.msg.sender);
		serv_got_chat_in(gc, chat_id, buddy_name,
				 PURPLE_MESSAGE_RECV, msg, ev->event.msg.time);
		g_free(buddy_name);
	}
	g_free(msg);
	g_free(from);
}

static void ggp_send_image_handler(PurpleConnection *gc, const struct gg_event *ev)
{
	GGPInfo *info = gc->proto_data;
	PurpleStoredImage *image;
	gint imgid = GPOINTER_TO_INT(g_hash_table_lookup(info->pending_images, GINT_TO_POINTER(ev->event.image_request.crc32)));

	purple_debug_info("gg", "ggp_send_image_handler: image request received, crc32: %u, imgid: %d\n", ev->event.image_request.crc32, imgid);

	if(imgid)
	{
		if((image = purple_imgstore_find_by_id(imgid))) {
			gint image_size = purple_imgstore_get_size(image);
			gconstpointer image_bin = purple_imgstore_get_data(image);
			const char *image_filename = purple_imgstore_get_filename(image);

			purple_debug_info("gg", "ggp_send_image_handler: sending image imgid: %i, crc: %u\n", imgid, ev->event.image_request.crc32);
			gg_image_reply(info->session, (unsigned long int)ev->event.image_request.sender, image_filename, image_bin, image_size);
			purple_imgstore_unref(image);
		} else {
			purple_debug_error("gg", "ggp_send_image_handler: image imgid: %i, crc: %u in hash but not found in imgstore!\n", imgid, ev->event.image_request.crc32);
		}
		g_hash_table_remove(info->pending_images, GINT_TO_POINTER(ev->event.image_request.crc32));
	}
}

static void ggp_typing_notification_handler(PurpleConnection *gc, uin_t uin, int length) {
	gchar *from;

	from = g_strdup_printf("%u", uin);
	if (length)
		serv_got_typing(gc, from, 0, PURPLE_TYPING);
	else
		serv_got_typing_stopped(gc, from);
	g_free(from);
}

/**
 * Handling of XML events.
 *
 * @param gc PurpleConnection.
 * @param data Raw XML contents.
 *
 * @see http://toxygen.net/libgadu/protocol/#ch1.13
 */
static void ggp_xml_event_handler(PurpleConnection *gc, char *data)
{
	xmlnode *xml = NULL;
	xmlnode *xmlnode_next_event;

	xml = xmlnode_from_str(data, -1);
	if (xml == NULL)
		goto out;

	xmlnode_next_event = xmlnode_get_child(xml, "event");
	while (xmlnode_next_event != NULL)
	{
		xmlnode *xmlnode_current_event = xmlnode_next_event;
		
		xmlnode *xmlnode_type;
		char *event_type_raw;
		int event_type = 0;
		
		xmlnode *xmlnode_sender;
		char *event_sender_raw;
		uin_t event_sender = 0;

		xmlnode_next_event = xmlnode_get_next_twin(xmlnode_next_event);
		
		xmlnode_type = xmlnode_get_child(xmlnode_current_event, "type");
		if (xmlnode_type == NULL)
			continue;
		event_type_raw = xmlnode_get_data(xmlnode_type);
		if (event_type_raw != NULL)
			event_type = atoi(event_type_raw);
		g_free(event_type_raw);
		
		xmlnode_sender = xmlnode_get_child(xmlnode_current_event, "sender");
		if (xmlnode_sender != NULL)
		{
			event_sender_raw = xmlnode_get_data(xmlnode_sender);
			if (event_sender_raw != NULL)
				event_sender = ggp_str_to_uin(event_sender_raw);
			g_free(event_sender_raw);
		}
		
		switch (event_type)
		{
			case 28: /* avatar update */
				purple_debug_info("gg",
					"ggp_xml_event_handler: avatar updated (uid: %u)\n",
					event_sender);
				ggp_update_buddy_avatar(gc, event_sender);
				break;
			default:
				purple_debug_error("gg",
					"ggp_xml_event_handler: unsupported event type=%d from=%u\n",
					event_type, event_sender);
		}
	}
	
	out:
		if (xml)
			xmlnode_free(xml);
}

static void ggp_callback_recv(gpointer _gc, gint fd, PurpleInputCondition cond)
{
	PurpleConnection *gc = _gc;
	GGPInfo *info = gc->proto_data;
	struct gg_event *ev;
	int i;

	if (!(ev = gg_watch_fd(info->session))) {
		purple_debug_error("gg",
			"ggp_callback_recv: gg_watch_fd failed -- CRITICAL!\n");
		purple_connection_error_reason (gc,
			PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
			_("Unable to read from socket"));
		return;
	}

	purple_input_remove(gc->inpa);
	gc->inpa = purple_input_add(info->session->fd,
		ggp_tcpsocket_inputcond_gg_to_purple(info->session->check),
		ggp_callback_recv, gc);

	switch (ev->type) {
		case GG_EVENT_NONE:
			/* Nothing happened. */
			break;
		case GG_EVENT_MSG:
			ggp_recv_message_handler(gc, ev);
			break;
		case GG_EVENT_ACK:
			/* Changing %u to %i fixes compiler warning */
			purple_debug_info("gg",
				"ggp_callback_recv: message sent to: %i, delivery status=%d, seq=%d\n",
				ev->event.ack.recipient, ev->event.ack.status,
				ev->event.ack.seq);
			break;
		case GG_EVENT_IMAGE_REPLY:
			ggp_recv_image_handler(gc, ev);
			break;
		case GG_EVENT_IMAGE_REQUEST:
			ggp_send_image_handler(gc, ev);
			break;
		case GG_EVENT_NOTIFY:
		case GG_EVENT_NOTIFY_DESCR:
			{
				struct gg_notify_reply *n;
				char *descr;

				purple_debug_info("gg", "notify_pre: (%d) status: %d\n",
						ev->event.notify->uin,
						GG_S(ev->event.notify->status));

				n = (ev->type == GG_EVENT_NOTIFY) ? ev->event.notify
								  : ev->event.notify_descr.notify;

				for (; n->uin; n++) {
					descr = (ev->type == GG_EVENT_NOTIFY) ? NULL
							: ev->event.notify_descr.descr;

					purple_debug_info("gg",
						"notify: (%d) status: %d; descr: %s\n",
						n->uin, GG_S(n->status), descr ? descr : "(null)");

					ggp_generic_status_handler(gc,
						n->uin, GG_S(n->status), descr);
				}
			}
			break;
		case GG_EVENT_NOTIFY60:
			for (i = 0; ev->event.notify60[i].uin; i++) {
				purple_debug_info("gg",
					"notify60: (%d) status=%d; version=%d; descr=%s\n",
					ev->event.notify60[i].uin,
					GG_S(ev->event.notify60[i].status),
					ev->event.notify60[i].version,
					ev->event.notify60[i].descr ? ev->event.notify60[i].descr : "(null)");

				ggp_generic_status_handler(gc, ev->event.notify60[i].uin,
					GG_S(ev->event.notify60[i].status),
					ev->event.notify60[i].descr);
			}
			break;
		case GG_EVENT_STATUS:
			purple_debug_info("gg", "status: (%d) status=%d; descr=%s\n",
					ev->event.status.uin, GG_S(ev->event.status.status),
					ev->event.status.descr ? ev->event.status.descr : "(null)");

			ggp_generic_status_handler(gc, ev->event.status.uin,
				GG_S(ev->event.status.status), ev->event.status.descr);
			break;
		case GG_EVENT_STATUS60:
			purple_debug_info("gg",
				"status60: (%d) status=%d; version=%d; descr=%s\n",
				ev->event.status60.uin, GG_S(ev->event.status60.status),
				ev->event.status60.version,
				ev->event.status60.descr ? ev->event.status60.descr : "(null)");

			ggp_generic_status_handler(gc, ev->event.status60.uin,
				GG_S(ev->event.status60.status), ev->event.status60.descr);
			break;
		case GG_EVENT_PUBDIR50_SEARCH_REPLY:
			ggp_pubdir_reply_handler(gc, ev->event.pubdir50);
			break;
		case GG_EVENT_TYPING_NOTIFICATION:
			ggp_typing_notification_handler(gc, ev->event.typing_notification.uin,
				ev->event.typing_notification.length);
			break;
		case GG_EVENT_XML_EVENT:
			purple_debug_info("gg", "GG_EVENT_XML_EVENT\n");
			ggp_xml_event_handler(gc, ev->event.xml_event.data);
			break;
		default:
			purple_debug_error("gg",
				"unsupported event type=%d\n", ev->type);
			break;
	}

	gg_free_event(ev);
}

static void ggp_async_login_handler(gpointer _gc, gint fd, PurpleInputCondition cond)
{
	PurpleConnection *gc = _gc;
	GGPInfo *info;
	struct gg_event *ev;

	g_return_if_fail(PURPLE_CONNECTION_IS_VALID(gc));

	info = gc->proto_data;

	purple_debug_info("gg", "login_handler: session: check = %d; state = %d;\n",
			info->session->check, info->session->state);

	switch (info->session->state) {
		case GG_STATE_RESOLVING:
			purple_debug_info("gg", "GG_STATE_RESOLVING\n");
			break;
		case GG_STATE_RESOLVING_GG:
			purple_debug_info("gg", "GG_STATE_RESOLVING_GG\n");
			break;
		case GG_STATE_CONNECTING_HUB:
			purple_debug_info("gg", "GG_STATE_CONNECTING_HUB\n");
			break;
		case GG_STATE_READING_DATA:
			purple_debug_info("gg", "GG_STATE_READING_DATA\n");
			break;
		case GG_STATE_CONNECTING_GG:
			purple_debug_info("gg", "GG_STATE_CONNECTING_GG\n");
			break;
		case GG_STATE_READING_KEY:
			purple_debug_info("gg", "GG_STATE_READING_KEY\n");
			break;
		case GG_STATE_READING_REPLY:
			purple_debug_info("gg", "GG_STATE_READING_REPLY\n");
			break;
		case GG_STATE_TLS_NEGOTIATION:
			purple_debug_info("gg", "GG_STATE_TLS_NEGOTIATION\n");
			break;
		default:
			purple_debug_error("gg", "unknown state = %d\n",
					 info->session->state);
		break;
	}

	if (!(ev = gg_watch_fd(info->session))) {
		purple_debug_error("gg", "login_handler: gg_watch_fd failed!\n");
		purple_connection_error_reason (gc,
			PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
			_("Unable to read from socket"));
		return;
	}
	purple_debug_info("gg", "login_handler: session->fd = %d\n", info->session->fd);
	purple_debug_info("gg", "login_handler: session: check = %d; state = %d;\n",
			info->session->check, info->session->state);

	purple_input_remove(gc->inpa);

	/** XXX I think that this shouldn't be done if ev->type is GG_EVENT_CONN_FAILED or GG_EVENT_CONN_SUCCESS -datallah */
	if (info->session->fd >= 0)
		gc->inpa = purple_input_add(info->session->fd,
			ggp_tcpsocket_inputcond_gg_to_purple(info->session->check),
			ggp_async_login_handler, gc);

	switch (ev->type) {
		case GG_EVENT_NONE:
			/* Nothing happened. */
			purple_debug_info("gg", "GG_EVENT_NONE\n");
			break;
		case GG_EVENT_CONN_SUCCESS:
			{
				purple_debug_info("gg", "GG_EVENT_CONN_SUCCESS\n");
				purple_input_remove(gc->inpa);
				gc->inpa = purple_input_add(info->session->fd,
					ggp_tcpsocket_inputcond_gg_to_purple(info->session->check),
					ggp_callback_recv, gc);

				ggp_buddylist_send(gc);
				purple_connection_update_progress(gc, _("Connected"), 1, 2);
				purple_connection_set_state(gc, PURPLE_CONNECTED);
			}
			break;
		case GG_EVENT_CONN_FAILED:
			purple_input_remove(gc->inpa);
			gc->inpa = 0;
			purple_connection_error_reason (gc,
				PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
				_("Connection failed"));
			break;
		case GG_EVENT_MSG:
			if (ev->event.msg.sender == 0)
				/* system messages are mostly ads */
				purple_debug_info("gg", "System message:\n%s\n",
					ev->event.msg.message);
			else
				purple_debug_warning("gg", "GG_EVENT_MSG: message from user %u "
					"unexpected while connecting:\n%s\n",
					ev->event.msg.sender,
					ev->event.msg.message);
			break;
		default:
			purple_debug_error("gg", "strange event: %d\n", ev->type);
			break;
	}

	gg_free_event(ev);
}

/* ---------------------------------------------------------------------- */
/* ----- PurplePluginProtocolInfo ----------------------------------------- */
/* ---------------------------------------------------------------------- */

static const char *ggp_list_icon(PurpleAccount *account, PurpleBuddy *buddy)
{
	return "gadu-gadu";
}

static char *ggp_status_text(PurpleBuddy *b)
{
	PurpleStatus *status;
	const char *msg;
	char *text;
	char *tmp;

	status = purple_presence_get_active_status(
		purple_buddy_get_presence(b));
	msg = purple_status_get_attr_string(status, "message");

	if (msg == NULL)
		return NULL;

	tmp = purple_markup_strip_html(msg);
	text = g_markup_escape_text(tmp, -1);
	g_free(tmp);

	return text;
}

static void ggp_tooltip_text(PurpleBuddy *b, PurpleNotifyUserInfo *user_info, gboolean full)
{
	PurpleStatus *status;
	char *text, *tmp;
	const char *msg, *name, *alias;

	g_return_if_fail(b != NULL);

	status = purple_presence_get_active_status(purple_buddy_get_presence(b));
	msg = purple_status_get_attr_string(status, "message");
	name = purple_status_get_name(status);
	alias = purple_buddy_get_alias(b);

	purple_notify_user_info_add_pair (user_info, _("Alias"), alias);

	if (msg != NULL) {
		text = g_markup_escape_text(msg, -1);
		if (PURPLE_BUDDY_IS_ONLINE(b)) {
			tmp = g_strdup_printf("%s: %s", name, text);
			purple_notify_user_info_add_pair(user_info, _("Status"), tmp);
			g_free(tmp);
		} else {
			purple_notify_user_info_add_pair(user_info, _("Message"), text);
		}
		g_free(text);
	/* We don't want to duplicate 'Status: Offline'. */
	} else if (PURPLE_BUDDY_IS_ONLINE(b)) {
		purple_notify_user_info_add_pair(user_info, _("Status"), name);
	}
}

static GList *ggp_status_types(PurpleAccount *account)
{
	PurpleStatusType *type;
	GList *types = NULL;

	type = purple_status_type_new_with_attrs(
			PURPLE_STATUS_AVAILABLE, NULL, NULL, TRUE, TRUE, FALSE,
			"message", _("Message"), purple_value_new(PURPLE_TYPE_STRING),
			NULL);
	types = g_list_append(types, type);

	/*
	 * Without this selecting Invisible as own status doesn't
	 * work. It's not used and not needed to show status of buddies.
	 */
	type = purple_status_type_new_with_attrs(
			PURPLE_STATUS_INVISIBLE, NULL, NULL, TRUE, TRUE, FALSE,
			"message", _("Message"), purple_value_new(PURPLE_TYPE_STRING),
			NULL);
	types = g_list_append(types, type);

	type = purple_status_type_new_with_attrs(
			PURPLE_STATUS_AWAY, NULL, NULL, TRUE, TRUE, FALSE,
			"message", _("Message"), purple_value_new(PURPLE_TYPE_STRING),
			NULL);
	types = g_list_append(types, type);

 	/*
	 * New statuses for GG 8.0 like PoGGadaj ze mna (not yet because
	 * libpurple can't support Chatty status) and Nie przeszkadzac
	 */
	type = purple_status_type_new_with_attrs(
			PURPLE_STATUS_UNAVAILABLE, NULL, NULL, TRUE, TRUE, FALSE,
			"message", _("Message"), purple_value_new(PURPLE_TYPE_STRING),
			NULL);
	types = g_list_append(types, type);

	/*
	 * This status is necessary to display guys who are blocking *us*.
	 */
	type = purple_status_type_new_with_attrs(
			PURPLE_STATUS_INVISIBLE, "blocked", _("Blocked"), TRUE, FALSE, FALSE,
			"message", _("Message"), purple_value_new(PURPLE_TYPE_STRING), NULL);
	types = g_list_append(types, type);

	type = purple_status_type_new_with_attrs(
			PURPLE_STATUS_OFFLINE, NULL, NULL, TRUE, TRUE, FALSE,
			"message", _("Message"), purple_value_new(PURPLE_TYPE_STRING),
			NULL);
	types = g_list_append(types, type);

	return types;
}

static GList *ggp_blist_node_menu(PurpleBlistNode *node)
{
	PurpleMenuAction *act;
	GList *m = NULL;
	PurpleAccount *account;
	GGPInfo *info;

	if (!PURPLE_BLIST_NODE_IS_BUDDY(node))
		return NULL;

	account = purple_buddy_get_account((PurpleBuddy *) node);
	info = purple_account_get_connection(account)->proto_data;
	if (info->chats) {
		act = purple_menu_action_new(_("Add to chat"),
			PURPLE_CALLBACK(ggp_bmenu_add_to_chat),
			NULL, NULL);
		m = g_list_append(m, act);
	}

	return m;
}

static GList *ggp_chat_info(PurpleConnection *gc)
{
	GList *m = NULL;
	struct proto_chat_entry *pce;

	pce = g_new0(struct proto_chat_entry, 1);
	pce->label = _("Chat _name:");
	pce->identifier = "name";
	pce->required = TRUE;
	m = g_list_append(m, pce);

	return m;
}

static void ggp_login(PurpleAccount *account)
{
	PurpleConnection *gc;
	PurplePresence *presence;
	PurpleStatus *status;
	struct gg_login_params *glp;
	GGPInfo *info;
	const char *address;
	const gchar *encryption_type;

	if (ggp_setup_proxy(account) == -1)
		return;

	gc = purple_account_get_connection(account);
	glp = g_new0(struct gg_login_params, 1);
	info = g_new0(GGPInfo, 1);

	/* Probably this should be moved to *_new() function. */
	info->session = NULL;
	info->chats = NULL;
	info->chats_count = 0;
	info->token = NULL;
	info->searches = ggp_search_new();
	info->pending_richtext_messages = NULL;
	info->pending_images = g_hash_table_new(g_direct_hash, g_direct_equal);
	info->status_broadcasting = purple_account_get_bool(account, "status_broadcasting", TRUE);
	
	gc->proto_data = info;

	glp->uin = ggp_get_uin(account);
	glp->password = (char *)purple_account_get_password(account);
	glp->image_size = 255;

	presence = purple_account_get_presence(account);
	status = purple_presence_get_active_status(presence);

	glp->encoding = GG_ENCODING_UTF8;
	glp->protocol_features = (GG_FEATURE_STATUS80|GG_FEATURE_DND_FFC
		|GG_FEATURE_TYPING_NOTIFICATION);

	glp->async = 1;
	glp->status = ggp_to_gg_status(status, &glp->status_descr);
	
	encryption_type = purple_account_get_string(account, "encryption", "none");
	purple_debug_info("gg", "Requested encryption type: %s\n", encryption_type);
	if (strcmp(encryption_type, "opportunistic_tls") == 0)
		glp->tls = 1;
	else
		glp->tls = 0;
	purple_debug_info("gg", "TLS enabled: %d\n", glp->tls);

	if (!info->status_broadcasting)
		glp->status = glp->status|GG_STATUS_FRIENDS_MASK;
	
	address = purple_account_get_string(account, "gg_server", "");
	if (address && *address) {
		/* TODO: Make this non-blocking */
		struct in_addr *addr = gg_gethostbyname(address);

		purple_debug_info("gg", "Using gg server given by user (%s)\n", address);

		if (addr == NULL) {
			gchar *tmp = g_strdup_printf(_("Unable to resolve hostname '%s': %s"),
					address, g_strerror(errno));
			purple_connection_error_reason(gc,
				PURPLE_CONNECTION_ERROR_NETWORK_ERROR, /* should this be a settings error? */
				tmp);
			g_free(tmp);
			return;
		}

		glp->server_addr = inet_addr(inet_ntoa(*addr));
		glp->server_port = 8074;
		free(addr);
	} else
		purple_debug_info("gg", "Trying to retrieve address from gg appmsg service\n");

	info->session = gg_login(glp);
	purple_connection_update_progress(gc, _("Connecting"), 0, 2);
	if (info->session == NULL) {
		purple_connection_error_reason (gc,
			PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
			_("Connection failed"));
		g_free(glp);
		return;
	}
	gc->inpa = purple_input_add(info->session->fd,
		ggp_tcpsocket_inputcond_gg_to_purple(info->session->check),
		ggp_async_login_handler, gc);
}

static void ggp_close(PurpleConnection *gc)
{

	if (gc == NULL) {
		purple_debug_info("gg", "gc == NULL\n");
		return;
	}

	if (gc->proto_data) {
		PurpleAccount *account = purple_connection_get_account(gc);
		PurpleStatus *status;
		GGPInfo *info = gc->proto_data;

		status = purple_account_get_active_status(account);

		if (info->session != NULL) {
			ggp_set_status(account, status);
			gg_logoff(info->session);
			gg_free_session(info->session);
		}

		purple_account_set_bool(account, "status_broadcasting", info->status_broadcasting);

		/* Immediately close any notifications on this handle since that process depends
		 * upon the contents of info->searches, which we are about to destroy.
		 */
		purple_notify_close_with_handle(gc);

		ggp_search_destroy(info->searches);
		g_list_free(info->pending_richtext_messages);
		g_hash_table_destroy(info->pending_images);
		g_free(info);
		gc->proto_data = NULL;
	}

	if (gc->inpa > 0)
		purple_input_remove(gc->inpa);

	purple_debug_info("gg", "Connection closed.\n");
}

static int ggp_send_im(PurpleConnection *gc, const char *who, const char *msg,
		       PurpleMessageFlags flags)
{
	GGPInfo *info = gc->proto_data;
	char *tmp, *plain;
	int ret = 1;
	unsigned char format[1024];
	unsigned int format_length = sizeof(struct gg_msg_richtext);
	gint pos = 0;
	GData *attribs;
	const char *start, *end = NULL, *last;

	if (msg == NULL || *msg == '\0') {
		return 0;
	}

	last = msg;

	/* Check if the message is richtext */
	/* TODO: Check formatting, too */
	if(purple_markup_find_tag("img", last, &start, &end, &attribs)) {

		GString *string_buffer = g_string_new(NULL);
		struct gg_msg_richtext fmt;

		do {
			PurpleStoredImage *image;
			const char *id;

			/* Add text before the image */
			if(start - last) {
				pos = pos + g_utf8_strlen(last, start - last);
				g_string_append_len(string_buffer, last, start - last);
			}

			if((id = g_datalist_get_data(&attribs, "id")) && (image = purple_imgstore_find_by_id(atoi(id)))) {
				struct gg_msg_richtext_format actformat;
				struct gg_msg_richtext_image actimage;
				gint image_size = purple_imgstore_get_size(image);
				gconstpointer image_bin = purple_imgstore_get_data(image);
				const char *image_filename = purple_imgstore_get_filename(image);
				uint32_t crc32 = gg_crc32(0, image_bin, image_size);

				g_hash_table_insert(info->pending_images, GINT_TO_POINTER(crc32), GINT_TO_POINTER(atoi(id)));
				purple_imgstore_ref(image);
				purple_debug_info("gg", "ggp_send_im_richtext: got crc: %u for imgid: %i\n", crc32, atoi(id));

				actformat.font = GG_FONT_IMAGE;
				actformat.position = pos;

				actimage.unknown1 = 0x0109;
				actimage.size = gg_fix32(image_size);
				actimage.crc32 = gg_fix32(crc32);

				if (actimage.size > 255000) {
					purple_debug_warning("gg", "ggp_send_im_richtext: image over 255kb!\n");
				} else {
					purple_debug_info("gg", "ggp_send_im_richtext: adding images to richtext, size: %i, crc32: %u, name: %s\n", actimage.size, actimage.crc32, image_filename);

					memcpy(format + format_length, &actformat, sizeof(actformat));
					format_length += sizeof(actformat);
					memcpy(format + format_length, &actimage, sizeof(actimage));
					format_length += sizeof(actimage);
				}
			} else {
				purple_debug_error("gg", "ggp_send_im_richtext: image not found in the image store!");
			}

			last = end + 1;
			g_datalist_clear(&attribs);

		} while(purple_markup_find_tag("img", last, &start, &end, &attribs));

		/* Add text after the images */
		if(last && *last) {
			pos = pos + g_utf8_strlen(last, -1);
			g_string_append(string_buffer, last);
		}

		fmt.flag = 2;
		fmt.length = format_length - sizeof(fmt);
		memcpy(format, &fmt, sizeof(fmt));

		purple_debug_info("gg", "ggp_send_im: richtext msg = %s\n", string_buffer->str);
		plain = purple_unescape_html(string_buffer->str);
		g_string_free(string_buffer, TRUE);
	} else {
		purple_debug_info("gg", "ggp_send_im: msg = %s\n", msg);
		plain = purple_unescape_html(msg);
	}

	/*
	tmp = charset_convert(plain, "UTF-8", "CP1250");
	*/
	tmp = g_strdup_printf("%s", plain);

	if (tmp && (format_length - sizeof(struct gg_msg_richtext))) {
		if(gg_send_message_richtext(info->session, GG_CLASS_CHAT, ggp_str_to_uin(who), (unsigned char *)tmp, format, format_length) < 0) {
			ret = -1;
		} else {
			ret = 1;
		}
	} else if (NULL == tmp || *tmp == 0) {
		ret = 0;
	} else if (strlen(tmp) > GG_MSG_MAXSIZE) {
		ret = -E2BIG;
	} else if (gg_send_message(info->session, GG_CLASS_CHAT,
				ggp_str_to_uin(who), (unsigned char *)tmp) < 0) {
		ret = -1;
	} else {
		ret = 1;
	}

	g_free(plain);
	g_free(tmp);

	return ret;
}

static unsigned int ggp_send_typing(PurpleConnection *gc, const char *name, PurpleTypingState state)
{
	int dummy_length; // we don't send real length of typed message
	
	if (state == PURPLE_TYPED) // not supported
		return 1;
	
	if (state == PURPLE_TYPING)
		dummy_length = (int)g_random_int();
	else // PURPLE_NOT_TYPING
		dummy_length = 0;
	
	gg_typing_notification(
		((GGPInfo*)gc->proto_data)->session,
		ggp_str_to_uin(name),
		dummy_length); 
	
	return 1; // wait 1 second before another notification
}

static void ggp_get_info(PurpleConnection *gc, const char *name)
{
	GGPInfo *info = gc->proto_data;
	GGPSearchForm *form;
	guint32 seq;

	form = ggp_search_form_new(GGP_SEARCH_TYPE_INFO);

	form->user_data = info;
	form->uin = g_strdup(name);

	seq = ggp_search_start(gc, form);
	ggp_search_add(info->searches, seq, form);
	purple_debug_info("gg", "ggp_get_info(): Added seq %u", seq);
}

static int ggp_to_gg_status(PurpleStatus *status, char **msg)
{
	const char *status_id = purple_status_get_id(status);
	int new_status, new_status_descr;
	const char *new_msg;

	g_return_val_if_fail(msg != NULL, 0);

	purple_debug_info("gg", "ggp_to_gg_status: Requested status = %s\n",
			status_id);

	if (strcmp(status_id, "available") == 0) {
		new_status = GG_STATUS_AVAIL;
		new_status_descr = GG_STATUS_AVAIL_DESCR;
	} else if (strcmp(status_id, "away") == 0) {
		new_status = GG_STATUS_BUSY;
		new_status_descr = GG_STATUS_BUSY_DESCR;
	} else if (strcmp(status_id, "unavailable") == 0) {
		new_status = GG_STATUS_DND;
		new_status_descr = GG_STATUS_DND_DESCR;
	} else if (strcmp(status_id, "invisible") == 0) {
		new_status = GG_STATUS_INVISIBLE;
		new_status_descr = GG_STATUS_INVISIBLE_DESCR;
	} else if (strcmp(status_id, "offline") == 0) {
		new_status = GG_STATUS_NOT_AVAIL;
		new_status_descr = GG_STATUS_NOT_AVAIL_DESCR;
	} else {
		new_status = GG_STATUS_AVAIL;
		new_status_descr = GG_STATUS_AVAIL_DESCR;
		purple_debug_info("gg",
			"ggp_set_status: unknown status requested (status_id=%s)\n",
			status_id);
	}

	new_msg = purple_status_get_attr_string(status, "message");

	if(new_msg) {
		/*
		char *tmp = purple_markup_strip_html(new_msg);
		*msg = charset_convert(tmp, "UTF-8", "CP1250");
		g_free(tmp);
		*/
		*msg = purple_markup_strip_html(new_msg);

		return new_status_descr;
	} else {
		*msg = NULL;
		return new_status;
	}
}

static void ggp_set_status(PurpleAccount *account, PurpleStatus *status)
{
	PurpleConnection *gc;
	GGPInfo *info;
	int new_status;
	char *new_msg = NULL;

	if (!purple_status_is_active(status))
		return;

	gc = purple_account_get_connection(account);
	info = gc->proto_data;

	new_status = ggp_to_gg_status(status, &new_msg);

	if (!info->status_broadcasting)
		new_status = new_status|GG_STATUS_FRIENDS_MASK;
	
	if (new_msg == NULL) {
		gg_change_status(info->session, new_status);
	} else {
		gg_change_status_descr(info->session, new_status, new_msg);
		g_free(new_msg);
	}

	ggp_status_fake_to_self(account);

}

static void ggp_add_buddy(PurpleConnection *gc, PurpleBuddy *buddy, PurpleGroup *group)
{
	PurpleAccount *account;
	GGPInfo *info = gc->proto_data;
	const gchar *name = purple_buddy_get_name(buddy);

	gg_add_notify(info->session, ggp_str_to_uin(name));

	account = purple_connection_get_account(gc);
	if (strcmp(purple_account_get_username(account), name) == 0) {
		ggp_status_fake_to_self(account);
	}
}

static void ggp_remove_buddy(PurpleConnection *gc, PurpleBuddy *buddy,
						 PurpleGroup *group)
{
	GGPInfo *info = gc->proto_data;

	gg_remove_notify(info->session, ggp_str_to_uin(purple_buddy_get_name(buddy)));
}

static void ggp_join_chat(PurpleConnection *gc, GHashTable *data)
{
	GGPInfo *info = gc->proto_data;
	GGPChat *chat;
	char *chat_name;
	GList *l;
	PurpleConversation *conv;
	PurpleAccount *account = purple_connection_get_account(gc);

	chat_name = g_hash_table_lookup(data, "name");

	if (chat_name == NULL)
		return;

	purple_debug_info("gg", "joined %s chat\n", chat_name);

	for (l = info->chats; l != NULL; l = l->next) {
		 chat = l->data;

		 if (chat != NULL && g_utf8_collate(chat->name, chat_name) == 0) {
			 purple_notify_error(gc, _("Chat error"),
				 _("This chat name is already in use"), NULL);
			 return;
		 }
	}

	ggp_confer_add_new(gc, chat_name);
	conv = serv_got_joined_chat(gc, info->chats_count, chat_name);
	purple_conv_chat_add_user(PURPLE_CONV_CHAT(conv),
				purple_account_get_username(account), NULL,
				PURPLE_CBFLAGS_NONE, TRUE);
}

static char *ggp_get_chat_name(GHashTable *data) {
	return g_strdup(g_hash_table_lookup(data, "name"));
}

static int ggp_chat_send(PurpleConnection *gc, int id, const char *message, PurpleMessageFlags flags)
{
	PurpleConversation *conv;
	GGPInfo *info = gc->proto_data;
	GGPChat *chat = NULL;
	GList *l;
	/* char *msg, *plain; */
	gchar *msg;
	uin_t *uins;
	int count = 0;

	if ((conv = purple_find_chat(gc, id)) == NULL)
		return -EINVAL;

	for (l = info->chats; l != NULL; l = l->next) {
		chat = l->data;

		if (g_utf8_collate(chat->name, conv->name) == 0) {
			break;
		}

		chat = NULL;
	}

	if (chat == NULL) {
		purple_debug_error("gg",
			"ggp_chat_send: Hm... that's strange. No such chat?\n");
		return -EINVAL;
	}

	uins = g_new0(uin_t, g_list_length(chat->participants));

	for (l = chat->participants; l != NULL; l = l->next) {
		uin_t uin = GPOINTER_TO_INT(l->data);

		uins[count++] = uin;
	}

	/*
	plain = purple_unescape_html(message);
	msg = charset_convert(plain, "UTF-8", "CP1250");
	g_free(plain);
	*/
	msg = purple_unescape_html(message);
	gg_send_message_confer(info->session, GG_CLASS_CHAT, count, uins,
				(unsigned char *)msg);
	g_free(msg);
	g_free(uins);

	serv_got_chat_in(gc, id,
			 purple_account_get_username(purple_connection_get_account(gc)),
			 flags, message, time(NULL));

	return 0;
}

static void ggp_keepalive(PurpleConnection *gc)
{
	GGPInfo *info = gc->proto_data;

	/* purple_debug_info("gg", "Keeping connection alive....\n"); */

	if (gg_ping(info->session) < 0) {
		purple_debug_info("gg", "Not connected to the server "
				"or gg_session is not correct\n");
		purple_connection_error_reason (gc,
			PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
			_("Not connected to the server"));
	}
}

static GList *ggp_actions(PurplePlugin *plugin, gpointer context)
{
	GList *m = NULL;
	PurplePluginAction *act;

	act = purple_plugin_action_new(_("Find buddies..."),
				     ggp_find_buddies);
	m = g_list_append(m, act);

	act = purple_plugin_action_new(_("Change status broadcasting"),
				     ggp_action_change_status_broadcasting);
	m = g_list_append(m, act);

	m = g_list_append(m, NULL);

	act = purple_plugin_action_new(_("Save buddylist to file..."),
				     ggp_action_buddylist_save);
	m = g_list_append(m, act);

	act = purple_plugin_action_new(_("Load buddylist from file..."),
				     ggp_action_buddylist_load);
	m = g_list_append(m, act);

	return m;
}

static gboolean ggp_offline_message(const PurpleBuddy *buddy)
{
	return TRUE;
}

static PurplePluginProtocolInfo prpl_info =
{
	OPT_PROTO_IM_IMAGE,
	NULL,				/* user_splits */
	NULL,				/* protocol_options */
	{"png", 32, 32, 96, 96, 0, PURPLE_ICON_SCALE_DISPLAY},	/* icon_spec */
	ggp_list_icon,			/* list_icon */
	NULL,				/* list_emblem */
	ggp_status_text,		/* status_text */
	ggp_tooltip_text,		/* tooltip_text */
	ggp_status_types,		/* status_types */
	ggp_blist_node_menu,		/* blist_node_menu */
	ggp_chat_info,			/* chat_info */
	NULL,				/* chat_info_defaults */
	ggp_login,			/* login */
	ggp_close,			/* close */
	ggp_send_im,			/* send_im */
	NULL,				/* set_info */
	ggp_send_typing,		/* send_typing */
	ggp_get_info,			/* get_info */
	ggp_set_status,			/* set_away */
	NULL,				/* set_idle */
	NULL,				/* change_passwd */
	ggp_add_buddy,			/* add_buddy */
	NULL,				/* add_buddies */
	ggp_remove_buddy,		/* remove_buddy */
	NULL,				/* remove_buddies */
	NULL,				/* add_permit */
	ggp_add_deny,			/* add_deny */
	NULL,				/* rem_permit */
	ggp_rem_deny,			/* rem_deny */
	NULL,				/* set_permit_deny */
	ggp_join_chat,			/* join_chat */
	NULL,				/* reject_chat */
	ggp_get_chat_name,		/* get_chat_name */
	NULL,				/* chat_invite */
	NULL,				/* chat_leave */
	NULL,				/* chat_whisper */
	ggp_chat_send,			/* chat_send */
	ggp_keepalive,			/* keepalive */
	NULL,				/* register_user */
	NULL,				/* get_cb_info */
	NULL,				/* get_cb_away */
	NULL,				/* alias_buddy */
	NULL,				/* group_buddy */
	NULL,				/* rename_group */
	NULL,				/* buddy_free */
	NULL,				/* convo_closed */
	NULL,				/* normalize */
	NULL,				/* set_buddy_icon */
	NULL,				/* remove_group */
	NULL,				/* get_cb_real_name */
	NULL,				/* set_chat_topic */
	NULL,				/* find_blist_chat */
	NULL,				/* roomlist_get_list */
	NULL,				/* roomlist_cancel */
	NULL,				/* roomlist_expand_category */
	NULL,				/* can_receive_file */
	NULL,				/* send_file */
	NULL,				/* new_xfer */
	ggp_offline_message,		/* offline_message */
	NULL,				/* whiteboard_prpl_ops */
	NULL,				/* send_raw */
	NULL,				/* roomlist_room_serialize */
	NULL,				/* unregister_user */
	NULL,				/* send_attention */
	NULL,				/* get_attention_types */
	sizeof(PurplePluginProtocolInfo),       /* struct_size */
	NULL,                           /* get_account_text_table */
	NULL,                           /* initiate_media */
	NULL,                            /* can_do_media */
	NULL,				/* get_moods */
	NULL,				/* set_public_alias */
	NULL,				/* get_public_alias */
	NULL,				/* add_buddy_with_invite */
	NULL				/* add_buddies_with_invite */
};

static PurplePluginInfo info = {
	PURPLE_PLUGIN_MAGIC,			/* magic */
	PURPLE_MAJOR_VERSION,			/* major_version */
	PURPLE_MINOR_VERSION,			/* minor_version */
	PURPLE_PLUGIN_PROTOCOL,			/* plugin type */
	NULL,					/* ui_requirement */
	0,					/* flags */
	NULL,					/* dependencies */
	PURPLE_PRIORITY_DEFAULT,		/* priority */

	"prpl-gg",				/* id */
	"Gadu-Gadu",				/* name */
	DISPLAY_VERSION,			/* version */

	N_("Gadu-Gadu Protocol Plugin"),	/* summary */
	N_("Polish popular IM"),		/* description */
	"boler@sourceforge.net",		/* author */
	PURPLE_WEBSITE,				/* homepage */

	NULL,					/* load */
	NULL,					/* unload */
	NULL,					/* destroy */

	NULL,					/* ui_info */
	&prpl_info,				/* extra_info */
	NULL,					/* prefs_info */
	ggp_actions,				/* actions */

	/* padding */
	NULL,
	NULL,
	NULL,
	NULL
};

static void purple_gg_debug_handler(int level, const char * format, va_list args) {
	PurpleDebugLevel purple_level;
	char *msg = g_strdup_vprintf(format, args);

	/* This is pretty pointless since the GG_DEBUG levels don't correspond to
	 * the purple ones */
	switch (level) {
		case GG_DEBUG_FUNCTION:
			purple_level = PURPLE_DEBUG_INFO;
			break;
		case GG_DEBUG_MISC:
		case GG_DEBUG_NET:
		case GG_DEBUG_DUMP:
		case GG_DEBUG_TRAFFIC:
		default:
			purple_level = PURPLE_DEBUG_MISC;
			break;
	}

	purple_debug(purple_level, "gg", "%s", msg);
	g_free(msg);
}

static void init_plugin(PurplePlugin *plugin)
{
	PurpleAccountOption *option;
	GList *encryption_options = NULL;

	option = purple_account_option_string_new(_("Nickname"),
			"nick", _("Gadu-Gadu User"));
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options,
						   option);

	option = purple_account_option_string_new(_("GG server"),
			"gg_server", "");
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options,
			option);

#define ADD_VALUE(list, desc, v) { \
	PurpleKeyValuePair *kvp = g_new0(PurpleKeyValuePair, 1); \
	kvp->key = g_strdup((desc)); \
	kvp->value = g_strdup((v)); \
	list = g_list_append(list, kvp); \
}

	ADD_VALUE(encryption_options, _("Don't use encryption"), "none");
	ADD_VALUE(encryption_options, _("Use encryption if available"),
		"opportunistic_tls");
#if 0
	/* TODO */
	ADD_VALUE(encryption_options, _("Require encryption"), "require_tls");
#endif

	option = purple_account_option_list_new(_("Connection security"),
		"encryption", encryption_options);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options,
		option);

	my_protocol = plugin;

	gg_debug_handler = purple_gg_debug_handler;
}

PURPLE_INIT_PLUGIN(gg, init_plugin, info);

/* vim: set ts=8 sts=0 sw=8 noet: */
