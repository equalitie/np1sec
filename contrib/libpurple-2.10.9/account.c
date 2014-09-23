/**
 * @file account.c Account API
 * @ingroup core
 */

/* purple
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
#include "account.h"
#include "core.h"
#include "dbus-maybe.h"
#include "debug.h"
#include "network.h"
#include "notify.h"
#include "pounce.h"
#include "prefs.h"
#include "privacy.h"
#include "prpl.h"
#include "request.h"
#include "server.h"
#include "signals.h"
#include "status.h"
#include "util.h"
#include "xmlnode.h"

typedef struct
{
	PurpleConnectionErrorInfo *current_error;
} PurpleAccountPrivate;

#define PURPLE_ACCOUNT_GET_PRIVATE(account) \
	((PurpleAccountPrivate *) (account->priv))

/* TODO: Should use PurpleValue instead of this?  What about "ui"? */
typedef struct
{
	PurplePrefType type;

	char *ui;

	union
	{
		int integer;
		char *string;
		gboolean boolean;

	} value;

} PurpleAccountSetting;

typedef struct
{
	PurpleAccountRequestType type;
	PurpleAccount *account;
	void *ui_handle;
	char *user;
	gpointer userdata;
	PurpleAccountRequestAuthorizationCb auth_cb;
	PurpleAccountRequestAuthorizationCb deny_cb;
	guint ref;
} PurpleAccountRequestInfo;

static PurpleAccountUiOps *account_ui_ops = NULL;

static GList   *accounts = NULL;
static guint    save_timer = 0;
static gboolean accounts_loaded = FALSE;

static GList *handles = NULL;

static void set_current_error(PurpleAccount *account,
	PurpleConnectionErrorInfo *new_err);

/*********************************************************************
 * Writing to disk                                                   *
 *********************************************************************/

static void
setting_to_xmlnode(gpointer key, gpointer value, gpointer user_data)
{
	const char *name;
	PurpleAccountSetting *setting;
	xmlnode *node, *child;
	char buf[21];

	name    = (const char *)key;
	setting = (PurpleAccountSetting *)value;
	node    = (xmlnode *)user_data;

	child = xmlnode_new_child(node, "setting");
	xmlnode_set_attrib(child, "name", name);

	if (setting->type == PURPLE_PREF_INT) {
		xmlnode_set_attrib(child, "type", "int");
		g_snprintf(buf, sizeof(buf), "%d", setting->value.integer);
		xmlnode_insert_data(child, buf, -1);
	}
	else if (setting->type == PURPLE_PREF_STRING && setting->value.string != NULL) {
		xmlnode_set_attrib(child, "type", "string");
		xmlnode_insert_data(child, setting->value.string, -1);
	}
	else if (setting->type == PURPLE_PREF_BOOLEAN) {
		xmlnode_set_attrib(child, "type", "bool");
		g_snprintf(buf, sizeof(buf), "%d", setting->value.boolean);
		xmlnode_insert_data(child, buf, -1);
	}
}

static void
ui_setting_to_xmlnode(gpointer key, gpointer value, gpointer user_data)
{
	const char *ui;
	GHashTable *table;
	xmlnode *node, *child;

	ui    = (const char *)key;
	table = (GHashTable *)value;
	node  = (xmlnode *)user_data;

	if (g_hash_table_size(table) > 0)
	{
		child = xmlnode_new_child(node, "settings");
		xmlnode_set_attrib(child, "ui", ui);
		g_hash_table_foreach(table, setting_to_xmlnode, child);
	}
}

static xmlnode *
status_attr_to_xmlnode(const PurpleStatus *status, const PurpleStatusType *type, const PurpleStatusAttr *attr)
{
	xmlnode *node;
	const char *id;
	char *value = NULL;
	PurpleStatusAttr *default_attr;
	PurpleValue *default_value;
	PurpleType attr_type;
	PurpleValue *attr_value;

	id = purple_status_attr_get_id(attr);
	g_return_val_if_fail(id, NULL);

	attr_value = purple_status_get_attr_value(status, id);
	g_return_val_if_fail(attr_value, NULL);
	attr_type = purple_value_get_type(attr_value);

	/*
	 * If attr_value is a different type than it should be
	 * then don't write it to the file.
	 */
	default_attr = purple_status_type_get_attr(type, id);
	default_value = purple_status_attr_get_value(default_attr);
	if (attr_type != purple_value_get_type(default_value))
		return NULL;

	/*
	 * If attr_value is the same as the default for this status
	 * then there is no need to write it to the file.
	 */
	if (attr_type == PURPLE_TYPE_STRING)
	{
		const char *string_value = purple_value_get_string(attr_value);
		const char *default_string_value = purple_value_get_string(default_value);
		if (purple_strequal(string_value, default_string_value))
			return NULL;
		value = g_strdup(purple_value_get_string(attr_value));
	}
	else if (attr_type == PURPLE_TYPE_INT)
	{
		int int_value = purple_value_get_int(attr_value);
		if (int_value == purple_value_get_int(default_value))
			return NULL;
		value = g_strdup_printf("%d", int_value);
	}
	else if (attr_type == PURPLE_TYPE_BOOLEAN)
	{
		gboolean boolean_value = purple_value_get_boolean(attr_value);
		if (boolean_value == purple_value_get_boolean(default_value))
			return NULL;
		value = g_strdup(boolean_value ?
								"true" : "false");
	}
	else
	{
		return NULL;
	}

	g_return_val_if_fail(value, NULL);

	node = xmlnode_new("attribute");

	xmlnode_set_attrib(node, "id", id);
	xmlnode_set_attrib(node, "value", value);

	g_free(value);

	return node;
}

static xmlnode *
status_attrs_to_xmlnode(const PurpleStatus *status)
{
	PurpleStatusType *type = purple_status_get_type(status);
	xmlnode *node, *child;
	GList *attrs, *attr;

	node = xmlnode_new("attributes");

	attrs = purple_status_type_get_attrs(type);
	for (attr = attrs; attr != NULL; attr = attr->next)
	{
		child = status_attr_to_xmlnode(status, type, (const PurpleStatusAttr *)attr->data);
		if (child)
			xmlnode_insert_child(node, child);
	}

	return node;
}

static xmlnode *
status_to_xmlnode(const PurpleStatus *status)
{
	xmlnode *node, *child;

	node = xmlnode_new("status");
	xmlnode_set_attrib(node, "type", purple_status_get_id(status));
	if (purple_status_get_name(status) != NULL)
		xmlnode_set_attrib(node, "name", purple_status_get_name(status));
	xmlnode_set_attrib(node, "active", purple_status_is_active(status) ? "true" : "false");

	child = status_attrs_to_xmlnode(status);
	xmlnode_insert_child(node, child);

	return node;
}

static xmlnode *
statuses_to_xmlnode(const PurplePresence *presence)
{
	xmlnode *node, *child;
	GList *statuses;
	PurpleStatus *status;

	node = xmlnode_new("statuses");

	statuses = purple_presence_get_statuses(presence);
	for (; statuses != NULL; statuses = statuses->next)
	{
		status = statuses->data;
		if (purple_status_type_is_saveable(purple_status_get_type(status)))
		{
			child = status_to_xmlnode(status);
			xmlnode_insert_child(node, child);
		}
	}

	return node;
}

static xmlnode *
proxy_settings_to_xmlnode(PurpleProxyInfo *proxy_info)
{
	xmlnode *node, *child;
	PurpleProxyType proxy_type;
	const char *value;
	int int_value;
	char buf[21];

	proxy_type = purple_proxy_info_get_type(proxy_info);

	node = xmlnode_new("proxy");

	child = xmlnode_new_child(node, "type");
	xmlnode_insert_data(child,
			(proxy_type == PURPLE_PROXY_USE_GLOBAL ? "global" :
			 proxy_type == PURPLE_PROXY_NONE       ? "none"   :
			 proxy_type == PURPLE_PROXY_HTTP       ? "http"   :
			 proxy_type == PURPLE_PROXY_SOCKS4     ? "socks4" :
			 proxy_type == PURPLE_PROXY_SOCKS5     ? "socks5" :
			 proxy_type == PURPLE_PROXY_TOR        ? "tor" :
			 proxy_type == PURPLE_PROXY_USE_ENVVAR ? "envvar" : "unknown"), -1);

	if ((value = purple_proxy_info_get_host(proxy_info)) != NULL)
	{
		child = xmlnode_new_child(node, "host");
		xmlnode_insert_data(child, value, -1);
	}

	if ((int_value = purple_proxy_info_get_port(proxy_info)) != 0)
	{
		g_snprintf(buf, sizeof(buf), "%d", int_value);
		child = xmlnode_new_child(node, "port");
		xmlnode_insert_data(child, buf, -1);
	}

	if ((value = purple_proxy_info_get_username(proxy_info)) != NULL)
	{
		child = xmlnode_new_child(node, "username");
		xmlnode_insert_data(child, value, -1);
	}

	if ((value = purple_proxy_info_get_password(proxy_info)) != NULL)
	{
		child = xmlnode_new_child(node, "password");
		xmlnode_insert_data(child, value, -1);
	}

	return node;
}

static xmlnode *
current_error_to_xmlnode(PurpleConnectionErrorInfo *err)
{
	xmlnode *node, *child;
	char type_str[3];

	node = xmlnode_new("current_error");

	if(err == NULL)
		return node;

	/* It doesn't make sense to have transient errors persist across a
	 * restart.
	 */
	if(!purple_connection_error_is_fatal (err->type))
		return node;

	child = xmlnode_new_child(node, "type");
	g_snprintf(type_str, sizeof(type_str), "%u", err->type);
	xmlnode_insert_data(child, type_str, -1);

	child = xmlnode_new_child(node, "description");
	if(err->description) {
		char *utf8ized = purple_utf8_try_convert(err->description);
		if(utf8ized == NULL)
			utf8ized = purple_utf8_salvage(err->description);
		xmlnode_insert_data(child, utf8ized, -1);
		g_free(utf8ized);
	}

	return node;
}

static xmlnode *
account_to_xmlnode(PurpleAccount *account)
{
	PurpleAccountPrivate *priv = PURPLE_ACCOUNT_GET_PRIVATE(account);

	xmlnode *node, *child;
	const char *tmp;
	PurplePresence *presence;
	PurpleProxyInfo *proxy_info;

	node = xmlnode_new("account");

	child = xmlnode_new_child(node, "protocol");
	xmlnode_insert_data(child, purple_account_get_protocol_id(account), -1);

	child = xmlnode_new_child(node, "name");
	xmlnode_insert_data(child, purple_account_get_username(account), -1);

	if (purple_account_get_remember_password(account) &&
		((tmp = purple_account_get_password(account)) != NULL))
	{
		child = xmlnode_new_child(node, "password");
		xmlnode_insert_data(child, tmp, -1);
	}

	if ((tmp = purple_account_get_alias(account)) != NULL)
	{
		child = xmlnode_new_child(node, "alias");
		xmlnode_insert_data(child, tmp, -1);
	}

	if ((presence = purple_account_get_presence(account)) != NULL)
	{
		child = statuses_to_xmlnode(presence);
		xmlnode_insert_child(node, child);
	}

	if ((tmp = purple_account_get_user_info(account)) != NULL)
	{
		/* TODO: Do we need to call purple_str_strip_char(tmp, '\r') here? */
		child = xmlnode_new_child(node, "userinfo");
		xmlnode_insert_data(child, tmp, -1);
	}

	if (g_hash_table_size(account->settings) > 0)
	{
		child = xmlnode_new_child(node, "settings");
		g_hash_table_foreach(account->settings, setting_to_xmlnode, child);
	}

	if (g_hash_table_size(account->ui_settings) > 0)
	{
		g_hash_table_foreach(account->ui_settings, ui_setting_to_xmlnode, node);
	}

	if ((proxy_info = purple_account_get_proxy_info(account)) != NULL)
	{
		child = proxy_settings_to_xmlnode(proxy_info);
		xmlnode_insert_child(node, child);
	}

	child = current_error_to_xmlnode(priv->current_error);
	xmlnode_insert_child(node, child);

	return node;
}

static xmlnode *
accounts_to_xmlnode(void)
{
	xmlnode *node, *child;
	GList *cur;

	node = xmlnode_new("account");
	xmlnode_set_attrib(node, "version", "1.0");

	for (cur = purple_accounts_get_all(); cur != NULL; cur = cur->next)
	{
		child = account_to_xmlnode(cur->data);
		xmlnode_insert_child(node, child);
	}

	return node;
}

static void
sync_accounts(void)
{
	xmlnode *node;
	char *data;

	if (!accounts_loaded)
	{
		purple_debug_error("account", "Attempted to save accounts before "
						 "they were read!\n");
		return;
	}

	node = accounts_to_xmlnode();
	data = xmlnode_to_formatted_str(node, NULL);
	purple_util_write_data_to_file("accounts.xml", data, -1);
	g_free(data);
	xmlnode_free(node);
}

static gboolean
save_cb(gpointer data)
{
	sync_accounts();
	save_timer = 0;
	return FALSE;
}

static void
schedule_accounts_save(void)
{
	if (save_timer == 0)
		save_timer = purple_timeout_add_seconds(5, save_cb, NULL);
}


/*********************************************************************
 * Reading from disk                                                 *
 *********************************************************************/
static void
migrate_yahoo_japan(PurpleAccount *account)
{
	/* detect a Yahoo! JAPAN account that existed prior to 2.6.0 and convert it
	 * to use the new prpl-yahoojp.  Also remove the account-specific settings
	 * we no longer need */

	if(purple_strequal(purple_account_get_protocol_id(account), "prpl-yahoo")) {
		if(purple_account_get_bool(account, "yahoojp", FALSE)) {
			const char *serverjp = purple_account_get_string(account, "serverjp", NULL);
			const char *xferjp_host = purple_account_get_string(account, "xferjp_host", NULL);

			g_return_if_fail(serverjp != NULL);
			g_return_if_fail(xferjp_host != NULL);

			purple_account_set_string(account, "server", serverjp);
			purple_account_set_string(account, "xfer_host", xferjp_host);

			purple_account_set_protocol_id(account, "prpl-yahoojp");
		}

		/* these should always be nuked */
		purple_account_remove_setting(account, "yahoojp");
		purple_account_remove_setting(account, "serverjp");
		purple_account_remove_setting(account, "xferjp_host");

	}
}

static void
migrate_icq_server(PurpleAccount *account)
{
	/* Migrate the login server setting for ICQ accounts.  See
	 * 'mtn log --last 1 --no-graph --from b6d7712e90b68610df3bd2d8cbaf46d94c8b3794'
	 * for details on the change. */

	if(purple_strequal(purple_account_get_protocol_id(account), "prpl-icq")) {
		const char *tmp = purple_account_get_string(account, "server", NULL);

		/* Non-secure server */
		if(purple_strequal(tmp,	"login.messaging.aol.com") ||
				purple_strequal(tmp, "login.oscar.aol.com"))
			purple_account_set_string(account, "server", "login.icq.com");

		/* Secure server */
		if(purple_strequal(tmp, "slogin.oscar.aol.com"))
			purple_account_set_string(account, "server", "slogin.icq.com");
	}
}

static void
migrate_xmpp_encryption(PurpleAccount *account)
{
	/* When this is removed, nuke the "old_ssl" and "require_tls" settings */
	if (g_str_equal(purple_account_get_protocol_id(account), "prpl-jabber")) {
		const char *sec = purple_account_get_string(account, "connection_security", "");

		if (g_str_equal("", sec)) {
			const char *val = "require_tls";
			if (purple_account_get_bool(account, "old_ssl", FALSE))
				val = "old_ssl";
			else if (!purple_account_get_bool(account, "require_tls", TRUE))
				val = "opportunistic_tls";

			purple_account_set_string(account, "connection_security", val);
		}
	}
}

static void
parse_settings(xmlnode *node, PurpleAccount *account)
{
	const char *ui;
	xmlnode *child;

	/* Get the UI string, if these are UI settings */
	ui = xmlnode_get_attrib(node, "ui");

	/* Read settings, one by one */
	for (child = xmlnode_get_child(node, "setting"); child != NULL;
			child = xmlnode_get_next_twin(child))
	{
		const char *name, *str_type;
		PurplePrefType type;
		char *data;

		name = xmlnode_get_attrib(child, "name");
		if (name == NULL)
			/* Ignore this setting */
			continue;

		str_type = xmlnode_get_attrib(child, "type");
		if (str_type == NULL)
			/* Ignore this setting */
			continue;

		if (purple_strequal(str_type, "string"))
			type = PURPLE_PREF_STRING;
		else if (purple_strequal(str_type, "int"))
			type = PURPLE_PREF_INT;
		else if (purple_strequal(str_type, "bool"))
			type = PURPLE_PREF_BOOLEAN;
		else
			/* Ignore this setting */
			continue;

		data = xmlnode_get_data(child);
		if (data == NULL)
			/* Ignore this setting */
			continue;

		if (ui == NULL)
		{
			if (type == PURPLE_PREF_STRING)
				purple_account_set_string(account, name, data);
			else if (type == PURPLE_PREF_INT)
				purple_account_set_int(account, name, atoi(data));
			else if (type == PURPLE_PREF_BOOLEAN)
				purple_account_set_bool(account, name,
									  (*data == '0' ? FALSE : TRUE));
		} else {
			if (type == PURPLE_PREF_STRING)
				purple_account_set_ui_string(account, ui, name, data);
			else if (type == PURPLE_PREF_INT)
				purple_account_set_ui_int(account, ui, name, atoi(data));
			else if (type == PURPLE_PREF_BOOLEAN)
				purple_account_set_ui_bool(account, ui, name,
										 (*data == '0' ? FALSE : TRUE));
		}

		g_free(data);
	}

	/* we do this here because we need access to account settings to determine
	 * if we can/should migrate an old Yahoo! JAPAN account */
	migrate_yahoo_japan(account);
	/* we do this here because we need access to account settings to determine
	 * if we can/should migrate an ICQ account's server setting */
	migrate_icq_server(account);
	/* we do this here because we need to do it before the user views the
	 * Edit Account dialog. */
	migrate_xmpp_encryption(account);
}

static GList *
parse_status_attrs(xmlnode *node, PurpleStatus *status)
{
	GList *list = NULL;
	xmlnode *child;
	PurpleValue *attr_value;

	for (child = xmlnode_get_child(node, "attribute"); child != NULL;
			child = xmlnode_get_next_twin(child))
	{
		const char *id = xmlnode_get_attrib(child, "id");
		const char *value = xmlnode_get_attrib(child, "value");

		if (!id || !*id || !value || !*value)
			continue;

		attr_value = purple_status_get_attr_value(status, id);
		if (!attr_value)
			continue;

		list = g_list_append(list, (char *)id);

		switch (purple_value_get_type(attr_value))
		{
			case PURPLE_TYPE_STRING:
				list = g_list_append(list, (char *)value);
				break;
			case PURPLE_TYPE_INT:
			case PURPLE_TYPE_BOOLEAN:
			{
				int v;
				if (sscanf(value, "%d", &v) == 1)
					list = g_list_append(list, GINT_TO_POINTER(v));
				else
					list = g_list_remove(list, id);
				break;
			}
			default:
				break;
		}
	}

	return list;
}

static void
parse_status(xmlnode *node, PurpleAccount *account)
{
	gboolean active = FALSE;
	const char *data;
	const char *type;
	xmlnode *child;
	GList *attrs = NULL;

	/* Get the active/inactive state */
	data = xmlnode_get_attrib(node, "active");
	if (data == NULL)
		return;
	if (g_ascii_strcasecmp(data, "true") == 0)
		active = TRUE;
	else if (g_ascii_strcasecmp(data, "false") == 0)
		active = FALSE;
	else
		return;

	/* Get the type of the status */
	type = xmlnode_get_attrib(node, "type");
	if (type == NULL)
		return;

	/* Read attributes into a GList */
	child = xmlnode_get_child(node, "attributes");
	if (child != NULL)
	{
		attrs = parse_status_attrs(child,
						purple_account_get_status(account, type));
	}

	purple_account_set_status_list(account, type, active, attrs);

	g_list_free(attrs);
}

static void
parse_statuses(xmlnode *node, PurpleAccount *account)
{
	xmlnode *child;

	for (child = xmlnode_get_child(node, "status"); child != NULL;
			child = xmlnode_get_next_twin(child))
	{
		parse_status(child, account);
	}
}

static void
parse_proxy_info(xmlnode *node, PurpleAccount *account)
{
	PurpleProxyInfo *proxy_info;
	xmlnode *child;
	char *data;

	proxy_info = purple_proxy_info_new();

	/* Use the global proxy settings, by default */
	purple_proxy_info_set_type(proxy_info, PURPLE_PROXY_USE_GLOBAL);

	/* Read proxy type */
	child = xmlnode_get_child(node, "type");
	if ((child != NULL) && ((data = xmlnode_get_data(child)) != NULL))
	{
		if (purple_strequal(data, "global"))
			purple_proxy_info_set_type(proxy_info, PURPLE_PROXY_USE_GLOBAL);
		else if (purple_strequal(data, "none"))
			purple_proxy_info_set_type(proxy_info, PURPLE_PROXY_NONE);
		else if (purple_strequal(data, "http"))
			purple_proxy_info_set_type(proxy_info, PURPLE_PROXY_HTTP);
		else if (purple_strequal(data, "socks4"))
			purple_proxy_info_set_type(proxy_info, PURPLE_PROXY_SOCKS4);
		else if (purple_strequal(data, "socks5"))
			purple_proxy_info_set_type(proxy_info, PURPLE_PROXY_SOCKS5);
		else if (purple_strequal(data, "tor"))
			purple_proxy_info_set_type(proxy_info, PURPLE_PROXY_TOR);
		else if (purple_strequal(data, "envvar"))
			purple_proxy_info_set_type(proxy_info, PURPLE_PROXY_USE_ENVVAR);
		else
		{
			purple_debug_error("account", "Invalid proxy type found when "
							 "loading account information for %s\n",
							 purple_account_get_username(account));
		}
		g_free(data);
	}

	/* Read proxy host */
	child = xmlnode_get_child(node, "host");
	if ((child != NULL) && ((data = xmlnode_get_data(child)) != NULL))
	{
		purple_proxy_info_set_host(proxy_info, data);
		g_free(data);
	}

	/* Read proxy port */
	child = xmlnode_get_child(node, "port");
	if ((child != NULL) && ((data = xmlnode_get_data(child)) != NULL))
	{
		purple_proxy_info_set_port(proxy_info, atoi(data));
		g_free(data);
	}

	/* Read proxy username */
	child = xmlnode_get_child(node, "username");
	if ((child != NULL) && ((data = xmlnode_get_data(child)) != NULL))
	{
		purple_proxy_info_set_username(proxy_info, data);
		g_free(data);
	}

	/* Read proxy password */
	child = xmlnode_get_child(node, "password");
	if ((child != NULL) && ((data = xmlnode_get_data(child)) != NULL))
	{
		purple_proxy_info_set_password(proxy_info, data);
		g_free(data);
	}

	/* If there are no values set then proxy_info NULL */
	if ((purple_proxy_info_get_type(proxy_info) == PURPLE_PROXY_USE_GLOBAL) &&
		(purple_proxy_info_get_host(proxy_info) == NULL) &&
		(purple_proxy_info_get_port(proxy_info) == 0) &&
		(purple_proxy_info_get_username(proxy_info) == NULL) &&
		(purple_proxy_info_get_password(proxy_info) == NULL))
	{
		purple_proxy_info_destroy(proxy_info);
		return;
	}

	purple_account_set_proxy_info(account, proxy_info);
}

static void
parse_current_error(xmlnode *node, PurpleAccount *account)
{
	guint type;
	char *type_str = NULL, *description = NULL;
	xmlnode *child;
	PurpleConnectionErrorInfo *current_error = NULL;

	child = xmlnode_get_child(node, "type");
	if (child == NULL || (type_str = xmlnode_get_data(child)) == NULL)
		return;
	type = atoi(type_str);
	g_free(type_str);

	if (type > PURPLE_CONNECTION_ERROR_OTHER_ERROR)
	{
		purple_debug_error("account",
			"Invalid PurpleConnectionError value %d found when "
			"loading account information for %s\n",
			type, purple_account_get_username(account));
		type = PURPLE_CONNECTION_ERROR_OTHER_ERROR;
	}

	child = xmlnode_get_child(node, "description");
	if (child)
		description = xmlnode_get_data(child);
	if (description == NULL)
		description = g_strdup("");

	current_error = g_new0(PurpleConnectionErrorInfo, 1);
	PURPLE_DBUS_REGISTER_POINTER(current_error, PurpleConnectionErrorInfo);
	current_error->type = type;
	current_error->description = description;

	set_current_error(account, current_error);
}

static PurpleAccount *
parse_account(xmlnode *node)
{
	PurpleAccount *ret;
	xmlnode *child;
	char *protocol_id = NULL;
	char *name = NULL;
	char *data;

	child = xmlnode_get_child(node, "protocol");
	if (child != NULL)
		protocol_id = xmlnode_get_data(child);

	child = xmlnode_get_child(node, "name");
	if (child != NULL)
		name = xmlnode_get_data(child);
	if (name == NULL)
	{
		/* Do we really need to do this? */
		child = xmlnode_get_child(node, "username");
		if (child != NULL)
			name = xmlnode_get_data(child);
	}

	if ((protocol_id == NULL) || (name == NULL))
	{
		g_free(protocol_id);
		g_free(name);
		return NULL;
	}

	ret = purple_account_new(name, _purple_oscar_convert(name, protocol_id)); /* XXX: */
	g_free(name);
	g_free(protocol_id);

	/* Read the password */
	child = xmlnode_get_child(node, "password");
	if ((child != NULL) && ((data = xmlnode_get_data(child)) != NULL))
	{
		purple_account_set_remember_password(ret, TRUE);
		purple_account_set_password(ret, data);
		g_free(data);
	}

	/* Read the alias */
	child = xmlnode_get_child(node, "alias");
	if ((child != NULL) && ((data = xmlnode_get_data(child)) != NULL))
	{
		if (*data != '\0')
			purple_account_set_alias(ret, data);
		g_free(data);
	}

	/* Read the statuses */
	child = xmlnode_get_child(node, "statuses");
	if (child != NULL)
	{
		parse_statuses(child, ret);
	}

	/* Read the userinfo */
	child = xmlnode_get_child(node, "userinfo");
	if ((child != NULL) && ((data = xmlnode_get_data(child)) != NULL))
	{
		purple_account_set_user_info(ret, data);
		g_free(data);
	}

	/* Read an old buddyicon */
	child = xmlnode_get_child(node, "buddyicon");
	if ((child != NULL) && ((data = xmlnode_get_data(child)) != NULL))
	{
		const char *dirname = purple_buddy_icons_get_cache_dir();
		char *filename = g_build_filename(dirname, data, NULL);
		gchar *contents;
		gsize len;

		if (g_file_get_contents(filename, &contents, &len, NULL))
		{
			purple_buddy_icons_set_account_icon(ret, (guchar *)contents, len);
		}
		else
		{
			/* Try to see if the icon got left behind in the old cache. */
			g_free(filename);
			filename = g_build_filename(g_get_home_dir(), ".gaim", "icons", data, NULL);
			if (g_file_get_contents(filename, &contents, &len, NULL)) {
				purple_buddy_icons_set_account_icon(ret, (guchar*)contents, len);
			}
		}

		g_free(filename);
		g_free(data);
	}

	/* Read settings (both core and UI) */
	for (child = xmlnode_get_child(node, "settings"); child != NULL;
			child = xmlnode_get_next_twin(child))
	{
		parse_settings(child, ret);
	}

	/* Read proxy */
	child = xmlnode_get_child(node, "proxy");
	if (child != NULL)
	{
		parse_proxy_info(child, ret);
	}

	/* Read current error */
	child = xmlnode_get_child(node, "current_error");
	if (child != NULL)
	{
		parse_current_error(child, ret);
	}

	return ret;
}

static void
load_accounts(void)
{
	xmlnode *node, *child;

	accounts_loaded = TRUE;

	node = purple_util_read_xml_from_file("accounts.xml", _("accounts"));

	if (node == NULL)
		return;

	for (child = xmlnode_get_child(node, "account"); child != NULL;
			child = xmlnode_get_next_twin(child))
	{
		PurpleAccount *new_acct;
		new_acct = parse_account(child);
		purple_accounts_add(new_acct);
	}

	xmlnode_free(node);

	_purple_buddy_icons_account_loaded_cb();
}


static void
delete_setting(void *data)
{
	PurpleAccountSetting *setting = (PurpleAccountSetting *)data;

	g_free(setting->ui);

	if (setting->type == PURPLE_PREF_STRING)
		g_free(setting->value.string);

	g_free(setting);
}

PurpleAccount *
purple_account_new(const char *username, const char *protocol_id)
{
	PurpleAccount *account = NULL;
	PurpleAccountPrivate *priv = NULL;
	PurplePlugin *prpl = NULL;
	PurplePluginProtocolInfo *prpl_info = NULL;
	PurpleStatusType *status_type;

	g_return_val_if_fail(username != NULL, NULL);
	g_return_val_if_fail(protocol_id != NULL, NULL);

	account = purple_accounts_find(username, protocol_id);

	if (account != NULL)
		return account;

	account = g_new0(PurpleAccount, 1);
	PURPLE_DBUS_REGISTER_POINTER(account, PurpleAccount);
	priv = g_new0(PurpleAccountPrivate, 1);
	account->priv = priv;

	purple_account_set_username(account, username);

	purple_account_set_protocol_id(account, protocol_id);

	account->settings = g_hash_table_new_full(g_str_hash, g_str_equal,
											  g_free, delete_setting);
	account->ui_settings = g_hash_table_new_full(g_str_hash, g_str_equal,
				g_free, (GDestroyNotify)g_hash_table_destroy);
	account->system_log = NULL;
	/* 0 is not a valid privacy setting */
	account->perm_deny = PURPLE_PRIVACY_ALLOW_ALL;

	purple_signal_emit(purple_accounts_get_handle(), "account-created", account);

	prpl = purple_find_prpl(protocol_id);

	if (prpl == NULL)
		return account;

	prpl_info = PURPLE_PLUGIN_PROTOCOL_INFO(prpl);
	if (prpl_info != NULL && prpl_info->status_types != NULL)
		purple_account_set_status_types(account, prpl_info->status_types(account));

	account->presence = purple_presence_new_for_account(account);

	status_type = purple_account_get_status_type_with_primitive(account, PURPLE_STATUS_AVAILABLE);
	if (status_type != NULL)
		purple_presence_set_status_active(account->presence,
										purple_status_type_get_id(status_type),
										TRUE);
	else
		purple_presence_set_status_active(account->presence,
										"offline",
										TRUE);

	return account;
}

void
purple_account_destroy(PurpleAccount *account)
{
	PurpleAccountPrivate *priv = NULL;
	GList *l;

	g_return_if_fail(account != NULL);

	purple_debug_info("account", "Destroying account %p\n", account);
	purple_signal_emit(purple_accounts_get_handle(), "account-destroying", account);

	for (l = purple_get_conversations(); l != NULL; l = l->next)
	{
		PurpleConversation *conv = (PurpleConversation *)l->data;

		if (purple_conversation_get_account(conv) == account)
			purple_conversation_set_account(conv, NULL);
	}

	g_free(account->username);
	g_free(account->alias);
	g_free(account->password);
	g_free(account->user_info);
	g_free(account->buddy_icon_path);
	g_free(account->protocol_id);

	g_hash_table_destroy(account->settings);
	g_hash_table_destroy(account->ui_settings);

	if (account->proxy_info)
		purple_proxy_info_destroy(account->proxy_info);

	purple_account_set_status_types(account, NULL);

	purple_presence_destroy(account->presence);

	if(account->system_log)
		purple_log_free(account->system_log);

	while (account->deny) {
		g_free(account->deny->data);
		account->deny = g_slist_delete_link(account->deny, account->deny);
	}

	while (account->permit) {
		g_free(account->permit->data);
		account->permit = g_slist_delete_link(account->permit, account->permit);
	}

	priv = PURPLE_ACCOUNT_GET_PRIVATE(account);
	PURPLE_DBUS_UNREGISTER_POINTER(priv->current_error);
	if (priv->current_error) {
		g_free(priv->current_error->description);
		g_free(priv->current_error);
	}
	g_free(priv);

	PURPLE_DBUS_UNREGISTER_POINTER(account);
	g_free(account);
}

void
purple_account_set_register_callback(PurpleAccount *account, PurpleAccountRegistrationCb cb, void *user_data)
{
	g_return_if_fail(account != NULL);

	account->registration_cb = cb;
	account->registration_cb_user_data = user_data;
}

void
purple_account_register(PurpleAccount *account)
{
	g_return_if_fail(account != NULL);

	purple_debug_info("account", "Registering account %s\n",
					purple_account_get_username(account));

	_purple_connection_new(account, TRUE, purple_account_get_password(account));
}

void
purple_account_unregister(PurpleAccount *account, PurpleAccountUnregistrationCb cb, void *user_data)
{
	g_return_if_fail(account != NULL);

	purple_debug_info("account", "Unregistering account %s\n",
					  purple_account_get_username(account));

	_purple_connection_new_unregister(account, purple_account_get_password(account), cb, user_data);
}

static void
request_password_ok_cb(PurpleAccount *account, PurpleRequestFields *fields)
{
	const char *entry;
	gboolean remember;

	entry = purple_request_fields_get_string(fields, "password");
	remember = purple_request_fields_get_bool(fields, "remember");

	if (!entry || !*entry)
	{
		purple_notify_error(account, NULL, _("Password is required to sign on."), NULL);
		return;
	}

	if(remember)
		purple_account_set_remember_password(account, TRUE);

	purple_account_set_password(account, entry);

	_purple_connection_new(account, FALSE, entry);
}

static void
request_password_cancel_cb(PurpleAccount *account, PurpleRequestFields *fields)
{
	/* Disable the account as the user has cancelled connecting */
	purple_account_set_enabled(account, purple_core_get_ui(), FALSE);
}


void
purple_account_request_password(PurpleAccount *account, GCallback ok_cb,
				GCallback cancel_cb, void *user_data)
{
	gchar *primary;
	const gchar *username;
	PurpleRequestFieldGroup *group;
	PurpleRequestField *field;
	PurpleRequestFields *fields;

	/* Close any previous password request windows */
	purple_request_close_with_handle(account);

	username = purple_account_get_username(account);
	primary = g_strdup_printf(_("Enter password for %s (%s)"), username,
								  purple_account_get_protocol_name(account));

	fields = purple_request_fields_new();
	group = purple_request_field_group_new(NULL);
	purple_request_fields_add_group(fields, group);

	field = purple_request_field_string_new("password", _("Enter Password"), NULL, FALSE);
	purple_request_field_string_set_masked(field, TRUE);
	purple_request_field_set_required(field, TRUE);
	purple_request_field_group_add_field(group, field);

	field = purple_request_field_bool_new("remember", _("Save password"), FALSE);
	purple_request_field_group_add_field(group, field);

	purple_request_fields(account,
                        NULL,
                        primary,
                        NULL,
                        fields,
                        _("OK"), ok_cb,
                        _("Cancel"), cancel_cb,
						account, NULL, NULL,
                        user_data);
	g_free(primary);
}

void
purple_account_connect(PurpleAccount *account)
{
	PurplePlugin *prpl;
	const char *password, *username;
	PurplePluginProtocolInfo *prpl_info;

	g_return_if_fail(account != NULL);

	username = purple_account_get_username(account);

	if (!purple_account_get_enabled(account, purple_core_get_ui())) {
		purple_debug_info("account",
				  "Account %s not enabled, not connecting.\n",
				  username);
		return;
	}

	prpl = purple_find_prpl(purple_account_get_protocol_id(account));
	if (prpl == NULL) {
		gchar *message;

		message = g_strdup_printf(_("Missing protocol plugin for %s"), username);
		purple_notify_error(account, _("Connection Error"), message, NULL);
		g_free(message);
		return;
	}

	purple_debug_info("account", "Connecting to account %s.\n", username);

	prpl_info = PURPLE_PLUGIN_PROTOCOL_INFO(prpl);
	password = purple_account_get_password(account);
	if ((password == NULL) &&
		!(prpl_info->options & OPT_PROTO_NO_PASSWORD) &&
		!(prpl_info->options & OPT_PROTO_PASSWORD_OPTIONAL))
		purple_account_request_password(account, G_CALLBACK(request_password_ok_cb), G_CALLBACK(request_password_cancel_cb), account);
	else
		_purple_connection_new(account, FALSE, password);
}

void
purple_account_disconnect(PurpleAccount *account)
{
	PurpleConnection *gc;
	const char *username;

	g_return_if_fail(account != NULL);
	g_return_if_fail(!purple_account_is_disconnected(account));

	username = purple_account_get_username(account);
	purple_debug_info("account", "Disconnecting account %s (%p)\n",
	                  username ? username : "(null)", account);

	account->disconnecting = TRUE;

	gc = purple_account_get_connection(account);
	_purple_connection_destroy(gc);
	if (!purple_account_get_remember_password(account))
		purple_account_set_password(account, NULL);
	purple_account_set_connection(account, NULL);

	account->disconnecting = FALSE;
}

void
purple_account_notify_added(PurpleAccount *account, const char *remote_user,
                          const char *id, const char *alias,
                          const char *message)
{
	PurpleAccountUiOps *ui_ops;

	g_return_if_fail(account     != NULL);
	g_return_if_fail(remote_user != NULL);

	ui_ops = purple_accounts_get_ui_ops();

	if (ui_ops != NULL && ui_ops->notify_added != NULL)
		ui_ops->notify_added(account, remote_user, id, alias, message);
}

void
purple_account_request_add(PurpleAccount *account, const char *remote_user,
                         const char *id, const char *alias,
                         const char *message)
{
	PurpleAccountUiOps *ui_ops;

	g_return_if_fail(account     != NULL);
	g_return_if_fail(remote_user != NULL);

	ui_ops = purple_accounts_get_ui_ops();

	if (ui_ops != NULL && ui_ops->request_add != NULL)
		ui_ops->request_add(account, remote_user, id, alias, message);
}

static PurpleAccountRequestInfo *
purple_account_request_info_unref(PurpleAccountRequestInfo *info)
{
	if (--info->ref)
		return info;

	/* TODO: This will leak info->user_data, but there is no callback to just clean that up */
	g_free(info->user);
	g_free(info);
	return NULL;
}

static void
purple_account_request_close_info(PurpleAccountRequestInfo *info)
{
	PurpleAccountUiOps *ops;

	ops = purple_accounts_get_ui_ops();

	if (ops != NULL && ops->close_account_request != NULL)
		ops->close_account_request(info->ui_handle);

	purple_account_request_info_unref(info);
}

void
purple_account_request_close_with_account(PurpleAccount *account)
{
	GList *l, *l_next;

	g_return_if_fail(account != NULL);

	for (l = handles; l != NULL; l = l_next) {
		PurpleAccountRequestInfo *info = l->data;

		l_next = l->next;

		if (info->account == account) {
			handles = g_list_remove(handles, info);
			purple_account_request_close_info(info);
		}
	}
}

void
purple_account_request_close(void *ui_handle)
{
	GList *l, *l_next;

	g_return_if_fail(ui_handle != NULL);

	for (l = handles; l != NULL; l = l_next) {
		PurpleAccountRequestInfo *info = l->data;

		l_next = l->next;

		if (info->ui_handle == ui_handle) {
			handles = g_list_remove(handles, info);
			purple_account_request_close_info(info);
		}
	}
}

static void
request_auth_cb(void *data)
{
	PurpleAccountRequestInfo *info = data;

	handles = g_list_remove(handles, info);

	if (info->auth_cb != NULL)
		info->auth_cb(info->userdata);

	purple_signal_emit(purple_accounts_get_handle(),
			"account-authorization-granted", info->account, info->user);

	purple_account_request_info_unref(info);
}

static void
request_deny_cb(void *data)
{
	PurpleAccountRequestInfo *info = data;

	handles = g_list_remove(handles, info);

	if (info->deny_cb != NULL)
		info->deny_cb(info->userdata);

	purple_signal_emit(purple_accounts_get_handle(),
			"account-authorization-denied", info->account, info->user);

	purple_account_request_info_unref(info);
}

void *
purple_account_request_authorization(PurpleAccount *account, const char *remote_user,
				     const char *id, const char *alias, const char *message, gboolean on_list,
				     PurpleAccountRequestAuthorizationCb auth_cb, PurpleAccountRequestAuthorizationCb deny_cb, void *user_data)
{
	PurpleAccountUiOps *ui_ops;
	PurpleAccountRequestInfo *info;
	int plugin_return;

	g_return_val_if_fail(account     != NULL, NULL);
	g_return_val_if_fail(remote_user != NULL, NULL);

	ui_ops = purple_accounts_get_ui_ops();

	plugin_return = GPOINTER_TO_INT(
			purple_signal_emit_return_1(purple_accounts_get_handle(),
				"account-authorization-requested", account, remote_user));

	if (plugin_return > 0) {
		if (auth_cb != NULL)
			auth_cb(user_data);
		return NULL;
	} else if (plugin_return < 0) {
		if (deny_cb != NULL)
			deny_cb(user_data);
		return NULL;
	}

	plugin_return = GPOINTER_TO_INT(
			purple_signal_emit_return_1(
				purple_accounts_get_handle(),
				"account-authorization-requested-with-message",
				account, remote_user, message
			));

	switch (plugin_return)
	{
		case PURPLE_ACCOUNT_RESPONSE_IGNORE:
			return NULL;
		case PURPLE_ACCOUNT_RESPONSE_ACCEPT:
			if (auth_cb != NULL)
				auth_cb(user_data);
			return NULL;
		case PURPLE_ACCOUNT_RESPONSE_DENY:
			if (deny_cb != NULL)
				deny_cb(user_data);
			return NULL;
	}

	if (ui_ops != NULL && ui_ops->request_authorize != NULL) {
		info            = g_new0(PurpleAccountRequestInfo, 1);
		info->type      = PURPLE_ACCOUNT_REQUEST_AUTHORIZATION;
		info->account   = account;
		info->auth_cb   = auth_cb;
		info->deny_cb   = deny_cb;
		info->userdata  = user_data;
		info->user      = g_strdup(remote_user);
		info->ref       = 2;  /* We hold an extra ref to make sure info remains valid
		                         if any of the callbacks are called synchronously. We
		                         unref it after the function call */

		info->ui_handle = ui_ops->request_authorize(account, remote_user, id, alias, message,
							    on_list, request_auth_cb, request_deny_cb, info);

		info = purple_account_request_info_unref(info);
		if (info) {
			handles = g_list_append(handles, info);
			return info->ui_handle;
		}
	}

	return NULL;
}

static void
change_password_cb(PurpleAccount *account, PurpleRequestFields *fields)
{
	const char *orig_pass, *new_pass_1, *new_pass_2;

	orig_pass  = purple_request_fields_get_string(fields, "password");
	new_pass_1 = purple_request_fields_get_string(fields, "new_password_1");
	new_pass_2 = purple_request_fields_get_string(fields, "new_password_2");

	if (g_utf8_collate(new_pass_1, new_pass_2))
	{
		purple_notify_error(account, NULL,
						  _("New passwords do not match."), NULL);

		return;
	}

	if ((purple_request_fields_is_field_required(fields, "password") &&
			(orig_pass == NULL || *orig_pass == '\0')) ||
		(purple_request_fields_is_field_required(fields, "new_password_1") &&
			(new_pass_1 == NULL || *new_pass_1 == '\0')) ||
		(purple_request_fields_is_field_required(fields, "new_password_2") &&
			(new_pass_2 == NULL || *new_pass_2 == '\0')))
	{
		purple_notify_error(account, NULL,
						  _("Fill out all fields completely."), NULL);
		return;
	}

	purple_account_change_password(account, orig_pass, new_pass_1);
}

void
purple_account_request_change_password(PurpleAccount *account)
{
	PurpleRequestFields *fields;
	PurpleRequestFieldGroup *group;
	PurpleRequestField *field;
	PurpleConnection *gc;
	PurplePlugin *prpl = NULL;
	PurplePluginProtocolInfo *prpl_info = NULL;
	char primary[256];

	g_return_if_fail(account != NULL);
	g_return_if_fail(purple_account_is_connected(account));

	gc = purple_account_get_connection(account);
	if (gc != NULL)
		prpl = purple_connection_get_prpl(gc);
	if (prpl != NULL)
		prpl_info = PURPLE_PLUGIN_PROTOCOL_INFO(prpl);

	fields = purple_request_fields_new();

	group = purple_request_field_group_new(NULL);
	purple_request_fields_add_group(fields, group);

	field = purple_request_field_string_new("password", _("Original password"),
										  NULL, FALSE);
	purple_request_field_string_set_masked(field, TRUE);
	if (!prpl_info || !(prpl_info->options & OPT_PROTO_PASSWORD_OPTIONAL))
		purple_request_field_set_required(field, TRUE);
	purple_request_field_group_add_field(group, field);

	field = purple_request_field_string_new("new_password_1",
										  _("New password"),
										  NULL, FALSE);
	purple_request_field_string_set_masked(field, TRUE);
	if (!prpl_info || !(prpl_info->options & OPT_PROTO_PASSWORD_OPTIONAL))
		purple_request_field_set_required(field, TRUE);
	purple_request_field_group_add_field(group, field);

	field = purple_request_field_string_new("new_password_2",
										  _("New password (again)"),
										  NULL, FALSE);
	purple_request_field_string_set_masked(field, TRUE);
	if (!prpl_info || !(prpl_info->options & OPT_PROTO_PASSWORD_OPTIONAL))
		purple_request_field_set_required(field, TRUE);
	purple_request_field_group_add_field(group, field);

	g_snprintf(primary, sizeof(primary), _("Change password for %s"),
			   purple_account_get_username(account));

	/* I'm sticking this somewhere in the code: bologna */

	purple_request_fields(purple_account_get_connection(account),
						NULL,
						primary,
						_("Please enter your current password and your "
						  "new password."),
						fields,
						_("OK"), G_CALLBACK(change_password_cb),
						_("Cancel"), NULL,
						account, NULL, NULL,
						account);
}

static void
set_user_info_cb(PurpleAccount *account, const char *user_info)
{
	PurpleConnection *gc;

	purple_account_set_user_info(account, user_info);
	gc = purple_account_get_connection(account);
	serv_set_info(gc, user_info);
}

void
purple_account_request_change_user_info(PurpleAccount *account)
{
	PurpleConnection *gc;
	char primary[256];

	g_return_if_fail(account != NULL);
	g_return_if_fail(purple_account_is_connected(account));

	gc = purple_account_get_connection(account);

	g_snprintf(primary, sizeof(primary),
			   _("Change user information for %s"),
			   purple_account_get_username(account));

	purple_request_input(gc, _("Set User Info"), primary, NULL,
					   purple_account_get_user_info(account),
					   TRUE, FALSE, ((gc != NULL) &&
					   (gc->flags & PURPLE_CONNECTION_HTML) ? "html" : NULL),
					   _("Save"), G_CALLBACK(set_user_info_cb),
					   _("Cancel"), NULL,
					   account, NULL, NULL,
					   account);
}

void
purple_account_set_username(PurpleAccount *account, const char *username)
{
	PurpleBlistUiOps *blist_ops;

	g_return_if_fail(account != NULL);

	g_free(account->username);
	account->username = g_strdup(username);

	schedule_accounts_save();

	/* if the name changes, we should re-write the buddy list
	 * to disk with the new name */
	blist_ops = purple_blist_get_ui_ops();
	if (blist_ops != NULL && blist_ops->save_account != NULL)
		blist_ops->save_account(account);
}

void
purple_account_set_password(PurpleAccount *account, const char *password)
{
	g_return_if_fail(account != NULL);

	g_free(account->password);
	account->password = g_strdup(password);

	schedule_accounts_save();
}

void
purple_account_set_alias(PurpleAccount *account, const char *alias)
{
	g_return_if_fail(account != NULL);

	/*
	 * Do nothing if alias and account->alias are both NULL.  Or if
	 * they're the exact same string.
	 */
	if (alias == account->alias)
		return;

	if ((!alias && account->alias) || (alias && !account->alias) ||
			g_utf8_collate(account->alias, alias))
	{
		char *old = account->alias;

		account->alias = g_strdup(alias);
		purple_signal_emit(purple_accounts_get_handle(), "account-alias-changed",
						 account, old);
		g_free(old);

		schedule_accounts_save();
	}
}

void
purple_account_set_user_info(PurpleAccount *account, const char *user_info)
{
	g_return_if_fail(account != NULL);

	g_free(account->user_info);
	account->user_info = g_strdup(user_info);

	schedule_accounts_save();
}

void purple_account_set_buddy_icon_path(PurpleAccount *account, const char *path)
{
	g_return_if_fail(account != NULL);

	g_free(account->buddy_icon_path);
	account->buddy_icon_path = g_strdup(path);

	schedule_accounts_save();
}

void
purple_account_set_protocol_id(PurpleAccount *account, const char *protocol_id)
{
	g_return_if_fail(account     != NULL);
	g_return_if_fail(protocol_id != NULL);

	g_free(account->protocol_id);
	account->protocol_id = g_strdup(protocol_id);

	schedule_accounts_save();
}

void
purple_account_set_connection(PurpleAccount *account, PurpleConnection *gc)
{
	g_return_if_fail(account != NULL);

	account->gc = gc;
}

void
purple_account_set_remember_password(PurpleAccount *account, gboolean value)
{
	g_return_if_fail(account != NULL);

	account->remember_pass = value;

	schedule_accounts_save();
}

void
purple_account_set_check_mail(PurpleAccount *account, gboolean value)
{
	g_return_if_fail(account != NULL);

	purple_account_set_bool(account, "check-mail", value);
}

void
purple_account_set_enabled(PurpleAccount *account, const char *ui,
			 gboolean value)
{
	PurpleConnection *gc;
	gboolean was_enabled = FALSE;

	g_return_if_fail(account != NULL);
	g_return_if_fail(ui      != NULL);

	was_enabled = purple_account_get_enabled(account, ui);

	purple_account_set_ui_bool(account, ui, "auto-login", value);
	gc = purple_account_get_connection(account);

	if(was_enabled && !value)
		purple_signal_emit(purple_accounts_get_handle(), "account-disabled", account);
	else if(!was_enabled && value)
		purple_signal_emit(purple_accounts_get_handle(), "account-enabled", account);

	if ((gc != NULL) && (gc->wants_to_die == TRUE))
		return;

	if (value && purple_presence_is_online(account->presence))
		purple_account_connect(account);
	else if (!value && !purple_account_is_disconnected(account))
		purple_account_disconnect(account);
}

void
purple_account_set_proxy_info(PurpleAccount *account, PurpleProxyInfo *info)
{
	g_return_if_fail(account != NULL);

	if (account->proxy_info != NULL)
		purple_proxy_info_destroy(account->proxy_info);

	account->proxy_info = info;

	schedule_accounts_save();
}

void
purple_account_set_privacy_type(PurpleAccount *account, PurplePrivacyType privacy_type)
{
	g_return_if_fail(account != NULL);

	account->perm_deny = privacy_type;
}

void
purple_account_set_status_types(PurpleAccount *account, GList *status_types)
{
	g_return_if_fail(account != NULL);

	/* Out with the old... */
	if (account->status_types != NULL)
	{
		g_list_foreach(account->status_types, (GFunc)purple_status_type_destroy, NULL);
		g_list_free(account->status_types);
	}

	/* In with the new... */
	account->status_types = status_types;
}

void
purple_account_set_status(PurpleAccount *account, const char *status_id,
						gboolean active, ...)
{
	GList *attrs = NULL;
	const gchar *id;
	gpointer data;
	va_list args;

	va_start(args, active);
	while ((id = va_arg(args, const char *)) != NULL)
	{
		attrs = g_list_append(attrs, (char *)id);
		data = va_arg(args, void *);
		attrs = g_list_append(attrs, data);
	}
	purple_account_set_status_list(account, status_id, active, attrs);
	g_list_free(attrs);
	va_end(args);
}

void
purple_account_set_status_list(PurpleAccount *account, const char *status_id,
							 gboolean active, GList *attrs)
{
	PurpleStatus *status;

	g_return_if_fail(account   != NULL);
	g_return_if_fail(status_id != NULL);

	status = purple_account_get_status(account, status_id);
	if (status == NULL)
	{
		purple_debug_error("account",
				   "Invalid status ID '%s' for account %s (%s)\n",
				   status_id, purple_account_get_username(account),
				   purple_account_get_protocol_id(account));
		return;
	}

	if (active || purple_status_is_independent(status))
		purple_status_set_active_with_attrs_list(status, active, attrs);

	/*
	 * Our current statuses are saved to accounts.xml (so that when we
	 * reconnect, we go back to the previous status).
	 */
	schedule_accounts_save();
}

struct public_alias_closure
{
	PurpleAccount *account;
	gpointer failure_cb;
};

static gboolean
set_public_alias_unsupported(gpointer data)
{
	struct public_alias_closure *closure = data;
	PurpleSetPublicAliasFailureCallback failure_cb = closure->failure_cb;

	failure_cb(closure->account,
	           _("This protocol does not support setting a public alias."));
	g_free(closure);

	return FALSE;
}

void
purple_account_set_public_alias(PurpleAccount *account,
		const char *alias, PurpleSetPublicAliasSuccessCallback success_cb,
		PurpleSetPublicAliasFailureCallback failure_cb)
{
	PurpleConnection *gc;
	PurplePlugin *prpl = NULL;
	PurplePluginProtocolInfo *prpl_info = NULL;

	g_return_if_fail(account != NULL);
	g_return_if_fail(purple_account_is_connected(account));

	gc = purple_account_get_connection(account);
	prpl = purple_connection_get_prpl(gc);
	prpl_info = PURPLE_PLUGIN_PROTOCOL_INFO(prpl);

	if (PURPLE_PROTOCOL_PLUGIN_HAS_FUNC(prpl_info, set_public_alias))
		prpl_info->set_public_alias(gc, alias, success_cb, failure_cb);
	else if (failure_cb) {
		struct public_alias_closure *closure =
				g_new0(struct public_alias_closure, 1);
		closure->account = account;
		closure->failure_cb = failure_cb;
		purple_timeout_add(0, set_public_alias_unsupported, closure);
	}
}

static gboolean
get_public_alias_unsupported(gpointer data)
{
	struct public_alias_closure *closure = data;
	PurpleGetPublicAliasFailureCallback failure_cb = closure->failure_cb;

	failure_cb(closure->account,
	           _("This protocol does not support fetching the public alias."));
	g_free(closure);

	return FALSE;
}

void
purple_account_get_public_alias(PurpleAccount *account,
		PurpleGetPublicAliasSuccessCallback success_cb,
		PurpleGetPublicAliasFailureCallback failure_cb)
{
	PurpleConnection *gc;
	PurplePlugin *prpl = NULL;
	PurplePluginProtocolInfo *prpl_info = NULL;

	g_return_if_fail(account != NULL);
	g_return_if_fail(purple_account_is_connected(account));

	gc = purple_account_get_connection(account);
	prpl = purple_connection_get_prpl(gc);
	prpl_info = PURPLE_PLUGIN_PROTOCOL_INFO(prpl);

	if (PURPLE_PROTOCOL_PLUGIN_HAS_FUNC(prpl_info, get_public_alias))
		prpl_info->get_public_alias(gc, success_cb, failure_cb);
	else if (failure_cb) {
		struct public_alias_closure *closure =
				g_new0(struct public_alias_closure, 1);
		closure->account = account;
		closure->failure_cb = failure_cb;
		purple_timeout_add(0, get_public_alias_unsupported, closure);
	}
}

gboolean
purple_account_get_silence_suppression(const PurpleAccount *account)
{
	return purple_account_get_bool(account, "silence-suppression", FALSE);
}

void
purple_account_set_silence_suppression(PurpleAccount *account, gboolean value)
{
	g_return_if_fail(account != NULL);

	purple_account_set_bool(account, "silence-suppression", value);
}

void
purple_account_clear_settings(PurpleAccount *account)
{
	g_return_if_fail(account != NULL);

	g_hash_table_destroy(account->settings);

	account->settings = g_hash_table_new_full(g_str_hash, g_str_equal,
											  g_free, delete_setting);
}

void
purple_account_remove_setting(PurpleAccount *account, const char *setting)
{
	g_return_if_fail(account != NULL);
	g_return_if_fail(setting != NULL);

	g_hash_table_remove(account->settings, setting);
}

void
purple_account_set_int(PurpleAccount *account, const char *name, int value)
{
	PurpleAccountSetting *setting;

	g_return_if_fail(account != NULL);
	g_return_if_fail(name    != NULL);

	setting = g_new0(PurpleAccountSetting, 1);

	setting->type          = PURPLE_PREF_INT;
	setting->value.integer = value;

	g_hash_table_insert(account->settings, g_strdup(name), setting);

	schedule_accounts_save();
}

void
purple_account_set_string(PurpleAccount *account, const char *name,
						const char *value)
{
	PurpleAccountSetting *setting;

	g_return_if_fail(account != NULL);
	g_return_if_fail(name    != NULL);

	setting = g_new0(PurpleAccountSetting, 1);

	setting->type         = PURPLE_PREF_STRING;
	setting->value.string = g_strdup(value);

	g_hash_table_insert(account->settings, g_strdup(name), setting);

	schedule_accounts_save();
}

void
purple_account_set_bool(PurpleAccount *account, const char *name, gboolean value)
{
	PurpleAccountSetting *setting;

	g_return_if_fail(account != NULL);
	g_return_if_fail(name    != NULL);

	setting = g_new0(PurpleAccountSetting, 1);

	setting->type       = PURPLE_PREF_BOOLEAN;
	setting->value.boolean = value;

	g_hash_table_insert(account->settings, g_strdup(name), setting);

	schedule_accounts_save();
}

static GHashTable *
get_ui_settings_table(PurpleAccount *account, const char *ui)
{
	GHashTable *table;

	table = g_hash_table_lookup(account->ui_settings, ui);

	if (table == NULL) {
		table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free,
									  delete_setting);
		g_hash_table_insert(account->ui_settings, g_strdup(ui), table);
	}

	return table;
}

void
purple_account_set_ui_int(PurpleAccount *account, const char *ui,
						const char *name, int value)
{
	PurpleAccountSetting *setting;
	GHashTable *table;

	g_return_if_fail(account != NULL);
	g_return_if_fail(ui      != NULL);
	g_return_if_fail(name    != NULL);

	setting = g_new0(PurpleAccountSetting, 1);

	setting->type          = PURPLE_PREF_INT;
	setting->ui            = g_strdup(ui);
	setting->value.integer = value;

	table = get_ui_settings_table(account, ui);

	g_hash_table_insert(table, g_strdup(name), setting);

	schedule_accounts_save();
}

void
purple_account_set_ui_string(PurpleAccount *account, const char *ui,
						   const char *name, const char *value)
{
	PurpleAccountSetting *setting;
	GHashTable *table;

	g_return_if_fail(account != NULL);
	g_return_if_fail(ui      != NULL);
	g_return_if_fail(name    != NULL);

	setting = g_new0(PurpleAccountSetting, 1);

	setting->type         = PURPLE_PREF_STRING;
	setting->ui           = g_strdup(ui);
	setting->value.string = g_strdup(value);

	table = get_ui_settings_table(account, ui);

	g_hash_table_insert(table, g_strdup(name), setting);

	schedule_accounts_save();
}

void
purple_account_set_ui_bool(PurpleAccount *account, const char *ui,
						 const char *name, gboolean value)
{
	PurpleAccountSetting *setting;
	GHashTable *table;

	g_return_if_fail(account != NULL);
	g_return_if_fail(ui      != NULL);
	g_return_if_fail(name    != NULL);

	setting = g_new0(PurpleAccountSetting, 1);

	setting->type       = PURPLE_PREF_BOOLEAN;
	setting->ui         = g_strdup(ui);
	setting->value.boolean = value;

	table = get_ui_settings_table(account, ui);

	g_hash_table_insert(table, g_strdup(name), setting);

	schedule_accounts_save();
}

static PurpleConnectionState
purple_account_get_state(const PurpleAccount *account)
{
	PurpleConnection *gc;

	g_return_val_if_fail(account != NULL, PURPLE_DISCONNECTED);

	gc = purple_account_get_connection(account);
	if (!gc)
		return PURPLE_DISCONNECTED;

	return purple_connection_get_state(gc);
}

gboolean
purple_account_is_connected(const PurpleAccount *account)
{
	return (purple_account_get_state(account) == PURPLE_CONNECTED);
}

gboolean
purple_account_is_connecting(const PurpleAccount *account)
{
	return (purple_account_get_state(account) == PURPLE_CONNECTING);
}

gboolean
purple_account_is_disconnected(const PurpleAccount *account)
{
	return (purple_account_get_state(account) == PURPLE_DISCONNECTED);
}

const char *
purple_account_get_username(const PurpleAccount *account)
{
	g_return_val_if_fail(account != NULL, NULL);

	return account->username;
}

const char *
purple_account_get_password(const PurpleAccount *account)
{
	g_return_val_if_fail(account != NULL, NULL);

	return account->password;
}

const char *
purple_account_get_alias(const PurpleAccount *account)
{
	g_return_val_if_fail(account != NULL, NULL);

	return account->alias;
}

const char *
purple_account_get_user_info(const PurpleAccount *account)
{
	g_return_val_if_fail(account != NULL, NULL);

	return account->user_info;
}

const char *
purple_account_get_buddy_icon_path(const PurpleAccount *account)
{
	g_return_val_if_fail(account != NULL, NULL);

	return account->buddy_icon_path;
}

const char *
purple_account_get_protocol_id(const PurpleAccount *account)
{
	g_return_val_if_fail(account != NULL, NULL);
	return account->protocol_id;
}

const char *
purple_account_get_protocol_name(const PurpleAccount *account)
{
	PurplePlugin *p;

	g_return_val_if_fail(account != NULL, NULL);

	p = purple_find_prpl(purple_account_get_protocol_id(account));

	return ((p && p->info->name) ? _(p->info->name) : _("Unknown"));
}

PurpleConnection *
purple_account_get_connection(const PurpleAccount *account)
{
	g_return_val_if_fail(account != NULL, NULL);

	return account->gc;
}

const gchar *
purple_account_get_name_for_display(const PurpleAccount *account)
{
	PurpleBuddy *self = NULL;
	PurpleConnection *gc = NULL;
	const gchar *name = NULL, *username = NULL, *displayname = NULL;

	name = purple_account_get_alias(account);

	if (name) {
		return name;
	}

	username = purple_account_get_username(account);
	self = purple_find_buddy((PurpleAccount *)account, username);

	if (self) {
		const gchar *calias= purple_buddy_get_contact_alias(self);

		/* We don't want to return the buddy name if the buddy/contact
		 * doesn't have an alias set. */
		if (!purple_strequal(username, calias)) {
			return calias;
		}
	}

	gc = purple_account_get_connection(account);
	displayname = purple_connection_get_display_name(gc);

	if (displayname) {
		return displayname;
	}

	return username;
}

gboolean
purple_account_get_remember_password(const PurpleAccount *account)
{
	g_return_val_if_fail(account != NULL, FALSE);

	return account->remember_pass;
}

gboolean
purple_account_get_check_mail(const PurpleAccount *account)
{
	g_return_val_if_fail(account != NULL, FALSE);

	return purple_account_get_bool(account, "check-mail", FALSE);
}

gboolean
purple_account_get_enabled(const PurpleAccount *account, const char *ui)
{
	g_return_val_if_fail(account != NULL, FALSE);
	g_return_val_if_fail(ui      != NULL, FALSE);

	return purple_account_get_ui_bool(account, ui, "auto-login", FALSE);
}

PurpleProxyInfo *
purple_account_get_proxy_info(const PurpleAccount *account)
{
	g_return_val_if_fail(account != NULL, NULL);

	return account->proxy_info;
}

PurplePrivacyType
purple_account_get_privacy_type(const PurpleAccount *account)
{
	g_return_val_if_fail(account != NULL, PURPLE_PRIVACY_ALLOW_ALL);

	return account->perm_deny;
}

PurpleStatus *
purple_account_get_active_status(const PurpleAccount *account)
{
	g_return_val_if_fail(account   != NULL, NULL);

	return purple_presence_get_active_status(account->presence);
}

PurpleStatus *
purple_account_get_status(const PurpleAccount *account, const char *status_id)
{
	g_return_val_if_fail(account   != NULL, NULL);
	g_return_val_if_fail(status_id != NULL, NULL);

	return purple_presence_get_status(account->presence, status_id);
}

PurpleStatusType *
purple_account_get_status_type(const PurpleAccount *account, const char *id)
{
	GList *l;

	g_return_val_if_fail(account != NULL, NULL);
	g_return_val_if_fail(id      != NULL, NULL);

	for (l = purple_account_get_status_types(account); l != NULL; l = l->next)
	{
		PurpleStatusType *status_type = (PurpleStatusType *)l->data;

		if (purple_strequal(purple_status_type_get_id(status_type), id))
			return status_type;
	}

	return NULL;
}

PurpleStatusType *
purple_account_get_status_type_with_primitive(const PurpleAccount *account, PurpleStatusPrimitive primitive)
{
	GList *l;

	g_return_val_if_fail(account != NULL, NULL);

	for (l = purple_account_get_status_types(account); l != NULL; l = l->next)
	{
		PurpleStatusType *status_type = (PurpleStatusType *)l->data;

		if (purple_status_type_get_primitive(status_type) == primitive)
			return status_type;
	}

	return NULL;
}

PurplePresence *
purple_account_get_presence(const PurpleAccount *account)
{
	g_return_val_if_fail(account != NULL, NULL);

	return account->presence;
}

gboolean
purple_account_is_status_active(const PurpleAccount *account,
							  const char *status_id)
{
	g_return_val_if_fail(account   != NULL, FALSE);
	g_return_val_if_fail(status_id != NULL, FALSE);

	return purple_presence_is_status_active(account->presence, status_id);
}

GList *
purple_account_get_status_types(const PurpleAccount *account)
{
	g_return_val_if_fail(account != NULL, NULL);

	return account->status_types;
}

int
purple_account_get_int(const PurpleAccount *account, const char *name,
					 int default_value)
{
	PurpleAccountSetting *setting;

	g_return_val_if_fail(account != NULL, default_value);
	g_return_val_if_fail(name    != NULL, default_value);

	setting = g_hash_table_lookup(account->settings, name);

	if (setting == NULL)
		return default_value;

	g_return_val_if_fail(setting->type == PURPLE_PREF_INT, default_value);

	return setting->value.integer;
}

const char *
purple_account_get_string(const PurpleAccount *account, const char *name,
						const char *default_value)
{
	PurpleAccountSetting *setting;

	g_return_val_if_fail(account != NULL, default_value);
	g_return_val_if_fail(name    != NULL, default_value);

	setting = g_hash_table_lookup(account->settings, name);

	if (setting == NULL)
		return default_value;

	g_return_val_if_fail(setting->type == PURPLE_PREF_STRING, default_value);

	return setting->value.string;
}

gboolean
purple_account_get_bool(const PurpleAccount *account, const char *name,
					  gboolean default_value)
{
	PurpleAccountSetting *setting;

	g_return_val_if_fail(account != NULL, default_value);
	g_return_val_if_fail(name    != NULL, default_value);

	setting = g_hash_table_lookup(account->settings, name);

	if (setting == NULL)
		return default_value;

	g_return_val_if_fail(setting->type == PURPLE_PREF_BOOLEAN, default_value);

	return setting->value.boolean;
}

int
purple_account_get_ui_int(const PurpleAccount *account, const char *ui,
						const char *name, int default_value)
{
	PurpleAccountSetting *setting;
	GHashTable *table;

	g_return_val_if_fail(account != NULL, default_value);
	g_return_val_if_fail(ui      != NULL, default_value);
	g_return_val_if_fail(name    != NULL, default_value);

	if ((table = g_hash_table_lookup(account->ui_settings, ui)) == NULL)
		return default_value;

	if ((setting = g_hash_table_lookup(table, name)) == NULL)
		return default_value;

	g_return_val_if_fail(setting->type == PURPLE_PREF_INT, default_value);

	return setting->value.integer;
}

const char *
purple_account_get_ui_string(const PurpleAccount *account, const char *ui,
						   const char *name, const char *default_value)
{
	PurpleAccountSetting *setting;
	GHashTable *table;

	g_return_val_if_fail(account != NULL, default_value);
	g_return_val_if_fail(ui      != NULL, default_value);
	g_return_val_if_fail(name    != NULL, default_value);

	if ((table = g_hash_table_lookup(account->ui_settings, ui)) == NULL)
		return default_value;

	if ((setting = g_hash_table_lookup(table, name)) == NULL)
		return default_value;

	g_return_val_if_fail(setting->type == PURPLE_PREF_STRING, default_value);

	return setting->value.string;
}

gboolean
purple_account_get_ui_bool(const PurpleAccount *account, const char *ui,
						 const char *name, gboolean default_value)
{
	PurpleAccountSetting *setting;
	GHashTable *table;

	g_return_val_if_fail(account != NULL, default_value);
	g_return_val_if_fail(ui      != NULL, default_value);
	g_return_val_if_fail(name    != NULL, default_value);

	if ((table = g_hash_table_lookup(account->ui_settings, ui)) == NULL)
		return default_value;

	if ((setting = g_hash_table_lookup(table, name)) == NULL)
		return default_value;

	g_return_val_if_fail(setting->type == PURPLE_PREF_BOOLEAN, default_value);

	return setting->value.boolean;
}

PurpleLog *
purple_account_get_log(PurpleAccount *account, gboolean create)
{
	g_return_val_if_fail(account != NULL, NULL);

	if(!account->system_log && create){
		PurplePresence *presence;
		int login_time;

		presence = purple_account_get_presence(account);
		login_time = purple_presence_get_login_time(presence);

		account->system_log	 = purple_log_new(PURPLE_LOG_SYSTEM,
				purple_account_get_username(account), account, NULL,
				(login_time != 0) ? login_time : time(NULL), NULL);
	}

	return account->system_log;
}

void
purple_account_destroy_log(PurpleAccount *account)
{
	g_return_if_fail(account != NULL);

	if(account->system_log){
		purple_log_free(account->system_log);
		account->system_log = NULL;
	}
}

void
purple_account_add_buddy(PurpleAccount *account, PurpleBuddy *buddy)
{
	PurplePluginProtocolInfo *prpl_info = NULL;
	PurpleConnection *gc;
	PurplePlugin *prpl = NULL;

	g_return_if_fail(account != NULL);
	g_return_if_fail(buddy != NULL);

	gc = purple_account_get_connection(account);
	if (gc != NULL)
		prpl = purple_connection_get_prpl(gc);

	if (prpl != NULL)
		prpl_info = PURPLE_PLUGIN_PROTOCOL_INFO(prpl);

	if (prpl_info != NULL) {
		if (PURPLE_PROTOCOL_PLUGIN_HAS_FUNC(prpl_info, add_buddy_with_invite))
			prpl_info->add_buddy_with_invite(gc, buddy, purple_buddy_get_group(buddy), NULL);
		else if (PURPLE_PROTOCOL_PLUGIN_HAS_FUNC(prpl_info, add_buddy))
			prpl_info->add_buddy(gc, buddy, purple_buddy_get_group(buddy));
	}
}

void
purple_account_add_buddy_with_invite(PurpleAccount *account, PurpleBuddy *buddy, const char *message)
{
	PurplePluginProtocolInfo *prpl_info = NULL;
	PurpleConnection *gc;
	PurplePlugin *prpl = NULL;

	g_return_if_fail(account != NULL);
	g_return_if_fail(buddy != NULL);

	gc = purple_account_get_connection(account);
	if (gc != NULL)
		prpl = purple_connection_get_prpl(gc);

	if (prpl != NULL)
		prpl_info = PURPLE_PLUGIN_PROTOCOL_INFO(prpl);

	if (prpl_info != NULL) {
		if (PURPLE_PROTOCOL_PLUGIN_HAS_FUNC(prpl_info, add_buddy_with_invite))
			prpl_info->add_buddy_with_invite(gc, buddy, purple_buddy_get_group(buddy), message);
		else if (PURPLE_PROTOCOL_PLUGIN_HAS_FUNC(prpl_info, add_buddy))
			prpl_info->add_buddy(gc, buddy, purple_buddy_get_group(buddy));
	}
}

void
purple_account_add_buddies(PurpleAccount *account, GList *buddies)
{
	PurplePluginProtocolInfo *prpl_info = NULL;
	PurpleConnection *gc = purple_account_get_connection(account);
	PurplePlugin *prpl = NULL;

	if (gc != NULL)
		prpl = purple_connection_get_prpl(gc);

	if (prpl != NULL)
		prpl_info = PURPLE_PLUGIN_PROTOCOL_INFO(prpl);

	if (prpl_info) {
		GList *cur, *groups = NULL;

		/* Make a list of what group each buddy is in */
		for (cur = buddies; cur != NULL; cur = cur->next) {
			PurpleBuddy *buddy = cur->data;
			groups = g_list_append(groups, purple_buddy_get_group(buddy));
		}

		if (PURPLE_PROTOCOL_PLUGIN_HAS_FUNC(prpl_info, add_buddies_with_invite))
			prpl_info->add_buddies_with_invite(gc, buddies, groups, NULL);
		else if (PURPLE_PROTOCOL_PLUGIN_HAS_FUNC(prpl_info, add_buddies))
			prpl_info->add_buddies(gc, buddies, groups);
		else if (PURPLE_PROTOCOL_PLUGIN_HAS_FUNC(prpl_info, add_buddy_with_invite)) {
			GList *curb = buddies, *curg = groups;

			while ((curb != NULL) && (curg != NULL)) {
				prpl_info->add_buddy_with_invite(gc, curb->data, curg->data, NULL);
				curb = curb->next;
				curg = curg->next;
			}
		}
		else if (PURPLE_PROTOCOL_PLUGIN_HAS_FUNC(prpl_info, add_buddy)) {
			GList *curb = buddies, *curg = groups;

			while ((curb != NULL) && (curg != NULL)) {
				prpl_info->add_buddy(gc, curb->data, curg->data);
				curb = curb->next;
				curg = curg->next;
			}
		}

		g_list_free(groups);
	}
}

void
purple_account_add_buddies_with_invite(PurpleAccount *account, GList *buddies, const char *message)
{
	PurplePluginProtocolInfo *prpl_info = NULL;
	PurpleConnection *gc = purple_account_get_connection(account);
	PurplePlugin *prpl = NULL;

	if (gc != NULL)
		prpl = purple_connection_get_prpl(gc);

	if (prpl != NULL)
		prpl_info = PURPLE_PLUGIN_PROTOCOL_INFO(prpl);

	if (prpl_info) {
		GList *cur, *groups = NULL;

		/* Make a list of what group each buddy is in */
		for (cur = buddies; cur != NULL; cur = cur->next) {
			PurpleBuddy *buddy = cur->data;
			groups = g_list_append(groups, purple_buddy_get_group(buddy));
		}

		if (PURPLE_PROTOCOL_PLUGIN_HAS_FUNC(prpl_info, add_buddies_with_invite))
			prpl_info->add_buddies_with_invite(gc, buddies, groups, message);
		else if (PURPLE_PROTOCOL_PLUGIN_HAS_FUNC(prpl_info, add_buddy_with_invite)) {
			GList *curb = buddies, *curg = groups;

			while ((curb != NULL) && (curg != NULL)) {
				prpl_info->add_buddy_with_invite(gc, curb->data, curg->data, message);
				curb = curb->next;
				curg = curg->next;
			}
		}
		else if (PURPLE_PROTOCOL_PLUGIN_HAS_FUNC(prpl_info, add_buddies))
			prpl_info->add_buddies(gc, buddies, groups);
		else if (PURPLE_PROTOCOL_PLUGIN_HAS_FUNC(prpl_info, add_buddy)) {
			GList *curb = buddies, *curg = groups;

			while ((curb != NULL) && (curg != NULL)) {
				prpl_info->add_buddy(gc, curb->data, curg->data);
				curb = curb->next;
				curg = curg->next;
			}
		}

		g_list_free(groups);
	}
}

void
purple_account_remove_buddy(PurpleAccount *account, PurpleBuddy *buddy,
		PurpleGroup *group)
{
	PurplePluginProtocolInfo *prpl_info = NULL;
	PurpleConnection *gc = purple_account_get_connection(account);
	PurplePlugin *prpl = NULL;

	if (gc != NULL)
		prpl = purple_connection_get_prpl(gc);

	if (prpl != NULL)
		prpl_info = PURPLE_PLUGIN_PROTOCOL_INFO(prpl);

	if (prpl_info && prpl_info->remove_buddy)
		prpl_info->remove_buddy(gc, buddy, group);
}

void
purple_account_remove_buddies(PurpleAccount *account, GList *buddies, GList *groups)
{
	PurplePluginProtocolInfo *prpl_info = NULL;
	PurpleConnection *gc = purple_account_get_connection(account);
	PurplePlugin *prpl = NULL;

	if (gc != NULL)
		prpl = purple_connection_get_prpl(gc);

	if (prpl != NULL)
		prpl_info = PURPLE_PLUGIN_PROTOCOL_INFO(prpl);

	if (prpl_info) {
		if (prpl_info->remove_buddies)
			prpl_info->remove_buddies(gc, buddies, groups);
		else {
			GList *curb = buddies;
			GList *curg = groups;
			while ((curb != NULL) && (curg != NULL)) {
				purple_account_remove_buddy(account, curb->data, curg->data);
				curb = curb->next;
				curg = curg->next;
			}
		}
	}
}

void
purple_account_remove_group(PurpleAccount *account, PurpleGroup *group)
{
	PurplePluginProtocolInfo *prpl_info = NULL;
	PurpleConnection *gc = purple_account_get_connection(account);
	PurplePlugin *prpl = NULL;

	if (gc != NULL)
		prpl = purple_connection_get_prpl(gc);

	if (prpl != NULL)
		prpl_info = PURPLE_PLUGIN_PROTOCOL_INFO(prpl);

	if (prpl_info && prpl_info->remove_group)
		prpl_info->remove_group(gc, group);
}

void
purple_account_change_password(PurpleAccount *account, const char *orig_pw,
		const char *new_pw)
{
	PurplePluginProtocolInfo *prpl_info = NULL;
	PurpleConnection *gc = purple_account_get_connection(account);
	PurplePlugin *prpl = NULL;

	purple_account_set_password(account, new_pw);

	if (gc != NULL)
		prpl = purple_connection_get_prpl(gc);

	if (prpl != NULL)
		prpl_info = PURPLE_PLUGIN_PROTOCOL_INFO(prpl);

	if (prpl_info && prpl_info->change_passwd)
		prpl_info->change_passwd(gc, orig_pw, new_pw);
}

gboolean purple_account_supports_offline_message(PurpleAccount *account, PurpleBuddy *buddy)
{
	PurpleConnection *gc;
	PurplePluginProtocolInfo *prpl_info = NULL;
	PurplePlugin *prpl = NULL;

	g_return_val_if_fail(account, FALSE);
	g_return_val_if_fail(buddy, FALSE);

	gc = purple_account_get_connection(account);
	if (gc == NULL)
		return FALSE;

	prpl = purple_connection_get_prpl(gc);

	if (prpl != NULL)
		prpl_info = PURPLE_PLUGIN_PROTOCOL_INFO(prpl);

	if (!prpl_info || !prpl_info->offline_message)
		return FALSE;
	return prpl_info->offline_message(buddy);
}

static void
signed_on_cb(PurpleConnection *gc,
             gpointer unused)
{
	PurpleAccount *account = purple_connection_get_account(gc);
	purple_account_clear_current_error(account);

	purple_signal_emit(purple_accounts_get_handle(), "account-signed-on",
	                   account);
}

static void
signed_off_cb(PurpleConnection *gc,
              gpointer unused)
{
	PurpleAccount *account = purple_connection_get_account(gc);

	purple_signal_emit(purple_accounts_get_handle(), "account-signed-off",
	                   account);
}

static void
set_current_error(PurpleAccount *account, PurpleConnectionErrorInfo *new_err)
{
	PurpleAccountPrivate *priv;
	PurpleConnectionErrorInfo *old_err;

	g_return_if_fail(account != NULL);

	priv = PURPLE_ACCOUNT_GET_PRIVATE(account);
	old_err = priv->current_error;

	if(new_err == old_err)
		return;

	priv->current_error = new_err;

	purple_signal_emit(purple_accounts_get_handle(),
	                   "account-error-changed",
	                   account, old_err, new_err);
	schedule_accounts_save();

	if(old_err)
		g_free(old_err->description);

	PURPLE_DBUS_UNREGISTER_POINTER(old_err);
	g_free(old_err);
}

static void
connection_error_cb(PurpleConnection *gc,
                    PurpleConnectionError type,
                    const gchar *description,
                    gpointer unused)
{
	PurpleAccount *account;
	PurpleConnectionErrorInfo *err;

	account = purple_connection_get_account(gc);

	g_return_if_fail(account != NULL);

	err = g_new0(PurpleConnectionErrorInfo, 1);
	PURPLE_DBUS_REGISTER_POINTER(err, PurpleConnectionErrorInfo);

	err->type = type;
	err->description = g_strdup(description);

	set_current_error(account, err);

	purple_signal_emit(purple_accounts_get_handle(), "account-connection-error",
	                   account, type, description);
}

const PurpleConnectionErrorInfo *
purple_account_get_current_error(PurpleAccount *account)
{
	PurpleAccountPrivate *priv = PURPLE_ACCOUNT_GET_PRIVATE(account);
	return priv->current_error;
}

void
purple_account_clear_current_error(PurpleAccount *account)
{
	set_current_error(account, NULL);
}

void
purple_accounts_add(PurpleAccount *account)
{
	g_return_if_fail(account != NULL);

	if (g_list_find(accounts, account) != NULL)
		return;

	accounts = g_list_append(accounts, account);

	schedule_accounts_save();

	purple_signal_emit(purple_accounts_get_handle(), "account-added", account);
}

void
purple_accounts_remove(PurpleAccount *account)
{
	g_return_if_fail(account != NULL);

	accounts = g_list_remove(accounts, account);

	schedule_accounts_save();

	/* Clearing the error ensures that account-error-changed is emitted,
	 * which is the end of the guarantee that the the error's pointer is
	 * valid.
	 */
	purple_account_clear_current_error(account);
	purple_signal_emit(purple_accounts_get_handle(), "account-removed", account);
}

void
purple_accounts_delete(PurpleAccount *account)
{
	PurpleBlistNode *gnode, *cnode, *bnode;
	GList *iter;

	g_return_if_fail(account != NULL);

	/*
	 * Disable the account before blowing it out of the water.
	 * Conceptually it probably makes more sense to disable the
	 * account for all UIs rather than the just the current UI,
	 * but it doesn't really matter.
	 */
	purple_account_set_enabled(account, purple_core_get_ui(), FALSE);

	purple_notify_close_with_handle(account);
	purple_request_close_with_handle(account);

	purple_accounts_remove(account);

	/* Remove this account's buddies */
	for (gnode = purple_blist_get_root();
	     gnode != NULL;
		 gnode = purple_blist_node_get_sibling_next(gnode))
	{
		if (!PURPLE_BLIST_NODE_IS_GROUP(gnode))
			continue;

		cnode = purple_blist_node_get_first_child(gnode);
		while (cnode) {
			PurpleBlistNode *cnode_next = purple_blist_node_get_sibling_next(cnode);

			if(PURPLE_BLIST_NODE_IS_CONTACT(cnode)) {
				bnode = purple_blist_node_get_first_child(cnode);
				while (bnode) {
					PurpleBlistNode *bnode_next = purple_blist_node_get_sibling_next(bnode);

					if (PURPLE_BLIST_NODE_IS_BUDDY(bnode)) {
						PurpleBuddy *b = (PurpleBuddy *)bnode;

						if (purple_buddy_get_account(b) == account)
							purple_blist_remove_buddy(b);
					}
					bnode = bnode_next;
				}
			} else if (PURPLE_BLIST_NODE_IS_CHAT(cnode)) {
				PurpleChat *c = (PurpleChat *)cnode;

				if (purple_chat_get_account(c) == account)
					purple_blist_remove_chat(c);
			}
			cnode = cnode_next;
		}
	}

	/* Remove any open conversation for this account */
	for (iter = purple_get_conversations(); iter; ) {
		PurpleConversation *conv = iter->data;
		iter = iter->next;
		if (purple_conversation_get_account(conv) == account)
			purple_conversation_destroy(conv);
	}

	/* Remove this account's pounces */
	purple_pounce_destroy_all_by_account(account);

	/* This will cause the deletion of an old buddy icon. */
	purple_buddy_icons_set_account_icon(account, NULL, 0);

	purple_account_destroy(account);
}

void
purple_accounts_reorder(PurpleAccount *account, gint new_index)
{
	gint index;
	GList *l;

	g_return_if_fail(account != NULL);
	g_return_if_fail(new_index <= g_list_length(accounts));

	index = g_list_index(accounts, account);

	if (index == -1) {
		purple_debug_error("account",
				   "Unregistered account (%s) discovered during reorder!\n",
				   purple_account_get_username(account));
		return;
	}

	l = g_list_nth(accounts, index);

	if (new_index > index)
		new_index--;

	/* Remove the old one. */
	accounts = g_list_delete_link(accounts, l);

	/* Insert it where it should go. */
	accounts = g_list_insert(accounts, account, new_index);

	schedule_accounts_save();
}

GList *
purple_accounts_get_all(void)
{
	return accounts;
}

GList *
purple_accounts_get_all_active(void)
{
	GList *list = NULL;
	GList *all = purple_accounts_get_all();

	while (all != NULL) {
		PurpleAccount *account = all->data;

		if (purple_account_get_enabled(account, purple_core_get_ui()))
			list = g_list_append(list, account);

		all = all->next;
	}

	return list;
}

PurpleAccount *
purple_accounts_find(const char *name, const char *protocol_id)
{
	PurpleAccount *account = NULL;
	GList *l;
	char *who;

	g_return_val_if_fail(name != NULL, NULL);
	g_return_val_if_fail(protocol_id != NULL, NULL);

	for (l = purple_accounts_get_all(); l != NULL; l = l->next) {
		account = (PurpleAccount *)l->data;
		if (!purple_strequal(account->protocol_id, protocol_id))
			continue;

		who = g_strdup(purple_normalize(account, name));
		if (purple_strequal(purple_normalize(account, purple_account_get_username(account)), who)) {
			g_free(who);
			return account;
		}
		g_free(who);
	}

	return NULL;
}

void
purple_accounts_restore_current_statuses()
{
	GList *l;
	PurpleAccount *account;

	/* If we're not connected to the Internet right now, we bail on this */
	if (!purple_network_is_available())
	{
		purple_debug_warning("account", "Network not connected; skipping reconnect\n");
		return;
	}

	for (l = purple_accounts_get_all(); l != NULL; l = l->next)
	{
		account = (PurpleAccount *)l->data;
		if (purple_account_get_enabled(account, purple_core_get_ui()) &&
			(purple_presence_is_online(account->presence)))
		{
			purple_account_connect(account);
		}
	}
}

void
purple_accounts_set_ui_ops(PurpleAccountUiOps *ops)
{
	account_ui_ops = ops;
}

PurpleAccountUiOps *
purple_accounts_get_ui_ops(void)
{
	return account_ui_ops;
}

void *
purple_accounts_get_handle(void)
{
	static int handle;

	return &handle;
}

void
purple_accounts_init(void)
{
	void *handle = purple_accounts_get_handle();
	void *conn_handle = purple_connections_get_handle();

	purple_signal_register(handle, "account-connecting",
						 purple_marshal_VOID__POINTER, NULL, 1,
						 purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_ACCOUNT));

	purple_signal_register(handle, "account-disabled",
						 purple_marshal_VOID__POINTER, NULL, 1,
						 purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_ACCOUNT));

	purple_signal_register(handle, "account-enabled",
						 purple_marshal_VOID__POINTER, NULL, 1,
						 purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_ACCOUNT));

	purple_signal_register(handle, "account-setting-info",
						 purple_marshal_VOID__POINTER_POINTER, NULL, 2,
						 purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_ACCOUNT),
						 purple_value_new(PURPLE_TYPE_STRING));

	purple_signal_register(handle, "account-set-info",
						 purple_marshal_VOID__POINTER_POINTER, NULL, 2,
						 purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_ACCOUNT),
						 purple_value_new(PURPLE_TYPE_STRING));

	purple_signal_register(handle, "account-created",
						 purple_marshal_VOID__POINTER, NULL, 1,
						 purple_value_new(PURPLE_TYPE_SUBTYPE, PURPLE_SUBTYPE_ACCOUNT));

	purple_signal_register(handle, "account-destroying",
						 purple_marshal_VOID__POINTER, NULL, 1,
						 purple_value_new(PURPLE_TYPE_SUBTYPE, PURPLE_SUBTYPE_ACCOUNT));

	purple_signal_register(handle, "account-added",
						 purple_marshal_VOID__POINTER, NULL, 1,
						 purple_value_new(PURPLE_TYPE_SUBTYPE, PURPLE_SUBTYPE_ACCOUNT));

	purple_signal_register(handle, "account-removed",
						 purple_marshal_VOID__POINTER, NULL, 1,
						 purple_value_new(PURPLE_TYPE_SUBTYPE, PURPLE_SUBTYPE_ACCOUNT));

	purple_signal_register(handle, "account-status-changed",
						 purple_marshal_VOID__POINTER_POINTER_POINTER, NULL, 3,
						 purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_ACCOUNT),
						 purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_STATUS),
						 purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_STATUS));

	purple_signal_register(handle, "account-actions-changed",
						 purple_marshal_VOID__POINTER, NULL, 1,
						 purple_value_new(PURPLE_TYPE_SUBTYPE, PURPLE_SUBTYPE_ACCOUNT));

	purple_signal_register(handle, "account-alias-changed",
						 purple_marshal_VOID__POINTER_POINTER, NULL, 2,
						 purple_value_new(PURPLE_TYPE_SUBTYPE,
							 			PURPLE_SUBTYPE_ACCOUNT),
						 purple_value_new(PURPLE_TYPE_STRING));

	purple_signal_register(handle, "account-authorization-requested",
						purple_marshal_INT__POINTER_POINTER,
						purple_value_new(PURPLE_TYPE_INT), 2,
						purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_ACCOUNT),
						purple_value_new(PURPLE_TYPE_STRING));

	purple_signal_register(handle, "account-authorization-requested-with-message",
						purple_marshal_INT__POINTER_POINTER_POINTER,
						purple_value_new(PURPLE_TYPE_INT), 3,
						purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_ACCOUNT),
						purple_value_new(PURPLE_TYPE_STRING),
						purple_value_new(PURPLE_TYPE_STRING));
	purple_signal_register(handle, "account-authorization-denied",
						purple_marshal_VOID__POINTER_POINTER, NULL, 2,
						purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_ACCOUNT),
						purple_value_new(PURPLE_TYPE_STRING));

	purple_signal_register(handle, "account-authorization-granted",
						purple_marshal_VOID__POINTER_POINTER, NULL, 2,
						purple_value_new(PURPLE_TYPE_SUBTYPE,
										PURPLE_SUBTYPE_ACCOUNT),
						purple_value_new(PURPLE_TYPE_STRING));

	purple_signal_register(handle, "account-error-changed",
	                       purple_marshal_VOID__POINTER_POINTER_POINTER,
	                       NULL, 3,
	                       purple_value_new(PURPLE_TYPE_SUBTYPE,
	                                        PURPLE_SUBTYPE_ACCOUNT),
	                       purple_value_new(PURPLE_TYPE_POINTER),
	                       purple_value_new(PURPLE_TYPE_POINTER));

	purple_signal_register(handle, "account-signed-on",
	                       purple_marshal_VOID__POINTER, NULL, 1,
	                       purple_value_new(PURPLE_TYPE_SUBTYPE,
	                                        PURPLE_SUBTYPE_ACCOUNT));

	purple_signal_register(handle, "account-signed-off",
	                       purple_marshal_VOID__POINTER, NULL, 1,
	                       purple_value_new(PURPLE_TYPE_SUBTYPE,
	                                        PURPLE_SUBTYPE_ACCOUNT));

	purple_signal_register(handle, "account-connection-error",
	                       purple_marshal_VOID__POINTER_INT_POINTER, NULL, 3,
	                       purple_value_new(PURPLE_TYPE_SUBTYPE,
	                                        PURPLE_SUBTYPE_ACCOUNT),
	                       purple_value_new(PURPLE_TYPE_ENUM),
	                       purple_value_new(PURPLE_TYPE_STRING));

	purple_signal_connect(conn_handle, "signed-on", handle,
	                      PURPLE_CALLBACK(signed_on_cb), NULL);
	purple_signal_connect(conn_handle, "signed-off", handle,
	                      PURPLE_CALLBACK(signed_off_cb), NULL);
	purple_signal_connect(conn_handle, "connection-error", handle,
	                      PURPLE_CALLBACK(connection_error_cb), NULL);

	load_accounts();

}

void
purple_accounts_uninit(void)
{
	gpointer handle = purple_accounts_get_handle();
	if (save_timer != 0)
	{
		purple_timeout_remove(save_timer);
		save_timer = 0;
		sync_accounts();
	}

	for (; accounts; accounts = g_list_delete_link(accounts, accounts))
		purple_account_destroy(accounts->data);

	purple_signals_disconnect_by_handle(handle);
	purple_signals_unregister_by_instance(handle);
}
