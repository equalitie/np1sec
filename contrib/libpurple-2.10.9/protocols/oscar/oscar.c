/*
 * purple
 *
 * Some code copyright (C) 1998-1999, Mark Spencer <markster@marko.net>
 * Some code copyright (C) 1999-2001, Eric Warmenhoven
 * Some code copyright (C) 2001-2003, Sean Egan
 * Some code copyright (C) 2001-2007, Mark Doliner <thekingant@users.sourceforge.net>
 * Some code copyright (C) 2005, Jonathan Clark <ardentlygnarly@users.sourceforge.net>
 * Some code copyright (C) 2007, ComBOTS Product GmbH (htfv) <foss@combots.com>
 * Some code copyright (C) 2008, Aman Gupta
 *
 * Most libfaim code copyright (C) 1998-2001 Adam Fritzler <afritz@auk.cx>
 * Some libfaim code copyright (C) 2001-2004 Mark Doliner <thekingant@users.sourceforge.net>
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

#include "account.h"
#include "accountopt.h"
#include "buddyicon.h"
#include "cipher.h"
#include "conversation.h"
#include "core.h"
#include "debug.h"
#include "encoding.h"
#include "imgstore.h"
#include "network.h"
#include "notify.h"
#include "privacy.h"
#include "prpl.h"
#include "proxy.h"
#include "request.h"
#include "util.h"
#include "version.h"
#include "visibility.h"

#include "oscarcommon.h"
#include "oscar.h"
#include "peer.h"

#define AIMHASHDATA "http://pidgin.im/aim_data.php3"

#define OSCAR_CONNECT_STEPS 6

static guint64 purple_caps =
	OSCAR_CAPABILITY_CHAT
		| OSCAR_CAPABILITY_BUDDYICON
		| OSCAR_CAPABILITY_DIRECTIM
		| OSCAR_CAPABILITY_SENDFILE
		| OSCAR_CAPABILITY_UNICODE
		| OSCAR_CAPABILITY_INTEROPERATE
		| OSCAR_CAPABILITY_SHORTCAPS
		| OSCAR_CAPABILITY_TYPING
		| OSCAR_CAPABILITY_ICQSERVERRELAY
		| OSCAR_CAPABILITY_NEWCAPS
		| OSCAR_CAPABILITY_XTRAZ
		| OSCAR_CAPABILITY_HTML_MSGS;

static guint8 features_aim[] = {0x01, 0x01, 0x01, 0x02};
static guint8 features_icq[] = {0x01};

struct create_room {
	char *name;
	int exchange;
};

struct oscar_ask_directim_data
{
	OscarData *od;
	char *who;
};

/* All the libfaim->purple callback functions */

/* Only used when connecting with the old-style BUCP login */
static int purple_parse_auth_resp  (OscarData *, FlapConnection *, FlapFrame *, ...);
static int purple_parse_login      (OscarData *, FlapConnection *, FlapFrame *, ...);
static int purple_parse_auth_securid_request(OscarData *, FlapConnection *, FlapFrame *, ...);

static int purple_handle_redirect  (OscarData *, FlapConnection *, FlapFrame *, ...);
static int purple_info_change      (OscarData *, FlapConnection *, FlapFrame *, ...);
static int purple_account_confirm  (OscarData *, FlapConnection *, FlapFrame *, ...);
static int purple_parse_oncoming   (OscarData *, FlapConnection *, FlapFrame *, ...);
static int purple_parse_offgoing   (OscarData *, FlapConnection *, FlapFrame *, ...);
static int purple_parse_incoming_im(OscarData *, FlapConnection *, FlapFrame *, ...);
static int purple_parse_misses     (OscarData *, FlapConnection *, FlapFrame *, ...);
static int purple_parse_clientauto (OscarData *, FlapConnection *, FlapFrame *, ...);
static int purple_parse_motd       (OscarData *, FlapConnection *, FlapFrame *, ...);
static int purple_chatnav_info     (OscarData *, FlapConnection *, FlapFrame *, ...);
static int purple_conv_chat_join        (OscarData *, FlapConnection *, FlapFrame *, ...);
static int purple_conv_chat_leave       (OscarData *, FlapConnection *, FlapFrame *, ...);
static int purple_conv_chat_info_update (OscarData *, FlapConnection *, FlapFrame *, ...);
static int purple_conv_chat_incoming_msg(OscarData *, FlapConnection *, FlapFrame *, ...);
static int purple_email_parseupdate(OscarData *, FlapConnection *, FlapFrame *, ...);
static int purple_icon_parseicon   (OscarData *, FlapConnection *, FlapFrame *, ...);
static int purple_parse_searcherror(OscarData *, FlapConnection *, FlapFrame *, ...);
static int purple_parse_searchreply(OscarData *, FlapConnection *, FlapFrame *, ...);
static int purple_bosrights        (OscarData *, FlapConnection *, FlapFrame *, ...);
static int purple_connerr          (OscarData *, FlapConnection *, FlapFrame *, ...);
static int purple_parse_mtn        (OscarData *, FlapConnection *, FlapFrame *, ...);
static int purple_parse_locaterights(OscarData *, FlapConnection *, FlapFrame *, ...);
static int purple_parse_buddyrights(OscarData *, FlapConnection *, FlapFrame *, ...);
static int purple_parse_genericerr (OscarData *, FlapConnection *, FlapFrame *, ...);
static int purple_memrequest       (OscarData *, FlapConnection *, FlapFrame *, ...);
static int purple_selfinfo         (OscarData *, FlapConnection *, FlapFrame *, ...);
static int purple_popup            (OscarData *, FlapConnection *, FlapFrame *, ...);
static int purple_ssi_parseerr     (OscarData *, FlapConnection *, FlapFrame *, ...);
static int purple_ssi_parserights  (OscarData *, FlapConnection *, FlapFrame *, ...);
static int purple_ssi_parselist    (OscarData *, FlapConnection *, FlapFrame *, ...);
static int purple_ssi_parseack     (OscarData *, FlapConnection *, FlapFrame *, ...);
static int purple_ssi_parseaddmod  (OscarData *, FlapConnection *, FlapFrame *, ...);
static int purple_ssi_authgiven    (OscarData *, FlapConnection *, FlapFrame *, ...);
static int purple_ssi_authrequest  (OscarData *, FlapConnection *, FlapFrame *, ...);
static int purple_ssi_authreply    (OscarData *, FlapConnection *, FlapFrame *, ...);
static int purple_ssi_gotadded     (OscarData *, FlapConnection *, FlapFrame *, ...);

static void purple_icons_fetch(PurpleConnection *gc);

void oscar_set_info(PurpleConnection *gc, const char *info);
static void oscar_set_info_and_status(PurpleAccount *account, gboolean setinfo, const char *rawinfo, gboolean setstatus, PurpleStatus *status);
static void oscar_set_extended_status(PurpleConnection *gc);
static gboolean purple_ssi_rerequestdata(gpointer data);

void oscar_free_name_data(struct name_data *data) {
	g_free(data->name);
	g_free(data->nick);
	g_free(data);
}

#ifdef _WIN32
const char *oscar_get_locale_charset(void) {
	static const char *charset = NULL;
	if (charset == NULL)
		g_get_charset(&charset);
	return charset;
}
#endif

static char *oscar_icqstatus(int state) {
	/* Make a cute little string that shows the status of the dude or dudet */
	if (state & AIM_ICQ_STATE_CHAT)
		return g_strdup(_("Free For Chat"));
	else if (state & AIM_ICQ_STATE_DND)
		return g_strdup(_("Do Not Disturb"));
	else if (state & AIM_ICQ_STATE_OUT)
		return g_strdup(_("Not Available"));
	else if (state & AIM_ICQ_STATE_BUSY)
		return g_strdup(_("Occupied"));
	else if (state & AIM_ICQ_STATE_AWAY)
		return g_strdup(_("Away"));
	else if (state & AIM_ICQ_STATE_WEBAWARE)
		return g_strdup(_("Web Aware"));
	else if (state & AIM_ICQ_STATE_INVISIBLE)
		return g_strdup(_("Invisible"));
	else if (state & AIM_ICQ_STATE_EVIL)
		return g_strdup(_("Evil"));
	else if (state & AIM_ICQ_STATE_DEPRESSION)
		return g_strdup(_("Depression"));
	else if (state & AIM_ICQ_STATE_ATHOME)
		return g_strdup(_("At home"));
	else if (state & AIM_ICQ_STATE_ATWORK)
		return g_strdup(_("At work"));
	else if (state & AIM_ICQ_STATE_LUNCH)
		return g_strdup(_("At lunch"));
	else
		return g_strdup(_("Online"));
}

static char *extract_name(const char *name) {
	char *tmp, *x;
	int i, j;

	if (!name)
		return NULL;

	x = strchr(name, '-');
	if (!x)
		return NULL;

	x = strchr(x + 1, '-');
	if (!x)
		return NULL;

	tmp = g_strdup(++x);

	for (i = 0, j = 0; x[i]; i++) {
		char hex[3];
		if (x[i] != '%') {
			tmp[j++] = x[i];
			continue;
		}
		strncpy(hex, x + ++i, 2);
		hex[2] = 0;
		i++;
		tmp[j++] = strtol(hex, NULL, 16);
	}

	tmp[j] = 0;
	return tmp;
}

static struct chat_connection *
find_oscar_chat(PurpleConnection *gc, int id)
{
	OscarData *od = purple_connection_get_protocol_data(gc);
	GSList *cur;
	struct chat_connection *cc;

	for (cur = od->oscar_chats; cur != NULL; cur = cur->next)
	{
		cc = (struct chat_connection *)cur->data;
		if (cc->id == id)
			return cc;
	}

	return NULL;
}

static struct chat_connection *
find_oscar_chat_by_conn(PurpleConnection *gc, FlapConnection *conn)
{
	OscarData *od = purple_connection_get_protocol_data(gc);
	GSList *cur;
	struct chat_connection *cc;

	for (cur = od->oscar_chats; cur != NULL; cur = cur->next)
	{
		cc = (struct chat_connection *)cur->data;
		if (cc->conn == conn)
			return cc;
	}

	return NULL;
}

static struct chat_connection *
find_oscar_chat_by_conv(PurpleConnection *gc, PurpleConversation *conv)
{
	OscarData *od = purple_connection_get_protocol_data(gc);
	GSList *cur;
	struct chat_connection *cc;

	for (cur = od->oscar_chats; cur != NULL; cur = cur->next)
	{
		cc = (struct chat_connection *)cur->data;
		if (cc->conv == conv)
			return cc;
	}

	return NULL;
}

void
oscar_chat_destroy(struct chat_connection *cc)
{
	g_free(cc->name);
	g_free(cc->show);
	g_free(cc);
}

static void
oscar_chat_kill(PurpleConnection *gc, struct chat_connection *cc)
{
	OscarData *od = purple_connection_get_protocol_data(gc);

	/* Notify the conversation window that we've left the chat */
	serv_got_chat_left(gc, purple_conv_chat_get_id(PURPLE_CONV_CHAT(cc->conv)));

	/* Destroy the chat_connection */
	od->oscar_chats = g_slist_remove(od->oscar_chats, cc);
	oscar_chat_destroy(cc);
}

/**
 * This is called from the callback functions for establishing
 * a TCP connection with an oscar host if an error occurred.
 */
static void
connection_common_error_cb(FlapConnection *conn, const gchar *error_message)
{
	OscarData *od;
	PurpleConnection *gc;

	od = conn->od;
	gc = od->gc;

	purple_debug_error("oscar", "unable to connect to FLAP "
			"server of type 0x%04hx\n", conn->type);

	if (conn->type == SNAC_FAMILY_AUTH)
	{
		/* This only happens when connecting with the old-style BUCP login */
		gchar *msg;
		msg = g_strdup_printf(_("Unable to connect to authentication server: %s"),
				error_message);
		purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, msg);
		g_free(msg);
	}
	else if (conn->type == SNAC_FAMILY_LOCATE)
	{
		gchar *msg;
		msg = g_strdup_printf(_("Unable to connect to BOS server: %s"),
				error_message);
		purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, msg);
		g_free(msg);
	}
	else
	{
		/* Maybe we should call this for BOS connections, too? */
		flap_connection_schedule_destroy(conn,
				OSCAR_DISCONNECT_COULD_NOT_CONNECT, error_message);
	}
}

/**
 * This is called from the callback functions for establishing
 * a TCP connection with an oscar host. Depending on the type
 * of host, we do a few different things here.
 */
static void
connection_common_established_cb(FlapConnection *conn)
{
	OscarData *od;
	PurpleConnection *gc;
	PurpleAccount *account;

	od = conn->od;
	gc = od->gc;
	account = purple_connection_get_account(gc);

	purple_debug_info("oscar", "connected to FLAP server of type 0x%04hx\n",
			conn->type);

	if (conn->cookie == NULL)
		flap_connection_send_version(od, conn);
	else
	{
		if (purple_account_get_bool(account, "use_clientlogin", OSCAR_DEFAULT_USE_CLIENTLOGIN))
		{
			ClientInfo aiminfo = CLIENTINFO_PURPLE_AIM;
			ClientInfo icqinfo = CLIENTINFO_PURPLE_ICQ;
			flap_connection_send_version_with_cookie_and_clientinfo(od,
					conn, conn->cookielen, conn->cookie,
					od->icq ? &icqinfo : &aiminfo,
					purple_account_get_bool(account, "allow_multiple_logins", OSCAR_DEFAULT_ALLOW_MULTIPLE_LOGINS));
		} else {
			flap_connection_send_version_with_cookie(od, conn,
					conn->cookielen, conn->cookie);
		}


		g_free(conn->cookie);
		conn->cookie = NULL;
	}

	if (conn->type == SNAC_FAMILY_AUTH)
	{
		/* This only happens when connecting with the old-style BUCP login */
		aim_request_login(od, conn, purple_account_get_username(account));
		purple_debug_info("oscar", "Username sent, waiting for response\n");
		purple_connection_update_progress(gc, _("Username sent"), 1, OSCAR_CONNECT_STEPS);
	}
	else if (conn->type == SNAC_FAMILY_LOCATE)
	{
		purple_connection_update_progress(gc, _("Connection established, cookie sent"), 4, OSCAR_CONNECT_STEPS);
	}
	else if (conn->type == SNAC_FAMILY_CHAT)
	{
		od->oscar_chats = g_slist_prepend(od->oscar_chats, conn->new_conn_data);
		conn->new_conn_data = NULL;
	}
}

static void
connection_established_cb(gpointer data, gint source, const gchar *error_message)
{
	FlapConnection *conn;

	conn = data;

	conn->connect_data = NULL;
	conn->fd = source;

	if (source < 0)
	{
		connection_common_error_cb(conn, error_message);
		return;
	}

	conn->watcher_incoming = purple_input_add(conn->fd,
			PURPLE_INPUT_READ, flap_connection_recv_cb, conn);
	connection_common_established_cb(conn);
}

static void
ssl_connection_established_cb(gpointer data, PurpleSslConnection *gsc,
		PurpleInputCondition cond)
{
	FlapConnection *conn;

	conn = data;

	purple_ssl_input_add(gsc, flap_connection_recv_cb_ssl, conn);
	connection_common_established_cb(conn);
}

static void
ssl_connection_error_cb(PurpleSslConnection *gsc, PurpleSslErrorType error,
		gpointer data)
{
	FlapConnection *conn;

	conn = data;

	if (conn->watcher_outgoing)
	{
		purple_input_remove(conn->watcher_outgoing);
		conn->watcher_outgoing = 0;
	}

	/* sslconn frees the connection on error */
	conn->gsc = NULL;

	connection_common_error_cb(conn, purple_ssl_strerror(error));
}

static void
flap_connection_established_bos(OscarData *od, FlapConnection *conn)
{
	PurpleConnection *gc = od->gc;

	aim_srv_reqpersonalinfo(od, conn);

	purple_debug_info("oscar", "ssi: requesting rights and list\n");
	aim_ssi_reqrights(od);
	aim_ssi_reqdata(od);
	if (od->getblisttimer > 0)
		purple_timeout_remove(od->getblisttimer);
	od->getblisttimer = purple_timeout_add_seconds(30, purple_ssi_rerequestdata, od);

	aim_locate_reqrights(od);
	aim_buddylist_reqrights(od, conn);
	aim_im_reqparams(od);
	aim_bos_reqrights(od, conn); /* TODO: Don't call this with ssi */

	purple_connection_update_progress(gc, _("Finalizing connection"), 5, OSCAR_CONNECT_STEPS);
}

static void
flap_connection_established_admin(OscarData *od, FlapConnection *conn)
{
	aim_srv_clientready(od, conn);
	purple_debug_info("oscar", "connected to admin\n");

	if (od->chpass) {
		purple_debug_info("oscar", "changing password\n");
		aim_admin_changepasswd(od, conn, od->newp, od->oldp);
		g_free(od->oldp);
		od->oldp = NULL;
		g_free(od->newp);
		od->newp = NULL;
		od->chpass = FALSE;
	}
	if (od->setnick) {
		purple_debug_info("oscar", "formatting username\n");
		aim_admin_setnick(od, conn, od->newformatting);
		g_free(od->newformatting);
		od->newformatting = NULL;
		od->setnick = FALSE;
	}
	if (od->conf) {
		purple_debug_info("oscar", "confirming account\n");
		aim_admin_reqconfirm(od, conn);
		od->conf = FALSE;
	}
	if (od->reqemail) {
		purple_debug_info("oscar", "requesting email address\n");
		aim_admin_getinfo(od, conn, 0x0011);
		od->reqemail = FALSE;
	}
	if (od->setemail) {
		purple_debug_info("oscar", "setting email address\n");
		aim_admin_setemail(od, conn, od->email);
		g_free(od->email);
		od->email = NULL;
		od->setemail = FALSE;
	}
}

static void
flap_connection_established_chat(OscarData *od, FlapConnection *conn)
{
	PurpleConnection *gc = od->gc;
	struct chat_connection *chatcon;
	static int id = 1;

	aim_srv_clientready(od, conn);

	chatcon = find_oscar_chat_by_conn(gc, conn);
	if (chatcon) {
		chatcon->id = id;
		chatcon->conv = serv_got_joined_chat(gc, id++, chatcon->show);
	}
}

static void
flap_connection_established_chatnav(OscarData *od, FlapConnection *conn)
{
	aim_srv_clientready(od, conn);
	aim_chatnav_reqrights(od, conn);
}

static void
flap_connection_established_alert(OscarData *od, FlapConnection *conn)
{
	aim_email_sendcookies(od);
	aim_email_activate(od);
	aim_srv_clientready(od, conn);
}

static void
flap_connection_established_bart(OscarData *od, FlapConnection *conn)
{
	PurpleConnection *gc = od->gc;

	aim_srv_clientready(od, conn);

	od->iconconnecting = FALSE;

	purple_icons_fetch(gc);
}

static int
flap_connection_established(OscarData *od, FlapConnection *conn, FlapFrame *fr, ...)
{
	purple_debug_info("oscar", "FLAP connection of type 0x%04hx is "
			"now fully connected\n", conn->type);
	if (conn->type == SNAC_FAMILY_LOCATE)
		flap_connection_established_bos(od, conn);
	else if (conn->type == SNAC_FAMILY_ADMIN)
		flap_connection_established_admin(od, conn);
	else if (conn->type == SNAC_FAMILY_CHAT)
		flap_connection_established_chat(od, conn);
	else if (conn->type == SNAC_FAMILY_CHATNAV)
		flap_connection_established_chatnav(od, conn);
	else if (conn->type == SNAC_FAMILY_ALERT)
		flap_connection_established_alert(od, conn);
	else if (conn->type == SNAC_FAMILY_BART)
		flap_connection_established_bart(od, conn);

	return 1;
}

static void
idle_reporting_pref_cb(const char *name, PurplePrefType type,
		gconstpointer value, gpointer data)
{
	PurpleConnection *gc;
	OscarData *od;
	gboolean report_idle;
	guint32 presence;

	gc = data;
	od = purple_connection_get_protocol_data(gc);
	report_idle = strcmp((const char *)value, "none") != 0;
	presence = aim_ssi_getpresence(od->ssi.local);

	if (report_idle)
		aim_ssi_setpresence(od, presence | AIM_SSI_PRESENCE_FLAG_SHOWIDLE);
	else
		aim_ssi_setpresence(od, presence & ~AIM_SSI_PRESENCE_FLAG_SHOWIDLE);
}

/**
 * Should probably make a "Use recent buddies group" account preference
 * so that this option is surfaced to the user.
 */
static void
recent_buddies_pref_cb(const char *name, PurplePrefType type,
		gconstpointer value, gpointer data)
{
	PurpleConnection *gc;
	OscarData *od;
	guint32 presence;

	gc = data;
	od = purple_connection_get_protocol_data(gc);
	presence = aim_ssi_getpresence(od->ssi.local);

	if (value)
		aim_ssi_setpresence(od, presence & ~AIM_SSI_PRESENCE_FLAG_NORECENTBUDDIES);
	else
		aim_ssi_setpresence(od, presence | AIM_SSI_PRESENCE_FLAG_NORECENTBUDDIES);
}

static const gchar *login_servers[] = {
	AIM_DEFAULT_LOGIN_SERVER,
	AIM_DEFAULT_SSL_LOGIN_SERVER,
	ICQ_DEFAULT_LOGIN_SERVER,
	ICQ_DEFAULT_SSL_LOGIN_SERVER,
};

static const gchar *
get_login_server(gboolean is_icq, gboolean use_ssl)
{
	return login_servers[(is_icq ? 2 : 0) + (use_ssl ? 1 : 0)];
}

static gint
compare_handlers(gconstpointer a, gconstpointer b)
{
	guint aa = GPOINTER_TO_UINT(a);
	guint bb = GPOINTER_TO_UINT(b);
	guint family1 = aa >> 16;
	guint family2 = bb >> 16;
	guint subtype1 = aa & 0xFFFF;
	guint subtype2 = bb & 0xFFFF;
	if (family1 != family2) {
		return family1 - family2;
	}
	return subtype1 - subtype2;
}

#if !GLIB_CHECK_VERSION(2,14,0)
static void hash_table_get_list_of_keys(gpointer key, gpointer value, gpointer user_data)
{
	GList **handlers = (GList **)user_data;

	*handlers = g_list_prepend(*handlers, key);
}
#endif /* GLIB < 2.14.0 */

void
oscar_login(PurpleAccount *account)
{
	PurpleConnection *gc;
	OscarData *od;
	const gchar *encryption_type;
	GList *handlers;
	GList *sorted_handlers;
	GList *cur;
	GString *msg = g_string_new("");

	gc = purple_account_get_connection(account);
	od = oscar_data_new();
	od->gc = gc;
	purple_connection_set_protocol_data(gc, od);

	oscar_data_addhandler(od, AIM_CB_FAM_SPECIAL, AIM_CB_SPECIAL_CONNERR, purple_connerr, 0);
	oscar_data_addhandler(od, AIM_CB_FAM_SPECIAL, AIM_CB_SPECIAL_CONNINITDONE, flap_connection_established, 0);

	oscar_data_addhandler(od, SNAC_FAMILY_ADMIN, 0x0003, purple_info_change, 0);
	oscar_data_addhandler(od, SNAC_FAMILY_ADMIN, 0x0005, purple_info_change, 0);
	oscar_data_addhandler(od, SNAC_FAMILY_ADMIN, 0x0007, purple_account_confirm, 0);
	oscar_data_addhandler(od, SNAC_FAMILY_ALERT, 0x0001, purple_parse_genericerr, 0);
	oscar_data_addhandler(od, SNAC_FAMILY_ALERT, SNAC_SUBTYPE_ALERT_MAILSTATUS, purple_email_parseupdate, 0);

	/* These are only needed when connecting with the old-style BUCP login */
	oscar_data_addhandler(od, SNAC_FAMILY_AUTH, 0x0003, purple_parse_auth_resp, 0);
	oscar_data_addhandler(od, SNAC_FAMILY_AUTH, 0x0007, purple_parse_login, 0);
	oscar_data_addhandler(od, SNAC_FAMILY_AUTH, SNAC_SUBTYPE_AUTH_SECURID_REQUEST, purple_parse_auth_securid_request, 0);

	oscar_data_addhandler(od, SNAC_FAMILY_BART, SNAC_SUBTYPE_BART_RESPONSE, purple_icon_parseicon, 0);
	oscar_data_addhandler(od, SNAC_FAMILY_BOS, 0x0001, purple_parse_genericerr, 0);
	oscar_data_addhandler(od, SNAC_FAMILY_BOS, 0x0003, purple_bosrights, 0);
	oscar_data_addhandler(od, SNAC_FAMILY_BUDDY, 0x0001, purple_parse_genericerr, 0);
	oscar_data_addhandler(od, SNAC_FAMILY_BUDDY, SNAC_SUBTYPE_BUDDY_RIGHTSINFO, purple_parse_buddyrights, 0);
	oscar_data_addhandler(od, SNAC_FAMILY_BUDDY, SNAC_SUBTYPE_BUDDY_ONCOMING, purple_parse_oncoming, 0);
	oscar_data_addhandler(od, SNAC_FAMILY_BUDDY, SNAC_SUBTYPE_BUDDY_OFFGOING, purple_parse_offgoing, 0);
	oscar_data_addhandler(od, SNAC_FAMILY_CHAT, 0x0001, purple_parse_genericerr, 0);
	oscar_data_addhandler(od, SNAC_FAMILY_CHAT, SNAC_SUBTYPE_CHAT_USERJOIN, purple_conv_chat_join, 0);
	oscar_data_addhandler(od, SNAC_FAMILY_CHAT, SNAC_SUBTYPE_CHAT_USERLEAVE, purple_conv_chat_leave, 0);
	oscar_data_addhandler(od, SNAC_FAMILY_CHAT, SNAC_SUBTYPE_CHAT_ROOMINFOUPDATE, purple_conv_chat_info_update, 0);
	oscar_data_addhandler(od, SNAC_FAMILY_CHAT, SNAC_SUBTYPE_CHAT_INCOMINGMSG, purple_conv_chat_incoming_msg, 0);
	oscar_data_addhandler(od, SNAC_FAMILY_CHATNAV, 0x0001, purple_parse_genericerr, 0);
	oscar_data_addhandler(od, SNAC_FAMILY_CHATNAV, SNAC_SUBTYPE_CHATNAV_INFO, purple_chatnav_info, 0);
	oscar_data_addhandler(od, SNAC_FAMILY_FEEDBAG, SNAC_SUBTYPE_FEEDBAG_ERROR, purple_ssi_parseerr, 0);
	oscar_data_addhandler(od, SNAC_FAMILY_FEEDBAG, SNAC_SUBTYPE_FEEDBAG_RIGHTSINFO, purple_ssi_parserights, 0);
	oscar_data_addhandler(od, SNAC_FAMILY_FEEDBAG, SNAC_SUBTYPE_FEEDBAG_LIST, purple_ssi_parselist, 0);
	oscar_data_addhandler(od, SNAC_FAMILY_FEEDBAG, SNAC_SUBTYPE_FEEDBAG_SRVACK, purple_ssi_parseack, 0);
	oscar_data_addhandler(od, SNAC_FAMILY_FEEDBAG, SNAC_SUBTYPE_FEEDBAG_ADD, purple_ssi_parseaddmod, 0);
	oscar_data_addhandler(od, SNAC_FAMILY_FEEDBAG, SNAC_SUBTYPE_FEEDBAG_MOD, purple_ssi_parseaddmod, 0);
	oscar_data_addhandler(od, SNAC_FAMILY_FEEDBAG, SNAC_SUBTYPE_FEEDBAG_RECVAUTH, purple_ssi_authgiven, 0);
	oscar_data_addhandler(od, SNAC_FAMILY_FEEDBAG, SNAC_SUBTYPE_FEEDBAG_RECVAUTHREQ, purple_ssi_authrequest, 0);
	oscar_data_addhandler(od, SNAC_FAMILY_FEEDBAG, SNAC_SUBTYPE_FEEDBAG_RECVAUTHREP, purple_ssi_authreply, 0);
	oscar_data_addhandler(od, SNAC_FAMILY_FEEDBAG, SNAC_SUBTYPE_FEEDBAG_ADDED, purple_ssi_gotadded, 0);
	oscar_data_addhandler(od, SNAC_FAMILY_ICBM, SNAC_SUBTYPE_ICBM_INCOMING, purple_parse_incoming_im, 0);
	oscar_data_addhandler(od, SNAC_FAMILY_ICBM, SNAC_SUBTYPE_ICBM_MISSEDCALL, purple_parse_misses, 0);
	oscar_data_addhandler(od, SNAC_FAMILY_ICBM, SNAC_SUBTYPE_ICBM_CLIENTAUTORESP, purple_parse_clientauto, 0);
	oscar_data_addhandler(od, SNAC_FAMILY_ICBM, SNAC_SUBTYPE_ICBM_MTN, purple_parse_mtn, 0);
	oscar_data_addhandler(od, SNAC_FAMILY_LOCATE, SNAC_SUBTYPE_LOCATE_RIGHTSINFO, purple_parse_locaterights, 0);
	oscar_data_addhandler(od, SNAC_FAMILY_OSERVICE, 0x0001, purple_parse_genericerr, 0);
	oscar_data_addhandler(od, SNAC_FAMILY_OSERVICE, 0x000f, purple_selfinfo, 0);
	oscar_data_addhandler(od, SNAC_FAMILY_OSERVICE, 0x001f, purple_memrequest, 0);
	oscar_data_addhandler(od, SNAC_FAMILY_OSERVICE, SNAC_SUBTYPE_OSERVICE_REDIRECT, purple_handle_redirect, 0);
	oscar_data_addhandler(od, SNAC_FAMILY_OSERVICE, SNAC_SUBTYPE_OSERVICE_MOTD, purple_parse_motd, 0);
	oscar_data_addhandler(od, SNAC_FAMILY_POPUP, 0x0002, purple_popup, 0);
	oscar_data_addhandler(od, SNAC_FAMILY_USERLOOKUP, SNAC_SUBTYPE_USERLOOKUP_ERROR, purple_parse_searcherror, 0);
	oscar_data_addhandler(od, SNAC_FAMILY_USERLOOKUP, 0x0003, purple_parse_searchreply, 0);

	g_string_append(msg, "Registered handlers: ");
#if GLIB_CHECK_VERSION(2,14,0)
	handlers = g_hash_table_get_keys(od->handlerlist);
#else
	handlers = NULL;
	g_hash_table_foreach(od->handlerlist, hash_table_get_list_of_keys, &handlers);
#endif /* GLIB < 2.14.0 */
	sorted_handlers = g_list_sort(g_list_copy(handlers), compare_handlers);
	for (cur = sorted_handlers; cur; cur = cur->next) {
		guint x = GPOINTER_TO_UINT(cur->data);
		g_string_append_printf(msg, "%04x/%04x, ", x >> 16, x & 0xFFFF);
	}
	g_list_free(sorted_handlers);
	g_list_free(handlers);
	purple_debug_misc("oscar", "%s\n", msg->str);
	g_string_free(msg, TRUE);

	purple_debug_misc("oscar", "oscar_login: gc = %p\n", gc);

	if (!oscar_util_valid_name(purple_account_get_username(account))) {
		gchar *buf;
		buf = g_strdup_printf(_("Unable to sign on as %s because the username is invalid.  Usernames must be a valid email address, or start with a letter and contain only letters, numbers and spaces, or contain only numbers."), purple_account_get_username(account));
		purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_INVALID_SETTINGS, buf);
		g_free(buf);
		return;
	}

	gc->flags |= PURPLE_CONNECTION_HTML;
	if (g_str_equal(purple_account_get_protocol_id(account), "prpl-icq")) {
		od->icq = TRUE;
	} else {
		gc->flags |= PURPLE_CONNECTION_AUTO_RESP;
	}

	/* Set this flag based on the protocol_id rather than the username,
	   because that is what's tied to the get_moods prpl callback. */
	if (g_str_equal(purple_account_get_protocol_id(account), "prpl-icq"))
		gc->flags |= PURPLE_CONNECTION_SUPPORT_MOODS;

	od->default_port = purple_account_get_int(account, "port", OSCAR_DEFAULT_LOGIN_PORT);

	encryption_type = purple_account_get_string(account, "encryption", OSCAR_DEFAULT_ENCRYPTION);
	if (!purple_ssl_is_supported() && strcmp(encryption_type, OSCAR_REQUIRE_ENCRYPTION) == 0) {
		purple_connection_error_reason(
			gc,
			PURPLE_CONNECTION_ERROR_NO_SSL_SUPPORT,
			_("You required encryption in your account settings, but encryption is not supported by your system."));
		return;
	}
	od->use_ssl = purple_ssl_is_supported() && strcmp(encryption_type, OSCAR_NO_ENCRYPTION) != 0;

	/* Connect to core Purple signals */
	purple_prefs_connect_callback(gc, "/purple/away/idle_reporting", idle_reporting_pref_cb, gc);
	purple_prefs_connect_callback(gc, "/plugins/prpl/oscar/recent_buddies", recent_buddies_pref_cb, gc);

	/*
	 * On 2008-03-05 AOL released some documentation on the OSCAR protocol
	 * which includes a new login method called clientLogin.  It is similar
	 * (though not the same?) as what the AIM 6.0 series uses to
	 * authenticate.
	 *
	 * AIM 5.9 and lower use an MD5-based login procedure called "BUCP".
	 * This authentication method is used for both ICQ and AIM when
	 * clientLogin is not enabled.
	 */
	if (purple_account_get_bool(account, "use_clientlogin", OSCAR_DEFAULT_USE_CLIENTLOGIN)) {
		send_client_login(od, purple_account_get_username(account));
	} else {
		FlapConnection *newconn;
		const char *server;

		newconn = flap_connection_new(od, SNAC_FAMILY_AUTH);

		if (od->use_ssl) {
			server = purple_account_get_string(account, "server", get_login_server(od->icq, TRUE));

			/*
			 * If the account's server is what the oscar prpl has offered as
			 * the default login server through the vast eons (all two of
			 * said default options, AFAIK) and the user wants SSL, we'll
			 * do what we know is best for them and change the setting out
			 * from under them to the SSL login server.
			 */
			if (!strcmp(server, get_login_server(od->icq, FALSE)) || !strcmp(server, AIM_ALT_LOGIN_SERVER)) {
				purple_debug_info("oscar", "Account uses SSL, so changing server to default SSL server\n");
				purple_account_set_string(account, "server", get_login_server(od->icq, TRUE));
				server = get_login_server(od->icq, TRUE);
			}

			newconn->gsc = purple_ssl_connect(account, server,
					purple_account_get_int(account, "port", OSCAR_DEFAULT_LOGIN_PORT),
					ssl_connection_established_cb, ssl_connection_error_cb, newconn);
		} else {
			server = purple_account_get_string(account, "server", get_login_server(od->icq, FALSE));

			/*
			 * See the comment above. We do the reverse here. If they don't want
			 * SSL but their server is set to OSCAR_DEFAULT_SSL_LOGIN_SERVER,
			 * set it back to the default.
			 */
			if (!strcmp(server, get_login_server(od->icq, TRUE))) {
				purple_debug_info("oscar", "Account does not use SSL, so changing server back to non-SSL\n");
				purple_account_set_string(account, "server", get_login_server(od->icq, FALSE));
				server = get_login_server(od->icq, FALSE);
			}

			newconn->connect_data = purple_proxy_connect(NULL, account, server,
					purple_account_get_int(account, "port", OSCAR_DEFAULT_LOGIN_PORT),
					connection_established_cb, newconn);
		}

		if (newconn->gsc == NULL && newconn->connect_data == NULL) {
			purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
					_("Unable to connect"));
			return;
		}
	}

	purple_connection_update_progress(gc, _("Connecting"), 0, OSCAR_CONNECT_STEPS);
}

void
oscar_close(PurpleConnection *gc)
{
	OscarData *od;

	od = purple_connection_get_protocol_data(gc);

	while (od->oscar_chats)
	{
		struct chat_connection *cc = od->oscar_chats->data;
		od->oscar_chats = g_slist_remove(od->oscar_chats, cc);
		oscar_chat_destroy(cc);
	}
	while (od->create_rooms)
	{
		struct create_room *cr = od->create_rooms->data;
		g_free(cr->name);
		od->create_rooms = g_slist_remove(od->create_rooms, cr);
		g_free(cr);
	}
	oscar_data_destroy(od);
	purple_connection_set_protocol_data(gc, NULL);

	purple_prefs_disconnect_by_handle(gc);

	purple_debug_info("oscar", "Signed off.\n");
}

/* XXX - Should use purple_util_fetch_url for the below stuff */
struct pieceofcrap {
	PurpleConnection *gc;
	unsigned long offset;
	unsigned long len;
	char *modname;
	int fd;
	FlapConnection *conn;
	unsigned int inpa;
};

static void damn_you(gpointer data, gint source, PurpleInputCondition c)
{
	struct pieceofcrap *pos = data;
	OscarData *od = purple_connection_get_protocol_data(pos->gc);
	char in = '\0';
	int x = 0;
	unsigned char m[17];
	GString *msg;

	while (read(pos->fd, &in, 1) == 1) {
		if (in == '\n')
			x++;
		else if (in != '\r')
			x = 0;
		if (x == 2)
			break;
		in = '\0';
	}
	if (in != '\n') {
		char buf[256];
		g_snprintf(buf, sizeof(buf), _("You may be disconnected shortly.  "
				"If so, check %s for updates."),
				oscar_get_ui_info_string("website", PURPLE_WEBSITE));
		purple_notify_warning(pos->gc, NULL,
							_("Unable to get a valid AIM login hash."),
							buf);
		purple_input_remove(pos->inpa);
		close(pos->fd);
		g_free(pos);
		return;
	}
	if (read(pos->fd, m, 16) != 16)
	{
		purple_debug_warning("oscar", "Could not read full AIM login hash "
				"from " AIMHASHDATA "--that's bad.\n");
	}
	m[16] = '\0';

	msg = g_string_new("Sending hash: ");
	for (x = 0; x < 16; x++)
		g_string_append_printf(msg, "%02hhx ", (unsigned char)m[x]);
	g_string_append(msg, "\n");
	purple_debug_misc("oscar", "%s", msg->str);
	g_string_free(msg, TRUE);

	purple_input_remove(pos->inpa);
	close(pos->fd);
	aim_sendmemblock(od, pos->conn, 0, 16, m, AIM_SENDMEMBLOCK_FLAG_ISHASH);
	g_free(pos);
}

static void
straight_to_hell(gpointer data, gint source, const gchar *error_message)
{
	struct pieceofcrap *pos = data;
	gchar *buf;
	gssize result;

	pos->fd = source;

	if (source < 0) {
		buf = g_strdup_printf(_("You may be disconnected shortly.  "
				"If so, check %s for updates."),
				oscar_get_ui_info_string("website", PURPLE_WEBSITE));
		purple_notify_warning(pos->gc, NULL,
							_("Unable to get a valid AIM login hash."),
							buf);
		g_free(buf);
		g_free(pos->modname);
		g_free(pos);
		return;
	}

	buf = g_strdup_printf("GET " AIMHASHDATA "?offset=%ld&len=%ld&modname=%s HTTP/1.0\n\n",
			pos->offset, pos->len, pos->modname ? pos->modname : "");
	result = send(pos->fd, buf, strlen(buf), 0);
	if (result != strlen(buf)) {
		if (result < 0)
			purple_debug_error("oscar", "Error writing %" G_GSIZE_FORMAT
					" bytes to fetch AIM hash data: %s\n",
					strlen(buf), g_strerror(errno));
		else
			purple_debug_error("oscar", "Tried to write %"
					G_GSIZE_FORMAT " bytes to fetch AIM hash data but "
					"instead wrote %" G_GSSIZE_FORMAT " bytes\n",
					strlen(buf), result);
	}
	g_free(buf);
	g_free(pos->modname);
	pos->inpa = purple_input_add(pos->fd, PURPLE_INPUT_READ, damn_you, pos);
	return;
}

/* size of icbmui.ocm, the largest module in AIM 3.5 */
#define AIM_MAX_FILE_SIZE 98304

static int purple_memrequest(OscarData *od, FlapConnection *conn, FlapFrame *fr, ...)
{
	va_list ap;
	struct pieceofcrap *pos;
	guint32 offset, len;
	char *modname;

	va_start(ap, fr);
	offset = va_arg(ap, guint32);
	len = va_arg(ap, guint32);
	modname = va_arg(ap, char *);
	va_end(ap);

	purple_debug_misc("oscar", "offset: %u, len: %u, file: %s\n",
					offset, len, (modname ? modname : "aim.exe"));

	if (len == 0) {
		purple_debug_misc("oscar", "len is 0, hashing NULL\n");
		aim_sendmemblock(od, conn, offset, len, NULL,
				AIM_SENDMEMBLOCK_FLAG_ISREQUEST);
		return 1;
	}

	pos = g_new0(struct pieceofcrap, 1);
	pos->gc = od->gc;
	pos->conn = conn;

	pos->offset = offset;
	pos->len = len;
	pos->modname = g_strdup(modname);

	if (purple_proxy_connect(pos->gc, pos->gc->account, "pidgin.im", 80,
			straight_to_hell, pos) == NULL)
	{
		char buf[256];
		g_free(pos->modname);
		g_free(pos);

		g_snprintf(buf, sizeof(buf), _("You may be disconnected shortly.  "
			"If so, check %s for updates."),
			oscar_get_ui_info_string("website", PURPLE_WEBSITE));
		purple_notify_warning(pos->gc, NULL,
							_("Unable to get a valid login hash."),
							buf);
	}

	return 1;
}

int oscar_connect_to_bos(PurpleConnection *gc, OscarData *od, const char *host, guint16 port, guint8 *cookie, guint16 cookielen, const char *tls_certname)
{
	PurpleAccount *account;
	FlapConnection *conn;

	account = purple_connection_get_account(gc);

	conn = flap_connection_new(od, SNAC_FAMILY_LOCATE);
	conn->cookielen = cookielen;
	conn->cookie = g_memdup(cookie, cookielen);

	/*
	 * Use TLS only if the server provided us with a tls_certname. The server might not specify a tls_certname even if we requested to use TLS,
	 * and that is something we should be prepared to.
	 */
	if (tls_certname)
	{
		conn->gsc = purple_ssl_connect_with_ssl_cn(account, host, port,
				ssl_connection_established_cb, ssl_connection_error_cb,
				tls_certname, conn);
	}
	else
	{
		conn->connect_data = purple_proxy_connect(NULL,
				account, host, port,
				connection_established_cb, conn);
	}

	if (conn->gsc == NULL && conn->connect_data == NULL)
	{
		purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, _("Unable to connect"));
		return 0;
	}

	od->default_port = port;

	purple_connection_update_progress(gc, _("Received authorization"), 3, OSCAR_CONNECT_STEPS);

	return 1;
}

/**
 * Only used when connecting with the old-style BUCP login.
 */
static int
purple_parse_auth_resp(OscarData *od, FlapConnection *conn, FlapFrame *fr, ...)
{
	PurpleConnection *gc = od->gc;
	PurpleAccount *account = purple_connection_get_account(gc);
	char *host; int port;
	int i;
	FlapConnection *newconn;
	va_list ap;
	struct aim_authresp_info *info;

	port = purple_account_get_int(account, "port", od->default_port);

	va_start(ap, fr);
	info = va_arg(ap, struct aim_authresp_info *);
	va_end(ap);

	purple_debug_info("oscar",
			   "inside auth_resp (Username: %s)\n", info->bn);

	if (info->errorcode || !info->bosip || !info->cookielen || !info->cookie) {
		char buf[256];
		switch (info->errorcode) {
		case 0x01:
			/* Unregistered username */
			purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_INVALID_USERNAME, _("Username does not exist"));
			break;
		case 0x05:
			/* Incorrect password */
			if (!purple_account_get_remember_password(account))
				purple_account_set_password(account, NULL);
			purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, _("Incorrect password"));
			break;
		case 0x11:
			/* Suspended account */
			purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, _("Your account is currently suspended"));
			break;
		case 0x02:
		case 0x14:
			/* service temporarily unavailable */
			purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, _("The AOL Instant Messenger service is temporarily unavailable."));
			break;
		case 0x18:
			/* username connecting too frequently */
			purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_OTHER_ERROR, _("Your username has been connecting and disconnecting too frequently. Wait ten minutes and try again. If you continue to try, you will need to wait even longer."));
			break;
		case 0x1c:
		{
			/* client too old */
			g_snprintf(buf, sizeof(buf), _("The client version you are using is too old. Please upgrade at %s"),
					oscar_get_ui_info_string("website", PURPLE_WEBSITE));
			purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_OTHER_ERROR, buf);
			break;
		}
		case 0x1d:
			/* IP address connecting too frequently */
			purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_OTHER_ERROR, _("Your IP address has been connecting and disconnecting too frequently. Wait a minute and try again. If you continue to try, you will need to wait even longer."));
			break;
		default:
			purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, _("Unknown reason"));
			break;
		}
		purple_debug_info("oscar", "Login Error Code 0x%04hx\n", info->errorcode);
		purple_debug_info("oscar", "Error URL: %s\n", info->errorurl ? info->errorurl : "");
		return 1;
	}

	purple_debug_misc("oscar", "Reg status: %hu\n"
							   "Email: %s\n"
							   "BOSIP: %s\n",
							   info->regstatus,
							   info->email ? info->email : "null",
							   info->bosip ? info->bosip : "null");
	purple_debug_info("oscar", "Closing auth connection...\n");
	flap_connection_schedule_destroy(conn, OSCAR_DISCONNECT_DONE, NULL);

	for (i = 0; i < strlen(info->bosip); i++) {
		if (info->bosip[i] == ':') {
			port = atoi(&(info->bosip[i+1]));
			break;
		}
	}
	host = g_strndup(info->bosip, i);
	newconn = flap_connection_new(od, SNAC_FAMILY_LOCATE);
	newconn->cookielen = info->cookielen;
	newconn->cookie = g_memdup(info->cookie, info->cookielen);

	if (od->use_ssl)
	{
		/*
		 * This shouldn't be hardcoded to "bos.oscar.aol.com" except that
		 * the server isn't sending us a name to use for comparing the
		 * certificate common name.
		 */
		newconn->gsc = purple_ssl_connect_with_ssl_cn(account, host, port,
				ssl_connection_established_cb, ssl_connection_error_cb,
				"bos.oscar.aol.com", newconn);
	}
	else
	{
		newconn->connect_data = purple_proxy_connect(NULL, account, host, port,
				connection_established_cb, newconn);
	}

	g_free(host);
	if (newconn->gsc == NULL && newconn->connect_data == NULL)
	{
		purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, _("Unable to connect"));
		return 0;
	}

	purple_connection_update_progress(gc, _("Received authorization"), 3, OSCAR_CONNECT_STEPS);

	return 1;
}

/**
 * Only used when connecting with the old-style BUCP login.
 */
static void
purple_parse_auth_securid_request_yes_cb(gpointer user_data, const char *msg)
{
	PurpleConnection *gc = user_data;
	OscarData *od = purple_connection_get_protocol_data(gc);

	aim_auth_securid_send(od, msg);
}

/**
 * Only used when connecting with the old-style BUCP login.
 */
static void
purple_parse_auth_securid_request_no_cb(gpointer user_data, const char *value)
{
	PurpleConnection *gc = user_data;

	/* Disconnect */
	purple_connection_error_reason(gc,
		PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED,
		_("The SecurID key entered is invalid"));
}

/**
 * Only used when connecting with the old-style BUCP login.
 */
static int
purple_parse_auth_securid_request(OscarData *od, FlapConnection *conn, FlapFrame *fr, ...)
{
	PurpleConnection *gc = od->gc;
	PurpleAccount *account = purple_connection_get_account(gc);
	gchar *primary;

	purple_debug_info("oscar", "Got SecurID request\n");

	primary = g_strdup_printf("Enter the SecurID key for %s.", purple_account_get_username(account));
	purple_request_input(gc, NULL, _("Enter SecurID"), primary,
					   _("Enter the 6 digit number from the digital display."),
					   FALSE, FALSE, NULL,
					   _("_OK"), G_CALLBACK(purple_parse_auth_securid_request_yes_cb),
					   _("_Cancel"), G_CALLBACK(purple_parse_auth_securid_request_no_cb),
					   account, NULL, NULL,
					   gc);
	g_free(primary);

	return 1;
}

/**
 * Only used when connecting with the old-style BUCP login.
 */
static int
purple_parse_login(OscarData *od, FlapConnection *conn, FlapFrame *fr, ...)
{
	PurpleConnection *gc;
	PurpleAccount *account;
	ClientInfo aiminfo = CLIENTINFO_PURPLE_AIM;
	ClientInfo icqinfo = CLIENTINFO_PURPLE_ICQ;
	va_list ap;
	char *key;
	gboolean truncate_pass;

	gc = od->gc;
	account = purple_connection_get_account(gc);

	va_start(ap, fr);
	key = va_arg(ap, char *);
	truncate_pass = va_arg(ap, int);
	va_end(ap);

	aim_send_login(od, conn, purple_account_get_username(account),
			purple_connection_get_password(gc), truncate_pass,
			od->icq ? &icqinfo : &aiminfo, key,
			purple_account_get_bool(account, "allow_multiple_logins", OSCAR_DEFAULT_ALLOW_MULTIPLE_LOGINS));

	purple_connection_update_progress(gc, _("Password sent"), 2, OSCAR_CONNECT_STEPS);

	return 1;
}

static int
purple_handle_redirect(OscarData *od, FlapConnection *conn, FlapFrame *fr, ...)
{
	PurpleConnection *gc = od->gc;
	PurpleAccount *account = purple_connection_get_account(gc);
	char *host, *separator;
	int port;
	FlapConnection *newconn;
	va_list ap;
	struct aim_redirect_data *redir;

	va_start(ap, fr);
	redir = va_arg(ap, struct aim_redirect_data *);
	va_end(ap);

	port = od->default_port;
	separator = strchr(redir->ip, ':');
	if (separator != NULL)
	{
		host = g_strndup(redir->ip, separator - redir->ip);
		port = atoi(separator + 1);
	}
	else
		host = g_strdup(redir->ip);

	if (!redir->use_ssl) {
		const gchar *encryption_type = purple_account_get_string(account, "encryption", OSCAR_DEFAULT_ENCRYPTION);
		if (strcmp(encryption_type, OSCAR_OPPORTUNISTIC_ENCRYPTION) == 0) {
			purple_debug_warning("oscar", "We won't use SSL for FLAP type 0x%04hx.\n", redir->group);
		} else if (strcmp(encryption_type, OSCAR_REQUIRE_ENCRYPTION) == 0) {
			purple_debug_error("oscar", "FLAP server %s:%d of type 0x%04hx doesn't support encryption.", host, port, redir->group);
			purple_connection_error_reason(
				gc,
				PURPLE_CONNECTION_ERROR_NO_SSL_SUPPORT,
				_("You required encryption in your account settings, but one of the servers doesn't support it."));
			return 0;
		}
	}

	/*
	 * These FLAP servers advertise SSL (type "0x02"), but SSL connections to these hosts
	 * die a painful death. iChat and Miranda, when using SSL, still do these in plaintext.
	 */
	if (redir->use_ssl && (redir->group == SNAC_FAMILY_ADMIN ||
	                       redir->group == SNAC_FAMILY_BART))
	{
		purple_debug_info("oscar", "Ignoring broken SSL for FLAP type 0x%04hx.\n", redir->group);
		redir->use_ssl = 0;
	}

	purple_debug_info("oscar", "Connecting to FLAP server %s:%d of type 0x%04hx\n", host, port, redir->group);

	newconn = flap_connection_new(od, redir->group);
	newconn->cookielen = redir->cookielen;
	newconn->cookie = g_memdup(redir->cookie, redir->cookielen);
	if (newconn->type == SNAC_FAMILY_CHAT)
	{
		struct chat_connection *cc;
		cc = g_new0(struct chat_connection, 1);
		cc->conn = newconn;
		cc->gc = gc;
		cc->name = g_strdup(redir->chat.room);
		cc->exchange = redir->chat.exchange;
		cc->instance = redir->chat.instance;
		cc->show = extract_name(redir->chat.room);
		newconn->new_conn_data = cc;
		purple_debug_info("oscar", "Connecting to chat room %s exchange %hu\n", cc->name, cc->exchange);
	}


	if (redir->use_ssl)
	{
		newconn->gsc = purple_ssl_connect_with_ssl_cn(account, host, port,
				ssl_connection_established_cb, ssl_connection_error_cb,
				redir->ssl_cert_cn, newconn);
	}
	else
	{
		newconn->connect_data = purple_proxy_connect(NULL, account, host, port,
				connection_established_cb, newconn);
	}

	if (newconn->gsc == NULL && newconn->connect_data == NULL)
	{
		flap_connection_schedule_destroy(newconn,
				OSCAR_DISCONNECT_COULD_NOT_CONNECT,
				_("Unable to initialize connection"));
		purple_debug_error("oscar", "Unable to connect to FLAP server "
				"of type 0x%04hx\n", redir->group);
	}
	g_free(host);

	return 1;
}


static int purple_parse_oncoming(OscarData *od, FlapConnection *conn, FlapFrame *fr, ...)
{
	PurpleConnection *gc;
	PurpleAccount *account;
	PurpleBuddy *buddy = NULL;
	PurpleStatus *previous_status = NULL;
	struct buddyinfo *bi;
	time_t time_idle = 0, signon = 0;
	int type = 0;
	gboolean buddy_is_away = FALSE;
	const char *status_id;
	va_list ap;
	aim_userinfo_t *info;
	char *message;
	char *itmsurl = NULL;

	gc = od->gc;
	account = purple_connection_get_account(gc);

	va_start(ap, fr);
	info = va_arg(ap, aim_userinfo_t *);
	va_end(ap);

	g_return_val_if_fail(info != NULL, 1);
	g_return_val_if_fail(info->bn != NULL, 1);

	buddy = purple_find_buddy(account, info->bn);
	if (buddy) {
		previous_status = purple_presence_get_active_status(purple_buddy_get_presence(buddy));
	}

	/*
	 * If this is an AIM buddy and their name has formatting, set their
	 * server alias.
	 */
	if (!oscar_util_valid_name_icq(info->bn)) {
		gboolean bn_has_formatting = FALSE;
		char *c;
		for (c = info->bn; *c != '\0'; c++) {
			if (!islower(*c)) {
				bn_has_formatting = TRUE;
				break;
			}
		}
		serv_got_alias(gc, info->bn,
				bn_has_formatting ? info->bn : NULL);
	}

	if (info->present & AIM_USERINFO_PRESENT_FLAGS) {
		if (info->flags & AIM_FLAG_AWAY)
			buddy_is_away = TRUE;
	}
	if (info->present & AIM_USERINFO_PRESENT_ICQEXTSTATUS) {
		type = info->icqinfo.status;
		if (!(info->icqinfo.status & AIM_ICQ_STATE_CHAT) &&
		      (info->icqinfo.status != AIM_ICQ_STATE_NORMAL)) {
			buddy_is_away = TRUE;
		}
	}

	if (oscar_util_valid_name_icq(info->bn)) {
		if (type & AIM_ICQ_STATE_CHAT)
			status_id = OSCAR_STATUS_ID_FREE4CHAT;
		else if (type & AIM_ICQ_STATE_DND)
			status_id = OSCAR_STATUS_ID_DND;
		else if (type & AIM_ICQ_STATE_OUT)
			status_id = OSCAR_STATUS_ID_NA;
		else if (type & AIM_ICQ_STATE_BUSY)
			status_id = OSCAR_STATUS_ID_OCCUPIED;
		else if (type & AIM_ICQ_STATE_AWAY)
			status_id = OSCAR_STATUS_ID_AWAY;
		else if (type & AIM_ICQ_STATE_INVISIBLE)
			status_id = OSCAR_STATUS_ID_INVISIBLE;
		else if (type & AIM_ICQ_STATE_EVIL)
			status_id = OSCAR_STATUS_ID_EVIL;
		else if (type & AIM_ICQ_STATE_DEPRESSION)
			status_id = OSCAR_STATUS_ID_DEPRESSION;
		else if (type & AIM_ICQ_STATE_ATHOME)
			status_id = OSCAR_STATUS_ID_ATHOME;
		else if (type & AIM_ICQ_STATE_ATWORK)
			status_id = OSCAR_STATUS_ID_ATWORK;
		else if (type & AIM_ICQ_STATE_LUNCH)
			status_id = OSCAR_STATUS_ID_LUNCH;
		else
			status_id = OSCAR_STATUS_ID_AVAILABLE;
	} else {
		if (type & AIM_ICQ_STATE_INVISIBLE)
			status_id = OSCAR_STATUS_ID_INVISIBLE;
		else if (buddy_is_away)
			status_id = OSCAR_STATUS_ID_AWAY;
		else
			status_id = OSCAR_STATUS_ID_AVAILABLE;
	}

	if (info->flags & AIM_FLAG_WIRELESS) {
		purple_prpl_got_user_status(account, info->bn, OSCAR_STATUS_ID_MOBILE, NULL);
	} else {
		purple_prpl_got_user_status_deactive(account, info->bn, OSCAR_STATUS_ID_MOBILE);
	}

	message = (info->status && info->status_len > 0)
			? oscar_encoding_to_utf8(info->status_encoding, info->status, info->status_len)
			: NULL;

	if (strcmp(status_id, OSCAR_STATUS_ID_AVAILABLE) == 0) {
		/* TODO: If itmsurl is NULL, does that mean the URL has been
		   cleared?  Or does it mean the URL should remain unchanged? */
		if (info->itmsurl != NULL) {
			itmsurl = (info->itmsurl_len > 0) ? oscar_encoding_to_utf8(info->itmsurl_encoding, info->itmsurl, info->itmsurl_len) : NULL;
		} else if (previous_status != NULL && purple_status_is_available(previous_status)) {
			itmsurl = g_strdup(purple_status_get_attr_string(previous_status, "itmsurl"));
		}
		purple_debug_info("oscar", "Activating status '%s' for buddy %s, message = '%s', itmsurl = '%s'\n", status_id, info->bn, message ? message : "(null)", itmsurl ? itmsurl : "(null)");
		purple_prpl_got_user_status(account, info->bn, status_id, "message", message, "itmsurl", itmsurl, NULL);
	} else {
		purple_debug_info("oscar", "Activating status '%s' for buddy %s, message = '%s'\n", status_id, info->bn, message ? message : "(null)");
		purple_prpl_got_user_status(account, info->bn, status_id, "message", message, NULL);
	}

	g_free(message);
	g_free(itmsurl);

	/* Login time stuff */
	if (info->present & AIM_USERINFO_PRESENT_ONLINESINCE)
		signon = info->onlinesince;
	else if (info->present & AIM_USERINFO_PRESENT_SESSIONLEN)
		signon = time(NULL) - info->sessionlen;
	purple_prpl_got_user_login_time(account, info->bn, signon);

	/* Idle time stuff */
	/* info->idletime is the number of minutes that this user has been idle */
	if (info->present & AIM_USERINFO_PRESENT_IDLE)
		time_idle = time(NULL) - info->idletime * 60;

	if (time_idle > 0)
		purple_prpl_got_user_idle(account, info->bn, TRUE, time_idle);
	else
		purple_prpl_got_user_idle(account, info->bn, FALSE, 0);

	/* Server stored icon stuff */
	bi = g_hash_table_lookup(od->buddyinfo, purple_normalize(account, info->bn));
	if (!bi) {
		bi = g_new0(struct buddyinfo, 1);
		g_hash_table_insert(od->buddyinfo, g_strdup(purple_normalize(account, info->bn)), bi);
	}
	bi->typingnot = FALSE;
	bi->ico_informed = FALSE;
	bi->ipaddr = info->icqinfo.ipaddr;

	if (info->iconcsumlen) {
		const char *saved_b16 = NULL;
		char *b16 = NULL;
		PurpleBuddy *b = NULL;

		b16 = purple_base16_encode(info->iconcsum, info->iconcsumlen);
		b = purple_find_buddy(account, info->bn);
		if (b != NULL)
			saved_b16 = purple_buddy_icons_get_checksum_for_user(b);

		if (!b16 || !saved_b16 || strcmp(b16, saved_b16)) {
			/* Invalidate the old icon for this user */
			purple_buddy_icons_set_for_user(account, info->bn, NULL, 0, NULL);

			/* Fetch the new icon (if we're not already doing so) */
			if (g_slist_find_custom(od->requesticon, info->bn,
					(GCompareFunc)oscar_util_name_compare) == NULL)
			{
				od->requesticon = g_slist_prepend(od->requesticon,
						g_strdup(purple_normalize(account, info->bn)));
				purple_icons_fetch(gc);
			}
		}
		g_free(b16);
	}

	return 1;
}

static int purple_parse_offgoing(OscarData *od, FlapConnection *conn, FlapFrame *fr, ...) {
	PurpleConnection *gc = od->gc;
	PurpleAccount *account = purple_connection_get_account(gc);
	va_list ap;
	aim_userinfo_t *info;

	va_start(ap, fr);
	info = va_arg(ap, aim_userinfo_t *);
	va_end(ap);

	purple_prpl_got_user_status(account, info->bn, OSCAR_STATUS_ID_OFFLINE, NULL);
	purple_prpl_got_user_status_deactive(account, info->bn, OSCAR_STATUS_ID_MOBILE);
	g_hash_table_remove(od->buddyinfo, purple_normalize(gc->account, info->bn));

	return 1;
}

static int incomingim_chan1(OscarData *od, FlapConnection *conn, aim_userinfo_t *userinfo, struct aim_incomingim_ch1_args *args) {
	PurpleConnection *gc = od->gc;
	PurpleAccount *account = purple_connection_get_account(gc);
	PurpleMessageFlags flags = 0;
	struct buddyinfo *bi;
	PurpleStoredImage *img;
	gchar *tmp;
	const char *start, *end;
	GData *attribs;

	purple_debug_misc("oscar", "Received IM from %s\n", userinfo->bn);

	bi = g_hash_table_lookup(od->buddyinfo, purple_normalize(account, userinfo->bn));
	if (!bi) {
		bi = g_new0(struct buddyinfo, 1);
		g_hash_table_insert(od->buddyinfo, g_strdup(purple_normalize(account, userinfo->bn)), bi);
	}

	if (args->icbmflags & AIM_IMFLAGS_AWAY)
		flags |= PURPLE_MESSAGE_AUTO_RESP;

	if (args->icbmflags & AIM_IMFLAGS_TYPINGNOT)
		bi->typingnot = TRUE;
	else
		bi->typingnot = FALSE;

	if ((args->icbmflags & AIM_IMFLAGS_HASICON) && (args->iconlen) && (args->iconsum) && (args->iconstamp)) {
		purple_debug_misc("oscar", "%s has an icon\n", userinfo->bn);
		if ((args->iconlen != bi->ico_len) || (args->iconsum != bi->ico_csum) || (args->iconstamp != bi->ico_time)) {
			bi->ico_need = TRUE;
			bi->ico_len = args->iconlen;
			bi->ico_csum = args->iconsum;
			bi->ico_time = args->iconstamp;
		}
	}

	img = purple_buddy_icons_find_account_icon(account);
	if ((img != NULL) &&
	    (args->icbmflags & AIM_IMFLAGS_BUDDYREQ) && !bi->ico_sent && bi->ico_informed) {
		gconstpointer data = purple_imgstore_get_data(img);
		size_t len = purple_imgstore_get_size(img);
		purple_debug_info("oscar",
				"Sending buddy icon to %s (%" G_GSIZE_FORMAT " bytes)\n",
				userinfo->bn, len);
		aim_im_sendch2_icon(od, userinfo->bn, data, len,
			purple_buddy_icons_get_account_icon_timestamp(account),
			aimutil_iconsum(data, len));
	}
	purple_imgstore_unref(img);

	tmp = g_strdup(args->msg);

	/*
	 * Convert iChat color tags to normal font tags.
	 */
	if (purple_markup_find_tag("body", tmp, &start, &end, &attribs))
	{
		int len;
		char *tmp2, *body;
		const char *ichattextcolor, *ichatballooncolor;
		const char *slash_body_start, *slash_body_end = NULL; /* </body> */
		GData *unused;

		/*
		 * Find the ending </body> so we can strip off the outer <html/>
		 * and <body/>
		 */
		if (purple_markup_find_tag("/body", end + 1, &slash_body_start, &slash_body_end, &unused))
		{
			body = g_strndup(start, slash_body_end - start + 1);
			g_datalist_clear(&unused);
		}
		else
		{
			purple_debug_warning("oscar", "Broken message contains <body> but not </body>!\n");
			/* Take everything after <body> */
			body = g_strdup(start);
		}

		ichattextcolor = g_datalist_get_data(&attribs, "ichattextcolor");
		if (ichattextcolor != NULL)
		{
			tmp2 = g_strdup_printf("<font color=\"%s\">%s</font>", ichattextcolor, body);
			g_free(body);
			body = tmp2;
		}

		ichatballooncolor = g_datalist_get_data(&attribs, "ichatballooncolor");
		if (ichatballooncolor != NULL)
		{
			tmp2 = g_strdup_printf("<font back=\"%s\">%s</font>", ichatballooncolor, body);
			g_free(body);
			body = tmp2;
		}

		g_datalist_clear(&attribs);

		len = start - tmp;
		tmp2 = g_strdup_printf("%.*s%s%s", len, tmp, body, slash_body_end ? slash_body_end + 1: "</body>");
		g_free(tmp);
		g_free(body);

		tmp = tmp2;
	}

	/*
	 * Are there <html/> surrounding tags? If so, strip them out, too.
	 */
	if (purple_markup_find_tag("html", tmp, &start, &end, &attribs))
	{
		gchar *tmp2;
		int len;

		g_datalist_clear(&attribs);

		len = start - tmp;
		tmp2 = g_strdup_printf("%.*s%s", len, tmp, end + 1);
		g_free(tmp);
		tmp = tmp2;
	}

	if (purple_markup_find_tag("/html", tmp, &start, &end, &attribs))
	{
		gchar *tmp2;
		int len;

		g_datalist_clear(&attribs);

		len = start - tmp;
		tmp2 = g_strdup_printf("%.*s%s", len, tmp, end + 1);
		g_free(tmp);
		tmp = tmp2;
	}

	serv_got_im(gc, userinfo->bn, tmp, flags, (args->icbmflags & AIM_IMFLAGS_OFFLINE) ? args->timestamp : time(NULL));
	g_free(tmp);

	return 1;
}

static int
incomingim_chan2(OscarData *od, FlapConnection *conn, aim_userinfo_t *userinfo, IcbmArgsCh2 *args)
{
	PurpleConnection *gc;
	PurpleAccount *account;
	PurpleMessageFlags flags = 0;
	char *message = NULL;

	g_return_val_if_fail(od != NULL, 0);
	g_return_val_if_fail(od->gc != NULL, 0);

	gc = od->gc;
	account = purple_connection_get_account(gc);
	od = purple_connection_get_protocol_data(gc);

	if (args == NULL)
		return 0;

	purple_debug_misc("oscar", "Incoming rendezvous message of type %"
			G_GUINT64_FORMAT ", user %s, status %hu\n",
			args->type, userinfo->bn, args->status);

	if (args->msg != NULL) {
		message = oscar_encoding_to_utf8(args->encoding, args->msg, args->msglen);
	}

	if (args->type & OSCAR_CAPABILITY_CHAT)
	{
		char *utf8name, *tmp;
		GHashTable *components;

		if (!args->info.chat.roominfo.name || !args->info.chat.roominfo.exchange) {
			g_free(message);
			return 1;
		}
		utf8name = oscar_encoding_to_utf8(args->encoding, args->info.chat.roominfo.name, args->info.chat.roominfo.namelen);

		tmp = extract_name(utf8name);
		if (tmp != NULL)
		{
			g_free(utf8name);
			utf8name = tmp;
		}

		components = g_hash_table_new_full(g_str_hash, g_str_equal, g_free,
				g_free);
		g_hash_table_replace(components, g_strdup("room"), utf8name);
		g_hash_table_replace(components, g_strdup("exchange"),
				g_strdup_printf("%d", args->info.chat.roominfo.exchange));
		serv_got_chat_invite(gc,
				     utf8name,
				     userinfo->bn,
				     message,
				     components);
	}

	else if ((args->type & OSCAR_CAPABILITY_SENDFILE) || (args->type & OSCAR_CAPABILITY_DIRECTIM))
	{
		if (args->status == AIM_RENDEZVOUS_PROPOSE)
		{
			peer_connection_got_proposition(od, userinfo->bn, message, args);
		}
		else if (args->status == AIM_RENDEZVOUS_CANCEL)
		{
			/* The other user cancelled a peer request */
			PeerConnection *conn;

			conn = peer_connection_find_by_cookie(od, userinfo->bn, args->cookie);
			/*
			 * If conn is NULL it means we haven't tried to create
			 * a connection with that user.  They may be trying to
			 * do something malicious.
			 */
			if (conn != NULL)
			{
				peer_connection_destroy(conn, OSCAR_DISCONNECT_REMOTE_CLOSED, NULL);
			}
		}
		else if (args->status == AIM_RENDEZVOUS_CONNECTED)
		{
			/*
			 * Remote user has accepted our peer request.  If we
			 * wanted to we could look up the PeerConnection using
			 * args->cookie, but we don't need to do anything here.
			 */
		}
	}

	else if (args->type & OSCAR_CAPABILITY_GETFILE)
	{
	}

	else if (args->type & OSCAR_CAPABILITY_TALK)
	{
	}

	else if (args->type & OSCAR_CAPABILITY_BUDDYICON)
	{
		purple_buddy_icons_set_for_user(account, userinfo->bn,
									  g_memdup(args->info.icon.icon, args->info.icon.length),
									  args->info.icon.length,
									  NULL);
	}

	else if (args->type & OSCAR_CAPABILITY_ICQSERVERRELAY)
	{
		purple_debug_info("oscar", "Got an ICQ Server Relay message of "
				"type %d\n", args->info.rtfmsg.msgtype);

		if (args->info.rtfmsg.msgtype == 1) {
			if (args->info.rtfmsg.msg != NULL) {
				char *rtfmsg;
				const char *encoding = args->encoding;
				size_t len = strlen(args->info.rtfmsg.msg);
				char *tmp, *tmp2;

				if (encoding == NULL && !g_utf8_validate(args->info.rtfmsg.msg, len, NULL)) {
					/* Yet another wonderful Miranda-related hack. If their user disables the "Send Unicode messages" setting,
					 * Miranda sends us ch2 messages in whatever Windows codepage is set as default on their user's system (instead of UTF-8).
					 * Of course, they don't bother to specify that codepage. Let's just fallback to the encoding OUR users can
					 * specify in account options as a last resort.
					 */
					encoding = purple_account_get_string(account, "encoding", OSCAR_DEFAULT_CUSTOM_ENCODING);
					purple_debug_info("oscar", "Miranda, is that you? Using '%s' as encoding\n", encoding);
				}

				rtfmsg = oscar_encoding_to_utf8(encoding, args->info.rtfmsg.msg, len);

				/* Channel 2 messages are supposed to be plain-text (never mind the name "rtfmsg", even
				 * the official client doesn't parse them as RTF). Therefore, we should escape them before
				 * showing to the user. */
				tmp = g_markup_escape_text(rtfmsg, -1);
				g_free(rtfmsg);
				tmp2 = purple_strreplace(tmp, "\r\n", "<br>");
				g_free(tmp);

				serv_got_im(gc, userinfo->bn, tmp2, flags, time(NULL));
				aim_im_send_icq_confirmation(od, userinfo->bn, args->cookie);
				g_free(tmp2);
			}
		} else if (args->info.rtfmsg.msgtype == 26) {
			purple_debug_info("oscar", "Sending X-Status Reply\n");
			icq_relay_xstatus(od, userinfo->bn, args->cookie);
		}
	}
	else
	{
		purple_debug_error("oscar", "Unknown request class %"
				G_GUINT64_FORMAT "\n", args->type);
	}

	g_free(message);

	return 1;
}

/* When someone sends you buddies */
static void
purple_icq_buddyadd(struct name_data *data)
{
	PurpleConnection *gc = data->gc;

	purple_blist_request_add_buddy(purple_connection_get_account(gc), data->name, NULL, data->nick);

	oscar_free_name_data(data);
}

static int
incomingim_chan4(OscarData *od, FlapConnection *conn, aim_userinfo_t *userinfo, struct aim_incomingim_ch4_args *args, time_t t)
{
	PurpleConnection *gc = od->gc;
	PurpleAccount *account = purple_connection_get_account(gc);
	gchar **msg1, **msg2;
	int i, numtoks;

	if (!args->type || !args->msg || !args->uin)
		return 1;

	purple_debug_info("oscar",
					"Received a channel 4 message of type 0x%02hx.\n",
					args->type);

	/*
	 * Split up the message at the delimeter character, then convert each
	 * string to UTF-8.  Unless, of course, this is a type 1 message.  If
	 * this is a type 1 message, then the delimiter 0xfe could be a valid
	 * character in whatever encoding the message was sent in.  Type 1
	 * messages are always made up of only one part, so we can easily account
	 * for this suck-ass part of the protocol by splitting the string into at
	 * most 1 baby string.
	 */
	msg1 = g_strsplit(args->msg, "\376", (args->type == 0x01 ? 1 : 0));
	for (numtoks=0; msg1[numtoks]; numtoks++);
	msg2 = (gchar **)g_malloc((numtoks+1)*sizeof(gchar *));
	for (i=0; msg1[i]; i++) {
		gchar *uin = g_strdup_printf("%u", args->uin);

		purple_str_strip_char(msg1[i], '\r');
		/* TODO: Should use an encoding other than ASCII? */
		msg2[i] = oscar_decode_im(account, uin, AIM_CHARSET_ASCII, msg1[i], strlen(msg1[i]));
		g_free(uin);
	}
	msg2[i] = NULL;

	switch (args->type) {
		case 0x01: { /* MacICQ message or basic offline message */
			if (i >= 1) {
				gchar *uin = g_strdup_printf("%u", args->uin);
				gchar *tmp;

				/* If the message came from an ICQ user then escape any HTML */
				tmp = g_markup_escape_text(msg2[0], -1);

				if (t) { /* This is an offline message */
					/* The timestamp is UTC-ish, so we need to get the offset */
#ifdef HAVE_TM_GMTOFF
					time_t now;
					struct tm *tm;
					now = time(NULL);
					tm = localtime(&now);
					t += tm->tm_gmtoff;
#else
#	ifdef HAVE_TIMEZONE
					tzset();
					t -= timezone;
#	endif
#endif
					serv_got_im(gc, uin, tmp, 0, t);
				} else { /* This is a message from MacICQ/Miranda */
					serv_got_im(gc, uin, tmp, 0, time(NULL));
				}
				g_free(uin);
				g_free(tmp);
			}
		} break;

		case 0x04: { /* Someone sent you a URL */
			if (i >= 2) {
				if (msg2[1] != NULL) {
					gchar *uin = g_strdup_printf("%u", args->uin);
					gchar *message = g_strdup_printf("<A HREF=\"%s\">%s</A>",
													 msg2[1],
													 (msg2[0] && msg2[0][0]) ? msg2[0] : msg2[1]);
					serv_got_im(gc, uin, message, 0, time(NULL));
					g_free(uin);
					g_free(message);
				}
			}
		} break;

		case 0x06: { /* Someone requested authorization */
			if (i >= 6) {
				gchar *bn = g_strdup_printf("%u", args->uin);
				gchar *reason = NULL;

				if (msg2[5] != NULL)
					reason = oscar_decode_im(account, bn, AIM_CHARSET_LATIN_1, msg2[5], strlen(msg2[5]));

				purple_debug_info("oscar",
						   "Received an authorization request from UIN %u\n",
						   args->uin);
				aim_icq_getalias(od, bn, TRUE, reason);
				g_free(bn);
				g_free(reason);
			}
		} break;

		case 0x07: { /* Someone has denied you authorization */
			if (i >= 1) {
				gchar *dialog_msg = g_strdup_printf(_("The user %u has denied your request to add them to your buddy list for the following reason:\n%s"), args->uin, msg2[0] ? msg2[0] : _("No reason given."));
				purple_notify_info(gc, NULL, _("ICQ authorization denied."),
								 dialog_msg);
				g_free(dialog_msg);
			}
		} break;

		case 0x08: { /* Someone has granted you authorization */
			gchar *dialog_msg = g_strdup_printf(_("The user %u has granted your request to add them to your buddy list."), args->uin);
			purple_notify_info(gc, NULL, "ICQ authorization accepted.",
							 dialog_msg);
			g_free(dialog_msg);
		} break;

		case 0x09: { /* Message from the Godly ICQ server itself, I think */
			if (i >= 5) {
				gchar *dialog_msg = g_strdup_printf(_("You have received a special message\n\nFrom: %s [%s]\n%s"), msg2[0], msg2[3], msg2[5]);
				purple_notify_info(gc, NULL, "ICQ Server Message", dialog_msg);
				g_free(dialog_msg);
			}
		} break;

		case 0x0d: { /* Someone has sent you a pager message from http://www.icq.com/your_uin */
			if (i >= 6) {
				gchar *dialog_msg = g_strdup_printf(_("You have received an ICQ page\n\nFrom: %s [%s]\n%s"), msg2[0], msg2[3], msg2[5]);
				purple_notify_info(gc, NULL, "ICQ Page", dialog_msg);
				g_free(dialog_msg);
			}
		} break;

		case 0x0e: { /* Someone has emailed you at your_uin@pager.icq.com */
			if (i >= 6) {
				gchar *dialog_msg = g_strdup_printf(_("You have received an ICQ email from %s [%s]\n\nMessage is:\n%s"), msg2[0], msg2[3], msg2[5]);
				purple_notify_info(gc, NULL, "ICQ Email", dialog_msg);
				g_free(dialog_msg);
			}
		} break;

		case 0x12: {
			/* Ack for authorizing/denying someone.  Or possibly an ack for sending any system notice */
			/* Someone added you to their buddy list? */
		} break;

		case 0x13: { /* Someone has sent you some ICQ buddies */
			guint i, num;
			gchar **text;
			text = g_strsplit(args->msg, "\376", 0);
			if (text) {
				/* Read the number of contacts that we were sent */
				errno = 0;
				num = text[0] ? strtoul(text[0], NULL, 10) : 0;

				if (num > 0 && errno == 0) {
					for (i=0; i<num; i++) {
						struct name_data *data;
						gchar *message;

						if (!text[i*2 + 1] || !text[i*2 + 2]) {
							/* We're missing the contact name or nickname.  Bail out. */
							gchar *tmp = g_strescape(args->msg, NULL);
							purple_debug_error("oscar", "Unknown syntax parsing "
									"ICQ buddies.  args->msg=%s\n", tmp);
							g_free(tmp);
							break;
						}

						message = g_strdup_printf(_("ICQ user %u has sent you a buddy: %s (%s)"), args->uin, text[i*2+2], text[i*2+1]);

						data = g_new(struct name_data, 1);
						data->gc = gc;
						data->name = g_strdup(text[i*2+1]);
						data->nick = g_strdup(text[i*2+2]);

						purple_request_action(gc, NULL, message,
								_("Do you want to add this buddy "
								  "to your buddy list?"),
								PURPLE_DEFAULT_ACTION_NONE,
								purple_connection_get_account(gc), data->name, NULL,
								data, 2,
								_("_Add"), G_CALLBACK(purple_icq_buddyadd),
								_("_Decline"), G_CALLBACK(oscar_free_name_data));
						g_free(message);
					}
				} else {
					gchar *tmp = g_strescape(args->msg, NULL);
					purple_debug_error("oscar", "Unknown syntax parsing "
							"ICQ buddies.  args->msg=%s\n", tmp);
					g_free(tmp);
				}
				g_strfreev(text);
			}
		} break;

		case 0x1a: { /* Handle SMS or someone has sent you a greeting card or requested buddies? */
			ByteStream qbs;
			guint16 smstype;
			guint32 taglen, smslen;
			char *tagstr = NULL, *smsmsg = NULL;
			xmlnode *xmlroot = NULL, *xmltmp = NULL;
			gchar *uin = NULL, *message = NULL;

			/* From libicq2000-0.3.2/src/ICQ.cpp */
			byte_stream_init(&qbs, (guint8 *)args->msg, args->msglen);
			byte_stream_advance(&qbs, 21);
			/* expected:	01 00 00 20 00 0e 28 f6 00 11 e7 d3 11 bc f3 00 04 ac 96 9d c2 | 00 00 | 06 00 00 00 | 49 43 51 53 43 53 ...*/
			/* unexpected:	00 00 26 00 81 1a 18 bc 0e 6c 18 47 a5 91 6f 18 dc c7 6f 1a | 00 00 | 0d 00 00 00 | 49 43 51 57 65 62 4d 65 73 73 61 67 65 ... */
			smstype = byte_stream_getle16(&qbs);
			if (smstype != 0)
				break;
			taglen = byte_stream_getle32(&qbs);
			if (taglen > 2000) {
				/* Avoid trying to allocate large amounts of memory, in
				   case we get something unexpected. */
				break;
			}
			tagstr = byte_stream_getstr(&qbs, taglen);
			if (tagstr == NULL)
				break;
			byte_stream_advance(&qbs, 3);
			byte_stream_advance(&qbs, 4);
			smslen = byte_stream_getle32(&qbs);
			if (smslen > 2000) {
				/* Avoid trying to allocate large amounts of memory, in
				   case we get something unexpected. */
				g_free(tagstr);
				break;
			}
			smsmsg = byte_stream_getstr(&qbs, smslen);

			/* Check if this is an SMS being sent from server */
			if ((smstype == 0) && (!strcmp(tagstr, "ICQSMS")) && (smsmsg != NULL))
			{
				xmlroot = xmlnode_from_str(smsmsg, -1);
				if (xmlroot != NULL)
				{
					xmltmp = xmlnode_get_child(xmlroot, "sender");
					if (xmltmp != NULL)
						uin = xmlnode_get_data(xmltmp);

					xmltmp = xmlnode_get_child(xmlroot, "text");
					if (xmltmp != NULL)
						message = xmlnode_get_data(xmltmp);

					if ((uin != NULL) && (message != NULL))
							serv_got_im(gc, uin, message, 0, time(NULL));

					g_free(uin);
					g_free(message);
					xmlnode_free(xmlroot);
				}
			}
			g_free(tagstr);
			g_free(smsmsg);
		} break;

		default: {
			purple_debug_info("oscar",
					   "Received a channel 4 message of unknown type "
					   "(type 0x%02hhx).\n", args->type);
		} break;
	}

	g_strfreev(msg1);
	g_strfreev(msg2);

	return 1;
}

static int purple_parse_incoming_im(OscarData *od, FlapConnection *conn, FlapFrame *fr, ...) {
	guint16 channel;
	int ret = 0;
	aim_userinfo_t *userinfo;
	va_list ap;

	va_start(ap, fr);
	channel = (guint16)va_arg(ap, unsigned int);
	userinfo = va_arg(ap, aim_userinfo_t *);

	switch (channel) {
		case 1: { /* standard message */
			struct aim_incomingim_ch1_args *args;
			args = va_arg(ap, struct aim_incomingim_ch1_args *);
			ret = incomingim_chan1(od, conn, userinfo, args);
		} break;

		case 2: { /* rendezvous */
			IcbmArgsCh2 *args;
			args = va_arg(ap, IcbmArgsCh2 *);
			ret = incomingim_chan2(od, conn, userinfo, args);
		} break;

		case 4: { /* ICQ */
			struct aim_incomingim_ch4_args *args;
			args = va_arg(ap, struct aim_incomingim_ch4_args *);
			ret = incomingim_chan4(od, conn, userinfo, args, 0);
		} break;

		default: {
			purple_debug_warning("oscar",
					   "ICBM received on unsupported channel (channel "
					   "0x%04hx).", channel);
		} break;
	}

	va_end(ap);

	return ret;
}

static int purple_parse_misses(OscarData *od, FlapConnection *conn, FlapFrame *fr, ...) {
	PurpleConnection *gc = od->gc;
	PurpleAccount *account = purple_connection_get_account(gc);
	char *buf;
	va_list ap;
	guint16 chan, nummissed, reason;
	aim_userinfo_t *userinfo;

	va_start(ap, fr);
	chan = (guint16)va_arg(ap, unsigned int);
	userinfo = va_arg(ap, aim_userinfo_t *);
	nummissed = (guint16)va_arg(ap, unsigned int);
	reason = (guint16)va_arg(ap, unsigned int);
	va_end(ap);

	switch(reason) {
		case 0: /* Invalid (0) */
			buf = g_strdup_printf(
				   dngettext(PACKAGE,
				   "You missed %hu message from %s because it was invalid.",
				   "You missed %hu messages from %s because they were invalid.",
				   nummissed),
				   nummissed,
				   userinfo->bn);
			break;
		case 1: /* Message too large */
			buf = g_strdup_printf(
				   dngettext(PACKAGE,
				   "You missed %hu message from %s because it was too large.",
				   "You missed %hu messages from %s because they were too large.",
				   nummissed),
				   nummissed,
				   userinfo->bn);
			break;
		case 2: /* Rate exceeded */
			buf = g_strdup_printf(
				   dngettext(PACKAGE,
				   "You missed %hu message from %s because the rate limit has been exceeded.",
				   "You missed %hu messages from %s because the rate limit has been exceeded.",
				   nummissed),
				   nummissed,
				   userinfo->bn);
			break;
		case 3: /* Evil Sender */
			buf = g_strdup_printf(
				   dngettext(PACKAGE,
				   "You missed %hu message from %s because his/her warning level is too high.",
				   "You missed %hu messages from %s because his/her warning level is too high.",
				   nummissed),
				   nummissed,
				   userinfo->bn);
			break;
		case 4: /* Evil Receiver */
			buf = g_strdup_printf(
				   dngettext(PACKAGE,
				   "You missed %hu message from %s because your warning level is too high.",
				   "You missed %hu messages from %s because your warning level is too high.",
				   nummissed),
				   nummissed,
				   userinfo->bn);
			break;
		default:
			buf = g_strdup_printf(
				   dngettext(PACKAGE,
				   "You missed %hu message from %s for an unknown reason.",
				   "You missed %hu messages from %s for an unknown reason.",
				   nummissed),
				   nummissed,
				   userinfo->bn);
			break;
	}

	if (!purple_conv_present_error(userinfo->bn, account, buf))
		purple_notify_error(od->gc, NULL, buf, NULL);
	g_free(buf);

	return 1;
}

static int
purple_parse_clientauto_ch2(OscarData *od, const char *who, guint16 reason, const guchar *cookie)
{
	if (reason == 0x0003)
	{
		/* Rendezvous was refused. */
		PeerConnection *conn;

		conn = peer_connection_find_by_cookie(od, who, cookie);

		if (conn == NULL)
		{
			purple_debug_info("oscar", "Received a rendezvous cancel message "
					"for a nonexistant connection from %s.\n", who);
		}
		else
		{
			peer_connection_destroy(conn, OSCAR_DISCONNECT_REMOTE_REFUSED, NULL);
		}
	}
	else
	{
		purple_debug_warning("oscar", "Received an unknown rendezvous "
				"message from %s.  Type 0x%04hx\n", who, reason);
	}

	return 0;
}

static int purple_parse_clientauto_ch4(OscarData *od, char *who, guint16 reason, guint32 state, char *msg) {
	PurpleConnection *gc = od->gc;

	switch(reason) {
		case 0x0003: { /* Reply from an ICQ status message request */
			char *statusmsg, **splitmsg;
			PurpleNotifyUserInfo *user_info;

			/* Split at (carriage return/newline)'s, then rejoin later with BRs between. */
			statusmsg = oscar_icqstatus(state);
			splitmsg = g_strsplit(msg, "\r\n", 0);

			user_info = purple_notify_user_info_new();

			purple_notify_user_info_add_pair(user_info, _("UIN"), who);
			purple_notify_user_info_add_pair(user_info, _("Status"), statusmsg);
			purple_notify_user_info_add_section_break(user_info);
			purple_notify_user_info_add_pair(user_info, NULL, g_strjoinv("<BR>", splitmsg));

			g_free(statusmsg);
			g_strfreev(splitmsg);

			purple_notify_userinfo(gc, who, user_info, NULL, NULL);
			purple_notify_user_info_destroy(user_info);

		} break;

		case 0x0006: { /* Reply from an ICQ status message request */
			char *statusmsg, **splitmsg;
			PurpleNotifyUserInfo *user_info;

			/* Split at (carriage return/newline)'s, then rejoin later with BRs between. */
			statusmsg = oscar_icqstatus(state);
			splitmsg = g_strsplit(msg, "\r\n", 0);

			user_info = purple_notify_user_info_new();

			purple_notify_user_info_add_pair(user_info, _("UIN"), who);
			purple_notify_user_info_add_pair(user_info, _("Status"), statusmsg);
			purple_notify_user_info_add_section_break(user_info);
			purple_notify_user_info_add_pair(user_info, NULL, g_strjoinv("<BR>", splitmsg));

			g_free(statusmsg);
			g_strfreev(splitmsg);

			purple_notify_userinfo(gc, who, user_info, NULL, NULL);
			purple_notify_user_info_destroy(user_info);

		} break;

		default: {
			purple_debug_warning("oscar",
					   "Received an unknown client auto-response from %s.  "
					   "Type 0x%04hx\n", who, reason);
		} break;
	} /* end of switch */

	return 0;
}

static int purple_parse_clientauto(OscarData *od, FlapConnection *conn, FlapFrame *fr, ...) {
	va_list ap;
	guint16 chan, reason;
	char *who;
	int ret = 1;

	va_start(ap, fr);
	chan = (guint16)va_arg(ap, unsigned int);
	who = va_arg(ap, char *);
	reason = (guint16)va_arg(ap, unsigned int);

	if (chan == 0x0002) { /* File transfer declined */
		guchar *cookie = va_arg(ap, guchar *);
		ret = purple_parse_clientauto_ch2(od, who, reason, cookie);
	} else if (chan == 0x0004) { /* ICQ message */
		guint32 state = 0;
		char *msg = NULL;
		if (reason == 0x0003) {
			state = va_arg(ap, guint32);
			msg = va_arg(ap, char *);
		}
		ret = purple_parse_clientauto_ch4(od, who, reason, state, msg);
	}

	va_end(ap);

	return ret;
}

static int purple_parse_genericerr(OscarData *od, FlapConnection *conn, FlapFrame *fr, ...) {
	va_list ap;
	guint16 reason;

	va_start(ap, fr);
	reason = (guint16) va_arg(ap, unsigned int);
	va_end(ap);

	purple_debug_error("oscar", "snac threw error (reason 0x%04hx: %s)\n",
			reason, oscar_get_msgerr_reason(reason));
	return 1;
}

static int purple_parse_mtn(OscarData *od, FlapConnection *conn, FlapFrame *fr, ...) {
	PurpleConnection *gc = od->gc;
	va_list ap;
	guint16 channel, event;
	char *bn;

	va_start(ap, fr);
	channel = (guint16) va_arg(ap, unsigned int);
	bn = va_arg(ap, char *);
	event = (guint16) va_arg(ap, unsigned int);
	va_end(ap);

	switch (event) {
		case 0x0000: { /* Text has been cleared */
			serv_got_typing_stopped(gc, bn);
		} break;

		case 0x0001: { /* Paused typing */
			serv_got_typing(gc, bn, 0, PURPLE_TYPED);
		} break;

		case 0x0002: { /* Typing */
			serv_got_typing(gc, bn, 0, PURPLE_TYPING);
		} break;

		case 0x000f: { /* Closed IM window */
			serv_got_typing_stopped(gc, bn);
		} break;

		default: {
			purple_debug_info("oscar", "Received unknown typing "
					"notification message from %s.  Channel is 0x%04x "
					"and event is 0x%04hx.\n", bn, channel, event);
		} break;
	}

	return 1;
}

static int purple_parse_motd(OscarData *od, FlapConnection *conn, FlapFrame *fr, ...)
{
	char *msg;
	guint16 id;
	va_list ap;

	va_start(ap, fr);
	id  = (guint16) va_arg(ap, unsigned int);
	msg = va_arg(ap, char *);
	va_end(ap);

	purple_debug_misc("oscar",
			   "MOTD: %s (%hu)\n", msg ? msg : "Unknown", id);
	if (id < 4)
		purple_notify_warning(od->gc, NULL,
							_("Your AIM connection may be lost."), NULL);

	return 1;
}

static int purple_chatnav_info(OscarData *od, FlapConnection *conn, FlapFrame *fr, ...) {
	va_list ap;
	guint16 type;

	va_start(ap, fr);
	type = (guint16) va_arg(ap, unsigned int);

	switch(type) {
		case 0x0002: {
			GString *msg = g_string_new("");
			guint8 maxrooms;
			struct aim_chat_exchangeinfo *exchanges;
			int exchangecount, i;

			maxrooms = (guint8) va_arg(ap, unsigned int);
			exchangecount = va_arg(ap, int);
			exchanges = va_arg(ap, struct aim_chat_exchangeinfo *);

			g_string_append_printf(msg, "chat info: Max Concurrent Rooms: %hhd, Exchange List (%d total): ", maxrooms, exchangecount);
			for (i = 0; i < exchangecount; i++) {
				g_string_append_printf(msg, "%hu", exchanges[i].number);
				if (exchanges[i].name) {
					g_string_append_printf(msg, " %s", exchanges[i].name);
				}
				g_string_append(msg, ", ");
			}
			purple_debug_misc("oscar", "%s\n", msg->str);
			g_string_free(msg, TRUE);

			while (od->create_rooms) {
				struct create_room *cr = od->create_rooms->data;
				purple_debug_info("oscar",
						   "creating room %s\n", cr->name);
				aim_chatnav_createroom(od, conn, cr->name, cr->exchange);
				g_free(cr->name);
				od->create_rooms = g_slist_remove(od->create_rooms, cr);
				g_free(cr);
			}
			}
			break;
		case 0x0008: {
			char *fqcn, *name, *ck;
			guint16 instance, flags, maxmsglen, maxoccupancy, unknown, exchange;
			guint8 createperms;
			guint32 createtime;

			fqcn = va_arg(ap, char *);
			instance = (guint16)va_arg(ap, unsigned int);
			exchange = (guint16)va_arg(ap, unsigned int);
			flags = (guint16)va_arg(ap, unsigned int);
			createtime = va_arg(ap, guint32);
			maxmsglen = (guint16)va_arg(ap, unsigned int);
			maxoccupancy = (guint16)va_arg(ap, unsigned int);
			createperms = (guint8)va_arg(ap, unsigned int);
			unknown = (guint16)va_arg(ap, unsigned int);
			name = va_arg(ap, char *);
			ck = va_arg(ap, char *);

			purple_debug_misc("oscar",
					"created room: %s %hu %hu %hu %u %hu %hu %hhu %hu %s %s\n",
					fqcn ? fqcn : "(null)", exchange, instance, flags, createtime,
					maxmsglen, maxoccupancy, createperms, unknown,
					name ? name : "(null)", ck);
			aim_chat_join(od, exchange, ck, instance);
			}
			break;
		default:
			purple_debug_warning("oscar",
					   "chatnav info: unknown type (%04hx)\n", type);
			break;
	}

	va_end(ap);

	return 1;
}

static int purple_conv_chat_join(OscarData *od, FlapConnection *conn, FlapFrame *fr, ...) {
	va_list ap;
	int count, i;
	aim_userinfo_t *info;
	PurpleConnection *gc = od->gc;

	struct chat_connection *c = NULL;

	va_start(ap, fr);
	count = va_arg(ap, int);
	info  = va_arg(ap, aim_userinfo_t *);
	va_end(ap);

	c = find_oscar_chat_by_conn(gc, conn);
	if (!c)
		return 1;

	for (i = 0; i < count; i++)
		purple_conv_chat_add_user(PURPLE_CONV_CHAT(c->conv), info[i].bn, NULL, PURPLE_CBFLAGS_NONE, TRUE);

	return 1;
}

static int purple_conv_chat_leave(OscarData *od, FlapConnection *conn, FlapFrame *fr, ...) {
	va_list ap;
	int count, i;
	aim_userinfo_t *info;
	PurpleConnection *gc = od->gc;

	struct chat_connection *c = NULL;

	va_start(ap, fr);
	count = va_arg(ap, int);
	info  = va_arg(ap, aim_userinfo_t *);
	va_end(ap);

	c = find_oscar_chat_by_conn(gc, conn);
	if (!c)
		return 1;

	for (i = 0; i < count; i++)
		purple_conv_chat_remove_user(PURPLE_CONV_CHAT(c->conv), info[i].bn, NULL);

	return 1;
}

static int purple_conv_chat_info_update(OscarData *od, FlapConnection *conn, FlapFrame *fr, ...) {
	va_list ap;
	guint16 maxmsglen, maxvisiblemsglen;
	PurpleConnection *gc = od->gc;
	struct chat_connection *ccon = find_oscar_chat_by_conn(gc, conn);

	if (!ccon)
		return 1;

	va_start(ap, fr);
	maxmsglen = (guint16)va_arg(ap, unsigned int);
	maxvisiblemsglen = (guint16)va_arg(ap, unsigned int);
	va_end(ap);

	purple_debug_misc("oscar",
			   "inside chat_info_update (maxmsglen = %hu, maxvislen = %hu)\n",
			   maxmsglen, maxvisiblemsglen);

	ccon->maxlen = maxmsglen;
	ccon->maxvis = maxvisiblemsglen;

	return 1;
}

static int purple_conv_chat_incoming_msg(OscarData *od, FlapConnection *conn, FlapFrame *fr, ...) {
	PurpleConnection *gc = od->gc;
	struct chat_connection *ccon = find_oscar_chat_by_conn(gc, conn);
	gchar *utf8;
	va_list ap;
	aim_userinfo_t *info;
	int len;
	char *msg;
	char *charset;

	if (!ccon)
		return 1;

	va_start(ap, fr);
	info = va_arg(ap, aim_userinfo_t *);
	len = va_arg(ap, int);
	msg = va_arg(ap, char *);
	charset = va_arg(ap, char *);
	va_end(ap);

	utf8 = oscar_encoding_to_utf8(charset, msg, len);
	serv_got_chat_in(gc, ccon->id, info->bn, 0, utf8, time(NULL));
	g_free(utf8);

	return 1;
}

static int purple_email_parseupdate(OscarData *od, FlapConnection *conn, FlapFrame *fr, ...) {
	va_list ap;
	PurpleConnection *gc;
	PurpleAccount *account;
	struct aim_emailinfo *emailinfo;
	int havenewmail;
	char *alertitle, *alerturl;

	gc = od->gc;
	account = purple_connection_get_account(gc);

	va_start(ap, fr);
	emailinfo = va_arg(ap, struct aim_emailinfo *);
	havenewmail = va_arg(ap, int);
	alertitle = va_arg(ap, char *);
	alerturl  = va_arg(ap, char *);
	va_end(ap);

	if (account != NULL && emailinfo != NULL && purple_account_get_check_mail(account) &&
			emailinfo->unread && havenewmail) {
		gchar *to = g_strdup_printf("%s%s%s",
				purple_account_get_username(account),
				emailinfo->domain ? "@" : "",
				emailinfo->domain ? emailinfo->domain : "");
		const char *tos[2] = { to };
		const char *urls[2] = { emailinfo->url };
		purple_notify_emails(gc, emailinfo->nummsgs, FALSE, NULL, NULL,
				tos, urls, NULL, NULL);
		g_free(to);
	}

	if (alertitle)
		purple_debug_misc("oscar", "Got an alert '%s' %s\n", alertitle, alerturl ? alerturl : "");

	return 1;
}

static int purple_icon_parseicon(OscarData *od, FlapConnection *conn, FlapFrame *fr, ...) {
	PurpleConnection *gc = od->gc;
	va_list ap;
	char *bn;
	guint8 iconcsumtype, *iconcsum, *icon;
	guint16 iconcsumlen, iconlen;

	va_start(ap, fr);
	bn = va_arg(ap, char *);
	iconcsumtype = va_arg(ap, int);
	iconcsum = va_arg(ap, guint8 *);
	iconcsumlen = va_arg(ap, int);
	icon = va_arg(ap, guint8 *);
	iconlen = va_arg(ap, int);
	va_end(ap);

	/*
	 * Some AIM clients will send a blank GIF image with iconlen 90 when
	 * no icon is set.  Ignore these.
	 */
	if ((iconlen > 0) && (iconlen != 90)) {
		char *b16 = purple_base16_encode(iconcsum, iconcsumlen);
		purple_buddy_icons_set_for_user(purple_connection_get_account(gc),
									  bn, g_memdup(icon, iconlen), iconlen, b16);
		g_free(b16);
	}

	return 1;
}

static void
purple_icons_fetch(PurpleConnection *gc)
{
	OscarData *od = purple_connection_get_protocol_data(gc);
	aim_userinfo_t *userinfo;
	FlapConnection *conn;

	conn = flap_connection_getbytype(od, SNAC_FAMILY_BART);
	if (!conn) {
		if (!od->iconconnecting) {
			aim_srv_requestnew(od, SNAC_FAMILY_BART);
			od->iconconnecting = TRUE;
		}
		return;
	}

	if (od->set_icon) {
		PurpleAccount *account = purple_connection_get_account(gc);
		PurpleStoredImage *img = purple_buddy_icons_find_account_icon(account);
		if (img == NULL) {
			aim_ssi_delicon(od);
		} else {
			purple_debug_info("oscar",
				   "Uploading icon to icon server\n");
			aim_bart_upload(od, purple_imgstore_get_data(img),
			                purple_imgstore_get_size(img));
			purple_imgstore_unref(img);
		}
		od->set_icon = FALSE;
	}

	while (od->requesticon != NULL)
	{
		userinfo = aim_locate_finduserinfo(od, (char *)od->requesticon->data);
		if ((userinfo != NULL) && (userinfo->iconcsumlen > 0))
			aim_bart_request(od, od->requesticon->data, userinfo->iconcsumtype, userinfo->iconcsum, userinfo->iconcsumlen);

		g_free(od->requesticon->data);
		od->requesticon = g_slist_delete_link(od->requesticon, od->requesticon);
	}

	purple_debug_misc("oscar", "no more icons to request\n");
}

static int purple_selfinfo(OscarData *od, FlapConnection *conn, FlapFrame *fr, ...) {
	va_list ap;
	aim_userinfo_t *info;

	va_start(ap, fr);
	info = va_arg(ap, aim_userinfo_t *);
	va_end(ap);

	purple_connection_set_display_name(od->gc, info->bn);

	return 1;
}

static int purple_connerr(OscarData *od, FlapConnection *conn, FlapFrame *fr, ...) {
	PurpleConnection *gc = od->gc;
	va_list ap;
	guint16 code;
	char *msg;

	va_start(ap, fr);
	code = (guint16)va_arg(ap, int);
	msg = va_arg(ap, char *);
	va_end(ap);

	purple_debug_info("oscar", "Disconnected.  Code is 0x%04x and msg is %s\n",
					code, (msg != NULL ? msg : ""));

	g_return_val_if_fail(conn != NULL, 1);

	if (conn->type == SNAC_FAMILY_CHAT) {
		struct chat_connection *cc;
		PurpleConversation *conv = NULL;

		cc = find_oscar_chat_by_conn(gc, conn);
		if (cc != NULL)
		{
			conv = purple_find_chat(gc, cc->id);

			if (conv != NULL)
			{
				/*
				 * TOOD: Have flap_connection_destroy_cb() send us the
				 *       error message stored in 'tmp', which should be
				 *       human-friendly, and print that to the chat room.
				 */
				gchar *buf;
				buf = g_strdup_printf(_("You have been disconnected from chat "
										"room %s."), cc->name);
				purple_conversation_write(conv, NULL, buf, PURPLE_MESSAGE_ERROR, time(NULL));
				g_free(buf);
			}
			oscar_chat_kill(gc, cc);
		}
	}

	return 1;
}

static int purple_parse_locaterights(OscarData *od, FlapConnection *conn, FlapFrame *fr, ...)
{
	PurpleConnection *gc = od->gc;
	PurpleAccount *account = purple_connection_get_account(gc);
	va_list ap;
	guint16 maxsiglen;

	va_start(ap, fr);
	maxsiglen = (guint16) va_arg(ap, int);
	va_end(ap);

	purple_debug_misc("oscar",
			   "locate rights: max sig len = %d\n", maxsiglen);

	od->rights.maxsiglen = od->rights.maxawaymsglen = (guint)maxsiglen;

	aim_locate_setcaps(od, purple_caps);
	oscar_set_info_and_status(account, TRUE, account->user_info, TRUE,
							  purple_account_get_active_status(account));

	return 1;
}

static int purple_parse_buddyrights(OscarData *od, FlapConnection *conn, FlapFrame *fr, ...) {
	va_list ap;
	guint16 maxbuddies, maxwatchers;

	va_start(ap, fr);
	maxbuddies = (guint16) va_arg(ap, unsigned int);
	maxwatchers = (guint16) va_arg(ap, unsigned int);
	va_end(ap);

	purple_debug_misc("oscar",
			   "buddy list rights: Max buddies = %hu / Max watchers = %hu\n", maxbuddies, maxwatchers);

	od->rights.maxbuddies = (guint)maxbuddies;
	od->rights.maxwatchers = (guint)maxwatchers;

	return 1;
}

static void oscar_format_username(PurpleConnection *gc, const char *new_display_name)
{
	OscarData *od;
	const char *old_display_name, *username;
	char *tmp, *at_sign;

	old_display_name = purple_connection_get_display_name(gc);
	if (old_display_name && strchr(old_display_name, '@')) {
		purple_debug_info("oscar", "Cowardly refusing to attempt to format "
				"screen name because the current formatting according to "
				"the server (%s) appears to be an email address\n",
				old_display_name);
		return;
	}

	username = purple_account_get_username(purple_connection_get_account(gc));
	if (oscar_util_name_compare(username, new_display_name)) {
		purple_notify_error(gc, NULL, _("The new formatting is invalid."),
						  _("Username formatting can change only capitalization and whitespace."));
		return;
	}

	tmp = g_strdup(new_display_name);

	/*
	 * If our local username is an email address then strip off the domain.
	 * This allows formatting to work if the user entered their username as
	 * 'something@aim.com' or possibly other AOL-owned domains.
	 */
	at_sign = strchr(tmp, '@');
	if (at_sign)
		at_sign[0] = '\0';

	od = purple_connection_get_protocol_data(gc);
	if (!flap_connection_getbytype(od, SNAC_FAMILY_ADMIN)) {
		/* We don't have a connection to an "admin" server.  Make one. */
		od->setnick = TRUE;
		g_free(od->newformatting);
		od->newformatting = tmp;
		aim_srv_requestnew(od, SNAC_FAMILY_ADMIN);
	} else {
		aim_admin_setnick(od, flap_connection_getbytype(od, SNAC_FAMILY_ADMIN), tmp);
		g_free(tmp);
	}
}

static int purple_bosrights(OscarData *od, FlapConnection *conn, FlapFrame *fr, ...) {
	PurpleConnection *gc;
	PurpleAccount *account;
	PurpleStatus *status;
	gboolean is_available;
	PurplePresence *presence;
	const char *username, *message, *itmsurl;
	char *tmp;
	va_list ap;
	guint16 maxpermits, maxdenies;

	gc = od->gc;
	od = purple_connection_get_protocol_data(gc);
	account = purple_connection_get_account(gc);

	va_start(ap, fr);
	maxpermits = (guint16) va_arg(ap, unsigned int);
	maxdenies = (guint16) va_arg(ap, unsigned int);
	va_end(ap);

	purple_debug_misc("oscar",
			   "BOS rights: Max permit = %hu / Max deny = %hu\n", maxpermits, maxdenies);

	od->rights.maxpermits = (guint)maxpermits;
	od->rights.maxdenies = (guint)maxdenies;

	purple_debug_info("oscar", "buddy list loaded\n");

	if (purple_account_get_user_info(account) != NULL)
		serv_set_info(gc, purple_account_get_user_info(account));

	username = purple_account_get_username(account);
	if (!od->icq && strcmp(username, purple_connection_get_display_name(gc)) != 0) {
		/*
		 * Format the username for AIM accounts if it's different
		 * than what's currently set.
		 */
		oscar_format_username(gc, username);
	}

	/* Set our available message based on the current status */
	status = purple_account_get_active_status(account);
	is_available = purple_status_is_available(status);
	if (is_available)
		message = purple_status_get_attr_string(status, "message");
	else
		message = NULL;
	tmp = purple_markup_strip_html(message);
	itmsurl = purple_status_get_attr_string(status, "itmsurl");
	aim_srv_setextrainfo(od, FALSE, 0, is_available, tmp, itmsurl);
	aim_srv_set_dc_info(od);
	g_free(tmp);

	presence = purple_status_get_presence(status);
	aim_srv_setidle(od, !purple_presence_is_idle(presence) ? 0 : time(NULL) - purple_presence_get_idle_time(presence));

	if (od->icq) {
		oscar_set_extended_status(gc);
		aim_icq_setsecurity(od,
			purple_account_get_bool(account, "authorization", OSCAR_DEFAULT_AUTHORIZATION),
			purple_account_get_bool(account, "web_aware", OSCAR_DEFAULT_WEB_AWARE));
	}

	aim_srv_requestnew(od, SNAC_FAMILY_ALERT);
	aim_srv_requestnew(od, SNAC_FAMILY_CHATNAV);

	od->bos.have_rights = TRUE;

	/*
	 * If we've already received our feedbag data then we're not waiting on
	 * anything else, so send the server clientready.
	 *
	 * Normally we get bos rights before we get our feedbag data, so this
	 * rarely (never?) happens.  And I'm not sure it actually matters if we
	 * wait for bos rights before calling clientready.  But it seems safer
	 * to do it this way.
	 */
	if (od->ssi.received_data) {
		aim_srv_clientready(od, conn);

		/* Request offline messages for AIM and ICQ */
		aim_im_reqofflinemsgs(od);

		purple_connection_set_state(gc, PURPLE_CONNECTED);
	}

	return 1;
}

static int purple_popup(OscarData *od, FlapConnection *conn, FlapFrame *fr, ...)
{
	PurpleConnection *gc = od->gc;
	gchar *text;
	va_list ap;
	char *msg, *url;
	guint16 wid, hei, delay;

	va_start(ap, fr);
	msg = va_arg(ap, char *);
	url = va_arg(ap, char *);
	wid = (guint16) va_arg(ap, int);
	hei = (guint16) va_arg(ap, int);
	delay = (guint16) va_arg(ap, int);
	va_end(ap);

	text = g_strdup_printf("%s<br><a href=\"%s\">%s</a>", msg, url, url);
	purple_notify_formatted(gc, NULL, _("Pop-Up Message"), NULL, text, NULL, NULL);
	g_free(text);

	return 1;
}

static void oscar_searchresults_add_buddy_cb(PurpleConnection *gc, GList *row, void *user_data)
{
	purple_blist_request_add_buddy(purple_connection_get_account(gc),
								 g_list_nth_data(row, 0), NULL, NULL);
}

static int purple_parse_searchreply(OscarData *od, FlapConnection *conn, FlapFrame *fr, ...)
{
	PurpleConnection *gc = od->gc;
	PurpleNotifySearchResults *results;
	PurpleNotifySearchColumn *column;
	gchar *secondary;
	int i, num;
	va_list ap;
	char *email, *usernames;

	va_start(ap, fr);
	email = va_arg(ap, char *);
	num = va_arg(ap, int);
	usernames = va_arg(ap, char *);
	va_end(ap);

	results = purple_notify_searchresults_new();

	if (results == NULL) {
		purple_debug_error("oscar", "purple_parse_searchreply: "
						 "Unable to display the search results.\n");
		purple_notify_error(gc, NULL,
						  _("Unable to display the search results."),
						  NULL);
		return 1;
	}

	secondary = g_strdup_printf(
					dngettext(PACKAGE, "The following username is associated with %s",
						 "The following usernames are associated with %s",
						 num),
					email);

	column = purple_notify_searchresults_column_new(_("Username"));
	purple_notify_searchresults_column_add(results, column);

	for (i = 0; i < num; i++) {
		GList *row;
		row = g_list_append(NULL, g_strdup(&usernames[i * (MAXSNLEN + 1)]));
		purple_notify_searchresults_row_add(results, row);
	}
	purple_notify_searchresults_button_add(results, PURPLE_NOTIFY_BUTTON_ADD,
										 oscar_searchresults_add_buddy_cb);
	purple_notify_searchresults(gc, NULL, NULL, secondary, results, NULL, NULL);

	g_free(secondary);

	return 1;
}

static int purple_parse_searcherror(OscarData *od, FlapConnection *conn, FlapFrame *fr, ...) {
	va_list ap;
	char *email;
	char *buf;

	va_start(ap, fr);
	email = va_arg(ap, char *);
	va_end(ap);

	buf = g_strdup_printf(_("No results found for email address %s"), email);
	purple_notify_error(od->gc, NULL, buf, NULL);
	g_free(buf);

	return 1;
}

static int purple_account_confirm(OscarData *od, FlapConnection *conn, FlapFrame *fr, ...) {
	PurpleConnection *gc = od->gc;
	guint16 status;
	va_list ap;
	char msg[256];

	va_start(ap, fr);
	status = (guint16) va_arg(ap, unsigned int); /* status code of confirmation request */
	va_end(ap);

	purple_debug_info("oscar",
			   "account confirmation returned status 0x%04x (%s)\n", status,
			status ? "unknown" : "email sent");
	if (!status) {
		g_snprintf(msg, sizeof(msg), _("You should receive an email asking to confirm %s."),
				purple_account_get_username(purple_connection_get_account(gc)));
		purple_notify_info(gc, NULL, _("Account Confirmation Requested"), msg);
	}

	return 1;
}

static int purple_info_change(OscarData *od, FlapConnection *conn, FlapFrame *fr, ...) {
	PurpleConnection *gc = od->gc;
	va_list ap;
	guint16 perms, err;
	char *url, *bn, *email;
	int change;

	va_start(ap, fr);
	change = va_arg(ap, int);
	perms = (guint16) va_arg(ap, unsigned int);
	err = (guint16) va_arg(ap, unsigned int);
	url = va_arg(ap, char *);
	bn = va_arg(ap, char *);
	email = va_arg(ap, char *);
	va_end(ap);

	purple_debug_misc("oscar",
					"account info: because of %s, perms=0x%04x, err=0x%04x, url=%s, bn=%s, email=%s\n",
					change ? "change" : "request", perms, err,
					(url != NULL) ? url : "(null)",
					(bn != NULL) ? bn : "(null)",
					(email != NULL) ? email : "(null)");

	if ((err > 0) && (url != NULL)) {
		char *dialog_msg;

		if (err == 0x0001)
			dialog_msg = g_strdup_printf(_("Error 0x%04x: Unable to format username because the requested name differs from the original."), err);
		else if (err == 0x0006)
			dialog_msg = g_strdup_printf(_("Error 0x%04x: Unable to format username because it is invalid."), err);
		else if (err == 0x00b)
			dialog_msg = g_strdup_printf(_("Error 0x%04x: Unable to format username because the requested name is too long."), err);
		else if (err == 0x001d)
			dialog_msg = g_strdup_printf(_("Error 0x%04x: Unable to change email address because there is already a request pending for this username."), err);
		else if (err == 0x0021)
			dialog_msg = g_strdup_printf(_("Error 0x%04x: Unable to change email address because the given address has too many usernames associated with it."), err);
		else if (err == 0x0023)
			dialog_msg = g_strdup_printf(_("Error 0x%04x: Unable to change email address because the given address is invalid."), err);
		else
			dialog_msg = g_strdup_printf(_("Error 0x%04x: Unknown error."), err);
		purple_notify_error(gc, NULL,
				_("Error Changing Account Info"), dialog_msg);
		g_free(dialog_msg);
		return 1;
	}

	if (email != NULL) {
		char *dialog_msg = g_strdup_printf(_("The email address for %s is %s"),
						   purple_account_get_username(purple_connection_get_account(gc)), email);
		purple_notify_info(gc, NULL, _("Account Info"), dialog_msg);
		g_free(dialog_msg);
	}

	return 1;
}

void
oscar_keepalive(PurpleConnection *gc)
{
	OscarData *od;
	GSList *l;

	od = purple_connection_get_protocol_data(gc);
	for (l = od->oscar_connections; l; l = l->next) {
		flap_connection_send_keepalive(od, l->data);
	}
}

unsigned int
oscar_send_typing(PurpleConnection *gc, const char *name, PurpleTypingState state)
{
	OscarData *od;
	PeerConnection *conn;

	od = purple_connection_get_protocol_data(gc);
	conn = peer_connection_find_by_type(od, name, OSCAR_CAPABILITY_DIRECTIM);

	if ((conn != NULL) && (conn->ready))
	{
		peer_odc_send_typing(conn, state);
	}
	else {
		/* Don't send if this turkey is in our deny list */
		GSList *list;
		for (list=gc->account->deny; (list && oscar_util_name_compare(name, list->data)); list=list->next);
		if (!list) {
			struct buddyinfo *bi = g_hash_table_lookup(od->buddyinfo, purple_normalize(gc->account, name));
			if (bi && bi->typingnot) {
				if (state == PURPLE_TYPING)
					aim_im_sendmtn(od, 0x0001, name, 0x0002);
				else if (state == PURPLE_TYPED)
					aim_im_sendmtn(od, 0x0001, name, 0x0001);
				else
					aim_im_sendmtn(od, 0x0001, name, 0x0000);
			}
		}
	}
	return 0;
}

/* TODO: Move this into odc.c! */
static void
purple_odc_send_im(PeerConnection *conn, const char *message, PurpleMessageFlags imflags)
{
	GString *msg;
	GString *data;
	gchar *tmp;
	gsize tmplen;
	guint16 charset;
	GData *attribs;
	const char *start, *end, *last;
	int oscar_id = 0;

	msg = g_string_new("<HTML><BODY>");
	data = g_string_new("<BINARY>");
	last = message;

	/* for each valid IMG tag... */
	while (last && *last && purple_markup_find_tag("img", last, &start, &end, &attribs))
	{
		PurpleStoredImage *image = NULL;
		const char *id;

		if (start - last) {
			g_string_append_len(msg, last, start - last);
		}

		id = g_datalist_get_data(&attribs, "id");

		/* ... if it refers to a valid purple image ... */
		if (id && (image = purple_imgstore_find_by_id(atoi(id)))) {
			/* ... append the message from start to the tag ... */
			unsigned long size = purple_imgstore_get_size(image);
			const char *filename = purple_imgstore_get_filename(image);
			gconstpointer imgdata = purple_imgstore_get_data(image);

			oscar_id++;

			/* ... insert a new img tag with the oscar id ... */
			if (filename)
				g_string_append_printf(msg,
					"<IMG SRC=\"%s\" ID=\"%d\" DATASIZE=\"%lu\">",
					filename, oscar_id, size);
			else
				g_string_append_printf(msg,
					"<IMG ID=\"%d\" DATASIZE=\"%lu\">",
					oscar_id, size);

			/* ... and append the data to the binary section ... */
			g_string_append_printf(data, "<DATA ID=\"%d\" SIZE=\"%lu\">",
				oscar_id, size);
			g_string_append_len(data, imgdata, size);
			g_string_append(data, "</DATA>");
		}
			/* If the tag is invalid, skip it, thus no else here */

		g_datalist_clear(&attribs);

		/* continue from the end of the tag */
		last = end + 1;
	}

	/* append any remaining message data */
	if (last && *last)
		g_string_append(msg, last);

	g_string_append(msg, "</BODY></HTML>");

	/* Convert the message to a good encoding */
	tmp = oscar_encode_im(msg->str, &tmplen, &charset, NULL);
	g_string_free(msg, TRUE);
	msg = g_string_new_len(tmp, tmplen);
	g_free(tmp);

	/* Append any binary data that we may have */
	if (oscar_id) {
		msg = g_string_append_len(msg, data->str, data->len);
		msg = g_string_append(msg, "</BINARY>");
	}
	g_string_free(data, TRUE);

	purple_debug_info("oscar", "sending direct IM %s using charset %i", msg->str, charset);

	peer_odc_send_im(conn, msg->str, msg->len, charset,
			imflags & PURPLE_MESSAGE_AUTO_RESP);
	g_string_free(msg, TRUE);
}

int
oscar_send_im(PurpleConnection *gc, const char *name, const char *message, PurpleMessageFlags imflags)
{
	OscarData *od;
	PurpleAccount *account;
	PeerConnection *conn;
	int ret;
	char *tmp1, *tmp2;
	gboolean is_sms, is_html;

	od = purple_connection_get_protocol_data(gc);
	account = purple_connection_get_account(gc);
	ret = 0;

	is_sms = oscar_util_valid_name_sms(name);

	if (od->icq && is_sms) {
		/*
		 * We're sending to a phone number and this is ICQ,
		 * so send the message as an SMS using aim_icq_sendsms()
		 */
		int ret;
		purple_debug_info("oscar", "Sending SMS to %s.\n", name);
		ret = aim_icq_sendsms(od, name, message, purple_account_get_username(account));
		return (ret >= 0 ? 1 : ret);
	}

	if (imflags & PURPLE_MESSAGE_AUTO_RESP)
		tmp1 = oscar_util_format_string(message, name);
	else
		tmp1 = g_strdup(message);

	conn = peer_connection_find_by_type(od, name, OSCAR_CAPABILITY_DIRECTIM);
	if ((conn != NULL) && (conn->ready))
	{
		/* If we're directly connected, send a direct IM */
		purple_debug_info("oscar", "Sending direct IM with flags %i\n", imflags);
		purple_odc_send_im(conn, tmp1, imflags);
	} else {
		struct buddyinfo *bi;
		struct aim_sendimext_args args;
		PurpleConversation *conv;
		PurpleStoredImage *img;
		PurpleBuddy *buddy;

		conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, name, account);

		if (strstr(tmp1, "<IMG "))
			purple_conversation_write(conv, "",
			                        _("Your IM Image was not sent. "
			                        "You must be Direct Connected to send IM Images."),
			                        PURPLE_MESSAGE_ERROR, time(NULL));

		buddy = purple_find_buddy(account, name);

		bi = g_hash_table_lookup(od->buddyinfo, purple_normalize(account, name));
		if (!bi) {
			bi = g_new0(struct buddyinfo, 1);
			g_hash_table_insert(od->buddyinfo, g_strdup(purple_normalize(account, name)), bi);
		}

		args.flags = 0;

		if (!is_sms && (!buddy || !PURPLE_BUDDY_IS_ONLINE(buddy)))
			args.flags |= AIM_IMFLAGS_OFFLINE;

		if (od->icq) {
			args.features = features_icq;
			args.featureslen = sizeof(features_icq);
		} else {
			args.features = features_aim;
			args.featureslen = sizeof(features_aim);

			if (imflags & PURPLE_MESSAGE_AUTO_RESP)
				args.flags |= AIM_IMFLAGS_AWAY;
		}

		if (bi->ico_need) {
			purple_debug_info("oscar",
					   "Sending buddy icon request with message\n");
			args.flags |= AIM_IMFLAGS_BUDDYREQ;
			bi->ico_need = FALSE;
		}

		img = purple_buddy_icons_find_account_icon(account);
		if (img) {
			gconstpointer data = purple_imgstore_get_data(img);
			args.iconlen = purple_imgstore_get_size(img);
			args.iconsum = aimutil_iconsum(data, args.iconlen);
			args.iconstamp = purple_buddy_icons_get_account_icon_timestamp(account);

			if ((args.iconlen != bi->ico_me_len) || (args.iconsum != bi->ico_me_csum) || (args.iconstamp != bi->ico_me_time)) {
				bi->ico_informed = FALSE;
				bi->ico_sent     = FALSE;
			}

			/*
			 * TODO:
			 * For some reason sending our icon to people only works
			 * when we're the ones who initiated the conversation.  If
			 * the other person sends the first IM then they never get
			 * the icon.  We should fix that.
			 */
			if (!bi->ico_informed) {
				purple_debug_info("oscar",
						   "Claiming to have a buddy icon\n");
				args.flags |= AIM_IMFLAGS_HASICON;
				bi->ico_me_len = args.iconlen;
				bi->ico_me_csum = args.iconsum;
				bi->ico_me_time = args.iconstamp;
				bi->ico_informed = TRUE;
			}

			purple_imgstore_unref(img);
		}

		args.destbn = name;

		if (oscar_util_valid_name_sms(name)) {
			/* Messaging an SMS (mobile) user--strip HTML */
			tmp2 = purple_markup_strip_html(tmp1);
			is_html = FALSE;
		} else {
			/* ICQ 6 wants its HTML wrapped in these tags. Oblige it. */
			tmp2 = g_strdup_printf("<HTML><BODY>%s</BODY></HTML>", tmp1);
			is_html = TRUE;
		}
		g_free(tmp1);
		tmp1 = tmp2;

		args.msg = oscar_encode_im(tmp1, &args.msglen, &args.charset, NULL);
		if (is_html && (args.msglen > MAXMSGLEN)) {
			/* If the length was too long, try stripping the HTML and then running it back through
			* purple_strdup_withhtml() and the encoding process. The result may be shorter. */
			g_free((char *)args.msg);

			tmp2 = purple_markup_strip_html(tmp1);
			g_free(tmp1);

			/* re-escape the entities */
			tmp1 = g_markup_escape_text(tmp2, -1);
			g_free(tmp2);

			tmp2 = purple_strdup_withhtml(tmp1);
			g_free(tmp1);
			tmp1 = tmp2;

			args.msg = oscar_encode_im(tmp1, &args.msglen, &args.charset, NULL);
			purple_debug_info("oscar", "Sending %s as %s because the original was too long.\n",
								  message, (char *)args.msg);
		}

		purple_debug_info("oscar", "Sending IM, charset=0x%04hx, length=%" G_GSIZE_FORMAT "\n", args.charset, args.msglen);
		ret = aim_im_sendch1_ext(od, &args);
		g_free((char *)args.msg);
	}

	g_free(tmp1);

	if (ret >= 0)
		return 1;

	return ret;
}

/*
 * As of 26 June 2006, ICQ users can request AIM info from
 * everyone, and can request ICQ info from ICQ users, and
 * AIM users can only request AIM info.
 */
void oscar_get_info(PurpleConnection *gc, const char *name) {
	OscarData *od = purple_connection_get_protocol_data(gc);

	if (od->icq && oscar_util_valid_name_icq(name))
		aim_icq_getallinfo(od, name);
	else
		aim_locate_getinfoshort(od, name, 0x00000003);
}

void oscar_set_idle(PurpleConnection *gc, int time) {
	OscarData *od = purple_connection_get_protocol_data(gc);
	aim_srv_setidle(od, time);
}

void
oscar_set_info(PurpleConnection *gc, const char *rawinfo)
{
	PurpleAccount *account;
	PurpleStatus *status;

	account = purple_connection_get_account(gc);
	status = purple_account_get_active_status(account);
	oscar_set_info_and_status(account, TRUE, rawinfo, FALSE, status);
}

static guint32
oscar_get_extended_status(PurpleConnection *gc)
{
	PurpleAccount *account;
	PurpleStatus *status;
	const gchar *status_id;
	guint32 data = 0x00000000;

	account = purple_connection_get_account(gc);
	status = purple_account_get_active_status(account);
	status_id = purple_status_get_id(status);

	data |= AIM_ICQ_STATE_HIDEIP;
	if (purple_account_get_bool(account, "web_aware", OSCAR_DEFAULT_WEB_AWARE))
		data |= AIM_ICQ_STATE_WEBAWARE;

	if (!strcmp(status_id, OSCAR_STATUS_ID_AVAILABLE))
		data |= AIM_ICQ_STATE_NORMAL;
	else if (!strcmp(status_id, OSCAR_STATUS_ID_AWAY))
		data |= AIM_ICQ_STATE_AWAY;
	else if (!strcmp(status_id, OSCAR_STATUS_ID_DND))
		data |= AIM_ICQ_STATE_AWAY | AIM_ICQ_STATE_DND | AIM_ICQ_STATE_BUSY;
	else if (!strcmp(status_id, OSCAR_STATUS_ID_NA))
		data |= AIM_ICQ_STATE_OUT | AIM_ICQ_STATE_AWAY;
	else if (!strcmp(status_id, OSCAR_STATUS_ID_OCCUPIED))
		data |= AIM_ICQ_STATE_AWAY | AIM_ICQ_STATE_BUSY;
	else if (!strcmp(status_id, OSCAR_STATUS_ID_FREE4CHAT))
		data |= AIM_ICQ_STATE_CHAT;
	else if (!strcmp(status_id, OSCAR_STATUS_ID_INVISIBLE))
		data |= AIM_ICQ_STATE_INVISIBLE;
	else if (!strcmp(status_id, OSCAR_STATUS_ID_EVIL))
		data |= AIM_ICQ_STATE_EVIL;
	else if (!strcmp(status_id, OSCAR_STATUS_ID_DEPRESSION))
		data |= AIM_ICQ_STATE_DEPRESSION;
	else if (!strcmp(status_id, OSCAR_STATUS_ID_ATWORK))
		data |= AIM_ICQ_STATE_ATWORK;
	else if (!strcmp(status_id, OSCAR_STATUS_ID_ATHOME))
		data |= AIM_ICQ_STATE_ATHOME;
	else if (!strcmp(status_id, OSCAR_STATUS_ID_LUNCH))
		data |= AIM_ICQ_STATE_LUNCH;
	else if (!strcmp(status_id, OSCAR_STATUS_ID_CUSTOM))
		data |= AIM_ICQ_STATE_OUT | AIM_ICQ_STATE_AWAY;

	return data;
}

static void
oscar_set_extended_status(PurpleConnection *gc)
{
	aim_srv_setextrainfo(purple_connection_get_protocol_data(gc), TRUE, oscar_get_extended_status(gc), FALSE, NULL, NULL);
}

static void
oscar_set_info_and_status(PurpleAccount *account, gboolean setinfo, const char *rawinfo,
						  gboolean setstatus, PurpleStatus *status)
{
	PurpleConnection *gc = purple_account_get_connection(account);
	OscarData *od = purple_connection_get_protocol_data(gc);
	PurpleStatusType *status_type;
	PurpleStatusPrimitive primitive;

	char *info_encoding = NULL;
	char *info = NULL;
	gsize infolen = 0;

	char *away_encoding = NULL;
	char *away = NULL;
	gsize awaylen = 0;

	char *status_text = NULL;
	const char *itmsurl = NULL;

	status_type = purple_status_get_type(status);
	primitive = purple_status_type_get_primitive(status_type);

	if (!setinfo)
	{
		/* Do nothing! */
	}
	else if (od->rights.maxsiglen == 0)
	{
		purple_notify_warning(gc, NULL, _("Unable to set AIM profile."),
							_("You have probably requested to set your "
							  "profile before the login procedure completed.  "
							  "Your profile remains unset; try setting it "
							  "again when you are fully connected."));
	}
	else if (rawinfo != NULL)
	{
		char *htmlinfo = purple_strdup_withhtml(rawinfo);
		info = oscar_encode_im(htmlinfo, &infolen, NULL, &info_encoding);
		g_free(htmlinfo);

		if (infolen > od->rights.maxsiglen)
		{
			gchar *errstr;
			errstr = g_strdup_printf(dngettext(PACKAGE, "The maximum profile length of %d byte "
									 "has been exceeded.  It has been truncated for you.",
									 "The maximum profile length of %d bytes "
									 "has been exceeded.  It has been truncated for you.",
									 od->rights.maxsiglen), od->rights.maxsiglen);
			purple_notify_warning(gc, NULL, _("Profile too long."), errstr);
			g_free(errstr);
		}
	}

	if (setstatus)
	{
		const char *status_html;

		status_html = purple_status_get_attr_string(status, "message");

		if (status_html == NULL || primitive == PURPLE_STATUS_AVAILABLE || primitive == PURPLE_STATUS_INVISIBLE)
		{
			/* This is needed for us to un-set any previous away message. */
			away = g_strdup("");
		}
		else
		{
			gchar *linkified;

			/* We do this for icq too so that they work for old third party clients */
			linkified = purple_markup_linkify(status_html);
			away = oscar_encode_im(linkified, &awaylen, NULL, &away_encoding);
			g_free(linkified);

			if (awaylen > od->rights.maxawaymsglen)
			{
				gchar *errstr;

				errstr = g_strdup_printf(dngettext(PACKAGE, "The maximum away message length of %d byte "
										 "has been exceeded.  It has been truncated for you.",
										 "The maximum away message length of %d bytes "
										 "has been exceeded.  It has been truncated for you.",
										 od->rights.maxawaymsglen), od->rights.maxawaymsglen);
				purple_notify_warning(gc, NULL, _("Away message too long."), errstr);
				g_free(errstr);
			}
		}
	}

	aim_locate_setprofile(od,
			info_encoding, info, MIN(infolen, od->rights.maxsiglen),
			away_encoding, away, MIN(awaylen, od->rights.maxawaymsglen));
	g_free(info);
	g_free(away);

	if (setstatus)
	{
		const char *status_html;

		status_html = purple_status_get_attr_string(status, "message");
		if (status_html != NULL)
		{
			status_text = purple_markup_strip_html(status_html);
			/* If the status_text is longer than 251 characters then truncate it */
			if (strlen(status_text) > MAXAVAILMSGLEN)
			{
				char *tmp = g_utf8_find_prev_char(status_text, &status_text[MAXAVAILMSGLEN - 2]);
				strcpy(tmp, "...");
			}
		}

		itmsurl = purple_status_get_attr_string(status, "itmsurl");

		aim_srv_setextrainfo(od, TRUE, oscar_get_extended_status(gc), TRUE, status_text, itmsurl);
		g_free(status_text);
	}
}

static void
oscar_set_icq_permdeny(PurpleAccount *account)
{
	PurpleConnection *gc = purple_account_get_connection(account);
	OscarData *od = purple_connection_get_protocol_data(gc);
	gboolean invisible = purple_account_is_status_active(account, OSCAR_STATUS_ID_INVISIBLE);

	/*
	 * For ICQ the permit/deny setting controls who can see you
	 * online. Mimicking the official client's behavior, we use PURPLE_PRIVACY_ALLOW_USERS
	 * when our status is "invisible" and PURPLE_PRIVACY_DENY_USERS otherwise.
	 * In the former case, we are visible only to buddies on our "permanently visible" list.
	 * In the latter, we are invisible only to buddies on our "permanently invisible" list.
	 */
	aim_ssi_setpermdeny(od, invisible ? PURPLE_PRIVACY_ALLOW_USERS : PURPLE_PRIVACY_DENY_USERS);
}

void
oscar_set_status(PurpleAccount *account, PurpleStatus *status)
{
	PurpleConnection *pc;
	OscarData *od;

	purple_debug_info("oscar", "Set status to %s\n", purple_status_get_name(status));

	/* Either setting a new status active or setting a status inactive.
	 * (Only possible for independent status (i.e. X-Status moods.) */
	if (!purple_status_is_active(status) && !purple_status_is_independent(status))
		return;

	if (!purple_account_is_connected(account))
		return;

	pc = purple_account_get_connection(account);
	od = purple_connection_get_protocol_data(pc);

	/* There's no need to do the stuff below for mood updates. */
	if (purple_status_type_get_primitive(purple_status_get_type(status)) == PURPLE_STATUS_MOOD) {
		aim_locate_setcaps(od, purple_caps);
		return;
	}

	if (od->icq) {
		/* Set visibility */
		oscar_set_icq_permdeny(account);
	}

	/* Set the AIM-style away message for both AIM and ICQ accounts */
	oscar_set_info_and_status(account, FALSE, NULL, TRUE, status);
}

void
oscar_add_buddy(PurpleConnection *gc, PurpleBuddy *buddy, PurpleGroup *group, const char *msg)
{
	OscarData *od;
	PurpleAccount *account;
	const char *bname, *gname;

	od = purple_connection_get_protocol_data(gc);
	account = purple_connection_get_account(gc);
	bname = purple_buddy_get_name(buddy);
	gname = purple_group_get_name(group);

	if (!oscar_util_valid_name(bname)) {
		gchar *buf;
		buf = g_strdup_printf(_("Unable to add the buddy %s because the username is invalid.  Usernames must be a valid email address, or start with a letter and contain only letters, numbers and spaces, or contain only numbers."), bname);
		if (!purple_conv_present_error(bname, account, buf))
			purple_notify_error(gc, NULL, _("Unable to Add"), buf);
		g_free(buf);

		/* Remove from local list */
		purple_blist_remove_buddy(buddy);

		return;
	}

	if (od->ssi.received_data) {
		if (!aim_ssi_itemlist_finditem(od->ssi.local, gname, bname, AIM_SSI_TYPE_BUDDY)) {
			purple_debug_info("oscar",
					   "ssi: adding buddy %s to group %s\n", bname, gname);
			aim_ssi_addbuddy(od, bname, gname, NULL, purple_buddy_get_alias_only(buddy), NULL, NULL, 0);

			/* Mobile users should always be online */
			if (bname[0] == '+') {
				purple_prpl_got_user_status(account, bname,
						OSCAR_STATUS_ID_AVAILABLE, NULL);
				purple_prpl_got_user_status(account, bname,
						OSCAR_STATUS_ID_MOBILE, NULL);
			}
		} else if (aim_ssi_waitingforauth(od->ssi.local,
		                                  aim_ssi_itemlist_findparentname(od->ssi.local, bname),
		                                  bname)) {
			/* Not authorized -- Re-request authorization */
			oscar_auth_sendrequest(gc, bname, msg);
		}
	}

	/* XXX - Should this be done from AIM accounts, as well? */
	if (od->icq)
		aim_icq_getalias(od, bname, FALSE, NULL);
}

void oscar_remove_buddy(PurpleConnection *gc, PurpleBuddy *buddy, PurpleGroup *group) {
	OscarData *od = purple_connection_get_protocol_data(gc);

	if (od->ssi.received_data) {
		const char *gname = purple_group_get_name(group);
		const char *bname = purple_buddy_get_name(buddy);
		purple_debug_info("oscar",
				   "ssi: deleting buddy %s from group %s\n", bname, gname);
		aim_ssi_delbuddy(od, bname, gname);
	}
}

void oscar_move_buddy(PurpleConnection *gc, const char *name, const char *old_group, const char *new_group) {
	OscarData *od = purple_connection_get_protocol_data(gc);

	if (od->ssi.received_data && strcmp(old_group, new_group)) {
		purple_debug_info("oscar",
				   "ssi: moving buddy %s from group %s to group %s\n", name, old_group, new_group);
		aim_ssi_movebuddy(od, old_group, new_group, name);
	}
}

void oscar_alias_buddy(PurpleConnection *gc, const char *name, const char *alias) {
	OscarData *od = purple_connection_get_protocol_data(gc);

	if (od->ssi.received_data) {
		char *gname = aim_ssi_itemlist_findparentname(od->ssi.local, name);
		if (gname) {
			purple_debug_info("oscar",
					   "ssi: changing the alias for buddy %s to %s\n", name, alias ? alias : "(none)");
			aim_ssi_aliasbuddy(od, gname, name, alias);
		}
	}
}

/*
 * FYI, the OSCAR SSI code removes empty groups automatically.
 */
void oscar_rename_group(PurpleConnection *gc, const char *old_name, PurpleGroup *group, GList *moved_buddies) {
	OscarData *od = purple_connection_get_protocol_data(gc);

	if (od->ssi.received_data) {
		const char *gname = purple_group_get_name(group);
		if (aim_ssi_itemlist_finditem(od->ssi.local, gname, NULL, AIM_SSI_TYPE_GROUP)) {
			GList *cur, *groups = NULL;
			PurpleAccount *account = purple_connection_get_account(gc);

			/* Make a list of what the groups each buddy is in */
			for (cur = moved_buddies; cur != NULL; cur = cur->next) {
				PurpleBlistNode *node = cur->data;
				/* node is PurpleBuddy, parent is a PurpleContact.
				 * We must go two levels up to get the Group */
				groups = g_list_append(groups,
						purple_buddy_get_group((PurpleBuddy*)node));
			}

			purple_account_remove_buddies(account, moved_buddies, groups);
			purple_account_add_buddies(account, moved_buddies);
			g_list_free(groups);
			purple_debug_info("oscar",
					   "ssi: moved all buddies from group %s to %s\n", old_name, gname);
		} else {
			aim_ssi_rename_group(od, old_name, gname);
			purple_debug_info("oscar",
					   "ssi: renamed group %s to %s\n", old_name, gname);
		}
	}
}

void oscar_remove_group(PurpleConnection *gc, PurpleGroup *group)
{
	aim_ssi_delgroup(purple_connection_get_protocol_data(gc), purple_group_get_name(group));
}

static gboolean purple_ssi_rerequestdata(gpointer data) {
	OscarData *od = data;

	aim_ssi_reqdata(od);

	return TRUE;
}

static int purple_ssi_parseerr(OscarData *od, FlapConnection *conn, FlapFrame *fr, ...) {
	PurpleConnection *gc = od->gc;
	va_list ap;
	guint16 reason;

	va_start(ap, fr);
	reason = (guint16)va_arg(ap, unsigned int);
	va_end(ap);

	purple_debug_error("oscar", "ssi: SNAC error %hu\n", reason);

	if (reason == 0x0005) {
		if (od->getblisttimer > 0)
			purple_timeout_remove(od->getblisttimer);
		else
			/* We only show this error the first time it happens */
			purple_notify_error(gc, NULL,
					_("Unable to Retrieve Buddy List"),
					_("The AIM servers were temporarily unable to send "
					"your buddy list.  Your buddy list is not lost, and "
					"will probably become available in a few minutes."));
		od->getblisttimer = purple_timeout_add_seconds(30, purple_ssi_rerequestdata, od);
		return 1;
	}

	return 1;
}

static int purple_ssi_parserights(OscarData *od, FlapConnection *conn, FlapFrame *fr, ...) {
	int i;
	va_list ap;
	int numtypes;
	guint16 *maxitems;
	GString *msg;

	va_start(ap, fr);
	numtypes = va_arg(ap, int);
	maxitems = va_arg(ap, guint16 *);
	va_end(ap);

	msg = g_string_new("ssi rights:");
	for (i=0; i<numtypes; i++)
		g_string_append_printf(msg, " max type 0x%04x=%hd,", i, maxitems[i]);
	g_string_append(msg, "\n");
	purple_debug_misc("oscar", "%s", msg->str);
	g_string_free(msg, TRUE);

	if (numtypes >= 0)
		od->rights.maxbuddies = maxitems[0];
	if (numtypes >= 1)
		od->rights.maxgroups = maxitems[1];
	if (numtypes >= 2)
		od->rights.maxpermits = maxitems[2];
	if (numtypes >= 3)
		od->rights.maxdenies = maxitems[3];

	return 1;
}

static int purple_ssi_parselist(OscarData *od, FlapConnection *conn, FlapFrame *fr, ...)
{
	PurpleConnection *gc;
	PurpleAccount *account;
	PurpleGroup *g;
	PurpleBuddy *b;
	GSList *cur, *next, *buddies;
	struct aim_ssi_item *curitem;
	guint32 tmp;
	PurpleStoredImage *img;
	va_list ap;
	guint16 fmtver, numitems;
	guint32 timestamp;
	guint16 deny_entry_type = aim_ssi_getdenyentrytype(od);

	gc = od->gc;
	od = purple_connection_get_protocol_data(gc);
	account = purple_connection_get_account(gc);

	va_start(ap, fr);
	fmtver = (guint16)va_arg(ap, int);
	numitems = (guint16)va_arg(ap, int);
	timestamp = va_arg(ap, guint32);
	va_end(ap);

	/* Don't attempt to re-request our buddy list later */
	if (od->getblisttimer != 0) {
		purple_timeout_remove(od->getblisttimer);
		od->getblisttimer = 0;
	}

	purple_debug_info("oscar", "ssi: syncing local list and server list\n");

	/* Clean the buddy list */
	aim_ssi_cleanlist(od);

	/*** Begin code for pruning buddies from local list if they're not in server list ***/

	/* Buddies */
	cur = NULL;
	for (buddies = purple_find_buddies(account, NULL);
			buddies;
			buddies = g_slist_delete_link(buddies, buddies))
	{
		PurpleGroup *g;
		const char *gname;
		const char *bname;

		b = buddies->data;
		g = purple_buddy_get_group(b);
		gname = purple_group_get_name(g);
		bname = purple_buddy_get_name(b);

		if (aim_ssi_itemlist_exists(od->ssi.local, bname)) {
			/* If the buddy is an ICQ user then load his nickname */
			const char *servernick = purple_blist_node_get_string((PurpleBlistNode*)b, "servernick");
			char *alias;
			const char *balias;
			if (servernick)
				serv_got_alias(gc, bname, servernick);

			/* Store local alias on server */
			alias = aim_ssi_getalias(od->ssi.local, gname, bname);
			balias = purple_buddy_get_local_buddy_alias(b);
			if (!alias && balias && *balias)
				aim_ssi_aliasbuddy(od, gname, bname, balias);
			g_free(alias);
		} else {
			purple_debug_info("oscar",
					"ssi: removing buddy %s from local list\n", bname);
			/* Queue the buddy for removal from the local list */
			cur = g_slist_prepend(cur, b);
		}
	}
	while (cur != NULL) {
		purple_blist_remove_buddy(cur->data);
		cur = g_slist_delete_link(cur, cur);
	}

	/* Permit list (ICQ doesn't have one) */
	if (!od->icq) {
		next = account->permit;
		while (next != NULL) {
			cur = next;
			next = next->next;
			if (!aim_ssi_itemlist_finditem(od->ssi.local, NULL, cur->data, AIM_SSI_TYPE_PERMIT)) {
				purple_debug_info("oscar",
						"ssi: removing permit %s from local list\n", (const char *)cur->data);
				purple_privacy_permit_remove(account, cur->data, TRUE);
			}
		}
	}

	/* Deny list */
	next = account->deny;
	while (next != NULL) {
		cur = next;
		next = next->next;
		if (!aim_ssi_itemlist_finditem(od->ssi.local, NULL, cur->data, deny_entry_type)) {
			purple_debug_info("oscar",
					"ssi: removing deny %s from local list\n", (const char *)cur->data);
			purple_privacy_deny_remove(account, cur->data, TRUE);
		}
	}

	/* Presence settings (idle time visibility) */
	tmp = aim_ssi_getpresence(od->ssi.local);
	if (tmp != 0xFFFFFFFF) {
		const char *idle_reporting_pref;
		gboolean report_idle;

		idle_reporting_pref = purple_prefs_get_string("/purple/away/idle_reporting");
		report_idle = strcmp(idle_reporting_pref, "none") != 0;

		if (report_idle)
			aim_ssi_setpresence(od, tmp | AIM_SSI_PRESENCE_FLAG_SHOWIDLE);
		else
			aim_ssi_setpresence(od, tmp & ~AIM_SSI_PRESENCE_FLAG_SHOWIDLE);
	}

	/*** End code for pruning buddies from local list ***/

	/*** Begin code for adding from server list to local list ***/

	for (curitem=od->ssi.local; curitem; curitem=curitem->next) {
		if (curitem->name && !g_utf8_validate(curitem->name, -1, NULL)) {
			/* Got node with invalid UTF-8 in the name.  Skip it. */
			purple_debug_warning("oscar", "ssi: server list contains item of "
					"type 0x%04hhx with a non-utf8 name\n", curitem->type);
			continue;
		}

		switch (curitem->type) {
			case AIM_SSI_TYPE_BUDDY: { /* Buddy */
				if (curitem->name) {
					struct aim_ssi_item *groupitem;
					char *gname, *gname_utf8, *alias, *alias_utf8;

					groupitem = aim_ssi_itemlist_find(od->ssi.local, curitem->gid, 0x0000);
					gname = groupitem ? groupitem->name : NULL;
					gname_utf8 = oscar_utf8_try_convert(account, od, gname);

					g = purple_find_group(gname_utf8 ? gname_utf8 : _("Orphans"));
					if (g == NULL) {
						g = purple_group_new(gname_utf8 ? gname_utf8 : _("Orphans"));
						purple_blist_add_group(g, NULL);
					}

					alias = aim_ssi_getalias(od->ssi.local, gname, curitem->name);
					alias_utf8 = oscar_utf8_try_convert(account, od, alias);

					b = purple_find_buddy_in_group(account, curitem->name, g);
					if (b) {
						/* Get server stored alias */
						purple_blist_alias_buddy(b, alias_utf8);
					} else {
						b = purple_buddy_new(account, curitem->name, alias_utf8);

						purple_debug_info("oscar",
								   "ssi: adding buddy %s to group %s to local list\n", curitem->name, gname);
						purple_blist_add_buddy(b, NULL, g, NULL);
					}

					/* Mobile users should always be online */
					if (curitem->name[0] == '+') {
						purple_prpl_got_user_status(account,
								purple_buddy_get_name(b),
								OSCAR_STATUS_ID_AVAILABLE, NULL);
						purple_prpl_got_user_status(account,
								purple_buddy_get_name(b),
								OSCAR_STATUS_ID_MOBILE, NULL);
					}

					g_free(gname_utf8);
					g_free(alias);
					g_free(alias_utf8);
				}
			} break;

			case AIM_SSI_TYPE_GROUP: { /* Group */
				if (curitem->name != NULL && purple_find_group(curitem->name) == NULL) {
					g = purple_group_new(curitem->name);
					purple_blist_add_group(g, NULL);
				}
			} break;

			case AIM_SSI_TYPE_PERMIT: { /* Permit buddy (unless we're on ICQ) */
				if (!od->icq && curitem->name) {
					for (cur = account->permit; (cur && oscar_util_name_compare(curitem->name, cur->data)); cur = cur->next);
					if (!cur) {
						purple_debug_info("oscar",
								   "ssi: adding permit buddy %s to local list\n", curitem->name);
						purple_privacy_permit_add(account, curitem->name, TRUE);
					}
				}
			} break;

			case AIM_SSI_TYPE_ICQDENY:
			case AIM_SSI_TYPE_DENY: { /* Deny buddy */
				if (curitem->type == deny_entry_type && curitem->name) {
					for (cur = account->deny; (cur && oscar_util_name_compare(curitem->name, cur->data)); cur = cur->next);
					if (!cur) {
						purple_debug_info("oscar",
								   "ssi: adding deny buddy %s to local list\n", curitem->name);
						purple_privacy_deny_add(account, curitem->name, TRUE);
					}
				}
			} break;

			case AIM_SSI_TYPE_PDINFO: { /* Permit/deny setting */
				/*
				 * We don't inherit the permit/deny setting from the server
				 * for ICQ because, for ICQ, this setting controls who can
				 * see your online status when you are invisible.  Thus it is
				 * a part of your status and not really related to blocking.
				 */
				if (!od->icq && curitem->data) {
					guint8 perm_deny = aim_ssi_getpermdeny(od->ssi.local);
					if (perm_deny != 0 && perm_deny != account->perm_deny)
					{
						purple_debug_info("oscar",
								   "ssi: changing permdeny from %d to %hhu\n", account->perm_deny, perm_deny);
						account->perm_deny = perm_deny;
					}
				}
			} break;

			case AIM_SSI_TYPE_PRESENCEPREFS: { /* Presence setting */
				/* We don't want to change Purple's setting because it applies to all accounts */
			} break;
		} /* End of switch on curitem->type */
	} /* End of for loop */

	/*** End code for adding from server list to local list ***/

	if (od->icq) {
		oscar_set_icq_permdeny(account);
	} else {
		oscar_set_aim_permdeny(gc);
	}

	/* Activate SSI */
	/* Sending the enable causes other people to be able to see you, and you to see them */
	/* Make sure your privacy setting/invisibility is set how you want it before this! */
	purple_debug_info("oscar",
			   "ssi: activating server-stored buddy list\n");
	aim_ssi_enable(od);

	/*
	 * Make sure our server-stored icon is updated correctly in
	 * the event that the local user set a new icon while this
	 * account was offline.
	 */
	img = purple_buddy_icons_find_account_icon(account);
	oscar_set_icon(gc, img);
	purple_imgstore_unref(img);

	/*
	 * If we've already received our bos rights then we're not waiting on
	 * anything else, so send the server clientready.
	 */
	if (od->bos.have_rights) {
		aim_srv_clientready(od, conn);

		/* Request offline messages for AIM and ICQ */
		aim_im_reqofflinemsgs(od);

		purple_connection_set_state(gc, PURPLE_CONNECTED);
	}

	return 1;
}

static int purple_ssi_parseack(OscarData *od, FlapConnection *conn, FlapFrame *fr, ...) {
	PurpleConnection *gc = od->gc;
	va_list ap;
	struct aim_ssi_tmp *retval;

	va_start(ap, fr);
	retval = va_arg(ap, struct aim_ssi_tmp *);
	va_end(ap);

	while (retval) {
		purple_debug_misc("oscar",
				   "ssi: status is 0x%04hx for a 0x%04hx action with name %s\n", retval->ack,  retval->action, retval->item ? (retval->item->name ? retval->item->name : "no name") : "no item");

		if (retval->ack != 0xffff)
		switch (retval->ack) {
			case 0x0000: { /* added successfully */
			} break;

			case 0x000c: { /* you are over the limit, the cheat is to the limit, come on fhqwhgads */
				gchar *buf;
				buf = g_strdup_printf(_("Unable to add the buddy %s because you have too many buddies in your buddy list.  Please remove one and try again."), (retval->name ? retval->name : _("(no name)")));
				if ((retval->name != NULL) && !purple_conv_present_error(retval->name, purple_connection_get_account(gc), buf))
					purple_notify_error(gc, NULL, _("Unable to Add"), buf);
				g_free(buf);
			} break;

			case 0x000e: { /* buddy requires authorization */
				if ((retval->action == SNAC_SUBTYPE_FEEDBAG_ADD) && (retval->name))
					oscar_auth_sendrequest(gc, retval->name, NULL);
			} break;

			default: { /* La la la */
				gchar *buf;
				purple_debug_error("oscar", "ssi: Action 0x%04hx was unsuccessful with error 0x%04hx\n", retval->action, retval->ack);
				buf = g_strdup_printf(_("Unable to add the buddy %s for an unknown reason."),
						(retval->name ? retval->name : _("(no name)")));
				if ((retval->name != NULL) && !purple_conv_present_error(retval->name, purple_connection_get_account(gc), buf))
					purple_notify_error(gc, NULL, _("Unable to Add"), buf);
				g_free(buf);
			} break;
		}

		retval = retval->next;
	}

	return 1;
}

static int
purple_ssi_parseaddmod(OscarData *od, FlapConnection *conn, FlapFrame *fr, ...)
{
	PurpleConnection *gc;
	PurpleAccount *account;
	char *gname, *gname_utf8, *alias, *alias_utf8;
	PurpleBuddy *b;
	PurpleGroup *g;
	struct aim_ssi_item *ssi_item;
	va_list ap;
	guint16 snac_subtype, type;
	const char *name;

	gc = od->gc;
	account = purple_connection_get_account(gc);

	va_start(ap, fr);
	snac_subtype = (guint16)va_arg(ap, int);
	type = (guint16)va_arg(ap, int);
	name = va_arg(ap, char *);
	va_end(ap);

	if ((type != 0x0000) || (name == NULL))
		return 1;

	gname = aim_ssi_itemlist_findparentname(od->ssi.local, name);
	gname_utf8 = gname ? oscar_utf8_try_convert(account, od, gname) : NULL;

	alias = aim_ssi_getalias(od->ssi.local, gname, name);
	alias_utf8 = oscar_utf8_try_convert(account, od, alias);
	g_free(alias);

	b = purple_find_buddy(account, name);
	if (b) {
		/*
		 * You're logged in somewhere else and you aliased one
		 * of your buddies, so update our local buddy list with
		 * the person's new alias.
		 */
		purple_blist_alias_buddy(b, alias_utf8);
	} else if (snac_subtype == 0x0008) {
		/*
		 * You're logged in somewhere else and you added a buddy to
		 * your server list, so add them to your local buddy list.
		 */
		b = purple_buddy_new(account, name, alias_utf8);

		if (!(g = purple_find_group(gname_utf8 ? gname_utf8 : _("Orphans")))) {
			g = purple_group_new(gname_utf8 ? gname_utf8 : _("Orphans"));
			purple_blist_add_group(g, NULL);
		}

		purple_debug_info("oscar",
				   "ssi: adding buddy %s to group %s to local list\n", name, gname_utf8 ? gname_utf8 : _("Orphans"));
		purple_blist_add_buddy(b, NULL, g, NULL);

		/* Mobile users should always be online */
		if (name[0] == '+') {
			purple_prpl_got_user_status(account,
					name, OSCAR_STATUS_ID_AVAILABLE, NULL);
			purple_prpl_got_user_status(account,
					name, OSCAR_STATUS_ID_MOBILE, NULL);
		}

	}

	ssi_item = aim_ssi_itemlist_finditem(od->ssi.local,
			gname, name, AIM_SSI_TYPE_BUDDY);
	if (ssi_item == NULL)
	{
		purple_debug_error("oscar", "purple_ssi_parseaddmod: "
				"Could not find ssi item for oncoming buddy %s, "
				"group %s\n", name, gname);
	}

	g_free(gname_utf8);
	g_free(alias_utf8);

	return 1;
}

static int purple_ssi_authgiven(OscarData *od, FlapConnection *conn, FlapFrame *fr, ...) {
	PurpleConnection *gc = od->gc;
	va_list ap;
	char *bn, *msg;
	gchar *dialog_msg, *nombre;
	struct name_data *data;
	PurpleBuddy *buddy;

	va_start(ap, fr);
	bn = va_arg(ap, char *);
	msg = va_arg(ap, char *);
	va_end(ap);

	purple_debug_info("oscar",
			   "ssi: %s has given you permission to add him to your buddy list\n", bn);

	buddy = purple_find_buddy(purple_connection_get_account(gc), bn);
	if (buddy && (purple_buddy_get_alias_only(buddy)))
		nombre = g_strdup_printf("%s (%s)", bn, purple_buddy_get_alias_only(buddy));
	else
		nombre = g_strdup(bn);

	dialog_msg = g_strdup_printf(_("The user %s has given you permission to add him or her to your buddy list.  Do you want to add this user?"), nombre);
	g_free(nombre);

	data = g_new(struct name_data, 1);
	data->gc = gc;
	data->name = g_strdup(bn);
	data->nick = (buddy ? g_strdup(purple_buddy_get_alias_only(buddy)) : NULL);

	purple_request_yes_no(gc, NULL, _("Authorization Given"), dialog_msg,
						PURPLE_DEFAULT_ACTION_NONE,
						purple_connection_get_account(gc), bn, NULL,
						data,
						G_CALLBACK(purple_icq_buddyadd),
						G_CALLBACK(oscar_free_name_data));
	g_free(dialog_msg);

	return 1;
}

static int purple_ssi_authrequest(OscarData *od, FlapConnection *conn, FlapFrame *fr, ...)
{
	va_list ap;
	const char *bn;
	char *msg;

	va_start(ap, fr);
	bn = va_arg(ap, const char *);
	msg = va_arg(ap, char *);
	va_end(ap);

	purple_debug_info("oscar",
			"ssi: received authorization request from %s\n", bn);

	if (!msg) {
		purple_debug_warning("oscar", "Received auth request from %s with "
				"empty message\n", bn);
	} else if (!g_utf8_validate(msg, -1, NULL)) {
		purple_debug_warning("oscar", "Received auth request from %s with "
				"invalid UTF-8 message\n", bn);
		msg = NULL;
	}

	aim_icq_getalias(od, bn, TRUE, msg);
	return 1;
}

static int purple_ssi_authreply(OscarData *od, FlapConnection *conn, FlapFrame *fr, ...) {
	PurpleConnection *gc = od->gc;
	va_list ap;
	char *bn, *msg;
	gchar *dialog_msg, *nombre;
	guint8 reply;
	PurpleBuddy *buddy;

	va_start(ap, fr);
	bn = va_arg(ap, char *);
	reply = (guint8)va_arg(ap, int);
	msg = va_arg(ap, char *);
	va_end(ap);

	purple_debug_info("oscar",
			   "ssi: received authorization reply from %s.  Reply is 0x%04hhx\n", bn, reply);

	buddy = purple_find_buddy(purple_connection_get_account(gc), bn);
	if (buddy && (purple_buddy_get_alias_only(buddy)))
		nombre = g_strdup_printf("%s (%s)", bn, purple_buddy_get_alias_only(buddy));
	else
		nombre = g_strdup(bn);

	if (reply) {
		/* Granted */
		dialog_msg = g_strdup_printf(_("The user %s has granted your request to add them to your buddy list."), nombre);
		purple_notify_info(gc, NULL, _("Authorization Granted"), dialog_msg);
	} else {
		/* Denied */
		dialog_msg = g_strdup_printf(_("The user %s has denied your request to add them to your buddy list for the following reason:\n%s"), nombre, msg ? msg : _("No reason given."));
		purple_notify_info(gc, NULL, _("Authorization Denied"), dialog_msg);
	}
	g_free(dialog_msg);
	g_free(nombre);

	return 1;
}

static int purple_ssi_gotadded(OscarData *od, FlapConnection *conn, FlapFrame *fr, ...) {
	PurpleConnection *gc = od->gc;
	PurpleAccount *account = purple_connection_get_account(gc);
	va_list ap;
	char *bn;
	PurpleBuddy *buddy;

	va_start(ap, fr);
	bn = va_arg(ap, char *);
	va_end(ap);

	buddy = purple_find_buddy(account, bn);
	purple_debug_info("oscar", "ssi: %s added you to their buddy list\n", bn);
	purple_account_notify_added(account, bn, NULL,
			(buddy ? purple_buddy_get_alias_only(buddy) : NULL), NULL);

	return 1;
}

GList *oscar_chat_info(PurpleConnection *gc) {
	GList *m = NULL;
	struct proto_chat_entry *pce;

	pce = g_new0(struct proto_chat_entry, 1);
	pce->label = _("_Room:");
	pce->identifier = "room";
	pce->required = TRUE;
	m = g_list_append(m, pce);

	pce = g_new0(struct proto_chat_entry, 1);
	pce->label = _("_Exchange:");
	pce->identifier = "exchange";
	pce->required = TRUE;
	pce->is_int = TRUE;
	pce->min = 4;
	pce->max = 20;
	m = g_list_append(m, pce);

	return m;
}

GHashTable *oscar_chat_info_defaults(PurpleConnection *gc, const char *chat_name)
{
	GHashTable *defaults;

	defaults = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);

	if (chat_name != NULL)
		g_hash_table_insert(defaults, "room", g_strdup(chat_name));
	g_hash_table_insert(defaults, "exchange", g_strdup("4"));

	return defaults;
}

char *
oscar_get_chat_name(GHashTable *data)
{
	return g_strdup(g_hash_table_lookup(data, "room"));
}

void
oscar_join_chat(PurpleConnection *gc, GHashTable *data)
{
	OscarData *od = purple_connection_get_protocol_data(gc);
	FlapConnection *conn;
	char *name, *exchange;
	int exchange_int;

	name = g_hash_table_lookup(data, "room");
	exchange = g_hash_table_lookup(data, "exchange");

	g_return_if_fail(name != NULL && *name != '\0');
	g_return_if_fail(exchange != NULL);

	errno = 0;
	exchange_int = strtol(exchange, NULL, 10);
	g_return_if_fail(errno == 0);

	purple_debug_info("oscar", "Attempting to join chat room %s.\n", name);

	if ((conn = flap_connection_getbytype(od, SNAC_FAMILY_CHATNAV)))
	{
		purple_debug_info("oscar", "chatnav exists, creating room\n");
		aim_chatnav_createroom(od, conn, name, exchange_int);
	} else {
		/* this gets tricky */
		struct create_room *cr = g_new0(struct create_room, 1);
		purple_debug_info("oscar", "chatnav does not exist, opening chatnav\n");
		cr->exchange = exchange_int;
		cr->name = g_strdup(name);
		od->create_rooms = g_slist_prepend(od->create_rooms, cr);
		aim_srv_requestnew(od, SNAC_FAMILY_CHATNAV);
	}
}

void
oscar_chat_invite(PurpleConnection *gc, int id, const char *message, const char *name)
{
	OscarData *od = purple_connection_get_protocol_data(gc);
	struct chat_connection *ccon = find_oscar_chat(gc, id);

	if (ccon == NULL)
		return;

	aim_im_sendch2_chatinvite(od, name, message ? message : "",
			ccon->exchange, ccon->name, 0x0);
}

void
oscar_chat_leave(PurpleConnection *gc, int id)
{
	PurpleConversation *conv;
	struct chat_connection *cc;

	conv = purple_find_chat(gc, id);

	g_return_if_fail(conv != NULL);

	purple_debug_info("oscar", "Leaving chat room %s\n",
			purple_conversation_get_name(conv));

	cc = find_oscar_chat(gc, purple_conv_chat_get_id(PURPLE_CONV_CHAT(conv)));
	flap_connection_schedule_destroy(cc->conn, OSCAR_DISCONNECT_DONE, NULL);
	oscar_chat_kill(gc, cc);
}

int oscar_send_chat(PurpleConnection *gc, int id, const char *message, PurpleMessageFlags flags)
{
	OscarData *od = purple_connection_get_protocol_data(gc);
	PurpleConversation *conv = NULL;
	struct chat_connection *c = NULL;
	char *buf, *buf2, *buf3;
	guint16 charset;
	char *charsetstr;
	gsize len;

	if (!(conv = purple_find_chat(gc, id)))
		return -EINVAL;

	if (!(c = find_oscar_chat_by_conv(gc, conv)))
		return -EINVAL;

	buf = purple_strdup_withhtml(message);

	if (strstr(buf, "<IMG "))
		purple_conversation_write(conv, "",
			_("Your IM Image was not sent. "
			  "You cannot send IM Images in AIM chats."),
			PURPLE_MESSAGE_ERROR, time(NULL));

	buf2 = oscar_encode_im(buf, &len, &charset, &charsetstr);
	/*
	 * Evan S. suggested that maxvis really does mean "number of
	 * visible characters" and not "number of bytes"
	 */
	if ((len > c->maxlen) || (len > c->maxvis)) {
		/* If the length was too long, try stripping the HTML and then running it back through
		 * purple_strdup_withhtml() and the encoding process. The result may be shorter. */
		g_free(buf2);

		buf3 = purple_markup_strip_html(buf);
		g_free(buf);

		buf = purple_strdup_withhtml(buf3);
		g_free(buf3);

		buf2 = oscar_encode_im(buf, &len, &charset, &charsetstr);

		if ((len > c->maxlen) || (len > c->maxvis)) {
			purple_debug_warning("oscar",
					"Could not send %s because (%" G_GSIZE_FORMAT " > maxlen %i) or (%" G_GSIZE_FORMAT " > maxvis %i)\n",
					buf2, len, c->maxlen, len, c->maxvis);
			g_free(buf);
			g_free(buf2);
			return -E2BIG;
		}

		purple_debug_info("oscar", "Sending %s as %s because the original was too long.\n",
				message, buf2);
	}

	aim_chat_send_im(od, c->conn, 0, buf2, len, charsetstr, "en");
	g_free(buf2);
	g_free(buf);

	return 0;
}

PurpleMood* oscar_get_purple_moods(PurpleAccount *account)
{
	return icq_get_purple_moods(account);
}

const char *oscar_list_icon_icq(PurpleAccount *a, PurpleBuddy *b)
{
	const char *name = b ? purple_buddy_get_name(b) : NULL;
	if (name && !oscar_util_valid_name_sms(name) && oscar_util_valid_name_icq(name))
		return "icq";

	return "icq";
}

const char *oscar_list_icon_aim(PurpleAccount *a, PurpleBuddy *b)
{
	const char *name = b ? purple_buddy_get_name(b) : NULL;
	if (name && !oscar_util_valid_name_sms(name) && oscar_util_valid_name_icq(name))
		return "icq";

	return "aim";
}

const char *oscar_list_emblem(PurpleBuddy *b)
{
	PurpleConnection *gc = NULL;
	OscarData *od = NULL;
	PurpleAccount *account = NULL;
	PurplePresence *presence;
	aim_userinfo_t *userinfo = NULL;
	const char *name;

	account = purple_buddy_get_account(b);
	name = purple_buddy_get_name(b);
	if (account != NULL)
		gc = purple_account_get_connection(account);
	if (gc != NULL)
		od = purple_connection_get_protocol_data(gc);
	if (od != NULL)
		userinfo = aim_locate_finduserinfo(od, name);

	presence = purple_buddy_get_presence(b);

	if (purple_presence_is_online(presence) == FALSE) {
		char *gname;
		if ((name) && (od) && (od->ssi.received_data) &&
			(gname = aim_ssi_itemlist_findparentname(od->ssi.local, name)) &&
			(aim_ssi_waitingforauth(od->ssi.local, gname, name))) {
			return "not-authorized";
		}
	}

	if (userinfo != NULL ) {
		if (userinfo->flags & AIM_FLAG_ADMINISTRATOR)
			return "admin";
		if (userinfo->flags & AIM_FLAG_ACTIVEBUDDY)
			return "bot";
		if (userinfo->capabilities & OSCAR_CAPABILITY_SECUREIM)
			return "secure";
		if (userinfo->icqinfo.status & AIM_ICQ_STATE_BIRTHDAY)
			return "birthday";

		/* Make the mood icon override anything below this. */
		if (purple_presence_is_status_primitive_active(presence, PURPLE_STATUS_MOOD))
			return NULL;

		if (userinfo->capabilities & OSCAR_CAPABILITY_HIPTOP)
			return "hiptop";
	}
	return NULL;
}

void oscar_tooltip_text(PurpleBuddy *b, PurpleNotifyUserInfo *user_info, gboolean full)
{
	PurpleConnection *gc;
	PurpleAccount *account;
	OscarData *od;
	aim_userinfo_t *userinfo;

	if (!PURPLE_BUDDY_IS_ONLINE(b))
		return;

	account = purple_buddy_get_account(b);
	gc = purple_account_get_connection(account);
	od = purple_connection_get_protocol_data(gc);
	userinfo = aim_locate_finduserinfo(od, purple_buddy_get_name(b));

	oscar_user_info_append_status(gc, user_info, b, userinfo, /* use_html_status */ FALSE);

	if (full)
		oscar_user_info_append_extra_info(gc, user_info, b, userinfo);
}

char *oscar_status_text(PurpleBuddy *b)
{
	PurpleConnection *gc;
	PurpleAccount *account;
	OscarData *od;
	const PurplePresence *presence;
	const PurpleStatus *status;
	const char *message;
	gchar *ret = NULL;

	gc = purple_account_get_connection(purple_buddy_get_account(b));
	account = purple_connection_get_account(gc);
	od = purple_connection_get_protocol_data(gc);
	presence = purple_buddy_get_presence(b);
	status = purple_presence_get_active_status(presence);

	if ((od != NULL) && !purple_presence_is_online(presence))
	{
		const char *name = purple_buddy_get_name(b);
		char *gname = aim_ssi_itemlist_findparentname(od->ssi.local, name);
		if (aim_ssi_waitingforauth(od->ssi.local, gname, name))
			ret = g_strdup(_("Not Authorized"));
		else
			ret = g_strdup(_("Offline"));
	}
	else
	{
		message = purple_status_get_attr_string(status, "message");
		if (message != NULL)
		{
			gchar *tmp = oscar_util_format_string(message, purple_account_get_username(account));
			ret = purple_markup_escape_text(tmp, -1);
			g_free(tmp);
		}
		else if (purple_status_is_available(status))
		{
			/* Don't show "Available" as status message in case buddy doesn't have a status message */
		}
		else
		{
			ret = g_strdup(purple_status_get_name(status));
		}
	}

	return ret;
}

void oscar_set_aim_permdeny(PurpleConnection *gc) {
	PurpleAccount *account = purple_connection_get_account(gc);
	OscarData *od = purple_connection_get_protocol_data(gc);

	/*
	 * Conveniently there is a one-to-one mapping between the
	 * values of libpurple's PurplePrivacyType and the values used
	 * by the oscar protocol.
	 */
	aim_ssi_setpermdeny(od, account->perm_deny);
}

void oscar_add_permit(PurpleConnection *gc, const char *who) {
	OscarData *od = purple_connection_get_protocol_data(gc);
	purple_debug_info("oscar", "ssi: About to add a permit\n");
	aim_ssi_add_to_private_list(od, who, AIM_SSI_TYPE_PERMIT);
}

void oscar_add_deny(PurpleConnection *gc, const char *who) {
	OscarData *od = purple_connection_get_protocol_data(gc);
	purple_debug_info("oscar", "ssi: About to add a deny\n");
	aim_ssi_add_to_private_list(od, who, aim_ssi_getdenyentrytype(od));
}

void oscar_rem_permit(PurpleConnection *gc, const char *who) {
	OscarData *od = purple_connection_get_protocol_data(gc);
	purple_debug_info("oscar", "ssi: About to delete a permit\n");
	aim_ssi_del_from_private_list(od, who, AIM_SSI_TYPE_PERMIT);
}

void oscar_rem_deny(PurpleConnection *gc, const char *who) {
	OscarData *od = purple_connection_get_protocol_data(gc);
	purple_debug_info("oscar", "ssi: About to delete a deny\n");
	aim_ssi_del_from_private_list(od, who, aim_ssi_getdenyentrytype(od));
}

GList *
oscar_status_types(PurpleAccount *account)
{
	gboolean is_icq;
	GList *status_types = NULL;
	PurpleStatusType *type;

	g_return_val_if_fail(account != NULL, NULL);

	/* Used to flag some statuses as "user settable" or not */
	is_icq = oscar_util_valid_name_icq(purple_account_get_username(account));

	/* Common status types */
	/* Really the available message should only be settable for AIM accounts */
	type = purple_status_type_new_with_attrs(PURPLE_STATUS_AVAILABLE,
										   OSCAR_STATUS_ID_AVAILABLE,
										   NULL, TRUE, TRUE, FALSE,
										   "message", _("Message"),
										   purple_value_new(PURPLE_TYPE_STRING),
										   "itmsurl", _("iTunes Music Store Link"),
										   purple_value_new(PURPLE_TYPE_STRING), NULL);
	status_types = g_list_prepend(status_types, type);

	type = purple_status_type_new_with_attrs(PURPLE_STATUS_AVAILABLE,
									 OSCAR_STATUS_ID_FREE4CHAT,
									 _("Free For Chat"), TRUE, is_icq, FALSE,
									 "message", _("Message"),
				purple_value_new(PURPLE_TYPE_STRING), NULL);

	status_types = g_list_prepend(status_types, type);

	type = purple_status_type_new_with_attrs(PURPLE_STATUS_AVAILABLE,
									 OSCAR_STATUS_ID_EVIL,
									 _("Evil"), TRUE, is_icq, FALSE,
				 "message", _("Message"),
				purple_value_new(PURPLE_TYPE_STRING), NULL);
	status_types = g_list_prepend(status_types, type);


	type = purple_status_type_new_with_attrs(PURPLE_STATUS_AVAILABLE,
									 OSCAR_STATUS_ID_DEPRESSION,
									 _("Depression"), TRUE, is_icq, FALSE,
				 "message", _("Message"),
				purple_value_new(PURPLE_TYPE_STRING), NULL);
	status_types = g_list_prepend(status_types, type);


	type = purple_status_type_new_with_attrs(PURPLE_STATUS_AVAILABLE,
									 OSCAR_STATUS_ID_ATHOME,
									 _("At home"), TRUE, is_icq, FALSE,
				"message", _("Message"),
				purple_value_new(PURPLE_TYPE_STRING), NULL);
	status_types = g_list_prepend(status_types, type);


	type = purple_status_type_new_with_attrs(PURPLE_STATUS_AVAILABLE,
									 OSCAR_STATUS_ID_ATWORK,
									 _("At work"), TRUE, is_icq, FALSE,
				"message", _("Message"),
				purple_value_new(PURPLE_TYPE_STRING), NULL);

	status_types = g_list_prepend(status_types, type);


	type = purple_status_type_new_with_attrs(PURPLE_STATUS_AVAILABLE,
									 OSCAR_STATUS_ID_LUNCH,
									 _("Lunch"), TRUE, is_icq, FALSE,
				"message", _("Message"),
				purple_value_new(PURPLE_TYPE_STRING), NULL);

	status_types = g_list_prepend(status_types, type);

	type = purple_status_type_new_with_attrs(PURPLE_STATUS_AWAY,
										   OSCAR_STATUS_ID_AWAY,
										   NULL, TRUE, TRUE, FALSE,
										   "message", _("Message"),
										   purple_value_new(PURPLE_TYPE_STRING), NULL);
	status_types = g_list_prepend(status_types, type);

	type = purple_status_type_new_with_attrs(PURPLE_STATUS_INVISIBLE,
									 OSCAR_STATUS_ID_INVISIBLE,
									 NULL, TRUE, TRUE, FALSE,
									 "message", _("Message"),
									  purple_value_new(PURPLE_TYPE_STRING), NULL);

	status_types = g_list_prepend(status_types, type);

	type = purple_status_type_new_full(PURPLE_STATUS_MOBILE, OSCAR_STATUS_ID_MOBILE, NULL, FALSE, FALSE, TRUE);
	status_types = g_list_prepend(status_types, type);

	/* ICQ-specific status types */
	type = purple_status_type_new_with_attrs(PURPLE_STATUS_UNAVAILABLE,
				OSCAR_STATUS_ID_OCCUPIED,
				_("Occupied"), TRUE, is_icq, FALSE,
				"message", _("Message"),
				purple_value_new(PURPLE_TYPE_STRING), NULL);
	status_types = g_list_prepend(status_types, type);

	type = purple_status_type_new_with_attrs(PURPLE_STATUS_UNAVAILABLE,
				OSCAR_STATUS_ID_DND,
				_("Do Not Disturb"), TRUE, is_icq, FALSE,
				"message", _("Message"),
				purple_value_new(PURPLE_TYPE_STRING), NULL);
	status_types = g_list_prepend(status_types, type);

	type = purple_status_type_new_with_attrs(PURPLE_STATUS_EXTENDED_AWAY,
				OSCAR_STATUS_ID_NA,
				_("Not Available"), TRUE, is_icq, FALSE,
				"message", _("Message"),
				purple_value_new(PURPLE_TYPE_STRING), NULL);
	status_types = g_list_prepend(status_types, type);

	type = purple_status_type_new_full(PURPLE_STATUS_OFFLINE,
									 OSCAR_STATUS_ID_OFFLINE,
									 NULL, TRUE, TRUE, FALSE);
	status_types = g_list_prepend(status_types, type);

	type = purple_status_type_new_with_attrs(PURPLE_STATUS_MOOD,
			"mood", NULL, TRUE, is_icq, TRUE,
			PURPLE_MOOD_NAME, _("Mood Name"), purple_value_new(PURPLE_TYPE_STRING),
			PURPLE_MOOD_COMMENT, _("Mood Comment"), purple_value_new(PURPLE_TYPE_STRING),
			NULL);
	status_types = g_list_prepend(status_types, type);

	return g_list_reverse(status_types);
}

static void oscar_ssi_editcomment(struct name_data *data, const char *text) {
	PurpleConnection *gc;
	PurpleAccount *account;
	OscarData *od;
	PurpleBuddy *b;
	PurpleGroup *g;

	gc = data->gc;
	od = purple_connection_get_protocol_data(gc);
	account = purple_connection_get_account(gc);

	b = purple_find_buddy(account, data->name);
	if (b == NULL) {
		oscar_free_name_data(data);
		return;
	}

	g = purple_buddy_get_group(b);
	if (g == NULL) {
		oscar_free_name_data(data);
		return;
	}

	aim_ssi_editcomment(od, purple_group_get_name(g), data->name, text);
	oscar_free_name_data(data);
}

static void oscar_buddycb_edit_comment(PurpleBlistNode *node, gpointer ignore) {

	PurpleBuddy *buddy;
	PurpleConnection *gc;
	OscarData *od;
	struct name_data *data;
	PurpleGroup *g;
	char *comment;
	gchar *comment_utf8;
	gchar *title;
	PurpleAccount *account;
	const char *name;

	g_return_if_fail(PURPLE_BLIST_NODE_IS_BUDDY(node));

	buddy = (PurpleBuddy *) node;
	name = purple_buddy_get_name(buddy);
	account = purple_buddy_get_account(buddy);
	gc = purple_account_get_connection(account);
	od = purple_connection_get_protocol_data(gc);

	if (!(g = purple_buddy_get_group(buddy)))
		return;

	data = g_new(struct name_data, 1);

	comment = aim_ssi_getcomment(od->ssi.local, purple_group_get_name(g), name);
	comment_utf8 = comment ? oscar_utf8_try_convert(account, od, comment) : NULL;

	data->gc = gc;
	data->name = g_strdup(name);
	data->nick = g_strdup(purple_buddy_get_alias_only(buddy));

	title = g_strdup_printf(_("Buddy Comment for %s"), data->name);
	purple_request_input(gc, title, _("Buddy Comment:"), NULL,
					   comment_utf8, TRUE, FALSE, NULL,
					   _("_OK"), G_CALLBACK(oscar_ssi_editcomment),
					   _("_Cancel"), G_CALLBACK(oscar_free_name_data),
					   account, data->name, NULL,
					   data);
	g_free(title);

	g_free(comment);
	g_free(comment_utf8);
}

static void
oscar_ask_directim_yes_cb(struct oscar_ask_directim_data *data)
{
	peer_connection_propose(data->od, OSCAR_CAPABILITY_DIRECTIM, data->who);
	g_free(data->who);
	g_free(data);
}

static void
oscar_ask_directim_no_cb(struct oscar_ask_directim_data *data)
{
	g_free(data->who);
	g_free(data);
}

/* This is called from right-click menu on a buddy node. */
static void
oscar_ask_directim(gpointer object, gpointer ignored)
{
	PurpleBlistNode *node;
	PurpleBuddy *buddy;
	PurpleConnection *gc;
	gchar *buf;
	struct oscar_ask_directim_data *data;
	PurpleAccount *account;

	node = object;

	g_return_if_fail(PURPLE_BLIST_NODE_IS_BUDDY(node));

	buddy = (PurpleBuddy *)node;
	account = purple_buddy_get_account(buddy);
	gc = purple_account_get_connection(account);

	data = g_new0(struct oscar_ask_directim_data, 1);
	data->who = g_strdup(purple_buddy_get_name(buddy));
	data->od = purple_connection_get_protocol_data(gc);
	buf = g_strdup_printf(_("You have selected to open a Direct IM connection with %s."),
			data->who);

	purple_request_action(gc, NULL, buf,
			_("Because this reveals your IP address, it "
			  "may be considered a security risk.  Do you "
			  "wish to continue?"),
			0, /* Default action is "connect" */
			account, data->who, NULL,
			data, 2,
			_("C_onnect"), G_CALLBACK(oscar_ask_directim_yes_cb),
			_("_Cancel"), G_CALLBACK(oscar_ask_directim_no_cb));
	g_free(buf);
}

static void
oscar_close_directim(gpointer object, gpointer ignored)
{
	PurpleBlistNode *node;
	PurpleBuddy *buddy;
	PurpleAccount *account;
	PurpleConnection *gc;
	PurpleConversation *conv;
	OscarData *od;
	PeerConnection *conn;
	const char *name;

	node = object;

	g_return_if_fail(PURPLE_BLIST_NODE_IS_BUDDY(node));

	buddy = (PurpleBuddy*)node;
	name = purple_buddy_get_name(buddy);
	account = purple_buddy_get_account(buddy);
	gc = purple_account_get_connection(account);
	od = gc->proto_data;
	conn = peer_connection_find_by_type(od, name, OSCAR_CAPABILITY_DIRECTIM);

	if (conn != NULL)
	{
		if (!conn->ready)
			aim_im_sendch2_cancel(conn);

		peer_connection_destroy(conn, OSCAR_DISCONNECT_LOCAL_CLOSED, NULL);

		/* OSCAR_DISCONNECT_LOCAL_CLOSED doesn't write anything to the convo
		 * window. Let the user know that we cancelled the Direct IM. */
		conv = purple_conversation_new(PURPLE_CONV_TYPE_IM, account, name);
		purple_conversation_write(conv, NULL, _("You closed the connection."),
				PURPLE_MESSAGE_SYSTEM, time(NULL));
	}
}

static void oscar_get_icqxstatusmsg(PurpleBlistNode *node, gpointer ignore)
{
	PurpleBuddy *buddy;
	PurpleConnection *gc;
	OscarData *od;
	PurpleAccount *account;
	const char *bname;

	g_return_if_fail(PURPLE_BLIST_NODE_IS_BUDDY(node));

	buddy = (PurpleBuddy *)node;
	bname = purple_buddy_get_name(buddy);

	account = purple_buddy_get_account(buddy);
	gc = purple_account_get_connection(account);
	od = purple_connection_get_protocol_data(gc);

	purple_debug_info("oscar", "Manual X-Status Get From %s to %s:\n", bname, purple_account_get_username(account));

	icq_im_xstatus_request(od, bname);
}

static void
oscar_get_aim_info_cb(PurpleBlistNode *node, gpointer ignore)
{
	PurpleBuddy *buddy;
	PurpleConnection *gc;

	g_return_if_fail(PURPLE_BLIST_NODE_IS_BUDDY(node));

	buddy = (PurpleBuddy *)node;
	gc = purple_account_get_connection(purple_buddy_get_account(buddy));

	aim_locate_getinfoshort(purple_connection_get_protocol_data(gc),
			purple_buddy_get_name(buddy), 0x00000003);
}

static GList *
oscar_buddy_menu(PurpleBuddy *buddy) {
	PurpleConnection *gc;
	OscarData *od;
	GList *menu;
	PurpleMenuAction *act;
	aim_userinfo_t *userinfo;
	PurpleAccount *account;
	const char *bname = purple_buddy_get_name(buddy);

	account = purple_buddy_get_account(buddy);
	gc = purple_account_get_connection(account);
	od = purple_connection_get_protocol_data(gc);
	userinfo = aim_locate_finduserinfo(od, bname);
	menu = NULL;

	if (od->icq && oscar_util_valid_name_icq(bname))
	{
		act = purple_menu_action_new(_("Get AIM Info"),
								   PURPLE_CALLBACK(oscar_get_aim_info_cb),
								   NULL, NULL);
		menu = g_list_prepend(menu, act);
	}

	if (purple_buddy_get_group(buddy) != NULL)
	{
		/* We only do this if the user is in our buddy list */
		act = purple_menu_action_new(_("Edit Buddy Comment"),
		                           PURPLE_CALLBACK(oscar_buddycb_edit_comment),
		                           NULL, NULL);
		menu = g_list_prepend(menu, act);
	}

	if (od->icq)
	{
		act = purple_menu_action_new(_("Get X-Status Msg"),
		                           PURPLE_CALLBACK(oscar_get_icqxstatusmsg),
		                           NULL, NULL);
		menu = g_list_prepend(menu, act);
		menu = g_list_prepend(menu, create_visibility_menu_item(od, bname));
	}

	if (userinfo &&
		oscar_util_name_compare(purple_account_get_username(account), bname) &&
		PURPLE_BUDDY_IS_ONLINE(buddy))
	{
		PeerConnection *conn;
		conn = peer_connection_find_by_type(od, bname, OSCAR_CAPABILITY_DIRECTIM);

		if (userinfo->capabilities & OSCAR_CAPABILITY_DIRECTIM)
		{
			if (conn)
			{
				act = purple_menu_action_new(_("End Direct IM Session"),
				                          PURPLE_CALLBACK(oscar_close_directim),
				                          NULL, NULL);
			}
			else
			{
				act = purple_menu_action_new(_("Direct IM"),
				                          PURPLE_CALLBACK(oscar_ask_directim),
				                          NULL, NULL);
			}
			menu = g_list_prepend(menu, act);
		}
	}

	if (od->ssi.received_data && purple_buddy_get_group(buddy) != NULL)
	{
		/*
		 * We only do this if the user is in our buddy list and we're
		 * waiting for authorization.
		 */
		char *gname;
		gname = aim_ssi_itemlist_findparentname(od->ssi.local, bname);
		if (gname && aim_ssi_waitingforauth(od->ssi.local, gname, bname))
		{
			act = purple_menu_action_new(_("Re-request Authorization"),
			                           PURPLE_CALLBACK(oscar_auth_sendrequest_menu),
			                           NULL, NULL);
			menu = g_list_prepend(menu, act);
		}
	}

	menu = g_list_reverse(menu);

	return menu;
}


GList *oscar_blist_node_menu(PurpleBlistNode *node) {
	if(PURPLE_BLIST_NODE_IS_BUDDY(node)) {
		return oscar_buddy_menu((PurpleBuddy *) node);
	} else {
		return NULL;
	}
}

static void
oscar_icq_privacy_opts(PurpleConnection *gc, PurpleRequestFields *fields)
{
	OscarData *od = purple_connection_get_protocol_data(gc);
	PurpleAccount *account = purple_connection_get_account(gc);
	PurpleRequestField *f;
	gboolean auth, web_aware;

	f = purple_request_fields_get_field(fields, "authorization");
	auth = purple_request_field_bool_get_value(f);

	f = purple_request_fields_get_field(fields, "web_aware");
	web_aware = purple_request_field_bool_get_value(f);

	purple_account_set_bool(account, "authorization", auth);
	purple_account_set_bool(account, "web_aware", web_aware);

	oscar_set_extended_status(gc);
	aim_icq_setsecurity(od, auth, web_aware);
}

static void
oscar_show_icq_privacy_opts(PurplePluginAction *action)
{
	PurpleConnection *gc = (PurpleConnection *) action->context;
	PurpleAccount *account = purple_connection_get_account(gc);
	PurpleRequestFields *fields;
	PurpleRequestFieldGroup *g;
	PurpleRequestField *f;
	gboolean auth, web_aware;

	auth = purple_account_get_bool(account, "authorization", OSCAR_DEFAULT_AUTHORIZATION);
	web_aware = purple_account_get_bool(account, "web_aware", OSCAR_DEFAULT_WEB_AWARE);

	fields = purple_request_fields_new();

	g = purple_request_field_group_new(NULL);

	f = purple_request_field_bool_new("authorization", _("Require authorization"), auth);
	purple_request_field_group_add_field(g, f);

	f = purple_request_field_bool_new("web_aware", _("Web aware (enabling this will cause you to receive SPAM!)"), web_aware);
	purple_request_field_group_add_field(g, f);

	purple_request_fields_add_group(fields, g);

	purple_request_fields(gc, _("ICQ Privacy Options"), _("ICQ Privacy Options"),
						NULL, fields,
						_("OK"), G_CALLBACK(oscar_icq_privacy_opts),
						_("Cancel"), NULL,
						purple_connection_get_account(gc), NULL, NULL,
						gc);
}

static void oscar_confirm_account(PurplePluginAction *action)
{
	PurpleConnection *gc;
	OscarData *od;
	FlapConnection *conn;

	gc = (PurpleConnection *)action->context;
	od = purple_connection_get_protocol_data(gc);

	conn = flap_connection_getbytype(od, SNAC_FAMILY_ADMIN);
	if (conn != NULL) {
		aim_admin_reqconfirm(od, conn);
	} else {
		od->conf = TRUE;
		aim_srv_requestnew(od, SNAC_FAMILY_ADMIN);
	}
}

static void oscar_show_email(PurplePluginAction *action)
{
	PurpleConnection *gc = (PurpleConnection *) action->context;
	OscarData *od = purple_connection_get_protocol_data(gc);
	FlapConnection *conn = flap_connection_getbytype(od, SNAC_FAMILY_ADMIN);

	if (conn) {
		aim_admin_getinfo(od, conn, 0x11);
	} else {
		od->reqemail = TRUE;
		aim_srv_requestnew(od, SNAC_FAMILY_ADMIN);
	}
}

static void oscar_change_email(PurpleConnection *gc, const char *email)
{
	OscarData *od = purple_connection_get_protocol_data(gc);
	FlapConnection *conn = flap_connection_getbytype(od, SNAC_FAMILY_ADMIN);

	if (conn) {
		aim_admin_setemail(od, conn, email);
	} else {
		od->setemail = TRUE;
		od->email = g_strdup(email);
		aim_srv_requestnew(od, SNAC_FAMILY_ADMIN);
	}
}

static void oscar_show_change_email(PurplePluginAction *action)
{
	PurpleConnection *gc = (PurpleConnection *) action->context;
	purple_request_input(gc, NULL, _("Change Address To:"), NULL, NULL,
					   FALSE, FALSE, NULL,
					   _("_OK"), G_CALLBACK(oscar_change_email),
					   _("_Cancel"), NULL,
					   purple_connection_get_account(gc), NULL, NULL,
					   gc);
}

static void oscar_show_awaitingauth(PurplePluginAction *action)
{
	PurpleConnection *gc = (PurpleConnection *) action->context;
	OscarData *od = purple_connection_get_protocol_data(gc);
	PurpleAccount *account = purple_connection_get_account(gc);
	GSList *buddies, *filtered_buddies, *cur;
	gchar *text;

	buddies = purple_find_buddies(account, NULL);
	filtered_buddies = NULL;
	for (cur = buddies; cur != NULL; cur = cur->next) {
		PurpleBuddy *buddy;
		const gchar *bname, *gname;

		buddy = cur->data;
		bname = purple_buddy_get_name(buddy);
		gname = purple_group_get_name(purple_buddy_get_group(buddy));
		if (aim_ssi_waitingforauth(od->ssi.local, gname, bname)) {
			filtered_buddies = g_slist_prepend(filtered_buddies, buddy);
		}
	}

	g_slist_free(buddies);

	filtered_buddies = g_slist_reverse(filtered_buddies);
	text = oscar_format_buddies(filtered_buddies, _("you are not waiting for authorization"));
	g_slist_free(filtered_buddies);

	purple_notify_formatted(gc, NULL, _("You are awaiting authorization from "
						  "the following buddies"),	_("You can re-request "
						  "authorization from these buddies by "
						  "right-clicking on them and selecting "
						  "\"Re-request Authorization.\""), text, NULL, NULL);
	g_free(text);
}

static void search_by_email_cb(PurpleConnection *gc, const char *email)
{
	OscarData *od = purple_connection_get_protocol_data(gc);

	aim_search_address(od, email);
}

static void oscar_show_find_email(PurplePluginAction *action)
{
	PurpleConnection *gc = (PurpleConnection *) action->context;
	purple_request_input(gc, _("Find Buddy by Email"),
					   _("Search for a buddy by email address"),
					   _("Type the email address of the buddy you are "
						 "searching for."),
					   NULL, FALSE, FALSE, NULL,
					   _("_Search"), G_CALLBACK(search_by_email_cb),
					   _("_Cancel"), NULL,
					   purple_connection_get_account(gc), NULL, NULL,
					   gc);
}

static void oscar_show_set_info(PurplePluginAction *action)
{
	PurpleConnection *gc = (PurpleConnection *) action->context;
	purple_account_request_change_user_info(purple_connection_get_account(gc));
}

static void oscar_show_set_info_icqurl(PurplePluginAction *action)
{
	PurpleConnection *gc = (PurpleConnection *) action->context;
	purple_notify_uri(gc, "http://www.icq.com/whitepages/user_details.php");
}

static void oscar_change_pass(PurplePluginAction *action)
{
	PurpleConnection *gc = (PurpleConnection *) action->context;
	purple_account_request_change_password(purple_connection_get_account(gc));
}

/**
 * Only used when connecting with the old-style BUCP login.
 */
static void oscar_show_chpassurl(PurplePluginAction *action)
{
	PurpleConnection *gc = (PurpleConnection *) action->context;
	OscarData *od = purple_connection_get_protocol_data(gc);
	gchar *substituted = purple_strreplace(od->authinfo->chpassurl, "%s", purple_account_get_username(purple_connection_get_account(gc)));
	purple_notify_uri(gc, substituted);
	g_free(substituted);
}

static void oscar_show_imforwardingurl(PurplePluginAction *action)
{
	PurpleConnection *gc = (PurpleConnection *) action->context;
	purple_notify_uri(gc, "http://mymobile.aol.com/dbreg/register?action=imf&clientID=1");
}

void oscar_set_icon(PurpleConnection *gc, PurpleStoredImage *img)
{
	OscarData *od = purple_connection_get_protocol_data(gc);

	if (img == NULL) {
		aim_ssi_delicon(od);
	} else {
		PurpleCipherContext *context;
		guchar md5[16];
		gconstpointer data = purple_imgstore_get_data(img);
		size_t len = purple_imgstore_get_size(img);

		context = purple_cipher_context_new_by_name("md5", NULL);
		purple_cipher_context_append(context, data, len);
		purple_cipher_context_digest(context, 16, md5, NULL);
		purple_cipher_context_destroy(context);

		aim_ssi_seticon(od, md5, 16);
	}
}

/**
 * Called by the Purple core to determine whether or not we're
 * allowed to send a file to this user.
 */
gboolean
oscar_can_receive_file(PurpleConnection *gc, const char *who)
{
	OscarData *od;
	PurpleAccount *account;

	od = purple_connection_get_protocol_data(gc);
	account = purple_connection_get_account(gc);

	if (od != NULL)
	{
		aim_userinfo_t *userinfo;
		userinfo = aim_locate_finduserinfo(od, who);

		/*
		 * Don't allowing sending a file to a user that does not support
		 * file transfer, and don't allow sending to ourselves.
		 */
		if (((userinfo == NULL) ||
			(userinfo->capabilities & OSCAR_CAPABILITY_SENDFILE)) &&
			oscar_util_name_compare(who, purple_account_get_username(account)))
		{
			return TRUE;
		}
	}

	return FALSE;
}

PurpleXfer *
oscar_new_xfer(PurpleConnection *gc, const char *who)
{
	PurpleXfer *xfer;
	OscarData *od;
	PurpleAccount *account;
	PeerConnection *conn;

	od = purple_connection_get_protocol_data(gc);
	account = purple_connection_get_account(gc);

	xfer = purple_xfer_new(account, PURPLE_XFER_SEND, who);
	if (xfer)
	{
		purple_xfer_ref(xfer);
		purple_xfer_set_init_fnc(xfer, peer_oft_sendcb_init);
		purple_xfer_set_cancel_send_fnc(xfer, peer_oft_cb_generic_cancel);
		purple_xfer_set_request_denied_fnc(xfer, peer_oft_cb_generic_cancel);
		purple_xfer_set_ack_fnc(xfer, peer_oft_sendcb_ack);

		conn = peer_connection_new(od, OSCAR_CAPABILITY_SENDFILE, who);
		conn->flags |= PEER_CONNECTION_FLAG_INITIATED_BY_ME;
		conn->flags |= PEER_CONNECTION_FLAG_APPROVED;
		aim_icbm_makecookie(conn->cookie);
		conn->xfer = xfer;
		xfer->data = conn;
	}

	return xfer;
}

/*
 * Called by the Purple core when the user indicates that a
 * file is to be sent to a special someone.
 */
void
oscar_send_file(PurpleConnection *gc, const char *who, const char *file)
{
	PurpleXfer *xfer;

	xfer = oscar_new_xfer(gc, who);

	if (file != NULL)
		purple_xfer_request_accepted(xfer, file);
	else
		purple_xfer_request(xfer);
}

GList *
oscar_actions(PurplePlugin *plugin, gpointer context)
{
	PurpleConnection *gc = (PurpleConnection *) context;
	OscarData *od = purple_connection_get_protocol_data(gc);
	GList *menu = NULL;
	PurplePluginAction *act;

	act = purple_plugin_action_new(_("Set User Info..."),
			oscar_show_set_info);
	menu = g_list_prepend(menu, act);

	if (od->icq)
	{
		act = purple_plugin_action_new(_("Set User Info (web)..."),
				oscar_show_set_info_icqurl);
		menu = g_list_prepend(menu, act);
	}

	act = purple_plugin_action_new(_("Change Password..."),
			oscar_change_pass);
	menu = g_list_prepend(menu, act);

	if (od->authinfo != NULL && od->authinfo->chpassurl != NULL)
	{
		/* This only happens when connecting with the old-style BUCP login */
		act = purple_plugin_action_new(_("Change Password (web)"),
				oscar_show_chpassurl);
		menu = g_list_prepend(menu, act);
	}

	if (!od->icq)
	{
		act = purple_plugin_action_new(_("Configure IM Forwarding (web)"),
				oscar_show_imforwardingurl);
		menu = g_list_prepend(menu, act);
	}

	menu = g_list_prepend(menu, NULL);

	if (od->icq)
	{
		/* ICQ actions */
		act = purple_plugin_action_new(_("Set Privacy Options..."),
				oscar_show_icq_privacy_opts);
		menu = g_list_prepend(menu, act);

		act = purple_plugin_action_new(_("Show Visible List"), oscar_show_visible_list);
		menu = g_list_prepend(menu, act);

		act = purple_plugin_action_new(_("Show Invisible List"), oscar_show_invisible_list);
		menu = g_list_prepend(menu, act);
	}
	else
	{
		/* AIM actions */
		act = purple_plugin_action_new(_("Confirm Account"),
				oscar_confirm_account);
		menu = g_list_prepend(menu, act);

		act = purple_plugin_action_new(_("Display Currently Registered Email Address"),
				oscar_show_email);
		menu = g_list_prepend(menu, act);

		act = purple_plugin_action_new(_("Change Currently Registered Email Address..."),
				oscar_show_change_email);
		menu = g_list_prepend(menu, act);
	}

	menu = g_list_prepend(menu, NULL);

	act = purple_plugin_action_new(_("Show Buddies Awaiting Authorization"),
			oscar_show_awaitingauth);
	menu = g_list_prepend(menu, act);

	menu = g_list_prepend(menu, NULL);

	act = purple_plugin_action_new(_("Search for Buddy by Email Address..."),
			oscar_show_find_email);
	menu = g_list_prepend(menu, act);

	menu = g_list_reverse(menu);

	return menu;
}

void oscar_change_passwd(PurpleConnection *gc, const char *old, const char *new)
{
	OscarData *od = purple_connection_get_protocol_data(gc);

	if (od->icq) {
		aim_icq_changepasswd(od, new);
	} else {
		FlapConnection *conn;
		conn = flap_connection_getbytype(od, SNAC_FAMILY_ADMIN);
		if (conn) {
			aim_admin_changepasswd(od, conn, new, old);
		} else {
			od->chpass = TRUE;
			od->oldp = g_strdup(old);
			od->newp = g_strdup(new);
			aim_srv_requestnew(od, SNAC_FAMILY_ADMIN);
		}
	}
}

void
oscar_convo_closed(PurpleConnection *gc, const char *who)
{
	OscarData *od;
	PeerConnection *conn;

	od = purple_connection_get_protocol_data(gc);
	conn = peer_connection_find_by_type(od, who, OSCAR_CAPABILITY_DIRECTIM);

	if (conn != NULL)
	{
		if (!conn->ready)
			aim_im_sendch2_cancel(conn);

		peer_connection_destroy(conn, OSCAR_DISCONNECT_LOCAL_CLOSED, NULL);
	}
}

const char *
oscar_normalize(const PurpleAccount *account, const char *str)
{
	static char buf[BUF_LEN];
	char *tmp1, *tmp2;
	int i, j;

	g_return_val_if_fail(str != NULL, NULL);

	/* copy str to buf and skip all blanks */
	i = 0;
	for (j = 0; str[j]; j++) {
		if (str[j] != ' ') {
			buf[i++] = str[j];
			if (i >= BUF_LEN - 1)
				break;
		}
	}
	buf[i] = '\0';

	tmp1 = g_utf8_strdown(buf, -1);
	tmp2 = g_utf8_normalize(tmp1, -1, G_NORMALIZE_DEFAULT);
	if (strlen(tmp2) > sizeof(buf) - 1) {
		purple_debug_error("oscar", "normalized string exceeds buffer length!\n");
	}
	g_strlcpy(buf, tmp2, sizeof(buf));
	g_free(tmp2);
	g_free(tmp1);

	return buf;
}

gboolean
oscar_offline_message(const PurpleBuddy *buddy)
{
	return TRUE;
}

/* TODO: Find somewhere to put this instead of including it in a bunch of places.
 * Maybe just change purple_accounts_find() to return anything for the prpl if there is no acct_id.
 */
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


static gboolean oscar_uri_handler(const char *proto, const char *cmd, GHashTable *params)
{
	char *acct_id = g_hash_table_lookup(params, "account");
	char prpl[11];
	PurpleAccount *acct;

	if (g_ascii_strcasecmp(proto, "aim") && g_ascii_strcasecmp(proto, "icq"))
		return FALSE;

	g_snprintf(prpl, sizeof(prpl), "prpl-%s", proto);

	acct = find_acct(prpl, acct_id);

	if (!acct)
		return FALSE;

	/* aim:GoIM?screenname=SCREENNAME&message=MESSAGE */
	if (!g_ascii_strcasecmp(cmd, "GoIM")) {
		char *bname = g_hash_table_lookup(params, "screenname");
		if (bname) {
			char *message = g_hash_table_lookup(params, "message");

			PurpleConversation *conv = purple_find_conversation_with_account(
				PURPLE_CONV_TYPE_IM, bname, acct);
			if (conv == NULL)
				conv = purple_conversation_new(PURPLE_CONV_TYPE_IM, acct, bname);
			purple_conversation_present(conv);

			if (message) {
				/* Spaces are encoded as '+' */
				g_strdelimit(message, "+", ' ');
				purple_conv_send_confirm(conv, message);
			}
		}
		/*else
			**If pidgindialogs_im() was in the core, we could use it here.
			 * It is all purple_request_* based, but I'm not sure it really belongs in the core
			pidgindialogs_im();*/

		return TRUE;
	}
	/* aim:GoChat?roomname=CHATROOMNAME&exchange=4 */
	else if (!g_ascii_strcasecmp(cmd, "GoChat")) {
		char *rname = g_hash_table_lookup(params, "roomname");
		if (rname) {
			/* This is somewhat hacky, but the params aren't useful after this command */
			g_hash_table_insert(params, g_strdup("exchange"), g_strdup("4"));
			g_hash_table_insert(params, g_strdup("room"), g_strdup(rname));
			serv_join_chat(purple_account_get_connection(acct), params);
		}
		/*else
			** Same as above (except that this would have to be re-written using purple_request_*)
			pidgin_blist_joinchat_show(); */

		return TRUE;
	}
	/* aim:AddBuddy?screenname=SCREENNAME&groupname=GROUPNAME*/
	else if (!g_ascii_strcasecmp(cmd, "AddBuddy")) {
		char *bname = g_hash_table_lookup(params, "screenname");
		char *gname = g_hash_table_lookup(params, "groupname");
		purple_blist_request_add_buddy(acct, bname, gname, NULL);
		return TRUE;
	}

	return FALSE;
}

void oscar_init(PurplePlugin *plugin, gboolean is_icq)
{
	PurplePluginProtocolInfo *prpl_info = PURPLE_PLUGIN_PROTOCOL_INFO(plugin);
	PurpleAccountOption *option;
	static gboolean init = FALSE;
	static const gchar *encryption_keys[] = {
		N_("Use encryption if available"),
		N_("Require encryption"),
		N_("Don't use encryption"),
		NULL
	};
	static const gchar *encryption_values[] = {
		OSCAR_OPPORTUNISTIC_ENCRYPTION,
		OSCAR_REQUIRE_ENCRYPTION,
		OSCAR_NO_ENCRYPTION,
		NULL
	};
	GList *encryption_options = NULL;
	int i;

	option = purple_account_option_string_new(_("Server"), "server", get_login_server(is_icq, TRUE));
	prpl_info->protocol_options = g_list_append(prpl_info->protocol_options, option);

	option = purple_account_option_int_new(_("Port"), "port", OSCAR_DEFAULT_LOGIN_PORT);
	prpl_info->protocol_options = g_list_append(prpl_info->protocol_options, option);

	for (i = 0; encryption_keys[i]; i++) {
		PurpleKeyValuePair *kvp = g_new0(PurpleKeyValuePair, 1);
		kvp->key = g_strdup(_(encryption_keys[i]));
		kvp->value = g_strdup(encryption_values[i]);
		encryption_options = g_list_append(encryption_options, kvp);
	}
	option = purple_account_option_list_new(_("Connection security"), "encryption", encryption_options);
	prpl_info->protocol_options = g_list_append(prpl_info->protocol_options, option);

	option = purple_account_option_bool_new(_("Use clientLogin"), "use_clientlogin",
			OSCAR_DEFAULT_USE_CLIENTLOGIN);
	prpl_info->protocol_options = g_list_append(prpl_info->protocol_options, option);

	option = purple_account_option_bool_new(
		_("Always use AIM/ICQ proxy server for\nfile transfers and direct IM (slower,\nbut does not reveal your IP address)"), "always_use_rv_proxy",
		OSCAR_DEFAULT_ALWAYS_USE_RV_PROXY);
	prpl_info->protocol_options = g_list_append(prpl_info->protocol_options, option);

	if (g_str_equal(purple_plugin_get_id(plugin), "prpl-aim")) {
		option = purple_account_option_bool_new(_("Allow multiple simultaneous logins"), "allow_multiple_logins",
												OSCAR_DEFAULT_ALLOW_MULTIPLE_LOGINS);
		prpl_info->protocol_options = g_list_append(prpl_info->protocol_options, option);
	}

	if (init)
		return;
	init = TRUE;

	/* Preferences */
	purple_prefs_add_none("/plugins/prpl/oscar");
	purple_prefs_add_bool("/plugins/prpl/oscar/recent_buddies", FALSE);

	purple_prefs_remove("/plugins/prpl/oscar/show_idle");
	purple_prefs_remove("/plugins/prpl/oscar/always_use_rv_proxy");

	/* protocol handler */
	/* TODO: figure out a good instance to use here */
	purple_signal_connect(purple_get_core(), "uri-handler", &init,
		PURPLE_CALLBACK(oscar_uri_handler), NULL);
}

