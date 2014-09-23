/**
 * @file irc.c
 *
 * purple
 *
 * Copyright (C) 2003, Robbert Haarman <purple@inglorion.net>
 * Copyright (C) 2003, 2012 Ethan Blanton <elb@pidgin.im>
 * Copyright (C) 2000-2003, Rob Flynn <rob@tgflinux.com>
 * Copyright (C) 1998-1999, Mark Spencer <markster@marko.net>
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

#include "accountopt.h"
#include "blist.h"
#include "conversation.h"
#include "debug.h"
#include "notify.h"
#include "prpl.h"
#include "plugin.h"
#include "util.h"
#include "version.h"

#include "irc.h"

#define PING_TIMEOUT 60

static void irc_ison_buddy_init(char *name, struct irc_buddy *ib, GList **list);

static const char *irc_blist_icon(PurpleAccount *a, PurpleBuddy *b);
static GList *irc_status_types(PurpleAccount *account);
static GList *irc_actions(PurplePlugin *plugin, gpointer context);
/* static GList *irc_chat_info(PurpleConnection *gc); */
static void irc_login(PurpleAccount *account);
static void irc_login_cb_ssl(gpointer data, PurpleSslConnection *gsc, PurpleInputCondition cond);
static void irc_login_cb(gpointer data, gint source, const gchar *error_message);
static void irc_ssl_connect_failure(PurpleSslConnection *gsc, PurpleSslErrorType error, gpointer data);
static void irc_close(PurpleConnection *gc);
static int irc_im_send(PurpleConnection *gc, const char *who, const char *what, PurpleMessageFlags flags);
static int irc_chat_send(PurpleConnection *gc, int id, const char *what, PurpleMessageFlags flags);
static void irc_chat_join (PurpleConnection *gc, GHashTable *data);
static void irc_input_cb(gpointer data, gint source, PurpleInputCondition cond);
static void irc_input_cb_ssl(gpointer data, PurpleSslConnection *gsc, PurpleInputCondition cond);

static guint irc_nick_hash(const char *nick);
static gboolean irc_nick_equal(const char *nick1, const char *nick2);
static void irc_buddy_free(struct irc_buddy *ib);

PurplePlugin *_irc_plugin = NULL;

static void irc_view_motd(PurplePluginAction *action)
{
	PurpleConnection *gc = (PurpleConnection *) action->context;
	struct irc_conn *irc;
	char *title;

	if (gc == NULL || gc->proto_data == NULL) {
		purple_debug(PURPLE_DEBUG_ERROR, "irc", "got MOTD request for NULL gc\n");
		return;
	}
	irc = gc->proto_data;
	if (irc->motd == NULL) {
		purple_notify_error(gc, _("Error displaying MOTD"), _("No MOTD available"),
				  _("There is no MOTD associated with this connection."));
		return;
	}
	title = g_strdup_printf(_("MOTD for %s"), irc->server);
	purple_notify_formatted(gc, title, title, NULL, irc->motd->str, NULL, NULL);
	g_free(title);
}

static int do_send(struct irc_conn *irc, const char *buf, gsize len)
{
	int ret;

	if (irc->gsc) {
		ret = purple_ssl_write(irc->gsc, buf, len);
	} else {
		ret = write(irc->fd, buf, len);
	}

	return ret;
}

static int irc_send_raw(PurpleConnection *gc, const char *buf, int len)
{
	struct irc_conn *irc = (struct irc_conn*)gc->proto_data;
	if (len == -1) {
		len = strlen(buf);
	}
	irc_send_len(irc, buf, len);
	return len;
}

static void
irc_send_cb(gpointer data, gint source, PurpleInputCondition cond)
{
	struct irc_conn *irc = data;
	int ret, writelen;

	writelen = purple_circ_buffer_get_max_read(irc->outbuf);

	if (writelen == 0) {
		purple_input_remove(irc->writeh);
		irc->writeh = 0;
		return;
	}

	ret = do_send(irc, irc->outbuf->outptr, writelen);

	if (ret < 0 && errno == EAGAIN)
		return;
	else if (ret <= 0) {
		PurpleConnection *gc = purple_account_get_connection(irc->account);
		gchar *tmp = g_strdup_printf(_("Lost connection with server: %s"),
			g_strerror(errno));
		purple_connection_error_reason (gc,
			PURPLE_CONNECTION_ERROR_NETWORK_ERROR, tmp);
		g_free(tmp);
		return;
	}

	purple_circ_buffer_mark_read(irc->outbuf, ret);

#if 0
	/* We *could* try to write more if we wrote it all */
	if (ret == write_len) {
		irc_send_cb(data, source, cond);
	}
#endif
}

int irc_send(struct irc_conn *irc, const char *buf)
{
    return irc_send_len(irc, buf, strlen(buf));
}

int irc_send_len(struct irc_conn *irc, const char *buf, int buflen)
{
	int ret;
 	char *tosend= g_strdup(buf);

	purple_signal_emit(_irc_plugin, "irc-sending-text", purple_account_get_connection(irc->account), &tosend);
	
	if (tosend == NULL)
		return 0;

	/* If we're not buffering writes, try to send immediately */
	if (!irc->writeh)
		ret = do_send(irc, tosend, buflen);
	else {
		ret = -1;
		errno = EAGAIN;
	}

	/* purple_debug(PURPLE_DEBUG_MISC, "irc", "sent%s: %s",
		irc->gsc ? " (ssl)" : "", tosend); */
	if (ret <= 0 && errno != EAGAIN) {
		PurpleConnection *gc = purple_account_get_connection(irc->account);
		gchar *tmp = g_strdup_printf(_("Lost connection with server: %s"),
			g_strerror(errno));
		purple_connection_error_reason (gc,
			PURPLE_CONNECTION_ERROR_NETWORK_ERROR, tmp);
		g_free(tmp);
	} else if (ret < buflen) {
		if (ret < 0)
			ret = 0;
		if (!irc->writeh)
			irc->writeh = purple_input_add(
				irc->gsc ? irc->gsc->fd : irc->fd,
				PURPLE_INPUT_WRITE, irc_send_cb, irc);
		purple_circ_buffer_append(irc->outbuf, tosend + ret,
			buflen - ret);
	}
	g_free(tosend);
	return ret;
}

/* XXX I don't like messing directly with these buddies */
gboolean irc_blist_timeout(struct irc_conn *irc)
{
	if (irc->ison_outstanding) {
		return TRUE;
	}

	g_hash_table_foreach(irc->buddies, (GHFunc)irc_ison_buddy_init,
	                     (gpointer *)&irc->buddies_outstanding);

	irc_buddy_query(irc);

	return TRUE;
}

void irc_buddy_query(struct irc_conn *irc)
{
	GList *lp;
	GString *string;
	struct irc_buddy *ib;
	char *buf;

	string = g_string_sized_new(512);

	while ((lp = g_list_first(irc->buddies_outstanding))) {
		ib = (struct irc_buddy *)lp->data;
		if (string->len + strlen(ib->name) + 1 > 450)
			break;
		g_string_append_printf(string, "%s ", ib->name);
		ib->new_online_status = FALSE;
		irc->buddies_outstanding = g_list_remove_link(irc->buddies_outstanding, lp);
	}

	if (string->len) {
		buf = irc_format(irc, "vn", "ISON", string->str);
		irc_send(irc, buf);
		g_free(buf);
		irc->ison_outstanding = TRUE;
	} else
		irc->ison_outstanding = FALSE;

	g_string_free(string, TRUE);
}

static void irc_ison_buddy_init(char *name, struct irc_buddy *ib, GList **list)
{
	*list = g_list_append(*list, ib);
}


static void irc_ison_one(struct irc_conn *irc, struct irc_buddy *ib)
{
	char *buf;

	if (irc->buddies_outstanding != NULL) {
		irc->buddies_outstanding = g_list_append(irc->buddies_outstanding, ib);
		return;
	}

	ib->new_online_status = FALSE;
	buf = irc_format(irc, "vn", "ISON", ib->name);
	irc_send(irc, buf);
	g_free(buf);
}


static const char *irc_blist_icon(PurpleAccount *a, PurpleBuddy *b)
{
	return "irc";
}

static GList *irc_status_types(PurpleAccount *account)
{
	PurpleStatusType *type;
	GList *types = NULL;

	type = purple_status_type_new(PURPLE_STATUS_AVAILABLE, NULL, NULL, TRUE);
	types = g_list_append(types, type);

	type = purple_status_type_new_with_attrs(
		PURPLE_STATUS_AWAY, NULL, NULL, TRUE, TRUE, FALSE,
		"message", _("Message"), purple_value_new(PURPLE_TYPE_STRING),
		NULL);
	types = g_list_append(types, type);

	type = purple_status_type_new(PURPLE_STATUS_OFFLINE, NULL, NULL, TRUE);
	types = g_list_append(types, type);

	return types;
}

static GList *irc_actions(PurplePlugin *plugin, gpointer context)
{
	GList *list = NULL;
	PurplePluginAction *act = NULL;

	act = purple_plugin_action_new(_("View MOTD"), irc_view_motd);
	list = g_list_append(list, act);

	return list;
}

static GList *irc_chat_join_info(PurpleConnection *gc)
{
	GList *m = NULL;
	struct proto_chat_entry *pce;

	pce = g_new0(struct proto_chat_entry, 1);
	pce->label = _("_Channel:");
	pce->identifier = "channel";
	pce->required = TRUE;
	m = g_list_append(m, pce);

	pce = g_new0(struct proto_chat_entry, 1);
	pce->label = _("_Password:");
	pce->identifier = "password";
	pce->secret = TRUE;
	m = g_list_append(m, pce);

	return m;
}

static GHashTable *irc_chat_info_defaults(PurpleConnection *gc, const char *chat_name)
{
	GHashTable *defaults;

	defaults = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);

	if (chat_name != NULL)
		g_hash_table_insert(defaults, "channel", g_strdup(chat_name));

	return defaults;
}

static void irc_login(PurpleAccount *account)
{
	PurpleConnection *gc;
	struct irc_conn *irc;
	char **userparts;
	const char *username = purple_account_get_username(account);

	gc = purple_account_get_connection(account);
	gc->flags |= PURPLE_CONNECTION_NO_NEWLINES;

	if (strpbrk(username, " \t\v\r\n") != NULL) {
		purple_connection_error_reason (gc,
			PURPLE_CONNECTION_ERROR_INVALID_SETTINGS,
			_("IRC nick and server may not contain whitespace"));
		return;
	}

	gc->proto_data = irc = g_new0(struct irc_conn, 1);
	irc->fd = -1;
	irc->account = account;
	irc->outbuf = purple_circ_buffer_new(512);

	userparts = g_strsplit(username, "@", 2);
	purple_connection_set_display_name(gc, userparts[0]);
	irc->server = g_strdup(userparts[1]);
	g_strfreev(userparts);

	irc->buddies = g_hash_table_new_full((GHashFunc)irc_nick_hash, (GEqualFunc)irc_nick_equal,
					     NULL, (GDestroyNotify)irc_buddy_free);
	irc->cmds = g_hash_table_new(g_str_hash, g_str_equal);
	irc_cmd_table_build(irc);
	irc->msgs = g_hash_table_new(g_str_hash, g_str_equal);
	irc_msg_table_build(irc);

	purple_connection_update_progress(gc, _("Connecting"), 1, 2);

	if (purple_account_get_bool(account, "ssl", FALSE)) {
		if (purple_ssl_is_supported()) {
			irc->gsc = purple_ssl_connect(account, irc->server,
					purple_account_get_int(account, "port", IRC_DEFAULT_SSL_PORT),
					irc_login_cb_ssl, irc_ssl_connect_failure, gc);
		} else {
			purple_connection_error_reason (gc,
				PURPLE_CONNECTION_ERROR_NO_SSL_SUPPORT,
				_("SSL support unavailable"));
			return;
		}
	}

	if (!irc->gsc) {

		if (purple_proxy_connect(gc, account, irc->server,
				 purple_account_get_int(account, "port", IRC_DEFAULT_PORT),
				 irc_login_cb, gc) == NULL)
		{
			purple_connection_error_reason (gc,
				PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
				_("Unable to connect"));
			return;
		}
	}
}

static gboolean do_login(PurpleConnection *gc) {
	char *buf, *tmp = NULL;
	char *server;
	const char *nickname, *identname, *realname;
	struct irc_conn *irc = gc->proto_data;
	const char *pass = purple_connection_get_password(gc);
#ifdef HAVE_CYRUS_SASL
	const gboolean use_sasl = purple_account_get_bool(irc->account, "sasl", FALSE);
#endif

	if (pass && *pass) {
#ifdef HAVE_CYRUS_SASL
		if (use_sasl)
			buf = irc_format(irc, "vv:", "CAP", "REQ", "sasl");
		else /* intended to fall through */
#endif
			buf = irc_format(irc, "v:", "PASS", pass);
		if (irc_send(irc, buf) < 0) {
			g_free(buf);
			return FALSE;
		}
		g_free(buf);
	}

	realname = purple_account_get_string(irc->account, "realname", "");
	identname = purple_account_get_string(irc->account, "username", "");

	if (identname == NULL || *identname == '\0') {
		identname = g_get_user_name();
	}

	if (identname != NULL && strchr(identname, ' ') != NULL) {
		tmp = g_strdup(identname);
		while ((buf = strchr(tmp, ' ')) != NULL) {
			*buf = '_';
		}
	}

	if (*irc->server == ':') {
		/* Same as hostname, above. */
		server = g_strdup_printf("0%s", irc->server);
	} else {
		server = g_strdup(irc->server);
	}

	buf = irc_format(irc, "vvvv:", "USER", tmp ? tmp : identname, "*", server,
	                 strlen(realname) ? realname : IRC_DEFAULT_ALIAS);
	g_free(tmp);
	g_free(server);
	if (irc_send(irc, buf) < 0) {
		g_free(buf);
		return FALSE;
	}
	g_free(buf);
	nickname = purple_connection_get_display_name(gc);
	buf = irc_format(irc, "vn", "NICK", nickname);
	irc->reqnick = g_strdup(nickname);
	irc->nickused = FALSE;
	if (irc_send(irc, buf) < 0) {
		g_free(buf);
		return FALSE;
	}
	g_free(buf);

	irc->recv_time = time(NULL);

	return TRUE;
}

static void irc_login_cb_ssl(gpointer data, PurpleSslConnection *gsc,
	PurpleInputCondition cond)
{
	PurpleConnection *gc = data;

	if (do_login(gc)) {
		purple_ssl_input_add(gsc, irc_input_cb_ssl, gc);
	}
}

static void irc_login_cb(gpointer data, gint source, const gchar *error_message)
{
	PurpleConnection *gc = data;
	struct irc_conn *irc = gc->proto_data;

	if (source < 0) {
		gchar *tmp = g_strdup_printf(_("Unable to connect: %s"),
			error_message);
		purple_connection_error_reason (gc,
			PURPLE_CONNECTION_ERROR_NETWORK_ERROR, tmp);
		g_free(tmp);
		return;
	}

	irc->fd = source;

	if (do_login(gc)) {
		gc->inpa = purple_input_add(irc->fd, PURPLE_INPUT_READ, irc_input_cb, gc);
	}
}

static void
irc_ssl_connect_failure(PurpleSslConnection *gsc, PurpleSslErrorType error,
		gpointer data)
{
	PurpleConnection *gc = data;
	struct irc_conn *irc = gc->proto_data;

	irc->gsc = NULL;

	purple_connection_ssl_error (gc, error);
}

static void irc_close(PurpleConnection *gc)
{
	struct irc_conn *irc = gc->proto_data;

	if (irc == NULL)
		return;

	if (irc->gsc || (irc->fd >= 0))
		irc_cmd_quit(irc, "quit", NULL, NULL);

	if (gc->inpa)
		purple_input_remove(gc->inpa);

	g_free(irc->inbuf);
	if (irc->gsc) {
		purple_ssl_close(irc->gsc);
	} else if (irc->fd >= 0) {
		close(irc->fd);
	}
	if (irc->timer)
		purple_timeout_remove(irc->timer);
	g_hash_table_destroy(irc->cmds);
	g_hash_table_destroy(irc->msgs);
	g_hash_table_destroy(irc->buddies);
	if (irc->motd)
		g_string_free(irc->motd, TRUE);
	g_free(irc->server);

	if (irc->writeh)
		purple_input_remove(irc->writeh);

	purple_circ_buffer_destroy(irc->outbuf);

	g_free(irc->mode_chars);
	g_free(irc->reqnick);

#ifdef HAVE_CYRUS_SASL
	if (irc->sasl_conn) {
		sasl_dispose(&irc->sasl_conn);
		irc->sasl_conn = NULL;
	}
	g_free(irc->sasl_cb);
	if(irc->sasl_mechs)
		g_string_free(irc->sasl_mechs, TRUE);
#endif


	g_free(irc);
}

static int irc_im_send(PurpleConnection *gc, const char *who, const char *what, PurpleMessageFlags flags)
{
	struct irc_conn *irc = gc->proto_data;
	char *plain;
	const char *args[2];

	args[0] = irc_nick_skip_mode(irc, who);

	purple_markup_html_to_xhtml(what, NULL, &plain);
	args[1] = plain;

	irc_cmd_privmsg(irc, "msg", NULL, args);
	g_free(plain);
	return 1;
}

static void irc_get_info(PurpleConnection *gc, const char *who)
{
	struct irc_conn *irc = gc->proto_data;
	const char *args[2];
	args[0] = who;
	args[1] = NULL;
	irc_cmd_whois(irc, "whois", NULL, args);
}

static void irc_set_status(PurpleAccount *account, PurpleStatus *status)
{
	PurpleConnection *gc = purple_account_get_connection(account);
	struct irc_conn *irc;
	const char *args[1];
	const char *status_id = purple_status_get_id(status);

	g_return_if_fail(gc != NULL);
	irc = gc->proto_data;

	if (!purple_status_is_active(status))
		return;

	args[0] = NULL;

	if (!strcmp(status_id, "away")) {
		args[0] = purple_status_get_attr_string(status, "message");
		if ((args[0] == NULL) || (*args[0] == '\0'))
			args[0] = _("Away");
		irc_cmd_away(irc, "away", NULL, args);
	} else if (!strcmp(status_id, "available")) {
		irc_cmd_away(irc, "back", NULL, args);
	}
}

static void irc_add_buddy(PurpleConnection *gc, PurpleBuddy *buddy, PurpleGroup *group)
{
	struct irc_conn *irc = (struct irc_conn *)gc->proto_data;
	struct irc_buddy *ib;
	const char *bname = purple_buddy_get_name(buddy);

	ib = g_hash_table_lookup(irc->buddies, bname);
	if (ib != NULL) {
		ib->ref++;
		purple_prpl_got_user_status(irc->account, bname,
				ib->online ? "available" : "offline", NULL);
	} else {
		ib = g_new0(struct irc_buddy, 1);
		ib->name = g_strdup(bname);
		ib->ref = 1;
		g_hash_table_replace(irc->buddies, ib->name, ib);
	}

	/* if the timer isn't set, this is during signon, so we don't want to flood
	 * ourself off with ISON's, so we don't, but after that we want to know when
	 * someone's online asap */
	if (irc->timer)
		irc_ison_one(irc, ib);
}

static void irc_remove_buddy(PurpleConnection *gc, PurpleBuddy *buddy, PurpleGroup *group)
{
	struct irc_conn *irc = (struct irc_conn *)gc->proto_data;
	struct irc_buddy *ib;

	ib = g_hash_table_lookup(irc->buddies, purple_buddy_get_name(buddy));
	if (ib && --ib->ref == 0) {
		g_hash_table_remove(irc->buddies, purple_buddy_get_name(buddy));
	}
}

static void read_input(struct irc_conn *irc, int len)
{
	char *cur, *end;

	irc->account->gc->last_received = time(NULL);
	irc->inbufused += len;
	irc->inbuf[irc->inbufused] = '\0';

	cur = irc->inbuf;

	/* This is a hack to work around the fact that marv gets messages
	 * with null bytes in them while using some weird irc server at work
	 */
	while ((cur < (irc->inbuf + irc->inbufused)) && !*cur)
		cur++;

	while (cur < irc->inbuf + irc->inbufused &&
	       ((end = strstr(cur, "\r\n")) || (end = strstr(cur, "\n")))) {
		int step = (*end == '\r' ? 2 : 1);
		*end = '\0';
		irc_parse_msg(irc, cur);
		cur = end + step;
	}
	if (cur != irc->inbuf + irc->inbufused) { /* leftover */
		irc->inbufused -= (cur - irc->inbuf);
		memmove(irc->inbuf, cur, irc->inbufused);
	} else {
		irc->inbufused = 0;
	}
}

static void irc_input_cb_ssl(gpointer data, PurpleSslConnection *gsc,
		PurpleInputCondition cond)
{

	PurpleConnection *gc = data;
	struct irc_conn *irc = gc->proto_data;
	int len;

	if(!g_list_find(purple_connections_get_all(), gc)) {
		purple_ssl_close(gsc);
		return;
	}

	if (irc->inbuflen < irc->inbufused + IRC_INITIAL_BUFSIZE) {
		irc->inbuflen += IRC_INITIAL_BUFSIZE;
		irc->inbuf = g_realloc(irc->inbuf, irc->inbuflen);
	}

	len = purple_ssl_read(gsc, irc->inbuf + irc->inbufused, IRC_INITIAL_BUFSIZE - 1);

	if (len < 0 && errno == EAGAIN) {
		/* Try again later */
		return;
	} else if (len < 0) {
		gchar *tmp = g_strdup_printf(_("Lost connection with server: %s"),
				g_strerror(errno));
		purple_connection_error_reason (gc,
			PURPLE_CONNECTION_ERROR_NETWORK_ERROR, tmp);
		g_free(tmp);
		return;
	} else if (len == 0) {
		purple_connection_error_reason (gc,
			PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
			_("Server closed the connection"));
		return;
	}

	read_input(irc, len);
}

static void irc_input_cb(gpointer data, gint source, PurpleInputCondition cond)
{
	PurpleConnection *gc = data;
	struct irc_conn *irc = gc->proto_data;
	int len;

	if (irc->inbuflen < irc->inbufused + IRC_INITIAL_BUFSIZE) {
		irc->inbuflen += IRC_INITIAL_BUFSIZE;
		irc->inbuf = g_realloc(irc->inbuf, irc->inbuflen);
	}

	len = read(irc->fd, irc->inbuf + irc->inbufused, IRC_INITIAL_BUFSIZE - 1);
	if (len < 0 && errno == EAGAIN) {
		return;
	} else if (len < 0) {
		gchar *tmp = g_strdup_printf(_("Lost connection with server: %s"),
				g_strerror(errno));
		purple_connection_error_reason (gc,
			PURPLE_CONNECTION_ERROR_NETWORK_ERROR, tmp);
		g_free(tmp);
		return;
	} else if (len == 0) {
		purple_connection_error_reason (gc,
			PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
			_("Server closed the connection"));
		return;
	}

	read_input(irc, len);
}

static void irc_chat_join (PurpleConnection *gc, GHashTable *data)
{
	struct irc_conn *irc = gc->proto_data;
	const char *args[2];

	args[0] = g_hash_table_lookup(data, "channel");
	args[1] = g_hash_table_lookup(data, "password");
	irc_cmd_join(irc, "join", NULL, args);
}

static char *irc_get_chat_name(GHashTable *data) {
	return g_strdup(g_hash_table_lookup(data, "channel"));
}

static void irc_chat_invite(PurpleConnection *gc, int id, const char *message, const char *name)
{
	struct irc_conn *irc = gc->proto_data;
	PurpleConversation *convo = purple_find_chat(gc, id);
	const char *args[2];

	if (!convo) {
		purple_debug(PURPLE_DEBUG_ERROR, "irc", "Got chat invite request for bogus chat\n");
		return;
	}
	args[0] = name;
	args[1] = purple_conversation_get_name(convo);
	irc_cmd_invite(irc, "invite", purple_conversation_get_name(convo), args);
}


static void irc_chat_leave (PurpleConnection *gc, int id)
{
	struct irc_conn *irc = gc->proto_data;
	PurpleConversation *convo = purple_find_chat(gc, id);
	const char *args[2];

	if (!convo)
		return;

	args[0] = purple_conversation_get_name(convo);
	args[1] = NULL;
	irc_cmd_part(irc, "part", purple_conversation_get_name(convo), args);
	serv_got_chat_left(gc, id);
}

static int irc_chat_send(PurpleConnection *gc, int id, const char *what, PurpleMessageFlags flags)
{
	struct irc_conn *irc = gc->proto_data;
	PurpleConversation *convo = purple_find_chat(gc, id);
	const char *args[2];
	char *tmp;

	if (!convo) {
		purple_debug(PURPLE_DEBUG_ERROR, "irc", "chat send on nonexistent chat\n");
		return -EINVAL;
	}
#if 0
	if (*what == '/') {
		return irc_parse_cmd(irc, convo->name, what + 1);
	}
#endif
	purple_markup_html_to_xhtml(what, NULL, &tmp);
	args[0] = convo->name;
	args[1] = tmp;

	irc_cmd_privmsg(irc, "msg", NULL, args);

	serv_got_chat_in(gc, id, purple_connection_get_display_name(gc), flags, what, time(NULL));
	g_free(tmp);
	return 0;
}

static guint irc_nick_hash(const char *nick)
{
	char *lc;
	guint bucket;

	lc = g_utf8_strdown(nick, -1);
	bucket = g_str_hash(lc);
	g_free(lc);

	return bucket;
}

static gboolean irc_nick_equal(const char *nick1, const char *nick2)
{
	return (purple_utf8_strcasecmp(nick1, nick2) == 0);
}

static void irc_buddy_free(struct irc_buddy *ib)
{
	g_free(ib->name);
	g_free(ib);
}

static void irc_chat_set_topic(PurpleConnection *gc, int id, const char *topic)
{
	char *buf;
	const char *name = NULL;
	struct irc_conn *irc;

	irc = gc->proto_data;
	name = purple_conversation_get_name(purple_find_chat(gc, id));

	if (name == NULL)
		return;

	buf = irc_format(irc, "vt:", "TOPIC", name, topic);
	irc_send(irc, buf);
	g_free(buf);
}

static PurpleRoomlist *irc_roomlist_get_list(PurpleConnection *gc)
{
	struct irc_conn *irc;
	GList *fields = NULL;
	PurpleRoomlistField *f;
	char *buf;

	irc = gc->proto_data;

	if (irc->roomlist)
		purple_roomlist_unref(irc->roomlist);

	irc->roomlist = purple_roomlist_new(purple_connection_get_account(gc));

	f = purple_roomlist_field_new(PURPLE_ROOMLIST_FIELD_STRING, "", "channel", TRUE);
	fields = g_list_append(fields, f);

	f = purple_roomlist_field_new(PURPLE_ROOMLIST_FIELD_INT, _("Users"), "users", FALSE);
	fields = g_list_append(fields, f);

	f = purple_roomlist_field_new(PURPLE_ROOMLIST_FIELD_STRING, _("Topic"), "topic", FALSE);
	fields = g_list_append(fields, f);

	purple_roomlist_set_fields(irc->roomlist, fields);

	buf = irc_format(irc, "v", "LIST");
	irc_send(irc, buf);
	g_free(buf);

	return irc->roomlist;
}

static void irc_roomlist_cancel(PurpleRoomlist *list)
{
	PurpleConnection *gc = purple_account_get_connection(list->account);
	struct irc_conn *irc;

	if (gc == NULL)
		return;

	irc = gc->proto_data;

	purple_roomlist_set_in_progress(list, FALSE);

	if (irc->roomlist == list) {
		irc->roomlist = NULL;
		purple_roomlist_unref(list);
	}
}

static void irc_keepalive(PurpleConnection *gc)
{
	struct irc_conn *irc = gc->proto_data;
	if ((time(NULL) - irc->recv_time) > PING_TIMEOUT)
		irc_cmd_ping(irc, NULL, NULL, NULL);
}

static PurplePluginProtocolInfo prpl_info =
{
	OPT_PROTO_CHAT_TOPIC | OPT_PROTO_PASSWORD_OPTIONAL |
	OPT_PROTO_SLASH_COMMANDS_NATIVE,
	NULL,					/* user_splits */
	NULL,					/* protocol_options */
	NO_BUDDY_ICONS,		/* icon_spec */
	irc_blist_icon,		/* list_icon */
	NULL,			/* list_emblems */
	NULL,					/* status_text */
	NULL,					/* tooltip_text */
	irc_status_types,	/* away_states */
	NULL,					/* blist_node_menu */
	irc_chat_join_info,	/* chat_info */
	irc_chat_info_defaults,	/* chat_info_defaults */
	irc_login,		/* login */
	irc_close,		/* close */
	irc_im_send,		/* send_im */
	NULL,					/* set_info */
	NULL,					/* send_typing */
	irc_get_info,		/* get_info */
	irc_set_status,		/* set_status */
	NULL,					/* set_idle */
	NULL,					/* change_passwd */
	irc_add_buddy,		/* add_buddy */
	NULL,					/* add_buddies */
	irc_remove_buddy,	/* remove_buddy */
	NULL,					/* remove_buddies */
	NULL,					/* add_permit */
	NULL,					/* add_deny */
	NULL,					/* rem_permit */
	NULL,					/* rem_deny */
	NULL,					/* set_permit_deny */
	irc_chat_join,		/* join_chat */
	NULL,					/* reject_chat */
	irc_get_chat_name,	/* get_chat_name */
	irc_chat_invite,	/* chat_invite */
	irc_chat_leave,		/* chat_leave */
	NULL,					/* chat_whisper */
	irc_chat_send,		/* chat_send */
	irc_keepalive,		/* keepalive */
	NULL,					/* register_user */
	NULL,					/* get_cb_info */
	NULL,					/* get_cb_away */
	NULL,					/* alias_buddy */
	NULL,					/* group_buddy */
	NULL,					/* rename_group */
	NULL,					/* buddy_free */
	NULL,					/* convo_closed */
	purple_normalize_nocase,	/* normalize */
	NULL,					/* set_buddy_icon */
	NULL,					/* remove_group */
	NULL,					/* get_cb_real_name */
	irc_chat_set_topic,	/* set_chat_topic */
	NULL,					/* find_blist_chat */
	irc_roomlist_get_list,	/* roomlist_get_list */
	irc_roomlist_cancel,	/* roomlist_cancel */
	NULL,					/* roomlist_expand_category */
	NULL,					/* can_receive_file */
	irc_dccsend_send_file,	/* send_file */
	irc_dccsend_new_xfer,	/* new_xfer */
	NULL,					/* offline_message */
	NULL,					/* whiteboard_prpl_ops */
	irc_send_raw,			/* send_raw */
	NULL,					/* roomlist_room_serialize */
	NULL,                   /* unregister_user */
	NULL,                   /* send_attention */
	NULL,                   /* get_attention_types */
	sizeof(PurplePluginProtocolInfo),    /* struct_size */
	NULL,                    /* get_account_text_table */
	NULL,                    /* initiate_media */
	NULL,					 /* get_media_caps */
	NULL,					 /* get_moods */
	NULL,					 /* set_public_alias */
	NULL,					 /* get_public_alias */
	NULL,					 /* add_buddy_with_invite */
	NULL					 /* add_buddies_with_invite */
};

static gboolean load_plugin (PurplePlugin *plugin) {

	purple_signal_register(plugin, "irc-sending-text",
			     purple_marshal_VOID__POINTER_POINTER, NULL, 2,
			     purple_value_new(PURPLE_TYPE_SUBTYPE, PURPLE_SUBTYPE_CONNECTION),
			     purple_value_new_outgoing(PURPLE_TYPE_STRING));
	purple_signal_register(plugin, "irc-receiving-text",
			     purple_marshal_VOID__POINTER_POINTER, NULL, 2,
			     purple_value_new(PURPLE_TYPE_SUBTYPE, PURPLE_SUBTYPE_CONNECTION),
			     purple_value_new_outgoing(PURPLE_TYPE_STRING));
	return TRUE;
}


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

	"prpl-irc",                                       /**< id             */
	"IRC",                                            /**< name           */
	DISPLAY_VERSION,                                  /**< version        */
	N_("IRC Protocol Plugin"),                        /**  summary        */
	N_("The IRC Protocol Plugin that Sucks Less"),    /**  description    */
	NULL,                                             /**< author         */
	PURPLE_WEBSITE,                                     /**< homepage       */

	load_plugin,                                      /**< load           */
	NULL,                                             /**< unload         */
	NULL,                                             /**< destroy        */

	NULL,                                             /**< ui_info        */
	&prpl_info,                                       /**< extra_info     */
	NULL,                                             /**< prefs_info     */
	irc_actions,

	/* padding */
	NULL,
	NULL,
	NULL,
	NULL
};

static void _init_plugin(PurplePlugin *plugin)
{
	PurpleAccountUserSplit *split;
	PurpleAccountOption *option;

	split = purple_account_user_split_new(_("Server"), IRC_DEFAULT_SERVER, '@');
	prpl_info.user_splits = g_list_append(prpl_info.user_splits, split);

	option = purple_account_option_int_new(_("Port"), "port", IRC_DEFAULT_PORT);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	option = purple_account_option_string_new(_("Encodings"), "encoding", IRC_DEFAULT_CHARSET);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	option = purple_account_option_bool_new(_("Auto-detect incoming UTF-8"), "autodetect_utf8", IRC_DEFAULT_AUTODETECT);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	option = purple_account_option_string_new(_("Ident name"), "username", "");
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	option = purple_account_option_string_new(_("Real name"), "realname", "");
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	/*
	option = purple_account_option_string_new(_("Quit message"), "quitmsg", IRC_DEFAULT_QUIT);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);
	*/

	option = purple_account_option_bool_new(_("Use SSL"), "ssl", FALSE);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

#ifdef HAVE_CYRUS_SASL
	option = purple_account_option_bool_new(_("Authenticate with SASL"), "sasl", FALSE);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	option = purple_account_option_bool_new(
						_("Allow plaintext SASL auth over unencrypted connection"),
						"auth_plain_in_clear", FALSE);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);
#endif

	_irc_plugin = plugin;

	purple_prefs_remove("/plugins/prpl/irc/quitmsg");
	purple_prefs_remove("/plugins/prpl/irc");

	irc_register_commands();
}

PURPLE_INIT_PLUGIN(irc, _init_plugin, info);
