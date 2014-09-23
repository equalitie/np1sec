/**
 * @file msgs.c
 *
 * purple
 *
 * Copyright (C) 2003, 2012 Ethan Blanton <elb@pidgin.im>
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

/*
 * Note: If you change any of these functions to use additional args you
 * MUST ensure the arg count is correct in parse.c. Otherwise it may be
 * possible for a malicious server or man-in-the-middle to trigger a crash.
 */

#include "internal.h"

#include "conversation.h"
#include "blist.h"
#include "notify.h"
#include "util.h"
#include "debug.h"
#include "irc.h"

#include <stdio.h>
#include <stdlib.h>

#ifdef HAVE_CYRUS_SASL
#include <sasl/sasl.h>
#endif

static char *irc_mask_nick(const char *mask);
static char *irc_mask_userhost(const char *mask);
static void irc_chat_remove_buddy(PurpleConversation *convo, char *data[2]);
static void irc_buddy_status(char *name, struct irc_buddy *ib, struct irc_conn *irc);
static void irc_connected(struct irc_conn *irc, const char *nick);

static void irc_msg_handle_privmsg(struct irc_conn *irc, const char *name,
                                   const char *from, const char *to,
                                   const char *rawmsg, gboolean notice);

#ifdef HAVE_CYRUS_SASL
static void irc_sasl_finish(struct irc_conn *irc);
#endif

static char *irc_mask_nick(const char *mask)
{
	char *end, *buf;

	end = strchr(mask, '!');
	if (!end)
		buf = g_strdup(mask);
	else
		buf = g_strndup(mask, end - mask);

	return buf;
}

static char *irc_mask_userhost(const char *mask)
{
	return g_strdup(strchr(mask, '!') + 1);
}

static void irc_chat_remove_buddy(PurpleConversation *convo, char *data[2])
{
	char *message, *stripped;

	stripped = data[1] ? irc_mirc2txt(data[1]) : NULL;
	message = g_strdup_printf("quit: %s", stripped);
	g_free(stripped);

	if (purple_conv_chat_find_user(PURPLE_CONV_CHAT(convo), data[0]))
		purple_conv_chat_remove_user(PURPLE_CONV_CHAT(convo), data[0], message);

	g_free(message);
}

static void irc_connected(struct irc_conn *irc, const char *nick)
{
	PurpleConnection *gc;
	PurpleStatus *status;
	GSList *buddies;
	PurpleAccount *account;

	if ((gc = purple_account_get_connection(irc->account)) == NULL
	    || PURPLE_CONNECTION_IS_CONNECTED(gc))
		return;

	purple_connection_set_display_name(gc, nick);
	purple_connection_set_state(gc, PURPLE_CONNECTED);
	account = purple_connection_get_account(gc);

	/* If we're away then set our away message */
	status = purple_account_get_active_status(irc->account);
	if (purple_status_get_type(status) != PURPLE_STATUS_AVAILABLE) {
		PurplePluginProtocolInfo *prpl_info = PURPLE_PLUGIN_PROTOCOL_INFO(gc->prpl);
		prpl_info->set_status(irc->account, status);
	}

	/* this used to be in the core, but it's not now */
	for (buddies = purple_find_buddies(account, NULL); buddies;
			buddies = g_slist_delete_link(buddies, buddies))
	{
		PurpleBuddy *b = buddies->data;
		struct irc_buddy *ib = g_new0(struct irc_buddy, 1);
		ib->name = g_strdup(purple_buddy_get_name(b));
		ib->ref = 1;
		g_hash_table_replace(irc->buddies, ib->name, ib);
	}

	irc_blist_timeout(irc);
	if (!irc->timer)
		irc->timer = purple_timeout_add_seconds(45, (GSourceFunc)irc_blist_timeout, (gpointer)irc);
}

/* This function is ugly, but it's really an error handler. */
void irc_msg_default(struct irc_conn *irc, const char *name, const char *from, char **args)
{
	int i;
	const char *end, *cur, *numeric = NULL;
	char *clean, *tmp, *convname;
	PurpleConversation *convo;

	for (cur = args[0], i = 0; i < 4; i++) {
		end = strchr(cur, ' ');
		if (end == NULL) {
			goto undirected;
		}
		/* Check for 3-digit numeric in second position */
		if (i == 1) {
			if (end - cur != 3
			    || !isdigit(cur[0]) || !isdigit(cur[1])
			    || !isdigit(cur[2])) {
				goto undirected;
			}
			/* Save the numeric for printing to the channel */
			numeric = cur;
		}
		/* Don't advance cur if we're on the final iteration. */
		if (i != 3) {
			cur = end + 1;
		}
	}

	/* At this point, cur is the beginning of the fourth position,
	 * end is the following space, and there are remaining
	 * arguments.  We'll check to see if this argument is a
	 * currently active conversation (private message or channel,
	 * either one), and print the numeric to that conversation if it
	 * is. */

	tmp = g_strndup(cur, end - cur);
	convname = purple_utf8_salvage(tmp);
	g_free(tmp);

	/* Check for an existing conversation */
	convo = purple_find_conversation_with_account(PURPLE_CONV_TYPE_ANY,
						      convname,
						      irc->account);
	g_free(convname);

	if (convo == NULL) {
		goto undirected;
	}

	/* end + 1 is the first argument past the target.  The initial
	 * arguments we've skipped are routing info, numeric, recipient
	 * (this account's nick, most likely), and target (this
	 * channel).  If end + 1 is an ASCII :, skip it, because it's
	 * meaningless in this context.  This won't catch all
	 * :-arguments, but it'll catch the easy case. */
	if (*++end == ':') {
		end++;
	}

	/* We then print "numeric: remainder". */
	clean = purple_utf8_salvage(end);
	tmp = g_strdup_printf("%.3s: %s", numeric, clean);
	g_free(clean);
	purple_conversation_write(convo, "", tmp,
				  PURPLE_MESSAGE_SYSTEM|PURPLE_MESSAGE_NO_LOG
				  |PURPLE_MESSAGE_RAW|PURPLE_MESSAGE_NO_LINKIFY,
				  time(NULL));
	g_free(tmp);
	return;

  undirected:
	/* This, too, should be escaped somehow (smarter) */
	clean = purple_utf8_salvage(args[0]);
	purple_debug(PURPLE_DEBUG_INFO, "irc", "Unrecognized message: %s\n", clean);
	g_free(clean);
}

void irc_msg_features(struct irc_conn *irc, const char *name, const char *from, char **args)
{
	gchar **features;
	int i;

	features = g_strsplit(args[1], " ", -1);
	for (i = 0; features[i]; i++) {
		char *val;
		if (!strncmp(features[i], "PREFIX=", 7)) {
			if ((val = strchr(features[i] + 7, ')')) != NULL)
				irc->mode_chars = g_strdup(val + 1);
		}
	}

	g_strfreev(features);
}

void irc_msg_luser(struct irc_conn *irc, const char *name, const char *from, char **args)
{
	if (!strcmp(name, "251")) {
		/* 251 is required, so we pluck our nick from here and
		 * finalize connection */
		irc_connected(irc, args[0]);
		/* Some IRC servers seem to not send a 255 numeric, so
		 * I guess we can't require it; 251 will do. */
	/* } else if (!strcmp(name, "255")) { */
	}
}

void irc_msg_away(struct irc_conn *irc, const char *name, const char *from, char **args)
{
	PurpleConnection *gc;
	char *msg;

	if (irc->whois.nick && !purple_utf8_strcasecmp(irc->whois.nick, args[1])) {
		/* We're doing a whois, show this in the whois dialog */
		irc_msg_whois(irc, name, from, args);
		return;
	}

	gc = purple_account_get_connection(irc->account);
	if (gc) {
		msg = g_markup_escape_text(args[2], -1);
		serv_got_im(gc, args[1], msg, PURPLE_MESSAGE_AUTO_RESP, time(NULL));
		g_free(msg);
	}
}

void irc_msg_badmode(struct irc_conn *irc, const char *name, const char *from, char **args)
{
	PurpleConnection *gc = purple_account_get_connection(irc->account);

	g_return_if_fail(gc);

	purple_notify_error(gc, NULL, _("Bad mode"), args[1]);
}

void irc_msg_ban(struct irc_conn *irc, const char *name, const char *from, char **args)
{
	PurpleConversation *convo;

	convo = purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT,
						      args[1], irc->account);

	if (!strcmp(name, "367")) {
		char *msg = NULL;
		/* Ban list entry */
		if (args[3] && args[4]) {
			/* This is an extended syntax, not in RFC 1459 */
			int t1 = atoi(args[4]);
			time_t t2 = time(NULL);
			char *time = purple_str_seconds_to_string(t2 - t1);
			msg = g_strdup_printf(_("Ban on %s by %s, set %s ago"),
			                      args[2], args[3], time);
			g_free(time);
		} else {
			msg = g_strdup_printf(_("Ban on %s"), args[2]);
		}
		if (convo) {
			purple_conv_chat_write(PURPLE_CONV_CHAT(convo), "", msg,
			                       PURPLE_MESSAGE_SYSTEM|PURPLE_MESSAGE_NO_LOG,
			                       time(NULL));
		} else {
			purple_debug_info("irc", "%s\n", msg);
		}
		g_free(msg);
	} else if (!strcmp(name, "368")) {
		if (!convo)
			return;
		/* End of ban list */
		purple_conv_chat_write(PURPLE_CONV_CHAT(convo), "",
		                       _("End of ban list"),
		                       PURPLE_MESSAGE_SYSTEM|PURPLE_MESSAGE_NO_LOG,
		                       time(NULL));
	}
}

void irc_msg_banned(struct irc_conn *irc, const char *name, const char *from, char **args)
{
	PurpleConnection *gc = purple_account_get_connection(irc->account);
	char *buf;

	g_return_if_fail(gc);

	buf = g_strdup_printf(_("You are banned from %s."), args[1]);
	purple_notify_error(gc, _("Banned"), _("Banned"), buf);
	g_free(buf);
}

void irc_msg_banfull(struct irc_conn *irc, const char *name, const char *from, char **args)
{
	PurpleConversation *convo;
	char *buf, *nick;

	convo = purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT, args[1], irc->account);
	if (!convo)
		return;

	nick = g_markup_escape_text(args[2], -1);
	buf = g_strdup_printf(_("Cannot ban %s: banlist is full"), nick);
	g_free(nick);
	purple_conv_chat_write(PURPLE_CONV_CHAT(convo), "", buf,
			     PURPLE_MESSAGE_SYSTEM|PURPLE_MESSAGE_NO_LOG,
			     time(NULL));
	g_free(buf);
}

void irc_msg_chanmode(struct irc_conn *irc, const char *name, const char *from, char **args)
{
	PurpleConversation *convo;
	char *buf, *escaped;

	convo = purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT, args[1], irc->account);
	if (!convo)	/* XXX punt on channels we are not in for now */
		return;

	escaped = (args[3] != NULL) ? g_markup_escape_text(args[3], -1) : NULL;
	buf = g_strdup_printf("mode for %s: %s %s", args[1], args[2], escaped ? escaped : "");
	purple_conv_chat_write(PURPLE_CONV_CHAT(convo), "", buf, PURPLE_MESSAGE_SYSTEM, time(NULL));
	g_free(escaped);
	g_free(buf);

	return;
}

void irc_msg_whois(struct irc_conn *irc, const char *name, const char *from, char **args)
{
	if (!irc->whois.nick) {
		purple_debug(PURPLE_DEBUG_WARNING, "irc", "Unexpected %s reply for %s\n", !strcmp(name, "314") ? "WHOWAS" : "WHOIS"
											   , args[1]);
		return;
	}

	if (purple_utf8_strcasecmp(irc->whois.nick, args[1])) {
		purple_debug(PURPLE_DEBUG_WARNING, "irc", "Got %s reply for %s while waiting for %s\n", !strcmp(name, "314") ? "WHOWAS" : "WHOIS"
												      , args[1], irc->whois.nick);
		return;
	}

	if (!strcmp(name, "301")) {
		irc->whois.away = g_strdup(args[2]);
	} else if (!strcmp(name, "311") || !strcmp(name, "314")) {
		irc->whois.ident = g_strdup(args[2]);
		irc->whois.host = g_strdup(args[3]);
		irc->whois.real = g_strdup(args[5]);
	} else if (!strcmp(name, "312")) {
		irc->whois.server = g_strdup(args[2]);
		irc->whois.serverinfo = g_strdup(args[3]);
	} else if (!strcmp(name, "313")) {
		irc->whois.ircop = 1;
	} else if (!strcmp(name, "317")) {
		irc->whois.idle = atoi(args[2]);
		if (args[3])
			irc->whois.signon = (time_t)atoi(args[3]);
	} else if (!strcmp(name, "319")) {
		if (irc->whois.channels == NULL) {
			irc->whois.channels = g_string_new(args[2]);
		} else {
			irc->whois.channels = g_string_append(irc->whois.channels, args[2]);
		}
	} else if (!strcmp(name, "320")) {
		irc->whois.identified = 1;
	} else if (!strcmp(name, "330")) {
		purple_debug(PURPLE_DEBUG_INFO, "irc", "330 %s: 1=[%s] 2=[%s] 3=[%s]",
				name, args[1], args[2], args[3]);
		if (!strcmp(args[3], "is logged in as"))
			irc->whois.login = g_strdup(args[2]);
	}
}

void irc_msg_endwhois(struct irc_conn *irc, const char *name, const char *from, char **args)
{
	PurpleConnection *gc;
	char *tmp, *tmp2;
	PurpleNotifyUserInfo *user_info;

	if (!irc->whois.nick) {
		purple_debug(PURPLE_DEBUG_WARNING, "irc", "Unexpected End of %s for %s\n", !strcmp(name, "369") ? "WHOWAS" : "WHOIS"
											     , args[1]);
		return;
	}
	if (purple_utf8_strcasecmp(irc->whois.nick, args[1])) {
		purple_debug(PURPLE_DEBUG_WARNING, "irc", "Received end of %s for %s, expecting %s\n", !strcmp(name, "369") ? "WHOWAS" : "WHOIS"
													 , args[1], irc->whois.nick);
		return;
	}

	user_info = purple_notify_user_info_new();

	tmp2 = g_markup_escape_text(args[1], -1);
	tmp = g_strdup_printf("%s%s%s", tmp2,
				(irc->whois.ircop ? _(" <i>(ircop)</i>") : ""),
				(irc->whois.identified ? _(" <i>(identified)</i>") : ""));
	purple_notify_user_info_add_pair(user_info, _("Nick"), tmp);
	g_free(tmp2);
	g_free(tmp);

	if (irc->whois.away) {
		tmp = g_markup_escape_text(irc->whois.away, strlen(irc->whois.away));
		g_free(irc->whois.away);
		purple_notify_user_info_add_pair(user_info, _("Away"), tmp);
		g_free(tmp);
	}
	if (irc->whois.real) {
		purple_notify_user_info_add_pair_plaintext(user_info, _("Real name"), irc->whois.real);
		g_free(irc->whois.real);
	}
	if (irc->whois.login) {
		purple_notify_user_info_add_pair_plaintext(user_info, _("Login name"), irc->whois.login);
		g_free(irc->whois.login);
	}
	if (irc->whois.ident) {
		purple_notify_user_info_add_pair_plaintext(user_info, _("Ident name"), irc->whois.ident);
		g_free(irc->whois.ident);
	}
	if (irc->whois.host) {
		purple_notify_user_info_add_pair_plaintext(user_info, _("Host name"), irc->whois.host);
		g_free(irc->whois.host);
	}
	if (irc->whois.server) {
		tmp = g_strdup_printf("%s (%s)", irc->whois.server, irc->whois.serverinfo);
		purple_notify_user_info_add_pair(user_info, _("Server"), tmp);
		g_free(tmp);
		g_free(irc->whois.server);
		g_free(irc->whois.serverinfo);
	}
	if (irc->whois.channels) {
		purple_notify_user_info_add_pair(user_info, _("Currently on"), irc->whois.channels->str);
		g_string_free(irc->whois.channels, TRUE);
	}
	if (irc->whois.idle) {
		gchar *timex = purple_str_seconds_to_string(irc->whois.idle);
		purple_notify_user_info_add_pair(user_info, _("Idle for"), timex);
		g_free(timex);
		purple_notify_user_info_add_pair(user_info,
														_("Online since"), purple_date_format_full(localtime(&irc->whois.signon)));
	}
	if (!strcmp(irc->whois.nick, "Paco-Paco")) {
		purple_notify_user_info_add_pair(user_info,
																   _("<b>Defining adjective:</b>"), _("Glorious"));
	}

	gc = purple_account_get_connection(irc->account);

	purple_notify_userinfo(gc, irc->whois.nick, user_info, NULL, NULL);
	purple_notify_user_info_destroy(user_info);

	g_free(irc->whois.nick);
	memset(&irc->whois, 0, sizeof(irc->whois));
}

void irc_msg_who(struct irc_conn *irc, const char *name, const char *from, char **args)
{
	if (!strcmp(name, "352")) {
		PurpleConversation *conv;
		PurpleConvChat *chat;
		PurpleConvChatBuddy *cb;
		
		char *cur, *userhost, *realname;
		
		PurpleConvChatBuddyFlags flags;
		GList *keys = NULL, *values = NULL;

		conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT, args[1], irc->account);
		if (!conv) {
			purple_debug(PURPLE_DEBUG_ERROR, "irc","Got a WHO response for %s, which doesn't exist\n", args[1]);
			return;
		}

		cb = purple_conv_chat_cb_find(PURPLE_CONV_CHAT(conv), args[5]);
		if (!cb) {
			purple_debug(PURPLE_DEBUG_ERROR, "irc", "Got a WHO response for %s who isn't a buddy.\n", args[5]);
			return;
		}

		chat = PURPLE_CONV_CHAT(conv);
		
		userhost = g_strdup_printf("%s@%s", args[2], args[3]);

		/* The final argument is a :-argument, but annoyingly
		 * contains two "words", the hop count and real name. */
		for (cur = args[7]; *cur; cur++) {
			if (*cur == ' ') {
				cur++;
				break;
			}
		}
		realname = g_strdup(cur);
		
		keys = g_list_prepend(keys, "userhost");
		values = g_list_prepend(values, userhost);
		
		keys = g_list_prepend(keys, "realname");
		values = g_list_prepend(values, realname);
		
		purple_conv_chat_cb_set_attributes(chat, cb, keys, values);
		
		g_list_free(keys);
		g_list_free(values);
		
		g_free(userhost);
		g_free(realname);
		
		flags = cb->flags;

		/* FIXME: I'm not sure this is really a good idea, now
		 * that we no longer do periodic WHO.  It seems to me
		 * like it's more likely to be confusing than not.
		 * Comments? */
		if (args[6][0] == 'G' && !(flags & PURPLE_CBFLAGS_AWAY)) {
			purple_conv_chat_user_set_flags(chat, cb->name, flags | PURPLE_CBFLAGS_AWAY);
		} else if(args[6][0] == 'H' && (flags & PURPLE_CBFLAGS_AWAY)) {
			purple_conv_chat_user_set_flags(chat, cb->name, flags & ~PURPLE_CBFLAGS_AWAY);
		}
	}
}

void irc_msg_list(struct irc_conn *irc, const char *name, const char *from, char **args)
{
	if (!irc->roomlist)
		return;

	if (!strcmp(name, "321")) {
		purple_roomlist_set_in_progress(irc->roomlist, TRUE);
		return;
	}

	if (!strcmp(name, "323")) {
		purple_roomlist_set_in_progress(irc->roomlist, FALSE);
		purple_roomlist_unref(irc->roomlist);
		irc->roomlist = NULL;
		return;
	}

	if (!strcmp(name, "322")) {
		PurpleRoomlistRoom *room;
		char *topic;

		if (!purple_roomlist_get_in_progress(irc->roomlist)) {
			purple_debug_warning("irc", "Buggy server didn't send RPL_LISTSTART.\n");
			purple_roomlist_set_in_progress(irc->roomlist, TRUE);
		}

		room = purple_roomlist_room_new(PURPLE_ROOMLIST_ROOMTYPE_ROOM, args[1], NULL);
		purple_roomlist_room_add_field(irc->roomlist, room, args[1]);
		purple_roomlist_room_add_field(irc->roomlist, room, GINT_TO_POINTER(strtol(args[2], NULL, 10)));
		topic = irc_mirc2txt(args[3]);
		purple_roomlist_room_add_field(irc->roomlist, room, topic);
		g_free(topic);
		purple_roomlist_room_add(irc->roomlist, room);
	}
}

void irc_msg_topic(struct irc_conn *irc, const char *name, const char *from, char **args)
{
	char *chan, *topic, *msg, *nick, *tmp, *tmp2;
	PurpleConversation *convo;

	if (!strcmp(name, "topic")) {
		chan = args[0];
		topic = irc_mirc2txt (args[1]);
	} else {
		chan = args[1];
		topic = irc_mirc2txt (args[2]);
	}

	convo = purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT, chan, irc->account);
	if (!convo) {
		purple_debug(PURPLE_DEBUG_ERROR, "irc", "Got a topic for %s, which doesn't exist\n", chan);
		g_free(topic);
		return;
	}

	/* If this is an interactive update, print it out */
	tmp = g_markup_escape_text(topic, -1);
	tmp2 = purple_markup_linkify(tmp);
	g_free(tmp);
	if (!strcmp(name, "topic")) {
		const char *current_topic = purple_conv_chat_get_topic(PURPLE_CONV_CHAT(convo));
		if (!(current_topic != NULL && strcmp(tmp2, current_topic) == 0))
		{
			char *nick_esc;
			nick = irc_mask_nick(from);
			nick_esc = g_markup_escape_text(nick, -1);
			purple_conv_chat_set_topic(PURPLE_CONV_CHAT(convo), nick, topic);
			if (*tmp2)
				msg = g_strdup_printf(_("%s has changed the topic to: %s"), nick_esc, tmp2);
			else
				msg = g_strdup_printf(_("%s has cleared the topic."), nick_esc);
			g_free(nick_esc);
			g_free(nick);
			purple_conv_chat_write(PURPLE_CONV_CHAT(convo), from, msg, PURPLE_MESSAGE_SYSTEM, time(NULL));
			g_free(msg);
		}
	} else {
		char *chan_esc = g_markup_escape_text(chan, -1);
		msg = g_strdup_printf(_("The topic for %s is: %s"), chan_esc, tmp2);
		g_free(chan_esc);
		purple_conv_chat_set_topic(PURPLE_CONV_CHAT(convo), NULL, topic);
		purple_conv_chat_write(PURPLE_CONV_CHAT(convo), "", msg, PURPLE_MESSAGE_SYSTEM, time(NULL));
		g_free(msg);
	}
	g_free(tmp2);
	g_free(topic);
}

void irc_msg_topicinfo(struct irc_conn *irc, const char *name, const char *from, char **args)
{
	PurpleConversation *convo;
	struct tm *tm;
	time_t t;
	char *msg, *timestamp, *datestamp;

	convo = purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT, args[1], irc->account);
	if (!convo) {
		purple_debug(PURPLE_DEBUG_ERROR, "irc", "Got topic info for %s, which doesn't exist\n", args[1]);
		return;
	}

	t = (time_t)atol(args[3]);
	if (t == 0) {
		purple_debug(PURPLE_DEBUG_ERROR, "irc", "Got apparently nonsensical topic timestamp %s\n", args[3]);
		return;
	}
	tm = localtime(&t);

	timestamp = g_strdup(purple_time_format(tm));
	datestamp = g_strdup(purple_date_format_short(tm));
	msg = g_strdup_printf(_("Topic for %s set by %s at %s on %s"), args[1], args[2], timestamp, datestamp);
	purple_conv_chat_write(PURPLE_CONV_CHAT(convo), "", msg, PURPLE_MESSAGE_SYSTEM | PURPLE_MESSAGE_NO_LINKIFY, time(NULL));
	g_free(timestamp);
	g_free(datestamp);
	g_free(msg);
}

void irc_msg_unknown(struct irc_conn *irc, const char *name, const char *from, char **args)
{
	PurpleConnection *gc = purple_account_get_connection(irc->account);
	char *buf;

	g_return_if_fail(gc);

	buf = g_strdup_printf(_("Unknown message '%s'"), args[1]);
	purple_notify_error(gc, _("Unknown message"), buf, _("The IRC server received a message it did not understand."));
	g_free(buf);
}

void irc_msg_names(struct irc_conn *irc, const char *name, const char *from, char **args)
{
	char *names, *cur, *end, *tmp, *msg;
	PurpleConversation *convo;

	if (!strcmp(name, "366")) {
		convo = purple_find_conversation_with_account(PURPLE_CONV_TYPE_ANY, args[1], irc->account);
		if (!convo) {
			purple_debug(PURPLE_DEBUG_ERROR, "irc", "Got a NAMES list for %s, which doesn't exist\n", args[1]);
			g_string_free(irc->names, TRUE);
			irc->names = NULL;
			return;
		}

		names = cur = g_string_free(irc->names, FALSE);
		irc->names = NULL;
		if (purple_conversation_get_data(convo, IRC_NAMES_FLAG)) {
			msg = g_strdup_printf(_("Users on %s: %s"), args[1], names ? names : "");
			if (purple_conversation_get_type(convo) == PURPLE_CONV_TYPE_CHAT)
				purple_conv_chat_write(PURPLE_CONV_CHAT(convo), "", msg, PURPLE_MESSAGE_SYSTEM|PURPLE_MESSAGE_NO_LOG, time(NULL));
			else
				purple_conv_im_write(PURPLE_CONV_IM(convo), "", msg, PURPLE_MESSAGE_SYSTEM|PURPLE_MESSAGE_NO_LOG, time(NULL));
			g_free(msg);
		} else if (cur != NULL) {
			GList *users = NULL;
			GList *flags = NULL;

			while (*cur) {
				PurpleConvChatBuddyFlags f = PURPLE_CBFLAGS_NONE;
				end = strchr(cur, ' ');
				if (!end)
					end = cur + strlen(cur);
				if (*cur == '@') {
					f = PURPLE_CBFLAGS_OP;
					cur++;
				} else if (*cur == '%') {
					f = PURPLE_CBFLAGS_HALFOP;
					cur++;
				} else if(*cur == '+') {
					f = PURPLE_CBFLAGS_VOICE;
					cur++;
				} else if(irc->mode_chars
					  && strchr(irc->mode_chars, *cur)) {
					if (*cur == '~')
						f = PURPLE_CBFLAGS_FOUNDER;
					cur++;
				}
				tmp = g_strndup(cur, end - cur);
				users = g_list_prepend(users, tmp);
				flags = g_list_prepend(flags, GINT_TO_POINTER(f));
				cur = end;
				if (*cur)
					cur++;
			}

			if (users != NULL) {
				GList *l;

				purple_conv_chat_add_users(PURPLE_CONV_CHAT(convo), users, NULL, flags, FALSE);

				for (l = users; l != NULL; l = l->next)
					g_free(l->data);

				g_list_free(users);
				g_list_free(flags);
			}

			purple_conversation_set_data(convo, IRC_NAMES_FLAG,
						   GINT_TO_POINTER(TRUE));
		}
		g_free(names);
	} else {
		if (!irc->names)
			irc->names = g_string_new("");

		if (irc->names->len && irc->names->str[irc->names->len - 1] != ' ')
			irc->names = g_string_append_c(irc->names, ' ');
		irc->names = g_string_append(irc->names, args[3]);
	}
}

void irc_msg_motd(struct irc_conn *irc, const char *name, const char *from, char **args)
{
	char *escaped;

	if (!strcmp(name, "375")) {
		if (irc->motd)
			g_string_free(irc->motd, TRUE);
		irc->motd = g_string_new("");
		return;
	} else if (!strcmp(name, "376")) {
		/* dircproxy 1.0.5 does not send 251 on reconnection, so
		 * finalize the connection here if it is not already done. */
		irc_connected(irc, args[0]);
		return;
	} else if (!strcmp(name, "422")) {
		/* in case there is no 251, and no MOTD set, finalize the connection.
		 * (and clear the motd for good measure). */

		if (irc->motd)
			g_string_free(irc->motd, TRUE);

		irc_connected(irc, args[0]);
		return;
	}

	if (!irc->motd) {
		purple_debug_error("irc", "IRC server sent MOTD without STARTMOTD\n");
		return;
	}

	if (!args[1])
		return;

	escaped = g_markup_escape_text(args[1], -1);
	g_string_append_printf(irc->motd, "%s<br>", escaped);
	g_free(escaped);
}

void irc_msg_time(struct irc_conn *irc, const char *name, const char *from, char **args)
{
	PurpleConnection *gc = purple_account_get_connection(irc->account);

	g_return_if_fail(gc);

	purple_notify_message(gc, PURPLE_NOTIFY_MSG_INFO, _("Time Response"),
			    _("The IRC server's local time is:"),
			    args[2], NULL, NULL);
}

void irc_msg_nochan(struct irc_conn *irc, const char *name, const char *from, char **args)
{
	PurpleConnection *gc = purple_account_get_connection(irc->account);

	g_return_if_fail(gc);

	purple_notify_error(gc, NULL, _("No such channel"), args[1]);
}

void irc_msg_nonick(struct irc_conn *irc, const char *name, const char *from, char **args)
{
	PurpleConnection *gc;
	PurpleConversation *convo;

	convo = purple_find_conversation_with_account(PURPLE_CONV_TYPE_ANY, args[1], irc->account);
	if (convo) {
		if (purple_conversation_get_type(convo) == PURPLE_CONV_TYPE_CHAT) /* does this happen? */
			purple_conv_chat_write(PURPLE_CONV_CHAT(convo), args[1], _("no such channel"),
					PURPLE_MESSAGE_SYSTEM|PURPLE_MESSAGE_NO_LOG, time(NULL));
		else
			purple_conv_im_write(PURPLE_CONV_IM(convo), args[1], _("User is not logged in"),
				      PURPLE_MESSAGE_SYSTEM|PURPLE_MESSAGE_NO_LOG, time(NULL));
	} else {
		if ((gc = purple_account_get_connection(irc->account)) == NULL)
			return;
		purple_notify_error(gc, NULL, _("No such nick or channel"), args[1]);
	}

	if (irc->whois.nick && !purple_utf8_strcasecmp(irc->whois.nick, args[1])) {
		g_free(irc->whois.nick);
		irc->whois.nick = NULL;
	}
}

void irc_msg_nosend(struct irc_conn *irc, const char *name, const char *from, char **args)
{
	PurpleConnection *gc;
	PurpleConversation *convo;

	convo = purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT, args[1], irc->account);
	if (convo) {
		purple_conv_chat_write(PURPLE_CONV_CHAT(convo), args[1], args[2], PURPLE_MESSAGE_SYSTEM|PURPLE_MESSAGE_NO_LOG, time(NULL));
	} else {
		if ((gc = purple_account_get_connection(irc->account)) == NULL)
			return;
		purple_notify_error(gc, NULL, _("Could not send"), args[2]);
	}
}

void irc_msg_notinchan(struct irc_conn *irc, const char *name, const char *from, char **args)
{
	PurpleConversation *convo = purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT, args[1], irc->account);

	purple_debug(PURPLE_DEBUG_INFO, "irc", "We're apparently not in %s, but tried to use it\n", args[1]);
	if (convo) {
		/*g_slist_remove(irc->gc->buddy_chats, convo);
		  purple_conversation_set_account(convo, NULL);*/
		purple_conv_chat_write(PURPLE_CONV_CHAT(convo), args[1], args[2], PURPLE_MESSAGE_SYSTEM|PURPLE_MESSAGE_NO_LOG, time(NULL));
	}
}

void irc_msg_notop(struct irc_conn *irc, const char *name, const char *from, char **args)
{
	PurpleConversation *convo;

	convo = purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT, args[1], irc->account);
	if (!convo)
		return;

	purple_conv_chat_write(PURPLE_CONV_CHAT(convo), "", args[2], PURPLE_MESSAGE_SYSTEM, time(NULL));
}

void irc_msg_invite(struct irc_conn *irc, const char *name, const char *from, char **args)
{
	PurpleConnection *gc = purple_account_get_connection(irc->account);
	GHashTable *components;
	gchar *nick;

	g_return_if_fail(gc);

	components = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	nick = irc_mask_nick(from);

	g_hash_table_insert(components, g_strdup("channel"), g_strdup(args[1]));

	serv_got_chat_invite(gc, args[1], nick, NULL, components);
	g_free(nick);
}

void irc_msg_inviteonly(struct irc_conn *irc, const char *name, const char *from, char **args)
{
	PurpleConnection *gc = purple_account_get_connection(irc->account);
	char *buf;

	g_return_if_fail(gc);

	buf = g_strdup_printf(_("Joining %s requires an invitation."), args[1]);
	purple_notify_error(gc, _("Invitation only"), _("Invitation only"), buf);
	g_free(buf);
}

void irc_msg_ison(struct irc_conn *irc, const char *name, const char *from, char **args)
{
	char **nicks;
	struct irc_buddy *ib;
	int i;

	nicks = g_strsplit(args[1], " ", -1);
	for (i = 0; nicks[i]; i++) {
		if ((ib = g_hash_table_lookup(irc->buddies, (gconstpointer)nicks[i])) == NULL) {
			continue;
		}
		ib->new_online_status = TRUE;
	}
	g_strfreev(nicks);

	if (irc->ison_outstanding)
		irc_buddy_query(irc);

	if (!irc->ison_outstanding)
		g_hash_table_foreach(irc->buddies, (GHFunc)irc_buddy_status, (gpointer)irc);
}

static void irc_buddy_status(char *name, struct irc_buddy *ib, struct irc_conn *irc)
{
	PurpleConnection *gc = purple_account_get_connection(irc->account);
	PurpleBuddy *buddy = purple_find_buddy(irc->account, name);

	if (!gc || !buddy)
		return;

	if (ib->online && !ib->new_online_status) {
		purple_prpl_got_user_status(irc->account, name, "offline", NULL);
		ib->online = FALSE;
	} else if (!ib->online && ib->new_online_status) {
		purple_prpl_got_user_status(irc->account, name, "available", NULL);
		ib->online = TRUE;
	}
}

void irc_msg_join(struct irc_conn *irc, const char *name, const char *from, char **args)
{
	PurpleConnection *gc = purple_account_get_connection(irc->account);
	PurpleConversation *convo;
	PurpleConvChat *chat;
	PurpleConvChatBuddy *cb;

	char *nick, *userhost, *buf;
	struct irc_buddy *ib;
	static int id = 1;

	g_return_if_fail(gc);

	nick = irc_mask_nick(from);

	if (!purple_utf8_strcasecmp(nick, purple_connection_get_display_name(gc))) {
		/* We are joining a channel for the first time */
		serv_got_joined_chat(gc, id++, args[0]);
		g_free(nick);
		convo = purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT,
							    args[0],
							    irc->account);

		if (convo == NULL) {
			purple_debug_error("irc", "tried to join %s but couldn't\n", args[0]);
			return;
		}
		purple_conversation_set_data(convo, IRC_NAMES_FLAG,
					   GINT_TO_POINTER(FALSE));
		
		// Get the real name and user host for all participants.
		buf = irc_format(irc, "vc", "WHO", args[0]);
		irc_send(irc, buf);
		g_free(buf);
		
		/* Until purple_conversation_present does something that
		 * one would expect in Pidgin, this call produces buggy
		 * behavior both for the /join and auto-join cases. */
		/* purple_conversation_present(convo); */
		return;
	}

	convo = purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT, args[0], irc->account);
	if (convo == NULL) {
		purple_debug(PURPLE_DEBUG_ERROR, "irc", "JOIN for %s failed\n", args[0]);
		g_free(nick);
		return;
	}

	userhost = irc_mask_userhost(from);
	chat = PURPLE_CONV_CHAT(convo);
	
	purple_conv_chat_add_user(chat, nick, userhost, PURPLE_CBFLAGS_NONE, TRUE);
	
	cb = purple_conv_chat_cb_find(chat, nick);
	
	if (cb) {
		purple_conv_chat_cb_set_attribute(chat, cb, "userhost", userhost);		
	}
	
	if ((ib = g_hash_table_lookup(irc->buddies, nick)) != NULL) {
		ib->new_online_status = TRUE;
		irc_buddy_status(nick, ib, irc);
	}

	g_free(userhost);
	g_free(nick);
}

void irc_msg_kick(struct irc_conn *irc, const char *name, const char *from, char **args)
{
	PurpleConnection *gc = purple_account_get_connection(irc->account);
	PurpleConversation *convo = purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT, args[0], irc->account);
	char *nick, *buf;

	g_return_if_fail(gc);

	nick = irc_mask_nick(from);

	if (!convo) {
		purple_debug(PURPLE_DEBUG_ERROR, "irc", "Received a KICK for unknown channel %s\n", args[0]);
		g_free(nick);
		return;
	}

	if (!purple_utf8_strcasecmp(purple_connection_get_display_name(gc), args[1])) {
		buf = g_strdup_printf(_("You have been kicked by %s: (%s)"), nick, args[2]);
		purple_conv_chat_write(PURPLE_CONV_CHAT(convo), args[0], buf, PURPLE_MESSAGE_SYSTEM, time(NULL));
		g_free(buf);
		serv_got_chat_left(gc, purple_conv_chat_get_id(PURPLE_CONV_CHAT(convo)));
	} else {
		buf = g_strdup_printf(_("Kicked by %s (%s)"), nick, args[2]);
		purple_conv_chat_remove_user(PURPLE_CONV_CHAT(convo), args[1], buf);
		g_free(buf);
	}

	g_free(nick);
	return;
}

void irc_msg_mode(struct irc_conn *irc, const char *name, const char *from, char **args)
{
	PurpleConversation *convo;
	char *nick = irc_mask_nick(from), *buf;

	if (*args[0] == '#' || *args[0] == '&') {	/* Channel	*/
		char *escaped;
		convo = purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT, args[0], irc->account);
		if (!convo) {
			purple_debug(PURPLE_DEBUG_ERROR, "irc", "MODE received for %s, which we are not in\n", args[0]);
			g_free(nick);
			return;
		}
		escaped = (args[2] != NULL) ? g_markup_escape_text(args[2], -1) : NULL;
		buf = g_strdup_printf(_("mode (%s %s) by %s"), args[1], escaped ? escaped : "", nick);
		purple_conv_chat_write(PURPLE_CONV_CHAT(convo), args[0], buf, PURPLE_MESSAGE_SYSTEM, time(NULL));
		g_free(escaped);
		g_free(buf);
		if(args[2]) {
			PurpleConvChatBuddyFlags newflag, flags;
			char *mcur, *cur, *end, *user;
			gboolean add = FALSE;
			mcur = args[1];
			cur = args[2];
			while (*cur && *mcur) {
				if ((*mcur == '+') || (*mcur == '-')) {
					add = (*mcur == '+') ? TRUE : FALSE;
					mcur++;
					continue;
				}
				end = strchr(cur, ' ');
				if (!end)
					end = cur + strlen(cur);
				user = g_strndup(cur, end - cur);
				flags = purple_conv_chat_user_get_flags(PURPLE_CONV_CHAT(convo), user);
				newflag = PURPLE_CBFLAGS_NONE;
				if (*mcur == 'o')
					newflag = PURPLE_CBFLAGS_OP;
				else if (*mcur =='h')
					newflag = PURPLE_CBFLAGS_HALFOP;
				else if (*mcur == 'v')
					newflag = PURPLE_CBFLAGS_VOICE;
				else if(irc->mode_chars
					  && strchr(irc->mode_chars, '~') && (*mcur == 'q'))
					newflag = PURPLE_CBFLAGS_FOUNDER;
				if (newflag) {
					if (add)
						flags |= newflag;
					else
						flags &= ~newflag;
					purple_conv_chat_user_set_flags(PURPLE_CONV_CHAT(convo), user, flags);
				}
				g_free(user);
				cur = end;
				if (*cur)
					cur++;
				if (*mcur)
					mcur++;
			}
		}
	} else {					/* User		*/
	}
	g_free(nick);
}

void irc_msg_nick(struct irc_conn *irc, const char *name, const char *from, char **args)
{
	PurpleConnection *gc = purple_account_get_connection(irc->account);
	PurpleConversation *conv;
	GSList *chats;
	char *nick = irc_mask_nick(from);

	irc->nickused = FALSE;

	if (!gc) {
		g_free(nick);
		return;
	}
	chats = gc->buddy_chats;

	if (!purple_utf8_strcasecmp(nick, purple_connection_get_display_name(gc))) {
		purple_connection_set_display_name(gc, args[0]);
	}

	while (chats) {
		PurpleConvChat *chat = PURPLE_CONV_CHAT(chats->data);
		/* This is ugly ... */
		if (purple_conv_chat_find_user(chat, nick))
			purple_conv_chat_rename_user(chat, nick, args[0]);
		chats = chats->next;
	}

	conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, nick,
						   irc->account);
	if (conv != NULL)
		purple_conversation_set_name(conv, args[0]);

	g_free(nick);
}

void irc_msg_badnick(struct irc_conn *irc, const char *name, const char *from, char **args)
{
	PurpleConnection *gc = purple_account_get_connection(irc->account);
	if (purple_connection_get_state(gc) == PURPLE_CONNECTED) {
		purple_notify_error(gc, _("Invalid nickname"),
				  _("Invalid nickname"),
				  _("Your selected nickname was rejected by the server.  It probably contains invalid characters."));

	} else {
		purple_connection_error_reason (gc,
				  PURPLE_CONNECTION_ERROR_INVALID_SETTINGS,
				  _("Your selected account name was rejected by the server.  It probably contains invalid characters."));
	}
}

void irc_msg_nickused(struct irc_conn *irc, const char *name, const char *from, char **args)
{
	char *newnick, *buf, *end;
	PurpleConnection *gc = purple_account_get_connection(irc->account);

	if (gc && purple_connection_get_state(gc) == PURPLE_CONNECTED) {
		/* We only want to do the following dance if the connection
		   has not been successfully completed.  If it has, just
		   notify the user that their /nick command didn't go. */
		buf = g_strdup_printf(_("The nickname \"%s\" is already being used."),
				      irc->reqnick);
		purple_notify_error(gc, _("Nickname in use"),
				    _("Nickname in use"), buf);
		g_free(buf);
		g_free(irc->reqnick);
		irc->reqnick = NULL;
		return;
	}

	if (strlen(args[1]) < strlen(irc->reqnick) || irc->nickused)
		newnick = g_strdup(args[1]);
	else
		newnick = g_strdup_printf("%s0", args[1]);
	end = newnick + strlen(newnick) - 1;
	/* try fallbacks */
	if((*end < '9') && (*end >= '1')) {
			*end = *end + 1;
	} else *end = '1';

	g_free(irc->reqnick);
	irc->reqnick = newnick;
	irc->nickused = TRUE;

	purple_connection_set_display_name(
		purple_account_get_connection(irc->account), newnick);

	buf = irc_format(irc, "vn", "NICK", newnick);
	irc_send(irc, buf);
	g_free(buf);
}

void irc_msg_notice(struct irc_conn *irc, const char *name, const char *from, char **args)
{
	irc_msg_handle_privmsg(irc, name, from, args[0], args[1], TRUE);
}

void irc_msg_nochangenick(struct irc_conn *irc, const char *name, const char *from, char **args)
{
	PurpleConnection *gc = purple_account_get_connection(irc->account);

	g_return_if_fail(gc);

	purple_notify_error(gc, _("Cannot change nick"), _("Could not change nick"), args[2]);
}

void irc_msg_part(struct irc_conn *irc, const char *name, const char *from, char **args)
{
	PurpleConnection *gc = purple_account_get_connection(irc->account);
	PurpleConversation *convo;
	char *nick, *msg, *channel;

	g_return_if_fail(gc);

	/* Undernet likes to :-quote the channel name, for no good reason
	 * that I can see.  This catches that. */
	channel = (args[0][0] == ':') ? &args[0][1] : args[0];

	convo = purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT, channel, irc->account);
	if (!convo) {
		purple_debug(PURPLE_DEBUG_INFO, "irc", "Got a PART on %s, which doesn't exist -- probably closed\n", channel);
		return;
	}

	nick = irc_mask_nick(from);
	if (!purple_utf8_strcasecmp(nick, purple_connection_get_display_name(gc))) {
		char *escaped = args[1] ? g_markup_escape_text(args[1], -1) : NULL;
		msg = g_strdup_printf(_("You have parted the channel%s%s"),
		                      (args[1] && *args[1]) ? ": " : "",
		                      (escaped && *escaped) ? escaped : "");
		g_free(escaped);
		purple_conv_chat_write(PURPLE_CONV_CHAT(convo), channel, msg, PURPLE_MESSAGE_SYSTEM, time(NULL));
		g_free(msg);
		serv_got_chat_left(gc, purple_conv_chat_get_id(PURPLE_CONV_CHAT(convo)));
	} else {
		msg = args[1] ? irc_mirc2txt(args[1]) : NULL;
		purple_conv_chat_remove_user(PURPLE_CONV_CHAT(convo), nick, msg);
		g_free(msg);
	}
	g_free(nick);
}

void irc_msg_ping(struct irc_conn *irc, const char *name, const char *from, char **args)
{
	char *buf;

	buf = irc_format(irc, "v:", "PONG", args[0]);
	irc_send(irc, buf);
	g_free(buf);
}

void irc_msg_pong(struct irc_conn *irc, const char *name, const char *from, char **args)
{
	PurpleConversation *convo;
	PurpleConnection *gc;
	char **parts, *msg;
	time_t oldstamp;

	parts = g_strsplit(args[1], " ", 2);

	if (!parts[0] || !parts[1]) {
		g_strfreev(parts);
		return;
	}

	if (sscanf(parts[1], "%lu", &oldstamp) != 1) {
		msg = g_strdup(_("Error: invalid PONG from server"));
	} else {
		msg = g_strdup_printf(_("PING reply -- Lag: %lu seconds"), time(NULL) - oldstamp);
	}

	convo = purple_find_conversation_with_account(PURPLE_CONV_TYPE_ANY, parts[0], irc->account);
	g_strfreev(parts);
	if (convo) {
		if (purple_conversation_get_type (convo) == PURPLE_CONV_TYPE_CHAT)
			purple_conv_chat_write(PURPLE_CONV_CHAT(convo), "PONG", msg, PURPLE_MESSAGE_SYSTEM|PURPLE_MESSAGE_NO_LOG, time(NULL));
		else
			purple_conv_im_write(PURPLE_CONV_IM(convo), "PONG", msg, PURPLE_MESSAGE_SYSTEM|PURPLE_MESSAGE_NO_LOG, time(NULL));
	} else {
		gc = purple_account_get_connection(irc->account);
		if (!gc) {
			g_free(msg);
			return;
		}
		purple_notify_info(gc, NULL, "PONG", msg);
	}
	g_free(msg);
}

void irc_msg_privmsg(struct irc_conn *irc, const char *name, const char *from, char **args)
{
	irc_msg_handle_privmsg(irc, name, from, args[0], args[1], FALSE);
}

static void irc_msg_handle_privmsg(struct irc_conn *irc, const char *name, const char *from, const char *to, const char *rawmsg, gboolean notice)
{
	PurpleConnection *gc = purple_account_get_connection(irc->account);
	PurpleConversation *convo;
	char *tmp;
	char *msg;
	char *nick;

	if (!gc)
		return;

	nick = irc_mask_nick(from);
	tmp = irc_parse_ctcp(irc, nick, to, rawmsg, notice);
	if (!tmp) {
		g_free(nick);
		return;
	}

	msg = irc_escape_privmsg(tmp, -1);
	g_free(tmp);

	tmp = irc_mirc2html(msg);
	g_free(msg);
	msg = tmp;
	if (notice) {
		tmp = g_strdup_printf("(notice) %s", msg);
		g_free(msg);
		msg = tmp;
	}

	if (!purple_utf8_strcasecmp(to, purple_connection_get_display_name(gc))) {
		serv_got_im(gc, nick, msg, 0, time(NULL));
	} else {
		convo = purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT, irc_nick_skip_mode(irc, to), irc->account);
		if (convo)
			serv_got_chat_in(gc, purple_conv_chat_get_id(PURPLE_CONV_CHAT(convo)), nick, 0, msg, time(NULL));
		else
			purple_debug_error("irc", "Got a %s on %s, which does not exist\n",
			                   notice ? "NOTICE" : "PRIVMSG", to);
	}
	g_free(msg);
	g_free(nick);
}

void irc_msg_regonly(struct irc_conn *irc, const char *name, const char *from, char **args)
{
	PurpleConnection *gc = purple_account_get_connection(irc->account);
	PurpleConversation *convo;
	char *msg;

	g_return_if_fail(gc);

	convo = purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT, args[1], irc->account);
	if (convo) {
		/* This is a channel we're already in; for some reason,
		 * freenode feels the need to notify us that in some
		 * hypothetical other situation this might not have
		 * succeeded.  Suppress that. */
		return;
	}

	msg = g_strdup_printf(_("Cannot join %s: Registration is required."), args[1]);
	purple_notify_error(gc, _("Cannot join channel"), msg, args[2]);
	g_free(msg);
}

void irc_msg_quit(struct irc_conn *irc, const char *name, const char *from, char **args)
{
	PurpleConnection *gc = purple_account_get_connection(irc->account);
	struct irc_buddy *ib;
	char *data[2];

	g_return_if_fail(gc);

	data[0] = irc_mask_nick(from);
	data[1] = args[0];
	/* XXX this should have an API, I shouldn't grab this directly */
	g_slist_foreach(gc->buddy_chats, (GFunc)irc_chat_remove_buddy, data);

	if ((ib = g_hash_table_lookup(irc->buddies, data[0])) != NULL) {
		ib->new_online_status = FALSE;
		irc_buddy_status(data[0], ib, irc);
	}
	g_free(data[0]);

	return;
}

void irc_msg_unavailable(struct irc_conn *irc, const char *name, const char *from, char **args)
{
	PurpleConnection *gc = purple_account_get_connection(irc->account);

	purple_notify_error(gc, NULL, _("Nick or channel is temporarily unavailable."), args[1]);
}

void irc_msg_wallops(struct irc_conn *irc, const char *name, const char *from, char **args)
{
	PurpleConnection *gc = purple_account_get_connection(irc->account);
	char *nick, *msg;

	g_return_if_fail(gc);

	nick = irc_mask_nick(from);
	msg = g_strdup_printf (_("Wallops from %s"), nick);
	g_free(nick);
	purple_notify_info(gc, NULL, msg, args[0]);
	g_free(msg);
}

#ifdef HAVE_CYRUS_SASL
static int
irc_sasl_cb_secret(sasl_conn_t *conn, void *ctx, int id, sasl_secret_t **secret)
{
	struct irc_conn *irc = ctx;
	sasl_secret_t *sasl_secret;
	const char *pw;
	size_t len;

	pw = purple_account_get_password(irc->account);

	if (!conn || !secret || id != SASL_CB_PASS)
		return SASL_BADPARAM;

	len = strlen(pw);
	/* Not an off-by-one because sasl_secret_t defines char data[1] */
	/* TODO: This can probably be moved to glib's allocator */
	sasl_secret = malloc(sizeof(sasl_secret_t) + len);
	if (!sasl_secret)
		return SASL_NOMEM;

	sasl_secret->len = len;
	strcpy((char*)sasl_secret->data, pw);

	*secret = sasl_secret;
	return SASL_OK;
}

static int
irc_sasl_cb_log(void *context, int level, const char *message)
{
	if(level <= SASL_LOG_TRACE)
		purple_debug_info("sasl", "%s\n", message);

	return SASL_OK;
}

static int
irc_sasl_cb_simple(void *ctx, int id, const char **res, unsigned *len)
{
	struct irc_conn *irc = ctx;
	PurpleConnection *gc = purple_account_get_connection(irc->account);

	switch(id) {
		case SASL_CB_AUTHNAME:
			*res = purple_connection_get_display_name(gc);
			break;
		case SASL_CB_USER:
			*res = "";
			break;
		default:
			return SASL_BADPARAM;
	}
	if (len) *len = strlen((char *)*res);
	return SASL_OK;
}

static void
irc_auth_start_cyrus(struct irc_conn *irc)
{
	int ret = 0;
	char *buf;
	sasl_security_properties_t secprops;
	PurpleAccount *account = irc->account;
	PurpleConnection *gc = purple_account_get_connection(account);

	gboolean plaintext;
	gboolean again = FALSE;

	/* Set up security properties and options */
	secprops.min_ssf = 0;
	secprops.security_flags = SASL_SEC_NOANONYMOUS;

	if (!irc->gsc) {
		secprops.max_ssf = -1;
		secprops.maxbufsize = 4096;
		plaintext = purple_account_get_bool(account, "auth_plain_in_clear", FALSE);
		if (!plaintext)
			secprops.security_flags |= SASL_SEC_NOPLAINTEXT;
	} else {
		secprops.max_ssf = 0;
		secprops.maxbufsize = 0;
		plaintext = TRUE;
	}

	secprops.property_names = 0;
	secprops.property_values = 0;

	do {
		gchar *tmp = NULL;
		again = FALSE;

		ret = sasl_client_new("irc", irc->server, NULL, NULL, irc->sasl_cb, 0, &irc->sasl_conn);

		if (ret != SASL_OK) {
			purple_debug_error("irc", "sasl_client_new failed: %d\n", ret);
			tmp = g_strdup_printf(_("Failed to initialize SASL authentication: %s"),
				sasl_errdetail(irc->sasl_conn));
			purple_connection_error_reason (gc,
				PURPLE_CONNECTION_ERROR_OTHER_ERROR, tmp);
			g_free(tmp);
			return;
		}

		sasl_setprop(irc->sasl_conn, SASL_AUTH_EXTERNAL, irc->account->username);
		sasl_setprop(irc->sasl_conn, SASL_SEC_PROPS, &secprops);

		ret = sasl_client_start(irc->sasl_conn, irc->sasl_mechs->str, NULL, NULL, NULL, &irc->current_mech);

		switch (ret) {
			case SASL_OK:
			case SASL_CONTINUE:
				irc->mech_works = FALSE;
				break;
			case SASL_NOMECH:
				purple_connection_error_reason (gc,
					PURPLE_CONNECTION_ERROR_AUTHENTICATION_IMPOSSIBLE,
					_("SASL authentication failed: No worthy authentication mechanisms found."));

				irc_sasl_finish(irc);
				return;
			case SASL_BADPARAM:
			case SASL_NOMEM:
				tmp = g_strdup_printf(_("SASL authentication failed: %s"), sasl_errdetail(irc->sasl_conn));
				purple_connection_error_reason (gc,
					PURPLE_CONNECTION_ERROR_OTHER_ERROR, tmp);
				g_free(tmp);

				irc_sasl_finish(irc);
				return;
			default:
				purple_debug_error("irc", "sasl_client_start failed: %s\n", sasl_errdetail(irc->sasl_conn));

				if (irc->current_mech && *irc->current_mech) {
					char *pos;
					if ((pos = strstr(irc->sasl_mechs->str, irc->current_mech))) {
						size_t index = pos - irc->sasl_mechs->str;
						g_string_erase(irc->sasl_mechs, index, strlen(irc->current_mech));

						/* Remove space which separated this mech from the next */
						if ((irc->sasl_mechs->str)[index] == ' ') {
							g_string_erase(irc->sasl_mechs, index, 1);
						}
					}

					again = TRUE;
				}
				irc_sasl_finish(irc);
		}
	} while (again);

	purple_debug_info("irc", "Using SASL: %s\n", irc->current_mech);

	buf = irc_format(irc, "vv", "AUTHENTICATE", irc->current_mech);
	irc_send(irc, buf);
	g_free(buf);
}

/* SASL authentication */
void
irc_msg_cap(struct irc_conn *irc, const char *name, const char *from, char **args)
{
	int ret = 0;
	int id = 0;
	PurpleConnection *gc = purple_account_get_connection(irc->account);
	const char *mech_list = NULL;

	if (strncmp(args[2], "sasl ", 6))
		return;
	if (strncmp(args[1], "ACK", 4)) {
		const char *tmp = _("SASL authentication failed: Server does not support SASL authentication.");
		purple_connection_error_reason (gc,
			PURPLE_CONNECTION_ERROR_AUTHENTICATION_IMPOSSIBLE, tmp);

		irc_sasl_finish(irc);
		return;
	}

	if ((ret = sasl_client_init(NULL)) != SASL_OK) {
		const char *tmp = _("SASL authentication failed: Initializing SASL failed.");
		purple_connection_error_reason (gc,
			PURPLE_CONNECTION_ERROR_OTHER_ERROR, tmp);
		return;
	}

	irc->sasl_cb = g_new0(sasl_callback_t, 5);

	irc->sasl_cb[id].id = SASL_CB_AUTHNAME;
	irc->sasl_cb[id].proc = irc_sasl_cb_simple;
	irc->sasl_cb[id].context = (void *)irc;
	id++;

	irc->sasl_cb[id].id = SASL_CB_USER;
	irc->sasl_cb[id].proc = irc_sasl_cb_simple;
	irc->sasl_cb[id].context = (void *)irc;
	id++;

	irc->sasl_cb[id].id = SASL_CB_PASS;
	irc->sasl_cb[id].proc = irc_sasl_cb_secret;
	irc->sasl_cb[id].context = (void *)irc;
	id++;

	irc->sasl_cb[id].id = SASL_CB_LOG;
	irc->sasl_cb[id].proc = irc_sasl_cb_log;
	irc->sasl_cb[id].context = (void *)irc;
	id++;

	irc->sasl_cb[id].id = SASL_CB_LIST_END;

	/* We need to do this to be able to list the mechanisms. */
	ret = sasl_client_new("irc", irc->server, NULL, NULL, irc->sasl_cb, 0, &irc->sasl_conn);

	sasl_listmech(irc->sasl_conn, NULL, "", " ", "", &mech_list, NULL, NULL);
	purple_debug_info("irc", "SASL: we have available: %s\n", mech_list);

	if (ret != SASL_OK) {
		gchar *tmp;

		purple_debug_error("irc", "sasl_client_new failed: %d\n", ret);
		tmp = g_strdup_printf(_("Failed to initialize SASL authentication: %s"),
			sasl_errdetail(irc->sasl_conn));
		purple_connection_error_reason (gc,
			PURPLE_CONNECTION_ERROR_OTHER_ERROR, tmp);
		g_free(tmp);

		return;
	}

	irc->sasl_mechs = g_string_new(mech_list);

	irc_auth_start_cyrus(irc);
}

void
irc_msg_auth(struct irc_conn *irc, char *arg)
{
	PurpleConnection *gc = purple_account_get_connection(irc->account);
	char *buf, *authinfo;
	char *serverin = NULL;
	unsigned serverinlen = 0;
	const gchar *c_out;
	unsigned int clen;
	int ret;

	irc->mech_works = TRUE;

	if (!arg)
		return;

	if (arg[0] != '+') {
		serverin = arg;
		serverinlen = strlen(serverin);
	}

	ret = sasl_client_step(irc->sasl_conn, serverin, serverinlen,
		NULL, &c_out, &clen);

	if (ret != SASL_OK && ret != SASL_CONTINUE) {

		gchar *tmp = g_strdup_printf(_("SASL authentication failed: %s"),
			sasl_errdetail(irc->sasl_conn));
		purple_connection_error_reason (gc,
			PURPLE_CONNECTION_ERROR_AUTHENTICATION_IMPOSSIBLE, tmp);
		g_free(tmp);

		irc_sasl_finish(irc);

		return;
	}

	if (clen > 0)
		authinfo = purple_base64_encode((const guchar*)c_out, clen);
	else
		authinfo = g_strdup("+");

	buf = irc_format(irc, "vv", "AUTHENTICATE", authinfo);
	irc_send(irc, buf);
	g_free(buf);
	g_free(authinfo);
}

void
irc_msg_authok(struct irc_conn *irc, const char *name, const char *from, char **args)
{
	char *buf;

	sasl_dispose(&irc->sasl_conn);
	irc->sasl_conn = NULL;
	purple_debug_info("irc", "Succesfully authenticated using SASL.\n");

	/* Finish auth session */
	buf = irc_format(irc, "vv", "CAP", "END");
	irc_send(irc, buf);
	g_free(buf);
}

void
irc_msg_authtryagain(struct irc_conn *irc, const char *name, const char *from, char **args)
{
	PurpleConnection *gc = purple_account_get_connection(irc->account);

	/* We already received at least one AUTHENTICATE reply from the
	 * server. This suggests it supports this mechanism, but the
	 * password was incorrect. It would be better to abort and inform
	 * the user than to try again with a different mechanism, so they
	 * aren't told the server supports no worthy mechanisms.
	 */
	if (irc->mech_works) {
		purple_connection_error_reason (gc,
			PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, _("Incorrect Password"));

		irc_sasl_finish(irc);

		return;
	}

	if (irc->current_mech) {
		char *pos;
		if ((pos = strstr(irc->sasl_mechs->str, irc->current_mech))) {
			size_t index = pos - irc->sasl_mechs->str;
			g_string_erase(irc->sasl_mechs, index, strlen(irc->current_mech));

			/* Remove space which separated this mech from the next */
			if ((irc->sasl_mechs->str)[index] == ' ') {
				g_string_erase(irc->sasl_mechs, index, 1);
			}
		}
	}
	if (*irc->sasl_mechs->str) {
		sasl_dispose(&irc->sasl_conn);

		purple_debug_info("irc", "Now trying with %s\n", irc->sasl_mechs->str);
		irc_auth_start_cyrus(irc);
	} else {
		purple_connection_error_reason (gc,
			PURPLE_CONNECTION_ERROR_AUTHENTICATION_IMPOSSIBLE,
			_("SASL authentication failed: No worthy mechanisms found"));

		irc_sasl_finish(irc);
	}
}

void
irc_msg_authfail(struct irc_conn *irc, const char *name, const char *from, char **args)
{
	PurpleConnection *gc = purple_account_get_connection(irc->account);

	/* Only show an error if we did not abort ourselves. */
	if (irc->sasl_conn) {
		purple_debug_info("irc", "SASL authentication failed: %s", sasl_errdetail(irc->sasl_conn));

		purple_connection_error_reason (gc,
			PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, _("Incorrect Password"));
	}

	irc_sasl_finish(irc);
}

static void
irc_sasl_finish(struct irc_conn *irc)
{
	char *buf;

	sasl_dispose(&irc->sasl_conn);
	irc->sasl_conn = NULL;

	g_free(irc->sasl_cb);
	irc->sasl_cb = NULL;

	/* Auth failed, abort */
	buf = irc_format(irc, "vv", "CAP", "END");
	irc_send(irc, buf);
	g_free(buf);
}
#endif

void irc_msg_ignore(struct irc_conn *irc, const char *name, const char *from, char **args)
{
	return;
}
