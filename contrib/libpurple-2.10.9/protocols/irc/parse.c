/**
 * @file parse.c
 *
 * purple
 *
 * Copyright (C) 2003, Ethan Blanton <eblanton@cs.purdue.edu>
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
#include "conversation.h"
#include "notify.h"
#include "debug.h"
#include "util.h"
#include "cmds.h"
#include "irc.h"

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

static char *irc_send_convert(struct irc_conn *irc, const char *string);
static char *irc_recv_convert(struct irc_conn *irc, const char *string);

static void irc_parse_error_cb(struct irc_conn *irc, char *input);

static char *irc_mirc_colors[16] = {
	"white", "black", "blue", "dark green", "red", "brown", "purple",
		"orange", "yellow", "green", "teal", "cyan", "light blue",
		"pink", "grey", "light grey" };

extern PurplePlugin *_irc_plugin;

/*typedef void (*IRCMsgCallback)(struct irc_conn *irc, char *from, char *name, char **args);*/
static struct _irc_msg {
	char *name;
	char *format;

	/** The required parameter count, based on values we use, not protocol
	 *  specification. */
	int req_cnt;

	void (*cb)(struct irc_conn *irc, const char *name, const char *from, char **args);
} _irc_msgs[] = {
	{ "005", "n*", 2, irc_msg_features },		/* Feature list			*/
	{ "251", "n:", 1, irc_msg_luser },		/* Client & Server count	*/
	{ "255", "n:", 1, irc_msg_luser },		/* Client & Server count Mk. II	*/
	{ "301", "nn:", 3, irc_msg_away },		/* User is away			*/
	{ "303", "n:", 2, irc_msg_ison },		/* ISON reply			*/
	{ "311", "nnvvv:", 6, irc_msg_whois },		/* Whois user			*/
	{ "312", "nnv:", 4, irc_msg_whois },		/* Whois server			*/
	{ "313", "nn:", 2, irc_msg_whois },		/* Whois ircop			*/
	{ "317", "nnvv", 3, irc_msg_whois },		/* Whois idle			*/
	{ "318", "nt:", 2, irc_msg_endwhois },		/* End of WHOIS			*/
	{ "319", "nn:", 3, irc_msg_whois },		/* Whois channels		*/
	{ "320", "nn:", 2, irc_msg_whois },		/* Whois (fn ident)		*/
	{ "330", "nnv:", 4, irc_msg_whois },		/* Whois (fn login)		*/
	{ "314", "nnnvv:", 6, irc_msg_whois },		/* Whowas user			*/
	{ "315", "nt:", 0, irc_msg_who },		/* end of WHO channel		*/
	{ "369", "nt:", 2, irc_msg_endwhois },		/* End of WHOWAS		*/
	{ "321", "*", 0, irc_msg_list },		/* Start of list		*/
	{ "322", "ncv:", 4, irc_msg_list },		/* List.			*/
	{ "323", ":", 0, irc_msg_list },		/* End of list.			*/
	{ "324", "ncv:", 3, irc_msg_chanmode },		/* Channel modes		*/
	{ "331", "nc:", 3, irc_msg_topic },		/* No channel topic		*/
	{ "332", "nc:", 3, irc_msg_topic },		/* Channel topic		*/
	{ "333", "ncvv", 4, irc_msg_topicinfo },	/* Topic setter stuff		*/
	{ "352", "ncvvvnv:", 8, irc_msg_who },		/* Channel WHO			*/
	{ "353", "nvc:", 4, irc_msg_names },		/* Names list			*/
	{ "366", "nc:", 2, irc_msg_names },		/* End of names			*/
	{ "367", "ncnnv", 3, irc_msg_ban },		/* Ban list			*/
	{ "368", "nc:", 2, irc_msg_ban },		/* End of ban list		*/
	{ "372", "n:", 1, irc_msg_motd },		/* MOTD				*/
	{ "375", "n:", 1, irc_msg_motd },		/* Start MOTD			*/
	{ "376", "n:", 1, irc_msg_motd },		/* End of MOTD			*/
	{ "391", "nv:", 3, irc_msg_time },		/* Time reply			*/
	{ "401", "nt:", 2, irc_msg_nonick },		/* No such nick/chan		*/
	{ "406", "nt:", 2, irc_msg_nonick },		/* No such nick for WHOWAS	*/
	{ "403", "nc:", 2, irc_msg_nochan },		/* No such channel		*/
	{ "404", "nt:", 3, irc_msg_nosend },		/* Cannot send to chan		*/
	{ "421", "nv:", 2, irc_msg_unknown },		/* Unknown command		*/
	{ "422", "n:", 1, irc_msg_motd },		/* MOTD file missing		*/
	{ "432", "vn:", 0, irc_msg_badnick },		/* Erroneous nickname		*/
	{ "433", "vn:", 2, irc_msg_nickused },		/* Nickname already in use	*/
	{ "437", "nc:", 2, irc_msg_unavailable },	/* Nick/channel is unavailable	*/
	{ "438", "nn:", 3, irc_msg_nochangenick },	/* Nick may not change		*/
	{ "442", "nc:", 3, irc_msg_notinchan },		/* Not in channel		*/
	{ "473", "nc:", 2, irc_msg_inviteonly },	/* Tried to join invite-only	*/
	{ "474", "nc:", 2, irc_msg_banned },		/* Banned from channel		*/
	{ "477", "nc:", 3, irc_msg_regonly },		/* Registration Required	*/
	{ "478", "nct:", 3, irc_msg_banfull },		/* Banlist is full		*/
	{ "482", "nc:", 3, irc_msg_notop },		/* Need to be op to do that	*/
	{ "501", "n:", 2, irc_msg_badmode },		/* Unknown mode flag		*/
	{ "506", "nc:", 3, irc_msg_nosend },		/* Must identify to send	*/
	{ "515", "nc:", 3, irc_msg_regonly },		/* Registration required	*/
#ifdef HAVE_CYRUS_SASL
	{ "903", "*", 0, irc_msg_authok},		/* SASL auth successful		*/
	{ "904", "*", 0, irc_msg_authtryagain },	/* SASL auth failed, can recover*/
	{ "905", "*", 0, irc_msg_authfail },		/* SASL auth failed		*/
	{ "906", "*", 0, irc_msg_authfail },		/* SASL auth failed		*/
	{ "907", "*", 0, irc_msg_authfail },		/* SASL auth failed		*/
	{ "cap", "vv:", 3, irc_msg_cap },		/* SASL capable			*/
#endif
	{ "invite", "n:", 2, irc_msg_invite },		/* Invited			*/
	{ "join", ":", 1, irc_msg_join },		/* Joined a channel		*/
	{ "kick", "cn:", 3, irc_msg_kick },		/* KICK				*/
	{ "mode", "tv:", 2, irc_msg_mode },		/* MODE for channel		*/
	{ "nick", ":", 1, irc_msg_nick },		/* Nick change			*/
	{ "notice", "t:", 2, irc_msg_notice },		/* NOTICE recv			*/
	{ "part", "c:", 1, irc_msg_part },		/* Parted a channel		*/
	{ "ping", ":", 1, irc_msg_ping },		/* Received PING from server	*/
	{ "pong", "v:", 2, irc_msg_pong },		/* Received PONG from server	*/
	{ "privmsg", "t:", 2, irc_msg_privmsg },	/* Received private message	*/
	{ "topic", "c:", 2, irc_msg_topic },		/* TOPIC command		*/
	{ "quit", ":", 1, irc_msg_quit },		/* QUIT notice			*/
	{ "wallops", ":", 1, irc_msg_wallops },		/* WALLOPS command		*/
	{ NULL, NULL, 0, NULL }
};

static struct _irc_user_cmd {
	char *name;
	char *format;
	IRCCmdCallback cb;
	char *help;
} _irc_cmds[] = {
	{ "action", ":", irc_cmd_ctcp_action, N_("action &lt;action to perform&gt;:  Perform an action.") },
	{ "authserv", ":", irc_cmd_service, N_("authserv: Send a command to authserv") },
	{ "away", ":", irc_cmd_away, N_("away [message]:  Set an away message, or use no message to return from being away.") },
	{ "ctcp", "t:", irc_cmd_ctcp, N_("ctcp <nick> <msg>: sends ctcp msg to nick.") },
	{ "chanserv", ":", irc_cmd_service, N_("chanserv: Send a command to chanserv") },
	{ "deop", ":", irc_cmd_op, N_("deop &lt;nick1&gt; [nick2] ...:  Remove channel operator status from someone. You must be a channel operator to do this.") },
	{ "devoice", ":", irc_cmd_op, N_("devoice &lt;nick1&gt; [nick2] ...:  Remove channel voice status from someone, preventing them from speaking if the channel is moderated (+m). You must be a channel operator to do this.") },
	{ "invite", ":", irc_cmd_invite, N_("invite &lt;nick&gt; [room]:  Invite someone to join you in the specified channel, or the current channel.") },
	{ "j", "cv", irc_cmd_join, N_("j &lt;room1&gt;[,room2][,...] [key1[,key2][,...]]:  Enter one or more channels, optionally providing a channel key for each if needed.") },
	{ "join", "cv", irc_cmd_join, N_("join &lt;room1&gt;[,room2][,...] [key1[,key2][,...]]:  Enter one or more channels, optionally providing a channel key for each if needed.") },
	{ "kick", "n:", irc_cmd_kick, N_("kick &lt;nick&gt; [message]:  Remove someone from a channel. You must be a channel operator to do this.") },
	{ "list", ":", irc_cmd_list, N_("list:  Display a list of chat rooms on the network. <i>Warning, some servers may disconnect you upon doing this.</i>") },
	{ "me", ":", irc_cmd_ctcp_action, N_("me &lt;action to perform&gt;:  Perform an action.") },
	{ "memoserv", ":", irc_cmd_service, N_("memoserv: Send a command to memoserv") },
	{ "mode", ":", irc_cmd_mode, N_("mode &lt;+|-&gt;&lt;A-Za-z&gt; &lt;nick|channel&gt;:  Set or unset a channel or user mode.") },
	{ "msg", "t:", irc_cmd_privmsg, N_("msg &lt;nick&gt; &lt;message&gt;:  Send a private message to a user (as opposed to a channel).") },
	{ "names", "c", irc_cmd_names, N_("names [channel]:  List the users currently in a channel.") },
	{ "nick", "n", irc_cmd_nick, N_("nick &lt;new nickname&gt;:  Change your nickname.") },
	{ "nickserv", ":", irc_cmd_service, N_("nickserv: Send a command to nickserv") },
	{ "notice", "t:", irc_cmd_privmsg, N_("notice &lt;target&lt;:  Send a notice to a user or channel.") },
	{ "op", ":", irc_cmd_op, N_("op &lt;nick1&gt; [nick2] ...:  Grant channel operator status to someone. You must be a channel operator to do this.") },
	{ "operwall", ":", irc_cmd_wallops, N_("operwall &lt;message&gt;:  If you don't know what this is, you probably can't use it.") },
	{ "operserv", ":", irc_cmd_service, N_("operserv: Send a command to operserv") },
	{ "part", "c:", irc_cmd_part, N_("part [room] [message]:  Leave the current channel, or a specified channel, with an optional message.") },
	{ "ping", "n", irc_cmd_ping, N_("ping [nick]:  Asks how much lag a user (or the server if no user specified) has.") },
	{ "query", "n:", irc_cmd_query, N_("query &lt;nick&gt; &lt;message&gt;:  Send a private message to a user (as opposed to a channel).") },
	{ "quit", ":", irc_cmd_quit, N_("quit [message]:  Disconnect from the server, with an optional message.") },
	{ "quote", "*", irc_cmd_quote, N_("quote [...]:  Send a raw command to the server.") },
	{ "remove", "n:", irc_cmd_remove, N_("remove &lt;nick&gt; [message]:  Remove someone from a room. You must be a channel operator to do this.") },
	{ "time", "", irc_cmd_time, N_("time: Displays the current local time at the IRC server.") },
	{ "topic", ":", irc_cmd_topic, N_("topic [new topic]:  View or change the channel topic.") },
	{ "umode", ":", irc_cmd_mode, N_("umode &lt;+|-&gt;&lt;A-Za-z&gt;:  Set or unset a user mode.") },
	{ "version", ":", irc_cmd_ctcp_version, N_("version [nick]: send CTCP VERSION request to a user") },
	{ "voice", ":", irc_cmd_op, N_("voice &lt;nick1&gt; [nick2] ...:  Grant channel voice status to someone. You must be a channel operator to do this.") },
	{ "wallops", ":", irc_cmd_wallops, N_("wallops &lt;message&gt;:  If you don't know what this is, you probably can't use it.") },
	{ "whois", "tt", irc_cmd_whois, N_("whois [server] &lt;nick&gt;:  Get information on a user.") },
	{ "whowas", "t", irc_cmd_whowas, N_("whowas &lt;nick&gt;: Get information on a user that has logged off.") },
	{ NULL, NULL, NULL, NULL }
};

static PurpleCmdRet irc_parse_purple_cmd(PurpleConversation *conv, const gchar *cmd,
                                        gchar **args, gchar **error, void *data)
{
	PurpleConnection *gc;
	struct irc_conn *irc;
	struct _irc_user_cmd *cmdent;

	gc = purple_conversation_get_gc(conv);
	if (!gc)
		return PURPLE_CMD_RET_FAILED;

	irc = gc->proto_data;

	if ((cmdent = g_hash_table_lookup(irc->cmds, cmd)) == NULL)
		return PURPLE_CMD_RET_FAILED;

	(cmdent->cb)(irc, cmd, purple_conversation_get_name(conv), (const char **)args);

	return PURPLE_CMD_RET_OK;
}

static void irc_register_command(struct _irc_user_cmd *c)
{
	PurpleCmdFlag f;
	char args[10];
	char *format;
	size_t i;

	f = PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_IM | PURPLE_CMD_FLAG_PRPL_ONLY
	    | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS;

	format = c->format;

	for (i = 0; (i < (sizeof(args) - 1)) && *format; i++, format++)
		switch (*format) {
		case 'v':
		case 'n':
		case 'c':
		case 't':
			args[i] = 'w';
			break;
		case ':':
		case '*':
			args[i] = 's';
			break;
		}

	args[i] = '\0';

	purple_cmd_register(c->name, args, PURPLE_CMD_P_PRPL, f, "prpl-irc",
	                  irc_parse_purple_cmd, _(c->help), NULL);
}

void irc_register_commands(void)
{
	struct _irc_user_cmd *c;

	for (c = _irc_cmds; c && c->name; c++)
		irc_register_command(c);
}

static char *irc_send_convert(struct irc_conn *irc, const char *string)
{
	char *utf8;
	GError *err = NULL;
	gchar **encodings;
	const gchar *enclist;

	enclist = purple_account_get_string(irc->account, "encoding", IRC_DEFAULT_CHARSET);
	encodings = g_strsplit(enclist, ",", 2);

	if (encodings[0] == NULL || !g_ascii_strcasecmp("UTF-8", encodings[0])) {
		g_strfreev(encodings);
		return NULL;
	}

	utf8 = g_convert(string, strlen(string), encodings[0], "UTF-8", NULL, NULL, &err);
	if (err) {
		purple_debug(PURPLE_DEBUG_ERROR, "irc", "Send conversion error: %s\n", err->message);
		purple_debug(PURPLE_DEBUG_ERROR, "irc", "Sending as UTF-8 instead of %s\n", encodings[0]);
		utf8 = g_strdup(string);
		g_error_free(err);
	}
	g_strfreev(encodings);

	return utf8;
}

static char *irc_recv_convert(struct irc_conn *irc, const char *string)
{
	char *utf8 = NULL;
	const gchar *charset, *enclist;
	gchar **encodings;
	gboolean autodetect;
	int i;

	autodetect = purple_account_get_bool(irc->account, "autodetect_utf8", IRC_DEFAULT_AUTODETECT);

	if (autodetect && g_utf8_validate(string, -1, NULL)) {
		return g_strdup(string);
	}

	enclist = purple_account_get_string(irc->account, "encoding", IRC_DEFAULT_CHARSET);
	encodings = g_strsplit(enclist, ",", -1);

	if (encodings[0] == NULL) {
		g_strfreev(encodings);
		return purple_utf8_salvage(string);
	}

	for (i = 0; encodings[i] != NULL; i++) {
		charset = encodings[i];
		while (*charset == ' ')
			charset++;

		if (!g_ascii_strcasecmp("UTF-8", charset)) {
			if (g_utf8_validate(string, -1, NULL))
				utf8 = g_strdup(string);
		} else {
			utf8 = g_convert(string, -1, "UTF-8", charset, NULL, NULL, NULL);
		}

		if (utf8) {
			g_strfreev(encodings);
			return utf8;
		}
	}
	g_strfreev(encodings);

	return purple_utf8_salvage(string);
}

/* This function is shamelessly stolen from glib--it is an old version of the
 * private function append_escaped_text, used by g_markup_escape_text, whose
 * behavior changed in glib 2.12. */
static void irc_append_escaped_text(GString *str, const char *text, gssize length)
{
	const char *p = text;
	const char *end = text + length;
	const char *next = NULL;

	while(p != end) {
		next = g_utf8_next_char(p);

		switch(*p) {
			case '&':
				g_string_append(str, "&amp;");
				break;
			case '<':
				g_string_append(str, "&lt;");
				break;
			case '>':
				g_string_append(str, "&gt;");
				break;
			case '\'':
				g_string_append(str, "&apos;");
				break;
			case '"':
				g_string_append(str, "&quot;");
				break;
			default:
				g_string_append_len(str, p, next - p);
				break;
		}

		p = next;
	}
}

/* This function is shamelessly stolen from glib--it is an old version of the
 * function g_markup_escape_text, whose behavior changed in glib 2.12. */
char *irc_escape_privmsg(const char *text, gssize length)
{
	GString *str;

	g_return_val_if_fail(text != NULL, NULL);

	if(length < 0)
		length = strlen(text);

	str = g_string_sized_new(length);

	irc_append_escaped_text(str, text, length);

	return g_string_free(str, FALSE);
}

/* XXX tag closings are not necessarily correctly nested here!  If we
 *     get a ^O or reach the end of the string and there are open
 *     tags, they are closed in a fixed order ... this means, for
 *     example, you might see <FONT COLOR="blue">some text <B>with
 *     various attributes</FONT></B> (notice that B and FONT overlap
 *     and are not cleanly nested).  This is imminently fixable but
 *     I am not fixing it right now.
 */
char *irc_mirc2html(const char *string)
{
	const char *cur, *end;
	char fg[3] = "\0\0", bg[3] = "\0\0";
	int fgnum, bgnum;
	int font = 0, bold = 0, underline = 0, italic = 0;
	GString *decoded;

	if (string == NULL)
		return NULL;

	decoded = g_string_sized_new(strlen(string));

	cur = string;
	do {
		end = strpbrk(cur, "\002\003\007\017\026\037");

		decoded = g_string_append_len(decoded, cur, end ? end - cur : strlen(cur));
		cur = end ? end : cur + strlen(cur);

		switch (*cur) {
		case '\002':
			cur++;
			if (!bold) {
				decoded = g_string_append(decoded, "<B>");
				bold = TRUE;
			} else {
				decoded = g_string_append(decoded, "</B>");
				bold = FALSE;
			}
			break;
		case '\003':
			cur++;
			fg[0] = fg[1] = bg[0] = bg[1] = '\0';
			if (isdigit(*cur))
				fg[0] = *cur++;
			if (isdigit(*cur))
				fg[1] = *cur++;
			if (*cur == ',') {
				cur++;
				if (isdigit(*cur))
					bg[0] = *cur++;
				if (isdigit(*cur))
					bg[1] = *cur++;
			}
			if (font) {
				decoded = g_string_append(decoded, "</FONT>");
				font = FALSE;
			}

			if (fg[0]) {
				fgnum = atoi(fg);
				if (fgnum < 0 || fgnum > 15)
					continue;
				font = TRUE;
				g_string_append_printf(decoded, "<FONT COLOR=\"%s\"", irc_mirc_colors[fgnum]);
				if (bg[0]) {
					bgnum = atoi(bg);
					if (bgnum >= 0 && bgnum < 16)
						g_string_append_printf(decoded, " BACK=\"%s\"", irc_mirc_colors[bgnum]);
				}
				decoded = g_string_append_c(decoded, '>');
			}
			break;
		case '\011':
			cur++;
			if (!italic) {
				decoded = g_string_append(decoded, "<I>");
				italic = TRUE;
			} else {
				decoded = g_string_append(decoded, "</I>");
				italic = FALSE;
			}
			break;
		case '\037':
			cur++;
			if (!underline) {
				decoded = g_string_append(decoded, "<U>");
				underline = TRUE;
			} else {
				decoded = g_string_append(decoded, "</U>");
				underline = FALSE;
			}
			break;
		case '\007':
		case '\026':
			cur++;
			break;
		case '\017':
			cur++;
			/* fallthrough */
		case '\000':
			if (bold)
				decoded = g_string_append(decoded, "</B>");
			if (italic)
				decoded = g_string_append(decoded, "</I>");
			if (underline)
				decoded = g_string_append(decoded, "</U>");
			if (font)
				decoded = g_string_append(decoded, "</FONT>");
			bold = italic = underline = font = FALSE;
			break;
		default:
			purple_debug(PURPLE_DEBUG_ERROR, "irc", "Unexpected mIRC formatting character %d\n", *cur);
		}
	} while (*cur);

	return g_string_free(decoded, FALSE);
}

char *irc_mirc2txt (const char *string)
{
	char *result;
	int i, j;

	if (string == NULL)
		return NULL;

	result = g_strdup (string);

	for (i = 0, j = 0; result[i]; i++) {
		switch (result[i]) {
		case '\002':
		case '\003':
			/* Foreground color */
			if (isdigit(result[i + 1]))
				i++;
			if (isdigit(result[i + 1]))
				i++;
			/* Optional comma and background color */
			if (result[i + 1] == ',') {
				i++;
				if (isdigit(result[i + 1]))
					i++;
				if (isdigit(result[i + 1]))
					i++;
			}
			/* Note that i still points to the last character
			 * of the color selection string. */
			continue;
		case '\007':
		case '\017':
		case '\026':
		case '\037':
			continue;
		default:
			result[j++] = result[i];
		}
	}
	result[j] = '\0';
	return result;
}

const char *irc_nick_skip_mode(struct irc_conn *irc, const char *nick)
{
	static const char *default_modes = "@+%&";
	const char *mode_chars;

	mode_chars = irc->mode_chars ? irc->mode_chars : default_modes;

	while (strchr(mode_chars, *nick) != NULL)
		nick++;

	return nick;
}

gboolean irc_ischannel(const char *string)
{
	return (string[0] == '#' || string[0] == '&');
}

char *irc_parse_ctcp(struct irc_conn *irc, const char *from, const char *to, const char *msg, int notice)
{
	PurpleConnection *gc;
	const char *cur = msg + 1;
	char *buf, *ctcp;
	time_t timestamp;

	/* Note that this is NOT correct w.r.t. multiple CTCPs in one
	 * message and low-level quoting ... but if you want that crap,
	 * use a real IRC client. */

	if (msg[0] != '\001' || msg[strlen(msg) - 1] != '\001')
		return g_strdup(msg);

	if (!strncmp(cur, "ACTION ", 7)) {
		cur += 7;
		buf = g_strdup_printf("/me %s", cur);
		buf[strlen(buf) - 1] = '\0';
		return buf;
	} else if (!strncmp(cur, "PING ", 5)) {
		if (notice) { /* reply */
			gc = purple_account_get_connection(irc->account);
			if (!gc)
				return NULL;
			/* TODO: Should this read in the timestamp as a double? */
			if (sscanf(cur, "PING %lu", &timestamp) == 1) {
				buf = g_strdup_printf(_("Reply time from %s: %lu seconds"), from, time(NULL) - timestamp);
				purple_notify_info(gc, _("PONG"), _("CTCP PING reply"), buf);
				g_free(buf);
			} else
				purple_debug(PURPLE_DEBUG_ERROR, "irc", "Unable to parse PING timestamp");
			return NULL;
		} else {
			buf = irc_format(irc, "vt:", "NOTICE", from, msg);
			irc_send(irc, buf);
			g_free(buf);
		}
	} else if (!strncmp(cur, "VERSION", 7) && !notice) {
		buf = irc_format(irc, "vt:", "NOTICE", from, "\001VERSION Purple IRC\001");
		irc_send(irc, buf);
		g_free(buf);
	} else if (!strncmp(cur, "DCC SEND ", 9)) {
		irc_dccsend_recv(irc, from, msg + 10);
		return NULL;
	}

	ctcp = g_strdup(msg + 1);
	ctcp[strlen(ctcp) - 1] = '\0';
	buf = g_strdup_printf("Received CTCP '%s' (to %s) from %s", ctcp, to, from);
	g_free(ctcp);
	return buf;
}

void irc_msg_table_build(struct irc_conn *irc)
{
	int i;

	if (!irc || !irc->msgs) {
		purple_debug(PURPLE_DEBUG_ERROR, "irc", "Attempt to build a message table on a bogus structure\n");
		return;
	}

	for (i = 0; _irc_msgs[i].name; i++) {
		g_hash_table_insert(irc->msgs, (gpointer)_irc_msgs[i].name, (gpointer)&_irc_msgs[i]);
	}
}

void irc_cmd_table_build(struct irc_conn *irc)
{
	int i;

	if (!irc || !irc->cmds) {
		purple_debug(PURPLE_DEBUG_ERROR, "irc", "Attempt to build a command table on a bogus structure\n");
		return;
	}

	for (i = 0; _irc_cmds[i].name ; i++) {
		g_hash_table_insert(irc->cmds, (gpointer)_irc_cmds[i].name, (gpointer)&_irc_cmds[i]);
	}
}

char *irc_format(struct irc_conn *irc, const char *format, ...)
{
	GString *string = g_string_new("");
	char *tok, *tmp;
	const char *cur;
	va_list ap;

	va_start(ap, format);
	for (cur = format; *cur; cur++) {
		if (cur != format)
			g_string_append_c(string, ' ');

		tok = va_arg(ap, char *);
		switch (*cur) {
		case 'v':
			g_string_append(string, tok);
			break;
		case ':':
			g_string_append_c(string, ':');
			/* no break! */
		case 't':
		case 'n':
		case 'c':
			tmp = irc_send_convert(irc, tok);
			g_string_append(string, tmp ? tmp : tok);
			g_free(tmp);
			break;
		default:
			purple_debug(PURPLE_DEBUG_ERROR, "irc", "Invalid format character '%c'\n", *cur);
			break;
		}
	}
	va_end(ap);
	g_string_append(string, "\r\n");
	return (g_string_free(string, FALSE));
}

void irc_parse_msg(struct irc_conn *irc, char *input)
{
	struct _irc_msg *msgent;
	char *cur, *end, *tmp, *from, *msgname, *fmt, **args, *msg;
	guint i;
	PurpleConnection *gc = purple_account_get_connection(irc->account);
	gboolean fmt_valid;
	int args_cnt;

	irc->recv_time = time(NULL);

	/*
	 * The data passed to irc-receiving-text is the raw protocol data.
	 * TODO: It should be passed as an array of bytes and a length
	 * instead of a null terminated string.
	 */
	purple_signal_emit(_irc_plugin, "irc-receiving-text", gc, &input);

	if (!strncmp(input, "PING ", 5)) {
		msg = irc_format(irc, "vv", "PONG", input + 5);
		irc_send(irc, msg);
		g_free(msg);
		return;
	} else if (!strncmp(input, "ERROR ", 6)) {
		if (g_utf8_validate(input, -1, NULL)) {
			char *tmp = g_strdup_printf("%s\n%s", _("Disconnected."), input);
			purple_connection_error_reason (gc,
				PURPLE_CONNECTION_ERROR_NETWORK_ERROR, tmp);
			g_free(tmp);
		} else
			purple_connection_error_reason (gc,
				PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
				_("Disconnected."));
		return;
#ifdef HAVE_CYRUS_SASL
	} else if (!strncmp(input, "AUTHENTICATE ", 13)) {
		irc_msg_auth(irc, input + 13);
		return;
#endif
	}

	if (input[0] != ':' || (cur = strchr(input, ' ')) == NULL) {
		irc_parse_error_cb(irc, input);
		return;
	}

	from = g_strndup(&input[1], cur - &input[1]);
	cur++;
	end = strchr(cur, ' ');
	if (!end)
		end = cur + strlen(cur);

	tmp = g_strndup(cur, end - cur);
	msgname = g_ascii_strdown(tmp, -1);
	g_free(tmp);

	if ((msgent = g_hash_table_lookup(irc->msgs, msgname)) == NULL) {
		irc_msg_default(irc, "", from, &input);
		g_free(msgname);
		g_free(from);
		return;
	}
	g_free(msgname);

	fmt_valid = TRUE;
	args = g_new0(char *, strlen(msgent->format));
	args_cnt = 0;
	for (cur = end, fmt = msgent->format, i = 0; fmt[i] && *cur++; i++) {
		switch (fmt[i]) {
		case 'v':
			if (!(end = strchr(cur, ' '))) end = cur + strlen(cur);
			/* This is a string of unknown encoding which we do not
			 * want to transcode, but it may or may not be valid
			 * UTF-8, so we'll salvage it.  If a nick/channel/target
			 * field has inadvertently been marked verbatim, this
			 * could cause weirdness. */
			tmp = g_strndup(cur, end - cur);
			args[i] = purple_utf8_salvage(tmp);
			g_free(tmp);
			cur += end - cur;
			break;
		case 't':
		case 'n':
		case 'c':
			if (!(end = strchr(cur, ' '))) end = cur + strlen(cur);
			tmp = g_strndup(cur, end - cur);
			args[i] = irc_recv_convert(irc, tmp);
			g_free(tmp);
			cur += end - cur;
			break;
		case ':':
			if (*cur == ':') cur++;
			args[i] = irc_recv_convert(irc, cur);
			cur = cur + strlen(cur);
			break;
		case '*':
			/* Ditto 'v' above; we're going to salvage this in case
			 * it leaks past the IRC prpl */
			args[i] = purple_utf8_salvage(cur);
			cur = cur + strlen(cur);
			break;
		default:
			purple_debug(PURPLE_DEBUG_ERROR, "irc", "invalid message format character '%c'\n", fmt[i]);
			fmt_valid = FALSE;
			break;
		}
		if (fmt_valid)
			args_cnt = i + 1;
	}
	if (G_UNLIKELY(!fmt_valid)) {
		purple_debug_error("irc", "message format was invalid");
	} else if (G_LIKELY(args_cnt >= msgent->req_cnt)) {
		tmp = irc_recv_convert(irc, from);
		(msgent->cb)(irc, msgent->name, tmp, args);
		g_free(tmp);
	} else {
		purple_debug_error("irc", "args count (%d) doesn't reach "
			"expected value of %d for the '%s' command",
			args_cnt, msgent->req_cnt, msgent->name);
	}
	for (i = 0; i < strlen(msgent->format); i++) {
		g_free(args[i]);
	}
	g_free(args);
	g_free(from);
}

static void irc_parse_error_cb(struct irc_conn *irc, char *input)
{
	char *clean;
	/* This really should be escaped somehow that you can tell what
	 * the junk was -- but as it is, it can crash glib. */
	clean = purple_utf8_salvage(input);
	purple_debug(PURPLE_DEBUG_WARNING, "irc", "Unrecognized string: %s\n", clean);
	g_free(clean);
}
