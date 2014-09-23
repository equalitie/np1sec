/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * purple
 *
 * Copyright (C) 1998-2001, Mark Spencer <markster@marko.net>
 * Some code borrowed from GtkZephyr, by
 * Jag/Sean Dilda <agrajag@linuxpower.org>/<smdilda@unity.ncsu.edu>
 * http://gtkzephyr.linuxpower.org/
 *
 * Some code borrowed from kzephyr, by
 * Chris Colohan <colohan+@cs.cmu.edu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02111-1301	 USA
 *

*/
#include "libpurple/internal.h"

#include "accountopt.h"
#include "debug.h"
#include "notify.h"
#include "prpl.h"
#include "server.h"
#include "util.h"
#include "cmds.h"
#include "privacy.h"
#include "version.h"

#include "internal.h"

#include <strings.h>

#define ZEPHYR_FALLBACK_CHARSET "ISO-8859-1"

/* these are deliberately high, since most people don't send multiple "PING"s */
#define ZEPHYR_TYPING_SEND_TIMEOUT 15
#define ZEPHYR_TYPING_RECV_TIMEOUT 10
#define ZEPHYR_FD_READ 0
#define ZEPHYR_FD_WRITE 1

extern Code_t ZGetLocations(ZLocations_t *, int *);
extern Code_t ZSetLocation(char *);
extern Code_t ZUnsetLocation(void);
extern Code_t ZGetSubscriptions(ZSubscription_t *, int*);
extern char __Zephyr_realm[];
typedef struct _zframe zframe;
typedef struct _zephyr_triple zephyr_triple;
typedef struct _zephyr_account zephyr_account;
typedef struct _parse_tree parse_tree;

typedef enum {
	PURPLE_ZEPHYR_NONE, /* Non-kerberized ZEPH0.2 */
	PURPLE_ZEPHYR_KRB4, /* ZEPH0.2 w/ KRB4 support */
	PURPLE_ZEPHYR_TZC,  /* tzc executable proxy */
	PURPLE_ZEPHYR_INTERGALACTIC_KRB4 /* Kerberized ZEPH0.3 */
} zephyr_connection_type;

struct _zephyr_account {
	PurpleAccount* account;
	char *username;
	char *realm;
	char *encoding;
	char* galaxy; /* not yet useful */
	char* krbtkfile; /* not yet useful */
	guint32 nottimer;
	guint32 loctimer;
	GList *pending_zloc_names;
	GSList *subscrips;
	int last_id;
	unsigned short port;
	char ourhost[HOST_NAME_MAX + 1];
	char ourhostcanon[HOST_NAME_MAX + 1];
	zephyr_connection_type connection_type;
	int totzc[2];
	int fromtzc[2];
	char *exposure;
	pid_t tzc_pid;
	gchar *away;
};

#define MAXCHILDREN 20

struct _parse_tree {
	gchar* contents;
	parse_tree *children[MAXCHILDREN];
	int num_children;
};

parse_tree null_parse_tree = {
	"",
	{NULL},
	0,
};

#define use_none(zephyr) ((zephyr->connection_type == PURPLE_ZEPHYR_NONE)?1:0)
#define use_krb4(zephyr) ((zephyr->connection_type == PURPLE_ZEPHYR_KRB4)?1:0)
#define use_tzc(zephyr) ((zephyr->connection_type == PURPLE_ZEPHYR_TZC)?1:0)

#define use_zeph02(zephyr) (  (zephyr->connection_type == PURPLE_ZEPHYR_NONE)?1: ((zephyr->connection_type == PURPLE_ZEPHYR_KRB4)?1:0))

/* struct I need for zephyr_to_html */
struct _zframe {
	/* true for everything but @color, since inside the parens of that one is
	 * the color. */
	gboolean has_closer;
	/* @i, @b, etc. */
	const char *env;
	/* }=1, ]=2, )=4, >=8 */
	int closer_mask;
	/* }, ], ), > */
	char *closer;
	/* </i>, </font>, </b>, etc. */
	const char *closing;
	/* text including the opening html thingie. */
	GString *text;
	/* href for links */
	gboolean is_href;
	GString *href;
	struct _zframe *enclosing;
};

struct _zephyr_triple {
	char *class;
	char *instance;
	char *recipient;
	char *name;
	gboolean open;
	int id;
};

#define z_call(func)		if (func != ZERR_NONE)\
					return;
#define z_call_r(func)		if (func != ZERR_NONE)\
					return TRUE;

#define z_call_s(func, err)	if (func != ZERR_NONE) {\
					purple_connection_error(gc, err);\
					return;\
				}

#ifdef WIN32
extern const char *username;
#endif

static Code_t zephyr_subscribe_to(zephyr_account* zephyr, char* class, char *instance, char *recipient, char* galaxy) {
	size_t result;
	Code_t ret_val = -1;

	if (use_tzc(zephyr)) {
		/* ((tzcfodder . subscribe) ("class" "instance" "recipient")) */
		gchar *zsubstr = g_strdup_printf("((tzcfodder . subscribe) (\"%s\" \"%s\" \"%s\"))\n",class,instance,recipient);
		size_t len = strlen(zsubstr);
		result = write(zephyr->totzc[ZEPHYR_FD_WRITE],zsubstr,len);
		if (result != len) {
			purple_debug_error("zephyr", "Unable to write a message: %s\n", g_strerror(errno));
		} else {
			ret_val = ZERR_NONE;
		}
		g_free(zsubstr);
	}
	else {
		if (use_zeph02(zephyr)) {
			ZSubscription_t sub;
			sub.zsub_class = class;
			sub.zsub_classinst = instance;
			sub.zsub_recipient = recipient;
			ret_val = ZSubscribeTo(&sub,1,0);
		}
	}
	return ret_val;
}

char *local_zephyr_normalize(zephyr_account* zephyr,const char *);
static void zephyr_chat_set_topic(PurpleConnection * gc, int id, const char *topic);
char* zephyr_tzc_deescape_str(const char *message);

static char *zephyr_strip_local_realm(zephyr_account* zephyr,const char* user){
	/*
	  Takes in a username of the form username or username@realm
	  and returns:
	  username, if there is no realm, or the realm is the local realm
	  or:
	  username@realm if there is a realm and it is foreign
	*/
	char *tmp = g_strdup(user);
	char *at = strchr(tmp,'@');
	if (at && !g_ascii_strcasecmp(at+1,zephyr->realm)) {
		/* We're passed in a username of the form user@users-realm */
		char* tmp2;
		*at = '\0';
		tmp2 = g_strdup(tmp);
		g_free(tmp);
		return tmp2;
	}
	else {
		/* We're passed in a username of the form user or user@foreign-realm */
		return tmp;
	}
}

/* this is so bad, and if Zephyr weren't so fucked up to begin with I
 * wouldn't do this. but it is so i will. */

/* just for debugging */
static void handle_unknown(ZNotice_t notice)
{
	purple_debug_error("zephyr","z_packet: %s\n", notice.z_packet);
	purple_debug_error("zephyr","z_version: %s\n", notice.z_version);
	purple_debug_error("zephyr","z_kind: %d\n", (int)(notice.z_kind));
	purple_debug_error("zephyr","z_class: %s\n", notice.z_class);
	purple_debug_error("zephyr","z_class_inst: %s\n", notice.z_class_inst);
	purple_debug_error("zephyr","z_opcode: %s\n", notice.z_opcode);
	purple_debug_error("zephyr","z_sender: %s\n", notice.z_sender);
	purple_debug_error("zephyr","z_recipient: %s\n", notice.z_recipient);
	purple_debug_error("zephyr","z_message: %s\n", notice.z_message);
	purple_debug_error("zephyr","z_message_len: %d\n", notice.z_message_len);
}


static zephyr_triple *new_triple(zephyr_account *zephyr,const char *c, const char *i, const char *r)
{
	zephyr_triple *zt;

	zt = g_new0(zephyr_triple, 1);
	zt->class = g_strdup(c);
	zt->instance = g_strdup(i);
	zt->recipient = g_strdup(r);
	zt->name = g_strdup_printf("%s,%s,%s", c, i?i:"", r?r:"");
	zt->id = ++(zephyr->last_id);
	zt->open = FALSE;
	return zt;
}

static void free_triple(zephyr_triple * zt)
{
	g_free(zt->class);
	g_free(zt->instance);
	g_free(zt->recipient);
	g_free(zt->name);
	g_free(zt);
}

/* returns true if zt1 is a subset of zt2.  This function is used to
   determine whether a zephyr sent to zt1 should be placed in the chat
   with triple zt2

   zt1 is a subset of zt2
   iff. the classnames are identical ignoring case
   AND. the instance names are identical (ignoring case), or zt2->instance is *.
   AND. the recipient names are identical
*/

static gboolean triple_subset(zephyr_triple * zt1, zephyr_triple * zt2)
{

	if (!zt2) {
		purple_debug_error("zephyr","zt2 doesn't exist\n");
		return FALSE;
	}
	if (!zt1) {
		purple_debug_error("zephyr","zt1 doesn't exist\n");
		return FALSE;
	}
	if (!(zt1->class)) {
		purple_debug_error("zephyr","zt1c doesn't exist\n");
		return FALSE;
	}
	if (!(zt1->instance)) {
		purple_debug_error("zephyr","zt1i doesn't exist\n");
		return FALSE;
	}
	if (!(zt1->recipient)) {
		purple_debug_error("zephyr","zt1r doesn't exist\n");
		return FALSE;
	}
	if (!(zt2->class)) {
		purple_debug_error("zephyr","zt2c doesn't exist\n");
		return FALSE;
	}
	if (!(zt2->recipient)) {
		purple_debug_error("zephyr","zt2r doesn't exist\n");
		return FALSE;
	}
	if (!(zt2->instance)) {
		purple_debug_error("zephyr","zt2i doesn't exist\n");
		return FALSE;
	}

	if (g_ascii_strcasecmp(zt2->class, zt1->class)) {
		return FALSE;
	}
	if (g_ascii_strcasecmp(zt2->instance, zt1->instance) && g_ascii_strcasecmp(zt2->instance, "*")) {
		return FALSE;
	}
	if (g_ascii_strcasecmp(zt2->recipient, zt1->recipient)) {
		return FALSE;
	}
	purple_debug_info("zephyr","<%s,%s,%s> is in <%s,%s,%s>\n",zt1->class,zt1->instance,zt1->recipient,zt2->class,zt2->instance,zt2->recipient);
	return TRUE;
}

static zephyr_triple *find_sub_by_triple(zephyr_account *zephyr,zephyr_triple * zt)
{
	zephyr_triple *curr_t;
	GSList *curr = zephyr->subscrips;

	while (curr) {
		curr_t = curr->data;
		if (triple_subset(zt, curr_t))
			return curr_t;
		curr = curr->next;
	}
	return NULL;
}

static zephyr_triple *find_sub_by_id(zephyr_account *zephyr,int id)
{
	zephyr_triple *zt;
	GSList *curr = zephyr->subscrips;

	while (curr) {
		zt = curr->data;
		if (zt->id == id)
			return zt;
		curr = curr->next;
	}
	return NULL;
}

/*
   Converts strings to utf-8 if necessary using user specified encoding
*/

static gchar *zephyr_recv_convert(PurpleConnection *gc, gchar *string)
{
	gchar *utf8;
	GError *err = NULL;
	zephyr_account *zephyr = gc->proto_data;
	if (g_utf8_validate(string, -1, NULL)) {
		return g_strdup(string);
	} else {
		utf8 = g_convert(string, -1, "UTF-8", zephyr->encoding, NULL, NULL, &err);
		if (err) {
			purple_debug_error("zephyr", "recv conversion error: %s\n", err->message);
			utf8 = g_strdup(_("(There was an error converting this message.	 Check the 'Encoding' option in the Account Editor)"));
			g_error_free(err);
		}

		return utf8;
	}
}

/* This parses HTML formatting (put out by one of the gtkimhtml widgets
   And converts it to zephyr formatting.
   It currently deals properly with <b>, <br>, <i>, <font face=...>, <font color=...>,
   It ignores <font back=...>
   It does
   <font size = "1 or 2" -> @small
   3 or 4  @medium()
   5,6, or 7 @large()
   <a href is dealt with by outputting "description <link>" or just "description" as appropriate
*/

static char *html_to_zephyr(const char *message)
{
	zframe *frames, *new_f;
	char *ret;

	if (*message == '\0')
		return g_strdup("");

	frames = g_new(zframe, 1);
	frames->text = g_string_new("");
	frames->href = NULL;
	frames->is_href = FALSE;
	frames->enclosing = NULL;
	frames->closing = NULL;
	frames->env = "";
	frames->has_closer = FALSE;
	frames->closer_mask = 15;

	purple_debug_info("zephyr","html received %s\n",message);
	while (*message) {
		if (frames->closing && !g_ascii_strncasecmp(message, frames->closing, strlen(frames->closing))) {
			zframe *popped;
			message += strlen(frames->closing);
			popped = frames;
			frames = frames->enclosing;
			if (popped->is_href) {
				frames->href = popped->text;
			} else {
				g_string_append(frames->text, popped->env);
				if (popped->has_closer) {
					g_string_append_c(frames->text,
							  (popped->closer_mask & 1) ? '{' :
							  (popped->closer_mask & 2) ? '[' :
							  (popped->closer_mask & 4) ? '(' :
							  '<');
				}
				g_string_append(frames->text, popped->text->str);
				if (popped->href)
				{
					int text_len = strlen(popped->text->str), href_len = strlen(popped->href->str);
					if (!((text_len == href_len && !strncmp(popped->href->str, popped->text->str, text_len)) ||
					      (7 + text_len == href_len && !strncmp(popped->href->str, "http://", 7) &&
					       !strncmp(popped->href->str + 7, popped->text->str, text_len)) ||
					      (7 + text_len == href_len && !strncmp(popped->href->str, "mailto:", 7) &&
					       !strncmp(popped->href->str + 7, popped->text->str, text_len)))) {
						g_string_append(frames->text, " <");
						g_string_append(frames->text, popped->href->str);
						if (popped->closer_mask & ~8) {
							g_string_append_c(frames->text, '>');
							popped->closer_mask &= ~8;
						} else {
							g_string_append(frames->text, "@{>}");
						}
					}
					g_string_free(popped->href, TRUE);
				}
				if (popped->has_closer) {
					g_string_append_c(frames->text,
							  (popped->closer_mask & 1) ? '}' :
							  (popped->closer_mask & 2) ? ']' :
							  (popped->closer_mask & 4) ? ')' :
							  '>');
				}
				if (!popped->has_closer)
					frames->closer_mask = popped->closer_mask;
				g_string_free(popped->text, TRUE);
			}
			g_free(popped);
		} else if (*message == '<') {
			if (!g_ascii_strncasecmp(message + 1, "i>", 2)) {
				new_f = g_new(zframe, 1);
				new_f->enclosing = frames;
				new_f->text = g_string_new("");
				new_f->href = NULL;
				new_f->is_href = FALSE;
				new_f->closing = "</i>";
				new_f->env = "@i";
				new_f->has_closer = TRUE;
				new_f->closer_mask = 15;
				frames = new_f;
				message += 3;
			} else if (!g_ascii_strncasecmp(message + 1, "b>", 2)) {
				new_f = g_new(zframe, 1);
				new_f->enclosing = frames;
				new_f->text = g_string_new("");
				new_f->href = NULL;
				new_f->is_href = FALSE;
				new_f->closing = "</b>";
				new_f->env = "@b";
				new_f->has_closer = TRUE;
				new_f->closer_mask = 15;
				frames = new_f;
				message += 3;
			} else if (!g_ascii_strncasecmp(message + 1, "br>", 3)) {
				g_string_append_c(frames->text, '\n');
				message += 4;
			} else if (!g_ascii_strncasecmp(message + 1, "a href=\"", 8)) {
				message += 9;
				new_f = g_new(zframe, 1);
				new_f->enclosing = frames;
				new_f->text = g_string_new("");
				new_f->href = NULL;
				new_f->is_href = FALSE;
				new_f->closing = "</a>";
				new_f->env = "";
				new_f->has_closer = FALSE;
				new_f->closer_mask = frames->closer_mask;
				frames = new_f;
				new_f = g_new(zframe, 1);
				new_f->enclosing = frames;
				new_f->text = g_string_new("");
				new_f->href = NULL;
				new_f->is_href = TRUE;
				new_f->closing = "\">";
				new_f->has_closer = FALSE;
				new_f->closer_mask = frames->closer_mask;
				frames = new_f;
			} else if (!g_ascii_strncasecmp(message + 1, "font", 4)) {
				new_f = g_new(zframe, 1);
				new_f->enclosing = frames;
				new_f->text = g_string_new("");
				new_f->href = NULL;
				new_f->is_href = FALSE;
				new_f->closing = "</font>";
				new_f->has_closer = TRUE;
				new_f->closer_mask = 15;
				message += 5;
				while (*message == ' ')
					message++;
				if (!g_ascii_strncasecmp(message, "color=\"", 7)) {
					message += 7;
					new_f->env = "@";
					frames = new_f;
					new_f = g_new(zframe, 1);
					new_f->enclosing = frames;
					new_f->env = "@color";
					new_f->text = g_string_new("");
					new_f->href = NULL;
					new_f->is_href = FALSE;
					new_f->closing = "\">";
					new_f->has_closer = TRUE;
					new_f->closer_mask = 15;
				} else if (!g_ascii_strncasecmp(message, "face=\"", 6)) {
					message += 6;
					new_f->env = "@";
					frames = new_f;
					new_f = g_new(zframe, 1);
					new_f->enclosing = frames;
					new_f->env = "@font";
					new_f->text = g_string_new("");
					new_f->href = NULL;
					new_f->is_href = FALSE;
					new_f->closing = "\">";
					new_f->has_closer = TRUE;
					new_f->closer_mask = 15;
				} else if (!g_ascii_strncasecmp(message, "size=\"", 6)) {
					message += 6;
					if ((*message == '1') || (*message == '2')) {
						new_f->env = "@small";
					} else if ((*message == '3')
						   || (*message == '4')) {
						new_f->env = "@medium";
					} else if ((*message == '5')
						   || (*message == '6')
						   || (*message == '7')) {
						new_f->env = "@large";
					} else {
						new_f->env = "";
						new_f->has_closer = FALSE;
						new_f->closer_mask = frames->closer_mask;
					}
					message += 3;
				} else {
					/* Drop all unrecognized/misparsed font tags */
					new_f->env = "";
					new_f->has_closer = FALSE;
					new_f->closer_mask = frames->closer_mask;
					while (g_ascii_strncasecmp(message, "\">", 2) != 0) {
						message++;
					}
					if (*message != '\0')
						message += 2;
				}
				frames = new_f;
			} else {
				/* Catch all for all unrecognized/misparsed <foo> tage */
				g_string_append_c(frames->text, *message++);
			}
		} else if (*message == '@') {
			g_string_append(frames->text, "@@");
			message++;
		} else if (*message == '}') {
			if (frames->closer_mask & ~1) {
				frames->closer_mask &= ~1;
				g_string_append_c(frames->text, *message++);
			} else {
				g_string_append(frames->text, "@[}]");
				message++;
			}
		} else if (*message == ']') {
			if (frames->closer_mask & ~2) {
				frames->closer_mask &= ~2;
				g_string_append_c(frames->text, *message++);
			} else {
				g_string_append(frames->text, "@{]}");
				message++;
			}
		} else if (*message == ')') {
			if (frames->closer_mask & ~4) {
				frames->closer_mask &= ~4;
				g_string_append_c(frames->text, *message++);
			} else {
				g_string_append(frames->text, "@{)}");
				message++;
			}
		} else if (!g_ascii_strncasecmp(message, "&gt;", 4)) {
			if (frames->closer_mask & ~8) {
				frames->closer_mask &= ~8;
				g_string_append_c(frames->text, *message++);
			} else {
				g_string_append(frames->text, "@{>}");
				message += 4;
			}
		} else {
			g_string_append_c(frames->text, *message++);
		}
	}
	ret = frames->text->str;
	g_string_free(frames->text, FALSE);
	g_free(frames);
	purple_debug_info("zephyr","zephyr outputted  %s\n",ret);
	return ret;
}

/* this parses zephyr formatting and converts it to html. For example, if
 * you pass in "@{@color(blue)@i(hello)}" you should get out
 * "<font color=blue><i>hello</i></font>". */
static char *zephyr_to_html(const char *message)
{
	zframe *frames, *curr;
	char *ret;

	frames = g_new(zframe, 1);
	frames->text = g_string_new("");
	frames->enclosing = NULL;
	frames->closing = "";
	frames->has_closer = FALSE;
	frames->closer = NULL;

	while (*message) {
		if (*message == '@' && message[1] == '@') {
			g_string_append(frames->text, "@");
			message += 2;
		} else if (*message == '@') {
			int end;
			for (end = 1; message[end] && (isalnum(message[end]) || message[end] == '_'); end++);
			if (message[end] &&
			    (message[end] == '{' || message[end] == '[' || message[end] == '(' ||
			     !g_ascii_strncasecmp(message + end, "&lt;", 4))) {
				zframe *new_f;
				char *buf;
				buf = g_new0(char, end);
				g_snprintf(buf, end, "%s", message + 1);
				message += end;
				new_f = g_new(zframe, 1);
				new_f->enclosing = frames;
				new_f->has_closer = TRUE;
				new_f->closer = (*message == '{' ? "}" :
						 *message == '[' ? "]" :
						 *message == '(' ? ")" :
						 "&gt;");
				message += (*message == '&' ? 4 : 1);
				if (!g_ascii_strcasecmp(buf, "italic") || !g_ascii_strcasecmp(buf, "i")) {
					new_f->text = g_string_new("<i>");
					new_f->closing = "</i>";
				} else if (!g_ascii_strcasecmp(buf, "small")) {
					new_f->text = g_string_new("<font size=\"1\">");
					new_f->closing = "</font>";
				} else if (!g_ascii_strcasecmp(buf, "medium")) {
					new_f->text = g_string_new("<font size=\"3\">");
					new_f->closing = "</font>";
				} else if (!g_ascii_strcasecmp(buf, "large")) {
					new_f->text = g_string_new("<font size=\"7\">");
					new_f->closing = "</font>";
				} else if (!g_ascii_strcasecmp(buf, "bold")
					   || !g_ascii_strcasecmp(buf, "b")) {
					new_f->text = g_string_new("<b>");
					new_f->closing = "</b>";
				} else if (!g_ascii_strcasecmp(buf, "font")) {
					zframe *extra_f;
					extra_f = g_new(zframe, 1);
					extra_f->enclosing = frames;
					new_f->enclosing = extra_f;
					extra_f->text = g_string_new("");
					extra_f->has_closer = FALSE;
					extra_f->closer = frames->closer;
					extra_f->closing = "</font>";
					new_f->text = g_string_new("<font face=\"");
					new_f->closing = "\">";
				} else if (!g_ascii_strcasecmp(buf, "color")) {
					zframe *extra_f;
					extra_f = g_new(zframe, 1);
					extra_f->enclosing = frames;
					new_f->enclosing = extra_f;
					extra_f->text = g_string_new("");
					extra_f->has_closer = FALSE;
					extra_f->closer = frames->closer;
					extra_f->closing = "</font>";
					new_f->text = g_string_new("<font color=\"");
					new_f->closing = "\">";
				} else {
					new_f->text = g_string_new("");
					new_f->closing = "";
				}
				frames = new_f;
			} else {
				/* Not a formatting tag, add the character as normal. */
				g_string_append_c(frames->text, *message++);
			}
		} else if (frames->closer && !g_ascii_strncasecmp(message, frames->closer, strlen(frames->closer))) {
			zframe *popped;
			gboolean last_had_closer;

			message += strlen(frames->closer);
			if (frames && frames->enclosing) {
				do {
					popped = frames;
					frames = frames->enclosing;
					g_string_append(frames->text, popped->text->str);
					g_string_append(frames->text, popped->closing);
					g_string_free(popped->text, TRUE);
					last_had_closer = popped->has_closer;
					g_free(popped);
				} while (frames && frames->enclosing && !last_had_closer);
			} else {
				g_string_append_c(frames->text, *message);
			}
		} else if (*message == '\n') {
			g_string_append(frames->text, "<br>");
			message++;
		} else {
			g_string_append_c(frames->text, *message++);
		}
	}
	/* go through all the stuff that they didn't close */
	while (frames->enclosing) {
		curr = frames;
		g_string_append(frames->enclosing->text, frames->text->str);
		g_string_append(frames->enclosing->text, frames->closing);
		g_string_free(frames->text, TRUE);
		frames = frames->enclosing;
		g_free(curr);
	}
	ret = frames->text->str;
	g_string_free(frames->text, FALSE);
	g_free(frames);
	return ret;
}

static gboolean pending_zloc(zephyr_account *zephyr, const char *who)
{
	GList *curr;

	for (curr = zephyr->pending_zloc_names; curr != NULL; curr = curr->next) {
		char* normalized_who = local_zephyr_normalize(zephyr,who);
		if (!g_ascii_strcasecmp(normalized_who, (char *)curr->data)) {
			g_free((char *)curr->data);
			zephyr->pending_zloc_names = g_list_remove(zephyr->pending_zloc_names, curr->data);
			return TRUE;
		}
	}
	return FALSE;
}

/* Called when the server notifies us a message couldn't get sent */

static void message_failed(PurpleConnection *gc, ZNotice_t notice, struct sockaddr_in from)
{
	if (g_ascii_strcasecmp(notice.z_class, "message")) {
		gchar* chat_failed = g_strdup_printf(_("Unable to send to chat %s,%s,%s"),notice.z_class,notice.z_class_inst,notice.z_recipient);
		purple_notify_error(gc,"",chat_failed,NULL);
		g_free(chat_failed);
	} else {
		purple_notify_error(gc, notice.z_recipient, _("User is offline"), NULL);
	}
}

static void handle_message(PurpleConnection *gc,ZNotice_t notice)
{
	zephyr_account* zephyr = gc->proto_data;

	if (!g_ascii_strcasecmp(notice.z_class, LOGIN_CLASS)) {
		/* well, we'll be updating in 20 seconds anyway, might as well ignore this. */
	} else if (!g_ascii_strcasecmp(notice.z_class, LOCATE_CLASS)) {
		if (!g_ascii_strcasecmp(notice.z_opcode, LOCATE_LOCATE)) {
			int nlocs;
			char *user;
			PurpleBuddy *b;
			const char *bname;

			/* XXX add real error reporting */
			if (ZParseLocations(&notice, NULL, &nlocs, &user) != ZERR_NONE)
				return;

			if ((b = purple_find_buddy(gc->account, user)) == NULL) {
				char* stripped_user = zephyr_strip_local_realm(zephyr,user);
				b = purple_find_buddy(gc->account,stripped_user);
				g_free(stripped_user);
			}

			bname = b ? purple_buddy_get_name(b) : NULL;
			if ((b && pending_zloc(zephyr,bname)) || pending_zloc(zephyr,user)) {
				ZLocations_t locs;
				int one = 1;
				PurpleNotifyUserInfo *user_info = purple_notify_user_info_new();
				char *tmp;
				const char *balias;

				purple_notify_user_info_add_pair(user_info, _("User"), (b ? bname : user));
				balias = purple_buddy_get_local_buddy_alias(b);
				if (b && balias)
					purple_notify_user_info_add_pair(user_info, _("Alias"), balias);

				if (!nlocs) {
					purple_notify_user_info_add_pair(user_info, NULL, _("Hidden or not logged-in"));
				}
				for (; nlocs > 0; nlocs--) {
					/* XXX add real error reporting */

					ZGetLocations(&locs, &one);
					tmp = g_strdup_printf(_("<br>At %s since %s"), locs.host, locs.time);
					purple_notify_user_info_add_pair(user_info, _("Location"), tmp);
					g_free(tmp);
				}
				purple_notify_userinfo(gc, (b ? bname : user),
						     user_info, NULL, NULL);
				purple_notify_user_info_destroy(user_info);
			} else {
				if (nlocs>0)
					purple_prpl_got_user_status(gc->account, b ? bname : user, "available", NULL);
				else
					purple_prpl_got_user_status(gc->account, b ? bname : user, "offline", NULL);
			}

			g_free(user);
		}
	} else {
		char *buf, *buf2, *buf3;
		char *send_inst;
		PurpleConversation *gconv1;
		PurpleConvChat *gcc;
		char *ptr = (char *) notice.z_message + (strlen(notice.z_message) + 1);
		int len;
		char *stripped_sender;
		int signature_length = strlen(notice.z_message);
		int message_has_no_body = 0;
		PurpleMessageFlags flags = 0;
		gchar *tmpescape;

		/* Need to deal with 0 length  messages to handle typing notification (OPCODE) ping messages */
		/* One field zephyrs would have caused purple to crash */
		if ( (notice.z_message_len == 0) || (signature_length >= notice.z_message_len - 1)) {
			message_has_no_body = 1;
			len = 0;
			purple_debug_info("zephyr","message_size %d %d %d\n",len,notice.z_message_len,signature_length);
			buf3 = g_strdup("");

		} else {
			len =  notice.z_message_len - ( signature_length +1);
			purple_debug_info("zephyr","message_size %d %d %d\n",len,notice.z_message_len,signature_length);
			buf = g_malloc(len + 1);
			g_snprintf(buf, len + 1, "%s", ptr);
			g_strchomp(buf);
			tmpescape = g_markup_escape_text(buf, -1);
			g_free(buf);
			buf2 = zephyr_to_html(tmpescape);
			buf3 = zephyr_recv_convert(gc, buf2);
			g_free(buf2);
			g_free(tmpescape);
		}

		stripped_sender = zephyr_strip_local_realm(zephyr,notice.z_sender);

		if (!g_ascii_strcasecmp(notice.z_class, "MESSAGE") && !g_ascii_strcasecmp(notice.z_class_inst, "PERSONAL")
		    && !g_ascii_strcasecmp(notice.z_recipient,zephyr->username)) {
			if (!g_ascii_strcasecmp(notice.z_message, "Automated reply:"))
				flags |= PURPLE_MESSAGE_AUTO_RESP;

			if (!g_ascii_strcasecmp(notice.z_opcode,"PING"))
				serv_got_typing(gc,stripped_sender,ZEPHYR_TYPING_RECV_TIMEOUT, PURPLE_TYPING);
			else
				serv_got_im(gc, stripped_sender, buf3, flags, time(NULL));

		} else {
			zephyr_triple *zt1, *zt2;
			gchar *send_inst_utf8;
			zephyr_account *zephyr = gc->proto_data;
			zt1 = new_triple(zephyr,notice.z_class, notice.z_class_inst, notice.z_recipient);
			zt2 = find_sub_by_triple(zephyr,zt1);
			if (!zt2) {
				/* This is a server supplied subscription */
				zephyr->subscrips = g_slist_append(zephyr->subscrips, new_triple(zephyr,zt1->class,zt1->instance,zt1->recipient));
				zt2 = find_sub_by_triple(zephyr,zt1);
			}

			if (!zt2->open) {
				zt2->open = TRUE;
				serv_got_joined_chat(gc, zt2->id, zt2->name);
				zephyr_chat_set_topic(gc,zt2->id,notice.z_class_inst);
			}

			if (!g_ascii_strcasecmp(notice.z_class_inst,"PERSONAL"))
				send_inst_utf8 = g_strdup(stripped_sender);
			else {
				send_inst = g_strdup_printf("[%s] %s",notice.z_class_inst,stripped_sender);
				send_inst_utf8 = zephyr_recv_convert(gc,send_inst);
				g_free(send_inst);
				if (!send_inst_utf8) {
					purple_debug_error("zephyr","Failed to convert instance for sender %s.\n", stripped_sender);
					send_inst_utf8 = g_strdup(stripped_sender);
				}
			}

			gconv1 = purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT,
														 zt2->name, gc->account);
			gcc = purple_conversation_get_chat_data(gconv1);
#ifndef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN 16
#endif
			if (!purple_conv_chat_find_user(gcc, stripped_sender)) {
				gchar ipaddr[INET_ADDRSTRLEN];
#ifdef HAVE_INET_NTOP
				inet_ntop(AF_INET, &notice.z_sender_addr.s_addr, ipaddr, sizeof(ipaddr));
#else
				memcpy(ipaddr,inet_ntoa(notice.z_sender_addr),sizeof(ipaddr));
#endif
				purple_conv_chat_add_user(gcc, stripped_sender, ipaddr, PURPLE_CBFLAGS_NONE, TRUE);
			}
			serv_got_chat_in(gc, zt2->id, send_inst_utf8, 0, buf3, time(NULL));
			g_free(send_inst_utf8);

			free_triple(zt1);
		}
		g_free(stripped_sender);
		g_free(buf3);
	}
}

static int  free_parse_tree(parse_tree* tree) {
	if (!tree) {
		return 0;
	}
	else {
		int i;
		for(i=0;i<tree->num_children;i++){
			if (tree->children[i]) {
				free_parse_tree(tree->children[i]);
				g_free(tree->children[i]);
			}
		}
		if ((tree != &null_parse_tree) && (tree->contents != NULL))
			g_free(tree->contents);

	}
	return 0;
}

static parse_tree *tree_child(parse_tree* tree,int index) {
	if (index < tree->num_children) {
		return tree->children[index];
	} else {
		return &null_parse_tree;
	}
}

static parse_tree *find_node(parse_tree* ptree,gchar* key)
{
	gchar* tc;

	if (!ptree || ! key)
		return &null_parse_tree;

	tc = tree_child(ptree,0)->contents;

	/* g_strcasecmp() is deprecated.  What is the encoding here??? */
	if (ptree->num_children > 0  &&	tc && !g_ascii_strcasecmp(tc, key)) {
		return ptree;
	} else {
		parse_tree *result = &null_parse_tree;
		int i;
		for(i = 0; i < ptree->num_children; i++) {
			result = find_node(ptree->children[i],key);
			if(result != &null_parse_tree) {
				break;
			}
		}
		return result;
	}
}

static parse_tree *parse_buffer(gchar* source, gboolean do_parse) {

	parse_tree *ptree = g_new0(parse_tree,1);
	ptree->contents = NULL;
	ptree->num_children=0;
	if (do_parse) {
		unsigned int p = 0;
		while(p < strlen(source)) {
			unsigned int end;
			gchar *newstr;

			/* Eat white space: */
			if(g_ascii_isspace(source[p]) || source[p] == '\001') {
				p++;
				continue;
			}

			/* Skip comments */
			if(source[p] == ';') {
				while(source[p] != '\n' && p < strlen(source)) {
					p++;
				}
				continue;
			}

			if(source[p] == '(') {
				int nesting = 0;
				gboolean in_quote = FALSE;
				gboolean escape_next = FALSE;
				p++;
				end = p;
				while(!(source[end] == ')' && nesting == 0 && !in_quote) && end < strlen(source)) {
					if(!escape_next) {
						if(source[end] == '\\') {
							escape_next = TRUE;
						}
						if(!in_quote) {
							if(source[end] == '(') {
								nesting++;
							}
							if(source[end] == ')') {
								nesting--;
							}
						}
						if(source[end] == '"') {
							in_quote = !in_quote;
						}
					} else {
						escape_next = FALSE;
					}
					end++;
				}
				do_parse = TRUE;

			} else {
				gchar end_char;
				if(source[p] == '"') {
					end_char = '"';
					p++;
				} else {
					end_char = ' ';
				}
				do_parse = FALSE;

				end = p;
				while(source[end] != end_char && end < strlen(source)) {
					if(source[end] == '\\')
						end++;
					end++;
				}
			}
			newstr = g_new0(gchar, end+1-p);
			strncpy(newstr,source+p,end-p);
			if (ptree->num_children < MAXCHILDREN) {
				/* In case we surpass maxchildren, ignore this */
				ptree->children[ptree->num_children++] = parse_buffer( newstr, do_parse);
			} else {
				purple_debug_error("zephyr","too many children in tzc output. skipping\n");
			}
			g_free(newstr);
			p = end + 1;
		}
		return ptree;
	} else {
		/* XXX does this have to be strdup'd */
		ptree->contents = g_strdup(source);
		return ptree;
	}
}

static parse_tree  *read_from_tzc(zephyr_account* zephyr){
	struct timeval tv;
	fd_set rfds;
	int bufsize = 2048;
	char *buf = (char *)calloc(bufsize, 1);
	char *bufcur = buf;
	int selected = 0;
	parse_tree *incoming_msg;

	FD_ZERO(&rfds);
	FD_SET(zephyr->fromtzc[ZEPHYR_FD_READ], &rfds);
	tv.tv_sec = 0;
	tv.tv_usec = 0;
	incoming_msg=NULL;

	while (select(zephyr->fromtzc[ZEPHYR_FD_READ] + 1, &rfds, NULL, NULL, &tv)) {
		selected = 1;
		read(zephyr->fromtzc[ZEPHYR_FD_READ], bufcur, 1);
		bufcur++;
		if ((bufcur - buf) > (bufsize - 1)) {
			if ((buf = realloc(buf, bufsize * 2)) == NULL) {
				purple_debug_error("zephyr","Ran out of memory\n");
				exit(-1);
			} else {
				bufcur = buf + bufsize;
				bufsize *= 2;
			}
		}
	}
	*bufcur = '\0';

	if (selected) {
		incoming_msg = parse_buffer(buf,TRUE);
	}
	free(buf);
	return incoming_msg;
}

static gint check_notify_tzc(gpointer data)
{
	PurpleConnection *gc = (PurpleConnection *)data;
	zephyr_account* zephyr = gc->proto_data;
	parse_tree *newparsetree = read_from_tzc(zephyr);
	if (newparsetree != NULL) {
		gchar *spewtype;
		if ( (spewtype =  tree_child(find_node(newparsetree,"tzcspew"),2)->contents) ) {
			if (!g_ascii_strncasecmp(spewtype,"message",7)) {
				ZNotice_t notice;
				parse_tree *msgnode = tree_child(find_node(newparsetree,"message"),2);
				parse_tree *bodynode = tree_child(msgnode,1);
				/*				char *zsig = g_strdup(" "); */ /* purple doesn't care about zsigs */
				char *msg  = zephyr_tzc_deescape_str(bodynode->contents);
				size_t bufsize = strlen(msg) + 3;
				char *buf = g_new0(char,bufsize);
				g_snprintf(buf,1+strlen(msg)+2," %c%s",'\0',msg);
				memset((char *)&notice, 0, sizeof(notice));
				notice.z_kind = ACKED;
				notice.z_port = 0;
				notice.z_opcode = tree_child(find_node(newparsetree,"opcode"),2)->contents;
				notice.z_class = zephyr_tzc_deescape_str(tree_child(find_node(newparsetree,"class"),2)->contents);
				notice.z_class_inst = tree_child(find_node(newparsetree,"instance"),2)->contents;
				notice.z_recipient = local_zephyr_normalize(zephyr,tree_child(find_node(newparsetree,"recipient"),2)->contents);
				notice.z_sender = local_zephyr_normalize(zephyr,tree_child(find_node(newparsetree,"sender"),2)->contents);
				notice.z_default_format = "Class $class, Instance $instance:\n" "To: @bold($recipient) at $time $date\n" "From: @bold($1) <$sender>\n\n$2";
				notice.z_message_len = strlen(msg) + 3;
				notice.z_message = buf;
				handle_message(gc, notice);
				g_free(msg);
				/*				  g_free(zsig); */
				g_free(buf);
				/* free_parse_tree(msgnode);
				   free_parse_tree(bodynode);
				   g_free(msg);
				   g_free(zsig);
				   g_free(buf);
				*/
			}
			else if (!g_ascii_strncasecmp(spewtype,"zlocation",9)) {
				/* check_loc or zephyr_zloc respectively */
				/* XXX fix */
				char *user;
				PurpleBuddy *b;
				const char *bname;
				int nlocs = 0;
				parse_tree *locations;
				gchar *locval;
				user = tree_child(find_node(newparsetree,"user"),2)->contents;

				if ((b = purple_find_buddy(gc->account, user)) == NULL) {
					gchar *stripped_user = zephyr_strip_local_realm(zephyr,user);
					b = purple_find_buddy(gc->account, stripped_user);
					g_free(stripped_user);
				}
				locations = find_node(newparsetree,"locations");
				locval = tree_child(tree_child(tree_child(tree_child(locations,2),0),0),2)->contents;

				if (!locval || !g_ascii_strcasecmp(locval," ") || (strlen(locval) == 0)) {
					nlocs = 0;
				} else {
					nlocs = 1;
				}

				bname = b ? purple_buddy_get_name(b) : NULL;
				if ((b && pending_zloc(zephyr,bname)) || pending_zloc(zephyr,user) || pending_zloc(zephyr,local_zephyr_normalize(zephyr,user))){
					PurpleNotifyUserInfo *user_info = purple_notify_user_info_new();
					char *tmp;
					const char *balias;

					purple_notify_user_info_add_pair(user_info, _("User"), (b ? bname : user));

					balias = b ? purple_buddy_get_local_buddy_alias(b) : NULL;
					if (balias)
						purple_notify_user_info_add_pair(user_info, _("Alias"), balias);

					if (!nlocs) {
						purple_notify_user_info_add_pair(user_info, NULL, _("Hidden or not logged-in"));
					} else {
						tmp = g_strdup_printf(_("<br>At %s since %s"),
									  tree_child(tree_child(tree_child(tree_child(locations,2),0),0),2)->contents,
									  tree_child(tree_child(tree_child(tree_child(locations,2),0),2),2)->contents);
						purple_notify_user_info_add_pair(user_info, _("Location"), tmp);
						g_free(tmp);
					}

					purple_notify_userinfo(gc, b ? bname : user,
							     user_info, NULL, NULL);
					purple_notify_user_info_destroy(user_info);
				} else {
					if (nlocs>0)
						purple_prpl_got_user_status(gc->account, b ? bname : user, "available", NULL);
					else
						purple_prpl_got_user_status(gc->account, b ? bname : user, "offline", NULL);
				}
			}
			else if (!g_ascii_strncasecmp(spewtype,"subscribed",10)) {
			}
			else if (!g_ascii_strncasecmp(spewtype,"start",5)) {
			}
			else if (!g_ascii_strncasecmp(spewtype,"error",5)) {
				/* XXX handle */
			}
		} else {
		}
	} else {
	}

	free_parse_tree(newparsetree);
	return TRUE;
}

static gint check_notify_zeph02(gpointer data)
{
	/* XXX add real error reporting */
	PurpleConnection *gc = (PurpleConnection*) data;
	while (ZPending()) {
		ZNotice_t notice;
		struct sockaddr_in from;
		/* XXX add real error reporting */

		z_call_r(ZReceiveNotice(&notice, &from));

		switch (notice.z_kind) {
		case UNSAFE:
		case UNACKED:
		case ACKED:
			handle_message(gc,notice);
			break;
		case SERVACK:
			if (!(g_ascii_strcasecmp(notice.z_message, ZSRVACK_NOTSENT))) {
				message_failed(gc,notice, from);
			}
			break;
		case CLIENTACK:
			purple_debug_error("zephyr", "Client ack received\n");
		default:
			/* we'll just ignore things for now */
			handle_unknown(notice);
			purple_debug_error("zephyr", "Unhandled notice.\n");
			break;
		}
		/* XXX add real error reporting */
		ZFreeNotice(&notice);
	}

	return TRUE;
}

#ifdef WIN32

static gint check_loc(gpointer data)
{
	GSList *buddies;
	ZLocations_t locations;
	PurpleConnection *gc = data;
	zephyr_account *zephyr = gc->proto_data;
	PurpleAccount *account = purple_connection_get_account(gc);
	int numlocs;
	int one = 1;

	for (buddies = purple_find_buddies(account, NULL); buddies;
			buddies = g_slist_delete_link(buddies, buddies)) {
		PurpleBuddy *b = buddies->data;
		char *chk;
		const char *bname = purple_buddy_get_name(b);
		chk = local_zephyr_normalize(bname);
		ZLocateUser(chk,&numlocs, ZAUTH);
		if (numlocs) {
			int i;
			for(i=0;i<numlocs;i++) {
				ZGetLocations(&locations,&one);
				serv_got_update(zgc,bname,1,0,0,0,0);
			}
		}
	}

	return TRUE;
}

#else

static gint check_loc(gpointer data)
{
	GSList *buddies;
	ZAsyncLocateData_t ald;
	PurpleConnection *gc = (PurpleConnection *)data;
	zephyr_account *zephyr = gc->proto_data;
	PurpleAccount *account = purple_connection_get_account(gc);

	if (use_zeph02(zephyr)) {
		ald.user = NULL;
		memset(&(ald.uid), 0, sizeof(ZUnique_Id_t));
		ald.version = NULL;
	}

	for (buddies = purple_find_buddies(account, NULL); buddies;
			buddies = g_slist_delete_link(buddies, buddies)) {
		PurpleBuddy *b = buddies->data;

		const char *chk;
		const char *name = purple_buddy_get_name(b);

		chk = local_zephyr_normalize(zephyr,name);
		purple_debug_info("zephyr","chk: %s b->name %s\n",chk,name);
		/* XXX add real error reporting */
		/* doesn't matter if this fails or not; we'll just move on to the next one */
		if (use_zeph02(zephyr)) {
#ifdef WIN32
			int numlocs;
			int one=1;
			ZLocateUser(chk,&numlocs,ZAUTH);
			if (numlocs) {
				int i;
				for(i=0;i<numlocs;i++) {
					ZGetLocations(&locations,&one);
					if (nlocs>0)
						purple_prpl_got_user_status(account,name,"available",NULL);
					else
						purple_prpl_got_user_status(account,name,"offline",NULL);
				}
			}
#else
			ZRequestLocations(chk, &ald, UNACKED, ZAUTH);
			g_free(ald.user);
			g_free(ald.version);
#endif /* WIN32 */
		} else
			if (use_tzc(zephyr)) {
				gchar *zlocstr = g_strdup_printf("((tzcfodder . zlocate) \"%s\")\n",chk);
				size_t len = strlen(zlocstr);
				size_t result = write(zephyr->totzc[ZEPHYR_FD_WRITE],zlocstr,len);
				if (result != len) {
					purple_debug_error("zephyr", "Unable to write a message: %s\n", g_strerror(errno));
				}
				g_free(zlocstr);
			}
	}

	return TRUE;
}

#endif /* WIN32 */

static char *get_exposure_level(void)
{
	/* XXX add real error reporting */
	char *exposure = ZGetVariable("exposure");

	if (!exposure)
		return EXPOSE_REALMVIS;
	if (!g_ascii_strcasecmp(exposure, EXPOSE_NONE))
		return EXPOSE_NONE;
	if (!g_ascii_strcasecmp(exposure, EXPOSE_OPSTAFF))
		return EXPOSE_OPSTAFF;
	if (!g_ascii_strcasecmp(exposure, EXPOSE_REALMANN))
		return EXPOSE_REALMANN;
	if (!g_ascii_strcasecmp(exposure, EXPOSE_NETVIS))
		return EXPOSE_NETVIS;
	if (!g_ascii_strcasecmp(exposure, EXPOSE_NETANN))
		return EXPOSE_NETANN;
	return EXPOSE_REALMVIS;
}

static void strip_comments(char *str)
{
	char *tmp = strchr(str, '#');

	if (tmp)
		*tmp = '\0';
	g_strchug(str);
	g_strchomp(str);
}

static void zephyr_inithosts(zephyr_account *zephyr)
{
	/* XXX This code may not be Win32 clean */
	struct hostent *hent;

	if (gethostname(zephyr->ourhost, sizeof(zephyr->ourhost)) == -1) {
		purple_debug_error("zephyr", "unable to retrieve hostname, %%host%% and %%canon%% will be wrong in subscriptions and have been set to unknown\n");
		g_strlcpy(zephyr->ourhost, "unknown", sizeof(zephyr->ourhost));
		g_strlcpy(zephyr->ourhostcanon, "unknown", sizeof(zephyr->ourhostcanon));
		return;
	}

	if (!(hent = gethostbyname(zephyr->ourhost))) {
		purple_debug_error("zephyr", "unable to resolve hostname, %%canon%% will be wrong in subscriptions.and has been set to the value of %%host%%, %s\n",zephyr->ourhost);
		g_strlcpy(zephyr->ourhostcanon, zephyr->ourhost, sizeof(zephyr->ourhostcanon));
		return;
	}

	g_strlcpy(zephyr->ourhostcanon, hent->h_name, sizeof(zephyr->ourhostcanon));

	return;
}

static void process_zsubs(zephyr_account *zephyr)
{
	/* Loads zephyr chats "(subscriptions) from ~/.zephyr.subs, and
	   registers (subscribes to) them on the server */

	/* XXX deal with unsubscriptions */
	/* XXX deal with punts */

	FILE *f;
	gchar *fname;
	gchar buff[BUFSIZ];

	fname = g_strdup_printf("%s/.zephyr.subs", purple_home_dir());
	f = g_fopen(fname, "r");
	if (f) {
		char **triple;
		char *recip;
		char *z_class;
		char *z_instance;
		char *z_galaxy = NULL;

		while (fgets(buff, BUFSIZ, f)) {
			strip_comments(buff);
			if (buff[0]) {
				triple = g_strsplit(buff, ",", 3);
				if (triple[0] && triple[1]) {
					char *tmp = g_strdup_printf("%s", zephyr->username);
					char *atptr;

					z_class = triple[0];
					z_instance = triple[1];
					if (triple[2] == NULL) {
						recip = g_malloc0(1);
					} else if (!g_ascii_strcasecmp(triple[2], "%me%")) {
						recip = g_strdup_printf("%s", zephyr->username);
					} else if (!g_ascii_strcasecmp(triple[2], "*")) {
						/* wildcard
						 * form of class,instance,* */
						recip = g_malloc0(1);
					} else if (!g_ascii_strcasecmp(triple[2], tmp)) {
						/* form of class,instance,aatharuv@ATHENA.MIT.EDU */
						recip = g_strdup(triple[2]);
					} else if ((atptr = strchr(triple[2], '@')) != NULL) {
						/* form of class,instance,*@ANDREW.CMU.EDU
						 * class,instance,@ANDREW.CMU.EDU
						 * If realm is local realm, blank recipient, else
						 * @REALM-NAME
						 */
						char *realmat = g_strdup_printf("@%s",zephyr->realm);

						if (!g_ascii_strcasecmp(atptr, realmat))
							recip = g_malloc0(1);
						else
							recip = g_strdup(atptr);
						g_free(realmat);
					} else {
						recip = g_strdup(triple[2]);
					}
					g_free(tmp);

					if (!g_ascii_strcasecmp(triple[0],"%host%")) {
						z_class = g_strdup(zephyr->ourhost);
					} else if (!g_ascii_strcasecmp(triple[0],"%canon%")) {
						z_class = g_strdup(zephyr->ourhostcanon);
					} else {
						z_class = g_strdup(triple[0]);
					}

					if (!g_ascii_strcasecmp(triple[1],"%host%")) {
						z_instance = g_strdup(zephyr->ourhost);
					} else if (!g_ascii_strcasecmp(triple[1],"%canon%")) {
						z_instance = g_strdup(zephyr->ourhostcanon);
					} else {
						z_instance = g_strdup(triple[1]);
					}

					/* There should be some sort of error report listing classes that couldn't be subbed to.
					   Not important right now though */

					if (zephyr_subscribe_to(zephyr,z_class, z_instance, recip,z_galaxy) != ZERR_NONE) {

						purple_debug_error("zephyr", "Couldn't subscribe to %s, %s, %s\n", z_class,z_instance,recip);
					}

					zephyr->subscrips = g_slist_append(zephyr->subscrips, new_triple(zephyr,z_class,z_instance,recip));
					/*					  g_hash_table_destroy(sub_hash_table); */
					g_free(z_instance);
					g_free(z_class);
					g_free(recip);
				}
				g_strfreev(triple);
			}
		}
		fclose(f);
	}
}

static void process_anyone(PurpleConnection *gc)
{
	zephyr_account *zephyr = purple_connection_get_protocol_data(gc);
	FILE *fd;
	gchar buff[BUFSIZ], *filename;
	PurpleGroup *g;
	PurpleBuddy *b;

	if (!(g = purple_find_group(_("Anyone")))) {
		g = purple_group_new(_("Anyone"));
		purple_blist_add_group(g, NULL);
	}

	filename = g_strconcat(purple_home_dir(), "/.anyone", NULL);
	if ((fd = g_fopen(filename, "r")) != NULL) {
		while (fgets(buff, BUFSIZ, fd)) {
			strip_comments(buff);
			if (buff[0]) {
				if (!purple_find_buddy(gc->account, buff)) {
					char *stripped_user = zephyr_strip_local_realm(zephyr,buff);
					purple_debug_info("zephyr","stripped_user %s\n",stripped_user);
					if (!purple_find_buddy(gc->account,stripped_user)){
						b = purple_buddy_new(gc->account, stripped_user, NULL);
						purple_blist_add_buddy(b, NULL, g, NULL);
					}
					g_free(stripped_user);
				}
			}
		}
		fclose(fd);
	}
	g_free(filename);
}

static char* normalize_zephyr_exposure(const char* exposure) {
	char *exp2 = g_strstrip(g_ascii_strup(exposure,-1));

	if (!exp2)
		return EXPOSE_REALMVIS;
	if (!g_ascii_strcasecmp(exp2, EXPOSE_NONE))
		return EXPOSE_NONE;
	if (!g_ascii_strcasecmp(exp2, EXPOSE_OPSTAFF))
		return EXPOSE_OPSTAFF;
	if (!g_ascii_strcasecmp(exp2, EXPOSE_REALMANN))
		return EXPOSE_REALMANN;
	if (!g_ascii_strcasecmp(exp2, EXPOSE_NETVIS))
		return EXPOSE_NETVIS;
	if (!g_ascii_strcasecmp(exp2, EXPOSE_NETANN))
		return EXPOSE_NETANN;
	return EXPOSE_REALMVIS;
}

static void zephyr_login(PurpleAccount * account)
{
	PurpleConnection *gc;
	zephyr_account *zephyr;
	gboolean read_anyone;
	gboolean read_zsubs;
	gchar *exposure;

	gc = purple_account_get_connection(account);
	read_anyone = purple_account_get_bool(gc->account,"read_anyone",TRUE);
	read_zsubs = purple_account_get_bool(gc->account,"read_zsubs",TRUE);
	exposure = (gchar *)purple_account_get_string(gc->account, "exposure_level", EXPOSE_REALMVIS);

#ifdef WIN32
	username = purple_account_get_username(account);
#endif
	gc->flags |= PURPLE_CONNECTION_AUTO_RESP | PURPLE_CONNECTION_HTML | PURPLE_CONNECTION_NO_BGCOLOR | PURPLE_CONNECTION_NO_URLDESC;
	gc->proto_data = zephyr=g_new0(zephyr_account,1);

	zephyr->account = account;

	/* Make sure that the exposure (visibility) is set to a sane value */
	zephyr->exposure=g_strdup(normalize_zephyr_exposure(exposure));

	if (purple_account_get_bool(gc->account,"use_tzc",0)) {
		zephyr->connection_type = PURPLE_ZEPHYR_TZC;
	} else {
		zephyr->connection_type = PURPLE_ZEPHYR_KRB4;
	}

	zephyr->encoding = (char *)purple_account_get_string(gc->account, "encoding", ZEPHYR_FALLBACK_CHARSET);
	purple_connection_update_progress(gc, _("Connecting"), 0, 8);

	/* XXX z_call_s should actually try to report the com_err determined error */
	if (use_tzc(zephyr)) {
		pid_t pid;
		/*		  purple_connection_error(gc,"tzc not supported yet"); */
		if ((pipe(zephyr->totzc) != 0) || (pipe(zephyr->fromtzc) != 0)) {
			purple_debug_error("zephyr", "pipe creation failed. killing\n");
			exit(-1);
		}

		pid = fork();

		if (pid == -1) {
			purple_debug_error("zephyr", "forking failed\n");
			exit(-1);
		}
		if (pid == 0) {
			unsigned int i=0;
			gboolean found_ps = FALSE;
			gchar ** tzc_cmd_array = g_strsplit(purple_account_get_string(gc->account,"tzc_command","/usr/bin/tzc -e %s")," ",0);
			if (close(1) == -1) {
				exit(-1);
			}
			if (dup2(zephyr->fromtzc[1], 1) == -1) {
				exit(-1);
			}
			if (close(zephyr->fromtzc[1]) == -1) {
				exit(-1);
			}
			if (close(0) == -1) {
				exit(-1);
			}
			if (dup2(zephyr->totzc[0], 0) == -1) {
				exit(-1);
			}
			if (close(zephyr->totzc[0]) == -1) {
				exit(-1);
			}
			/* tzc_command should really be of the form
			   path/to/tzc -e %s
			   or
			   ssh username@hostname pathtotzc -e %s
			   -- this should not require a password, and ideally should be kerberized ssh --
			   or
			   fsh username@hostname pathtotzc -e %s
			*/
			while(tzc_cmd_array[i] != NULL){
				if (!g_ascii_strncasecmp(tzc_cmd_array[i],"%s",2)) {
					/*					fprintf(stderr,"replacing %%s with %s\n",zephyr->exposure); */
					tzc_cmd_array[i] = g_strdup(zephyr->exposure);
					found_ps = TRUE;

				} else {
					/*					fprintf(stderr,"keeping %s\n",tzc_cmd_array[i]); */
				}
				i++;
			}

			if (!found_ps) {
				exit(-1);
			}

			execvp(tzc_cmd_array[0], tzc_cmd_array);
			exit(-1);
		}
		else {
			fd_set rfds;
			int bufsize = 2048;
			char *buf = (char *)calloc(bufsize, 1);
			char *bufcur = buf;
			struct timeval tv;
			char *ptr;
			int parenlevel=0;
			char* tempstr;
			int tempstridx;
			int select_status;

			zephyr->tzc_pid = pid;
			/* wait till we have data to read from ssh */
			FD_ZERO(&rfds);
			FD_SET(zephyr->fromtzc[ZEPHYR_FD_READ], &rfds);

			tv.tv_sec = 10;
			tv.tv_usec = 0;

			purple_debug_info("zephyr", "about to read from tzc\n");

			if (waitpid(pid, NULL, WNOHANG) == 0) { /* Only select if tzc is still running */
				purple_debug_info("zephyr", "about to read from tzc\n");
				select_status = select(zephyr->fromtzc[ZEPHYR_FD_READ] + 1, &rfds, NULL, NULL, NULL);
			}
			else {
				purple_debug_info("zephyr", "tzc exited early\n");
				select_status = -1;
			}

			FD_ZERO(&rfds);
			FD_SET(zephyr->fromtzc[ZEPHYR_FD_READ], &rfds);
			while (select_status > 0 &&
			       select(zephyr->fromtzc[ZEPHYR_FD_READ] + 1, &rfds, NULL, NULL, &tv) > 0) {
				read(zephyr->fromtzc[ZEPHYR_FD_READ], bufcur, 1);
				bufcur++;
				if ((bufcur - buf) > (bufsize - 1)) {
					if ((buf = realloc(buf, bufsize * 2)) == NULL) {
						exit(-1);
					} else {
						bufcur = buf + bufsize;
						bufsize *= 2;
					}
				}
				FD_ZERO(&rfds);
				FD_SET(zephyr->fromtzc[ZEPHYR_FD_READ], &rfds);
				tv.tv_sec = 10;
				tv.tv_usec = 0;

			}
			/*			  fprintf(stderr, "read from tzc\n"); */
			*bufcur = '\0';
			ptr = buf;

			/* ignore all tzcoutput till we've received the first (*/
			while (ptr < bufcur && (*ptr !='(')) {
				ptr++;
			}
			if (ptr >=bufcur) {
				purple_connection_error(gc,"invalid output by tzc (or bad parsing code)");
				free(buf);
				return;
			}

			while(ptr < bufcur) {
				if (*ptr == '(') {
					parenlevel++;
				}
				else if (*ptr == ')') {
					parenlevel--;
				}
				purple_debug_info("zephyr","tzc parenlevel is %d\n",parenlevel);
				switch (parenlevel) {
				case 0:
					break;
				case 1:
					/* Search for next beginning (, or for the ending */
					ptr++;
					while((*ptr != '(') && (*ptr != ')') && (ptr <bufcur))
						ptr++;
					if (ptr >= bufcur)
						purple_debug_error("zephyr","tzc parsing error\n");
					break;
				case 2:
					/* You are probably at
					   (foo . bar ) or (foo . "bar") or (foo . chars) or (foo . numbers) or (foo . () )
					   Parse all the data between the first and last f, and move past )
					*/
					tempstr = g_malloc0(20000);
					tempstridx=0;
					while(parenlevel >1) {
						ptr++;
						if (*ptr == '(')
							parenlevel++;
						if (*ptr == ')')
							parenlevel--;
						if (parenlevel > 1) {
							tempstr[tempstridx++]=*ptr;
						} else {
							ptr++;
						}
					}
					purple_debug_info("zephyr","tempstr parsed\n");
					/* tempstr should now be a tempstridx length string containing all characters
					   from that after the first ( to the one before the last paren ). */
					/* We should have the following possible lisp strings but we don't care
					   (tzcspew . start) (version . "something") (pid . number)*/
					/* We care about 'zephyrid . "username@REALM.NAME"' and 'exposure . "SOMETHING"' */
					tempstridx=0;
					if (!g_ascii_strncasecmp(tempstr,"zephyrid",8)) {
						gchar* username = g_malloc0(100);
						int username_idx=0;
						char *realm;
						purple_debug_info("zephyr","zephyrid found\n");
						tempstridx+=8;
						while(tempstr[tempstridx] !='"' && tempstridx < 20000)
							tempstridx++;
						tempstridx++;
						while(tempstr[tempstridx] !='"' && tempstridx < 20000)
							username[username_idx++]=tempstr[tempstridx++];

						zephyr->username = g_strdup_printf("%s",username);
						if ((realm = strchr(username,'@')))
							zephyr->realm = g_strdup_printf("%s",realm+1);
						else {
							realm = (gchar *)purple_account_get_string(gc->account,"realm","");
							if (!*realm) {
								realm = "local-realm";
							}
							zephyr->realm = g_strdup(realm);
							g_strlcpy(__Zephyr_realm, (const char*)zephyr->realm, REALM_SZ-1);
						}
						/* else {
						   zephyr->realm = g_strdup("local-realm");
						   }*/

						g_free(username);
					}  else {
						purple_debug_info("zephyr", "something that's not zephyr id found %s\n",tempstr);
					}

					/* We don't care about anything else yet */
					g_free(tempstr);
					break;
				default:
					purple_debug_info("zephyr","parenlevel is not 1 or 2\n");
					/* This shouldn't be happening */
					break;
				}
				if (parenlevel==0)
					break;
			} /* while (ptr < bufcur) */
			purple_debug_info("zephyr", "tzc startup done\n");
		free(buf);
		}
	}
	else if ( use_zeph02(zephyr)) {
		gchar* realm;
		z_call_s(ZInitialize(), "Couldn't initialize zephyr");
		z_call_s(ZOpenPort(&(zephyr->port)), "Couldn't open port");
		z_call_s(ZSetLocation((char *)zephyr->exposure), "Couldn't set location");

		realm = (gchar *)purple_account_get_string(gc->account,"realm","");
		if (!*realm) {
			realm = ZGetRealm();
		}
		zephyr->realm = g_strdup(realm);
		g_strlcpy(__Zephyr_realm, (const char*)zephyr->realm, REALM_SZ-1);
		zephyr->username = g_strdup(ZGetSender());

		/*		zephyr->realm = g_strdup(ZGetRealm()); */
		purple_debug_info("zephyr","realm: %s\n",zephyr->realm);
	}
	else {
		purple_connection_error(gc,"Only ZEPH0.2 supported currently");
		return;
	}
	purple_debug_info("zephyr","does it get here\n");
	purple_debug_info("zephyr"," realm: %s username:%s\n", zephyr->realm, zephyr->username);

	/* For now */
	zephyr->galaxy = NULL;
	zephyr->krbtkfile = NULL;
	zephyr_inithosts(zephyr);

	if (zephyr_subscribe_to(zephyr,"MESSAGE","PERSONAL",zephyr->username,NULL) != ZERR_NONE) {
		/* XXX don't translate this yet. It could be written better */
		/* XXX error messages could be handled with more detail */
		purple_notify_error(account->gc, NULL,
				  "Unable to subscribe to messages", "Unable to subscribe to initial messages");
		return;
	}

	purple_connection_set_state(gc, PURPLE_CONNECTED);

	if (read_anyone)
		process_anyone(gc);
	if (read_zsubs)
		process_zsubs(zephyr);

	if (use_zeph02(zephyr)) {
		zephyr->nottimer = purple_timeout_add(100, check_notify_zeph02, gc);
	} else if (use_tzc(zephyr)) {
		zephyr->nottimer = purple_timeout_add(100, check_notify_tzc, gc);
	}
	zephyr->loctimer = purple_timeout_add_seconds(20, check_loc, gc);

}

static void write_zsubs(zephyr_account *zephyr)
{
	/* Exports subscription (chat) list back to
	 * .zephyr.subs
	 * XXX deal with %host%, %canon%, unsubscriptions, and negative subscriptions (punts?)
	 */

	GSList *s = zephyr->subscrips;
	zephyr_triple *zt;
	FILE *fd;
	char *fname;

	char **triple;

	fname = g_strdup_printf("%s/.zephyr.subs", purple_home_dir());
	fd = g_fopen(fname, "w");

	if (!fd) {
		g_free(fname);
		return;
	}

	while (s) {
		char *zclass, *zinst, *zrecip;
		zt = s->data;
		triple = g_strsplit(zt->name, ",", 3);

		/* deal with classes */
		if (!g_ascii_strcasecmp(triple[0],zephyr->ourhost)) {
			zclass = g_strdup("%host%");
		} else if (!g_ascii_strcasecmp(triple[0],zephyr->ourhostcanon)) {
			zclass = g_strdup("%canon%");
		} else {
			zclass = g_strdup(triple[0]);
		}

		/* deal with instances */

		if (!g_ascii_strcasecmp(triple[1],zephyr->ourhost)) {
			zinst = g_strdup("%host%");
		} else if (!g_ascii_strcasecmp(triple[1],zephyr->ourhostcanon)) {
			zinst = g_strdup("%canon%");;
		} else {
			zinst = g_strdup(triple[1]);
		}

		/* deal with recipients */
		if (triple[2] == NULL) {
			zrecip = g_strdup("*");
		} else if (!g_ascii_strcasecmp(triple[2],"")){
			zrecip = g_strdup("*");
		} else if (!g_ascii_strcasecmp(triple[2], zephyr->username)) {
			zrecip = g_strdup("%me%");
		} else {
			zrecip = g_strdup(triple[2]);
		}

		fprintf(fd, "%s,%s,%s\n",zclass,zinst,zrecip);

		g_free(zclass);
		g_free(zinst);
		g_free(zrecip);
		g_free(triple);
		s = s->next;
	}
	g_free(fname);
	fclose(fd);
}

static void write_anyone(zephyr_account *zephyr)
{
	GSList *buddies;
	char *fname;
	FILE *fd;
	PurpleAccount *account;
	fname = g_strdup_printf("%s/.anyone", purple_home_dir());
	fd = g_fopen(fname, "w");
	if (!fd) {
		g_free(fname);
		return;
	}

	account = zephyr->account;
	for (buddies = purple_find_buddies(account, NULL); buddies;
			buddies = g_slist_delete_link(buddies, buddies)) {
		PurpleBuddy *b = buddies->data;
		gchar *stripped_user = zephyr_strip_local_realm(zephyr, purple_buddy_get_name(b));
		fprintf(fd, "%s\n", stripped_user);
		g_free(stripped_user);
	}

	fclose(fd);
	g_free(fname);
}

static void zephyr_close(PurpleConnection * gc)
{
	GList *l;
	GSList *s;
	zephyr_account *zephyr = gc->proto_data;
	pid_t tzc_pid = zephyr->tzc_pid;

	l = zephyr->pending_zloc_names;
	while (l) {
		g_free((char *)l->data);
		l = l->next;
	}
	g_list_free(zephyr->pending_zloc_names);

	if (purple_account_get_bool(gc->account, "write_anyone", FALSE))
		write_anyone(zephyr);

	if (purple_account_get_bool(gc->account, "write_zsubs", FALSE))
		write_zsubs(zephyr);

	s = zephyr->subscrips;
	while (s) {
		free_triple((zephyr_triple *) s->data);
		s = s->next;
	}
	g_slist_free(zephyr->subscrips);

	if (zephyr->nottimer)
		purple_timeout_remove(zephyr->nottimer);
	zephyr->nottimer = 0;
	if (zephyr->loctimer)
		purple_timeout_remove(zephyr->loctimer);
	zephyr->loctimer = 0;
	gc = NULL;
	if (use_zeph02(zephyr)) {
		z_call(ZCancelSubscriptions(0));
		z_call(ZUnsetLocation());
		z_call(ZClosePort());
	} else {
		/* assume tzc */
		if (kill(tzc_pid,SIGTERM) == -1) {
			int err=errno;
			if (err==EINVAL) {
				purple_debug_error("zephyr","An invalid signal was specified when killing tzc\n");
			}
			else if (err==ESRCH) {
				purple_debug_error("zephyr","Tzc's pid didn't exist while killing tzc\n");
			}
			else if (err==EPERM) {
				purple_debug_error("zephyr","purple didn't have permission to kill tzc\n");
			}
			else {
				purple_debug_error("zephyr","miscellaneous error while attempting to close tzc\n");
			}
		}
	}
}

static int zephyr_send_message(zephyr_account *zephyr,char* zclass, char* instance, char* recipient, const char *im,
			       const char *sig, char *opcode) ;

static const char * zephyr_get_signature(void)
{
	/* XXX add zephyr error reporting */
	const char * sig =ZGetVariable("zwrite-signature");
	if (!sig) {
		sig = g_get_real_name();
	}
	return sig;
}

static int zephyr_chat_send(PurpleConnection * gc, int id, const char *im, PurpleMessageFlags flags)
{
	zephyr_triple *zt;
	const char *sig;
	PurpleConversation *gconv1;
	PurpleConvChat *gcc;
	char *inst;
	char *recipient;
	zephyr_account *zephyr = gc->proto_data;

	zt = find_sub_by_id(zephyr,id);
	if (!zt)
		/* this should never happen. */
		return -EINVAL;

	sig = zephyr_get_signature();

	gconv1 = purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT, zt->name,
												 gc->account);
	gcc = purple_conversation_get_chat_data(gconv1);

	if (!(inst = (char *)purple_conv_chat_get_topic(gcc)))
		inst = g_strdup("PERSONAL");

	if (!g_ascii_strcasecmp(zt->recipient, "*"))
		recipient = local_zephyr_normalize(zephyr,"");
	else
		recipient = local_zephyr_normalize(zephyr,zt->recipient);

	zephyr_send_message(zephyr,zt->class,inst,recipient,im,sig,"");
	return 0;
}


static int zephyr_send_im(PurpleConnection * gc, const char *who, const char *im, PurpleMessageFlags flags)
{
	const char *sig;
	zephyr_account *zephyr = gc->proto_data;
	if (flags & PURPLE_MESSAGE_AUTO_RESP)
		sig = "Automated reply:";
	else {
		sig = zephyr_get_signature();
	}
	zephyr_send_message(zephyr,"MESSAGE","PERSONAL",local_zephyr_normalize(zephyr,who),im,sig,"");

	return 1;
}

/* Munge the outgoing zephyr so that any quotes or backslashes are
   escaped and do not confuse tzc: */

static char* zephyr_tzc_escape_msg(const char *message)
{
	int pos = 0;
	int pos2 = 0;
	char *newmsg;

	if (message && (strlen(message) > 0)) {
		newmsg = g_new0(char,1+strlen(message)*2);
		while(pos < strlen(message)) {
			if (message[pos]=='\\') {
				newmsg[pos2]='\\';
				newmsg[pos2+1]='\\';
				pos2+=2;
			}
			else if (message[pos]=='"') {
				newmsg[pos2]='\\';
				newmsg[pos2+1]='"';
				pos2+=2;
			}
			else {
				newmsg[pos2] = message[pos];
				pos2++;
			}
			pos++;
		}
	} else {
		newmsg = g_strdup("");
	}
	/*	fprintf(stderr,"newmsg %s message %s\n",newmsg,message); */
	return newmsg;
}

char* zephyr_tzc_deescape_str(const char *message)
{
	int pos = 0;
	int pos2 = 0;
	char *newmsg;

	if (message && (strlen(message) > 0)) {
		newmsg = g_new0(char,strlen(message)+1);
		while(pos < strlen(message)) {
			if (message[pos]=='\\') {
				pos++;
			}
			newmsg[pos2] = message[pos];
			pos++;pos2++;
		}
		newmsg[pos2]='\0';
	} else {
		newmsg = g_strdup("");
	}

	return newmsg;
}

static int zephyr_send_message(zephyr_account *zephyr,char* zclass, char* instance, char* recipient, const char *im,
			       const char *sig, char *opcode)
{

	/* (From the tzc source)
	 * emacs sends something of the form:
	 * ((class . "MESSAGE")
	 *  (auth . t)
	 *  (recipients ("PERSONAL" . "bovik") ("test" . ""))
	 *  (sender . "bovik")
	 *  (message . ("Harry Bovik" "my zgram"))
	 * )
	 */
	char *html_buf;
	char *html_buf2;
	html_buf = html_to_zephyr(im);
	html_buf2 = purple_unescape_html(html_buf);

	if(use_tzc(zephyr)) {
		size_t len;
		size_t result;
		char* zsendstr;
		/* CMU cclub tzc doesn't grok opcodes for now  */
		char* tzc_sig = zephyr_tzc_escape_msg(sig);
		char *tzc_body = zephyr_tzc_escape_msg(html_buf2);
		zsendstr = g_strdup_printf("((tzcfodder . send) (class . \"%s\") (auth . t) (recipients (\"%s\" . \"%s\")) (message . (\"%s\" \"%s\"))	) \n",
					   zclass, instance, recipient, tzc_sig, tzc_body);
		/*		fprintf(stderr,"zsendstr = %s\n",zsendstr); */
		len = strlen(zsendstr);
		result = write(zephyr->totzc[ZEPHYR_FD_WRITE], zsendstr, len);
		if (result != len) {
			g_free(zsendstr);
			g_free(html_buf2);
			g_free(html_buf);
			return errno;
		}
		g_free(zsendstr);
	} else if (use_zeph02(zephyr)) {
		ZNotice_t notice;
		char *buf = g_strdup_printf("%s%c%s", sig, '\0', html_buf2);
		memset((char *)&notice, 0, sizeof(notice));

		notice.z_kind = ACKED;
		notice.z_port = 0;
		notice.z_opcode = "";
		notice.z_class = zclass;
		notice.z_class_inst = instance;
		notice.z_recipient = recipient;
		notice.z_sender = 0;
		notice.z_default_format = "Class $class, Instance $instance:\n" "To: @bold($recipient) at $time $date\n" "From: @bold($1) <$sender>\n\n$2";
		notice.z_message_len = strlen(html_buf2) + strlen(sig) + 2;
		notice.z_message = buf;
		notice.z_opcode = g_strdup(opcode);
		purple_debug_info("zephyr","About to send notice\n");
		if (! ZSendNotice(&notice, ZAUTH) == ZERR_NONE) {
			/* XXX handle errors here */
			g_free(buf);
			g_free(html_buf2);
			g_free(html_buf);
			return 0;
		}
		purple_debug_info("zephyr","notice sent\n");
		g_free(buf);
	}

	g_free(html_buf2);
	g_free(html_buf);

	return 1;
}

char *local_zephyr_normalize(zephyr_account *zephyr,const char *orig)
{
	/*
	   Basically the inverse of zephyr_strip_local_realm
	*/
	char* buf;

	if (!g_ascii_strcasecmp(orig, "")) {
		return g_strdup("");
	}

	if (strchr(orig,'@')) {
		buf = g_strdup_printf("%s",orig);
	} else {
		buf = g_strdup_printf("%s@%s",orig,zephyr->realm);
	}
	return buf;
}

static const char *zephyr_normalize(const PurpleAccount *account, const char *who)
{
	static char buf[BUF_LEN];
	PurpleConnection *gc;
	char *tmp;

	gc = purple_account_get_connection(account);
	if (gc == NULL)
		return NULL;

	tmp = local_zephyr_normalize(gc->proto_data, who);

	if (strlen(tmp) >= sizeof(buf)) {
		g_free(tmp);
		return NULL;
	}

	g_strlcpy(buf, tmp, sizeof(buf));
	g_free(tmp);

	return buf;
}

static void zephyr_zloc(PurpleConnection *gc, const char *who)
{
	ZAsyncLocateData_t ald;
	zephyr_account *zephyr = gc->proto_data;
	gchar* normalized_who = local_zephyr_normalize(zephyr,who);

	if (use_zeph02(zephyr)) {
		if (ZRequestLocations(normalized_who, &ald, UNACKED, ZAUTH) == ZERR_NONE) {
			zephyr->pending_zloc_names = g_list_append(zephyr->pending_zloc_names,
								   g_strdup(normalized_who));
		} else {
			/* XXX deal with errors somehow */
		}
	} else if (use_tzc(zephyr)) {
		size_t len;
		size_t result;
		char* zlocstr = g_strdup_printf("((tzcfodder . zlocate) \"%s\")\n",normalized_who);
		zephyr->pending_zloc_names = g_list_append(zephyr->pending_zloc_names, g_strdup(normalized_who));
		len = strlen(zlocstr);
		result = write(zephyr->totzc[ZEPHYR_FD_WRITE],zlocstr,len);
		if (result != len) {
			purple_debug_error("zephyr", "Unable to write a message: %s\n", g_strerror(errno));
		}
		g_free(zlocstr);
	}
}

static void zephyr_set_status(PurpleAccount *account, PurpleStatus *status) {
	size_t len;
	size_t result;
	zephyr_account *zephyr = purple_account_get_connection(account)->proto_data;
	PurpleStatusPrimitive primitive = purple_status_type_get_primitive(purple_status_get_type(status));

	if (zephyr->away) {
		g_free(zephyr->away);
		zephyr->away=NULL;
	}

	if (primitive == PURPLE_STATUS_AWAY) {
		zephyr->away = g_strdup(purple_status_get_attr_string(status,"message"));
	}
	else if (primitive == PURPLE_STATUS_AVAILABLE) {
		if (use_zeph02(zephyr)) {
			ZSetLocation(zephyr->exposure);
		}
		else {
			char *zexpstr = g_strdup_printf("((tzcfodder . set-location) (hostname . \"%s\") (exposure . \"%s\"))\n",zephyr->ourhost,zephyr->exposure);
			len = strlen(zexpstr);
			result = write(zephyr->totzc[ZEPHYR_FD_WRITE],zexpstr,len);
			if (result != len) {
				purple_debug_error("zephyr", "Unable to write message: %s\n", g_strerror(errno));
			}
			g_free(zexpstr);
		}
	}
	else if (primitive == PURPLE_STATUS_INVISIBLE) {
		/* XXX handle errors */
		if (use_zeph02(zephyr)) {
			ZSetLocation(EXPOSE_OPSTAFF);
		} else {
			char *zexpstr = g_strdup_printf("((tzcfodder . set-location) (hostname . \"%s\") (exposure . \"%s\"))\n",zephyr->ourhost,EXPOSE_OPSTAFF);
			len = strlen(zexpstr);
			result = write(zephyr->totzc[ZEPHYR_FD_WRITE],zexpstr,len);
			if (result != len) {
				purple_debug_error("zephyr", "Unable to write message: %s\n", g_strerror(errno));
			}
			g_free(zexpstr);
		}
	}
}

static GList *zephyr_status_types(PurpleAccount *account)
{
	PurpleStatusType *type;
	GList *types = NULL;

	/* zephyr has several exposures
	   NONE (where you are hidden, and zephyrs to you are in practice silently dropped -- yes this is wrong)
	   OPSTAFF "hidden"
	   REALM-VISIBLE visible to people in local realm
	   REALM-ANNOUNCED REALM-VISIBLE+ plus your logins/logouts are announced to <login,username,*>
	   NET-VISIBLE REALM-ANNOUNCED, plus visible to people in foreign realm
	   NET-ANNOUNCED NET-VISIBLE, plus logins/logouts are announced	 to <login,username,*>

	   Online will set the user to the exposure they have in their options (defaulting to REALM-VISIBLE),
	   Hidden, will set the user's exposure to OPSTAFF

	   Away won't change their exposure but will set an auto away message (for IMs only)
	*/

	type = purple_status_type_new(PURPLE_STATUS_AVAILABLE, NULL, NULL, TRUE);
	types = g_list_append(types,type);

	type = purple_status_type_new(PURPLE_STATUS_INVISIBLE, NULL, NULL, TRUE);
	types = g_list_append(types,type);

	type = purple_status_type_new_with_attrs(
					       PURPLE_STATUS_AWAY, NULL, NULL, TRUE, TRUE, FALSE,
					       "message", _("Message"), purple_value_new(PURPLE_TYPE_STRING),
					       NULL);
	types = g_list_append(types, type);

	type = purple_status_type_new(PURPLE_STATUS_OFFLINE, NULL, NULL, TRUE);
	types = g_list_append(types,type);

	return types;
}

static GList *zephyr_chat_info(PurpleConnection * gc)
{
	GList *m = NULL;
	struct proto_chat_entry *pce;

	pce = g_new0(struct proto_chat_entry, 1);

	pce->label = _("_Class:");
	pce->identifier = "class";
	m = g_list_append(m, pce);

	pce = g_new0(struct proto_chat_entry, 1);

	pce->label = _("_Instance:");
	pce->identifier = "instance";
	m = g_list_append(m, pce);

	pce = g_new0(struct proto_chat_entry, 1);

	pce->label = _("_Recipient:");
	pce->identifier = "recipient";
	m = g_list_append(m, pce);

	return m;
}

/* Called when the server notifies us a message couldn't get sent */

static void zephyr_subscribe_failed(PurpleConnection *gc,char * z_class, char *z_instance, char * z_recipient, char* z_galaxy)
{
	gchar* subscribe_failed = g_strdup_printf(_("Attempt to subscribe to %s,%s,%s failed"), z_class, z_instance,z_recipient);
	purple_notify_error(gc,"", subscribe_failed, NULL);
	g_free(subscribe_failed);
}

static char *zephyr_get_chat_name(GHashTable *data) {
	gchar* zclass = g_hash_table_lookup(data,"class");
	gchar* inst = g_hash_table_lookup(data,"instance");
	gchar* recipient = g_hash_table_lookup(data, "recipient");
	if (!zclass) /* This should never happen */
		zclass = "";
	if (!inst)
		inst = "*";
	if (!recipient)
		recipient = "";
	return g_strdup_printf("%s,%s,%s",zclass,inst,recipient);
}


static void zephyr_join_chat(PurpleConnection * gc, GHashTable * data)
{
	/*	ZSubscription_t sub; */
	zephyr_triple *zt1, *zt2;
	const char *classname;
	const char *instname;
	const char *recip;
	zephyr_account *zephyr=gc->proto_data;
	classname = g_hash_table_lookup(data, "class");
	instname = g_hash_table_lookup(data, "instance");
	recip = g_hash_table_lookup(data, "recipient");


	if (!classname)
		return;

	if (!g_ascii_strcasecmp(classname,"%host%"))
		classname = g_strdup(zephyr->ourhost);
	if (!g_ascii_strcasecmp(classname,"%canon%"))
		classname = g_strdup(zephyr->ourhostcanon);

	if (!instname || !strlen(instname))
		instname = "*";

	if (!g_ascii_strcasecmp(instname,"%host%"))
		instname = g_strdup(zephyr->ourhost);
	if (!g_ascii_strcasecmp(instname,"%canon%"))
		instname = g_strdup(zephyr->ourhostcanon);

	if (!recip || (*recip == '*'))
		recip = "";
	if (!g_ascii_strcasecmp(recip, "%me%"))
		recip = zephyr->username;

	zt1 = new_triple(zephyr,classname, instname, recip);
	zt2 = find_sub_by_triple(zephyr,zt1);
	if (zt2) {
		free_triple(zt1);
		if (!zt2->open) {
			if (!g_ascii_strcasecmp(instname,"*"))
				instname = "PERSONAL";
			serv_got_joined_chat(gc, zt2->id, zt2->name);
			zephyr_chat_set_topic(gc,zt2->id,instname);
			zt2->open = TRUE;
		}
		return;
	}

	/*	sub.zsub_class = zt1->class;
		sub.zsub_classinst = zt1->instance;
		sub.zsub_recipient = zt1->recipient; */

	if (zephyr_subscribe_to(zephyr,zt1->class,zt1->instance,zt1->recipient,NULL) != ZERR_NONE) {
		/* XXX output better subscription information */
		zephyr_subscribe_failed(gc,zt1->class,zt1->instance,zt1->recipient,NULL);
		free_triple(zt1);
		return;
	}

	zephyr->subscrips = g_slist_append(zephyr->subscrips, zt1);
	zt1->open = TRUE;
	serv_got_joined_chat(gc, zt1->id, zt1->name);
	if (!g_ascii_strcasecmp(instname,"*"))
		instname = "PERSONAL";
	zephyr_chat_set_topic(gc,zt1->id,instname);
}

static void zephyr_chat_leave(PurpleConnection * gc, int id)
{
	zephyr_triple *zt;
	zephyr_account *zephyr = gc->proto_data;
	zt = find_sub_by_id(zephyr,id);

	if (zt) {
		zt->open = FALSE;
		zt->id = ++(zephyr->last_id);
	}
}

static PurpleChat *zephyr_find_blist_chat(PurpleAccount *account, const char *name)
{
	PurpleBlistNode *gnode, *cnode;

	/* XXX needs to be %host%,%canon%, and %me% clean */
	for(gnode = purple_blist_get_root(); gnode;
			gnode = purple_blist_node_get_sibling_next(gnode)) {
		for(cnode = purple_blist_node_get_first_child(gnode);
				cnode;
				cnode = purple_blist_node_get_sibling_next(cnode)) {
			PurpleChat *chat = (PurpleChat*)cnode;
			char *zclass, *inst, *recip;
			char** triple;
			GHashTable *components;
			if(!PURPLE_BLIST_NODE_IS_CHAT(cnode))
				continue;
			if(purple_chat_get_account(chat) != account)
				continue;
			components = purple_chat_get_components(chat);
			if(!(zclass = g_hash_table_lookup(components, "class")))
				continue;
			if(!(inst = g_hash_table_lookup(components, "instance")))
				inst = g_strdup("");
			if(!(recip = g_hash_table_lookup(components, "recipient")))
				recip = g_strdup("");
			/*			purple_debug_info("zephyr","in zephyr_find_blist_chat name: %s\n",name?name:""); */
			triple = g_strsplit(name,",",3);
			if (!g_ascii_strcasecmp(triple[0],zclass) && !g_ascii_strcasecmp(triple[1],inst) && !g_ascii_strcasecmp(triple[2],recip))
				return chat;

		}
	}
	return NULL;
}
static const char *zephyr_list_icon(PurpleAccount * a, PurpleBuddy * b)
{
	return "zephyr";
}

static unsigned int zephyr_send_typing(PurpleConnection *gc, const char *who, PurpleTypingState state) {
	gchar *recipient;
	zephyr_account *zephyr = gc->proto_data;
	if (use_tzc(zephyr))
		return 0;

	if (state == PURPLE_NOT_TYPING)
		return 0;

	/* XXX We probably should care if this fails. Or maybe we don't want to */
	if (!who) {
		purple_debug_info("zephyr", "who is null\n");
		recipient = local_zephyr_normalize(zephyr,"");
	} else {
		char *comma = strrchr(who, ',');
		/* Don't ping broadcast (chat) recipients */
		/* The strrchr case finds a realm-stripped broadcast subscription
		   e.g. comma is the last character in the string */
		if (comma && ( (*(comma+1) == '\0') || (*(comma+1) == '@')))
			return 0;

		recipient = local_zephyr_normalize(zephyr,who);
	}

	purple_debug_info("zephyr","about to send typing notification to %s\n",recipient);
	zephyr_send_message(zephyr,"MESSAGE","PERSONAL",recipient,"","","PING");
	purple_debug_info("zephyr","sent typing notification\n");

	/*
	 * TODO: Is this correct?  It means we will call
	 *       serv_send_typing(gc, who, PURPLE_TYPING) once every 15 seconds
	 *       until the Purple user stops typing.
	 */
	return ZEPHYR_TYPING_SEND_TIMEOUT;
}



static void zephyr_chat_set_topic(PurpleConnection * gc, int id, const char *topic)
{
	zephyr_triple *zt;
	PurpleConversation *gconv;
	PurpleConvChat *gcc;
	gchar *topic_utf8;
	zephyr_account* zephyr = gc->proto_data;
	char *sender = (char *)zephyr->username;

	zt = find_sub_by_id(zephyr,id);
	/* find_sub_by_id can return NULL */
	if (!zt)
		return;
	gconv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT, zt->name,
												gc->account);
	gcc = purple_conversation_get_chat_data(gconv);

	topic_utf8 = zephyr_recv_convert(gc,(gchar *)topic);
	purple_conv_chat_set_topic(gcc,sender,topic_utf8);
	g_free(topic_utf8);
	return;
}

/*  commands */

static PurpleCmdRet zephyr_purple_cmd_msg(PurpleConversation *conv,
				      const char *cmd, char **args, char **error, void *data)
{
	char *recipient;
	zephyr_account *zephyr = purple_conversation_get_gc(conv)->proto_data;
	if (!g_ascii_strcasecmp(args[0],"*"))
		return PURPLE_CMD_RET_FAILED;  /* "*" is not a valid argument */
	else
		recipient = local_zephyr_normalize(zephyr,args[0]);

	if (strlen(recipient) < 1)
		return PURPLE_CMD_RET_FAILED; /* a null recipient is a chat message, not an IM */

	if (zephyr_send_message(zephyr,"MESSAGE","PERSONAL",recipient,args[1],zephyr_get_signature(),""))
		return PURPLE_CMD_RET_OK;
	else
		return PURPLE_CMD_RET_FAILED;
}

static PurpleCmdRet zephyr_purple_cmd_zlocate(PurpleConversation *conv,
					  const char *cmd, char **args, char **error, void *data)
{
	zephyr_zloc(purple_conversation_get_gc(conv),args[0]);
	return PURPLE_CMD_RET_OK;
}

static PurpleCmdRet zephyr_purple_cmd_instance(PurpleConversation *conv,
					   const char *cmd, char **args, char **error, void *data)
{
	/* Currently it sets the instance with leading spaces and
	 * all. This might not be the best thing to do, though having
	 * one word isn't ideal either.	 */

	PurpleConvChat *gcc = purple_conversation_get_chat_data(conv);
	int id = gcc->id;
	const char* instance = args[0];
	zephyr_chat_set_topic(purple_conversation_get_gc(conv),id,instance);
	return PURPLE_CMD_RET_OK;
}

static PurpleCmdRet zephyr_purple_cmd_joinchat_cir(PurpleConversation *conv,
					       const char *cmd, char **args, char **error, void *data)
{
	/* Join a new zephyr chat */
	GHashTable *triple = g_hash_table_new(NULL,NULL);
	g_hash_table_insert(triple,"class",args[0]);
	g_hash_table_insert(triple,"instance",args[1]);
	g_hash_table_insert(triple,"recipient",args[2]);
	zephyr_join_chat(purple_conversation_get_gc(conv),triple);
	return PURPLE_CMD_RET_OK;
}

static PurpleCmdRet zephyr_purple_cmd_zi(PurpleConversation *conv,
				     const char *cmd, char **args, char **error, void *data)
{
	/* args = instance, message */
	zephyr_account *zephyr = purple_conversation_get_gc(conv)->proto_data;
	if ( zephyr_send_message(zephyr,"message",args[0],"",args[1],zephyr_get_signature(),""))
		return PURPLE_CMD_RET_OK;
	else
		return PURPLE_CMD_RET_FAILED;
}

static PurpleCmdRet zephyr_purple_cmd_zci(PurpleConversation *conv,
				      const char *cmd, char **args, char **error, void *data)
{
	/* args = class, instance, message */
	zephyr_account *zephyr = purple_conversation_get_gc(conv)->proto_data;
	if ( zephyr_send_message(zephyr,args[0],args[1],"",args[2],zephyr_get_signature(),""))
		return PURPLE_CMD_RET_OK;
	else
		return PURPLE_CMD_RET_FAILED;
}

static PurpleCmdRet zephyr_purple_cmd_zcir(PurpleConversation *conv,
				       const char *cmd, char **args, char **error, void *data)
{
	/* args = class, instance, recipient, message */
	zephyr_account *zephyr = purple_conversation_get_gc(conv)->proto_data;
	if ( zephyr_send_message(zephyr,args[0],args[1],args[2],args[3],zephyr_get_signature(),""))
		return PURPLE_CMD_RET_OK;
	else
		return PURPLE_CMD_RET_FAILED;
}

static PurpleCmdRet zephyr_purple_cmd_zir(PurpleConversation *conv,
				      const char *cmd, char **args, char **error, void *data)
{
	/* args = instance, recipient, message */
	zephyr_account *zephyr = purple_conversation_get_gc(conv)->proto_data;
	if ( zephyr_send_message(zephyr,"message",args[0],args[1],args[2],zephyr_get_signature(),""))
		return PURPLE_CMD_RET_OK;
	else
		return PURPLE_CMD_RET_FAILED;
}

static PurpleCmdRet zephyr_purple_cmd_zc(PurpleConversation *conv,
				     const char *cmd, char **args, char **error, void *data)
{
	/* args = class, message */
	zephyr_account *zephyr = purple_conversation_get_gc(conv)->proto_data;
	if ( zephyr_send_message(zephyr,args[0],"PERSONAL","",args[1],zephyr_get_signature(),""))
		return PURPLE_CMD_RET_OK;
	else
		return PURPLE_CMD_RET_FAILED;
}

static void zephyr_register_slash_commands(void)
{

	purple_cmd_register("msg","ws", PURPLE_CMD_P_PRPL,
			  PURPLE_CMD_FLAG_IM | PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PRPL_ONLY,
			  "prpl-zephyr",
			  zephyr_purple_cmd_msg, _("msg &lt;nick&gt; &lt;message&gt;:  Send a private message to a user"), NULL);

	purple_cmd_register("zlocate","w", PURPLE_CMD_P_PRPL,
			  PURPLE_CMD_FLAG_IM | PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PRPL_ONLY,
			  "prpl-zephyr",
			  zephyr_purple_cmd_zlocate, _("zlocate &lt;nick&gt;: Locate user"), NULL);

	purple_cmd_register("zl","w", PURPLE_CMD_P_PRPL,
			  PURPLE_CMD_FLAG_IM | PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PRPL_ONLY,
			  "prpl-zephyr",
			  zephyr_purple_cmd_zlocate, _("zl &lt;nick&gt;: Locate user"), NULL);

	purple_cmd_register("instance","s", PURPLE_CMD_P_PRPL,
			  PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PRPL_ONLY,
			  "prpl-zephyr",
			  zephyr_purple_cmd_instance, _("instance &lt;instance&gt;: Set the instance to be used on this class"), NULL);

	purple_cmd_register("inst","s", PURPLE_CMD_P_PRPL,
			  PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PRPL_ONLY,
			  "prpl-zephyr",
			  zephyr_purple_cmd_instance, _("inst &lt;instance&gt;: Set the instance to be used on this class"), NULL);

	purple_cmd_register("topic","s", PURPLE_CMD_P_PRPL,
			  PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PRPL_ONLY,
			  "prpl-zephyr",
			  zephyr_purple_cmd_instance, _("topic &lt;instance&gt;: Set the instance to be used on this class"), NULL);

	purple_cmd_register("sub", "www", PURPLE_CMD_P_PRPL,
			  PURPLE_CMD_FLAG_IM | PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PRPL_ONLY,
			  "prpl-zephyr",
			  zephyr_purple_cmd_joinchat_cir,
			  _("sub &lt;class&gt; &lt;instance&gt; &lt;recipient&gt;: Join a new chat"), NULL);

	purple_cmd_register("zi","ws", PURPLE_CMD_P_PRPL,
			  PURPLE_CMD_FLAG_IM | PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PRPL_ONLY,
			  "prpl-zephyr",
			  zephyr_purple_cmd_zi, _("zi &lt;instance&gt;: Send a message to &lt;message,<i>instance</i>,*&gt;"), NULL);

	purple_cmd_register("zci","wws",PURPLE_CMD_P_PRPL,
			  PURPLE_CMD_FLAG_IM | PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PRPL_ONLY,
			  "prpl-zephyr",
			  zephyr_purple_cmd_zci,
			  _("zci &lt;class&gt; &lt;instance&gt;: Send a message to &lt;<i>class</i>,<i>instance</i>,*&gt;"), NULL);

	purple_cmd_register("zcir","wwws",PURPLE_CMD_P_PRPL,
			  PURPLE_CMD_FLAG_IM | PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PRPL_ONLY,
			  "prpl-zephyr",
			  zephyr_purple_cmd_zcir,
			  _("zcir &lt;class&gt; &lt;instance&gt; &lt;recipient&gt;: Send a message to &lt;<i>class</i>,<i>instance</i>,<i>recipient</i>&gt;"), NULL);

	purple_cmd_register("zir","wws",PURPLE_CMD_P_PRPL,
			  PURPLE_CMD_FLAG_IM | PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PRPL_ONLY,
			  "prpl-zephyr",
			  zephyr_purple_cmd_zir,
			  _("zir &lt;instance&gt; &lt;recipient&gt;: Send a message to &lt;MESSAGE,<i>instance</i>,<i>recipient</i>&gt;"), NULL);

	purple_cmd_register("zc","ws", PURPLE_CMD_P_PRPL,
			  PURPLE_CMD_FLAG_IM | PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PRPL_ONLY,
			  "prpl-zephyr",
			  zephyr_purple_cmd_zc, _("zc &lt;class&gt;: Send a message to &lt;<i>class</i>,PERSONAL,*&gt;"), NULL);

}


static int zephyr_resubscribe(PurpleConnection *gc)
{
	/* Resubscribe to the in-memory list of subscriptions and also
	   unsubscriptions*/
	zephyr_account *zephyr = gc->proto_data;
	GSList *s = zephyr->subscrips;
	zephyr_triple *zt;
	while (s) {
		zt = s->data;
		/* XXX We really should care if this fails */
		zephyr_subscribe_to(zephyr,zt->class,zt->instance,zt->recipient,NULL);
		s = s->next;
	}
	/* XXX handle unsubscriptions */
	return 1;
}


static void zephyr_action_resubscribe(PurplePluginAction *action)
{

	PurpleConnection *gc = (PurpleConnection *) action->context;
	zephyr_resubscribe(gc);
}


static void zephyr_action_get_subs_from_server(PurplePluginAction *action)
{
	PurpleConnection *gc = (PurpleConnection *) action->context;
	zephyr_account *zephyr = gc->proto_data;
	gchar *title;
	int retval, nsubs, one,i;
	ZSubscription_t subs;
	if (use_zeph02(zephyr)) {
		GString* subout = g_string_new("Subscription list<br>");

		title = g_strdup_printf("Server subscriptions for %s", zephyr->username);

		if (zephyr->port == 0) {
			purple_debug_error("zephyr", "error while retrieving port\n");
			return;
		}
		if ((retval = ZRetrieveSubscriptions(zephyr->port,&nsubs)) != ZERR_NONE) {
			/* XXX better error handling */
			purple_debug_error("zephyr", "error while retrieving subscriptions from server\n");
			return;
		}
		for(i=0;i<nsubs;i++) {
			one = 1;
			if ((retval = ZGetSubscriptions(&subs,&one)) != ZERR_NONE) {
				/* XXX better error handling */
				purple_debug_error("zephyr", "error while retrieving individual subscription\n");
				return;
			}
			g_string_append_printf(subout, "Class %s Instance %s Recipient %s<br>",
					       subs.zsub_class, subs.zsub_classinst,
					       subs.zsub_recipient);
		}
		purple_notify_formatted(gc, title, title, NULL,  subout->str, NULL, NULL);
	} else {
		/* XXX fix */
		purple_notify_error(gc,"","tzc doesn't support this action",NULL);
	}
}


static GList *zephyr_actions(PurplePlugin *plugin, gpointer context)
{
	GList *list = NULL;
	PurplePluginAction *act = NULL;

	act = purple_plugin_action_new(_("Resubscribe"), zephyr_action_resubscribe);
	list = g_list_append(list, act);

	act = purple_plugin_action_new(_("Retrieve subscriptions from server"), zephyr_action_get_subs_from_server);
	list = g_list_append(list,act);

	return list;
}

static PurplePlugin *my_protocol = NULL;

static PurplePluginProtocolInfo prpl_info = {
	OPT_PROTO_CHAT_TOPIC | OPT_PROTO_NO_PASSWORD,
	NULL,					/* ??? user_splits */
	NULL,					/* ??? protocol_options */
	NO_BUDDY_ICONS,
	zephyr_list_icon,
	NULL,					/* ??? list_emblems */
	NULL,					/* ??? status_text */
	NULL,					/* ??? tooltip_text */
	zephyr_status_types,	/* status_types */
	NULL,					/* ??? blist_node_menu - probably all useful actions are already handled*/
	zephyr_chat_info,		/* chat_info */
	NULL,					/* chat_info_defaults */
	zephyr_login,			/* login */
	zephyr_close,			/* close */
	zephyr_send_im,			/* send_im */
	NULL,					/* XXX set info (Location?) */
	zephyr_send_typing,		/* send_typing */
	zephyr_zloc,			/* get_info */
	zephyr_set_status,		/* set_status */
	NULL,					/* ??? set idle */
	NULL,					/* change password */
	NULL,					/* add_buddy */
	NULL,					/* add_buddies */
	NULL,					/* remove_buddy */
	NULL,					/* remove_buddies */
	NULL,					/* add_permit */
	NULL,					/* add_deny */
	NULL,					/* remove_permit */
	NULL,					/* remove_deny */
	NULL,					/* set_permit_deny */
	zephyr_join_chat,		/* join_chat */
	NULL,					/* reject_chat -- No chat invites*/
	zephyr_get_chat_name,	/* get_chat_name */
	NULL,					/* chat_invite -- No chat invites*/
	zephyr_chat_leave,		/* chat_leave */
	NULL,					/* chat_whisper -- No "whispering"*/
	zephyr_chat_send,		/* chat_send */
	NULL,					/* keepalive -- Not necessary*/
	NULL,					/* register_user -- Not supported*/
	NULL,					/* XXX get_cb_info */
	NULL,					/* get_cb_away */
	NULL,					/* alias_buddy */
	NULL,					/* group_buddy */
	NULL,					/* rename_group */
	NULL,					/* buddy_free */
	NULL,					/* convo_closed */
	zephyr_normalize,		/* normalize */
	NULL,					/* XXX set_buddy_icon */
	NULL,					/* remove_group */
	NULL,					/* XXX get_cb_real_name */
	zephyr_chat_set_topic,	/* set_chat_topic */
	zephyr_find_blist_chat,	/* find_blist_chat */
	NULL,					/* roomlist_get_list */
	NULL,					/* roomlist_cancel */
	NULL,					/* roomlist_expand_category */
	NULL,					/* can_receive_file */
	NULL,					/* send_file */
	NULL,					/* new_xfer */
	NULL,					/* offline_message */
	NULL,					/* whiteboard_prpl_ops */
	NULL,					/* send_raw */
	NULL,					/* roomlist_room_serialize */

	NULL,
	NULL,
	NULL,
	sizeof(PurplePluginProtocolInfo),       /* struct_size */
	NULL,					/* get_account_text_table */
	NULL,					/* initate_media */
	NULL,					/* get_media_caps */
	NULL,					/* get_moods */
	NULL,					/* set_public_alias */
	NULL,					/* get_public_alias */
	NULL,					/* add_buddy_with_invite */
	NULL					/* add_buddies_with_invite */
};

static PurplePluginInfo info = {
	PURPLE_PLUGIN_MAGIC,
	PURPLE_MAJOR_VERSION,
	PURPLE_MINOR_VERSION,
	PURPLE_PLUGIN_PROTOCOL,				  /**< type	      */
	NULL,						  /**< ui_requirement */
	0,							  /**< flags	      */
	NULL,						  /**< dependencies   */
	PURPLE_PRIORITY_DEFAULT,				  /**< priority	      */

	"prpl-zephyr",					   /**< id	       */
	"Zephyr",						 /**< name	     */
	DISPLAY_VERSION,					  /**< version	      */
	/**  summary	    */
	N_("Zephyr Protocol Plugin"),
	/**  description    */
	N_("Zephyr Protocol Plugin"),
	NULL,						  /**< author	      */
	PURPLE_WEBSITE,					  /**< homepage	      */

	NULL,						  /**< load	      */
	NULL,						  /**< unload	      */
	NULL,						  /**< destroy	      */

	NULL,						  /**< ui_info	      */
	&prpl_info,					  /**< extra_info     */
	NULL,
	zephyr_actions,

	/* padding */
	NULL,
	NULL,
	NULL,
	NULL
};

static void init_plugin(PurplePlugin * plugin)
{
	PurpleAccountOption *option;
	char *tmp = get_exposure_level();

	option = purple_account_option_bool_new(_("Use tzc"), "use_tzc", FALSE);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	option = purple_account_option_string_new(_("tzc command"), "tzc_command", "/usr/bin/tzc -e %s");
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	option = purple_account_option_bool_new(_("Export to .anyone"), "write_anyone", FALSE);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	option = purple_account_option_bool_new(_("Export to .zephyr.subs"), "write_zsubs", FALSE);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	option = purple_account_option_bool_new(_("Import from .anyone"), "read_anyone", TRUE);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	option = purple_account_option_bool_new(_("Import from .zephyr.subs"), "read_zsubs", TRUE);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	option = purple_account_option_string_new(_("Realm"), "realm", "");
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	option = purple_account_option_string_new(_("Exposure"), "exposure_level", tmp?tmp: EXPOSE_REALMVIS);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	option = purple_account_option_string_new(_("Encoding"), "encoding", ZEPHYR_FALLBACK_CHARSET);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	my_protocol = plugin;
	zephyr_register_slash_commands();
}

PURPLE_INIT_PLUGIN(zephyr, init_plugin, info);
