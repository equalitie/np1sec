/**
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
#include "debug.h"

#include "google.h"
#include "jabber.h"
#include "chat.h"

/* This does two passes on the string. The first pass goes through
 * and determine if all the structured text is properly balanced, and
 * how many instances of each there is. The second pass goes and converts
 * everything to HTML, depending on what's figured out by the first pass.
 * It will short circuit once it knows it has no more replacements to make
 */
char *jabber_google_format_to_html(const char *text)
{
	const char *p;

	/* The start of the screen may be consdiered a space for this purpose */
	gboolean preceding_space = TRUE;

	gboolean in_bold = FALSE, in_italic = FALSE;
	gboolean in_tag = FALSE;

	gint bold_count = 0, italic_count = 0;

	GString *str;

	for (p = text; *p != '\0'; p = g_utf8_next_char(p)) {
		gunichar c = g_utf8_get_char(p);
		if (c == '*' && !in_tag) {
			if (in_bold && (g_unichar_isspace(*(p+1)) ||
					*(p+1) == '\0' ||
					*(p+1) == '<')) {
				bold_count++;
				in_bold = FALSE;
			} else if (preceding_space && !in_bold && !g_unichar_isspace(*(p+1))) {
				bold_count++;
				in_bold = TRUE;
			}
			preceding_space = TRUE;
		} else if (c == '_' && !in_tag) {
			if (in_italic && (g_unichar_isspace(*(p+1)) ||
					*(p+1) == '\0' ||
					*(p+1) == '<')) {
				italic_count++;
				in_italic = FALSE;
			} else if (preceding_space && !in_italic && !g_unichar_isspace(*(p+1))) {
				italic_count++;
				in_italic = TRUE;
			}
			preceding_space = TRUE;
		} else if (c == '<' && !in_tag) {
			in_tag = TRUE;
		} else if (c == '>' && in_tag) {
			in_tag = FALSE;
		} else if (!in_tag) {
			if (g_unichar_isspace(c))
				preceding_space = TRUE;
			else
				preceding_space = FALSE;
		}
	}

	str  = g_string_new(NULL);
	in_bold = in_italic = in_tag = FALSE;
	preceding_space = TRUE;

	for (p = text; *p != '\0'; p = g_utf8_next_char(p)) {
		gunichar c = g_utf8_get_char(p);

		if (bold_count < 2 && italic_count < 2 && !in_bold && !in_italic) {
			g_string_append(str, p);
			return g_string_free(str, FALSE);
		}


		if (c == '*' && !in_tag) {
			if (in_bold &&
			    (g_unichar_isspace(*(p+1))||*(p+1)=='<')) { /* This is safe in UTF-8 */
				str = g_string_append(str, "</b>");
				in_bold = FALSE;
				bold_count--;
			} else if (preceding_space && bold_count > 1 && !g_unichar_isspace(*(p+1))) {
				str = g_string_append(str, "<b>");
				bold_count--;
				in_bold = TRUE;
			} else {
				str = g_string_append_unichar(str, c);
			}
			preceding_space = TRUE;
		} else if (c == '_' && !in_tag) {
			if (in_italic &&
			    (g_unichar_isspace(*(p+1))||*(p+1)=='<')) {
				str = g_string_append(str, "</i>");
				italic_count--;
				in_italic = FALSE;
			} else if (preceding_space && italic_count > 1 && !g_unichar_isspace(*(p+1))) {
				str = g_string_append(str, "<i>");
				italic_count--;
				in_italic = TRUE;
			} else {
				str = g_string_append_unichar(str, c);
			}
			preceding_space = TRUE;
		} else if (c == '<' && !in_tag) {
			str = g_string_append_unichar(str, c);
			in_tag = TRUE;
		} else if (c == '>' && in_tag) {
			str = g_string_append_unichar(str, c);
			in_tag = FALSE;
		} else if (!in_tag) {
			str = g_string_append_unichar(str, c);
			if (g_unichar_isspace(c))
				preceding_space = TRUE;
			else
				preceding_space = FALSE;
		} else {
			str = g_string_append_unichar(str, c);
		}
	}
	return g_string_free(str, FALSE);
}



void google_buddy_node_chat(PurpleBlistNode *node, gpointer data)
{
	PurpleBuddy *buddy;
	PurpleConnection *gc;
	JabberStream *js;
	JabberChat *chat;
	gchar *room;
	gchar *uuid = purple_uuid_random();

	g_return_if_fail(PURPLE_BLIST_NODE_IS_BUDDY(node));

	buddy = PURPLE_BUDDY(node);
	gc = purple_account_get_connection(purple_buddy_get_account(buddy));
	g_return_if_fail(gc != NULL);
	js = purple_connection_get_protocol_data(gc);

	room = g_strdup_printf("private-chat-%s", uuid);
	chat = jabber_join_chat(js, room, GOOGLE_GROUPCHAT_SERVER, js->user->node,
	                        NULL, NULL);
	if (chat) {
		chat->muc = TRUE;
		jabber_chat_invite(gc, chat->id, "", purple_buddy_get_name(buddy));
	}

	g_free(room);
	g_free(uuid);
}
