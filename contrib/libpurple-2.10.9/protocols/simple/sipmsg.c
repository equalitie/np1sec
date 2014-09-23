/**
 * @file sipmsg.c
 *
 * purple
 *
 * Copyright (C) 2005 Thomas Butter <butter@uni-mannheim.de>
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

#include "simple.h"
#include "sipmsg.h"

#define MAX_CONTENT_LENGTH 30000000

struct sipmsg *sipmsg_parse_msg(const gchar *msg) {
	const char *tmp = strstr(msg, "\r\n\r\n");
	char *line;
	struct sipmsg *smsg;

	if(!tmp) return NULL;

	line = g_strndup(msg, tmp - msg);

	smsg = sipmsg_parse_header(line);
	if(smsg != NULL)
		smsg->body = g_strdup(tmp + 4);
	else
		purple_debug_error("SIMPLE", "No header parsed from line: %s\n", line);

	g_free(line);
	return smsg;
}

struct sipmsg *sipmsg_parse_header(const gchar *header) {
	struct sipmsg *msg;
	gchar **parts, **lines;
	gchar *dummy, *dummy2, *tmp;
	const gchar *tmp2;
	int i = 1;

	lines = g_strsplit(header,"\r\n",0);
	if(!lines[0]) {
		g_strfreev(lines);
		return NULL;
	}

	parts = g_strsplit(lines[0], " ", 3);
	if(!parts[0] || !parts[1] || !parts[2]) {
		g_strfreev(parts);
		g_strfreev(lines);
		return NULL;
	}

	msg = g_new0(struct sipmsg,1);
	if(strstr(parts[0],"SIP")) { /* numeric response */
		msg->method = g_strdup(parts[2]);
		msg->response = strtol(parts[1],NULL,10);
	} else { /* request */
		msg->method = g_strdup(parts[0]);
		msg->target = g_strdup(parts[1]);
		msg->response = 0;
	}
	g_strfreev(parts);

	for(i=1; lines[i] && strlen(lines[i])>2; i++) {
		parts = g_strsplit(lines[i], ":", 2);
		if(!parts[0] || !parts[1]) {
			g_strfreev(parts);
			g_strfreev(lines);
			sipmsg_free(msg);
			return NULL;
		}
		dummy = parts[1];
		dummy2 = 0;
		while(*dummy==' ' || *dummy=='\t') dummy++;
		dummy2 = g_strdup(dummy);
		while(lines[i+1] && (lines[i+1][0]==' ' || lines[i+1][0]=='\t')) {
			i++;
			dummy = lines[i];
			while(*dummy==' ' || *dummy=='\t') dummy++;
			tmp = g_strdup_printf("%s %s",dummy2, dummy);
			g_free(dummy2);
			dummy2 = tmp;
		}
		sipmsg_add_header(msg, parts[0], dummy2);
		g_free(dummy2);
		g_strfreev(parts);
	}
	g_strfreev(lines);

	tmp2 = sipmsg_find_header(msg, "Content-Length");
	if (tmp2 != NULL)
		msg->bodylen = strtol(tmp2, NULL, 10);
	if (msg->bodylen < 0) {
		purple_debug_warning("simple", "Invalid body length: %d",
			msg->bodylen);
		msg->bodylen = 0;
	} else if (msg->bodylen > MAX_CONTENT_LENGTH) {
		purple_debug_warning("simple", "Got Content-Length of %d bytes on "
				"incoming message (max is %u bytes). Ignoring message body.\n",
				msg->bodylen, MAX_CONTENT_LENGTH);
		msg->bodylen = 0;
	}

	if(msg->response) {
		tmp2 = sipmsg_find_header(msg, "CSeq");
		g_free(msg->method);
		if(!tmp2) {
			/* SHOULD NOT HAPPEN */
			msg->method = NULL;
		} else {
			parts = g_strsplit(tmp2, " ", 2);
			msg->method = g_strdup(parts[1]);
			g_strfreev(parts);
		}
	}

	return msg;
}

void sipmsg_print(const struct sipmsg *msg) {
	GSList *cur;
	struct siphdrelement *elem;
	purple_debug(PURPLE_DEBUG_MISC, "simple", "SIP MSG\n");
	purple_debug(PURPLE_DEBUG_MISC, "simple", "response: %d\nmethod: %s\nbodylen: %d\n",msg->response,msg->method,msg->bodylen);
	if(msg->target) purple_debug(PURPLE_DEBUG_MISC, "simple", "target: %s\n",msg->target);
	cur = msg->headers;
	while(cur) {
		elem = cur->data;
		purple_debug(PURPLE_DEBUG_MISC, "simple", "name: %s value: %s\n",elem->name, elem->value);
		cur = g_slist_next(cur);
	}
}

char *sipmsg_to_string(const struct sipmsg *msg) {
	GSList *cur;
	GString *outstr = g_string_new("");
	struct siphdrelement *elem;

	if(msg->response)
		g_string_append_printf(outstr, "SIP/2.0 %d Unknown\r\n",
			msg->response);
	else
		g_string_append_printf(outstr, "%s %s SIP/2.0\r\n",
			msg->method, msg->target);

	cur = msg->headers;
	while(cur) {
		elem = cur->data;
		g_string_append_printf(outstr, "%s: %s\r\n", elem->name,
			elem->value);
		cur = g_slist_next(cur);
	}

	g_string_append_printf(outstr, "\r\n%s", msg->bodylen ? msg->body : "");

	return g_string_free(outstr, FALSE);
}
void sipmsg_add_header(struct sipmsg *msg, const gchar *name, const gchar *value) {
	struct siphdrelement *element = g_new(struct siphdrelement,1);
	element->name = g_strdup(name);
	element->value = g_strdup(value);
	msg->headers = g_slist_append(msg->headers, element);
}

void sipmsg_free(struct sipmsg *msg) {
	struct siphdrelement *elem;
	while(msg->headers) {
		elem = msg->headers->data;
		msg->headers = g_slist_remove(msg->headers,elem);
		g_free(elem->name);
		g_free(elem->value);
		g_free(elem);
	}
	g_free(msg->method);
	g_free(msg->target);
	g_free(msg->body);
	g_free(msg);
}

void sipmsg_remove_header(struct sipmsg *msg, const gchar *name) {
	struct siphdrelement *elem;
	GSList *tmp = msg->headers;
	while(tmp) {
		elem = tmp->data;
		if(g_ascii_strcasecmp(elem->name, name)==0) {
			msg->headers = g_slist_remove(msg->headers, elem);
			g_free(elem->name);
			g_free(elem->value);
			g_free(elem);
			return;
		}
		tmp = g_slist_next(tmp);
	}
	return;
}

const gchar *sipmsg_find_header(struct sipmsg *msg, const gchar *name) {
	GSList *tmp;
	struct siphdrelement *elem;
	tmp = msg->headers;
	while(tmp) {
		elem = tmp->data;
		if(g_ascii_strcasecmp(elem->name, name)==0) {
			return elem->value;
		}
		tmp = g_slist_next(tmp);
	}
	return NULL;
}

