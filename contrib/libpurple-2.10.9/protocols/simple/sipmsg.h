/**
 * @file sipmsg.h
 *
 * purple
 *
 * Copyright (C) 2005, Thomas Butter <butter@uni-mannheim.de>
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

#ifndef _PURPLE_SIPMSG_H
#define _PURPLE_SIPMSG_H

#include <glib.h>

struct sipmsg {
	int response; /* 0 means request, otherwise response code */
	gchar *method;
	gchar *target;
	GSList *headers;
	int bodylen;
	gchar *body;
};

struct siphdrelement {
	gchar *name;
	gchar *value;
};

struct sipmsg *sipmsg_parse_msg(const gchar *msg);
struct sipmsg *sipmsg_parse_header(const gchar *header);
void sipmsg_add_header(struct sipmsg *msg, const gchar *name, const gchar *value);
void sipmsg_free(struct sipmsg *msg);
const gchar *sipmsg_find_header(struct sipmsg *msg, const gchar *name);
void sipmsg_remove_header(struct sipmsg *msg, const gchar *name);
void sipmsg_print(const struct sipmsg *msg);
char *sipmsg_to_string(const struct sipmsg *msg);
#endif /* _PURPLE_SIMPLE_H */
