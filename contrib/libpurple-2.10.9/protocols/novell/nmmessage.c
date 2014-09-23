/*
 * nmmessage.c
 *
 * Copyright (c) 2004 Novell, Inc. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA	02111-1301	USA
 *
 */

#include "nmmessage.h"

struct _NMMessage
{
	NMConference *conference;
	char *text;
	guint32 ref_count;
};


/** Message API **/

NMMessage *
nm_create_message(const char *text)
{
	NMMessage *msg = g_new0(NMMessage, 1);

	if (text)
		msg->text = g_strdup(text);

	msg->ref_count = 1;
	return msg;
}

void
nm_message_add_ref(NMMessage * msg)
{
	if (msg)
		msg->ref_count++;
}

void
nm_release_message(NMMessage * msg)
{
	if (msg && (--(msg->ref_count) == 0)) {
		if (msg->text)
			g_free(msg->text);

		if (msg->conference)
			nm_release_conference(msg->conference);

		g_free(msg);
	}
}

const char *
nm_message_get_text(NMMessage * msg)
{
	if (msg == NULL)
		return NULL;

	return msg->text;
}

void
nm_message_set_conference(NMMessage * msg, NMConference * conf)
{
	if (msg == NULL || conf == NULL)
		return;

	/* Need to ref the conference first so that it doesn't
	 * get released out from under us
	 */
	nm_conference_add_ref(conf);

	msg->conference = conf;
}

NMConference *
nm_message_get_conference(NMMessage * msg)
{
	if (msg == NULL)
		return NULL;

	return msg->conference;
}
