/**
 * @file slpmsg.c SLP Message functions
 *
 * purple
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
#include "debug.h"

#include "slpmsg.h"
#include "slpmsg_part.h"
#include "slplink.h"

/**************************************************************************
 * SLP Message
 **************************************************************************/

MsnSlpMessage *
msn_slpmsg_new(MsnSlpLink *slplink, MsnSlpCall *slpcall)
{
	MsnSlpMessage *slpmsg;
	MsnP2PVersion p2p;

	g_return_val_if_fail(slplink != NULL, NULL);

	slpmsg = g_new0(MsnSlpMessage, 1);

	if (purple_debug_is_verbose())
		purple_debug_info("msn", "slpmsg new (%p)\n", slpmsg);

	msn_slpmsg_set_slplink(slpmsg, slplink);
	slpmsg->slpcall = slpcall;

	p2p = msn_slplink_get_p2p_version(slplink);
	slpmsg->p2p_info = msn_p2p_info_new(p2p);

	return slpmsg;
}

void
msn_slpmsg_destroy(MsnSlpMessage *slpmsg)
{
	MsnSlpLink *slplink;
	GList *cur;

	g_return_if_fail(slpmsg != NULL);

	if (purple_debug_is_verbose())
		purple_debug_info("msn", "slpmsg destroy (%p)\n", slpmsg);

	slplink = slpmsg->slplink;

	purple_imgstore_unref(slpmsg->img);

	/* We don't want to free the data of the PurpleStoredImage,
	 * but to avoid code duplication, it's sharing buffer. */
	if (slpmsg->img == NULL)
		g_free(slpmsg->buffer);

	for (cur = slpmsg->parts; cur != NULL; cur = g_list_delete_link(cur, cur))
	{
		/* Something is pointing to this slpmsg, so we should remove that
		 * pointer to prevent a crash. */
		/* Ex: a user goes offline and after that we receive an ACK */

		MsnSlpMessagePart *part = cur->data;

		part->ack_cb = NULL;
		part->nak_cb = NULL;
		part->ack_data = NULL;
		msn_slpmsgpart_unref(part);
	}

	slplink->slp_msgs = g_list_remove(slplink->slp_msgs, slpmsg);

	msn_p2p_info_free(slpmsg->p2p_info);

	g_free(slpmsg);
}

void
msn_slpmsg_set_slplink(MsnSlpMessage *slpmsg, MsnSlpLink *slplink)
{
	g_return_if_fail(slplink != NULL);

	slpmsg->slplink = slplink;

	slplink->slp_msgs =
		g_list_append(slplink->slp_msgs, slpmsg);
}

void
msn_slpmsg_set_body(MsnSlpMessage *slpmsg, const char *body,
						 long long size)
{
	/* We can only have one data source at a time. */
	g_return_if_fail(slpmsg->buffer == NULL);
	g_return_if_fail(slpmsg->img == NULL);
	g_return_if_fail(slpmsg->ft == FALSE);

	if (body != NULL)
		slpmsg->buffer = g_memdup(body, size);
	else
		slpmsg->buffer = g_new0(guchar, size);

	slpmsg->size = size;
}

void
msn_slpmsg_set_image(MsnSlpMessage *slpmsg, PurpleStoredImage *img)
{
	/* We can only have one data source at a time. */
	g_return_if_fail(slpmsg->buffer == NULL);
	g_return_if_fail(slpmsg->img == NULL);
	g_return_if_fail(slpmsg->ft == FALSE);

	slpmsg->img = purple_imgstore_ref(img);
	slpmsg->buffer = (guchar *)purple_imgstore_get_data(img);
	slpmsg->size = purple_imgstore_get_size(img);
}


MsnSlpMessage *
msn_slpmsg_sip_new(MsnSlpCall *slpcall, int cseq,
				   const char *header, const char *branch,
				   const char *content_type, const char *content)
{
	MsnSlpLink *slplink;
	PurpleAccount *account;
	MsnSlpMessage *slpmsg;
	char *body;
	gsize body_len;
	gsize content_len;

	g_return_val_if_fail(slpcall != NULL, NULL);
	g_return_val_if_fail(header  != NULL, NULL);

	slplink = slpcall->slplink;
	account = slplink->session->account;

	/* Let's remember that "content" should end with a 0x00 */

	content_len = (content != NULL) ? strlen(content) + 1 : 0;

	body = g_strdup_printf(
		"%s\r\n"
		"To: <msnmsgr:%s>\r\n"
		"From: <msnmsgr:%s>\r\n"
		"Via: MSNSLP/1.0/TLP ;branch={%s}\r\n"
		"CSeq: %d\r\n"
		"Call-ID: {%s}\r\n"
		"Max-Forwards: 0\r\n"
		"Content-Type: %s\r\n"
		"Content-Length: %" G_GSIZE_FORMAT "\r\n"
		"\r\n",
		header,
		slplink->remote_user,
		purple_account_get_username(account),
		branch,
		cseq,
		slpcall->id,
		content_type,
		content_len);

	body_len = strlen(body);

	if (content_len > 0)
	{
		body_len += content_len;
		body = g_realloc(body, body_len);
		g_strlcat(body, content, body_len);
	}

	slpmsg = msn_slpmsg_new(slplink, slpcall);
	msn_slpmsg_set_body(slpmsg, body, body_len);

	g_free(body);

	return slpmsg;
}

MsnSlpMessage *msn_slpmsg_ack_new(MsnSlpLink *slplink, MsnP2PInfo *ack_info)
{
	MsnSlpMessage *slpmsg;
	MsnP2PInfo *new_info;

	slpmsg = msn_slpmsg_new(slplink, NULL);

	new_info = slpmsg->p2p_info;
	msn_p2p_info_create_ack(ack_info, new_info);
	slpmsg->size = msn_p2p_info_get_total_size(ack_info);
	slpmsg->info = "SLP ACK";

	return slpmsg;
}

MsnSlpMessage *msn_slpmsg_obj_new(MsnSlpCall *slpcall, PurpleStoredImage *img)
{
	MsnSlpMessage *slpmsg;

	slpmsg = msn_slpmsg_new(slpcall->slplink, slpcall);
	msn_p2p_info_set_flags(slpmsg->p2p_info, P2P_MSN_OBJ_DATA);
	slpmsg->info = "SLP DATA";

	msn_slpmsg_set_image(slpmsg, img);

	return slpmsg;
}

MsnSlpMessage *msn_slpmsg_dataprep_new(MsnSlpCall *slpcall)
{
	MsnSlpMessage *slpmsg;

	slpmsg = msn_slpmsg_new(slpcall->slplink, slpcall);

	msn_p2p_info_set_session_id(slpmsg->p2p_info, slpcall->session_id);
	msn_slpmsg_set_body(slpmsg, NULL, 4);
	slpmsg->info = "SLP DATA PREP";

	return slpmsg;

}

MsnSlpMessage *msn_slpmsg_file_new(MsnSlpCall *slpcall, size_t size)
{
	MsnSlpMessage *slpmsg;

	slpmsg = msn_slpmsg_new(slpcall->slplink, slpcall);

	msn_p2p_info_set_flags(slpmsg->p2p_info, P2P_FILE_DATA);
	slpmsg->info = "SLP FILE";
	slpmsg->size = size;

	return slpmsg;
}

char *msn_slpmsg_serialize(MsnSlpMessage *slpmsg, size_t *ret_size)
{
	char *header;
	char *footer;
	char *base;
	char *tmp;
	size_t header_size, footer_size;

	header = msn_p2p_header_to_wire(slpmsg->p2p_info, &header_size);
	footer = msn_p2p_footer_to_wire(slpmsg->p2p_info, &footer_size);

	base = g_malloc(header_size + slpmsg->size + footer_size);
	tmp = base;

	/* Copy header */
	memcpy(tmp, header, header_size);
	tmp += header_size;

	/* Copy body */
	memcpy(tmp, slpmsg->buffer, slpmsg->size);
	tmp += slpmsg->size;

	/* Copy footer */
	memcpy(tmp, footer, footer_size);
	tmp += footer_size;

	*ret_size = tmp - base;

	g_free(header);
	g_free(footer);

	return base;
}

void msn_slpmsg_show_readable(MsnSlpMessage *slpmsg)
{
	GString *str;

	str = g_string_new(NULL);

	msn_p2p_info_to_string(slpmsg->p2p_info, str);

	if (purple_debug_is_verbose() && slpmsg->buffer != NULL) {
		g_string_append_len(str, (gchar*)slpmsg->buffer, slpmsg->size);

		if (slpmsg->buffer[slpmsg->size - 1] == '\0') {
			str->len--;
			g_string_append(str, " 0x00");
		}
		g_string_append(str, "\r\n");

	}

	purple_debug_info("msn", "SlpMessage %s:\n{%s}\n", slpmsg->info, str->str);
}
