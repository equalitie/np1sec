/**
 * @file slpmsg_part.c MSNSLP Parts
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

MsnSlpMessagePart *msn_slpmsgpart_new(MsnP2PInfo *info)
{
	MsnSlpMessagePart *part;

	part = g_new0(MsnSlpMessagePart, 1);

	part->info = info;

	part->ack_cb = msn_slpmsgpart_ack;
	part->nak_cb = msn_slpmsgpart_nak;

	return msn_slpmsgpart_ref(part);
}

MsnSlpMessagePart *
msn_slpmsgpart_new_from_data(MsnP2PVersion p2p, const char *data, size_t data_len)
{
	MsnSlpMessagePart *part;
	MsnP2PInfo *info;
	size_t len;
	int body_len;

	info = msn_p2p_info_new(p2p);

	/* Extract the binary SLP header */
	len = msn_p2p_header_from_wire(info, data, data_len);
	if (len == 0) {
		msn_p2p_info_free(info);
		return NULL;
	}
	data += len;
	part = msn_slpmsgpart_new(info);

	/* Extract the body */
	body_len = data_len - len - P2P_PACKET_FOOTER_SIZE;
	/* msg->body_len = msg->msnslp_header.length; */

	if (body_len > 0) {
		part->size = body_len;
		part->buffer = g_malloc(body_len);
		memcpy(part->buffer, data, body_len);
		data += body_len;
	}

	/* Extract the footer */
	if (body_len >= 0)
		msn_p2p_footer_from_wire(part->info, data);

	return part;
}

static void msn_slpmsgpart_destroy(MsnSlpMessagePart *part)
{
	g_free(part->info);
	g_free(part->buffer);

	g_free(part);

}

MsnSlpMessagePart *msn_slpmsgpart_ref(MsnSlpMessagePart *part)
{
	g_return_val_if_fail(part != NULL, NULL);
	part->ref_count++;

	if (purple_debug_is_verbose())
		purple_debug_info("msn", "part ref (%p)[%u]\n", part, part->ref_count);

	return part;
}

void msn_slpmsgpart_unref(MsnSlpMessagePart *part)
{
	g_return_if_fail(part != NULL);
	g_return_if_fail(part->ref_count > 0);

	part->ref_count--;

	if (purple_debug_is_verbose())
		purple_debug_info("msn", "part unref (%p)[%u]\n", part, part->ref_count);

	if (part->ref_count == 0) {
		msn_slpmsgpart_destroy(part);
	}
}

void msn_slpmsgpart_set_bin_data(MsnSlpMessagePart *part, const void *data, size_t len)
{
	g_return_if_fail(part != NULL);

	g_free(part->buffer);

	if (data != NULL && len > 0) {
		part->buffer = g_malloc(len + 1);
		memcpy(part->buffer, data, len);
		part->buffer[len] = '\0';
		part->size = len;
	} else {
		part->buffer = NULL;
		part->size = 0;
	}

}

char *msn_slpmsgpart_serialize(MsnSlpMessagePart *part, size_t *ret_size)
{
	char *header;
	char *footer;
	char *base;
	char *tmp;
	size_t header_size, footer_size;

	header = msn_p2p_header_to_wire(part->info, &header_size);
	footer = msn_p2p_footer_to_wire(part->info, &footer_size);

	base = g_malloc(header_size + part->size + footer_size);
	tmp = base;

	/* Copy header */
	memcpy(tmp, header, header_size);
	tmp += header_size;

	/* Copy body */
	memcpy(tmp, part->buffer, part->size);
	tmp += part->size;

	/* Copy footer */
	memcpy(tmp, footer, footer_size);
	tmp += footer_size;

	*ret_size = tmp - base;

	g_free(header);
	g_free(footer);

	return base;
}

/* We have received the message ack */
void
msn_slpmsgpart_ack(MsnSlpMessagePart *part, void *data)
{
	MsnSlpMessage *slpmsg;
	guint64 offset;
	long long real_size;

	slpmsg = data;

	real_size = msn_p2p_info_is_ack(slpmsg->p2p_info) ? 0 : slpmsg->size;

	offset = msn_p2p_info_get_offset(slpmsg->p2p_info);
	offset += msn_p2p_info_get_length(part->info);
	msn_p2p_info_set_offset(slpmsg->p2p_info, offset);

	slpmsg->parts = g_list_remove(slpmsg->parts, part);
	msn_slpmsgpart_unref(part);

	if (offset < real_size)
	{
		if (slpmsg->slpcall->xfer && purple_xfer_get_status(slpmsg->slpcall->xfer) == PURPLE_XFER_STATUS_STARTED)
		{
			slpmsg->slpcall->xfer_msg = slpmsg;
			purple_xfer_prpl_ready(slpmsg->slpcall->xfer);
		}
		else
			msn_slplink_send_msgpart(slpmsg->slplink, slpmsg);
	}
	else
	{
		/* The whole message has been sent */
		if (msn_p2p_msg_is_data(slpmsg->p2p_info))
		{
			if (slpmsg->slpcall != NULL)
			{
				if (slpmsg->slpcall->cb)
					slpmsg->slpcall->cb(slpmsg->slpcall,
						NULL, 0);
			}
		}
	}
}

/* We have received the message nak. */
void
msn_slpmsgpart_nak(MsnSlpMessagePart *part, void *data)
{
	MsnSlpMessage *slpmsg;

	slpmsg = data;

	msn_slplink_send_msgpart(slpmsg->slplink, slpmsg);

	slpmsg->parts = g_list_remove(slpmsg->parts, part);
	msn_slpmsgpart_unref(part);
}

void
msn_slpmsgpart_to_string(MsnSlpMessagePart *part, GString *str)
{
	msn_p2p_info_to_string(part->info, str);
}

