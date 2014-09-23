/**
 * @file p2p.c MSN P2P functions
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

#include "p2p.h"
#include "tlv.h"
#include "msnutils.h"

MsnP2PInfo *
msn_p2p_info_new(MsnP2PVersion version)
{
	MsnP2PInfo *info = g_new0(MsnP2PInfo, 1);
	info->version = version;

	switch (version) {
		case MSN_P2P_VERSION_ONE:
		case MSN_P2P_VERSION_TWO:
			/* Nothing to do */
			break;

		default:
			purple_debug_error("msn", "Invalid P2P Info version: %d\n", version);
			g_free(info);
			info = NULL;
	}

	return info;
}

MsnP2PInfo *
msn_p2p_info_dup(MsnP2PInfo *info)
{
	MsnP2PInfo *new_info = g_new0(MsnP2PInfo, 1);

	new_info->version = info->version;

	switch (info->version) {
		case MSN_P2P_VERSION_ONE:
			*new_info = *info;
			break;

		case MSN_P2P_VERSION_TWO:
			*new_info = *info;
			new_info->header.v2.header_tlv = msn_tlvlist_copy(info->header.v2.header_tlv);
			new_info->header.v2.data_tlv = msn_tlvlist_copy(info->header.v2.data_tlv);
			break;

		default:
			purple_debug_error("msn", "Invalid P2P Info version: %d\n", info->version);
			g_free(new_info);
			new_info = NULL;
	}

	return new_info;
}

void
msn_p2p_info_free(MsnP2PInfo *info)
{
	switch (info->version) {
		case MSN_P2P_VERSION_ONE:
			/* Nothing to do! */
			break;

		case MSN_P2P_VERSION_TWO:
			msn_tlvlist_free(info->header.v2.header_tlv);
			msn_tlvlist_free(info->header.v2.data_tlv);
			break;

		default:
			purple_debug_error("msn", "Invalid P2P Info version: %d\n", info->version);
	}

	g_free(info);
}

size_t
msn_p2p_header_from_wire(MsnP2PInfo *info, const char *wire, size_t max_len)
{
	size_t len = 0;

	switch (info->version) {
		case MSN_P2P_VERSION_ONE: {
			MsnP2PHeader *header = &info->header.v1;

			if (max_len < P2P_PACKET_HEADER_SIZE) {
				/* Invalid packet length */
				len = 0;
				break;
			}

			header->session_id = msn_pop32le(wire);
			header->id         = msn_pop32le(wire);
			header->offset     = msn_pop64le(wire);
			header->total_size = msn_pop64le(wire);
			header->length     = msn_pop32le(wire);
			header->flags      = msn_pop32le(wire);
			header->ack_id     = msn_pop32le(wire);
			header->ack_sub_id = msn_pop32le(wire);
			header->ack_size   = msn_pop64le(wire);

			len = P2P_PACKET_HEADER_SIZE;
			break;
		}

		case MSN_P2P_VERSION_TWO: {
			MsnP2Pv2Header *header = &info->header.v2;

			header->header_len = msn_pop8(wire);
			header->opcode = msn_pop8(wire);
			header->message_len = msn_pop16be(wire);
			header->base_id = msn_pop32be(wire);
			if (header->header_len + header->message_len + P2P_PACKET_FOOTER_SIZE > max_len) {
				/* Invalid header and data length */
				len = 0;
				break;
			}

			if (header->header_len > 8) {
				header->header_tlv = msn_tlvlist_read(wire, header->header_len - 8);
				wire += header->header_len - 8;
			}

			if (header->message_len > 0) {
				/* Parse Data packet */

				header->data_header_len = msn_pop8(wire);
				if (header->data_header_len > header->message_len) {
					/* Invalid data header length */
					len = 0;
					break;
				}
				header->data_tf = msn_pop8(wire);
				header->package_number = msn_pop16be(wire);
				header->session_id = msn_pop32be(wire);

				if (header->data_header_len > 8) {
					header->data_tlv = msn_tlvlist_read(wire, header->data_header_len - 8);
					wire += header->data_header_len - 8;
				}
			}

			len = header->header_len + header->message_len;

			break;
		}

		default:
			purple_debug_error("msn", "Invalid P2P Info version: %d\n", info->version);
	}

	return len;
}

char *
msn_p2p_header_to_wire(MsnP2PInfo *info, size_t *len)
{
	char *wire = NULL;
	char *tmp;

	switch (info->version) {
		case MSN_P2P_VERSION_ONE: {
			MsnP2PHeader *header = &info->header.v1;
			tmp = wire = g_new(char, P2P_PACKET_HEADER_SIZE);

			msn_push32le(tmp, header->session_id);
			msn_push32le(tmp, header->id);
			msn_push64le(tmp, header->offset);
			msn_push64le(tmp, header->total_size);
			msn_push32le(tmp, header->length);
			msn_push32le(tmp, header->flags);
			msn_push32le(tmp, header->ack_id);
			msn_push32le(tmp, header->ack_sub_id);
			msn_push64le(tmp, header->ack_size);

			if (len)
				*len = P2P_PACKET_HEADER_SIZE;

			break;
		}

		case MSN_P2P_VERSION_TWO: {
			MsnP2Pv2Header *header = &info->header.v2;
			char *header_wire = NULL;
			char *data_header_wire = NULL;

			if (header->header_tlv != NULL)
				header_wire = msn_tlvlist_write(header->header_tlv, (size_t *)&header->header_len);
			else
				header->header_len = 0;

			if (header->data_tlv != NULL)
				data_header_wire = msn_tlvlist_write(header->data_tlv, (size_t *)&header->data_header_len);
			else
				header->data_header_len = 0;

			tmp = wire = g_new(char, 16 + header->header_len + header->data_header_len);

			msn_push8(tmp, header->header_len + 8);
			msn_push8(tmp, header->opcode);
			msn_push16be(tmp, header->data_header_len + 8 + header->message_len);
			msn_push32be(tmp, header->base_id);

			if (header_wire != NULL) {
				memcpy(tmp, header_wire, header->header_len);
				tmp += header->header_len;
			}

			msn_push8(tmp, header->data_header_len + 8);
			msn_push8(tmp, header->data_tf);
			msn_push16be(tmp, header->package_number);
			msn_push32be(tmp, header->session_id);

			if (data_header_wire != NULL) {
				memcpy(tmp, data_header_wire, header->data_header_len);
				tmp += header->data_header_len;
			}

			if (len)
				*len = header->header_len + header->data_header_len + 16;

			break;
		}

		default:
			purple_debug_error("msn", "Invalid P2P Info version: %d\n", info->version);
	}

	return wire;
}

size_t
msn_p2p_footer_from_wire(MsnP2PInfo *info, const char *wire)
{
	MsnP2PFooter *footer;

	footer = &info->footer;

	footer->value = msn_pop32be(wire);

	return P2P_PACKET_FOOTER_SIZE;
}

char *
msn_p2p_footer_to_wire(MsnP2PInfo *info, size_t *len)
{
	MsnP2PFooter *footer;
	char *wire;
	char *tmp;

	footer = &info->footer;
	tmp = wire = g_new(char, P2P_PACKET_FOOTER_SIZE);

	msn_push32be(tmp, footer->value);

	if (len)
		*len = P2P_PACKET_FOOTER_SIZE;

	return wire;
}

void
msn_p2p_info_to_string(MsnP2PInfo *info, GString *str)
{
	switch (info->version) {
		case MSN_P2P_VERSION_ONE: {
			MsnP2PHeader *header = &info->header.v1;
			g_string_append_printf(str, "Session ID: %u\r\n", header->session_id);
			g_string_append_printf(str, "ID:         %u\r\n", header->id);
			g_string_append_printf(str, "Offset:     %" G_GUINT64_FORMAT "\r\n", header->offset);
			g_string_append_printf(str, "Total size: %" G_GUINT64_FORMAT "\r\n", header->total_size);
			g_string_append_printf(str, "Length:     %u\r\n", header->length);
			g_string_append_printf(str, "Flags:      0x%x\r\n", header->flags);
			g_string_append_printf(str, "ACK ID:     %u\r\n", header->ack_id);
			g_string_append_printf(str, "SUB ID:     %u\r\n", header->ack_sub_id);
			g_string_append_printf(str, "ACK Size:   %" G_GUINT64_FORMAT "\r\n", header->ack_size);

			break;
		}

		case MSN_P2P_VERSION_TWO:
			/* Nothing to do! */
			break;

		default:
			purple_debug_error("msn", "Invalid P2P Info version: %d\n", info->version);
	}

	g_string_append_printf(str, "Footer:     0x%08X\r\n", info->footer.value);
}

gboolean
msn_p2p_msg_is_data(const MsnP2PInfo *info)
{
	gboolean data = FALSE;

	switch (info->version) {
		case MSN_P2P_VERSION_ONE: {
			guint32 flags = info->header.v1.flags;
			data = (flags == P2P_MSN_OBJ_DATA ||
			        flags == (P2P_WLM2009_COMP | P2P_MSN_OBJ_DATA) ||
			        flags == P2P_FILE_DATA);
			break;
		}

		case MSN_P2P_VERSION_TWO:
			data = info->header.v2.message_len > 0;
			break;

		default:
			purple_debug_error("msn", "Invalid P2P Info version: %d\n", info->version);
	}

	return data;
}

gboolean
msn_p2p_info_is_valid(MsnP2PInfo *info)
{
	gboolean valid = FALSE;

	switch (info->version) {
		case MSN_P2P_VERSION_ONE:
			valid = info->header.v1.total_size >= info->header.v1.length;
			break;

		case MSN_P2P_VERSION_TWO:
			/* Nothing to do! */
			valid = TRUE;
			break;

		default:
			purple_debug_error("msn", "Invalid P2P Info version: %d\n", info->version);
	}

	return valid;
}

gboolean
msn_p2p_info_is_first(MsnP2PInfo *info)
{
	gboolean first = FALSE;

	switch (info->version) {
		case MSN_P2P_VERSION_ONE:
			first = info->header.v1.offset == 0;
			break;

		case MSN_P2P_VERSION_TWO:
			/* Nothing to do! */
			first = info->header.v2.data_tf & TF_FIRST;
			break;

		default:
			purple_debug_error("msn", "Invalid P2P Info version: %d\n", info->version);
	}

	return first;
}

gboolean
msn_p2p_info_is_final(MsnP2PInfo *info)
{
	gboolean final = FALSE;

	switch (info->version) {
		case MSN_P2P_VERSION_ONE:
			final = info->header.v1.offset + info->header.v1.length >= info->header.v1.total_size;
			break;

		case MSN_P2P_VERSION_TWO:
			final = msn_tlv_gettlv(info->header.v2.data_tlv, P2P_DATA_TLV_REMAINING, 1) == NULL;
			break;

		default:
			purple_debug_error("msn", "Invalid P2P Info version: %d\n", info->version);
	}

	return final;
}

void
msn_p2p_info_create_ack(MsnP2PInfo *old_info, MsnP2PInfo *new_info)
{
	switch (old_info->version) {
		case MSN_P2P_VERSION_ONE: {
			MsnP2PHeader *old = &old_info->header.v1;
			MsnP2PHeader *new = &new_info->header.v1;

			new->session_id = old->session_id;
			new->flags = P2P_ACK;
			new->ack_id = old->id;
			new->ack_sub_id = old->ack_id;
			new->ack_size = old->total_size;
			break;
		}

		case MSN_P2P_VERSION_TWO: {
			MsnP2Pv2Header *old = &old_info->header.v2;
			MsnP2Pv2Header *new = &new_info->header.v2;

			msn_tlvlist_add_32(&new->header_tlv, P2P_HEADER_TLV_TYPE_ACK, old->base_id + old->message_len);
			new->opcode = P2P_OPCODE_NONE;

			if (old->message_len > 0) {
				if (!msn_tlv_gettlv(old->header_tlv, P2P_HEADER_TLV_TYPE_ACK, 1)) {
					if (old->opcode & P2P_OPCODE_SYN) {
						msn_tlv_t *ack_tlv;
						new->opcode |= P2P_OPCODE_RAK;
						
						ack_tlv = msn_tlv_gettlv(old->header_tlv, P2P_HEADER_TLV_TYPE_PEER_INFO, 1);
						if (ack_tlv) {
							msn_tlvlist_add_tlv(&new->header_tlv, ack_tlv);
							new->opcode |= P2P_OPCODE_SYN;
						}
					}
				}
			}
			break;
		}

		default:
			purple_debug_error("msn", "Invalid P2P Info version: %d\n", old_info->version);
	}
}

gboolean
msn_p2p_info_require_ack(MsnP2PInfo *info)
{
	gboolean ret = FALSE;

	switch (info->version) {
		case MSN_P2P_VERSION_ONE: {
			guint32 flags = msn_p2p_info_get_flags(info);

			ret = flags == P2P_NO_FLAG || flags == P2P_WLM2009_COMP ||
			      msn_p2p_msg_is_data(info);
			break;
		}

		case MSN_P2P_VERSION_TWO:
			ret = (info->header.v2.opcode & P2P_OPCODE_RAK) > 0;
			break;

		default:
			purple_debug_error("msn", "Invalid P2P Info version: %d\n", info->version);
	}

	return ret;
}

gboolean
msn_p2p_info_is_ack(MsnP2PInfo *info)
{
	gboolean ret = FALSE;

	switch (info->version) {
		case MSN_P2P_VERSION_ONE: {
			ret = msn_p2p_info_get_flags(info) == P2P_ACK;
			break;
		}

		case MSN_P2P_VERSION_TWO:
			ret = msn_tlv_gettlv(info->header.v2.header_tlv, P2P_HEADER_TLV_TYPE_ACK, 1) != NULL;
			break;

		default:
			purple_debug_error("msn", "Invalid P2P Info version: %d\n", info->version);
	}

	return ret;
}

void
msn_p2p_info_init_first(MsnP2PInfo *info, MsnP2PInfo *old_info)
{
	switch (info->version) {
		case MSN_P2P_VERSION_ONE:
			info->header.v1.session_id = old_info->header.v1.session_id;
			info->header.v1.flags = old_info->header.v1.flags;
			break;

		case MSN_P2P_VERSION_TWO:
			info->header.v2.data_tf = TF_FIRST;
			break;

		default:
			purple_debug_error("msn", "Invalid P2P Info version: %d\n", info->version);
	}
}

guint32
msn_p2p_info_get_session_id(MsnP2PInfo *info)
{
	guint32 session_id = 0;

	switch (info->version) {
		case MSN_P2P_VERSION_ONE:
			session_id = info->header.v1.session_id;
			break;

		case MSN_P2P_VERSION_TWO:
			session_id = info->header.v2.session_id;
			break;

		default:
			purple_debug_error("msn", "Invalid P2P Info version: %d\n", info->version);
	}

	return session_id;
}

guint32
msn_p2p_info_get_id(MsnP2PInfo *info)
{
	guint32 id = 0;

	switch (info->version) {
		case MSN_P2P_VERSION_ONE:
			id = info->header.v1.id;
			break;

		case MSN_P2P_VERSION_TWO:
			id = info->header.v2.base_id;
			break;

		default:
			purple_debug_error("msn", "Invalid P2P Info version: %d\n", info->version);
	}

	return id;
}

guint64
msn_p2p_info_get_offset(MsnP2PInfo *info)
{
	guint64 offset = 0;

	switch (info->version) {
		case MSN_P2P_VERSION_ONE:
			offset = info->header.v1.offset;
			break;

		case MSN_P2P_VERSION_TWO:
			/* Nothing to do! */
			break;

		default:
			purple_debug_error("msn", "Invalid P2P Info version: %d\n", info->version);
	}

	return offset;
}

guint64
msn_p2p_info_get_total_size(MsnP2PInfo *info)
{
	guint64 total_size = 0;

	switch (info->version) {
		case MSN_P2P_VERSION_ONE:
			total_size = info->header.v1.total_size;
			break;

		case MSN_P2P_VERSION_TWO:
			/* Nothing to do! */
			break;

		default:
			purple_debug_error("msn", "Invalid P2P Info version: %d\n", info->version);
	}

	return total_size;
}

guint32
msn_p2p_info_get_length(MsnP2PInfo *info)
{
	guint32 length = 0;

	switch (info->version) {
		case MSN_P2P_VERSION_ONE:
			length = info->header.v1.length;
			break;

		case MSN_P2P_VERSION_TWO:
			/* Nothing to do! */
			break;

		default:
			purple_debug_error("msn", "Invalid P2P Info version: %d\n", info->version);
	}

	return length;
}

guint32
msn_p2p_info_get_flags(MsnP2PInfo *info)
{
	guint32 flags = 0;

	switch (info->version) {
		case MSN_P2P_VERSION_ONE:
			flags = info->header.v1.flags;
			break;

		case MSN_P2P_VERSION_TWO:
			flags = info->header.v2.data_tf;
			break;

		default:
			purple_debug_error("msn", "Invalid P2P Info version: %d\n", info->version);
	}

	return flags;
}

guint32
msn_p2p_info_get_ack_id(MsnP2PInfo *info)
{
	guint32 ack_id = 0;

	switch (info->version) {
		case MSN_P2P_VERSION_ONE:
			ack_id = info->header.v1.ack_id;
			break;

		case MSN_P2P_VERSION_TWO:
			/* Nothing to do! */
			break;

		default:
			purple_debug_error("msn", "Invalid P2P Info version: %d\n", info->version);
	}

	return ack_id;
}

guint32
msn_p2p_info_get_ack_sub_id(MsnP2PInfo *info)
{
	guint32 ack_sub_id = 0;

	switch (info->version) {
		case MSN_P2P_VERSION_ONE:
			ack_sub_id = info->header.v1.ack_sub_id;
			break;

		case MSN_P2P_VERSION_TWO:
			/* Nothing to do! */
			break;

		default:
			purple_debug_error("msn", "Invalid P2P Info version: %d\n", info->version);
	}

	return ack_sub_id;
}

guint64
msn_p2p_info_get_ack_size(MsnP2PInfo *info)
{
	guint64 ack_size = 0;

	switch (info->version) {
		case MSN_P2P_VERSION_ONE:
			ack_size = info->header.v1.ack_size;
			break;

		case MSN_P2P_VERSION_TWO:
			/* Nothing to do! */
			break;

		default:
			purple_debug_error("msn", "Invalid P2P Info version: %d\n", info->version);
	}

	return ack_size;
}

guint32
msn_p2p_info_get_app_id(MsnP2PInfo *info)
{
	return info->footer.value;
}

void
msn_p2p_info_set_session_id(MsnP2PInfo *info, guint32 session_id)
{
	switch (info->version) {
		case MSN_P2P_VERSION_ONE:
			info->header.v1.session_id = session_id;
			break;

		case MSN_P2P_VERSION_TWO:
			info->header.v2.session_id = session_id;
			break;

		default:
			purple_debug_error("msn", "Invalid P2P Info version: %d\n", info->version);
	}

}

void
msn_p2p_info_set_id(MsnP2PInfo *info, guint32 id)
{
	switch (info->version) {
		case MSN_P2P_VERSION_ONE:
			info->header.v1.id = id;
			break;

		case MSN_P2P_VERSION_TWO:
			info->header.v2.base_id = id;
			break;

		default:
			purple_debug_error("msn", "Invalid P2P Info version: %d\n", info->version);
	}

}

void
msn_p2p_info_set_offset(MsnP2PInfo *info, guint64 offset)
{
	switch (info->version) {
		case MSN_P2P_VERSION_ONE:
			info->header.v1.offset = offset;
			break;

		case MSN_P2P_VERSION_TWO:
			/* Nothing to do! */
			break;

		default:
			purple_debug_error("msn", "Invalid P2P Info version: %d\n", info->version);
	}
}

void
msn_p2p_info_set_total_size(MsnP2PInfo *info, guint64 total_size)
{
	switch (info->version) {
		case MSN_P2P_VERSION_ONE:
			info->header.v1.total_size = total_size;
			break;

		case MSN_P2P_VERSION_TWO:
			/* Nothing to do! */
			break;

		default:
			purple_debug_error("msn", "Invalid P2P Info version: %d\n", info->version);
	}
}

void
msn_p2p_info_set_length(MsnP2PInfo *info, guint32 length)
{
	switch (info->version) {
		case MSN_P2P_VERSION_ONE:
			info->header.v1.length = length;
			break;

		case MSN_P2P_VERSION_TWO:
			/* Nothing to do! */
			break;

		default:
			purple_debug_error("msn", "Invalid P2P Info version: %d\n", info->version);
	}
}

void
msn_p2p_info_set_flags(MsnP2PInfo *info, guint32 flags)
{
	switch (info->version) {
		case MSN_P2P_VERSION_ONE:
			info->header.v1.flags = flags;
			break;

		case MSN_P2P_VERSION_TWO:
			info->header.v2.data_tf = flags;
			break;

		default:
			purple_debug_error("msn", "Invalid P2P Info version: %d\n", info->version);
	}
}

void
msn_p2p_info_set_ack_id(MsnP2PInfo *info, guint32 ack_id)
{
	switch (info->version) {
		case MSN_P2P_VERSION_ONE:
			info->header.v1.ack_id = ack_id;
			break;

		case MSN_P2P_VERSION_TWO:
			/* Nothing to do! */
			break;

		default:
			purple_debug_error("msn", "Invalid P2P Info version: %d\n", info->version);
	}
}

void
msn_p2p_info_set_ack_sub_id(MsnP2PInfo *info, guint32 ack_sub_id)
{
	switch (info->version) {
		case MSN_P2P_VERSION_ONE:
			info->header.v1.ack_sub_id = ack_sub_id;
			break;

		case MSN_P2P_VERSION_TWO:
			/* Nothing to do! */
			break;

		default:
			purple_debug_error("msn", "Invalid P2P Info version: %d\n", info->version);
	}
}

void
msn_p2p_info_set_ack_size(MsnP2PInfo *info, guint64 ack_size)
{
	switch (info->version) {
		case MSN_P2P_VERSION_ONE:
			info->header.v1.ack_size = ack_size;
			break;

		case MSN_P2P_VERSION_TWO:
			/* Nothing to do! */
			break;

		default:
			purple_debug_error("msn", "Invalid P2P Info version: %d\n", info->version);
	}
}

void
msn_p2p_info_set_app_id(MsnP2PInfo *info, guint32 app_id)
{
	info->footer.value = app_id;
}

