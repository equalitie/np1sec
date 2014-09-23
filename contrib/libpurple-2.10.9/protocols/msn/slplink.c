/**
 * @file slplink.c MSNSLP Link support
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

#include "msn.h"
#include "slplink.h"
#include "slpmsg_part.h"

#include "sbconn.h"
#include "switchboard.h"
#include "slp.h"
#include "p2p.h"

#ifdef MSN_DEBUG_SLP_FILES
static int m_sc = 0;
static int m_rc = 0;

static void
debug_part_to_file(MsnSlpMessage *msg, gboolean send)
{
	char *tmp;
	char *dir;
	char *data;
	int c;
	gsize data_size;

	dir = send ? "send" : "recv";
	c = send ? m_sc++ : m_rc++;
	tmp = g_strdup_printf("%s/msntest/%s/%03d", purple_user_dir(), dir, c);
	data = msn_slpmsg_serialize(msg, &data_size);
	if (!purple_util_write_data_to_file_absolute(tmp, data, data_size))
	{
		purple_debug_error("msn", "could not save debug file\n");
	}
	g_free(tmp);
}
#endif

/**************************************************************************
 * Main
 **************************************************************************/

static MsnSlpLink *
msn_slplink_new(MsnSession *session, const char *username)
{
	MsnSlpLink *slplink;

	g_return_val_if_fail(session != NULL, NULL);

	slplink = g_new0(MsnSlpLink, 1);

	if (purple_debug_is_verbose())
		purple_debug_info("msn", "slplink_new: slplink(%p)\n", slplink);

	slplink->session = session;
	slplink->slp_seq_id = rand() % 0xFFFFFF00 + 4;

	slplink->remote_user = g_strdup(username);
	slplink->p2p_version = MSN_P2P_VERSION_ONE;

	slplink->slp_msg_queue = g_queue_new();

	session->slplinks =
		g_list_append(session->slplinks, slplink);

	return msn_slplink_ref(slplink);
}

static void
msn_slplink_destroy(MsnSlpLink *slplink)
{
	MsnSession *session;

	if (purple_debug_is_verbose())
		purple_debug_info("msn", "slplink_destroy: slplink(%p)\n", slplink);

	if (slplink->swboard != NULL) {
		slplink->swboard->slplinks = g_list_remove(slplink->swboard->slplinks, slplink);
		slplink->swboard = NULL;
	}

	session = slplink->session;

	if (slplink->dc != NULL) {
		slplink->dc->slplink = NULL;
		msn_dc_destroy(slplink->dc);
		slplink->dc = NULL;
	}

	while (slplink->slp_calls != NULL)
		msn_slpcall_destroy(slplink->slp_calls->data);

	g_queue_free(slplink->slp_msg_queue);

	session->slplinks =
		g_list_remove(session->slplinks, slplink);

	g_free(slplink->remote_user);

	g_free(slplink);
}

MsnSlpLink *
msn_slplink_ref(MsnSlpLink *slplink)
{
	g_return_val_if_fail(slplink != NULL, NULL);

	slplink->refs++;
	if (purple_debug_is_verbose())
		purple_debug_info("msn", "slplink ref (%p)[%d]\n", slplink, slplink->refs);

	return slplink;
}

void
msn_slplink_unref(MsnSlpLink *slplink)
{
	g_return_if_fail(slplink != NULL);

	slplink->refs--;
	if (purple_debug_is_verbose())
		purple_debug_info("msn", "slplink unref (%p)[%d]\n", slplink, slplink->refs);

	if (slplink->refs == 0)
		msn_slplink_destroy(slplink);
}

MsnSlpLink *
msn_session_find_slplink(MsnSession *session, const char *who)
{
	GList *l;

	for (l = session->slplinks; l != NULL; l = l->next)
	{
		MsnSlpLink *slplink;

		slplink = l->data;

		if (!strcmp(slplink->remote_user, who))
			return slplink;
	}

	return NULL;
}

MsnSlpLink *
msn_session_get_slplink(MsnSession *session, const char *username)
{
	MsnSlpLink *slplink;

	g_return_val_if_fail(session != NULL, NULL);
	g_return_val_if_fail(username != NULL, NULL);

	slplink = msn_session_find_slplink(session, username);

	if (slplink == NULL)
		slplink = msn_slplink_new(session, username);

	return slplink;
}

void
msn_slplink_add_slpcall(MsnSlpLink *slplink, MsnSlpCall *slpcall)
{
	if (slplink->swboard != NULL)
		slplink->swboard->flag |= MSN_SB_FLAG_FT;

	slplink->slp_calls = g_list_append(slplink->slp_calls, slpcall);

	/*
	if (slplink->dc != NULL && slplink->dc->state == DC_STATE_ESTABLISHED)
		msn_dc_ref(slplink->dc);
	*/
}

void
msn_slplink_remove_slpcall(MsnSlpLink *slplink, MsnSlpCall *slpcall)
{
	/*
	if (slplink->dc != NULL && slplink->dc->state == DC_STATE_ESTABLISHED)
		msn_dc_unref(slplink->dc);
	*/

	slplink->slp_calls = g_list_remove(slplink->slp_calls, slpcall);

	/* The slplink has no slpcalls in it, release it from MSN_SB_FLAG_FT.
	 * If nothing else is using it then this might cause swboard to be
	 * destroyed. */
	if (slplink->slp_calls == NULL && slplink->swboard != NULL) {
		slplink->swboard->slplinks = g_list_remove(slplink->swboard->slplinks, slplink);
		msn_switchboard_release(slplink->swboard, MSN_SB_FLAG_FT);
		slplink->swboard = NULL;
	}

	if (slplink->dc != NULL) {
		if ((slplink->dc->state != DC_STATE_ESTABLISHED && slplink->dc->slpcall == slpcall)
		 || (slplink->slp_calls == NULL)) {
			/* The DC is not established and its corresponding slpcall is dead,
			 * or the slplink has no slpcalls in it and no longer needs the DC.
			 */
			slplink->dc->slplink = NULL;
			msn_dc_destroy(slplink->dc);
			slplink->dc = NULL;
		}
	}
}

MsnSlpCall *
msn_slplink_find_slp_call(MsnSlpLink *slplink, const char *id)
{
	GList *l;
	MsnSlpCall *slpcall;

	if (!id)
		return NULL;

	for (l = slplink->slp_calls; l != NULL; l = l->next)
	{
		slpcall = l->data;

		if (slpcall->id && !strcmp(slpcall->id, id))
			return slpcall;
	}

	return NULL;
}

MsnSlpCall *
msn_slplink_find_slp_call_with_session_id(MsnSlpLink *slplink, long id)
{
	GList *l;
	MsnSlpCall *slpcall;

	for (l = slplink->slp_calls; l != NULL; l = l->next)
	{
		slpcall = l->data;

		if (slpcall->session_id == id)
			return slpcall;
	}

	return NULL;
}

MsnP2PVersion
msn_slplink_get_p2p_version(MsnSlpLink *slplink)
{
	return slplink->p2p_version;
}

static void
msn_slplink_send_part(MsnSlpLink *slplink, MsnSlpMessagePart *part)
{
	if (slplink->dc != NULL && slplink->dc->state == DC_STATE_ESTABLISHED)
	{
		msn_dc_enqueue_part(slplink->dc, part);
	}
	else
	{
		msn_sbconn_send_part(slplink, part);
	}
}

void
msn_slplink_send_msgpart(MsnSlpLink *slplink, MsnSlpMessage *slpmsg)
{
	MsnSlpMessagePart *part;
	MsnP2PInfo *info;
	long long real_size;
	size_t len = 0;
	guint64 offset;

	/* Maybe we will want to create a new msg for this slpmsg instead of
	 * reusing the same one all the time. */
	info = slpmsg->p2p_info;
	part = msn_slpmsgpart_new(msn_p2p_info_dup(info));
	part->ack_data = slpmsg;

	real_size = msn_p2p_info_is_ack(info) ? 0 : slpmsg->size;

	offset = msn_p2p_info_get_offset(info);
	if (offset < real_size)
	{
		if (slpmsg->slpcall && slpmsg->slpcall->xfer && purple_xfer_get_type(slpmsg->slpcall->xfer) == PURPLE_XFER_SEND &&
				purple_xfer_get_status(slpmsg->slpcall->xfer) == PURPLE_XFER_STATUS_STARTED)
		{
			len = MIN(MSN_SBCONN_MAX_SIZE, slpmsg->slpcall->u.outgoing.len);
			msn_slpmsgpart_set_bin_data(part, slpmsg->slpcall->u.outgoing.data, len);
		}
		else
		{
			len = slpmsg->size - offset;

			if (len > MSN_SBCONN_MAX_SIZE)
				len = MSN_SBCONN_MAX_SIZE;

			msn_slpmsgpart_set_bin_data(part, slpmsg->buffer + offset, len);
		}

		msn_p2p_info_set_length(slpmsg->p2p_info, len);
	}

#if 0
	/* TODO: port this function to SlpMessageParts */
	if (purple_debug_is_verbose())
		msn_message_show_readable(msg, slpmsg->info, slpmsg->text_body);
#endif

#ifdef MSN_DEBUG_SLP_FILES
	debug_part_to_file(slpmsg, TRUE);
#endif

	slpmsg->parts = g_list_append(slpmsg->parts, part);
	msn_slplink_send_part(slplink, part);


	if (msn_p2p_msg_is_data(info) && slpmsg->slpcall != NULL)
	{
		slpmsg->slpcall->progress = TRUE;

		if (slpmsg->slpcall->progress_cb != NULL)
		{
			slpmsg->slpcall->progress_cb(slpmsg->slpcall, slpmsg->size,
										 len);
		}
	}

	/* slpmsg->offset += len; */
}

static void
msn_slplink_release_slpmsg(MsnSlpLink *slplink, MsnSlpMessage *slpmsg)
{
	MsnP2PInfo *info;
	guint32 flags;

	info = slpmsg->p2p_info;

	flags = msn_p2p_info_get_flags(info);
	if (flags == P2P_NO_FLAG)
	{
		msn_p2p_info_set_ack_id(info, rand() % 0xFFFFFF00);
	}
	else if (msn_p2p_msg_is_data(info))
	{
		MsnSlpCall *slpcall;
		slpcall = slpmsg->slpcall;

		g_return_if_fail(slpcall != NULL);
		msn_p2p_info_set_session_id(info, slpcall->session_id);
		msn_p2p_info_set_app_id(info, slpcall->app_id);
		msn_p2p_info_set_ack_id(info, rand() % 0xFFFFFF00);
	}

	msn_p2p_info_set_id(info, slpmsg->id);

	msn_p2p_info_set_total_size(info, slpmsg->size);

	msn_slplink_send_msgpart(slplink, slpmsg);
}

void
msn_slplink_queue_slpmsg(MsnSlpLink *slplink, MsnSlpMessage *slpmsg)
{
	g_return_if_fail(slpmsg != NULL);

	slpmsg->id = slplink->slp_seq_id++;

	g_queue_push_tail(slplink->slp_msg_queue, slpmsg);
}

void
msn_slplink_send_slpmsg(MsnSlpLink *slplink, MsnSlpMessage *slpmsg)
{
	slpmsg->id = slplink->slp_seq_id++;

	msn_slplink_release_slpmsg(slplink, slpmsg);
}

void
msn_slplink_send_queued_slpmsgs(MsnSlpLink *slplink)
{
	MsnSlpMessage *slpmsg;

	/* Send the queued msgs in the order they were created */
	while ((slpmsg = g_queue_pop_head(slplink->slp_msg_queue)) != NULL)
	{
		msn_slplink_release_slpmsg(slplink, slpmsg);
	}
}

static void
msn_slplink_send_ack(MsnSlpLink *slplink, MsnP2PInfo *info)
{
	MsnSlpMessage *slpmsg = msn_slpmsg_ack_new(slplink, info);

	msn_slplink_send_slpmsg(slplink, slpmsg);
	msn_slpmsg_destroy(slpmsg);
}

static MsnSlpMessage *
msn_slplink_message_find(MsnSlpLink *slplink, long session_id, long id)
{
	GList *e;

	for (e = slplink->slp_msgs; e != NULL; e = e->next)
	{
		MsnSlpMessage *slpmsg = e->data;

		if ((msn_p2p_info_get_session_id(slpmsg->p2p_info) == session_id) && (slpmsg->id == id))
			return slpmsg;
	}

	return NULL;
}

static MsnSlpMessage *
init_first_msg(MsnSlpLink *slplink, MsnP2PInfo *info)
{
	MsnSlpMessage *slpmsg;
	guint32 session_id;

	slpmsg = msn_slpmsg_new(slplink, NULL);
	slpmsg->id = msn_p2p_info_get_id(info);
	session_id = msn_p2p_info_get_session_id(info);
	slpmsg->size = msn_p2p_info_get_total_size(info);
	msn_p2p_info_init_first(slpmsg->p2p_info, info);

	if (session_id)
	{
		slpmsg->slpcall = msn_slplink_find_slp_call_with_session_id(slplink, session_id);
		if (slpmsg->slpcall != NULL)
		{
			if (msn_p2p_msg_is_data(info))
			{
				PurpleXfer *xfer = slpmsg->slpcall->xfer;
				if (xfer != NULL)
				{
					slpmsg->ft = TRUE;
					slpmsg->slpcall->xfer_msg = slpmsg;

					purple_xfer_ref(xfer);
					purple_xfer_start(xfer,	-1, NULL, 0);

					if (xfer->data == NULL) {
						purple_xfer_unref(xfer);
						msn_slpmsg_destroy(slpmsg);
						g_return_val_if_reached(NULL);
					} else {
						purple_xfer_unref(xfer);
					}
				}
			}
		}
	}
	if (!slpmsg->ft && slpmsg->size)
	{
		slpmsg->buffer = g_try_malloc(slpmsg->size);
		if (slpmsg->buffer == NULL)
		{
			purple_debug_error("msn", "Failed to allocate buffer for slpmsg\n");
			msn_slpmsg_destroy(slpmsg);
			return NULL;
		}
	}

	return slpmsg;
}

static void
process_complete_msg(MsnSlpLink *slplink, MsnSlpMessage *slpmsg, MsnP2PInfo *info)
{
	MsnSlpCall *slpcall;

	slpcall = msn_slp_process_msg(slplink, slpmsg);

	if (slpcall == NULL) {
		msn_slpmsg_destroy(slpmsg);
		return;
	}

	purple_debug_info("msn", "msn_slplink_process_msg: slpmsg complete\n");

	if (msn_p2p_info_require_ack(slpmsg->p2p_info))
	{
		/* Release all the messages and send the ACK */

		if (slpcall->wait_for_socket) {
			/*
			 * Save ack for later because we have to send
			 * a 200 OK message to the previous direct connect
			 * invitation before ACK but the listening socket isn't
			 * created yet.
			 */
			purple_debug_info("msn", "msn_slplink_process_msg: save ACK\n");

			slpcall->slplink->dc->prev_ack = msn_slpmsg_ack_new(slplink, info);
		} else if (!slpcall->wasted) {
			purple_debug_info("msn", "msn_slplink_process_msg: send ACK\n");

			msn_slplink_send_ack(slplink, info);
			msn_slplink_send_queued_slpmsgs(slplink);
		}
	}

	msn_slpmsg_destroy(slpmsg);

	if (!slpcall->wait_for_socket && slpcall->wasted)
		msn_slpcall_destroy(slpcall);
}

static void
slpmsg_add_part(MsnSlpMessage *slpmsg, MsnSlpMessagePart *part)
{
	if (slpmsg->ft) {
		slpmsg->slpcall->u.incoming_data =
				g_byte_array_append(slpmsg->slpcall->u.incoming_data, (const guchar *)part->buffer, part->size);
		purple_xfer_prpl_ready(slpmsg->slpcall->xfer);
	}
	else if (slpmsg->size && slpmsg->buffer) {
		guint64 offset = msn_p2p_info_get_offset(part->info);
		if (G_MAXSIZE - part->size < offset
				|| (offset + part->size) > slpmsg->size
				|| msn_p2p_info_get_offset(slpmsg->p2p_info) != offset) {
			purple_debug_error("msn",
				"Oversized slpmsg - msgsize=%lld offset=%" G_GUINT64_FORMAT " len=%" G_GSIZE_FORMAT "\n",
				slpmsg->size, offset, part->size);
			g_return_if_reached();
		} else {
			memcpy(slpmsg->buffer + offset, part->buffer, part->size);
			msn_p2p_info_set_offset(slpmsg->p2p_info, offset + part->size);
		}
	}
}

void
msn_slplink_process_msg(MsnSlpLink *slplink, MsnSlpMessagePart *part)
{
	MsnSlpMessage *slpmsg;
	MsnP2PInfo *info;

	info = part->info;

	if (!msn_p2p_info_is_valid(info))
	{
		/* We seem to have received a bad header */
		purple_debug_warning("msn", "Total size listed in SLP binary header "
				"was less than length of this particular message.  This "
				"should not happen.  Dropping message.\n");
		return;
	}

	if (msn_p2p_info_is_first(info))
		slpmsg = init_first_msg(slplink, info);
	else {
		guint32 session_id, id;
		session_id = msn_p2p_info_get_session_id(info);
		id = msn_p2p_info_get_id(info);
		slpmsg = msn_slplink_message_find(slplink, session_id, id);
		if (slpmsg == NULL)
		{
			/* Probably the transfer was cancelled */
			purple_debug_error("msn", "Couldn't find slpmsg\n");
			return;
		}
	}

	slpmsg_add_part(slpmsg, part);

	if (msn_p2p_msg_is_data(slpmsg->p2p_info) && slpmsg->slpcall != NULL)
	{
		slpmsg->slpcall->progress = TRUE;

		if (slpmsg->slpcall->progress_cb != NULL)
		{
			slpmsg->slpcall->progress_cb(slpmsg->slpcall, slpmsg->size,
										 part->size);
		}
	}

#if 0
	if (slpmsg->buffer == NULL)
		return;
#endif

	/* All the pieces of the slpmsg have been received */
	if (msn_p2p_info_is_final(info))
		process_complete_msg(slplink, slpmsg, info);

	/* NOTE: The slpmsg will be destroyed in process_complete_msg or left in
	   the slplink until fully received. Don't free it here!
	 */
}

void
msn_slplink_request_object(MsnSlpLink *slplink,
						   const char *info,
						   MsnSlpCb cb,
						   MsnSlpEndCb end_cb,
						   const MsnObject *obj)
{
	MsnSlpCall *slpcall;
	char *msnobj_data;
	char *msnobj_base64;

	g_return_if_fail(slplink != NULL);
	g_return_if_fail(obj     != NULL);

	msnobj_data = msn_object_to_string(obj);
	msnobj_base64 = purple_base64_encode((const guchar *)msnobj_data, strlen(msnobj_data));
	g_free(msnobj_data);

	slpcall = msn_slpcall_new(slplink);
	msn_slpcall_init(slpcall, MSN_SLPCALL_ANY);

	slpcall->data_info = g_strdup(info);
	slpcall->cb = cb;
	slpcall->end_cb = end_cb;

	msn_slpcall_invite(slpcall, MSN_OBJ_GUID, P2P_APPID_OBJ, msnobj_base64);

	g_free(msnobj_base64);
}
