/**
 * @file xfer.c MSN File Transfer functions
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

#include "msnutils.h"
#include "sbconn.h"
#include "xfer.h"

/**************************************************************************
 * Xfer
 **************************************************************************/

void
msn_xfer_init(PurpleXfer *xfer)
{
	MsnSlpCall *slpcall;
	/* MsnSlpLink *slplink; */
	char *content;

	purple_debug_info("msn", "xfer_init\n");

	slpcall = xfer->data;

	/* Send Ok */
	content = g_strdup_printf("SessionID: %lu\r\n\r\n",
							  slpcall->session_id);

	msn_slp_send_ok(slpcall, slpcall->branch, "application/x-msnmsgr-sessionreqbody",
			content);

	g_free(content);
	msn_slplink_send_queued_slpmsgs(slpcall->slplink);
}

void
msn_xfer_cancel(PurpleXfer *xfer)
{
	MsnSlpCall *slpcall;
	char *content;

	g_return_if_fail(xfer != NULL);
	g_return_if_fail(xfer->data != NULL);

	slpcall = xfer->data;

	if (purple_xfer_get_status(xfer) == PURPLE_XFER_STATUS_CANCEL_LOCAL)
	{
		if (slpcall->started)
		{
			msn_slpcall_close(slpcall);
		}
		else
		{
			content = g_strdup_printf("SessionID: %lu\r\n\r\n",
									slpcall->session_id);

			msn_slp_send_decline(slpcall, slpcall->branch, "application/x-msnmsgr-sessionreqbody",
						content);

			g_free(content);
			msn_slplink_send_queued_slpmsgs(slpcall->slplink);

			if (purple_xfer_get_type(xfer) == PURPLE_XFER_SEND)
				slpcall->wasted = TRUE;
			else
				msn_slpcall_destroy(slpcall);
		}
	}
}

gssize
msn_xfer_write(const guchar *data, gsize len, PurpleXfer *xfer)
{
	MsnSlpCall *slpcall;

	g_return_val_if_fail(xfer != NULL, -1);
	g_return_val_if_fail(data != NULL, -1);
	g_return_val_if_fail(len > 0, -1);

	g_return_val_if_fail(purple_xfer_get_type(xfer) == PURPLE_XFER_SEND, -1);

	slpcall = xfer->data;
	/* Not sure I trust it'll be there */
	g_return_val_if_fail(slpcall != NULL, -1);

	g_return_val_if_fail(slpcall->xfer_msg != NULL, -1);

	slpcall->u.outgoing.len = len;
	slpcall->u.outgoing.data = data;
	msn_slplink_send_msgpart(slpcall->slplink, slpcall->xfer_msg);

	return MIN(MSN_SBCONN_MAX_SIZE, len);
}

gssize
msn_xfer_read(guchar **data, PurpleXfer *xfer)
{
	MsnSlpCall *slpcall;
	gsize len;

	g_return_val_if_fail(xfer != NULL, -1);
	g_return_val_if_fail(data != NULL, -1);

	g_return_val_if_fail(purple_xfer_get_type(xfer) == PURPLE_XFER_RECEIVE, -1);

	slpcall = xfer->data;
	/* Not sure I trust it'll be there */
	g_return_val_if_fail(slpcall != NULL, -1);

	/* Just pass up the whole GByteArray. We'll make another. */
	*data = slpcall->u.incoming_data->data;
	len = slpcall->u.incoming_data->len;

	g_byte_array_free(slpcall->u.incoming_data, FALSE);
	slpcall->u.incoming_data = g_byte_array_new();

	return len;
}

void
msn_xfer_end_cb(MsnSlpCall *slpcall, MsnSession *session)
{
	if ((purple_xfer_get_status(slpcall->xfer) != PURPLE_XFER_STATUS_DONE) &&
		(purple_xfer_get_status(slpcall->xfer) != PURPLE_XFER_STATUS_CANCEL_REMOTE) &&
		(purple_xfer_get_status(slpcall->xfer) != PURPLE_XFER_STATUS_CANCEL_LOCAL))
	{
		purple_xfer_cancel_remote(slpcall->xfer);
	}
}

void
msn_xfer_completed_cb(MsnSlpCall *slpcall, const guchar *body,
					  gsize size)
{
	PurpleXfer *xfer = slpcall->xfer;

	purple_xfer_set_completed(xfer, TRUE);
	purple_xfer_end(xfer);
}

gchar *
msn_file_context_to_wire(MsnFileContext *context)
{
	gchar *ret, *tmp;

	tmp = ret = g_new(gchar, MSN_FILE_CONTEXT_SIZE + context->preview_len + 1);

	msn_push32le(tmp, context->length);
	msn_push32le(tmp, context->version);
	msn_push64le(tmp, context->file_size);
	msn_push32le(tmp, context->type);
	memcpy(tmp, context->file_name, MAX_FILE_NAME_LEN * 2);
	tmp += MAX_FILE_NAME_LEN * 2;
	memcpy(tmp, context->unknown1, sizeof(context->unknown1));
	tmp += sizeof(context->unknown1);
	msn_push32le(tmp, context->unknown2);
	if (context->preview) {
		memcpy(tmp, context->preview, context->preview_len);
	}
	tmp[context->preview_len] = '\0';

	return ret;
}

MsnFileContext *
msn_file_context_from_wire(const char *buf, gsize len)
{
	MsnFileContext *context;

	if (!buf || len < MSN_FILE_CONTEXT_SIZE)
		return NULL;

	context = g_new(MsnFileContext, 1);

	context->length = msn_pop32le(buf);
	context->version = msn_pop32le(buf);
	if (context->version == 2) {
		/* The length field is broken for this version. No check. */
		context->length = MSN_FILE_CONTEXT_SIZE;
	} else if (context->version == 3) {
		if (context->length != MSN_FILE_CONTEXT_SIZE + 63) {
			g_free(context);
			return NULL;
		} else if (len < MSN_FILE_CONTEXT_SIZE + 63) {
			g_free(context);
			return NULL;
		}
	} else {
		purple_debug_warning("msn", "Received MsnFileContext with unknown version: %d\n", context->version);
		g_free(context);
		return NULL;
	}

	context->file_size = msn_pop64le(buf);
	context->type = msn_pop32le(buf);
	memcpy(context->file_name, buf, MAX_FILE_NAME_LEN * 2);
	buf += MAX_FILE_NAME_LEN * 2;
	memcpy(context->unknown1, buf, sizeof(context->unknown1));
	buf += sizeof(context->unknown1);
	context->unknown2 = msn_pop32le(buf);

	if (context->type == 0 && len > context->length) {
		context->preview_len = len - context->length;
		context->preview = g_memdup(buf, context->preview_len);
	} else {
		context->preview_len = 0;
		context->preview = NULL;
	}

	return context;
}

