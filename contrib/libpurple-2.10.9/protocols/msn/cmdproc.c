/**
 * @file cmdproc.c MSN command processor functions
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

#include "cmdproc.h"
#include "error.h"

MsnCmdProc *
msn_cmdproc_new(MsnSession *session)
{
	MsnCmdProc *cmdproc;

	cmdproc = g_new0(MsnCmdProc, 1);

	cmdproc->session = session;
	cmdproc->txqueue = g_queue_new();
	cmdproc->history = msn_history_new();

	cmdproc->multiparts = g_hash_table_new_full(g_str_hash, g_str_equal,
	                                            NULL, (GDestroyNotify)msn_message_unref);

	return cmdproc;
}

void
msn_cmdproc_destroy(MsnCmdProc *cmdproc)
{
	MsnTransaction *trans;

	while ((trans = g_queue_pop_head(cmdproc->txqueue)) != NULL)
		msn_transaction_destroy(trans);

	g_queue_free(cmdproc->txqueue);

	msn_history_destroy(cmdproc->history);

	if (cmdproc->last_cmd != NULL)
		msn_command_unref(cmdproc->last_cmd);

	g_hash_table_destroy(cmdproc->multiparts);

	g_free(cmdproc);
}

void
msn_cmdproc_process_queue(MsnCmdProc *cmdproc)
{
	MsnTransaction *trans;

	while ((trans = g_queue_pop_head(cmdproc->txqueue)) != NULL)
		msn_cmdproc_send_trans(cmdproc, trans);
}

void
msn_cmdproc_queue_trans(MsnCmdProc *cmdproc, MsnTransaction *trans)
{
	g_return_if_fail(cmdproc != NULL);
	g_return_if_fail(trans   != NULL);

	g_queue_push_tail(cmdproc->txqueue, trans);
}

static void
show_debug_cmd(MsnCmdProc *cmdproc, gboolean incoming, const char *command)
{
	MsnServConn *servconn;
	const char *names[] = { "NS", "SB" };
	char *show;
	char tmp;
	size_t len;

	servconn = cmdproc->servconn;
	len = strlen(command);
	show = g_strdup(command);

	tmp = (incoming) ? 'S' : 'C';

	if ((show[len - 1] == '\n') && (show[len - 2] == '\r'))
	{
		show[len - 2] = '\0';
	}

	purple_debug_misc("msn", "%c: %s %03d: %s\n", tmp,
					names[servconn->type], servconn->num, show);

	g_free(show);
}

gboolean
msn_cmdproc_send_trans(MsnCmdProc *cmdproc, MsnTransaction *trans)
{
	MsnServConn *servconn;
	char *data;
	size_t len;
	gboolean ret;

	g_return_val_if_fail(cmdproc != NULL, TRUE);
	g_return_val_if_fail(trans != NULL, TRUE);

	servconn = cmdproc->servconn;

	if (!servconn->connected) {
		msn_transaction_destroy(trans);
		return FALSE;
	}

	if (trans->saveable)
		msn_history_add(cmdproc->history, trans);

	data = msn_transaction_to_string(trans);

	len = strlen(data);

	show_debug_cmd(cmdproc, FALSE, data);

	if (trans->callbacks == NULL)
		trans->callbacks = g_hash_table_lookup(cmdproc->cbs_table->cmds,
											   trans->command);

	if (trans->payload != NULL)
	{
		data = g_realloc(data, len + trans->payload_len);
		memcpy(data + len, trans->payload, trans->payload_len);
		len += trans->payload_len;

		/*
		 * We're done with trans->payload.  Free it so that the memory
		 * doesn't sit around in cmdproc->history.
		 */
		g_free(trans->payload);
		trans->payload = NULL;
		trans->payload_len = 0;
	}

	ret = msn_servconn_write(servconn, data, len) != -1;

	if (!trans->saveable)
		msn_transaction_destroy(trans);
	g_free(data);
	return ret;
}

void
msn_cmdproc_process_payload(MsnCmdProc *cmdproc, char *payload,
							int payload_len)
{
	MsnCommand *last;

	g_return_if_fail(cmdproc != NULL);

	last = cmdproc->last_cmd;
	last->payload = g_memdup(payload, payload_len);
	last->payload_len = payload_len;

	if (last->payload_cb != NULL)
		last->payload_cb(cmdproc, last, payload, payload_len);
}

void
msn_cmdproc_process_msg(MsnCmdProc *cmdproc, MsnMessage *msg)
{
	MsnMsgTypeCb cb;
	const char *message_id = NULL;

	/* Multi-part messages */
	message_id = msn_message_get_header_value(msg, "Message-ID");
	if (message_id != NULL) {
		/* This is the first in a series of chunks */

		const char *chunk_text = msn_message_get_header_value(msg, "Chunks");
		guint chunk;
		if (chunk_text != NULL) {
			chunk = strtol(chunk_text, NULL, 10);
			/* 1024 chunks of ~1300 bytes is ~1MB, which seems OK to prevent
			   some random client causing pidgin to hog a ton of memory.
			   Probably should figure out the maximum that the official client
			   actually supports, though. */
			if (chunk > 0 && chunk < 1024) {
				msg->total_chunks = chunk;
				msg->received_chunks = 1;
				g_hash_table_insert(cmdproc->multiparts, (gpointer)message_id, msn_message_ref(msg));
				purple_debug_info("msn", "Received chunked message, message_id: '%s', total chunks: %d\n",
				                  message_id, chunk);
			} else {
				purple_debug_error("msn", "MessageId '%s' has too many chunks: %d\n", message_id, chunk);
			}
			return;
		} else {
			chunk_text = msn_message_get_header_value(msg, "Chunk");
			if (chunk_text != NULL) {
				/* This is one chunk in a series of chunks */

				MsnMessage *first = g_hash_table_lookup(cmdproc->multiparts, message_id);
				chunk = strtol(chunk_text, NULL, 10);
				if (first != NULL) {
					if (first->received_chunks != chunk) {
						/*
						 * We received an out of order chunk number (i.e. not the
						 * next one in the sequence).  Not sure if this can happen
						 * legitimately, but we definitely don't handle it right
						 * now.
						 */
						g_hash_table_remove(cmdproc->multiparts, message_id);
						return;
					}

					/* Chunk is from 1 to total-1 (doesn't count first one) */
					purple_debug_info("msn", "Received chunk %d of %d, message_id: '%s'\n",
							chunk + 1, first->total_chunks, message_id);
					first->body = g_realloc(first->body, first->body_len + msg->body_len);
					memcpy(first->body + first->body_len, msg->body, msg->body_len);
					first->body_len += msg->body_len;
					first->received_chunks++;
					if (first->received_chunks != first->total_chunks)
						/* We're waiting for more chunks */
						return;

					/*
					 * We have all the chunks for this message, great!  Send
					 * it along... The caller takes care of freeing the old one.
					 */
					msg = first;
				} else {
					purple_debug_error("msn",
					                   "Unable to find first chunk of message_id '%s' to correspond with chunk %d.\n",
					                   message_id, chunk + 1);
				}
			} else {
				purple_debug_error("msn", "Received MessageId '%s' with no chunk number!\n", message_id);
			}
		}
	}

	if (msn_message_get_content_type(msg) == NULL)
	{
		purple_debug_misc("msn", "failed to find message content\n");
		return;
	}

	cb = g_hash_table_lookup(cmdproc->cbs_table->msgs,
							 msn_message_get_content_type(msg));

	if (cb != NULL)
		cb(cmdproc, msg);
	else
		purple_debug_warning("msn", "Unhandled content-type '%s'\n",
						   msn_message_get_content_type(msg));

	if (message_id != NULL)
		g_hash_table_remove(cmdproc->multiparts, message_id);
}

void
msn_cmdproc_process_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
	MsnTransCb cb = NULL;
	MsnTransaction *trans = NULL;

	if (cmd->trId)
		cmd->trans = trans = msn_history_find(cmdproc->history, cmd->trId);

	if (trans != NULL)
		if (trans->timer) {
			purple_timeout_remove(trans->timer);
			trans->timer = 0;
		}

	if (g_ascii_isdigit(cmd->command[0]) && trans != NULL)
	{
		MsnErrorCb error_cb;
		int error;

		error = atoi(cmd->command);

		error_cb = trans->error_cb;
		if (error_cb == NULL)
			error_cb = g_hash_table_lookup(cmdproc->cbs_table->errors, trans->command);

		if (error_cb != NULL)
			error_cb(cmdproc, trans, error);
		else
			msn_error_handle(cmdproc->session, error);

		return;
	}

	cb = g_hash_table_lookup(cmdproc->cbs_table->async, cmd->command);

	if (cb == NULL && trans != NULL && trans->callbacks != NULL)
		cb = g_hash_table_lookup(trans->callbacks, cmd->command);

	if (cb == NULL)
		cb = g_hash_table_lookup(cmdproc->cbs_table->fallback, cmd->command);

	if (cb != NULL)
		cb(cmdproc, cmd);
	else
		purple_debug_warning("msn", "Unhandled command '%s'\n",
						   cmd->command);

	if (trans != NULL && trans->pendent_cmd != NULL)
		msn_transaction_unqueue_cmd(trans, cmdproc);
}

void
msn_cmdproc_process_cmd_text(MsnCmdProc *cmdproc, const char *command)
{
	show_debug_cmd(cmdproc, TRUE, command);

	if (cmdproc->last_cmd != NULL)
		msn_command_unref(cmdproc->last_cmd);

	cmdproc->last_cmd = msn_command_from_string(command);

	msn_cmdproc_process_cmd(cmdproc, cmdproc->last_cmd);
}
