/**
 * @file history.c MSN history functions
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
#include "msn.h"
#include "history.h"

MsnHistory *
msn_history_new(void)
{
	MsnHistory *history = g_new0(MsnHistory, 1);

	history->trId = 1;

	history->queue = g_queue_new();

	return history;
}

void
msn_history_destroy(MsnHistory *history)
{
	MsnTransaction *trans;

	while ((trans = g_queue_pop_head(history->queue)) != NULL)
		msn_transaction_destroy(trans);

	g_queue_free(history->queue);
	g_free(history);
}

MsnTransaction *
msn_history_find(MsnHistory *history, unsigned int trId)
{
	MsnTransaction *trans;
	GList *list;

	for (list = history->queue->head; list != NULL; list = list->next)
	{
		trans = list->data;
		if (trans->trId == trId)
			return trans;
	}

	return NULL;
}

void
msn_history_add(MsnHistory *history, MsnTransaction *trans)
{
	GQueue *queue;
	int max_elems;

	g_return_if_fail(history != NULL);
	g_return_if_fail(trans   != NULL);

	queue = history->queue;

	trans->trId = history->trId++;

	g_queue_push_tail(queue, trans);

	if (trans->cmdproc->servconn->type == MSN_SERVCONN_NS)
		max_elems = MSN_NS_HIST_ELEMS;
	else
		max_elems = MSN_SB_HIST_ELEMS;

	if (queue->length > max_elems)
	{
		trans = g_queue_pop_head(queue);
		msn_transaction_destroy(trans);
	}
}

