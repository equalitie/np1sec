/**
 * @file eventloop.c Purple Event Loop API
 * @ingroup core
 */

/* purple
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
#include "eventloop.h"

static PurpleEventLoopUiOps *eventloop_ui_ops = NULL;

guint
purple_timeout_add(guint interval, GSourceFunc function, gpointer data)
{
	PurpleEventLoopUiOps *ops = purple_eventloop_get_ui_ops();

	return ops->timeout_add(interval, function, data);
}

guint
purple_timeout_add_seconds(guint interval, GSourceFunc function, gpointer data)
{
	PurpleEventLoopUiOps *ops = purple_eventloop_get_ui_ops();

	if (ops->timeout_add_seconds)
		return ops->timeout_add_seconds(interval, function, data);
	else
		return ops->timeout_add(1000 * interval, function, data);
}

gboolean
purple_timeout_remove(guint tag)
{
	PurpleEventLoopUiOps *ops = purple_eventloop_get_ui_ops();

	return ops->timeout_remove(tag);
}

guint
purple_input_add(int source, PurpleInputCondition condition, PurpleInputFunction func, gpointer user_data)
{
	PurpleEventLoopUiOps *ops = purple_eventloop_get_ui_ops();

	return ops->input_add(source, condition, func, user_data);
}

gboolean
purple_input_remove(guint tag)
{
	PurpleEventLoopUiOps *ops = purple_eventloop_get_ui_ops();

	return ops->input_remove(tag);
}

int
purple_input_get_error(int fd, int *error)
{
	PurpleEventLoopUiOps *ops = purple_eventloop_get_ui_ops();

	if (ops->input_get_error)
	{
		int ret = ops->input_get_error(fd, error);
		errno = *error;
		return ret;
	}
	else
	{
		socklen_t len;
		len = sizeof(*error);

		return getsockopt(fd, SOL_SOCKET, SO_ERROR, error, &len);
	}
}

void
purple_eventloop_set_ui_ops(PurpleEventLoopUiOps *ops)
{
	eventloop_ui_ops = ops;
}

PurpleEventLoopUiOps *
purple_eventloop_get_ui_ops(void)
{
	g_return_val_if_fail(eventloop_ui_ops != NULL, NULL);

	return eventloop_ui_ops;
}
