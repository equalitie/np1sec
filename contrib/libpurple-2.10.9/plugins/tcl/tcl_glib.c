/*
 * Tcl/Glib glue
 *
 * Copyright (C) 2003, 2004, 2006 Ethan Blanton <eblanton@cs.purdue.edu>
 *
 * This file is dual-licensed under the two sets of terms below.  You may
 * use, redistribute, or modify it pursuant to either the set of conditions
 * under "TERMS 1" or "TERMS 2", at your discretion.  The DISCLAIMER
 * applies to both sets of terms.
 *
 * TERMS 1
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02111-1301  USA
 *
 * TERMS 2
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must contain the above copyright
 *    notice and this comment block in their entirety.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice and the text of this comment block in their entirety in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * DISCLAIMER
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

/*
 * NOTES
 *
 * This file was developed for the Purple project.  It inserts the Tcl
 * event loop into the glib2 event loop for the purposes of providing
 * Tcl bindings in a glib2 (e.g. Gtk2) program.  To use it, simply
 * link it into your executable, include tcl_glib.h, and call the
 * function tcl_glib_init() before creating or using any Tcl
 * interpreters.  Then go ahead and use Tcl, Tk, whatever to your
 * heart's content.
 *
 * BUGS
 *
 * tcl_wait_for_event seems to have a bug that makes vwait not work so
 * well...  I'm not sure why, yet, but I haven't put much time into
 * it.  Hopefully I will figure it out soon.  In the meantime, this
 * means that Tk's bgerror function (which is called when there is an
 * error in a callback function) causes some Bad Mojo -- you should
 * override it with a function that does not use Tk
 */

#include <tcl.h>
#include <glib.h>
#include <string.h>

#include "tcl_glib.h"

struct tcl_file_handler {
	int source;
	int fd;
	int mask;
	int pending;
	Tcl_FileProc *proc;
	ClientData data;
};

struct tcl_file_event {
	Tcl_Event header;
	int fd;
};

static guint tcl_timer;
static gboolean tcl_timer_pending;
static GHashTable *tcl_file_handlers;

static void tcl_set_timer(Tcl_Time *timePtr);
static int tcl_wait_for_event(Tcl_Time *timePtr);
static void tcl_create_file_handler(int fd, int mask, Tcl_FileProc *proc, ClientData data);
static void tcl_delete_file_handler(int fd);

static gboolean tcl_kick(gpointer data);
static gboolean tcl_file_callback(GIOChannel *source, GIOCondition condition, gpointer data);
static int tcl_file_event_callback(Tcl_Event *event, int flags);

#undef Tcl_InitNotifier

ClientData Tcl_InitNotifier()
{
	return NULL;
}

void tcl_glib_init ()
{
	Tcl_NotifierProcs notifier;

	memset(&notifier, 0, sizeof(notifier));

	notifier.createFileHandlerProc = tcl_create_file_handler;
	notifier.deleteFileHandlerProc = tcl_delete_file_handler;
	notifier.setTimerProc = tcl_set_timer;
	notifier.waitForEventProc = tcl_wait_for_event;

	Tcl_SetNotifier(&notifier);
	Tcl_SetServiceMode(TCL_SERVICE_ALL);

	tcl_timer_pending = FALSE;
	tcl_file_handlers = g_hash_table_new(g_direct_hash, g_direct_equal);
}

static void tcl_set_timer(Tcl_Time *timePtr)
{
	guint interval;

	if (tcl_timer_pending)
		g_source_remove(tcl_timer);

	if (timePtr == NULL) {
		tcl_timer_pending = FALSE;
		return;
	}

	interval = timePtr->sec * 1000 + (timePtr->usec ? timePtr->usec / 1000 : 0);
	tcl_timer = g_timeout_add(interval, tcl_kick, NULL);
	tcl_timer_pending = TRUE;
}

static int tcl_wait_for_event(Tcl_Time *timePtr)
{
	if (!timePtr || (timePtr->sec == 0 && timePtr->usec == 0)) {
		g_main_context_iteration(NULL, FALSE);
		return 1;
	} else {
		tcl_set_timer(timePtr);
	}

	g_main_context_iteration(NULL, TRUE);

	return 1;
}

static void tcl_create_file_handler(int fd, int mask, Tcl_FileProc *proc, ClientData data)
{
	struct tcl_file_handler *tfh = g_new0(struct tcl_file_handler, 1);
	GIOChannel *channel;
	GIOCondition cond = 0;

	if (g_hash_table_lookup(tcl_file_handlers, GINT_TO_POINTER(fd)))
            tcl_delete_file_handler(fd);

	if (mask & TCL_READABLE)
		cond |= G_IO_IN;
	if (mask & TCL_WRITABLE)
		cond |= G_IO_OUT;
	if (mask & TCL_EXCEPTION)
		cond |= G_IO_ERR|G_IO_HUP|G_IO_NVAL;

	tfh->fd = fd;
	tfh->mask = mask;
	tfh->proc = proc;
	tfh->data = data;

	channel = g_io_channel_unix_new(fd);
	tfh->source = g_io_add_watch_full(channel, G_PRIORITY_DEFAULT, cond, tcl_file_callback, tfh, g_free);
	g_io_channel_unref(channel);

	g_hash_table_insert(tcl_file_handlers, GINT_TO_POINTER(fd), tfh);

	Tcl_ServiceAll();
}

static void tcl_delete_file_handler(int fd)
{
	struct tcl_file_handler *tfh = g_hash_table_lookup(tcl_file_handlers, GINT_TO_POINTER(fd));

	if (tfh == NULL)
		return;

	g_source_remove(tfh->source);
	g_hash_table_remove(tcl_file_handlers, GINT_TO_POINTER(fd));

	Tcl_ServiceAll();
}

static gboolean tcl_kick(gpointer data)
{
	tcl_timer_pending = FALSE;

	Tcl_ServiceAll();

	return FALSE;
}

static gboolean tcl_file_callback(GIOChannel *source, GIOCondition condition, gpointer data)
{
	struct tcl_file_handler *tfh = data;
	struct tcl_file_event *fev;
	int mask = 0;

	if (condition & G_IO_IN)
		mask |= TCL_READABLE;
	if (condition & G_IO_OUT)
		mask |= TCL_WRITABLE;
	if (condition & (G_IO_ERR|G_IO_HUP|G_IO_NVAL))
		mask |= TCL_EXCEPTION;

	if (!(tfh->mask & (mask & ~tfh->pending)))
		return TRUE;

	tfh->pending |= mask;
	fev = (struct tcl_file_event *)ckalloc(sizeof(struct tcl_file_event));
	memset(fev, 0, sizeof(struct tcl_file_event));
	fev->header.proc = tcl_file_event_callback;
	fev->fd = tfh->fd;
	Tcl_QueueEvent((Tcl_Event *)fev, TCL_QUEUE_TAIL);

	Tcl_ServiceAll();

	return TRUE;
}

int tcl_file_event_callback(Tcl_Event *event, int flags)
{
	struct tcl_file_handler *tfh;
	struct tcl_file_event *fev = (struct tcl_file_event *)event;
	int mask;

	if (!(flags & TCL_FILE_EVENTS)) {
		return 0;
	}

	tfh = g_hash_table_lookup(tcl_file_handlers, GINT_TO_POINTER(fev->fd));
	if (tfh == NULL)
		return 1;

	mask = tfh->mask & tfh->pending;
	if (mask)
		(*tfh->proc)(tfh->data, mask);
	tfh->pending = 0;

	return 1;
}
