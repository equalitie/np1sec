/* GLIB - Library of useful routines for C programming
 * Copyright (C) 1995-1997  Peter Mattis, Spencer Kimball and Josh MacDonald
 *
 * giowin32.c: IO Channels for Win32.
 * Copyright 1998 Owen Taylor and Tor Lillqvist
 * Copyright 1999-2000 Tor Lillqvist and Craig Setera
 * Copyright 2001-2003 Andrew Lanoix
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02111-1301, USA.
 */

/*
 * Modified by the GLib Team and others 1997-2000.  See the AUTHORS
 * file for a list of people on the GLib Team.  See the ChangeLog
 * files for a list of changes.  These files are distributed with
 * GLib at ftp://ftp.gtk.org/pub/gtk/.
 */

/* Define this to get (very) verbose logging of all channels */
/* #define G_IO_WIN32_DEBUG */

/* #include "config.h" */

#include <glib.h>

#include <stdlib.h>
#include <winsock2.h>
#include <windows.h>
#include <fcntl.h>
#include <io.h>
#include <process.h>
#include <errno.h>
#include <sys/stat.h>

#include <glib/gstdio.h>

typedef struct _GIOWin32Channel GIOWin32Channel;
typedef struct _GIOWin32Watch GIOWin32Watch;

#define BUFFER_SIZE 4096

GIOChannel *wpurple_g_io_channel_win32_new_socket (int socket);

typedef enum {
  G_IO_WIN32_WINDOWS_MESSAGES,	/* Windows messages */
  G_IO_WIN32_FILE_DESC,		/* Unix-like file descriptors from
				 * _open() or _pipe(). Read with read().
				 * Have to create separate thread to read.
				 */
  G_IO_WIN32_SOCKET		/* Sockets. A separate thread is blocked
				 * in select() most of the time.
				 */
} GIOWin32ChannelType;

struct _GIOWin32Channel {
  GIOChannel channel;
  gint fd;			/* Either a Unix-like file handle as provided
				 * by the Microsoft C runtime, or a SOCKET
				 * as provided by WinSock.
				 */
  GIOWin32ChannelType type;

  gboolean debug;

  CRITICAL_SECTION mutex;

  /* This is used by G_IO_WIN32_WINDOWS_MESSAGES channels */
  HWND hwnd;			/* handle of window, or NULL */

  /* Following fields are used by both fd and socket channels. */
  gboolean running;		/* Is reader thread running. FALSE if
				 * EOF has been reached.
				 */
  gboolean needs_close;		/* If the channel has been closed while
				 * the reader thread was still running.
				 */
  guint thread_id;		/* If non-NULL has a reader thread, or has
				 * had.*/
  HANDLE data_avail_event;

  gushort revents;

  /* Following fields used by fd channels for input */

  /* Data is kept in a circular buffer. To be able to distinguish between
   * empty and full buffer, we cannot fill it completely, but have to
   * leave a one character gap.
   *
   * Data available is between indexes rdp and wrp-1 (modulo BUFFER_SIZE).
   *
   * Empty:    wrp == rdp
   * Full:     (wrp + 1) % BUFFER_SIZE == rdp
   * Partial:  otherwise
   */
  guchar *buffer;		/* (Circular) buffer */
  gint wrp, rdp;		/* Buffer indices for writing and reading */
  HANDLE space_avail_event;

  /* Following fields used by socket channels */
  GSList *watches;
  HANDLE data_avail_noticed_event;
  gint reset_send; /* socket used to send data so select_thread() can reset/re-loop */
  gint reset_recv; /* socket used to recv data so select_thread() can reset/re-loop */
};

#define LOCK(mutex) EnterCriticalSection (&mutex)
#define UNLOCK(mutex) LeaveCriticalSection (&mutex)

struct _GIOWin32Watch {
  GSource       source;
  GPollFD       pollfd;
  GIOChannel   *channel;
  GIOCondition  condition;
};

static void
g_win32_print_gioflags (GIOFlags flags)
{
  char *bar = "";

  if (flags & G_IO_FLAG_APPEND)
    bar = "|", g_print ("APPEND");
  if (flags & G_IO_FLAG_NONBLOCK)
    g_print ("%sNONBLOCK", bar), bar = "|";
  if (flags & G_IO_FLAG_IS_READABLE)
    g_print ("%sREADABLE", bar), bar = "|";
  if (flags & G_IO_FLAG_IS_WRITEABLE)
    g_print ("%sWRITEABLE", bar), bar = "|";
  if (flags & G_IO_FLAG_IS_SEEKABLE)
    g_print ("%sSEEKABLE", bar), bar = "|";
}

static gboolean
g_io_win32_get_debug_flag (void)
{
#ifdef G_IO_WIN32_DEBUG
  return TRUE;
#else
  if (getenv ("G_IO_WIN32_DEBUG") != NULL)
    return TRUE;
  else
    return FALSE;
#endif
}

static void
g_io_channel_win32_init (GIOWin32Channel *channel)
{
  channel->debug = g_io_win32_get_debug_flag ();
  channel->buffer = NULL;
  channel->running = FALSE;
  channel->needs_close = FALSE;
  channel->thread_id = 0;
  channel->data_avail_event = NULL;
  channel->revents = 0;
  channel->space_avail_event = NULL;
  channel->reset_send = INVALID_SOCKET;
  channel->reset_recv = INVALID_SOCKET;
  channel->data_avail_noticed_event = NULL;
  channel->watches = NULL;
  InitializeCriticalSection (&channel->mutex);
}

static void
create_events (GIOWin32Channel *channel)
{
  SECURITY_ATTRIBUTES sec_attrs;

  sec_attrs.nLength = sizeof (SECURITY_ATTRIBUTES);
  sec_attrs.lpSecurityDescriptor = NULL;
  sec_attrs.bInheritHandle = FALSE;

  /* The data available event is manual reset, the space available event
   * is automatic reset.
   */
  if (!(channel->data_avail_event = CreateEvent (&sec_attrs, TRUE, FALSE, NULL))
      || !(channel->space_avail_event = CreateEvent (&sec_attrs, FALSE, FALSE, NULL))
      || !(channel->data_avail_noticed_event = CreateEvent (&sec_attrs, FALSE, FALSE, NULL)))
    {
      gchar *emsg = g_win32_error_message (GetLastError ());
      g_error ("Error creating event: %s", emsg);
      g_free (emsg);
    }
}

static void
create_thread (GIOWin32Channel     *channel,
	       GIOCondition         condition,
	       unsigned (__stdcall *thread) (void *parameter))
{
  HANDLE thread_handle;

  thread_handle = (HANDLE) _beginthreadex (NULL, 0, thread, channel, 0,
					   &channel->thread_id);
  if (thread_handle == 0)
    g_warning (G_STRLOC ": Error creating reader thread: %s",
	       g_strerror (errno));
  else if (!CloseHandle (thread_handle))
    g_warning (G_STRLOC ": Error closing thread handle: %s\n",
	       g_win32_error_message (GetLastError ()));

  WaitForSingleObject (channel->space_avail_event, INFINITE);
}

static void
init_reset_sockets (GIOWin32Channel *channel)
{
  struct sockaddr_in local, local2, server;
  int len;

  channel->reset_send = (gint) socket (AF_INET, SOCK_DGRAM, 0);
  if (channel->reset_send == INVALID_SOCKET)
    {
      g_warning (G_STRLOC ": Error creating reset_send socket: %s\n",
		 g_win32_error_message (WSAGetLastError ()));
    }

  local.sin_family = AF_INET;
  local.sin_port = 0;
  local.sin_addr.s_addr = htonl (INADDR_LOOPBACK);

  if (bind (channel->reset_send, (struct sockaddr *)&local, sizeof (local)) == SOCKET_ERROR)
    {
      g_warning (G_STRLOC ": Error binding to reset_send socket: %s\n",
		 g_win32_error_message (WSAGetLastError ()));
  }

  local2.sin_family = AF_INET;
  local2.sin_port = 0;
  local2.sin_addr.s_addr = htonl (INADDR_LOOPBACK);

  channel->reset_recv = (gint) socket (AF_INET, SOCK_DGRAM, 0);
  if (channel->reset_recv == INVALID_SOCKET)
    {
      g_warning (G_STRLOC ": Error creating reset_recv socket: %s\n",
		 g_win32_error_message (WSAGetLastError ()));
  }

  if (bind (channel->reset_recv, (struct sockaddr *)&local2, sizeof (local)) == SOCKET_ERROR)
    {
      g_warning (G_STRLOC ": Error binding to reset_recv socket: %s\n",
		 g_win32_error_message (WSAGetLastError ()));
    }

  len = sizeof (local2);
  if (getsockname (channel->reset_recv, (struct sockaddr *)&local2, &len) == SOCKET_ERROR)
    {
      g_warning (G_STRLOC ": Error getsockname with reset_recv socket: %s\n",
		 g_win32_error_message (WSAGetLastError ()));
    }

  memset (&server, 0, sizeof (server));
  server.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  server.sin_family = AF_INET;
  server.sin_port = local2.sin_port;

  if (connect (channel->reset_send, (struct sockaddr  *)&server, sizeof (server)) == SOCKET_ERROR)
    {
      g_warning (G_STRLOC ": connect to reset_recv socket: %s\n",
		 g_win32_error_message (WSAGetLastError ()));
  }

}

static unsigned __stdcall
select_thread (void *parameter)
{
  GIOWin32Channel *channel = parameter;
  fd_set read_fds, write_fds, except_fds;
  GSList *tmp;
  int n;
  char buffer[8];

  g_io_channel_ref ((GIOChannel *)channel);

  if (channel->debug)
    g_print ("select_thread %#x: start fd:%d data_avail:%#x data_avail_noticed:%#x\n",
	     channel->thread_id,
	     channel->fd,
	     (guint) channel->data_avail_event,
	     (guint) channel->data_avail_noticed_event);

  channel->rdp = channel->wrp = 0;
  channel->running = TRUE;

  SetEvent (channel->space_avail_event);

  while (channel->running)
    {
      FD_ZERO (&read_fds);
      FD_ZERO (&write_fds);
      FD_ZERO (&except_fds);
      FD_SET (channel->reset_recv, &read_fds);

      LOCK (channel->mutex);
      tmp = channel->watches;
      while (tmp)
	{
	  GIOWin32Watch *watch = (GIOWin32Watch *)tmp->data;

	  if (watch->condition & (G_IO_IN | G_IO_HUP))
	    FD_SET (channel->fd, &read_fds);
	  if (watch->condition & G_IO_OUT)
	    FD_SET (channel->fd, &write_fds);
	  if (watch->condition & G_IO_ERR)
	    FD_SET (channel->fd, &except_fds);

	  tmp = tmp->next;
	}
      UNLOCK (channel->mutex);

      if (channel->debug)
	g_print ("select_thread %#x: calling select() for%s%s%s\n",
		 channel->thread_id,
		 (FD_ISSET (channel->fd, &read_fds) ? " IN" : ""),
		 (FD_ISSET (channel->fd, &write_fds) ? " OUT" : ""),
		 (FD_ISSET (channel->fd, &except_fds) ? " ERR" : ""));

      n = select (1, &read_fds, &write_fds, &except_fds, NULL);

      LOCK (channel->mutex);
      if (channel->needs_close)
	{
	  UNLOCK (channel->mutex);
	  break;
	}
      UNLOCK (channel->mutex);

      if (n == SOCKET_ERROR)
	{
	  if (channel->debug)
	    g_print ("select_thread %#x: select returned SOCKET_ERROR\n",
		     channel->thread_id);
	  break;
	}

    if (FD_ISSET (channel->reset_recv, &read_fds))
    {
      if (channel->debug)
        g_print ("select_thread %#x: re-looping\n",
            channel->thread_id);
      recv (channel->reset_recv,  (char *)&buffer, (int) sizeof (buffer), 0);
      continue;
    }

    if (channel->debug)
      g_print ("select_thread %#x: got%s%s%s\n",
	       channel->thread_id,
	       (FD_ISSET (channel->fd, &read_fds) ? " IN" : ""),
	       (FD_ISSET (channel->fd, &write_fds) ? " OUT" : ""),
	       (FD_ISSET (channel->fd, &except_fds) ? " ERR" : ""));

    if (FD_ISSET (channel->fd, &read_fds))
      channel->revents |= G_IO_IN;
    if (FD_ISSET (channel->fd, &write_fds))
      channel->revents |= G_IO_OUT;
    if (FD_ISSET (channel->fd, &except_fds))
      channel->revents |= G_IO_ERR;

    if (channel->debug)
      g_print ("select_thread %#x: resetting data_avail_noticed, setting data_avail\n",
	       channel->thread_id);

    LOCK (channel->mutex);
    ResetEvent (channel->data_avail_noticed_event);
    SetEvent (channel->data_avail_event);
    if (channel->needs_close)
      {
	UNLOCK (channel->mutex);
	break;
      }
    UNLOCK (channel->mutex);

    if (channel->debug)
      g_print ("select_thread %#x: waiting for data_avail_noticed\n",
        channel->thread_id);

    WaitForSingleObject (channel->data_avail_noticed_event, INFINITE);
    if (channel->debug)
      g_print ("select_thread %#x: got data_avail_noticed\n",
		 channel->thread_id);
    }

  LOCK (channel->mutex);
  channel->running = FALSE;
  if (channel->debug)
    g_print ("select_thread %#x: got error, setting data_avail\n",
	     channel->thread_id);
  SetEvent (channel->data_avail_event);
  UNLOCK (channel->mutex);
  g_io_channel_unref ((GIOChannel *)channel);

  /* No need to call _endthreadex(), the actual thread starter routine
   * in MSVCRT (see crt/src/threadex.c:_threadstartex) calls
   * _endthreadex() for us.
   */

  return 0;
}

static gboolean
g_io_win32_prepare (GSource *source,
		    gint    *timeout)
{
  GIOWin32Watch *watch = (GIOWin32Watch *)source;
  GIOCondition buffer_condition = g_io_channel_get_buffer_condition (watch->channel);
  GIOWin32Channel *channel = (GIOWin32Channel *)watch->channel;

  *timeout = -1;

  if (channel->debug)
    g_print ("g_io_win32_prepare: for thread %#x buffer_condition:%#x\n"
	     "  watch->pollfd.events:%#x watch->pollfd.revents:%#x channel->revents:%#x\n",
	     channel->thread_id, buffer_condition,
	     watch->pollfd.events, watch->pollfd.revents, channel->revents);

  if (channel->type == G_IO_WIN32_FILE_DESC)
    {
      LOCK (channel->mutex);
      if (channel->running && channel->wrp == channel->rdp)
	{
	  if (channel->debug)
	    g_print ("g_io_win32_prepare: for thread %#x, setting channel->revents = 0\n",
		     channel->thread_id);
	  channel->revents = 0;
	}
      UNLOCK (channel->mutex);
    }
  else if (channel->type == G_IO_WIN32_SOCKET)
    {
      LOCK (channel->mutex);
      channel->revents = 0;
      if (channel->debug)
	g_print ("g_io_win32_prepare: for thread %#x, setting data_avail_noticed\n",
		 channel->thread_id);
      SetEvent (channel->data_avail_noticed_event);
      if (channel->debug)
	g_print ("g_io_win32_prepare: thread %#x, there.\n",
		 channel->thread_id);
      UNLOCK (channel->mutex);
    }

  return ((watch->condition & buffer_condition) == watch->condition);
}

static gboolean
g_io_win32_check (GSource *source)
{
  MSG msg;
  GIOWin32Watch *watch = (GIOWin32Watch *)source;
  GIOWin32Channel *channel = (GIOWin32Channel *)watch->channel;
  GIOCondition buffer_condition = g_io_channel_get_buffer_condition (watch->channel);

  if (channel->debug)
    g_print ("g_io_win32_check: for thread %#x buffer_condition:%#x\n"
	     "  watch->pollfd.events:%#x watch->pollfd.revents:%#x channel->revents:%#x\n",
	     channel->thread_id, buffer_condition,
	     watch->pollfd.events, watch->pollfd.revents, channel->revents);

  if (channel->type != G_IO_WIN32_WINDOWS_MESSAGES)
    {
      watch->pollfd.revents = (watch->pollfd.events & channel->revents);
    }
  else
    {
      return (PeekMessage (&msg, channel->hwnd, 0, 0, PM_NOREMOVE));
    }

  if (channel->type == G_IO_WIN32_SOCKET)
    {
      LOCK (channel->mutex);
      if (channel->debug)
	g_print ("g_io_win32_check: thread %#x, resetting data_avail\n",
		 channel->thread_id);
      ResetEvent (channel->data_avail_event);
      if (channel->debug)
	g_print ("g_io_win32_check: thread %#x, there.\n",
		 channel->thread_id);
      UNLOCK (channel->mutex);
    }

  return ((watch->pollfd.revents | buffer_condition) & watch->condition);
}

static gboolean
g_io_win32_dispatch (GSource     *source,
		     GSourceFunc  callback,
		     gpointer     user_data)
{
  GIOFunc func = (GIOFunc)callback;
  GIOWin32Watch *watch = (GIOWin32Watch *)source;
  GIOCondition buffer_condition = g_io_channel_get_buffer_condition (watch->channel);

  if (!func)
    {
      g_warning (G_STRLOC ": GIOWin32Watch dispatched without callback\n"
		 "You must call g_source_connect().");
      return FALSE;
    }

  return (*func) (watch->channel,
		  (watch->pollfd.revents | buffer_condition) & watch->condition,
		  user_data);
}

static void
g_io_win32_finalize (GSource *source)
{
  GIOWin32Watch *watch = (GIOWin32Watch *)source;
  GIOWin32Channel *channel = (GIOWin32Channel *)watch->channel;
  char send_buffer[] = "f";

  LOCK (channel->mutex);
  if (channel->debug)
    g_print ("g_io_win32_finalize: channel with thread %#x\n",
	     channel->thread_id);

  channel->watches = g_slist_remove (channel->watches, watch);

  SetEvent (channel->data_avail_noticed_event);
  if (channel->type == G_IO_WIN32_SOCKET)
  {
    /* Tell select_thread() to exit */
    channel->needs_close = 1;
    /* Wake up select_thread() from its blocking select() */
    send (channel->reset_send, send_buffer, sizeof (send_buffer), 0);
  }

  UNLOCK (channel->mutex);
  g_io_channel_unref (watch->channel);
}

static GSourceFuncs wp_g_io_watch_funcs = {
  g_io_win32_prepare,
  g_io_win32_check,
  g_io_win32_dispatch,
  g_io_win32_finalize,
  NULL, NULL
};

static GSource *
g_io_win32_create_watch (GIOChannel    *channel,
			 GIOCondition   condition,
			 unsigned (__stdcall *thread) (void *parameter))
{
  GIOWin32Channel *win32_channel = (GIOWin32Channel *)channel;
  GIOWin32Watch *watch;
  GSource *source;
  char send_buffer[] = "c";

  source = g_source_new (&wp_g_io_watch_funcs, sizeof (GIOWin32Watch));
  watch = (GIOWin32Watch *)source;

  watch->channel = channel;
  g_io_channel_ref (channel);

  watch->condition = condition;

  if (win32_channel->data_avail_event == NULL)
    create_events (win32_channel);

  watch->pollfd.fd = (gint) win32_channel->data_avail_event;
  watch->pollfd.events = condition;

  if (win32_channel->debug)
    g_print ("g_io_win32_create_watch: fd:%d condition:%#x handle:%#x\n",
	     win32_channel->fd, condition, watch->pollfd.fd);

  LOCK (win32_channel->mutex);
  win32_channel->watches = g_slist_append (win32_channel->watches, watch);

  if (win32_channel->thread_id == 0)
    create_thread (win32_channel, condition, thread);
  else
    send (win32_channel->reset_send, send_buffer, sizeof (send_buffer), 0);

  g_source_add_poll (source, &watch->pollfd);
  UNLOCK (win32_channel->mutex);

  return source;
}

static void
g_io_win32_free (GIOChannel *channel)
{
  GIOWin32Channel *win32_channel = (GIOWin32Channel *)channel;

  if (win32_channel->debug)
    g_print ("thread %#x: freeing channel, fd: %d\n",
	     win32_channel->thread_id,
	     win32_channel->fd);

  if (win32_channel->reset_send && win32_channel->reset_send != INVALID_SOCKET)
    closesocket (win32_channel->reset_send);
  if (win32_channel->reset_recv && win32_channel->reset_recv != INVALID_SOCKET)
    closesocket (win32_channel->reset_recv);
  if (win32_channel->data_avail_event)
    CloseHandle (win32_channel->data_avail_event);
  if (win32_channel->space_avail_event)
    CloseHandle (win32_channel->space_avail_event);
  if (win32_channel->data_avail_noticed_event)
    CloseHandle (win32_channel->data_avail_noticed_event);
  DeleteCriticalSection (&win32_channel->mutex);

  g_free (win32_channel->buffer);
  g_slist_free (win32_channel->watches);
  g_free (win32_channel);
}

static GIOStatus
g_io_win32_sock_read (GIOChannel *channel,
		      gchar      *buf,
		      gsize       count,
		      gsize      *bytes_read,
		      GError    **err)
{
  GIOWin32Channel *win32_channel = (GIOWin32Channel *)channel;
  gint result;
  GIOChannelError error = G_IO_STATUS_NORMAL;
  GIOStatus internal_status = G_IO_STATUS_NORMAL;
  char send_buffer[] = "sr";

  if (win32_channel->debug)
    g_print ("g_io_win32_sock_read: sockfd:%d count:%d\n",
	     win32_channel->fd, count);
#ifdef WE_NEED_TO_HANDLE_WSAEINTR
repeat:
#endif
  result = recv (win32_channel->fd, buf, count, 0);

  if (win32_channel->debug)
    g_print ("g_io_win32_sock_read: recv:%d\n", result);

  if (result == SOCKET_ERROR)
    {
      *bytes_read = 0;

      switch (WSAGetLastError ())
	{
	case WSAEINVAL:
          error = G_IO_CHANNEL_ERROR_INVAL;
          break;
	case WSAEWOULDBLOCK:
          return G_IO_STATUS_AGAIN;
#ifdef WE_NEED_TO_HANDLE_WSAEINTR /* not anymore with wsock2 ? */
	case WSAEINTR:
          goto repeat;
#endif
	default:
	  error = G_IO_CHANNEL_ERROR_FAILED;
          break;
	}
      g_set_error (err, G_IO_CHANNEL_ERROR, error, "Socket read error");
      internal_status = G_IO_STATUS_ERROR;
      /* FIXME get all errors, better error messages */
    }
  else
    {
      *bytes_read = result;
      if (result == 0)
	internal_status = G_IO_STATUS_EOF;
    }

  if ((internal_status == G_IO_STATUS_EOF) ||
      (internal_status == G_IO_STATUS_ERROR))
    {
      LOCK (win32_channel->mutex);
      SetEvent (win32_channel->data_avail_noticed_event);
      win32_channel->needs_close = 1;
      send (win32_channel->reset_send, send_buffer, sizeof (send_buffer), 0);
      UNLOCK (win32_channel->mutex);
    }
  return internal_status;
}

static GIOStatus
g_io_win32_sock_write (GIOChannel  *channel,
		       const gchar *buf,
		       gsize        count,
		       gsize       *bytes_written,
		       GError     **err)
{
  GIOWin32Channel *win32_channel = (GIOWin32Channel *)channel;
  gint result;
  GIOChannelError error = G_IO_STATUS_NORMAL;
  char send_buffer[] = "sw";

  if (win32_channel->debug)
    g_print ("g_io_win32_sock_write: sockfd:%d count:%d\n",
	     win32_channel->fd, count);
#ifdef WE_NEED_TO_HANDLE_WSAEINTR
repeat:
#endif
  result = send (win32_channel->fd, buf, count, 0);

  if (win32_channel->debug)
    g_print ("g_io_win32_sock_write: send:%d\n", result);

  if (result == SOCKET_ERROR)
    {
      *bytes_written = 0;

      switch (WSAGetLastError ())
	{
	case WSAEINVAL:
	  error = G_IO_CHANNEL_ERROR_INVAL;
          break;
	case WSAEWOULDBLOCK:
          return G_IO_STATUS_AGAIN;
#ifdef WE_NEED_TO_HANDLE_WSAEINTR /* not anymore with wsock2 ? */
	case WSAEINTR:
          goto repeat;
#endif
	default:
	  error = G_IO_CHANNEL_ERROR_FAILED;
          break;
	}
      g_set_error (err, G_IO_CHANNEL_ERROR, error, "Socket write error");
      LOCK (win32_channel->mutex);
      SetEvent (win32_channel->data_avail_noticed_event);
      win32_channel->needs_close = 1;
      send (win32_channel->reset_send, send_buffer, sizeof (send_buffer), 0);
      UNLOCK (win32_channel->mutex);
      return G_IO_STATUS_ERROR;
      /* FIXME get all errors, better error messages */
    }
  else
    {
      *bytes_written = result;

      return G_IO_STATUS_NORMAL;
    }
}

static GIOStatus
g_io_win32_sock_close (GIOChannel *channel,
		       GError    **err)
{
  GIOWin32Channel *win32_channel = (GIOWin32Channel *)channel;

  LOCK (win32_channel->mutex);
  if (win32_channel->running)
    {
      if (win32_channel->debug)
	g_print ("thread %#x: running, marking for later close\n",
		 win32_channel->thread_id);
      win32_channel->running = FALSE;
      win32_channel->needs_close = TRUE;
      SetEvent(win32_channel->data_avail_noticed_event);
    }
  if (win32_channel->fd != -1)
    {
      if (win32_channel->debug)
	g_print ("thread %#x: closing socket %d\n",
		 win32_channel->thread_id,
		 win32_channel->fd);

      closesocket (win32_channel->fd);
      win32_channel->fd = -1;
    }
  UNLOCK (win32_channel->mutex);

  /* FIXME error detection? */

  return G_IO_STATUS_NORMAL;
}

static GSource *
g_io_win32_sock_create_watch (GIOChannel    *channel,
			      GIOCondition   condition)
{
  return g_io_win32_create_watch (channel, condition, select_thread);
}

static GIOStatus
g_io_win32_set_flags (GIOChannel *channel,
                      GIOFlags    flags,
                      GError    **err)
{
  GIOWin32Channel *win32_channel = (GIOWin32Channel *)channel;

  if (win32_channel->debug)
    {
      g_print ("g_io_win32_set_flags: ");
      g_win32_print_gioflags (flags);
      g_print ("\n");
    }

  g_warning ("g_io_win32_set_flags () not implemented.\n");

  return G_IO_STATUS_NORMAL;
}

static GIOFlags
g_io_win32_sock_get_flags (GIOChannel *channel)
{
  /* XXX Could do something here. */
  return 0;
}

static GIOFuncs win32_channel_sock_funcs = {
  g_io_win32_sock_read,
  g_io_win32_sock_write,
  NULL,
  g_io_win32_sock_close,
  g_io_win32_sock_create_watch,
  g_io_win32_free,
  g_io_win32_set_flags,
  g_io_win32_sock_get_flags,
};

GIOChannel *
wpurple_g_io_channel_win32_new_socket (int socket)
{
  GIOWin32Channel *win32_channel = g_new (GIOWin32Channel, 1);
  GIOChannel *channel = (GIOChannel *)win32_channel;

  g_io_channel_init (channel);
  g_io_channel_win32_init (win32_channel);
  init_reset_sockets (win32_channel);
  if (win32_channel->debug)
    g_print ("g_io_channel_win32_new_socket: sockfd:%d\n", socket);
  channel->funcs = &win32_channel_sock_funcs;
  win32_channel->type = G_IO_WIN32_SOCKET;
  win32_channel->fd = socket;

  /* XXX: check this */
  channel->is_readable = TRUE;
  channel->is_writeable = TRUE;

  channel->is_seekable = FALSE;

  return channel;
}

#if 0
void
g_io_channel_win32_set_debug (GIOChannel *channel,
			      gboolean    flag)
{
  GIOWin32Channel *win32_channel = (GIOWin32Channel *)channel;

  win32_channel->debug = flag;
}
#endif

