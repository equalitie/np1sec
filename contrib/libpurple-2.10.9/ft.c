/**
 * @file ft.c File Transfer API
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
 *
 */
#include "internal.h"
#include "dbus-maybe.h"
#include "ft.h"
#include "network.h"
#include "notify.h"
#include "prefs.h"
#include "proxy.h"
#include "request.h"
#include "util.h"
#include "debug.h"

#define FT_INITIAL_BUFFER_SIZE 4096
#define FT_MAX_BUFFER_SIZE     65535

static PurpleXferUiOps *xfer_ui_ops = NULL;
static GList *xfers;

/*
 * A hack to store more data since we can't extend the size of PurpleXfer
 * easily.
 */
static GHashTable *xfers_data = NULL;

typedef struct _PurpleXferPrivData {
	/*
	 * Used to moderate the file transfer when either the read/write ui_ops are
	 * set or fd is not set. In those cases, the UI/prpl call the respective
	 * function, which is somewhat akin to a fd watch being triggered.
	 */
	enum {
		PURPLE_XFER_READY_NONE = 0x0,
		PURPLE_XFER_READY_UI   = 0x1,
		PURPLE_XFER_READY_PRPL = 0x2,
	} ready;

	/* TODO: Should really use a PurpleCircBuffer for this. */
	GByteArray *buffer;

	gpointer thumbnail_data;		/**< thumbnail image */
	gsize thumbnail_size;
	gchar *thumbnail_mimetype;
} PurpleXferPrivData;

static int purple_xfer_choose_file(PurpleXfer *xfer);

static void
purple_xfer_priv_data_destroy(gpointer data)
{
	PurpleXferPrivData *priv = data;

	if (priv->buffer)
		g_byte_array_free(priv->buffer, TRUE);

	g_free(priv->thumbnail_data);

	g_free(priv->thumbnail_mimetype);

	g_free(priv);
}

static const gchar *
purple_xfer_status_type_to_string(PurpleXferStatusType type)
{
	static const struct {
		PurpleXferStatusType type;
		const char *name;
	} type_names[] = {
		{ PURPLE_XFER_STATUS_UNKNOWN, "unknown" },
		{ PURPLE_XFER_STATUS_NOT_STARTED, "not started" },
		{ PURPLE_XFER_STATUS_ACCEPTED, "accepted" },
		{ PURPLE_XFER_STATUS_STARTED, "started" },
		{ PURPLE_XFER_STATUS_DONE, "done" },
		{ PURPLE_XFER_STATUS_CANCEL_LOCAL, "cancelled locally" },
		{ PURPLE_XFER_STATUS_CANCEL_REMOTE, "cancelled remotely" }
	};
	int i;

	for (i = 0; i < G_N_ELEMENTS(type_names); ++i)
		if (type_names[i].type == type)
			return type_names[i].name;

	return "invalid state";
}

GList *
purple_xfers_get_all()
{
	return xfers;
}

PurpleXfer *
purple_xfer_new(PurpleAccount *account, PurpleXferType type, const char *who)
{
	PurpleXfer *xfer;
	PurpleXferUiOps *ui_ops;
	PurpleXferPrivData *priv;

	g_return_val_if_fail(type    != PURPLE_XFER_UNKNOWN, NULL);
	g_return_val_if_fail(account != NULL,              NULL);
	g_return_val_if_fail(who     != NULL,              NULL);

	xfer = g_new0(PurpleXfer, 1);
	PURPLE_DBUS_REGISTER_POINTER(xfer, PurpleXfer);

	xfer->ref = 1;
	xfer->type    = type;
	xfer->account = account;
	xfer->who     = g_strdup(who);
	xfer->ui_ops  = ui_ops = purple_xfers_get_ui_ops();
	xfer->message = NULL;
	xfer->current_buffer_size = FT_INITIAL_BUFFER_SIZE;
	xfer->fd = -1;

	priv = g_new0(PurpleXferPrivData, 1);
	priv->ready = PURPLE_XFER_READY_NONE;

	if (ui_ops && ui_ops->data_not_sent) {
		/* If the ui will handle unsent data no need for buffer */
		priv->buffer = NULL;
	} else {
		priv->buffer = g_byte_array_sized_new(FT_INITIAL_BUFFER_SIZE);
	}

	g_hash_table_insert(xfers_data, xfer, priv);

	ui_ops = purple_xfer_get_ui_ops(xfer);

	if (ui_ops != NULL && ui_ops->new_xfer != NULL)
		ui_ops->new_xfer(xfer);

	xfers = g_list_prepend(xfers, xfer);

	if (purple_debug_is_verbose())
		purple_debug_info("xfer", "new %p [%d]\n", xfer, xfer->ref);

	return xfer;
}

static void
purple_xfer_destroy(PurpleXfer *xfer)
{
	PurpleXferUiOps *ui_ops;

	g_return_if_fail(xfer != NULL);

	if (purple_debug_is_verbose())
		purple_debug_info("xfer", "destroyed %p [%d]\n", xfer, xfer->ref);

	/* Close the file browser, if it's open */
	purple_request_close_with_handle(xfer);

	if (purple_xfer_get_status(xfer) == PURPLE_XFER_STATUS_STARTED)
		purple_xfer_cancel_local(xfer);

	ui_ops = purple_xfer_get_ui_ops(xfer);

	if (ui_ops != NULL && ui_ops->destroy != NULL)
		ui_ops->destroy(xfer);

	g_free(xfer->who);
	g_free(xfer->filename);
	g_free(xfer->remote_ip);
	g_free(xfer->local_filename);

	g_hash_table_remove(xfers_data, xfer);

	PURPLE_DBUS_UNREGISTER_POINTER(xfer);
	xfers = g_list_remove(xfers, xfer);
	g_free(xfer);
}

void
purple_xfer_ref(PurpleXfer *xfer)
{
	g_return_if_fail(xfer != NULL);

	xfer->ref++;

	if (purple_debug_is_verbose())
		purple_debug_info("xfer", "ref'd %p [%d]\n", xfer, xfer->ref);
}

void
purple_xfer_unref(PurpleXfer *xfer)
{
	g_return_if_fail(xfer != NULL);
	g_return_if_fail(xfer->ref > 0);

	xfer->ref--;

	if (purple_debug_is_verbose())
		purple_debug_info("xfer", "unref'd %p [%d]\n", xfer, xfer->ref);

	if (xfer->ref == 0)
		purple_xfer_destroy(xfer);
}

static void
purple_xfer_set_status(PurpleXfer *xfer, PurpleXferStatusType status)
{
	g_return_if_fail(xfer != NULL);

	if (purple_debug_is_verbose())
		purple_debug_info("xfer", "Changing status of xfer %p from %s to %s\n",
				xfer, purple_xfer_status_type_to_string(xfer->status),
				purple_xfer_status_type_to_string(status));

	if (xfer->status == status)
		return;

	xfer->status = status;

	if(xfer->type == PURPLE_XFER_SEND) {
		switch(status) {
			case PURPLE_XFER_STATUS_ACCEPTED:
				purple_signal_emit(purple_xfers_get_handle(), "file-send-accept", xfer);
				break;
			case PURPLE_XFER_STATUS_STARTED:
				purple_signal_emit(purple_xfers_get_handle(), "file-send-start", xfer);
				break;
			case PURPLE_XFER_STATUS_DONE:
				purple_signal_emit(purple_xfers_get_handle(), "file-send-complete", xfer);
				break;
			case PURPLE_XFER_STATUS_CANCEL_LOCAL:
			case PURPLE_XFER_STATUS_CANCEL_REMOTE:
				purple_signal_emit(purple_xfers_get_handle(), "file-send-cancel", xfer);
				break;
			default:
				break;
		}
	} else if(xfer->type == PURPLE_XFER_RECEIVE) {
		switch(status) {
			case PURPLE_XFER_STATUS_ACCEPTED:
				purple_signal_emit(purple_xfers_get_handle(), "file-recv-accept", xfer);
				break;
			case PURPLE_XFER_STATUS_STARTED:
				purple_signal_emit(purple_xfers_get_handle(), "file-recv-start", xfer);
				break;
			case PURPLE_XFER_STATUS_DONE:
				purple_signal_emit(purple_xfers_get_handle(), "file-recv-complete", xfer);
				break;
			case PURPLE_XFER_STATUS_CANCEL_LOCAL:
			case PURPLE_XFER_STATUS_CANCEL_REMOTE:
				purple_signal_emit(purple_xfers_get_handle(), "file-recv-cancel", xfer);
				break;
			default:
				break;
		}
	}
}

static void
purple_xfer_conversation_write_internal(PurpleXfer *xfer,
	const char *message, gboolean is_error, gboolean print_thumbnail)
{
	PurpleConversation *conv = NULL;
	PurpleMessageFlags flags = PURPLE_MESSAGE_SYSTEM;
	char *escaped;
	gconstpointer thumbnail_data;
	gsize size;

	g_return_if_fail(xfer != NULL);
	g_return_if_fail(message != NULL);

	thumbnail_data = purple_xfer_get_thumbnail(xfer, &size);

	conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, xfer->who,
											   purple_xfer_get_account(xfer));

	if (conv == NULL)
		return;

	escaped = g_markup_escape_text(message, -1);

	if (is_error)
		flags |= PURPLE_MESSAGE_ERROR;

	if (print_thumbnail && thumbnail_data) {
		gchar *message_with_img;
		gpointer data = g_memdup(thumbnail_data, size);
		int id = purple_imgstore_add_with_id(data, size, NULL);

		message_with_img =
			g_strdup_printf("<img id='%d'> %s", id, escaped);
		purple_conversation_write(conv, NULL, message_with_img, flags,
			time(NULL));
		purple_imgstore_unref_by_id(id);
		g_free(message_with_img);
	} else {
		purple_conversation_write(conv, NULL, escaped, flags, time(NULL));
	}
	g_free(escaped);
}

void
purple_xfer_conversation_write(PurpleXfer *xfer, gchar *message,
	gboolean is_error)
{
	purple_xfer_conversation_write_internal(xfer, message, is_error, FALSE);
}

/* maybe this one should be exported publically? */
static void
purple_xfer_conversation_write_with_thumbnail(PurpleXfer *xfer,
	const gchar *message)
{
	purple_xfer_conversation_write_internal(xfer, message, FALSE, TRUE);
}


static void purple_xfer_show_file_error(PurpleXfer *xfer, const char *filename)
{
	int err = errno;
	gchar *msg = NULL, *utf8;
	PurpleXferType xfer_type = purple_xfer_get_type(xfer);
	PurpleAccount *account = purple_xfer_get_account(xfer);

	utf8 = g_filename_to_utf8(filename, -1, NULL, NULL, NULL);
	switch(xfer_type) {
		case PURPLE_XFER_SEND:
			msg = g_strdup_printf(_("Error reading %s: \n%s.\n"),
								  utf8, g_strerror(err));
			break;
		case PURPLE_XFER_RECEIVE:
			msg = g_strdup_printf(_("Error writing %s: \n%s.\n"),
								  utf8, g_strerror(err));
			break;
		default:
			msg = g_strdup_printf(_("Error accessing %s: \n%s.\n"),
								  utf8, g_strerror(err));
			break;
	}
	g_free(utf8);

	purple_xfer_conversation_write(xfer, msg, TRUE);
	purple_xfer_error(xfer_type, account, xfer->who, msg);
	g_free(msg);
}

static void
purple_xfer_choose_file_ok_cb(void *user_data, const char *filename)
{
	PurpleXfer *xfer;
	PurpleXferType type;
	struct stat st;
	gchar *dir;

	xfer = (PurpleXfer *)user_data;
	type = purple_xfer_get_type(xfer);

	if (g_stat(filename, &st) != 0) {
		/* File not found. */
		if (type == PURPLE_XFER_RECEIVE) {
#ifndef _WIN32
			int mode = W_OK;
#else
			int mode = F_OK;
#endif
			dir = g_path_get_dirname(filename);

			if (g_access(dir, mode) == 0) {
				purple_xfer_request_accepted(xfer, filename);
			} else {
				purple_xfer_ref(xfer);
				purple_notify_message(
					NULL, PURPLE_NOTIFY_MSG_ERROR, NULL,
					_("Directory is not writable."), NULL,
					(PurpleNotifyCloseCallback)purple_xfer_choose_file, xfer);
			}

			g_free(dir);
		}
		else {
			purple_xfer_show_file_error(xfer, filename);
			purple_xfer_cancel_local(xfer);
		}
	}
	else if ((type == PURPLE_XFER_SEND) && (st.st_size == 0)) {

		purple_notify_error(NULL, NULL,
						  _("Cannot send a file of 0 bytes."), NULL);

		purple_xfer_cancel_local(xfer);
	}
	else if ((type == PURPLE_XFER_SEND) && S_ISDIR(st.st_mode)) {
		/*
		 * XXX - Sending a directory should be valid for some protocols.
		 */
		purple_notify_error(NULL, NULL,
						  _("Cannot send a directory."), NULL);

		purple_xfer_cancel_local(xfer);
	}
	else if ((type == PURPLE_XFER_RECEIVE) && S_ISDIR(st.st_mode)) {
		char *msg, *utf8;
		utf8 = g_filename_to_utf8(filename, -1, NULL, NULL, NULL);
		msg = g_strdup_printf(
					_("%s is not a regular file. Cowardly refusing to overwrite it.\n"), utf8);
		g_free(utf8);
		purple_notify_error(NULL, NULL, msg, NULL);
		g_free(msg);
		purple_xfer_request_denied(xfer);
	}
	else if (type == PURPLE_XFER_SEND) {
#ifndef _WIN32
		int mode = R_OK;
#else
		int mode = F_OK;
#endif

		if (g_access(filename, mode) == 0) {
			purple_xfer_request_accepted(xfer, filename);
		} else {
			purple_xfer_ref(xfer);
			purple_notify_message(
				NULL, PURPLE_NOTIFY_MSG_ERROR, NULL,
				_("File is not readable."), NULL,
				(PurpleNotifyCloseCallback)purple_xfer_choose_file, xfer);
		}
	}
	else {
		purple_xfer_request_accepted(xfer, filename);
	}

	purple_xfer_unref(xfer);
}

static void
purple_xfer_choose_file_cancel_cb(void *user_data, const char *filename)
{
	PurpleXfer *xfer = (PurpleXfer *)user_data;

	purple_xfer_set_status(xfer, PURPLE_XFER_STATUS_CANCEL_LOCAL);
	if (purple_xfer_get_type(xfer) == PURPLE_XFER_SEND)
		purple_xfer_cancel_local(xfer);
	else
		purple_xfer_request_denied(xfer);
	purple_xfer_unref(xfer);
}

static int
purple_xfer_choose_file(PurpleXfer *xfer)
{
	purple_request_file(xfer, NULL, purple_xfer_get_filename(xfer),
					  (purple_xfer_get_type(xfer) == PURPLE_XFER_RECEIVE),
					  G_CALLBACK(purple_xfer_choose_file_ok_cb),
					  G_CALLBACK(purple_xfer_choose_file_cancel_cb),
					  purple_xfer_get_account(xfer), xfer->who, NULL,
					  xfer);

	return 0;
}

static int
cancel_recv_cb(PurpleXfer *xfer)
{
	purple_xfer_set_status(xfer, PURPLE_XFER_STATUS_CANCEL_LOCAL);
	purple_xfer_request_denied(xfer);
	purple_xfer_unref(xfer);

	return 0;
}

static void
purple_xfer_ask_recv(PurpleXfer *xfer)
{
	char *buf, *size_buf;
	size_t size;
	gconstpointer thumb;
	gsize thumb_size;

	/* If we have already accepted the request, ask the destination file
	   name directly */
	if (purple_xfer_get_status(xfer) != PURPLE_XFER_STATUS_ACCEPTED) {
		PurpleBuddy *buddy = purple_find_buddy(xfer->account, xfer->who);

		if (purple_xfer_get_filename(xfer) != NULL)
		{
			size = purple_xfer_get_size(xfer);
			size_buf = purple_str_size_to_units(size);
			buf = g_strdup_printf(_("%s wants to send you %s (%s)"),
						  buddy ? purple_buddy_get_alias(buddy) : xfer->who,
						  purple_xfer_get_filename(xfer), size_buf);
			g_free(size_buf);
		}
		else
		{
			buf = g_strdup_printf(_("%s wants to send you a file"),
						buddy ? purple_buddy_get_alias(buddy) : xfer->who);
		}

		if (xfer->message != NULL)
			serv_got_im(purple_account_get_connection(xfer->account),
								 xfer->who, xfer->message, 0, time(NULL));

		if ((thumb = purple_xfer_get_thumbnail(xfer, &thumb_size))) {
			purple_request_accept_cancel_with_icon(xfer, NULL, buf, NULL,
				PURPLE_DEFAULT_ACTION_NONE, xfer->account, xfer->who, NULL,
				thumb, thumb_size, xfer,
				G_CALLBACK(purple_xfer_choose_file),
				G_CALLBACK(cancel_recv_cb));
		} else {
			purple_request_accept_cancel(xfer, NULL, buf, NULL,
				PURPLE_DEFAULT_ACTION_NONE, xfer->account, xfer->who, NULL,
				xfer, G_CALLBACK(purple_xfer_choose_file),
				G_CALLBACK(cancel_recv_cb));
		}

		g_free(buf);
	} else
		purple_xfer_choose_file(xfer);
}

static int
ask_accept_ok(PurpleXfer *xfer)
{
	purple_xfer_request_accepted(xfer, NULL);

	return 0;
}

static int
ask_accept_cancel(PurpleXfer *xfer)
{
	purple_xfer_request_denied(xfer);
	purple_xfer_unref(xfer);

	return 0;
}

static void
purple_xfer_ask_accept(PurpleXfer *xfer)
{
	char *buf, *buf2 = NULL;
	PurpleBuddy *buddy = purple_find_buddy(xfer->account, xfer->who);

	buf = g_strdup_printf(_("Accept file transfer request from %s?"),
				  buddy ? purple_buddy_get_alias(buddy) : xfer->who);
	if (purple_xfer_get_remote_ip(xfer) &&
		purple_xfer_get_remote_port(xfer))
		buf2 = g_strdup_printf(_("A file is available for download from:\n"
					 "Remote host: %s\nRemote port: %d"),
					   purple_xfer_get_remote_ip(xfer),
					   purple_xfer_get_remote_port(xfer));
	purple_request_accept_cancel(xfer, NULL, buf, buf2,
							   PURPLE_DEFAULT_ACTION_NONE,
							   xfer->account, xfer->who, NULL,
							   xfer,
							   G_CALLBACK(ask_accept_ok),
							   G_CALLBACK(ask_accept_cancel));
	g_free(buf);
	g_free(buf2);
}

void
purple_xfer_request(PurpleXfer *xfer)
{
	g_return_if_fail(xfer != NULL);
	g_return_if_fail(xfer->ops.init != NULL);

	purple_xfer_ref(xfer);

	if (purple_xfer_get_type(xfer) == PURPLE_XFER_RECEIVE)
	{
		purple_signal_emit(purple_xfers_get_handle(), "file-recv-request", xfer);
		if (purple_xfer_get_status(xfer) == PURPLE_XFER_STATUS_CANCEL_LOCAL)
		{
			/* The file-transfer was cancelled by a plugin */
			purple_xfer_cancel_local(xfer);
		}
		else if (purple_xfer_get_filename(xfer) ||
		           purple_xfer_get_status(xfer) == PURPLE_XFER_STATUS_ACCEPTED)
		{
			gchar* message = NULL;
			PurpleBuddy *buddy = purple_find_buddy(xfer->account, xfer->who);

			message = g_strdup_printf(_("%s is offering to send file %s"),
				buddy ? purple_buddy_get_alias(buddy) : xfer->who, purple_xfer_get_filename(xfer));
			purple_xfer_conversation_write_with_thumbnail(xfer, message);
			g_free(message);

			/* Ask for a filename to save to if it's not already given by a plugin */
			if (xfer->local_filename == NULL)
				purple_xfer_ask_recv(xfer);
		}
		else
		{
			purple_xfer_ask_accept(xfer);
		}
	}
	else
	{
		purple_xfer_choose_file(xfer);
	}
}

void
purple_xfer_request_accepted(PurpleXfer *xfer, const char *filename)
{
	PurpleXferType type;
	struct stat st;
	char *msg, *utf8, *base;
	PurpleAccount *account;
	PurpleBuddy *buddy;

	if (xfer == NULL)
		return;

	type = purple_xfer_get_type(xfer);
	account = purple_xfer_get_account(xfer);

	purple_debug_misc("xfer", "request accepted for %p\n", xfer);

	if (!filename && type == PURPLE_XFER_RECEIVE) {
		xfer->status = PURPLE_XFER_STATUS_ACCEPTED;
		xfer->ops.init(xfer);
		return;
	}

	buddy = purple_find_buddy(account, xfer->who);

	if (type == PURPLE_XFER_SEND) {
		/* Sending a file */
		/* Check the filename. */
		PurpleXferUiOps *ui_ops;
		ui_ops = purple_xfer_get_ui_ops(xfer);

#ifdef _WIN32
		if (g_strrstr(filename, "../") || g_strrstr(filename, "..\\"))
#else
		if (g_strrstr(filename, "../"))
#endif
		{
			utf8 = g_filename_to_utf8(filename, -1, NULL, NULL, NULL);

			msg = g_strdup_printf(_("%s is not a valid filename.\n"), utf8);
			purple_xfer_error(type, account, xfer->who, msg);
			g_free(utf8);
			g_free(msg);

			purple_xfer_unref(xfer);
			return;
		}

		if (ui_ops == NULL || (ui_ops->ui_read == NULL && ui_ops->ui_write == NULL)) {
			if (g_stat(filename, &st) == -1) {
				purple_xfer_show_file_error(xfer, filename);
				purple_xfer_unref(xfer);
				return;
			}

			purple_xfer_set_local_filename(xfer, filename);
			purple_xfer_set_size(xfer, st.st_size);
		} else {
			purple_xfer_set_local_filename(xfer, filename);
		}

		base = g_path_get_basename(filename);
		utf8 = g_filename_to_utf8(base, -1, NULL, NULL, NULL);
		g_free(base);
		purple_xfer_set_filename(xfer, utf8);

		msg = g_strdup_printf(_("Offering to send %s to %s"),
				utf8, buddy ? purple_buddy_get_alias(buddy) : xfer->who);
		g_free(utf8);
		purple_xfer_conversation_write(xfer, msg, FALSE);
		g_free(msg);
	}
	else {
		/* Receiving a file */
		xfer->status = PURPLE_XFER_STATUS_ACCEPTED;
		purple_xfer_set_local_filename(xfer, filename);

		msg = g_strdup_printf(_("Starting transfer of %s from %s"),
				xfer->filename, buddy ? purple_buddy_get_alias(buddy) : xfer->who);
		purple_xfer_conversation_write(xfer, msg, FALSE);
		g_free(msg);
	}

	purple_xfer_add(xfer);
	xfer->ops.init(xfer);

}

void
purple_xfer_request_denied(PurpleXfer *xfer)
{
	g_return_if_fail(xfer != NULL);

	purple_debug_misc("xfer", "xfer %p denied\n", xfer);

	if (xfer->ops.request_denied != NULL)
		xfer->ops.request_denied(xfer);

	purple_xfer_unref(xfer);
}

PurpleXferType
purple_xfer_get_type(const PurpleXfer *xfer)
{
	g_return_val_if_fail(xfer != NULL, PURPLE_XFER_UNKNOWN);

	return xfer->type;
}

PurpleAccount *
purple_xfer_get_account(const PurpleXfer *xfer)
{
	g_return_val_if_fail(xfer != NULL, NULL);

	return xfer->account;
}

const char *
purple_xfer_get_remote_user(const PurpleXfer *xfer)
{
	g_return_val_if_fail(xfer != NULL, NULL);
	return xfer->who;
}

PurpleXferStatusType
purple_xfer_get_status(const PurpleXfer *xfer)
{
	g_return_val_if_fail(xfer != NULL, PURPLE_XFER_STATUS_UNKNOWN);

	return xfer->status;
}

/* FIXME: Rename with cancelled for 3.0.0. */
gboolean
purple_xfer_is_canceled(const PurpleXfer *xfer)
{
	g_return_val_if_fail(xfer != NULL, TRUE);

	if ((purple_xfer_get_status(xfer) == PURPLE_XFER_STATUS_CANCEL_LOCAL) ||
	    (purple_xfer_get_status(xfer) == PURPLE_XFER_STATUS_CANCEL_REMOTE))
		return TRUE;
	else
		return FALSE;
}

gboolean
purple_xfer_is_completed(const PurpleXfer *xfer)
{
	g_return_val_if_fail(xfer != NULL, TRUE);

	return (purple_xfer_get_status(xfer) == PURPLE_XFER_STATUS_DONE);
}

const char *
purple_xfer_get_filename(const PurpleXfer *xfer)
{
	g_return_val_if_fail(xfer != NULL, NULL);

	return xfer->filename;
}

const char *
purple_xfer_get_local_filename(const PurpleXfer *xfer)
{
	g_return_val_if_fail(xfer != NULL, NULL);

	return xfer->local_filename;
}

size_t
purple_xfer_get_bytes_sent(const PurpleXfer *xfer)
{
	g_return_val_if_fail(xfer != NULL, 0);

	return xfer->bytes_sent;
}

size_t
purple_xfer_get_bytes_remaining(const PurpleXfer *xfer)
{
	g_return_val_if_fail(xfer != NULL, 0);

	return xfer->bytes_remaining;
}

size_t
purple_xfer_get_size(const PurpleXfer *xfer)
{
	g_return_val_if_fail(xfer != NULL, 0);

	return xfer->size;
}

double
purple_xfer_get_progress(const PurpleXfer *xfer)
{
	g_return_val_if_fail(xfer != NULL, 0.0);

	if (purple_xfer_get_size(xfer) == 0)
		return 0.0;

	return ((double)purple_xfer_get_bytes_sent(xfer) /
			(double)purple_xfer_get_size(xfer));
}

unsigned int
purple_xfer_get_local_port(const PurpleXfer *xfer)
{
	g_return_val_if_fail(xfer != NULL, -1);

	return xfer->local_port;
}

const char *
purple_xfer_get_remote_ip(const PurpleXfer *xfer)
{
	g_return_val_if_fail(xfer != NULL, NULL);

	return xfer->remote_ip;
}

unsigned int
purple_xfer_get_remote_port(const PurpleXfer *xfer)
{
	g_return_val_if_fail(xfer != NULL, -1);

	return xfer->remote_port;
}

time_t
purple_xfer_get_start_time(const PurpleXfer *xfer)
{
	g_return_val_if_fail(xfer != NULL, 0);

	return xfer->start_time;
}

time_t
purple_xfer_get_end_time(const PurpleXfer *xfer)
{
	g_return_val_if_fail(xfer != NULL, 0);

	return xfer->end_time;
}

void
purple_xfer_set_completed(PurpleXfer *xfer, gboolean completed)
{
	PurpleXferUiOps *ui_ops;

	g_return_if_fail(xfer != NULL);

	if (completed == TRUE) {
		char *msg = NULL;
		PurpleConversation *conv;

		purple_xfer_set_status(xfer, PURPLE_XFER_STATUS_DONE);

		if (purple_xfer_get_filename(xfer) != NULL)
		{
			char *filename = g_markup_escape_text(purple_xfer_get_filename(xfer), -1);
			if (purple_xfer_get_local_filename(xfer)
			 && purple_xfer_get_type(xfer) == PURPLE_XFER_RECEIVE)
			{
				char *local = g_markup_escape_text(purple_xfer_get_local_filename(xfer), -1);
				msg = g_strdup_printf(_("Transfer of file <A HREF=\"file://%s\">%s</A> complete"),
				                      local, filename);
				g_free(local);
			}
			else
				msg = g_strdup_printf(_("Transfer of file %s complete"),
				                      filename);
			g_free(filename);
		}
		else
			msg = g_strdup(_("File transfer complete"));

		conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, xfer->who,
		                                             purple_xfer_get_account(xfer));

		if (conv != NULL)
			purple_conversation_write(conv, NULL, msg, PURPLE_MESSAGE_SYSTEM, time(NULL));
		g_free(msg);
	}

	ui_ops = purple_xfer_get_ui_ops(xfer);

	if (ui_ops != NULL && ui_ops->update_progress != NULL)
		ui_ops->update_progress(xfer, purple_xfer_get_progress(xfer));
}

void
purple_xfer_set_message(PurpleXfer *xfer, const char *message)
{
	g_return_if_fail(xfer != NULL);

	g_free(xfer->message);
	xfer->message = g_strdup(message);
}

void
purple_xfer_set_filename(PurpleXfer *xfer, const char *filename)
{
	g_return_if_fail(xfer != NULL);

	g_free(xfer->filename);
	xfer->filename = g_strdup(filename);
}

void
purple_xfer_set_local_filename(PurpleXfer *xfer, const char *filename)
{
	g_return_if_fail(xfer != NULL);

	g_free(xfer->local_filename);
	xfer->local_filename = g_strdup(filename);
}

void
purple_xfer_set_size(PurpleXfer *xfer, size_t size)
{
	g_return_if_fail(xfer != NULL);

	xfer->size = size;
	xfer->bytes_remaining = xfer->size - purple_xfer_get_bytes_sent(xfer);
}

void
purple_xfer_set_bytes_sent(PurpleXfer *xfer, size_t bytes_sent)
{
	g_return_if_fail(xfer != NULL);

	xfer->bytes_sent = bytes_sent;
	xfer->bytes_remaining = purple_xfer_get_size(xfer) - bytes_sent;
}

PurpleXferUiOps *
purple_xfer_get_ui_ops(const PurpleXfer *xfer)
{
	g_return_val_if_fail(xfer != NULL, NULL);

	return xfer->ui_ops;
}

void
purple_xfer_set_init_fnc(PurpleXfer *xfer, void (*fnc)(PurpleXfer *))
{
	g_return_if_fail(xfer != NULL);

	xfer->ops.init = fnc;
}

void purple_xfer_set_request_denied_fnc(PurpleXfer *xfer, void (*fnc)(PurpleXfer *))
{
	g_return_if_fail(xfer != NULL);

	xfer->ops.request_denied = fnc;
}

void
purple_xfer_set_read_fnc(PurpleXfer *xfer, gssize (*fnc)(guchar **, PurpleXfer *))
{
	g_return_if_fail(xfer != NULL);

	xfer->ops.read = fnc;
}

void
purple_xfer_set_write_fnc(PurpleXfer *xfer,
						gssize (*fnc)(const guchar *, size_t, PurpleXfer *))
{
	g_return_if_fail(xfer != NULL);

	xfer->ops.write = fnc;
}

void
purple_xfer_set_ack_fnc(PurpleXfer *xfer,
			  void (*fnc)(PurpleXfer *, const guchar *, size_t))
{
	g_return_if_fail(xfer != NULL);

	xfer->ops.ack = fnc;
}

void
purple_xfer_set_start_fnc(PurpleXfer *xfer, void (*fnc)(PurpleXfer *))
{
	g_return_if_fail(xfer != NULL);

	xfer->ops.start = fnc;
}

void
purple_xfer_set_end_fnc(PurpleXfer *xfer, void (*fnc)(PurpleXfer *))
{
	g_return_if_fail(xfer != NULL);

	xfer->ops.end = fnc;
}

void
purple_xfer_set_cancel_send_fnc(PurpleXfer *xfer, void (*fnc)(PurpleXfer *))
{
	g_return_if_fail(xfer != NULL);

	xfer->ops.cancel_send = fnc;
}

void
purple_xfer_set_cancel_recv_fnc(PurpleXfer *xfer, void (*fnc)(PurpleXfer *))
{
	g_return_if_fail(xfer != NULL);

	xfer->ops.cancel_recv = fnc;
}

static void
purple_xfer_increase_buffer_size(PurpleXfer *xfer)
{
	xfer->current_buffer_size = MIN(xfer->current_buffer_size * 1.5,
			FT_MAX_BUFFER_SIZE);
}

gssize
purple_xfer_read(PurpleXfer *xfer, guchar **buffer)
{
	gssize s, r;

	g_return_val_if_fail(xfer   != NULL, 0);
	g_return_val_if_fail(buffer != NULL, 0);

	if (purple_xfer_get_size(xfer) == 0)
		s = xfer->current_buffer_size;
	else
		s = MIN(purple_xfer_get_bytes_remaining(xfer), xfer->current_buffer_size);

	if (xfer->ops.read != NULL)	{
		r = (xfer->ops.read)(buffer, xfer);
	}
	else {
		*buffer = g_malloc0(s);

		r = read(xfer->fd, *buffer, s);
		if (r < 0 && errno == EAGAIN)
			r = 0;
		else if (r < 0)
			r = -1;
		else if (r == 0)
			r = -1;
	}

	if (r == xfer->current_buffer_size)
		/*
		 * We managed to read the entire buffer.  This means our this
		 * network is fast and our buffer is too small, so make it
		 * bigger.
		 */
		purple_xfer_increase_buffer_size(xfer);

	return r;
}

gssize
purple_xfer_write(PurpleXfer *xfer, const guchar *buffer, gsize size)
{
	gssize r, s;

	g_return_val_if_fail(xfer   != NULL, 0);
	g_return_val_if_fail(buffer != NULL, 0);
	g_return_val_if_fail(size   != 0,    0);

	s = MIN(purple_xfer_get_bytes_remaining(xfer), size);

	if (xfer->ops.write != NULL) {
		r = (xfer->ops.write)(buffer, s, xfer);
	} else {
		r = write(xfer->fd, buffer, s);
		if (r < 0 && errno == EAGAIN)
			r = 0;
	}
	if (r >= 0 && (purple_xfer_get_bytes_sent(xfer)+r) >= purple_xfer_get_size(xfer) &&
		!purple_xfer_is_completed(xfer))
		purple_xfer_set_completed(xfer, TRUE);
	

	return r;
}

static void
do_transfer(PurpleXfer *xfer)
{
	PurpleXferUiOps *ui_ops;
	guchar *buffer = NULL;
	gssize r = 0;

	ui_ops = purple_xfer_get_ui_ops(xfer);

	if (xfer->type == PURPLE_XFER_RECEIVE) {
		r = purple_xfer_read(xfer, &buffer);
		if (r > 0) {
			size_t wc;
			if (ui_ops && ui_ops->ui_write)
				wc = ui_ops->ui_write(xfer, buffer, r);
			else
				wc = fwrite(buffer, 1, r, xfer->dest_fp);

			if (wc != r) {
				purple_debug_error("filetransfer", "Unable to write whole buffer.\n");
				purple_xfer_cancel_local(xfer);
				g_free(buffer);
				return;
			}

			if ((purple_xfer_get_size(xfer) > 0) &&
				((purple_xfer_get_bytes_sent(xfer)+r) >= purple_xfer_get_size(xfer)))
				purple_xfer_set_completed(xfer, TRUE);
		} else if(r < 0) {
			purple_xfer_cancel_remote(xfer);
			g_free(buffer);
			return;
		}
	} else if (xfer->type == PURPLE_XFER_SEND) {
		size_t result = 0;
		size_t s = MIN(purple_xfer_get_bytes_remaining(xfer), xfer->current_buffer_size);
		PurpleXferPrivData *priv = g_hash_table_lookup(xfers_data, xfer);
		gboolean read = TRUE;

		/* this is so the prpl can keep the connection open
		   if it needs to for some odd reason. */
		if (s == 0) {
			if (xfer->watcher) {
				purple_input_remove(xfer->watcher);
				xfer->watcher = 0;
			}
			return;
		}

		if (priv->buffer) {
			if (priv->buffer->len < s) {
				s -= priv->buffer->len;
				read = TRUE;
			} else {
				read = FALSE;
			}
		}

		if (read) {
			if (ui_ops && ui_ops->ui_read) {
				gssize tmp = ui_ops->ui_read(xfer, &buffer, s);
				if (tmp == 0) {
					/*
					 * The UI claimed it was ready, but didn't have any data for
					 * us...  It will call purple_xfer_ui_ready when ready, which
					 * sets back up this watcher.
					 */
					if (xfer->watcher != 0) {
						purple_input_remove(xfer->watcher);
						xfer->watcher = 0;
					}

					/* Need to indicate the prpl is still ready... */
					priv->ready |= PURPLE_XFER_READY_PRPL;

					g_return_if_reached();
				} else if (tmp < 0) {
					purple_debug_error("filetransfer", "Unable to read whole buffer.\n");
					purple_xfer_cancel_local(xfer);
					return;
				}

				result = tmp;
			} else {
				buffer = g_malloc(s);
				result = fread(buffer, 1, s, xfer->dest_fp);
				if (result != s) {
					purple_debug_error("filetransfer", "Unable to read whole buffer.\n");
					purple_xfer_cancel_local(xfer);
					g_free(buffer);
					return;
				}
			}
		}

		if (priv->buffer) {
			g_byte_array_append(priv->buffer, buffer, result);
			g_free(buffer);
			buffer = priv->buffer->data;
			result = priv->buffer->len;
		}

		r = purple_xfer_write(xfer, buffer, result);

		if (r == -1) {
			purple_xfer_cancel_remote(xfer);
			if (!priv->buffer)
				/* We don't free buffer if priv->buffer is set, because in
				   that case buffer doesn't belong to us. */
				g_free(buffer);
			return;
		} else if (r == result) {
			/*
			 * We managed to write the entire buffer.  This means our
			 * network is fast and our buffer is too small, so make it
			 * bigger.
			 */
			purple_xfer_increase_buffer_size(xfer);
		} else {
			if (ui_ops && ui_ops->data_not_sent)
				ui_ops->data_not_sent(xfer, buffer + r, result - r);
		}

		if (priv->buffer) {
			/*
			 * Remove what we wrote
			 * If we wrote the whole buffer the byte array will be empty
			 * Otherwise we'll keep what wasn't sent for next time.
			 */
			buffer = NULL;
			g_byte_array_remove_range(priv->buffer, 0, r);
		}
	}

	if (r > 0) {
		if (purple_xfer_get_size(xfer) > 0)
			xfer->bytes_remaining -= r;

		xfer->bytes_sent += r;

		if (xfer->ops.ack != NULL)
			xfer->ops.ack(xfer, buffer, r);

		g_free(buffer);

		if (ui_ops != NULL && ui_ops->update_progress != NULL)
			ui_ops->update_progress(xfer,
				purple_xfer_get_progress(xfer));
	}

	if (purple_xfer_is_completed(xfer))
		purple_xfer_end(xfer);
}

static void
transfer_cb(gpointer data, gint source, PurpleInputCondition condition)
{
	PurpleXfer *xfer = data;

	if (xfer->dest_fp == NULL) {
		/* The UI is moderating its side manually */
		PurpleXferPrivData *priv = g_hash_table_lookup(xfers_data, xfer);
		if (0 == (priv->ready & PURPLE_XFER_READY_UI)) {
			priv->ready |= PURPLE_XFER_READY_PRPL;

			purple_input_remove(xfer->watcher);
			xfer->watcher = 0;

			purple_debug_misc("xfer", "prpl is ready on ft %p, waiting for UI\n", xfer);
			return;
		}

		priv->ready = PURPLE_XFER_READY_NONE;
	}

	do_transfer(xfer);
}

static void
begin_transfer(PurpleXfer *xfer, PurpleInputCondition cond)
{
	PurpleXferType type = purple_xfer_get_type(xfer);
	PurpleXferUiOps *ui_ops = purple_xfer_get_ui_ops(xfer);

	if (xfer->start_time != 0) {
		purple_debug_error("xfer", "Transfer is being started multiple times\n");
		g_return_if_reached();
	}

	if (ui_ops == NULL || (ui_ops->ui_read == NULL && ui_ops->ui_write == NULL)) {
		xfer->dest_fp = g_fopen(purple_xfer_get_local_filename(xfer),
		                        type == PURPLE_XFER_RECEIVE ? "wb" : "rb");

		if (xfer->dest_fp == NULL) {
			purple_xfer_show_file_error(xfer, purple_xfer_get_local_filename(xfer));
			purple_xfer_cancel_local(xfer);
			return;
		}

		fseek(xfer->dest_fp, xfer->bytes_sent, SEEK_SET);
	}

	if (xfer->fd != -1)
		xfer->watcher = purple_input_add(xfer->fd, cond, transfer_cb, xfer);

	xfer->start_time = time(NULL);

	if (xfer->ops.start != NULL)
		xfer->ops.start(xfer);
}

static void
connect_cb(gpointer data, gint source, const gchar *error_message)
{
	PurpleXfer *xfer = (PurpleXfer *)data;

	if (source < 0) {
		purple_xfer_cancel_local(xfer);
		return;
	}

	xfer->fd = source;

	begin_transfer(xfer, PURPLE_INPUT_READ);
}

void
purple_xfer_ui_ready(PurpleXfer *xfer)
{
	PurpleInputCondition cond;
	PurpleXferType type;
	PurpleXferPrivData *priv;

	g_return_if_fail(xfer != NULL);

	priv = g_hash_table_lookup(xfers_data, xfer);
	priv->ready |= PURPLE_XFER_READY_UI;

	if (0 == (priv->ready & PURPLE_XFER_READY_PRPL)) {
		purple_debug_misc("xfer", "UI is ready on ft %p, waiting for prpl\n", xfer);
		return;
	}

	purple_debug_misc("xfer", "UI (and prpl) ready on ft %p, so proceeding\n", xfer);

	type = purple_xfer_get_type(xfer);
	if (type == PURPLE_XFER_SEND)
		cond = PURPLE_INPUT_WRITE;
	else /* if (type == PURPLE_XFER_RECEIVE) */
		cond = PURPLE_INPUT_READ;

	if (xfer->watcher == 0 && xfer->fd != -1)
		xfer->watcher = purple_input_add(xfer->fd, cond, transfer_cb, xfer);

	priv->ready = PURPLE_XFER_READY_NONE;

	do_transfer(xfer);
}

void
purple_xfer_prpl_ready(PurpleXfer *xfer)
{
	PurpleXferPrivData *priv;

	g_return_if_fail(xfer != NULL);

	priv = g_hash_table_lookup(xfers_data, xfer);
	priv->ready |= PURPLE_XFER_READY_PRPL;

	/* I don't think fwrite/fread are ever *not* ready */
	if (xfer->dest_fp == NULL && 0 == (priv->ready & PURPLE_XFER_READY_UI)) {
		purple_debug_misc("xfer", "prpl is ready on ft %p, waiting for UI\n", xfer);
		return;
	}

	purple_debug_misc("xfer", "Prpl (and UI) ready on ft %p, so proceeding\n", xfer);

	priv->ready = PURPLE_XFER_READY_NONE;

	do_transfer(xfer);
}

void
purple_xfer_start(PurpleXfer *xfer, int fd, const char *ip,
				unsigned int port)
{
	PurpleInputCondition cond;
	PurpleXferType type;

	g_return_if_fail(xfer != NULL);
	g_return_if_fail(purple_xfer_get_type(xfer) != PURPLE_XFER_UNKNOWN);

	type = purple_xfer_get_type(xfer);

	purple_xfer_set_status(xfer, PURPLE_XFER_STATUS_STARTED);

	/*
	 * FIXME 3.0.0 -- there's too much broken code depending on fd == 0
	 * meaning "don't use a real fd"
	 */
	if (fd == 0)
		fd = -1;

	if (type == PURPLE_XFER_RECEIVE) {
		cond = PURPLE_INPUT_READ;

		if (ip != NULL) {
			xfer->remote_ip   = g_strdup(ip);
			xfer->remote_port = port;

			/* Establish a file descriptor. */
			purple_proxy_connect(NULL, xfer->account, xfer->remote_ip,
							   xfer->remote_port, connect_cb, xfer);

			return;
		}
		else {
			xfer->fd = fd;
		}
	}
	else {
		cond = PURPLE_INPUT_WRITE;

		xfer->fd = fd;
	}

	begin_transfer(xfer, cond);
}

void
purple_xfer_end(PurpleXfer *xfer)
{
	g_return_if_fail(xfer != NULL);

	/* See if we are actually trying to cancel this. */
	if (!purple_xfer_is_completed(xfer)) {
		purple_xfer_cancel_local(xfer);
		return;
	}

	xfer->end_time = time(NULL);
	if (xfer->ops.end != NULL)
		xfer->ops.end(xfer);

	if (xfer->watcher != 0) {
		purple_input_remove(xfer->watcher);
		xfer->watcher = 0;
	}

	if (xfer->fd != -1)
		close(xfer->fd);

	if (xfer->dest_fp != NULL) {
		fclose(xfer->dest_fp);
		xfer->dest_fp = NULL;
	}

	purple_xfer_unref(xfer);
}

void
purple_xfer_add(PurpleXfer *xfer)
{
	PurpleXferUiOps *ui_ops;

	g_return_if_fail(xfer != NULL);

	ui_ops = purple_xfer_get_ui_ops(xfer);

	if (ui_ops != NULL && ui_ops->add_xfer != NULL)
		ui_ops->add_xfer(xfer);
}

void
purple_xfer_cancel_local(PurpleXfer *xfer)
{
	PurpleXferUiOps *ui_ops;
	char *msg = NULL;

	g_return_if_fail(xfer != NULL);

	/* TODO: We definitely want to close any open request dialogs associated
	   with this transfer.  However, in some cases the request dialog might
	   own a reference on the xfer.  This happens at least with the "%s wants
	   to send you %s" dialog from purple_xfer_ask_recv().  In these cases
	   the ref count will not be decremented when the request dialog is
	   closed, so the ref count will never reach 0 and the xfer will never
	   be freed.  This is a memleak and should be fixed.  It's not clear what
	   the correct fix is.  Probably requests should have a destroy function
	   that is called when the request is destroyed.  But also, ref counting
	   xfer objects makes this code REALLY complicated.  An alternate fix is
	   to not ref count and instead just make sure the object still exists
	   when we try to use it. */
	purple_request_close_with_handle(xfer);

	purple_xfer_set_status(xfer, PURPLE_XFER_STATUS_CANCEL_LOCAL);
	xfer->end_time = time(NULL);

	if (purple_xfer_get_filename(xfer) != NULL)
	{
		msg = g_strdup_printf(_("You cancelled the transfer of %s"),
							  purple_xfer_get_filename(xfer));
	}
	else
	{
		msg = g_strdup(_("File transfer cancelled"));
	}
	purple_xfer_conversation_write(xfer, msg, FALSE);
	g_free(msg);

	if (purple_xfer_get_type(xfer) == PURPLE_XFER_SEND)
	{
		if (xfer->ops.cancel_send != NULL)
			xfer->ops.cancel_send(xfer);
	}
	else
	{
		if (xfer->ops.cancel_recv != NULL)
			xfer->ops.cancel_recv(xfer);
	}

	if (xfer->watcher != 0) {
		purple_input_remove(xfer->watcher);
		xfer->watcher = 0;
	}

	if (xfer->fd != -1)
		close(xfer->fd);

	if (xfer->dest_fp != NULL) {
		fclose(xfer->dest_fp);
		xfer->dest_fp = NULL;
	}

	ui_ops = purple_xfer_get_ui_ops(xfer);

	if (ui_ops != NULL && ui_ops->cancel_local != NULL)
		ui_ops->cancel_local(xfer);

	xfer->bytes_remaining = 0;

	purple_xfer_unref(xfer);
}

void
purple_xfer_cancel_remote(PurpleXfer *xfer)
{
	PurpleXferUiOps *ui_ops;
	gchar *msg;
	PurpleAccount *account;
	PurpleBuddy *buddy;

	g_return_if_fail(xfer != NULL);

	purple_request_close_with_handle(xfer);
	purple_xfer_set_status(xfer, PURPLE_XFER_STATUS_CANCEL_REMOTE);
	xfer->end_time = time(NULL);

	account = purple_xfer_get_account(xfer);
	buddy = purple_find_buddy(account, xfer->who);

	if (purple_xfer_get_filename(xfer) != NULL)
	{
		msg = g_strdup_printf(_("%s cancelled the transfer of %s"),
				buddy ? purple_buddy_get_alias(buddy) : xfer->who, purple_xfer_get_filename(xfer));
	}
	else
	{
		msg = g_strdup_printf(_("%s cancelled the file transfer"),
				buddy ? purple_buddy_get_alias(buddy) : xfer->who);
	}
	purple_xfer_conversation_write(xfer, msg, TRUE);
	purple_xfer_error(purple_xfer_get_type(xfer), account, xfer->who, msg);
	g_free(msg);

	if (purple_xfer_get_type(xfer) == PURPLE_XFER_SEND)
	{
		if (xfer->ops.cancel_send != NULL)
			xfer->ops.cancel_send(xfer);
	}
	else
	{
		if (xfer->ops.cancel_recv != NULL)
			xfer->ops.cancel_recv(xfer);
	}

	if (xfer->watcher != 0) {
		purple_input_remove(xfer->watcher);
		xfer->watcher = 0;
	}

	if (xfer->fd != -1)
		close(xfer->fd);

	if (xfer->dest_fp != NULL) {
		fclose(xfer->dest_fp);
		xfer->dest_fp = NULL;
	}

	ui_ops = purple_xfer_get_ui_ops(xfer);

	if (ui_ops != NULL && ui_ops->cancel_remote != NULL)
		ui_ops->cancel_remote(xfer);

	xfer->bytes_remaining = 0;

	purple_xfer_unref(xfer);
}

void
purple_xfer_error(PurpleXferType type, PurpleAccount *account, const char *who, const char *msg)
{
	char *title;

	g_return_if_fail(msg  != NULL);
	g_return_if_fail(type != PURPLE_XFER_UNKNOWN);

	if (account) {
		PurpleBuddy *buddy;
		buddy = purple_find_buddy(account, who);
		if (buddy)
			who = purple_buddy_get_alias(buddy);
	}

	if (type == PURPLE_XFER_SEND)
		title = g_strdup_printf(_("File transfer to %s failed."), who);
	else
		title = g_strdup_printf(_("File transfer from %s failed."), who);

	purple_notify_error(NULL, NULL, title, msg);

	g_free(title);
}

void
purple_xfer_update_progress(PurpleXfer *xfer)
{
	PurpleXferUiOps *ui_ops;

	g_return_if_fail(xfer != NULL);

	ui_ops = purple_xfer_get_ui_ops(xfer);
	if (ui_ops != NULL && ui_ops->update_progress != NULL)
		ui_ops->update_progress(xfer, purple_xfer_get_progress(xfer));
}

gconstpointer
purple_xfer_get_thumbnail(const PurpleXfer *xfer, gsize *len)
{
	PurpleXferPrivData *priv = g_hash_table_lookup(xfers_data, xfer);

	if (len)
		*len = priv->thumbnail_size;

	return priv->thumbnail_data;
}

const gchar *
purple_xfer_get_thumbnail_mimetype(const PurpleXfer *xfer)
{
	PurpleXferPrivData *priv = g_hash_table_lookup(xfers_data, xfer);

	return priv->thumbnail_mimetype;
}

void
purple_xfer_set_thumbnail(PurpleXfer *xfer, gconstpointer thumbnail,
	gsize size, const gchar *mimetype)
{
	PurpleXferPrivData *priv = g_hash_table_lookup(xfers_data, xfer);

	g_free(priv->thumbnail_data);
	g_free(priv->thumbnail_mimetype);

	if (thumbnail && size > 0) {
		priv->thumbnail_data = g_memdup(thumbnail, size);
		priv->thumbnail_size = size;
		priv->thumbnail_mimetype = g_strdup(mimetype);
	} else {
		priv->thumbnail_data = NULL;
		priv->thumbnail_size = 0;
		priv->thumbnail_mimetype = NULL;
	}
}

void
purple_xfer_prepare_thumbnail(PurpleXfer *xfer, const gchar *formats)
{
	if (xfer->ui_ops->add_thumbnail) {
		xfer->ui_ops->add_thumbnail(xfer, formats);
	}
}

/**************************************************************************
 * File Transfer Subsystem API
 **************************************************************************/
void *
purple_xfers_get_handle(void) {
	static int handle = 0;

	return &handle;
}

void
purple_xfers_init(void) {
	void *handle = purple_xfers_get_handle();

	xfers_data = g_hash_table_new_full(g_direct_hash, g_direct_equal,
	                                   NULL, purple_xfer_priv_data_destroy);

	/* register signals */
	purple_signal_register(handle, "file-recv-accept",
	                     purple_marshal_VOID__POINTER, NULL, 1,
	                     purple_value_new(PURPLE_TYPE_SUBTYPE,
	                                    PURPLE_SUBTYPE_XFER));
	purple_signal_register(handle, "file-send-accept",
	                     purple_marshal_VOID__POINTER, NULL, 1,
	                     purple_value_new(PURPLE_TYPE_SUBTYPE,
	                                    PURPLE_SUBTYPE_XFER));
	purple_signal_register(handle, "file-recv-start",
	                     purple_marshal_VOID__POINTER, NULL, 1,
	                     purple_value_new(PURPLE_TYPE_SUBTYPE,
	                                    PURPLE_SUBTYPE_XFER));
	purple_signal_register(handle, "file-send-start",
	                     purple_marshal_VOID__POINTER, NULL, 1,
	                     purple_value_new(PURPLE_TYPE_SUBTYPE,
	                                    PURPLE_SUBTYPE_XFER));
	purple_signal_register(handle, "file-send-cancel",
	                     purple_marshal_VOID__POINTER, NULL, 1,
	                     purple_value_new(PURPLE_TYPE_SUBTYPE,
	                                    PURPLE_SUBTYPE_XFER));
	purple_signal_register(handle, "file-recv-cancel",
	                     purple_marshal_VOID__POINTER, NULL, 1,
	                     purple_value_new(PURPLE_TYPE_SUBTYPE,
	                                    PURPLE_SUBTYPE_XFER));
	purple_signal_register(handle, "file-send-complete",
	                     purple_marshal_VOID__POINTER, NULL, 1,
	                     purple_value_new(PURPLE_TYPE_SUBTYPE,
	                                    PURPLE_SUBTYPE_XFER));
	purple_signal_register(handle, "file-recv-complete",
	                     purple_marshal_VOID__POINTER, NULL, 1,
	                     purple_value_new(PURPLE_TYPE_SUBTYPE,
	                                    PURPLE_SUBTYPE_XFER));
	purple_signal_register(handle, "file-recv-request",
	                     purple_marshal_VOID__POINTER, NULL, 1,
	                     purple_value_new(PURPLE_TYPE_SUBTYPE,
	                                    PURPLE_SUBTYPE_XFER));
}

void
purple_xfers_uninit(void)
{
	void *handle = purple_xfers_get_handle();

	purple_signals_disconnect_by_handle(handle);
	purple_signals_unregister_by_instance(handle);

	g_hash_table_destroy(xfers_data);
	xfers_data = NULL;
}

void
purple_xfers_set_ui_ops(PurpleXferUiOps *ops) {
	xfer_ui_ops = ops;
}

PurpleXferUiOps *
purple_xfers_get_ui_ops(void) {
	return xfer_ui_ops;
}
