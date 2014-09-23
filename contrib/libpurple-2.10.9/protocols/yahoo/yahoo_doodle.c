/*
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
 *
 */

/******************************************************************************
 * INCLUDES
 *****************************************************************************/
#include "internal.h"

#include "account.h"
#include "accountopt.h"
#include "blist.h"
#include "cipher.h"
#include "cmds.h"
#include "debug.h"
#include "notify.h"
#include "privacy.h"
#include "prpl.h"
#include "proxy.h"
#include "request.h"
#include "server.h"
#include "util.h"
#include "version.h"

#include "libymsg.h"
#include "yahoo_packet.h"
#include "yahoo_friend.h"
#include "yahoochat.h"
#include "ycht.h"
#include "yahoo_filexfer.h"
#include "yahoo_picture.h"

#include "whiteboard.h"
#include "yahoo_doodle.h"

/******************************************************************************
 * Globals
 *****************************************************************************/
#if 0
const int DefaultColorRGB24[] =
{
	DOODLE_COLOR_RED,
	DOODLE_COLOR_ORANGE,
	DOODLE_COLOR_YELLOW,
	DOODLE_COLOR_GREEN,
	DOODLE_COLOR_CYAN,
	DOODLE_COLOR_BLUE,
	DOODLE_COLOR_VIOLET,
	DOODLE_COLOR_PURPLE,
	DOODLE_COLOR_TAN,
	DOODLE_COLOR_BROWN,
	DOODLE_COLOR_BLACK,
	DOODLE_COLOR_GREY,
	DOODLE_COLOR_WHITE
};
#endif

/******************************************************************************
 * Functions
 *****************************************************************************/
PurpleCmdRet yahoo_doodle_purple_cmd_start(PurpleConversation *conv, const char *cmd, char **args, char **error, void *data)
{
	PurpleAccount *account;
	PurpleConnection *gc;
	const gchar *name;

	if(*args && args[0])
		return PURPLE_CMD_RET_FAILED;

	account = purple_conversation_get_account(conv);
	gc = purple_account_get_connection(account);
	name = purple_conversation_get_name(conv);
	yahoo_doodle_initiate(gc, name);

	/* Write a local message to this conversation showing that a request for a
	 * Doodle session has been made
	 */
	purple_conv_im_write(PURPLE_CONV_IM(conv), "", _("Sent Doodle request."),
					   PURPLE_MESSAGE_NICK | PURPLE_MESSAGE_RECV, time(NULL));

	return PURPLE_CMD_RET_OK;
}

void yahoo_doodle_initiate(PurpleConnection *gc, const char *name)
{
	PurpleAccount *account;
	char *to = (char*)name;

	g_return_if_fail(gc);
	g_return_if_fail(name);

	account = purple_connection_get_account(gc);

	if(purple_whiteboard_get_session(account, to) == NULL)
	{
		/* Insert this 'session' in the list.  At this point, it's only a
		 * requested session.
		 */
		purple_whiteboard_create(account, to, DOODLE_STATE_REQUESTING);
	}

	/* NOTE Perhaps some careful handling of remote assumed established
	 * sessions
	 */

	yahoo_doodle_command_send_ready(gc, to, DOODLE_IMV_KEY);
	yahoo_doodle_command_send_request(gc, to, DOODLE_IMV_KEY);

}

static void yahoo_doodle_command_got_request(PurpleConnection *gc, const char *from, const char *imv_key)
{
	PurpleAccount *account;
	PurpleWhiteboard *wb;

	purple_debug_info("yahoo", "doodle: Got Request (%s)\n", from);

	account = purple_connection_get_account(gc);

	/* Only handle this if local client requested Doodle session (else local
	 * client would have sent one)
	 */
	wb = purple_whiteboard_get_session(account, from);

	/* If a session with the remote user doesn't exist */
	if(wb == NULL)
	{
		doodle_session *ds;
		/* Ask user if they wish to accept the request for a doodle session */
		/* TODO Ask local user to start Doodle session with remote user */
		/* NOTE This if/else statement won't work right--must use dialog
		 * results
		 */

		/* char dialog_message[64];
		g_sprintf(dialog_message, "%s is requesting to start a Doodle session with you.", from);

		purple_notify_message(NULL, PURPLE_NOTIFY_MSG_INFO, "Doodle",
		dialog_message, NULL, NULL, NULL);
		*/

		wb = purple_whiteboard_create(account, from, DOODLE_STATE_REQUESTED);
		ds = wb->proto_data;
		ds->imv_key = g_strdup(imv_key);

		yahoo_doodle_command_send_ready(gc, from, imv_key);
	}

	/* TODO Might be required to clear the canvas of an existing doodle
	 * session at this point
	 */
}

static void yahoo_doodle_command_got_ready(PurpleConnection *gc, const char *from, const char *imv_key)
{
	PurpleAccount *account;
	PurpleWhiteboard *wb;

	purple_debug_info("yahoo", "doodle: Got Ready(%s)\n", from);

	account = purple_connection_get_account(gc);

	/* Only handle this if local client requested Doodle session (else local
	 * client would have sent one)
	 */
	wb = purple_whiteboard_get_session(account, from);

	if(wb == NULL)
		return;

	if(wb->state == DOODLE_STATE_REQUESTING)
	{
		doodle_session *ds = wb->proto_data;
		purple_whiteboard_start(wb);

		wb->state = DOODLE_STATE_ESTABLISHED;

		yahoo_doodle_command_send_confirm(gc, from, imv_key);
		/* Let's steal the imv_key and reuse it */
		g_free(ds->imv_key);
		ds->imv_key = g_strdup(imv_key);
	}
	else if(wb->state == DOODLE_STATE_ESTABLISHED)
	{
		/* TODO Ask whether to save picture too */
		purple_whiteboard_clear(wb);
	}

	/* NOTE Not sure about this... I am trying to handle if the remote user
	 * already thinks we're in a session with them (when their chat message
	 * contains the doodle imv key)
	 */
	else if(wb->state == DOODLE_STATE_REQUESTED)
	{
		/* purple_whiteboard_start(wb); */
		yahoo_doodle_command_send_ready(gc, from, imv_key);
	}
}

static void yahoo_doodle_command_got_draw(PurpleConnection *gc, const char *from, const char *message)
{
	PurpleAccount *account;
	PurpleWhiteboard *wb;
	char **tokens;
	int i;
	GList *d_list = NULL; /* a local list of drawing info */

	g_return_if_fail(message != NULL);

	purple_debug_info("yahoo", "doodle: Got Draw (%s)\n", from);
	purple_debug_info("yahoo", "doodle: Draw message: %s\n", message);

	account = purple_connection_get_account(gc);

	/* Only handle this if local client requested Doodle session (else local
	 * client would have sent one)
	 */
	wb = purple_whiteboard_get_session(account, from);

	if(wb == NULL)
		return;

	/* TODO Functionalize
	 * Convert drawing packet message to an integer list
	 */

	/* Check to see if the message begans and ends with quotes */
	if((message[0] != '\"') || (message[strlen(message) - 1] != '\"'))
		return;

	/* Ignore the inital quotation mark. */
	message += 1;

	tokens = g_strsplit(message, ",", 0);

	/* Traverse and extract all integers divided by commas */
	for (i = 0; tokens[i] != NULL; i++)
	{
		int last = strlen(tokens[i]) - 1;
		if (tokens[i][last] == '"')
			tokens[i][last] = '\0';

		d_list = g_list_prepend(d_list, GINT_TO_POINTER(atoi(tokens[i])));
	}
	d_list = g_list_reverse(d_list);

	g_strfreev(tokens);

	yahoo_doodle_draw_stroke(wb, d_list);

	/* goodle_doodle_session_set_canvas_as_icon(ds); */

	g_list_free(d_list);
}


static void yahoo_doodle_command_got_clear(PurpleConnection *gc, const char *from)
{
	PurpleAccount *account;
	PurpleWhiteboard *wb;

	purple_debug_info("yahoo", "doodle: Got Clear (%s)\n", from);

	account = purple_connection_get_account(gc);

	/* Only handle this if local client requested Doodle session (else local
	 * client would have sent one)
	 */
	wb = purple_whiteboard_get_session(account, from);

	if(wb == NULL)
		return;

	if(wb->state == DOODLE_STATE_ESTABLISHED)
	{
		/* TODO Ask user whether to save the image before clearing it */

		purple_whiteboard_clear(wb);
	}
}


static void
yahoo_doodle_command_got_extra(PurpleConnection *gc, const char *from, const char *message, const char *imv_key)
{
	purple_debug_info("yahoo", "doodle: Got Extra (%s)\n", from);

	/* I do not like these 'extra' features, so I'll only handle them in one
	 * way, which is returning them with the command/packet to turn them off
	 */
	yahoo_doodle_command_send_extra(gc, from, DOODLE_EXTRA_NONE, imv_key);
}

static void yahoo_doodle_command_got_confirm(PurpleConnection *gc, const char *from)
{
	PurpleAccount *account;
	PurpleWhiteboard *wb;

	purple_debug_info("yahoo", "doodle: Got Confirm (%s)\n", from);

	/* Get the doodle session */
	account = purple_connection_get_account(gc);

	/* Only handle this if local client requested Doodle session (else local
	 * client would have sent one)
	 */
	wb = purple_whiteboard_get_session(account, from);

	if(wb == NULL)
		return;

	/* TODO Combine the following IF's? */

	/* Check if we requested a doodle session */
	/*if(wb->state == DOODLE_STATE_REQUESTING)
	{
		wb->state = DOODLE_STATE_ESTABLISHED;

		purple_whiteboard_start(wb);

		yahoo_doodle_command_send_confirm(gc, from);
	}*/

	/* Check if we accepted a request for a doodle session */
	if(wb->state == DOODLE_STATE_REQUESTED)
	{
		wb->state = DOODLE_STATE_ESTABLISHED;

		purple_whiteboard_start(wb);
	}
}

void yahoo_doodle_command_got_shutdown(PurpleConnection *gc, const char *from)
{
	PurpleAccount *account;
	PurpleWhiteboard *wb;

	g_return_if_fail(from != NULL);

	purple_debug_info("yahoo", "doodle: Got Shutdown (%s)\n", from);

	account = purple_connection_get_account(gc);

	/* Only handle this if local client requested Doodle session (else local
	 * client would have sent one)
	 */
	wb = purple_whiteboard_get_session(account, from);

	if(wb == NULL)
		return;

	/* TODO Ask if user wants to save picture before the session is closed */

	wb->state = DOODLE_STATE_CANCELLED;
	purple_whiteboard_destroy(wb);
}

static void yahoo_doodle_command_send_generic(const char *type,
											  PurpleConnection *gc,
											  const char *to,
											  const char *message,
											  int command,
											  const char *imv,
											  const char *sixtyfour)
{
	YahooData *yd;
	struct yahoo_packet *pkt;

	purple_debug_info("yahoo", "doodle: Sent %s (%s)\n", type, to);

	yd = gc->proto_data;

	/* Make and send an acknowledge (ready) Doodle packet */
	pkt = yahoo_packet_new(YAHOO_SERVICE_P2PFILEXFER, YAHOO_STATUS_AVAILABLE, yd->session_id);
	yahoo_packet_hash_str(pkt, 49,  "IMVIRONMENT");
	yahoo_packet_hash_str(pkt, 1,    purple_account_get_username(gc->account));
	yahoo_packet_hash_str(pkt, 14,   message);
	yahoo_packet_hash_int(pkt, 13,   command);
	yahoo_packet_hash_str(pkt, 5,    to);
	yahoo_packet_hash_str(pkt, 63,   imv ? imv : DOODLE_IMV_KEY);
	yahoo_packet_hash_str(pkt, 64,   sixtyfour);
	yahoo_packet_hash_str(pkt, 1002, "1");

	yahoo_packet_send_and_free(pkt, yd);
}

void yahoo_doodle_command_send_ready(PurpleConnection *gc, const char *to, const char *imv_key)
{
	yahoo_doodle_command_send_generic("Ready", gc, to, "1", DOODLE_CMD_READY, imv_key, "1");
}

void yahoo_doodle_command_send_request(PurpleConnection *gc, const char *to, const char *imv_key)
{
	yahoo_doodle_command_send_generic("Request", gc, to, "", DOODLE_CMD_REQUEST, imv_key, "0");
}

void yahoo_doodle_command_send_draw(PurpleConnection *gc, const char *to, const char *message, const char *imv_key)
{
	yahoo_doodle_command_send_generic("Draw", gc, to, message, DOODLE_CMD_DRAW, imv_key, "1");
}

void yahoo_doodle_command_send_clear(PurpleConnection *gc, const char *to, const char *imv_key)
{
	yahoo_doodle_command_send_generic("Clear", gc, to, " ", DOODLE_CMD_CLEAR, imv_key, "1");
}

void yahoo_doodle_command_send_extra(PurpleConnection *gc, const char *to, const char *message, const char *imv_key)
{
	yahoo_doodle_command_send_generic("Extra", gc, to, message, DOODLE_CMD_EXTRA, imv_key, "1");
}

void yahoo_doodle_command_send_confirm(PurpleConnection *gc, const char *to, const char *imv_key)
{
	yahoo_doodle_command_send_generic("Confirm", gc, to, "1", DOODLE_CMD_CONFIRM, imv_key, "1");
}

void yahoo_doodle_command_send_shutdown(PurpleConnection *gc, const char *to)
{
	yahoo_doodle_command_send_generic("Shutdown", gc, to, "", DOODLE_CMD_SHUTDOWN, ";0", "0");
}

void yahoo_doodle_start(PurpleWhiteboard *wb)
{
	doodle_session *ds = g_new0(doodle_session, 1);

	/* purple_debug_debug("yahoo", "doodle: yahoo_doodle_start()\n"); */

	/* Set default brush size and color */
	ds->brush_size  = DOODLE_BRUSH_SMALL;
	ds->brush_color = DOODLE_COLOR_RED;

	wb->proto_data = ds;
}

void yahoo_doodle_end(PurpleWhiteboard *wb)
{
	PurpleConnection *gc = purple_account_get_connection(wb->account);
	doodle_session *ds = wb->proto_data;

	/* g_debug_debug("yahoo", "doodle: yahoo_doodle_end()\n"); */

	if (gc && wb->state != DOODLE_STATE_CANCELLED)
		yahoo_doodle_command_send_shutdown(gc, wb->who);

	g_free(ds->imv_key);
	g_free(wb->proto_data);
}

void yahoo_doodle_get_dimensions(const PurpleWhiteboard *wb, int *width, int *height)
{
	/* standard Doodle canvases are of one size:  368x256 */
	*width = DOODLE_CANVAS_WIDTH;
	*height = DOODLE_CANVAS_HEIGHT;
}

static char *yahoo_doodle_build_draw_string(doodle_session *ds, GList *draw_list)
{
	GString *message;

	g_return_val_if_fail(draw_list != NULL, NULL);

	message = g_string_new("");
	g_string_printf(message, "\"%d,%d", ds->brush_color, ds->brush_size);

	for(; draw_list != NULL; draw_list = draw_list->next)
	{
		g_string_append_printf(message, ",%d", GPOINTER_TO_INT(draw_list->data));
	}
	g_string_append_c(message, '"');

	return g_string_free(message, FALSE);
}

void yahoo_doodle_send_draw_list(PurpleWhiteboard *wb, GList *draw_list)
{
	doodle_session *ds = wb->proto_data;
	char *message;

	g_return_if_fail(draw_list != NULL);

	message = yahoo_doodle_build_draw_string(ds, draw_list);
	yahoo_doodle_command_send_draw(wb->account->gc, wb->who, message, ds->imv_key);
	g_free(message);
}

void yahoo_doodle_clear(PurpleWhiteboard *wb)
{
	doodle_session *ds = wb->proto_data;
	yahoo_doodle_command_send_clear(wb->account->gc, wb->who, ds->imv_key);
}


/* Traverse through the list and draw the points and lines */
void yahoo_doodle_draw_stroke(PurpleWhiteboard *wb, GList *draw_list)
{
	int brush_color;
	int brush_size;
	int x;
	int y;

	g_return_if_fail(draw_list != NULL);

	brush_color = GPOINTER_TO_INT(draw_list->data);
	draw_list = draw_list->next;
	g_return_if_fail(draw_list != NULL);

	brush_size = GPOINTER_TO_INT(draw_list->data);
	draw_list = draw_list->next;
	g_return_if_fail(draw_list != NULL);

	x = GPOINTER_TO_INT(draw_list->data);
	draw_list = draw_list->next;
	g_return_if_fail(draw_list != NULL);

	y = GPOINTER_TO_INT(draw_list->data);
	draw_list = draw_list->next;
	g_return_if_fail(draw_list != NULL);

	/*
	purple_debug_debug("yahoo", "doodle: Drawing: color=%d, size=%d, (%d,%d)\n", brush_color, brush_size, x, y);
	*/

	while(draw_list != NULL && draw_list->next != NULL)
	{
		int dx = GPOINTER_TO_INT(draw_list->data);
		int dy = GPOINTER_TO_INT(draw_list->next->data);

		purple_whiteboard_draw_line(wb,
								  x, y,
								  x + dx, y + dy,
								  brush_color, brush_size);

		x += dx;
		y += dy;

		draw_list = draw_list->next->next;
	}
}

void yahoo_doodle_get_brush(const PurpleWhiteboard *wb, int *size, int *color)
{
	doodle_session *ds = wb->proto_data;
	*size = ds->brush_size;
	*color = ds->brush_color;
}

void yahoo_doodle_set_brush(PurpleWhiteboard *wb, int size, int color)
{
	doodle_session *ds = wb->proto_data;
	ds->brush_size = size;
	ds->brush_color = color;

	/* Notify the core about the changes */
	purple_whiteboard_set_brush(wb, size, color);
}

void yahoo_doodle_process(PurpleConnection *gc, const char *me, const char *from,
						  const char *command, const char *message, const char *imv_key)
{
	if(!command)
		return;

	/* Now check to see what sort of Doodle message it is */
	switch(atoi(command))
	{
		case DOODLE_CMD_REQUEST:
			yahoo_doodle_command_got_request(gc, from, imv_key);
			break;

		case DOODLE_CMD_READY:
			yahoo_doodle_command_got_ready(gc, from, imv_key);
			break;

		case DOODLE_CMD_CLEAR:
			yahoo_doodle_command_got_clear(gc, from);
			break;

		case DOODLE_CMD_DRAW:
			yahoo_doodle_command_got_draw(gc, from, message);
			break;

		case DOODLE_CMD_EXTRA:
			yahoo_doodle_command_got_extra(gc, from, message, imv_key);
			break;

		case DOODLE_CMD_CONFIRM:
			yahoo_doodle_command_got_confirm(gc, from);
			break;
	}
}
