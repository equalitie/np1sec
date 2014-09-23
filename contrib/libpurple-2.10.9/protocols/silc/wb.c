/*

  wb.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2005 - 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#include "internal.h"
#include "silc.h"
#include "silcclient.h"
#include "silcpurple.h"
#include "wb.h"

/*
  SILC Whiteboard packet:

  1 byte	command
  2 bytes	width
  2 bytes	height
  4 bytes	brush color
  2 bytes	brush size
  n bytes	data

  Data:

  4 bytes	x
  4 bytes	y

  Commands:

  0x01		draw
  0x02		clear

  MIME:

  MIME-Version: 1.0
  Content-Type: application/x-wb
  Content-Transfer-Encoding: binary

*/

#define SILCPURPLE_WB_MIME "MIME-Version: 1.0\r\nContent-Type: application/x-wb\r\nContent-Transfer-Encoding: binary\r\n\r\n"
#define SILCPURPLE_WB_HEADER strlen(SILCPURPLE_WB_MIME) + 11

#define SILCPURPLE_WB_WIDTH 500
#define SILCPURPLE_WB_HEIGHT 400
#define SILCPURPLE_WB_WIDTH_MAX 1024
#define SILCPURPLE_WB_HEIGHT_MAX 1024

/* Commands */
typedef enum {
	SILCPURPLE_WB_DRAW 	= 0x01,
	SILCPURPLE_WB_CLEAR	= 0x02,
} SilcPurpleWbCommand;

/* Brush size */
typedef enum {
	SILCPURPLE_WB_BRUSH_SMALL = 2,
	SILCPURPLE_WB_BRUSH_MEDIUM = 5,
	SILCPURPLE_WB_BRUSH_LARGE = 10,
} SilcPurpleWbBrushSize;

/* Brush color (XXX Purple should provide default colors) */
typedef enum {
	SILCPURPLE_WB_COLOR_BLACK		= 0,
	SILCPURPLE_WB_COLOR_RED		= 13369344,
	SILCPURPLE_WB_COLOR_GREEN		= 52224,
	SILCPURPLE_WB_COLOR_BLUE		= 204,
	SILCPURPLE_WB_COLOR_YELLOW 	= 15658496,
	SILCPURPLE_WB_COLOR_ORANGE	= 16737792,
	SILCPURPLE_WB_COLOR_CYAN		= 52428,
	SILCPURPLE_WB_COLOR_VIOLET	= 5381277,
	SILCPURPLE_WB_COLOR_PURPLE	= 13369548,
	SILCPURPLE_WB_COLOR_TAN		= 12093547,
	SILCPURPLE_WB_COLOR_BROWN		= 5256485,
	SILCPURPLE_WB_COLOR_GREY		= 11184810,
	SILCPURPLE_WB_COLOR_WHITE		= 16777215,
} SilcPurpleWbColor;

typedef struct {
	int type;		/* 0 = buddy, 1 = channel */
	union {
		SilcClientEntry client;
		SilcChannelEntry channel;
	} u;
	int width;
	int height;
	int brush_size;
	int brush_color;
} *SilcPurpleWb;

/* Initialize whiteboard */

PurpleWhiteboard *silcpurple_wb_init(SilcPurple sg, SilcClientEntry client_entry)
{
        SilcClientConnection conn;
	PurpleWhiteboard *wb;
	SilcPurpleWb wbs;

	conn = sg->conn;
	wb = purple_whiteboard_get_session(sg->account, client_entry->nickname);
	if (!wb)
		wb = purple_whiteboard_create(sg->account, client_entry->nickname, 0);
	if (!wb)
		return NULL;

	if (!wb->proto_data) {
		wbs = silc_calloc(1, sizeof(*wbs));
		if (!wbs)
			return NULL;
		wbs->type = 0;
		wbs->u.client = client_entry;
		wbs->width = SILCPURPLE_WB_WIDTH;
		wbs->height = SILCPURPLE_WB_HEIGHT;
		wbs->brush_size = SILCPURPLE_WB_BRUSH_SMALL;
		wbs->brush_color = SILCPURPLE_WB_COLOR_BLACK;
		wb->proto_data = wbs;

		/* Start the whiteboard */
		purple_whiteboard_start(wb);
		purple_whiteboard_clear(wb);
	}

	return wb;
}

PurpleWhiteboard *silcpurple_wb_init_ch(SilcPurple sg, SilcChannelEntry channel)
{
	PurpleWhiteboard *wb;
	SilcPurpleWb wbs;

	wb = purple_whiteboard_get_session(sg->account, channel->channel_name);
	if (!wb)
		wb = purple_whiteboard_create(sg->account, channel->channel_name, 0);
	if (!wb)
		return NULL;

	if (!wb->proto_data) {
		wbs = silc_calloc(1, sizeof(*wbs));
		if (!wbs)
			return NULL;
		wbs->type = 1;
		wbs->u.channel = channel;
		wbs->width = SILCPURPLE_WB_WIDTH;
		wbs->height = SILCPURPLE_WB_HEIGHT;
		wbs->brush_size = SILCPURPLE_WB_BRUSH_SMALL;
		wbs->brush_color = SILCPURPLE_WB_COLOR_BLACK;
		wb->proto_data = wbs;

		/* Start the whiteboard */
		purple_whiteboard_start(wb);
		purple_whiteboard_clear(wb);
	}

	return wb;
}

static void
silcpurple_wb_parse(SilcPurpleWb wbs, PurpleWhiteboard *wb,
		  unsigned char *message, SilcUInt32 message_len)
{
	SilcUInt8 command;
	SilcUInt16 width, height, brush_size;
	SilcUInt32 brush_color, x, y, dx, dy;
	SilcBufferStruct buf;
	int ret;

	/* Parse the packet */
	silc_buffer_set(&buf, message, message_len);
	ret = silc_buffer_unformat(&buf,
				   SILC_STR_UI_CHAR(&command),
				   SILC_STR_UI_SHORT(&width),
				   SILC_STR_UI_SHORT(&height),
				   SILC_STR_UI_INT(&brush_color),
				   SILC_STR_UI_SHORT(&brush_size),
				   SILC_STR_END);
	if (ret < 0)
		return;
	silc_buffer_pull(&buf, ret);

	/* Update whiteboard if its dimensions changed */
	if (width != wbs->width || height != wbs->height)
		silcpurple_wb_set_dimensions(wb, width, height);

	if (command == SILCPURPLE_WB_DRAW) {
		/* Parse data and draw it */
		ret = silc_buffer_unformat(&buf,
					   SILC_STR_UI_INT(&dx),
					   SILC_STR_UI_INT(&dy),
					   SILC_STR_END);
		if (ret < 0)
			return;
		silc_buffer_pull(&buf, 8);
		x = dx;
		y = dy;
		while (silc_buffer_len(&buf) > 0) {
			ret = silc_buffer_unformat(&buf,
						   SILC_STR_UI_INT(&dx),
						   SILC_STR_UI_INT(&dy),
						   SILC_STR_END);
			if (ret < 0)
				return;
			silc_buffer_pull(&buf, 8);

			purple_whiteboard_draw_line(wb, x, y, x + dx, y + dy,
						    brush_color, brush_size);
			x += dx;
			y += dy;
		}
	}

	if (command == SILCPURPLE_WB_CLEAR)
		purple_whiteboard_clear(wb);
}

typedef struct {
  unsigned char *message;
  SilcUInt32 message_len;
  SilcPurple sg;
  SilcClientEntry sender;
  SilcChannelEntry channel;
} *SilcPurpleWbRequest;

static void
silcpurple_wb_request_cb(SilcPurpleWbRequest req, gint id)
{
	PurpleWhiteboard *wb;

        if (id != 1)
                goto out;

	if (!req->channel)
		wb = silcpurple_wb_init(req->sg, req->sender);
	else
		wb = silcpurple_wb_init_ch(req->sg, req->channel);

	silcpurple_wb_parse(wb->proto_data, wb, req->message, req->message_len);

  out:
	silc_free(req->message);
	silc_free(req);
}

static void
silcpurple_wb_request(SilcClient client, const unsigned char *message,
		      SilcUInt32 message_len, SilcClientEntry sender,
		      SilcChannelEntry channel)
{
	char tmp[256];
	SilcPurpleWbRequest req;
	PurpleConnection *gc;
	SilcPurple sg;

	gc = client->application;
	sg = gc->proto_data;

	/* Open whiteboard automatically if requested */
	if (purple_account_get_bool(sg->account, "open-wb", FALSE)) {
		PurpleWhiteboard *wb;

		if (!channel)
			wb = silcpurple_wb_init(sg, sender);
		else
			wb = silcpurple_wb_init_ch(sg, channel);

		silcpurple_wb_parse(wb->proto_data, wb,
				    (unsigned char *)message,
				    message_len);
		return;
	}

	/* Close any previous unaccepted requests */
	purple_request_close_with_handle(sender);

	if (!channel) {
		g_snprintf(tmp, sizeof(tmp),
			   _("%s sent message to whiteboard. Would you like "
			     "to open the whiteboard?"), sender->nickname);
	} else {
		g_snprintf(tmp, sizeof(tmp),
			   _("%s sent message to whiteboard on %s channel. "
			     "Would you like to open the whiteboard?"),
			   sender->nickname, channel->channel_name);
	}

	req = silc_calloc(1, sizeof(*req));
	if (!req)
		return;
	req->message = silc_memdup(message, message_len);
	req->message_len = message_len;
	req->sender = sender;
	req->channel = channel;
	req->sg = sg;

	purple_request_action(gc, _("Whiteboard"), tmp, NULL, 1,
				sg->account, sender->nickname, NULL, req, 2,
			    _("Yes"), G_CALLBACK(silcpurple_wb_request_cb),
			    _("No"), G_CALLBACK(silcpurple_wb_request_cb));
}

/* Process incoming whiteboard message */

void silcpurple_wb_receive(SilcClient client, SilcClientConnection conn,
			 SilcClientEntry sender, SilcMessagePayload payload,
			 SilcMessageFlags flags, const unsigned char *message,
			 SilcUInt32 message_len)
{
	SilcPurple sg;
        PurpleConnection *gc;
	PurpleWhiteboard *wb;
	SilcPurpleWb wbs;

	gc = client->application;
        sg = gc->proto_data;

	wb = purple_whiteboard_get_session(sg->account, sender->nickname);
	if (!wb) {
		/* Ask user if they want to open the whiteboard */
		silcpurple_wb_request(client, message, message_len,
				    sender, NULL);
		return;
	}

	wbs = wb->proto_data;
	silcpurple_wb_parse(wbs, wb, (unsigned char *)message, message_len);
}

/* Process incoming whiteboard message on channel */

void silcpurple_wb_receive_ch(SilcClient client, SilcClientConnection conn,
			    SilcClientEntry sender, SilcChannelEntry channel,
			    SilcMessagePayload payload,
			    SilcMessageFlags flags,
			    const unsigned char *message,
			    SilcUInt32 message_len)
{
	SilcPurple sg;
        PurpleConnection *gc;
	PurpleWhiteboard *wb;
	SilcPurpleWb wbs;

	gc = client->application;
        sg = gc->proto_data;

	wb = purple_whiteboard_get_session(sg->account, channel->channel_name);
	if (!wb) {
		/* Ask user if they want to open the whiteboard */
		silcpurple_wb_request(client, message, message_len,
				    sender, channel);
		return;
	}

	wbs = wb->proto_data;
	silcpurple_wb_parse(wbs, wb, (unsigned char *)message, message_len);
}

/* Send whiteboard message */

void silcpurple_wb_send(PurpleWhiteboard *wb, GList *draw_list)
{
	SilcPurpleWb wbs = wb->proto_data;
	SilcBuffer packet;
	GList *list;
	int len;
        PurpleConnection *gc;
        SilcPurple sg;

	g_return_if_fail(draw_list);
	gc = purple_account_get_connection(wb->account);
	g_return_if_fail(gc);
 	sg = gc->proto_data;
	g_return_if_fail(sg);

	len = SILCPURPLE_WB_HEADER;
	for (list = draw_list; list; list = list->next)
		len += 4;

	packet = silc_buffer_alloc_size(len);
	if (!packet)
		return;

	/* Assmeble packet */
	silc_buffer_format(packet,
			   SILC_STR_UI32_STRING(SILCPURPLE_WB_MIME),
			   SILC_STR_UI_CHAR(SILCPURPLE_WB_DRAW),
			   SILC_STR_UI_SHORT(wbs->width),
			   SILC_STR_UI_SHORT(wbs->height),
			   SILC_STR_UI_INT(wbs->brush_color),
			   SILC_STR_UI_SHORT(wbs->brush_size),
			   SILC_STR_END);
	silc_buffer_pull(packet, SILCPURPLE_WB_HEADER);
	for (list = draw_list; list; list = list->next) {
		silc_buffer_format(packet,
				   SILC_STR_UI_INT(GPOINTER_TO_INT(list->data)),
				   SILC_STR_END);
		silc_buffer_pull(packet, 4);
	}

	/* Send the message */
	if (wbs->type == 0) {
		/* Private message */
		silc_client_send_private_message(sg->client, sg->conn,
						 wbs->u.client,
						 SILC_MESSAGE_FLAG_DATA, NULL,
						 packet->head, len);
	} else if (wbs->type == 1) {
		/* Channel message. Channel private keys are not supported. */
		silc_client_send_channel_message(sg->client, sg->conn,
						 wbs->u.channel, NULL,
						 SILC_MESSAGE_FLAG_DATA, NULL,
						 packet->head, len);
	}

	silc_buffer_free(packet);
}

/* Purple Whiteboard operations */

void silcpurple_wb_start(PurpleWhiteboard *wb)
{
	/* Nothing here.  Everything is in initialization */
}

void silcpurple_wb_end(PurpleWhiteboard *wb)
{
	silc_free(wb->proto_data);
	wb->proto_data = NULL;
}

void silcpurple_wb_get_dimensions(const PurpleWhiteboard *wb, int *width, int *height)
{
	SilcPurpleWb wbs = wb->proto_data;
	*width = wbs->width;
	*height = wbs->height;
}

void silcpurple_wb_set_dimensions(PurpleWhiteboard *wb, int width, int height)
{
	SilcPurpleWb wbs = wb->proto_data;
	wbs->width = width > SILCPURPLE_WB_WIDTH_MAX ? SILCPURPLE_WB_WIDTH_MAX :
			width;
	wbs->height = height > SILCPURPLE_WB_HEIGHT_MAX ? SILCPURPLE_WB_HEIGHT_MAX :
			height;

	/* Update whiteboard */
	purple_whiteboard_set_dimensions(wb, wbs->width, wbs->height);
}

void silcpurple_wb_get_brush(const PurpleWhiteboard *wb, int *size, int *color)
{
	SilcPurpleWb wbs = wb->proto_data;
	*size = wbs->brush_size;
	*color = wbs->brush_color;
}

void silcpurple_wb_set_brush(PurpleWhiteboard *wb, int size, int color)
{
	SilcPurpleWb wbs = wb->proto_data;
	wbs->brush_size = size;
	wbs->brush_color = color;

	/* Update whiteboard */
	purple_whiteboard_set_brush(wb, size, color);
}

void silcpurple_wb_clear(PurpleWhiteboard *wb)
{
	SilcPurpleWb wbs = wb->proto_data;
	SilcBuffer packet;
	int len;
        PurpleConnection *gc;
        SilcPurple sg;

	gc = purple_account_get_connection(wb->account);
	g_return_if_fail(gc);
 	sg = gc->proto_data;
	g_return_if_fail(sg);

	len = SILCPURPLE_WB_HEADER;
	packet = silc_buffer_alloc_size(len);
	if (!packet)
		return;

	/* Assmeble packet */
	silc_buffer_format(packet,
			   SILC_STR_UI32_STRING(SILCPURPLE_WB_MIME),
			   SILC_STR_UI_CHAR(SILCPURPLE_WB_CLEAR),
			   SILC_STR_UI_SHORT(wbs->width),
			   SILC_STR_UI_SHORT(wbs->height),
			   SILC_STR_UI_INT(wbs->brush_color),
			   SILC_STR_UI_SHORT(wbs->brush_size),
			   SILC_STR_END);

	/* Send the message */
	if (wbs->type == 0) {
		/* Private message */
		silc_client_send_private_message(sg->client, sg->conn,
						 wbs->u.client,
						 SILC_MESSAGE_FLAG_DATA, NULL,
						 packet->head, len);
	} else if (wbs->type == 1) {
		/* Channel message */
		silc_client_send_channel_message(sg->client, sg->conn,
						 wbs->u.channel, NULL,
						 SILC_MESSAGE_FLAG_DATA, NULL,
						 packet->head, len);
	}

	silc_buffer_free(packet);
}
