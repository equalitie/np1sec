/*

  silcpurple.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2005 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef SILCPURPLE_WB_H
#define SILCPURPLE_WB_H

#include "silcpurple.h"
#include "whiteboard.h"

PurpleWhiteboard *
silcpurple_wb_init(SilcPurple sg, SilcClientEntry client_entry);
PurpleWhiteboard *
silcpurple_wb_init_ch(SilcPurple sg, SilcChannelEntry channel);
void silcpurple_wb_receive(SilcClient client, SilcClientConnection conn,
			 SilcClientEntry sender, SilcMessagePayload payload,
			 SilcMessageFlags flags, const unsigned char *message,
			 SilcUInt32 message_len);
void silcpurple_wb_receive_ch(SilcClient client, SilcClientConnection conn,
			    SilcClientEntry sender, SilcChannelEntry channel,
			    SilcMessagePayload payload,
			    SilcMessageFlags flags,
			    const unsigned char *message,
			    SilcUInt32 message_len);
void silcpurple_wb_start(PurpleWhiteboard *wb);
void silcpurple_wb_end(PurpleWhiteboard *wb);
void silcpurple_wb_get_dimensions(const PurpleWhiteboard *wb, int *width, int *height);
void silcpurple_wb_set_dimensions(PurpleWhiteboard *wb, int width, int height);
void silcpurple_wb_get_brush(const PurpleWhiteboard *wb, int *size, int *color);
void silcpurple_wb_set_brush(PurpleWhiteboard *wb, int size, int color);
void silcpurple_wb_send(PurpleWhiteboard *wb, GList *draw_list);
void silcpurple_wb_clear(PurpleWhiteboard *wb);

#endif /* SILCPURPLE_WB_H */
