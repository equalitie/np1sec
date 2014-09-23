#include "module.h"

MODULE = Purple::Whiteboard  PACKAGE = Purple::Whiteboard  PREFIX = purple_whiteboard_
PROTOTYPES: ENABLE

void
purple_whiteboard_clear(wb)
	Purple::Whiteboard wb

Purple::Whiteboard
purple_whiteboard_create(account, who, state)
	Purple::Account account
	const char* who
	int state

void
purple_whiteboard_destroy(wb)
	Purple::Whiteboard wb

void
purple_whiteboard_draw_line(wb, x1, y1, x2, y2, color, size)
	Purple::Whiteboard wb
	int x1
	int y1
	int x2
	int y2
	int color
	int size

void
purple_whiteboard_draw_point(wb, x, y, color, size)
	Purple::Whiteboard wb
	int x
	int y
	int color
	int size

Purple::Whiteboard
purple_whiteboard_get_session(account, who)
	Purple::Account account
	const char* who

void
purple_whiteboard_send_brush(wb, size, color)
	Purple::Whiteboard wb
	int size
	int color

void
purple_whiteboard_send_clear(wb)
	Purple::Whiteboard wb

void
purple_whiteboard_set_brush(wb, size, color)
	Purple::Whiteboard wb
	int size
	int color

void
purple_whiteboard_set_dimensions(wb, width, height)
	Purple::Whiteboard wb
	int width
	int height

gboolean
purple_whiteboard_get_brush(wb, OUTLIST int size, OUTLIST int color)
	Purple::Whiteboard wb
	PROTOTYPE: $

gboolean
purple_whiteboard_get_dimensions(wb, OUTLIST int width, OUTLIST int height)
	Purple::Whiteboard wb
	PROTOTYPE: $

void
purple_whiteboard_start(wb)
	Purple::Whiteboard wb

