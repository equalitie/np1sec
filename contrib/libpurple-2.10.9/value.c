/**
 * @file value.c Value wrapper API
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

#include "value.h"

#define OUTGOING_FLAG 0x01

PurpleValue *
purple_value_new(PurpleType type, ...)
{
	PurpleValue *value;
	va_list args;

	g_return_val_if_fail(type != PURPLE_TYPE_UNKNOWN, NULL);

	value = g_new0(PurpleValue, 1);

	value->type = type;

	va_start(args, type);

	if (type == PURPLE_TYPE_SUBTYPE)
		value->u.subtype = va_arg(args, int);
	else if (type == PURPLE_TYPE_BOXED)
		value->u.specific_type = g_strdup(va_arg(args, char *));

	va_end(args);

	return value;
}

PurpleValue *
purple_value_new_outgoing(PurpleType type, ...)
{
	PurpleValue *value;
	va_list args;

	g_return_val_if_fail(type != PURPLE_TYPE_UNKNOWN, NULL);

	value = g_new0(PurpleValue, 1);

	value->type = type;

	va_start(args, type);

	if (type == PURPLE_TYPE_SUBTYPE)
		value->u.subtype = va_arg(args, int);
	else if (type == PURPLE_TYPE_BOXED)
		value->u.specific_type = g_strdup(va_arg(args, char *));

	va_end(args);

	value->flags |= OUTGOING_FLAG;

	return value;
}

void
purple_value_destroy(PurpleValue *value)
{
	g_return_if_fail(value != NULL);

	if (purple_value_get_type(value) == PURPLE_TYPE_BOXED)
	{
		g_free(value->u.specific_type);
	}
	else if (purple_value_get_type(value) == PURPLE_TYPE_STRING)
	{
		g_free(value->data.string_data);
	}

	g_free(value);
}

PurpleValue *
purple_value_dup(const PurpleValue *value)
{
	PurpleValue *new_value;
	PurpleType type;

	g_return_val_if_fail(value != NULL, NULL);

	type = purple_value_get_type(value);

	if (type == PURPLE_TYPE_SUBTYPE)
	{
		new_value = purple_value_new(PURPLE_TYPE_SUBTYPE,
								   purple_value_get_subtype(value));
	}
	else if (type == PURPLE_TYPE_BOXED)
	{
		new_value = purple_value_new(PURPLE_TYPE_BOXED,
								   purple_value_get_specific_type(value));
	}
	else
		new_value = purple_value_new(type);

	new_value->flags = value->flags;

	switch (type)
	{
		case PURPLE_TYPE_CHAR:
			purple_value_set_char(new_value, purple_value_get_char(value));
			break;

		case PURPLE_TYPE_UCHAR:
			purple_value_set_uchar(new_value, purple_value_get_uchar(value));
			break;

		case PURPLE_TYPE_BOOLEAN:
			purple_value_set_boolean(new_value, purple_value_get_boolean(value));
			break;

		case PURPLE_TYPE_SHORT:
			purple_value_set_short(new_value, purple_value_get_short(value));
			break;

		case PURPLE_TYPE_USHORT:
			purple_value_set_ushort(new_value, purple_value_get_ushort(value));
			break;

		case PURPLE_TYPE_INT:
			purple_value_set_int(new_value, purple_value_get_int(value));
			break;

		case PURPLE_TYPE_UINT:
			purple_value_set_uint(new_value, purple_value_get_uint(value));
			break;

		case PURPLE_TYPE_LONG:
			purple_value_set_long(new_value, purple_value_get_long(value));
			break;

		case PURPLE_TYPE_ULONG:
			purple_value_set_ulong(new_value, purple_value_get_ulong(value));
			break;

		case PURPLE_TYPE_INT64:
			purple_value_set_int64(new_value, purple_value_get_int64(value));
			break;

		case PURPLE_TYPE_UINT64:
			purple_value_set_uint64(new_value, purple_value_get_uint64(value));
			break;

		case PURPLE_TYPE_STRING:
			purple_value_set_string(new_value, purple_value_get_string(value));
			break;

		case PURPLE_TYPE_OBJECT:
			purple_value_set_object(new_value, purple_value_get_object(value));
			break;

		case PURPLE_TYPE_POINTER:
			purple_value_set_pointer(new_value, purple_value_get_pointer(value));
			break;

		case PURPLE_TYPE_ENUM:
			purple_value_set_enum(new_value, purple_value_get_enum(value));
			break;

		case PURPLE_TYPE_BOXED:
			purple_value_set_boxed(new_value, purple_value_get_boxed(value));
			break;

		default:
			break;
	}

	return new_value;
}

PurpleType
purple_value_get_type(const PurpleValue *value)
{
	g_return_val_if_fail(value != NULL, PURPLE_TYPE_UNKNOWN);

	return value->type;
}

unsigned int
purple_value_get_subtype(const PurpleValue *value)
{
	g_return_val_if_fail(value != NULL, 0);
	g_return_val_if_fail(purple_value_get_type(value) == PURPLE_TYPE_SUBTYPE, 0);

	return value->u.subtype;
}

const char *
purple_value_get_specific_type(const PurpleValue *value)
{
	g_return_val_if_fail(value != NULL, NULL);
	g_return_val_if_fail(purple_value_get_type(value) == PURPLE_TYPE_BOXED, NULL);

	return value->u.specific_type;
}

gboolean
purple_value_is_outgoing(const PurpleValue *value)
{
	g_return_val_if_fail(value != NULL, FALSE);

	return (value->flags & OUTGOING_FLAG);
}

void
purple_value_set_char(PurpleValue *value, char data)
{
	g_return_if_fail(value != NULL);

	value->data.char_data = data;
}

void
purple_value_set_uchar(PurpleValue *value, unsigned char data)
{
	g_return_if_fail(value != NULL);

	value->data.uchar_data = data;
}

void
purple_value_set_boolean(PurpleValue *value, gboolean data)
{
	g_return_if_fail(value != NULL);

	value->data.boolean_data = data;
}

void
purple_value_set_short(PurpleValue *value, short data)
{
	g_return_if_fail(value != NULL);

	value->data.short_data = data;
}

void
purple_value_set_ushort(PurpleValue *value, unsigned short data)
{
	g_return_if_fail(value != NULL);

	value->data.ushort_data = data;
}

void
purple_value_set_int(PurpleValue *value, int data)
{
	g_return_if_fail(value != NULL);

	value->data.int_data = data;
}

void
purple_value_set_uint(PurpleValue *value, unsigned int data)
{
	g_return_if_fail(value != NULL);

	value->data.int_data = data;
}

void
purple_value_set_long(PurpleValue *value, long data)
{
	g_return_if_fail(value != NULL);

	value->data.long_data = data;
}

void
purple_value_set_ulong(PurpleValue *value, unsigned long data)
{
	g_return_if_fail(value != NULL);

	value->data.long_data = data;
}

void
purple_value_set_int64(PurpleValue *value, gint64 data)
{
	g_return_if_fail(value != NULL);

	value->data.int64_data = data;
}

void
purple_value_set_uint64(PurpleValue *value, guint64 data)
{
	g_return_if_fail(value != NULL);

	value->data.uint64_data = data;
}

void
purple_value_set_string(PurpleValue *value, const char *data)
{
	g_return_if_fail(value != NULL);
	g_return_if_fail(data == NULL || g_utf8_validate(data, -1, NULL));

	g_free(value->data.string_data);
	value->data.string_data = g_strdup(data);
}

void
purple_value_set_object(PurpleValue *value, void *data)
{
	g_return_if_fail(value != NULL);

	value->data.object_data = data;
}

void
purple_value_set_pointer(PurpleValue *value, void *data)
{
	g_return_if_fail(value != NULL);

	value->data.pointer_data = data;
}

void
purple_value_set_enum(PurpleValue *value, int data)
{
	g_return_if_fail(value != NULL);

	value->data.enum_data = data;
}

void
purple_value_set_boxed(PurpleValue *value, void *data)
{
	g_return_if_fail(value != NULL);

	value->data.boxed_data = data;
}

char
purple_value_get_char(const PurpleValue *value)
{
	g_return_val_if_fail(value != NULL, 0);

	return value->data.char_data;
}

unsigned char
purple_value_get_uchar(const PurpleValue *value)
{
	g_return_val_if_fail(value != NULL, 0);

	return value->data.uchar_data;
}

gboolean
purple_value_get_boolean(const PurpleValue *value)
{
	g_return_val_if_fail(value != NULL, FALSE);

	return value->data.boolean_data;
}

short
purple_value_get_short(const PurpleValue *value)
{
	g_return_val_if_fail(value != NULL, 0);

	return value->data.short_data;
}

unsigned short
purple_value_get_ushort(const PurpleValue *value)
{
	g_return_val_if_fail(value != NULL, 0);

	return value->data.ushort_data;
}

int
purple_value_get_int(const PurpleValue *value)
{
	g_return_val_if_fail(value != NULL, 0);

	return value->data.int_data;
}

unsigned int
purple_value_get_uint(const PurpleValue *value)
{
	g_return_val_if_fail(value != NULL, 0);

	return value->data.int_data;
}

long
purple_value_get_long(const PurpleValue *value)
{
	g_return_val_if_fail(value != NULL, 0);

	return value->data.long_data;
}

unsigned long
purple_value_get_ulong(const PurpleValue *value)
{
	g_return_val_if_fail(value != NULL, 0);

	return value->data.long_data;
}

gint64
purple_value_get_int64(const PurpleValue *value)
{
	g_return_val_if_fail(value != NULL, 0);

	return value->data.int64_data;
}

guint64
purple_value_get_uint64(const PurpleValue *value)
{
	g_return_val_if_fail(value != NULL, 0);

	return value->data.uint64_data;
}

const char *
purple_value_get_string(const PurpleValue *value)
{
	g_return_val_if_fail(value != NULL, NULL);

	return value->data.string_data;
}

void *
purple_value_get_object(const PurpleValue *value)
{
	g_return_val_if_fail(value != NULL, NULL);

	return value->data.object_data;
}

void *
purple_value_get_pointer(const PurpleValue *value)
{
	g_return_val_if_fail(value != NULL, NULL);

	return value->data.pointer_data;
}

int
purple_value_get_enum(const PurpleValue *value)
{
	g_return_val_if_fail(value != NULL, -1);

	return value->data.enum_data;
}

void *
purple_value_get_boxed(const PurpleValue *value)
{
	g_return_val_if_fail(value != NULL, NULL);

	return value->data.boxed_data;
}

