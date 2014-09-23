/*
 * nmfield.c
 *
 * Copyright (c) 2004 Novell, Inc. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA	02111-1301	USA
 *
 */

#include <string.h>
#include <stdio.h>
#include "nmfield.h"

/* Free a field value and tag */
static void _free_field(NMField * field);

/* Free a field value */
static void _free_field_value(NMField * field);

/* Make a deep copy of the field */
static void _copy_field(NMField * dest, NMField * src);

/* Make a deep copy of the field's value */
static void _copy_field_value(NMField * dest, NMField * src);

/* Create a string from a value -- for debugging */
static char *_value_to_string(NMField * field);

static NMField *
_add_blank_field(NMField *fields, guint32 count)
{
	guint32 new_len;

	if (fields == NULL) {
		fields = g_new0(NMField, 10);
		fields->len = 10;
	} else {
		if (fields->len < count + 2) {
			new_len = count + 10;
			fields = g_realloc(fields, new_len * sizeof(NMField));
			fields->len = new_len;
		}
	}
	return fields;
}

NMField *
nm_field_add_number(NMField * fields, const char *tag, guint32 size, guint8 method,
					guint8 flags, guint32 value, guint8 type)
{
	guint32 count;
	NMField *field;

	count = nm_count_fields(fields);
	fields = _add_blank_field(fields, count);

	field = &(fields[count]);
	field->tag = g_strdup(tag);
	field->size = size;
	field->method = method;
	field->flags = flags;
	field->value = value;
	field->type = type;

	/* Null terminate the field array */
	field = &((fields)[count + 1]);
	field->tag = NULL;
	field->value = 0;
	field->ptr_value = NULL;

	return fields;
}

NMField *
nm_field_add_pointer(NMField * fields, const char *tag, guint32 size, guint8 method,
					 guint8 flags, gpointer value, guint8 type)
{
	guint32 count;
	NMField *field = NULL;

	count = nm_count_fields(fields);
	fields = _add_blank_field(fields, count);

	field = &(fields[count]);
	field->tag = g_strdup(tag);
	field->size = size;
	field->method = method;
	field->flags = flags;
	field->ptr_value = value;
	field->type = type;

	/* Null terminate the field array */
	field = &((fields)[count + 1]);
	field->tag = NULL;
	field->value = 0;
	field->ptr_value = NULL;

	return fields;
}

guint32
nm_count_fields(NMField * fields)
{
	guint32 count = 0;

	if (fields) {
		while (fields->tag != NULL) {
			count++;
			fields++;
		}
	}

	return count;
}

void
nm_free_fields(NMField ** fields)
{
	NMField *field = NULL;

	if ((fields == NULL) || (*fields == NULL))
		return;

	field = *fields;

	while (field->tag != NULL) {
		_free_field(field);
		field++;
	}

	g_free(*fields);
	*fields = NULL;
}


static void
_free_field(NMField * field)
{
	if (field == NULL)
		return;

	_free_field_value(field);
	g_free(field->tag);
}

static void
_free_field_value(NMField * field)
{
	if (field == NULL)
		return;

	switch (field->type) {
		case NMFIELD_TYPE_BINARY:
		case NMFIELD_TYPE_UTF8:
		case NMFIELD_TYPE_DN:
			g_free(field->ptr_value);
			break;

		case NMFIELD_TYPE_ARRAY:
		case NMFIELD_TYPE_MV:
			nm_free_fields((NMField **)&field->ptr_value);
			break;

		default:
			break;
	}

	field->size = 0;
	field->ptr_value = NULL;
}

NMField *
nm_locate_field(char *tag, NMField * fields)
{
	NMField *ret_fields = NULL;

	if ((fields == NULL) || (tag == NULL)) {
		return NULL;
	}

	while (fields->tag != NULL) {
		if (g_ascii_strcasecmp(fields->tag, tag) == 0) {
			ret_fields = fields;
			break;
		}
		fields++;
	}

	return ret_fields;
}

NMField *
nm_copy_field_array(NMField * src)
{
	NMField *ptr = NULL;
	NMField *dest = NULL;
	int count;

	if (src != NULL) {
		count = nm_count_fields(src) + 1;
		dest = g_new0(NMField, count);
		dest->len = count;
		ptr = dest;
		while (src->tag != NULL) {
			_copy_field(ptr, src);
			ptr++;
			src++;
		}
	}

	return dest;
}

static void
_copy_field(NMField * dest, NMField * src)
{
	dest->type = src->type;
	dest->flags = src->flags;
	dest->method = src->method;
	dest->tag = g_strdup(src->tag);
	_copy_field_value(dest, src);
}

static void
_copy_field_value(NMField * dest, NMField * src)
{
	dest->type = src->type;
	switch (dest->type) {
		case NMFIELD_TYPE_UTF8:
		case NMFIELD_TYPE_DN:
			if (src->size == 0 && src->ptr_value != NULL) {
				src->size = strlen((char *) src->ptr_value) + 1;
			}
			/* fall through */
		case NMFIELD_TYPE_BINARY:
			if (src->size != 0 && src->ptr_value != NULL) {
				dest->ptr_value = g_new0(char, src->size);
				memcpy(dest->ptr_value, src->ptr_value, src->size);
			}
			break;

		case NMFIELD_TYPE_ARRAY:
		case NMFIELD_TYPE_MV:
			dest->ptr_value = nm_copy_field_array((NMField *)src->ptr_value);
			break;

		default:
			/* numeric value */
			dest->value = src->value;
			break;
	}

	dest->size = src->size;
}

void
nm_remove_field(NMField * field)
{
	NMField *tmp;
	guint32 len;

	if ((field != NULL) && (field->tag != NULL)) {
		_free_field(field);

		/* Move fields down */
		tmp = field + 1;
		while (1) {
			/* Don't overwrite the size of the array */
			len = field->len;

			*field = *tmp;

			field->len = len;

			if (tmp->tag == NULL)
				break;

			field++;
			tmp++;
		}
	}
}

void
nm_print_fields(NMField * fields)
{
	char *str = NULL;
	NMField *field = fields;

	if (fields == NULL)
		return;

	while (field->tag != NULL) {
		if (field->type == NMFIELD_TYPE_ARRAY || field->type == NMFIELD_TYPE_MV) {
			printf("Subarray START: %s Method = %d\n", field->tag, field->method);
			nm_print_fields((NMField *) field->ptr_value);
			printf("Subarray END: %s\n", field->tag);
		} else {
			str = _value_to_string(field);
			printf("Tag=%s;Value=%s\n", field->tag, str);
			g_free(str);
			str = NULL;
		}
		field++;
	}

}

static char *
_value_to_string(NMField * field)
{
	char *value = NULL;

	if (field == NULL)
		return NULL;

	/* This is a single value attribute */
	if (((field->type == NMFIELD_TYPE_UTF8) ||
		 (field->type == NMFIELD_TYPE_DN)) && (field->ptr_value != NULL)) {
		value = g_strdup((const char *) field->ptr_value);
	} else if (field->type == NMFIELD_TYPE_BINARY && field->ptr_value != NULL) {
		value = g_new0(char, field->size);
		memcpy(value, (const char *) field->ptr_value, field->size);
	} else if (field->type == NMFIELD_TYPE_BOOL) {
		if (field->value) {
			value = g_strdup(NM_FIELD_TRUE);
		} else {
			value = g_strdup(NM_FIELD_FALSE);
		}
	} else {
		/* assume it is a number */
		value = g_new0(char, 20);

		switch (field->type) {
		case NMFIELD_TYPE_BYTE:
		case NMFIELD_TYPE_WORD:
		case NMFIELD_TYPE_DWORD:
			value = g_strdup_printf("%ld", (long) field->value);
			break;

		case NMFIELD_TYPE_UBYTE:
		case NMFIELD_TYPE_UWORD:
		case NMFIELD_TYPE_UDWORD:
			value = g_strdup_printf("%lu", (unsigned long) field->value);
			break;
		}
	}

	if (value == NULL)
		value = g_strdup("NULL");

	return value;
}
