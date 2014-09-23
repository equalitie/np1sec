/*
 * nmuserrecord.c
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

#include <glib.h>
#include <string.h>
#include "nmuserrecord.h"
#include "nmfield.h"
#include "nmuser.h"

struct _NMUserRecord
{
	NMSTATUS_T status;
	char *status_text;
	char *dn;
	char *cn;
	char *display_id;
	char *fname;
	char *lname;
	char *full_name;
	NMField *fields;
	gboolean auth_attr;
	gpointer data;
	int ref_count;
};

struct _NMProperty
{
	char *tag;
	char *value;
};

static int count = 0;

/* API functions */

NMUserRecord *
nm_create_user_record()
{
	NMUserRecord *user_record = g_new0(NMUserRecord, 1);

	user_record->ref_count = 1;

	purple_debug(PURPLE_DEBUG_INFO, "novell", "Creating user_record, total=%d\n",
			   count++);

	return user_record;
}

static char *
_get_attribute_value(NMField *field)
{
	char *value = NULL;

	if (field->ptr_value == NULL)
		return NULL;

	if (field->type == NMFIELD_TYPE_UTF8 || field->type == NMFIELD_TYPE_DN) {

		value = (char *)field->ptr_value;

	} else if (field->type == NMFIELD_TYPE_MV) {

		/* Need to handle multi-valued returns, for now
		 * just pick the first value and return it
		 */
		NMField *tmp = (NMField *)field->ptr_value;
		if ((tmp != NULL) &&
			((tmp->type == NMFIELD_TYPE_UTF8) ||
			(tmp->type == NMFIELD_TYPE_DN))) {

			value = (char *)tmp->ptr_value;

		} else {
			return NULL;
		}

	} else {
		return NULL;
	}

	return g_strdup(value);
}
/*
 * This creates a user_record for the reference list the
 * field array that is passed in should be a
 * NM_A_FA_USER_DETAILS array.
 */
NMUserRecord *
nm_create_user_record_from_fields(NMField * details)
{
	NMUserRecord *user_record;
	NMField *field, *fields = details;

	if (details == NULL) {
		return NULL;
	}

	if (details->type == NMFIELD_TYPE_ARRAY) {
		if (details->ptr_value == NULL)
			return NULL;
		fields = (NMField *) details->ptr_value;
	}

	user_record = nm_create_user_record();

	if ((field = nm_locate_field(NM_A_SZ_AUTH_ATTRIBUTE, fields))) {

		if (field->ptr_value) {
			user_record->display_id = _get_attribute_value(field);
			user_record->auth_attr = TRUE;
		}
	}

	if ((field = nm_locate_field(NM_A_SZ_DN, fields))) {

		if (field->ptr_value) {
			user_record->dn = _get_attribute_value(field);
		}
	}

	if ((field = nm_locate_field("CN", fields))) {

		if (field->ptr_value) {
			user_record->cn = _get_attribute_value(field);
		}
	}

	if ((field = nm_locate_field("Given Name", fields))) {

		if (field->ptr_value) {
			user_record->fname = _get_attribute_value(field);
		}
	}

	if ((field = nm_locate_field("Surname", fields))) {

		if (field->ptr_value) {
			user_record->lname = _get_attribute_value(field);
		}
	}

	if ((field = nm_locate_field("Full Name", fields))) {

		if (field->ptr_value) {
			user_record->full_name = _get_attribute_value(field);
		}
	}

	if ((field = nm_locate_field(NM_A_SZ_STATUS, fields))) {

		if (field->ptr_value)
			user_record->status = atoi((char *) field->ptr_value);

	}

	if ((field = nm_locate_field(NM_A_SZ_MESSAGE_BODY, fields))) {

		if (field->ptr_value)
			user_record->status_text = g_strdup((char *) field->ptr_value);

	}

	user_record->fields = nm_copy_field_array(fields);

	return user_record;
}

void
nm_user_record_copy(NMUserRecord * dest, NMUserRecord * src)
{
	if (dest == NULL || src == NULL)
		return;

	dest->status = src->status;

	/* Copy status text */
	if (dest->status_text) {
		g_free(dest->status_text);
		dest->status_text = NULL;
	}

	if (src->status_text)
		dest->status_text = g_strdup(src->status_text);

	/* Copy DN */
	if (dest->dn) {
		g_free(dest->dn);
		dest->dn = NULL;
	}

	if (src->dn)
		dest->dn = g_strdup(src->dn);

	/* Copy CN */
	if (dest->cn) {
		g_free(dest->cn);
		dest->cn = NULL;
	}

	if (src->cn)
		dest->cn = g_strdup(src->cn);

	/* Copy display id */
	if (dest->display_id) {
		g_free(dest->display_id);
		dest->display_id = NULL;
	}

	if (src->display_id)
		dest->display_id = g_strdup(src->display_id);

	/* Copy first name */
	if (dest->fname) {
		g_free(dest->fname);
		dest->fname = NULL;
	}

	if (src->fname)
		dest->fname = g_strdup(src->fname);

	/* Copy last name */
	if (dest->lname) {
		g_free(dest->lname);
		dest->lname = NULL;
	}

	if (src->lname)
		dest->lname = g_strdup(src->lname);

	/* Copy full name */
	if (dest->full_name) {
		g_free(dest->full_name);
		dest->full_name = NULL;
	}

	if (src->full_name)
		dest->full_name = g_strdup(src->full_name);

	/* Copy fields */
	if (src->fields) {

		if (dest->fields) {
			nm_free_fields(&dest->fields);
		}

		dest->fields = nm_copy_field_array(src->fields);
	}

	/* Copy data */
	dest->data = src->data;
}

void
nm_user_record_add_ref(NMUserRecord * user_record)
{
	if (user_record)
		user_record->ref_count++;
}

void
nm_release_user_record(NMUserRecord * user_record)
{
	if (--(user_record->ref_count) == 0) {

		purple_debug(PURPLE_DEBUG_INFO, "novell",
				   "Releasing user_record, total=%d\n", --count);

		if (user_record->dn) {
			g_free(user_record->dn);
		}

		if (user_record->cn) {
			g_free(user_record->cn);
		}

		if (user_record->display_id) {
			g_free(user_record->display_id);
		}

		if (user_record->fname) {
			g_free(user_record->fname);
		}

		if (user_record->lname) {
			g_free(user_record->lname);
		}

		if (user_record->full_name) {
			g_free(user_record->full_name);
		}

		if (user_record->status_text) {
			g_free(user_record->status_text);
		}

		nm_free_fields(&user_record->fields);

		g_free(user_record);
	}
}

/* UserRecord API */

NMSTATUS_T
nm_user_record_get_status(NMUserRecord * user_record)
{
	if (user_record == NULL)
		return (NMSTATUS_T) - 1;

	return user_record->status;

}

const char *
nm_user_record_get_status_text(NMUserRecord * user_record)
{
	if (user_record == NULL)
		return NULL;

	return user_record->status_text;
}

void
nm_user_record_set_dn(NMUserRecord * user_record, const char *dn)
{
	if (user_record != NULL && dn != NULL) {
		if (user_record->dn)
			g_free(user_record->dn);

		user_record->dn = g_strdup(dn);
	}
}

const char *
nm_user_record_get_dn(NMUserRecord * user_record)
{
	if (user_record == NULL)
		return NULL;

	return user_record->dn;
}

void
nm_user_record_set_userid(NMUserRecord * user_record, const char *userid)
{
	if (user_record != NULL && userid != NULL) {
		if (user_record->cn)
			g_free(user_record->cn);

		user_record->cn = g_strdup(userid);
	}
}

const char *
nm_user_record_get_userid(NMUserRecord * user_record)
{
	if (user_record == NULL)
		return NULL;

	return user_record->cn;
}

void
nm_user_record_set_display_id(NMUserRecord * user_record, const char *display_id)
{
	if (user_record != NULL && display_id != NULL) {
		if (user_record->display_id)
			g_free(user_record->display_id);

		user_record->display_id = g_strdup(display_id);
	}
}

const char *
nm_user_record_get_display_id(NMUserRecord * user_record)
{
	if (user_record == NULL)
		return NULL;

	if (user_record->display_id == NULL) {
		user_record->display_id = nm_typed_to_dotted(user_record->dn);
	}

	return user_record->display_id;
}

const char *
nm_user_record_get_full_name(NMUserRecord * user_record)
{
	if (user_record == NULL)
		return NULL;

	if (user_record->full_name == NULL) {
		if (user_record->fname && user_record->lname) {
			user_record->full_name = g_strdup_printf("%s %s",
													 user_record->fname,
													 user_record->lname);

		}
	}

	return user_record->full_name;
}

const char *
nm_user_record_get_first_name(NMUserRecord * user_record)
{
	if (user_record == NULL)
		return NULL;

	return user_record->fname;

}

const char *
nm_user_record_get_last_name(NMUserRecord * user_record)
{
	if (user_record == NULL)
		return NULL;

	return user_record->lname;
}

gpointer
nm_user_record_get_data(NMUserRecord * user_record)
{
	if (user_record == NULL)
		return NULL;

	return user_record->data;
}

void
nm_user_record_set_data(NMUserRecord * user_record, gpointer data)
{
	if (user_record == NULL)
		return;

	user_record->data = data;
}

void
nm_user_record_set_status(NMUserRecord * user_record,
						  int status, const char *text)
{
	if (user_record == NULL)
		return;

	user_record->status = status;

	if (user_record->status_text) {
		g_free(user_record->status_text);
		user_record->status_text = NULL;
	}

	if (text)
		user_record->status_text = g_strdup(text);
}

gboolean
nm_user_record_get_auth_attr(NMUserRecord *user_record)
{
	if (user_record == NULL)
		return FALSE;

	return user_record->auth_attr;
}

int
nm_user_record_get_property_count(NMUserRecord * user_record)
{
	NMField *locate, *fields;

	int count = 0;

	if (user_record && user_record->fields) {
		locate = nm_locate_field(NM_A_FA_INFO_DISPLAY_ARRAY,
								 (NMField *) user_record->fields);
		if (locate && (fields = (NMField *) (locate->ptr_value))) {
			count = (int) nm_count_fields(fields);
		}
	}
	return count;
}

NMProperty *
nm_user_record_get_property(NMUserRecord * user_record, int index)
{
	NMProperty *property = NULL;
	NMField *field = NULL, *fields, *locate;

	if (user_record && user_record->fields) {
		locate = nm_locate_field(NM_A_FA_INFO_DISPLAY_ARRAY,
								 (NMField *) user_record->fields);
		if (locate && (fields = (NMField *) (locate->ptr_value))) {
			int max = nm_count_fields(fields);

			if (index < max) {
				if (user_record) {
					field = &fields[index];
					if (field && field->tag && field->ptr_value) {
						property = g_new0(NMProperty, 1);
						property->tag = g_strdup(field->tag);
						property->value = _get_attribute_value(field);
					}
				}
			}
		}
	}

	return property;
}

void
nm_release_property(NMProperty * property)
{
	if (property) {
		if (property->tag)
			g_free(property->tag);

		if (property->value)
			g_free(property->value);

		g_free(property);
	}
}

const char *
nm_property_get_tag(NMProperty * property)
{
	if (property)
		return property->tag;
	else
		return NULL;
}

const char *
nm_property_get_value(NMProperty * property)
{
	if (property)
		return property->value;
	else
		return NULL;
}
