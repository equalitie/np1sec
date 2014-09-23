/*
 * nmcontact.c
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
#include "nmcontact.h"
#include "nmfield.h"
#include "nmuser.h"

struct _NMContact
{
	int id;
	int parent_id;
	int seq;
	char *dn;
	char *display_name;
	NMUserRecord *user_record;
	gpointer data;
	int ref_count;
};

struct _NMFolder
{
	int id;
	int seq;
	char *name;
	GSList *folders;
	GSList *contacts;
	int ref_count;
};

static int count = 0;

static void _release_folder_contacts(NMFolder * folder);
static void _release_folder_folders(NMFolder * folder);
static void _add_contacts(NMUser * user, NMFolder * folder, NMField * fields);
static void _add_folders(NMFolder * root, NMField * fields);

/*********************************************************************
 * Contact API
 *********************************************************************/

NMContact *
nm_create_contact()
{
	NMContact *contact = g_new0(NMContact, 1);

	contact->ref_count = 1;

	purple_debug(PURPLE_DEBUG_INFO, "novell", "Creating contact, total=%d\n",
			   count++);

	return contact;
}

/*
 * This creates a contact for the contact list. The
 * field array that is passed in should be a
 * NM_A_FA_CONTACT array.
 *
 */
NMContact *
nm_create_contact_from_fields(NMField * fields)
{
	NMContact *contact;
	NMField *field;

	if ( fields == NULL || fields->tag == NULL || fields->ptr_value == 0 ||
		 strcmp(fields->tag, NM_A_FA_CONTACT) )
	{
		return NULL;
	}

	contact = nm_create_contact();

	if ((field = nm_locate_field(NM_A_SZ_OBJECT_ID, (NMField *) fields->ptr_value))) {

		if (field->ptr_value)
			contact->id = atoi((char *) field->ptr_value);

	}

	if ((field = nm_locate_field(NM_A_SZ_PARENT_ID, (NMField *) fields->ptr_value))) {

		if (field->ptr_value)
			contact->parent_id = atoi((char *) field->ptr_value);

	}

	if ((field =
		 nm_locate_field(NM_A_SZ_SEQUENCE_NUMBER, (NMField *) fields->ptr_value))) {

		if (field->ptr_value)
			contact->seq = atoi((char *) field->ptr_value);

	}

	if ((field =
		 nm_locate_field(NM_A_SZ_DISPLAY_NAME, (NMField *) fields->ptr_value))) {

		if (field->ptr_value)
			contact->display_name = g_strdup((char *) field->ptr_value);

	}

	if ((field = nm_locate_field(NM_A_SZ_DN, (NMField *) fields->ptr_value))) {

		if (field->ptr_value)
			contact->dn = g_strdup((char *) field->ptr_value);

	}

	return contact;
}

void
nm_contact_update_list_properties(NMContact * contact, NMField * fields)
{
	NMField *field;

	if (contact == NULL || fields == NULL || fields->ptr_value == 0)
		return;

	if ((field = nm_locate_field(NM_A_SZ_OBJECT_ID, (NMField *) fields->ptr_value))) {

		if (field->ptr_value)
			contact->id = atoi((char *)field->ptr_value);

	}

	if ((field = nm_locate_field(NM_A_SZ_PARENT_ID, (NMField *) fields->ptr_value))) {

		if (field->ptr_value)
			contact->parent_id = atoi((char *) field->ptr_value);

	}

	if ((field =
		 nm_locate_field(NM_A_SZ_SEQUENCE_NUMBER, (NMField *) fields->ptr_value))) {

		if (field->ptr_value)
			contact->seq = atoi((char *) field->ptr_value);

	}

	if ((field =
		 nm_locate_field(NM_A_SZ_DISPLAY_NAME, (NMField *) fields->ptr_value))) {

		if (field->ptr_value) {
			if (contact->display_name)
				g_free(contact->display_name);

			contact->display_name = g_strdup((char *) field->ptr_value);
		}

	}

	if ((field = nm_locate_field(NM_A_SZ_DN, (NMField *) fields->ptr_value))) {

		if (field->ptr_value) {
			if (contact->dn)
				g_free(contact->dn);

			contact->dn = g_strdup((char *) field->ptr_value);
		}

	}
}

NMField *
nm_contact_to_fields(NMContact * contact)
{
	NMField *fields = NULL;

	if (contact == NULL)
		return NULL;

	fields = nm_field_add_pointer(fields, NM_A_SZ_OBJECT_ID, 0, NMFIELD_METHOD_VALID, 0,
								  g_strdup_printf("%d", contact->id), NMFIELD_TYPE_UTF8);

	fields = nm_field_add_pointer(fields, NM_A_SZ_PARENT_ID, 0, NMFIELD_METHOD_VALID, 0,
								  g_strdup_printf("%d", contact->parent_id), NMFIELD_TYPE_UTF8);

	fields = nm_field_add_pointer(fields, NM_A_SZ_SEQUENCE_NUMBER, 0, NMFIELD_METHOD_VALID, 0,
								  g_strdup_printf("%d", contact->seq), NMFIELD_TYPE_UTF8);

	if (contact->display_name != NULL) {
		fields = nm_field_add_pointer(fields, NM_A_SZ_DISPLAY_NAME, 0, NMFIELD_METHOD_VALID, 0,
									  g_strdup(contact->display_name), NMFIELD_TYPE_UTF8);
	}

	if (contact->dn != NULL) {
		fields = nm_field_add_pointer(fields, NM_A_SZ_DN, 0, NMFIELD_METHOD_VALID, 0,
									  g_strdup(contact->dn), NMFIELD_TYPE_UTF8);
	}

	return fields;
}

void
nm_contact_add_ref(NMContact * contact)
{
	if (contact)
		contact->ref_count++;
}

void
nm_release_contact(NMContact * contact)
{
	if (contact == NULL)
		return;

	if (--(contact->ref_count) == 0) {

		purple_debug(PURPLE_DEBUG_INFO, "novell",
				   "Releasing contact, total=%d\n", --count);

		if (contact->display_name) {
			g_free(contact->display_name);
		}

		if (contact->dn) {
			g_free(contact->dn);
		}

		if (contact->user_record) {
			nm_release_user_record(contact->user_record);
		}

		g_free(contact);
	}

}

const char *
nm_contact_get_display_name(NMContact * contact)
{
	if (contact == NULL)
		return NULL;

	if (contact->user_record != NULL && contact->display_name == NULL) {
		const char *full_name, *lname, *fname, *cn, *display_id;

		full_name = nm_user_record_get_full_name(contact->user_record);
		fname = nm_user_record_get_first_name(contact->user_record);
		lname = nm_user_record_get_last_name(contact->user_record);
		cn = nm_user_record_get_userid(contact->user_record);
		display_id = nm_user_record_get_display_id(contact->user_record);

		/* Try to build a display name. */
		if (full_name) {

			contact->display_name = g_strdup(full_name);

		} else if (fname && lname) {

			contact->display_name = g_strdup_printf("%s %s", fname, lname);

		} else {

			/* If auth attribute is set use it */
			if (nm_user_record_get_auth_attr(contact->user_record) &&
				display_id != NULL)	{

				contact->display_name = g_strdup(display_id);

			} else {

				/* Use CN or display id */
				if (cn) {

					contact->display_name = g_strdup(cn);

				} else if (display_id) {

					contact->display_name = g_strdup(display_id);

				}

			}

		}
	}

	return contact->display_name;
}

void
nm_contact_set_display_name(NMContact * contact, const char *display_name)
{
	if (contact == NULL)
		return;

	if (contact->display_name) {
		g_free(contact->display_name);
		contact->display_name = NULL;
	}

	if (display_name)
		contact->display_name = g_strdup(display_name);
}

void
nm_contact_set_dn(NMContact * contact, const char *dn)
{
	if (contact == NULL)
		return;

	if (contact->dn) {
		g_free(contact->dn);
		contact->dn = NULL;
	}

	if (dn)
		contact->dn = g_strdup(dn);
}

const char *
nm_contact_get_dn(NMContact * contact)
{
	if (contact == NULL)
		return NULL;

	return contact->dn;
}

gpointer
nm_contact_get_data(NMContact * contact)
{
	if (contact == NULL)
		return NULL;

	return contact->data;
}

int
nm_contact_get_id(NMContact * contact)
{
	if (contact == NULL)
		return -1;

	return contact->id;
}

int
nm_contact_get_parent_id(NMContact * contact)
{
	if (contact == NULL)
		return -1;

	return contact->parent_id;
}

void
nm_contact_set_data(NMContact * contact, gpointer data)
{
	if (contact == NULL)
		return;

	contact->data = data;
}

void
nm_contact_set_user_record(NMContact * contact, NMUserRecord * user_record)
{
	if (contact == NULL)
		return;

	if (contact->user_record) {
		nm_release_user_record(contact->user_record);
	}

	nm_user_record_add_ref(user_record);
	contact->user_record = user_record;
}

NMUserRecord *
nm_contact_get_user_record(NMContact * contact)
{
	if (contact == NULL)
		return NULL;

	return contact->user_record;
}

const char *
nm_contact_get_userid(NMContact * contact)
{
	NMUserRecord *user_record;
	const char *userid = NULL;

	if (contact == NULL)
		return NULL;

	user_record = nm_contact_get_user_record(contact);
	if (user_record) {
		userid = nm_user_record_get_userid(user_record);
	}

	return userid;
}

const char *
nm_contact_get_display_id(NMContact * contact)
{
	NMUserRecord *user_record;
	const char *id = NULL;

	if (contact == NULL)
		return NULL;

	user_record = nm_contact_get_user_record(contact);
	if (user_record) {
		id = nm_user_record_get_display_id(user_record);
	}

	return id;
}


/*********************************************************************
 * Folder API
 *********************************************************************/

NMFolder *
nm_create_folder(const char *name)
{
	NMFolder *folder = g_new0(NMFolder, 1);

	if (name)
		folder->name = g_strdup(name);

	folder->ref_count = 1;

	return folder;
}

NMFolder *
nm_create_folder_from_fields(NMField * fields)
{
	NMField *field;
	NMFolder *folder;

	if (fields == NULL || fields->ptr_value == 0)
		return NULL;

	folder = g_new0(NMFolder, 1);

	if ((field = nm_locate_field(NM_A_SZ_OBJECT_ID, (NMField *) fields->ptr_value))) {

		if (field->ptr_value)
			folder->id = atoi((char *) field->ptr_value);
	}

	if ((field =
		 nm_locate_field(NM_A_SZ_SEQUENCE_NUMBER, (NMField *) fields->ptr_value))) {

		if (field->ptr_value)
			folder->seq = atoi((char *) field->ptr_value);
	}

	if ((field =
		 nm_locate_field(NM_A_SZ_DISPLAY_NAME, (NMField *) fields->ptr_value))) {

		if (field->ptr_value)
			folder->name = g_strdup((char *) field->ptr_value);
	}

	folder->ref_count = 1;
	return folder;
}

NMField *
nm_folder_to_fields(NMFolder * folder)
{
	NMField *fields = NULL;

	if (folder == NULL)
		return NULL;

	fields = nm_field_add_pointer(fields, NM_A_SZ_OBJECT_ID, 0, NMFIELD_METHOD_VALID, 0,
								  g_strdup_printf("%d", folder->id), NMFIELD_TYPE_UTF8);

	fields = nm_field_add_pointer(fields, NM_A_SZ_PARENT_ID, 0, NMFIELD_METHOD_VALID, 0,
								  g_strdup("0"), NMFIELD_TYPE_UTF8);

	fields = nm_field_add_pointer(fields, NM_A_SZ_TYPE, 0, NMFIELD_METHOD_VALID, 0,
								  g_strdup("1"), NMFIELD_TYPE_UTF8);

	fields = nm_field_add_pointer(fields, NM_A_SZ_SEQUENCE_NUMBER, 0, NMFIELD_METHOD_VALID, 0,
								  g_strdup_printf("%d", folder->seq), NMFIELD_TYPE_UTF8);

	if (folder->name != NULL) {
		fields = nm_field_add_pointer(fields, NM_A_SZ_DISPLAY_NAME, 0, NMFIELD_METHOD_VALID, 0,
									  g_strdup(folder->name), NMFIELD_TYPE_UTF8);
	}


	return fields;
}

void
nm_folder_update_list_properties(NMFolder * folder, NMField * fields)
{
	NMField *field;

	if (folder == NULL || fields == NULL || fields->ptr_value == 0)
		return;

	if ((field = nm_locate_field(NM_A_SZ_OBJECT_ID, (NMField *) fields->ptr_value))) {

		if (field->ptr_value)
			folder->id = atoi((char *) field->ptr_value);

	}

	if ((field =
		 nm_locate_field(NM_A_SZ_SEQUENCE_NUMBER, (NMField *) fields->ptr_value))) {

		if (field->ptr_value)
			folder->seq = atoi((char *) field->ptr_value);

	}

	if ((field =
		 nm_locate_field(NM_A_SZ_DISPLAY_NAME, (NMField *) fields->ptr_value))) {

		if (field->ptr_value) {
			if (folder->name)
				g_free(folder->name);

			folder->name = g_strdup((char *) field->ptr_value);
		}

	}

}

void
nm_release_folder(NMFolder * folder)
{
	if (folder == NULL)
		return;

	if (--(folder->ref_count) == 0) {
		if (folder->name) {
			g_free(folder->name);
		}

		if (folder->folders) {
			_release_folder_folders(folder);
		}

		if (folder->contacts) {
			_release_folder_contacts(folder);
		}

		g_free(folder);
	}
}


void
nm_folder_add_ref(NMFolder * folder)
{
	if (folder)
		folder->ref_count++;
}

int
nm_folder_get_subfolder_count(NMFolder * folder)
{
	if (folder == NULL)
		return 0;

	if (folder->folders)
		return g_slist_length(folder->folders);
	else
		return 0;
}

NMFolder *
nm_folder_get_subfolder(NMFolder * folder, int index)
{
	if (folder == NULL)
		return NULL;

	if (folder->folders)
		return (NMFolder *) g_slist_nth_data(folder->folders, index);
	else
		return NULL;
}

int
nm_folder_get_contact_count(NMFolder * folder)
{
	if (folder == NULL)
		return 0;

	if (folder->contacts != NULL)
		return g_slist_length(folder->contacts);
	else
		return 0;
}

NMContact *
nm_folder_get_contact(NMFolder * folder, int index)
{
	if (folder == NULL)
		return NULL;

	if (folder->contacts)
		return (NMContact *) g_slist_nth_data(folder->contacts, index);
	else
		return NULL;
}

const char *
nm_folder_get_name(NMFolder * folder)
{
	if (folder == NULL)
		return NULL;

	return folder->name;
}

void
nm_folder_set_name(NMFolder * folder, const char *name)
{
	if (folder == NULL || name == NULL)
		return;

	if (folder->name)
		g_free(folder->name);

	folder->name = g_strdup(name);
}

int
nm_folder_get_id(NMFolder * folder)
{
	if (folder == NULL) {
		return  -1;
	}

	return folder->id;
}

void
nm_folder_add_folder_to_list(NMFolder * root, NMFolder * folder)
{
	GSList *node;

	if (root == NULL || folder == NULL)
		return;

	node = root->folders;
	while (node) {
		if (folder->seq <= ((NMFolder *) node->data)->seq) {
			nm_folder_add_ref(folder);
			root->folders = g_slist_insert_before(root->folders, node, folder);
			break;
		}
		node = g_slist_next(node);
	}
	if (node == NULL) {
		nm_folder_add_ref(folder);
		root->folders = g_slist_append(root->folders, folder);
	}
}

void
nm_folder_remove_contact(NMFolder * folder, NMContact * contact)
{
	GSList *node;

	if (folder == NULL || contact == NULL)
		return;

	node = folder->contacts;
	while (node) {
		if (contact->id == ((NMContact *) (node->data))->id) {
			folder->contacts = g_slist_remove(folder->contacts, node->data);
			nm_release_contact(contact);
			break;
		}
		node = g_slist_next(node);
	}
}

void
nm_folder_add_contact_to_list(NMFolder * root_folder, NMContact * contact)
{
	GSList *node = NULL;
	NMFolder *folder = root_folder;

	if (folder == NULL || contact == NULL)
		return;

	/* Find folder to add contact to */
	if (contact->parent_id != 0) {
		node = folder->folders;
		while (node) {
			folder = (NMFolder *) node->data;
			if (contact->parent_id == folder->id) {
				break;
			}
			folder = NULL;
			node = g_slist_next(node);
		}
	}

	/* Add contact to list */
	if (folder) {
		node = folder->contacts;
		while (node) {
			if (contact->seq <= ((NMContact *) (node->data))->seq) {
				nm_contact_add_ref(contact);
				folder->contacts =
					g_slist_insert_before(folder->contacts, node, contact);
				break;
			}
			node = g_slist_next(node);
		}

		if (node == NULL) {
			nm_contact_add_ref(contact);
			folder->contacts = g_slist_append(folder->contacts, contact);
		}
	}
}

void
nm_folder_add_contacts_and_folders(NMUser * user, NMFolder * root,
								   NMField * fields)
{
	/* Add the contacts and folders from the field array */
	if (user && root && fields) {
		_add_folders(root, fields);
		_add_contacts(user, root, fields);
	}
}

gpointer
nm_folder_find_item_by_object_id(NMFolder * root_folder, int object_id)
{
	int cnt, cnt2, i, j;
	gpointer item = NULL;
	NMFolder *folder;
	NMContact *contact;

	if (root_folder == NULL)
		return NULL;

	/* Check all contacts for the top level folder */
	cnt = nm_folder_get_contact_count(root_folder);
	for (i = 0; i < cnt; i++) {
		contact = nm_folder_get_contact(root_folder, i);
		if (contact && (contact->id == object_id)) {
			item = contact;
			break;
		}
	}

	/* If we haven't found the item yet, check the subfolders */
	if (item == NULL) {
		cnt = nm_folder_get_subfolder_count(root_folder);
		for (i = 0; (i < cnt) && (item == NULL); i++) {
			folder = nm_folder_get_subfolder(root_folder, i);

			/* Check the id of this folder */
			if (folder && (folder->id == object_id)) {
				item = folder;
				break;
			}

			/* Check all contacts for this folder */
			cnt2 = nm_folder_get_contact_count(folder);
			for (j = 0; j < cnt2; j++) {
				contact = nm_folder_get_contact(folder, j);
				if (contact && (contact->id == object_id)) {
					item = contact;
					break;
				}
			}
		}
	}

	return item;
}

NMContact *
nm_folder_find_contact_by_userid(NMFolder * folder, const char *userid)
{
	int cnt, i;
	NMContact *tmp, *contact = NULL;

	if (folder == NULL || userid == NULL)
		return NULL;

	cnt = nm_folder_get_contact_count(folder);
	for (i = 0; i < cnt; i++) {
		tmp = nm_folder_get_contact(folder, i);
		if (tmp && nm_utf8_str_equal(nm_contact_get_userid(tmp), userid)) {
			contact = tmp;
			break;
		}
	}

	return contact;
}

NMContact *
nm_folder_find_contact_by_display_id(NMFolder * folder, const char *display_id)
{
	int cnt, i;
	NMContact *tmp, *contact = NULL;

	if (folder == NULL || display_id == NULL)
		return NULL;

	cnt = nm_folder_get_contact_count(folder);
	for (i = 0; i < cnt; i++) {
		tmp = nm_folder_get_contact(folder, i);
		if (tmp && nm_utf8_str_equal(nm_contact_get_display_id(tmp), display_id)) {
			contact = tmp;
			break;
		}
	}

	return contact;
}

NMContact *
nm_folder_find_contact(NMFolder * folder, const char *dn)
{
	int cnt, i;
	NMContact *tmp, *contact = NULL;

	if (folder == NULL || dn == NULL)
		return NULL;

	cnt = nm_folder_get_contact_count(folder);
	for (i = 0; i < cnt; i++) {
		tmp = nm_folder_get_contact(folder, i);
		if (tmp && nm_utf8_str_equal(nm_contact_get_dn(tmp), dn)) {
			contact = tmp;
			break;
		}
	}

	return contact;
}


/*********************************************************************
 * Utility functions
 *********************************************************************/

static void
_release_folder_contacts(NMFolder * folder)
{
	GSList *cnode;
	NMContact *contact;

	for (cnode = folder->contacts; cnode; cnode = cnode->next) {
		contact = cnode->data;
		cnode->data = NULL;
		nm_release_contact(contact);
	}

	g_slist_free(folder->contacts);
	folder->contacts = NULL;
}

static void
_release_folder_folders(NMFolder * folder)
{
	GSList *fnode;
	NMFolder *subfolder;

	if (folder == NULL)
		return;

	for (fnode = folder->folders; fnode; fnode = fnode->next) {
		subfolder = fnode->data;
		fnode->data = NULL;
		nm_release_folder(subfolder);
	}

	g_slist_free(folder->folders);
	folder->folders = NULL;
}

static void
_add_folders(NMFolder * root, NMField * fields)
{
	NMFolder *folder = NULL;
	NMField *locate = NULL;

	locate = nm_locate_field(NM_A_FA_FOLDER, fields);
	while (locate != NULL) {

		/* Create a new folder */
		folder = nm_create_folder_from_fields(locate);

		/* Add subfolder to roots folder list */
		nm_folder_add_folder_to_list(root, folder);

		/* Decrement the ref count */
		nm_release_folder(folder);

		/* Find the next folder */
		locate = nm_locate_field(NM_A_FA_FOLDER, locate+1);

	}
}

static void
_add_contacts(NMUser * user, NMFolder * folder, NMField * fields)
{
	NMContact *contact = NULL;
	NMField *locate = NULL,  *details;
	NMUserRecord *user_record = NULL;

	locate = nm_locate_field(NM_A_FA_CONTACT, fields);
	while (locate != NULL) {

		/* Create a new contact from the fields */
		contact = nm_create_contact_from_fields(locate);

		/* Add it to our contact list */
		nm_folder_add_contact_to_list(folder, contact);

		/* Update the contact cache */
		nm_user_add_contact(user, contact);

		/* Update the user record cache */
		if ((details = nm_locate_field(NM_A_FA_USER_DETAILS,
									   (NMField *) locate->ptr_value))) {
			user_record = nm_find_user_record(user, nm_contact_get_dn(contact));
			if (user_record == NULL) {
				user_record = nm_create_user_record_from_fields(details);
				nm_user_record_set_dn(user_record, nm_contact_get_dn(contact));
				nm_user_add_user_record(user, user_record);
				nm_release_user_record(user_record);
			}
			nm_contact_set_user_record(contact, user_record);
		}

		nm_release_contact(contact);

		locate = nm_locate_field(NM_A_FA_CONTACT, locate+1);
	}
}
