/*
 * nmcontact.h
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

#ifndef __NM_CONTACT_H__
#define __NM_CONTACT_H__

#include <glib.h>

typedef struct _NMContact NMContact;
typedef struct _NMContactProperty NMContactProperty;
typedef struct _NMFolder NMFolder;

#include "nmfield.h"
#include "nmuser.h"

/**
 * Creates a contact
 *
 * Should be released by calling nm_release_contact
 *
 * @return 			The new NMContact
 *
 */
NMContact *nm_create_contact(void);

/**
 * Creates a contact from a field array representing the
 * contact
 *
 * Should be released by calling nm_release_contact
 *
 * @param	fields	Should be the NM_A_FA_CONTACT for
 *					the contact
 *
 * @return	The new contact
 *
 */
NMContact *nm_create_contact_from_fields(NMField * fields);

/**
 * Add a reference to an existing contact
 *
 * The reference should be released by calling
 * nm_release_contact
 *
 * @param	contact	The contact
 *
 */
void nm_contact_add_ref(NMContact * contact);

/**
 * Update the contact list properties of the contact (sequence, parent id, etc.)
 *
 * @param	contact	The contact to update
 * @param	fields	The fields to update from (should be a NM_A_FA_CONTACT array)
 *
 */
void nm_contact_update_list_properties(NMContact * contact, NMField * fields);

/**
 * Release a contact reference
 *
 * @param	contact	The contact to release.
 *
 */
void nm_release_contact(NMContact * contact);

/**
 * Get the display name of a contact
 *
 * @param	contact	The contact
 *
 * @return	The display name of a contact
 *
 */
const char *nm_contact_get_display_name(NMContact * contact);

/**
 * Get the DN of a contact
 *
 * @param	contact	The contact
 *
 * @return	The DN of the contact
 */
const char *nm_contact_get_dn(NMContact * contact);

/**
 * Set the display name for a contact. This is called
 * by nm_send_rename_contact. It should not be called
 * directly (it does not change the display name on the
 * server side list -- nm_send_rename_conact does).
 *
 * @param	contact			The contact
 * @param	display_name	The new display name
 *
 */
void nm_contact_set_display_name(NMContact * contact, const char * display_name);

/**
 * Set the DN for the contact
 *
 * @param	contact	The contact
 * @param	dn		The new DN for the contact
 *
 */
void nm_contact_set_dn(NMContact * contact, const char * dn);

/**
 * Return a field array (NM_A_FA_CONTACT) representing the contact
 *
 * @param	contact	The contact
 *
 * @return	A field array representing the contact
 */
NMField *nm_contact_to_fields(NMContact * contact);

/**
 * Set the user record for the contact
 *
 * @param	contact			The contact
 * @param	user_record		The user record
 *
 */
void nm_contact_set_user_record(NMContact * contact, NMUserRecord * user_record);

/**
 * Get the user record for the contact
 *
 * @param	contact	The contact
 *
 * @return	The user record associated with the contact
 *
 */
NMUserRecord *nm_contact_get_user_record(NMContact * contact);

/**
 * Get the user defined data for the contact
 *
 * @param	contact	The contact
 *
 * @return	The user defined data for the contact
 *
 */
gpointer nm_contact_get_data(NMContact * contact);

/**
 * Get the Object ID for the contact
 *
 * @param	contact	The contact
 *
 * @return	The ID for the contact
 */
int nm_contact_get_id(NMContact * contact);

/**
 * Get the ID for the folder that the contact is in
 *
 * @param	contact	The contact
 *
 * @return	The ID of the folder that contains the contact
 *
 */
int nm_contact_get_parent_id(NMContact * contact);

/**
 * Get The userid of the contact.
 *
 * @param	contact	The contact
 *
 * @return	The userid of the contact
 *
 */
const char *nm_contact_get_userid(NMContact * contact);

/**
 * Get the display id of the contact
 *
 * @param	contact	The contact
 *
 * @return	The display id of the contact
 */
const char *nm_contact_get_display_id(NMContact * contact);

/**
 * Set the user defined data for the contact
 *
 * @param	contact	The contact
 * @param	data	The user defined data
 *
 */
void nm_contact_set_data(NMContact * contact, gpointer data);

/**
 * Create a folder with the given name
 *
 * @param	name	The name of the folder
 *
 * @return 	The new folder
 *
 */
NMFolder *nm_create_folder(const char *name);

/**
 * Create a folder from a NM_A_FA_FOLDER field array
 *
 * @param	fields	The NM_A_FA_FOLDER field array
 *
 * @return	The new folder
 *
 */
NMFolder *nm_create_folder_from_fields(NMField * fields);

/**
 * Add a reference to an existing folder
 *
 * The reference should be released by calling
 * nm_release_folder
 *
 * @param	folder	The folder
 *
 */
void nm_folder_add_ref(NMFolder * folder);

/**
 * Release a reference to a folder.
 *
 * @param	folder	The folder to release
 *
 */
void nm_release_folder(NMFolder * folder);

/**
 * Return the number of subfolders for the given
 * folder
 *
 * @param	folder	The folder
 *
 * @return	The number of subfolders contained by folder
 */
int nm_folder_get_subfolder_count(NMFolder * folder);

/**
 * Get a subfolder
 *
 * @param	folder	The root folder
 * @param	index	The index of the folder to get
 *
 * @return	The subfolder at the given index
 *
 */
NMFolder *nm_folder_get_subfolder(NMFolder * folder, int index);

/**
 * Get the number of contacts in the given folder
 *
 * @param	folder	The folder
 *
 * @return	The number of contacts contained by folder
 *
 */
int nm_folder_get_contact_count(NMFolder * folder);

/**
 * Get a contact in the given folder
 *
 * @param	folder	The folder
 * @param	index	The index of the contact to get
 *
 * @return	The contact at the given index
 *
 */
NMContact *nm_folder_get_contact(NMFolder * folder, int index);

/**
 * Get the name of the folder
 *
 * @param	folder	The folder
 *
 * @return	The name of the folder.
 *
 */
const char *nm_folder_get_name(NMFolder * folder);

/**
 * Set the name of a folder. Do not call this directly.
 * It does not change the name of the folder in the
 * server side contact list. You must call
 * nm_send_set_folder_name().
 *
 * @param	folder	The folder
 * @param	name	The new name for the folder
 *
 */
void nm_folder_set_name(NMFolder * folder, const char *name);

/**
 * Get Object ID for folder
 *
 * @param	folder	The folder
 *
 * @return	The ID of the folder
 *
 */
int nm_folder_get_id(NMFolder * folder);

/**
 * Add contacts and folders from fields into root
 *
 * @param	user	The logged in user
 * @param	root	The root folder
 * @param	fields	The contact list field array
 *
 */
void nm_folder_add_contacts_and_folders(NMUser * user, NMFolder * root,
										NMField * fields);
/**
 * Add a contact to the contact list.
 *
 * @param	root_folder	The root folder of the contact list
 * @param	contact		The contact to add
 *
 */
void nm_folder_add_contact_to_list(NMFolder * root_folder,
									  NMContact * contact);

/**
 * Update the contact list properties of the folder (sequence, parent id, etc.)
 *
 * @param	folder	The folder to update
 * @param	fields	The fields to update from (should be a NM_A_FA_FOLDER array)
 *
 */
void nm_folder_update_list_properties(NMFolder * folder, NMField * fields);

/**
 * Add folder to the contact list
 *
 * @param	root_folder	The root folder of the contact list
 * @param	folder		The folder to add to the contact list
 *
 */
void nm_folder_add_folder_to_list(NMFolder * root_folder, NMFolder * folder);

/**
 * Find the object with the given id
 *
 * @param	root_folder	The root folder of the contact list
 * @param	object_id	The object id of the object to find
 *
 * @return	The object with object id (either a contact or a folder)
 */
gpointer nm_folder_find_item_by_object_id(NMFolder * root_folder,
										  int object_id);

/**
 * Remove a contact from the folder
 *
 * @param	folder	The folder
 * @param	contact	The contact to remove
 *
 */
void nm_folder_remove_contact(NMFolder * folder, NMContact * contact);

/**
 * Find a contact in a folder by DN
 *
 * @param	folder	The folder to search
 * @param	dn		The DN of the contact to find
 *
 * @return	The contact if found, NULL otherwise
 *
 */
NMContact *nm_folder_find_contact(NMFolder * folder, const char *dn);

/**
 * Find a contact in a folder by userid
 *
 * @param	folder	The folder to search
 * @param	userid	The userid of the contact to find
 *
 * @return	The contact if found, NULL otherwise
 *
 */
NMContact *nm_folder_find_contact_by_userid(NMFolder * folder,
											const char *userid);

/**
 * Find a contact in a folder by display id
 *
 * @param	folder		The folder to search
 * @param	display_id	The userid of the contact to find
 *
 * @return	The contact if found, NULL otherwise
 *
 */
NMContact *
nm_folder_find_contact_by_display_id(NMFolder * folder, const char *display_id);

/**
 * Return a field array (NM_A_FA_FOLDER) representing the folder
 *
 * @param	folder	The folder
 *
 * @return	A field array representing the folder
 */
NMField *nm_folder_to_fields(NMFolder * folder);

#endif
