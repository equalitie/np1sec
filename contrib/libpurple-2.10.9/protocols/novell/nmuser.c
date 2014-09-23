/*
 * nmuser.c
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

#include "internal.h"
#include <string.h>
#include "nmfield.h"
#include "nmuser.h"
#include "nmconn.h"
#include "nmcontact.h"
#include "nmuserrecord.h"
#include "util.h"

/* This is the template that we wrap outgoing messages in, since the other
 * GW Messenger clients expect messages to be in RTF.
 */
#define RTF_TEMPLATE 	"{\\rtf1\\ansi\n"\
                        "{\\fonttbl{\\f0\\fnil Unknown;}}\n"\
						"{\\colortbl ;\\red0\\green0\\blue0;}\n"\
						"\\uc1\\cf1\\f0\\fs24 %s\\par\n}"
#define NM_MAX_MESSAGE_SIZE 2048

static NMERR_T nm_process_response(NMUser * user);
static void _update_contact_list(NMUser * user, NMField * fields);
static void _handle_multiple_get_details_login_cb(NMUser * user, NMERR_T ret_code,
												  gpointer resp_data, gpointer user_data);
static char * nm_rtfize_text(char *text);

/**
 * See header for comments on on "public" functions
 */

NMUser *
nm_initialize_user(const char *name, const char *server_addr,
				   int port, gpointer data, nm_event_cb event_callback)
{
	NMUser *user;
	if (name == NULL || server_addr == NULL || event_callback == NULL)
		return NULL;

	user = g_new0(NMUser, 1);



	user->contacts =
		g_hash_table_new_full(g_str_hash, nm_utf8_str_equal,
							  g_free, (GDestroyNotify) nm_release_contact);

	user->user_records =
		g_hash_table_new_full(g_str_hash, nm_utf8_str_equal, g_free,
							  (GDestroyNotify) nm_release_user_record);

	user->display_id_to_dn = g_hash_table_new_full(g_str_hash, nm_utf8_str_equal,
												   g_free, g_free);

	user->name = g_strdup(name);
	user->conn = nm_create_conn(server_addr, port);
	user->conn->addr = g_strdup(server_addr);
	user->conn->port = port;
	user->evt_callback = event_callback;
	user->client_data = data;

	return user;
}


void
nm_deinitialize_user(NMUser * user)
{
	nm_release_conn(user->conn);

	if (user->contacts) {
		g_hash_table_destroy(user->contacts);
	}

	if (user->user_records) {
		g_hash_table_destroy(user->user_records);
	}

	if (user->display_id_to_dn) {
		g_hash_table_destroy(user->display_id_to_dn);
	}

	if (user->name) {
		g_free(user->name);
	}

	if (user->user_record) {
		nm_release_user_record(user->user_record);
	}

	nm_conference_list_free(user);
	nm_destroy_contact_list(user);

	g_free(user);
}

NMERR_T
nm_send_login(NMUser * user, const char *pwd, const char *my_addr,
			  const char *user_agent, nm_response_cb callback, gpointer data)
{
	NMERR_T rc = NM_OK;
	NMField *fields = NULL;

	if (user == NULL || pwd == NULL || user_agent == NULL) {
		return NMERR_BAD_PARM;
	}

	fields = nm_field_add_pointer(fields, NM_A_SZ_USERID, 0, NMFIELD_METHOD_VALID, 0,
								  g_strdup(user->name), NMFIELD_TYPE_UTF8);

	fields = nm_field_add_pointer(fields, NM_A_SZ_CREDENTIALS, 0, NMFIELD_METHOD_VALID, 0,
								  g_strdup(pwd), NMFIELD_TYPE_UTF8);

	fields = nm_field_add_pointer(fields, NM_A_SZ_USER_AGENT, 0, NMFIELD_METHOD_VALID, 0,
								  g_strdup(user_agent), NMFIELD_TYPE_UTF8);

	fields = nm_field_add_number(fields, NM_A_UD_BUILD, 0, NMFIELD_METHOD_VALID, 0,
								 NM_PROTOCOL_VERSION, NMFIELD_TYPE_UDWORD);
	if (my_addr) {
		fields = nm_field_add_pointer(fields, NM_A_IP_ADDRESS, 0, NMFIELD_METHOD_VALID, 0,
									  g_strdup(my_addr), NMFIELD_TYPE_UTF8);
	}

	/* Send the login */
	rc = nm_send_request(user->conn, "login", fields, callback, data, NULL);

	nm_free_fields(&fields);
	return rc;
}

NMERR_T
nm_send_set_status(NMUser * user, int status, const char *text,
				   const char *auto_resp, nm_response_cb callback, gpointer data)
{
	NMERR_T rc = NM_OK;
	NMField *fields = NULL;

	if (user == NULL)
		return NMERR_BAD_PARM;

	/* Add the status */
	fields = nm_field_add_pointer(fields, NM_A_SZ_STATUS, 0, NMFIELD_METHOD_VALID, 0,
								  g_strdup_printf("%d", status), NMFIELD_TYPE_UTF8);

	/* Add the status text and auto reply text if there is any */
	if (text) {
		fields = nm_field_add_pointer(fields, NM_A_SZ_STATUS_TEXT, 0,
									  NMFIELD_METHOD_VALID, 0, g_strdup(text),
									  NMFIELD_TYPE_UTF8);
	}

	if (auto_resp) {
		fields = nm_field_add_pointer(fields, NM_A_SZ_MESSAGE_BODY, 0,
									  NMFIELD_METHOD_VALID, 0, g_strdup(auto_resp),
									  NMFIELD_TYPE_UTF8);
	}

	rc = nm_send_request(user->conn, "setstatus", fields, callback, data, NULL);

	nm_free_fields(&fields);
	return rc;
}

NMERR_T
nm_send_multiple_get_details(NMUser * user, GSList *names,
							 nm_response_cb callback, gpointer data)
{
	NMERR_T rc = NM_OK;
	NMField *fields = NULL;
	GSList *node;

	if (user == NULL || names == NULL)
		return NMERR_BAD_PARM;

	/* Add in DN or display id */
	for (node = names; node; node = node->next) {
		fields = nm_field_add_pointer(fields, NM_A_SZ_USERID, 0, NMFIELD_METHOD_VALID, 0,
									  g_strdup(node->data), NMFIELD_TYPE_UTF8);
	}

	rc = nm_send_request(user->conn, "getdetails", fields, callback, data, NULL);

	nm_free_fields(&fields);
	return rc;
}

NMERR_T
nm_send_get_details(NMUser * user, const char *name,
					nm_response_cb callback, gpointer data)
{
	NMERR_T rc = NM_OK;
	NMField *fields = NULL;

	if (user == NULL || name == NULL)
		return NMERR_BAD_PARM;

	/* Add in DN or display id */
	if (strstr("=", name)) {
		fields = nm_field_add_pointer(fields, NM_A_SZ_DN, 0, NMFIELD_METHOD_VALID, 0,
									  g_strdup(name), NMFIELD_TYPE_DN);
	} else {

		const char *dn = nm_lookup_dn(user, name);
		if (dn) {
			fields = nm_field_add_pointer(fields, NM_A_SZ_DN, 0, NMFIELD_METHOD_VALID, 0,
										  g_strdup(name), NMFIELD_TYPE_DN);
		} else {
			fields =
				nm_field_add_pointer(fields, NM_A_SZ_USERID, 0, NMFIELD_METHOD_VALID, 0,
									 g_strdup(name), NMFIELD_TYPE_UTF8);
		}

	}

	rc = nm_send_request(user->conn, "getdetails", fields, callback, data, NULL);

	nm_free_fields(&fields);
	return rc;
}

NMERR_T
nm_send_create_conference(NMUser * user, NMConference * conference,
						  nm_response_cb callback, gpointer data)
{
	NMERR_T rc = NM_OK;
	NMField *fields = NULL;
	NMField *tmp = NULL;
	NMField *field = NULL;
	NMRequest *req = NULL;
	int count, i;

	if (user == NULL || conference == NULL)
		return NMERR_BAD_PARM;

	/* Add in a blank guid */
	tmp = nm_field_add_pointer(tmp, NM_A_SZ_OBJECT_ID, 0, NMFIELD_METHOD_VALID, 0,
							   g_strdup(BLANK_GUID), NMFIELD_TYPE_UTF8);

	fields = nm_field_add_pointer(fields, NM_A_FA_CONVERSATION, 0,
								  NMFIELD_METHOD_VALID, 0, tmp,
								  NMFIELD_TYPE_ARRAY);
	tmp = NULL;


	/* Add participants in */
	count = nm_conference_get_participant_count(conference);
	for (i = 0; i < count; i++) {
		NMUserRecord *user_record = nm_conference_get_participant(conference, i);

		if (user_record) {
			fields = nm_field_add_pointer(fields, NM_A_SZ_DN,
										  0, NMFIELD_METHOD_VALID, 0,
										  g_strdup(nm_user_record_get_dn(user_record)),
										  NMFIELD_TYPE_DN);
		}
	}

	/* Add our user in */
	field = nm_locate_field(NM_A_SZ_DN, user->fields);
	if (field) {
		fields = nm_field_add_pointer(fields, NM_A_SZ_DN,
									  0, NMFIELD_METHOD_VALID, 0,
									  g_strdup((char *) field->ptr_value),
									  NMFIELD_TYPE_DN);
	}

	rc = nm_send_request(user->conn, "createconf", fields, callback, data, &req);
	if (rc == NM_OK && req) {
		nm_conference_add_ref(conference);
		nm_request_set_data(req, conference);
	}

	if (req)
		nm_release_request(req);

	nm_free_fields(&fields);
	return rc;
}

NMERR_T
nm_send_leave_conference(NMUser * user, NMConference * conference,
						 nm_response_cb callback, gpointer data)
{
	NMERR_T rc = NM_OK;
	NMField *fields = NULL;
	NMField *tmp = NULL;
	NMRequest *req = NULL;

	if (user == NULL || conference == NULL)
		return NMERR_BAD_PARM;

	/* Add in the conference guid */
	tmp = nm_field_add_pointer(tmp, NM_A_SZ_OBJECT_ID, 0, NMFIELD_METHOD_VALID, 0,
							   g_strdup(nm_conference_get_guid(conference)),
							   NMFIELD_TYPE_UTF8);

	fields = nm_field_add_pointer(fields, NM_A_FA_CONVERSATION, 0,
								  NMFIELD_METHOD_VALID, 0, tmp,
								  NMFIELD_TYPE_ARRAY);
	tmp = NULL;

	/* Send the request to the server */
	rc = nm_send_request(user->conn, "leaveconf", fields, callback, data, &req);
	if (rc == NM_OK && req)
		nm_request_set_data(req, conference);

	if (req)
		nm_release_request(req);

	nm_free_fields(&fields);
	return rc;
}

NMERR_T
nm_send_join_conference(NMUser * user, NMConference * conference,
						nm_response_cb callback, gpointer data)
{
	NMERR_T rc = NM_OK;
	NMField *fields = NULL, *tmp = NULL;
	NMRequest *req = NULL;

	if (user == NULL || conference == NULL)
		return NMERR_BAD_PARM;

	/* Add in the conference guid */
	tmp = nm_field_add_pointer(tmp, NM_A_SZ_OBJECT_ID, 0, NMFIELD_METHOD_VALID, 0,
							   g_strdup(nm_conference_get_guid(conference)),
							   NMFIELD_TYPE_UTF8);

	fields = nm_field_add_pointer(fields, NM_A_FA_CONVERSATION, 0,
								  NMFIELD_METHOD_VALID, 0, tmp,
								  NMFIELD_TYPE_ARRAY);
	tmp = NULL;

	/* Send the request to the server */
	rc = nm_send_request(user->conn, "joinconf", fields, callback, data, &req);
	if (rc == NM_OK && req)
		nm_request_set_data(req, conference);

	if (req)
		nm_release_request(req);

	nm_free_fields(&fields);
	return rc;
}

NMERR_T
nm_send_reject_conference(NMUser * user, NMConference * conference,
						  nm_response_cb callback, gpointer data)
{
	NMERR_T rc = NM_OK;
	NMField *fields = NULL;
	NMField *tmp = NULL;
	NMRequest *req = NULL;

	if (user == NULL || conference == NULL)
		return NMERR_BAD_PARM;

	/* Add in the conference guid */
	tmp = nm_field_add_pointer(tmp, NM_A_SZ_OBJECT_ID, 0, NMFIELD_METHOD_VALID, 0,
							   g_strdup(nm_conference_get_guid(conference)),
							   NMFIELD_TYPE_UTF8);

	fields = nm_field_add_pointer(fields, NM_A_FA_CONVERSATION, 0,
								  NMFIELD_METHOD_VALID, 0, tmp,
								  NMFIELD_TYPE_ARRAY);
	tmp = NULL;

	/* Send the request to the server */
	rc = nm_send_request(user->conn, "rejectconf", fields, callback, data, &req);
	if (rc == NM_OK && req)
		nm_request_set_data(req, conference);

	if (req)
		nm_release_request(req);

	nm_free_fields(&fields);
	return rc;
}

NMERR_T
nm_send_conference_invite(NMUser *user, NMConference *conference, NMUserRecord *user_record,
						  const char *message, nm_response_cb callback, gpointer data)
{
	NMERR_T rc = NM_OK;
	NMField *fields = NULL;
	NMField *tmp = NULL;
	NMRequest *req = NULL;

	if (user == NULL || conference == NULL || user_record == NULL)
		return NMERR_BAD_PARM;

	/* Add in the conference guid */
	tmp = nm_field_add_pointer(tmp, NM_A_SZ_OBJECT_ID, 0, NMFIELD_METHOD_VALID, 0,
							   g_strdup(nm_conference_get_guid(conference)),
							   NMFIELD_TYPE_UTF8);

	fields = nm_field_add_pointer(fields, NM_A_FA_CONVERSATION, 0,
								  NMFIELD_METHOD_VALID, 0, tmp,
								  NMFIELD_TYPE_ARRAY);
	tmp = NULL;

	/* Add in DN of user to invite */
	fields = nm_field_add_pointer(fields, NM_A_SZ_DN, 0, NMFIELD_METHOD_VALID, 0,
								  g_strdup(nm_user_record_get_dn(user_record)),
								  NMFIELD_TYPE_DN);

	/* Add the invite message if there is one */
	if (message)
		fields = nm_field_add_pointer(fields, NM_A_SZ_MESSAGE_BODY, 0, NMFIELD_METHOD_VALID, 0,
									  g_strdup(message), NMFIELD_TYPE_UTF8);

	/* Send the request to the server */
	rc = nm_send_request(user->conn, "sendinvite", fields, callback, data, &req);
	if (rc == NM_OK && req)
		nm_request_set_data(req, conference);

	if (req)
		nm_release_request(req);

	nm_free_fields(&fields);
	return rc;
}

NMERR_T
nm_send_message(NMUser * user, NMMessage * message, nm_response_cb callback)
{
	NMERR_T rc = NM_OK;
	char *text, *rtfized;
	NMField *fields = NULL, *tmp = NULL;
	NMConference *conf;
	NMUserRecord *user_record;
	int count, i;

	if (user == NULL || message == NULL) {
		return NMERR_BAD_PARM;
	}

	conf = nm_message_get_conference(message);
	if (!nm_conference_is_instantiated(conf)) {
		rc = NMERR_CONFERENCE_NOT_INSTANTIATED;
	} else {

		tmp = nm_field_add_pointer(tmp, NM_A_SZ_OBJECT_ID, 0, NMFIELD_METHOD_VALID, 0,
								   g_strdup(nm_conference_get_guid(conf)),
								   NMFIELD_TYPE_UTF8);

		fields =
			nm_field_add_pointer(fields, NM_A_FA_CONVERSATION, 0, NMFIELD_METHOD_VALID, 0,
								 tmp, NMFIELD_TYPE_ARRAY);
		tmp = NULL;

		/* Add RTF and plain text versions of the message */
		text = g_strdup(nm_message_get_text(message));

		/* Truncate if necessary */
		if (strlen(text) > NM_MAX_MESSAGE_SIZE)
			text[NM_MAX_MESSAGE_SIZE] = 0;

		rtfized = nm_rtfize_text(text);

		purple_debug_info("novell", "message text is: %s\n", text);
		purple_debug_info("novell", "message rtf is: %s\n", rtfized);

		tmp = nm_field_add_pointer(tmp, NM_A_SZ_MESSAGE_BODY, 0, NMFIELD_METHOD_VALID, 0,
								   rtfized, NMFIELD_TYPE_UTF8);

		tmp = nm_field_add_number(tmp, NM_A_UD_MESSAGE_TYPE, 0, NMFIELD_METHOD_VALID, 0,
								  0, NMFIELD_TYPE_UDWORD);

		tmp = nm_field_add_pointer(tmp, NM_A_SZ_MESSAGE_TEXT, 0, NMFIELD_METHOD_VALID, 0,
								   text, NMFIELD_TYPE_UTF8);

		fields = nm_field_add_pointer(fields, NM_A_FA_MESSAGE, 0, NMFIELD_METHOD_VALID, 0,
									  tmp, NMFIELD_TYPE_ARRAY);
		tmp = NULL;

		/* Add participants */
		count = nm_conference_get_participant_count(conf);
		for (i = 0; i < count; i++) {
			user_record = nm_conference_get_participant(conf, i);
			if (user_record) {
				fields =
					nm_field_add_pointer(fields, NM_A_SZ_DN, 0, NMFIELD_METHOD_VALID, 0,
										 g_strdup(nm_user_record_get_dn(user_record)),
										 NMFIELD_TYPE_DN);
			}
		}

		/* Send the request */
		rc = nm_send_request(user->conn, "sendmessage", fields, callback, NULL, NULL);
	}

	nm_free_fields(&fields);
	return rc;
}

NMERR_T
nm_send_typing(NMUser * user, NMConference * conf,
			   gboolean typing, nm_response_cb callback)
{
	NMERR_T rc = NM_OK;
	char *str = NULL;
	NMField *fields = NULL, *tmp = NULL;

	if (user == NULL || conf == NULL) {
		return NMERR_BAD_PARM;
	}

	if (!nm_conference_is_instantiated(conf)) {
		rc = NMERR_CONFERENCE_NOT_INSTANTIATED;
	} else {
		/* Add the conference GUID */
		tmp = nm_field_add_pointer(tmp, NM_A_SZ_OBJECT_ID, 0, NMFIELD_METHOD_VALID, 0,
								   g_strdup(nm_conference_get_guid(conf)),
								   NMFIELD_TYPE_UTF8);

		/* Add typing type */
		str = g_strdup_printf("%d",
							  (typing ? NMEVT_USER_TYPING :
							   NMEVT_USER_NOT_TYPING));

		tmp = nm_field_add_pointer(tmp, NM_A_SZ_TYPE, 0, NMFIELD_METHOD_VALID, 0,
								   str, NMFIELD_TYPE_UTF8);

		fields =
			nm_field_add_pointer(fields, NM_A_FA_CONVERSATION, 0, NMFIELD_METHOD_VALID, 0,
								 tmp, NMFIELD_TYPE_ARRAY);
		tmp = NULL;

		rc = nm_send_request(user->conn, "sendtyping", fields, callback, NULL, NULL);
	}

	nm_free_fields(&fields);
	return rc;
}

NMERR_T
nm_send_create_contact(NMUser * user, NMFolder * folder,
					   NMContact * contact, nm_response_cb callback,
					   gpointer data)
{
	NMERR_T rc = NM_OK;
	NMField *fields = NULL;
	NMRequest *req = NULL;
	const char *name = NULL;
	const char *display_name = NULL;

	if (user == NULL || folder == NULL || contact == NULL) {
		return NMERR_BAD_PARM;
	}

	/* Add parent ID */
	fields = nm_field_add_pointer(fields, NM_A_SZ_PARENT_ID, 0, NMFIELD_METHOD_VALID, 0,
								  g_strdup_printf("%d", nm_folder_get_id(folder)),
								  NMFIELD_TYPE_UTF8);

	/* Check to see if userid is current user and return an error? */

	/* Check to see if contact already exists and return an error? */

	/* Add userid or dn */
	name = nm_contact_get_dn(contact);
	if (name == NULL)
		return NMERR_BAD_PARM;

	if (strstr("=", name)) {
		fields = nm_field_add_pointer(fields, NM_A_SZ_DN, 0, NMFIELD_METHOD_VALID, 0,
									  g_strdup(name), NMFIELD_TYPE_DN);
	} else {
		fields = nm_field_add_pointer(fields, NM_A_SZ_USERID, 0, NMFIELD_METHOD_VALID, 0,
									  g_strdup(name), NMFIELD_TYPE_UTF8);
	}

	/* Add display name */
	display_name = nm_contact_get_display_name(contact);
	if (display_name)
		fields = nm_field_add_pointer(fields, NM_A_SZ_DISPLAY_NAME, 0, NMFIELD_METHOD_VALID, 0,
									  g_strdup(display_name), NMFIELD_TYPE_UTF8);

	/* Dispatch the request */
	rc = nm_send_request(user->conn, "createcontact", fields, callback, data, &req);
	if (rc == NM_OK && req)
		nm_request_set_data(req, contact);

	if (req)
		nm_release_request(req);

	nm_free_fields(&fields);
	return rc;
}

NMERR_T
nm_send_remove_contact(NMUser * user, NMFolder * folder,
					   NMContact * contact, nm_response_cb callback,
					   gpointer data)
{
	NMERR_T rc = NM_OK;
	NMField *fields = NULL;
	NMRequest *req = NULL;

	if (user == NULL || folder == NULL || contact == NULL) {
		return NMERR_BAD_PARM;
	}

	/* Add parent id */
	fields = nm_field_add_pointer(fields, NM_A_SZ_PARENT_ID, 0, NMFIELD_METHOD_VALID, 0,
								  g_strdup_printf("%d", nm_folder_get_id(folder)),
								  NMFIELD_TYPE_UTF8);

	/* Add object id */
	fields = nm_field_add_pointer(fields, NM_A_SZ_OBJECT_ID, 0, NMFIELD_METHOD_VALID, 0,
								  g_strdup_printf("%d", nm_contact_get_id(contact)),
								  NMFIELD_TYPE_UTF8);

	/* Dispatch the request */
	rc = nm_send_request(user->conn, "deletecontact", fields, callback, data, &req);
	if (rc == NM_OK && req)
		nm_request_set_data(req, contact);

	if (req)
		nm_release_request(req);

	nm_free_fields(&fields);
	return rc;
}

NMERR_T
nm_send_create_folder(NMUser * user, const char *name,
					  nm_response_cb callback, gpointer data)
{
	NMERR_T rc = NM_OK;
	NMField *fields = NULL;
	NMRequest *req = NULL;

	if (user == NULL || name == NULL) {
		return NMERR_BAD_PARM;
	}

	/* Add parent ID */
	fields = nm_field_add_pointer(fields, NM_A_SZ_PARENT_ID, 0, NMFIELD_METHOD_VALID, 0,
								  g_strdup("0"), NMFIELD_TYPE_UTF8);

	/* Add name of the folder to add */
	fields =
		nm_field_add_pointer(fields, NM_A_SZ_DISPLAY_NAME, 0, NMFIELD_METHOD_VALID, 0,
							 g_strdup(name), NMFIELD_TYPE_UTF8);

	/* Add sequence, for now just put it at the bottom */
	fields =
		nm_field_add_pointer(fields, NM_A_SZ_SEQUENCE_NUMBER, 0, NMFIELD_METHOD_VALID, 0,
							 g_strdup("-1"), NMFIELD_TYPE_UTF8);

	/* Dispatch the request */
	rc = nm_send_request(user->conn, "createfolder", fields, callback, data, &req);
	if (rc == NM_OK && req)
		nm_request_set_data(req, g_strdup(name));

	if (req)
		nm_release_request(req);

	nm_free_fields(&fields);
	return rc;
}

NMERR_T
nm_send_remove_folder(NMUser * user, NMFolder * folder,
					  nm_response_cb callback, gpointer data)
{
	NMERR_T rc = NM_OK;
	NMField *fields = NULL;
	NMRequest *req = NULL;

	if (user == NULL || folder == NULL) {
		return NMERR_BAD_PARM;
	}

	/* Add the object id */
	fields = nm_field_add_pointer(fields, NM_A_SZ_OBJECT_ID, 0, NMFIELD_METHOD_VALID, 0,
								  g_strdup_printf("%d", nm_folder_get_id(folder)),
								  NMFIELD_TYPE_UTF8);

	/* Dispatch the request */
	rc = nm_send_request(user->conn, "deletecontact", fields, callback, data, &req);
	if (rc == NM_OK && req)
		nm_request_set_data(req, folder);

	if (req)
		nm_release_request(req);

	nm_free_fields(&fields);
	return rc;
}

NMERR_T
nm_send_get_status(NMUser * user, NMUserRecord * user_record,
				   nm_response_cb callback, gpointer data)
{
	NMERR_T rc = NM_OK;
	NMField *fields = NULL;
	NMRequest *req = NULL;
	const char *dn;

	if (user == NULL || user_record == NULL)
		return NMERR_BAD_PARM;

	/* Add DN to field list */
	dn = nm_user_record_get_dn(user_record);
	if (dn == NULL)
		return (NMERR_T) -1;

	fields = nm_field_add_pointer(fields, NM_A_SZ_DN, 0, NMFIELD_METHOD_VALID, 0,
								  g_strdup(dn), NMFIELD_TYPE_UTF8);

	/* Dispatch the request */
	rc = nm_send_request(user->conn, "getstatus", fields, callback, data, &req);
	if (rc == NM_OK && req)
		nm_request_set_data(req, user_record);

	if (req)
		nm_release_request(req);

	nm_free_fields(&fields);
	return rc;
}

NMERR_T
nm_send_rename_contact(NMUser * user, NMContact * contact,
					   const char *new_name, nm_response_cb callback,
					   gpointer data)
{
	NMERR_T rc = NM_OK;
	NMField *field = NULL, *fields = NULL, *list = NULL;
	NMRequest *req = NULL;

	if (user == NULL || contact == NULL || new_name == NULL)
		return NMERR_BAD_PARM;

	/* Create field list for current contact */
	field = nm_contact_to_fields(contact);
	if (field) {

		fields =
			nm_field_add_pointer(fields, NM_A_FA_CONTACT, 0, NMFIELD_METHOD_DELETE, 0,
								 field, NMFIELD_TYPE_ARRAY);
		field = NULL;

		/* Update the contacts display name locally */
		nm_contact_set_display_name(contact, new_name);

		/* Create field list for updated contact */
		field = nm_contact_to_fields(contact);
		if (field) {
			fields =
				nm_field_add_pointer(fields, NM_A_FA_CONTACT, 0, NMFIELD_METHOD_ADD, 0,
									 field, NMFIELD_TYPE_ARRAY);
			field = NULL;

			/* Package it up */
			list =
				nm_field_add_pointer(list, NM_A_FA_CONTACT_LIST, 0, NMFIELD_METHOD_VALID,
									 0, fields, NMFIELD_TYPE_ARRAY);
			fields = NULL;

			rc = nm_send_request(user->conn, "updateitem", list, callback, data, &req);
			if (rc == NM_OK && req)
				nm_request_set_data(req, contact);
		}
	}

	if (req)
		nm_release_request(req);

	if (list)
		nm_free_fields(&list);

	return rc;
}

NMERR_T
nm_send_rename_folder(NMUser * user, NMFolder * folder, const char *new_name,
					  nm_response_cb callback, gpointer data)
{
	NMERR_T rc = NM_OK;
	NMField *field = NULL, *fields = NULL, *list = NULL;
	NMRequest *req = NULL;

	if (user == NULL || folder == NULL || new_name == NULL)
		return NMERR_BAD_PARM;

	/* Make sure folder does not already exist!? */
	if (nm_find_folder(user, new_name))
		return NMERR_FOLDER_EXISTS;

	/* Create field list for current folder */
	field = nm_folder_to_fields(folder);
	if (field) {

		fields = nm_field_add_pointer(fields, NM_A_FA_FOLDER, 0, NMFIELD_METHOD_DELETE, 0,
									  field, NMFIELD_TYPE_ARRAY);
		field = NULL;

		/* Update the folders display name locally */
		nm_folder_set_name(folder, new_name);

		/* Create field list for updated folder */
		field = nm_folder_to_fields(folder);
		if (field) {
			fields = nm_field_add_pointer(fields, NM_A_FA_FOLDER, 0, NMFIELD_METHOD_ADD, 0,
										  field, NMFIELD_TYPE_ARRAY);
			field = NULL;

			/* Package it up */
			list = nm_field_add_pointer(list, NM_A_FA_CONTACT_LIST, 0, NMFIELD_METHOD_VALID,
										0, fields, NMFIELD_TYPE_ARRAY);
			fields = NULL;

			rc = nm_send_request(user->conn, "updateitem", list, callback, data, &req);
			if (rc == NM_OK && req)
				nm_request_set_data(req, folder);
		}
	}

	if (req)
		nm_release_request(req);

	if (list)
		nm_free_fields(&list);

	return rc;
}

NMERR_T
nm_send_move_contact(NMUser * user, NMContact * contact, NMFolder * folder,
					 nm_response_cb callback, gpointer data)
{
	NMERR_T rc = NM_OK;
	NMField *field = NULL, *fields = NULL, *list = NULL;
	NMRequest *req = NULL;

	if (user == NULL || contact == NULL || folder == NULL)
		return NMERR_BAD_PARM;

	/* Create field list for the contact */
	field = nm_contact_to_fields(contact);
	if (field) {

		fields = nm_field_add_pointer(fields, NM_A_FA_CONTACT, 0, NMFIELD_METHOD_DELETE, 0,
									  field, NMFIELD_TYPE_ARRAY);
		field = NULL;

		/* Wrap the contact up and add it to the request field list */
		list = nm_field_add_pointer(list, NM_A_FA_CONTACT_LIST, 0, NMFIELD_METHOD_VALID, 0,
									fields, NMFIELD_TYPE_ARRAY);
		fields = NULL;

		/* Add sequence number */
		list = nm_field_add_pointer(list, NM_A_SZ_SEQUENCE_NUMBER, 0, NMFIELD_METHOD_VALID,
									0, g_strdup("-1"), NMFIELD_TYPE_UTF8);

		/* Add parent ID */
		list = nm_field_add_pointer(list, NM_A_SZ_PARENT_ID, 0, NMFIELD_METHOD_VALID, 0,
									g_strdup_printf("%d",  nm_folder_get_id(folder)),
									NMFIELD_TYPE_UTF8);

		/* Dispatch the request */
		rc = nm_send_request(user->conn, "movecontact", list, callback, data, &req);
		if (rc == NM_OK && req)
			nm_request_set_data(req, contact);

	}

	if (req)
		nm_release_request(req);

	if (list)
		nm_free_fields(&list);

	return rc;
}


NMERR_T
nm_send_create_privacy_item(NMUser *user, const char *who, gboolean allow_list,
							nm_response_cb callback, gpointer data)
{
	NMERR_T rc = NM_OK;
	NMField *fields = NULL;
	const char *tag;

	if (user == NULL || who == NULL)
		return NMERR_BAD_PARM;

	if (allow_list)
		tag = NM_A_SZ_BLOCKING_ALLOW_ITEM;
	else
		tag = NM_A_SZ_BLOCKING_DENY_ITEM;

    fields = nm_field_add_pointer(fields, tag, 0, NMFIELD_METHOD_ADD, 0,
								  g_strdup(who), NMFIELD_TYPE_UTF8);

	rc = nm_send_request(user->conn, "createblock", fields, callback, data, NULL);

	nm_free_fields(&fields);
	return rc;
}

NMERR_T
nm_send_remove_privacy_item(NMUser *user, const char *dn, gboolean allow_list,
							nm_response_cb callback, gpointer data)
{
	NMERR_T rc = NM_OK;
	NMField *fields = NULL;
	const char *tag;
	GSList **list_ptr, *node;

	if (user == NULL || dn == NULL)
		return NMERR_BAD_PARM;

	if (allow_list) {
		tag = NM_A_BLOCKING_ALLOW_LIST;
		list_ptr = &user->allow_list;
	} else {
		tag = NM_A_BLOCKING_DENY_LIST;
		list_ptr = &user->deny_list;
	}

	/* Remove item from the cached list */
	if ((node = g_slist_find_custom(*list_ptr, dn, (GCompareFunc)purple_utf8_strcasecmp))) {
		*list_ptr = g_slist_remove_link(*list_ptr, node);
		g_slist_free_1(node);
	}

    fields = nm_field_add_pointer(fields, tag, 0, NMFIELD_METHOD_DELETE, 0,
								  g_strdup(dn), NMFIELD_TYPE_DN);

	rc = nm_send_request(user->conn, "updateblocks", fields, callback, data, NULL);

	nm_free_fields(&fields);
	return rc;

}

NMERR_T
nm_send_set_privacy_default(NMUser *user, gboolean default_deny,
							nm_response_cb callback, gpointer data)
{
	NMERR_T rc = NM_OK;
	NMField *fields = NULL;

	if (user == NULL)
		return NMERR_BAD_PARM;

	fields = nm_field_add_pointer(fields, NM_A_BLOCKING, 0, NMFIELD_METHOD_UPDATE, 0,
								  (default_deny ? g_strdup("1") : g_strdup("0")),
								  NMFIELD_TYPE_UTF8);

	rc = nm_send_request(user->conn, "updateblocks", fields, callback, data, NULL);

	nm_free_fields(&fields);
	return rc;
}

NMERR_T
nm_send_keepalive(NMUser *user, nm_response_cb callback, gpointer data)
{
	NMERR_T rc = NM_OK;

	if (user == NULL)
		return NMERR_BAD_PARM;

	rc = nm_send_request(user->conn, "ping", NULL, callback, data, NULL);

	return rc;
}

NMERR_T
nm_process_new_data(NMUser * user)
{
	NMConn *conn;
	NMERR_T rc = NM_OK;
	guint32 val;

	if (user == NULL)
		return NMERR_BAD_PARM;

	conn = user->conn;

	/* Check to see if this is an event or a response */
	rc = nm_read_all(conn, (char *) &val, sizeof(val));
	if (rc == NM_OK) {
		if (strncmp((char *) &val, "HTTP", strlen("HTTP")) == 0)
			rc = nm_process_response(user);
		else
			rc = nm_process_event(user, GUINT32_FROM_LE(val));

	} else {
		if (errno == EAGAIN)
			rc = NM_OK;
		else
			rc = NMERR_PROTOCOL;
	}

	return rc;
}

NMConference *
nm_find_conversation(NMUser * user, const char *who)
{
	NMConference *conference = NULL;
	NMConference *tmp;
	GSList *cnode;

	if (user && user->conferences) {
		for (cnode = user->conferences; cnode; cnode = cnode->next) {
			tmp = cnode->data;
			if (nm_conference_get_participant_count(tmp) == 1) {
				NMUserRecord *ur = nm_conference_get_participant(tmp, 0);

				if (ur) {
					if (nm_utf8_str_equal(nm_user_record_get_dn(ur), who)) {
						conference = tmp;
						break;
					}
				}
			}
		}
	}

	return conference;
}

void
nm_conference_list_add(NMUser * user, NMConference * conf)
{
	if (user == NULL || conf == NULL)
		return;

	nm_conference_add_ref(conf);
	user->conferences = g_slist_append(user->conferences, conf);
}

void
nm_conference_list_remove(NMUser * user, NMConference * conf)
{
	if (user == NULL || conf == NULL)
		return;

	if (g_slist_find(user->conferences, conf)) {
		user->conferences = g_slist_remove(user->conferences, conf);
		nm_release_conference(conf);
	}
}

void
nm_conference_list_free(NMUser * user)
{
	GSList *cnode;
	NMConference *conference;

	if (user == NULL)
		return;

	if (user->conferences) {
		for (cnode = user->conferences; cnode; cnode = cnode->next) {
			conference = cnode->data;
			cnode->data = NULL;
			nm_release_conference(conference);
		}

		g_slist_free(user->conferences);
		user->conferences = NULL;
	}
}

NMConference *
nm_conference_list_find(NMUser * user, const char *guid)
{
	GSList *cnode;
	NMConference *conference = NULL, *tmp;

	if (user == NULL || guid == NULL)
		return NULL;

	if (user->conferences) {
		for (cnode = user->conferences; cnode; cnode = cnode->next) {
			tmp = cnode->data;
			if (nm_are_guids_equal(nm_conference_get_guid(tmp), guid)) {
				conference = tmp;
				break;
			}
		}
	}

	return conference;
}

gboolean
nm_are_guids_equal(const char *guid1, const char *guid2)
{
	if (guid1 == NULL || guid2 == NULL)
		return FALSE;

	return (strncmp(guid1, guid2, CONF_GUID_END) == 0);
}

void
nm_user_add_contact(NMUser * user, NMContact * contact)
{
	if (user == NULL || contact == NULL)
		return;

	nm_contact_add_ref(contact);

	g_hash_table_insert(user->contacts,
						g_utf8_strdown(nm_contact_get_dn(contact), -1), contact);
}

void
nm_user_add_user_record(NMUser * user, NMUserRecord * user_record)
{
	const char *display_id;
	const char *dn;

	if (!user || !user_record)
		return;

	display_id = nm_user_record_get_display_id(user_record);
	dn = nm_user_record_get_dn(user_record);

	if (!dn || !display_id)
		return;

	nm_user_record_add_ref(user_record);

	g_hash_table_insert(user->user_records,
						g_utf8_strdown(dn, -1),
						user_record);

	g_hash_table_insert(user->display_id_to_dn,
						g_utf8_strdown(display_id, -1),
						g_utf8_strdown(dn, -1));
}

nm_event_cb
nm_user_get_event_callback(NMUser * user)
{
	if (user == NULL)
		return NULL;

	return user->evt_callback;
}

NMConn *
nm_user_get_conn(NMUser * user)
{
	if (user == NULL)
		return NULL;

	return user->conn;
}

NMERR_T
nm_create_contact_list(NMUser * user)
{
	NMERR_T rc = NM_OK;
	NMField *locate = NULL;

	if (user == NULL || user->fields == NULL) {
		return NMERR_BAD_PARM;
	}

	/* Create the root folder */
	user->root_folder = nm_create_folder("");

	/* Find the contact list in the login fields */
	locate = nm_locate_field(NM_A_FA_CONTACT_LIST, user->fields);
	if (locate != NULL) {

		/* Add the folders and then the contacts */
		nm_folder_add_contacts_and_folders(user, user->root_folder,
										   (NMField *) (locate->ptr_value));

	}

	return rc;
}

gboolean nm_user_is_privacy_locked(NMUser *user)
{
	if (user) {
		return user->privacy_locked;
	}

	return FALSE;
}

static gboolean
_create_privacy_list(NMUser * user, NMRequest *request)
{
	NMField *locate = NULL;
	GSList *need_details = NULL;

	/* Are the privacy settings locked */
	locate = nm_locate_field(NM_A_LOCKED_ATTR_LIST, user->fields);
	if (locate && locate->ptr_value) {
		if (locate->type == NMFIELD_TYPE_UTF8 &&
			(purple_utf8_strcasecmp(locate->ptr_value, NM_A_BLOCKING) == 0)) {
			user->privacy_locked = TRUE;
		} else if (locate->type == NMFIELD_TYPE_MV ||
				   locate->type == NMFIELD_TYPE_ARRAY) {
			NMField *tmp = (NMField *)locate->ptr_value;
			while (tmp && tmp->tag) {
				if (purple_utf8_strcasecmp(tmp->ptr_value, NM_A_BLOCKING) == 0) {
					user->privacy_locked = TRUE;
					break;
				}
				tmp++;
			}
		}
	}

	/* Set default deny flag */
	locate = nm_locate_field(NM_A_BLOCKING, user->fields);
	if (locate && locate->ptr_value) {
		user->default_deny = atoi((char *)locate->ptr_value);
	}

	/* Read internal blocking allow list */
	locate = nm_locate_field(NM_A_BLOCKING_ALLOW_LIST, user->fields);
	if (locate && locate->ptr_value) {

		if (locate->type == NMFIELD_TYPE_MV) {
			locate = (NMField *)locate->ptr_value;
			for (; locate->tag != NULL; locate++) {
				if (locate->ptr_value) {

					user->allow_list = g_slist_append(user->allow_list, (char *)locate->ptr_value);

					if (nm_find_user_record(user, (char *)locate->ptr_value) == NULL)
						need_details = g_slist_append(need_details, (char *)locate->ptr_value);

				}
			}
		} else {

			user->allow_list = g_slist_append(user->allow_list, (char *)locate->ptr_value);

			if (nm_find_user_record(user, (char *)locate->ptr_value) == NULL)
				need_details = g_slist_append(need_details, (char *)locate->ptr_value);

		}
	}

	/* Read internal blocking deny list */
	locate = nm_locate_field(NM_A_BLOCKING_DENY_LIST, user->fields);
	if (locate && locate->ptr_value) {

		if (locate->type == NMFIELD_TYPE_MV) {
			locate =  (NMField *)locate->ptr_value;
			for (; locate->tag != NULL; locate++) {
				if (locate->ptr_value) {

					user->deny_list = g_slist_append(user->deny_list, (char *)locate->ptr_value);

					if (nm_find_user_record(user, (char *)locate->ptr_value) == NULL)
						need_details = g_slist_append(need_details, (char *)locate->ptr_value);

				}
			}
		} else {

			user->deny_list = g_slist_append(user->deny_list, (char *)locate->ptr_value);

			if (nm_find_user_record(user, (char *)locate->ptr_value) == NULL)
				need_details = g_slist_append(need_details, (char *)locate->ptr_value);

		}
	}

	if (need_details) {

		nm_request_add_ref(request);
		nm_send_multiple_get_details(user, need_details,
									 _handle_multiple_get_details_login_cb, request);

		return FALSE;
	}

	return TRUE;
}

void
nm_destroy_contact_list(NMUser * user)
{
	if (user == NULL)
		return;

	if (user->root_folder) {
		nm_release_folder(user->root_folder);
		user->root_folder = NULL;
	}
}

NMFolder *
nm_get_root_folder(NMUser * user)
{
	if (user == NULL)
		return NULL;

	if (user->root_folder == NULL)
		nm_create_contact_list(user);

	return user->root_folder;
}

NMContact *
nm_find_contact(NMUser * user, const char *name)
{
	char *str;
	const char *dn = NULL;
	NMContact *contact = NULL;

	if (user == NULL || name == NULL)
		return NULL;

	str = g_utf8_strdown(name, -1);
	if (strstr(str, "=")) {
		dn = str;
	} else {
		/* Assume that we have a display id instead of a dn */
		dn = (const char *) g_hash_table_lookup(user->display_id_to_dn, str);
	}

	/* Find contact object in reference table */
	if (dn) {
		contact = (NMContact *) g_hash_table_lookup(user->contacts, dn);
	}

	g_free(str);
	return contact;
}

GList *
nm_find_contacts(NMUser * user, const char *dn)
{
	guint32 i, cnt;
	NMFolder *folder;
	NMContact *contact;
	GList *contacts = NULL;

	if (user == NULL || dn == NULL)
		return NULL;

	/* Check for contact at the root */
	contact = nm_folder_find_contact(user->root_folder, dn);
	if (contact) {
		contacts = g_list_append(contacts, contact);
		contact = NULL;
	}

	/* Check for contact in each subfolder */
	cnt = nm_folder_get_subfolder_count(user->root_folder);
	for (i = 0; i < cnt; i++) {
		folder = nm_folder_get_subfolder(user->root_folder, i);
		contact = nm_folder_find_contact(folder, dn);
		if (contact) {
			contacts = g_list_append(contacts, contact);
			contact = NULL;
		}
	}

	return contacts;
}

NMUserRecord *
nm_find_user_record(NMUser * user, const char *name)
{
	char *str = NULL;
	const char *dn = NULL;
	NMUserRecord *user_record = NULL;

	if (user == NULL || name == NULL)
		return NULL;

	str = g_utf8_strdown(name, -1);
	if (strstr(str, "=")) {
		dn = str;
	} else {
		/* Assume that we have a display id instead of a dn */
		dn = (const char *) g_hash_table_lookup(user->display_id_to_dn, str);
	}

	/* Find user record in reference table */
	if (dn) {
		user_record =
			(NMUserRecord *) g_hash_table_lookup(user->user_records, dn);
	}

	g_free(str);
	return user_record;
}

const char *
nm_lookup_dn(NMUser * user, const char *display_id)
{
	const char *dn;
	char *lower;

	if (user == NULL || display_id == NULL)
		return NULL;

	lower = g_utf8_strdown(display_id, -1);
	dn = g_hash_table_lookup(user->display_id_to_dn, lower);
	g_free(lower);

	return dn;
}

NMFolder *
nm_find_folder(NMUser * user, const char *name)
{
	NMFolder *folder = NULL, *temp;
	int i, num_folders;
	const char *tname = NULL;

	if (user == NULL || name == NULL)
		return NULL;

	if (*name == '\0')
		return user->root_folder;

	num_folders = nm_folder_get_subfolder_count(user->root_folder);
	for (i = 0; i < num_folders; i++) {
		temp = nm_folder_get_subfolder(user->root_folder, i);
		tname = nm_folder_get_name(temp);
		if (tname && (strcmp(tname, name) == 0)) {
			folder = temp;
			break;
		}
	}

	return folder;
}

NMFolder *
nm_find_folder_by_id(NMUser * user, int object_id)
{
	NMFolder *folder = NULL, *temp;
	int i, num_folders;

	if (user == NULL)
		return NULL;

	if (object_id == 0)
		return user->root_folder;

	num_folders = nm_folder_get_subfolder_count(user->root_folder);
	for (i = 0; i < num_folders; i++) {
		temp = nm_folder_get_subfolder(user->root_folder, i);
		if (nm_folder_get_id(temp) == object_id) {
			folder = temp;
			break;
		}
	}

	return folder;
}

static void
_handle_multiple_get_details_login_cb(NMUser * user, NMERR_T ret_code,
									  gpointer resp_data, gpointer user_data)
{
	nm_response_cb cb;
	NMRequest *request = user_data;

	if (user == NULL || request == NULL)
		return;

	if ((cb = nm_request_get_callback(request))) {
		cb(user, ret_code, nm_request_get_data(request),
		   nm_request_get_user_define(request));
		nm_release_request(request);
	}
}

static void
_handle_multiple_get_details_joinconf_cb(NMUser * user, NMERR_T ret_code,
										 gpointer resp_data, gpointer user_data)
{
	NMRequest *request = user_data;
	NMUserRecord *user_record = resp_data;
	NMConference *conference;
	GSList *list, *node;

	if (user == NULL || resp_data == NULL || user_data == NULL)
		return;

	conference = nm_request_get_data(request);
	list = nm_request_get_user_define(request);

	if (ret_code == 0 && conference && list) {

		/* Add the user to the conference */
		nm_conference_add_participant(conference, user_record);

		/* Find the user in the list and remove it */
		for (node = list; node; node = node->next) {
			if (nm_utf8_str_equal(nm_user_record_get_dn(user_record),
								  (const char *) node->data)) {
				g_free(node->data);
				list = g_slist_remove(list, node->data);
				nm_request_set_user_define(request, list);
				break;
			}
		}

		/* Time to callback? */
		if (list == NULL) {
			nm_response_cb cb = nm_request_get_callback(request);

			if (cb) {
				cb(user, 0, conference, conference);
			}
			nm_release_request(request);
		}
	}
}

static NMERR_T
nm_call_handler(NMUser * user, NMRequest * request, NMField * fields)
{
	NMERR_T rc = NM_OK, ret_code = NM_OK;
	NMConference *conf = NULL;
	NMUserRecord *user_record = NULL;
	NMField *locate = NULL;
	NMField *field = NULL;
	const char *cmd;
	nm_response_cb cb;
	gboolean done = TRUE;

	if (user == NULL || request == NULL || fields == NULL)
		return NMERR_BAD_PARM;

	/* Get the return code */
	field = nm_locate_field(NM_A_SZ_RESULT_CODE, fields);
	if (field) {
		ret_code = atoi((char *) field->ptr_value);
	} else {
		ret_code = NMERR_PROTOCOL;
	}

	cmd = nm_request_get_cmd(request);
	if (ret_code == NM_OK && cmd != NULL) {

		if (strcmp("login", cmd) == 0) {

			user->user_record = nm_create_user_record_from_fields(fields);

			/* Save the users fields */
			user->fields = nm_copy_field_array(fields);

			nm_create_contact_list(user);
			done = _create_privacy_list(user, request);

		} else if (strcmp("setstatus", cmd) == 0) {

			/* Nothing to do */

		} else if (strcmp("createconf", cmd) == 0) {

			conf = (NMConference *) nm_request_get_data(request);

			/* get the convo guid */
			locate = nm_locate_field(NM_A_FA_CONVERSATION, fields);
			if (locate) {
				field =
					nm_locate_field(NM_A_SZ_OBJECT_ID, (NMField *) fields->ptr_value);
				if (field) {
					nm_conference_set_guid(conf, (char *) field->ptr_value);
				}
			}

			nm_conference_list_add(user, conf);
			nm_release_conference(conf);

		} else if (strcmp("leaveconf", cmd) == 0) {

			conf = (NMConference *) nm_request_get_data(request);
			nm_conference_list_remove(user, conf);

		} else if (strcmp("joinconf", cmd) == 0) {
			GSList *list = NULL, *node;

			conf = nm_request_get_data(request);

			locate = nm_locate_field(NM_A_FA_CONTACT_LIST, fields);
			if (locate && locate->ptr_value != 0) {

				field = (NMField *) locate->ptr_value;
				while ((field = nm_locate_field(NM_A_SZ_DN, field))) {
					if (field && field->ptr_value != 0) {

						if (nm_utf8_str_equal
							(nm_user_record_get_dn(user->user_record),
							 (const char *) field->ptr_value)) {
							field++;
							continue;
						}

						user_record =
							nm_find_user_record(user,
												(const char *) field->ptr_value);
						if (user_record == NULL) {
							list =
								g_slist_append(list,
											   g_strdup((char *) field->ptr_value));
						} else {
							nm_conference_add_participant(conf, user_record);
						}
					}
					field++;
				}

				if (list != NULL) {

					done = FALSE;
					nm_request_set_user_define(request, list);
					nm_request_add_ref(request);
					for (node = list; node; node = node->next) {

						nm_send_get_details(user, (const char *) node->data,
											_handle_multiple_get_details_joinconf_cb,
											request);
					}
				}
			}

		} else if (strcmp("getdetails", cmd) == 0) {

			locate = nm_locate_field(NM_A_FA_RESULTS, fields);
			while (locate && locate->ptr_value != 0) {

				user_record = nm_create_user_record_from_fields(locate);
				if (user_record) {
					NMUserRecord *tmp;

					tmp =
						nm_find_user_record(user,
											nm_user_record_get_dn(user_record));
					if (tmp) {

						/* Update the existing user record */
						nm_user_record_copy(tmp, user_record);
						nm_release_user_record(user_record);
						user_record = tmp;

					} else {
						nm_user_add_user_record(user, user_record);
						nm_release_user_record(user_record);
					}

					/* Response data is new user record */
					nm_request_set_data(request, (gpointer) user_record);
				}

				locate = nm_locate_field(NM_A_FA_RESULTS, locate+1);
			}

		} else if (strcmp("createfolder", cmd) == 0) {

			_update_contact_list(user, fields);

		} else if (strcmp("createcontact", cmd) == 0) {

			_update_contact_list(user, fields);

			locate =
				nm_locate_field(NM_A_SZ_OBJECT_ID, (NMField *) fields->ptr_value);
			if (locate) {

				NMContact *new_contact =
					nm_folder_find_item_by_object_id(user->root_folder,
													 atoi((char *)locate->ptr_value));

				if (new_contact) {

					/* Add the contact to our cache */
					nm_user_add_contact(user, new_contact);

					/* Set the contact as the response data */
					nm_request_set_data(request, (gpointer) new_contact);

				}

			}

		} else if (strcmp("deletecontact", cmd) == 0) {

			_update_contact_list(user, fields);

		} else if (strcmp("movecontact", cmd) == 0) {

			_update_contact_list(user, fields);

		} else if (strcmp("getstatus", cmd) == 0) {

			locate = nm_locate_field(NM_A_SZ_STATUS, fields);
			if (locate) {
				nm_user_record_set_status((NMUserRecord *)
										  nm_request_get_data(request),
										  atoi((char *) locate->ptr_value), NULL);
			}

		} else if (strcmp("updateitem", cmd) == 0) {

			/* Nothing extra to do here */

		} else if (strcmp("createblock", cmd) == 0) {
			if ((locate = nm_locate_field(NM_A_BLOCKING_DENY_LIST, fields))) {
				if (locate->ptr_value) {
					user->deny_list = g_slist_append(user->deny_list, g_strdup((char *)locate->ptr_value));
				}
			} else if ((locate = nm_locate_field(NM_A_BLOCKING_ALLOW_LIST, fields))) {
				if (locate->ptr_value) {
					user->allow_list = g_slist_append(user->allow_list, g_strdup((char *)locate->ptr_value));
				}
			}
		} else if (strcmp("updateblocks", cmd) == 0) {
			/* nothing to do here */
		} else {

			/* Nothing to do, just print debug message  */
			purple_debug(PURPLE_DEBUG_INFO, "novell",
					   "nm_call_handler(): Unknown request command, %s\n", cmd);

		}
	}

	if (done && (cb = nm_request_get_callback(request))) {

		cb(user, ret_code, nm_request_get_data(request),
		   nm_request_get_user_define(request));
	}

	return rc;
}

static NMERR_T
nm_process_response(NMUser * user)
{
	NMERR_T rc = NM_OK;
	NMField *fields = NULL;
	NMField *field = NULL;
	NMConn *conn = user->conn;
	NMRequest *req = NULL;

	rc = nm_read_header(conn);
	if (rc == NM_OK) {
		rc = nm_read_fields(conn, -1, &fields);
	}

	if (rc == NM_OK) {
		field = nm_locate_field(NM_A_SZ_TRANSACTION_ID, fields);
		if (field != NULL && field->ptr_value != 0) {
			req = nm_conn_find_request(conn, atoi((char *) field->ptr_value));
			if (req != NULL) {
				rc = nm_call_handler(user, req, fields);
				nm_conn_remove_request_item(conn, req);
			}

		}
	}

	if (fields)
		nm_free_fields(&fields);

	return rc;
}

/*
 * Some utility functions...haven't figured out where
 * they belong yet.
 */

gboolean
nm_utf8_str_equal(gconstpointer str1, gconstpointer str2)
{
	return (purple_utf8_strcasecmp(str1, str2) == 0);
}

char *
nm_typed_to_dotted(const char *typed)
{
	unsigned i = 0, j = 0;
	char *dotted;

	if (typed == NULL)
		return NULL;

	dotted = g_new0(char, strlen(typed));

	do {

		/* replace comma with a dot */
		if (j != 0) {
			dotted[j] = '.';
			j++;
		}

		/* skip the type */
		while (typed[i] != '\0' && typed[i] != '=')
			i++;

		/* verify that we aren't running off the end */
		if (typed[i] == '\0') {
			dotted[j] = '\0';
			break;
		}

		i++;

		/* copy the object name to context */
		while (typed[i] != '\0' && typed[i] != ',') {
			dotted[j] = typed[i];
			j++;
			i++;
		}

	} while (typed[i] != '\0');

	return dotted;
}

const char *
nm_error_to_string(NMERR_T err)
{
	static char *unknown_msg = NULL;

	g_free(unknown_msg);
	unknown_msg = NULL;

	switch (err) {

		case NMERR_BAD_PARM:
			return _("Required parameters not passed in");

		case NMERR_TCP_WRITE:
			return _("Unable to write to network");

		case NMERR_TCP_READ:
			return _("Unable to read from network");

		case NMERR_PROTOCOL:
			return _("Error communicating with server");

		case NMERR_CONFERENCE_NOT_FOUND:
		case NMERR_CONFERENCE_NOT_FOUND_2:
			return _("Conference not found");

		case NMERR_CONFERENCE_NOT_INSTANTIATED:
			return _("Conference does not exist");

		case NMERR_DUPLICATE_FOLDER:
		case NMERR_FOLDER_EXISTS:
			return _("A folder with that name already exists");

		case NMERR_NOT_SUPPORTED:
			return _("Not supported");

		case NMERR_PASSWORD_EXPIRED:
		case NMERR_PASSWORD_EXPIRED_2:
			return _("Password has expired");

		case NMERR_PASSWORD_INVALID:
			return _("Incorrect password");

		case NMERR_USER_NOT_FOUND:
			return _("User not found");

		case NMERR_USER_DISABLED:
			return _("Account has been disabled");

		case NMERR_DIRECTORY_FAILURE:
			return _("The server could not access the directory");

		case NMERR_ADMIN_LOCKED:
			return _("Your system administrator has disabled this operation");

		case NMERR_SERVER_BUSY:
			return _("The server is unavailable; try again later");

		case NMERR_DUPLICATE_CONTACT:
			return _("Cannot add a contact to the same folder twice");

		case NMERR_USER_NOT_ALLOWED:
			return _("Cannot add yourself");

		case NMERR_MASTER_ARCHIVE_MISSING:
			return _("Master archive is misconfigured");

		case NMERR_AUTHENTICATION_FAILED:
		case NMERR_CREDENTIALS_MISSING:
			return _("Incorrect username or password");

		case NMERR_HOST_NOT_FOUND:
			return _("Could not recognize the host of the username you entered");

		case NMERR_ACCESS_DENIED:
			return _("Your account has been disabled because too many incorrect passwords were entered");

		case NMERR_DUPLICATE_PARTICIPANT:
			return _("You cannot add the same person twice to a conversation");

		case NMERR_TOO_MANY_CONTACTS:
		case NMERR_TOO_MANY_FOLDERS:
			return _("You have reached your limit for the number of contacts allowed");

		case NMERR_OBJECT_NOT_FOUND:
			return _("You have entered an incorrect username");

		case NMERR_DIRECTORY_UPDATE:
			return _("An error occurred while updating the directory");

		case NMERR_SERVER_PROTOCOL:
			return _("Incompatible protocol version");

		case NMERR_USER_BLOCKED:
			return _("The user has blocked you");

		case NMERR_EVAL_CONNECTION_LIMIT:
			return _("This evaluation version does not allow more than ten users to log in at one time");

		case NMERR_CONVERSATION_INVITE:
			return _("The user is either offline or you are blocked");

		default:
			unknown_msg = g_strdup_printf (_("Unknown error: 0x%X"), err);

			return unknown_msg;
	}
}

static void
_update_contact_list(NMUser * user, NMField * fields)
{
	NMField *list, *cursor, *locate;
	gint objid1;
	NMContact *contact;
	NMFolder *folder;
	gpointer item;

	if (user == NULL || fields == NULL)
		return;

	/* Is it wrapped in a RESULTS array? */
	if (strcmp(fields->tag, NM_A_FA_RESULTS) == 0) {
		list = (NMField *) fields->ptr_value;
	} else {
		list = fields;
	}

	/* Update the cached contact list */
	cursor = (NMField *) list->ptr_value;
	while (cursor->tag != NULL) {
		if ((g_ascii_strcasecmp(cursor->tag, NM_A_FA_CONTACT) == 0) ||
			(g_ascii_strcasecmp(cursor->tag, NM_A_FA_FOLDER) == 0)) {

			locate =
				nm_locate_field(NM_A_SZ_OBJECT_ID, (NMField *) cursor->ptr_value);
			if (locate != NULL && locate->ptr_value != 0) {
				objid1 = atoi((char *) locate->ptr_value);
				item =
					nm_folder_find_item_by_object_id(user->root_folder, objid1);
				if (item != NULL) {
					if (cursor->method == NMFIELD_METHOD_ADD) {
						if (g_ascii_strcasecmp(cursor->tag, NM_A_FA_CONTACT) == 0) {
							contact = (NMContact *) item;
							nm_contact_update_list_properties(contact, cursor);
						} else if (g_ascii_strcasecmp(cursor->tag, NM_A_FA_FOLDER)
								   == 0) {
							folder = (NMFolder *) item;
							nm_folder_update_list_properties(folder, cursor);
						}
					} else if (cursor->method == NMFIELD_METHOD_DELETE) {
						if (g_ascii_strcasecmp(cursor->tag, NM_A_FA_CONTACT) == 0) {
							contact = (NMContact *) item;
							folder =
								nm_find_folder_by_id(user,
													 nm_contact_get_parent_id
													 (contact));
							if (folder) {
								nm_folder_remove_contact(folder, contact);
							}
						} else if (g_ascii_strcasecmp(cursor->tag, NM_A_FA_FOLDER)
								   == 0) {
							/* TODO: write nm_folder_remove_folder */
							/* ignoring for now, should not be a big deal */
/*								folder = (NMFolder *) item;*/
/*								nm_folder_remove_folder(user->root_folder, folder);*/
						}
					}
				} else {

					if (cursor->method == NMFIELD_METHOD_ADD) {

						/* Not found,  so we need to add it */
						if (g_ascii_strcasecmp(cursor->tag, NM_A_FA_CONTACT) == 0) {

							const char *dn = NULL;

							locate =
								nm_locate_field(NM_A_SZ_DN,
												(NMField *) cursor->ptr_value);
							if (locate != NULL && locate->ptr_value != 0) {
								dn = (const char *) locate->ptr_value;
								if (dn != NULL) {
									contact =
										nm_create_contact_from_fields(cursor);
									if (contact) {
										nm_folder_add_contact_to_list(user->
																	  root_folder,
																	  contact);
										nm_release_contact(contact);
									}
								}
							}
						} else if (g_ascii_strcasecmp(cursor->tag, NM_A_FA_FOLDER)
								   == 0) {
							folder = nm_create_folder_from_fields(cursor);
							nm_folder_add_folder_to_list(user->root_folder,
														 folder);
							nm_release_folder(folder);
						}
					}
				}
			}
		}
		cursor++;
	}
}

static char *
nm_rtfize_text(char *text)
{
	GString *gstr = NULL;
	unsigned char *pch;
	char *uni_str = NULL, *rtf = NULL;
	int bytes;
	gunichar uc;

	gstr = g_string_sized_new(strlen(text)*2);
	pch = (unsigned char *)text;
	while (*pch) {
		if ((*pch) <= 0x7F) {
			switch (*pch) {
				case '{':
				case '}':
				case '\\':
					gstr = g_string_append_c(gstr, '\\');
					gstr = g_string_append_c(gstr, *pch);
					break;
				case '\n':
					gstr = g_string_append(gstr, "\\par ");
					break;
				default:
					gstr = g_string_append_c(gstr, *pch);
					break;
			}
			pch++;
		} else {
			/* convert the utf-8 character to ucs-4 for rtf encoding */
			if(*pch <= 0xDF) {
				uc = ((((gunichar)pch[0]) & 0x001F) << 6) |
					(((gunichar)pch[1]) & 0x003F);
				bytes = 2;
			} else if(*pch <= 0xEF) {
				uc = ((((gunichar)pch[0]) & 0x000F) << 12) |
					((((gunichar)pch[1]) & 0x003F) << 6) |
					(((gunichar)pch[2]) & 0x003F);
				bytes = 3;
			} else if (*pch <= 0xF7) {
				uc = ((((gunichar)pch[0]) & 0x0007) << 18) |
					((((gunichar)pch[1]) & 0x003F) << 12) |
					((((gunichar)pch[2]) & 0x003F) << 6) |
					(((gunichar)pch[3]) & 0x003F);
				bytes = 4;
			} else if (*pch <= 0xFB) {
				uc = ((((gunichar)pch[0]) & 0x0003) << 24) |
					((((gunichar)pch[1]) & 0x003F) << 18) |
					((((gunichar)pch[2]) & 0x003F) << 12) |
					((((gunichar)pch[3]) & 0x003F) << 6) |
					(((gunichar)pch[4]) & 0x003F);
				bytes = 5;
			} else if (*pch <= 0xFD) {
				uc = ((((gunichar)pch[0]) & 0x0001) << 30) |
					((((gunichar)pch[1]) & 0x003F) << 24) |
					((((gunichar)pch[2]) & 0x003F) << 18) |
					((((gunichar)pch[3]) & 0x003F) << 12) |
					((((gunichar)pch[4]) & 0x003F) << 6) |
					(((gunichar)pch[5]) & 0x003F);
				bytes = 6;
			} else {
				/* should never happen ... bogus utf-8! */
				purple_debug_info("novell", "bogus utf-8 lead byte: 0x%X\n", pch[0]);
				uc = 0x003F;
				bytes = 1;
			}
			uni_str = g_strdup_printf("\\u%d?", uc);
			purple_debug_info("novell", "unicode escaped char %s\n", uni_str);
			gstr = g_string_append(gstr, uni_str);
			pch += bytes;
			g_free(uni_str);
		}
	}

	rtf = g_strdup_printf(RTF_TEMPLATE, gstr->str);
	g_string_free(gstr, TRUE);
	return rtf;
}
