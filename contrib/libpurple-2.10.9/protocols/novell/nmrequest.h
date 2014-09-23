/*
 * nmrequest.h
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

#ifndef __NM_REQUEST_H__
#define __NM_REQUEST_H__

typedef struct _NMRequest NMRequest;

#include "nmuser.h"

/**
 *	Create a new request object. Object must be release with nm_release_object.
 *
 *	@param	cmd				The request command string (e.g. "login")
 *	@param	trans_id		The request transaction id
 *	@param	gmt				The time in seconds that the request was created
 *
 *	@return The new request object
 */
NMRequest *nm_create_request(const char *cmd, int trans_id, int gmt, nm_response_cb cb,
							 gpointer resp_data, gpointer user_define);

/**
 *	Release a request object.
 *
 *	@param	req		The request to release
 */
void nm_release_request(NMRequest * req);

/**
 *  Add a new reference to this object. This reference must be released by
 *  a call to nm_release_object.
 *
 *	@param	req				The request object
 */
void nm_request_add_ref(NMRequest * req);

/**
 *	Set the response callback for this request object. This is the callback
 *  that will be made when we get a response from the server.
 *
 *	@param	req			The request object
 *	@param	callback	The response callback
 *
 */
void nm_request_set_callback(NMRequest * req, nm_response_cb callback);

/**
 *	Set the response data. This will be set differently depending on
 *  the request type (for example to nm_send_get_details will set this
 *  to be the newly create NMUserRecord object).
 *
 *	@param	req			The request object
 *	@param	data		Pointer to some data
 *
 */
void nm_request_set_data(NMRequest * req, gpointer data);

/**
 *	Set the user defined data. This is the data that the client
 *  passes to the various nm_send_* functions. We will pass it
 *  back when we make the callback.
 *
 *	@param	req				The request object
 *	@param	user_define		Pointer to some data
 *
 */
void nm_request_set_user_define(NMRequest * req, gpointer user_define);

/**
 *	Set the return code. This is the return code that we received in
 *  the server response fields.
 *
 *	@param	req			The request object
 *	@param	rc			The return code to set
 */
void nm_request_set_ret_code(NMRequest * req, NMERR_T rc);

/**
 *	Get the transaction id for this request.
 *
 *	@param	req			The request object
 *
 * 	@return	The transaction id.
 */
int nm_request_get_trans_id(NMRequest * req);

/**
 *	Get the command (request type) for this request.
 *
 *	@param	req			The request object
 *
 * 	@return	The request cmd
 */
const char *nm_request_get_cmd(NMRequest * req);

/**
 *	Get the response data for this request
 *
 *	@param	req			The request object
 *
 * 	@return	The response data
 */
gpointer nm_request_get_data(NMRequest * req);

/**
 *	Get the user defined data for this request
 *
 *	@param	req			The request object
 *
 * 	@return	The user defined data
 */
gpointer nm_request_get_user_define(NMRequest * req);

/**
 *	Get the response callback for this request
 *
 *	@param	req			The request object
 *
 * 	@return	The response callback
 */
nm_response_cb nm_request_get_callback(NMRequest * req);

/**
 *	Get the return code
 *
 *	@param	req			The request object
 *
 * 	@return	The return code (from the response fields)
 */
NMERR_T nm_request_get_ret_code(NMRequest * req);

#endif
