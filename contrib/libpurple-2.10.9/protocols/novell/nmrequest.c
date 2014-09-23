/*
 * nmrequest.c
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

#include "nmrequest.h"

static int count = 0;

struct _NMRequest
{
	int trans_id;
	char *cmd;
	int gmt;
	gpointer data;
	gpointer user_define;
	nm_response_cb callback;
	int ref_count;
	NMERR_T ret_code;
};

NMRequest *nm_create_request(const char *cmd, int trans_id, int gmt, nm_response_cb cb,
							 gpointer resp_data, gpointer user_define)
{
	NMRequest *req;

	if (cmd == NULL)
		return NULL;

	req  = g_new0(NMRequest, 1);
	req->cmd = g_strdup(cmd);
	req->trans_id = trans_id;
	req->gmt = gmt;
	req->callback = cb;
	req->data = resp_data;
	req->user_define = user_define;
	req->ref_count = 1;

	purple_debug_info("novell", "Creating NMRequest instance, total=%d\n", ++count);

	return req;
}

void
nm_release_request(NMRequest * req)
{
	if (req && (--req->ref_count == 0)) {
		if (req->cmd)
			g_free(req->cmd);
		g_free(req);

		purple_debug_info("novell",
						"Releasing NMRequest instance, total=%d\n", --count);
	}

}

void
nm_request_add_ref(NMRequest * req)
{
	if (req)
		req->ref_count++;
}

void
nm_request_set_callback(NMRequest * req, nm_response_cb callback)
{
	if (req)
		req->callback = callback;
}

void
nm_request_set_data(NMRequest * req, gpointer data)
{
	if (req)
		req->data = data;
}

void
nm_request_set_user_define(NMRequest * req, gpointer user_define)
{
	if (req)
		req->user_define = user_define;
}

int
nm_request_get_trans_id(NMRequest * req)
{
	if (req)
		return req->trans_id;
	else
		return -1;
}

const char *
nm_request_get_cmd(NMRequest * req)
{
	if (req == NULL)
		return NULL;

	return req->cmd;
}

gpointer
nm_request_get_data(NMRequest * req)
{
	if (req == NULL)
		return NULL;

	return req->data;
}

gpointer
nm_request_get_user_define(NMRequest * req)
{
	if (req == NULL)
		return NULL;

	return req->user_define;
}

nm_response_cb
nm_request_get_callback(NMRequest * req)
{
	if (req == NULL)
		return NULL;

	return req->callback;
}


void
nm_request_set_ret_code(NMRequest * req, NMERR_T rc)
{
	if (req)
		req->ret_code = rc;
}

NMERR_T
nm_request_get_ret_code(NMRequest * req)
{
	if (req)
		return req->ret_code;
	else
		return (NMERR_T) - 1;
}
