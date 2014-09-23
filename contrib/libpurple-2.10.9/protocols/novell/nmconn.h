/*
 * nmconn.h
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

#ifndef __NM_CONN_H__
#define __NM_CONN_H__

typedef struct _NMConn NMConn;
typedef struct _NMSSLConn NMSSLConn;

#include "nmfield.h"
#include "nmuser.h"

typedef int (*nm_ssl_read_cb) (gpointer ssl_data, void *buff, int len);
typedef int (*nm_ssl_write_cb) (gpointer ssl_data, const void *buff, int len);

struct _NMConn
{

	/* The address of the server that we are connecting to. */
	char *addr;

	/* The port that we are connecting to. */
	int port;

	/* The file descriptor of the socket for the connection. */
	int fd;

	/* The transaction counter. */
	int trans_id;

	/* A list of requests currently awaiting a response. */
	GSList *requests;

	/* Are we connected? TRUE if so, FALSE if not. */
	gboolean connected;

	/* Are we running in secure mode? */
	gboolean use_ssl;

	/* Have we been redirected? */
	gboolean redirect;

	/* SSL connection  */
	NMSSLConn *ssl_conn;

};

struct _NMSSLConn
{

	/*  Data to pass to the callbacks */
	gpointer data;

	/* Callbacks for reading/writing */
	nm_ssl_read_cb read;
	nm_ssl_write_cb write;

};

/**
 * Allocate a new NMConn struct
 *
 * @param 	The address of the server that we are connecting to.
 * @param 	The port that we are connecting to.
 *
 * @return		A pointer to a newly allocated NMConn struct, should
 *				be freed by calling nm_release_conn()
 */
NMConn *nm_create_conn(const char *addr, int port);

/**
 * Release an NMConn
 *
 * @param 	Pointer to the NMConn to release.
 *
 */
void nm_release_conn(NMConn *conn);

/**
 * Write len bytes from the given buffer.
 *
 * @param conn	The connection to write to.
 * @param buff	The buffer to write from.
 * @param len	The number of bytes to write.
 *
 * @return		The number of bytes written.
 */
int nm_tcp_write(NMConn * conn, const void *buff, int len);

/**
 * Read at most len bytes into the given buffer.
 *
 * @param conn	The connection to read from.
 * @param buff	The buffer to write to.
 * @param len	The maximum number of bytes to read.
 *
 * @return		The number of bytes read.
 */
int nm_tcp_read(NMConn * conn, void *buff, int len);

/**
 * Read exactly len bytes into the given buffer.
 *
 * @param conn	The connection to read from.
 * @param buff	The buffer to write to.
 * @param len	The number of bytes to read.
 *
 * @return		NM_OK on success, NMERR_TCP_READ if read fails.
 */
NMERR_T nm_read_all(NMConn * conn, char *buf, int len);

/**
 * Read a 32 bit value and convert it to the host byte order.
 *
 * @param conn	The connection to read from.
 * @param val	A pointer to unsigned 32 bit integer
 *
 * @return		NM_OK on success, NMERR_TCP_READ if read fails.
 */
NMERR_T
nm_read_uint32(NMConn *conn, guint32 *val);

/**
 * Read a 16 bit value and convert it to the host byte order.
 *
 * @param conn	The connection to read from.
 * @param val	A pointer to unsigned 16 bit integer
 *
 * @return		NM_OK on success, NMERR_TCP_READ if read fails.
 */
NMERR_T
nm_read_uint16(NMConn *conn, guint16 *val);

/**
 * Dispatch a request to the server.
 *
 * @param conn		The connection.
 * @param cmd		The request to dispatch.
 * @param fields	The field list for the request.
 * @param cb		The response callback for the new request object.
 * @param data		The user defined data for the request (to be passed to the resp cb).
 * @param req		The request. Should be freed with nm_release_request.
 *
 * @return			NM_OK on success.
 */
NMERR_T
nm_send_request(NMConn *conn, char *cmd, NMField *fields,
				nm_response_cb cb, gpointer data, NMRequest **request);

/**
 * Write out the given field list.
 *
 * @param conn		The connection to write to.
 * @param fields	The field list to write.
 *
 * @return			NM_OK on success.
 */
NMERR_T nm_write_fields(NMConn * conn, NMField * fields);

/**
 * Read the headers for a response.
 *
 * @param conn		The connection to read from.
 *
 * @return			NM_OK on success.
 */
NMERR_T nm_read_header(NMConn * conn);

/**
 * Read a field list from the connection.
 *
 * @param conn		The connection to read from.
 * @param count		The maximum number of fields to read (or -1 for no max).
 * @param fields	The field list. This is an out param. It
 *					should be freed by calling nm_free_fields
 *					when finished.
 *
 * @return			NM_OK on success.
 */
NMERR_T nm_read_fields(NMConn * conn, int count, NMField ** fields);

/**
 * Add a request to the connections request list.
 *
 * @param conn		The connection.
 * @param request	The request to add to the list.
 */
void nm_conn_add_request_item(NMConn * conn, NMRequest * request);

/**
 * Remove a request from the connections list.
 *
 * @param conn		The connection.
 * @param request	The request to remove from the list.
 */
void nm_conn_remove_request_item(NMConn * conn, NMRequest * request);

/**
 * Find the request with the given transaction id in the connections
 * request list.
 *
 * @param conn		The connection.
 * @param trans_id	The transaction id of the request to return.
 *
 * @return 			The request, or NULL if a matching request is not
 *					found.
 */
NMRequest *nm_conn_find_request(NMConn * conn, int trans_id);

/**
 * Get the server address for the connection.
 *
 * @param conn		The connection.
 *
 * @return 			The server address for the connection.
 *
 */
const char *nm_conn_get_addr(NMConn * conn);

/**
 * Get the port for the connection.
 *
 * @param conn		The connection.
 *
 * @return 			The port that we are connected to.
 */
int nm_conn_get_port(NMConn * conn);

#endif
