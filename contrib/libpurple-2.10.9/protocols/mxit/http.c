/*
 *					MXit Protocol libPurple Plugin
 *
 *			-- MXit client protocol implementation --
 *
 *				Pieter Loubser	<libpurple@mxit.com>
 *
 *			(C) Copyright 2009	MXit Lifestyle (Pty) Ltd.
 *				<http://www.mxitlifestyle.com>
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

#include	"internal.h"
#include	"debug.h"

#include	"mxit.h"
#include	"protocol.h"
#include	"http.h"


/* HTTP constants */
#define		HTTP_11_200_OK		"HTTP/1.1 200 OK\r\n"
#define		HTTP_11_100_CONT	"HTTP/1.1 100 Continue\r\n"
#define		HTTP_11_SEPERATOR	"\r\n\r\n"
#define		HTTP_CONTENT_LEN	"Content-Length: "


/* define to enable HTTP debugging */
#define		DEBUG_HTTP


/*------------------------------------------------------------------------
 * This will freeup the memory used by a HTTP request structure
 *
 *	@param req		The HTTP structure's resources should be freed up
 */
static void free_http_request( struct http_request* req )
{
	g_free( req->host );
	g_free( req->data );
	g_free( req );
}


/*------------------------------------------------------------------------
 * Write the request to the HTTP server.
 *
 *  @param fd			The file descriptor
 *  @param pktdata		The packet data
 *  @param pktlen		The length of the packet data
 *  @return				Return -1 on error, otherwise 0
 */
static int mxit_http_raw_write( int fd, const char* pktdata, int pktlen )
{
	int		written;
	int		res;

	written = 0;
	while ( written < pktlen ) {
		res = write( fd, &pktdata[written], pktlen - written );
		if ( res <= 0 ) {
			/* error on socket */
			if ( errno == EAGAIN )
				continue;

			purple_debug_error( MXIT_PLUGIN_ID, "Error while writing packet to HTTP server (%i)\n", res );
			return -1;
		}
		written += res;
	}

	return 0;
}


/*------------------------------------------------------------------------
 * Callback when data is received from the HTTP server.
 *
 *  @param user_data		The MXit session object
 *  @param source			The file-descriptor on which data was received
 *  @param cond				Condition which caused the callback (PURPLE_INPUT_READ)
 */
static void mxit_cb_http_read( gpointer user_data, gint source, PurpleInputCondition cond )
{
	struct MXitSession*	session		= (struct MXitSession*) user_data;
	char				buf[256];
	int					buflen;
	char*				body;
	int					bodylen;
	char*				ch;
	int					len;
	char*				tmp;
	int					res;
	char*				next;

	purple_debug_info( MXIT_PLUGIN_ID, "mxit_cb_http_read\n" );

	if ( session->rx_state == RX_STATE_RLEN ) {
		/* we are reading in the HTTP headers */

		/* copy partial headers if we have any part saved */
		memcpy( buf, session->rx_dbuf, session->rx_i );
		buflen = session->rx_i;

		/* read bytes from the socket */
		len = read( session->fd, buf + buflen, sizeof( buf ) - ( buflen + 1 ) );
		if ( len <= 0 ) {
			/* connection has been terminated, or error occurred */
			goto done;
		}
		buf[buflen+len] = '\0';

//nextpacket:

#ifdef	DEBUG_HTTP
		purple_debug_info( MXIT_PLUGIN_ID, "HTTP POST READ 1: (%i)\n", len );
		dump_bytes( session, buf + buflen, len );
#endif

		/* see if we have all the HTTP headers yet */
		ch = strstr( buf, HTTP_11_SEPERATOR );
		if ( !ch ) {
			/* we need to wait for more input, so save what we have */
			session->rx_i = buflen + len;
			memcpy( session->rx_dbuf, buf, session->rx_i );
			return;
		}
		buflen += len;

		/* we have the header's end now skip over the http separator to get the body offset */
		ch += strlen( HTTP_11_SEPERATOR );
		*(ch - 1) = '\0';
		body = ch;

		res = buflen - ( ch - buf );
		if ( res > 0 ) {
			/* we read more bytes than just the header so copy it over */
			memcpy( session->rx_dbuf, ch, res );
			session->rx_i = res;
		}
		else {
			session->rx_i = 0;
		}

		/* test for a good response */
		if ( ( strncmp( buf, HTTP_11_200_OK, strlen( HTTP_11_200_OK ) ) != 0 ) && ( strncmp( buf, HTTP_11_100_CONT, strlen( HTTP_11_100_CONT ) ) != 0 ) ) {
			/* bad result */
			purple_debug_error( MXIT_PLUGIN_ID, "HTTP error: %s\n", ch );
			goto done;
		}

		/* find the content-length */
		ch = (char*) purple_strcasestr( buf, HTTP_CONTENT_LEN );
		if ( !ch ) {
			/* bad request. it does not contain a content-length header */
			purple_debug_error( MXIT_PLUGIN_ID, "HTTP reply received without content-length header (ignoring packet)\n" );
			goto done;
		}

		/* parse the content-length */
		ch += strlen( HTTP_CONTENT_LEN );
		tmp = strchr( ch, '\r' );
		if ( !tmp ) {
			purple_debug_error( MXIT_PLUGIN_ID, "Received bad HTTP reply packet (ignoring packet)\n" );
			goto done;
		}
		tmp = g_strndup( ch, tmp - ch );
		bodylen = atoi( tmp );
		g_free( tmp );
		tmp = NULL;

		if ( buflen + bodylen >= CP_MAX_PACKET ) {
			/* this packet is way to big */
			goto done;
		}
		else if ( buflen > ( ( body - buf ) + bodylen ) ) {
			/* we have a second packet here */
			next = body + bodylen;
			session->rx_res = 0;
		}
		else {
			session->rx_res = bodylen - session->rx_i;
		}

		if ( session->rx_res == 0 ) {
			/* we have read all the data */
			session->rx_i = bodylen;
			session->rx_state = RX_STATE_PROC;
		}
		else {
			/* there is still some data outstanding */
			session->rx_state = RX_STATE_DATA;
		}
	}
	else if ( session->rx_state == RX_STATE_DATA ) {
		/* we are reading the HTTP content (body) */

		/* read bytes from the socket */
		len = read( session->fd, &session->rx_dbuf[session->rx_i], session->rx_res );
		if ( len <= 0 ) {
			/* connection has been terminated, or error occurred */
			goto done;
		}

#ifdef	DEBUG_HTTP
		purple_debug_info( MXIT_PLUGIN_ID, "HTTP POST READ 2: (%i)\n", len );
		dump_bytes( session, &session->rx_dbuf[session->rx_i], len );
#endif
		session->rx_i += len;
		session->rx_res -= len;

		if ( session->rx_res == 0 ) {
			/* ok, so now we have read in the whole packet */
			session->rx_state = RX_STATE_PROC;
		}
	}

	if ( session->rx_state == RX_STATE_PROC ) {
		mxit_parse_packet( session );

#if	0
		if ( next ) {
			/* there is another packet of which we read some data */

			/* reset input */
			session->rx_state = RX_STATE_RLEN;
			session->rx_lbuf[0] = '\0';
			session->rx_i = 0;
			session->rx_res = 0;

			/* move read data */
			len = next - buf;
			buflen = len;
			memcpy( buf, next, len );
			goto nextpacket;
		}
#endif

		/* we are done */
		goto done;
	}

	return;
done:
	close( session->fd );
	purple_input_remove( session->http_handler );
	session->http_handler = 0;
}


/*------------------------------------------------------------------------
 * Callback invoked once the connection has been established to the HTTP server,
 * or on connection failure.
 *
 *  @param user_data		The MXit session object
 *  @param source			The file-descriptor associated with the connection
 *  @param error_message	Message explaining why the connection failed
 */
static void mxit_cb_http_connect( gpointer user_data, gint source, const gchar* error_message )
{
	struct http_request*	req	= (struct http_request*) user_data;

	purple_debug_info( MXIT_PLUGIN_ID, "mxit_cb_http_connect\n" );

	/* source is the file descriptor of the new connection */
	if ( source < 0 ) {
		purple_debug_info( MXIT_PLUGIN_ID, "mxit_cb_http_connect failed: %s\n", error_message );
		purple_connection_error( req->session->con, _( "Unable to connect to the MXit HTTP server. Please check your server settings." ) );
		return;
	}

	/* we now have an open and active TCP connection to the mxit server */
	req->session->fd = source;

	/* reset the receive buffer */
	req->session->rx_state = RX_STATE_RLEN;
	req->session->rx_lbuf[0] = '\0';
	req->session->rx_i = 0;
	req->session->rx_res = 0;

	/* start listening on the open connection for messages from the server (reference: "libpurple/eventloop.h") */
	req->session->http_handler = purple_input_add( req->session->fd, PURPLE_INPUT_READ, mxit_cb_http_read, req->session );

	/* actually send the request to the HTTP server */
	mxit_http_raw_write( req->session->fd, req->data, req->datalen );

	/* free up resources */
	free_http_request( req );
	req = NULL;
}


/*------------------------------------------------------------------------
 * Create HTTP connection for sending a HTTP request
 *
 *	@param session		The MXit session object
 *	@param host			The server name to connect to
 *	@param port			The port number to connect to
 *	@param data			The HTTP request data (including HTTP headers etc.)
 *	@param datalen		The HTTP request data length
 */
void mxit_http_send_request( struct MXitSession* session, char* host, int port, const char* data, int datalen )
{
	PurpleProxyConnectData*		con	= NULL;
	struct http_request*		req;

	/* build the http request */
	req = g_new0( struct http_request, 1 );
	req->session = session;
	req->host = host;
	req->port = port;
	req->data = g_malloc0( datalen );
	memcpy( req->data, data, datalen );
	req->datalen = datalen;

	/* open connection to the HTTP server */
	con = purple_proxy_connect( NULL, session->acc, host, port, mxit_cb_http_connect, req );
	if ( !con ) {
		purple_connection_error_reason( session->con, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, _( "Unable to connect" ) );
	}
}

