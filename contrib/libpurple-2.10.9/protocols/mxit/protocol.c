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
#include	"version.h"

#include	"protocol.h"
#include	"mxit.h"
#include	"roster.h"
#include	"chunk.h"
#include	"filexfer.h"
#include	"markup.h"
#include	"multimx.h"
#include	"splashscreen.h"
#include	"login.h"
#include	"formcmds.h"
#include	"http.h"
#include	"cipher.h"
#include	"voicevideo.h"


#define		MXIT_MS_OFFSET		3

/* configure the right record terminator char to use */
#define		CP_REC_TERM			( ( session->http ) ? CP_HTTP_REC_TERM : CP_SOCK_REC_TERM )


/*------------------------------------------------------------------------
 * return the current timestamp in milliseconds
 */
gint64 mxit_now_milli( void )
{
	GTimeVal	now;

	g_get_current_time( &now );

	return ( ( now.tv_sec * 1000 ) + ( now.tv_usec / 1000 ) );
}


/*------------------------------------------------------------------------
 * Display a notification popup message to the user.
 *
 *  @param type			The type of notification:
 *		- info:		PURPLE_NOTIFY_MSG_INFO
 *		- warning:	PURPLE_NOTIFY_MSG_WARNING
 *		- error:	PURPLE_NOTIFY_MSG_ERROR
 *  @param heading		Heading text
 *  @param message		Message text
 */
void mxit_popup( int type, const char* heading, const char* message )
{
	/* (reference: "libpurple/notify.h") */
	purple_notify_message( NULL, type, _( MXIT_POPUP_WIN_NAME ), heading, message, NULL, NULL );
}


/*------------------------------------------------------------------------
 * For compatibility with legacy clients, all usernames are sent from MXit with a domain
 *  appended.  For MXit contacts, this domain is set to "@m".  This function strips
 *  those fake domains.
 *
 *  @param username		The username of the contact
 */
void mxit_strip_domain( char* username )
{
	if ( g_str_has_suffix( username, "@m" ) )
		username[ strlen( username ) - 2 ] = '\0';
}


/*------------------------------------------------------------------------
 * Dump a byte buffer to the console for debugging purposes.
 *
 *  @param buf			The data
 *  @param len			The data length
 */
void dump_bytes( struct MXitSession* session, const char* buf, int len )
{
	char*	msg	= g_malloc0( len + 1 );
	int		i;

	for ( i = 0; i < len; i++ ) {
		char ch	= buf[i];

		if ( ch == CP_REC_TERM )		/* record terminator */
			msg[i] = '!';
		else if ( ch == CP_FLD_TERM )	/* field terminator */
			msg[i] = '^';
		else if ( ch == CP_PKT_TERM )	/* packet terminator */
			msg[i] = '@';
		else if ( ( ch < 0x20 ) || ( ch > 0x7E ) )		/* non-printable character */
			msg[i] = '_';
		else
			msg[i] = ch;
	}

	purple_debug_info( MXIT_PLUGIN_ID, "DUMP: '%s'\n", msg );

	g_free( msg );
}


/*------------------------------------------------------------------------
 * Determine if we have an active chat with a specific contact
 *
 *  @param session		The MXit session object
 *  @param who			The contact name
 *  @return				Return true if we have an active chat with the contact
 */
gboolean find_active_chat( const GList* chats, const char* who )
{
	const GList*	list	= chats;
	const char*		chat	= NULL;

	while ( list ) {
		chat = (const char*) list->data;

		if ( strcmp( chat, who ) == 0 )
			return TRUE;

		list = g_list_next( list );
	}

	return FALSE;
}


/*========================================================================================================================
 * Low-level Packet transmission
 */

/*------------------------------------------------------------------------
 * Remove next packet from transmission queue.
 *
 *  @param session		The MXit session object
 *  @return				The next packet for transmission (or NULL)
 */
static struct tx_packet* pop_tx_packet( struct MXitSession* session )
{
	struct tx_packet*	packet	= NULL;

	if ( session->queue.count > 0 ) {
		/* dequeue the next packet */
		packet = session->queue.packets[session->queue.rd_i];
		session->queue.packets[session->queue.rd_i] = NULL;
		session->queue.rd_i = ( session->queue.rd_i + 1 ) % MAX_QUEUE_SIZE;
		session->queue.count--;
	}

	return packet;
}


/*------------------------------------------------------------------------
 * Add packet to transmission queue.
 *
 *  @param session		The MXit session object
 *  @param packet		The packet to transmit
 *  @return				Return TRUE if packet was enqueue, or FALSE if queue is full.
 */
static gboolean push_tx_packet( struct MXitSession* session, struct tx_packet* packet )
{
	if ( session->queue.count < MAX_QUEUE_SIZE ) {
		/* enqueue packet */
		session->queue.packets[session->queue.wr_i] = packet;
		session->queue.wr_i = ( session->queue.wr_i + 1 ) % MAX_QUEUE_SIZE;
		session->queue.count++;
		return TRUE;
	}
	else
		return FALSE;		/* queue is full */
}


/*------------------------------------------------------------------------
 * Deallocate transmission packet.
 *
 *  @param packet		The packet to deallocate.
 */
static void free_tx_packet( struct tx_packet* packet )
{
	g_free( packet->data );
	g_free( packet );
	packet = NULL;
}


/*------------------------------------------------------------------------
 * Flush all the packets from the tx queue and release the resources.
 *
 *  @param session		The MXit session object
 */
static void flush_queue( struct MXitSession* session )
{
	struct tx_packet*	packet;

	purple_debug_info( MXIT_PLUGIN_ID, "flushing the tx queue\n" );

	while ( (packet = pop_tx_packet( session ) ) != NULL )
		free_tx_packet( packet );
}


/*------------------------------------------------------------------------
 * TX Step 3: Write the packet data to the TCP connection.
 *
 *  @param fd			The file descriptor
 *  @param pktdata		The packet data
 *  @param pktlen		The length of the packet data
 *  @return				Return -1 on error, otherwise 0
 */
static int mxit_write_sock_packet( int fd, const char* pktdata, int pktlen )
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

			purple_debug_error( MXIT_PLUGIN_ID, "Error while writing packet to MXit server (%i)\n", res );
			return -1;
		}
		written += res;
	}

	return 0;
}


/*------------------------------------------------------------------------
 * Callback called for handling a HTTP GET response
 *
 *  @param url_data			libPurple internal object (see purple_util_fetch_url_request)
 *  @param user_data		The MXit session object
 *  @param url_text			The data returned (could be NULL if error)
 *  @param len				The length of the data returned (0 if error)
 *  @param error_message	Descriptive error message
 */
static void mxit_cb_http_rx( PurpleUtilFetchUrlData* url_data, gpointer user_data, const gchar* url_text, gsize len, const gchar* error_message )
{
	struct MXitSession*		session		= (struct MXitSession*) user_data;

	/* clear outstanding request */
	session->async_calls = g_slist_remove( session->async_calls, url_data );

	if ( ( !url_text ) || ( len == 0 ) ) {
		/* error with request */
		purple_debug_error( MXIT_PLUGIN_ID, "HTTP response error (%s)\n", error_message );
		return;
	}

	/* convert the HTTP result */
	memcpy( session->rx_dbuf, url_text, len );
	session->rx_i = len;

	mxit_parse_packet( session );
}


/*------------------------------------------------------------------------
 * TX Step 3: Write the packet data to the HTTP connection (GET style).
 *
 *  @param session		The MXit session object
 *  @param pktdata		The packet data
 *  @param pktlen		The length of the packet data
 *  @return				Return -1 on error, otherwise 0
 */
static void mxit_write_http_get( struct MXitSession* session, struct tx_packet* packet )
{
	PurpleUtilFetchUrlData*	url_data;
	char*		part	= NULL;
	char*		url		= NULL;

	if ( packet->datalen > 0 ) {
		char*	tmp		= NULL;

		tmp = g_strndup( packet->data, packet->datalen );
		part = g_strdup( purple_url_encode( tmp ) );
		g_free( tmp );
	}

	url = g_strdup_printf( "%s?%s%s", session->http_server, purple_url_encode( packet->header ), ( !part ) ? "" : part );

#ifdef	DEBUG_PROTOCOL
	purple_debug_info( MXIT_PLUGIN_ID, "HTTP GET: '%s'\n", url );
#endif

	/* send the HTTP request */
	url_data = purple_util_fetch_url_request( url, TRUE, MXIT_HTTP_USERAGENT, TRUE, NULL, FALSE, mxit_cb_http_rx, session );
	if ( url_data )
		session->async_calls = g_slist_prepend( session->async_calls, url_data );

	g_free( url );
	if ( part )
		g_free( part );
}


/*------------------------------------------------------------------------
 * TX Step 3: Write the packet data to the HTTP connection (POST style).
 *
 *  @param session		The MXit session object
 *  @param pktdata		The packet data
 *  @param pktlen		The length of the packet data
 *  @return				Return -1 on error, otherwise 0
 */
static void mxit_write_http_post( struct MXitSession* session, struct tx_packet* packet )
{
	char		request[256 + packet->datalen];
	int			reqlen;
	char*		host_name;
	int			host_port;
	gboolean	ok;

	/* extract the HTTP host name and host port number to connect to */
	ok = purple_url_parse( session->http_server, &host_name, &host_port, NULL, NULL, NULL );
	if ( !ok ) {
		purple_debug_error( MXIT_PLUGIN_ID, "HTTP POST error: (host name '%s' not valid)\n", session->http_server );
	}

	/* strip off the last '&' from the header */
	packet->header[packet->headerlen - 1] = '\0';
	packet->headerlen--;

	/* build the HTTP request packet */
	reqlen = g_snprintf( request, 256,
					"POST %s?%s HTTP/1.1\r\n"
					"User-Agent: " MXIT_HTTP_USERAGENT "\r\n"
					"Content-Type: application/octet-stream\r\n"
					"Host: %s\r\n"
					"Content-Length: %d\r\n"
					"\r\n",
					session->http_server,
					purple_url_encode( packet->header ),
					host_name,
					packet->datalen - MXIT_MS_OFFSET
	);

	/* copy over the packet body data (could be binary) */
	memcpy( request + reqlen, packet->data + MXIT_MS_OFFSET, packet->datalen - MXIT_MS_OFFSET );
	reqlen += packet->datalen;

#ifdef	DEBUG_PROTOCOL
	purple_debug_info( MXIT_PLUGIN_ID, "HTTP POST:\n" );
	dump_bytes( session, request, reqlen );
#endif

	/* send the request to the HTTP server */
	mxit_http_send_request( session, host_name, host_port, request, reqlen );
}


/*------------------------------------------------------------------------
 * TX Step 2: Handle the transmission of the packet to the MXit server.
 *
 *  @param session		The MXit session object
 *  @param packet		The packet to transmit
 */
static void mxit_send_packet( struct MXitSession* session, struct tx_packet* packet )
{
	int		res;

	if ( !( session->flags & MXIT_FLAG_CONNECTED ) ) {
		/* we are not connected so ignore all packets to be send */
		purple_debug_error( MXIT_PLUGIN_ID, "Dropping TX packet (we are not connected)\n" );
		return;
	}

	purple_debug_info( MXIT_PLUGIN_ID, "Packet send CMD:%i (%i)\n", packet->cmd, packet->headerlen + packet->datalen );
#ifdef	DEBUG_PROTOCOL
	dump_bytes( session, packet->header, packet->headerlen );
	dump_bytes( session, packet->data, packet->datalen );
#endif

	if ( !session->http ) {
		/* socket connection */
		char		data[packet->datalen + packet->headerlen];
		int			datalen;

		/* create raw data buffer */
		memcpy( data, packet->header, packet->headerlen );
		memcpy( data + packet->headerlen, packet->data, packet->datalen );
		datalen = packet->headerlen + packet->datalen;

		res = mxit_write_sock_packet( session->fd, data, datalen );
		if ( res < 0 ) {
			/* we must have lost the connection, so terminate it so that we can reconnect */
			purple_connection_error( session->con, _( "We have lost the connection to MXit. Please reconnect." ) );
		}
	}
	else {
		/* http connection */

		if ( packet->cmd == CP_CMD_MEDIA ) {
			/* multimedia packets must be send with a HTTP POST */
			mxit_write_http_post( session, packet );
		}
		else {
			mxit_write_http_get( session, packet );
		}
	}

	/* update the timestamp of the last-transmitted packet */
	session->last_tx = mxit_now_milli();

	/*
	 * we need to remember that we are still waiting for the ACK from
	 * the server on this request
	 */
	session->outack = packet->cmd;

	/* free up the packet resources */
	free_tx_packet( packet );
}


/*------------------------------------------------------------------------
 * TX Step 1: Create a new Tx packet and queue it for sending.
 *
 *  @param session		The MXit session object
 *  @param data			The packet data (payload)
 *  @param datalen		The length of the packet data
 *  @param cmd			The MXit command for this packet
 */
static void mxit_queue_packet( struct MXitSession* session, const char* data, int datalen, int cmd )
{
	struct tx_packet*	packet;
	char				header[256];
	int					hlen;

	/* create a packet for sending */
	packet = g_new0( struct tx_packet, 1 );
	packet->data = g_malloc0( datalen );
	packet->cmd = cmd;
	packet->headerlen = 0;

	/* create generic packet header */
	hlen = g_snprintf( header, sizeof( header ), "id=%s%c", purple_account_get_username( session->acc ), CP_REC_TERM );	/* client mxitid */

	if ( session->http ) {
		/* http connection only */
		hlen += g_snprintf( header + hlen, sizeof( header ) - hlen, "s=" );
		if ( session->http_sesid > 0 ) {
			hlen += g_snprintf( header + hlen, sizeof( header ) - hlen, "%u%c", session->http_sesid, CP_FLD_TERM );	/* http session id */
		}
		session->http_seqno++;
		hlen += g_snprintf( header + hlen, sizeof( header ) - hlen, "%u%c", session->http_seqno, CP_REC_TERM );		/* http request sequence id */
	}

	hlen += g_snprintf( header + hlen, sizeof( header ) - hlen, "cm=%i%c", cmd, CP_REC_TERM ); 						/* packet command */

	if ( !session->http ) {
		/* socket connection only */
		packet->headerlen = g_snprintf( packet->header, sizeof( packet->header ), "ln=%i%c", ( datalen + hlen ), CP_REC_TERM );		/* packet length */
	}

	/* copy the header to packet */
	memcpy( packet->header + packet->headerlen, header, hlen );
	packet->headerlen += hlen;

	/* copy payload to packet */
	if ( datalen > 0 )
		memcpy( packet->data, data, datalen );
	packet->datalen = datalen;


	/* shortcut */
	if ( ( session->queue.count == 0 ) && ( session->outack == 0 ) ) {
		/* the queue is empty and there are no outstanding acks so we can write it directly */
		mxit_send_packet( session, packet );
	}
	else {
		/* we need to queue this packet */

		if ( ( packet->cmd == CP_CMD_PING ) || ( packet->cmd == CP_CMD_POLL ) ) {
			/* we do NOT queue HTTP poll nor socket ping packets */
			free_tx_packet( packet );
			return;
		}

		purple_debug_info( MXIT_PLUGIN_ID, "queueing packet for later sending cmd=%i\n", cmd );
		if ( !push_tx_packet( session, packet ) ) {
			/* packet could not be queued for transmission */
			mxit_popup( PURPLE_NOTIFY_MSG_ERROR, _( "Message Send Error" ), _( "Unable to process your request at this time" ) );
			free_tx_packet( packet );
		}
	}
}


/*------------------------------------------------------------------------
 * Manage the packet send queue (send next packet, timeout's, etc).
 *
 *  @param session		The MXit session object
 */
static void mxit_manage_queue( struct MXitSession* session )
{
	struct tx_packet*	packet		= NULL;
	gint64				now			= mxit_now_milli();

	if ( !( session->flags & MXIT_FLAG_CONNECTED ) ) {
		/* we are not connected, so ignore the queue */
		return;
	}
	else if ( session->outack > 0 ) {
		/* we are still waiting for an outstanding ACK from the MXit server */
		if ( session->last_tx <= mxit_now_milli() - ( MXIT_ACK_TIMEOUT * 1000 ) ) {
			/* ack timeout! so we close the connection here */
			purple_debug_info( MXIT_PLUGIN_ID, "mxit_manage_queue: Timeout awaiting ACK for command '%i'\n", session->outack );
			purple_connection_error( session->con, _( "Timeout while waiting for a response from the MXit server." ) );
		}
		return;
	}

	/*
	 * the mxit server has flood detection and it prevents you from sending messages to fast.
	 * this is a self defense mechanism, a very annoying feature. so the client must ensure that
	 * it does not send messages too fast otherwise mxit will ignore the user for 30 seconds.
	 * this is what we are trying to avoid here..
	 */
	if ( session->q_fast_timer_id == 0 ) {
		/* the fast timer has not been set yet */
		if ( session->last_tx > ( now - MXIT_TX_DELAY ) ) {
			/* we need to wait a little before sending the next packet, so schedule a wakeup call */
			gint64 tdiff = now - ( session->last_tx );
			guint delay = ( MXIT_TX_DELAY - tdiff ) + 9;
			if ( delay <= 0 )
				delay = MXIT_TX_DELAY;
			session->q_fast_timer_id = purple_timeout_add( delay, mxit_manage_queue_fast, session );
		}
		else {
			/* get the next packet from the queue to send */
			packet = pop_tx_packet( session );
			if ( packet != NULL ) {
				/* there was a packet waiting to be sent to the server, now is the time to do something about it */

				/* send the packet to MXit server */
				mxit_send_packet( session, packet );
			}
		}
	}
}


/*------------------------------------------------------------------------
 * Slow callback to manage the packet send queue.
 *
 *  @param session		The MXit session object
 */
gboolean mxit_manage_queue_slow( gpointer user_data )
{
	struct MXitSession* session		= (struct MXitSession*) user_data;

	mxit_manage_queue( session );

	/* continue running */
	return TRUE;
}


/*------------------------------------------------------------------------
 * Fast callback to manage the packet send queue.
 *
 *  @param session		The MXit session object
 */
gboolean mxit_manage_queue_fast( gpointer user_data )
{
	struct MXitSession* session		= (struct MXitSession*) user_data;

	session->q_fast_timer_id = 0;
	mxit_manage_queue( session );

	/* stop running */
	return FALSE;
}


/*------------------------------------------------------------------------
 * Callback to manage HTTP server polling (HTTP connections ONLY)
 *
 *  @param session		The MXit session object
 */
gboolean mxit_manage_polling( gpointer user_data )
{
	struct MXitSession* session		= (struct MXitSession*) user_data;
	gboolean			poll		= FALSE;
	gint64				now			= mxit_now_milli();
	gint64				rxdiff;

	if ( !( session->flags & MXIT_FLAG_LOGGEDIN ) ) {
		/* we only poll if we are actually logged in */
		return TRUE;
	}

	/* calculate the time differences */
	rxdiff = now - session->last_rx;

	if ( rxdiff < MXIT_HTTP_POLL_MIN ) {
		/* we received some reply a few moments ago, so reset the poll interval */
		session->http_interval = MXIT_HTTP_POLL_MIN;
	}
	else if ( session->http_last_poll < ( now - session->http_interval ) ) {
		/* time to poll again */
		poll = TRUE;

		/* back-off some more with the polling */
		session->http_interval = session->http_interval + ( session->http_interval / 2 );
		if ( session->http_interval > MXIT_HTTP_POLL_MAX )
			session->http_interval = MXIT_HTTP_POLL_MAX;
	}

	/* debugging */
	//purple_debug_info( MXIT_PLUGIN_ID, "POLL TIMER: %i (%i)\n", session->http_interval, rxdiff );

	if ( poll ) {
		/* send poll request */
		session->http_last_poll = mxit_now_milli();
		mxit_send_poll( session );
	}

	return TRUE;
}


/*========================================================================================================================
 * Send MXit operations.
 */

/*------------------------------------------------------------------------
 * Send a ping/keepalive packet to MXit server.
 *
 *  @param session		The MXit session object
 */
void mxit_send_ping( struct MXitSession* session )
{
	/* queue packet for transmission */
	mxit_queue_packet( session, NULL, 0, CP_CMD_PING );
}


/*------------------------------------------------------------------------
 * Send a poll request to the HTTP server (HTTP connections ONLY).
 *
 *  @param session		The MXit session object
 */
void mxit_send_poll( struct MXitSession* session )
{
	/* queue packet for transmission */
	mxit_queue_packet( session, NULL, 0, CP_CMD_POLL );
}


/*------------------------------------------------------------------------
 * Send a logout packet to the MXit server.
 *
 *  @param session		The MXit session object
 */
void mxit_send_logout( struct MXitSession* session )
{
	/* queue packet for transmission */
	mxit_queue_packet( session, NULL, 0, CP_CMD_LOGOUT );
}


/*------------------------------------------------------------------------
 * Send a register packet to the MXit server.
 *
 *  @param session		The MXit session object
 */
void mxit_send_register( struct MXitSession* session )
{
	struct MXitProfile*	profile		= session->profile;
	const char*			locale;
	char				data[CP_MAX_PACKET];
	int					datalen;
	char*				clientVersion;
	unsigned int		features	= MXIT_CP_FEATURES;

	locale = purple_account_get_string( session->acc, MXIT_CONFIG_LOCALE, MXIT_DEFAULT_LOCALE );

	/* Voice and Video supported */
	if ( mxit_audio_enabled() && mxit_video_enabled() )
		features |= ( MXIT_CF_VOICE | MXIT_CF_VIDEO );
	else if ( mxit_audio_enabled() )
		features |= MXIT_CF_VOICE;

	/* generate client version string (eg, P-2.7.10-Y-PURPLE) */
	clientVersion = g_strdup_printf( "%c-%i.%i.%i-%s-%s", MXIT_CP_DISTCODE, PURPLE_MAJOR_VERSION, PURPLE_MINOR_VERSION, PURPLE_MICRO_VERSION, MXIT_CP_ARCH, MXIT_CP_PLATFORM );

	/* convert the packet to a byte stream */
	datalen = g_snprintf( data, sizeof( data ),
								"ms=%s%c%s%c%i%c%s%c"		/* "ms"=password\1version\1maxreplyLen\1name\1 */
								"%s%c%i%c%s%c%s%c"			/* dateOfBirth\1gender\1location\1capabilities\1 */
								"%s%c%i%c%s%c%s"			/* dc\1features\1dialingcode\1locale */
								"%c%i%c%i",					/* \1protocolVer\1lastRosterUpdate */
								session->encpwd, CP_FLD_TERM, clientVersion, CP_FLD_TERM, CP_MAX_FILESIZE, CP_FLD_TERM, profile->nickname, CP_FLD_TERM,
								profile->birthday, CP_FLD_TERM, ( profile->male ) ? 1 : 0, CP_FLD_TERM, MXIT_DEFAULT_LOC, CP_FLD_TERM, MXIT_CP_CAP, CP_FLD_TERM,
								session->distcode, CP_FLD_TERM, features, CP_FLD_TERM, session->dialcode, CP_FLD_TERM, locale,
								CP_FLD_TERM, MXIT_CP_PROTO_VESION, CP_FLD_TERM, 0
	);

	/* queue packet for transmission */
	mxit_queue_packet( session, data, datalen, CP_CMD_REGISTER );

	g_free( clientVersion );
}


/*------------------------------------------------------------------------
 * Send a login packet to the MXit server.
 *
 *  @param session		The MXit session object
 */
void mxit_send_login( struct MXitSession* session )
{
	const char*		splashId;
	const char*		locale;
	char			data[CP_MAX_PACKET];
	int				datalen;
	char*			clientVersion;
	unsigned int	features	= MXIT_CP_FEATURES;

	locale = purple_account_get_string( session->acc, MXIT_CONFIG_LOCALE, MXIT_DEFAULT_LOCALE );

	/* Voice and Video supported */
	if ( mxit_audio_enabled() && mxit_video_enabled() )
		features |= ( MXIT_CF_VOICE | MXIT_CF_VIDEO );
	else if ( mxit_audio_enabled() )
		features |= MXIT_CF_VOICE;

	/* generate client version string (eg, P-2.7.10-Y-PURPLE) */
	clientVersion = g_strdup_printf( "%c-%i.%i.%i-%s-%s", MXIT_CP_DISTCODE, PURPLE_MAJOR_VERSION, PURPLE_MINOR_VERSION, PURPLE_MICRO_VERSION, MXIT_CP_ARCH, MXIT_CP_PLATFORM );

	/* convert the packet to a byte stream */
	datalen = g_snprintf( data, sizeof( data ),
								"ms=%s%c%s%c%i%c"			/* "ms"=password\1version\1getContacts\1 */
								"%s%c%s%c%i%c"				/* capabilities\1dc\1features\1 */
								"%s%c%s%c"					/* dialingcode\1locale\1 */
								"%i%c%i%c%i",				/* maxReplyLen\1protocolVer\1lastRosterUpdate */
								session->encpwd, CP_FLD_TERM, clientVersion, CP_FLD_TERM, 1, CP_FLD_TERM,
								MXIT_CP_CAP, CP_FLD_TERM, session->distcode, CP_FLD_TERM, features, CP_FLD_TERM,
								session->dialcode, CP_FLD_TERM, locale, CP_FLD_TERM,
								CP_MAX_FILESIZE, CP_FLD_TERM, MXIT_CP_PROTO_VESION, CP_FLD_TERM, 0
	);

	/* include "custom resource" information */
	splashId = splash_current( session );
	if ( splashId != NULL )
		datalen += g_snprintf( data + datalen, sizeof( data ) - datalen, "%ccr=%s", CP_REC_TERM, splashId );

	/* queue packet for transmission */
	mxit_queue_packet( session, data, datalen, CP_CMD_LOGIN );

	g_free( clientVersion );
}


/*------------------------------------------------------------------------
 * Send a chat message packet to the MXit server.
 *
 *  @param session		The MXit session object
 *  @param to			The username of the recipient
 *  @param msg			The message text
 */
void mxit_send_message( struct MXitSession* session, const char* to, const char* msg, gboolean parse_markup, gboolean is_command )
{
	char		data[CP_MAX_PACKET];
	char*		markuped_msg;
	int			datalen;
	int			msgtype = ( is_command ? CP_MSGTYPE_COMMAND : CP_MSGTYPE_NORMAL );

	/* first we need to convert the markup from libPurple to MXit format */
	if ( parse_markup )
		markuped_msg = mxit_convert_markup_tx( msg, &msgtype );
	else
		markuped_msg = g_strdup( msg );

	/* convert the packet to a byte stream */
	datalen = g_snprintf( data, sizeof( data ),
								"ms=%s%c%s%c%i%c%i",		/* "ms"=jid\1msg\1type\1flags */
								to, CP_FLD_TERM, markuped_msg, CP_FLD_TERM, msgtype, CP_FLD_TERM, CP_MSG_MARKUP | CP_MSG_EMOTICON
	);

	/* free the resources */
	g_free( markuped_msg );

	/* queue packet for transmission */
	mxit_queue_packet( session, data, datalen, CP_CMD_TX_MSG );
}


/*------------------------------------------------------------------------
 * Send a extended profile request packet to the MXit server.
 *
 *  @param session		The MXit session object
 *  @param username		Username who's profile is being requested (NULL = our own)
 *  @param nr_attribs	Number of attributes being requested
 *  @param attribute	The names of the attributes
 */
void mxit_send_extprofile_request( struct MXitSession* session, const char* username, unsigned int nr_attrib, const char* attribute[] )
{
	char			data[CP_MAX_PACKET];
	int				datalen;
	unsigned int	i;

	datalen = g_snprintf( data, sizeof( data ),
								"ms=%s%c%i",		/* "ms="mxitid\1nr_attributes */
								( username ? username : "" ), CP_FLD_TERM, nr_attrib
	);

	/* add attributes */
	for ( i = 0; i < nr_attrib; i++ )
		datalen += g_snprintf( data + datalen, sizeof( data ) - datalen, "%c%s", CP_FLD_TERM, attribute[i] );

	/* queue packet for transmission */
	mxit_queue_packet( session, data, datalen, CP_CMD_EXTPROFILE_GET );
}


/*------------------------------------------------------------------------
 * Send an update profile packet to the MXit server.
 *
 *  @param session		The MXit session object
 *  @param password		The new password to be used for logging in (optional)
 *	@param nr_attrib	The number of attributes
 *	@param attributes	String containing the attribute-name, attribute-type and value (seperated by '\01')
 */
void mxit_send_extprofile_update( struct MXitSession* session, const char* password, unsigned int nr_attrib, const char* attributes )
{
	char			data[CP_MAX_PACKET];
	gchar**			parts					= NULL;
	int				datalen;
	unsigned int	i;

	if ( attributes )
		parts = g_strsplit( attributes, "\01", 1 + ( nr_attrib * 3 ) );

	/* convert the packet to a byte stream */
	datalen = g_snprintf( data, sizeof( data ),
								"ms=%s%c%i",	/* "ms"=password\1nr_attibutes  */
								( password ) ? password : "", CP_FLD_TERM, nr_attrib
	);

	/* add attributes */
	for ( i = 1; i < nr_attrib * 3; i+=3 ) {
		if ( parts == NULL || parts[i] == NULL || parts[i + 1] == NULL || parts[i + 2] == NULL ) {
			purple_debug_error( MXIT_PLUGIN_ID, "Invalid profile update attributes = '%s' - nbr=%u\n", attributes, nr_attrib );
			g_strfreev( parts );
			return;
		}
		datalen += g_snprintf( data + datalen, sizeof( data ) - datalen,
								"%c%s%c%s%c%s",		/* \1name\1type\1value  */
								CP_FLD_TERM, parts[i], CP_FLD_TERM, parts[i + 1], CP_FLD_TERM, parts[i + 2] );
	}

	/* queue packet for transmission */
	mxit_queue_packet( session, data, datalen, CP_CMD_EXTPROFILE_SET );

	/* freeup the memory */
	g_strfreev( parts );
}


/*------------------------------------------------------------------------
 * Send packet to request list of suggested friends.
 *
 *  @param session		The MXit session object
 *  @param max			Maximum number of results to return
 *  @param nr_attribs	Number of attributes being requested
 *  @param attribute	The names of the attributes
 */
void mxit_send_suggest_friends( struct MXitSession* session, int max, unsigned int nr_attrib, const char* attribute[] )
{
	char			data[CP_MAX_PACKET];
	int				datalen;
	unsigned int	i;

	/* convert the packet to a byte stream */
	datalen = g_snprintf( data, sizeof( data ),
								"ms=%i%c%s%c%i%c%i%c%i",	/* inputType \1 input \1 maxSuggestions \1 startIndex \1 numAttributes \1 name0 \1 name1 ... \1 nameN */
								CP_SUGGEST_FRIENDS, CP_FLD_TERM, "", CP_FLD_TERM, max, CP_FLD_TERM, 0, CP_FLD_TERM, nr_attrib );

	/* add attributes */
	for ( i = 0; i < nr_attrib; i++ )
		datalen += g_snprintf( data + datalen, sizeof( data ) - datalen, "%c%s", CP_FLD_TERM, attribute[i] );

	/* queue packet for transmission */
	mxit_queue_packet( session, data, datalen, CP_CMD_SUGGESTCONTACTS );
}


/*------------------------------------------------------------------------
 * Send packet to perform a search for users.
 *
 *  @param session		The MXit session object
 *  @param max			Maximum number of results to return
 *  @param text			The search text
 *  @param nr_attribs	Number of attributes being requested
 *  @param attribute	The names of the attributes
 */
void mxit_send_suggest_search( struct MXitSession* session, int max, const char* text, unsigned int nr_attrib, const char* attribute[] )
{
	char			data[CP_MAX_PACKET];
	int				datalen;
	unsigned int	i;

	/* convert the packet to a byte stream */
	datalen = g_snprintf( data, sizeof( data ),
								"ms=%i%c%s%c%i%c%i%c%i",	/* inputType \1 input \1 maxSuggestions \1 startIndex \1 numAttributes \1 name0 \1 name1 ... \1 nameN */
								CP_SUGGEST_SEARCH, CP_FLD_TERM, text, CP_FLD_TERM, max, CP_FLD_TERM, 0, CP_FLD_TERM, nr_attrib );

	/* add attributes */
	for ( i = 0; i < nr_attrib; i++ )
		datalen += g_snprintf( data + datalen, sizeof( data ) - datalen, "%c%s", CP_FLD_TERM, attribute[i] );

	/* queue packet for transmission */
	mxit_queue_packet( session, data, datalen, CP_CMD_SUGGESTCONTACTS );
}


/*------------------------------------------------------------------------
 * Send a presence update packet to the MXit server.
 *
 *  @param session		The MXit session object
 *  @param presence		The presence (as per MXit types)
 *  @param statusmsg	The status message (can be NULL)
 */
void mxit_send_presence( struct MXitSession* session, int presence, const char* statusmsg )
{
	char		data[CP_MAX_PACKET];
	int			datalen;

	/* convert the packet to a byte stream */
	datalen = g_snprintf( data, sizeof( data ),
								"ms=%i%c",					/* "ms"=show\1status */
								presence, CP_FLD_TERM
	);

	/* append status message (if one is set) */
	if ( statusmsg )
		datalen += g_snprintf( data + datalen, sizeof( data ) - datalen, "%s", statusmsg );

	/* queue packet for transmission */
	mxit_queue_packet( session, data, datalen, CP_CMD_STATUS );
}


/*------------------------------------------------------------------------
 * Send a mood update packet to the MXit server.
 *
 *  @param session		The MXit session object
 *  @param mood			The mood (as per MXit types)
 */
void mxit_send_mood( struct MXitSession* session, int mood )
{
	char		data[CP_MAX_PACKET];
	int			datalen;

	/* convert the packet to a byte stream */
	datalen = g_snprintf( data, sizeof( data ),
								"ms=%i",	/* "ms"=mood */
								mood
	);

	/* queue packet for transmission */
	mxit_queue_packet( session, data, datalen, CP_CMD_MOOD );
}


/*------------------------------------------------------------------------
 * Send an invite contact packet to the MXit server.
 *
 *  @param session		The MXit session object
 *  @param username		The username of the contact being invited
 *  @param mxitid		Indicates the username is a MXitId.
 *  @param alias		Our alias for the contact
 *  @param groupname	Group in which contact should be stored.
 *  @param message		Invite message
 */
void mxit_send_invite( struct MXitSession* session, const char* username, gboolean mxitid, const char* alias, const char* groupname, const char* message )
{
	char		data[CP_MAX_PACKET];
	int			datalen;

	/* convert the packet to a byte stream */
	datalen = g_snprintf( data, sizeof( data ),
								"ms=%s%c%s%c%s%c%i%c%s%c%i",	/* "ms"=group \1 username \1 alias \1 type \1 msg \1 isuserid */
								groupname, CP_FLD_TERM, username, CP_FLD_TERM, alias,
								CP_FLD_TERM, MXIT_TYPE_MXIT, CP_FLD_TERM,
								( message ? message : "" ), CP_FLD_TERM,
								( mxitid ? 0 : 1 )
	);

	/* queue packet for transmission */
	mxit_queue_packet( session, data, datalen, CP_CMD_INVITE );
}


/*------------------------------------------------------------------------
 * Send a remove contact packet to the MXit server.
 *
 *  @param session		The MXit session object
 *  @param username		The username of the contact being removed
 */
void mxit_send_remove( struct MXitSession* session, const char* username )
{
	char		data[CP_MAX_PACKET];
	int			datalen;

	/* convert the packet to a byte stream */
	datalen = g_snprintf( data, sizeof( data ),
								"ms=%s",	/* "ms"=username */
								username
	);

	/* queue packet for transmission */
	mxit_queue_packet( session, data, datalen, CP_CMD_REMOVE );
}


/*------------------------------------------------------------------------
 * Send an accept subscription (invite) packet to the MXit server.
 *
 *  @param session		The MXit session object
 *  @param username		The username of the contact being accepted
 *  @param alias		Our alias for the contact
 */
void mxit_send_allow_sub( struct MXitSession* session, const char* username, const char* alias )
{
	char		data[CP_MAX_PACKET];
	int			datalen;

	/* convert the packet to a byte stream */
	datalen = g_snprintf( data, sizeof( data ),
								"ms=%s%c%s%c%s",	/* "ms"=username\1group\1alias */
								username, CP_FLD_TERM, "", CP_FLD_TERM, alias
	);

	/* queue packet for transmission */
	mxit_queue_packet( session, data, datalen, CP_CMD_ALLOW );
}


/*------------------------------------------------------------------------
 * Send an deny subscription (invite) packet to the MXit server.
 *
 *  @param session		The MXit session object
 *  @param username		The username of the contact being denied
 *  @param reason		The message describing the reason for the rejection (can be NULL).
 */
void mxit_send_deny_sub( struct MXitSession* session, const char* username, const char* reason )
{
	char		data[CP_MAX_PACKET];
	int			datalen;

	/* convert the packet to a byte stream */
	datalen = g_snprintf( data, sizeof( data ),
								"ms=%s",	/* "ms"=username */
								username
	);

	/* append reason (if one is set) */
	if ( reason )
		datalen += g_snprintf( data + datalen, sizeof( data ) - datalen, "%c%s", CP_FLD_TERM, reason );

	/* queue packet for transmission */
	mxit_queue_packet( session, data, datalen, CP_CMD_DENY );
}


/*------------------------------------------------------------------------
 * Send an update contact packet to the MXit server.
 *
 *  @param session		The MXit session object
 *  @param username		The username of the contact being denied
 *  @param alias		Our alias for the contact
 *  @param groupname	Group in which contact should be stored.
 */
void mxit_send_update_contact( struct MXitSession* session, const char* username, const char* alias, const char* groupname )
{
	char		data[CP_MAX_PACKET];
	int			datalen;

	/* convert the packet to a byte stream */
	datalen = g_snprintf( data, sizeof( data ),
								"ms=%s%c%s%c%s",	/* "ms"=groupname\1username\1alias */
								groupname, CP_FLD_TERM, username, CP_FLD_TERM, alias
	);

	/* queue packet for transmission */
	mxit_queue_packet( session, data, datalen, CP_CMD_UPDATE );
}


/*------------------------------------------------------------------------
 * Send a splash-screen click event packet.
 *
 *  @param session		The MXit session object
 *  @param splashid		The identifier of the splash-screen
 */
void mxit_send_splashclick( struct MXitSession* session, const char* splashid )
{
	char		data[CP_MAX_PACKET];
	int			datalen;

	/* convert the packet to a byte stream */
	datalen = g_snprintf( data, sizeof( data ),
								"ms=%s",	/* "ms"=splashId */
								splashid
	);

	/* queue packet for transmission */
	mxit_queue_packet( session, data, datalen, CP_CMD_SPLASHCLICK );
}


/*------------------------------------------------------------------------
 * Send a message event packet.
 *
 *  @param session		The MXit session object
 *  @param to           The username of the original sender (ie, recipient of the event)
 *  @param id			The identifier of the event (received in message)
 *  @param event		Identified the type of event
 */
void mxit_send_msgevent( struct MXitSession* session, const char* to, const char* id, int event )
{
	char		data[CP_MAX_PACKET];
	int			datalen;

	purple_debug_info( MXIT_PLUGIN_ID, "mxit_send_msgevent: to=%s id=%s event=%i\n", to, id, event );

	/* convert the packet to a byte stream */
	datalen = g_snprintf( data, sizeof( data ),
								"ms=%s%c%s%c%i",		/* "ms"=contactAddress \1 id \1 event */
								to, CP_FLD_TERM, id, CP_FLD_TERM, event
	);

	/* queue packet for transmission */
	mxit_queue_packet( session, data, datalen, CP_CMD_MSGEVENT );
}


/*------------------------------------------------------------------------
 * Send packet to create a MultiMX room.
 *
 *  @param session		The MXit session object
 *  @param groupname	Name of the room to create
 *  @param nr_usernames	Number of users in initial invite
 *  @param usernames	The usernames of the users in the initial invite
 */
void mxit_send_groupchat_create( struct MXitSession* session, const char* groupname, int nr_usernames, const char* usernames[] )
{
	char		data[CP_MAX_PACKET];
	int			datalen;
	int			i;

	/* convert the packet to a byte stream */
	datalen = g_snprintf( data, sizeof( data ),
								"ms=%s%c%i",	/* "ms"=roomname\1nr_jids\1jid0\1..\1jidN */
								groupname, CP_FLD_TERM, nr_usernames
	);

	/* add usernames */
	for ( i = 0; i < nr_usernames; i++ )
		datalen += g_snprintf( data + datalen, sizeof( data ) - datalen, "%c%s", CP_FLD_TERM, usernames[i] );

	/* queue packet for transmission */
	mxit_queue_packet( session, data, datalen, CP_CMD_GRPCHAT_CREATE );
}


/*------------------------------------------------------------------------
 * Send packet to invite users to existing MultiMX room.
 *
 *  @param session		The MXit session object
 *  @param roomid		The unique RoomID for the MultiMx room.
 *  @param nr_usernames	Number of users being invited
 *  @param usernames	The usernames of the users being invited
 */
void mxit_send_groupchat_invite( struct MXitSession* session, const char* roomid, int nr_usernames, const char* usernames[] )
{
	char		data[CP_MAX_PACKET];
	int			datalen;
	int			i;

	/* convert the packet to a byte stream */
	datalen = g_snprintf( data, sizeof( data ),
								"ms=%s%c%i",	/* "ms"=roomid\1nr_jids\1jid0\1..\1jidN */
								roomid, CP_FLD_TERM, nr_usernames
	);

	/* add usernames */
	for ( i = 0; i < nr_usernames; i++ )
		datalen += g_snprintf( data + datalen, sizeof( data ) - datalen, "%c%s", CP_FLD_TERM, usernames[i] );

	/* queue packet for transmission */
	mxit_queue_packet( session, data, datalen, CP_CMD_GRPCHAT_INVITE );
}


/*------------------------------------------------------------------------
 * Send a "send file direct" multimedia packet.
 *
 *  @param session		The MXit session object
 *  @param username		The username of the recipient
 *  @param filename		The name of the file being sent
 *  @param buf			The content of the file
 *  @param buflen		The length of the file contents
 */
void mxit_send_file( struct MXitSession* session, const char* username, const char* filename, const unsigned char* buf, int buflen )
{
	char				data[CP_MAX_PACKET];
	int					datalen		= 0;
	gchar*				chunk;
	int					size;

	purple_debug_info( MXIT_PLUGIN_ID, "SENDING FILE '%s' of %i bytes to user '%s'\n", filename, buflen, username );

	/* convert the packet to a byte stream */
	datalen = g_snprintf( data, sizeof( data ), "ms=" );

	/* map chunk header over data buffer */
	chunk = &data[datalen];

	size = mxit_chunk_create_senddirect( chunk_data( chunk ), username, filename, buf, buflen );
	if ( size < 0 ) {
		purple_debug_error( MXIT_PLUGIN_ID, "Error creating senddirect chunk (%i)\n", size );
		return;
	}

	set_chunk_type( chunk, CP_CHUNK_DIRECT_SND );
	set_chunk_length( chunk, size );
	datalen += MXIT_CHUNK_HEADER_SIZE + size;

	/* send the byte stream to the mxit server */
	mxit_queue_packet( session, data, datalen, CP_CMD_MEDIA );
}


/*------------------------------------------------------------------------
 * Send a "reject file" multimedia packet.
 *
 *  @param session		The MXit session object
 *  @param fileid		A unique ID that identifies this file
 */
void mxit_send_file_reject( struct MXitSession* session, const char* fileid )
{
	char				data[CP_MAX_PACKET];
	int					datalen		= 0;
	gchar*				chunk;
	int					size;

	purple_debug_info( MXIT_PLUGIN_ID, "mxit_send_file_reject\n" );

	/* convert the packet to a byte stream */
	datalen = g_snprintf( data, sizeof( data ), "ms=" );

	/* map chunk header over data buffer */
	chunk = &data[datalen];

	size = mxit_chunk_create_reject( chunk_data( chunk ), fileid );
	if ( size < 0 ) {
		purple_debug_error( MXIT_PLUGIN_ID, "Error creating reject chunk (%i)\n", size );
		return;
	}

	set_chunk_type( chunk, CP_CHUNK_REJECT );
	set_chunk_length( chunk, size );
	datalen += MXIT_CHUNK_HEADER_SIZE + size;

	/* send the byte stream to the mxit server */
	mxit_queue_packet( session, data, datalen, CP_CMD_MEDIA );
}


/*------------------------------------------------------------------------
 * Send a "get file" multimedia packet.
 *
 *  @param session		The MXit session object
 *  @param fileid		A unique ID that identifies this file
 *  @param filesize		The number of bytes to retrieve
 *  @param offset		Offset in file at which to start retrieving
 */
void mxit_send_file_accept( struct MXitSession* session, const char* fileid, int filesize, int offset )
{
	char				data[CP_MAX_PACKET];
	int					datalen		= 0;
	gchar*				chunk;
	int					size;

	purple_debug_info( MXIT_PLUGIN_ID, "mxit_send_file_accept\n" );

	/* convert the packet to a byte stream */
	datalen = g_snprintf( data, sizeof( data ), "ms=" );

	/* map chunk header over data buffer */
	chunk = &data[datalen];

	size = mxit_chunk_create_get( chunk_data(chunk), fileid, filesize, offset );
	if ( size < 0 ) {
		purple_debug_error( MXIT_PLUGIN_ID, "Error creating getfile chunk (%i)\n", size );
		return;
	}

	set_chunk_type( chunk, CP_CHUNK_GET );
	set_chunk_length( chunk, size );
	datalen += MXIT_CHUNK_HEADER_SIZE + size;

	/* send the byte stream to the mxit server */
	mxit_queue_packet( session, data, datalen, CP_CMD_MEDIA );
}


/*------------------------------------------------------------------------
 * Send a "received file" multimedia packet.
 *
 *  @param session		The MXit session object
 *  @param status		The status of the file-transfer
 */
void mxit_send_file_received( struct MXitSession* session, const char* fileid, short status )
{
	char				data[CP_MAX_PACKET];
	int					datalen		= 0;
	gchar*				chunk;
	int					size;

	purple_debug_info( MXIT_PLUGIN_ID, "mxit_send_file_received\n" );

	/* convert the packet to a byte stream */
	datalen = g_snprintf( data, sizeof( data ), "ms=" );

	/* map chunk header over data buffer */
	chunk = &data[datalen];

	size = mxit_chunk_create_received( chunk_data(chunk), fileid, status );
	if ( size < 0 ) {
		purple_debug_error( MXIT_PLUGIN_ID, "Error creating received chunk (%i)\n", size );
		return;
	}

	set_chunk_type( chunk, CP_CHUNK_RECEIVED );
	set_chunk_length( chunk, size );
	datalen += MXIT_CHUNK_HEADER_SIZE + size;

	/* send the byte stream to the mxit server */
	mxit_queue_packet( session, data, datalen, CP_CMD_MEDIA );
}


/*------------------------------------------------------------------------
 * Send a "set avatar" multimedia packet.
 *
 *  @param session		The MXit session object
 *  @param data			The avatar data
 *  @param buflen		The length of the avatar data
 */
void mxit_set_avatar( struct MXitSession* session, const unsigned char* avatar, int avatarlen )
{
	char				data[CP_MAX_PACKET];
	int					datalen		= 0;
	gchar*				chunk;
	int					size;

	purple_debug_info( MXIT_PLUGIN_ID, "mxit_set_avatar: %i bytes\n", avatarlen );

	/* convert the packet to a byte stream */
	datalen = g_snprintf( data, sizeof( data ), "ms=" );

	/* map chunk header over data buffer */
	chunk = &data[datalen];

	size = mxit_chunk_create_set_avatar( chunk_data(chunk), avatar, avatarlen );
	if ( size < 0 ) {
		purple_debug_error( MXIT_PLUGIN_ID, "Error creating set avatar chunk (%i)\n", size );
		return;
	}

	set_chunk_type( chunk, CP_CHUNK_SET_AVATAR );
	set_chunk_length( chunk, size );
	datalen += MXIT_CHUNK_HEADER_SIZE + size;

	/* send the byte stream to the mxit server */
	mxit_queue_packet( session, data, datalen, CP_CMD_MEDIA );
}


/*------------------------------------------------------------------------
 * Send a "get avatar" multimedia packet.
 *
 *  @param session		The MXit session object
 *  @param mxitId		The username who's avatar to request
 *  @param avatarId		The id of the avatar image (as string)
 *  @param data			The avatar data
 *  @param buflen		The length of the avatar data
 */
void mxit_get_avatar( struct MXitSession* session, const char* mxitId, const char* avatarId )
{
	char				data[CP_MAX_PACKET];
	int					datalen		= 0;
	gchar*				chunk;
	int					size;

	purple_debug_info( MXIT_PLUGIN_ID, "mxit_get_avatar: %s\n", mxitId );

	/* convert the packet to a byte stream */
	datalen = g_snprintf( data, sizeof( data ), "ms=" );

	/* map chunk header over data buffer */
	chunk = &data[datalen];

	size = mxit_chunk_create_get_avatar( chunk_data(chunk), mxitId, avatarId );
	if ( size < 0 ) {
		purple_debug_error( MXIT_PLUGIN_ID, "Error creating get avatar chunk (%i)\n", size );
		return;
	}

	set_chunk_type( chunk, CP_CHUNK_GET_AVATAR );
	set_chunk_length( chunk, size );
	datalen += MXIT_CHUNK_HEADER_SIZE + size;

	/* send the byte stream to the mxit server */
	mxit_queue_packet( session, data, datalen, CP_CMD_MEDIA );
}


/*------------------------------------------------------------------------
 * Process a login message packet.
 *
 *  @param session		The MXit session object
 *  @param records		The packet's data records
 *  @param rcount		The number of data records
 */
static void mxit_parse_cmd_login( struct MXitSession* session, struct record** records, int rcount )
{
	PurpleStatus*	status;
	int				presence;
	const char*		statusmsg;
	const char*		profilelist[] = { CP_PROFILE_BIRTHDATE, CP_PROFILE_GENDER, CP_PROFILE_FULLNAME,
									CP_PROFILE_TITLE, CP_PROFILE_FIRSTNAME, CP_PROFILE_LASTNAME, CP_PROFILE_EMAIL,
									CP_PROFILE_MOBILENR, CP_PROFILE_WHEREAMI, CP_PROFILE_ABOUTME, CP_PROFILE_RELATIONSHIP, CP_PROFILE_FLAGS };

	purple_account_set_int( session->acc, MXIT_CONFIG_STATE, MXIT_STATE_LOGIN );

	/* we were not yet logged in so we need to complete the login sequence here */
	session->flags |= MXIT_FLAG_LOGGEDIN;
	purple_connection_update_progress( session->con, _( "Successfully Logged In..." ), 3, 4 );
	purple_connection_set_state( session->con, PURPLE_CONNECTED );

	/* save extra info if this is a HTTP connection */
	if ( session->http ) {
		/* save the http server to use for this session */
		g_strlcpy( session->http_server, records[1]->fields[3]->data, sizeof( session->http_server ) );

		/* save the session id */
		session->http_sesid = atoi( records[0]->fields[0]->data );
	}

	/* extract UserId (from protocol 5.9) */
	if ( records[1]->fcount >= 9 )
		session->uid = g_strdup( records[1]->fields[8]->data );

	/* extract VoIP server (from protocol 6.2) */
	if ( records[1]->fcount >= 11 )
		g_strlcpy( session->voip_server, records[1]->fields[10]->data, sizeof( session->voip_server ) );

	/* display the current splash-screen */
	if ( splash_popup_enabled( session ) )
		splash_display( session );

	/* update presence status */
	status = purple_account_get_active_status( session->acc );
	presence = mxit_convert_presence( purple_status_get_id( status ) );
	statusmsg = purple_status_get_attr_string( status, "message" );

	if ( ( presence != MXIT_PRESENCE_ONLINE ) || ( statusmsg ) ) {
		/* when logging into MXit, your default presence is online. but with the UI, one can change
		 * the presence to whatever. in the case where its changed to a different presence setting
		 * we need to send an update to the server, otherwise the user's presence will be out of
		 * sync between the UI and MXit.
		 */
		char* statusmsg1 = purple_markup_strip_html( statusmsg );
		char* statusmsg2 = g_strndup( statusmsg1, CP_MAX_STATUS_MSG );

		mxit_send_presence( session, presence, statusmsg2 );

		g_free( statusmsg1 );
		g_free( statusmsg2 );
	}

	/* retrieve our MXit profile */
	mxit_send_extprofile_request( session, NULL, ARRAY_SIZE( profilelist ), profilelist );
}


/*------------------------------------------------------------------------
 * Process a received message packet.
 *
 *  @param session		The MXit session object
 *  @param records		The packet's data records
 *  @param rcount		The number of data records
 */
static void mxit_parse_cmd_message( struct MXitSession* session, struct record** records, int rcount )
{
	struct RXMsgData*	mx			= NULL;
	char*				message		= NULL;
	char*				sender		= NULL;
	int					msglen		= 0;
	int					msgflags	= 0;
	int					msgtype		= 0;

	if ( ( rcount == 1 ) || ( records[0]->fcount < 2 ) || ( records[1]->fcount == 0 ) || ( records[1]->fields[0]->len == 0 ) ) {
		/* packet contains no message or an empty message */
		return;
	}

	message = records[1]->fields[0]->data;
	msglen = strlen( message );

	/* strip off dummy domain */
	sender = records[0]->fields[0]->data;
	mxit_strip_domain( sender );

#ifdef	DEBUG_PROTOCOL
	purple_debug_info( MXIT_PLUGIN_ID, "Message received from '%s'\n", sender );
#endif

	/* decode message flags (if any) */
	if ( records[0]->fcount >= 5 )
		msgflags = atoi( records[0]->fields[4]->data );
	msgtype = atoi( records[0]->fields[2]->data );

	if ( msgflags & CP_MSG_PWD_ENCRYPTED ) {
		/* this is a password encrypted message. we do not currently support those so ignore it */
		PurpleBuddy*	buddy;
		const char*		name;
		char			msg[128];

		buddy = purple_find_buddy( session->acc, sender );
		if ( buddy )
			name = purple_buddy_get_alias( buddy );
		else
			name = sender;
		g_snprintf( msg, sizeof( msg ), _( "%s sent you an encrypted message, but it is not supported on this client." ), name );
		mxit_popup( PURPLE_NOTIFY_MSG_WARNING, _( "Message Error" ), msg );
		return;
	}
	else if ( msgflags & CP_MSG_TL_ENCRYPTED ) {
		/* this is a transport-layer encrypted message. */
		message = mxit_decrypt_message( session, message );
		if ( !message ) {
			/* could not be decrypted */
			serv_got_im( session->con, sender, _( "An encrypted message was received which could not be decrypted." ), PURPLE_MESSAGE_ERROR, time( NULL ) );
			return;
		}
	}

	if ( msgflags & CP_MSG_NOTIFY_DELIVERY ) {
		/* delivery notification is requested */
		if ( records[0]->fcount >= 4 )
			mxit_send_msgevent( session, sender, records[0]->fields[3]->data, CP_MSGEVENT_DELIVERED );
	}

	/* create and initialise new markup struct */
	mx = g_new0( struct RXMsgData, 1 );
	mx->msg = g_string_sized_new( msglen );
	mx->session = session;
	mx->from = g_strdup( sender );
	mx->timestamp = atoi( records[0]->fields[1]->data );
	mx->got_img = FALSE;
	mx->chatid = -1;
	mx->img_count = 0;

	/* update list of active chats */
	if ( !find_active_chat( session->active_chats, mx->from ) ) {
		session->active_chats = g_list_append( session->active_chats, g_strdup( mx->from ) );
	}

	if ( is_multimx_contact( session, mx->from ) ) {
		/* this is a MultiMx chatroom message */
		multimx_message_received( mx, message, msglen, msgtype, msgflags );
	}
	else {
		mxit_parse_markup( mx, message, msglen, msgtype, msgflags );
	}

	/* we are now done parsing the message */
	mx->converted = TRUE;
	if ( mx->img_count == 0 ) {
		/* we have all the data we need for this message to be displayed now. */
		mxit_show_message( mx );
	}
	else {
		/* this means there are still images outstanding for this message and
		 * still need to wait for them before we can display the message.
		 * so the image received callback function will eventually display
		 * the message. */
	}

	/* cleanup */
	if ( msgflags & CP_MSG_TL_ENCRYPTED )
		g_free( message );
}


/*------------------------------------------------------------------------
 * Process a received subscription request packet.
 *
 *  @param session		The MXit session object
 *  @param records		The packet's data records
 *  @param rcount		The number of data records
 */
static void mxit_parse_cmd_new_sub( struct MXitSession* session, struct record** records, int rcount )
{
	struct contact*		contact;
	struct record*		rec;
	int					i;

	purple_debug_info( MXIT_PLUGIN_ID, "mxit_parse_cmd_new_sub (%i recs)\n", rcount );

	for ( i = 0; i < rcount; i++ ) {
		rec = records[i];

		if ( rec->fcount < 4 ) {
			purple_debug_error( MXIT_PLUGIN_ID, "BAD SUBSCRIPTION RECORD! %i fields\n", rec->fcount );
			break;
		}

		/* build up a new contact info struct */
		contact = g_new0( struct contact, 1 );

		g_strlcpy( contact->username, rec->fields[0]->data, sizeof( contact->username ) );
		mxit_strip_domain( contact->username );				/* remove dummy domain */
		g_strlcpy( contact->alias, rec->fields[1]->data, sizeof( contact->alias ) );
		contact->type = atoi( rec->fields[2]->data );

		if ( rec->fcount >= 5 ) {
			/* there is a personal invite message attached */
			if ( ( rec->fields[4]->data ) && ( strlen( rec->fields[4]->data ) > 0 ) )
				contact->msg = strdup( rec->fields[4]->data );
		}

		/* handle the subscription */
		if ( contact-> type == MXIT_TYPE_MULTIMX ) {		/* subscription to a MultiMX room */
			char* creator = NULL;

			if ( rec->fcount >= 6 )
				creator = rec->fields[5]->data;

			multimx_invite( session, contact, creator );
		}
		else
			mxit_new_subscription( session, contact );
	}
}


/*------------------------------------------------------------------------
 * Parse the received presence value, and ensure that it is supported.
 *
 *  @param value		The received presence value.
 *  @return				A valid presence value.
 */
static short mxit_parse_presence( const char* value )
{
	short presence = atoi( value );

	/* ensure that the presence value is valid */
	switch ( presence ) {
		case MXIT_PRESENCE_OFFLINE :
		case MXIT_PRESENCE_ONLINE :
		case MXIT_PRESENCE_AWAY :
		case MXIT_PRESENCE_DND :
			return presence;

		default :
			return MXIT_PRESENCE_ONLINE;
	}
}


/*------------------------------------------------------------------------
 * Process a received contact update packet.
 *
 *  @param session		The MXit session object
 *  @param records		The packet's data records
 *  @param rcount		The number of data records
 */
static void mxit_parse_cmd_contact( struct MXitSession* session, struct record** records, int rcount )
{
	struct contact*		contact	= NULL;
	struct record*		rec;
	int					i;

	purple_debug_info( MXIT_PLUGIN_ID, "mxit_parse_cmd_contact (%i recs)\n", rcount );

	for ( i = 0; i < rcount; i++ ) {
		rec = records[i];

		if ( rec->fcount < 6 ) {
			purple_debug_error( MXIT_PLUGIN_ID, "BAD CONTACT RECORD! %i fields\n", rec->fcount );
			break;
		}

		/* build up a new contact info struct */
		contact = g_new0( struct contact, 1 );

		g_strlcpy( contact->groupname, rec->fields[0]->data, sizeof( contact->groupname ) );
		g_strlcpy( contact->username, rec->fields[1]->data, sizeof( contact->username ) );
		mxit_strip_domain( contact->username );				/* remove dummy domain */
		g_strlcpy( contact->alias, rec->fields[2]->data, sizeof( contact->alias ) );

		contact->presence = mxit_parse_presence( rec->fields[3]->data );
		contact->type = atoi( rec->fields[4]->data );
		contact->mood = atoi( rec->fields[5]->data );

		if ( rec->fcount > 6 ) {
			/* added in protocol 5.9 - flags & subtype */
			contact->flags = atoi( rec->fields[6]->data );
			contact->subtype = rec->fields[7]->data[0];
		}
		if ( rec->fcount > 8 ) {
			/* added in protocol 6.0 - reject message */
			contact->msg = g_strdup( rec->fields[8]->data );
		}

		/* add the contact to the buddy list */
		if ( contact-> type == MXIT_TYPE_MULTIMX )			/* contact is a MultiMX room */
			multimx_created( session, contact );
		else
			mxit_update_contact( session, contact );
	}

	if ( !( session->flags & MXIT_FLAG_FIRSTROSTER ) ) {
		session->flags |= MXIT_FLAG_FIRSTROSTER;
		mxit_update_blist( session );
	}
}


/*------------------------------------------------------------------------
 * Process a received presence update packet.
 *
 *  @param session		The MXit session object
 *  @param records		The packet's data records
 *  @param rcount		The number of data records
 */
static void mxit_parse_cmd_presence( struct MXitSession* session, struct record** records, int rcount )
{
	int					i;

	purple_debug_info( MXIT_PLUGIN_ID, "mxit_parse_cmd_presence (%i recs)\n", rcount );

	for ( i = 0; i < rcount; i++ ) {
		struct record*	rec		= records[i];
		int				flags	= 0;

		if ( rec->fcount < 6 ) {
			purple_debug_error( MXIT_PLUGIN_ID, "BAD PRESENCE RECORD! %i fields\n", rec->fcount );
			break;
		}

		/*
		 * The format of the record is:
		 * contactAddressN \1 presenceN \1 moodN \1 customMoodN \1 statusMsgN \1 avatarIdN [ \1 flagsN ]
		 */
		mxit_strip_domain( rec->fields[0]->data );		/* contactAddress */

		if ( rec->fcount >= 7 )		/* flags field is included */
			flags = atoi( rec->fields[6]->data );

		mxit_update_buddy_presence( session, rec->fields[0]->data, mxit_parse_presence( rec->fields[1]->data ), atoi( rec->fields[2]->data ),
				rec->fields[3]->data, rec->fields[4]->data, flags );
		mxit_update_buddy_avatar( session, rec->fields[0]->data, rec->fields[5]->data );
	}
}


/*------------------------------------------------------------------------
 * Process a received extended profile packet.
 *
 *  @param session		The MXit session object
 *  @param records		The packet's data records
 *  @param rcount		The number of data records
 */
static void mxit_parse_cmd_extprofile( struct MXitSession* session, struct record** records, int rcount )
{
	const char*				mxitId		= records[0]->fields[0]->data;
	struct MXitProfile*		profile		= NULL;
	int						count;
	int						i;
	const char*				avatarId	= NULL;
	char*					statusMsg	= NULL;

	purple_debug_info( MXIT_PLUGIN_ID, "mxit_parse_cmd_extprofile: profile for '%s'\n", mxitId );

	if ( ( records[0]->fields[0]->len == 0 ) || ( session->uid && ( strcmp( session->uid, records[0]->fields[0]->data ) == 0 ) ) ) {
		/* No UserId or Our UserId provided, so this must be our own profile information */
		if ( session->profile == NULL )
			session->profile = g_new0( struct MXitProfile, 1 );
		profile = session->profile;
	}
	else {
		/* is a buddy's profile */
		profile = g_new0( struct MXitProfile, 1 );
	}

	/* set the count for attributes */
	count = atoi( records[0]->fields[1]->data );

	for ( i = 0; i < count; i++ ) {
		char* fname;
		char* fvalue;
		char* fstatus;
		int f = ( i * 3 ) + 2;

		fname = records[0]->fields[f]->data;		/* field name */
		fvalue = records[0]->fields[f + 1]->data;	/* field value */
		fstatus = records[0]->fields[f + 2]->data;	/* field status */

		/* first check the status on the returned attribute */
		if ( fstatus[0] != '0' ) {
			/* error: attribute requested was NOT found */
			purple_debug_error( MXIT_PLUGIN_ID, "Bad profile status on attribute '%s' \n", fname );
			continue;
		}

		if ( strcmp( CP_PROFILE_BIRTHDATE, fname ) == 0 ) {
			/* birthdate */
			if ( records[0]->fields[f + 1]->len > 10 ) {
				fvalue[10] = '\0';
				records[0]->fields[f + 1]->len = 10;
			}
			memcpy( profile->birthday, fvalue, records[0]->fields[f + 1]->len );
		}
		else if ( strcmp( CP_PROFILE_GENDER, fname ) == 0 ) {
			/* gender */
			profile->male = ( fvalue[0] == '1' );
		}
		else if ( strcmp( CP_PROFILE_FULLNAME, fname ) == 0 ) {
			/* nickname */
			g_strlcpy( profile->nickname, fvalue, sizeof( profile->nickname ) );
		}
		else if ( strcmp( CP_PROFILE_STATUS, fname ) == 0 ) {
			/* status message - just keep a reference to the value */
			statusMsg = g_markup_escape_text( fvalue, -1 );
		}
		else if ( strcmp( CP_PROFILE_AVATAR, fname ) == 0 ) {
			/* avatar id - just keep a reference to the value */
			avatarId = fvalue;
		}
		else if ( strcmp( CP_PROFILE_TITLE, fname ) == 0 ) {
			/* title */
			g_strlcpy( profile->title, fvalue, sizeof( profile->title ) );
		}
		else if ( strcmp( CP_PROFILE_FIRSTNAME, fname ) == 0 ) {
			/* first name */
			g_strlcpy( profile->firstname, fvalue, sizeof( profile->firstname ) );
		}
		else if ( strcmp( CP_PROFILE_LASTNAME, fname ) == 0 ) {
			/* last name */
			g_strlcpy( profile->lastname, fvalue, sizeof( profile->lastname ) );
		}
		else if ( strcmp( CP_PROFILE_EMAIL, fname ) == 0 ) {
			/* email address */
			g_strlcpy( profile->email, fvalue, sizeof( profile->email ) );
		}
		else if ( strcmp( CP_PROFILE_MOBILENR, fname ) == 0 ) {
			/* mobile number */
			g_strlcpy( profile->mobilenr, fvalue, sizeof( profile->mobilenr ) );
		}
		else if ( strcmp( CP_PROFILE_REGCOUNTRY, fname ) == 0 ) {
			/* registered country */
			g_strlcpy( profile->regcountry, fvalue, sizeof( profile->regcountry ) );
		}
		else if ( strcmp( CP_PROFILE_FLAGS, fname ) == 0 ) {
			/* profile flags */
			profile->flags = g_ascii_strtoll( fvalue, NULL, 10 );
		}
		else if ( strcmp( CP_PROFILE_LASTSEEN, fname ) == 0 ) {
			/* last seen online */
			profile->lastonline = g_ascii_strtoll( fvalue, NULL, 10 );
		}
		else if ( strcmp( CP_PROFILE_WHEREAMI, fname ) == 0 ) {
			/* where am I */
			g_strlcpy( profile->whereami, fvalue, sizeof( profile->whereami ) );
		}
		else if ( strcmp( CP_PROFILE_ABOUTME, fname ) == 0) {
			/* about me */
			g_strlcpy( profile->aboutme, fvalue, sizeof( profile->aboutme ) );
		}
		else if ( strcmp( CP_PROFILE_RELATIONSHIP, fname ) == 0) {
			/* relatinship status */
			profile->relationship = strtol( fvalue, NULL, 10 );
		}
		else {
			/* invalid profile attribute */
			purple_debug_error( MXIT_PLUGIN_ID, "Invalid profile attribute received '%s' \n", fname );
		}
	}

	if ( profile != session->profile ) {
		/* not our own profile */
		struct contact*		contact		= NULL;

		contact = get_mxit_invite_contact( session, mxitId );
		if ( contact ) {
			/* this is an invite, so update its profile info */
			if ( ( statusMsg ) && ( strlen( statusMsg ) > 0 ) ) {
				/* update the status message */
				if ( contact->statusMsg )
					g_free( contact->statusMsg );
				contact->statusMsg = strdup( statusMsg );
			}
			else
				contact->statusMsg = NULL;
			if ( contact->profile )
				g_free( contact->profile );
			contact->profile = profile;
			if ( ( avatarId ) && ( strlen( avatarId ) > 0 ) ) {
				/* avatar must be requested for this invite before we can display it */
				mxit_get_avatar( session, mxitId, avatarId );
				if ( contact->avatarId )
					g_free( contact->avatarId );
				contact->avatarId = strdup( avatarId );
			}
			else {
				/* display what we have */
				contact->avatarId = NULL;
				mxit_show_profile( session, mxitId, profile );
			}
		}
		else {
			/* this is a contact */
			if ( avatarId )
				mxit_update_buddy_avatar( session, mxitId, avatarId );

			if ( ( statusMsg ) && ( strlen( statusMsg ) > 0 ) ) {
				/* update the status message */
				PurpleBuddy*		buddy	= NULL;

				buddy = purple_find_buddy( session->acc, mxitId );
				if ( buddy ) {
					contact = purple_buddy_get_protocol_data( buddy );
					if ( contact ) {
						if ( contact->statusMsg )
							g_free( contact->statusMsg );
						contact->statusMsg = strdup( statusMsg );
					}
				}
			}

			/* show the profile */
			mxit_show_profile( session, mxitId, profile );
			g_free( profile );
		}
	}

	g_free( statusMsg );
}


/*------------------------------------------------------------------------
 * Process a received suggest-contacts packet.
 *
 *  @param session		The MXit session object
 *  @param records		The packet's data records
 *  @param rcount		The number of data records
 */
static void mxit_parse_cmd_suggestcontacts( struct MXitSession* session, struct record** records, int rcount )
{
	GList* entries = NULL;
	int searchType;
	int maxResults;
	int count;
	int i;

	/*
	 * searchType \1 numSuggestions \1 total \1 numAttributes \1 name0 \1 name1 \1 ... \1 nameN \0
	 * userid \1 contactType \1 value0 \1 value1 ... valueN \0
	 * ...
	 * userid \1 contactType \1 value0 \1 value1 ... valueN
	 */

	/* the type of results */
	searchType = atoi( records[0]->fields[0]->data );

	/* the maximum number of results */
	maxResults = atoi( records[0]->fields[2]->data );

	/* set the count for attributes */
	count = atoi( records[0]->fields[3]->data );

	for ( i = 1; i < rcount; i ++ ) {
		struct record*		rec		= records[i];
		struct MXitProfile*	profile	= g_new0( struct MXitProfile, 1 );
		int j;

		g_strlcpy( profile->userid, rec->fields[0]->data, sizeof( profile->userid ) );
		// TODO: ContactType - User or Service

		for ( j = 0; j < count; j++ ) {
			char* fname;
			char* fvalue = "";

			fname = records[0]->fields[4 + j]->data;		/* field name */
			if ( records[i]->fcount > ( 2 + j ) )
				fvalue = records[i]->fields[2 + j]->data;	/* field value */

			purple_debug_info( MXIT_PLUGIN_ID, " %s: field='%s' value='%s'\n", profile->userid, fname, fvalue );

			if ( strcmp( CP_PROFILE_BIRTHDATE, fname ) == 0 ) {
				/* birthdate */
				g_strlcpy( profile->birthday, fvalue, sizeof( profile->birthday ) );
			}
			else if ( strcmp( CP_PROFILE_FIRSTNAME, fname ) == 0 ) {
				/* first name */
				g_strlcpy( profile->firstname, fvalue, sizeof( profile->firstname ) );
			}
			else if ( strcmp( CP_PROFILE_LASTNAME, fname ) == 0 ) {
				/* last name */
				g_strlcpy( profile->lastname, fvalue, sizeof( profile->lastname ) );
			}
			else if ( strcmp( CP_PROFILE_GENDER, fname ) == 0 ) {
				/* gender */
				profile->male = ( fvalue[0] == '1' );
			}
			else if ( strcmp( CP_PROFILE_FULLNAME, fname ) == 0 ) {
				/* nickname */
				g_strlcpy( profile->nickname, fvalue, sizeof( profile->nickname ) );
			}
			else if ( strcmp( CP_PROFILE_WHEREAMI, fname ) == 0 ) {
				/* where am I */
				g_strlcpy( profile->whereami, fvalue, sizeof( profile->whereami ) );
			}
			/* ignore other attibutes */
		}

		entries = g_list_append( entries, profile );
	}

	/* display */
	mxit_show_search_results( session, searchType, maxResults, entries );

	/* cleanup */
	g_list_foreach( entries, (GFunc)g_free, NULL );
}

/*------------------------------------------------------------------------
 * Process a received message event packet.
 *
 *  @param session		The MXit session object
 *  @param records		The packet's data records
 *  @param rcount		The number of data records
 */
static void mxit_parse_cmd_msgevent( struct MXitSession* session, struct record** records, int rcount )
{
	int event;

	/*
	 * contactAddress \1 dateTime \1 id \1 event
	 */

	/* strip off dummy domain */
	mxit_strip_domain( records[0]->fields[0]->data );

	event = atoi( records[0]->fields[3]->data );

	switch ( event ) {
		case CP_MSGEVENT_TYPING :							/* user is typing */
		case CP_MSGEVENT_ANGRY :							/* user is typing angrily */
			serv_got_typing( session->con, records[0]->fields[0]->data, 0, PURPLE_TYPING );
			break;

		case CP_MSGEVENT_STOPPED :							/* user has stopped typing */
			serv_got_typing_stopped( session->con, records[0]->fields[0]->data );
			break;

		case CP_MSGEVENT_ERASING :							/* user is erasing text */
		case CP_MSGEVENT_DELIVERED :						/* message was delivered */
		case CP_MSGEVENT_DISPLAYED :						/* message was viewed */
			/* these are currently not supported by libPurple */
			break;

		default:
			purple_debug_error( MXIT_PLUGIN_ID, "Unknown message event received (%i)\n", event );
	}
}


/*------------------------------------------------------------------------
 * Return the length of a multimedia chunk
 *
 * @return		The actual chunk data length in bytes
 */
static int get_chunk_len( const char* chunkdata )
{
	int*	sizeptr;

	sizeptr = (int*) &chunkdata[1];		/* we skip the first byte (type field) */

	return ntohl( *sizeptr );
}


/*------------------------------------------------------------------------
 * Process a received multimedia packet.
 *
 *  @param session		The MXit session object
 *  @param records		The packet's data records
 *  @param rcount		The number of data records
 */
static void mxit_parse_cmd_media( struct MXitSession* session, struct record** records, int rcount )
{
	char	type;
	int		size;

	type = records[0]->fields[0]->data[0];
	size = get_chunk_len( records[0]->fields[0]->data );

	purple_debug_info( MXIT_PLUGIN_ID, "mxit_parse_cmd_media (%i records) (%i bytes)\n", rcount, size );

	/* supported chunked data types */
	switch ( type ) {
		case CP_CHUNK_CUSTOM :				/* custom resource */
			{
				struct cr_chunk chunk;

				/* decode the chunked data */
				memset( &chunk, 0, sizeof( struct cr_chunk ) );
				mxit_chunk_parse_cr( &records[0]->fields[0]->data[sizeof( char ) + sizeof( int )], records[0]->fields[0]->len, &chunk );

				purple_debug_info( MXIT_PLUGIN_ID, "chunk info id=%s handle=%s op=%i\n", chunk.id, chunk.handle, chunk.operation );

				/* this is a splash-screen operation */
				if ( strcmp( chunk.handle, HANDLE_SPLASH2 ) == 0 ) {
					if ( chunk.operation == CR_OP_UPDATE ) {		/* update the splash-screen */
						struct splash_chunk *splash = chunk.resources->data;			// TODO: Fix - assuming 1st resource is splash
						gboolean clickable = ( g_list_length( chunk.resources ) > 1 );	// TODO: Fix - if 2 resources, then is clickable

						if ( splash != NULL )
							splash_update( session, chunk.id, splash->data, splash->datalen, clickable );
					}
					else if ( chunk.operation == CR_OP_REMOVE )		/* remove the splash-screen */
						splash_remove( session );
				}

				/* cleanup custom resources */
				g_list_foreach( chunk.resources, (GFunc)g_free, NULL );

			}
			break;

		case CP_CHUNK_OFFER :				/* file offer */
			{
				struct offerfile_chunk chunk;

				/* decode the chunked data */
				memset( &chunk, 0, sizeof( struct offerfile_chunk ) );
				mxit_chunk_parse_offer( &records[0]->fields[0]->data[sizeof( char ) + sizeof( int )], records[0]->fields[0]->len, &chunk );

				/* process the offer */
				mxit_xfer_rx_offer( session, chunk.username, chunk.filename, chunk.filesize, chunk.fileid );
			}
			break;

		case CP_CHUNK_GET :					/* get file response */
			{
				struct getfile_chunk chunk;

				/* decode the chunked data */
				memset( &chunk, 0, sizeof( struct getfile_chunk ) );
				mxit_chunk_parse_get( &records[0]->fields[0]->data[sizeof( char ) + sizeof( int )], records[0]->fields[0]->len, &chunk );

				/* process the getfile */
				mxit_xfer_rx_file( session, chunk.fileid, chunk.data, chunk.length );
			}
			break;

		case CP_CHUNK_GET_AVATAR :			/* get avatars */
			{
				struct getavatar_chunk chunk;
				struct contact* contact = NULL;

				/* decode the chunked data */
				memset( &chunk, 0, sizeof( struct getavatar_chunk ) );
				mxit_chunk_parse_get_avatar( &records[0]->fields[0]->data[sizeof( char ) + sizeof( int )], records[0]->fields[0]->len, &chunk );

				/* update avatar image */
				if ( chunk.data ) {
					purple_debug_info( MXIT_PLUGIN_ID, "updating avatar for contact '%s'\n", chunk.mxitid );

					contact = get_mxit_invite_contact( session, chunk.mxitid );
					if ( contact ) {
						/* this is an invite (add image to the internal image store) */
						contact->imgid = purple_imgstore_add_with_id( g_memdup( chunk.data, chunk.length ), chunk.length, NULL );
						/* show the profile */
						mxit_show_profile( session, chunk.mxitid, contact->profile );
					}
					else {
						/* this is a contact's avatar, so update it */
						purple_buddy_icons_set_for_user( session->acc, chunk.mxitid, g_memdup( chunk.data, chunk.length ), chunk.length, chunk.avatarid );
					}
				}
			}
			break;

		case CP_CHUNK_SET_AVATAR :
			/* this is a reply packet to a set avatar request. no action is required */
			break;

		case CP_CHUNK_DIRECT_SND :
			/* this is a ack for a file send. */
			{
				struct sendfile_chunk chunk;

				memset( &chunk, 0, sizeof( struct sendfile_chunk ) );
				mxit_chunk_parse_sendfile( &records[0]->fields[0]->data[sizeof( char ) + sizeof( int )], records[0]->fields[0]->len, &chunk );

				purple_debug_info( MXIT_PLUGIN_ID, "file-send send to '%s' [status=%i message='%s']\n", chunk.username, chunk.status, chunk.statusmsg );

				if ( chunk.status != 0 )	/* not success */
					mxit_popup( PURPLE_NOTIFY_MSG_ERROR, _( "File Send Failed" ), chunk.statusmsg );
			}
			break;

		case CP_CHUNK_RECEIVED :
			/* this is a ack for a file received. no action is required */
			break;

		default :
			purple_debug_error( MXIT_PLUGIN_ID, "Unsupported chunked data packet type received (%i)\n", type );
			break;
	}
}


/*------------------------------------------------------------------------
 * Handle a redirect sent from the MXit server.
 *
 *  @param session		The MXit session object
 *  @param url			The redirect information
 */
static void mxit_perform_redirect( struct MXitSession* session, const char* url )
{
	gchar**		parts;
	gchar**		host;
	int			type;

	purple_debug_info( MXIT_PLUGIN_ID, "mxit_perform_redirect: %s\n", url );

	/* tokenize the URL string */
	parts = g_strsplit( url, ";", 0 );

	/* Part 1: protocol://host:port */
	host = g_strsplit( parts[0], ":", 4 );
	if ( strcmp( host[0], "socket" ) == 0 ) {
		/* redirect to a MXit socket proxy */
		g_strlcpy( session->server, &host[1][2], sizeof( session->server ) );
		session->port = atoi( host[2] );
	}
	else {
		purple_connection_error( session->con, _( "Cannot perform redirect using the specified protocol" ) );
		goto redirect_fail;
	}

	/* Part 2: type of redirect */
	type = atoi( parts[1] );
	if ( type == CP_REDIRECT_PERMANENT ) {
		/* permanent redirect, so save new MXit server and port */
		purple_account_set_string( session->acc, MXIT_CONFIG_SERVER_ADDR, session->server );
		purple_account_set_int( session->acc, MXIT_CONFIG_SERVER_PORT, session->port );
	}

	/* Part 3: message (optional) */
	if ( parts[2] != NULL )
		purple_connection_notice( session->con, parts[2] );

	purple_debug_info( MXIT_PLUGIN_ID, "mxit_perform_redirect: %s redirect to %s:%i\n",
			( type == CP_REDIRECT_PERMANENT ) ? "Permanent" : "Temporary", session->server, session->port );

	/* perform the re-connect to the new MXit server */
	mxit_reconnect( session );

redirect_fail:
	g_strfreev( parts );
	g_strfreev( host );
}


/*------------------------------------------------------------------------
 * Process a success response received from the MXit server.
 *
 *  @param session		The MXit session object
 *  @param packet		The received packet
 */
static int process_success_response( struct MXitSession* session, struct rx_packet* packet )
{
	/* ignore ping/poll packets */
	if ( ( packet->cmd != CP_CMD_PING ) && ( packet->cmd != CP_CMD_POLL ) )
		session->last_rx = mxit_now_milli();

	/*
	 * when we pass the packet records to the next level for parsing
	 * we minus 3 records because 1) the first record is the packet
	 * type 2) packet reply status 3) the last record is bogus
	 */

	/* packet command */
	switch ( packet->cmd ) {

		case CP_CMD_REGISTER :
				/* fall through, when registeration successful, MXit will auto login */
		case CP_CMD_LOGIN :
				/* login response */
				if ( !( session->flags & MXIT_FLAG_LOGGEDIN ) ) {
					mxit_parse_cmd_login( session, &packet->records[2], packet->rcount - 3 );
				}
				break;

		case CP_CMD_LOGOUT :
				/* logout response */
				session->flags &= ~MXIT_FLAG_LOGGEDIN;
				purple_account_disconnect( session->acc );

				/* note:
				 * we do not prompt the user here for a reconnect, because this could be the user
				 * logging in with his phone. so we just disconnect the account otherwise
				 * mxit will start to bounce between the phone and pidgin. also could be a valid
				 * disconnect selected by the user.
				 */
				return -1;

		case CP_CMD_CONTACT :
				/* contact update */
				mxit_parse_cmd_contact( session, &packet->records[2], packet->rcount - 3 );
				break;

		case CP_CMD_PRESENCE :
				/* presence update */
				mxit_parse_cmd_presence( session, &packet->records[2], packet->rcount - 3 );
				break;

		case CP_CMD_RX_MSG :
				/* incoming message (no bogus record) */
				mxit_parse_cmd_message( session, &packet->records[2], packet->rcount - 2 );
				break;

		case CP_CMD_NEW_SUB :
				/* new subscription request */
				mxit_parse_cmd_new_sub( session, &packet->records[2], packet->rcount - 3 );
				break;

		case CP_CMD_MEDIA :
				/* multi-media message */
				mxit_parse_cmd_media( session, &packet->records[2], packet->rcount - 2 );
				break;

		case CP_CMD_EXTPROFILE_GET :
				/* profile update */
				mxit_parse_cmd_extprofile( session, &packet->records[2], packet->rcount - 2 );
				break;

		case CP_CMD_SUGGESTCONTACTS :
				/* suggest contacts */
				mxit_parse_cmd_suggestcontacts( session, &packet->records[2], packet->rcount - 2 );
				break;

		case CP_CMD_GOT_MSGEVENT :
				/* received message event */
				mxit_parse_cmd_msgevent( session, &packet->records[2], packet->rcount - 2 );
				break;

		case CP_CMD_MOOD :
				/* mood update */
		case CP_CMD_UPDATE :
				/* update contact information */
		case CP_CMD_ALLOW :
				/* allow subscription ack */
		case CP_CMD_DENY :
				/* deny subscription ack */
		case CP_CMD_INVITE :
				/* invite contact ack */
		case CP_CMD_REMOVE :
				/* remove contact ack */
		case CP_CMD_TX_MSG :
				/* outgoing message ack */
		case CP_CMD_STATUS :
				/* presence update ack */
		case CP_CMD_GRPCHAT_CREATE :
				/* create groupchat */
		case CP_CMD_GRPCHAT_INVITE :
				/* groupchat invite */
		case CP_CMD_PING :
				/* ping reply */
		case CP_CMD_POLL :
				/* HTTP poll reply */
		case CP_CMD_EXTPROFILE_SET :
				/* profile update */
				// TODO: Protocol 6.2 indicates status for each attribute, and current value.
		case CP_CMD_SPLASHCLICK :
				/* splash-screen clickthrough */
		case CP_CMD_MSGEVENT :
				/* event message */
				break;

		default :
			/* unknown packet */
			purple_debug_error( MXIT_PLUGIN_ID, "Received unknown client packet (cmd = %i)\n", packet->cmd );
	}

	return 0;
}


/*------------------------------------------------------------------------
 * Process an error response received from the MXit server.
 *
 *  @param session		The MXit session object
 *  @param packet		The received packet
 */
static int process_error_response( struct MXitSession* session, struct rx_packet* packet )
{
	char			errmsg[256];
	const char*		errdesc;

	/* set the error description to be shown to the user */
	if ( packet->errmsg )
		errdesc = packet->errmsg;
	else
		errdesc = _( "An internal MXit server error occurred." );

	purple_debug_info( MXIT_PLUGIN_ID, "Error Reply %i:%s\n", packet->errcode, errdesc );

	if ( packet->errcode == MXIT_ERRCODE_LOGGEDOUT ) {
		/* we are not currently logged in, so we need to reconnect */
		purple_connection_error( session->con, _( errdesc ) );
	}

	/* packet command */
	switch ( packet->cmd ) {

		case CP_CMD_REGISTER :
		case CP_CMD_LOGIN :
				if ( packet->errcode == MXIT_ERRCODE_REDIRECT ) {
					mxit_perform_redirect( session, packet->errmsg );
					return 0;
				}
				else {
					g_snprintf( errmsg, sizeof( errmsg ), _( "Login error: %s (%i)" ), errdesc, packet->errcode );
					purple_connection_error( session->con, errmsg );
					return -1;
				}
		case CP_CMD_LOGOUT :
				g_snprintf( errmsg, sizeof( errmsg ), _( "Logout error: %s (%i)" ), errdesc, packet->errcode );
				purple_connection_error_reason( session->con, PURPLE_CONNECTION_ERROR_NAME_IN_USE, _( errmsg ) );
				return -1;
		case CP_CMD_CONTACT :
				mxit_popup( PURPLE_NOTIFY_MSG_WARNING, _( "Contact Error" ), _( errdesc ) );
				break;
		case CP_CMD_RX_MSG :
				mxit_popup( PURPLE_NOTIFY_MSG_WARNING, _( "Message Error" ), _( errdesc ) );
				break;
		case CP_CMD_TX_MSG :
				mxit_popup( PURPLE_NOTIFY_MSG_WARNING, _( "Message Sending Error" ), _( errdesc ) );
				break;
		case CP_CMD_STATUS :
				mxit_popup( PURPLE_NOTIFY_MSG_WARNING, _( "Status Error" ), _( errdesc ) );
				break;
		case CP_CMD_MOOD :
				mxit_popup( PURPLE_NOTIFY_MSG_WARNING, _( "Mood Error" ), _( errdesc ) );
				break;
		case CP_CMD_KICK :
				/*
				 * the MXit server sends this packet if we were idle for too long.
				 * to stop the server from closing this connection we need to resend
				 * the login packet.
				 */
				mxit_send_login( session );
				break;
		case CP_CMD_INVITE :
				mxit_popup( PURPLE_NOTIFY_MSG_WARNING, _( "Invitation Error" ), _( errdesc ) );
				break;
		case CP_CMD_REMOVE :
				mxit_popup( PURPLE_NOTIFY_MSG_WARNING, _( "Contact Removal Error" ), _( errdesc ) );
				break;
		case CP_CMD_ALLOW :
		case CP_CMD_DENY :
				mxit_popup( PURPLE_NOTIFY_MSG_WARNING, _( "Subscription Error" ), _( errdesc ) );
				break;
		case CP_CMD_UPDATE :
				mxit_popup( PURPLE_NOTIFY_MSG_WARNING, _( "Contact Update Error" ), _( errdesc ) );
				break;
		case CP_CMD_MEDIA :
				mxit_popup( PURPLE_NOTIFY_MSG_WARNING, _( "File Transfer Error" ), _( errdesc ) );
				break;
		case CP_CMD_GRPCHAT_CREATE :
				mxit_popup( PURPLE_NOTIFY_MSG_WARNING, _( "Cannot create MultiMx room" ), _( errdesc ) );
				break;
		case CP_CMD_GRPCHAT_INVITE :
				mxit_popup( PURPLE_NOTIFY_MSG_WARNING, _( "MultiMx Invitation Error" ), _( errdesc ) );
				break;
		case CP_CMD_EXTPROFILE_GET :
		case CP_CMD_EXTPROFILE_SET :
				mxit_popup( PURPLE_NOTIFY_MSG_WARNING, _( "Profile Error" ), _( errdesc ) );
				break;
		case CP_CMD_SPLASHCLICK :
		case CP_CMD_MSGEVENT :
				/* ignore error */
				break;
		case CP_CMD_PING :
		case CP_CMD_POLL :
				break;
		default :
				mxit_popup( PURPLE_NOTIFY_MSG_ERROR, _( "Error" ), _( errdesc ) );
				break;
	}

	return 0;
}


/*========================================================================================================================
 * Low-level Packet receive
 */

#ifdef	DEBUG_PROTOCOL
/*------------------------------------------------------------------------
 * Dump a received packet structure.
 *
 *  @param p			The received packet
 */
static void dump_packet( struct rx_packet* p )
{
	struct record*		r	= NULL;
	struct field*		f	= NULL;
	int					i;
	int					j;

	purple_debug_info( MXIT_PLUGIN_ID, "PACKET DUMP: (%i records)\n", p->rcount );

	for ( i = 0; i < p->rcount; i++ ) {
		r = p->records[i];
		purple_debug_info( MXIT_PLUGIN_ID, "RECORD: (%i fields)\n", r->fcount );

		for ( j = 0; j < r->fcount; j++ ) {
			f = r->fields[j];
			purple_debug_info( MXIT_PLUGIN_ID, "\tFIELD: (len=%i) '%s' \n", f->len, f->data );
		}
	}
}
#endif


/*------------------------------------------------------------------------
 * Free up memory used by a packet structure.
 *
 *  @param p			The received packet
 */
static void free_rx_packet( struct rx_packet* p )
{
	struct record*		r	= NULL;
	struct field*		f	= NULL;
	int					i;
	int					j;

	for ( i = 0; i < p->rcount; i++ ) {
		r = p->records[i];

		for ( j = 0; j < r->fcount; j++ ) {
			g_free( f );
		}
		g_free( r->fields );
		g_free( r );
	}
	g_free( p->records );
}


/*------------------------------------------------------------------------
 * Add a new field to a record.
 *
 *  @param r			Parent record object
 *  @return				The newly created field
 */
static struct field* add_field( struct record* r )
{
	struct field*	field;

	field = g_new0( struct field, 1 );

	r->fields = g_realloc( r->fields, sizeof( struct field* ) * ( r->fcount + 1 ) );
	r->fields[r->fcount] = field;
	r->fcount++;

	return field;
}


/*------------------------------------------------------------------------
 * Add a new record to a packet.
 *
 *  @param p			The packet object
 *  @return				The newly created record
 */
static struct record* add_record( struct rx_packet* p )
{
	struct record*	rec;

	rec = g_new0( struct record, 1 );

	p->records = g_realloc( p->records, sizeof( struct record* ) * ( p->rcount + 1 ) );
	p->records[p->rcount] = rec;
	p->rcount++;

	return rec;
}


/*------------------------------------------------------------------------
 * Parse the received byte stream into a proper client protocol packet.
 *
 *  @param session		The MXit session object
 *  @return				Success (0) or Failure (!0)
 */
int mxit_parse_packet( struct MXitSession* session )
{
	struct rx_packet	packet;
	struct record*		rec;
	struct field*		field;
	gboolean			pbreak;
	unsigned int		i;
	int					res	= 0;

#ifdef	DEBUG_PROTOCOL
	purple_debug_info( MXIT_PLUGIN_ID, "Received packet (%i bytes)\n", session->rx_i );
	dump_bytes( session, session->rx_dbuf, session->rx_i );
#endif

	i = 0;
	while ( i < session->rx_i ) {

		/* create first record and field */
		rec = NULL;
		field = NULL;
		memset( &packet, 0x00, sizeof( struct rx_packet ) );
		rec = add_record( &packet );
		pbreak = FALSE;

		/* break up the received packet into fields and records for easy parsing */
		while ( ( i < session->rx_i ) && ( !pbreak ) ) {

			switch ( session->rx_dbuf[i] ) {
				case CP_SOCK_REC_TERM :
						/* new record */
						if ( packet.rcount == 1 ) {
							/* packet command */
							packet.cmd = atoi( packet.records[0]->fields[0]->data );
						}
						else if ( packet.rcount == 2 ) {
							/* special case: binary multimedia packets should not be parsed here */
							if ( packet.cmd == CP_CMD_MEDIA ) {
								/* add the chunked to new record */
								rec = add_record( &packet );
								field = add_field( rec );
								field->data = &session->rx_dbuf[i + 1];
								field->len = session->rx_i - i;
								/* now skip the binary data */
								res = get_chunk_len( field->data );
								/* determine if we have more packets */
								if ( res + 6 + i < session->rx_i ) {
									/* we have more than one packet in this stream */
									i += res + 6;
									pbreak = TRUE;
								}
								else {
									i = session->rx_i;
								}
							}
						}
						else if ( !field ) {
							field = add_field( rec );
							field->data = &session->rx_dbuf[i];
						}
						session->rx_dbuf[i] = '\0';
						rec = add_record( &packet );
						field = NULL;

						break;
				case CP_FLD_TERM :
						/* new field */
						session->rx_dbuf[i] = '\0';
						if ( !field ) {
							field = add_field( rec );
							field->data = &session->rx_dbuf[i];
						}
						field = NULL;
						break;
				case CP_PKT_TERM :
						/* packet is done! */
						session->rx_dbuf[i] = '\0';
						pbreak = TRUE;
						break;
				default :
						/* skip non special characters */
						if ( !field ) {
							field = add_field( rec );
							field->data = &session->rx_dbuf[i];
						}
						field->len++;
						break;
			}

			i++;
		}

		if ( packet.rcount < 2 ) {
			/* bad packet */
			purple_connection_error( session->con, _( "Invalid packet received from MXit." ) );
			free_rx_packet( &packet );
			continue;
		}

		session->rx_dbuf[session->rx_i] = '\0';
		packet.errcode = atoi( packet.records[1]->fields[0]->data );

		purple_debug_info( MXIT_PLUGIN_ID, "Packet received CMD:%i (%i)\n", packet.cmd, packet.errcode );
#ifdef	DEBUG_PROTOCOL
		/* debug */
		dump_packet( &packet );
#endif

		/* reset the out ack */
		if ( session->outack == packet.cmd ) {
			/* outstanding ack received from mxit server */
			session->outack = 0;
		}

		/* check packet status */
		if ( packet.errcode != MXIT_ERRCODE_SUCCESS ) {
			/* error reply! */
			if ( ( packet.records[1]->fcount > 1 ) && ( packet.records[1]->fields[1]->data ) )
				packet.errmsg = packet.records[1]->fields[1]->data;
			else
				packet.errmsg = NULL;

			res = process_error_response( session, &packet );
		}
		else {
			/* success reply! */
			res = process_success_response( session, &packet );
		}

		/* free up the packet resources */
		free_rx_packet( &packet );
	}

	if ( session->outack == 0 )
			mxit_manage_queue( session );

	return res;
}


/*------------------------------------------------------------------------
 * Callback when data is received from the MXit server.
 *
 *  @param user_data		The MXit session object
 *  @param source			The file-descriptor on which data was received
 *  @param cond				Condition which caused the callback (PURPLE_INPUT_READ)
 */
void mxit_cb_rx( gpointer user_data, gint source, PurpleInputCondition cond )
{
	struct MXitSession*	session		= (struct MXitSession*) user_data;
	char				ch;
	int					res;
	int					len;

	if ( session->rx_state == RX_STATE_RLEN ) {
		/* we are reading in the packet length */
		len = read( session->fd, &ch, 1 );
		if ( len < 0 ) {
			/* connection error */
			purple_connection_error( session->con, _( "A connection error occurred to MXit. (read stage 0x01)" ) );
			return;
		}
		else if ( len == 0 ) {
			/* connection closed */
			purple_connection_error( session->con, _( "A connection error occurred to MXit. (read stage 0x02)" ) );
			return;
		}
		else {
			/* byte read */
			if ( ch == CP_REC_TERM ) {
				/* the end of the length record found */
				session->rx_lbuf[session->rx_i] = '\0';
				session->rx_res = atoi( &session->rx_lbuf[3] );
				if ( session->rx_res > CP_MAX_PACKET ) {
					purple_connection_error( session->con, _( "A connection error occurred to MXit. (read stage 0x03)" ) );
				}
				session->rx_state = RX_STATE_DATA;
				session->rx_i = 0;
			}
			else {
				/* still part of the packet length record */
				session->rx_lbuf[session->rx_i] = ch;
				session->rx_i++;
				if ( session->rx_i >= sizeof( session->rx_lbuf ) ) {
					/* malformed packet length record (too long) */
					purple_connection_error( session->con, _( "A connection error occurred to MXit. (read stage 0x04)" ) );
					return;
				}
			}
		}
	}
	else if ( session->rx_state == RX_STATE_DATA ) {
		/* we are reading in the packet data */
		len = read( session->fd, &session->rx_dbuf[session->rx_i], session->rx_res );
		if ( len < 0 ) {
			/* connection error */
			purple_connection_error( session->con, _( "A connection error occurred to MXit. (read stage 0x05)" ) );
			return;
		}
		else if ( len == 0 ) {
			/* connection closed */
			purple_connection_error( session->con, _( "A connection error occurred to MXit. (read stage 0x06)" ) );
			return;
		}
		else {
			/* data read */
			session->rx_i += len;
			session->rx_res -= len;

			if ( session->rx_res == 0 ) {
				/* ok, so now we have read in the whole packet */
				session->rx_state = RX_STATE_PROC;
			}
		}
	}

	if ( session->rx_state == RX_STATE_PROC ) {
		/* we have a full packet, which we now need to process */
		res = mxit_parse_packet( session );

		if ( res == 0 ) {
			/* we are still logged in */
			session->rx_state = RX_STATE_RLEN;
			session->rx_res = 0;
			session->rx_i = 0;
		}
	}
}


/*------------------------------------------------------------------------
 * Log the user off MXit and close the connection
 *
 *  @param session		The MXit session object
 */
void mxit_close_connection( struct MXitSession* session )
{
	purple_debug_info( MXIT_PLUGIN_ID, "mxit_close_connection\n" );

	if ( !( session->flags & MXIT_FLAG_CONNECTED ) ) {
		/* we are already closed */
		return;
	}
	else if ( session->flags & MXIT_FLAG_LOGGEDIN ) {
		/* we are currently logged in so we need to send a logout packet */
		if ( !session->http ) {
			mxit_send_logout( session );
		}
		session->flags &= ~MXIT_FLAG_LOGGEDIN;
	}
	session->flags &= ~MXIT_FLAG_CONNECTED;

	/* cancel all outstanding async calls */
	while ( session->async_calls ) {
		purple_util_fetch_url_cancel( session->async_calls->data );
		session->async_calls = g_slist_delete_link( session->async_calls, session->async_calls );
	}

	/* remove the input cb function */
	if ( session->con->inpa ) {
		purple_input_remove( session->con->inpa );
		session->con->inpa = 0;
	}

	/* remove HTTP poll timer */
	if ( session->http_timer_id > 0 )
		purple_timeout_remove( session->http_timer_id );

	/* remove slow queue manager timer */
	if ( session->q_slow_timer_id > 0 )
		purple_timeout_remove( session->q_slow_timer_id );

	/* remove fast queue manager timer */
	if ( session->q_fast_timer_id > 0 )
		purple_timeout_remove( session->q_fast_timer_id );

	/* remove all groupchat rooms */
	while ( session->rooms != NULL ) {
		struct multimx* multimx = (struct multimx *) session->rooms->data;

		session->rooms = g_list_remove( session->rooms, multimx );

		free( multimx );
	}
	g_list_free( session->rooms );
	session->rooms = NULL;

	/* remove all rx chats names */
	while ( session->active_chats != NULL ) {
		char* chat = (char*) session->active_chats->data;

		session->active_chats = g_list_remove( session->active_chats, chat );

		g_free( chat );
	}
	g_list_free( session->active_chats );
	session->active_chats = NULL;

	/* clear the internal invites */
	while ( session->invites != NULL ) {
		struct contact* contact = (struct contact*) session->invites->data;

		session->invites = g_list_remove( session->invites, contact );

		if ( contact->msg )
			g_free( contact->msg );
		if ( contact->statusMsg )
			g_free( contact->statusMsg );
		if ( contact->profile )
			g_free( contact->profile );
		g_free( contact );
	}
	g_list_free( session->invites );
	session->invites = NULL;

	/* free profile information */
	if ( session->profile )
		free( session->profile );

	/* free custom emoticons */
	mxit_free_emoticon_cache( session );

	/* free allocated memory */
	if ( session->uid )
		g_free( session->uid );
	g_free( session->encpwd );
	session->encpwd = NULL;

	/* flush all the commands still in the queue */
	flush_queue( session );
}

