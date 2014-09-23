/*
 *					MXit Protocol libPurple Plugin
 *
 *			-- file transfers (sending and receiving)  --
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

#include	"protocol.h"
#include	"mxit.h"
#include	"chunk.h"
#include	"filexfer.h"


#define		MIME_TYPE_OCTETSTREAM		"application/octet-stream"


/* supported file mime types */
static struct mime_type {
	const char*		magic;
	const short		magic_len;
	const char*		mime;
} const mime_types[] = {
					/*	magic									length	mime					*/
	/* images */	{	"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A",		8,		"image/png"				},		/* image png */
					{	"\xFF\xD8",								2,		"image/jpeg"			},		/* image jpeg */
					{	"\x3C\x3F\x78\x6D\x6C",					5,		"image/svg+xml"			},		/* image SVGansi */
					{	"\xEF\xBB\xBF",							3,		"image/svg+xml"			},		/* image SVGutf */
					{	"\xEF\xBB\xBF",							3,		"image/svg+xml"			},		/* image SVGZ */
	/* mxit */		{	"\x4d\x58\x4d",							3,		"application/mxit-msgs"	},		/* mxit message */
					{	"\x4d\x58\x44\x01",						4,		"application/mxit-mood" },		/* mxit mood */
					{	"\x4d\x58\x45\x01",						4,		"application/mxit-emo"	},		/* mxit emoticon */
					{	"\x4d\x58\x46\x01",						4,		"application/mxit-emof"	},		/* mxit emoticon frame */
					{	"\x4d\x58\x53\x01",						4,		"application/mxit-skin"	},		/* mxit skin */
	/* audio */		{	"\x4d\x54\x68\x64",						4,		"audio/midi"			},		/* audio midi */
					{	"\x52\x49\x46\x46",						4,		"audio/wav"				},		/* audio wav */
					{	"\xFF\xF1",								2,		"audio/aac"				},		/* audio aac1 */
					{	"\xFF\xF9",								2,		"audio/aac"				},		/* audio aac2 */
					{	"\xFF",									1,		"audio/mp3"				},		/* audio mp3 */
					{	"\x23\x21\x41\x4D\x52\x0A",				6,		"audio/amr"				},		/* audio AMR */
					{	"\x23\x21\x41\x4D\x52\x2D\x57\x42",		8,		"audio/amr-wb"			},		/* audio AMR WB */
					{	"\x00\x00\x00",							3,		"audio/mp4"				},		/* audio mp4 */
					{	"\x2E\x73\x6E\x64",						4,		"audio/au"				}		/* audio AU */
};


/*------------------------------------------------------------------------
 * Return the MIME type matching the data file.
 *
 *  @param filename		The name of file
 *  @param buf			The data
 *  @param buflen		The length of the data
 *  @return				A MIME type string
 */
const char* file_mime_type( const char* filename, const char* buf, int buflen )
{
	unsigned int	i;

	/* check for matching magic headers */
	for ( i = 0; i < ARRAY_SIZE( mime_types ); i++ ) {

		if ( buflen < mime_types[i].magic_len )	/* data is shorter than size of magic */
			continue;

		if ( memcmp( buf, mime_types[i].magic, mime_types[i].magic_len ) == 0 )
			return mime_types[i].mime;
	}

	/* we did not find the MIME type, so return the default (application/octet-stream) */
	return MIME_TYPE_OCTETSTREAM;
}


/*------------------------------------------------------------------------
 * Cleanup and deallocate a MXit file transfer object
 *
 *  @param xfer			The file transfer object
 */
static void mxit_xfer_free( PurpleXfer* xfer )
{
	struct mxitxfer*	mx		= (struct mxitxfer*) xfer->data;;

	if ( mx ) {
		g_free( mx );
		xfer->data = NULL;
	}
}


/*========================================================================================================================
 * File Transfer callbacks
 */

/*------------------------------------------------------------------------
 * Initialise a new file transfer.
 *
 *  @param xfer			The file transfer object
 */
static void mxit_xfer_init( PurpleXfer* xfer )
{
	struct mxitxfer*	mx	= (struct mxitxfer*) xfer->data;

	purple_debug_info( MXIT_PLUGIN_ID, "mxit_xfer_init\n" );

	if ( purple_xfer_get_type( xfer ) == PURPLE_XFER_SEND ) {
		/* we are trying to send a file to MXit */

		if ( purple_xfer_get_size( xfer ) > CP_MAX_FILESIZE ) {
			/* the file is too big */
			purple_xfer_error( purple_xfer_get_type( xfer ), purple_xfer_get_account( xfer ), purple_xfer_get_remote_user( xfer ), _( "The file you are trying to send is too large!" ) );
			purple_xfer_cancel_local( xfer );
			return;
		}

		/* start the file transfer */
		purple_xfer_start( xfer, -1, NULL, 0 );
	}
	else {
		/*
		 * we have just accepted a file transfer request from MXit.  send a confirmation
		 * to the MXit server so that can send us the file
		 */
		mxit_send_file_accept( mx->session, mx->fileid, purple_xfer_get_size( xfer ), 0 );
	}
}


/*------------------------------------------------------------------------
 * Start the file transfer.
 *
 *  @param xfer			The file transfer object
 */
static void mxit_xfer_start( PurpleXfer* xfer )
{
	goffset			filesize;
	unsigned char*	buffer;
	int				wrote;

	purple_debug_info( MXIT_PLUGIN_ID, "mxit_xfer_start\n" );

	if ( purple_xfer_get_type( xfer ) == PURPLE_XFER_SEND ) {
		/*
		 * the user wants to send a file to one of his contacts. we need to create
		 * a buffer and copy the file data into memory and then we can send it to
		 * the contact. we will send the whole file with one go.
		 */
		filesize = purple_xfer_get_bytes_remaining( xfer );
		buffer = g_malloc( filesize );

		if ( fread( buffer, filesize, 1, xfer->dest_fp ) > 0 ) {
			/* send data */
			wrote = purple_xfer_write( xfer, buffer, filesize );
			if ( wrote > 0 )
				purple_xfer_set_bytes_sent( xfer, wrote );
		}
		else {
			/* file read error */
			purple_xfer_error( purple_xfer_get_type( xfer ), purple_xfer_get_account( xfer ), purple_xfer_get_remote_user( xfer ), _( "Unable to access the local file" ) );
			purple_xfer_cancel_local( xfer );
		}

		/* free the buffer */
		g_free( buffer );
		buffer = NULL;
	}
}


/*------------------------------------------------------------------------
 * The file transfer has ended.
 *
 *  @param xfer			The file transfer object
 */
static void mxit_xfer_end( PurpleXfer* xfer )
{
	purple_debug_info( MXIT_PLUGIN_ID, "mxit_xfer_end\n" );

	/* deallocate object */
	mxit_xfer_free( xfer );
}


/*------------------------------------------------------------------------
 * The file transfer (to a user) has been cancelled.
 *
 *  @param xfer			The file transfer object
 */
static void mxit_xfer_cancel_send( PurpleXfer* xfer )
{
	purple_debug_info( MXIT_PLUGIN_ID, "mxit_xfer_cancel_send\n" );

	/* deallocate object */
	mxit_xfer_free( xfer );
}


/*------------------------------------------------------------------------
 * Send the file data.
 *
 *  @param buffer		The data to sent
 *  @param size			The length of the data to send
 *  @param xfer			The file transfer object
 *  @return				The amount of data actually sent
 */
static gssize mxit_xfer_write( const guchar* buffer, size_t size, PurpleXfer* xfer )
{
	struct mxitxfer*	mx	= (struct mxitxfer*) xfer->data;

	purple_debug_info( MXIT_PLUGIN_ID, "mxit_xfer_write\n" );

	if ( !mx ) {
		purple_debug_warning( MXIT_PLUGIN_ID, "mxit_xfer_write: invalid internal mxit xfer data\n" );
		return -1;
	}
	else if ( purple_xfer_get_type( xfer ) != PURPLE_XFER_SEND ) {
		purple_debug_warning( MXIT_PLUGIN_ID, "mxit_xfer_write: wrong xfer type received\n" );
		return -1;
	}

	/* create and send the packet to MXit */
	mxit_send_file( mx->session, purple_xfer_get_remote_user( xfer ), purple_xfer_get_filename( xfer ), buffer, size );

	/* the transfer is complete */
	purple_xfer_set_completed( xfer, TRUE );

	return size;
}


/*------------------------------------------------------------------------
 * The user has rejected a file offer from MXit.
 *
 *  @param xfer			The file transfer object
 */
static void mxit_xfer_request_denied( PurpleXfer* xfer )
{
	struct mxitxfer*	mx		= (struct mxitxfer*) xfer->data;

	purple_debug_info( MXIT_PLUGIN_ID, "mxit_xfer_request_denied\n" );

	/* send file reject packet to MXit server */
	mxit_send_file_reject( mx->session, mx->fileid );

	/* deallocate object */
	mxit_xfer_free( xfer );
}


/*------------------------------------------------------------------------
 * The file transfer (from MXit) has been cancelled.
 */
static void mxit_xfer_cancel_recv( PurpleXfer* xfer )
{
	purple_debug_info( MXIT_PLUGIN_ID, "mxit_xfer_cancel_recv\n" );

	/* deallocate object */
	mxit_xfer_free( xfer );
}


/*========================================================================================================================
 * Callbacks from libPurple
 */

/*------------------------------------------------------------------------
 * Indicate if file transfers are supported to this contact.
 * For MXit file transfers are always supported.
 *
 *  @param gc			The connection object
 *  @param who			The username of the contact
 *  @return				TRUE if file transfers are supported
 */
gboolean mxit_xfer_enabled( PurpleConnection* gc, const char* who )
{
	return TRUE;
}


/*------------------------------------------------------------------------
 * Create and initialize a new file transfer to a contact.
 *
 *  @param gc			The connection object
 *  @param who			The username of the recipient
 */
PurpleXfer* mxit_xfer_new( PurpleConnection* gc, const char* who )
{
	struct MXitSession*	session	= purple_connection_get_protocol_data( gc );
	PurpleXfer*			xfer	= NULL;
	struct mxitxfer*	mx		= NULL;

	/* (reference: "libpurple/ft.h") */
	xfer = purple_xfer_new( session->acc, PURPLE_XFER_SEND, who );

	/* create file info and attach it to the file transfer */
	mx = g_new0( struct mxitxfer, 1 );
	mx->session = session;
	xfer->data = mx;

	/* configure callbacks (reference: "libpurple/ft.h") */
	purple_xfer_set_init_fnc( xfer, mxit_xfer_init );
	purple_xfer_set_start_fnc( xfer, mxit_xfer_start );
	purple_xfer_set_end_fnc( xfer, mxit_xfer_end );
	purple_xfer_set_cancel_send_fnc( xfer, mxit_xfer_cancel_send );
	purple_xfer_set_write_fnc( xfer, mxit_xfer_write );

	return xfer;
}


/*------------------------------------------------------------------------
 * The user has initiated a file transfer to a contact.
 *
 *  @param gc			The connection object
 *  @param who			The username of the contact
 *  @param filename		The filename (is NULL if request has not been accepted yet)
 */
void mxit_xfer_tx( PurpleConnection* gc, const char* who, const char* filename )
{
	PurpleXfer	*xfer	= mxit_xfer_new( gc, who );

	if ( filename )
		purple_xfer_request_accepted( xfer, filename );
	else
		purple_xfer_request( xfer );
}


/*========================================================================================================================
 * Calls from the MXit Protocol layer
 */

/*------------------------------------------------------------------------
 * A file transfer offer has been received from the MXit server.
 *
 *  @param session		The MXit session object
 *  @param usermame		The username of the sender
 *  @param filename		The name of the file being offered
 *  @param filesize		The size of the file being offered
 *  @param fileid		A unique ID that identifies this file
 */
void mxit_xfer_rx_offer( struct MXitSession* session, const char* username, const char* filename, int filesize, const char* fileid )
{
	PurpleXfer*			xfer	= NULL;
	struct mxitxfer*	mx		= NULL;

	purple_debug_info( MXIT_PLUGIN_ID, "File Offer: file=%s, from=%s, size=%i\n", filename, username, filesize );

	xfer = purple_xfer_new( session->acc, PURPLE_XFER_RECEIVE, username );
	if ( xfer ) {
		/* create a new mxit xfer struct for internal use */
		mx = g_new0( struct mxitxfer, 1 );
		mx->session = session;
		memcpy( mx->fileid, fileid, MXIT_CHUNK_FILEID_LEN );
		xfer->data = mx;

		purple_xfer_set_filename( xfer, filename );
		if( filesize > 0 )
			purple_xfer_set_size( xfer, filesize );

		/* register file transfer callback functions */
		purple_xfer_set_init_fnc( xfer, mxit_xfer_init );
		purple_xfer_set_request_denied_fnc( xfer, mxit_xfer_request_denied );
		purple_xfer_set_cancel_recv_fnc( xfer, mxit_xfer_cancel_recv );
		purple_xfer_set_end_fnc( xfer, mxit_xfer_end );

		/* give the request to the user to accept/deny */
		purple_xfer_request( xfer );
	}
}


/*------------------------------------------------------------------------
 * Return the libPurple file-transfer object associated with a MXit transfer
 *
 *  @param session		The MXit session object
 *  @param fileid		A unique ID that identifies this file
 */
static PurpleXfer* find_mxit_xfer( struct MXitSession* session, const char* fileid )
{
	GList*		item	= NULL;
	PurpleXfer*	xfer	= NULL;

	item = purple_xfers_get_all();		/* list of all active transfers */
	while ( item ) {
		xfer = item->data;

		if ( purple_xfer_get_account( xfer ) == session->acc ) {
			/* transfer is associated with this MXit account */
			struct mxitxfer* mx	= xfer->data;

			/* does the fileid match? */
			if ( ( mx ) && ( memcmp( mx->fileid, fileid, MXIT_CHUNK_FILEID_LEN ) == 0 ) )
				break;
		}

		item = g_list_next( item );
	}

	if ( item )
		return item->data;
	else
		return NULL;
}

/*------------------------------------------------------------------------
 * A file has been received from the MXit server.
 *
 *  @param session		The	MXit session object
 *  @param fileid		A unique ID that identifies this file
 *  @param data			The file data
 *  @param datalen		The size of the data
 */
void mxit_xfer_rx_file( struct MXitSession* session, const char* fileid, const char* data, int datalen )
{
	PurpleXfer*			xfer	= NULL;

	purple_debug_info( MXIT_PLUGIN_ID, "mxit_xfer_rx_file: (size=%i)\n", datalen );

	/* find the file-transfer object */
	xfer = find_mxit_xfer( session, fileid );
	if ( xfer ) {
		/* this is the transfer we have been looking for */
		purple_xfer_ref( xfer );
		purple_xfer_start( xfer, -1, NULL, 0 );

		if ( fwrite( data, datalen, 1, xfer->dest_fp ) > 0 ) {
			purple_xfer_unref( xfer );
			purple_xfer_set_completed( xfer, TRUE );
			purple_xfer_end( xfer );

			/* inform MXit that file was successfully received */
			mxit_send_file_received( session, fileid, RECV_STATUS_SUCCESS );
		}
		else {
			/* file write error */
			purple_xfer_error( purple_xfer_get_type( xfer ), purple_xfer_get_account( xfer ), purple_xfer_get_remote_user( xfer ), _( "Unable to save the file" ) );
			purple_xfer_cancel_local( xfer );
		}
	}
	else {
		/* file transfer not found */
		mxit_send_file_received( session, fileid, RECV_STATUS_BAD_ID );
	}
}
