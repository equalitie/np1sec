/*
 *					MXit Protocol libPurple Plugin
 *
 *			-- handle chunked data (multimedia messages) --
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


/*========================================================================================================================
 * Data-Type encoding
 */

#if	0
#include	<byteswap.h>
#if (__BYTE_ORDER == __BIG_ENDIAN)
#define SWAP_64(x)  (x)
#else
#define SWAP_64(x)  bswap_64(x)
#endif
#endif

/*------------------------------------------------------------------------
 * Encode a single byte in the chunked data.
 *
 *  @param chunkdata		The chunked-data buffer
 *  @param value			The byte
 *  @return					The number of bytes added.
 */
static int add_int8( char* chunkdata, char value )
{
	*chunkdata = value;

	return sizeof( char );
}

/*------------------------------------------------------------------------
 * Encode a 16-bit value in the chunked data.
 *
 *  @param chunkdata		The chunked-data buffer
 *  @param value			The 16-bit value
 *  @return					The number of bytes added.
 */
static int add_int16( char* chunkdata, short value )
{
	value = htons( value );		/* network byte-order */
	memcpy( chunkdata, &value, sizeof( short ) );

	return sizeof( short );
}

/*------------------------------------------------------------------------
 * Encode a 32-bit value in the chunked data.
 *
 *  @param chunkdata		The chunked-data buffer
 *  @param value			The 32-bit value
 *  @return					The number of bytes added.
 */
static int add_int32( char* chunkdata, int value )
{
	value = htonl( value );		/* network byte-order */
	memcpy( chunkdata, &value, sizeof( int ) );

	return sizeof( int );
}

#if	0
/*------------------------------------------------------------------------
 * Encode a 64-bit value in the chunked data.
 *
 *  @param chunkdata		The chunked-data buffer
 *  @param value			The 64-bit value
 *  @return					The number of bytes added.
 */
static int add_int64( char* chunkdata, int64_t value )
{
	value = SWAP_64( value );	/* network byte-order */
	memcpy( chunkdata, &value, sizeof( int64_t ) );

	return sizeof( int64_t );
}
#endif

/*------------------------------------------------------------------------
 * Encode a block of data in the chunked data.
 *
 *  @param chunkdata		The chunked-data buffer
 *  @param data				The data to add
 *  @param datalen			The length of the data to add
 *  @return					The number of bytes added.
 */
static int add_data( char* chunkdata, const char* data, int datalen )
{
	memcpy( chunkdata, data, datalen );

	return datalen;
}

/*------------------------------------------------------------------------
 * Encode a string as UTF-8 in the chunked data.
 *
 *  @param chunkdata		The chunked-data buffer
 *  @param str				The string to encode
 *  @return					The number of bytes in the string
 */
static int add_utf8_string( char* chunkdata, const char* str )
{
	int		pos		= 0;
	size_t	len		= strlen( str );

	/* utf8 string length [2 bytes] */
	pos += add_int16( &chunkdata[pos], len );

	/* utf8 string */
	pos += add_data( &chunkdata[pos], str, len );

	return pos;
}


/*========================================================================================================================
 * Data-Type decoding
 */

/*------------------------------------------------------------------------
 * Extract a single byte from the chunked data.
 *
 *  @param chunkdata		The chunked-data buffer
 *  @param value			The byte
 *  @return					The number of bytes extracted.
 */
static int get_int8( const char* chunkdata, char* value )
{
	*value = *chunkdata;

	return sizeof( char );
}

/*------------------------------------------------------------------------
 * Extract a 16-bit value from the chunked data.
 *
 *  @param chunkdata		The chunked-data buffer
 *  @param value			The 16-bit value
 *  @return					The number of bytes extracted
 */
static int get_int16( const char* chunkdata, short* value )
{
	*value = ntohs( *( (const short*) chunkdata ) );	/* host byte-order */

	return sizeof( short );
}

/*------------------------------------------------------------------------
 * Extract a 32-bit value from the chunked data.
 *
 *  @param chunkdata		The chunked-data buffer
 *  @param value			The 32-bit value
 *  @return					The number of bytes extracted
 */
static int get_int32( const char* chunkdata, int* value )
{
	*value = ntohl( *( (const int*) chunkdata ) );	/* host byte-order */

	return sizeof( int );
}

#if	0
/*------------------------------------------------------------------------
 * Extract a 64-bit value from the chunked data.
 *
 *  @param chunkdata		The chunked-data buffer
 *  @param value			The 64-bit value
 *  @return					The number of bytes extracted
 */
static int get_int64( const char* chunkdata, int64_t* value )
{
	*value = SWAP_64( *( (const int64_t*) chunkdata ) );	/* host byte-order */

	return sizeof( int64_t );
}
#endif

/*------------------------------------------------------------------------
 * Copy a block of data from the chunked data.
 *
 *  @param chunkdata		The chunked-data buffer
 *  @param dest				Where to store the extract data
 *  @param datalen			The length of the data to extract
 *  @return					The number of bytes extracted
 */
static int get_data( const char* chunkdata, char* dest, int datalen )
{
	memcpy( dest, chunkdata, datalen );

	return datalen;
}

/*------------------------------------------------------------------------
 * Extract a UTF-8 encoded string from the chunked data.
 *
 *  @param chunkdata		The chunked-data buffer
 *  @param str				A pointer to extracted string.  Must be g_free()'d.
 *  @param maxstrlen		Maximum size of destination buffer.
 *  @return					The number of bytes consumed
 */
static int get_utf8_string( const char* chunkdata, char* str, int maxstrlen )
{
	int		pos = 0;
	short	len;
	int		skip = 0;

	/* string length [2 bytes] */
	pos += get_int16( &chunkdata[pos], &len );

	if ( len > maxstrlen ) {
		/* possible buffer overflow */
		purple_debug_error( MXIT_PLUGIN_ID, "Buffer overflow detected (get_utf8_string)\n" );
		skip = len - maxstrlen;
		len = maxstrlen;
	}

	/* string data */
	pos += get_data( &chunkdata[pos], str, len );
	str[len] = '\0';		/* terminate string */

	return pos + skip;
}


/*========================================================================================================================
 * Chunked Data encoding
 */

/*------------------------------------------------------------------------
 * Encode a "reject file" chunk.  (Chunk type 7)
 *
 *  @param chunkdata		Chunked-data buffer
 *  @param fileid			A unique ID that identifies this file
 *  @return					The number of bytes encoded in the buffer
 */
int mxit_chunk_create_reject( char* chunkdata, const char* fileid )
{
	int		pos		= 0;

	/* file id [8 bytes] */
	pos += add_data( &chunkdata[pos], fileid, MXIT_CHUNK_FILEID_LEN );

	/* rejection reason [1 byte] */
	pos += add_int8( &chunkdata[pos], REJECT_BY_USER );

	/* rejection description [UTF-8 (optional)] */
	pos += add_utf8_string( &chunkdata[pos], "" );

	return pos;
}


/*------------------------------------------------------------------------
 * Encode a "get file" request chunk.  (Chunk type 8)
 *
 *  @param chunkdata		Chunked-data buffer
 *  @param fileid			A unique ID that identifies this file
 *  @param filesize			The number of bytes to retrieve
 *  @param offset			The start offset in the file
 *  @return					The number of bytes encoded in the buffer
 */
int mxit_chunk_create_get( char* chunkdata, const char* fileid, int filesize, int offset )
{
	int		pos		= 0;

	/* file id [8 bytes] */
	pos += add_data( &chunkdata[pos], fileid, MXIT_CHUNK_FILEID_LEN );

	/* offset [4 bytes] */
	pos += add_int32( &chunkdata[pos], offset );

	/* length [4 bytes] */
	pos += add_int32( &chunkdata[pos], filesize );

	return pos;
}


/*------------------------------------------------------------------------
 * Encode a "received file" chunk.  (Chunk type 9)
 *
 *  @param chunkdata		Chunked-data buffer
 *  @param fileid			A unique ID that identifies this file
 *  @param status			The status of the file transfer (see chunk.h)
 *  @return					The number of bytes encoded in the buffer
 */
int mxit_chunk_create_received( char* chunkdata, const char* fileid, unsigned char status )
{
	int		pos		= 0;

	/* file id [8 bytes] */
	pos += add_data( &chunkdata[pos], fileid, MXIT_CHUNK_FILEID_LEN );

	/* status [1 byte] */
	pos += add_int8( &chunkdata[pos], status );

	return pos;
}


/*------------------------------------------------------------------------
 * Encode a "send file direct" chunk.  (Chunk type 10)
 *
 *  @param chunkdata		Chunked-data buffer
 *  @param username			The username of the recipient
 *  @param filename			The name of the file being sent
 *  @param data				The file contents
 *  @param datalen			The size of the file contents
 *  @return					The number of bytes encoded in the buffer
 */
int mxit_chunk_create_senddirect( char* chunkdata, const char* username, const char* filename, const unsigned char* data, int datalen )
{
	int			pos		= 0;
	const char*	mime	= NULL;

	/* data length [4 bytes] */
	pos += add_int32( &chunkdata[pos], datalen );

	/* number of username(s) [2 bytes] */
	pos += add_int16( &chunkdata[pos], 1 );

	/* username(s) [UTF-8] */
	pos += add_utf8_string( &chunkdata[pos], username );

	/* filename [UTF-8] */
	pos += add_utf8_string( &chunkdata[pos], filename );

	/* file mime type [UTF-8] */
	mime = file_mime_type( filename, (const char*) data, datalen );
	pos += add_utf8_string( &chunkdata[pos], mime );

	/* human readable description [UTF-8 (optional)] */
	pos += add_utf8_string( &chunkdata[pos], "" );

	/* crc [4 bytes] (0 = optional) */
	pos += add_int32( &chunkdata[pos], 0 );

	/* the actual file data */
	pos += add_data( &chunkdata[pos], (const char *) data, datalen );

	return pos;
}


/*------------------------------------------------------------------------
 * Encode a "set avatar" chunk.  (Chunk type 13)
 *
 *  @param chunkdata		Chunked-data buffer
 *  @param data				The avatar data
 *  @param datalen			The size of the avatar data
 *  @return					The number of bytes encoded in the buffer
 */
int mxit_chunk_create_set_avatar( char* chunkdata, const unsigned char* data, int datalen )
{
	const char	fileid[MXIT_CHUNK_FILEID_LEN];
	int			pos = 0;

	/* id [8 bytes] */
	memset( &fileid, 0, sizeof( fileid ) );		/* set to 0 for file upload */
	pos += add_data( &chunkdata[pos], fileid, MXIT_CHUNK_FILEID_LEN );

	/* size [4 bytes] */
	pos += add_int32( &chunkdata[pos], datalen );

	/* crc [4 bytes] (0 = optional) */
	pos += add_int32( &chunkdata[pos], 0 );

	/* the actual file data */
	pos += add_data( &chunkdata[pos], (const char *) data, datalen );

	return pos;
}


/*------------------------------------------------------------------------
 * Encode a "get avatar" chunk.  (Chunk type 14)
 *
 *  @param chunkdata		Chunked-data buffer
 *  @param mxitId			The username who's avatar to download
 *  @param avatarId			The Id of the avatar image (as string)
 *  @return					The number of bytes encoded in the buffer
 */
int mxit_chunk_create_get_avatar( char* chunkdata, const char* mxitId, const char* avatarId )
{
	int			pos = 0;

	/* number of avatars [4 bytes] */
	pos += add_int32( &chunkdata[pos], 1 );

	/* username [UTF-8] */
	pos += add_utf8_string( &chunkdata[pos], mxitId );

	/* avatar id [UTF-8] */
	pos += add_utf8_string( &chunkdata[pos], avatarId );

	/* avatar format [UTF-8] */
	pos += add_utf8_string( &chunkdata[pos], MXIT_AVATAR_TYPE );

	/* avatar bit depth [1 byte] */
	pos += add_int8( &chunkdata[pos], MXIT_AVATAR_BITDEPT );

	/* number of sizes [2 bytes] */
	pos += add_int16( &chunkdata[pos], 1 );

	/* image size [4 bytes] */
	pos += add_int32( &chunkdata[pos], MXIT_AVATAR_SIZE );

	return pos;
}


/*========================================================================================================================
 * Chunked Data decoding
 */

/*------------------------------------------------------------------------
 * Parse a received "offer file" chunk.  (Chunk 6)
 *
 *  @param chunkdata		Chunked data buffer
 *  @param datalen			The length of the chunked data
 *  @param offer			Decoded offerfile information
 */
void mxit_chunk_parse_offer( char* chunkdata, int datalen, struct offerfile_chunk* offer )
{
	int			pos			= 0;

	purple_debug_info( MXIT_PLUGIN_ID, "mxit_chunk_parse_offer (%i bytes)\n", datalen );

	/* id [8 bytes] */
	pos += get_data( &chunkdata[pos], offer->fileid, 8);

	/* from username [UTF-8] */
	pos += get_utf8_string( &chunkdata[pos], offer->username, sizeof( offer->username ) );
	mxit_strip_domain( offer->username );

	/* file size [4 bytes] */
	pos += get_int32( &chunkdata[pos], &(offer->filesize) );

	/* filename [UTF-8] */
	pos += get_utf8_string( &chunkdata[pos], offer->filename, sizeof( offer->filename ) );

	/* mime type [UTF-8] */
	pos += get_utf8_string( &chunkdata[pos], offer->mimetype, sizeof( offer->mimetype ) );

	/* timestamp [8 bytes] */
	/* not used by libPurple */

	/* file description [UTF-8] */
	/* not used by libPurple */

	/* file alternative [UTF-8] */
	/* not used by libPurple */

	/* flags [4 bytes] */
	/* not used by libPurple */
}


/*------------------------------------------------------------------------
 * Parse a received "get file" response chunk.  (Chunk 8)
 *
 *  @param chunkdata		Chunked data buffer
 *  @param datalen			The length of the chunked data
 *  @param offer			Decoded getfile information
 */
void mxit_chunk_parse_get( char* chunkdata, int datalen, struct getfile_chunk* getfile )
{
	int			pos			= 0;

	purple_debug_info( MXIT_PLUGIN_ID, "mxit_chunk_parse_file (%i bytes)\n", datalen );

	/* id [8 bytes] */
	pos += get_data( &chunkdata[pos], getfile->fileid, 8 );

	/* offset [4 bytes] */
	pos += get_int32( &chunkdata[pos], &(getfile->offset) );

	/* file length [4 bytes] */
	pos += get_int32( &chunkdata[pos], &(getfile->length) );

	/* crc [4 bytes] */
	pos += get_int32( &chunkdata[pos], &(getfile->crc) );

	/* file data */
	getfile->data = &chunkdata[pos];
}


/*------------------------------------------------------------------------
 * Parse a received splash screen chunk.  (Chunk 2)
 *
 *  @param chunkdata		Chunked data buffer
 *  @param datalen			The length of the chunked data
 *  @param splash			Decoded splash image information
 */
static void mxit_chunk_parse_splash( char* chunkdata, int datalen, struct splash_chunk* splash )
{
	int			pos			= 0;

	purple_debug_info( MXIT_PLUGIN_ID, "mxit_chunk_parse_splash (%i bytes)\n", datalen );

	/* anchor [1 byte] */
	pos += get_int8( &chunkdata[pos], &(splash->anchor) );

	/* time to show [1 byte] */
	pos += get_int8( &chunkdata[pos], &(splash->showtime) );

	/* background color [4 bytes] */
	pos += get_int32( &chunkdata[pos], &(splash->bgcolor) );

	/* file data */
	splash->data = &chunkdata[pos];

	/* data length */
	splash->datalen = datalen - pos;
}


/*------------------------------------------------------------------------
 * Parse a received "custom resource" chunk.  (Chunk 1)
 *
 *  @param chunkdata		Chunked data buffer
 *  @param datalen			The length of the chunked data
 *  @param offer			Decoded custom resource
 */
void mxit_chunk_parse_cr( char* chunkdata, int datalen, struct cr_chunk* cr )
{
	int			pos			= 0;
	int			chunklen	= 0;

	purple_debug_info( MXIT_PLUGIN_ID, "mxit_chunk_parse_cr (%i bytes)\n", datalen );

	/* id [UTF-8] */
	pos += get_utf8_string( &chunkdata[pos], cr->id, sizeof( cr->id ) );

	/* handle [UTF-8] */
	pos += get_utf8_string( &chunkdata[pos], cr->handle, sizeof( cr->handle ) );

	/* operation [1 byte] */
	pos += get_int8( &chunkdata[pos], &(cr->operation) );

	/* chunk size [4 bytes] */
	pos += get_int32( &chunkdata[pos], &chunklen );

	/* parse the resource chunks */
	while ( chunklen > 0 ) {
		gchar* chunk = &chunkdata[pos];

		/* start of chunk data */
		pos += MXIT_CHUNK_HEADER_SIZE;

		switch ( chunk_type( chunk ) ) {
			case CP_CHUNK_SPLASH :			/* splash image */
				{
					struct splash_chunk* splash = g_new0( struct splash_chunk, 1 );

					mxit_chunk_parse_splash( &chunkdata[pos], chunk_length( chunk ), splash );

					cr->resources = g_list_append( cr->resources, splash );
					break;
				}
			case CP_CHUNK_CLICK :			/* splash click */
				{
					struct splash_click_chunk* click = g_new0( struct splash_click_chunk, 1 );

					cr->resources = g_list_append( cr->resources, click );
					break;
				}
			default:
				purple_debug_info( MXIT_PLUGIN_ID, "Unsupported custom resource chunk received (%i)\n", chunk_type( chunk) );
		}

		/* skip over data to next resource chunk */
		pos += chunk_length( chunk );
		chunklen -= ( MXIT_CHUNK_HEADER_SIZE + chunk_length( chunk ) );
	}
}


/*------------------------------------------------------------------------
 * Parse a received "send file direct" response chunk.  (Chunk 10)
 *
 *  @param chunkdata		Chunked data buffer
 *  @param datalen			The length of the chunked data
 *  @param sendfile			Decoded sendfile information
 */
void mxit_chunk_parse_sendfile( char* chunkdata, int datalen, struct sendfile_chunk* sendfile )
{
	int			pos		= 0;
	short		entries	= 0;

	purple_debug_info( MXIT_PLUGIN_ID, "mxit_chunk_parse_sendfile (%i bytes)\n", datalen );

	/* number of entries [2 bytes] */
	pos += get_int16( &chunkdata[pos], &entries );

	if ( entries < 1 )		/* no data */
		return;

	/* contactAddress [UTF-8 string] */
	pos += get_utf8_string( &chunkdata[pos], sendfile->username, sizeof( sendfile->username ) );

	/* status [4 bytes] */
	pos += get_int32( &chunkdata[pos], &(sendfile->status) );

	/* status message [UTF-8 string] */
	pos += get_utf8_string( &chunkdata[pos], sendfile->statusmsg, sizeof( sendfile->statusmsg ) );
}


/*------------------------------------------------------------------------
 * Parse a received "get avatar" response chunk.  (Chunk 14)
 *
 *  @param chunkdata		Chunked data buffer
 *  @param datalen			The length of the chunked data
 *  @param avatar			Decoded avatar information
 */
void mxit_chunk_parse_get_avatar( char* chunkdata, int datalen, struct getavatar_chunk* avatar )
{
	int			pos			= 0;
	int			numfiles	= 0;

	purple_debug_info( MXIT_PLUGIN_ID, "mxit_chunk_parse_get_avatar (%i bytes)\n", datalen );

	/* number of files [4 bytes] */
	pos += get_int32( &chunkdata[pos], &numfiles );

	if ( numfiles < 1 )		/* no data */
		return;

	/* mxitId [UTF-8 string] */
	pos += get_utf8_string( &chunkdata[pos], avatar->mxitid, sizeof( avatar->mxitid ) );

	/* avatar id [UTF-8 string] */
	pos += get_utf8_string( &chunkdata[pos], avatar->avatarid, sizeof( avatar->avatarid ) );

	/* format [UTF-8 string] */
	pos += get_utf8_string( &chunkdata[pos], avatar->format, sizeof( avatar->format ) );

	/* bit depth [1 byte] */
	pos += get_int8( &chunkdata[pos], &(avatar->bitdepth) );

	/* crc [4 bytes] */
	pos += get_int32( &chunkdata[pos], &(avatar->crc) );

	/* width [4 bytes] */
	pos += get_int32( &chunkdata[pos], &(avatar->width) );

	/* height [4 bytes] */
	pos += get_int32( &chunkdata[pos], &(avatar->height) );

	/* file length [4 bytes] */
	pos += get_int32( &chunkdata[pos], &(avatar->length) );

	/* file data */
	avatar->data = &chunkdata[pos];
}
