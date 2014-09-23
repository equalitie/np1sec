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

#ifndef		_MXIT_CHUNK_H_
#define		_MXIT_CHUNK_H_


#include	"roster.h"


#define		MXIT_CHUNK_FILEID_LEN		8			/* bytes */
#define		MXIT_CHUNK_HEADER_SIZE		5			/* type (1 byte) + length (4 bytes) */


/* Multimedia chunk types */
#define		CP_CHUNK_NONE				0x00		/* (0) no chunk */
#define		CP_CHUNK_CUSTOM				0x01		/* (1) custom resource */
#define		CP_CHUNK_SPLASH				0x02		/* (2) splash image */
#define		CP_CHUNK_CLICK				0x03		/* (3) splash click through */
#define		CP_CHUNK_OFFER				0x06		/* (6) offer file */
#define		CP_CHUNK_REJECT				0x07		/* (7) reject file */
#define		CP_CHUNK_GET				0x08		/* (8) get file */
#define		CP_CHUNK_RECEIVED			0x09		/* (9) received file */
#define		CP_CHUNK_DIRECT_SND			0x0A		/* (10) send file direct */
#define		CP_CHUNK_DIRECT_FWD			0x0B		/* (11) forward file direct */
#define		CP_CHUNK_SKIN				0x0C		/* (12) MXit client skin */
#define		CP_CHUNK_SET_AVATAR			0x0D		/* (13) set avatar */
#define		CP_CHUNK_GET_AVATAR			0x0E		/* (14) get avatar */
#define		CP_CHUNK_END				0x7E		/* (126) end */
#define		CP_CHUNK_EXT				0x7F		/* (127) extended type */


/* Custom Resource operations */
#define		CR_OP_UPDATE				0
#define		CR_OP_REMOVE				1

/* File Received status */
#define		RECV_STATUS_SUCCESS			0
#define		RECV_STATUS_PARSE_FAIL		1
#define		RECV_STATUS_CANNOT_OPEN		8
#define		RECV_STATUS_BAD_CRC			9
#define		RECV_STATUS_BAD_ID			10

/* File Reject status */
#define		REJECT_BY_USER				1
#define		REJECT_FILETYPE				2
#define		REJECT_NO_RESOURCES			3
#define		REJECT_BAD_RECIPIENT		4

/*
 * Chunk header manipulation functions
 */
static inline guint chunk_type( gchar* chunkheader )
{
	return *chunkheader;
}

static inline void set_chunk_type( gchar* chunkheader, guint type )
{
	*chunkheader = type;
}

static inline guint32 chunk_length( gchar* chunkheader )
{
	guint32 length = *( (const guint32*) &chunkheader[1] );
	return htonl( length );
}

static inline void set_chunk_length( gchar* chunkheader, guint32 size )
{
	size = htonl( size );
	memcpy( &chunkheader[1], &size, sizeof( guint32 ) );
}

static inline gchar* chunk_data( gchar* chunkheader )
{
	return &chunkheader[MXIT_CHUNK_HEADER_SIZE];
}

/*
 * Offer File chunk (6).
 */
struct offerfile_chunk {
	char	fileid[MXIT_CHUNK_FILEID_LEN];
	char	username[MXIT_CP_MAX_JID_LEN + 1];
	int		filesize;
	char	filename[FILENAME_MAX];
	char	mimetype[64];
};

/*
 * Get File chunk (8) response.
 */
struct getfile_chunk {
	char	fileid[MXIT_CHUNK_FILEID_LEN];
	int		offset;
	int		length;
	int		crc;
	char*	data;
};

/*
 * Custom Resource chunk (1).
 */
struct cr_chunk {
	char	id[64];
	char	handle[64];
	char	operation;
	GList*	resources;
};

/*
 * Splash Image chunk (2)
 */
struct splash_chunk {
	char	anchor;
	char	showtime;
	int		bgcolor;
	char*	data;
	int		datalen;
};

/*
 * Splash Click Through chunk (3)
 */
struct splash_click_chunk {
	char	reserved[1];
};

/*
 * Get Avatar chunk (14) response.
 */
struct getavatar_chunk {
	char	mxitid[50];
	char	avatarid[64];
	char	format[16];
	char	bitdepth;
	int		crc;
	int		width;
	int		height;
	int		length;
	char*	data;
};

/*
 * Send File Direct chunk (10) response.
 */
struct sendfile_chunk {
	char	username[MXIT_CP_MAX_JID_LEN + 1];
	int		status;
	char	statusmsg[1024];
};

/* Encode chunk */
int mxit_chunk_create_senddirect( char* chunkdata, const char* username, const char* filename, const unsigned char* data, int datalen );
int mxit_chunk_create_reject( char* chunkdata, const char* fileid );
int mxit_chunk_create_get( char* chunkdata, const char* fileid, int filesize, int offset );
int mxit_chunk_create_received( char* chunkdata, const char* fileid, unsigned char status );
int mxit_chunk_create_set_avatar( char* chunkdata, const unsigned char* data, int datalen );
int mxit_chunk_create_get_avatar( char* chunkdata, const char* mxitId, const char* avatarId );

/* Decode chunk */
void mxit_chunk_parse_offer( char* chunkdata, int datalen, struct offerfile_chunk* offer );
void mxit_chunk_parse_get( char* chunkdata, int datalen, struct getfile_chunk* getfile );
void mxit_chunk_parse_cr( char* chunkdata, int datalen, struct cr_chunk* cr );
void mxit_chunk_parse_sendfile( char* chunkdata, int datalen, struct sendfile_chunk* sendfile );
void mxit_chunk_parse_get_avatar( char* chunkdata, int datalen, struct getavatar_chunk* avatar );

#endif		/* _MXIT_CHUNK_H_ */

