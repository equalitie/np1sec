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

#ifndef		_MXIT_FILEXFER_H_
#define		_MXIT_FILEXFER_H_


/*
 * a MXit file transfer
 */
struct mxitxfer {
	struct MXitSession*		session;
	char					fileid[MXIT_CHUNK_FILEID_LEN];
};

const char* file_mime_type( const char* filename, const char* buf, int buflen );

/* libPurple callbacks */
gboolean mxit_xfer_enabled( PurpleConnection* gc, const char* who );
void mxit_xfer_tx( PurpleConnection* gc, const char* who, const char* filename );
PurpleXfer* mxit_xfer_new( PurpleConnection* gc, const char* who );

/* MXit Protocol callbacks */
void mxit_xfer_rx_offer( struct MXitSession* session, const char* username, const char* filename, int filesize, const char* fileid );
void mxit_xfer_rx_file( struct MXitSession* session, const char* fileid, const char* data, int datalen );


#endif		/* _MXIT_FILEXFER_H_ */
