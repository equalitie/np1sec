/*
 *					MXit Protocol libPurple Plugin
 *
 *						-- encryption --
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

#ifndef		_MXIT_CIPHER_H_
#define		_MXIT_CIPHER_H_


struct MXitSession;


char* mxit_encrypt_password( struct MXitSession* session );

char* mxit_decrypt_message( struct MXitSession* session, char* message );
char* mxit_encrypt_message( struct MXitSession* session, char* message );

#endif		/* _MXIT_CIPHER_H_ */
