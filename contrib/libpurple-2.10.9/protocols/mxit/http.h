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


#ifndef		_MXIT_HTTP_H_
#define		_MXIT_HTTP_H_



struct http_request
{
	struct MXitSession*		session;
	char*					host;
	int						port;
	char*					data;
	int						datalen;
};


void mxit_http_send_request( struct MXitSession* session, char* host, int port, const char* data, int datalen );



#endif		/* _MXIT_HTTP_H_ */

