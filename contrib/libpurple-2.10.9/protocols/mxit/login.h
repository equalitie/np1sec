/*
 *					MXit Protocol libPurple Plugin
 *
 *				-- MXit user login functionality --
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

#ifndef		_MXIT_LOGIN_H_
#define		_MXIT_LOGIN_H_


struct login_data {
	char*		wapserver;			/* direct WAP server for postback */
	char*		sessionid;			/* unique session id */
	guchar*		captcha;			/* actual captcha (PNG) */
	gsize		captcha_size;		/* captcha size */
	char*		cc;					/* country code */
	char*		locale;				/* locale (language) */
};


void mxit_login( PurpleAccount* account );
void mxit_register( PurpleAccount* account );
void mxit_reconnect( struct MXitSession* session );


#endif		/* _MXIT_LOGIN_H_ */
