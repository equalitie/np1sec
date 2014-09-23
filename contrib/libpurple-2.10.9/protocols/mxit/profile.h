/*
 *					MXit Protocol libPurple Plugin
 *
 *					-- user profile's --
 *
 *				Andrew Victor	<libpurple@mxit.com>
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

#ifndef		_MXIT_PROFILE_H_
#define		_MXIT_PROFILE_H_


/* MXit relationship status types */
#define MXIT_RELATIONSHIP_UNKNOWN		0
#define MXIT_RELATIONSHIP_DONTSAY		1
#define MXIT_RELATIONSHIP_SINGLE		2
#define MXIT_RELATIONSHIP_INVOLVED		3
#define MXIT_RELATIONSHIP_ENGAGED		4
#define MXIT_RELATIONSHIP_MARRIED		5
#define MXIT_RELATIONSHIP_COMPLICATED	6
#define MXIT_RELATIONSHIP_WIDOWED		7
#define MXIT_RELATIONSHIP_SEPARATED		8
#define MXIT_RELATIONSHIP_DIVORCED		9

struct MXitProfile {
	/* required */
	char		loginname[64];						/* name user uses to log into MXit with (aka 'mxitid') */
	char		userid[51];							/* internal UserId (only in search results) */
	char		nickname[101];						/* user's own display name (aka 'display name', aka 'fullname', aka 'alias') in MXit */
	char		birthday[16];						/* user's birthday "YYYY-MM-DD" */
	gboolean	male;								/* true if the user's gender is male (otherwise female) */
	char		pin[16];							/* user's password */

	/* optional */
	char		title[21];							/* user's title */
	char		firstname[51];						/* user's first name */
	char		lastname[51];						/* user's last name (aka 'surname') */
	char		email[201];							/* user's email address */
	char		mobilenr[21];						/* user's mobile number */
	char		regcountry[3];						/* user's registered country code */
	char		whereami[51];						/* where am I / where I live */
	char		aboutme[513];						/* about me */
	int			relationship;						/* relationship status */

	gint64		flags;								/* user's profile flags */
	gint64		lastonline;							/* user's last-online timestamp */
};

struct MXitSession;
void mxit_show_profile( struct MXitSession* session, const char* username, struct MXitProfile* profile );
void mxit_show_search_results( struct MXitSession* session, int searchType, int maxResults, GList* entries );
const char* mxit_relationship_to_name( short id );

gboolean validateDate( const char* bday );


#endif		/* _MXIT_PROFILE_H_ */
