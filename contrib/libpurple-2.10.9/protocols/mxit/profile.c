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

#define		_XOPEN_SOURCE
#include	<time.h>

#include	"internal.h"

#include	"mxit.h"
#include	"profile.h"
#include	"roster.h"


/*------------------------------------------------------------------------
 * Return the MXit Relationship status as a string.
 *
 * @param id		The Relationship status value (see profile.h)
 * @return			The relationship status as a text string.
 */
const char* mxit_relationship_to_name( short id )
{
	switch ( id ) {
		case MXIT_RELATIONSHIP_UNKNOWN :
			return _( "Unknown" );
		case MXIT_RELATIONSHIP_DONTSAY :
			return _( "Don't want to say" );
		case MXIT_RELATIONSHIP_SINGLE :
			return _( "Single" );
		case MXIT_RELATIONSHIP_INVOLVED :
			return _( "In a relationship" );
		case MXIT_RELATIONSHIP_ENGAGED :
			return _( "Engaged" );
		case MXIT_RELATIONSHIP_MARRIED :
			return _( "Married" );
		case MXIT_RELATIONSHIP_COMPLICATED :
			return _( "It's complicated" );
		case MXIT_RELATIONSHIP_WIDOWED :
			return _( "Widowed" );
		case MXIT_RELATIONSHIP_SEPARATED :
			return _( "Separated" );
		case MXIT_RELATIONSHIP_DIVORCED :
			return _( "Divorced" );
		default :
			return "";
	}
}

/*------------------------------------------------------------------------
 * Returns true if it is a valid date.
 *
 * @param bday		Date-of-Birth string (YYYY-MM-DD)
 * @return			TRUE if valid, else FALSE
 */
gboolean validateDate( const char* bday )
{
	struct tm*	tm;
	time_t		t;
	int			cur_year;
	int			max_days[13]	= { 0, 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
	char		date[16];
	int			year;
	int			month;
	int			day;

	/* validate length */
	if ( strlen( bday ) != 10 ) {
		return FALSE;
	}

	/* validate the format */
	if (	( !isdigit( bday[0] ) ) || ( !isdigit( bday[1] ) ) || ( !isdigit( bday[2] ) ) || ( !isdigit( bday[3] ) ) ||		/* year */
			( bday[4] != '-' ) ||
			( !isdigit( bday[5] ) ) || ( !isdigit( bday[6] ) ) ||															/* month */
			( bday[7] != '-' ) ||
			( !isdigit( bday[8] ) ) || ( !isdigit( bday[9] ) ) ) { 															/* day */
		return FALSE;
	}

	/* convert */
	t = time( NULL );
	tm = gmtime( &t );
	cur_year = tm->tm_year + 1900;
	memcpy( date, bday, 10 );
	date[4] = '\0';
	date[7] = '\0';
	date[10] = '\0';
	year = atoi( &date[0] );
	month = atoi( &date[5] );
	day = atoi( &date[8] );

	/* validate month */
	if ( ( month < 1 ) || ( month > 12 ) ) {
		return FALSE;
	}

	/* validate day */
	if ( ( day < 1 ) || ( day > max_days[month] ) ) {
		return FALSE;
	}

	/* validate year */
	if ( ( year < ( cur_year - 100 ) ) || ( year >= cur_year ) ) {
		/* you are either tooo old or tooo young to join mxit... sorry */
		return FALSE;
	}

	/* special case leap-year */
	if ( ( year % 4 != 0 ) && ( month == 2 ) && ( day == 29 ) ) {
		/* cannot have 29 days in February in non leap-years! */
		return FALSE;
	}

	return TRUE;
}


/*------------------------------------------------------------------------
 * Calculate an Age from the date-of-birth.
 *
 * @param date		Date-of-Birth string (YYYY-MM-DD)
 * @return			The age
 */
static int calculateAge( const char* date )
{
	time_t t;
	struct tm now, bdate;
	int age;

	if ( ( !date ) || ( strlen( date ) == 0 ) )
		return 0;

	/* current time */
	t = time( NULL );
	localtime_r( &t, &now );

	/* decode hdate */
	memset( &bdate, 0, sizeof( struct tm ) );
	purple_str_to_time( date, FALSE, &bdate, NULL, NULL );

	/* calculate difference */
	age = now.tm_year - bdate.tm_year;
	if ( now.tm_mon < bdate.tm_mon )		/* is before month of birth */
		age--;
	else if ( ( now.tm_mon == bdate.tm_mon ) && ( now.tm_mday < bdate.tm_mday ) )	/* before birthday in current month */
		age--;

	return age;
}


/*------------------------------------------------------------------------
 * Returns timestamp field in date & time format (DD-MM-YYYY HH:MM:SS)
 *
 * @param msecs		The timestamps (milliseconds since epoch)
 * @return			Date & Time in a display'able format.
 */
static const char* datetime( gint64 msecs )
{
	time_t secs = msecs / 1000;

	struct tm t;
	localtime_r( &secs, &t );

	return purple_utf8_strftime( "%d-%m-%Y %H:%M:%S", &t );
}


/*------------------------------------------------------------------------
 * Display the profile information.
 *
 * @param session		The MXit session object
 * @param username		The username who's profile information this is
 * @param profile		The profile
 */
void mxit_show_profile( struct MXitSession* session, const char* username, struct MXitProfile* profile )
{
	PurpleNotifyUserInfo*	info		= purple_notify_user_info_new();
	struct contact*			contact		= NULL;
	PurpleBuddy*			buddy;
	gchar*					tmp			= NULL;

	buddy = purple_find_buddy( session->acc, username );
	if ( buddy ) {
		purple_notify_user_info_add_pair( info, _( "Alias" ), purple_buddy_get_alias( buddy ) );
		purple_notify_user_info_add_section_break( info );
		contact = purple_buddy_get_protocol_data( buddy );
	}

	purple_notify_user_info_add_pair( info, _( "Display Name" ), profile->nickname );

	tmp = g_strdup_printf("%s (%i)", profile->birthday, calculateAge( profile->birthday ) );
	purple_notify_user_info_add_pair( info, _( "Birthday" ), tmp );
	g_free( tmp );

	purple_notify_user_info_add_pair( info, _( "Gender" ), profile->male ? _( "Male" ) : _( "Female" ) );

	/* optional information */
	purple_notify_user_info_add_pair( info, _( "First Name" ), profile->firstname );
	purple_notify_user_info_add_pair( info, _( "Last Name" ), profile->lastname );
	purple_notify_user_info_add_pair( info, _( "Country" ), profile->regcountry );

	if ( strlen( profile->aboutme ) > 0 )
		purple_notify_user_info_add_pair( info, _( "About Me" ), profile->aboutme );
	if ( strlen( profile->whereami ) > 0 )
		purple_notify_user_info_add_pair( info, _( "Where I Live" ), profile->whereami );

	purple_notify_user_info_add_pair_plaintext( info, _( "Relationship Status" ), mxit_relationship_to_name( profile->relationship ) );

	purple_notify_user_info_add_section_break( info );

	if ( contact ) {
		/* presence */
		purple_notify_user_info_add_pair( info, _( "Status" ), mxit_convert_presence_to_name( contact->presence ) );

		/* last online */
		if ( contact->presence == MXIT_PRESENCE_OFFLINE )
			purple_notify_user_info_add_pair( info, _( "Last Online" ), ( profile->lastonline == 0 ) ? _( "Unknown" ) : datetime( profile->lastonline ) );

		/* mood */
		if ( contact->mood != MXIT_MOOD_NONE )
			purple_notify_user_info_add_pair( info, _( "Mood" ), mxit_convert_mood_to_name( contact->mood ) );
		else
			purple_notify_user_info_add_pair( info, _( "Mood" ), _( "None" ) );

		/* status message */
		if ( contact->statusMsg )
			purple_notify_user_info_add_pair( info, _( "Status Message" ), contact->statusMsg );

		/* subscription type */
		purple_notify_user_info_add_pair( info, _( "Subscription" ), mxit_convert_subtype_to_name( contact->subtype ) );
	}
	else {
		/* this is an invite */
		contact = get_mxit_invite_contact( session, username );
		if ( contact ) {
			/* invite found */

			if ( contact->msg )
				purple_notify_user_info_add_pair( info, _( "Invite Message" ), contact->msg );

			if ( contact->imgid ) {
				/* this invite has a avatar */
				char* img_text;
				img_text = g_strdup_printf( "<img id='%d'>", contact->imgid );
				purple_notify_user_info_add_pair( info, _( "Photo" ), img_text );
				g_free( img_text );
			}

			if ( contact->statusMsg )
				purple_notify_user_info_add_pair( info, _( "Status Message" ), contact->statusMsg );
		}
	}

	purple_notify_userinfo( session->con, username, info, NULL, NULL );
	purple_notify_user_info_destroy( info );
}


/*------------------------------------------------------------------------
 * Display the profiles of search results.
 *
 * @param gc			The connection object
 * @param row			The selected row from search-results
 * @param user_data		NULL (unused)
 */
static void mxit_search_results_add_cb( PurpleConnection *gc, GList *row, gpointer user_data )
{
	/* display add buddy dialog */
	purple_blist_request_add_buddy( purple_connection_get_account( gc ), g_list_nth_data( row, 0 ), NULL, g_list_nth_data( row, 1 ) );
}


/*------------------------------------------------------------------------
 * Display the profiles of search results.
 *
 * @param session		The MXit session object
 * @param searchType	The type of search (CP_SUGGEST_*)
 * @param maxResults	The maximum number of results
 * @param entries		The list of profile entries
 */
void mxit_show_search_results( struct MXitSession* session, int searchType, int maxResults, GList* entries )
{
	PurpleNotifySearchResults*	results;
	PurpleNotifySearchColumn*	column;
	gchar*						text;

	if ( !entries ) {
		mxit_popup( PURPLE_NOTIFY_MSG_INFO, _( "No results" ), _( "No contacts found." ) );
		return;
	}

	results = purple_notify_searchresults_new();
	if ( !results )
		return;

	/* define columns */
	column = purple_notify_searchresults_column_new( _( "UserId" ) );
	purple_notify_searchresults_column_add( results, column );
	column = purple_notify_searchresults_column_new( _( "Display Name" ) );
	purple_notify_searchresults_column_add( results, column );
	column = purple_notify_searchresults_column_new( _( "First Name" ) );
	purple_notify_searchresults_column_add( results, column );
	column = purple_notify_searchresults_column_new( _( "Last Name" ) );
	purple_notify_searchresults_column_add( results, column );
	column = purple_notify_searchresults_column_new( _( "Gender" ) );
	purple_notify_searchresults_column_add( results, column );
	column = purple_notify_searchresults_column_new( _( "Age" ) );
	purple_notify_searchresults_column_add( results, column );
	column = purple_notify_searchresults_column_new( _( "Where I live" ) );
	purple_notify_searchresults_column_add( results, column );

	while ( entries != NULL ) {
		struct MXitProfile* profile	= ( struct MXitProfile *) entries->data;
		GList*	row;
		gchar* tmp = purple_base64_encode( (unsigned char *) profile->userid, strlen( profile->userid ) );

		/* column values */
		row = g_list_append( NULL, g_strdup_printf( "#%s", tmp ) );
		row = g_list_append( row, g_strdup( profile->nickname ) );
		row = g_list_append( row, g_strdup( profile->firstname ) );
		row = g_list_append( row, g_strdup( profile->lastname ) );
		row = g_list_append( row, g_strdup( profile->male ? "Male" : "Female" ) );
		row = g_list_append( row, g_strdup_printf( "%i", calculateAge( profile->birthday ) ) );
		row = g_list_append( row, g_strdup( profile->whereami ) );

		purple_notify_searchresults_row_add( results, row );
		entries = g_list_next( entries );

		g_free( tmp );
	}

	/* button */
	purple_notify_searchresults_button_add( results, PURPLE_NOTIFY_BUTTON_INVITE, mxit_search_results_add_cb );

	if ( searchType == CP_SUGGEST_FRIENDS )
		text = g_strdup_printf( dngettext( PACKAGE, "You have %i suggested friend.", "You have %i suggested friends.", maxResults ), maxResults );
	else
		text = g_strdup_printf( dngettext( PACKAGE, "We found %i contact that matches your search.", "We found %i contacts that match your search.", maxResults ), maxResults );

	purple_notify_searchresults( session->con, NULL, text, NULL, results, NULL, NULL );

	g_free( text );
}
