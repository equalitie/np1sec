/*
 *					MXit Protocol libPurple Plugin
 *
 *					-- handle MXit plugin actions --
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
#include	"request.h"

#include	"protocol.h"
#include	"mxit.h"
#include	"roster.h"
#include	"actions.h"
#include	"splashscreen.h"
#include	"cipher.h"
#include	"profile.h"


/*------------------------------------------------------------------------
 * The user has selected to change their profile.
 *
 *  @param gc		The connection object
 *  @param fields	The fields from the request pop-up
 */
static void mxit_profile_cb( PurpleConnection* gc, PurpleRequestFields* fields )
{
	struct MXitSession*		session	= purple_connection_get_protocol_data( gc );
	PurpleRequestField*		field	= NULL;
	const char*				name	= NULL;
	const char*				bday	= NULL;
	const char*				err		= NULL;
	GList*					entry	= NULL;

	purple_debug_info( MXIT_PLUGIN_ID, "mxit_profile_cb\n" );

	if ( !PURPLE_CONNECTION_IS_VALID( gc ) ) {
		purple_debug_error( MXIT_PLUGIN_ID, "Unable to update profile; account offline.\n" );
		return;
	}

	/* validate name */
	name = purple_request_fields_get_string( fields, "name" );
	if ( ( !name ) || ( strlen( name ) < 3 ) ) {
		err = _( "The Display Name you entered is invalid." );
		goto out;
	}

	/* validate birthdate */
	bday = purple_request_fields_get_string( fields, "bday" );
	if ( ( !bday ) || ( strlen( bday ) < 10 ) || ( !validateDate( bday ) ) ) {
		err = _( "The birthday you entered is invalid. The correct format is: 'YYYY-MM-DD'." );
		goto out;
	}

out:
	if ( !err ) {
		struct MXitProfile*	profile		= session->profile;
		GString*			attributes	= g_string_sized_new( 128 );
		char				attrib[512];
		unsigned int		acount		= 0;


		/* update name */
		g_strlcpy( profile->nickname, name, sizeof( profile->nickname ) );
		g_snprintf( attrib, sizeof( attrib ), "\01%s\01%i\01%s", CP_PROFILE_FULLNAME, CP_PROFILE_TYPE_UTF8, profile->nickname );
		g_string_append( attributes, attrib );
		acount++;

		/* update birthday */
		g_strlcpy( profile->birthday, bday, sizeof( profile->birthday ) );
		g_snprintf( attrib, sizeof( attrib ), "\01%s\01%i\01%s", CP_PROFILE_BIRTHDATE, CP_PROFILE_TYPE_UTF8, profile->birthday );
		g_string_append( attributes, attrib );
		acount++;

		/* update gender */
		profile->male = ( purple_request_fields_get_choice( fields, "male" ) != 0 );
		g_snprintf( attrib, sizeof( attrib ), "\01%s\01%i\01%s", CP_PROFILE_GENDER, CP_PROFILE_TYPE_BOOL, ( profile->male ) ? "1" : "0" );
		g_string_append( attributes, attrib );
		acount++;

		/* update title */
		name = purple_request_fields_get_string( fields, "title" );
		if ( !name )
			profile->title[0] = '\0';
		else
			g_strlcpy( profile->title, name, sizeof( profile->title ) );
		g_snprintf( attrib, sizeof( attrib ), "\01%s\01%i\01%s", CP_PROFILE_TITLE, CP_PROFILE_TYPE_UTF8, profile->title );
		g_string_append( attributes, attrib );
		acount++;

		/* update firstname */
		name = purple_request_fields_get_string( fields, "firstname" );
		if ( !name )
			profile->firstname[0] = '\0';
		else
			g_strlcpy( profile->firstname, name, sizeof( profile->firstname ) );
		g_snprintf( attrib, sizeof( attrib ), "\01%s\01%i\01%s", CP_PROFILE_FIRSTNAME, CP_PROFILE_TYPE_UTF8, profile->firstname );
		g_string_append( attributes, attrib );
		acount++;

		/* update lastname */
		name = purple_request_fields_get_string( fields, "lastname" );
		if ( !name )
			profile->lastname[0] = '\0';
		else
			g_strlcpy( profile->lastname, name, sizeof( profile->lastname ) );
		g_snprintf( attrib, sizeof( attrib ), "\01%s\01%i\01%s", CP_PROFILE_LASTNAME, CP_PROFILE_TYPE_UTF8, profile->lastname );
		g_string_append( attributes, attrib );
		acount++;

		/* update email address */
		name = purple_request_fields_get_string( fields, "email" );
		if ( !name )
			profile->email[0] = '\0';
		else
			g_strlcpy( profile->email, name, sizeof( profile->email ) );
		g_snprintf( attrib, sizeof( attrib ), "\01%s\01%i\01%s", CP_PROFILE_EMAIL, CP_PROFILE_TYPE_UTF8, profile->email );
		g_string_append( attributes, attrib );
		acount++;

		/* update mobile number */
		name = purple_request_fields_get_string( fields, "mobilenumber" );
		if ( !name )
			profile->mobilenr[0] = '\0';
		else
			g_strlcpy( profile->mobilenr, name, sizeof( profile->mobilenr ) );
		g_snprintf( attrib, sizeof( attrib ), "\01%s\01%i\01%s", CP_PROFILE_MOBILENR, CP_PROFILE_TYPE_UTF8, profile->mobilenr );
		g_string_append( attributes, attrib );
		acount++;

		/* update about me */
		name = purple_request_fields_get_string( fields, "aboutme" );
		if ( !name )
			profile->aboutme[0] = '\0';
		else
			g_strlcpy( profile->aboutme, name, sizeof( profile->aboutme ) );
		g_snprintf( attrib, sizeof( attrib ), "\01%s\01%i\01%s", CP_PROFILE_ABOUTME, CP_PROFILE_TYPE_UTF8, profile->aboutme );
		g_string_append( attributes, attrib );
		acount++;

		/* update where am i */
		name = purple_request_fields_get_string( fields, "whereami" );
		if ( !name )
			profile->whereami[0] = '\0';
		else
			g_strlcpy( profile->whereami, name, sizeof( profile->whereami ) );
		g_snprintf( attrib, sizeof( attrib ), "\01%s\01%i\01%s", CP_PROFILE_WHEREAMI, CP_PROFILE_TYPE_UTF8, profile->whereami );
		g_string_append( attributes, attrib );
		acount++;

		/* relationship status */
		field = purple_request_fields_get_field( fields, "relationship" );
		entry = g_list_first( purple_request_field_list_get_selected( field ) );
		profile->relationship = atoi( purple_request_field_list_get_data( field, entry->data ) );
		g_snprintf( attrib, sizeof( attrib ), "\01%s\01%i\01%i", CP_PROFILE_RELATIONSHIP, CP_PROFILE_TYPE_SHORT, profile->relationship );
		g_string_append( attributes, attrib );
		acount++;

		/* update flags */
		field = purple_request_fields_get_field( fields, "searchable" );
		if ( purple_request_field_bool_get_value( field ) )		/* is searchable -> clear not-searchable flag */
			profile->flags &= ~CP_PROF_NOT_SEARCHABLE;
		else
			profile->flags |= CP_PROF_NOT_SEARCHABLE;
		field = purple_request_fields_get_field( fields, "suggestable" );
		if ( purple_request_field_bool_get_value( field ) )		/* is suggestable -> clear not-suggestable flag */
			profile->flags &= ~CP_PROF_NOT_SUGGESTABLE;
		else
			profile->flags |= CP_PROF_NOT_SUGGESTABLE;
		g_snprintf( attrib, sizeof( attrib ), "\01%s\01%i\01%" G_GINT64_FORMAT, CP_PROFILE_FLAGS, CP_PROFILE_TYPE_LONG, profile->flags);
		g_string_append( attributes, attrib );
		acount++;

		/* send the profile update to MXit */
		mxit_send_extprofile_update( session, NULL, acount, attributes->str );
		g_string_free( attributes, TRUE );
	}
	else {
		/* show error to user */
		mxit_popup( PURPLE_NOTIFY_MSG_ERROR, _( "Profile Update Error" ), err );
	}
}


/*------------------------------------------------------------------------
 * Display and update the user's profile.
 *
 *  @param action	The action object
 */
static void mxit_profile_action( PurplePluginAction* action )
{
	PurpleConnection*			gc		= (PurpleConnection*) action->context;
	struct MXitSession*			session	= purple_connection_get_protocol_data( gc );
	struct MXitProfile*			profile	= session->profile;

	PurpleRequestFields*		fields	= NULL;
	PurpleRequestField*			field	= NULL;

	purple_debug_info( MXIT_PLUGIN_ID, "mxit_profile_action\n" );

	/* ensure that we actually have the user's profile information */
	if ( !profile ) {
		/* no profile information yet, so we cannot update */
		mxit_popup( PURPLE_NOTIFY_MSG_WARNING, _( "Profile" ), _( "Your profile information is not yet retrieved. Please try again later." ) );
		return;
	}

	fields = purple_request_fields_new();

	/* Public information - what other users can see */
	{
		PurpleRequestFieldGroup* public_group = purple_request_field_group_new( "Public information" );

		/* display name */
		field = purple_request_field_string_new( "name", _( "Display Name" ), profile->nickname, FALSE );
		purple_request_field_group_add_field( public_group, field );

		/* birthday */
		field = purple_request_field_string_new( "bday", _( "Birthday" ), profile->birthday, FALSE );
		purple_request_field_group_add_field( public_group, field );
		if ( profile->flags & CP_PROF_DOBLOCKED )
			purple_request_field_string_set_editable( field, FALSE );

		/* gender */
		field = purple_request_field_choice_new( "male", _( "Gender" ), ( profile->male ) ? 1 : 0 );
		purple_request_field_choice_add( field, _( "Female" ) );		/* 0 */
		purple_request_field_choice_add( field, _( "Male" ) );			/* 1 */
		purple_request_field_group_add_field( public_group, field );

		/* first name */
		field = purple_request_field_string_new( "firstname", _( "First Name" ), profile->firstname, FALSE );
		purple_request_field_group_add_field( public_group, field );

		/* last name */
		field = purple_request_field_string_new( "lastname", _( "Last Name" ), profile->lastname, FALSE );
		purple_request_field_group_add_field( public_group, field );

		/* about me */
		field = purple_request_field_string_new( "aboutme", _( "About Me" ), profile->aboutme, FALSE);
		purple_request_field_group_add_field( public_group, field );

		/* where I live */
		field = purple_request_field_string_new( "whereami", _( "Where I Live" ), profile->whereami, FALSE);
		purple_request_field_group_add_field( public_group, field );

		/* relationship status */
		field = purple_request_field_list_new( "relationship", _( "Relationship Status" ) );
		purple_request_field_list_set_multi_select( field, FALSE );
		purple_request_field_list_add_icon( field, mxit_relationship_to_name( MXIT_RELATIONSHIP_UNKNOWN ), NULL, g_strdup_printf( "%i", MXIT_RELATIONSHIP_UNKNOWN ) );
		purple_request_field_list_add_icon( field, mxit_relationship_to_name( MXIT_RELATIONSHIP_DONTSAY ), NULL, g_strdup_printf( "%i", MXIT_RELATIONSHIP_DONTSAY ) );
		purple_request_field_list_add_icon( field, mxit_relationship_to_name( MXIT_RELATIONSHIP_SINGLE ), NULL, g_strdup_printf( "%i", MXIT_RELATIONSHIP_SINGLE ) );
		purple_request_field_list_add_icon( field, mxit_relationship_to_name( MXIT_RELATIONSHIP_INVOLVED ), NULL, g_strdup_printf( "%i", MXIT_RELATIONSHIP_INVOLVED ) );
		purple_request_field_list_add_icon( field, mxit_relationship_to_name( MXIT_RELATIONSHIP_ENGAGED ), NULL, g_strdup_printf( "%i", MXIT_RELATIONSHIP_ENGAGED ) );
		purple_request_field_list_add_icon( field, mxit_relationship_to_name( MXIT_RELATIONSHIP_MARRIED ), NULL, g_strdup_printf( "%i", MXIT_RELATIONSHIP_MARRIED ) );
		purple_request_field_list_add_icon( field, mxit_relationship_to_name( MXIT_RELATIONSHIP_COMPLICATED ), NULL, g_strdup_printf( "%i", MXIT_RELATIONSHIP_COMPLICATED ) );
		purple_request_field_list_add_icon( field, mxit_relationship_to_name( MXIT_RELATIONSHIP_WIDOWED ), NULL, g_strdup_printf( "%i", MXIT_RELATIONSHIP_WIDOWED ) );
		purple_request_field_list_add_icon( field, mxit_relationship_to_name( MXIT_RELATIONSHIP_SEPARATED ), NULL, g_strdup_printf( "%i", MXIT_RELATIONSHIP_SEPARATED ) );
		purple_request_field_list_add_icon( field, mxit_relationship_to_name( MXIT_RELATIONSHIP_DIVORCED ), NULL, g_strdup_printf( "%i", MXIT_RELATIONSHIP_DIVORCED ) );
		purple_request_field_list_add_selected( field, mxit_relationship_to_name( profile->relationship ) );
		purple_request_field_group_add_field( public_group, field );

		purple_request_fields_add_group( fields, public_group );
	}

	/* Private information - what only MXit can see */
	{
		PurpleRequestFieldGroup* private_group = purple_request_field_group_new( "Private information" );

		/* title */
		field = purple_request_field_string_new( "title", _( "Title" ), profile->title, FALSE );
		purple_request_field_group_add_field( private_group, field );

		/* email */
		field = purple_request_field_string_new( "email", _( "Email" ), profile->email, FALSE );
		purple_request_field_group_add_field( private_group, field );

		/* mobile number */
		field = purple_request_field_string_new( "mobilenumber", _( "Mobile Number" ), profile->mobilenr, FALSE );
		purple_request_field_group_add_field( private_group, field );

		/* is searchable */
		field = purple_request_field_bool_new( "searchable", _( "Can be searched" ), ( ( profile->flags & CP_PROF_NOT_SEARCHABLE ) == 0) );
		purple_request_field_group_add_field( private_group, field );

		/* is suggestable */
		field = purple_request_field_bool_new( "suggestable", _( "Can be suggested" ), ( ( profile->flags & CP_PROF_NOT_SUGGESTABLE ) == 0 ) );
		purple_request_field_group_add_field( private_group, field );

		purple_request_fields_add_group( fields, private_group );
	}

	/* (reference: "libpurple/request.h") */
	purple_request_fields( gc, _( "Profile" ), _( "Update your MXit Profile" ), NULL, fields, _( "Set" ),
			G_CALLBACK( mxit_profile_cb ), _( "Cancel" ), NULL, purple_connection_get_account( gc ), NULL, NULL, gc );
}


/*------------------------------------------------------------------------
 * The user has selected to change their PIN.
 *
 *  @param gc		The connection object
 *  @param fields	The fields from the request pop-up
 */
static void mxit_change_pin_cb( PurpleConnection* gc, PurpleRequestFields* fields )
{
	struct MXitSession*		session	= purple_connection_get_protocol_data( gc );
	const char*				pin		= NULL;
	const char*				pin2	= NULL;
	const char*				err		= NULL;
	int						len;
	int						i;

	if ( !PURPLE_CONNECTION_IS_VALID( gc ) ) {
		purple_debug_error( MXIT_PLUGIN_ID, "Unable to update PIN; account offline.\n" );
		return;
	}

	/* validate pin */
	pin = purple_request_fields_get_string( fields, "pin" );
	if ( !pin ) {
		err = _( "The PIN you entered is invalid." );
		goto out;
	}
	len = strlen( pin );
	if ( ( len < 4 ) || ( len > 10 ) ) {
		err = _( "The PIN you entered has an invalid length [4-10]." );
		goto out;
	}
	for ( i = 0; i < len; i++ ) {
		if ( !g_ascii_isdigit( pin[i] ) ) {
			err = _( "The PIN is invalid. It should only consist of digits [0-9]." );
			goto out;
		}
	}
	pin2 = purple_request_fields_get_string( fields, "pin2" );
	if ( ( !pin2 ) || ( strcmp( pin, pin2 ) != 0 ) ) {
		err = _( "The two PINs you entered do not match." );
		goto out;
	}

out:
	if ( !err ) {
		/* update PIN in account */
		purple_account_set_password( session->acc, pin );

		/* update session object */
		g_free( session->encpwd );
		session->encpwd = mxit_encrypt_password( session );

		/* send the update request to MXit */
		mxit_send_extprofile_update( session, session->encpwd, 0, NULL );
	}
	else {
		/* show error to user */
		mxit_popup( PURPLE_NOTIFY_MSG_ERROR, _( "PIN Update Error" ), err );
	}
}


/*------------------------------------------------------------------------
 * Enable the user to change their PIN.
 *
 *  @param action	The action object
 */
static void mxit_change_pin_action( PurplePluginAction* action )
{
	PurpleConnection*			gc		= (PurpleConnection*) action->context;
	struct MXitSession*			session	= purple_connection_get_protocol_data( gc );

	PurpleRequestFields*		fields	= NULL;
	PurpleRequestFieldGroup*	group	= NULL;
	PurpleRequestField*			field	= NULL;

	purple_debug_info( MXIT_PLUGIN_ID, "mxit_change_pin_action\n" );

	fields = purple_request_fields_new();
	group = purple_request_field_group_new( NULL );
	purple_request_fields_add_group( fields, group );

	/* pin */
	field = purple_request_field_string_new( "pin", _( "PIN" ), purple_account_get_password( session->acc ), FALSE );
	purple_request_field_string_set_masked( field, TRUE );
	purple_request_field_group_add_field( group, field );

	/* verify pin */
	field = purple_request_field_string_new( "pin2", _( "Verify PIN" ), purple_account_get_password( session->acc ), FALSE );
	purple_request_field_string_set_masked( field, TRUE );
	purple_request_field_group_add_field( group, field );

	/* (reference: "libpurple/request.h") */
	purple_request_fields( gc, _( "Change PIN" ), _( "Change MXit PIN" ), NULL, fields, _( "Set" ),
			G_CALLBACK( mxit_change_pin_cb ), _( "Cancel" ), NULL, purple_connection_get_account( gc ), NULL, NULL, gc );
}


/*------------------------------------------------------------------------
 * Display the current splash-screen, or a notification pop-up if one is not available.
 *
 *  @param action	The action object
 */
static void mxit_splash_action( PurplePluginAction* action )
{
	PurpleConnection*		gc		= (PurpleConnection*) action->context;
	struct MXitSession*		session	= purple_connection_get_protocol_data( gc );

	if ( splash_current( session ) != NULL )
		splash_display( session );
	else
		mxit_popup( PURPLE_NOTIFY_MSG_INFO, _( "View Splash" ), _( "There is no splash-screen currently available" ) );
}


/*------------------------------------------------------------------------
 * Display info about the plugin.
 *
 *  @param action	The action object
 */
static void mxit_about_action( PurplePluginAction* action )
{
	char	version[256];

	g_snprintf( version, sizeof( version ),
											"MXit Client Protocol v%i.%i\n\n"
											"Author:\nPieter Loubser\n\n"
											"Contributors:\nAndrew Victor\n\n"
											"Testers:\nBraeme Le Roux\n\n",
											( MXIT_CP_PROTO_VESION / 10 ), ( MXIT_CP_PROTO_VESION % 10 ) );

	mxit_popup( PURPLE_NOTIFY_MSG_INFO, _( "About" ), version );
}


/*------------------------------------------------------------------------
 * Request list of suggested friends.
 *
 *  @param action	The action object
 */
static void mxit_suggested_friends_action( PurplePluginAction* action )
{
	PurpleConnection*		gc				= (PurpleConnection*) action->context;
	struct MXitSession*		session			= purple_connection_get_protocol_data( gc );
	const char*				profilelist[]	= {
				CP_PROFILE_BIRTHDATE, CP_PROFILE_GENDER, CP_PROFILE_FULLNAME, CP_PROFILE_FIRSTNAME,
				CP_PROFILE_LASTNAME, CP_PROFILE_REGCOUNTRY, CP_PROFILE_STATUS, CP_PROFILE_AVATAR,
				CP_PROFILE_WHEREAMI, CP_PROFILE_ABOUTME };

	mxit_send_suggest_friends( session, MXIT_SEARCHRESULTS_MAX, ARRAY_SIZE( profilelist ), profilelist );
}


/*------------------------------------------------------------------------
 * Perform contact search.
 *
 *  @param action	The action object
 */
static void mxit_user_search_cb( PurpleConnection *gc, const char *input )
{
	struct MXitSession*		session			= purple_connection_get_protocol_data( gc );
	const char*				profilelist[]	= {
				CP_PROFILE_BIRTHDATE, CP_PROFILE_GENDER, CP_PROFILE_FULLNAME, CP_PROFILE_FIRSTNAME,
				CP_PROFILE_LASTNAME, CP_PROFILE_REGCOUNTRY, CP_PROFILE_STATUS, CP_PROFILE_AVATAR,
				CP_PROFILE_WHEREAMI, CP_PROFILE_ABOUTME };

	mxit_send_suggest_search( session, MXIT_SEARCHRESULTS_MAX, input, ARRAY_SIZE( profilelist ), profilelist );
}


/*------------------------------------------------------------------------
 * Display the search input form.
 *
 *  @param action	The action object
 */
static void mxit_user_search_action( PurplePluginAction* action )
{
	PurpleConnection*		gc				= (PurpleConnection*) action->context;

	purple_request_input( gc, _( "Search for user" ),
		_( "Search for a MXit contact" ),
		_( "Type search information" ),
		NULL, FALSE, FALSE, NULL,
		_( "_Search" ), G_CALLBACK( mxit_user_search_cb ),
		_( "_Cancel" ), NULL,
		purple_connection_get_account( gc ), NULL, NULL,
		gc );
}


/*------------------------------------------------------------------------
 * Associate actions with the MXit plugin.
 *
 *  @param plugin	The MXit protocol plugin
 *  @param context	The connection context (if available)
 *  @return			The list of plugin actions
 */
GList* mxit_actions( PurplePlugin* plugin, gpointer context )
{
	PurplePluginAction*		action	= NULL;
	GList*					m		= NULL;

	/* display / change profile */
	action = purple_plugin_action_new( _( "Change Profile..." ), mxit_profile_action );
	m = g_list_append( m, action );

	/* change PIN */
	action = purple_plugin_action_new( _( "Change PIN..." ), mxit_change_pin_action );
	m = g_list_append( m, action );

	/* suggested friends */
	action = purple_plugin_action_new( _( "Suggested friends..." ), mxit_suggested_friends_action );
	m = g_list_append( m, action );

	/* search for contacts */
	action = purple_plugin_action_new( _( "Search for contacts..." ), mxit_user_search_action );
	m = g_list_append( m, action );

	/* display splash-screen */
	action = purple_plugin_action_new( _( "View Splash..." ), mxit_splash_action );
	m = g_list_append( m, action );

	/* display plugin version */
	action = purple_plugin_action_new( _( "About..." ), mxit_about_action );
	m = g_list_append( m, action );

	return m;
}
