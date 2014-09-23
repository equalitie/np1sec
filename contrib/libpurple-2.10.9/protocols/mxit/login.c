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

#include	"internal.h"
#include	"debug.h"
#include	"request.h"
#include	"version.h"

#include	"protocol.h"
#include	"mxit.h"
#include	"cipher.h"
#include	"login.h"
#include	"profile.h"

/* requesting captcha size */
#define		MXIT_CAPTCHA_HEIGHT		50
#define		MXIT_CAPTCHA_WIDTH		150


/* prototypes */
static void mxit_register_view( struct MXitSession* session );
static void get_clientinfo( struct MXitSession* session );


/*------------------------------------------------------------------------
 * Create a new mxit session object
 *
 * @return The MXit session object
 */
static struct MXitSession* mxit_create_object( PurpleAccount* account )
{
	PurpleConnection*	con			= purple_account_get_connection( account );
	struct MXitSession*	session		= NULL;

	/* currently the wapsite does not handle a '+' in front of the username (mxitid) so we just strip it */
	{
		const char* username	= purple_account_get_username( account );

		if ( username[0] == '+' ) {
			char* fixed = g_strdup( &username[1] );
			purple_account_set_username( account, fixed );
			g_free( fixed );
		}
	}

	session = g_new0( struct MXitSession, 1 );
	session->con = con;
	session->acc = account;

	/* configure the connection (reference: "libpurple/connection.h") */
	purple_connection_set_protocol_data( con, session );
	con->flags |= PURPLE_CONNECTION_NO_BGCOLOR | PURPLE_CONNECTION_NO_URLDESC | PURPLE_CONNECTION_HTML | PURPLE_CONNECTION_SUPPORT_MOODS;

	/* configure the session (reference: "libpurple/account.h") */
	g_strlcpy( session->server, purple_account_get_string( account, MXIT_CONFIG_SERVER_ADDR, DEFAULT_SERVER ), sizeof( session->server ) );
	g_strlcpy( session->http_server, purple_account_get_string( account, MXIT_CONFIG_HTTPSERVER, DEFAULT_HTTP_SERVER ), sizeof( session->http_server ) );
	session->port = purple_account_get_int( account, MXIT_CONFIG_SERVER_PORT, DEFAULT_PORT );
	g_strlcpy( session->distcode, purple_account_get_string( account, MXIT_CONFIG_DISTCODE, "" ), sizeof( session->distcode ) );
	g_strlcpy( session->clientkey, purple_account_get_string( account, MXIT_CONFIG_CLIENTKEY, "" ), sizeof( session->clientkey ) );
	g_strlcpy( session->dialcode, purple_account_get_string( account, MXIT_CONFIG_DIALCODE, "" ), sizeof( session->dialcode ) );
	session->http = purple_account_get_bool( account, MXIT_CONFIG_USE_HTTP, FALSE );
	session->iimages = g_hash_table_new( g_str_hash, g_str_equal );
	session->rx_state = RX_STATE_RLEN;
	session->http_interval = MXIT_HTTP_POLL_MIN;
	session->http_last_poll = mxit_now_milli();

	return session;
}


/*------------------------------------------------------------------------
 * We now have a connection established with MXit, so we can start the
 * login procedure
 *
 * @param session	The MXit session object
 */
static void mxit_connected( struct MXitSession* session )
{
	int			state;

	purple_debug_info( MXIT_PLUGIN_ID, "mxit_connected\n" );

	session->flags |= MXIT_FLAG_CONNECTED;
	purple_connection_update_progress( session->con, _( "Logging In..." ), 2, 4 );

	/* create a timer to send a ping packet if the connection is idle */
	session->last_tx = mxit_now_milli();

	/* encrypt the user password */
	session->encpwd = mxit_encrypt_password( session );

	state = purple_account_get_int( session->acc, MXIT_CONFIG_STATE, MXIT_STATE_LOGIN );
	if ( state == MXIT_STATE_LOGIN ) {
		/* create and send login packet */
		mxit_send_login( session );
	}
	else {
		if ( !session->profile ) {
			/* we have lost the session profile, so ask the user to enter it again */
			mxit_register_view( session );
		}
		else {
			/* create and send the register packet */
			mxit_send_register( session );
		}
	}

	/* enable signals */
	mxit_enable_signals( session );

#ifdef		MXIT_LINK_CLICK
	/* register for uri click notification */
	mxit_register_uri_handler();
#endif

	/* start the polling if this is a HTTP connection */
	if ( session->http ) {
		session->http_timer_id = purple_timeout_add_seconds( 2, mxit_manage_polling, session );
	}

	/* This timer might already exist if we're registering a new account */
	if ( session->q_slow_timer_id == 0 ) {
		/* start the tx queue manager timer */
		session->q_slow_timer_id = purple_timeout_add_seconds( 2, mxit_manage_queue_slow, session );
	}
}


/*------------------------------------------------------------------------
 * Callback invoked once the connection has been established to the MXit server,
 * or on connection failure.
 *
 *  @param user_data		The MXit session object
 *  @param source			The file-descriptor associated with the connection
 *  @param error_message	Message explaining why the connection failed
 */
static void mxit_cb_connect( gpointer user_data, gint source, const gchar* error_message )
{
	struct MXitSession*	session		= (struct MXitSession*) user_data;

	purple_debug_info( MXIT_PLUGIN_ID, "mxit_cb_connect\n" );

	/* source is the file descriptor of the new connection */
	if ( source < 0 ) {
		purple_debug_info( MXIT_PLUGIN_ID, "mxit_cb_connect failed: %s\n", error_message );
		purple_connection_error( session->con, _( "Unable to connect to the MXit server. Please check your server settings." ) );
		return;
	}

	/* we now have an open and active TCP connection to the mxit server */
	session->fd = source;

	/* start listening on the open connection for messages from the server (reference: "libpurple/eventloop.h") */
	session->con->inpa = purple_input_add( session->fd, PURPLE_INPUT_READ, mxit_cb_rx, session );

	mxit_connected( session );
}


/*------------------------------------------------------------------------
 * Attempt to establish a connection to the MXit server.
 *
 *  @param session			The MXit session object
 */
static void mxit_login_connect( struct MXitSession* session )
{
	PurpleProxyConnectData*		data	= NULL;

	purple_debug_info( MXIT_PLUGIN_ID, "mxit_login_connect\n" );

	purple_connection_update_progress( session->con, _( "Connecting..." ), 1, 4 );

	/*
	 * at this stage we have all the user's information we require
	 * for logging into MXit. we will now create a new connection to
	 * a MXit server.
	 */

	if ( !session->http ) {
		/* socket connection */
		data = purple_proxy_connect( session->con, session->acc, session->server, session->port, mxit_cb_connect, session );
		if ( !data ) {
			purple_connection_error( session->con, _( "Unable to connect to the MXit server. Please check your server settings." ) );
			return;
		}
	}
	else {
		/* http connection */
		mxit_connected( session );
	}
}


/*------------------------------------------------------------------------
 * Register a new account with MXit
 *
 * @param gc		The connection object
 * @param fields	This is the fields filled-in by the user
 */
static void mxit_cb_register_ok( PurpleConnection *gc, PurpleRequestFields *fields )
{
	struct MXitSession*		session		= purple_connection_get_protocol_data( gc );
	struct MXitProfile*		profile		= session->profile;
	const char*				str;
	const char*				pin;
	const char*				err			= NULL;
	int						len;
	int						i;

	purple_debug_info( MXIT_PLUGIN_ID, "mxit_cb_register_ok\n" );

	if ( !PURPLE_CONNECTION_IS_VALID( gc ) ) {
		purple_debug_error( MXIT_PLUGIN_ID, "Unable to register; account offline.\n" );
		return;
	}

	/* nickname */
	str = purple_request_fields_get_string( fields, "nickname" );
	if ( ( !str ) || ( strlen( str ) < 3 ) ) {
		err = _( "The Display Name you entered is too short." );
		goto out;
	}
	g_strlcpy( profile->nickname, str, sizeof( profile->nickname ) );

	/* birthdate */
	str = purple_request_fields_get_string( fields, "bday" );
	if ( ( !str ) || ( strlen( str ) < 10 ) || ( !validateDate( str ) ) ) {
		err = _( "The birthday you entered is invalid. The correct format is: 'YYYY-MM-DD'." );
		goto out;
	}
	g_strlcpy( profile->birthday, str, sizeof( profile->birthday ) );

	/* gender */
	profile->male = ( purple_request_fields_get_choice( fields, "male" ) != 0 );

	/* pin */
	pin = purple_request_fields_get_string( fields, "pin" );
	if ( !pin ) {
		err = _( "The PIN you entered is invalid." );
		goto out;
	}
	len = strlen( pin );
	if ( ( len < 7 ) || ( len > 10 ) ) {
		err = _( "The PIN you entered has an invalid length [7-10]." );
		goto out;
	}
	for ( i = 0; i < len; i++ ) {
		if ( !g_ascii_isdigit( pin[i] ) ) {
			err = _( "The PIN is invalid. It should only consist of digits [0-9]." );
			goto out;
		}
	}
	str = purple_request_fields_get_string( fields, "pin2" );
	if ( ( !str ) || ( strcmp( pin, str ) != 0 ) ) {
		err = _( "The two PINs you entered do not match." );
		goto out;
	}
	g_strlcpy( profile->pin, pin, sizeof( profile->pin ) );

out:
	if ( !err ) {
		purple_account_set_password( session->acc, session->profile->pin );
		mxit_login_connect( session );
	}
	else {
		/* show error to user */
		mxit_popup( PURPLE_NOTIFY_MSG_ERROR, _( "Registration Error" ), err );
		mxit_register_view( session );
	}
}


/*------------------------------------------------------------------------
 * Register a new account with MXit
 *
 * @param gc		The connection object
 * @param fields	This is the fields filled-in by the user
 */
static void mxit_cb_register_cancel( PurpleConnection *gc, PurpleRequestFields *fields )
{
	purple_debug_info( MXIT_PLUGIN_ID, "mxit_cb_register_cancel\n" );

	/* disconnect */
	purple_account_disconnect( purple_connection_get_account( gc ) );
}


/*------------------------------------------------------------------------
 * Show a window to the user so that he can enter his information
 *
 *  @param session		The MXit session object
 */
static void mxit_register_view( struct MXitSession* session )
{
	struct MXitProfile*			profile;
	PurpleRequestFields*		fields;
	PurpleRequestFieldGroup*	group;
	PurpleRequestField*			field;

	if ( !session->profile ) {
		/* we need to create a profile object here */
		session->profile = g_new0( struct MXitProfile, 1 );
	}
	profile = session->profile;

	fields = purple_request_fields_new();
	group = purple_request_field_group_new( NULL );
	purple_request_fields_add_group( fields, group );

	/* mxit login name */
	field = purple_request_field_string_new( "loginname", _( "MXit ID" ), purple_account_get_username( session->acc ), FALSE );
	purple_request_field_string_set_editable( field, FALSE );
	purple_request_field_group_add_field( group, field );

	/* nick name (required) */
	field = purple_request_field_string_new( "nickname", _( "Display Name" ), profile->nickname, FALSE );
	purple_request_field_set_required( field, TRUE );
	purple_request_field_group_add_field( group, field );

	/* birthday (required) */
	field = purple_request_field_string_new( "bday", _( "Birthday" ), profile->birthday, FALSE );
	purple_request_field_string_set_default_value( field, "YYYY-MM-DD" );
	purple_request_field_set_required( field, TRUE );
	purple_request_field_group_add_field( group, field );

	/* gender */
	field = purple_request_field_choice_new( "male", _( "Gender" ), ( profile->male ) ? 1 : 0 );
	purple_request_field_choice_add( field, _( "Female" ) );		/* 0 */
	purple_request_field_choice_add( field, _( "Male" ) );			/* 1 */
	purple_request_field_group_add_field( group, field );

	/* pin (required) */
	field = purple_request_field_string_new( "pin", _( "PIN" ), profile->pin, FALSE );
	purple_request_field_string_set_masked( field, TRUE );
	purple_request_field_set_required( field, TRUE );
	purple_request_field_group_add_field( group, field );
	field = purple_request_field_string_new( "pin2", _( "Verify PIN" ), "", FALSE );
	purple_request_field_string_set_masked( field, TRUE );
	purple_request_field_set_required( field, TRUE );
	purple_request_field_group_add_field( group, field );

	/* show the form to the user to complete */
	purple_request_fields( session->con, _( "Register New MXit Account" ), _( "Register New MXit Account" ), _( "Please fill in the following fields:" ), fields, _( "OK" ), G_CALLBACK( mxit_cb_register_ok ), _( "Cancel" ), G_CALLBACK( mxit_cb_register_cancel ), session->acc, NULL, NULL, session->con );
}


/*------------------------------------------------------------------------
 * Callback function invoked once the Authorization information has been submitted
 * to the MXit WAP site.
 *
 *  @param url_data			libPurple internal object (see purple_util_fetch_url_request)
 *  @param user_data		The MXit session object
 *  @param url_text			The data returned from the WAP site
 *  @param len				The length of the data returned
 *  @param error_message	Descriptive error message
 */
static void mxit_cb_clientinfo2( PurpleUtilFetchUrlData* url_data, gpointer user_data, const gchar* url_text, gsize len, const gchar* error_message )
{
	struct MXitSession*		session		= (struct MXitSession*) user_data;
	gchar**					parts;
	gchar**					host;
	int						state;

	purple_debug_info( MXIT_PLUGIN_ID, "mxit_clientinfo_cb2\n" );

#ifdef	DEBUG_PROTOCOL
	purple_debug_info( MXIT_PLUGIN_ID, "HTTP RESPONSE: '%s'\n", url_text );
#endif

	/* remove request from the async outstanding calls list */
	session->async_calls = g_slist_remove( session->async_calls, url_data );

	if ( !url_text ) {
		/* no reply from the WAP site */
		purple_connection_error( session->con, _( "Error contacting the MXit WAP site. Please try again later." ) );
		return;
	}

	/* explode the response from the WAP site into an array */
	parts = g_strsplit( url_text, ";", 15 );

	if ( !parts ) {
		/* wapserver error */
		purple_connection_error( session->con, _( "MXit is currently unable to process the request. Please try again later." ) );
		return;
	}

	/* check wapsite return code */
	switch ( parts[0][0] ) {
			case '0' :
				/* valid reply! */
				break;
			case '1' :
				purple_connection_error( session->con, _( "Wrong security code entered. Please try again later." ) );
				return;
			case '2' :
				purple_connection_error( session->con, _( "Your session has expired. Please try again later." ) );
				return;
			case '5' :
				purple_connection_error( session->con, _( "Invalid country selected. Please try again." ) );
				return;
			case '6' :
				purple_connection_error( session->con, _( "The MXit ID you entered is not registered. Please register first." ) );
				return;
			case '7' :
				purple_connection_error( session->con, _( "The MXit ID you entered is already registered. Please choose another." ) );
				/* this user's account already exists, so we need to change the registration login flag to be login */
				purple_account_set_int( session->acc, MXIT_CONFIG_STATE, MXIT_STATE_LOGIN );
				return;
			case '3' :
			case '4' :
			default :
				purple_connection_error( session->con, _( "Internal error. Please try again later." ) );
				return;
	}

	/* now parse and split the distribution code and the client key */
	g_strlcpy( session->distcode, &parts[1][2], 36 + 1 );
	g_strlcpy( session->clientkey, &parts[1][38], 8 + 1 );

	/* get the dial code for the client */
	g_strlcpy( session->dialcode, parts[4], sizeof( session->dialcode ) );

	/* parse the proxy server address and port number */
	host = g_strsplit( parts[2], ":", 4 );
	g_strlcpy( session->server, &host[1][2], sizeof( session->server ) );
	session->port = atoi( &host[2][0] );

	/* parse the http proxy server address and port number */
	g_strlcpy( session->http_server, parts[3], sizeof( session->http_server ) );

	purple_debug_info( MXIT_PLUGIN_ID, "distcode='%s', clientkey='%s', dialcode='%s'\n", session->distcode, session->clientkey, session->dialcode );
	purple_debug_info( MXIT_PLUGIN_ID, "sock_server='%s', http_server='%s', port='%i', cc='%s'\n", session->server, session->http_server, session->port, parts[11] );

	/* save the information (reference: "libpurple/account.h") */
	purple_account_set_string( session->acc, MXIT_CONFIG_DISTCODE, session->distcode );
	purple_account_set_string( session->acc, MXIT_CONFIG_CLIENTKEY, session->clientkey );
	purple_account_set_string( session->acc, MXIT_CONFIG_DIALCODE, session->dialcode );
	purple_account_set_string( session->acc, MXIT_CONFIG_SERVER_ADDR, session->server );
	purple_account_set_int( session->acc, MXIT_CONFIG_SERVER_PORT, session->port );
	purple_account_set_string( session->acc, MXIT_CONFIG_HTTPSERVER, session->http_server );

	/* update the state */
	state = purple_account_get_int( session->acc, MXIT_CONFIG_STATE, MXIT_STATE_LOGIN );
	if ( state == MXIT_STATE_REGISTER1 )
		purple_account_set_int( session->acc, MXIT_CONFIG_STATE, MXIT_STATE_REGISTER2 );

	/* freeup the memory */
	g_strfreev( host );
	g_strfreev( parts );

	if ( state == MXIT_STATE_LOGIN ) {
		/* now we can continue with the login process */
		mxit_login_connect( session );
	}
	else {
		/* the user is registering so we need to get more information from him/her first to complete the process */
		mxit_register_view( session );
	}
}


/*------------------------------------------------------------------------
 * Free up the data associated with the Authorization process.
 *
 *  @param data			The data object to free
 */
static void free_logindata( struct login_data* data )
{
	if ( !data )
		return;

	/* free up the login resources */
	g_free( data->wapserver );
	g_free( data->sessionid );
	g_free( data->captcha );
	g_free( data->cc );
	g_free( data->locale );
	g_free( data );
}


/*------------------------------------------------------------------------
 * This function is called when the user accepts the Authorization form.
 *
 *  @param gc				The connection object
 *  @param fields			The list of fields in the accepted form
 */
static void mxit_cb_captcha_ok( PurpleConnection* gc, PurpleRequestFields* fields )
{
	struct MXitSession*		session	= purple_connection_get_protocol_data( gc );
	PurpleUtilFetchUrlData*	url_data;
	PurpleRequestField*		field;
	const char*				captcha_resp;
	GList*					entries;
	GList*					entry;
	char*					url;
	int						state;

	/* get the captcha response */
	captcha_resp = purple_request_fields_get_string( fields, "code" );
	if ( ( captcha_resp == NULL ) || ( captcha_resp[0] == '\0' ) ) {
		/* the user did not fill in the captcha */
		mxit_popup( PURPLE_NOTIFY_MSG_ERROR, _( "Error" ), _( "You did not enter the security code" ) );
		free_logindata( session->logindata );
		purple_account_disconnect( session->acc );
		return;
	}

	/* get chosen country */
	field = purple_request_fields_get_field( fields, "country" );
	entries = purple_request_field_list_get_selected( field );
	entry = g_list_first( entries );
	session->logindata->cc = purple_request_field_list_get_data( field, entry->data );
	purple_account_set_string( session->acc, MXIT_CONFIG_COUNTRYCODE, session->logindata->cc );

	/* get chosen language */
	field = purple_request_fields_get_field( fields, "locale" );
	entries = purple_request_field_list_get_selected( field );
	entry = g_list_first( entries );
	session->logindata->locale = purple_request_field_list_get_data( field, entry->data );
	purple_account_set_string( session->acc, MXIT_CONFIG_LOCALE, session->logindata->locale );

#ifdef	DEBUG_PROTOCOL
	purple_debug_info( MXIT_PLUGIN_ID, "cc='%s', locale='%s', captcha='%s'\n", session->logindata->cc, session->logindata->locale, captcha_resp );
#endif

	/* get state */
	state = purple_account_get_int( session->acc, MXIT_CONFIG_STATE, MXIT_STATE_LOGIN );

	url = g_strdup_printf( "%s?type=getpid&sessionid=%s&login=%s&ver=%i.%i.%i&clientid=%s&cat=%s&chalresp=%s&cc=%s&loc=%s&path=%i&brand=%s&model=%s&h=%i&w=%i&ts=%li",
			session->logindata->wapserver,
			session->logindata->sessionid,
			purple_url_encode( purple_account_get_username( session->acc ) ),
			PURPLE_MAJOR_VERSION, PURPLE_MINOR_VERSION, PURPLE_MICRO_VERSION,
			MXIT_CLIENT_ID,
			MXIT_CP_ARCH,
			captcha_resp,
			session->logindata->cc,
			session->logindata->locale,
			( state == MXIT_STATE_REGISTER1 ) ? 0 : 1,
			MXIT_CP_PLATFORM,
			MXIT_CP_OS,
			MXIT_CAPTCHA_HEIGHT,
			MXIT_CAPTCHA_WIDTH,
			time( NULL )
	);
	url_data = purple_util_fetch_url_request( url, TRUE, MXIT_HTTP_USERAGENT, TRUE, NULL, FALSE, mxit_cb_clientinfo2, session );
	if ( url_data )
		session->async_calls = g_slist_prepend( session->async_calls, url_data );

#ifdef	DEBUG_PROTOCOL
	purple_debug_info( MXIT_PLUGIN_ID, "HTTP REQUEST: '%s'\n", url );
#endif
	g_free( url );

	/* free up the login resources */
	free_logindata( session->logindata );
}


/*------------------------------------------------------------------------
 * This function is called when the user cancels the Authorization form.
 *
 *  @param gc				The connection object
 *  @param fields			The list of fields in the cancelled form
 */
static void mxit_cb_captcha_cancel( PurpleConnection* gc, PurpleRequestFields* fields )
{
	struct MXitSession*		session	= purple_connection_get_protocol_data( gc );

	/* free up the login resources */
	free_logindata( session->logindata );

	/* we cannot continue, so we disconnect this account */
	purple_account_disconnect( session->acc );
}


/*------------------------------------------------------------------------
 * Callback function invoked once the client information has been retrieved from
 * the MXit WAP site.  Display page where user can select their authorization information.
 *
 *  @param url_data			libPurple internal object (see purple_util_fetch_url_request)
 *  @param user_data		The MXit session object
 *  @param url_text			The data returned from the WAP site
 *  @param len				The length of the data returned
 *  @param error_message	Descriptive error message
 */
static void mxit_cb_clientinfo1( PurpleUtilFetchUrlData* url_data, gpointer user_data, const gchar* url_text, gsize len, const gchar* error_message )
{
	struct MXitSession*			session		= (struct MXitSession*) user_data;
	struct login_data*			logindata;
	PurpleRequestFields*		fields;
	PurpleRequestFieldGroup*	group		= NULL;
	PurpleRequestField*			field		= NULL;
	gchar**						parts;
	gchar**						countries;
	gchar**						locales;
	int							i;

	purple_debug_info( MXIT_PLUGIN_ID, "mxit_clientinfo_cb1\n" );

#ifdef	DEBUG_PROTOCOL
	purple_debug_info( MXIT_PLUGIN_ID, "RESPONSE: %s\n", url_text );
#endif

	/* remove request from the async outstanding calls list */
	session->async_calls = g_slist_remove( session->async_calls, url_data );

	if ( !url_text ) {
		/* no reply from the WAP site */
		purple_connection_error( session->con, _( "Error contacting the MXit WAP site. Please try again later." ) );
		return;
	}

	/* explode the response from the WAP site into an array */
	parts = g_strsplit( url_text, ";", 15 );

	if ( ( !parts ) || ( parts[0][0] != '0' ) ) {
		/* server could not find the user */
		purple_connection_error( session->con, _( "MXit is currently unable to process the request. Please try again later." ) );
		return;
	}

	/* save received settings */
	logindata = g_new0( struct login_data, 1 );
	logindata->wapserver = g_strdup( parts[1] );
	logindata->sessionid = g_strdup( parts[2] );
	session->logindata = logindata;

	/* now generate the popup requesting the user for action */

	fields = purple_request_fields_new();
	group = purple_request_field_group_new( NULL );
	purple_request_fields_add_group( fields, group );

	/* add the captcha */
	logindata->captcha = purple_base64_decode( parts[3], &logindata->captcha_size );
	field = purple_request_field_image_new( "captcha", _( "Security Code" ), (gchar*) logindata->captcha, logindata->captcha_size );
	purple_request_field_group_add_field( group, field );

	/* ask for input (required) */
	field = purple_request_field_string_new( "code", _( "Enter Security Code" ), NULL, FALSE );
	purple_request_field_set_required( field, TRUE );
	purple_request_field_group_add_field( group, field );

	/* choose your country, but be careful, we already know your IP! ;-) */
	countries = g_strsplit( parts[4], ",", 500 );
	field = purple_request_field_list_new( "country", _( "Your Country" ) );
	purple_request_field_list_set_multi_select( field, FALSE );
	for ( i = 0; countries[i]; i++ ) {
		gchar**		country;

		country = g_strsplit( countries[i], "|", 2 );
		if ( !country ) {
			/* oops, this is not good, time to bail */
			break;
		}
		purple_request_field_list_add( field, country[1], g_strdup( country[0] ) );
		if ( strcmp( country[1], parts[6] ) == 0 ) {
			/* based on the user's IP, this is his current country code, so we default to it */
			purple_request_field_list_add_selected( field, country[1] );
		}
		g_strfreev( country );
	}
	purple_request_field_group_add_field( group, field );

	/* choose your language */
	locales = g_strsplit( parts[5], ",", 200 );
	field = purple_request_field_list_new( "locale", _( "Your Language" ) );
	purple_request_field_list_set_multi_select( field, FALSE );
	for ( i = 0; locales[i]; i++ ) {
		gchar**		locale;

		locale = g_strsplit( locales[i], "|", 2 );
		if ( !locale ) {
			/* oops, this is not good, time to bail */
			break;
		}
		purple_request_field_list_add( field, locale[1], g_strdup( locale[0] ) );
		g_strfreev( locale );
	}
	purple_request_field_list_add_selected( field, "English" );
	purple_request_field_group_add_field( group, field );

	/* display the form to the user and wait for his/her input */
	purple_request_fields( session->con, "MXit", _( "MXit Authorization" ), _( "MXit account validation" ), fields,
			_( "Continue" ), G_CALLBACK( mxit_cb_captcha_ok ), _( "Cancel" ), G_CALLBACK( mxit_cb_captcha_cancel ), session->acc, NULL, NULL, session->con );

	/* freeup the memory */
	g_strfreev( parts );
}


/*------------------------------------------------------------------------
 * Initiate a request for the client information (distribution code, client key, etc)
 *  required for logging in from the MXit WAP site.
 *
 *  @param session		The MXit session object
 */
static void get_clientinfo( struct MXitSession* session )
{
	PurpleUtilFetchUrlData*	url_data;
	const char*				wapserver;
	char*					url;

	purple_debug_info( MXIT_PLUGIN_ID, "get_clientinfo\n" );

	purple_connection_update_progress( session->con, _( "Retrieving User Information..." ), 0, 4 );

	/* get the WAP site as was configured by the user in the advanced settings */
	wapserver = purple_account_get_string( session->acc, MXIT_CONFIG_WAPSERVER, DEFAULT_WAPSITE );

	/* reference: "libpurple/util.h" */
	url = g_strdup_printf( "%s/res/?type=challenge&getcountries=true&getlanguage=true&getimage=true&h=%i&w=%i&ts=%li", wapserver, MXIT_CAPTCHA_HEIGHT, MXIT_CAPTCHA_WIDTH, time( NULL ) );
	url_data = purple_util_fetch_url_request( url, TRUE, MXIT_HTTP_USERAGENT, TRUE, NULL, FALSE, mxit_cb_clientinfo1, session );
	if ( url_data )
		session->async_calls = g_slist_prepend( session->async_calls, url_data );

#ifdef	DEBUG_PROTOCOL
	purple_debug_info( MXIT_PLUGIN_ID, "HTTP REQUEST: '%s'\n", url );
#endif
	g_free( url );
}


/*------------------------------------------------------------------------
 * Log the user into MXit.
 *
 *  @param account		The account object
 */
void mxit_login( PurpleAccount* account )
{
	struct MXitSession*		session		= NULL;

	purple_debug_info( MXIT_PLUGIN_ID, "mxit_login\n" );

	/* create and save a new mxit session */
	session = mxit_create_object( account );

	/*
	 * before we can login we need to have a valid distribution code and client key for authentication.
	 * if we don't have any info saved from a previous login, we need to get it from the MXit WAP site.
	 * we do cache it, so this step is only done on the very first login for each account.
	 */
	if ( strlen( session->distcode ) == 0 ) {
		/* this must be the very first login, so we need to retrieve the user information */
		get_clientinfo( session );
	}
	else {
		/* we can continue with the login */
		mxit_login_connect( session );
	}
}


/*------------------------------------------------------------------------
 * Perform a reconnect to the MXit server, and maintain same session object.
 *
 *  @param account		The account object
 */
void mxit_reconnect( struct MXitSession* session )
{
	purple_debug_info( MXIT_PLUGIN_ID, "mxit_reconnect\n" );

	/* remove the input cb function */
	if ( session->con->inpa ) {
		purple_input_remove( session->con->inpa );
		session->con->inpa = 0;
	}

	/* close existing connection */
	session->flags &= ~MXIT_FLAG_CONNECTED;
	purple_proxy_connect_cancel_with_handle( session->con );

	/* perform the re-connect */
	mxit_login_connect( session );
}


/*------------------------------------------------------------------------
 * Register a new account with MXit
 *
 * @param acc		The account object
 */
void mxit_register( PurpleAccount* account )
{
	struct MXitSession*		session		= NULL;

	purple_debug_info( MXIT_PLUGIN_ID, "mxit_register\n" );

	/* create and save a new mxit session */
	session = mxit_create_object( account );
	purple_account_set_int( account, MXIT_CONFIG_STATE, MXIT_STATE_REGISTER1 );

	get_clientinfo( session );
}

