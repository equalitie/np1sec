/*
 *					MXit Protocol libPurple Plugin
 *
 *			-- user roster management (mxit contacts) --
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
#include	"roster.h"


struct contact_invite {
	struct MXitSession*		session;		/* MXit session object */
	struct contact*			contact;		/* The contact performing the invite */
};


/*========================================================================================================================
 * Presence / Status
 */

/* statuses (reference: libpurple/status.h) */
static struct status
{
	PurpleStatusPrimitive	primitive;
	int						mxit;
	const char*				id;
	const char*				name;
} const mxit_statuses[] = {
		/*	primitive,						no,							id,			name					*/
		{	PURPLE_STATUS_OFFLINE,			MXIT_PRESENCE_OFFLINE,		"offline",	N_( "Offline" )			},	/* 0 */
		{	PURPLE_STATUS_AVAILABLE,		MXIT_PRESENCE_ONLINE,		"online",	N_( "Available" )		},	/* 1 */
		{	PURPLE_STATUS_AWAY,				MXIT_PRESENCE_AWAY,			"away",		N_( "Away" )			},	/* 2 */
		{	PURPLE_STATUS_AVAILABLE,		MXIT_PRESENCE_AVAILABLE,	"chat",		N_( "Chatty" )			},	/* 3 */
		{	PURPLE_STATUS_UNAVAILABLE,		MXIT_PRESENCE_DND,			"dnd",		N_( "Do Not Disturb" )	}	/* 4 */
};


/*------------------------------------------------------------------------
 * Return list of supported statuses. (see status.h)
 *
 *  @param account	The MXit account object
 *  @return			List of PurpleStatusType
 */
GList* mxit_status_types( PurpleAccount* account )
{
	GList*				statuslist	= NULL;
	PurpleStatusType*	type;
	unsigned int		i;

	for ( i = 0; i < ARRAY_SIZE( mxit_statuses ); i++ ) {
		const struct status* status = &mxit_statuses[i];

		/* add mxit status (reference: "libpurple/status.h") */
		type = purple_status_type_new_with_attrs( status->primitive, status->id, _( status->name ), TRUE, TRUE, FALSE,
					"message", _( "Message" ), purple_value_new( PURPLE_TYPE_STRING ),
					NULL );

		statuslist = g_list_append( statuslist, type );
	}

	/* add Mood option */
	type = purple_status_type_new_with_attrs( PURPLE_STATUS_MOOD, "mood", NULL, FALSE, TRUE, TRUE,
		PURPLE_MOOD_NAME, _( "Mood Name" ), purple_value_new( PURPLE_TYPE_STRING ),
		NULL );
	statuslist = g_list_append( statuslist, type );

	return statuslist;
}


/*------------------------------------------------------------------------
 * Returns the MXit presence code, given the unique status ID.
 *
 *  @param id		The status ID
 *  @return			The MXit presence code
 */
int mxit_convert_presence( const char* id )
{
	unsigned int	i;

	for ( i = 0; i < ARRAY_SIZE( mxit_statuses ); i++ ) {
		if ( strcmp( mxit_statuses[i].id, id ) == 0 )	/* status found! */
			return mxit_statuses[i].mxit;
	}

	return -1;
}


/*------------------------------------------------------------------------
 * Returns the MXit presence as a string, given the MXit presence ID.
 *
 *  @param no		The MXit presence I (see above)
 *  @return			The presence as a text string
 */
const char* mxit_convert_presence_to_name( short no )
{
	unsigned int	i;

	for ( i = 0; i < ARRAY_SIZE( mxit_statuses ); i++ ) {
		if ( mxit_statuses[i].mxit == no )				/* status found! */
			return _( mxit_statuses[i].name );
	}

	return "";
}


/*========================================================================================================================
 * Moods
 */

/* moods (reference: libpurple/status.h) */
static PurpleMood mxit_moods[] = {
	{ "angry",		N_( "Angry" ),		NULL },
	{ "excited",	N_( "Excited" ),	NULL },
	{ "grumpy",		N_( "Grumpy" ),		NULL },
	{ "happy",		N_( "Happy" ),		NULL },
	{ "in_love",	N_( "In love" ),	NULL },
	{ "invincible",	N_( "Invincible" ),	NULL },
	{ "sad",		N_( "Sad" ),		NULL },
	{ "hot",		N_( "Hot" ),		NULL },
	{ "sick",		N_( "Sick" ),		NULL },
	{ "sleepy",		N_( "Sleepy" ),		NULL },
	{ "bored",		N_( "Bored" ),		NULL },
	{ "cold",		N_( "Cold" ),		NULL },
	{ "confused",	N_( "Confused" ),	NULL },
	{ "hungry",		N_( "Hungry" ),		NULL },
	{ "stressed",	N_( "Stressed" ),	NULL },
	/* Mark the last record. */
	{ NULL, NULL, NULL }
};


/*------------------------------------------------------------------------
 * Returns the MXit mood code, given the unique mood ID.
 *
 *  @param id		The mood ID
 *  @return			The MXit mood code
 */
int mxit_convert_mood( const char* id )
{
	unsigned int	i;

	/* Mood is being unset */
	if ( id == NULL )
		return MXIT_MOOD_NONE;

	for ( i = 0; i < ARRAY_SIZE( mxit_moods ) - 1; i++ ) {
		if ( strcmp( mxit_moods[i].mood, id ) == 0 )	/* mood found! */
			return i + 1;		/* because MXIT_MOOD_NONE is 0 */
	}

	return -1;
}


/*------------------------------------------------------------------------
 * Return the list of MXit-supported moods.
 *
 *  @param account	The MXit account object
 */
PurpleMood* mxit_get_moods( PurpleAccount *account )
{
	return mxit_moods;
}


/*------------------------------------------------------------------------
 * Returns the MXit mood as a string, given the MXit mood's ID.
 *
 *  @param id		The MXit mood ID (see roster.h)
 *  @return			The mood as a text string
 */
const char* mxit_convert_mood_to_name( short id )
{
	switch ( id ) {
		case MXIT_MOOD_ANGRY :
				return _( "Angry" );
		case MXIT_MOOD_EXCITED :
				return _( "Excited" );
		case MXIT_MOOD_GRUMPY :
				return _( "Grumpy" );
		case MXIT_MOOD_HAPPY :
				return _( "Happy" );
		case MXIT_MOOD_INLOVE :
				return _( "In Love" );
		case MXIT_MOOD_INVINCIBLE :
				return _( "Invincible" );
		case MXIT_MOOD_SAD :
				return _( "Sad" );
		case MXIT_MOOD_HOT :
				return _( "Hot" );
		case MXIT_MOOD_SICK :
				return _( "Sick" );
		case MXIT_MOOD_SLEEPY :
				return _( "Sleepy" );
		case MXIT_MOOD_BORED :
				return _( "Bored" );
		case MXIT_MOOD_COLD :
				return _( "Cold" );
		case MXIT_MOOD_CONFUSED :
				return _( "Confused" );
		case MXIT_MOOD_HUNGRY :
				return _( "Hungry" );
		case MXIT_MOOD_STRESSED :
				return _( "Stressed" );
		case MXIT_MOOD_NONE :
		default :
				return "";
	}
}


/*========================================================================================================================
 * Subscription Types
 */

/*------------------------------------------------------------------------
 * Returns a Contact subscription type as a string.
 *
 *  @param subtype	The subscription type
 *  @return			The subscription type as a text string
 */
const char* mxit_convert_subtype_to_name( short subtype )
{
	switch ( subtype ) {
		case MXIT_SUBTYPE_BOTH :
				return _( "Both" );
		case MXIT_SUBTYPE_PENDING :
				return _( "Pending" );
		case MXIT_SUBTYPE_ASK :
				return _( "Invited" );
		case MXIT_SUBTYPE_REJECTED :
				return _( "Rejected" );
		case MXIT_SUBTYPE_DELETED :
				return _( "Deleted" );
		case MXIT_SUBTYPE_NONE :
				return _( "None" );
		default :
				return "";
	}
}


/*========================================================================================================================
 * Calls from the MXit Protocol layer
 */

#if	0
/*------------------------------------------------------------------------
 * Dump a contact's info the the debug console.
 *
 *  @param contact		The contact
 */
static void dump_contact( struct contact* contact )
{
	purple_debug_info( MXIT_PLUGIN_ID, "CONTACT: name='%s', alias='%s', group='%s', type='%i', presence='%i', mood='%i'\n",
						contact->username, contact->alias, contact->groupname, contact->type, contact->presence, contact->mood );
}
#endif


#if	0
/*------------------------------------------------------------------------
 * Move a buddy from one group to another
 *
 * @param buddy		the buddy to move between groups
 * @param group		the new group to move the buddy to
 */
static PurpleBuddy* mxit_update_buddy_group( struct MXitSession* session, PurpleBuddy* buddy, PurpleGroup* group )
{
	PurpleGroup*		current_group	= purple_buddy_get_group( buddy );

	/* make sure the groups actually differs */
	if ( strcmp( current_group->name, group->name ) != 0 ) {
		/* groupnames does not match, so we need to make the update */

		struct contact*		contact		= purple_buddy_get_protocol_data( buddy );
		PurpleBuddy*		newbuddy	= NULL;

		purple_debug_info( MXIT_PLUGIN_ID, "Moving '%s' from group '%s' to '%s'\n", buddy->alias, current_group->name, group->name );

		/*
		 * XXX: libPurple does not currently provide an API to change or rename the group name
		 * for a specific buddy. One option is to remove the buddy from the list and re-adding
		 * him in the new group, but by doing that makes the buddy go offline and then online
		 * again. This is really not ideal and very irritating, but how else then?
		 */

		/* create new buddy, and transfer 'contact' data */
		newbuddy = purple_buddy_new( session->acc, buddy->name, buddy->alias );
		purple_buddy_set_protocol_data( newbuddy, contact );
		purple_buddy_set_protocol_data( buddy, NULL );

		/* remove the buddy */
		purple_blist_remove_buddy( buddy );

		/* add buddy */
		purple_blist_add_buddy( newbuddy, NULL, group, NULL );

		/* now re-instate his presence again */
		if ( contact ) {

			/* update the buddy's status (reference: "libpurple/prpl.h") */
			if ( contact->statusMsg )
				purple_prpl_got_user_status( session->acc, newbuddy->name, mxit_statuses[contact->presence].id, "message", contact->statusMsg, NULL );
			else
				purple_prpl_got_user_status( session->acc, newbuddy->name, mxit_statuses[contact->presence].id, NULL );

			/* update the buddy's mood */
			if ( contact->mood == MXIT_MOOD_NONE )
				purple_prpl_got_user_status_deactive( session->acc, newbuddy->name, "mood" );
			else
				purple_prpl_got_user_status( session->acc, newbuddy->name, "mood", PURPLE_MOOD_NAME, mxit_moods[contact->mood-1].mood, NULL );

			/* update avatar */
			if ( contact->avatarId ) {
				mxit_get_avatar( session, newbuddy->name, contact->avatarId );
				g_free( contact->avatarId );
				contact->avatarId = NULL;
			}
		}

		return newbuddy;
	}
	else
		return buddy;
}
#endif


/*------------------------------------------------------------------------
 * A contact update packet was received from the MXit server, so update the buddy's
 * information.
 *
 *  @param session		The MXit session object
 *  @param contact		The contact
 */
void mxit_update_contact( struct MXitSession* session, struct contact* contact )
{
	PurpleBuddy*		buddy	= NULL;
	PurpleGroup*		group	= NULL;
	const char*			id		= NULL;

	purple_debug_info( MXIT_PLUGIN_ID, "mxit_update_contact: user='%s' alias='%s' group='%s'\n", contact->username, contact->alias, contact->groupname );

	/*
	 * libPurple requires all contacts to be in a group.
	 * So if this MXit contact isn't in a group, pretend it is.
	 */
	if ( *contact->groupname == '\0' ) {
		g_strlcpy( contact->groupname, MXIT_DEFAULT_GROUP, sizeof( contact->groupname ) );
	}

	/* find or create a group for this contact */
	group = purple_find_group( contact->groupname );
	if ( !group )
		group = purple_group_new( contact->groupname );

	/* see if the buddy is not in the group already */
	buddy = purple_find_buddy_in_group( session->acc, contact->username, group );
	if ( !buddy ) {
		/* buddy not found in the group */

		/* lets try finding him in all groups */
		buddy = purple_find_buddy( session->acc, contact->username );
		if ( buddy ) {
			/* ok, so we found him in another group. to switch him between groups we must delete him and add him again. */
			purple_blist_remove_buddy( buddy );
			buddy = NULL;
		}

		/* create new buddy */
		buddy = purple_buddy_new( session->acc, contact->username, contact->alias );
		purple_buddy_set_protocol_data( buddy, contact );

		/* add new buddy to list */
		purple_blist_add_buddy( buddy, NULL, group, NULL );
	}
	else {
		/* buddy was found in the group */

		gpointer data = NULL;

		/* now update the buddy's alias */
		purple_blist_alias_buddy( buddy, contact->alias );

		/* replace the buddy's contact struct */
		if ( ( data = purple_buddy_get_protocol_data( buddy ) ) )
			free( data );
		purple_buddy_set_protocol_data( buddy, contact );
	}

	/* load buddy's avatar id */
	id = purple_buddy_icons_get_checksum_for_user( buddy );
	if ( id )
		contact->avatarId = g_strdup( id );
	else
		contact->avatarId = NULL;

	/* update the buddy's status (reference: "libpurple/prpl.h") */
	purple_prpl_got_user_status( session->acc, contact->username, mxit_statuses[contact->presence].id, NULL );

	/* update the buddy's mood */
	if ( contact->mood == MXIT_MOOD_NONE )
		purple_prpl_got_user_status_deactive( session->acc, contact->username, "mood" );
	else
		purple_prpl_got_user_status( session->acc, contact->username, "mood", PURPLE_MOOD_NAME, mxit_moods[contact->mood-1].mood, NULL );
}


/*------------------------------------------------------------------------
 * A presence update packet was received from the MXit server, so update the buddy's
 * information.
 *
 *  @param session		The MXit session object
 *  @param username		The contact which presence to update
 *  @param presence		The new presence state for the contact
 *  @param mood			The new mood for the contact
 *  @param customMood	The custom mood identifier
 *  @param statusMsg	This is the contact's status message
 *  @param flags		The contact's presence flags.
 */
void mxit_update_buddy_presence( struct MXitSession* session, const char* username, short presence, short mood, const char* customMood, const char* statusMsg, int flags )
{
	PurpleBuddy*		buddy	= NULL;
	struct contact*		contact	= NULL;

	purple_debug_info( MXIT_PLUGIN_ID, "mxit_update_buddy_presence: user='%s' presence=%i mood=%i customMood='%s' statusMsg='%s'\n",
		username, presence, mood, customMood, statusMsg );

	if ( ( presence < MXIT_PRESENCE_OFFLINE ) || ( presence > MXIT_PRESENCE_DND ) ) {
		purple_debug_info( MXIT_PLUGIN_ID, "mxit_update_buddy_presence: invalid presence state %i\n", presence );
		return;		/* ignore packet */
	}

	/* find the buddy information for this contact (reference: "libpurple/blist.h") */
	buddy = purple_find_buddy( session->acc, username );
	if ( !buddy ) {
		purple_debug_warning( MXIT_PLUGIN_ID, "mxit_update_buddy_presence: unable to find the buddy '%s'\n", username );
		return;
	}

	contact = purple_buddy_get_protocol_data( buddy );
	if ( !contact )
		return;

	contact->presence = presence;
	contact->mood = mood;
	contact->capabilities = flags;

	/* validate mood */
	if ( ( contact->mood < MXIT_MOOD_NONE ) || ( contact->mood > MXIT_MOOD_STRESSED ) )
		contact->mood = MXIT_MOOD_NONE;

	g_strlcpy( contact->customMood, customMood, sizeof( contact->customMood ) );
	// TODO: Download custom mood frame.

	/* update status message */
	if ( contact->statusMsg ) {
		g_free( contact->statusMsg );
		contact->statusMsg = NULL;
	}
	if ( ( statusMsg ) && ( statusMsg[0] != '\0' ) )
		contact->statusMsg = g_markup_escape_text( statusMsg, -1 );

	/* update the buddy's status (reference: "libpurple/prpl.h") */
	if ( contact->statusMsg )
		purple_prpl_got_user_status( session->acc, username, mxit_statuses[contact->presence].id, "message", contact->statusMsg, NULL );
	else
		purple_prpl_got_user_status( session->acc, username, mxit_statuses[contact->presence].id, NULL );

	/* update the buddy's mood */
	if ( contact->mood == MXIT_MOOD_NONE )
		purple_prpl_got_user_status_deactive( session->acc, username, "mood" );
	else
		purple_prpl_got_user_status( session->acc, username, "mood", PURPLE_MOOD_NAME, mxit_moods[contact->mood-1].mood, NULL );
}


/*------------------------------------------------------------------------
 * Update the buddy's avatar.
 * Either a presence update packet was received from the MXit server, or a profile response.
 *
 *  @param session		The MXit session object
 *  @param username		The contact which presence to update
 *  @param avatarId		This is the contact's avatar id
 */
void mxit_update_buddy_avatar( struct MXitSession* session, const char* username, const char* avatarId )
{
	PurpleBuddy*		buddy	= NULL;
	struct contact*		contact	= NULL;

	purple_debug_info( MXIT_PLUGIN_ID, "mxit_update_buddy_avatar: user='%s' avatar='%s'\n", username, avatarId );

	/* find the buddy information for this contact (reference: "libpurple/blist.h") */
	buddy = purple_find_buddy( session->acc, username );
	if ( !buddy ) {
		purple_debug_warning( MXIT_PLUGIN_ID, "mxit_update_buddy_presence: unable to find the buddy '%s'\n", username );
		return;
	}

	contact = purple_buddy_get_protocol_data( buddy );
	if ( !contact )
		return;

	if ( ( contact->avatarId ) && ( g_ascii_strcasecmp( contact->avatarId, avatarId ) == 0 ) ) {
		/*  avatar has not changed - do nothing */
	}
	else if ( avatarId[0] != '\0' ) {		/* avatar has changed */
		if ( contact->avatarId )
			g_free( contact->avatarId );
		contact->avatarId = g_strdup( avatarId );

		/* Send request to download new avatar image */
		mxit_get_avatar( session, username, avatarId );
	}
	else		/* clear current avatar */
		purple_buddy_icons_set_for_user( session->acc, username, NULL, 0, NULL );
}


/*------------------------------------------------------------------------
 * update the blist cached by libPurple. We need to do this to keep
 * libPurple and MXit's rosters in sync with each other.
 *
 * @param session		The MXit session object
 */
void mxit_update_blist( struct MXitSession* session )
{
	PurpleBuddy*	buddy	= NULL;
	GSList*			list	= NULL;
	unsigned int	i;

	/* remove all buddies we did not receive a roster update for.
	 * these contacts must have been removed from another client */
	list = purple_find_buddies( session->acc, NULL );

	for ( i = 0; i < g_slist_length( list ); i++ ) {
		buddy = g_slist_nth_data( list, i );

		if ( !purple_buddy_get_protocol_data( buddy ) ) {
			const gchar* alias = purple_buddy_get_alias( buddy );
			const gchar* name = purple_buddy_get_name( buddy );

			/* this buddy should be removed, because we did not receive him in our roster update from MXit */
			purple_debug_info( MXIT_PLUGIN_ID, "Removed 'old' buddy from the blist '%s' (%s)\n", alias, name );
			purple_blist_remove_buddy( buddy );
		}
	}

	/* tell the UI to update the blist */
	purple_blist_add_account( session->acc );
}


/*------------------------------------------------------------------------
 * The user authorized an invite (subscription request).
 *
 *  @param user_data	Object associated with the invite
 */
static void mxit_cb_buddy_auth( gpointer user_data )
{
	struct contact_invite*	invite	= (struct contact_invite*) user_data;

	purple_debug_info( MXIT_PLUGIN_ID, "mxit_cb_buddy_auth '%s'\n", invite->contact->username );

	/* send a allow subscription packet to MXit */
	mxit_send_allow_sub( invite->session, invite->contact->username, invite->contact->alias );

	/* remove the invite from our internal invites list */
	invite->session->invites = g_list_remove( invite->session->invites, invite->contact );

	/* freeup invite object */
	if ( invite->contact->msg )
		g_free( invite->contact->msg );
	if ( invite->contact->statusMsg )
		g_free( invite->contact->statusMsg );
	if ( invite->contact->profile )
		g_free( invite->contact->profile );
	g_free( invite->contact );
	g_free( invite );
}


/*------------------------------------------------------------------------
 * The user rejected an invite (subscription request).
 *
 *  @param user_data	Object associated with the invite
 */
static void mxit_cb_buddy_deny( gpointer user_data )
{
	struct contact_invite*	invite	= (struct contact_invite*) user_data;

	purple_debug_info( MXIT_PLUGIN_ID, "mxit_cb_buddy_deny '%s'\n", invite->contact->username );

	/* send a deny subscription packet to MXit */
	mxit_send_deny_sub( invite->session, invite->contact->username, NULL );

	/* remove the invite from our internal invites list */
	invite->session->invites = g_list_remove( invite->session->invites, invite->contact );

	/* freeup invite object */
	if ( invite->contact->msg )
		g_free( invite->contact->msg );
	if ( invite->contact->statusMsg )
		g_free( invite->contact->statusMsg );
	if ( invite->contact->profile )
		g_free( invite->contact->profile );
	g_free( invite->contact );
	g_free( invite );
}


/*------------------------------------------------------------------------
 * A new subscription request packet was received from the MXit server.
 * Prompt user to accept or reject it.
 *
 *  @param session		The MXit session object
 *  @param contact		The contact performing the invite
 */
void mxit_new_subscription( struct MXitSession* session, struct contact* contact )
{
	struct contact_invite*	invite;

	purple_debug_info( MXIT_PLUGIN_ID, "mxit_new_subscription from '%s' (%s)\n", contact->username, contact->alias );

	invite = g_new0( struct contact_invite, 1 );
	invite->session = session;
	invite->contact = contact;

	/* add the invite to our internal invites list */
	invite->session->invites = g_list_append( invite->session->invites, invite->contact );

	/* (reference: "libpurple/account.h") */
	purple_account_request_authorization( session->acc, contact->username, NULL, contact->alias, contact->msg, FALSE, mxit_cb_buddy_auth, mxit_cb_buddy_deny, invite );
}


/*------------------------------------------------------------------------
 * Return the contact object for a mxit invite
 *
 *  @param session		The MXit session object
 *  @param username		The username of the contact
 *  @return				The contact object for the inviting user
 */
struct contact* get_mxit_invite_contact( struct MXitSession* session, const char* username )
{
	struct contact*		con		= NULL;
	struct contact*		match	= NULL;
	unsigned int		i;

	/* run through all the invites and try and find the match */
	for ( i = 0; i < g_list_length( session->invites ); i++ ) {
		con = g_list_nth_data( session->invites, i );
		if ( strcmp( con->username, username ) == 0 ) {
			/* invite found */
			match = con;
			break;
		}
	}

	return match;
}


/*------------------------------------------------------------------------
 * Return TRUE if this is a MXit Chatroom contact.
 *
 *  @param session		The MXit session object
 *  @param username		The username of the contact
 */
gboolean is_mxit_chatroom_contact( struct MXitSession* session, const char* username )
{
	PurpleBuddy*		buddy;
	struct contact*		contact	= NULL;

	/* find the buddy */
	buddy = purple_find_buddy( session->acc, username );
	if ( !buddy ) {
		purple_debug_warning( MXIT_PLUGIN_ID, "is_mxit_chatroom_contact: unable to find the buddy '%s'\n", username );
		return FALSE;
	}

	contact = purple_buddy_get_protocol_data( buddy );
	if ( !contact )
		return FALSE;

	return ( contact->type == MXIT_TYPE_CHATROOM );
}


/*========================================================================================================================
 * Callbacks from libpurple
 */

/*------------------------------------------------------------------------
 * The user has added a buddy to the list, so send an invite request.
 *
 *  @param gc		The connection object
 *  @param buddy	The new buddy
 *  @param group	The group of the new buddy
 *  @param message	The invite message
 */
void mxit_add_buddy( PurpleConnection* gc, PurpleBuddy* buddy, PurpleGroup* group, const char* message )
{
	struct MXitSession*	session	= purple_connection_get_protocol_data( gc );
	GSList*				list	= NULL;
	PurpleBuddy*		mxbuddy	= NULL;
	unsigned int		i;
	const gchar *		buddy_name = purple_buddy_get_name( buddy );
	const gchar *		buddy_alias = purple_buddy_get_alias( buddy );
	const gchar *		group_name = purple_group_get_name( group );

	purple_debug_info( MXIT_PLUGIN_ID, "mxit_add_buddy '%s' (group='%s')\n", buddy_name, group_name );

	list = purple_find_buddies( session->acc, buddy_name );
	if ( g_slist_length( list ) == 1 ) {
		purple_debug_info( MXIT_PLUGIN_ID, "mxit_add_buddy (scenario 1) (list:%i)\n", g_slist_length( list ) );
		/*
		 * we only send an invite to MXit when the user is not already inside our
		 * blist.  this is done because purple does an add_buddy() call when
		 * you accept an invite.  so in that case the user is already
		 * in our blist and ready to be chatted to.
		 */

		if ( buddy_name[0] == '#' ) {
			gchar *tmp = (gchar*) purple_base64_decode( buddy_name + 1, NULL );
			if ( tmp ) {
				mxit_send_invite( session, tmp, FALSE, buddy_alias, group_name, message );
				g_free( tmp );
			}
		}
		else
			mxit_send_invite( session, buddy_name, TRUE, buddy_alias, group_name, message );
	}
	else {
		purple_debug_info( MXIT_PLUGIN_ID, "mxit_add_buddy (scenario 2) (list:%i)\n", g_slist_length( list ) );
		/*
		 * we already have the buddy in our list, so we will only update
		 * his information here and not send another invite message
		 */

		/* find the correct buddy */
		for ( i = 0; i < g_slist_length( list ); i++ ) {
			mxbuddy = g_slist_nth_data( list, i );

			if ( purple_buddy_get_protocol_data( mxbuddy ) != NULL ) {
				/* this is our REAL MXit buddy! */

				/* now update the buddy's alias */
				purple_blist_alias_buddy( mxbuddy, buddy_alias );

				/* now update the buddy's group */
//				mxbuddy = mxit_update_buddy_group( session, mxbuddy, group );

				/* send the update to the MXit server */
				mxit_send_update_contact( session, purple_buddy_get_name( mxbuddy ), purple_buddy_get_alias( mxbuddy ), group_name );
			}
		}
	}

	/*
	 * we remove the buddy here from the buddy list because the MXit server
	 * will send us a proper contact update packet if this succeeds.  now
	 * we do not have to worry about error handling in case of adding an
	 * invalid contact.  so the user will still see the contact as offline
	 * until he eventually accepts the invite.
	 */
	purple_blist_remove_buddy( buddy );

	g_slist_free( list );
}


/*------------------------------------------------------------------------
 * The user has removed a buddy from the list.
 *
 *  @param gc		The connection object
 *  @param buddy	The buddy being removed
 *  @param group	The group the buddy was in
 */
void mxit_remove_buddy( PurpleConnection* gc, PurpleBuddy* buddy, PurpleGroup* group )
{
	struct MXitSession*	session	= purple_connection_get_protocol_data( gc );
	const gchar *		buddy_name = purple_buddy_get_name( buddy );

	purple_debug_info( MXIT_PLUGIN_ID, "mxit_remove_buddy '%s'\n", buddy_name );

	mxit_send_remove( session, buddy_name );
}


/*------------------------------------------------------------------------
 * The user changed the buddy's alias.
 *
 *  @param gc		The connection object
 *  @param who		The username of the buddy
 *  @param alias	The new alias
 */
void mxit_buddy_alias( PurpleConnection* gc, const char* who, const char* alias )
{
	struct MXitSession*	session	= purple_connection_get_protocol_data( gc );
	PurpleBuddy*		buddy	= NULL;
	PurpleGroup*		group	= NULL;

	purple_debug_info( MXIT_PLUGIN_ID, "mxit_buddy_alias '%s' to '%s\n", who, alias );

	/* find the buddy */
	buddy = purple_find_buddy( session->acc, who );
	if ( !buddy ) {
		purple_debug_warning( MXIT_PLUGIN_ID, "mxit_buddy_alias: unable to find the buddy '%s'\n", who );
		return;
	}

	/* find buddy group */
	group = purple_buddy_get_group( buddy );
	if ( !group ) {
		purple_debug_warning( MXIT_PLUGIN_ID, "mxit_buddy_alias: unable to find the group for buddy '%s'\n", who );
		return;
	}

	mxit_send_update_contact( session, who, alias, purple_group_get_name( group ) );
}


/*------------------------------------------------------------------------
 * The user changed the group for a single buddy.
 *
 *  @param gc			The connection object
 *  @param who			The username of the buddy
 *  @param old_group	The old group's name
 *  @param new_group	The new group's name
 */
void mxit_buddy_group( PurpleConnection* gc, const char* who, const char* old_group, const char* new_group )
{
	struct MXitSession*	session	= purple_connection_get_protocol_data( gc );
	PurpleBuddy*		buddy	= NULL;

	purple_debug_info( MXIT_PLUGIN_ID, "mxit_buddy_group from '%s' to '%s'\n", old_group, new_group );

	/* find the buddy */
	buddy = purple_find_buddy( session->acc, who );
	if ( !buddy ) {
		purple_debug_warning( MXIT_PLUGIN_ID, "mxit_buddy_group: unable to find the buddy '%s'\n", who );
		return;
	}

	mxit_send_update_contact( session, who, purple_buddy_get_alias( buddy ), new_group );
}


/*------------------------------------------------------------------------
 * The user has selected to rename a group, so update all contacts in that
 * group.
 *
 *  @param gc				The connection object
 *  @param old_name			The old group name
 *  @param group			The updated group object
 *  @param moved_buddies	The buddies affected by the rename
 */
void mxit_rename_group( PurpleConnection* gc, const char* old_name, PurpleGroup* group, GList* moved_buddies )
{
	struct MXitSession*	session	= purple_connection_get_protocol_data( gc );
	PurpleBuddy*		buddy	= NULL;
	GList*				item	= NULL;

	purple_debug_info( MXIT_PLUGIN_ID, "mxit_rename_group from '%s' to '%s\n", old_name, purple_group_get_name( group ) );

	//  TODO: Might be more efficient to use the "rename group" command (cmd=29).

	/* loop through all the contacts in the group and send updates */
	item = moved_buddies;
	while ( item ) {
		buddy = item->data;
		mxit_send_update_contact( session, purple_buddy_get_name( buddy ), purple_buddy_get_alias( buddy ), purple_group_get_name( group ) );
		item = g_list_next( item );
	}
}

