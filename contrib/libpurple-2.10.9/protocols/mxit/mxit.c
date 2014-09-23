/*
 *					MXit Protocol libPurple Plugin
 *
 *					--  MXit libPurple plugin API --
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
#include	"accountopt.h"
#include	"version.h"

#include	"mxit.h"
#include	"protocol.h"
#include	"login.h"
#include	"roster.h"
#include	"chunk.h"
#include	"filexfer.h"
#include	"actions.h"
#include	"multimx.h"
#include	"voicevideo.h"


#ifdef	MXIT_LINK_CLICK


/* pidgin callback function pointers for URI click interception */
static void *(*mxit_pidgin_uri_cb)(const char *uri);
static PurpleNotifyUiOps* mxit_nots_override_original;
static PurpleNotifyUiOps mxit_nots_override;
static int not_link_ref_count = 0;


/*------------------------------------------------------------------------
 * Handle an URI clicked on the UI
 *
 * @param link	the link name which has been clicked
 */
static void* mxit_link_click( const char* link64 )
{
	PurpleAccount*		account;
	PurpleConnection*	gc;
	gchar**				parts		= NULL;
	gchar*				link		= NULL;
	gsize				len;
	gboolean			is_command	= FALSE;

	purple_debug_info( MXIT_PLUGIN_ID, "mxit_link_click (%s)\n", link64 );

	if ( g_ascii_strncasecmp( link64, MXIT_LINK_PREFIX, strlen( MXIT_LINK_PREFIX ) ) != 0 ) {
		/* this is not for us */
		goto skip;
	}

	/* decode the base64 payload */
	link = (gchar*) purple_base64_decode( link64 + strlen( MXIT_LINK_PREFIX ), &len );
	purple_debug_info( MXIT_PLUGIN_ID, "Clicked Link: '%s'\n", link );

	parts = g_strsplit( link, "|", 6 );

	/* check if this is a valid mxit link */
	if ( ( !parts ) || ( !parts[0] ) || ( !parts[1] ) || ( !parts[2] ) || ( !parts[3] ) || ( !parts[4] ) || ( !parts[5] ) ) {
		/* this is not for us */
		goto skip;
	}
	else if ( g_ascii_strcasecmp( parts[0], MXIT_LINK_KEY ) != 0 ) {
		/* this is not for us */
		goto skip;
	}

	/* find the account */
	account = purple_accounts_find( parts[1], parts[2] );
	if ( !account )
		goto skip;
	gc = purple_account_get_connection( account );
	if ( !gc )
		goto skip;

	/* determine if it's a command-response to send */
	is_command = ( atoi( parts[4] ) == 1 );

	/* send click message back to MXit */
	mxit_send_message( purple_connection_get_protocol_data( gc ), parts[3], parts[5], FALSE, is_command );

	g_free( link );
	link = NULL;
	g_strfreev( parts );
	parts = NULL;

	return (void*) link64;

skip:
	/* this is not an internal mxit link */

	if ( link )
		g_free( link );
	link = NULL;

	if ( parts )
		g_strfreev( parts );
	parts = NULL;

	if ( mxit_pidgin_uri_cb )
		return mxit_pidgin_uri_cb( link64 );
	else
		return (void*) link64;
}


/*------------------------------------------------------------------------
 * Register MXit to receive URI click notifications from the UI
 */
void mxit_register_uri_handler( void )
{
	not_link_ref_count++;
	if ( not_link_ref_count == 1 ) {
		/* make copy of notifications */
		mxit_nots_override_original = purple_notify_get_ui_ops();
		memcpy( &mxit_nots_override, mxit_nots_override_original, sizeof( PurpleNotifyUiOps ) );

		/* save previously configured callback function pointer */
		mxit_pidgin_uri_cb = mxit_nots_override.notify_uri;

		/* override the URI function call with MXit's own one */
		mxit_nots_override.notify_uri = mxit_link_click;
		purple_notify_set_ui_ops( &mxit_nots_override );
	}
}


/*------------------------------------------------------------------------
 * Unregister MXit from receiving URI click notifications from the UI
 */
static void mxit_unregister_uri_handler()
{
	not_link_ref_count--;
	if ( not_link_ref_count == 0 ) {
		/* restore the notifications to its original state */
		purple_notify_set_ui_ops( mxit_nots_override_original );
	}
}

#endif


/*------------------------------------------------------------------------
 * This gets called when a new chat conversation is opened by the user
 *
 *  @param conv				The conversation object
 *  @param session			The MXit session object
 */
static void mxit_cb_chat_created( PurpleConversation* conv, struct MXitSession* session )
{
	PurpleConnection*	gc;
	struct contact*		contact;
	PurpleBuddy*		buddy;
	const char*			who;
	char*				tmp;

	gc = purple_conversation_get_gc( conv );
	if ( session->con != gc ) {
		/* not our conversation */
		return;
	}
	else if ( purple_conversation_get_type( conv ) != PURPLE_CONV_TYPE_IM ) {
		/* wrong type of conversation */
		return;
	}

	/* get the contact name */
	who = purple_conversation_get_name( conv );
	if ( !who )
		return;

	purple_debug_info( MXIT_PLUGIN_ID, "Conversation started with '%s'\n", who );

	/* find the buddy object */
	buddy = purple_find_buddy( session->acc, who );
	if ( !buddy )
		return;

	contact = purple_buddy_get_protocol_data( buddy );
	if ( !contact )
		return;

	/* we ignore all conversations with which we have chatted with in this session */
	if ( find_active_chat( session->active_chats, who ) )
		return;

	/* determine if this buddy is a MXit service */
	switch ( contact->type ) {
		case MXIT_TYPE_BOT :
		case MXIT_TYPE_CHATROOM :
		case MXIT_TYPE_GALLERY :
		case MXIT_TYPE_INFO :
				tmp = g_strdup_printf("<font color=\"#999999\">%s</font>\n", _( "Loading menu..." ));
				serv_got_im( session->con, who, tmp, PURPLE_MESSAGE_NOTIFY, time( NULL ) );
				g_free( tmp );
				mxit_send_message( session, who, " ", FALSE, FALSE );
		default :
				break;
	}
}


/*------------------------------------------------------------------------
 * Enable some signals to handled by our plugin
 *
 *  @param session			The MXit session object
 */
void mxit_enable_signals( struct MXitSession* session )
{
	/* enable the signal when a new conversation is opened by the user */
	purple_signal_connect_priority( purple_conversations_get_handle(), "conversation-created", session, PURPLE_CALLBACK( mxit_cb_chat_created ),
			session, PURPLE_SIGNAL_PRIORITY_HIGHEST );
}


/*------------------------------------------------------------------------
 * Disable some signals handled by our plugin
 *
 *  @param session			The MXit session object
 */
static void mxit_disable_signals( struct MXitSession* session )
{
	/* disable the signal when a new conversation is opened by the user */
	purple_signal_disconnect( purple_conversations_get_handle(), "conversation-created", session, PURPLE_CALLBACK( mxit_cb_chat_created ) );
}


/*------------------------------------------------------------------------
 * Return the base icon name.
 *
 *  @param account	The MXit account object
 *  @param buddy	The buddy
 *  @return			The icon name (excluding extension)
 */
static const char* mxit_list_icon( PurpleAccount* account, PurpleBuddy* buddy )
{
	return "mxit";
}


/*------------------------------------------------------------------------
 * Return the emblem icon name.
 *
 *  @param buddy	The buddy
 *  @return			The icon name (excluding extension)
 */
static const char* mxit_list_emblem( PurpleBuddy* buddy )
{
	struct contact*	contact = purple_buddy_get_protocol_data( buddy );

	if ( !contact )
		return NULL;

	/* subscription state is Pending, Rejected or Deleted */
	if ( contact->subtype != MXIT_SUBTYPE_BOTH )
		return "not-authorized";

	switch ( contact-> type ) {
		case MXIT_TYPE_JABBER :			/* external contacts via MXit */
		case MXIT_TYPE_MSN :
		case MXIT_TYPE_YAHOO :
		case MXIT_TYPE_ICQ :
		case MXIT_TYPE_AIM :
		case MXIT_TYPE_QQ :
		case MXIT_TYPE_WV :
			return "external";

		case MXIT_TYPE_BOT :			/* MXit services */
		case MXIT_TYPE_GALLERY :
		case MXIT_TYPE_INFO :
			return "bot";

		case MXIT_TYPE_CHATROOM :		/* MXit group chat services */
		case MXIT_TYPE_MULTIMX :
		default:
			return NULL;
	}
}


/*------------------------------------------------------------------------
 * Return short string representing buddy's status for display on buddy list.
 * Returns status message (if one is set), or otherwise the mood.
 *
 *  @param buddy	The buddy.
 *  @return			The status text
 */
char* mxit_status_text( PurpleBuddy* buddy )
{
	char* text = NULL;
	struct contact*	contact = purple_buddy_get_protocol_data( buddy );

	if ( !contact )
		return NULL;

	if ( contact->statusMsg )							/* status message */
		text = g_strdup( contact-> statusMsg );
	else if ( contact->mood != MXIT_MOOD_NONE )			/* mood */
		text = g_strdup( mxit_convert_mood_to_name( contact->mood ) );

	return text;
}


/*------------------------------------------------------------------------
 * Return UI tooltip information for a buddy when hovering in buddy list.
 *
 *  @param buddy	The buddy
 *  @param info		The tooltip info being returned
 *  @param full		Return full or summarized information
 */
static void mxit_tooltip( PurpleBuddy* buddy, PurpleNotifyUserInfo* info, gboolean full )
{
	struct contact*	contact = purple_buddy_get_protocol_data( buddy );

	if ( !contact )
		return;

	/* status (reference: "libpurple/notify.h") */
	if ( contact->presence != MXIT_PRESENCE_OFFLINE )
		purple_notify_user_info_add_pair( info, _( "Status" ), mxit_convert_presence_to_name( contact->presence ) );

	/* status message */
	if ( contact->statusMsg )
		purple_notify_user_info_add_pair( info, _( "Status Message" ), contact->statusMsg );

	/* mood */
	if ( contact->mood != MXIT_MOOD_NONE )
		purple_notify_user_info_add_pair( info, _( "Mood" ), mxit_convert_mood_to_name( contact->mood ) );

	/* subscription type */
	if ( contact->subtype != 0 )
		purple_notify_user_info_add_pair( info, _( "Subscription" ), mxit_convert_subtype_to_name( contact->subtype ) );

	/* rejection message */
	if ( ( contact->subtype == MXIT_SUBTYPE_REJECTED ) && ( contact->msg != NULL ) )
		purple_notify_user_info_add_pair( info, _( "Rejection Message" ), contact->msg );
}


/*------------------------------------------------------------------------
 * Initiate the logout sequence, close the connection and clear the session data.
 *
 *  @param gc	The connection object
 */
static void mxit_close( PurpleConnection* gc )
{
	struct MXitSession*	session	= purple_connection_get_protocol_data( gc );

	/* disable signals */
	mxit_disable_signals( session );

	/* close the connection */
	mxit_close_connection( session );

#ifdef		MXIT_LINK_CLICK
	/* unregister for uri click notification */
	mxit_unregister_uri_handler();
#endif

	purple_debug_info( MXIT_PLUGIN_ID, "Releasing the session object..\n" );

	/* free the session memory */
	g_free( session );
	session = NULL;
}


/*------------------------------------------------------------------------
 * Send a message to a contact
 *
 *  @param gc		The connection object
 *  @param who		The username of the recipient
 *  @param message	The message text
 *  @param flags	Message flags (defined in conversation.h)
 *  @return			Positive value (success, and echo to conversation window)
					Zero (success, no echo)
					Negative value (error)
 */
static int mxit_send_im( PurpleConnection* gc, const char* who, const char* message, PurpleMessageFlags flags )
{
	purple_debug_info( MXIT_PLUGIN_ID, "Sending message '%s' to buddy '%s'\n", message, who );

	mxit_send_message( purple_connection_get_protocol_data( gc ), who, message, TRUE, FALSE );

	return 1;		/* echo to conversation window */
}


/*------------------------------------------------------------------------
 * The user changed their current presence state.
 *
 *  @param account	The MXit account object
 *  @param status	The new status (libPurple status type)
 */
static void mxit_set_status( PurpleAccount* account, PurpleStatus* status )
{
	struct MXitSession*		session =	purple_connection_get_protocol_data( purple_account_get_connection( account ) );
	const char*				statusid;
	int						presence;
	char*					statusmsg1;
	char*					statusmsg2;

	/* Handle mood changes */
	if ( purple_status_type_get_primitive( purple_status_get_type( status ) ) == PURPLE_STATUS_MOOD ) {
		const char* moodid = purple_status_get_attr_string( status, PURPLE_MOOD_NAME );
		int mood;

		/* convert the purple mood to a mxit mood */
		mood = mxit_convert_mood( moodid );
		if ( mood < 0 ) {
			/* error, mood not found */
			purple_debug_info( MXIT_PLUGIN_ID, "Mood status NOT found! (id = %s)\n", moodid );
			return;
		}

		/* update mood state */
		mxit_send_mood( session, mood );
		return;
	}

	/* get the status id (reference: "libpurple/status.h") */
	statusid = purple_status_get_id( status );

	/* convert the purple status to a mxit status */
	presence = mxit_convert_presence( statusid );
	if ( presence < 0 ) {
		/* error, status not found */
		purple_debug_info( MXIT_PLUGIN_ID, "Presence status NOT found! (id = %s)\n", statusid );
		return;
	}

	statusmsg1 = purple_markup_strip_html( purple_status_get_attr_string( status, "message" ) );
	statusmsg2 = g_strndup( statusmsg1, CP_MAX_STATUS_MSG );

	purple_debug_info( MXIT_PLUGIN_ID, "mxit_set_status: '%s'\n", statusmsg2 );

	/* update presence state */
	mxit_send_presence( session, presence, statusmsg2 );

	g_free( statusmsg1 );
	g_free( statusmsg2 );
}


/*------------------------------------------------------------------------
 * MXit supports messages to offline contacts.
 *
 *  @param buddy	The buddy
 */
static gboolean mxit_offline_message( const PurpleBuddy *buddy )
{
	return TRUE;
}


/*------------------------------------------------------------------------
 * Free the resources used to store a buddy.
 *
 *  @param buddy	The buddy
 */
static void mxit_free_buddy( PurpleBuddy* buddy )
{
	struct contact*		contact;

	purple_debug_info( MXIT_PLUGIN_ID, "mxit_free_buddy\n" );

	contact = purple_buddy_get_protocol_data( buddy );
	if ( contact ) {
		if ( contact->statusMsg )
			g_free( contact->statusMsg );
		if ( contact->avatarId )
			g_free( contact->avatarId );
		if ( contact->msg )
			g_free( contact->msg );
		g_free( contact );
	}

	purple_buddy_set_protocol_data( buddy, NULL );
}


/*------------------------------------------------------------------------
 * Periodic task called every KEEPALIVE_INTERVAL (30 sec) to to maintain
 * idle connections, timeouts and the transmission queue to the MXit server.
 *
 *  @param gc		The connection object
 */
static void mxit_keepalive( PurpleConnection *gc )
{
	struct MXitSession*	session	= purple_connection_get_protocol_data( gc );

	/* if not logged in, there is nothing to do */
	if ( !( session->flags & MXIT_FLAG_LOGGEDIN ) )
		return;

	/* pinging is only for socket connections (HTTP does polling) */
	if ( session->http )
		return;

	if ( session->last_tx <= ( mxit_now_milli() - ( MXIT_PING_INTERVAL * 1000 ) ) ) {
		/*
		 * this connection has been idle for too long, better ping
		 * the server before it kills our connection.
		 */
		mxit_send_ping( session );
	}
}


/*------------------------------------------------------------------------
 * Set or clear our Buddy icon.
 *
 *  @param gc		The connection object
 *  @param img		The buddy icon data
 */
static void mxit_set_buddy_icon( PurpleConnection *gc, PurpleStoredImage *img )
{
	struct MXitSession*	session	= purple_connection_get_protocol_data( gc );

	if ( img == NULL )
		mxit_set_avatar( session, NULL, 0 );
	else
		mxit_set_avatar( session, purple_imgstore_get_data( img ), purple_imgstore_get_size( img ) );
}


/*------------------------------------------------------------------------
 * Request profile information for another MXit contact.
 *
 *  @param gc		The connection object
 *  @param who		The username of the contact.
 */
static void mxit_get_info( PurpleConnection *gc, const char *who )
{
	PurpleBuddy*			buddy;
	struct contact*			contact;
	struct MXitSession*		session			= purple_connection_get_protocol_data( gc );
	const char*				profilelist[]	= { CP_PROFILE_BIRTHDATE, CP_PROFILE_GENDER, CP_PROFILE_FULLNAME,
												CP_PROFILE_FIRSTNAME, CP_PROFILE_LASTNAME, CP_PROFILE_REGCOUNTRY, CP_PROFILE_LASTSEEN,
												CP_PROFILE_STATUS, CP_PROFILE_AVATAR, CP_PROFILE_WHEREAMI, CP_PROFILE_ABOUTME, CP_PROFILE_RELATIONSHIP };

	purple_debug_info( MXIT_PLUGIN_ID, "mxit_get_info: '%s'\n", who );

	/* find the buddy information for this contact (reference: "libpurple/blist.h") */
	buddy = purple_find_buddy( session->acc, who );
	if ( buddy ) {
		/* user is in our contact-list, so it's not an invite */
		contact = purple_buddy_get_protocol_data( buddy );
		if ( !contact )
			return;

		/* only MXit users have profiles */
		if ( contact->type != MXIT_TYPE_MXIT ) {
			mxit_popup( PURPLE_NOTIFY_MSG_WARNING, _( "No profile available" ), _( "This contact does not have a profile." ) );
			return;
		}
	}

	/* send profile request */
	mxit_send_extprofile_request( session, who, ARRAY_SIZE( profilelist ), profilelist );
}


/*------------------------------------------------------------------------
 * Return a list of labels to be used by Pidgin for assisting the user.
 */
static GHashTable* mxit_get_text_table( PurpleAccount* acc )
{
	GHashTable* table;

	table = g_hash_table_new( g_str_hash, g_str_equal );

	g_hash_table_insert( table, "login_label", (gpointer)_( "Your MXit ID..." ) );

	return table;
}


/*------------------------------------------------------------------------
 * Re-Invite was selected from the buddy-list menu.
 *
 *  @param node		The entry in the buddy list.
 *  @param ignored	(not used)
 */
static void mxit_reinvite( PurpleBlistNode *node, gpointer ignored )
{
	PurpleBuddy*		buddy		= (PurpleBuddy *) node;
	PurpleConnection*	gc			= purple_account_get_connection( purple_buddy_get_account( buddy ) );
	struct MXitSession*	session		= purple_connection_get_protocol_data( gc );
	struct contact*		contact;

	contact = purple_buddy_get_protocol_data( (PurpleBuddy*) node );
	if ( !contact )
		return;

	/* send a new invite */
	mxit_send_invite( session, contact->username, TRUE, contact->alias, contact->groupname, NULL );
}


/*------------------------------------------------------------------------
 * Buddy-list menu.
 *
 *  @param node		The entry in the buddy list.
 */
static GList* mxit_blist_menu( PurpleBlistNode *node )
{
	PurpleBuddy*		buddy;
	struct contact*		contact;
	GList*				m = NULL;
	PurpleMenuAction*	act;

	if ( !PURPLE_BLIST_NODE_IS_BUDDY( node ) )
		return NULL;

	buddy = (PurpleBuddy *) node;
	contact = purple_buddy_get_protocol_data( buddy );
	if ( !contact )
		return NULL;

	if ( ( contact->subtype == MXIT_SUBTYPE_DELETED ) || ( contact->subtype == MXIT_SUBTYPE_REJECTED ) || ( contact->subtype == MXIT_SUBTYPE_NONE ) ) {
		/* contact is in Deleted, Rejected or None state */
		act = purple_menu_action_new( _( "Re-Invite" ), PURPLE_CALLBACK( mxit_reinvite ), NULL, NULL );
		m = g_list_append( m, act );
	}

	return m;
}


/*------------------------------------------------------------------------
 * Return Chat-room default settings.
 *
 *  @return		Chat defaults list
 */
static GHashTable *mxit_chat_info_defaults( PurpleConnection *gc, const char *chat_name )
{
    return g_hash_table_new_full( g_str_hash, g_str_equal, NULL, g_free );
}


/*------------------------------------------------------------------------
 * Send a typing indicator event.
 *
 *  @param gc		The connection object
 *  @param name		The username of the contact
 *  @param state	The typing state to be reported.
 */
static unsigned int mxit_send_typing( PurpleConnection *gc, const char *name, PurpleTypingState state )
{
	PurpleAccount*		account		= purple_connection_get_account( gc );
	struct MXitSession*	session		= purple_connection_get_protocol_data( gc );
	PurpleBuddy*		buddy;
	struct contact*		contact;
	gchar*				messageId	= NULL;

	/* find the buddy information for this contact (reference: "libpurple/blist.h") */
	buddy = purple_find_buddy( account, name );
	if ( !buddy ) {
		purple_debug_warning( MXIT_PLUGIN_ID, "mxit_send_typing: unable to find the buddy '%s'\n", name );
		return 0;
	}

	contact = purple_buddy_get_protocol_data( buddy );
	if ( !contact )
		return 0;

	/* does this contact support and want typing notification? */
	if ( ! ( contact->capabilities & MXIT_PFLAG_TYPING ) )
		return 0;

	messageId = purple_uuid_random();		/* generate a unique message id */

	switch ( state ) {
		case PURPLE_TYPING :		/* currently typing */
			mxit_send_msgevent( session, name, messageId, CP_MSGEVENT_TYPING );
			break;

		case PURPLE_TYPED :			/* stopped typing */
		case PURPLE_NOT_TYPING :	/* not typing / erased all text */
			mxit_send_msgevent( session, name, messageId, CP_MSGEVENT_STOPPED );
			break;

		default:
			break;
	}

	g_free( messageId );

	return 0;
}


/*========================================================================================================================*/

static PurplePluginProtocolInfo proto_info = {
	OPT_PROTO_REGISTER_NOSCREENNAME | OPT_PROTO_UNIQUE_CHATNAME | OPT_PROTO_IM_IMAGE | OPT_PROTO_INVITE_MESSAGE,			/* options */
	NULL,					/* user_splits */
	NULL,					/* protocol_options */
	{						/* icon_spec */
		"png,jpeg,bmp",										/* supported formats */
		32, 32,												/* min width & height */
		800, 800,											/* max width & height */
		CP_MAX_FILESIZE,									/* max filesize */
		PURPLE_ICON_SCALE_SEND | PURPLE_ICON_SCALE_DISPLAY	/* scaling rules */
	},
	mxit_list_icon,			/* list_icon */
	mxit_list_emblem,		/* list_emblem */
	mxit_status_text,		/* status_text */
	mxit_tooltip,			/* tooltip_text */
	mxit_status_types,		/* status types				[roster.c] */
	mxit_blist_menu,		/* blist_node_menu */
	mxit_chat_info,			/* chat_info				[multimx.c] */
	mxit_chat_info_defaults,/* chat_info_defaults */
	mxit_login,				/* login					[login.c] */
	mxit_close,				/* close */
	mxit_send_im,			/* send_im */
	NULL,					/* set_info */
	mxit_send_typing,		/* send_typing */
	mxit_get_info,			/* get_info */
	mxit_set_status,		/* set_status */
	NULL,					/* set_idle */
	NULL,					/* change_passwd */
	NULL,					/* add_buddy				[roster.c] */
	NULL,					/* add_buddies */
	mxit_remove_buddy,		/* remove_buddy				[roster.c] */
	NULL,					/* remove_buddies */
	NULL,					/* add_permit */
	NULL,					/* add_deny */
	NULL,					/* rem_permit */
	NULL,					/* rem_deny */
	NULL,					/* set_permit_deny */
	mxit_chat_join,			/* join_chat				[multimx.c] */
	mxit_chat_reject,		/* reject chat invite		[multimx.c] */
	mxit_chat_name,			/* get_chat_name			[multimx.c] */
	mxit_chat_invite,		/* chat_invite				[multimx.c] */
	mxit_chat_leave,		/* chat_leave				[multimx.c] */
	NULL,					/* chat_whisper */
	mxit_chat_send,			/* chat_send				[multimx.c] */
	mxit_keepalive,			/* keepalive */
	mxit_register,			/* register_user */
	NULL,					/* get_cb_info */
	NULL,					/* get_cb_away */
	mxit_buddy_alias,		/* alias_buddy				[roster.c] */
	mxit_buddy_group,		/* group_buddy				[roster.c] */
	mxit_rename_group,		/* rename_group				[roster.c] */
	mxit_free_buddy,		/* buddy_free */
	NULL,					/* convo_closed */
	NULL,					/* normalize */
	mxit_set_buddy_icon,	/* set_buddy_icon */
	NULL,					/* remove_group */			// TODO: Add function to move all contacts out of this group (cmd=30 - remove group)?
	NULL,					/* get_cb_real_name */
	NULL,					/* set_chat_topic */
	NULL,					/* find_blist_chat */
	NULL,					/* roomlist_get_list */
	NULL,					/* roomlist_cancel */
	NULL,					/* roomlist_expand_category */
	mxit_xfer_enabled,		/* can_receive_file			[filexfer.c] */
	mxit_xfer_tx,			/* send_file				[filexfer.c */
	mxit_xfer_new,			/* new_xfer					[filexfer.c] */
	mxit_offline_message,	/* offline_message */
	NULL,					/* whiteboard_prpl_ops */
	NULL,					/* send_raw */
	NULL,					/* roomlist_room_serialize */
	NULL,					/* unregister_user */
	NULL,					/* send_attention */
	NULL,					/* attention_types */
	sizeof( PurplePluginProtocolInfo ),		/* struct_size */
	mxit_get_text_table,	/* get_account_text_table */
	mxit_media_initiate,	/* initiate_media */
	mxit_media_caps,		/* get_media_caps */
	mxit_get_moods,			/* get_moods */
	NULL,					/* set_public_alias */
	NULL,					/* get_public_alias */
	mxit_add_buddy,			/* add_buddy_with_invite */
	NULL					/* add_buddies_with_invite */
};


static PurplePluginInfo plugin_info = {
	PURPLE_PLUGIN_MAGIC,								/* purple magic, this must always be PURPLE_PLUGIN_MAGIC */
	PURPLE_MAJOR_VERSION,								/* libpurple version */
	PURPLE_MINOR_VERSION,								/* libpurple version */
	PURPLE_PLUGIN_PROTOCOL,								/* plugin type (connecting to another network) */
	NULL,												/* UI requirement (NULL for core plugin) */
	0,													/* plugin flags (zero is default) */
	NULL,												/* plugin dependencies (set this value to NULL no matter what) */
	PURPLE_PRIORITY_DEFAULT,							/* libpurple priority */

	MXIT_PLUGIN_ID,										/* plugin id (must be unique) */
	MXIT_PLUGIN_NAME,									/* plugin name (this will be displayed in the UI) */
	DISPLAY_VERSION,									/* version of the plugin */

	MXIT_PLUGIN_SUMMARY,								/* short summary of the plugin */
	MXIT_PLUGIN_DESC,									/* description of the plugin (can be long) */
	MXIT_PLUGIN_EMAIL,									/* plugin author name and email address */
	MXIT_PLUGIN_WWW,									/* plugin website (to find new versions and reporting of bugs) */

	NULL,												/* function pointer for loading the plugin */
	NULL,												/* function pointer for unloading the plugin */
	NULL,												/* function pointer for destroying the plugin */

	NULL,												/* pointer to an UI-specific struct */
	&proto_info,										/* pointer to either a PurplePluginLoaderInfo or PurplePluginProtocolInfo struct */
	NULL,												/* pointer to a PurplePluginUiInfo struct */
	mxit_actions,										/* function pointer where you can define plugin-actions */

	/* padding */
	NULL,												/* pointer reserved for future use */
	NULL,												/* pointer reserved for future use */
	NULL,												/* pointer reserved for future use */
	NULL												/* pointer reserved for future use */
};


/*------------------------------------------------------------------------
 * Initialising the MXit plugin.
 *
 *  @param plugin	The plugin object
 */
static void init_plugin( PurplePlugin* plugin )
{
	PurpleAccountOption*	option;

	purple_debug_info( MXIT_PLUGIN_ID, "Loading MXit libPurple plugin...\n" );

	/* Configuration options */

	/* WAP server (reference: "libpurple/accountopt.h") */
	option = purple_account_option_string_new( _( "WAP Server" ), MXIT_CONFIG_WAPSERVER, DEFAULT_WAPSITE );
	proto_info.protocol_options = g_list_append( proto_info.protocol_options, option );

	option = purple_account_option_bool_new( _( "Connect via HTTP" ), MXIT_CONFIG_USE_HTTP, FALSE );
	proto_info.protocol_options = g_list_append( proto_info.protocol_options, option );

	option = purple_account_option_bool_new( _( "Enable splash-screen popup" ), MXIT_CONFIG_SPLASHPOPUP, FALSE );
	proto_info.protocol_options = g_list_append( proto_info.protocol_options, option );
}

PURPLE_INIT_PLUGIN( mxit, init_plugin, plugin_info );

