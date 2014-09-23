/*
 *					MXit Protocol libPurple Plugin
 *
 *						-- MultiMx GroupChat --
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

#include "internal.h"
#include "debug.h"

#include "protocol.h"
#include "mxit.h"
#include "multimx.h"
#include "markup.h"


#if 0
static void multimx_dump(struct multimx* multimx)
{
	purple_debug_info(MXIT_PLUGIN_ID, "MultiMX:\n");
	purple_debug_info(MXIT_PLUGIN_ID, "  Chat ID: %i\n", multimx->chatid);
	purple_debug_info(MXIT_PLUGIN_ID, "  Username: %s\n", multimx->roomid);
	purple_debug_info(MXIT_PLUGIN_ID, "  Alias: %s\n", multimx->roomname);
	purple_debug_info(MXIT_PLUGIN_ID, "  State: %i\n", multimx->state);
}
#endif


/*------------------------------------------------------------------------
 * Find a MultiMx session based on libpurple chatID.
 *
 *  @param session		The MXit session object
 *  @param id			The libpurple group-chat ID
 *  @return				The MultiMX room object (or NULL if not found)
 */
static struct multimx* find_room_by_id(struct MXitSession* session, int id)
{
	GList* x = session->rooms;

	while (x != NULL) {
		struct multimx* multimx = (struct multimx *) x->data;

		if (multimx->chatid == id)
			return multimx;

		x = g_list_next(x);
	}

	return NULL;
}


/*------------------------------------------------------------------------
 * Find a MultiMx session based on Alias
 *
 *  @param session		The MXit session object
 *  @param roomname		The UI room-name
 *  @return				The MultiMX room object (or NULL if not found)
 */
static struct multimx* find_room_by_alias(struct MXitSession* session, const char* roomname)
{
	GList* x = session->rooms;

	while (x != NULL) {
		struct multimx* multimx = (struct multimx *) x->data;

		if (!strcmp(multimx->roomname, roomname))
			return multimx;

		x = g_list_next(x);
	}

	return NULL;
}


/*------------------------------------------------------------------------
 * Find a MultiMx session based on Username (MXit RoomId)
 *
 *  @param session		The MXit session object
 *  @param username		The MXit RoomID (MultiMX contact username)
 *  @return				The MultiMX room object (or NULL if not found)
 */
static struct multimx* find_room_by_username(struct MXitSession* session, const char* username)
{
	GList* x = session->rooms;

	while (x != NULL) {
		struct multimx* multimx = (struct multimx *) x->data;

		if (!strcmp(multimx->roomid, username))
			return multimx;

		x = g_list_next(x);
	}

	return NULL;
}


/*------------------------------------------------------------------------
 * Create a GroupChat room, and add to list of rooms.
 *
 *  @param session		The MXit session object
 *  @param roomid		The MXit RoomID (MultiMX contact username)
 *  @param roomname		The UI room-name
 *  @param state		The initial state of the room (see multimx.h)
 *  @return				The MultiMX room object
 */
static struct multimx* room_create(struct MXitSession* session, const char* roomid, const char* roomname, short state)
{
	struct multimx* multimx = NULL;
	static int groupchatID = 1;

	purple_debug_info(MXIT_PLUGIN_ID, "Groupchat create - roomid='%s' roomname='%s'\n", roomid, roomname);

	/* Create a new GroupChat */
	multimx = g_new0(struct multimx, 1);

	/* Initialize groupchat */
	g_strlcpy(multimx->roomid, roomid, sizeof(multimx->roomid));
	g_strlcpy(multimx->roomname, roomname, sizeof(multimx->roomname));
	multimx->chatid = groupchatID++;
	multimx->state = state;

	/* determine our nickname (from profile) */
	if (session->profile && (session->profile->nickname[0] != '\0'))
		multimx->nickname = g_strdup(session->profile->nickname);

	/* Add to GroupChat list */
	session->rooms = g_list_append(session->rooms, multimx);

	return multimx;
}


/*------------------------------------------------------------------------
 * Free the Groupchat room.
 *
 *  @param session		The MXit session object
 *  @param multimx		The MultiMX room object to deallocate
 */
static void room_remove(struct MXitSession* session, struct multimx* multimx)
{
	/* Remove from GroupChat list */
	session->rooms = g_list_remove(session->rooms, multimx);

	/* free nickname */
	if (multimx->nickname)
		g_free(multimx->nickname);

	/* Deallocate it */
	g_free (multimx);
	multimx = NULL;
}


/*------------------------------------------------------------------------
 * Another user has join the GroupChat, add them to the member-list.
 *
 *  @param convo		The Conversation object
 *  @param nickname		The nickname of the user who joined the room
 */
static void member_added(PurpleConversation* convo, const char* nickname)
{
	purple_debug_info(MXIT_PLUGIN_ID, "member_added: '%s'\n", nickname);

	purple_conv_chat_add_user(PURPLE_CONV_CHAT(convo), nickname, NULL, PURPLE_CBFLAGS_NONE, TRUE);
}


/*------------------------------------------------------------------------
 * Another user has left the GroupChat, remove them from the member-list.
 *
 *  @param convo		The Conversation object
 *  @param nickname		The nickname of the user who left the room
 */
static void member_removed(PurpleConversation* convo, const char* nickname)
{
	purple_debug_info(MXIT_PLUGIN_ID, "member_removed: '%s'\n", nickname);

	purple_conv_chat_remove_user(PURPLE_CONV_CHAT(convo), nickname, NULL);
}


/*------------------------------------------------------------------------
 * A user was kicked from the GroupChat, remove them from the member-list.
 *
 *  @param convo		The Conversation object
 *  @param nickname		The nickname of the user who was kicked
 */
static void member_kicked(PurpleConversation* convo, const char* nickname)
{
	purple_debug_info(MXIT_PLUGIN_ID, "member_kicked: '%s'\n", nickname);

	purple_conv_chat_remove_user(PURPLE_CONV_CHAT(convo), nickname, _("was kicked"));
}


/*------------------------------------------------------------------------
 * You were kicked from the GroupChat.
 *
 *  @param convo		The Conversation object
 *  @param session		The MXit session object
 *  @param multimx		The MultiMX room object
 */
static void you_kicked(PurpleConversation* convo, struct MXitSession* session, struct multimx* multimx)
{
	purple_debug_info(MXIT_PLUGIN_ID, "you_kicked\n");

	purple_conv_chat_write(PURPLE_CONV_CHAT(convo), "MXit", _("You have been kicked from this MultiMX."), PURPLE_MESSAGE_SYSTEM, time(NULL));
	purple_conv_chat_clear_users(PURPLE_CONV_CHAT(convo));
	serv_got_chat_left(session->con, multimx->chatid);
}


/*------------------------------------------------------------------------
 * Update the full GroupChat member list.
 *
 *  @param convo		The Conversation object
 *  @param data			The nicknames of the users in the room (separated by \n)
 */
static void member_update(PurpleConversation* convo, char* data)
{
	gchar** userlist;
	int i = 0;

	purple_debug_info(MXIT_PLUGIN_ID, "member_update: '%s'\n", data);

	/* Clear list */
	purple_conv_chat_clear_users(PURPLE_CONV_CHAT(convo));

	/* Add each member */
	data = g_strstrip(data);				/* string leading & trailing whitespace */
	userlist = g_strsplit(data, "\n", 0);	/* tokenize string */
	while (userlist[i] != NULL) {
		purple_debug_info(MXIT_PLUGIN_ID, "member_update - adding: '%s'\n", userlist[i]);
		purple_conv_chat_add_user(PURPLE_CONV_CHAT(convo), userlist[i], NULL, PURPLE_CBFLAGS_NONE, FALSE);
		i++;
	}
	g_strfreev(userlist);
}


/* -------------------------------------------------------------------------------------------------
 * Calls from MXit Protocol layer
 * ------------------------------------------------------------------------------------------------- */

/*------------------------------------------------------------------------
 * Received a Subscription Request to a MultiMX room.
 *
 *  @param session		The MXit session object
 *  @param contact		The invited MultiMX room's contact information
 *  @param creator		The nickname of the room's creator / invitor
 */
void multimx_invite(struct MXitSession* session, struct contact* contact, const char* creator)
{
	GHashTable *components;

	purple_debug_info(MXIT_PLUGIN_ID, "Groupchat invite to '%s' (roomid='%s') by '%s'\n", contact->alias, contact->username, creator);

	/* Check if the room already exists (ie, already joined or invite pending) */
	if (find_room_by_username(session, contact->username) != NULL)
		return;

	/* Create a new room */
	room_create(session, contact->username, contact->alias, STATE_INVITED);

	components = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	g_hash_table_insert(components, g_strdup("room"), g_strdup(contact->alias));

	/* Call libpurple - will trigger either 'mxit_chat_join' or 'mxit_chat_reject' */
	serv_got_chat_invite(session->con, contact->alias, creator, NULL, components);
}


/*------------------------------------------------------------------------
 * MultiMX room has been added to the roster.
 *
 *  @param session		The MXit session object
 *  @param contact		The MultiMX room's contact information
 */
void multimx_created(struct MXitSession* session, struct contact* contact)
{
	PurpleConnection *gc = session->con;
	struct multimx* multimx = NULL;

	purple_debug_info(MXIT_PLUGIN_ID, "Groupchat '%s' created as '%s'\n", contact->alias, contact->username);

	/* Find matching MultiMX group */
	multimx = find_room_by_username(session, contact->username);
	if (multimx == NULL) {
		multimx = room_create(session, contact->username, contact->alias, TRUE);
	}
	else if (multimx->state == STATE_INVITED) {
		/* After successfully accepting an invitation */
		multimx->state = STATE_JOINED;
	}

	/* Call libpurple - will trigger 'mxit_chat_join' */
	serv_got_joined_chat(gc, multimx->chatid, multimx->roomname);

	/* Send ".list" command to GroupChat server to retrieve current member-list */
	mxit_send_message(session, multimx->roomid, ".list", FALSE, FALSE);
}


/*------------------------------------------------------------------------
 * Is this username a MultiMX contact?
 *
 *  @param session		The MXit session object
 *  @param username		The username of the contact
 *  @return				TRUE if this contacts matches the RoomID of a MultiMX room.
 */
gboolean is_multimx_contact(struct MXitSession* session, const char* username)
{
	/* Check for username in list of open rooms */
	return (find_room_by_username(session, username) != NULL);
}


/*------------------------------------------------------------------------
 * Received a message from a MultiMX room.
 *
 */
void multimx_message_received(struct RXMsgData* mx, char* msg, int msglen, short msgtype, int msgflags)
{
	struct multimx* multimx = NULL;

	purple_debug_info(MXIT_PLUGIN_ID, "Groupchat message received: %s\n", msg);

	/* Find matching multimx group */
	multimx = find_room_by_username(mx->session, mx->from);
	if (multimx == NULL) {
		purple_debug_error(MXIT_PLUGIN_ID, "Groupchat '%s' not found\n", mx->from);
		return;
	}

	/* Determine if system message or a message from a contact */
	if (msg[0] == '<') {
		/* Message contains embedded nickname - must be from contact */
		unsigned int i;

		for (i = 1; i < strlen(msg); i++) {		/* search for end of nickname */
			if (msg[i] == '>') {
				msg[i] = '\0';
				g_free(mx->from);
				mx->from = g_strdup(&msg[1]);
				msg = &msg[i+2];		/* skip '>' and newline */
				break;
			}
		}

		/* now do markup processing on the message */
		mx->chatid = multimx->chatid;
		mxit_parse_markup(mx, msg, strlen(msg), msgtype, msgflags);
	}
	else {
		/* Must be a service message */
		char* ofs;

		PurpleConversation* convo = purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT, multimx->roomname, mx->session->acc);
		if (convo == NULL) {
			purple_debug_error(MXIT_PLUGIN_ID, "Conversation '%s' not found\n", multimx->roomname);
			return;
		}

		/* Determine if somebody has joined or left - update member-list */
		if ((ofs = strstr(msg, " has joined")) != NULL) {
			/* Somebody has joined */
			*ofs = '\0';
			member_added(convo, msg);
			mx->processed = TRUE;
		}
		else if ((ofs = strstr(msg, " has left")) != NULL) {
			/* Somebody has left */
			*ofs = '\0';
			member_removed(convo, msg);
			mx->processed = TRUE;
		}
		else if ((ofs = strstr(msg, " has been kicked")) != NULL) {
			/* Somebody has been kicked */
			*ofs = '\0';
			member_kicked(convo, msg);
			mx->processed = TRUE;
		}
		else if (strcmp(msg, "You have been kicked.") == 0) {
			/* You have been kicked */
			you_kicked(convo, mx->session, multimx);
			mx->processed = TRUE;
		}
		else if (g_str_has_prefix(msg, "The following users are in this MultiMx:") == TRUE) {
			member_update(convo, msg + strlen("The following users are in this MultiMx:") + 1);
			mx->processed = TRUE;
		}
		else {
			/* Display server message in chat window */
			serv_got_chat_in(mx->session->con, multimx->chatid, "MXit", PURPLE_MESSAGE_SYSTEM, msg, mx->timestamp);
			mx->processed = TRUE;
		}
	}
}



/* -------------------------------------------------------------------------------------------------
 * Callbacks from libpurple
 * ------------------------------------------------------------------------------------------------- */

/*------------------------------------------------------------------------
 * User has selected "Add Chat" from the main menu.
 *
 *  @param gc			The connection object
 *  @return				A list of chat configuration values
 */
GList* mxit_chat_info(PurpleConnection *gc)
{
	GList *m = NULL;
	struct proto_chat_entry *pce;

	/* Configuration option: Room Name */
	pce = g_new0(struct proto_chat_entry, 1);
	pce->label = _( "_Room Name:" );
	pce->identifier = "room";
	pce->required = TRUE;
	m = g_list_append(m, pce);

	return m;
}


/*------------------------------------------------------------------------
 * User has joined a chatroom, either because they are creating it or they
 * accepted an invite.
 *
 *  @param gc			The connection object
 *  @param components	The list of chat configuration values
 */
void mxit_chat_join(PurpleConnection *gc, GHashTable *components)
{
	struct MXitSession* session = purple_connection_get_protocol_data(gc);
	const char* roomname = NULL;
	struct multimx* multimx = NULL;

	purple_debug_info(MXIT_PLUGIN_ID, "mxit_chat_join\n");

	/* Determine if groupchat already exists */
	roomname = g_hash_table_lookup(components, "room");
	multimx = find_room_by_alias(session, roomname);

	if (multimx != NULL) {
		/* The room information already exists */

		if (multimx->state == STATE_INVITED) {
			/* Invite is pending */
			purple_debug_info(MXIT_PLUGIN_ID, "Groupchat %i accept sent\n", multimx->chatid);

			/* Send Subscription Accept to MXit */
			mxit_send_allow_sub(session, multimx->roomid, multimx->roomname);
		}
		else {
			/* Join existing room */
			purple_debug_info(MXIT_PLUGIN_ID, "Groupchat %i rejoined\n", multimx->chatid);

			serv_got_joined_chat(gc, multimx->chatid, multimx->roomname);
		}
	}
	else {
		/* Send Groupchat Create to MXit */
		mxit_send_groupchat_create(session, roomname, 0, NULL);
	}
}


/*------------------------------------------------------------------------
 * User has rejected an invite to join a MultiMX room.
 *
 *  @param gc			The connection object
 *  @param components	The list of chat configuration values
 */
void mxit_chat_reject(PurpleConnection *gc, GHashTable* components)
{
	struct MXitSession* session = purple_connection_get_protocol_data(gc);
	const char* roomname = NULL;
	struct multimx* multimx = NULL;

	purple_debug_info(MXIT_PLUGIN_ID, "mxit_chat_reject\n");

	roomname = g_hash_table_lookup(components, "room");
	multimx = find_room_by_alias(session, roomname);
	if (multimx == NULL) {
		purple_debug_error(MXIT_PLUGIN_ID, "Groupchat '%s' not found\n", roomname);
		return;
	}

	/* Send Subscription Reject to MXit */
	mxit_send_deny_sub(session, multimx->roomid, NULL);

	/* Remove from our list of rooms */
	room_remove(session, multimx);
}


/*------------------------------------------------------------------------
 * Return name of chatroom (on mouse hover)
 *
 *  @param components	The list of chat configuration values.
 *  @return				The name of the chat room
 */
char* mxit_chat_name(GHashTable *components)
{
	return g_strdup(g_hash_table_lookup(components, "room"));
}


/*------------------------------------------------------------------------
 * User has selected to invite somebody to a chatroom.
 *
 *  @param gc			The connection object
 *  @param id			The chat room ID
 *  @param msg			The invitation message entered by the user
 *  @param name			The username of the person to invite
 */
void mxit_chat_invite(PurpleConnection *gc, int id, const char *msg, const char *username)
{
	struct MXitSession* session = purple_connection_get_protocol_data(gc);
	struct multimx* multimx = NULL;
	PurpleBuddy* buddy;
	PurpleConversation *convo;
	char* tmp;

	purple_debug_info(MXIT_PLUGIN_ID, "Groupchat invite to '%s'\n", username);

	/* Find matching MultiMX group */
	multimx = find_room_by_id(session, id);
	if (multimx == NULL) {
		purple_debug_error(MXIT_PLUGIN_ID, "Could not find groupchat %i\n", id);
		return;
	}

	/* Send invite to MXit */
	mxit_send_groupchat_invite(session, multimx->roomid, 1, &username);

	/* Find the buddy information for this contact (reference: "libpurple/blist.h") */
	buddy = purple_find_buddy(session->acc, username);
	if (!buddy) {
		purple_debug_warning(MXIT_PLUGIN_ID, "mxit_chat_invite: unable to find the buddy '%s'\n", username);
		return;
	}

	convo = purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT, multimx->roomname, session->acc);
	if (convo == NULL) {
		purple_debug_error(MXIT_PLUGIN_ID, "Conversation '%s' not found\n", multimx->roomname);
		return;
	}

	/* Display system message in chat window */
	tmp = g_strdup_printf("%s: %s", _("You have invited"), purple_buddy_get_alias(buddy));
	purple_conv_chat_write(PURPLE_CONV_CHAT(convo), "MXit", tmp, PURPLE_MESSAGE_SYSTEM, time(NULL));
	g_free(tmp);
}


/*------------------------------------------------------------------------
 * User as closed the chat window, and the chatroom is not marked as persistent.
 *
 *  @param gc			The connection object
 *  @param id			The chat room ID
 */
void mxit_chat_leave(PurpleConnection *gc, int id)
{
	struct MXitSession* session = purple_connection_get_protocol_data(gc);
	struct multimx* multimx = NULL;

	purple_debug_info(MXIT_PLUGIN_ID, "Groupchat %i leave\n", id);

	/* Find matching multimx group */
	multimx = find_room_by_id(session, id);
	if (multimx == NULL) {
		purple_debug_error(MXIT_PLUGIN_ID, "Could not find groupchat %i\n", id);
		return;
	}

	/* Send Remove Groupchat to MXit */
	mxit_send_remove(session, multimx->roomid);

	/* Remove from our list of rooms */
	room_remove(session, multimx);
}


/*------------------------------------------------------------------------
 * User has entered a message in a chatroom window, send it to the MXit server.
 *
 *  @param gc			The connection object
 *  @param id			The chat room ID
 *  @param message		The sent message data
 *  @param flags		The message flags
 *  @return				Indicates success / failure
 */
int mxit_chat_send(PurpleConnection *gc, int id, const char *message, PurpleMessageFlags flags)
{
	struct MXitSession* session = purple_connection_get_protocol_data(gc);
	struct multimx* multimx = NULL;
	const char* nickname;

	purple_debug_info(MXIT_PLUGIN_ID, "Groupchat %i message send: '%s'\n", id, message);

	/* Find matching MultiMX group */
	multimx = find_room_by_id(session, id);
	if (multimx == NULL) {
		purple_debug_error(MXIT_PLUGIN_ID, "Could not find groupchat %i\n", id);
		return -1;
	}

	/* Send packet to MXit */
	mxit_send_message(session, multimx->roomid, message, TRUE, FALSE);

	/* Determine our nickname to display */
	if (multimx->nickname)
		nickname = multimx->nickname;
	else
		nickname = purple_account_get_alias(purple_connection_get_account(gc));		/* local alias */

	/* Display message in chat window */
	serv_got_chat_in(gc, id, nickname, flags, message, time(NULL));

	return 0;
}

