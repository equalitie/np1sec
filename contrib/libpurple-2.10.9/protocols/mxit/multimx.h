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

#ifndef		_MXIT_MULTIMX_H_
#define		_MXIT_MULTIMX_H_

#include	"roster.h"


/* GroupChat Room state */
#define		STATE_CREATOR	0
#define		STATE_INVITED	1
#define		STATE_JOINED	2

/*
 * a MultiMX room
 */
struct multimx {
	char	roomname[MXIT_CP_MAX_ALIAS_LEN];	/* name of the room */
	char	roomid[MXIT_CP_MAX_JID_LEN];		/* internal JID for room */
	int		chatid;								/* libpurple chat ID */
	char*	nickname;							/* our nickname in the room */
	short	state;								/* state */
};


/*
 * Received a Subscription Request to a MultiMX room.
 */
void multimx_invite(struct MXitSession* session, struct contact* contact, const char* creator);

/*
 * MultiMX room has been added to the roster.
 */
void multimx_created(struct MXitSession* session, struct contact* contact);

/*
 * Is this username a MultiMX contact?
 */
gboolean is_multimx_contact(struct MXitSession* session, const char* username);

/*
 * Received a message from a MultiMX room.
 */
void multimx_message_received(struct RXMsgData* mx, char* message, int len, short msgtype, int msgflags);

/*
 * User has selected "Add Chat" from the main menu.
 */
GList* mxit_chat_info(PurpleConnection *gc);

/*
 * User has joined a chatroom, either because they are creating it or they accepted an invite.
 */
void mxit_chat_join(PurpleConnection *gc, GHashTable *data);

/*
 * User has rejected an invite to join a MultiMX room.
 */
void mxit_chat_reject(PurpleConnection *gc, GHashTable* components);

/*
 * Return name of chatroom (on mouse hover)
 */
char* mxit_chat_name(GHashTable *data);

/*
 * User has selected to invite somebody to a chatroom.
 */
void mxit_chat_invite(PurpleConnection *gc, int id, const char *msg, const char *name);

/*
 * User as closed the chat window, and the chatroom is not marked as persistent.
 */
void mxit_chat_leave(PurpleConnection *gc, int id);

/*
 * User has entered a message in a chatroom window, send it to the MXit server.
 */
int mxit_chat_send(PurpleConnection *gc, int id, const char *message, PurpleMessageFlags flags);


#endif		/* _MXIT_MULTIMX_H_ */
