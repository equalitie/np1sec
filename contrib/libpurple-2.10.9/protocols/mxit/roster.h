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

#ifndef		_MXIT_ROSTER_H_
#define		_MXIT_ROSTER_H_


/* MXit contact presence states */
#define		MXIT_PRESENCE_OFFLINE		0x00
#define		MXIT_PRESENCE_ONLINE		0x01
#define		MXIT_PRESENCE_AWAY			0x02
#define		MXIT_PRESENCE_AVAILABLE		0x03
#define		MXIT_PRESENCE_DND			0x04


/* MXit contact types */
#define		MXIT_TYPE_MXIT				0x00
#define		MXIT_TYPE_JABBER			0x01
#define		MXIT_TYPE_MSN				0x02
#define		MXIT_TYPE_YAHOO				0x03
#define		MXIT_TYPE_ICQ				0x04
#define		MXIT_TYPE_AIM				0x05
#define		MXIT_TYPE_QQ				0x06
#define		MXIT_TYPE_WV				0x07
#define		MXIT_TYPE_BOT				0x08
#define		MXIT_TYPE_CHATROOM			0x09
#define		MXIT_TYPE_SMS				0x0A
#define		MXIT_TYPE_GROUP				0x0B
#define		MXIT_TYPE_GALLERY			0x0C
#define		MXIT_TYPE_INFO				0x0D
#define		MXIT_TYPE_MULTIMX			0x0E
#define		MXIT_TYPE_HYBRID			0x0F


/* MXit contact moods */
#define		MXIT_MOOD_NONE				0x00
#define		MXIT_MOOD_ANGRY				0x01
#define		MXIT_MOOD_EXCITED			0x02
#define		MXIT_MOOD_GRUMPY			0x03
#define		MXIT_MOOD_HAPPY				0x04
#define		MXIT_MOOD_INLOVE			0x05
#define		MXIT_MOOD_INVINCIBLE		0x06
#define		MXIT_MOOD_SAD				0x07
#define		MXIT_MOOD_HOT				0x08
#define		MXIT_MOOD_SICK				0x09
#define		MXIT_MOOD_SLEEPY			0x0A
#define		MXIT_MOOD_BORED				0x0B
#define		MXIT_MOOD_COLD				0x0C
#define		MXIT_MOOD_CONFUSED			0x0D
#define		MXIT_MOOD_HUNGRY			0x0E
#define		MXIT_MOOD_STRESSED			0x0F


/* MXit contact flags */
//#define		MXIT_CFLAG_HIDDEN			0x02		/* (DEPRECATED) */
#define		MXIT_CFLAG_GATEWAY			0x04
#define		MXIT_CFLAG_FOCUS_SEND_BLANK	0x20000


/* MXit presence flags */
#define		MXIT_PFLAG_VOICE			0x1
#define		MXIT_PFLAG_VIDEO			0x2
#define		MXIT_PFLAG_TYPING			0x4


/* Subscription types */
#define		MXIT_SUBTYPE_BOTH			'B'
#define		MXIT_SUBTYPE_PENDING		'P'
#define		MXIT_SUBTYPE_ASK			'A'
#define		MXIT_SUBTYPE_REJECTED		'R'
#define		MXIT_SUBTYPE_DELETED		'D'
#define		MXIT_SUBTYPE_NONE			'N'


/* client protocol constants */
#define		MXIT_CP_MAX_JID_LEN			64
#define		MXIT_CP_MAX_GROUP_LEN		32
#define		MXIT_CP_MAX_ALIAS_LEN		100

#define		MXIT_DEFAULT_GROUP			"MXit"


/*
 * a MXit contact
 */
struct contact {
	char		username[MXIT_CP_MAX_JID_LEN+1];	/* unique contact name (with domain) */
	char		alias[MXIT_CP_MAX_ALIAS_LEN+1];		/* contact alias (what will be seen) */
	char		groupname[MXIT_CP_MAX_GROUP_LEN+1];	/* contact group name */

	short		type;								/* contact type */
	short		mood;								/* contact current mood */
	int			flags;								/* contact flags */
	short		presence;							/* presence state */
	int			capabilities;						/* contact capabilities */
	short		subtype;							/* subscription type */

	char*		msg;								/* invite/rejection message */

	char		customMood[16];						/* custom mood */
	char*		statusMsg;							/* status message */
	char*		avatarId;							/* avatarId */

	/* invites only */
	void*		profile;							/* user's profile (if available) */
	int			imgid;								/* avatar image id in the imgstore */
};

/* Presence / Status */
GList* mxit_status_types( PurpleAccount* account );
int mxit_convert_presence( const char* id );
const char* mxit_convert_presence_to_name( short no );
const char* mxit_convert_subtype_to_name( short subtype );

/* Moods */
int mxit_convert_mood( const char* id );
const char* mxit_convert_mood_to_name( short id );

/* MXit Protocol callbacks */
void mxit_update_contact( struct MXitSession* session, struct contact* contact );
void mxit_update_buddy_presence( struct MXitSession* session, const char* username, short presence, short mood, const char* customMood, const char* statusMsg, int flags );
void mxit_update_buddy_avatar( struct MXitSession* session, const char* username, const char* avatarId );
void mxit_new_subscription( struct MXitSession* session, struct contact* contact );
void mxit_update_blist( struct MXitSession* session );
gboolean is_mxit_chatroom_contact( struct MXitSession* session, const char* username );
struct contact* get_mxit_invite_contact( struct MXitSession* session, const char* username );

/* libPurple callbacks */
void mxit_add_buddy( PurpleConnection* gc, PurpleBuddy* buddy, PurpleGroup* group, const char* message );
void mxit_remove_buddy( PurpleConnection* gc, PurpleBuddy* buddy, PurpleGroup* group );
void mxit_buddy_alias( PurpleConnection* gc, const char* who, const char* alias );
void mxit_buddy_group( PurpleConnection* gc, const char* who, const char* old_group, const char* new_group );
void mxit_rename_group( PurpleConnection* gc, const char* old_name, PurpleGroup* group, GList* moved_buddies );
PurpleMood* mxit_get_moods( PurpleAccount *account );


#endif		/* _MXIT_ROSTER_H_ */
