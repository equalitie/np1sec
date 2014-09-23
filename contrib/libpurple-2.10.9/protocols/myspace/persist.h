/* MySpaceIM Protocol Plugin, persist commands
 *
 * Copyright (C) 2007, Jeff Connelly <jeff2@soc.pidgin.im>
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

#ifndef _MYSPACE_PERSIST_H
#define _MYSPACE_PERSIST_H

/** Command codes */
#define MSIM_CMD_GET               1
#define MSIM_CMD_PUT               2
#define MSIM_CMD_DELETE            3

/** Command bit fields */
#define MSIM_CMD_BIT_CODE          255        /*< Bits specifying command code */
#define MSIM_CMD_BIT_REPLY         256        /**< 1=reply, 0=request */
#define MSIM_CMD_BIT_ACTION        512        /**< 1=action, 0=information */
#define MSIM_CMD_BIT_ERROR        1024        /**< 1=error, 0=normal */

/** Macros to read cmd bitfield. */
#define MSIM_CMD_GET_CODE(x)      (x & MSIM_CMD_BIT_CODE)
#define MSIM_CMD_IS_REPLY(x)      (x & MSIM_CMD_BIT_REPLY)
#define MSIM_CMD_IS_REQUEST(x)   !(x & MSIM_CMD_BIT_REPLY)
#define MSIM_CMD_IS_ACTION(x)     (x & MSIM_CMD_BIT_ACTION)
#define MSIM_CMD_IS_INFO(x)      !(x & MSIM_CMD_BIT_ACTION)
#define MSIM_CMD_IS_ERROR(x)      (x & MSIM_CMD_BIT_ERROR)
#define MSIM_CMD_IS_NORMAL(x)    !(x & MSIM_CMD_BIT_ERROR)

/** Define a set of _DSN and _LID constants for a persistance request. */
#define MSIM_PERSIST_DSN_LID(name,dsn,lid)             \
    static const int name##_DSN = dsn;                 \
    static const int name##_LID = lid;

/* Can't do this, errors:
 *     persist.h:51:3: error: '#' is not followed by a macro parameter
 *  In file included from myspace.c:37:
 *  persist.h:56: error: expected ')' before numeric constant
 * So instead, I define const ints above.
#define MSIM_PERSIST_DSN_LID(name,dsn,lid)             \
	#define name##_DSN        dsn                  \
	#define name##_LID        lid
#endif
*/

/** Messages to Get information                dsn lid */
MSIM_PERSIST_DSN_LID(MG_LIST_ALL_CONTACTS,         0, 1)
MSIM_PERSIST_DSN_LID(MG_USER_INFO_BY_ID,           0, 2)
MSIM_PERSIST_DSN_LID(MG_OWN_IM_INFO,               1, 4)
MSIM_PERSIST_DSN_LID(MG_IM_INFO_BY_ID,             1, 17)
MSIM_PERSIST_DSN_LID(MG_LIST_ALL_GROUPS,           2, 6)
MSIM_PERSIST_DSN_LID(MG_MYSPACE_INFO_BY_ID,        4, 3)
MSIM_PERSIST_DSN_LID(MG_OWN_MYSPACE_INFO,          4, 5)
MSIM_PERSIST_DSN_LID(MG_MYSPACE_INFO_BY_STRING,    5, 7)
MSIM_PERSIST_DSN_LID(MG_CHECK_MAIL,                7, 18)
MSIM_PERSIST_DSN_LID(MG_WEB_CHALLENGE,            17, 26)
MSIM_PERSIST_DSN_LID(MG_USER_SONG,                21, 28)
MSIM_PERSIST_DSN_LID(MG_SERVER_INFO,             101, 20)

/** Messages to Change/send information */
MSIM_PERSIST_DSN_LID(MC_USER_PREFERENCES,          1, 10)
MSIM_PERSIST_DSN_LID(MC_DELETE_CONTACT_INFO,       0, 8)
MSIM_PERSIST_DSN_LID(MC_CONTACT_INFO,              0, 9)
MSIM_PERSIST_DSN_LID(MC_SET_USERNAME,              9, 14)
MSIM_PERSIST_DSN_LID(MC_IMPORT_ALL_FRIENDS,       14, 21)
MSIM_PERSIST_DSN_LID(MC_INVITE,                   16, 25)

/** Messages to Delete information */
MSIM_PERSIST_DSN_LID(MD_DELETE_BUDDY,              0, 8)

/** Error codes */
#define MERR_PARSE                    1
#define MERR_NOT_LOGGED_IN            2
#define MERR_ANOTHER_LOGIN            6
#define MERR_BAD_EMAIL                259
#define MERR_BAD_PASSWORD             260
#define MERR_BAD_UID_IN_PERSISTR      4352

#endif /* !_MYSPACE_PERSIST_H */
