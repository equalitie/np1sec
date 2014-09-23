/* MySpaceIM Protocol Plugin, header file
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

#ifndef _MYSPACE_MYSPACE_H
#define _MYSPACE_MYSPACE_H

#include "internal.h"

/* Other includes */
#include <string.h>
#include <errno.h>/* for EAGAIN */
#include <stdarg.h>
#include <math.h>

#include <glib.h>

#ifdef _WIN32
#include "win32dep.h"
#else
/* For recv() and send(); needed to match Win32 */
#include <sys/types.h>
#include <sys/socket.h>
#endif

#include "notify.h"
#include "plugin.h"
#include "accountopt.h"
#include "version.h"
#include "cipher.h"     /* for SHA-1 */
#include "util.h"       /* for base64 */
#include "debug.h"      /* for purple_debug_info */
#include "request.h"    /* For dialogs used in setting the username */
#include "xmlnode.h"
#include "core.h"
#include "conversation.h" /* For late normalization */

/* MySpaceIM includes */
#include "persist.h"
#include "message.h"
#include "session.h"
#include "zap.h"
#include "markup.h"
#include "user.h"

/* Conditional compilation options */
/* Send third-party client version? (Recognized by us and Miranda's plugin) */
/*#define MSIM_SEND_CLIENT_VERSION              */

/* Debugging options */
/* Low-level and rarely needed */
/*#define MSIM_DEBUG_PARSE             */
/*#define MSIM_DEBUG_LOGIN_CHALLENGE*/
/*#define MSIM_DEBUG_RXBUF            */

/* Encode unknown HTML tags from IM clients in messages as [tag], instead of
 * ignoring. Useful for debugging */
/*#define MSIM_MARKUP_SHOW_UNKNOWN_TAGS  */

/* Define to cause init_plugin() to run some tests and print
 * the results to the Purple debug log, then exit. Useful to
 * run with 'pidgin -d' to see the output. Don't define if
 * you want to actually use the plugin! */
/*#define MSIM_SELF_TEST            */

/* Constants */

/* Maximum length of a password that is acceptable. This is the limit
 * on the official client (build 679) and on the 'new password' field at
 * http://settings.myspace.com/index.cfm?fuseaction=user.changepassword
 * (though curiously, not on the 'current password' field). */

/* After login fails, if password is greater than this many characters,
 * warn user that it may be too long. */
#define MSIM_MAX_PASSWORD_LENGTH    10

/* Maximum length of usernames, when setting. */
#define MSIM_MAX_USERNAME_LENGTH    25

/* Build version of MySpaceIM to report to servers (1.0.xxx.0) */
#define MSIM_CLIENT_VERSION         697

/* Check for a newer official MySpaceIM client on startup?
 * (Mostly useful for developers) */
/*#define MSIM_CHECK_NEWER_VERSION*/

/* Language codes from http://www.microsoft.com/globaldev/reference/oslocversion.mspx */
#define MSIM_LANGUAGE_ID_ENGLISH    1033
#define MSIM_LANGUAGE_NAME_ENGLISH  "ENGLISH"

/* msimprpl version string of this plugin */
#define MSIM_PRPL_VERSION_STRING    "0.18"

/* Default server */
#define MSIM_SERVER                 "im.myspace.akadns.net"
#define MSIM_PORT                   1863        /* TODO: alternate ports and automatic */

/* Time between keepalives (seconds) - if no data within this time, is dead. */
#define MSIM_KEEPALIVE_INTERVAL     (3 * 60)
/*#define MSIM_USE_KEEPALIVE*/

/* Time to check if alive (seconds) */
#define MSIM_KEEPALIVE_INTERVAL_CHECK   30

/* Time to check for new mail (milliseconds) */
#define MSIM_MAIL_INTERVAL_CHECK    (60 * 1000)

/* Constants */
#define HASH_SIZE                   0x14        /**< Size of SHA-1 hash for login */
#define NONCE_SIZE                  0x20        /**< Half of decoded 'nc' field */
#define MSIM_READ_BUF_SIZE          (15 * 1024) /**< Receive buffer size */
#define MSIM_FINAL_STRING           "\\final\\" /**< Message end marker */

/* Messages */
#define MSIM_BM_ACTION_OR_IM_DELAYABLE  1
#define MSIM_BM_STATUS                  100
#define MSIM_BM_ACTION_OR_IM_INSTANT    121
#define MSIM_BM_MEDIA                   122
#define MSIM_BM_PROFILE                 124
#define MSIM_BM_STATUS_MOOD             126
#define MSIM_BM_UNOFFICIAL_CLIENT       200

/* Authentication algorithm for login2 */
#define MSIM_AUTH_ALGORITHM         196610

/* Recognized challenge length */
#define MSIM_AUTH_CHALLENGE_LENGTH  0x40

#ifdef SEND_OUR_IP_ADDRESSES
/* TODO: obtain IPs of network interfaces from user's machine, instead of
 * hardcoding these values below (used in msim_compute_login_response).
 * This is not immediately
 * important because you can still connect and perform basic
 * functions of the protocol. There is also a high chance that the addreses
 * are RFC1918 private, so the servers couldn't do anything with them
 * anyways except make note of that fact. Probably important for any
 * kind of direct connection, or file transfer functionality.
 */

#define MSIM_LOGIN_IP_LIST  "\x00\x00\x00\x00\x05\x7f\x00\x00\x01\x00\x00\x00\x00\x0a\x00\x00\x40\xc0\xa8\x58\x01\xc0\xa8\x3c\x01"
#define MSIM_LOGIN_IP_LIST_LEN         25
#endif /* SEND_OUR_IP_ADDRESSES */

/* Indexes into status string (0|1|2|3|..., but 0 always empty) */
#define MSIM_STATUS_ORDINAL_EMPTY       0
#define MSIM_STATUS_ORDINAL_UNKNOWNs    1
#define MSIM_STATUS_ORDINAL_ONLINE      2
#define MSIM_STATUS_ORDINAL_UNKNOWNss   3
#define MSIM_STATUS_ORDINAL_HEADLINE    4
#define MSIM_STATUS_ORDINAL_UNKNOWNls   5
#define MSIM_STATUS_ORDINAL_UNKNOWN     6
#define MSIM_STATUS_ORDINAL_UNKNOWN1    7
#define MSIM_STATUS_ORDINAL_UNKNOWNp    8
#define MSIM_STATUS_ORDINAL_UNKNOWN2    9

/* Status codes - states a buddy (or you!) can be in. */
#define MSIM_STATUS_CODE_OFFLINE_OR_HIDDEN    0
#define MSIM_STATUS_CODE_ONLINE               1
#define MSIM_STATUS_CODE_IDLE                 2
#define MSIM_STATUS_CODE_AWAY                 5

/* Inbox status bitfield values for MsimSession.inbox_status. */
#define MSIM_INBOX_MAIL                 (1 << 0)
#define MSIM_INBOX_BLOG_COMMENT         (1 << 1)
#define MSIM_INBOX_PROFILE_COMMENT      (1 << 2)
#define MSIM_INBOX_FRIEND_REQUEST       (1 << 3)
#define MSIM_INBOX_PICTURE_COMMENT      (1 << 4)

/* Codes for msim_got_contact_list(), to tell what to do afterwards. */
#define MSIM_CONTACT_LIST_INITIAL_FRIENDS	0
#define MSIM_CONTACT_LIST_IMPORT_ALL_FRIENDS	1
#define MSIM_CONTACT_LIST_IMPORT_TOP_FRIENDS	2

/* Error codes */
#define MSIM_ERROR_INCORRECT_PASSWORD           260
#define MSIM_ERROR_LOGGED_IN_ELSEWHERE          6

/* Functions */
gboolean msim_send_raw(MsimSession *session, const gchar *msg);

gboolean msim_send_bm(MsimSession *session, const gchar *who, const gchar *text, int type);

gboolean msim_we_are_logged_on(MsimSession *session);

void msim_unrecognized(MsimSession *session, MsimMessage *msg, gchar *note);
guint msim_new_reply_callback(MsimSession *session, MSIM_USER_LOOKUP_CB cb, gpointer data);

#endif /* !_MYSPACE_MYSPACE_H */
