/* MySpaceIM Protocol Plugin, session
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

#ifndef _MYSPACE_SESSION_H
#define _MYSPACE_SESSION_H

#include "account.h"

/* Random number in every MsimSession, to ensure it is valid. */
#define MSIM_SESSION_STRUCT_MAGIC       0xe4a6752b

/* Everything needed to keep track of a session (proto_data field in PurpleConnection) */
typedef struct _MsimSession
{
	guint magic;                        /**< MSIM_SESSION_STRUCT_MAGIC */
	PurpleAccount *account;
	PurpleConnection *gc;
	guint sesskey;                      /**< Session key from server */
	guint userid;                       /**< This user's numeric user ID */
	gchar *username;                    /**< This user's unique username */
	gboolean show_only_to_list;
	int privacy_mode;                   /**< This is a bitmask */
	int offline_message_mode;
	gint fd;                            /**< File descriptor to/from server */

	/* TODO: Remove. */
	GHashTable *user_lookup_cb;         /**< Username -> userid lookup callback */
	GHashTable *user_lookup_cb_data;    /**< Username -> userid lookup callback data */

	MsimMessage *server_info;           /**< Parameters from server */

	gchar *rxbuf;                       /**< Receive buffer */
	guint rxoff;                        /**< Receive buffer offset */
	guint rxsize;                       /**< Receive buffer size */
	guint next_rid;                     /**< Next request/response ID */
	time_t last_comm;                   /**< Time received last communication */
	guint inbox_status;                 /**< Bit field of inbox notifications */
	guint inbox_handle;                 /**< The handle for the mail check timer */
} MsimSession;

MsimSession *msim_session_new(PurpleAccount *acct);
void msim_session_destroy(MsimSession *session);

#endif /* !_MYSPACE_SESSION_H */
