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

#include "myspace.h"

/* Session methods */

/**
 * Create a new MSIM session.
 *
 * @param acct The account to create the session from.
 *
 * @return Pointer to a new session. Free with msim_session_destroy.
 */
MsimSession *
msim_session_new(PurpleAccount *acct)
{
	MsimSession *session;

	g_return_val_if_fail(acct != NULL, NULL);

	session = g_new0(MsimSession, 1);

	session->magic = MSIM_SESSION_STRUCT_MAGIC;
	session->account = acct;
	session->gc = purple_account_get_connection(acct);
	session->sesskey = 0;
	session->userid = 0;
	session->username = NULL;
	session->fd = -1;

	/* TODO: Remove. */
	session->user_lookup_cb = g_hash_table_new_full(g_direct_hash,
			g_direct_equal, NULL, NULL);  /* do NOT free function pointers! (values) */
	session->user_lookup_cb_data = g_hash_table_new_full(g_direct_hash,
			g_direct_equal, NULL, NULL);/* TODO: we don't know what the values are,
											 they could be integers inside gpointers
											 or strings, so I don't freed them.
											 Figure this out, once free cache. */

	/* Created in msim_process_server_info() */
	session->server_info = NULL;

	session->rxoff = 0;
	session->rxsize = MSIM_READ_BUF_SIZE;
	session->rxbuf = g_new0(gchar, session->rxsize);
	session->next_rid = 1;
	session->last_comm = time(NULL);
	session->inbox_status = 0;
	session->inbox_handle = 0;

	return session;
}

/**
 * Free a session.
 *
 * @param session The session to destroy.
 */
void
msim_session_destroy(MsimSession *session)
{
	session->magic = -1;

	g_free(session->rxbuf);
	g_free(session->username);

	/* TODO: Remove. */
	g_hash_table_destroy(session->user_lookup_cb);
	g_hash_table_destroy(session->user_lookup_cb_data);

	if (session->server_info) {
		msim_msg_free(session->server_info);
	}

	/* Stop checking the inbox at the end of the session. */
	if (session->inbox_handle) {
		purple_timeout_remove(session->inbox_handle);
	}

	g_free(session);
}
