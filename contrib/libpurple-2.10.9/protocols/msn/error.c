/**
 * @file error.c Error functions
 *
 * purple
 *
 * Purple is the legal property of its developers, whose names are too numerous
 * to list here.  Please refer to the COPYRIGHT file distributed with this
 * source distribution.
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
/* Masca: can we get rid of the sync issue dialog? */
#include "request.h"

#include "error.h"

typedef struct
{
	MsnSession *session;
	char *who;
	char *group;
	gboolean add;

} MsnAddRemData;

const char *
msn_error_get_text(unsigned int type, gboolean *debug)
{
	static char msg[256];
	const char *result;
	*debug = FALSE;

	switch (type) {
		case 0:
			result = _("Unable to parse message");
			*debug = TRUE;
			break;
		case 200:
			result = _("Syntax Error (probably a client bug)");
			*debug = TRUE;
			break;
		case 201:
			result = _("Invalid email address");
			break;
		case 205:
			result = _("User does not exist");
			break;
		case 206:
			result = _("Fully qualified domain name missing");
			break;
		case 207:
			result = _("Already logged in");
			break;
		case 208:
			result = _("Invalid username");
			break;
		case 209:
			result = _("Invalid friendly name");
			break;
		case 210:
			result = _("List full");
			break;
		case 215:
			result = _("Already there");
			*debug = TRUE;
			break;
		case 216:
			result = _("Not on list");
			break;
		case 217:
			result = _("User is offline");
			break;
		case 218:
			result = _("Already in the mode");
			*debug = TRUE;
			break;
		case 219:
			result = _("Already in opposite list");
			*debug = TRUE;
			break;
		case 223:
			result = _("Too many groups");
			break;
		case 224:
			result = _("Invalid group");
			break;
		case 225:
			result = _("User not in group");
			break;
		case 229:
			result = _("Group name too long");
			break;
		case 230:
			result = _("Cannot remove group zero");
			*debug = TRUE;
			break;
		case 231:
			result = _("Tried to add a user to a group that doesn't exist");
			break;
		case 280:
			result = _("Switchboard failed");
			*debug = TRUE;
			break;
		case 281:
			result = _("Notify transfer failed");
			*debug = TRUE;
			break;

		case 300:
			result = _("Required fields missing");
			*debug = TRUE;
			break;
		case 301:
			result = _("Too many hits to a FND");
			*debug = TRUE;
			break;
		case 302:
			result = _("Not logged in");
			break;

		case 500:
			result = _("Service temporarily unavailable");
			break;
		case 501:
			result = _("Database server error");
			*debug = TRUE;
			break;
		case 502:
			result = _("Command disabled");
			*debug = TRUE;
			break;
		case 510:
			result = _("File operation error");
			*debug = TRUE;
			break;
		case 520:
			result = _("Memory allocation error");
			*debug = TRUE;
			break;
		case 540:
			result = _("Wrong CHL value sent to server");
			*debug = TRUE;
			break;

		case 600:
			result = _("Server busy");
			break;
		case 601:
			result = _("Server unavailable");
			break;
		case 602:
			result = _("Peer notification server down");
			*debug = TRUE;
			break;
		case 603:
			result = _("Database connect error");
			*debug = TRUE;
			break;
		case 604:
			result = _("Server is going down (abandon ship)");
			break;
		case 605:
			result = _("Server unavailable");
			break;

		case 707:
			result = _("Error creating connection");
			*debug = TRUE;
			break;
		case 710:
			result = _("CVR parameters are either unknown or not allowed");
			*debug = TRUE;
			break;
		case 711:
			result = _("Unable to write");
			break;
		case 712:
			result = _("Session overload");
			*debug = TRUE;
			break;
		case 713:
			result = _("User is too active");
			break;
		case 714:
			result = _("Too many sessions");
			break;
		case 715:
			result = _("Passport not verified");
			break;
		case 717:
			result = _("Bad friend file");
			*debug = TRUE;
			break;
		case 731:
			result = _("Not expected");
			*debug = TRUE;
			break;

		case 800:
			result = _("Friendly name is changing too rapidly");
			break;

		case 910:
		case 912:
		case 918:
		case 919:
		case 921:
		case 922:
			result = _("Server too busy");
			break;
		case 911:
		case 917:
			result = _("Authentication failed");
			break;
		case 913:
			result = _("Not allowed when offline");
			break;
		case 914:
		case 915:
		case 916:
			result = _("Server unavailable");
			break;
		case 920:
			result = _("Not accepting new users");
			break;
		case 923:
			result = _("Kids Passport without parental consent");
			break;
		case 924:
			result = _("Passport account not yet verified");
			break;
		case 927:
			result = _("Passport account suspended");
			break;
		case 928:
			result = _("Bad ticket");
			*debug = TRUE;
			break;

		default:
			g_snprintf(msg, sizeof(msg),
			           _("Unknown Error Code %d"), type);
			*debug = TRUE;
			result = msg;
			break;
	}

	return result;
}

void
msn_error_handle(MsnSession *session, unsigned int type)
{
	char *buf;
	gboolean debug;

	buf = g_strdup_printf(_("MSN Error: %s\n"),
	                      msn_error_get_text(type, &debug));
	if (debug)
		purple_debug_warning("msn", "error %d: %s\n", type, buf);
	else
		purple_notify_error(session->account->gc, NULL, buf, NULL);
	g_free(buf);
}

/* Remove the buddy referenced by the MsnAddRemData before the serverside list
 * is changed.  If the buddy will be added, he'll be added back; if he will be
 * removed, he won't be. */
/* Actually with our MSNP14 code that isn't true yet, he won't be added back :(
 * */
static void
msn_complete_sync_issue(MsnAddRemData *data)
{
	PurpleBuddy *buddy;
	PurpleGroup *group = NULL;

	if (data->group != NULL)
		group = purple_find_group(data->group);

	if (group != NULL)
		buddy = purple_find_buddy_in_group(data->session->account, data->who, group);
	else
		buddy = purple_find_buddy(data->session->account, data->who);

	if (buddy != NULL)
		purple_blist_remove_buddy(buddy);
}


static void
msn_add_cb(MsnAddRemData *data)
{
#if 0
	/* this *should* be necessary !! */
	msn_complete_sync_issue(data);
#endif
	MsnUserList *userlist = data->session->userlist;

	msn_userlist_add_buddy(userlist, data->who, data->group);

	g_free(data->group);
	g_free(data->who);
	g_free(data);
}

static void
msn_rem_cb(MsnAddRemData *data)
{
	MsnUserList *userlist = data->session->userlist;
	msn_complete_sync_issue(data);


	if (data->group == NULL) {
		msn_userlist_rem_buddy_from_list(userlist, data->who, MSN_LIST_FL);
	} else {
		g_free(data->group);
	}

	g_free(data->who);
	g_free(data);
}

void
msn_error_sync_issue(MsnSession *session, const char *passport,
					const char *group_name)
{
	PurpleConnection *gc;
	PurpleAccount *account;
	MsnAddRemData *data;
	char *msg, *reason;

	account = session->account;
	gc = purple_account_get_connection(account);

	data          = g_new0(MsnAddRemData, 1);
	data->who     = g_strdup(passport);
	data->group   = g_strdup(group_name);
	data->session = session;

	msg = g_strdup_printf(_("Buddy list synchronization issue in %s (%s)"),
						  purple_account_get_username(account),
						  purple_account_get_protocol_name(account));

	if (group_name != NULL)
	{
		reason = g_strdup_printf(_("%s on the local list is "
								   "inside the group \"%s\" but not on "
								   "the server list. "
								   "Do you want this buddy to be added?"),
								 passport, group_name);
	}
	else
	{
		reason = g_strdup_printf(_("%s is on the local list but "
								   "not on the server list. "
								   "Do you want this buddy to be added?"),
								 passport);
	}

	purple_request_action(gc, NULL, msg, reason, PURPLE_DEFAULT_ACTION_NONE,
						account, data->who, NULL,
						data, 2,
						_("Yes"), G_CALLBACK(msn_add_cb),
						_("No"), G_CALLBACK(msn_rem_cb));

	g_free(reason);
	g_free(msg);
}

