/**
 * @file notification.c Notification server functions
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
#include "cipher.h"
#include "core.h"
#include "debug.h"

#include "notification.h"

#include "contact.h"
#include "error.h"
#include "msnutils.h"
#include "state.h"
#include "userlist.h"

static MsnTable *cbs_table;

/**************************************************************************
 * Main
 **************************************************************************/

static void
destroy_cb(MsnServConn *servconn)
{
	MsnNotification *notification;

	notification = servconn->cmdproc->data;
	g_return_if_fail(notification != NULL);

	msn_notification_destroy(notification);
}

MsnNotification *
msn_notification_new(MsnSession *session)
{
	MsnNotification *notification;
	MsnServConn *servconn;

	g_return_val_if_fail(session != NULL, NULL);

	notification = g_new0(MsnNotification, 1);

	notification->session = session;
	notification->servconn = servconn = msn_servconn_new(session, MSN_SERVCONN_NS);
	msn_servconn_set_destroy_cb(servconn, destroy_cb);

	notification->cmdproc = servconn->cmdproc;
	notification->cmdproc->data = notification;
	notification->cmdproc->cbs_table = cbs_table;

	return notification;
}

void
msn_notification_destroy(MsnNotification *notification)
{
	notification->cmdproc->data = NULL;

	msn_servconn_set_destroy_cb(notification->servconn, NULL);

	msn_servconn_destroy(notification->servconn);

	g_free(notification);
}

/**************************************************************************
 * Connect
 **************************************************************************/

static void
connect_cb(MsnServConn *servconn)
{
	MsnCmdProc *cmdproc;
	MsnSession *session;
	MsnTransaction *trans;
	GString *vers;
	const char *ver_str;
	int i;

	g_return_if_fail(servconn != NULL);

	cmdproc = servconn->cmdproc;
	session = servconn->session;

	vers = g_string_new("");

	for (i = WLM_MAX_PROTOCOL; i >= WLM_MIN_PROTOCOL; i--)
		g_string_append_printf(vers, " MSNP%d", i);

	g_string_append(vers, " CVR0");

	if (session->login_step == MSN_LOGIN_STEP_START)
		msn_session_set_login_step(session, MSN_LOGIN_STEP_HANDSHAKE);
	else
		msn_session_set_login_step(session, MSN_LOGIN_STEP_HANDSHAKE2);

	/* Skip the initial space */
	ver_str = (vers->str + 1);
	trans = msn_transaction_new(cmdproc, "VER", "%s", ver_str);
	msn_cmdproc_send_trans(cmdproc, trans);

	g_string_free(vers, TRUE);
}

gboolean
msn_notification_connect(MsnNotification *notification, const char *host, int port)
{
	MsnServConn *servconn;

	g_return_val_if_fail(notification != NULL, FALSE);

	servconn = notification->servconn;

	msn_servconn_set_connect_cb(servconn, connect_cb);
	notification->in_use = msn_servconn_connect(servconn, host, port, TRUE);

	return notification->in_use;
}

void
msn_notification_disconnect(MsnNotification *notification)
{
	g_return_if_fail(notification != NULL);
	g_return_if_fail(notification->in_use);

	msn_servconn_disconnect(notification->servconn);

	notification->in_use = FALSE;
}

/**************************************************************************
 * Login
 **************************************************************************/

void
msn_got_login_params(MsnSession *session, const char *ticket, const char *response)
{
	MsnCmdProc *cmdproc;
	MsnTransaction *trans;

	cmdproc = session->notification->cmdproc;

	msn_session_set_login_step(session, MSN_LOGIN_STEP_AUTH_END);

	trans = msn_transaction_new(cmdproc, "USR", "SSO S %s %s %s", ticket, response, session->guid);

	msn_cmdproc_send_trans(cmdproc, trans);
}

static void
cvr_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
	PurpleAccount *account;
	MsnTransaction *trans;

	account = cmdproc->session->account;

	trans = msn_transaction_new(cmdproc, "USR", "SSO I %s", purple_account_get_username(account));
	msn_cmdproc_send_trans(cmdproc, trans);
}

static void
usr_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
	MsnSession *session = cmdproc->session;

	if (!g_ascii_strcasecmp(cmd->params[1], "OK"))
	{
		/* authenticate OK */
		msn_session_set_login_step(session, MSN_LOGIN_STEP_SYN);
	}
	else if (!g_ascii_strcasecmp(cmd->params[1], "SSO"))
	{
		/* RPS authentication */

		if (session->nexus)
			msn_nexus_destroy(session->nexus);

		session->nexus = msn_nexus_new(session);

		session->nexus->policy = g_strdup(cmd->params[3]);
		session->nexus->nonce = g_strdup(cmd->params[4]);

		msn_session_set_login_step(session, MSN_LOGIN_STEP_AUTH_START);

		msn_nexus_connect(session->nexus);
	}
}

static void
usr_error(MsnCmdProc *cmdproc, MsnTransaction *trans, int error)
{
	MsnErrorType msnerr = 0;

	switch (error)
	{
		case 500:
		case 601:
		case 910:
		case 921:
			msnerr = MSN_ERROR_SERV_UNAVAILABLE;
			break;
		case 911:
			msnerr = MSN_ERROR_AUTH;
			break;
		default:
			return;
			break;
	}

	msn_session_set_error(cmdproc->session, msnerr, NULL);
}

static void
ver_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
	MsnSession *session;
	MsnTransaction *trans;
	PurpleAccount *account;
	gboolean protocol_supported = FALSE;
	int proto_ver;
	size_t i;

	session = cmdproc->session;
	account = session->account;

	session->protocol_ver = 0;
	for (i = 1; i < cmd->param_count; i++)
	{
		if (sscanf(cmd->params[i], "MSNP%d", &proto_ver) == 1) {
			if (proto_ver >= WLM_MIN_PROTOCOL
			 && proto_ver <= WLM_MAX_PROTOCOL
			 && proto_ver > session->protocol_ver) {
				protocol_supported = TRUE;
				session->protocol_ver = proto_ver;
			}
		}
	}

	if (!protocol_supported)
	{
		msn_session_set_error(session, MSN_ERROR_UNSUPPORTED_PROTOCOL,
							  NULL);
		return;
	}

	purple_debug_info("msn", "Negotiated protocol version %d with the server.\n", session->protocol_ver);

	/*
	 * Windows Live Messenger 8.5
	 * Notice :CVR String discriminate!
	 * reference of http://www.microsoft.com/globaldev/reference/oslocversion.mspx
	 * to see the Local ID
	 */
	trans = msn_transaction_new(cmdproc, "CVR",
					"0x0409 winnt 5.1 i386 MSNMSGR 8.5.1302 BC01 %s",
					 purple_account_get_username(account));
	msn_cmdproc_send_trans(cmdproc, trans);
}

/**************************************************************************
 * Log out
 **************************************************************************/

static void
out_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
	if (cmd->param_count == 0)
		msn_session_set_error(cmdproc->session, -1, NULL);
	else if (!g_ascii_strcasecmp(cmd->params[0], "OTH"))
		msn_session_set_error(cmdproc->session, MSN_ERROR_SIGN_OTHER,
							  NULL);
	else if (!g_ascii_strcasecmp(cmd->params[0], "SSD"))
		msn_session_set_error(cmdproc->session, MSN_ERROR_SERV_DOWN, NULL);
}

void
msn_notification_close(MsnNotification *notification)
{
	MsnTransaction *trans;

	g_return_if_fail(notification != NULL);

	if (!notification->in_use)
		return;

	trans = msn_transaction_new(notification->cmdproc, "OUT", NULL);
	msn_transaction_set_saveable(trans, FALSE);
	msn_cmdproc_send_trans(notification->cmdproc, trans);

	msn_notification_disconnect(notification);
}

/**************************************************************************
 * Messages
 **************************************************************************/

static void
msg_cmd_post(MsnCmdProc *cmdproc, MsnCommand *cmd, char *payload,
			 size_t len)
{
	MsnMessage *msg;

	msg = msn_message_new_from_cmd(cmdproc->session, cmd);

	msn_message_parse_payload(msg, payload, len, MSG_LINE_DEM, MSG_BODY_DEM);
	if (purple_debug_is_verbose())
		msn_message_show_readable(msg, "Notification", TRUE);

	msn_cmdproc_process_msg(cmdproc, msg);

	msn_message_unref(msg);
}

static void
msg_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
	purple_debug_info("msn", "Processing MSG... \n");

	/* NOTE: cmd is not always cmdproc->last_cmd, sometimes cmd is a queued
	 * command and we are processing it */
	if (cmd->payload == NULL) {
		cmdproc->last_cmd->payload_cb = msg_cmd_post;
		cmd->payload_len = atoi(cmd->params[2]);
	} else {
		g_return_if_fail(cmd->payload_cb != NULL);

#if 0 /* glib on win32 doesn't correctly support precision modifiers for a string */
		purple_debug_info("msn", "MSG payload:{%.*s}\n", (guint)cmd->payload_len, cmd->payload);
#endif
		cmd->payload_cb(cmdproc, cmd, cmd->payload, cmd->payload_len);
	}
}

/*send Message to Yahoo Messenger*/
void
msn_notification_send_uum(MsnSession *session, MsnMessage *msg)
{
	MsnCmdProc *cmdproc;
	MsnTransaction *trans;
	char *payload;
	gsize payload_len;
	int type;
	MsnUser *user;
	int network;

	g_return_if_fail(msg != NULL);

	cmdproc = session->notification->cmdproc;

	payload = msn_message_gen_payload(msg, &payload_len);
	type = msg->type;
	user = msn_userlist_find_user(session->userlist, msg->remote_user);
	if (user)
		network = msn_user_get_network(user);
	else
		network = MSN_NETWORK_PASSPORT;

	purple_debug_info("msn",
		"send UUM, payload{%s}, strlen:%" G_GSIZE_FORMAT ", len:%" G_GSIZE_FORMAT "\n",
		payload, strlen(payload), payload_len);

	trans = msn_transaction_new(cmdproc, "UUM", "%s %d %d %" G_GSIZE_FORMAT,
		msg->remote_user, network, type, payload_len);
	msn_transaction_set_payload(trans, payload, strlen(payload));
	msn_cmdproc_send_trans(cmdproc, trans);
}

/*Yahoo msg process*/
static void
ubm_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
	purple_debug_info("msn", "Processing UBM... \n");

	/* NOTE: cmd is not always cmdproc->last_cmd, sometimes cmd is a queued
	 * command and we are processing it */
	if (cmd->payload == NULL) {
		cmdproc->last_cmd->payload_cb = msg_cmd_post;
		cmd->payload_len = atoi(cmd->params[5]);
	} else {
		g_return_if_fail(cmd->payload_cb != NULL);

		purple_debug_info("msn", "UBM payload:{%.*s}\n", (guint)(cmd->payload_len), cmd->payload);
		msg_cmd_post(cmdproc, cmd, cmd->payload, cmd->payload_len);
	}
}

/**************************************************************************
 * Challenges
 *  we use MD5 to caculate the Challenges
 **************************************************************************/
static void
chl_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
	MsnTransaction *trans;
	char buf[33];

	msn_handle_chl(cmd->params[1], buf);
	trans = msn_transaction_new(cmdproc, "QRY", "%s 32", MSNP15_WLM_PRODUCT_ID);

	msn_transaction_set_payload(trans, buf, 32);

	msn_cmdproc_send_trans(cmdproc, trans);
}

/**************************************************************************
 * Buddy Lists
 **************************************************************************/

typedef struct MsnFqyCbData {
	MsnFqyCb cb;
	gpointer data;
} MsnFqyCbData;

/* add contact to xmlnode */
static void
msn_add_contact_xml(xmlnode *mlNode, const char *passport, MsnListOp list_op, MsnNetwork networkId)
{
	xmlnode *d_node,*c_node;
	char **tokens;
	const char *email,*domain;
	char fmt_str[3];

	g_return_if_fail(passport != NULL);

	purple_debug_info("msn", "Passport: %s, type: %d\n", passport, networkId);
	tokens = g_strsplit(passport, "@", 2);
	email = tokens[0];
	domain = tokens[1];

	if (email == NULL || domain == NULL) {
		purple_debug_error("msn", "Invalid passport (%s) specified to add to contact xml.\n", passport);
		g_strfreev(tokens);
		g_return_if_reached();
	}

	/*find a domain Node*/
	for (d_node = xmlnode_get_child(mlNode, "d"); d_node;
	     d_node = xmlnode_get_next_twin(d_node)) {
		const char *attr = xmlnode_get_attrib(d_node,"n");
		if (attr == NULL)
			continue;
		if (!strcmp(attr, domain))
			break;
	}

	if (d_node == NULL) {
		/*domain not found, create a new domain Node*/
		purple_debug_info("msn", "Didn't find existing domain node, adding one.\n");
		d_node = xmlnode_new("d");
		xmlnode_set_attrib(d_node, "n", domain);
		xmlnode_insert_child(mlNode, d_node);
	}

	/*create contact node*/
	c_node = xmlnode_new("c");
	xmlnode_set_attrib(c_node, "n", email);

	if (list_op != 0) {
		purple_debug_info("msn", "list_op: %d\n", list_op);
		g_snprintf(fmt_str, sizeof(fmt_str), "%d", list_op);
		xmlnode_set_attrib(c_node, "l", fmt_str);
	}

	if (networkId != MSN_NETWORK_UNKNOWN) {
		g_snprintf(fmt_str, sizeof(fmt_str), "%d", networkId);
		/*mobile*/
		/*type_str = g_strdup_printf("4");*/
		xmlnode_set_attrib(c_node, "t", fmt_str);
	}

	xmlnode_insert_child(d_node, c_node);

	g_strfreev(tokens);
}

static void
msn_notification_post_adl(MsnCmdProc *cmdproc, const char *payload, int payload_len)
{
	MsnTransaction *trans;
	purple_debug_info("msn", "Sending ADL with payload: %s\n", payload);
	trans = msn_transaction_new(cmdproc, "ADL", "%i", payload_len);
	msn_transaction_set_payload(trans, payload, payload_len);
	msn_cmdproc_send_trans(cmdproc, trans);
}

static void
msn_notification_post_rml(MsnCmdProc *cmdproc, const char *payload, int payload_len)
{
	MsnTransaction *trans;
	purple_debug_info("msn", "Sending RML with payload: %s\n", payload);
	trans = msn_transaction_new(cmdproc, "RML", "%i", payload_len);
	msn_transaction_set_payload(trans, payload, payload_len);
	msn_cmdproc_send_trans(cmdproc, trans);
}

void
msn_notification_send_fqy(MsnSession *session,
                          const char *payload, int payload_len,
                          MsnFqyCb cb,
                          gpointer cb_data)
{
	MsnTransaction *trans;
	MsnCmdProc *cmdproc;
	MsnFqyCbData *data;

	cmdproc = session->notification->cmdproc;

	data = g_new(MsnFqyCbData, 1);
	data->cb = cb;
	data->data = cb_data;

	trans = msn_transaction_new(cmdproc, "FQY", "%d", payload_len);
	msn_transaction_set_payload(trans, payload, payload_len);
	msn_transaction_set_data(trans, data);
	msn_transaction_set_data_free(trans, g_free);
	msn_cmdproc_send_trans(cmdproc, trans);
}

static void
update_contact_network(MsnSession *session, const char *passport, MsnNetwork network, gpointer unused)
{
	MsnUser *user;

	if (network == MSN_NETWORK_UNKNOWN)
	{
		purple_debug_warning("msn",
		                     "Ignoring user %s about which server knows nothing.\n",
		                     passport);
		/* Decrement the count for unknown results so that we'll continue login.
		   Also, need to finish the login process here as well, because ADL OK
		   will not be called. */
		if (purple_debug_is_verbose())
			purple_debug_info("msn", "ADL/FQY count is %d\n", session->adl_fqy);
		if (--session->adl_fqy == 0)
			msn_session_finish_login(session);
		return;
	}

	/* TODO: Also figure out how to update membership lists */
	user = msn_userlist_find_user(session->userlist, passport);
	if (user) {
		xmlnode *adl_node;
		char *payload;
		int payload_len;

		msn_user_set_network(user, network);

		adl_node = xmlnode_new("ml");
		xmlnode_set_attrib(adl_node, "l", "1");
		msn_add_contact_xml(adl_node, passport,
		                    user->list_op & MSN_LIST_OP_MASK, network);
		payload = xmlnode_to_str(adl_node, &payload_len);
		msn_notification_post_adl(session->notification->cmdproc, payload, payload_len);
		g_free(payload);
		xmlnode_free(adl_node);
	} else {
		purple_debug_error("msn",
		                   "Got FQY update for unknown user %s on network %d.\n",
		                   passport, network);
	}
}

/*dump contact info to NS*/
void
msn_notification_dump_contact(MsnSession *session)
{
	MsnUser *user;
	GList *l;
	xmlnode *adl_node;
	xmlnode *fqy_node;
	char *payload;
	int payload_len;
	int adl_count = 0;
	int fqy_count = 0;
	PurpleConnection *pc;
	const char *display_name;

	adl_node = xmlnode_new("ml");
	adl_node->child = NULL;
	xmlnode_set_attrib(adl_node, "l", "1");
	fqy_node = xmlnode_new("ml");

	/*get the userlist*/
	for (l = session->userlist->users; l != NULL; l = l->next) {
		user = l->data;

		/* skip RL & PL during initial dump */
		if (!(user->list_op & MSN_LIST_OP_MASK))
			continue;

		if (user->passport && !strcmp(user->passport, "messenger@microsoft.com"))
			continue;

		if ((user->list_op & MSN_LIST_OP_MASK & ~MSN_LIST_FL_OP)
		 == (MSN_LIST_AL_OP | MSN_LIST_BL_OP)) {
			/* The server will complain if we send it a user on both the
			   Allow and Block lists. So assume they're on the Block list
			   and remove them from the Allow list in the membership lists to
			   stop this from happening again. */
			purple_debug_warning("msn",
			                     "User %s is on both Allow and Block list; "
			                     "removing from Allow list.\n",
			                     user->passport);
			msn_user_unset_op(user, MSN_LIST_AL_OP);
		}

		if (user->networkid != MSN_NETWORK_UNKNOWN) {
			msn_add_contact_xml(adl_node, user->passport,
			                    user->list_op & MSN_LIST_OP_MASK,
			                    user->networkid);

			/* each ADL command may contain up to 150 contacts */
			if (++adl_count % 150 == 0) {
				payload = xmlnode_to_str(adl_node, &payload_len);

				/* ADL's are returned all-together */
				session->adl_fqy++;
				if (purple_debug_is_verbose())
					purple_debug_info("msn", "Posting ADL, count is %d\n",
					                  session->adl_fqy);

				msn_notification_post_adl(session->notification->cmdproc,
					payload, payload_len);

				g_free(payload);
				xmlnode_free(adl_node);

				adl_node = xmlnode_new("ml");
				adl_node->child = NULL;
				xmlnode_set_attrib(adl_node, "l", "1");
			}
		} else {
			/* FQY's are returned one-at-a-time */
			session->adl_fqy++;
			if (purple_debug_is_verbose())
				purple_debug_info("msn", "Adding FQY address, count is %d\n",
				                  session->adl_fqy);

			msn_add_contact_xml(fqy_node, user->passport, 0, user->networkid);

			/* each FQY command may contain up to 150 contacts, probably */
			if (++fqy_count % 150 == 0) {
				payload = xmlnode_to_str(fqy_node, &payload_len);

				msn_notification_send_fqy(session, payload, payload_len,
				                          update_contact_network, NULL);

				g_free(payload);
				xmlnode_free(fqy_node);
				fqy_node = xmlnode_new("ml");
			}
		}
	}

	/* Send the rest, or just an empty one to let the server set us online */
	if (adl_count == 0 || adl_count % 150 != 0) {
		payload = xmlnode_to_str(adl_node, &payload_len);

		/* ADL's are returned all-together */
		session->adl_fqy++;
		if (purple_debug_is_verbose())
			purple_debug_info("msn", "Posting ADL, count is %d\n",
			                  session->adl_fqy);

		msn_notification_post_adl(session->notification->cmdproc, payload, payload_len);

		g_free(payload);
	}

	if (fqy_count % 150 != 0) {
		payload = xmlnode_to_str(fqy_node, &payload_len);

		msn_notification_send_fqy(session, payload, payload_len,
		                          update_contact_network, NULL);

		g_free(payload);
	}

	xmlnode_free(adl_node);
	xmlnode_free(fqy_node);

	msn_session_activate_login_timeout(session);

	pc = purple_account_get_connection(session->account);
	display_name = purple_connection_get_display_name(pc);
	if (display_name
	    && strcmp(display_name,
		      purple_account_get_username(session->account))) {
		msn_set_public_alias(pc, display_name, NULL, NULL);
	}

}

static void
blp_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
}

static void
adl_cmd_parse(MsnCmdProc *cmdproc, MsnCommand *cmd, char *payload,
		                         size_t len)
{
	xmlnode *root, *domain_node;

	purple_debug_misc("msn", "Parsing received ADL XML data\n");

	g_return_if_fail(payload != NULL);

	root = xmlnode_from_str(payload, (gssize) len);

	if (root == NULL) {
		purple_debug_info("msn", "Invalid XML in ADL!\n");
		return;
	}
	for (domain_node = xmlnode_get_child(root, "d");
	     domain_node;
	     domain_node = xmlnode_get_next_twin(domain_node)) {
		xmlnode *contact_node = NULL;

		for (contact_node = xmlnode_get_child(domain_node, "c");
		     contact_node;
		     contact_node = xmlnode_get_next_twin(contact_node)) {
			const gchar *list;
			gint list_op = 0;

			list = xmlnode_get_attrib(contact_node, "l");
			if (list != NULL) {
				list_op = atoi(list);
			}

			if (list_op & MSN_LIST_RL_OP) {
				/* someone is adding us */
				msn_get_contact_list(cmdproc->session, MSN_PS_PENDING_LIST, NULL);
			}
		}
	}

	xmlnode_free(root);
}

static void
adl_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
	MsnSession *session;

	g_return_if_fail(cmdproc != NULL);
	g_return_if_fail(cmdproc->session != NULL);
	g_return_if_fail(cmdproc->last_cmd != NULL);
	g_return_if_fail(cmd != NULL);

	session = cmdproc->session;

	if (!strcmp(cmd->params[1], "OK")) {
		/* ADL ack */
		if (purple_debug_is_verbose())
			purple_debug_info("msn", "ADL ACK, count is %d\n",
			                  session->adl_fqy);
		if (--session->adl_fqy == 0)
			msn_session_finish_login(session);
	} else {
		cmdproc->last_cmd->payload_cb = adl_cmd_parse;
		cmd->payload_len = atoi(cmd->params[1]);
	}

	return;
}

static void
adl_error_parse(MsnCmdProc *cmdproc, MsnCommand *cmd, char *payload, size_t len)
{
	MsnSession *session;
	PurpleAccount *account;
	PurpleConnection *gc;
	int error = GPOINTER_TO_INT(cmd->payload_cbdata);

	session = cmdproc->session;
	account = session->account;
	gc = purple_account_get_connection(account);

	if (error == 241) {
		/* khc: some googling suggests that error 241 means the buddy is somehow
		   in the local list, but not the server list, and that we should add
		   those buddies to the addressbook. For now I will just notify the user
		   about the raw payload, because I am lazy */
		xmlnode *adl = xmlnode_from_str(payload, len);
		GString *emails = g_string_new(NULL);

		xmlnode *domain = xmlnode_get_child(adl, "d");
		while (domain) {
			const char *domain_str = xmlnode_get_attrib(domain, "n");
			xmlnode *contact = xmlnode_get_child(domain, "c");
			while (contact) {
				g_string_append_printf(emails, "%s@%s\n",
					xmlnode_get_attrib(contact, "n"), domain_str);
				contact = xmlnode_get_next_twin(contact);
			}
			domain = xmlnode_get_next_twin(domain);
		}

		purple_notify_error(gc, NULL,
			_("The following users are missing from your addressbook"),
			emails->str);
		g_string_free(emails, TRUE);
		xmlnode_free(adl);
	}
	else
	{
		char *adl = g_strndup(payload, len);
		char *reason = g_strdup_printf(_("Unknown error (%d): %s"),
			error, adl);
		g_free(adl);

		purple_notify_error(gc, NULL, _("Unable to add user"), reason);
		g_free(reason);
	}
}

static void
adl_error(MsnCmdProc *cmdproc, MsnTransaction *trans, int error)
{
	MsnSession *session;
	PurpleAccount *account;
	PurpleConnection *gc;
	MsnCommand *cmd = cmdproc->last_cmd;

	session = cmdproc->session;
	account = session->account;
	gc = purple_account_get_connection(account);

	purple_debug_error("msn", "ADL error\n");
	if (cmd->param_count > 1) {
		cmd->payload_cb = adl_error_parse;
		cmd->payload_len = atoi(cmd->params[1]);
		cmd->payload_cbdata = GINT_TO_POINTER(error);
	} else {
		char *reason = g_strdup_printf(_("Unknown error (%d)"), error);
		purple_notify_error(gc, NULL, _("Unable to add user"), reason);
		g_free(reason);
	}
}

static void
rml_error_parse(MsnCmdProc *cmdproc, MsnCommand *cmd, char *payload, size_t len)
{
	MsnSession *session;
	PurpleAccount *account;
	PurpleConnection *gc;
	char *adl, *reason;
	int error = GPOINTER_TO_INT(cmd->payload_cbdata);

	session = cmdproc->session;
	account = session->account;
	gc = purple_account_get_connection(account);

	adl = g_strndup(payload, len);
	reason = g_strdup_printf(_("Unknown error (%d): %s"),
		error, adl);
	g_free(adl);

	purple_notify_error(gc, NULL, _("Unable to remove user"), reason);
	g_free(reason);
}

static void
rml_error(MsnCmdProc *cmdproc, MsnTransaction *trans, int error)
{
	MsnSession *session;
	PurpleAccount *account;
	PurpleConnection *gc;
	MsnCommand *cmd = cmdproc->last_cmd;

	session = cmdproc->session;
	account = session->account;
	gc = purple_account_get_connection(account);

	purple_debug_error("msn", "RML error\n");
	if (cmd->param_count > 1) {
		cmd->payload_cb = rml_error_parse;
		cmd->payload_len = atoi(cmd->params[1]);
		cmd->payload_cbdata = GINT_TO_POINTER(error);
	} else {
		char *reason = g_strdup_printf(_("Unknown error (%d)"), error);
		purple_notify_error(gc, NULL, _("Unable to remove user"), reason);
		g_free(reason);
	}
}

static void
fqy_cmd_post(MsnCmdProc *cmdproc, MsnCommand *cmd, char *payload,
			 size_t len)
{
	MsnSession *session;
	xmlnode *ml, *d, *c;
	const char *domain;
	const char *local;
	const char *type;
	char *passport;
	MsnNetwork network = MSN_NETWORK_PASSPORT;

	session = cmdproc->session;

	/* FQY response:
	    <ml><d n="domain.com"><c n="local-node" t="network" /></d></ml> */
	ml = xmlnode_from_str(payload, len);
	for (d = xmlnode_get_child(ml, "d");
	     d != NULL;
	     d = xmlnode_get_next_twin(d)) {
		domain = xmlnode_get_attrib(d, "n");
		for (c = xmlnode_get_child(d, "c");
		     c != NULL;
		     c = xmlnode_get_next_twin(c)) {
			local = xmlnode_get_attrib(c, "n");
			type = xmlnode_get_attrib(c, "t");

			passport = g_strdup_printf("%s@%s", local, domain);

			if (g_ascii_isdigit(cmd->command[0]))
				network = MSN_NETWORK_UNKNOWN;
			else if (type != NULL)
				network = (MsnNetwork)strtoul(type, NULL, 10);

			purple_debug_info("msn", "FQY response says %s is from network %d\n",
			                  passport, network);
			if (cmd->trans->data) {
				MsnFqyCbData *fqy_data = cmd->trans->data;
				fqy_data->cb(session, passport, network, fqy_data->data);
				/* Don't free fqy_data yet since the server responds to FQY multiple times.
				   It will be freed when cmd->trans is freed. */
			}

			g_free(passport);
		}
	}

	xmlnode_free(ml);
}

static void
fqy_error(MsnCmdProc *cmdproc, MsnTransaction *trans, int error)
{
	MsnCommand *cmd = cmdproc->last_cmd;

	purple_debug_warning("msn", "FQY error %d\n", error);
	if (cmd->param_count > 1) {
		cmd->payload_cb = fqy_cmd_post;
		cmd->payload_len = atoi(cmd->params[1]);
		cmd->payload_cbdata = GINT_TO_POINTER(error);
	}
#if 0
	/* If the server didn't send us a corresponding email address for this
	   FQY error, it's probably going to disconnect us. So it isn't necessary
	   to tell the handler about it. */
	else if (trans->data)
		((MsnFqyCb)trans->data)(session, NULL, MSN_NETWORK_UNKNOWN, NULL);
#endif
}

static void
fqy_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
	purple_debug_info("msn", "Process FQY\n");
	cmdproc->last_cmd->payload_cb = fqy_cmd_post;
	cmd->payload_len = atoi(cmd->params[1]);
}

static void
rml_cmd_post(MsnCmdProc *cmdproc, MsnCommand *cmd, char *payload,
			 size_t len)
{
	if (payload != NULL)
		purple_debug_info("msn", "Received RML:\n%s\n", payload);
}

static void
rml_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
	purple_debug_info("msn", "Process RML\n");
	cmd->payload_len = atoi(cmd->params[1]);
	cmdproc->last_cmd->payload_cb = rml_cmd_post;
}

static void
qng_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
	/* TODO: Call PNG after the timeout specified. */
}


static void
fln_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
	MsnUser *user;
	char *passport;
	int networkid;

	/* Tell libpurple that the user has signed off */
	msn_parse_user(cmd->params[0], &passport, &networkid);
	user = msn_userlist_find_user(cmdproc->session->userlist, passport);
	msn_user_set_state(user, NULL);
	msn_user_update(user);

	g_free(passport);
}

static void
iln_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
	MsnSession *session;
	MsnUser *user;
	MsnObject *msnobj = NULL;
	unsigned long clientid, extcaps;
	char *extcap_str;
	int networkid = 0;
	const char *state, *passport;
	char *friendly;

	session = cmdproc->session;

	state    = cmd->params[1];
	passport = cmd->params[2];

	user = msn_userlist_find_user(session->userlist, passport);
	if (user == NULL)
		/* Where'd this come from? */
		return;

	if (cmd->param_count == 8) {
		/* Yahoo! Buddy, looks like */
		networkid = atoi(cmd->params[3]);
		friendly = g_strdup(purple_url_decode(cmd->params[4]));
		clientid = strtoul(cmd->params[5], &extcap_str, 10);
		if (extcap_str && *extcap_str)
			extcaps = strtoul(extcap_str+1, NULL, 10);
		else
			extcaps = 0;

		/* cmd->params[7] seems to be a URL to a Yahoo! icon:
				https://sec.yimg.com/i/us/nt/b/purpley.1.0.png
		   ... and it's purple, HAH!
		*/
	} else if (cmd->param_count == 7) {
		/* MSNP14+ with Display Picture object */
		networkid = atoi(cmd->params[3]);
		friendly = g_strdup(purple_url_decode(cmd->params[4]));
		clientid = strtoul(cmd->params[5], &extcap_str, 10);
		if (extcap_str && *extcap_str)
			extcaps = strtoul(extcap_str+1, NULL, 10);
		else
			extcaps = 0;
		msnobj = msn_object_new_from_string(purple_url_decode(cmd->params[6]));
	} else if (cmd->param_count == 6) {
		/* Yes, this is 5. The friendly name could start with a number,
		   but the display picture object can't... */
		if (isdigit(cmd->params[5][0])) {
			/* MSNP14 without Display Picture object */
			networkid = atoi(cmd->params[3]);
			friendly = g_strdup(purple_url_decode(cmd->params[4]));
			clientid = strtoul(cmd->params[5], &extcap_str, 10);
			if (extcap_str && *extcap_str)
				extcaps = strtoul(extcap_str+1, NULL, 10);
			else
				extcaps = 0;
		} else {
			/* MSNP8+ with Display Picture object */
			friendly = g_strdup(purple_url_decode(cmd->params[3]));
			clientid = strtoul(cmd->params[4], &extcap_str, 10);
			if (extcap_str && *extcap_str)
				extcaps = strtoul(extcap_str+1, NULL, 10);
			else
				extcaps = 0;
			msnobj = msn_object_new_from_string(purple_url_decode(cmd->params[5]));
		}
	} else if (cmd->param_count == 5) {
		/* MSNP8+ without Display Picture object */
		friendly = g_strdup(purple_url_decode(cmd->params[3]));
		clientid = strtoul(cmd->params[4], &extcap_str, 10);
		if (extcap_str && *extcap_str)
			extcaps = strtoul(extcap_str+1, NULL, 10);
		else
			extcaps = 0;
	} else {
		purple_debug_warning("msn", "Received ILN with unknown number of parameters.\n");
		return;
	}

	if (msn_user_set_friendly_name(user, friendly)) {
		msn_update_contact(session, passport, MSN_UPDATE_DISPLAY, friendly);
	}
	g_free(friendly);

	msn_user_set_object(user, msnobj);

	user->mobile = (clientid & MSN_CAP_MOBILE_ON) || (user->extinfo && user->extinfo->phone_mobile && user->extinfo->phone_mobile[0] == '+');
	msn_user_set_clientid(user, clientid);
	msn_user_set_extcaps(user, extcaps);
	msn_user_set_network(user, networkid);

	msn_user_set_state(user, state);
	msn_user_update(user);
}

static void
ipg_cmd_post(MsnCmdProc *cmdproc, MsnCommand *cmd, char *payload, size_t len)
{
	PurpleConnection *gc;
	MsnUserList *userlist;
	const char *who = NULL;
	char *text = NULL;
	const char *id = NULL;
	xmlnode *payloadNode, *from, *msg, *textNode;

	purple_debug_misc("msn", "Incoming Page: {%s}\n", payload);

	userlist = cmdproc->session->userlist;
	gc = purple_account_get_connection(cmdproc->session->account);

	/* payload looks like this:
	   <?xml version="1.0"?>
	   <NOTIFICATION id="0" siteid="111100400" siteurl="http://mobile.msn.com/">
	     <TO name="passport@example.com">
	       <VIA agent="mobile"/>
	     </TO>
	     <FROM name="tel:+XXXXXXXXXXX"/>
		 <MSG pri="1" id="1">
		   <CAT Id="110110001"/>
		   <ACTION url="2wayIM.asp"/>
		   <SUBSCR url="2wayIM.asp"/>
		   <BODY lcid="1033">
		     <TEXT>Message was here</TEXT>
		   </BODY>
		 </MSG>
	   </NOTIFICATION>
	*/

	/* This is the payload if your message was too long:
	   <NOTIFICATION id="TrID" siteid="111100400" siteurl="http://mobile.msn.com/">
	     <TO name="passport@example.com">
	       <VIA agent="mobile"/>
	     </TO>
	     <FROM name="tel:+XXXXXXXXXXX"/>
	     <MSG pri="1" id="407">
	       <CAT Id="110110001"/>
	       <ACTION url="2wayIM.asp"/>
	       <SUBSCR url="2wayIM.asp"/>
	       <BODY lcid="1033">
	         <TEXT></TEXT>
	       </BODY>
	     </MSG>
	   </NOTIFICATION>
	*/

	payloadNode = xmlnode_from_str(payload, len);
	if (!payloadNode)
		return;

	if (!(from = xmlnode_get_child(payloadNode, "FROM")) ||
		!(msg = xmlnode_get_child(payloadNode, "MSG")) ||
		!(textNode = xmlnode_get_child(msg, "BODY/TEXT"))) {
		xmlnode_free(payloadNode);
		return;
	}

	who = xmlnode_get_attrib(from, "name");
	if (!who) return;

	text = xmlnode_get_data(textNode);

	/* Match number to user's mobile number, FROM is a phone number if the
	   other side page you using your phone number */
	if (!strncmp(who, "tel:+", 5)) {
		MsnUser *user =
			msn_userlist_find_user_with_mobile_phone(userlist, who + 4);

		if (user && user->passport)
			who = user->passport;
	}

	id = xmlnode_get_attrib(msg, "id");

	if (id && strcmp(id, "1")) {
		PurpleConversation *conv
			= purple_find_conversation_with_account(PURPLE_CONV_TYPE_ANY,
			                                        who, gc->account);
		if (conv != NULL) {
			const char *error;
			if (!strcmp(id, "407"))
				error = _("Mobile message was not sent because it was too long.");
			else
				error = _("Mobile message was not sent because an unknown error occurred.");

			purple_conversation_write(conv, NULL, error,
			                          PURPLE_MESSAGE_ERROR, time(NULL));

			if ((id = xmlnode_get_attrib(payloadNode, "id")) != NULL) {
				unsigned int trId = atol(id);
				MsnTransaction *trans;

				trans = msn_history_find(cmdproc->history, trId);
				if (trans) {
					MsnMessage *msg = (MsnMessage *)trans->data;

					if (msg) {
						char *body_str = msn_message_to_string(msg);
						char *body_enc = g_markup_escape_text(body_str, -1);

						purple_conversation_write(conv, NULL, body_enc,
					                          	PURPLE_MESSAGE_RAW, time(NULL));

						g_free(body_str);
						g_free(body_enc);
						msn_message_unref(msg);
						trans->data = NULL;
					}
				}
			}
		}
	} else {
		serv_got_im(gc, who, text, 0, time(NULL));
	}

	g_free(text);
	xmlnode_free(payloadNode);
}

static void
ipg_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
	cmd->payload_len = atoi(cmd->params[0]);
	cmdproc->last_cmd->payload_cb = ipg_cmd_post;
}

static void
nln_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
	MsnSession *session;
	MsnUser *user;
	MsnObject *msnobj;
	unsigned long clientid, extcaps;
	char *extcap_str;
	char *passport;
	int networkid;
	const char *state, *friendly;

	session = cmdproc->session;

	state = cmd->params[0];
	msn_parse_user(cmd->params[1], &passport, &networkid);
	friendly = purple_url_decode(cmd->params[2]);

	user = msn_userlist_find_user(session->userlist, passport);
	if (user == NULL) return;

	if (msn_user_set_friendly_name(user, friendly) && user != session->user)
	{
		msn_update_contact(session, passport, MSN_UPDATE_DISPLAY, friendly);
	}

	if (cmd->param_count == 5)
	{
		msnobj = msn_object_new_from_string(purple_url_decode(cmd->params[4]));
		msn_user_set_object(user, msnobj);
	}
	else
	{
		msn_user_set_object(user, NULL);
	}

	clientid = strtoul(cmd->params[3], &extcap_str, 10);
	if (extcap_str && *extcap_str)
		extcaps = strtoul(extcap_str+1, NULL, 10);
	else
		extcaps = 0;

	user->mobile = (clientid & MSN_CAP_MOBILE_ON) || (user->extinfo && user->extinfo->phone_mobile && user->extinfo->phone_mobile[0] == '+');

	msn_user_set_clientid(user, clientid);
	msn_user_set_extcaps(user, extcaps);
	msn_user_set_network(user, networkid);

	msn_user_set_state(user, state);
	msn_user_update(user);

	g_free(passport);
}

#if 0
static void
chg_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
	char *state = cmd->params[1];
	int state_id = 0;

	if (!strcmp(state, "NLN"))
		state_id = MSN_ONLINE;
	else if (!strcmp(state, "BSY"))
		state_id = MSN_BUSY;
	else if (!strcmp(state, "IDL"))
		state_id = MSN_IDLE;
	else if (!strcmp(state, "BRB"))
		state_id = MSN_BRB;
	else if (!strcmp(state, "AWY"))
		state_id = MSN_AWAY;
	else if (!strcmp(state, "PHN"))
		state_id = MSN_PHONE;
	else if (!strcmp(state, "LUN"))
		state_id = MSN_LUNCH;
	else if (!strcmp(state, "HDN"))
		state_id = MSN_HIDDEN;

	cmdproc->session->state = state_id;
}
#endif


static void
not_cmd_post(MsnCmdProc *cmdproc, MsnCommand *cmd, char *payload, size_t len)
{
#if 0
	MSN_SET_PARAMS("NOT %d\r\n%s", cmdproc->servconn->payload, payload);
	purple_debug_misc("msn", "Notification: {%s}\n", payload);
#endif
}

static void
not_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
	cmd->payload_len = atoi(cmd->params[0]);
	cmdproc->last_cmd->payload_cb = not_cmd_post;
}

static void
prp_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
	MsnSession *session = cmdproc->session;
	const char *type, *value;

	g_return_if_fail(cmd->param_count >= 3);

	type = cmd->params[2];

	if (cmd->param_count == 4)
	{
		value = cmd->params[3];
		if (!strcmp(type, "PHH"))
			msn_user_set_home_phone(session->user, purple_url_decode(value));
		else if (!strcmp(type, "PHW"))
			msn_user_set_work_phone(session->user, purple_url_decode(value));
		else if (!strcmp(type, "PHM"))
			msn_user_set_mobile_phone(session->user, purple_url_decode(value));
	}
	else
	{
		if (!strcmp(type, "PHH"))
			msn_user_set_home_phone(session->user, NULL);
		else if (!strcmp(type, "PHW"))
			msn_user_set_work_phone(session->user, NULL);
		else if (!strcmp(type, "PHM"))
			msn_user_set_mobile_phone(session->user, NULL);
	}
}

/**************************************************************************
 * Misc commands
 **************************************************************************/

static void
url_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
	MsnSession *session;
	PurpleConnection *gc;
	PurpleAccount *account;
	const char *rru;
	const char *url;
	PurpleCipherContext *cipher;
	gchar creds[33];
	char *buf;

	gulong tmp_timestamp;

	session = cmdproc->session;
	account = session->account;
	gc = account->gc;

	rru = cmd->params[1];
	url = cmd->params[2];

	session->passport_info.mail_timestamp = time(NULL);
	tmp_timestamp = session->passport_info.mail_timestamp - session->passport_info.sl;

	buf = g_strdup_printf("%s%lu%s",
	                      session->passport_info.mspauth ? session->passport_info.mspauth : "BOGUS",
	                      tmp_timestamp,
	                      purple_connection_get_password(gc));

	cipher = purple_cipher_context_new_by_name("md5", NULL);
	purple_cipher_context_append(cipher, (const guchar *)buf, strlen(buf));
	purple_cipher_context_digest_to_str(cipher, sizeof(creds), creds, NULL);
	purple_cipher_context_destroy(cipher);
	g_free(buf);

	g_free(session->passport_info.mail_url);
	session->passport_info.mail_url =
		g_strdup_printf("%s&auth=%s&creds=%s&sl=%ld&username=%s&mode=ttl&sid=%s&id=2&rru=%s&svc=mail&js=yes",
		                url,
		                session->passport_info.mspauth ? purple_url_encode(session->passport_info.mspauth) : "BOGUS",
		                creds,
		                tmp_timestamp,
		                msn_user_get_passport(session->user),
		                session->passport_info.sid,
		                rru);

	/* The user wants to check his or her email */
	if (cmd->trans && cmd->trans->data)
		purple_notify_uri(purple_account_get_connection(account), session->passport_info.mail_url);
}
/**************************************************************************
 * Switchboards
 **************************************************************************/

static void
rng_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
	MsnSession *session;
	MsnSwitchBoard *swboard;
	const char *session_id;
	char *host;
	int port;

	session = cmdproc->session;
	session_id = cmd->params[0];

	msn_parse_socket(cmd->params[1], &host, &port);

	if (session->http_method)
		port = 80;

	swboard = msn_switchboard_new(session);

	msn_switchboard_set_invited(swboard, TRUE);
	msn_switchboard_set_session_id(swboard, session_id);
	msn_switchboard_set_auth_key(swboard, cmd->params[3]);
	swboard->im_user = g_strdup(cmd->params[4]);
	/* msn_switchboard_add_user(swboard, cmd->params[4]); */

	if (!msn_switchboard_connect(swboard, host, port))
		msn_switchboard_destroy(swboard);

	g_free(host);
}

static void
xfr_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
	char *host;
	int port;

	if (strcmp(cmd->params[1], "SB") && strcmp(cmd->params[1], "NS"))
	{
		/* Maybe we can have a generic bad command error. */
		purple_debug_error("msn", "Bad XFR command (%s)\n", cmd->params[1]);
		return;
	}

	msn_parse_socket(cmd->params[2], &host, &port);

	if (!strcmp(cmd->params[1], "SB"))
	{
		purple_debug_error("msn", "This shouldn't be handled here.\n");
	}
	else if (!strcmp(cmd->params[1], "NS"))
	{
		MsnSession *session;

		session = cmdproc->session;

		msn_session_set_login_step(session, MSN_LOGIN_STEP_TRANSFER);

		msn_notification_connect(session->notification, host, port);
	}

	g_free(host);
}

static void
gcf_cmd_post(MsnCmdProc *cmdproc, MsnCommand *cmd, char *payload,
			 size_t len)
{
/* QuLogic: Disabled until confirmed correct. */
#if 0
	xmlnode *root;
	xmlnode *policy;

	g_return_if_fail(cmd->payload != NULL);

	if ( (root = xmlnode_from_str(cmd->payload, cmd->payload_len)) == NULL)
	{
		purple_debug_error("msn", "Unable to parse GCF payload into a XML tree\n");
		return;
	}


	g_free(cmdproc->session->blocked_text);
	cmdproc->session->blocked_text = NULL;

	/* We need a get_child with attrib... */
	policy = xmlnode_get_child(root, "Policy");
	while (policy) {
		if (g_str_equal(xmlnode_get_attrib(policy, "type"), "SHIELDS"))
			break;
		policy = xmlnode_get_next_twin(policy);
	}

	if (policy) {
		GString *blocked = g_string_new(NULL);
		xmlnode *imtext = xmlnode_get_child(policy,
		                                    "config/block/regexp/imtext");
		while (imtext) {
			const char *value = xmlnode_get_attrib(imtext, "value");
			g_string_append_printf(blocked, "%s<br/>\n",
			                       purple_base64_decode(value, NULL));
			imtext = xmlnode_get_next_twin(imtext);
		}

		cmdproc->session->blocked_text = g_string_free(blocked, FALSE);
	}

	xmlnode_free(root);
#endif
}

static void
gcf_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
	purple_debug_info("msn", "Processing GCF command\n");

	cmdproc->last_cmd->payload_cb  = gcf_cmd_post;
	cmd->payload_len = atoi(cmd->params[1]);
}

static void
sbs_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
	purple_debug_info("msn", "Processing SBS... \n");
	/*get the payload content*/
}

static void
parse_user_endpoints(MsnUser *user, xmlnode *payloadNode)
{
	MsnSession *session;
	xmlnode *epNode, *capsNode;
	MsnUserEndpoint data;
	const char *id;
	char *caps, *tmp;
	gboolean is_me;

	purple_debug_info("msn", "Get EndpointData\n");

	session = user->userlist->session;
	is_me = (user == session->user);

	msn_user_clear_endpoints(user);
	for (epNode = xmlnode_get_child(payloadNode, "EndpointData");
	     epNode;
	     epNode = xmlnode_get_next_twin(epNode)) {
		id = xmlnode_get_attrib(epNode, "id");
		capsNode = xmlnode_get_child(epNode, "Capabilities");

		/* Disconnect others, if MPOP is disabled */
		if (is_me
		 && !session->enable_mpop
		 && strncasecmp(id + 1, session->guid, 36) != 0) {
			purple_debug_info("msn", "Disconnecting Endpoint %s\n", id);

			tmp = g_strdup_printf("%s;%s", user->passport, id);
			msn_notification_send_uun(session, tmp, MSN_UNIFIED_NOTIFICATION_MPOP, "goawyplzthxbye");
			g_free(tmp);
		} else {
			if (capsNode != NULL) {
				caps = xmlnode_get_data(capsNode);

				data.clientid = strtoul(caps, &tmp, 10);
				if (tmp && *tmp)
					data.extcaps = strtoul(tmp + 1, NULL, 10);
				else
					data.extcaps = 0;

				g_free(caps);
			} else {
				data.clientid = 0;
				data.extcaps = 0;
			}

			msn_user_set_endpoint_data(user, id, &data);
		}
	}

	if (is_me && session->enable_mpop) {
		for (epNode = xmlnode_get_child(payloadNode, "PrivateEndpointData");
		     epNode;
		     epNode = xmlnode_get_next_twin(epNode)) {
			MsnUserEndpoint *ep;
			xmlnode *nameNode, *clientNode;

			/*	<PrivateEndpointData id='{GUID}'>
					<EpName>Endpoint Name</EpName>
					<Idle>true/false</Idle>
					<ClientType>1</ClientType>
					<State>NLN</State>
				</PrivateEndpointData>
			*/
			id = xmlnode_get_attrib(epNode, "id");
			ep = msn_user_get_endpoint_data(user, id);

			if (ep != NULL) {
				nameNode = xmlnode_get_child(epNode, "EpName");
				if (nameNode != NULL) {
					g_free(ep->name);
					ep->name = xmlnode_get_data(nameNode);
				}

				clientNode = xmlnode_get_child(epNode, "ClientType");
				if (clientNode != NULL) {
					tmp = xmlnode_get_data(clientNode);
					ep->type = strtoul(tmp, NULL, 10);
					g_free(tmp);
				}
			}
		}
	}
}

static void parse_currentmedia(MsnUser *user, const char *cmedia)
{
	char **cmedia_array;
	int strings = 0;

	if (!cmedia || cmedia[0] == '\0') {
		purple_debug_info("msn", "No currentmedia string\n");
		return;
	}

	purple_debug_info("msn", "Parsing currentmedia string: \"%s\"\n", cmedia);

	cmedia_array = g_strsplit(cmedia, "\\0", 0);

	/*
	 * 0: Application
	 * 1: 'Music'/'Games'/'Office'
	 * 2: '1' if enabled, '0' if not
	 * 3: Format (eg. {0} by {1})
	 * 4: Title
	 * If 'Music':
	 *  5: Artist
	 *  6: Album
	 *  7: ?
	 */
	strings  = g_strv_length(cmedia_array);

	if (strings >= 4 && !strcmp(cmedia_array[2], "1")) {
		if (user->extinfo == NULL)
			user->extinfo = g_new0(MsnUserExtendedInfo, 1);
		else {
			g_free(user->extinfo->media_album);
			g_free(user->extinfo->media_artist);
			g_free(user->extinfo->media_title);
		}

		if (!strcmp(cmedia_array[1], "Music"))
			user->extinfo->media_type = CURRENT_MEDIA_MUSIC;
		else if (!strcmp(cmedia_array[1], "Games"))
			user->extinfo->media_type = CURRENT_MEDIA_GAMES;
		else if (!strcmp(cmedia_array[1], "Office"))
			user->extinfo->media_type = CURRENT_MEDIA_OFFICE;
		else
			user->extinfo->media_type = CURRENT_MEDIA_UNKNOWN;

		user->extinfo->media_title = g_strdup(cmedia_array[strings == 4 ? 3 : 4]);
		user->extinfo->media_artist = strings > 5 ? g_strdup(cmedia_array[5]) : NULL;
		user->extinfo->media_album = strings > 6 ? g_strdup(cmedia_array[6]) : NULL;
	}

	g_strfreev(cmedia_array);
}

/*
 * Get the UBX's PSM info
 * Post it to the User status
 * Thanks for Chris <ukdrizzle@yahoo.co.uk>'s code
 */
static void
ubx_cmd_post(MsnCmdProc *cmdproc, MsnCommand *cmd, char *payload,
			 size_t len)
{
	MsnSession *session;
	MsnUser *user;
	char *passport;
	int network;
	xmlnode *payloadNode;
	char *psm_str, *str;

	session = cmdproc->session;

	msn_parse_user(cmd->params[0], &passport, &network);
	user = msn_userlist_find_user(session->userlist, passport);

	if (user == NULL) {
		str = g_strndup(payload, len);
		purple_debug_info("msn", "unknown user %s, payload is %s\n",
			passport, str);
		g_free(passport);
		g_free(str);
		return;
	}

	g_free(passport);

	/* Free any existing media info for this user */
	if (user->extinfo) {
		g_free(user->extinfo->media_album);
		g_free(user->extinfo->media_artist);
		g_free(user->extinfo->media_title);
		user->extinfo->media_album = NULL;
		user->extinfo->media_artist = NULL;
		user->extinfo->media_title = NULL;
		user->extinfo->media_type = CURRENT_MEDIA_UNKNOWN;
	}

	if (len != 0) {
		payloadNode = xmlnode_from_str(payload, len);
		if (!payloadNode) {
			purple_debug_error("msn", "UBX XML parse Error!\n");

			msn_user_set_statusline(user, NULL);

			msn_user_update(user);
			return;
		}

		psm_str = msn_get_psm(payloadNode);
		msn_user_set_statusline(user, psm_str);
		g_free(psm_str);

		str = msn_get_currentmedia(payloadNode);
		parse_currentmedia(user, str);
		g_free(str);

		parse_user_endpoints(user, payloadNode);

		xmlnode_free(payloadNode);

	} else {
		msn_user_set_statusline(user, NULL);
	}

	msn_user_update(user);
}

static void
ubx_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
	purple_debug_misc("msn", "UBX received.\n");
	cmdproc->last_cmd->payload_cb  = ubx_cmd_post;
	cmd->payload_len = atoi(cmd->params[1]);
}

static void
uux_cmd_post(MsnCmdProc *cmdproc, MsnCommand *cmd, char *payload,
			 size_t len)
{
	/* Do Nothing, right now. */
	if (payload != NULL)
		purple_debug_info("msn", "UUX payload:\n%s\n", payload);
}

static void
uux_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
	purple_debug_misc("msn", "UUX received.\n");
	cmdproc->last_cmd->payload_cb = uux_cmd_post;
	cmd->payload_len = atoi(cmd->params[1]);
}

void
msn_notification_send_uux(MsnSession *session, const char *payload)
{
	MsnTransaction *trans;
	MsnCmdProc *cmdproc;
	size_t len = strlen(payload);

	cmdproc = session->notification->cmdproc;
	purple_debug_misc("msn", "Sending UUX command with payload: %s\n", payload);
	trans = msn_transaction_new(cmdproc, "UUX", "%" G_GSIZE_FORMAT, len);
	msn_transaction_set_payload(trans, payload, len);
	msn_cmdproc_send_trans(cmdproc, trans);
}

void msn_notification_send_uux_endpointdata(MsnSession *session)
{
	xmlnode *epDataNode;
	xmlnode *capNode;
	char *caps;
	char *payload;
	int length;

	epDataNode = xmlnode_new("EndpointData");

	capNode = xmlnode_new_child(epDataNode, "Capabilities");
	caps = g_strdup_printf("%d:%02d", MSN_CLIENT_ID_CAPABILITIES, MSN_CLIENT_ID_EXT_CAPS);
	xmlnode_insert_data(capNode, caps, -1);
	g_free(caps);

	payload = xmlnode_to_str(epDataNode, &length);

	msn_notification_send_uux(session, payload);

	xmlnode_free(epDataNode);
	g_free(payload);
}

void msn_notification_send_uux_private_endpointdata(MsnSession *session)
{
	xmlnode *private;
	const char *name;
	xmlnode *epname;
	xmlnode *idle;
	GHashTable *ui_info;
	const gchar *ui_type;
	xmlnode *client_type;
	xmlnode *state;
	char *payload;
	int length;

	private = xmlnode_new("PrivateEndpointData");

	name = purple_account_get_string(session->account, "endpoint-name", NULL);
	epname = xmlnode_new_child(private, "EpName");
	xmlnode_insert_data(epname, name, -1);

	idle = xmlnode_new_child(private, "Idle");
	xmlnode_insert_data(idle, "false", -1);

	/* ClientType info (from amsn guys):
		0: None
		1: Computer
		2: Website
		3: Mobile / none
		4: Xbox / phone /mobile
		9: MsnGroup
		32: Email member, currently Yahoo!
	*/
	client_type = xmlnode_new_child(private, "ClientType");
	ui_info = purple_core_get_ui_info();
	ui_type = ui_info ? g_hash_table_lookup(ui_info, "client_type") : NULL;
	if (ui_type) {
		if (strcmp(ui_type, "pc") == 0)
			xmlnode_insert_data(client_type, "1", -1);
		else if (strcmp(ui_type, "web") == 0)
			xmlnode_insert_data(client_type, "2", -1);
		else if (strcmp(ui_type, "phone") == 0)
			xmlnode_insert_data(client_type, "3", -1);
		else if (strcmp(ui_type, "handheld") == 0)
			xmlnode_insert_data(client_type, "3", -1);
		else
			xmlnode_insert_data(client_type, "1", -1);
	}
	else
		xmlnode_insert_data(client_type, "1", -1);

	state = xmlnode_new_child(private, "State");
	xmlnode_insert_data(state, msn_state_get_text(msn_state_from_account(session->account)), -1);

	payload = xmlnode_to_str(private, &length);

	msn_notification_send_uux(session, payload);

	xmlnode_free(private);
	g_free(payload);
}

static void
ubn_cmd_post(MsnCmdProc *cmdproc, MsnCommand *cmd, char *payload,
			 size_t len)
{
	/* Do Nothing, right now. */
	if (payload != NULL)
		purple_debug_info("msn", "UBN payload:\n%s\n", payload);
}

static void
ubn_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
	purple_debug_misc("msn", "UBN received from %s.\n", cmd->params[0]);
	cmdproc->last_cmd->payload_cb  = ubn_cmd_post;
	cmd->payload_len = atoi(cmd->params[2]);
}

static void
uun_cmd_post(MsnCmdProc *cmdproc, MsnCommand *cmd, char *payload,
			 size_t len)
{
	/* Do Nothing, right now. */
	if (payload != NULL)
		purple_debug_info("msn", "UUN payload:\n%s\n", payload);
}

static void
uun_cmd(MsnCmdProc *cmdproc, MsnCommand *cmd)
{
	if (strcmp(cmd->params[1], "OK") != 0) {
		purple_debug_misc("msn", "UUN received.\n");
		cmdproc->last_cmd->payload_cb = uun_cmd_post;
		cmd->payload_len = atoi(cmd->params[1]);
	}
	else
		purple_debug_misc("msn", "UUN OK received.\n");
}

void
msn_notification_send_uun(MsnSession *session, const char *user,
                          MsnUnifiedNotificationType type, const char *payload)
{
	MsnTransaction *trans;
	MsnCmdProc *cmdproc;
	size_t len = strlen(payload);

	cmdproc = session->notification->cmdproc;
	purple_debug_misc("msn", "Sending UUN command %d to %s with payload: %s\n",
	                  type, user, payload);
	trans = msn_transaction_new(cmdproc, "UUN", "%s %d %" G_GSIZE_FORMAT,
	                            user, type, len);
	msn_transaction_set_payload(trans, payload, len);
	msn_cmdproc_send_trans(cmdproc, trans);
}

void
msn_notification_send_circle_auth(MsnSession *session, const char *ticket)
{
	MsnTransaction *trans;
	MsnCmdProc *cmdproc;
	char *encoded;

	cmdproc = session->notification->cmdproc;

	encoded = purple_base64_encode((guchar *)ticket, strlen(ticket));
	trans = msn_transaction_new(cmdproc, "USR", "SHA A %s", encoded);
	msn_cmdproc_send_trans(cmdproc, trans);

	g_free(encoded);
}

/**************************************************************************
 * Message Types
 **************************************************************************/

static void
profile_msg(MsnCmdProc *cmdproc, MsnMessage *msg)
{
	MsnSession *session;
	const char *value;
#ifdef MSN_PARTIAL_LISTS
	const char *clLastChange;
#endif

	session = cmdproc->session;

	if (strcmp(msg->remote_user, "Hotmail"))
		/* This isn't an official message. */
		return;

	if ((value = msn_message_get_header_value(msg, "sid")) != NULL)
	{
		g_free(session->passport_info.sid);
		session->passport_info.sid = g_strdup(value);
	}

	if ((value = msn_message_get_header_value(msg, "MSPAuth")) != NULL)
	{
		g_free(session->passport_info.mspauth);
		session->passport_info.mspauth = g_strdup(value);
	}

	if ((value = msn_message_get_header_value(msg, "ClientIP")) != NULL)
	{
		g_free(session->passport_info.client_ip);
		session->passport_info.client_ip = g_strdup(value);
	}

	if ((value = msn_message_get_header_value(msg, "ClientPort")) != NULL)
	{
		session->passport_info.client_port = ntohs(atoi(value));
	}

	if ((value = msn_message_get_header_value(msg, "LoginTime")) != NULL)
		session->passport_info.sl = atol(value);

	if ((value = msn_message_get_header_value(msg, "EmailEnabled")) != NULL)
		session->passport_info.email_enabled = (gboolean)atol(value);

#ifdef MSN_PARTIAL_LISTS
	/*starting retrieve the contact list*/
	clLastChange = purple_account_get_string(session->account, "CLLastChange", NULL);
	/* msn_userlist_load defeats all attempts at trying to detect blist sync issues */
	msn_userlist_load(session);
	msn_get_contact_list(session, MSN_PS_INITIAL, clLastChange);
#else
	/* always get the full list? */
	msn_get_contact_list(session, MSN_PS_INITIAL, NULL);
#endif
}

static void
initial_email_msg(MsnCmdProc *cmdproc, MsnMessage *msg)
{
	MsnSession *session;
	PurpleConnection *gc;
	GHashTable *table;
	const char *unread;

	session = cmdproc->session;
	gc = session->account->gc;

	if (strcmp(msg->remote_user, "Hotmail"))
		/* This isn't an official message. */
		return;

	if (session->passport_info.mail_url == NULL)
	{
		MsnTransaction *trans;
		trans = msn_transaction_new(cmdproc, "URL", "%s", "INBOX");
		msn_transaction_queue_cmd(trans, msg->cmd);

		msn_cmdproc_send_trans(cmdproc, trans);

		return;
	}

	if (!purple_account_get_check_mail(session->account))
		return;

	table = msn_message_get_hashtable_from_body(msg);

	unread = g_hash_table_lookup(table, "Inbox-Unread");

	if (unread != NULL)
	{
		int count = atoi(unread);

		if (count > 0)
		{
			const char *passports[2] = { msn_user_get_passport(session->user) };
			const char *urls[2] = { session->passport_info.mail_url };

			purple_notify_emails(gc, count, FALSE, NULL, NULL,
							   passports, urls, NULL, NULL);
		}
	}

	g_hash_table_destroy(table);
}

/*offline Message notification process*/
static void
initial_mdata_msg(MsnCmdProc *cmdproc, MsnMessage *msg)
{
	MsnSession *session;
	PurpleConnection *gc;
	GHashTable *table;
	const char *mdata, *unread;

	session = cmdproc->session;
	gc = session->account->gc;

	if (strcmp(msg->remote_user, "Hotmail"))
		/* This isn't an official message. */
		return;

	table = msn_message_get_hashtable_from_body(msg);

	mdata = g_hash_table_lookup(table, "Mail-Data");

	if (mdata != NULL)
		msn_parse_oim_msg(session->oim, mdata);

	if (g_hash_table_lookup(table, "Inbox-URL") == NULL)
	{
		g_hash_table_destroy(table);
		return;
	}

	if (session->passport_info.mail_url == NULL)
	{
		MsnTransaction *trans;
		trans = msn_transaction_new(cmdproc, "URL", "%s", "INBOX");
		msn_transaction_queue_cmd(trans, msg->cmd);

		msn_cmdproc_send_trans(cmdproc, trans);

		g_hash_table_destroy(table);
		return;
	}

	if (!purple_account_get_check_mail(session->account))
	{
		g_hash_table_destroy(table);
		return;
	}

	unread = g_hash_table_lookup(table, "Inbox-Unread");

	if (unread != NULL)
	{
		int count = atoi(unread);

		if (count > 0)
		{
			const char *passports[2] = { msn_user_get_passport(session->user) };
			const char *urls[2] = { session->passport_info.mail_url };

			purple_notify_emails(gc, count, FALSE, NULL, NULL,
							   passports, urls, NULL, NULL);
		}
	}

	g_hash_table_destroy(table);
}

/*offline Message Notification*/
static void
delete_oim_msg(MsnCmdProc *cmdproc, MsnMessage *msg)
{
	purple_debug_misc("msn", "Delete OIM message.\n");
}

static void
email_msg(MsnCmdProc *cmdproc, MsnMessage *msg)
{
	MsnSession *session;
	PurpleConnection *gc;
	GHashTable *table;
	char *from, *subject, *tmp;

	session = cmdproc->session;
	gc = session->account->gc;

	if (strcmp(msg->remote_user, "Hotmail"))
		/* This isn't an official message. */
		return;

	if (session->passport_info.mail_url == NULL)
	{
		MsnTransaction *trans;
		trans = msn_transaction_new(cmdproc, "URL", "%s", "INBOX");
		msn_transaction_queue_cmd(trans, msg->cmd);

		msn_cmdproc_send_trans(cmdproc, trans);

		return;
	}

	if (!purple_account_get_check_mail(session->account))
		return;

	table = msn_message_get_hashtable_from_body(msg);

	from = subject = NULL;

	tmp = g_hash_table_lookup(table, "From");
	if (tmp != NULL)
		from = purple_mime_decode_field(tmp);

	tmp = g_hash_table_lookup(table, "Subject");
	if (tmp != NULL)
		subject = purple_mime_decode_field(tmp);

	purple_notify_email(gc,
					  (subject != NULL ? subject : ""),
					  (from != NULL ?  from : ""),
					  msn_user_get_passport(session->user),
					  session->passport_info.mail_url, NULL, NULL);

	g_free(from);
	g_free(subject);

	g_hash_table_destroy(table);
}

static void
system_msg(MsnCmdProc *cmdproc, MsnMessage *msg)
{
	GHashTable *table;
	const char *type_s;

	if (strcmp(msg->remote_user, "Hotmail"))
		/* This isn't an official message. */
		return;

	table = msn_message_get_hashtable_from_body(msg);

	if ((type_s = g_hash_table_lookup(table, "Type")) != NULL)
	{
		int type = atoi(type_s);
		char buf[MSN_BUF_LEN] = "";
		int minutes;

		switch (type)
		{
			case 1:
				minutes = atoi(g_hash_table_lookup(table, "Arg1"));
				g_snprintf(buf, sizeof(buf), dngettext(PACKAGE,
							"The MSN server will shut down for maintenance "
							"in %d minute. You will automatically be "
							"signed out at that time.  Please finish any "
							"conversations in progress.\n\nAfter the "
							"maintenance has been completed, you will be "
							"able to successfully sign in.",
							"The MSN server will shut down for maintenance "
							"in %d minutes. You will automatically be "
							"signed out at that time.  Please finish any "
							"conversations in progress.\n\nAfter the "
							"maintenance has been completed, you will be "
							"able to successfully sign in.", minutes),
						minutes);
			default:
				break;
		}

		if (*buf != '\0')
			purple_notify_info(cmdproc->session->account->gc, NULL, buf, NULL);
	}

	g_hash_table_destroy(table);
}

/**************************************************************************
 * Dispatch server list management
 **************************************************************************/
typedef struct MsnAddRemoveListData {
	MsnCmdProc *cmdproc;
	MsnUser *user;
	MsnListOp list_op;
	gboolean add;
} MsnAddRemoveListData;

static void
modify_unknown_buddy_on_list(MsnSession *session, const char *passport,
                             MsnNetwork network, gpointer data)
{
	MsnAddRemoveListData *addrem = data;
	MsnCmdProc *cmdproc;
	xmlnode *node;
	char *payload;
	int payload_len;

	cmdproc = addrem->cmdproc;

	/* Update user first */
	msn_user_set_network(addrem->user, network);

	node = xmlnode_new("ml");
	node->child = NULL;

	msn_add_contact_xml(node, passport, addrem->list_op, network);

	payload = xmlnode_to_str(node, &payload_len);
	xmlnode_free(node);

	if (addrem->add)
		msn_notification_post_adl(cmdproc, payload, payload_len);
	else
		msn_notification_post_rml(cmdproc, payload, payload_len);

	g_free(payload);
	g_free(addrem);
}

void
msn_notification_add_buddy_to_list(MsnNotification *notification, MsnListId list_id,
							  MsnUser *user)
{
	MsnAddRemoveListData *addrem;
	MsnCmdProc *cmdproc;
	MsnListOp list_op = 1 << list_id;
	xmlnode *adl_node;
	char *payload;
	int payload_len;

	cmdproc = notification->servconn->cmdproc;

	adl_node = xmlnode_new("ml");
	adl_node->child = NULL;

	msn_add_contact_xml(adl_node, user->passport, list_op, user->networkid);

	payload = xmlnode_to_str(adl_node, &payload_len);
	xmlnode_free(adl_node);

	if (user->networkid != MSN_NETWORK_UNKNOWN) {
		msn_notification_post_adl(cmdproc, payload, payload_len);

	} else {
		addrem = g_new(MsnAddRemoveListData, 1);
		addrem->cmdproc = cmdproc;
		addrem->user = user;
		addrem->list_op = list_op;
		addrem->add = TRUE;

		msn_notification_send_fqy(notification->session, payload, payload_len,
		                          modify_unknown_buddy_on_list, addrem);
	}

	g_free(payload);
}

void
msn_notification_rem_buddy_from_list(MsnNotification *notification, MsnListId list_id,
						   MsnUser *user)
{
	MsnAddRemoveListData *addrem;
	MsnCmdProc *cmdproc;
	MsnListOp list_op = 1 << list_id;
	xmlnode *rml_node;
	char *payload;
	int payload_len;

	cmdproc = notification->servconn->cmdproc;

	rml_node = xmlnode_new("ml");
	rml_node->child = NULL;

	msn_add_contact_xml(rml_node, user->passport, list_op, user->networkid);

	payload = xmlnode_to_str(rml_node, &payload_len);
	xmlnode_free(rml_node);

	if (user->networkid != MSN_NETWORK_UNKNOWN) {
		msn_notification_post_rml(cmdproc, payload, payload_len);

	} else {
		addrem = g_new(MsnAddRemoveListData, 1);
		addrem->cmdproc = cmdproc;
		addrem->user = user;
		addrem->list_op = list_op;
		addrem->add = FALSE;

		msn_notification_send_fqy(notification->session, payload, payload_len,
		                          modify_unknown_buddy_on_list, addrem);
	}

	g_free(payload);
}

/**************************************************************************
 * Init
 **************************************************************************/
void
msn_notification_init(void)
{
	cbs_table = msn_table_new();

	/* Synchronous */
	msn_table_add_cmd(cbs_table, "CHG", "CHG", NULL);
	msn_table_add_cmd(cbs_table, "CHG", "ILN", iln_cmd);
	msn_table_add_cmd(cbs_table, "ADL", "ILN", iln_cmd);
	msn_table_add_cmd(cbs_table, "USR", "USR", usr_cmd);
	msn_table_add_cmd(cbs_table, "USR", "XFR", xfr_cmd);
	msn_table_add_cmd(cbs_table, "USR", "GCF", gcf_cmd);
	msn_table_add_cmd(cbs_table, "CVR", "CVR", cvr_cmd);
	msn_table_add_cmd(cbs_table, "VER", "VER", ver_cmd);
	msn_table_add_cmd(cbs_table, "PRP", "PRP", prp_cmd);
	msn_table_add_cmd(cbs_table, "BLP", "BLP", blp_cmd);
	msn_table_add_cmd(cbs_table, "XFR", "XFR", xfr_cmd);

	/* Asynchronous */
	msn_table_add_cmd(cbs_table, NULL, "IPG", ipg_cmd);
	msn_table_add_cmd(cbs_table, NULL, "MSG", msg_cmd);
	msn_table_add_cmd(cbs_table, NULL, "UBM", ubm_cmd);
	msn_table_add_cmd(cbs_table, NULL, "GCF", gcf_cmd);
	msn_table_add_cmd(cbs_table, NULL, "SBS", sbs_cmd);
	msn_table_add_cmd(cbs_table, NULL, "NOT", not_cmd);

	msn_table_add_cmd(cbs_table, NULL, "CHL", chl_cmd);
	msn_table_add_cmd(cbs_table, NULL, "RML", rml_cmd);
	msn_table_add_cmd(cbs_table, NULL, "ADL", adl_cmd);
	msn_table_add_cmd(cbs_table, NULL, "FQY", fqy_cmd);

	msn_table_add_cmd(cbs_table, NULL, "QRY", NULL);
	msn_table_add_cmd(cbs_table, NULL, "QNG", qng_cmd);
	msn_table_add_cmd(cbs_table, NULL, "FLN", fln_cmd);
	msn_table_add_cmd(cbs_table, NULL, "NLN", nln_cmd);
	msn_table_add_cmd(cbs_table, NULL, "ILN", iln_cmd);
	msn_table_add_cmd(cbs_table, NULL, "OUT", out_cmd);
	msn_table_add_cmd(cbs_table, NULL, "RNG", rng_cmd);

	msn_table_add_cmd(cbs_table, NULL, "UBX", ubx_cmd);
	msn_table_add_cmd(cbs_table, NULL, "UUX", uux_cmd);

	msn_table_add_cmd(cbs_table, NULL, "UBN", ubn_cmd);
	msn_table_add_cmd(cbs_table, NULL, "UUN", uun_cmd);

	msn_table_add_cmd(cbs_table, NULL, "URL", url_cmd);

	msn_table_add_cmd(cbs_table, "fallback", "XFR", xfr_cmd);

	msn_table_add_error(cbs_table, "ADL", adl_error);
	msn_table_add_error(cbs_table, "RML", rml_error);
	msn_table_add_error(cbs_table, "FQY", fqy_error);
	msn_table_add_error(cbs_table, "USR", usr_error);

	msn_table_add_msg_type(cbs_table,
						   "text/x-msmsgsprofile",
						   profile_msg);
	/*initial OIM notification*/
	msn_table_add_msg_type(cbs_table,
							"text/x-msmsgsinitialmdatanotification",
							initial_mdata_msg);
	/*OIM notification when user online*/
	msn_table_add_msg_type(cbs_table,
							"text/x-msmsgsoimnotification",
							initial_mdata_msg);
	msn_table_add_msg_type(cbs_table,
						   "text/x-msmsgsinitialemailnotification",
						   initial_email_msg);
	msn_table_add_msg_type(cbs_table,
						   "text/x-msmsgsemailnotification",
						   email_msg);
	/*delete an offline Message notification*/
	msn_table_add_msg_type(cbs_table,
							"text/x-msmsgsactivemailnotification",
						   delete_oim_msg);
	msn_table_add_msg_type(cbs_table,
						   "application/x-msmsgssystemmessage",
						   system_msg);
	/* generic message handlers */
	msn_table_add_msg_type(cbs_table, "text/plain",
						   msn_plain_msg);
	msn_table_add_msg_type(cbs_table, "text/x-msmsgscontrol",
						   msn_control_msg);
	msn_table_add_msg_type(cbs_table, "text/x-msnmsgr-datacast",
						   msn_datacast_msg);
}

void
msn_notification_end(void)
{
	msn_table_destroy(cbs_table);
}

