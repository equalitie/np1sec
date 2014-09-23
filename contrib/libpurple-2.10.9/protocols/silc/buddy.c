/*

  silcpurple_buddy.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2004 - 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#include "internal.h"
#include "silc.h"
#include "silcclient.h"
#include "silcpurple.h"
#include "wb.h"

/***************************** Key Agreement *********************************/

static void
silcpurple_buddy_keyagr(PurpleBlistNode *node, gpointer data);

static void
silcpurple_buddy_keyagr_do(PurpleConnection *gc, const char *name,
			   gboolean force_local);

typedef struct {
	char *nick;
	PurpleConnection *gc;
} *SilcPurpleResolve;

static void
silcpurple_buddy_keyagr_resolved(SilcClient client,
				 SilcClientConnection conn,
				 SilcStatus status,
				 SilcDList clients,
				 void *context)
{
	PurpleConnection *gc = client->application;
	SilcPurpleResolve r = context;
	char tmp[256];

	if (!clients) {
		g_snprintf(tmp, sizeof(tmp),
			   _("User %s is not present in the network"), r->nick);
		purple_notify_error(gc, _("Key Agreement"),
				  _("Cannot perform the key agreement"), tmp);
		g_free(r->nick);
		silc_free(r);
		return;
	}

	silcpurple_buddy_keyagr_do(gc, r->nick, FALSE);
	g_free(r->nick);
	silc_free(r);
}

static void
silcpurple_buddy_keyagr_cb(SilcClient client,
			   SilcClientConnection conn,
			   SilcClientEntry client_entry,
			   SilcKeyAgreementStatus status,
			   SilcSKEKeyMaterial key,
			   void *context)
{
	PurpleConnection *gc = client->application;
	SilcPurple sg = gc->proto_data;

	if (!sg->conn)
		return;

	switch (status) {
	case SILC_KEY_AGREEMENT_OK:
		{
			PurpleConversation *convo;
			char tmp[128];

			/* Set the private key for this client */
			silc_client_del_private_message_key(client, conn, client_entry);
			silc_client_add_private_message_key_ske(client, conn, client_entry,
								NULL, NULL, key);
			silc_ske_free_key_material(key);


			/* Open IM window */
			convo = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM,
								      client_entry->nickname, sg->account);
			if (convo) {
				/* we don't have windows in the core anymore...but we may want to
				 * provide some method for asking the UI to show the window
				purple_conv_window_show(purple_conversation_get_window(convo));
				 */
			} else {
				convo = purple_conversation_new(PURPLE_CONV_TYPE_IM, sg->account,
								client_entry->nickname);
			}
			g_snprintf(tmp, sizeof(tmp), "%s [private key]", client_entry->nickname);
			purple_conversation_set_title(convo, tmp);
		}
		break;

	case SILC_KEY_AGREEMENT_ERROR:
		purple_notify_error(gc, _("Key Agreement"),
				    _("Error occurred during key agreement"), NULL);
		break;

	case SILC_KEY_AGREEMENT_FAILURE:
		purple_notify_error(gc, _("Key Agreement"), _("Key Agreement failed"), NULL);
		break;

	case SILC_KEY_AGREEMENT_TIMEOUT:
		purple_notify_error(gc, _("Key Agreement"),
				    _("Timeout during key agreement"), NULL);
		break;

	case SILC_KEY_AGREEMENT_ABORTED:
		purple_notify_error(gc, _("Key Agreement"),
				    _("Key agreement was aborted"), NULL);
		break;

	case SILC_KEY_AGREEMENT_ALREADY_STARTED:
		purple_notify_error(gc, _("Key Agreement"),
				    _("Key agreement is already started"), NULL);
		break;

	case SILC_KEY_AGREEMENT_SELF_DENIED:
		purple_notify_error(gc, _("Key Agreement"),
				    _("Key agreement cannot be started with yourself"),
				    NULL);
		break;

	default:
		break;
	}
}

static void
silcpurple_buddy_keyagr_do(PurpleConnection *gc, const char *name,
			   gboolean force_local)
{
	SilcPurple sg = gc->proto_data;
	SilcDList clients;
	SilcClientEntry client_entry;
	SilcClientConnectionParams params;
	char *local_ip = NULL, *remote_ip = NULL;
	gboolean local = TRUE;
	SilcSocket sock;

	if (!sg->conn || !name)
		return;

	/* Find client entry */
	clients = silc_client_get_clients_local(sg->client, sg->conn, name,
						FALSE);
	if (!clients) {
		/* Resolve unknown user */
		SilcPurpleResolve r = silc_calloc(1, sizeof(*r));
		if (!r)
			return;
		r->nick = g_strdup(name);
		r->gc = gc;
		silc_client_get_clients(sg->client, sg->conn, name, NULL,
					silcpurple_buddy_keyagr_resolved, r);
		return;
	}

	silc_socket_stream_get_info(silc_packet_stream_get_stream(sg->conn->stream),
				    &sock, NULL, NULL, NULL);

	/* Resolve the local IP from the outgoing socket connection.  We resolve
	   it to check whether we have a private range IP address or public IP
	   address.  If we have public then we will assume that we are not behind
	   NAT and will provide automatically the point of connection to the
	   agreement.  If we have private range address we assume that we are
	   behind NAT and we let the responder provide the point of connection.

	   The algorithm also checks the remote IP address of server connection.
	   If it is private range address and we have private range address we
	   assume that we are chatting in LAN and will provide the point of
	   connection.

	   Naturally this algorithm does not always get things right. */

	if (silc_net_check_local_by_sock(sock, NULL, &local_ip)) {
		/* Check if the IP is private */
		if (!force_local && silcpurple_ip_is_private(local_ip)) {
			local = FALSE;

			/* Local IP is private, resolve the remote server IP to see whether
			   we are talking to Internet or just on LAN. */
			if (silc_net_check_host_by_sock(sock, NULL,
							&remote_ip))
				if (silcpurple_ip_is_private(remote_ip))
					/* We assume we are in LAN.  Let's provide
					   the connection point. */
					local = TRUE;
		}
	}

	if (force_local)
		local = TRUE;

	if (local && !local_ip)
		local_ip = silc_net_localip();

	silc_dlist_start(clients);
	client_entry = silc_dlist_get(clients);

	memset(&params, 0, sizeof(params));
	params.timeout_secs = 60;
	if (local)
	  /* Provide connection point */
	  params.local_ip = local_ip;

	/* Send the key agreement request */
	silc_client_send_key_agreement(sg->client, sg->conn, client_entry,
				       &params, sg->public_key,
				       sg->private_key,
				       silcpurple_buddy_keyagr_cb, NULL);

	silc_free(local_ip);
	silc_free(remote_ip);
	silc_client_list_free(sg->client, sg->conn, clients);
}

typedef struct {
	SilcClient client;
	SilcClientConnection conn;
	SilcClientID client_id;
	char *hostname;
	SilcUInt16 port;
} *SilcPurpleKeyAgrAsk;

static void
silcpurple_buddy_keyagr_request_cb(SilcPurpleKeyAgrAsk a, gint id)
{
	SilcClientEntry client_entry;
	SilcClientConnectionParams params;

	if (id != 1)
		goto out;

	/* Get the client entry. */
	client_entry = silc_client_get_client_by_id(a->client, a->conn,
						    &a->client_id);
	if (!client_entry) {
		purple_notify_error(a->client->application, _("Key Agreement"),
				    _("The remote user is not present in the network any more"),
				    NULL);
		goto out;
	}

	/* If the hostname was provided by the requestor perform the key agreement
	   now.  Otherwise, we will send him a request to connect to us. */
	if (a->hostname) {
		memset(&params, 0, sizeof(params));
		params.timeout_secs = 60;
		silc_client_perform_key_agreement(a->client, a->conn,
						  client_entry, &params,
						  a->conn->public_key,
						  a->conn->private_key,
						  a->hostname, a->port,
						  silcpurple_buddy_keyagr_cb, NULL);
	} else {
		/* Send request.  Force us as the point of connection since requestor
		   did not provide the point of connection. */
		silcpurple_buddy_keyagr_do(a->client->application,
					   client_entry->nickname, TRUE);
	}

 out:
	g_free(a->hostname);
	silc_free(a);
}

void silcpurple_buddy_keyagr_request(SilcClient client,
				     SilcClientConnection conn,
				     SilcClientEntry client_entry,
				     const char *hostname, SilcUInt16 port,
				     SilcUInt16 protocol)
{
	char tmp[128], tmp2[128];
	SilcPurpleKeyAgrAsk a;
	PurpleConnection *gc = client->application;

	/* For now Pidgin don't support UDP key agreement */
	if (protocol == 1)
	  return;

	g_snprintf(tmp, sizeof(tmp),
		   _("Key agreement request received from %s. Would you like to "
		     "perform the key agreement?"), client_entry->nickname);
	if (hostname)
		g_snprintf(tmp2, sizeof(tmp2),
			   _("The remote user is waiting key agreement on:\n"
			     "Remote host: %s\nRemote port: %d"), hostname, port);

	a = silc_calloc(1, sizeof(*a));
	if (!a)
		return;
	a->client = client;
	a->conn = conn;
	a->client_id = client_entry->id;
	if (hostname)
		a->hostname = g_strdup(hostname);
	a->port = port;

	purple_request_action(client->application, _("Key Agreement Request"), tmp,
			      hostname ? tmp2 : NULL, 1, gc->account, client_entry->nickname,
			      NULL, a, 2, _("Yes"), G_CALLBACK(silcpurple_buddy_keyagr_request_cb),
			      _("No"), G_CALLBACK(silcpurple_buddy_keyagr_request_cb));
}

static void
silcpurple_buddy_keyagr(PurpleBlistNode *node, gpointer data)
{
	PurpleBuddy *buddy;
	PurpleAccount *account;

	buddy = (PurpleBuddy *)node;
	account = purple_buddy_get_account(buddy);
	silcpurple_buddy_keyagr_do(purple_account_get_connection(account),
			purple_buddy_get_name(buddy), FALSE);
}


/**************************** Static IM Key **********************************/

static void
silcpurple_buddy_resetkey(PurpleBlistNode *node, gpointer data)
{
	PurpleBuddy *b;
	PurpleConnection *gc;
        SilcPurple sg;
	SilcDList clients;

	g_return_if_fail(PURPLE_BLIST_NODE_IS_BUDDY(node));

	b = (PurpleBuddy *) node;
	gc = purple_account_get_connection(purple_buddy_get_account(b));
	sg = gc->proto_data;

	/* Find client entry */
	clients = silc_client_get_clients_local(sg->client, sg->conn,
						purple_buddy_get_name(b), FALSE);
	if (!clients)
		return;

	silc_dlist_start(clients);
	silc_client_del_private_message_key(sg->client, sg->conn,
					    silc_dlist_get(clients));
	silc_client_list_free(sg->client, sg->conn, clients);
}

typedef struct {
	SilcClient client;
	SilcClientConnection conn;
	SilcClientID client_id;
} *SilcPurplePrivkey;

static void
silcpurple_buddy_privkey(PurpleConnection *gc, const char *name);

static void
silcpurple_buddy_privkey_cb(SilcPurplePrivkey p, const char *passphrase)
{
	SilcClientEntry client_entry;

        if (!passphrase || !(*passphrase)) {
                silc_free(p);
                return;
        }

	/* Get the client entry. */
	client_entry = silc_client_get_client_by_id(p->client, p->conn,
						    &p->client_id);
	if (!client_entry) {
		purple_notify_error(p->client->application, _("IM With Password"),
				    _("The remote user is not present in the network any more"),
				    NULL);
		silc_free(p);
		return;
	}

	/* Set the private message key */
	silc_client_del_private_message_key(p->client, p->conn,
					    client_entry);
	silc_client_add_private_message_key(p->client, p->conn,
					    client_entry, NULL, NULL,
					    (unsigned char *)passphrase,
					    strlen(passphrase));
        silc_free(p);
}

static void
silcpurple_buddy_privkey_resolved(SilcClient client,
				  SilcClientConnection conn,
				  SilcStatus status,
				  SilcDList clients,
				  void *context)
{
	char tmp[256];

	if (!clients) {
		g_snprintf(tmp, sizeof(tmp),
			   _("User %s is not present in the network"),
			   (const char *)context);
		purple_notify_error(client->application, _("IM With Password"),
				  _("Cannot set IM key"), tmp);
		g_free(context);
		return;
	}

	silcpurple_buddy_privkey(client->application, context);
	g_free(context);
}

static void
silcpurple_buddy_privkey(PurpleConnection *gc, const char *name)
{
	SilcPurple sg = gc->proto_data;
	SilcPurplePrivkey p;
	SilcDList clients;
	SilcClientEntry client_entry;

	if (!name)
		return;

	/* Find client entry */
	clients = silc_client_get_clients_local(sg->client, sg->conn,
						name, FALSE);
	if (!clients) {
		silc_client_get_clients(sg->client, sg->conn, name, NULL,
					silcpurple_buddy_privkey_resolved,
					g_strdup(name));
		return;
	}

	silc_dlist_start(clients);
	client_entry = silc_dlist_get(clients);

	p = silc_calloc(1, sizeof(*p));
	if (!p)
		return;
	p->client = sg->client;
	p->conn = sg->conn;
	p->client_id = client_entry->id;
	purple_request_input(gc, _("IM With Password"), NULL,
	                     _("Set IM Password"), NULL, FALSE, TRUE, NULL,
	                     _("OK"), G_CALLBACK(silcpurple_buddy_privkey_cb),
	                     _("Cancel"), G_CALLBACK(silcpurple_buddy_privkey_cb),
	                     gc->account, NULL, NULL, p);

	silc_client_list_free(sg->client, sg->conn, clients);
}

static void
silcpurple_buddy_privkey_menu(PurpleBlistNode *node, gpointer data)
{
	PurpleBuddy *buddy;
	PurpleConnection *gc;

	g_return_if_fail(PURPLE_BLIST_NODE_IS_BUDDY(node));

	buddy = (PurpleBuddy *) node;
	gc = purple_account_get_connection(purple_buddy_get_account(buddy));

	silcpurple_buddy_privkey(gc, purple_buddy_get_name(buddy));
}


/**************************** Get Public Key *********************************/

typedef struct {
	SilcClient client;
	SilcClientConnection conn;
	SilcClientID client_id;
} *SilcPurpleBuddyGetkey;

static void
silcpurple_buddy_getkey(PurpleConnection *gc, const char *name);

static SilcBool
silcpurple_buddy_getkey_cb(SilcClient client, SilcClientConnection conn,
			   SilcCommand command, SilcStatus status,
			   SilcStatus error, void *context, va_list ap)
{
	SilcClientEntry client_entry;
	SilcPurpleBuddyGetkey g = context;

	if (status != SILC_STATUS_OK) {
		purple_notify_error(g->client->application, _("Get Public Key"),
				  _("The remote user is not present in the network any more"),
				  NULL);
		silc_free(g);
		return FALSE;
	}

	/* Get the client entry. */
	client_entry = silc_client_get_client_by_id(g->client, g->conn,
						    &g->client_id);
	if (!client_entry) {
		purple_notify_error(g->client->application, _("Get Public Key"),
				  _("The remote user is not present in the network any more"),
				  NULL);
		silc_free(g);
		return FALSE;
	}

	if (!client_entry->public_key) {
		silc_free(g);
		return FALSE;
	}

	/* Now verify the public key */
	silcpurple_verify_public_key(g->client, g->conn, client_entry->nickname,
				     SILC_CONN_CLIENT, client_entry->public_key,
				     NULL, NULL);
	silc_free(g);
	return TRUE;
}

static void
silcpurple_buddy_getkey_resolved(SilcClient client,
				 SilcClientConnection conn,
				 SilcStatus status,
				 SilcDList clients,
				 void *context)
{
	char tmp[256];

	if (!clients) {
		g_snprintf(tmp, sizeof(tmp),
			   _("User %s is not present in the network"),
			   (const char *)context);
		purple_notify_error(client->application, _("Get Public Key"),
				    _("Cannot fetch the public key"), tmp);
		g_free(context);
		return;
	}

	silcpurple_buddy_getkey(client->application, context);
	g_free(context);
}

static void
silcpurple_buddy_getkey(PurpleConnection *gc, const char *name)
{
	SilcPurple sg = gc->proto_data;
	SilcClient client = sg->client;
	SilcClientConnection conn = sg->conn;
	SilcClientEntry client_entry;
	SilcDList clients;
	SilcPurpleBuddyGetkey g;
	SilcUInt16 cmd_ident;

	if (!name)
		return;

	/* Find client entry */
	clients = silc_client_get_clients_local(client, conn, name, FALSE);
	if (!clients) {
		silc_client_get_clients(client, conn, name, NULL,
					silcpurple_buddy_getkey_resolved,
					g_strdup(name));
		return;
	}

	silc_dlist_start(clients);
	client_entry = silc_dlist_get(clients);

	/* Call GETKEY */
	g = silc_calloc(1, sizeof(*g));
	if (!g)
		return;
	g->client = client;
	g->conn = conn;
	g->client_id = client_entry->id;
	cmd_ident = silc_client_command_call(client, conn, NULL, "GETKEY",
					     client_entry->nickname, NULL);
	silc_client_command_pending(conn, SILC_COMMAND_GETKEY, cmd_ident,
				    silcpurple_buddy_getkey_cb, g);
	silc_client_list_free(client, conn, clients);
}

static void
silcpurple_buddy_getkey_menu(PurpleBlistNode *node, gpointer data)
{
	PurpleBuddy *buddy;
	PurpleConnection *gc;

	g_return_if_fail(PURPLE_BLIST_NODE_IS_BUDDY(node));

	buddy = (PurpleBuddy *) node;
	gc = purple_account_get_connection(purple_buddy_get_account(buddy));

	silcpurple_buddy_getkey(gc, purple_buddy_get_name(buddy));
}

static void
silcpurple_buddy_showkey(PurpleBlistNode *node, gpointer data)
{
	PurpleBuddy *b;
	PurpleConnection *gc;
	SilcPurple sg;
	SilcPublicKey public_key;
	const char *pkfile;

	g_return_if_fail(PURPLE_BLIST_NODE_IS_BUDDY(node));

	b = (PurpleBuddy *) node;
	gc = purple_account_get_connection(purple_buddy_get_account(b));
	sg = gc->proto_data;

	pkfile = purple_blist_node_get_string(node, "public-key");
	if (!silc_pkcs_load_public_key(pkfile, &public_key)) {
		purple_notify_error(gc,
				  _("Show Public Key"),
				  _("Could not load public key"), NULL);
		return;
	}

	silcpurple_show_public_key(sg, purple_buddy_get_name(b), public_key, NULL, NULL);
	silc_pkcs_public_key_free(public_key);
}


/**************************** Buddy routines *********************************/

/* The buddies are implemented by using the WHOIS and WATCH commands that
   can be used to search users by their public key.  Since nicknames aren't
   unique in SILC we cannot trust the buddy list using their nickname.  We
   associate public keys to buddies and use those to search and watch
   in the network.

   The problem is that Purple does not return PurpleBuddy contexts to the
   callbacks but the buddy names.  Naturally, this is not going to work
   with SILC.  But, for now, we have to do what we can... */

typedef struct {
	SilcClient client;
	SilcClientConnection conn;
	SilcClientID client_id;
	PurpleBuddy *b;
	unsigned char *offline_pk;
	SilcUInt32 offline_pk_len;
	SilcPublicKey public_key;
	unsigned int offline        : 1;
	unsigned int pubkey_search  : 1;
	unsigned int init           : 1;
} *SilcPurpleBuddyRes;

static void
silcpurple_add_buddy_ask_pk_cb(SilcPurpleBuddyRes r, gint id);
static void
silcpurple_add_buddy_resolved(SilcClient client,
			      SilcClientConnection conn,
			      SilcStatus status,
			      SilcDList clients,
			      void *context);

void silcpurple_get_info(PurpleConnection *gc, const char *who)
{
	SilcPurple sg = gc->proto_data;
	SilcClient client = sg->client;
	SilcClientConnection conn = sg->conn;
	SilcClientEntry client_entry;
	PurpleBuddy *b;
	const char *filename, *nick = who;
	char tmp[256];

	if (!who)
		return;
	if (strlen(who) > 1 && who[0] == '@')
		nick = who + 1;
	if (strlen(who) > 1 && who[0] == '*')
		nick = who + 1;
	if (strlen(who) > 2 && who[0] == '*' && who[1] == '@')
		nick = who + 2;

	b = purple_find_buddy(gc->account, nick);
	if (b) {
		/* See if we have this buddy's public key.  If we do use that
		   to search the details. */
		gpointer proto_data;
		filename = purple_blist_node_get_string((PurpleBlistNode *)b, "public-key");
		if (filename) {
			/* Call WHOIS.  The user info is displayed in the WHOIS
			   command reply. */
			silc_client_command_call(client, conn, NULL, "WHOIS",
						 "-details", "-pubkey", filename, NULL);
			return;
		}

		if (!(proto_data = purple_buddy_get_protocol_data(b))) {
			g_snprintf(tmp, sizeof(tmp),
				   _("User %s is not present in the network"), purple_buddy_get_name(b));
			purple_notify_error(gc, _("User Information"),
					  _("Cannot get user information"), tmp);
			return;
		}

		client_entry = silc_client_get_client_by_id(client, conn, proto_data);
		if (client_entry) {
			/* Call WHOIS.  The user info is displayed in the WHOIS
			   command reply. */
			silc_client_command_call(client, conn, NULL, "WHOIS",
						 client_entry->nickname, "-details", NULL);
		}
	} else {
		/* Call WHOIS just with nickname. */
		silc_client_command_call(client, conn, NULL, "WHOIS", nick, NULL);
	}
}

static void
silcpurple_add_buddy_pk_no(SilcPurpleBuddyRes r)
{
	char tmp[512];
	g_snprintf(tmp, sizeof(tmp), _("The %s buddy is not trusted"),
		   purple_buddy_get_name(r->b));
	purple_notify_error(r->client->application, _("Add Buddy"), tmp,
			    _("You cannot receive buddy notifications until you "
			      "import his/her public key.  You can use the Get Public Key "
			      "command to get the public key."));
	purple_prpl_got_user_status(purple_buddy_get_account(r->b), purple_buddy_get_name(r->b), SILCPURPLE_STATUS_ID_OFFLINE, NULL);
}

static void
silcpurple_add_buddy_save(SilcBool success, void *context)
{
	SilcPurpleBuddyRes r = context;
	PurpleBuddy *b = r->b;
	SilcClientEntry client_entry;
	SilcAttributePayload attr;
	SilcAttribute attribute;
	SilcVCardStruct vcard;
	SilcMime message = NULL, extension = NULL;
	SilcMime usericon = NULL;
	SilcAttributeObjPk serverpk, usersign, serversign;
	gboolean usign_success = TRUE, ssign_success = TRUE;
	char filename[512], filename2[512], *fingerprint = NULL, *tmp;
	SilcUInt32 len;
	SilcHash hash;
	int i;

	if (!success) {
		/* The user did not trust the public key. */
		silcpurple_add_buddy_pk_no(r);
		silc_free(r->offline_pk);
		if (r->public_key)
		  silc_pkcs_public_key_free(r->public_key);
		silc_free(r);
		return;
	}

	if (r->offline) {
		/* User is offline.  Associate the imported public key with
		   this user. */
		fingerprint = silc_hash_fingerprint(NULL, r->offline_pk,
						    r->offline_pk_len);
		for (i = 0; i < strlen(fingerprint); i++)
			if (fingerprint[i] == ' ')
				fingerprint[i] = '_';
		g_snprintf(filename, sizeof(filename) - 1,
			   "%s" G_DIR_SEPARATOR_S "clientkeys" G_DIR_SEPARATOR_S "clientkey_%s.pub",
			   silcpurple_silcdir(), fingerprint);
		purple_blist_node_set_string((PurpleBlistNode *)b, "public-key", filename);
		purple_prpl_got_user_status(purple_buddy_get_account(r->b), purple_buddy_get_name(r->b), SILCPURPLE_STATUS_ID_OFFLINE, NULL);
		silc_free(fingerprint);
		silc_free(r->offline_pk);
		if (r->public_key)
		  silc_pkcs_public_key_free(r->public_key);
		silc_free(r);
		return;
	}

	/* Get the client entry. */
	client_entry = silc_client_get_client_by_id(r->client, r->conn,
						    &r->client_id);
	if (!client_entry) {
		silc_free(r->offline_pk);
		silc_pkcs_public_key_free(r->public_key);
		if (r->public_key)
		  silc_pkcs_public_key_free(r->public_key);
		silc_free(r);
		return;
	}

	memset(&vcard, 0, sizeof(vcard));
	memset(&serverpk, 0, sizeof(serverpk));
	memset(&usersign, 0, sizeof(usersign));
	memset(&serversign, 0, sizeof(serversign));

	/* Now that we have the public key and we trust it now we
	   save the attributes of the buddy and update its status. */

	if (client_entry->attrs) {
		silc_dlist_start(client_entry->attrs);
		while ((attr = silc_dlist_get(client_entry->attrs))
		       != SILC_LIST_END) {
			attribute = silc_attribute_get_attribute(attr);

			switch (attribute) {
			case SILC_ATTRIBUTE_USER_INFO:
				if (!silc_attribute_get_object(attr, (void *)&vcard,
							       sizeof(vcard)))
					continue;
				break;

			case SILC_ATTRIBUTE_STATUS_MESSAGE:
				message = silc_mime_alloc();
				if (!silc_attribute_get_object(attr, (void *)message,
							       sizeof(*message)))
					continue;
				break;

			case SILC_ATTRIBUTE_EXTENSION:
				extension = silc_mime_alloc();
				if (!silc_attribute_get_object(attr, (void *)extension,
							       sizeof(*extension)))
					continue;
				break;

			case SILC_ATTRIBUTE_USER_ICON:
				usericon = silc_mime_alloc();
				if (!silc_attribute_get_object(attr, (void *)usericon,
							       sizeof(*usericon)))
					continue;
				break;

			case SILC_ATTRIBUTE_SERVER_PUBLIC_KEY:
				if (serverpk.type)
					continue;
				if (!silc_attribute_get_object(attr, (void *)&serverpk,
							       sizeof(serverpk)))
					continue;
				break;

			case SILC_ATTRIBUTE_USER_DIGITAL_SIGNATURE:
				if (usersign.data)
					continue;
				if (!silc_attribute_get_object(attr, (void *)&usersign,
							       sizeof(usersign)))
					continue;
				break;

			case SILC_ATTRIBUTE_SERVER_DIGITAL_SIGNATURE:
				if (serversign.data)
					continue;
				if (!silc_attribute_get_object(attr, (void *)&serversign,
							       sizeof(serversign)))
					continue;
				break;

			default:
				break;
			}
		}
	}

	/* Verify the attribute signatures */
	silc_hash_alloc((const unsigned char *)"sha1", &hash);

	if (usersign.data) {
		unsigned char *verifyd;
		SilcUInt32 verify_len;

		verifyd = silc_attribute_get_verify_data(client_entry->attrs,
							 FALSE, &verify_len);
		if (verifyd && !silc_pkcs_verify(client_entry->public_key,
						 usersign.data,
						 usersign.data_len,
						 verifyd, verify_len, hash))
			usign_success = FALSE;
		silc_free(verifyd);
	}

	if (serversign.data) {
		SilcPublicKey public_key;
		SilcPKCSType type = 0;
		unsigned char *verifyd;
		SilcUInt32 verify_len;

		if (!strcmp(serverpk.type, "silc-rsa"))
		  type = SILC_PKCS_SILC;
		else if (!strcmp(serverpk.type, "ssh-rsa"))
		  type = SILC_PKCS_SSH2;
		else if (!strcmp(serverpk.type, "x509v3-sign-rsa"))
		  type = SILC_PKCS_X509V3;
		else if (!strcmp(serverpk.type, "pgp-sign-rsa"))
		  type = SILC_PKCS_OPENPGP;

		if (silc_pkcs_public_key_alloc(type, serverpk.data,
					       serverpk.data_len,
					       &public_key)) {
			verifyd = silc_attribute_get_verify_data(client_entry->attrs,
								 TRUE, &verify_len);
			if (verifyd && !silc_pkcs_verify(public_key,
							 serversign.data,
							 serversign.data_len,
							 verifyd, verify_len,
							 hash))
				ssign_success = FALSE;
			silc_pkcs_public_key_free(public_key);
			silc_free(verifyd);
		}
	}

	fingerprint = silc_fingerprint(client_entry->fingerprint, 20);
	for (i = 0; i < strlen(fingerprint); i++)
		if (fingerprint[i] == ' ')
			fingerprint[i] = '_';

	if (usign_success || ssign_success) {
		struct passwd *pw;
		struct stat st;

		memset(filename2, 0, sizeof(filename2));

		/* Filename for dir */
		tmp = fingerprint + strlen(fingerprint) - 9;
		g_snprintf(filename, sizeof(filename) - 1,
			   "%s" G_DIR_SEPARATOR_S "friends" G_DIR_SEPARATOR_S "%s",
			   silcpurple_silcdir(), tmp);

		pw = getpwuid(getuid());
		if (!pw)
			return;

		/* Create dir if it doesn't exist */
		if ((g_stat(filename, &st)) == -1) {
			if (errno == ENOENT) {
				if (pw->pw_uid == geteuid()) {
					int ret = g_mkdir(filename, 0755);
					if (ret < 0)
						return;
					}
			}
		}

		/* Save VCard */
		g_snprintf(filename2, sizeof(filename2) - 1,
			   "%s" G_DIR_SEPARATOR_S "vcard", filename);
		if (vcard.full_name) {
			tmp = (char *)silc_vcard_encode(&vcard, &len);
			silc_file_writefile(filename2, tmp, len);
			silc_free(tmp);
		}

		/* Save status message */
		if (message) {
			memset(filename2, 0, sizeof(filename2));
			g_snprintf(filename2, sizeof(filename2) - 1,
				   "%s" G_DIR_SEPARATOR_S "status_message.mime",
				   filename);
			tmp = (char *)silc_mime_get_data(message, &len);
			silc_file_writefile(filename2, tmp, len);
			silc_mime_free(message);
		}

		/* Save extension data */
		if (extension) {
			memset(filename2, 0, sizeof(filename2));
			g_snprintf(filename2, sizeof(filename2) - 1,
				   "%s" G_DIR_SEPARATOR_S "extension.mime",
				   filename);
			tmp = (char *)silc_mime_get_data(extension, &len);
			silc_file_writefile(filename2, tmp, len);
			silc_mime_free(extension);
		}

		/* Save user icon */
		if (usericon) {
			const char *type = silc_mime_get_field(usericon, "Content-Type");
			if (type &&
			    (!strcmp(type, "image/jpeg") ||
			     !strcmp(type, "image/gif") ||
			     !strcmp(type, "image/bmp") ||
			     !strcmp(type, "image/png"))) {
				const unsigned char *data;
				SilcUInt32 data_len;
				data = silc_mime_get_data(usericon, &data_len);
				if (data) {
					/* TODO: Check if SILC gives us something to use as the checksum instead */
					purple_buddy_icons_set_for_user(purple_buddy_get_account(r->b), purple_buddy_get_name(r->b), g_memdup(data, data_len), data_len, NULL);
				}
			}
			silc_mime_free(usericon);
		}
	}

	/* Save the public key path to buddy properties, as it is used
	   to identify the buddy in the network (and not the nickname). */
	memset(filename, 0, sizeof(filename));
	g_snprintf(filename, sizeof(filename) - 1,
		   "%s" G_DIR_SEPARATOR_S "clientkeys" G_DIR_SEPARATOR_S "clientkey_%s.pub",
		   silcpurple_silcdir(), fingerprint);
	purple_blist_node_set_string((PurpleBlistNode *)b, "public-key", filename);

	/* Update online status */
	purple_prpl_got_user_status(purple_buddy_get_account(r->b), purple_buddy_get_name(r->b), SILCPURPLE_STATUS_ID_AVAILABLE, NULL);

	/* Finally, start watching this user so we receive its status
	   changes from the server */
	g_snprintf(filename2, sizeof(filename2) - 1, "+%s", filename);
	silc_client_command_call(r->client, r->conn, NULL, "WATCH", "-pubkey",
				 filename2, NULL);

	silc_hash_free(hash);
	silc_free(fingerprint);
	silc_free(r->offline_pk);
	if (r->public_key)
	  silc_pkcs_public_key_free(r->public_key);
	silc_free(r);
}

static void
silcpurple_add_buddy_ask_import(void *user_data, const char *name)
{
	SilcPurpleBuddyRes r = (SilcPurpleBuddyRes)user_data;

	/* Load the public key */
	if (!silc_pkcs_load_public_key(name, &r->public_key)) {
		silcpurple_add_buddy_ask_pk_cb(r, 0);
		purple_notify_error(r->client->application,
				  _("Add Buddy"), _("Could not load public key"), NULL);
		return;
	}

	/* Now verify the public key */
	r->offline_pk = silc_pkcs_public_key_encode(r->public_key, &r->offline_pk_len);
	silcpurple_verify_public_key(r->client, r->conn, purple_buddy_get_name(r->b),
				     SILC_CONN_CLIENT, r->public_key,
				     silcpurple_add_buddy_save, r);
}

static void
silcpurple_add_buddy_ask_pk_cancel(void *user_data, const char *name)
{
	SilcPurpleBuddyRes r = (SilcPurpleBuddyRes)user_data;

	/* The user did not import public key.  The buddy is unusable. */
	silcpurple_add_buddy_pk_no(r);
	silc_free(r);
}

static void
silcpurple_add_buddy_ask_pk_cb(SilcPurpleBuddyRes r, gint id)
{
	if (id != 0) {
		/* The user did not import public key.  The buddy is unusable. */
		silcpurple_add_buddy_pk_no(r);
		silc_free(r);
		return;
	}

	/* Open file selector to select the public key. */
	purple_request_file(r->client->application, _("Open..."), NULL, FALSE,
			    G_CALLBACK(silcpurple_add_buddy_ask_import),
			    G_CALLBACK(silcpurple_add_buddy_ask_pk_cancel),
			    purple_buddy_get_account(r->b), purple_buddy_get_name(r->b), NULL, r);

}

static void
silcpurple_add_buddy_ask_pk(SilcPurpleBuddyRes r)
{
	char tmp[512];
	g_snprintf(tmp, sizeof(tmp), _("The %s buddy is not present in the network"),
		   purple_buddy_get_name(r->b));
	purple_request_action(r->client->application, _("Add Buddy"), tmp,
			      _("To add the buddy you must import his/her public key. "
				"Press Import to import a public key."), 0,
			      purple_buddy_get_account(r->b), purple_buddy_get_name(r->b), NULL, r, 2,
			      _("Cancel"), G_CALLBACK(silcpurple_add_buddy_ask_pk_cb),
			      _("_Import..."), G_CALLBACK(silcpurple_add_buddy_ask_pk_cb));
}

static SilcBool
silcpurple_add_buddy_getkey_cb(SilcClient client, SilcClientConnection conn,
			       SilcCommand command, SilcStatus status,
			       SilcStatus error, void *context, va_list ap)
{
	SilcPurpleBuddyRes r = context;
	SilcClientEntry client_entry;

	if (status != SILC_STATUS_OK) {
		/* The buddy is offline/nonexistent. We will require user
		   to associate a public key with the buddy or the buddy
		   cannot be added. */
		r->offline = TRUE;
		silcpurple_add_buddy_ask_pk(r);
		return FALSE;
	}

	/* Get the client entry. */
	client_entry = silc_client_get_client_by_id(r->client, r->conn,
						    &r->client_id);
	if (!client_entry || !client_entry->public_key) {
		/* The buddy is offline/nonexistent. We will require user
		   to associate a public key with the buddy or the buddy
		   cannot be added. */
		r->offline = TRUE;
		silcpurple_add_buddy_ask_pk(r);
		return FALSE;
	}

	/* Now verify the public key */
	silcpurple_verify_public_key(r->client, r->conn, client_entry->nickname,
				     SILC_CONN_CLIENT, client_entry->public_key,
				     silcpurple_add_buddy_save, r);
	return TRUE;
}

static void
silcpurple_add_buddy_select_cb(SilcPurpleBuddyRes r, PurpleRequestFields *fields)
{
	PurpleRequestField *f;
	GList *list;
	SilcClientEntry client_entry;
	SilcDList clients;

	f = purple_request_fields_get_field(fields, "list");
	list = purple_request_field_list_get_selected(f);
	if (!list) {
		/* The user did not select any user. */
		silcpurple_add_buddy_pk_no(r);
		silc_free(r);
		return;
	}

	client_entry = purple_request_field_list_get_data(f, list->data);
	clients = silc_dlist_init();
	silc_dlist_add(clients, client_entry);
	silcpurple_add_buddy_resolved(r->client, r->conn, SILC_STATUS_OK,
				      clients, r);
	silc_dlist_uninit(clients);
}

static void
silcpurple_add_buddy_select_cancel(SilcPurpleBuddyRes r, PurpleRequestFields *fields)
{
	/* The user did not select any user. */
	silcpurple_add_buddy_pk_no(r);
	silc_free(r);
}

static void
silcpurple_add_buddy_select(SilcPurpleBuddyRes r, SilcDList clients)
{
	PurpleRequestFields *fields;
	PurpleRequestFieldGroup *g;
	PurpleRequestField *f;
	char tmp[512], tmp2[128];
	char *fingerprint;
	SilcClientEntry client_entry;

	fields = purple_request_fields_new();
	g = purple_request_field_group_new(NULL);
	f = purple_request_field_list_new("list", NULL);
	purple_request_field_group_add_field(g, f);
	purple_request_field_list_set_multi_select(f, FALSE);
	purple_request_fields_add_group(fields, g);

	silc_dlist_start(clients);
	while ((client_entry = silc_dlist_get(clients))) {
		fingerprint = NULL;
		if (*client_entry->fingerprint) {
			fingerprint = silc_fingerprint(client_entry->fingerprint, 20);
			g_snprintf(tmp2, sizeof(tmp2), "\n%s", fingerprint);
		}
		g_snprintf(tmp, sizeof(tmp), "%s - %s (%s@%s)%s",
			   client_entry->realname, client_entry->nickname,
			   client_entry->username, *client_entry->hostname ?
			   client_entry->hostname : "",
			   fingerprint ? tmp2 : "");
		purple_request_field_list_add_icon(f, tmp, NULL, client_entry);
		silc_free(fingerprint);
	}

	purple_request_fields(r->client->application, _("Add Buddy"),
			      _("Select correct user"),
			      r->pubkey_search
			      ? _("More than one user was found with the same public key. Select "
				  "the correct user from the list to add to the buddy list.")
			      : _("More than one user was found with the same name. Select "
				  "the correct user from the list to add to the buddy list."),
			      fields,
			      _("OK"), G_CALLBACK(silcpurple_add_buddy_select_cb),
			      _("Cancel"), G_CALLBACK(silcpurple_add_buddy_select_cancel),
			      purple_buddy_get_account(r->b), purple_buddy_get_name(r->b), NULL, r);
}

static void
silcpurple_add_buddy_resolved(SilcClient client,
			      SilcClientConnection conn,
			      SilcStatus status,
			      SilcDList clients,
			      void *context)
{
	SilcPurpleBuddyRes r = context;
	PurpleBuddy *b = r->b;
	SilcAttributePayload pub;
	SilcAttributeObjPk userpk;
	const char *filename;
	SilcClientEntry client_entry = NULL;
	SilcUInt16 cmd_ident;
	const char *name;

	filename = purple_blist_node_get_string((PurpleBlistNode *)b, "public-key");

	/* If the buddy is offline/nonexistent, we will require user
	   to associate a public key with the buddy or the buddy
	   cannot be added. */
	if (!clients) {
		if (r->init) {
			silc_free(r);
			return;
		}

		r->offline = TRUE;
		/* If the user has already associated a public key, try loading it
		 * before prompting the user to load it again */
		if (filename != NULL)
			silcpurple_add_buddy_ask_import(r, filename);
		else
			silcpurple_add_buddy_ask_pk(r);
		return;
	}

	/* If more than one client was found with nickname, we need to verify
	   from user which one is the correct. */
	if (silc_dlist_count(clients) > 1 && !r->pubkey_search) {
		if (r->init) {
			silc_free(r);
			return;
		}

		silcpurple_add_buddy_select(r, clients);
		return;
	}

	silc_dlist_start(clients);
	client_entry = silc_dlist_get(clients);

	name = purple_buddy_get_name(b);

	/* If we searched using public keys and more than one entry was found
	   the same person is logged on multiple times. */
	if (silc_dlist_count(clients) > 1 && r->pubkey_search && name) {
		if (r->init) {
			/* Find the entry that closest matches to the
			   buddy nickname. */
			SilcClientEntry entry;
			silc_dlist_start(clients);
			while ((entry = silc_dlist_get(clients))) {
				if (!g_ascii_strncasecmp(name, entry->nickname,
						 strlen(name))) {
					client_entry = entry;
					break;
				}
			}
		} else {
			/* Verify from user which one is correct */
			silcpurple_add_buddy_select(r, clients);
			return;
		}
	}

	/* The client was found.  Now get its public key and verify
	   that before adding the buddy. */
	memset(&userpk, 0, sizeof(userpk));
	purple_buddy_set_protocol_data(b, silc_memdup(&client_entry->id, sizeof(client_entry->id)));
	r->client_id = client_entry->id;

	/* Get the public key from attributes, if not present then
	   resolve it with GETKEY unless we have it cached already. */
	if (client_entry->attrs && !client_entry->public_key) {
		pub = silcpurple_get_attr(client_entry->attrs,
					  SILC_ATTRIBUTE_USER_PUBLIC_KEY);
		if (!pub || !silc_attribute_get_object(pub, (void *)&userpk,
						       sizeof(userpk))) {
			/* Get public key with GETKEY */
			cmd_ident =
			  silc_client_command_call(client, conn, NULL,
						   "GETKEY", client_entry->nickname, NULL);
			silc_client_command_pending(conn, SILC_COMMAND_GETKEY,
						    cmd_ident,
						    silcpurple_add_buddy_getkey_cb,
						    r);
			return;
		}
		if (!silc_pkcs_public_key_alloc(SILC_PKCS_SILC,
						userpk.data, userpk.data_len,
						&client_entry->public_key))
			return;
		silc_free(userpk.data);
	} else if (filename && !client_entry->public_key) {
		if (!silc_pkcs_load_public_key(filename, &client_entry->public_key)) {
			/* Get public key with GETKEY */
			cmd_ident =
			  silc_client_command_call(client, conn, NULL,
						   "GETKEY", client_entry->nickname, NULL);
			silc_client_command_pending(conn, SILC_COMMAND_GETKEY,
						    cmd_ident,
						    silcpurple_add_buddy_getkey_cb,
						    r);
			return;
		}
	} else if (!client_entry->public_key) {
		/* Get public key with GETKEY */
		cmd_ident =
		  silc_client_command_call(client, conn, NULL,
					   "GETKEY", client_entry->nickname, NULL);
		silc_client_command_pending(conn, SILC_COMMAND_GETKEY,
					    cmd_ident,
					    silcpurple_add_buddy_getkey_cb,
					    r);
		return;
	}

	/* We have the public key, verify it. */
	silcpurple_verify_public_key(client, conn, client_entry->nickname,
				     SILC_CONN_CLIENT,
				     client_entry->public_key,
				     silcpurple_add_buddy_save, r);
}

static void
silcpurple_add_buddy_i(PurpleConnection *gc, PurpleBuddy *b, gboolean init)
{
	SilcPurple sg = gc->proto_data;
	SilcClient client = sg->client;
	SilcClientConnection conn = sg->conn;
	SilcPurpleBuddyRes r;
	SilcBuffer attrs;
	const char *filename, *name = purple_buddy_get_name(b);

	r = silc_calloc(1, sizeof(*r));
	if (!r)
		return;
	r->client = client;
	r->conn = conn;
	r->b = b;
	r->init = init;

	/* See if we have this buddy's public key.  If we do use that
	   to search the details. */
	filename = purple_blist_node_get_string((PurpleBlistNode *)b, "public-key");
	if (filename) {
		SilcPublicKey public_key;
		SilcAttributeObjPk userpk;

		if (!silc_pkcs_load_public_key(filename, &public_key))
			return;

		/* Get all attributes, and use the public key to search user */
		name = NULL;
		attrs = silc_client_attributes_request(SILC_ATTRIBUTE_USER_INFO,
						       SILC_ATTRIBUTE_SERVICE,
						       SILC_ATTRIBUTE_STATUS_MOOD,
						       SILC_ATTRIBUTE_STATUS_FREETEXT,
						       SILC_ATTRIBUTE_STATUS_MESSAGE,
						       SILC_ATTRIBUTE_PREFERRED_LANGUAGE,
						       SILC_ATTRIBUTE_PREFERRED_CONTACT,
						       SILC_ATTRIBUTE_TIMEZONE,
						       SILC_ATTRIBUTE_GEOLOCATION,
						       SILC_ATTRIBUTE_USER_ICON,
						       SILC_ATTRIBUTE_DEVICE_INFO, 0);
		userpk.type = "silc-rsa";
		userpk.data = silc_pkcs_public_key_encode(public_key, &userpk.data_len);
		attrs = silc_attribute_payload_encode(attrs,
						      SILC_ATTRIBUTE_USER_PUBLIC_KEY,
						      SILC_ATTRIBUTE_FLAG_VALID,
						      &userpk, sizeof(userpk));
		silc_free(userpk.data);
		silc_pkcs_public_key_free(public_key);
		r->pubkey_search = TRUE;
	} else {
		/* Get all attributes */
		attrs = silc_client_attributes_request(0);
	}

	/* Resolve */
	silc_client_get_clients_whois(client, conn, name, NULL, attrs,
				      silcpurple_add_buddy_resolved, r);
	silc_buffer_free(attrs);
}

void silcpurple_add_buddy(PurpleConnection *gc, PurpleBuddy *buddy, PurpleGroup *group)
{
	/* Don't add if the buddy is already on the list.
	 *
	 * SILC doesn't have groups, so we also don't need to do anything
	 * for a move. */
	if (purple_buddy_get_protocol_data(buddy) == NULL)
		silcpurple_add_buddy_i(gc, buddy, FALSE);
}

void silcpurple_send_buddylist(PurpleConnection *gc)
{
	GSList *buddies;
	PurpleAccount *account;

	account = purple_connection_get_account(gc);

	for (buddies = purple_find_buddies(account, NULL); buddies;
			buddies = g_slist_delete_link(buddies, buddies))
	{
		PurpleBuddy *buddy = buddies->data;
		silcpurple_add_buddy_i(gc, buddy, TRUE);
	}
}

void silcpurple_remove_buddy(PurpleConnection *gc, PurpleBuddy *buddy,
			   PurpleGroup *group)
{
	silc_free(purple_buddy_get_protocol_data(buddy));
}

void silcpurple_idle_set(PurpleConnection *gc, int idle)

{
	SilcPurple sg;
	SilcClient client;
	SilcClientConnection conn;
	SilcAttributeObjService service;
	const char *server;
	int port;

	sg = gc->proto_data;
	if (sg == NULL)
		return;

	client = sg->client;
	if (client == NULL)
		return;

	conn = sg->conn;
	if (conn == NULL)
		return;

	server = purple_account_get_string(sg->account, "server",
					 "silc.silcnet.org");
	port = purple_account_get_int(sg->account, "port", 706),

	memset(&service, 0, sizeof(service));
	silc_client_attribute_del(client, conn,
				  SILC_ATTRIBUTE_SERVICE, NULL);
	service.port = port;
	g_snprintf(service.address, sizeof(service.address), "%s", server);
	service.idle = idle;
	silc_client_attribute_add(client, conn, SILC_ATTRIBUTE_SERVICE,
				  &service, sizeof(service));
}

char *silcpurple_status_text(PurpleBuddy *b)
{
	PurpleAccount *account = purple_buddy_get_account(b);
	PurpleConnection *gc = purple_account_get_connection(account);
	SilcPurple sg = gc->proto_data;
	SilcClient client = sg->client;
	SilcClientConnection conn = sg->conn;
	SilcClientID *client_id = purple_buddy_get_protocol_data(b);
	SilcClientEntry client_entry;
	SilcAttributePayload attr;
	SilcAttributeMood mood = 0;

	/* Get the client entry. */
	client_entry = silc_client_get_client_by_id(client, conn, client_id);
	if (!client_entry)
		return NULL;

	/* If user is online, we show the mood status, if available.
	   If user is offline or away that status is indicated. */

	if (client_entry->mode & SILC_UMODE_DETACHED)
		return g_strdup(_("Detached"));
	if (client_entry->mode & SILC_UMODE_GONE)
		return g_strdup(_("Away"));
	if (client_entry->mode & SILC_UMODE_INDISPOSED)
		return g_strdup(_("Indisposed"));
	if (client_entry->mode & SILC_UMODE_BUSY)
		return g_strdup(_("Busy"));
	if (client_entry->mode & SILC_UMODE_PAGE)
		return g_strdup(_("Wake Me Up"));
	if (client_entry->mode & SILC_UMODE_HYPER)
		return g_strdup(_("Hyper Active"));
	if (client_entry->mode & SILC_UMODE_ROBOT)
		return g_strdup(_("Robot"));

	attr = silcpurple_get_attr(client_entry->attrs, SILC_ATTRIBUTE_STATUS_MOOD);
	if (attr && silc_attribute_get_object(attr, &mood, sizeof(mood))) {
		/* The mood is a bit mask, so we could show multiple moods,
		   but let's show only one for now. */
		if (mood & SILC_ATTRIBUTE_MOOD_HAPPY)
			return g_strdup(_("Happy"));
		if (mood & SILC_ATTRIBUTE_MOOD_SAD)
			return g_strdup(_("Sad"));
		if (mood & SILC_ATTRIBUTE_MOOD_ANGRY)
			return g_strdup(_("Angry"));
		if (mood & SILC_ATTRIBUTE_MOOD_JEALOUS)
			return g_strdup(_("Jealous"));
		if (mood & SILC_ATTRIBUTE_MOOD_ASHAMED)
			return g_strdup(_("Ashamed"));
		if (mood & SILC_ATTRIBUTE_MOOD_INVINCIBLE)
			return g_strdup(_("Invincible"));
		if (mood & SILC_ATTRIBUTE_MOOD_INLOVE)
			return g_strdup(_("In Love"));
		if (mood & SILC_ATTRIBUTE_MOOD_SLEEPY)
			return g_strdup(_("Sleepy"));
		if (mood & SILC_ATTRIBUTE_MOOD_BORED)
			return g_strdup(_("Bored"));
		if (mood & SILC_ATTRIBUTE_MOOD_EXCITED)
			return g_strdup(_("Excited"));
		if (mood & SILC_ATTRIBUTE_MOOD_ANXIOUS)
			return g_strdup(_("Anxious"));
	}

	return NULL;
}

void silcpurple_tooltip_text(PurpleBuddy *b, PurpleNotifyUserInfo *user_info, gboolean full)
{
	PurpleAccount *account = purple_buddy_get_account(b);
	PurpleConnection *gc = purple_account_get_connection(account);
	SilcPurple sg = gc->proto_data;
	SilcClient client = sg->client;
	SilcClientConnection conn = sg->conn;
	SilcClientID *client_id = purple_buddy_get_protocol_data(b);
	SilcClientEntry client_entry;
	char *moodstr, *statusstr, *contactstr, *langstr, *devicestr, *tzstr, *geostr;
	char tmp[256];

	/* Get the client entry. */
	client_entry = silc_client_get_client_by_id(client, conn, client_id);
	if (!client_entry)
		return;

	purple_notify_user_info_add_pair(user_info, _("Nickname"),
					       client_entry->nickname);
	g_snprintf(tmp, sizeof(tmp), "%s@%s", client_entry->username, client_entry->hostname);
	purple_notify_user_info_add_pair(user_info, _("Username"), tmp);
	if (client_entry->mode) {
		memset(tmp, 0, sizeof(tmp));
		silcpurple_get_umode_string(client_entry->mode,
					  tmp, sizeof(tmp) - strlen(tmp));
		purple_notify_user_info_add_pair(user_info, _("User Modes"), tmp);
	}

	silcpurple_parse_attrs(client_entry->attrs, &moodstr, &statusstr, &contactstr, &langstr, &devicestr, &tzstr, &geostr);

	if (statusstr) {
		purple_notify_user_info_add_pair(user_info, _("Message"), statusstr);
		g_free(statusstr);
	}

	if (full) {
		if (moodstr) {
			purple_notify_user_info_add_pair(user_info, _("Mood"), moodstr);
			g_free(moodstr);
		}

		if (contactstr) {
			purple_notify_user_info_add_pair(user_info, _("Preferred Contact"), contactstr);
			g_free(contactstr);
		}

		if (langstr) {
			purple_notify_user_info_add_pair(user_info, _("Preferred Language"), langstr);
			g_free(langstr);
		}

		if (devicestr) {
			purple_notify_user_info_add_pair(user_info, _("Device"), devicestr);
			g_free(devicestr);
		}

		if (tzstr) {
			purple_notify_user_info_add_pair(user_info, _("Timezone"), tzstr);
			g_free(tzstr);
		}

		if (geostr) {
			purple_notify_user_info_add_pair(user_info, _("Geolocation"), geostr);
			g_free(geostr);
		}
	}
}

static void
silcpurple_buddy_kill(PurpleBlistNode *node, gpointer data)
{
	PurpleBuddy *b;
	PurpleConnection *gc;
	SilcPurple sg;

	g_return_if_fail(PURPLE_BLIST_NODE_IS_BUDDY(node));

	b = (PurpleBuddy *) node;
	gc = purple_account_get_connection(purple_buddy_get_account(b));
	sg = gc->proto_data;

	/* Call KILL */
	silc_client_command_call(sg->client, sg->conn, NULL, "KILL",
				 purple_buddy_get_name(b), "Killed by operator", NULL);
}

typedef struct {
	SilcPurple sg;
	SilcClientEntry client_entry;
} *SilcPurpleBuddyWb;

static void
silcpurple_buddy_wb(PurpleBlistNode *node, gpointer data)
{
	SilcPurpleBuddyWb wb = data;
	silcpurple_wb_init(wb->sg, wb->client_entry);
	silc_free(wb);
}

GList *silcpurple_buddy_menu(PurpleBuddy *buddy)
{
	PurpleAccount *account = purple_buddy_get_account(buddy);
	PurpleConnection *gc = purple_account_get_connection(account);
	SilcPurple sg = gc->proto_data;
	SilcClientConnection conn = sg->conn;
	const char *pkfile = NULL;
	SilcClientEntry client_entry = NULL;
	PurpleMenuAction *act;
	GList *m = NULL;
	SilcPurpleBuddyWb wb;

	pkfile = purple_blist_node_get_string((PurpleBlistNode *) buddy, "public-key");
	client_entry = silc_client_get_client_by_id(sg->client,
						    sg->conn,
						    purple_buddy_get_protocol_data(buddy));

	if (client_entry &&
	    silc_client_private_message_key_is_set(sg->client,
						   sg->conn, client_entry)) {
		act = purple_menu_action_new(_("Reset IM Key"),
		                           PURPLE_CALLBACK(silcpurple_buddy_resetkey),
		                           NULL, NULL);
		m = g_list_append(m, act);
	} else {
		act = purple_menu_action_new(_("IM with Key Exchange"),
		                           PURPLE_CALLBACK(silcpurple_buddy_keyagr),
		                           NULL, NULL);
		m = g_list_append(m, act);

		act = purple_menu_action_new(_("IM with Password"),
		                           PURPLE_CALLBACK(silcpurple_buddy_privkey_menu),
		                           NULL, NULL);
		m = g_list_append(m, act);
	}

	if (pkfile) {
		act = purple_menu_action_new(_("Show Public Key"),
		                           PURPLE_CALLBACK(silcpurple_buddy_showkey),
		                           NULL, NULL);
		m = g_list_append(m, act);

	} else {
		act = purple_menu_action_new(_("Get Public Key..."),
		                           PURPLE_CALLBACK(silcpurple_buddy_getkey_menu),
		                           NULL, NULL);
		m = g_list_append(m, act);
	}

	if (conn && conn->local_entry->mode & SILC_UMODE_ROUTER_OPERATOR) {
		act = purple_menu_action_new(_("Kill User"),
		                           PURPLE_CALLBACK(silcpurple_buddy_kill),
		                           NULL, NULL);
		m = g_list_append(m, act);
	}

	if (client_entry) {
		wb = silc_calloc(1, sizeof(*wb));
		wb->sg = sg;
		wb->client_entry = client_entry;
		act = purple_menu_action_new(_("Draw On Whiteboard"),
		                           PURPLE_CALLBACK(silcpurple_buddy_wb),
		                           (void *)wb, NULL);
		m = g_list_append(m, act);
	}
	return m;
}

void silcpurple_buddy_set_icon(PurpleConnection *gc, PurpleStoredImage *img)
{
	SilcPurple sg = gc->proto_data;
	SilcClient client = sg->client;
	SilcClientConnection conn = sg->conn;
	SilcMime mime;
	char type[32];
	const char *t;

	/* Remove */
	if (!img) {
		silc_client_attribute_del(client, conn,
					  SILC_ATTRIBUTE_USER_ICON, NULL);
		return;
	}

	/* Add */
	mime = silc_mime_alloc();
	if (!mime)
		return;

	t = purple_imgstore_get_extension(img);
	if (!t || !strcmp(t, "icon")) {
		silc_mime_free(mime);
		return;
	}
	if (!strcmp(t, "jpg"))
		t = "jpeg";
	g_snprintf(type, sizeof(type), "image/%s", t);
	silc_mime_add_field(mime, "Content-Type", type);
	silc_mime_add_data(mime, purple_imgstore_get_data(img), purple_imgstore_get_size(img));

	silc_client_attribute_add(client, conn,
				  SILC_ATTRIBUTE_USER_ICON, mime, sizeof(*mime));

	silc_mime_free(mime);
}
