/*

  silcpurple_buddy.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2004 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#include "silcincludes.h"
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
			       SilcClientEntry *clients,
			       SilcUInt32 clients_count,
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
		silc_free(r->nick);
		silc_free(r);
		return;
	}

	silcpurple_buddy_keyagr_do(gc, r->nick, FALSE);
	silc_free(r->nick);
	silc_free(r);
}

typedef struct {
	gboolean responder;
} *SilcPurpleKeyAgr;

static void
silcpurple_buddy_keyagr_cb(SilcClient client,
			 SilcClientConnection conn,
			 SilcClientEntry client_entry,
			 SilcKeyAgreementStatus status,
			 SilcSKEKeyMaterial *key,
			 void *context)
{
	PurpleConnection *gc = client->application;
	SilcPurple sg = gc->proto_data;
	SilcPurpleKeyAgr a = context;

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
								NULL, NULL, key, a->responder);
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

	silc_free(a);
}

static void
silcpurple_buddy_keyagr_do(PurpleConnection *gc, const char *name,
			 gboolean force_local)
{
	SilcPurple sg = gc->proto_data;
	SilcClientEntry *clients;
	SilcUInt32 clients_count;
	char *local_ip = NULL, *remote_ip = NULL;
	gboolean local = TRUE;
	char *nickname;
	SilcPurpleKeyAgr a;

	if (!sg->conn || !name)
		return;

	if (!silc_parse_userfqdn(name, &nickname, NULL))
		return;

	/* Find client entry */
	clients = silc_client_get_clients_local(sg->client, sg->conn, nickname, name,
						&clients_count);
	if (!clients) {
		/* Resolve unknown user */
		SilcPurpleResolve r = silc_calloc(1, sizeof(*r));
		if (!r)
			return;
		r->nick = g_strdup(name);
		r->gc = gc;
		silc_client_get_clients(sg->client, sg->conn, nickname, NULL,
					silcpurple_buddy_keyagr_resolved, r);
		silc_free(nickname);
		return;
	}

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

	if (silc_net_check_local_by_sock(sg->conn->sock->sock, NULL, &local_ip)) {
		/* Check if the IP is private */
		if (!force_local && silcpurple_ip_is_private(local_ip)) {
			local = FALSE;

			/* Local IP is private, resolve the remote server IP to see whether
			   we are talking to Internet or just on LAN. */
			if (silc_net_check_host_by_sock(sg->conn->sock->sock, NULL,
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

	a = silc_calloc(1, sizeof(*a));
	if (!a)
		return;
	a->responder = local;

	/* Send the key agreement request */
	silc_client_send_key_agreement(sg->client, sg->conn, clients[0],
				       local ? local_ip : NULL, NULL, 0, 60,
				       silcpurple_buddy_keyagr_cb, a);

	silc_free(local_ip);
	silc_free(remote_ip);
	silc_free(clients);
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
	SilcPurpleKeyAgr ai;
	SilcClientEntry client_entry;

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
		ai = silc_calloc(1, sizeof(*ai));
		if (!ai)
			goto out;
		ai->responder = FALSE;
		silc_client_perform_key_agreement(a->client, a->conn, client_entry,
						  a->hostname, a->port,
						  silcpurple_buddy_keyagr_cb, ai);
	} else {
		/* Send request.  Force us as the point of connection since requestor
		   did not provide the point of connection. */
		silcpurple_buddy_keyagr_do(a->client->application,
					 client_entry->nickname, TRUE);
	}

 out:
	silc_free(a->hostname);
	silc_free(a);
}

void silcpurple_buddy_keyagr_request(SilcClient client,
				   SilcClientConnection conn,
				   SilcClientEntry client_entry,
				   const char *hostname, SilcUInt16 port)
{
	char tmp[128], tmp2[128];
	SilcPurpleKeyAgrAsk a;
	PurpleConnection *gc = client->application;

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
	a->client_id = *client_entry->id;
	if (hostname)
		a->hostname = strdup(hostname);
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

	buddy = (PurpleBuddy *)node;
	silcpurple_buddy_keyagr_do(buddy->account->gc, buddy->name, FALSE);
}


/**************************** Static IM Key **********************************/

static void
silcpurple_buddy_resetkey(PurpleBlistNode *node, gpointer data)
{
	PurpleBuddy *b;
	PurpleConnection *gc;
        SilcPurple sg;
	char *nickname;
	SilcClientEntry *clients;
	SilcUInt32 clients_count;

	g_return_if_fail(PURPLE_BLIST_NODE_IS_BUDDY(node));

	b = (PurpleBuddy *) node;
	gc = purple_account_get_connection(b->account);
	sg = gc->proto_data;

	if (!silc_parse_userfqdn(b->name, &nickname, NULL))
		return;

	/* Find client entry */
	clients = silc_client_get_clients_local(sg->client, sg->conn,
						nickname, b->name,
						&clients_count);
	if (!clients) {
		silc_free(nickname);
		return;
	}

	clients[0]->prv_resp = FALSE;
	silc_client_del_private_message_key(sg->client, sg->conn,
					    clients[0]);
	silc_free(clients);
	silc_free(nickname);
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
					    strlen(passphrase), FALSE,
					    client_entry->prv_resp);
	if (!client_entry->prv_resp)
		silc_client_send_private_message_key_request(p->client,
							     p->conn,
							     client_entry);
        silc_free(p);
}

static void
silcpurple_buddy_privkey_resolved(SilcClient client,
				SilcClientConnection conn,
				SilcClientEntry *clients,
				SilcUInt32 clients_count,
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
	silc_free(context);
}

static void
silcpurple_buddy_privkey(PurpleConnection *gc, const char *name)
{
	SilcPurple sg = gc->proto_data;
	char *nickname;
	SilcPurplePrivkey p;
	SilcClientEntry *clients;
	SilcUInt32 clients_count;

	if (!name)
		return;
	if (!silc_parse_userfqdn(name, &nickname, NULL))
		return;

	/* Find client entry */
	clients = silc_client_get_clients_local(sg->client, sg->conn,
						nickname, name,
						&clients_count);
	if (!clients) {
		silc_client_get_clients(sg->client, sg->conn, nickname, NULL,
					silcpurple_buddy_privkey_resolved,
					g_strdup(name));
		silc_free(nickname);
		return;
	}

	p = silc_calloc(1, sizeof(*p));
	if (!p)
		return;
	p->client = sg->client;
	p->conn = sg->conn;
	p->client_id = *clients[0]->id;
	purple_request_input(gc, _("IM With Password"), NULL,
	                     _("Set IM Password"), NULL, FALSE, TRUE, NULL,
	                     _("OK"), G_CALLBACK(silcpurple_buddy_privkey_cb),
	                     _("Cancel"), G_CALLBACK(silcpurple_buddy_privkey_cb),
	                     gc->account, NULL, NULL, p);

	silc_free(clients);
	silc_free(nickname);
}

static void
silcpurple_buddy_privkey_menu(PurpleBlistNode *node, gpointer data)
{
	PurpleBuddy *buddy;
	PurpleConnection *gc;

	g_return_if_fail(PURPLE_BLIST_NODE_IS_BUDDY(node));

	buddy = (PurpleBuddy *) node;
	gc = purple_account_get_connection(buddy->account);

	silcpurple_buddy_privkey(gc, buddy->name);
}


/**************************** Get Public Key *********************************/

typedef struct {
	SilcClient client;
	SilcClientConnection conn;
	SilcClientID client_id;
} *SilcPurpleBuddyGetkey;

static void
silcpurple_buddy_getkey(PurpleConnection *gc, const char *name);

static void
silcpurple_buddy_getkey_cb(SilcPurpleBuddyGetkey g,
			 SilcClientCommandReplyContext cmd)
{
	SilcClientEntry client_entry;
	unsigned char *pk;
	SilcUInt32 pk_len;

	/* Get the client entry. */
	client_entry = silc_client_get_client_by_id(g->client, g->conn,
						    &g->client_id);
	if (!client_entry) {
		purple_notify_error(g->client->application, _("Get Public Key"),
				  _("The remote user is not present in the network any more"),
				  NULL);
		silc_free(g);
		return;
	}

	if (!client_entry->public_key) {
		silc_free(g);
		return;
	}

	/* Now verify the public key */
	pk = silc_pkcs_public_key_encode(client_entry->public_key, &pk_len);
	silcpurple_verify_public_key(g->client, g->conn, client_entry->nickname,
				   SILC_SOCKET_TYPE_CLIENT,
				   pk, pk_len, SILC_SKE_PK_TYPE_SILC,
				   NULL, NULL);
	silc_free(pk);
	silc_free(g);
}

static void
silcpurple_buddy_getkey_resolved(SilcClient client,
			       SilcClientConnection conn,
			       SilcClientEntry *clients,
			       SilcUInt32 clients_count,
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
	silc_free(context);
}

static void
silcpurple_buddy_getkey(PurpleConnection *gc, const char *name)
{
	SilcPurple sg = gc->proto_data;
	SilcClient client = sg->client;
	SilcClientConnection conn = sg->conn;
	SilcClientEntry *clients;
	SilcUInt32 clients_count;
	SilcPurpleBuddyGetkey g;
	char *nickname;

	if (!name)
		return;

	if (!silc_parse_userfqdn(name, &nickname, NULL))
		return;

	/* Find client entry */
	clients = silc_client_get_clients_local(client, conn, nickname, name,
						&clients_count);
	if (!clients) {
		silc_client_get_clients(client, conn, nickname, NULL,
					silcpurple_buddy_getkey_resolved,
					g_strdup(name));
		silc_free(nickname);
		return;
	}

	/* Call GETKEY */
	g = silc_calloc(1, sizeof(*g));
	if (!g)
		return;
	g->client = client;
	g->conn = conn;
	g->client_id = *clients[0]->id;
	silc_client_command_call(client, conn, NULL, "GETKEY",
				 clients[0]->nickname, NULL);
	silc_client_command_pending(conn, SILC_COMMAND_GETKEY,
				    conn->cmd_ident,
				    (SilcCommandCb)silcpurple_buddy_getkey_cb, g);
	silc_free(clients);
	silc_free(nickname);
}

static void
silcpurple_buddy_getkey_menu(PurpleBlistNode *node, gpointer data)
{
	PurpleBuddy *buddy;
	PurpleConnection *gc;

	g_return_if_fail(PURPLE_BLIST_NODE_IS_BUDDY(node));

	buddy = (PurpleBuddy *) node;
	gc = purple_account_get_connection(buddy->account);

	silcpurple_buddy_getkey(gc, buddy->name);
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
	gc = purple_account_get_connection(b->account);
	sg = gc->proto_data;

	pkfile = purple_blist_node_get_string(node, "public-key");
	if (!silc_pkcs_load_public_key(pkfile, &public_key, SILC_PKCS_FILE_PEM) &&
	    !silc_pkcs_load_public_key(pkfile, &public_key, SILC_PKCS_FILE_BIN)) {
		purple_notify_error(gc,
				  _("Show Public Key"),
				  _("Could not load public key"), NULL);
		return;
	}

	silcpurple_show_public_key(sg, b->name, public_key, NULL, NULL);
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
	unsigned int offline        : 1;
	unsigned int pubkey_search  : 1;
	unsigned int init           : 1;
} *SilcPurpleBuddyRes;

static void
silcpurple_add_buddy_ask_pk_cb(SilcPurpleBuddyRes r, gint id);
static void
silcpurple_add_buddy_resolved(SilcClient client,
			    SilcClientConnection conn,
			    SilcClientEntry *clients,
			    SilcUInt32 clients_count,
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
		filename = purple_blist_node_get_string((PurpleBlistNode *)b, "public-key");
		if (filename) {
			/* Call WHOIS.  The user info is displayed in the WHOIS
			   command reply. */
			silc_client_command_call(client, conn, NULL, "WHOIS",
						 "-details", "-pubkey", filename, NULL);
			return;
		}

		if (!b->proto_data) {
			g_snprintf(tmp, sizeof(tmp),
				   _("User %s is not present in the network"), b->name);
			purple_notify_error(gc, _("User Information"),
					  _("Cannot get user information"), tmp);
			return;
		}

		client_entry = silc_client_get_client_by_id(client, conn, b->proto_data);
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
		   r->b->name);
	purple_notify_error(r->client->application, _("Add Buddy"), tmp,
			  _("You cannot receive buddy notifications until you "
			    "import his/her public key.  You can use the Get Public Key "
			    "command to get the public key."));
	purple_prpl_got_user_status(purple_buddy_get_account(r->b), purple_buddy_get_name(r->b), SILCPURPLE_STATUS_ID_OFFLINE, NULL);
}

static void
silcpurple_add_buddy_save(bool success, void *context)
{
	SilcPurpleBuddyRes r = context;
	PurpleBuddy *b = r->b;
	SilcClient client = r->client;
	SilcClientEntry client_entry;
	SilcAttributePayload attr;
	SilcAttribute attribute;
	SilcVCardStruct vcard;
	SilcAttributeObjMime message, extension;
#ifdef SILC_ATTRIBUTE_USER_ICON
	SilcAttributeObjMime usericon;
#endif
	SilcAttributeObjPk serverpk, usersign, serversign;
	gboolean usign_success = TRUE, ssign_success = TRUE;
	char filename[512], filename2[512], *fingerprint = NULL, *tmp;
	SilcUInt32 len;
	int i;

	if (!success) {
		/* The user did not trust the public key. */
		silcpurple_add_buddy_pk_no(r);
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
		silc_free(r);
		return;
	}

	/* Get the client entry. */
	client_entry = silc_client_get_client_by_id(r->client, r->conn,
						    &r->client_id);
	if (!client_entry) {
		silc_free(r);
		return;
	}

	memset(&vcard, 0, sizeof(vcard));
	memset(&message, 0, sizeof(message));
	memset(&extension, 0, sizeof(extension));
#ifdef SILC_ATTRIBUTE_USER_ICON
	memset(&usericon, 0, sizeof(usericon));
#endif
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
				if (!silc_attribute_get_object(attr, (void *)&message,
							       sizeof(message)))
					continue;
				break;

			case SILC_ATTRIBUTE_EXTENSION:
				if (!silc_attribute_get_object(attr, (void *)&extension,
							       sizeof(extension)))
					continue;
				break;

#ifdef SILC_ATTRIBUTE_USER_ICON
			case SILC_ATTRIBUTE_USER_ICON:
				if (!silc_attribute_get_object(attr, (void *)&usericon,
							       sizeof(usericon)))
					continue;
				break;
#endif

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

	if (usersign.data) {
		SilcPKCS pkcs;
		unsigned char *verifyd;
		SilcUInt32 verify_len;

		silc_pkcs_alloc((unsigned char*)"rsa", &pkcs);
		verifyd = silc_attribute_get_verify_data(client_entry->attrs,
							 FALSE, &verify_len);
		if (verifyd && silc_pkcs_public_key_set(pkcs, client_entry->public_key)){
			if (!silc_pkcs_verify_with_hash(pkcs, client->sha1hash,
							usersign.data,
							usersign.data_len,
							verifyd, verify_len))
				usign_success = FALSE;
		}
		silc_free(verifyd);
	}

	if (serversign.data && !strcmp(serverpk.type, "silc-rsa")) {
		SilcPublicKey public_key;
		SilcPKCS pkcs;
		unsigned char *verifyd;
		SilcUInt32 verify_len;

		if (silc_pkcs_public_key_decode(serverpk.data, serverpk.data_len,
						&public_key)) {
			silc_pkcs_alloc((unsigned char *)"rsa", &pkcs);
			verifyd = silc_attribute_get_verify_data(client_entry->attrs,
								 TRUE, &verify_len);
			if (verifyd && silc_pkcs_public_key_set(pkcs, public_key)) {
				if (!silc_pkcs_verify_with_hash(pkcs, client->sha1hash,
							       serversign.data,
							       serversign.data_len,
							       verifyd, verify_len))
					ssign_success = FALSE;
			}
			silc_pkcs_public_key_free(public_key);
			silc_free(verifyd);
		}
	}

	fingerprint = silc_fingerprint(client_entry->fingerprint,
				       client_entry->fingerprint_len);
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
		if (message.mime) {
			memset(filename2, 0, sizeof(filename2));
			g_snprintf(filename2, sizeof(filename2) - 1,
				   "%s" G_DIR_SEPARATOR_S "status_message.mime",
				   filename);
			silc_file_writefile(filename2, (char *)message.mime,
					    message.mime_len);
		}

		/* Save extension data */
		if (extension.mime) {
			memset(filename2, 0, sizeof(filename2));
			g_snprintf(filename2, sizeof(filename2) - 1,
				   "%s" G_DIR_SEPARATOR_S "extension.mime",
				   filename);
			silc_file_writefile(filename2, (char *)extension.mime,
					    extension.mime_len);
		}

#ifdef SILC_ATTRIBUTE_USER_ICON
		/* Save user icon */
		if (usericon.mime) {
			SilcMime m = silc_mime_decode(usericon.mime,
						      usericon.mime_len);
			if (m) {
				const char *type = silc_mime_get_field(m, "Content-Type");
				if (!strcmp(type, "image/jpeg") ||
				    !strcmp(type, "image/gif") ||
				    !strcmp(type, "image/bmp") ||
				    !strcmp(type, "image/png")) {
					const unsigned char *data;
					SilcUInt32 data_len;
					data = silc_mime_get_data(m, &data_len);
					if (data) {
						/* TODO: Check if SILC gives us something to use as the checksum instead */
						purple_buddy_icons_set_for_user(purple_buddy_get_account(r->b), purple_buddy_get_name(r->b), g_memdup(data, data_len), data_len, NULL);
					}
				}
				silc_mime_free(m);
			}
		}
#endif
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

	silc_free(fingerprint);
	silc_free(r);
}

static void
silcpurple_add_buddy_ask_import(void *user_data, const char *name)
{
	SilcPurpleBuddyRes r = (SilcPurpleBuddyRes)user_data;
	SilcPublicKey public_key;

	/* Load the public key */
	if (!silc_pkcs_load_public_key(name, &public_key, SILC_PKCS_FILE_PEM) &&
	    !silc_pkcs_load_public_key(name, &public_key, SILC_PKCS_FILE_BIN)) {
		silcpurple_add_buddy_ask_pk_cb(r, 0);
		purple_notify_error(r->client->application,
				  _("Add Buddy"), _("Could not load public key"), NULL);
		return;
	}

	/* Now verify the public key */
	r->offline_pk = silc_pkcs_public_key_encode(public_key, &r->offline_pk_len);
	silcpurple_verify_public_key(r->client, r->conn, r->b->name,
				   SILC_SOCKET_TYPE_CLIENT,
				   r->offline_pk, r->offline_pk_len,
				   SILC_SKE_PK_TYPE_SILC,
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
		   r->b->name);
	purple_request_action(r->client->application, _("Add Buddy"), tmp,
			    _("To add the buddy you must import his/her public key. "
			      "Press Import to import a public key."), 0,
				  purple_buddy_get_account(r->b), purple_buddy_get_name(r->b), NULL, r, 2,
			    _("Cancel"), G_CALLBACK(silcpurple_add_buddy_ask_pk_cb),
			    _("_Import..."), G_CALLBACK(silcpurple_add_buddy_ask_pk_cb));
}

static void
silcpurple_add_buddy_getkey_cb(SilcPurpleBuddyRes r,
			     SilcClientCommandReplyContext cmd)
{
	SilcClientEntry client_entry;
	unsigned char *pk;
	SilcUInt32 pk_len;

	/* Get the client entry. */
	client_entry = silc_client_get_client_by_id(r->client, r->conn,
						    &r->client_id);
	if (!client_entry || !client_entry->public_key) {
		/* The buddy is offline/nonexistent. We will require user
		   to associate a public key with the buddy or the buddy
		   cannot be added. */
		r->offline = TRUE;
		silcpurple_add_buddy_ask_pk(r);
		return;
	}

	/* Now verify the public key */
	pk = silc_pkcs_public_key_encode(client_entry->public_key, &pk_len);
	silcpurple_verify_public_key(r->client, r->conn, client_entry->nickname,
				   SILC_SOCKET_TYPE_CLIENT,
				   pk, pk_len, SILC_SKE_PK_TYPE_SILC,
				   silcpurple_add_buddy_save, r);
	silc_free(pk);
}

static void
silcpurple_add_buddy_select_cb(SilcPurpleBuddyRes r, PurpleRequestFields *fields)
{
	PurpleRequestField *f;
	GList *list;
	SilcClientEntry client_entry;

	f = purple_request_fields_get_field(fields, "list");
	list = purple_request_field_list_get_selected(f);
	if (!list) {
		/* The user did not select any user. */
		silcpurple_add_buddy_pk_no(r);
		silc_free(r);
		return;
	}

	client_entry = purple_request_field_list_get_data(f, list->data);
	silcpurple_add_buddy_resolved(r->client, r->conn, &client_entry, 1, r);
}

static void
silcpurple_add_buddy_select_cancel(SilcPurpleBuddyRes r, PurpleRequestFields *fields)
{
	/* The user did not select any user. */
	silcpurple_add_buddy_pk_no(r);
	silc_free(r);
}

static void
silcpurple_add_buddy_select(SilcPurpleBuddyRes r,
			  SilcClientEntry *clients,
			  SilcUInt32 clients_count)
{
	PurpleRequestFields *fields;
	PurpleRequestFieldGroup *g;
	PurpleRequestField *f;
	char tmp[512], tmp2[128];
	int i;
	char *fingerprint;

	fields = purple_request_fields_new();
	g = purple_request_field_group_new(NULL);
	f = purple_request_field_list_new("list", NULL);
	purple_request_field_group_add_field(g, f);
	purple_request_field_list_set_multi_select(f, FALSE);
	purple_request_fields_add_group(fields, g);

	for (i = 0; i < clients_count; i++) {
		fingerprint = NULL;
		if (clients[i]->fingerprint) {
			fingerprint = silc_fingerprint(clients[i]->fingerprint,
						       clients[i]->fingerprint_len);
			g_snprintf(tmp2, sizeof(tmp2), "\n%s", fingerprint);
		}
		g_snprintf(tmp, sizeof(tmp), "%s - %s (%s@%s)%s",
			   clients[i]->realname, clients[i]->nickname,
			   clients[i]->username, clients[i]->hostname ?
			   clients[i]->hostname : "",
			   fingerprint ? tmp2 : "");
		purple_request_field_list_add_icon(f, tmp, NULL, clients[i]);
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
			    SilcClientEntry *clients,
			    SilcUInt32 clients_count,
			    void *context)
{
	SilcPurpleBuddyRes r = context;
	PurpleBuddy *b = r->b;
	SilcAttributePayload pub;
	SilcAttributeObjPk userpk;
	unsigned char *pk;
	SilcUInt32 pk_len;
	const char *filename;

	filename = purple_blist_node_get_string((PurpleBlistNode *)b, "public-key");

	/* If the buddy is offline/nonexistent, we will require user
	   to associate a public key with the buddy or the buddy
	   cannot be added. */
	if (!clients_count) {
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
	if (clients_count > 1 && !r->pubkey_search) {
		if (r->init) {
			silc_free(r);
			return;
		}

		silcpurple_add_buddy_select(r, clients, clients_count);
		return;
	}

	/* If we searched using public keys and more than one entry was found
	   the same person is logged on multiple times. */
	if (clients_count > 1 && r->pubkey_search && b->name) {
		if (r->init) {
			/* Find the entry that closest matches to the
			   buddy nickname. */
			int i;
			for (i = 0; i < clients_count; i++) {
				if (!g_ascii_strncasecmp(b->name, clients[i]->nickname,
						 strlen(b->name))) {
					clients[0] = clients[i];
					break;
				}
			}
		} else {
			/* Verify from user which one is correct */
			silcpurple_add_buddy_select(r, clients, clients_count);
			return;
		}
	}

	/* The client was found.  Now get its public key and verify
	   that before adding the buddy. */
	memset(&userpk, 0, sizeof(userpk));
	b->proto_data = silc_memdup(clients[0]->id, sizeof(*clients[0]->id));
	r->client_id = *clients[0]->id;

	/* Get the public key from attributes, if not present then
	   resolve it with GETKEY unless we have it cached already. */
	if (clients[0]->attrs && !clients[0]->public_key) {
		pub = silcpurple_get_attr(clients[0]->attrs,
					SILC_ATTRIBUTE_USER_PUBLIC_KEY);
		if (!pub || !silc_attribute_get_object(pub, (void *)&userpk,
						       sizeof(userpk))) {
			/* Get public key with GETKEY */
			silc_client_command_call(client, conn, NULL,
						 "GETKEY", clients[0]->nickname, NULL);
			silc_client_command_pending(conn, SILC_COMMAND_GETKEY,
						    conn->cmd_ident,
						    (SilcCommandCb)silcpurple_add_buddy_getkey_cb,
						    r);
			return;
		}
		if (!silc_pkcs_public_key_decode(userpk.data, userpk.data_len,
						 &clients[0]->public_key))
			return;
		silc_free(userpk.data);
	} else if (filename && !clients[0]->public_key) {
		if (!silc_pkcs_load_public_key(filename, &clients[0]->public_key,
					       SILC_PKCS_FILE_PEM) &&
		    !silc_pkcs_load_public_key(filename, &clients[0]->public_key,
					       SILC_PKCS_FILE_BIN)) {
			/* Get public key with GETKEY */
			silc_client_command_call(client, conn, NULL,
						 "GETKEY", clients[0]->nickname, NULL);
			silc_client_command_pending(conn, SILC_COMMAND_GETKEY,
						    conn->cmd_ident,
						    (SilcCommandCb)silcpurple_add_buddy_getkey_cb,
						    r);
			return;
		}
	} else if (!clients[0]->public_key) {
		/* Get public key with GETKEY */
		silc_client_command_call(client, conn, NULL,
					 "GETKEY", clients[0]->nickname, NULL);
		silc_client_command_pending(conn, SILC_COMMAND_GETKEY,
					    conn->cmd_ident,
					    (SilcCommandCb)silcpurple_add_buddy_getkey_cb,
					    r);
		return;
	}

	/* We have the public key, verify it. */
	pk = silc_pkcs_public_key_encode(clients[0]->public_key, &pk_len);
	silcpurple_verify_public_key(client, conn, clients[0]->nickname,
				   SILC_SOCKET_TYPE_CLIENT,
				   pk, pk_len, SILC_SKE_PK_TYPE_SILC,
				   silcpurple_add_buddy_save, r);
	silc_free(pk);
}

static void
silcpurple_add_buddy_i(PurpleConnection *gc, PurpleBuddy *b, gboolean init)
{
	SilcPurple sg = gc->proto_data;
	SilcClient client = sg->client;
	SilcClientConnection conn = sg->conn;
	SilcPurpleBuddyRes r;
	SilcBuffer attrs;
	const char *filename, *name = b->name;

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

		if (!silc_pkcs_load_public_key(filename, &public_key,
					       SILC_PKCS_FILE_PEM) &&
		    !silc_pkcs_load_public_key(filename, &public_key,
					       SILC_PKCS_FILE_BIN))
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
#ifdef SILC_ATTRIBUTE_USER_ICON
						       SILC_ATTRIBUTE_USER_ICON,
#endif
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
	 * SILC doesn't have groups, so we don't need to do anything
	 * for a move. */
	if (purple_buddy_get_protocol_data(buddy) == NULL)
		silcpurple_add_buddy_i(gc, buddy, FALSE);
}

void silcpurple_send_buddylist(PurpleConnection *gc)
{
	PurpleBuddyList *blist;
	PurpleBlistNode *gnode, *cnode, *bnode;
	PurpleBuddy *buddy;
	PurpleAccount *account;

	account = purple_connection_get_account(gc);

	if ((blist = purple_get_blist()) != NULL)
	{
		for (gnode = blist->root; gnode != NULL; gnode = gnode->next)
		{
			if (!PURPLE_BLIST_NODE_IS_GROUP(gnode))
				continue;
			for (cnode = gnode->child; cnode != NULL; cnode = cnode->next)
			{
				if (!PURPLE_BLIST_NODE_IS_CONTACT(cnode))
					continue;
				for (bnode = cnode->child; bnode != NULL; bnode = bnode->next)
				{
					if (!PURPLE_BLIST_NODE_IS_BUDDY(bnode))
						continue;
					buddy = (PurpleBuddy *)bnode;
					if (purple_buddy_get_account(buddy) == account)
						silcpurple_add_buddy_i(gc, buddy, TRUE);
				}
			}
		}
	}
}

void silcpurple_remove_buddy(PurpleConnection *gc, PurpleBuddy *buddy,
			   PurpleGroup *group)
{
	silc_free(buddy->proto_data);
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
	SilcPurple sg = b->account->gc->proto_data;
	SilcClient client = sg->client;
	SilcClientConnection conn = sg->conn;
	SilcClientID *client_id = b->proto_data;
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
	SilcPurple sg = b->account->gc->proto_data;
	SilcClient client = sg->client;
	SilcClientConnection conn = sg->conn;
	SilcClientID *client_id = b->proto_data;
	SilcClientEntry client_entry;
	char *moodstr, *statusstr, *contactstr, *langstr, *devicestr, *tzstr, *geostr;
	char tmp[256];

	/* Get the client entry. */
	client_entry = silc_client_get_client_by_id(client, conn, client_id);
	if (!client_entry)
		return;

	if (client_entry->nickname)
		purple_notify_user_info_add_pair(user_info, _("Nickname"),
					       client_entry->nickname);
	if (client_entry->username && client_entry->hostname) {
		g_snprintf(tmp, sizeof(tmp), "%s@%s", client_entry->username, client_entry->hostname);
		purple_notify_user_info_add_pair(user_info, _("Username"), tmp);
	}
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
	gc = purple_account_get_connection(b->account);
	sg = gc->proto_data;

	/* Call KILL */
	silc_client_command_call(sg->client, sg->conn, NULL, "KILL",
				 b->name, "Killed by operator", NULL);
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
	PurpleConnection *gc = purple_account_get_connection(buddy->account);
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
						    buddy->proto_data);

	if (client_entry && client_entry->send_key) {
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

#ifdef SILC_ATTRIBUTE_USER_ICON
void silcpurple_buddy_set_icon(PurpleConnection *gc, PurpleStoredImage *img)
{
	SilcPurple sg = gc->proto_data;
	SilcClient client = sg->client;
	SilcClientConnection conn = sg->conn;
	SilcMime mime;
	char type[32];
	unsigned char *icon;
	const char *t;
	SilcAttributeObjMime obj;

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

	obj.mime = icon = silc_mime_encode(mime, &obj.mime_len);
	if (obj.mime)
		silc_client_attribute_add(client, conn,
					  SILC_ATTRIBUTE_USER_ICON, &obj, sizeof(obj));

	silc_free(icon);
	silc_mime_free(mime);
}
#endif
