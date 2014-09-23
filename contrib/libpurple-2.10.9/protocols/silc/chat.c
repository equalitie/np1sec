/*

  silcpurple_chat.c

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

/***************************** Channel Routines ******************************/

GList *silcpurple_chat_info(PurpleConnection *gc)
{
	GList *ci = NULL;
	struct proto_chat_entry *pce;

	pce = g_new0(struct proto_chat_entry, 1);
	pce->label = _("_Channel:");
	pce->identifier = "channel";
	pce->required = TRUE;
	ci = g_list_append(ci, pce);

	pce = g_new0(struct proto_chat_entry, 1);
	pce->label = _("_Passphrase:");
	pce->identifier = "passphrase";
	pce->secret = TRUE;
	ci = g_list_append(ci, pce);

	return ci;
}

GHashTable *silcpurple_chat_info_defaults(PurpleConnection *gc, const char *chat_name)
{
	GHashTable *defaults;

	defaults = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);

	if (chat_name != NULL)
		g_hash_table_insert(defaults, "channel", g_strdup(chat_name));

	return defaults;
}

static void
silcpurple_chat_getinfo(PurpleConnection *gc, GHashTable *components);

static void
silcpurple_chat_getinfo_res(SilcClient client,
			    SilcClientConnection conn,
			    SilcStatus status,
			    SilcDList channels,
			    void *context)
{
	GHashTable *components = context;
	PurpleConnection *gc = client->application;
	const char *chname;
	char tmp[256];

	chname = g_hash_table_lookup(components, "channel");
	if (!chname)
		return;

	if (!channels) {
		g_snprintf(tmp, sizeof(tmp),
			   _("Channel %s does not exist in the network"), chname);
		purple_notify_error(gc, _("Channel Information"),
				  _("Cannot get channel information"), tmp);
		return;
	}

	silcpurple_chat_getinfo(gc, components);
}


static void
silcpurple_chat_getinfo(PurpleConnection *gc, GHashTable *components)
{
	SilcPurple sg = gc->proto_data;
	const char *chname;
	char tmp[256], *tmp2;
	GString *s;
	SilcChannelEntry channel;
	SilcHashTableList htl;
	SilcChannelUser chu;

	if (!components)
		return;

	chname = g_hash_table_lookup(components, "channel");
	if (!chname)
		return;
	channel = silc_client_get_channel(sg->client, sg->conn,
					  (char *)chname);
	if (!channel) {
		silc_client_get_channel_resolve(sg->client, sg->conn,
						(char *)chname,
						silcpurple_chat_getinfo_res,
						components);
		return;
	}

	s = g_string_new("");
	tmp2 = g_markup_escape_text(channel->channel_name, -1);
	g_string_append_printf(s, _("<b>Channel Name:</b> %s"), tmp2);
	g_free(tmp2);
	if (channel->user_list && silc_hash_table_count(channel->user_list))
		g_string_append_printf(s, _("<br><b>User Count:</b> %d"),
				       (int)silc_hash_table_count(channel->user_list));

	silc_hash_table_list(channel->user_list, &htl);
	while (silc_hash_table_get(&htl, NULL, (void *)&chu)) {
		if (chu->mode & SILC_CHANNEL_UMODE_CHANFO) {
			tmp2 = g_markup_escape_text(chu->client->nickname, -1);
			g_string_append_printf(s, _("<br><b>Channel Founder:</b> %s"),
					       tmp2);
			g_free(tmp2);
			break;
		}
	}
	silc_hash_table_list_reset(&htl);

	if (channel->cipher)
		g_string_append_printf(s, _("<br><b>Channel Cipher:</b> %s"),
				       channel->cipher);

	if (channel->hmac)
		/* Definition of HMAC: http://en.wikipedia.org/wiki/HMAC */
		g_string_append_printf(s, _("<br><b>Channel HMAC:</b> %s"),
				       channel->hmac);

	if (channel->topic) {
		tmp2 = g_markup_escape_text(channel->topic, -1);
		g_string_append_printf(s, _("<br><b>Channel Topic:</b><br>%s"), tmp2);
		g_free(tmp2);
	}

	if (channel->mode) {
		g_string_append(s, _("<br><b>Channel Modes:</b> "));
		silcpurple_get_chmode_string(channel->mode, tmp, sizeof(tmp));
		g_string_append(s, tmp);
	}

	if (channel->founder_key) {
		char *fingerprint, *babbleprint;
		unsigned char *pk;
		SilcUInt32 pk_len;
		pk = silc_pkcs_public_key_encode(channel->founder_key, &pk_len);
		if (pk) {
			fingerprint = silc_hash_fingerprint(NULL, pk, pk_len);
			babbleprint = silc_hash_babbleprint(NULL, pk, pk_len);

			g_string_append_printf(s, _("<br><b>Founder Key Fingerprint:</b><br>%s"), fingerprint);
			g_string_append_printf(s, _("<br><b>Founder Key Babbleprint:</b><br>%s"), babbleprint);

			silc_free(fingerprint);
			silc_free(babbleprint);
			silc_free(pk);
		}
	}

	purple_notify_formatted(gc, NULL, _("Channel Information"), NULL, s->str, NULL, NULL);
	g_string_free(s, TRUE);
}


static void
silcpurple_chat_getinfo_menu(PurpleBlistNode *node, gpointer data)
{
	PurpleChat *chat = (PurpleChat *)node;
	PurpleAccount *account = purple_chat_get_account(chat);
	silcpurple_chat_getinfo(purple_account_get_connection(account),
			purple_chat_get_components(chat));
}


#if 0   /* XXX For now these are not implemented.  We need better
	   listview dialog from Purple for these. */
/************************** Channel Invite List ******************************/

static void
silcpurple_chat_invitelist(PurpleBlistNode *node, gpointer data);
{

}


/**************************** Channel Ban List *******************************/

static void
silcpurple_chat_banlist(PurpleBlistNode *node, gpointer data);
{

}
#endif


/************************* Channel Authentication ****************************/

typedef struct {
	SilcPurple sg;
	SilcChannelEntry channel;
	PurpleChat *c;
	SilcDList pubkeys;
} *SilcPurpleChauth;

static void
silcpurple_chat_chpk_add(void *user_data, const char *name)
{
	SilcPurpleChauth sgc = (SilcPurpleChauth)user_data;
	SilcPurple sg = sgc->sg;
	SilcClient client = sg->client;
	SilcClientConnection conn = sg->conn;
	SilcPublicKey public_key;
	SilcBuffer chpks, pk, chidp;
	unsigned char mode[4];
	SilcUInt32 m;

	/* Load the public key */
	if (!silc_pkcs_load_public_key(name, &public_key)) {
		silcpurple_chat_chauth_show(sgc->sg, sgc->channel, sgc->pubkeys);
		silc_dlist_uninit(sgc->pubkeys);
		silc_free(sgc);
		purple_notify_error(client->application,
				    _("Add Channel Public Key"),
				    _("Could not load public key"), NULL);
		return;
	}

	pk = silc_public_key_payload_encode(public_key);
	chpks = silc_buffer_alloc_size(2);
	SILC_PUT16_MSB(1, chpks->head);
	chpks = silc_argument_payload_encode_one(chpks, pk->data,
						 silc_buffer_len(pk), 0x00);
	silc_buffer_free(pk);

	m = sgc->channel->mode;
	m |= SILC_CHANNEL_MODE_CHANNEL_AUTH;

	/* Send CMODE */
	SILC_PUT32_MSB(m, mode);
	chidp = silc_id_payload_encode(&sgc->channel->id, SILC_ID_CHANNEL);
	silc_client_command_send(client, conn, SILC_COMMAND_CMODE,
				 silcpurple_command_reply, NULL, 3,
				 1, chidp->data, silc_buffer_len(chidp),
				 2, mode, sizeof(mode),
				 9, chpks->data, silc_buffer_len(chpks));
	silc_buffer_free(chpks);
	silc_buffer_free(chidp);
	if (sgc->pubkeys) {
	  silc_dlist_start(sgc->pubkeys);
	  while ((public_key = silc_dlist_get(sgc->pubkeys)))
		silc_pkcs_public_key_free(public_key);
	  silc_dlist_uninit(sgc->pubkeys);
	}
	silc_free(sgc);
}

static void
silcpurple_chat_chpk_cancel(void *user_data, const char *name)
{
	SilcPurpleChauth sgc = (SilcPurpleChauth)user_data;
	SilcPublicKey public_key;

	silcpurple_chat_chauth_show(sgc->sg, sgc->channel, sgc->pubkeys);

	if (sgc->pubkeys) {
	  silc_dlist_start(sgc->pubkeys);
	  while ((public_key = silc_dlist_get(sgc->pubkeys)))
		silc_pkcs_public_key_free(public_key);
	  silc_dlist_uninit(sgc->pubkeys);
	}
	silc_free(sgc);
}

static void
silcpurple_chat_chpk_cb(SilcPurpleChauth sgc, PurpleRequestFields *fields)
{
	SilcPurple sg = sgc->sg;
	SilcClient client = sg->client;
	SilcClientConnection conn = sg->conn;
	PurpleRequestField *f;
	GList *list;
	SilcPublicKey public_key;
	SilcBuffer chpks, pk, chidp;
	SilcUInt16 c = 0, ct;
	unsigned char mode[4];
	SilcUInt32 m;

	f = purple_request_fields_get_field(fields, "list");
	if (!purple_request_field_list_get_selected(f)) {
		/* Add new public key */
		purple_request_file(sg->gc, _("Open Public Key..."), NULL, FALSE,
				    G_CALLBACK(silcpurple_chat_chpk_add),
				    G_CALLBACK(silcpurple_chat_chpk_cancel),
				    purple_connection_get_account(sg->gc), NULL, NULL, sgc);
		return;
	}

	list = purple_request_field_list_get_items(f);
	chpks = silc_buffer_alloc_size(2);

	for (ct = 0; list; list = list->next, ct++) {
		public_key = purple_request_field_list_get_data(f, list->data);
		if (purple_request_field_list_is_selected(f, list->data)) {
			/* Delete this public key */
			pk = silc_public_key_payload_encode(public_key);
			chpks = silc_argument_payload_encode_one(chpks, pk->data,
								 silc_buffer_len(pk), 0x01);
			silc_buffer_free(pk);
			c++;
		}
	}
	if (!c) {
		silc_buffer_free(chpks);
		return;
	}
	SILC_PUT16_MSB(c, chpks->head);

	m = sgc->channel->mode;
	if (ct == c)
		m &= ~SILC_CHANNEL_MODE_CHANNEL_AUTH;

	/* Send CMODE */
	SILC_PUT32_MSB(m, mode);
	chidp = silc_id_payload_encode(&sgc->channel->id, SILC_ID_CHANNEL);
	silc_client_command_send(client, conn, SILC_COMMAND_CMODE,
				 silcpurple_command_reply, NULL, 3,
				 1, chidp->data, silc_buffer_len(chidp),
				 2, mode, sizeof(mode),
				 9, chpks->data, silc_buffer_len(chpks));
	silc_buffer_free(chpks);
	silc_buffer_free(chidp);
	if (sgc->pubkeys) {
	  silc_dlist_start(sgc->pubkeys);
	  while ((public_key = silc_dlist_get(sgc->pubkeys)))
		silc_pkcs_public_key_free(public_key);
	  silc_dlist_uninit(sgc->pubkeys);
	}
	silc_free(sgc);
}

static void
silcpurple_chat_chauth_ok(SilcPurpleChauth sgc, PurpleRequestFields *fields)
{
	SilcPurple sg = sgc->sg;
	PurpleRequestField *f;
	SilcPublicKey public_key;
	const char *curpass, *val;
	int set;

	f = purple_request_fields_get_field(fields, "passphrase");
	val = purple_request_field_string_get_value(f);
	curpass = purple_blist_node_get_string((PurpleBlistNode *)sgc->c, "passphrase");

	if (!val && curpass)
		set = 0;
	else if (val && !curpass)
		set = 1;
	else if (val && curpass && strcmp(val, curpass))
		set = 1;
	else
		set = -1;

	if (set == 1) {
		silc_client_command_call(sg->client, sg->conn, NULL, "CMODE",
					 sgc->channel->channel_name, "+a", val, NULL);
		purple_blist_node_set_string((PurpleBlistNode *)sgc->c, "passphrase", val);
	} else if (set == 0) {
		silc_client_command_call(sg->client, sg->conn, NULL, "CMODE",
					 sgc->channel->channel_name, "-a", NULL);
		purple_blist_node_remove_setting((PurpleBlistNode *)sgc->c, "passphrase");
	}

	if (sgc->pubkeys) {
	  silc_dlist_start(sgc->pubkeys);
	  while ((public_key = silc_dlist_get(sgc->pubkeys)))
		silc_pkcs_public_key_free(public_key);
	  silc_dlist_uninit(sgc->pubkeys);
	}
	silc_free(sgc);
}

void silcpurple_chat_chauth_show(SilcPurple sg, SilcChannelEntry channel,
				 SilcDList channel_pubkeys)
{
	SilcPublicKey public_key;
	SilcSILCPublicKey silc_pubkey;
	unsigned char *pk;
	SilcUInt32 pk_len;
	char *fingerprint, *babbleprint;
	SilcPublicKeyIdentifier ident;
	char tmp2[1024], t[512];
	PurpleRequestFields *fields;
	PurpleRequestFieldGroup *g;
	PurpleRequestField *f;
	SilcPurpleChauth sgc;
	const char *curpass = NULL;

	sgc = silc_calloc(1, sizeof(*sgc));
	if (!sgc)
		return;
	sgc->sg = sg;
	sgc->channel = channel;

	fields = purple_request_fields_new();

	if (sgc->c)
	  curpass = purple_blist_node_get_string((PurpleBlistNode *)sgc->c, "passphrase");

	g = purple_request_field_group_new(NULL);
	f = purple_request_field_string_new("passphrase", _("Channel Passphrase"),
					    curpass, FALSE);
	purple_request_field_string_set_masked(f, TRUE);
	purple_request_field_group_add_field(g, f);
	purple_request_fields_add_group(fields, g);

	g = purple_request_field_group_new(NULL);
	f = purple_request_field_label_new("l1", _("Channel Public Keys List"));
	purple_request_field_group_add_field(g, f);
	purple_request_fields_add_group(fields, g);

	g_snprintf(t, sizeof(t),
		   _("Channel authentication is used to secure the channel from "
		     "unauthorized access. The authentication may be based on "
		     "passphrase and digital signatures. If passphrase is set, it "
		     "is required to be able to join. If channel public keys are set "
		     "then only users whose public keys are listed are able to join."));

	if (!channel_pubkeys || !silc_dlist_count(channel_pubkeys)) {
		f = purple_request_field_list_new("list", NULL);
		purple_request_field_group_add_field(g, f);
		purple_request_fields(sg->gc, _("Channel Authentication"),
				      _("Channel Authentication"), t, fields,
				      _("Add / Remove"), G_CALLBACK(silcpurple_chat_chpk_cb),
				      _("OK"), G_CALLBACK(silcpurple_chat_chauth_ok),
				      purple_connection_get_account(sg->gc), NULL, NULL, sgc);
		if (channel_pubkeys)
		  silc_dlist_uninit(channel_pubkeys);
		return;
	}
	sgc->pubkeys = channel_pubkeys;

	g = purple_request_field_group_new(NULL);
	f = purple_request_field_list_new("list", NULL);
	purple_request_field_group_add_field(g, f);
	purple_request_fields_add_group(fields, g);

	silc_dlist_start(channel_pubkeys);
	while ((public_key = silc_dlist_get(channel_pubkeys))) {
		pk = silc_pkcs_public_key_encode(public_key, &pk_len);
		if (!pk)
			continue;
		fingerprint = silc_hash_fingerprint(NULL, pk + 4, pk_len - 4);
		babbleprint = silc_hash_babbleprint(NULL, pk + 4, pk_len - 4);

		silc_pubkey = silc_pkcs_get_context(SILC_PKCS_SILC, public_key);
		ident = &silc_pubkey->identifier;

		g_snprintf(tmp2, sizeof(tmp2), "%s\n  %s\n  %s",
			   ident->realname ? ident->realname : ident->username ?
			   ident->username : "", fingerprint, babbleprint);
		purple_request_field_list_add_icon(f, tmp2, NULL, public_key);

		silc_free(fingerprint);
		silc_free(babbleprint);
	}

	purple_request_field_list_set_multi_select(f, FALSE);
	purple_request_fields(sg->gc, _("Channel Authentication"),
			      _("Channel Authentication"), t, fields,
			      _("Add / Remove"), G_CALLBACK(silcpurple_chat_chpk_cb),
			      _("OK"), G_CALLBACK(silcpurple_chat_chauth_ok),
			      purple_connection_get_account(sg->gc), NULL, NULL, sgc);
}

static void
silcpurple_chat_chauth(PurpleBlistNode *node, gpointer data)
{
	PurpleChat *chat;
	PurpleConnection *gc;
	SilcPurple sg;

	g_return_if_fail(PURPLE_BLIST_NODE_IS_CHAT(node));

	chat = (PurpleChat *) node;
	gc = purple_account_get_connection(purple_chat_get_account(chat));
	sg = gc->proto_data;

	silc_client_command_call(sg->client, sg->conn, NULL, "CMODE",
				 g_hash_table_lookup(purple_chat_get_components(chat), "channel"),
				 "+C", NULL);
}


/************************** Channel Private Groups **************************/

/* Private groups are "virtual" channels.  They are groups inside a channel.
   This is implemented by using channel private keys.  By knowing a channel
   private key user becomes part of that group and is able to talk on that
   group.  Other users, on the same channel, won't be able to see the
   messages of that group.  It is possible to have multiple groups inside
   a channel - and thus having multiple private keys on the channel. */

typedef struct {
	SilcPurple sg;
	PurpleChat *c;
	const char *channel;
} *SilcPurpleCharPrv;

static void
silcpurple_chat_prv_add(SilcPurpleCharPrv p, PurpleRequestFields *fields)
{
	SilcPurple sg = p->sg;
	char tmp[512];
	PurpleRequestField *f;
	const char *name, *passphrase, *alias;
	GHashTable *comp;
	PurpleGroup *g;
	PurpleChat *cn;

	f = purple_request_fields_get_field(fields, "name");
	name = purple_request_field_string_get_value(f);
	if (!name) {
		silc_free(p);
		return;
	}
	f = purple_request_fields_get_field(fields, "passphrase");
	passphrase = purple_request_field_string_get_value(f);
	f = purple_request_fields_get_field(fields, "alias");
	alias = purple_request_field_string_get_value(f);

	/* Add private group to buddy list */
	g_snprintf(tmp, sizeof(tmp), "%s [Private Group]", name);
	comp = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);
	g_hash_table_replace(comp, "channel", g_strdup(tmp));
	g_hash_table_replace(comp, "passphrase", g_strdup(passphrase));

	cn = purple_chat_new(sg->account, alias, comp);
	g = purple_chat_get_group(p->c);
	purple_blist_add_chat(cn, g, (PurpleBlistNode *)p->c);

	/* Associate to a real channel */
	purple_blist_node_set_string((PurpleBlistNode *)cn, "parentch", p->channel);

	/* Join the group */
	silcpurple_chat_join(sg->gc, comp);

	silc_free(p);
}

static void
silcpurple_chat_prv_cancel(SilcPurpleCharPrv p, PurpleRequestFields *fields)
{
	silc_free(p);
}

static void
silcpurple_chat_prv(PurpleBlistNode *node, gpointer data)
{
	PurpleChat *chat;
	PurpleConnection *gc;
	SilcPurple sg;

	SilcPurpleCharPrv p;
	PurpleRequestFields *fields;
	PurpleRequestFieldGroup *g;
	PurpleRequestField *f;
	char tmp[512];

	g_return_if_fail(PURPLE_BLIST_NODE_IS_CHAT(node));

	chat = (PurpleChat *) node;
	gc = purple_account_get_connection(purple_chat_get_account(chat));
	sg = gc->proto_data;

	p = silc_calloc(1, sizeof(*p));
	if (!p)
		return;
	p->sg = sg;

	p->channel = g_hash_table_lookup(purple_chat_get_components(chat), "channel");
	p->c = purple_blist_find_chat(sg->account, p->channel);

	fields = purple_request_fields_new();

	g = purple_request_field_group_new(NULL);
	f = purple_request_field_string_new("name", _("Group Name"),
					  NULL, FALSE);
	purple_request_field_group_add_field(g, f);

	f = purple_request_field_string_new("passphrase", _("Passphrase"),
					  NULL, FALSE);
	purple_request_field_string_set_masked(f, TRUE);
	purple_request_field_group_add_field(g, f);

	f = purple_request_field_string_new("alias", _("Alias"),
					  NULL, FALSE);
	purple_request_field_group_add_field(g, f);
	purple_request_fields_add_group(fields, g);

	g_snprintf(tmp, sizeof(tmp),
		   _("Please enter the %s channel private group name and passphrase."),
		   p->channel);
	purple_request_fields(gc, _("Add Channel Private Group"), NULL, tmp, fields,
			      _("Add"), G_CALLBACK(silcpurple_chat_prv_add),
			      _("Cancel"), G_CALLBACK(silcpurple_chat_prv_cancel),
			      purple_connection_get_account(gc), NULL, NULL, p);
}


/****************************** Channel Modes ********************************/

static void
silcpurple_chat_permanent_reset(PurpleBlistNode *node, gpointer data)
{
	PurpleChat *chat;
	PurpleConnection *gc;
	SilcPurple sg;

	g_return_if_fail(PURPLE_BLIST_NODE_IS_CHAT(node));

	chat = (PurpleChat *) node;
	gc = purple_account_get_connection(purple_chat_get_account(chat));
	sg = gc->proto_data;

	silc_client_command_call(sg->client, sg->conn, NULL, "CMODE",
				 g_hash_table_lookup(purple_chat_get_components(chat), "channel"),
				 "-f", NULL);
}

static void
silcpurple_chat_permanent(PurpleBlistNode *node, gpointer data)
{
	PurpleChat *chat;
	PurpleConnection *gc;
	SilcPurple sg;
	const char *channel;

	g_return_if_fail(PURPLE_BLIST_NODE_IS_CHAT(node));

	chat = (PurpleChat *) node;
	gc = purple_account_get_connection(purple_chat_get_account(chat));
	sg = gc->proto_data;

	if (!sg->conn)
		return;

	/* XXX we should have ability to define which founder
	   key to use.  Now we use the user's own public key
	   (default key). */

	/* Call CMODE */
	channel = g_hash_table_lookup(purple_chat_get_components(chat), "channel");
	silc_client_command_call(sg->client, sg->conn, NULL, "CMODE", channel,
				 "+f", NULL);
}

typedef struct {
	SilcPurple sg;
	char *channel;
} *SilcPurpleChatInput;

static void
silcpurple_chat_ulimit_cb(SilcPurpleChatInput s, const char *limit)
{
	SilcChannelEntry channel;
	int ulimit = 0;

	channel = silc_client_get_channel(s->sg->client, s->sg->conn,
					  (char *)s->channel);
	if (!channel)
		return;
	if (limit)
		ulimit = atoi(limit);

	if (!limit || !(*limit) || *limit == '0') {
		if (limit && ulimit == channel->user_limit) {
			g_free(s->channel);
			silc_free(s);
			return;
		}
		silc_client_command_call(s->sg->client, s->sg->conn, NULL, "CMODE",
					 s->channel, "-l", NULL);

		g_free(s->channel);
		silc_free(s);
		return;
	}

	if (ulimit == channel->user_limit) {
		g_free(s->channel);
		silc_free(s);
		return;
	}

	/* Call CMODE */
	silc_client_command_call(s->sg->client, s->sg->conn, NULL, "CMODE",
				 s->channel, "+l", limit, NULL);

	g_free(s->channel);
	silc_free(s);
}

static void
silcpurple_chat_ulimit(PurpleBlistNode *node, gpointer data)
{
	PurpleChat *chat;
	PurpleConnection *gc;
	SilcPurple sg;

	SilcPurpleChatInput s;
	SilcChannelEntry channel;
	char *ch;
	char tmp[32];

	g_return_if_fail(PURPLE_BLIST_NODE_IS_CHAT(node));

	chat = (PurpleChat *) node;
	gc = purple_account_get_connection(purple_chat_get_account(chat));
	sg = gc->proto_data;

	if (!sg->conn)
		return;

	ch = g_strdup(g_hash_table_lookup(purple_chat_get_components(chat), "channel"));
	channel = silc_client_get_channel(sg->client, sg->conn, (char *)ch);
	if (!channel)
		return;

	s = silc_calloc(1, sizeof(*s));
	if (!s)
		return;
	s->channel = ch;
	s->sg = sg;
	g_snprintf(tmp, sizeof(tmp), "%d", (int)channel->user_limit);
	purple_request_input(gc, _("User Limit"), NULL,
			   _("Set user limit on channel. Set to zero to reset user limit."),
			   tmp, FALSE, FALSE, NULL,
			   _("OK"), G_CALLBACK(silcpurple_chat_ulimit_cb),
			   _("Cancel"), G_CALLBACK(silcpurple_chat_ulimit_cb),
			   purple_connection_get_account(gc), NULL, NULL, s);
}

static void
silcpurple_chat_resettopic(PurpleBlistNode *node, gpointer data)
{
	PurpleChat *chat;
	PurpleConnection *gc;
	SilcPurple sg;

	g_return_if_fail(PURPLE_BLIST_NODE_IS_CHAT(node));

	chat = (PurpleChat *) node;
	gc = purple_account_get_connection(purple_chat_get_account(chat));
	sg = gc->proto_data;

	silc_client_command_call(sg->client, sg->conn, NULL, "CMODE",
				 g_hash_table_lookup(purple_chat_get_components(chat), "channel"),
				 "-t", NULL);
}

static void
silcpurple_chat_settopic(PurpleBlistNode *node, gpointer data)
{
	PurpleChat *chat;
	PurpleConnection *gc;
	SilcPurple sg;

	g_return_if_fail(PURPLE_BLIST_NODE_IS_CHAT(node));

	chat = (PurpleChat *) node;
	gc = purple_account_get_connection(purple_chat_get_account(chat));
	sg = gc->proto_data;

	silc_client_command_call(sg->client, sg->conn, NULL, "CMODE",
				 g_hash_table_lookup(purple_chat_get_components(chat), "channel"),
				 "+t", NULL);
}

static void
silcpurple_chat_resetprivate(PurpleBlistNode *node, gpointer data)
{
	PurpleChat *chat;
	PurpleConnection *gc;
	SilcPurple sg;

	g_return_if_fail(PURPLE_BLIST_NODE_IS_CHAT(node));

	chat = (PurpleChat *) node;
	gc = purple_account_get_connection(purple_chat_get_account(chat));
	sg = gc->proto_data;

	silc_client_command_call(sg->client, sg->conn, NULL, "CMODE",
				 g_hash_table_lookup(purple_chat_get_components(chat), "channel"),
				 "-p", NULL);
}

static void
silcpurple_chat_setprivate(PurpleBlistNode *node, gpointer data)
{
	PurpleChat *chat;
	PurpleConnection *gc;
	SilcPurple sg;

	g_return_if_fail(PURPLE_BLIST_NODE_IS_CHAT(node));

	chat = (PurpleChat *) node;
	gc = purple_account_get_connection(purple_chat_get_account(chat));
	sg = gc->proto_data;

	silc_client_command_call(sg->client, sg->conn, NULL, "CMODE",
				 g_hash_table_lookup(purple_chat_get_components(chat), "channel"),
				 "+p", NULL);
}

static void
silcpurple_chat_resetsecret(PurpleBlistNode *node, gpointer data)
{
	PurpleChat *chat;
	PurpleConnection *gc;
	SilcPurple sg;

	g_return_if_fail(PURPLE_BLIST_NODE_IS_CHAT(node));

	chat = (PurpleChat *) node;
	gc = purple_account_get_connection(purple_chat_get_account(chat));
	sg = gc->proto_data;

	silc_client_command_call(sg->client, sg->conn, NULL, "CMODE",
				 g_hash_table_lookup(purple_chat_get_components(chat), "channel"),
				 "-s", NULL);
}

static void
silcpurple_chat_setsecret(PurpleBlistNode *node, gpointer data)
{
	PurpleChat *chat;
	PurpleConnection *gc;
	SilcPurple sg;

	g_return_if_fail(PURPLE_BLIST_NODE_IS_CHAT(node));

	chat = (PurpleChat *) node;
	gc = purple_account_get_connection(purple_chat_get_account(chat));
	sg = gc->proto_data;

	silc_client_command_call(sg->client, sg->conn, NULL, "CMODE",
				 g_hash_table_lookup(purple_chat_get_components(chat), "channel"),
				 "+s", NULL);
}

typedef struct {
	SilcPurple sg;
	SilcChannelEntry channel;
} *SilcPurpleChatWb;

static void
silcpurple_chat_wb(PurpleBlistNode *node, gpointer data)
{
	SilcPurpleChatWb wb = data;
	silcpurple_wb_init_ch(wb->sg, wb->channel);
	silc_free(wb);
}

GList *silcpurple_chat_menu(PurpleChat *chat)
{
	GHashTable *components = purple_chat_get_components(chat);
	PurpleConnection *gc = purple_account_get_connection(purple_chat_get_account(chat));
	SilcPurple sg = gc->proto_data;
	SilcClientConnection conn = sg->conn;
	const char *chname = NULL;
	SilcChannelEntry channel = NULL;
	SilcChannelUser chu = NULL;
	SilcUInt32 mode = 0;

	GList *m = NULL;
	PurpleMenuAction *act;

	if (components)
		chname = g_hash_table_lookup(components, "channel");
	if (!chname)
		return NULL;
	channel = silc_client_get_channel(sg->client, sg->conn,
					  (char *)chname);
	if (channel) {
		chu = silc_client_on_channel(channel, conn->local_entry);
		if (chu)
			mode = chu->mode;
	}

	if (strstr(chname, "[Private Group]"))
		return NULL;

	act = purple_menu_action_new(_("Get Info"),
	                           PURPLE_CALLBACK(silcpurple_chat_getinfo_menu),
	                           NULL, NULL);
	m = g_list_append(m, act);

#if 0   /* XXX For now these are not implemented.  We need better
	   listview dialog from Purple for these. */
	if (mode & SILC_CHANNEL_UMODE_CHANOP) {
		act = purple_menu_action_new(_("Invite List"),
		                           PURPLE_CALLBACK(silcpurple_chat_invitelist),
		                           NULL, NULL);
		m = g_list_append(m, act);

		act = purple_menu_action_new(_("Ban List"),
		                           PURPLE_CALLBACK(silcpurple_chat_banlist),
		                           NULL, NULL);
		m = g_list_append(m, act);
	}
#endif

	if (chu) {
		act = purple_menu_action_new(_("Add Private Group"),
		                           PURPLE_CALLBACK(silcpurple_chat_prv),
		                           NULL, NULL);
		m = g_list_append(m, act);
	}

	if (chu && mode & SILC_CHANNEL_UMODE_CHANFO) {
		act = purple_menu_action_new(_("Channel Authentication"),
		                           PURPLE_CALLBACK(silcpurple_chat_chauth),
		                           NULL, NULL);
		m = g_list_append(m, act);

		if (channel->mode & SILC_CHANNEL_MODE_FOUNDER_AUTH) {
			act = purple_menu_action_new(_("Reset Permanent"),
			                           PURPLE_CALLBACK(silcpurple_chat_permanent_reset),
			                           NULL, NULL);
			m = g_list_append(m, act);
		} else {
			act = purple_menu_action_new(_("Set Permanent"),
			                           PURPLE_CALLBACK(silcpurple_chat_permanent),
			                           NULL, NULL);
			m = g_list_append(m, act);
		}
	}

	if (chu && mode & SILC_CHANNEL_UMODE_CHANOP) {
		act = purple_menu_action_new(_("Set User Limit"),
		                           PURPLE_CALLBACK(silcpurple_chat_ulimit),
		                           NULL, NULL);
		m = g_list_append(m, act);

		if (channel->mode & SILC_CHANNEL_MODE_TOPIC) {
			act = purple_menu_action_new(_("Reset Topic Restriction"),
			                           PURPLE_CALLBACK(silcpurple_chat_resettopic),
			                           NULL, NULL);
			m = g_list_append(m, act);
		} else {
			act = purple_menu_action_new(_("Set Topic Restriction"),
			                           PURPLE_CALLBACK(silcpurple_chat_settopic),
			                           NULL, NULL);
			m = g_list_append(m, act);
		}

		if (channel->mode & SILC_CHANNEL_MODE_PRIVATE) {
			act = purple_menu_action_new(_("Reset Private Channel"),
			                           PURPLE_CALLBACK(silcpurple_chat_resetprivate),
			                           NULL, NULL);
			m = g_list_append(m, act);
		} else {
			act = purple_menu_action_new(_("Set Private Channel"),
			                           PURPLE_CALLBACK(silcpurple_chat_setprivate),
			                           NULL, NULL);
			m = g_list_append(m, act);
		}

		if (channel->mode & SILC_CHANNEL_MODE_SECRET) {
			act = purple_menu_action_new(_("Reset Secret Channel"),
			                           PURPLE_CALLBACK(silcpurple_chat_resetsecret),
			                           NULL, NULL);
			m = g_list_append(m, act);
		} else {
			act = purple_menu_action_new(_("Set Secret Channel"),
			                           PURPLE_CALLBACK(silcpurple_chat_setsecret),
			                           NULL, NULL);
			m = g_list_append(m, act);
		}
	}

	if (chu && channel) {
		SilcPurpleChatWb wb;
		wb = silc_calloc(1, sizeof(*wb));
		wb->sg = sg;
		wb->channel = channel;
		act = purple_menu_action_new(_("Draw On Whiteboard"),
		                           PURPLE_CALLBACK(silcpurple_chat_wb),
		                           (void *)wb, NULL);
		m = g_list_append(m, act);
	}

	return m;
}


/******************************* Joining Etc. ********************************/

char *silcpurple_get_chat_name(GHashTable *data)
{
	return g_strdup(g_hash_table_lookup(data, "channel"));
}

void silcpurple_chat_join(PurpleConnection *gc, GHashTable *data)
{
	SilcPurple sg = gc->proto_data;
	SilcClient client = sg->client;
	SilcClientConnection conn = sg->conn;
	const char *channel, *passphrase, *parentch;

	if (!conn)
		return;

	channel = g_hash_table_lookup(data, "channel");
	passphrase = g_hash_table_lookup(data, "passphrase");

	/* Check if we are joining a private group.  Handle it
	   purely locally as it's not a real channel */
	if (strstr(channel, "[Private Group]")) {
		SilcChannelEntry channel_entry;
		SilcChannelPrivateKey key;
		PurpleChat *c;
		SilcPurplePrvgrp grp;

		c = purple_blist_find_chat(sg->account, channel);
		parentch = purple_blist_node_get_string((PurpleBlistNode *)c, "parentch");
		if (!parentch)
			return;

		channel_entry = silc_client_get_channel(sg->client, sg->conn,
							(char *)parentch);
		if (!channel_entry ||
		    !silc_client_on_channel(channel_entry, sg->conn->local_entry)) {
			char tmp[512];
			g_snprintf(tmp, sizeof(tmp),
				   _("You have to join the %s channel before you are "
				     "able to join the private group"), parentch);
			purple_notify_error(gc, _("Join Private Group"),
					  _("Cannot join private group"), tmp);
			return;
		}

		/* Add channel private key */
		if (!silc_client_add_channel_private_key(client, conn,
							 channel_entry, channel,
							 NULL, NULL,
							 (unsigned char *)passphrase,
							 strlen(passphrase), &key))
			return;

		/* Join the group */
		grp = silc_calloc(1, sizeof(*grp));
		if (!grp)
			return;
		grp->id = ++sg->channel_ids + SILCPURPLE_PRVGRP;
		grp->chid = SILC_PTR_TO_32(channel_entry->context);
		grp->parentch = parentch;
		grp->channel = channel;
		grp->key = key;
		sg->grps = g_list_append(sg->grps, grp);
		serv_got_joined_chat(gc, grp->id, channel);
		return;
	}

	/* XXX We should have other properties here as well:
	   1. whether to try to authenticate to the channel
	     1a. with default key,
	     1b. with specific key.
	   2. whether to try to authenticate to become founder.
	     2a. with default key,
	     2b. with specific key.

	   Since now such variety is not possible in the join dialog
	   we always use -founder and -auth options, which try to
	   do both 1 and 2 with default keys. */

	/* Call JOIN */
	if ((passphrase != NULL) && (*passphrase != '\0'))
		silc_client_command_call(client, conn, NULL, "JOIN",
					 channel, passphrase, "-auth", "-founder", NULL);
	else
		silc_client_command_call(client, conn, NULL, "JOIN",
					 channel, "-auth", "-founder", NULL);
}

void silcpurple_chat_invite(PurpleConnection *gc, int id, const char *msg,
			    const char *name)
{
	SilcPurple sg = gc->proto_data;
	SilcClient client = sg->client;
	SilcClientConnection conn = sg->conn;
	SilcHashTableList htl;
	SilcChannelUser chu;
	gboolean found = FALSE;

	if (!conn)
		return;

	/* See if we are inviting on a private group.  Invite
	   to the actual channel */
	if (id > SILCPURPLE_PRVGRP) {
		GList *l;
		SilcPurplePrvgrp prv;

		for (l = sg->grps; l; l = l->next)
			if (((SilcPurplePrvgrp)l->data)->id == id)
				break;
		if (!l)
			return;
		prv = l->data;
		id = prv->chid;
	}

	/* Find channel by id */
	silc_hash_table_list(conn->local_entry->channels, &htl);
	while (silc_hash_table_get(&htl, NULL, (void *)&chu)) {
		if (SILC_PTR_TO_32(chu->channel->context) == id ) {
			found = TRUE;
			break;
		}
	}
	silc_hash_table_list_reset(&htl);
	if (!found)
		return;

	/* Call INVITE */
	silc_client_command_call(client, conn, NULL, "INVITE",
				 chu->channel->channel_name,
				 name, NULL);
}

void silcpurple_chat_leave(PurpleConnection *gc, int id)
{
	SilcPurple sg = gc->proto_data;
	SilcClient client = sg->client;
	SilcClientConnection conn = sg->conn;
	SilcHashTableList htl;
	SilcChannelUser chu;
	gboolean found = FALSE;
	GList *l;
	SilcPurplePrvgrp prv;

	if (!conn)
		return;

	/* See if we are leaving a private group */
	if (id > SILCPURPLE_PRVGRP) {
		SilcChannelEntry channel;

		for (l = sg->grps; l; l = l->next)
			if (((SilcPurplePrvgrp)l->data)->id == id)
				break;
		if (!l)
			return;
		prv = l->data;
		channel = silc_client_get_channel(sg->client, sg->conn,
						  (char *)prv->parentch);
		if (!channel)
			return;
		silc_client_del_channel_private_key(client, conn,
						    channel, prv->key);
		silc_free(prv);
		sg->grps = g_list_remove(sg->grps, prv);
		serv_got_chat_left(gc, id);
		return;
	}

	/* Find channel by id */
	silc_hash_table_list(conn->local_entry->channels, &htl);
	while (silc_hash_table_get(&htl, NULL, (void *)&chu)) {
		if (SILC_PTR_TO_32(chu->channel->context) == id ) {
			found = TRUE;
			break;
		}
	}
	silc_hash_table_list_reset(&htl);
	if (!found)
		return;

	/* Call LEAVE */
	silc_client_command_call(client, conn, NULL, "LEAVE",
				 chu->channel->channel_name, NULL);

	serv_got_chat_left(gc, id);

	/* Leave from private groups on this channel as well */
	for (l = sg->grps; l; l = l->next)
		if (((SilcPurplePrvgrp)l->data)->chid == id) {
			prv = l->data;
			silc_client_del_channel_private_key(client, conn,
							    chu->channel,
							    prv->key);
			serv_got_chat_left(gc, prv->id);
			silc_free(prv);
			sg->grps = g_list_remove(sg->grps, prv);
			if (!sg->grps)
				break;
		}
}

int silcpurple_chat_send(PurpleConnection *gc, int id, const char *msg,
			 PurpleMessageFlags msgflags)
{
	SilcPurple sg = gc->proto_data;
	SilcClient client = sg->client;
	SilcClientConnection conn = sg->conn;
	SilcHashTableList htl;
	SilcChannelUser chu;
	SilcChannelEntry channel = NULL;
	SilcChannelPrivateKey key = NULL;
	SilcMessageFlags flags;
	int ret = 0;
	char *msg2, *tmp;
	gboolean found = FALSE;
	gboolean sign = purple_account_get_bool(sg->account, "sign-verify", FALSE);
	SilcDList list;

	if (!msg || !conn)
		return 0;

	flags = SILC_MESSAGE_FLAG_UTF8;

	tmp = msg2 = purple_unescape_html(msg);

	if (!g_ascii_strncasecmp(msg2, "/me ", 4))
	{
		msg2 += 4;
		if (!*msg2) {
			g_free(tmp);
			return 0;
		}
		flags |= SILC_MESSAGE_FLAG_ACTION;
	} else if (strlen(msg) > 1 && msg[0] == '/') {
		if (!silc_client_command_call(client, conn, msg + 1))
			purple_notify_error(gc, _("Call Command"), _("Cannot call command"),
					    _("Unknown command"));
		g_free(tmp);
		return 0;
	}


	if (sign)
		flags |= SILC_MESSAGE_FLAG_SIGNED;

	/* Get the channel private key if we are sending on
	   private group */
	if (id > SILCPURPLE_PRVGRP) {
		GList *l;
		SilcPurplePrvgrp prv;

		for (l = sg->grps; l; l = l->next)
			if (((SilcPurplePrvgrp)l->data)->id == id)
				break;
		if (!l) {
			g_free(tmp);
			return 0;
		}
		prv = l->data;
		channel = silc_client_get_channel(sg->client, sg->conn,
						  (char *)prv->parentch);
		if (!channel) {
			g_free(tmp);
			return 0;
		}
		key = prv->key;
	}

	if (!channel) {
		/* Find channel by id */
		silc_hash_table_list(conn->local_entry->channels, &htl);
		while (silc_hash_table_get(&htl, NULL, (void *)&chu)) {
			if (SILC_PTR_TO_32(chu->channel->context) == id ) {
				found = TRUE;
				break;
			}
		}
		silc_hash_table_list_reset(&htl);
		if (!found) {
			g_free(tmp);
			return 0;
		}
		channel = chu->channel;
	}

	/* Check for images */
	if (msgflags & PURPLE_MESSAGE_IMAGES) {
		list = silcpurple_image_message(msg, &flags);
		if (list) {
			/* Send one or more MIME message.  If more than one, they
			   are MIME fragments due to over large message */
			SilcBuffer buf;

			silc_dlist_start(list);
			while ((buf = silc_dlist_get(list)) != SILC_LIST_END)
				ret =
			 	silc_client_send_channel_message(client, conn,
								 channel, key,
								 flags, sg->sha1hash,
								 buf->data,
								 silc_buffer_len(buf));
			silc_mime_partial_free(list);
			g_free(tmp);

			if (ret)
				  serv_got_chat_in(gc, id, purple_connection_get_display_name(gc), msgflags, msg, time(NULL));
			return ret;
		}
	}

	/* Send channel message */
	ret = silc_client_send_channel_message(client, conn, channel, key,
					       flags, sg->sha1hash,
					       (unsigned char *)msg2,
					       strlen(msg2));
	if (ret) {
		serv_got_chat_in(gc, id, purple_connection_get_display_name(gc), msgflags, msg,
				 time(NULL));
	}
	g_free(tmp);

	return ret;
}

void silcpurple_chat_set_topic(PurpleConnection *gc, int id, const char *topic)
{
	SilcPurple sg = gc->proto_data;
	SilcClient client = sg->client;
	SilcClientConnection conn = sg->conn;
	SilcHashTableList htl;
	SilcChannelUser chu;
	gboolean found = FALSE;

	if (!conn)
		return;

	/* See if setting topic on private group.  Set it
	   on the actual channel */
	if (id > SILCPURPLE_PRVGRP) {
		GList *l;
		SilcPurplePrvgrp prv;

		for (l = sg->grps; l; l = l->next)
			if (((SilcPurplePrvgrp)l->data)->id == id)
				break;
		if (!l)
			return;
		prv = l->data;
		id = prv->chid;
	}

	/* Find channel by id */
	silc_hash_table_list(conn->local_entry->channels, &htl);
	while (silc_hash_table_get(&htl, NULL, (void *)&chu)) {
		if (SILC_PTR_TO_32(chu->channel->context) == id ) {
			found = TRUE;
			break;
		}
	}
	silc_hash_table_list_reset(&htl);
	if (!found)
		return;

	/* Call TOPIC */
	silc_client_command_call(client, conn, NULL, "TOPIC",
				 chu->channel->channel_name, topic, NULL);
}

PurpleRoomlist *silcpurple_roomlist_get_list(PurpleConnection *gc)
{
	SilcPurple sg = gc->proto_data;
	SilcClient client = sg->client;
	SilcClientConnection conn = sg->conn;
	GList *fields = NULL;
	PurpleRoomlistField *f;

	if (!conn)
		return NULL;

	if (sg->roomlist)
		purple_roomlist_unref(sg->roomlist);

	sg->roomlist_cancelled = FALSE;

	sg->roomlist = purple_roomlist_new(purple_connection_get_account(gc));
	f = purple_roomlist_field_new(PURPLE_ROOMLIST_FIELD_STRING, "", "channel", TRUE);
	fields = g_list_append(fields, f);
	f = purple_roomlist_field_new(PURPLE_ROOMLIST_FIELD_INT,
				    _("Users"), "users", FALSE);
	fields = g_list_append(fields, f);
	f = purple_roomlist_field_new(PURPLE_ROOMLIST_FIELD_STRING,
				    _("Topic"), "topic", FALSE);
	fields = g_list_append(fields, f);
	purple_roomlist_set_fields(sg->roomlist, fields);

	/* Call LIST */
	silc_client_command_call(client, conn, "LIST");

	purple_roomlist_set_in_progress(sg->roomlist, TRUE);

	return sg->roomlist;
}

void silcpurple_roomlist_cancel(PurpleRoomlist *list)
{
	PurpleConnection *gc = purple_account_get_connection(list->account);
	SilcPurple sg;

	if (!gc)
		return;
	sg = gc->proto_data;

	purple_roomlist_set_in_progress(list, FALSE);
	if (sg->roomlist == list) {
		purple_roomlist_unref(sg->roomlist);
		sg->roomlist = NULL;
		sg->roomlist_cancelled = TRUE;
	}
}
