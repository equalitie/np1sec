/*

  silcpurple.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2004 - 2005 Pekka Riikonen

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
#include "version.h"
#include "wb.h"
#include "core.h"

extern SilcClientOperations ops;
static PurplePlugin *silc_plugin = NULL;

static const char *
silcpurple_list_icon(PurpleAccount *a, PurpleBuddy *b)
{
	return (const char *)"silc";
}

static GList *
silcpurple_away_states(PurpleAccount *account)
{
	PurpleStatusType *type;
	GList *types = NULL;

	type = purple_status_type_new_full(PURPLE_STATUS_AVAILABLE, SILCPURPLE_STATUS_ID_AVAILABLE, NULL, TRUE, TRUE, FALSE);
	types = g_list_append(types, type);
	type = purple_status_type_new_full(PURPLE_STATUS_AVAILABLE, SILCPURPLE_STATUS_ID_HYPER, _("Hyper Active"), TRUE, TRUE, FALSE);
	types = g_list_append(types, type);
	type = purple_status_type_new_full(PURPLE_STATUS_AWAY, SILCPURPLE_STATUS_ID_AWAY, NULL, TRUE, TRUE, FALSE);
	types = g_list_append(types, type);
	type = purple_status_type_new_full(PURPLE_STATUS_UNAVAILABLE, SILCPURPLE_STATUS_ID_BUSY, _("Busy"), TRUE, TRUE, FALSE);
	types = g_list_append(types, type);
	type = purple_status_type_new_full(PURPLE_STATUS_AWAY, SILCPURPLE_STATUS_ID_INDISPOSED, _("Indisposed"), TRUE, TRUE, FALSE);
	types = g_list_append(types, type);
	type = purple_status_type_new_full(PURPLE_STATUS_AWAY, SILCPURPLE_STATUS_ID_PAGE, _("Wake Me Up"), TRUE, TRUE, FALSE);
	types = g_list_append(types, type);
	type = purple_status_type_new_full(PURPLE_STATUS_OFFLINE, SILCPURPLE_STATUS_ID_OFFLINE, NULL, TRUE, TRUE, FALSE);
	types = g_list_append(types, type);

	return types;
}

static void
silcpurple_set_status(PurpleAccount *account, PurpleStatus *status)
{
	PurpleConnection *gc = purple_account_get_connection(account);
	SilcPurple sg = NULL;
	SilcUInt32 mode;
	SilcBuffer idp;
	unsigned char mb[4];
	const char *state;

	if (gc != NULL)
		sg = gc->proto_data;

	if (status == NULL)
		return;

	state = purple_status_get_id(status);

	if (state == NULL)
		return;

	if ((sg == NULL) || (sg->conn == NULL))
		return;

	mode = sg->conn->local_entry->mode;
	mode &= ~(SILC_UMODE_GONE |
		  SILC_UMODE_HYPER |
		  SILC_UMODE_BUSY |
		  SILC_UMODE_INDISPOSED |
		  SILC_UMODE_PAGE);

	if (!strcmp(state, "hyper"))
		mode |= SILC_UMODE_HYPER;
	else if (!strcmp(state, "away"))
		mode |= SILC_UMODE_GONE;
	else if (!strcmp(state, "busy"))
		mode |= SILC_UMODE_BUSY;
	else if (!strcmp(state, "indisposed"))
		mode |= SILC_UMODE_INDISPOSED;
	else if (!strcmp(state, "page"))
		mode |= SILC_UMODE_PAGE;

	/* Send UMODE */
	idp = silc_id_payload_encode(sg->conn->local_id, SILC_ID_CLIENT);
	SILC_PUT32_MSB(mode, mb);
	silc_client_command_send(sg->client, sg->conn, SILC_COMMAND_UMODE,
				 ++sg->conn->cmd_ident, 2,
				 1, idp->data, idp->len,
				 2, mb, sizeof(mb));
	silc_buffer_free(idp);
}


/*************************** Connection Routines *****************************/

static void
silcpurple_keepalive(PurpleConnection *gc)
{
	SilcPurple sg = gc->proto_data;
	silc_client_send_packet(sg->client, sg->conn, SILC_PACKET_HEARTBEAT,
				NULL, 0);
}

static gboolean
silcpurple_scheduler(gpointer *context)
{
	SilcPurple sg = (SilcPurple)context;
	silc_client_run_one(sg->client);
	return TRUE;
}

static void
silcpurple_nickname_parse(const char *nickname,
			char **ret_nickname)
{
	silc_parse_userfqdn(nickname, ret_nickname, NULL);
}

static void
silcpurple_login_connected(gpointer data, gint source, const gchar *error_message)
{
	PurpleConnection *gc = data;
	SilcPurple sg;
	SilcClient client;
	SilcClientConnection conn;
	PurpleAccount *account;
	SilcClientConnectionParams params;
	SilcUInt32 mask;
	const char *dfile, *tmp;
#ifdef SILC_ATTRIBUTE_USER_ICON
	PurpleStoredImage *img;
#endif
#ifdef HAVE_SYS_UTSNAME_H
	struct utsname u;
#endif


	g_return_if_fail(gc != NULL);

	sg = gc->proto_data;

	if (source < 0) {
		purple_connection_error_reason(gc,
			PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
			_("Connection failed"));
		return;
	}

	client = sg->client;
	account = sg->account;

	/* Get session detachment data, if available */
	memset(&params, 0, sizeof(params));
	dfile = silcpurple_session_file(purple_account_get_username(sg->account));
	params.detach_data = (unsigned char *)silc_file_readfile(dfile, &params.detach_data_len);
	if (params.detach_data)
		params.detach_data[params.detach_data_len] = 0;

	/* Add connection to SILC client library */
	conn = silc_client_add_connection(
			  sg->client, &params,
			  (char *)purple_account_get_string(account, "server",
							  "silc.silcnet.org"),
			  purple_account_get_int(account, "port", 706), sg);
	if (!conn) {
		purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
			_("Unable to initialize SILC Client connection"));
		gc->proto_data = NULL;
		return;
	}
	sg->conn = conn;

	/* Progress */
	if (params.detach_data) {
		purple_connection_update_progress(gc, _("Resuming session"), 2, 5);
		sg->resuming = TRUE;
	} else {
		purple_connection_update_progress(gc, _("Performing key exchange"), 2, 5);
	}

	/* Perform SILC Key Exchange.  The "silc_connected" will be called
	   eventually. */
	silc_client_start_key_exchange(sg->client, sg->conn, source);

	/* Set default attributes */
	mask = SILC_ATTRIBUTE_MOOD_NORMAL;
	silc_client_attribute_add(client, conn,
				  SILC_ATTRIBUTE_STATUS_MOOD,
				  SILC_32_TO_PTR(mask),
				  sizeof(SilcUInt32));
	mask = SILC_ATTRIBUTE_CONTACT_CHAT;
	silc_client_attribute_add(client, conn,
				  SILC_ATTRIBUTE_PREFERRED_CONTACT,
				  SILC_32_TO_PTR(mask),
				  sizeof(SilcUInt32));
#ifdef HAVE_SYS_UTSNAME_H
	if (!uname(&u)) {
		SilcAttributeObjDevice dev;
		memset(&dev, 0, sizeof(dev));
		dev.type = SILC_ATTRIBUTE_DEVICE_COMPUTER;
		dev.version = u.release;
		dev.model = u.sysname;
		silc_client_attribute_add(client, conn,
					  SILC_ATTRIBUTE_DEVICE_INFO,
					  (void *)&dev, sizeof(dev));
	}
#endif
#ifdef _WIN32
	tmp = _tzname[0];
#else
	tmp = tzname[0];
#endif
	silc_client_attribute_add(client, conn,
				  SILC_ATTRIBUTE_TIMEZONE,
				  (void *)tmp, strlen(tmp));

#ifdef SILC_ATTRIBUTE_USER_ICON
	/* Set our buddy icon */
	img = purple_buddy_icons_find_account_icon(account);
	silcpurple_buddy_set_icon(gc, img);
	purple_imgstore_unref(img);
#endif

	silc_free(params.detach_data);
}

static void
silcpurple_login(PurpleAccount *account)
{
	SilcPurple sg;
	SilcClient client;
	SilcClientParams params;
	PurpleConnection *gc;
	char pkd[256], prd[256];
	const char *cipher, *hmac;
	char *realname;
	int i;

	gc = account->gc;
	if (!gc)
		return;
	gc->proto_data = NULL;

	memset(&params, 0, sizeof(params));
	strcat(params.nickname_format, "%n@%h%a");
	params.nickname_parse = silcpurple_nickname_parse;
	params.ignore_requested_attributes = FALSE;

	/* Allocate SILC client */
	client = silc_client_alloc(&ops, &params, gc, NULL);
	if (!client) {
		purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_OTHER_ERROR,
		                             _("Out of memory"));
		return;
	}

	/* Get username, real name and local hostname for SILC library */
	if (purple_account_get_username(account)) {
		const char *u = purple_account_get_username(account);
		char **up = g_strsplit(u, "@", 2);
		client->username = strdup(up[0]);
		g_strfreev(up);
	} else {
		client->username = silc_get_username();
		purple_account_set_username(account, client->username);
	}
	realname = silc_get_real_name();
	if (purple_account_get_user_info(account)) {
		client->realname = strdup(purple_account_get_user_info(account));
		free(realname);
	} else if ((silc_get_real_name() != NULL) && (*realname != '\0')) {
		client->realname = realname;
		purple_account_set_user_info(account, client->realname);
	} else {
		free(realname);
		client->realname = strdup(_("John Noname"));
	}
	client->hostname = silc_net_localhost();

	purple_connection_set_display_name(gc, client->username);

	/* Register requested cipher and HMAC */
	cipher = purple_account_get_string(account, "cipher", SILC_DEFAULT_CIPHER);
	for (i = 0; silc_default_ciphers[i].name; i++)
		if (!strcmp(silc_default_ciphers[i].name, cipher)) {
			silc_cipher_register(&(silc_default_ciphers[i]));
			break;
		}
	hmac = purple_account_get_string(account, "hmac", SILC_DEFAULT_HMAC);
	for (i = 0; silc_default_hmacs[i].name; i++)
		if (!strcmp(silc_default_hmacs[i].name, hmac)) {
			silc_hmac_register(&(silc_default_hmacs[i]));
			break;
		}

	/* Init SILC client */
	if (!silc_client_init(client)) {
		purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_OTHER_ERROR,
		                             _("Unable to initialize SILC protocol"));
		return;
	}

	/* Check the ~/.silc dir and create it, and new key pair if necessary. */
	if (!silcpurple_check_silc_dir(gc)) {
		purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_OTHER_ERROR,
		                             _("Error loading SILC key pair"));
		return;
	}

	/* Progress */
	purple_connection_update_progress(gc, _("Connecting to SILC Server"), 1, 5);

	/* Load SILC key pair */
	g_snprintf(pkd, sizeof(pkd), "%s" G_DIR_SEPARATOR_S "public_key.pub", silcpurple_silcdir());
	g_snprintf(prd, sizeof(prd), "%s" G_DIR_SEPARATOR_S "private_key.prv", silcpurple_silcdir());
	if (!silc_load_key_pair((char *)purple_account_get_string(account, "public-key", pkd),
							(char *)purple_account_get_string(account, "private-key", prd),
				(gc->password == NULL) ? "" : gc->password, &client->pkcs,
				&client->public_key, &client->private_key)) {
		g_snprintf(pkd, sizeof(pkd), _("Unable to load SILC key pair: %s"), g_strerror(errno));
		purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_OTHER_ERROR,
		                             pkd);
		return;
	}

	sg = silc_calloc(1, sizeof(*sg));
	if (!sg)
		return;
	memset(sg, 0, sizeof(*sg));
	sg->client = client;
	sg->gc = gc;
	sg->account = account;
	gc->proto_data = sg;

	/* Connect to the SILC server */
	if (purple_proxy_connect(gc, account,
			       purple_account_get_string(account, "server",
						       "silc.silcnet.org"),
			       purple_account_get_int(account, "port", 706),
			       silcpurple_login_connected, gc) == NULL)
	{
		purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
		                             _("Unable to create connection"));
		return;
	}

	/* Schedule SILC using Glib's event loop */
	sg->scheduler = purple_timeout_add(300, (GSourceFunc)silcpurple_scheduler, sg);
}

static int
silcpurple_close_final(gpointer *context)
{
	SilcPurple sg = (SilcPurple)context;
	silc_client_stop(sg->client);
	silc_client_free(sg->client);
#ifdef HAVE_SILCMIME_H
	if (sg->mimeass)
		silc_mime_assembler_free(sg->mimeass);
#endif
	silc_free(sg);
	return 0;
}

static void
silcpurple_close(PurpleConnection *gc)
{
	SilcPurple sg = gc->proto_data;
	GHashTable *ui_info;
	const char *ui_name = NULL, *ui_website = NULL;
	char *quit_msg;

	g_return_if_fail(sg != NULL);

	ui_info = purple_core_get_ui_info();

	if(ui_info) {
		ui_name = g_hash_table_lookup(ui_info, "name");
		ui_website = g_hash_table_lookup(ui_info, "website");
	}

	if(!ui_name || !ui_website) {
		ui_name = "Pidgin";
		ui_website = PURPLE_WEBSITE;
	}
	quit_msg = g_strdup_printf(_("Download %s: %s"),
							   ui_name, ui_website);

	/* Send QUIT */
	silc_client_command_call(sg->client, sg->conn, NULL,
				 "QUIT", quit_msg, NULL);
	g_free(quit_msg);

	if (sg->conn)
		silc_client_close_connection(sg->client, sg->conn);

	purple_timeout_remove(sg->scheduler);
	purple_timeout_add(1, (GSourceFunc)silcpurple_close_final, sg);
}


/****************************** Protocol Actions *****************************/

static void
silcpurple_attrs_cancel(PurpleConnection *gc, PurpleRequestFields *fields)
{
	/* Nothing */
}

static void
silcpurple_attrs_cb(PurpleConnection *gc, PurpleRequestFields *fields)
{
	SilcPurple sg = gc->proto_data;
	SilcClient client = sg->client;
	SilcClientConnection conn = sg->conn;
	PurpleRequestField *f;
	char *tmp;
	SilcUInt32 tmp_len, mask;
	SilcAttributeObjService service;
	SilcAttributeObjDevice dev;
	SilcVCardStruct vcard;
	const char *val;

	sg = gc->proto_data;
	if (!sg)
		return;

	memset(&service, 0, sizeof(service));
	memset(&dev, 0, sizeof(dev));
	memset(&vcard, 0, sizeof(vcard));

	silc_client_attribute_del(client, conn,
				  SILC_ATTRIBUTE_USER_INFO, NULL);
	silc_client_attribute_del(client, conn,
				  SILC_ATTRIBUTE_SERVICE, NULL);
	silc_client_attribute_del(client, conn,
				  SILC_ATTRIBUTE_STATUS_MOOD, NULL);
	silc_client_attribute_del(client, conn,
				  SILC_ATTRIBUTE_STATUS_FREETEXT, NULL);
	silc_client_attribute_del(client, conn,
				  SILC_ATTRIBUTE_STATUS_MESSAGE, NULL);
	silc_client_attribute_del(client, conn,
				  SILC_ATTRIBUTE_PREFERRED_LANGUAGE, NULL);
	silc_client_attribute_del(client, conn,
				  SILC_ATTRIBUTE_PREFERRED_CONTACT, NULL);
	silc_client_attribute_del(client, conn,
				  SILC_ATTRIBUTE_TIMEZONE, NULL);
	silc_client_attribute_del(client, conn,
				  SILC_ATTRIBUTE_GEOLOCATION, NULL);
	silc_client_attribute_del(client, conn,
				  SILC_ATTRIBUTE_DEVICE_INFO, NULL);

	/* Set mood */
	mask = 0;
	f = purple_request_fields_get_field(fields, "mood_normal");
	if (f && purple_request_field_bool_get_value(f))
		mask |= SILC_ATTRIBUTE_MOOD_NORMAL;
	f = purple_request_fields_get_field(fields, "mood_happy");
	if (f && purple_request_field_bool_get_value(f))
		mask |= SILC_ATTRIBUTE_MOOD_HAPPY;
	f = purple_request_fields_get_field(fields, "mood_sad");
	if (f && purple_request_field_bool_get_value(f))
		mask |= SILC_ATTRIBUTE_MOOD_SAD;
	f = purple_request_fields_get_field(fields, "mood_angry");
	if (f && purple_request_field_bool_get_value(f))
		mask |= SILC_ATTRIBUTE_MOOD_ANGRY;
	f = purple_request_fields_get_field(fields, "mood_jealous");
	if (f && purple_request_field_bool_get_value(f))
		mask |= SILC_ATTRIBUTE_MOOD_JEALOUS;
	f = purple_request_fields_get_field(fields, "mood_ashamed");
	if (f && purple_request_field_bool_get_value(f))
		mask |= SILC_ATTRIBUTE_MOOD_ASHAMED;
	f = purple_request_fields_get_field(fields, "mood_invincible");
	if (f && purple_request_field_bool_get_value(f))
		mask |= SILC_ATTRIBUTE_MOOD_INVINCIBLE;
	f = purple_request_fields_get_field(fields, "mood_inlove");
	if (f && purple_request_field_bool_get_value(f))
		mask |= SILC_ATTRIBUTE_MOOD_INLOVE;
	f = purple_request_fields_get_field(fields, "mood_sleepy");
	if (f && purple_request_field_bool_get_value(f))
		mask |= SILC_ATTRIBUTE_MOOD_SLEEPY;
	f = purple_request_fields_get_field(fields, "mood_bored");
	if (f && purple_request_field_bool_get_value(f))
		mask |= SILC_ATTRIBUTE_MOOD_BORED;
	f = purple_request_fields_get_field(fields, "mood_excited");
	if (f && purple_request_field_bool_get_value(f))
		mask |= SILC_ATTRIBUTE_MOOD_EXCITED;
	f = purple_request_fields_get_field(fields, "mood_anxious");
	if (f && purple_request_field_bool_get_value(f))
		mask |= SILC_ATTRIBUTE_MOOD_ANXIOUS;
	silc_client_attribute_add(client, conn,
				  SILC_ATTRIBUTE_STATUS_MOOD,
				  SILC_32_TO_PTR(mask),
				  sizeof(SilcUInt32));

	/* Set preferred contact */
	mask = 0;
	f = purple_request_fields_get_field(fields, "contact_chat");
	if (f && purple_request_field_bool_get_value(f))
		mask |= SILC_ATTRIBUTE_CONTACT_CHAT;
	f = purple_request_fields_get_field(fields, "contact_email");
	if (f && purple_request_field_bool_get_value(f))
		mask |= SILC_ATTRIBUTE_CONTACT_EMAIL;
	f = purple_request_fields_get_field(fields, "contact_call");
	if (f && purple_request_field_bool_get_value(f))
		mask |= SILC_ATTRIBUTE_CONTACT_CALL;
	f = purple_request_fields_get_field(fields, "contact_sms");
	if (f && purple_request_field_bool_get_value(f))
		mask |= SILC_ATTRIBUTE_CONTACT_SMS;
	f = purple_request_fields_get_field(fields, "contact_mms");
	if (f && purple_request_field_bool_get_value(f))
		mask |= SILC_ATTRIBUTE_CONTACT_MMS;
	f = purple_request_fields_get_field(fields, "contact_video");
	if (f && purple_request_field_bool_get_value(f))
		mask |= SILC_ATTRIBUTE_CONTACT_VIDEO;
	if (mask)
		silc_client_attribute_add(client, conn,
					  SILC_ATTRIBUTE_PREFERRED_CONTACT,
					  SILC_32_TO_PTR(mask),
					  sizeof(SilcUInt32));

	/* Set status text */
	val = NULL;
	f = purple_request_fields_get_field(fields, "status_text");
	if (f)
		val = purple_request_field_string_get_value(f);
	if (val && *val)
		silc_client_attribute_add(client, conn,
					  SILC_ATTRIBUTE_STATUS_FREETEXT,
					  (void *)val, strlen(val));

	/* Set vcard */
	val = NULL;
	f = purple_request_fields_get_field(fields, "vcard");
	if (f)
		val = purple_request_field_string_get_value(f);
	if (val && *val) {
		purple_account_set_string(sg->account, "vcard", val);
		tmp = silc_file_readfile(val, &tmp_len);
		if (tmp) {
			tmp[tmp_len] = 0;
			if (silc_vcard_decode((unsigned char *)tmp, tmp_len, &vcard))
				silc_client_attribute_add(client, conn,
							  SILC_ATTRIBUTE_USER_INFO,
							  (void *)&vcard,
							  sizeof(vcard));
		}
		silc_vcard_free(&vcard);
		silc_free(tmp);
	} else {
		purple_account_set_string(sg->account, "vcard", "");
	}

#ifdef HAVE_SYS_UTSNAME_H
	/* Set device info */
	f = purple_request_fields_get_field(fields, "device");
	if (f && purple_request_field_bool_get_value(f)) {
		struct utsname u;
		if (!uname(&u)) {
			dev.type = SILC_ATTRIBUTE_DEVICE_COMPUTER;
			dev.version = u.release;
			dev.model = u.sysname;
			silc_client_attribute_add(client, conn,
						  SILC_ATTRIBUTE_DEVICE_INFO,
						  (void *)&dev, sizeof(dev));
		}
	}
#endif

	/* Set timezone */
	val = NULL;
	f = purple_request_fields_get_field(fields, "timezone");
	if (f)
		val = purple_request_field_string_get_value(f);
	if (val && *val)
		silc_client_attribute_add(client, conn,
					  SILC_ATTRIBUTE_TIMEZONE,
					  (void *)val, strlen(val));
}

static void
silcpurple_attrs(PurplePluginAction *action)
{
	PurpleConnection *gc = (PurpleConnection *) action->context;
	SilcPurple sg = gc->proto_data;
	SilcClient client = sg->client;
	SilcClientConnection conn = sg->conn;
	PurpleRequestFields *fields;
	PurpleRequestFieldGroup *g;
	PurpleRequestField *f;
	SilcHashTable attrs;
	SilcAttributePayload attr;
	gboolean mnormal = TRUE, mhappy = FALSE, msad = FALSE,
		mangry = FALSE, mjealous = FALSE, mashamed = FALSE,
		minvincible = FALSE, minlove = FALSE, msleepy = FALSE,
		mbored = FALSE, mexcited = FALSE, manxious = FALSE;
	gboolean cemail = FALSE, ccall = FALSE, csms = FALSE,
		cmms = FALSE, cchat = TRUE, cvideo = FALSE;
	gboolean device = TRUE;
	char status[1024];

	sg = gc->proto_data;
	if (!sg)
		return;

	memset(status, 0, sizeof(status));

	attrs = silc_client_attributes_get(client, conn);
	if (attrs) {
		if (silc_hash_table_find(attrs,
					 SILC_32_TO_PTR(SILC_ATTRIBUTE_STATUS_MOOD),
					 NULL, (void *)&attr)) {
			SilcUInt32 mood = 0;
			silc_attribute_get_object(attr, &mood, sizeof(mood));
			mnormal = !mood;
			mhappy = (mood & SILC_ATTRIBUTE_MOOD_HAPPY);
			msad = (mood & SILC_ATTRIBUTE_MOOD_SAD);
			mangry = (mood & SILC_ATTRIBUTE_MOOD_ANGRY);
			mjealous = (mood & SILC_ATTRIBUTE_MOOD_JEALOUS);
			mashamed = (mood & SILC_ATTRIBUTE_MOOD_ASHAMED);
			minvincible = (mood & SILC_ATTRIBUTE_MOOD_INVINCIBLE);
			minlove = (mood & SILC_ATTRIBUTE_MOOD_INLOVE);
			msleepy = (mood & SILC_ATTRIBUTE_MOOD_SLEEPY);
			mbored = (mood & SILC_ATTRIBUTE_MOOD_BORED);
			mexcited = (mood & SILC_ATTRIBUTE_MOOD_EXCITED);
			manxious = (mood & SILC_ATTRIBUTE_MOOD_ANXIOUS);
		}

		if (silc_hash_table_find(attrs,
					 SILC_32_TO_PTR(SILC_ATTRIBUTE_PREFERRED_CONTACT),
					 NULL, (void *)&attr)) {
			SilcUInt32 contact = 0;
			silc_attribute_get_object(attr, &contact, sizeof(contact));
			cemail = (contact & SILC_ATTRIBUTE_CONTACT_EMAIL);
			ccall = (contact & SILC_ATTRIBUTE_CONTACT_CALL);
			csms = (contact & SILC_ATTRIBUTE_CONTACT_SMS);
			cmms = (contact & SILC_ATTRIBUTE_CONTACT_MMS);
			cchat = (contact & SILC_ATTRIBUTE_CONTACT_CHAT);
			cvideo = (contact & SILC_ATTRIBUTE_CONTACT_VIDEO);
		}

		if (silc_hash_table_find(attrs,
					 SILC_32_TO_PTR(SILC_ATTRIBUTE_STATUS_FREETEXT),
					 NULL, (void *)&attr))
			silc_attribute_get_object(attr, &status, sizeof(status));

		if (!silc_hash_table_find(attrs,
					  SILC_32_TO_PTR(SILC_ATTRIBUTE_DEVICE_INFO),
					  NULL, (void *)&attr))
			device = FALSE;
	}

	fields = purple_request_fields_new();

	g = purple_request_field_group_new(NULL);
	f = purple_request_field_label_new("l3", _("Your Current Mood"));
	purple_request_field_group_add_field(g, f);
	f = purple_request_field_bool_new("mood_normal", _("Normal"), mnormal);
	purple_request_field_group_add_field(g, f);
	f = purple_request_field_bool_new("mood_happy", _("Happy"), mhappy);
	purple_request_field_group_add_field(g, f);
	f = purple_request_field_bool_new("mood_sad", _("Sad"), msad);
	purple_request_field_group_add_field(g, f);
	f = purple_request_field_bool_new("mood_angry", _("Angry"), mangry);
	purple_request_field_group_add_field(g, f);
	f = purple_request_field_bool_new("mood_jealous", _("Jealous"), mjealous);
	purple_request_field_group_add_field(g, f);
	f = purple_request_field_bool_new("mood_ashamed", _("Ashamed"), mashamed);
	purple_request_field_group_add_field(g, f);
	f = purple_request_field_bool_new("mood_invincible", _("Invincible"), minvincible);
	purple_request_field_group_add_field(g, f);
	f = purple_request_field_bool_new("mood_inlove", _("In love"), minlove);
	purple_request_field_group_add_field(g, f);
	f = purple_request_field_bool_new("mood_sleepy", _("Sleepy"), msleepy);
	purple_request_field_group_add_field(g, f);
	f = purple_request_field_bool_new("mood_bored", _("Bored"), mbored);
	purple_request_field_group_add_field(g, f);
	f = purple_request_field_bool_new("mood_excited", _("Excited"), mexcited);
	purple_request_field_group_add_field(g, f);
	f = purple_request_field_bool_new("mood_anxious", _("Anxious"), manxious);
	purple_request_field_group_add_field(g, f);

	f = purple_request_field_label_new("l4", _("\nYour Preferred Contact Methods"));
	purple_request_field_group_add_field(g, f);
	f = purple_request_field_bool_new("contact_chat", _("Chat"), cchat);
	purple_request_field_group_add_field(g, f);
	f = purple_request_field_bool_new("contact_email", _("Email"), cemail);
	purple_request_field_group_add_field(g, f);
	f = purple_request_field_bool_new("contact_call", _("Phone"), ccall);
	purple_request_field_group_add_field(g, f);
	f = purple_request_field_bool_new("contact_sms", _("SMS"), csms);
	purple_request_field_group_add_field(g, f);
	f = purple_request_field_bool_new("contact_mms", _("MMS"), cmms);
	purple_request_field_group_add_field(g, f);
	f = purple_request_field_bool_new("contact_video", _("Video conferencing"), cvideo);
	purple_request_field_group_add_field(g, f);
	purple_request_fields_add_group(fields, g);

	g = purple_request_field_group_new(NULL);
	f = purple_request_field_string_new("status_text", _("Your Current Status"),
					  status[0] ? status : NULL, TRUE);
	purple_request_field_group_add_field(g, f);
	purple_request_fields_add_group(fields, g);

	g = purple_request_field_group_new(NULL);
#if 0
	f = purple_request_field_label_new("l2", _("Online Services"));
	purple_request_field_group_add_field(g, f);
	f = purple_request_field_bool_new("services",
					_("Let others see what services you are using"),
					TRUE);
	purple_request_field_group_add_field(g, f);
#endif
#ifdef HAVE_SYS_UTSNAME_H
	f = purple_request_field_bool_new("device",
					_("Let others see what computer you are using"),
					device);
	purple_request_field_group_add_field(g, f);
#endif
	purple_request_fields_add_group(fields, g);

	g = purple_request_field_group_new(NULL);
	f = purple_request_field_string_new("vcard", _("Your VCard File"),
					  purple_account_get_string(sg->account, "vcard", ""),
					  FALSE);
	purple_request_field_group_add_field(g, f);
#ifdef _WIN32
	f = purple_request_field_string_new("timezone", _("Timezone"), _tzname[0], FALSE);
#else
	f = purple_request_field_string_new("timezone", _("Timezone"), tzname[0], FALSE);
#endif
	purple_request_field_group_add_field(g, f);
	purple_request_fields_add_group(fields, g);

	purple_request_fields(gc, _("User Online Status Attributes"),
			    _("User Online Status Attributes"),
			    _("You can let other users see your online status information "
			      "and your personal information. Please fill the information "
			      "you would like other users to see about yourself."),
			    fields,
			    _("OK"), G_CALLBACK(silcpurple_attrs_cb),
			    _("Cancel"), G_CALLBACK(silcpurple_attrs_cancel),
				gc->account, NULL, NULL, gc);
}

static void
silcpurple_detach(PurplePluginAction *action)
{
	PurpleConnection *gc = (PurpleConnection *) action->context;
	SilcPurple sg;

	if (!gc)
		return;
	sg = gc->proto_data;
	if (!sg)
		return;

	/* Call DETACH */
	silc_client_command_call(sg->client, sg->conn, "DETACH");
	sg->detaching = TRUE;
}

static void
silcpurple_view_motd(PurplePluginAction *action)
{
	PurpleConnection *gc = (PurpleConnection *) action->context;
	SilcPurple sg;
	char *tmp;

	if (!gc)
		return;
	sg = gc->proto_data;
	if (!sg)
		return;

	if (!sg->motd) {
		purple_notify_error(
		     gc, _("Message of the Day"), _("No Message of the Day available"),
		     _("There is no Message of the Day associated with this connection"));
		return;
	}

	tmp = g_markup_escape_text(sg->motd, -1);
	purple_notify_formatted(gc, NULL, _("Message of the Day"), NULL,
			      tmp, NULL, NULL);
	g_free(tmp);
}

static void
silcpurple_create_keypair_cancel(PurpleConnection *gc, PurpleRequestFields *fields)
{
	/* Nothing */
}

static void
silcpurple_create_keypair_cb(PurpleConnection *gc, PurpleRequestFields *fields)
{
	SilcPurple sg = gc->proto_data;
	PurpleRequestField *f;
	const char *val, *pkfile = NULL, *prfile = NULL;
	const char *pass1 = NULL, *pass2 = NULL, *un = NULL, *hn = NULL;
	const char *rn = NULL, *e = NULL, *o = NULL, *c = NULL;
	char *identifier;
	int keylen = SILCPURPLE_DEF_PKCS_LEN;
	SilcPublicKey public_key;

	sg = gc->proto_data;
	if (!sg)
		return;

	val = NULL;
	f = purple_request_fields_get_field(fields, "pass1");
	if (f)
		val = purple_request_field_string_get_value(f);
	if (val && *val)
		pass1 = val;
	else
		pass1 = "";
	val = NULL;
	f = purple_request_fields_get_field(fields, "pass2");
	if (f)
		val = purple_request_field_string_get_value(f);
	if (val && *val)
		pass2 = val;
	else
		pass2 = "";

	if (strcmp(pass1, pass2)) {
		purple_notify_error(
		     gc, _("Create New SILC Key Pair"), _("Passphrases do not match"), NULL);
		return;
	}

	val = NULL;
	f = purple_request_fields_get_field(fields, "key");
	if (f)
		val = purple_request_field_string_get_value(f);
	if (val && *val)
		keylen = atoi(val);
	f = purple_request_fields_get_field(fields, "pkfile");
	if (f)
		pkfile = purple_request_field_string_get_value(f);
	f = purple_request_fields_get_field(fields, "prfile");
	if (f)
		prfile = purple_request_field_string_get_value(f);

	f = purple_request_fields_get_field(fields, "un");
	if (f)
		un = purple_request_field_string_get_value(f);
	f = purple_request_fields_get_field(fields, "hn");
	if (f)
		hn = purple_request_field_string_get_value(f);
	f = purple_request_fields_get_field(fields, "rn");
	if (f)
		rn = purple_request_field_string_get_value(f);
	f = purple_request_fields_get_field(fields, "e");
	if (f)
		e = purple_request_field_string_get_value(f);
	f = purple_request_fields_get_field(fields, "o");
	if (f)
		o = purple_request_field_string_get_value(f);
	f = purple_request_fields_get_field(fields, "c");
	if (f)
		c = purple_request_field_string_get_value(f);

	identifier = silc_pkcs_encode_identifier((char *)un, (char *)hn,
						 (char *)rn, (char *)e, (char *)o, (char *)c);

	/* Create the key pair */
	if (!silc_create_key_pair(SILCPURPLE_DEF_PKCS, keylen, pkfile, prfile,
				  identifier, pass1, NULL, &public_key, NULL,
				  FALSE)) {
		purple_notify_error(
		     gc, _("Create New SILC Key Pair"), _("Key Pair Generation failed"), NULL);
		return;
	}

	silcpurple_show_public_key(sg, NULL, public_key, NULL, NULL);

	silc_pkcs_public_key_free(public_key);
	silc_free(identifier);
}

static void
silcpurple_create_keypair(PurplePluginAction *action)
{
	PurpleConnection *gc = (PurpleConnection *) action->context;
	SilcPurple sg = gc->proto_data;
	PurpleRequestFields *fields;
	PurpleRequestFieldGroup *g;
	PurpleRequestField *f;
	const char *username, *realname;
	char *hostname, **u;
	char tmp[256], pkd[256], pkd2[256], prd[256], prd2[256];

	username = purple_account_get_username(sg->account);
	u = g_strsplit(username, "@", 2);
	username = u[0];
	realname = purple_account_get_user_info(sg->account);
	hostname = silc_net_localhost();
	g_snprintf(tmp, sizeof(tmp), "%s@%s", username, hostname);

	g_snprintf(pkd2, sizeof(pkd2), "%s" G_DIR_SEPARATOR_S"public_key.pub", silcpurple_silcdir());
	g_snprintf(prd2, sizeof(prd2), "%s" G_DIR_SEPARATOR_S"private_key.prv", silcpurple_silcdir());
	g_snprintf(pkd, sizeof(pkd) - 1, "%s",
		   purple_account_get_string(gc->account, "public-key", pkd2));
	g_snprintf(prd, sizeof(prd) - 1, "%s",
		   purple_account_get_string(gc->account, "private-key", prd2));

	fields = purple_request_fields_new();

	g = purple_request_field_group_new(NULL);
	f = purple_request_field_string_new("key", _("Key length"), "2048", FALSE);
	purple_request_field_group_add_field(g, f);
	f = purple_request_field_string_new("pkfile", _("Public key file"), pkd, FALSE);
	purple_request_field_group_add_field(g, f);
	f = purple_request_field_string_new("prfile", _("Private key file"), prd, FALSE);
	purple_request_field_group_add_field(g, f);
	purple_request_fields_add_group(fields, g);

	g = purple_request_field_group_new(NULL);
	f = purple_request_field_string_new("un", _("Username"), username ? username : "", FALSE);
	purple_request_field_group_add_field(g, f);
	f = purple_request_field_string_new("hn", _("Hostname"), hostname ? hostname : "", FALSE);
	purple_request_field_group_add_field(g, f);
	f = purple_request_field_string_new("rn", _("Real name"), realname ? realname : "", FALSE);
	purple_request_field_group_add_field(g, f);
	f = purple_request_field_string_new("e", _("Email"), tmp, FALSE);
	purple_request_field_group_add_field(g, f);
	f = purple_request_field_string_new("o", _("Organization"), "", FALSE);
	purple_request_field_group_add_field(g, f);
	f = purple_request_field_string_new("c", _("Country"), "", FALSE);
	purple_request_field_group_add_field(g, f);
	purple_request_fields_add_group(fields, g);

	g = purple_request_field_group_new(NULL);
	f = purple_request_field_string_new("pass1", _("Passphrase"), "", FALSE);
	purple_request_field_string_set_masked(f, TRUE);
	purple_request_field_group_add_field(g, f);
	f = purple_request_field_string_new("pass2", _("Passphrase (retype)"), "", FALSE);
	purple_request_field_string_set_masked(f, TRUE);
	purple_request_field_group_add_field(g, f);
	purple_request_fields_add_group(fields, g);

	purple_request_fields(gc, _("Create New SILC Key Pair"),
			    _("Create New SILC Key Pair"), NULL, fields,
			    _("Generate Key Pair"), G_CALLBACK(silcpurple_create_keypair_cb),
			    _("Cancel"), G_CALLBACK(silcpurple_create_keypair_cancel),
				gc->account, NULL, NULL, gc);

	g_strfreev(u);
	silc_free(hostname);
}

static void
silcpurple_change_pass(PurplePluginAction *action)
{
	PurpleConnection *gc = (PurpleConnection *) action->context;
	purple_account_request_change_password(purple_connection_get_account(gc));
}

static void
silcpurple_change_passwd(PurpleConnection *gc, const char *old, const char *new)
{
	char prd[256];
	g_snprintf(prd, sizeof(prd), "%s" G_DIR_SEPARATOR_S "private_key.pub", silcpurple_silcdir());
	silc_change_private_key_passphrase(purple_account_get_string(gc->account,
								   "private-key",
								   prd), old ? old : "", new ? new : "");
}

static void
silcpurple_show_set_info(PurplePluginAction *action)
{
	PurpleConnection *gc = (PurpleConnection *) action->context;
	purple_account_request_change_user_info(purple_connection_get_account(gc));
}

static void
silcpurple_set_info(PurpleConnection *gc, const char *text)
{
}

static GList *
silcpurple_actions(PurplePlugin *plugin, gpointer context)
{
	GList *list = NULL;
	PurplePluginAction *act;

	act = purple_plugin_action_new(_("Online Status"),
			silcpurple_attrs);
	list = g_list_append(list, act);

	act = purple_plugin_action_new(_("Detach From Server"),
			silcpurple_detach);
	list = g_list_append(list, act);

	act = purple_plugin_action_new(_("View Message of the Day"),
			silcpurple_view_motd);
	list = g_list_append(list, act);

	act = purple_plugin_action_new(_("Create SILC Key Pair..."),
			silcpurple_create_keypair);
	list = g_list_append(list, act);

	act = purple_plugin_action_new(_("Change Password..."),
			silcpurple_change_pass);
	list = g_list_append(list, act);

	act = purple_plugin_action_new(_("Set User Info..."),
			silcpurple_show_set_info);
	list = g_list_append(list, act);

	return list;
}


/******************************* IM Routines *********************************/

typedef struct {
	char *nick;
	char *message;
	SilcUInt32 message_len;
	SilcMessageFlags flags;
	PurpleMessageFlags gflags;
} *SilcPurpleIM;

static void
silcpurple_send_im_resolved(SilcClient client,
			  SilcClientConnection conn,
			  SilcClientEntry *clients,
			  SilcUInt32 clients_count,
			  void *context)
{
	PurpleConnection *gc = client->application;
	SilcPurple sg = gc->proto_data;
	SilcPurpleIM im = context;
	PurpleConversation *convo;
	char tmp[256], *nickname = NULL;
	SilcClientEntry client_entry;
#ifdef HAVE_SILCMIME_H
	SilcDList list;
#endif

	convo = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, im->nick,
							sg->account);
	if (!convo)
		return;

	if (!clients)
		goto err;

	if (clients_count > 1) {
		silc_parse_userfqdn(im->nick, &nickname, NULL);

		/* Find the correct one. The im->nick might be a formatted nick
		   so this will find the correct one. */
		clients = silc_client_get_clients_local(client, conn,
							nickname, im->nick,
							&clients_count);
		if (!clients)
			goto err;
		client_entry = clients[0];
		silc_free(clients);
	} else {
		client_entry = clients[0];
	}

#ifdef HAVE_SILCMIME_H
	/* Check for images */
	if (im->gflags & PURPLE_MESSAGE_IMAGES) {
		list = silcpurple_image_message(im->message, (SilcUInt32 *)&im->flags);
		if (list) {
			/* Send one or more MIME message.  If more than one, they
			   are MIME fragments due to over large message */
			SilcBuffer buf;

			silc_dlist_start(list);
			while ((buf = silc_dlist_get(list)) != SILC_LIST_END)
				silc_client_send_private_message(client, conn,
								 client_entry, im->flags,
								 buf->data, buf->len,
								 TRUE);
			silc_mime_partial_free(list);
			purple_conv_im_write(PURPLE_CONV_IM(convo), conn->local_entry->nickname,
				   im->message, 0, time(NULL));
			goto out;
		}
	}
#endif

	/* Send the message */
	silc_client_send_private_message(client, conn, client_entry, im->flags,
					 (unsigned char *)im->message, im->message_len, TRUE);
	purple_conv_im_write(PURPLE_CONV_IM(convo), conn->local_entry->nickname,
			   im->message, 0, time(NULL));
	goto out;

 err:
	g_snprintf(tmp, sizeof(tmp),
		   _("User <I>%s</I> is not present in the network"), im->nick);
	purple_conversation_write(convo, NULL, tmp, PURPLE_MESSAGE_SYSTEM, time(NULL));

 out:
	g_free(im->nick);
	g_free(im->message);
	silc_free(im);
	silc_free(nickname);
}

static int
silcpurple_send_im(PurpleConnection *gc, const char *who, const char *message,
		 PurpleMessageFlags flags)
{
	SilcPurple sg = gc->proto_data;
	SilcClient client = sg->client;
	SilcClientConnection conn = sg->conn;
	SilcClientEntry *clients;
	SilcUInt32 clients_count, mflags;
	char *nickname, *msg, *tmp;
	int ret = 0;
	gboolean sign = purple_account_get_bool(sg->account, "sign-verify", FALSE);
#ifdef HAVE_SILCMIME_H
	SilcDList list;
#endif

	if (!who || !message)
		return 0;

	mflags = SILC_MESSAGE_FLAG_UTF8;

	tmp = msg = purple_unescape_html(message);

	if (!g_ascii_strncasecmp(msg, "/me ", 4)) {
		msg += 4;
		if (!*msg) {
			g_free(tmp);
			return 0;
		}
		mflags |= SILC_MESSAGE_FLAG_ACTION;
	} else if (strlen(msg) > 1 && msg[0] == '/') {
		if (!silc_client_command_call(client, conn, msg + 1))
			purple_notify_error(gc, _("Call Command"), _("Cannot call command"),
					_("Unknown command"));
		g_free(tmp);
		return 0;
	}


	if (!silc_parse_userfqdn(who, &nickname, NULL)) {
		g_free(tmp);
		return 0;
	}

	if (sign)
		mflags |= SILC_MESSAGE_FLAG_SIGNED;

	/* Find client entry */
	clients = silc_client_get_clients_local(client, conn, nickname, who,
						&clients_count);
	if (!clients) {
		/* Resolve unknown user */
		SilcPurpleIM im = silc_calloc(1, sizeof(*im));
		if (!im) {
			g_free(tmp);
			return 0;
		}
		im->nick = g_strdup(who);
		im->message = g_strdup(message);
		im->message_len = strlen(im->message);
		im->flags = mflags;
		im->gflags = flags;
		silc_client_get_clients(client, conn, nickname, NULL,
					silcpurple_send_im_resolved, im);
		silc_free(nickname);
		g_free(tmp);
		return 0;
	}

#ifdef HAVE_SILCMIME_H
	/* Check for images */
	if (flags & PURPLE_MESSAGE_IMAGES) {
		list = silcpurple_image_message(message, &mflags);
		if (list) {
			/* Send one or more MIME message.  If more than one, they
			   are MIME fragments due to over large message */
			SilcBuffer buf;

			silc_dlist_start(list);
			while ((buf = silc_dlist_get(list)) != SILC_LIST_END)
				ret =
			 	silc_client_send_private_message(client, conn,
								 clients[0], mflags,
								 buf->data, buf->len,
								 TRUE);
			silc_mime_partial_free(list);
			g_free(tmp);
			silc_free(nickname);
			silc_free(clients);
			return ret;
		}
	}
#endif

	/* Send private message directly */
	ret = silc_client_send_private_message(client, conn, clients[0],
					       mflags,
					       (unsigned char *)msg,
					       strlen(msg), TRUE);

	g_free(tmp);
	silc_free(nickname);
	silc_free(clients);
	return ret;
}


static GList *silcpurple_blist_node_menu(PurpleBlistNode *node) {
	/* split this single menu building function back into the two
	   original: one for buddies and one for chats */

	if(PURPLE_BLIST_NODE_IS_CHAT(node)) {
		return silcpurple_chat_menu((PurpleChat *) node);
	} else if(PURPLE_BLIST_NODE_IS_BUDDY(node)) {
		return silcpurple_buddy_menu((PurpleBuddy *) node);
	} else {
		g_return_val_if_reached(NULL);
	}
}

/********************************* Commands **********************************/

static PurpleCmdRet silcpurple_cmd_chat_part(PurpleConversation *conv,
		const char *cmd, char **args, char **error, void *data)
{
	PurpleConnection *gc;
	PurpleConversation *convo = conv;
	int id = 0;

	gc = purple_conversation_get_gc(conv);

	if (gc == NULL)
		return PURPLE_CMD_RET_FAILED;

	if(args && args[0])
		convo = purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT, args[0],
									gc->account);

	if (convo != NULL)
		id = purple_conv_chat_get_id(PURPLE_CONV_CHAT(convo));

	if (id == 0)
		return PURPLE_CMD_RET_FAILED;

	silcpurple_chat_leave(gc, id);

	return PURPLE_CMD_RET_OK;

}

static PurpleCmdRet silcpurple_cmd_chat_topic(PurpleConversation *conv,
		const char *cmd, char **args, char **error, void *data)
{
	PurpleConnection *gc;
	int id = 0;
	char *buf, *tmp, *tmp2;
	const char *topic;

	gc = purple_conversation_get_gc(conv);
	id = purple_conv_chat_get_id(PURPLE_CONV_CHAT(conv));

	if (gc == NULL || id == 0)
		return PURPLE_CMD_RET_FAILED;

	if (!args || !args[0]) {
		topic = purple_conv_chat_get_topic (PURPLE_CONV_CHAT(conv));
		if (topic) {
			tmp = g_markup_escape_text(topic, -1);
			tmp2 = purple_markup_linkify(tmp);
			buf = g_strdup_printf(_("current topic is: %s"), tmp2);
			g_free(tmp);
			g_free(tmp2);
		} else
			buf = g_strdup(_("No topic is set"));
		purple_conv_chat_write(PURPLE_CONV_CHAT(conv), gc->account->username, buf,
							 PURPLE_MESSAGE_SYSTEM|PURPLE_MESSAGE_NO_LOG, time(NULL));
		g_free(buf);

	}

	if (args && args[0] && (strlen(args[0]) > 255)) {
		*error = g_strdup(_("Topic too long"));
		return PURPLE_CMD_RET_FAILED;
	}

	silcpurple_chat_set_topic(gc, id, args ? args[0] : NULL);

	return PURPLE_CMD_RET_OK;
}

static PurpleCmdRet silcpurple_cmd_chat_join(PurpleConversation *conv,
        const char *cmd, char **args, char **error, void *data)
{
	GHashTable *comp;

	if(!args || !args[0])
		return PURPLE_CMD_RET_FAILED;

	comp = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, NULL);

	g_hash_table_replace(comp, "channel", args[0]);
	if(args[1])
		g_hash_table_replace(comp, "passphrase", args[1]);

	silcpurple_chat_join(purple_conversation_get_gc(conv), comp);

	g_hash_table_destroy(comp);
	return PURPLE_CMD_RET_OK;
}

static PurpleCmdRet silcpurple_cmd_chat_list(PurpleConversation *conv,
        const char *cmd, char **args, char **error, void *data)
{
	PurpleConnection *gc;
	gc = purple_conversation_get_gc(conv);
	purple_roomlist_show_with_account(purple_connection_get_account(gc));
	return PURPLE_CMD_RET_OK;
}

static PurpleCmdRet silcpurple_cmd_whois(PurpleConversation *conv,
		const char *cmd, char **args, char **error, void *data)
{
	PurpleConnection *gc;

	gc = purple_conversation_get_gc(conv);

	if (gc == NULL)
		return PURPLE_CMD_RET_FAILED;

	silcpurple_get_info(gc, args[0]);

	return PURPLE_CMD_RET_OK;
}

static PurpleCmdRet silcpurple_cmd_msg(PurpleConversation *conv,
		const char *cmd, char **args, char **error, void *data)
{
	int ret;
	PurpleConnection *gc;

	gc = purple_conversation_get_gc(conv);

	if (gc == NULL)
		return PURPLE_CMD_RET_FAILED;

	ret = silcpurple_send_im(gc, args[0], args[1], PURPLE_MESSAGE_SEND);

	if (ret)
		return PURPLE_CMD_RET_OK;
	else
		return PURPLE_CMD_RET_FAILED;
}

static PurpleCmdRet silcpurple_cmd_query(PurpleConversation *conv,
		const char *cmd, char **args, char **error, void *data)
{
	int ret = 1;
	PurpleConversation *convo;
	PurpleConnection *gc;
	PurpleAccount *account;

	if (!args || !args[0]) {
		*error = g_strdup(_("You must specify a nick"));
		return PURPLE_CMD_RET_FAILED;
	}

	gc = purple_conversation_get_gc(conv);

	if (gc == NULL)
		return PURPLE_CMD_RET_FAILED;

	account = purple_connection_get_account(gc);

	convo = purple_conversation_new(PURPLE_CONV_TYPE_IM, account, args[0]);

	if (args[1]) {
		ret = silcpurple_send_im(gc, args[0], args[1], PURPLE_MESSAGE_SEND);
		purple_conv_im_write(PURPLE_CONV_IM(convo), purple_connection_get_display_name(gc),
				args[1], PURPLE_MESSAGE_SEND, time(NULL));
	}

	if (ret)
		return PURPLE_CMD_RET_OK;
	else
		return PURPLE_CMD_RET_FAILED;
}

static PurpleCmdRet silcpurple_cmd_motd(PurpleConversation *conv,
		const char *cmd, char **args, char **error, void *data)
{
	PurpleConnection *gc;
	SilcPurple sg;
	char *tmp;

	gc = purple_conversation_get_gc(conv);

	if (gc == NULL)
		return PURPLE_CMD_RET_FAILED;

	sg = gc->proto_data;

	if (sg == NULL)
		return PURPLE_CMD_RET_FAILED;

	if (!sg->motd) {
		*error = g_strdup(_("There is no Message of the Day associated with this connection"));
		return PURPLE_CMD_RET_FAILED;
	}

	tmp = g_markup_escape_text(sg->motd, -1);
	purple_notify_formatted(gc, NULL, _("Message of the Day"), NULL,
			tmp, NULL, NULL);
	g_free(tmp);

	return PURPLE_CMD_RET_OK;
}

static PurpleCmdRet silcpurple_cmd_detach(PurpleConversation *conv,
		const char *cmd, char **args, char **error, void *data)
{
	PurpleConnection *gc;
	SilcPurple sg;

	gc = purple_conversation_get_gc(conv);

	if (gc == NULL)
		return PURPLE_CMD_RET_FAILED;

	sg = gc->proto_data;

	if (sg == NULL)
		return PURPLE_CMD_RET_FAILED;

	silc_client_command_call(sg->client, sg->conn, "DETACH");
	sg->detaching = TRUE;

	return PURPLE_CMD_RET_OK;
}

static PurpleCmdRet silcpurple_cmd_cmode(PurpleConversation *conv,
		const char *cmd, char **args, char **error, void *data)
{
	PurpleConnection *gc;
	SilcPurple sg;
	SilcChannelEntry channel;
	char *silccmd, *silcargs, *msg, tmp[256];
	const char *chname;

	gc = purple_conversation_get_gc(conv);

	if (gc == NULL || !args || gc->proto_data == NULL)
		return PURPLE_CMD_RET_FAILED;

	sg = gc->proto_data;

	if (args[0])
		chname = args[0];
	else
		chname = purple_conversation_get_name(conv);

	if (!args[1]) {
		channel = silc_client_get_channel(sg->client, sg->conn,
										  (char *)chname);
		if (!channel) {
			*error = g_strdup_printf(_("channel %s not found"), chname);
			return PURPLE_CMD_RET_FAILED;
		}
		if (channel->mode) {
			silcpurple_get_chmode_string(channel->mode, tmp, sizeof(tmp));
			msg = g_strdup_printf(_("channel modes for %s: %s"), chname, tmp);
		} else {
			msg = g_strdup_printf(_("no channel modes are set on %s"), chname);
		}
		purple_conv_chat_write(PURPLE_CONV_CHAT(conv), "",
							 msg, PURPLE_MESSAGE_SYSTEM|PURPLE_MESSAGE_NO_LOG, time(NULL));
		g_free(msg);
		return PURPLE_CMD_RET_OK;
	}

	silcargs = g_strjoinv(" ", args);
	silccmd = g_strconcat(cmd, " ", args ? silcargs : NULL, NULL);
	g_free(silcargs);
	if (!silc_client_command_call(sg->client, sg->conn, silccmd)) {
		g_free(silccmd);
		*error = g_strdup_printf(_("Failed to set cmodes for %s"), args[0]);
		return PURPLE_CMD_RET_FAILED;
	}
	g_free(silccmd);

	return PURPLE_CMD_RET_OK;
}

static PurpleCmdRet silcpurple_cmd_generic(PurpleConversation *conv,
		const char *cmd, char **args, char **error, void *data)
{
	PurpleConnection *gc;
	SilcPurple sg;
	char *silccmd, *silcargs;

	gc = purple_conversation_get_gc(conv);

	if (gc == NULL)
		return PURPLE_CMD_RET_FAILED;

	sg = gc->proto_data;

	if (sg == NULL)
		return PURPLE_CMD_RET_FAILED;

	silcargs = g_strjoinv(" ", args);
	silccmd = g_strconcat(cmd, " ", args ? silcargs : NULL, NULL);
	g_free(silcargs);
	if (!silc_client_command_call(sg->client, sg->conn, silccmd)) {
		g_free(silccmd);
		*error = g_strdup_printf(_("Unknown command: %s, (may be a client bug)"), cmd);
		return PURPLE_CMD_RET_FAILED;
	}
	g_free(silccmd);

	return PURPLE_CMD_RET_OK;
}

static PurpleCmdRet silcpurple_cmd_quit(PurpleConversation *conv,
		const char *cmd, char **args, char **error, void *data)
{
	PurpleConnection *gc;
	SilcPurple sg;
	GHashTable *ui_info;
	const char *ui_name = NULL, *ui_website = NULL;
	char *quit_msg;

	gc = purple_conversation_get_gc(conv);

	if (gc == NULL)
		return PURPLE_CMD_RET_FAILED;

	sg = gc->proto_data;

	if (sg == NULL)
		return PURPLE_CMD_RET_FAILED;

	ui_info = purple_core_get_ui_info();

	if(ui_info) {
		ui_name = g_hash_table_lookup(ui_info, "name");
		ui_website = g_hash_table_lookup(ui_info, "website");
	}

	if(!ui_name || !ui_website) {
		ui_name = "Pidgin";
		ui_website = PURPLE_WEBSITE;
	}
	quit_msg = g_strdup_printf(_("Download %s: %s"),
							   ui_name, ui_website);

	silc_client_command_call(sg->client, sg->conn, NULL,
				 "QUIT", (args && args[0]) ? args[0] : quit_msg, NULL);
	g_free(quit_msg);

	return PURPLE_CMD_RET_OK;
}

static PurpleCmdRet silcpurple_cmd_call(PurpleConversation *conv,
		const char *cmd, char **args, char **error, void *data)
{
	PurpleConnection *gc;
	SilcPurple sg;

	gc = purple_conversation_get_gc(conv);

	if (gc == NULL)
		return PURPLE_CMD_RET_FAILED;

	sg = gc->proto_data;

	if (sg == NULL)
		return PURPLE_CMD_RET_FAILED;

	if (!silc_client_command_call(sg->client, sg->conn, args[0])) {
		*error = g_strdup_printf(_("Unknown command: %s"), args[0]);
		return PURPLE_CMD_RET_FAILED;
	}

	return PURPLE_CMD_RET_OK;
}


/************************** Plugin Initialization ****************************/

static void
silcpurple_register_commands(void)
{
	purple_cmd_register("part", "w", PURPLE_CMD_P_PRPL,
			PURPLE_CMD_FLAG_IM | PURPLE_CMD_FLAG_CHAT |
			PURPLE_CMD_FLAG_PRPL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
			"prpl-silc", silcpurple_cmd_chat_part, _("part [channel]:  Leave the chat"), NULL);
	purple_cmd_register("leave", "w", PURPLE_CMD_P_PRPL,
			PURPLE_CMD_FLAG_IM | PURPLE_CMD_FLAG_CHAT |
			PURPLE_CMD_FLAG_PRPL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
			"prpl-silc", silcpurple_cmd_chat_part, _("leave [channel]:  Leave the chat"), NULL);
	purple_cmd_register("topic", "s", PURPLE_CMD_P_PRPL,
			PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PRPL_ONLY |
			PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS, "prpl-silc",
			silcpurple_cmd_chat_topic, _("topic [&lt;new topic&gt;]:  View or change the topic"), NULL);
	purple_cmd_register("join", "ws", PURPLE_CMD_P_PRPL,
			PURPLE_CMD_FLAG_IM | PURPLE_CMD_FLAG_CHAT |
			PURPLE_CMD_FLAG_PRPL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
			"prpl-silc", silcpurple_cmd_chat_join,
			_("join &lt;channel&gt; [&lt;password&gt;]:  Join a chat on this network"), NULL);
	purple_cmd_register("list", "", PURPLE_CMD_P_PRPL,
			PURPLE_CMD_FLAG_IM | PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PRPL_ONLY |
			PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS, "prpl-silc",
			silcpurple_cmd_chat_list, _("list:  List channels on this network"), NULL);
	purple_cmd_register("whois", "w", PURPLE_CMD_P_PRPL,
			PURPLE_CMD_FLAG_IM | PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PRPL_ONLY,
			"prpl-silc",
			silcpurple_cmd_whois, _("whois &lt;nick&gt;:  View nick's information"), NULL);
	purple_cmd_register("msg", "ws", PURPLE_CMD_P_PRPL,
			PURPLE_CMD_FLAG_IM | PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PRPL_ONLY,
			"prpl-silc", silcpurple_cmd_msg,
			_("msg &lt;nick&gt; &lt;message&gt;:  Send a private message to a user"), NULL);
	purple_cmd_register("query", "ws", PURPLE_CMD_P_PRPL,
			PURPLE_CMD_FLAG_IM | PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PRPL_ONLY |
			PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS, "prpl-silc", silcpurple_cmd_query,
			_("query &lt;nick&gt; [&lt;message&gt;]:  Send a private message to a user"), NULL);
	purple_cmd_register("motd", "", PURPLE_CMD_P_PRPL,
			PURPLE_CMD_FLAG_IM | PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PRPL_ONLY |
			PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS, "prpl-silc", silcpurple_cmd_motd,
			_("motd:  View the server's Message Of The Day"), NULL);
	purple_cmd_register("detach", "", PURPLE_CMD_P_PRPL,
			PURPLE_CMD_FLAG_IM | PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PRPL_ONLY,
			"prpl-silc", silcpurple_cmd_detach,
			_("detach:  Detach this session"), NULL);
	purple_cmd_register("quit", "s", PURPLE_CMD_P_PRPL,
			PURPLE_CMD_FLAG_IM | PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PRPL_ONLY |
			PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS, "prpl-silc", silcpurple_cmd_quit,
			_("quit [message]:  Disconnect from the server, with an optional message"), NULL);
	purple_cmd_register("call", "s", PURPLE_CMD_P_PRPL,
			PURPLE_CMD_FLAG_IM | PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PRPL_ONLY,
			"prpl-silc", silcpurple_cmd_call,
			_("call &lt;command&gt;:  Call any silc client command"), NULL);
	/* These below just get passed through for the silc client library to deal
	 * with */
	purple_cmd_register("kill", "ws", PURPLE_CMD_P_PRPL,
			PURPLE_CMD_FLAG_IM | PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PRPL_ONLY |
			PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS, "prpl-silc", silcpurple_cmd_generic,
			_("kill &lt;nick&gt; [-pubkey|&lt;reason&gt;]:  Kill nick"), NULL);
	purple_cmd_register("nick", "w", PURPLE_CMD_P_PRPL,
			PURPLE_CMD_FLAG_IM | PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PRPL_ONLY,
			"prpl-silc", silcpurple_cmd_generic,
			_("nick &lt;newnick&gt;:  Change your nickname"), NULL);
	purple_cmd_register("whowas", "ww", PURPLE_CMD_P_PRPL,
			PURPLE_CMD_FLAG_IM | PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PRPL_ONLY |
			PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS, "prpl-silc", silcpurple_cmd_generic,
			_("whowas &lt;nick&gt;:  View nick's information"), NULL);
	purple_cmd_register("cmode", "wws", PURPLE_CMD_P_PRPL,
			PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PRPL_ONLY |
			PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS, "prpl-silc", silcpurple_cmd_cmode,
			_("cmode &lt;channel&gt; [+|-&lt;modes&gt;] [arguments]:  Change or display channel modes"), NULL);
	purple_cmd_register("cumode", "wws", PURPLE_CMD_P_PRPL,
			PURPLE_CMD_FLAG_IM | PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PRPL_ONLY |
			PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS, "prpl-silc", silcpurple_cmd_generic,
			_("cumode &lt;channel&gt; +|-&lt;modes&gt; &lt;nick&gt;:  Change nick's modes on channel"), NULL);
	purple_cmd_register("umode", "w", PURPLE_CMD_P_PRPL,
			PURPLE_CMD_FLAG_IM | PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PRPL_ONLY,
			"prpl-silc", silcpurple_cmd_generic,
			_("umode &lt;usermodes&gt;:  Set your modes in the network"), NULL);
	purple_cmd_register("oper", "s", PURPLE_CMD_P_PRPL,
			PURPLE_CMD_FLAG_IM | PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PRPL_ONLY,
			"prpl-silc", silcpurple_cmd_generic,
			_("oper &lt;nick&gt; [-pubkey]:  Get server operator privileges"), NULL);
	purple_cmd_register("invite", "ws", PURPLE_CMD_P_PRPL,
			PURPLE_CMD_FLAG_IM | PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PRPL_ONLY |
			PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS, "prpl-silc", silcpurple_cmd_generic,
			_("invite &lt;channel&gt; [-|+]&lt;nick&gt;:  invite nick or add/remove from channel invite list"), NULL);
	purple_cmd_register("kick", "wws", PURPLE_CMD_P_PRPL,
			PURPLE_CMD_FLAG_IM | PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PRPL_ONLY |
			PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS, "prpl-silc", silcpurple_cmd_generic,
			_("kick &lt;channel&gt; &lt;nick&gt; [comment]:  Kick client from channel"), NULL);
	purple_cmd_register("info", "w", PURPLE_CMD_P_PRPL,
			PURPLE_CMD_FLAG_IM | PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PRPL_ONLY |
			PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS, "prpl-silc", silcpurple_cmd_generic,
			_("info [server]:  View server administrative details"), NULL);
	purple_cmd_register("ban", "ww", PURPLE_CMD_P_PRPL,
			PURPLE_CMD_FLAG_IM | PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PRPL_ONLY |
			PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS, "prpl-silc", silcpurple_cmd_generic,
			_("ban [&lt;channel&gt; +|-&lt;nick&gt;]:  Ban client from channel"), NULL);
	purple_cmd_register("getkey", "w", PURPLE_CMD_P_PRPL,
			PURPLE_CMD_FLAG_IM | PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PRPL_ONLY,
			"prpl-silc", silcpurple_cmd_generic,
			_("getkey &lt;nick|server&gt;:  Retrieve client's or server's public key"), NULL);
	purple_cmd_register("stats", "", PURPLE_CMD_P_PRPL,
			PURPLE_CMD_FLAG_IM | PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PRPL_ONLY,
			"prpl-silc", silcpurple_cmd_generic,
			_("stats:  View server and network statistics"), NULL);
	purple_cmd_register("ping", "", PURPLE_CMD_P_PRPL,
			PURPLE_CMD_FLAG_IM | PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PRPL_ONLY,
			"prpl-silc", silcpurple_cmd_generic,
			_("ping:  Send PING to the connected server"), NULL);
#if 0 /* Purple doesn't handle these yet */
	purple_cmd_register("users", "w", PURPLE_CMD_P_PRPL,
			PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PRPL_ONLY,
			"prpl-silc", silcpurple_cmd_users,
			_("users &lt;channel&gt;:  List users in channel"));
	purple_cmd_register("names", "ww", PURPLE_CMD_P_PRPL,
			PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PRPL_ONLY |
			PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS, "prpl-silc", silcpurple_cmd_names,
			_("names [-count|-ops|-halfops|-voices|-normal] &lt;channel(s)&gt;:  List specific users in channel(s)"));
#endif
}

static PurpleWhiteboardPrplOps silcpurple_wb_ops =
{
	silcpurple_wb_start,
	silcpurple_wb_end,
	silcpurple_wb_get_dimensions,
	silcpurple_wb_set_dimensions,
	silcpurple_wb_get_brush,
	silcpurple_wb_set_brush,
	silcpurple_wb_send,
	silcpurple_wb_clear,

	/* padding */
	NULL,
	NULL,
	NULL,
	NULL
};

static PurplePluginProtocolInfo prpl_info =
{
#ifdef HAVE_SILCMIME_H
	OPT_PROTO_CHAT_TOPIC | OPT_PROTO_UNIQUE_CHATNAME |
	OPT_PROTO_PASSWORD_OPTIONAL | OPT_PROTO_IM_IMAGE |
	OPT_PROTO_SLASH_COMMANDS_NATIVE,
#else
	OPT_PROTO_CHAT_TOPIC | OPT_PROTO_UNIQUE_CHATNAME |
	OPT_PROTO_PASSWORD_OPTIONAL |
	OPT_PROTO_SLASH_COMMANDS_NATIVE,
#endif
	NULL,						/* user_splits */
	NULL,						/* protocol_options */
#ifdef SILC_ATTRIBUTE_USER_ICON
	{"jpeg,gif,png,bmp", 0, 0, 96, 96, 0, PURPLE_ICON_SCALE_DISPLAY}, /* icon_spec */
#else
	NO_BUDDY_ICONS,
#endif
	silcpurple_list_icon,			/* list_icon */
	NULL,				/* list_emblems */
	silcpurple_status_text,		/* status_text */
	silcpurple_tooltip_text,		/* tooltip_text */
	silcpurple_away_states,		/* away_states */
	silcpurple_blist_node_menu,	/* blist_node_menu */
	silcpurple_chat_info,			/* chat_info */
	silcpurple_chat_info_defaults,/* chat_info_defaults */
	silcpurple_login,				/* login */
	silcpurple_close,				/* close */
	silcpurple_send_im,			/* send_im */
	silcpurple_set_info,			/* set_info */
	NULL,						/* send_typing */
	silcpurple_get_info,			/* get_info */
	silcpurple_set_status,		/* set_status */
	silcpurple_idle_set,			/* set_idle */
	silcpurple_change_passwd,		/* change_passwd */
	silcpurple_add_buddy,			/* add_buddy */
	NULL,						/* add_buddies */
	silcpurple_remove_buddy,		/* remove_buddy */
	NULL,						/* remove_buddies */
	NULL,						/* add_permit */
	NULL,						/* add_deny */
	NULL,						/* rem_permit */
	NULL,						/* rem_deny */
	NULL,						/* set_permit_deny */
	silcpurple_chat_join,			/* join_chat */
	NULL,						/* reject_chat */
	silcpurple_get_chat_name,		/* get_chat_name */
	silcpurple_chat_invite,		/* chat_invite */
	silcpurple_chat_leave,		/* chat_leave */
	NULL,						/* chat_whisper */
	silcpurple_chat_send,			/* chat_send */
	silcpurple_keepalive,			/* keepalive */
	NULL,						/* register_user */
	NULL,						/* get_cb_info */
	NULL,						/* get_cb_away */
	NULL,						/* alias_buddy */
	NULL,						/* group_buddy */
	NULL,						/* rename_group */
	NULL,						/* buddy_free */
	NULL,						/* convo_closed */
	NULL,						/* normalize */
#ifdef SILC_ATTRIBUTE_USER_ICON
	silcpurple_buddy_set_icon,			/* set_buddy_icon */
#else
	NULL,
#endif
	NULL,						/* remove_group */
	NULL,						/* get_cb_real_name */
	silcpurple_chat_set_topic,	/* set_chat_topic */
	NULL,						/* find_blist_chat */
	silcpurple_roomlist_get_list,	/* roomlist_get_list */
	silcpurple_roomlist_cancel,	/* roomlist_cancel */
	NULL,						/* roomlist_expand_category */
	NULL,						/* can_receive_file */
	silcpurple_ftp_send_file,		/* send_file */
	silcpurple_ftp_new_xfer,		/* new_xfer */
	NULL,						/* offline_message */
	&silcpurple_wb_ops,			/* whiteboard_prpl_ops */
	NULL,                       /* send_raw */
	NULL,                       /* roomlist_room_serialize */
	NULL,                       /* unregister_user */
	NULL,                       /* send_attention */
	NULL,                       /* get_attention_types */
	sizeof(PurplePluginProtocolInfo),       /* struct_size */
	NULL,                       /* get_account_text_table */
	NULL,                       /* initiate_media */
	NULL,                       /* get_media_caps */
	NULL,                       /* get_moods */
	NULL,                       /* set_public_alias */
	NULL,                       /* get_public_alias */
	NULL,                       /* add_buddy_with_invite */
	NULL                        /* add_buddies_with_invite */
};

static PurplePluginInfo info =
{
	PURPLE_PLUGIN_MAGIC,
	PURPLE_MAJOR_VERSION,
	PURPLE_MINOR_VERSION,
	PURPLE_PLUGIN_PROTOCOL,                             /**< type           */
	NULL,                                             /**< ui_requirement */
	0,                                                /**< flags          */
	NULL,                                             /**< dependencies   */
	PURPLE_PRIORITY_DEFAULT,                            /**< priority       */

	"prpl-silc",                                      /**< id             */
	"SILC",                                           /**< name           */
	"1.0",                                            /**< version        */
	/**  summary        */
	N_("SILC Protocol Plugin"),
	/**  description    */
	N_("Secure Internet Live Conferencing (SILC) Protocol"),
	"Pekka Riikonen",                                 /**< author         */
	"http://silcnet.org/",                            /**< homepage       */

	NULL,                                             /**< load           */
	NULL,                                             /**< unload         */
	NULL,                                             /**< destroy        */

	NULL,                                             /**< ui_info        */
	&prpl_info,                                       /**< extra_info     */
	NULL,                                             /**< prefs_info     */
	silcpurple_actions,

	/* padding */
	NULL,
	NULL,
	NULL,
	NULL
};

static void
init_plugin(PurplePlugin *plugin)
{
	PurpleAccountOption *option;
	PurpleAccountUserSplit *split;
	char tmp[256];
	int i;
	PurpleKeyValuePair *kvp;
	GList *list = NULL;

	silc_plugin = plugin;

	split = purple_account_user_split_new(_("Network"), "silcnet.org", '@');
	prpl_info.user_splits = g_list_append(prpl_info.user_splits, split);

	/* Account options */
	option = purple_account_option_string_new(_("Connect server"),
						"server",
						"silc.silcnet.org");
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);
	option = purple_account_option_int_new(_("Port"), "port", 706);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);
	g_snprintf(tmp, sizeof(tmp), "%s" G_DIR_SEPARATOR_S "public_key.pub", silcpurple_silcdir());
	option = purple_account_option_string_new(_("Public Key file"),
						"public-key", tmp);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);
	g_snprintf(tmp, sizeof(tmp), "%s" G_DIR_SEPARATOR_S "private_key.prv", silcpurple_silcdir());
	option = purple_account_option_string_new(_("Private Key file"),
						"private-key", tmp);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	for (i = 0; silc_default_ciphers[i].name; i++) {
		kvp = g_new0(PurpleKeyValuePair, 1);
		kvp->key = g_strdup(silc_default_ciphers[i].name);
		kvp->value = g_strdup(silc_default_ciphers[i].name);
		list = g_list_append(list, kvp);
	}
	option = purple_account_option_list_new(_("Cipher"), "cipher", list);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	list = NULL;
	for (i = 0; silc_default_hmacs[i].name; i++) {
		kvp = g_new0(PurpleKeyValuePair, 1);
		kvp->key = g_strdup(silc_default_hmacs[i].name);
		kvp->value = g_strdup(silc_default_hmacs[i].name);
		list = g_list_append(list, kvp);
	}
	option = purple_account_option_list_new(_("HMAC"), "hmac", list);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	option = purple_account_option_bool_new(_("Public key authentication"),
					      "pubkey-auth", FALSE);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);
	option = purple_account_option_bool_new(_("Block IMs without Key Exchange"),
					      "block-ims", FALSE);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);
	option = purple_account_option_bool_new(_("Block messages to whiteboard"),
					      "block-wb", FALSE);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);
	option = purple_account_option_bool_new(_("Automatically open whiteboard"),
					      "open-wb", FALSE);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);
	option = purple_account_option_bool_new(_("Digitally sign and verify all messages"),
					      "sign-verify", FALSE);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	purple_prefs_remove("/plugins/prpl/silc");

	silcpurple_register_commands();

#ifdef _WIN32
	silc_net_win32_init();
#endif
}

PURPLE_INIT_PLUGIN(silc10, init_plugin, info);
