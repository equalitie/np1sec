/**
 * @file slpcall.c SLP Call Functions
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
#include "smiley.h"

#include "msnutils.h"
#include "slpcall.h"

#include "slp.h"
#include "p2p.h"
#include "xfer.h"

/**************************************************************************
 * Main
 **************************************************************************/

static gboolean
msn_slpcall_timeout(gpointer data)
{
	MsnSlpCall *slpcall;

	slpcall = data;

	if (purple_debug_is_verbose())
		purple_debug_info("msn", "slpcall_timeout: slpcall(%p)\n", slpcall);

	if (!slpcall->pending && !slpcall->progress)
	{
		msn_slpcall_destroy(slpcall);
		return TRUE;
	}

	slpcall->progress = FALSE;

	return TRUE;
}

MsnSlpCall *
msn_slpcall_new(MsnSlpLink *slplink)
{
	MsnSlpCall *slpcall;

	g_return_val_if_fail(slplink != NULL, NULL);

	slpcall = g_new0(MsnSlpCall, 1);

	if (purple_debug_is_verbose())
		purple_debug_info("msn", "slpcall_new: slpcall(%p)\n", slpcall);

	slpcall->slplink = slplink;

	msn_slplink_add_slpcall(slplink, slpcall);

	slpcall->timer = purple_timeout_add_seconds(MSN_SLPCALL_TIMEOUT, msn_slpcall_timeout, slpcall);

	return slpcall;
}

void
msn_slpcall_destroy(MsnSlpCall *slpcall)
{
	GList *e;

	if (purple_debug_is_verbose())
		purple_debug_info("msn", "slpcall_destroy: slpcall(%p)\n", slpcall);

	g_return_if_fail(slpcall != NULL);

	if (slpcall->timer)
		purple_timeout_remove(slpcall->timer);

	for (e = slpcall->slplink->slp_msgs; e != NULL; )
	{
		MsnSlpMessage *slpmsg = e->data;
		e = e->next;

		if (purple_debug_is_verbose())
			purple_debug_info("msn", "slpcall_destroy: trying slpmsg(%p)\n",
			                  slpmsg);

		if (slpmsg->slpcall == slpcall)
		{
			msn_slpmsg_destroy(slpmsg);
		}
	}

	if (slpcall->end_cb != NULL)
		slpcall->end_cb(slpcall, slpcall->slplink->session);

	if (slpcall->xfer != NULL) {
		if (purple_xfer_get_type(slpcall->xfer) == PURPLE_XFER_RECEIVE)
			g_byte_array_free(slpcall->u.incoming_data, TRUE);
		slpcall->xfer->data = NULL;
		purple_xfer_unref(slpcall->xfer);
	}


	msn_slplink_remove_slpcall(slpcall->slplink, slpcall);

	g_free(slpcall->id);
	g_free(slpcall->branch);
	g_free(slpcall->data_info);

	g_free(slpcall);
}

void
msn_slpcall_init(MsnSlpCall *slpcall, MsnSlpCallType type)
{
	slpcall->session_id = rand() % 0xFFFFFF00 + 4;
	slpcall->id = rand_guid();
	slpcall->type = type;
}

void
msn_slpcall_session_init(MsnSlpCall *slpcall)
{
	if (slpcall->session_init_cb)
		slpcall->session_init_cb(slpcall);

	slpcall->started = TRUE;
}

void
msn_slpcall_invite(MsnSlpCall *slpcall, const char *euf_guid,
					MsnP2PAppId app_id, const char *context)
{
	MsnSlpLink *slplink;
	MsnSlpMessage *slpmsg;
	char *header;
	char *content;

	g_return_if_fail(slpcall != NULL);
	g_return_if_fail(context != NULL);

	slplink = slpcall->slplink;

	slpcall->branch = rand_guid();

	content = g_strdup_printf(
		"EUF-GUID: {%s}\r\n"
		"SessionID: %lu\r\n"
		"AppID: %d\r\n"
		"Context: %s\r\n\r\n",
		euf_guid,
		slpcall->session_id,
		app_id,
		context);

	header = g_strdup_printf("INVITE MSNMSGR:%s MSNSLP/1.0",
							 slplink->remote_user);

	slpmsg = msn_slpmsg_sip_new(slpcall, 0, header, slpcall->branch,
								"application/x-msnmsgr-sessionreqbody", content);

	slpmsg->info = "SLP INVITE";
	slpmsg->text_body = TRUE;

	msn_slplink_send_slpmsg(slplink, slpmsg);

	g_free(header);
	g_free(content);
}

void
msn_slpcall_close(MsnSlpCall *slpcall)
{
	g_return_if_fail(slpcall != NULL);
	g_return_if_fail(slpcall->slplink != NULL);

	send_bye(slpcall, "application/x-msnmsgr-sessionclosebody");
	msn_slplink_send_queued_slpmsgs(slpcall->slplink);
	msn_slpcall_destroy(slpcall);
}

/*****************************************************************************
 * Parse received SLP messages
 ****************************************************************************/

/**************************************************************************
 *** Util
 **************************************************************************/

static char *
get_token(const char *str, const char *start, const char *end)
{
	const char *c, *c2;

	if ((c = strstr(str, start)) == NULL)
		return NULL;

	c += strlen(start);

	if (end != NULL)
	{
		if ((c2 = strstr(c, end)) == NULL)
			return NULL;

		return g_strndup(c, c2 - c);
	}
	else
	{
		/* This has to be changed */
		return g_strdup(c);
	}

}

/* XXX: this could be improved if we tracked custom smileys
 * per-protocol, per-account, per-session or (ideally) per-conversation
 */
static PurpleStoredImage *
find_valid_emoticon(PurpleAccount *account, const char *path)
{
	GList *smileys;

	if (!purple_account_get_bool(account, "custom_smileys", TRUE))
		return NULL;

	smileys = purple_smileys_get_all();

	for (; smileys; smileys = g_list_delete_link(smileys, smileys)) {
		PurpleSmiley *smiley;
		PurpleStoredImage *img;

		smiley = smileys->data;
		img = purple_smiley_get_stored_image(smiley);

		if (purple_strequal(path, purple_imgstore_get_filename(img))) {
			g_list_free(smileys);
			return img;
		}

		purple_imgstore_unref(img);
	}

	purple_debug_error("msn", "Received illegal request for file %s\n", path);
	return NULL;
}

static char *
parse_dc_nonce(const char *content, MsnDirectConnNonceType *ntype)
{
	char *nonce;

	*ntype = DC_NONCE_UNKNOWN;

	nonce = get_token(content, "Hashed-Nonce: {", "}\r\n");
	if (nonce) {
		*ntype = DC_NONCE_SHA1;
	} else {
		guint32 n1, n6;
		guint16 n2, n3, n4, n5;
		nonce = get_token(content, "Nonce: {", "}\r\n");
		if (nonce
		 && sscanf(nonce, "%08x-%04hx-%04hx-%04hx-%04hx%08x",
		           &n1, &n2, &n3, &n4, &n5, &n6) == 6) {
			*ntype = DC_NONCE_PLAIN;
			g_free(nonce);
			nonce = g_malloc(16);
			*(guint32 *)(nonce +  0) = GUINT32_TO_LE(n1);
			*(guint16 *)(nonce +  4) = GUINT16_TO_LE(n2);
			*(guint16 *)(nonce +  6) = GUINT16_TO_LE(n3);
			*(guint16 *)(nonce +  8) = GUINT16_TO_BE(n4);
			*(guint16 *)(nonce + 10) = GUINT16_TO_BE(n5);
			*(guint32 *)(nonce + 12) = GUINT32_TO_BE(n6);
		} else {
			/* Invalid nonce, so ignore request */
			g_free(nonce);
			nonce = NULL;
		}
	}

	return nonce;
}

static void
msn_slp_process_transresp(MsnSlpCall *slpcall, const char *content)
{
	/* A direct connection negotiation response */
	char *bridge;
	char *nonce;
	char *listening;
	MsnDirectConn *dc = slpcall->slplink->dc;
	MsnDirectConnNonceType ntype;

	purple_debug_info("msn", "process_transresp\n");

	/* Direct connections are disabled. */
	if (!purple_account_get_bool(slpcall->slplink->session->account, "direct_connect", TRUE))
		return;

	g_return_if_fail(dc != NULL);
	g_return_if_fail(dc->state == DC_STATE_CLOSED);

	bridge = get_token(content, "Bridge: ", "\r\n");
	nonce = parse_dc_nonce(content, &ntype);
	listening = get_token(content, "Listening: ", "\r\n");
	if (listening && bridge && !strcmp(bridge, "TCPv1")) {
		/* Ok, the client supports direct TCP connection */

		/* We always need this. */
		if (ntype == DC_NONCE_SHA1) {
			strncpy(dc->remote_nonce, nonce, 36);
			dc->remote_nonce[36] = '\0';
		}

		if (!strcasecmp(listening, "false")) {
			if (dc->listen_data != NULL) {
				/*
				 * We'll listen for incoming connections but
				 * the listening socket isn't ready yet so we cannot
				 * send the INVITE packet now. Put the slpcall into waiting mode
				 * and let the callback send the invite.
				 */
				slpcall->wait_for_socket = TRUE;

			} else if (dc->listenfd != -1) {
				/* The listening socket is ready. Send the INVITE here. */
				msn_dc_send_invite(dc);

			} else {
				/* We weren't able to create a listener either. Use SB. */
				msn_dc_fallback_to_sb(dc);
			}

		} else {
			/*
			 * We should connect to the client so parse
			 * IP/port from response.
			 */
			char *ip, *port_str;
			int port = 0;

			if (ntype == DC_NONCE_PLAIN) {
				/* Only needed for listening side. */
				memcpy(dc->nonce, nonce, 16);
			}

			/* Cancel any listen attempts because we don't need them. */
			if (dc->listenfd_handle != 0) {
				purple_input_remove(dc->listenfd_handle);
				dc->listenfd_handle = 0;
			}
			if (dc->connect_timeout_handle != 0) {
				purple_timeout_remove(dc->connect_timeout_handle);
				dc->connect_timeout_handle = 0;
			}
			if (dc->listenfd != -1) {
				purple_network_remove_port_mapping(dc->listenfd);
				close(dc->listenfd);
				dc->listenfd = -1;
			}
			if (dc->listen_data != NULL) {
				purple_network_listen_cancel(dc->listen_data);
				dc->listen_data = NULL;
			}

			/* Save external IP/port for later use. We'll try local connection first. */
			dc->ext_ip = get_token(content, "IPv4External-Addrs: ", "\r\n");
			port_str = get_token(content, "IPv4External-Port: ", "\r\n");
			if (port_str) {
				dc->ext_port = atoi(port_str);
				g_free(port_str);
			}

			ip = get_token(content, "IPv4Internal-Addrs: ", "\r\n");
			port_str = get_token(content, "IPv4Internal-Port: ", "\r\n");
			if (port_str) {
				port = atoi(port_str);
				g_free(port_str);
			}

			if (ip && port) {
				/* Try internal address first */
				dc->connect_data = purple_proxy_connect(
					NULL,
					slpcall->slplink->session->account,
					ip,
					port,
					msn_dc_connected_to_peer_cb,
					dc
				);

				if (dc->connect_data) {
					/* Add connect timeout handle */
					dc->connect_timeout_handle = purple_timeout_add_seconds(
						DC_OUTGOING_TIMEOUT,
						msn_dc_outgoing_connection_timeout_cb,
						dc
					);
				} else {
					/*
					 * Connection failed
					 * Try external IP/port (if specified)
					 */
					msn_dc_outgoing_connection_timeout_cb(dc);
				}

			} else {
				/*
				 * Omitted or invalid internal IP address / port
				 * Try external IP/port (if specified)
				 */
				msn_dc_outgoing_connection_timeout_cb(dc);
			}

			g_free(ip);
		}

	} else {
		/*
		 * Invalid direct connect invitation or
		 * TCP connection is not supported
		 */
	}

	g_free(listening);
	g_free(nonce);
	g_free(bridge);

	return;
}

static void
got_sessionreq(MsnSlpCall *slpcall, const char *branch,
			   const char *euf_guid, const char *context)
{
	gboolean accepted = FALSE;

	if (!strcmp(euf_guid, MSN_OBJ_GUID))
	{
		/* Emoticon or UserDisplay */
		char *content;
		gsize len;
		MsnSlpLink *slplink;
		MsnSlpMessage *slpmsg;
		MsnObject *obj;
		char *msnobj_data;
		PurpleStoredImage *img = NULL;
		int type;

		/* Send Ok */
		content = g_strdup_printf("SessionID: %lu\r\n\r\n",
								  slpcall->session_id);

		msn_slp_send_ok(slpcall, branch, "application/x-msnmsgr-sessionreqbody",
				content);

		g_free(content);

		slplink = slpcall->slplink;

		msnobj_data = (char *)purple_base64_decode(context, &len);
		obj = msn_object_new_from_string(msnobj_data);
		type = msn_object_get_type(obj);
		g_free(msnobj_data);
		if (type == MSN_OBJECT_EMOTICON) {
			img = find_valid_emoticon(slplink->session->account, obj->location);
		} else if (type == MSN_OBJECT_USERTILE) {
			img = msn_object_get_image(obj);
			if (img)
				purple_imgstore_ref(img);
		}
		msn_object_destroy(obj);

		if (img != NULL) {
			/* DATA PREP */
			slpmsg = msn_slpmsg_dataprep_new(slpcall);
			msn_slplink_queue_slpmsg(slplink, slpmsg);

			/* DATA */
			slpmsg = msn_slpmsg_obj_new(slpcall, img);
			msn_slplink_queue_slpmsg(slplink, slpmsg);
			purple_imgstore_unref(img);

			accepted = TRUE;

		} else {
			purple_debug_error("msn", "Wrong object.\n");
		}
	}

	else if (!strcmp(euf_guid, MSN_FT_GUID))
	{
		/* File Transfer */
		PurpleAccount *account;
		PurpleXfer *xfer;
		MsnFileContext *file_context;
		char *buf;
		gsize bin_len;
		guint32 file_size;
		char *file_name;

		account = slpcall->slplink->session->account;

		slpcall->end_cb = msn_xfer_end_cb;
		slpcall->branch = g_strdup(branch);

		slpcall->pending = TRUE;

		xfer = purple_xfer_new(account, PURPLE_XFER_RECEIVE,
							 slpcall->slplink->remote_user);

		buf = (char *)purple_base64_decode(context, &bin_len);
		file_context = msn_file_context_from_wire(buf, bin_len);

		if (file_context != NULL) {
			file_size = file_context->file_size;

			file_name = g_convert((const gchar *)&file_context->file_name,
			                      MAX_FILE_NAME_LEN * 2,
			                      "UTF-8", "UTF-16LE",
			                      NULL, NULL, NULL);

			purple_xfer_set_filename(xfer, file_name ? file_name : "");
			g_free(file_name);
			purple_xfer_set_size(xfer, file_size);
			purple_xfer_set_init_fnc(xfer, msn_xfer_init);
			purple_xfer_set_request_denied_fnc(xfer, msn_xfer_cancel);
			purple_xfer_set_cancel_recv_fnc(xfer, msn_xfer_cancel);
			purple_xfer_set_read_fnc(xfer, msn_xfer_read);
			purple_xfer_set_write_fnc(xfer, msn_xfer_write);

			slpcall->u.incoming_data = g_byte_array_new();

			slpcall->xfer = xfer;
			purple_xfer_ref(slpcall->xfer);

			xfer->data = slpcall;

			if (file_context->preview) {
				purple_xfer_set_thumbnail(xfer, file_context->preview,
				                          file_context->preview_len,
				    					  "image/png");
				g_free(file_context->preview);
			}

			purple_xfer_request(xfer);
		}
		g_free(file_context);
		g_free(buf);

		accepted = TRUE;

	} else if (!strcmp(euf_guid, MSN_CAM_REQUEST_GUID)) {
		purple_debug_info("msn", "Cam request.\n");
		if (slpcall->slplink && slpcall->slplink->session) {
			PurpleConversation *conv;
			gchar *from = slpcall->slplink->remote_user;
			conv = purple_find_conversation_with_account(
					PURPLE_CONV_TYPE_IM, from,
					slpcall->slplink->session->account);
			if (conv) {
				char *buf;
				buf = g_strdup_printf(
						_("%s requests to view your "
						"webcam, but this request is "
						"not yet supported."), from);
				purple_conversation_write(conv, NULL, buf,
						PURPLE_MESSAGE_SYSTEM |
						PURPLE_MESSAGE_NOTIFY,
						time(NULL));
				g_free(buf);
			}
		}

	} else if (!strcmp(euf_guid, MSN_CAM_GUID)) {
		purple_debug_info("msn", "Cam invite.\n");
		if (slpcall->slplink && slpcall->slplink->session) {
			PurpleConversation *conv;
			gchar *from = slpcall->slplink->remote_user;
			conv = purple_find_conversation_with_account(
					PURPLE_CONV_TYPE_IM, from,
					slpcall->slplink->session->account);
			if (conv) {
				char *buf;
				buf = g_strdup_printf(
						_("%s invited you to view his/her webcam, but "
						"this is not yet supported."), from);
				purple_conversation_write(conv, NULL, buf,
						PURPLE_MESSAGE_SYSTEM |
						PURPLE_MESSAGE_NOTIFY,
						time(NULL));
				g_free(buf);
			}
		}

	} else
		purple_debug_warning("msn", "SLP SessionReq with unknown EUF-GUID: %s\n", euf_guid);

	if (!accepted) {
		char *content = g_strdup_printf("SessionID: %lu\r\n\r\n",
		                                slpcall->session_id);
		msn_slp_send_decline(slpcall, branch, "application/x-msnmsgr-sessionreqbody", content);
		g_free(content);
	}
}

void
send_bye(MsnSlpCall *slpcall, const char *type)
{
	MsnSlpLink *slplink;
	PurpleAccount *account;
	MsnSlpMessage *slpmsg;
	char *header;

	slplink = slpcall->slplink;

	g_return_if_fail(slplink != NULL);

	account = slplink->session->account;

	header = g_strdup_printf("BYE MSNMSGR:%s MSNSLP/1.0",
							 purple_account_get_username(account));

	slpmsg = msn_slpmsg_sip_new(slpcall, 0, header,
								"A0D624A6-6C0C-4283-A9E0-BC97B4B46D32",
								type,
								"\r\n");
	g_free(header);

	slpmsg->info = "SLP BYE";
	slpmsg->text_body = TRUE;

	msn_slplink_queue_slpmsg(slplink, slpmsg);
}

static void
got_invite(MsnSlpCall *slpcall,
		   const char *branch, const char *type, const char *content)
{
	MsnSlpLink *slplink;

	slplink = slpcall->slplink;

	if (!strcmp(type, "application/x-msnmsgr-sessionreqbody"))
	{
		char *euf_guid, *context;
		char *temp;

		euf_guid = get_token(content, "EUF-GUID: {", "}\r\n");

		temp = get_token(content, "SessionID: ", "\r\n");
		if (temp != NULL)
			slpcall->session_id = atoi(temp);
		g_free(temp);

		temp = get_token(content, "AppID: ", "\r\n");
		if (temp != NULL)
			slpcall->app_id = atoi(temp);
		g_free(temp);

		context = get_token(content, "Context: ", "\r\n");

		if (context != NULL)
			got_sessionreq(slpcall, branch, euf_guid, context);

		g_free(context);
		g_free(euf_guid);
	}
	else if (!strcmp(type, "application/x-msnmsgr-transreqbody"))
	{
		/* A direct connection negotiation request */
		char *bridges;
		char *nonce;
		MsnDirectConnNonceType ntype;

		purple_debug_info("msn", "got_invite: transreqbody received\n");

		/* Direct connections may be disabled. */
		if (!purple_account_get_bool(slplink->session->account, "direct_connect", TRUE)) {
			msn_slp_send_ok(slpcall, branch,
				"application/x-msnmsgr-transrespbody",
				"Bridge: TCPv1\r\n"
				"Listening: false\r\n"
				"Nonce: {00000000-0000-0000-0000-000000000000}\r\n"
				"\r\n");
			msn_slpcall_session_init(slpcall);

			return;
		}

		/* Don't do anything if we already have a direct connection */
		if (slplink->dc != NULL)
			return;

		bridges = get_token(content, "Bridges: ", "\r\n");
		nonce = parse_dc_nonce(content, &ntype);
		if (bridges && strstr(bridges, "TCPv1") != NULL) {
			/*
			 * Ok, the client supports direct TCP connection
			 * Try to create a listening port
			 */
			MsnDirectConn *dc;

			dc = msn_dc_new(slpcall);
			if (ntype == DC_NONCE_PLAIN) {
				/* There is only one nonce for plain auth. */
				dc->nonce_type = ntype;
				memcpy(dc->nonce, nonce, 16);
			} else if (ntype == DC_NONCE_SHA1) {
				/* Each side has a nonce in SHA1 auth. */
				dc->nonce_type = ntype;
				strncpy(dc->remote_nonce, nonce, 36);
				dc->remote_nonce[36] = '\0';
			}

			dc->listen_data = purple_network_listen_range(
				0, 0,
				SOCK_STREAM,
				msn_dc_listen_socket_created_cb,
				dc
			);

			if (dc->listen_data == NULL) {
				/* Listen socket creation failed */

				purple_debug_info("msn", "got_invite: listening failed\n");

				if (dc->nonce_type != DC_NONCE_PLAIN)
					msn_slp_send_ok(slpcall, branch,
						"application/x-msnmsgr-transrespbody",
						"Bridge: TCPv1\r\n"
						"Listening: false\r\n"
						"Hashed-Nonce: {00000000-0000-0000-0000-000000000000}\r\n"
						"\r\n");
				else
					msn_slp_send_ok(slpcall, branch,
						"application/x-msnmsgr-transrespbody",
						"Bridge: TCPv1\r\n"
						"Listening: false\r\n"
						"Nonce: {00000000-0000-0000-0000-000000000000}\r\n"
						"\r\n");

			} else {
				/*
				 * Listen socket created successfully.
				 * Don't send anything here because we don't know the parameters
				 * of the created socket yet. msn_dc_send_ok will be called from
				 * the callback function: dc_listen_socket_created_cb
				 */
				purple_debug_info("msn", "got_invite: listening socket created\n");

				dc->send_connection_info_msg_cb = msn_dc_send_ok;
				slpcall->wait_for_socket = TRUE;
			}

		} else {
			/*
			 * Invalid direct connect invitation or
			 * TCP connection is not supported.
			 */
		}

		g_free(nonce);
		g_free(bridges);
	}
	else if (!strcmp(type, "application/x-msnmsgr-transrespbody"))
	{
		/* A direct connection negotiation response */
		msn_slp_process_transresp(slpcall, content);
	}
}

static void
got_ok(MsnSlpCall *slpcall,
	   const char *type, const char *content)
{
	g_return_if_fail(slpcall != NULL);
	g_return_if_fail(type    != NULL);

	if (!strcmp(type, "application/x-msnmsgr-sessionreqbody"))
	{
		char *content;
		char *header;
		char *nonce = NULL;
		MsnSession *session = slpcall->slplink->session;
		MsnSlpMessage *msg;
		MsnDirectConn *dc;
		MsnUser *user;

		if (!purple_account_get_bool(session->account, "direct_connect", TRUE)) {
			/* Don't attempt a direct connection if disabled. */
			msn_slpcall_session_init(slpcall);
			return;
		}

		if (slpcall->slplink->dc != NULL) {
			/* If we already have an established direct connection
			 * then just start the transfer.
			 */
			msn_slpcall_session_init(slpcall);
			return;
		}

		user = msn_userlist_find_user(session->userlist,
		                              slpcall->slplink->remote_user);
		if (!user || !(user->clientid & 0xF0000000))	{
			/* Just start a normal SB transfer. */
			msn_slpcall_session_init(slpcall);
			return;
		}

		/* Try direct file transfer by sending a second INVITE */
		dc = msn_dc_new(slpcall);
		g_free(slpcall->branch);
		slpcall->branch = rand_guid();

		dc->listen_data = purple_network_listen_range(
			0, 0,
			SOCK_STREAM,
			msn_dc_listen_socket_created_cb,
			dc
		);

		header = g_strdup_printf(
			"INVITE MSNMSGR:%s MSNSLP/1.0",
			slpcall->slplink->remote_user
		);

		if (dc->nonce_type == DC_NONCE_SHA1)
			nonce = g_strdup_printf("Hashed-Nonce: {%s}\r\n", dc->nonce_hash);

		if (dc->listen_data == NULL) {
			/* Listen socket creation failed */
			purple_debug_info("msn", "got_ok: listening failed\n");

			content = g_strdup_printf(
				"Bridges: TCPv1\r\n"
				"NetID: %u\r\n"
				"Conn-Type: IP-Restrict-NAT\r\n"
				"UPnPNat: false\r\n"
				"ICF: false\r\n"
				"%s"
				"\r\n",

				rand() % G_MAXUINT32,
				nonce ? nonce : ""
			);

		} else {
			/* Listen socket created successfully. */
			purple_debug_info("msn", "got_ok: listening socket created\n");

			content = g_strdup_printf(
				"Bridges: TCPv1\r\n"
				"NetID: 0\r\n"
				"Conn-Type: Direct-Connect\r\n"
				"UPnPNat: false\r\n"
				"ICF: false\r\n"
				"%s"
				"\r\n",

				nonce ? nonce : ""
			);
		}

		msg = msn_slpmsg_sip_new(
			slpcall,
			0,
			header,
			slpcall->branch,
			"application/x-msnmsgr-transreqbody",
			content
		);
		msg->info = "DC INVITE";
		msg->text_body = TRUE;
		g_free(nonce);
		g_free(header);
		g_free(content);

		msn_slplink_queue_slpmsg(slpcall->slplink, msg);
	}
	else if (!strcmp(type, "application/x-msnmsgr-transreqbody"))
	{
		/* Do we get this? */
		purple_debug_info("msn", "OK with transreqbody\n");
	}
	else if (!strcmp(type, "application/x-msnmsgr-transrespbody"))
	{
		msn_slp_process_transresp(slpcall, content);
	}
}

static void
got_error(MsnSlpCall *slpcall,
          const char *error, const char *type, const char *content)
{
	/* It's not valid. Kill this off. */
	purple_debug_error("msn", "Received non-OK result: %s\n",
	                   error ? error : "Unknown");

	if (type && !strcmp(type, "application/x-msnmsgr-transreqbody")) {
		MsnDirectConn *dc = slpcall->slplink->dc;
		if (dc) {
			msn_dc_fallback_to_sb(dc);
			return;
		}
	}

	slpcall->wasted = TRUE;
}

static MsnSlpCall *
msn_slp_sip_recv(MsnSlpLink *slplink, const char *body)
{
	MsnSlpCall *slpcall;

	if (body == NULL)
	{
		purple_debug_warning("msn", "received bogus message\n");
		return NULL;
	}

	if (!strncmp(body, "INVITE", strlen("INVITE")))
	{
		/* This is an INVITE request */
		char *branch;
		char *call_id;
		char *content;
		char *content_type;

		/* From: <msnmsgr:buddy@hotmail.com> */
#if 0
		slpcall->remote_user = get_token(body, "From: <msnmsgr:", ">\r\n");
#endif

		branch = get_token(body, ";branch={", "}");

		call_id = get_token(body, "Call-ID: {", "}");

#if 0
		long content_len = -1;

		temp = get_token(body, "Content-Length: ", "\r\n");
		if (temp != NULL)
			content_len = atoi(temp);
		g_free(temp);
#endif
		content_type = get_token(body, "Content-Type: ", "\r\n");

		content = get_token(body, "\r\n\r\n", NULL);

		slpcall = NULL;
		if (branch && call_id)
		{
			slpcall = msn_slplink_find_slp_call(slplink, call_id);
			if (slpcall)
			{
				g_free(slpcall->branch);
				slpcall->branch = g_strdup(branch);
				got_invite(slpcall, branch, content_type, content);
			}
			else if (content_type && content)
			{
				slpcall = msn_slpcall_new(slplink);
				slpcall->id = g_strdup(call_id);
				got_invite(slpcall, branch, content_type, content);
			}
		}

		g_free(call_id);
		g_free(branch);
		g_free(content_type);
		g_free(content);
	}
	else if (!strncmp(body, "MSNSLP/1.0 ", strlen("MSNSLP/1.0 ")))
	{
		/* This is a response */
		char *content;
		char *content_type;
		/* Make sure this is "OK" */
		const char *status = body + strlen("MSNSLP/1.0 ");
		char *call_id;

		call_id = get_token(body, "Call-ID: {", "}");
		slpcall = msn_slplink_find_slp_call(slplink, call_id);
		g_free(call_id);

		g_return_val_if_fail(slpcall != NULL, NULL);

		content_type = get_token(body, "Content-Type: ", "\r\n");

		content = get_token(body, "\r\n\r\n", NULL);

		if (strncmp(status, "200 OK", 6))
		{
			char *error = NULL;
			const char *c;

			/* Eww */
			if ((c = strchr(status, '\r')) || (c = strchr(status, '\n')) ||
				(c = strchr(status, '\0')))
			{
				size_t len = c - status;
				error = g_strndup(status, len);
			}

			got_error(slpcall, error, content_type, content);
			g_free(error);

		} else {
			/* Everything's just dandy */
			got_ok(slpcall, content_type, content);
		}

		g_free(content_type);
		g_free(content);
	}
	else if (!strncmp(body, "BYE", strlen("BYE")))
	{
		/* This is a BYE request */
		char *call_id;

		call_id = get_token(body, "Call-ID: {", "}");
		slpcall = msn_slplink_find_slp_call(slplink, call_id);
		g_free(call_id);

		if (slpcall != NULL)
			slpcall->wasted = TRUE;

		/* msn_slpcall_destroy(slpcall); */
	}
	else
		slpcall = NULL;

	return slpcall;
}

MsnSlpCall *
msn_slp_process_msg(MsnSlpLink *slplink, MsnSlpMessage *slpmsg)
{
	MsnSlpCall *slpcall;
	const guchar *body;
	gsize body_len;
	guint32 session_id;
	guint32 flags;

	slpcall = NULL;
	body = slpmsg->buffer;
	body_len = msn_p2p_info_get_offset(slpmsg->p2p_info);

	session_id = msn_p2p_info_get_session_id(slpmsg->p2p_info);
	flags = msn_p2p_info_get_flags(slpmsg->p2p_info);

	if (flags == P2P_NO_FLAG || flags == P2P_WLM2009_COMP)
	{
		char *body_str;

		if (session_id == 64)
		{
			/* This is for handwritten messages (Ink) */
			GError *error = NULL;
			gsize bytes_read, bytes_written;

			body_str = g_convert((const gchar *)body, body_len / 2,
			                     "UTF-8", "UTF-16LE",
			                     &bytes_read, &bytes_written, &error);
			body_len -= bytes_read + 2;
			body += bytes_read + 2;
			if (body_str == NULL
			 || body_len <= 0
			 || strstr(body_str, "image/gif") == NULL)
			{
				if (error != NULL) {
					purple_debug_error("msn",
					                   "Unable to convert Ink header from UTF-16 to UTF-8: %s\n",
					                   error->message);
					g_error_free(error);
				}
				else
					purple_debug_error("msn",
					                   "Received Ink in unknown format\n");
				g_free(body_str);
				return NULL;
			}
			g_free(body_str);

			body_str = g_convert((const gchar *)body, body_len / 2,
			                     "UTF-8", "UTF-16LE",
			                     &bytes_read, &bytes_written, &error);
			if (!body_str)
			{
				if (error != NULL) {
					purple_debug_error("msn",
					                   "Unable to convert Ink body from UTF-16 to UTF-8: %s\n",
					                   error->message);
					g_error_free(error);
				}
				else
					purple_debug_error("msn",
					                   "Received Ink in unknown format\n");
				return NULL;
			}

			msn_switchboard_show_ink(slpmsg->slplink->swboard,
			                         slplink->remote_user,
			                         body_str);
		}
		else
		{
			body_str = g_strndup((const char *)body, body_len);
			slpcall = msn_slp_sip_recv(slplink, body_str);
		}
		g_free(body_str);
	}
	 else if (msn_p2p_msg_is_data(slpmsg->p2p_info))
	{
		slpcall = msn_slplink_find_slp_call_with_session_id(slplink, session_id);

		if (slpcall != NULL)
		{
			if (slpcall->timer) {
				purple_timeout_remove(slpcall->timer);
				slpcall->timer = 0;
			}

			if (slpcall->cb)
				slpcall->cb(slpcall, body, body_len);

			slpcall->wasted = TRUE;
		}
	}
	else if (msn_p2p_info_is_ack(slpmsg->p2p_info))
	{
		/* Acknowledgement of previous message. Don't do anything currently. */
	}
	else
		purple_debug_warning("msn", "Unprocessed SLP message with flags 0x%04x\n",
		                     flags);

	return slpcall;
}
