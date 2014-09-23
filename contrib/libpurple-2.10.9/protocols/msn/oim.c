/**
 * @file oim.c
 * 	get and send MSN offline Instant Message via SOAP request
 *	Author
 * 		MaYuan<mayuan2006@gmail.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,  USA
 */

#include "internal.h"
#include "debug.h"

#include "soap.h"
#include "oim.h"
#include "msnutils.h"

typedef struct _MsnOimSendReq {
	char *from_member;
	char *friendname;
	char *to_member;
	char *oim_msg;
} MsnOimSendReq;

typedef struct {
	MsnOim *oim;
	char *msg_id;
} MsnOimRecvData;

/*Local Function Prototype*/
static void msn_parse_oim_xml(MsnOim *oim, xmlnode *node);
static void msn_oim_free_send_req(MsnOimSendReq *req);
static void msn_oim_recv_data_free(MsnOimRecvData *data);
static void msn_oim_post_single_get_msg(MsnOim *oim, MsnOimRecvData *data);

/*new a OIM object*/
MsnOim *
msn_oim_new(MsnSession *session)
{
	MsnOim *oim;

	oim = g_new0(MsnOim, 1);
	oim->session = session;
	oim->oim_list = NULL;
	oim->run_id = rand_guid();
	oim->challenge = NULL;
	oim->send_queue = g_queue_new();
	oim->send_seq = 1;
	return oim;
}

/*destroy the oim object*/
void
msn_oim_destroy(MsnOim *oim)
{
	MsnOimSendReq *request;

	purple_debug_info("msn", "destroy the OIM %p\n", oim);
	g_free(oim->run_id);
	g_free(oim->challenge);

	while ((request = g_queue_pop_head(oim->send_queue)) != NULL)
		msn_oim_free_send_req(request);
	g_queue_free(oim->send_queue);

	while (oim->oim_list != NULL)
		msn_oim_recv_data_free((MsnOimRecvData *)oim->oim_list->data);

	g_free(oim);
}

static MsnOimSendReq *
msn_oim_new_send_req(const char *from_member, const char*friendname,
	const char* to_member, const char *msg)
{
	MsnOimSendReq *request;

	request = g_new0(MsnOimSendReq, 1);
	request->from_member	= g_strdup(from_member);
	request->friendname		= g_strdup(friendname);
	request->to_member		= g_strdup(to_member);
	request->oim_msg		= g_strdup(msg);
	return request;
}

static void
msn_oim_free_send_req(MsnOimSendReq *req)
{
	g_return_if_fail(req != NULL);

	g_free(req->from_member);
	g_free(req->friendname);
	g_free(req->to_member);
	g_free(req->oim_msg);

	g_free(req);
}

static MsnOimRecvData *
msn_oim_recv_data_new(MsnOim *oim, char *msg_id)
{
	MsnOimRecvData *data;

	data = g_new0(MsnOimRecvData, 1);
	data->oim = oim;
	data->msg_id = msg_id;

	oim->oim_list = g_list_append(oim->oim_list, data);

	return data;
}

/* Probably only good for g_list_find_custom */
static gint
msn_recv_data_equal(MsnOimRecvData *a, const char *msg_id)
{
	return strcmp(a->msg_id, msg_id);
}

static void
msn_oim_recv_data_free(MsnOimRecvData *data)
{
	data->oim->oim_list = g_list_remove(data->oim->oim_list, data);
	g_free(data->msg_id);

	g_free(data);
}

/****************************************
 * Manage OIM Tokens
 ****************************************/
typedef struct _MsnOimRequestData {
	MsnOim *oim;
	gboolean send;
	const char *action;
	const char *host;
	const char *url;
	xmlnode *body;
	MsnSoapCallback cb;
	gpointer cb_data;
} MsnOimRequestData;

static gboolean msn_oim_request_helper(MsnOimRequestData *data);

static void
msn_oim_request_cb(MsnSoapMessage *request, MsnSoapMessage *response,
	gpointer req_data)
{
	MsnOimRequestData *data = (MsnOimRequestData *)req_data;
	xmlnode *fault = NULL;
	xmlnode *faultcode = NULL;

	if (response != NULL)
		fault = xmlnode_get_child(response->xml, "Body/Fault");

	if (fault && (faultcode = xmlnode_get_child(fault, "faultcode"))) {
		gchar *faultcode_str = xmlnode_get_data(faultcode);
		gboolean need_token_update = FALSE;

		if (faultcode_str) {
			if (g_str_equal(faultcode_str, "q0:BadContextToken") ||
				g_str_equal(faultcode_str, "AuthenticationFailed") ||
				g_str_equal(faultcode_str, "s:AuthenticationFailed"))
				need_token_update = TRUE;
			else if (g_str_equal(faultcode_str, "q0:AuthenticationFailed") &&
				xmlnode_get_child(fault, "detail/RequiredAuthPolicy") != NULL)
				need_token_update = TRUE;
		}

		if (need_token_update) {
			purple_debug_warning("msn", "OIM Request Error, Updating token now.\n");
			msn_nexus_update_token(data->oim->session->nexus,
				data->send ? MSN_AUTH_LIVE_SECURE : MSN_AUTH_MESSENGER_WEB,
				(GSourceFunc)msn_oim_request_helper, data);
			g_free(faultcode_str);
			return;

		}

		g_free(faultcode_str);
	}

	if (data->cb)
		data->cb(request, response, data->cb_data);
	xmlnode_free(data->body);
	g_free(data);
}

static gboolean
msn_oim_request_helper(MsnOimRequestData *data)
{
	MsnSession *session = data->oim->session;

	if (data->send) {
		/* The Sending of OIM's uses a different token for some reason. */
		xmlnode *ticket;
		ticket = xmlnode_get_child(data->body, "Header/Ticket");
		xmlnode_set_attrib(ticket, "passport",
			msn_nexus_get_token_str(session->nexus, MSN_AUTH_LIVE_SECURE));
	}
	else
	{
		xmlnode *passport;
		xmlnode *xml_t;
		xmlnode *xml_p;
		GHashTable *token;
		const char *msn_t;
		const char *msn_p;

		token = msn_nexus_get_token(session->nexus, MSN_AUTH_MESSENGER_WEB);
		g_return_val_if_fail(token != NULL, FALSE);

		msn_t = g_hash_table_lookup(token, "t");
		msn_p = g_hash_table_lookup(token, "p");

		g_return_val_if_fail(msn_t != NULL, FALSE);
		g_return_val_if_fail(msn_p != NULL, FALSE);

		passport = xmlnode_get_child(data->body, "Header/PassportCookie");
		xml_t = xmlnode_get_child(passport, "t");
		xml_p = xmlnode_get_child(passport, "p");

		/* frees old token text, or the 'EMPTY' text if first time */
		xmlnode_free(xml_t->child);
		xmlnode_free(xml_p->child);

		xmlnode_insert_data(xml_t, msn_t, -1);
		xmlnode_insert_data(xml_p, msn_p, -1);
	}

	msn_soap_message_send(session,
		msn_soap_message_new(data->action, xmlnode_copy(data->body)),
		data->host, data->url, FALSE,
		msn_oim_request_cb, data);

	return FALSE;
}


static void
msn_oim_make_request(MsnOim *oim, gboolean send, const char *action,
	const char *host, const char *url, xmlnode *body, MsnSoapCallback cb,
	gpointer cb_data)
{
	MsnOimRequestData *data = g_new0(MsnOimRequestData, 1);
	data->oim = oim;
	data->send = send;
	data->action = action;
	data->host = host;
	data->url = url;
	data->body = body;
	data->cb = cb;
	data->cb_data = cb_data;

	msn_oim_request_helper(data);
}

/****************************************
 * OIM GetMetadata request
 * **************************************/
static void
msn_oim_get_metadata_cb(MsnSoapMessage *request, MsnSoapMessage *response,
	gpointer data)
{
	MsnOim *oim = data;

	if (response) {
		msn_parse_oim_xml(oim,
			xmlnode_get_child(response->xml, "Body/GetMetadataResponse/MD"));
	}
}

/* Post to get the OIM Metadata */
static void
msn_oim_get_metadata(MsnOim *oim)
{
	msn_oim_make_request(oim, FALSE, MSN_OIM_GET_METADATA_ACTION,
		MSN_OIM_RETRIEVE_HOST, MSN_OIM_RETRIEVE_URL,
		xmlnode_from_str(MSN_OIM_GET_METADATA_TEMPLATE, -1),
		msn_oim_get_metadata_cb, oim);
}

/****************************************
 * OIM send SOAP request
 * **************************************/
/*encode the message to OIM Message Format*/
static gchar *
msn_oim_msg_to_str(MsnOim *oim, const char *body)
{
	GString *oim_body;
	char *oim_base64;
	char *c;
	int len;
	size_t base64_len;

	purple_debug_info("msn", "Encoding OIM Message...\n");
	len = strlen(body);
	c = oim_base64 = purple_base64_encode((const guchar *)body, len);
	base64_len = strlen(oim_base64);
	purple_debug_info("msn", "Encoded base64 body:{%s}\n", oim_base64);

	oim_body = g_string_new(NULL);
	g_string_printf(oim_body, MSN_OIM_MSG_TEMPLATE,
		oim->run_id, oim->send_seq);

#define OIM_LINE_LEN 76
	while (base64_len > OIM_LINE_LEN) {
		g_string_append_len(oim_body, c, OIM_LINE_LEN);
		g_string_append_c(oim_body, '\n');
		c += OIM_LINE_LEN;
		base64_len -= OIM_LINE_LEN;
	}
#undef OIM_LINE_LEN

	g_string_append(oim_body, c);

	g_free(oim_base64);

	return g_string_free(oim_body, FALSE);
}

/*
 * Process the send return SOAP string
 * If got SOAP Fault,get the lock key,and resend it.
 */
static void
msn_oim_send_read_cb(MsnSoapMessage *request, MsnSoapMessage *response,
	gpointer data)
{
	MsnOim *oim = data;
	MsnOimSendReq *msg = g_queue_pop_head(oim->send_queue);

	g_return_if_fail(msg != NULL);

	if (response == NULL) {
		purple_debug_info("msn", "cannot send OIM: %s\n", msg->oim_msg);
	} else {
		xmlnode	*faultNode = xmlnode_get_child(response->xml, "Body/Fault");

		if (faultNode == NULL) {
			/*Send OK! return*/
			purple_debug_info("msn", "sent OIM: %s\n", msg->oim_msg);
		} else {
			xmlnode *faultcode = xmlnode_get_child(faultNode, "faultcode");

			if (faultcode) {
				char *faultcode_str = xmlnode_get_data(faultcode);

				if (faultcode_str && g_str_equal(faultcode_str, "q0:AuthenticationFailed")) {
					xmlnode *challengeNode = xmlnode_get_child(faultNode,
						"detail/LockKeyChallenge");
					char *challenge = NULL;

					if (challengeNode == NULL || (challenge = xmlnode_get_data(challengeNode)) == NULL) {
						if (oim->challenge) {
							g_free(oim->challenge);
							oim->challenge = NULL;

							purple_debug_info("msn", "Resending OIM: %s\n",
								msg->oim_msg);
							g_queue_push_head(oim->send_queue, msg);
							msn_oim_send_msg(oim);
							msg = NULL;
						} else {
							purple_debug_info("msn",
								"Can't find lock key for OIM: %s\n",
								msg->oim_msg);
						}
					} else {
						char buf[33];

						msn_handle_chl(challenge, buf);

						g_free(oim->challenge);
						oim->challenge = g_strndup(buf, sizeof(buf));
						g_free(challenge);
						purple_debug_info("msn", "Found lockkey:{%s}\n", oim->challenge);

						/*repost the send*/
						purple_debug_info("msn", "Resending OIM: %s\n", msg->oim_msg);
						g_queue_push_head(oim->send_queue, msg);
						msn_oim_send_msg(oim);
						msg = NULL;
					}
				} else {
					/* Report the error */
					const char *str_reason = NULL;

					if (faultcode_str) {
						if (g_str_equal(faultcode_str, "q0:SystemUnavailable")) {
							str_reason = _("Message was not sent because the system is "
							               "unavailable. This normally happens when the "
							               "user is blocked or does not exist.");
						} else if (g_str_equal(faultcode_str, "q0:SenderThrottleLimitExceeded")) {
							str_reason = _("Message was not sent because messages "
							               "are being sent too quickly.");
						} else if (g_str_equal(faultcode_str, "q0:InvalidContent")) {
							str_reason = _("Message was not sent because an unknown "
							               "encoding error occurred.");
						}
					}

					if (str_reason == NULL) {
						str_reason = _("Message was not sent because an unknown "
						               "error occurred.");
					}

					msn_session_report_user(oim->session, msg->to_member,
						str_reason, PURPLE_MESSAGE_ERROR);
					msn_session_report_user(oim->session, msg->to_member,
						msg->oim_msg, PURPLE_MESSAGE_RAW);
				}

				g_free(faultcode_str);
			}
		}
	}

	if (msg)
		msn_oim_free_send_req(msg);
}

void
msn_oim_prep_send_msg_info(MsnOim *oim, const char *membername,
						   const char* friendname, const char *tomember,
						   const char * msg)
{
	g_return_if_fail(oim != NULL);

	g_queue_push_tail(oim->send_queue,
		msn_oim_new_send_req(membername, friendname, tomember, msg));
}

/*post send single message request to oim server*/
void
msn_oim_send_msg(MsnOim *oim)
{
	MsnOimSendReq *oim_request;
	char *soap_body;
	char *msg_body;

	g_return_if_fail(oim != NULL);
	oim_request = g_queue_peek_head(oim->send_queue);
	g_return_if_fail(oim_request != NULL);

	purple_debug_info("msn", "Sending OIM: %s\n", oim_request->oim_msg);

	/* if we got the challenge lock key, we compute it
	 * else we go for the SOAP fault and resend it.
	 */
	if (oim->challenge == NULL){
		purple_debug_info("msn", "No lock key challenge, waiting for SOAP Fault and Resend\n");
	}

	msg_body = msn_oim_msg_to_str(oim, oim_request->oim_msg);
	soap_body = g_strdup_printf(MSN_OIM_SEND_TEMPLATE,
					oim_request->from_member,
					oim_request->friendname,
					oim_request->to_member,
					MSNP15_WLM_PRODUCT_ID,
					oim->challenge ? oim->challenge : "",
					oim->send_seq,
					msg_body);

	msn_oim_make_request(oim, TRUE, MSN_OIM_SEND_SOAP_ACTION, MSN_OIM_SEND_HOST,
		MSN_OIM_SEND_URL, xmlnode_from_str(soap_body, -1), msn_oim_send_read_cb,
		oim);

	/*increase the offline Sequence control*/
	if (oim->challenge != NULL) {
		oim->send_seq++;
	}

	g_free(msg_body);
	g_free(soap_body);
}

/****************************************
 * OIM delete SOAP request
 * **************************************/
static void
msn_oim_delete_read_cb(MsnSoapMessage *request, MsnSoapMessage *response,
	gpointer data)
{
	MsnOimRecvData *rdata = data;

	if (response && xmlnode_get_child(response->xml, "Body/Fault") == NULL)
		purple_debug_info("msn", "Delete OIM success\n");
	else
		purple_debug_info("msn", "Delete OIM failed\n");

	msn_oim_recv_data_free(rdata);
}

/*Post to get the Offline Instant Message*/
static void
msn_oim_post_delete_msg(MsnOimRecvData *rdata)
{
	MsnOim *oim = rdata->oim;
	char *msgid = rdata->msg_id;
	char *soap_body;

	purple_debug_info("msn", "Delete single OIM Message {%s}\n",msgid);

	soap_body = g_strdup_printf(MSN_OIM_DEL_TEMPLATE, msgid);

	msn_oim_make_request(oim, FALSE, MSN_OIM_DEL_SOAP_ACTION, MSN_OIM_RETRIEVE_HOST,
		MSN_OIM_RETRIEVE_URL, xmlnode_from_str(soap_body, -1), msn_oim_delete_read_cb, rdata);

	g_free(soap_body);
}

/****************************************
 * OIM get SOAP request
 * **************************************/
/* like purple_str_to_time, but different. The format of the timestamp
 * is like this: 5 Sep 2007 21:42:12 -0700 */
static time_t
msn_oim_parse_timestamp(const char *timestamp)
{
	char month_str[4], tz_str[6];
	char *tz_ptr = tz_str;
	static const char *months[] = {
		"Jan", "Feb", "Mar", "Apr", "May", "Jun",
		"Jul", "Aug", "Sep", "Oct", "Nov", "Dec", NULL
	};
	time_t tval = 0;
	struct tm t;
	memset(&t, 0, sizeof(t));

	time(&tval);
	localtime_r(&tval, &t);

	if (sscanf(timestamp, "%02d %03s %04d %02d:%02d:%02d %05s",
					&t.tm_mday, month_str, &t.tm_year,
					&t.tm_hour, &t.tm_min, &t.tm_sec, tz_str) == 7) {
		gboolean offset_positive = TRUE;
		int tzhrs;
		int tzmins;

		for (t.tm_mon = 0;
			 months[t.tm_mon] != NULL &&
				 strcmp(months[t.tm_mon], month_str) != 0; t.tm_mon++);
		if (months[t.tm_mon] != NULL) {
			if (*tz_str == '-') {
				offset_positive = FALSE;
				tz_ptr++;
			} else if (*tz_str == '+') {
				tz_ptr++;
			}

			if (sscanf(tz_ptr, "%02d%02d", &tzhrs, &tzmins) == 2) {
				time_t tzoff = tzhrs * 60 * 60 + tzmins * 60;
#ifdef _WIN32
				long sys_tzoff;
#endif

				if (offset_positive)
					tzoff *= -1;

				t.tm_year -= 1900;

#ifdef _WIN32
				if ((sys_tzoff = wpurple_get_tz_offset()) != -1)
					tzoff += sys_tzoff;
#else
#ifdef HAVE_TM_GMTOFF
				tzoff += t.tm_gmtoff;
#else
#	ifdef HAVE_TIMEZONE
				tzset();    /* making sure */
				tzoff -= timezone;
#	endif
#endif
#endif /* _WIN32 */

				return mktime(&t) + tzoff;
			}
		}
	}

	purple_debug_info("msn", "Can't parse timestamp %s\n", timestamp);
	return tval;
}

/*Post the Offline Instant Message to User Conversation*/
static void
msn_oim_report_to_user(MsnOimRecvData *rdata, const char *msg_str)
{
	MsnMessage *message;
	const char *date;
	const char *from;
	const char *boundary;
	char *decode_msg = NULL, *clean_msg = NULL;
	gsize body_len;
	char **tokens;
	char *passport = NULL;
	time_t stamp;
	const char *charset = NULL;

	message = msn_message_new(MSN_MSG_UNKNOWN);

	msn_message_parse_payload(message, msg_str, strlen(msg_str),
	                          MSG_OIM_LINE_DEM, MSG_OIM_BODY_DEM);
	purple_debug_info("msn", "oim body:{%s}\n", message->body);

	boundary = msn_message_get_header_value(message, "boundary");

	if (boundary != NULL) {
		char *bounds;
		char **part;

		bounds = g_strdup_printf("--%s" MSG_OIM_LINE_DEM, boundary);
		tokens = g_strsplit(message->body, bounds, 0);

		/* tokens+1 to skip the "This is a multipart message..." text */
		for (part = tokens+1; *part != NULL; part++) {
			MsnMessage *multipart;
			const char *type;
			multipart = msn_message_new(MSN_MSG_UNKNOWN);
			msn_message_parse_payload(multipart, *part, strlen(*part),
			                          MSG_OIM_LINE_DEM, MSG_OIM_BODY_DEM);

			type = msn_message_get_content_type(multipart);
			if (type && !strcmp(type, "text/plain")) {
				decode_msg = (char *)purple_base64_decode(multipart->body, &body_len);
				charset = msn_message_get_charset(multipart);

				msn_message_unref(multipart);
				break;
			}
			msn_message_unref(multipart);
		}

		g_strfreev(tokens);
		g_free(bounds);

		if (decode_msg == NULL) {
			purple_debug_error("msn", "Couldn't find text/plain OIM message.\n");
			msn_message_unref(message);
			return;
		}
	} else {
		decode_msg = (char *)purple_base64_decode(message->body, &body_len);
		charset = msn_message_get_charset(message);
	}

	if (charset && !((g_ascii_strncasecmp(charset, "UTF-8", 5) == 0) || (g_ascii_strncasecmp(charset, "UTF8", 4) == 0))) {
		clean_msg = g_convert(decode_msg, body_len, "UTF-8", charset, NULL, NULL, NULL);

		if (!clean_msg) {
			char *clean = purple_utf8_salvage(decode_msg);

			purple_debug_error("msn", "Failed to convert charset from %s to UTF-8 for OIM message: %s\n", charset, clean);

			clean_msg = g_strdup_printf(_("%s (There was an error receiving this message. "
			                              "Converting the encoding from %s to UTF-8 failed.)"),
			                            clean, charset);
			g_free(clean);
		}

		g_free(decode_msg);

	} else if (!g_utf8_validate(decode_msg, body_len, NULL)) {
		char *clean = purple_utf8_salvage(decode_msg);

		purple_debug_error("msn", "Received an OIM message that is not UTF-8,"
		                          " and no encoding specified: %s\n", clean);

		if (charset) {
			clean_msg = g_strdup_printf(_("%s (There was an error receiving this message."
			                              " The charset was %s, but it was not valid UTF-8.)"),
			                            clean, charset);
		} else {
			clean_msg = g_strdup_printf(_("%s (There was an error receiving this message."
			                              " The charset was missing, but it was not valid UTF-8.)"),
			                            clean);
		}

		g_free(clean);
		g_free(decode_msg);

	} else {
		clean_msg = decode_msg;
	}

	from = msn_message_get_header_value(message, "X-OIM-originatingSource");

	/* Match number to user's mobile number, FROM is a phone number
	   if the other side pages you using your phone number */
	if (from && !strncmp(from, "tel:+", 5)) {
		MsnUser *user =	msn_userlist_find_user_with_mobile_phone(
				rdata->oim->session->userlist, from + 4);

		if (user && user->passport)
			passport = g_strdup(user->passport);
	}

	if (passport == NULL) {
		char *start, *end;

		from = msn_message_get_header_value(message, "From");

		tokens = g_strsplit(from, " ", 2);
		if (tokens[1] != NULL)
			from = (const char *)tokens[1];

		start = strchr(from, '<');
		if (start != NULL) {
			start++;
			end = strchr(from, '>');
			if (end != NULL)
				passport = g_strndup(start, end - start);
		}
		if (passport == NULL)
			passport = g_strdup(_("Unknown"));

		g_strfreev(tokens);
	}

	date = msn_message_get_header_value(message, "Date");
	stamp = msn_oim_parse_timestamp(date);
	purple_debug_info("msn", "oim Date:{%s},passport{%s}\n",
	                  date, passport);

	serv_got_im(purple_account_get_connection(rdata->oim->session->account), passport, clean_msg, 0,
	            stamp);

	/*Now get the oim message ID from the oim_list.
	 * and append to read list to prepare for deleting the Offline Message when sign out
	 */
	msn_oim_post_delete_msg(rdata);

	g_free(passport);
	g_free(clean_msg);
	msn_message_unref(message);
}

/* Parse the XML data,
 * prepare to report the OIM to user
 */
static void
msn_oim_get_read_cb(MsnSoapMessage *request, MsnSoapMessage *response,
	gpointer data)
{
	MsnOimRecvData *rdata = data;

	if (response != NULL) {
		xmlnode *msg_node = xmlnode_get_child(response->xml,
			"Body/GetMessageResponse/GetMessageResult");

		if (msg_node) {
			char *msg_str = xmlnode_get_data(msg_node);
			msn_oim_report_to_user(rdata, msg_str);
			g_free(msg_str);
		} else {
			char *str = xmlnode_to_str(response->xml, NULL);
			purple_debug_info("msn", "Unknown OIM response: %s\n", str);
			g_free(str);
			msn_oim_recv_data_free(rdata);
		}
	} else {
		purple_debug_info("msn", "Failed to get OIM\n");
		msn_oim_recv_data_free(rdata);
	}

}

/* parse the oim XML data
 * and post it to the soap server to get the Offline Message
 * */
void
msn_parse_oim_msg(MsnOim *oim,const char *xmlmsg)
{
	xmlnode *node;

	purple_debug_info("msn", "%s\n", xmlmsg);

	if (!strcmp(xmlmsg, "too-large")) {
		/* Too many OIM's to send via NS, so we need to request them via SOAP. */
		msn_oim_get_metadata(oim);
	} else {
		node = xmlnode_from_str(xmlmsg, -1);
		msn_parse_oim_xml(oim, node);
		xmlnode_free(node);
	}
}

static void
msn_parse_oim_xml(MsnOim *oim, xmlnode *node)
{
	xmlnode *mNode;
	xmlnode *iu_node;
	MsnSession *session = oim->session;

	g_return_if_fail(node != NULL);

	if (strcmp(node->name, "MD") != 0) {
		char *xmlmsg = xmlnode_to_str(node, NULL);
		purple_debug_info("msn", "WTF is this? %s\n", xmlmsg);
		g_free(xmlmsg);
		return;
	}

	iu_node = xmlnode_get_child(node, "E/IU");

	if (iu_node != NULL && purple_account_get_check_mail(session->account))
	{
		char *unread = xmlnode_get_data(iu_node);
		const char *passports[2] = { msn_user_get_passport(session->user) };
		const char *urls[2] = { session->passport_info.mail_url };
		int count;

		/* XXX/khc: pretty sure this is wrong */
		if (unread && (count = atoi(unread)) > 0)
			purple_notify_emails(session->account->gc, count, FALSE, NULL,
				NULL, passports, urls, NULL, NULL);
		g_free(unread);
	}

	for(mNode = xmlnode_get_child(node, "M"); mNode;
					mNode = xmlnode_get_next_twin(mNode)){
		char *passport, *msgid, *nickname, *rtime = NULL;
		xmlnode *e_node, *i_node, *n_node, *rt_node;

		e_node = xmlnode_get_child(mNode, "E");
		passport = xmlnode_get_data(e_node);

		i_node = xmlnode_get_child(mNode, "I");
		msgid = xmlnode_get_data(i_node);

		n_node = xmlnode_get_child(mNode, "N");
		nickname = xmlnode_get_data(n_node);

		rt_node = xmlnode_get_child(mNode, "RT");
		if (rt_node != NULL) {
			rtime = xmlnode_get_data(rt_node);
		}
/*		purple_debug_info("msn", "E:{%s},I:{%s},rTime:{%s}\n",passport,msgid,rTime); */

		if (!g_list_find_custom(oim->oim_list, msgid, (GCompareFunc)msn_recv_data_equal)) {
			MsnOimRecvData *data = msn_oim_recv_data_new(oim, msgid);
			msn_oim_post_single_get_msg(oim, data);
			msgid = NULL;
		}

		g_free(passport);
		g_free(msgid);
		g_free(rtime);
		g_free(nickname);
	}
}

/*Post to get the Offline Instant Message*/
static void
msn_oim_post_single_get_msg(MsnOim *oim, MsnOimRecvData *data)
{
	char *soap_body;

	purple_debug_info("msn", "Get single OIM Message\n");

	soap_body = g_strdup_printf(MSN_OIM_GET_TEMPLATE, data->msg_id);

	msn_oim_make_request(oim, FALSE, MSN_OIM_GET_SOAP_ACTION, MSN_OIM_RETRIEVE_HOST,
		MSN_OIM_RETRIEVE_URL, xmlnode_from_str(soap_body, -1), msn_oim_get_read_cb,
		data);

	g_free(soap_body);
}

