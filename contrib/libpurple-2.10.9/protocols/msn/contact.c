/**
 * @file contact.c
 * 	get MSN contacts via SOAP request
 *	created by MaYuan<mayuan2006@gmail.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,  USA
 */

#include "internal.h"
#include "debug.h"

#include "contact.h"
#include "xmlnode.h"
#include "group.h"
#include "msnutils.h"
#include "soap.h"
#include "nexus.h"
#include "user.h"

const char *MsnSoapPartnerScenarioText[] =
{
	"Initial",
	"ContactSave",
	"MessengerPendingList",
	"ContactMsgrAPI",
	"BlockUnblock",
	"Timer"
};

const char *MsnMemberRole[] =
{
	"Forward",
	"Allow",
	"Block",
	"Reverse",
	"Pending"
};

typedef struct {
	MsnSession *session;
	MsnSoapPartnerScenario which;
} GetContactListCbData;

MsnCallbackState *
msn_callback_state_new(MsnSession *session)
{
	MsnCallbackState *state = g_new0(MsnCallbackState, 1);

	state->session = session;

	return state;
}

MsnCallbackState *
msn_callback_state_dup(MsnCallbackState *state)
{
	MsnCallbackState *new_state = g_new0(MsnCallbackState, 1);

	new_state->session = state->session;
	new_state->who = g_strdup(state->who);
	new_state->uid = g_strdup(state->uid);
	new_state->old_group_name = g_strdup(state->old_group_name);
	new_state->new_group_name = g_strdup(state->new_group_name);
	new_state->guid = g_strdup(state->guid);
	/* The rest should be made new */

	return new_state;
}

void
msn_callback_state_free(MsnCallbackState *state)
{
	if (state == NULL)
		return;

	g_free(state->who);
	g_free(state->uid);
	g_free(state->old_group_name);
	g_free(state->new_group_name);
	g_free(state->guid);
	xmlnode_free(state->body);

	g_free(state);
}

void
msn_callback_state_set_who(MsnCallbackState *state, const gchar *who)
{
	g_return_if_fail(state != NULL);

	g_free(state->who);
	state->who = g_strdup(who);
}

void
msn_callback_state_set_uid(MsnCallbackState *state, const gchar *uid)
{
	g_return_if_fail(state != NULL);

	g_free(state->uid);
	state->uid = g_strdup(uid);
}

void
msn_callback_state_set_old_group_name(MsnCallbackState *state, const gchar *old_group_name)
{
	g_return_if_fail(state != NULL);

	g_free(state->old_group_name);
	state->old_group_name = g_strdup(old_group_name);
}

void
msn_callback_state_set_new_group_name(MsnCallbackState *state, const gchar *new_group_name)
{
	g_return_if_fail(state != NULL);

	g_free(state->new_group_name);
	state->new_group_name = g_strdup(new_group_name);
}

void
msn_callback_state_set_guid(MsnCallbackState *state, const gchar *guid)
{
	g_return_if_fail(state != NULL);

	g_free(state->guid);
	state->guid = g_strdup(guid);
}


void
msn_callback_state_set_list_id(MsnCallbackState *state, MsnListId list_id)
{
	g_return_if_fail(state != NULL);

	state->list_id = list_id;
}

void
msn_callback_state_set_action(MsnCallbackState *state, MsnCallbackAction action)
{
	g_return_if_fail(state != NULL);

	state->action |= action;
}

/***************************************************************
 * General SOAP handling
 ***************************************************************/

static const char *
msn_contact_operation_str(MsnCallbackAction action)
{
	/* Make sure this is large enough when adding more */
	static char buf[BUF_LEN];
	buf[0] = '\0';

	if (action & MSN_ADD_BUDDY)
		strcat(buf, "Adding Buddy,");
	if (action & MSN_MOVE_BUDDY)
		strcat(buf, "Moving Buddy,");
	if (action & MSN_ACCEPTED_BUDDY)
		strcat(buf, "Accepted Buddy,");
	if (action & MSN_DENIED_BUDDY)
		strcat(buf, "Denied Buddy,");
	if (action & MSN_ADD_GROUP)
		strcat(buf, "Adding Group,");
	if (action & MSN_DEL_GROUP)
		strcat(buf, "Deleting Group,");
	if (action & MSN_RENAME_GROUP)
		strcat(buf, "Renaming Group,");
	if (action & MSN_UPDATE_INFO)
		strcat(buf, "Updating Contact Info,");
	if (action & MSN_ANNOTATE_USER)
		strcat(buf, "Annotating Contact,");

	return buf;
}

static gboolean msn_contact_request(MsnCallbackState *state);

static void
msn_contact_request_cb(MsnSoapMessage *req, MsnSoapMessage *resp,
	gpointer data)
{
	MsnCallbackState *state = data;
	xmlnode *fault;
	char *faultcode_str;
	xmlnode *cachekey;
	char *changed;

	if (resp == NULL) {
		purple_debug_error("msn",
		                   "Operation {%s} failed. No response received from server.\n",
		                   msn_contact_operation_str(state->action));
		msn_session_set_error(state->session, MSN_ERROR_BAD_BLIST, NULL);
		msn_callback_state_free(state);
		return;
	}

 	/* Update CacheKey if necessary */
 	cachekey = xmlnode_get_child(resp->xml, "Header/ServiceHeader/CacheKeyChanged");
 	if (cachekey != NULL) {
 		changed = xmlnode_get_data(cachekey);
 		if (changed && !strcmp(changed, "true")) {
 			cachekey = xmlnode_get_child(resp->xml, "Header/ServiceHeader/CacheKey");
 			g_free(state->session->abch_cachekey);
 			state->session->abch_cachekey = xmlnode_get_data(cachekey);
 			purple_debug_info("msn", "Updated CacheKey for %s to '%s'.\n",
 			                  purple_account_get_username(state->session->account),
 			                  state->session->abch_cachekey);
 		}
 		g_free(changed);
 	}

	fault = xmlnode_get_child(resp->xml, "Body/Fault");

	if (fault == NULL) {
		/* No errors */
		if (state->cb)
			state->cb(req, resp, data);
		msn_callback_state_free(state);
		return;
	}

	faultcode_str = xmlnode_get_data(xmlnode_get_child(fault, "faultcode"));

	if (faultcode_str && g_str_equal(faultcode_str, "q0:BadContextToken")) {
		purple_debug_info("msn",
		                  "Contact Operation {%s} failed because of bad token."
		                  " Updating token now and retrying operation.\n",
		                  msn_contact_operation_str(state->action));
		/* Token has expired, so renew it, and try again later */
		msn_nexus_update_token(state->session->nexus, MSN_AUTH_CONTACTS,
		                       (GSourceFunc)msn_contact_request, data);
	}
	else
	{
		if (state->cb) {
			state->cb(req, resp, data);
		} else {
			/* We don't know how to respond to this faultcode, so log it */
			char *str = xmlnode_to_str(fault, NULL);
			purple_debug_error("msn", "Operation {%s} Failed, SOAP Fault was: %s\n",
			                   msn_contact_operation_str(state->action), str);
			g_free(str);
		}
		msn_callback_state_free(state);
	}

	g_free(faultcode_str);
}

static gboolean
msn_contact_request(MsnCallbackState *state)
{
	xmlnode *cachekey = xmlnode_get_child(state->body,
	                                      "Header/ABApplicationHeader/CacheKey");
	if (cachekey != NULL)
		xmlnode_free(cachekey);
	if (state->session->abch_cachekey != NULL) {
		cachekey = xmlnode_new_child(xmlnode_get_child(state->body, "Header/ABApplicationHeader"), "CacheKey");
		xmlnode_insert_data(cachekey, state->session->abch_cachekey, -1);
	}
	if (state->token == NULL)
		state->token = xmlnode_get_child(state->body,
			"Header/ABAuthHeader/TicketToken");
	/* delete old & replace with new token */
	xmlnode_free(state->token->child);
	xmlnode_insert_data(state->token,
		msn_nexus_get_token_str(state->session->nexus, MSN_AUTH_CONTACTS), -1);
	msn_soap_message_send(state->session,
		msn_soap_message_new(state->post_action, xmlnode_copy(state->body)),
		MSN_CONTACT_SERVER, state->post_url, FALSE,
		msn_contact_request_cb, state);
	return FALSE;
}

/***************************************************************
 * Address Book and Membership List Operations
 ***************************************************************/

/*get MSN member role utility*/
static MsnListId
msn_get_memberrole(const char *role)
{
	g_return_val_if_fail(role != NULL, 0);

	if (!strcmp(role,"Allow")) {
		return MSN_LIST_AL;
	} else if (!strcmp(role,"Block")) {
		return MSN_LIST_BL;
	} else if (!strcmp(role,"Reverse")) {
		return MSN_LIST_RL;
	} else if (!strcmp(role,"Pending")) {
		return MSN_LIST_PL;
	}
	return 0;
}

/* Create the AddressBook in the server, if we don't have one */
static void
msn_create_address_cb(MsnSoapMessage *req, MsnSoapMessage *resp, gpointer data)
{
	MsnCallbackState *state = data;
	if (resp && xmlnode_get_child(resp->xml, "Body/Fault") == NULL) {
		purple_debug_info("msn", "Address Book successfully created!\n");
		msn_get_address_book(state->session, MSN_PS_INITIAL, NULL, NULL);
	} else {
		purple_debug_info("msn", "Address Book creation failed!\n");
	}
}

static void
msn_create_address_book(MsnSession *session)
{
	gchar *body;
	MsnCallbackState *state;

	g_return_if_fail(session != NULL);
	g_return_if_fail(session->user != NULL);
	g_return_if_fail(session->user->passport != NULL);

	purple_debug_info("msn", "Creating an Address Book.\n");

	body = g_strdup_printf(MSN_ADD_ADDRESSBOOK_TEMPLATE,
	                       session->user->passport);

	state = msn_callback_state_new(session);
	state->body = xmlnode_from_str(body, -1);
	state->post_action = MSN_ADD_ADDRESSBOOK_SOAP_ACTION;
	state->post_url = MSN_ADDRESS_BOOK_POST_URL;
	state->cb = msn_create_address_cb;
	msn_contact_request(state);

	g_free(body);
}

static void
msn_parse_each_member(MsnSession *session, xmlnode *member, const char *node,
	MsnListId list)
{
	char *passport;
	char *type;
	char *member_id;
	MsnUser *user;
	xmlnode *annotation;
	guint nid = MSN_NETWORK_UNKNOWN;
	char *invite = NULL;

	passport = xmlnode_get_data(xmlnode_get_child(member, node));
	if (!msn_email_is_valid(passport)) {
		g_free(passport);
		return;
	}

	type = xmlnode_get_data(xmlnode_get_child(member, "Type"));
	member_id = xmlnode_get_data(xmlnode_get_child(member, "MembershipId"));

	user = msn_userlist_find_add_user(session->userlist, passport, NULL);

	for (annotation = xmlnode_get_child(member, "Annotations/Annotation");
	     annotation;
	     annotation = xmlnode_get_next_twin(annotation)) {
		char *name = xmlnode_get_data(xmlnode_get_child(annotation, "Name"));
		char *value = xmlnode_get_data(xmlnode_get_child(annotation, "Value"));
		if (name && value) {
			if (!strcmp(name, "MSN.IM.BuddyType")) {
				nid = strtoul(value, NULL, 10);
			}
			else if (!strcmp(name, "MSN.IM.InviteMessage")) {
				invite = value;
				value = NULL;
			}
		}
		g_free(name);
		g_free(value);
	}

	/* For EmailMembers, the network must be found in the annotations, above.
	   Otherwise, PassportMembers are on the Passport network. */
	if (!strcmp(node, "PassportName"))
		nid = MSN_NETWORK_PASSPORT;

	purple_debug_info("msn", "CL: %s name: %s, Type: %s, MembershipID: %s, NetworkID: %u\n",
		node, passport, type, member_id == NULL ? "(null)" : member_id, nid);

	msn_user_set_network(user, nid);
	msn_user_set_invite_message(user, invite);

	if (list == MSN_LIST_PL && member_id) {
		user->member_id_on_pending_list = atoi(member_id);
	}

	msn_got_lst_user(session, user, 1 << list, NULL);

	g_free(passport);
	g_free(type);
	g_free(member_id);
	g_free(invite);
}

static void
msn_parse_each_service(MsnSession *session, xmlnode *service)
{
	xmlnode *type;

	if ((type = xmlnode_get_child(service, "Info/Handle/Type"))) {
		char *type_str = xmlnode_get_data(type);

		if (g_str_equal(type_str, "Profile")) {
			/* Process Windows Live 'Messenger Roaming Identity' */
		} else if (g_str_equal(type_str, "Messenger")) {
			xmlnode *lastchange = xmlnode_get_child(service, "LastChange");
			char *lastchange_str = xmlnode_get_data(lastchange);
			xmlnode *membership;

			purple_debug_info("msn", "CL last change: %s\n", lastchange_str);
			purple_account_set_string(session->account,	"CLLastChange",
				lastchange_str);

			for (membership = xmlnode_get_child(service,
					"Memberships/Membership");
				 membership; membership = xmlnode_get_next_twin(membership)) {

				xmlnode *role = xmlnode_get_child(membership, "MemberRole");
				char *role_str = xmlnode_get_data(role);
				MsnListId list = msn_get_memberrole(role_str);
				xmlnode *member;

				purple_debug_info("msn", "CL MemberRole role: %s, list: %d\n",
					role_str, list);

				for (member = xmlnode_get_child(membership, "Members/Member");
					 member; member = xmlnode_get_next_twin(member)) {
					const char *member_type = xmlnode_get_attrib(member, "type");
					if (g_str_equal(member_type, "PassportMember")) {
						msn_parse_each_member(session, member, "PassportName",
							list);
					} else if (g_str_equal(member_type, "PhoneMember")) {

					} else if (g_str_equal(member_type, "EmailMember")) {
						msn_parse_each_member(session, member, "Email",	list);
					}
				}

				g_free(role_str);
			}

			g_free(lastchange_str);
		}

		g_free(type_str);
	}
}

/*parse contact list*/
static gboolean
msn_parse_contact_list(MsnSession *session, xmlnode *node)
{
	xmlnode *fault, *faultnode;

	/* we may get a response if our cache data is too old:
	 *
	 * <faultstring>Need to do full sync. Can't sync deltas Client
	 * has too old a copy for us to do a delta sync</faultstring>
	 *
	 * this is not handled yet
	 */
	if ((fault = xmlnode_get_child(node, "Body/Fault"))) {
		if ((faultnode = xmlnode_get_child(fault, "faultstring"))) {
			char *faultstring = xmlnode_get_data(faultnode);
			purple_debug_info("msn", "Retrieving contact list failed: %s\n",
				faultstring);
			g_free(faultstring);
		}
		if ((faultnode = xmlnode_get_child(fault, "detail/errorcode"))) {
			char *errorcode = xmlnode_get_data(faultnode);

			if (g_str_equal(errorcode, "ABDoesNotExist")) {
				msn_create_address_book(session);
				g_free(errorcode);
				return FALSE;
			}

			g_free(errorcode);
		}

		msn_get_contact_list(session, MSN_PS_INITIAL, NULL);
		return FALSE;
	} else {
		xmlnode *service;

		for (service = xmlnode_get_child(node, "Body/FindMembershipResponse/"
				"FindMembershipResult/Services/Service");
			 service; service = xmlnode_get_next_twin(service)) {
			msn_parse_each_service(session, service);
		}
		return TRUE;
	}
}

static void
msn_get_contact_list_cb(MsnSoapMessage *req, MsnSoapMessage *resp,
	gpointer data)
{
	MsnCallbackState *state = data;
	MsnSession *session = state->session;

	g_return_if_fail(session != NULL);

	if (resp != NULL) {
#ifdef MSN_PARTIAL_LISTS
		const char *abLastChange;
		const char *dynamicItemLastChange;
#endif

		purple_debug_misc("msn", "Got the contact list!\n");

		if (msn_parse_contact_list(session, resp->xml)) {
#ifdef MSN_PARTIAL_LISTS
			abLastChange = purple_account_get_string(session->account,
				"ablastChange", NULL);
			dynamicItemLastChange = purple_account_get_string(session->account,
				"DynamicItemLastChanged", NULL);
#endif

			if (state->partner_scenario == MSN_PS_INITIAL) {
#ifdef MSN_PARTIAL_LISTS
				/* XXX: this should be enabled when we can correctly do partial
				   syncs with the server. Currently we need to retrieve the whole
				   list to detect sync issues */
				msn_get_address_book(session, MSN_PS_INITIAL, abLastChange, dynamicItemLastChange);
#else
				msn_get_address_book(session, MSN_PS_INITIAL, NULL, NULL);
#endif
			}
		}
	}
}

/*SOAP  get contact list*/
void
msn_get_contact_list(MsnSession *session,
	const MsnSoapPartnerScenario partner_scenario, const char *update_time)
{
	gchar *body = NULL;
	gchar *update_str = NULL;
	MsnCallbackState *state;
	const gchar *partner_scenario_str = MsnSoapPartnerScenarioText[partner_scenario];

	purple_debug_misc("msn", "Getting Contact List.\n");

	if (update_time != NULL) {
		purple_debug_info("msn", "CL Last update time: %s\n", update_time);
		update_str = g_strdup_printf(MSN_GET_CONTACT_UPDATE_XML, update_time);
	}

	body = g_strdup_printf(MSN_GET_CONTACT_TEMPLATE, partner_scenario_str,
	                       update_str ? update_str : "");

	state = msn_callback_state_new(session);
	state->partner_scenario = partner_scenario;
	state->body = xmlnode_from_str(body, -1);
	state->post_action = MSN_GET_CONTACT_SOAP_ACTION;
	state->post_url = MSN_GET_CONTACT_POST_URL;
	state->cb = msn_get_contact_list_cb;
	msn_contact_request(state);

	g_free(update_str);
	g_free(body);
}

static void
msn_parse_addressbook_groups(MsnSession *session, xmlnode *node)
{
	xmlnode *group;

	purple_debug_info("msn", "msn_parse_addressbook_groups()\n");

	for(group = xmlnode_get_child(node, "Group"); group;
					group = xmlnode_get_next_twin(group)){
		xmlnode *groupId, *groupInfo, *groupname;
		char *group_id = NULL, *group_name = NULL;

		if ((groupId = xmlnode_get_child(group, "groupId")))
			group_id = xmlnode_get_data(groupId);
		if ((groupInfo = xmlnode_get_child(group, "groupInfo")) && (groupname = xmlnode_get_child(groupInfo, "name")))
			group_name = xmlnode_get_data(groupname);

		if (group_id == NULL) {
			/* Group of ungroupped buddies */
			g_free(group_name);
			continue;
		}

		msn_group_new(session->userlist, group_id, group_name);

		purple_debug_info("msn", "AB group_id: %s, name: %s\n", group_id, group_name ? group_name : "(null)");
		if ((purple_find_group(group_name)) == NULL) {
			PurpleGroup *g = purple_group_new(group_name);
			purple_blist_add_group(g, NULL);
		}
		g_free(group_id);
		g_free(group_name);
	}
}

static gboolean
msn_parse_addressbook_mobile(xmlnode *contactInfo, char **inout_mobile_number)
{
	xmlnode *phones;
	char *mobile_number = NULL;
	gboolean mobile = FALSE;

	*inout_mobile_number = NULL;

	if ((phones = xmlnode_get_child(contactInfo, "phones"))) {
		xmlnode *contact_phone;
		char *phone_type = NULL;

		for (contact_phone = xmlnode_get_child(phones, "ContactPhone");
			 contact_phone;
			 contact_phone = xmlnode_get_next_twin(contact_phone)) {
			xmlnode *contact_phone_type;

			if (!(contact_phone_type =
					xmlnode_get_child(contact_phone, "contactPhoneType")))
				continue;

			phone_type = xmlnode_get_data(contact_phone_type);

			if (phone_type && !strcmp(phone_type, "ContactPhoneMobile")) {
				xmlnode *number;

				if ((number = xmlnode_get_child(contact_phone, "number"))) {
					xmlnode *messenger_enabled;
					char *is_messenger_enabled = NULL;

					g_free(mobile_number);
					mobile_number = xmlnode_get_data(number);

					if (mobile_number &&
							(messenger_enabled = xmlnode_get_child(contact_phone, "isMessengerEnabled"))
							&& (is_messenger_enabled = xmlnode_get_data(messenger_enabled))
							&& !strcmp(is_messenger_enabled, "true"))
						mobile = TRUE;

					g_free(is_messenger_enabled);
				}
			}

			g_free(phone_type);
		}
	}

	*inout_mobile_number = mobile_number;
	return mobile;
}

static void
msn_parse_addressbook_contacts(MsnSession *session, xmlnode *node)
{
	xmlnode *contactNode;
	char *passport = NULL, *Name = NULL, *uid = NULL, *type = NULL, *mobile_number = NULL, *alias = NULL;
	gboolean mobile = FALSE;
	PurpleConnection *pc = purple_account_get_connection(session->account);

	for(contactNode = xmlnode_get_child(node, "Contact"); contactNode;
				contactNode = xmlnode_get_next_twin(contactNode)) {
		xmlnode *contactId, *contactInfo, *contactType, *passportName, *displayName, *guid, *groupIds;
		xmlnode *annotation;
		MsnUser *user;

		g_free(passport);
		g_free(Name);
		g_free(uid);
		g_free(type);
		g_free(mobile_number);
		g_free(alias);
		passport = Name = uid = type = mobile_number = alias = NULL;
		mobile = FALSE;

		if (!(contactId = xmlnode_get_child(contactNode,"contactId"))
				|| !(contactInfo = xmlnode_get_child(contactNode, "contactInfo"))
				|| !(contactType = xmlnode_get_child(contactInfo, "contactType")))
			continue;

		uid = xmlnode_get_data(contactId);
		type = xmlnode_get_data(contactType);

		/* Find out our settings */
		if (type && !strcmp(type, "Me")) {
			/* setup the Display Name */
			if (purple_connection_get_display_name(pc) == NULL) {
				char *friendly = NULL;
				if ((displayName = xmlnode_get_child(contactInfo, "displayName")))
					friendly = xmlnode_get_data(displayName);
				purple_connection_set_display_name(pc,
					friendly ? purple_url_decode(friendly) : NULL);
				g_free(friendly);
			}

			for (annotation = xmlnode_get_child(contactInfo, "annotations/Annotation");
			     annotation;
			     annotation = xmlnode_get_next_twin(annotation)) {
				char *name, *value;
				name = xmlnode_get_data(xmlnode_get_child(annotation, "Name"));
				value = xmlnode_get_data(xmlnode_get_child(annotation, "Value"));
				if (name && g_str_equal(name, "MSN.IM.MPOP")) {
					if (!value || atoi(value) != 0)
						session->enable_mpop = TRUE;
					else
						session->enable_mpop = FALSE;
				}
				g_free(name);
				g_free(value);
			}

			continue; /* Not adding own account as buddy to buddylist */
		}

		passportName = xmlnode_get_child(contactInfo, "passportName");
		if (passportName == NULL) {
			xmlnode *emailsNode, *contactEmailNode, *emailNode;
			xmlnode *messengerEnabledNode;
			char *msnEnabled;

			/*TODO: add it to the non-instant Messenger group and recognize as email Membership*/
			/* Yahoo/Federated User? */
			emailsNode = xmlnode_get_child(contactInfo, "emails");
			if (emailsNode == NULL) {
				/*TODO:  need to support the Mobile type*/
				continue;
			}
			for (contactEmailNode = xmlnode_get_child(emailsNode, "ContactEmail");
			     contactEmailNode;
			     contactEmailNode = xmlnode_get_next_twin(contactEmailNode)) {
				if ((messengerEnabledNode = xmlnode_get_child(contactEmailNode, "isMessengerEnabled"))) {

					msnEnabled = xmlnode_get_data(messengerEnabledNode);

					if (msnEnabled && !strcmp(msnEnabled, "true")) {
						if ((emailNode = xmlnode_get_child(contactEmailNode, "email")))
							passport = xmlnode_get_data(emailNode);

						/* Messenger enabled, Get the Passport*/
						purple_debug_info("msn", "AB Yahoo/Federated User %s\n", passport ? passport : "(null)");
						g_free(msnEnabled);
						break;
					}

					g_free(msnEnabled);
				}
			}
		} else {
			xmlnode *messenger_user;
			/* ignore non-messenger contacts */
			if ((messenger_user = xmlnode_get_child(contactInfo, "isMessengerUser"))) {
				char *is_messenger_user = xmlnode_get_data(messenger_user);

				if (is_messenger_user && !strcmp(is_messenger_user, "false")) {
					g_free(is_messenger_user);
					continue;
				}

				g_free(is_messenger_user);
			}

			passport = xmlnode_get_data(passportName);
		}

		/* Couldn't find anything */
		if (passport == NULL)
			continue;

		if (!msn_email_is_valid(passport))
			continue;

		if ((displayName = xmlnode_get_child(contactInfo, "displayName")))
			Name = xmlnode_get_data(displayName);
		else
			Name = g_strdup(passport);

		for (annotation = xmlnode_get_child(contactInfo, "annotations/Annotation");
		     annotation;
		     annotation = xmlnode_get_next_twin(annotation)) {
			char *name;
			name = xmlnode_get_data(xmlnode_get_child(annotation, "Name"));
			if (!name)
				continue;
			if (!strcmp(name, "AB.NickName"))
				alias = xmlnode_get_data(xmlnode_get_child(annotation, "Value"));
			else if (!strcmp(name, "MSN.IM.HasSharedFolder"))
				; /* Do nothing yet... */
			else if (!strcmp(name, "AB.Spouse"))
				; /* Do nothing yet... */
			else if (!strcmp(name, "MSN.Mobile.ContactId"))
				; /* Do nothing yet... */
			else
				purple_debug_info("msn",
				                  "Unknown AB contact annotation: %s\n", name);
			g_free(name);
		}

		mobile = msn_parse_addressbook_mobile(contactInfo, &mobile_number);

		purple_debug_misc("msn", "AB passport:{%s} uid:{%s} display:{%s} alias: {%s} mobile:{%s} mobile number:{%s}\n",
			passport, uid ? uid : "(null)", Name ? Name : "(null)", alias ? alias : "(null)",
			mobile ? "true" : "false", mobile_number ? mobile_number : "(null)");

		user = msn_userlist_find_add_user(session->userlist, passport, Name);
		msn_user_set_uid(user, uid);
		msn_user_set_mobile_phone(user, mobile_number);

		groupIds = xmlnode_get_child(contactInfo, "groupIds");
		if (groupIds) {
			for (guid = xmlnode_get_child(groupIds, "guid"); guid;
							guid = xmlnode_get_next_twin(guid)) {
				char *group_id = xmlnode_get_data(guid);
				msn_user_add_group_id(user, group_id);
				purple_debug_misc("msn", "AB guid:%s\n", group_id ? group_id : "(null)");
				g_free(group_id);
			}
		} else {
			purple_debug_info("msn", "User not in any groups, adding to default group.\n");
			/*not in any group,Then set default group*/
			msn_user_add_group_id(user, MSN_INDIVIDUALS_GROUP_ID);
		}

		msn_got_lst_user(session, user, MSN_LIST_FL_OP, NULL);

		if (mobile && user)
		{
			user->mobile = TRUE;
			purple_prpl_got_user_status(session->account, user->passport, "mobile", NULL);
			purple_prpl_got_user_status(session->account, user->passport, "available", NULL);
		}
		if (alias)
			purple_serv_got_private_alias(pc, passport, alias);
	}

	g_free(passport);
	g_free(Name);
	g_free(uid);
	g_free(type);
	g_free(mobile_number);
	g_free(alias);
}

static void
msn_parse_addressbook_circles(MsnSession *session, xmlnode *node)
{
	xmlnode *ticket;

	/* TODO: Parse groups */

	ticket = xmlnode_get_child(node, "CircleTicket");
	if (ticket) {
		char *data = xmlnode_get_data(ticket);
		msn_notification_send_circle_auth(session, data);
		g_free(data);
	}
}

static gboolean
msn_parse_addressbook(MsnSession *session, xmlnode *node)
{
	xmlnode *result;
	xmlnode *groups;
	xmlnode *contacts;
	xmlnode *abNode;
	xmlnode *circleNode;
	xmlnode *fault;

	if ((fault = xmlnode_get_child(node, "Body/Fault"))) {
		xmlnode *faultnode;

		if ((faultnode = xmlnode_get_child(fault, "faultstring"))) {
			gchar *faultstring = xmlnode_get_data(faultnode);
			purple_debug_info("msn", "AB Faultstring: %s\n", faultstring);
			g_free(faultstring);
		}

		if ((faultnode = xmlnode_get_child(fault, "detail/errorcode"))) {
			gchar *errorcode = xmlnode_get_data(faultnode);

			purple_debug_info("msn", "AB Error Code: %s\n", errorcode);

			if (g_str_equal(errorcode, "ABDoesNotExist")) {
				g_free(errorcode);
				return TRUE;
			}
			g_free(errorcode);
		}

		return FALSE;
	}

	result = xmlnode_get_child(node, "Body/ABFindContactsPagedResponse/ABFindContactsPagedResult");
	if (result == NULL) {
		purple_debug_misc("msn", "Received no address book update\n");
		return TRUE;
	}

	/* I don't see this "groups" tag documented on msnpiki, need to find out
	   if they are really there, and update msnpiki */
	/*Process Group List*/
	groups = xmlnode_get_child(result, "Groups");
	if (groups != NULL) {
		msn_parse_addressbook_groups(session, groups);
	}

	/* Add an "Other Contacts" group for buddies who aren't in a group */
	msn_group_new(session->userlist, MSN_INDIVIDUALS_GROUP_ID,
				  MSN_INDIVIDUALS_GROUP_NAME);
	purple_debug_misc("msn", "AB group_id:%s name:%s\n",
					  MSN_INDIVIDUALS_GROUP_ID, MSN_INDIVIDUALS_GROUP_NAME);
	if ((purple_find_group(MSN_INDIVIDUALS_GROUP_NAME)) == NULL){
		PurpleGroup *g = purple_group_new(MSN_INDIVIDUALS_GROUP_NAME);
		purple_blist_add_group(g, NULL);
	}

	/* Add a "Non-IM Contacts" group */
	msn_group_new(session->userlist, MSN_NON_IM_GROUP_ID, MSN_NON_IM_GROUP_NAME);
	purple_debug_misc("msn", "AB group_id:%s name:%s\n", MSN_NON_IM_GROUP_ID, MSN_NON_IM_GROUP_NAME);
	if ((purple_find_group(MSN_NON_IM_GROUP_NAME)) == NULL) {
		PurpleGroup *g = purple_group_new(MSN_NON_IM_GROUP_NAME);
		purple_blist_add_group(g, NULL);
	}

	/*Process contact List*/
	purple_debug_info("msn", "Process contact list...\n");
	contacts = xmlnode_get_child(result, "Contacts");
	if (contacts != NULL) {
		msn_parse_addressbook_contacts(session, contacts);
	}

	abNode = xmlnode_get_child(result, "Ab");
	if (abNode != NULL) {
		xmlnode *node2;
		char *tmp = NULL;

		if ((node2 = xmlnode_get_child(abNode, "lastChange")))
			tmp = xmlnode_get_data(node2);
		purple_debug_info("msn", "AB lastchanged Time:{%s}\n", tmp ? tmp : "(null)");
		purple_account_set_string(session->account, "ablastChange", tmp);

		g_free(tmp); tmp = NULL;
		if ((node2 = xmlnode_get_child(abNode, "DynamicItemLastChanged")))
			tmp = xmlnode_get_data(node2);
		purple_debug_info("msn", "AB DynamicItemLastChanged :{%s}\n", tmp ? tmp : "(null)");
		purple_account_set_string(session->account, "DynamicItemLastChanged", tmp);
		g_free(tmp);
	}

	circleNode = xmlnode_get_child(result, "CircleResult");
	if (circleNode != NULL) {
		msn_parse_addressbook_circles(session, circleNode);
	}

	return TRUE;
}

static void
msn_get_address_cb(MsnSoapMessage *req, MsnSoapMessage *resp, gpointer data)
{
	MsnCallbackState *state = data;
	MsnSession *session = state->session;

	g_return_if_fail(session != NULL);

	purple_debug_misc("msn", "Got the Address Book!\n");

	if (msn_parse_addressbook(session, resp->xml)) {
		msn_send_privacy(session->account->gc);
		msn_notification_dump_contact(session);
	} else {
		/* This is making us loop infinitely when we fail to parse the
		  address book, disable for now (we should re-enable when we
		  send timestamps)
		*/
		/*
		msn_get_address_book(session, NULL, NULL);
		*/
		msn_session_set_error(session, MSN_ERROR_BAD_BLIST, NULL);
	}
}

/*get the address book*/
void
msn_get_address_book(MsnSession *session,
	MsnSoapPartnerScenario partner_scenario, const char *LastChanged,
	const char *dynamicItemLastChange)
{
	char *body, *update_str = NULL;
	MsnCallbackState *state;

	purple_debug_misc("msn", "Getting Address Book\n");

	/*build SOAP and POST it*/
	if (dynamicItemLastChange != NULL)
		update_str = g_strdup_printf(MSN_GET_ADDRESS_UPDATE_XML, dynamicItemLastChange);
	else if (LastChanged != NULL)
		update_str = g_strdup_printf(MSN_GET_ADDRESS_UPDATE_XML, LastChanged);

	body = g_strdup_printf(MSN_GET_ADDRESS_TEMPLATE,
		MsnSoapPartnerScenarioText[partner_scenario],
		update_str ? update_str : "");

	state = msn_callback_state_new(session);
	state->body = xmlnode_from_str(body, -1);
	state->post_action = MSN_GET_ADDRESS_SOAP_ACTION;
	state->post_url = MSN_ADDRESS_BOOK_POST_URL;
	state->cb = msn_get_address_cb;
	msn_contact_request(state);

	g_free(update_str);
	g_free(body);
}

/***************************************************************
 * Contact Operations
 ***************************************************************/

static void
msn_add_contact_read_cb(MsnSoapMessage *req, MsnSoapMessage *resp,
	gpointer data)
{
	MsnCallbackState *state = data;
	MsnSession *session = state->session;

	MsnUserList *userlist;
	MsnUser *user;
	xmlnode *guid;

	xmlnode *fault;

	g_return_if_fail(session != NULL);
	userlist = session->userlist;

	fault = xmlnode_get_child(resp->xml, "Body/Fault");
	if (fault != NULL) {
		char *errorcode = xmlnode_get_data(xmlnode_get_child(fault, "detail/errorcode"));
		if (errorcode && !strcmp(errorcode, "EmailDomainIsFederated")) {
			/* Do something special! */
			purple_debug_error("msn", "Contact is from a federated domain, but don't know what to do yet!\n");

		} else if (errorcode && !strcmp(errorcode, "InvalidPassportUser")) {
			PurpleBuddy *buddy = purple_find_buddy(session->account, state->who);
			char *str = g_strdup_printf(_("Unable to add \"%s\"."), state->who);
			purple_notify_error(state->session, _("Buddy Add error"), str,
			                    _("The username specified does not exist."));
			g_free(str);
			msn_userlist_rem_buddy(userlist, state->who);
			if (buddy != NULL)
				purple_blist_remove_buddy(buddy);

		} else {
			/* We don't know how to respond to this faultcode, so log it */
			char *fault_str = xmlnode_to_str(fault, NULL);
			if (fault_str != NULL) {
				purple_debug_error("msn", "Operation {%s} Failed, SOAP Fault was: %s\n",
				                   msn_contact_operation_str(state->action), fault_str);
				g_free(fault_str);
			}
		}
		return;
	}

	purple_debug_info("msn", "Contact added successfully\n");

	msn_userlist_add_buddy_to_list(userlist, state->who, MSN_LIST_AL);
	msn_userlist_add_buddy_to_list(userlist, state->who, MSN_LIST_FL);

	user = msn_userlist_find_add_user(userlist, state->who, state->who);
	msn_user_add_group_id(user, state->guid);

	guid = xmlnode_get_child(resp->xml,
		"Body/ABContactAddResponse/ABContactAddResult/guid");
	if (guid != NULL) {
		char *uid = xmlnode_get_data(guid);
		msn_user_set_uid(user, uid);
		purple_debug_info("msn", "Set %s guid to %s.\n", state->who, uid);
		g_free(uid);
	}
}

/* add a Contact in MSN_INDIVIDUALS_GROUP */
void
msn_add_contact(MsnSession *session, MsnCallbackState *state, const char *passport)
{
	MsnUser *user;
	gchar *body = NULL;
	gchar *contact_xml = NULL;

	purple_debug_info("msn", "Adding contact %s to contact list\n", passport);

	user = msn_userlist_find_user(session->userlist, passport);
	if (user == NULL) {
		purple_debug_warning("msn", "Unable to retrieve user %s from the userlist!\n", passport);
		return; /* guess this never happened! */
	}

	if (user->networkid != MSN_NETWORK_PASSPORT) {
		contact_xml = g_strdup_printf(MSN_CONTACT_EMAIL_XML,
		                              user->networkid == MSN_NETWORK_YAHOO ?
		                                  "Messenger2" :
		                                  "Messenger3",
		                              passport, 0);
	} else {
		contact_xml = g_strdup_printf(MSN_CONTACT_XML, passport);
	}
	body = g_strdup_printf(MSN_ADD_CONTACT_TEMPLATE, contact_xml);

	state->body = xmlnode_from_str(body, -1);
	state->post_action = MSN_CONTACT_ADD_SOAP_ACTION;
	state->post_url = MSN_ADDRESS_BOOK_POST_URL;
	state->cb = msn_add_contact_read_cb;
	msn_contact_request(state);

	g_free(contact_xml);
	g_free(body);
}

static void
msn_add_contact_to_group_read_cb(MsnSoapMessage *req, MsnSoapMessage *resp,
	gpointer data)
{
	MsnCallbackState *state = data;
	MsnSession *session = state->session;
	MsnUserList *userlist;
	xmlnode *fault;

	g_return_if_fail(session != NULL);
	userlist = session->userlist;

	fault = xmlnode_get_child(resp->xml, "Body/Fault");
	if (fault != NULL) {
		char *errorcode = xmlnode_get_data(xmlnode_get_child(fault, "detail/errorcode"));
		if (errorcode && !strcmp(errorcode, "EmailDomainIsFederated")) {
			/* Do something special! */
			purple_debug_error("msn", "Contact is from a federated domain, but don't know what to do yet!\n");

		} else if (errorcode && !strcmp(errorcode, "InvalidPassportUser")) {
			PurpleBuddy *buddy = purple_find_buddy(session->account, state->who);
			char *str = g_strdup_printf(_("Unable to add \"%s\"."), state->who);
			purple_notify_error(session, _("Buddy Add error"), str,
			                    _("The username specified does not exist."));
			g_free(str);
			msn_userlist_rem_buddy(userlist, state->who);
			if (buddy != NULL)
				purple_blist_remove_buddy(buddy);

		} else {
			/* We don't know how to respond to this faultcode, so log it */
			char *fault_str = xmlnode_to_str(fault, NULL);
			if (fault_str != NULL) {
				purple_debug_error("msn", "Operation {%s} Failed, SOAP Fault was: %s\n",
				                   msn_contact_operation_str(state->action), fault_str);
				g_free(fault_str);
			}
		}
		return;
	}

	if (msn_userlist_add_buddy_to_group(userlist, state->who,
			state->new_group_name)) {
		purple_debug_info("msn", "Contact %s added to group %s successfully!\n", state->who, state->new_group_name);
	} else {
		purple_debug_info("msn", "Contact %s added to group %s successfully on server, but failed in the local list\n", state->who, state->new_group_name);
	}

	if (state->action & MSN_ADD_BUDDY) {
		MsnUser *user = msn_userlist_find_user(userlist, state->who);
		xmlnode *guid = xmlnode_get_child(resp->xml,
			"Body/ABGroupContactAddResponse/ABGroupContactAddResult/guid");

		if (guid != NULL) {
			char *uid = xmlnode_get_data(guid);
			msn_user_set_uid(user, uid);
			purple_debug_info("msn", "Set %s guid to %s.\n", state->who, uid);
			g_free(uid);
		}

		msn_userlist_add_buddy_to_list(userlist, state->who, MSN_LIST_AL);
		msn_userlist_add_buddy_to_list(userlist, state->who, MSN_LIST_FL);

		if (msn_user_is_in_list(user, MSN_LIST_PL)) {
			msn_del_contact_from_list(state->session, NULL, state->who, MSN_LIST_PL);
			return;
		}
	}

	if (state->action & MSN_MOVE_BUDDY) {
		msn_del_contact_from_group(state->session, state->who, state->old_group_name);
	}
}

void
msn_add_contact_to_group(MsnSession *session, MsnCallbackState *state,
			 const char *passport, const char *groupId)
{
	MsnUserList *userlist;
	MsnUser *user;
	gchar *body = NULL, *contact_xml, *invite;

	g_return_if_fail(passport != NULL);
	g_return_if_fail(groupId != NULL);

	g_return_if_fail(session != NULL);

	userlist = session->userlist;

	if (!strcmp(groupId, MSN_INDIVIDUALS_GROUP_ID) || !strcmp(groupId, MSN_NON_IM_GROUP_ID)) {

		user = msn_userlist_find_add_user(userlist, passport, passport);

		if (state->action & MSN_ADD_BUDDY) {
			msn_add_contact(session, state, passport);
			return;
		}

		if (state->action & MSN_MOVE_BUDDY) {
			msn_user_add_group_id(user, groupId);
			msn_del_contact_from_group(session, passport, state->old_group_name);
		}

		return;
	}

	purple_debug_info("msn", "Adding user %s to group %s\n", passport,
			  msn_userlist_find_group_name(userlist, groupId));

	user = msn_userlist_find_user(userlist, passport);
	if (user == NULL) {
		purple_debug_warning("msn", "Unable to retrieve user %s from the userlist!\n", passport);
		msn_callback_state_free(state);
		return; /* guess this never happened! */
	}

	if (user->uid != NULL) {
		contact_xml = g_strdup_printf(MSN_CONTACT_ID_XML, user->uid);
	} else if (user->networkid != MSN_NETWORK_PASSPORT) {
		contact_xml = g_strdup_printf(MSN_CONTACT_EMAIL_XML,
		                              user->networkid == MSN_NETWORK_YAHOO ?
		                                  "Messenger2" :
		                                  "Messenger3",
		                              passport, 0);
	} else {
		contact_xml = g_strdup_printf(MSN_CONTACT_XML, passport);
	}

	if (user->invite_message) {
		char *tmp;
		body = g_markup_escape_text(user->invite_message, -1);

		/* Ignore the cast, we treat it as const anyway. */
		tmp = (char *)purple_connection_get_display_name(session->account->gc);
		tmp = tmp ? g_markup_escape_text(tmp, -1) : g_strdup("");

		invite = g_strdup_printf(MSN_CONTACT_INVITE_MESSAGE_XML, body, tmp);

		g_free(body);
		g_free(tmp);

		/* We can free this now */
		g_free(user->invite_message);
		user->invite_message = NULL;

	} else {
		invite = g_strdup("");
	}

	body = g_strdup_printf(MSN_ADD_CONTACT_GROUP_TEMPLATE, groupId, contact_xml, invite);

	state->body = xmlnode_from_str(body, -1);
	state->post_action = MSN_ADD_CONTACT_GROUP_SOAP_ACTION;
	state->post_url = MSN_ADDRESS_BOOK_POST_URL;
	state->cb = msn_add_contact_to_group_read_cb;
	msn_contact_request(state);

	g_free(invite);
	g_free(contact_xml);
	g_free(body);
}

static void
msn_delete_contact_read_cb(MsnSoapMessage *req, MsnSoapMessage *resp,
	gpointer data)
{
	MsnCallbackState *state = data;
	MsnUserList *userlist = state->session->userlist;
	MsnUser *user = msn_userlist_find_user_with_id(userlist, state->uid);
	xmlnode *fault;

	/* We don't know how to respond to this faultcode, so log it */
	fault = xmlnode_get_child(resp->xml, "Body/Fault");
	if (fault != NULL) {
		char *fault_str = xmlnode_to_str(fault, NULL);
		purple_debug_error("msn", "Operation {%s} Failed, SOAP Fault was: %s\n",
		                   msn_contact_operation_str(state->action), fault_str);
		g_free(fault_str);
		return;
	}

	purple_debug_info("msn", "Delete contact successful\n");

	if (user != NULL) {
		msn_userlist_remove_user(userlist, user);
	}
}

/*delete a Contact*/
void
msn_delete_contact(MsnSession *session, MsnUser *user)
{
	gchar *body = NULL;
	gchar *contact_id_xml = NULL ;
	MsnCallbackState *state;

	if (user->uid != NULL) {
		contact_id_xml = g_strdup_printf(MSN_CONTACT_ID_XML, user->uid);
		purple_debug_info("msn", "Deleting contact with contactId: %s\n", user->uid);
	} else {
		purple_debug_info("msn", "Unable to delete contact %s without a ContactId\n", user->passport);
		return;
	}

	state = msn_callback_state_new(session);
	msn_callback_state_set_uid(state, user->uid);

	/* build SOAP request */
	body = g_strdup_printf(MSN_DEL_CONTACT_TEMPLATE, contact_id_xml);

	state->body = xmlnode_from_str(body, -1);
	state->post_action = MSN_CONTACT_DEL_SOAP_ACTION;
	state->post_url = MSN_ADDRESS_BOOK_POST_URL;
	state->cb = msn_delete_contact_read_cb;
	msn_contact_request(state);

	g_free(contact_id_xml);
	g_free(body);
}

static void
msn_del_contact_from_group_read_cb(MsnSoapMessage *req, MsnSoapMessage *resp,
	gpointer data)
{
	MsnCallbackState *state = data;
	xmlnode *fault;

	/* We don't know how to respond to this faultcode, so log it */
	fault = xmlnode_get_child(resp->xml, "Body/Fault");
	if (fault != NULL) {
		char *fault_str = xmlnode_to_str(fault, NULL);
		purple_debug_error("msn", "Operation {%s} Failed, SOAP Fault was: %s\n",
		                   msn_contact_operation_str(state->action), fault_str);
		g_free(fault_str);
		return;
	}

	if (msn_userlist_rem_buddy_from_group(state->session->userlist,
			state->who, state->old_group_name)) {
		purple_debug_info("msn", "Contact %s deleted successfully from group %s\n", state->who, state->old_group_name);
	} else {
		purple_debug_info("msn", "Contact %s deleted successfully from group %s in the server, but failed in the local list\n", state->who, state->old_group_name);
	}
}

void
msn_del_contact_from_group(MsnSession *session, const char *passport, const char *group_name)
{
	MsnUserList * userlist;
	MsnUser *user;
	MsnCallbackState *state;
	gchar *body, *contact_id_xml;
	const gchar *groupId;

	g_return_if_fail(passport != NULL);
	g_return_if_fail(group_name != NULL);
	g_return_if_fail(session != NULL);

	userlist = session->userlist;

	groupId = msn_userlist_find_group_id(userlist, group_name);
	if (groupId != NULL) {
		purple_debug_info("msn", "Deleting user %s from group %s\n", passport, group_name);
	} else {
		purple_debug_warning("msn", "Unable to retrieve group id from group %s !\n", group_name);
		return;
	}

	user = msn_userlist_find_user(userlist, passport);

	if (user == NULL) {
		purple_debug_warning("msn", "Unable to retrieve user from passport %s!\n", passport);
		return;
	}

	if ( !strcmp(groupId, MSN_INDIVIDUALS_GROUP_ID) || !strcmp(groupId, MSN_NON_IM_GROUP_ID)) {
		msn_user_remove_group_id(user, groupId);
		return;
	}

	state = msn_callback_state_new(session);
	msn_callback_state_set_who(state, passport);
	msn_callback_state_set_guid(state, groupId);
	msn_callback_state_set_old_group_name(state, group_name);

	if (user->uid != NULL)
		contact_id_xml = g_strdup_printf(MSN_CONTACT_ID_XML, user->uid);
	else
		contact_id_xml = g_strdup_printf(MSN_CONTACT_XML, passport);
	body = g_strdup_printf(MSN_CONTACT_DEL_GROUP_TEMPLATE, contact_id_xml, groupId);

	state->body = xmlnode_from_str(body, -1);
	state->post_action = MSN_CONTACT_DEL_GROUP_SOAP_ACTION;
	state->post_url = MSN_ADDRESS_BOOK_POST_URL;
	state->cb = msn_del_contact_from_group_read_cb;
	msn_contact_request(state);

	g_free(contact_id_xml);
	g_free(body);
}


static void
msn_update_contact_read_cb(MsnSoapMessage *req, MsnSoapMessage *resp,
	gpointer data)
{
	MsnCallbackState *state = (MsnCallbackState *)data;
	xmlnode *fault;

	/* We don't know how to respond to this faultcode, so log it */
	fault = xmlnode_get_child(resp->xml, "Body/Fault");
	if (fault != NULL) {
		char *fault_str = xmlnode_to_str(fault, NULL);
		purple_debug_error("msn", "Operation {%s} Failed, SOAP Fault was: %s\n",
		                   msn_contact_operation_str(state->action), fault_str);
		g_free(fault_str);
		return;
	}

	purple_debug_info("msn", "Contact updated successfully\n");
}

/* Update a contact's info */
void
msn_update_contact(MsnSession *session, const char *passport, MsnContactUpdateType type, const char* value)
{
	MsnCallbackState *state;
	xmlnode *contact;
	xmlnode *contact_info;
	xmlnode *changes;
	MsnUser *user = NULL;

	purple_debug_info("msn", "Update contact information for %s with new %s: %s\n",
		passport ? passport : "(null)",
		type == MSN_UPDATE_DISPLAY ? "display name" : "alias",
		value ? value : "(null)");
	g_return_if_fail(passport != NULL);

	if (strcmp(passport, "Me") != 0) {
		user = msn_userlist_find_user(session->userlist, passport);
		if (!user)
			return;
	}

	contact_info = xmlnode_new("contactInfo");
	changes = xmlnode_new("propertiesChanged");

	switch (type) {
		xmlnode *annotations;
		xmlnode *display;
		xmlnode *a, *n, *v;
		case MSN_UPDATE_DISPLAY:
			display = xmlnode_new_child(contact_info, "displayName");
			xmlnode_insert_data(display, value, -1);
			xmlnode_insert_data(changes, "DisplayName", -1);
			break;

		case MSN_UPDATE_ALIAS:
			annotations = xmlnode_new_child(contact_info, "annotations");
			xmlnode_insert_data(changes, "Annotation ", -1);

			a = xmlnode_new_child(annotations, "Annotation");
			n = xmlnode_new_child(a, "Name");
			xmlnode_insert_data(n, "AB.NickName", -1);
			v = xmlnode_new_child(a, "Value");
			xmlnode_insert_data(v, value, -1);
			break;

		default:
			g_return_if_reached();
	}

	state = msn_callback_state_new(session);

	state->body = xmlnode_from_str(MSN_CONTACT_UPDATE_TEMPLATE, -1);
	state->action = MSN_UPDATE_INFO;
	state->post_action = MSN_CONTACT_UPDATE_SOAP_ACTION;
	state->post_url = MSN_ADDRESS_BOOK_POST_URL;
	state->cb = msn_update_contact_read_cb;

	contact = xmlnode_get_child(state->body, "Body/ABContactUpdate/contacts/Contact");
	xmlnode_insert_child(contact, contact_info);
	xmlnode_insert_child(contact, changes);

	xmlnode_insert_data(xmlnode_get_child(state->body,
	                                      "Header/ABApplicationHeader/PartnerScenario"),
	                    MsnSoapPartnerScenarioText[MSN_PS_SAVE_CONTACT], -1);

	if (user) {
		xmlnode *contactId = xmlnode_new_child(contact, "contactId");
		msn_callback_state_set_uid(state, user->uid);
		xmlnode_insert_data(contactId, state->uid, -1);
	} else {
		xmlnode *contactType = xmlnode_new_child(contact_info, "contactType");
		xmlnode_insert_data(contactType, "Me", -1);
	}

	msn_contact_request(state);
}

static void
msn_annotate_contact_read_cb(MsnSoapMessage *req, MsnSoapMessage *resp,
	gpointer data)
{
	MsnCallbackState *state = (MsnCallbackState *)data;
	xmlnode *fault;

	/* We don't know how to respond to this faultcode, so log it */
	fault = xmlnode_get_child(resp->xml, "Body/Fault");
	if (fault != NULL) {
		char *fault_str = xmlnode_to_str(fault, NULL);
		purple_debug_error("msn", "Operation {%s} Failed, SOAP Fault was: %s\n",
		                   msn_contact_operation_str(state->action), fault_str);
		g_free(fault_str);
		return;
	}

	purple_debug_info("msn", "Contact annotated successfully\n");
}

/* Update a contact's annotations */
void
msn_annotate_contact(MsnSession *session, const char *passport, ...)
{
	va_list params;
	MsnCallbackState *state;
	xmlnode *contact;
	xmlnode *contact_info;
	xmlnode *annotations;
	MsnUser *user = NULL;

	g_return_if_fail(passport != NULL);

	if (strcmp(passport, "Me") != 0) {
		user = msn_userlist_find_user(session->userlist, passport);
		if (!user)
			return;
	}

	contact_info = xmlnode_new("contactInfo");
	annotations = xmlnode_new_child(contact_info, "annotations");

	va_start(params, passport);
	while (TRUE) {
		const char *name;
		const char *value;
		xmlnode *a, *n, *v;

		name = va_arg(params, const char *);
		if (!name)
			break;

		value = va_arg(params, const char *);
		if (!value)
			break;

		a = xmlnode_new_child(annotations, "Annotation");
		n = xmlnode_new_child(a, "Name");
		xmlnode_insert_data(n, name, -1);
		v = xmlnode_new_child(a, "Value");
		xmlnode_insert_data(v, value, -1);
	}
	va_end(params);

	state = msn_callback_state_new(session);

	state->body = xmlnode_from_str(MSN_CONTACT_ANNOTATE_TEMPLATE, -1);
	state->action = MSN_ANNOTATE_USER;
	state->post_action = MSN_CONTACT_ANNOTATE_SOAP_ACTION;
	state->post_url = MSN_ADDRESS_BOOK_POST_URL;
	state->cb = msn_annotate_contact_read_cb;

	xmlnode_insert_data(xmlnode_get_child(state->body,
	                                      "Header/ABApplicationHeader/PartnerScenario"),
	                    MsnSoapPartnerScenarioText[MSN_PS_SAVE_CONTACT], -1);

	contact = xmlnode_get_child(state->body, "Body/ABContactUpdate/contacts/Contact");
	xmlnode_insert_child(contact, contact_info);

	if (user) {
		xmlnode *contactId = xmlnode_new_child(contact, "contactId");
		msn_callback_state_set_uid(state, user->uid);
		xmlnode_insert_data(contactId, state->uid, -1);
	} else {
		xmlnode *contactType = xmlnode_new_child(contact_info, "contactType");
		xmlnode_insert_data(contactType, "Me", -1);
	}

	msn_contact_request(state);
}

static void
msn_del_contact_from_list_read_cb(MsnSoapMessage *req, MsnSoapMessage *resp,
	gpointer data)
{
	MsnCallbackState *state = data;
	MsnSession *session = state->session;
	xmlnode *fault;

	/* We don't know how to respond to this faultcode, so log it */
	fault = xmlnode_get_child(resp->xml, "Body/Fault");
	if (fault != NULL) {
		char *fault_str = xmlnode_to_str(fault, NULL);
		purple_debug_error("msn", "Operation {%s} Failed, SOAP Fault was: %s\n",
		                   msn_contact_operation_str(state->action), fault_str);
		g_free(fault_str);
		return;
	}

	purple_debug_info("msn", "Contact %s deleted successfully from %s list on server!\n", state->who, MsnMemberRole[state->list_id]);

	if (state->list_id == MSN_LIST_PL) {
		MsnUser *user = msn_userlist_find_user(session->userlist, state->who);
		MsnCallbackState *new_state = msn_callback_state_dup(state);

		if (user != NULL)
			msn_user_unset_op(user, MSN_LIST_PL_OP);

		msn_add_contact_to_list(session, new_state, state->who, MSN_LIST_RL);
		return;
	} else if (state->list_id == MSN_LIST_AL) {
		purple_privacy_permit_remove(session->account, state->who, TRUE);
		msn_add_contact_to_list(session, NULL, state->who, MSN_LIST_BL);
	} else if (state->list_id == MSN_LIST_BL) {
		purple_privacy_deny_remove(session->account, state->who, TRUE);
		msn_add_contact_to_list(session, NULL, state->who, MSN_LIST_AL);
	}

}

void
msn_del_contact_from_list(MsnSession *session, MsnCallbackState *state,
			  const gchar *passport, const MsnListId list)
{
	gchar *body = NULL, *member = NULL;
	MsnSoapPartnerScenario partner_scenario;
	MsnUser *user;

	g_return_if_fail(session != NULL);
	g_return_if_fail(session->userlist != NULL);
	g_return_if_fail(passport != NULL);
	g_return_if_fail(list < 5);

	purple_debug_info("msn", "Deleting contact %s from %s list\n", passport, MsnMemberRole[list]);

	if (state == NULL) {
		state = msn_callback_state_new(session);
	}
	msn_callback_state_set_list_id(state, list);
	msn_callback_state_set_who(state, passport);

	user = msn_userlist_find_user(session->userlist, passport);

	if (list == MSN_LIST_PL) {
		partner_scenario = MSN_PS_CONTACT_API;
		if (user->networkid != MSN_NETWORK_PASSPORT)
			member = g_strdup_printf(MSN_MEMBER_MEMBERSHIPID_XML,
			                         "EmailMember", "Email",
			                         user->member_id_on_pending_list);
		else
			member = g_strdup_printf(MSN_MEMBER_MEMBERSHIPID_XML,
			                         "PassportMember", "Passport",
			                         user->member_id_on_pending_list);
	} else {
		/* list == MSN_LIST_AL || list == MSN_LIST_BL */
		partner_scenario = MSN_PS_BLOCK_UNBLOCK;
		if (user && user->networkid != MSN_NETWORK_PASSPORT)
			member = g_strdup_printf(MSN_MEMBER_PASSPORT_XML,
			                         "EmailMember", "Email",
			                         "Email", passport, "Email");
		else
			member = g_strdup_printf(MSN_MEMBER_PASSPORT_XML,
			                         "PassportMember", "Passport",
			                         "PassportName", passport, "PassportName");
	}

	body = g_strdup_printf(MSN_CONTACT_DELETE_FROM_LIST_TEMPLATE,
		MsnSoapPartnerScenarioText[partner_scenario],
		MsnMemberRole[list], member);

	state->body = xmlnode_from_str(body, -1);
	state->post_action = MSN_DELETE_MEMBER_FROM_LIST_SOAP_ACTION;
	state->post_url = MSN_SHARE_POST_URL;
	state->cb = msn_del_contact_from_list_read_cb;
	msn_contact_request(state);

	g_free(member);
	g_free(body);
}

static void
msn_add_contact_to_list_read_cb(MsnSoapMessage *req, MsnSoapMessage *resp,
	gpointer data)
{
	MsnCallbackState *state = data;
	xmlnode *fault;

	/* We don't know how to respond to this faultcode, so log it */
	fault = xmlnode_get_child(resp->xml, "Body/Fault");
	if (fault != NULL) {
		char *fault_str = xmlnode_to_str(fault, NULL);
		purple_debug_error("msn", "Operation {%s} Failed, SOAP Fault was: %s\n",
		                   msn_contact_operation_str(state->action), fault_str);
		g_free(fault_str);
		return;
	}

	g_return_if_fail(state->session != NULL);

	purple_debug_info("msn", "Contact %s added successfully to %s list on server!\n", state->who, MsnMemberRole[state->list_id]);

	if (state->list_id == MSN_LIST_RL) {
		MsnUser *user = msn_userlist_find_user(state->session->userlist, state->who);

		if (user != NULL) {
			msn_user_set_op(user, MSN_LIST_RL_OP);
		}

		if (state->action & MSN_DENIED_BUDDY) {
			msn_add_contact_to_list(state->session, NULL, state->who, MSN_LIST_BL);
		} else if (state->list_id == MSN_LIST_AL) {
			purple_privacy_permit_add(state->session->account, state->who, TRUE);
		} else if (state->list_id == MSN_LIST_BL) {
			purple_privacy_deny_add(state->session->account, state->who, TRUE);
		}
	}
}

void
msn_add_contact_to_list(MsnSession *session, MsnCallbackState *state,
			const gchar *passport, const MsnListId list)
{
	gchar *body = NULL, *member = NULL;
	MsnSoapPartnerScenario partner_scenario;
	MsnUser *user;

	g_return_if_fail(session != NULL);
	g_return_if_fail(passport != NULL);
	g_return_if_fail(list < 5);

	purple_debug_info("msn", "Adding contact %s to %s list\n", passport, MsnMemberRole[list]);

	if (state == NULL) {
		state = msn_callback_state_new(session);
	}
	msn_callback_state_set_list_id(state, list);
	msn_callback_state_set_who(state, passport);

	user = msn_userlist_find_user(session->userlist, passport);

	partner_scenario = (list == MSN_LIST_RL) ? MSN_PS_CONTACT_API : MSN_PS_BLOCK_UNBLOCK;
	if (user && user->networkid != MSN_NETWORK_PASSPORT)
		member = g_strdup_printf(MSN_MEMBER_PASSPORT_XML,
		                         "EmailMember", "Email",
		                         "Email", state->who, "Email");
	else
		member = g_strdup_printf(MSN_MEMBER_PASSPORT_XML,
		                         "PassportMember", "Passport",
		                         "PassportName", state->who, "PassportName");

	body = g_strdup_printf(MSN_CONTACT_ADD_TO_LIST_TEMPLATE,
		MsnSoapPartnerScenarioText[partner_scenario],
		MsnMemberRole[list], member);

	state->body = xmlnode_from_str(body, -1);
	state->post_action = MSN_ADD_MEMBER_TO_LIST_SOAP_ACTION;
	state->post_url = MSN_SHARE_POST_URL;
	state->cb = msn_add_contact_to_list_read_cb;
	msn_contact_request(state);

	g_free(member);
	g_free(body);
}

#if 0
static void
msn_gleams_read_cb(MsnSoapMessage *req, MsnSoapMessage *resp, gpointer data)
{
	purple_debug_info("msn", "Gleams read done\n");
}

/*get the gleams info*/
void
msn_get_gleams(MsnSession *session)
{
	MsnSoapReq *soap_request;

	purple_debug_info("msn", "msn get gleams info...\n");

	state = msn_callback_state_new(session);
	state->body = xmlnode_from_str(MSN_GLEAMS_TEMPLATE, -1);
	state->post_action = MSN_GET_GLEAMS_SOAP_ACTION;
	state->post_url = MSN_ADDRESS_BOOK_POST_URL;
	state->cb = msn_gleams_read_cb;
	msn_contact_request(state);
}
#endif


/***************************************************************
 * Group Operations
 ***************************************************************/

static void
msn_group_read_cb(MsnSoapMessage *req, MsnSoapMessage *resp, gpointer data)
{
	MsnCallbackState *state = data;
	MsnSession *session;
	MsnUserList *userlist;
	xmlnode *fault;

	/* We don't know how to respond to this faultcode, so log it */
	fault = xmlnode_get_child(resp->xml, "Body/Fault");
	if (fault != NULL) {
		char *fault_str = xmlnode_to_str(fault, NULL);
		purple_debug_error("msn", "Operation {%s} Failed, SOAP Fault was: %s\n",
		                   msn_contact_operation_str(state->action), fault_str);
		g_free(fault_str);
		return;
	}

	purple_debug_info("msn", "Group request successful.\n");

	g_return_if_fail(state->session != NULL);
	g_return_if_fail(state->session->userlist != NULL);

	session = state->session;
	userlist = session->userlist;

	if (state->action & MSN_RENAME_GROUP) {
		msn_userlist_rename_group_id(session->userlist,
					     state->guid,
					     state->new_group_name);
	}

	if (state->action & MSN_ADD_GROUP) {
		/* the response is taken from
		   http://telepathy.freedesktop.org/wiki/Pymsn/MSNP/ContactListActions
		   should copy it to msnpiki some day */
		xmlnode *guid_node = xmlnode_get_child(resp->xml,
			"Body/ABGroupAddResponse/ABGroupAddResult/guid");

		if (guid_node) {
			char *guid = xmlnode_get_data(guid_node);

			/* create and add the new group to the userlist */
			purple_debug_info("msn", "Adding group %s with guid = %s to the userlist\n", state->new_group_name, guid);
			msn_group_new(session->userlist, guid, state->new_group_name);

			if (state->action & MSN_ADD_BUDDY) {
				msn_userlist_add_buddy(session->userlist,
					state->who,
					state->new_group_name);
			} else if (state->action & MSN_MOVE_BUDDY) {
				/* This will be freed when the add contact callback fires */
				MsnCallbackState *new_state = msn_callback_state_dup(state);
				msn_add_contact_to_group(session, new_state, state->who, guid);
				g_free(guid);
				return;
			}
			g_free(guid);
		} else {
			purple_debug_info("msn", "Adding group %s failed\n",
				state->new_group_name);
		}
	}

	if (state->action & MSN_DEL_GROUP) {
		GList *l;

		msn_userlist_remove_group_id(session->userlist, state->guid);
		for (l = userlist->users; l != NULL; l = l->next) {
			msn_user_remove_group_id( (MsnUser *)l->data, state->guid);
		}
	}
}

/* add group */
void
msn_add_group(MsnSession *session, MsnCallbackState *state, const char* group_name)
{
	char *body = NULL;
	char *escaped_group_name = NULL;

	g_return_if_fail(session != NULL);
	g_return_if_fail(group_name != NULL);

	purple_debug_info("msn", "Adding group %s to contact list.\n", group_name);

	if (state == NULL) {
		state = msn_callback_state_new(session);
	}

	msn_callback_state_set_action(state, MSN_ADD_GROUP);
	msn_callback_state_set_new_group_name(state, group_name);

	/* escape group name's html special chars so it can safely be sent
	* in a XML SOAP request
	*/
	escaped_group_name = g_markup_escape_text(group_name, -1);
	body = g_strdup_printf(MSN_GROUP_ADD_TEMPLATE, escaped_group_name);

	state->body = xmlnode_from_str(body, -1);
	state->post_action = MSN_GROUP_ADD_SOAP_ACTION;
	state->post_url = MSN_ADDRESS_BOOK_POST_URL;
	state->cb = msn_group_read_cb;
	msn_contact_request(state);

	g_free(escaped_group_name);
	g_free(body);
}

/* delete group */
void
msn_del_group(MsnSession *session, const gchar *group_name)
{
	MsnCallbackState *state;
	char *body = NULL;
	const gchar *guid;

	g_return_if_fail(session != NULL);

	g_return_if_fail(group_name != NULL);
	purple_debug_info("msn", "Deleting group %s from contact list\n", group_name);

	guid = msn_userlist_find_group_id(session->userlist, group_name);

	/* if group uid we need to del is NULL,
	*  we need to delete nothing
	*/
	if (guid == NULL) {
		purple_debug_info("msn", "Group %s guid not found, returning.\n", group_name);
		return;
	}

	if ( !strcmp(guid, MSN_INDIVIDUALS_GROUP_ID) || !strcmp(guid, MSN_NON_IM_GROUP_ID) ) {
		/* XXX add back PurpleGroup since it isn't really removed in the server? */
		return;
	}

	state = msn_callback_state_new(session);
	msn_callback_state_set_action(state, MSN_DEL_GROUP);
	msn_callback_state_set_guid(state, guid);

	body = g_strdup_printf(MSN_GROUP_DEL_TEMPLATE, guid);

	state->body = xmlnode_from_str(body, -1);
	state->post_action = MSN_GROUP_DEL_SOAP_ACTION;
	state->post_url = MSN_ADDRESS_BOOK_POST_URL;
	state->cb = msn_group_read_cb;
	msn_contact_request(state);

	g_free(body);
}

/* rename group */
void
msn_contact_rename_group(MsnSession *session, const char *old_group_name, const char *new_group_name)
{
	gchar *body = NULL;
	const gchar * guid;
	MsnCallbackState *state;
	char *escaped_group_name;

	g_return_if_fail(session != NULL);
	g_return_if_fail(session->userlist != NULL);
	g_return_if_fail(old_group_name != NULL);
	g_return_if_fail(new_group_name != NULL);

	purple_debug_info("msn", "Renaming group %s to %s.\n", old_group_name, new_group_name);

	guid = msn_userlist_find_group_id(session->userlist, old_group_name);
	if (guid == NULL)
		return;

	state = msn_callback_state_new(session);
	msn_callback_state_set_guid(state, guid);
	msn_callback_state_set_new_group_name(state, new_group_name);

	if ( !strcmp(guid, MSN_INDIVIDUALS_GROUP_ID) || !strcmp(guid, MSN_NON_IM_GROUP_ID) ) {
		MsnCallbackState *new_state = msn_callback_state_dup(state);
		msn_add_group(session, new_state, new_group_name);
		/* XXX move every buddy there (we probably need to fix concurrent SOAP reqs first) */
	}

	msn_callback_state_set_action(state, MSN_RENAME_GROUP);

	escaped_group_name = g_markup_escape_text(new_group_name, -1);
	body = g_strdup_printf(MSN_GROUP_RENAME_TEMPLATE, guid, escaped_group_name);

	state->body = xmlnode_from_str(body, -1);
	state->post_action = MSN_GROUP_RENAME_SOAP_ACTION;
	state->post_url = MSN_ADDRESS_BOOK_POST_URL;
	state->cb = msn_group_read_cb;
	msn_contact_request(state);

	g_free(escaped_group_name);
	g_free(body);
}

