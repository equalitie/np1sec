/*
 * purple - Jabber Protocol Plugin
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
 *
 */
#include "internal.h"
#include "debug.h"
#include "imgstore.h"
#include "prpl.h"
#include "notify.h"
#include "request.h"
#include "util.h"
#include "xmlnode.h"

#include "buddy.h"
#include "chat.h"
#include "jabber.h"
#include "iq.h"
#include "presence.h"
#include "useravatar.h"
#include "xdata.h"
#include "pep.h"
#include "adhoccommands.h"
#include "google/google.h"

typedef struct {
	long idle_seconds;
} JabberBuddyInfoResource;

typedef struct {
	JabberStream *js;
	JabberBuddy *jb;
	char *jid;
	GSList *ids;
	GHashTable *resources;
	guint timeout_handle;
	GSList *vcard_imgids;
	PurpleNotifyUserInfo *user_info;
	long last_seconds;
	gchar *last_message;
} JabberBuddyInfo;

static void
jabber_buddy_resource_free(JabberBuddyResource *jbr)
{
	g_return_if_fail(jbr != NULL);

	jbr->jb->resources = g_list_remove(jbr->jb->resources, jbr);

	while(jbr->commands) {
		JabberAdHocCommands *cmd = jbr->commands->data;
		g_free(cmd->jid);
		g_free(cmd->node);
		g_free(cmd->name);
		g_free(cmd);
		jbr->commands = g_list_delete_link(jbr->commands, jbr->commands);
	}

	while (jbr->caps.exts) {
		g_free(jbr->caps.exts->data);
		jbr->caps.exts = g_list_delete_link(jbr->caps.exts, jbr->caps.exts);
	}

	g_free(jbr->name);
	g_free(jbr->status);
	g_free(jbr->thread_id);
	g_free(jbr->client.name);
	g_free(jbr->client.version);
	g_free(jbr->client.os);
	g_free(jbr);
}

void jabber_buddy_free(JabberBuddy *jb)
{
	g_return_if_fail(jb != NULL);

	g_free(jb->error_msg);
	while(jb->resources)
		jabber_buddy_resource_free(jb->resources->data);

	g_free(jb);
}

JabberBuddy *jabber_buddy_find(JabberStream *js, const char *name,
		gboolean create)
{
	JabberBuddy *jb;
	char *realname;

	if (js->buddies == NULL)
		return NULL;

	if(!(realname = jabber_get_bare_jid(name)))
		return NULL;

	jb = g_hash_table_lookup(js->buddies, realname);

	if(!jb && create) {
		jb = g_new0(JabberBuddy, 1);
		g_hash_table_insert(js->buddies, realname, jb);
	} else
		g_free(realname);

	return jb;
}

/* Returns -1 if a is a higher priority resource than b, or is
 * "more available" than b.  0 if they're the same, and 1 if b is
 * higher priority/more available than a.
 */
static gint resource_compare_cb(gconstpointer a, gconstpointer b)
{
	const JabberBuddyResource *jbra = a;
	const JabberBuddyResource *jbrb = b;
	JabberBuddyState state_a, state_b;

	if (jbra->priority != jbrb->priority)
		return jbra->priority > jbrb->priority ? -1 : 1;

	/* Fold the states for easier comparison */
	/* TODO: Differentiate online/chat and away/dnd? */
	switch (jbra->state) {
		case JABBER_BUDDY_STATE_ONLINE:
		case JABBER_BUDDY_STATE_CHAT:
			state_a = JABBER_BUDDY_STATE_ONLINE;
			break;
		case JABBER_BUDDY_STATE_AWAY:
		case JABBER_BUDDY_STATE_DND:
			state_a = JABBER_BUDDY_STATE_AWAY;
			break;
		case JABBER_BUDDY_STATE_XA:
			state_a = JABBER_BUDDY_STATE_XA;
			break;
		case JABBER_BUDDY_STATE_UNAVAILABLE:
			state_a = JABBER_BUDDY_STATE_UNAVAILABLE;
			break;
		default:
			state_a = JABBER_BUDDY_STATE_UNKNOWN;
			break;
	}

	switch (jbrb->state) {
		case JABBER_BUDDY_STATE_ONLINE:
		case JABBER_BUDDY_STATE_CHAT:
			state_b = JABBER_BUDDY_STATE_ONLINE;
			break;
		case JABBER_BUDDY_STATE_AWAY:
		case JABBER_BUDDY_STATE_DND:
			state_b = JABBER_BUDDY_STATE_AWAY;
			break;
		case JABBER_BUDDY_STATE_XA:
			state_b = JABBER_BUDDY_STATE_XA;
			break;
		case JABBER_BUDDY_STATE_UNAVAILABLE:
			state_b = JABBER_BUDDY_STATE_UNAVAILABLE;
			break;
		default:
			state_b = JABBER_BUDDY_STATE_UNKNOWN;
			break;
	}

	if (state_a == state_b) {
		if (jbra->idle == jbrb->idle)
			return 0;
		else if ((jbra->idle && !jbrb->idle) ||
				(jbra->idle && jbrb->idle && jbra->idle < jbrb->idle))
			return 1;
		else
			return -1;
	}

	if (state_a == JABBER_BUDDY_STATE_ONLINE)
		return -1;
	else if (state_a == JABBER_BUDDY_STATE_AWAY &&
				(state_b == JABBER_BUDDY_STATE_XA ||
				 state_b == JABBER_BUDDY_STATE_UNAVAILABLE ||
				 state_b == JABBER_BUDDY_STATE_UNKNOWN))
		return -1;
	else if (state_a == JABBER_BUDDY_STATE_XA &&
				(state_b == JABBER_BUDDY_STATE_UNAVAILABLE ||
				 state_b == JABBER_BUDDY_STATE_UNKNOWN))
		return -1;
	else if (state_a == JABBER_BUDDY_STATE_UNAVAILABLE &&
				state_b == JABBER_BUDDY_STATE_UNKNOWN)
		return -1;

	return 1;
}

JabberBuddyResource *jabber_buddy_find_resource(JabberBuddy *jb,
		const char *resource)
{
	GList *l;

	if (!jb)
		return NULL;

	if (resource == NULL)
		return jb->resources ? jb->resources->data : NULL;

	for (l = jb->resources; l; l = l->next)
	{
		JabberBuddyResource *jbr = l->data;
		if (jbr->name && g_str_equal(resource, jbr->name))
			return jbr;
	}

	return NULL;
}

JabberBuddyResource *jabber_buddy_track_resource(JabberBuddy *jb, const char *resource,
		int priority, JabberBuddyState state, const char *status)
{
	/* TODO: Optimization: Only reinsert if priority+state changed */
	JabberBuddyResource *jbr = jabber_buddy_find_resource(jb, resource);
	if (jbr) {
		jb->resources = g_list_remove(jb->resources, jbr);
	} else {
		jbr = g_new0(JabberBuddyResource, 1);
		jbr->jb = jb;
		jbr->name = g_strdup(resource);
		jbr->capabilities = JABBER_CAP_NONE;
		jbr->tz_off = PURPLE_NO_TZ_OFF;
	}
	jbr->priority = priority;
	jbr->state = state;
	g_free(jbr->status);
	jbr->status = g_strdup(status);

	jb->resources = g_list_insert_sorted(jb->resources, jbr,
	                                     resource_compare_cb);
	return jbr;
}

void jabber_buddy_remove_resource(JabberBuddy *jb, const char *resource)
{
	JabberBuddyResource *jbr = jabber_buddy_find_resource(jb, resource);

	if(!jbr)
		return;

	jabber_buddy_resource_free(jbr);
}

/*******
 * This is the old vCard stuff taken from the old prpl.  vCards, by definition
 * are a temporary thing until jabber can get its act together and come up
 * with a format for user information, hence the namespace of 'vcard-temp'
 *
 * Since I don't feel like putting that much work into something that's
 * _supposed_ to go away, i'm going to just copy the kludgy old code here,
 * and make it purdy when jabber comes up with a standards-track JEP to
 * replace vcard-temp
 *                                 --Nathan
 *******/

/*---------------------------------------*/
/* Jabber "set info" (vCard) support     */
/*---------------------------------------*/

/*
 * V-Card format:
 *
 *  <vCard prodid='' version='' xmlns=''>
 *    <FN></FN>
 *    <N>
 *	<FAMILY/>
 *	<GIVEN/>
 *    </N>
 *    <NICKNAME/>
 *    <URL/>
 *    <ADR>
 *	<STREET/>
 *	<EXTADD/>
 *	<LOCALITY/>
 *	<REGION/>
 *	<PCODE/>
 *	<COUNTRY/>
 *    </ADR>
 *    <TEL/>
 *    <EMAIL/>
 *    <ORG>
 *	<ORGNAME/>
 *	<ORGUNIT/>
 *    </ORG>
 *    <TITLE/>
 *    <ROLE/>
 *    <DESC/>
 *    <BDAY/>
 *  </vCard>
 *
 * See also:
 *
 *	http://docs.jabber.org/proto/html/vcard-temp.html
 *	http://www.vcard-xml.org/dtd/vCard-XML-v2-20010520.dtd
 */

/*
 * Cross-reference user-friendly V-Card entry labels to vCard XML tags
 * and attributes.
 *
 * Order is (or should be) unimportant.  For example: we have no way of
 * knowing in what order real data will arrive.
 *
 * Format: Label, Pre-set text, "visible" flag, "editable" flag, XML tag
 *         name, XML tag's parent tag "path" (relative to vCard node).
 *
 *         List is terminated by a NULL label pointer.
 *
 *	   Entries with no label text, but with XML tag and parent tag
 *	   entries, are used by V-Card XML construction routines to
 *	   "automagically" construct the appropriate XML node tree.
 *
 * Thoughts on future direction/expansion
 *
 *	This is a "simple" vCard.
 *
 *	It is possible for nodes other than the "vCard" node to have
 *      attributes.  Should that prove necessary/desirable, add an
 *      "attributes" pointer to the vcard_template struct, create the
 *      necessary tag_attr structs, and add 'em to the vcard_dflt_data
 *      array.
 *
 *	The above changes will (obviously) require changes to the vCard
 *      construction routines.
 */

struct vcard_template {
	char *label;			/* label text pointer */
	char *tag;			/* tag text */
	char *ptag;			/* parent tag "path" text */
} const vcard_template_data[] = {
	{N_("Full Name"),          "FN",        NULL},
	{N_("Family Name"),        "FAMILY",    "N"},
	{N_("Given Name"),         "GIVEN",     "N"},
	{N_("Nickname"),           "NICKNAME",  NULL},
	{N_("URL"),                "URL",       NULL},
	{N_("Street Address"),     "STREET",    "ADR"},
	{N_("Extended Address"),   "EXTADD",    "ADR"},
	{N_("Locality"),           "LOCALITY",  "ADR"},
	{N_("Region"),             "REGION",    "ADR"},
	{N_("Postal Code"),        "PCODE",     "ADR"},
	{N_("Country"),            "CTRY",      "ADR"},
	{N_("Telephone"),          "NUMBER",    "TEL"},
	{N_("Email"),              "USERID",    "EMAIL"},
	{N_("Organization Name"),  "ORGNAME",   "ORG"},
	{N_("Organization Unit"),  "ORGUNIT",   "ORG"},
	{N_("Job Title"),          "TITLE",     NULL},
	{N_("Role"),               "ROLE",      NULL},
	{N_("Birthday"),           "BDAY",      NULL},
	{N_("Description"),        "DESC",      NULL},
	{"",                       "N",         NULL},
	{"",                       "ADR",       NULL},
	{"",                       "ORG",       NULL},
	{NULL,                     NULL,        NULL}
};

/*
 * The "vCard" tag's attribute list...
 */
struct tag_attr {
	char *attr;
	char *value;
} const vcard_tag_attr_list[] = {
	{"prodid",   "-//HandGen//NONSGML vGen v1.0//EN"},
	{"version",  "2.0",                             },
	{"xmlns",    "vcard-temp",                      },
	{NULL, NULL},
};


/*
 * Insert a tag node into an xmlnode tree, recursively inserting parent tag
 * nodes as necessary
 *
 * Returns pointer to inserted node
 *
 * Note to hackers: this code is designed to be re-entrant (it's recursive--it
 * calls itself), so don't put any "static"s in here!
 */
static xmlnode *insert_tag_to_parent_tag(xmlnode *start, const char *parent_tag, const char *new_tag)
{
	xmlnode *x = NULL;

	/*
	 * If the parent tag wasn't specified, see if we can get it
	 * from the vCard template struct.
	 */
	if(parent_tag == NULL) {
		const struct vcard_template *vc_tp = vcard_template_data;

		while(vc_tp->label != NULL) {
			if(strcmp(vc_tp->tag, new_tag) == 0) {
				parent_tag = vc_tp->ptag;
				break;
			}
			++vc_tp;
		}
	}

	/*
	 * If we have a parent tag...
	 */
	if(parent_tag != NULL ) {
		/*
		 * Try to get the parent node for a tag
		 */
		if((x = xmlnode_get_child(start, parent_tag)) == NULL) {
			/*
			 * Descend?
			 */
			char *grand_parent = g_strdup(parent_tag);
			char *parent;

			if((parent = strrchr(grand_parent, '/')) != NULL) {
				*(parent++) = '\0';
				x = insert_tag_to_parent_tag(start, grand_parent, parent);
			} else {
				x = xmlnode_new_child(start, grand_parent);
			}
			g_free(grand_parent);
		} else {
			/*
			 * We found *something* to be the parent node.
			 * Note: may be the "root" node!
			 */
			xmlnode *y;
			if((y = xmlnode_get_child(x, new_tag)) != NULL) {
				return(y);
			}
		}
	}

	/*
	 * insert the new tag into its parent node
	 */
	return(xmlnode_new_child((x == NULL? start : x), new_tag));
}

/*
 * Send vCard info to Jabber server
 */
void jabber_set_info(PurpleConnection *gc, const char *info)
{
	PurpleStoredImage *img;
	JabberIq *iq;
	JabberStream *js = purple_connection_get_protocol_data(gc);
	xmlnode *vc_node;
	const struct tag_attr *tag_attr;

	/* if we have't grabbed the remote vcard yet, we can't
	 * assume that what we have here is correct */
	if(!js->vcard_fetched)
		return;

	if (js->vcard_timer) {
		purple_timeout_remove(js->vcard_timer);
		js->vcard_timer = 0;
	}

	g_free(js->avatar_hash);
	js->avatar_hash = NULL;

	/*
	 * Send only if there's actually any *information* to send
	 */
	vc_node = info ? xmlnode_from_str(info, -1) : NULL;

	if (vc_node && (!vc_node->name ||
			g_ascii_strncasecmp(vc_node->name, "vCard", 5))) {
		xmlnode_free(vc_node);
		vc_node = NULL;
	}

	if ((img = purple_buddy_icons_find_account_icon(gc->account))) {
		gconstpointer avatar_data;
		gsize avatar_len;
		xmlnode *photo, *binval, *type;
		gchar *enc;

		if(!vc_node) {
			vc_node = xmlnode_new("vCard");
			for(tag_attr = vcard_tag_attr_list; tag_attr->attr != NULL; ++tag_attr)
				xmlnode_set_attrib(vc_node, tag_attr->attr, tag_attr->value);
		}

		avatar_data = purple_imgstore_get_data(img);
		avatar_len = purple_imgstore_get_size(img);
		/* Get rid of an old PHOTO if one exists.
		 * TODO: This may want to be modified to remove all old PHOTO
		 * children, at the moment some people have managed to get
		 * multiple PHOTO entries in their vCard. */
		if((photo = xmlnode_get_child(vc_node, "PHOTO"))) {
			xmlnode_free(photo);
		}
		photo = xmlnode_new_child(vc_node, "PHOTO");
		type = xmlnode_new_child(photo, "TYPE");
		xmlnode_insert_data(type, "image/png", -1);
		binval = xmlnode_new_child(photo, "BINVAL");
		enc = purple_base64_encode(avatar_data, avatar_len);

		js->avatar_hash =
			jabber_calculate_data_hash(avatar_data, avatar_len, "sha1");

		xmlnode_insert_data(binval, enc, -1);
		g_free(enc);
		purple_imgstore_unref(img);
	} else if (vc_node) {
		xmlnode *photo;
		/* TODO: Remove all PHOTO children? (see above note) */
		if ((photo = xmlnode_get_child(vc_node, "PHOTO"))) {
			xmlnode_free(photo);
		}
	}

	if (vc_node != NULL) {
		iq = jabber_iq_new(js, JABBER_IQ_SET);
		xmlnode_insert_child(iq->node, vc_node);
		jabber_iq_send(iq);

		/* Send presence to update vcard-temp:x:update */
		jabber_presence_send(js, FALSE);
	}
}

void jabber_set_buddy_icon(PurpleConnection *gc, PurpleStoredImage *img)
{
	PurpleAccount *account = purple_connection_get_account(gc);

	/* Publish the avatar as specified in XEP-0084 */
	jabber_avatar_set(gc->proto_data, img);
	/* Set the image in our vCard */
	jabber_set_info(gc, purple_account_get_user_info(account));

	/* TODO: Fake image to ourselves, since a number of servers do not echo
	 * back our presence to us. To do this without uselessly copying the data
	 * of the image, we need purple_buddy_icons_set_for_user_image (i.e. takes
	 * an existing icon/stored image). */
}

/*
 * This is the callback from the "ok clicked" for "set vCard"
 *
 * Sets the vCard with data from PurpleRequestFields.
 */
static void
jabber_format_info(PurpleConnection *gc, PurpleRequestFields *fields)
{
	xmlnode *vc_node;
	PurpleRequestField *field;
	const char *text;
	char *p;
	const struct vcard_template *vc_tp;
	const struct tag_attr *tag_attr;

	vc_node = xmlnode_new("vCard");

	for(tag_attr = vcard_tag_attr_list; tag_attr->attr != NULL; ++tag_attr)
		xmlnode_set_attrib(vc_node, tag_attr->attr, tag_attr->value);

	for (vc_tp = vcard_template_data; vc_tp->label != NULL; vc_tp++) {
		if (*vc_tp->label == '\0')
			continue;

		field = purple_request_fields_get_field(fields, vc_tp->tag);
		text  = purple_request_field_string_get_value(field);


		if (text != NULL && *text != '\0') {
			xmlnode *xp;

			purple_debug_info("jabber", "Setting %s to '%s'\n", vc_tp->tag, text);

			if ((xp = insert_tag_to_parent_tag(vc_node,
											   NULL, vc_tp->tag)) != NULL) {

				xmlnode_insert_data(xp, text, -1);
			}
		}
	}

	p = xmlnode_to_str(vc_node, NULL);
	xmlnode_free(vc_node);

	purple_account_set_user_info(purple_connection_get_account(gc), p);
	serv_set_info(gc, p);

	g_free(p);
}

/*
 * This gets executed by the proto action
 *
 * Creates a new PurpleRequestFields struct, gets the XML-formatted user_info
 * string (if any) into GSLists for the (multi-entry) edit dialog and
 * calls the set_vcard dialog.
 */
void jabber_setup_set_info(PurplePluginAction *action)
{
	PurpleConnection *gc = (PurpleConnection *) action->context;
	PurpleRequestFields *fields;
	PurpleRequestFieldGroup *group;
	PurpleRequestField *field;
	const struct vcard_template *vc_tp;
	const char *user_info;
	char *cdata = NULL;
	xmlnode *x_vc_data = NULL;

	fields = purple_request_fields_new();
	group = purple_request_field_group_new(NULL);
	purple_request_fields_add_group(fields, group);

	/*
	 * Get existing, XML-formatted, user info
	 */
	if((user_info = purple_account_get_user_info(gc->account)) != NULL)
		x_vc_data = xmlnode_from_str(user_info, -1);

	/*
	 * Set up GSLists for edit with labels from "template," data from user info
	 */
	for(vc_tp = vcard_template_data; vc_tp->label != NULL; ++vc_tp) {
		xmlnode *data_node;
		if((vc_tp->label)[0] == '\0')
			continue;

		if (x_vc_data != NULL) {
			if(vc_tp->ptag == NULL) {
				data_node = xmlnode_get_child(x_vc_data, vc_tp->tag);
			} else {
				gchar *tag = g_strdup_printf("%s/%s", vc_tp->ptag, vc_tp->tag);
				data_node = xmlnode_get_child(x_vc_data, tag);
				g_free(tag);
			}
			if(data_node)
				cdata = xmlnode_get_data(data_node);
		}

		if(strcmp(vc_tp->tag, "DESC") == 0) {
			field = purple_request_field_string_new(vc_tp->tag,
												  _(vc_tp->label), cdata,
												  TRUE);
		} else {
			field = purple_request_field_string_new(vc_tp->tag,
												  _(vc_tp->label), cdata,
												  FALSE);
		}

		g_free(cdata);
		cdata = NULL;

		purple_request_field_group_add_field(group, field);
	}

	if(x_vc_data != NULL)
		xmlnode_free(x_vc_data);

	purple_request_fields(gc, _("Edit XMPP vCard"),
						_("Edit XMPP vCard"),
						_("All items below are optional. Enter only the "
						  "information with which you feel comfortable."),
						fields,
						_("Save"), G_CALLBACK(jabber_format_info),
						_("Cancel"), NULL,
						purple_connection_get_account(gc), NULL, NULL,
						gc);
}

/*---------------------------------------*/
/* End Jabber "set info" (vCard) support */
/*---------------------------------------*/

/******
 * end of that ancient crap that needs to die
 ******/

static void jabber_buddy_info_destroy(JabberBuddyInfo *jbi)
{
	/* Remove the timeout, which would otherwise trigger jabber_buddy_get_info_timeout() */
	if (jbi->timeout_handle > 0)
		purple_timeout_remove(jbi->timeout_handle);

	g_free(jbi->jid);
	g_hash_table_destroy(jbi->resources);
	g_free(jbi->last_message);
	purple_notify_user_info_destroy(jbi->user_info);
	g_free(jbi);
}

static void
add_jbr_info(JabberBuddyInfo *jbi, const char *resource,
             JabberBuddyResource *jbr)
{
	JabberBuddyInfoResource *jbir;
	PurpleNotifyUserInfo *user_info;

	jbir = g_hash_table_lookup(jbi->resources, resource);
	user_info = jbi->user_info;

	if (jbr && jbr->client.name) {
		char *tmp =
			g_strdup_printf("%s%s%s", jbr->client.name,
		                    (jbr->client.version ? " " : ""),
		                    (jbr->client.version ? jbr->client.version : ""));
		purple_notify_user_info_prepend_pair(user_info, _("Client"), tmp);
		g_free(tmp);

		if (jbr->client.os)
			purple_notify_user_info_prepend_pair(user_info, _("Operating System"), jbr->client.os);
	}

	if (jbr && jbr->tz_off != PURPLE_NO_TZ_OFF) {
		time_t now_t;
		struct tm *now;
		char *timestamp;
		time(&now_t);
		now_t += jbr->tz_off;
		now = gmtime(&now_t);

		timestamp =
			g_strdup_printf("%s %c%02d%02d", purple_time_format(now),
		                    jbr->tz_off < 0 ? '-' : '+',
		                    abs(jbr->tz_off / (60*60)),
		                    abs((jbr->tz_off % (60*60)) / 60));
		purple_notify_user_info_prepend_pair(user_info, _("Local Time"), timestamp);
		g_free(timestamp);
	}

	if (jbir && jbir->idle_seconds > 0) {
		char *idle = purple_str_seconds_to_string(jbir->idle_seconds);
		purple_notify_user_info_prepend_pair(user_info, _("Idle"), idle);
		g_free(idle);
	}

	if (jbr) {
		char *purdy = NULL;
		char *tmp;
		char priority[12];
		const char *status_name = jabber_buddy_state_get_name(jbr->state);

		if (jbr->status) {
			tmp = purple_markup_escape_text(jbr->status, -1);
			purdy = purple_strdup_withhtml(tmp);
			g_free(tmp);

			if (purple_strequal(status_name, purdy))
				status_name = NULL;
		}

		tmp = g_strdup_printf("%s%s%s", (status_name ? status_name : ""),
						((status_name && purdy) ? ": " : ""),
						(purdy ? purdy : ""));
		purple_notify_user_info_prepend_pair(user_info, _("Status"), tmp);

		g_snprintf(priority, sizeof(priority), "%d", jbr->priority);
		purple_notify_user_info_prepend_pair(user_info, _("Priority"), priority);

		g_free(tmp);
		g_free(purdy);
	} else {
		purple_notify_user_info_prepend_pair(user_info, _("Status"), _("Unknown"));
	}
}

static void jabber_buddy_info_show_if_ready(JabberBuddyInfo *jbi)
{
	char *resource_name;
	JabberBuddyResource *jbr;
	GList *resources;
	PurpleNotifyUserInfo *user_info;

	/* not yet */
	if (jbi->ids)
		return;

	user_info = jbi->user_info;
	resource_name = jabber_get_resource(jbi->jid);

	/* If we have one or more pairs from the vcard, put a section break above it */
	if (purple_notify_user_info_get_entries(user_info))
		purple_notify_user_info_prepend_section_break(user_info);

	/* Add the information about the user's resource(s) */
	if (resource_name) {
		jbr = jabber_buddy_find_resource(jbi->jb, resource_name);
		add_jbr_info(jbi, resource_name, jbr);
	} else {
		/* TODO: This is in priority-ascending order (lowest prio first), because
		 * everything is prepended.  Is that ok? */
		for (resources = jbi->jb->resources; resources; resources = resources->next) {
			jbr = resources->data;

			/* put a section break between resources, this is not needed if
			 we are at the first, because one was already added for the vcard
			 section */
			if (resources != jbi->jb->resources)
				purple_notify_user_info_prepend_section_break(user_info);

			add_jbr_info(jbi, jbr->name, jbr);

			if (jbr->name)
				purple_notify_user_info_prepend_pair(user_info, _("Resource"), jbr->name);
		}
	}

	if (!jbi->jb->resources) {
		/* the buddy is offline */
		gboolean is_domain = jabber_jid_is_domain(jbi->jid);

		if (jbi->last_seconds > 0) {
			char *last = purple_str_seconds_to_string(jbi->last_seconds);
			gchar *message = NULL;
			const gchar *title = NULL;
			if (is_domain) {
				title = _("Uptime");
				message = last;
				last = NULL;
			} else {
				title = _("Logged Off");
				message = g_strdup_printf(_("%s ago"), last);
			}
			purple_notify_user_info_prepend_pair(user_info, title, message);
			g_free(last);
			g_free(message);
		}

		if (!is_domain) {
			gchar *status =
				g_strdup_printf("%s%s%s",	_("Offline"),
				                jbi->last_message ? ": " : "",
				                jbi->last_message ? jbi->last_message : "");
			purple_notify_user_info_prepend_pair(user_info, _("Status"), status);
			g_free(status);
		}
	}

	g_free(resource_name);

	purple_notify_userinfo(jbi->js->gc, jbi->jid, user_info, NULL, NULL);

	while (jbi->vcard_imgids) {
		purple_imgstore_unref_by_id(GPOINTER_TO_INT(jbi->vcard_imgids->data));
		jbi->vcard_imgids = g_slist_delete_link(jbi->vcard_imgids, jbi->vcard_imgids);
	}

	jbi->js->pending_buddy_info_requests = g_slist_remove(jbi->js->pending_buddy_info_requests, jbi);

	jabber_buddy_info_destroy(jbi);
}

static void jabber_buddy_info_remove_id(JabberBuddyInfo *jbi, const char *id)
{
	GSList *l = jbi->ids;
	char *comp_id;

	if(!id)
		return;

	while(l) {
		comp_id = l->data;
		if(!strcmp(id, comp_id)) {
			jbi->ids = g_slist_remove(jbi->ids, comp_id);
			g_free(comp_id);
			return;
		}
		l = l->next;
	}
}

static gboolean
set_own_vcard_cb(gpointer data)
{
	JabberStream *js = data;
	PurpleAccount *account = purple_connection_get_account(js->gc);

	js->vcard_timer = 0;

	jabber_set_info(js->gc, purple_account_get_user_info(account));

	return FALSE;
}

static void jabber_vcard_save_mine(JabberStream *js, const char *from,
                                   JabberIqType type, const char *id,
                                   xmlnode *packet, gpointer data)
{
	xmlnode *vcard, *photo, *binval;
	char *txt, *vcard_hash = NULL;
	PurpleAccount *account;

	if (type == JABBER_IQ_ERROR) {
		xmlnode *error;
		purple_debug_warning("jabber", "Server returned error while retrieving vCard\n");

		error = xmlnode_get_child(packet, "error");
		if (!error || !xmlnode_get_child(error, "item-not-found"))
			return;
	}

	account = purple_connection_get_account(js->gc);

	if((vcard = xmlnode_get_child(packet, "vCard")) ||
			(vcard = xmlnode_get_child_with_namespace(packet, "query", "vcard-temp")))
	{
		txt = xmlnode_to_str(vcard, NULL);
		purple_account_set_user_info(account, txt);
		g_free(txt);
	} else {
		/* if we have no vCard, then lets not overwrite what we might have locally */
	}

	js->vcard_fetched = TRUE;

	if (vcard && (photo = xmlnode_get_child(vcard, "PHOTO")) &&
	             (binval = xmlnode_get_child(photo, "BINVAL"))) {
		gsize size;
		char *bintext = xmlnode_get_data(binval);
		if (bintext) {
			guchar *data = purple_base64_decode(bintext, &size);
			g_free(bintext);

			if (data) {
				vcard_hash = jabber_calculate_data_hash(data, size, "sha1");
				g_free(data);
			}
		}
	}

	/* Republish our vcard if the photo is different than the server's */
	if (js->initial_avatar_hash && !purple_strequal(vcard_hash, js->initial_avatar_hash)) {
		/*
		 * Google Talk has developed the behavior that it will not accept
		 * a vcard set in the first 10 seconds (or so) of the connection;
		 * it returns an error (namespaces trimmed):
		 * <error code="500" type="wait"><internal-server-error/></error>.
		 */
		if (js->googletalk)
			js->vcard_timer = purple_timeout_add_seconds(10, set_own_vcard_cb,
			                                             js);
		else
			jabber_set_info(js->gc, purple_account_get_user_info(account));
	} else if (vcard_hash) {
		/* A photo is in the vCard. Advertise its hash */
		js->avatar_hash = vcard_hash;
		vcard_hash = NULL;

		/* Send presence to update vcard-temp:x:update */
		jabber_presence_send(js, FALSE);
	}

	g_free(vcard_hash);
}

void jabber_vcard_fetch_mine(JabberStream *js)
{
	JabberIq *iq = jabber_iq_new(js, JABBER_IQ_GET);

	xmlnode *vcard = xmlnode_new_child(iq->node, "vCard");
	xmlnode_set_namespace(vcard, "vcard-temp");
	jabber_iq_set_callback(iq, jabber_vcard_save_mine, NULL);

	jabber_iq_send(iq);
}

static void jabber_vcard_parse(JabberStream *js, const char *from,
                               JabberIqType type, const char *id,
                               xmlnode *packet, gpointer data)
{
	char *bare_jid;
	char *text;
	char *serverside_alias = NULL;
	xmlnode *vcard;
	PurpleAccount *account;
	JabberBuddyInfo *jbi = data;
	PurpleNotifyUserInfo *user_info;

	g_return_if_fail(jbi != NULL);

	jabber_buddy_info_remove_id(jbi, id);

	if (type == JABBER_IQ_ERROR) {
		purple_debug_info("jabber", "Got error response for vCard\n");
		jabber_buddy_info_show_if_ready(jbi);
		return;
	}

	user_info = jbi->user_info;
	account = purple_connection_get_account(js->gc);
	bare_jid = jabber_get_bare_jid(from ? from : purple_account_get_username(account));

	/* TODO: Is the query xmlns='vcard-temp' version of this still necessary? */
	if((vcard = xmlnode_get_child(packet, "vCard")) ||
			(vcard = xmlnode_get_child_with_namespace(packet, "query", "vcard-temp"))) {
		xmlnode *child;
		for(child = vcard->child; child; child = child->next)
		{
			xmlnode *child2;

			if(child->type != XMLNODE_TYPE_TAG)
				continue;

			text = xmlnode_get_data(child);
			if(text && !strcmp(child->name, "FN")) {
				if (!serverside_alias)
					serverside_alias = g_strdup(text);

				purple_notify_user_info_add_pair_plaintext(user_info, _("Full Name"), text);
			} else if(!strcmp(child->name, "N")) {
				for(child2 = child->child; child2; child2 = child2->next)
				{
					char *text2;

					if(child2->type != XMLNODE_TYPE_TAG)
						continue;

					text2 = xmlnode_get_data(child2);
					if(text2 && !strcmp(child2->name, "FAMILY")) {
						purple_notify_user_info_add_pair_plaintext(user_info, _("Family Name"), text2);
					} else if(text2 && !strcmp(child2->name, "GIVEN")) {
						purple_notify_user_info_add_pair_plaintext(user_info, _("Given Name"), text2);
					} else if(text2 && !strcmp(child2->name, "MIDDLE")) {
						purple_notify_user_info_add_pair_plaintext(user_info, _("Middle Name"), text2);
					}
					g_free(text2);
				}
			} else if(text && !strcmp(child->name, "NICKNAME")) {
				/* Prefer the Nickcname to the Full Name as the serverside alias if it's not just part of the jid.
				 * Ignore it if it's part of the jid. */
				if (strstr(bare_jid, text) == NULL) {
					g_free(serverside_alias);
					serverside_alias = g_strdup(text);

					purple_notify_user_info_add_pair_plaintext(user_info, _("Nickname"), text);
				}
			} else if(text && !strcmp(child->name, "BDAY")) {
				purple_notify_user_info_add_pair_plaintext(user_info, _("Birthday"), text);
			} else if(!strcmp(child->name, "ADR")) {
				gboolean address_line_added = FALSE;

				for(child2 = child->child; child2; child2 = child2->next)
				{
					char *text2;

					if(child2->type != XMLNODE_TYPE_TAG)
						continue;

					text2 = xmlnode_get_data(child2);
					if (text2 == NULL)
						continue;

					/* We do this here so that it's not added if all the child
					 * elements are empty. */
					if (!address_line_added)
					{
						purple_notify_user_info_add_section_header(user_info, _("Address"));
						address_line_added = TRUE;
					}

					if(!strcmp(child2->name, "POBOX")) {
						purple_notify_user_info_add_pair_plaintext(user_info, _("P.O. Box"), text2);
					} else if (g_str_equal(child2->name, "EXTADD") || g_str_equal(child2->name, "EXTADR")) {
						/*
						 * EXTADD is correct, EXTADR is generated by other
						 * clients. The next time someone reads this, remove
						 * EXTADR.
						 */
						purple_notify_user_info_add_pair_plaintext(user_info, _("Extended Address"), text2);
					} else if(!strcmp(child2->name, "STREET")) {
						purple_notify_user_info_add_pair_plaintext(user_info, _("Street Address"), text2);
					} else if(!strcmp(child2->name, "LOCALITY")) {
						purple_notify_user_info_add_pair_plaintext(user_info, _("Locality"), text2);
					} else if(!strcmp(child2->name, "REGION")) {
						purple_notify_user_info_add_pair_plaintext(user_info, _("Region"), text2);
					} else if(!strcmp(child2->name, "PCODE")) {
						purple_notify_user_info_add_pair_plaintext(user_info, _("Postal Code"), text2);
					} else if(!strcmp(child2->name, "CTRY")
								|| !strcmp(child2->name, "COUNTRY")) {
						purple_notify_user_info_add_pair_plaintext(user_info, _("Country"), text2);
					}
					g_free(text2);
				}

				if (address_line_added)
					purple_notify_user_info_add_section_break(user_info);

			} else if(!strcmp(child->name, "TEL")) {
				char *number;
				if((child2 = xmlnode_get_child(child, "NUMBER"))) {
					/* show what kind of number it is */
					number = xmlnode_get_data(child2);
					if(number) {
						purple_notify_user_info_add_pair_plaintext(user_info, _("Telephone"), number);
						g_free(number);
					}
				} else if((number = xmlnode_get_data(child))) {
					/* lots of clients (including purple) do this, but it's
					 * out of spec */
					purple_notify_user_info_add_pair_plaintext(user_info, _("Telephone"), number);
					g_free(number);
				}
			} else if(!strcmp(child->name, "EMAIL")) {
				char *userid, *escaped;
				if((child2 = xmlnode_get_child(child, "USERID"))) {
					/* show what kind of email it is */
					userid = xmlnode_get_data(child2);
					if(userid) {
						char *mailto;
						escaped = g_markup_escape_text(userid, -1);
						mailto = g_strdup_printf("<a href=\"mailto:%s\">%s</a>", escaped, escaped);
						purple_notify_user_info_add_pair(user_info, _("Email"), mailto);

						g_free(mailto);
						g_free(escaped);
						g_free(userid);
					}
				} else if((userid = xmlnode_get_data(child))) {
					/* lots of clients (including purple) do this, but it's
					 * out of spec */
					char *mailto;

					escaped = g_markup_escape_text(userid, -1);
					mailto = g_strdup_printf("<a href=\"mailto:%s\">%s</a>", escaped, escaped);
					purple_notify_user_info_add_pair(user_info, _("Email"), mailto);

					g_free(mailto);
					g_free(escaped);
					g_free(userid);
				}
			} else if(!strcmp(child->name, "ORG")) {
				for(child2 = child->child; child2; child2 = child2->next)
				{
					char *text2;

					if(child2->type != XMLNODE_TYPE_TAG)
						continue;

					text2 = xmlnode_get_data(child2);
					if(text2 && !strcmp(child2->name, "ORGNAME")) {
						purple_notify_user_info_add_pair_plaintext(user_info, _("Organization Name"), text2);
					} else if(text2 && !strcmp(child2->name, "ORGUNIT")) {
						purple_notify_user_info_add_pair_plaintext(user_info, _("Organization Unit"), text2);
					}
					g_free(text2);
				}
			} else if(text && !strcmp(child->name, "TITLE")) {
				purple_notify_user_info_add_pair_plaintext(user_info, _("Job Title"), text);
			} else if(text && !strcmp(child->name, "ROLE")) {
				purple_notify_user_info_add_pair_plaintext(user_info, _("Role"), text);
			} else if(text && !strcmp(child->name, "DESC")) {
				purple_notify_user_info_add_pair_plaintext(user_info, _("Description"), text);
			} else if(!strcmp(child->name, "PHOTO") ||
					!strcmp(child->name, "LOGO")) {
				char *bintext = NULL;
				xmlnode *binval;

				if ((binval = xmlnode_get_child(child, "BINVAL")) &&
						(bintext = xmlnode_get_data(binval))) {
					gsize size;
					guchar *data;
					gboolean photo = (strcmp(child->name, "PHOTO") == 0);

					data = purple_base64_decode(bintext, &size);
					if (data) {
						char *img_text;
						char *hash;

						jbi->vcard_imgids = g_slist_prepend(jbi->vcard_imgids, GINT_TO_POINTER(purple_imgstore_add_with_id(g_memdup(data, size), size, "logo.png")));
						img_text = g_strdup_printf("<img id='%d'>", GPOINTER_TO_INT(jbi->vcard_imgids->data));

						purple_notify_user_info_add_pair(user_info, (photo ? _("Photo") : _("Logo")), img_text);

						hash = jabber_calculate_data_hash(data, size, "sha1");
						purple_buddy_icons_set_for_user(account, bare_jid, data, size, hash);
						g_free(hash);
						g_free(img_text);
					}
					g_free(bintext);
				}
			}
			g_free(text);
		}
	}

	if (serverside_alias) {
		PurpleBuddy *b;
		/* If we found a serverside alias, set it and tell the core */
		serv_got_alias(js->gc, bare_jid, serverside_alias);
		b = purple_find_buddy(account, bare_jid);
		if (b) {
			purple_blist_node_set_string((PurpleBlistNode*)b, "servernick", serverside_alias);
		}

		g_free(serverside_alias);
	}

	g_free(bare_jid);

	jabber_buddy_info_show_if_ready(jbi);
}

static void jabber_buddy_info_resource_free(gpointer data)
{
	JabberBuddyInfoResource *jbri = data;
	g_free(jbri);
}

static guint jbir_hash(gconstpointer v)
{
	if (v)
		return g_str_hash(v);
	else
		return 0;
}

static gboolean jbir_equal(gconstpointer v1, gconstpointer v2)
{
	const gchar *resource_1 = v1;
	const gchar *resource_2 = v2;

	return purple_strequal(resource_1, resource_2);
}

static void jabber_version_parse(JabberStream *js, const char *from,
                                 JabberIqType type, const char *id,
                                 xmlnode *packet, gpointer data)
{
	JabberBuddyInfo *jbi = data;
	xmlnode *query;
	char *resource_name;

	g_return_if_fail(jbi != NULL);

	jabber_buddy_info_remove_id(jbi, id);

	if(!from)
		return;

	resource_name = jabber_get_resource(from);

	if(resource_name) {
		if (type == JABBER_IQ_RESULT) {
			if((query = xmlnode_get_child(packet, "query"))) {
				JabberBuddyResource *jbr = jabber_buddy_find_resource(jbi->jb, resource_name);
				if(jbr) {
					xmlnode *node;
					if((node = xmlnode_get_child(query, "name"))) {
						jbr->client.name = xmlnode_get_data(node);
					}
					if((node = xmlnode_get_child(query, "version"))) {
						jbr->client.version = xmlnode_get_data(node);
					}
					if((node = xmlnode_get_child(query, "os"))) {
						jbr->client.os = xmlnode_get_data(node);
					}
				}
			}
		}
		g_free(resource_name);
	}

	jabber_buddy_info_show_if_ready(jbi);
}

static void jabber_last_parse(JabberStream *js, const char *from,
                              JabberIqType type, const char *id,
                              xmlnode *packet, gpointer data)
{
	JabberBuddyInfo *jbi = data;
	xmlnode *query;
	char *resource_name;
	const char *seconds;

	g_return_if_fail(jbi != NULL);

	jabber_buddy_info_remove_id(jbi, id);

	if(!from)
		return;

	resource_name = jabber_get_resource(from);

	if(resource_name) {
		if (type == JABBER_IQ_RESULT) {
			if((query = xmlnode_get_child(packet, "query"))) {
				seconds = xmlnode_get_attrib(query, "seconds");
				if(seconds) {
					char *end = NULL;
					long sec = strtol(seconds, &end, 10);
					JabberBuddy *jb = NULL;
					char *resource = NULL;
					char *buddy_name = NULL;
					JabberBuddyResource *jbr = NULL;

					if(end != seconds) {
						JabberBuddyInfoResource *jbir = g_hash_table_lookup(jbi->resources, resource_name);
						if(jbir) {
							jbir->idle_seconds = sec;
						}
					}
					/* Update the idle time of the buddy resource, if we got it.
					 This will correct the value when a server doesn't mark
					 delayed presence and we got the presence when signing on */
					jb = jabber_buddy_find(js, from, FALSE);
					if (jb) {
						resource = jabber_get_resource(from);
						buddy_name = jabber_get_bare_jid(from);
						/* if the resource already has an idle time set, we
						 must have gotten it originally from a presence. In
						 this case we update it. Otherwise don't update it, to
						 avoid setting an idle and not getting informed about
						 the resource getting unidle */
						if (resource && buddy_name) {
							jbr = jabber_buddy_find_resource(jb, resource);
							if (jbr) {
								if (jbr->idle) {
									if (sec) {
										jbr->idle = time(NULL) - sec;
									} else {
										jbr->idle = 0;
									}

									if (jbr ==
										jabber_buddy_find_resource(jb, NULL)) {
										purple_prpl_got_user_idle(js->gc->account,
											buddy_name, jbr->idle, jbr->idle);
									}
								}
							}
						}
						g_free(resource);
						g_free(buddy_name);
					}
				}
			}
		}
		g_free(resource_name);
	}

	jabber_buddy_info_show_if_ready(jbi);
}

static void jabber_last_offline_parse(JabberStream *js, const char *from,
									  JabberIqType type, const char *id,
									  xmlnode *packet, gpointer data)
{
	JabberBuddyInfo *jbi = data;
	xmlnode *query;
	const char *seconds;

	g_return_if_fail(jbi != NULL);

	jabber_buddy_info_remove_id(jbi, id);

	if (type == JABBER_IQ_RESULT) {
		if((query = xmlnode_get_child(packet, "query"))) {
			seconds = xmlnode_get_attrib(query, "seconds");
			if(seconds) {
				char *end = NULL;
				long sec = strtol(seconds, &end, 10);
				if(end != seconds) {
					jbi->last_seconds = sec;
				}
			}
			jbi->last_message = xmlnode_get_data(query);
		}
	}

	jabber_buddy_info_show_if_ready(jbi);
}

static void jabber_time_parse(JabberStream *js, const char *from,
                              JabberIqType type, const char *id,
                              xmlnode *packet, gpointer data)
{
	JabberBuddyInfo *jbi = data;
	JabberBuddyResource *jbr;
	char *resource_name;

	g_return_if_fail(jbi != NULL);

	jabber_buddy_info_remove_id(jbi, id);

	if (!from)
		return;

	resource_name = jabber_get_resource(from);
	jbr = resource_name ? jabber_buddy_find_resource(jbi->jb, resource_name) : NULL;
	g_free(resource_name);
	if (jbr) {
		if (type == JABBER_IQ_RESULT) {
			xmlnode *time = xmlnode_get_child(packet, "time");
			xmlnode *tzo = time ? xmlnode_get_child(time, "tzo") : NULL;
			char *tzo_data = tzo ? xmlnode_get_data(tzo) : NULL;
			if (tzo_data) {
				char *c = tzo_data;
				int hours, minutes;
				if (tzo_data[0] == 'Z' && tzo_data[1] == '\0') {
					jbr->tz_off = 0;
				} else {
					gboolean offset_positive = (tzo_data[0] == '+');
					/* [+-]HH:MM */
					if (((*c == '+' || *c == '-') && (c = c + 1)) &&
							sscanf(c, "%02d:%02d", &hours, &minutes) == 2) {
						jbr->tz_off = 60*60*hours + 60*minutes;
						if (!offset_positive)
							jbr->tz_off *= -1;
					} else {
						purple_debug_info("jabber", "Ignoring malformed timezone %s",
						                  tzo_data);
					}
				}

				g_free(tzo_data);
			}
		}
	}

	jabber_buddy_info_show_if_ready(jbi);
}

void jabber_buddy_remove_all_pending_buddy_info_requests(JabberStream *js)
{
	if (js->pending_buddy_info_requests)
	{
		JabberBuddyInfo *jbi;
		GSList *l = js->pending_buddy_info_requests;
		while (l) {
			jbi = l->data;

			g_slist_free(jbi->ids);
			jabber_buddy_info_destroy(jbi);

			l = l->next;
		}

		g_slist_free(js->pending_buddy_info_requests);
		js->pending_buddy_info_requests = NULL;
	}
}

static gboolean jabber_buddy_get_info_timeout(gpointer data)
{
	JabberBuddyInfo *jbi = data;

	/* remove the pending callbacks */
	while(jbi->ids) {
		char *id = jbi->ids->data;
		jabber_iq_remove_callback_by_id(jbi->js, id);
		jbi->ids = g_slist_remove(jbi->ids, id);
		g_free(id);
	}

	jbi->js->pending_buddy_info_requests = g_slist_remove(jbi->js->pending_buddy_info_requests, jbi);
	jbi->timeout_handle = 0;

	jabber_buddy_info_show_if_ready(jbi);

	return FALSE;
}

static gboolean _client_is_blacklisted(JabberBuddyResource *jbr, const char *ns)
{
	/* can't be blacklisted if we don't know what you're running yet */
	if(!jbr->client.name)
		return FALSE;

	if(!strcmp(ns, NS_LAST_ACTIVITY)) {
		if(!strcmp(jbr->client.name, "Trillian")) {
			/* verified by nwalp 2007/05/09 */
			if(!strcmp(jbr->client.version, "3.1.0.121") ||
					/* verified by nwalp 2007/09/19 */
					!strcmp(jbr->client.version, "3.1.7.0")) {
				return TRUE;
			}
		}
	}

	return FALSE;
}

static void
dispatch_queries_for_resource(JabberStream *js, JabberBuddyInfo *jbi,
                              gboolean is_bare_jid, const char *jid,
                              JabberBuddyResource *jbr)
{
	JabberIq *iq;
	JabberBuddyInfoResource *jbir;
	char *full_jid = NULL;
	const char *to;

	if (is_bare_jid && jbr->name) {
		full_jid = g_strdup_printf("%s/%s", jid, jbr->name);
		to = full_jid;
	} else
		to = jid;

	jbir = g_new0(JabberBuddyInfoResource, 1);
	g_hash_table_insert(jbi->resources, g_strdup(jbr->name), jbir);

	if(!jbr->client.name) {
		iq = jabber_iq_new_query(js, JABBER_IQ_GET, "jabber:iq:version");
		xmlnode_set_attrib(iq->node, "to", to);
		jabber_iq_set_callback(iq, jabber_version_parse, jbi);
		jbi->ids = g_slist_prepend(jbi->ids, g_strdup(iq->id));
		jabber_iq_send(iq);
	}

	/* this is to fix the feeling of irritation I get when trying
	 * to get info on a friend running Trillian, which doesn't
	 * respond (with an error or otherwise) to jabber:iq:last
	 * requests.  There are a number of Trillian users in my
	 * office. */
	if(!_client_is_blacklisted(jbr, NS_LAST_ACTIVITY)) {
		iq = jabber_iq_new_query(js, JABBER_IQ_GET, NS_LAST_ACTIVITY);
		xmlnode_set_attrib(iq->node, "to", to);
		jabber_iq_set_callback(iq, jabber_last_parse, jbi);
		jbi->ids = g_slist_prepend(jbi->ids, g_strdup(iq->id));
		jabber_iq_send(iq);
	}

	if (jbr->tz_off == PURPLE_NO_TZ_OFF &&
			(!jbr->caps.info ||
			 	jabber_resource_has_capability(jbr, NS_ENTITY_TIME))) {
		xmlnode *child;
		iq = jabber_iq_new(js, JABBER_IQ_GET);
		xmlnode_set_attrib(iq->node, "to", to);
		child = xmlnode_new_child(iq->node, "time");
		xmlnode_set_namespace(child, NS_ENTITY_TIME);
		jabber_iq_set_callback(iq, jabber_time_parse, jbi);
		jbi->ids = g_slist_prepend(jbi->ids, g_strdup(iq->id));
		jabber_iq_send(iq);
	}

	g_free(full_jid);
}

static void jabber_buddy_get_info_for_jid(JabberStream *js, const char *jid)
{
	JabberIq *iq;
	xmlnode *vcard;
	GList *resources;
	JabberBuddy *jb;
	JabberBuddyInfo *jbi;
	const char *slash;
	gboolean is_bare_jid;

	jb = jabber_buddy_find(js, jid, TRUE);

	/* invalid JID */
	if(!jb)
		return;

	slash = strchr(jid, '/');
	is_bare_jid = (slash == NULL);

	jbi = g_new0(JabberBuddyInfo, 1);
	jbi->jid = g_strdup(jid);
	jbi->js = js;
	jbi->jb = jb;
	jbi->resources = g_hash_table_new_full(jbir_hash, jbir_equal, g_free, jabber_buddy_info_resource_free);
	jbi->user_info = purple_notify_user_info_new();

	iq = jabber_iq_new(js, JABBER_IQ_GET);

	xmlnode_set_attrib(iq->node, "to", jid);
	vcard = xmlnode_new_child(iq->node, "vCard");
	xmlnode_set_namespace(vcard, "vcard-temp");

	jabber_iq_set_callback(iq, jabber_vcard_parse, jbi);
	jbi->ids = g_slist_prepend(jbi->ids, g_strdup(iq->id));

	jabber_iq_send(iq);

	if (is_bare_jid) {
		if (jb->resources) {
			for(resources = jb->resources; resources; resources = resources->next) {
				JabberBuddyResource *jbr = resources->data;
				dispatch_queries_for_resource(js, jbi, is_bare_jid, jid, jbr);
			}
		} else {
			/* user is offline, send a jabber:iq:last to find out last time online */
			iq = jabber_iq_new_query(js, JABBER_IQ_GET, NS_LAST_ACTIVITY);
			xmlnode_set_attrib(iq->node, "to", jid);
			jabber_iq_set_callback(iq, jabber_last_offline_parse, jbi);
			jbi->ids = g_slist_prepend(jbi->ids, g_strdup(iq->id));
			jabber_iq_send(iq);
		}
	} else {
		JabberBuddyResource *jbr = jabber_buddy_find_resource(jb, slash + 1);
		if (jbr)
			dispatch_queries_for_resource(js, jbi, is_bare_jid, jid, jbr);
		else
			purple_debug_warning("jabber", "jabber_buddy_get_info_for_jid() "
					"was passed JID %s, but there is no corresponding "
					"JabberBuddyResource!\n", jid);
	}

	js->pending_buddy_info_requests = g_slist_prepend(js->pending_buddy_info_requests, jbi);
	jbi->timeout_handle = purple_timeout_add_seconds(30, jabber_buddy_get_info_timeout, jbi);
}

void jabber_buddy_get_info(PurpleConnection *gc, const char *who)
{
	JabberStream *js = purple_connection_get_protocol_data(gc);
	JabberID *jid = jabber_id_new(who);

	if (!jid)
		return;

	if (jid->node && jabber_chat_find(js, jid->node, jid->domain)) {
		/* For a conversation, include the resource (indicates the user). */
		jabber_buddy_get_info_for_jid(js, who);
	} else {
		char *bare_jid = jabber_get_bare_jid(who);
		jabber_buddy_get_info_for_jid(js, bare_jid);
		g_free(bare_jid);
	}

	jabber_id_free(jid);
}

static void jabber_buddy_set_invisibility(JabberStream *js, const char *who,
		gboolean invisible)
{
	PurplePresence *gpresence;
	PurpleAccount *account;
	PurpleStatus *status;
	JabberBuddy *jb = jabber_buddy_find(js, who, TRUE);
	xmlnode *presence;
	JabberBuddyState state;
	char *msg;
	int priority;

	account   = purple_connection_get_account(js->gc);
	gpresence = purple_account_get_presence(account);
	status    = purple_presence_get_active_status(gpresence);

	purple_status_to_jabber(status, &state, &msg, &priority);
	presence = jabber_presence_create_js(js, state, msg, priority);

	g_free(msg);

	xmlnode_set_attrib(presence, "to", who);
	if(invisible) {
		xmlnode_set_attrib(presence, "type", "invisible");
		jb->invisible |= JABBER_INVIS_BUDDY;
	} else {
		jb->invisible &= ~JABBER_INVIS_BUDDY;
	}

	jabber_send(js, presence);
	xmlnode_free(presence);
}

static void jabber_buddy_make_invisible(PurpleBlistNode *node, gpointer data)
{
	PurpleBuddy *buddy;
	PurpleConnection *gc;
	JabberStream *js;

	g_return_if_fail(PURPLE_BLIST_NODE_IS_BUDDY(node));

	buddy = (PurpleBuddy *) node;
	gc = purple_account_get_connection(purple_buddy_get_account(buddy));
	js = purple_connection_get_protocol_data(gc);

	jabber_buddy_set_invisibility(js, purple_buddy_get_name(buddy), TRUE);
}

static void jabber_buddy_make_visible(PurpleBlistNode *node, gpointer data)
{
	PurpleBuddy *buddy;
	PurpleConnection *gc;
	JabberStream *js;

	g_return_if_fail(PURPLE_BLIST_NODE_IS_BUDDY(node));

	buddy = (PurpleBuddy *) node;
	gc = purple_account_get_connection(purple_buddy_get_account(buddy));
	js = purple_connection_get_protocol_data(gc);

	jabber_buddy_set_invisibility(js, purple_buddy_get_name(buddy), FALSE);
}

static void cancel_presence_notification(gpointer data)
{
	PurpleBuddy *buddy;
	PurpleConnection *gc;
	JabberStream *js;

	buddy = data;
	gc = purple_account_get_connection(purple_buddy_get_account(buddy));
	js = purple_connection_get_protocol_data(gc);

	jabber_presence_subscription_set(js, purple_buddy_get_name(buddy), "unsubscribed");
}

static void
jabber_buddy_cancel_presence_notification(PurpleBlistNode *node,
                                          gpointer data)
{
	PurpleBuddy *buddy;
	PurpleAccount *account;
	PurpleConnection *gc;
	const gchar *name;
	char *msg;

	g_return_if_fail(PURPLE_BLIST_NODE_IS_BUDDY(node));

	buddy = (PurpleBuddy *) node;
	name = purple_buddy_get_name(buddy);
	account = purple_buddy_get_account(buddy);
	gc = purple_account_get_connection(account);

	msg = g_strdup_printf(_("%s will no longer be able to see your status "
	                        "updates.  Do you want to continue?"), name);
	purple_request_yes_no(gc, NULL, _("Cancel Presence Notification"),
	                      msg, 0 /* Yes */, account, name, NULL, buddy,
	                      cancel_presence_notification, NULL /* Do nothing */);
	g_free(msg);
}

static void jabber_buddy_rerequest_auth(PurpleBlistNode *node, gpointer data)
{
	PurpleBuddy *buddy;
	PurpleConnection *gc;
	JabberStream *js;

	g_return_if_fail(PURPLE_BLIST_NODE_IS_BUDDY(node));

	buddy = (PurpleBuddy *) node;
	gc = purple_account_get_connection(purple_buddy_get_account(buddy));
	js = purple_connection_get_protocol_data(gc);

	jabber_presence_subscription_set(js, purple_buddy_get_name(buddy), "subscribe");
}


static void jabber_buddy_unsubscribe(PurpleBlistNode *node, gpointer data)
{
	PurpleBuddy *buddy;
	PurpleConnection *gc;
	JabberStream *js;

	g_return_if_fail(PURPLE_BLIST_NODE_IS_BUDDY(node));

	buddy = (PurpleBuddy *) node;
	gc = purple_account_get_connection(purple_buddy_get_account(buddy));
	js = purple_connection_get_protocol_data(gc);

	jabber_presence_subscription_set(js, purple_buddy_get_name(buddy), "unsubscribe");
}

static void jabber_buddy_login(PurpleBlistNode *node, gpointer data) {
	if(PURPLE_BLIST_NODE_IS_BUDDY(node)) {
		/* simply create a directed presence of the current status */
		PurpleBuddy *buddy = (PurpleBuddy *) node;
		PurpleConnection *gc = purple_account_get_connection(purple_buddy_get_account(buddy));
		JabberStream *js = purple_connection_get_protocol_data(gc);
		PurpleAccount *account = purple_connection_get_account(gc);
		PurplePresence *gpresence = purple_account_get_presence(account);
		PurpleStatus *status = purple_presence_get_active_status(gpresence);
		xmlnode *presence;
		JabberBuddyState state;
		char *msg;
		int priority;

		purple_status_to_jabber(status, &state, &msg, &priority);
		presence = jabber_presence_create_js(js, state, msg, priority);

		g_free(msg);

		xmlnode_set_attrib(presence, "to", purple_buddy_get_name(buddy));

		jabber_send(js, presence);
		xmlnode_free(presence);
	}
}

static void jabber_buddy_logout(PurpleBlistNode *node, gpointer data) {
	if(PURPLE_BLIST_NODE_IS_BUDDY(node)) {
		/* simply create a directed unavailable presence */
		PurpleBuddy *buddy = (PurpleBuddy *) node;
		PurpleConnection *gc = purple_account_get_connection(purple_buddy_get_account(buddy));
		JabberStream *js = purple_connection_get_protocol_data(gc);
		xmlnode *presence;

		presence = jabber_presence_create_js(js, JABBER_BUDDY_STATE_UNAVAILABLE, NULL, 0);

		xmlnode_set_attrib(presence, "to", purple_buddy_get_name(buddy));

		jabber_send(js, presence);
		xmlnode_free(presence);
	}
}

static GList *jabber_buddy_menu(PurpleBuddy *buddy)
{
	PurpleConnection *gc = purple_account_get_connection(purple_buddy_get_account(buddy));
	JabberStream *js = purple_connection_get_protocol_data(gc);
	const char *name = purple_buddy_get_name(buddy);
	JabberBuddy *jb = jabber_buddy_find(js, name, TRUE);
	GList *jbrs;

	GList *m = NULL;
	PurpleMenuAction *act;

	if(!jb)
		return m;

	if (js->protocol_version.major == 0 && js->protocol_version.minor == 9 &&
			jb != js->user_jb) {
		if(jb->invisible & JABBER_INVIS_BUDDY) {
			act = purple_menu_action_new(_("Un-hide From"),
			                           PURPLE_CALLBACK(jabber_buddy_make_visible),
			                           NULL, NULL);
		} else {
			act = purple_menu_action_new(_("Temporarily Hide From"),
			                           PURPLE_CALLBACK(jabber_buddy_make_invisible),
			                           NULL, NULL);
		}
		m = g_list_append(m, act);
	}

	if(jb->subscription & JABBER_SUB_FROM && jb != js->user_jb) {
		act = purple_menu_action_new(_("Cancel Presence Notification"),
		                           PURPLE_CALLBACK(jabber_buddy_cancel_presence_notification),
		                           NULL, NULL);
		m = g_list_append(m, act);
	}

	if(!(jb->subscription & JABBER_SUB_TO)) {
		act = purple_menu_action_new(_("(Re-)Request authorization"),
		                           PURPLE_CALLBACK(jabber_buddy_rerequest_auth),
		                           NULL, NULL);
		m = g_list_append(m, act);

	} else if (jb != js->user_jb) {

		/* shouldn't this just happen automatically when the buddy is
		   removed? */
		act = purple_menu_action_new(_("Unsubscribe"),
		                           PURPLE_CALLBACK(jabber_buddy_unsubscribe),
		                           NULL, NULL);
		m = g_list_append(m, act);
	}

	if (js->googletalk) {
		act = purple_menu_action_new(_("Initiate _Chat"),
		                           PURPLE_CALLBACK(google_buddy_node_chat),
		                           NULL, NULL);
		m = g_list_append(m, act);
	}

	/*
	 * This if-condition implements parts of XEP-0100: Gateway Interaction
	 *
	 * According to stpeter, there is no way to know if a jid on the roster is a gateway without sending a disco#info.
	 * However, since the gateway might appear offline to us, we cannot get that information. Therefore, I just assume
	 * that gateways on the roster can be identified by having no '@' in their jid. This is a faily safe assumption, since
	 * people don't tend to have a server or other service there.
	 *
	 * TODO: Use disco#info...
	 */
	if (strchr(name, '@') == NULL) {
		act = purple_menu_action_new(_("Log In"),
									 PURPLE_CALLBACK(jabber_buddy_login),
									 NULL, NULL);
		m = g_list_append(m, act);
		act = purple_menu_action_new(_("Log Out"),
									 PURPLE_CALLBACK(jabber_buddy_logout),
									 NULL, NULL);
		m = g_list_append(m, act);
	}

	/* add all ad hoc commands to the action menu */
	for(jbrs = jb->resources; jbrs; jbrs = g_list_next(jbrs)) {
		JabberBuddyResource *jbr = jbrs->data;
		GList *commands;
		if (!jbr->commands)
			continue;
		for(commands = jbr->commands; commands; commands = g_list_next(commands)) {
			JabberAdHocCommands *cmd = commands->data;
			act = purple_menu_action_new(cmd->name, PURPLE_CALLBACK(jabber_adhoc_execute_action), cmd, NULL);
			m = g_list_append(m, act);
		}
	}

	return m;
}

GList *
jabber_blist_node_menu(PurpleBlistNode *node)
{
	if(PURPLE_BLIST_NODE_IS_BUDDY(node)) {
		return jabber_buddy_menu((PurpleBuddy *) node);
	} else {
		return NULL;
	}
}


static void user_search_result_add_buddy_cb(PurpleConnection *gc, GList *row, void *user_data)
{
	/* XXX find out the jid */
	purple_blist_request_add_buddy(purple_connection_get_account(gc),
			g_list_nth_data(row, 0), NULL, NULL);
}

static void user_search_result_cb(JabberStream *js, const char *from,
                                  JabberIqType type, const char *id,
                                  xmlnode *packet, gpointer data)
{
	PurpleNotifySearchResults *results;
	PurpleNotifySearchColumn *column;
	xmlnode *x, *query, *item, *field;

	/* XXX error checking? */
	if(!(query = xmlnode_get_child(packet, "query")))
		return;

	results = purple_notify_searchresults_new();
	if((x = xmlnode_get_child_with_namespace(query, "x", "jabber:x:data"))) {
		xmlnode *reported;
		GSList *column_vars = NULL;

		purple_debug_info("jabber", "new-skool\n");

		if((reported = xmlnode_get_child(x, "reported"))) {
			xmlnode *field = xmlnode_get_child(reported, "field");
			while(field) {
				const char *var = xmlnode_get_attrib(field, "var");
				const char *label = xmlnode_get_attrib(field, "label");
				if(var) {
					column = purple_notify_searchresults_column_new(label ? label : var);
					purple_notify_searchresults_column_add(results, column);
					column_vars = g_slist_append(column_vars, (char *)var);
				}
				field = xmlnode_get_next_twin(field);
			}
		}

		item = xmlnode_get_child(x, "item");
		while(item) {
			GList *row = NULL;
			GSList *l;
			xmlnode *valuenode;
			const char *var;

			for (l = column_vars; l != NULL; l = l->next) {
				/*
				 * Build a row containing the strings that correspond
				 * to each column of the search results.
				 */
				for (field = xmlnode_get_child(item, "field");
						field != NULL;
						field = xmlnode_get_next_twin(field))
				{
					if ((var = xmlnode_get_attrib(field, "var")) &&
							!strcmp(var, l->data) &&
							(valuenode = xmlnode_get_child(field, "value")))
					{
						char *value = xmlnode_get_data(valuenode);
						row = g_list_append(row, value);
						break;
					}
				}
				if (field == NULL)
					/* No data for this column */
					row = g_list_append(row, NULL);
			}
			purple_notify_searchresults_row_add(results, row);
			item = xmlnode_get_next_twin(item);
		}

		g_slist_free(column_vars);
	} else {
		/* old skool */
		purple_debug_info("jabber", "old-skool\n");

		column = purple_notify_searchresults_column_new(_("JID"));
		purple_notify_searchresults_column_add(results, column);
		column = purple_notify_searchresults_column_new(_("First Name"));
		purple_notify_searchresults_column_add(results, column);
		column = purple_notify_searchresults_column_new(_("Last Name"));
		purple_notify_searchresults_column_add(results, column);
		column = purple_notify_searchresults_column_new(_("Nickname"));
		purple_notify_searchresults_column_add(results, column);
		column = purple_notify_searchresults_column_new(_("Email"));
		purple_notify_searchresults_column_add(results, column);

		for(item = xmlnode_get_child(query, "item"); item; item = xmlnode_get_next_twin(item)) {
			const char *jid;
			xmlnode *node;
			GList *row = NULL;

			if(!(jid = xmlnode_get_attrib(item, "jid")))
				continue;

			row = g_list_append(row, g_strdup(jid));
			node = xmlnode_get_child(item, "first");
			row = g_list_append(row, node ? xmlnode_get_data(node) : NULL);
			node = xmlnode_get_child(item, "last");
			row = g_list_append(row, node ? xmlnode_get_data(node) : NULL);
			node = xmlnode_get_child(item, "nick");
			row = g_list_append(row, node ? xmlnode_get_data(node) : NULL);
			node = xmlnode_get_child(item, "email");
			row = g_list_append(row, node ? xmlnode_get_data(node) : NULL);
			purple_debug_info("jabber", "row=%p\n", row);
			purple_notify_searchresults_row_add(results, row);
		}
	}

	purple_notify_searchresults_button_add(results, PURPLE_NOTIFY_BUTTON_ADD,
			user_search_result_add_buddy_cb);

	purple_notify_searchresults(js->gc, NULL, NULL, _("The following are the results of your search"), results, NULL, NULL);
}

static void user_search_x_data_cb(JabberStream *js, xmlnode *result, gpointer data)
{
	xmlnode *query;
	JabberIq *iq;
	char *dir_server = data;
	const char *type;

	/* if they've cancelled the search, we're
	 * just going to get an error if we send
	 * a cancel, so skip it */
	type = xmlnode_get_attrib(result, "type");
	if(type && !strcmp(type, "cancel")) {
		g_free(dir_server);
		return;
	}

	iq = jabber_iq_new_query(js, JABBER_IQ_SET, "jabber:iq:search");
	query = xmlnode_get_child(iq->node, "query");

	xmlnode_insert_child(query, result);

	jabber_iq_set_callback(iq, user_search_result_cb, NULL);
	xmlnode_set_attrib(iq->node, "to", dir_server);
	jabber_iq_send(iq);
	g_free(dir_server);
}

struct user_search_info {
	JabberStream *js;
	char *directory_server;
};

static void user_search_cancel_cb(struct user_search_info *usi, PurpleRequestFields *fields)
{
	g_free(usi->directory_server);
	g_free(usi);
}

static void user_search_cb(struct user_search_info *usi, PurpleRequestFields *fields)
{
	JabberStream *js = usi->js;
	JabberIq *iq;
	xmlnode *query;
	GList *groups, *flds;

	iq = jabber_iq_new_query(js, JABBER_IQ_SET, "jabber:iq:search");
	query = xmlnode_get_child(iq->node, "query");

	for(groups = purple_request_fields_get_groups(fields); groups; groups = groups->next) {
		for(flds = purple_request_field_group_get_fields(groups->data);
				flds; flds = flds->next) {
			PurpleRequestField *field = flds->data;
			const char *id = purple_request_field_get_id(field);
			const char *value = purple_request_field_string_get_value(field);

			if(value && (!strcmp(id, "first") || !strcmp(id, "last") || !strcmp(id, "nick") || !strcmp(id, "email"))) {
				xmlnode *y = xmlnode_new_child(query, id);
				xmlnode_insert_data(y, value, -1);
			}
		}
	}

	jabber_iq_set_callback(iq, user_search_result_cb, NULL);
	xmlnode_set_attrib(iq->node, "to", usi->directory_server);
	jabber_iq_send(iq);

	g_free(usi->directory_server);
	g_free(usi);
}

#if 0
/* This is for gettext only -- it will see this even though there's an #if 0. */

/*
 * An incomplete list of server generated original language search
 * comments for Jabber User Directories
 *
 * See discussion thread "Search comment for Jabber is not translatable"
 * in purple-i18n@lists.sourceforge.net (March 2006)
 */
static const char * jabber_user_dir_comments [] = {
	/* current comment from Jabber User Directory users.jabber.org */
	N_("Find a contact by entering the search criteria in the given fields. "
	   "Note: Each field supports wild card searches (%)"),
	NULL
};
#endif

static void user_search_fields_result_cb(JabberStream *js, const char *from,
                                         JabberIqType type, const char *id,
                                         xmlnode *packet, gpointer data)
{
	xmlnode *query, *x;

	if (!from)
		return;

	if (type == JABBER_IQ_ERROR) {
		char *msg = jabber_parse_error(js, packet, NULL);

		if(!msg)
			msg = g_strdup(_("Unknown error"));

		purple_notify_error(js->gc, _("Directory Query Failed"),
				  _("Could not query the directory server."), msg);
		g_free(msg);

		return;
	}


	if(!(query = xmlnode_get_child(packet, "query")))
		return;

	if((x = xmlnode_get_child_with_namespace(query, "x", "jabber:x:data"))) {
		jabber_x_data_request(js, x, user_search_x_data_cb, g_strdup(from));
		return;
	} else {
		struct user_search_info *usi;
		xmlnode *instnode;
		char *instructions = NULL;
		PurpleRequestFields *fields;
		PurpleRequestFieldGroup *group;
		PurpleRequestField *field;

		/* old skool */
		fields = purple_request_fields_new();
		group = purple_request_field_group_new(NULL);
		purple_request_fields_add_group(fields, group);

		if((instnode = xmlnode_get_child(query, "instructions")))
		{
			char *tmp = xmlnode_get_data(instnode);

			if(tmp)
			{
				/* Try to translate the message (see static message
				   list in jabber_user_dir_comments[]) */
				instructions = g_strdup_printf(_("Server Instructions: %s"), _(tmp));
				g_free(tmp);
			}
		}

		if(!instructions)
		{
			instructions = g_strdup(_("Fill in one or more fields to search "
						  "for any matching XMPP users."));
		}

		if(xmlnode_get_child(query, "first")) {
			field = purple_request_field_string_new("first", _("First Name"),
					NULL, FALSE);
			purple_request_field_group_add_field(group, field);
		}
		if(xmlnode_get_child(query, "last")) {
			field = purple_request_field_string_new("last", _("Last Name"),
					NULL, FALSE);
			purple_request_field_group_add_field(group, field);
		}
		if(xmlnode_get_child(query, "nick")) {
			field = purple_request_field_string_new("nick", _("Nickname"),
					NULL, FALSE);
			purple_request_field_group_add_field(group, field);
		}
		if(xmlnode_get_child(query, "email")) {
			field = purple_request_field_string_new("email", _("Email Address"),
					NULL, FALSE);
			purple_request_field_group_add_field(group, field);
		}

		usi = g_new0(struct user_search_info, 1);
		usi->js = js;
		usi->directory_server = g_strdup(from);

		purple_request_fields(js->gc, _("Search for XMPP users"),
				_("Search for XMPP users"), instructions, fields,
				_("Search"), G_CALLBACK(user_search_cb),
				_("Cancel"), G_CALLBACK(user_search_cancel_cb),
				purple_connection_get_account(js->gc), NULL, NULL,
				usi);

		g_free(instructions);
	}
}

void jabber_user_search(JabberStream *js, const char *directory)
{
	JabberIq *iq;

	/* XXX: should probably better validate the directory we're given */
	if(!directory || !*directory) {
		purple_notify_error(js->gc, _("Invalid Directory"), _("Invalid Directory"), NULL);
		return;
	}

	/* If the value provided isn't the disco#info default, persist it.  Otherwise,
	   make sure we aren't persisting an old value */
	if(js->user_directories && js->user_directories->data &&
	   !strcmp(directory, js->user_directories->data)) {
		purple_account_set_string(js->gc->account, "user_directory", "");
	}
	else {
		purple_account_set_string(js->gc->account, "user_directory", directory);
	}

	iq = jabber_iq_new_query(js, JABBER_IQ_GET, "jabber:iq:search");
	xmlnode_set_attrib(iq->node, "to", directory);

	jabber_iq_set_callback(iq, user_search_fields_result_cb, NULL);

	jabber_iq_send(iq);
}

void jabber_user_search_begin(PurplePluginAction *action)
{
	PurpleConnection *gc = (PurpleConnection *) action->context;
	JabberStream *js = purple_connection_get_protocol_data(gc);
	const char *def_val = purple_account_get_string(js->gc->account, "user_directory", "");
	if(!*def_val && js->user_directories)
		def_val = js->user_directories->data;

	purple_request_input(gc, _("Enter a User Directory"), _("Enter a User Directory"),
			_("Select a user directory to search"),
			def_val,
			FALSE, FALSE, NULL,
			_("Search Directory"), PURPLE_CALLBACK(jabber_user_search),
			_("Cancel"), NULL,
			NULL, NULL, NULL,
			js);
}

gboolean
jabber_resource_know_capabilities(const JabberBuddyResource *jbr)
{
	return jbr->caps.info != NULL;
}

gboolean
jabber_resource_has_capability(const JabberBuddyResource *jbr, const gchar *cap)
{
	const GList *node = NULL;
	const JabberCapsNodeExts *exts;

	if (!jbr->caps.info) {
		purple_debug_info("jabber",
			"Unable to find caps: nothing known about buddy\n");
		return FALSE;
	}

	node = g_list_find_custom(jbr->caps.info->features, cap, (GCompareFunc)strcmp);
	if (!node && jbr->caps.exts && jbr->caps.info->exts) {
		const GList *ext;
		exts = jbr->caps.info->exts;
		/* Walk through all the enabled caps, checking each list for the cap.
		 * Don't check it twice, though. */
		for (ext = jbr->caps.exts; ext && !node; ext = ext->next) {
			GList *features = g_hash_table_lookup(exts->exts, ext->data);
			if (features)
				node = g_list_find_custom(features, cap, (GCompareFunc)strcmp);
		}
	}

	return (node != NULL);
}

gboolean
jabber_buddy_has_capability(const JabberBuddy *jb, const gchar *cap)
{
	JabberBuddyResource *jbr = jabber_buddy_find_resource((JabberBuddy*)jb, NULL);

	if (!jbr) {
		purple_debug_info("jabber",
			"Unable to find caps: buddy might be offline\n");
		return FALSE;
	}

	return jabber_resource_has_capability(jbr, cap);
}

const gchar *
jabber_resource_get_identity_category_type(const JabberBuddyResource *jbr,
	const gchar *category)
{
	const GList *iter = NULL;

	if (jbr->caps.info) {
		for (iter = jbr->caps.info->identities ; iter ; iter = g_list_next(iter)) {
			const JabberIdentity *identity =
				(JabberIdentity *) iter->data;

			if (strcmp(identity->category, category) == 0) {
				return identity->type;
			}
		}
	}

	return NULL;
}
