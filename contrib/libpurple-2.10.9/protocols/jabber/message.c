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
#include "notify.h"
#include "server.h"
#include "util.h"
#include "adhoccommands.h"
#include "buddy.h"
#include "chat.h"
#include "data.h"
#include "google/google.h"
#include "message.h"
#include "xmlnode.h"
#include "pep.h"
#include "smiley.h"
#include "iq.h"

#include <string.h>

void jabber_message_free(JabberMessage *jm)
{
	g_free(jm->from);
	g_free(jm->to);
	g_free(jm->id);
	g_free(jm->subject);
	g_free(jm->body);
	g_free(jm->xhtml);
	g_free(jm->password);
	g_free(jm->error);
	g_free(jm->thread_id);
	g_list_free(jm->etc);
	g_list_free(jm->eventitems);

	g_free(jm);
}

static void handle_chat(JabberMessage *jm)
{
	JabberID *jid = jabber_id_new(jm->from);

	PurpleConnection *gc;
	PurpleAccount *account;
	JabberBuddy *jb;
	JabberBuddyResource *jbr;

	if(!jid)
		return;

	gc = jm->js->gc;
	account = purple_connection_get_account(gc);

	jb = jabber_buddy_find(jm->js, jm->from, TRUE);
	jbr = jabber_buddy_find_resource(jb, jid->resource);

	if(!jm->xhtml && !jm->body) {
		if (jbr && jm->chat_state != JM_STATE_NONE)
			jbr->chat_states = JABBER_CHAT_STATES_SUPPORTED;

		if(JM_STATE_COMPOSING == jm->chat_state) {
			serv_got_typing(gc, jm->from, 0, PURPLE_TYPING);
		} else if(JM_STATE_PAUSED == jm->chat_state) {
			serv_got_typing(gc, jm->from, 0, PURPLE_TYPED);
		} else if(JM_STATE_GONE == jm->chat_state) {
			PurpleConversation *conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM,
					jm->from, account);
			if (conv && jid->node && jid->domain) {
				char buf[256];
				PurpleBuddy *buddy;

				g_snprintf(buf, sizeof(buf), "%s@%s", jid->node, jid->domain);

				if ((buddy = purple_find_buddy(account, buf))) {
					const char *who;
					char *escaped;

					who = purple_buddy_get_alias(buddy);
					escaped = g_markup_escape_text(who, -1);

					g_snprintf(buf, sizeof(buf),
					           _("%s has left the conversation."), escaped);
					g_free(escaped);

					/* At some point when we restructure PurpleConversation,
					 * this should be able to be implemented by removing the
					 * user from the conversation like we do with chats now. */
					purple_conversation_write(conv, "", buf,
					                        PURPLE_MESSAGE_SYSTEM, time(NULL));
				}
			}
			serv_got_typing_stopped(gc, jm->from);

		} else {
			serv_got_typing_stopped(gc, jm->from);
		}
	} else {
		if (jid->resource) {
			/*
			 * We received a message from a specific resource, so
			 * we probably want a reply to go to this specific
			 * resource (i.e. bind/lock the conversation to this
			 * resource).
			 *
			 * This works because purple_conv_im_send gets the name
			 * from purple_conversation_get_name()
			 */
			PurpleConversation *conv;

			conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM,
			                                             jm->from, account);
			if (conv && !g_str_equal(jm->from,
			                         purple_conversation_get_name(conv))) {
				purple_debug_info("jabber", "Binding conversation to %s\n",
				                  jm->from);
				purple_conversation_set_name(conv, jm->from);
			}
		}

		if(jbr) {
			/* Treat SUPPORTED as a terminal with no escape :) */
			if (jbr->chat_states != JABBER_CHAT_STATES_SUPPORTED) {
				if (jm->chat_state != JM_STATE_NONE)
					jbr->chat_states = JABBER_CHAT_STATES_SUPPORTED;
				else
					jbr->chat_states = JABBER_CHAT_STATES_UNSUPPORTED;
			}

			if(jbr->thread_id)
				g_free(jbr->thread_id);
			jbr->thread_id = g_strdup(jbr->thread_id);
		}

		if (jm->js->googletalk && jm->xhtml == NULL) {
			char *tmp = jm->body;
			jm->body = jabber_google_format_to_html(jm->body);
			g_free(tmp);
		}
		serv_got_im(gc, jm->from, jm->xhtml ? jm->xhtml : jm->body, 0, jm->sent);
	}

	jabber_id_free(jid);
}

static void handle_headline(JabberMessage *jm)
{
	char *title;
	GString *body;
	GList *etc;

	if(!jm->xhtml && !jm->body)
		return; /* ignore headlines without any content */

	body = g_string_new("");
	title = g_strdup_printf(_("Message from %s"), jm->from);

	if(jm->xhtml)
		g_string_append(body, jm->xhtml);
	else if(jm->body)
		g_string_append(body, jm->body);

	for(etc = jm->etc; etc; etc = etc->next) {
		xmlnode *x = etc->data;
		const char *xmlns = xmlnode_get_namespace(x);
		if(xmlns && !strcmp(xmlns, NS_OOB_X_DATA)) {
			xmlnode *url, *desc;
			char *urltxt, *desctxt;

			url = xmlnode_get_child(x, "url");
			desc = xmlnode_get_child(x, "desc");

			if(!url || !desc)
				continue;

			urltxt = xmlnode_get_data(url);
			desctxt = xmlnode_get_data(desc);

			/* I'm all about ugly hacks */
			if(body->len && jm->body && !strcmp(body->str, jm->body))
				g_string_printf(body, "<a href='%s'>%s</a>",
						urltxt, desctxt);
			else
				g_string_append_printf(body, "<br/><a href='%s'>%s</a>",
						urltxt, desctxt);

			g_free(urltxt);
			g_free(desctxt);
		}
	}

	purple_notify_formatted(jm->js->gc, title, jm->subject ? jm->subject : title,
			NULL, body->str, NULL, NULL);

	g_free(title);
	g_string_free(body, TRUE);
}

static void handle_groupchat(JabberMessage *jm)
{
	JabberID *jid = jabber_id_new(jm->from);
	JabberChat *chat;

	if(!jid)
		return;

	chat = jabber_chat_find(jm->js, jid->node, jid->domain);

	if(!chat)
		return;

	if(jm->subject) {
		purple_conv_chat_set_topic(PURPLE_CONV_CHAT(chat->conv), jid->resource,
				jm->subject);
		if(!jm->xhtml && !jm->body) {
			char *msg, *tmp, *tmp2;
			tmp = g_markup_escape_text(jm->subject, -1);
			tmp2 = purple_markup_linkify(tmp);
			if(jid->resource)
				msg = g_strdup_printf(_("%s has set the topic to: %s"), jid->resource, tmp2);
			else
				msg = g_strdup_printf(_("The topic is: %s"), tmp2);
			purple_conv_chat_write(PURPLE_CONV_CHAT(chat->conv), "", msg, PURPLE_MESSAGE_SYSTEM, jm->sent);
			g_free(tmp);
			g_free(tmp2);
			g_free(msg);
		}
	}

	if(jm->xhtml || jm->body) {
		if(jid->resource)
			serv_got_chat_in(jm->js->gc, chat->id, jid->resource,
							jm->delayed ? PURPLE_MESSAGE_DELAYED : 0,
							jm->xhtml ? jm->xhtml : jm->body, jm->sent);
		else if(chat->muc)
			purple_conv_chat_write(PURPLE_CONV_CHAT(chat->conv), "",
							jm->xhtml ? jm->xhtml : jm->body,
							PURPLE_MESSAGE_SYSTEM, jm->sent);
	}

	jabber_id_free(jid);
}

static void handle_groupchat_invite(JabberMessage *jm)
{
	GHashTable *components;
	JabberID *jid = jabber_id_new(jm->to);

	if(!jid)
		return;

	components = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);

	g_hash_table_replace(components, "room", g_strdup(jid->node));
	g_hash_table_replace(components, "server", g_strdup(jid->domain));
	g_hash_table_replace(components, "handle", g_strdup(jm->js->user->node));
	g_hash_table_replace(components, "password", g_strdup(jm->password));

	jabber_id_free(jid);
	serv_got_chat_invite(jm->js->gc, jm->to, jm->from, jm->body, components);
}

static void handle_error(JabberMessage *jm)
{
	char *buf;

	if(!jm->body)
		return;

	buf = g_strdup_printf(_("Message delivery to %s failed: %s"),
			jm->from, jm->error ? jm->error : "");

	purple_notify_formatted(jm->js->gc, _("XMPP Message Error"), _("XMPP Message Error"), buf,
			jm->xhtml ? jm->xhtml : jm->body, NULL, NULL);

	g_free(buf);
}

static void handle_buzz(JabberMessage *jm) {
	PurpleAccount *account;

	/* Delayed buzz MUST NOT be accepted */
	if(jm->delayed)
		return;

	/* Reject buzz when it's not enabled */
	if(!jm->js->allowBuzz)
		return;

	account = purple_connection_get_account(jm->js->gc);

	if (purple_find_buddy(account, jm->from) == NULL)
		return; /* Do not accept buzzes from unknown people */

	/* xmpp only has 1 attention type, so index is 0 */
	purple_prpl_got_attention(jm->js->gc, jm->from, 0);
}

/* used internally by the functions below */
typedef struct {
	gchar *cid;
	gchar *alt;
} JabberSmileyRef;


static void
jabber_message_get_refs_from_xmlnode_internal(const xmlnode *message,
	GHashTable *table)
{
	xmlnode *child;

	for (child = xmlnode_get_child(message, "img") ; child ;
		 child = xmlnode_get_next_twin(child)) {
		const gchar *src = xmlnode_get_attrib(child, "src");

		if (g_str_has_prefix(src, "cid:")) {
			const gchar *cid = src + 4;

			/* if we haven't "fetched" this yet... */
			if (!g_hash_table_lookup(table, cid)) {
				/* take a copy of the cid and let the SmileyRef own it... */
				gchar *temp_cid = g_strdup(cid);
				JabberSmileyRef *ref = g_new0(JabberSmileyRef, 1);
				const gchar *alt = xmlnode_get_attrib(child, "alt");
				ref->cid = temp_cid;
				/* if there is no "alt" string, use the cid...
				 include the entire src, eg. "cid:.." to avoid linkification */
				if (alt && alt[0] != '\0') {
					/* workaround for when "alt" is set to the value of the
					 CID (which Jabbim seems to do), to avoid it showing up
						 as an mailto: link */
					if (purple_email_is_valid(alt)) {
						ref->alt = g_strdup_printf("smiley:%s", alt);
					} else {
						ref->alt = g_strdup(alt);
					}
				} else {
					ref->alt = g_strdup(src);
				}
				g_hash_table_insert(table, temp_cid, ref);
			}
		}
	}

	for (child = message->child ; child ; child = child->next) {
		jabber_message_get_refs_from_xmlnode_internal(child, table);
	}
}

static gboolean
jabber_message_get_refs_steal(gpointer key, gpointer value, gpointer user_data)
{
	GList **refs = (GList **) user_data;
	JabberSmileyRef *ref = (JabberSmileyRef *) value;

	*refs = g_list_append(*refs, ref);

	return TRUE;
}

static GList *
jabber_message_get_refs_from_xmlnode(const xmlnode *message)
{
	GList *refs = NULL;
	GHashTable *unique_refs = g_hash_table_new(g_str_hash, g_str_equal);

	jabber_message_get_refs_from_xmlnode_internal(message, unique_refs);
	(void) g_hash_table_foreach_steal(unique_refs,
		jabber_message_get_refs_steal, (gpointer) &refs);
	g_hash_table_destroy(unique_refs);
	return refs;
}

static gchar *
jabber_message_xml_to_string_strip_img_smileys(xmlnode *xhtml)
{
	gchar *markup = xmlnode_to_str(xhtml, NULL);
	int len = strlen(markup);
	int pos = 0;
	GString *out = g_string_new(NULL);

	while (pos < len) {
		/* this is a bit cludgy, maybe there is a better way to do this...
		  we need to find all <img> tags within the XHTML and replace those
			tags with the value of their "alt" attributes */
		if (g_str_has_prefix(&(markup[pos]), "<img")) {
			xmlnode *img = NULL;
			int pos2 = pos;
			const gchar *src;

			for (; pos2 < len ; pos2++) {
				if (g_str_has_prefix(&(markup[pos2]), "/>")) {
					pos2 += 2;
					break;
				} else if (g_str_has_prefix(&(markup[pos2]), "</img>")) {
					pos2 += 5;
					break;
				}
			}

			/* note, if the above loop didn't find the end of the <img> tag,
			  it the parsed string will be until the end of the input string,
			  in which case xmlnode_from_str will bail out and return NULL,
			  in this case the "if" statement below doesn't trigger and the
			  text is copied unchanged */
			img = xmlnode_from_str(&(markup[pos]), pos2 - pos);
			src = xmlnode_get_attrib(img, "src");

			if (g_str_has_prefix(src, "cid:")) {
				const gchar *alt = xmlnode_get_attrib(img, "alt");
				/* if the "alt" attribute is empty, put the cid as smiley string */
				if (alt && alt[0] != '\0') {
					/* if the "alt" is the same as the CID, as Jabbim does,
					 this prevents linkification... */
					if (purple_email_is_valid(alt)) {
						gchar *safe_alt = g_strdup_printf("smiley:%s", alt);
						out = g_string_append(out, safe_alt);
						g_free(safe_alt);
					} else {
						out = g_string_append(out, alt);
					}
				} else {
					out = g_string_append(out, src);
				}
				pos += pos2 - pos;
			} else {
				out = g_string_append_c(out, markup[pos]);
				pos++;
			}

			xmlnode_free(img);

		} else {
			out = g_string_append_c(out, markup[pos]);
			pos++;
		}
	}

	g_free(markup);
	return g_string_free(out, FALSE);
}

static void
jabber_message_add_remote_smileys(JabberStream *js, const gchar *who,
    const xmlnode *message)
{
	xmlnode *data_tag;
	for (data_tag = xmlnode_get_child_with_namespace(message, "data", NS_BOB) ;
		 data_tag ;
		 data_tag = xmlnode_get_next_twin(data_tag)) {
		const gchar *cid = xmlnode_get_attrib(data_tag, "cid");
		const JabberData *data = jabber_data_find_remote_by_cid(js, who, cid);

		if (!data && cid != NULL) {
			/* we haven't cached this already, let's add it */
			JabberData *new_data = jabber_data_create_from_xml(data_tag);

			if (new_data) {
				jabber_data_associate_remote(js, who, new_data);
			}
		}
	}
}

static void
jabber_message_request_data_cb(JabberData *data, gchar *alt,
    gpointer userdata)
{
	PurpleConversation *conv = (PurpleConversation *) userdata;

	if (data) {
		purple_conv_custom_smiley_write(conv, alt,
										jabber_data_get_data(data),
										jabber_data_get_size(data));
		purple_conv_custom_smiley_close(conv, alt);
	}

	g_free(alt);
}

void jabber_message_parse(JabberStream *js, xmlnode *packet)
{
	JabberMessage *jm;
	const char *id, *from, *to, *type;
	xmlnode *child;
	gboolean signal_return;

	from = xmlnode_get_attrib(packet, "from");
	id   = xmlnode_get_attrib(packet, "id");
	to   = xmlnode_get_attrib(packet, "to");
	type = xmlnode_get_attrib(packet, "type");

	signal_return = GPOINTER_TO_INT(purple_signal_emit_return_1(purple_connection_get_prpl(js->gc),
			"jabber-receiving-message", js->gc, type, id, from, to, packet));
	if (signal_return)
		return;

	jm = g_new0(JabberMessage, 1);
	jm->js = js;
	jm->sent = time(NULL);
	jm->delayed = FALSE;
	jm->chat_state = JM_STATE_NONE;

	if(type) {
		if(!strcmp(type, "normal"))
			jm->type = JABBER_MESSAGE_NORMAL;
		else if(!strcmp(type, "chat"))
			jm->type = JABBER_MESSAGE_CHAT;
		else if(!strcmp(type, "groupchat"))
			jm->type = JABBER_MESSAGE_GROUPCHAT;
		else if(!strcmp(type, "headline"))
			jm->type = JABBER_MESSAGE_HEADLINE;
		else if(!strcmp(type, "error"))
			jm->type = JABBER_MESSAGE_ERROR;
		else
			jm->type = JABBER_MESSAGE_OTHER;
	} else {
		jm->type = JABBER_MESSAGE_NORMAL;
	}

	jm->from = g_strdup(from);
	jm->to   = g_strdup(to);
	jm->id   = g_strdup(id);

	for(child = packet->child; child; child = child->next) {
		const char *xmlns = xmlnode_get_namespace(child);
		if(child->type != XMLNODE_TYPE_TAG)
			continue;

		if(!strcmp(child->name, "error")) {
			const char *code = xmlnode_get_attrib(child, "code");
			char *code_txt = NULL;
			char *text = xmlnode_get_data(child);
			if (!text) {
				xmlnode *enclosed_text_node;

				if ((enclosed_text_node = xmlnode_get_child(child, "text")))
					text = xmlnode_get_data(enclosed_text_node);
			}

			if(code)
				code_txt = g_strdup_printf(_("(Code %s)"), code);

			if(!jm->error)
				jm->error = g_strdup_printf("%s%s%s",
						text ? text : "",
						text && code_txt ? " " : "",
						code_txt ? code_txt : "");

			g_free(code_txt);
			g_free(text);
		} else if (xmlns == NULL) {
			/* QuLogic: Not certain this is correct, but it would have happened
			   with the previous code. */
			if(!strcmp(child->name, "x"))
				jm->etc = g_list_append(jm->etc, child);
			/* The following tests expect xmlns != NULL */
			continue;
		} else if(!strcmp(child->name, "subject") && !strcmp(xmlns, NS_XMPP_CLIENT)) {
			if(!jm->subject) {
				jm->subject = xmlnode_get_data(child);
				if(!jm->subject)
					jm->subject = g_strdup("");
			}
		} else if(!strcmp(child->name, "thread") && !strcmp(xmlns, NS_XMPP_CLIENT)) {
			if(!jm->thread_id)
				jm->thread_id = xmlnode_get_data(child);
		} else if(!strcmp(child->name, "body") && !strcmp(xmlns, NS_XMPP_CLIENT)) {
			if(!jm->body) {
				char *msg = xmlnode_get_data(child);
				char *escaped = purple_markup_escape_text(msg, -1);
				jm->body = purple_strdup_withhtml(escaped);
				g_free(escaped);
				g_free(msg);
			}
		} else if(!strcmp(child->name, "html") && !strcmp(xmlns, NS_XHTML_IM)) {
			if(!jm->xhtml && xmlnode_get_child(child, "body")) {
				char *c;

				const PurpleConnection *gc = js->gc;
				PurpleAccount *account = purple_connection_get_account(gc);
				PurpleConversation *conv = NULL;
				GList *smiley_refs = NULL;
				gchar *reformatted_xhtml;

				if (purple_account_get_bool(account, "custom_smileys", TRUE)) {
					/* find a list of smileys ("cid" and "alt" text pairs)
					  occuring in the message */
					smiley_refs = jabber_message_get_refs_from_xmlnode(child);
					purple_debug_info("jabber", "found %d smileys\n",
						g_list_length(smiley_refs));

					if (smiley_refs) {
						if (jm->type == JABBER_MESSAGE_GROUPCHAT) {
							JabberID *jid = jabber_id_new(jm->from);
							JabberChat *chat = NULL;

							if (jid) {
								chat = jabber_chat_find(js, jid->node, jid->domain);
								if (chat)
									conv = chat->conv;
								jabber_id_free(jid);
							}
						} else if (jm->type == JABBER_MESSAGE_NORMAL ||
						           jm->type == JABBER_MESSAGE_CHAT) {
							conv =
								purple_find_conversation_with_account(PURPLE_CONV_TYPE_ANY,
									from, account);
							if (!conv) {
								/* we need to create the conversation here */
								conv =
									purple_conversation_new(PURPLE_CONV_TYPE_IM,
									account, from);
							}
						}
					}

					/* process any newly provided smileys */
					jabber_message_add_remote_smileys(js, to, packet);
				}

				/* reformat xhtml so that img tags with a "cid:" src gets
				  translated to the bare text of the emoticon (the "alt" attrib) */
				/* this is done also when custom smiley retrieval is turned off,
				  this way the receiver always sees the shortcut instead */
				reformatted_xhtml =
					jabber_message_xml_to_string_strip_img_smileys(child);

				jm->xhtml = reformatted_xhtml;

				/* add known custom emoticons to the conversation */
				/* note: if there were no smileys in the incoming message, or
				  	if receiving custom smileys is turned off, smiley_refs will
					be NULL */
				for (; conv && smiley_refs ; smiley_refs = g_list_delete_link(smiley_refs, smiley_refs)) {
					JabberSmileyRef *ref = (JabberSmileyRef *) smiley_refs->data;
					const gchar *cid = ref->cid;
					gchar *alt = g_strdup(ref->alt);

					purple_debug_info("jabber",
						"about to add custom smiley %s to the conv\n", alt);
					if (purple_conv_custom_smiley_add(conv, alt, "cid", cid,
						    TRUE)) {
						const JabberData *data =
								jabber_data_find_remote_by_cid(js, from, cid);
						/* if data is already known, we write it immediatly */
						if (data) {
							purple_debug_info("jabber",
								"data is already known\n");
							purple_conv_custom_smiley_write(conv, alt,
								jabber_data_get_data(data),
								jabber_data_get_size(data));
							purple_conv_custom_smiley_close(conv, alt);
						} else {
							/* we need to request the smiley (data) */
							purple_debug_info("jabber",
								"data is unknown, need to request it\n");
							jabber_data_request(js, cid, from, alt, FALSE,
							    jabber_message_request_data_cb, conv);
						}
					}
					g_free(ref->cid);
					g_free(ref->alt);
					g_free(ref);
				}

			    /* Convert all newlines to whitespace. Technically, even regular, non-XML HTML is supposed to ignore newlines, but Pidgin has, as convention
				 * treated \n as a newline for compatibility with other protocols
				 */
				for (c = jm->xhtml; *c != '\0'; c++) {
					if (*c == '\n')
						*c = ' ';
				}
			}
		} else if(!strcmp(child->name, "active") && !strcmp(xmlns,"http://jabber.org/protocol/chatstates")) {
			jm->chat_state = JM_STATE_ACTIVE;
		} else if(!strcmp(child->name, "composing") && !strcmp(xmlns,"http://jabber.org/protocol/chatstates")) {
			jm->chat_state = JM_STATE_COMPOSING;
		} else if(!strcmp(child->name, "paused") && !strcmp(xmlns,"http://jabber.org/protocol/chatstates")) {
			jm->chat_state = JM_STATE_PAUSED;
		} else if(!strcmp(child->name, "inactive") && !strcmp(xmlns,"http://jabber.org/protocol/chatstates")) {
			jm->chat_state = JM_STATE_INACTIVE;
		} else if(!strcmp(child->name, "gone") && !strcmp(xmlns,"http://jabber.org/protocol/chatstates")) {
			jm->chat_state = JM_STATE_GONE;
		} else if(!strcmp(child->name, "event") && !strcmp(xmlns,"http://jabber.org/protocol/pubsub#event")) {
			xmlnode *items;
			jm->type = JABBER_MESSAGE_EVENT;
			for(items = xmlnode_get_child(child,"items"); items; items = items->next)
				jm->eventitems = g_list_append(jm->eventitems, items);
		} else if(!strcmp(child->name, "attention") && !strcmp(xmlns, NS_ATTENTION)) {
			jm->hasBuzz = TRUE;
		} else if(!strcmp(child->name, "delay") && !strcmp(xmlns, NS_DELAYED_DELIVERY)) {
			const char *timestamp = xmlnode_get_attrib(child, "stamp");
			jm->delayed = TRUE;
			if(timestamp)
				jm->sent = purple_str_to_time(timestamp, TRUE, NULL, NULL, NULL);
		} else if(!strcmp(child->name, "x")) {
			if(!strcmp(xmlns, NS_DELAYED_DELIVERY_LEGACY)) {
				const char *timestamp = xmlnode_get_attrib(child, "stamp");
				jm->delayed = TRUE;
				if(timestamp)
					jm->sent = purple_str_to_time(timestamp, TRUE, NULL, NULL, NULL);
			} else if(!strcmp(xmlns, "jabber:x:conference") &&
					jm->type != JABBER_MESSAGE_GROUPCHAT_INVITE &&
					jm->type != JABBER_MESSAGE_ERROR) {
				const char *jid = xmlnode_get_attrib(child, "jid");
				if(jid) {
					const char *reason = xmlnode_get_attrib(child, "reason");
					const char *password = xmlnode_get_attrib(child, "password");

					jm->type = JABBER_MESSAGE_GROUPCHAT_INVITE;
					g_free(jm->to);
					jm->to = g_strdup(jid);

					if (reason) {
						g_free(jm->body);
						jm->body = g_strdup(reason);
					}

					if (password) {
						g_free(jm->password);
						jm->password = g_strdup(password);
					}
				}
			} else if(!strcmp(xmlns, "http://jabber.org/protocol/muc#user") &&
					jm->type != JABBER_MESSAGE_ERROR) {
				xmlnode *invite = xmlnode_get_child(child, "invite");
				if(invite) {
					xmlnode *reason, *password;
					const char *jid = xmlnode_get_attrib(invite, "from");
					g_free(jm->to);
					jm->to = jm->from;
					jm->from = g_strdup(jid);
					if((reason = xmlnode_get_child(invite, "reason"))) {
						g_free(jm->body);
						jm->body = xmlnode_get_data(reason);
					}
					if((password = xmlnode_get_child(child, "password"))) {
						g_free(jm->password);
						jm->password = xmlnode_get_data(password);
					}

					jm->type = JABBER_MESSAGE_GROUPCHAT_INVITE;
				}
			} else {
				jm->etc = g_list_append(jm->etc, child);
			}
		} else if (g_str_equal(child->name, "query")) {
			const char *node = xmlnode_get_attrib(child, "node");
			if (purple_strequal(xmlns, NS_DISCO_ITEMS)
					&& purple_strequal(node, "http://jabber.org/protocol/commands")) {
				jabber_adhoc_got_list(js, jm->from, child);
			}
		}
	}

	if(jm->hasBuzz)
		handle_buzz(jm);

	switch(jm->type) {
		case JABBER_MESSAGE_OTHER:
			purple_debug_info("jabber",
					"Received message of unknown type: %s\n", type);
			/* Fall-through is intentional */
		case JABBER_MESSAGE_NORMAL:
		case JABBER_MESSAGE_CHAT:
			handle_chat(jm);
			break;
		case JABBER_MESSAGE_HEADLINE:
			handle_headline(jm);
			break;
		case JABBER_MESSAGE_GROUPCHAT:
			handle_groupchat(jm);
			break;
		case JABBER_MESSAGE_GROUPCHAT_INVITE:
			handle_groupchat_invite(jm);
			break;
		case JABBER_MESSAGE_EVENT:
			jabber_handle_event(jm);
			break;
		case JABBER_MESSAGE_ERROR:
			handle_error(jm);
			break;
	}
	jabber_message_free(jm);
}

static const gchar *
jabber_message_get_mimetype_from_ext(const gchar *ext)
{
	if (strcmp(ext, "png") == 0) {
		return "image/png";
	} else if (strcmp(ext, "gif") == 0) {
		return "image/gif";
	} else if (strcmp(ext, "jpg") == 0) {
		return "image/jpeg";
	} else if (strcmp(ext, "tif") == 0) {
		return "image/tif";
	} else {
		return "image/x-icon"; /* or something... */
	}
}

static GList *
jabber_message_xhtml_find_smileys(const char *xhtml)
{
	GList *smileys = purple_smileys_get_all();
	GList *found_smileys = NULL;

	for (; smileys ; smileys = g_list_delete_link(smileys, smileys)) {
		PurpleSmiley *smiley = (PurpleSmiley *) smileys->data;

		const gchar *shortcut = purple_smiley_get_shortcut(smiley);
		const gssize len = strlen(shortcut);

		gchar *escaped = g_markup_escape_text(shortcut, len);
		const char *pos = strstr(xhtml, escaped);

		if (pos) {
			found_smileys = g_list_append(found_smileys, smiley);
		}

		g_free(escaped);
	}

	return found_smileys;
}

static gchar *
jabber_message_get_smileyfied_xhtml(const gchar *xhtml, const GList *smileys)
{
	/* create XML element for all smileys (img tags) */
	GString *result = g_string_new(NULL);
	int pos = 0;
	int length = strlen(xhtml);

	while (pos < length) {
		const GList *iterator;
		gboolean found_smiley = FALSE;

		for (iterator = smileys ; iterator ;
			iterator = g_list_next(iterator)) {
			const PurpleSmiley *smiley = (PurpleSmiley *) iterator->data;
			const gchar *shortcut = purple_smiley_get_shortcut(smiley);
			const gssize len = strlen(shortcut);
			gchar *escaped = g_markup_escape_text(shortcut, len);

			if (g_str_has_prefix(&(xhtml[pos]), escaped)) {
				/* we found the current smiley at this position */
				const JabberData *data =
					jabber_data_find_local_by_alt(shortcut);
				xmlnode *img = jabber_data_get_xhtml_im(data, shortcut);
				int len;
				gchar *img_text = xmlnode_to_str(img, &len);

				found_smiley = TRUE;
				result = g_string_append(result, img_text);
				g_free(img_text);
				pos += strlen(escaped);
				g_free(escaped);
				xmlnode_free(img);
				break;
			} else {
				/* cleanup from the before the next round... */
				g_free(escaped);
			}
		}
		if (!found_smiley) {
			/* there was no smiley here, just copy one byte */
			result = g_string_append_c(result, xhtml[pos]);
			pos++;
		}
	}

	return g_string_free(result, FALSE);
}

static gboolean
jabber_conv_support_custom_smileys(JabberStream *js,
								   PurpleConversation *conv,
								   const gchar *who)
{
	JabberBuddy *jb;
	JabberChat *chat;

	switch (purple_conversation_get_type(conv)) {
		case PURPLE_CONV_TYPE_IM:
			jb = jabber_buddy_find(js, who, FALSE);
			if (jb) {
				return jabber_buddy_has_capability(jb, NS_BOB);
			} else {
				return FALSE;
			}
			break;
		case PURPLE_CONV_TYPE_CHAT:
			chat = jabber_chat_find_by_conv(conv);
			if (chat) {
				/* do not attempt to send custom smileys in a MUC with more than
				 10 people, to avoid getting too many BoB requests */
				return jabber_chat_get_num_participants(chat) <= 10 &&
					jabber_chat_all_participants_have_capability(chat,
						NS_BOB);
			} else {
				return FALSE;
			}
			break;
		default:
			return FALSE;
			break;
	}
}

static char *
jabber_message_smileyfy_xhtml(JabberMessage *jm, const char *xhtml)
{
	PurpleAccount *account = purple_connection_get_account(jm->js->gc);
	PurpleConversation *conv =
		purple_find_conversation_with_account(PURPLE_CONV_TYPE_ANY, jm->to,
			account);

	if (jabber_conv_support_custom_smileys(jm->js, conv, jm->to)) {
		GList *found_smileys = jabber_message_xhtml_find_smileys(xhtml);

		if (found_smileys) {
			gchar *smileyfied_xhtml = NULL;
			const GList *iterator;
			GList *valid_smileys = NULL;
			gboolean has_too_large_smiley = FALSE;

			for (iterator = found_smileys; iterator ;
				iterator = g_list_next(iterator)) {
				PurpleSmiley *smiley = (PurpleSmiley *) iterator->data;
				const gchar *shortcut = purple_smiley_get_shortcut(smiley);
				const JabberData *data =
					jabber_data_find_local_by_alt(shortcut);
				PurpleStoredImage *image = purple_smiley_get_stored_image(smiley);

				if (purple_imgstore_get_size(image) <= JABBER_DATA_MAX_SIZE) {
					/* the object has not been sent before */
					if (!data) {
						const gchar *ext = purple_imgstore_get_extension(image);
						JabberStream *js = jm->js;

						JabberData *new_data =
							jabber_data_create_from_data(purple_imgstore_get_data(image),
								purple_imgstore_get_size(image),
								jabber_message_get_mimetype_from_ext(ext), FALSE, js);
						purple_debug_info("jabber",
							"cache local smiley alt = %s, cid = %s\n",
							shortcut, jabber_data_get_cid(new_data));
						jabber_data_associate_local(new_data, shortcut);
					}
					valid_smileys = g_list_append(valid_smileys, smiley);
				} else {
					has_too_large_smiley = TRUE;
					purple_debug_warning("jabber", "Refusing to send smiley %s "
							"(too large, max is %d)\n",
							purple_smiley_get_shortcut(smiley),
							JABBER_DATA_MAX_SIZE);
				}
			}

			if (has_too_large_smiley) {
				purple_conversation_write(conv, NULL,
				    _("A custom smiley in the message is too large to send."),
					PURPLE_MESSAGE_ERROR, time(NULL));
			}

			smileyfied_xhtml =
				jabber_message_get_smileyfied_xhtml(xhtml, valid_smileys);
			g_list_free(found_smileys);
			g_list_free(valid_smileys);

			return smileyfied_xhtml;
		}
	}

	return NULL;
}

void jabber_message_send(JabberMessage *jm)
{
	xmlnode *message, *child;
	const char *type = NULL;

	message = xmlnode_new("message");

	switch(jm->type) {
		case JABBER_MESSAGE_NORMAL:
			type = "normal";
			break;
		case JABBER_MESSAGE_CHAT:
		case JABBER_MESSAGE_GROUPCHAT_INVITE:
			type = "chat";
			break;
		case JABBER_MESSAGE_HEADLINE:
			type = "headline";
			break;
		case JABBER_MESSAGE_GROUPCHAT:
			type = "groupchat";
			break;
		case JABBER_MESSAGE_ERROR:
			type = "error";
			break;
		case JABBER_MESSAGE_OTHER:
		default:
			type = NULL;
			break;
	}

	if(type)
		xmlnode_set_attrib(message, "type", type);

	if (jm->id)
		xmlnode_set_attrib(message, "id", jm->id);

	xmlnode_set_attrib(message, "to", jm->to);

	if(jm->thread_id) {
		child = xmlnode_new_child(message, "thread");
		xmlnode_insert_data(child, jm->thread_id, -1);
	}

	child = NULL;
	switch(jm->chat_state)
	{
		case JM_STATE_ACTIVE:
			child = xmlnode_new_child(message, "active");
			break;
		case JM_STATE_COMPOSING:
			child = xmlnode_new_child(message, "composing");
			break;
		case JM_STATE_PAUSED:
			child = xmlnode_new_child(message, "paused");
			break;
		case JM_STATE_INACTIVE:
			child = xmlnode_new_child(message, "inactive");
			break;
		case JM_STATE_GONE:
			child = xmlnode_new_child(message, "gone");
			break;
		case JM_STATE_NONE:
			/* yep, nothing */
			break;
	}
	if(child)
		xmlnode_set_namespace(child, "http://jabber.org/protocol/chatstates");

	if(jm->subject) {
		child = xmlnode_new_child(message, "subject");
		xmlnode_insert_data(child, jm->subject, -1);
	}

	if(jm->body) {
		child = xmlnode_new_child(message, "body");
		xmlnode_insert_data(child, jm->body, -1);
	}

	if(jm->xhtml) {
		if ((child = xmlnode_from_str(jm->xhtml, -1))) {
			xmlnode_insert_child(message, child);
		} else {
			purple_debug_error("jabber",
					"XHTML translation/validation failed, returning: %s\n",
					jm->xhtml);
		}
	}

	jabber_send(jm->js, message);

	xmlnode_free(message);
}

/*
 * Compare the XHTML and plain strings passed in for "equality". Any HTML markup
 * other than <br/> (matches a newline) in the XHTML will cause this to return
 * FALSE.
 */
static gboolean
jabber_xhtml_plain_equal(const char *xhtml_escaped,
                         const char *plain)
{
	int i = 0;
	int j = 0;
	gboolean ret;
	char *xhtml = purple_unescape_html(xhtml_escaped);

	while (xhtml[i] && plain[j]) {
		if (xhtml[i] == plain[j]) {
			i += 1;
			j += 1;
			continue;
		}

		if (plain[j] == '\n' && !strncmp(xhtml+i, "<br/>", 5)) {
			i += 5;
			j += 1;
			continue;
		}

		g_free(xhtml);
		return FALSE;
	}

	/* Are we at the end of both strings? */
	ret = (xhtml[i] == plain[j]) && (xhtml[i] == '\0');
	g_free(xhtml);
	return ret;
}

int jabber_message_send_im(PurpleConnection *gc, const char *who, const char *msg,
		PurpleMessageFlags flags)
{
	JabberMessage *jm;
	JabberBuddy *jb;
	JabberBuddyResource *jbr;
	char *xhtml;
	char *tmp;
	char *resource;

	if(!who || !msg)
		return 0;

	if (purple_debug_is_verbose()) {
		/* TODO: Maybe we need purple_debug_is_really_verbose? :) */
		purple_debug_misc("jabber", "jabber_message_send_im: who='%s'\n"
		                            "\tmsg='%s'\n", who, msg);
	}

	resource = jabber_get_resource(who);

	jb = jabber_buddy_find(gc->proto_data, who, TRUE);
	jbr = jabber_buddy_find_resource(jb, resource);

	g_free(resource);

	jm = g_new0(JabberMessage, 1);
	jm->js = gc->proto_data;
	jm->type = JABBER_MESSAGE_CHAT;
	jm->chat_state = JM_STATE_ACTIVE;
	jm->to = g_strdup(who);
	jm->id = jabber_get_next_id(jm->js);

	if(jbr) {
		if(jbr->thread_id)
			jm->thread_id = jbr->thread_id;

		if (jbr->chat_states == JABBER_CHAT_STATES_UNSUPPORTED)
			jm->chat_state = JM_STATE_NONE;
		else {
			/* if(JABBER_CHAT_STATES_UNKNOWN == jbr->chat_states)
			   jbr->chat_states = JABBER_CHAT_STATES_UNSUPPORTED; */
		}
	}

	tmp = purple_utf8_strip_unprintables(msg);
	purple_markup_html_to_xhtml(tmp, &xhtml, &jm->body);
	g_free(tmp);

	tmp = jabber_message_smileyfy_xhtml(jm, xhtml);
	if (tmp) {
		g_free(xhtml);
		xhtml = tmp;
	}

	/*
	 * For backward compatibility with user expectations or for those not on
	 * the user's roster, allow sending XHTML-IM markup.
	 */
	if (!jbr || !jbr->caps.info ||
			jabber_resource_has_capability(jbr, NS_XHTML_IM)) {
		if (!jabber_xhtml_plain_equal(xhtml, jm->body))
			/* Wrap the message in <p/> for great interoperability justice. */
			jm->xhtml = g_strdup_printf("<html xmlns='" NS_XHTML_IM "'><body xmlns='" NS_XHTML "'><p>%s</p></body></html>", xhtml);
	}

	g_free(xhtml);

	jabber_message_send(jm);
	jabber_message_free(jm);
	return 1;
}

int jabber_message_send_chat(PurpleConnection *gc, int id, const char *msg, PurpleMessageFlags flags)
{
	JabberChat *chat;
	JabberMessage *jm;
	JabberStream *js;
	char *xhtml;
	char *tmp;

	if(!msg || !gc)
		return 0;

	js = gc->proto_data;
	chat = jabber_chat_find_by_id(js, id);

	if(!chat)
		return 0;

	jm = g_new0(JabberMessage, 1);
	jm->js = gc->proto_data;
	jm->type = JABBER_MESSAGE_GROUPCHAT;
	jm->to = g_strdup_printf("%s@%s", chat->room, chat->server);
	jm->id = jabber_get_next_id(jm->js);

	tmp = purple_utf8_strip_unprintables(msg);
	purple_markup_html_to_xhtml(tmp, &xhtml, &jm->body);
	g_free(tmp);
	tmp = jabber_message_smileyfy_xhtml(jm, xhtml);
	if (tmp) {
		g_free(xhtml);
		xhtml = tmp;
	}

	if (chat->xhtml && !jabber_xhtml_plain_equal(xhtml, jm->body))
		/* Wrap the message in <p/> for greater interoperability justice. */
		jm->xhtml = g_strdup_printf("<html xmlns='" NS_XHTML_IM "'><body xmlns='" NS_XHTML "'><p>%s</p></body></html>", xhtml);

	g_free(xhtml);

	jabber_message_send(jm);
	jabber_message_free(jm);

	return 1;
}

unsigned int jabber_send_typing(PurpleConnection *gc, const char *who, PurpleTypingState state)
{
	JabberStream *js;
	JabberMessage *jm;
	JabberBuddy *jb;
	JabberBuddyResource *jbr;
	char *resource;

	js = purple_connection_get_protocol_data(gc);
	jb = jabber_buddy_find(js, who, TRUE);
	if (!jb)
		return 0;

	resource = jabber_get_resource(who);
	jbr = jabber_buddy_find_resource(jb, resource);
	g_free(resource);

	/* We know this entity doesn't support chat states */
	if (jbr && jbr->chat_states == JABBER_CHAT_STATES_UNSUPPORTED)
		return 0;

	/* *If* we don't have presence /and/ the buddy can't see our
	 * presence, don't send typing notifications.
	 */
	if (!jbr && !(jb->subscription & JABBER_SUB_FROM))
		return 0;

	/* TODO: figure out threading */
	jm = g_new0(JabberMessage, 1);
	jm->js = js;
	jm->type = JABBER_MESSAGE_CHAT;
	jm->to = g_strdup(who);
	jm->id = jabber_get_next_id(jm->js);

	if(PURPLE_TYPING == state)
		jm->chat_state = JM_STATE_COMPOSING;
	else if(PURPLE_TYPED == state)
		jm->chat_state = JM_STATE_PAUSED;
	else
		jm->chat_state = JM_STATE_ACTIVE;

	/* if(JABBER_CHAT_STATES_UNKNOWN == jbr->chat_states)
		jbr->chat_states = JABBER_CHAT_STATES_UNSUPPORTED; */

	jabber_message_send(jm);
	jabber_message_free(jm);

	return 0;
}

gboolean jabber_buzz_isenabled(JabberStream *js, const gchar *namespace) {
	return js->allowBuzz;
}

gboolean jabber_custom_smileys_isenabled(JabberStream *js, const gchar *namespace)
{
	const PurpleConnection *gc = js->gc;
	PurpleAccount *account = purple_connection_get_account(gc);

	return purple_account_get_bool(account, "custom_smileys", TRUE);
}
