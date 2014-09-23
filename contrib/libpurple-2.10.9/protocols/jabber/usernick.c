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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02111-1301  USA
 *
 */

#include "internal.h"

#include "usernick.h"
#include "pep.h"
#include <string.h>
#include "internal.h"
#include "request.h"
#include "status.h"

static void jabber_nick_cb(JabberStream *js, const char *from, xmlnode *items) {
	/* it doesn't make sense to have more than one item here, so let's just pick the first one */
	xmlnode *item = xmlnode_get_child(items, "item");
	JabberBuddy *buddy = jabber_buddy_find(js, from, FALSE);
	xmlnode *nick;
	char *nickname = NULL;

	/* ignore the nick of people not on our buddy list */
	if (!buddy || !item)
		return;

	nick = xmlnode_get_child_with_namespace(item, "nick", "http://jabber.org/protocol/nick");
	if (!nick)
		return;
	nickname = xmlnode_get_data(nick);
	serv_got_alias(js->gc, from, nickname);
	g_free(nickname);
}

static void do_nick_set(JabberStream *js, const char *nick) {
	xmlnode *publish, *nicknode;

	publish = xmlnode_new("publish");
	xmlnode_set_attrib(publish,"node","http://jabber.org/protocol/nick");
	nicknode = xmlnode_new_child(xmlnode_new_child(publish, "item"), "nick");
	xmlnode_set_namespace(nicknode, "http://jabber.org/protocol/nick");

	if(nick && nick[0] != '\0')
		xmlnode_insert_data(nicknode, nick, -1);

	jabber_pep_publish(js, publish);
	/* publish is freed by jabber_pep_publish -> jabber_iq_send -> jabber_iq_free
		(yay for well-defined memory management rules) */
}

static void do_nick_got_own_nick_cb(JabberStream *js, const char *from, xmlnode *items) {
	char *oldnickname = NULL;
	xmlnode *item = NULL;

	if (items)
		item = xmlnode_get_child(items,"item");

	if(item) {
		xmlnode *nick = xmlnode_get_child_with_namespace(item,"nick","http://jabber.org/protocol/nick");
		if(nick)
			oldnickname = xmlnode_get_data(nick);
	}

	purple_request_input(js->gc, _("Set User Nickname"), _("Please specify a new nickname for you."),
		_("This information is visible to all contacts on your contact list, so choose something appropriate."),
		oldnickname, FALSE, FALSE, NULL, _("Set"), PURPLE_CALLBACK(do_nick_set), _("Cancel"), NULL,
		purple_connection_get_account(js->gc), NULL, NULL, js);
	g_free(oldnickname);
}

static void do_nick_set_nick(PurplePluginAction *action) {
	PurpleConnection *gc = action->context;
	JabberStream *js = purple_connection_get_protocol_data(gc);

	/* since the nickname might have been changed by another resource of this account, we always have to request the old one
		from the server to present as the default for the new one */
	jabber_pep_request_item(js, NULL, "http://jabber.org/protocol/nick", NULL, do_nick_got_own_nick_cb);
}

void jabber_nick_init(void) {
	jabber_add_feature("http://jabber.org/protocol/nick", jabber_pep_namespace_only_when_pep_enabled_cb);
	jabber_pep_register_handler("http://jabber.org/protocol/nick", jabber_nick_cb);
}

void jabber_nick_init_action(GList **m) {
	PurplePluginAction *act = purple_plugin_action_new(_("Set Nickname..."), do_nick_set_nick);
	*m = g_list_append(*m, act);
}
