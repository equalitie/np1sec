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

#include "usermood.h"
#include "pep.h"
#include <string.h>
#include "internal.h"
#include "request.h"
#include "debug.h"

static PurpleMood moods[] = {
	{"afraid", N_("Afraid"), NULL},
	{"amazed", N_("Amazed"), NULL},
	{"amorous", N_("Amorous"), NULL},
	{"angry", N_("Angry"), NULL},
	{"annoyed", N_("Annoyed"), NULL},
	{"anxious", N_("Anxious"), NULL},
	{"aroused", N_("Aroused"), NULL},
	{"ashamed", N_("Ashamed"), NULL},
	{"bored", N_("Bored"), NULL},
	{"brave", N_("Brave"), NULL},
	{"calm", N_("Calm"), NULL},
	{"cautious", N_("Cautious"), NULL},
	{"cold", N_("Cold"), NULL},
	{"confident", N_("Confident"), NULL},
	{"confused", N_("Confused"), NULL},
	{"contemplative", N_("Contemplative"), NULL},
	{"contented", N_("Contented"), NULL},
	{"cranky", N_("Cranky"), NULL},
	{"crazy", N_("Crazy"), NULL},
	{"creative", N_("Creative"), NULL},
	{"curious", N_("Curious"), NULL},
	{"dejected", N_("Dejected"), NULL},
	{"depressed", N_("Depressed"), NULL},
	{"disappointed", N_("Disappointed"), NULL},
	{"disgusted", N_("Disgusted"), NULL},
	{"dismayed", N_("Dismayed"), NULL},
	{"distracted", N_("Distracted"), NULL},
	{"embarrassed", N_("Embarrassed"), NULL},
	{"envious", N_("Envious"), NULL},
	{"excited", N_("Excited"), NULL},
	{"flirtatious", N_("Flirtatious"), NULL},
	{"frustrated", N_("Frustrated"), NULL},
	{"grateful", N_("Grateful"), NULL},
	{"grieving", N_("Grieving"), NULL},
	{"grumpy", N_("Grumpy"), NULL},
	{"guilty", N_("Guilty"), NULL},
	{"happy", N_("Happy"), NULL},
	{"hopeful", N_("Hopeful"), NULL},
	{"hot", N_("Hot"), NULL},
	{"humbled", N_("Humbled"), NULL},
	{"humiliated", N_("Humiliated"), NULL},
	{"hungry", N_("Hungry"), NULL},
	{"hurt", N_("Hurt"), NULL},
	{"impressed", N_("Impressed"), NULL},
	{"in_awe", N_("In awe"), NULL},
	{"in_love", N_("In love"), NULL},
	{"indignant", N_("Indignant"), NULL},
	{"interested", N_("Interested"), NULL},
	{"intoxicated", N_("Intoxicated"), NULL},
	{"invincible", N_("Invincible"), NULL},
	{"jealous", N_("Jealous"), NULL},
	{"lonely", N_("Lonely"), NULL},
	{"lost", N_("Lost"), NULL},
	{"lucky", N_("Lucky"), NULL},
	{"mean", N_("Mean"), NULL},
	{"moody", N_("Moody"), NULL},
	{"nervous", N_("Nervous"), NULL},
	{"neutral", N_("Neutral"), NULL},
	{"offended", N_("Offended"), NULL},
	{"outraged", N_("Outraged"), NULL},
	{"playful", N_("Playful"), NULL},
	{"proud", N_("Proud"), NULL},
	{"relaxed", N_("Relaxed"), NULL},
	{"relieved", N_("Relieved"), NULL},
	{"remorseful", N_("Remorseful"), NULL},
	{"restless", N_("Restless"), NULL},
	{"sad", N_("Sad"), NULL},
	{"sarcastic", N_("Sarcastic"), NULL},
	{"satisfied", N_("Satisfied"), NULL},
	{"serious", N_("Serious"), NULL},
	{"shocked", N_("Shocked"), NULL},
	{"shy", N_("Shy"), NULL},
	{"sick", N_("Sick"), NULL},
	{"sleepy", N_("Sleepy"), NULL},
	{"spontaneous", N_("Spontaneous"), NULL},
	{"stressed", N_("Stressed"), NULL},
	{"strong", N_("Strong"), NULL},
	{"surprised", N_("Surprised"), NULL},
	{"thankful", N_("Thankful"), NULL},
	{"thirsty", N_("Thirsty"), NULL},
	{"tired", N_("Tired"), NULL},
	{"undefined", N_("Undefined"), NULL},
	{"weak", N_("Weak"), NULL},
	{"worried", N_("Worried"), NULL},
	/* Mark the last record. */
	{NULL, NULL, NULL}
};

static void jabber_mood_cb(JabberStream *js, const char *from, xmlnode *items) {
	/* it doesn't make sense to have more than one item here, so let's just pick the first one */
	xmlnode *item = xmlnode_get_child(items, "item");
	const char *newmood = NULL;
	char *moodtext = NULL;
	JabberBuddy *buddy = jabber_buddy_find(js, from, FALSE);
	xmlnode *moodinfo, *mood;
	/* ignore the mood of people not on our buddy list */
	if (!buddy || !item)
		return;

	mood = xmlnode_get_child_with_namespace(item, "mood", "http://jabber.org/protocol/mood");
	if (!mood)
		return;
	for (moodinfo = mood->child; moodinfo; moodinfo = moodinfo->next) {
		if (moodinfo->type == XMLNODE_TYPE_TAG) {
			if (!strcmp(moodinfo->name, "text")) {
				if (!moodtext) /* only pick the first one */
					moodtext = xmlnode_get_data(moodinfo);
			} else {
				int i;
				for (i = 0; moods[i].mood; ++i) {
					/* verify that the mood is known (valid) */
					if (!strcmp(moodinfo->name, moods[i].mood)) {
						newmood = moods[i].mood;
						break;
					}
				}
			}
		}
		if (newmood != NULL && moodtext != NULL)
			break;
	}
	if (newmood != NULL) {
		purple_prpl_got_user_status(js->gc->account, from, "mood",
				PURPLE_MOOD_NAME, newmood,
				PURPLE_MOOD_COMMENT, moodtext,
				NULL);
	} else {
		purple_prpl_got_user_status_deactive(js->gc->account, from, "mood");
	}
	g_free(moodtext);
}

void jabber_mood_init(void) {
	jabber_add_feature("http://jabber.org/protocol/mood", jabber_pep_namespace_only_when_pep_enabled_cb);
	jabber_pep_register_handler("http://jabber.org/protocol/mood", jabber_mood_cb);
}

void jabber_mood_set(JabberStream *js, const char *mood, const char *text) {
	xmlnode *publish, *moodnode;

	publish = xmlnode_new("publish");
	xmlnode_set_attrib(publish,"node","http://jabber.org/protocol/mood");
	moodnode = xmlnode_new_child(xmlnode_new_child(publish, "item"), "mood");
	xmlnode_set_namespace(moodnode, "http://jabber.org/protocol/mood");
	if (mood && *mood) {
		/* if mood is NULL, set an empty mood node, meaning: unset mood */
	    xmlnode_new_child(moodnode, mood);
	}

	if (text && *text) {
		xmlnode *textnode = xmlnode_new_child(moodnode, "text");
		xmlnode_insert_data(textnode, text, -1);
	}

	jabber_pep_publish(js, publish);
	/* publish is freed by jabber_pep_publish -> jabber_iq_send -> jabber_iq_free
	   (yay for well-defined memory management rules) */
}

PurpleMood *jabber_get_moods(PurpleAccount *account)
{
	return moods;
}
