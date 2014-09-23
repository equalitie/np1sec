#include <string.h>

#include "tests.h"
#include "../xmlnode.h"
#include "../protocols/jabber/caps.h"

START_TEST(test_parse_invalid)
{
	xmlnode *query;

	fail_unless(NULL == jabber_caps_parse_client_info(NULL));

	/* Something other than a disco#info query */
	query = xmlnode_new("foo");
	fail_unless(NULL == jabber_caps_parse_client_info(query));
	xmlnode_free(query);

	query = xmlnode_new("query");
	fail_unless(NULL == jabber_caps_parse_client_info(query));
	xmlnode_set_namespace(query, "jabber:iq:last");
	fail_unless(NULL == jabber_caps_parse_client_info(query));
	xmlnode_free(query);
}
END_TEST

#define assert_caps_calculate_match(hash_func, hash, str) { \
	xmlnode *query = xmlnode_from_str((str), -1); \
	JabberCapsClientInfo *info = jabber_caps_parse_client_info(query); \
	gchar *got_hash = jabber_caps_calculate_hash(info, (hash_func)); \
	assert_string_equal_free((hash), got_hash); \
}

START_TEST(test_calculate_caps)
{
	assert_caps_calculate_match("sha1", "GNjxthSckUNvAIoCCJFttjl6VL8=",
	"<query xmlns='http://jabber.org/protocol/disco#info' node='http://tkabber.jabber.ru/#GNjxthSckUNvAIoCCJFttjl6VL8='><identity category='client' type='pc' name='Tkabber'/><x xmlns='jabber:x:data' type='result'><field var='FORM_TYPE' type='hidden'><value>urn:xmpp:dataforms:softwareinfo</value></field><field var='software'><value>Tkabber</value></field><field var='software_version'><value> ( 8.5.5 )</value></field><field var='os'><value>ATmega640-16AU</value></field><field var='os_version'><value/></field></x><feature var='games:board'/><feature var='google:mail:notify'/><feature var='http://jabber.org/protocol/activity'/><feature var='http://jabber.org/protocol/bytestreams'/><feature var='http://jabber.org/protocol/chatstates'/><feature var='http://jabber.org/protocol/commands'/><feature var='http://jabber.org/protocol/commands'/><feature var='http://jabber.org/protocol/disco#info'/><feature var='http://jabber.org/protocol/disco#items'/><feature var='http://jabber.org/protocol/feature-neg'/><feature var='http://jabber.org/protocol/geoloc'/><feature var='http://jabber.org/protocol/ibb'/><feature var='http://jabber.org/protocol/iqibb'/><feature var='http://jabber.org/protocol/mood'/><feature var='http://jabber.org/protocol/muc'/><feature var='http://jabber.org/protocol/mute#ancestor'/><feature var='http://jabber.org/protocol/mute#editor'/><feature var='http://jabber.org/protocol/rosterx'/><feature var='http://jabber.org/protocol/si'/><feature var='http://jabber.org/protocol/si/profile/file-transfer'/><feature var='http://jabber.org/protocol/tune'/><feature var='jabber:iq:avatar'/><feature var='jabber:iq:browse'/><feature var='jabber:iq:dtcp'/><feature var='jabber:iq:filexfer'/><feature var='jabber:iq:ibb'/><feature var='jabber:iq:inband'/><feature var='jabber:iq:jidlink'/><feature var='jabber:iq:last'/><feature var='jabber:iq:oob'/><feature var='jabber:iq:privacy'/><feature var='jabber:iq:time'/><feature var='jabber:iq:version'/><feature var='jabber:x:data'/><feature var='jabber:x:event'/><feature var='jabber:x:oob'/><feature var='urn:xmpp:ping'/><feature var='urn:xmpp:receipts'/><feature var='urn:xmpp:time'/></query>");
}
END_TEST

Suite *
jabber_caps_suite(void)
{
	Suite *s = suite_create("Jabber Caps Functions");

	TCase *tc = tcase_create("Parsing invalid ndoes");
	tcase_add_test(tc, test_parse_invalid);
	suite_add_tcase(s, tc);

	tc = tcase_create("Calculating from XMLnode");
	tcase_add_test(tc, test_calculate_caps);
	suite_add_tcase(s, tc);

	return s;
}
