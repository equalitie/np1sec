#include <string.h>

#include "tests.h"
#include "../account.h"
#include "../conversation.h"
#include "../xmlnode.h"
#include "../protocols/jabber/jutil.h"

START_TEST(test_get_resource)
{
	assert_string_equal_free("baz", jabber_get_resource("foo@bar/baz"));
	assert_string_equal_free("baz", jabber_get_resource("bar/baz"));
	assert_string_equal_free("baz/bat", jabber_get_resource("foo@bar/baz/bat"));
	assert_string_equal_free("baz/bat", jabber_get_resource("bar/baz/bat"));
}
END_TEST

START_TEST(test_get_resource_no_resource)
{

	fail_unless(NULL == jabber_get_resource("foo@bar"));
	fail_unless(NULL == jabber_get_resource("bar"));
}
END_TEST

START_TEST(test_get_bare_jid)
{
	assert_string_equal_free("foo@bar", jabber_get_bare_jid("foo@bar"));
	assert_string_equal_free("foo@bar", jabber_get_bare_jid("foo@bar/baz"));
	assert_string_equal_free("bar", jabber_get_bare_jid("bar"));
	assert_string_equal_free("bar", jabber_get_bare_jid("bar/baz"));
}
END_TEST

START_TEST(test_nodeprep_validate)
{
	char *longnode;

	fail_unless(jabber_nodeprep_validate(NULL));
	fail_unless(jabber_nodeprep_validate("foo"));
	fail_unless(jabber_nodeprep_validate("%d"));
	fail_unless(jabber_nodeprep_validate("y\\z"));
	fail_unless(jabber_nodeprep_validate("a="));
	fail_unless(jabber_nodeprep_validate("a,"));

	longnode = g_strnfill(1023, 'a');
	fail_unless(jabber_nodeprep_validate(longnode));
	g_free(longnode);

	longnode = g_strnfill(1024, 'a');
	fail_if(jabber_nodeprep_validate(longnode));
	g_free(longnode);
}
END_TEST

START_TEST(test_nodeprep_validate_illegal_chars)
{
	fail_if(jabber_nodeprep_validate("don't"));
	fail_if(jabber_nodeprep_validate("m@ke"));
	fail_if(jabber_nodeprep_validate("\"me\""));
	fail_if(jabber_nodeprep_validate("&ngry"));
	fail_if(jabber_nodeprep_validate("c:"));
	fail_if(jabber_nodeprep_validate("a/b"));
	fail_if(jabber_nodeprep_validate("4>2"));
	fail_if(jabber_nodeprep_validate("4<7"));
}
END_TEST

START_TEST(test_nodeprep_validate_too_long)
{
	char *longnode = g_strnfill(1024, 'a');
	fail_if(jabber_nodeprep_validate(longnode));
	g_free(longnode);
}
END_TEST

#define assert_valid_jid(str) { \
	JabberID *jid = jabber_id_new(str); \
	fail_if(jid == NULL, "JID '%s' is valid but jabber_id_new() rejected it", str); \
	jabber_id_free(jid); \
}

#define assert_invalid_jid(str) { \
	JabberID *jid = jabber_id_new(str); \
	fail_if(jid != NULL, "JID '%s' is invalid but jabber_id_new() allowed it", str); \
	jabber_id_free(jid); \
}

#define assert_jid_parts(expect_node, expect_domain, str) { \
	JabberID *jid = jabber_id_new(str); \
	fail_if(jid == NULL, "JID '%s' is valid but jabber_id_new() rejected it", str); \
	fail_if(jid->node == NULL,     "JID '%s' is valid but jabber_id_new() didn't return a node", str); \
	fail_if(jid->domain == NULL,   "JID '%s' is valid but jabber_id_new() didn't return a domain", str); \
	fail_if(jid->resource != NULL, "JID '%s' doesn't contain a resource", str); \
	assert_string_equal(expect_node, jid->node); \
	assert_string_equal(expect_domain, jid->domain); \
	jabber_id_free(jid); \
}

START_TEST(test_jabber_id_new)
{
	assert_valid_jid("gmail.com");
	assert_valid_jid("gmail.com/Test");
	assert_valid_jid("gmail.com/Test@");
	assert_valid_jid("gmail.com/@");
	assert_valid_jid("gmail.com/Test@alkjaweflkj");
	assert_valid_jid("mark.doliner@gmail.com");
	assert_valid_jid("mark.doliner@gmail.com/Test12345");
	assert_valid_jid("mark.doliner@gmail.com/Test@12345");
	assert_valid_jid("mark.doliner@gmail.com/Te/st@12@//345");
	assert_valid_jid("わいど@conference.jabber.org");
	assert_valid_jid("まりるーむ@conference.jabber.org");
	assert_valid_jid("mark.doliner@gmail.com/まりるーむ");
	assert_valid_jid("mark.doliner@gmail/stuff.org");
	assert_valid_jid("stuart@nödåtXäYZ.se");
	assert_valid_jid("stuart@nödåtXäYZ.se/まりるーむ");
	assert_valid_jid("mark.doliner@わいど.org");
	assert_valid_jid("nick@まつ.おおかみ.net");
	assert_valid_jid("paul@10.0.42.230/s");
	assert_valid_jid("paul@[::1]"); /* IPv6 */
	assert_valid_jid("paul@[2001:470:1f05:d58::2]");
	assert_valid_jid("paul@[2001:470:1f05:d58::2]/foo");
	assert_valid_jid("pa=ul@10.0.42.230");
	assert_valid_jid("pa,ul@10.0.42.230");

	assert_invalid_jid("@gmail.com");
	assert_invalid_jid("@@gmail.com");
	assert_invalid_jid("mark.doliner@@gmail.com/Test12345");
	assert_invalid_jid("mark@doliner@gmail.com/Test12345");
	assert_invalid_jid("@gmail.com/Test@12345");
	assert_invalid_jid("/Test@12345");
	assert_invalid_jid("mark.doliner@");
	assert_invalid_jid("mark.doliner/");
	assert_invalid_jid("mark.doliner@gmail_stuff.org");
	assert_invalid_jid("mark.doliner@gmail[stuff.org");
	assert_invalid_jid("mark.doliner@gmail\\stuff.org");
	assert_invalid_jid("paul@[::1]124");
	assert_invalid_jid("paul@2[::1]124/as");
	assert_invalid_jid("paul@まつ.おおかみ/\x01");

	/*
	 * RFC 3454 Section 6 reads, in part,
	 * "If a string contains any RandALCat character, the
	 *  string MUST NOT contain any LCat character."
	 * The character is U+066D (ARABIC FIVE POINTED STAR).
	 */
	assert_invalid_jid("foo@example.com/٭simplexe٭");

	/* Ensure that jabber_id_new is properly lowercasing node and domains */
	assert_jid_parts("paul", "darkrain42.org", "PaUL@darkrain42.org");
	assert_jid_parts("paul", "darkrain42.org", "paul@DaRkRaIn42.org");

	/* These case-mapping tests culled from examining RFC3454 B.2 */

	/* Cyrillic capital EF (U+0424) maps to lowercase EF (U+0444) */
	assert_jid_parts("ф", "darkrain42.org", "Ф@darkrain42.org");

#ifdef USE_IDN
	/*
	 * These character (U+A664 and U+A665) are not mapped to anything in
	 * RFC3454 B.2. This first test *fails* when not using IDN because glib's
	 * case-folding/utf8_strdown improperly (for XMPP) lowercases the character.
	 *
	 * This is known, but not (very?) likely to actually cause a problem, so
	 * this test is commented out when using glib's functions.
	 */
	assert_jid_parts("Ꙥ", "darkrain42.org", "Ꙥ@darkrain42.org");
	assert_jid_parts("ꙥ", "darkrain42.org", "ꙥ@darkrain42.org");
#endif

	/* U+04E9 to U+04E9 */
	assert_jid_parts("paul", "өarkrain42.org", "paul@Өarkrain42.org");
}
END_TEST

START_TEST(test_jabber_normalize)
{
	assert_string_equal("paul@darkrain42.org", jabber_normalize(NULL, "PaUL@DaRkRain42.org"));
	assert_string_equal("paul@darkrain42.org", jabber_normalize(NULL, "PaUL@DaRkRain42.org/"));
	assert_string_equal("paul@darkrain42.org", jabber_normalize(NULL, "PaUL@DaRkRain42.org/resource"));
}
END_TEST

Suite *
jabber_jutil_suite(void)
{
	Suite *s = suite_create("Jabber Utility Functions");

	TCase *tc = tcase_create("Get Resource");
	tcase_add_test(tc, test_get_resource);
	tcase_add_test(tc, test_get_resource_no_resource);
	suite_add_tcase(s, tc);

	tc = tcase_create("Get Bare JID");
	tcase_add_test(tc, test_get_bare_jid);
	suite_add_tcase(s, tc);

	tc = tcase_create("JID validate");
	tcase_add_test(tc, test_nodeprep_validate);
	tcase_add_test(tc, test_nodeprep_validate_illegal_chars);
	tcase_add_test(tc, test_nodeprep_validate_too_long);
	tcase_add_test(tc, test_jabber_id_new);
	tcase_add_test(tc, test_jabber_normalize);
	suite_add_tcase(s, tc);

	return s;
}
