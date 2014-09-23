#include <string.h>

#include "tests.h"
#include "../util.h"
#include "../protocols/jabber/auth_scram.h"
#include "../protocols/jabber/jutil.h"

static JabberScramHash sha1_mech = { "-SHA-1", "sha1", 20 };

#define assert_pbkdf2_equal(password, salt, count, expected) { \
	GString *p = g_string_new(password); \
	GString *s = g_string_new(salt); \
	guchar *result = jabber_scram_hi(&sha1_mech, p, s, count); \
	fail_if(result == NULL, "Hi() returned NULL"); \
	fail_if(0 != memcmp(result, expected, 20), "Hi() returned invalid result"); \
	g_string_free(s, TRUE); \
	g_string_free(p, TRUE); \
}

START_TEST(test_pbkdf2)
{
	assert_pbkdf2_equal("password", "salt", 1, "\x0c\x60\xc8\x0f\x96\x1f\x0e\x71\xf3\xa9\xb5\x24\xaf\x60\x12\x06\x2f\xe0\x37\xa6");
	assert_pbkdf2_equal("password", "salt", 2, "\xea\x6c\x01\x4d\xc7\x2d\x6f\x8c\xcd\x1e\xd9\x2a\xce\x1d\x41\xf0\xd8\xde\x89\x57");
	assert_pbkdf2_equal("password", "salt", 4096, "\x4b\x00\x79\x01\xb7\x65\x48\x9a\xbe\xad\x49\xd9\x26\xf7\x21\xd0\x65\xa4\x29\xc1");

#if 0
	/* This causes libcheck to time out :-D */
	assert_pbkdf2_equal("password", "salt", 16777216, "\xee\xfe\x3d\x61\xcd\x4d\xa4\xe4\xe9\x94\x5b\x3d\x6b\xa2\x15\x8c\x26\x34\xe9\x84");
#endif
}
END_TEST

START_TEST(test_proofs)
{
	JabberScramData *data = g_new0(JabberScramData, 1);
	gboolean ret;
	GString *salt;
	const char *client_proof;
/*	const char *server_signature; */

	data->hash = &sha1_mech;
	data->password = g_strdup("password");
	data->auth_message = g_string_new("n=username@jabber.org,r=8jLxB5515dhFxBil5A0xSXMH,"
			"r=8jLxB5515dhFxBil5A0xSXMHabc,s=c2FsdA==,i=1,"
			"c=biws,r=8jLxB5515dhFxBil5A0xSXMHabc");
	client_proof = "\x48\x61\x30\xa5\x61\x0b\xae\xb9\xe4\x11\xa8\xfd\xa5\xcd\x34\x1d\x8a\x3c\x28\x17";

	salt = g_string_new("salt");
	ret = jabber_scram_calc_proofs(data, salt, 1);
	fail_if(ret == FALSE, "Failed to calculate SCRAM proofs!");

	fail_unless(0 == memcmp(client_proof, data->client_proof->str, 20));
	g_string_free(salt, TRUE);

	jabber_scram_data_destroy(data);
}
END_TEST

#define assert_successful_exchange(pw, nonce, start_data, challenge1, response1, success) { \
	JabberScramData *data = g_new0(JabberScramData, 1); \
	gboolean ret; \
	gchar *out; \
	\
	data->step = 1; \
	data->hash = &sha1_mech; \
	data->password = jabber_saslprep(pw); \
	fail_if(data->password == NULL); \
	data->cnonce = g_strdup(nonce); \
	data->auth_message = g_string_new(start_data); \
	\
	ret = jabber_scram_feed_parser(data, challenge1, &out); \
	fail_unless(ret == TRUE); \
	fail_unless(g_str_equal(out, response1), "Got unexpected response to challenge. Expected %s, got %s", response1, out); \
	g_free(out); \
	\
	data->step = 2; \
	ret = jabber_scram_feed_parser(data, success, &out); \
	fail_unless(ret == TRUE); \
	fail_unless(out == NULL); \
	\
	jabber_scram_data_destroy(data); \
}

START_TEST(test_mech)
{
	assert_successful_exchange("password", "H7yDYKAWBCrM2Fa5SxGa4iez",
			"n=paul,r=H7yDYKAWBCrM2Fa5SxGa4iez",
			"r=H7yDYKAWBCrM2Fa5SxGa4iezFPVDPpDUcGxPkH3RzP,s=3rXeErP/os7jUNqU,i=4096",
			"c=biws,r=H7yDYKAWBCrM2Fa5SxGa4iezFPVDPpDUcGxPkH3RzP,p=pXkak78EuwwOEwk2/h/OzD7NkEI=",
			"v=ldX4EBNnOgDnNTOCmbSfBHAUCOs=");

#ifdef USE_IDN
	assert_successful_exchange("pass½word", "GNb2HsNI7VnTv8ABsE5AnY8W",
			"n=paul,r=GNb2HsNI7VnTv8ABsE5AnY8W",
			"r=GNb2HsNI7VnTv8ABsE5AnY8W/w/I3eRKM0I7jxFWOH,s=ysAriUjPzFqOXnMQ,i=4096",
			"c=biws,r=GNb2HsNI7VnTv8ABsE5AnY8W/w/I3eRKM0I7jxFWOH,p=n/CtgdWjOYnLQ4m9Na+wPn9D2uY=",
			"v=4TkZwKWy6JHNmrUbU2+IdAaXtos=");
#endif
}
END_TEST

Suite *
jabber_scram_suite(void)
{
	Suite *s = suite_create("Jabber SASL SCRAM functions");

	TCase *tc = tcase_create("PBKDF2 Functionality");
	tcase_add_test(tc, test_pbkdf2);
	suite_add_tcase(s, tc);

	tc = tcase_create("SCRAM Proofs");
	tcase_add_test(tc, test_proofs);
	suite_add_tcase(s, tc);

	tc = tcase_create("SCRAM exchange");
	tcase_add_test(tc, test_mech);
	suite_add_tcase(s, tc);
	return s;
}
