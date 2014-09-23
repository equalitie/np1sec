#ifndef TESTS_H
#  define TESTS_H

#include "../purple.h"

#include <check.h>

/* define the test suites here */
/* remember to add the suite to the runner in check_libpurple.c */
Suite * master_suite(void);
Suite * cipher_suite(void);
Suite * jabber_caps_suite(void);
Suite * jabber_digest_md5_suite(void);
Suite * jabber_jutil_suite(void);
Suite * jabber_scram_suite(void);
Suite * oscar_util_suite(void);
Suite * yahoo_util_suite(void);
Suite * util_suite(void);
Suite * xmlnode_suite(void);

/* helper macros */
#define assert_int_equal(expected, actual) { \
	fail_if(expected != actual, "Expected '%d' but got '%d'", expected, actual); \
}

#define assert_string_equal(expected, actual) { \
	const gchar *a = actual; \
	fail_unless(strcmp(expected, a) == 0, "Expected '%s' but got '%s'", expected, a); \
}

#define assert_string_equal_free(expected, actual) { \
	gchar *b = actual; \
	assert_string_equal(expected, b); \
	g_free(b); \
}


#endif /* ifndef TESTS_H */

