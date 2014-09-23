#include <string.h>

#include "tests.h"
#include "../xmlnode.h"

/*
 * If we really wanted to test the billion laughs attack we would
 * need to have more than just 4 ha's.  But as long as this shorter
 * document fails to parse, the longer one should also fail to parse.
 */
START_TEST(test_xmlnode_billion_laughs_attack)
{
	const char *malicious_xml_doc = "<!DOCTYPE root [ <!ENTITY ha \"Ha !\"><!ENTITY ha2 \"&ha; &ha;\"><!ENTITY ha3 \"&ha2; &ha2;\"> ]><root>&ha3;</root>";

	/* Uncomment this line if you want to see the error message given by
	   the parser for the above XML document */
	/* purple_debug_set_enabled(TRUE); */

	fail_if(xmlnode_from_str(malicious_xml_doc, -1),
			"xmlnode_from_str() returned an XML tree, but we didn't want it to");
}
END_TEST

Suite *
xmlnode_suite(void)
{
	Suite *s = suite_create("Utility Functions");

	TCase *tc = tcase_create("xmlnode");
	tcase_add_test(tc, test_xmlnode_billion_laughs_attack);
	suite_add_tcase(s, tc);

	return s;
}
