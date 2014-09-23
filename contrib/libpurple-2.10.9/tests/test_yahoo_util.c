#include <string.h>

#include "tests.h"
#include "../protocols/yahoo/libymsg.h"

static void setup_codes_to_html(void)
{
	yahoo_init_colorht();
}

static void teardown_codes_to_html(void)
{
	yahoo_dest_colorht();
}

START_TEST(test_codes_to_html)
{
	assert_string_equal_free("",
			yahoo_codes_to_html(""));
	assert_string_equal_free("",
			yahoo_codes_to_html("\x1B[12345m"));
	assert_string_equal_free("plain",
			yahoo_codes_to_html("plain"));
	assert_string_equal_free("unknown  ansi code",
			yahoo_codes_to_html("unknown \x1B[12345m ansi code"));
	assert_string_equal_free("plain &lt;peanut&gt;",
			yahoo_codes_to_html("plain <peanut>"));
	assert_string_equal_free("plain &lt;peanut",
			yahoo_codes_to_html("plain <peanut"));
	assert_string_equal_free("plain&gt; peanut",
			yahoo_codes_to_html("plain> peanut"));
	assert_string_equal_free("<font face='inva&gt;lid'>test</font>",
			yahoo_codes_to_html("<font face='inva>lid'>test"));
	assert_string_equal_free("&lt;font face=&apos;inva&gt;lid",
			yahoo_codes_to_html("<font face='inva>lid"));

	/* bold/italic/underline */
	assert_string_equal_free("<b>bold</b>",
			yahoo_codes_to_html("\x1B[1mbold"));
	assert_string_equal_free("<i>italic</i>",
			yahoo_codes_to_html("\x1B[2mitalic"));
	assert_string_equal_free("<u>underline</u>",
			yahoo_codes_to_html("\x1B[4munderline"));
	assert_string_equal_free("no markup",
			yahoo_codes_to_html("no\x1B[x4m markup"));
	assert_string_equal_free("<b>bold</b> <i>italic</i> <u>underline</u>",
			yahoo_codes_to_html("\x1B[1mbold\x1B[x1m \x1B[2mitalic\x1B[x2m \x1B[4munderline"));
	assert_string_equal_free("<b>bold <i>bolditalic</i></b><i> italic</i>",
			yahoo_codes_to_html("\x1B[1mbold \x1B[2mbolditalic\x1B[x1m italic"));
	assert_string_equal_free("<b>bold <i>bolditalic</i></b><i> <u>italicunderline</u></i>",
			yahoo_codes_to_html("\x1B[1mbold \x1B[2mbolditalic\x1B[x1m \x1B[4mitalicunderline"));
	assert_string_equal_free("<b>bold <i>bolditalic <u>bolditalicunderline</u></i><u> boldunderline</u></b>",
			yahoo_codes_to_html("\x1B[1mbold \x1B[2mbolditalic \x1B[4mbolditalicunderline\x1B[x2m boldunderline"));
	assert_string_equal_free("<b>bold <i>bolditalic <u>bolditalicunderline</u></i></b><i><u> italicunderline</u></i>",
			yahoo_codes_to_html("\x1B[1mbold \x1B[2mbolditalic \x1B[4mbolditalicunderline\x1B[x1m italicunderline"));

	/* link */
	assert_string_equal_free("http://pidgin.im/",
			yahoo_codes_to_html("\x1B[lmhttp://pidgin.im/\x1B[xlm"));

#ifdef USE_CSS_FORMATTING
	/* font color */
	assert_string_equal_free("<span style='color: #0000FF'>blue</span>",
			yahoo_codes_to_html("\x1B[31mblue"));
	assert_string_equal_free("<span style='color: #70ea15'>custom color</span>",
			yahoo_codes_to_html("\x1B[#70ea15mcustom color"));

	/* font face */
	assert_string_equal_free("<font face='Georgia'>test</font>",
			yahoo_codes_to_html("<font face='Georgia'>test</font>"));

	/* font size */
	assert_string_equal_free("<font><span style='font-size: 15pt'>test</span></font>",
			yahoo_codes_to_html("<font size='15'>test"));
	assert_string_equal_free("<font><span style='font-size: 32pt'>size 32</span></font>",
			yahoo_codes_to_html("<font size='32'>size 32"));

	/* combinations */
	assert_string_equal_free("<font face='Georgia'><span style='font-size: 32pt'>test</span></font>",
			yahoo_codes_to_html("<font face='Georgia' size='32'>test"));
	assert_string_equal_free("<span style='color: #FF0080'><font><span style='font-size: 15pt'>test</span></font></span>",
			yahoo_codes_to_html("\x1B[35m<font size='15'>test"));
#else
	/* font color */
	assert_string_equal_free("<font color='#0000FF'>blue</font>",
			yahoo_codes_to_html("\x1B[31mblue"));
	assert_string_equal_free("<font color='#70ea15'>custom color</font>",
			yahoo_codes_to_html("\x1B[#70ea15mcustom color"));
	assert_string_equal_free("test",
			yahoo_codes_to_html("<ALT #ff0000,#00ff00,#0000ff>test</ALT>"));

	/* font face */
	assert_string_equal_free("<font face='Georgia'>test</font>",
			yahoo_codes_to_html("<font face='Georgia'>test"));

	/* font size */
	assert_string_equal_free("<font size='4' absz='15'>test</font>",
			yahoo_codes_to_html("<font size='15'>test"));
	assert_string_equal_free("<font size='6' absz='32'>size 32</font>",
			yahoo_codes_to_html("<font size='32'>size 32"));

	/* combinations */
	assert_string_equal_free("<font face='Georgia' size='6' absz='32'>test</font>",
			yahoo_codes_to_html("<font face='Georgia' size='32'>test"));
	assert_string_equal_free("<font color='#FF0080'><font size='4' absz='15'>test</font></font>",
			yahoo_codes_to_html("\x1B[35m<font size='15'>test"));
	assert_string_equal_free(":&lt;",
			yahoo_codes_to_html("<FADE #ff0000,#00ff00,#0000ff>:<</FADE>"));
#endif /* !USE_CSS_FORMATTING */
}
END_TEST

START_TEST(test_html_to_codes)
{
	assert_string_equal_free("plain",
			yahoo_html_to_codes("plain"));
	assert_string_equal_free("plain <peanut>",
			yahoo_html_to_codes("plain &lt;peanut&gt;"));
	assert_string_equal_free("plain <peanut",
			yahoo_html_to_codes("plain &lt;peanut"));
	assert_string_equal_free("plain> peanut",
			yahoo_html_to_codes("plain&gt; peanut"));
	assert_string_equal_free("plain >",
			yahoo_html_to_codes("plain &gt;"));
	assert_string_equal_free("plain > ",
			yahoo_html_to_codes("plain &gt; "));
	assert_string_equal_free("plain <",
			yahoo_html_to_codes("plain &lt;"));
	assert_string_equal_free("plain < ",
			yahoo_html_to_codes("plain &lt; "));
	assert_string_equal_free("plain &lt",
			yahoo_html_to_codes("plain &lt"));
	assert_string_equal_free("plain &",
			yahoo_html_to_codes("plain &amp;"));

	/* bold/italic/underline */
	assert_string_equal_free("\x1B[1mbold\x1B[x1m",
			yahoo_html_to_codes("<b>bold</b>"));
	assert_string_equal_free("\x1B[2mitalic\x1B[x2m",
			yahoo_html_to_codes("<i>italic</i>"));
	assert_string_equal_free("\x1B[4munderline\x1B[x4m",
			yahoo_html_to_codes("<u>underline</u>"));
	assert_string_equal_free("no markup",
			yahoo_html_to_codes("no</u> markup"));
	assert_string_equal_free("\x1B[1mbold\x1B[x1m \x1B[2mitalic\x1B[x2m \x1B[4munderline\x1B[x4m",
			yahoo_html_to_codes("<b>bold</b> <i>italic</i> <u>underline</u>"));
	assert_string_equal_free("\x1B[1mbold \x1B[2mbolditalic\x1B[x2m\x1B[x1m\x1B[2m italic\x1B[x2m",
			yahoo_html_to_codes("<b>bold <i>bolditalic</i></b><i> italic</i>"));
	assert_string_equal_free("\x1B[1mbold \x1B[2mbolditalic\x1B[x2m\x1B[x1m\x1B[2m \x1B[4mitalicunderline\x1B[x4m\x1B[x2m",
			yahoo_html_to_codes("<b>bold <i>bolditalic</i></b><i> <u>italicunderline</u></i>"));

	/* link */
	assert_string_equal_free("http://pidgin.im/",
			yahoo_html_to_codes("<A HREF=\"http://pidgin.im/\">http://pidgin.im/</A>"));
	assert_string_equal_free("mark@example.com",
			yahoo_html_to_codes("<A HREF=\"mailto:mark@example.com\">mark@example.com</A>"));
#if 0
	assert_string_equal_free("Pidgin (http://pidgin.im/)",
			yahoo_html_to_codes("<A HREF=\"http://pidgin.im/\">Pidgin</A>"));
#endif

	/* font nothing */
	assert_string_equal_free("nothing",
			yahoo_html_to_codes("<font>nothing</font>"));

	/* font color */
	assert_string_equal_free("\x1B[#E71414mred\x1B[#000000m",
			yahoo_html_to_codes("<font color=\"#E71414\">red</font>"));
	assert_string_equal_free("\x1B[#FF0000mred\x1B[#000000m \x1B[#0000FFmblue\x1B[#000000m black",
			yahoo_html_to_codes("<font color=\"#FF0000\">red</font> <font color=\"#0000FF\">blue</font> black"));

	/* font size */
	assert_string_equal_free("<font size=\"10\">test</font>",
			yahoo_html_to_codes("<font size=\"2\">test</font>"));
	assert_string_equal_free("<font size=\"30\">test</font>",
			yahoo_html_to_codes("<font size=\"6\">test</font>"));

	/* combinations */
	assert_string_equal_free("\x1B[#FF0000m<font size=\"8\">redsmall</font> rednormal\x1B[#000000m",
			yahoo_html_to_codes("<font color=\"#FF0000\"><font size=\"1\">redsmall</font> rednormal</font>"));

	assert_string_equal_free("\x1B[#FF0000m<font size=\"8\">redsmall</font> \x1B[#00FF00mgreennormal\x1B[#FF0000m rednormal\x1B[#000000m",
			yahoo_html_to_codes("<font color=\"#FF0000\"><font size=\"1\">redsmall</font> <font color=\"#00FF00\">greennormal</font> rednormal</font>"));

	assert_string_equal_free("\x1B[1mbold \x1B[#FF0000mred <font face=\"Comic Sans MS\" size=\"20\">larger \x1B[#000000mbacktoblack <font size=\"12\">normalsize</font>\x1B[#FF0000m</font>\x1B[#000000m\x1B[x1m",
			yahoo_html_to_codes("<b>bold <font color=\"#FF0000\">red <font face=\"Comic Sans MS\" size=\"5\">larger <font color=\"#000000\">backtoblack <font size=\"3\">normalsize</font></font></font></font></b>"));

	/* buzz/unknown tags */
	assert_string_equal_free("<ding>",
			yahoo_html_to_codes("<ding>"));
	assert_string_equal_free("Unknown <tags>",
			yahoo_html_to_codes("Unknown <tags>"));
}
END_TEST

Suite *
yahoo_util_suite(void)
{
	Suite *s;
	TCase *tc;

	s = suite_create("Yahoo Utility Functions");

	tc = tcase_create("Convert IM from network format to HTML");
	tcase_add_unchecked_fixture(tc, setup_codes_to_html, teardown_codes_to_html);
	tcase_add_test(tc, test_codes_to_html);
	suite_add_tcase(s, tc);

	tc = tcase_create("Convert IM from HTML to network format");
	tcase_add_test(tc, test_html_to_codes);
	suite_add_tcase(s, tc);

	return s;
}
