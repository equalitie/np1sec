# Unit tests

noinst_PROGRAMS += libnp1sec_test

TESTS += libnp1sec_test

libnp1sec_test_SOURCES = \
	test/crypt_test.cc \
	test/main.cc \
    test/chat_mocker.cc \
    test/chat_mocker_np1sec_plugin.cc \
 	test/session_test.cc \
    test/test_message.cc \
libnp1sec_test_CPPFLAGS = \
	-I$(top_srcdir)/${GTEST_BASE} \
	-I$(top_srcdir)/${GTEST_INCLUDE}

libnp1sec_test_LDADD = \
	libnp1sec.la

libnp1sec_test_LDFLAGS = \
	$(top_srcdir)/${GTEST_BASE}/lib/libgtest.la -lpthread

# Integration tests

noinst_PROGRAMS += xmpp_test

xmpp_test_SOURCES = test/xmpp_test.cpp

xmpp_test_LDADD = \
 	$(PURPLE_LIBS) \
 	libnp1sec.la

xmpp_test_CPPFLAGS = \
	$(PURPLE_CFLAGS) \
	-I$(srcdir)/src

# gtest

noinst_LTLIBRARIES += contrib/gtest/lib/libgtest.la

contrib_gtest_lib_libgtest_la_SOURCES = \
	contrib/gtest/src/gtest-all.cc

contrib_gtest_lib_libgtest_la_CPPFLAGS = \
	-I$(top_srcdir)/${GTEST_BASE} \
	-I$(top_srcdir)/${GTEST_INCLUDE}

