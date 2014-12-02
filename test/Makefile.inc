# Unit tests

noinst_PROGRAMS += libmpseq_test

TESTS += libmpseq_test

libmpseq_test_SOURCES = \
	test/session_test.cc \
	test/userstate_test.cc \
	test/crypt_test.cc \
	test/main.cc

libmpseq_test_CPPFLAGS = \
	-I$(top_srcdir)/${GTEST_BASE} \
	-I$(top_srcdir)/${GTEST_INCLUDE}

libmpseq_test_LDADD = \
	libmpseq.la

libmpseq_test_LDFLAGS = \
	$(top_srcdir)/${GTEST_BASE}/lib/libgtest.la -lpthread

# Integration tests

noinst_PROGRAMS += xmpp_test

xmpp_test_SOURCES = test/xmpp_test.cpp

xmpp_test_LDADD = \
	$(PURPLE_LIBS) \
	libmpseq.la

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

