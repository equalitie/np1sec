# Integration tests

noinst_PROGRAMS += xmpp_test
noinst_PROGRAMS += libmpseq_test

TESTS += libmpseq_test

libmpseq_test_SOURCES = \
	test/session_test.cc \
	test/crypt_test.cc \
	test/main.cc \
	src/session.cc \
	src/base64.cc \
	src/crypt.cc

libmpseq_test_CPPFLAGS = \
	-I$(top_srcdir)/${GTEST_BASE} \
	-I$(top_srcdir)/${GTEST_INCLUDE} \
	$(LIBGCRYPT_CFLAGS)

libmpseq_test_LDADD = \
	$(LIBGCRYPT_LIBS)

libmpseq_test_LDFLAGS = \
	$(top_srcdir)/${GTEST_BASE}/lib/libgtest.la -lpthread

xmpp_test_SOURCES = test/xmpp_test.cpp


xmpp_test_LDADD = \
	$(PURPLE_LIBS) \
    libmpseq.la                   

xmpp_test_CPPFLAGS = \
	$(PURPLE_CFLAGS) \
    -I$(srcdir)/src

