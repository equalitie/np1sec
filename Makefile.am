ACLOCAL_AMFLAGS = -I m4

AM_CPPFLAGS = -I. -I$(srcdir)/src \
	$(LIBGCRYPT_CFLAGS)

noinst_LTLIBRARIES =
noinst_PROGRAMS =

TESTS =

lib_LTLIBRARIES = libmpseq.la
# Unit tests

libmpseq_la_SOURCES = src/crypt.cc \
	src/session.cc \
	src/userstate.cc

libmpseq_la_LIBADD = \
	$(LIBGCRYPT_LIBS)

noinst_LTLIBRARIES += contrib/gtest/lib/libgtest.la

contrib_gtest_lib_libgtest_la_SOURCES = \
	contrib/gtest/src/gtest-all.cc

contrib_gtest_lib_libgtest_la_CPPFLAGS = \
	-I$(top_srcdir)/${GTEST_BASE} \
	-I$(top_srcdir)/${GTEST_INCLUDE}

noinst_PROGRAMS += libmpseq_test

TESTS += libmpseq_test

libmpseq_test_SOURCES = \
	test/session_test.cc \
	test/crypt_test.cc \
	test/main.cc \
	src/crypt.cc

libmpseq_test_CPPFLAGS = \
	-I$(top_srcdir)/${GTEST_BASE} \
	-I$(top_srcdir)/${GTEST_INCLUDE} \
	$(LIBGCRYPT_CFLAGS)

libmpseq_test_LDADD = \
	$(LIBGCRYPT_LIBS)

libmpseq_test_LDFLAGS = \
	$(top_srcdir)/${GTEST_BASE}/lib/libgtest.la -lpthread

include test/Makefile.inc
include Makefile.am.lint
