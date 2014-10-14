ACLOCAL_AMFLAGS = -I m4

noinst_LTLIBRARIES =
noinst_PROGRAMS =

TESTS =

# Unit tests

noinst_LTLIBRARIES += contrib/gtest/lib/libgtest.la

contrib_gtest_lib_libgtest_la_SOURCES = \
	contrib/gtest/src/gtest-all.cc

contrib_gtest_lib_libgtest_la_CPPFLAGS = \
	-I$(top_srcdir)/${GTEST_BASE} \
	-I$(top_srcdir)/${GTEST_INCLUDE}

noinst_PROGRAMS += libmpotr_test

TESTS += libmpotr_test

libmpotr_test_SOURCES = src/session_test.cc

libmpotr_test_CPPFLAGS = \
	-I$(top_srcdir)/${GTEST_BASE} \
	-I$(top_srcdir)/${GTEST_INCLUDE} \
	$(LIBGCRYPT_CFLAGS)

libmpotr_test_LDADD = \
	$(LIBGCRYPT_LIBS)

libmpotr_test_LDFLAGS = \
	$(top_srcdir)/${GTEST_BASE}/lib/libgtest.la -lpthread

include test/Makefile.inc
include Makefile.am.lint
