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
	src/base64.cc \
	src/userstate.cc

libmpseq_la_LIBADD = \
	$(LIBGCRYPT_LIBS)

noinst_LTLIBRARIES += contrib/gtest/lib/libgtest.la

contrib_gtest_lib_libgtest_la_SOURCES = \
	contrib/gtest/src/gtest-all.cc

contrib_gtest_lib_libgtest_la_CPPFLAGS = \
	-I$(top_srcdir)/${GTEST_BASE} \
	-I$(top_srcdir)/${GTEST_INCLUDE}


include test/Makefile.inc
include Makefile.am.lint
