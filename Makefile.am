ACLOCAL_AMFLAGS = -I m4

AM_CPPFLAGS = -I. -I$(srcdir)/src \
	$(LIBGCRYPT_CFLAGS)

noinst_LTLIBRARIES =
noinst_PROGRAMS =

TESTS =

lib_LTLIBRARIES = libmpseq.la

libmpseq_la_SOURCES = \
	src/crypt.cc \
	src/session.cc \
	src/userstate.cc

libmpseq_la_LIBADD = \
	$(LIBGCRYPT_LIBS)

include test/Makefile.inc
include Makefile.am.lint
