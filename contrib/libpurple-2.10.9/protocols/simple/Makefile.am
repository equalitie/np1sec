EXTRA_DIST = \
	Makefile.mingw

pkgdir = $(libdir)/purple-$(PURPLE_MAJOR_VERSION)

SIMPLESOURCES = \
	simple.c \
	simple.h \
	sipmsg.c \
	sipmsg.h

AM_CFLAGS = $(st)

libsimple_la_LDFLAGS = -module -avoid-version

if STATIC_SIMPLE

st = -DPURPLE_STATIC_PRPL
noinst_LTLIBRARIES   = libsimple.la
libsimple_la_SOURCES = $(SIMPLESOURCES)
libsimple_la_CFLAGS  = $(AM_CFLAGS)

else

st =
pkg_LTLIBRARIES      = libsimple.la
libsimple_la_SOURCES = $(SIMPLESOURCES)
libsimple_la_LIBADD  = $(GLIB_LIBS)

endif

AM_CPPFLAGS = \
	-I$(top_srcdir)/libpurple \
	-I$(top_builddir)/libpurple \
	$(GLIB_CFLAGS) \
	$(DEBUG_CFLAGS)
