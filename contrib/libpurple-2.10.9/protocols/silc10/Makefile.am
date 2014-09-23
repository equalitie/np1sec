EXTRA_DIST = \
	Makefile.mingw \
	README \
	TODO

pkgdir = $(libdir)/purple-$(PURPLE_MAJOR_VERSION)

SILCSOURCES = silc.c silcpurple.h buddy.c chat.c ft.c ops.c pk.c util.c wb.c wb.h

AM_CFLAGS = $(st)

libsilcpurple_la_LDFLAGS = -module -avoid-version

if STATIC_SILC

st = -DPURPLE_STATIC_PRPL $(SILC_CFLAGS)
noinst_LTLIBRARIES       = libsilcpurple.la
libsilcpurple_la_SOURCES = $(SILCSOURCES)
libsilcpurple_la_CFLAGS  = $(AM_CFLAGS)
libsilcpurple_la_LIBADD  = $(SILC_LIBS)

else

st = $(SILC_CFLAGS)
pkg_LTLIBRARIES          = libsilcpurple.la
libsilcpurple_la_SOURCES = $(SILCSOURCES)
libsilcpurple_la_LIBADD  = $(GLIB_LIBS) $(SILC_LIBS)

endif

AM_CPPFLAGS = \
	-I$(top_srcdir)/libpurple \
	-I$(top_builddir)/libpurple \
	$(DEBUG_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(SILC_CFLAGS)
