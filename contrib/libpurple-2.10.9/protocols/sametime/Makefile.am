EXTRA_DIST = \
	Makefile.mingw

pkgdir = $(libdir)/purple-$(PURPLE_MAJOR_VERSION)

noinst_HEADERS = sametime.h

SAMETIMESOURCES = sametime.c

AM_CFLAGS = \
	$(st)

if STATIC_SAMETIME

st = -DPURPLE_STATIC_PRPL
noinst_LTLIBRARIES     = libsametime.la
libsametime_la_CFLAGS  = $(AM_CFLAGS)

else

st =
pkg_LTLIBRARIES     = libsametime.la

endif

libsametime_la_SOURCES = $(SAMETIMESOURCES)
libsametime_la_LDFLAGS = -module -avoid-version
libsametime_la_LIBADD = $(GLIB_LIBS) $(MEANWHILE_LIBS)

AM_CPPFLAGS = \
	-I$(top_srcdir)/libpurple \
	-I$(top_builddir)/libpurple \
	$(DEBUG_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(MEANWHILE_CFLAGS) \
	-DG_LOG_DOMAIN=\"sametime\"

