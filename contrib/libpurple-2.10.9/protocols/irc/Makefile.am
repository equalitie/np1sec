EXTRA_DIST = \
	Makefile.mingw

pkgdir = $(libdir)/purple-$(PURPLE_MAJOR_VERSION)

IRCSOURCES = \
	cmds.c \
	dcc_send.c \
	irc.c \
	irc.h \
	msgs.c \
	parse.c

AM_CFLAGS = $(st)

libirc_la_LDFLAGS = -module -avoid-version

if STATIC_IRC

st = -DPURPLE_STATIC_PRPL
noinst_LTLIBRARIES = libirc.la
libirc_la_SOURCES  = $(IRCSOURCES)
libirc_la_CFLAGS   = $(AM_CFLAGS)

else

st =
pkg_LTLIBRARIES   = libirc.la
libirc_la_SOURCES = $(IRCSOURCES)
libirc_la_LIBADD  = $(GLIB_LIBS) $(SASL_LIBS)

endif

AM_CPPFLAGS = \
	-I$(top_srcdir)/libpurple \
	-I$(top_builddir)/libpurple \
	$(GLIB_CFLAGS) \
	$(DEBUG_CFLAGS)
