EXTRA_DIST = \
	Makefile.mingw

pkgdir = $(libdir)/purple-$(PURPLE_MAJOR_VERSION)

MSIMSOURCES = markup.c \
	  markup.h \
	  message.c \
	  message.h \
	  myspace.c \
	  myspace.h \
	  persist.h \
	  session.c \
	  session.h \
	  user.c \
	  user.h \
	  zap.c \
	  zap.h

AM_CFLAGS = $(st)

libmyspace_la_LDFLAGS = -module -avoid-version

if STATIC_MYSPACE

st = -DPURPLE_STATIC_PRPL
noinst_LTLIBRARIES    = libmyspace.la
libmyspace_la_SOURCES = $(MSIMSOURCES)
libmyspace_la_CFLAGS  = $(AM_CFLAGS)

else

st =
pkg_LTLIBRARIES       = libmyspace.la
libmyspace_la_SOURCES = $(MSIMSOURCES)
libmyspace_la_LIBADD  = $(GLIB_LIBS)

endif

AM_CPPFLAGS = \
	-I$(top_srcdir)/libpurple \
	-I$(top_builddir)/libpurple \
	$(GLIB_CFLAGS) \
	$(DEBUG_CFLAGS)
