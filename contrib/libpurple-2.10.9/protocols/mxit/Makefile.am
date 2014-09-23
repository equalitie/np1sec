EXTRA_DIST = \
	Makefile.mingw

pkgdir = $(libdir)/purple-$(PURPLE_MAJOR_VERSION)

MXITSOURCES = \
	actions.c \
	actions.h \
	aes.c \
	aes.h \
	chunk.c \
	chunk.h \
	cipher.c \
	cipher.h \
	filexfer.c \
	filexfer.h \
	formcmds.c \
	formcmds.h \
	http.c \
	http.h \
	login.c \
	login.h \
	markup.c \
	markup.h \
	multimx.c \
	multimx.h \
	mxit.c \
	mxit.h \
	profile.c \
	profile.h \
	protocol.c \
	protocol.h \
	roster.c \
	roster.h \
	splashscreen.c \
	splashscreen.h \
	voicevideo.c \
	voicevideo.h


AM_CFLAGS = $(st)

libmxit_la_LDFLAGS = -module -avoid-version

if STATIC_MXIT

st = -DPURPLE_STATIC_PRPL
noinst_LTLIBRARIES = libmxit.la
libmxit_la_SOURCES  = $(MXITSOURCES)
libmxit_la_CFLAGS   = $(AM_CFLAGS)

else

st =
pkg_LTLIBRARIES   = libmxit.la
libmxit_la_SOURCES = $(MXITSOURCES)
libmxit_la_LIBADD  = $(GLIB_LIBS)

endif

AM_CPPFLAGS = \
	-I$(top_srcdir)/libpurple \
	-I$(top_builddir)/libpurple \
	$(GLIB_CFLAGS) \
	$(DEBUG_CFLAGS)
