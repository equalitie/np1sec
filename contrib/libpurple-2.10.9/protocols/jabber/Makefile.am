EXTRA_DIST = \
	Makefile.mingw \
	win32/posix.uname.c \
	win32/utsname.h

pkgdir = $(libdir)/purple-$(PURPLE_MAJOR_VERSION)

JABBERSOURCES = \
			  adhoccommands.c \
			  adhoccommands.h \
			  auth.c \
			  auth.h \
			  auth_digest_md5.c \
			  auth_digest_md5.h \
			  auth_plain.c \
			  auth_scram.c \
			  auth_scram.h \
			  buddy.c \
			  buddy.h \
			  bosh.c \
			  bosh.h \
			  caps.c \
			  caps.h \
			  chat.c \
			  chat.h \
			  data.c \
			  data.h \
			  disco.c \
			  disco.h \
			  google/gmail.c \
			  google/gmail.h \
			  google/google.c \
			  google/google.h \
			  google/google_presence.c \
			  google/google_presence.h \
			  google/google_roster.c \
			  google/google_roster.h \
			  google/google_session.c \
			  google/google_session.h \
			  google/jingleinfo.c \
			  google/jingleinfo.h \
			  google/relay.c \
			  google/relay.h \
			  ibb.c \
			  ibb.h \
			  iq.c \
			  iq.h \
			  jabber.c \
			  jabber.h \
			  jingle/jingle.c \
			  jingle/jingle.h \
			  jingle/content.c \
			  jingle/content.h \
			  jingle/iceudp.c \
			  jingle/iceudp.h \
			  jingle/rawudp.c \
			  jingle/rawudp.h \
			  jingle/rtp.c \
			  jingle/rtp.h \
			  jingle/session.c \
			  jingle/session.h \
			  jingle/transport.c \
			  jingle/transport.h \
			  jutil.c \
			  jutil.h \
			  message.c \
			  message.h \
			  namespaces.h \
			  oob.c \
			  oob.h \
			  parser.c \
			  parser.h \
			  pep.c \
			  pep.h \
			  ping.c \
			  ping.h \
			  presence.c \
			  presence.h \
			  roster.c \
			  roster.h \
			  si.c \
			  si.h \
			  useravatar.c \
			  useravatar.h \
			  usermood.c \
			  usermood.h \
			  usernick.c \
			  usernick.h \
			  usertune.c \
			  usertune.h \
			  xdata.c \
			  xdata.h

AM_CFLAGS = $(st)

libxmpp_la_LDFLAGS = -module -avoid-version

if USE_CYRUS_SASL
JABBERSOURCES += auth_cyrus.c
endif

if STATIC_JABBER

st = -DPURPLE_STATIC_PRPL
noinst_LTLIBRARIES   = libjabber.la
libjabber_la_SOURCES = $(JABBERSOURCES) libxmpp.c
libjabber_la_CFLAGS  = $(AM_CFLAGS)

else

st =
pkg_LTLIBRARIES      = libjabber.la libxmpp.la
libjabber_la_SOURCES = $(JABBERSOURCES)
libjabber_la_LIBADD  = $(GLIB_LIBS) $(SASL_LIBS) $(LIBXML_LIBS) $(IDN_LIBS)\
	$(FARSIGHT_LIBS) \
	$(GSTREAMER_LIBS) \
	$(GSTINTERFACES_LIBS)

libxmpp_la_SOURCES = libxmpp.c
libxmpp_la_LIBADD = libjabber.la

endif

AM_CPPFLAGS = \
	-I$(top_srcdir)/libpurple \
	-I$(top_builddir)/libpurple \
	$(DEBUG_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(IDN_CFLAGS) \
	$(LIBXML_CFLAGS) \
	$(FARSIGHT_CFLAGS) \
	$(GSTREAMER_CFLAGS) \
	$(GSTINTERFACES_CFLAGS)
