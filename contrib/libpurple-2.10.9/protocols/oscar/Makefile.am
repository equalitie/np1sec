EXTRA_DIST = \
	COPYING \
	AUTHORS \
	Makefile.mingw

pkgdir = $(libdir)/purple-$(PURPLE_MAJOR_VERSION)

OSCARSOURCES = \
	authorization.c     \
	bstream.c           \
	clientlogin.c       \
	encoding.c          \
	encoding.h          \
	family_admin.c      \
	family_alert.c      \
	family_auth.c       \
	family_bart.c       \
	family_bos.c        \
	family_buddy.c      \
	family_chat.c       \
	family_chatnav.c    \
	family_icq.c        \
	family_icbm.c       \
	family_locate.c     \
	family_oservice.c   \
	family_popup.c      \
	family_feedbag.c    \
	family_stats.c      \
	family_userlookup.c \
	flap_connection.c   \
	misc.c         \
	msgcookie.c         \
	odc.c               \
	oft.c               \
	oscar.c             \
	oscar.h             \
	oscarcommon.h       \
	oscar_data.c        \
	peer.c              \
	peer.h              \
	peer_proxy.c        \
	rxhandlers.c        \
	snac.c              \
	snactypes.h         \
	tlv.c               \
	userinfo.c          \
	util.c              \
	visibility.c	    \
	visibility.h

AM_CFLAGS = $(st)

libaim_la_LDFLAGS = -module -avoid-version
libicq_la_LDFLAGS = -module -avoid-version
if STATIC_OSCAR

st = -DPURPLE_STATIC_PRPL
noinst_LTLIBRARIES  = liboscar.la
liboscar_la_SOURCES = $(OSCARSOURCES) libaim.c libicq.c
liboscar_la_CFLAGS  = $(AM_CFLAGS)

else

st =
pkg_LTLIBRARIES     = liboscar.la libaim.la libicq.la
liboscar_la_SOURCES = $(OSCARSOURCES)
liboscar_la_LIBADD  = $(GLIB_LIBS)

libaim_la_SOURCES   = libaim.c
libaim_la_LIBADD    = liboscar.la

libicq_la_SOURCES   = libicq.c
libicq_la_LIBADD    = liboscar.la

endif

AM_CPPFLAGS = \
	-I$(top_srcdir)/libpurple \
	-I$(top_builddir)/libpurple \
	$(GLIB_CFLAGS) \
	$(DEBUG_CFLAGS)
