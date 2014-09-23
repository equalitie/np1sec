# Integration tests

purple_coresources = \
	contrib/libpurple/account.c \
	contrib/libpurple/accountopt.c \
	contrib/libpurple/blist.c \
	contrib/libpurple/buddyicon.c \
	contrib/libpurple/certificate.c \
	contrib/libpurple/cipher.c \
	contrib/libpurple/circbuffer.c \
	contrib/libpurple/cmds.c \
	contrib/libpurple/connection.c \
	contrib/libpurple/conversation.c \
	contrib/libpurple/core.c \
	contrib/libpurple/debug.c \
	contrib/libpurple/desktopitem.c \
	contrib/libpurple/eventloop.c \
	contrib/libpurple/ft.c \
	contrib/libpurple/idle.c \
	contrib/libpurple/imgstore.c \
	contrib/libpurple/log.c \
	contrib/libpurple/media/backend-fs2.c \
	contrib/libpurple/media/backend-iface.c \
	contrib/libpurple/media/candidate.c \
	contrib/libpurple/media/codec.c \
	contrib/libpurple/media/enum-types.c \
	contrib/libpurple/media.c \
	contrib/libpurple/mediamanager.c \
	contrib/libpurple/mime.c \
	contrib/libpurple/nat-pmp.c \
	contrib/libpurple/network.c \
	contrib/libpurple/ntlm.c \
	contrib/libpurple/notify.c \
	contrib/libpurple/plugin.c \
	contrib/libpurple/pluginpref.c \
	contrib/libpurple/pounce.c \
	contrib/libpurple/prefs.c \
	contrib/libpurple/privacy.c \
	contrib/libpurple/proxy.c \
	contrib/libpurple/prpl.c \
	contrib/libpurple/request.c \
	contrib/libpurple/roomlist.c \
	contrib/libpurple/savedstatuses.c \
	contrib/libpurple/server.c \
	contrib/libpurple/signals.c \
	contrib/libpurple/smiley.c \
	contrib/libpurple/dnsquery.c \
	contrib/libpurple/dnssrv.c\
	contrib/libpurple/status.c \
	contrib/libpurple/stringref.c \
	contrib/libpurple/stun.c \
	contrib/libpurple/sound.c \
	contrib/libpurple/sound-theme.c \
	contrib/libpurple/sound-theme-loader.c \
	contrib/libpurple/sslconn.c \
	contrib/libpurple/theme.c \
	contrib/libpurple/theme-loader.c \
	contrib/libpurple/theme-manager.c \
	contrib/libpurple/upnp.c \
	contrib/libpurple/util.c \
	contrib/libpurple/value.c \
	contrib/libpurple/version.c \
	contrib/libpurple/xmlnode.c \
	contrib/libpurple/whiteboard.c

noinst_LTLIBRARIES += contrib/libpurple/libpurple.la

contrib_libpurple_libpurple_la_SOURCES = \
	$(purple_coresources)

contrib_libpurple_libpurple_la_LIBADD = \
	$(GLIB_LIBS) \
	$(LIBXML_LIBS)

PURPLE_MAJOR_VERSION = 2

contrib_libpurple_libpurple_la_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(LIBXML_CFLAGS) \
	-I$(top_srcdir)/contrib/libpurple \
	-DDATADIR=\"$(datadir)\" \
	-DLIBDIR=\"$(libdir)/purple-$(PURPLE_MAJOR_VERSION)/\" \
	-DLOCALEDIR=\"$(datadir)/locale\" \
	-DSYSCONFDIR=\"$(sysconfdir)\"

noinst_PROGRAMS += xmpp_test

TESTS += xmpp_test

xmpp_test_SOURCES = test/xmpp_test.cpp

xmpp_test_LDFLAGS = \
	$(top_srcdir)/contrib/libpurple/libpurple.la \
	$(GLIB_LIBS)

xmpp_test_CPPFLAGS = \
	-I$(top_srcdir)/contrib/libpurple \
	$(GLIB_CFLAGS)
