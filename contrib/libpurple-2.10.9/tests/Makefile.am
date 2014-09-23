if HAVE_CHECK
TESTS=check_libpurple

clean-local:
	-rm -rf libpurple..

check_PROGRAMS=check_libpurple

check_libpurple_SOURCES=\
        check_libpurple.c \
	    tests.h \
		test_cipher.c \
		test_jabber_caps.c \
		test_jabber_digest_md5.c \
		test_jabber_jutil.c \
		test_jabber_scram.c \
		test_oscar_util.c \
		test_yahoo_util.c \
		test_util.c \
		test_xmlnode.c \
		$(top_builddir)/libpurple/util.h

check_libpurple_CFLAGS=\
        @CHECK_CFLAGS@ \
		$(GLIB_CFLAGS) \
		$(DEBUG_CFLAGS) \
		$(LIBXML_CFLAGS) \
		-I.. \
		-I$(top_srcdir)/libpurple \
		-DBUILDDIR=\"$(top_builddir)\"

check_libpurple_LDADD=\
		$(top_builddir)/libpurple/protocols/jabber/libjabber.la \
		$(top_builddir)/libpurple/protocols/oscar/liboscar.la \
		$(top_builddir)/libpurple/protocols/yahoo/libymsg.la \
		$(top_builddir)/libpurple/libpurple.la \
        @CHECK_LIBS@ \
		$(GLIB_LIBS)

endif
