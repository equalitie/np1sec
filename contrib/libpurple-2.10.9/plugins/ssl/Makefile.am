EXTRA_DIST = \
		Makefile.mingw

plugindir = $(libdir)/purple-$(PURPLE_MAJOR_VERSION)

ssl_la_LDFLAGS        = -module -avoid-version
ssl_gnutls_la_LDFLAGS = -module -avoid-version
ssl_nss_la_LDFLAGS    = -module -avoid-version

if PLUGINS

# I'm sorry to report that Automake Conditionals don't support
#   if USE_GNUTLS && USE_NSS
# but only support testing a single variable. Hence:

if USE_GNUTLS
if USE_NSS
plugin_LTLIBRARIES = \
	ssl.la           \
	ssl-gnutls.la    \
	ssl-nss.la
else
plugin_LTLIBRARIES = \
	ssl.la           \
	ssl-gnutls.la
endif
else
if USE_NSS
plugin_LTLIBRARIES = \
	ssl.la           \
	ssl-nss.la
else
plugin_LTLIBRARIES = \
	ssl.la
endif
endif

ssl_la_SOURCES        = ssl.c
ssl_gnutls_la_SOURCES = ssl-gnutls.c
ssl_nss_la_SOURCES    = ssl-nss.c

ssl_la_LIBADD        = $(GLIB_LIBS)
ssl_gnutls_la_LIBADD = $(GLIB_LIBS) $(GNUTLS_LIBS)
ssl_nss_la_LIBADD    = $(GLIB_LIBS) $(NSS_LIBS)

endif # PLUGINS

AM_CPPFLAGS = \
	-DDATADIR=\"$(datadir)\" \
	-DLIBDIR=\"$(libdir)/libpurple\" \
	-I$(top_srcdir)/libpurple \
	-I$(top_builddir)/libpurple \
	$(DEBUG_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(PLUGIN_CFLAGS)

ssl_gnutls_la_CFLAGS = $(AM_CPPFLAGS) $(GNUTLS_CFLAGS)
ssl_nss_la_CFLAGS = $(AM_CPPFLAGS) $(NSS_CFLAGS)
