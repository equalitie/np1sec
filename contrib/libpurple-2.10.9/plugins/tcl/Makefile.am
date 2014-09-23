plugindir = $(libdir)/purple-$(PURPLE_MAJOR_VERSION)

tcl_la_LDFLAGS = -module -avoid-version

plugin_LTLIBRARIES = tcl.la

tcl_la_SOURCES = tcl.c tcl_glib.c tcl_glib.h tcl_cmds.c tcl_signals.c tcl_purple.h \
                 tcl_ref.c tcl_cmd.c

tcl_la_LIBADD = $(GLIB_LIBS) $(TCL_LIBS) $(TK_LIBS)

EXTRA_DIST = signal-test.tcl Makefile.mingw

AM_CPPFLAGS = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/libpurple \
	-I$(top_builddir)/libpurple \
	$(DEBUG_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(PLUGIN_CFLAGS) \
	$(TK_CFLAGS) \
	$(TCL_CFLAGS)
