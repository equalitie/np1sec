plugindir = $(libdir)/purple-$(PURPLE_MAJOR_VERSION)

plugin_LTLIBRARIES = mono.la

mono_la_SOURCES	= \
	mono.c \
	mono-glue.h \
	mono-helper.c \
	mono-helper.h \
	debug-glue.c \
	signal-glue.c \
	blist-glue.c \
	status-glue.c 

mono_la_LDFLAGS  = -module -avoid-version

mono_la_LIBADD = $(MONO_LIBS)

AM_CPPFLAGS = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/libpurple \
	$(DEBUG_CFLAGS) \
	$(PLUGIN_CFLAGS) \
	$(MONO_CFLAGS)
