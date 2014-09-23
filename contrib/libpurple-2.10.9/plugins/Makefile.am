DIST_SUBDIRS = mono perl ssl tcl

if USE_PERL
PERL_DIR = perl
endif

if USE_TCL
TCL_DIR = tcl
endif

if ENABLE_DBUS
DBUS_LTLIB = dbus-example.la
endif

if USE_MONO
MONO_DIR = mono
endif

SUBDIRS = \
	$(MONO_DIR) \
	$(PERL_DIR) \
	ssl \
	$(TCL_DIR)

plugindir = $(libdir)/purple-$(PURPLE_MAJOR_VERSION)

autoaccept_la_LDFLAGS       = -module -avoid-version
buddynote_la_LDFLAGS        = -module -avoid-version
ciphertest_la_LDFLAGS		= -module -avoid-version
codeinline_la_LDFLAGS		= -module -avoid-version
debug_example_la_LDFLAGS    = -module -avoid-version
helloworld_la_LDFLAGS       = -module -avoid-version
idle_la_LDFLAGS             = -module -avoid-version
joinpart_la_LDFLAGS         = -module -avoid-version
log_reader_la_LDFLAGS       = -module -avoid-version
newline_la_LDFLAGS          = -module -avoid-version
notify_example_la_LDFLAGS   = -module -avoid-version
offlinemsg_la_LDFLAGS       = -module -avoid-version
one_time_password_la_LDFLAGS	= -module -avoid-version
pluginpref_example_la_LDFLAGS = -module -avoid-version
psychic_la_LDFLAGS          = -module -avoid-version
signals_test_la_LDFLAGS		= -module -avoid-version
simple_la_LDFLAGS			= -module -avoid-version
statenotify_la_LDFLAGS      = -module -avoid-version

# this can't be in a conditional otherwise automake 1.4 yells
dbus_example_la_LDFLAGS     = -module -avoid-version

if PLUGINS

plugin_LTLIBRARIES = \
	autoaccept.la       \
	buddynote.la        \
	idle.la             \
	joinpart.la         \
	log_reader.la       \
	newline.la          \
	offlinemsg.la       \
	psychic.la          \
	statenotify.la      \
	$(DBUS_LTLIB)

noinst_LTLIBRARIES = \
	ciphertest.la \
	codeinline.la \
	debug_example.la \
	helloworld.la \
	notify_example.la \
	one_time_password.la \
	pluginpref_example.la \
	signals_test.la \
	simple.la

autoaccept_la_SOURCES       = autoaccept.c
buddynote_la_SOURCES        = buddynote.c
ciphertest_la_SOURCES		= ciphertest.c
codeinline_la_SOURCES		= codeinline.c
debug_example_la_SOURCES = debug_example.c
helloworld_la_SOURCES       = helloworld.c
idle_la_SOURCES             = idle.c
joinpart_la_SOURCES         = joinpart.c
log_reader_la_SOURCES       = log_reader.c
newline_la_SOURCES          = newline.c
notify_example_la_SOURCES   = notify_example.c
offlinemsg_la_SOURCES       = offlinemsg.c
one_time_password_la_SOURCES	= one_time_password.c
pluginpref_example_la_SOURCES = pluginpref_example.c
psychic_la_SOURCES          = psychic.c
signals_test_la_SOURCES		= signals-test.c
simple_la_SOURCES			= simple.c
statenotify_la_SOURCES      = statenotify.c

autoaccept_la_LIBADD        = $(GLIB_LIBS)
buddynote_la_LIBADD         = $(GLIB_LIBS)
ciphertest_la_LIBADD		= $(GLIB_LIBS)
codeinline_la_LIBADD		= $(GLIB_LIBS)
idle_la_LIBADD              = $(GLIB_LIBS)
joinpart_la_LIBADD          = $(GLIB_LIBS)
log_reader_la_LIBADD        = $(GLIB_LIBS)
newline_la_LIBADD           = $(GLIB_LIBS)
notify_example_la_LIBADD    = $(GLIB_LIBS)
offlinemsg_la_LIBADD        = $(GLIB_LIBS)
one_time_password_la_LIBADD = $(GLIB_LIBS)
pluginpref_example_la_LIBADD = $(GLIB_LIBS)
psychic_la_LIBADD           = $(GLIB_LIBS)
signals_test_la_LIBADD		= $(GLIB_LIBS)
simple_la_LIBADD			= $(GLIB_LIBS)
statenotify_la_LIBADD       = $(GLIB_LIBS)

if ENABLE_DBUS

CLEANFILES              = dbus-example-bindings.c
dbus_example_la_SOURCES = dbus-example.c

dbus_example_la_LIBADD      = $(GLIB_LIBS) $(DBUS_LIBS)

.PHONY: always

$(top_builddir)/libpurple/dbus-types.h: always
	cd $(@D) && $(MAKE) $(AM_MAKEFLAGS) $(@F)

dbus-example-bindings.c: $(top_srcdir)/libpurple/dbus-analyze-functions.py $(dbus_example_la_SOURCES)
	cat $(srcdir)/$(dbus_example_la_SOURCES) | \
	$(PYTHON) $(top_srcdir)/libpurple/dbus-analyze-functions.py --export-only > $@

$(dbus_example_la_OBJECTS) dbus-example.so: dbus-example-bindings.c $(top_builddir)/libpurple/dbus-types.h


endif # ENABLE_DBUS

endif # PLUGINS

EXTRA_DIST = \
	Makefile.mingw \
	dbus-buddyicons-example.py \
	filectl.c \
	fortuneprofile.pl \
	ipc-test-client.c \
	ipc-test-server.c \
	startup.py

AM_CPPFLAGS = \
	-DDATADIR=\"$(datadir)\" \
	-I$(top_srcdir)/libpurple \
	-I$(top_builddir)/libpurple \
	$(DEBUG_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(PLUGIN_CFLAGS) \
	$(DBUS_CFLAGS)

#
# This part allows people to build their own plugins in here.
# Yes, it's a mess.
#
SUFFIXES = .c .so
.c.so:
	$(LIBTOOL) --mode=compile $(CC) -DHAVE_CONFIG_H -I$(top_builddir) $(AM_CPPFLAGS) $(CFLAGS) -c $< -o tmp$@.lo $(PLUGIN_CFLAGS)
	$(LIBTOOL) --mode=link    $(CC) $(CFLAGS) -o libtmp$@.la -rpath $(plugindir) tmp$@.lo $(LIBS) $(LDFLAGS) -module -avoid-version $(PLUGIN_LIBS)
	@rm -f tmp$@.lo tmp$@.o libtmp$@.la
	@cp .libs/libtmp$@*.so $@
	@rm -rf .libs/libtmp$@.*
