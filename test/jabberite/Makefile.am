AUTOMAKE_OPTIONS = subdir-objects
ACLOCAL_AMFLAGS = -I config-aux --install
AM_CXXFLAGS = -Werror -Wall -Wextra -Wformat=2 -std=c++0x
AM_CPPFLAGS = -I. -I$(srcdir)/src \
	$(lib_CPPFLAGS)

noinst_PROGRAMS += jabberite

jabberite_SOURCES = test/jabberite.cc \
                    test/jabberite_np1sec_plugin.cc

jabberite_LDADD = \
	$(PURPLE_LIBS) \
	libnp1sec.la

jabberite_CPPFLAGS = \
	$(PURPLE_CFLAGS) \
	-I$(srcdir)/src
