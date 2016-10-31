ACLOCAL_AMFLAGS = -I m4

AM_CPPFLAGS = -I. -I$(srcdir)/src \
	$(LIBGCRYPT_CFLAGS) \
	$(LIBEVENT_CFLAGS) \
	$(PURPLE_CFLAGS)

bin_PROGRAMS = jabberling

jabberling_SOURCES = \
	src/base64.cc \
	src/crypto.cc \
	src/jabberling.cc \
	src/main.cc \
	src/message.cc \
	src/room.cc

jabberling_LDADD = \
	$(LIBGCRYPT_LIBS) \
	$(LIBEVENT_LIBS) \
	$(PURPLE_LIBS) \
	-lreadline
