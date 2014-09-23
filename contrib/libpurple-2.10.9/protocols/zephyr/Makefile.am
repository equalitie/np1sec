pkgdir = $(libdir)/purple-$(PURPLE_MAJOR_VERSION)

ZEPHYRSOURCES = \
	ZAsyncLocate.c \
	ZCkAuth.c \
	ZCkIfNot.c \
	ZClosePort.c \
	ZCmpUID.c \
	ZCmpUIDP.c \
	ZFlsLocs.c \
	ZFlsSubs.c \
	ZFmtAuth.c \
	ZFmtList.c \
	ZFmtNotice.c \
	ZFmtRaw.c \
	ZFmtRawLst.c \
	ZFmtSmRLst.c \
	ZFmtSmRaw.c \
	ZFreeNot.c \
	ZGetLocs.c \
	ZGetSender.c \
	ZGetSubs.c \
	ZGetWGPort.c \
	ZIfNotice.c \
	ZInit.c \
	ZLocations.c \
	ZMakeAscii.c \
	ZMkAuth.c \
	ZNewLocU.c \
	ZOpenPort.c \
	ZParseNot.c \
	ZPeekIfNot.c \
	ZPeekNot.c \
	ZPeekPkt.c \
	ZPending.c \
	ZReadAscii.c \
	ZRecvNot.c \
	ZRecvPkt.c \
	ZRetSubs.c \
	ZSendList.c \
	ZSendNot.c \
	ZSendPkt.c \
	ZSendRLst.c \
	ZSendRaw.c \
	ZSetDest.c \
	ZSetFD.c \
	ZSetSrv.c \
	ZSubs.c \
	ZVariables.c \
	ZWait4Not.c \
	ZhmStat.c \
	Zinternal.c \
	com_err.h \
	error_message.c \
	error_table.h \
	et_name.c \
	init_et.c \
	internal.h \
	mit-copyright.h \
	mit-sipb-copyright.h \
	sysdep.h \
	zephyr_err.c \
	zephyr_err.h \
	zephyr_internal.h \
	zephyr.c

ZEPHYRSOURCESEXT = zephyr.c

AM_CFLAGS = $(st)

ZEPHYRLIBS = $(KRB4_LDFLAGS) $(KRB4_LIBS)

ZEPHYRLIBSEXT = $(ZEPHYR_LDFLAGS) $(ZEPHYR_LIBS)

libzephyr_la_LDFLAGS = -module -avoid-version

if STATIC_ZEPHYR

st = -DPURPLE_STATIC_PRPL -Dlint
noinst_LTLIBRARIES   = libzephyr.la
libzephyr_la_SOURCES = $(ZEPHYRSOURCES)
libzephyr_la_CFLAGS  = $(AM_CFLAGS)
libzephyr_la_LIBADD  = $(ZEPHYRLIBS)

else

st = -Dlint
pkg_LTLIBRARIES = libzephyr.la

if EXTERNAL_LIBZEPHYR
libzephyr_la_SOURCES = $(ZEPHYRSOURCESEXT)
libzephyr_la_LIBADD  = $(GLIB_LIBS) $(ZEPHYRLIBSEXT)
else
libzephyr_la_SOURCES = $(ZEPHYRSOURCES)
libzephyr_la_LIBADD  = $(GLIB_LIBS) $(ZEPHYRLIBS)
endif


endif

AM_CPPFLAGS = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/libpurple \
	-I$(top_builddir)/libpurple \
	-I$(top_srcdir)/libpurple/protocols \
	-DCONFDIR=\"$(sysconfdir)\" \
	$(GLIB_CFLAGS) \
	$(KRB4_CFLAGS) \
	$(DEBUG_CFLAGS)
