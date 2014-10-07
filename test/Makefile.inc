# Integration tests

noinst_PROGRAMS += xmpp_test

TESTS += xmpp_test

xmpp_test_SOURCES = test/xmpp_test.cpp

xmpp_test_LDADD = \
	$(PURPLE_LIBS)

xmpp_test_CPPFLAGS = \
	$(PURPLE_CFLAGS)
