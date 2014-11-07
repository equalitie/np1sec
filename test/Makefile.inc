# Integration tests

noinst_PROGRAMS += xmpp_test

xmpp_test_SOURCES = test/xmpp_test.cpp


xmpp_test_LDADD = \
	$(PURPLE_LIBS) \
    libmpseq.la                   

xmpp_test_CPPFLAGS = \
	$(PURPLE_CFLAGS) \
    -I$(srcdir)/src

