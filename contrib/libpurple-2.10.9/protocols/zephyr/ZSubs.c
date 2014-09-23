/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZSubscribeTo, ZUnsubscribeTo, and
 * ZCancelSubscriptions functions.
 *
 *	Created by:	Robert French
 *
 *	Copyright (c) 1987,1988 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h".
 */

#include "internal.h"

static Code_t Z_Subscriptions __P((register ZSubscription_t *sublist,
				   int nitems, unsigned int port,
				   char *opcode, int authit));
static Code_t subscr_sendoff __P((ZNotice_t *notice, char **lyst, int num,
				  int authit));

Code_t ZSubscribeTo(sublist, nitems, port)
    ZSubscription_t *sublist;
    int nitems;
    unsigned int port;
{
    return (Z_Subscriptions(sublist, nitems, port, CLIENT_SUBSCRIBE, 1));
}

Code_t ZSubscribeToSansDefaults(sublist, nitems, port)
    ZSubscription_t *sublist;
    int nitems;
    unsigned int port;
{
    return (Z_Subscriptions(sublist, nitems, port, CLIENT_SUBSCRIBE_NODEFS,
			    1));
}

Code_t ZUnsubscribeTo(sublist, nitems, port)
    ZSubscription_t *sublist;
    int nitems;
    unsigned int port;
{
    return (Z_Subscriptions(sublist, nitems, port, CLIENT_UNSUBSCRIBE, 1));
}

Code_t ZCancelSubscriptions(port)
    unsigned int port;
{
    return (Z_Subscriptions((ZSubscription_t *)0, 0, port,
			    CLIENT_CANCELSUB, 0));
}

/*
 * This routine must do its own fragmentation.  Subscriptions must
 * not be broken across packet boundaries, or else the server will
 * mis-interpret them.
 */

static Code_t
Z_Subscriptions(sublist, nitems, port, opcode, authit)
    register ZSubscription_t *sublist;
    int nitems;
    unsigned int port;
    char *opcode;
    int authit;
{
    register int i, j;
    int retval;
    ZNotice_t notice;
    char header[Z_MAXHEADERLEN];
    char **list;
    char *recip;
    int hdrlen;
    int size_avail = Z_MAXPKTLEN-Z_FRAGFUDGE; /* space avail for data,
						 adjusted below */
    int size, start, numok;

    /* nitems = 0 means cancel all subscriptions; still need to allocate a */
    /* array for one item so we can cancel, however. */

    list = (char **)malloc((unsigned)((nitems==0)?1:nitems)*3*sizeof(char *));
    if (!list)
        return (ENOMEM);

    (void) memset((char *)&notice, 0, sizeof(notice));
    notice.z_kind = ACKED;
    notice.z_port = port;
    notice.z_class = ZEPHYR_CTL_CLASS;
    notice.z_class_inst = ZEPHYR_CTL_CLIENT;
    notice.z_opcode = opcode;
    notice.z_sender = 0;
    notice.z_recipient = "";
    notice.z_default_format = "";
    notice.z_message_len = 0;

    /* format the header to figure out how long it is */
    retval = Z_FormatHeader(&notice, header, sizeof(header), &hdrlen, ZAUTH);
    if (retval != ZERR_NONE && !authit)
	retval = Z_FormatHeader(&notice, header, sizeof(header),
				&hdrlen, ZNOAUTH);
    if (retval != ZERR_NONE) {
	free((char *)list);
	return(retval);
    }

    /* compute amount of room left */
    size_avail -= hdrlen;
    size = size_avail;

    /* assemble subs into an array of pointers */
    for (i=0;i<nitems;i++) {
	list[i*3] = sublist[i].zsub_class;
	list[i*3+1] = sublist[i].zsub_classinst;
	recip = sublist[i].zsub_recipient;
	if (recip && *recip == '*')
	  recip++;
	if (!recip || (*recip != 0 && *recip != '@'))
	  recip = ZGetSender();
	list[i*3+2] = recip;
    }

    start = -1;
    i = 0;
    numok = 0;
    if (!nitems) {
	/* there aren't really any, but we need to xmit anyway */
	retval = subscr_sendoff(&notice, list, 0, authit);
	free((char *)list);
	return(retval);
    }
    while(i < nitems) {
	if (start == -1) {
	    size = size_avail;
	    start = i;
	    numok = 0;
	}
	if ((j = strlen(list[i*3])
	     + strlen(list[i*3+1])
	     + strlen(list[i*3+2]) + 3) <= size) {
	    /* it will fit in this packet */
	    size -= j;
	    numok++;
	    i++;
	    continue;
	}
	if (!numok) {			/* a single subscription won't
					   fit into one packet */
	    free((char *)list);
	    return(ZERR_FIELDLEN);
	}
	retval = subscr_sendoff(&notice, &list[start*3], numok, authit);
	if (retval) {
	    free((char *)list);
	    return(retval);
	}
	start = -1;
    }
    if (numok)
	retval = subscr_sendoff(&notice, &list[start*3], numok, authit);
    free((char *)list);
    return(retval);
}

static Code_t
subscr_sendoff(notice, lyst, num, authit)
ZNotice_t *notice;
char **lyst;
int num;
int authit;
{
    register Code_t retval;
    ZNotice_t retnotice;

    retval = ZSendList(notice, lyst, num*3, ZAUTH);
    if (retval != ZERR_NONE && !authit)
	retval = ZSendList(notice, lyst, num*3, ZNOAUTH);

    if (retval != ZERR_NONE)
	return (retval);
    if ((retval = ZIfNotice(&retnotice, (struct sockaddr_in *)0,
				ZCompareUIDPred, (char *)&notice->z_uid)) !=
	ZERR_NONE)
	return (retval);
    if (retnotice.z_kind == SERVNAK) {
	ZFreeNotice(&retnotice);
	return (ZERR_SERVNAK);
    }
    if (retnotice.z_kind != SERVACK) {
	ZFreeNotice(&retnotice);
	return (ZERR_INTERNAL);
    }
    ZFreeNotice(&retnotice);
    return (ZERR_NONE);
}
