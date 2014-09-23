/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZCheckIfNotice function.
 *
 *	Created by:	Robert French
 *
 *	Copyright (c) 1987,1988 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h".
 */

#include "internal.h"

Code_t ZCheckIfNotice(notice, from, predicate, args)
    ZNotice_t *notice;
    struct sockaddr_in *from;
    register int (*predicate) __P((ZNotice_t *, void *));
    void *args;
{
    ZNotice_t tmpnotice;
    Code_t retval;
    register char *buffer;
    register struct _Z_InputQ *qptr;

    if ((retval = Z_ReadEnqueue()) != ZERR_NONE)
	return (retval);

    qptr = Z_GetFirstComplete();

    while (qptr) {
	if ((retval = ZParseNotice(qptr->packet, qptr->packet_len,
				   &tmpnotice)) != ZERR_NONE)
	    return (retval);
	if ((*predicate)(&tmpnotice, args)) {
	    if (!(buffer = (char *) malloc((unsigned) qptr->packet_len)))
		return (ENOMEM);
	    (void) memcpy(buffer, qptr->packet, qptr->packet_len);
	    if (from)
		*from = qptr->from;
	    if ((retval = ZParseNotice(buffer, qptr->packet_len,
				       notice)) != ZERR_NONE) {
		free(buffer);
		return (retval);
	    }
	    Z_RemQueue(qptr);
	    return (ZERR_NONE);
	}
	qptr = Z_GetNextComplete(qptr);
    }

    return (ZERR_NONOTICE);
}
