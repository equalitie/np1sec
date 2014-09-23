/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for ZReceiveNotice function.
 *
 *	Created by:	Robert French
 *
 *	Copyright (c) 1987,1988 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h".
 */

#include "internal.h"

Code_t ZReceiveNotice(notice, from)
    ZNotice_t *notice;
    struct sockaddr_in *from;
{
    char *buffer;
    struct _Z_InputQ *nextq;
    int len, auth;
    Code_t retval;

    if ((retval = Z_WaitForComplete()) != ZERR_NONE)
	return (retval);

    nextq = Z_GetFirstComplete();

    if (!nextq)
	    return (ENOMEM);

    len = nextq->packet_len;

    if (!(buffer = (char *) malloc((unsigned) len)))
	return (ENOMEM);

    if (from)
	*from = nextq->from;

    (void) memcpy(buffer, nextq->packet, len);

    auth = nextq->auth;
    Z_RemQueue(nextq);

    if ((retval = ZParseNotice(buffer, len, notice)) != ZERR_NONE)
	return (retval);
    notice->z_checked_auth = auth;
    return ZERR_NONE;
}
