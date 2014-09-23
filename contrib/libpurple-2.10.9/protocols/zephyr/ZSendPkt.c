/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZSendPacket function.
 *
 *	Created by:	Robert French
 *
 *	Copyright (c) 1987,1991 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h".
 */

#include "internal.h"
#ifdef WIN32
#include <winsock.h>
#else
#include <sys/socket.h>
#endif

static int wait_for_hmack(ZNotice_t *notice, void *uid);

Code_t ZSendPacket(packet, len, waitforack)
    char *packet;
    int len;
    int waitforack;
{
    Code_t retval;
    struct sockaddr_in dest;
    ZNotice_t notice, acknotice;

    if (!packet || len < 0)
	return (ZERR_ILLVAL);

    if (len > Z_MAXPKTLEN)
	return (ZERR_PKTLEN);

    if (ZGetFD() < 0)
	if ((retval = ZOpenPort((unsigned short *)0)) != ZERR_NONE)
	    return (retval);

    dest = ZGetDestAddr();

    if (sendto(ZGetFD(), packet, len, 0, (struct sockaddr *)&dest,
	       sizeof(dest)) < 0)
	return (errno);

    if (!waitforack)
	return (ZERR_NONE);

    if ((retval = ZParseNotice(packet, len, &notice)) != ZERR_NONE)
	return (retval);

    retval = Z_WaitForNotice (&acknotice, wait_for_hmack, &notice.z_uid,
			      HM_TIMEOUT);
    if (retval == ETIMEDOUT)
      return ZERR_HMDEAD;
    if (retval == ZERR_NONE)
      ZFreeNotice (&acknotice);
    return retval;
}

static int wait_for_hmack(ZNotice_t *notice, void *uid)
{
    return (notice->z_kind == HMACK && ZCompareUID(&notice->z_uid, (ZUnique_Id_t *)uid));
}
