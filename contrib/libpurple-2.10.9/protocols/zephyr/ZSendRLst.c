/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZSendRawList function.
 *
 *	Created by:	John T. Kohl
 *
 *	Copyright (c) 1988 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h".
 */

#include "internal.h"

#if 0
Code_t ZSendRawList(notice, list, nitems)
    ZNotice_t *notice;
    char *list[];
    int nitems;
{
    return(ZSrvSendRawList(notice, list, nitems, Z_XmitFragment));
}

Code_t ZSrvSendRawList(notice, list, nitems, send_routine)
    ZNotice_t *notice;
    char *list[];
    int nitems;
    Code_t (*send_routine)();
{
    Code_t retval;
    ZNotice_t newnotice;
    char *buffer;
    int len;

    if ((retval = ZFormatRawNoticeList(notice, list, nitems, &buffer,
				       &len)) != ZERR_NONE)
	return (retval);

    if ((retval = ZParseNotice(buffer, len, &newnotice)) != ZERR_NONE)
	return (retval);

    retval = Z_SendFragmentedNotice(&newnotice, len, NULL, send_routine);

    free(buffer);

    return (retval);
}
#endif
