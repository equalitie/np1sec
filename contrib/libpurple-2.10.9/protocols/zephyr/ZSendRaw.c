/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZSendRawNotice function.
 *
 *	Created by:	Robert French
 *
 *	Copyright (c) 1987 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h".
 */

#include "internal.h"

#if 0
Code_t ZSendRawNotice(notice)
    ZNotice_t *notice;
{
    Code_t retval;
    ZNotice_t newnotice;
    char *buffer;
    int len;

    if ((retval = ZFormatRawNotice(notice, &buffer, &len)) !=
	ZERR_NONE)
	return (retval);

    if ((retval = ZParseNotice(buffer, len, &newnotice)) != ZERR_NONE)
	return (retval);

    retval = Z_SendFragmentedNotice(&newnotice, len, NULL, Z_XmitFragment);

    free(buffer);

    return (retval);
}
#endif
