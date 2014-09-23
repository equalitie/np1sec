/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZFormatRawNoticeList function.
 *
 *	Created by:	Robert French
 *
 *	Copyright (c) 1987 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h".
 */

#include "internal.h"

Code_t ZFormatRawNoticeList(notice, list, nitems, buffer, ret_len)
    ZNotice_t *notice;
    char *list[];
    int nitems;
    char **buffer;
    int *ret_len;
{
    char header[Z_MAXHEADERLEN];
    int hdrlen, i, size;
    char *ptr;
    Code_t retval;

    if ((retval = Z_FormatRawHeader(notice, header, sizeof(header),
				    &hdrlen, NULL, NULL)) != ZERR_NONE)
	return (retval);

    size = 0;
    for (i=0;i<nitems;i++)
	size += strlen(list[i])+1;

    *ret_len = hdrlen+size;

    if (!(*buffer = (char *) malloc((unsigned) *ret_len)))
	return (ENOMEM);

    (void) memcpy(*buffer, header, hdrlen);

    ptr = *buffer+hdrlen;

    for (;nitems;nitems--, list++) {
	i = strlen(*list)+1;
	(void) memcpy(ptr, *list, i);
	ptr += i;
    }

    return (ZERR_NONE);
}
