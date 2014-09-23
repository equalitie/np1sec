/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZMakeAscii function.
 *
 *	Created by:	Robert French
 *
 *	Copyright (c) 1987 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h".
 */

#include "internal.h"

static char *itox_chars = "0123456789ABCDEF";

Code_t ZMakeAscii(ptr, len, field, num)
    register char *ptr;
    int len;
    unsigned char *field;
    int num;
{
    int i;

    for (i=0;i<num;i++) {
	/* we need to add "0x" if we are between 4 byte pieces */
	if ((i & 3) == 0) {
	    if (len < (i?4:3))
		return ZERR_FIELDLEN;
	    /* except at the beginning, put a space in before the "0x" */
	    if (i) {
		*ptr++ = ' ';
		len--;
	    }
	    *ptr++ = '0';
	    *ptr++ = 'x';
	    len -= 2;
	}
	if (len < 3)
	    return ZERR_FIELDLEN;
	*ptr++ = itox_chars[(int) (field[i] >> 4)];
	*ptr++ = itox_chars[(int) (field[i] & 0xf)];
	len -= 2;
    }

    *ptr = '\0';
    return ZERR_NONE;
}

Code_t ZMakeAscii32(ptr, len, value)
    register char *ptr;
    int len;
    unsigned long value;
{
    if (len < 11)
	return ZERR_FIELDLEN;
    *ptr++ = '0';
    *ptr++ = 'x';
    *ptr++ = itox_chars[(value >> 28) & 0xf];
    *ptr++ = itox_chars[(value >> 24) & 0xf];
    *ptr++ = itox_chars[(value >> 20) & 0xf];
    *ptr++ = itox_chars[(value >> 16) & 0xf];
    *ptr++ = itox_chars[(value >> 12) & 0xf];
    *ptr++ = itox_chars[(value >>  8) & 0xf];
    *ptr++ = itox_chars[(value >>  4) & 0xf];
    *ptr++ = itox_chars[(value >>  0) & 0xf];
    *ptr = 0;
    return ZERR_NONE;
}

Code_t ZMakeAscii16(ptr, len, value)
    register char *ptr;
    int len;
    unsigned int value;
{
    if (len < 7)
	return ZERR_FIELDLEN;
    *ptr++ = '0';
    *ptr++ = 'x';
    *ptr++ = itox_chars[(value >> 12) & 0xf];
    *ptr++ = itox_chars[(value >>  8) & 0xf];
    *ptr++ = itox_chars[(value >>  4) & 0xf];
    *ptr++ = itox_chars[(value >>  0) & 0xf];
    *ptr = 0;
    return ZERR_NONE;
}

