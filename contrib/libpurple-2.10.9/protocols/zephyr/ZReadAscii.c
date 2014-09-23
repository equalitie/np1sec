/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZReadAscii function.
 *
 *	Created by:	Robert French
 *
 *	Copyright (c) 1987, 1990 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h".
 */

#include "internal.h"

#define Z_cnvt_xtoi(c)  ((temp=(c)-'0'),(temp<10)?temp:((temp-='A'-'9'-1),(temp<16)?temp:-1))

Code_t ZReadAscii(ptr, len, field, num)
    char *ptr;
    int len;
    unsigned char *field;
    int num;
{
    int i;
    unsigned int hexbyte;
    register int c1, c2;
    register unsigned int temp;

    for (i=0;i<num;i++) {
	if (*ptr == ' ') {
	    ptr++;
	    if (--len < 0)
		return ZERR_BADFIELD;
	}
	if (ptr[0] == '0' && ptr[1] == 'x') {
	    ptr += 2;
	    len -= 2;
	    if (len < 0)
		return ZERR_BADFIELD;
	}
	c1 = Z_cnvt_xtoi(ptr[0]);
	if (c1 < 0)
		return ZERR_BADFIELD;
	c2 = Z_cnvt_xtoi(ptr[1]);
	if (c2 < 0)
		return ZERR_BADFIELD;
	hexbyte = (c1 << 4) | c2;
	field[i] = hexbyte;
	ptr += 2;
	len -= 2;
	if (len < 0)
	    return ZERR_BADFIELD;
    }

    return *ptr ? ZERR_BADFIELD : ZERR_NONE;
}

Code_t ZReadAscii32(ptr, len, value_ptr)
    char *ptr;
    int len;
    unsigned long *value_ptr;
{
    unsigned char buf[4];
    Code_t retval;

    retval = ZReadAscii(ptr, len, buf, 4);
    if (retval != ZERR_NONE)
	return retval;
    *value_ptr = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
    return ZERR_NONE;
}

Code_t ZReadAscii16(ptr, len, value_ptr)
    char *ptr;
    int len;
    unsigned short *value_ptr;
{
    unsigned char buf[2];
    Code_t retval;

    retval = ZReadAscii(ptr, len, buf, 2);
    if (retval != ZERR_NONE)
	return retval;
    *value_ptr = (buf[0] << 8) | buf[1];
    return ZERR_NONE;
}

