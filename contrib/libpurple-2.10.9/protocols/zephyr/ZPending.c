/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZPending function.
 *
 *	Created by:	Robert French
 *
 *	Copyright (c) 1987 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h".
 */

#include "internal.h"

int ZPending()
{
	int retval;

	if (ZGetFD() < 0) {
		errno = ZERR_NOPORT;
		return (-1);
	}

	if ((retval = Z_ReadEnqueue()) != ZERR_NONE) {
		errno = retval;
		return (-1);
	}

	return(ZQLength());
}
