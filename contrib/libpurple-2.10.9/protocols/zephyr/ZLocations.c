/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZSetLocation, ZUnsetLocation, and
 * ZFlushMyLocations functions.
 *
 *	Created by:	Robert French
 *
 *	Copyright (c) 1987,1988,1991 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h".
 */

#include "internal.h"

#ifndef WIN32
#include <pwd.h>
#endif

#include <stdlib.h>
#include <errno.h>

Code_t ZSetLocation(exposure)
    char *exposure;
{
    return (Z_SendLocation(LOGIN_CLASS, exposure, ZAUTH,
			   "$sender logged in to $1 on $3 at $2"));
}

Code_t ZUnsetLocation()
{
    return (Z_SendLocation(LOGIN_CLASS, LOGIN_USER_LOGOUT, ZNOAUTH,
			   "$sender logged out of $1 on $3 at $2"));
}

Code_t ZFlushMyLocations()
{
    return (Z_SendLocation(LOGIN_CLASS, LOGIN_USER_FLUSH, ZAUTH, ""));
}

static char host[MAXHOSTNAMELEN];
static char *mytty = NULL;
static int reenter = 0;

Code_t Z_SendLocation(class, opcode, auth, format)
    char *class;
    char *opcode;
    Z_AuthProc auth;
    char *format;
{
    int retval;
    time_t ourtime;
    ZNotice_t notice, retnotice;
    char *bptr[3];
#ifndef X_DISPLAY_MISSING
    char *display;
#endif
#ifndef WIN32
    char *ttyp;
    char *p;
#endif
    struct hostent *hent;
    short wg_port = ZGetWGPort();

    (void) memset((char *)&notice, 0, sizeof(notice));
    notice.z_kind = ACKED;
    notice.z_port = (unsigned short) ((wg_port == -1) ? 0 : wg_port);
    notice.z_class = class;
    notice.z_class_inst = ZGetSender();
    notice.z_opcode = opcode;
    notice.z_sender = 0;
    notice.z_recipient = "";
    notice.z_num_other_fields = 0;
    notice.z_default_format = format;

    /*
      keep track of what we said before so that we can be consistent
      when changing location information.
      This is done mainly for the sake of the WindowGram client.
     */

    if (!reenter) {
	    if (gethostname(host, MAXHOSTNAMELEN) < 0)
		    return (errno);

	    hent = gethostbyname(host);
	    if (hent) {
	      (void) strncpy(host, hent->h_name, sizeof(host));
	      host[sizeof(host) - 1] = '\0';
	    }
#ifndef X_DISPLAY_MISSING
	    if ((display = getenv("DISPLAY")) && *display) {
		    mytty = g_strdup(display);
	    } else {
#endif
#ifdef WIN32
		    mytty = g_strdup("WinPurple");
#else
		    ttyp = ttyname(0);
		    if (ttyp && *ttyp) {
			p = strchr(ttyp + 1, '/');
			mytty = g_strdup((p) ? p + 1 : ttyp);
		    } else {
			mytty = g_strdup("unknown");
		    }
#endif
#ifndef X_DISPLAY_MISSING
	    }
#endif
	    reenter = 1;
    }

    ourtime = time((time_t *)0);
    bptr[0] = host;
    bptr[1] = ctime(&ourtime);
    bptr[1][strlen(bptr[1])-1] = '\0';
    bptr[2] = mytty;

    if ((retval = ZSendList(&notice, bptr, 3, auth)) != ZERR_NONE)
	return (retval);

    retval = Z_WaitForNotice (&retnotice, ZCompareUIDPred, &notice.z_uid,
			      SRV_TIMEOUT);
    if (retval != ZERR_NONE)
      return retval;

    if (retnotice.z_kind == SERVNAK) {
	if (!retnotice.z_message_len) {
	    ZFreeNotice(&retnotice);
	    return (ZERR_SERVNAK);
	}
	if (!strcmp(retnotice.z_message, ZSRVACK_NOTSENT)) {
	    ZFreeNotice(&retnotice);
	    return (ZERR_AUTHFAIL);
	}
	if (!strcmp(retnotice.z_message, ZSRVACK_FAIL)) {
	    ZFreeNotice(&retnotice);
	    return (ZERR_LOGINFAIL);
	}
	ZFreeNotice(&retnotice);
	return (ZERR_SERVNAK);
    }

    if (retnotice.z_kind != SERVACK) {
	ZFreeNotice(&retnotice);
	return (ZERR_INTERNAL);
    }

    if (!retnotice.z_message_len) {
	ZFreeNotice(&retnotice);
	return (ZERR_INTERNAL);
    }

    if (strcmp(retnotice.z_message, ZSRVACK_SENT) &&
	strcmp(retnotice.z_message, ZSRVACK_NOTSENT)) {
	ZFreeNotice(&retnotice);
	return (ZERR_INTERNAL);
    }

    ZFreeNotice(&retnotice);

    return (ZERR_NONE);
}
