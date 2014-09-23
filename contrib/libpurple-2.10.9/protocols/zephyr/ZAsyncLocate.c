/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for asynchronous location functions.
 *
 *	Created by:	Marc Horowitz
 *
 *	Copyright (c) 1990,1991 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h".
 */

#include "internal.h"

Code_t ZRequestLocations(user, zald, kind, auth)
     const char *user;
     ZAsyncLocateData_t *zald;
     ZNotice_Kind_t kind;	/* UNSAFE, UNACKED, or ACKED */
     Z_AuthProc auth;
{
    int retval;
    ZNotice_t notice;
    size_t userlen, versionlen;

    if (ZGetFD() < 0)
	if ((retval = ZOpenPort((unsigned short *)0)) != ZERR_NONE)
	    return (retval);

    (void) memset((char *)&notice, 0, sizeof(notice));
    notice.z_kind = kind;
    notice.z_port = __Zephyr_port;
    notice.z_class = LOCATE_CLASS;
    notice.z_class_inst = user;
    notice.z_opcode = LOCATE_LOCATE;
    notice.z_sender = 0;
    notice.z_recipient = "";
    notice.z_default_format = "";
    notice.z_message_len = 0;

    if ((retval = ZSendNotice(&notice, auth)) != ZERR_NONE)
	return(retval);

    userlen = strlen(user) + 1;
    versionlen = strlen(notice.z_version) + 1;
    if ((zald->user = (char *) malloc(userlen)) == NULL) {
	return(ENOMEM);
    }
    if ((zald->version = (char *) malloc(versionlen)) == NULL) {
	free(zald->user);
	return(ENOMEM);
    }
    zald->uid = notice.z_multiuid;
    g_strlcpy(zald->user,user,userlen);
    g_strlcpy(zald->version,notice.z_version,versionlen);

    return(ZERR_NONE);
}

Code_t ZParseLocations(notice,zald,nlocs,user)
     ZNotice_t *notice;
     ZAsyncLocateData_t *zald;
     int *nlocs;
     char **user;
{
    char *ptr, *end;
    int i;

    ZFlushLocations();    /* This never fails (this function is part of the
			     library, so it is allowed to know this). */

    /* non-matching protocol version numbers means the
       server is probably an older version--must punt */

    if (zald && strcmp(notice->z_version, zald->version))
      return(ZERR_VERS);

    if (notice->z_kind == SERVNAK)
      return (ZERR_SERVNAK);

    /* flag ACKs as special */
    if (notice->z_kind == SERVACK &&
	!strcmp(notice->z_opcode, LOCATE_LOCATE)) {
	*nlocs = -1;
	return(ZERR_NONE);
    }

    if (notice->z_kind != ACKED)
	return (ZERR_INTERNAL);

    end = notice->z_message+notice->z_message_len;

    __locate_num = 0;

    for (ptr=notice->z_message;ptr<end;ptr++)
      if (!*ptr)
	__locate_num++;

    __locate_num /= 3;

    if (__locate_num)
      {
      __locate_list = (ZLocations_t *)malloc((unsigned)__locate_num*
					     sizeof(ZLocations_t));
      if (!__locate_list)
	return (ENOMEM);
    } else {
      __locate_list = 0;
    }

    for (ptr=notice->z_message, i=0; i<__locate_num; i++) {
       unsigned int len;

       len = strlen (ptr) + 1;
       __locate_list[i].host = (char *) malloc(len);
       if (!__locate_list[i].host)
	  return (ENOMEM);
       g_strlcpy(__locate_list[i].host, ptr,len);
       ptr += len;

       len = strlen (ptr) + 1;
       __locate_list[i].time = (char *) malloc(len);
       if (!__locate_list[i].time)
	  return (ENOMEM);
       g_strlcpy(__locate_list[i].time, ptr,len);
       ptr += len;

       len = strlen (ptr) + 1;
       __locate_list[i].tty = (char *) malloc(len);
       if (!__locate_list[i].tty)
	  return (ENOMEM);
       g_strlcpy(__locate_list[i].tty, ptr,len);
       ptr += len;
    }

    __locate_next = 0;
    *nlocs = __locate_num;
    if (user) {
	size_t len;    
	if (zald) {
	    len = strlen(zald->user) + 1;
	    if ((*user = (char *) malloc(len)) == NULL)
		return(ENOMEM);
	    g_strlcpy(*user,zald->user,len);
	} else {
	    len = strlen(notice->z_class_inst) + 1;
	    if ((*user = (char *) malloc(len)) == NULL)
		return(ENOMEM);
	    g_strlcpy(*user,notice->z_class_inst,len);
	}
    }
    return (ZERR_NONE);
}

int ZCompareALDPred(notice, zald)
     ZNotice_t *notice;
     void *zald;
{
    return(ZCompareUID(&(notice->z_multiuid),
		       &(((ZAsyncLocateData_t *) zald)->uid)));
}

void ZFreeALD(zald)
     ZAsyncLocateData_t *zald;
{
   if (!zald) return;

   if (zald->user) free(zald->user);
   if (zald->version) free(zald->version);
   (void) memset(zald, 0, sizeof(*zald));
}
