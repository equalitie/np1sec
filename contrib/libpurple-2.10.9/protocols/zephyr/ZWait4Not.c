/* This file is part of the Project Athena Zephyr Notification System.
 * It contains the ZCheckIfNotice/select loop used for waiting for
 * a notice, with a timeout.
 *
 *	Copyright (c) 1991 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h".
 */

#include "internal.h"

#ifdef WIN32
#include <winsock2.h>

#ifndef ZEPHYR_USES_KERBEROS
static int  gettimeofday(struct timeval* tv, struct timezone* tz){
     union {
     long long ns100; /*time since 1 Jan 1601 in 100ns units */
       FILETIME ft;
     } _now;

     GetSystemTimeAsFileTime( &(_now.ft) );
     tv->tv_usec=(long)((_now.ns100 / 10LL) % 1000000LL );
     tv->tv_sec= (long)((_now.ns100-(116444736000000000LL))/10000000LL);
     return 0;
   }
#endif

#else
#include <sys/socket.h>
#endif

Code_t Z_WaitForNotice (notice, pred, arg, timeout)
     ZNotice_t *notice;
     int (*pred) __P((ZNotice_t *, void *));
     void *arg;
     int timeout;
{
  Code_t retval;
  struct timeval tv, t0;
  fd_set fdmask;
  int i, fd;

  retval = ZCheckIfNotice (notice, (struct sockaddr_in *) 0, pred,
			   (char *) arg);
  if (retval == ZERR_NONE)
    return ZERR_NONE;
  if (retval != ZERR_NONOTICE)
    return retval;

  fd = ZGetFD ();
  FD_ZERO (&fdmask);
  tv.tv_sec = timeout;
  tv.tv_usec = 0;
  gettimeofday (&t0, (struct timezone *)NULL);
  t0.tv_sec += timeout;
  while (1) {
    FD_SET (fd, &fdmask);
    i = select (fd + 1, &fdmask, (fd_set *) 0, (fd_set *) 0, &tv);
    if (i == 0)
      return ETIMEDOUT;
    if (i < 0 && errno != EINTR)
      return errno;
    if (i > 0) {
      retval = ZCheckIfNotice (notice, (struct sockaddr_in *) 0, pred,
			       (char *) arg);
      if (retval != ZERR_NONOTICE) /* includes ZERR_NONE */
	return retval;
    }
    gettimeofday (&tv, (struct timezone *) NULL);
    tv.tv_usec = t0.tv_usec - tv.tv_usec;
    if (tv.tv_usec < 0) {
      tv.tv_usec += 1000000;
      tv.tv_sec = t0.tv_sec - tv.tv_sec - 1;
    }
    else
      tv.tv_sec = t0.tv_sec - tv.tv_sec;
  }
  /*NOTREACHED*/
}
