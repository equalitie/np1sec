/* This file is part of the Project Athena Zephyr Notification System.
 * It contains system-dependent header code.
 *
 *	Created by:	Greg Hudson
 *
 *	Copyright (c) 1988,1991 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h".
 */

#ifndef __SYSDEP_H__
#define __SYSDEP_H__

#include <config.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <signal.h>
#ifndef WIN32
#include <syslog.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/time.h>

#if defined(STDC_HEADERS) || defined(HAVE_STDLIB_H)
# include <stdlib.h>
#else
# ifdef HAVE_MALLOC_H
#  include <malloc.h>
# else
char *malloc(), *realloc(void);
# endif
char *getenv(), *strerror(), *ctime(), *strcpy(void);
time_t time(void);
ZEPHYR_INT32 random(void);
#endif

#ifndef HAVE_RANDOM
#ifdef HAVE_LRAND48
#define random lrand48
#define srandom srand48
#else
#define random rand
#define srandom srand
#endif
#endif

#ifndef HAVE_STRERROR
extern char *sys_errlist[];
# define strerror(x) (sys_errlist[(x)])
#endif

/* Strings. */
#if defined(STDC_HEADERS) || defined(HAVE_STRING_H)
# include <string.h>
#else
# ifndef HAVE_STRCHR
#  define strchr index
#  define strrchr rindex
# endif
char *strchr(), *strrchr(void);
# ifndef HAVE_MEMCPY
#  define memcpy(d, s, n) bcopy ((s), (d), (n))
#  define memcmp bcmp
# endif
# ifndef HAVE_MEMMOVE
#  define memmove(d, s, n) bcopy ((s), (d), (n))
# endif
#endif

/* Exit status handling and wait(). */
#ifdef HAVE_SYS_WAIT_H
# include <sys/wait.h>
#endif
#ifndef WEXITSTATUS
# define WEXITSTATUS(stat_val) ((unsigned)(stat_val) >> 8)
#endif
#ifndef WIFEXITED
# define WIFEXITED(stat_val) (((stat_val) & 255) == 0)
#endif

#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#endif

/* Because we have public header files (and our prototypes need to agree with
 * those header files, use __STDC__ to guess whether the compiler can handle
 * stdarg, const, and prototypes. */
#ifdef __STDC__
# include <stdarg.h>
# define VA_START(ap, last) va_start(ap, last)
# ifndef __P
#  define __P(x) x
# endif
#else
# include <varargs.h>
# define VA_START(ap, last) va_start(ap)
# define const
# ifndef __P
#  define __P(x) ()
# endif
#endif

/* openlog(). */
#ifdef LOG_AUTH
/* A decent syslog */
#define OPENLOG(str, opts, facility)	openlog(str, opts, facility)
#else
/* Probably a 4.2-type syslog */
#define OPENLOG(str, opts, facility)	openlog(str, opts)
#endif

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif

#ifdef HAVE_PATHS_H
# include <paths.h>
# define TEMP_DIRECTORY _PATH_VARTMP
#else
# define TEMP_DIRECTORY FOUND_TMP
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#else
# ifdef HAVE_SYS_FILE_H
#  include <sys/file.h>
# endif
uid_t getuid(void);
char *ttyname(void);
#ifdef HAVE_GETHOSTID
ZEPHYR_INT32 gethostid(void);
#endif
#endif

#ifndef STDIN_FILENO
#define STDIN_FILENO 0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2
#endif

#ifdef HAVE_TERMIOS_H
# include <termios.h>
#else
# ifdef HAVE_SYS_FILIO_H
#  include <sys/filio.h>
# else
#  ifdef HAVE_SGTTY_H
#   include <sgtty.h>
#  endif
#  ifdef HAVE_SYS_IOCTL_H
#   include <sys/ioctl.h>
#  endif
# endif
#endif

/* Kerberos compatibility. */
#ifdef ZEPHYR_USES_KERBEROS
# include <krb.h>
#ifdef WIN32

#else
# include <krb_err.h>
#endif /* WIN32 */
# include <des.h>
#ifndef WIN32
# ifndef HAVE_KRB_GET_ERR_TEXT
#  define krb_get_err_text(n)	krb_err_txt[n]
# endif
#endif /* WIN32 */
# ifndef HAVE_KRB_LOG
#  define krb_log		log
# endif
#endif /* ZEPHYR_USES_KERBEROS */

#ifdef HAVE_SYS_UIO_H
# include <sys/uio.h>
#endif

#ifdef HAVE_SYS_UTSNAME_H
# include <sys/utsname.h>
#endif

#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif

#ifdef HAVE_SYS_MSGBUF_H
#include <sys/msgbuf.h>
#endif

#ifndef MSG_BSIZE
#define MSG_BSIZE BUFSIZ
#endif

#endif /* __SYSDEP_H__ */

