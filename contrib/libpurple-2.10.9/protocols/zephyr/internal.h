#ifndef __INTERNAL_H__
#define __INTERNAL_H__

#include <sysdep.h>

#ifdef LIBZEPHYR_EXT
#include <zephyr/zephyr.h>
#else
#include <zephyr_internal.h>
#endif

#ifndef WIN32
#include <netdb.h>
#endif



#ifdef WIN32

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 512
#endif

#define ETIMEDOUT WSAETIMEDOUT
#define EADDRINUSE WSAEADDRINUSE
#else /* !WIN32 */

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 4096
#endif

#endif

#ifdef ZEPHYR_USES_HESIOD
#include <hesiod.h>
#endif

#ifndef ZEPHYR_USES_KERBEROS
#define REALM_SZ	MAXHOSTNAMELEN
#define INST_SZ		0		/* no instances w/o Kerberos */
#define ANAME_SZ	9		/* size of a username + null */
#define CLOCK_SKEW	300		/* max time to cache packet ids */
#endif

#define SERVER_SVC_FALLBACK	htons((unsigned short) 2103)
#define HM_SVC_FALLBACK		htons((unsigned short) 2104)
#define HM_SRV_SVC_FALLBACK	htons((unsigned short) 2105)

#define ZAUTH_CKSUM_FAILED	(-2) /* Used only by server. */
#define ZAUTH_UNSET		(-3) /* Internal to client library. */
#define Z_MAXFRAGS		500	/* Max number of packet fragments */
#define Z_MAXNOTICESIZE		400000	/* Max size of incoming notice */
#define Z_MAXQUEUESIZE		1500000	/* Max size of input queue notices */
#define Z_FRAGFUDGE		13	/* Room to for multinotice field */
#define Z_NOTICETIMELIMIT	30	/* Time to wait for fragments */
#define Z_INITFILTERSIZE	30	/* Starting size of uid filter */

struct _Z_Hole {
    struct _Z_Hole	*next;
    int			first;
    int			last;
};

struct _Z_InputQ {
    struct _Z_InputQ	*next;
    struct _Z_InputQ	*prev;
    ZNotice_Kind_t	kind;
    unsigned ZEPHYR_INT32 timep;
    int			packet_len;
    char		*packet;
    int			complete;
    struct sockaddr_in	from;
    struct _Z_Hole	*holelist;
    ZUnique_Id_t	uid;
    int			auth;
    int			header_len;
    char		*header;
    int			msg_len;
    char		*msg;
};

extern struct _Z_InputQ *__Q_Head, *__Q_Tail;

extern int __Zephyr_open;	/* 0 if FD opened, 1 otherwise */
extern int __HM_set;		/* 0 if dest addr set, 1 otherwise */
extern int __Zephyr_server;	/* 0 if normal client, 1 if server or zhm */

extern ZLocations_t *__locate_list;
extern int __locate_num;
extern int __locate_next;

extern ZSubscription_t *__subscriptions_list;
extern int __subscriptions_num;
extern int __subscriptions_next;

extern int __Zephyr_port;		/* Port number */
extern struct in_addr __My_addr;

typedef Code_t (*Z_SendProc) __P((ZNotice_t *, char *, int, int));

struct _Z_InputQ *Z_GetFirstComplete __P((void));
struct _Z_InputQ *Z_GetNextComplete __P((struct _Z_InputQ *));
Code_t Z_XmitFragment __P((ZNotice_t*, char *,int,int));
void Z_RemQueue __P((struct _Z_InputQ *));
Code_t Z_AddNoticeToEntry __P((struct _Z_InputQ*, ZNotice_t*, int));
Code_t Z_FormatAuthHeader __P((ZNotice_t *, char *, int, int *, Z_AuthProc));
Code_t Z_FormatHeader __P((ZNotice_t *, char *, int, int *, Z_AuthProc));
Code_t Z_FormatRawHeader __P((ZNotice_t *, char*, int,
			      int*, char **, char **));
Code_t Z_ReadEnqueue __P((void));
Code_t Z_ReadWait __P((void));
Code_t Z_SendLocation __P((char*, char*, Z_AuthProc, char*));
Code_t Z_SendFragmentedNotice __P((ZNotice_t *notice, int len,
				   Z_AuthProc cert_func,
				   Z_SendProc send_func));
Code_t Z_WaitForComplete __P((void));
Code_t Z_WaitForNotice __P((ZNotice_t *notice,
			    int (*pred) __P((ZNotice_t *, void *)), void *arg,
			    int timeout));

#endif /* __INTERNAL_H__ */

