/* This file is part of the Project Athena Zephyr Notification System.
 * It contains global definitions
 *
 *	Created by:	Robert French
 *
 *	Copyright (c) 1987,1988,1991 by the Massachusetts Institute of
 *	Technology. For copying and distribution information, see the
 *	file "mit-copyright.h".
 */

#ifndef __ZEPHYR_H__
#define __ZEPHYR_H__

#include <config.h>

#include <glib.h>

#include <sys/types.h>
#include <sys/time.h>

#include <zephyr_err.h>

#ifndef IPPROTO_MAX	/* Make sure not already included */
#ifndef WIN32
#include <netinet/in.h>
#endif
#endif

/* Use __STDC__ to guess whether we can use stdarg, prototypes, and const.
 * This is a public header file, so autoconf can't help us here. */
#ifdef __STDC__
# include <stdarg.h>
# define ZP(x) x
# define ZCONST const
#else
# define ZP(x) ()
# define ZCONST
#endif

#ifdef WIN32
/* this really should be uint32_t */
/*typedef unsigned int in_addr_t;
struct in_addr
{
  in_addr_t s_addr;
}; */
#include <winsock2.h>
#endif

/* Service names */
#define	HM_SVCNAME		"zephyr-hm"
#define HM_SRV_SVCNAME		"zephyr-hm-srv"
#define	SERVER_SVCNAME		"zephyr-clt"
#define SERVER_SERVICE		"zephyr"
#define SERVER_INSTANCE		"zephyr"

#define ZVERSIONHDR	"ZEPH"
#define ZVERSIONMAJOR	0
#define ZVERSIONMINOR	2

#define Z_MAXPKTLEN		1024
#define Z_MAXHEADERLEN		800
#define Z_MAXOTHERFIELDS	10	/* Max unknown fields in ZNotice_t */
#define Z_NUMFIELDS		17

/* Authentication levels returned by ZCheckAuthentication */
#define ZAUTH_FAILED    	(-1)
#define ZAUTH_YES       	1
#define ZAUTH_NO        	0

typedef char ZPacket_t[Z_MAXPKTLEN];

/* Packet type */
typedef enum {
    UNSAFE, UNACKED, ACKED, HMACK, HMCTL, SERVACK, SERVNAK, CLIENTACK, STAT
} ZNotice_Kind_t;
extern ZCONST char *ZNoticeKinds[9];

/* Unique ID format */
typedef struct _ZUnique_Id_t {
    struct	in_addr zuid_addr;
    struct	timeval	tv;
} ZUnique_Id_t;

/* Checksum */
typedef unsigned long ZChecksum_t;

/* Notice definition */
typedef struct _ZNotice_t {
    char		*z_packet;
    char		*z_version;
    ZNotice_Kind_t	z_kind;
    ZUnique_Id_t	z_uid;
#define z_sender_addr	z_uid.zuid_addr
    struct		timeval z_time;
    unsigned short	z_port;
    int			z_auth;
    int			z_checked_auth;
    int			z_authent_len;
    char		*z_ascii_authent;
    char		*z_class;
    const char		*z_class_inst;
    char		*z_opcode;
    char		*z_sender;
    const char		*z_recipient;
    char		*z_default_format;
    char		*z_multinotice;
    ZUnique_Id_t	z_multiuid;
    ZChecksum_t		z_checksum;
    int			z_num_other_fields;
    char		*z_other_fields[Z_MAXOTHERFIELDS];
    caddr_t		z_message;
    int			z_message_len;
} ZNotice_t;

/* Subscription structure */
typedef struct _ZSubscriptions_t {
    char	*zsub_recipient;
    char	*zsub_class;
    char	*zsub_classinst;
} ZSubscription_t;

/* Function return code */
typedef int Code_t;

/* Locations structure */
typedef struct _ZLocations_t {
    char	*host;
    char	*time;
    char	*tty;
} ZLocations_t;

typedef struct _ZAsyncLocateData_t {
    char		*user;
    ZUnique_Id_t	uid;
    char		*version;
} ZAsyncLocateData_t;

/* for ZSetDebug */
#ifdef Z_DEBUG
void (*__Z_debug_print) ZP((ZCONST char *fmt, va_list args, void *closure));
void *__Z_debug_print_closure;
#endif

int ZCompareUIDPred ZP((ZNotice_t *, void *));
int ZCompareMultiUIDPred ZP((ZNotice_t *, void *));

/* Defines for ZFormatNotice, et al. */
typedef Code_t (*Z_AuthProc) ZP((ZNotice_t*, char *, int, int *));
Code_t ZMakeAuthentication ZP((ZNotice_t*, char *,int, int*));

char *ZGetSender ZP((void));
char *ZGetVariable ZP((char *));
Code_t ZSetVariable ZP((char *var, char *value));
Code_t ZUnsetVariable ZP((char *var));
int ZGetWGPort ZP((void));
Code_t ZSetDestAddr ZP((struct sockaddr_in *));
Code_t ZFormatNoticeList ZP((ZNotice_t*, char**, int,
			     char **, int*, Z_AuthProc));
Code_t ZParseNotice ZP((char*, int, ZNotice_t *));
Code_t ZReadAscii ZP((char*, int, unsigned char*, int));
Code_t ZReadAscii32 ZP((char *, int, unsigned long *));
Code_t ZReadAscii16 ZP((char *, int, unsigned short *));
Code_t ZSendPacket ZP((char*, int, int));
Code_t ZSendList ZP((ZNotice_t*, char *[], int, Z_AuthProc));
Code_t ZSrvSendList ZP((ZNotice_t*, char*[], int, Z_AuthProc, Code_t (*)()));
Code_t ZSendNotice ZP((ZNotice_t *, Z_AuthProc));
Code_t ZSrvSendNotice ZP((ZNotice_t*, Z_AuthProc, Code_t (*)()));
Code_t ZFormatNotice ZP((ZNotice_t*, char**, int*, Z_AuthProc));
Code_t ZFormatSmallNotice ZP((ZNotice_t*, ZPacket_t, int*, Z_AuthProc));
Code_t ZFormatRawNoticeList ZP((ZNotice_t *notice, char *list[], int nitems,
				char **buffer, int *ret_len));
Code_t ZLocateUser ZP((char *, int *, Z_AuthProc));
Code_t ZRequestLocations ZP((const char *, ZAsyncLocateData_t *,
			     ZNotice_Kind_t, Z_AuthProc));
Code_t ZhmStat ZP((struct in_addr *, ZNotice_t *));
Code_t ZInitialize ZP((void));
Code_t ZSetServerState ZP((int));
Code_t ZSetFD ZP((int));
Code_t ZFormatSmallRawNotice ZP((ZNotice_t*, ZPacket_t, int*));
int ZCompareUID ZP((ZUnique_Id_t*, ZUnique_Id_t*));
Code_t ZMakeAscii ZP((char*, int, unsigned char*, int));
Code_t ZMakeAscii32 ZP((char *, int, unsigned long));
Code_t ZMakeAscii16 ZP((char *, int, unsigned int));
Code_t ZReceivePacket ZP((ZPacket_t, int*, struct sockaddr_in*));
Code_t ZCheckAuthentication ZP((ZNotice_t*, struct sockaddr_in*));
Code_t ZSetLocation ZP((char *exposure));
Code_t ZUnsetLocation ZP((void));
Code_t ZFlushMyLocations ZP((void));
Code_t ZFormatRawNotice ZP((ZNotice_t *, char**, int *));
Code_t ZRetrieveSubscriptions ZP((unsigned short, int*));
Code_t ZOpenPort ZP((unsigned short *port));
Code_t ZClosePort ZP((void));
Code_t ZFlushLocations ZP((void));
Code_t ZFlushSubscriptions ZP((void));
Code_t ZFreeNotice ZP((ZNotice_t *notice));
Code_t ZParseLocations ZP((register ZNotice_t *notice,
			   register ZAsyncLocateData_t *zald, int *nlocs,
			   char **user));
int ZCompareALDPred ZP((ZNotice_t *notice, void *zald));
void ZFreeALD ZP((register ZAsyncLocateData_t *zald));
Code_t ZCheckIfNotice ZP((ZNotice_t *notice, struct sockaddr_in *from,
			  register int (*predicate) ZP((ZNotice_t *,void *)),
			  void *args));
Code_t ZPeekPacket ZP((char **buffer, int *ret_len,
		       struct sockaddr_in *from));
Code_t ZPeekNotice ZP((ZNotice_t *notice, struct sockaddr_in *from));
Code_t ZIfNotice ZP((ZNotice_t *notice, struct sockaddr_in *from,
		     int (*predicate) ZP((ZNotice_t *, void *)), void *args));
Code_t ZSubscribeTo ZP((ZSubscription_t *sublist, int nitems,
			unsigned int port));
Code_t ZSubscribeToSansDefaults ZP((ZSubscription_t *sublist, int nitems,
				    unsigned int port));
Code_t ZUnsubscribeTo ZP((ZSubscription_t *sublist, int nitems,
			  unsigned int port));
Code_t ZCancelSubscriptions ZP((unsigned int port));
int ZPending ZP((void));
Code_t ZReceiveNotice ZP((ZNotice_t *notice, struct sockaddr_in *from));
#ifdef Z_DEBUG
void Z_debug ZP((ZCONST char *, ...));
#endif

#undef ZP

/* Compatibility */
#define	ZNewLocateUser ZLocateUser

/* Macros to retrieve Zephyr library values. */
extern int __Zephyr_fd;
extern int __Q_CompleteLength;
extern struct sockaddr_in __HM_addr;
extern char __Zephyr_realm[];
#define ZGetFD()	__Zephyr_fd
#define ZQLength()	__Q_CompleteLength
#define ZGetDestAddr()	__HM_addr
#define ZGetRealm()	__Zephyr_realm

#ifdef Z_DEBUG
void ZSetDebug ZP((void (*)(ZCONST char *, va_list, void *), void *));
#define ZSetDebug(proc,closure)    (__Z_debug_print=(proc), \
				    __Z_debug_print_closure=(closure), \
				    (void) 0)
#else
#define	ZSetDebug(proc,closure)
#endif

/* Maximum queue length */
#define Z_MAXQLEN 		30

/* Successful function return */
#define ZERR_NONE		0

/* Hostmanager wait time (in secs) */
#define HM_TIMEOUT		1

/* Server wait time (in secs) */
#define	SRV_TIMEOUT		30

#define ZAUTH (ZMakeAuthentication)
#define ZNOAUTH ((Z_AuthProc)0)

/* Packet strings */
#define ZSRVACK_SENT		"SENT"	/* SERVACK codes */
#define ZSRVACK_NOTSENT		"LOST"
#define ZSRVACK_FAIL		"FAIL"

/* Server internal class */
#define ZEPHYR_ADMIN_CLASS	"ZEPHYR_ADMIN"	/* Class */

/* Control codes sent to a server */
#define ZEPHYR_CTL_CLASS	"ZEPHYR_CTL"	/* Class */

#define ZEPHYR_CTL_CLIENT	"CLIENT"	/* Inst: From client */
#define CLIENT_SUBSCRIBE	"SUBSCRIBE"	/* Opcode: Subscribe */
#define CLIENT_SUBSCRIBE_NODEFS	"SUBSCRIBE_NODEFS"	/* Opcode: Subscribe */
#define CLIENT_UNSUBSCRIBE	"UNSUBSCRIBE"	/* Opcode: Unsubsubscribe */
#define CLIENT_CANCELSUB	"CLEARSUB"	/* Opcode: Clear all subs */
#define CLIENT_GIMMESUBS	"GIMME"		/* Opcode: Give me subs */
#define	CLIENT_GIMMEDEFS	"GIMMEDEFS"	/* Opcode: Give me default
						 * subscriptions */

#define ZEPHYR_CTL_HM		"HM"		/* Inst: From HM */
#define HM_BOOT			"BOOT"		/* Opcode: Boot msg */
#define HM_FLUSH		"FLUSH"		/* Opcode: Flush me */
#define HM_DETACH		"DETACH"	/* Opcode: Detach me */
#define HM_ATTACH		"ATTACH"	/* Opcode: Attach me */

/* Control codes send to a HostManager */
#define	HM_CTL_CLASS		"HM_CTL"	/* Class */

#define HM_CTL_SERVER		"SERVER"	/* Inst: From server */
#define SERVER_SHUTDOWN		"SHUTDOWN"	/* Opcode: Server shutdown */
#define SERVER_PING		"PING"		/* Opcode: PING */

#define HM_CTL_CLIENT           "CLIENT"        /* Inst: From client */
#define CLIENT_FLUSH            "FLUSH"         /* Opcode: Send flush to srv */
#define CLIENT_NEW_SERVER       "NEWSERV"       /* Opcode: Find new server */

/* HM Statistics */
#define HM_STAT_CLASS		"HM_STAT"	/* Class */

#define HM_STAT_CLIENT		"HMST_CLIENT"	/* Inst: From client */
#define HM_GIMMESTATS		"GIMMESTATS"	/* Opcode: get stats */

/* Login class messages */
#define LOGIN_CLASS		"LOGIN"		/* Class */

/* Class Instance is principal of user who is logging in or logging out */

#define EXPOSE_NONE		"NONE"		/* Opcode: Not visible */
#define EXPOSE_OPSTAFF		"OPSTAFF"	/* Opcode: Opstaff visible */
#define EXPOSE_REALMVIS		"REALM-VISIBLE"	/* Opcode: Realm visible */
#define EXPOSE_REALMANN		"REALM-ANNOUNCED"/* Opcode: Realm announced */
#define EXPOSE_NETVIS		"NET-VISIBLE"	/* Opcode: Net visible */
#define EXPOSE_NETANN		"NET-ANNOUNCED"	/* Opcode: Net announced */
#define	LOGIN_USER_LOGIN	"USER_LOGIN"	/* Opcode: user login
						   (from server) */
#define LOGIN_USER_LOGOUT	"USER_LOGOUT"	/* Opcode: User logout */
#define	LOGIN_USER_FLUSH	"USER_FLUSH"	/* Opcode: flush all locs */

/* Locate class messages */
#define LOCATE_CLASS		"USER_LOCATE"	/* Class */

#define LOCATE_HIDE		"USER_HIDE"	/* Opcode: Hide me */
#define LOCATE_UNHIDE		"USER_UNHIDE"	/* Opcode: Unhide me */

/* Class Instance is principal of user to locate */
#define LOCATE_LOCATE		"LOCATE"	/* Opcode: Locate user */

/* WG_CTL class messages */
#define WG_CTL_CLASS		"WG_CTL"	/* Class */

#define WG_CTL_USER		"USER"		/* Inst: User request */
#define USER_REREAD		"REREAD"	/* Opcode: Reread desc file */
#define USER_SHUTDOWN		"SHUTDOWN"	/* Opcode: Go catatonic */
#define USER_STARTUP		"STARTUP"	/* Opcode: Come out of it */
#define USER_EXIT		"EXIT"		/* Opcode: Exit the client */

#endif /* __ZEPHYR_H__ */
