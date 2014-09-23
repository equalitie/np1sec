/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZInitialize function.
 *
 *	Created by:	Robert French
 *
 *	Copyright (c) 1987, 1991 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h".
 */

#ifdef ZEPHYR_USES_KERBEROS
#ifdef WIN32

#else
#include <krb_err.h>
#endif
#endif

#include "internal.h"

#ifdef WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#endif


#ifndef INADDR_NONE
#define INADDR_NONE 0xffffffff
#endif

Code_t ZInitialize()
{
    struct servent *hmserv;
    struct hostent *hostent;
    char addr[4], hostname[MAXHOSTNAMELEN];
    struct in_addr servaddr;
    struct sockaddr_in sin;
    int s;
    socklen_t sinsize = sizeof(sin);
    Code_t code;
    ZNotice_t notice;
#ifdef ZEPHYR_USES_KERBEROS
    char *krealm = NULL;
    int krbval;
    char d1[ANAME_SZ], d2[INST_SZ];

    /*    initialize_krb_error_table(); */
#endif

    initialize_zeph_error_table();

    (void) memset((char *)&__HM_addr, 0, sizeof(__HM_addr));

    __HM_addr.sin_family = AF_INET;

    /* Set up local loopback address for HostManager */
    addr[0] = 127;
    addr[1] = 0;
    addr[2] = 0;
    addr[3] = 1;

    hmserv = (struct servent *)getservbyname(HM_SVCNAME, "udp");
    __HM_addr.sin_port = (hmserv) ? hmserv->s_port : HM_SVC_FALLBACK;

    (void) memcpy((char *)&__HM_addr.sin_addr, addr, 4);

    __HM_set = 0;

    /* Initialize the input queue */
    __Q_Tail = NULL;
    __Q_Head = NULL;

    /* if the application is a server, there might not be a zhm.  The
       code will fall back to something which might not be "right",
       but this is is ok, since none of the servers call krb_rd_req. */

    servaddr.s_addr = INADDR_NONE;
    if (! __Zephyr_server) {
       if ((code = ZOpenPort(NULL)) != ZERR_NONE)
	  return(code);

       if ((code = ZhmStat(NULL, &notice)) != ZERR_NONE)
	  return(code);

       ZClosePort();

       /* the first field, which is NUL-terminated, is the server name.
	  If this code ever support a multiplexing zhm, this will have to
	  be made smarter, and probably per-message */

#ifdef ZEPHYR_USES_KERBEROS
       krealm = krb_realmofhost(notice.z_message);
#endif
       hostent = gethostbyname(notice.z_message);
       if (hostent && hostent->h_addrtype == AF_INET)
	   memcpy(&servaddr, hostent->h_addr, sizeof(servaddr));

       ZFreeNotice(&notice);
    }

#ifdef ZEPHYR_USES_KERBEROS
    if (krealm) {
      g_strlcpy(__Zephyr_realm, krealm, REALM_SZ);
    } else if ((krb_get_tf_fullname(TKT_FILE, d1, d2, __Zephyr_realm)
		!= KSUCCESS) &&
	       ((krbval = krb_get_lrealm(__Zephyr_realm, 1)) != KSUCCESS)) {
	return (krbval);
    }
#else
    g_strlcpy(__Zephyr_realm, "local-realm", REALM_SZ);
#endif

    __My_addr.s_addr = INADDR_NONE;
    if (servaddr.s_addr != INADDR_NONE) {
	/* Try to get the local interface address by connecting a UDP
	 * socket to the server address and getting the local address.
	 * Some broken operating systems (e.g. Solaris 2.0-2.5) yield
	 * INADDR_ANY (zero), so we have to check for that. */
	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s != -1) {
	    memset(&sin, 0, sizeof(sin));
	    sin.sin_family = AF_INET;
	    memcpy(&sin.sin_addr, &servaddr, sizeof(servaddr));
	    sin.sin_port = HM_SRV_SVC_FALLBACK;
	    if (connect(s, (struct sockaddr *) &sin, sizeof(sin)) == 0
		&& getsockname(s, (struct sockaddr *) &sin, &sinsize) == 0
		&& sin.sin_addr.s_addr != 0)
		memcpy(&__My_addr, &sin.sin_addr, sizeof(__My_addr));
	    close(s);
	}
    }
    if (__My_addr.s_addr == INADDR_NONE) {
	/* We couldn't figure out the local interface address by the
	 * above method.  Try by resolving the local hostname.  (This
	 * is a pretty broken thing to do, and unfortunately what we
	 * always do on server machines.) */
	if (gethostname(hostname, sizeof(hostname)) == 0) {
	    hostent = gethostbyname(hostname);
	    if (hostent && hostent->h_addrtype == AF_INET)
		memcpy(&__My_addr, hostent->h_addr, sizeof(__My_addr));
	}
    }
    /* If the above methods failed, zero out __My_addr so things will
     * sort of kind of work. */
    if (__My_addr.s_addr == INADDR_NONE)
	__My_addr.s_addr = 0;

    /* Get the sender so we can cache it */
    (void) ZGetSender();

    return (ZERR_NONE);
}

