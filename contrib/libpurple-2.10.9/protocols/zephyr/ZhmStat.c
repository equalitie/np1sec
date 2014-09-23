/* This file is part of the Project Athena Zephyr Notification System.
 * It contains the ZhmStat() function.
 *
 *      Created by:     Marc Horowitz
 *
 *      Copyright (c) 1996 by the Massachusetts Institute of Technology.
 *      For copying and distribution information, see the file
 *      "mit-copyright.h".
 */

#include "internal.h"

#ifdef WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#endif

#ifndef INADDR_LOOPBACK
#define INADDR_LOOPBACK 0x7f000001
#endif

Code_t ZhmStat(hostaddr, notice)
    struct in_addr *hostaddr;
    ZNotice_t *notice;
{
    struct servent *sp;
    struct sockaddr_in sin;
    ZNotice_t req;
    Code_t code;
    struct timeval tv;
    fd_set readers;

    (void) memset((char *)&sin, 0, sizeof(struct sockaddr_in));

    sp = getservbyname(HM_SVCNAME, "udp");

    sin.sin_port = (sp) ? sp->s_port : HM_SVC_FALLBACK;
    sin.sin_family = AF_INET;

    if (hostaddr)
	sin.sin_addr = *hostaddr;
    else
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    (void) memset((char *)&req, 0, sizeof(req));
    req.z_kind = STAT;
    req.z_port = 0;
    req.z_class = HM_STAT_CLASS;
    req.z_class_inst = HM_STAT_CLIENT;
    req.z_opcode = HM_GIMMESTATS;
    req.z_sender = "";
    req.z_recipient = "";
    req.z_default_format = "";
    req.z_message_len = 0;

    if ((code = ZSetDestAddr(&sin)) != ZERR_NONE)
	return(code);

    if ((code = ZSendNotice(&req, ZNOAUTH)) != ZERR_NONE)
	return(code);

    /* Wait up to ten seconds for a response. */
    FD_ZERO(&readers);
    FD_SET(ZGetFD(), &readers);
    tv.tv_sec = 10;
    tv.tv_usec = 0;
    code = select(ZGetFD() + 1, &readers, NULL, NULL, &tv);
    if (code < 0 && errno != EINTR)
	return(errno);
    if (code == 0 || (code < 0 && errno == EINTR) || ZPending() == 0)
	return(ZERR_HMDEAD);

    return(ZReceiveNotice(notice, (struct sockaddr_in *) 0));
}
