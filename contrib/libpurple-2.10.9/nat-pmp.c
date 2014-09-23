/**
 * @file nat-pmp.c NAT-PMP Implementation
 * @ingroup core
 */

/* purple
 *
 * Purple is the legal property of its developers, whose names are too numerous
 * to list here.  Please refer to the COPYRIGHT file distributed with this
 * source distribution.
 *
 * Most code in nat-pmp.c copyright (C) 2007, R. Tyler Ballance, bleep, LLC.
 * This file is distributed under the 3-clause (modified) BSD license:
 * Redistribution and use in source and binary forms, with or without modification, are permitted
 * provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this list of conditions and
 * the following disclaimer.
 * Neither the name of the bleep. LLC nor the names of its contributors may be used to endorse or promote
 * products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 */

#include "internal.h"
#include "nat-pmp.h"
#include "debug.h"
#include "signals.h"
#include "network.h"

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#ifdef HAVE_SYS_SYSCTL_H
#include <sys/sysctl.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

/* We will need sysctl() and NET_RT_DUMP, both of which are not present
 * on all platforms, to continue. */
#if defined(HAVE_SYS_SYSCTL_H) && defined(NET_RT_DUMP)

#include <sys/types.h>
#include <net/route.h>

#define PMP_DEBUG	1

typedef struct {
	guint8	version;
	guint8 opcode;
} PurplePmpIpRequest;

typedef struct {
	guint8		version;
	guint8		opcode; /* 128 + n */
	guint16		resultcode;
	guint32		epoch;
	guint32		address;
} PurplePmpIpResponse;

typedef struct {
	guint8		version;
	guint8		opcode;
	char		reserved[2];
	guint16		privateport;
	guint16		publicport;
	guint32		lifetime;
} PurplePmpMapRequest;

struct _PurplePmpMapResponse {
	guint8		version;
	guint8		opcode;
	guint16		resultcode;
	guint32		epoch;
	guint16		privateport;
	guint16		publicport;
	guint32		lifetime;
};

typedef struct _PurplePmpMapResponse PurplePmpMapResponse;

typedef enum {
	PURPLE_PMP_STATUS_UNDISCOVERED = -1,
	PURPLE_PMP_STATUS_UNABLE_TO_DISCOVER,
	PURPLE_PMP_STATUS_DISCOVERING,
	PURPLE_PMP_STATUS_DISCOVERED
} PurpleUPnPStatus;

typedef struct {
	PurpleUPnPStatus status;
	gchar *publicip;
} PurplePmpInfo;

static PurplePmpInfo pmp_info = {PURPLE_PMP_STATUS_UNDISCOVERED, NULL};

/*
 *	Thanks to R. Matthew Emerson for the fixes on this
 */

#define PMP_MAP_OPCODE_UDP	1
#define PMP_MAP_OPCODE_TCP	2

#define PMP_VERSION			0
#define PMP_PORT			5351
#define PMP_TIMEOUT			250000	/* 250000 useconds */

/* alignment constraint for routing socket */
#define ROUNDUP(a)			((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))
#define ADVANCE(x, n)		(x += ROUNDUP((n)->sa_len))

static void
get_rtaddrs(int bitmask, struct sockaddr *sa, struct sockaddr *addrs[])
{
	int i;

	for (i = 0; i < RTAX_MAX; i++)
	{
		if (bitmask & (1 << i))
		{
			addrs[i] = sa;
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
			sa = (struct sockaddr *)(ROUNDUP(sa->sa_len) + (char *)sa);
#else
			if (sa->sa_family == AF_INET)
				sa = (struct sockaddr*)(sizeof(struct sockaddr_in) + (char *)sa);
#ifdef AF_INET6
			else if (sa->sa_family == AF_INET6)
				sa = (struct sockaddr*)(sizeof(struct sockaddr_in6) + (char *)sa);
#endif
#endif
		}
		else
		{
			addrs[i] = NULL;
		}
	}
}

static int
is_default_route(struct sockaddr *sa, struct sockaddr *mask)
{
    struct sockaddr_in *sin;

    if (sa->sa_family != AF_INET)
		return 0;

    sin = (struct sockaddr_in *)sa;
    if ((sin->sin_addr.s_addr == INADDR_ANY) &&
		mask &&
		(ntohl(((struct sockaddr_in *)mask)->sin_addr.s_addr) == 0L ||
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
		 mask->sa_len == 0
#else
		0
#endif
		))
		return 1;
    else
		return 0;
}

/*!
 * The return sockaddr_in must be g_free()'d when no longer needed
 */
static struct sockaddr_in *
default_gw()
{
	int mib[6];
	size_t needed;
	char *buf, *next, *lim;
	struct rt_msghdr *rtm;
	struct sockaddr *sa;
	struct sockaddr_in *sin = NULL;

	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE; /* entire routing table or a subset of it */
	mib[2] = 0; /* protocol number - always 0 */
	mib[3] = 0; /* address family - 0 for all addres families */
	mib[4] = NET_RT_DUMP;
	mib[5] = 0;

	/* Determine the buffer side needed to get the full routing table */
	if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0)
	{
		purple_debug_warning("nat-pmp", "sysctl: net.route.0.0.dump estimate\n");
		return NULL;
	}

	if (!(buf = malloc(needed)))
	{
		purple_debug_warning("nat-pmp", "Failed to malloc %" G_GSIZE_FORMAT "\n", needed);
		return NULL;
	}

	/* Read the routing table into buf */
	if (sysctl(mib, 6, buf, &needed, NULL, 0) < 0)
	{
		free(buf);
		purple_debug_warning("nat-pmp", "sysctl: net.route.0.0.dump\n");
		return NULL;
	}

	lim = buf + needed;

	for (next = buf; next < lim; next += rtm->rtm_msglen)
	{
		rtm = (struct rt_msghdr *)next;
		sa = (struct sockaddr *)(rtm + 1);

		if (sa->sa_family == AF_INET)
		{
			struct sockaddr_in *cursin = (struct sockaddr_in*) sa;

			if ((rtm->rtm_flags & RTF_GATEWAY)
			    && cursin->sin_addr.s_addr == INADDR_ANY)
			{
				/* We found the default route. Now get the destination address and netmask. */
				struct sockaddr *rti_info[RTAX_MAX];
				struct sockaddr addr, mask;

				get_rtaddrs(rtm->rtm_addrs, sa, rti_info);
				memset(&addr, 0, sizeof(addr));

				if (rtm->rtm_addrs & RTA_DST)
					memcpy(&addr, rti_info[RTAX_DST], sizeof(addr));

				memset(&mask, 0, sizeof(mask));

				if (rtm->rtm_addrs & RTA_NETMASK)
					memcpy(&mask, rti_info[RTAX_NETMASK], sizeof(mask));

				if (rtm->rtm_addrs & RTA_GATEWAY &&
					is_default_route(&addr, &mask))
				{
					if (rti_info[RTAX_GATEWAY]) {
						struct sockaddr_in *rti_sin = (struct sockaddr_in *)rti_info[RTAX_GATEWAY];
						sin = g_new0(struct sockaddr_in, 1);
						sin->sin_family = rti_sin->sin_family;
						sin->sin_port = rti_sin->sin_port;
						sin->sin_addr.s_addr = rti_sin->sin_addr.s_addr;
						memcpy(sin, rti_info[RTAX_GATEWAY], sizeof(struct sockaddr_in));

						purple_debug_info("nat-pmp", "Found a default gateway\n");
						break;
					}
				}
			}
		}
	}

	free(buf);
	return sin;
}

/*!
 *	purple_pmp_get_public_ip() will return the publicly facing IP address of the
 *	default NAT gateway. The function will return NULL if:
 *		- The gateway doesn't support NAT-PMP
 *		- The gateway errors in some other spectacular fashion
 */
char *
purple_pmp_get_public_ip()
{
	struct sockaddr_in addr, *gateway, *publicsockaddr = NULL;
	struct timeval req_timeout;
	socklen_t len;

	PurplePmpIpRequest req;
	PurplePmpIpResponse resp;
	int sendfd;

	if (pmp_info.status == PURPLE_PMP_STATUS_UNABLE_TO_DISCOVER)
		return NULL;

	if ((pmp_info.status == PURPLE_PMP_STATUS_DISCOVERED) && (pmp_info.publicip != NULL))
	{
#ifdef PMP_DEBUG
		purple_debug_info("nat-pmp", "Returning cached publicip %s\n",pmp_info.publicip);
#endif
		return pmp_info.publicip;
	}

	gateway = default_gw();

	if (!gateway)
	{
		purple_debug_info("nat-pmp", "Cannot request public IP from a NULL gateway!\n");
		/* If we get a NULL gateway, don't try again next time */
		pmp_info.status = PURPLE_PMP_STATUS_UNABLE_TO_DISCOVER;
		return NULL;
	}

	/* Default port for NAT-PMP is 5351 */
	if (gateway->sin_port != PMP_PORT)
		gateway->sin_port = htons(PMP_PORT);

	req_timeout.tv_sec = 0;
	req_timeout.tv_usec = PMP_TIMEOUT;

	sendfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	/* Clean out both req and resp structures */
	memset(&req, 0, sizeof(PurplePmpIpRequest));
	memset(&resp, 0, sizeof(PurplePmpIpResponse));
	req.version = 0;
	req.opcode = 0;

	/* The NAT-PMP spec says we should attempt to contact the gateway 9 times, doubling the time we wait each time.
	 * Even starting with a timeout of 0.1 seconds, that means that we have a total waiting of 204.6 seconds.
	 * With the recommended timeout of 0.25 seconds, we're talking 511.5 seconds (8.5 minutes).
	 *
	 * This seems really silly... if this were nonblocking, a couple retries might be in order, but it's not at present.
	 */
#ifdef PMP_DEBUG
	purple_debug_info("nat-pmp", "Attempting to retrieve the public ip address for the NAT device at: %s\n", inet_ntoa(gateway->sin_addr));
	purple_debug_info("nat-pmp", "\tTimeout: %ds %dus\n", req_timeout.tv_sec, req_timeout.tv_usec);
#endif

	/* TODO: Non-blocking! */

	if (sendto(sendfd, &req, sizeof(req), 0, (struct sockaddr *)(gateway), sizeof(struct sockaddr)) < 0)
	{
		purple_debug_info("nat-pmp", "There was an error sending the NAT-PMP public IP request! (%s)\n", g_strerror(errno));
		g_free(gateway);
		pmp_info.status = PURPLE_PMP_STATUS_UNABLE_TO_DISCOVER;
		return NULL;
	}

	if (setsockopt(sendfd, SOL_SOCKET, SO_RCVTIMEO, &req_timeout, sizeof(req_timeout)) < 0)
	{
		purple_debug_info("nat-pmp", "There was an error setting the socket's options! (%s)\n", g_strerror(errno));
		g_free(gateway);
		pmp_info.status = PURPLE_PMP_STATUS_UNABLE_TO_DISCOVER;
		return NULL;
	}

	/* TODO: Non-blocking! */
	len = sizeof(struct sockaddr_in);
	if (recvfrom(sendfd, &resp, sizeof(PurplePmpIpResponse), 0, (struct sockaddr *)(&addr), &len) < 0)
	{
		if (errno != EAGAIN)
		{
			purple_debug_info("nat-pmp", "There was an error receiving the response from the NAT-PMP device! (%s)\n", g_strerror(errno));
			g_free(gateway);
			pmp_info.status = PURPLE_PMP_STATUS_UNABLE_TO_DISCOVER;
			return NULL;
		}
	}

	if (addr.sin_addr.s_addr == gateway->sin_addr.s_addr)
		publicsockaddr = &addr;
	else
	{
		purple_debug_info("nat-pmp", "Response was not received from our gateway! Instead from: %s\n", inet_ntoa(addr.sin_addr));
		g_free(gateway);

		pmp_info.status = PURPLE_PMP_STATUS_UNABLE_TO_DISCOVER;
		return NULL;
	}

	if (!publicsockaddr) {
		g_free(gateway);

		pmp_info.status = PURPLE_PMP_STATUS_UNABLE_TO_DISCOVER;
		return NULL;
	}

#ifdef PMP_DEBUG
	purple_debug_info("nat-pmp", "Response received from NAT-PMP device:\n");
	purple_debug_info("nat-pmp", "version: %d\n", resp.version);
	purple_debug_info("nat-pmp", "opcode: %d\n", resp.opcode);
	purple_debug_info("nat-pmp", "resultcode: %d\n", ntohs(resp.resultcode));
	purple_debug_info("nat-pmp", "epoch: %d\n", ntohl(resp.epoch));
	struct in_addr in;
	in.s_addr = resp.address;
	purple_debug_info("nat-pmp", "address: %s\n", inet_ntoa(in));
#endif

	publicsockaddr->sin_addr.s_addr = resp.address;

	g_free(gateway);

	g_free(pmp_info.publicip);
	pmp_info.publicip = g_strdup(inet_ntoa(publicsockaddr->sin_addr));
	pmp_info.status = PURPLE_PMP_STATUS_DISCOVERED;

	return inet_ntoa(publicsockaddr->sin_addr);
}

gboolean
purple_pmp_create_map(PurplePmpType type, unsigned short privateport, unsigned short publicport, int lifetime)
{
	struct sockaddr_in *gateway;
	gboolean success = TRUE;
	int sendfd;
	struct timeval req_timeout;
	PurplePmpMapRequest req;
	PurplePmpMapResponse *resp;

	gateway = default_gw();

	if (!gateway)
	{
		purple_debug_info("nat-pmp", "Cannot create mapping on a NULL gateway!\n");
		return FALSE;
	}

	/* Default port for NAT-PMP is 5351 */
	if (gateway->sin_port != PMP_PORT)
		gateway->sin_port = htons(PMP_PORT);

	resp = g_new0(PurplePmpMapResponse, 1);

	req_timeout.tv_sec = 0;
	req_timeout.tv_usec = PMP_TIMEOUT;

	sendfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	/* Set up the req */
	memset(&req, 0, sizeof(PurplePmpMapRequest));
	req.version = 0;
	req.opcode = ((type == PURPLE_PMP_TYPE_UDP) ? PMP_MAP_OPCODE_UDP : PMP_MAP_OPCODE_TCP);
	req.privateport = htons(privateport); /* What a difference byte ordering makes...d'oh! */
	req.publicport = htons(publicport);
	req.lifetime = htonl(lifetime);

	/* The NAT-PMP spec says we should attempt to contact the gateway 9 times, doubling the time we wait each time.
	 * Even starting with a timeout of 0.1 seconds, that means that we have a total waiting of 204.6 seconds.
	 * With the recommended timeout of 0.25 seconds, we're talking 511.5 seconds (8.5 minutes).
	 *
	 * This seems really silly... if this were nonblocking, a couple retries might be in order, but it's not at present.
	 * XXX Make this nonblocking.
	 * XXX This code looks like the pmp_get_public_ip() code. Can it be consolidated?
	 */
#ifdef PMP_DEBUG
	purple_debug_info("nat-pmp", "Attempting to create a NAT-PMP mapping the private port %d, and the public port %d\n", privateport, publicport);
	purple_debug_info("nat-pmp", "\tTimeout: %ds %dus\n", req_timeout.tv_sec, req_timeout.tv_usec);
#endif

	/* TODO: Non-blocking! */
	success = (sendto(sendfd, &req, sizeof(req), 0, (struct sockaddr *)(gateway), sizeof(struct sockaddr)) >= 0);
	if (!success)
		purple_debug_info("nat-pmp", "There was an error sending the NAT-PMP mapping request! (%s)\n", g_strerror(errno));

	if (success)
	{
		success = (setsockopt(sendfd, SOL_SOCKET, SO_RCVTIMEO, &req_timeout, sizeof(req_timeout)) >= 0);
		if (!success)
			purple_debug_info("nat-pmp", "There was an error setting the socket's options! (%s)\n", g_strerror(errno));
	}

	if (success)
	{
		/* The original code treats EAGAIN as a reason to iterate.. but I've removed iteration. This may be a problem */
		/* TODO: Non-blocking! */
		success = ((recvfrom(sendfd, resp, sizeof(PurplePmpMapResponse), 0, NULL, NULL) >= 0) ||
				   (errno == EAGAIN));
		if (!success)
			purple_debug_info("nat-pmp", "There was an error receiving the response from the NAT-PMP device! (%s)\n", g_strerror(errno));
	}

	if (success)
	{
		success = (resp->opcode == (req.opcode + 128));
		if (!success)
			purple_debug_info("nat-pmp", "The opcode for the response from the NAT device (%i) does not match the request opcode (%i + 128 = %i)!\n",
							  resp->opcode, req.opcode, req.opcode + 128);
	}

#ifdef PMP_DEBUG
	if (success)
	{
		purple_debug_info("nat-pmp", "Response received from NAT-PMP device:\n");
		purple_debug_info("nat-pmp", "version: %d\n", resp->version);
		purple_debug_info("nat-pmp", "opcode: %d\n", resp->opcode);
		purple_debug_info("nat-pmp", "resultcode: %d\n", ntohs(resp->resultcode));
		purple_debug_info("nat-pmp", "epoch: %d\n", ntohl(resp->epoch));
		purple_debug_info("nat-pmp", "privateport: %d\n", ntohs(resp->privateport));
		purple_debug_info("nat-pmp", "publicport: %d\n", ntohs(resp->publicport));
		purple_debug_info("nat-pmp", "lifetime: %d\n", ntohl(resp->lifetime));
	}
#endif

	g_free(resp);
	g_free(gateway);

	/* XXX The private port may actually differ from the one we requested, according to the spec.
	 * We don't handle that situation at present.
	 *
	 * TODO: Look at the result and verify it matches what we wanted; either return a failure if it doesn't,
	 * or change network.c to know what to do if the desired private port shifts as a result of the nat-pmp operation.
	 */
	return success;
}

gboolean
purple_pmp_destroy_map(PurplePmpType type, unsigned short privateport)
{
	gboolean success;

	success = purple_pmp_create_map(((type == PURPLE_PMP_TYPE_UDP) ? PMP_MAP_OPCODE_UDP : PMP_MAP_OPCODE_TCP),
							privateport, 0, 0);
	if (!success)
		purple_debug_warning("nat-pmp", "Failed to properly destroy mapping for %s port %d!\n",
							 ((type == PURPLE_PMP_TYPE_UDP) ? "UDP" : "TCP"), privateport);

	return success;
}

static void
purple_pmp_network_config_changed_cb(void *data)
{
	pmp_info.status = PURPLE_PMP_STATUS_UNDISCOVERED;
	g_free(pmp_info.publicip);
	pmp_info.publicip = NULL;
}

static void*
purple_pmp_get_handle(void)
{
	static int handle;

	return &handle;
}

void
purple_pmp_init()
{
	purple_signal_connect(purple_network_get_handle(), "network-configuration-changed",
		  purple_pmp_get_handle(), PURPLE_CALLBACK(purple_pmp_network_config_changed_cb),
		  GINT_TO_POINTER(0));
}
#else /* #ifdef NET_RT_DUMP */
char *
purple_pmp_get_public_ip()
{
	return NULL;
}

gboolean
purple_pmp_create_map(PurplePmpType type, unsigned short privateport, unsigned short publicport, int lifetime)
{
	return FALSE;
}

gboolean
purple_pmp_destroy_map(PurplePmpType type, unsigned short privateport)
{
	return FALSE;
}

void
purple_pmp_init()
{

}
#endif /* #if !(defined(HAVE_SYS_SYCTL_H) && defined(NET_RT_DUMP)) */
