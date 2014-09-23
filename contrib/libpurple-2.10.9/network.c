/**
 * @file network.c Network Implementation
 * @ingroup core
 */

/* purple
 *
 * Purple is the legal property of its developers, whose names are too numerous
 * to list here.  Please refer to the COPYRIGHT file distributed with this
 * source distribution.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02111-1301  USA
 */

#include "internal.h"

#ifndef _WIN32
#include <arpa/nameser.h>
#include <resolv.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/ioctl.h>
#ifdef HAVE_GETIFADDRS
#include <ifaddrs.h>
#endif
#else
#include <nspapi.h>
#endif

/* Solaris */
#if defined (__SVR4) && defined (__sun)
#include <sys/sockio.h>
#endif

#include "debug.h"
#include "account.h"
#include "nat-pmp.h"
#include "network.h"
#include "prefs.h"
#include "stun.h"
#include "upnp.h"
#include "dnsquery.h"

#ifdef USE_IDN
#include <idna.h>
#endif

/*
 * Calling sizeof(struct ifreq) isn't always correct on
 * Mac OS X (and maybe others).
 */
#ifdef _SIZEOF_ADDR_IFREQ
#  define HX_SIZE_OF_IFREQ(a) _SIZEOF_ADDR_IFREQ(a)
#else
#  define HX_SIZE_OF_IFREQ(a) sizeof(a)
#endif

#ifdef HAVE_NETWORKMANAGER
#include <dbus/dbus-glib.h>
#include <NetworkManager.h>

#if !defined(NM_CHECK_VERSION)
#define NM_CHECK_VERSION(x,y,z) 0
#endif

static DBusGConnection *nm_conn = NULL;
static DBusGProxy *nm_proxy = NULL;
static DBusGProxy *dbus_proxy = NULL;
static NMState nm_state = NM_STATE_UNKNOWN;
static gboolean have_nm_state = FALSE;

#elif defined _WIN32
static int current_network_count;

/* Mutex for the other global vars */
static GStaticMutex mutex = G_STATIC_MUTEX_INIT;
static gboolean network_initialized = FALSE;
static HANDLE network_change_handle = NULL;
static int (WSAAPI *MyWSANSPIoctl) (
		HANDLE hLookup, DWORD dwControlCode, LPVOID lpvInBuffer,
		DWORD cbInBuffer, LPVOID lpvOutBuffer, DWORD cbOutBuffer,
		LPDWORD lpcbBytesReturned, LPWSACOMPLETION lpCompletion) = NULL;
#endif

struct _PurpleNetworkListenData {
	int listenfd;
	int socket_type;
	gboolean retry;
	gboolean adding;
	PurpleNetworkListenCallback cb;
	gpointer cb_data;
	UPnPMappingAddRemove *mapping_data;
	int timer;
};

#ifdef HAVE_NETWORKMANAGER
static NMState nm_get_network_state(void);
#endif

#if defined(HAVE_NETWORKMANAGER) || defined(_WIN32)
static gboolean force_online;
#endif

/* Cached IP addresses for STUN and TURN servers (set globally in prefs) */
static gchar *stun_ip = NULL;
static gchar *turn_ip = NULL;

/* Keep track of port mappings done with UPnP and NAT-PMP */
static GHashTable *upnp_port_mappings = NULL;
static GHashTable *nat_pmp_port_mappings = NULL;

const unsigned char *
purple_network_ip_atoi(const char *ip)
{
	static unsigned char ret[4];
	gchar *delimiter = ".";
	gchar **split;
	int i;

	g_return_val_if_fail(ip != NULL, NULL);

	split = g_strsplit(ip, delimiter, 4);
	for (i = 0; split[i] != NULL; i++)
		ret[i] = atoi(split[i]);
	g_strfreev(split);

	/* i should always be 4 */
	if (i != 4)
		return NULL;

	return ret;
}

void
purple_network_set_public_ip(const char *ip)
{
	g_return_if_fail(ip != NULL);

	/* XXX - Ensure the IP address is valid */

	purple_prefs_set_string("/purple/network/public_ip", ip);
}

const char *
purple_network_get_public_ip(void)
{
	return purple_prefs_get_string("/purple/network/public_ip");
}

const char *
purple_network_get_local_system_ip(int fd)
{
	char buffer[1024];
	static char ip[16];
	char *tmp;
	struct ifconf ifc;
	struct ifreq *ifr;
	struct sockaddr_in *sinptr;
	guint32 lhost = htonl((127 << 24) + 1); /* 127.0.0.1 */
	long unsigned int add;
	int source = fd;

	if (fd < 0)
		source = socket(PF_INET,SOCK_STREAM, 0);

	ifc.ifc_len = sizeof(buffer);
	ifc.ifc_req = (struct ifreq *)buffer;
	ioctl(source, SIOCGIFCONF, &ifc);

	if (fd < 0)
		close(source);

	tmp = buffer;
	while (tmp < buffer + ifc.ifc_len)
	{
		ifr = (struct ifreq *)tmp;
		tmp += HX_SIZE_OF_IFREQ(*ifr);

		if (ifr->ifr_addr.sa_family == AF_INET)
		{
			sinptr = (struct sockaddr_in *)&ifr->ifr_addr;
			if (sinptr->sin_addr.s_addr != lhost)
			{
				add = ntohl(sinptr->sin_addr.s_addr);
				g_snprintf(ip, 16, "%lu.%lu.%lu.%lu",
					((add >> 24) & 255),
					((add >> 16) & 255),
					((add >> 8) & 255),
					add & 255);

				return ip;
			}
		}
	}

	return "0.0.0.0";
}

GList *
purple_network_get_all_local_system_ips(void)
{
#if defined(HAVE_GETIFADDRS) && defined(HAVE_INET_NTOP)
	GList *result = NULL;
	struct ifaddrs *start, *ifa;
	int ret;

	ret = getifaddrs(&start);
	if (ret < 0) {
		purple_debug_warning("network",
				"getifaddrs() failed: %s\n", g_strerror(errno));
		return NULL;
	}

	for (ifa = start; ifa; ifa = ifa->ifa_next) {
		int family = ifa->ifa_addr ? ifa->ifa_addr->sa_family : AF_UNSPEC;
		char host[INET6_ADDRSTRLEN];
		const char *tmp = NULL;

		if ((family != AF_INET && family != AF_INET6) || ifa->ifa_flags & IFF_LOOPBACK)
			continue;

		if (family == AF_INET)
			tmp = inet_ntop(family, &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr, host, sizeof(host));
		else {
			struct sockaddr_in6 *sockaddr = (struct sockaddr_in6 *)ifa->ifa_addr;
			/* Peer-peer link-local communication is a big TODO.  I am not sure
			 * how communicating link-local addresses is supposed to work, and
			 * it seems like it would require attempting the cartesian product
			 * of the local and remote interfaces to see if any match (eww).
			 */
			if (!IN6_IS_ADDR_LINKLOCAL(&sockaddr->sin6_addr))
				tmp = inet_ntop(family, &sockaddr->sin6_addr, host, sizeof(host));
		}
		if (tmp != NULL)
			result = g_list_prepend(result, g_strdup(tmp));
	}

	freeifaddrs(start);

	return g_list_reverse(result);
#else /* HAVE_GETIFADDRS && HAVE_INET_NTOP */
	GList *result = NULL;
	int source = socket(PF_INET,SOCK_STREAM, 0);
	char buffer[1024];
	char *tmp;
	struct ifconf ifc;
	struct ifreq *ifr;

	ifc.ifc_len = sizeof(buffer);
	ifc.ifc_req = (struct ifreq *)buffer;
	ioctl(source, SIOCGIFCONF, &ifc);
	close(source);

	tmp = buffer;
	while (tmp < buffer + ifc.ifc_len) {
		char dst[INET_ADDRSTRLEN];

		ifr = (struct ifreq *)tmp;
		tmp += HX_SIZE_OF_IFREQ(*ifr);

		if (ifr->ifr_addr.sa_family == AF_INET) {
			struct sockaddr_in *sinptr = (struct sockaddr_in *)&ifr->ifr_addr;

			inet_ntop(AF_INET, &sinptr->sin_addr, dst,
				sizeof(dst));
			purple_debug_info("network",
				"found local i/f with address %s on IPv4\n", dst);
			if (!purple_strequal(dst, "127.0.0.1")) {
				result = g_list_append(result, g_strdup(dst));
			}
		}
	}

	return result;
#endif /* HAVE_GETIFADDRS && HAVE_INET_NTOP */
}

const char *
purple_network_get_my_ip(int fd)
{
	const char *ip = NULL;
	PurpleStunNatDiscovery *stun;

	/* Check if the user specified an IP manually */
	if (!purple_prefs_get_bool("/purple/network/auto_ip")) {
		ip = purple_network_get_public_ip();
		/* Make sure the IP address entered by the user is valid */
		if ((ip != NULL) && (purple_network_ip_atoi(ip) != NULL))
			return ip;
	} else {
		/* Check if STUN discovery was already done */
		stun = purple_stun_discover(NULL);
		if ((stun != NULL) && (stun->status == PURPLE_STUN_STATUS_DISCOVERED))
			return stun->publicip;

		/* Attempt to get the IP from a NAT device using UPnP */
		ip = purple_upnp_get_public_ip();
		if (ip != NULL)
			return ip;

		/* Attempt to get the IP from a NAT device using NAT-PMP */
		ip = purple_pmp_get_public_ip();
		if (ip != NULL)
			return ip;
	}

	/* Just fetch the IP of the local system */
	return purple_network_get_local_system_ip(fd);
}


static void
purple_network_set_upnp_port_mapping_cb(gboolean success, gpointer data)
{
	PurpleNetworkListenData *listen_data;

	listen_data = data;
	/* TODO: Once we're keeping track of upnp requests... */
	/* listen_data->pnp_data = NULL; */

	if (!success) {
		purple_debug_warning("network", "Couldn't create UPnP mapping\n");
		if (listen_data->retry) {
			listen_data->retry = FALSE;
			listen_data->adding = FALSE;
			listen_data->mapping_data = purple_upnp_remove_port_mapping(
						purple_network_get_port_from_fd(listen_data->listenfd),
						(listen_data->socket_type == SOCK_STREAM) ? "TCP" : "UDP",
						purple_network_set_upnp_port_mapping_cb, listen_data);
			return;
		}
	} else if (!listen_data->adding) {
		/* We've tried successfully to remove the port mapping.
		 * Try to add it again */
		listen_data->adding = TRUE;
		listen_data->mapping_data = purple_upnp_set_port_mapping(
					purple_network_get_port_from_fd(listen_data->listenfd),
					(listen_data->socket_type == SOCK_STREAM) ? "TCP" : "UDP",
					purple_network_set_upnp_port_mapping_cb, listen_data);
		return;
	}

	if (success) {
		/* add port mapping to hash table */
		gint key = purple_network_get_port_from_fd(listen_data->listenfd);
		gint value = listen_data->socket_type;
		g_hash_table_insert(upnp_port_mappings, GINT_TO_POINTER(key), GINT_TO_POINTER(value));
	}

	if (listen_data->cb)
		listen_data->cb(listen_data->listenfd, listen_data->cb_data);

	/* Clear the UPnP mapping data, since it's complete and purple_network_listen_cancel() will try to cancel
	 * it otherwise. */
	listen_data->mapping_data = NULL;
	purple_network_listen_cancel(listen_data);
}

static gboolean
purple_network_finish_pmp_map_cb(gpointer data)
{
	PurpleNetworkListenData *listen_data;
	gint key;
	gint value;

	listen_data = data;
	listen_data->timer = 0;

	/* add port mapping to hash table */
	key = purple_network_get_port_from_fd(listen_data->listenfd);
	value = listen_data->socket_type;
	g_hash_table_insert(nat_pmp_port_mappings, GINT_TO_POINTER(key), GINT_TO_POINTER(value));

	if (listen_data->cb)
		listen_data->cb(listen_data->listenfd, listen_data->cb_data);

	purple_network_listen_cancel(listen_data);

	return FALSE;
}

static gboolean listen_map_external = TRUE;
void purple_network_listen_map_external(gboolean map_external)
{
	listen_map_external = map_external;
}

static PurpleNetworkListenData *
purple_network_do_listen(unsigned short port, int socket_family, int socket_type, PurpleNetworkListenCallback cb, gpointer cb_data)
{
	int listenfd = -1;
	int flags;
	const int on = 1;
	PurpleNetworkListenData *listen_data;
	unsigned short actual_port;
#ifdef HAVE_GETADDRINFO
	int errnum;
	struct addrinfo hints, *res, *next;
	char serv[6];

	/*
	 * Get a list of addresses on this machine.
	 */
	g_snprintf(serv, sizeof(serv), "%hu", port);
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = socket_family;
	hints.ai_socktype = socket_type;
	errnum = getaddrinfo(NULL /* any IP */, serv, &hints, &res);
	if (errnum != 0) {
#ifndef _WIN32
		purple_debug_warning("network", "getaddrinfo: %s\n", purple_gai_strerror(errnum));
		if (errnum == EAI_SYSTEM)
			purple_debug_warning("network", "getaddrinfo: system error: %s\n", g_strerror(errno));
#else
		purple_debug_warning("network", "getaddrinfo: Error Code = %d\n", errnum);
#endif
		return NULL;
	}

	/*
	 * Go through the list of addresses and attempt to listen on
	 * one of them.
	 * XXX - Try IPv6 addresses first?
	 */
	for (next = res; next != NULL; next = next->ai_next) {
		listenfd = socket(next->ai_family, next->ai_socktype, next->ai_protocol);
		if (listenfd < 0)
			continue;
		if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) != 0)
			purple_debug_warning("network", "setsockopt(SO_REUSEADDR): %s\n", g_strerror(errno));
		if (bind(listenfd, next->ai_addr, next->ai_addrlen) == 0)
			break; /* success */
		/* XXX - It is unclear to me (datallah) whether we need to be
		   using a new socket each time */
		close(listenfd);
	}

	freeaddrinfo(res);

	if (next == NULL)
		return NULL;
#else
	struct sockaddr_in sockin;

	if (socket_family != AF_INET && socket_family != AF_UNSPEC) {
		purple_debug_warning("network", "Address family %d only "
		                     "supported when built with getaddrinfo() "
		                     "support\n", socket_family);
		return NULL;
	}

	if ((listenfd = socket(AF_INET, socket_type, 0)) < 0) {
		purple_debug_warning("network", "socket: %s\n", g_strerror(errno));
		return NULL;
	}

	if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) != 0)
		purple_debug_warning("network", "setsockopt: %s\n", g_strerror(errno));

	memset(&sockin, 0, sizeof(struct sockaddr_in));
	sockin.sin_family = PF_INET;
	sockin.sin_port = htons(port);

	if (bind(listenfd, (struct sockaddr *)&sockin, sizeof(struct sockaddr_in)) != 0) {
		purple_debug_warning("network", "bind: %s\n", g_strerror(errno));
		close(listenfd);
		return NULL;
	}
#endif

	if (socket_type == SOCK_STREAM && listen(listenfd, 4) != 0) {
		purple_debug_warning("network", "listen: %s\n", g_strerror(errno));
		close(listenfd);
		return NULL;
	}
	flags = fcntl(listenfd, F_GETFL);
	fcntl(listenfd, F_SETFL, flags | O_NONBLOCK);
#ifndef _WIN32
	fcntl(listenfd, F_SETFD, FD_CLOEXEC);
#endif
	actual_port = purple_network_get_port_from_fd(listenfd);

	purple_debug_info("network", "Listening on port: %hu\n", actual_port);

	listen_data = g_new0(PurpleNetworkListenData, 1);
	listen_data->listenfd = listenfd;
	listen_data->adding = TRUE;
	listen_data->retry = TRUE;
	listen_data->cb = cb;
	listen_data->cb_data = cb_data;
	listen_data->socket_type = socket_type;

	if (!purple_socket_speaks_ipv4(listenfd) || !listen_map_external ||
			!purple_prefs_get_bool("/purple/network/map_ports"))
	{
		purple_debug_info("network", "Skipping external port mapping.\n");
		/* The pmp_map_cb does what we want to do */
		listen_data->timer = purple_timeout_add(0, purple_network_finish_pmp_map_cb, listen_data);
	}
	/* Attempt a NAT-PMP Mapping, which will return immediately */
	else if (purple_pmp_create_map(((socket_type == SOCK_STREAM) ? PURPLE_PMP_TYPE_TCP : PURPLE_PMP_TYPE_UDP),
							  actual_port, actual_port, PURPLE_PMP_LIFETIME))
	{
		purple_debug_info("network", "Created NAT-PMP mapping on port %i\n", actual_port);
		/* We want to return listen_data now, and on the next run loop trigger the cb and destroy listen_data */
		listen_data->timer = purple_timeout_add(0, purple_network_finish_pmp_map_cb, listen_data);
	}
	else
	{
		/* Attempt a UPnP Mapping */
		listen_data->mapping_data = purple_upnp_set_port_mapping(
						 actual_port,
						 (socket_type == SOCK_STREAM) ? "TCP" : "UDP",
						 purple_network_set_upnp_port_mapping_cb, listen_data);
	}

	return listen_data;
}

PurpleNetworkListenData *
purple_network_listen_family(unsigned short port, int socket_family,
                             int socket_type, PurpleNetworkListenCallback cb,
                             gpointer cb_data)
{
	g_return_val_if_fail(port != 0, NULL);

	return purple_network_do_listen(port, socket_family, socket_type,
	                                cb, cb_data);
}

PurpleNetworkListenData *
purple_network_listen(unsigned short port, int socket_type,
		PurpleNetworkListenCallback cb, gpointer cb_data)
{
	return purple_network_listen_family(port, AF_UNSPEC, socket_type,
	                                    cb, cb_data);
}

PurpleNetworkListenData *
purple_network_listen_range_family(unsigned short start, unsigned short end,
                                   int socket_family, int socket_type,
                                   PurpleNetworkListenCallback cb,
                                   gpointer cb_data)
{
	PurpleNetworkListenData *ret = NULL;

	if (purple_prefs_get_bool("/purple/network/ports_range_use")) {
		start = purple_prefs_get_int("/purple/network/ports_range_start");
		end = purple_prefs_get_int("/purple/network/ports_range_end");
	} else {
		if (end < start)
			end = start;
	}

	for (; start <= end; start++) {
		ret = purple_network_do_listen(start, AF_UNSPEC, socket_type, cb, cb_data);
		if (ret != NULL)
			break;
	}

	return ret;
}

PurpleNetworkListenData *
purple_network_listen_range(unsigned short start, unsigned short end,
                            int socket_type, PurpleNetworkListenCallback cb,
                            gpointer cb_data)
{
	return purple_network_listen_range_family(start, end, AF_UNSPEC,
	                                          socket_type, cb, cb_data);
}

void purple_network_listen_cancel(PurpleNetworkListenData *listen_data)
{
	if (listen_data->mapping_data != NULL)
		purple_upnp_cancel_port_mapping(listen_data->mapping_data);

	if (listen_data->timer > 0)
		purple_timeout_remove(listen_data->timer);

	g_free(listen_data);
}

unsigned short
purple_network_get_port_from_fd(int fd)
{
	struct sockaddr_in addr;
	socklen_t len;

	g_return_val_if_fail(fd >= 0, 0);

	len = sizeof(addr);
	if (getsockname(fd, (struct sockaddr *) &addr, &len) == -1) {
		purple_debug_warning("network", "getsockname: %s\n", g_strerror(errno));
		return 0;
	}

	return ntohs(addr.sin_port);
}

#ifdef _WIN32
#ifndef NS_NLA
#define NS_NLA 15
#endif
static gint
wpurple_get_connected_network_count(void)
{
	gint net_cnt = 0;

	WSAQUERYSET qs;
	HANDLE h;
	gint retval;
	int errorid;

	memset(&qs, 0, sizeof(WSAQUERYSET));
	qs.dwSize = sizeof(WSAQUERYSET);
	qs.dwNameSpace = NS_NLA;

	retval = WSALookupServiceBegin(&qs, LUP_RETURN_ALL, &h);
	if (retval != ERROR_SUCCESS) {
		gchar *msg;
		errorid = WSAGetLastError();
		msg = g_win32_error_message(errorid);
		purple_debug_warning("network", "Couldn't retrieve NLA SP lookup handle. "
						"NLA service is probably not running. Message: %s (%d).\n",
						msg, errorid);
		g_free(msg);

		return -1;
	} else {
		char buf[4096];
		WSAQUERYSET *res = (LPWSAQUERYSET) buf;
		DWORD size = sizeof(buf);
		while ((retval = WSALookupServiceNext(h, 0, &size, res)) == ERROR_SUCCESS) {
			net_cnt++;
			purple_debug_info("network", "found network '%s'\n",
					res->lpszServiceInstanceName ? res->lpszServiceInstanceName : "(NULL)");
			size = sizeof(buf);
		}

		errorid = WSAGetLastError();
		if (!(errorid == WSA_E_NO_MORE || errorid == WSAENOMORE)) {
			gchar *msg = g_win32_error_message(errorid);
			purple_debug_error("network", "got unexpected NLA response %s (%d)\n", msg, errorid);
			g_free(msg);

			net_cnt = -1;
		}

		retval = WSALookupServiceEnd(h);
	}

	return net_cnt;

}

static gboolean wpurple_network_change_thread_cb(gpointer data)
{
	gint new_count;
	PurpleConnectionUiOps *ui_ops = purple_connections_get_ui_ops();

	new_count = wpurple_get_connected_network_count();

	if (new_count < 0)
		return FALSE;

	purple_debug_info("network", "Received Network Change Notification. Current network count is %d, previous count was %d.\n", new_count, current_network_count);

	purple_signal_emit(purple_network_get_handle(), "network-configuration-changed", NULL);

	if (new_count > 0 && ui_ops != NULL && ui_ops->network_connected != NULL) {
		ui_ops->network_connected();
	} else if (new_count == 0 && current_network_count > 0 &&
			   ui_ops != NULL && ui_ops->network_disconnected != NULL) {
		ui_ops->network_disconnected();
	}

	current_network_count = new_count;

	return FALSE;
}

static gboolean _print_debug_msg(gpointer data) {
	gchar *msg = data;
	purple_debug_warning("network", "%s", msg);
	g_free(msg);
	return FALSE;
}

static gpointer wpurple_network_change_thread(gpointer data)
{
	WSAQUERYSET qs;
	WSAEVENT *nla_event;
	time_t last_trigger = time(NULL) - 31;
	char buf[4096];
	WSAQUERYSET *res = (LPWSAQUERYSET) buf;
	DWORD size;

	if ((nla_event = WSACreateEvent()) == WSA_INVALID_EVENT) {
		int errorid = WSAGetLastError();
		gchar *msg = g_win32_error_message(errorid);
		purple_timeout_add(0, _print_debug_msg,
						   g_strdup_printf("Couldn't create WSA event. "
										   "Message: %s (%d).\n", msg, errorid));
		g_free(msg);
		g_thread_exit(NULL);
		return NULL;
	}

	while (TRUE) {
		int retval;
		DWORD retLen = 0;
		WSACOMPLETION completion;
		WSAOVERLAPPED overlapped;

		g_static_mutex_lock(&mutex);
		if (network_initialized == FALSE) {
			/* purple_network_uninit has been called */
			WSACloseEvent(nla_event);
			g_static_mutex_unlock(&mutex);
			g_thread_exit(NULL);
			return NULL;
		}

		if (network_change_handle == NULL) {
			memset(&qs, 0, sizeof(WSAQUERYSET));
			qs.dwSize = sizeof(WSAQUERYSET);
			qs.dwNameSpace = NS_NLA;
			if (WSALookupServiceBegin(&qs, 0, &network_change_handle) == SOCKET_ERROR) {
				int errorid = WSAGetLastError();
				gchar *msg = g_win32_error_message(errorid);
				purple_timeout_add(0, _print_debug_msg,
								   g_strdup_printf("Couldn't retrieve NLA SP lookup handle. "
												   "NLA service is probably not running. Message: %s (%d).\n",
													msg, errorid));
				g_free(msg);
				WSACloseEvent(nla_event);
				g_static_mutex_unlock(&mutex);
				g_thread_exit(NULL);
				return NULL;
			}
		}
		g_static_mutex_unlock(&mutex);

		memset(&completion, 0, sizeof(WSACOMPLETION));
		completion.Type = NSP_NOTIFY_EVENT;
		overlapped.hEvent = nla_event;
		completion.Parameters.Event.lpOverlapped = &overlapped;

		if (MyWSANSPIoctl(network_change_handle, SIO_NSP_NOTIFY_CHANGE, NULL, 0, NULL, 0, &retLen, &completion) == SOCKET_ERROR) {
			int errorid = WSAGetLastError();
			if (errorid == WSA_INVALID_HANDLE) {
				purple_timeout_add(0, _print_debug_msg,
								   g_strdup("Invalid NLA handle; resetting.\n"));
				g_static_mutex_lock(&mutex);
				retval = WSALookupServiceEnd(network_change_handle);
				network_change_handle = NULL;
				g_static_mutex_unlock(&mutex);
				continue;
			/* WSA_IO_PENDING indicates successful async notification will happen */
			} else if (errorid != WSA_IO_PENDING) {
				gchar *msg = g_win32_error_message(errorid);
				purple_timeout_add(0, _print_debug_msg,
								   g_strdup_printf("Unable to wait for changes. Message: %s (%d).\n",
												   msg, errorid));
				g_free(msg);
			}
		}

		/* Make sure at least 30 seconds have elapsed since the last
		 * notification so we don't peg the cpu if this keeps changing. */
		if ((time(NULL) - last_trigger) < 30)
			Sleep(30000);

		/* This will block until NLA notifies us */
		retval = WaitForSingleObjectEx(nla_event, WSA_INFINITE, TRUE);

		last_trigger = time(NULL);

		g_static_mutex_lock(&mutex);
		if (network_initialized == FALSE) {
			/* Time to die */
			WSACloseEvent(nla_event);
			g_static_mutex_unlock(&mutex);
			g_thread_exit(NULL);
			return NULL;
		}

		size = sizeof(buf);
		while ((retval = WSALookupServiceNext(network_change_handle, 0, &size, res)) == ERROR_SUCCESS) {
			/*purple_timeout_add(0, _print_debug_msg,
							   g_strdup_printf("thread found network '%s'\n",
											   res->lpszServiceInstanceName ? res->lpszServiceInstanceName : "(NULL)"));*/
			size = sizeof(buf);
		}

		WSAResetEvent(nla_event);
		g_static_mutex_unlock(&mutex);

		purple_timeout_add(0, wpurple_network_change_thread_cb, NULL);
	}

	g_thread_exit(NULL);
	return NULL;
}
#endif

gboolean
purple_network_is_available(void)
{
#ifdef HAVE_NETWORKMANAGER
	if (force_online)
		return TRUE;

	if (!have_nm_state)
	{
		have_nm_state = TRUE;
		nm_state = nm_get_network_state();
		if (nm_state == NM_STATE_UNKNOWN)
			purple_debug_warning("network", "NetworkManager not active. Assuming connection exists.\n");
	}

	switch (nm_state)
	{
		case NM_STATE_UNKNOWN:
#if NM_CHECK_VERSION(0,8,992)
		case NM_STATE_CONNECTED_LOCAL:
		case NM_STATE_CONNECTED_SITE:
		case NM_STATE_CONNECTED_GLOBAL:
#else
		case NM_STATE_CONNECTED:
#endif
			return TRUE;
		default:
			break;
	}

	return FALSE;

#elif defined _WIN32
	return (current_network_count > 0 || force_online);
#else
	return TRUE;
#endif
}

void
purple_network_force_online()
{
#if defined(HAVE_NETWORKMANAGER) || defined(_WIN32)
	force_online = TRUE;
#endif
}

#ifdef HAVE_NETWORKMANAGER
static void
nm_update_state(NMState state)
{
	NMState prev = nm_state;
	PurpleConnectionUiOps *ui_ops = purple_connections_get_ui_ops();

	have_nm_state = TRUE;
	nm_state = state;

	purple_signal_emit(purple_network_get_handle(), "network-configuration-changed", NULL);

	switch(state)
	{
#if NM_CHECK_VERSION(0,8,992)
		case NM_STATE_CONNECTED_LOCAL:
		case NM_STATE_CONNECTED_SITE:
		case NM_STATE_CONNECTED_GLOBAL:
#else
		case NM_STATE_CONNECTED:
#endif
			/* Call res_init in case DNS servers have changed */
			res_init();
			/* update STUN IP in case we it changed (theoretically we could
			   have gone from IPv4 to IPv6, f.ex. or we were previously
			   offline */
			purple_network_set_stun_server(
				purple_prefs_get_string("/purple/network/stun_server"));
			purple_network_set_turn_server(
				purple_prefs_get_string("/purple/network/turn_server"));

			if (ui_ops != NULL && ui_ops->network_connected != NULL)
				ui_ops->network_connected();
			break;
		case NM_STATE_ASLEEP:
		case NM_STATE_CONNECTING:
		case NM_STATE_DISCONNECTED:
#if NM_CHECK_VERSION(0,8,992)
		case NM_STATE_DISCONNECTING:
#endif
			if (prev != NM_STATE_CONNECTED && prev != NM_STATE_UNKNOWN)
				break;
			if (ui_ops != NULL && ui_ops->network_disconnected != NULL)
				ui_ops->network_disconnected();
			break;
		case NM_STATE_UNKNOWN:
		default:
			break;
	}
}

static void
nm_state_change_cb(DBusGProxy *proxy, NMState state, gpointer user_data)
{
	purple_debug_info("network", "Got StateChange from NetworkManager: %d.\n", state);
	nm_update_state(state);
}

static NMState
nm_get_network_state(void)
{
	GError *err = NULL;
	NMState state = NM_STATE_UNKNOWN;

	if (!nm_proxy)
		return NM_STATE_UNKNOWN;

	if (!dbus_g_proxy_call(nm_proxy, "state", &err, G_TYPE_INVALID, G_TYPE_UINT, &state, G_TYPE_INVALID)) {
		g_error_free(err);
		return NM_STATE_UNKNOWN;
	}

	return state;
}

static void
nm_dbus_name_owner_changed_cb(DBusGProxy *proxy, char *service, char *old_owner, char *new_owner, gpointer user_data)
{
	if (g_str_equal(service, NM_DBUS_SERVICE)) {
		gboolean old_owner_good = old_owner && (old_owner[0] != '\0');
		gboolean new_owner_good = new_owner && (new_owner[0] != '\0');

		purple_debug_info("network", "Got NameOwnerChanged signal, service = '%s', old_owner = '%s', new_owner = '%s'\n", service, old_owner, new_owner);
		if (!old_owner_good && new_owner_good) {	/* Equivalent to old ServiceCreated signal */
			purple_debug_info("network", "NetworkManager has started.\n");
			nm_update_state(nm_get_network_state());
		} else if (old_owner_good && !new_owner_good) {	/* Equivalent to old ServiceDeleted signal */
			purple_debug_info("network", "NetworkManager has gone away.\n");
			nm_update_state(NM_STATE_UNKNOWN);
		}
	}
}

#endif

static void
purple_network_ip_lookup_cb(GSList *hosts, gpointer data,
	const char *error_message)
{
	const gchar **ip = (const gchar **) data;

	if (error_message) {
		purple_debug_error("network", "lookup of IP address failed: %s\n",
			error_message);
		g_slist_free(hosts);
		return;
	}

	if (hosts && g_slist_next(hosts)) {
		struct sockaddr *addr = g_slist_next(hosts)->data;
		char dst[INET6_ADDRSTRLEN];

		if (addr->sa_family == AF_INET6) {
			inet_ntop(addr->sa_family, &((struct sockaddr_in6 *) addr)->sin6_addr,
				dst, sizeof(dst));
		} else {
			inet_ntop(addr->sa_family, &((struct sockaddr_in *) addr)->sin_addr,
				dst, sizeof(dst));
		}

		*ip = g_strdup(dst);
		purple_debug_info("network", "set IP address: %s\n", *ip);
	}

	while (hosts != NULL) {
		hosts = g_slist_delete_link(hosts, hosts);
		/* Free the address */
		g_free(hosts->data);
		hosts = g_slist_delete_link(hosts, hosts);
	}
}

void
purple_network_set_stun_server(const gchar *stun_server)
{
	if (stun_server && stun_server[0] != '\0') {
		if (purple_network_is_available()) {
			purple_debug_info("network", "running DNS query for STUN server\n");
			purple_dnsquery_a_account(NULL, stun_server, 3478, purple_network_ip_lookup_cb,
				&stun_ip);
		} else {
			purple_debug_info("network",
				"network is unavailable, don't try to update STUN IP");
		}
	} else if (stun_ip) {
		g_free(stun_ip);
		stun_ip = NULL;
	}
}

void
purple_network_set_turn_server(const gchar *turn_server)
{
	if (turn_server && turn_server[0] != '\0') {
		if (purple_network_is_available()) {
			purple_debug_info("network", "running DNS query for TURN server\n");
			purple_dnsquery_a_account(NULL, turn_server,
				purple_prefs_get_int("/purple/network/turn_port"),
				purple_network_ip_lookup_cb, &turn_ip);
		} else {
			purple_debug_info("network",
				"network is unavailable, don't try to update TURN IP");
		}
	} else if (turn_ip) {
		g_free(turn_ip);
		turn_ip = NULL;
	}
}


const gchar *
purple_network_get_stun_ip(void)
{
	return stun_ip;
}

const gchar *
purple_network_get_turn_ip(void)
{
	return turn_ip;
}

void *
purple_network_get_handle(void)
{
	static int handle;

	return &handle;
}

static void
purple_network_upnp_mapping_remove_cb(gboolean sucess, gpointer data)
{
	purple_debug_info("network", "done removing UPnP port mapping\n");
}

/* the reason for these functions to have these signatures is to be able to
 use them for g_hash_table_foreach to clean remaining port mappings, which is
 not yet done */
static void
purple_network_upnp_mapping_remove(gpointer key, gpointer value,
	gpointer user_data)
{
	gint port = GPOINTER_TO_INT(key);
	gint protocol = GPOINTER_TO_INT(value);
	purple_debug_info("network", "removing UPnP port mapping for port %d\n",
		port);
	purple_upnp_remove_port_mapping(port,
		protocol == SOCK_STREAM ? "TCP" : "UDP",
		purple_network_upnp_mapping_remove_cb, NULL);
	g_hash_table_remove(upnp_port_mappings, GINT_TO_POINTER(port));
}

static void
purple_network_nat_pmp_mapping_remove(gpointer key, gpointer value,
	gpointer user_data)
{
	gint port = GPOINTER_TO_INT(key);
	gint protocol = GPOINTER_TO_INT(value);
	purple_debug_info("network", "removing NAT-PMP port mapping for port %d\n",
		port);
	purple_pmp_destroy_map(
		protocol == SOCK_STREAM ? PURPLE_PMP_TYPE_TCP : PURPLE_PMP_TYPE_UDP,
		port);
	g_hash_table_remove(nat_pmp_port_mappings, GINT_TO_POINTER(port));
}

void
purple_network_remove_port_mapping(gint fd)
{
	int port = purple_network_get_port_from_fd(fd);
	gint protocol = GPOINTER_TO_INT(g_hash_table_lookup(upnp_port_mappings, GINT_TO_POINTER(port)));

	if (protocol) {
		purple_network_upnp_mapping_remove(GINT_TO_POINTER(port), GINT_TO_POINTER(protocol), NULL);
	} else {
		protocol = GPOINTER_TO_INT(g_hash_table_lookup(nat_pmp_port_mappings, GINT_TO_POINTER(port)));
		if (protocol) {
			purple_network_nat_pmp_mapping_remove(GINT_TO_POINTER(port), GINT_TO_POINTER(protocol), NULL);
		}
	}
}

int purple_network_convert_idn_to_ascii(const gchar *in, gchar **out)
{
#ifdef USE_IDN
	char *tmp;
	int ret;

	g_return_val_if_fail(out != NULL, -1);

	ret = idna_to_ascii_8z(in, &tmp, IDNA_USE_STD3_ASCII_RULES);
	if (ret != IDNA_SUCCESS) {
		*out = NULL;
		return ret;
	}

	*out = g_strdup(tmp);
	/* This *MUST* be freed with free, not g_free */
	free(tmp);
	return 0;
#else
	g_return_val_if_fail(out != NULL, -1);

	*out = g_strdup(in);
	return 0;
#endif
}

void
purple_network_init(void)
{
#ifdef HAVE_NETWORKMANAGER
	GError *error = NULL;
#endif
#ifdef _WIN32
	GError *err = NULL;
	gint cnt = wpurple_get_connected_network_count();

	network_initialized = TRUE;
	if (cnt < 0) /* Assume there is a network */
		current_network_count = 1;
	/* Don't listen for network changes if we can't tell anyway */
	else {
		current_network_count = cnt;
		if ((MyWSANSPIoctl = (void*) wpurple_find_and_loadproc("ws2_32.dll", "WSANSPIoctl"))) {
			if (!g_thread_create(wpurple_network_change_thread, NULL, FALSE, &err))
				purple_debug_error("network", "Couldn't create Network Monitor thread: %s\n", err ? err->message : "");
		}
	}
#endif

	purple_prefs_add_none  ("/purple/network");
	purple_prefs_add_string("/purple/network/stun_server", "");
	purple_prefs_add_string("/purple/network/turn_server", "");
	purple_prefs_add_int   ("/purple/network/turn_port", 3478);
	purple_prefs_add_int	 ("/purple/network/turn_port_tcp", 3478);
	purple_prefs_add_string("/purple/network/turn_username", "");
	purple_prefs_add_string("/purple/network/turn_password", "");
	purple_prefs_add_bool  ("/purple/network/auto_ip", TRUE);
	purple_prefs_add_string("/purple/network/public_ip", "");
	purple_prefs_add_bool  ("/purple/network/map_ports", TRUE);
	purple_prefs_add_bool  ("/purple/network/ports_range_use", FALSE);
	purple_prefs_add_int   ("/purple/network/ports_range_start", 1024);
	purple_prefs_add_int   ("/purple/network/ports_range_end", 2048);

	if(purple_prefs_get_bool("/purple/network/map_ports") || purple_prefs_get_bool("/purple/network/auto_ip"))
		purple_upnp_discover(NULL, NULL);

#ifdef HAVE_NETWORKMANAGER
	nm_conn = dbus_g_bus_get(DBUS_BUS_SYSTEM, &error);
	if (!nm_conn) {
		purple_debug_warning("network", "Error connecting to DBus System service: %s.\n", error->message);
	} else {
		nm_proxy = dbus_g_proxy_new_for_name(nm_conn,
		                                     NM_DBUS_SERVICE,
		                                     NM_DBUS_PATH,
		                                     NM_DBUS_INTERFACE);
		/* NM 0.6 signal */
		dbus_g_proxy_add_signal(nm_proxy, "StateChange", G_TYPE_UINT, G_TYPE_INVALID);
		dbus_g_proxy_connect_signal(nm_proxy, "StateChange",
		                            G_CALLBACK(nm_state_change_cb), NULL, NULL);
		/* NM 0.7 and later signal */
		dbus_g_proxy_add_signal(nm_proxy, "StateChanged", G_TYPE_UINT, G_TYPE_INVALID);
		dbus_g_proxy_connect_signal(nm_proxy, "StateChanged",
		                            G_CALLBACK(nm_state_change_cb), NULL, NULL);

		dbus_proxy = dbus_g_proxy_new_for_name(nm_conn,
		                                       DBUS_SERVICE_DBUS,
		                                       DBUS_PATH_DBUS,
		                                       DBUS_INTERFACE_DBUS);
		dbus_g_proxy_add_signal(dbus_proxy, "NameOwnerChanged", G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_INVALID);
		dbus_g_proxy_connect_signal(dbus_proxy, "NameOwnerChanged",
		                            G_CALLBACK(nm_dbus_name_owner_changed_cb), NULL, NULL);
	}
#endif

	purple_signal_register(purple_network_get_handle(), "network-configuration-changed",
						   purple_marshal_VOID, NULL, 0);

	purple_pmp_init();
	purple_upnp_init();

	purple_network_set_stun_server(
		purple_prefs_get_string("/purple/network/stun_server"));
	purple_network_set_turn_server(
		purple_prefs_get_string("/purple/network/turn_server"));

	upnp_port_mappings = g_hash_table_new(g_direct_hash, g_direct_equal);
	nat_pmp_port_mappings = g_hash_table_new(g_direct_hash, g_direct_equal);
}



void
purple_network_uninit(void)
{
#ifdef HAVE_NETWORKMANAGER
	if (nm_proxy) {
		dbus_g_proxy_disconnect_signal(nm_proxy, "StateChange", G_CALLBACK(nm_state_change_cb), NULL);
		dbus_g_proxy_disconnect_signal(nm_proxy, "StateChanged", G_CALLBACK(nm_state_change_cb), NULL);
		g_object_unref(G_OBJECT(nm_proxy));
	}
	if (dbus_proxy) {
		dbus_g_proxy_disconnect_signal(dbus_proxy, "NameOwnerChanged", G_CALLBACK(nm_dbus_name_owner_changed_cb), NULL);
		g_object_unref(G_OBJECT(dbus_proxy));
	}
	if (nm_conn)
		dbus_g_connection_unref(nm_conn);
#endif

#ifdef _WIN32
	g_static_mutex_lock(&mutex);
	network_initialized = FALSE;
	if (network_change_handle != NULL) {
		int retval;
		/* Trigger the NLA thread to stop waiting for network changes. Not
		 * doing this can cause hangs on WSACleanup. */
		purple_debug_warning("network", "Terminating the NLA thread\n");
		if ((retval = WSALookupServiceEnd(network_change_handle)) == SOCKET_ERROR) {
			int errorid = WSAGetLastError();
			gchar *msg = g_win32_error_message(errorid);
			purple_debug_warning("network", "Unable to kill NLA thread. Message: %s (%d).\n",
				msg, errorid);
			g_free(msg);
		}
		network_change_handle = NULL;

	}
	g_static_mutex_unlock(&mutex);

#endif
	purple_signal_unregister(purple_network_get_handle(),
							 "network-configuration-changed");

	if (stun_ip)
		g_free(stun_ip);

	g_hash_table_destroy(upnp_port_mappings);
	g_hash_table_destroy(nat_pmp_port_mappings);

	/* TODO: clean up remaining port mappings, note calling
	 purple_upnp_remove_port_mapping from here doesn't quite work... */
}
