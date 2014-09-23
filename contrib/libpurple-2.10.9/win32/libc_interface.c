/*
 * purple
 *
 * Copyright (C) 2002-2003, Herman Bloggs <hermanator12002@yahoo.com>
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
 *
 */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <io.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/timeb.h>
#include <sys/stat.h>
#include <time.h>
#include <glib.h>
#include "config.h"
#include "debug.h"
#include "libc_internal.h"
#include <glib/gstdio.h>

/** This is redefined here because we can't include internal.h */
#ifdef ENABLE_NLS
#  include <locale.h>
#  include <libintl.h>
#  define _(String) ((const char *)dgettext(PACKAGE, String))
#  ifdef gettext_noop
#    define N_(String) gettext_noop (String)
#  else
#    define N_(String) (String)
#  endif
#else
#  include <locale.h>
#  define N_(String) (String)
#  ifndef _
#    define _(String) ((const char *)String)
#  endif
#  define ngettext(Singular, Plural, Number) ((Number == 1) ? ((const char *)Singular) : ((const char *)Plural))
#  define dngettext(Domain, Singular, Plural, Number) ((Number == 1) ? ((const char *)Singular) : ((const char *)Plural))
#endif

#ifndef S_ISDIR
# define S_ISDIR(m) (((m)&S_IFDIR)==S_IFDIR)
#endif

static char errbuf[1024];

/* helpers */
static int wpurple_is_socket( int fd ) {
	int optval;
	int optlen = sizeof(int);

	if( (getsockopt(fd, SOL_SOCKET, SO_TYPE, (void*)&optval, &optlen)) == SOCKET_ERROR ) {
		int error = WSAGetLastError();
		if( error == WSAENOTSOCK )
			return FALSE;
		else {
                        purple_debug(PURPLE_DEBUG_WARNING, "wpurple", "wpurple_is_socket: getsockopt returned error: %d\n", error);
			return FALSE;
		}
	}
	return TRUE;
}

/* socket.h */
int wpurple_socket (int namespace, int style, int protocol) {
	int ret;

	ret = socket( namespace, style, protocol );

	if( ret == INVALID_SOCKET ) {
		errno = WSAGetLastError();
		return -1;
	}
	return ret;
}

int wpurple_connect(int socket, struct sockaddr *addr, u_long length) {
	int ret;

	ret = connect( socket, addr, length );

	if( ret == SOCKET_ERROR ) {
		errno = WSAGetLastError();
		if( errno == WSAEWOULDBLOCK )
			errno = WSAEINPROGRESS;
		return -1;
	}
	return 0;
}

int wpurple_getsockopt(int socket, int level, int optname, void *optval, socklen_t *optlenptr) {
	if(getsockopt(socket, level, optname, optval, optlenptr) == SOCKET_ERROR ) {
		errno = WSAGetLastError();
		return -1;
	}
	return 0;
}

int wpurple_setsockopt(int socket, int level, int optname, const void *optval, socklen_t optlen) {
	if(setsockopt(socket, level, optname, optval, optlen) == SOCKET_ERROR ) {
		errno = WSAGetLastError();
		return -1;
	}
	return 0;
}

int wpurple_getsockname(int socket, struct sockaddr *addr, socklen_t *lenptr) {
        if(getsockname(socket, addr, lenptr) == SOCKET_ERROR) {
                errno = WSAGetLastError();
                return -1;
        }
        return 0;
}

int wpurple_bind(int socket, struct sockaddr *addr, socklen_t length) {
        if(bind(socket, addr, length) == SOCKET_ERROR) {
                errno = WSAGetLastError();
                return -1;
        }
        return 0;
}

int wpurple_listen(int socket, unsigned int n) {
        if(listen(socket, n) == SOCKET_ERROR) {
                errno = WSAGetLastError();
                return -1;
        }
        return 0;
}

int wpurple_sendto(int socket, const void *buf, size_t len, int flags, const struct sockaddr *to, socklen_t tolen) {
	int ret;
	if ((ret = sendto(socket, buf, len, flags, to, tolen)
			) == SOCKET_ERROR) {
		errno = WSAGetLastError();
		if(errno == WSAEWOULDBLOCK || errno == WSAEINPROGRESS)
			errno = EAGAIN;
		return -1;
	}
	return ret;
}

/* fcntl.h */
/* This is not a full implementation of fcntl. Update as needed.. */
int wpurple_fcntl(int socket, int command, ...) {

	switch( command ) {
	case F_GETFL:
		return 0;

	case F_SETFL:
	{
		va_list args;
		int val;
		int ret=0;

		va_start(args, command);
		val = va_arg(args, int);
		va_end(args);

		switch( val ) {
		case O_NONBLOCK:
		{
			u_long imode=1;
			ret = ioctlsocket(socket, FIONBIO, &imode);
			break;
		}
		case 0:
		{
			u_long imode=0;
			ret = ioctlsocket(socket, FIONBIO, &imode);
			break;
		}
		default:
			errno = EINVAL;
			return -1;
		}/*end switch*/
		if( ret == SOCKET_ERROR ) {
			errno = WSAGetLastError();
			return -1;
		}
		return 0;
	}
	default:
                purple_debug(PURPLE_DEBUG_WARNING, "wpurple", "wpurple_fcntl: Unsupported command\n");
		return -1;
	}/*end switch*/
}

/* sys/ioctl.h */
int wpurple_ioctl(int fd, int command, void* val) {
	switch( command ) {
	case FIONBIO:
	{
		if (ioctlsocket(fd, FIONBIO, (unsigned long *)val) == SOCKET_ERROR) {
			errno = WSAGetLastError();
			return -1;
		}
		return 0;
	}
	case SIOCGIFCONF:
	{
		INTERFACE_INFO InterfaceList[20];
		unsigned long nBytesReturned;
		if (WSAIoctl(fd, SIO_GET_INTERFACE_LIST,
				0, 0, &InterfaceList,
				sizeof(InterfaceList), &nBytesReturned,
				0, 0) == SOCKET_ERROR) {
			errno = WSAGetLastError();
			return -1;
		} else {
			int i;
			struct ifconf *ifc = val;
			char *tmp = ifc->ifc_buf;
			int nNumInterfaces =
				nBytesReturned / sizeof(INTERFACE_INFO);
			for (i = 0; i < nNumInterfaces; i++) {
				INTERFACE_INFO ii = InterfaceList[i];
				struct ifreq *ifr = (struct ifreq *) tmp;
				struct sockaddr_in *sa = (struct sockaddr_in *) &ifr->ifr_addr;

				sa->sin_family = ii.iiAddress.AddressIn.sin_family;
				sa->sin_port = ii.iiAddress.AddressIn.sin_port;
				sa->sin_addr.s_addr = ii.iiAddress.AddressIn.sin_addr.s_addr;
				tmp += sizeof(struct ifreq);

				/* Make sure that we can fit in the original buffer */
				if (tmp >= (ifc->ifc_buf + ifc->ifc_len + sizeof(struct ifreq))) {
					break;
				}
			}
			/* Replace the length with the actually used length */
			ifc->ifc_len = ifc->ifc_len - (ifc->ifc_buf - tmp);
			return 0;
		}
	}
	default:
		errno = EINVAL;
		return -1;
	}/*end switch*/
}

/* arpa/inet.h */
int wpurple_inet_aton(const char *name, struct in_addr *addr) {
	if((addr->s_addr = inet_addr(name)) == INADDR_NONE)
		return 0;
	else
		return 1;
}

/* Thanks to GNU wget for this inet_ntop() implementation */
const char *
wpurple_inet_ntop (int af, const void *src, char *dst, socklen_t cnt)
{
  /* struct sockaddr can't accomodate struct sockaddr_in6. */
  union {
    struct sockaddr_in6 sin6;
    struct sockaddr_in sin;
  } sa;
  DWORD dstlen = cnt;
  size_t srcsize;

  ZeroMemory(&sa, sizeof(sa));
  switch (af)
    {
    case AF_INET:
      sa.sin.sin_family = AF_INET;
      sa.sin.sin_addr = *(struct in_addr *) src;
      srcsize = sizeof (sa.sin);
      break;
    case AF_INET6:
      sa.sin6.sin6_family = AF_INET6;
      sa.sin6.sin6_addr = *(struct in6_addr *) src;
      srcsize = sizeof (sa.sin6);
      break;
    default:
      abort ();
    }

  if (WSAAddressToString ((struct sockaddr *) &sa, srcsize, NULL, dst, &dstlen) != 0)
    {
      errno = WSAGetLastError();
      return NULL;
    }
  return (const char *) dst;
}

int
wpurple_inet_pton(int af, const char *src, void *dst)
{
	/* struct sockaddr can't accomodate struct sockaddr_in6. */
	union {
		struct sockaddr_in6 sin6;
		struct sockaddr_in sin;
	} sa;
	size_t srcsize;
	
	switch(af)
	{
		case AF_INET:
			sa.sin.sin_family = AF_INET;
			srcsize = sizeof (sa.sin);
		break;
		case AF_INET6:
			sa.sin6.sin6_family = AF_INET6;
			srcsize = sizeof (sa.sin6);
		break;
		default:
			errno = WSAEPFNOSUPPORT;
			return -1;
	}
	
	if (WSAStringToAddress(src, af, NULL, (struct sockaddr *) &sa, &srcsize) != 0)
	{
		errno = WSAGetLastError();
		return -1;
	}
	
	switch(af)
	{
		case AF_INET:
			memcpy(dst, &sa.sin.sin_addr, sizeof(sa.sin.sin_addr));
		break;
		case AF_INET6:
			memcpy(dst, &sa.sin6.sin6_addr, sizeof(sa.sin6.sin6_addr));
		break;
	}
	
	return 1;
}


/* netdb.h */
struct hostent* wpurple_gethostbyname(const char *name) {
	struct hostent *hp;

	if((hp = gethostbyname(name)) == NULL) {
		errno = WSAGetLastError();
		return NULL;
	}
	return hp;
}

/* string.h */
char* wpurple_strerror(int errornum) {
	if (errornum > WSABASEERR) {
		switch(errornum) {
			case WSAECONNABORTED: /* 10053 */
				g_snprintf(errbuf, sizeof(errbuf), "%s", _("Connection interrupted by other software on your computer."));
				break;
			case WSAECONNRESET: /* 10054 */
				g_snprintf(errbuf, sizeof(errbuf), "%s", _("Remote host closed connection."));
				break;
			case WSAETIMEDOUT: /* 10060 */
				g_snprintf(errbuf, sizeof(errbuf), "%s", _("Connection timed out."));
				break;
			case WSAECONNREFUSED: /* 10061 */
				g_snprintf(errbuf, sizeof(errbuf), "%s", _("Connection refused."));
				break;
			case WSAEADDRINUSE: /* 10048 */
				g_snprintf(errbuf, sizeof(errbuf), "%s", _("Address already in use."));
				break;
			default:
				g_snprintf(errbuf, sizeof(errbuf), "Windows socket error #%d", errornum);
		}
	} else {
		const char *tmp = g_strerror(errornum);
		g_snprintf(errbuf, sizeof(errbuf), "%s", tmp);
	}
	return errbuf;
}

/* unistd.h */

/*
 *  We need to figure out whether fd is a file or socket handle.
 */
int wpurple_read(int fd, void *buf, unsigned int size) {
	int ret;

	if (fd < 0) {
		errno = EBADF;
		g_return_val_if_reached(-1);
	}

	if(wpurple_is_socket(fd)) {
		if((ret = recv(fd, buf, size, 0)) == SOCKET_ERROR) {
			errno = WSAGetLastError();
			if(errno == WSAEWOULDBLOCK || errno == WSAEINPROGRESS)
				errno = EAGAIN;
			return -1;
		}
#if 0
		else if( ret == 0 ) {
			/* connection has been gracefully closed */
			errno = WSAENOTCONN;
			return -1;
		}
#endif
		else {
			/* success reading socket */
			return ret;
		}
	} else {
		/* fd is not a socket handle.. pass it off to read */
		return _read(fd, buf, size);
	}
}

int wpurple_send(int fd, const void *buf, unsigned int size, int flags) {
	int ret;

	ret = send(fd, buf, size, flags);

	if (ret == SOCKET_ERROR) {
		errno = WSAGetLastError();
		if(errno == WSAEWOULDBLOCK || errno == WSAEINPROGRESS)
			errno = EAGAIN;
		return -1;
	}
	return ret;
}

int wpurple_write(int fd, const void *buf, unsigned int size) {

	if (fd < 0) {
		errno = EBADF;
		g_return_val_if_reached(-1);
	}

	if(wpurple_is_socket(fd))
		return wpurple_send(fd, buf, size, 0);
	else
		return _write(fd, buf, size);
}

int wpurple_recv(int fd, void *buf, size_t len, int flags) {
	int ret;

	if((ret = recv(fd, buf, len, flags)) == SOCKET_ERROR) {
			errno = WSAGetLastError();
			if(errno == WSAEWOULDBLOCK || errno == WSAEINPROGRESS)
				errno = EAGAIN;
			return -1;
	} else {
		return ret;
	}
}

int wpurple_close(int fd) {
	int ret;

	if (fd < 0) {
		errno = EBADF;
		g_return_val_if_reached(-1);
	}

	if( wpurple_is_socket(fd) ) {
		if( (ret = closesocket(fd)) == SOCKET_ERROR ) {
			errno = WSAGetLastError();
			return -1;
		}
		else
			return 0;
	}
	else
		return _close(fd);
}

int wpurple_gethostname(char *name, size_t size) {
        if(gethostname(name, size) == SOCKET_ERROR) {
                errno = WSAGetLastError();
			return -1;
        }
        return 0;
}

/* sys/time.h */

int wpurple_gettimeofday(struct timeval *p, struct timezone *z) {
	int res = 0;
	struct _timeb timebuffer;

	if (z != 0) {
		_tzset();
		z->tz_minuteswest = _timezone/60;
		z->tz_dsttime = _daylight;
	}

	if (p != 0) {
		_ftime(&timebuffer);
		p->tv_sec = timebuffer.time;			/* seconds since 1-1-1970 */
		p->tv_usec = timebuffer.millitm*1000; 	/* microseconds */
	}

	return res;
}

/* stdio.h */

int wpurple_rename (const char *oldname, const char *newname) {
	return g_rename(oldname, newname);
}

/* time.h */

struct tm * wpurple_localtime_r (const time_t *time, struct tm *resultp) {
	struct tm* tmptm;

	if(!time)
		return NULL;
	tmptm = localtime(time);
	if(resultp && tmptm)
		return memcpy(resultp, tmptm, sizeof(struct tm));
	else
		return NULL;
}

/*
 * Used by purple_utf8_strftime() by way of purple_internal_strftime()
 * in src/util.c
 *
 * Code derived from PostgreSQL src/timezone/pgtz.c:
 * http://developer.postgresql.org/cvsweb.cgi/pgsql/src/timezone/pgtz.c
 */

/*
PostgreSQL Database Management System
(formerly known as Postgres, then as Postgres95)

Portions Copyright (c) 1996-2005, PostgreSQL Global Development Group

Portions Copyright (c) 1994, The Regents of the University of California

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose, without fee, and without a written agreement
is hereby granted, provided that the above copyright notice and this
paragraph and the following two paragraphs appear in all copies.

IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO ANY PARTY FOR
DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES, INCLUDING
LOST PROFITS, ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS
DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA HAS BEEN ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS FOR A PARTICULAR PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS
ON AN "AS IS" BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATIONS TO
PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR MODIFICATIONS.

*/
static struct
{
	char *wstd;		/* Windows name of standard timezone */
	char *wdst;		/* Windows name of daylight timezone */
	char *ustd;		/* Unix name of standard timezone */
	char *udst;		/* Unix name of daylight timezone */
} win32_tzmap[] =
{
	{
		"", "",
		"", "",
	},
	/*
	 * This list was built from the contents of the registry at
	 * "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Time Zones"
	 * on Windows XP Professional SP1
	 */
	{
		"Afghanistan Standard Time", "Afghanistan Daylight Time",
		"AFT", "AFT"
	},
	{
		"Alaskan Standard Time", "Alaskan Daylight Time",
		"AKST", "AKDT"
	},
	{
		"Arab Standard Time", "Arab Daylight Time",
		"AST", "AST"
	},
	{
		"Arabian Standard Time", "Arabian Daylight Time",
		"GST", "GST"
	},
	{
		"Arabic Standard Time", "Arabic Daylight Time",
		"AST", "ADT"
	},
	{
		"Atlantic Standard Time", "Atlantic Daylight Time",
		"AST", "ADT"
	},
	{
		"AUS Central Standard Time", "AUS Central Daylight Time",
		"CST", "CST"
	},
	{
		"AUS Eastern Standard Time", "AUS Eastern Daylight Time",
		"EST", "EST"
	},
	{
		"Azores Standard Time", "Azores Daylight Time",
		"AZOT", "AZOST"
	},
	{
		"Canada Central Standard Time", "Canada Central Daylight Time",
		"CST", "MDT"
	},
	{
		"Cape Verde Standard Time", "Cape Verde Daylight Time",
		"CVT", "CVST"
	},
	{
		"Caucasus Standard Time", "Caucasus Daylight Time",
		"AZT", "AZST"
	},
	{
		"Cen. Australia Standard Time", "Cen. Australia Daylight Time",
		"CST", "CST"
	},
	{
		"Central America Standard Time", "Central America Daylight Time",
		"CST", "CDT"
	},
	{
		"Central Asia Standard Time", "Central Asia Daylight Time",
		"BDT", "BDT"
	},
	{
		"Central Europe Standard Time", "Central Europe Daylight Time",
		"CET", "CEST"
	},
	{
		"Central European Standard Time", "Central European Daylight Time",
		"CET", "CEST"
	},
	{
		"Central Pacific Standard Time", "Central Pacific Daylight Time",
		"NCT", "NCST"
	},
	{
		"Central Standard Time", "Central Daylight Time",
		"CST", "CDT"
	},
	{
		"China Standard Time", "China Daylight Time",
		"HKT", "HKST"
	},
	{
		"Dateline Standard Time", "Dateline Daylight Time",
		"GMT+12", "GMT+12"
	},
	{
		"E. Africa Standard Time", "E. Africa Daylight Time",
		"EAT", "EAT"
	},
	{
		"E. Australia Standard Time", "E. Australia Daylight Time",
		"EST", "EST"
	},
	{
		"E. Europe Standard Time", "E. Europe Daylight Time",
		"EET", "EEST"
	},
	{
		"E. South America Standard Time", "E. South America Daylight Time",
		"BRT", "BRST"
	},
	{
		"Eastern Standard Time", "Eastern Daylight Time",
		"EST", "EDT"
	},
	{
		"Egypt Standard Time", "Egypt Daylight Time",
		"EET", "EEST"
	},
	{
		"Ekaterinburg Standard Time", "Ekaterinburg Daylight Time",
		"YEKT", "YEKST"
	},
	{
		"Fiji Standard Time", "Fiji Daylight Time",
		"FJT", "FJST"
	},
	{
		"FLE Standard Time", "FLE Daylight Time",
		"EET", "EEST"
	},
	{
		"GMT Standard Time", "GMT Daylight Time",
		"GMT", "IST"
	},
	{
		"Greenland Standard Time", "Greenland Daylight Time",
		"WGT", "WGST"
	},
	{
		"Greenwich Standard Time", "Greenwich Daylight Time",
		"WET", "WEST"
	},
	{
		"GTB Standard Time", "GTB Daylight Time",
		"EET", "EEST"
	},
	{
		"Hawaiian Standard Time", "Hawaiian Daylight Time",
		"HST", "HPT"
	},
	{
		"India Standard Time", "India Daylight Time",
		"IST", "IST"
	},
	{
		"Iran Standard Time", "Iran Daylight Time",
		"IRST", "IRDT"
	},
	{
		"Jerusalem Standard Time", "Jerusalem Daylight Time",
		"IST", "IDT"
	},
	{
		"Korea Standard Time", "Korea Daylight Time",
		"KST", "KDT"
	},
	{
		"Mexico Standard Time", "Mexico Daylight Time",
		"CST", "CDT"
	},
	{
		"Mexico Standard Time", "Mexico Daylight Time",
		"BOT", "BOST"
	},
	{
		"Mid-Atlantic Standard Time", "Mid-Atlantic Daylight Time",
		"GST", "GST"
	},
	{
		"Mountain Standard Time", "Mountain Daylight Time",
		"MST", "MDT"
	},
	{
		"Myanmar Standard Time", "Myanmar Daylight Time",
		"MMT", "MMT"
	},
	{
		"N. Central Asia Standard Time", "N. Central Asia Daylight Time",
		"ALMT", "ALMST"
	},
	{
		"Nepal Standard Time", "Nepal Daylight Time",
		"NPT", "NPT"
	},
	{
		"New Zealand Standard Time", "New Zealand Daylight Time",
		"NZST", "NZDT"
	},
	{
		"Newfoundland Standard Time", "Newfoundland Daylight Time",
		"NST", "NDT"
	},
	{
		"North Asia East Standard Time", "North Asia East Daylight Time",
		"IRKT", "IRKST"
	},
	{
		"North Asia Standard Time", "North Asia Daylight Time",
		"KRAT", "KRAST"
	},
	{
		"Pacific SA Standard Time", "Pacific SA Daylight Time",
		"CLT", "CLST"
	},
	{
		"Pacific Standard Time", "Pacific Daylight Time",
		"PST", "PDT"
	},
	{
		"Romance Standard Time", "Romance Daylight Time",
		"CET", "CEST"
	},
	{
		"Russian Standard Time", "Russian Daylight Time",
		"MSK", "MSD"
	},
	{
		"SA Eastern Standard Time", "SA Eastern Daylight Time",
		"ART", "ARST"
	},
	{
		"SA Pacific Standard Time", "SA Pacific Daylight Time",
		"COT", "COST"
	},
	{
		"SA Western Standard Time", "SA Western Daylight Time",
		"VET", "VET"
	},
	{
		"Samoa Standard Time", "Samoa Daylight Time",
		"SST", "NDT"
	},
	{
		"SE Asia Standard Time", "SE Asia Daylight Time",
		"ICT", "ICT"
	},
	{
		"Malay Peninsula Standard Time", "Malay Peninsula Daylight Time",
		"MYT", "MALST"
	},
	{
		"South Africa Standard Time", "South Africa Daylight Time",
		"CAT", "CAT"
	},
	{
		"Sri Lanka Standard Time", "Sri Lanka Daylight Time",
		"LKT", "IST"
	},
	{
		"Taipei Standard Time", "Taipei Daylight Time",
		"CST", "CDT"
	},
	{
		"Tasmania Standard Time", "Tasmania Daylight Time",
		"EST", "EST"
	},
	{
		"Tokyo Standard Time", "Tokyo Daylight Time",
		"JST", "JDT"
	},
	{
		"Tonga Standard Time", "Tonga Daylight Time",
		"TOT", "TOST"
	},
	{
		"US Eastern Standard Time", "US Eastern Daylight Time",
		"EST", "EDT"
	},
	{
		"US Mountain Standard Time", "US Mountain Daylight Time",
		"MST", "MDT"
	},
	{
		"Vladivostok Standard Time", "Vladivostok Daylight Time",
		"VLAT", "VLAST"
	},
	{
		"W. Australia Standard Time", "W. Australia Daylight Time",
		"WST", "WST"
	},

	/* Not mapped in PostgreSQL.
	 *
	 * I mapped this based on the following information... -- rlaager
	 * $ cd /usr/share/zoneinfo/Africa
	 * $ for i in * ; do echo `TZ=Africa/$i date +"%z %Z"` $i ; done | grep +0100
	 * +0100 CET Algiers
	 * +0100 WAT Bangui
	 * +0100 WAT Brazzaville
	 * +0100 CET Ceuta
	 * +0100 WAT Douala
	 * +0100 WAT Kinshasa
	 * +0100 WAT Lagos
	 * +0100 WAT Libreville
	 * +0100 WAT Luanda
	 * +0100 WAT Malabo
	 * +0100 WAT Ndjamena
	 * +0100 WAT Niamey
	 * +0100 WAT Porto-Novo
	 * +0100 CET Tunis
	 **/
	{
		"W. Central Africa Standard Time", "W. Central Africa Daylight Time",
		"WAT", "WAT"
	},

	{
		"W. Europe Standard Time", "W. Europe Daylight Time",
		"CET", "CEST"
	},
	{
		"West Asia Standard Time", "West Asia Daylight Time",
		"PKT", "PKST"
	},
	{
		"West Pacific Standard Time", "West Pacific Daylight Time",
		"ChST", "ChST"
	},
	{
		"Yakutsk Standard Time", "Yakutsk Daylight Time",
		"YAKT", "YAKST"
	},
	{
		NULL, NULL,
		NULL, NULL
	}
};

const char *
wpurple_get_timezone_abbreviation(const struct tm *tm)
{
	int i;
	char tzname[128];
	char localtzname[256];
	HKEY rootKey;
	int idx;

	if (!tm)
	{
		purple_debug_warning("wpurple", "could not determine current date/time: localtime failed\n");
		return "";
	}

	if (strftime(tzname, sizeof(tzname) - 1, "%Z", tm) == 0)
	{
		purple_debug_error("wpurple", "timezone name is too long for the buffer\n");
		return "";
	}

	for (i = 0; win32_tzmap[i].wstd != NULL; i++)
	{
		if (strcmp(tzname, win32_tzmap[i].wstd) == 0)
		{
#if 0
			purple_debug_info("wpurple", "TZ \"%s\" matches Windows timezone \"%s\"\n",
			                win32_tzmap[i].ustd, tzname);
#endif
			/* Cache the Result */
			if (i > 0) {
				if (win32_tzmap[0].wstd[0] != '\0')
					g_free(win32_tzmap[0].wstd);
				win32_tzmap[0].wstd = g_strdup(tzname);
				win32_tzmap[0].ustd = win32_tzmap[i].ustd;
			}

			return win32_tzmap[i].ustd;
		}
		if (strcmp(tzname, win32_tzmap[i].wdst) == 0)
		{
#if 0
			purple_debug_info("wpurple", "TZ \"%s\" matches Windows timezone \"%s\"\n",
			                win32_tzmap[i].udst, tzname);
#endif
			/* Cache the Result */
			if (i > 0) {
				if (win32_tzmap[0].wdst[0] != '\0')
					g_free(win32_tzmap[0].wdst);
				win32_tzmap[0].wdst = g_strdup(tzname);
				win32_tzmap[0].udst = win32_tzmap[i].udst;
			}

			return win32_tzmap[i].udst;
		}
	}

	/*
	 * Localized Windows versions return localized names for the timezone.
	 * Scan the registry to find the English name, and then try matching
	 * against our table again.
	 */
	memset(localtzname, 0, sizeof(localtzname));
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
			   "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Time Zones",
					 0,
					 KEY_READ,
					 &rootKey) != ERROR_SUCCESS)
	{
		purple_debug_warning("wpurple", "could not open registry key to identify Windows timezone: %i\n", (int) GetLastError());
		return "";
	}

	for (idx = 0;; idx++)
	{
		char keyname[256];
		char zonename[256];
		DWORD namesize;
		FILETIME lastwrite;
		HKEY key;
		LONG r;

		memset(keyname, 0, sizeof(keyname));
		namesize = sizeof(keyname);
		if ((r = RegEnumKeyEx(rootKey,
							  idx,
							  keyname,
							  &namesize,
							  NULL,
							  NULL,
							  NULL,
							  &lastwrite)) != ERROR_SUCCESS)
		{
			if (r == ERROR_NO_MORE_ITEMS)
				break;
			purple_debug_warning("wpurple", "could not enumerate registry subkeys to identify Windows timezone: %i\n", (int) r);
			break;
		}

		if ((r = RegOpenKeyEx(rootKey, keyname, 0, KEY_READ, &key)) != ERROR_SUCCESS)
		{
			purple_debug_warning("wpurple", "could not open registry subkey to identify Windows timezone: %i\n", (int) r);
			break;
		}

		memset(zonename, 0, sizeof(zonename));
		namesize = sizeof(zonename);
		if ((r = RegQueryValueEx(key, "Std", NULL, NULL, (LPBYTE)zonename, &namesize)) != ERROR_SUCCESS)
		{
			purple_debug_warning("wpurple", "could not query value for 'std' to identify Windows timezone: %i\n", (int) r);
			RegCloseKey(key);
			break;
		}
		if (strcmp(tzname, zonename) == 0)
		{
			/* Matched zone */
			g_strlcpy(localtzname, keyname, sizeof(localtzname));
			RegCloseKey(key);
			break;
		}
		memset(zonename, 0, sizeof(zonename));
		namesize = sizeof(zonename);
		if ((r = RegQueryValueEx(key, "Dlt", NULL, NULL, (LPBYTE)zonename, &namesize)) != ERROR_SUCCESS)
		{
			purple_debug_warning("wpurple", "could not query value for 'dlt' to identify Windows timezone: %i\n", (int) r);
			RegCloseKey(key);
			break;
		}
		if (strcmp(tzname, zonename) == 0)
		{
			/* Matched DST zone */
			g_strlcpy(localtzname, keyname, sizeof(localtzname));
			RegCloseKey(key);
			break;
		}

		RegCloseKey(key);
	}

	RegCloseKey(rootKey);

	if (localtzname[0])
	{
		/* Found a localized name, so scan for that one too */
		for (i = 0; win32_tzmap[i].wstd != NULL; i++)
		{
			if (strcmp(localtzname, win32_tzmap[i].wstd) == 0)
			{
#if 0
				purple_debug_info("wpurple", "TZ \"%s\" matches localized Windows timezone \"%s\" (\"%s\")\n",
				                win32_tzmap[i].ustd, tzname, localtzname);
#endif
				/* Cache the Result */
				if (win32_tzmap[0].wstd[0] != '\0')
					g_free(win32_tzmap[0].wstd);
				win32_tzmap[0].wstd = g_strdup(tzname);
				win32_tzmap[0].ustd = win32_tzmap[i].ustd;

				return win32_tzmap[i].ustd;
			}
			if (strcmp(localtzname, win32_tzmap[i].wdst) == 0)
			{
#if 0
				purple_debug_info("wpurple", "TZ \"%s\" matches localized Windows timezone \"%s\" (\"%s\")\n",
				                win32_tzmap[i].udst, tzname, localtzname);
#endif
				/* Cache the Result */
				if (win32_tzmap[0].wdst[0] != '\0')
					g_free(win32_tzmap[0].wdst);

				win32_tzmap[0].wdst = g_strdup(tzname);
				win32_tzmap[0].udst = win32_tzmap[i].udst;

				return win32_tzmap[i].udst;
			}
		}
	}

	purple_debug_warning("wpurple", "could not find a match for Windows timezone \"%s\"\n", tzname);
	return "";
}

int wpurple_g_access (const gchar *filename, int mode);
/**
 * @deprecated - remove for 3.0.0
 */
int
wpurple_g_access (const gchar *filename, int mode)
{
	return g_access(filename, mode);
}


