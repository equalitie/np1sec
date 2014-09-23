/*
 * purple
 *
 * File: libc_interface.h
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
#ifndef _LIBC_INTERFACE_H_
#define _LIBC_INTERFACE_H_
#include <winsock2.h>
#include <ws2tcpip.h>
#include <io.h>
#include <errno.h>
#include "libc_internal.h"
#include <glib.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifdef _MSC_VER
#define S_IRUSR S_IREAD
#define S_IWUSR S_IWRITE
#define S_IXUSR S_IEXEC

#define S_ISDIR(m)	 (((m)&S_IFDIR)==S_IFDIR)

#define F_OK 0
#endif

/* sys/socket.h */
#define socket( domain, style, protocol ) \
wpurple_socket( domain, style, protocol )

#define connect( socket, addr, length ) \
wpurple_connect( socket, addr, length )

#define getsockopt( socket, level, optname, optval, optlenptr ) \
wpurple_getsockopt( socket, level, optname, optval, optlenptr )

#define setsockopt( socket, level, optname, optval, optlen ) \
wpurple_setsockopt( socket, level, optname, optval, optlen )

#define getsockname( socket, addr, lenptr ) \
wpurple_getsockname( socket, addr, lenptr )

#define bind( socket, addr, length ) \
wpurple_bind( socket, addr, length )

#define listen( socket, n ) \
wpurple_listen( socket, n )

#define sendto(socket, buf, len, flags, to, tolen) \
wpurple_sendto(socket, buf, len, flags, to, tolen)

#define recv(fd, buf, len, flags) \
wpurple_recv(fd, buf, len, flags)

#define send(socket, buf, buflen, flags) \
wpurple_send(socket, buf, buflen, flags)

/* sys/ioctl.h */
#define ioctl( fd, command, val ) \
wpurple_ioctl( fd, command, val )

/* fcntl.h */
#define fcntl( fd, command, ... ) \
wpurple_fcntl( fd, command, ##__VA_ARGS__ )

/* arpa/inet.h */
#define inet_aton( name, addr ) \
wpurple_inet_aton( name, addr )

#define inet_ntop( af, src, dst, cnt ) \
wpurple_inet_ntop( af, src, dst, cnt )

#define inet_pton( af, src, dst ) \
wpurple_inet_pton( af, src, dst )

/* netdb.h */
#define gethostbyname( name ) \
wpurple_gethostbyname( name )

/* netinet/in.h */
#define ntohl( netlong ) \
(unsigned int)ntohl( netlong )

/* string.h */
#define hstrerror( herror ) \
wpurple_strerror( errno )
#define strerror( errornum ) \
wpurple_strerror( errornum )
#define g_strerror( errornum ) \
wpurple_strerror( errornum )

/* unistd.h */
#define read( fd, buf, buflen ) \
wpurple_read( fd, buf, buflen )

#define write( socket, buf, buflen ) \
wpurple_write( socket, buf, buflen )

#define close( fd ) \
wpurple_close( fd )

#ifndef sleep
#define sleep(x) Sleep((x)*1000)
#endif

#define gethostname( name, size ) \
wpurple_gethostname( name, size )

#define fsync(fd) _commit(fd)

/* sys/time.h */
#define gettimeofday( timeval, timezone ) \
wpurple_gettimeofday( timeval, timezone )

/* stdio.h */
#undef snprintf
#define snprintf _snprintf
#undef vsnprintf
#define vsnprintf _vsnprintf

#define rename( oldname, newname ) \
wpurple_rename( oldname, newname )

/* sys/stat.h */
#define fchmod(a,b)

/* time.h */
#define localtime_r( time, resultp ) \
wpurple_localtime_r( time, resultp )

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _LIBC_INTERFACE_H_ */
