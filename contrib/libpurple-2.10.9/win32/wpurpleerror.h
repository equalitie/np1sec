/*
 * purple
 *
 * File: wpurpleerror.h
 * Date: October 14, 2002
 * Description: Convert Winsock errors to Unix errors
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
#ifndef _WPURPLEERROR_H
#define _WPURPLEERROR_H

/* Here we define unix socket errors as windows socket errors */

#define ENETDOWN WSAENETDOWN
#define EAFNOSUPPORT WSAEAFNOSUPPORT
#define EINPROGRESS WSAEINPROGRESS
#define ENOBUFS WSAENOBUFS
#define EPROTONOSUPPORT WSAEPROTONOSUPPORT
#define EPROTOTYPE WSAEPROTOTYPE
#define ESOCKTNOSUPPORT WSAESOCKTNOSUPPORT

#define EADDRINUSE WSAEADDRINUSE
#define EINPROGRESS WSAEINPROGRESS
#define EALREADY WSAEALREADY
#define EADDRNOTAVAIL WSAEADDRNOTAVAIL
#define ECONNREFUSED WSAECONNREFUSED
#define EISCONN WSAEISCONN
#define ENETUNREACH WSAENETUNREACH
#define ENOTSOCK WSAENOTSOCK
#define ETIMEDOUT WSAETIMEDOUT
#define EWOULDBLOCK WSAEWOULDBLOCK

#define ENOTCONN WSAENOTCONN
#define ENETRESET WSAENETRESET
#define EOPNOTSUPP WSAEOPNOTSUPP
#define ESHUTDOWN WSAESHUTDOWN
#define EMSGSIZE WSAEMSGSIZE
#define ECONNABORTED WSAECONNABORTED
#define ECONNRESET WSAECONNRESET
#define EHOSTUNREACH WSAEHOSTUNREACH

#endif /* end _WPURPLEERROR_H */
