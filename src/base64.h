/*
 *  Off-the-Record Messaging library
 *  Copyright (C) 2004-2012  Ian Goldberg, Chris Alexander, Willy Lew,
 *  			     Nikita Borisov
 *                           <otr@cypherpunks.ca>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of version 2.1 of the GNU Lesser General
 *  Public License as published by the Free Software Foundation.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef __B64_H__
#define __B64_H__

#include <cstddef>

namespace np1sec
{

/*
 * base64 encode data.  Insert no linebreaks or whitespace.
 *
 * The buffer base64data must contain at least ((datalen+2)/3)*4 bytes of
 * space.  This function will return the number of bytes actually used.
 */
size_t base64_encode(char* base64data, const unsigned char* data, size_t datalen);

/*
 * base64 decode data.  Skip non-base64 chars, and terminate at the
 * first '=', or the end of the buffer.
 *
 * The buffer data must contain at least ((base64len+3) / 4) * 3 bytes
 * of space.  This function will return the number of bytes actually
 * used.
 */
size_t base64_decode(unsigned char* data, const char* base64data, size_t base64len);

} // namespace np1sec

#endif
