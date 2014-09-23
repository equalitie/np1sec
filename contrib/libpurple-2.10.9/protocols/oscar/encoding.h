/*
 * Purple's oscar protocol plugin
 * This file is the legal property of its developers.
 * Please see the AUTHORS file distributed alongside this file.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02111-1301  USA
*/

#ifndef _ENCODING_H_
#define _ENCODING_H_

#include "oscar.h"
#include "oscarcommon.h"

gchar * oscar_encoding_to_utf8(const char *encoding, const char *text, int textlen);
gchar * oscar_utf8_try_convert(PurpleAccount *account, OscarData *od, const gchar *msg);

/**
 * This attemps to decode an incoming IM into a UTF8 string.
 *
 * We try decoding using two different character sets.  The charset
 * specified in the IM determines the order in which we attempt to
 * decode.  We do this because there are lots of broken ICQ clients
 * that don't correctly send non-ASCII messages.  And if Purple isn't
 * able to deal with that crap, then people complain like banshees.
 */
gchar * oscar_decode_im(PurpleAccount *account, const char *sourcebn, guint16 charset, const gchar *data, gsize datalen);

/**
 * Figure out what encoding to use when sending a given outgoing message.
 */
gchar * oscar_encode_im(const gchar *msg, gsize *result_len, guint16 *charset, gchar **charsetstr);

#endif