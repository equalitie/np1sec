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

#include "oscar.h"

static aim_tlv_t *
createtlv(guint16 type, guint16 length, guint8 *value)
{
	aim_tlv_t *ret;

	ret = g_new(aim_tlv_t, 1);
	ret->type = type;
	ret->length = length;
	ret->value = value;

	return ret;
}

static void
freetlv(aim_tlv_t *oldtlv)
{
	g_free(oldtlv->value);
	g_free(oldtlv);
}

static GSList *
aim_tlv_read(GSList *list, ByteStream *bs)
{
	guint16 type, length;
	aim_tlv_t *tlv;

	type = byte_stream_get16(bs);
	length = byte_stream_get16(bs);

	if (length > byte_stream_bytes_left(bs)) {
		aim_tlvlist_free(list);
		return NULL;
	}

	tlv = createtlv(type, length, NULL);
	if (tlv->length > 0) {
		tlv->value = byte_stream_getraw(bs, length);
		if (!tlv->value) {
			freetlv(tlv);
			aim_tlvlist_free(list);
			return NULL;
		}
	}

	return g_slist_prepend(list, tlv);
}

/**
 * Read a TLV chain from a buffer.
 *
 * Reads and parses a series of TLV patterns from a data buffer; the
 * returned structure is manipulatable with the rest of the TLV
 * routines.  When done with a TLV chain, aim_tlvlist_free() should
 * be called to free the dynamic substructures.
 *
 * TODO: There should be a flag setable here to have the tlvlist contain
 * bstream references, so that at least the ->value portion of each
 * element doesn't need to be malloc/memcpy'd.  This could prove to be
 * just as efficient as the in-place TLV parsing used in a couple places
 * in libfaim.
 *
 * @param bs Input bstream
 * @return Return the TLV chain read
 */
GSList *aim_tlvlist_read(ByteStream *bs)
{
	GSList *list = NULL;

	while (byte_stream_bytes_left(bs) > 0) {
		list = aim_tlv_read(list, bs);
		if (list == NULL)
			return NULL;
	}

	return g_slist_reverse(list);
}

/**
 * Read a TLV chain from a buffer.
 *
 * Reads and parses a series of TLV patterns from a data buffer; the
 * returned structure is manipulatable with the rest of the TLV
 * routines.  When done with a TLV chain, aim_tlvlist_free() should
 * be called to free the dynamic substructures.
 *
 * TODO: There should be a flag setable here to have the tlvlist contain
 * bstream references, so that at least the ->value portion of each
 * element doesn't need to be malloc/memcpy'd.  This could prove to be
 * just as efficient as the in-place TLV parsing used in a couple places
 * in libfaim.
 *
 * @param bs Input bstream
 * @param num The max number of TLVs that will be read, or -1 if unlimited.
 *        There are a number of places where you want to read in a tlvchain,
 *        but the chain is not at the end of the SNAC, and the chain is
 *        preceded by the number of TLVs.  So you can limit that with this.
 * @return Return the TLV chain read
 */
GSList *aim_tlvlist_readnum(ByteStream *bs, guint16 num)
{
	GSList *list = NULL;

	while ((byte_stream_bytes_left(bs) > 0) && (num != 0)) {
		list = aim_tlv_read(list, bs);
		if (list == NULL)
			return NULL;
		num--;
	}

	return g_slist_reverse(list);
}

/**
 * Read a TLV chain from a buffer.
 *
 * Reads and parses a series of TLV patterns from a data buffer; the
 * returned structure is manipulatable with the rest of the TLV
 * routines.  When done with a TLV chain, aim_tlvlist_free() should
 * be called to free the dynamic substructures.
 *
 * TODO: There should be a flag setable here to have the tlvlist contain
 * bstream references, so that at least the ->value portion of each
 * element doesn't need to be malloc/memcpy'd.  This could prove to be
 * just as efficient as the in-place TLV parsing used in a couple places
 * in libfaim.
 *
 * @param bs Input bstream
 * @param len The max length in bytes that will be read.
 *        There are a number of places where you want to read in a tlvchain,
 *        but the chain is not at the end of the SNAC, and the chain is
 *        preceded by the length of the TLVs.  So you can limit that with this.
 * @return Return the TLV chain read
 */
GSList *aim_tlvlist_readlen(ByteStream *bs, guint16 len)
{
	GSList *list = NULL;

	while ((byte_stream_bytes_left(bs) > 0) && (len > 0)) {
		list = aim_tlv_read(list, bs);
		if (list == NULL)
			return NULL;

		len -= 2 + 2 + ((aim_tlv_t *)list->data)->length;
	}

	return g_slist_reverse(list);
}

/**
 * Duplicate a TLV chain.
 * This is pretty self explanatory.
 *
 * @param orig The TLV chain you want to make a copy of.
 * @return A newly allocated TLV chain.
 */
GSList *aim_tlvlist_copy(GSList *orig)
{
	GSList *new = NULL;
	aim_tlv_t *tlv;

	while (orig != NULL) {
		tlv = orig->data;
		aim_tlvlist_add_raw(&new, tlv->type, tlv->length, tlv->value);
		orig = orig->next;
	}

	return new;
}

/*
 * Compare two TLV lists for equality.  This probably is not the most
 * efficient way to do this.
 *
 * @param one One of the TLV chains to compare.
 * @param two The other TLV chain to compare.
 * @return Return 0 if the lists are the same, return 1 if they are different.
 */
int aim_tlvlist_cmp(GSList *one, GSList *two)
{
	ByteStream bs1, bs2;

	if (aim_tlvlist_size(one) != aim_tlvlist_size(two))
		return 1;

	byte_stream_new(&bs1, aim_tlvlist_size(one));
	byte_stream_new(&bs2, aim_tlvlist_size(two));

	aim_tlvlist_write(&bs1, &one);
	aim_tlvlist_write(&bs2, &two);

	if (memcmp(bs1.data, bs2.data, bs1.len)) {
		byte_stream_destroy(&bs1);
		byte_stream_destroy(&bs2);
		return 1;
	}

	byte_stream_destroy(&bs1);
	byte_stream_destroy(&bs2);

	return 0;
}

/**
 * Free a TLV chain structure
 *
 * Walks the list of TLVs in the passed TLV chain and
 * frees each one. Note that any references to this data
 * should be removed before calling this.
 *
 * @param list Chain to be freed
 */
void aim_tlvlist_free(GSList *list)
{
	while (list != NULL)
	{
		freetlv(list->data);
		list = g_slist_delete_link(list, list);
	}
}

/**
 * Count the number of TLVs in a chain.
 *
 * @param list Chain to be counted.
 * @return The number of TLVs stored in the passed chain.
 */
int aim_tlvlist_count(GSList *list)
{
	GSList *cur;
	int count;

	if (list == NULL)
		return 0;

	for (cur = list, count = 0; cur; cur = cur->next)
		count++;

	return count;
}

/**
 * Count the number of bytes in a TLV chain.
 *
 * @param list Chain to be sized
 * @return The number of bytes that would be needed to
 *         write the passed TLV chain to a data buffer.
 */
int aim_tlvlist_size(GSList *list)
{
	GSList *cur;
	int size;

	if (list == NULL)
		return 0;

	for (cur = list, size = 0; cur; cur = cur->next)
		size += (4 + ((aim_tlv_t *)cur->data)->length);

	return size;
}

/**
 * Adds the passed string as a TLV element of the passed type
 * to the TLV chain.
 *
 * @param list Desination chain (%NULL pointer if empty).
 * @param type TLV type.
 * @param length Length of string to add (not including %NULL).
 * @param value String to add.
 * @return The size of the value added.
 */
int aim_tlvlist_add_raw(GSList **list, const guint16 type, const guint16 length, const guint8 *value)
{
	aim_tlv_t *tlv;

	if (list == NULL)
		return 0;

	tlv = createtlv(type, length, NULL);
	if (tlv->length > 0)
		tlv->value = g_memdup(value, length);

	*list = g_slist_append(*list, tlv);

	return tlv->length;
}

/**
 * Add a one byte integer to a TLV chain.
 *
 * @param list Destination chain.
 * @param type TLV type to add.
 * @param value Value to add.
 * @return The size of the value added.
 */
int aim_tlvlist_add_8(GSList **list, const guint16 type, const guint8 value)
{
	guint8 v8[1];

	aimutil_put8(v8, value);

	return aim_tlvlist_add_raw(list, type, 1, v8);
}

/**
 * Add a two byte integer to a TLV chain.
 *
 * @param list Destination chain.
 * @param type TLV type to add.
 * @param value Value to add.
 * @return The size of the value added.
 */
int aim_tlvlist_add_16(GSList **list, const guint16 type, const guint16 value)
{
	guint8 v16[2];

	aimutil_put16(v16, value);

	return aim_tlvlist_add_raw(list, type, 2, v16);
}

/**
 * Add a four byte integer to a TLV chain.
 *
 * @param list Destination chain.
 * @param type TLV type to add.
 * @param value Value to add.
 * @return The size of the value added.
 */
int aim_tlvlist_add_32(GSList **list, const guint16 type, const guint32 value)
{
	guint8 v32[4];

	aimutil_put32(v32, value);

	return aim_tlvlist_add_raw(list, type, 4, v32);
}

/**
 * Add a string to a TLV chain.
 *
 * @param list Destination chain.
 * @param type TLV type to add.
 * @param value Value to add.
 * @return The size of the value added.
 */
int aim_tlvlist_add_str(GSList **list, const guint16 type, const char *value)
{
	return aim_tlvlist_add_raw(list, type, strlen(value), (guint8 *)value);
}

static int
count_caps(guint64 caps)
{
	int set_bits = 0;
	while (caps) {
		set_bits += caps & 1;
		caps >>= 1;
	}
	return set_bits;
}

/**
 * Adds a block of capability blocks to a TLV chain. The bitfield
 * passed in should be a bitwise %OR of any of the %AIM_CAPS constants:
 *
 *     %OSCAR_CAPABILITY_BUDDYICON   Supports Buddy Icons
 *     %OSCAR_CAPABILITY_TALK        Supports Voice Chat
 *     %OSCAR_CAPABILITY_IMIMAGE     Supports DirectIM/IMImage
 *     %OSCAR_CAPABILITY_CHAT        Supports Chat
 *     %OSCAR_CAPABILITY_GETFILE     Supports Get File functions
 *     %OSCAR_CAPABILITY_SENDFILE    Supports Send File functions
 *
 * @param list Destination chain
 * @param type TLV type to add
 * @param caps Bitfield of capability flags to send
 * @return The size of the value added.
 */
int aim_tlvlist_add_caps(GSList **list, const guint16 type, const guint64 caps, const char *mood)
{
	int len;
	ByteStream bs;
	guint32 bs_size;
	guint8 *data;

	if (caps == 0)
		return 0; /* nothing there anyway */

	data = icq_get_custom_icon_data(mood);
	bs_size = 16*(count_caps(caps) + (data != NULL ? 1 : 0));

	byte_stream_new(&bs, bs_size);
	byte_stream_putcaps(&bs, caps);

	/* adding of custom icon GUID */
	if (data != NULL)
		byte_stream_putraw(&bs, data, 16);

	len = aim_tlvlist_add_raw(list, type, byte_stream_curpos(&bs), bs.data);

	byte_stream_destroy(&bs);

	return len;
}

/**
 * Adds the given chatroom info to a TLV chain.
 *
 * @param list Destination chain.
 * @param type TLV type to add.
 * @param roomname The name of the chat.
 * @param instance The instance.
 * @return The size of the value added.
 */
int aim_tlvlist_add_chatroom(GSList **list, guint16 type, guint16 exchange, const char *roomname, guint16 instance)
{
	int len;
	ByteStream bs;

	byte_stream_new(&bs, 2 + 1 + strlen(roomname) + 2);

	byte_stream_put16(&bs, exchange);
	byte_stream_put8(&bs, strlen(roomname));
	byte_stream_putstr(&bs, roomname);
	byte_stream_put16(&bs, instance);

	len = aim_tlvlist_add_raw(list, type, byte_stream_curpos(&bs), bs.data);

	byte_stream_destroy(&bs);

	return len;
}

/**
 * Adds a TLV with a zero length to a TLV chain.
 *
 * @param list Destination chain.
 * @param type TLV type to add.
 * @return The size of the value added.
 */
int aim_tlvlist_add_noval(GSList **list, const guint16 type)
{
	return aim_tlvlist_add_raw(list, type, 0, NULL);
}

/*
 * Note that the inner TLV chain will not be modifiable as a tlvchain once
 * it is written using this.  Or rather, it can be, but updates won't be
 * made to this.
 *
 * TODO: Should probably support sublists for real.
 *
 * This is so neat.
 *
 * @param list Destination chain.
 * @param type TLV type to add.
 * @param t1 The TLV chain you want to write.
 * @return The number of bytes written to the destination TLV chain.
 *         0 is returned if there was an error or if the destination
 *         TLV chain has length 0.
 */
int aim_tlvlist_add_frozentlvlist(GSList **list, guint16 type, GSList **tlvlist)
{
	int buflen;
	ByteStream bs;

	buflen = aim_tlvlist_size(*tlvlist);

	if (buflen <= 0)
		return 0;

	byte_stream_new(&bs, buflen);

	aim_tlvlist_write(&bs, tlvlist);

	aim_tlvlist_add_raw(list, type, byte_stream_curpos(&bs), bs.data);

	byte_stream_destroy(&bs);

	return buflen;
}

/**
 * Substitute a TLV of a given type with a new TLV of the same type.  If
 * you attempt to replace a TLV that does not exist, this function will
 * just add a new TLV as if you called aim_tlvlist_add_raw().
 *
 * @param list Desination chain (%NULL pointer if empty).
 * @param type TLV type.
 * @param length Length of string to add (not including %NULL).
 * @param value String to add.
 * @return The length of the TLV.
 */
int aim_tlvlist_replace_raw(GSList **list, const guint16 type, const guint16 length, const guint8 *value)
{
	GSList *cur;
	aim_tlv_t *tlv;

	if (list == NULL)
		return 0;

	for (cur = *list; cur != NULL; cur = cur->next)
	{
		tlv = cur->data;
		if (tlv->type == type)
			break;
	}

	if (cur == NULL)
		/* TLV does not exist, so add a new one */
		return aim_tlvlist_add_raw(list, type, length, value);

	g_free(tlv->value);
	tlv->length = length;
	if (tlv->length > 0) {
		tlv->value = g_memdup(value, length);
	} else
		tlv->value = NULL;

	return tlv->length;
}

/**
 * Substitute a TLV of a given type with a new TLV of the same type.  If
 * you attempt to replace a TLV that does not exist, this function will
 * just add a new TLV as if you called aim_tlvlist_add_str().
 *
 * @param list Desination chain (%NULL pointer if empty).
 * @param type TLV type.
 * @param str String to add.
 * @return The length of the TLV.
 */
int aim_tlvlist_replace_str(GSList **list, const guint16 type, const char *str)
{
	return aim_tlvlist_replace_raw(list, type, strlen(str), (const guchar *)str);
}

/**
 * Substitute a TLV of a given type with a new TLV of the same type.  If
 * you attempt to replace a TLV that does not exist, this function will
 * just add a new TLV as if you called aim_tlvlist_add_raw().
 *
 * @param list Desination chain (%NULL pointer if empty).
 * @param type TLV type.
 * @return The length of the TLV.
 */
int aim_tlvlist_replace_noval(GSList **list, const guint16 type)
{
	return aim_tlvlist_replace_raw(list, type, 0, NULL);
}

/**
 * Substitute a TLV of a given type with a new TLV of the same type.  If
 * you attempt to replace a TLV that does not exist, this function will
 * just add a new TLV as if you called aim_tlvlist_add_raw().
 *
 * @param list Desination chain (%NULL pointer if empty).
 * @param type TLV type.
 * @param value 8 bit value to add.
 * @return The length of the TLV.
 */
int aim_tlvlist_replace_8(GSList **list, const guint16 type, const guint8 value)
{
	guint8 v8[1];

	aimutil_put8(v8, value);

	return aim_tlvlist_replace_raw(list, type, 1, v8);
}

/**
 * Substitute a TLV of a given type with a new TLV of the same type.  If
 * you attempt to replace a TLV that does not exist, this function will
 * just add a new TLV as if you called aim_tlvlist_add_raw().
 *
 * @param list Desination chain (%NULL pointer if empty).
 * @param type TLV type.
 * @param value 32 bit value to add.
 * @return The length of the TLV.
 */
int aim_tlvlist_replace_32(GSList **list, const guint16 type, const guint32 value)
{
	guint8 v32[4];

	aimutil_put32(v32, value);

	return aim_tlvlist_replace_raw(list, type, 4, v32);
}

/**
 * Remove all TLVs of a given type.  If you attempt to remove a TLV
 * that does not exist, nothing happens.
 *
 * @param list Desination chain (%NULL pointer if empty).
 * @param type TLV type.
 */
void aim_tlvlist_remove(GSList **list, const guint16 type)
{
	GSList *cur, *next;
	aim_tlv_t *tlv;

	if (list == NULL || *list == NULL)
		return;

	cur = *list;
	while (cur != NULL)
	{
		tlv = cur->data;
		next = cur->next;

		if (tlv->type == type)
		{
			/* Delete this TLV */
			*list = g_slist_delete_link(*list, cur);
			g_free(tlv->value);
			g_free(tlv);
		}

		cur = next;
	}
}

/**
 * Write a TLV chain into a data buffer.
 *
 * Copies a TLV chain into a raw data buffer, writing only the number
 * of bytes specified. This operation does not free the chain;
 * aim_tlvlist_free() must still be called to free up the memory used
 * by the chain structures.
 *
 * TODO: Clean this up, make better use of bstreams
 *
 * @param bs Input bstream
 * @param list Source TLV chain
 * @return Return 0 if the destination bstream is too small.
 */
int aim_tlvlist_write(ByteStream *bs, GSList **list)
{
	int goodbuflen;
	GSList *cur;
	aim_tlv_t *tlv;

	/* do an initial run to test total length */
	goodbuflen = aim_tlvlist_size(*list);

	if (goodbuflen > byte_stream_bytes_left(bs))
		return 0; /* not enough buffer */

	/* do the real write-out */
	for (cur = *list; cur; cur = cur->next) {
		tlv = cur->data;
		byte_stream_put16(bs, tlv->type);
		byte_stream_put16(bs, tlv->length);
		if (tlv->length > 0)
			byte_stream_putraw(bs, tlv->value, tlv->length);
	}

	return 1; /* TODO: This is a nonsensical return */
}


/**
 * Grab the Nth TLV of type type in the TLV list list.
 *
 * Returns a pointer to an aim_tlv_t of the specified type;
 * %NULL on error.  The @nth parameter is specified starting at %1.
 * In most cases, there will be no more than one TLV of any type
 * in a chain.
 *
 * @param list Source chain.
 * @param type Requested TLV type.
 * @param nth Index of TLV of type to get.
 * @return The TLV you were looking for, or NULL if one could not be found.
 */
aim_tlv_t *aim_tlv_gettlv(GSList *list, const guint16 type, const int nth)
{
	GSList *cur;
	aim_tlv_t *tlv;
	int i;

	for (cur = list, i = 0; cur != NULL; cur = cur->next) {
		tlv = cur->data;
		if (tlv->type == type)
			i++;
		if (i >= nth)
			return tlv;
	}

	return NULL;
}

/**
 * Get the length of the data of the nth TLV in the given TLV chain.
 *
 * @param list Source chain.
 * @param type Requested TLV type.
 * @param nth Index of TLV of type to get.
 * @return The length of the data in this TLV, or -1 if the TLV could not be
 *         found.  Unless -1 is returned, this value will be 2 bytes.
 */
int aim_tlv_getlength(GSList *list, const guint16 type, const int nth)
{
	aim_tlv_t *tlv;

	tlv = aim_tlv_gettlv(list, type, nth);
	if (tlv == NULL)
		return -1;

	return tlv->length;
}

char *
aim_tlv_getvalue_as_string(aim_tlv_t *tlv)
{
	char *ret;

	ret = g_malloc(tlv->length + 1);
	memcpy(ret, tlv->value, tlv->length);
	ret[tlv->length] = '\0';

	return ret;
}

/**
 * Retrieve the data from the nth TLV in the given TLV chain as a string.
 *
 * @param list Source TLV chain.
 * @param type TLV type to search for.
 * @param nth Index of TLV to return.
 * @return The value of the TLV you were looking for, or NULL if one could
 *         not be found.  This is a dynamic buffer and must be freed by the
 *         caller.
 */
char *aim_tlv_getstr(GSList *list, const guint16 type, const int nth)
{
	aim_tlv_t *tlv;

	tlv = aim_tlv_gettlv(list, type, nth);
	if (tlv == NULL)
		return NULL;

	return aim_tlv_getvalue_as_string(tlv);
}

/**
 * Retrieve the data from the nth TLV in the given TLV chain as an 8bit
 * integer.
 *
 * @param list Source TLV chain.
 * @param type TLV type to search for.
 * @param nth Index of TLV to return.
 * @return The value the TLV you were looking for, or 0 if one could
 *         not be found.
 */
guint8 aim_tlv_get8(GSList *list, const guint16 type, const int nth)
{
	aim_tlv_t *tlv;

	tlv = aim_tlv_gettlv(list, type, nth);
	if (tlv == NULL)
		return 0; /* erm */

	return aimutil_get8(tlv->value);
}

/**
 * Retrieve the data from the nth TLV in the given TLV chain as a 16bit
 * integer.
 *
 * @param list Source TLV chain.
 * @param type TLV type to search for.
 * @param nth Index of TLV to return.
 * @return The value the TLV you were looking for, or 0 if one could
 *         not be found.
 */
guint16 aim_tlv_get16(GSList *list, const guint16 type, const int nth)
{
	aim_tlv_t *tlv;

	tlv = aim_tlv_gettlv(list, type, nth);
	if (tlv == NULL)
		return 0; /* erm */

	return aimutil_get16(tlv->value);
}

/**
 * Retrieve the data from the nth TLV in the given TLV chain as a 32bit
 * integer.
 *
 * @param list Source TLV chain.
 * @param type TLV type to search for.
 * @param nth Index of TLV to return.
 * @return The value the TLV you were looking for, or 0 if one could
 *         not be found.
 */
guint32 aim_tlv_get32(GSList *list, const guint16 type, const int nth)
{
	aim_tlv_t *tlv;

	tlv = aim_tlv_gettlv(list, type, nth);
	if (tlv == NULL)
		return 0; /* erm */

	return aimutil_get32(tlv->value);
}
