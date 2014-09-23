/**
 * @file tlv.c MSN TLV functions
 *
 * purple
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

#include "tlv.h"
#include "msnutils.h"

static msn_tlv_t *
createtlv(guint8 type, guint8 length, guint8 *value)
{
	msn_tlv_t *ret;

	ret = g_new(msn_tlv_t, 1);
	ret->type = type;
	ret->length = length;
	ret->value = value;

	return ret;
}

static void
freetlv(msn_tlv_t *oldtlv)
{
	g_free(oldtlv->value);
	g_free(oldtlv);
}

GSList *
msn_tlvlist_read(const char *bs, size_t bs_len)
{
	GSList *list = NULL;

	while (bs_len > 0) {
		guint8 type, length;
		msn_tlv_t *tlv;

		if (bs_len == 3 && *bs == 0) {
			/* Padding to multiple of 4 */
			break;
		} else if (bs_len == 2 && *bs == 0) {
			/* Padding to multiple of 4 */
			break;
		} else if (bs_len == 1) {
			if (*bs == 0) {
				/* Padding to multiple of 4 */
				break;
			} else {
				/* TLV is not small enough to fit here */
				msn_tlvlist_free(list);
				return NULL;
			}
		}

		type = msn_pop8(bs);
		length = msn_pop8(bs);
		bs_len -= 2;

		if (length > bs_len) {
			msn_tlvlist_free(list);
			return NULL;
		}

		tlv = createtlv(type, length, NULL);
		if (length > 0) {
			tlv->value = g_memdup(bs, length);
			if (!tlv->value) {
				freetlv(tlv);
				msn_tlvlist_free(list);
				return NULL;
			}
		}

		bs_len -= length;
		bs += length;

		list = g_slist_prepend(list, tlv);
	}

	return g_slist_reverse(list);
}

GSList *
msn_tlvlist_copy(GSList *orig)
{
	GSList *new = NULL;
	msn_tlv_t *tlv;

	while (orig != NULL) {
		tlv = orig->data;
		msn_tlvlist_add_raw(&new, tlv->type, tlv->length, (const char *)tlv->value);
		orig = orig->next;
	}

	return new;
}

gboolean
msn_tlvlist_equal(GSList *one, GSList *two)
{
	while (one && two) {
		msn_tlv_t *a = one->data;
		msn_tlv_t *b = two->data;

		if (a->type != b->type)
			return FALSE;
		else if (a->length != b->length)
			return FALSE;
		else if (!a->value && b->value)
			return FALSE;
		else if (a->value && !b->value)
			return FALSE;
		else if (a->value && b->value && memcmp(a->value, b->value, a->length) != 0)
			return FALSE;

		one = one->next;
		two = two->next;
	}

	return one == two;
}

void
msn_tlvlist_free(GSList *list)
{
	while (list != NULL) {
		freetlv(list->data);
		list = g_slist_delete_link(list, list);
	}
}

int
msn_tlvlist_count(GSList *list)
{
	return g_slist_length(list);
}

size_t
msn_tlvlist_size(GSList *list)
{
	int size;

	if (list == NULL)
		return 0;

	for (size = 0; list; list = list->next)
		size += (2 + ((msn_tlv_t *)list->data)->length);

	return size;
}

int
msn_tlvlist_add_raw(GSList **list, const guint8 type, const guint8 length, const char *value)
{
	msn_tlv_t *tlv;

	if (list == NULL)
		return 0;

	tlv = createtlv(type, length, NULL);
	if (length > 0)
		tlv->value = g_memdup(value, length);

	*list = g_slist_append(*list, tlv);

	return tlv->length;
}

int
msn_tlvlist_add_8(GSList **list, const guint8 type, const guint8 value)
{
	char v8[1];

	msn_write8(v8, value);

	return msn_tlvlist_add_raw(list, type, 1, v8);
}

int
msn_tlvlist_add_16(GSList **list, const guint8 type, const guint16 value)
{
	char v16[2];

	msn_write16be(v16, value);

	return msn_tlvlist_add_raw(list, type, 2, v16);
}

int
msn_tlvlist_add_32(GSList **list, const guint8 type, const guint32 value)
{
	char v32[4];

	msn_write32be(v32, value);

	return msn_tlvlist_add_raw(list, type, 4, v32);
}

int
msn_tlvlist_add_str(GSList **list, const guint8 type, const char *value)
{
	return msn_tlvlist_add_raw(list, type, strlen(value), value);
}

int
msn_tlvlist_add_empty(GSList **list, const guint8 type)
{
	return msn_tlvlist_add_raw(list, type, 0, NULL);
}

int
msn_tlvlist_add_tlv(GSList **list, const msn_tlv_t *tlv)
{
	return msn_tlvlist_add_raw(list, tlv->type, tlv->length, (const char *)tlv->value);
}

int
msn_tlvlist_replace_raw(GSList **list, const guint8 type, const guint8 length, const char *value)
{
	GSList *cur;
	msn_tlv_t *tlv;

	if (list == NULL)
		return 0;

	for (cur = *list; cur != NULL; cur = cur->next) {
		tlv = cur->data;
		if (tlv->type == type)
			break;
	}

	if (cur == NULL)
		/* TLV does not exist, so add a new one */
		return msn_tlvlist_add_raw(list, type, length, value);

	g_free(tlv->value);
	tlv->length = length;
	if (length > 0) {
		tlv->value = g_memdup(value, length);
	} else
		tlv->value = NULL;

	return length;
}

int
msn_tlvlist_replace_str(GSList **list, const guint8 type, const char *str)
{
	return msn_tlvlist_replace_raw(list, type, strlen(str), str);
}

int
msn_tlvlist_replace_empty(GSList **list, const guint8 type)
{
	return msn_tlvlist_replace_raw(list, type, 0, NULL);
}

int
msn_tlvlist_replace_8(GSList **list, const guint8 type, const guint8 value)
{
	char v8[1];

	msn_write8(v8, value);

	return msn_tlvlist_replace_raw(list, type, 1, v8);
}

int
msn_tlvlist_replace_32(GSList **list, const guint8 type, const guint32 value)
{
	char v32[4];

	msn_write32be(v32, value);

	return msn_tlvlist_replace_raw(list, type, 4, v32);
}

int
msn_tlvlist_replace_tlv(GSList **list, const msn_tlv_t *tlv)
{
	return msn_tlvlist_replace_raw(list, tlv->type, tlv->length, (const char *)tlv->value);
}

void
msn_tlvlist_remove(GSList **list, const guint8 type)
{
	GSList *cur, *next;
	msn_tlv_t *tlv;

	if (list == NULL || *list == NULL)
		return;

	cur = *list;
	while (cur != NULL) {
		tlv = cur->data;
		next = cur->next;

		if (tlv->type == type) {
			/* Delete this TLV */
			*list = g_slist_delete_link(*list, cur);
			g_free(tlv->value);
			g_free(tlv);
		}

		cur = next;
	}
}

char *
msn_tlvlist_write(GSList *list, size_t *out_len)
{
	char *buf;
	char *tmp;
	size_t bytes_left;
	size_t total_len;

	tmp = buf = g_malloc(256);
	bytes_left = total_len = 256;

	for (; list; list = g_slist_next(list)) {
		msn_tlv_t *tlv = (msn_tlv_t *)list->data;

		if (G_UNLIKELY(tlv->length + 2 > bytes_left)) {
			buf = g_realloc(buf, total_len + 256);
			bytes_left += 256;
			total_len += 256;
			tmp = buf + (total_len - bytes_left);
		}

		msn_push8(tmp, tlv->type);
		msn_push8(tmp, tlv->length);
		memcpy(tmp, tlv->value, tlv->length);
		tmp += tlv->length;

		bytes_left -= (tlv->length + 2);
	}

	/* Align length to multiple of 4 */
	total_len = total_len - bytes_left;
	bytes_left = 4 - total_len % 4;
	if (bytes_left != 4)
		memset(tmp, 0, bytes_left);
	else
		bytes_left = 0;

	*out_len = total_len + bytes_left;

	return buf;
}

msn_tlv_t *
msn_tlv_gettlv(GSList *list, const guint8 type, const int nth)
{
	msn_tlv_t *tlv;
	int i;

	for (i = 0; list != NULL; list = list->next) {
		tlv = list->data;
		if (tlv->type == type)
			i++;
		if (i >= nth)
			return tlv;
	}

	return NULL;
}

int
msn_tlv_getlength(GSList *list, const guint8 type, const int nth)
{
	msn_tlv_t *tlv;

	tlv = msn_tlv_gettlv(list, type, nth);
	if (tlv == NULL)
		return -1;

	return tlv->length;
}

char *
msn_tlv_getvalue_as_string(msn_tlv_t *tlv)
{
	char *ret;

	ret = g_malloc(tlv->length + 1);
	memcpy(ret, tlv->value, tlv->length);
	ret[tlv->length] = '\0';

	return ret;
}

char *
msn_tlv_getstr(GSList *list, const guint8 type, const int nth)
{
	msn_tlv_t *tlv;

	tlv = msn_tlv_gettlv(list, type, nth);
	if (tlv == NULL)
		return NULL;

	return msn_tlv_getvalue_as_string(tlv);
}

guint8
msn_tlv_get8(GSList *list, const guint8 type, const int nth)
{
	msn_tlv_t *tlv;

	tlv = msn_tlv_gettlv(list, type, nth);
	if (tlv == NULL)
		return 0; /* erm */

	return msn_read8((const char *)tlv->value);
}

guint16
msn_tlv_get16(GSList *list, const guint8 type, const int nth)
{
	msn_tlv_t *tlv;

	tlv = msn_tlv_gettlv(list, type, nth);
	if (tlv == NULL)
		return 0; /* erm */

	return msn_read16be((const char *)tlv->value);
}

guint32
msn_tlv_get32(GSList *list, const guint8 type, const int nth)
{
	msn_tlv_t *tlv;

	tlv = msn_tlv_gettlv(list, type, nth);
	if (tlv == NULL)
		return 0; /* erm */

	return msn_read32be((const char *)tlv->value);
}

