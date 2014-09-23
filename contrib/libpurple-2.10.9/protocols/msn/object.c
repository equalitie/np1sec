/**
 * @file object.c MSNObject API
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

#include "msn.h"
#include "object.h"
#include "debug.h"
/* Sha1 stuff */
#include "cipher.h"
/* Base64 stuff */
#include "util.h"

#define GET_STRING_TAG(field, id) \
	if ((tag = strstr(str, id "=\"")) != NULL) \
	{ \
		tag += strlen(id "=\""); \
		c = strchr(tag, '"'); \
		if (c != NULL) \
		{ \
			if (obj->field != NULL) \
				g_free(obj->field); \
			obj->field = g_strndup(tag, c - tag); \
		} \
	}

#define GET_INT_TAG(field, id) \
	if ((tag = strstr(str, id "=\"")) != NULL) \
	{ \
		char buf[16]; \
		size_t offset; \
		tag += strlen(id "=\""); \
		c = strchr(tag, '"'); \
		if (c != NULL) \
		{ \
			memset(buf, 0, sizeof(buf)); \
			offset = c - tag; \
			if (offset >= sizeof(buf)) \
				offset = sizeof(buf) - 1; \
			strncpy(buf, tag, offset); \
			obj->field = atoi(buf); \
		} \
	}

static GList *local_objs;

MsnObject *
msn_object_new(void)
{
	MsnObject *obj;

	obj = g_new0(MsnObject, 1);

	msn_object_set_type(obj, MSN_OBJECT_UNKNOWN);
	msn_object_set_friendly(obj, "AAA=");

	return obj;
}

MsnObject *
msn_object_new_from_string(const char *str)
{
	MsnObject *obj;
	char *tag, *c;

	g_return_val_if_fail(str != NULL, NULL);

	if (strncmp(str, "<msnobj ", 8))
		return NULL;

	obj = msn_object_new();

	GET_STRING_TAG(creator,  "Creator");
	GET_INT_TAG(size,        "Size");
	GET_INT_TAG(type,        "Type");
	GET_STRING_TAG(location, "Location");
	GET_STRING_TAG(friendly, "Friendly");
	GET_STRING_TAG(sha1d,    "SHA1D");
	GET_STRING_TAG(sha1c,    "SHA1C");
	GET_STRING_TAG(url,      "Url");
	GET_STRING_TAG(url1,     "Url1");

	/* If we are missing any of the required elements then discard the object */
	if (obj->creator == NULL || obj->size == 0 || obj->type == 0
	 || obj->sha1d == NULL) {
		purple_debug_error("msn", "Discarding invalid msnobj: '%s'\n", str);
		msn_object_destroy(obj);
		return NULL;
	}

	if (obj->location == NULL || obj->friendly == NULL) {
		/* Location/friendly are required for non-buddyicon objects */
		if (obj->type != MSN_OBJECT_USERTILE) {
			purple_debug_error("msn", "Discarding invalid msnobj: '%s'\n", str);
			msn_object_destroy(obj);
			return NULL;
		/* Buddy icon object can contain Url/Url1 instead */
		} else if (obj->url == NULL || obj->url1 == NULL) {
			purple_debug_error("msn", "Discarding invalid msnobj: '%s'\n", str);
			msn_object_destroy(obj);
			return NULL;
		}
	}

	return obj;
}

MsnObject*
msn_object_new_from_image(PurpleStoredImage *img, const char *location,
		const char *creator, MsnObjectType type)
{
	MsnObject *msnobj;

	PurpleCipherContext *ctx;
	char *buf;
	gconstpointer data;
	size_t size;
	char *base64;
	unsigned char digest[20];

	msnobj = NULL;

	if (img == NULL)
		return msnobj;

	size = purple_imgstore_get_size(img);
	data = purple_imgstore_get_data(img);

	/* New object */
	msnobj = msn_object_new();
	msn_object_set_local(msnobj);
	msn_object_set_type(msnobj, type);
	msn_object_set_location(msnobj, location);
	msn_object_set_creator(msnobj, creator);

	msn_object_set_image(msnobj, img);

	/* Compute the SHA1D field. */
	memset(digest, 0, sizeof(digest));

	ctx = purple_cipher_context_new_by_name("sha1", NULL);
	purple_cipher_context_append(ctx, data, size);
	purple_cipher_context_digest(ctx, sizeof(digest), digest, NULL);

	base64 = purple_base64_encode(digest, sizeof(digest));
	msn_object_set_sha1d(msnobj, base64);
	g_free(base64);

	msn_object_set_size(msnobj, size);

	/* Compute the SHA1C field. */
	buf = g_strdup_printf(
		"Creator%sSize%dType%dLocation%sFriendly%sSHA1D%s",
		msn_object_get_creator(msnobj),
		msn_object_get_size(msnobj),
		msn_object_get_type(msnobj),
		msn_object_get_location(msnobj),
		msn_object_get_friendly(msnobj),
		msn_object_get_sha1d(msnobj));

	memset(digest, 0, sizeof(digest));

	purple_cipher_context_reset(ctx, NULL);
	purple_cipher_context_append(ctx, (const guchar *)buf, strlen(buf));
	purple_cipher_context_digest(ctx, sizeof(digest), digest, NULL);
	purple_cipher_context_destroy(ctx);
	g_free(buf);

	base64 = purple_base64_encode(digest, sizeof(digest));
	msn_object_set_sha1c(msnobj, base64);
	g_free(base64);

	return msnobj;
}

void
msn_object_destroy(MsnObject *obj)
{
	g_return_if_fail(obj != NULL);

	g_free(obj->creator);
	g_free(obj->location);
	g_free(obj->friendly);
	g_free(obj->sha1d);
	g_free(obj->sha1c);
	g_free(obj->url);
	g_free(obj->url1);

	purple_imgstore_unref(obj->img);

	if (obj->local)
		local_objs = g_list_remove(local_objs, obj);

	g_free(obj);
}

char *
msn_object_to_string(const MsnObject *obj)
{
	char *str;
	const char *sha1c;

	g_return_val_if_fail(obj != NULL, NULL);

	sha1c = msn_object_get_sha1c(obj);

	str = g_strdup_printf("<msnobj Creator=\"%s\" Size=\"%d\" Type=\"%d\" "
						  "Location=\"%s\" Friendly=\"%s\" SHA1D=\"%s\""
						  "%s%s%s/>",
						  msn_object_get_creator(obj),
						  msn_object_get_size(obj),
						  msn_object_get_type(obj),
						  msn_object_get_location(obj),
						  msn_object_get_friendly(obj),
						  msn_object_get_sha1d(obj),
						  sha1c ? " SHA1C=\"" : "",
						  sha1c ? sha1c : "",
						  sha1c ? "\"" : "");

	return str;
}

void
msn_object_set_creator(MsnObject *obj, const char *creator)
{
	g_return_if_fail(obj != NULL);

	g_free(obj->creator);
	obj->creator = g_strdup(creator);
}

void
msn_object_set_size(MsnObject *obj, int size)
{
	g_return_if_fail(obj != NULL);

	obj->size = size;
}

void
msn_object_set_type(MsnObject *obj, MsnObjectType type)
{
	g_return_if_fail(obj != NULL);

	obj->type = type;
}

void
msn_object_set_location(MsnObject *obj, const char *location)
{
	g_return_if_fail(obj != NULL);

	g_free(obj->location);
	obj->location = g_strdup(location);
}

void
msn_object_set_friendly(MsnObject *obj, const char *friendly)
{
	g_return_if_fail(obj != NULL);

	g_free(obj->friendly);
	obj->friendly = g_strdup(friendly);
}

void
msn_object_set_sha1d(MsnObject *obj, const char *sha1d)
{
	g_return_if_fail(obj != NULL);

	g_free(obj->sha1d);
	obj->sha1d = g_strdup(sha1d);
}

void
msn_object_set_sha1c(MsnObject *obj, const char *sha1c)
{
	g_return_if_fail(obj != NULL);

	g_free(obj->sha1c);
	obj->sha1c = g_strdup(sha1c);
}

void
msn_object_set_url(MsnObject *obj, const char *url)
{
	g_return_if_fail(obj != NULL);

	g_free(obj->url);
	obj->url = g_strdup(url);
}

void
msn_object_set_url1(MsnObject *obj, const char *url)
{
	g_return_if_fail(obj != NULL);

	g_free(obj->url1);
	obj->url1 = g_strdup(url);
}

const char *
msn_object_get_creator(const MsnObject *obj)
{
	g_return_val_if_fail(obj != NULL, NULL);

	return obj->creator;
}

int
msn_object_get_size(const MsnObject *obj)
{
	g_return_val_if_fail(obj != NULL, 0);

	return obj->size;
}

MsnObjectType
msn_object_get_type(const MsnObject *obj)
{
	g_return_val_if_fail(obj != NULL, MSN_OBJECT_UNKNOWN);

	return obj->type;
}

const char *
msn_object_get_location(const MsnObject *obj)
{
	g_return_val_if_fail(obj != NULL, NULL);

	return obj->location;
}

const char *
msn_object_get_friendly(const MsnObject *obj)
{
	g_return_val_if_fail(obj != NULL, NULL);

	return obj->friendly;
}

const char *
msn_object_get_sha1d(const MsnObject *obj)
{
	g_return_val_if_fail(obj != NULL, NULL);

	return obj->sha1d;
}

const char *
msn_object_get_sha1c(const MsnObject *obj)
{
	g_return_val_if_fail(obj != NULL, NULL);

	return obj->sha1c;
}

const char *
msn_object_get_sha1(const MsnObject *obj)
{
	g_return_val_if_fail(obj != NULL, NULL);

	if(obj->sha1c != NULL) {
		return obj->sha1c;
	} else {
		return obj->sha1d;
	}
}

const char *
msn_object_get_url(const MsnObject *obj)
{
	g_return_val_if_fail(obj != NULL, NULL);

	return obj->url;
}

const char *
msn_object_get_url1(const MsnObject *obj)
{
	g_return_val_if_fail(obj != NULL, NULL);

	return obj->url1;
}

MsnObject *
msn_object_find_local(const char *sha1)
{
	GList *l;

	g_return_val_if_fail(sha1 != NULL, NULL);

	for (l = local_objs; l != NULL; l = l->next)
	{
		MsnObject *local_obj = l->data;

		if (!strcmp(msn_object_get_sha1(local_obj), sha1))
			return local_obj;
	}

	return NULL;

}

void
msn_object_set_local(MsnObject *obj)
{
	g_return_if_fail(obj != NULL);

	obj->local = TRUE;

	local_objs = g_list_append(local_objs, obj);
}

void
msn_object_set_image(MsnObject *obj, PurpleStoredImage *img)
{
	g_return_if_fail(obj != NULL);
	g_return_if_fail(img != NULL);

	/* obj->local = TRUE; */

	purple_imgstore_unref(obj->img);
	obj->img = purple_imgstore_ref(img);
}

PurpleStoredImage *
msn_object_get_image(const MsnObject *obj)
{
	MsnObject *local_obj;

	g_return_val_if_fail(obj != NULL, NULL);

	local_obj = msn_object_find_local(msn_object_get_sha1(obj));

	if (local_obj != NULL)
		return local_obj->img;

	return NULL;
}
