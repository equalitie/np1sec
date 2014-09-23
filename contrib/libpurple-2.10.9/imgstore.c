/**
 * @file imgstore.c IM Image Store API
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
 *
*/

#include "internal.h"

#include "dbus-maybe.h"
#include "debug.h"
#include "imgstore.h"
#include "util.h"

static GHashTable *imgstore;
static unsigned int nextid = 0;

/*
 * NOTE: purple_imgstore_add() creates these without zeroing the memory, so
 * NOTE: make sure to update that function when adding members.
 */
struct _PurpleStoredImage
{
	int id;
	guint8 refcount;
	size_t size;     /**< The image data's size. */
	char *filename;  /**< The filename (for the UI) */
	gpointer data;   /**< The image data. */
};

PurpleStoredImage *
purple_imgstore_add(gpointer data, size_t size, const char *filename)
{
	PurpleStoredImage *img;

	g_return_val_if_fail(data != NULL, NULL);
	g_return_val_if_fail(size > 0, NULL);

	img = g_new(PurpleStoredImage, 1);
	PURPLE_DBUS_REGISTER_POINTER(img, PurpleStoredImage);
	img->data = data;
	img->size = size;
	img->filename = g_strdup(filename);
	img->refcount = 1;
	img->id = 0;

	return img;
}

PurpleStoredImage *
purple_imgstore_new_from_file(const char *path)
{
	gchar *data = NULL;
	size_t len;
	GError *err = NULL;

	g_return_val_if_fail(path != NULL && *path != '\0', NULL);

	if (!g_file_get_contents(path, &data, &len, &err)) {
		purple_debug_error("imgstore", "Error reading %s: %s\n",
				path, err->message);
		g_error_free(err);
		return NULL;
	}
	return purple_imgstore_add(data, len, path);
}

int
purple_imgstore_add_with_id(gpointer data, size_t size, const char *filename)
{
	PurpleStoredImage *img = purple_imgstore_add(data, size, filename);
	if (!img) {
		return 0;
	}

	/*
	 * Use the next unused id number.  We do it in a loop on the
	 * off chance that nextid wraps back around to 0 and the hash
	 * table still contains entries from the first time around.
	 */
	do {
		img->id = ++nextid;
	} while (img->id == 0 || g_hash_table_lookup(imgstore, &(img->id)) != NULL);

	g_hash_table_insert(imgstore, &(img->id), img);

	return img->id;
}

PurpleStoredImage *purple_imgstore_find_by_id(int id)
{
	PurpleStoredImage *img = g_hash_table_lookup(imgstore, &id);

	if (img != NULL)
		purple_debug_misc("imgstore", "retrieved image id %d\n", img->id);

	return img;
}

gconstpointer purple_imgstore_get_data(PurpleStoredImage *img)
{
	g_return_val_if_fail(img != NULL, NULL);

	return img->data;
}

size_t purple_imgstore_get_size(PurpleStoredImage *img)
{
	g_return_val_if_fail(img != NULL, 0);

	return img->size;
}

const char *purple_imgstore_get_filename(const PurpleStoredImage *img)
{
	g_return_val_if_fail(img != NULL, NULL);

	return img->filename;
}

const char *purple_imgstore_get_extension(PurpleStoredImage *img)
{
	g_return_val_if_fail(img != NULL, NULL);

	return purple_util_get_image_extension(img->data, img->size);
}

void purple_imgstore_ref_by_id(int id)
{
	PurpleStoredImage *img = purple_imgstore_find_by_id(id);

	g_return_if_fail(img != NULL);

	purple_imgstore_ref(img);
}

void purple_imgstore_unref_by_id(int id)
{
	PurpleStoredImage *img = purple_imgstore_find_by_id(id);

	g_return_if_fail(img != NULL);

	purple_imgstore_unref(img);
}

PurpleStoredImage *
purple_imgstore_ref(PurpleStoredImage *img)
{
	g_return_val_if_fail(img != NULL, NULL);

	img->refcount++;

	return img;
}

PurpleStoredImage *
purple_imgstore_unref(PurpleStoredImage *img)
{
	if (img == NULL)
		return NULL;

	g_return_val_if_fail(img->refcount > 0, NULL);

	img->refcount--;

	if (img->refcount == 0)
	{
		purple_signal_emit(purple_imgstore_get_handle(),
		                   "image-deleting", img);
		if (img->id)
			g_hash_table_remove(imgstore, &img->id);

		g_free(img->data);
		g_free(img->filename);
		PURPLE_DBUS_UNREGISTER_POINTER(img);
		g_free(img);
		img = NULL;
	}

	return img;
}

void *
purple_imgstore_get_handle()
{
	static int handle;

	return &handle;
}

void
purple_imgstore_init()
{
	void *handle = purple_imgstore_get_handle();

	purple_signal_register(handle, "image-deleting",
	                       purple_marshal_VOID__POINTER, NULL,
	                       1,
	                       purple_value_new(PURPLE_TYPE_SUBTYPE,
	                                        PURPLE_SUBTYPE_STORED_IMAGE));

	imgstore = g_hash_table_new(g_int_hash, g_int_equal);
}

void
purple_imgstore_uninit()
{
	g_hash_table_destroy(imgstore);

	purple_signals_unregister_by_instance(purple_imgstore_get_handle());
}
