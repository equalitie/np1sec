#include "module.h"

MODULE = Purple::ImgStore  PACKAGE = Purple::ImgStore  PREFIX = purple_imgstore_
PROTOTYPES: ENABLE

Purple::StoredImage
purple_imgstore_add(data, size, filename)
	void *data
	size_t size
	const char *filename

int
purple_imgstore_add_with_id(data, size, filename)
	void *data
	size_t size
	const char *filename

Purple::StoredImage
purple_imgstore_find_by_id(id)
	int id

gconstpointer 
purple_imgstore_get_data(i)
	Purple::StoredImage i

const char *
purple_imgstore_get_filename(i)
	Purple::StoredImage i

size_t 
purple_imgstore_get_size(i)
	Purple::StoredImage i

const char *
purple_imgstore_get_extension(i)
	Purple::StoredImage i

Purple::StoredImage
purple_imgstore_ref(id)
	Purple::StoredImage id

Purple::StoredImage
purple_imgstore_unref(id)
	Purple::StoredImage id

void
purple_imgstore_ref_by_id(id)
	int id

void
purple_imgstore_unref_by_id(id)
	int id

