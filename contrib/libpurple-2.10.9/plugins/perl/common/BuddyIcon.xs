#include "module.h"

MODULE = Purple::Buddy::Icon PACKAGE = Purple::Buddy::Icon   PREFIX = purple_buddy_icon_
PROTOTYPES: ENABLE

Purple::Buddy::Icon
purple_buddy_icon_ref(icon)
	Purple::Buddy::Icon icon

Purple::Buddy::Icon
purple_buddy_icon_unref(icon)
	Purple::Buddy::Icon icon

void
purple_buddy_icon_update(icon)
	Purple::Buddy::Icon icon

void
purple_buddy_icon_set_data(icon, data, len, checksum)
	Purple::Buddy::Icon icon
	void * data
	size_t len
	char *checksum

Purple::Account
purple_buddy_icon_get_account(icon)
	Purple::Buddy::Icon icon

const char *
purple_buddy_icon_get_username(icon)
	Purple::Buddy::Icon icon

const void *
purple_buddy_icon_get_data(icon, len)
	Purple::Buddy::Icon icon
	size_t &len

const char *
purple_buddy_icon_get_extension(icon)
	Purple::Buddy::Icon icon

void
purple_buddy_icon_get_scale_size(spec, width, height)
	Purple::Buddy::Icon::Spec spec
	int *width
	int *height

gchar_own *
purple_buddy_icon_get_full_path(icon);
	Purple::Buddy::Icon icon

MODULE = Purple::Buddy::Icon PACKAGE = Purple::Buddy::Icons   PREFIX = purple_buddy_icons_
PROTOTYPES: ENABLE

void
purple_buddy_icons_set_caching(caching)
	gboolean caching

gboolean
purple_buddy_icons_is_caching()

void
purple_buddy_icons_set_cache_dir(cache_dir)
	const char *cache_dir

const char *
purple_buddy_icons_get_cache_dir();

Purple::Handle
purple_buddy_icons_get_handle();

