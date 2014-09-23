#include "module.h"

MODULE = Purple::Smiley  PACKAGE = Purple::Smiley  PREFIX = purple_smiley_
PROTOTYPES: ENABLE

Purple::Smiley
purple_smiley_new(img, shortcut)
	Purple::StoredImage img
	const char * shortcut

Purple::Smiley
purple_smiley_new_from_file(shortcut, filepath)
	const char * shortcut
	const char * filepath

void
purple_smiley_delete(smiley)
	Purple::Smiley smiley

gboolean
purple_smiley_set_shortcut(smiley, shortcut)
	Purple::Smiley smiley
	const char * shortcut

void
purple_smiley_set_data(smiley, data, data_len)
	Purple::Smiley  smiley
	guchar * data
	size_t  data_len

const char *
purple_smiley_get_shortcut(smiley)
	Purple::Smiley smiley

const char *
purple_smiley_get_checksum(smiley)
	Purple::Smiley smiley

Purple::StoredImage
purple_smiley_get_stored_image(smiley)
	Purple::Smiley smiley

gconstpointer
purple_smiley_get_data(smiley, len)
	Purple::Smiley smiley
	size_t * len

const char *
purple_smiley_get_extension(smiley)
	Purple::Smiley smiley


gchar_own *
purple_smiley_get_full_path(smiley)
	Purple::Smiley smiley


MODULE = Purple::Smiley  PACKAGE = Purple::Smileys  PREFIX = purple_smileys_
PROTOTYPES: ENABLE

void
purple_smileys_get_all()
PREINIT:
    GList *l;
PPCODE:
    for (l = purple_smileys_get_all(); l != NULL; l = g_list_delete_link(l, l)) {
        XPUSHs(sv_2mortal(purple_perl_bless_object(l->data, "Purple::Smiley")));
    }

Purple::Smiley
purple_smileys_find_by_shortcut(shortcut)
	const char * shortcut

Purple::Smiley
purple_smileys_find_by_checksum(checksum)
	const char * checksum

const char *
purple_smileys_get_storing_dir()

