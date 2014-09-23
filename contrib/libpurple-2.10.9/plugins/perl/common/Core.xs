#include "module.h"

MODULE = Purple::Core  PACKAGE = Purple::Core  PREFIX = purple_core_
PROTOTYPES: ENABLE

gboolean 
purple_core_quit_cb()
PPCODE:
	/* The argument to purple_core_quit_cb is not used,
	 * so there's little point in requiring it on the
	 * Perl side. */
	RETVAL = purple_core_quit_cb(NULL);
	ST(0) = boolSV(RETVAL);
	sv_2mortal(ST(0));

const char *
purple_core_get_version()

const char *
purple_core_get_ui()

