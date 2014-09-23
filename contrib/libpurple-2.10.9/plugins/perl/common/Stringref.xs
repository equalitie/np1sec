#include "module.h"

MODULE = Purple::Stringref  PACKAGE = Purple::Stringref  PREFIX = purple_stringref_
PROTOTYPES: ENABLE

int
purple_stringref_cmp(s1, s2)
	Purple::Stringref s1
	Purple::Stringref s2

size_t
purple_stringref_len(stringref)
	Purple::Stringref stringref

Purple::Stringref
purple_stringref_new(class, value)
	const char *value
    C_ARGS:
	value

Purple::Stringref
purple_stringref_new_noref(class, value)
	const char *value
    C_ARGS:
	value

Purple::Stringref
purple_stringref_ref(stringref)
	Purple::Stringref stringref

void
purple_stringref_unref(stringref)
	Purple::Stringref stringref

const char *
purple_stringref_value(stringref)
	Purple::Stringref stringref
