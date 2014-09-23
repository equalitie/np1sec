#include "module.h"

MODULE = Purple::Debug  PACKAGE = Purple::Debug  PREFIX = purple_debug_
PROTOTYPES: ENABLE

BOOT:
{
	HV *stash = gv_stashpv("Purple::Debug", 1);

	static const constiv *civ, const_iv[] = {
#define const_iv(name) {#name, (IV)PURPLE_DEBUG_##name}
		const_iv(ALL),
		const_iv(MISC),
		const_iv(INFO),
		const_iv(WARNING),
		const_iv(ERROR),
		const_iv(FATAL),
	};

	for (civ = const_iv + sizeof(const_iv) / sizeof(const_iv[0]); civ-- > const_iv; )
		newCONSTSUB(stash, (char *)civ->name, newSViv(civ->iv));
}

void
purple_debug(level, category, string)
	Purple::DebugLevel level
	const char *category
	const char *string
CODE:
	purple_debug(level, category, "%s", string);

void
purple_debug_misc(category, string)
	const char *category
	const char *string
CODE:
	purple_debug_misc(category, "%s", string);

void
purple_debug_info(category, string)
	const char *category
	const char *string
CODE:
	purple_debug_info(category, "%s", string);

void
purple_debug_warning(category, string)
	const char *category
	const char *string
CODE:
	purple_debug_warning(category, "%s", string);

void
purple_debug_error(category, string)
	const char *category
	const char *string
CODE:
	purple_debug_error(category, "%s", string);

void
purple_debug_fatal(category, string)
	const char *category
	const char *string
CODE:
	purple_debug_fatal(category, "%s", string);

void
purple_debug_set_enabled(enabled)
	gboolean enabled

gboolean
purple_debug_is_enabled()
