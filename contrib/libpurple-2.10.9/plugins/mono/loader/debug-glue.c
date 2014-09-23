#include "mono-glue.h"
#include "debug.h"

void purple_debug_glue(int type, MonoString *cat, MonoString *str)
{
	char *ccat;
	char *cstr;

	ccat = mono_string_to_utf8(cat);
	cstr = mono_string_to_utf8(str);

	purple_debug(type, ccat, "%s", cstr);

	g_free(ccat);
	g_free(cstr);
}
