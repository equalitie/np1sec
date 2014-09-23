#include <string.h>
#include "blist.h"
#include "mono-helper.h"
#include "mono-glue.h"

MonoObject* purple_blist_get_handle_glue(void)
{
	void *handle = purple_blist_get_handle();

	return mono_value_box(ml_get_domain(), mono_get_intptr_class(), &handle);
}

MonoObject* purple_blist_build_buddy_object(void* data)
{
	MonoObject *obj = NULL;

	PurpleBuddy *buddy = (PurpleBuddy*)data;

	obj = ml_create_api_object("Buddy");
	g_return_val_if_fail(obj != NULL, NULL);

	ml_set_prop_string(obj, "Name", (char*)purple_buddy_get_name(buddy));
	ml_set_prop_string(obj, "Alias", (char*)purple_buddy_get_alias(buddy));

	return obj;
}
