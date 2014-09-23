#include "status.h"
#include "mono-helper.h"
#include "mono-glue.h"

MonoObject* purple_status_build_status_object(void* data)
{
	MonoObject *obj = NULL;
	PurpleStatus *status = (PurpleStatus*)data;

	obj = ml_create_api_object("Status");
	g_return_val_if_fail(obj != NULL, NULL);

	ml_set_prop_string(obj, "Id", (char*)purple_status_get_id(status));

	return obj;
}
