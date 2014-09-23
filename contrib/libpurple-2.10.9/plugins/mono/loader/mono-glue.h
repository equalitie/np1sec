#ifndef _PURPLE_MONO_LOADER_GLUE_H_
#define _PURPLE_MONO_LOADER_GLUE_H_

#include <mono/jit/jit.h>
#include <mono/metadata/object.h>
#include <mono/metadata/environment.h>
#include <mono/metadata/assembly.h>

void purple_debug_glue(int type, MonoString *cat, MonoString *str);

int purple_signal_connect_glue(MonoObject *h, MonoObject *plugin, MonoString *signal, MonoObject *func);

MonoObject* purple_blist_get_handle_glue(void);

MonoObject* purple_blist_build_buddy_object(void* buddy);

MonoObject* purple_status_build_status_object(void* data);

#endif
