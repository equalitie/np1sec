#include "module.h"

MODULE = Purple::Idle  PACKAGE = Purple::Idle  PREFIX = purple_idle_
PROTOTYPES: ENABLE

void
purple_idle_touch()

void
purple_idle_set(time)
	time_t time

