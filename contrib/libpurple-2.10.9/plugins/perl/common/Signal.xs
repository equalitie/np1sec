#include "module.h"
#include "../perl-handlers.h"

MODULE = Purple::Signal  PACKAGE = Purple::Signal  PREFIX = purple_signal_
PROTOTYPES: ENABLE

void
purple_signal_connect_priority(instance, signal, plugin, callback, priority, data = 0)
	Purple::Handle instance
	const char *signal
	Purple::Plugin plugin
	SV *callback
	int priority
	SV *data
CODE:
	purple_perl_signal_connect(plugin, instance, signal, callback, data, priority);

void
purple_signal_connect(instance, signal, plugin, callback, data = 0)
	Purple::Handle instance
	const char *signal
	Purple::Plugin plugin
	SV *callback
	SV *data
CODE:
	purple_perl_signal_connect(plugin, instance, signal, callback, data, PURPLE_SIGNAL_PRIORITY_DEFAULT);

void
purple_signal_disconnect(instance, signal, plugin)
	Purple::Handle instance
	const char *signal
	Purple::Plugin plugin
CODE:
	purple_perl_signal_disconnect(plugin, instance, signal);
