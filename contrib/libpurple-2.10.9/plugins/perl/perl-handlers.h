#ifndef _PURPLE_PERL_HANDLERS_H_
#define _PURPLE_PERL_HANDLERS_H_

#include "cmds.h"
#include "plugin.h"
#include "prefs.h"
#include "pluginpref.h"
#ifdef PURPLE_GTKPERL
#include "gtkplugin.h"
#include "gtkutils.h"
#endif

typedef struct
{
	PurpleCmdId id;
	SV *callback;
	SV *data;
	gchar *prpl_id;
	gchar *cmd;
	PurplePlugin *plugin;
} PurplePerlCmdHandler;

typedef struct
{
	SV *callback;
	SV *data;
	PurplePlugin *plugin;
	int iotag;

} PurplePerlTimeoutHandler;

typedef struct
{
	gchar *signal;
	SV *callback;
	SV *data;
	void *instance;
	PurplePlugin *plugin;

} PurplePerlSignalHandler;

typedef struct
{
	SV *callback;
	SV *data;
	PurplePlugin *plugin;
	int iotag;

} PurplePerlPrefsHandler;

void purple_perl_plugin_action_cb(PurplePluginAction * gpa);
GList *purple_perl_plugin_actions(PurplePlugin *plugin, gpointer context);

PurplePluginPrefFrame *purple_perl_get_plugin_frame(PurplePlugin *plugin);

#ifdef PURPLE_GTKPERL
GtkWidget *purple_perl_gtk_get_plugin_frame(PurplePlugin *plugin);
#endif

guint purple_perl_timeout_add(PurplePlugin *plugin, int seconds, SV *callback,
                              SV *data);
gboolean purple_perl_timeout_remove(guint handle);
void purple_perl_timeout_clear_for_plugin(PurplePlugin *plugin);
void purple_perl_timeout_clear(void);

void purple_perl_signal_connect(PurplePlugin *plugin, void *instance,
                              const char *signal, SV *callback,
                              SV *data, int priority);
void purple_perl_signal_disconnect(PurplePlugin *plugin, void *instance,
                                 const char *signal);
void purple_perl_signal_clear_for_plugin(PurplePlugin *plugin);
void purple_perl_signal_clear(void);

PurpleCmdId purple_perl_cmd_register(PurplePlugin *plugin, const gchar *cmd,
                                 const gchar *args, PurpleCmdPriority priority,
                                 PurpleCmdFlag flag, const gchar *prpl_id,
                                 SV *callback, const gchar *helpstr, SV *data);
void purple_perl_cmd_unregister(PurpleCmdId id);
void purple_perl_cmd_clear_for_plugin(PurplePlugin *plugin);

guint purple_perl_prefs_connect_callback(PurplePlugin *plugin, const char *name, SV *callback, SV *data);
void purple_perl_prefs_disconnect_callback(guint callback_id);
void purple_perl_pref_cb_clear_for_plugin(PurplePlugin *plugin);

#endif /* _PURPLE_PERL_HANDLERS_H_ */
