#include "perl-common.h"
#include "perl-handlers.h"

#include "debug.h"
#include "signals.h"

extern PerlInterpreter *my_perl;
static GSList *cmd_handlers = NULL;
static GSList *signal_handlers = NULL;
static GSList *timeout_handlers = NULL;
static GSList *pref_handlers = NULL;

/* perl < 5.8.0 doesn't define PERL_MAGIC_ext */
#ifndef PERL_MAGIC_ext
#define PERL_MAGIC_ext '~'
#endif

void
purple_perl_plugin_action_cb(PurplePluginAction *action)
{
	SV **callback;
	HV *hv = NULL;
	gchar *hvname;
	PurplePlugin *plugin;
	PurplePerlScript *gps;
	dSP;

	plugin = action->plugin;
	gps = (PurplePerlScript *)plugin->info->extra_info;
	hvname = g_strdup_printf("%s::plugin_actions", gps->package);
	hv = get_hv(hvname, FALSE);
	g_free(hvname);

	if (hv == NULL)
		croak("No plugin_actions hash found in \"%s\" plugin.", purple_plugin_get_name(plugin));

	ENTER;
	SAVETMPS;

	callback = hv_fetch(hv, action->label, strlen(action->label), 0);

	if (callback == NULL || *callback == NULL)
		croak("No plugin_action function named \"%s\" in \"%s\" plugin.", action->label, purple_plugin_get_name(plugin));

	PUSHMARK(sp);
	XPUSHs(purple_perl_bless_object(gps->plugin, "Purple::Plugin"));
	PUTBACK;

	call_sv(*callback, G_EVAL | G_VOID | G_DISCARD);

	SPAGAIN;

	if (SvTRUE(ERRSV)) {
		purple_debug_error("perl",
		                 "Perl plugin action function exited abnormally: %s\n",
		                 SvPVutf8_nolen(ERRSV));
	}

	PUTBACK;
	FREETMPS;
	LEAVE;
}

GList *
purple_perl_plugin_actions(PurplePlugin *plugin, gpointer context)
{
	GList *l = NULL;
	PurplePerlScript *gps;
	int i = 0, count = 0;
	dSP;

	gps = plugin->info->extra_info;

	ENTER;
	SAVETMPS;

	PUSHMARK(SP);
	XPUSHs(sv_2mortal(purple_perl_bless_object(plugin, "Purple::Plugin")));
	/* XXX This *will* cease working correctly if context gets changed to
	 * ever be able to hold anything other than a PurpleConnection */
	if (context != NULL)
		XPUSHs(sv_2mortal(purple_perl_bless_object(context,
		                                         "Purple::Connection")));
	else
		XPUSHs(&PL_sv_undef);
	PUTBACK;

	count = call_pv(gps->plugin_action_sub, G_EVAL | G_ARRAY);

	SPAGAIN;

	if (SvTRUE(ERRSV)) {
		purple_debug_error("perl",
		                 "Perl plugin actions lookup exited abnormally: %s\n",
		                 SvPVutf8_nolen(ERRSV));
	}

	if (count == 0)
		croak("The plugin_actions sub didn't return anything.\n");

	for (i = 0; i < count; i++) {
		SV *sv;
		PurplePluginAction *act;

		sv = POPs;
		act = purple_plugin_action_new(SvPVutf8_nolen(sv), purple_perl_plugin_action_cb);
		l = g_list_prepend(l, act);
	}

	PUTBACK;
	FREETMPS;
	LEAVE;

	return l;
}

#ifdef PURPLE_GTKPERL
GtkWidget *
purple_perl_gtk_get_plugin_frame(PurplePlugin *plugin)
{
	SV * sv;
	int count;
	MAGIC *mg;
	GtkWidget *ret;
	PurplePerlScript *gps;
	dSP;

	gps = plugin->info->extra_info;

	ENTER;
	SAVETMPS;

	count = call_pv(gps->gtk_prefs_sub, G_EVAL | G_SCALAR | G_NOARGS);
	if (count != 1)
		croak("call_pv: Did not return the correct number of values.\n");

	/* the frame was created in a perl sub and is returned */
	SPAGAIN;

	if (SvTRUE(ERRSV)) {
		purple_debug_error("perl",
		                 "Perl gtk plugin frame init exited abnormally: %s\n",
		                 SvPVutf8_nolen(ERRSV));
	}

	/* We have a Gtk2::Frame on top of the stack */
	sv = POPs;

	/* The magic field hides the pointer to the actual GtkWidget */
	mg = mg_find(SvRV(sv), PERL_MAGIC_ext);
	ret = (GtkWidget *)mg->mg_ptr;

	PUTBACK;
	FREETMPS;
	LEAVE;

	return ret;
}
#endif

PurplePluginPrefFrame *
purple_perl_get_plugin_frame(PurplePlugin *plugin)
{
	/* Sets up the Perl Stack for our call back into the script to run the
	 * plugin_pref... sub */
	int count;
	PurplePerlScript *gps;
	PurplePluginPrefFrame *ret_frame;
	dSP;

	gps = (PurplePerlScript *)plugin->info->extra_info;

	ENTER;
	SAVETMPS;
	/* Some perl magic to run perl_plugin_pref_frame_SV perl sub and
	 * return the frame */
	PUSHMARK(SP);
	PUTBACK;

	count = call_pv(gps->prefs_sub, G_EVAL | G_SCALAR | G_NOARGS);

	SPAGAIN;

	if (SvTRUE(ERRSV)) {
		purple_debug_error("perl",
		                 "Perl plugin prefs frame init exited abnormally: %s\n",
		                 SvPVutf8_nolen(ERRSV));
	}

	if (count != 1)
		croak("call_pv: Did not return the correct number of values.\n");
	/* the frame was created in a perl sub and is returned */
	ret_frame = (PurplePluginPrefFrame *)purple_perl_ref_object(POPs);

	/* Tidy up the Perl stack */
	PUTBACK;
	FREETMPS;
	LEAVE;

	return ret_frame;
}

static gboolean
destroy_timeout_handler(PurplePerlTimeoutHandler *handler)
{
	gboolean ret = FALSE;

	timeout_handlers = g_slist_remove(timeout_handlers, handler);

	if (handler->iotag > 0)
		ret = purple_timeout_remove(handler->iotag);

	if (handler->callback != NULL)
		SvREFCNT_dec(handler->callback);

	if (handler->data != NULL)
		SvREFCNT_dec(handler->data);

	g_free(handler);

	return ret;
}

static void
destroy_signal_handler(PurplePerlSignalHandler *handler)
{
	signal_handlers = g_slist_remove(signal_handlers, handler);

	if (handler->callback != NULL)
		SvREFCNT_dec(handler->callback);

	if (handler->data != NULL)
		SvREFCNT_dec(handler->data);

	g_free(handler->signal);
	g_free(handler);
}

static gboolean
perl_timeout_cb(gpointer data)
{
	PurplePerlTimeoutHandler *handler = data;
	gboolean ret = FALSE;

	dSP;
	ENTER;
	SAVETMPS;
	PUSHMARK(sp);
	XPUSHs((SV *)handler->data);
	PUTBACK;
	call_sv(handler->callback, G_EVAL | G_SCALAR);
	SPAGAIN;

	if (SvTRUE(ERRSV)) {
		purple_debug_error("perl",
		                 "Perl timeout function exited abnormally: %s\n",
		                 SvPVutf8_nolen(ERRSV));
	}

	ret = POPi;

	PUTBACK;
	FREETMPS;
	LEAVE;

	if (ret == FALSE)
		destroy_timeout_handler(handler);

	return ret;
}

typedef void *DATATYPE;

static void *
perl_signal_cb(va_list args, void *data)
{
	PurplePerlSignalHandler *handler = data;
	void *ret_val = NULL;
	int i;
	int count;
	int value_count;
	PurpleValue *ret_value, **values;
	SV **sv_args;
	DATATYPE **copy_args;

	dSP;
	PERL_SET_CONTEXT(my_perl);
	SPAGAIN;
	ENTER;
	SAVETMPS;
	PUSHMARK(sp);

	purple_signal_get_values(handler->instance, handler->signal,
	                         &ret_value, &value_count, &values);

	sv_args   = g_new(SV *,    value_count);
	copy_args = g_new(void **, value_count);

	for (i = 0; i < value_count; i++) {
		sv_args[i] = purple_perl_sv_from_vargs(values[i],
#ifdef VA_COPY_AS_ARRAY
		                                       (va_list*)args,
#else
		                                       (va_list*)&args,
#endif
		                                       &copy_args[i]);

		XPUSHs(sv_args[i]);
	}

	XPUSHs((SV *)handler->data);

	PUTBACK;

	if (ret_value != NULL) {
		count = call_sv(handler->callback, G_EVAL | G_SCALAR);

		SPAGAIN;

		if (count != 1)
			croak("Uh oh! call_sv returned %i != 1", i);
		else
			ret_val = purple_perl_data_from_sv(ret_value, POPs);
	} else {
		call_sv(handler->callback, G_EVAL | G_SCALAR);

		SPAGAIN;
	}

	if (SvTRUE(ERRSV)) {
		purple_debug_error("perl",
		                 "Perl function exited abnormally: %s\n",
		                 SvPVutf8_nolen(ERRSV));
	}

	/* See if any parameters changed. */
	for (i = 0; i < value_count; i++) {
		if (purple_value_is_outgoing(values[i])) {
			switch (purple_value_get_type(values[i])) {
				case PURPLE_TYPE_BOOLEAN:
					*((gboolean *)copy_args[i]) = SvIV(sv_args[i]);
					break;

				case PURPLE_TYPE_INT:
					*((int *)copy_args[i]) = SvIV(sv_args[i]);
					break;

				case PURPLE_TYPE_UINT:
					*((unsigned int *)copy_args[i]) = SvUV(sv_args[i]);
					break;

				case PURPLE_TYPE_LONG:
					*((long *)copy_args[i]) = SvIV(sv_args[i]);
					break;

				case PURPLE_TYPE_ULONG:
					*((unsigned long *)copy_args[i]) = SvUV(sv_args[i]);
					break;

				case PURPLE_TYPE_INT64:
					*((gint64 *)copy_args[i]) = SvIV(sv_args[i]);
					break;

				case PURPLE_TYPE_UINT64:
					*((guint64 *)copy_args[i]) = SvUV(sv_args[i]);
					break;

				case PURPLE_TYPE_STRING:
					if (!*((char **)copy_args[i]) || !SvPVX(sv_args[i]) ||
							strcmp(*((char **)copy_args[i]), SvPVX(sv_args[i]))) {
						g_free(*((char **)copy_args[i]));
						*((char **)copy_args[i]) =
							g_strdup(SvPVutf8_nolen(sv_args[i]));
					}
					/* Clean up sv_args[i] - we're done with it */
					sv_2mortal(sv_args[i]);
					break;

				case PURPLE_TYPE_POINTER:
				case PURPLE_TYPE_BOXED:
					*((void **)copy_args[i]) = (void *)SvIV(sv_args[i]);
					break;
				case PURPLE_TYPE_SUBTYPE:
					*((void **)copy_args[i]) = purple_perl_ref_object(sv_args[i]);
					break;

				default:
					break;
			}


#if 0
			*((void **)copy_args[i]) = purple_perl_data_from_sv(values[i],
															  sv_args[i]);
#endif
		}
	}

	PUTBACK;
	FREETMPS;
	LEAVE;

	g_free(sv_args);
	g_free(copy_args);

	purple_debug_misc("perl", "ret_val = %p\n", ret_val);

	return ret_val;
}

static PurplePerlSignalHandler *
find_signal_handler(PurplePlugin *plugin, void *instance, const char *signal)
{
	PurplePerlSignalHandler *handler;
	GSList *l;

	for (l = signal_handlers; l != NULL; l = l->next) {
		handler = l->data;

		if (handler->plugin == plugin &&
			handler->instance == instance &&
			!strcmp(handler->signal, signal)) {
			return handler;
		}
	}

	return NULL;
}

guint
purple_perl_timeout_add(PurplePlugin *plugin, int seconds, SV *callback, SV *data)
{
	PurplePerlTimeoutHandler *handler;

	if (plugin == NULL) {
		croak("Invalid handle in adding perl timeout handler.\n");
		return 0;
	}

	handler = g_new0(PurplePerlTimeoutHandler, 1);

	handler->plugin   = plugin;
	handler->callback = (callback != NULL && callback != &PL_sv_undef
	                     ? newSVsv(callback) : NULL);
	handler->data     = (data != NULL && data != &PL_sv_undef
	                     ? newSVsv(data) : NULL);

	timeout_handlers = g_slist_append(timeout_handlers, handler);

	handler->iotag = purple_timeout_add_seconds(seconds, perl_timeout_cb, handler);

	return handler->iotag;
}

gboolean
purple_perl_timeout_remove(guint handle)
{
	PurplePerlTimeoutHandler *handler;
	GSList *l, *l_next;

	for (l = timeout_handlers; l != NULL; l = l_next) {
		handler =  l->data;
		l_next = l->next;

		if (handler->iotag == handle)
			return destroy_timeout_handler(handler);
	}

	purple_debug_info("perl", "No timeout handler found with handle %u.\n",
	                  handle);
	return FALSE;
}

void
purple_perl_timeout_clear_for_plugin(PurplePlugin *plugin)
{
	PurplePerlTimeoutHandler *handler;
	GSList *l, *l_next;

	for (l = timeout_handlers; l != NULL; l = l_next) {
		handler = l->data;
		l_next = l->next;

		if (handler->plugin == plugin)
			destroy_timeout_handler(handler);
	}
}

void
purple_perl_timeout_clear(void)
{
	while (timeout_handlers != NULL)
		destroy_timeout_handler(timeout_handlers->data);
}

void
purple_perl_signal_connect(PurplePlugin *plugin, void *instance,
                         const char *signal, SV *callback, SV *data,
                         int priority)
{
	PurplePerlSignalHandler *handler;

	handler = g_new0(PurplePerlSignalHandler, 1);
	handler->plugin   = plugin;
	handler->instance = instance;
	handler->signal   = g_strdup(signal);
	handler->callback = (callback != NULL &&
	                     callback != &PL_sv_undef ? newSVsv(callback)
	                                              : NULL);
	handler->data     = (data != NULL &&
	                     data != &PL_sv_undef ? newSVsv(data) : NULL);

	signal_handlers = g_slist_append(signal_handlers, handler);

	purple_signal_connect_priority_vargs(instance, signal, plugin,
	                                   PURPLE_CALLBACK(perl_signal_cb),
	                                   handler, priority);
}

void
purple_perl_signal_disconnect(PurplePlugin *plugin, void *instance,
                            const char *signal)
{
	PurplePerlSignalHandler *handler;

	handler = find_signal_handler(plugin, instance, signal);

	if (handler == NULL) {
		croak("Invalid signal handler information in "
		      "disconnecting a perl signal handler.\n");
		return;
	}

	destroy_signal_handler(handler);
}

void
purple_perl_signal_clear_for_plugin(PurplePlugin *plugin)
{
	PurplePerlSignalHandler *handler;
	GSList *l, *l_next;

	for (l = signal_handlers; l != NULL; l = l_next) {
		l_next = l->next;
		handler = l->data;

		if (handler->plugin == plugin)
			destroy_signal_handler(handler);
	}
}

void
purple_perl_signal_clear(void)
{
	while (signal_handlers != NULL)
		destroy_signal_handler(signal_handlers->data);
}

static PurpleCmdRet
perl_cmd_cb(PurpleConversation *conv, const gchar *command,
            gchar **args, gchar **error, void *data)
{
	int i = 0, count, ret_value = PURPLE_CMD_RET_OK;
	SV *cmdSV, *tmpSV, *convSV;
	PurplePerlCmdHandler *handler = data;

	dSP;
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);

	/* Push the conversation onto the perl stack */
	convSV = sv_2mortal(purple_perl_bless_object(conv, "Purple::Conversation"));
	XPUSHs(convSV);

	/* Push the command string onto the perl stack */
	cmdSV = newSVpv(command, 0);
	cmdSV = sv_2mortal(cmdSV);
	XPUSHs(cmdSV);

	/* Push the data onto the perl stack */
	XPUSHs((SV *)handler->data);

	/* Push any arguments we may have */
	for (i = 0; args[i] != NULL; i++) {
		/* XXX The mortality of these created SV's should prevent
		 * memory issues, if I read/understood everything correctly...
		 */
		tmpSV = newSVpv(args[i], 0);
		tmpSV = sv_2mortal(tmpSV);
		XPUSHs(tmpSV);
	}

	PUTBACK;
	count = call_sv(handler->callback, G_EVAL | G_SCALAR);

	if (count != 1)
		croak("call_sv: Did not return the correct number of values.\n");

	if (SvTRUE(ERRSV)) {
		purple_debug_error("perl",
		                 "Perl plugin command function exited abnormally: %s\n",
		                 SvPVutf8_nolen(ERRSV));
	}

	SPAGAIN;

	ret_value = POPi;

	PUTBACK;
	FREETMPS;
	LEAVE;

	return ret_value;
}

PurpleCmdId
purple_perl_cmd_register(PurplePlugin *plugin, const gchar *command,
                       const gchar *args, PurpleCmdPriority priority,
                       PurpleCmdFlag flag, const gchar *prpl_id, SV *callback,
                       const gchar *helpstr, SV *data)
{
	PurplePerlCmdHandler *handler;

	handler          = g_new0(PurplePerlCmdHandler, 1);
	handler->plugin  = plugin;
	handler->cmd     = g_strdup(command);
	handler->prpl_id = g_strdup(prpl_id);

	if (callback != NULL && callback != &PL_sv_undef)
		handler->callback = newSVsv(callback);
	else
		handler->callback = NULL;

	if (data != NULL && data != &PL_sv_undef)
		handler->data = newSVsv(data);
	else
		handler->data = NULL;

	cmd_handlers = g_slist_append(cmd_handlers, handler);

	handler->id = purple_cmd_register(command, args, priority, flag, prpl_id,
	                                PURPLE_CMD_FUNC(perl_cmd_cb), helpstr,
	                                handler);

	return handler->id;
}

static void
destroy_cmd_handler(PurplePerlCmdHandler *handler)
{
	purple_cmd_unregister(handler->id);
	cmd_handlers = g_slist_remove(cmd_handlers, handler);

	if (handler->callback != NULL)
		SvREFCNT_dec(handler->callback);

	if (handler->data != NULL)
		SvREFCNT_dec(handler->data);

	g_free(handler->cmd);
	g_free(handler->prpl_id);
	g_free(handler);
}

void
purple_perl_cmd_clear_for_plugin(PurplePlugin *plugin)
{
	PurplePerlCmdHandler *handler;
	GSList *l, *l_next;

	for (l = cmd_handlers; l != NULL; l = l_next) {
		handler = l->data;
		l_next = l->next;

		if (handler->plugin == plugin)
			destroy_cmd_handler(handler);
	}
}

static PurplePerlCmdHandler *
find_cmd_handler(PurpleCmdId id)
{
	PurplePerlCmdHandler *handler;
	GSList *l;

	for (l = cmd_handlers; l != NULL; l = l->next) {
		handler = (PurplePerlCmdHandler *)l->data;

		if (handler->id == id)
			return handler;
	}

	return NULL;
}

void
purple_perl_cmd_unregister(PurpleCmdId id)
{
	PurplePerlCmdHandler *handler;

	handler = find_cmd_handler(id);

	if (handler == NULL) {
		croak("Invalid command id in removing a perl command handler.\n");
		return;
	}

	destroy_cmd_handler(handler);
}

static void
perl_pref_cb(const char *name, PurplePrefType type, gconstpointer value,
			 gpointer data)
{
	PurplePerlPrefsHandler *handler = data;

	dSP;
	ENTER;
	SAVETMPS;
	PUSHMARK(sp);
	XPUSHs(sv_2mortal(newSVpv(name, 0)));

	XPUSHs(sv_2mortal(newSViv(type)));

	switch(type) {
		case PURPLE_PREF_INT:
			XPUSHs(sv_2mortal(newSViv(GPOINTER_TO_INT(value))));
			break;
		case PURPLE_PREF_BOOLEAN:
			XPUSHs((GPOINTER_TO_INT(value) == FALSE) ? &PL_sv_no : &PL_sv_yes);
			break;
		case PURPLE_PREF_STRING:
		case PURPLE_PREF_PATH:
			XPUSHs(sv_2mortal(newSVGChar(value)));
			break;
		case PURPLE_PREF_STRING_LIST:
		case PURPLE_PREF_PATH_LIST:
			{
				AV* av = newAV();
				const GList *l = value;

				/* Append stuff backward to preserve order */
				while (l && l->next) l = l->next;
				while (l) {
					av_push(av, sv_2mortal(newSVGChar(l->data)));
					l = l->prev;
				}
				XPUSHs(sv_2mortal(newRV_noinc((SV *) av)));
			} break;
		default:
		case PURPLE_PREF_NONE:
			XPUSHs(&PL_sv_undef);
			break;
	}

	XPUSHs((SV *)handler->data);
	PUTBACK;
	call_sv(handler->callback, G_EVAL | G_VOID | G_DISCARD);
	SPAGAIN;

	if (SvTRUE(ERRSV)) {
		purple_debug_error("perl",
		                 "Perl prefs callback function exited abnormally: %s\n",
		                 SvPVutf8_nolen(ERRSV));
	}

	PUTBACK;
	FREETMPS;
	LEAVE;
}

guint
purple_perl_prefs_connect_callback(PurplePlugin *plugin, const char *name,
								   SV *callback, SV *data)
{
	PurplePerlPrefsHandler *handler;

	if (plugin == NULL) {
		croak("Invalid handle in adding perl prefs handler.\n");
		return 0;
	}

	handler = g_new0(PurplePerlPrefsHandler, 1);

	handler->plugin   = plugin;
	handler->callback = (callback != NULL && callback != &PL_sv_undef
	                     ? newSVsv(callback) : NULL);
	handler->data     = (data != NULL && data != &PL_sv_undef
	                     ? newSVsv(data) : NULL);

	pref_handlers = g_slist_prepend(pref_handlers, handler);

	handler->iotag = purple_prefs_connect_callback(plugin, name, perl_pref_cb, handler);

	return handler->iotag;
}

static void
destroy_prefs_handler(PurplePerlPrefsHandler *handler)
{
	pref_handlers = g_slist_remove(pref_handlers, handler);

	if (handler->iotag > 0)
		purple_prefs_disconnect_callback(handler->iotag);

	if (handler->callback != NULL)
		SvREFCNT_dec(handler->callback);

	if (handler->data != NULL)
		SvREFCNT_dec(handler->data);

	g_free(handler);
}

void purple_perl_prefs_disconnect_callback(guint callback_id)
{
	GSList *l, *l_next;
	PurplePerlPrefsHandler *handler;

	for (l = pref_handlers; l != NULL; l = l_next) {
		l_next = l->next;
		handler = l->data;

		if (handler->iotag == callback_id) {
			destroy_prefs_handler(handler);
			return;
		}
	}

	purple_debug_info("perl", "No prefs handler found with handle %u.\n",
	                  callback_id);
}

void purple_perl_pref_cb_clear_for_plugin(PurplePlugin *plugin)
{
	GSList *l, *l_next;
	PurplePerlPrefsHandler *handler;

	for (l = pref_handlers; l != NULL; l = l_next) {
		l_next = l->next;
		handler = l->data;

		if (handler->plugin == plugin)
			destroy_prefs_handler(handler);
	}
}
