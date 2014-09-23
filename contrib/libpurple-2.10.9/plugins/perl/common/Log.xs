#include "module.h"

MODULE = Purple::Log  PACKAGE = Purple::Log  PREFIX = purple_log_
PROTOTYPES: ENABLE

BOOT:
{
	HV *type_stash = gv_stashpv("Purple::Log::Type", 1);
	HV *flags_stash = gv_stashpv("Purple::Log::ReadFlags", 1);

	static const constiv *civ, type_const_iv[] = {
#define const_iv(name) {#name, (IV)PURPLE_LOG_##name}
		const_iv(IM),
		const_iv(CHAT),
		const_iv(SYSTEM),
	};
	static const constiv flags_const_iv[] = {
#undef const_iv
#define const_iv(name) {#name, (IV)PURPLE_LOG_READ_##name}
		const_iv(NO_NEWLINE),
	};

	for (civ = type_const_iv + sizeof(type_const_iv) / sizeof(type_const_iv[0]); civ-- > type_const_iv; )
		newCONSTSUB(type_stash, (char *)civ->name, newSViv(civ->iv));

	for (civ = flags_const_iv + sizeof(flags_const_iv) / sizeof(flags_const_iv[0]); civ-- > flags_const_iv; )
		newCONSTSUB(flags_stash, (char *)civ->name, newSViv(civ->iv));
}

Purple::Handle
purple_log_get_handle()

int
purple_log_common_sizer(log)
	Purple::Log log

void
purple_log_common_writer(log, ext)
	Purple::Log log
	const char *ext

gint
purple_log_compare(y, z)
	gconstpointer y
	gconstpointer z

void
purple_log_free(log)
	Purple::Log log

gchar_own *
purple_log_get_log_dir(type, name, account)
	Purple::LogType type
	const char *name
	Purple::Account account

void
purple_log_get_log_sets()
PREINIT:
	GHashTable *l;
PPCODE:
	l = purple_log_get_log_sets();
	XPUSHs(sv_2mortal(purple_perl_bless_object(l, "GHashTable")));

void
purple_log_get_logs(type, name, account)
	Purple::LogType type
	const char *name
	Purple::Account account
PREINIT:
	GList *l, *ll;
PPCODE:
	ll = purple_log_get_logs(type, name, account);
	for (l = ll; l != NULL; l = l->next) {
		XPUSHs(sv_2mortal(purple_perl_bless_object(l->data, "Purple::Log")));
	}
	/* We can free the list here but the script needs to free the
	 * Purple::Log 'objects' itself. */
	g_list_free(ll);

int
purple_log_get_size(log)
	Purple::Log log

void
purple_log_get_system_logs(account)
	Purple::Account account
PREINIT:
	GList *l, *ll;
PPCODE:
	ll = purple_log_get_system_logs(account);
	for (l = ll; l != NULL; l = l->next) {
		XPUSHs(sv_2mortal(purple_perl_bless_object(l->data, "Purple::Log")));
	}
	/* We can free the list here but the script needs to free the
	 * Purple::Log 'objects' itself. */
	g_list_free(ll);

int
purple_log_get_total_size(type, name, account)
	Purple::LogType type
	const char *name
	Purple::Account account

void
purple_log_logger_free(logger)
	Purple::Log::Logger logger

void
purple_log_logger_get_options()
PREINIT:
	GList *l, *ll;
PPCODE:
	/* This might want to be massaged to a hash, since that's essentially
	 * what the key/value list is emulating. */
	for (l = ll = purple_log_logger_get_options(); l != NULL; l = l->next) {
		XPUSHs(sv_2mortal(newSVpv(l->data, 0)));
	}
	g_list_free(ll);

gchar_own *
purple_log_read(log, flags)
	Purple::Log log
	Purple::Log::ReadFlags flags

gint
purple_log_set_compare(y, z)
	gconstpointer y
	gconstpointer z
