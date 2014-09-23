#include "module.h"

MODULE = Purple::Prpl  PACKAGE = Purple::Find  PREFIX = purple_find_
PROTOTYPES: ENABLE

Purple::Plugin
purple_find_prpl(id)
	const char *id

MODULE = Purple::Prpl  PACKAGE = Purple::Prpl  PREFIX = purple_prpl_
PROTOTYPES: ENABLE

void
purple_prpl_change_account_status(account, old_status, new_status)
	Purple::Account account
	Purple::Status old_status
	Purple::Status new_status

void
purple_prpl_get_statuses(account, presence)
	Purple::Account account
	Purple::Presence presence
PREINIT:
	GList *l, *ll;
PPCODE:
	ll = purple_prpl_get_statuses(account,presence);
	for (l = ll; l != NULL; l = l->next) {
		XPUSHs(sv_2mortal(purple_perl_bless_object(l->data, "Purple::Status")));
	}
	/* We can free the list here but the script needs to free the
	 * Purple::Status 'objects' itself. */
	g_list_free(ll);

void
purple_prpl_got_account_idle(account, idle, idle_time)
	Purple::Account account
	gboolean idle
	time_t idle_time

void
purple_prpl_got_account_login_time(account, login_time)
	Purple::Account account
	time_t login_time

void
purple_prpl_got_user_idle(account, name, idle, idle_time)
	Purple::Account account
	const char *name
	gboolean idle
	time_t idle_time

void
purple_prpl_got_user_login_time(account, name, login_time)
	Purple::Account account
	const char *name
	time_t login_time

int
purple_prpl_send_raw(gc, str)
	Purple::Connection gc
	const char *str
PREINIT:
	PurplePluginProtocolInfo *prpl_info;
CODE:
	if (!gc)
		RETVAL = 0;
	else {
		prpl_info = PURPLE_PLUGIN_PROTOCOL_INFO(gc->prpl);
		if (prpl_info && prpl_info->send_raw != NULL) {
			RETVAL = prpl_info->send_raw(gc, str, strlen(str));
		} else {
			RETVAL = 0;
		}
	}
OUTPUT:
	RETVAL

