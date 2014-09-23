#include "module.h"

MODULE = Purple::Connection  PACKAGE = Purple::Connection  PREFIX = purple_connection_
PROTOTYPES: ENABLE

BOOT:
{
	HV *stash = gv_stashpv("Purple::Connection::State", 1);

	static const constiv *civ, const_iv[] = {
#define const_iv(name) {#name, (IV)PURPLE_##name}
		const_iv(DISCONNECTED),
		const_iv(CONNECTED),
		const_iv(CONNECTING),
	};

	for (civ = const_iv + sizeof(const_iv) / sizeof(const_iv[0]); civ-- > const_iv; )
		newCONSTSUB(stash, (char *)civ->name, newSViv(civ->iv));
}

Purple::Account
purple_connection_get_account(gc)
	Purple::Connection gc

const char *
purple_connection_get_password(gc)
	Purple::Connection gc

const char *
purple_connection_get_display_name(gc)
	Purple::Connection gc

void
purple_connection_notice(gc, text)
	Purple::Connection gc
	const char *text

void
purple_connection_error(gc, reason)
	Purple::Connection gc
	const char *reason

void
purple_connection_destroy(gc)
	Purple::Connection gc

void
purple_connection_set_state(gc, state)
	Purple::Connection gc
	Purple::ConnectionState state

void
purple_connection_set_account(gc, account)
	Purple::Connection gc
	Purple::Account account

void
purple_connection_set_display_name(gc, name)
	Purple::Connection gc
	const char *name

Purple::ConnectionState
purple_connection_get_state(gc)
	Purple::Connection gc

MODULE = Purple::Connection  PACKAGE = Purple::Connections  PREFIX = purple_connections_
PROTOTYPES: ENABLE

void
purple_connections_disconnect_all()

void
purple_connections_get_all()
PREINIT:
	GList *l;
PPCODE:
	for (l = purple_connections_get_all(); l != NULL; l = l->next) {
		XPUSHs(sv_2mortal(purple_perl_bless_object(l->data, "Purple::Connection")));
	}

void
purple_connections_get_connecting()
PREINIT:
	GList *l;
PPCODE:
	for (l = purple_connections_get_connecting(); l != NULL; l = l->next) {
		XPUSHs(sv_2mortal(purple_perl_bless_object(l->data, "Purple::Connection")));
	}

Purple::Handle
purple_connections_get_handle()
