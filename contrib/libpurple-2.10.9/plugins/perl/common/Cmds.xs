#include "module.h"
#include "../perl-handlers.h"

MODULE = Purple::Cmd  PACKAGE = Purple::Cmd  PREFIX = purple_cmd_
PROTOTYPES: ENABLE

BOOT:
{
	HV *status_stash = gv_stashpv("Purple::Cmd::Status", 1);
	HV *ret_stash = gv_stashpv("Purple::Cmd::Return", 1);
	HV *p_stash = gv_stashpv("Purple::Cmd::Priority", 1);
	HV *flag_stash = gv_stashpv("Purple::Cmd::Flag", 1);

	static const constiv *civ, status_const_iv[] = {
#define const_iv(name) {#name, (IV)PURPLE_CMD_STATUS_##name}
		const_iv(OK),
		const_iv(FAILED),
		const_iv(NOT_FOUND),
		const_iv(WRONG_ARGS),
		const_iv(WRONG_PRPL),
		const_iv(WRONG_TYPE),
	};
	static const constiv ret_const_iv[] = {
#undef const_iv
#define const_iv(name) {#name, (IV)PURPLE_CMD_RET_##name}
		const_iv(OK),
		const_iv(FAILED),
		const_iv(CONTINUE),
	};
	static const constiv p_const_iv[] = {
#undef const_iv
#define const_iv(name) {#name, (IV)PURPLE_CMD_P_##name}
		const_iv(VERY_LOW),
		const_iv(LOW),
		const_iv(DEFAULT),
		const_iv(PRPL),
		const_iv(PLUGIN),
		const_iv(ALIAS),
		const_iv(HIGH),
		const_iv(VERY_HIGH),
	};
	static const constiv flag_const_iv[] = {
#undef const_iv
#define const_iv(name) {#name, (IV)PURPLE_CMD_FLAG_##name}
		const_iv(IM),
		const_iv(CHAT),
		const_iv(PRPL_ONLY),
		const_iv(ALLOW_WRONG_ARGS),
	};

	for (civ = status_const_iv + sizeof(status_const_iv) / sizeof(status_const_iv[0]); civ-- > status_const_iv;)
		newCONSTSUB(status_stash, (char *)civ->name, newSViv(civ->iv));

	for (civ = ret_const_iv + sizeof(ret_const_iv) / sizeof(ret_const_iv[0]); civ-- > ret_const_iv;)
		newCONSTSUB(ret_stash, (char *)civ->name, newSViv(civ->iv));

	for (civ = p_const_iv + sizeof(p_const_iv) / sizeof(p_const_iv[0]); civ-- > p_const_iv;)
		newCONSTSUB(p_stash, (char *)civ->name, newSViv(civ->iv));

	for (civ = flag_const_iv + sizeof(flag_const_iv) / sizeof(flag_const_iv[0]); civ-- > flag_const_iv;)
		newCONSTSUB(flag_stash, (char *)civ->name, newSViv(civ->iv));
}

void
purple_cmd_help(conv, command)
	Purple::Conversation conv
	const gchar *command
PREINIT:
	GList *l, *ll;
PPCODE:
	for (l = ll = purple_cmd_help(conv, command); l != NULL; l = l->next) {
		XPUSHs(sv_2mortal(newSVpv(l->data, 0)));
	}
	g_list_free(ll);

void
purple_cmd_list(conv)
	Purple::Conversation conv
PREINIT:
	GList *l, *ll;
PPCODE:
	for (l = ll = purple_cmd_list(conv); l != NULL; l = l->next) {
		XPUSHs(sv_2mortal(newSVpv(l->data, 0)));
	}
	g_list_free(ll);

Purple::Cmd::Id
purple_cmd_register(plugin, command, args, priority, flag, prpl_id, func, helpstr, data = 0)
	Purple::Plugin plugin
	const gchar *command
	const gchar *args
	Purple::Cmd::Priority priority
	Purple::Cmd::Flag flag
	const gchar *prpl_id
	SV *func
	const gchar *helpstr
	SV *data
CODE:
	RETVAL = purple_perl_cmd_register(plugin, command, args, priority, flag,
	                                prpl_id, func, helpstr, data);
OUTPUT:
	RETVAL

void
purple_cmd_unregister(id)
	Purple::Cmd::Id id
CODE:
	purple_perl_cmd_unregister(id);
