#include "module.h"

MODULE = Purple::Pounce  PACKAGE = Purple::Pounce  PREFIX = purple_pounce_
PROTOTYPES: ENABLE

BOOT:
{
	HV *event_stash = gv_stashpv("Purple::Pounce::Event", 1);
	HV *option_stash = gv_stashpv("Purple::Pounce::Option", 1);

	static const constiv *civ, event_const_iv[] = {
#define const_iv(name) {#name, (IV)PURPLE_POUNCE_##name}
		const_iv(NONE),
		const_iv(SIGNON),
		const_iv(SIGNOFF),
		const_iv(AWAY),
		const_iv(AWAY_RETURN),
		const_iv(IDLE),
		const_iv(IDLE_RETURN),
		const_iv(TYPING),
		const_iv(TYPED),
		const_iv(TYPING_STOPPED),
		const_iv(MESSAGE_RECEIVED),
	};
	static const constiv option_const_iv[] = {
#undef const_iv
#define const_iv(name) {#name, (IV)PURPLE_POUNCE_OPTION_##name}
		const_iv(NONE),
		const_iv(AWAY),
	};

	for (civ = event_const_iv + sizeof(event_const_iv) / sizeof(event_const_iv[0]); civ-- > event_const_iv; )
		newCONSTSUB(event_stash, (char *)civ->name, newSViv(civ->iv));

	for (civ = option_const_iv + sizeof(option_const_iv) / sizeof(option_const_iv[0]); civ-- > option_const_iv; )
		newCONSTSUB(option_stash, (char *)civ->name, newSViv(civ->iv));
}

void
purple_pounce_action_register(pounce, name)
	Purple::Pounce pounce
	const char *name

void
purple_pounce_destroy(pounce)
	Purple::Pounce pounce

void
purple_pounce_destroy_all_by_account(account)
	Purple::Account account

void *
purple_pounce_get_data(pounce)
	Purple::Pounce pounce

Purple::PounceEvent
purple_pounce_get_events(pounce)
	Purple::Pounce pounce

const char *
purple_pounce_get_pouncee(pounce)
	Purple::Pounce pounce

Purple::Account
purple_pounce_get_pouncer(pounce)
	Purple::Pounce pounce

gboolean
purple_pounce_get_save(pounce)
	Purple::Pounce pounce

void
purple_pounce_set_data(pounce, data)
	Purple::Pounce pounce
	void * data

void
purple_pounce_set_events(pounce, events)
	Purple::Pounce pounce
	Purple::PounceEvent events

void
purple_pounce_set_pouncee(pounce, pouncee)
	Purple::Pounce pounce
	const char *pouncee

void
purple_pounce_set_pouncer(pounce, pouncer)
	Purple::Pounce pounce
	Purple::Account pouncer

void
purple_pounce_set_save(pounce, save)
	Purple::Pounce pounce
	gboolean save

MODULE = Purple::Pounce  PACKAGE = Purple::Pounces  PREFIX = purple_pounces_
PROTOTYPES: ENABLE

void
purple_pounces_get_all()
PREINIT:
	GList *l;
PPCODE:
	for (l = purple_pounces_get_all(); l != NULL; l = l->next) {
		XPUSHs(sv_2mortal(purple_perl_bless_object(l->data, "Purple::Pounce")));
	}

void
purple_pounces_get_all_for_ui(ui)
	const char *ui
PREINIT:
	GList *l, *ll;
PPCODE:
	ll = purple_pounces_get_all_for_ui(ui);
	for (l = ll; l != NULL; l = l->next) {
		XPUSHs(sv_2mortal(purple_perl_bless_object(l->data, "Purple::Pounce")));
	}
	g_list_free(ll);

Purple::Handle
purple_pounces_get_handle()

gboolean
purple_pounces_load()

void
purple_pounces_unregister_handler(ui)
	const char *ui
