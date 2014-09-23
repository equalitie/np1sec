#include "module.h"

/* I can't get this to work, both with and without the const on the return
 * type I get errors from gcc. One way about ignoring types in a cast, and the
 * other about assigning to read-only variables.
const Purple::StatusType
purple_savedstatus_substatus_get_type(substatus)
	const Purple::SavedStatus::Sub substatus
*/

MODULE = Purple::SavedStatus  PACKAGE = Purple::SavedStatus  PREFIX = purple_savedstatus_
PROTOTYPES: ENABLE

Purple::SavedStatus
purple_savedstatus_new(title, type)
	const char *title
	Purple::StatusPrimitive type

void
purple_savedstatus_set_title(status, title)
	Purple::SavedStatus status
	const char *title

void
purple_savedstatus_set_type(status, type)
	Purple::SavedStatus status
	Purple::StatusPrimitive type

void
purple_savedstatus_set_message(status, message)
	Purple::SavedStatus status
	const char *message

void
purple_savedstatus_set_substatus(status, account, type, message)
	Purple::SavedStatus status
	Purple::Account account
	Purple::StatusType type
	const char *message

void
purple_savedstatus_unset_substatus(status, account)
	Purple::SavedStatus status
	Purple::Account account

gboolean
purple_savedstatus_delete(title)
	const char *title

Purple::SavedStatus
purple_savedstatus_get_current()

Purple::SavedStatus
purple_savedstatus_get_default()

Purple::SavedStatus
purple_savedstatus_get_idleaway()

gboolean
purple_savedstatus_is_idleaway()

void
purple_savedstatus_set_idleaway(idleaway)
	gboolean idleaway

Purple::SavedStatus
purple_savedstatus_get_startup()

Purple::SavedStatus
purple_savedstatus_find(title)
	const char *title

Purple::SavedStatus
purple_savedstatus_find_by_creation_time(creation_time)
	time_t creation_time

Purple::SavedStatus
purple_savedstatus_find_transient_by_type_and_message(type, message)
	Purple::StatusPrimitive type
	const char *message

gboolean
purple_savedstatus_is_transient(saved_status)
	const Purple::SavedStatus saved_status

const char *
purple_savedstatus_get_title(saved_status)
	const Purple::SavedStatus saved_status

Purple::StatusPrimitive
purple_savedstatus_get_type(saved_status)
	const Purple::SavedStatus saved_status

const char *
purple_savedstatus_get_message(saved_status)
	const Purple::SavedStatus saved_status

time_t
purple_savedstatus_get_creation_time(saved_status)
	const Purple::SavedStatus saved_status

gboolean
purple_savedstatus_has_substatuses(saved_status)
	const Purple::SavedStatus saved_status

Purple::SavedStatus::Sub
purple_savedstatus_get_substatus(saved_status, account)
	Purple::SavedStatus saved_status
	Purple::Account account

void
purple_savedstatus_activate(saved_status)
	Purple::SavedStatus saved_status

void
purple_savedstatus_activate_for_account(saved_status, account)
	const Purple::SavedStatus saved_status
	Purple::Account account

MODULE = Purple::SavedStatus::Sub  PACKAGE = Purple::SavedStatus::Sub  PREFIX = purple_savedstatus_substatus_
PROTOTYPES: ENABLE

const char *
purple_savedstatus_substatus_get_message(substatus)
	const Purple::SavedStatus::Sub substatus

MODULE = Purple::SavedStatus  PACKAGE = Purple::SavedStatuses  PREFIX = purple_savedstatuses_
PROTOTYPES: ENABLE

void
purple_savedstatuses_get_all()
PREINIT:
	GList *l;
PPCODE:
	for (l = purple_savedstatuses_get_all(); l != NULL; l = l->next) {
		XPUSHs(sv_2mortal(purple_perl_bless_object(l->data, "Purple::SavedStatus")));
	}

void
purple_savedstatuses_get_popular(how_many)
	unsigned int how_many
PREINIT:
	GList *l, *ll;
PPCODE:
	ll = purple_savedstatuses_get_popular(how_many);
	for (l = ll; l != NULL; l = l->next) {
		XPUSHs(sv_2mortal(purple_perl_bless_object(l->data, "Purple::SavedStatus")));
	}
	g_list_free(ll);

Purple::Handle
purple_savedstatuses_get_handle()
