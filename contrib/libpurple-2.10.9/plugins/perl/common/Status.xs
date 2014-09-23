#include "module.h"

/* TODO

void
purple_status_type_add_attrs(status_type, id, name, value, purple_status_type_add_attrs)
	Purple::StatusType status_type
	const char *id
	const char *name
	Purple::Value value
	...

Purple::StatusType
purple_status_type_new_with_attrs(primitive, id, name, saveable, user_settable, independent, attr_id, attr_name, attr_value, purple_status_type_new_with_attrs)
	Purple::StatusPrimitive primitive
	const char *id
	const char *name
	gboolean saveable
	gboolean user_settable
	gboolean independent
	const char *attr_id
	const char *attr_name
	Purple::Value attr_value
	...

*/

/* These break on faceprint's amd64 box
void
purple_status_type_add_attrs_vargs(status_type, args)
	Purple::StatusType status_type
	va_list args

void
purple_status_set_active_with_attrs(status, active, args)
	Purple::Status status
	gboolean active
	va_list args

	*/

MODULE = Purple::Status  PACKAGE = Purple::Presence  PREFIX = purple_presence_
PROTOTYPES: ENABLE

BOOT:
{
	HV *context_stash = gv_stashpv("Purple::Presence::Context", 1);
	HV *primitive_stash = gv_stashpv("Purple::Status::Primitive", 1);

	static const constiv *civ, context_const_iv[] = {
#define const_iv(name) {#name, (IV)PURPLE_PRESENCE_CONTEXT_##name}
		const_iv(UNSET),
		const_iv(ACCOUNT),
		const_iv(CONV),
		const_iv(BUDDY),
	};
	static const constiv primitive_const_iv[] = {
#undef const_iv
#define const_iv(name) {#name, (IV)PURPLE_STATUS_##name}
		const_iv(UNSET),
		const_iv(OFFLINE),
		const_iv(AVAILABLE),
		const_iv(UNAVAILABLE),
		const_iv(INVISIBLE),
		const_iv(AWAY),
		const_iv(EXTENDED_AWAY),
		const_iv(MOBILE),
	};

	for (civ = context_const_iv + sizeof(context_const_iv) / sizeof(context_const_iv[0]); civ-- > context_const_iv; )
		newCONSTSUB(context_stash, (char *)civ->name, newSViv(civ->iv));

	for (civ = primitive_const_iv + sizeof(primitive_const_iv) / sizeof(primitive_const_iv[0]); civ-- > primitive_const_iv; )
		newCONSTSUB(primitive_stash, (char *)civ->name, newSViv(civ->iv));
}

void
purple_presence_add_list(presence, source_list)
	Purple::Presence presence
	SV *source_list
PREINIT:
	GList *t_GL;
	int i, t_len;
PPCODE:
	t_GL = NULL;
	t_len = av_len((AV *)SvRV(source_list));

	for (i = 0; i <= t_len; i++) {
		t_GL = g_list_append(t_GL, SvPVutf8_nolen(*av_fetch((AV *)SvRV(source_list), i, 0)));
	}
	purple_presence_add_list(presence, t_GL);
	g_list_free(t_GL);

void
purple_presence_add_status(presence, status)
	Purple::Presence presence
	Purple::Status status

gint
purple_presence_compare(presence1, presence2)
	Purple::Presence presence1
	Purple::Presence presence2

void
purple_presence_destroy(presence)
	Purple::Presence presence

Purple::Account
purple_presence_get_account(presence)
	Purple::Presence presence

Purple::Status
purple_presence_get_active_status(presence)
	Purple::Presence presence

const char *
purple_presence_get_chat_user(presence)
	Purple::Presence presence

Purple::PresenceContext
purple_presence_get_context(presence)
	Purple::Presence presence

Purple::Conversation
purple_presence_get_conversation(presence)
	Purple::Presence presence

time_t
purple_presence_get_idle_time(presence)
	Purple::Presence presence

time_t
purple_presence_get_login_time(presence)
	Purple::Presence presence

Purple::Status
purple_presence_get_status(presence, status_id)
	Purple::Presence presence
	const char *status_id

void
purple_presence_get_statuses(presence)
	Purple::Presence presence
PREINIT:
	GList *l;
PPCODE:
	for (l = purple_presence_get_statuses(presence); l != NULL; l = l->next) {
		XPUSHs(sv_2mortal(purple_perl_bless_object(l->data, "Purple::Status")));
	}

gboolean
purple_presence_is_available(presence)
	Purple::Presence presence

gboolean
purple_presence_is_idle(presence)
	Purple::Presence presence

gboolean
purple_presence_is_online(presence)
	Purple::Presence presence

gboolean
purple_presence_is_status_active(presence, status_id)
	Purple::Presence presence
	const char *status_id

gboolean
purple_presence_is_status_primitive_active(presence, primitive)
	Purple::Presence presence
	Purple::StatusPrimitive primitive

Purple::Presence
purple_presence_new(context)
	Purple::PresenceContext context

Purple::Presence
purple_presence_new_for_account(account)
	Purple::Account account

Purple::Presence
purple_presence_new_for_buddy(buddy)
	Purple::BuddyList::Buddy buddy

Purple::Presence
purple_presence_new_for_conv(conv)
	Purple::Conversation conv

void
purple_presence_set_idle(presence, idle, idle_time)
	Purple::Presence presence
	gboolean idle
	time_t idle_time

void
purple_presence_set_login_time(presence, login_time)
	Purple::Presence presence
	time_t login_time

void
purple_presence_set_status_active(presence, status_id, active)
	Purple::Presence presence
	const char *status_id
	gboolean active

void
purple_presence_switch_status(presence, status_id)
	Purple::Presence presence
	const char *status_id

MODULE = Purple::Status  PACKAGE = Purple::Primitive  PREFIX = purple_primitive_
PROTOTYPES: ENABLE

const char *
purple_primitive_get_id_from_type(type)
	Purple::StatusPrimitive type

const char *
purple_primitive_get_name_from_type(type)
	Purple::StatusPrimitive type

Purple::StatusPrimitive
purple_primitive_get_type_from_id(id)
	const char *id

MODULE = Purple::Status  PACKAGE = Purple::StatusAttr PREFIX = purple_status_attr_
PROTOTYPES: ENABLE

void
purple_status_attr_destroy(attr)
	Purple::StatusAttr attr

const char *
purple_status_attr_get_id(attr)
	Purple::StatusAttr attr

const char *
purple_status_attr_get_name(attr)
	Purple::StatusAttr attr

Purple::Value
purple_status_attr_get_value(attr)
	Purple::StatusAttr attr

Purple::StatusAttr
purple_status_attr_new(id, name, value_type)
	const char *id
	const char *name
	Purple::Value value_type

MODULE = Purple::Status  PACKAGE = Purple::Status  PREFIX = purple_status_
PROTOTYPES: ENABLE

gint
purple_status_compare(status1, status2)
	Purple::Status status1
	Purple::Status status2

void
purple_status_destroy(status)
	Purple::Status status

gboolean
purple_status_get_attr_boolean(status, id)
	Purple::Status status
	const char *id

int
purple_status_get_attr_int(status, id)
	Purple::Status status
	const char *id

const char *
purple_status_get_attr_string(status, id)
	Purple::Status status
	const char *id

Purple::Value
purple_status_get_attr_value(status, id)
	Purple::Status status
	const char *id

Purple::Handle
purple_status_get_handle()

const char *
purple_status_get_id(status)
	Purple::Status status

const char *
purple_status_get_name(status)
	Purple::Status status

Purple::Presence
purple_status_get_presence(status)
	Purple::Status status

Purple::StatusType
purple_status_get_type(status)
	Purple::Status status

gboolean
purple_status_is_active(status)
	Purple::Status status

gboolean
purple_status_is_available(status)
	Purple::Status status

gboolean
purple_status_is_exclusive(status)
	Purple::Status status

gboolean
purple_status_is_independent(status)
	Purple::Status status

gboolean
purple_status_is_online(status)
	Purple::Status status

Purple::Status
purple_status_new(status_type, presence)
	Purple::StatusType status_type
	Purple::Presence presence

void
purple_status_set_active(status, active)
	Purple::Status status
	gboolean active

void
purple_status_set_attr_boolean(status, id, value)
	Purple::Status status
	const char *id
	gboolean value

void
purple_status_set_attr_string(status, id, value)
	Purple::Status status
	const char *id
	const char *value

MODULE = Purple::Status  PACKAGE = Purple::StatusType  PREFIX = purple_status_type_
PROTOTYPES: ENABLE

void
purple_status_type_add_attr(status_type, id, name, value)
	Purple::StatusType status_type
	const char *id
	const char *name
	Purple::Value value

void
purple_status_type_destroy(status_type)
	Purple::StatusType status_type

Purple::StatusAttr
purple_status_type_get_attr(status_type, id)
	Purple::StatusType status_type
	const char *id

void
purple_status_type_get_attrs(status_type)
	Purple::StatusType status_type
PREINIT:
	GList *l;
PPCODE:
	for (l = purple_status_type_get_attrs(status_type); l != NULL; l = l->next) {
		XPUSHs(sv_2mortal(purple_perl_bless_object(l->data, "Purple::StatusAttr")));
	}

Purple::StatusType
purple_status_type_find_with_id(status_types, id)
	SV *status_types
	const char *id
PREINIT:
	GList *t_GL;
	int i, t_len;
CODE:
	t_GL = NULL;
	t_len = av_len((AV *)SvRV(status_types));

	for (i = 0; i <= t_len; i++) {
		t_GL = g_list_append(t_GL, SvPVutf8_nolen(*av_fetch((AV *)SvRV(status_types), i, 0)));
	}
	RETVAL = (PurpleStatusType *)purple_status_type_find_with_id(t_GL, id);
	g_list_free(t_GL);
OUTPUT:
	RETVAL

const char *
purple_status_type_get_id(status_type)
	Purple::StatusType status_type

const char *
purple_status_type_get_name(status_type)
	Purple::StatusType status_type

const char *
purple_status_type_get_primary_attr(status_type)
	Purple::StatusType status_type

Purple::StatusPrimitive
purple_status_type_get_primitive(status_type)
	Purple::StatusType status_type

gboolean
purple_status_type_is_available(status_type)
	Purple::StatusType status_type

gboolean
purple_status_type_is_exclusive(status_type)
	Purple::StatusType status_type

gboolean
purple_status_type_is_independent(status_type)
	Purple::StatusType status_type

gboolean
purple_status_type_is_saveable(status_type)
	Purple::StatusType status_type

gboolean
purple_status_type_is_user_settable(status_type)
	Purple::StatusType status_type

Purple::StatusType
purple_status_type_new(primitive, id, name, user_settable)
	Purple::StatusPrimitive primitive
	const char *id
	const char *name
	gboolean user_settable

Purple::StatusType
purple_status_type_new_full(primitive, id, name, saveable, user_settable, independent)
	Purple::StatusPrimitive primitive
	const char *id
	const char *name
	gboolean saveable
	gboolean user_settable
	gboolean independent

void
purple_status_type_set_primary_attr(status_type, attr_id)
	Purple::StatusType status_type
	const char *attr_id
