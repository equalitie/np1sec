#include "module.h"

MODULE = Purple::Roomlist  PACKAGE = Purple::Roomlist  PREFIX = purple_roomlist_
PROTOTYPES: ENABLE

BOOT:
{
	HV *room_stash = gv_stashpv("Purple::Roomlist::Room::Type", 1);
	HV *field_stash = gv_stashpv("Purple::Roomlist::Field::Type", 1);

	static const constiv *civ, room_const_iv[] = {
#define const_iv(name) {#name, (IV)PURPLE_ROOMLIST_ROOMTYPE_##name}
		const_iv(CATEGORY),
		const_iv(ROOM),
	};
	static const constiv field_const_iv[] = {
#undef const_iv
#define const_iv(name) {#name, (IV)PURPLE_ROOMLIST_FIELD_##name}
		const_iv(BOOL),
		const_iv(INT),
		const_iv(STRING),
	};

	for (civ = room_const_iv + sizeof(room_const_iv) / sizeof(room_const_iv[0]); civ-- > room_const_iv; )
		newCONSTSUB(room_stash, (char *)civ->name, newSViv(civ->iv));

	for (civ = field_const_iv + sizeof(field_const_iv) / sizeof(field_const_iv[0]); civ-- > field_const_iv; )
		newCONSTSUB(field_stash, (char *)civ->name, newSViv(civ->iv));
}

void 
purple_roomlist_cancel_get_list(list)
	Purple::Roomlist list

void 
purple_roomlist_expand_category(list, category)
	Purple::Roomlist list
	Purple::Roomlist::Room category

gboolean 
purple_roomlist_get_in_progress(list)
	Purple::Roomlist list

Purple::Roomlist
purple_roomlist_get_list(gc)
	Purple::Connection gc

Purple::Roomlist
purple_roomlist_new(account)
	Purple::Account account

void 
purple_roomlist_ref(list)
	Purple::Roomlist list

void 
purple_roomlist_room_add(list, room)
	Purple::Roomlist list
	Purple::Roomlist::Room room

void 
purple_roomlist_room_add_field(list, room, field)
	Purple::Roomlist list
	Purple::Roomlist::Room room
	gconstpointer field

void 
purple_roomlist_room_join(list, room)
	Purple::Roomlist list
	Purple::Roomlist::Room room

void 
purple_roomlist_set_fields(list, fields)
	Purple::Roomlist list
	SV *fields
PREINIT:
	GList *t_GL;
	int i, t_len;
PPCODE:
	t_GL = NULL;
	t_len = av_len((AV *)SvRV(fields));

	for (i = 0; i <= t_len; i++)
		t_GL = g_list_append(t_GL, SvPVutf8_nolen(*av_fetch((AV *)SvRV(fields), i, 0)));

	purple_roomlist_set_fields(list, t_GL);

void 
purple_roomlist_set_in_progress(list, in_progress)
	Purple::Roomlist list
	gboolean in_progress

void 
purple_roomlist_show_with_account(account)
	Purple::Account account

void 
purple_roomlist_unref(list)
	Purple::Roomlist list

