#undef PURPLE_DISABLE_DEPRECATED
#include "module.h"
#include "../perl-handlers.h"

static void
chat_components_foreach(gpointer key, gpointer value, gpointer user_data)
{
	HV *hv = user_data;
	hv_store(hv, key, strlen(key), newSVpv(value, 0), 0);
}

MODULE = Purple::BuddyList  PACKAGE = Purple  PREFIX = purple_
PROTOTYPES: ENABLE

BOOT:
{
	HV *stash = gv_stashpv("Purple::BuddyList::Node", 1);

	static const constiv *civ, const_iv[] = {
#define const_iv(name) {#name, (IV)PURPLE_BLIST_##name##_NODE}
		const_iv(GROUP),
		const_iv(CONTACT),
		const_iv(BUDDY),
		const_iv(CHAT),
		const_iv(OTHER),
#undef const_iv
#define const_iv(name) {#name, (IV)PURPLE_BLIST_NODE_FLAG_##name}
		const_iv(NO_SAVE),
	};

	for (civ = const_iv + sizeof(const_iv) / sizeof(const_iv[0]); civ-- > const_iv; )
		newCONSTSUB(stash, (char *)civ->name, newSViv(civ->iv));
}

Purple::BuddyList
purple_get_blist()

void
purple_set_blist(blist)
	Purple::BuddyList blist

MODULE = Purple::BuddyList  PACKAGE = Purple::Find  PREFIX = purple_find_
PROTOTYPES: ENABLE

Purple::BuddyList::Buddy
purple_find_buddy(account, name)
	Purple::Account account
	const char * name

void
purple_find_buddies(account, name)
	Purple::Account account
	const char * name
PREINIT:
	GSList *l, *ll;
PPCODE:
	ll = purple_find_buddies(account, name);
	for (l = ll; l != NULL; l = l->next) {
		XPUSHs(sv_2mortal(purple_perl_bless_object(l->data, "Purple::BuddyList::Buddy")));
	}
	g_slist_free(ll);

Purple::BuddyList::Group
purple_find_group(name)
	const char *name

MODULE = Purple::BuddyList  PACKAGE = Purple::Find  PREFIX = purple_
PROTOTYPES: ENABLE

gboolean
purple_group_on_account(group, account)
	Purple::BuddyList::Group  group
	Purple::Account account

MODULE = Purple::BuddyList  PACKAGE = Purple::BuddyList::Contact  PREFIX = purple_contact_
PROTOTYPES: ENABLE

Purple::BuddyList::Contact
purple_contact_new();

Purple::BuddyList::Buddy
purple_contact_get_priority_buddy(contact)
	Purple::BuddyList::Contact contact

void
purple_contact_set_alias(contact, alias)
	Purple::BuddyList::Contact contact
	const char * alias

const char *
purple_contact_get_alias(contact)
	Purple::BuddyList::Contact contact

gboolean
purple_contact_on_account(contact, account)
	Purple::BuddyList::Contact contact
	Purple::Account account

void
purple_contact_invalidate_priority_buddy(contact)
	Purple::BuddyList::Contact contact

MODULE = Purple::BuddyList  PACKAGE = Purple::BuddyList::Group  PREFIX = purple_group_
PROTOTYPES: ENABLE

Purple::BuddyList::Group
purple_group_new(name)
	const char *name

void
purple_group_get_accounts(group)
	Purple::BuddyList::Group  group
PREINIT:
	GSList *l, *ll;
PPCODE:
	ll = purple_group_get_accounts(group);
	for (l = ll; l != NULL; l = l->next) {
		XPUSHs(sv_2mortal(purple_perl_bless_object(l->data, "Purple::Account")));
	}
	g_slist_free(ll);

gboolean
purple_group_on_account(group, account)
	Purple::BuddyList::Group  group
	Purple::Account account

const char *
purple_group_get_name(group)
	Purple::BuddyList::Group group

MODULE = Purple::BuddyList  PACKAGE = Purple::BuddyList  PREFIX = purple_blist_
PROTOTYPES: ENABLE

void
purple_blist_add_contact(contact, group, node)
	Purple::BuddyList::Contact contact
	Purple::BuddyList::Group  group
	Purple::BuddyList::Node node

void
purple_blist_merge_contact(source, node)
	Purple::BuddyList::Contact source
	Purple::BuddyList::Node node

void
purple_blist_add_group(group, node)
	Purple::BuddyList::Group  group
	Purple::BuddyList::Node node

void
purple_blist_add_buddy(buddy, contact, group, node)
	Purple::BuddyList::Buddy buddy
	Purple::BuddyList::Contact contact
	Purple::BuddyList::Group  group
	Purple::BuddyList::Node node

void
purple_blist_remove_buddy(buddy)
	Purple::BuddyList::Buddy buddy

void
purple_blist_remove_contact(contact)
	Purple::BuddyList::Contact contact

void
purple_blist_remove_chat(chat)
	Purple::BuddyList::Chat chat

void
purple_blist_remove_group(group)
	Purple::BuddyList::Group  group

Purple::BuddyList::Chat
purple_blist_find_chat(account, name)
	Purple::Account account
	const char *name

void
purple_blist_add_chat(chat, group, node)
	Purple::BuddyList::Chat chat
	Purple::BuddyList::Group  group
	Purple::BuddyList::Node node

Purple::BuddyList
purple_blist_new()

void
purple_blist_show()

void
purple_blist_destroy();

void
purple_blist_set_visible(show)
	gboolean show

void
purple_blist_update_buddy_status(buddy, old_status)
	Purple::BuddyList::Buddy buddy
	Purple::Status old_status

void
purple_blist_update_buddy_icon(buddy)
	Purple::BuddyList::Buddy buddy

void
purple_blist_rename_buddy(buddy, name)
	Purple::BuddyList::Buddy buddy
	const char * name

void
purple_blist_alias_buddy(buddy, alias)
	Purple::BuddyList::Buddy buddy
	const char * alias

void
purple_blist_server_alias_buddy(buddy, alias)
	Purple::BuddyList::Buddy buddy
	const char * alias

void
purple_blist_alias_chat(chat, alias)
	Purple::BuddyList::Chat chat
	const char * alias

void
purple_blist_rename_group(group, name)
	Purple::BuddyList::Group  group
	const char * name

void
purple_blist_add_account(account)
	Purple::Account account

void
purple_blist_remove_account(account)
	Purple::Account account

int
purple_blist_get_group_size(group, offline)
	Purple::BuddyList::Group  group
	gboolean offline

int
purple_blist_get_group_online_count(group)
	Purple::BuddyList::Group  group

void
purple_blist_load()

void
purple_blist_schedule_save()

void
purple_blist_request_add_group()

Purple::Handle
purple_blist_get_handle()

Purple::BuddyList::Node
purple_blist_get_root()

MODULE = Purple::BuddyList  PACKAGE = Purple::BuddyList::Node  PREFIX = purple_blist_node_
PROTOTYPES: ENABLE

void
purple_blist_node_get_extended_menu(node)
	Purple::BuddyList::Node node
PREINIT:
	GList *l, *ll;
PPCODE:
	ll = purple_blist_node_get_extended_menu(node);
	for (l = ll; l != NULL; l = l->next) {
		XPUSHs(sv_2mortal(purple_perl_bless_object(l->data, "Purple::Menu::Action")));
	}
	/* We can free the list here but the script needs to free the
	 * Purple::Menu::Action 'objects' itself. */
	g_list_free(ll);

void
purple_blist_node_set_bool(node, key, value)
	Purple::BuddyList::Node node
	const char * key
	gboolean value

gboolean
purple_blist_node_get_bool(node, key)
	Purple::BuddyList::Node node
	const char * key

void
purple_blist_node_set_int(node, key, value)
	Purple::BuddyList::Node node
	const char * key
	int value

int
purple_blist_node_get_int(node, key)
	Purple::BuddyList::Node node
	const char * key

const char *
purple_blist_node_get_string(node, key)
	Purple::BuddyList::Node node
	const char * key

void
purple_blist_node_remove_setting(node, key)
	Purple::BuddyList::Node node
	const char * key

void
purple_blist_node_set_flags(node, flags)
	Purple::BuddyList::Node node
	Purple::BuddyList::NodeFlags flags

Purple::BuddyList::NodeFlags
purple_blist_node_get_flags(node)
	Purple::BuddyList::Node node

Purple::BuddyList::NodeType
purple_blist_node_get_type(node)
	Purple::BuddyList::Node node

Purple::BuddyList::Node
purple_blist_node_next(node, offline)
	Purple::BuddyList::Node node
	gboolean offline

MODULE = Purple::BuddyList  PACKAGE = Purple::BuddyList::Chat  PREFIX = purple_chat_
PROTOTYPES: ENABLE

Purple::BuddyList::Group
purple_chat_get_group(chat)
	Purple::BuddyList::Chat chat

const char *
purple_chat_get_name(chat)
	Purple::BuddyList::Chat chat

HV *
purple_chat_get_components(chat)
	Purple::BuddyList::Chat chat
INIT:
	HV * t_HV;
	GHashTable * t_GHash;
CODE:
	t_GHash = purple_chat_get_components(chat);
	RETVAL = t_HV = newHV();
	g_hash_table_foreach(t_GHash, chat_components_foreach, t_HV);
OUTPUT:
	RETVAL

Purple::BuddyList::Chat
purple_chat_new(account, alias, components)
	Purple::Account account
	const char * alias
	SV * components
INIT:
	HV * t_HV;
	HE * t_HE;
	SV * t_SV;
	GHashTable * t_GHash;
	I32 len;
	char *t_key, *t_value;
CODE:
	t_HV =  (HV *)SvRV(components);
	t_GHash = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

	for (t_HE = hv_iternext(t_HV); t_HE != NULL; t_HE = hv_iternext(t_HV) ) {
		t_key = hv_iterkey(t_HE, &len);
		t_SV = *hv_fetch(t_HV, t_key, len, 0);
		t_value = SvPVutf8_nolen(t_SV);

		g_hash_table_insert(t_GHash, g_strdup(t_key), g_strdup(t_value));
	}

	RETVAL = purple_chat_new(account, alias, t_GHash);
OUTPUT:
	RETVAL

MODULE = Purple::BuddyList  PACKAGE = Purple::BuddyList::Buddy  PREFIX = purple_buddy_
PROTOTYPES: ENABLE

Purple::BuddyList::Buddy
purple_buddy_new(account, name, alias)
	Purple::Account account
	const char *name
	const char *alias

const char *
purple_buddy_get_server_alias(buddy)
    Purple::BuddyList::Buddy buddy

void
purple_buddy_set_icon(buddy, icon)
	Purple::BuddyList::Buddy buddy
	Purple::Buddy::Icon icon

Purple::Account
purple_buddy_get_account(buddy)
	Purple::BuddyList::Buddy buddy

Purple::BuddyList::Group
purple_buddy_get_group(buddy)
	Purple::BuddyList::Buddy buddy

const char *
purple_buddy_get_name(buddy)
	Purple::BuddyList::Buddy buddy

Purple::Buddy::Icon
purple_buddy_get_icon(buddy)
	Purple::BuddyList::Buddy buddy

Purple::BuddyList::Contact
purple_buddy_get_contact(buddy)
	Purple::BuddyList::Buddy buddy

Purple::Presence
purple_buddy_get_presence(buddy)
	Purple::BuddyList::Buddy buddy

const char *
purple_buddy_get_alias_only(buddy)
	Purple::BuddyList::Buddy buddy

const char *
purple_buddy_get_contact_alias(buddy)
	Purple::BuddyList::Buddy buddy

const char *
purple_buddy_get_local_alias(buddy)
	Purple::BuddyList::Buddy buddy

const char *
purple_buddy_get_alias(buddy)
	Purple::BuddyList::Buddy buddy
