#include "module.h"

MODULE = Purple::Account  PACKAGE = Purple::Account  PREFIX = purple_account_
PROTOTYPES: ENABLE

Purple::Presence
purple_account_get_presence(account)
    Purple::Account account

Purple::Account
purple_account_new(class, username, protocol_id)
    const char * username
    const char * protocol_id
    C_ARGS:
    username, protocol_id

void
purple_account_destroy(account)
    Purple::Account account

void
purple_account_connect(account)
    Purple::Account account

void
purple_account_register(account)
    Purple::Account account

void
purple_account_disconnect(account)
    Purple::Account account

void
purple_account_request_change_password(account)
    Purple::Account account

void
purple_account_request_change_user_info(account)
    Purple::Account account

void
purple_account_set_username(account, username)
    Purple::Account account
    const char * username

void
purple_account_set_password(account, password)
    Purple::Account account
    const char * password

void
purple_account_set_alias(account, alias)
    Purple::Account account
    const char * alias

void
purple_account_set_user_info(account, user_info)
    Purple::Account account
    const char *user_info

void
purple_account_set_buddy_icon_path(account, icon)
    Purple::Account account
    const char *icon

void
purple_account_set_connection(account, gc)
    Purple::Account account
    Purple::Connection gc

void
purple_account_set_remember_password(account, value)
    Purple::Account account
    gboolean value

void
purple_account_set_check_mail(account, value)
    Purple::Account account
    gboolean value

void purple_account_set_enabled(account, ui, value)
    Purple::Account account
    const char *ui
    gboolean value

void
purple_account_set_proxy_info(account, info)
    Purple::Account account
    Purple::ProxyInfo info

void
purple_account_set_status(account, status_id, active)
    Purple::Account account
    const char *status_id
    gboolean active
CODE:
    purple_account_set_status(account, status_id, active, NULL);

void
purple_account_set_status_types(account, status_types)
    Purple::Account account
    SV * status_types
PREINIT:
    GList *t_GL;
    int i, t_len;
PPCODE:
    t_GL = NULL;
    t_len = av_len((AV *)SvRV(status_types));

    for (i = 0; i <= t_len; i++)
        t_GL = g_list_append(t_GL, SvPVutf8_nolen(*av_fetch((AV *)SvRV(status_types), i, 0)));

    purple_account_set_status_types(account, t_GL);

void
purple_account_clear_settings(account)
    Purple::Account account

void
purple_account_set_int(account, name, value)
    Purple::Account account
    const char *name
    int value

gboolean
purple_account_is_connected(account)
    Purple::Account account

const char *
purple_account_get_username(account)
    Purple::Account account

const char *
purple_account_get_password(account)
    Purple::Account account

const char *
purple_account_get_alias(account)
    Purple::Account account

const char *
purple_account_get_user_info(account)
    Purple::Account account

const char *
purple_account_get_buddy_icon_path(account)
    Purple::Account account

const char *
purple_account_get_protocol_id(account)
    Purple::Account account

const char *
purple_account_get_protocol_name(account)
    Purple::Account account

Purple::Connection
purple_account_get_connection(account)
    Purple::Account account

gboolean
purple_account_get_remember_password(account)
    Purple::Account account

gboolean
purple_account_get_check_mail(account)
    Purple::Account account

gboolean
purple_account_get_enabled(account, ui)
    Purple::Account account
    const char *ui

Purple::ProxyInfo
purple_account_get_proxy_info(account)
    Purple::Account account

Purple::Status
purple_account_get_active_status(account)
    Purple::Account account

void
purple_account_get_status_types(account)
    Purple::Account account
PREINIT:
    GList *l;
PPCODE:
    for (l = purple_account_get_status_types(account); l != NULL; l = l->next) {
        XPUSHs(sv_2mortal(purple_perl_bless_object(l->data, "Purple::StatusType")));
    }

Purple::Log
purple_account_get_log(account, create)
    Purple::Account account
    gboolean create

void
purple_account_destroy_log(account)
    Purple::Account account

void
purple_account_add_buddies(account, list)
    Purple::Account account
    SV * list
PREINIT:
    GList *t_GL;
    int i, t_len;
PPCODE:
    t_GL = NULL;
    t_len = av_len((AV *)SvRV(list));

    for (i = 0; i <= t_len; i++)
        t_GL = g_list_append(t_GL, SvPVutf8_nolen(*av_fetch((AV *)SvRV(list), i, 0)));

    purple_account_add_buddies(account, t_GL);
    g_list_free(t_GL);

void
purple_account_add_buddy(account, buddy)
    Purple::Account account
    Purple::BuddyList::Buddy  buddy

void
purple_account_change_password(account, a, b)
    Purple::Account account
    const char *    a
    const char *    b

void
purple_account_remove_buddies(account, A, B)
    Purple::Account account
    SV * A
    SV * B
PREINIT:
    GList *t_GL1, *t_GL2;
    int i, t_len;
PPCODE:
    t_GL1 = NULL;
    t_len = av_len((AV *)SvRV(A));

    for (i = 0; i <= t_len; i++)
        t_GL1 = g_list_append(t_GL1, SvPVutf8_nolen(*av_fetch((AV *)SvRV(A), i, 0)));

    t_GL2 = NULL;
    t_len = av_len((AV *)SvRV(B));

    for (i = 0; i <= t_len; i++)
        t_GL2 = g_list_append(t_GL2, SvPVutf8_nolen(*av_fetch((AV *)SvRV(B), i, 0)));

    purple_account_remove_buddies(account, t_GL1, t_GL2);
    g_list_free(t_GL1);
    g_list_free(t_GL2);

void
purple_account_remove_buddy(account, buddy, group)
    Purple::Account account
    Purple::BuddyList::Buddy buddy
    Purple::BuddyList::Group group

void
purple_account_remove_group(account, group)
    Purple::Account account
    Purple::BuddyList::Group group

MODULE = Purple::Account  PACKAGE = Purple::Accounts  PREFIX = purple_accounts_
PROTOTYPES: ENABLE

void
purple_accounts_add(account)
    Purple::Account account

void
purple_accounts_remove(account)
    Purple::Account account

void
purple_accounts_delete(account)
    Purple::Account account

void
purple_accounts_reorder(account, new_index)
    Purple::Account account
    size_t new_index

void
purple_accounts_get_all()
PREINIT:
    GList *l;
PPCODE:
    for (l = purple_accounts_get_all(); l != NULL; l = l->next) {
        XPUSHs(sv_2mortal(purple_perl_bless_object(l->data, "Purple::Account")));
    }

void
purple_accounts_get_all_active()
PREINIT:
    GList *list, *iter;
PPCODE:
    list = purple_accounts_get_all_active();
    for (iter = list; iter != NULL; iter = iter->next) {
        XPUSHs(sv_2mortal(purple_perl_bless_object(iter->data, "Purple::Account")));
    }
    g_list_free(list);

void
purple_accounts_restore_current_statuses()

Purple::Account
purple_accounts_find(name, protocol)
    const char * name
    const char * protocol

Purple::Handle
purple_accounts_get_handle()
