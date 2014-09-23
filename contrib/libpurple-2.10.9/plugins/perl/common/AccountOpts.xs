#include "module.h"

MODULE = Purple::Account::Option  PACKAGE = Purple::Account::Option  PREFIX = purple_account_option_
PROTOTYPES: ENABLE

void
purple_account_option_destroy(option)
	Purple::Account::Option option

const char *
purple_account_option_get_default_string(option)
	Purple::Account::Option option

void
purple_account_option_add_list_item(option, key, value)
	Purple::Account::Option option
	const char * key
	const char * value

void
purple_account_option_set_default_string(option, value);
	Purple::Account::Option option
	const char * value

void
purple_account_option_set_default_int(option, value);
	Purple::Account::Option option
	int value

void
purple_account_option_set_default_bool(option, value);
	Purple::Account::Option option
	gboolean value

Purple::Account::Option
purple_account_option_list_new(class, text, pref_name, values)
	const char * text
	const char * pref_name
	SV * values
PREINIT:
	GList *t_GL;
	int i, t_len;
CODE:
	t_GL = NULL;
	t_len = av_len((AV *)SvRV(values));

	for (i = 0; i <= t_len; i++)
		t_GL = g_list_append(t_GL, SvPVutf8_nolen(*av_fetch((AV *)SvRV(values), i, 0)));

	RETVAL  = purple_account_option_list_new(text, pref_name, t_GL);
OUTPUT:
	RETVAL

Purple::Account::Option
purple_account_option_string_new(class, text, pref_name, default_value)
	const char * text
	const char * pref_name
	const char * default_value
    C_ARGS:
	text, pref_name, default_value

Purple::Account::Option
purple_account_option_int_new(class, text, pref_name, default_value)
	const char * text
	const char * pref_name
	gboolean default_value
    C_ARGS:
	text, pref_name, default_value

Purple::Account::Option
purple_account_option_bool_new(class, text, pref_name, default_value)
	const char * text
	const char * pref_name
	gboolean default_value
    C_ARGS:
	text, pref_name, default_value

Purple::Account::Option
purple_account_option_new(class, type, text, pref_name)
	Purple::PrefType type
	const char * text
	const char * pref_name
    C_ARGS:
	type, text, pref_name

void
purple_account_option_get_list(option)
	Purple::Account::Option option
PREINIT:
	GList *l;
PPCODE:
	for (l = purple_account_option_get_list(option); l != NULL; l = l->next) {
		/* XXX These are actually PurpleKeyValuePairs but we don't have a
		 * type for that and even if we did I don't think there's
		 * anything perl could do with them, so I'm just going to
		 * leave this as a Purple::ListEntry for now. */
		XPUSHs(sv_2mortal(purple_perl_bless_object(l->data, "Purple::ListEntry")));
	}

Purple::PrefType
purple_account_option_get_type(option)
	Purple::Account::Option option

gboolean
purple_account_option_get_masked(option)
	Purple::Account::Option option

int
purple_account_option_get_default_int(option)
	Purple::Account::Option option;

gboolean
purple_account_option_get_default_bool(option)
	Purple::Account::Option option;

const char *
purple_account_option_get_setting(option)
	Purple::Account::Option option

const char *
purple_account_option_get_text(option)
	Purple::Account::Option option

void
purple_account_option_set_list(option, values)
	Purple::Account::Option option
	SV * values
PREINIT:
	GList *t_GL;
	int i, t_len;
PPCODE:
	t_GL = NULL;
	t_len = av_len((AV *)SvRV(values));

	for (i = 0; i <= t_len; i++)
		t_GL = g_list_append(t_GL, SvPVutf8_nolen(*av_fetch((AV *)SvRV(values), i, 0)));

	purple_account_option_set_list(option, t_GL);

void
purple_account_option_set_masked(option, masked)
	Purple::Account::Option option
	gboolean masked

MODULE = Purple::Account::Option  PACKAGE = Purple::Account::UserSplit  PREFIX = purple_account_user_split_
PROTOTYPES: ENABLE

Purple::Account::UserSplit
purple_account_user_split_new(class, text, default_value, sep)
	const char * text
	const char * default_value
	char sep
    C_ARGS:
	text, default_value, sep

char
purple_account_user_split_get_separator(split)
	Purple::Account::UserSplit split

const char *
purple_account_user_split_get_text(split)
	Purple::Account::UserSplit split

void
purple_account_user_split_destroy(split)
	Purple::Account::UserSplit split
