#include "module.h"

/* This breaks on faceprint's amd64 box
void *
purple_request_action_varg(handle, title, primary, secondary, default_action, user_data, action_count, actions)
	void * handle
	const char *title
	const char *primary
	const char *secondary
	unsigned int default_action
	void *user_data
	size_t action_count
	va_list actions
	*/


typedef struct {
	SV *ok_fun;
	SV *cancel_fun;
} PurplePerlRequestData;

static void
purple_perl_request_data_free(PurplePerlRequestData *ppr)
{
	if (ppr->ok_fun)
		SvREFCNT_dec(ppr->ok_fun);
	if (ppr->cancel_fun)
		SvREFCNT_dec(ppr->cancel_fun);
	g_free(ppr);
}

/********************************************************/
/*                                                      */
/* Callback function that calls a perl subroutine       */
/*                                                      */
/* The void * field data is being used as a way to hide */
/* the perl sub's name in a PurplePerlRequestData         */
/*                                                      */
/********************************************************/
static void
purple_perl_request_ok_cb(void * data, PurpleRequestFields *fields)
{
	PurplePerlRequestData *gpr = (PurplePerlRequestData *)data;

	dSP;
	ENTER;
	SAVETMPS;
	PUSHMARK(sp);

	XPUSHs(sv_2mortal(purple_perl_bless_object(fields, "Purple::Request::Fields")));
	PUTBACK;
	call_sv(gpr->ok_fun, G_EVAL | G_SCALAR);
	SPAGAIN;

	PUTBACK;
	FREETMPS;
	LEAVE;

	purple_perl_request_data_free(gpr);
}

static void
purple_perl_request_cancel_cb(void * data, PurpleRequestFields *fields)
{
	PurplePerlRequestData *gpr = (PurplePerlRequestData *)data;

	dSP;
	ENTER;
	SAVETMPS;
	PUSHMARK(sp);

	XPUSHs(sv_2mortal(purple_perl_bless_object(fields, "Purple::Request::Fields")));
	PUTBACK;
	call_sv(gpr->cancel_fun, G_EVAL | G_SCALAR);
	SPAGAIN;

	PUTBACK;
	FREETMPS;
	LEAVE;

	purple_perl_request_data_free(gpr);
}

MODULE = Purple::Request  PACKAGE = Purple::Request  PREFIX = purple_request_
PROTOTYPES: ENABLE

BOOT:
{
	HV *request_stash = gv_stashpv("Purple::RequestType", 1);
	HV *request_field_stash = gv_stashpv("Purple::RequestFieldType", 1);

	static const constiv *civ, request_const_iv[] = {
#define const_iv(name) {#name, (IV)PURPLE_REQUEST_##name}
		const_iv(INPUT),
		const_iv(CHOICE),
		const_iv(ACTION),
		const_iv(FIELDS),
		const_iv(FILE),
		const_iv(FOLDER),
	};
	static const constiv request_field_const_iv[] = {
#undef const_iv
#define const_iv(name) {#name, (IV)PURPLE_REQUEST_FIELD_##name}
		const_iv(NONE),
		const_iv(STRING),
		const_iv(INTEGER),
		const_iv(BOOLEAN),
		const_iv(CHOICE),
		const_iv(LIST),
		const_iv(LABEL),
		const_iv(IMAGE),
		const_iv(ACCOUNT),
	};

	for (civ = request_const_iv + sizeof(request_const_iv) / sizeof(request_const_iv[0]); civ-- > request_const_iv; )
		newCONSTSUB(request_stash, (char *)civ->name, newSViv(civ->iv));

	for (civ = request_field_const_iv + sizeof(request_field_const_iv) / sizeof(request_field_const_iv[0]); civ-- > request_field_const_iv; )
		newCONSTSUB(request_field_stash, (char *)civ->name, newSViv(civ->iv));
}

void *
purple_request_input(handle, title, primary, secondary, default_value, multiline, masked, hint, ok_text, ok_cb, cancel_text, cancel_cb)
	Purple::Plugin handle
	const char * title
	const char * primary
	const char * secondary
	const char * default_value
	gboolean multiline
	gboolean masked
	gchar * hint
	const char * ok_text
	SV * ok_cb
	const char * cancel_text
	SV * cancel_cb
CODE:
	PurplePerlRequestData *gpr;
	char *basename;

	basename = g_path_get_basename(handle->path);
	purple_perl_normalize_script_name(basename);
	gpr = g_new(PurplePerlRequestData, 1);
	gpr->ok_fun = purple_perl_sv_from_fun(handle, ok_cb);
	gpr->cancel_fun = purple_perl_sv_from_fun(handle, cancel_cb);
	g_free(basename);

	RETVAL = purple_request_input(handle, title, primary, secondary, default_value, multiline, masked, hint, ok_text, G_CALLBACK(purple_perl_request_ok_cb), cancel_text, G_CALLBACK(purple_perl_request_cancel_cb), NULL, NULL, NULL, gpr);
OUTPUT:
	RETVAL

void *
purple_request_file(handle, title, filename, savedialog, ok_cb, cancel_cb)
	Purple::Plugin handle
	const char * title
	const char * filename
	gboolean savedialog
	SV * ok_cb
	SV * cancel_cb
CODE:
	PurplePerlRequestData *gpr;
	char *basename;

	basename = g_path_get_basename(handle->path);
	purple_perl_normalize_script_name(basename);
	gpr = g_new(PurplePerlRequestData, 1);
	gpr->ok_fun = purple_perl_sv_from_fun(handle, ok_cb);
	gpr->cancel_fun = purple_perl_sv_from_fun(handle, cancel_cb);
	g_free(basename);

	RETVAL = purple_request_file(handle, title, filename, savedialog, G_CALLBACK(purple_perl_request_ok_cb), G_CALLBACK(purple_perl_request_cancel_cb), NULL, NULL, NULL, gpr);
OUTPUT:
	RETVAL

void *
purple_request_fields(handle, title, primary, secondary, fields, ok_text, ok_cb, cancel_text, cancel_cb)
	Purple::Plugin handle
	const char * title
	const char * primary
	const char * secondary
	Purple::Request::Fields fields
	const char * ok_text
	SV * ok_cb
	const char * cancel_text
	SV * cancel_cb
CODE:
	PurplePerlRequestData *gpr;
	char *basename;

	basename = g_path_get_basename(handle->path);
	purple_perl_normalize_script_name(basename);
	gpr = g_new(PurplePerlRequestData, 1);
	gpr->ok_fun = purple_perl_sv_from_fun(handle, ok_cb);
	gpr->cancel_fun = purple_perl_sv_from_fun(handle, cancel_cb);
	g_free(basename);

	RETVAL = purple_request_fields(handle, title, primary, secondary, fields, ok_text, G_CALLBACK(purple_perl_request_ok_cb), cancel_text, G_CALLBACK(purple_perl_request_cancel_cb), NULL, NULL, NULL, gpr);
OUTPUT:
	RETVAL

void
purple_request_close(type, uihandle)
	Purple::RequestType type
	void * uihandle

void
purple_request_close_with_handle(handle)
	void * handle


MODULE = Purple::Request  PACKAGE = Purple::Request::Field  PREFIX = purple_request_field_
PROTOTYPES: ENABLE

Purple::Request::Field
purple_request_field_account_new(class, id, text, account = NULL)
	const char *id
	const char *text
	Purple::Account account
	C_ARGS: id, text, account

Purple::Account
purple_request_field_account_get_default_value(field)
	Purple::Request::Field field

IV
purple_request_field_account_get_filter(field)
	Purple::Request::Field field
CODE:
	RETVAL = PTR2IV(purple_request_field_account_get_filter(field));
OUTPUT:
	RETVAL

gboolean
purple_request_field_account_get_show_all(field)
	Purple::Request::Field field

Purple::Account
purple_request_field_account_get_value(field)
	Purple::Request::Field field

void
purple_request_field_account_set_default_value(field, default_value)
	Purple::Request::Field field
	Purple::Account default_value

void
purple_request_field_account_set_show_all(field, show_all)
	Purple::Request::Field field
	gboolean show_all

void
purple_request_field_account_set_value(field, value)
	Purple::Request::Field field
	Purple::Account value

MODULE = Purple::Request  PACKAGE = Purple::Request::Field  PREFIX = purple_request_field_
PROTOTYPES: ENABLE

Purple::Request::Field
purple_request_field_bool_new(class, id, text, default_value = TRUE)
	const char *id
	const char *text
	gboolean default_value
	C_ARGS: id, text, default_value

gboolean
purple_request_field_bool_get_default_value(field)
	Purple::Request::Field field

gboolean
purple_request_field_bool_get_value(field)
	Purple::Request::Field field

void
purple_request_field_bool_set_default_value(field, default_value)
	Purple::Request::Field field
	gboolean default_value

void
purple_request_field_bool_set_value(field, value)
	Purple::Request::Field field
	gboolean value

MODULE = Purple::Request  PACKAGE = Purple::Request::Field  PREFIX = purple_request_field_
PROTOTYPES: ENABLE

Purple::Request::Field
purple_request_field_choice_new(class, id, text, default_value = 0)
	const char *id
	const char *text
	int default_value
	C_ARGS: id, text, default_value

void
purple_request_field_choice_add(field, label)
	Purple::Request::Field field
	const char *label

int
purple_request_field_choice_get_default_value(field)
	Purple::Request::Field field

void
purple_request_field_choice_get_labels(field)
	Purple::Request::Field field
PREINIT:
	GList *l;
PPCODE:
	for (l = purple_request_field_choice_get_labels(field); l != NULL; l = l->next) {
		XPUSHs(sv_2mortal(newSVpv(l->data, 0)));
	}

int
purple_request_field_choice_get_value(field)
	Purple::Request::Field field

void
purple_request_field_choice_set_default_value(field, default_value)
	Purple::Request::Field field
	int default_value

void
purple_request_field_choice_set_value(field, value)
	Purple::Request::Field field
	int value

MODULE = Purple::Request  PACKAGE = Purple::Request::Field  PREFIX = purple_request_field_
PROTOTYPES: ENABLE

Purple::Request::Field
purple_request_field_int_new(clas, id, text, default_value = 0)
	const char *id
	const char *text
	int default_value
	C_ARGS: id, text, default_value

int
purple_request_field_int_get_default_value(field)
	Purple::Request::Field field

int
purple_request_field_int_get_value(field)
	Purple::Request::Field field

void
purple_request_field_int_set_default_value(field, default_value)
	Purple::Request::Field field
	int default_value

void
purple_request_field_int_set_value(field, value)
	Purple::Request::Field field
	int value

gboolean
purple_request_field_is_required(field)
	Purple::Request::Field field

MODULE = Purple::Request  PACKAGE = Purple::Request::Field  PREFIX = purple_request_field_
PROTOTYPES: ENABLE

Purple::Request::Field
purple_request_field_label_new(class, id, text)
	const char *id
	const char *text
	C_ARGS: id, text

MODULE = Purple::Request  PACKAGE = Purple::Request::Field  PREFIX = purple_request_field_
PROTOTYPES: ENABLE

Purple::Request::Field
purple_request_field_list_new(class, id, text)
	const char *id
	const char *text
	C_ARGS: id, text

void
purple_request_field_list_add(field, item, data)
	Purple::Request::Field field
	const char *item
	void * data

void
purple_request_field_list_add_icon(field, item, icon_path, data)
	Purple::Request::Field field
	const char *item
	const char *icon_path
	void * data

void
purple_request_field_list_add_selected(field, item)
	Purple::Request::Field field
	const char *item

void
purple_request_field_list_clear_selected(field)
	Purple::Request::Field field

void *
purple_request_field_list_get_data(field, text)
	Purple::Request::Field field
	const char *text

void
purple_request_field_list_get_items(field)
	Purple::Request::Field field
PREINIT:
	GList *l;
PPCODE:
	for (l = purple_request_field_list_get_items(field); l != NULL; l = l->next) {
		XPUSHs(sv_2mortal(newSVpv(l->data, 0)));
	}

gboolean
purple_request_field_list_get_multi_select(field)
	Purple::Request::Field field

void
purple_request_field_list_get_selected(field)
	Purple::Request::Field field
PREINIT:
	GList *l;
PPCODE:
	for (l = purple_request_field_list_get_selected(field); l != NULL; l = l->next) {
		XPUSHs(sv_2mortal(newSVpv(l->data, 0)));
	}

gboolean
purple_request_field_list_is_selected(field, item)
	Purple::Request::Field field
	const char *item

void
purple_request_field_list_set_multi_select(field, multi_select)
	Purple::Request::Field field
	gboolean multi_select

MODULE = Purple::Request  PACKAGE = Purple::Request::Field  PREFIX = purple_request_field_
PROTOTYPES: ENABLE

Purple::Request::Field
purple_request_field_new(class, id, text, type)
	const char *id
	const char *text
	Purple::RequestFieldType type
	C_ARGS: id, text, type

void
purple_request_field_set_label(field, label)
	Purple::Request::Field field
	const char *label

void
purple_request_field_set_required(field, required)
	Purple::Request::Field field
	gboolean required

void
purple_request_field_set_type_hint(field, type_hint)
	Purple::Request::Field field
	const char *type_hint

void
purple_request_field_set_visible(field, visible)
	Purple::Request::Field field
	gboolean visible

MODULE = Purple::Request  PACKAGE = Purple::Request::Field  PREFIX = purple_request_field_
PROTOTYPES: ENABLE

Purple::Request::Field
purple_request_field_string_new(class, id, text, default_value, multiline)
	const char *id
	const char *text
	const char *default_value
	gboolean multiline
	C_ARGS: id, text, default_value, multiline

const char *
purple_request_field_string_get_default_value(field)
	Purple::Request::Field field

const char *
purple_request_field_string_get_value(field)
	Purple::Request::Field field

gboolean
purple_request_field_string_is_editable(field)
	Purple::Request::Field field

gboolean
purple_request_field_string_is_masked(field)
	Purple::Request::Field field

gboolean
purple_request_field_string_is_multiline(field)
	Purple::Request::Field field

void
purple_request_field_string_set_default_value(field, default_value)
	Purple::Request::Field field
	const char *default_value

void
purple_request_field_string_set_editable(field, editable)
	Purple::Request::Field field
	gboolean editable

void
purple_request_field_string_set_masked(field, masked)
	Purple::Request::Field field
	gboolean masked

void
purple_request_field_string_set_value(field, value)
	Purple::Request::Field field
	const char *value

MODULE = Purple::Request  PACKAGE = Purple::Request::Field::Group  PREFIX = purple_request_field_group_
PROTOTYPES: ENABLE

void
purple_request_field_group_add_field(group, field)
	Purple::Request::Field::Group group
	Purple::Request::Field field

void
purple_request_field_group_destroy(group)
	Purple::Request::Field::Group group

void
purple_request_field_group_get_fields(group)
	Purple::Request::Field::Group group
PREINIT:
	GList *l;
PPCODE:
	for (l = purple_request_field_group_get_fields(group); l != NULL; l = l->next) {
		XPUSHs(sv_2mortal(purple_perl_bless_object(l->data, "Purple::Request::Field")));
	}

const char *
purple_request_field_group_get_title(group)
	Purple::Request::Field::Group group

Purple::Request::Field::Group
purple_request_field_group_new(class, title)
	const char *title
	C_ARGS: title

MODULE = Purple::Request  PACKAGE = Purple::Request::Field  PREFIX = purple_request_field_
PROTOTYPES: ENABLE

void
purple_request_field_destroy(field)
	Purple::Request::Field field

const char *
purple_request_field_get_id(field)
	Purple::Request::Field field

const char *
purple_request_field_get_label(field)
	Purple::Request::Field field

Purple::RequestFieldType
purple_request_field_get_type(field)
	Purple::Request::Field field

const char *
purple_request_field_get_type_hint(field)
	Purple::Request::Field field

gboolean
purple_request_field_is_visible(field)
	Purple::Request::Field field

MODULE = Purple::Request  PACKAGE = Purple::Request::Fields  PREFIX = purple_request_fields_
PROTOTYPES: ENABLE

Purple::Request::Fields
purple_request_fields_new(class)
	C_ARGS: /* void */

void
purple_request_fields_add_group(fields, group)
	Purple::Request::Fields fields
	Purple::Request::Field::Group group

gboolean
purple_request_fields_all_required_filled(fields)
	Purple::Request::Fields fields

void
purple_request_fields_destroy(fields)
	Purple::Request::Fields fields

gboolean
purple_request_fields_exists(fields, id)
	Purple::Request::Fields fields
	const char *id

Purple::Account
purple_request_fields_get_account(fields, id)
	Purple::Request::Fields fields
	const char *id

gboolean
purple_request_fields_get_bool(fields, id)
	Purple::Request::Fields fields
	const char *id

int
purple_request_fields_get_choice(fields, id)
	Purple::Request::Fields fields
	const char *id

Purple::Request::Field
purple_request_fields_get_field(fields, id)
	Purple::Request::Fields fields
	const char *id

void
purple_request_fields_get_groups(fields)
	Purple::Request::Fields fields
PREINIT:
	GList *l;
PPCODE:
	for (l = purple_request_fields_get_groups(fields); l != NULL; l = l->next) {
		XPUSHs(sv_2mortal(purple_perl_bless_object(l->data, "Purple::Request::Field::Group")));
	}

int
purple_request_fields_get_integer(fields, id)
	Purple::Request::Fields fields
	const char *id

void
purple_request_fields_get_required(fields)
	Purple::Request::Fields fields
PREINIT:
	GList *l;
PPCODE:
	for (l = purple_request_fields_get_required(fields); l != NULL; l = l->next) {
		XPUSHs(sv_2mortal(purple_perl_bless_object(l->data, "Purple::Request::Field")));
	}

const char *
purple_request_fields_get_string(fields, id)
	Purple::Request::Fields fields
	const char *id

gboolean
purple_request_fields_is_field_required(fields, id)
	Purple::Request::Fields fields
	const char *id
