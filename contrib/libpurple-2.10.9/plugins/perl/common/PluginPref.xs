#include "module.h"

MODULE = Purple::PluginPref  PACKAGE = Purple::PluginPref::Frame  PREFIX = purple_plugin_pref_frame_
PROTOTYPES: ENABLE

BOOT:
{
	HV *string_format_stash = gv_stashpv("Purple::String::Format::Type", 1);
	HV *plugin_pref_stash = gv_stashpv("Purple::PluginPref::Type", 1);

	static const constiv *civ, string_format_const_iv[] = {
#define const_iv(name) {#name, (IV)PURPLE_STRING_FORMAT_TYPE_##name}
		const_iv(NONE),
		const_iv(MULTILINE),
		const_iv(HTML),
	};
	static const constiv plugin_pref_const_iv[] = {
#undef const_iv
#define const_iv(name) {#name, (IV)PURPLE_PLUGIN_PREF_##name}
		const_iv(NONE),
		const_iv(CHOICE),
		const_iv(INFO),
		const_iv(STRING_FORMAT),
	};

	for (civ = string_format_const_iv + sizeof(string_format_const_iv) / sizeof(string_format_const_iv[0]); civ-- > string_format_const_iv; )
		newCONSTSUB(string_format_stash, (char *)civ->name, newSViv(civ->iv));

	for (civ = plugin_pref_const_iv + sizeof(plugin_pref_const_iv) / sizeof(plugin_pref_const_iv[0]); civ-- > plugin_pref_const_iv; )
		newCONSTSUB(plugin_pref_stash, (char *)civ->name, newSViv(civ->iv));
}

void
purple_plugin_pref_frame_add(frame, pref)
	Purple::PluginPref::Frame frame
	Purple::PluginPref pref

void
purple_plugin_pref_frame_destroy(frame)
	Purple::PluginPref::Frame frame

void
purple_plugin_pref_frame_get_prefs(frame)
	Purple::PluginPref::Frame frame
PREINIT:
	GList *l;
PPCODE:
	for (l = purple_plugin_pref_frame_get_prefs(frame); l != NULL; l = l->next) {
		XPUSHs(sv_2mortal(purple_perl_bless_object(l->data, "Purple::PluginPref")));
	}

Purple::PluginPref::Frame
purple_plugin_pref_frame_new(class)
    C_ARGS: /* void */

MODULE = Purple::PluginPref  PACKAGE = Purple::PluginPref  PREFIX = purple_plugin_pref_
PROTOTYPES: ENABLE

void
purple_plugin_pref_add_choice(pref, label, choice)
	Purple::PluginPref pref
	const char *label
# Do the appropriate conversion based on the perl type specified.
# Currently only Strings and Ints will work.
	gpointer choice = (SvPOKp($arg) ? SvPVutf8_nolen($arg) : (SvIOKp($arg) ? GINT_TO_POINTER(SvIV($arg)) : NULL));

void
purple_plugin_pref_destroy(pref)
	Purple::PluginPref pref


void
purple_plugin_pref_get_bounds(pref, OUTLIST int min, OUTLIST int max)
	Purple::PluginPref pref
	# According to the perlxs manual page we shouldn't need to specify a
	# prototype here because "[p]arameters preceded by OUTLIST keyword do
	# not appear in the usage signature of the generated Perl function."
	# however that appears to only work for the usage error message and
	# not for the call to newXSproto. Since I can't find any documentation
	# for newXSproto at the moment I have no idea if that matters so
	# override the prototype here.
	PROTOTYPE: $

void
purple_plugin_pref_get_choices(pref)
	Purple::PluginPref pref
PREINIT:
	GList *l;
PPCODE:
	for (l = purple_plugin_pref_get_choices(pref); l != NULL; l = l->next) {
		XPUSHs(sv_2mortal(purple_perl_bless_object(l->data, "Purple::ListItem")));
	}

const char *
purple_plugin_pref_get_label(pref)
	Purple::PluginPref pref

gboolean
purple_plugin_pref_get_masked(pref)
	Purple::PluginPref pref

Purple::String::Format::Type
purple_plugin_pref_get_format_type(pref)
	Purple::PluginPref pref

unsigned int
purple_plugin_pref_get_max_length(pref)
	Purple::PluginPref pref

const char *
purple_plugin_pref_get_name(pref)
	Purple::PluginPref pref

Purple::PluginPrefType
purple_plugin_pref_get_type(pref)
	Purple::PluginPref pref

Purple::PluginPref
purple_plugin_pref_new(class)
    C_ARGS: /* void */

Purple::PluginPref
purple_plugin_pref_new_with_label(class, label)
	const char *label
    C_ARGS:
	label

Purple::PluginPref
purple_plugin_pref_new_with_name(class, name)
	const char *name
    C_ARGS:
	name

Purple::PluginPref
purple_plugin_pref_new_with_name_and_label(class, name, label)
	const char *name
	const char *label
    C_ARGS:
	name, label

void
purple_plugin_pref_set_bounds(pref, min, max)
	Purple::PluginPref pref
	int min
	int max

void
purple_plugin_pref_set_label(pref, label)
	Purple::PluginPref pref
	const char *label

void
purple_plugin_pref_set_masked(pref, mask)
	Purple::PluginPref pref
	gboolean mask

void
purple_plugin_pref_set_format_type(pref, format)
	Purple::PluginPref pref
	Purple::String::Format::Type format

void
purple_plugin_pref_set_max_length(pref, max_length)
	Purple::PluginPref pref
	unsigned int max_length

void
purple_plugin_pref_set_name(pref, name)
	Purple::PluginPref pref
	const char *name

void
purple_plugin_pref_set_type(pref, type)
	Purple::PluginPref pref
	Purple::PluginPrefType type
PREINIT:
	PurplePluginPrefType gpp_type;
CODE:
	gpp_type = PURPLE_PLUGIN_PREF_NONE;

	if (type == 1) {
		gpp_type = PURPLE_PLUGIN_PREF_CHOICE;
	} else if (type == 2) {
		gpp_type = PURPLE_PLUGIN_PREF_INFO;
	} else if (type == 3) {
		gpp_type = PURPLE_PLUGIN_PREF_STRING_FORMAT;
	}
	purple_plugin_pref_set_type(pref, gpp_type);
