/**
 * @file tcl.c Purple Tcl plugin bindings
 *
 * purple
 *
 * Copyright (C) 2003 Ethan Blanton <eblanton@cs.purdue.edu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02111-1301  USA
 */

#include "config.h"

#include <tcl.h>

#ifdef HAVE_TK
#include <tk.h>
#endif

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

#include "tcl_glib.h"
#include "tcl_purple.h"

#include "internal.h"
#include "connection.h"
#include "plugin.h"
#include "signals.h"
#include "debug.h"
#include "util.h"
#include "version.h"

struct tcl_plugin_data {
	PurplePlugin *plugin;
	Tcl_Interp *interp;
};

PurpleStringref *PurpleTclRefAccount;
PurpleStringref *PurpleTclRefConnection;
PurpleStringref *PurpleTclRefConversation;
PurpleStringref *PurpleTclRefPointer;
PurpleStringref *PurpleTclRefPlugin;
PurpleStringref *PurpleTclRefPresence;
PurpleStringref *PurpleTclRefStatus;
PurpleStringref *PurpleTclRefStatusAttr;
PurpleStringref *PurpleTclRefStatusType;
PurpleStringref *PurpleTclRefXfer;
PurpleStringref *PurpleTclRefHandle;

static GHashTable *tcl_plugins = NULL;

PurplePlugin *_tcl_plugin;

static gboolean tcl_loaded = FALSE;

PurplePlugin *tcl_interp_get_plugin(Tcl_Interp *interp)
{
	struct tcl_plugin_data *data;

	if (tcl_plugins == NULL)
		return NULL;

	data = g_hash_table_lookup(tcl_plugins, (gpointer)interp);
	return data != NULL ? data->plugin : NULL;
}

static int tcl_init_interp(Tcl_Interp *interp)
{
	char *rcfile;
	char init[] =
		"namespace eval ::purple {\n"
		"	namespace export account buddy connection conversation\n"
		"	namespace export core debug notify prefs send_im\n"
		"	namespace export signal unload\n"
		"	namespace eval _callback { }\n"
		"\n"
		"	proc conv_send { account who text } {\n"
		"		set gc [purple::account connection $account]\n"
		"		set convo [purple::conversation new $account $who]\n"
		"		set myalias [purple::account alias $account]\n"
		"\n"
		"		if {![string length $myalias]} {\n"
		"			set myalias [purple::account username $account]\n"
		"		}\n"
		"\n"
		"		purple::send_im $gc $who $text\n"
		"		purple::conversation write $convo	send $myalias $text\n"
		"	}\n"
		"}\n"
		"\n"
		"proc bgerror { message } {\n"
		"	global errorInfo\n"
		"	purple::notify -error \"Tcl Error\" \"Tcl Error: $message\" \"$errorInfo\"\n"
		"}\n";

	if (Tcl_EvalEx(interp, init, -1, TCL_EVAL_GLOBAL) != TCL_OK) {
		return 1;
	}

	Tcl_SetVar(interp, "argc", "0", TCL_GLOBAL_ONLY);
	Tcl_SetVar(interp, "argv0", "purple", TCL_GLOBAL_ONLY);
	Tcl_SetVar(interp, "tcl_interactive", "0", TCL_GLOBAL_ONLY);
	rcfile = g_strdup_printf("%s" G_DIR_SEPARATOR_S "tclrc", purple_user_dir());
	Tcl_SetVar(interp, "tcl_rcFileName", rcfile, TCL_GLOBAL_ONLY);
	g_free(rcfile);

	Tcl_SetVar(interp, "::purple::version", VERSION, TCL_GLOBAL_ONLY);
	Tcl_SetVar(interp, "::purple::user_dir", purple_user_dir(), TCL_GLOBAL_ONLY);
#ifdef HAVE_TK
	Tcl_SetVar(interp, "::purple::tk_available", "1", TCL_GLOBAL_ONLY);
#else
	Tcl_SetVar(interp, "::purple::tk_available", "0", TCL_GLOBAL_ONLY);
#endif /* HAVE_TK */

	Tcl_CreateObjCommand(interp, "::purple::account", tcl_cmd_account, (ClientData)NULL, NULL);
	Tcl_CreateObjCommand(interp, "::purple::buddy", tcl_cmd_buddy, (ClientData)NULL, NULL);
	Tcl_CreateObjCommand(interp, "::purple::cmd", tcl_cmd_cmd, (ClientData)NULL, NULL);
	Tcl_CreateObjCommand(interp, "::purple::connection", tcl_cmd_connection, (ClientData)NULL, NULL);
	Tcl_CreateObjCommand(interp, "::purple::conversation", tcl_cmd_conversation, (ClientData)NULL, NULL);
	Tcl_CreateObjCommand(interp, "::purple::core", tcl_cmd_core, (ClientData)NULL, NULL);
	Tcl_CreateObjCommand(interp, "::purple::debug", tcl_cmd_debug, (ClientData)NULL, NULL);
	Tcl_CreateObjCommand(interp, "::purple::notify", tcl_cmd_notify, (ClientData)NULL, NULL);
	Tcl_CreateObjCommand(interp, "::purple::plugins", tcl_cmd_plugins, (ClientData)NULL, NULL);
	Tcl_CreateObjCommand(interp, "::purple::prefs", tcl_cmd_prefs, (ClientData)NULL, NULL);
	Tcl_CreateObjCommand(interp, "::purple::presence", tcl_cmd_presence, (ClientData)NULL, NULL);
	Tcl_CreateObjCommand(interp, "::purple::send_im", tcl_cmd_send_im, (ClientData)NULL, NULL);
	Tcl_CreateObjCommand(interp, "::purple::savedstatus", tcl_cmd_savedstatus, (ClientData)NULL, NULL);
	Tcl_CreateObjCommand(interp, "::purple::signal", tcl_cmd_signal, (ClientData)NULL, NULL);
	Tcl_CreateObjCommand(interp, "::purple::status", tcl_cmd_status, (ClientData)NULL, NULL);
	Tcl_CreateObjCommand(interp, "::purple::status_attr", tcl_cmd_status_attr, (ClientData)NULL, NULL);
	Tcl_CreateObjCommand(interp, "::purple::status_type", tcl_cmd_status_type, (ClientData)NULL, NULL);
	Tcl_CreateObjCommand(interp, "::purple::unload", tcl_cmd_unload, (ClientData)NULL, NULL);

	return 0;
}

static Tcl_Interp *tcl_create_interp(void)
{
	Tcl_Interp *interp;

	interp = Tcl_CreateInterp();
	if (Tcl_Init(interp) == TCL_ERROR) {
		Tcl_DeleteInterp(interp);
		return NULL;
	}

	if (tcl_init_interp(interp)) {
		Tcl_DeleteInterp(interp);
		return NULL;
	}
	Tcl_StaticPackage(interp, "purple", tcl_init_interp, NULL);

	return interp;
}

static gboolean tcl_probe_plugin(PurplePlugin *plugin)
{
	PurplePluginInfo *info;
	Tcl_Interp *interp;
	Tcl_Parse parse;
	Tcl_Obj *result, **listitems;
	char *buf;
	const char *next;
	int found = 0, err = 0, nelems;
	gsize len;
	gboolean status = FALSE;

	if (!g_file_get_contents(plugin->path, &buf, &len, NULL)) {
		purple_debug(PURPLE_DEBUG_INFO, "tcl", "Error opening plugin %s\n",
			     plugin->path);
		return FALSE;
	}

	if ((interp = tcl_create_interp()) == NULL) {
		return FALSE;
	}

	next = buf;
	do {
		if (Tcl_ParseCommand(interp, next, len, 0, &parse) == TCL_ERROR) {
			purple_debug(PURPLE_DEBUG_ERROR, "tcl", "parse error in %s: %s\n", plugin->path,
				   Tcl_GetString(Tcl_GetObjResult(interp)));
			err = 1;
			break;
		}
		if (parse.tokenPtr[0].type == TCL_TOKEN_SIMPLE_WORD
		    && !strncmp(parse.tokenPtr[0].start, "proc", parse.tokenPtr[0].size)) {
			if (!strncmp(parse.tokenPtr[2].start, "plugin_init", parse.tokenPtr[2].size)) {
				if (Tcl_EvalEx(interp, parse.commandStart, parse.commandSize, TCL_EVAL_GLOBAL) != TCL_OK) {
					Tcl_FreeParse(&parse);
					break;
				}
				found = 1;
				/* We'll continue parsing the file, just in case */
			}
		}
		len -= (parse.commandStart + parse.commandSize) - next;
		next = parse.commandStart + parse.commandSize;
		Tcl_FreeParse(&parse);
	} while (len);

	if (found && !err) {
		if (Tcl_EvalEx(interp, "plugin_init", -1, TCL_EVAL_GLOBAL) == TCL_OK) {
			result = Tcl_GetObjResult(interp);
			if (Tcl_ListObjGetElements(interp, result, &nelems, &listitems) == TCL_OK) {
				if ((nelems == 6) || (nelems == 7)) {
					info = g_new0(PurplePluginInfo, 1);

					info->magic = PURPLE_PLUGIN_MAGIC;
					info->major_version = PURPLE_MAJOR_VERSION;
					info->minor_version = PURPLE_MINOR_VERSION;
					info->type = PURPLE_PLUGIN_STANDARD;
					info->dependencies = g_list_append(info->dependencies, "core-tcl");

					info->name = g_strdup(Tcl_GetString(listitems[0]));
					info->version = g_strdup(Tcl_GetString(listitems[1]));
					info->summary = g_strdup(Tcl_GetString(listitems[2]));
					info->description = g_strdup(Tcl_GetString(listitems[3]));
					info->author = g_strdup(Tcl_GetString(listitems[4]));
					info->homepage = g_strdup(Tcl_GetString(listitems[5]));

					if (nelems == 6)
						info->id = g_strdup_printf("tcl-%s", Tcl_GetString(listitems[0]));
					else if (nelems == 7)
						info->id = g_strdup_printf("tcl-%s", Tcl_GetString(listitems[6]));

					plugin->info = info;

					if (purple_plugin_register(plugin))
						status = TRUE;
				}
			}
		}
	}

	Tcl_DeleteInterp(interp);
	g_free(buf);
	return status;
}

static gboolean tcl_load_plugin(PurplePlugin *plugin)
{
	struct tcl_plugin_data *data;
	Tcl_Interp *interp;
	Tcl_Obj *result;

	plugin->extra = NULL;

	if ((interp = tcl_create_interp()) == NULL) {
		purple_debug(PURPLE_DEBUG_ERROR, "tcl", "Could not initialize Tcl interpreter\n");
		return FALSE;
	}

	Tcl_SourceRCFile(interp);

	if (Tcl_EvalFile(interp, plugin->path) != TCL_OK) {
		result = Tcl_GetObjResult(interp);
		purple_debug(PURPLE_DEBUG_ERROR, "tcl",
		           "Error evaluating %s: %s\n", plugin->path,
		           Tcl_GetString(result));
		Tcl_DeleteInterp(interp);
		return FALSE;
	}

	Tcl_Preserve((ClientData)interp);

	data = g_new0(struct tcl_plugin_data, 1);
	data->plugin = plugin;
	data->interp = interp;
	plugin->extra = data;

	g_hash_table_insert(tcl_plugins, (gpointer)interp, (gpointer)data);

	return TRUE;
}

static gboolean tcl_unload_plugin(PurplePlugin *plugin)
{
	struct tcl_plugin_data *data;

	if (plugin == NULL)
		return TRUE;

	data = plugin->extra;

	if (data != NULL) {
		g_hash_table_remove(tcl_plugins, (gpointer)(data->interp));
		purple_signals_disconnect_by_handle(data->interp);
		tcl_cmd_cleanup(data->interp);
		tcl_signal_cleanup(data->interp);
		Tcl_Release((ClientData)data->interp);
		Tcl_DeleteInterp(data->interp);
		g_free(data);
	}

	return TRUE;
}

static void tcl_destroy_plugin(PurplePlugin *plugin)
{
	if (plugin->info != NULL) {
		g_free(plugin->info->id);
		g_free(plugin->info->name);
		g_free(plugin->info->version);
		g_free(plugin->info->description);
		g_free(plugin->info->author);
		g_free(plugin->info->homepage);
	}

	return;
}

static gboolean tcl_load(PurplePlugin *plugin)
{
	if(!tcl_loaded)
		return FALSE;
	tcl_glib_init();
	tcl_cmd_init();
	tcl_signal_init();
	purple_tcl_ref_init();

	PurpleTclRefAccount = purple_stringref_new("Account");
	PurpleTclRefConnection = purple_stringref_new("Connection");
	PurpleTclRefConversation = purple_stringref_new("Conversation");
	PurpleTclRefPointer = purple_stringref_new("Pointer");
	PurpleTclRefPlugin = purple_stringref_new("Plugin");
	PurpleTclRefPresence = purple_stringref_new("Presence");
	PurpleTclRefStatus = purple_stringref_new("Status");
	PurpleTclRefStatusAttr = purple_stringref_new("StatusAttr");
	PurpleTclRefStatusType = purple_stringref_new("StatusType");
	PurpleTclRefXfer = purple_stringref_new("Xfer");
	PurpleTclRefHandle = purple_stringref_new("Handle");

	tcl_plugins = g_hash_table_new(g_direct_hash, g_direct_equal);

#ifdef HAVE_TK
	Tcl_StaticPackage(NULL, "Tk", Tk_Init, Tk_SafeInit);
#endif /* HAVE_TK */

	return TRUE;
}

static gboolean tcl_unload(PurplePlugin *plugin)
{
	g_hash_table_destroy(tcl_plugins);
	tcl_plugins = NULL;

	purple_stringref_unref(PurpleTclRefAccount);
	purple_stringref_unref(PurpleTclRefConnection);
	purple_stringref_unref(PurpleTclRefConversation);
	purple_stringref_unref(PurpleTclRefPointer);
	purple_stringref_unref(PurpleTclRefPlugin);
	purple_stringref_unref(PurpleTclRefPresence);
	purple_stringref_unref(PurpleTclRefStatus);
	purple_stringref_unref(PurpleTclRefStatusAttr);
	purple_stringref_unref(PurpleTclRefStatusType);
	purple_stringref_unref(PurpleTclRefXfer);

	return TRUE;
}

static PurplePluginLoaderInfo tcl_loader_info =
{
	NULL,
	tcl_probe_plugin,
	tcl_load_plugin,
	tcl_unload_plugin,
	tcl_destroy_plugin,

	/* pidgin */
	NULL,
	NULL,
	NULL,
	NULL
};

static PurplePluginInfo tcl_info =
{
	PURPLE_PLUGIN_MAGIC,
	PURPLE_MAJOR_VERSION,
	PURPLE_MINOR_VERSION,
	PURPLE_PLUGIN_LOADER,
	NULL,
	0,
	NULL,
	PURPLE_PRIORITY_DEFAULT,
	"core-tcl",
	N_("Tcl Plugin Loader"),
	DISPLAY_VERSION,
	N_("Provides support for loading Tcl plugins"),
	N_("Provides support for loading Tcl plugins"),
	"Ethan Blanton <eblanton@cs.purdue.edu>",
	PURPLE_WEBSITE,
	tcl_load,
	tcl_unload,
	NULL,
	NULL,
	&tcl_loader_info,
	NULL,
	NULL,

	/* padding */
	NULL,
	NULL,
	NULL,
	NULL
};

#ifdef _WIN32
typedef Tcl_Interp* (__cdecl* LPFNTCLCREATEINTERP)(void);
typedef void        (__cdecl* LPFNTKINIT)(Tcl_Interp*);

LPFNTCLCREATEINTERP wtcl_CreateInterp = NULL;
LPFNTKINIT wtk_Init = NULL;
#undef Tcl_CreateInterp
#define Tcl_CreateInterp wtcl_CreateInterp
#undef Tk_Init
#define Tk_Init wtk_Init

static gboolean tcl_win32_init() {
	const char regkey[] = "SOFTWARE\\ActiveState\\ActiveTcl\\";
	char *version = NULL;
	gboolean retval = FALSE;

	if ((version = wpurple_read_reg_string(HKEY_LOCAL_MACHINE, regkey, "CurrentVersion"))
			|| (version = wpurple_read_reg_string(HKEY_CURRENT_USER, regkey, "CurrentVersion"))) {
		char *path = NULL;
		char *regkey2;
		char **tokens;
		int major = 0, minor = 0, micro = 0;

		tokens = g_strsplit(version, ".", 0);
		if (tokens[0] && tokens[1] && tokens[2]) {
			major = atoi(tokens[0]);
			minor = atoi(tokens[1]);
			micro = atoi(tokens[2]);
		}
		g_strfreev(tokens);

		regkey2 = g_strdup_printf("%s%s\\", regkey, version);
		if (!(major == 8 && minor == 4 && micro >= 5))
			purple_debug(PURPLE_DEBUG_INFO, "tcl", "Unsupported ActiveTCL version %s found.\n", version);
		else if ((path = wpurple_read_reg_string(HKEY_LOCAL_MACHINE, regkey2, NULL)) || (path = wpurple_read_reg_string(HKEY_CURRENT_USER, regkey2, NULL))) {
			char *tclpath;
			char *tkpath;

			purple_debug(PURPLE_DEBUG_INFO, "tcl", "Loading ActiveTCL version %s from \"%s\"\n", version, path);

			tclpath = g_build_filename(path, "bin", "tcl84.dll", NULL);
			tkpath = g_build_filename(path, "bin", "tk84.dll", NULL);

			if(!(wtcl_CreateInterp = (LPFNTCLCREATEINTERP) wpurple_find_and_loadproc(tclpath, "Tcl_CreateInterp"))) {
				purple_debug(PURPLE_DEBUG_INFO, "tcl", "tcl_win32_init error loading Tcl_CreateInterp\n");
			} else {
				if(!(wtk_Init = (LPFNTKINIT) wpurple_find_and_loadproc(tkpath, "Tk_Init"))) {
					HMODULE mod;
					purple_debug(PURPLE_DEBUG_INFO, "tcl", "tcl_win32_init error loading Tk_Init\n");
					if((mod = GetModuleHandle("tcl84.dll")))
						FreeLibrary(mod);
				} else {
					retval = TRUE;
				}
			}
			g_free(tclpath);
			g_free(tkpath);
		}
		g_free(path);
		g_free(regkey2);
	}

	g_free(version);

	if (!retval)
		purple_debug(PURPLE_DEBUG_INFO, "tcl", _("Unable to detect ActiveTCL installation. If you wish to use TCL plugins, install ActiveTCL from http://www.activestate.com\n"));

	return retval;
}

#endif /* _WIN32 */

static void tcl_init_plugin(PurplePlugin *plugin)
{
#ifdef USE_TCL_STUBS
	Tcl_Interp *interp = NULL;
#endif
	_tcl_plugin = plugin;

#ifdef USE_TCL_STUBS
#ifdef _WIN32
	if(!tcl_win32_init())
		return;
#endif
	if(!(interp = Tcl_CreateInterp()))
		return;

	if(!Tcl_InitStubs(interp, TCL_VERSION, 0)) {
		purple_debug(PURPLE_DEBUG_ERROR, "tcl", "Tcl_InitStubs: %s\n", interp->result);
		return;
	}
#endif

	Tcl_FindExecutable("purple");

#if defined(USE_TK_STUBS) && defined(HAVE_TK)
	Tk_Init(interp);

	if(!Tk_InitStubs(interp, TK_VERSION, 0)) {
		purple_debug(PURPLE_DEBUG_ERROR, "tcl", "Error Tk_InitStubs: %s\n", interp->result);
		Tcl_DeleteInterp(interp);
		return;
	}
#endif
	tcl_loaded = TRUE;
#ifdef USE_TCL_STUBS
	Tcl_DeleteInterp(interp);
#endif
	tcl_loader_info.exts = g_list_append(tcl_loader_info.exts, "tcl");
}

PURPLE_INIT_PLUGIN(tcl, tcl_init_plugin, tcl_info)
