/*
 * purple
 *
 * Copyright (C) 2003 Christian Hammond <chipx86@gnupdate.org>
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
#ifdef HAVE_CONFIG_H
#include <config.h>
# ifdef HAVE_LIMITS_H
#  include <limits.h>
#  ifndef NAME_MAX
#   define NAME_MAX _POSIX_NAME_MAX
#  endif
# endif
#endif

#ifdef DEBUG
# undef DEBUG
#endif

#undef PACKAGE

#define group perl_group

#ifdef _WIN32
/* This took me an age to figure out.. without this __declspec(dllimport)
 * will be ignored.
 */
# define HASATTRIBUTE
#endif

#include <EXTERN.h>

#ifndef _SEM_SEMUN_UNDEFINED
# define HAS_UNION_SEMUN
#endif

#include <perl.h>
#include <XSUB.h>

#ifndef _WIN32
# include <sys/mman.h>
#endif

#undef PACKAGE

#ifndef _WIN32
# include <dirent.h>
#else
 /* We're using perl's win32 port of this */
# define dirent direct
#endif

#undef group

/* perl module support */
#ifdef _WIN32
EXTERN_C void boot_Win32CORE (pTHX_ CV* cv);
#endif

#ifdef OLD_PERL
extern void boot_DynaLoader _((CV * cv));
#else
extern void boot_DynaLoader _((pTHX_ CV * cv)); /* perl is so wacky */
#endif

#undef _
#ifdef DEBUG
# undef DEBUG
#endif
#ifdef _WIN32
# undef pipe
#endif

#ifdef _WIN32
#define _WIN32DEP_H_
#endif
#include "internal.h"
#include "debug.h"
#include "plugin.h"
#include "signals.h"
#include "version.h"

#include "perl-common.h"
#include "perl-handlers.h"

#include <gmodule.h>

#define PERL_PLUGIN_ID "core-perl"

PerlInterpreter *my_perl = NULL;

static PurplePluginUiInfo ui_info =
{
	purple_perl_get_plugin_frame,
	0,   /* page_num (Reserved) */
	NULL, /* frame (Reserved)    */
	/* Padding */
	NULL,
	NULL,
	NULL,
	NULL
};

#ifdef PURPLE_GTKPERL
static PurpleGtkPluginUiInfo gtk_ui_info =
{
	purple_perl_gtk_get_plugin_frame,
	0 /* page_num (Reserved) */
};
#endif

static void
#ifdef OLD_PERL
xs_init()
#else
xs_init(pTHX)
#endif
{
	char *file = __FILE__;
	GList *search_paths = purple_plugins_get_search_paths();
	dXSUB_SYS;

	/* This one allows dynamic loading of perl modules in perl scripts by
	 * the 'use perlmod;' construction */
	newXS("DynaLoader::boot_DynaLoader", boot_DynaLoader, file);
#ifdef _WIN32
	newXS("Win32CORE::bootstrap", boot_Win32CORE, file);
#endif

	while (search_paths != NULL) {
		gchar *uselib;
		const gchar *search_path = search_paths->data;
		search_paths = g_list_next(search_paths);

		uselib = g_strdup_printf("unshift @INC, q(%s%sperl);",
		                         search_path, G_DIR_SEPARATOR_S);
		eval_pv(uselib, TRUE);
		g_free(uselib);
	}
}

static void
perl_init(void)
{
	/* changed the name of the variable from load_file to perl_definitions
	 * since now it does much more than defining the load_file sub.
	 * Moreover, deplaced the initialisation to the xs_init function.
	 * (TheHobbit) */
	char *perl_args[] = { "", "-e", "0", "-w" };
	char perl_definitions[] =
	{
		/* We use to function one to load a file the other to execute
		 * the string obtained from the first and holding the file
		 * contents. This allows to have a really local $/ without
		 * introducing temp variables to hold the old value. Just a
		 * question of style:) */
		"package Purple::PerlLoader;"
		"use Symbol;"

		"sub load_file {"
		  "my $f_name=shift;"
		  "local $/=undef;"
		  "open FH,$f_name or return \"__FAILED__\";"
		  "$_=<FH>;"
		  "close FH;"
		  "return $_;"
		"}"

		"sub destroy_package {"
		  "eval { $_[0]->UNLOAD() if $_[0]->can('UNLOAD'); };"
		  "Symbol::delete_package($_[0]);"
		"}"

		"sub load_n_eval {"
		  "my ($f_name, $package) = @_;"
		  "destroy_package($package);"
		  "my $strin=load_file($f_name);"
		  "return 2 if($strin eq \"__FAILED__\");"
		  "my $eval = qq{package $package; $strin;};"

		  "{"
		  "  eval $eval;"
		  "}"

		  "if($@) {"
		    /*"  #something went wrong\n"*/
		    "die(\"Errors loading file $f_name: $@\");"
		  "}"

		  "return 0;"
		"}"
	};

	my_perl = perl_alloc();
	PERL_SET_CONTEXT(my_perl);
	PL_perl_destruct_level = 1;
	perl_construct(my_perl);
#ifdef DEBUG
	perl_parse(my_perl, xs_init, 4, perl_args, NULL);
#else
	perl_parse(my_perl, xs_init, 3, perl_args, NULL);
#endif
#ifdef HAVE_PERL_EVAL_PV
	eval_pv(perl_definitions, TRUE);
#else
	perl_eval_pv(perl_definitions, TRUE); /* deprecated */
#endif
	perl_run(my_perl);
}

static void
perl_end(void)
{
	if (my_perl == NULL)
		return;

	PL_perl_destruct_level = 1;
	PERL_SET_CONTEXT(my_perl);
	perl_eval_pv(
		"foreach my $lib (@DynaLoader::dl_modules) {"
		  "if ($lib =~ /^Purple\\b/) {"
		    "$lib .= '::deinit();';"
		    "eval $lib;"
		  "}"
		"}",
		TRUE);

	PL_perl_destruct_level = 1;
	PERL_SET_CONTEXT(my_perl);
	perl_destruct(my_perl);
	perl_free(my_perl);
	my_perl = NULL;
}

void
purple_perl_callXS(void (*subaddr)(pTHX_ CV *cv), CV *cv, SV **mark)
{
	dSP;

	PUSHMARK(mark);
	(*subaddr)(aTHX_ cv);

	PUTBACK;
}

static gboolean
probe_perl_plugin(PurplePlugin *plugin)
{

	char *args[] = {"", plugin->path };
	char **argv = args;
	int argc = 2, ret;
	PerlInterpreter *prober;
	gboolean status = TRUE;
	HV *plugin_info;

	PERL_SYS_INIT(&argc, &argv);

	/* XXX This would be much faster if we didn't create a new
	 *     PerlInterpreter every time we probe a plugin */
	prober = perl_alloc();

	PERL_SET_CONTEXT(prober);

	PL_perl_destruct_level = 1;
	perl_construct(prober);

/* Fix IO redirection to match where pidgin's is going.
 * Without this, we lose stdout/stderr unless we redirect to a file */
#ifdef _WIN32
{
	PerlIO* newprlIO = PerlIO_open("CONOUT$", "w");
	if (newprlIO) {
		int stdout_fd = PerlIO_fileno(PerlIO_stdout());
		int stderr_fd = PerlIO_fileno(PerlIO_stderr());
		PerlIO_close(PerlIO_stdout());
		PerlIO_close(PerlIO_stderr());
		PerlLIO_dup2(PerlIO_fileno(newprlIO), stdout_fd);
		PerlLIO_dup2(PerlIO_fileno(newprlIO), stderr_fd);

		PerlIO_close(newprlIO);
	}
}
#endif

	ret = perl_parse(prober, xs_init, argc, argv, NULL);

	if (ret != 0) {
		const char * errmsg = "Unknown error";
		if (SvTRUE(ERRSV))
			errmsg = SvPVutf8_nolen(ERRSV);
		purple_debug_error("perl", "Unable to parse plugin %s (%d:%s)\n",
						   plugin->path, ret, errmsg);
		status = FALSE;
		goto cleanup;
	}

	ret = perl_run(prober);

	if (ret != 0) {
		const char * errmsg = "Unknown error";
		if (SvTRUE(ERRSV))
			errmsg = SvPVutf8_nolen(ERRSV);
		purple_debug_error("perl", "Unable to run perl interpreter on plugin %s (%d:%s)\n",
						   plugin->path, ret, errmsg);
		status = FALSE;
		goto cleanup;
	}

	plugin_info = perl_get_hv("PLUGIN_INFO", FALSE);

	if (plugin_info == NULL)
		status = FALSE;
	else if (!hv_exists(plugin_info, "perl_api_version",
	                    strlen("perl_api_version")) ||
	         !hv_exists(plugin_info, "name", strlen("name")) ||
	         !hv_exists(plugin_info, "load", strlen("load"))) {
		/* Not a valid plugin. */

		status = FALSE;
	} else {
		SV **key;
		int perl_api_ver;

		key = hv_fetch(plugin_info, "perl_api_version",
		               strlen("perl_api_version"), 0);

		perl_api_ver = SvIV(*key);

		if (perl_api_ver != 2)
			status = FALSE;
		else {
			PurplePluginInfo *info;
			PurplePerlScript *gps;
			char *basename;

			info = g_new0(PurplePluginInfo, 1);
			gps  = g_new0(PurplePerlScript, 1);

			info->magic = PURPLE_PLUGIN_MAGIC;
			info->major_version = PURPLE_MAJOR_VERSION;
			info->minor_version = PURPLE_MINOR_VERSION;
			info->type = PURPLE_PLUGIN_STANDARD;

			info->dependencies = g_list_append(info->dependencies,
			                                   PERL_PLUGIN_ID);

			gps->plugin = plugin;

			basename = g_path_get_basename(plugin->path);
			purple_perl_normalize_script_name(basename);
			gps->package = g_strdup_printf("Purple::Script::%s",
			                               basename);
			g_free(basename);

			/* We know this one exists. */
			key = hv_fetch(plugin_info, "name", strlen("name"), 0);
			info->name = g_strdup(SvPVutf8_nolen(*key));
			/* Set id here in case we don't find one later. */
			info->id = g_strdup(info->name);

#ifdef PURPLE_GTKPERL
			if ((key = hv_fetch(plugin_info, "GTK_UI",
			                    strlen("GTK_UI"), 0)))
				info->ui_requirement = PURPLE_GTK_PLUGIN_TYPE;
#endif

			if ((key = hv_fetch(plugin_info, "url",
			                    strlen("url"), 0)))
				info->homepage = g_strdup(SvPVutf8_nolen(*key));

			if ((key = hv_fetch(plugin_info, "author",
			                    strlen("author"), 0)))
				info->author = g_strdup(SvPVutf8_nolen(*key));

			if ((key = hv_fetch(plugin_info, "summary",
			                    strlen("summary"), 0)))
				info->summary = g_strdup(SvPVutf8_nolen(*key));

			if ((key = hv_fetch(plugin_info, "description",
			                    strlen("description"), 0)))
				info->description = g_strdup(SvPVutf8_nolen(*key));

			if ((key = hv_fetch(plugin_info, "version",
			                    strlen("version"), 0)))
				info->version = g_strdup(SvPVutf8_nolen(*key));

			/* We know this one exists. */
			key = hv_fetch(plugin_info, "load", strlen("load"), 0);
			gps->load_sub = g_strdup_printf("%s::%s", gps->package,
			                                SvPVutf8_nolen(*key));

			if ((key = hv_fetch(plugin_info, "unload",
			                    strlen("unload"), 0)))
				gps->unload_sub = g_strdup_printf("%s::%s",
				                                  gps->package,
				                                  SvPVutf8_nolen(*key));

			if ((key = hv_fetch(plugin_info, "id",
			                    strlen("id"), 0))) {
				g_free(info->id);
				info->id = g_strdup_printf("perl-%s",
				                           SvPVutf8_nolen(*key));
			}

		/********************************************************/
		/* Only one of the next two options should be present   */
		/*                                                      */
		/* prefs_info - Uses non-GUI (read GTK) purple API calls  */
		/*              and creates a PurplePluginPrefInfo type.  */
		/*                                                      */
		/* gtk_prefs_info - Requires gtk2-perl be installed by  */
		/*                  the user and he must create a       */
		/*                  GtkWidget the user and he must      */
		/*                  create a GtkWidget representing the */
		/*                  plugin preferences page.            */
		/********************************************************/
			if ((key = hv_fetch(plugin_info, "prefs_info",
			                    strlen("prefs_info"), 0))) {
				/* key now is the name of the Perl sub that
				 * will create a frame for us */
				gps->prefs_sub = g_strdup_printf("%s::%s",
				                                 gps->package,
				                                 SvPVutf8_nolen(*key));
				info->prefs_info = &ui_info;
			}

#ifdef PURPLE_GTKPERL
			if ((key = hv_fetch(plugin_info, "gtk_prefs_info",
			                    strlen("gtk_prefs_info"), 0))) {
				/* key now is the name of the Perl sub that
				 * will create a frame for us */
				gps->gtk_prefs_sub = g_strdup_printf("%s::%s",
				                                     gps->package,
				                                     SvPVutf8_nolen(*key));
				info->ui_info = &gtk_ui_info;
			}
#endif

			if ((key = hv_fetch(plugin_info, "plugin_action_sub",
			                    strlen("plugin_action_sub"), 0))) {
				gps->plugin_action_sub = g_strdup_printf("%s::%s",
				                                         gps->package,
				                                         SvPVutf8_nolen(*key));
				info->actions = purple_perl_plugin_actions;
			}

			plugin->info = info;
			info->extra_info = gps;

			status = purple_plugin_register(plugin);
		}
	}

	cleanup:
	PL_perl_destruct_level = 1;
	PERL_SET_CONTEXT(prober);
	perl_destruct(prober);
	perl_free(prober);
	return status;
}

static gboolean
load_perl_plugin(PurplePlugin *plugin)
{
	PurplePerlScript *gps = (PurplePerlScript *)plugin->info->extra_info;
	gboolean loaded = TRUE;
	char *atmp[3] = { plugin->path, NULL, NULL };

	if (gps == NULL || gps->load_sub == NULL)
		return FALSE;

	purple_debug(PURPLE_DEBUG_INFO, "perl", "Loading perl script\n");

	if (my_perl == NULL)
		perl_init();

	plugin->handle = gps;

	atmp[1] = gps->package;

	PERL_SET_CONTEXT(my_perl);
	execute_perl("Purple::PerlLoader::load_n_eval", 2, atmp);

	{
		dSP;
		PERL_SET_CONTEXT(my_perl);
		SPAGAIN;
		ENTER;
		SAVETMPS;
		PUSHMARK(sp);
		XPUSHs(sv_2mortal(purple_perl_bless_object(plugin,
		                                         "Purple::Plugin")));
		PUTBACK;

		perl_call_pv(gps->load_sub, G_EVAL | G_SCALAR);
		SPAGAIN;

		if (SvTRUE(ERRSV)) {
			purple_debug(PURPLE_DEBUG_ERROR, "perl",
			           "Perl function %s exited abnormally: %s\n",
			           gps->load_sub, SvPVutf8_nolen(ERRSV));
			loaded = FALSE;
		}

		PUTBACK;
		FREETMPS;
		LEAVE;
	}

	return loaded;
}

static void
destroy_package(const char *package)
{
	dSP;
	PERL_SET_CONTEXT(my_perl);
	SPAGAIN;

	ENTER;
	SAVETMPS;

	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSVpv(package, 0)));
	PUTBACK;

	perl_call_pv("Purple::PerlLoader::destroy_package",
	             G_VOID | G_EVAL | G_DISCARD);

	SPAGAIN;

	PUTBACK;
	FREETMPS;
	LEAVE;
}

static gboolean
unload_perl_plugin(PurplePlugin *plugin)
{
	PurplePerlScript *gps = (PurplePerlScript *)plugin->info->extra_info;

	if (gps == NULL)
		return FALSE;

	purple_debug(PURPLE_DEBUG_INFO, "perl", "Unloading perl script\n");

	if (gps->unload_sub != NULL) {
		dSP;
		PERL_SET_CONTEXT(my_perl);
		SPAGAIN;
		ENTER;
		SAVETMPS;
		PUSHMARK(sp);
		XPUSHs(sv_2mortal(purple_perl_bless_object(plugin,
		                                         "Purple::Plugin")));
		PUTBACK;

		perl_call_pv(gps->unload_sub, G_EVAL | G_SCALAR);
		SPAGAIN;

		if (SvTRUE(ERRSV)) {
			purple_debug(PURPLE_DEBUG_ERROR, "perl",
			           "Perl function %s exited abnormally: %s\n",
			           gps->unload_sub, SvPVutf8_nolen(ERRSV));
		}

		PUTBACK;
		FREETMPS;
		LEAVE;
	}

	purple_perl_cmd_clear_for_plugin(plugin);
	purple_perl_signal_clear_for_plugin(plugin);
	purple_perl_timeout_clear_for_plugin(plugin);
	purple_perl_pref_cb_clear_for_plugin(plugin);

	destroy_package(gps->package);

	return TRUE;
}

static void
destroy_perl_plugin(PurplePlugin *plugin)
{
	if (plugin->info != NULL) {
		PurplePerlScript *gps;

		g_free(plugin->info->name);
		g_free(plugin->info->id);
		g_free(plugin->info->homepage);
		g_free(plugin->info->author);
		g_free(plugin->info->summary);
		g_free(plugin->info->description);
		g_free(plugin->info->version);

		gps = (PurplePerlScript *)plugin->info->extra_info;
		if (gps != NULL) {
			g_free(gps->package);
			g_free(gps->load_sub);
			g_free(gps->unload_sub);
			g_free(gps->prefs_sub);
#ifdef PURPLE_GTKPERL
			g_free(gps->gtk_prefs_sub);
#endif
			g_free(gps->plugin_action_sub);
			g_free(gps);
			plugin->info->extra_info = NULL;
		}

		g_free(plugin->info);
		plugin->info = NULL;
	}
}

static gboolean
plugin_load(PurplePlugin *plugin)
{
	return TRUE;
}

static gboolean
plugin_unload(PurplePlugin *plugin)
{
	perl_end();

	return TRUE;
}

static PurplePluginLoaderInfo loader_info =
{
	NULL,                                             /**< exts           */
	probe_perl_plugin,                                /**< probe          */
	load_perl_plugin,                                 /**< load           */
	unload_perl_plugin,                               /**< unload         */
	destroy_perl_plugin,                              /**< destroy        */

	/* padding */
	NULL,
	NULL,
	NULL,
	NULL
};

static PurplePluginInfo info =
{
	PURPLE_PLUGIN_MAGIC,
	PURPLE_MAJOR_VERSION,
	PURPLE_MINOR_VERSION,
	PURPLE_PLUGIN_LOADER,                             /**< type           */
	NULL,                                             /**< ui_requirement */
	0,                                                /**< flags          */
	NULL,                                             /**< dependencies   */
	PURPLE_PRIORITY_DEFAULT,                          /**< priority       */

	PERL_PLUGIN_ID,                                   /**< id             */
	N_("Perl Plugin Loader"),                         /**< name           */
	DISPLAY_VERSION,                                  /**< version        */
	N_("Provides support for loading perl plugins."), /**< summary        */
	N_("Provides support for loading perl plugins."), /**< description    */
	"Christian Hammond <chipx86@gnupdate.org>",       /**< author         */
	PURPLE_WEBSITE,                                   /**< homepage       */

	plugin_load,                                      /**< load           */
	plugin_unload,                                    /**< unload         */
	NULL,                                             /**< destroy        */

	NULL,                                             /**< ui_info        */
	&loader_info,                                     /**< extra_info     */
	NULL,
	NULL,

	/* padding */
	NULL,
	NULL,
	NULL,
	NULL
};

static void
init_plugin(PurplePlugin *plugin)
{
	loader_info.exts = g_list_append(loader_info.exts, "pl");
}

#ifdef __SUNPRO_C
#pragma init (my_init)
#else
void __attribute__ ((constructor)) my_init(void);
#endif

void
my_init(void)
{
	/* Mostly evil hack... puts perl.so's symbols in the global table but
	 * does not create a circular dependency because g_module_open will
	 * only open the library once. */
	/* Do we need to keep track of the returned GModule here so that we
	 * can g_module_close it when this plugin gets unloaded?
	 * At the moment I don't think this plugin can ever get unloaded but
	 * in case that becomes possible this wants to get noted. */
	g_module_open("perl.so", 0);
}

PURPLE_INIT_PLUGIN(perl, init_plugin, info)
