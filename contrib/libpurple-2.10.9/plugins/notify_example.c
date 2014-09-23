/*
 * Notify API Example Plugin
 *
 * Copyright (C) 2007, John Bailey <rekkanoryo@cpw.pidgin.im>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02111-1301, USA.
 *
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <glib.h>

/* This will prevent compiler errors in some instances and is better explained in the
 * how-to documents on the wiki */
#ifndef G_GNUC_NULL_TERMINATED
# if __GNUC__ >= 4
#  define G_GNUC_NULL_TERMINATED __attribute__((__sentinel__))
# else
#  define G_GNUC_NULL_TERMINATED
# endif
#endif

/* This is the required definition of PURPLE_PLUGINS as required for a plugin,
 * but we protect it with an #ifndef because config.h may define it for us
 * already and this would cause an unneeded compiler warning. */
#ifndef PURPLE_PLUGINS
# define PURPLE_PLUGINS
#endif

#define PLUGIN_ID "core-notifyexample"
#define PLUGIN_AUTHOR "John Bailey <rekkanoryo@cpw.pidgin.im>"

#include <notify.h>
#include <plugin.h>
#include <version.h>

static PurplePlugin *notify_example = NULL;

/* The next four functions and the calls within them should cause dialog boxes to appear
 * when you select the plugin action from the Tools->Notify Example menu */
static void
notify_error_cb(PurplePluginAction *action)
{
	purple_notify_error(notify_example, "Test Notification", "Test Notification",
		"This is a test error notification");
}

static void
notify_info_cb(PurplePluginAction *action)
{
	purple_notify_info(notify_example, "Test Notification", "Test Notification",
		"This is a test informative notification");
}

static void
notify_warn_cb(PurplePluginAction *action)
{
	purple_notify_warning(notify_example, "Test Notification", "Test Notification",
		"This is a test warning notification");
}

static void
notify_format_cb(PurplePluginAction *action)
{
	purple_notify_formatted(notify_example, "Test Notification", "Test Notification",
		"Test Notification",
		"<I>This is a test notification with formatted text.</I>", NULL, NULL);
}

static void
notify_uri_cb(PurplePluginAction *action)
{
	/* This one should open your web browser of choice. */
	purple_notify_uri(notify_example, "http://www.pidgin.im/");
}

static GList *
plugin_actions(PurplePlugin *plugin, gpointer context)
{
	GList *actions = NULL;

	/* Here we take advantage of return values to avoid the need for a temp variable */
	actions = g_list_prepend(actions,
		purple_plugin_action_new("Show Error Notification", notify_error_cb));

	actions = g_list_prepend(actions,
		purple_plugin_action_new("Show Info Notification", notify_info_cb));

	actions = g_list_prepend(actions,
		purple_plugin_action_new("Show Warning Notification", notify_warn_cb));

	actions = g_list_prepend(actions,
		purple_plugin_action_new("Show Formatted Notification", notify_format_cb));

	actions = g_list_prepend(actions,
		purple_plugin_action_new("Show URI Notification", notify_uri_cb));

	return g_list_reverse(actions);
}

static gboolean
plugin_load(PurplePlugin *plugin)
{
	/* we need a handle for all the notify calls */
	notify_example = plugin;

	return TRUE;
}

static PurplePluginInfo info = {
	PURPLE_PLUGIN_MAGIC,        /* magic number */
	PURPLE_MAJOR_VERSION,       /* purple major */
	PURPLE_MINOR_VERSION,       /* purple minor */
	PURPLE_PLUGIN_STANDARD,     /* plugin type */
	NULL,                       /* UI requirement */
	0,                          /* flags */
	NULL,                       /* dependencies */
	PURPLE_PRIORITY_DEFAULT,    /* priority */

	PLUGIN_ID,                  /* id */
	"Notify API Example",       /* name */
	DISPLAY_VERSION,            /* version */
	"Notify API Example",       /* summary */
	"Notify API Example",       /* description */
	PLUGIN_AUTHOR,              /* author */
	"http://pidgin.im",         /* homepage */

	plugin_load,                /* load */
	NULL,                       /* unload */
	NULL,                       /* destroy */

	NULL,                       /* ui info */
	NULL,                       /* extra info */
	NULL,                       /* prefs info */
	plugin_actions,             /* actions */
	NULL,                       /* reserved */
	NULL,                       /* reserved */
	NULL,                       /* reserved */
	NULL                        /* reserved */
};

static void
init_plugin(PurplePlugin *plugin)
{
}

PURPLE_INIT_PLUGIN(notifyexample, init_plugin, info)

