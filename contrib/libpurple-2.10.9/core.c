/**
 * @file core.c Purple Core API
 * @ingroup core
 */

/* purple
 *
 * Purple is the legal property of its developers, whose names are too numerous
 * to list here.  Please refer to the COPYRIGHT file distributed with this
 * source distribution.
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
#include "internal.h"
#include "cipher.h"
#include "certificate.h"
#include "cmds.h"
#include "connection.h"
#include "conversation.h"
#include "core.h"
#include "debug.h"
#include "dnsquery.h"
#include "ft.h"
#include "idle.h"
#include "imgstore.h"
#include "network.h"
#include "notify.h"
#include "plugin.h"
#include "pounce.h"
#include "prefs.h"
#include "privacy.h"
#include "proxy.h"
#include "savedstatuses.h"
#include "signals.h"
#include "smiley.h"
#include "sound.h"
#include "sound-theme-loader.h"
#include "sslconn.h"
#include "status.h"
#include "stun.h"
#include "theme-manager.h"
#include "util.h"

#ifdef HAVE_DBUS
#  ifndef DBUS_API_SUBJECT_TO_CHANGE
#    define DBUS_API_SUBJECT_TO_CHANGE
#  endif
#  include <dbus/dbus.h>
#  include "dbus-purple.h"
#  include "dbus-server.h"
#  include "dbus-bindings.h"
#endif

struct PurpleCore
{
	char *ui;

	void *reserved;
};

static PurpleCoreUiOps *_ops  = NULL;
static PurpleCore      *_core = NULL;

STATIC_PROTO_INIT

gboolean
purple_core_init(const char *ui)
{
	PurpleCoreUiOps *ops;
	PurpleCore *core;

	g_return_val_if_fail(ui != NULL, FALSE);
	g_return_val_if_fail(purple_get_core() == NULL, FALSE);

#ifdef ENABLE_NLS
	bindtextdomain(PACKAGE, LOCALEDIR);
#endif
#ifdef _WIN32
	wpurple_init();
#endif

	g_type_init();

	_core = core = g_new0(PurpleCore, 1);
	core->ui = g_strdup(ui);
	core->reserved = NULL;

	ops = purple_core_get_ui_ops();

	/* The signals subsystem is important and should be first. */
	purple_signals_init();

	purple_util_init();

	purple_signal_register(core, "uri-handler",
		purple_marshal_BOOLEAN__POINTER_POINTER_POINTER,
		purple_value_new(PURPLE_TYPE_BOOLEAN), 3,
		purple_value_new(PURPLE_TYPE_STRING), /* Protocol */
		purple_value_new(PURPLE_TYPE_STRING), /* Command */
		purple_value_new(PURPLE_TYPE_BOXED, "GHashTable *")); /* Parameters */

	purple_signal_register(core, "quitting", purple_marshal_VOID, NULL, 0);

	/* The prefs subsystem needs to be initialized before static protocols
	 * for protocol prefs to work. */
	purple_prefs_init();

	purple_debug_init();

	if (ops != NULL)
	{
		if (ops->ui_prefs_init != NULL)
			ops->ui_prefs_init();

		if (ops->debug_ui_init != NULL)
			ops->debug_ui_init();
	}

#ifdef HAVE_DBUS
	purple_dbus_init();
#endif

	purple_ciphers_init();
	purple_cmds_init();

	/* Since plugins get probed so early we should probably initialize their
	 * subsystem right away too.
	 */
	purple_plugins_init();

	/* Initialize all static protocols. */
	static_proto_init();

	purple_plugins_probe(G_MODULE_SUFFIX);

	purple_theme_manager_init();

	/* The buddy icon code uses the imgstore, so init it early. */
	purple_imgstore_init();

	/* Accounts use status, buddy icons and connection signals, so
	 * initialize these before accounts
	 */
	purple_status_init();
	purple_buddy_icons_init();
	purple_connections_init();

	purple_accounts_init();
	purple_savedstatuses_init();
	purple_notify_init();
	purple_certificate_init();
	purple_conversations_init();
	purple_blist_init();
	purple_log_init();
	purple_network_init();
	purple_privacy_init();
	purple_pounces_init();
	purple_proxy_init();
	purple_dnsquery_init();
	purple_sound_init();
	purple_ssl_init();
	purple_stun_init();
	purple_xfers_init();
	purple_idle_init();
	purple_smileys_init();
	/*
	 * Call this early on to try to auto-detect our IP address and
	 * hopefully save some time later.
	 */
	purple_network_get_my_ip(-1);

	if (ops != NULL && ops->ui_init != NULL)
		ops->ui_init();

	/* The UI may have registered some theme types, so refresh them */
	purple_theme_manager_refresh();

	return TRUE;
}

void
purple_core_quit(void)
{
	PurpleCoreUiOps *ops;
	PurpleCore *core = purple_get_core();

	g_return_if_fail(core != NULL);

	/* The self destruct sequence has been initiated */
	purple_signal_emit(purple_get_core(), "quitting");

	/* Transmission ends */
	purple_connections_disconnect_all();

	/*
	 * Certificates must be destroyed before the SSL plugins, because
	 * PurpleCertificates contain pointers to PurpleCertificateSchemes,
	 * and the PurpleCertificateSchemes will be unregistered when the
	 * SSL plugin is uninit.
	 */
	purple_certificate_uninit();

	/* The SSL plugins must be uninit before they're unloaded */
	purple_ssl_uninit();

	/* Unload all non-loader, non-prpl plugins before shutting down
	 * subsystems. */
	purple_debug_info("main", "Unloading normal plugins\n");
	purple_plugins_unload(PURPLE_PLUGIN_STANDARD);

	/* Save .xml files, remove signals, etc. */
	purple_smileys_uninit();
	purple_idle_uninit();
	purple_pounces_uninit();
	purple_blist_uninit();
	purple_ciphers_uninit();
	purple_notify_uninit();
	purple_conversations_uninit();
	purple_connections_uninit();
	purple_buddy_icons_uninit();
	purple_savedstatuses_uninit();
	purple_status_uninit();
	purple_accounts_uninit();
	purple_sound_uninit();
	purple_theme_manager_uninit();
	purple_xfers_uninit();
	purple_proxy_uninit();
	purple_dnsquery_uninit();
	purple_imgstore_uninit();
	purple_network_uninit();

	/* Everything after unloading all plugins must not fail if prpls aren't
	 * around */
	purple_debug_info("main", "Unloading all plugins\n");
	purple_plugins_destroy_all();

	ops = purple_core_get_ui_ops();
	if (ops != NULL && ops->quit != NULL)
		ops->quit();

	/* Everything after prefs_uninit must not try to read any prefs */
	purple_prefs_uninit();
	purple_plugins_uninit();
#ifdef HAVE_DBUS
	purple_dbus_uninit();
#endif

	purple_cmds_uninit();
	/* Everything after util_uninit cannot try to write things to the confdir */
	purple_util_uninit();
	purple_log_uninit();

	purple_signals_uninit();

	g_free(core->ui);
	g_free(core);

#ifdef _WIN32
	wpurple_cleanup();
#endif

	_core = NULL;
}

gboolean
purple_core_quit_cb(gpointer unused)
{
	purple_core_quit();

	return FALSE;
}

const char *
purple_core_get_version(void)
{
	return VERSION;
}

const char *
purple_core_get_ui(void)
{
	PurpleCore *core = purple_get_core();

	g_return_val_if_fail(core != NULL, NULL);

	return core->ui;
}

PurpleCore *
purple_get_core(void)
{
	return _core;
}

void
purple_core_set_ui_ops(PurpleCoreUiOps *ops)
{
	_ops = ops;
}

PurpleCoreUiOps *
purple_core_get_ui_ops(void)
{
	return _ops;
}

#ifdef HAVE_DBUS
static char *purple_dbus_owner_user_dir(void)
{
	DBusMessage *msg = NULL, *reply = NULL;
	DBusConnection *dbus_connection = NULL;
	DBusError dbus_error;
	char *remote_user_dir = NULL;

	if ((dbus_connection = purple_dbus_get_connection()) == NULL)
		return NULL;

	if ((msg = dbus_message_new_method_call(DBUS_SERVICE_PURPLE, DBUS_PATH_PURPLE, DBUS_INTERFACE_PURPLE, "PurpleUserDir")) == NULL)
		return NULL;

	dbus_error_init(&dbus_error);
	reply = dbus_connection_send_with_reply_and_block(dbus_connection, msg, 5000, &dbus_error);
	dbus_message_unref(msg);
	dbus_error_free(&dbus_error);

	if (reply)
	{
		dbus_error_init(&dbus_error);
		dbus_message_get_args(reply, &dbus_error, DBUS_TYPE_STRING, &remote_user_dir, DBUS_TYPE_INVALID);
		remote_user_dir = g_strdup(remote_user_dir);
		dbus_error_free(&dbus_error);
		dbus_message_unref(reply);
	}

	return remote_user_dir;
}

#endif /* HAVE_DBUS */

gboolean
purple_core_ensure_single_instance()
{
	gboolean is_single_instance = TRUE;
#ifdef HAVE_DBUS
	/* in the future, other mechanisms might have already set this to FALSE */
	if (is_single_instance)
	{
		if (!purple_dbus_is_owner())
		{
			const char *user_dir = purple_user_dir();
			char *dbus_owner_user_dir = purple_dbus_owner_user_dir();

			is_single_instance = !purple_strequal(dbus_owner_user_dir, user_dir);
			g_free(dbus_owner_user_dir);
		}
	}
#endif /* HAVE_DBUS */

	return is_single_instance;
}

static gboolean
move_and_symlink_dir(const char *path, const char *basename, const char *old_base, const char *new_base, const char *relative)
{
	char *new_name = g_build_filename(new_base, basename, NULL);
#ifndef _WIN32
	char *old_name;
#endif
	if (g_rename(path, new_name))
	{
		purple_debug_error("core", "Error renaming %s to %s: %s. Please report this at " PURPLE_DEVEL_WEBSITE "\n",
		                   path, new_name, g_strerror(errno));
		g_free(new_name);
		return FALSE;
	}
	g_free(new_name);

#ifndef _WIN32
	/* NOTE: This new_name is relative. */
	new_name = g_build_filename(relative, basename, NULL);
	old_name = g_build_filename(old_base, basename, NULL);
	if (symlink(new_name, old_name))
	{
		purple_debug_warning("core", "Error symlinking %s to %s: %s. Please report this at " PURPLE_DEVEL_WEBSITE "\n",
		                     old_name, new_name, g_strerror(errno));
	}
	g_free(old_name);
	g_free(new_name);
#endif

	return TRUE;
}

gboolean
purple_core_migrate(void)
{
	const char *user_dir = purple_user_dir();
	char *old_user_dir = g_strconcat(purple_home_dir(),
	                                 G_DIR_SEPARATOR_S ".gaim", NULL);
	char *status_file;
	FILE *fp;
	GDir *dir;
	GError *err;
	const char *entry;
#ifndef _WIN32
	char *logs_dir;
#endif
	char *old_icons_dir;

	if (!g_file_test(old_user_dir, G_FILE_TEST_EXISTS))
	{
		/* ~/.gaim doesn't exist, so there's nothing to migrate. */
		g_free(old_user_dir);
		return TRUE;
	}

	status_file = g_strconcat(user_dir, G_DIR_SEPARATOR_S "migrating", NULL);

	if (g_file_test(user_dir, G_FILE_TEST_EXISTS))
	{
		/* If we're here, we have both ~/.gaim and .purple. */

		if (!g_file_test(status_file, G_FILE_TEST_EXISTS))
		{
			/* There's no "migrating" status file,
			 * so ~/.purple is all up to date. */
			g_free(status_file);
			g_free(old_user_dir);
			return TRUE;
		}
	}

	/* If we're here, it's time to migrate from ~/.gaim to ~/.purple. */

        /* Ensure the user directory exists */
	if (!g_file_test(user_dir, G_FILE_TEST_IS_DIR))
	{
		if (g_mkdir(user_dir, S_IRUSR | S_IWUSR | S_IXUSR) == -1)
		{
			purple_debug_error("core", "Error creating directory %s: %s. Please report this at " PURPLE_DEVEL_WEBSITE "\n",
			                   user_dir, g_strerror(errno));
			g_free(status_file);
			g_free(old_user_dir);
			return FALSE;
		}
	}

	/* This writes ~/.purple/migrating, which allows us to detect
	 * incomplete migrations and properly retry. */
	if (!(fp = g_fopen(status_file, "w")))
	{
		purple_debug_error("core", "Error opening file %s for writing: %s. Please report this at " PURPLE_DEVEL_WEBSITE "\n",
		                   status_file, g_strerror(errno));
		g_free(status_file);
		g_free(old_user_dir);
		return FALSE;
	}
	fclose(fp);

	/* Open ~/.gaim so we can loop over its contents. */
	err = NULL;
	if (!(dir = g_dir_open(old_user_dir, 0, &err)))
	{
		purple_debug_error("core", "Error opening directory %s: %s. Please report this at " PURPLE_DEVEL_WEBSITE "\n",
		                   status_file,
		                   (err ? err->message : "Unknown error"));
		if (err)
			g_error_free(err);
		g_free(status_file);
		g_free(old_user_dir);
		return FALSE;
	}

	/* Loop over the contents of ~/.gaim */
	while ((entry = g_dir_read_name(dir)))
	{
		char *name = g_build_filename(old_user_dir, entry, NULL);

#ifndef _WIN32
		/* Deal with symlinks... */
		if (g_file_test(name, G_FILE_TEST_IS_SYMLINK))
		{
			/* We're only going to duplicate a logs symlink. */
			if (purple_strequal(entry, "logs"))
			{
				char *link;
				err = NULL;

				if ((link = g_file_read_link(name, &err)) == NULL)
				{
					char *name_utf8 = g_filename_to_utf8(name, -1, NULL, NULL, NULL);
					purple_debug_error("core", "Error reading symlink %s: %s. Please report this at " PURPLE_DEVEL_WEBSITE "\n",
					                   name_utf8 ? name_utf8 : name, err->message);
					g_free(name_utf8);
					g_error_free(err);
					g_free(name);
					g_dir_close(dir);
					g_free(status_file);
					g_free(old_user_dir);
					return FALSE;
				}

				logs_dir = g_build_filename(user_dir, "logs", NULL);

				if (purple_strequal(link, "../.purple/logs") ||
				    purple_strequal(link, logs_dir))
				{
					/* If the symlink points to the new directory, we're
					 * likely just trying again after a failed migration,
					 * so there's no need to fail here. */
					g_free(link);
					g_free(logs_dir);
					continue;
				}

				/* In case we are trying again after a failed migration, we need
				 * to unlink any existing symlink.  If it's a directory, this
				 * will fail, and so will the symlink below, which is good
				 * because the user should sort things out. */
				g_unlink(logs_dir);

				/* Relative links will most likely still be
				 * valid from ~/.purple, though it's not
				 * guaranteed.  Oh well. */
				if (symlink(link, logs_dir))
				{
					purple_debug_error("core", "Error symlinking %s to %s: %s. Please report this at " PURPLE_DEVEL_WEBSITE "\n",
					                   logs_dir, link, g_strerror(errno));
					g_free(link);
					g_free(name);
					g_free(logs_dir);
					g_dir_close(dir);
					g_free(status_file);
					g_free(old_user_dir);
					return FALSE;
				}

				g_free(link);
				g_free(logs_dir);
				continue;
			}

			/* Ignore all other symlinks. */
			continue;
		}
#endif

		/* Deal with directories... */
		if (g_file_test(name, G_FILE_TEST_IS_DIR))
		{
			if (purple_strequal(entry, "icons"))
			{
				/* This is a special case for the Album plugin, which
				 * stores data in the icons folder.  We're not copying
				 * the icons directory over because previous bugs
				 * meant that it filled up with junk for many users.
				 * This is a great time to purge it. */

				GDir *icons_dir;
				char *new_icons_dir;
				const char *icons_entry;

				err = NULL;
				if (!(icons_dir = g_dir_open(name, 0, &err)))
				{
					purple_debug_error("core", "Error opening directory %s: %s. Please report this at " PURPLE_DEVEL_WEBSITE "\n",
					                   name,
					                   (err ? err->message : "Unknown error"));
					if (err)
						g_error_free(err);
					g_free(name);
					g_dir_close(dir);
					g_free(status_file);
					g_free(old_user_dir);
					return FALSE;
				}

				new_icons_dir = g_build_filename(user_dir, "icons", NULL);
			        /* Ensure the new icon directory exists */
				if (!g_file_test(new_icons_dir, G_FILE_TEST_IS_DIR))
				{
					if (g_mkdir(new_icons_dir, S_IRUSR | S_IWUSR | S_IXUSR) == -1)
					{
						purple_debug_error("core", "Error creating directory %s: %s. Please report this at " PURPLE_DEVEL_WEBSITE "\n",
						                   new_icons_dir, g_strerror(errno));
						g_free(new_icons_dir);
						g_dir_close(icons_dir);
						g_free(name);
						g_dir_close(dir);
						g_free(status_file);
						g_free(old_user_dir);
						return FALSE;
					}
				}

				while ((icons_entry = g_dir_read_name(icons_dir)))
				{
					char *icons_name = g_build_filename(name, icons_entry, NULL);

					if (g_file_test(icons_name, G_FILE_TEST_IS_DIR))
					{
						if (!move_and_symlink_dir(icons_name, icons_entry,
						                          name, new_icons_dir, "../../.purple/icons"))
						{
							g_free(icons_name);
							g_free(new_icons_dir);
							g_dir_close(icons_dir);
							g_free(name);
							g_dir_close(dir);
							g_free(status_file);
							g_free(old_user_dir);
							return FALSE;
						}
					}
					g_free(icons_name);
				}

				g_dir_close(icons_dir);
			}
			else if (purple_strequal(entry, "plugins"))
			{
				/* Do nothing, because we broke plugin compatibility.
				 * This means that the plugins directory gets left behind. */
			}
			else
			{
				/* All other directories are moved and symlinked. */
				if (!move_and_symlink_dir(name, entry, old_user_dir, user_dir, "../.purple"))
				{
					g_free(name);
					g_dir_close(dir);
					g_free(status_file);
					g_free(old_user_dir);
					return FALSE;
				}
			}
		}
		else if (g_file_test(name, G_FILE_TEST_IS_REGULAR))
		{
			/* Regular files are copied. */

			char *new_name;
			FILE *new_file;

			if (!(fp = g_fopen(name, "rb")))
			{
				purple_debug_error("core", "Error opening file %s for reading: %s. Please report this at " PURPLE_DEVEL_WEBSITE "\n",
				                   name, g_strerror(errno));
				g_free(name);
				g_dir_close(dir);
				g_free(status_file);
				g_free(old_user_dir);
				return FALSE;
			}

			new_name = g_build_filename(user_dir, entry, NULL);
			if (!(new_file = g_fopen(new_name, "wb")))
			{
				purple_debug_error("core", "Error opening file %s for writing: %s. Please report this at " PURPLE_DEVEL_WEBSITE "\n",
				                   new_name, g_strerror(errno));
				fclose(fp);
				g_free(new_name);
				g_free(name);
				g_dir_close(dir);
				g_free(status_file);
				g_free(old_user_dir);
				return FALSE;
			}

			while (!feof(fp))
			{
				unsigned char buf[256];
				size_t size;

				size = fread(buf, 1, sizeof(buf), fp);
				if (size != sizeof(buf) && !feof(fp))
				{
					purple_debug_error("core", "Error reading %s: %s. Please report this at " PURPLE_DEVEL_WEBSITE "\n",
					                   name, g_strerror(errno));
					fclose(new_file);
					fclose(fp);
					g_free(new_name);
					g_free(name);
					g_dir_close(dir);
					g_free(status_file);
					g_free(old_user_dir);
					return FALSE;
				}

				if (!fwrite(buf, size, 1, new_file) && ferror(new_file) != 0)
				{
					purple_debug_error("core", "Error writing %s: %s. Please report this at " PURPLE_DEVEL_WEBSITE "\n",
					                   new_name, g_strerror(errno));
					fclose(new_file);
					fclose(fp);
					g_free(new_name);
					g_free(name);
					g_dir_close(dir);
					g_free(status_file);
					g_free(old_user_dir);
					return FALSE;
				}
			}

			if (fclose(new_file))
			{
				purple_debug_error("core", "Error writing: %s: %s. Please report this at " PURPLE_DEVEL_WEBSITE "\n",
				                   new_name, g_strerror(errno));
			}
			if (fclose(fp))
			{
				purple_debug_warning("core", "Error closing %s: %s\n",
				                     name, g_strerror(errno));
			}
			g_free(new_name);
		}
		else
			purple_debug_warning("core", "Not a regular file or directory: %s\n", name);

		g_free(name);
	}

	/* The migration was successful, so delete the status file. */
	if (g_unlink(status_file))
	{
		purple_debug_error("core", "Error unlinking file %s: %s. Please report this at " PURPLE_DEVEL_WEBSITE "\n",
		                   status_file, g_strerror(errno));
		g_free(status_file);
		return FALSE;
	}

	old_icons_dir = g_build_filename(old_user_dir, "icons", NULL);
	_purple_buddy_icon_set_old_icons_dir(old_icons_dir);
	g_free(old_icons_dir);

	g_free(old_user_dir);

	g_free(status_file);
	return TRUE;
}

GHashTable* purple_core_get_ui_info() {
	PurpleCoreUiOps *ops = purple_core_get_ui_ops();

	if(NULL == ops || NULL == ops->get_ui_info)
		return NULL;

	return ops->get_ui_info();
}
