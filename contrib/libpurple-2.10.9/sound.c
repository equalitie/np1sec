/*
 * purple
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
 *
 */
#include "internal.h"

#include "blist.h"
#include "prefs.h"
#include "sound.h"
#include "sound-theme-loader.h"
#include "theme-manager.h"

static PurpleSoundUiOps *sound_ui_ops = NULL;

#define STATUS_AVAILABLE 1
#define STATUS_AWAY 2

static time_t last_played[PURPLE_NUM_SOUNDS];

static gboolean
purple_sound_play_required(const PurpleAccount *account)
{
	gint pref_status = purple_prefs_get_int("/purple/sound/while_status");

	if (pref_status == 3)
	{
		/* Play sounds: Always */
		return TRUE;
	}

	if (account != NULL)
	{
		PurpleStatus *status = purple_account_get_active_status(account);

		if (purple_status_is_online(status))
		{
			gboolean available = purple_status_is_available(status);
			return (( available && pref_status == STATUS_AVAILABLE) ||
			        (!available && pref_status == STATUS_AWAY));
		}
	}

	/* We get here a couple of ways.  Either the request has been OK'ed
	 * by purple_sound_play_event() and we're here because the UI has
	 * called purple_sound_play_file(), or we're here for something
	 * not related to an account (like testing a sound). */
	return TRUE;
}

void
purple_sound_play_file(const char *filename, const PurpleAccount *account)
{
	if (!purple_sound_play_required(account))
		return;

	if(sound_ui_ops && sound_ui_ops->play_file)
		sound_ui_ops->play_file(filename);
}

void
purple_sound_play_event(PurpleSoundEventID event, const PurpleAccount *account)
{
	if (!purple_sound_play_required(account))
		return;

	if (time(NULL) - last_played[event] < 2)
		return;
	last_played[event] = time(NULL);

	if(sound_ui_ops && sound_ui_ops->play_event) {
		int plugin_return;

		plugin_return = GPOINTER_TO_INT(purple_signal_emit_return_1(
			purple_sounds_get_handle(), "playing-sound-event",
			event, account));

		if (plugin_return)
			return;
		else
			sound_ui_ops->play_event(event);
	}
}

void
purple_sound_set_ui_ops(PurpleSoundUiOps *ops)
{
	if(sound_ui_ops && sound_ui_ops->uninit)
		sound_ui_ops->uninit();

	sound_ui_ops = ops;

	if(sound_ui_ops && sound_ui_ops->init)
		sound_ui_ops->init();
}

PurpleSoundUiOps *
purple_sound_get_ui_ops(void)
{
	return sound_ui_ops;
}

void
purple_sound_init()
{
	void *handle = purple_sounds_get_handle();

	/**********************************************************************
	 * Register signals
	**********************************************************************/

	purple_signal_register(handle, "playing-sound-event",
	                     purple_marshal_BOOLEAN__INT_POINTER,
	                     purple_value_new(PURPLE_TYPE_BOOLEAN), 2,
	                     purple_value_new(PURPLE_TYPE_INT),
	                     purple_value_new(PURPLE_TYPE_SUBTYPE,
	                                    PURPLE_SUBTYPE_ACCOUNT));

	purple_prefs_add_none("/purple/sound");
	purple_prefs_add_int("/purple/sound/while_status", STATUS_AVAILABLE);
	memset(last_played, 0, sizeof(last_played));

	purple_theme_manager_register_type(g_object_new(PURPLE_TYPE_SOUND_THEME_LOADER, "type", "sound", NULL));
}

void
purple_sound_uninit()
{
	if(sound_ui_ops && sound_ui_ops->uninit)
		sound_ui_ops->uninit();

	purple_signals_unregister_by_instance(purple_sounds_get_handle());
}

void *
purple_sounds_get_handle()
{
	static int handle;

	return &handle;
}
