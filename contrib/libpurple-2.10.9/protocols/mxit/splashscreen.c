/*
 *					MXit Protocol libPurple Plugin
 *
 *						-- splash screens --
 *
 *				Andrew Victor	<libpurple@mxit.com>
 *
 *			(C) Copyright 2009	MXit Lifestyle (Pty) Ltd.
 *				<http://www.mxitlifestyle.com>
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
#include "debug.h"
#include "imgstore.h"
#include "request.h"

#include "protocol.h"
#include "mxit.h"
#include "splashscreen.h"


/*------------------------------------------------------------------------
 * Return the ID of the current splash-screen.
 *
 *  @param session		The MXit session object
 *  @return				The ID of the splash-screen (or NULL if no splash-screen)
 */
const char* splash_current(struct MXitSession* session)
{
	const char* splashId = purple_account_get_string(session->acc, MXIT_CONFIG_SPLASHID, NULL);

	if ((splashId != NULL) && (*splashId != '\0')) {
		purple_debug_info(MXIT_PLUGIN_ID, "Current splashId: '%s'\n", splashId);
		return splashId;
	}
	else
		return NULL;
}


/*------------------------------------------------------------------------
 * Indicate if splash-screen popups are enabled.
 *
 *  @param session		The MXit session object
 *  @return				TRUE if the popup is enabled.
 */
gboolean splash_popup_enabled(struct MXitSession* session)
{
	return purple_account_get_bool(session->acc, MXIT_CONFIG_SPLASHPOPUP, DEFAULT_SPLASH_POPUP);
}


/*------------------------------------------------------------------------
 * Return if the current splash-screen is clickable.
 *
 *  @param session		The MXit session object
 *  @return				TRUE or FALSE
 */
static gboolean splash_clickable(struct MXitSession* session)
{
	return purple_account_get_bool(session->acc, MXIT_CONFIG_SPLASHCLICK, FALSE);
}


/*------------------------------------------------------------------------
 * Remove the stored splash-screen (if it exists).
 *
 *  @param session		The MXit session object
 */
void splash_remove(struct MXitSession* session)
{
	const char* splashId = NULL;
	char* filename;

	/* Get current splash ID */
	splashId = splash_current(session);

	if (splashId != NULL) {
		purple_debug_info(MXIT_PLUGIN_ID, "Removing splashId: '%s'\n", splashId);

		/* Delete stored splash image */
		filename = g_strdup_printf("%s" G_DIR_SEPARATOR_S "mxit" G_DIR_SEPARATOR_S "%s.png", purple_user_dir(), splashId);
		g_unlink(filename);
		g_free(filename);

		/* Clear current splash ID from settings */
		purple_account_set_string(session->acc, MXIT_CONFIG_SPLASHID, "");
		purple_account_set_bool(session->acc, MXIT_CONFIG_SPLASHCLICK, FALSE);
	}
}


/*------------------------------------------------------------------------
 * Save a new splash-screen for later display.
 *
 *  @param session		The MXit session object
 *  @param splashID		The ID of the splash-screen
 *  @param data			Splash-screen image data (PNG format)
 *  @param datalen		Splash-screen image data size
 */
void splash_update(struct MXitSession* session, const char* splashId, const char* data, int datalen, gboolean clickable)
{
	char* dir;
	char* filename;

	/* Remove the current splash-screen */
	splash_remove(session);

	/* Save the new splash image */
	dir = g_strdup_printf("%s" G_DIR_SEPARATOR_S "mxit", purple_user_dir());
	purple_build_dir(dir, S_IRUSR | S_IWUSR | S_IXUSR);		/* ensure directory exists */

	filename = g_strdup_printf("%s" G_DIR_SEPARATOR_S "%s.png", dir, purple_escape_filename(splashId));
	if (purple_util_write_data_to_file_absolute(filename, data, datalen)) {
		/* Store new splash-screen ID to settings */
		purple_account_set_string(session->acc, MXIT_CONFIG_SPLASHID, splashId);
		purple_account_set_bool(session->acc, MXIT_CONFIG_SPLASHCLICK, clickable );
	}

	g_free(dir);
	g_free(filename);
}


/*------------------------------------------------------------------------
 * The user has clicked OK on the Splash request form.
 *
 *  @param gc			The connection object
 *  @param fields		The list of fields in the accepted form
 */
static void splash_click_ok(PurpleConnection* gc, PurpleRequestFields* fields)
{
	struct MXitSession*	session	= purple_connection_get_protocol_data(gc);
	const char* splashId;

	/* Get current splash ID */
	splashId = splash_current(session);
	if (splashId == NULL)		/* no splash-screen */
		return;

	/* if is clickable, then send click event */
	if (splash_clickable(session))
		mxit_send_splashclick(session, splashId);
}


/*------------------------------------------------------------------------
 * Display the current splash-screen.
 *
 *  @param session		The MXit session object
 */
void splash_display(struct MXitSession* session)
{
	const char* splashId = NULL;
	char* filename;
	gchar* imgdata;
	gsize imglen;
	int imgid = -1;

	/* Get current splash ID */
	splashId = splash_current(session);
	if (splashId == NULL)		/* no splash-screen */
		return;

	purple_debug_info(MXIT_PLUGIN_ID, "Display Splash: '%s'\n", splashId);

	/* Load splash-screen image from file */
	filename = g_strdup_printf("%s" G_DIR_SEPARATOR_S "mxit" G_DIR_SEPARATOR_S "%s.png", purple_user_dir(), splashId);
	if (g_file_get_contents(filename, &imgdata, &imglen, NULL)) {
		char buf[128];

		/* Add splash-image to imagestore */
		imgid = purple_imgstore_add_with_id(g_memdup(imgdata, imglen), imglen, NULL);

		/* Generate and display message */
		g_snprintf(buf, sizeof(buf), "<img id=\"%d\">", imgid);

		/* Open a request-type popup to display the image */
		{
			PurpleRequestFields*		fields;
			PurpleRequestFieldGroup*	group;
			PurpleRequestField*			field;

			fields = purple_request_fields_new();
			group = purple_request_field_group_new(NULL);
			purple_request_fields_add_group(fields, group);

			field = purple_request_field_image_new("splash", "", imgdata, imglen);		/* add splash image */
			purple_request_field_group_add_field(group, field);

			if (splash_clickable(session)) {
				purple_request_fields(session->con, _("MXit Advertising"), NULL, NULL, fields,
					_("More Information"), G_CALLBACK(splash_click_ok), _("Close"), NULL, session->acc, NULL, NULL, session->con);
			}
			else {
				purple_request_fields(session->con, _("MXit Advertising"), NULL, NULL, fields,
					_("Continue"), G_CALLBACK(splash_click_ok), _("Close"), NULL, session->acc, NULL, NULL, session->con);
			}
		}

		/* Release reference to image */
		purple_imgstore_unref_by_id(imgid);

		g_free(imgdata);
	}

	g_free(filename);
}
