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

#ifndef		_MXIT_SPLASHSCREEN_H_
#define		_MXIT_SPLASHSCREEN_H_

#define		HANDLE_SPLASH1		"plas1.png"
#define		HANDLE_SPLASH2		"plas2.png"

#define		DEFAULT_SPLASH_POPUP	FALSE		/* disabled by default */

/*
 * Return the ID of the current splash-screen.
 */
const char* splash_current(struct MXitSession* session);

/*
 * Indicate if splash-screen popups are enabled.
 */
gboolean splash_popup_enabled(struct MXitSession* session);

/*
 * Save a new splash-screen.
 */
void splash_update(struct MXitSession* session, const char* splashId, const char* data, int datalen, gboolean clickable);

/*
 * Remove the stored splash-screen (if it exists).
 */
void splash_remove(struct MXitSession* session);

/*
 * Display the current splash-screen.
 */
void splash_display(struct MXitSession* session);

#endif		/* _MXIT_SPLASHSCREEN_H_ */
