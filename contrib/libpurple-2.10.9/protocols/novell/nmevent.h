/*
 * nmevent.h
 *
 * Copyright (c) 2004 Novell, Inc. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA	02111-1301	USA
 *
 */

#ifndef __NM_EVENT_H__
#define __NM_EVENT_H__

typedef struct _NMEvent NMEvent;

#include "nmuser.h"
#include <sys/types.h>

/**
 * Defines for the event types
 */
#define	NMEVT_INVALID_RECIPIENT			101
#define	NMEVT_UNDELIVERABLE_STATUS		102
#define	NMEVT_STATUS_CHANGE				103
#define	NMEVT_CONTACT_ADD				104
#define	NMEVT_CONFERENCE_CLOSED			105
#define	NMEVT_CONFERENCE_JOINED			106
#define	NMEVT_CONFERENCE_LEFT			107
#define	NMEVT_RECEIVE_MESSAGE			108
#define	NMEVT_RECEIVE_FILE				109
#define NMEVT_USER_TYPING				112
#define NMEVT_USER_NOT_TYPING			113
#define NMEVT_USER_DISCONNECT			114
#define NMEVT_SERVER_DISCONNECT			115
#define NMEVT_CONFERENCE_RENAME			116
#define NMEVT_CONFERENCE_INVITE			117
#define NMEVT_CONFERENCE_INVITE_NOTIFY	118
#define NMEVT_CONFERENCE_REJECT			119
#define NMEVT_RECEIVE_AUTOREPLY			121
#define NMEVT_START						NMEVT_INVALID_RECIPIENT
#define NMEVT_STOP						NMEVT_RECEIVE_AUTOREPLY

/**
 * Process the event. The event will be read, an NMEvent will
 * be created, and the event callback will be called.
 *
 * @param user		The main user structure.
 * @param type		The type of the event to read.
 *
 * @return			NM_OK on success
 */
NMERR_T nm_process_event(NMUser * user, int type);

/**
 * Creates an NMEvent
 *
 * The NMEvent should be released by calling
 * nm_release_event.
 *
 * @param type		The event type, see defines above.
 * @param source	The DN of the event source.
 * @param gmt		The time that the event occurred.
 *
 * @return 			The new NMEvent
 */
NMEvent *nm_create_event(int type, const char *source, guint32 gmt);

/**
 * Releases an NMEvent
 *
 * @param event		The event to release
 *
 */
void nm_release_event(NMEvent * event);

/**
 * Sets the conference object for the given event.
 *
 * @param event			The event.
 * @param conference	The conference to associate with the event.
 *
 */
void nm_event_set_conference(NMEvent * event, NMConference * conference);

/**
 * Returns the conference object associated with the given event. This should not
 * be released. If it needs to be kept around call nm_conference_addref().
 *
 * @param event	The event.
 *
 * @return		The conference associated with the event, or NULL
 *				if no conference has been set for the event.
 */
NMConference *nm_event_get_conference(NMEvent * event);

/**
 * Sets the NMUserRecord object for the given event.
 * The user record represents the event source.
 *
 * @param event			The event.
 * @param user_record	The user record to associate with the event.
 *
 */
void nm_event_set_user_record(NMEvent * event, NMUserRecord * user_record);

/**
 * Returns the NMUserRecord object associated with the given event.
 * The user record represents the event source. This should not
 * be released. If it needs to be kept around call
 * nm_user_record_add_ref().
 *
 * @param event	The event.
 *
 * @return		The user record associated with the event, or NULL
 *				if no user record has been set for the event.
 */
NMUserRecord *nm_event_get_user_record(NMEvent * event);

/**
 * Sets the text to associate with the given event.
 *
 * @param event	The event.
 * @param text	The text to associate with the event.
 *
 */
void nm_event_set_text(NMEvent * event, const char *text);

/**
 * Returns the text associated with the given event.
 *
 * @param event	The event.
 *
 * @return		The text associated with the event, or NULL
 *				if no text has been set for the event.
 */
const char *nm_event_get_text(NMEvent * event);

/**
 * Returns the source of the event (this will be the full DN of the
 * event source).
 *
 * @param event	The event.
 *
 * @return		The full DN of the event's source.
 */
const char *nm_event_get_source(NMEvent * event);

/**
 * Returns the type of the event. See the defines above for
 * a list of possible event types.
 *
 * @param event	The event.
 *
 * @return		The type of the event.
 *
 */
int nm_event_get_type(NMEvent * event);

/**
 * Returns the time that the event took place.
 *
 * @param event	The event.
 *
 * @return		The timestamp for the event.
 */
time_t nm_event_get_gmt(NMEvent * event);

#endif
