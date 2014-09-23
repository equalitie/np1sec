/*
 * nmconference.h
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

#ifndef __NM_CONFERENCE_H__
#define __NM_CONFERENCE_H__

typedef struct _NMConference NMConference;

#include "nmuserrecord.h"

/* A blank GUID -- represents an uninstatiated conference */
#define BLANK_GUID "[00000000-00000000-00000000-0000-0000]"

/* This is how much of the conference GUIDs to compare when testing
 * to see if two conferences are the same. We cannot compare the
 * entire GUID because the last part is the session count.
 */
#define CONF_GUID_END 27

/**
 * Creates an conference object.
 *
 * The conference should be released by calling
 * nm_release_conference
 *
 * @param guid		The GUID for the conference.
 *
 * @return 			The new NMConference
 */
NMConference *nm_create_conference(const char *guid);

/**
 * Increments the reference count for the conference.
 *
 * The reference to the conference should be released
 * by calling nm_release_conference
 *
 * @param conference	The conference to reference
 */
void nm_conference_add_ref(NMConference * conference);

/**
 * Releases the resources associated with the conference
 * if there are no more references to it, otherwise just
 * decrements the reference count.
 *
 * @param conf		The conference to release
 *
 */
void nm_release_conference(NMConference * conf);

/**
 * Set the GUID for the conference.
 *
 * @param conference	The conference
 * @param guid			The new conference GUID
 *
 */
void nm_conference_set_guid(NMConference * conference, const char *guid);

/**
 * Return the GUID for the conference.
 *
 * @param conference	The conference
 *
 * @return				The GUID for the conference
 */
const char *nm_conference_get_guid(NMConference * conference);

/**
 * Add a participant to the conference.
 *
 * @param conference	The conference
 * @param user_record	The user record to add as a participant
 *
 * @return
 */
void nm_conference_add_participant(NMConference * conference,
								   NMUserRecord * user_record);

/**
 * Remove a participant to the conference.
 *
 * @param conference	The conference
 * @param dn			The dn of the participant to remove
 *
 */
void nm_conference_remove_participant(NMConference * conference, const char *dn);

/**
 * Return the total number of participants in the conference.
 *
 * @param conference	The conference
 *
 * @return				The number of participants for the conference
 *
 */
int nm_conference_get_participant_count(NMConference * conference);

/**
 * Return a participant given an index.
 *
 * @param conference	The conference
 * @param index			The index of the participant to get
 *
 * @return				The participant or NULL if the index is out of range.
 *
 */
NMUserRecord *nm_conference_get_participant(NMConference * conference, int index);

/**
 * Check to see if the conference has been instantiated
 *
 * @param conference	The conference
 *
 * @return				TRUE if the conference has been instantiated,
 *						FALSE otherwise.
 *
 */
gboolean nm_conference_is_instantiated(NMConference * conf);

/**
 * Set the flags for the conference.
 *
 * @param conference	The conference
 * @param flags			The conference flags.
 *
 */
void nm_conference_set_flags(NMConference * conference, guint32 flags);

/**
 * Set the user defined data for the conference.
 *
 * @param conference	The conference
 * @param data			User defined data
 *
 */
void nm_conference_set_data(NMConference * conference, gpointer data);

/**
 * Get the user defined data for the conference.
 *
 * @param conference	The conference
 *
 * @return				The data if it has been set, NULL otherwise.
 *
 */
gpointer nm_conference_get_data(NMConference * conference);

#endif
