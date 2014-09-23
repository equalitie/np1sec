/*
 * nmmessage.h
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

#ifndef __NM_MESSAGE_H__
#define __NM_MESSAGE_H__

typedef struct _NMMessage NMMessage;

#include "nmconference.h"

/**
 * Creates a new message.
 *
 * The returned message should be released by calling
 * nm_release_message
 *
 * @param	text	The message text
 * @return			A newly allocated message
 */
NMMessage *nm_create_message(const char *text);

/**
 * Increment the reference count for the message object.
 *
 * @param	msg		The message
 */
void nm_message_add_ref(NMMessage * msg);

/**
 * Releases a message.
 *
 * @param	msg		The message
 */
void nm_release_message(NMMessage * msg);

/**
 * Returns the message text
 *
 * @param	msg		The message
 * @return 			The message text
 */
const char *nm_message_get_text(NMMessage * msg);

/**
 * Sets the conference object for a message
 *
 * @param	msg		The message
 * @param	conf	The conference to associate with the message
 * @return			RVALUE_OK on success
 */
void nm_message_set_conference(NMMessage * msg, NMConference * conf);

/**
 * Returns the conference object associated with the message
 *
 * Note: this does not increment the reference count for the
 * conference and the conference should NOT be released with
 * nm_release_conference. If the reference needs to be kept
 * around nm_conference_add_ref should be called.
 *
 * @param	msg		The message
 * @return			The conference associated with this message
 */
NMConference *nm_message_get_conference(NMMessage * msg);

#endif
