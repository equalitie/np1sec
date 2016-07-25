/**
 * Multiparty Off-the-Record Messaging library
 * Copyright (C) 2014, eQualit.ie
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of version 3 of the GNU Lesser General
 *  License as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */
#ifndef SRC_TRANSCRIPT_CONSISTENCY_H_
#define SRC_TRANSCRIPT_CONSISTENCY_H_
// this header files contains the structure needed for transcript consistency
// check it moved out of session.h to make the code easier to read and follow

namespace np1sec
{

class UserState;
class Session;

/**
 * Structure for ops data for waiting timer for receiving ack
 * from other participants
 */
struct AckTimerOps {
    Session* session;
    Participant* participant;
    MessageId message_id;

    AckTimerOps() : session(nullptr), participant(nullptr){}; // This is to make [] of map
    // working, but soon we'll move to another type

    AckTimerOps(Session* session, Participant* participant, uint32_t message_parent_id)
        : session(session), participant(participant), message_id(message_parent_id)
    {
    }
};

struct ParticipantConsistencyBlock {
    bool have_transcript_hash;
    HashBlock transcript_hash;
    void* consistency_timer;
    AckTimerOps ack_timer_ops;
};

typedef std::vector<ParticipantConsistencyBlock> ConsistencyBlockVector;

} // namespace np1sec

#endif
