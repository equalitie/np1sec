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

class np1secUserState;
class np1secSession;

class MessageDigest
{
  public:
    HashBlock digest;
    uint32_t message_id;

    void update(std::string new_message);

    /**
     * Compute a unique globally ordered id from the time stamped message,
     * ultimately this function should be overridable by the client.
     */
    uint32_t compute_message_id(std::string cur_message);
};

/**
 * Structure for ops data for waiting timer for receiving ack
 * from other participants
 */
struct AckTimerOps {
    np1secSession* session;
    Participant* participant;
    MessageId message_id;

    AckTimerOps() : session(nullptr), participant(nullptr){}; // This is to make [] of map
    // working, but soon we'll move to another type

    AckTimerOps(np1secSession* session, Participant* participant, uint32_t message_parent_id)
        : session(session), participant(participant), message_id(message_parent_id)
    {
    }
};

struct ParticipantConsistencyBlock {
    HashStdBlock transcript_hash;
    void* consistency_timer;
    AckTimerOps ack_timer_ops;
};

typedef std::vector<ParticipantConsistencyBlock> ConsistencyBlockVector;

/* /\** */
/*  * Callback function to manage sending of heartbeats */
/*  * */
/*  *\/ */
/* static void cb_send_heartbeat(void *arg); */

/* /\** */
/*  * Callback function to cause automatic sending of ack for  */
/*  * received message */
/*  * */
/*  *\/ */
/* static void cb_send_ack(void *arg); */

/* /\** */
/*  * Callback function to cause automatic warning if ack not */
/*  * received for previously sent message */
/*  * */
/*  *\/ */
/* static void cb_ack_not_received(void *arg); */

/* /\** */
/*  * The timer set upon of sending a message. */
/*  * when this timer is timed out means that  */
/*  * we haven't received our own message */
/*  *\/ */
/* static void cb_ack_not_sent(void* arg); */

/* /\** */
/*  * when times out, the leaving user check  */
/*  * all user's consistency before leaving */
/*  *\/ */
/* static void cb_leave(void *arg); */

} // namespace np1sec

#endif
