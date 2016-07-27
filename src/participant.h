/**
 * Multiparty Off-the-Record Messaging library
 * Copyright (C) 2014, eQualit.ie
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of version 3 of the GNU Lesser General
 * Public License as published by the Free Software Foundation.
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

#ifndef SRC_PARTICIPANT_H_
#define SRC_PARTICIPANT_H_

#include <string>
#include <list>
#include <map>

#include "crypto.h"
#include "logger.h"

namespace np1sec
{

/**
 * This class keeps the state of each participant in the room, including the
 * user themselves.
 */
class Participant
{
  public:
    std::string nickname;
    PublicKey long_term_public_key;
    PublicKey ephemeral_public_key;
    PublicKey next_ephemeral_public_key;

    uint32_t last_acked_message_id;
    void* send_ack_timer = nullptr;

    Hash cur_keyshare;
    SymmetricKey p2p_key;
    bool authenticated = false;
    bool authed_to = false;
    bool key_share_contributed;
    bool leaving = false;

    uint32_t index; // keep the place of the partcipant in sorted peers array
    /* this is the i in U_i and we have
                                 participants[peers[i]].index == i
                                 tautology

                                 sorry we barely have space for half
                                 of human kind in a room :( on the other
                                 hand if you cramp 4billion people in
                                 a room, you have little reason to keep
                                 the transcript confidential
                              */

    enum ForwardSecracyContribution { NONE, EPHEMERAL, KEY_SHARE };

    ForwardSecracyContribution ForwardSecracyStatus = NONE;

    /**
     * crypto material access functions
     */
    void set_ephemeral_key(const PublicKey& ephemeral_key)
    {
        ephemeral_public_key = ephemeral_key;
    }

    /**
     * store the encrypted keyshare and set the contributed flag true
     *
     */
    void set_key_share(const Hash& new_key_share)
    {
        cur_keyshare = new_key_share;
        key_share_contributed = true;
    }

    /**
     * computes the p2p triple dh secret between participants
     *
     * throw an exception in case it fails
     */
    void compute_p2p_private(const PrivateKey& long_term_private_key, const PrivateKey& ephemeral_private_key);

    /**
     * Generate the approperiate authentication token to send to the
     * to the participant so they trust (authenticate us)
     *
     * throw an exception in case it fails
     */
    Hash authenticate_to(const PrivateKey& long_term_private_key, const PrivateKey& ephemeral_private_key);

    /**
     * Generate the approperiate authentication token check its equality
     * to authenticate the alleged participant
     *
     * @param auth_token authentication token received as a message
     *
     * throw and exception if authentication fails
     */
    void be_authenticated(const std::string& nickname, const Hash& key_confirmation,
                          const PrivateKey& long_term_private_key, const PrivateKey& ephemeral_private_key);

    /**
     * default constructor
     * TODO: This only exists because stl asks for it
     * don't use it
     */
    Participant()
    {
        logger.abort("not suppose to actually use the default constructor of Participant class");
    }

    Participant(const std::string& nickname, const PublicKey& long_term_public_key, const PublicKey& ephemeral_public_key):
        nickname(nickname),
        long_term_public_key(long_term_public_key),
        ephemeral_public_key(ephemeral_public_key),
        authenticated(false),
        authed_to(false),
        key_share_contributed(false)
    {}
};

typedef std::map<std::string, Participant> ParticipantMap;

bool operator<(const Participant& rhs, const Participant& lhs);

/**
 *  this is basically the merge function
 */
ParticipantMap operator+(const ParticipantMap& lhs, const ParticipantMap& rhs);

/**
 * this is basically the difference function
 */
ParticipantMap operator-(const ParticipantMap& lhs, const ParticipantMap& rhs);

} // namespace np1sec

#endif // SRC_PARTICIPANT_H_
