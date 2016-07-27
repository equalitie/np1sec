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

#include <algorithm>
#include <cstring>

#include "exceptions.h"
#include "participant.h"

namespace np1sec
{

/**
 * operator < needed by map class not clear why but it doesn't compile
 * It first does nick name check then public key check. in reality
 * public key check is not needed as the nickname are supposed to be
 * unique (that is why nickname is more approperiate for sorting than
 * public key)
 */
bool operator<(const Participant& lhs, const Participant& rhs)
{
    if (lhs.nickname < rhs.nickname) {
        return true;
    } else if (lhs.nickname > rhs.nickname) {
        return false;
    } else {
        return lhs.long_term_public_key < rhs.long_term_public_key;
    }
}

/**
 * Generate the approperiate authentication token check its equality
 * to authenticate the alleged participant
 *
 * @param auth_token authentication token received as a message
 * @param authenicator_id running thread user id  //TODO
 *  can give it to youget rid of this as thread_user_as_partcipant
 * @param thread_user_id_key the key (pub & prive) of the user running the
 *        thread
 *
 * @return true if peer's authenticity could be established
 */
void Participant::be_authenticated(const std::string& nickname, const Hash& key_confirmation,
                                   const PrivateKey& long_term_private_key, const PrivateKey& ephemeral_private_key)
{
    compute_p2p_private(long_term_private_key, ephemeral_private_key);

    std::string hash_buffer;
    hash_buffer += p2p_key.key.as_string();
    hash_buffer += nickname;
    hash_buffer += long_term_private_key.public_key().as_string();
    if (key_confirmation == crypto::hash(hash_buffer, true)) {
        this->authenticated = true;
    } else {
        logger.warn("participant " + nickname + " failed TDH authentication");
        throw AuthenticationException();
    }
}

/**
 * Generate the approperiate authentication token check its equality
 * to authenticate the alleged participant
 */
Hash Participant::authenticate_to(const PrivateKey& long_term_private_key, const PrivateKey& ephemeral_private_key)
{
    compute_p2p_private(long_term_private_key, ephemeral_private_key);

    std::string hash_buffer;
    hash_buffer += p2p_key.key.as_string();
    hash_buffer += nickname;
    hash_buffer += long_term_public_key.as_string();
    return crypto::hash(hash_buffer, true);
}

/**
 * computes the p2p triple dh secret between participants
 *
 * @return true on success
 */
void Participant::compute_p2p_private(const PrivateKey& long_term_private_key, const PrivateKey& ephemeral_private_key)
{
    p2p_key.key = crypto::triple_diffie_hellman(
        long_term_private_key,
        ephemeral_private_key,
        long_term_public_key,
        ephemeral_public_key,
        long_term_public_key < long_term_private_key.public_key()
    );
}

/**
 *  this is basically the merge function
 */
ParticipantMap operator+(const ParticipantMap& lhs, const ParticipantMap& rhs)
{
    ParticipantMap result(lhs);

    result.insert(rhs.begin(), rhs.end());
    return result;
}

/**
 * this is basically the difference function
 */
ParticipantMap operator-(const ParticipantMap& lhs, const ParticipantMap& rhs)
{
    ParticipantMap difference;

    std::set_difference(lhs.begin(), lhs.end(), rhs.begin(), rhs.end(), std::inserter(difference, difference.end()));

    return difference;
}

} // namespace np1sec
