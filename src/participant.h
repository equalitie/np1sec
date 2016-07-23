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

#include "exceptions.h"
#include "crypt.h"

namespace np1sec
{

/**
   Participant id

   consists of nickname and "a" fingerprint of public key
   the finger print is compact ed25519 point representation
   in 32 bit (x cordinate and one bit for sign)
 */
struct ParticipantId {
    static const unsigned int c_fingerprint_length = 32;
    std::string nickname;
    uint8_t fingerprint[c_fingerprint_length]; // Finger print is actually the long term public point of participant
                                               // that
    // is x coordinate and one bit for distinguishing the corresponding y

    /**
     * @return nickname|FingerPrint;
     */
    std::string id_to_stringbuffer()
    {
        std::string string_id(nickname);
        string_id.append(reinterpret_cast<char*>(fingerprint), c_fingerprint_length);

        return string_id;
    }

    /**
     *  constructor
     */
    ParticipantId(std::string nickname, std::string fingerprint_strbuff) : nickname(nickname)
    {
        memcpy(fingerprint, fingerprint_strbuff.c_str(), fingerprint_strbuff.size());
    }

    ParticipantId(std::string nickname, AsymmetricKey fingerprint_sexp)
    {
        std::string fingerprint_strbuff(retrieve_result(fingerprint_sexp));
        ParticipantId(nickname, fingerprint_strbuff);
    }

    ParticipantId(std::string nickname_, uint8_t* fingerprint_)
    {
        nickname = nickname_;
        memcpy(fingerprint, fingerprint_, c_fingerprint_length);
    }

    /**
     * Just a default constructor for when we don't want to initiate the
     * participant name and key
     */
    ParticipantId() {}

    /**
     *  constructor using one string buff which has both nick
     *  and fingerprint
     *
     */
    ParticipantId(const std::string& nick_fingerprint_strbuff)
    {
        // TODO:: We need to throw up if the participant format isn't correct
        nickname = nick_fingerprint_strbuff.substr(0, nick_fingerprint_strbuff.size() - c_fingerprint_length);
        if ((nick_fingerprint_strbuff.size() - nickname.size()) != ParticipantId::c_fingerprint_length) {
            logger.error("can not convert string participant id", __FUNCTION__);
            throw MessageFormatException();
        }

        std::string fingerprint_strbuff =
            nick_fingerprint_strbuff.substr(nickname.length(), ParticipantId::c_fingerprint_length);
        memcpy(fingerprint, fingerprint_strbuff.c_str(), fingerprint_strbuff.size());
    }

    /**
     * Access function when the finger print is added later
     */
    void set_fingerprint(std::string fingerprint_strbuff)
    {
        memcpy(fingerprint, fingerprint_strbuff.c_str(), fingerprint_strbuff.size());
    }
};

/**
 * This sturct is used by the client to send the list of participant in
 * the room. consequently np1sec will try to authenticate the participant
 * and establish a group session
 *
 */
struct UnauthenticatedParticipant {
    ParticipantId participant_id;
    uint8_t ephemeral_pub_key[c_ephemeral_key_length]; // This should be in some convienient
    // Format
    bool authenticated;

    /**
    * constructor
    */
    UnauthenticatedParticipant(ParticipantId participant_id, std::string ephemeral_pub_key, bool authenticated = false)
        : participant_id(participant_id), authenticated(authenticated)

    {
        memcpy(this->ephemeral_pub_key, ephemeral_pub_key.c_str(), c_ephemeral_key_length);
    }

    UnauthenticatedParticipant(ParticipantId participant_id, uint8_t* ephemeral_pub_key, bool authenticated = false)
        : participant_id(participant_id), authenticated(authenticated)

    {
        memcpy(this->ephemeral_pub_key, ephemeral_pub_key, c_ephemeral_key_length);
    }

    /**
     * default constructor when we don't want to setup a participant
     */
    UnauthenticatedParticipant() {}

    /**
     * Default copy constructor
     */
    UnauthenticatedParticipant(const UnauthenticatedParticipant& rhs)
        : participant_id(rhs.participant_id), authenticated(rhs.authenticated)
    {
        memcpy(this->ephemeral_pub_key, rhs.ephemeral_pub_key, c_ephemeral_key_length);
    }

    /**
     * turns a string of type:
     *
     *  nickfingerprintephemeralkey
     *
     * to an authenticated particpiant
     */
    UnauthenticatedParticipant(const std::string& participant_id_and_ephmeralkey)
        : participant_id((participant_id_and_ephmeralkey.size() > c_ephemeral_key_length + sizeof(DTByte)
                              ? participant_id_and_ephmeralkey.substr(0, participant_id_and_ephmeralkey.size() -
                                                                             c_ephemeral_key_length - 1)
                              : ""))
    {
        if (participant_id_and_ephmeralkey.size() < c_ephemeral_key_length + sizeof(DTByte)) {
            logger.error("can not convert string to unauthenticated participant", __FUNCTION__);
            throw MessageFormatException();
        }
        std::string ephemeral_pub_key = participant_id_and_ephmeralkey.substr(participant_id_and_ephmeralkey.size() -
                                                                              c_ephemeral_key_length - sizeof(DTByte));

        memcpy(this->ephemeral_pub_key, ephemeral_pub_key.c_str(), c_ephemeral_key_length);
        authenticated = (participant_id_and_ephmeralkey.back() == 1);
    };

    std::string unauthed_participant_to_stringbuffer()
    {
        std::string string_id(participant_id.id_to_stringbuffer());
        string_id += std::string(reinterpret_cast<char*>(ephemeral_pub_key), c_ephemeral_key_length);
        string_id += static_cast<char>(authenticated ? 1 : 0);
        return string_id;
    }
};

typedef std::list<UnauthenticatedParticipant> UnauthenticatedParticipantList;

class ParticipantInSessionProperties
{
    // TOOD move all session related values here
};

/**
 * This class keeps the state of each participant in the room, including the
 * user themselves.
 */
class Participant
{
  public:
    ParticipantId id;
    PublicKey long_term_pub_key;
    PublicKey ephemeral_key = nullptr;
    MessageId last_acked_message_id;
    void* send_ack_timer = nullptr;
    edCurvePublicKey raw_ephemeral_key = {};
    edCurvePublicKey future_raw_ephemeral_key = {};
    // MessageDigest message_digest;

    np1secKeyShare cur_keyshare;
    np1secSymmetricKey p2p_key = {};
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

    // Participant* thread_user_as_participant;

    // default copy constructor
    Participant(const Participant& rhs)
        : id(rhs.id), long_term_pub_key(rhs.long_term_pub_key), authenticated(rhs.authenticated),
          authed_to(rhs.authed_to), key_share_contributed(rhs.key_share_contributed), index(rhs.index)

    {
        long_term_pub_key = copy_crypto_resource(rhs.long_term_pub_key);
        set_ephemeral_key(rhs.raw_ephemeral_key);
        memcpy(future_raw_ephemeral_key, rhs.future_raw_ephemeral_key, sizeof(edCurvePublicKey));
        memcpy(p2p_key, rhs.p2p_key, sizeof(np1secSymmetricKey));
        memcpy(cur_keyshare, rhs.cur_keyshare, sizeof(np1secKeyShare));
    }

    enum ForwardSecracyContribution { NONE, EPHEMERAL, KEY_SHARE };

    ForwardSecracyContribution ForwardSecracyStatus = NONE;

    /**
     * crypto material access functions
     */
    void set_ephemeral_key(const edCurvePublicKey raw_ephemeral_key)
    {
        release_crypto_resource(this->ephemeral_key);
        // delete [] this->raw_ephemeral_key; doesn't make sense to delete const length array
        memcpy(this->raw_ephemeral_key, raw_ephemeral_key, sizeof(edCurvePublicKey));
        ephemeral_key = reconstruct_public_key_sexp(
            std::string(reinterpret_cast<const char*>(raw_ephemeral_key), c_ephemeral_key_length));
    }

    /**
     * store the encrypted keyshare and set the contributed flag true
     *
     */
    void set_key_share(const np1secKeyShare new_key_share)
    {
        memcpy(this->cur_keyshare, new_key_share, sizeof(np1secKeyShare));
        key_share_contributed = true;
    }

    /**
     * computes the p2p triple dh secret between participants
     *
     * throw an exception in case it fails
     */
    void compute_p2p_private(AsymmetricKey thread_user_id_key, Cryptic* thread_user_crypto);

    /**
     * Generate the approperiate authentication token to send to the
     * to the participant so they trust (authenticate us)
     *
     * @param auth_token authentication token received as a message
     *
     * throw an exception in case it fails
     */
    void authenticate_to(Token auth_token, const AsymmetricKey thread_user_id_key,
                         Cryptic* thread_user_crypto);

    /**
     * Generate the approperiate authentication token check its equality
     * to authenticate the alleged participant
     *
     * @param auth_token authentication token received as a message
     *
     * throw and exception if authentication fails
     */
    void be_authenticated(std::string authenicator_id, const Token auth_token,
                          AsymmetricKey thread_user_id_key, Cryptic* thread_user_crypto);

    /**
     * default constructor
     * TODO: This only exists because stl asks for it
     * don't use it
     */
    Participant() : id(""), long_term_pub_key(nullptr), key_share_contributed(false)
    {
        logger.abort("not suppose to actually use the default constructor of Participant class");
    }

    Participant(const UnauthenticatedParticipant& unauth_participant)
        : id(unauth_participant.participant_id),
          long_term_pub_key(reconstruct_public_key_sexp(
              hash_to_string_buff(unauth_participant.participant_id.fingerprint))),
          authenticated(false), authed_to(false), key_share_contributed(false)
    {
        set_ephemeral_key(unauth_participant.ephemeral_pub_key);
    }

    // destructor
    ~Participant()
    {
        // release gcrypt stuff
        release_crypto_resource(this->ephemeral_key);
        release_crypto_resource(this->long_term_pub_key);
        // TODO - Verify with Vmon that these are necessary
        //secure_wipe(ephemeral_key, c_hash_length);
        //secure_wipe(raw_ephemeral_key, c_hash_length);
        //secure_wipe(future_raw_ephemeral_key, c_hash_length);
        secure_wipe(cur_keyshare, c_hash_length);
        secure_wipe(p2p_key, c_hash_length);
        //logger.debug("Wiped ephemeral_key from Participant");
        //logger.debug("Wiped raw_ephemeral_key from Participant");
        //logger.debug("Wiped cur_keyshare from Participant");
        logger.debug("Wiped future_raw_ephemeral_key from Participant");
        logger.debug("Wiped p2p_key from Participant");
    }
};

typedef std::map<std::string, Participant> ParticipantMap;

/**
 * To be used in std::sort to sort the particpant list
 * in a way that is consistent way between all participants
 */
bool sort_by_long_term_pub_key(const AsymmetricKey lhs, const AsymmetricKey rhs);

/**
 * operator < needed by map class not clear why but it doesn't compile
 * It first does nick name check then public key check. in reality
 * public key check is not needed as the nickname are supposed to be
 * unique (that is why nickname is more approperiate for sorting than
 * public key)
 */
bool operator<(const Participant& rhs, const Participant& lhs);

/**
 *  this is basically the merge function
 */
ParticipantMap operator+(const ParticipantMap& lhs, const ParticipantMap& rhs);

/**
 * this is basically the difference function
 */
ParticipantMap operator-(const ParticipantMap& lhs, const ParticipantMap& rhs);

/**
 * get a ParticipantMap and make a string containing the names
 * of the participant suitable for printing out
 */
std::string participants_to_string(const ParticipantMap& plist);

} // namespace np1sec

#endif // SRC_PARTICIPANT_H_
