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
#include <event2/event.h>
#include "src/crypt.h"

/**
   Participant id
   
   consists of nickname and "a" fingerprint of public key
   the finger print is compact ed25519 point representation
   in 32 bit (x cordinate and one bit for sign)
 */
struct ParticipantId
{
  static const unsigned int c_fingerprint_length = 32;
  std::string nickname;
  uint8_t fingerprint[c_fingerprint_length]; //Finger print is actually the long term public point of participant that
  //is x coordinate and one bit for distinguishing the corresponding y

  /**
   * @return nickname|FingerPrint;
   */
  std::string id_to_stringbuffer() {
    std::string string_id(nickname);
    string_id += c_subfield_delim; 
    string_id.append(reinterpret_cast<char*>(fingerprint), c_fingerprint_length);

    return string_id;
  }

  /**
   *  constructor
   *
   */
  ParticipantId(std::string nickname, std::string fingerprint_strbuff)
  :nickname(nickname)
  {
    memcpy(fingerprint, fingerprint_strbuff.c_str(), fingerprint_strbuff.size());
  }

  ParticipantId(std::string nickname, np1secAsymmetricKey fingerprint_sexp)
  {
    std::string fingerprint_strbuff(Cryptic::retrieve_result(fingerprint_sexp));
    ParticipantId(nickname, fingerprint_strbuff);
  }

  /**
   *  constructor using one string buff which has both nick 
   *  and fingerprint
   *
   */
  ParticipantId(std::string nick_clone_fingerprint_strbuff)
  {
    //TODO:: We need to throw up if the format isn't correct
    std::string nickname = nick_clone_fingerprint_strbuff.substr(0, nick_clone_fingerprint_strbuff.find(c_subfield_delim.c_str()));
    std::string fingerprint_strbuff = nick_clone_fingerprint_strbuff.substr(nickname.length() + c_subfield_delim.length() , ParticipantId::c_fingerprint_length);
    memcpy(fingerprint, fingerprint_strbuff.c_str(), fingerprint_strbuff.size());
  }

  /**
   * copy constructor
   */
  ParticipantId(const ParticipantId& lhs)
  {
    nickname = lhs.nickname;
    memcpy(fingerprint, lhs.fingerprint, c_fingerprint_length);
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
  HashBlock ephemeral_pub_key;  // This should be in some convienient 
  // Format

  /**
  * constructor 
  */
  UnauthenticatedParticipant(ParticipantId participant_id, std::string ephemeral_pub_key)
   :participant_id (participant_id)
  {
    memcpy(this->ephemeral_pub_key, ephemeral_pub_key.c_str(), c_ephemeral_key_length);
  }

  /**
   * Default copy constructor
   */
  UnauthenticatedParticipant(const UnauthenticatedParticipant& rhs)
  :participant_id(rhs.participant_id)
  {
    memcpy(this->ephemeral_pub_key, rhs.ephemeral_pub_key, c_ephemeral_key_length);
  }
  
  /**
   * turns a string of type:
   * 
   *  nick:fingerprintephemeralkey 
   *
   * to an authenticated particpiant
   */
UnauthenticatedParticipant(std::string participant_id_and_ephmeralkey)
:participant_id(participant_id_and_ephmeralkey)
  {
    std::string ephemeral_pub_key = participant_id_and_ephmeralkey.substr(participant_id.nickname.length() + c_subfield_delim.length() + ParticipantId::c_fingerprint_length, c_ephemeral_key_length);
    memcpy(this->ephemeral_pub_key, ephemeral_pub_key.c_str(), c_ephemeral_key_length);
    
  }
  
};

typedef std::list<UnauthenticatedParticipant> UnauthenticatedParticipantList;
/** 
 * This class keeps the state of each participant in the room, including the
 * user themselves.
 */
class Participant {
 protected:
  /**
   * computes the p2p triple dh secret between participants
   *
   * @return true on success
   */
  bool compute_p2p_private(np1secAsymmetricKey thread_user_id_key);

  Cryptic* thread_user_crypto;
  Participant* thread_user_as_participant;
  
 public:
  ParticipantId id;
  np1secPublicKey long_term_pub_key;
  np1secPublicKey ephemeral_key;
  event* receive_ack_timer;
  event* send_ack_timer;
  HashBlock raw_ephemeral_key = {};
  // MessageDigest message_digest;

  np1secKeyShare cur_keyshare;
  HashBlock p2p_key = {};
  bool authenticated;
  bool authed_to;
  // np1secKeySHare future_key_share;

  uint32_t in_session_index; /* this is the i in U_i and we have
                                participants[peers[i]].index == i
                                tautology
                                
                                sorry we barely have space for half
                                half of human kind in a room :(
                             */

  enum ForwardSecracyContribution {
    NONE,
    EPHEMERAL,
    KEY_SHARE
  };

  ForwardSecracyContribution ForwardSecracyStatus = NONE;

  /**
   * running thread user crypto access function
   */
  void set_thread_user_crypto(Cryptic* cryptic)
  {
    thread_user_crypto = cryptic;
  }
    
  /**
   * crypto material access functions
   *
   * @return true if successfully updated to the new key
   */
  bool set_ephemeral_key(HashBlock raw_ephemeral_key)
  {
    gcry_sexp_release(ephemeral_key);
    delete [] raw_ephemeral_key;
    memcpy(this->raw_ephemeral_key, raw_ephemeral_key, sizeof(HashBlock));
    ephemeral_key = Cryptic::convert_to_sexp(std::string(reinterpret_cast<char*>(raw_ephemeral_key), c_ephemeral_key_length));

    return (ephemeral_key != nullptr);
  }
  
  /**
   * Generate the approperiate authentication token check its equality
   * to authenticate the alleged participant
   *
   * @param auth_token authentication token received as a message
   * 
   * @return true if peer's authenticity could be established
   */
  bool authenticate_to(HashBlock auth_token, np1secAsymmetricKey thread_user_id_key);
  bool be_authenticated(std::string authenicator_id, HashBlock auth_token, np1secAsymmetricKey thread_user_id_key);

  /**
   * default constructor
   */
 Participant(ParticipantId participant_id)
   :id(participant_id),
    ephemeral_key(nullptr),
    authenticated(false),
    authed_to(false),
    long_term_pub_key(Cryptic::convert_to_sexp(reinterpret_cast<char*>(participant_id.fingerprint))) 
      {
      }

};

/**
 * To be used in std::sort to sort the particpant list
 * in a way that is consistent way between all participants
 */
bool sort_by_long_term_pub_key(Participant& lhs, Participant& rhs);

#endif  // SRC_PARTICIPANT_H_
