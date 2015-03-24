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
#include <event2/event.h>
#include "src/crypt.h"

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
  std::string id; //nickname;
  std::string nickname;
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
  bool set_ephmeral_key(HashBlock raw_ephemeral_key)
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
   * default constructoro
   */
 Participant(std::string participant_id = "")
   :id(participant_id),
    ephemeral_key(nullptr),
    authenticated(false),
    authed_to(false){
    
  }

};

/**
 * To be used in std::sort to sort the particpant list
 * in a way that is consistent way between all participants
 */
bool sort_by_long_term_pub_key(Participant& lhs, Participant& rhs);

#endif  // SRC_PARTICIPANT_H_
