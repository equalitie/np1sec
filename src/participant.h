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
#include <event2/event.h>

#include "exceptions.h"
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
   * Just a default constructor for when we don't want to initiate the
   * participant name and key
   */
  ParticipantId()
  {
  }
  
  /**
   *  constructor using one string buff which has both nick 
   *  and fingerprint
   *
   */
  ParticipantId(std::string nick_clone_fingerprint_strbuff)
  {
    //TODO:: We need to throw up if the participant format isn't correct
    std::string nickname = nick_clone_fingerprint_strbuff.substr(0, nick_clone_fingerprint_strbuff.find(c_subfield_delim.c_str()));
    if ((nick_clone_fingerprint_strbuff.size() - nickname.size()) != ParticipantId::c_fingerprint_length)
      throw np1secMessageFormatException();
    
    std::string fingerprint_strbuff = nick_clone_fingerprint_strbuff.substr(nickname.length() + c_subfield_delim.length() , ParticipantId::c_fingerprint_length);
    memcpy(fingerprint, fingerprint_strbuff.c_str(), fingerprint_strbuff.size());
  }

  /**
   * copy constructor
   */
  ParticipantId(const ParticipantId& lhs)
  :nickname(lhs.nickname)
  {
    memcpy(fingerprint, lhs.fingerprint, c_fingerprint_length);
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
  uint8_t ephemeral_pub_key[c_ephemeral_key_length];  // This should be in some convienient 
  // Format
  bool authenticated;

  /**
  * constructor 
  */
UnauthenticatedParticipant(ParticipantId participant_id, std::string ephemeral_pub_key, bool authenticated = false)
:participant_id (participant_id),
    authenticated(authenticated)
     
  {
    memcpy(this->ephemeral_pub_key, ephemeral_pub_key.c_str(), c_ephemeral_key_length);
  }

  /**
   * default constructor when we don't want to setup a participant
   */
  UnauthenticatedParticipant()
  {
  }
  
  /**
   * Default copy constructor
   */
  UnauthenticatedParticipant(const UnauthenticatedParticipant& rhs)
  :participant_id(rhs.participant_id), authenticated(rhs.authenticated)
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
    //TODO:: We need to throw up if the participant format isn't correct
    std::string ephemeral_pub_key =
      participant_id_and_ephmeralkey.substr(
                                            participant_id.nickname.length() +
                                            c_subfield_delim.length() +
                                            ParticipantId::c_fingerprint_length,
                                            c_ephemeral_key_length);
    
    memcpy(this->ephemeral_pub_key, ephemeral_pub_key.c_str(), c_ephemeral_key_length);

  }

  std::string unauthed_participant_to_stringbuffer() {
    std::string string_id(participant_id.id_to_stringbuffer());
    string_id += std::string(reinterpret_cast<char*>(ephemeral_pub_key), sizeof(c_ephemeral_key_length));
    return string_id;
  }
  
};

typedef std::list<UnauthenticatedParticipant> UnauthenticatedParticipantList;

class ParticipantInSessionProperties {
  //TOOD move all session related values here

};

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
  np1secPublicKey long_term_pub_key = nullptr;
  np1secPublicKey ephemeral_key = nullptr;
  MessageId last_acked_message_id;
  void* send_ack_timer;
  HashBlock raw_ephemeral_key = {};
  // MessageDigest message_digest;

  np1secKeyShare cur_keyshare;
  HashBlock p2p_key = {};
  bool authenticated;
  bool authed_to;
  bool key_share_contributed;
  unsigned int index; //keep the place of the partcipant in sorted peers array
   /* this is the i in U_i and we have
                                participants[peers[i]].index == i
                                tautology
                                
                                sorry we barely have space for half
                                half of human kind in a room :(
                             */

  // np1secKeySHare future_key_share;

  //default copy constructor
  Participant(const Participant& rhs)
    :
  id(rhs.id),
    long_term_pub_key(rhs.long_term_pub_key),
    authenticated(rhs.authenticated),
    authed_to(rhs.authed_to),
    thread_user_crypto(rhs.thread_user_crypto),
    send_ack_timer(nullptr),
    key_share_contributed(rhs.key_share_contributed),
    index(rhs.index)
    
  {
    long_term_pub_key = Cryptic::copy_crypto_resource(rhs.long_term_pub_key);
    set_ephemeral_key(rhs.raw_ephemeral_key);
    memcpy(p2p_key, rhs.p2p_key, sizeof(HashBlock));
  }
  
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
  bool set_ephemeral_key(const HashBlock raw_ephemeral_key)
  {
    Cryptic::release_crypto_resource(this->ephemeral_key);
    //delete [] this->raw_ephemeral_key; doesn't make sense to delete const length array
    memcpy(this->raw_ephemeral_key, raw_ephemeral_key, sizeof(HashBlock));
    ephemeral_key = Cryptic::reconstruct_public_key_sexp(std::string(reinterpret_cast<const char*>(raw_ephemeral_key), c_ephemeral_key_length));

    return (ephemeral_key != nullptr);
  }

  /**
   * store the encrypted keyshare and set the contributed flag true
   *
   */
  void set_key_share(const HashBlock new_key_share)
  {
    memcpy(this->cur_keyshare, new_key_share, sizeof(HashBlock));
    key_share_contributed = true;

  }

  /**
   * Generate the approperiate authentication token to send to the
   * to the participant so they trust (authenticate us)
   *
   * @param auth_token authentication token received as a message
   * 
   * @return true if peer's authenticity could be established
   */
  bool authenticate_to(HashBlock auth_token, const np1secAsymmetricKey thread_user_id_key);

  /**
   * Generate the approperiate authentication token check its equality
   * to authenticate the alleged participant
   *
   * @param auth_token authentication token received as a message
   * 
   * @return true if peer's authenticity could be established
   */
  bool be_authenticated(std::string authenicator_id, const HashBlock auth_token, np1secAsymmetricKey thread_user_id_key);

  /**
   * default constructor
   * TODO: This only exists because stl asks for it
   * don't use it
   */
  Participant()
    : id(""),
    ephemeral_key(nullptr),
    authenticated(false),
    authed_to(false)
      {
        assert(0);
      }
    
 Participant(const UnauthenticatedParticipant& unauth_participant, Cryptic* thread_crypto)
   :id(unauth_participant.participant_id),
    authenticated(false),
    authed_to(false),
    long_term_pub_key(Cryptic::reconstruct_public_key_sexp(Cryptic::hash_to_string_buff(unauth_participant.participant_id.fingerprint))),
    thread_user_crypto(thread_crypto),
    send_ack_timer(nullptr)

      {
        set_ephemeral_key(unauth_participant.ephemeral_pub_key);
      }

  //destructor
  ~Participant()
    {
      //release gcrypt stuff
      Cryptic::release_crypto_resource(this->ephemeral_key);
      Cryptic::release_crypto_resource(this->long_term_pub_key);

    }
};

/**
 * To be used in std::sort to sort the particpant list
 * in a way that is consistent way between all participants
 */
bool sort_by_long_term_pub_key(const Participant& lhs, const Participant& rhs);

/**
 * operator < needed by map class not clear why but it doesn't compile
 * It first does nick name check then public key check. in reality
 * public key check is not needed as the nickname are supposed to be 
 * unique (that is why nickname is more approperiate for sorting than
 * public key)
 */
bool operator<(const Participant& rhs, const Participant& lhs);

#endif  // SRC_PARTICIPANT_H_
