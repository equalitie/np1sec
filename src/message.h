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

#ifndef SRC_MESSAGE_H_
#define SRC_MESSAGE_H_

#include "src/common.h"
#include "src/interface.h"
#include "src/crypt.h"
#include "src/base64.h"

class np1secMessage {
 protected:
  Cryptic cryptic;

  std::vector<std::string> &split(const std::string &s,
                                  char delim,
                                  std::vector<std::string> &elems) {
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, delim)) {
        elems.push_back(item);
    }
    return elems;
  }


  std::vector<std::string> split(const std::string &s, char delim) {
    std::vector<std::string> elems;
    split(s, delim, elems);
    return elems;
  }

 public:
  enum np1secMessageType {
    UNKNOWN,
    JOINER_AUTH,
    JOIN_REQUEST,
    PARTICIPANTS_INFO,
    SESSION_CONFIRMATION,
    SESSION_HALT,
    GROUP_SHARE,
    USER_MESSAGE,
    PURE_META_MESSAGE,
    LEAVE_REQUEST,
    FAREWELL,
    SESSION_P_LIST,
    TOTAL_NO_OF_MESSAGE_TYPE //This should be always the last message type

  };

  np1secMessageType message_type;
  uint32_t message_id;
  SessionID session_id;
  std::string sender_id;
  std::string user_message;
  std::string meta_message;
  std::string sys_message;
  np1secLoadFlag meta_load_flag;
  std::string meta_load;
  int meta_only;
  HashBlock transcript_chain_hash;
  std::string nonce;
  std::string z_sender;
  std::vector<UnauthenticatedParticipant> session_view;
  std::string session_key_confirmation;
  std::string key_confirmation;
  std::string joiner_info;
  std::vector<std::string> pstates;

  /*
   * Construct a new np1secMessage based on a set of message components
   * as input
   */
  np1secMessage(SessionID session_id, std::string sender_id,
                std::string user_message, np1secMessageType message_type,
                HashBlock* transcript_chain_hash, np1secLoadFlag meta_load_flag,
                std::string meta_load, std::vector<std::string> pstates,
                Cryptic cryptic);

  /*
   * Construct a new np1secMessage based on a set of message components
   * based on an encrypted message as input
   */
  np1secMessage(std::string raw_message, Cryptic cryptic);

  /*
   * Construct a new np1secMessage for p_infotem messages
   * based on a set of input components 
   **/
  np1secMessage(SessionID session_id,
                             np1secMessageType message_type,
                             std::string session_view,
                             std::string key_confirmation,
                             std::string session_key_confirmation,
                             std::string joiner_info,
                             std::string z_sender);

  /**
   * @return if the message is of type PARTICIPANTS_INFO it returns 
   *         the list of participants with their ephemerals otherwise
   *         throw an exception
   */
  std::vector<UnauthenticatedParticipant> participants_in_the_room();

  std::string session_view_as_string();

  void string_to_session_view(std::string sv_string);

  /**
   * Compute a unique globally ordered id from the time stamped message,
   * ultimately this function should be overridable by the client.
   */
  uint32_t compute_message_id(std::string cur_message);

  /**
   * Base 64 encode encrypted message
   *
   */
  std::string base64_encode(std::string message);

  /**
   * Base 64 decode encrypted message
   *
   */
  std::string base64_decode(std::string encode_message);

  /**
   * Create and return a signed form of the message
   *
   */
  std::string sign_message(std::string message);

  /**
   * Verify the message
   *
   */
  bool verify_message(std::string signed_message, std::string signature);

  /**
   * Create and return an encrypted form of the signed message
   *
   */
  std::string encrypt_message(std::string signed_message);

  /**
   * Decrypt and return the raw form of the message
   *
   */
  std::string decrypt_message(std::string encrypted_message);

  /**
   * Compose message into sendable formt
   *
   */
  std::string format_sendable_message();

  /**
   * Format p_info message for inclusion for
   * standalone use
   *
   */
  void format_generic_message();

  /**
   * Unwrap p_info message into its constituent components
   *
   */
  void unwrap_generic_message();

  void unwrap_user_message();

  /**
   * Format Meta message for inclusion with standard message or for
   * standalone use
   *
   */
  void format_meta_message();

  /**
   * Unwrap meta message into its constituent components
   *
   */
  void unwrap_meta_message();

  /**
   * Return string containing the current state for all participants
   *
   */
  std::string ustate_values();

  /**
   * Generate 128 bit nonce value to be placed inside the message 
   * as random interesting data
   *
   */
  void generate_nonce(unsigned char* buffer);

  /**
   * Destructor
   *
   */
  ~np1secMessage();
};

#endif  // SRC_MESSAGE_H_
