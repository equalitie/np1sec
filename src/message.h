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
#include "src/crypt.h"
#include "src/base64.h"

class np1secMessage {
 protected:
  Cryptic cryptic;
  np1secMessageType message_type;

 public:
  uint32_t message_id;
  SessionID session_id;
  std::string sender_id;
  std::string user_message;
  std::string meta_message;
  np1secLoadFlag meta_load_flag;
  std::string meta_load;
  int meta_only;
  HashBlock transcript_chain_hash;
  std::string nonce;
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
  std::string sign_message();

  /**
   * Verify the message
   *
   */
  bool verify_message(std::string signed_message, std::string signature);

  /**
   * Create and return an encrypted form of the signed message
   *
   */
  std::string encrypt_message();

  /**
   * Decrypt and return the raw form of the message
   *
   */
  std::string decrypt_message();

  /**
   * Compose message into sendable formt
   *
   */
  std::string format_sendable_message();

  /**
   * Format Meta message for inclusion with standard message or for
   * standalone use
   *
   */
  std::string format_meta_message();

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
