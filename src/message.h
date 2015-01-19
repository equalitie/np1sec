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
  std::string message_id;
  SessionID session_id;
  std::string sender_id;
  std::string user_message;
  std::string meta_message;
  HashBlock transcript_chain_hash;
  std::string nonce;

  /*
   * Construct a new np1secMessage based on a set of message components
   * as input
   */
  np1secMessage(SessionID session_id, std::string sender_id, std::string user_message, np1secMessageType message_type, HashBlock transcript_chain_hash);

  /*
   * Construct a new np1secMessage based on a set of message components
   * based on an encrypted message as input
   */
  np1secMessage(string::id raw_message);

  /**
   * Format message 

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
  std::string base64_decode(std:string encode_message);

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
