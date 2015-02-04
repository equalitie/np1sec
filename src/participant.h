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
#include "src/crypt.h"

/** 
 * This class keeps the state of each participant in the room, including the
 * user themselves.
 */
class Participant {
 public:
  std::string id;
  LongTermPublicKey long_term_pub_key;
  np1secPublicKey ephemeral_key;
  // MessageDigest message_digest;

  // np1secKeyShare cur_keyshare;
  // np1secKeySHare future_key_share;

  enum ForwardSecracyContribution {
    NONE,
    EPHEMERAL,
    KEY_SHARE
  };

  ForwardSecracyContribution ForwardSecracyStatus = NONE;

  /**
   * default constructor
   */
  Participant() {
  }
};

/**
 * To be used in std::sort to sort the particpant list
 * in a way that is consistent way between all participants
 */
bool sort_by_long_term_pub_key(Participant& lhs, Participant& rhs) {
  return Cryptic::retrieveResult(lhs.long_term_pub_key)
         < Cryptic::retrieveResult(rhs.long_term_pub_key);
}

#endif  // SRC_PARTICIPANT_H_
