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

#ifndef SRC_COMMON_H_
#define SRC_COMMON_H_

extern "C" {
  #include <assert.h>
}

#include <cstdint>
#include <sstream>
#include <iterator>
#include <stdexcept>
#include <vector>
#include <string>
#include <cstring>

#include "src/base64.h"

#define UNUSED(expr) (void)(expr)

extern "C" {
  #include "gcrypt.h"
}

typedef gcry_sexp_t np1secPrivateKey;
typedef gcry_sexp_t np1secPublicKey;
typedef std::pair<np1secPrivateKey, np1secPublicKey> KeyPair;
//TODO: it really makes sense that the public key is already stored in HashBlock 
//Format as we never use public key directly when we have the main
//key and only use this to transmit it to others

enum np1secLoadFlag {
  NO_LOAD,
  NEW_EPHEMERAL_KEY,
  LEAVE,
  NEW_SECRET_SHARE
};

// The length of the output of the hash function in bytes.
const size_t c_hash_length = 32;

typedef uint8_t HashBlock[c_hash_length];
//typedef std::vector<uint8_t> SessionID;
class SessionId
{
 protected:
  HashBlock session_id_raw;
  bool is_set;

 public:
  SessionId(const HashBlock sid)
    :is_set(true)
    {
      memcpy(session_id_raw, sid, sizeof(HashBlock));
    }

  SessionId()
   :is_set(false) {
  }

  // copy constructor: do we need one?
  /* SessionId(SessionId& lhs) { */
  /*   std::memcpy(session_id_raw, lhs.session_id_raw, sizeof(HashBlock)); */
  /*   is_set = lhs.is_set; */
  /* } */

  void set(HashBlock sid)
  {
    //only one time is possible
    //sanity check: You can only compute session id once
    assert(!is_set);
    memcpy(session_id_raw, sid, sizeof(HashBlock));
    is_set = true;
    
  }

  uint8_t* get() {
    if (is_set) return session_id_raw; else return nullptr;
  }

  std::string get_as_stringbuff() {
    return std::string(reinterpret_cast<const char*>(session_id_raw), sizeof(HashBlock));
  }
  
};

const std::string c_np1sec_protocol_name("np1sec");
const std::string c_np1sec_delim(":o)"); //because http://en.wikipedia.org/wiki/Man%27s_best_friend_(phrase)
const std::string c_subfield_delim(":"); //needed by ParticipantId defined in interface.h 

#endif  // SRC_COMMON_H_
