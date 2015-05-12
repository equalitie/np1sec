/**
 * Multiparty Off-the-Record Messaging library
 * Copyright (C) 2014, eQualit.ie
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of version 3 of the GNU Lesser General
 *  License as published by the Free Software Foundation.
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

#ifndef SRC_SESSION_ID_H_
#define SRC_SESSION_ID_H_

#include "src/common.h"
#include "src/participant.h"
#include "src/crypt.h"

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

  SessionId(ParticipantMap& plist) {
    compute(plist);
  }

  // copy constructor: do we need one?
  /* SessionId(SessionId& lhs) { */
  /*   std::memcpy(session_id_raw, lhs.session_id_raw, sizeof(HashBlock)); */
  /*   is_set = lhs.is_set; */
  /* } */

  void set(const HashBlock sid)
  {
    //only one time is possible
    //sanity check: You can only compute session id once
    assert(!is_set);
    memcpy(session_id_raw, sid, sizeof(HashBlock));
    is_set = true;
    
  }

  /**
   * given a plist it compute the session id of a session 
   * which has that plist as participants
   */
  void compute(ParticipantMap& plist)
  {
    assert(plist.size());

    std::string session_id_blob;
    for (auto it = plist.begin(); it != plist.end(); ++it) {
      Participant& p = it->second;
      UnauthenticatedParticipant uap(p.id, Cryptic::hash_to_string_buff(p.raw_ephemeral_key), p.authenticated);
      session_id_blob += uap.unauthed_participant_to_stringbuffer();
      session_id_blob.erase(session_id_blob.size()-1); //dropping authentication info
    }

    HashStdBlock sid =  Cryptic::hash(session_id_blob);
    memcpy(session_id_raw, sid.data(), sizeof(HashBlock));
    is_set = true;

  }
  
  uint8_t* get() {
    if (is_set) return session_id_raw; else return nullptr;
  }

  std::string get_as_stringbuff() {
    return (is_set) ? std::string(reinterpret_cast<const char*>(session_id_raw), sizeof(HashBlock)) : std::string();
  }

};

#endif
