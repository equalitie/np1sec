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

#include "common.h"
#include "participant.h"
#include "crypt.h"

namespace np1sec
{

class SessionId
{
  protected:
    HashBlock session_id_raw;
    bool is_set;

  public:
    SessionId(const HashBlock sid) : is_set(true) { memcpy(session_id_raw, sid, sizeof(HashBlock)); }

    SessionId() : is_set(false) {}

    SessionId(ParticipantMap& plist) { compute(plist); }

    void set(const HashBlock sid)
    {
        // only one time is possible
        // sanity check: You can only compute session id once
        assert(!is_set);
        memcpy(session_id_raw, sid, sizeof(HashBlock));
        is_set = true;
    }

    /**
     * given a plist it compute the session id of a session
     * which has that plist as participants
     */
    void compute(const ParticipantMap& plist)
    {
        assert(plist.size());

        std::string session_id_blob;
        for (auto it = plist.begin(); it != plist.end(); ++it) {
            const Participant& p = it->second;
            session_id_blob += p.id.nickname;
            session_id_blob += std::string((char *)p.id.fingerprint, sizeof(p.id.fingerprint));
            session_id_blob += std::string((char *)p.raw_ephemeral_key, sizeof(p.raw_ephemeral_key));
        }

        hash(session_id_blob, session_id_raw);
        is_set = true;
    }

    uint8_t* get()
    {
        if (is_set)
            return session_id_raw;
        else
            return nullptr;
    }

    std::string get_as_stringbuff()
    {
        if (is_set) {
            return std::string(reinterpret_cast<const char*>(session_id_raw), sizeof(HashBlock));
        } else {
            return "";
        }
    }

    bool operator==(const SessionId& rhs)
    {
        return (is_set == rhs.is_set && !compare_hash(session_id_raw, rhs.session_id_raw));
    }
};

} // namespace np1sec

#endif
