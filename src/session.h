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

#include <string>
#include <vector>

#include "src/common.h"
#include "src/participant.h"
#include "src/crypt.h"
#include "src/base64.h"


#ifndef SRC_SESSION_H_
#define SRC_SESSION_H_

class MessageDigest {
 public:
  HashBlock digest;
  uint32_t message_id;

  void update(std::string new_message);
  // {
  //   message_id = compute_message_id(new_message);
  //   digest = mpseq_hash(digest + new_message);
  // };

  // Compute a unique globally ordered id from the time stamped message,
  // ultimately this function should be overridable by the client.
  uint32_t compute_message_id(std::string cur_message);
};

enum mpSeQMessageType {
  USER_MESSAGE,
  PURE_META_MESSAG
};

struct mpSeQMessage {
  mpSeQMessageType metamessage;
  std::string user_message;
};

// Defining essential types
struct SessionID {
  uint8_t id[c_hash_length];
};
typedef uint8_t  mpSeQBareMessage[];


/**
 * This class is encapsulating all information and action, a user needs and
 * performs in a session.
 */
class mpSeQSession {
 protected:
  HashBlock hashed_id;

  std::string _room_name;
  std::string _my_id;

  Ed25519Key ed25519Key;
  // Keeps the list of the live participants in the room and their current/new
  // keys/shares, last heartbeat, etc.
  std::vector<Participant> peers;

  // Keeps the list of the updated participants in the room once the
  // join/accept or farewell finishes.
  std::vector<Participant> peers_in_limbo;

  time_t key_freshness_time_stamp;

  // It is called by mpSeQ when ever the protocol needs to send meta data
  // messages (key exchange, etc) which is not initiated by a message from user.
  bool send_bare(mpSeQBareMessage message);

 public:
  SessionID session_id;

  // Constructor, initiate by joining.
  mpSeQSession(std::string new_room_name, std::string user_id);

  // Initiate with room members.
  bool join(std::vector<std::string> room_members);

  // Should be called when someone new join the chatroom. This will modify the
  // session id.
  bool accept(std::string new_participant_id);

  // This will be called when a user leave a chatroom to update the key.
  bool farewell(std::string leaver_id);

  // When a user wants to send a message to a session it needs to call its send
  // function.
  std::string send(mpSeQMessage message);

  // When a message is received from a session the receive function needs to be
  // called to decrypt. It updates the session status and returns the decrypted
  // message to be shown, it might be null if the message was a meta message.
  mpSeQMessage receive(std::string raw_message);

  // Destructor, session should be destroyed at leave.
  ~mpSeQSession();
};

#endif  // SRC_SESSION_H_
