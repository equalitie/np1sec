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

#ifndef SRC_SESSION_H_
#define SRC_SESSION_H_

#include <string>
#include <vector>
#include "src/common.h"
#include "src/participant.h"
#include "src/crypt.h"

typedef std::vector<uint8_t> SessionID;
class np1secSession;

#include "src/userstate.h"

class MessageDigest {
 public:
  HashBlock digest;
  uint32_t message_id;

  void update(std::string new_message);

  /**
   * Compute a unique globally ordered id from the time stamped message,
   * ultimately this function should be overridable by the client.
   */
  uint32_t compute_message_id(std::string cur_message);
};

enum np1secMessageType {
  USER_MESSAGE,
  PURE_META_MESSAG
};

struct np1secMessage {
  np1secMessageType metamessage;
  std::string user_message;
};

// Defining essential types
typedef uint8_t np1secBareMessage[];


/**
 * This class is encapsulating all information and action, a user needs and
 * performs in a session.
 */
class np1secSession {
 protected:
  HashBlock hashed_id;
  Cryptic cryptic;

  np1secUserState *us;
  std::string room_name;

  Participant myself;
  vector<UnauthenticatedParticipant> participants_in_the_room;

  /**
   * Keeps the list of the live participants in the room and their current/new
   * keys/shares, last heartbeat, etc.
   */
  std::vector<Participant> peers;

  /**
   * Keeps the list of the updated participants in the room once the
   * join/accept or farewell finishes.
   */
  std::vector<Participant> peers_in_limbo;

  time_t key_freshness_time_stamp;

  SessionID session_id;

 public:
  np1secSession();

  /**
   * Constructor, initiate by joining.
   */
  np1secSession(np1secUserState *us, std::string room_name, std::string name, std::vector<UnauthenticatedParticipant>participants_in_the_room);

  /**
   * access function for session_id;
   */
  SeesionID my_session_id() { return session_id};

  bool join();

  /**
   * Should be called when someone new join the chatroom. This will modify the
   * session id.
   */
  bool accept(std::string new_participant_id);

  /**
   * This will be called when a user leaves a chatroom to update the key.
   */
  bool farewell(std::string leaver_id);

  /**
   * When a user wants to send a message to a session it needs to call its send
   * function.
   */
  bool send(np1secMessage message);

  /**
   * When a message is received from a session the receive function needs to be
   * called to decrypt. It updates the session status and returns the decrypted
   * message to be shown, it might be null if the message was a meta message.
   */
  np1secMessage receive(std::string raw_message);

  /**
   * Destructor, session should be destroyed at leave.
   */
  ~np1secSession();
};

#endif  // SRC_SESSION_H_
