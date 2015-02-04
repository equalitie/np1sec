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
#include "src/interface.h"
#include "src/participant.h"
#include "src/crypt.h"
#include "src/message.h"

typedef std::vector<uint8_t> SessionID;
class np1secSession;
class np1secUserState;

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
  std::vector<UnauthenticatedParticipant> participants_in_the_room;

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

  /**
   * it should be invoked only once to compute the session id
   * if one need session id then they need a new session
   *
   * @return return true upon successful computation
   */
  bool compute_session_id();

  /**
 * (n+1)sec sessions are implemented as finite state machines.
 * Each message transaction might ends up in state change. 
 * this is a generic class to store every state and manage its
 * transition, illigiblity etc
 * 
 */
  enum np1secSessionState {
    NONE,
    JOIN_REQUESTED, //The thread has requested to join by sending ephemeral key
    REPLIED_TO_NEW_JOIN, //The thread has received a join from a participant replied by participant list
    GROUP_KEY_GENERATED, //The thread has computed the session key and has sent the conformation
    IN_SESSION, //Key has been confirmed
    UPDATED_KEY, //all new shares has been received and new key has been generated, no more send possible
    LEAVE_REQUESTED, //Leave requested by the thread, waiting for final transcirpt consitancy check
    FAREWELLED, //LEAVE is received from another participant and a meta message for transcript consistancy and new shares has been sent
    DEAD //Won't accept receive or sent messages, possibly throw up
  };

  np1secSessionState my_state;

  /**
   * Received the pre-processed message and based on the state
   * of the session decides what is the appropriate action
   *
   * @param receive_message pre-processed received message handed in by receive function
   *
   * @return true if state has been change 
   */
  bool state_handler(np1secMessage receivd_message);
  
 public:
  /**
     constructor
     You can't have a session without a user
   */
  np1secSession(np1secUserState *us);

  /**
   * Constructor, initiate by joining.
   */
  np1secSession(np1secUserState *us, std::string room_name, std::vector<UnauthenticatedParticipant>participants_in_the_room);

  /**
   * access function for session_id;
   */
  SessionID my_session_id() { return session_id;};

  /**
   * Should be called by userstate when the user wants to join a new room
   *
   * @parma long_term_id_key the key pair of joining party is need for 
   *        deniable authentication
   *
   * @return return true if the first stage of join is completed successfully
   */
  bool join(LongTermIDKey long_term_id_key);

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
