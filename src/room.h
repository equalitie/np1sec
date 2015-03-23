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

#ifndef SRC_ROOM_H_
#define SRC_ROOM_H_

#include <string>
#include <map>

#include "src/common.h"
#include "src/crypt.h"
#include "src/interface.h"
#include "src/session.h"
#include "src/message.h"

class np1secUserState;
class np1secSession;
class np1secMessage;

//The type that keep the set of all sessions associated with this room
//It really need to be a pointer, because the sessions are mostly
//create by other sessions and handed to the room.

//Should we point to a session or store the session itself?
typedef std::map<SessionID, np1secSession> SessionMap;

/**
 * Manage all sessions associated to a room, this is follow the concurrent 
 * join protocol described in the np1sec spec
 * 
 * The session-room invarients is that:
 *  - All participant in active session, share the same view about who is in 
 *    the active session of the room.
 *
 * nTherefore session creation fololws the following algorithm:
 *
 * User is in active session:
 * - Receive a join join requet-> make a new session immediately with session id.
 * - Receive a leave requet -> make a new session immediately with session id.
 * - Receive a message with wrong sid -> ignore.
 *
 * User not in the active session:
 * - UserState join-> just send join to room without session
 * - receive with existing sid -> goes to sid.
 * - receive with non-existing sid -> generate a new session.
 *
 */
class np1secRoom {
 protected:
  std::string name; //room name given in creation by user_state
  np1secUserState* user_state;
  //with exception of possibly one session, every
  //session has session id.
  enum UserInRoomState {
    CURRENT_USER,
    JOINING
  };

  UserInRoomState user_in_room_state;
  Cryptic np1sec_ephemeral_crypto; //We keep ephemeral crypo constant
  //during join request to avoid repeated need for authentication
  //forward serecy procedure can update it consequently. 
  SessionMap session_universe;

  //list of sessions in limbo, they need to give birth to new
  //sessions in-limbo in case a user join or leave.
  //std::list<np1secSession*> limbo; //no need for this limbo every
  //session beside current session.
  
  SessionID active_session;

 public:
  /**
   * constructor: sets room name, make the user status joing 
   * by default.
   *
   */
  np1secRoom(std::string room_name, np1secUserState* user_state);
  
  //Depricated: the approach of session factor is not working
  //as some of request for new session (specifically leave)
  //might come in encrypted format and as such the room
  //has no idea about the new session. 
  /* /\** */
  /*  * When a join request is received, it create a session */
  /*  * */
  /*  *\/ */
  /* np1secSession np1secRoom::session_factory(breeding_session, */
  /*                                         join_message);
  
  /**
   * called by UserState, everytime the user trys to join a room
   * it just simply send a join message to the room.
   */
  void join();
    
  /**
   * manages the finite state machine of the sid part of the message
   * based on sid (or absence of it), it decides what to do with the 
   * message
   *
   * User is in active session:
   * - Receive a join join requet-> make a new session immediately with session id.
   * - Receive a leave requet -> make a new session immediately with session id.
   * - Receive a message with wrong sid -> ignore.
   *
   * User not in the active session:
   * - UserState join-> just send join to room without session
   * - receive with existing sid -> goes to sid.
   * - receive with non-existing sid -> generate a new session.
   *
   *
   */
  void receive_handler(np1secMessage received_message);

  /**
   * manages activating a session which concerns an additional
   * person joining or an person leaving. it inform all sessions
   * in limbo to add or drop the person.
   * 
   * @param newl_activated_session the session that just got confirmation
   *        from all particpants and is ready to be the default session of
   *        the room
   */
  void activated_session(SessionID newly_activated_session);

};    

typedef std::map<std::string, np1secSession*> session_room_map;

#endif //SRC_ROOM_H_
