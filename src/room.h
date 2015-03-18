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

class np1secUserState;
//This has been removed in favor of np1secSession::operator- function
//np1secSession::operator+ functions.
//which compute the contrast of two sessions and gives set up of joining
//and leaving users.
/* /\** */
/*  * it represents a message from a session to the room. When a room needs */
/*  * to take action based on result of a message that a session is received */
/*  * */
/*  *  */
/*  * */
/*  *\/ */
/* class RoomAction { */
/*   //historically RoomAction was the way to inform chat client about */
/*   //actions, however we decided the main tool for action transmission */
/*   //to chat client are callback function */

/*   // the only real action type is only */
/*   //activate which signal changing active session and hence */
/*   //cryptographically verifiable join and leave. */
/*  public: */
/*   enum ActionType { */
/*     NO_ACTION, */
/*     JOIN, */
/*     LEAVE, */
/*     REKEY, */
/*     NEW_MESSAGE */
/*   }; */

/*   ActionType action_type; */
/*   UserEphemeralId acting_user;  // The user which joined, left or sent a message. */
  
/* }; */

//The type that keep the set of all sessions associated with this room
//It really need to be a pointer, because the sessions are mostly
//create by other sessions and handed to the room.
typedef std::map<SessionID, np1secSession> SessionMap;

/**
 * Manage all sessions associated to a room, this is follow the concurrent join
 * protocol described in the np1sec spec
 * 
 * The session-room invarients is that:
 *  - All participant in active session, share the same view about who is in 
 *    the active session of the room.
 *
 * Therefore session creation fololws the following algorithm:
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
  crypto np1sec_ephemeral_crypto; //We keep ephemeral crypo constant
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
  
  /**
   * called by UserState, everytime the user trys to join a room
   * it just simply send a join message to the room.
   */
  join();
    
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
