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

//#error I am here

#include <string>
#include <map>

#include "src/common.h"
#include "src/crypt.h"
#include "src/interface.h"
#include "src/session.h"
#include "src/message.h"

//The type that keep the set of all sessions associated with this room
//It really need to be a pointer, because the sessions are mostly
//create by other sessions and handed to the room.

//Should we point to a session or store the session itself?
typedef std::map<std::string, np1secSession*> SessionMap;

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
  ParticipantId myself;
  size_t room_size = 0; //we only need keep track of
  //the room size till we become a current user. after that
  //the session can take care of that

  //with exception of possibly one session, every
  //session has session id.
  enum UserInRoomState {
    JOINING, //, LEAVING_USER //TODO: sit and think if we need this?
    CURRENT_USER
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
  
  SessionId active_session;
  SessionId next_in_activation_line;

  /**
   * manages activating a session which concerns an additional
   * person joining or an person leaving. it inform all sessions
   * in limbo to add or drop the person.
   * 
   * @param newl_activated_session the session that just got confirmation
   *        from all particpants and is ready to be the default session of
   *        the room
   */
  void activate_session(SessionId newly_activated_session);

  /**
   * Mark in-limbo sessions which are not valid any more as stale so 
   * subsequently one can make a fresh session out of each
   * mark them stale prevent them from replying to confimation etc and  
   * misleading joining participants in moving forward
   */
  void stale_in_limbo_sessions_presume_heir(SessionId new_successor);

  /**
   *  When a new sesison generates key we need to update all session in limbo
   *  (kill them and generate new one for each) which ad here to this generated
   *  key session.
   * if somebody leaves, as soon as they live you need to update them cause
   * they are useless and the leaving person aren't going to confirmed any of them
   */
  void refresh_stale_in_limbo_sessions(SessionId new_parent_session_id);


 public:
  /**
   * constructor: sets room name, make the user status joing 
   * by default.
   *
   */
  np1secRoom(std::string room_name, np1secUserState* user_state, std::vector<std::string> participants_in_the_room);

  /**
   * bad constructor just for the sake of operator[] of chatrooms
   *
   */
  np1secRoom() {
      assert(0);
  }

  //we need to deep copy the session_universe
  np1secRoom(const np1secRoom& rhs)
    : name(rhs.name), //room name given in creation by user_state
    user_state(rhs.user_state),
    myself(rhs.myself),
    room_size(rhs.room_size),
    user_in_room_state(rhs.user_in_room_state),
    np1sec_ephemeral_crypto(rhs.np1sec_ephemeral_crypto),
    active_session(rhs.active_session),
    next_in_activation_line(rhs.next_in_activation_line)
      {
        logger.debug("copying room object");
        for(auto& cur_session: rhs.session_universe) {
          np1secSession* new_copy = new np1secSession(*cur_session.second);
          session_universe[new_copy->session_id.get_as_stringbuff()] = new_copy;
        }
    }
  /**
   * called by UserState, everytime the user trys to join a room
   * it just simply send a join message to the room.
   */
  void join();

  /**
   *  If the user is joiner and already has constructed a session for
   *  the room and for any reason haven't received a reply from current
   *  participant this functions resend the join request
   */
  void try_rejoin();
  
  /**
   * called by room constructor, everytime the user is the first joiner
   * of an empty room and hence does not need to convince anybody about
   * their identity, etc.
   */
  void solitary_join();

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
   *  sends user message given in plain text by the client to the 
   *  active session of the room
   *
   *  @param plain_message user text message
   *
   *  throw exception if no active session is established for the current 
   *  room
   */
  void send_user_message(std::string plain_message);

  /**
   * Just sends a message for closing the transcript consistency
   * this also initiate the new session creation for other users
   */
  void leave();

  /**
   * Just sends a message for closing the transcript consistency
   * this also initiate the new session creation for other users
   */
  void shrink(std::string leaving_user_nick);

  /**
   * called by user state when somebody else joins the
   * the room to keep track of the room size
   */
  void increment_size();
  
  /**
   * for np1secSession when it breeds a new session specailly 
   * in the forward secrecy timer to be able to insert it 
   * in the room's session map
   */
  void insert_session(np1secSession* new_session);

  /**
   * Destructor need to clean up the session universe
   */
  ~np1secRoom();

};    

typedef std::map<std::string, np1secSession*> session_room_map;

#endif //SRC_ROOM_H_
