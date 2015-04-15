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

#include "src/message.h"
#include "userstate.h"
#include "src/room.h"

using namespace std;

/**
 * called by room constructor, everytime the user is the first joiner
 * of an empty room and hence does not need to convince anybody about
 * their identity, etc.
 */
void np1secRoom::solitary_join() {
  //simply faking the particpant inf message
  assert(user_in_room_state == JOINING); 
  
  UnauthenticatedParticipantList session_view;
  
  session_view.push_back(UnauthenticatedParticipant(*(user_state->myself), Cryptic::public_key_to_stringbuff(np1sec_ephemeral_crypto.get_ephemeral_pub_key()),true));

  SessionId empty_session_id;
  // np1secMessage solitary_joiner_info(empty_session_id,
  //                                    np1secMessage::PARTICIPANTS_INFO,
  //                                    session_view,
  //                                    "",
  //                                    "", //session conf
  //                                    "", //joiner info
  //                                    "",
  //                                    user_state,
  //                                    name);
  
  np1secSession sole_joiner_session(user_state,
                                    name,
                                    &np1sec_ephemeral_crypto,
                                    session_view);

  session_universe.insert(pair<string, np1secSession>(sole_joiner_session.my_session_id().get_as_stringbuff(), sole_joiner_session));
  
}

/**
 * called by room constructor, everytime the user trys to join a room
 * occupied by others. it just simply send a join message to the room.
 */
void np1secRoom::join() {
  assert(user_in_room_state == JOINING); //no double join but we need a
  //more humane way of doing this
  //turening sexp to stirng buffer.
  UnauthenticatedParticipant me(*(user_state->myself), Cryptic::public_key_to_stringbuff(np1sec_ephemeral_crypto.get_ephemeral_pub_key()),true);
  np1secMessage join_message(np1secMessage::JOIN_REQUEST,
                             me,
                             user_state,
                             name);
  join_message.send();
  
}

/**
 * constructor: sets room name, make the user status joing 
 * by default.
 *
 */
np1secRoom::np1secRoom(std::string room_name, np1secUserState* user_state, std::vector<std::string> participants_in_the_room)
  : name(room_name), user_state(user_state), user_in_room_state(JOINING)
{
  np1sec_ephemeral_crypto.init(); //generate intitial ephemeral keys for join
  if (participants_in_the_room.size() <= 1)
    solitary_join();
  else
    join();
}

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
 * Other messages should be deligated this way
 * using
         the following procedure:
           1. If the message has sid:
                if there is a live session with that sid, deligate
                to that session
                else if the message has sid but session with such
                sid does not exists or the session is dead
                   if the room has active session, give it to the active sesssion of the room
                   else 
                      make a new session for that room and deligate it to it 
                      (but it is a sort of error, ignore the message. Join message doesn't have                    sid)

           2. If the message doesn't have sid, it is a join message
                if the room has active session
                  deligate it to the active session. 
                else
                  (this shouldn't happen either). *
 */
void np1secRoom::receive_handler(np1secMessage received_message)
{
  //If the user is not in the session, we can do nothing with
  //session less messages, we are joining and we need info
  //about the room
  //RoomAction resulting_action = c_no_room_action;
  if (user_in_room_state == JOINING) {
    if (received_message.has_sid()) {
      if (session_universe.find(Cryptic::hash_to_string_buff(received_message.session_id)) != session_universe.end())
        RoomAction resulting_action = session_universe[Cryptic::hash_to_string_buff(received_message.session_id)].state_handler(received_message);
      
      else {
        session_universe.insert(pair<string, np1secSession>(Cryptic::hash_to_string_buff(received_message.session_id), np1secSession(user_state, name, &np1sec_ephemeral_crypto, received_message)));
      }
    }
    //else just ignore it, it is probably another user's join that we don't
    //care.
  } else if (user_in_room_state == CURRENT_USER) {
    if (received_message.has_sid()) {
      if (session_universe.find(Cryptic::hash_to_string_buff(received_message.session_id)) != session_universe.end()) {
        RoomAction resulting_action = session_universe[Cryptic::hash_to_string_buff(received_message.session_id)].state_handler(received_message);
        
      }
      // else //ignone
    } else  //no sid, it should be a join message, verify and send to active session
      if (received_message.message_type == np1secMessage::JOIN_REQUEST) {
        RoomAction action_to_take = session_universe[active_session.get_as_stringbuff()].state_handler(received_message);
        if (action_to_take.action_type == RoomAction::NEW_SESSION) {
          session_universe.insert(pair<string, np1secSession>(action_to_take.bred_session->my_session_id().get_as_stringbuff(),*(action_to_take.bred_session)));
          delete action_to_take.bred_session; //:(
        }
      }
    //else just ignore it
    assert(0); //just for test to make sure we don't end up here
    return;
  }

  //Now we check if the resulting action resulted in new session
  //we have to activate that session
  if (received_message.has_sid())
    if (active_session.get_as_stringbuff() != Cryptic::hash_to_string_buff(received_message.session_id))
      if (session_universe[Cryptic::hash_to_string_buff(received_message.session_id)].get_state() == np1secSession::IN_SESSION)
      activate_session(received_message.session_id);
  
  //np1secSession *cur_session = retrieve_session(room_name);
  // if (!cur_session) {
  //   //only possible operation should be join and leave 
  //   if (np1sec_message.find(":o?JOIN:o?") == 0) {
  //     // check if it is ourselves or somebody else who is joining
  //     string joining_nick = np1sec_message.substr(strlen(":o?JOIN:o?"));

  //     if (name == joining_nick) {
  //       ;//ignore
  //     } else {
  //       this->accept_new_user(room_name, joining_nick);
  //     }
  //   } else if (np1sec_message.find(":o?LEAVE:o?") == 0) {
  //     string leaving_nick = np1sec_message.substr(strlen(":o?LEAVE:o?"));
  //     if (leaving_nick==name) {
  //       leave_room(room_name);
  //     } else {
  //       shrink_on_leave(room_name, leaving_nick);
  //     }
  //   } else if (np1sec_message.find(":o?SEND:o?") == 0) {
  //     string message_with_id = np1sec_message.substr(strlen(":o?SEND:o?"));
  //     size_t sender_pos = message_with_id.find(":o?");
  //     string message_id_str = message_with_id.substr(0, sender_pos);
  //     int message_id;
  //     stringstream(message_id_str) >> message_id;
  //     string sender_and_message = message_with_id.substr(
  //                                 sender_pos + strlen(":o?"));
  //     size_t message_pos = sender_and_message.find(":o?");
  //     string sender = message_with_id.substr(0, message_pos);
  //     // we don't care really about sender
  //     string pure_message = sender_and_message.substr(message_pos + strlen(":o?"));
  //   }
  // }
  
  // np1secMessage received_message = cur_session->receive(np1sec_message);
  // RoomAction room_action = { NULL, received_message.user_message };
  // return room_action;

}

/**
 * manages activating a session which concerns an additional
 * person joining or an person leaving. it inform all sessions
 * in limbo to add or drop the person.
 * 
 * @param newl_activated_session the session that just got confirmation
 *        from all particpants and is ready to be the default session of
 *        the room
 */
void np1secRoom::activate_session(SessionId newly_activated_session)
{
  SessionId dying_session = active_session;
  if (dying_session.get())
    session_universe[active_session.get_as_stringbuff()].commit_suicide();
  else
    user_in_room_state = CURRENT_USER; //in case it is our first session
  
  active_session = newly_activated_session;
  
  for(SessionMap::iterator session_it = session_universe.begin(); session_it != session_universe.end(); session_it++) {
    //first we need to check if such a session in limbo currently exists
    //if it exists, that mean the joining user has already started the
    //negotiotion with the sesssion and there is no need to update the
    //session
    
    //in order to accomplish this task the easiest (but not most efficient
    //avernue is to generate the session, and if the sid is already in the
    //list just delete it. Beside memory allocation/dellocation it is not
    //clear if anything more is wasted.
    
    //this is *not* true, sessions actually sends auth_token and key shares
    //as a part of their creation. So to avoid side effect we compute the prospective
    //session id first
    
    //update: in favor of simplicity we are having a nonbroadcasting creation
    //so we can create and kill sessions with not so much problem
    if ((session_it->second.get_state() != np1secSession::DEAD) && (session_it->second.get_state() != np1secSession::IN_SESSION)) {
      session_it->second.commit_suicide();
      np1secSession *born_session = nullptr;
      if (dying_session.get())
        *born_session  = session_it->second + session_universe[active_session.get_as_stringbuff()] - session_universe[dying_session.get_as_stringbuff()];
      else
        *born_session  = session_it->second + session_universe[active_session.get_as_stringbuff()];
                            
      if (session_universe.find(born_session->my_session_id().get_as_stringbuff()) == session_universe.end()) //we don't had the session,
        session_universe.insert(pair<string, np1secSession>(born_session->my_session_id().get_as_stringbuff(), *born_session));

      delete born_session;
      
    }
  }
}

/**
 *  sends user message given in plain text by the client to the 
 *  active session of the room
 *
 *  @param plain_message user text message
 *
 *  @return false if no active session is established for the current 
 *  room
 */
bool np1secRoom::send_user_message(std::string plain_message)
{
  if (active_session.get()) {
    session_universe[active_session.get_as_stringbuff()].send(plain_message, np1secMessage::USER_MESSAGE);
    return true;
  }

  assert(0); //just for test to detect if something gone wrong
  return false; //you can't send message now
  //TODO: We should queue the messages and send them
  //when the session is established
 
}

// np1secSession* np1secRoom::retrieve_session(std::string room_name) {
//   np1secSession *cur_session = nullptr;
//   session_room_map::iterator it = session_in_a_room.find(room_name);

//   if ( it != session_in_a_room.end() ) {
//     cur_session = it->second;
//   }

//   return cur_session;

// }
