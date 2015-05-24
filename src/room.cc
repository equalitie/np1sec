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
 * called by room constructor, everytime the user is the first joiner
 * of an empty room and hence does not need to convince anybody about
 * their identity, etc.
 */
void np1secRoom::solitary_join() {
  //simply faking the particpant inf message
  assert(user_in_room_state == JOINING); 
  
  //UnauthenticatedParticipantList session_view;
  ParticipantMap& participants;
  
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
  np1secMessage join_message;

  join_message.create_join_request_msg(me);
  join_message.send(name, user_state);
  
}

void np1secRoom::try_rejoin() {
  //you don't need to retry sole-joining as it is
  //a deterministic process 
  if (user_in_room_state != JOINING) {
    join();

  } else {
    //you have to leave before rejoining
    throw np1secInvalidRoomException();

  }

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
  RoomAction action_to_take = c_no_room_action;
  if (user_in_room_state == JOINING) {
    if (received_message.has_sid()) {
      if (session_universe.find(received_message.session_id.get_as_stringbuff()) != session_universe.end()) {
        auto message_session = session_universe.find(received_message.session_id.get_as_stringbuff());
        action_to_take = message_session->second.state_handler(received_message);
      
      } else {
        //we are only interested in PARTICIANT_INFO
        if (received_message.message_type == np1secMessage::PARTICIPANTS_INFO) {
          np1secSession* new_session = new np1secSession(user_state, name, &np1sec_ephemeral_crypto, received_message);
          if (new_session->my_state != np1secSession::DEAD)
            session_universe.emplace(pair<string, np1secSession>(received_message.session_id.get_as_stringbuff(), *new_session));
          else
            delete new_session;
        } //otherwise that message doesn't concern us (the entrance for setting up session id is
        //PARTICIPANTS_INFO
      }
    }
    //else just ignore it, it is probably another user's join that we don't
    //care.
  } else if (user_in_room_state == CURRENT_USER) {
    if (received_message.has_sid()) {
      if (session_universe.find(Cryptic::hash_to_string_buff(received_message.session_id.get())) != session_universe.end()) {
        action_to_take = session_universe[received_message.session_id.get_as_stringbuff()].state_handler(received_message);
        
      }
      // else //ignone, we haven't generated this session, so we could be leaving, we have 
    } else  {//no sid, it should be a join message, verify and send to active session
      if (received_message.message_type == np1secMessage::JOIN_REQUEST) {
        action_to_take = session_universe[active_session.get_as_stringbuff()].state_handler(received_message);
        // delete action_to_take.bred_session; //:( TODO: room needs to create the session.
        // new_session_it.firs->keep_peers_in_order_spot_myself(); //to update pointer
        // //to thread user as participant is not valid anymore. This is obviously digusting
        // //we need a respectable copy constructor for np1secSession
      }
    } //has sid or not
    //if the action resulted in new session we need to add it to session universe
    if (action_to_take.action_type == RoomAction::NEW_SESSION) 
      session_universe.emplace(pair<string, np1secSession>(action_to_take.bred_session->my_session_id().get_as_stringbuff(),*(action_to_take.bred_session)));

  } else {
    //else just ignore it
    assert(0); //just for test to make sure we don't end up here
    return;
    
  }//State in the room

  //Now we check if the resulting action resulted in new confirmed session
  //we have to activate that session:
  //1. first we should have the session in our universe.
  //2. The session should have different session_id than
  //   the currently active one
  
  if (received_message.has_sid()) {
    auto message_session = session_universe.find(received_message.session_id.get_as_stringbuff());
    if (message_session != session_universe.end()) {
      if (active_session.get_as_stringbuff() != received_message.session_id.get_as_stringbuff()) {
        if (message_session->second.get_state() == np1secSession::IN_SESSION) {
          user_state->ops->join(name, message_session->second.peers, user_state->ops->bare_sender_data);
          activate_session(received_message.session_id.get());
        }
      }
    }
  }
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
/**
 * Just sends a message for closing the transcript consistency
 * this also initiate the new session creation for other users
 */
void np1secRoom::leave() {
  if (user_in_room_state == CURRENT_USER) { 
    if (active_session.get()) {
      session_universe[active_session.get_as_stringbuff()].leave();//send leave and start leave timer
    }
    //else do nothing basically TODO::somebody should throw out the room though
  }
  else {
    //if you want to leave the room while joining. 
    //if you have confirmed your session or not. However, as long as
    //the session hasn't been started then we don't need to check for
    //consistency. In any case we can just let it shrink
    log.info("nothing to do; leaving from a room we haven't joined");
  }

}

void np1secRoom::shrink(std::string leaving_nick) {
  if (user_in_room_state == CURRENT_USER) {
    //we need to detect if we have already generated the shrunk
    //session or not.
    //first we get the plist of active session, if the leaving use
    if (active_session.get()) {
      auto active_session_element = session_universe.find(active_session.get_as_stringbuff());
      if (active_session_element != session_universe.end()) {
        if (active_session_element->second.participants.find(leaving_nick) != active_session_element->second.participants.end()) {
          np1secSession& active_np1sec_session = active_session_element->second;

          if (active_np1sec_session.my_state != np1secSession::FAREWELLED) {
            //alternatively we can just check the state of active_session and if 
            //it is farewelled then we don't need to worry about generating the
            //shrank session
            // Actually this is a better solution, because the session are staying
            //in the session universe even after they die so their existenec doesn't
            //mean we have taken any action
            //we avoid making a new session, if the session is not made we will make the new session 
            //so not to duplicate the re-share message. the reshare message has the same session
            //id so the participants handle it to the previously made session. the shares are the same. Either the session
          //is waiting for more share which result in replacing the same share or is
          //waiting for confirmation and so it ignores the share message.

          //We basically avoid sending an extra message which is not part of the protocol
          //but it is the implementation particularity, and duplicating such message which doesn't
          // violate the          
          //protocol. (you might want to send the same message 10 times to increase
          //reliability and the protocol shouldn't choke on that.

          //Now consider the situation that pn announce intention to leave at the same
          //then last person forward secrecy contribution is matured. the current
          //session should stop the share renewal, cause the state is farewelled.
          //(normally the renew session should never be confirmed. because the leaving
          //(user haven't confirmed and move cause it sends its leaving message
          //to current session, as such it is important that the leaving user,
          //doesn't confirm a session after intention to leave, if he does though,
          //we'll recover through immature leave procedure.

          //It is also important to note as soon as we have new session, all session
          //in limbo will die and give birth to new session compatible with current
          //plist


            SessionId shrank_session_id = active_np1sec_session.shrank_session_id(leaving_nick);
            auto shrank_session = session_universe.find(shrank_session_id.get_as_stringbuff());
            if (shrank_session != session_universe.end()) {
              //TODO: come up with a revining mechanism
              //revive the session, if revive fails we re-make it
              //shrank_session->second.revive();
              //if (shrank_session->second.my_state = np1sec::DEAD) {
              session_universe.erase(shrank_session_id.get_as_stringbuff());
              //shrank_session = session_universe.end();
            }

            auto action_to_take = active_np1sec_session.shrink(leaving_nick);
            if (action_to_take.action_type == RoomAction::NEW_SESSION) {
              session_universe.emplace(pair<string, np1secSession>(action_to_take.bred_session->my_session_id().get_as_stringbuff(),*(action_to_take.bred_session)));
            }

          } //Already FAREWELLED
          log.info("no need to shrinked. Already farewelled.");
          //otherwise we already have made the
          //shrank session don't worry about it
        } //else if we don't find the nick, it is ok, just ignore it might be the leaving user has joined the xmpp room but not being accepted by the pariticipants
        else {
          log.warn("The leaving user " + leaving_nick + " is not part of active session");
        }
      } else {
        log.error("Internal error: the active session is not in session universe.");
        assert(0); //I'm not throwing exception, cause if we end up here it
        //is totally our fault, nothing external can cause this.
      
      }
    }
        //else do nothing basically TODO::somebody should throw out the room though
  else {
    log.warn("room contains no active sesssion");
  }
}


