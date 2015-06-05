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
  original_room_size = participants_in_the_room.size();

  join();

}

/**
 * called by room constructor, everytime the user is the first joiner
 * of an empty room and hence does not need to convince anybody about
 * their identity, etc.
 */
void np1secRoom::solitary_join() {
  //simply faking the particpant inf message
  logger.assert_or_die(user_in_room_state == JOINING, "only can be called in joining stage", __FUNCTION__, user_state->myself->nickname); 
  
  //UnauthenticatedParticipantList session_view;
  ParticipantMap participants;
  
  participants.insert( pair<string,Participant> (user_state->myself->nickname, Participant(UnauthenticatedParticipant(*(user_state->myself), Cryptic::public_key_to_stringbuff(np1sec_ephemeral_crypto.get_ephemeral_pub_key()),true))));

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
  
  np1secSession sole_joiner_session(np1secSession::CREATOR,
                                      user_state,
                                      name,
                                      &np1sec_ephemeral_crypto,
                                      participants);
  

  session_universe.insert(pair<string, np1secSession>(sole_joiner_session.my_session_id().get_as_stringbuff(), sole_joiner_session));
  
}

/**
 * called by room constructor, everytime the user trys to join a room
 * occupied by others. it just simply send a join message to the room.
 */
void np1secRoom::join() {
  logger.assert_or_die(user_in_room_state == JOINING, "only can be called in joining stage", __FUNCTION__, user_state->myself->nickname); //no double join but we need a
  logger.assert_or_die(original_room_size, "being in an empty room is a logical contradition", __FUNCTION__, user_state->myself->nickname);

  if (original_room_size == 1) {
    logger.info("creating room " + name + "...", __FUNCTION__, user_state->myself->nickname);
    solitary_join();

  } else {
    logger.info("joining room " + name + "...",  __FUNCTION__, user_state->myself->nickname);

    //more humane way of doing this
    //turening sexp to stirng buffer.
    UnauthenticatedParticipant me(*(user_state->myself), Cryptic::public_key_to_stringbuff(np1sec_ephemeral_crypto.get_ephemeral_pub_key()),true);
    np1secMessage join_message;

    join_message.create_join_request_msg(me);
    join_message.send(name, user_state);

  }
  
}

/**
 *  If the user is joiner and already has constructed a session for
 *  the room and for any reason haven't received a reply from current
 *  participant this functions resend the join request
 */
void np1secRoom::try_rejoin() {
  //you don't need to retry sole-joining as it is
  //a deterministic process 
  if (user_in_room_state == JOINING) {
    join();

  } else {
    //it is probably called by a desperate
    //ding session that doesn't know we are
    //are already joind
    logger.warn("already in the session. igonring calls for re-join", __FUNCTION__, user_state->myself->nickname);

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
 * - receivae with existing sid -> goes to sid.
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

  logger.info("room " + name + " handling message " + to_string(received_message.message_type) + " from " + received_message.sender_nick, __FUNCTION__, user_state->myself->nickname);
  
  if (user_in_room_state == JOINING) {
    logger.info("in JOINING state", __FUNCTION__, user_state->myself->nickname);
    if (received_message.has_sid()) {
      auto message_session = session_universe.find(received_message.session_id.get_as_stringbuff());
      if (message_session != session_universe.end() && (message_session->second.my_state != np1secSession::DEAD)) {
        action_to_take = message_session->second.state_handler(received_message);
      } else {
        //we are only interested in PARTICIANT_INFO
        if (received_message.message_type == np1secMessage::PARTICIPANTS_INFO) {
          try {
            ParticipantMap prop_empty_plist;
            np1secSession* new_session = new np1secSession(np1secSession::JOINER, user_state, name, &np1sec_ephemeral_crypto, prop_empty_plist, &received_message);
            if (new_session->my_state != np1secSession::DEAD) {
              //we need to get rid of old session if it is dead
              //till we get a reviving mechanisim
              if (message_session != session_universe.end() && (message_session->second.my_state == np1secSession::DEAD)) {
                session_universe.erase(message_session->first);
              }
              session_universe.emplace(pair<string, np1secSession>(received_message.session_id.get_as_stringbuff(), *new_session));
            }
          } catch(std::exception& e) {
            logger.error(e.what(), __func__, user_state->myself->nickname);
            
          }
          
        } //otherwise that message doesn't concern us (the entrance for setting up session id is
        //PARTICIPANTS_INFO
      }
    }
    //else just ignore it, it is probably another user's join that we don't
    //care.
  } else if (user_in_room_state == CURRENT_USER) {
    logger.info("in CURRENT_USER state", __FUNCTION__, user_state->myself->nickname);
    if (received_message.has_sid()) {
      if (session_universe.find(Cryptic::hash_to_string_buff(received_message.session_id.get())) != session_universe.end()) {
        try {
          action_to_take = session_universe[received_message.session_id.get_as_stringbuff()].state_handler(received_message);
        } catch(std::exception& e) {
          logger.error(e.what(), __FUNCTION__, user_state->myself->nickname);
        }
      }
      // else //ignone, we haven't generated this session, so we could be leaving, we have 
    } else  {//no sid, it should be a join message, verify and send to active session
      if (received_message.message_type == np1secMessage::JOIN_REQUEST) {
        try {
          action_to_take = session_universe[active_session.get_as_stringbuff()].state_handler(received_message);
        } catch(std::exception& e) {
          logger.error(e.what(), __FUNCTION__, user_state->myself->nickname);
        }

        // delete action_to_take.bred_session; //:( TODO: room needs to create the session.
        // new_session_it.firs->keep_peers_in_order_spot_myself(); //to update pointer
        // //to thread user as participant is not valid anymore. This is obviously digusting
        // //we need a respectable copy constructor for np1secSession
      } else {
        logger.error("Invalid state-less message, of type " + to_string(received_message.message_type) +" only session-less message allowed is JOIN_REQUEST of type "+ to_string(np1secMessage::JOIN_REQUEST), __FUNCTION__, user_state->myself->nickname);
        throw np1secInvalidDataException();
      }
    } //has sid or not
    //if the action resulted in new session we need to add it to session universe
    if (action_to_take.action_type == RoomAction::NEW_SESSION) 
      session_universe.emplace(pair<string, np1secSession>(action_to_take.bred_session->my_session_id().get_as_stringbuff(),*(action_to_take.bred_session)));

  } else { //user state in the room 
    //else just ignore it
    logger.abort("unhandled room state " + to_string(user_in_room_state)); //just for test to make sure we don't end up here
    
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
      //np1secSession *born_session = nullptr;
      ParticipantMap new_participant_list;
      if (dying_session.get())
        new_participant_list = session_it->second.participants + session_universe[active_session.get_as_stringbuff()].participants - session_universe[dying_session.get_as_stringbuff()].participants;
        //*born_session  = session_it->second + session_universe[active_session.get_as_stringbuff()] - session_universe[dying_session.get_as_stringbuff()];
      else
        new_participant_list = session_it->second.participants + session_universe[active_session.get_as_stringbuff()].participants;
        //*born_session  = session_it->second + session_universe[active_session.get_as_stringbuff()];
      //check if the session already exists
      SessionId to_be_born_session_id(new_participant_list);
      
      if (session_universe.find(to_be_born_session_id.get_as_stringbuff()) == session_universe.end()) { //we don't had the session, 
        try {
          session_universe.insert(pair<string, np1secSession>(to_be_born_session_id.get_as_stringbuff(), np1secSession(np1secSession::ACCEPTOR, user_state,
                                      name,
                                      &np1sec_ephemeral_crypto,
                                                                                                                       new_participant_list)));
        } catch(std::exception& e) {
          logger.error(e.what());
        }
      }
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
void np1secRoom::send_user_message(std::string plain_message)
{
  if (active_session.get()) {
    session_universe[active_session.get_as_stringbuff()].send(plain_message, np1secMessage::USER_MESSAGE);
  } else {
    logger.error("trying to send message to a room " + name +  " with no active session", __FUNCTION__, user_state->myself->nickname);
    throw np1secInvalidRoomException();
    //just for test to detect if something gone wrong
    //you can't send message now
    //TODO: maybe We should queue the messages and send them
    //when the session is established
  }
  
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
    logger.info("nothing to do; leaving from a room we haven't joined");
  }

}

void np1secRoom::shrink(std::string leaving_nick) {
  if (user_in_room_state == JOINING) {
    original_room_size--;
    try_rejoin(); //it helps because although the active session
    //of current occupants still contatins the leaver, the new
    //session will be born without zombies
    
  } else if (user_in_room_state == CURRENT_USER) {
    //we need to detect if we have already generated the shrunk
    //session or not.
    //first we get the plist of active session, if the leaving use
    logger.assert_or_die(active_session.get(), "shrinking while we have no active sessions"); 
    auto active_session_element = session_universe.find(active_session.get_as_stringbuff());
    logger.assert_or_die(active_session_element != session_universe.end(), "Internal error: the active session is not in session universe.");

    np1secSession& active_np1sec_session = active_session_element->second;

    //if (active_np1sec_session.my_state != np1secSession::FAREWELLED) {
    //alternatively we can just check the state of active_session and if 
    //it is farewelled then we don't need to worry about generating the
    //shrank session

    //this is not true anymore as many participants can request leave
    //from current session. as the result new session will be generated
    //cumulatively for participants who are leaving current session
    //until the one of the session is confirmed. therefore many farewell
    //can occure in one session.

    //because the session are staying in the session universe even after
    //they die so their existenec doesn't mean we have taken any action we
    //avoid making a new session, if the session is not made we will make
    //the new session  so not to duplicate the re-share message.
    //the reshare message has the same session id so the participants
    //handle it to the previously made session. the shares are the same.
    //Either the session is waiting for more share which result in
    //replacing the same share or is
    //waiting for confirmation and so it ignores the share message.

    //The best practice is to check the zombie list of the session,
    //if the participant is already in zombie list, we already have
    //made a session without them

    //We basically avoid sending an extra message which is not part of the protocol
    //but it is the implementation particularity, and duplicating such message whinch doesn't
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

    // SessionId shrank_session_id = active_np1sec_session.shrank_session_id(leaving_nick);
    // auto shrank_session = session_universe.find(shrank_session_id.get_as_stringbuff());
    // if (shrank_session != session_universe.end()) {
    //   //TODO: come up with a revining mechanism
    //   //revive the session, if revive fails we re-make it
    //   //shrank_session->second.revive();
    //   //if (shrank_session->second.my_state = np1sec::DEAD) {
    //   session_universe.erase(shrank_session_id.get_as_stringbuff());
    //         //shrank_session = session_universe.end();
    // }
    //as long as we are replacing it no nead to erase the std::map
    //will take care of it (not really emplace only work if there is
    //no element) but if we want to revive it then we can
    //do more

    //so we try to shrink it anyway, if the user is already zombied
    //we do nothing.
    try {
      auto action_to_take = active_np1sec_session.shrink(leaving_nick);
      if (action_to_take.action_type == RoomAction::NEW_SESSION) {
        auto old_shrank_session = session_universe.find(action_to_take.bred_session->my_session_id().get_as_stringbuff());
        if (old_shrank_session != session_universe.end()) {
          //if (old_shrank_session->second.my_state = np1sec::DEAD) { //should we check and erease only if DEAD?
          session_universe.erase(old_shrank_session->first);
        }
        session_universe.emplace(pair<string, np1secSession>(action_to_take.bred_session->my_session_id().get_as_stringbuff(),*(action_to_take.bred_session)));
      } else {
        //Already FAREWELLED: TODO you should check the zombie list actually
        logger.info("no need to shrink. Already farewelled.");
        //otherwise we already have made the
        //shrank session don't worry about it
      }
    } catch (std::exception &e) {
      logger.error("failed to shrink the session", __FUNCTION__, user_state->myself->nickname);
      logger.error(e.what(), __FUNCTION__, user_state->myself->nickname);
    }
   
    //active session
    //else do nothing basically TODO::somebody should throw out the room though
    //else {
    //  logger.warn("room contains no active sesssion");
  } // not current user, do nothing
  
}


