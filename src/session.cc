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

#include <assert.h>
#include <stdlib.h>
#include <string>

#include "src/session.h"
#include "src/exceptions.h"
#include "src/userstate.h"

using namespace std;

void MessageDigest::update(std::string new_message) {
  UNUSED(new_message);
  return;
}

void cb_send_heartbeat(evutil_socket_t fd, short what, void *arg) {
  np1secSession* session = (static_cast<np1secSession*>(arg));
  session->send("Heartbeat", np1secMessage::PURE_META_MESSAGE);
  //session->start_heartbeat_timer();
}
                         
void cb_ack_not_received(evutil_socket_t fd,short what,void *arg) {
  // Construct message for ack
  np1secSession* session = (static_cast<np1secSession*>(arg));
  session->send("Where is my ack?", np1secMessage::PURE_META_MESSAGE);

}

void cb_send_ack(evutil_socket_t fd, short what, void *arg) {
  // Construct message with p.id
  np1secSession* session = (static_cast<np1secSession*>(arg));
  session->send("ACK", np1secMessage::PURE_META_MESSAGE);

}

// TODO: Who is calling this? Answer: compute_session_id
// TODO: This should move to crypto really and called hash with
// overloaded parameters
gcry_error_t np1secSession::compute_hash(HashBlock transcript_chain,
                                     std::string message) {
  assert(message.size() % 2 == 0);

  unsigned char *bin;
  const char *p = message.c_str();
  for (int i=0; i < message.size(); i++, p+=2) {
    sscanf(p, "%2hhx", &bin);
  }
  return cryptic.hash(bin, message.size()/2, transcript_chain, true);
}

//All constructors
// np1secSession::np1secSession(np1secUserState *us)
//   :myself(us->user_id())
// {
//   throw std::invalid_argument("Default constructor should not be used.");
// }

/**
   sole joiner constructor
 */
np1secSession::np1secSession(np1secUserState *us, std::string room_name,
                             Cryptic* current_ephemeral_crypto,
                             const UnauthenticatedParticipantList& sole_participant_view) : us(us), room_name(room_name),  cryptic(*current_ephemeral_crypto), myself(*us->myself)

{
  my_state = DEAD; //in case anything fails

  populate_participants_and_peers(sole_participant_view);

  //if participant[myself].ephemeral is not crytpic ephemeral, halt
  compute_session_id();

  if (send_view_auth_and_share())
    my_state = RE_SHARED;

}

/**
 * This constructor should be only called when the session is generated
 * to join. That's why all participant are not authenticated.
 */
np1secSession::np1secSession(np1secUserState *us, std::string room_name,
                             Cryptic* current_ephemeral_crypto,
                             np1secMessage participants_info_message) : us(us), room_name(room_name),  cryptic(*current_ephemeral_crypto)
{
  my_state = DEAD; //in case anything fails

  //TODO:: obviously we need an access function to make sure there is joiner info
  //update participant info or let it be there if they are consistent with
  //UnauthenticatedParticipantList session_view() = participants_info_message.session_view();
  //the participant is added unauthenticated
  populate_participants_and_peers(participants_info_message.session_view);

  //keep the z_share
  participants[participants_info_message.sender_id].set_key_share(reinterpret_cast<const uint8_t*>(participants_info_message.z_sender.c_str()));

  //TODO::make sure we are added correctly
  //if participant[myself].ephemeral is not crytpic ephemeral, halt
  compute_session_id();

  my_state = JOIN_REQUESTED;
  
}

/**
 * Almost copy constructor, we only alter the plist
 */
// np1secSession::np1secSession(np1secSession& breeding_session, 
//               ParticipantMap updated_participants)
//   :participants(updated_participants)
// {

//   compute_session_id();
  
// }


/**
   Constructor being called by current participant receiving join request
   That's why (in room) participants are are already authenticated
   
     - in new session constructor these will happen
       - computes session_id
       - compute kc = kc_{sender, joiner}
       - compute z_sender (self)
       - set new session status to REPLIED_TO_NEW_JOIN
       - send 
 */
np1secSession::np1secSession(np1secUserState *us, std::string room_name, np1secMessage join_message, ParticipantMap current_authed_participants)
  :room_name(room_name),
   myself(*us->myself)
   //TODO: not sure the session needs to know the room name: It needs because message class
          //need  to know to send the message to :-/
          //send should be the function of np1secRoom maybe :-?
{
  my_state = DEAD; //in case anything fails
  
  this->participants = current_authed_participants;
  UnauthenticatedParticipant  joiner(join_message.joiner_info);
  //TODO:: obviously we need an access function to make sure there is joiner info
  //update participant info or let it be there if they are consistent with

  this->participants.insert(pair<string,Participant> (joiner.participant_id.nickname, Participant(joiner, &cryptic)));
  peers.push_back(joiner.participant_id.nickname);
  keep_peers_in_order_spot_myself(); 
  //the participant is added unauthenticated
  //TODO::    throw np1secMessageFormatException(); when message is bad

  //We can't authenticate here, join message doesn't have kc
  // if (!participants[received_message.sender_id].authenticate(my_id, received_message.kc)) {
  //   return;
  // }

  compute_session_id();
}

/**
   Constructor being called by current participant receiving leave request
   
     - in new session constructor these will happen
       - drop leaver
       - computes session_id
       - compute z_sender (self)
       - set new session status to RE_SHARED

*/
np1secSession::np1secSession(np1secUserState* us, std::string room_name, string leaver_id, ParticipantMap current_authed_participants)
  :room_name(room_name),
   myself(*us->myself)
   //TODO: not sure the session needs to know the room name
{
  my_state = DEAD; //in case anything fails

  participants = current_authed_participants;
  current_authed_participants.erase(leaver_id);

  auto it = std::find(peers.begin(), peers.end(), leaver_id);
  if(it != peers.end())
    peers.erase(it);

  keep_peers_in_order_spot_myself(); 

  /*if (!participants[participant_id].set_ephemeral_key(it->ephemeral_key))
    throw np1secMessage::MessageFormatException;*/

  compute_session_id();
  if (send_auth_and_share_message()) //TODO a reshare message
    my_state = RE_SHARED;

}

/**
   Constructor being called by operator+ and operator- to breed 
   new (unestablished) session
   
     - in new session constructor these will happen
       - computes session_id
       - compute z_sender (self)
       - set new session status to RE_SHARED

*/
np1secSession::np1secSession(np1secUserState* us, std::string room_name, ParticipantMap current_authed_participants)
  :room_name(room_name),
   myself(*us->myself)
   //TODO: not sure the session needs to know the room name
{
  my_state = DEAD; //in case anything fails

  participants = current_authed_participants;

  populate_peers_from_participants();
  compute_session_id();
  
  if (send_view_auth_and_share())
    my_state = RE_SHARED;

}

np1secSession np1secSession::operator+(np1secSession a) {
  std::map<std::string, Participant> combination;
  combination.insert(participants.begin(), participants.end());
  combination.insert(a.participants.begin(), a.participants.end());
  np1secSession new_session(us, room_name, combination);

  return new_session;
  
}

np1secSession np1secSession::operator-(np1secSession a) {
  std::map<std::string, Participant> difference;
  std::set_difference(
    participants.begin(), participants.end(),
    a.participants.begin(), a.participants.end(),
    std::inserter(difference, difference.end()));
  np1secSession new_session(us, room_name, difference);

  return new_session;
}

/**
 * it should be invoked only once to compute the session id
 * if one need session id then they need a new session
 *
 * @return return true upon successful computation
 */
//TODO::move this to SessionId Class
bool np1secSession::compute_session_id() {
  std::string cat_string = "";

  if (peers.size() == 0) //nothing to compute
    return false;

  /**
   * Generate Session ID
   */

  //session_id = Hash of (U1,ehpmeral1, U2);
  for (std::vector<std::string>::iterator it = peers.begin(); it != peers.end(); ++it) {
    Participant& p = participants[*it];
    cat_string += p.id.id_to_stringbuffer();
    cat_string += cryptic.hash_to_string_buff(p.raw_ephemeral_key);
  }

  HashBlock sid;
  compute_hash(sid, cat_string); //why just not having  simple function which
  //compute the hash of an string
  assert(!session_id.get()); //if session id isn't set we have to set it
  session_id.set(sid);
  return true;

}

/**
 *  setup session view based on session view message,
 *  note the session view is set once and for all change in 
 *  session view always need new session object.
 */
bool np1secSession::setup_session_view(np1secMessage session_view_message) {

  assert(0);
  populate_participants_and_peers(session_view_message.session_view);
  // //First get a list of user identities
  // UnauthenticatedParticipantList plist =  session_view_message.session_view()();
  // //update participant info or let it be there if they are consistent with

  // for(UnauthenticatedParticipantList::iterator it = plist.begin(); it != plist.begin(); it++) {
  //     //new participant we need to recompute the session id
  //   participants.insert(pair<string, Participant>(it->participant_id.nickname,Participant(it->participant_id, cryptic))); //the participant is added unauthenticated
  //   if (!participants[it->participant_id.nickname].set_ephemeral_key(it->ephemeral_pub_key))
  //     throw np1secMessageFormatException();

  // }

  // populate_peers_from_participants();
  compute_session_id();

}

//TODO:: add check for validity of session key
bool np1secSession::compute_session_confirmation()
{
  string to_be_hashed = Cryptic::hash_to_string_buff(session_key);
  to_be_hashed += myself.nickname;

  Cryptic::hash(to_be_hashed, session_confirmation);

  return true;
  
}

bool np1secSession::validate_session_confirmation(np1secMessage confirmation_message)
{
  HashBlock expected_hash;

  string to_be_hashed = Cryptic::hash_to_string_buff(session_key);
  to_be_hashed += confirmation_message.sender_id;

  Cryptic::hash(to_be_hashed, expected_hash);

  return Cryptic::compare_hash(expected_hash, reinterpret_cast<const uint8_t*>(confirmation_message.session_key_confirmation.c_str()));
  
}

bool np1secSession::group_enc() {
  unsigned int my_right = (my_index + 1 == peers.size()) ? 0 : my_index+1;
  unsigned int my_left = (my_index == 0) ? peers.size() - 1 : my_index-1;
  std::string to_hash_right = Cryptic::hash_to_string_buff(participants[peers[my_right]].p2p_key) + session_id.get_as_stringbuff();
  std::string to_hash_left = Cryptic::hash_to_string_buff(participants[peers[my_left]].p2p_key) + session_id.get_as_stringbuff();

  HashBlock hbr;
  Cryptic::hash(to_hash_right.c_str(), to_hash_right.size(), hbr, true);

  HashBlock hbl;
  Cryptic::hash(to_hash_left.c_str(), to_hash_left.size(), hbl, true);

  for (unsigned i=0; i < sizeof(HashBlock); i++) {
      hbr[i] ^= hbl[i];
  }

  memcpy(participants[myself.nickname].cur_keyshare, hbr, sizeof(HashBlock));

  return true;
  
}

bool np1secSession::group_dec() {
  unsigned int my_right = (my_index + 1 == peers.size()) ? 0 : my_index+1;
  std::vector<std::string> all_r(peers.size());
  HashBlock last_hbr;

  //We assume that user has computed his share
  // std::string to_hash_right = Cryptic::hash_to_string_buff(participants[peers[my_right]].p2p_key) + session_id.get_as_stringbuff();
  //   HashBlock hbr;
  //Cryptic::hash(to_hash_right.c_str(), to_hash_right.size(), hbr, true);
  HashBlock hbr;
  
  memcpy(hbr, participants[peers[my_index]].cur_keyshare, sizeof(HashBlock));
  //memcpy(all_r[my_index], hbr, sizeof(HashBlock));
  all_r[my_index] = Cryptic::hash_to_string_buff(hbr);
  for (unsigned i=0; i < sizeof(HashBlock); i++) {
    hbr[i] ^= participants[peers[my_right]].cur_keyshare[i];
  }
  //memcpy(all_r[my_right], hbr, sizeof(HashBlock));
  all_r[my_right] = Cryptic::hash_to_string_buff(hbr);
  memcpy(last_hbr, hbr, sizeof(HashBlock));

  for (unsigned counter = 0; counter < peers.size(); counter++) {
       
    for (unsigned i=0; i < sizeof(HashBlock); i++) {
        last_hbr[i] ^= participants[peers[my_right]].cur_keyshare[i];
   }
    //memcpy(all_r[my_right], last_hbr, sizeof(HashBlock));
    all_r[my_right] = Cryptic::hash_to_string_buff(last_hbr);
    my_right = (my_right + 1 == peers.size()) ? 0 : my_right+1;
  } 

  std::string to_hash;
  for (std::vector<std::string>::iterator it = all_r.begin(); it != all_r.end(); ++it) {
    to_hash += (*it).c_str();
  }

  to_hash += session_id.get_as_stringbuff();
  HashBlock session_key;
  Cryptic::hash(to_hash.c_str(), to_hash.size(), session_key, true);
  cryptic.set_session_key(session_key);

  return true; //check if the recovered left is the same as calculated left
  
}

bool np1secSession::everybody_authenticated_and_contributed()
{
  for(ParticipantMap::iterator it = participants.begin(); it != participants.end(); it++)
    if (!it->second.authenticated || !it->second.key_share_contributed)
      return false;

  return true;
  
}

bool np1secSession::everybody_confirmed()
{
  for(vector<bool>::iterator it = confirmed_peers.begin(); it != confirmed_peers.end(); it++)
    if (!(*it))
      return false;

  return true;
  
}

/**
 *   Joiner call this after receiving the participant info to
 *    authenticate to everybody in the room
 */
bool np1secSession::joiner_send_auth_and_share() {
  assert(session_id.get()); //sanity check
  if (!group_enc()) //compute my share for group key
    return false;

  HashBlock cur_auth_token;

  std::string auth_batch;

  for(uint32_t i = 0; i < peers.size(); i++) {
    if (!participants[peers[i]].authed_to) {
      participants[peers[i]].authenticate_to(cur_auth_token, us->long_term_key_pair.get_key_pair().first);
      auth_batch.append(reinterpret_cast<char*>(&i), sizeof(uint32_t));
      auth_batch.append(reinterpret_cast<char*>(cur_auth_token), sizeof(HashBlock));
    }
  }

  UnauthenticatedParticipantList temp_view = session_view();
  np1secMessage outboundmessage(session_id,
                                np1secMessage::JOINER_AUTH,
                                temp_view, //this is empty and shouldn't be sent
                                auth_batch,
                                "",
                                "",
                                string(reinterpret_cast<char*>(participants[myself.nickname].cur_keyshare), sizeof(HashBlock)),
                                us,
                                room_name);

}

/**
 *  Current participant sends this to the room
 *  to re share? 
 *  TODO: when do actually we need to call this
 *  When a partcipant leave
 */
bool np1secSession::send_auth_and_share_message() {
  assert(session_id.get());
  if (!group_enc()) //compute my share for group key
    return false;

  HashBlock cur_auth_token;
  //if (!participants[joiner_id].authed_to) {
  //participants[joiner_id].authenticate_to(cur_auth_token);

  UnauthenticatedParticipantList session_view_list = session_view();
  np1secMessage outboundmessage(session_id,
                                np1secMessage::GROUP_SHARE,
                                session_view_list,
                                "",//auth_token,
                                "",//session conf
                                "",//joiner info
                                string(reinterpret_cast<char*>(participants[myself.nickname].cur_keyshare), sizeof(HashBlock)),
                                us,
                                room_name);
  outboundmessage.send();
  return true;

}

/**
   Preparinig PARTICIPANT_INFO Message

    current user calls this to send participant info to joiner
    and others
    sid, ((U_1,y_i)...(U_{n+1},y_{i+1}), kc, z_joiner
*/
bool np1secSession::send_view_auth_and_share(string joiner_id) {
  assert(session_id.get());
  if (!group_enc()) //compute my share for group key
    return false;

  HashBlock cur_auth_token;
  if (!joiner_id.empty())
    if (!participants[joiner_id].authed_to)
      participants[joiner_id].authenticate_to(cur_auth_token, us->long_term_key_pair.get_key_pair().first);

  UnauthenticatedParticipantList session_view_list = session_view();
  np1secMessage outboundmessage(session_id,
                                np1secMessage::PARTICIPANTS_INFO,
                                session_view_list,
                                string(reinterpret_cast<char*>(cur_auth_token), sizeof(HashBlock)),
                                "", //session conf
                                "", //joiner info
                                string(reinterpret_cast<char*>(participants[myself.nickname].cur_keyshare), sizeof(HashBlock)),
                                us,
                                room_name);

  outboundmessage.send();
  return true;

}

//DEPRICATED in favor of send_view_auth_share_message
/**
   Current user will use this to inform new user
   about their share and also the session plist klist

*/
// bool np1secSession::send_share_message() {
//   assert(session_id_is_set);
//   if (!group_enc()) //compute my share for group key
//     return false;
  
//   np1secMessage outboundmessage.create_participant_info(RE_SHARE,
//                                                         sid,
//                                                         //unauthenticated_participants
//                                                         //"",//auth_batch,
//                                                         session_key_share);
//   outboundmessage.send();
//   return true;

// }

/**
 * Receives the pre-processed message and based on the state
 * of the session decides what is the appropriate action
 *
 * @param receive_message pre-processed received message handed in by receive function
 *
 * @return true if state has been change 
 */
RoomAction np1secSession::state_handler(np1secMessage received_message)
{
  if (np1secFSMGraphTransitionMatrix[my_state][received_message.message_type]) //other wise just ignore
    {
      StateAndAction result  = (this->*np1secFSMGraphTransitionMatrix[my_state][received_message.message_type])(received_message);
      my_state = result.first;
      return result.second;
    }
  
  return RoomAction(RoomAction::BAD_ACTION);

//depricated in favor of double array fsm model
  // switch(my_state) {
  //   case np1secSession::NONE:
  //     //This probably shouldn't happen, if a session has
  //     //no state state_handler shouldn't be called.
  //     //The receive_handler of the user_state should call
  //     //approperiate inition of a session of session less
  //     //message
  //     throw  np1secSessionStateException();
  //     break;
        
  //   case np1secSession::JOIN_REQUESTED: //The thread has requested to join by sending ephemeral key
  //     //Excepting to receive list of current participant
  //     break;
  //   case np1secSession::REPLIED_TO_NEW_JOIN: //The thread has received a join from a participant replied by participant list
  //     break;
  //   case np1secSession::GROUP_KEY_GENERATED: //The thread has computed the session key and has sent the conformation
  //     break;
  //   case np1secSession::IN_SESSION: //Key has been confirmed      
  //     break;
  //   case np1secSession::UPDATED_KEY: //all new shares has been received and new key has been generated: no more send possible
  //     break;
  //   case np1secSession::LEAVE_REQUESTED: //Leave requested by the thread: waiting for final transcirpt consitancy check
  //     break;
  //   case np1secSession::FAREWELLED: //LEAVE is received from another participant and a meta message for transcript consistancy and new shares has been sent
  //     break;
  //   case np1secSession::DEAD: //Won't accept receive or sent messages, possibly throw up
  //     break;
  //   default:
  //     return false;
  // };
  
}

//***** Joiner state transitors ****

/**
   For join user calls this when receivemessage has type of PARTICIPANTS_INFO
   
   sid, ((U_1,y_i)...(U_{n+1},y_{i+1}), (kc_{sender, joiner}), z_sender

   - Authenticate sender if fail halt

   for everybody including the sender

   joiner should:
   - set session view
   - compute session_id
   - add z_sender to the table of shares 
   - compute kc = kc_{joiner, everybody}
   - compute z_joiner
   - send 
   sid, ((U_1,y_i)...(U_{n+1},y_{i+1}), kc, z_joiner
*/
np1secSession::StateAndAction np1secSession::auth_and_reshare(np1secMessage received_message) {
  if (!session_id.get()) {
    if (!setup_session_view(received_message))
      return StateAndAction(DEAD, RoomAction(RoomAction::NO_ACTION));
    else
      joiner_send_auth_and_share();
  }

  if (participants.find(received_message.sender_id) != participants.end())
    return StateAndAction(DEAD, RoomAction(RoomAction::NO_ACTION));

  if (!participants[received_message.sender_id].be_authenticated(myself.id_to_stringbuffer(), reinterpret_cast<const uint8_t*>(received_message.key_confirmation.c_str()), us->long_term_key_pair.get_key_pair().first))
    return StateAndAction(DEAD, RoomAction(RoomAction::NO_ACTION));

  participants[received_message.sender_id].set_key_share(reinterpret_cast<const uint8_t*>(received_message.z_sender.c_str()));

  return StateAndAction(my_state, RoomAction(RoomAction::NO_ACTION));

  //TODO: check the ramification of lies by other participants about honest
  //participant ephemeral key. Normally nothing should happen as we recompute
  //the session id and so the session will never get messages from honest
  //participants and so will never be authed.

}

/**
   For the joiner user, calls it when receive a session confirmation
   message.
   
   sid, ((U_1,y_i)...(U_{n+1},y_{i+1}), hash(GroupKey, U_sender)
   
   of SESSION_CONFIRMATION type
   
   if it is the same sid as the session id, marks the confirmation in 
   the confirmation list for the sender. If all confirmed, change 
   state to IN_SESSION, call the call back join from ops.
   
   If the sid is different send a new join request
   
*/
np1secSession::StateAndAction np1secSession::confirm_or_resession(np1secMessage received_message) {
  //if sid is the same mark the participant as confirmed
  //receiving mismatch sid basically means rejoin
  if (Cryptic::compare_hash(received_message.session_id, session_id.get())) {
    if (validate_session_confirmation(received_message))
      confirmed_peers[participants[received_message.sender_id].index] = true;
    else {
      return StateAndAction(DEAD, RoomAction(RoomAction::NO_ACTION));
    }

    if (everybody_confirmed())
      return StateAndAction(IN_SESSION, RoomAction(RoomAction::NO_ACTION));
    
  }
  
  //Depricated: in the new model it is the np1sec room which check for
  //non matching sid and make a new session for it.
  // else {
  //   //we need to rejoin, categorically we are against chanigng session id
  //   //so we make a new session. This make us safely ignore replies to
  //   //old session id (they go to the dead session)
  //   np1secSession* new_child_session = new np1secSession(room_name); //calling join constructor;
  //   if (new_child_session->session_id_is_set) {
  //     new_child_session->my_parent = this;
  //     my_children[new_child_session->session_id] = new_child_session;
  //   }
  //   return StateAndAction(DEAD, RoomAction(RoomAction::NO_ACTION));
  // }

  return StateAndAction(my_state, RoomAction(RoomAction::NO_ACTION));
        
}

//*****JOINER state transitors END*****

//*****Current participant state transitors*****
/**
     For the current user, calls it when receive JOIN_REQUEST with
     
     (U_joiner, y_joiner)

     - start a new new participant list which does
     
     - computes session_id
     - new session does:
     - compute kc = kc_{joiner, everybody}
     - compute z_sender (self)
     - set new session status to REPLIED_TO_NEW_JOIN
     - send

     sid, ((U_1,y_i)...(U_{n+1},y_{i+1}), (kc_{sender, joiner}), z_sender
     
     of PARTICIPANT_INFO message type

     change status to REPLIED_TO_NEW_JOIN

 */
np1secSession::StateAndAction np1secSession::send_auth_share_and_participant_info(np1secMessage received_message)
{

  RoomAction new_session_action;
  np1secSession* new_child_session = new np1secSession(us, room_name, received_message, participants);
  
  if (!new_child_session->session_id.get()) 
    delete new_child_session; //failed to establish a legit session
  else {
    new_child_session->send_view_auth_and_share(received_message.joiner_info);
    new_child_session->my_state = REPLIED_TO_NEW_JOIN;

    new_session_action.action_type = RoomAction::NEW_SESSION;
    new_session_action.bred_session = new_child_session;

    //This broadcast not happens in session constructor because sometime we want just to make
    //a session object and not tell the whole world about it.
  }
   //Depricated: np1secRoom manages the set of sessions
   //new_child_session->my_parent = this;
   //my_children[new_child_session->session_id] = new_child_session;

   //TODO: this is incomplete, you need to report your session 
   //to the room. more logically the room just need to request the
   //creation of the room.
   // }
   // else {*
   //   //throw the session out
   //   //trigger the session (in-lmbo) about the repeated join/
   //   */
    
  //our state doesn't need to change
  return StateAndAction(my_state, new_session_action);

}

/**
   For the current user, calls it when receive JOINER_AUTH
   
   sid, U_sender, y_i, _kc, z_sender, signature

   or PARTICIPANT_INFO from users in the session
   
   - Authenticate joiner halt if fails
   - Change status to AUTHED_JOINER
   - Halt all sibling sessions
   
   - add z_sender to share table
   - if all share are there compute the group key send the confirmation
   
   sid, hash(GroupKey, U_sender), signature 
   
   change status GROUP_KEY_GENERATED
   otherwise no change to the status
   
*/
np1secSession::StateAndAction np1secSession::confirm_auth_add_update_share_repo(np1secMessage received_message) {
  if (received_message.message_type == np1secMessage::JOINER_AUTH) {
    if (!participants[received_message.sender_id].be_authenticated(myself.nickname, Cryptic::strbuff_to_hash(received_message.key_confirmation), us->long_term_key_pair.get_key_pair().first))  {
      return StateAndAction(DEAD, RoomAction());
    }

    //kill_all_my_siblings(); 
    participants[received_message.sender_id].set_key_share(Cryptic::strbuff_to_hash(received_message.z_sender));
  }
  //else { //assuming the message is PARTICIPANT_INFO from other in
    //session people
    
  //}
  UnauthenticatedParticipantList session_view_list = session_view();
  if (everybody_authenticated_and_contributed()) {
    if (group_dec()) {
      np1secMessage outboundmessage(session_id,
                                    np1secMessage::SESSION_CONFIRMATION,
                                    session_view_list,
                                    "", //auth
                                    Cryptic::hash_to_string_buff(session_confirmation),
                                    "", //joiner_info
                                    "", //z
                                    us,
                                    room_name);
      
      outboundmessage.send();

      return StateAndAction(GROUP_KEY_GENERATED, RoomAction());
    }

    return StateAndAction(DEAD, RoomAction());
  }
  //otherwise just wait for more shares
  return StateAndAction(my_state, RoomAction());
  
}

/**
   For the current user, calls it when receive a session confirmation
   message.
   
   sid, hash(GroupKey, U_sender), signature
   
   if it is the same sid as the session id, marks the confirmation in 
   the confirmation list for the sender. If all confirmed, change 
   state to IN_SESSION, make this session the main session of the
   room
   
   If the sid is different, something is wrong halt drop session
   
*/
np1secSession::StateAndAction np1secSession::mark_confirmed_and_may_move_session(np1secMessage received_message) {
  //TODO:realistically we don't need to check sid, if sid
  //doesn't match we shouldn't have reached this point
  if (validate_session_confirmation(received_message))
    confirmed_peers[participants[received_message.sender_id].index] = true;
  else
    return StateAndAction(DEAD, c_no_room_action);
  
  confirmed_peers[participants[received_message.sender_id].index] = true;
  
  if (everybody_confirmed()) {
    //activate(); it is matter of changing to IN_SESSION
    return StateAndAction(IN_SESSION, c_no_room_action);
  }

  return StateAndAction(my_state, c_no_room_action);
    
}

/**
 * This will be called when another user leaves a chatroom to update the key.
 * 
 * This should send a message the same an empty meta message for sending
 * the leaving user the status of transcript consistency
 * 
 * This also make new session which send message of Of FAREWELL type new
 * share list for the shrinked session 
 *
 * sid, z_sender, transcript_consistency_stuff
 *
 * kills all sibling sessions in making as the leaving user is no longer 
 * available to confirm any new session.
 * 
 * The status of the session is changed to farewelled. 
 * The statatus of new sid session is changed to re_shared
 */
np1secSession::StateAndAction np1secSession::send_farewell_and_reshare(np1secMessage received_message) {

  //TODO::chose the requested hash not any hash
  HashBlock* transcript_chain_hash = transcript_chain.rbegin()->second;
  
  np1secLoadFlag meta_load_flag = NO_LOAD;
  std::string meta_load = NULL;
  np1secMessage outbound(session_id,
                         myself.nickname,
                         "", //no user message
                         np1secMessage::FAREWELL,
                         *transcript_chain_hash,
                         meta_load_flag,
                         meta_load,
                         peers,
                         &cryptic,
                         us,
                         room_name);


  np1secSession* new_child_session = new np1secSession(us, room_name, received_message, participants); //TODO::we need a different constructor for leave, for the reason of tracking RaisonDEtre
  
  RoomAction new_session_action;
  //if (new_child_session->session_id.get()) { //why it should fail?
  assert(new_child_session->session_id.get());
  new_session_action.action_type = RoomAction::NEW_SESSION;
  new_session_action.bred_session = new_child_session;
    
  return StateAndAction(FAREWELLED, c_no_room_action);
    
  //our state doesn't need to change
  //return StateAndAction(my_state, c_no_room_action);

}

//Depricated: room take care of join and make a new session
// bool np1secSession::join(LongTermIDKey long_term_id_key) {
//   //don't come here
//   assert(0);
//   //We need to generate our ephemerals anyways
//   if (!cryptic.init()) {
//     return false;
//   }
//   myself.ephemeral_key = cryptic.get_ephemeral_pub_key();

//   //we add ourselves to the (authenticated) participant list
//   participants[myself.id];
//   peers[0]=myself.id;

//   // if nobody else is in the room have nothing to do more than
//   // just computing the session_id
//   if (session_view().size()== 1) {
//     assert(this->compute_session_id());
         
//   }
//   else {
    
//   }
//   us->ops->send_bare(room_name, us->user_id(), "testing 123", NULL);
//   return true;
// }

// bool np1secSession::accept(std::string new_participant_id) {
//   UNUSED(new_participant_id);
//   return true;
// }

//TODO: this blong to message class
bool np1secSession::received_p_list(std::string participant_list) {
  //Split up participant list and load it into the map
  assert(0);
  char* tmp = strdup(participant_list.c_str());

  std::string ids_keys = strtok(tmp, c_np1sec_delim.c_str());
  std::vector<std::string> list_ids_keys;
  while (!ids_keys.empty()) {
    std::string decoded = "";
    otrl_base64_otr_decode(ids_keys.c_str(),
                           (unsigned char**)decoded.c_str(),
                           reinterpret_cast<size_t*>(ids_keys.size()));
    list_ids_keys.push_back(ids_keys);
    ids_keys = strtok(NULL, c_np1sec_delim.c_str());
  }

  for (std::vector<std::string>::iterator it = list_ids_keys.begin();
       it != list_ids_keys.end(); ++it) {
    tmp = strdup((*it).c_str());
    std::string id = strtok(tmp, c_np1sec_delim.c_str());
    std::string key = strtok(NULL, c_np1sec_delim.c_str());
    gcry_sexp_t sexp_key = Cryptic::convert_to_sexp(key); 
    Participant p();//id, crypto);
    //p.ephemeral_key = sexp_key;
    //session_view().push_back(UnauthenticatedParticipant(ParticipantId(id, p)));
  }

  return true;
}

// bool np1secSession::farewell(std::string leaver_id) {
//   UNUSED(leaver_id);
//   return true;
// }

void np1secSession::start_heartbeat_timer() {
  struct event *timer_event;
  struct timeval ten_seconds = {10, 0};
  struct event_base *base = event_base_new();

  timer_event = event_new(base, -1, EV_TIMEOUT, &cb_send_heartbeat, this);
  event_add(timer_event, &ten_seconds);

  event_base_dispatch(base);
}

void np1secSession::start_ack_timers() {
  struct event *timer_event;
  struct timeval ten_seconds = {10, 0};
  struct event_base *base = event_base_new();

  for (ParticipantMap::iterator it = participants.begin();
       it != participants.end();
       ++it) {
    timer_event = event_new(base, -1, EV_TIMEOUT, cb_ack_not_received, this);
    (*it).second.receive_ack_timer = timer_event;
    event_add((*it).second.receive_ack_timer, &ten_seconds);
  }

  event_base_dispatch(base);
}

void np1secSession::start_receive_ack_timer(std::string sender_id) {
  struct event *timer_event;
  struct timeval ten_seconds = {10, 0};
  struct event_base *base = event_base_new();

  //msg = otrl_base64_otr_encode((unsigned char*)combined_content.c_str(),
  //                             combined_content.size());
  //(us->ops->send_bare)(room_name, myself.id, msg, static_cast<void*>(us));

  timer_event = event_new(base, -1, EV_TIMEOUT, &cb_send_ack, this);
  participants[sender_id].receive_ack_timer = timer_event;
  event_add(participants[sender_id].receive_ack_timer, &ten_seconds);
  event_base_dispatch(base);
}

void np1secSession::stop_timer_send() {
  for (std::map<std::string, Participant>::iterator
       it = participants.begin();
       it != participants.end();
       ++it) {
    event_free((*it).second.send_ack_timer);
  }
}

void np1secSession::stop_timer_receive(std::string acknowledger_id) {
  event_free(participants[acknowledger_id].receive_ack_timer);
}

void np1secSession::add_message_to_transcript(std::string message,
                                        uint32_t message_id) {
  HashBlock *hb;
  std::stringstream ss;
  std::string pointlessconversion;

  ss << transcript_chain.rbegin()->second;
  ss >> pointlessconversion;
  pointlessconversion += c_np1sec_delim + message;

  compute_message_hash(*hb, pointlessconversion);

  transcript_chain[message_id] = hb;
}

bool np1secSession::send(std::string message, np1secMessage::np1secMessageType message_type) {
  HashBlock* transcript_chain_hash = transcript_chain.rbegin()->second;
  // TODO(bill)
  // Add code to check message type and get
  // meta load if needed
  np1secLoadFlag meta_load_flag = NO_LOAD;
  std::string meta_load = NULL;
  np1secMessage outbound(session_id, us->user_id(),
                         message, message_type,
                         *transcript_chain_hash,
                         meta_load_flag, meta_load,
                         peers,
                         &cryptic,
                         us,
                         room_name);

  // As we're sending a new message we are no longer required to ack
  // any received messages
  stop_timer_send();

  if (message_type == np1secMessage::USER_MESSAGE) {
    // We create a set of times for all other peers for acks we expect for
    // our sent message
    start_ack_timers();
  }

  // us->ops->send_bare(room_name, outbound);
  return true;
  
}

np1secMessage np1secSession::receive(std::string raw_message) {
  HashBlock* transcript_chain_hash = transcript_chain.rbegin()->second;
  np1secMessage received_message(raw_message, &cryptic, us, room_name);

  if (*transcript_chain_hash == received_message.transcript_chain_hash) {
    add_message_to_transcript(received_message.user_message,
                        received_message.message_id);
    // Stop awaiting ack timer for the sender
    stop_timer_receive(received_message.sender_id);

    // Start an ack timer for us so we remember to say thank you
    // for the message
    start_receive_ack_timer(received_message.sender_id);

  } else {
    // The hash is a lie!
  }

  if (received_message.message_type == np1secMessage::SESSION_P_LIST) {
    //TODO
    // function to separate peers
    // add peers to map
    // convert load to sexp
  }

  return received_message;

}

np1secSession::~np1secSession() {
  //delete session_id;
  //return;
}

gcry_error_t np1secSession::compute_message_hash(HashBlock transcript_chain,
                                     std::string message) {
  return Cryptic::hash(message.c_str(), message.size(), transcript_chain, true);
}
