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

namespace np1sec {

/**
 * To be used in std::sort to sort the particpant list
 * in a way that is consistent way between all participants
 */
bool compare_creation_priority(const  RaisonDEtre& lhs, const RaisonDEtre& rhs) 
{
  return lhs.reason <= rhs.reason;

}

void cb_re_session(void *arg) {
  np1secSession* session = (static_cast<np1secSession*>(arg));
  logger.assert_or_die(session->my_state != np1secSession::DEAD,"postmortem racheting?");

  logger.info("RESESSION: forward secrecy ratcheting", __FUNCTION__, session->myself.nickname);

  np1secSession* new_child_session = new np1secSession(np1secSession::PEER, session->us, session->room_name, &session->future_cryptic, session->future_participants());

  try {
    logger.assert_or_die(session->us->chatrooms.find(session->room_name) != session->us->chatrooms.end(), "np1sec can not add session to room " + session->room_name + " which apparenly doesn't exists", __FUNCTION__, session->myself.nickname);

    session->us->chatrooms[session->room_name].insert_session(new_child_session);
  } catch(std::exception& e) {
    logger.error("Failed to resession to ensure forward secrecy", __FUNCTION__, session->myself.nickname);

  }

  session->session_life_timer = nullptr;
  
}
                         
void cb_ack_not_received(void *arg) {
  // Construct message for ack
  AckTimerOps* ack_timer_ops = static_cast<AckTimerOps*>(arg);

  if (ack_timer_ops->session->my_state == np1secSession::DEAD)
    logger.debug("postmortem consistency chcek", __FUNCTION__, ack_timer_ops->session->myself.nickname);

  std::string ack_failure_message = ack_timer_ops->participant->id.nickname + " failed to ack";
  ack_timer_ops->session->us->ops->display_message(ack_timer_ops->session->room_name, "np1sec directive", ack_failure_message, ack_timer_ops->session->us);
    logger.warn(ack_failure_message + " in room " + ack_timer_ops->session->room_name, __FUNCTION__, ack_timer_ops->session->myself.nickname);

    //this is object (not pointer) in the message chain
    //it gets destroyed when the chain get destroyed
    //delete ack_timer_ops;
  
}

void cb_send_ack(void *arg) {
  // Construct message with p.id
  np1secSession* session = (static_cast<np1secSession*>(arg));

  if (session->my_state == np1secSession::DEAD)
    logger.debug("postmortem consistency chcek", __FUNCTION__, session->myself.nickname);

  session->send_ack_timer = nullptr;

  logger.debug("long time, no messege! acknowledging received messages", __FUNCTION__, session->myself.nickname);
  
  session->send("", np1secMessage::JUST_ACK);

}

/**
 * The timer set upon of sending a message.
 * when this timer is timed out means that 
 * we haven't received our own message
 */
void cb_ack_not_sent(void* arg) {
  // Construct message with p.id
  AckTimerOps* ack_timer_ops = static_cast<AckTimerOps*>(arg);

  if (ack_timer_ops->session->my_state == np1secSession::DEAD)
    logger.debug("postmortem consistency chcek", __FUNCTION__, ack_timer_ops->session->myself.nickname);

  std::string ack_failure_message = "we did not receive our own sent message";
  ack_timer_ops->session->us->ops->display_message(ack_timer_ops->session->room_name, "np1sec directive", ack_failure_message, ack_timer_ops->session->us);

}

/**
 * when times out, the leaving user check 
 * all user's consistency before leaving
 */
void cb_leave(void *arg) {
  np1secSession* session = (static_cast<np1secSession*>(arg));

  session->check_leave_transcript_consistency();
  session->commit_suicide();

}

/**
 * rejoining a room in case joining times out. The hope is that room
 * member kicks the non-responsive user out of the room meanwhile
 */
void cb_rejoin(void *arg) {
  np1secSession* session = (static_cast<np1secSession*>(arg));

  //just kill myself and ask the room to rejoin
  session->commit_suicide();

  auto session_room = session->us->chatrooms.find(session->room_name);
  logger.assert_or_die(session_room != session->us->chatrooms.end(), "the room which the ssession belongs you has disappeared", __FUNCTION__, session->myself.nickname);

  logger.debug("joining session timed out, trying to rejoin", __FUNCTION__, session->myself.nickname);
  
  session_room->second.try_rejoin();

  session->rejoin_timer = nullptr;
  
}

/**
   Constructor being called by current participant receiving join request
   That's why (in room) participants are are already authenticated
   
     - in new session constructor these will happen
       - computes session_id
       - compute kc = kc_{sender, joiner}
       - compute z_sender (self)
       - set new session status to REPLIED_TO_NEW_JOIN
       - send 

  Or
  Leave Constructor being called by current participant receiving leave request
   
     - in new session constructor these will happen
       - drop leaver
       - computes session_id
       - compute z_sender (self)
       - set new session status to RE_SHARED

*/
/**
   Constructor being called by operator+ and operator- to breed 
   new (unestablished) session
   
     - in new session constructor these will happen
       - computes session_id
       - compute z_sender (self)
       - set new session status to RE_SHARED

*/
np1secSession::np1secSession(np1secSessionConceiverCondition conceiver,
                             np1secUserState* us,
                             std::string room_name,
                             Cryptic* current_ephemeral_crypto,
                             const ParticipantMap& current_participants,
                             const ParticipantMap& parent_plist,
                             np1secMessage* conceiving_message
                             )
  : us(us),
    room_name(room_name),
    myself(*us->myself),
    cryptic(*current_ephemeral_crypto),
    participants(current_participants),
    parental_participants(parent_plist)
    //conceiving_message(&(*conceiving_message)) //forcing copying, we need a fresh copy
{
  engrave_state_machine_graph();

  logger.info("constructing new session for room " + room_name + " with " + std::to_string(participants.size()) + " participants", __FUNCTION__, myself.nickname);

  //Joiner is the only one who can't compute session id at creation so we
  //need give them a specail treatement
  if (conceiver == JOINER) {
    logger.assert_or_die(conceiving_message && conceiving_message->message_type == np1secMessage::PARTICIPANTS_INFO, "wrong message type is provided to the joiner " + myself.nickname + " to establish a session. Message type " + std::to_string(np1secMessage::PARTICIPANTS_INFO) + " was expected but type " + std::to_string(conceiving_message->message_type)+ " was provided.", __FUNCTION__, myself.nickname);
    my_state = JOIN_REQUESTED;

    populate_participants_and_peers(conceiving_message->get_session_view());
    
  } else {
    switch(conceiver) {
    case CREATOR:
      logger.assert_or_die(participants.size() == 1, "initiated a room by more than a one participants", __FUNCTION__, myself.nickname);
      break;
      
    case ACCEPTOR:
      {
        if (conceiving_message) {
          logger.assert_or_die( (conceiving_message->message_type == np1secMessage::JOIN_REQUEST || conceiving_message->message_type == np1secMessage::PARTICIPANTS_INFO), "Acceptor message should be of type " + logger.message_type_to_text[np1secMessage::JOIN_REQUEST] + " or " + logger.message_type_to_text[np1secMessage::PARTICIPANTS_INFO] + " but message type of " + std::to_string(conceiving_message->message_type)+ " was provided.", __FUNCTION__, myself.nickname);
          //raisons_detre.push_back(RaisonDEtre(RaisonDEtre::JOIN, UnauthenticatedParticipant(conceiving_message->joiner_info).participant_id));
        }                       
        break;
        
      }

    case STAYER: {
      // logger.assert_or_die(!(conceiving_message && conceiving_message->message_type == np1secMessage::IN_SESSION_MESSAGE && conceiving_message->message_sub_type == np1secMessage::LEAVE_MESSAGE),                 "wrong message type is provided to the stayer " + myself.nickname + " to establish a session. Leave messaage is expected.");
      // string leaver_id = conceiving_message->sender_nick;
      // raisons_detre.push_back(RaisonDEtre(RaisonDEtre::LEAVE, leaver->second.id));
      // participants.erase(leaver_id);
      break;
    }

    case PEER:
      raisons_detre.push_back(RaisonDEtre(RaisonDEtre::RESESSION));
      break;
      
    default:
      logger.abort("wrong conceiver type: " + std::to_string(conceiver), __FUNCTION__, myself.nickname);

    } //switch

    populate_peers_from_participants();
    my_state = RE_SHARED;
    
  } //end of else (i.e !=  JOINER)
  
  //common ritual after getting the participants filled up (or down) as requested
  if (conceiver == CREATOR) {
    send_view_auth_and_share();
    arm_rejoin_timer();
  }else if (conceiver == JOINER) {
    logger.assert_or_die(conceiving_message, "conceiving message missing to create new session", __FUNCTION__, myself.nickname);
    np1secMessage to_send  = *conceiving_message;

    verify_peers_signature(to_send); //check message authenticity before going forward
    joiner_send_auth_and_share();
    my_state = auth_and_reshare(to_send).first;
    arm_rejoin_timer();
  }
  else if (conceiver == ACCEPTOR) {
    std::string joiner_id;
    if (conceiving_message && conceiving_message->message_type == np1secMessage::JOIN_REQUEST) {
      joiner_id =  UnauthenticatedParticipant(conceiving_message->joiner_info).participant_id.nickname;
    } else if (!delta_plist().empty()) {
      logger.assert_or_die(delta_plist().size()<=1, "this is n+1sec, one addition at time", __FUNCTION__, myself.nickname);
      joiner_id = delta_plist().begin()->second.id.nickname;
    }

    if (conceiving_message && conceiving_message->message_type == np1secMessage::PARTICIPANTS_INFO) {
      confirm_auth_add_update_share_repo(*conceiving_message);
    }
    
    send_view_auth_and_share(joiner_id);
  }
  else if (conceiver == PEER || conceiver == STAYER) //just anything else
    send_new_share_message();
  else
    logger.abort("invalid session conceiver", __FUNCTION__, myself.nickname);

  logger.info("session constructed with FSM new state: " + logger.state_to_text[my_state], __FUNCTION__, myself.nickname);

}

/**
 * it should be invoked only once to compute the session id
 * if one need session id then they need a new session
 *
 * @return return true upon successful computation
 */
void np1secSession::compute_session_id()
{
  logger.assert_or_die(!session_id.get(), "session id is unchangable"); //if session id isn't set we have to set it
  session_id.compute(participants);

}

/**
 *  setup session view based on session view message,
 *  note the session view is set once and for all change in 
 *  session view always need new session object.
 */
void np1secSession::setup_session_view(np1secMessage session_view_message) {

  populate_participants_and_peers(session_view_message.get_session_view());
  compute_session_id();

  if (session_id.get() == nullptr)
    throw np1secMessageFormatException();

}

void np1secSession::compute_session_confirmation()
{
  std::string to_be_hashed = Cryptic::hash_to_string_buff(session_key);
  to_be_hashed += myself.nickname;

  Cryptic::hash(to_be_hashed, session_confirmation);
  
}

void np1secSession::account_for_session_and_key_consistency()
{
  std::string to_be_hashed = Cryptic::hash_to_string_buff(session_key);
  to_be_hashed += session_id.get_as_stringbuff();

  HashBlock key_sid_hash;
  Cryptic::hash(to_be_hashed, key_sid_hash);

  last_received_message_id = 0; //key confirmation is the first message
  add_message_to_transcript(Cryptic::hash_to_string_buff(key_sid_hash),
                            last_received_message_id);

}

bool np1secSession::validate_session_confirmation(np1secMessage confirmation_message)
{
  HashBlock expected_hash;

  //set the future ephemeral key for the user
  memcpy(participants[confirmation_message.sender_nick].future_raw_ephemeral_key, confirmation_message.next_session_ephemeral_key.data(), c_ephemeral_key_length);

  std::string to_be_hashed = Cryptic::hash_to_string_buff(session_key);
  to_be_hashed += confirmation_message.sender_nick;

  Cryptic::hash(to_be_hashed, expected_hash);

  return !(Cryptic::compare_hash(expected_hash, reinterpret_cast<const uint8_t*>(confirmation_message.session_key_confirmation.c_str())));

}

/**
 * compute the right secret share
 * @param side  either c_my_right = 1 or c_my_left = 1
 */
std::string np1secSession::secret_share_on(int32_t side)
{
  HashBlock hb;
  
  assert(side == c_my_left || side == c_my_right);
  uint32_t positive_side = side + ((side < 0) ? peers.size() : 0);
  unsigned int my_neighbour = (my_index + positive_side) % peers.size();

  //we can't compute the secret if we don't know the neighbour ephemeral key
  assert(participants[peers[my_neighbour]].ephemeral_key);
  participants[peers[my_neighbour]].compute_p2p_private(us->long_term_key_pair.get_key_pair().first, &cryptic);

  Cryptic::hash(Cryptic::hash_to_string_buff(participants[peers[my_neighbour]].p2p_key) + session_id.get_as_stringbuff(), hb, true);
  
  return Cryptic::hash_to_string_buff(hb);

}

void np1secSession::group_enc() {
  HashBlock hbr, hbl;
  HashStdBlock sr = secret_share_on(c_my_right);
  HashStdBlock sl = secret_share_on(c_my_left);
  memcpy(hbr, Cryptic::strbuff_to_hash(sr), sizeof(HashBlock));
  memcpy(hbl, Cryptic::strbuff_to_hash(sl), sizeof(HashBlock));

  for (unsigned i=0; i < sizeof(HashBlock); i++) {
    hbr[i] ^= hbl[i];
  }

  participants[myself.nickname].set_key_share(hbr);
  
}

void np1secSession::group_dec() {

  std::vector<std::string> all_r(peers.size());

  HashBlock hbr;
  HashStdBlock sr = secret_share_on(c_my_right);
  memcpy(hbr, Cryptic::strbuff_to_hash(sr), sizeof(HashBlock));
  all_r[my_index] = Cryptic::hash_to_string_buff(hbr);

  for (uint32_t counter = 0; counter < peers.size(); counter++) {
    //memcpy(all_r[my_right], last_hbr, sizeof(HashBlock));
    size_t current_peer = (my_index + counter) % peers.size();
    size_t peer_on_the_right = (current_peer + 1) % peers.size();
    all_r[current_peer] = Cryptic::hash_to_string_buff(hbr);
    for (unsigned i=0; i < sizeof(HashBlock); i++) {
        hbr[i] ^= participants[peers[peer_on_the_right]].cur_keyshare[i];
   }
  } 
  //assert(hbr[0]==reinterpret_cast<const uint8_t&>(all_r[my_index][0]));
  
  std::string to_hash;
  for (std::vector<std::string>::iterator it = all_r.begin(); it != all_r.end(); ++it) {
    to_hash += (*it).c_str();
  }

  to_hash += session_id.get_as_stringbuff();
  Cryptic::hash(to_hash.c_str(), to_hash.size(), session_key, true);
  cryptic.set_session_key(session_key);
  
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
  for(std::vector<bool>::iterator it = confirmed_peers.begin(); it != confirmed_peers.end(); it++)
    if (!(*it))
      return false;

  return true;
  
}

bool np1secSession::nobody_confirmed()
{
  for(std::vector<bool>::iterator it = confirmed_peers.begin(); it != confirmed_peers.end(); it++)
    if ((*it))
      return false;

  return true;
  
}

/**
 *   Joiner call this after receiving the participant info to
 *    authenticate to everybody in the room
 */
void np1secSession::joiner_send_auth_and_share() {
  group_enc(); //compute my share for group key

  HashBlock cur_auth_token;
  std::string auth_batch;

  for(uint32_t i = 0; i < peers.size(); i++) {
    if (!participants[peers[i]].authed_to) {
      participants[peers[i]].authenticate_to(cur_auth_token, us->long_term_key_pair.get_key_pair().first, &cryptic);
      auth_batch.append(reinterpret_cast<char*>(&i), sizeof(uint32_t));
      auth_batch.append(reinterpret_cast<char*>(cur_auth_token), sizeof(HashBlock));
    }
  }

  np1secMessage outbound(&cryptic);

  outbound.create_joiner_auth_msg(session_id,
                                auth_batch,
                                std::string(reinterpret_cast<char*>(participants[myself.nickname].cur_keyshare), sizeof(HashBlock)));
  outbound.send(room_name, us);

}

/**
 *  Current participant sends this to the room
 *  to re share?  (when someone leave or in
 *  session forward secrecy)
 *  TODO: when do actually we need to call this
 *  When a partcipant leave
 */
void np1secSession::send_new_share_message() {
  logger.assert_or_die(session_id.get(), "can't send share message witouh session id");
  group_enc(); //compute my share for group key

  np1secMessage outboundmessage(&cryptic);

  outboundmessage.create_group_share_msg(session_id,
                                         std::string(reinterpret_cast<char*>(participants[myself.nickname].cur_keyshare), sizeof(HashBlock)));

  outboundmessage.send(room_name, us);

}

/**
   Preparinig PARTICIPANT_INFO Message

    current user calls this to send participant info to joiner
    and others
i    sid, ((U_1,y_i)...(U_{n+1},y_{i+1}), kc, z_joiner
*/
void np1secSession::send_view_auth_and_share(std::string joiner_id) {
  logger.assert_or_die(session_id.get(), "can not share view  when session id is missing");
  group_enc(); //compute my share for group key

  HashBlock cur_auth_token;
  if (!joiner_id.empty()) {
    if (participants.find(joiner_id) == participants.end()) {
      logger.error("can't authenticate to non-member joining participant " + joiner_id, __FUNCTION__, myself.nickname);
      throw np1secInvalidParticipantException();
    }

    participants[joiner_id].authenticate_to(cur_auth_token, us->long_term_key_pair.get_key_pair().first, &cryptic);
  }

  UnauthenticatedParticipantList session_view_list = session_view();
  np1secMessage outboundmessage(&cryptic);

  try {
    outboundmessage.create_participant_info_msg(session_id,
                                                session_view_list,
                                                std::string(reinterpret_cast<char*>(cur_auth_token), sizeof(HashBlock)),
                                                std::string(reinterpret_cast<char*>(participants[myself.nickname].cur_keyshare), sizeof(HashBlock)));

  } catch(np1secCryptoException()) {
    logger.error("unable to create participant info message due to cryptographic failure");
    throw;
  }
  
  logger.debug("sending participant info message");
  outboundmessage.send(room_name, us);

}

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
  logger.info("handling state: " + logger.state_to_text[my_state] + " message_type:" + logger.message_type_to_text[received_message.message_type], __FUNCTION__, myself.nickname);
  if (!this->np1secFSMGraphTransitionMatrix[my_state][received_message.message_type]) {
    logger.debug("lose state transitor, don't know where to go on FSM. ignoring message",  __FUNCTION__, myself.nickname);
  
  } else {
    //JOIN_REQUEST has no singnature
    //IN_SESSION is encrypted
    //Note that the first PARTICIPANT_INFO of the joiner doesn't make it here 
    if ((received_message.message_type != np1secMessage::JOIN_REQUEST) &&
        (received_message.message_type != np1secMessage::IN_SESSION_MESSAGE))
      verify_peers_signature(received_message);
    StateAndAction result  = (this->*np1secFSMGraphTransitionMatrix[my_state][received_message.message_type])(received_message);
    my_state = result.first;
    logger.info("FSM new state: " + logger.state_to_text[my_state], __FUNCTION__, myself.nickname);
    return result.second;

  } 
  
  return RoomAction(RoomAction::NO_ACTION);

}

//***** Joiner state transitors ****

/**
   For join user calls this when receive message has type of PARTICIPANTS_INFO
   
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
  if (participants.find(received_message.sender_nick) == participants.end())
    throw np1secInvalidParticipantException();
  
  participants[received_message.sender_nick].be_authenticated(myself.id_to_stringbuffer(), reinterpret_cast<const uint8_t*>(received_message.key_confirmation.c_str()), us->long_term_key_pair.get_key_pair().first, &cryptic);
  
  //keep participant's z_share if they passes authentication
  participants[received_message.sender_nick].set_key_share(reinterpret_cast<const uint8_t*>(received_message.z_sender.c_str()));

  return send_session_confirmation_if_everybody_is_contributed();

  //TODO: check the ramification of lies by other participants about honest
  //participant ephemeral key. Normally nothing should happen as we recompute
  //the session id and so the session will never get messages from honest
  //participants and so will never be authed.
  //return StateAndAction(my_state, RoomAction(RoomAction::NO_ACTION));

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
  //This function is never called because
  //if sid is the same mark the participant as confirmed
  //receiving mismatch sid basically means rejoin
  if (Cryptic::compare_hash(received_message.session_id.get(), session_id.get())) {
    if (validate_session_confirmation(received_message))
      confirmed_peers[participants[received_message.sender_nick].index] = true;
    else {
      logger.warn(received_message.sender_nick + "failed to provid a valid session confirmation. confirmation ignored.", __FUNCTION__, myself.nickname);
      //we just ignore the message instead I think
      //I can throw something too.
      return StateAndAction(my_state, RoomAction(RoomAction::NO_ACTION));
    }

    if (everybody_confirmed()) {
      //flush the raison d'etre because we have fullfield it
      //raison_detre.clear();
      return StateAndAction(IN_SESSION, RoomAction(RoomAction::NO_ACTION));
    }
    else {
      return StateAndAction(my_state, RoomAction(RoomAction::NO_ACTION));
    }

  } else { //It is not ours, if we haven't received any confirmation then
    //we should die
    if (nobody_confirmed()) {
      return StateAndAction(DEAD, RoomAction(RoomAction::NO_ACTION));
    } else {
      return StateAndAction(my_state, RoomAction(RoomAction::NO_ACTION));
    }
  }
    
  
  
        
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
np1secSession::StateAndAction np1secSession::init_a_session_with_new_user(np1secMessage received_message)
{

  RoomAction new_session_action;
  
  logger.assert_or_die(received_message.message_type == np1secMessage::JOIN_REQUEST, "wrong message type is provided to the accetpor " + myself.nickname + " to establish a session. Message type " + std::to_string(np1secMessage::JOIN_REQUEST) + " was expected but type " + std::to_string(received_message.message_type) + " was provided.");

  UnauthenticatedParticipant  joiner(received_message.joiner_info);
  //each id can only join once but it might be zombied out so we need
  //account for that
  //inform everybody about your transcript chain
  send("", np1secMessage::JUST_ACK);

  ParticipantMap live_participants = future_participants();
  if (live_participants.find(joiner.participant_id.nickname) == live_participants.end()) {
    logger.info("creating a session with new participant " + joiner.participant_id.nickname);
    live_participants.insert(std::pair<std::string,Participant> (joiner.participant_id.nickname, Participant(joiner)));

    np1secSession* new_child_session = new np1secSession(ACCEPTOR, us, room_name, &future_cryptic, live_participants, future_participants(), &received_message);

    //if it fails it throw exception catched by the room 
    new_session_action.action_type = RoomAction::NEW_SESSION;
    new_session_action.bred_session = new_child_session;

    //This broadcast not happens in session constructor because sometime we want just to make
    //a session object and not tell the whole world about it.
  } else {
    logger.warn(joiner.participant_id.nickname + " can't join the room twice");
    throw np1secDoubleJoinException();
    
  }

  //TODO: this is incomplete, you need to report your session 
  //to the room. more logically the room just need to request the
  //creation of the room. so just return the list of participants
  //to the room and ask the room to construct it
    
  //our state doesn't need to change
  return StateAndAction(my_state, new_session_action);

}

//*****Current participant state transitors*****
/**
     For the current user, calls it when receive PARTICIPANT_INFO which
     doesn't exists in its universe, this only happens when they are the 
     joining participant in previous itteration
     
     sid, ((U_1,y_i)...(U_{n+1},y_{i+1}), (kc_{sender, joiner}), z_sender

     - start a new new participant list which does
       checks if itself is part of the list.

     - it verifies the future keys of current session, other wise
       reject the session. anybody not on current session list
       mark as unauthenticated.
     

 */
RoomAction np1secSession::init_a_session_with_plist(np1secMessage received_message)
{

  RoomAction new_session_action;
  
  logger.assert_or_die(received_message.message_type == np1secMessage::PARTICIPANTS_INFO, "wrong message type is provided to the accetpor " + myself.nickname + " to establish a session. Message type " + logger.message_type_to_text[np1secMessage::PARTICIPANTS_INFO] + " was expected but type " + logger.message_type_to_text[np1secMessage::PARTICIPANTS_INFO] + " was provided.");

  //check the signature
  if (participants.find(received_message.sender_nick) == participants.end()) {
    logger.warn("sender not part of participant");
    throw np1secInvalidParticipantException();
  }    

  np1secPublicKey temp_future_pub_key = Cryptic::reconstruct_public_key_sexp(Cryptic::hash_to_string_buff(participants[received_message.sender_nick].future_raw_ephemeral_key));
                                                                             
  if (!received_message.verify_message(temp_future_pub_key))
    {
      Cryptic::release_crypto_resource(temp_future_pub_key);
      logger.warn("failed to verify signature of PARTICIPANT_INFO message.");
      throw np1secAuthenticationException();
    }
  
  Cryptic::release_crypto_resource(temp_future_pub_key);

  ParticipantMap live_participants = participants_list_to_map(received_message.get_session_view());
  
  if (live_participants.find(myself.nickname) == live_participants.end()) {
    logger.warn("rejecting participant info message which myself am not part of");
    throw np1secInvalidRoomException();
  }

  //only let those which match the same public key as stored in our future list
  //to be authenticated
  for(auto& cur_participant : live_participants) {
    if (participants.find(cur_participant.second.id.nickname) != participants.end()) {
      cur_participant.second.authenticated = !Cryptic::compare_hash(participants[cur_participant.second.id.nickname].future_raw_ephemeral_key, cur_participant.second.raw_ephemeral_key);
    } else {
      cur_participant.second.authenticated = false;
    }
  }

  np1secSession* new_child_session = new np1secSession(ACCEPTOR, us, room_name, &future_cryptic, live_participants, future_participants(), &received_message);

  //if it fails it throw exception catched by the room 
  new_session_action.action_type = RoomAction::NEW_SESSION;
  new_session_action.bred_session = new_child_session;

  //our state doesn't need to change
  return new_session_action;
  
}

/**
 * for immature leave when we don't have leave intention 
 */
RoomAction np1secSession::shrink(std::string leaving_nick)
{
  //we are basically running the intention to leave message
  //without broadcasting it (because it is not us who intend to do so)
  //make a fake intention to leave message but don't send ack
  RoomAction new_session_action;

  auto leaver = participants.find(leaving_nick);
  if (leaver == participants.end()) {
    logger.warn("participant " + leaving_nick + " is not part of the active session of the room " + room_name + " from which they are trying to leave, already parted?");
  } else if (zombies.find(leaving_nick) != zombies.end()) {//we haven already shrunk and made a session 
    logger.debug("shrunk session for leaving user " + leaving_nick + " has already been generated. nothing to do", __FUNCTION__, myself.nickname);
  } else { //shrink now
    //if everything is ok add the leaver to the zombie list and make a
    //session without zombies
    zombies.insert(*leaver);

    //raison_detre.insert(RaisonDEtre(LEAVE, leaver->id));
    
    np1secSession* new_child_session = new np1secSession(PEER, us, room_name, &future_cryptic, future_participants());
  
    new_session_action.action_type = RoomAction::NEW_PRIORITY_SESSION;
    new_session_action.bred_session = new_child_session;
    
    //we are as we have farewelled
    //my_state = FAREWELLED; //We shouldn't change here and it is not clear why we
    //we need this stage, not to accept join? why? join will fail by non confirmation
    //of the leavers 
    return new_session_action;
  }

  return c_no_room_action;

}

/**
 * Move the session from DEAD to 
 */
// RoomAction np1secSession::revive_session()
// {
//   StateAndAction state_and_action = send_session_confirmation_if_everybody_is_contributed();
//   my_state = state_and_action.first;

//   return state_and_action.second;
  
// }

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
    if (received_message.authentication_table.find(my_index) != received_message.authentication_table.end())
      participants[received_message.sender_nick].be_authenticated(myself.id_to_stringbuffer(), Cryptic::strbuff_to_hash(received_message.authentication_table[my_index]), us->long_term_key_pair.get_key_pair().first, &cryptic);
  }

  participants[received_message.sender_nick].set_key_share(Cryptic::strbuff_to_hash(received_message.z_sender));

  return send_session_confirmation_if_everybody_is_contributed();
  //else { //assuming the message is PARTICIPANT_INFO from other in
  //session people
    
  //}
  
}
/**
 * sends session confirmation if everybody is contributed and authenticated
 * returns DEAD state if fails to decrypt the group key.
 *         GROUP_KEY_GENERATED otherwise
 *          the current state if not everybody authenticated
 */
np1secSession::StateAndAction np1secSession::send_session_confirmation_if_everybody_is_contributed()
{

  if (everybody_authenticated_and_contributed()) {
    group_dec();
    //first compute the confirmation
    compute_session_confirmation();
    //we need our future ephemeral key to attach to the message
    future_cryptic.init();
    //now send the confirmation messagbe
    np1secMessage outboundmessage(&cryptic);

    outboundmessage.create_session_confirmation_msg(session_id,
                                                    Cryptic::hash_to_string_buff(session_confirmation), Cryptic::public_key_to_stringbuff(future_cryptic.get_ephemeral_pub_key()));
      
    outboundmessage.send(room_name, us);

    RoomAction re_limbo_action;
    
    re_limbo_action.action_type = RoomAction::PRESUME_HEIR;
    re_limbo_action.bred_session = this;

    return StateAndAction(GROUP_KEY_GENERATED, re_limbo_action);
    //if we are joing we don't need to relimbo and the room will
    //ignore the action, 

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
  if (!validate_session_confirmation(received_message)) {
    logger.warn(received_message.sender_nick + "failed to provid a valid session confirmation. confirmation ignored.", __FUNCTION__, myself.nickname);
    return StateAndAction(my_state, c_no_room_action);
  }
  
  confirmed_peers[participants[received_message.sender_nick].index] = true;
  
  if (everybody_confirmed()) {
    //kill the rejoin timer
    if (rejoin_timer) us->ops->axe_timer(rejoin_timer, us->ops->bare_sender_data);
    rejoin_timer = nullptr;

    //activate(); it is matter of changing to IN_SESSION
    //we also need to initiate the transcript chain with 
    account_for_session_and_key_consistency();

    //flush the raison d'etre because we have fullfield it
    ///raison_detre.clear();
    //start the session life timer
    session_life_timer = us->ops->set_timer(cb_re_session, this,
                                            us->ops->c_session_life_span, us->ops->bare_sender_data);

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
  //send a farewell message
  send("", np1secMessage::JUST_ACK); //no point to send FS loads as the session is
  //ending anyway
  //return init_a_session_with_new_plist(received_message);
  logger.assert_or_die(received_message.message_type == np1secMessage::IN_SESSION_MESSAGE && received_message.message_sub_type == np1secMessage::LEAVE_MESSAGE,                 "wrong message type is provided to the stayer " + myself.nickname + " to establish a session. Leave messaage is expected.", __FUNCTION__, myself.nickname);

  logger.info(received_message.sender_nick + " waves goodbye.", __FUNCTION__, myself.nickname);

  return StateAndAction(my_state, shrink(received_message.sender_nick));
  //FAREWELL doesn't make sense. we act normally till a new
  //session get constructed
  //meanwhile if a new joiner trys to join we get the join but the join
  //will (hopefully) fails cause the leaver is leaving and ignoring
  //all join request. A new session will be establish and then new
  //participant info will be sent. In reallity all joiners need to
  //wait for all leavers to leave

}

/**
 * compute the id of a potential session when leaving_nick leaves the session
 */
SessionId np1secSession::shrank_session_id(std::string leaver_nick)
{
  auto leaver = participants.find(leaver_nick);
  if (leaver == participants.end()) {
    logger.error("participant " + leaver_nick + "is not in the session from which they are trying to leave", __FUNCTION__, myself.nickname);
    throw np1secInvalidDataException();
  }

  ParticipantMap temp_zombies = zombies;
  temp_zombies.insert(*leaver);
  ParticipantMap temp_plist = participants - temp_zombies;

  SessionId shrank_id(temp_plist);

  return shrank_id;

}

void np1secSession::leave() {
  //tell everybody I'm leaving and tell them about the closure
  //of my transcript consistency

  //if you are the only person in the session then
  //just leave
  //TODO:: is it good to call the ops directly?
  logger.debug("leaving the session", __FUNCTION__, myself.nickname);
  if (participants.size() == 1) {
    logger.debug("last person in the session, not waiting for farewell", __FUNCTION__, myself.nickname);

    logger.assert_or_die(my_index == 0 && peers.size() == 1, "peers is not sync with participants");
    peers.pop_back();
    us->ops->leave(room_name, peers, us->ops->bare_sender_data);
    commit_suicide();
  }

  //otherwise, inform others in the room about your leaving the room
  logger.debug("informing other, waiting for farewell", __FUNCTION__, myself.nickname);  
  leave_parent = last_received_message_id;
  send("", np1secMessage::LEAVE_MESSAGE);

  farewell_deadline_timer = us->ops->set_timer(
    cb_leave, this, us->ops->c_inactive_ergo_non_sum_interval, us->ops->bare_sender_data);
  my_state = LEAVE_REQUESTED;

}

/**
 * When we receive a message we set a timer so to check that
 * everybody else has received the same message
 */
void np1secSession::start_ack_timers(const np1secMessage& received_message) {
  for (ParticipantMap::iterator it = participants.begin();
       it != participants.end();
       ++it) {
    //we accumulate the timers, when we receive ack, we drop what we
    //have before 
    if ((received_message.sender_nick != (*it).second.id.nickname) &&
        (received_message.sender_nick != myself.nickname)) //not for the sender and not 
      //for myself
    {
      received_transcript_chain[received_message.message_id][(*it).second.index].ack_timer_ops.session = this;
      received_transcript_chain[received_message.message_id][(*it).second.index].ack_timer_ops.participant = &(it->second);
      received_transcript_chain[received_message.message_id][(*it).second.index].ack_timer_ops.message_id = received_message.message_id;
      received_transcript_chain[received_message.message_id][(*it).second.index].consistency_timer =
      us->ops->set_timer(cb_ack_not_received,
      &(received_transcript_chain[received_message.message_id][(*it).second.index].ack_timer_ops),
      us->ops->c_consistency_failure_interval, us->ops->bare_sender_data);
      
    }
  }
}

// void np1secSession::start_conditional_send_ack_timer() {
//   //if there is already an ack timer 
//   //then that will take care of acking 
//   //for us as well
  
// }

/**
 * When we receive a message we start a timer to make sure that we'll
 * send an ack if we haven't send any message
 */
void np1secSession::start_acking_timer() {
  if (!send_ack_timer) {
    logger.debug("arming send ack timer01");
    send_ack_timer = us->ops->set_timer(cb_send_ack, this, us->ops->c_ack_interval, us->ops->bare_sender_data);
  }
  // for (std::map<std::string, Participant>::iterator
  //      it = participants.begin();
  //      it != participants.end();
  //      ++it) {
  //   if ((*it).second.send_ack_timer) {
  //     us->ops->axe_timer((*it).second.send_ack_timer, us->ops->bare_sender_data);
  //     (*it).second.send_ack_timer = nullptr;
  //   }
  // }
}

void np1secSession::stop_acking_timer() {
  if (send_ack_timer) {
    logger.debug("disarming send ack timer01");
    us->ops->axe_timer(send_ack_timer, us->ops->bare_sender_data);
    send_ack_timer = nullptr;
  }
  // for (std::map<std::string, Participant>::iterator
  //      it = participants.begin();
  //      it != participants.end();
  //      ++it) {
  //   if ((*it).second.send_ack_timer) {
  //     us->ops->axe_timer((*it).second.send_ack_timer, us->ops->bare_sender_data);
  //     (*it).second.send_ack_timer = nullptr;
  //   }
  // }
}

void np1secSession::stop_timer_receive(std::string acknowledger_id, MessageId message_id) {

  for(MessageId i = participants[acknowledger_id].last_acked_message_id + 1; i <= message_id; i++) {
    if (received_transcript_chain[message_id][participants[acknowledger_id].index].consistency_timer)
      us->ops->axe_timer(received_transcript_chain[message_id][participants[acknowledger_id].index].consistency_timer,
                         us->ops->bare_sender_data);
    received_transcript_chain[message_id][participants[acknowledger_id].index].consistency_timer = nullptr;
  }

  participants[acknowledger_id].last_acked_message_id = message_id;

}

/**
 * Inserts a block in the send transcript chain and start a 
 * timer to receive the ack for it
 */
void np1secSession::update_send_transcript_chain(MessageId own_message_id,
                                  std::string message) {
  HashBlock hb;
  Cryptic::hash(message, hb, true);
  sent_transcript_chain[own_message_id].transcript_hash = Cryptic::hash_to_string_buff(hb);
  sent_transcript_chain[own_message_id].ack_timer_ops = AckTimerOps(this, nullptr, own_message_id);
 
  sent_transcript_chain[own_message_id].consistency_timer = us->ops->set_timer(cb_ack_not_sent,
  &(sent_transcript_chain[own_message_id].ack_timer_ops), us->ops->c_send_receive_interval, us->ops->bare_sender_data);

}

/**
 * - kills the send ack timer for the message in case we are the sender
 * - Fill our own transcript chain for the message
 * - start all ack timer for others for this message
 * - Perform parent consistency check
 */
void np1secSession::perform_received_consisteny_tasks(np1secMessage received_message)
{
  //defuse the "I didn't get my own message timer 
  if (received_message.sender_nick == myself.nickname) {
    if (sent_transcript_chain[received_message.sender_message_id].consistency_timer) {//the timer might legitemately has been killed due to suicide
      us->ops->axe_timer(
                         sent_transcript_chain[received_message.sender_message_id].consistency_timer,
                         us->ops->bare_sender_data);
      sent_transcript_chain[received_message.sender_message_id].consistency_timer = nullptr;
    }
  }

  add_message_to_transcript(received_message.final_whole_message, received_message.message_id);

  //it needs to be called after add as it assumes it is already added
  start_ack_timers(received_message);

}

/**
 * - check the consistency of the parent message with our own.
 * - kill all ack receive timers of the sender for the parent backward
 */
void np1secSession::check_parent_message_consistency(np1secMessage received_message)
{
  received_transcript_chain[received_message.parent_id][participants[received_message.sender_nick].index].transcript_hash = received_message.transcript_chain_hash;

  if (received_transcript_chain[received_message.parent_id][my_index].transcript_hash != received_transcript_chain[received_message.parent_id][participants[received_message.sender_nick].index].transcript_hash)
    {
      std::string consistency_failure_message = received_message.sender_nick  + " transcript doesn't match ours as of " + std::to_string(received_message.parent_id);
      us->ops->display_message(room_name, "np1sec directive", consistency_failure_message, us);
      logger.error(consistency_failure_message, __FUNCTION__, myself.nickname);
    }

  stop_timer_receive(received_message.sender_nick, received_message.message_id);

}

/**
 * - check the consistency of all participants for the parent leave message
 */
bool np1secSession::check_leave_transcript_consistency()
{
  uint32_t no_of_peers_farewelled = 0;
  if (received_transcript_chain.find(leave_parent) != received_transcript_chain.end()) {
    for(uint32_t i = 0; i < peers.size(); i++) {
     
      //we need to check if we have already got the farewell from this peer
      if (!received_transcript_chain[leave_parent][i].transcript_hash.empty()) {
        no_of_peers_farewelled++;
        if (received_transcript_chain[leave_parent][i].transcript_hash != received_transcript_chain[leave_parent][my_index].transcript_hash) {
          std::string consistency_failure_message = peers[i]  + " transcript doesn't match ours";
          us->ops->display_message(room_name, "np1sec directive", consistency_failure_message, us);
          logger.error(consistency_failure_message, __FUNCTION__, myself.nickname);
        } //not equal
      } //not empty
    } //for
  } //we got it already
  
  return (no_of_peers_farewelled == peers.size());
  
}

void np1secSession::add_message_to_transcript(std::string message,
                                        MessageId message_id) {
  HashBlock hb;
  std::stringstream ss;
  std::string pointlessconversion;

  if (received_transcript_chain.size() > 0) {
    ss << received_transcript_chain.rbegin()->second[my_index].transcript_hash;
    ss >> pointlessconversion;
    pointlessconversion += c_np1sec_delim + message;

  } else {
    pointlessconversion = message;

  }

  Cryptic::hash(pointlessconversion, hb);

  if (received_transcript_chain.find(message_id) == received_transcript_chain.end()) {
    ConsistencyBlockVector chain_block(participants.size());
    received_transcript_chain.insert(std::pair<MessageId, ConsistencyBlockVector>(message_id, chain_block));
  }
  
  (received_transcript_chain[message_id])[my_index].transcript_hash = Cryptic::hash_to_string_buff(hb);
  received_transcript_chain[message_id][my_index].consistency_timer = nullptr;

}

void np1secSession::send(std::string message, np1secMessage::np1secMessageSubType message_type) {
  if (!(my_state >=  IN_SESSION) && my_state <=  LEAVE_REQUESTED) {
    logger.error("you can't send in session message to a session which is not established", __FUNCTION__, myself.nickname);
    throw np1secInvalidSessionStateException();
  }

  np1secMessage outbound(&cryptic);
  logger.info("own ctr before send: " + std::to_string(own_message_counter), __FUNCTION__, myself.nickname);

  outbound.create_in_session_msg(session_id, 
                                 my_index,
                                 own_message_counter+1,
                                 last_received_message_id,
                                 received_transcript_chain.rbegin()->second[my_index].transcript_hash,
                                 message_type,
                                 message
                                 //no in session forward secrecy for now
                           );

  // us->ops->send_bare(room_name, outbound);
  outbound.send(room_name, us);
  
  //if everything went well add the counter
  own_message_counter++;
  
  logger.info("own ctr after send: " + std::to_string(own_message_counter), __FUNCTION__, myself.nickname);

  update_send_transcript_chain(own_message_counter, outbound.compute_hash());
  // As we're sending a new message we are no longer required to ack
  // any received messages till we receive a new message
  stop_acking_timer();
  
}

np1secSession::StateAndAction np1secSession::receive(np1secMessage encrypted_message) {

  //we need to receive it again, as now we have the encryption key 
  np1secMessage received_message(encrypted_message.final_whole_message, &cryptic, participants.size());

  //check signature if not valid, just ignore the message
  //first we need to get the correct ephemeral key
  if (received_message.sender_index < peers.size()) {
    if (received_message.verify_message(participants[peers[received_message.sender_index]].ephemeral_key)) {
      //only messages with valid signature are concidered received
      //for any matters including consistency chcek
      last_received_message_id++;
      received_message.sender_nick = peers[received_message.sender_index]; //just to keep the message structure consistent, and for the use in new session (like session resulted from leave) otherwise in the session we should just use the index
      perform_received_consisteny_tasks(received_message);
      if (my_state == LEAVE_REQUESTED) {
        if (check_leave_transcript_consistency()) {//we are done we can leave
          //stop the farewell deadline timer
          if (farewell_deadline_timer) {
            us->ops->axe_timer(farewell_deadline_timer, us->ops->bare_sender_data);
            farewell_deadline_timer = nullptr;
          }

          peers.pop_back();
          us->ops->leave(room_name, peers, us->ops->bare_sender_data);
          commit_suicide();
          StateAndAction(DEAD, c_no_room_action);
          
        }
      }
      //if it is user message, display content
      else if ((received_message.message_sub_type == np1secMessage::USER_MESSAGE)) {
        us->ops->display_message(room_name, participants[peers[received_message.sender_index]].id.nickname, received_message.user_message, us->ops->bare_sender_data);

        start_acking_timer(); //if we don't send any message for a while we'll
        //ack all messages
      }
      else if ((received_message.message_sub_type == np1secMessage::LEAVE_MESSAGE) && (received_message.sender_nick != myself.nickname) && my_state != DEAD)  {
        return send_farewell_and_reshare(received_message);
      }
    
    } else 
      received_message.message_type = np1secMessage::INADMISSIBLE;

  } else
    received_message.message_type = np1secMessage::INADMISSIBLE;

  return StateAndAction(my_state, c_no_room_action);

}

/**
 * prepare a new list of participant for a new session
 * replacing future key to current key and drop zombies
 */
ParticipantMap np1secSession::future_participants() {
  ParticipantMap live_participants = participants - zombies;
  for(auto& cur_participant: live_participants)
    cur_participant.second.set_ephemeral_key(cur_participant.second.future_raw_ephemeral_key);

  return live_participants;

}

/**
 * returns participants - parental_participants
 * it shows what is the session suppose to add or
 * drop it is a replacement for raison_detre
 */
ParticipantMap np1secSession::delta_plist()
{
  return participants - parental_participants;
}

/**
 * change the state to DEAD. it is needed when we bread a new
 * session out of this session. 
 * it also axes all of the timers
 */
void np1secSession::commit_suicide() {
  //we try to send a last ack, if it fails no big deal

  disarm_all_timers();
  my_state = DEAD;

}

/**
 * stop all timers
 */
void np1secSession::disarm_all_timers() {
  if (farewell_deadline_timer) us->ops->axe_timer(farewell_deadline_timer, us->ops->bare_sender_data);
  if (send_ack_timer) us->ops->axe_timer(send_ack_timer, us->ops->bare_sender_data);

  if (rejoin_timer) us->ops->axe_timer(rejoin_timer, us->ops->bare_sender_data);

  if (session_life_timer) us->ops->axe_timer(session_life_timer, us->ops->bare_sender_data);

  for(auto& cur_block: received_transcript_chain)
    for(auto& cur_participant: cur_block.second)
      if(cur_participant.consistency_timer) {
        us->ops->axe_timer(cur_participant.consistency_timer, us->ops->bare_sender_data);
      }

  for(auto& cur_block: sent_transcript_chain)
    if (cur_block.second.consistency_timer) {
      us->ops->axe_timer(cur_block.second.consistency_timer, us->ops->bare_sender_data);
    }

  clear_all_timers();
}

/**
 * stop all timers
 */
void np1secSession::clear_all_timers() {

  farewell_deadline_timer = nullptr;
  send_ack_timer = nullptr;
  rejoin_timer = nullptr;
  session_life_timer = nullptr;

  for(auto& cur_block: received_transcript_chain)
    for(auto& cur_participant: cur_block.second)
        cur_participant.consistency_timer = nullptr;

  for(auto& cur_block: sent_transcript_chain)
      cur_block.second.consistency_timer = nullptr;

}

/**
 * tells if rejoin is active
 */
void np1secSession::arm_rejoin_timer() {
    logger.assert_or_die(!rejoin_timer, "no re-arming the rejoin timer!", __FUNCTION__, myself.nickname); //we shouldn't rearm rejoin timer
    logger.debug("arming rejoin timer, in case we can't join successfully",__FUNCTION__, myself.nickname);
      rejoin_timer = us->ops->set_timer(cb_rejoin, this, us->ops->c_unresponsive_ergo_non_sum_interval, us->ops->bare_sender_data);
      
}

np1secSession::~np1secSession() {
  //commit_suicide(); //just to kill all timers
  //we can't commit suicide because our copy constructor
  //copy the session and its destruction shouldn't
  //mean that the session as concept is destructed
}

} // namespace np1sec
