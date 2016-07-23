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

#include "session.h"
#include "exceptions.h"
#include "userstate.h"

namespace np1sec
{

void cb_re_session(void* arg)
{
    Session* session = (static_cast<Session*>(arg));
    logger.assert_or_die(session->my_state != Session::DEAD, "postmortem racheting?");

    logger.info("RESESSION: forward secrecy ratcheting", __FUNCTION__, session->myself.nickname);

    Session* new_child_session = new Session(Session::PEER, session->us, session->room, session->room_name,
                                                         &session->future_cryptic, session->future_participants());

    try {
        logger.assert_or_die(session->us->chatrooms.find(session->room_name) != session->us->chatrooms.end(),
                             "np1sec can not add session to room " + session->room_name +
                                 " which apparenly doesn't exists",
                             __FUNCTION__, session->myself.nickname);

        session->us->chatrooms[session->room_name]->insert_session(new_child_session);
    } catch (std::exception& e) {
        logger.error("Failed to resession to ensure forward secrecy", __FUNCTION__, session->myself.nickname);
    }

    session->session_life_timer = nullptr;
}

void cb_ack_not_received(void* arg)
{
    // Construct message for ack
    AckTimerOps* ack_timer_ops = static_cast<AckTimerOps*>(arg);

    if (ack_timer_ops->session->my_state == Session::DEAD)
        logger.debug("postmortem consistency chcek", __FUNCTION__, ack_timer_ops->session->myself.nickname);

    std::string ack_failure_message = ack_timer_ops->participant->id.nickname + " failed to ack";
    ack_timer_ops->session->us->ops->display_message(ack_timer_ops->session->room_name, "np1sec directive",
                                                     ack_failure_message, ack_timer_ops->session->us->ops->bare_sender_data);
    logger.warn(ack_failure_message + " in room " + ack_timer_ops->session->room_name, __FUNCTION__,
                ack_timer_ops->session->myself.nickname);

    // this is object (not pointer) in the message chain
    // it gets destroyed when the chain get destroyed
    // delete ack_timer_ops;
}

void cb_send_ack(void* arg)
{
    // Construct message with p.id
    Session* session = (static_cast<Session*>(arg));

    if (session->my_state == Session::DEAD)
        logger.debug("postmortem consistency chcek", __FUNCTION__, session->myself.nickname);

    session->send_ack_timer = nullptr;

    logger.debug("long time, no messege! acknowledging received messages", __FUNCTION__, session->myself.nickname);

    session->send("", InSessionMessage::JUST_ACK);
}

/**
 * The timer set upon of sending a message.
 * when this timer is timed out means that
 * we haven't received our own message
 */
void cb_ack_not_sent(void* arg)
{
    // Construct message with p.id
    AckTimerOps* ack_timer_ops = static_cast<AckTimerOps*>(arg);

    if (ack_timer_ops->session->my_state == Session::DEAD)
        logger.debug("postmortem consistency chcek", __FUNCTION__, ack_timer_ops->session->myself.nickname);

    std::string ack_failure_message = "we did not receive our own sent message";
    ack_timer_ops->session->us->ops->display_message(ack_timer_ops->session->room_name, "np1sec directive",
                                                     ack_failure_message, ack_timer_ops->session->us->ops->bare_sender_data);
}

/**
 * when times out, the leaving user check
 * all user's consistency before leaving
 */
void cb_leave(void* arg)
{
    Session* session = (static_cast<Session*>(arg));

    session->check_leave_transcript_consistency();
    session->commit_suicide();
}

/**
 * rejoining a room in case joining times out. The hope is that room
 * member kicks the non-responsive user out of the room meanwhile
 */
void cb_rejoin(void* arg)
{
    Session* session = (static_cast<Session*>(arg));

    // just kill myself and ask the room to rejoin
    session->commit_suicide();

    auto session_room = session->us->chatrooms.find(session->room_name);
    logger.assert_or_die(session_room != session->us->chatrooms.end(),
                         "the room which the ssession belongs you has disappeared", __FUNCTION__,
                         session->myself.nickname);

    logger.debug("joining session timed out, trying to rejoin", __FUNCTION__, session->myself.nickname);

    session_room->second->try_rejoin();

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
Session::Session(SessionConceiverCondition conceiver, UserState* us, Room *room, std::string room_name,
                             Cryptic* current_ephemeral_crypto, const ParticipantMap& current_participants,
                             const ParticipantMap& parent_plist)
    : us(us), room(room), room_name(room_name), myself(*us->myself), cryptic(*current_ephemeral_crypto),
      participants(current_participants), parental_participants(parent_plist)
{
    logger.info("constructing new session for room " + room_name + " with " + std::to_string(participants.size()) +
                    " participants",
                __FUNCTION__, myself.nickname);

    populate_peers_from_participants();

    if (conceiver == JOINER) {
        my_state = JOIN_REQUESTED;

        joiner_send_auth_and_share();
        arm_rejoin_timer();
    } else if (conceiver == CREATOR) {
        my_state = RE_SHARED;


        send_view_auth_and_share();
        arm_rejoin_timer();
    } else if (conceiver == ACCEPTOR) {
        my_state = RE_SHARED;


        std::string joiner_id;
        if (!delta_plist().empty()) {
            logger.assert_or_die(delta_plist().size() <= 1, "this is n+1sec, one addition at time", __FUNCTION__,
                                 myself.nickname);
            joiner_id = delta_plist().begin()->second.id.nickname;
        }
        send_view_auth_and_share(joiner_id);
    } else if (conceiver == PEER) {
        my_state = RE_SHARED;


        send_new_share_message();
    } else {
        logger.abort("wrong conceiver type: " + std::to_string(conceiver), __FUNCTION__, myself.nickname);
    }

    logger.info("session constructed with FSM new state: " + logger.state_to_text[my_state], __FUNCTION__,
                myself.nickname);
}

/**
 * it should be invoked only once to compute the session id
 * if one need session id then they need a new session
 *
 * @return return true upon successful computation
 */
void Session::compute_session_id()
{
    logger.assert_or_die(!session_id.get(), "session id is unchangable"); // if session id isn't set we have to set it
    session_id.compute(participants);
}

Hash Session::session_confirmation(std::string participant_nickname)
{
    std::string hash_buffer;
    hash_buffer += hash_to_string_buff(session_key);
    hash_buffer += participant_nickname;
    Hash result;
    hash(hash_buffer, result.buffer);
    return result;
}

void Session::account_for_session_and_key_consistency()
{
    std::string to_be_hashed = hash_to_string_buff(session_key);
    to_be_hashed += session_id.get_as_stringbuff();

    HashBlock key_sid_hash;
    hash(to_be_hashed, key_sid_hash);

    last_received_message_id = 0; // key confirmation is the first message
    add_message_to_transcript(hash_to_string_buff(key_sid_hash), last_received_message_id);
}

/**
 * compute the right secret share
 * @param side  either c_my_right = 1 or c_my_left = 1
 */
void Session::secret_share_on(int32_t side, HashBlock hb)
{
    assert(side == c_my_left || side == c_my_right);
    uint32_t positive_side = side + ((side < 0) ? peers.size() : 0);
    unsigned int my_neighbour = (my_index + positive_side) % peers.size();

    // we can't compute the secret if we don't know the neighbour ephemeral key
    assert(participants[peers[my_neighbour]].ephemeral_key);
    participants[peers[my_neighbour]].compute_p2p_private(us->long_term_key_pair.get_key_pair().first, &cryptic);

    // compute p2p_key + session_id.session_id_raw
    size_t num_bytes = c_hash_length + c_hash_length;
    uint8_t bytes[num_bytes];
    memcpy(bytes, participants[peers[my_neighbour]].p2p_key, c_hash_length);
    memcpy(bytes + (sizeof(uint8_t) * c_hash_length), session_id.get(), c_hash_length);
    hash((void*)bytes, num_bytes, hb, true);
    secure_wipe(bytes, c_hash_length + c_hash_length);
}

void Session::group_enc()
{
    HashBlock hbr, hbl;
    secret_share_on(c_my_right, hbr);
    secret_share_on(c_my_left, hbl);

    for (unsigned i = 0; i < sizeof(HashBlock); i++) {
        hbr[i] ^= hbl[i];
    }

    participants[myself.nickname].set_key_share(hbr);
    secure_wipe(hbr, c_hash_length);
    secure_wipe(hbl, c_hash_length);
}

void Session::group_dec()
{
    HashBlock hbr;
    HashBlock all_r[peers.size() + 1];
   
    secret_share_on(c_my_right, hbr);
    memcpy(all_r[my_index], hbr, c_hash_length);

    for (uint32_t counter = 0; counter < peers.size(); counter++) {
        // memcpy(all_r[my_right], last_hbr, sizeof(HashBlock));
        size_t current_peer = (my_index + counter) % peers.size();
        size_t peer_on_the_right = (current_peer + 1) % peers.size();
        memcpy(all_r[current_peer], hbr, c_hash_length);
        for (unsigned i = 0; i < sizeof(HashBlock); i++) {
            hbr[i] ^= participants[peers[peer_on_the_right]].cur_keyshare[i];
        }
    }
    
    memcpy(all_r[peers.size()], session_id.get(), c_hash_length);
    hash(all_r, peers.size() + 1, session_key, true);
    cryptic.set_session_key(session_key);
    
    secure_wipe(hbr, c_hash_length);
    for (size_t i = 0; i < peers.size() + 1; i++) {
        secure_wipe(all_r[i], c_hash_length);
    }
}

bool Session::everybody_authenticated_and_contributed()
{
    for (ParticipantMap::iterator it = participants.begin(); it != participants.end(); it++)
        if (!it->second.authenticated || !it->second.key_share_contributed)
            return false;

    return true;
}

bool Session::everybody_confirmed()
{
    for (std::vector<bool>::iterator it = confirmed_peers.begin(); it != confirmed_peers.end(); it++)
        if (!(*it))
            return false;

    return true;
}

bool Session::nobody_confirmed()
{
    for (std::vector<bool>::iterator it = confirmed_peers.begin(); it != confirmed_peers.end(); it++)
        if ((*it))
            return false;

    return true;
}

/**
 *   Joiner call this after receiving the participant info to
 *   authenticate to everybody in the room
 */
void Session::joiner_send_auth_and_share()
{
    group_enc(); // compute my share for group key

    JoinerAuthMessage message;
    for (uint32_t i = 0; i < peers.size(); i++) {
        if (!participants[peers[i]].authed_to) {
            Hash key_confirmation;
            participants[peers[i]].authenticate_to(key_confirmation.buffer,
                us->long_term_key_pair.get_key_pair().first, &cryptic);
            message.key_confirmations[i] = key_confirmation;
        }
    }
    memcpy(message.sender_share.buffer, participants[myself.nickname].cur_keyshare, sizeof(message.sender_share.buffer));
    send(message.encode());
}

/**
 *  Current participant sends this to the room
 *  to re share?  (when someone leave or in
 *  session forward secrecy)
 *  TODO: when do actually we need to call this
 *  When a partcipant leave
 */
void Session::send_new_share_message()
{
    logger.assert_or_die(session_id.get(), "can't send share message witouh session id");
    group_enc(); // compute my share for group key

    GroupShareMessage message;
    memcpy(message.sender_share.buffer, participants[myself.nickname].cur_keyshare, sizeof(message.sender_share.buffer));
    send(message.encode());
}

/**
   Preparinig PARTICIPANT_INFO Message

    current user calls this to send participant info to joiner
    and others
i    sid, ((U_1,y_i)...(U_{n+1},y_{i+1}), kc, z_joiner
*/
void Session::send_view_auth_and_share(std::string joiner_id)
{
    logger.assert_or_die(session_id.get(), "can not share view  when session id is missing");
    group_enc(); // compute my share for group key

    Token cur_auth_token;
    memset(cur_auth_token, 0, sizeof(cur_auth_token));
    if (!joiner_id.empty()) {
        if (participants.find(joiner_id) == participants.end()) {
            logger.error("can't authenticate to non-member joining participant " + joiner_id, __FUNCTION__,
                         myself.nickname);
            throw InvalidParticipantException();
        }

        participants[joiner_id].authenticate_to(cur_auth_token, us->long_term_key_pair.get_key_pair().first, &cryptic);
    }

    ParticipantsInfoMessage message;
    for (size_t i = 0; i < peers.size(); i++) {
        ParticipantsInfoMessage::ParticipantInfo participant;
        participant.nickname = participants[peers[i]].id.nickname;
        memcpy(participant.long_term_public_key.buffer, participants[peers[i]].id.fingerprint, sizeof(participant.long_term_public_key.buffer));
        memcpy(participant.ephemeral_public_key.buffer, hash_to_string_buff(participants[peers[i]].raw_ephemeral_key).data(), sizeof(participant.ephemeral_public_key.buffer));
        participant.authenticated = participants[peers[i]].authenticated;
        message.participants.push_back(participant);
    }
    memcpy(message.key_confirmation.buffer, cur_auth_token, sizeof(message.key_confirmation.buffer));
    memcpy(message.sender_share.buffer, participants[myself.nickname].cur_keyshare, sizeof(message.sender_share.buffer));
    send(message.encode());

    logger.debug("sending participant info message");
}

/**
 * Receives the pre-processed message and based on the state
 * of the session decides what is the appropriate action
 *
 * @param receive_message pre-processed received message handed in by receive function
 *
 * @return true if state has been change
 */
RoomAction Session::state_handler(const std::string& sender, SessionMessage message)
{
    logger.info("handling state: " + logger.state_to_text[my_state] + " message_type:" +
                    logger.message_type_to_text[message.type],
                __FUNCTION__, myself.nickname);

    assert(message.session_id.as_string() == session_id.get_as_stringbuff());


    if (message.type == Message::IN_SESSION_MESSAGE) {
        if (my_state == IN_SESSION || my_state == DEAD || my_state == LEAVE_REQUESTED) {
            SignedSessionMessage decrypted_message = SignedSessionMessage::decrypt(message, &cryptic);
            if (participants.find(sender) == participants.end()) {
                logger.error("authing participant " + sender + " is not in the session ");
                throw InvalidParticipantException();
            }
            if (!decrypted_message.verify(participants[sender].ephemeral_key)) {
                logger.warn("dropping in-session message with invalid signature by participant " + sender);
                return RoomAction(RoomAction::NO_ACTION);
            }

            StateAndAction result = receive(sender, decrypted_message);
            my_state = result.first;
            return result.second;
        }
    } else {
        SignedSessionMessage signed_session_message = SignedSessionMessage::decode(message);
        if (participants.find(sender) == participants.end()) {
            logger.error("authing participant " + sender + " is not in the session ");
            throw InvalidParticipantException();
        }
        if (!signed_session_message.verify(participants[sender].ephemeral_key)) {
            logger.warn("dropping message with invalid signature by participant " + sender);
            return RoomAction(RoomAction::NO_ACTION);
        }

        if (message.type == Message::PARTICIPANTS_INFO) {
            ParticipantsInfoMessage participants_info = ParticipantsInfoMessage::decode(signed_session_message);

            if (my_state == JOIN_REQUESTED) {
                participants[sender].be_authenticated(
                    myself.id_to_stringbuffer(),
                    participants_info.key_confirmation.buffer,
                    us->long_term_key_pair.get_key_pair().first,
                    &cryptic);
            }
            if (my_state == JOIN_REQUESTED || my_state == RE_SHARED) {
                participants[sender].set_key_share(participants_info.sender_share.buffer);

                StateAndAction result = send_session_confirmation_if_everybody_is_contributed();
                my_state = result.first;
                return result.second;
            }
        } else if (message.type == Message::JOINER_AUTH) {
            JoinerAuthMessage joiner_auth = JoinerAuthMessage::decode(signed_session_message);

            if (my_state == RE_SHARED) {
                if (joiner_auth.key_confirmations.find(my_index) != joiner_auth.key_confirmations.end()) {
                    participants[sender].be_authenticated(
                        myself.id_to_stringbuffer(),
                        joiner_auth.key_confirmations[my_index].buffer,
                        us->long_term_key_pair.get_key_pair().first,
                        &cryptic);
                }

                participants[sender].set_key_share(joiner_auth.sender_share.buffer);

                StateAndAction result = send_session_confirmation_if_everybody_is_contributed();
                my_state = result.first;
                return result.second;
            }
        } else if (message.type == Message::GROUP_SHARE) {
            GroupShareMessage group_share = GroupShareMessage::decode(signed_session_message);

            if (my_state == RE_SHARED) {
                participants[sender].set_key_share(group_share.sender_share.buffer);

                StateAndAction result = send_session_confirmation_if_everybody_is_contributed();
                my_state = result.first;
                return result.second;
            }
        } else if (message.type == Message::SESSION_CONFIRMATION) {
            SessionConfirmationMessage session_confirmation_message = SessionConfirmationMessage::decode(signed_session_message);

            if (my_state == GROUP_KEY_GENERATED) {
                if (session_confirmation(sender) != session_confirmation_message.session_confirmation) {
                    logger.warn(sender + " failed to provide a valid session confirmation, confirmation ignored", __FUNCTION__, myself.nickname);
                    return c_no_room_action;
                }

                memcpy(participants[sender].future_raw_ephemeral_key, session_confirmation_message.next_ephemeral_public_key.buffer, c_ephemeral_key_length);
                confirmed_peers[participants[sender].index] = true;

                if (everybody_confirmed()) {
                    if (rejoin_timer)
                        us->ops->axe_timer(rejoin_timer, us->ops->bare_sender_data);
                    rejoin_timer = nullptr;

                    account_for_session_and_key_consistency();

                    session_life_timer = us->ops->set_timer(cb_re_session, this, us->ops->c_session_life_span, us->ops->bare_sender_data);

                    my_state = IN_SESSION;
                }

                return c_no_room_action;
            }
        } else {
            assert(false);
        }
    }

    return RoomAction(RoomAction::NO_ACTION);
}

/**
 * for immature leave when we don't have leave intention
 */
RoomAction Session::shrink(std::string leaving_nick)
{
    // we are basically running the intention to leave message
    // without broadcasting it (because it is not us who intend to do so)
    // make a fake intention to leave message but don't send ack
    RoomAction new_session_action;

    auto leaver = participants.find(leaving_nick);
    if (leaver == participants.end()) {
        logger.warn("participant " + leaving_nick + " is not part of the active session of the room " + room_name +
                    " from which they are trying to leave, already parted?");
    } else if (zombies.find(leaving_nick) != zombies.end()) { // we haven already shrunk and made a session
        logger.debug("shrunk session for leaving user " + leaving_nick + " has already been generated. nothing to do",
                     __FUNCTION__, myself.nickname);
    } else { // shrink now
        // if everything is ok add the leaver to the zombie list and make a
        // session without zombies
        zombies.insert(*leaver);

        Session* new_child_session =
            new Session(PEER, us, room, room_name, &future_cryptic, future_participants());

        new_session_action.action_type = RoomAction::NEW_PRIORITY_SESSION;
        new_session_action.bred_session = new_child_session;

        // we are as we have farewelled
        // my_state = FAREWELLED; //We shouldn't change here and it is not clear why we
        // we need this stage, not to accept join? why? join will fail by non confirmation
        // of the leavers
        return new_session_action;
    }

    return c_no_room_action;
}

/**
 * sends session confirmation if everybody is contributed and authenticated
 * returns DEAD state if fails to decrypt the group key.
 *         GROUP_KEY_GENERATED otherwise
 *          the current state if not everybody authenticated
 */
Session::StateAndAction Session::send_session_confirmation_if_everybody_is_contributed()
{

    if (everybody_authenticated_and_contributed()) {
        group_dec();

        // we need our future ephemeral key to attach to the message
        future_cryptic.init();

        SessionConfirmationMessage message;
        message.session_confirmation = session_confirmation(myself.nickname);
        memcpy(message.next_ephemeral_public_key.buffer,
            public_key_to_stringbuff(future_cryptic.get_ephemeral_pub_key()).data(),
            sizeof(message.next_ephemeral_public_key.buffer));
        send(message.encode());

        RoomAction re_limbo_action;

        re_limbo_action.action_type = RoomAction::PRESUME_HEIR;
        re_limbo_action.bred_session = this;

        return StateAndAction(GROUP_KEY_GENERATED, re_limbo_action);
        // if we are joing we don't need to relimbo and the room will
        // ignore the action,
    }
 
    // otherwise just wait for more shares
    return StateAndAction(my_state, RoomAction());
}

void Session::leave()
{
    // tell everybody I'm leaving and tell them about the closure
    // of my transcript consistency

    // if you are the only person in the session then
    // just leave
    // TODO:: is it good to call the ops directly?
    logger.debug("leaving the session", __FUNCTION__, myself.nickname);
    if (participants.size() == 1) {
        logger.debug("last person in the session, not waiting for farewell", __FUNCTION__, myself.nickname);

        logger.assert_or_die(my_index == 0 && peers.size() == 1, "peers is not sync with participants");
        peers.pop_back();
        us->ops->leave(room_name, peers, us->ops->bare_sender_data);
        commit_suicide();
    }

    // otherwise, inform others in the room about your leaving the room
    logger.debug("informing other, waiting for farewell", __FUNCTION__, myself.nickname);
    leave_parent = last_received_message_id;
    send("", InSessionMessage::LEAVE_MESSAGE);

    farewell_deadline_timer =
        us->ops->set_timer(cb_leave, this, us->ops->c_inactive_ergo_non_sum_interval, us->ops->bare_sender_data);
    my_state = LEAVE_REQUESTED;
}

/**
 * When we receive a message we set a timer so to check that
 * everybody else has received the same message
 */
void Session::start_ack_timers(const std::string& sender)
{
    for (ParticipantMap::iterator it = participants.begin(); it != participants.end(); ++it) {
        // we accumulate the timers, when we receive ack, we drop what we
        // have before
        if ((sender != (*it).second.id.nickname) &&
            (sender != myself.nickname)) // not for the sender and not
        // for myself
        {
            received_transcript_chain[last_received_message_id][(*it).second.index].ack_timer_ops.session = this;
            received_transcript_chain[last_received_message_id][(*it).second.index].ack_timer_ops.participant =
                &(it->second);
            received_transcript_chain[last_received_message_id][(*it).second.index].ack_timer_ops.message_id =
                last_received_message_id;
            received_transcript_chain[last_received_message_id][(*it).second.index].consistency_timer =
                us->ops->set_timer(
                    cb_ack_not_received,
                    &(received_transcript_chain[last_received_message_id][(*it).second.index].ack_timer_ops),
                    us->ops->c_consistency_failure_interval, us->ops->bare_sender_data);
        }
    }
}

// void Session::start_conditional_send_ack_timer() {
//   //if there is already an ack timer
//   //then that will take care of acking
//   //for us as well

// }

/**
 * When we receive a message we start a timer to make sure that we'll
 * send an ack if we haven't send any message
 */
void Session::start_acking_timer()
{
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

void Session::stop_acking_timer()
{
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

/**
 * Inserts a block in the send transcript chain and start a
 * timer to receive the ack for it
 */
void Session::update_send_transcript_chain(MessageId own_message_id, std::string message)
{
    HashBlock hb;
    hash(message, hb, true);
    sent_transcript_chain[own_message_id].transcript_hash = hash_to_string_buff(hb);
    sent_transcript_chain[own_message_id].ack_timer_ops = AckTimerOps(this, nullptr, own_message_id);

    sent_transcript_chain[own_message_id].consistency_timer =
        us->ops->set_timer(cb_ack_not_sent, &(sent_transcript_chain[own_message_id].ack_timer_ops),
                           us->ops->c_send_receive_interval, us->ops->bare_sender_data);
}

/**
 * - check the consistency of all participants for the parent leave message
 */
bool Session::check_leave_transcript_consistency()
{
    uint32_t no_of_peers_farewelled = 0;
    if (received_transcript_chain.find(leave_parent) != received_transcript_chain.end()) {
        for (uint32_t i = 0; i < peers.size(); i++) {

            // we need to check if we have already got the farewell from this peer
            if (!received_transcript_chain[leave_parent][i].transcript_hash.empty()) {
                no_of_peers_farewelled++;
                if (received_transcript_chain[leave_parent][i].transcript_hash !=
                    received_transcript_chain[leave_parent][my_index].transcript_hash) {
                    std::string consistency_failure_message = peers[i] + " transcript doesn't match ours";
                    us->ops->display_message(room_name, "np1sec directive", consistency_failure_message, us->ops->bare_sender_data);
                    logger.error(consistency_failure_message, __FUNCTION__, myself.nickname);
                } // not equal
            } // not empty
        } // for
    } // we got it already

    return (no_of_peers_farewelled == peers.size());
}

void Session::add_message_to_transcript(std::string message, MessageId message_id)
{
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

    hash(pointlessconversion, hb);

    if (received_transcript_chain.find(message_id) == received_transcript_chain.end()) {
        ConsistencyBlockVector chain_block(participants.size());
        received_transcript_chain.insert(std::pair<MessageId, ConsistencyBlockVector>(message_id, chain_block));
    }

    (received_transcript_chain[message_id])[my_index].transcript_hash = hash_to_string_buff(hb);
    received_transcript_chain[message_id][my_index].consistency_timer = nullptr;
}

void Session::send(std::string payload, InSessionMessage::Type message_type)
{
    if (!(my_state >= IN_SESSION) && my_state <= LEAVE_REQUESTED) {
        logger.error("you can't send in session message to a session which is not established", __FUNCTION__,
                     myself.nickname);
        throw InvalidSessionStateException();
    }

    own_message_counter++;

    InSessionMessage message;
    message.sender_index = my_index;
    message.sender_message_id = own_message_counter;
    message.parent_server_message_id = last_received_message_id;
    memcpy(message.transcript_chain_hash.buffer,
        received_transcript_chain.rbegin()->second[my_index].transcript_hash.data(),
        sizeof(message.transcript_chain_hash.buffer));
    gcry_randomize(message.nonce.buffer, sizeof(message.nonce.buffer), GCRY_STRONG_RANDOM);
    message.subtype = message_type;
    message.payload = payload;

    UnsignedCurrentSessionMessage encoded_message = message.encode();
    UnsignedSessionMessage unsigned_message;
    unsigned_message.type = encoded_message.type;
    unsigned_message.payload = encoded_message.payload;
    memcpy(unsigned_message.session_id.buffer, session_id.get(), sizeof(unsigned_message.session_id.buffer));
    SignedSessionMessage signed_message = SignedSessionMessage::sign(unsigned_message, &cryptic);
    SessionMessage encrypted_message = signed_message.encrypt(&cryptic);

    room->send(encrypted_message.encode());


    update_send_transcript_chain(own_message_counter, unsigned_message.signed_body());
    // As we're sending a new message we are no longer required to ack
    // any received messages till we receive a new message
    stop_acking_timer();
}

Session::StateAndAction Session::receive(const std::string& sender, const SignedSessionMessage& signed_message)
{
    last_received_message_id++;

    add_message_to_transcript(signed_message.signed_body(), last_received_message_id);

    InSessionMessage message = InSessionMessage::decode(signed_message);

    if (sender == myself.nickname) {
        logger.debug("own ctr of received message: " + std::to_string(own_message_counter), __FUNCTION__,
                     myself.nickname);
        if (sent_transcript_chain[message.sender_message_id].consistency_timer)
            us->ops->axe_timer(sent_transcript_chain[message.sender_message_id].consistency_timer, us->ops->bare_sender_data);
        sent_transcript_chain[message.sender_message_id].consistency_timer = nullptr;
    }

    // it needs to be called after add as it assumes it is already added
    start_ack_timers(sender);

    if (my_state == LEAVE_REQUESTED) {
        if (check_leave_transcript_consistency()) {
            // we are done we can leave

            // stop the farewell deadline timer
            if (farewell_deadline_timer)
                us->ops->axe_timer(farewell_deadline_timer, us->ops->bare_sender_data);
            farewell_deadline_timer = nullptr;

            peers.pop_back();
            us->ops->leave(room_name, peers, us->ops->bare_sender_data);
            commit_suicide();
            return StateAndAction(DEAD, c_no_room_action);
        }
    }

    if (message.subtype == InSessionMessage::JUST_ACK) {
        return StateAndAction(my_state, c_no_room_action);
    } else if (message.subtype == InSessionMessage::USER_MESSAGE) {
        us->ops->display_message(room_name, sender, message.payload, us->ops->bare_sender_data);

        start_acking_timer();
        return StateAndAction(my_state, c_no_room_action);
    } else if (message.subtype == InSessionMessage::LEAVE_MESSAGE) {
        if (sender != myself.nickname && my_state != DEAD) {
            logger.info(sender + " waves goodbye.", __FUNCTION__, myself.nickname);

            send("", InSessionMessage::JUST_ACK);
            return StateAndAction(my_state, shrink(sender));
        }
        return StateAndAction(my_state, c_no_room_action);
    } else {
        assert(false);
    }
}

/**
 * prepare a new list of participant for a new session
 * replacing future key to current key and drop zombies
 */
ParticipantMap Session::future_participants()
{
    ParticipantMap live_participants = participants - zombies;
    for (auto& cur_participant : live_participants)
        cur_participant.second.set_ephemeral_key(cur_participant.second.future_raw_ephemeral_key);

    return live_participants;
}

/**
 * returns participants - parental_participants
 * it shows what is the session suppose to add or
 * drop it is a replacement for raison_detre
 */
ParticipantMap Session::delta_plist() { return participants - parental_participants; }

/**
 * change the state to DEAD. it is needed when we bread a new
 * session out of this session.
 * it also axes all of the timers
 */
void Session::commit_suicide()
{
    // we try to send a last ack, if it fails no big deal

    disarm_all_timers();
    my_state = DEAD;
}

/**
 * stop all timers
 */
void Session::disarm_all_timers()
{
    if (farewell_deadline_timer)
        us->ops->axe_timer(farewell_deadline_timer, us->ops->bare_sender_data);
    farewell_deadline_timer = nullptr;
    if (send_ack_timer)
        us->ops->axe_timer(send_ack_timer, us->ops->bare_sender_data);
    send_ack_timer = nullptr;

    if (rejoin_timer)
        us->ops->axe_timer(rejoin_timer, us->ops->bare_sender_data);
    rejoin_timer = nullptr;

    if (session_life_timer)
        us->ops->axe_timer(session_life_timer, us->ops->bare_sender_data);
    session_life_timer = nullptr;

    for (auto& cur_block : received_transcript_chain)
        for (auto& cur_participant : cur_block.second) {
            if (cur_participant.consistency_timer) {
                us->ops->axe_timer(cur_participant.consistency_timer, us->ops->bare_sender_data);
            }
            cur_participant.consistency_timer = nullptr;
        }

    for (auto& cur_block : sent_transcript_chain) {
        if (cur_block.second.consistency_timer) {
            us->ops->axe_timer(cur_block.second.consistency_timer, us->ops->bare_sender_data);
        }
        cur_block.second.consistency_timer = nullptr;
    }
}

/**
 * tells if rejoin is active
 */
void Session::arm_rejoin_timer()
{
    logger.assert_or_die(!rejoin_timer, "no re-arming the rejoin timer!", __FUNCTION__,
                         myself.nickname); // we shouldn't rearm rejoin timer
    logger.debug("arming rejoin timer, in case we can't join successfully", __FUNCTION__, myself.nickname);
    rejoin_timer =
        us->ops->set_timer(cb_rejoin, this, us->ops->c_unresponsive_ergo_non_sum_interval, us->ops->bare_sender_data);
}

void Session::send(const UnsignedCurrentSessionMessage& message)
{
    UnsignedSessionMessage unsigned_message;
    unsigned_message.type = message.type;
    unsigned_message.payload = message.payload;
    memcpy(unsigned_message.session_id.buffer, session_id.get(), sizeof(unsigned_message.session_id.buffer));

    SignedSessionMessage signed_message = SignedSessionMessage::sign(unsigned_message, &cryptic);

    room->send(signed_message.encode().encode());
}

Session::~Session()
{
    secure_wipe(session_key, c_hash_length);
    logger.debug("Wiped session_key from Session");
}

} // namespace np1sec
