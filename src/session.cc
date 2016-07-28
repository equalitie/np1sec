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
#include <cassert>

#include "exceptions.h"
#include "session.h"
#include "room.h"

namespace np1sec
{

static SessionId compute_session_id(const ParticipantMap& participants) throw(CryptoException)
{
    std::string hash_buffer;
    for (auto it = participants.begin(); it != participants.end(); it++) {
        hash_buffer += it->second.nickname;
        hash_buffer += it->second.long_term_public_key.as_string();
        hash_buffer += it->second.ephemeral_public_key.as_string();
    }

    return SessionId(crypto::hash(hash_buffer));
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
Session::Session(SessionConceiverCondition conceiver, Application* application, Room *room,
                 const std::string& nickname, const PrivateKey& long_term_private_key, const PrivateKey& ephemeral_private_key,
                 const ParticipantMap& current_participants, const ParticipantMap& parent_plist):
    application(application),
    room(room),
    nickname(nickname),
    long_term_private_key(long_term_private_key),
    ephemeral_private_key(ephemeral_private_key),
    next_ephemeral_private_key(PrivateKey::generate()),
    participants(current_participants),
    parental_participants(parent_plist),
    session_id(compute_session_id(participants))
{
    logger.info("constructing new session for room " + room->name + " with " + std::to_string(participants.size()) +
                    " participants",
                __FUNCTION__);

    if (participants.find(nickname) == participants.end()) {
        logger.debug("the message wasn't meant to us", __FUNCTION__);
        throw InvalidRoomException();
    }
    for (ParticipantMap::iterator it = participants.begin(); it != participants.end(); it++) {
        peers.push_back(it->first);
    }
    std::sort(peers.begin(), peers.end());
    for (size_t i = 0; i < peers.size(); i++) {
        participants[peers[i]].index = i;
        if (peers[i] == nickname) {
            my_index = i;
        }
    }
    // we trust ourselves so no need to auth ourselves neither be_authed_to
    participants[peers[my_index]].authenticated = true;
    participants[peers[my_index]].authed_to = true;
    confirmed_peers.resize(peers.size());



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
            logger.assert_or_die(delta_plist().size() <= 1, "this is n+1sec, one addition at time", __FUNCTION__);
            joiner_id = delta_plist().begin()->second.nickname;
        }
        send_view_auth_and_share(joiner_id);
    } else if (conceiver == PEER) {
        my_state = RE_SHARED;


        send_new_share_message();
    } else {
        logger.abort("wrong conceiver type: " + std::to_string(conceiver), __FUNCTION__);
    }

    logger.info("session constructed with FSM new state: " + logger.state_to_text[my_state], __FUNCTION__);
}

Hash Session::session_confirmation(std::string participant_nickname)
{
    std::string hash_buffer;
    hash_buffer += session_key.key.as_string();
    hash_buffer += participant_nickname;
    return crypto::hash(hash_buffer);
}

void Session::account_for_session_and_key_consistency()
{
    std::string hash_buffer;
    hash_buffer += session_key.key.as_string();
    hash_buffer += session_id.as_string();

    last_received_message_id = 0; // key confirmation is the first message
    add_message_to_transcript(crypto::hash(hash_buffer).as_string(), last_received_message_id);
}

/**
 * compute the right secret share
 * @param side  either c_my_right = 1 or c_my_left = 1
 */
Hash Session::secret_share_on(int32_t side)
{
    assert(side == c_my_left || side == c_my_right);
    size_t neighbour = (my_index + side + peers.size()) % peers.size();

    participants[peers[neighbour]].compute_p2p_private(long_term_private_key, ephemeral_private_key);

    std::string hash_buffer;
    hash_buffer += participants[peers[neighbour]].p2p_key.key.as_string();
    hash_buffer += session_id.as_string();
    return crypto::hash(hash_buffer, true);
}

void Session::group_enc()
{
    Hash share_left = secret_share_on(c_my_left);
    Hash share_right = secret_share_on(c_my_right);

    Hash key_share;
    for (size_t i = 0; i < sizeof(key_share.buffer); i++) {
        key_share.buffer[i] = share_left.buffer[i] ^ share_right.buffer[i];
    }

    participants[nickname].set_key_share(key_share);
}

void Session::group_dec()
{
    std::vector<Hash> shares;
    shares.resize(peers.size());

    Hash accumulator = secret_share_on(c_my_right);
    for (size_t i = 0; i < peers.size(); i++) {
        size_t index = (my_index + i) % peers.size();
        shares[index] = accumulator;
        size_t next = (index + 1) % peers.size();
        for (size_t j = 0; j < sizeof(accumulator.buffer); j++) {
            accumulator.buffer[j] ^= participants[peers[next]].cur_keyshare.buffer[j];
        }
    }

    std::string hash_buffer;
    for (size_t i = 0; i < peers.size(); i++) {
        hash_buffer += shares[i].as_string();
    }
    hash_buffer += session_id.as_string();

    session_key.key = crypto::hash(hash_buffer, true);
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

void Session::joiner_send_auth_and_share()
{
    group_enc();

    JoinerAuthMessage message;
    for (uint32_t i = 0; i < peers.size(); i++) {
        if (!participants[peers[i]].authed_to) {
            message.key_confirmations[i] = participants[peers[i]].authenticate_to(long_term_private_key, ephemeral_private_key);
        }
    }
    message.sender_share = participants[nickname].cur_keyshare;
    send(message.encode());
}

void Session::send_new_share_message()
{
    group_enc();

    GroupShareMessage message;
    message.sender_share = participants[nickname].cur_keyshare;
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
    group_enc(); // compute my share for group key

    Hash cur_auth_token;
    memset(cur_auth_token.buffer, 0, sizeof(cur_auth_token));
    if (!joiner_id.empty()) {
        if (participants.find(joiner_id) == participants.end()) {
            logger.error("can't authenticate to non-member joining participant " + joiner_id, __FUNCTION__);
            throw InvalidParticipantException();
        }

        cur_auth_token = participants[joiner_id].authenticate_to(long_term_private_key, ephemeral_private_key);
    }

    ParticipantsInfoMessage message;
    for (size_t i = 0; i < peers.size(); i++) {
        ParticipantsInfoMessage::ParticipantInfo participant;
        participant.nickname = participants[peers[i]].nickname;
        participant.long_term_public_key = participants[peers[i]].long_term_public_key;
        participant.ephemeral_public_key = participants[peers[i]].ephemeral_public_key;
        participant.authenticated = participants[peers[i]].authenticated;
        message.participants.push_back(participant);
    }
    message.key_confirmation = cur_auth_token;
    message.sender_share = participants[nickname].cur_keyshare;
    send(message.encode());

    logger.debug("sending participant info message");
}

RoomAction Session::state_handler(const std::string& sender, SessionMessage message)
{
    logger.info("handling state: " + logger.state_to_text[my_state] + " message_type:" +
                    logger.message_type_to_text[message.type],
                __FUNCTION__);

    assert(message.session_id == session_id);


    if (message.type == Message::IN_SESSION_MESSAGE) {
        if (my_state == IN_SESSION || my_state == DEAD || my_state == LEAVE_REQUESTED) {
            SignedSessionMessage decrypted_message = SignedSessionMessage::decrypt(message, session_key);
            if (participants.find(sender) == participants.end()) {
                logger.error("authing participant " + sender + " is not in the session ");
                throw InvalidParticipantException();
            }
            if (!decrypted_message.verify(participants[sender].ephemeral_public_key)) {
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
        if (!signed_session_message.verify(participants[sender].ephemeral_public_key)) {
            logger.warn("dropping message with invalid signature by participant " + sender);
            return RoomAction(RoomAction::NO_ACTION);
        }

        if (message.type == Message::PARTICIPANTS_INFO) {
            ParticipantsInfoMessage participants_info = ParticipantsInfoMessage::decode(signed_session_message);

            if (my_state == JOIN_REQUESTED) {
                participants[sender].be_authenticated(
                    nickname,
                    participants_info.key_confirmation,
                    long_term_private_key,
                    ephemeral_private_key);
            }
            if (my_state == JOIN_REQUESTED || my_state == RE_SHARED) {
                participants[sender].set_key_share(participants_info.sender_share);

                StateAndAction result = send_session_confirmation_if_everybody_is_contributed();
                my_state = result.first;
                return result.second;
            }
        } else if (message.type == Message::JOINER_AUTH) {
            JoinerAuthMessage joiner_auth = JoinerAuthMessage::decode(signed_session_message);

            if (my_state == RE_SHARED) {
                if (joiner_auth.key_confirmations.find(my_index) != joiner_auth.key_confirmations.end()) {
                    participants[sender].be_authenticated(
                        nickname,
                        joiner_auth.key_confirmations[my_index],
                        long_term_private_key,
                        ephemeral_private_key);
                }

                participants[sender].set_key_share(joiner_auth.sender_share);

                StateAndAction result = send_session_confirmation_if_everybody_is_contributed();
                my_state = result.first;
                return result.second;
            }
        } else if (message.type == Message::GROUP_SHARE) {
            GroupShareMessage group_share = GroupShareMessage::decode(signed_session_message);

            if (my_state == RE_SHARED) {
                participants[sender].set_key_share(group_share.sender_share);

                StateAndAction result = send_session_confirmation_if_everybody_is_contributed();
                my_state = result.first;
                return result.second;
            }
        } else if (message.type == Message::SESSION_CONFIRMATION) {
            SessionConfirmationMessage session_confirmation_message = SessionConfirmationMessage::decode(signed_session_message);

            if (my_state == GROUP_KEY_GENERATED) {
                if (session_confirmation(sender) != session_confirmation_message.session_confirmation) {
                    logger.warn(sender + " failed to provide a valid session confirmation, confirmation ignored", __FUNCTION__);
                    return c_no_room_action;
                }

                participants[sender].next_ephemeral_public_key = session_confirmation_message.next_ephemeral_public_key;
                confirmed_peers[participants[sender].index] = true;

                if (everybody_confirmed()) {
                    rejoin_timer.stop();

                    account_for_session_and_key_consistency();

                    session_life_timer = application->set_timer(application->session_life_span(), [this] {
                        logger.assert_or_die(my_state != Session::DEAD, "postmorten ratcheting?");
                        logger.info("RESESSION: forward secrecy ratcheting", __FUNCTION__);
                        Session* child_session = new Session(Session::PEER, application, room,
                            nickname, long_term_private_key, next_ephemeral_private_key,
                            future_participants());
                        room->insert_session(child_session);
                    });

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
        logger.warn("participant " + leaving_nick + " is not part of the active session of the room " + room->name +
                    " from which they are trying to leave, already parted?");
    } else if (zombies.find(leaving_nick) != zombies.end()) { // we haven already shrunk and made a session
        logger.debug("shrunk session for leaving user " + leaving_nick + " has already been generated. nothing to do",
                     __FUNCTION__);
    } else { // shrink now
        // if everything is ok add the leaver to the zombie list and make a
        // session without zombies
        zombies.insert(*leaver);

        Session* new_child_session =
            new Session(PEER, application, room, nickname, long_term_private_key, next_ephemeral_private_key, future_participants());

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

        SessionConfirmationMessage message;
        message.session_confirmation = session_confirmation(nickname);
        message.next_ephemeral_public_key = next_ephemeral_private_key.public_key();
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
    logger.debug("leaving the session", __FUNCTION__);
    if (participants.size() == 1) {
        logger.debug("last person in the session, not waiting for farewell", __FUNCTION__);

        logger.assert_or_die(my_index == 0 && peers.size() == 1, "peers is not sync with participants");
        peers.pop_back();
        application->leave(room->name, peers);
        commit_suicide();
    }

    // otherwise, inform others in the room about your leaving the room
    logger.debug("informing other, waiting for farewell", __FUNCTION__);
    leave_parent = last_received_message_id;
    send("", InSessionMessage::LEAVE_MESSAGE);

    farewell_deadline_timer = application->set_timer(application->inactive_ergo_non_sum_interval(), [this] {
        check_leave_transcript_consistency();
        commit_suicide();
    });
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
        if ((sender != it->second.nickname) &&
            (sender != nickname)) // not for the sender and not
        // for myself
        {
            received_transcript_chain[last_received_message_id][(*it).second.index].have_transcript_hash = false;

            Participant& participant = it->second;
            received_transcript_chain[last_received_message_id][(*it).second.index].consistency_timer = application->set_timer(
                application->consistency_failure_interval(),
                [this, participant] {
                    if (my_state == Session::DEAD) {
                        logger.debug("postmortem consistency check", __FUNCTION__);
                    }
                    std::string message = participant.nickname + " failed to ack";
                    application->display_message(room->name, "np1sec directive", message);
                    logger.warn(message + " in room " + room->name, __FUNCTION__);
                }
            );
        }
    }
}


/**
 * When we receive a message we start a timer to make sure that we'll
 * send an ack if we haven't send any message
 */
void Session::start_acking_timer()
{
    if (!send_ack_timer.active()) {
        send_ack_timer = application->set_timer(application->ack_interval(), [this] {
            if (my_state == Session::DEAD) {
                logger.debug("postmorten consistency check", __FUNCTION__);
            }
            logger.debug("long time, no message! acknowledging received messages", __FUNCTION__);
            send("", InSessionMessage::JUST_ACK);
        });
    }
}

void Session::stop_acking_timer()
{
    send_ack_timer.stop();
}

/**
 * Inserts a block in the send transcript chain and start a
 * timer to receive the ack for it
 */
void Session::update_send_transcript_chain(MessageId own_message_id, std::string message)
{
    sent_transcript_chain[own_message_id].transcript_hash = crypto::hash(message);
    sent_transcript_chain[own_message_id].consistency_timer = application->set_timer(application->send_receive_interval(),
        [this, own_message_id] {
            if (my_state == Session::DEAD) {
                logger.debug("postmorten consistency check", __FUNCTION__);
            }
            application->display_message(room->name, "np1sec directive", "we did not receive our own sent message");
        }
    );
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
            if (received_transcript_chain[leave_parent][i].have_transcript_hash) {
                no_of_peers_farewelled++;
                if (received_transcript_chain[leave_parent][i].transcript_hash != received_transcript_chain[leave_parent][my_index].transcript_hash)
                {
                    std::string consistency_failure_message = peers[i] + " transcript doesn't match ours";
                    application->display_message(room->name, "np1sec directive", consistency_failure_message);
                    logger.error(consistency_failure_message, __FUNCTION__);
                } // not equal
            } // not empty
        } // for
    } // we got it already

    return (no_of_peers_farewelled == peers.size());
}

void Session::add_message_to_transcript(std::string message, MessageId message_id)
{
    if (received_transcript_chain.find(message_id) == received_transcript_chain.end()) {
        ConsistencyBlockVector chain_block(participants.size());
        received_transcript_chain.insert(std::pair<MessageId, ConsistencyBlockVector>(message_id, std::move(chain_block)));
    }

    std::string hash_buffer;
    if (received_transcript_chain.size() > 0) {
        hash_buffer = received_transcript_chain.rbegin()->second[my_index].transcript_hash.as_string() + message;
    } else {
        hash_buffer = message;
    }

    received_transcript_chain[message_id][my_index].have_transcript_hash = true;
    received_transcript_chain[message_id][my_index].transcript_hash = crypto::hash(hash_buffer);
}

void Session::send(std::string payload, InSessionMessage::Type message_type)
{
    if (!(my_state >= IN_SESSION) && my_state <= LEAVE_REQUESTED) {
        logger.error("you can't send in session message to a session which is not established", __FUNCTION__);
        throw InvalidSessionStateException();
    }

    own_message_counter++;

    InSessionMessage message;
    message.sender_index = my_index;
    message.sender_message_id = own_message_counter;
    message.parent_server_message_id = last_received_message_id;
    received_transcript_chain.rbegin()->second[my_index].transcript_hash = message.transcript_chain_hash;
    message.nonce = crypto::nonce<sizeof(message.nonce.buffer)>();
    message.subtype = message_type;
    message.payload = payload;

    UnsignedCurrentSessionMessage encoded_message = message.encode();
    UnsignedSessionMessage unsigned_message;
    unsigned_message.type = encoded_message.type;
    unsigned_message.payload = encoded_message.payload;
    unsigned_message.session_id = session_id;
    SignedSessionMessage signed_message = SignedSessionMessage::sign(unsigned_message, ephemeral_private_key);
    SessionMessage encrypted_message = signed_message.encrypt(session_key);

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

    if (sender == nickname) {
        logger.debug("own ctr of received message: " + std::to_string(own_message_counter), __FUNCTION__);
        sent_transcript_chain[message.sender_message_id].consistency_timer.stop();
    }

    // it needs to be called after add as it assumes it is already added
    start_ack_timers(sender);

    if (my_state == LEAVE_REQUESTED) {
        if (check_leave_transcript_consistency()) {
            // we are done we can leave

            // stop the farewell deadline timer
            farewell_deadline_timer.stop();

            peers.pop_back();
            application->leave(room->name, peers);
            commit_suicide();
            return StateAndAction(DEAD, c_no_room_action);
        }
    }

    if (message.subtype == InSessionMessage::JUST_ACK) {
        return StateAndAction(my_state, c_no_room_action);
    } else if (message.subtype == InSessionMessage::USER_MESSAGE) {
        application->display_message(room->name, sender, message.payload);

        start_acking_timer();
        return StateAndAction(my_state, c_no_room_action);
    } else if (message.subtype == InSessionMessage::LEAVE_MESSAGE) {
        if (sender != nickname && my_state != DEAD) {
            logger.info(sender + " waves goodbye.", __FUNCTION__);

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
        cur_participant.second.set_ephemeral_key(cur_participant.second.next_ephemeral_public_key);

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
    farewell_deadline_timer.stop();
    send_ack_timer.stop();
    rejoin_timer.stop();
    session_life_timer.stop();
    for (auto& cur_block : received_transcript_chain) {
        for (auto& cur_participant : cur_block.second) {
            cur_participant.consistency_timer.stop();
        }
    }
    for (auto& cur_block : sent_transcript_chain) {
        cur_block.second.consistency_timer.stop();
    }
}

/**
 * tells if rejoin is active
 */
void Session::arm_rejoin_timer()
{
    logger.assert_or_die(!rejoin_timer.active(), "no re-arming the rejoin timer!", __FUNCTION__);
    logger.debug("arming rejoin timer, in case we can't join successfully", __FUNCTION__);
    rejoin_timer = application->set_timer(application->unresponsive_ergo_non_sum_interval(), [this] {
        commit_suicide();
        logger.debug("joining session timed out, trying to rejoin", __FUNCTION__);
        room->try_rejoin();
    });
}

void Session::send(const UnsignedCurrentSessionMessage& message)
{
    UnsignedSessionMessage unsigned_message;
    unsigned_message.type = message.type;
    unsigned_message.payload = message.payload;
    unsigned_message.session_id = session_id;

    SignedSessionMessage signed_message = SignedSessionMessage::sign(unsigned_message, ephemeral_private_key);

    room->send(signed_message.encode().encode());
}

} // namespace np1sec
