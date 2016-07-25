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

#include "userstate.h"
#include "room.h"

#include "message.h"

namespace np1sec
{

/**
 * constructor: sets room name, make the user status joing
 * by default.
 *
 */
Room::Room(std::string room_name, UserState* user_state,
                       uint32_t room_size)
    : name(room_name), user_state(user_state), user_in_room_state(JOINING)
{
    np1sec_ephemeral_crypto.init(); // generate intitial ephemeral keys for join
    //room_size = participants_in_the_room.size(); //we should not rely on the server for room size?
    this->room_size = room_size; //this really should be changed to lonely_room

    join();
}

/**
 * called by room constructor, everytime the user is the first joiner
 * of an empty room and hence does not need to convince anybody about
 * their identity, etc.
 */
void Room::solitary_join()
{
    // simply faking the particpant inf message
    logger.assert_or_die(user_in_room_state == JOINING, "only can be called in joining stage", __FUNCTION__,
                         user_state->myself->nickname);

    ParticipantMap participants;
    Participant self(user_state->myself->nickname, user_state->myself->fingerprint,
        (uint8_t*)public_key_to_stringbuff(np1sec_ephemeral_crypto.get_ephemeral_pub_key()).data());
    participants.insert(std::pair<std::string, Participant>(user_state->myself->nickname, self));

    Session* session = new Session(Session::CREATOR, user_state, this, name, &np1sec_ephemeral_crypto, participants);

    session_universe[session->my_session_id().get_as_stringbuff()] = session;
}

/**
 * called by room constructor, everytime the user trys to join a room
 * occupied by others. it just simply send a join message to the room.
 */
void Room::join()
{
    logger.assert_or_die(user_in_room_state == JOINING, "only can be called in joining stage", __FUNCTION__,
                         user_state->myself->nickname); // no double join but we need a
    //We should not die. in particular we already know that one participant is in the room.
    logger.assert_or_die(room_size > 0, "room size reported to be: " + std::to_string(room_size) + ". being in an empty room is a logical contradition",
                         __FUNCTION__, user_state->myself->nickname);

    logger.debug("currently " + std::to_string(room_size) + " partcipants in the room", __FUNCTION__,
                 user_state->myself->nickname);

    if (room_size == 1) {
        logger.info("creating room " + name + "...", __FUNCTION__, user_state->myself->nickname);
        solitary_join();
    } else {
        logger.info("joining room " + name + "...", __FUNCTION__, user_state->myself->nickname);

        JoinRequestMessage join_request;
        join_request.nickname = user_state->myself->nickname;
        memcpy(join_request.long_term_public_key.buffer, user_state->myself->fingerprint, sizeof(join_request.long_term_public_key.buffer));
        memcpy(join_request.ephemeral_public_key.buffer, public_key_to_stringbuff(np1sec_ephemeral_crypto.get_ephemeral_pub_key()).data(), sizeof(join_request.ephemeral_public_key.buffer));
        send(join_request.encode());
    }
}

/**
 *  If the user is joiner and already has constructed a session for
 *  the room and for any reason haven't received a reply from current
 *  participant this functions resend the join request
 */
void Room::try_rejoin()
{
    // you don't need to retry sole-joining as it is
    // a deterministic process
    if (user_in_room_state == JOINING) {
        // we need to kill everything already is in progress
        for (SessionMap::iterator session_it = session_universe.begin(); session_it != session_universe.end();
             session_it++)
            session_it->second->commit_suicide();

        join();

    } else {
        // it is probably called by a desperate
        // ding session that doesn't know we are
        // are already joind
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
void Room::receive_handler(std::string message_string, std::string sender_nickname)
{
    Message message = Message::decode(message_string);

    // If the user is not in the session, we can do nothing with
    // session less messages, we are joining and we need info
    // about the room
    RoomAction action_to_take = c_no_room_action;

    logger.info("room " + name + " handling message " + logger.message_type_to_text[message.type] + " from " + sender_nickname,
        __FUNCTION__, user_state->myself->nickname);

    //   The principale:

    // At each session movement
    // - Many can leave.
    // - less than or equal to 1 can join.

    // Joiner
    // - PARTICIPANTS_INFO: Make a session if you are of it.
    // - Orphant CONFIRMATION: Should only be send for one session at the time. Hence if you receive a confirmation,
    // which is not for one of your limbo session, any limbo session which does not have a confirmation will die, though
    // you need to check signature.

    // - Current user:
    // - SHRINK: make a session with removed all zombies, update all limbos parent to the new session: that's how leave
    // is prioritize over join and resession.
    // - KEY_GENERATED: updated limbos, send confirmation.
    // - Confirmed: move session.

    Session *session;

    if (message.type == Message::JOIN_REQUEST) {
        session = nullptr;
        JoinRequestMessage join_request_message = JoinRequestMessage::decode(message);

        if (user_in_room_state == CURRENT_USER) {
            Session *next_in_activation = session_universe[next_in_activation_line.get_as_stringbuff()];
            ParticipantMap current_participants = next_in_activation->future_participants();
            ParticipantMap next_participants = current_participants;

            if (next_participants.find(join_request_message.nickname) != next_participants.end()) {
                logger.warn(join_request_message.nickname + " can't join the room twice");
            } else {
                next_participants.insert(std::pair<std::string, Participant>(join_request_message.nickname, 
                    Participant(join_request_message.nickname, join_request_message.long_term_public_key.buffer, join_request_message.ephemeral_public_key.buffer)));
                action_to_take.action_type = RoomAction::NEW_SESSION;
                action_to_take.bred_session = new Session(Session::ACCEPTOR, user_state, this, name,
                    &next_in_activation->future_cryptic, next_participants, current_participants);
            }
        }
        // else just ignore it, it is probably another user's join that we don't
        // care.
    } else {
        SessionMessage session_message = SessionMessage::decode(message);

        std::string session_id = session_message.session_id.as_string();
        if (session_universe.find(session_id) == session_universe.end()) {
            session = nullptr;
        } else {
            session = session_universe[session_id];
        }

        if (user_in_room_state == JOINING) {
            logger.debug("in JOINING state", __FUNCTION__, user_state->myself->nickname);

            if (session && (session->get_state() != Session::DEAD)) {
                action_to_take = session->state_handler(sender_nickname, session_message);
            } else {
                // we are only interested in PARTICIANT_INFO and SESSION_CONFIRMATION (they means death to unconfirmed
                // sessions)
                if (message.type == Message::PARTICIPANTS_INFO) {
                    try {
                        SignedSessionMessage signed_message = SignedSessionMessage::decode(session_message);
                        ParticipantsInfoMessage participants_info = ParticipantsInfoMessage::decode(signed_message);

                        ParticipantMap participants;
                        for (size_t i = 0; i < participants_info.participants.size(); i++) {
                            participants.insert(std::pair<std::string, Participant>(participants_info.participants[i].nickname,
                                Participant(participants_info.participants[i].nickname,
                                    participants_info.participants[i].long_term_public_key.buffer,
                                    participants_info.participants[i].ephemeral_public_key.buffer
                                )));
                        }

                        Session* new_session =
                            new Session(Session::JOINER, user_state, this, name, &np1sec_ephemeral_crypto, participants);
                        if (new_session->get_state() != Session::DEAD) {
                            // we need to get rid of old session if it is dead
                            // till we get a reviving mechanisim
                            if (session && session->get_state() == Session::DEAD) {
                                delete session;
                                session = 0;
                                session_universe.erase(session_id);
                            }
                            session_universe[session_id] = new_session;

                            new_session->state_handler(sender_nickname, session_message);
                        }
                    } catch (std::exception& e) {
                        logger.warn(e.what(), __FUNCTION__, user_state->myself->nickname);
                    }
                } else if (message.type == Message::SESSION_CONFIRMATION) {
                    // this is bad news we haven't been confirmed and we received a
                    // confirmation for another sid. so it means another session is being
                    // confirmed. If we haven't sent any confirmation, then we should die
                    // if we have sent a confirmation then what? still we die
                    // these are going to die by themselves
                    for (auto& cur_session : session_universe)
                        if (cur_session.second->get_state() != Session::DEAD &&
                            cur_session.second->nobody_confirmed()) {
                            logger.debug("somebody else is confirming session, need to rejoin", __FUNCTION__,
                                         user_state->myself->nickname);
                            cur_session.second->commit_suicide(); // we know the action is either death or nothing in
                                                                  // both case we don't need to do anything
                        }

                } // otherwise that message doesn't concern us (the entrance for setting up session id is
                // PARTICIPANTS_INFO
            }
        } else if (user_in_room_state == CURRENT_USER) {
            logger.debug("in CURRENT_USER state", __FUNCTION__, user_state->myself->nickname);
            // if we are current user we must have active_session
            logger.assert_or_die(active_session.get() &&
                                    session_universe.find(active_session.get_as_stringbuff()) != session_universe.end(),
                                "CURRENT_USER without active session! something doesn't make sense");

            if (session) {
                try {
                    action_to_take = session->state_handler(sender_nickname, session_message);
                } catch (std::exception& e) {
                    logger.error(e.what(), __FUNCTION__, user_state->myself->nickname);
                }
            } else if (message.type == Message::PARTICIPANTS_INFO &&
                       session_universe[active_session.get_as_stringbuff()]->get_state() != Session::LEAVE_REQUESTED)
            {
                SignedSessionMessage signed_message = SignedSessionMessage::decode(session_message);
                ParticipantsInfoMessage participants_info = ParticipantsInfoMessage::decode(signed_message);

                // We just joined, and then missed a new user's join request.
                Session *next_in_activation = session_universe[next_in_activation_line.get_as_stringbuff()];
                ParticipantMap current_participants = next_in_activation->future_participants();

                // Check the message signature.
                if (current_participants.find(sender_nickname) == current_participants.end()) {
                    logger.warn("sender not part of participant");
                } else if (!signed_message.verify(current_participants[sender_nickname].ephemeral_key)) {
                    logger.warn("failed to verify signature of PARTICIPANT_INFO message.");
                } else {
                    // Create a session for the participants in the message.
                    ParticipantMap next_participants;
                    for (size_t i = 0; i < participants_info.participants.size(); i++) {
                        next_participants.insert(std::pair<std::string, Participant>(participants_info.participants[i].nickname, Participant(
                            participants_info.participants[i].nickname,
                            participants_info.participants[i].long_term_public_key.buffer,
                            participants_info.participants[i].ephemeral_public_key.buffer
                        )));
                    }

                    if (next_participants.find(myself.nickname) == next_participants.end()) {
                        logger.warn("rejecting participant info message which myself am not part of");
                    } else {
                        // Authenticate participants that did not change keys.
                        for (auto participant : next_participants) {
                            if (current_participants.find(participant.second.id.nickname) != current_participants.end()) {
                                participant.second.authenticated =
                                    !compare_hash(current_participants[participant.second.id.nickname].raw_ephemeral_key,
                                                participant.second.raw_ephemeral_key);
                            } else {
                                participant.second.authenticated = false;
                            }
                        }

                        action_to_take.action_type = RoomAction::NEW_SESSION;
                        action_to_take.bred_session = new Session(Session::ACCEPTOR, user_state, this, name,
                            &next_in_activation->future_cryptic, next_participants, current_participants);

                        action_to_take.bred_session->state_handler(sender_nickname, session_message);
                    }
                }
            }
        }
    }

    logger.debug("room state: " + std::to_string(user_in_room_state) + " requested action: " +
                        std::to_string(action_to_take.action_type),
                    __FUNCTION__, user_state->myself->nickname); // just for test to make sure we don't end up here

    // if the action resulted in new session we need to add it to session universe
    if (action_to_take.action_type == RoomAction::NEW_SESSION ||
        action_to_take.action_type == RoomAction::NEW_PRIORITY_SESSION)
    {
        // TODO:: we need to delete a dead session probably
        session_universe[action_to_take.bred_session->my_session_id().get_as_stringbuff()] = action_to_take.bred_session;
    }

    if (action_to_take.action_type == RoomAction::NEW_PRIORITY_SESSION ||
        action_to_take.action_type == RoomAction::PRESUME_HEIR)
    {
        stale_in_limbo_sessions_presume_heir(action_to_take.bred_session->session_id);
    }

    // Now we check if the resulting action resulted in new confirmed session
    // we have to activate that session:
    // 1. first we should have the session in our universe.
    // 2. The session should have different session_id than
    //   the currently active one

    if (session) {
        if (!(session->session_id == active_session)) {
            if (session->get_state() == Session::IN_SESSION) {
                user_state->ops->join(name, session->peers, user_state->ops->bare_sender_data);
                activate_session(session->session_id);
            }
        }
    }
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
void Room::activate_session(SessionId newly_activated_session)
{
    SessionId dying_session = active_session;
    if (dying_session.get()) {
        logger.assert_or_die(newly_activated_session == next_in_activation_line,
                             "some illigitimate session got activated", __FUNCTION__);

        refresh_stale_in_limbo_sessions(newly_activated_session);
        // killing the active session after refreshing other sessions
        // will keep in the universe stash till next round of session move
        // to be earased. this help us to decrypt any message on the way
        session_universe[active_session.get_as_stringbuff()]->commit_suicide();
    } else {
        user_in_room_state = CURRENT_USER; // in case it is our first session
        // TODO: we probably need to kill all other sessions in limbo.
        // considering max-one-new-participant-at-the-time prinicipal

        // I think when a session is freshly activated it should actually be also
        // the session for the next join/leave, we have already assert this in
        // current_user case but for joining user we enforce it
        next_in_activation_line = newly_activated_session;
    }

    active_session = newly_activated_session;
}

/**
 * Mark in-limbo sessions which are not valid any more as stale so
 * subsequently one can make a fresh session out of each
 * mark them stale prevent them from replying to confimation etc and
 * misleading joining participants in moving forward
 */
void Room::stale_in_limbo_sessions_presume_heir(SessionId new_successor)
{
    logger.debug("changing the next session in activation line", __FUNCTION__, user_state->myself->nickname);
    // make new parent the one breed new sessions from now on
    next_in_activation_line = new_successor;

    for (SessionMap::iterator session_it = session_universe.begin(); session_it != session_universe.end();
         session_it++) {
        if ((session_it->second->get_state() != Session::DEAD) &&
            (session_it->second->get_state() != Session::IN_SESSION) &&
            (!(session_it->second->session_id == new_successor))) {
            session_it->second->stale_me();
        }
    }
}

/**
 *  When a new sesison generates key we need to update all session in limbo
 *  (kill them and generate new one for each) which ad here to this generated
 *  key session.
 * if somebody leaves, as soon as they live you need to update them cause
 * they are useless and the leaving person aren't going to confirmed any of them
 */
void Room::refresh_stale_in_limbo_sessions(SessionId new_parent_session_id)
{
    auto new_parent_session = session_universe.find(new_parent_session_id.get_as_stringbuff());
    // make sure the new parent actually exists
    logger.assert_or_die(new_parent_session != session_universe.end(),
                         "new parental session doesn't exists in the session universe", __FUNCTION__,
                         user_state->myself->nickname);
    logger.assert_or_die(new_parent_session->second->get_state() != Session::DEAD,
                         "can't breed out of a dead parent", __FUNCTION__, user_state->myself->nickname);

    SessionMap refreshed_sessions;
    for (SessionMap::iterator session_it = session_universe.begin(); session_it != session_universe.end();
         /*session_it++ we do it in the for case by case (due to erasing)*/) {
        // first we need to check if such a session in limbo currently exists
        // if it exists, that mean the joining user has already started the
        // negotiotion with the sesssion and there is no need to update the
        // session

        // in order to accomplish this task the easiest (but not most efficient
        // avernue is to generate the session, and if the sid is already in the
        // list just delete it. Beside memory allocation/dellocation it is not
        // clear if anything more is wasted.

        // this is *not* true, sessions actually sends auth_token and key shares
        // as a part of their creation. So to avoid side effect we compute the prospective
        // session id first

        // update: in favor of simplicity we are having a nonbroadcasting creation
        // so we can create and kill sessions with not so much problem
        if ((session_it->second->get_state() != Session::DEAD) &&
            (session_it->second->get_state() != Session::IN_SESSION) &&
            (session_it->second->session_id.get_as_stringbuff() !=
             new_parent_session_id
                 .get_as_stringbuff())) { // basically only the stale sessions, we can make that explicit
            logger.debug("refreshing " + logger.state_to_text[session_it->second->get_state()] + " session with: " +
                             participants_to_string(session_it->second->participants) + " as new active session has: " +
                             participants_to_string(new_parent_session->second->future_participants()),
                         __FUNCTION__, user_state->myself->nickname);

            session_it->second->commit_suicide();
            // Session *born_session = nullptr;
            ParticipantMap new_participant_list =
                session_it->second->delta_plist() + new_parent_session->second->future_participants();

            logger.debug("creating new session in limbo with participants: " +
                             participants_to_string(new_participant_list),
                         __FUNCTION__, user_state->myself->nickname);
            //*born_session  = session_it->second + session_universe[active_session.get_as_stringbuff()];
            // check if the session already exists
            SessionId to_be_born_session_id(new_participant_list);

            // if (session_universe.find(to_be_born_session_id.get_as_stringbuff()) == session_universe.end()) {
            try {
                // XXX/redwire
                // This is an awfully fishy use of `new`!!!
                refreshed_sessions.insert(std::pair<std::string, Session*>(
                    to_be_born_session_id.get_as_stringbuff(),
                    new Session(Session::ACCEPTOR, user_state, this, name,
                                      &new_parent_session->second->future_cryptic, new_participant_list,
                                      new_parent_session->second->future_participants())));
            } catch (std::exception& e) {
                logger.error(e.what());
            }
            session_it++;

            //}
        } else if (session_it->second->get_state() == Session::DEAD) { // anything that was dead before
            SessionMap::iterator to_erase =
                session_it; // TODO: is it the best way? we still not sure what to do with dead session
            session_it++;
            delete to_erase->second;
            session_universe.erase(to_erase);
        } else {
            session_it++;
        }
    }

    // now merge the refreshed sessions
    session_universe.insert(refreshed_sessions.begin(), refreshed_sessions.end());
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
void Room::send_user_message(std::string plain_message)
{
    if (active_session.get()) {
        session_universe[active_session.get_as_stringbuff()]->send(plain_message, InSessionMessage::USER_MESSAGE);
    } else {
        logger.error("trying to send message to a room " + name + " with no active session", __FUNCTION__,
                     user_state->myself->nickname);
        throw InvalidRoomException();
        // just for test to detect if something gone wrong
        // you can't send message now
        // TODO: maybe We should queue the messages and send them
        // when the session is established
    }
}

/**
 * Just sends a message for closing the transcript consistency
 * this also initiate the new session creation for other users
 */
void Room::leave()
{
    if (user_in_room_state == CURRENT_USER) {
        if (active_session.get()) {
            session_universe[active_session.get_as_stringbuff()]->leave(); // send leave and start leave timer
        }
        // else do nothing basically TODO::somebody should throw out the room though
    } else {
        // if you want to leave the room while joining.
        // if you have confirmed your session or not. However, as long as
        // the session hasn't been started then we don't need to check for
        // consistency. In any case we can just let it shrink
        logger.debug("nothing to do; leaving from a room we haven't joined");
    }
}

/**
 * called by user state when somebody else joins the
 * the room to keep track of the room size
 */
void Room::increment_size()
{
    room_size++;
    logger.debug("currently " + std::to_string(room_size) + " partcipants in the room", __FUNCTION__,
                 user_state->myself->nickname);
}

void Room::shrink(std::string leaving_nick)
{
    // room_size--;
    logger.debug("currently " + std::to_string(room_size) + " partcipants in the room", __FUNCTION__,
                 user_state->myself->nickname);
    if (user_in_room_state == JOINING) {
        logger.debug("somebody left, before we can join, starting from the begining", __FUNCTION__);
        try_rejoin(); // it helps because although the active session
        // of current occupants still contatins the leaver, the new
        // session will be born without zombies

    } else if (user_in_room_state == CURRENT_USER) {
        // we need to detect if we have already generated the shrunk
        // session or not.
        // first we get the plist of active session, if the leaving use
        logger.assert_or_die(active_session.get(), "shrinking while we have no active sessions");
        auto active_session_element = session_universe.find(active_session.get_as_stringbuff());
        logger.assert_or_die(active_session_element != session_universe.end(),
                             "Internal error: the active session is not in session universe.");

        Session* active_np1sec_session = active_session_element->second;

        // if (active_np1sec_session.my_state != Session::FAREWELLED) {
        // alternatively we can just check the state of active_session and if
        // it is farewelled then we don't need to worry about generating the
        // shrank session

        // this is not true anymore as many participants can request leave
        // from current session. as the result new session will be generated
        // cumulatively for participants who are leaving current session
        // until the one of the session is confirmed. therefore many farewell
        // can occure in one session.

        // because the session are staying in the session universe even after
        // they die so their existenec doesn't mean we have taken any action we
        // avoid making a new session, if the session is not made we will make
        // the new session  so not to duplicate the re-share message.
        // the reshare message has the same session id so the participants
        // handle it to the previously made session. the shares are the same.
        // Either the session is waiting for more share which result in
        // replacing the same share or is
        // waiting for confirmation and so it ignores the share message.

        // The best practice is to check the zombie list of the session,
        // if the participant is already in zombie list, we already have
        // made a session without them

        // We basically avoid sending an extra message which is not part of the protocol
        // but it is the implementation particularity, and duplicating such message whinch doesn't
        // violate the
        // protocol. (you might want to send the same message 10 times to increase
        // reliability and the protocol shouldn't choke on that.

        // Now consider the situation that pn announce intention to leave at the same
        // then last person forward secrecy contribution is matured. the current
        // session should stop the share renewal, cause the state is farewelled.
        //(normally the renew session should never be confirmed. because the leaving
        //(user haven't confirmed and move cause it sends its leaving message
        // to current session, as such it is important that the leaving user,
        // doesn't confirm a session after intention to leave, if he does though,
        // we'll recover through immature leave procedure.

        // It is also important to note as soon as we have new session, all session
        // in limbo will die and give birth to new session compatible with current
        // plist

        // so we try to shrink it anyway, if the user is already zombied
        // we do nothing.
        try {
            auto action_to_take = active_np1sec_session->shrink(leaving_nick);
            if (action_to_take.action_type == RoomAction::NEW_PRIORITY_SESSION) {
                auto old_shrank_session =
                    session_universe.find(action_to_take.bred_session->my_session_id().get_as_stringbuff());
                if (old_shrank_session != session_universe.end()) {
                    // if (old_shrank_session->second.my_state = np1sec::DEAD) { //should we check and erease only if
                    // DEAD?
                    old_shrank_session->second->commit_suicide();
                    delete old_shrank_session->second;
                    session_universe.erase(old_shrank_session->first);
                }
                session_universe.insert(std::pair<std::string, Session*>(
                    action_to_take.bred_session->my_session_id().get_as_stringbuff(), action_to_take.bred_session));
                stale_in_limbo_sessions_presume_heir(action_to_take.bred_session->my_session_id());
            } else {
                // Already FAREWELLED: TODO you should check the zombie list actually
                logger.assert_or_die(action_to_take.action_type == RoomAction::NO_ACTION,
                                     "shrink should result in priority session or nothing"); // sanity check
                logger.debug("no need to shrink. Already farewelled.");
                // otherwise we already have made the
                // shrank session don't worry about it
            }
        } catch (std::exception& e) {
            logger.error("failed to shrink the session", __FUNCTION__, user_state->myself->nickname);
            logger.error(e.what(), __FUNCTION__, user_state->myself->nickname);
        }

        // active session
        // else do nothing basically TODO::somebody should throw out the room though
        // else {
        //  logger.warn("room contains no active sesssion");
    } // not current user, do nothing
}

void Room::insert_session(Session* new_session)
{
    logger.assert_or_die(new_session->get_state() != Session::DEAD, "trying to adding a dead session?!",
                         __FUNCTION__, user_state->myself->nickname);

    auto old_session = session_universe.find(new_session->my_session_id().get_as_stringbuff());
    if (old_session != session_universe.end()) {
        if (old_session->second->get_state() != Session::DEAD) {
            logger.warn("trying to erase a live session? killing the session...", __FUNCTION__,
                        user_state->myself->nickname); // we need to check and commit suicide in case it is alive
            old_session->second->commit_suicide();
            delete old_session->second;
            session_universe.erase(old_session->first);
        }
    }

    session_universe.emplace(
        std::pair<std::string, Session*>(new_session->my_session_id().get_as_stringbuff(), new_session));
}

void Room::send(const Message& message)
{
    user_state->ops->send_bare(name, message.encode(), user_state->ops->bare_sender_data);
}

Room::~Room()
{
    for (auto& cur_session : session_universe) {
        cur_session.second->commit_suicide();
        delete cur_session.second;
    }
}

} // namespace np1sec
