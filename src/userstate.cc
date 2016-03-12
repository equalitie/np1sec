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

#ifndef SRC_USERSTATE_CC_
#define SRC_USERSTATE_CC_

#include <string>

#include "src/interface.h"
#include "src/userstate.h"

namespace np1sec
{

/** The client only calls functions in UserState. As such, the client need to handle exception (or false return
   values) that is resulted from these calls. In most situation, handling simply means to inform the user about the
   failure.

    In principal, the client should be aware of all exception reported to the userstate.*/

/**
 *
 * Exceptions:
 *
 * If we are not able to make the UserState Object mostly because the
 * long term key has wrong format, the client need to know that the
 * creation of  the user state object had failed. However, as the
 * constructor is not able to return value, our only option is
 * to throw an exception.
 */
UserState::UserState(std::string name, AppOps* ops, uint8_t* key_pair) : myself(nullptr), ops(ops)
{
    if (key_pair) {
        logger.info("intitiating UserState with pre-generated key pair");
        long_term_key_pair.set_key_pair(key_pair);
        // we also populate our id key to send it to other
        // during join.
        try {
            myself = new ParticipantId(name, public_key_to_stringbuff(long_term_key_pair.get_public_key()));
        } catch (std::exception& e) {
            logger.error("failed to initiate user state with provided key " + (std::string)(e.what()));

            // we can't recover we need to rethrow
            throw;
        }

        // if the client doesn't initiate the public
        // key now it needs to call init sometimes before
        // join or join fails due to lack of crypto material
    } else {
        myself = new ParticipantId(name, "");
        logger.warn("no long term key is provided for particiant " + myself->nickname);
    }
}

UserState::~UserState()
{
    delete myself;
    // long_term_key_pair destructor takes care of zeroising
    // the memory
}

/**
 * Exceptions:
 *
 * If the generation of the long term key fails, mainly due to lack
 * of randomness, then the client need to be informed that we are not
 * able to connect to any room in this situation.
 */
bool UserState::init()
{
    if (long_term_key_pair.is_initiated()) {
        return true;
    }
    logger.info("generating long term key for participant " + myself->nickname);
    try {
        long_term_key_pair.generate();
        myself->set_fingerprint(public_key_to_stringbuff(long_term_key_pair.get_public_key()));
        return true;
    } catch (CryptoException& crypto_exception) {
        logger.error("failed to generate long term key for participant " + myself->nickname);
        return false;
    }
}

/**
 *
 *  Exceptions:
 *
 *  This function initiating the join process, even if it ends successful *  ly it doesn't mean that we have joined the
 * room as join is a multi
 *  round process.
 *
 *  The intiation can fails only if our crypto values have problem.
 *  or the network conditino makes sending the initiation message
 *  impossible. the inititation message only contains the long term
 *  and ephemeral public keys.
 *
 *  Another condition which can make the failure of join inititation
 *  is that if we are already has joined a session in this room.
 */
bool UserState::join_room(std::string room_name, uint32_t room_size)
{
    // we can't join without id key
    if (!long_term_key_pair.is_initiated()) {
        logger.error(myself->nickname + "doesn't have sufficient credential to join room" + room_name +
                     ". Long term id key has not been initiated for " + myself->nickname);
        throw InsufficientCredentialException();
    }

    // we join the room, the room make a join session

    // if the room is not made, we make it.
    if (chatrooms.find(room_name) == chatrooms.end()) {
        // room creation triger joining
        try {
            chatrooms.emplace(room_name, Room(room_name, this, room_size));
        } catch (std::exception& e) {
            logger.error(e.what(), __FUNCTION__, myself->nickname);
            logger.error("unable to join the room", __FUNCTION__, myself->nickname);
        }
    } else {
        // we asks the room to re-join.
        // it is not clear if it is a good idea
        // we need to have a better way in retrying
        // join
        // if (!chatrooms[room_name].join()) {
        // TODO:garbage collector for the room?
        try { // try rejoining
            chatrooms[room_name].try_rejoin();
        } catch (InvalidRoomException& e) {
            logger.warn("alreay in the room. need to leave the room before rejoining it.");
            return false;
        }
    }

    return true;
}

void UserState::increment_room_size(std::string room_name)
{
    // if the room is not made, we make it.
    if (chatrooms.find(room_name) != chatrooms.end()) {
        // room creation triger joining
        chatrooms[room_name].increment_size();
    }
}

/**
 * The client informs the user state about leaving the room by calling this
 * function.
 *
 * @param room_name the chat room name to leave from
 *
 * Exception: If the client asks us to leave a room that we haven't
 * join, then we have to inform the client about its mistake.
 */
void UserState::leave_room(std::string room_name)
{
    // if there is no room, it was a mistake to give us the message
    if (chatrooms.find(room_name) == chatrooms.end()) {
        logger.error("unable to leave from room " + room_name + ". user " + myself->nickname + " is not in the room",
                     __FUNCTION__, myself->nickname);
        throw InvalidRoomException();
    }

    chatrooms[room_name].leave();
}

/**
 * the client need to call this function when another user leave the chatroom.
 *
 * @param room_name the chat room name
 * @param leaving_user_id is the id that the leaving user is using in the room.
 *
 * Exception:
 * throw an exception if the user isn't in the room. no exception doesn't
 *         mean that the successful
 */
void UserState::shrink(std::string room_name, std::string leaving_user_id)
{
    // if there is no room, it was a mistake to give us the message
    if (chatrooms.find(room_name) == chatrooms.end()) {
        logger.error("unable to shrink room " + room_name + ". user " + myself->nickname + "is not in the room");
        throw InvalidRoomException();
    }

    // we really should start shrinking here. the other
    // session will take care of consistency
    logger.info(leaving_user_id + " is leaving " + room_name, __FUNCTION__, myself->nickname);
    logger.info(room_name + " shrinking", __FUNCTION__, myself->nickname);
    chatrooms[room_name].shrink(leaving_user_id);
}

/**
 *  This is the main message handler of the whole protocol:
 *
 *  The most important thing that user state message handler
 *  does is to
 *      - Process the unencrypted part of the message.
 *      - decide which room should handle the message using the room
 *        name
 *
 *  Exception:
 *  Failure of digesting a message, due to be encrypted by an
 *  unknown key or a manipulated message need to be reported
 *  to the client, to warn the user about it, but the client
 *  can't do much more about it.
 *
 */
void UserState::receive_handler(std::string room_name, std::string sender_nickname, std::string received_message,
                                      uint32_t message_id)
{
    logger.debug("receiving message...", __FUNCTION__, myself->nickname);
    try {
        Message received(received_message, nullptr); // so no decryption key here
        received.sender_nick = sender_nickname;
        // in case the transport is providing the message id (if it is zero means to
        // trust the global order
        received.message_id = message_id;

        // if there is no room, it was a mistake to give us the message
        logger.assert_or_die(chatrooms.find(room_name) != chatrooms.end(),
                             "np1sec can not receive messages from room " + room_name +
                                 " to which has not been informed to join");

        chatrooms[room_name].receive_handler(received);
    } catch (std::exception& e) { // any unhandled error till here, we just
        // ignore as bad message
        logger.error(e.what(), __FUNCTION__, myself->nickname);
        logger.warn("unable to handle received message from " + sender_nickname);
    }
}

/**
 * Exception:
 *
 * send can fails due to the fact that the client tries to send a
 * a message to a room that the user haven't joined (join processes)
 * has not ended successfully.
 *
 */
void UserState::send_handler(std::string room_name, std::string plain_message)
{
    logger.assert_or_die(chatrooms.find(room_name) != chatrooms.end(), "np1sec can not send messages to room " +
                                                                           room_name +
                                                                           " to which has not been informed to join");
    try {
        chatrooms[room_name].send_user_message(plain_message);
    } catch (std::exception& e) { // any unhandled error till here, we just
        // ignore as bad message
        logger.error(e.what(), __FUNCTION__, myself->nickname);
        logger.warn("unable to send  message to " + room_name, __FUNCTION__, myself->nickname);
    }
}

} // namespace np1sec

#endif // SRC_USERSTATE_CC_
