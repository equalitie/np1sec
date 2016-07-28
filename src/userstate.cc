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

#include <cassert>

#include "room.h"
#include "userstate.h"

namespace np1sec
{

UserState::UserState(std::string name, AppOps* ops /*, std::string private_key*/):
    nickname(name),
    long_term_private_key(PrivateKey::generate()),
    application(new AppOpsApplication(ops))
{
}

bool UserState::join_room(std::string room_name, uint32_t room_size)
{
    if (chatrooms.find(room_name) == chatrooms.end()) {
        try {
            chatrooms[room_name] = new Room(room_name, application, nickname, long_term_private_key, room_size);
        } catch (std::exception& e) {
            logger.error(e.what(), __FUNCTION__);
            logger.error("unable to join the room", __FUNCTION__);
        }
    } else {
        logger.warn("alreay in the room. need to leave the room before rejoining it.");
        return false;
    }

    return true;
}

void UserState::increment_room_size(std::string room_name)
{
    if (chatrooms.find(room_name) != chatrooms.end()) {
        chatrooms[room_name]->increment_size();
    }
}

void UserState::leave_room(std::string room_name)
{
    if (chatrooms.find(room_name) == chatrooms.end()) {
        logger.error("unable to leave from room " + room_name + ". user " + nickname + " is not in the room", __FUNCTION__);
        throw InvalidRoomException();
    }

    chatrooms[room_name]->leave();
}

void UserState::shrink(std::string room_name, std::string leaving_user_id)
{
    if (chatrooms.find(room_name) == chatrooms.end()) {
        logger.error("unable to shrink room " + room_name + ". user " + nickname + "is not in the room");
        throw InvalidRoomException();
    }

    logger.info(leaving_user_id + " is leaving " + room_name, __FUNCTION__);
    logger.info(room_name + " shrinking", __FUNCTION__);
    chatrooms[room_name]->shrink(leaving_user_id);
}
void UserState::receive_handler(std::string room_name, std::string sender_nickname, std::string received_message)
{
    logger.debug("receiving message...", __FUNCTION__);
    try {
        logger.assert_or_die(chatrooms.find(room_name) != chatrooms.end(),
                             "np1sec can not receive messages from room " + room_name +
                                 " to which has not been informed to join");

        chatrooms[room_name]->receive_handler(received_message, sender_nickname);
    } catch (std::exception& e) {
        logger.error(e.what(), __FUNCTION__);
        logger.warn("unable to handle received message from " + sender_nickname);
    }
}

void UserState::send_handler(std::string room_name, std::string plain_message)
{
    logger.assert_or_die(chatrooms.find(room_name) != chatrooms.end(), "np1sec can not send messages to room " +
                                                                           room_name +
                                                                           " to which has not been informed to join");
    try {
        chatrooms[room_name]->send_user_message(plain_message);
    } catch (std::exception& e) {
        logger.error(e.what(), __FUNCTION__);
        logger.warn("unable to send  message to " + room_name, __FUNCTION__);
    }
}

} // namespace np1sec
