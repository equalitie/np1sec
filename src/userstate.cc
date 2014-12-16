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

#include "src/userstate.h"


np1secUserState::np1secUserState(std::string name, np1secAppOps *ops,
                                 uint8_t* key_pair) : name(name), ops(ops) {
  if (key_pair) {
    // FIXME: populate long_term_private_key from key_pair
  }
}

np1secUserState::~np1secUserState() {
  delete long_term_private_key;
}

bool np1secUserState::init() {
  if (long_term_private_key) {
    return true;
  }
  long_term_private_key = new LongTermIDKey();
  return long_term_private_key->init();
}

bool np1secUserState::join_room(std::string room_name) {
  np1secSession new_session(this, room_name, name);

  if (!new_session.join()) {
    return false;
  }

  // np1sec_sessions.insert({ new_session.session_id, new_session });
  // sessions_in_a_room.insert({ room_name, new_session.session_id });
  return true;
}

RoomAction np1secUserState::receive_handler(std::string room_name,
                                            std::string np1sec_message) {
  np1secSession cur_session = retrieve_session(room_name);
  np1secMessage received_message = cur_session.receive(np1sec_message);
  RoomAction room_action = { NULL, received_message.user_message };
  return room_action;
}

std::string np1secUserState::send_handler(std::string room_name,
                                          std::string plain_message) {
  np1secSession cur_session = retrieve_session(room_name);
  np1secMessage message = { USER_MESSAGE, plain_message };
  std::string b64_content = NULL;
  b64_content = cur_session.send(message);

  return b64_content;
}

np1secSession np1secUserState::retrieve_session(std::string room_name) {
  np1secSession cur_session;

  if (sessions_in_a_room.find(room_name) != sessions_in_a_room.end() &&
      np1sec_sessions.find(sessions_in_a_room.find(room_name)->second)
        != np1sec_sessions.end()
  ) {
    cur_session = np1sec_sessions[sessions_in_a_room.find(room_name)->second];
  } else {
    if (join_room(room_name)) {
      cur_session = retrieve_session(room_name);
    }
  }

  return cur_session;
}

#endif  // SRC_USERSTATE_CC_
