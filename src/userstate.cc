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

using namespace std;

np1secUserState::np1secUserState(std::string name, np1secAppOps *ops,
                                 uint8_t* key_pair)
  : ops(ops),
    myself(nullptr)
{
  if (key_pair) {
    long_term_key_pair.set_key_pair(key_pair);
    //we also populate our id key to send it to other
    //during join.
    myself = new ParticipantId(name, Cryptic::public_key_to_stringbuff(long_term_key_pair.get_public_key()));
    
    //if the client doesn't initiate the public
    //key now it needs to call init sometimes before
    //join or join fails due to lack of crypto material
  } else {
    myself = new ParticipantId(name, "");
  }
    
}

np1secUserState::~np1secUserState() {
  delete myself;

  //TODO:Maybe for security reason we have
  //to turn long_term_key_pair into
  //pointer and fill-up mem before
  //deleting it
  //delete long_term_key_pair;
}

bool np1secUserState::init() {
  if (long_term_key_pair.is_initiated()) {
    return true;
  }
  long_term_key_pair.generate();
  myself->set_fingerprint(Cryptic::public_key_to_stringbuff(long_term_key_pair.get_public_key()));
  return true;
}

bool np1secUserState::join_room(std::string room_name,
                                std::vector<std::string> participants_in_the_room) {
  //we can't join without id key
  if (!long_term_key_pair.is_initiated())
    throw np1secInsufficientCredentialException();
  
  //we join the room, the room make a join session

  //if the room is not made, we make it.
  if (chatrooms.find(room_name) == chatrooms.end()) {
    //room creation triger joining
    chatrooms.insert(pair<string, np1secRoom>(room_name, np1secRoom(room_name, this, participants_in_the_room)));
  } else {
    //we asks the room to re-join.
    //it is not clear if it is a good idea
    //we need to have a better way in retrying
    //join 
    //if (!chatrooms[room_name].join()) {
      //TODO:garbage collector for the room?
      return false;
      //}
  }

  return true;
  
}

/**
   This is the main message handler of the whole protocol:

   The most important thing that user state message handler
   does is to 
       - Process the unencrypted part of the message.
       - decide which room should handle the message using the room name
 */
void np1secUserState::receive_handler(std::string room_name,
                                      std::string sender_nickname,
                                      std::string received_message,
                                      uint32_t message_id) {
  np1secMessage received(received_message, nullptr, this, room_name); //so no decryption key here
  received.sender_id = sender_nickname;

  //if there is no room, it was a mistake to give us the message
  assert(chatrooms.find(room_name) != chatrooms.end());

  chatrooms[room_name].receive_handler(received);

}

bool np1secUserState::send_handler(std::string room_name,
                                   std::string plain_message) {
  assert(chatrooms.find(room_name) != chatrooms.end());    // uh oh 
  return chatrooms[room_name].send_user_message(plain_message);
  
}

#endif  // SRC_USERSTATE_CC_
