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

#include "src/userstate.h"

/** 
    Constructor
      
    @param username: the user name which is going to be used as default nickname for
    the rooms
*/
mpSeQUserState::mpSeQUserState(std::string username) :
  name(username), long_term_private_key() {}

// @param key_pair the binary blob which contains the long term identity key
//                 pair for ED25519, default null trigger new pair generation.
bool mpSeQUserState::init(uint8_t* key_pair) {
  // FIXME: key_pair !== nullptr
  return long_term_private_key.init();
}

bool mpSeQUserState::join_room(std::string room_name,
                               std::vector<std::string> room_members) {
  mpSeQSession new_session(room_name, this->name);
  return new_session.join(room_members);
}
/**
     The client need to call this function when the user is joining a room.

     @param room_name the chat room name
     @param user_in_room_id the id that user is using to join this room, this is similar to alias. 

     @return true in case of success (does not mean successful join) and false in case of failure. 
     client need to inform server of leaving the room in case of
     failure 
*/
bool mpSeQUserState::join_room(std::string room_name, std::string new_user_id){

  mpSeQSession new_session(room_name, new_user_id, true);
  
  mpseq_sessions.insert( new_session.session_id, new_session );
  sessions_in_a_room.insert(room_name, new_session.session_id);

  if(!new_session.join(room_name, new_user_id)){
    return false;
  }
  
  return true;
}

RoomAction mpSeQUserState::receive_handler(std::string room_name,
                                           std::string mpseq_message) {
  mpSeQSession cur_session = retrieve_session(room_name);
  mpSeQMessage received_message = cur_session.receive(mpseq_message);
  RoomAction room_action = { NULL, received_message.user_message };
  return room_action;

}

/**
   When the user uses the client interface to send a message
   the client need to call this function to send the message

   @param room_name the chat room name
   @param plain_message unencrypted message needed to be send
          securely

   @return message to send, null in case of failure
*/
std::string mpSeQUserState::send_handler(std::string room_name,
                                   std::string plain_message) {
  mpSeQSession cur_session = retrieve_session(room_name);
  mpSeQMessage message = { USER_MESSAGE, plain_message };
  std::string b64_content = NULL;
  b64_content = cur_session.send(message);

  return b64_content;
}
  /**
   * Retrieve the session object associated with the given room name. To
   * allow sending and receiving of messages relative to that session
   *
   * @param room_name the chat room_name
   *
   * @return the current session if it exists for the given room or create
   * a new session and return that.
   *
   */
mpSeQSession mpSeQUserState::retrieve_session(std::string room_name){

  if(sessions_in_a_room.find(room_name) != sessions_in_a_room.end() and 
          mpseq_sessions.find( sessions_in_a_room.find(room_name)->second ) != mpseq_sessions.end() 
          ){

    return mpseq_sessions[ sessions_in_a_room.find(room_name)->second];

  }else{  

    if(join_room(room_name, name)){

      return retrieve_session(room_name);

    }
  }

}
