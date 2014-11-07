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

    @param key_pair the binary blob which contains the long term identiy key pair
                         for ED25519, defult null trigger new pair generation.
                         TODO: ignored for now
*/
mpSeQUserState::mpSeQUserState(std::string username, uint8_t* key_pair)
  : name(username), long_term_private_key() {
}

RoomAction mpSeQUserState::receive_handler(std::string room_name,
                                           std::string mpseq_message) {
}

/**
   When the user uses the client interface to send a message
   the client need to call this function to send the message

   @param room_name the chat room name
   @param plain_message unencrypted message needed to be send
          securely

   @return message to send, null in case of failure
*/
char* mpSeQUserState::send_handler(std::string room_name,
                                   std::string plain_message) {
}
