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

/** 
    Constructor
      
    @param username: the user name which is going to be used as default nickname for
    the rooms

    @param private_key the binary blob which contains the long term private key
                         for ED25519 
*/
mpSeQUserState::mpSeQUserState(std::string username, uint8_t* private_key)
: long_term_private_key(private_key), name(username)
{
    
};

RoomAction mpSeQUserState::receive_handler(std::string room_name, std::string mpotr_message)
{
  
};
