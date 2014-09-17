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

#include <string>
#include <map>


#ifndef SRC_USERSTATE_H_
#define SRC_USERSTATE_H_

class RoomAction {
 public:
  enum ActionType {
    NO_ACTION,
    JOIN,
    LEAVE,
    NEW_MESSAGE
  }

  std::string acting_user;  // The user which joined, left or sent a message.
  std::string new_message;
};

/**
 * Manages a user with long term identity for participating in a multiparty
 * chat sessions. It keeps track of sessions that user is participating in.
 */
class MpotrlUserState {
 protected:
  PrivateKey *long_term_private_key;
  std::map<Session> user_session mpotr_sessions;

 public:
  // Constructor
  MpotrlUserState();

  /**
     The client need to call this function when the user is joining a room.

     @param room_name the chat room name
     @param user_in_room_id the id that user is using to join this room, this is similar to alias. 

     @return true in case of success (does not mean successful join) and false in case of failure. 
     client need to inform server of leaving the room in case of
     failure 
   */
  bool join_room(std::string room_name, std:string new_user_id);

  /**
     the client need to call this function when a user join the
     chatroom. 

     @param room_name the chat room name
     @param new_user_id is the id that the new user is using
            in the room.
     
     @return true in case initiating the join was successful
             . This does not mean that the successful join
             false if process fails
   */
  bool accept_new_user(std::string room_name, std::string new_user_id);

  /**
     When the user uses the client interface to send a message
     the client need to call this function to send the message

     @param room_name the chat room name
     @param plain_message unencrypted message needed to be send
     securely

     @return true in case of success, false in case of failure
  */
  bool send(std::string room_name, std::string plain_message);

  /**
     The client need to call this function whenever a message
     is received. This function uses the content of the message
     and the status of the room to interpret the message
     
     @param room_name the chat room name
     @param mpotr_message the message needed to be sent

     @return a RoomAction object informing the client how
     to update the interface (add, remove user or display a
     message
   */
  RoomAction receive(std::string room_name, std::string mpotr_message);

  // The client informs the user state about leaving the room by calling this
  // function.
  void leave_room();

  // Destructor
  ~MpotrlUserState();
};

#endif  // SRC_USERSTATE_H_
