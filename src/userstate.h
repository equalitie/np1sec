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

#ifndef SRC_USERSTATE_H_
#define SRC_USERSTATE_H_

#include <string>
#include <map>

#include "src/common.h"
#include "src/crypt.h"
#include "src/interface.h"

class np1secUserState;

#include "src/room.h"
#include "src/session.h"

typedef std::map<std::string, np1secRoom> RoomMap;

/**
 * Manages a user with long term identity for participating in a multiparty
 * chat sessions. It keeps track of sessions that user is participating in.
 */
class np1secUserState {
 public:
  //TOOD: protoct these guys
  ParticipantId* myself;
  LongTermIDKey long_term_key_pair; //private and public key
  //np1secAsymmetricKey long_term_pub_key;
  RoomMap chatrooms;
  np1secAppOps *ops;

  /**
   * Constructor
   *
   * @param name: the user name which is going to be used as default nickname
   *              for the rooms
   * @param key_pair the binary blob which contains the long term identity key
   *                 pair for ED25519.
   */
  np1secUserState(std::string name, np1secAppOps *ops,
                  uint8_t* key_pair = nullptr);

  bool init();

  /**
   * access function for nick
   */
  std::string user_id()  {
    return myself->id_to_stringbuffer();
  }

  /**
   * access function for for long term id key
   */
  KeyPair user_id_key()
  {
    return long_term_key_pair.get_key_pair();
  }

  /**
   * The client need to call this function when the user is joining a room.
   *
   * @param room_name the chat room name
   *
   * @return true in case of success (does not mean successful join) and false
   *         in case of failure. client need to inform server of leaving the
   *         room in case of failure
   */
  //TODO it is not clear that return value is useful at all. drop it if it
  //has no use
  bool join_room(std::string room_name
                 , std::vector<std::string> participants_in_the_room
                 );

  //Depricate, join request is triggered through join message
  /* /\** */
  /*  * the client need to call this function when a user join the chatroom. */
  /*  * */
  /*  * @param room_name the chat room name */
  /*  * @param new_user_id is the id that the new user is using in the room. */
  /*  * */
  /*  * @return true in case initiating the join was successful. This does not */
  /*  *         mean that the successful join false if process fails */
  /*  *\/ */
  /* bool accept_new_user(std::string room_name, std::string new_user_id) */
  /* {return false; //place holder for now */
  /* } */

  /**
   * When the user uses the client interface to send a message the client need
   * to call this function to send the message
   *
   * @param room_name the chat room name
   * @param plain_message unencrypted message needed to be send securely
   *
   * @return true in case of success, false in case of failure
   */
  bool send_handler(std::string room_name, std::string plain_message);

  /**
   * The client need to call this function whenever a message is received. This
   * function uses the content of the message and the status of the room to
   * interpret the message
   *
   * @param room_name the chat room name
   * @param np1sec_message the message needed to be sent
   *
   * @return a RoomAction object informing the client how to update the
   *         interface (add, remove user or display a message
   */
  void receive_handler(std::string room_name,
                       std::string sender_nickname,
                       std::string np1sec_message,
                       uint32_t message_id = 0);

  /**
   * The client informs the user state about leaving the room by calling this
   * function.
   * 
   * @param room_name the chat room name to leave from
   */
  void leave_room(std::string room_name)
  {}

  /**
   * the client need to call this function when another user leave the chatroom.
   *
   * @param room_name the chat room name
   * @param leaving_user_id is the id that the leaving user is using in the room.
   *
   * @return true in case initiating the leave was successful. This does not
   *         mean that the successful leave false if process fails
   */
  bool shrink_on_leave(std::string room_name, std::string leaving_user_id)
  {}
  
  /**
   * Retrieve the session object associated with the given room name. To
   * allow sending and receiving of messages relative to that session
   *
   * @param room_name the chat room_name
   *
   * @return the current session if it exists.
   */
  np1secSession *retrieve_session(std::string room_name);

  ~np1secUserState();
};

#endif  // SRC_USERSTATE_H_
