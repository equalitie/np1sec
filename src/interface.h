/**
 * (n+1)Sec Multiparty Off-the-Record Messaging library
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
#ifndef SRC_INTERFACE_H_
#define SRC_INTERFACE_H_
/**
 * This file should be included by the client to use develop the interface 
 * between np1sec and the client.
 *
 * See test/chat_mocker_np1sec_plugin.h/.cc  example
 */

#ifndef SRC_INTERFACE_H_
#define SRC_INTERFACE_H_

#include <string>

/**
 * This sturct is used by the client to send the list of participant in
 * the room. consequently np1sec will try to authenticate the participant 
 * and establish a group session
 *
 */
struct UnauthenticatedParticipant {
  std::string participants;
  std::string long_term_pub_key_hex;  // This should be in some convienient Hex
  // Format
};

/**
 * Calls from np1sec to the application.
 */
struct np1secAppOps {
  // Data that is passed to send_bare
  void* bare_sender_data = NULL;
  /**
   * It is called by np1sec whenever the protocol needs to send meta data
   * messages (key exchange, etc) which are not initiated by a message from
   * the user.
   *  
   * @param data is member variable bare_sender_data which is passed to the 
   *             function in case any auxilary data is needed
   *
   * 
   */
  void (*send_bare)(std::string room_name,
                    std::string sender_nickname,
                    std::string message,
                    void* data);

  // TODO(vmon): Why do we need to join a room?
  // We can call back when join or leave is completed but
  // then also we need a call back when other people
  // join the room or leave that's why we have room
  // action as the return of the receive handlere
  /** 
   * Asks the app to join a room or a coversation 
   */
  // void (*join)(std::string room_name);

  /** 
   * Asks the app to leave a room or a coversation 
   */
  // void (*leave)(std::string room_name);
};

#endif  // SRC_INTERFACE_H_
