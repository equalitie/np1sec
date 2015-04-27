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
/**
 * This file should be included by the client to use develop the interface 
 * between np1sec and the client.
 *
 * See test/chat_mocker_np1sec_plugin.h/.cc  example
 */

#ifndef SRC_INTERFACE_H_
#define SRC_INTERFACE_H_

#include <string>

#include "src/crypt.h"

/**
 * Calls from np1sec to the application.
 */
struct np1secAppOps {
  // Data that is passed to send_bare
  uint32_t c_heartbeating_interval;
  uint32_t c_inactive_ergo_non_sum_interval;
  uint32_t c_unresponsive_ergo_non_sum_interval;
  uint32_t c_ack_interval;
  uint32_t c_consistency_failure_interval;
  uint32_t c_send_receive_interval;

  np1secAppOps() {};
  
  np1secAppOps(uint32_t ACK_GRACE_INTERVAL , uint32_t REKEY_GRACE_INTERVAL,  uint32_t INTERACTION_GRACE_INTERVAL, uint32_t BROADCAST_LATENCY)
  : c_heartbeating_interval(REKEY_GRACE_INTERVAL / 2),
    c_inactive_ergo_non_sum_interval(REKEY_GRACE_INTERVAL + 2*(BROADCAST_LATENCY)),
    c_unresponsive_ergo_non_sum_interval(INTERACTION_GRACE_INTERVAL + 2*(BROADCAST_LATENCY)),
    c_ack_interval(ACK_GRACE_INTERVAL),
    c_consistency_failure_interval(ACK_GRACE_INTERVAL + 2*(BROADCAST_LATENCY)),
    c_send_receive_interval(INTERACTION_GRACE_INTERVAL + 2*(BROADCAST_LATENCY))

    
  {
  }
  
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
                    std::string message,
                    void* data);

  // TODO(vmon): Why do we need to join a room?
  // We can call back when join or leave is completed but
  // then also we need a call back when other people
  // join the room or leave that's why we have room
  // action as the return of the receive handlere

  //The problem is that some of the actions are
  //not message dependent like fail to ping for example.
  
  /** 
   * inform the app that someone (including the user themselves) 
   * join a room or a coversation left the room.
   */
  void (*join)(std::string room_name,
                std::string joiner_nickname,
               void* aux_data);

  /** 
   * inform the app that someone (including the user themself) left  
   a room or a coversation, for ui purpose
   */
   void (*leave)(std::string room_name,
         std::string joiner_nickname,
         void* aux_data);

  /**
   * Asks the app to display a message in the room
   */
  void (*display_message)(std::string room_name,
                          std::string sender_nick,
                          std::string message,
                          void* aux_data);


  /**
   * confirm the association of nickname and public key
   */
  void (*validate_long_term_key)(std::string nickname,
                          np1secPublicKey fingerprint,
                          void* aux_data);

  /**
   * it needs to set a timer which calls timer_callback function after 
   * interval
   * 
   * @return a handle to the timer as void* which can be sent to axe_timer
   *         to delete the timer
   */
  void* (*set_timer)(void (*timer_callback)(void* opdata), void* opdata, uint32_t interval);

  /**
   * should deactiave to_be_defused timer
   */
  void (*axe_timer)(void* to_be_defused_timer);

  
};

#endif  // SRC_INTERFACE_H_
