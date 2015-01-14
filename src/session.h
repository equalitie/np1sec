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

#ifndef SRC_SESSION_H_
#define SRC_SESSION_H_

#include <string>
#include <vector>

#include <event2/event.h>

#include "src/common.h"
#include "src/participant.h"

class np1secSession;

// Defining essential types
typedef uint8_t np1secBareMessage[];


/**
 * This class is encapsulating all information and action, a user needs and
 * performs in a session.
 */
class np1secSession {
 protected:
  Cryptic cryptic;
  HashBlock hashed_id;

  np1secUserState *us;
  std::string room_name;
  std::string name;

  /**
   * Keeps the list of the live participants in the room and their current/new
   * keys/shares, last heartbeat, etc.
   */
  std::vector<Participant> peers;

  /**
   * Keeps the list of the updated participants in the room once the
   * join/accept or farewell finishes.
   */
  std::vector<Participant> peers_in_limbo;

  /**
    * Keeps a list of the ack timers for recently sent messages indexed by peers
    *
    */
  std::map<std::string, struct event> awaiting_ack;
	 
  /**
   * Keeps a list of timers for acks that need to be sent for messages received
   * the list is indexed by peer.
   */
  std::map<std::string, struct event> acks_to_send;

  time_t key_freshness_time_stamp;

  /*
   * Callback function to cause automatic sending of ack for 
   * received message
   *
   */
  void cb_send_ack(evutil_socket_t fd, short what, void *arg);

  /*
   * Callback function to cause automatic warning if ack not
   * received for previously sent message
   *
   */
  void cb_ack_not_received(evutil_socket_t fd, short what, void *arg);


 public:
  SessionID session_id;

  np1secSession();

  /**
   * Constructor, initiate by joining.
   */
  np1secSession(np1secUserState *us, std::string room_name, std::string name);

  bool join();

  /**
   * Should be called when someone new join the chatroom. This will modify the
   * session id.
   */
  bool accept(std::string new_participant_id);

  /**
   * This will be called when a user leaves a chatroom to update the key.
   */
  bool farewell(std::string leaver_id);

  /**
   * Generate acknowledgement timers for all other participants
   *
   */
  void start_ack_timers();

  /*
   * Start received message acknowledgement timer
   *
   */
  void start_receive_ack_timer(Participant sender);

  /**
   * End ack timer on for given acknowledgeing participants
   *
   */
  void stop_timer_receive(Participant acknowledger);

  /*
   * Stop ack to send timers when user sends new message before timer expires
   *
   */
  void stop_timer_send(); 
	
  /**
   * When a user wants to send a message to a session it needs to call its send
   * function.
   */
  bool send(std::string message);

  /**
   * When a message is received from a session the receive function needs to be
   * called to decrypt. It updates the session status and returns the decrypted
   * message to be shown, it might be null if the message was a meta message.
   */
  np1secMessage receive(std::string raw_message);

  /**
   * Destructor, session should be destroyed at leave.
   */
  ~np1secSession();
};

#endif  // SRC_SESSION_H_
