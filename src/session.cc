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

#ifndef SRC_SESSION_CC_
#define SRC_SESSION_CC_

#include "src/session.h"
#include <stdlib.h>

void MessageDigest::update(std::string new_message) {
  UNUSED(new_message);
  return;
}

uint32_t MessageDigest::compute_message_id(std::string cur_message) {
  UNUSED(cur_message);
  return 0;
}

np1secSession::np1secSession() {
  throw std::invalid_argument("Default constructor should not be used.");
}

np1secSession::np1secSession(np1secUserState *us, std::string room_name,
                             std::string name) : us(us), room_name(room_name),
                                                 name(name) {}

bool np1secSession::join() {
  if (!cryptic.init()) {
    return false;
  }
  us->ops->send_bare(room_name, "testing 123");
  return true;
}

bool np1secSession::accept(std::string new_participant_id) {
  UNUSED(new_participant_id);
  return true;
}

bool np1secSession::farewell(std::string leaver_id) {
  UNUSED(leaver_id);
  return true;
}

void cb_ack_not_received(evutil_socket_t fd, short what, void *arg) {


}

void cb_send_ack(evutil_socket_t fd, short what, void *arg) {
  

}

void np1secSession::start_ack_timers() {
  struct event *timer_event;
  struct timeval ten_seconds = {10, 0};
  struct event_base *base = event_base_new();
	
  for (std::vector<Participant>::iterator it = peers.begin(); it != peers.end; ++it) {
    timer_event = event_new(base, -1, EV_TIMEOUT, cb_ack_not_received, NULL);
    awaiting_ack[it.id] = timer_event; 
    event_add(awaiting_ack[it.id], &ten_seconds);
  }

  event_base_dispatch(base);
}

void np1secSession::start_receive_ack_timer(std::string sender_id) {
  struct event *timer_event;
  struct timeval ten_seconds = {10, 0};
  struct event_base *base = event_base_new();
	
  timer_event = event_new(base, -1, EV_TIMEOUT, cb_ack_not_received, NULL);
  acks_to_send[sender_id] = time_event;
  event_add(awaiting_ack[sender_id], &ten_seconds);
  event_base_dispatch(base);
}

void np1secSession::stop_timer_send() {
	
  for (std::map<Particpant, struct event>::iterator it=acks_to_send.begin(); it!=acks_to_send.end(); ++it) {
    event_free(it->value);
    acks_to_send.erase(it);
  }
}

void np1secSession::stop_timer_receive(std::string acknowledger_id) {
  event_free(awaiting_ack[acknowledger_id]);
  awaiting_ack.erase(acknowledger_id);
}

bool np1secSession::send(std::string message) {
  unsigned char *buffer = NULL;
  gcry_randomize(buffer, 32, GCRY_STRONG_RANDOM);

  np1secMessage outbound(session_id, , USER_MESSAGE,
                         transcript_chain_hash, cryptic);

  // As we're sending a new message we are no longer required to ack
  // any received messages 
  stop_timer_send();

  // We create a set of times for all other peers for acks we expect for
  // our sent message
  start_ack_timers();

  us->ops->send_bare(room_name, outbound);
  return true;
}

np1secMessage np1secSession::receive(std::string raw_message) {
  std::string decoded_content;
  std::string signature, message_content, decrypted_message;
  np1secMessage received_message(raw_message);

  // Stop awaiting ack timer for the sender
  stop_timer_receive(received_message.sender_id);

  // Start an ack timer for us so we remember to say thank you
  // for the message
  start_receive_ack_timer(received_message.sender_id);

  return received_message;
}

np1secSession::~np1secSession() {
  return;
}

#endif  // SRC_SESSION_CC_
