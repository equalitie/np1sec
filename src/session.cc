// session.cc
//
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

#include "src/session.h"

void MessageDigest::update(std::string new_message) {
  return;
}

uint32_t MessageDigest::compute_message_id(std::string cur_message) {
  return 0;
}

bool mpSeQSession::send_bare(mpSeQBareMessage message) {
  return true;
}

mpSeQSession::mpSeQSession(std::string new_room_name, std::string user_id,
                           bool emptyroom) {
  return;
}

bool mpSeQSession::join(std::string new_room_name, std::string user_id,
                        std::string new_participant_id) {
  return true;
}

bool mpSeQSession::accept(std::string new_participant_id) {
  return true;
}

bool mpSeQSession::farewell(std::string leaver_id) {
  return true;
}

bool mpSeQSession::send(mpSeQMessage message) {
  HashBlock hb;

  Hash(message.user_message, sizeof(message.user_message), hb, true);

  return hb;
}

mpSeQMessage mpSeQSession::receive(std::string raw_message) {
  std::string decrypted_message = DecryptMessage(raw_message);
  mpSeQMessage ReceivedMessage = DecryptMessage(raw_message);
  return ReceivedMessage;
}

mpSeQSession::~mpSeQSession() {
  return;
}
