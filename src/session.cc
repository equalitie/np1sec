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
#include <time.h>
#include <stdlib.h>

void MessageDigest::update(std::string new_message) {
  return;
}

uint32_t MessageDigest::compute_message_id(std::string cur_message) {
  return 0;
}

bool np1secSession::send_bare(np1secBareMessage message) {
  return true;
}

np1secSession::np1secSession() {
  throw std::invalid_argument("Default constructor should not be used.");
}

np1secSession::np1secSession(std::string new_room_name, std::string user_id) :
  _room_name(new_room_name), _my_id(user_id) {}

bool np1secSession::join(std::vector<std::string> room_members) {
  for (std::vector<std::string>::iterator it = room_members.begin();
       it != room_members.end(); ++it) {
    printf("member: %s\n", it->c_str());
  }
  return true;
}

bool np1secSession::accept(std::string new_participant_id) {
  return true;
}

bool np1secSession::farewell(std::string leaver_id) {
  return true;
}

std::string np1secSession::send(np1secMessage message) {
  unsigned char *buffer = NULL;
  std::string signature = NULL;
  std::string encrypted_content = NULL;
  std::string combined_content = NULL;
  gcry_randomize(buffer, 32, GCRY_STRONG_RANDOM);

  HashBlock hb;
  // Add random noise to message to ensure hashing/signing is unique
  // for similar messages
  message.user_message.append(":");
  message.user_message.append(reinterpret_cast<const char*>(buffer));
  gcry_free(buffer);

  signature = cryptic.Sign(message.user_message);
  encrypted_content = cryptic.Encrypt(message.user_message);

  combined_content = encrypted_content;
  combined_content.append(" ");
  combined_content.append(signature);

  // Hash(message.user_message, sizeof(message.user_message), hb, true);

  return otrl_base64_otr_encode((unsigned char*)combined_content.c_str(),
                                combined_content.size());
}

np1secMessage np1secSession::receive(std::string raw_message) {
  std::string decoded_content;
  std::string signature, message_content, decrypted_message;
  np1secMessage received_message;

  otrl_base64_otr_decode(raw_message.c_str(),
                         (unsigned char**)decoded_content.c_str(),
                         reinterpret_cast<size_t*>(raw_message.size()));

  // split decoded content into encrypted message and signature
  std::stringstream ss(decoded_content);
  std::istream_iterator<std::string> begin(ss);
  std::istream_iterator<std::string> end;
  std::vector<std::string> vstrings(begin, end);

  if (vstrings.size() != 2) {
    std::printf("mpSeSession: failed to retrieve valid content and signature");
    return received_message;
  }

  message_content = std::string(vstrings[0]);
  signature = std::string(vstrings[1]);

  if (cryptic.Verify(message_content, signature)) {
    decrypted_message = cryptic.Decrypt(message_content);
  }

  received_message = {USER_MESSAGE, decrypted_message};
  return received_message;
}

np1secSession::~np1secSession() {
  return;
}
