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

bool mpSeQSession::send_bare(mpSeQBareMessage message) {
  return true;
}

mpSeQSession::mpSeQSession(std::string new_room_name, std::string user_id) :
  _room_name(new_room_name), _my_id(user_id), ed25519Key() {}

bool mpSeQSession::join(std::vector<std::string> room_members) {
  for (std::vector<std::string>::iterator it = room_members.begin();
       it != room_members.end(); ++it) {
    printf("member: %s\n", it->c_str());
  }
  return true;
}

bool mpSeQSession::accept(std::string new_participant_id) {
  return true;
}

bool mpSeQSession::farewell(std::string leaver_id) {
  return true;
}

std::string mpSeQSession::send(mpSeQMessage message) {
  unsigned char *buffer = NULL;
  std::string signature = NULL;
  std::string encrypted_content = NULL;
  std::string combined_content = NULL;
  gcry_randomize( buffer, 32, GCRY_STRONG_RANDOM );

  HashBlock hb;
  // Add random noise to message to ensure hashing/signing is unique
  // for similar messages
  message.user_message.append(":");
  message.user_message.append(reinterpret_cast<const char*>(buffer));
  gcry_free(buffer);
  
  signature = ed25519Key.Sign( message.user_message );
  encrypted_content = ed25519Key.Encrypt( message.user_message );

  combined_content = encrypted_content;
  combined_content.append(" ");
  combined_content.append(signature);

  //Hash(message.user_message, sizeof(message.user_message), hb, true);

  return Base64::Encode(combined_content.c_str());
}

mpSeQMessage mpSeQSession::receive(std::string raw_message) {
  std::string decoded_content;
  std::string signature, message_content, decrypted_message;
  mpSeQMessage received_message;

  decoded_content = Base64::Decode(raw_message.c_str(), raw_message.c_str()+raw_message.size());


  //split decoded content into encrypted message and signature
  std::stringstream ss(decoded_content);
  std::istream_iterator<std::string> begin(ss);
  std::istream_iterator<std::string> end;
  std::vector<std::string> vstrings(begin, end);
  if( vstrings.size() != 2){
    std::printf("mpSeSession: failed to retrieve valid content and signature");
    return received_message;
  }

  message_content = std::string(vstrings[0]);
  signature = std::string(vstrings[1]); 

  if( ed25519Key.Verify(message_content, signature) ){
    decrypted_message = ed25519Key.Decrypt(message_content);
  }

  received_message = {USER_MESSAGE, decrypted_message};

  return received_message;
}

mpSeQSession::~mpSeQSession() {
  return;
}
