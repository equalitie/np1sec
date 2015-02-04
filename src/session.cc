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

#include <time.h>
#include <stdlib.h>

#include "src/session.h"

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

/**
 * This constructor should be only called when the session is generated
 * to join. That's why all participant are not authenticated.
 */
np1secSession::np1secSession(np1secUserState *us, std::string room_name,
                             std::string name, std::vector<UnauthenticatedParticipant>participants_in_the_room) : us(us), room_name(room_name), participants_in_the_room(participants_in_the_room)
{
  myself.id(name);
}

/**
 * Received the pre-processed message and based on the state
 * of the session decides what is the appropriate action
 *
 * @param receive_message pre-processed received message handed in by receive function
 *
 * @return true if state has been change 
 */
bool np1secSession::state_handler(np1secMessage receivd_message)
{
  switch(my_state) {
    case np1session::NONE:
      //This probably shouldn't happen, if a session has
      //no state state_handler shouldn't be called.
      //The receive_handler of the user_state should call
      //approperiate inition of a session of session less
      //message
      throw  np1secSessionStateException;
        
    case np1session::JOIN_REQUESTED, //The thread has requested to join by sending ephemeral key
      //Excepting to receive list of current participant
      
    REPLIED_TO_NEW_JOIN, //The thread has received a join from a participant replied by participant list
    GROUP_KEY_GENERATED, //The thread has computed the session key and has sent the conformation
    IN_SESSION, //Key has been confirmed
    UPDATED_KEY, //all new shares has been received and new key has been generated, no more send possible
    LEAVE_REQUESTED, //Leave requested by the thread, waiting for final transcirpt consitancy check
    FAREWELLED, //LEAVE is received from another participant and a meta message for transcript consistancy and new shares has been sent
    DEAD //Won't accept receive or sent messages, possibly throw up

    
  }
  
}

bool np1secSession::join(long_term_pub_key, long_term_prv_key) {

  //We need to generate our ephemerals anyways
  if (!cryptic.init()) {
    return false;
  }
  myself.ephemeral_key = cryptic.ephemeral_pub_key;

  //we add ourselves to the (authenticated) participant list
  peer.push_back(myself);

  //if nobody else is in the room have nothing to do more than
  //just computing the session_id
  if (participants_in_the_room.size()== 1) {
    this->compute_session_id();
         
  }
  else {
    
  }
  
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

bool np1secSession::send(np1secMessage message) {
  gcry_error_t err;
  unsigned char *buffer = NULL;
  std::string signature = NULL;
  std::string encrypted_content = NULL;
  std::string combined_content = NULL;
  gcry_randomize(buffer, 32, GCRY_STRONG_RANDOM);
  unsigned char *sigbuf = NULL;
  size_t siglen;
  char *msg = NULL;

  // Add random noise to message to ensure hashing/signing is unique
  // for similar messages
  message.user_message.append(":");
  message.user_message.append(reinterpret_cast<const char*>(buffer));
  gcry_free(buffer);

  if ( cryptic.Sign(&sigbuf, &siglen,
        message.user_message) == gcry_error(GPG_ERR_NO_ERROR)) {
    encrypted_content = cryptic.Encrypt(message.user_message);
  }

  combined_content = encrypted_content;
  combined_content.append(" ");
  combined_content.append(signature);


  msg = otrl_base64_otr_encode((unsigned char*)combined_content.c_str(),
                               combined_content.size());
  us->ops->send_bare(room_name, msg);
  return true;
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

  if ( cryptic.Verify(message_content, (unsigned char*)signature.c_str())
       == gcry_error(GPG_ERR_NO_ERROR)) {
    decrypted_message = cryptic.Decrypt(message_content);
  }

  received_message = {USER_MESSAGE, decrypted_message};
  return received_message;
}

np1secSession::~np1secSession() {
  return;
}
