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


#ifndef SRC_MESSAGE_CC_
#define SRC_MESSAGE_CC_
#include "src/userstate.h"
#include "src/message.h"
#include "src/exceptions.h"

np1secMessage::np1secMessage(SessionID session_id,
                            std::string sender_id,
                            std::string user_message,
                            np1secMessageType message_type,
                            HashBlock transcript_chain_hash,
                            np1secLoadFlag meta_load_flag,
                            std::string meta_load,
                            std::vector<std::string> pstates,
                            Cryptic* cryptic, 
                            np1secUserState* us,
                             std::string room_name)
: session_id(session_id),
  sender_id(sender_id),
  user_message(user_message),
  message_type(message_type),
  transcript_chain_hash(transcript_chain_hash),
  meta_load_flag(meta_load_flag),
  meta_load(meta_load),
  cryptic(cryptic),
  pstates(pstates),
  us(us),
  room_name(room_name)
  
{
  if (message_type == PURE_META_MESSAGE) {
    this->meta_only = 1;
  }
}

np1secMessage::np1secMessage(SessionID session_id,
                             np1secMessageType message_type,
                             std::string session_view,
                             std::string key_confirmation,
                             std::string session_key_confirmation,
                             std::string joiner_info,
                             std::string z_sender,
                             np1secUserState* us,
                             std::string room_name){
  session_id = session_id;
  message_type = message_type;
  session_view = session_view;
  key_confirmation = key_confirmation;
  session_key_confirmation = session_key_confirmation;
  joiner_info = joiner_info;
  z_sender = z_sender;
  us = us;
  room_name = room_name;
}


np1secMessage::np1secMessage(std::string raw_message, Cryptic cryptic, np1secUserState usi, std::string room_name) {
  cryptic = cryptic;
  char* buf = strdup(raw_message.c_str());
  std::string np1sec = strtok(buf, c_np1sec_delim.c_str());
  us = us;
  room_name = room_name;
  if (np1sec.compare("np1sec")) {
    unwrap_generic_message();  
  }
}

/**
 * @return if the message is of type PARTICIPANTS_INFO it returns 
 *         the list of participants with their ephemerals otherwise
 *         throw an exception
 */
std::vector<UnauthenticatedParticipant> np1secMessage::participants_in_the_room()
{
  if (message_type != PARTICIPANTS_INFO)
    
    throw np1secMessageFormatException();

  std::vector<UnauthenticatedParticipant> disceted_participants;
  
  return disceted_participants;

}

std::string np1secMessage::session_view_as_string(){
  std::string output = c_np1sec_delim.c_str();
  for (std::vector<UnauthenticatedParticipant>::iterator it = session_view.begin(); it != session_view.end(); ++it){
    output += (*it).participant_id.id_to_stringbuffer(); // + _subfield_delim; //TODO::we don't need delim public key has static
    //length 
    //output += (*it).long_term_pub_key_hex + c_np1sec_delim.c_str(); 
  }
  return base64_encode(output);
}

void np1secMessage::string_to_session_view(std::string sv_string) {
  std::string temp = base64_decode(sv_string);
  std::string token = strtok(&temp[0], c_np1sec_delim.c_str());
  //this is dangerous as it assumes the string is
  //in pairs
  //TOOD::This need to be fixed, also how do we know end
  //Why aren't we using string::find?
  //TODO:: We need to delegiate breaking to the Participant Id class
  while (!token.empty()) {
    std::string nickname = token.substr(0, token.find(c_subfield_delim.c_str()));
    std::string fingerprint = token.substr(nickname.length() + c_subfield_delim.length(), nickname.length() + c_subfield_delim.length() +ParticipantId::c_fingerprint_length);
    std::string ephemeral_key = token.substr(nickname.length() +c_subfield_delim.length() + ParticipantId::c_fingerprint_length, nickname.length() + ParticipantId::c_fingerprint_length + c_ephemeral_key_length);
    ParticipantId pid(nickname, fingerprint);
    UnauthenticatedParticipant uap(pid, ephemeral_key);
    token = token.substr(nickname.length() + c_subfield_delim.length() + ParticipantId::c_fingerprint_length + c_ephemeral_key_length);
    /*uap.participant = token;
    token = strtok(NULL, c_subfield_delim.c_str());
    uap.long_term_pub_key_hex = token;
    token = strtok(NULL, c_subfield_delim.c_str());*/
    session_view.push_back(uap);
  }
}

void np1secMessage::format_generic_message() {
  std::string signature;
  sys_message = "" + std::to_string(message_type) + c_np1sec_delim.c_str();
  std::string sid_string(reinterpret_cast<char const*>(session_id));
  
  switch (message_type) {
    case PARTICIPANTS_INFO:
      sys_message += c_np1sec_delim.c_str() + session_view_as_string();
      sys_message += c_np1sec_delim.c_str() + key_confirmation;
      sys_message += c_np1sec_delim.c_str() + z_sender;
      break;
    case SESSION_CONFIRMATION:
      sys_message += c_np1sec_delim.c_str() + session_view_as_string();
      sys_message += c_np1sec_delim.c_str() + session_key_confirmation;
      break;
    case JOIN_REQUEST:
      sys_message += c_np1sec_delim.c_str() + joiner_info;
      break;
    case JOINER_AUTH:
      sys_message += c_np1sec_delim.c_str() + key_confirmation;
      sys_message += c_np1sec_delim.c_str() + z_sender;
      break;
    case FAREWELL:
      sys_message += c_np1sec_delim.c_str() + session_view_as_string();
      sys_message += c_np1sec_delim.c_str() + z_sender;
      meta_load = "";
      meta_load_flag = NO_LOAD;
      
      format_meta_message();
      sys_message += c_np1sec_delim.c_str() + meta_message;
      break;
   }

  signature = sign_message(sys_message);
  sys_message += signature + c_np1sec_delim.c_str();
  sys_message = c_np1sec_delim.c_str() + sid_string + c_np1sec_delim.c_str() + sys_message;
  sys_message = base64_encode(sys_message);
  sys_message = c_np1sec_protocol_name + c_np1sec_delim.c_str() + sys_message;
}

void np1secMessage::unwrap_generic_message() {

  std::string message = base64_decode(strtok(NULL, c_np1sec_delim.c_str()));
  message_type = (np1secMessageType)atoi(strtok(&message[0], c_np1sec_delim.c_str()));
  std::string temp = strtok(NULL, c_np1sec_delim.c_str());
  std::string signature, sv_string;
  if (!temp.empty()) {
    memcpy(session_id, temp.c_str(), temp.size());
  
    switch (message_type) {
      case PARTICIPANTS_INFO:
        sv_string = strtok(NULL, c_np1sec_delim.c_str());
        key_confirmation = strtok(NULL, c_np1sec_delim.c_str());
        z_sender = strtok(NULL, c_np1sec_delim.c_str());
        signature = strtok(NULL, c_np1sec_delim.c_str());
        string_to_session_view(sv_string);
        break;
      case SESSION_CONFIRMATION:
        sv_string = strtok(NULL, c_np1sec_delim.c_str());
        session_key_confirmation = strtok(NULL, c_np1sec_delim.c_str());
        signature = strtok(NULL, c_np1sec_delim.c_str());
        string_to_session_view(sv_string);
        break;
      case JOIN_REQUEST:
        joiner_info = strtok(NULL, c_np1sec_delim.c_str());
        signature = strtok(NULL, c_np1sec_delim.c_str());
        break;
      case JOINER_AUTH:
        key_confirmation = strtok(NULL, c_np1sec_delim.c_str());
        z_sender = strtok(NULL, c_np1sec_delim.c_str());
        signature = strtok(NULL, c_np1sec_delim.c_str());
        break;
      case FAREWELL:
        sv_string = strtok(NULL, c_np1sec_delim.c_str());
        z_sender = strtok(NULL, c_np1sec_delim.c_str());
        meta_message = strtok(NULL, c_np1sec_delim.c_str());
        signature = strtok(NULL, c_np1sec_delim.c_str());
        string_to_session_view(sv_string);
        break;
      case USER_MESSAGE:
        unwrap_user_message();
        break;
    }
  }
}

void np1secMessage::unwrap_user_message() {
  std::string np1sec, encrypted_message, phased_message,
              signed_message, signature;

  encrypted_message = strtok(NULL, c_np1sec_delim.c_str());

  phased_message = base64_decode(encrypted_message);
  std::string temp = strtok(&phased_message[0], c_np1sec_delim.c_str());
  memcpy(session_id, temp.c_str(), temp.size());
  encrypted_message = strtok(NULL, c_np1sec_delim.c_str());

  phased_message = decrypt_message(base64_decode(encrypted_message));
  signed_message = strtok(&phased_message[0], c_np1sec_delim.c_str());
  signature = strtok(NULL, c_np1sec_delim.c_str());

  if (verify_message(signed_message, signature)) {
    signed_message = base64_decode(signed_message);
    std::string temp;
    temp = strtok(&signed_message[0], c_np1sec_delim.c_str());
    // TODO(bill): clarify session id check
//      if(session_id.compare(temp)) {
      sender_id = strtok(NULL, c_np1sec_delim.c_str());
      user_message = strtok(NULL, c_np1sec_delim.c_str());

      meta_message = strtok(NULL, c_np1sec_delim.c_str());
      unwrap_meta_message();
      std::string hash_string = strtok(NULL, c_np1sec_delim.c_str());
      memcpy(transcript_chain_hash, hash_string.c_str(), hash_string.size());
      nonce = strtok(NULL, c_np1sec_delim.c_str());
      message_id = compute_message_id(user_message);
//      }

      message_type = UNKNOWN;
  }
}

void np1secMessage::format_meta_message() {
  meta_message = "" + std::to_string(meta_only) + c_np1sec_delim.c_str();
  meta_message += c_np1sec_delim.c_str() + ustate_values();
  meta_message += c_np1sec_delim.c_str() + std::to_string(meta_load_flag);
  meta_message += c_np1sec_delim.c_str() + meta_load;
  meta_message = base64_encode(meta_message);
}

void np1secMessage::unwrap_meta_message() {
  meta_message = base64_decode(meta_message);
  meta_only = atoi(strtok(&meta_message[0], c_np1sec_delim.c_str()));
  std::string ustates = strtok(NULL, c_np1sec_delim.c_str());
  meta_load_flag = static_cast<np1secLoadFlag>(atoi(strtok(NULL, c_np1sec_delim.c_str())));
  meta_load = strtok(NULL, c_np1sec_delim.c_str());
}

std::string np1secMessage::ustate_values() {
  std::string ustates;
  for (std::vector<std::string>::iterator it = pstates.begin();
       it != pstates.end(); ++it) {
    ustates += *it;
  }
  return ustates;
}

std::string np1secMessage::format_sendable_message() {
  std::string base_message, phased_message, signature;
  std::string sid_string(reinterpret_cast<char const*>(session_id));

  base_message = sid_string + c_np1sec_delim.c_str();
  base_message += sender_id + c_np1sec_delim.c_str();
  base_message += user_message + c_np1sec_delim.c_str();

  format_meta_message();
  base_message += meta_message + c_np1sec_delim.c_str();
  std::string hash_string(reinterpret_cast<char const*>(transcript_chain_hash));
  base_message += hash_string + c_np1sec_delim.c_str();
  base_message += nonce + c_np1sec_delim.c_str();

  base_message = base64_encode(base_message);

  signature = sign_message(base_message);
  base_message += signature + c_np1sec_delim.c_str();

  base_message = base64_encode(base_message);

  phased_message = encrypt_message(base_message);
  phased_message = sid_string + c_np1sec_delim.c_str() + phased_message;

  phased_message = base64_encode(phased_message);
  phased_message = "np1sec:O3" + phased_message + c_np1sec_delim.c_str();

  return phased_message;
}

uint32_t np1secMessage::compute_message_id(std::string cur_message) {
  return 0;
}

void np1secMessage::send() {
  us->ops->send_bare(room_name, sys_message, &us);
}

void np1secMessage::generate_nonce(unsigned char* buffer) {
  gcry_randomize(buffer, 128, GCRY_STRONG_RANDOM);
}

std::string np1secMessage::base64_encode(std::string message) {
  return otrl_base64_otr_encode((unsigned char*)message.c_str(),
                                 message.size());
}

std::string np1secMessage::base64_decode(std::string message) {
  std::string decoded;
  otrl_base64_otr_decode(message.c_str(),
                         (unsigned char**)decoded.c_str(),
                         reinterpret_cast<size_t*>(message.size()));
  return decoded;
}

std::string np1secMessage::sign_message(std::string message) {
  gcry_error_t err;
  unsigned char *sigbuf = NULL;
  size_t siglen;

  err = cryptic->Sign(&sigbuf, &siglen, message);

  std::string signature(reinterpret_cast<char*>(sigbuf));

  return signature;
}


bool np1secMessage::verify_message(std::string signed_message,
                                   std::string signature) {
  if ( cryptic->Verify(signed_message, (unsigned char*)signature.c_str())
       == gcry_error(GPG_ERR_NO_ERROR)) {
    return true;
  }

  return false;
}

std::string np1secMessage::encrypt_message(std::string signed_message) {
  return cryptic->Encrypt(signed_message);
}


std::string np1secMessage::decrypt_message(std::string encrypted_message) {
  return cryptic->Decrypt(encrypted_message);
}

gcry_error_t np1secMessage::compute_hash(HashBlock transcript_chain,
                                     std::string message) {
  return cryptic->hash(message.c_str(), message.size(), transcript_chain, true);
}

np1secMessage::~np1secMessage() {
  return;
}
#endif  // SRC_MESSAGE_CC_
