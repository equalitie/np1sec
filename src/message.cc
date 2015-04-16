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
#include "src/message.h"
#include "src/userstate.h"
#include "src/exceptions.h"

np1secMessage::np1secMessage(){
}

np1secMessage::np1secMessage(std::string raw_message, Cryptic* cryptic):
  cryptic(cryptic)
{
  final_whole_message = raw_message;
  std::vector<std::string> message_tokens = split(raw_message,c_np1sec_delim); 
  if (message_tokens[0] == c_np1sec_protocol_name) {
    unwrap_generic_message(message_tokens);  
  } else {
    throw np1secMessageFormatException();
    //TODO:: do something intelligent here
    //should we warn the user about unencrypted message
    //and then return everything as the plain text?
  }
}

/**
 * @return if the message is of type PARTICIPANTS_INFO it returns 
 *         the list of participants with their ephemerals otherwise
 *         throw an exception
 */
UnauthenticatedParticipantList np1secMessage::participants_in_the_room()
{
  if (message_type != PARTICIPANTS_INFO)
    
    throw np1secMessageFormatException();

  UnauthenticatedParticipantList disceted_participants;
  //TODO fill up the list
  
  return disceted_participants;

}

std::string np1secMessage::session_view_as_string(){
  std::string output = c_np1sec_delim.c_str();
  for (UnauthenticatedParticipantList::iterator it = session_view.begin(); it != session_view.end(); ++it){
    output += (*it).participant_id.id_to_stringbuffer(); // + _subfield_delim; //TODO::we don't need delim public key has static
    output += Cryptic::hash_to_string_buff((*it).ephemeral_pub_key);
    //length 
    //output += (*it).long_term_pub_key_hex + c_np1sec_delim.c_str(); 
  }
  return base64_encode(output);
}

void np1secMessage::string_to_session_view(std::string sv_string) {
  std::string temp = base64_decode(sv_string);
  std::vector<std::string> sub_tokens = split(temp, c_np1sec_delim);
  if (sub_tokens.size() == 0) //something is wrong
    throw np1secMessageFormatException();

  std::string token = sub_tokens[1]; //because it starts with c_np1sec_delim
  //so the first field is empty
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
    this->session_view.push_back(uap);
  }
}

void np1secMessage::create_participant_info_msg(SessionId session_id, 
                                 UnauthenticatedParticipantList& session_view_list, 
                                 std::string key_confirmation,
                                 std::string z_sender) {
  this->session_id.set(session_id.get());
  this->message_type = PARTICIPANTS_INFO;
  sys_message = session_view_as_string();
  sys_message += key_confirmation;
  sys_message += z_sender;

  append_msg_end();
  
}

void np1secMessage::create_group_share_msg(SessionId session_id, 
                                 UnauthenticatedParticipantList& session_view_list, 
                                 std::string z_sender) {
  this->session_id.set(session_id.get());
  this->message_type = GROUP_SHARE;
  sys_message = session_view_as_string();
  sys_message += z_sender;

  append_msg_end();
  
}

void np1secMessage::create_session_confirmation_msg(SessionId session_id, 
                                 UnauthenticatedParticipantList& session_view_list, 
                                 std::string session_key_confirmation) {

  this->session_id.set(session_id.get());
  this->message_type = SESSION_CONFIRMATION;
  sys_message = session_view_as_string();
  sys_message += session_key_confirmation;

  append_msg_end();
  
}

void np1secMessage::create_join_request_msg(UnauthenticatedParticipant joiner) {
   
  this->message_type = JOIN_REQUEST;
  sys_message = joiner.unauthed_participant_to_stringbuffer();

  append_msg_end();
}                             

void np1secMessage::create_joiner_auth_msg(SessionId session_id,
                          std::string key_confirmation,
                          std::string z_sender) {

  this->session_id.set(session_id.get());
  this->message_type = JOINER_AUTH;
  sys_message = key_confirmation;
  sys_message += z_sender;

  append_msg_end();

}

void np1secMessage::create_farewell_msg(SessionId session_id,
                                        UnauthenticatedParticipantList& session_view_list, 
                                        std::string z_sender) {

  this->session_id.set(session_id.get());
  this->message_type = FAREWELL;
  sys_message = session_view_as_string();
  sys_message += z_sender;

  append_msg_end();

}

void np1secMessage::append_msg_end() {

  if (this->session_id.get() != nullptr) {
    sys_message = c_np1sec_delim + this->session_id.get_as_stringbuff() + sys_message + c_np1sec_delim;
  } 
  
  sys_message = std::to_string(this->message_type) + sys_message + c_np1sec_delim;
  sys_message = base64_encode(sys_message);
  sys_message = c_np1sec_protocol_name + c_np1sec_delim + sys_message + c_np1sec_delim;

}

void np1secMessage::unwrap_generic_message(std::vector<std::string> m_tokens) {
  std::string message = base64_decode(m_tokens[1]);
  std::vector<std::string> sub_tokens = split(message, c_np1sec_delim);

  message_type = (np1secMessageType)atoi(sub_tokens[0].c_str());
  std::string signature, sv_string;
  
  switch (message_type) {
      case PARTICIPANTS_INFO:
        this->session_id.set(reinterpret_cast<uint8_t*>(&sub_tokens[1][0]));
        sv_string = sub_tokens[2];
        this->key_confirmation = sub_tokens[3];
        this->z_sender = sub_tokens[4];
        string_to_session_view(sv_string);
        break;
      case SESSION_CONFIRMATION:
        this->session_id.set(reinterpret_cast<uint8_t*>(&sub_tokens[1][0]));
        sv_string = sub_tokens[2];
        this->session_key_confirmation = sub_tokens[3];
        string_to_session_view(sv_string);
        break;
      case JOIN_REQUEST:
        this->joiner_info = sub_tokens[1];
        break;
      case JOINER_AUTH:
        this->session_id.set(reinterpret_cast<uint8_t*>(&sub_tokens[1][0]));
        this->key_confirmation = sub_tokens[2];
        this->z_sender = sub_tokens[3];
        break;
      case FAREWELL:
      case GROUP_SHARE:
        this->session_id.set(reinterpret_cast<uint8_t*>(&sub_tokens[1][0]));
        sv_string = sub_tokens[2];
        this->z_sender = sub_tokens[4];
        string_to_session_view(sv_string);
        break;
      case USER_MESSAGE:
        this->session_id.set(reinterpret_cast<uint8_t*>(&sub_tokens[1][0]));
        unwrap_user_message(sub_tokens[2]);
        break;
  }
 
}

std::string np1secMessage::ustate_values(std::vector<std::string> pstates) {
  std::string ustates;
  for (std::vector<std::string>::iterator it = pstates.begin();
       it != pstates.end(); ++it) {
    ustates += *it;
  }
  return ustates;
}

std::string np1secMessage::create_user_msg(SessionId session_id,
                                           std::string sender_index,
                                           std::string user_message,
                                           np1secMessageType message_type,
                                           HashBlock transcript_chain_hash,
                                           np1secLoadFlag meta_load_flag,
                                           std::string meta_load,
                                           std::vector<std::string> pstates,
                                           Cryptic* cryptic
                                           ) {

  std::string base_message, phased_message, signature;
  char length[8];
  unsigned char buffer[128];
  gcry_randomize(buffer, 128, GCRY_STRONG_RANDOM);
  std::string ustates = ustate_values(pstates);

  std::string hash_string(reinterpret_cast<char const*>(transcript_chain_hash), sizeof(HashBlock));
  std::string nonce(reinterpret_cast<char const*>(buffer), sizeof(buffer));

  base_message = session_id.get_as_stringbuff();
  base_message += hash_string;
  base_message += nonce;

  base_message += sender_index;

  size_t size = user_message.size();
  memcpy(length, &size, sizeof(size_t));
  std::string var(length, sizeof(size_t));
  base_message += var;  
  base_message += user_message;

  base_message += std::to_string(meta_only);

  size = ustates.size();
  memcpy(length, &size, sizeof(size_t));
  var.assign(length, sizeof(size_t));

  base_message += var;  
  base_message += ustates;

  base_message += std::to_string(meta_load_flag);
  base_message += meta_load;
  signature = sign_message(base_message);
  base_message += signature + c_np1sec_delim.c_str();
  phased_message = encrypt_message(base_message);

  if (this->session_id.get() != nullptr) {
    phased_message = c_np1sec_delim + this->session_id.get_as_stringbuff() + phased_message + c_np1sec_delim;
  } 
  
  phased_message = std::to_string(this->message_type) + sys_message + c_np1sec_delim;
  phased_message = base64_encode(phased_message);
  phased_message = c_np1sec_protocol_name + c_np1sec_delim + phased_message + c_np1sec_delim;

  final_whole_message = phased_message;

  return phased_message;
  
}

void np1secMessage::unwrap_user_message(std::string u_message) {
  std::string encrypted_message, phased_message,
              signed_message, signature, temp_store;
  std::vector<std::string> m_tokens = split(u_message, c_np1sec_delim);
  encrypted_message = m_tokens[0];

  phased_message = base64_decode(encrypted_message);
  
  // Read first 32 bytes which represent the session id
  temp_store = phased_message.substr(0,31);
  HashBlock sid;
  memcpy(sid, temp_store.c_str(), sizeof(HashBlock));
  this->session_id.set(sid);

  // Remove sid from string
  phased_message.erase(0,31);

  phased_message = decrypt_message(base64_decode(phased_message));
  m_tokens = split(phased_message, c_np1sec_delim);
  signature = m_tokens[0];
  signed_message = m_tokens[1];

  // Read next 32 bytes from string which represent copy of sid
  if (verify_message(signed_message, signature)) {
    //read 32 for sid
    temp_store = phased_message.substr(0,31);
    memcpy(sid, temp_store.c_str(), sizeof(HashBlock));
    if(sid != this->session_id.get()){
      throw np1secMessageFormatException();
    }

    //read 32 for transcript hash
    phased_message.erase(0,31);
    temp_store = phased_message.substr(0,31);
    memcpy(this->transcript_chain_hash, temp_store.c_str(), sizeof(HashBlock));

    //read 128 for nonce
    phased_message.erase(0,31);
    this->nonce = phased_message.substr(0,127);

    //read 4 for sender_index
    phased_message.erase(0,127);
    this->sender_index = phased_message.substr(0,7);

    //read 4 for message length
    phased_message.erase(0,7);
    size_t msg_len = atoi(phased_message.substr(0,7).c_str());

    //read message length for message
    phased_message.erase(0, 7);
    this->user_message = phased_message.substr(0, msg_len);

    //read 4 for meta_only
    phased_message.erase(0, msg_len);
    this->meta_only = atoi(phased_message.substr(0,7).c_str());

    //read number of participants for ustate
    phased_message.erase(0,7);
    size_t p_num = atoi(phased_message.substr(0,7).c_str());

    //read p_states based on p_num
    phased_message.erase(0,7);
    this->ustates = phased_message.substr(0,p_num);

    //read 4 for meta_load_flag
    phased_message.erase(0,p_num);
    this->meta_load_flag = static_cast<np1secLoadFlag>(atoi(phased_message.substr(0,7).c_str())); 

    //read size of meta load
    phased_message.erase(0,7);
    this->meta_load = phased_message;
      
    message_id = compute_message_id(user_message);

  } else {
    throw np1secMessageSignatureException();
  }
}

uint32_t np1secMessage::compute_message_id(std::string cur_message) {
  return 0;
}

void np1secMessage::send(std::string room_name, np1secUserState* us) {
  us->ops->send_bare(room_name, sys_message, us->ops->bare_sender_data); //This is not cool
  //message just should ask us to send and then us is the only one which has
  //access to ops internals
  
}


std::string np1secMessage::base64_encode(std::string message) {
  return otrl_base64_otr_encode((unsigned char*)message.c_str(),
                                 message.size());
}

std::string np1secMessage::base64_decode(std::string message) {
  unsigned char* buf;
  size_t len;
  otrl_base64_otr_decode(message.c_str(),
                         &buf,
                         &len);
  return std::string(reinterpret_cast<const char*>(buf), len);
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

HashStdBlock np1secMessage::compute_hash()
{
  if (final_whole_message.length()) {
    HashBlock hb;
    Cryptic::hash(final_whole_message, hb, true);
    return Cryptic::hash_to_string_buff(hb);
  }
  else
    return "";
  
}

std::string np1secMessage::decrypt_message(std::string encrypted_message) {
  return cryptic->Decrypt(encrypted_message);
}

np1secMessage::~np1secMessage() {
}
#endif  // SRC_MESSAGE_CC_
