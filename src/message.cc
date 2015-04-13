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

np1secMessage::np1secMessage(SessionId session_id,
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
: sender_id(sender_id),
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
  set_session_id(session_id.get());
  
  if (message_type == PURE_META_MESSAGE) {
    this->meta_only = 1;
  }
}

void np1secMessage::set_session_id(const uint8_t* new_session_id) {

  if (new_session_id) {
    session_id = session_id_buffer; //I wanna throw up :( we should use stirng buffer
    memcpy(session_id_buffer, new_session_id, sizeof(HashBlock));
  } else {
    session_id = nullptr;
  }
    
}
np1secMessage::np1secMessage(SessionId& session_id,
                             np1secMessageType message_type,
                             UnauthenticatedParticipantList& session_view,
                             std::string key_confirmation,
                             std::string session_key_confirmation,
                             std::string joiner_info,
                             std::string z_sender,
                             np1secUserState* us,
                             std::string room_name)
  :
  message_type(message_type),
  session_view(session_view),
  key_confirmation(key_confirmation),
  session_key_confirmation(session_key_confirmation),
  joiner_info(joiner_info),
  z_sender(z_sender),
  us(us),
  room_name(room_name)
  {
    set_session_id(session_id.get());
    format_generic_message();
  }


np1secMessage::np1secMessage(std::string raw_message, Cryptic* cryptic, np1secUserState* usi, std::string room_name):
  us(us),
  room_name(room_name),
  cryptic(cryptic)
{
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
 * constructor for join message
 */
np1secMessage::np1secMessage(np1secMessageType message_type,
                             UnauthenticatedParticipant joiner,
                             np1secUserState* us,
                             std::string room_name)
  :message_type(message_type),
   session_id(nullptr),us(us),
   room_name(room_name),
   joiner_info(joiner.unauthed_participant_to_stringbuffer())
{
  format_generic_message();

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

void np1secMessage::format_generic_message() {
  std::string signature;
  sys_message = "" + std::to_string(this->message_type);
  std::string sid_string;
 
  switch (this->message_type) {
    case PARTICIPANTS_INFO:
      sys_message += c_np1sec_delim + session_view_as_string();
      sys_message += c_np1sec_delim + this->key_confirmation;
      sys_message += c_np1sec_delim + this->z_sender;
      break;
    case SESSION_CONFIRMATION:
      sys_message += c_np1sec_delim.c_str() + session_view_as_string();
      sys_message += c_np1sec_delim + this->session_key_confirmation;
      break;
    case JOIN_REQUEST:
      sys_message += c_np1sec_delim + this->joiner_info;
      break;
    case JOINER_AUTH:
      sys_message += c_np1sec_delim + this->key_confirmation;
      sys_message += c_np1sec_delim + this->z_sender;
      break;
    case FAREWELL:
      sys_message += c_np1sec_delim + session_view_as_string();
      sys_message += c_np1sec_delim + this->z_sender;
      meta_load = "";
      meta_load_flag = NO_LOAD;
      format_meta_message();
      sys_message += c_np1sec_delim + this->meta_message;
      break;
   }

  if (this->session_id) {
    sid_string.assign(reinterpret_cast<char const*>(this->session_id), sizeof(HashBlock));
    sys_message = sid_string + c_np1sec_delim + sys_message + c_np1sec_delim;
  } else {
    sys_message += c_np1sec_delim;
  }
  sys_message = base64_encode(sys_message);
  sys_message = c_np1sec_protocol_name + c_np1sec_delim + sys_message + c_np1sec_delim;
}

void np1secMessage::unwrap_generic_message(std::vector<std::string> m_tokens) {

  std::string message = base64_decode(m_tokens[1]);
  std::vector<std::string> sub_tokens = split(message, c_np1sec_delim);
  /*if(sub_tokens.size() <=0 ){
    throw "np1secMessage::unwrap_generic_message: message no tokenisable";
  } */ 	
  std::string temp = sub_tokens[0];
  message_type = (np1secMessageType)atoi(sub_tokens[1].c_str());
  std::string signature, sv_string;

  if (!temp.empty())
    set_session_id(reinterpret_cast<uint8_t*>(&temp[0]));
  
  switch (message_type) {
      case PARTICIPANTS_INFO:
        sv_string = sub_tokens[2];
        this->key_confirmation = sub_tokens[3];
        this->z_sender = sub_tokens[4];
        string_to_session_view(sv_string);
        break;
      case SESSION_CONFIRMATION:
        sv_string = sub_tokens[2];
        this->session_key_confirmation = sub_tokens[3];
        string_to_session_view(sv_string);
        break;
      case JOIN_REQUEST:
        this->joiner_info = sub_tokens[2];
        break;
      case JOINER_AUTH:
        this->key_confirmation = sub_tokens[2];
        this->z_sender = sub_tokens[3];
        break;
      case FAREWELL:
        sv_string = sub_tokens[2];
        this->z_sender = sub_tokens[3];
        this->meta_message = sub_tokens[4];
        string_to_session_view(sv_string);
        break;
      case USER_MESSAGE:
        unwrap_user_message(sub_tokens[2]);
        break;
  }
 
}

void np1secMessage::unwrap_user_message(std::string u_message) {
  std::string np1sec, encrypted_message, phased_message,
              signed_message, signature;
  std::vector<std::string> m_tokens = split(u_message, c_np1sec_delim);
  encrypted_message = m_tokens[0];

  phased_message = base64_decode(encrypted_message);
  m_tokens = split(phased_message, c_np1sec_delim);

  std::string temp = m_tokens[0];
  set_session_id(reinterpret_cast<const uint8_t*>(temp.c_str()));

  encrypted_message = m_tokens[1];

  phased_message = decrypt_message(base64_decode(encrypted_message));
  m_tokens = split(phased_message, c_np1sec_delim);

  signed_message = m_tokens[0];
  signature = m_tokens[1];

  if (verify_message(signed_message, signature)) {
    signed_message = base64_decode(signed_message);
    std::string temp;
    m_tokens = split(signed_message, c_np1sec_delim);
    // TODO(bill): clarify session id check
//      if(session_id.compare(temp)) {
      sender_id = m_tokens[1];
      user_message = m_tokens[2];

      meta_message = m_tokens[3];
      unwrap_meta_message();

      std::string hash_string = m_tokens[4];
      memcpy(transcript_chain_hash, hash_string.c_str(), hash_string.size());
      nonce = m_tokens[5];
      message_id = compute_message_id(user_message);
//      }

      message_type = UNKNOWN;
  }
}

void np1secMessage::format_meta_message() {
  meta_message = "" + std::to_string(meta_only) + c_np1sec_delim.c_str();
  meta_message += c_np1sec_delim + ustate_values();
  meta_message += c_np1sec_delim + std::to_string(meta_load_flag);
  meta_message += c_np1sec_delim + meta_load;
  meta_message = base64_encode(meta_message);
}

void np1secMessage::unwrap_meta_message() {
  meta_message = base64_decode(meta_message);
  std::vector<std::string> m_tokens = split(meta_message, c_np1sec_delim);
  meta_only = atoi(m_tokens[0].c_str());
  std::string ustates = m_tokens[1];
  meta_load_flag = static_cast<np1secLoadFlag>(atoi(m_tokens[2].c_str()));
  meta_load = m_tokens[3];
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
  phased_message = sid_string + c_np1sec_delim + phased_message;

  phased_message = base64_encode(phased_message);
  phased_message = "np1sec:O3" + phased_message + c_np1sec_delim.c_str();

  return phased_message;
}

uint32_t np1secMessage::compute_message_id(std::string cur_message) {
  return 0;
}

void np1secMessage::send() {
  us->ops->send_bare(room_name, sys_message, us->ops->bare_sender_data); //This is not cool
  //message just should ask us to send and then us is the only one which has
  //access to ops internals
  
}

void np1secMessage::generate_nonce(unsigned char* buffer) {
  gcry_randomize(buffer, 128, GCRY_STRONG_RANDOM);
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


std::string np1secMessage::decrypt_message(std::string encrypted_message) {
  return cryptic->Decrypt(encrypted_message);
}

np1secMessage::~np1secMessage() {
  return;
}
#endif  // SRC_MESSAGE_CC_
