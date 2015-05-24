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

#include <iostream>

#include "src/message.h"
#include "src/userstate.h"
#include "src/exceptions.h"

/**
 *  return the apporperiate string buffer which contains the data
 *  in data
 */
std::string np1secMessage::encode_opaque_data(const std::string& data)
{
  std::string result(data_to_string(static_cast<const uint32_t>(data.size())));
  result += data;
  return result;

}

/**
 *  gets a string starts with opaque data field 
 *  return a pairs of strings, first with the opaque data (without length)
 *  second the rest of the string
 */
std::pair<std::string, std::string> np1secMessage::decode_opaque_field(std::string opaque_data)
{
  uint32_t opaque_string_size(*(reinterpret_cast<const uint32_t*>(opaque_data.data())));
  if (opaque_string_size > opaque_data.size())
    throw np1secMessageFormatException();

  std::string opaque_string_data(opaque_data.data() + sizeof(uint32_t), opaque_string_size);
  std::string the_rest = opaque_data.substr(opaque_string_data.size() + sizeof(uint32_t));

  return std::pair<std::string, std::string>(opaque_string_data, the_rest);
                                            
}

np1secMessage::np1secMessage(Cryptic *cryptic)
  :cryptic(cryptic)
{
}

np1secMessage::np1secMessage(std::string raw_message, Cryptic* cryptic, size_t no_of_participants):
  cryptic(cryptic),
  no_of_participants(no_of_participants)
{
  final_whole_message = raw_message;
  unwrap_generic_message(check_and_chop_protocol_tag(raw_message));
}

/**
 * @return if the message is of type PARTICIPANTS_INFO it returns 
 *         the list of participants with their ephemerals otherwise
 *         throw an exception
 */
const UnauthenticatedParticipantList& np1secMessage::get_session_view()
{
  if (message_type != PARTICIPANTS_INFO || session_view.empty())
    throw np1secMessageFormatException();
  //if the message is of participant info then session_view
  //get filled on construction

  return session_view;
  
}

std::string np1secMessage::session_view_as_string() {

  std::string output;
  if (!session_view.size()) //it is an invalid room
    throw np1secInvalidRoomException();
    
  for (UnauthenticatedParticipantList::iterator it = session_view.begin(); it != session_view.end(); ++it){
    output += encode_opaque_data((*it).unauthed_participant_to_stringbuffer());
  }
  
  return output;

}

void np1secMessage::string_to_session_view(std::string sv_string) {
  while(sv_string.size()) {
    std::pair<std::string, std::string> pid_and_rest = decode_opaque_field(sv_string);
    this->session_view.push_back(UnauthenticatedParticipant(pid_and_rest.first));
    sv_string = pid_and_rest.second;
  }
}

void np1secMessage::create_participant_info_msg(SessionId session_id,
                                 UnauthenticatedParticipantList& session_view_list, 
                                 std::string key_confirmation,
                                 HashStdBlock z_sender) {

  //data verification
  logger.assert(session_id.get(), "can not create participant info message for id-less session");

  this->message_type = PARTICIPANTS_INFO;
  this->session_id.set(session_id.get());
  this->session_view = session_view_list;

  sys_message = encode_opaque_data(session_view_as_string());
  sys_message += encode_opaque_data(key_confirmation);
  sys_message += z_sender;

  append_msg_end();
  
}

void np1secMessage::create_group_share_msg(SessionId session_id, 
                                 std::string z_sender) {
  //data verification
  if (!session_id.get())
    throw np1secInvalidDataException();

  this->message_type = GROUP_SHARE;
  this->session_id.set(session_id.get());
  sys_message += z_sender;

  append_msg_end();
  
}

void np1secMessage::create_session_confirmation_msg(SessionId session_id, 
                                 std::string session_key_confirmation) {
  //data verification
  logger.assert(session_id.get(), "can not create confirmation message for id-less session");

  this->session_id.set(session_id.get());
  this->message_type = SESSION_CONFIRMATION;
  sys_message = session_key_confirmation;

  append_msg_end();
  
}

void np1secMessage::create_join_request_msg(UnauthenticatedParticipant joiner) {
   
  this->message_type = JOIN_REQUEST;
  sys_message = joiner.unauthed_participant_to_stringbuffer();

  //no need to be signed
  append_msg_end(false);
  
}                             

void np1secMessage::create_joiner_auth_msg(SessionId session_id,
                          std::string key_confirmation,
                          std::string z_sender) {

  //data verification
  logger.assert(session_id.get(), "can not create joiner auth message for id-less session");

  this->message_type = JOINER_AUTH;
  this->session_id.set(session_id.get());
  sys_message = encode_opaque_data(key_confirmation);
  sys_message += z_sender;

  append_msg_end();

}

// void np1secMessage::create_farewell_msg(SessionId session_id,
//                                         UnauthenticatedParticipantList& session_view_list, 
//                                         std::string z_sender) {

//   this->session_id.set(session_id.get());
//   this->message_type = FAREWELL;
//   sys_message = session_view_as_string();
//   sys_message += z_sender;

//   append_msg_end();

// }

void np1secMessage::append_msg_end(bool need_to_be_signed) {
  std::string clear_message = data_to_string(c_np1sec_protocol_version) + data_to_string((DTByte)(this->message_type));

  if (this->session_id.get() != nullptr) {
    clear_message += this->session_id.get_as_stringbuff();
  } 

  if (need_to_be_signed) {
      signature = sign_message(clear_message + sys_message);

  sys_message = sys_message + signature;
  
  if (message_type == IN_SESSION_MESSAGE) {
    sys_message = encrypt_message(sys_message);
  }

  sys_message = clear_message + sys_message;

  sys_message = base64_encode(sys_message);
  sys_message = c_np1sec_protocol_name + sys_message;

  final_whole_message = sys_message;
  
}

void np1secMessage::unwrap_generic_message(std::string b64ed_message) {
  std::string message = base64_decode(b64ed_message);

  size_t c_message_type_offset = sizeof(DTShort); //message type is immediately after
  //protocol version

  //check version
  if (!check_version_validity(message))
    throw np1secVersionMismatchException();

  message_type = (np1secMessageType)(*reinterpret_cast<DTByte*>(&message[c_message_type_offset]));

  size_t current_offset = c_message_type_offset + sizeof(DTByte);
  std::cout << message_type << std::endl;
  
  switch (message_type)
    {
    case JOIN_REQUEST:
      //the only session id-less unsigned message is JOIN_REQUEST
      this->joiner_info = message.substr(current_offset);
      break;


    default:
      //the message should have 
      //now we get the session id
      if (message.size() < current_offset + c_hash_length)
        throw np1secMessageFormatException();
        
      this->session_id.set(reinterpret_cast<uint8_t*>(&message[current_offset]));
      current_offset += c_hash_length;
      
      if (message_type == IN_SESSION_MESSAGE) {
        //this is an encrypted message and we can't do more before
        //decryption. If we don't have the session key then we stop here
        //the first part of signed message
        signed_message = message.substr(0,current_offset);
        encrypted_part_of_message = message.substr(current_offset);
        if (cryptic)
          unwrap_in_session_message(encrypted_part_of_message);
        
      }
      else {
        
        //at least we need to have a signature size
        if (message.length() < current_offset + c_signature_length)
          throw np1secMessageFormatException();
      
        //we only store these values so the session later calls the verify function
        //because we don't keep track of the sender public key we are unable to
        //verify the signature ourselves.
        signed_message = message.substr(0, message.size() - c_signature_length);
        signature = message.substr(signed_message.size());


        //from now on we deal with the messages separately
        switch (message_type)
        {        
        case PARTICIPANTS_INFO:
          {
            std::pair<std::string, std::string> sv_and_rest  = decode_opaque_field(signed_message.substr(current_offset));
            string_to_session_view(sv_and_rest.first);

            std::pair<std::string, std::string> confirmation_and_share = decode_opaque_field(sv_and_rest.second);
            key_confirmation = confirmation_and_share.first;
            z_sender = confirmation_and_share.second;
            if (z_sender.size() != c_hash_length)
              throw np1secMessageFormatException();
               
            break;
          }

        case JOINER_AUTH:
          {
            std::pair<std::string, std::string> confirmation_and_share = decode_opaque_field(signed_message.substr(current_offset));

            key_confirmation = confirmation_and_share.first;
            build_authentication_table();
            
            z_sender = confirmation_and_share.second;
            if (z_sender.size() != c_hash_length)
              throw np1secMessageFormatException();
          
            break;
          }

        case GROUP_SHARE:
          z_sender = signed_message.substr(current_offset);
          if (z_sender.size() != c_hash_length)
            throw np1secMessageFormatException();
              
          break;
              
        case SESSION_CONFIRMATION:
          session_key_confirmation = signed_message.substr(current_offset);
          if (session_key_confirmation.size() != c_hash_length)
            throw np1secMessageFormatException();
          break;

        default:
          //we exhausted all type possibility 
          throw np1secMessageFormatException();
              
        }
      }
    }

}

void np1secMessage::build_authentication_table()
{
  std::string remaining_confirmations = key_confirmation;
  while(remaining_confirmations.size()) {
    if (remaining_confirmations.size() < sizeof(DTLength) + sizeof(DTHash))
      throw np1secMessageFormatException();

    authentication_table.insert(std::pair<DTLength, std::string>(string_to_length(remaining_confirmations.data()), std::string(remaining_confirmations.data()+sizeof(DTLength), sizeof(DTHash))));

    remaining_confirmations.erase(0, sizeof(DTLength) + sizeof(DTHash));

  }
  
}

/**
   version, type, sid, Encrypted, signature
   Encrypted
   meta
   sender_id, own_sender_id, parent_id, Transcript Hash nounce
   TV Opaque
   user message
   TV Hash
   ephemeral key
   TV Hash
   Group Share
   TV Hash
   Session confirmation
   TV BYTE*SESSION_SIZE
   ustates
   TV 0 Length
   Leave
 */
std::string np1secMessage::create_in_session_msg(SessionId session_id,
                                                 uint32_t sender_index,
                                                 uint32_t sender_own_id,
                                                 uint32_t parent_id,
                                                 HashStdBlock transcript_chain_hash,
                                                 np1secMessageSubType message_sub_type,
                                                 std::string user_message,
                                                 HashStdBlock new_ephemeral_key,
                                                 HashStdBlock new_share,
                                                 const std::vector<std::string>& pstates
                                                 ) {

  if (!cryptic) //you can't make a user message without cryptic being set
    throw np1secInsufficientCredentialException();

  message_type = IN_SESSION_MESSAGE;
  logger.assert(session_id.get(), "can not create in-session message for id-less session");
  this->session_id.set(session_id.get());
  std::string base_message;
  //first we cook the meta part

  char length[8];
  HashBlock buffer;
  gcry_randomize(buffer, c_hash_length, GCRY_STRONG_RANDOM);

  base_message = data_to_string(sender_index);
  base_message += data_to_string(sender_own_id);
  base_message += data_to_string(parent_id);
  base_message += transcript_chain_hash;
  base_message += Cryptic::hash_to_string_buff(buffer);

  switch(message_sub_type)
    {
    case USER_MESSAGE:
      base_message += data_to_string((DTShort)message_sub_type);
      base_message += encode_opaque_data(user_message);
      break;
    case LEAVE_MESSAGE:
      base_message += data_to_string((DTShort)message_sub_type);

    }
  
  if (new_ephemeral_key.size() == c_ephemeral_key_length) {
    base_message += data_to_string((DTShort)EPHEMERAL_KEY);
    base_message = new_ephemeral_key;
  }

  if (new_share.size() == c_hash_length) {
    base_message += data_to_string((DTShort)KEY_SHARE);
    base_message = new_ephemeral_key;
  }

  if (pstates.size()) {
    base_message += data_to_string((DTShort)CONTRIBUTION_STATE);
    std::string ustates = ustate_values(pstates);
    base_message += ustates;
  }

  sys_message = base_message;
  
  append_msg_end(true);
  
  return final_whole_message;
  
}

void np1secMessage::unwrap_in_session_message(std::string u_message) {
  std::string encrypted_message, phased_message, temp_store;

  phased_message = decrypt_message(u_message);
  if (phased_message.size() < c_signature_length)
    throw np1secMessageFormatException();
  
  std::string signed_encrypted_part = phased_message.substr(0,phased_message.size() - c_signature_length);
  signed_message += signed_encrypted_part;
  signature = phased_message.substr(signed_encrypted_part.size());
  // Read next 32 bytes from string which represent copy of sid
  //  if (verify_message(signed_message, signature)) { //we can't verify
  //we are not keeping track of pub keys

  //sender_index: DTLength
  size_t current_offset = move_offset_or_throw_up(signed_encrypted_part, 0, 0, sizeof(DTLength));
  sender_index = string_to_length(&signed_encrypted_part[current_offset]);

  //sender_own_id: DTLength
  current_offset = move_offset_or_throw_up(signed_encrypted_part, current_offset, sizeof(DTLength),  sizeof(DTLength));
  sender_message_id = string_to_length(&signed_encrypted_part[current_offset]);

  //parent_id: DTLength
  current_offset = move_offset_or_throw_up(signed_encrypted_part, current_offset, sizeof(DTLength),  sizeof(DTLength));
  parent_id = string_to_length(&signed_encrypted_part[current_offset]);

  //transcript hash: DTLength
  current_offset = move_offset_or_throw_up(signed_encrypted_part, current_offset, sizeof(DTLength),  sizeof(DTHash));
  transcript_chain_hash = signed_encrypted_part.substr(current_offset, sizeof(DTHash));

  //nonce DTHash
  current_offset = move_offset_or_throw_up(signed_encrypted_part, current_offset, sizeof(DTHash),  sizeof(DTHash));
  nonce = signed_encrypted_part.substr(current_offset, sizeof(DTHash));

  //now we recover the TVs
  current_offset = move_offset_or_throw_up(signed_encrypted_part, current_offset, sizeof(DTHash));
  std::string sub_messages_remainder = signed_encrypted_part.substr(current_offset);
  //if the message has no TVs then it is just an ACK
  np1secMessageSubType current_sub_message_type = JUST_ACK;
  while(sub_messages_remainder.size()) {
    //message sub type hash: DTLength
    current_offset = move_offset_or_throw_up(sub_messages_remainder, 0, 0, sizeof(DTShort)); //just checking to have valid length
    np1secMessageSubType current_sub_message_type = static_cast<np1secMessageSubType>(string_to_short(&sub_messages_remainder[current_offset]));
    current_offset = move_offset_or_throw_up(sub_messages_remainder, current_offset, sizeof(DTShort));

    switch(current_sub_message_type)
      {
      case USER_MESSAGE:
        {
        message_sub_type = USER_MESSAGE;
        std::pair<std::string,std::string> user_message_and_rest = decode_opaque_field(sub_messages_remainder.substr(current_offset));
        user_message = user_message_and_rest.first;
        sub_messages_remainder = user_message_and_rest.second;
        current_offset = 0;
        break;
        }

      case LEAVE_MESSAGE:
        message_sub_type = LEAVE_MESSAGE;
        sub_messages_remainder = sub_messages_remainder.substr(current_offset);
        break;

      case JUST_ACK: //Add nothing
        break;

      default: //this is about in session forward secracy
        throw np1secNotImplementedException();
        
      }
  };
        
  //message_id = compute_message_id(user_message);

}

uint32_t np1secMessage::compute_message_id(std::string cur_message) {
  return message_id;
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

  try { 
    cryptic->sign(&sigbuf, &siglen, message);
  } catch (np1secCryptoException& e) {
    log.error("unable to sign the outgoing message");
    throw;

  }

  std::string signature(reinterpret_cast<char*>(sigbuf), siglen);

  return signature;
  
}


bool np1secMessage::verify_message(np1secPublicKey sender_ephemeral_key) {
  if (cryptic->verify(signed_message, (unsigned char*)signature.c_str(), sender_ephemeral_key)   == gcry_error(GPG_ERR_NO_ERROR)) {
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
    throw np1secInvalidDataException;
  
}

std::string np1secMessage::decrypt_message(std::string encrypted_message) {
  return cryptic->Decrypt(encrypted_message);
}

np1secMessage::~np1secMessage() {
}
#endif  // SRC_MESSAGE_CC_
