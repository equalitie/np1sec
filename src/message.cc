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

#ifndef SRC_MESSAGE_H_
#define SRC_MESSAGE_H_
#include message.h

np1secMessage::np1secMessage(SessionID session_id, std::string sender_id, strd::string user_message, np1secMessageType message_type, transcript_chain_hash, Cryptic cryptic) {
  session_id = session_id;
  sender_id = sender_id;
  user_message = user_message;
  message_type = message_type;
  transcript_chain_hash = transcript_chain_hash; 	
  cryptic = cryptic;
}

np1secMessage::np1secMessage(std::string raw_message, Cryptic cryptic) {
  std::string np1sec, encrypted_message, phased_message, signed_message, signature;
  np1sec = strtok(raw_message, ":O3");

  if (np1sec.compare("np1sec) {

    encoded_message = strtok(NULL, ":O3");

    phaseed_message = base64_decode(encrypted_message);
    ssession_id = strtok(phased_message, ":O3");
    encrypted_message = strtok(NULL, ":O3");

    phased_message = decrypt( base64_decode(encrypted_message));
    signed_message = strtok(phased_message, ":O3");
    signature = strtok(NULL, ":O3");

    if(verify_message(signed_message, signature)) {
      signed_message = base64_decode(signed_message);
      std::string temp;
      temp = strtok(signed_message, ":O3");
      if(sid.compare(temp)) {
        sender_id = strtok(NULL, ":O3");
        user_message = strtok(NULL, ":O3");
        meta_message = strtok(NULL, ":O3");
        transcript_chain_hash = strtok(NULL, ":O3");
        nonce = strtok(NULL, ":O3");
	message_id = compute_message_id(user_message);
      }
    }
  }

}

std::string format_sendable_message() {
  std::string base_message, phased_message, signature;

  base_message = session_id + ":O3";
  base_message += sender_id + ":O3";
  base_message += user_message + ":O3";
  base_message += meta_message + ":O3";
  base_message += transcript_chain_hash + ":O3";
  base_message += nonce + ":O3";

  base_message = base64_encode(base_message);

  signature = sign_message(base_message);
  base_message += signature + ":O3";

  base_message = base64_encode(base_message);

  phased_message = encrypt_message(base_message);
  phased_message = session_id + ":O3" + phased_message;

  phased_message = base64_encode(phased_message);
  phased_message = "np1sec:O3" + phased_message + ":O3";

  return phased_message;
}

uint32_t np1secMessage::compute_message_id(std::string cur_message) {

}

std::string np1secMessage::base64_encode(std::string message) {
  return otrl_base64_otr_encode((unsigned char*)message.c_str(), message.size());
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

  err = cryptic.Sign(&sigbuf, &siglen, message);

  std:string signature(sigbuf  
}


bool np1secMessage::verify_message(std::string signed_message, std::string signature) {
  if ( cryptic.Verify(signed_message, (unsigned char*)signature.c_str())
       == gcry_error(GPG_ERR_NO_ERROR)) {
    return True;
  } 

  return false;
}

std::string np1secMessage::encrypt_message(std::string signed_message) {

 return cryptic.Encrypt(signed_message); 
}


std::string np1secMessage::decrypt_message(std::string encrypted_message) {

  decrypted_message = cryptic.Decrypt(encrypted_message);
}

np1secMessage::~np1secMessage() {
  return;
}
