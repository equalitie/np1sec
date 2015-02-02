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

np1secMessage::np1secMessage(SessionID session_id, std::string sender_id,
                            std::string user_message,
                            np1secMessageType message_type,
                            HashBlock* transcript_chain_hash,
                            np1secLoadFlag meta_load_flag,
                            std::string meta_load,
                            std::vector<std::string> pstates,
                            Cryptic cryptic) {
  session_id = session_id;
  sender_id = sender_id;
  user_message = user_message;
  message_type = message_type;
  transcript_chain_hash = transcript_chain_hash;
  if (message_type == PURE_META_MESSAGE) {
    meta_only = 1;
  }
  meta_load_flag = meta_load_flag;
  meta_load = meta_load;
  cryptic = cryptic;
  pstates = pstates;
}

np1secMessage::np1secMessage(std::string raw_message, Cryptic cryptic) {
  cryptic = cryptic;

  std::string np1sec, encrypted_message, phased_message,
              signed_message, signature;
  np1sec = strtok(&raw_message[0], ":O3");

  if (np1sec.compare("np1sec")) {
    encrypted_message = strtok(NULL, ":O3");

    phased_message = base64_decode(encrypted_message);
    std::string temp = strtok(&phased_message[0], ":O3");
    session_id = std::vector<uint8_t>(temp.begin(), temp.end());
    encrypted_message = strtok(NULL, ":O3");

    phased_message = decrypt_message(base64_decode(encrypted_message));
    signed_message = strtok(&phased_message[0], ":O3");
    signature = strtok(NULL, ":O3");

    if (verify_message(signed_message, signature)) {
      signed_message = base64_decode(signed_message);
      std::string temp;
      temp = strtok(&signed_message[0], ":O3");
      // TODO(bill): clarify session id check
//      if(session_id.compare(temp)) {
        sender_id = strtok(NULL, ":O3");
        user_message = strtok(NULL, ":O3");

        meta_message = strtok(NULL, ":O3");
        unwrap_meta_message();
        std::string hash_string = strtok(NULL, ":O3");
        memcpy(transcript_chain_hash, hash_string.c_str(), hash_string.size());
        nonce = strtok(NULL, ":O3");
        message_id = compute_message_id(user_message);
//      }
    }
  }
}

void np1secMessage::format_meta_message() {
  meta_message = "" + std::to_string(meta_only) + ":03";
  meta_message += ":03" + ustate_values();
  meta_message += ":03" + std::to_string(meta_load_flag);
  meta_message += ":03" + meta_load;
  meta_message = base64_encode(meta_message);
}

void np1secMessage::unwrap_meta_message() {
  meta_message = base64_decode(meta_message);
  meta_only = atoi(strtok(&meta_message[0], ":03"));
  std::string ustates = strtok(NULL, ":03");
  meta_load_flag = static_cast<np1secLoadFlag>(atoi(strtok(NULL, ":03")));
  meta_load = strtok(NULL, ":03");
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
  std::string sid_string(session_id.begin(), session_id.end());

  base_message = sid_string + ":O3";
  base_message += sender_id + ":O3";
  base_message += user_message + ":O3";

  format_meta_message();
  base_message += meta_message + ":O3";
  std::string hash_string(reinterpret_cast<char const*>(transcript_chain_hash));
  base_message += hash_string + ":O3";
  base_message += nonce + ":O3";

  base_message = base64_encode(base_message);

  signature = sign_message(base_message);
  base_message += signature + ":O3";

  base_message = base64_encode(base_message);

  phased_message = encrypt_message(base_message);
  phased_message = sid_string + ":O3" + phased_message;

  phased_message = base64_encode(phased_message);
  phased_message = "np1sec:O3" + phased_message + ":O3";

  return phased_message;
}

uint32_t np1secMessage::compute_message_id(std::string cur_message) {
  return NULL;
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

  err = cryptic.Sign(&sigbuf, &siglen, message);

  std::string signature(reinterpret_cast<char*>(sigbuf));

  return signature;
}


bool np1secMessage::verify_message(std::string signed_message,
                                   std::string signature) {
  if ( cryptic.Verify(signed_message, (unsigned char*)signature.c_str())
       == gcry_error(GPG_ERR_NO_ERROR)) {
    return true;
  }

  return false;
}

std::string np1secMessage::encrypt_message(std::string signed_message) {
  return cryptic.Encrypt(signed_message);
}


std::string np1secMessage::decrypt_message(std::string encrypted_message) {
  return cryptic.Decrypt(encrypted_message);
}

np1secMessage::~np1secMessage() {
  return;
}

#endif  // SRC_MESSAGE_CC_
