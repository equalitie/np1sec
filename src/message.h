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
 * MERCHANTABILITY or FITNESS FOR A definederal Public
 * License along with this library; if not, write to tm_tokenshe Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef SRC_MESSAGE_H_
#define SRC_MESSAGE_H_

#include <utility>
#include <string>
#include <map>
#include <iostream>

#include "src/common.h"
#include "src/interface.h"
#include "src/crypt.h"
#include "src/base64.h"
#include "src/participant.h"
#include "src/session_id.h"

class np1secUserState;

class np1secMessage {
 protected:

  Cryptic* cryptic; //message class is never responsible to delete the cryptic object
  UnauthenticatedParticipantList session_view;

  std::vector<std::string> &split(const std::string &s,
                                  const std::string delim,
                                  std::vector<std::string> &elems) {
    std::string destructable_s(s);
    std::string token;
    size_t npos;
    while ((npos = destructable_s.find(delim)) != std::string::npos) {
      token = destructable_s.substr(0,npos);
      elems.push_back(token);
      size_t end = npos + delim.length();
      destructable_s.erase(0, end);
    }
    //we need to check to see if anything left and we send it
    //as the last token
    if (destructable_s.length())
      elems.push_back(destructable_s);

    return elems;
  }

  std::vector<std::string> split(const std::string& s, const std::string delim) {
    std::vector<std::string> elems;
    split(s, delim, elems);
    return elems;
  }

  /**
   * move the current offset to point to the next token, it checks that
   * we won't exceed the expected length of next token
   * otherwise throw message format exception
   */
  size_t move_offset_or_throw_up(const std::string& parsed_string, size_t current_offset, size_t move_window, size_t expected_field_length = 0) {
    if (parsed_string.size() < current_offset + move_window + expected_field_length) {
      logger.error("invalid length: total: " +  std::to_string(parsed_string.size()) +
                   " cur: " + std::to_string(current_offset) +
                   " f1: " + std::to_string(move_window) +
                   " f2: " + std::to_string(expected_field_length));
      throw np1secMessageFormatException();
    }

    return current_offset + move_window;
    
  }
  
  //aux formating functions
  std::string data_to_string(const DTByte data) {
    return std::string(reinterpret_cast<const char*>(&data), sizeof(DTByte));
  }

  std::string data_to_string(const DTShort data) {
    return std::string(reinterpret_cast<const char*>(&data), sizeof(DTShort));
  }

  std::string data_to_string(const DTLength data) {
    return std::string(reinterpret_cast<const char*>(&data), sizeof(DTLength));
  }

  uint32_t string_to_length(const char* data) {
    return uint32_t(*reinterpret_cast<const uint32_t*>(data));
  }

  uint16_t string_to_short(const char* data) {
    return uint16_t(*reinterpret_cast<const uint16_t*>(data));
  }

  uint8_t string_to_byte(const char* data) {
    return uint8_t(*reinterpret_cast<const uint8_t*>(data));
  }

  std::string check_and_chop_protocol_tag(const std::string& raw_message) {
    if (raw_message.substr(0, c_np1sec_protocol_name.size()) != c_np1sec_protocol_name)
      throw np1secMessageFormatException();
    //TODO:: do something intelligent here
    //should we warn the user about unencrypted message
    //and then return everything as the plain text?
    else
      return raw_message.substr(c_np1sec_protocol_name.size());
    
  }

  enum EncodeDataType {
    DT_BYTE,
    DT_SHORT,
    DT_HASH,
    DT_OPAQUE
  };

  /**
   *  returns the apporperiate string buffer which contains the data
   *  in data in opaque format (length attached)
   *
   */
  std::string encode_opaque_data(const std::string& data);

  /**
   *  gets a string starts with opaque data field 
   *  return a pairs of strings, first with the opaque data (without length)
   *  second the rest of the string
   */
  std::pair<std::string, std::string> decode_opaque_field(std::string opaque_data);
  
  bool check_version_validity(std::string& raw_protocol_less_message)
  {
    if (raw_protocol_less_message.size() < sizeof(DTShort))
      throw np1secMessageFormatException();

    return (*(reinterpret_cast<const DTShort*>(raw_protocol_less_message.data())) == c_np1sec_protocol_version);
    
  }
   
 public:
  enum np1secMessageType {
    UNKNOWN                     =0x00, //Invalid
    JOIN_REQUEST                =0x0a, //Session establishement
    PARTICIPANTS_INFO           =0x0b,
    JOINER_AUTH                 =0x0c,
    GROUP_SHARE                 =0x0d,
    SESSION_CONFIRMATION        =0x0e, //In session messages
    IN_SESSION_MESSAGE          =0x10,
    INADMISSIBLE               =0x20,
    TOTAL_NO_OF_MESSAGE_TYPE    //This should be always the last message type

  };

  enum np1secMessageSubType {
    JUST_ACK,
    USER_MESSAGE,
    LEAVE_MESSAGE,
    EPHEMERAL_KEY,
    KEY_SHARE,
    CONTRIBUTION_STATE
  };

  np1secMessageType message_type;
  SessionId session_id;
  DTLength sender_index;
  std::string sender_nick;
  MessageId message_id;
  MessageId sender_message_id;
  MessageId parent_id;
  HashBlock session_id_buffer;
  np1secMessageSubType message_sub_type;
  std::string user_message;
  std::string sys_message;
  np1secLoadFlag meta_load_flag;
  HashStdBlock transcript_chain_hash;
  std::string nonce;
  HashStdBlock z_sender;
  std::map<DTLength, std::string> authentication_table;
  std::string key_confirmation;
  std::string session_key_confirmation;
  std::string next_session_ephemeral_key;
  std::string joiner_info;
  std::vector<std::string> pstates;
  size_t no_of_participants;

  /** signature stuff */
  std::string signed_message; //we store the part of message
  //which supposed to be/is signed here so the session class
  //verifies the signature. The message class can not verify
  //the signature cause it does not keep track of the ephemeral
  //public key of the participants
  std::string signature;
  //unacceptable for format or invalid signature etc

  std::string encrypted_part_of_message; //it is used when we don't have
  //the key to decrypt yet till later.
  
   
  /** message hash and consistency necessities */
  HashStdBlock message_hash;
  std::string final_whole_message;

  /** to make sending by message itself possible*/
  np1secUserState* us;
  std::string room_name;
 
  /*
   * Construct a new np1secMessage based on a set of message components
   * as input
   */
  np1secMessage(Cryptic* cryptic = nullptr);

  /*
   * Construct a new np1secMessage based on a set of message components
   * based on an encrypted message as input
   */
  np1secMessage(std::string raw_message, Cryptic* cryptic = nullptr, size_t no_of_participants = 0);

  /**
   * @return if the message is of type PARTICIPANTS_INFO it returns 
   *         the list of participants with their ephemerals
   *         (session view)otherwise
   *         throw an exception
   */
  const UnauthenticatedParticipantList& get_session_view();

  std::string session_view_as_string();

  /**
   * Create PARTICIPANT_INFO system message
   *
   */
  void create_participant_info_msg(SessionId session_id, 
                                 UnauthenticatedParticipantList& session_view_list, 
                                 std::string key_confirmation,
                                 HashStdBlock z_sender);
 
  /**
   * create session_confirmation system message
   *
   */
  void create_session_confirmation_msg(SessionId session_id, 
                                       std::string session_key_confirmation,
                                       std::string next_session_ephemeral_key);

  /**
   * create JOIN_REQUEST system message
   *
   */
  void create_join_request_msg(UnauthenticatedParticipant joiner);
 
  /**
   * create JOINER_AUTH system message
   *
   */
  void create_joiner_auth_msg(SessionId session_id,
                          std::string key_confirmation,
                          std::string z_sender);

  /**
   * create GROUP_SHARE system message
   *
   */
  void create_group_share_msg(SessionId session_id, 
                                 std::string z_sender);

  /**
   * Append standard message end for system messages
   *
   */
  void append_msg_end(bool need_to_be_signed = true);

  /**
   * Create USER_MESSAGE
   *
   */
  std::string create_in_session_msg(SessionId session_id,
                                    uint32_t sender_index,
                                    uint32_t sender_own_id,
                                    uint32_t parent_id,
                                    HashStdBlock transcript_chain_hash,
                                    np1secMessageSubType message_sub_type,
                                    std::string user_message = "",
                                    HashStdBlock new_ephemeral_key = "",
                                    HashStdBlock new_share = "",
                                    const std::vector<std::string>& pstates = std::vector<std::string>()
                                    );


  void string_to_session_view(std::string sv_string);

  /**
   * returns true if session_id is set
   */
  bool has_sid() { return (session_id.get() != nullptr);}

  /**
   * Compute a unique globally ordered id from the time stamped message,
   * ultimately this function should be overridable by the client.
   */
  uint32_t compute_message_id(std::string cur_message);

  /**
   * This function is responsible for sending of bare messages
   *
   */
  void send(std::string room_name, np1secUserState* us);

  /**
   * Base 64 encode encrypted message
   *
   */
  std::string base64_encode(std::string message);

  /**
   * Base 64 decode encrypted message
   *
   */
  std::string base64_decode(std::string encode_message);

  /**
   * Create and return a signed form of the message
   *
   */
  std::string sign_message(std::string message);

  /**
   * Verify the message
   *
   */
  bool verify_message(np1secPublicKey sender_ephemeral_key);

  /**
   * Create and return an encrypted form of the signed message
   *
   */
  std::string encrypt_message(std::string signed_message);

  /**
   * Decrypt and return the raw form of the message
   *
   */
  std::string decrypt_message(std::string encrypted_message);

  /**
   * Compose message into sendable formt
   *
   */
  std::string format_sendable_message();

  /**
   * Format p_info message for inclusion for
   * standalone use
   *
   */
  void format_generic_message();

  /**
   * Unwrap p_info message into its constituent components
   *
   */
  void unwrap_generic_message(std::string b64ed_message);

  void unwrap_in_session_message(std::string u_message);

  /**
   * Format Meta message for inclusion with standard message or for
   * standalone use
   *
   */
  void format_meta_message();

  /**
   * Unwrap meta message into its constituent components
   *
   */
  void unwrap_meta_message();

  /**
   * Return string containing the current state for all participants
   *
   */
  std::string ustate_values(std::vector<std::string> pstates);

  /**
   * chop the key_confirmation from joiner auth and make a 
   * table out of it.
   */
  void build_authentication_table();

  /**
   * Destructor
   *
   */
  ~np1secMessage();

  /**
   * 
   *
   */
  HashStdBlock compute_hash();

};

#endif  // SRC_MESSAGE_H_
