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

#include "contrib/gtest/include/gtest/gtest.h"
//#include "contrib/gtest/gtest.h"
#include "src/session.h"
#include "src/crypt.h"
#include "src/common.h"
#include "src/message.h"
#include "src/userstate.h"
#include "test/chat_mocker.h"
#include "test/chat_mocker_np1sec_plugin.h"

class MessageTest : public ::testing::Test{
  
protected: //gtest needs the elements to be protocted
  //First we need to run a chatserver but this is always the case so I'm making
  //class to setup chat server
  ChatMocker mock_server;
  struct np1secAppOps mockops;

  virtual void SetUp() {
    mockops.send_bare = send_bare;
    mockops.join = new_session_announce;
    mockops.leave = new_session_announce;
  };
};

TEST_F(MessageTest, test_compute_message_id) {
}

// TEST_F(MessageTest, test_np1secMessage_constructor) {
//   Cryptic cryptic;
//   SessionId session_id(reinterpret_cast<const uint8_t*>("abcdefgh"));
//   std::string sender_id = "test_user";
//   std::string user_message = "test message";
//   np1secMessage::np1secMessageType message_type = np1secMessage::USER_MESSAGE;
//   HashBlock* transcript_chain_hash = 0;
//   np1secLoadFlag meta_load_flag = NO_LOAD;
//   std::string meta_load = "";
//   std::vector<std::string> pstates = {"1"};
//   np1secUserState* us = new np1secUserState("tester", nullptr);
//   np1secMessage msg(session_id,
//                     sender_id,
//                     user_message,
//                     message_type,
//                     transcript_chain_hash,
//                     meta_load_flag,
//                     meta_load,
//                     pstates,
//                     &cryptic,
//                     &us);

//   ASSERT_EQ(msg.session_id, session_id);
//   ASSERT_EQ(msg.sender_id, sender_id);
//   ASSERT_EQ(msg.meta_load_flag, meta_load_flag);
//   ASSERT_EQ(msg.meta_load, meta_load);
//   ASSERT_EQ(msg.pstates, pstates);
// }

// TEST_F(MessageTest, test_format_meta_message) {
// }

TEST_F(MessageTest, test_participant_info){
  std::string room_name = "test_room_name";
  std::string base  = "0xfd, 0xfc, 0xfe, 0xfa";
  UnauthenticatedParticipantList session_view_list;
  HashBlock sid;
  SessionId session_id;
  HashBlock cur_auth_token; 
  np1secKeyShare cur_keyshare;


  memcpy(sid, base.c_str(), sizeof(HashBlock) );
  memcpy(cur_auth_token, base.c_str(), sizeof(HashBlock) );
  memcpy(cur_keyshare, base.c_str(), sizeof(HashBlock) );
  session_id.set(sid);
 
  np1secAppOps joiner_mockops = mockops;
  std::string joiner = "joiner";                                                         
  std::pair<ChatMocker*, std::string> mock_aux_joiner_data(&mock_server,joiner);         
  joiner_mockops.bare_sender_data = static_cast<void*>(&mock_aux_joiner_data);      
  np1secUserState* joiner_state = new np1secUserState(joiner, &joiner_mockops);     
  //They can use the same mock up as they are using the same mock server            
  joiner_state->init();

  Cryptic np1sec_ephemeral_crypto;
  np1sec_ephemeral_crypto.init();

  UnauthenticatedParticipant test_participant(*(joiner_state->myself),Cryptic::public_key_to_stringbuff(np1sec_ephemeral_crypto.get_ephemeral_pub_key()), true); 

  session_view_list.push_back(test_participant);

  np1secMessage outbound(session_id,
                                np1secMessage::PARTICIPANTS_INFO,
                                session_view_list,
                                std::string(reinterpret_cast<char*>(cur_auth_token), sizeof(HashBlock)),
                                "", //session conf
                                "", //joiner info
                                std::string(reinterpret_cast<char*>(cur_keyshare), sizeof(HashBlock)),
                                joiner_state,
                                room_name);  

  np1secMessage inbound(outbound.sys_message,
                               nullptr,
                               joiner_state,
                               room_name);
  ASSERT_EQ((*outbound.session_id), (*inbound.session_id));
}

TEST_F(MessageTest, test_join_auth){
  std::string room_name = "test_room_name";
  std::string base  = "0xfd, 0xfc, 0xfe, 0xfa";
  UnauthenticatedParticipantList session_view_list;
  HashBlock sid;
  SessionId session_id;
  HashBlock cur_auth_token; 
  np1secKeyShare cur_keyshare;


  memcpy(sid, base.c_str(), sizeof(HashBlock) );
  memcpy(cur_auth_token, base.c_str(), sizeof(HashBlock) );
  memcpy(cur_keyshare, base.c_str(), sizeof(HashBlock) );
  session_id.set(sid);
 
  np1secAppOps joiner_mockops = mockops;
  std::string joiner = "joiner";                                                         
  std::pair<ChatMocker*, std::string> mock_aux_joiner_data(&mock_server,joiner);         
  joiner_mockops.bare_sender_data = static_cast<void*>(&mock_aux_joiner_data);      
  np1secUserState* joiner_state = new np1secUserState(joiner, &joiner_mockops);     
  //They can use the same mock up as they are using the same mock server            
  joiner_state->init();

  Cryptic np1sec_ephemeral_crypto;
  np1sec_ephemeral_crypto.init();

  UnauthenticatedParticipant test_participant(*(joiner_state->myself),Cryptic::public_key_to_stringbuff(np1sec_ephemeral_crypto.get_ephemeral_pub_key()), true); 

  session_view_list.push_back(test_participant);

  np1secMessage outbound(session_id,
                         np1secMessage::JOINER_AUTH,
                                session_view_list,
                                std::string(reinterpret_cast<char*>(cur_auth_token), sizeof(HashBlock)),
                                "", //session conf
                                "", //joiner info
                                std::string(reinterpret_cast<char*>(cur_keyshare), sizeof(HashBlock)),
                                joiner_state,
                                room_name);  

  np1secMessage inbound(outbound.sys_message,
                               nullptr,
                               joiner_state,
                               room_name);
  ASSERT_EQ(outbound.message_type, inbound.message_type);

}

TEST_F(MessageTest, test_session_confirmation){

  std::string room_name = "test_room_name";
  std::string base  = "0xfd, 0xfc, 0xfe, 0xfa";
  UnauthenticatedParticipantList session_view_list;
  HashBlock sid;
  SessionId session_id;
  HashBlock cur_auth_token; 
  np1secKeyShare cur_keyshare;


  memcpy(sid, base.c_str(), sizeof(HashBlock) );
  memcpy(cur_auth_token, base.c_str(), sizeof(HashBlock) );
  memcpy(cur_keyshare, base.c_str(), sizeof(HashBlock) );
  session_id.set(sid);
 
  np1secAppOps joiner_mockops = mockops;
  std::string joiner = "joiner";                                                         
  std::pair<ChatMocker*, std::string> mock_aux_joiner_data(&mock_server,joiner);         
  joiner_mockops.bare_sender_data = static_cast<void*>(&mock_aux_joiner_data);      
  np1secUserState* joiner_state = new np1secUserState(joiner, &joiner_mockops);     
  //They can use the same mock up as they are using the same mock server            
  joiner_state->init();

  Cryptic np1sec_ephemeral_crypto;
  np1sec_ephemeral_crypto.init();

  UnauthenticatedParticipant test_participant(*(joiner_state->myself),Cryptic::public_key_to_stringbuff(np1sec_ephemeral_crypto.get_ephemeral_pub_key()), true); 

  session_view_list.push_back(test_participant);


  np1secMessage outbound(session_id,
                                    np1secMessage::SESSION_CONFIRMATION,
                                    session_view_list,
                                    "", //auth
                                    Cryptic::hash_to_string_buff(sid),
                                    "", //joiner_info
                                    "", //z
                                    joiner_state,
                                    room_name);

  np1secMessage inbound(outbound.sys_message,
                               nullptr,
                               joiner_state,
                               room_name);
  ASSERT_EQ(outbound.message_type, inbound.message_type);

}

TEST_F(MessageTest, test_join_request) {

  std::string room_name = "test_room_name";
  
  np1secAppOps joiner_mockops = mockops;
  std::string joiner = "joiner";                                                         
  std::pair<ChatMocker*, std::string> mock_aux_joiner_data(&mock_server,joiner);         
  joiner_mockops.bare_sender_data = static_cast<void*>(&mock_aux_joiner_data);      
  np1secUserState* joiner_state = new np1secUserState(joiner, &joiner_mockops);     
  //They can use the same mock up as they are using the same mock server            
  joiner_state->init();

  Cryptic np1sec_ephemeral_crypto;
  np1sec_ephemeral_crypto.init();

  UnauthenticatedParticipant test_participant(*(joiner_state->myself),Cryptic::public_key_to_stringbuff(np1sec_ephemeral_crypto.get_ephemeral_pub_key()), true); 


  np1secMessage join_message(np1secMessage::JOIN_REQUEST,
                             test_participant,
                             joiner_state,
                             room_name);
  

  np1secMessage received_join(join_message.sys_message, 
                              nullptr,
                              joiner_state,
                              room_name);  


  ASSERT_EQ(join_message.message_type, received_join.message_type);

}

// TEST_F(MessageTest, test_format_sendable_message) {
//   Cryptic cryptic;
//   SessionID session_id = {1};
//   std::string sender_id = "test_user";
//   std::string user_message = "test message";
//   np1secMessage::np1secMessageType message_type = np1secMessage::USER_MESSAGE;
//   HashBlock* transcript_chain_hash = 0;
//   np1secLoadFlag meta_load_flag = NO_LOAD;
//   std::string meta_load = "";
//   std::vector<std::string> pstates = {"1"};

//   np1secMessage msg(session_id,
//                     sender_id,
//                     user_message,
//                     message_type,
//                     transcript_chain_hash,
//                     meta_load_flag,
//                     meta_load,
//                     pstates,
//                     cryptic);

//   std::string sendable_msg = msg.format_sendable_message();
// }
