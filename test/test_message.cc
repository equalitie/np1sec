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

#include <gtest/gtest.h>
#include "src/session.h"
#include "src/crypt.h"
#include "src/common.h"
#include "src/message.h"

class MessageTest : public ::testing::Test{};

TEST_F(MessageTest, test_compute_message_id) {
}


TEST_F(MessageTest, test_np1secMessage_constructor) {
  Cryptic cryptic;
  SessionID session_id = {1};
  std::string sender_id = "test_user";
  std::string user_message = "test message";
  np1secMessageType message_type = USER_MESSAGE;
  HashBlock* transcript_chain_hash = 0;
  np1secLoadFlag meta_load_flag = NO_LOAD;
  std::string meta_load = "";
  std::vector<std::string> pstates = {"1"};

  np1secMessage msg(session_id,
                    sender_id,
                    user_message,
                    message_type,
                    transcript_chain_hash,
                    meta_load_flag,
                    meta_load,
                    pstates,
                    cryptic);

  ASSERT_EQ(msg.session_id, session_id);
  ASSERT_EQ(msg.sender_id, sender_id);
  ASSERT_EQ(msg.meta_load_flag, meta_load_flag);
  ASSERT_EQ(msg.meta_load, meta_load);
  ASSERT_EQ(msg.pstates, pstates);
}

TEST_F(MessageTest, test_format_meta_message) {
}

TEST_F(MessageTest, test_format_sendable_message) {
  Cryptic cryptic;
  SessionID session_id = {1};
  std::string sender_id = "test_user";
  std::string user_message = "test message";
  np1secMessageType message_type = USER_MESSAGE;
  HashBlock* transcript_chain_hash = 0;
  np1secLoadFlag meta_load_flag = NO_LOAD;
  std::string meta_load = "";
  std::vector<std::string> pstates = {"1"};

  np1secMessage msg(session_id,
                    sender_id,
                    user_message,
                    message_type,
                    transcript_chain_hash,
                    meta_load_flag,
                    meta_load,
                    pstates,
                    cryptic);

  std::string sendable_msg = msg.format_sendable_message();

}
