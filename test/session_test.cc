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

#include "chat_mocker.h"
#include "chat_mocker_np1sec_plugin.h"

using namespace std;

//Just a wrapper to call the mocker send function 
void send_bare(std::string room_name, std::string sender_nickname, std::string message, void* data)
{
  static_cast<ChatMocker>(data)->send(room_name, sender_nickname, message);
  
};

class SessionTest : public ::testing::Test{

  //First we need to run a chatserver but this is always the case so I'm making
  //class to setup chat server
  ChatMocker mock_server;
  struct np1secAppOps mockops

  string mock_room_name = "testroom";
  
  virtual void SetUp() {
    bare_sender_data = static_cast<void*>mock_server;
    mockops.send_bare = send_bare;
    
  };
  
};


TEST_F(SessionTest, test_send) {
}

TEST_F(SessionTest, test_receive) {
}

TEST_F(SessionTest, test_init) {
  //first we need a username and we use it
  //to sign in the room
  string username = "sole-tester";
  np1secUserState* user_state = new np1secUserState(username, &mockops);

  mock_server.sign_in(username, chat_mocker_plugin_receive_handler, static_cast<void*>user_state);
  mock_server.join(mock_room_name);
  
  np1secSession new_session(room_name, name);
  ASSERT_TRUE(new_session.join());
  
}
