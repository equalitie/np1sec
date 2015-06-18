/**
 * Multiparty Off-the-Record Messaging library
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
#include <fstream>
#include <string>
#include <cstdio> // Required for `remove` function to delete files

#include "src/session.h"
#include "src/userstate.h"

#include "src/crypt.h"
#include "src/common.h"
#include "src/message.h"
#include "src/interface.h"

#include "test/chat_mocker.h"
#include "test/chat_mocker_np1sec_plugin.h"

using namespace std;

const std::string callback_log =  "callbackoutput.txt";

class SessionTest : public ::testing::Test{

protected: //gtest needs the elements to be protocted
  //First we need to run a chatserver but this is always the case so I'm making
  //class to setup chat server
  ChatMocker mock_server;
  np1secAppOps* mockops;
  struct event_base* base;

  string mock_room_name;
  
  virtual void SetUp() {
  uint32_t hundred_mili_sec = 100;
  uint32_t one_sec = 1000;
  //uint32_t two_sec = 2000;
  //uint32_t ten_sec = 10000;

      // np1secAppOps(uint32_t ACK_GRACE_INTERVAL,
      //          uint32_t REKEY_GRACE_INTERVAL,
      //          uint32_t INTERACTION_GRACE_INTERVAL,
      //          uint32_t BROADCAST_LATENCY)

    mockops = new np1secAppOps(hundred_mili_sec, one_sec, hundred_mili_sec, hundred_mili_sec);
    mockops->send_bare = send_bare;
    mockops->join = new_session_announce;
    mockops->leave = new_session_announce;
    mockops->display_message = display_message;
    mockops->set_timer = set_timer;
    mockops->axe_timer = axe_timer;
    //mockops->am_i_alone = am_i_alone;

    // Gets information about the currently running test.
// Do NOT delete the returned object - it's managed by the UnitTest class.
    const ::testing::TestInfo* const test_info =
      ::testing::UnitTest::GetInstance()->current_test_info();
    
    mock_room_name = test_info->name();
    mock_room_name += "_room";

    //mock_server.initialize_event_manager(base);
  // Configure the logger to write to `callback_log` for the sake of checking 
  };
  
};

// Callback for set_timer
// Checks that a line containing "HEARTBEAT" was written to the `callback_log` file.
// void check_heartbeat_log(void* arg)
// {
//   ChatMocker* server = reinterpret_cast<ChatMocker*>(arg);
//   std::ifstream in;
//   in.open(callback_log, std::ifstream::in);
//   std::string log_line;
//   bool found_heartbeat = false;

//   ASSERT_TRUE(in.good());
//   while (std::getline(in, log_line)) {
//     found_heartbeat = found_heartbeat || log_line.find("HEARTBEAT") != std::string::npos;
//   }
//   in.close();
//   server->end_event_loop();
//   ASSERT_TRUE(found_heartbeat);
// }

// Callback for set_timer
// Checks that `callback_log` does not exist. 
// // void check_not_heartbeat_log(void* arg)
// // {
// //   ChatMocker* server = reinterpret_cast<ChatMocker*>(arg);
// //   std::ifstream in;
// //   in.open(callback_log, std::ifstream::in);
// //   std::string log_line;
// //   bool found_log_file = in.good();
// //   server->end_event_loop();
// //   ASSERT_FALSE(found_log_file);
// // }

// // A callback function that will always cause a test failure.
// // Used to test that axe_timer prevents a queued timer event from firing.
// void fail(void* arg)
// {
//   logger.error("fail() called despite axing of timer");
//   ASSERT_TRUE(false);
// }


// Callback for set_timer
// Checks that a line containing "HEARTBEAT" was written to the `callback_log` file.
void check_log_for_phrase(void* arg)
{
  std::pair<ChatMocker*, std::string>* server_and_phrase = reinterpret_cast<std::pair<ChatMocker*, std::string>*>(arg);
  ChatMocker* server = server_and_phrase->first;
  std::string catch_phrase = server_and_phrase->second;
  std::ifstream in;
  ASSERT_NO_THROW(in.open(callback_log, std::ifstream::in));
  std::string log_line;
  bool found_phrase = false;

  logger.info("reading the log for catch phrase");

  ASSERT_TRUE(in.good());
  while (std::getline(in, log_line)) {
    found_phrase = found_phrase || log_line.find(catch_phrase) != std::string::npos;
    
  }
  in.close();
  server->end_event_loop();
  ASSERT_TRUE(found_phrase);
}


// TEST_F(SessionTest, test_heartbeat_timer)
// {
//   //first we need a username and we use it
//   //to sign in the room
//   string username = "sole-tester";
//   std::pair<ChatMocker*, string> mock_aux_data(&mock_server,username);
//   mockops->bare_sender_data = static_cast<void*>(&mock_aux_data);

//   np1secUserState* user_state = new np1secUserState(username, mockops);
//   user_state->init();

//   pair<np1secUserState*, ChatMocker*> user_server_state(user_state, &mock_server);

//   //client login and join
//   mock_server.sign_in(username, chat_mocker_np1sec_plugin_receive_handler, static_cast<void*>(&user_server_state));
//   mock_server.join(mock_room_name, user_state->user_nick());

//   //we need to call this after every action
//   //receive your own key share and send confirmation
//   mock_server.receive();

//   // Write HEARTBEAT to `callback_log`
//   logger.config(true, true, callback_log);
//   logger.info("Writing HEARTBEAT\n");
//   logger.config(true, false, "");
//   uint32_t timeout = mockops->c_heartbeating_interval * 10;
//   pair<ChatMocker*, std::string>* encoded = new pair<ChatMocker*, std::string>(
//     &mock_server, "");
//   logger.info("Setting check_heartbeat_log callback");
//   std::string* identifier = reinterpret_cast<std::string*>(
//     set_timer(check_heartbeat_log, &mock_server, timeout, encoded));
//   event_base_dispatch(base);
//   remove(callback_log.c_str());
//   // Give the `fail` callback a little more time, in case axing takes some time.
//   logger.info("Setting fail callback");
//   identifier = reinterpret_cast<std::string*>(
//     set_timer(fail, nullptr, timeout * 9, encoded));
//   // Although slightly superfluous, we add a timer to verify that the log file
//   // doesn't exist for the purpose of testing that axe_timer leaves other events.
//   logger.info("Setting check_not_heartbeat_log callback");
//   std::string* identifier2 = reinterpret_cast<std::string*>(
//     set_timer(check_not_heartbeat_log, &mock_server, timeout, encoded));
//   logger.info("Dispatching the event base");
//   event_base_dispatch(base);
//   logger.info("Axing the fail callback");
//   axe_timer(identifier, encoded);
//   delete identifier;
//   delete identifier2;

//   exit(0);
// }

// TEST_F(SessionTest, test_cb_ack_not_received){
//   //Awaiting test frame
// }

// TEST_F(SessionTest, test_cb_send_ack){
//   //Awaiting test frame
// }

/*TEST_F(SessionTest, test_add_message_to_transcript) {
 uint32_t id = 1;
 std:string message = "test message";
 HashBlock* hb;
 compute_message_hash(hb, message);
 session.add_message_to_transcript(message, id);
 
 ASSERT_EQ(hb, session.transcript_chain[id]);

 }

TEST_F(SessionTest, test_start_ack_timers) {
  //Gen participant list
  Participant p;

  session.start_ack_timers();
  //Check timer is present for given participant
  map<Participant, struct event>::iterator it = session.awaiting_ack.find(p.id);
 
  ASSERT_NE(it, session.awaiting_ack.end());

} 

TEST_F(SessionTest, test_receive_ack_timer) {

  std::string sender_id = "1";

  session.start_receive_ack_timer(sender_id);

  map<Participant, struct event>::iterator it = session.acks_to_send.find(sender_id);
  ASSERT_NE(it, session.acks.to_send.end());

}

TEST_F(SessionTest, test_stop_timer_send) {
  //Gen participant list
  Participant p;

  session.stop_timer_send();

  map<Participant, struct event>::iterator it = session.acks_to_send.find(p.id);

  ASSERT_EQ(it, session.acks_to_send.end());

}

TEST_F(SessionTest, test_stop_timer_receive) {
  std::string acknowledger_id = "1";

  session.stop_timer_receive(acknowledger_id);

  map<Participant, struct event>::iterator it = session.awaiting_ack.find(
                                                          acknowledger_id);
  ASSERT_EQ(it, session.awaiting_ack.end());

}

TEST_F(SessionTest, test_send) {
  std::string message = "This is a test message we hope to see on the otherside.";

  bool result = session.send(message);

  ASSERT_TRUE(result);
  

}

TEST_F(SessionTest, test_receive) {
  //set up comparison message
  np1secMessage test_example();
  std::string raw_content = "";
  std::sender_id = "1"; 
  np1secMessage test_result = session.receive(raw_message, sender_id);
  

  }*/

TEST_F(SessionTest, test_init) {
  //first we need a username and we use it
  //to sign in the room
  string username = "sole-tester";
  std::pair<ChatMocker*, string> mock_aux_data(&mock_server,username);
  mockops->bare_sender_data = static_cast<void*>(&mock_aux_data);

  np1secUserState* user_state = new np1secUserState(username, mockops);
  ASSERT_TRUE(user_state->init());

  pair<np1secUserState*, ChatMocker*> user_server_state(user_state, &mock_server);

  //client login and join
  mock_server.sign_in(username, chat_mocker_np1sec_plugin_receive_handler, static_cast<void*>(&user_server_state));
  mock_server.join(mock_room_name, user_state->user_nick());

  //we need to call this after every action
  //receive your own key share and send confirmation
  mock_server.receive();

  //receive your own confirmation
  mock_server.receive(); //no need actually

  /*UnauthenticatedParticipantList participants_in_the_room;
    participants_in_the_room.push_back((UnauthenticatedParticipant){user_state->user_nick(), ""});*/

  //user_state->join(mock_room_name, mock_server.participant_list(mock_room_name));

  //tell np1sec to go through join: no need to call this, we receive
  //our own join message in our receive-handler
  //in general, if it is not the case then the client 
  //duty is to implement a handler to call join.
  //chat_mocker_np1sec_plugin_join(mock_room_name, &user_server_state);

  //np1secSession new_session(user_state, mock_room_name, participants_in_the_room);
  //ASSERT_TRUE(new_session.join(user_state->user_id_key_pair()));
  
}

TEST_F(SessionTest, test_second_join) {
  string mock_room_name = string(__FUNCTION__) + "room";
  //first we need a username and we use it
  //to sign in the room
  //return;
  string creator = "creator";
  np1secAppOps creator_mockops = *mockops;
  std::pair<ChatMocker*, string> mock_aux_creator_data(&mock_server,creator);
  creator_mockops.bare_sender_data = static_cast<void*>(&mock_aux_creator_data);
  np1secUserState* creator_state = new np1secUserState(creator, &creator_mockops);
  creator_state->init();
  
  np1secAppOps joiner_mockops = *mockops;
  string joiner = "joiner";
  std::pair<ChatMocker*, string> mock_aux_joiner_data(&mock_server,joiner);
  joiner_mockops.bare_sender_data = static_cast<void*>(&mock_aux_joiner_data);
  np1secUserState* joiner_state = new np1secUserState(joiner, &joiner_mockops);
  //They can use the same mock up as they are using the same mock server
  joiner_state->init();

  pair<np1secUserState*, ChatMocker*> creator_server_state(creator_state, &mock_server);
  pair<np1secUserState*, ChatMocker*> joiner_server_state(joiner_state, &mock_server);

  //everybody signs in
  //creator
  mock_server.sign_in(creator, chat_mocker_np1sec_plugin_receive_handler, static_cast<void*>(&creator_server_state));
  //joiner
  mock_server.sign_in(joiner, chat_mocker_np1sec_plugin_receive_handler, static_cast<void*>(&joiner_server_state));

  //creator joins first
  mock_server.join(mock_room_name, creator_state->user_nick());

  //receive your share and own confirmation
  mock_server.receive();
  
  //then joiner joins
  mock_server.join(mock_room_name, joiner_state->user_nick());

  //receive the join requests and start reations
  mock_server.receive();
  
  //tell np1sec to go through join
  //chat_mocker_np1sec_plugin_join(mock_room_name, &joiner_server_state);

  //np1secSession new_session(user_state, mock_room_name, participants_in_the_room);
  //ASSERT_TRUE(new_session.join(user_state->user_id_key_pair()));

}

TEST_F(SessionTest, test_solitary_talk) {
  //first we need a username and we use it
  //to sign in the room
  //return;
  string username = "sole-tester";
  std::pair<ChatMocker*, string> mock_aux_data(&mock_server,username);
  mockops->bare_sender_data = static_cast<void*>(&mock_aux_data);
  np1secUserState* user_state = new np1secUserState(username, mockops);
  user_state->init();

  pair<np1secUserState*, ChatMocker*> user_server_state(user_state, &mock_server);

  //client login and join
  mock_server.sign_in(username, chat_mocker_np1sec_plugin_receive_handler, static_cast<void*>(&user_server_state));
  mock_server.join(mock_room_name, user_state->user_nick());

  //tell np1sec to go through join
  //chat_mocker_np1sec_plugin_join(mock_room_name, &user_server_state);

  //we need to call this after every action
  //receive your own key share and send confirmation
  mock_server.receive();

  //say something
  chat_mocker_np1sec_plugin_send(mock_room_name, "Hello, World!", &user_server_state);

  //and receive it
  mock_server.receive();
  
}

TEST_F(SessionTest, test_join_talk) {
  //return;
  //first we need a username and we use it
  //to sign in the room
  string creator = "creator";
  np1secAppOps creator_mockops = *mockops;
  std::pair<ChatMocker*, string> mock_aux_creator_data(&mock_server,creator);
  creator_mockops.bare_sender_data = static_cast<void*>(&mock_aux_creator_data);
  np1secUserState* creator_state = new np1secUserState(creator, &creator_mockops);
  creator_state->init();
  
  np1secAppOps joiner_mockops = *mockops;
  string joiner = "joiner";
  std::pair<ChatMocker*, string> mock_aux_joiner_data(&mock_server,joiner);
  joiner_mockops.bare_sender_data = static_cast<void*>(&mock_aux_joiner_data);
  np1secUserState* joiner_state = new np1secUserState(joiner, &joiner_mockops);
  //They can use the same mock up as they are using the same mock server
  joiner_state->init();

  pair<np1secUserState*, ChatMocker*> creator_server_state(creator_state, &mock_server);
  pair<np1secUserState*, ChatMocker*> joiner_server_state(joiner_state, &mock_server);

  //everybody signs in
  //creator
  mock_server.sign_in(creator, chat_mocker_np1sec_plugin_receive_handler, static_cast<void*>(&creator_server_state));
  //joiner
  mock_server.sign_in(joiner, chat_mocker_np1sec_plugin_receive_handler, static_cast<void*>(&joiner_server_state));

  //creator joins first
  mock_server.join(mock_room_name, creator_state->user_nick());

  //receive your share and own confirmation
  mock_server.receive();
  
  //then joiner joins
  mock_server.join(mock_room_name, joiner_state->user_nick());

  //receive the join requests and start reations
  mock_server.receive();
  
  //tell np1sec to go through join
  //chat_mocker_np1sec_plugin_join(mock_room_name, &joiner_server_state);

  //np1secSession new_session(user_state, mock_room_name, participants_in_the_room);
  //ASSERT_TRUE(new_session.join(user_state->user_id_key_pair()));

  //say something
  chat_mocker_np1sec_plugin_send(mock_room_name, "Hello, Joiner!", &creator_server_state);
  //and receive it
  mock_server.receive();

  //chat_mocker_np1sec_plugin_send(mock_room_name, "Hello, Creator!", &joiner_server_state);
  //and receive it
  mock_server.receive();

}

TEST_F(SessionTest, test_three_party_chat) {
  //return;
  //first we need a username and we use it
  //to sign in the room
  string alice = "alice";
  np1secAppOps alice_mockops = *mockops;
  std::pair<ChatMocker*, string> mock_aux_alice_data(&mock_server,alice);
  alice_mockops.bare_sender_data = static_cast<void*>(&mock_aux_alice_data);
  np1secUserState* alice_state = new np1secUserState(alice, &alice_mockops);
  alice_state->init();
  
  np1secAppOps bob_mockops = *mockops;
  string bob = "bob";
  std::pair<ChatMocker*, string> mock_aux_bob_data(&mock_server,bob);
  bob_mockops.bare_sender_data = static_cast<void*>(&mock_aux_bob_data);
  np1secUserState* bob_state = new np1secUserState(bob, &bob_mockops);
  //They can use the same mock up as they are using the same mock server
  bob_state->init();

  np1secAppOps charlie_mockops = *mockops;
  string charlie = "charlie";
  std::pair<ChatMocker*, string> mock_aux_charlie_data(&mock_server,charlie);
  charlie_mockops.bare_sender_data = static_cast<void*>(&mock_aux_charlie_data);
  np1secUserState* charlie_state = new np1secUserState(charlie, &charlie_mockops);
  charlie_state->init();

  pair<np1secUserState*, ChatMocker*> alice_server_state(alice_state, &mock_server);
  pair<np1secUserState*, ChatMocker*> bob_server_state(bob_state, &mock_server);
  pair<np1secUserState*, ChatMocker*> charlie_server_state(charlie_state, &mock_server);

  //everybody signs in
  //alice
  mock_server.sign_in(alice, chat_mocker_np1sec_plugin_receive_handler, static_cast<void*>(&alice_server_state));
  //bob
  mock_server.sign_in(bob, chat_mocker_np1sec_plugin_receive_handler, static_cast<void*>(&bob_server_state));
  //charlie
  mock_server.sign_in(charlie, chat_mocker_np1sec_plugin_receive_handler, static_cast<void*>(&charlie_server_state));

  //alice joins first
  mock_server.join(mock_room_name, alice_state->user_nick());

  //receive your share and own confirmation
  mock_server.receive();
  
  //then bob joins
  mock_server.join(mock_room_name, bob_state->user_nick());

  //receive the join requests and start reations
  mock_server.receive();

  //say something
  chat_mocker_np1sec_plugin_send(mock_room_name, "Hello, I'm Alice!", &alice_server_state);
  //and receive it
  mock_server.receive();

  //then charlie joins
  mock_server.join(mock_room_name, charlie_state->user_nick());

  chat_mocker_np1sec_plugin_send(mock_room_name, "Ah Charlie is here again!", &bob_server_state);

  //receive the join requests and start reations
  mock_server.receive();

  chat_mocker_np1sec_plugin_send(mock_room_name, "Hello, I'm Charlie!", &charlie_server_state);
  //and receive it
  mock_server.receive();

}

TEST_F(SessionTest, test_solitary_leave) {
  //first we need a username and we use it
  //to sign in the room
  //return;
  string username = "sole-tester";
  std::pair<ChatMocker*, string> mock_aux_data(&mock_server, username);
  mockops->bare_sender_data = static_cast<void*>(&mock_aux_data);
  np1secUserState* user_state = new np1secUserState(username, mockops);
  user_state->init();

  pair<np1secUserState*, ChatMocker*> user_server_state(user_state, &mock_server);

  //client login and join
  mock_server.sign_in(username, chat_mocker_np1sec_plugin_receive_handler, static_cast<void*>(&user_server_state));
  mock_server.join(mock_room_name, user_state->user_nick());

  //we need to call this after every action
  //receive your own key share and send confirmation
  mock_server.receive();

  mock_server.intend_to_leave(mock_room_name, user_state->user_nick());

  mock_server.receive();

  
}

TEST_F(SessionTest, test_leave_from_2p_conv) {
  //first we need a username and we use it
  //to sign in the room
  //return;
  string creator = "creator";
  np1secAppOps creator_mockops = *mockops;
  std::pair<ChatMocker*, string> mock_aux_creator_data(&mock_server,creator);
  creator_mockops.bare_sender_data = static_cast<void*>(&mock_aux_creator_data);
  np1secUserState* creator_state = new np1secUserState(creator, &creator_mockops);
  creator_state->init();
  
  np1secAppOps joiner_mockops = *mockops;
  string joiner = "joiner";
  std::pair<ChatMocker*, string> mock_aux_joiner_data(&mock_server,joiner);
  joiner_mockops.bare_sender_data = static_cast<void*>(&mock_aux_joiner_data);
  np1secUserState* joiner_state = new np1secUserState(joiner, &joiner_mockops);
  //They can use the same mock up as they are using the same mock server
  joiner_state->init();

  pair<np1secUserState*, ChatMocker*> creator_server_state(creator_state, &mock_server);
  pair<np1secUserState*, ChatMocker*> joiner_server_state(joiner_state, &mock_server);

  //everybody signs in
  //creator
  mock_server.sign_in(creator, chat_mocker_np1sec_plugin_receive_handler, static_cast<void*>(&creator_server_state));
  //joiner
  mock_server.sign_in(joiner, chat_mocker_np1sec_plugin_receive_handler, static_cast<void*>(&joiner_server_state));

  //creator joins first
  mock_server.join(mock_room_name, creator_state->user_nick());

  //receive your share and own confirmation
  mock_server.receive();
  
  //then joiner joins
  mock_server.join(mock_room_name, joiner_state->user_nick());

  //receive the join requests and start reations
  mock_server.receive();
  
  //creator says I'm leaving the room.
  mock_server.intend_to_leave(mock_room_name, creator_state->user_nick());

  mock_server.receive();

  //this should be called by the receive
  mock_server.leave(mock_room_name, creator_state->user_nick());

  //and receive it
  mock_server.receive();
  
}

TEST_F(SessionTest, test_immature_leave_from_2p_conv) {
  //first we need a username and we use it
  //to sign in the room
  //return;
  string creator = "creator";
  np1secAppOps creator_mockops = *mockops;
  std::pair<ChatMocker*, string> mock_aux_creator_data(&mock_server,creator);
  creator_mockops.bare_sender_data = static_cast<void*>(&mock_aux_creator_data);
  np1secUserState* creator_state = new np1secUserState(creator, &creator_mockops);
  creator_state->init();
  
  np1secAppOps joiner_mockops = *mockops;
  string joiner = "joiner";
  std::pair<ChatMocker*, string> mock_aux_joiner_data(&mock_server,joiner);
  joiner_mockops.bare_sender_data = static_cast<void*>(&mock_aux_joiner_data);
  np1secUserState* joiner_state = new np1secUserState(joiner, &joiner_mockops);
  //They can use the same mock up as they are using the same mock server
  joiner_state->init();

  pair<np1secUserState*, ChatMocker*> creator_server_state(creator_state, &mock_server);
  pair<np1secUserState*, ChatMocker*> joiner_server_state(joiner_state, &mock_server);

  //everybody signs in
  //creator
  mock_server.sign_in(creator, chat_mocker_np1sec_plugin_receive_handler, static_cast<void*>(&creator_server_state));
  //joiner
  mock_server.sign_in(joiner, chat_mocker_np1sec_plugin_receive_handler, static_cast<void*>(&joiner_server_state));

  //creator joins first
  mock_server.join(mock_room_name, creator_state->user_nick());

  //receive your share and own confirmation
  mock_server.receive();
  
  //then joiner joins
  mock_server.join(mock_room_name, joiner_state->user_nick());

  //receive the join requests and start reations
  mock_server.receive();
  
  //Joiner just leave without announcing the intention and doing the consistency
  //check
  mock_server.leave(mock_room_name, joiner_state->user_nick());

  //and receive it
  mock_server.receive();
  
}

TEST_F(SessionTest, test_concurrent_join) {
  //return;
  //first we need a username and we use it
  //to sign in the room
  string alice = "alice";
  np1secAppOps alice_mockops = *mockops;
  std::pair<ChatMocker*, string> mock_aux_alice_data(&mock_server,alice);
  alice_mockops.bare_sender_data = static_cast<void*>(&mock_aux_alice_data);
  np1secUserState* alice_state = new np1secUserState(alice, &alice_mockops);
  alice_state->init();
  
  np1secAppOps bob_mockops = *mockops;
  string bob = "bob";
  std::pair<ChatMocker*, string> mock_aux_bob_data(&mock_server,bob);
  bob_mockops.bare_sender_data = static_cast<void*>(&mock_aux_bob_data);
  np1secUserState* bob_state = new np1secUserState(bob, &bob_mockops);
  //They can use the same mock up as they are using the same mock server
  bob_state->init();

  np1secAppOps charlie_mockops = *mockops;
  string charlie = "charlie";
  std::pair<ChatMocker*, string> mock_aux_charlie_data(&mock_server,charlie);
  charlie_mockops.bare_sender_data = static_cast<void*>(&mock_aux_charlie_data);
  np1secUserState* charlie_state = new np1secUserState(charlie, &charlie_mockops);
  charlie_state->init();

  pair<np1secUserState*, ChatMocker*> alice_server_state(alice_state, &mock_server);
  pair<np1secUserState*, ChatMocker*> bob_server_state(bob_state, &mock_server);
  pair<np1secUserState*, ChatMocker*> charlie_server_state(charlie_state, &mock_server);

  //everybody signs in
  //alice
  mock_server.sign_in(alice, chat_mocker_np1sec_plugin_receive_handler, static_cast<void*>(&alice_server_state));
  //bob
  mock_server.sign_in(bob, chat_mocker_np1sec_plugin_receive_handler, static_cast<void*>(&bob_server_state));
  //charlie
  mock_server.sign_in(charlie, chat_mocker_np1sec_plugin_receive_handler, static_cast<void*>(&charlie_server_state));

  //alice joins first
  mock_server.join(mock_room_name, alice_state->user_nick());

  //receive your share and own confirmation
  mock_server.receive();
  
  //then bob joins
  mock_server.join(mock_room_name, bob_state->user_nick());
  //then charlie joins
  mock_server.join(mock_room_name, charlie_state->user_nick());

  //receive the join requests and start reations
  mock_server.receive();

  chat_mocker_np1sec_plugin_send(mock_room_name, "Happy concurrent join!", &charlie_server_state);
  
  mock_server.receive();

}

TEST_F(SessionTest, test_concurrent_join_leave) {

  //this test is not working with 3 participants cause chatmocker number of particiants
  //is comming from the server while everything else is based on messages
  //so from client side.
  //to make it work is that the number of participant also should come from
  //client side. so for example the @P@JOIN message should have the number
  //of participants
  string alice = "alice";
  np1secAppOps alice_mockops = *mockops;
  std::pair<ChatMocker*, string> mock_aux_alice_data(&mock_server,alice);
  alice_mockops.bare_sender_data = static_cast<void*>(&mock_aux_alice_data);
  np1secUserState* alice_state = new np1secUserState(alice, &alice_mockops);
  alice_state->init();
  
  np1secAppOps bob_mockops = *mockops;
  string bob = "bob";
  std::pair<ChatMocker*, string> mock_aux_bob_data(&mock_server,bob);
  bob_mockops.bare_sender_data = static_cast<void*>(&mock_aux_bob_data);
  np1secUserState* bob_state = new np1secUserState(bob, &bob_mockops);
  //They can use the same mock up as they are using the same mock server
  bob_state->init();

  np1secAppOps charlie_mockops = *mockops;
  string charlie = "charlie";
  std::pair<ChatMocker*, string> mock_aux_charlie_data(&mock_server,charlie);
  charlie_mockops.bare_sender_data = static_cast<void*>(&mock_aux_charlie_data);
  np1secUserState* charlie_state = new np1secUserState(charlie, &charlie_mockops);
  charlie_state->init();

  np1secAppOps david_mockops = *mockops;
  string david = "david";
  std::pair<ChatMocker*, string> mock_aux_david_data(&mock_server,david);
  david_mockops.bare_sender_data = static_cast<void*>(&mock_aux_david_data);
  np1secUserState* david_state = new np1secUserState(david, &david_mockops);
  david_state->init();

  pair<np1secUserState*, ChatMocker*> alice_server_state(alice_state, &mock_server);
  pair<np1secUserState*, ChatMocker*> bob_server_state(bob_state, &mock_server);
  pair<np1secUserState*, ChatMocker*> charlie_server_state(charlie_state, &mock_server);
  pair<np1secUserState*, ChatMocker*> david_server_state(david_state, &mock_server);

  //everybody signs in
  //alice
  mock_server.sign_in(alice, chat_mocker_np1sec_plugin_receive_handler, static_cast<void*>(&alice_server_state));
  //bob
  mock_server.sign_in(bob, chat_mocker_np1sec_plugin_receive_handler, static_cast<void*>(&bob_server_state));
  //charlie
  mock_server.sign_in(charlie, chat_mocker_np1sec_plugin_receive_handler, static_cast<void*>(&charlie_server_state));
  //david
  mock_server.sign_in(david, chat_mocker_np1sec_plugin_receive_handler, static_cast<void*>(&david_server_state));

  //alice joins first
  mock_server.join(mock_room_name, alice_state->user_nick());

  //receive your share and own confirmation
  mock_server.receive();
  
  //then bob joins
  mock_server.join(mock_room_name, bob_state->user_nick());
  //receive the join requests and start reations
  mock_server.receive();

  mock_server.join(mock_room_name, charlie_state->user_nick());
  mock_server.join(mock_room_name, david_state->user_nick());
  mock_server.leave(mock_room_name, charlie_state->user_nick());

  //receive the join requests and start reations
  mock_server.receive();

  chat_mocker_np1sec_plugin_send(mock_room_name, "Happy concurrent join/leave!", &david_server_state);
  
  mock_server.receive();

}

TEST_F(SessionTest, test_ression_forward_secrecy)
{
  //first we need a username and we use it
  //to sign in the room
  string username = "sole-tester";
  std::pair<ChatMocker*, string> mock_aux_data(&mock_server,username);
  mockops->bare_sender_data = static_cast<void*>(&mock_aux_data);

  np1secUserState* user_state = new np1secUserState(username, mockops);
  user_state->init();

  pair<np1secUserState*, ChatMocker*> user_server_state(user_state, &mock_server);

  //client login and join
  mock_server.sign_in(username, chat_mocker_np1sec_plugin_receive_handler, static_cast<void*>(&user_server_state));
  mock_server.join(mock_room_name, user_state->user_nick());

  //we need to call this after every action
  //receive your own key share and send confirmation
  mock_server.receive();

  // Write HEARTBEAT to `callback_log`
  string catch_phrase = "RESESSION";
  uint32_t timeout = mockops->c_session_life_span * 2;
  pair<ChatMocker*, std::string>* encoded = new pair<ChatMocker*, std::string>(
    &mock_server, catch_phrase);
  logger.config(true, true, callback_log);
  logger.info("waiting for " + to_string(timeout) + " millisecond for check_log callback to check the log....");
    std::string* identifier = reinterpret_cast<std::string*>(
  set_timer(check_log_for_phrase, encoded, timeout, encoded));
  mock_server.dispatch_event_loop();
  remove(callback_log.c_str());
  delete identifier;
  logger.config(true, false, "");
}
