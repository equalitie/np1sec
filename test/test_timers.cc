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

/*
#include <utility>
#include "contrib/gtest/include/gtest/gtesh.h"
#include "src/session.h"
#include "src/userstate.h"
#include "test/chat_mocker.h"
#include "event2/event.h"

const uint32_t five_seconds_mic = 5000000; // Microseconds
const uint32_t five_seconds_mil = 5000; // Miliseconds
const std::string room_name = "Test room";
const std::string user_name = "Test user";
const uint32_t message_parent_id = 0;

class TimerTest : public ::testing::Test
{
protected:
  ChatMocker mock_server;
  struct event_base* base;
  np1secUserState* ustate;
  np1secAppOpps* appops;
  Cryptic* current_ephemeral_crypto;
  UnauthenticatedParticipantList& sole_participant_view;
  np1secSession* session;
  AckTimerOps* timerops;

  virtual void SetUp()
  {
    base = event_base_new();
    mock_server.initialize_event_manager(base);
    appops = new np1secAppOps(five_seconds_mil, five_seconds_mil, five_seconds_mil, five_seconds_mil);
    // Create a dummy keypair consisting of all 0s.
    uint8_t* keypair = malloc(sizeof(uint8_t) * 64);
    for (int i = 0; i < 64; i++) {
      keypair[i] = 0;
    }
    ustate = new np1secUserState(user_name, appops, keypair);
    current_ephemeral_crypto = ;
    sole_participant_view = ;
    session = new np1secSession(ustate, room_name, current_ephemeral_crypto, sole_participant_view);
    participant = ;
    timerops = new AckTimerOps(session, participant, message_parent_id);
  }
};

// TODO
// Either extend test_fire_timer and test_stop_timer to include some assertions to verify the
// correctness of each callback or else augment the calls to each callback so that each call has
// appropriate assertions made.
void test_fire_timer(ChatMocker chat_server, struct event_base* base, void (*timer)(void* arg), void* arg)
{
  pair<ChatMocker*, std::string>* encoded(&chat_server, "");
  std::string* identifier = set_timer(timer, arg, five_seconds_mic, encoded);
  event_base_dispatch(base);
  delete identifier;
}

void test_stop_timer(ChatMocker chat_server, struct event_base* base, void (*timer)(void* arg), void* arg)
{
  pair<ChatMocker*, std::string>* encoded(&chat_server, "");
  std::string* identifier = set_timer(timer, arg, five_seconds_mic, encoded);
  event_base_dispatch(base);
  axe_timer(identifier, encoded);
  delete identifier;
}

TEST_F(SessionTest, test_init) {
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

  //we need to call this after every action
  //receive your own key share and send confirmation
  mock_server.receive();

  //receive your own confirmation
  mock_server.receive(); //no need actually
}

TEST_F(TimerTest, test_timers)
{
  test_fire_timer(mock_server, base, cb_send_heartbeat, session);
  test_stop_timer(mock_server, base, cb_send_heartbeat, session);
  test_fire_timer(mock_server, base, cb_ack_not_received, timerops);
  test_stop_timer(mock_server, base, cb_ack_not_received, timerops);
  test_fire_timer(mock_server, base, cb_send_ack, timerops);
  test_stop_timer(mock_server, base, cb_send_ack, timerops);
  test_fire_timer(mock_server, base, cb_ack_not_sent, timerops);
  test_stop_timer(mock_server, base, cb_ack_not_sent, timerops);
  test_fire_timer(mock_server, base, cb_leave, timerops);
  test_stop_timer(mock_server, base, cb_leave, timerops);
}
*/
