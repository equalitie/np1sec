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

#include "src/message.h"
#include "src/interface.h"

#include "test/chat_mocker.h"
#include "test/chat_mocker_np1sec_plugin.h"

using namespace std;
using namespace np1sec;

const std::string callback_log = "callbackoutput.txt";

class SessionTest : public ::testing::Test
{

  protected: // gtest needs the elements to be protocted
    // First we need to run a chatserver but this is always the case so I'm making
    // class to setup chat server
    ChatMocker mock_server;
    AppOps* mockops;
    struct event_base* base;

    string mock_room_name;

    virtual void SetUp()
    {
        uint32_t hundred_mili_sec = 100;
        uint32_t one_sec = 1000;
        // uint32_t two_sec = 2000;
        // uint32_t ten_sec = 10000;

        // AppOps(uint32_t ACK_GRACE_INTERVAL,
        //          uint32_t REKEY_GRACE_INTERVAL,
        //          uint32_t INTERACTION_GRACE_INTERVAL,
        //          uint32_t BROADCAST_LATENCY)

        mockops = new AppOps(hundred_mili_sec, one_sec, hundred_mili_sec, hundred_mili_sec);
        mockops->send_bare = send_bare;
        mockops->join = new_session_announce;
        mockops->leave = new_session_announce;
        mockops->display_message = display_message;
        mockops->set_timer = set_timer;
        mockops->axe_timer = axe_timer;
        // mockops->am_i_alone = am_i_alone;

        // Gets information about the currently running test.
        // Do NOT delete the returned object - it's managed by the UnitTest class.
        const ::testing::TestInfo* const test_info = ::testing::UnitTest::GetInstance()->current_test_info();

        mock_room_name = test_info->name();
        mock_room_name += "_room";

        // mock_server.initialize_event_manager(base);
        // Configure the logger to write to `callback_log` for the sake of checking
    };
};

/*TEST_F(SessionTest, test_add_message_to_transcript) {
 uint32_t id = 1;
 std:string message = "test message";
 HashBlock* hb;
 compute_message_hash(hb, message);
 session.add_message_to_transcript(message, id);

 ASSERT_EQ(hb, session.transcript_chain[id]);

 }*/

TEST_F(SessionTest, test_init)
{
    // first we need a username and we use it
    // to sign in the room
    string username = "sole-tester";
    std::pair<ChatMocker*, string> mock_aux_data(&mock_server, username);
    mockops->bare_sender_data = static_cast<void*>(&mock_aux_data);
    logger.debug("Set bare_sender_data");

    UserState user_state(username, mockops);
    logger.debug("Initialized user_state");

    pair<UserState*, ChatMocker*> user_server_state(&user_state, &mock_server);

    // client login and join
    logger.debug("Signing in");
    mock_server.sign_in(username, chat_mocker_np1sec_plugin_receive_handler, static_cast<void*>(&user_server_state));
    logger.debug("Joining");
    mock_server.join(mock_room_name, user_state.user_nick());
    logger.debug("Successfully joined");

    // we need to call this after every action
    // receive your own key share and send confirmation
    logger.debug("Receiving 1...");
    mock_server.receive();

    // receive your own confirmation
    logger.debug("Receiving 2...");
    mock_server.receive(); // no need actually

    /*UnauthenticatedParticipantList participants_in_the_room;
      participants_in_the_room.push_back((UnauthenticatedParticipant){user_state->user_nick(), ""});*/

    // user_state->join(mock_room_name, mock_server.participant_list(mock_room_name));

    // tell np1sec to go through join: no need to call this, we receive
    // our own join message in our receive-handler
    // in general, if it is not the case then the client
    // duty is to implement a handler to call join.
    // chat_mocker_np1sec_plugin_join(mock_room_name, &user_server_state);

    // np1secSession new_session(user_state, mock_room_name, participants_in_the_room);
    // ASSERT_TRUE(new_session.join(user_state->user_id_key_pair()));
}

TEST_F(SessionTest, test_second_join)
{
    string mock_room_name = string(__FUNCTION__) + "room";
    // first we need a username and we use it
    // to sign in the room
    // return;
    string creator = "creator";
    AppOps creator_mockops = *mockops;
    std::pair<ChatMocker*, string> mock_aux_creator_data(&mock_server, creator);
    creator_mockops.bare_sender_data = static_cast<void*>(&mock_aux_creator_data);
    UserState creator_state(creator, &creator_mockops);

    AppOps joiner_mockops = *mockops;
    string joiner = "joiner";
    std::pair<ChatMocker*, string> mock_aux_joiner_data(&mock_server, joiner);
    joiner_mockops.bare_sender_data = static_cast<void*>(&mock_aux_joiner_data);
    UserState joiner_state(joiner, &joiner_mockops);
    // They can use the same mock up as they are using the same mock server

    pair<UserState*, ChatMocker*> creator_server_state(&creator_state, &mock_server);
    pair<UserState*, ChatMocker*> joiner_server_state(&joiner_state, &mock_server);

    // everybody signs in
    // creator
    mock_server.sign_in(creator, chat_mocker_np1sec_plugin_receive_handler, static_cast<void*>(&creator_server_state));
    // joiner
    mock_server.sign_in(joiner, chat_mocker_np1sec_plugin_receive_handler, static_cast<void*>(&joiner_server_state));

    // creator joins first
    mock_server.join(mock_room_name, creator_state.user_nick());

    // receive your share and own confirmation
    mock_server.receive();

    // then joiner joins
    mock_server.join(mock_room_name, joiner_state.user_nick());

    // receive the join requests and start reations
    mock_server.receive();

    // tell np1sec to go through join
    // chat_mocker_np1sec_plugin_join(mock_room_name, &joiner_server_state);

    // np1secSession new_session(user_state, mock_room_name, participants_in_the_room);
    // ASSERT_TRUE(new_session.join(user_state->user_id_key_pair()));
}

TEST_F(SessionTest, test_solitary_talk)
{
    // first we need a username and we use it
    // to sign in the room
    // return;
    string username = "sole-tester";
    std::pair<ChatMocker*, string> mock_aux_data(&mock_server, username);
    mockops->bare_sender_data = static_cast<void*>(&mock_aux_data);
    UserState* user_state = new UserState(username, mockops);

    pair<UserState*, ChatMocker*> user_server_state(user_state, &mock_server);

    // client login and join
    mock_server.sign_in(username, chat_mocker_np1sec_plugin_receive_handler, static_cast<void*>(&user_server_state));
    mock_server.join(mock_room_name, user_state->user_nick());

    // tell np1sec to go through join
    // chat_mocker_np1sec_plugin_join(mock_room_name, &user_server_state);

    // we need to call this after every action
    // receive your own key share and send confirmation
    mock_server.receive();

    // say something
    chat_mocker_np1sec_plugin_send(mock_room_name, "Hello, World!", &user_server_state);

    // and receive it
    mock_server.receive();
}

TEST_F(SessionTest, test_join_talk)
{
    // return;
    // first we need a username and we use it
    // to sign in the room
    string creator = "creator";
    AppOps creator_mockops = *mockops;
    std::pair<ChatMocker*, string> mock_aux_creator_data(&mock_server, creator);
    creator_mockops.bare_sender_data = static_cast<void*>(&mock_aux_creator_data);
    UserState creator_state(creator, &creator_mockops);

    AppOps joiner_mockops = *mockops;
    string joiner = "joiner";
    std::pair<ChatMocker*, string> mock_aux_joiner_data(&mock_server, joiner);
    joiner_mockops.bare_sender_data = static_cast<void*>(&mock_aux_joiner_data);
    UserState joiner_state(joiner, &joiner_mockops);
    // They can use the same mock up as they are using the same mock server

    pair<UserState*, ChatMocker*> creator_server_state(&creator_state, &mock_server);
    pair<UserState*, ChatMocker*> joiner_server_state(&joiner_state, &mock_server);

    // everybody signs in
    // creator
    mock_server.sign_in(creator, chat_mocker_np1sec_plugin_receive_handler, static_cast<void*>(&creator_server_state));
    // joiner
    mock_server.sign_in(joiner, chat_mocker_np1sec_plugin_receive_handler, static_cast<void*>(&joiner_server_state));

    // creator joins first
    mock_server.join(mock_room_name, creator_state.user_nick());

    // receive your share and own confirmation
    mock_server.receive();

    // then joiner joins
    mock_server.join(mock_room_name, joiner_state.user_nick());

    // receive the join requests and start reations
    mock_server.receive();

    // tell np1sec to go through join
    // chat_mocker_np1sec_plugin_join(mock_room_name, &joiner_server_state);

    // np1secSession new_session(user_state, mock_room_name, participants_in_the_room);
    // ASSERT_TRUE(new_session.join(user_state->user_id_key_pair()));

    // say something
    chat_mocker_np1sec_plugin_send(mock_room_name, "Hello, Joiner!", &creator_server_state);
    // and receive it
    mock_server.receive();

    // chat_mocker_np1sec_plugin_send(mock_room_name, "Hello, Creator!", &joiner_server_state);
    // and receive it
    mock_server.receive();
}

TEST_F(SessionTest, test_three_party_chat)
{
    // return;
    // first we need a username and we use it
    // to sign in the room
    string alice = "alice";
    AppOps alice_mockops = *mockops;
    std::pair<ChatMocker*, string> mock_aux_alice_data(&mock_server, alice);
    alice_mockops.bare_sender_data = static_cast<void*>(&mock_aux_alice_data);
    UserState* alice_state = new UserState(alice, &alice_mockops);

    AppOps bob_mockops = *mockops;
    string bob = "bob";
    std::pair<ChatMocker*, string> mock_aux_bob_data(&mock_server, bob);
    bob_mockops.bare_sender_data = static_cast<void*>(&mock_aux_bob_data);
    UserState* bob_state = new UserState(bob, &bob_mockops);
    // They can use the same mock up as they are using the same mock server

    AppOps charlie_mockops = *mockops;
    string charlie = "charlie";
    std::pair<ChatMocker*, string> mock_aux_charlie_data(&mock_server, charlie);
    charlie_mockops.bare_sender_data = static_cast<void*>(&mock_aux_charlie_data);
    UserState* charlie_state = new UserState(charlie, &charlie_mockops);

    pair<UserState*, ChatMocker*> alice_server_state(alice_state, &mock_server);
    pair<UserState*, ChatMocker*> bob_server_state(bob_state, &mock_server);
    pair<UserState*, ChatMocker*> charlie_server_state(charlie_state, &mock_server);

    // everybody signs in
    // alice
    mock_server.sign_in(alice, chat_mocker_np1sec_plugin_receive_handler, static_cast<void*>(&alice_server_state));
    // bob
    mock_server.sign_in(bob, chat_mocker_np1sec_plugin_receive_handler, static_cast<void*>(&bob_server_state));
    // charlie
    mock_server.sign_in(charlie, chat_mocker_np1sec_plugin_receive_handler, static_cast<void*>(&charlie_server_state));

    // alice joins first
    mock_server.join(mock_room_name, alice_state->user_nick());

    // receive your share and own confirmation
    mock_server.receive();

    // then bob joins
    mock_server.join(mock_room_name, bob_state->user_nick());

    // receive the join requests and start reations
    mock_server.receive();

    // say something
    chat_mocker_np1sec_plugin_send(mock_room_name, "Hello, I'm Alice!", &alice_server_state);
    // and receive it
    mock_server.receive();

    // then charlie joins
    mock_server.join(mock_room_name, charlie_state->user_nick());

    chat_mocker_np1sec_plugin_send(mock_room_name, "Ah Charlie is here again!", &bob_server_state);

    // receive the join requests and start reations
    mock_server.receive();

    chat_mocker_np1sec_plugin_send(mock_room_name, "Hello, I'm Charlie!", &charlie_server_state);
    // and receive it
    mock_server.receive();

    chat_mocker_np1sec_plugin_send(mock_room_name, "Hey Charlie! I love you!", &bob_server_state);
    // and receive it
    mock_server.receive();

    delete alice_state;
    delete bob_state;
    delete charlie_state;
}

TEST_F(SessionTest, test_ten_party_chat)
{
    // return;
    // first we need a username and we use it
    // to sign in the room
    const unsigned int total_no_participants = 10;

    string participant_base_name = "p";
    AppOps participant_mockops[total_no_participants];
    std::pair<ChatMocker*, string> mock_aux_participant_data[total_no_participants];
    UserState* participant_state[total_no_participants];
    pair<UserState*, ChatMocker*> participant_server_state[total_no_participants];

    for (unsigned int i = 0; i < total_no_participants; i++) {
        std::string cur_participant_name = participant_base_name + std::to_string(i);
        participant_mockops[i] = *mockops;
        mock_aux_participant_data[i] = std::pair<ChatMocker*, string>(&mock_server, cur_participant_name);
        participant_mockops[i].bare_sender_data = static_cast<void*>(&mock_aux_participant_data[i]);
        ;
        participant_state[i] = new UserState(cur_participant_name, &participant_mockops[i]);

        participant_server_state[i] = pair<UserState*, ChatMocker*>(participant_state[i], &mock_server);

        mock_server.sign_in(cur_participant_name, chat_mocker_np1sec_plugin_receive_handler,
                            static_cast<void*>(&participant_server_state[i]));

        mock_server.join(mock_room_name, participant_state[i]->user_nick());

        mock_server.receive();
    }

    for (unsigned i = 0; i < total_no_participants; i++)
        delete participant_state[i];
}

TEST_F(SessionTest, test_solitary_leave)
{
    // first we need a username and we use it
    // to sign in the room
    // return;
    string username = "sole-tester";
    std::pair<ChatMocker*, string> mock_aux_data(&mock_server, username);
    mockops->bare_sender_data = static_cast<void*>(&mock_aux_data);
    UserState user_state(username, mockops);

    pair<UserState*, ChatMocker*> user_server_state(&user_state, &mock_server);

    // client login and join
    mock_server.sign_in(username, chat_mocker_np1sec_plugin_receive_handler, static_cast<void*>(&user_server_state));
    mock_server.join(mock_room_name, user_state.user_nick());

    // we need to call this after every action
    // receive your own key share and send confirmation
    mock_server.receive();

    mock_server.intend_to_leave(mock_room_name, user_state.user_nick());

    mock_server.receive();
}

TEST_F(SessionTest, test_leave_from_2p_conv)
{
    // first we need a username and we use it
    // to sign in the room
    // return;
    string creator = "creator";
    AppOps creator_mockops = *mockops;
    std::pair<ChatMocker*, string> mock_aux_creator_data(&mock_server, creator);
    creator_mockops.bare_sender_data = static_cast<void*>(&mock_aux_creator_data);
    UserState* creator_state = new UserState(creator, &creator_mockops);

    AppOps joiner_mockops = *mockops;
    string joiner = "joiner";
    std::pair<ChatMocker*, string> mock_aux_joiner_data(&mock_server, joiner);
    joiner_mockops.bare_sender_data = static_cast<void*>(&mock_aux_joiner_data);
    UserState* joiner_state = new UserState(joiner, &joiner_mockops);
    // They can use the same mock up as they are using the same mock server

    pair<UserState*, ChatMocker*> creator_server_state(creator_state, &mock_server);
    pair<UserState*, ChatMocker*> joiner_server_state(joiner_state, &mock_server);

    // everybody signs in
    // creator
    mock_server.sign_in(creator, chat_mocker_np1sec_plugin_receive_handler, static_cast<void*>(&creator_server_state));
    // joiner
    mock_server.sign_in(joiner, chat_mocker_np1sec_plugin_receive_handler, static_cast<void*>(&joiner_server_state));

    // creator joins first
    mock_server.join(mock_room_name, creator_state->user_nick());

    // receive your share and own confirmation
    mock_server.receive();

    // then joiner joins
    mock_server.join(mock_room_name, joiner_state->user_nick());

    // receive the join requests and start reations
    mock_server.receive();

    // creator says I'm leaving the room.
    mock_server.intend_to_leave(mock_room_name, creator_state->user_nick());

    mock_server.receive();

    // this should be called by the receive
    mock_server.leave(mock_room_name, creator_state->user_nick());

    // and receive it
    mock_server.receive();

    delete creator_state;
    delete joiner_state;
}

TEST_F(SessionTest, test_immature_leave_from_2p_conv)
{
    // first we need a username and we use it
    // to sign in the room
    // return;
    string creator = "creator";
    AppOps creator_mockops = *mockops;
    std::pair<ChatMocker*, string> mock_aux_creator_data(&mock_server, creator);
    creator_mockops.bare_sender_data = static_cast<void*>(&mock_aux_creator_data);
    UserState* creator_state = new UserState(creator, &creator_mockops);

    AppOps joiner_mockops = *mockops;
    string joiner = "joiner";
    std::pair<ChatMocker*, string> mock_aux_joiner_data(&mock_server, joiner);
    joiner_mockops.bare_sender_data = static_cast<void*>(&mock_aux_joiner_data);
    UserState* joiner_state = new UserState(joiner, &joiner_mockops);
    // They can use the same mock up as they are using the same mock server

    pair<UserState*, ChatMocker*> creator_server_state(creator_state, &mock_server);
    pair<UserState*, ChatMocker*> joiner_server_state(joiner_state, &mock_server);

    // everybody signs in
    // creator
    mock_server.sign_in(creator, chat_mocker_np1sec_plugin_receive_handler, static_cast<void*>(&creator_server_state));
    // joiner
    mock_server.sign_in(joiner, chat_mocker_np1sec_plugin_receive_handler, static_cast<void*>(&joiner_server_state));

    // creator joins first
    mock_server.join(mock_room_name, creator_state->user_nick());

    // receive your share and own confirmation
    mock_server.receive();

    // then joiner joins
    mock_server.join(mock_room_name, joiner_state->user_nick());

    // receive the join requests and start reations
    mock_server.receive();

    // Joiner just leave without announcing the intention and doing the consistency
    // check
    mock_server.leave(mock_room_name, joiner_state->user_nick());

    // and receive it
    mock_server.receive();

    delete creator_state;
    delete joiner_state;
}

TEST_F(SessionTest, test_concurrent_join)
{
    // return;
    // first we need a username and we use it
    // to sign in the room
    string alice = "alice";
    AppOps alice_mockops = *mockops;
    std::pair<ChatMocker*, string> mock_aux_alice_data(&mock_server, alice);
    alice_mockops.bare_sender_data = static_cast<void*>(&mock_aux_alice_data);
    UserState* alice_state = new UserState(alice, &alice_mockops);

    AppOps bob_mockops = *mockops;
    string bob = "bob";
    std::pair<ChatMocker*, string> mock_aux_bob_data(&mock_server, bob);
    bob_mockops.bare_sender_data = static_cast<void*>(&mock_aux_bob_data);
    UserState* bob_state = new UserState(bob, &bob_mockops);
    // They can use the same mock up as they are using the same mock server

    AppOps charlie_mockops = *mockops;
    string charlie = "charlie";
    std::pair<ChatMocker*, string> mock_aux_charlie_data(&mock_server, charlie);
    charlie_mockops.bare_sender_data = static_cast<void*>(&mock_aux_charlie_data);
    UserState* charlie_state = new UserState(charlie, &charlie_mockops);

    pair<UserState*, ChatMocker*> alice_server_state(alice_state, &mock_server);
    pair<UserState*, ChatMocker*> bob_server_state(bob_state, &mock_server);
    pair<UserState*, ChatMocker*> charlie_server_state(charlie_state, &mock_server);

    // everybody signs in
    // alice
    mock_server.sign_in(alice, chat_mocker_np1sec_plugin_receive_handler, static_cast<void*>(&alice_server_state));
    // bob
    mock_server.sign_in(bob, chat_mocker_np1sec_plugin_receive_handler, static_cast<void*>(&bob_server_state));
    // charlie
    mock_server.sign_in(charlie, chat_mocker_np1sec_plugin_receive_handler, static_cast<void*>(&charlie_server_state));

    // alice joins first
    mock_server.join(mock_room_name, alice_state->user_nick());

    // receive your share and own confirmation
    mock_server.receive();

    // then bob joins
    mock_server.join(mock_room_name, bob_state->user_nick());
    // then charlie joins
    mock_server.join(mock_room_name, charlie_state->user_nick());

    // receive the join requests and start reations
    mock_server.receive();

    chat_mocker_np1sec_plugin_send(mock_room_name, "Happy concurrent join!", &charlie_server_state);

    mock_server.receive();

    delete alice_state;
    delete bob_state;
    delete charlie_state;
}

TEST_F(SessionTest, test_concurrent_join_leave)
{

    // this test is not working with 3 participants cause chatmocker number of particiants
    // is comming from the server while everything else is based on messages
    // so from client side.
    // to make it work is that the number of participant also should come from
    // client side. so for example the @P@JOIN message should have the number
    // of participants
    string alice = "alice";
    AppOps alice_mockops = *mockops;
    std::pair<ChatMocker*, string> mock_aux_alice_data(&mock_server, alice);
    alice_mockops.bare_sender_data = static_cast<void*>(&mock_aux_alice_data);
    UserState* alice_state = new UserState(alice, &alice_mockops);

    AppOps bob_mockops = *mockops;
    string bob = "bob";
    std::pair<ChatMocker*, string> mock_aux_bob_data(&mock_server, bob);
    bob_mockops.bare_sender_data = static_cast<void*>(&mock_aux_bob_data);
    UserState* bob_state = new UserState(bob, &bob_mockops);
    // They can use the same mock up as they are using the same mock server

    AppOps charlie_mockops = *mockops;
    string charlie = "charlie";
    std::pair<ChatMocker*, string> mock_aux_charlie_data(&mock_server, charlie);
    charlie_mockops.bare_sender_data = static_cast<void*>(&mock_aux_charlie_data);
    UserState* charlie_state = new UserState(charlie, &charlie_mockops);

    AppOps david_mockops = *mockops;
    string david = "david";
    std::pair<ChatMocker*, string> mock_aux_david_data(&mock_server, david);
    david_mockops.bare_sender_data = static_cast<void*>(&mock_aux_david_data);
    UserState* david_state = new UserState(david, &david_mockops);

    pair<UserState*, ChatMocker*> alice_server_state(alice_state, &mock_server);
    pair<UserState*, ChatMocker*> bob_server_state(bob_state, &mock_server);
    pair<UserState*, ChatMocker*> charlie_server_state(charlie_state, &mock_server);
    pair<UserState*, ChatMocker*> david_server_state(david_state, &mock_server);

    // everybody signs in
    // alice
    mock_server.sign_in(alice, chat_mocker_np1sec_plugin_receive_handler, static_cast<void*>(&alice_server_state));
    // bob
    mock_server.sign_in(bob, chat_mocker_np1sec_plugin_receive_handler, static_cast<void*>(&bob_server_state));
    // charlie
    mock_server.sign_in(charlie, chat_mocker_np1sec_plugin_receive_handler, static_cast<void*>(&charlie_server_state));
    // david
    mock_server.sign_in(david, chat_mocker_np1sec_plugin_receive_handler, static_cast<void*>(&david_server_state));

    // alice joins first
    mock_server.join(mock_room_name, alice_state->user_nick());

    // receive your share and own confirmation
    mock_server.receive();

    // then bob joins
    mock_server.join(mock_room_name, bob_state->user_nick());
    // receive the join requests and start reations
    mock_server.receive();

    mock_server.join(mock_room_name, charlie_state->user_nick());
    mock_server.join(mock_room_name, david_state->user_nick());
    mock_server.leave(mock_room_name, charlie_state->user_nick());

    // receive the join requests and start reations
    mock_server.receive();

    chat_mocker_np1sec_plugin_send(mock_room_name, "Happy concurrent join/leave!", &david_server_state);

    mock_server.receive();

    delete alice_state;
    delete bob_state;
    delete charlie_state;
    delete david_state;
}
