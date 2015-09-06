/**
   This is a mock/simulator of a multi party chat protocol runing on the
   same machine for the purpose of testing np1sec

   Authors: Vmon, 2015-01: initial version
 */
extern "C" {
#include <assert.h>
}

#include <map>
#include <list>
#include <queue>
#include <iostream>
#include <iomanip>
#include <sstream>

#include "src/logger.h"
using namespace std;

#ifndef TEST_CHAT_MOCKER_H_
#define TEST_CHAT_MOCKER_H_

extern np1sec::Logger mock_logger;

/**
   This class store the information about different participants
   including their receive and send functions
 */

void chat_mocker_np1sec_plugin_receive_handler(std::string room_name, std::string np1sec_message, void* aux_data);

class MockParticipant
{
  public:
    std::string nick;
    void* aux_data; // the data to send to receive_handler
    void (*receive_handler)(std::string room_name, std::string message, void* aux_data);
    bool scheduled_to_leave = false;

    // void (*join_handler)(std::string room_name,
    // void* aux_data); //we don't need the join handler
    // because we receive our own join message and therefore
    // we can react to that.
};

class MockRoom
{
  protected:
    uint64_t global_message_id = 0;
    std::string name;
    std::map<std::string, MockParticipant> _participant_list;
    std::queue<std::string> message_queue;

    void broadcast(std::string message) { message_queue.push(message); }

  public:
    MockRoom() { assert(0); }

    MockRoom(std::string room_name) : name(room_name) {}

    void join(std::string nick, void (*receive_handler)(std::string room_name, std::string message, void* user_data),
              void* user_data)
    {
        _participant_list[nick].nick = nick;
        _participant_list[nick].receive_handler = receive_handler;
        _participant_list[nick].aux_data = user_data;

        // receive_handler; in real life, its re doesn't happen here
        // _participant_list[nick].aux_data = user_data;
        mock_logger.debug("room size by server: " + to_string(_participant_list.size()), __FUNCTION__);
        broadcast("@<o>@JOIN@<o>@" + nick);
    }

    /**
       access function for participants
     */
    std::vector<std::string> participant_list()
    {
        std::vector<std::string> participant_nicks;
        for (std::map<std::string, MockParticipant>::iterator cur_participant = _participant_list.begin();
             cur_participant != _participant_list.end(); cur_participant++) {
            participant_nicks.push_back((cur_participant->second).nick);
        };

        return participant_nicks;
    }

    void intend_to_leave(std::string nick) { broadcast("@<o>@INTEND2LEAVE@<o>@" + nick); }

    void leave(std::string nick)
    {
        _participant_list[nick].scheduled_to_leave = true;
        broadcast("@<o>@LEAVE@<o>@" + nick);
    }

    void send(std::string sender_nick, std::string message)
    {
        global_message_id++;
        broadcast("@<o>@SEND@<o>@" + std::to_string(global_message_id) + "@<o>@" + sender_nick + "@<o>@" + message);
    }

    void receive()
    {
        std::string leaving_nick;
        while (!message_queue.empty()) {
            mock_logger.debug(name + " received message: ", message_queue.front(), __FUNCTION__);
            for (std::map<std::string, MockParticipant>::iterator cur_participant = _participant_list.begin();
                 cur_participant != _participant_list.end() && !_participant_list.empty(); cur_participant++) {
                if (cur_participant->second.scheduled_to_leave)
                    leaving_nick = cur_participant->second.nick;
                else
                    (*(cur_participant->second).receive_handler)(name, message_queue.front(),
                                                                 (cur_participant->second).aux_data);
            }

            if (!leaving_nick.empty()) { // one participant can leave per message
                _participant_list.erase(leaving_nick);
                leaving_nick.clear();
            }

            message_queue.pop();
        }
    }
};

/**
   This client simulate both client and server.
   as everythnig happens locally
 */
class ChatMocker
{
  protected:
    std::map<std::string, MockRoom> rooms;
    std::map<std::string, MockParticipant> signed_in_participant;

  public:
    /**
     * does nothing return null. just a place holder
     */
    virtual std::string* add_timeout(void* arg, const uint32_t timeout)
    {
        (void)arg;
        (void)timeout;

        return nullptr;
    }

    /**
     * does nothing
     */
    virtual void remove_timeout(std::string* identifier)
    {
        (void)identifier;
        return;
    }

    /**
     * Add the participant to the singed in list and keep track of their
     * receive handler
     */
    void sign_in(std::string nick, void (*receive_handler)(std::string room_name, std::string message, void* user_data),
                 void* user_data)
    {
        signed_in_participant[nick].nick = nick;
        signed_in_participant[nick].receive_handler = receive_handler;
        signed_in_participant[nick].aux_data = user_data;
    }

    /**
     * join the room by adding the name of the participant to the room list
     */
    void join(std::string room, std::string nick)
    {
        if (rooms.find(room) == rooms.end())
            rooms.insert(std::pair<std::string, MockRoom>(room, MockRoom(room)));

        rooms[room].join(nick, signed_in_participant[nick].receive_handler, signed_in_participant[nick].aux_data);
        // we need to call the join_handler if it exists
    }

    /**
       return the list of participant in the room
       it makes the base for the list of participant in the room
     */
    std::vector<std::string> participant_list(std::string room) { return rooms[room].participant_list(); }

    /**
     * signal intention to leave so the last transcript
     * consistency check can be executed.
     */
    void intend_to_leave(std::string room, std::string nick)
    {
        // In normal situation you need to call a local function
        // for the similicity in the mock version, we make this through
        // sending a message to the room and other participants just
        // ignore it
        rooms[room].intend_to_leave(nick);
    }

    /**
     * drop the participant from the room
     */
    void leave(std::string room, std::string nick) { rooms[room].leave(nick); }

    /**
     * send a message to the room
     */
    void send(std::string room, std::string nick, std::string message) { rooms[room].send(nick, message); }

    /**
     * makes everybody receive all messages from all rooms
     */
    void receive()
    {
        for (auto it = rooms.begin(); it != rooms.end(); it++)
            it->second.receive();
    }
};

#endif // TEST_CHAT_MOCKER_H_
