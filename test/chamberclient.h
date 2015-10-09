/**
 * This is a client implementation for testing in EchoChamber
 * https://github.com/equalitie/EchoChamber
 *
 * Authors: Zack Mullaly, 09/10/2015
 */

#include <map>
#include <queue>
#include <list>
#include <iostream>

#include "src/logger.h"

#ifndef _CHAMBER_CLIENT_H_
#define _CHAMBER_CLIENT_H_

extern np1sec::Logger logger;

class TParticipant;
class TRoom;

// Handler function for message receipt
typedef void (*receive_h)(std::string room_name, std::string message, void* user_data);

// A mapping of participant names to participant instances
typedef std::map<std::string, TParticipant> ParticipantMap;

// A queue of incoming messages that have yet to be handled
typedef std::queue<std::string> MessageQueue;

// A list of nicknames of participants in a room
typedef std::vector<std::string> ParticipantList;

/**
 * Stores information about participants in chats.
 */
class TParticipant
{
    public:
        std::string nickname;
        // Data to be passed to a receive handler
        void* aux_data
        receive_h recv_handler;
        bool scheduled_to_leave = false;
};

class TRoom
{
    protected:
        uint64_t global_message_id = 0;
        std::string name;
        ParticipantMap participants;
        MessageQueue messages;

        void broadcast(std::string message)
        {
            messages.push(message);
        }

    public:
        MockRoom(std::string room_name)
          : name(room_name) { }

        /**
         * Handle having a participant join the room.
         * @param nickname - The nickname of the joining user
         * @param handler - A message-receipt handler function to invoke when the user is to receive a message
         * @param user_data - The blob of data relevant to the user joining
         */
        void join(std::string nickname, receieve_h handler, void* user_data)
        {
            participants[nickname].nickname = nickname;
            participants[nickname].recv_handler = handler;
            participants[nickname].aux_data = user_data;
            broadcast("@<o>@JOIN@<o>@" + nickname);
        }

        /**
         * An accessor to obtain the list of nicknames of participants in the room.
         */
        ParticipantList get_participants()
        {
          ParticipantList list;
          for (auto current = participants.begin(); current != participants.end(); current++) {
              list.push_back((current->second).nickname);
          }
          return list;
        }

        /**
         * Inform room participants of a user's intention to leave.
         * @param nickname - The nickname of the user who intends to leave
         */
        void notify_intend_leave(std::string nickname)
        {
            broadcast("@<o>@INTEND2LEAVE@<o>@" + nickname);
        }

        /**
         * Inform room participants that a user is leaving.
         * @param nickname - The nickname of the user who is leaving
         */
        void leave(std::string nickname)
        {
            participants[nickname].scheduled_to_leave = true;
            broadcast("@<o>@LEAVE@<o>@" + nickname);
        }

        /**
         * Send a message to the participants in the room.
         * @param sender - The nickname of the participant sending the message
         * @param message - The content of the message they would like to send
         */
        void send(std::string sender, std::string message)
        {
            global_message_id++;
            broadcast("@<o>@SEND@<o>@" + std::to_string(global_message_id) + "@<o>@" + sender + "@<o>@" + message);
        }

        void receive()
        {
            std::string leaving_nickname;
            while (!messages.empty()) {
                for (auto current = participants.begin(); current != participants.end(); current++) {
                    auto participant = current->second;
                    if (participant.scheduled_to_leave) {
                        leaving_nickname = participant.nickname;
                    } else {
                        (*participant.recv_handler)(name, messages.front(), participant.aux_data);
                    }
                }
                // Only allow one participant to leave per message handled.
                if (!leaving_nickname.empty()) {
                    participants.erase(leaving_nickname);
                    leaving_nickname.clear();
                }
                messages.pop();
            }
        }
};

#endif // _CHAMBER_CLIENT_H_
