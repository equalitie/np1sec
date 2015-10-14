/**
 * This is a client implementation for testing in EchoChamber
 * https://github.com/equalitie/EchoChamber
 *
 * Authors: Zack Mullaly, 09/10/2015
 */

#include <map>
#include <vector>
#include <iostream>

#include "src/logger.h"
#include "src/userstate.h"

#include "test/mongoose.h"

#ifndef _CHAMBER_CLIENT_H_
#define _CHAMBER_CLIENT_H_

extern np1sec::Logger logger;

// Early declarations of the test participant and test room classes
// so that we can declare types and function signatures referring to them
class TParticipant;
class TRoom;

// A mapping of participant names to participant instances
typedef std::map<std::string, TParticipant> ParticipantMap;

// A mapping of room names to room instances
typedef std::map<std::string, TRoom> RoomMap;

// A list of nicknames of participants in a room
typedef std::vector<std::string> ParticipantList;

// The type signature of a callback to be provided to a timer
typedef void (*timer_cb)(void*);

// A collection of error cases that should be handled by the client
typedef enum
{
    NIL,             // No error has occurred
    NOT_SIGNED_IN,   // The user has tried to do something before signing in
    BAD_CREDENTIALS, // The user does not have the right keys to be able to participate in a session
    PARSE_ERROR      // The message (for sending) could not be parsed
}
TError;

/**
 * Function signatures for code that interacts with np1sec
 */
void chamber_join(std::string room_name, void* aux_data);
void chamber_send_raw(std::string room_name, std::string message, void* aux_data);
void chamber_announce_new_session(std::string room_name, ParticipantList participants, void* aux_data);
void chamber_print_message(std::string room_name, std::string sender, std::string message, void* aux_data);
void* chamber_set_timer(timer_cb callback, void* ops_data, uint32_t interval, void* aux_data);
void chamber_del_timer(void* to_be_removed, void* aux_data);
bool chamber_single_user_in_room(std::string room_name, void* aux_data);
TError chamber_receive_handler(std::string room_name, std::string message);
void chamber_send(std::string room_name, std::string message, void* aux_data);
/*
 * End of function signatures for np1sec interaction
 **/

/**
 * Helper functions
 */
TError parse_and_send(std::string room_name, std::string message, np1sec::UserState* user);

/**
 * Stores information about participants in chats.
 */
class TParticipant
{
    public:
        std::string nickname;
        // Data to be passed to a receive handler
        bool scheduled_to_leave = false;
};

class TRoom
{
    protected:
        uint64_t global_message_id = 0;
        std::string name;
        ParticipantMap participants;

        /**
         * Send a message to the chamber server to be sent to the room.
         * @param message - The contents of the message to send
         */
        void broadcast(std::string message) {
            std::cout << "Broadcasting:\t" << message << std::endl;
            return;
        }

    public:
        TRoom()
            : name("") { }

        TRoom(std::string room_name)
            : name(room_name) { }

        /**
         * Handle having a participant join the room.
         * @param nickname - The nickname of the joining user
         */
        void join(std::string nickname)
        {
            participants[nickname].nickname = nickname;
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

        /**
         * Process a receive event by handling all the messages in the queue and allowing
         * for one participant to leave for each message handled.
         */
        void receive()
        {
            std::cout << "Calling TRoom::receive()" << std::endl;
            /*
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
            */
        }
};

/**
 * A client's view of the world.
 * Contains all of the information that a client needs to be able to understand messages
 * received from others as well as generate messages.
 * It also supplies all of the methods (albeit with empty definitions) a real client
 * would be expected to have.
 */
class TState
{
    protected:
        RoomMap rooms;
        ParticipantMap participants;

    public:
        /**
         * Adds a callback function to an EventManager to be invoked after some time.
         * Here, it does nothing.
         * @param arg - The callback to invoke
         * @param timeout - The number of milliseconds to wait before invoking the callback
         * @return a pointer to a string that uniquely identifies the queued function
         */
        virtual std::string* add_timeout(void* arg, const uint32_t timeout)
        {
            (void)arg;
            (void)timeout;
            return nullptr;
        }

        /**
         * Remove a function from an EventManager so it is never invoked.
         * Here, it does nothing.
         * @param identifier - A pointer to a string that uniquely identifies the callback
         */
        virtual void remove_timeout(std::string* identifier)
        {
            (void)identifier;
            return;
        }

        /**
         * Add a new participant to the list of signed in users and track their receipt handler.
         * @param nickname - The nickname of the user signing in
         * @param handler - The function to invoke when a message for the user is received
         * @param user_data - Other data associated with the user
         */
        void sign_in(std::string nickname, receive_h handler, void* user_data)
        {
            participants[nickname].nickname = nickname;
            participants[nickname].recv_handler = handler;
            participants[nickname].aux_data = user_data;
        }

        /**
         * Allow a signed in user to join a room, or create a new room if the room
         * does not already exist.
         * @param room_name - The name of the room to have the user join
         * @param nickname - The nickname of the user joining the room
         */
        TError join(std::string room_name, std::string nickname)
        {
            TParticipant user;
            if (participants.find(nickname) == participants.end()) {
                return NOT_SIGNED_IN;
            }
            user = participants[nickname];
            if (rooms.find(room_name) == rooms.end()) {
                std::pair<std::string, TRoom> new_room_pair(room_name, TRoom(room_name));
                rooms.insert(new_room_pair);
            }
            rooms[room_name].join(nickname, user.recv_handler, user.aux_data);
            return NIL;
        }

        /**
         * Obtain a list of the participants in a room.
         * @param room_name - The name of the room to get the list of participants from
         */
        ParticipantList get_participants(std::string room_name)
        {
            return rooms[room_name].get_participants();
        }

        /**
         * Signal intention to leave so that the last transcript consistency check
         * can be executed.
         * @param room_name - The name of the room to depart from
         * @param nickname - The nickname of the user who wishes to leave
         */
        void notify_intend_leave(std::string room_name, std::string nickname)
        {
            rooms[room_name].notify_intend_leave(nickname);
        }

        /**
         * Remove a participant from the room.
         * @param room_name - The name of the room to remove the user from
         * @param nickname - The nickname of the user to remove
         */
        void leave(std::string room_name, std::string nickname)
        {
            rooms[room_name].leave(nickname);
        }

        /**
         * Send a message to a room.
         * @param room_name - The name of the room to send the message to
         * @param nickname - The nickname of the user sending the message
         * @param message - The content of the message to send
         */
        void send(std::string room_name, std::string nickname, std::string message)
        {
            rooms[room_name].send(nickname, message);
        }

        /**
         * Initiate the process of having every user receive and process all messages
         * from all rooms.
         */
        void receive()
        {
            for (auto iterator = rooms.begin(); iterator != rooms.end(); iterator++) {
                iterator->second.receive();
            }
        }
};

#endif // _CHAMBER_CLIENT_H_
