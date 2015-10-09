/**
 * This is a client implementation for testing in EchoChamber
 * https://github.com/equalitie/EchoChamber
 *
 * Authors: Zack Mullaly, 09/10/2015
 */

#include <utility>
#include <iostream>

#include "test/chamberclient.h"

// np1sec functionality
#include "src/userstate.h"
#include "src/common.h"

// A pair containing information about a specific user and the test state
typedef std::pair<UserState*, TState*> StatePair;

// A pair containing test state and a user's nickname
typedef std::pair<TState*, std::string> StateNicknamePair;

/**
 * Join a room.
 * @param room_name - The name of the room to join
 * @param aux_data - A pointer to memory containing
 */
void chamber_join(std::string room_name, void* aux_data)
{
    StatePair* state = reinterpret_cast<StatePair*>(aux_data);
    ParticipantList participants = state->second->participants(room_name);
    state->first->join_room(room_name, participants);
}

/**
 * A wrapper around functionality for sending a message.
 * @param room_name - The name of the room to send to
 * @param message - The contents of the message to send
 * @param aux_data - A pointer to memory containing
 */
void chamber_send_raw(std::string room_name, std::string message, void* aux_data)
{
    StateNicknamePair* state_user = reinterpret_cast<StateNicknamePair*>(aux_data);
    TState* state = state_user->first;
    std::string sender = state_user->second;
    state->send(room_name, sender, message);
}

/**
 * Inform a room about joining and leaving events.
 * @param room_name - The name of the room to inform of the event
 * @param participants - The list (vector) of nicknames of participants in the room
 * @param aux_data - A pointer to memory containing a pair with: 1. A RoomMap and 2. The informer's nickname
 */
void chamber_announce_new_session(std::string room_name, ParticipantList participants, void* aux_data)
{
    StateNicknamePair* state_nick = reinterpret_cast<StateNickNamePair*>(aux_data);
    // Check if the user is no longer in the participants list, indicating that they are leaving
    if (std::find(participants.begin(), participants.end(), state_nick->second) == participants.end()) {
        std::cout << state_nick->second << " left the room " << room_name << std::endl;
        state_nick->first->leave(room_name, state_nick->second);
    } else {
        std::cout << state_nick->second << " is establishing a new session in " << room_name << std::endl;
        for (uint32_t i = 0; i < participants.size(); i++) {
            std::cout << participants[i] << " ";
        }
        std::cout << std::endl;
    }
}

/**
 * Output a message to stdout.
 * @param room_name - The name of the room from which the message originates
 * @param sender - The nickname of the user who sent the message
 * @param message - The content of the message
 * @param aux_data - 
 */
void chamber_print_message(std::string room_name, std::string sender, std::string message, void* aux_data)
{
    (void)aux_data;
    std::cout << sender << "@" << room_name << ": " << message << std::endl;
}

/**
 * Add a timeout callback to be invoked.
 * @param callback - The callback to clal with the provided ops_data
 * @param ops_data - The argument to pass to the callback when its called
 * @param interval - The number of microseconds to wait before calling the callback
 * @param aux_data -
 */
void* chamber_set_timer(timer_cb callback, void* ops_data, uint32_t interval, void* aux_data)
{
    StateNicknamePair* state_nick = reinterpret_cast<StateNicknamePair*>(aux_data);
    std::pair<timer_cb, void*>* cb_data = new std::pair<timer_cb, void*>(callback, ops_data);
    std::string* s = state_nick->first->add_timeout(cb_data, interval);
    return s;
}

/**
 * Remove a pending timeout event so it will not be invoked.
 * @param to_be_removed - A string identifying the event in the event manager
 * @param aux_data -
 */
void chamber_del_timer(void* to_be_removed, void* aux_data)
{
    StateNicknamePair* state_nick = reinterpret_cast<StateNicknamePair*>(aux_data);
    std::string* identifier = reinterpret_cast<std::string*>(to_be_removed);
    state_nick->first->remove_timeout(identifier);
}

/**
 * Determine if a room has only one user.
 * @param room_name - The name of the room to inspect
 * @param aux_data -
 */
bool chamber_single_user_in_room(std::string room_name, void* aux_data)
{
    StateNicknamePair* state_nick = reinterpret_cast<StateNicknamePair*>(aux_data);
    return state_nick->first->participants(room_name).size() == 1;
}

/**
 * The callback to invoke when a message is received.
 * @param room_name - The name of the room that a message originates from
 * @param aux_data -
 */
void chamber_receive_handler(std::string room_name, std::string message, void* aux_data)
{
    
}

/**
 * The send function a client can use to send a message securely to a room.
 * @param room_name - The name of the room to send the message to
 * @param message - The content of the message to send
 * @param aux_data -
 */
void chamber_send(std::string room_name, std::string message, void* aux_data)
{
    StateNicknamePair* state_nick = reinterpret_cast<StateNicknamePair*>(aux_data);
    state_nick->first->send(room_name, state_nick->second, message);
}
