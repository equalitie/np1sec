/**
 *  This is an interface between mock/simulator of a multi party chat protocol *
 *  similar interface plugin needs to be implemented by the client developers
 *  who wishes to connect
 * 
 *  runing on same machine and np1sec. This is both for test purpose and for 
 *  illusteration of how to write an interface for using np1sec library
 *
 *  The plugin needs to call np1sec on the following events:
 *  - user joins a chatroom: join
 *  - another user joins the chatroom: accept.
 *  - user leaves the chatroom: leave.
 *  - another user leave the chatroom: farewell.
 *  - Receiving message: receive_handler (only message should be passed and message id and the sender).
 *
 *  - The plugin also need to set the point to the send_bare_message to userstate
 *  Authors: Vmon, 2015-01: initial version
 */

/**
 * Receive the messages from chat mocker, interpret the message and
 * call the approperiate function from userstate class  of npsec1 
 * libreary.
 * 
 */
#include <utility>
#include <vector>
#include <string>
#include <iostream>

#include "test/chat_mocker.h"

// npsec1 functions
#include "src/userstate.h"
#include "src/common.h"

using namespace std;

void chat_mocker_np1sec_plugin_join(std::string room_name,
                                        void* aux_data)
{
  pair<np1secUserState*, ChatMocker*>* user_server_state = reinterpret_cast<pair<np1secUserState*, ChatMocker*>*>(aux_data);
  //It is chat client duty to provide the userstate class with
  //the list of participants not really other participants are going to do it.
  vector<string> current_occupants = user_server_state->second->participant_list(room_name);
  //UnauthenticatedParticipantList current_occupants_with_key;
  //for(uint32_t cur_participant = 0; cur_participant < current_occupants.size(); cur_participant++)
  //  current_occupants_with_key.push_back((UnauthenticatedParticipant){current_occupants[cur_participant], ""});

  user_server_state->first->join_room(room_name, current_occupants);

}

void chat_mocker_np1sec_plugin_receive_handler(std::string room_name,
                                               std::string np1sec_message,
                                               void* aux_data)
{
  pair<np1secUserState*, ChatMocker*>* user_server_state = reinterpret_cast<pair<np1secUserState*, ChatMocker*>*>(aux_data);

  // we need to process message and see if it is join leave or actual message
  //why? it is crazy to expect the client to disect and digest the message
  //actully it is not. In libpurple, it might be that libpurple calls different
  //functions for different actions, but the chat mocker put everything
  //in a message
  //only possible operation should be join and leave 
  if (np1sec_message.find("@<o>@JOIN@<o>@") == 0) {
    // check if it is ourselves or somebody else who is joining
    string joining_nick = np1sec_message.substr(strlen("@<o>@JOIN@<o>@"));

    if (user_server_state->first->user_nick() == joining_nick) {
      try {
        user_server_state->first->join_room(room_name, user_server_state->second->participant_list(room_name));
      } catch(np1secInsufficientCredentialException& e) {
        logger.error(joining_nick + " failed to join room" + room_name);
      }
    } else {
      user_server_state->first->increment_room_size(room_name);
      //we don't need to react, (we can, the protocol doesn't stop us
      //but we are lazy and we react to the join request sent by the joiner
      // user_server_state->first->receive_handler(room_name,
      //                                           joining_nick,
      //                                           np1sec_message);
                                                
      //user_server_state->first->accept_new_user(room_name, joining_nick);
      //ignore
    }
  } else if (np1sec_message.find("@<o>@INTEND2LEAVE@<o>@") == 0) {
    string leaving_nick = np1sec_message.substr(strlen("@<o>@INTEND2LEAVE@<o>@"));
    if (leaving_nick==user_server_state->first->user_nick()) {
      user_server_state->first->leave_room(room_name);
    } else {
      //do nothing. //in real life this won't come as a message
      //we are using the room both for IM and internal  messaging
      //apparatus
    }
  } else if (np1sec_message.find("@<o>@LEAVE@<o>@") == 0) {
    string leaving_nick = np1sec_message.substr(strlen("@<o>@LEAVE@<o>@"));
    if (leaving_nick != user_server_state->first->user_nick()) {
      //kick out in case haven't left cleanly.
      user_server_state->first->shrink(room_name, leaving_nick);
      
    }else {
      //that shouldn't happen, if I left I shouldn't receive messages
      assert(0);
    }
    
  } else if (np1sec_message.find("@<o>@SEND@<o>@") == 0) {
    string message_with_id = np1sec_message.substr(strlen("@<o>@SEND@<o>@"));
    size_t sender_pos = message_with_id.find("@<o>@");
    string message_id_str = message_with_id.substr(0, sender_pos);
    int message_id;
    stringstream(message_id_str) >> message_id;
    string sender_and_message = message_with_id.substr(
                                  sender_pos + strlen("@<o>@"));
    size_t message_pos = sender_and_message.find("@<o>@");
    string sender = sender_and_message.substr(0, message_pos);
    // we don't care really about sender
    string pure_message = sender_and_message.substr(
                                    message_pos + strlen("@<o>@"));
  //RoomActoin will tell you to 1)show message, 2)add participant 3) remove participant etc
 //not sure yet
    user_server_state->first->receive_handler(room_name,
                                              sender,
                                              pure_message,
                                              message_id);
  }
  
};

/**
 * This should be called by the client to secure send
 * user message to a room,using np1sec library
 */
void chat_mocker_np1sec_plugin_send(std::string room_name,
                                    std::string message,
                                    void* aux_data)
{
  pair<np1secUserState*, ChatMocker*>* user_server_state = reinterpret_cast<pair<np1secUserState*, ChatMocker*>*>(aux_data);

  user_server_state->first->send_handler(room_name, message);

}

// Just a wrapper to call the mocker send function
void send_bare(std::string room_name, std::string message, void* data)
{
  //pair<np1secUserState*, ChatMocker*>* user_server_state = reinterpret_cast<pair<np1secUserState*, ChatMocker*>*>(data);
  ChatMocker* chat_server = (static_cast<pair<ChatMocker*, std::string>*>(data))->first;
  std::string sender = (static_cast<pair<ChatMocker*, std::string>*>(data))->second;

  chat_server->send(room_name, sender, message);
  
}

// informing join and leave
void new_session_announce(std::string room_name, std::vector<std::string> plist, void* aux_data)
{
  std::pair<ChatMocker*, string>* server_and_nick = reinterpret_cast<std::pair<ChatMocker*, string>*>(aux_data);
  if (std::find(plist.begin(), plist.end(), server_and_nick->second) == plist.end()) {//we are leaving the room
    cout << server_and_nick->second << "'s client: " << server_and_nick->second << " left room" << endl;
    server_and_nick->first->leave(room_name, server_and_nick->second);

  } else {
    cout << reinterpret_cast<std::pair<ChatMocker*, string>*>(aux_data)->second << "'s client: " << "new session established: ";
    for(uint32_t i = 0; i < plist.size();  i++) {
      std::cout << plist[i] << " ";
    }

    std::cout << std::endl;

  }
  
}

//Display received messages
void display_message(std::string room_name, std::string sender_nickname, std::string user_message, void* aux_data)
{
  
  cout << reinterpret_cast<std::pair<ChatMocker*, string>*>(aux_data)->second << "'s client: " << sender_nickname << "@" << room_name << ": " << user_message << endl;
  
}

// Add a timeout callback to the ChatMocker server provided
// timer_callback - The callback to call with the provided opdata
// opdata         - The data to call timer_callback with
// interval       - The number of microseconds to wait before calling timer_callback
// data           - A pair containing a chatmocker and a string
void* set_timer(void (*timer_callback)(void* opdata), void* opdata, uint32_t interval, void* data)
{
  ChatMocker* chat_server = (reinterpret_cast<pair<ChatMocker*, std::string>*>(data))->first;
  pair<timeout_callback, void*>* my_data = new pair<timeout_callback, void*>(timer_callback, opdata);
  std::string* s = chat_server->add_timeout(my_data, interval);
  return s;
}

// Remove a timeout event from the ChatMocker server provided
// identifier - The string that identifies the event to be removed in the event manager
// data       - A pair containing a chatmocker and a string
void axe_timer(void* identifier, void* data)
{
  std::string* ident = reinterpret_cast<std::string*>(identifier);
  ChatMocker* chat_server = (reinterpret_cast<pair<ChatMocker*, std::string>*>(data))->first;
  chat_server->remove_timeout(ident);
}

/*void join(std::string room_name, std::string sender_nickname, void* data)
{
  cout << sender_nickname << "Securely joined: " << endl;
  
  }*/

// bool am_i_alone(std::string room_name, void* aux_data) {
//   ChatMocker* chat_server = (static_cast<pair<ChatMocker*, std::string>*>(aux_data))->first;
//   exit(0);
//   return (!(chat_server->participant_list(room_name).size() > 1));
  
// }
