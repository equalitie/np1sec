/**
 *  This is an interface between mock/simulator of a multi party chat protocol 
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
#include "chat_mocker.h"

//npsec1 functions
#include "src/userstate.h"
#include "src/common.h"

using namespace std;

void chat_mocker_plugin_receive_handler(std::string room_name, std::string message, void* aux_data);
{
  np1secUserState* user_state = reinterpret_cast<np1secUserState*>(aux_data);

  //we need to process message and see if it is join leave or actual message
  if (message.find(":o?JOIN:o?") == 0) {
    //check if it is ourselves or somebody else who is joining
    string joining_nick = message.substr(strlen(":o?JOIN:o?"));

    if (user_state->username() == joining_nick) {
      user_state->join_room(room_name);
    } else {
      user_state->accept(room_name, joining_nick);
    }
  } else if (message.find(":o?LEAVE:o?") == 0) {
    string leaving_nick = message.substr(strlen(":o?LEAVE:o?"));
    if (user_state->username() == leaving_nick) {
      user_state->leave_room(room_name);
    } else {
      user_state->shrink_on_leave(room_name, leaving_nick);
    }
  } else if (message.find(":o?SEND:o?") == 0) {
    string message_with_id = message.substr(strlen(":o?SEND:o?"));
    size_t sender_pos = message_with_id.find(":o?");
    string message_id_str = message_with_id.substr(0, nick_pos);
    int message_id;
    stringstream(message_id_str) >> message_id;
    string sender_and_message = message_with_id.substr(nick_pos + strlen(":o?"));
    string message_pos = sender_and_message.find(":o?");
    string sender =  = message_with_id.substr(0, message_pos); //we don't care really about sender
    string pure_message = sender_and_message.substr(message_pos + strlen(":o?"));
        
    RoomAction the_action = user_statereceive->receive_handler(room_name, np1sec_message, message_id);
  }
  
  user_state->receive_handler(room_name, message);
  
}
