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

#ifndef CHAT_MOCKER_NP1SEC_PLUGIN_H_
#define CHAT_MOCKER_NP1SEC_PLUGIN_H_

/**
 * This need to be given to np1sec to info the ui of joinig 
 * a room 
 */
void chat_mocker_np1sec_plugin_join(std::string room_name,
                                    void* aux_data);

// Just a wrapper to call the mocker send function
void send_bare(std::string room_name, std::string message, void* data);

void new_session_announce(std::string room_name, std::string sender_nickname, void* aux_data);

/**
 * Receive the messages from chat mocker, interpret the message and
 * call the approperiate function from userstate class  of npsec1 
 * libreary.
 * 
 */
void chat_mocker_plugin_receive_handler(std::string room_name,
                                        std::string message,
                                        void* aux_data);

/**
 * This should be called by the client to secure send
 * user message to a room,using np1sec library
 */
void chat_mocker_np1sec_plugin_send(std::string room_name,
                                    std::string message,
                                    void* aux_data);


#endif  // TEST_CHAT_MOCKER_NP!SEC_PLUGIN_H_
