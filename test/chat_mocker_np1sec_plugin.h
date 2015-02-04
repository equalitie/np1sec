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
 * Receive the messages from chat mocker, interpret the message and
 * call the approperiate function from userstate class  of npsec1 
 * libreary.
 * 
 */
void chat_mocker_plugin_receive_handler(std::string room_name,
                                        std::string message,
                                        void* aux_data);

#endif  // TEST_CHAT_MOCKER_NP!SEC_PLUGIN_H_
