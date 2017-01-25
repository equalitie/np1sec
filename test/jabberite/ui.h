/**
 * (n+1)Sec Multiparty Off-the-Record Messaging library
 * Copyright (C) 2016, eQualit.ie
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

#ifndef TEST_JABBERITE_UI_H
#define TEST_JABBERITE_UI_H

extern "C" {
#include <glib.h>
#include "purple.h"
}

#include <getopt.h>

#include <string>
#include <vector>

#include "src/room.h"



class JabberiteConversationInterface;

class Jabberite
{
	public:
	Jabberite();
	
	void parse_options(int argc, char** argv);
	void run();
	virtual std::vector<option> extra_options() = 0;
	virtual bool process_option(char option, char* argument) = 0;
	virtual std::string explain_option(char option) = 0;
	virtual std::string explain_parameter(char option) = 0;
	
	void connect();
	void disconnect();
	void create_conversation();
	
	void leave(int conversation_id);
	void invite(int conversation_id, std::string username);
	void join(int conversation_id);
	void votekick(int conversation_id, std::string username, bool kick);
	void send_chat(int conversation_id, std::string message);
	
	np1sec::Conversation* conversation(int id);
	
	
	
	virtual void connected() = 0;
	virtual void connection_error() = 0;
	virtual void disconnected() = 0;
	
	virtual void user_joined(std::string username, np1sec::PublicKey public_key) = 0;
	virtual void user_left(std::string username, np1sec::PublicKey public_key) = 0;
	
	virtual void created_conversation(int id, np1sec::Conversation* conversation) = 0;
	virtual void invited_to_conversation(int id, np1sec::Conversation* conversation, std::string username) = 0;
	
	virtual void user_invited(int conversation_id, std::string inviter, std::string invitee) = 0;
	virtual void invitation_cancelled(int conversation_id, std::string inviter, std::string invitee) = 0;
	virtual void user_authenticated(int conversation_id, std::string username, np1sec::PublicKey public_key) = 0;
	virtual void user_authentication_failed(int conversation_id, std::string username) = 0;
	virtual void user_joining(int conversation_id, std::string username) = 0;
	virtual void user_left(int conversation_id, std::string username) = 0;
	virtual void votekick_registered(int conversation_id, std::string kicker, std::string victim, bool kicked) = 0;
	
	virtual void user_joined(int conversation_id, std::string username) = 0;
	virtual void message_received(int conversation_id, std::string sender, std::string message) = 0;
	
	virtual void joining(int conversation_id) = 0;
	virtual void joined(int conversation_id) = 0;
	virtual void left(int conversation_id) = 0;
	
	int conversation_id(np1sec::Conversation* conversation);
	int add_conversation(JabberiteConversationInterface* interface);
	int remove_conversation(np1sec::Conversation* conversation);
	
	
	
	protected:
	void do_run();
	void print_usage(std::string program_name, std::vector<option> extra_options);
	
	
	public:
	std::string username;
	std::string password;
	std::string server;
	std::string room_name;
	int port;
	std::string nickname;
	
	PurpleAccount* account;
	PurpleConnection* connection;
	PurpleConversation* conv;
	
	bool frozen;
	
	np1sec::Room* room;
	// interface
	std::vector<JabberiteConversationInterface*> conversations;
};



#endif
