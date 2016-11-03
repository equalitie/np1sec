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

#include "src/channel.h"



class JabberiteChannelInterface;

class Jabberite
{
	public:
	Jabberite();
	
	void run(int argc, char** argv);
	virtual std::vector<option> extra_options() = 0;
	virtual bool process_option(char option, char* argument) = 0;
	virtual std::string explain_option(char option) = 0;
	virtual std::string explain_parameter(char option) = 0;
	
	
	
	void create_channel();
	void join_channel(int id);
	void authorize(std::string username);
	
	np1sec::Channel* channel(int id);
	
	
	
	virtual void connected() = 0;
	virtual void connection_error() = 0;
	virtual void disconnected() = 0;
	
	virtual void new_channel(int id, np1sec::Channel* channel) = 0;
	virtual void channel_removed(int id) = 0;
	virtual void joined_channel(int id) = 0;
	
	virtual void user_joined(int channel_id, std::string username) = 0;
	virtual void user_left(int channel_id, std::string username) = 0;
	virtual void user_authenticated(int channel_id, std::string username, np1sec::PublicKey public_key) = 0;
	virtual void user_authentication_failed(int channel_id, std::string username) = 0;
	virtual void user_authorized_by(int channel_id, std::string user, std::string target) = 0;
	virtual void user_promoted(int channel_id, std::string username) = 0;
	
	virtual void joined(int channel_id) = 0;
	virtual void authorized(int channel_id) = 0;
	
	
	
	int channel_id(np1sec::Channel* channel);
	int add_channel(JabberiteChannelInterface* interface);
	int remove_channel(np1sec::Channel* channel);
	
	
	
	protected:
	void do_run();
	void print_usage(std::string program_name, std::vector<option> extra_options);
	
	
	public:
	std::string username;
	std::string password;
	std::string server;
	std::string room_name;
	int port;
	
	PurpleAccount* account;
	PurpleConnection* connection;
	PurpleConversation* conversation;
	
	np1sec::Room* room;
	// interface
	std::vector<JabberiteChannelInterface*> channels;
};



#endif
