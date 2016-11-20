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

#include "ui.h"

#include <unistd.h>

#define USE_VARARGS 1
#define PREFER_STDARG 1
#include <readline/readline.h>

class CliJabberite final : public Jabberite
{
	public:
	CliJabberite(): m_verbose(false) {}
	std::vector<option> extra_options();
	bool process_option(char option, char* argument);
	std::string explain_option(char option);
	std::string explain_parameter(char option);
	
	void connected();
	void connection_error();
	void disconnected();
	
	void new_channel(int id, np1sec::Channel* channel);
	void channel_removed(int id);
	void joined_channel(int id);
	
	void user_joined(int channel_id, std::string username);
	void user_left(int channel_id, std::string username);
	void user_authenticated(int channel_id, std::string username, np1sec::PublicKey public_key);
	void user_authentication_failed(int channel_id, std::string username);
	void user_authorized_by(int channel_id, std::string user, std::string target);
	void user_promoted(int channel_id, std::string username);
	
	void joined(int channel_id);
	void authorized(int channel_id);
	
	void joined_chat(int channel_id);
	void user_joined_chat(int channel_id, std::string username);
	void message_received(int channel_id, std::string username, std::string message);
	
	void dump(int channel_id);
	void print(const std::string& message);
	
	void parse_command(const std::string& line);
	
	protected:
	bool m_verbose;
};


std::vector<option> CliJabberite::extra_options()
{
	option verbose = { "verbose", 0, NULL, 'v' };
	
	std::vector<option> options;
	options.push_back(verbose);
	return options;
}

bool CliJabberite::process_option(char option, char* /*argument */)
{
	if (option == 'v') {
		m_verbose = true;
		return true;
	} else {
		return false;
	}
}

std::string CliJabberite::explain_option(char option)
{
	if (option == 'v') {
		return "Enable verbose channel status reporting";
	} else {
		return "";
	}
}

std::string CliJabberite::explain_parameter(char /* option */)
{
	return "";
}

void CliJabberite::connected()
{
	print("** Connected\n");
}

void CliJabberite::connection_error()
{
	print("** Connection error\n");
}

void CliJabberite::disconnected()
{
	print("** Disconnected\n");
}

void CliJabberite::new_channel(int id, np1sec::Channel*)
{
	print("** Found channel " + std::to_string(id) + ":\n");
	dump(id);
}

void CliJabberite::channel_removed(int id)
{
	print("** Removed channel " + std::to_string(id) + "\n");
}

void CliJabberite::joined_channel(int id)
{
	print("** Joined channel " + std::to_string(id) + ":\n");
	dump(id);
}

void CliJabberite::user_joined(int channel_id, std::string username)
{
	print("** User " + username + " joined the channel\n");
	dump(channel_id);
}

void CliJabberite::user_left(int channel_id, std::string username)
{
	print("** User " + username + " left the channel\n");
	dump(channel_id);
}

void CliJabberite::user_authenticated(int channel_id, std::string username, np1sec::PublicKey public_key)
{
	print("** User " + username + " authenticated as " + public_key.dump_hex() + "\n");
	dump(channel_id);
}

void CliJabberite::user_authentication_failed(int channel_id, std::string username)
{
	print("** User " + username + " failed authentication\n");
	dump(channel_id);
}

void CliJabberite::user_authorized_by(int channel_id, std::string user, std::string target)
{
	print("** User " + target + " was authorized by " + user + "\n");
	dump(channel_id);
}

void CliJabberite::user_promoted(int channel_id, std::string username)
{
	print("** User " + username + " was promoted\n");
	dump(channel_id);
}

void CliJabberite::joined(int channel_id)
{
	print("** You joined the channel\n");
	dump(channel_id);
}

void CliJabberite::authorized(int channel_id)
{
	print("** You were promoted\n");
	dump(channel_id);
}

void CliJabberite::joined_chat(int channel_id)
{
	print("** You joined the chat\n");
	dump(channel_id);
}

void CliJabberite::user_joined_chat(int channel_id, std::string username)
{
	print("** " + username + " joined the chat\n");
	dump(channel_id);
}

void CliJabberite::message_received(int /*channel_id*/, std::string username, std::string message)
{
	print("<" + username + "> " + message + "\n");
}


void CliJabberite::dump(int channel_id)
{
	if (!m_verbose) {
		return;
	}
	
	np1sec::Channel* channel = this->channel(channel_id);
	print(std::string("Channel status:\n"));
	print(std::string("  Member: ") + (channel->am_member() ? "yes" : "no") + "\n");
	print(std::string("  Authorized: ") + (channel->am_authorized() ? "yes" : "no") + "\n");
	print(std::string("Participants:\n"));
	for (const std::string& username : channel->users()) {
		print(std::string("  ") + username + "\n");
		if (channel->user_authentication(username) == np1sec::Channel::AuthenticationStatus::Authenticated) {
			print(std::string("    Identity: ") + channel->user_key(username).dump_hex() + "\n");
		} else if (channel->user_authentication(username) == np1sec::Channel::AuthenticationStatus::AuthenticationFailed) {
			print(std::string("    Identity: FAILED\n"));
		} else {
			print(std::string("    Identity: Unauthenticated\n"));
		}
		print(std::string("    Authorized: ") + (channel->user_is_authorized(username) ? "yes" : "no") + "\n");
		if (!channel->user_is_authorized(username)) {
			for (const std::string& peer : channel->users()) {
				if (channel->user_is_authorized(peer)) {
					print(std::string("      ") + peer + ":\n");
					print(std::string("        ") + username + " authorized by " + peer + ": " + (channel->user_has_authorized(peer, username) ? "yes" : "no") + "\n");
					print(std::string("        ") + peer + " authorized by " + username + ": " + (channel->user_has_authorized(username, peer) ? "yes" : "no") + "\n");
				}
			}
		}
	}
}

void readline_print(std::string message);

void CliJabberite::print(const std::string& message)
{
	readline_print(message);
}

void CliJabberite::parse_command(const std::string& line)
{
	if (line == "/create") {
		create_channel();
	} else if (line.substr(0, 5) == "/join") {
		size_t id = std::stoi(line.substr(6));
		join_channel(id);
	} else if (line.substr(0, 7) == "/accept") {
		authorize(line.substr(8));
	} else if (line.substr(0, 5) == "/kick") {
		votekick(line.substr(6), true);
	} else if (line.substr(0, 7) == "/unkick") {
		votekick(line.substr(8), false);
	} else if (line.substr(0, 1) == "/") {
		// do nothing
	} else {
		send_chat(line);
	}
}




CliJabberite* readline_cli_jabberite;
int readline_eof = 0;
bool readline_in_callback = false;

void readline_input_line(char *line)
{
	if (!line) {
		readline_eof = 1;
		return;
	}
	
	readline_in_callback = true;
	readline_cli_jabberite->parse_command(std::string(line));
	readline_in_callback = false;
}

void readline_print(std::string message)
{
	if (readline_in_callback) {
		printf("%s", message.c_str());
	} else {
		char* line = rl_copy_text(0, rl_end);
		rl_save_prompt();
		rl_replace_line("", 0);
		rl_redisplay();
		
		printf("%s", message.c_str());
		
		rl_replace_line(line, 0);
		free(line);
		rl_restore_prompt();
		rl_redisplay();
	}
}

static gboolean readline_stdin_callback(GIOChannel*, GIOCondition, gpointer)
{
	rl_callback_read_char();
	
	return readline_eof == 0;
}

int main(int argc, char** argv)
{
	readline_cli_jabberite = new CliJabberite();
	readline_cli_jabberite->parse_options(argc, argv);
	
	rl_callback_handler_install("", readline_input_line);
	atexit(rl_callback_handler_remove);
	
	GIOChannel* io = g_io_channel_unix_new(STDIN_FILENO);
	g_io_add_watch(io, G_IO_IN, readline_stdin_callback, NULL);
	
	readline_cli_jabberite->run();
	
	return 0;
}
