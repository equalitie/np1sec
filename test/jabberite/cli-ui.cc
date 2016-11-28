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
	
	void user_joined(std::string username, np1sec::PublicKey public_key);
	void user_left(std::string username, np1sec::PublicKey public_key);

	void created_conversation(int id, np1sec::Conversation* conversation);
	void invited_to_conversation(int id, np1sec::Conversation* conversation, std::string username);
	
	void user_invited(int conversation_id, std::string inviter, std::string invitee);
	void invitation_cancelled(int conversation_id, std::string inviter, std::string invitee);
	void user_authenticated(int conversation_id, std::string username, np1sec::PublicKey public_key);
	void user_authentication_failed(int conversation_id, std::string username);
	void user_joined(int conversation_id, std::string username);
	void user_left(int conversation_id, std::string username);
	void votekick_registered(int conversation_id, std::string kicker, std::string victim, bool kicked);
	
	void user_joined_chat(int conversation_id, std::string username);
	void message_received(int conversation_id, std::string sender, std::string message);
	
	void joined(int conversation_id);
	void joined_chat(int conversation_id);
	void left(int conversation_id);
	
	void dump(int conversation_id);
	void print(const std::string& message);
	
	void parse_command(const std::string& line);
	
	protected:
	bool m_verbose;
	int m_active_conversation = -1;
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
		return "Enable verbose conversation status reporting";
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

void CliJabberite::user_joined(std::string username, np1sec::PublicKey public_key)
{
	print("** User joined: " + username + "    " + public_key.dump_hex() + "\n");
}

void CliJabberite::user_left(std::string username, np1sec::PublicKey public_key)
{
	print("** User left: " + username + "    " + public_key.dump_hex() + "\n");
}

void CliJabberite::created_conversation(int id, np1sec::Conversation*)
{
	print("** Created conversation " + std::to_string(id) + ":\n");
	dump(id);
}

void CliJabberite::invited_to_conversation(int id, np1sec::Conversation*, std::string username)
{
	print("** Invited to conversation " + std::to_string(id) + " by " + username + ":\n");
	dump(id);
}

void CliJabberite::user_invited(int conversation_id, std::string inviter, std::string invitee)
{
	print("** <" + std::to_string(conversation_id) + "> " + inviter + " invited user " + invitee + "\n");
	if (m_verbose) dump(conversation_id);
}

void CliJabberite::invitation_cancelled(int conversation_id, std::string inviter, std::string invitee)
{
	print("** <" + std::to_string(conversation_id) + "> " + inviter + " cancelled the invite for user " + invitee + "\n");
	if (m_verbose) dump(conversation_id);
}

void CliJabberite::user_authenticated(int conversation_id, std::string username, np1sec::PublicKey public_key)
{
	print("** <" + std::to_string(conversation_id) + "> " + username + " authenticated as " + public_key.dump_hex() + "\n");
	if (m_verbose) dump(conversation_id);
}

void CliJabberite::user_authentication_failed(int conversation_id, std::string username)
{
	print("** <" + std::to_string(conversation_id) + "> " + username + " failed to authenticate\n");
	if (m_verbose) dump(conversation_id);
}

void CliJabberite::user_joined(int conversation_id, std::string username)
{
	print("** <" + std::to_string(conversation_id) + "> " + username + " joined the conversation\n");
	if (m_verbose) dump(conversation_id);
}

void CliJabberite::user_left(int conversation_id, std::string username)
{
	print("** <" + std::to_string(conversation_id) + "> " + username + " left the conversation\n");
	if (m_verbose) dump(conversation_id);
}

void CliJabberite::votekick_registered(int conversation_id, std::string kicker, std::string victim, bool kicked)
{
	print("** <" + std::to_string(conversation_id) + "> " + kicker + (kicked ? " kicked " : " unkicked ") + victim + "\n");
	if (m_verbose) dump(conversation_id);
}

void CliJabberite::user_joined_chat(int conversation_id, std::string username)
{
	print("** <" + std::to_string(conversation_id) + "> " + username + " joined the chat session\n");
	if (m_verbose) dump(conversation_id);
}

void CliJabberite::message_received(int conversation_id, std::string sender, std::string message)
{
	print("** <" + std::to_string(conversation_id) + "> <" + sender + "> " + message + "\n");
}

void CliJabberite::joined(int conversation_id)
{
	print("** <" + std::to_string(conversation_id) + "> you joined the conversation\n");
	if (m_verbose) dump(conversation_id);
}

void CliJabberite::joined_chat(int conversation_id)
{
	print("** <" + std::to_string(conversation_id) + "> you joined the chat session\n");
	if (m_verbose) dump(conversation_id);
}

void CliJabberite::left(int conversation_id)
{
	print("** <" + std::to_string(conversation_id) + "> you left the conversation\n");
	if (m_verbose) dump(conversation_id);
}

void CliJabberite::dump(int conversation_id)
{
	np1sec::Conversation* conversation = this->conversation(conversation_id);
	
	print(std::string("Conversation status <") + std::to_string(conversation_id) + ">:\n");
	print(std::string("  Status: ") + (conversation->is_invite() ? "invited" : conversation->in_chat() ? "chatting" : "participant") + "\n");
	print(std::string("Participants:\n"));
	for (const std::string& username : conversation->participants()) {
		print(std::string("  ") + username + "\n");
		if (conversation->user_is_authenticated(username)) {
			print(std::string("    Identity: ") + conversation->user_public_key(username).dump_hex() + "\n");
		} else if (conversation->user_failed_authentication(username)) {
			print(std::string("    Identity: FAILED\n"));
		} else {
			print(std::string("    Identity: Unauthenticated\n"));
		}
		print(std::string("    In chat: ") + (conversation->participant_in_chat(username) ? "yes" : "no") + "\n");
	}
	print(std::string("Invitees:\n"));
	for (const std::string& username : conversation->invitees()) {
		print(std::string("  ") + username + "\n");
		if (conversation->user_is_authenticated(username)) {
			print(std::string("    Identity: ") + conversation->user_public_key(username).dump_hex() + "\n");
		} else if (conversation->user_failed_authentication(username)) {
			print(std::string("    Identity: FAILED\n"));
		} else {
			print(std::string("    Identity: Unauthenticated\n"));
		}
		print(std::string("    Invited by: ") + conversation->invitee_inviter(username) + "\n");
	}
}

void readline_print(std::string message);

void CliJabberite::print(const std::string& message)
{
	readline_print(message);
}

void CliJabberite::parse_command(const std::string& line)
{
	if (line == "/connect") {
		connect();
	} else if (line == "/disconnect") {
		disconnect();
	} else if (line == "/create") {
		create_conversation();
	} else if (line.substr(0, 7) == "/select") {
		int id = std::stoi(line.substr(8));
		if (conversation(id)) {
			print("** Selecting conversation " + std::to_string(id) + "\n");
			m_active_conversation = id;
		}
	} else if (line.substr(0, 7) == "/invite") {
		invite(m_active_conversation, line.substr(8));
	} else if (line == "/join") {
		join(m_active_conversation);
	} else if (line.substr(0, 5) == "/kick") {
		votekick(m_active_conversation, line.substr(6), true);
	} else if (line.substr(0, 7) == "/unkick") {
		votekick(m_active_conversation, line.substr(8), false);
	} else if (line == "/freeze") {
		frozen = true;
	} else if (line == "/unfreeze") {
		frozen = false;
	} else if (line.substr(0, 1) == "/") {
		// do nothing
	} else {
		send_chat(m_active_conversation, line);
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
