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

#include "room.h"

#include <cassert>

namespace np1sec
{

Room::Room(RoomInterface* interface, const std::string& username, const PrivateKey& private_key):
	m_interface(interface),
	m_username(username),
	m_long_term_private_key(private_key),
	m_disconnecting(false),
	m_conversations(this)
{
	assert(m_interface);
}

void Room::connect()
{
	if (!m_users.empty() || !m_message_queue.empty()) {
		disconnect();
	}
	
	m_ephemeral_private_key = PrivateKey::generate(true);
	
	HelloMessage hello_message;
	hello_message.long_term_public_key = m_long_term_private_key.public_key();
	hello_message.ephemeral_public_key = m_ephemeral_private_key.public_key();
	hello_message.reply = false;
	send_message(hello_message.encode());
}

void Room::disconnect()
{
	m_disconnecting = true;
	m_disconnect_nonce = crypto::nonce_hash();
	
	QuitMessage quit_message;
	quit_message.nonce = m_disconnect_nonce;
	send_message(quit_message.encode());
	
	m_message_queue.clear();
	
	interface()->disconnected();
	
	m_users.clear();
	
	m_conversations.disconnect();
}

void Room::create_conversation()
{
	m_conversations.create_conversation();
}

void Room::message_received(const std::string& sender, const std::string& text_message)
{
	if (m_disconnecting) {
		if (sender != username()) {
			return;
		}
		
		Message np1sec_message;
		try {
			np1sec_message = Message::decode(text_message);
		} catch(MessageFormatException) {
			return;
		}
		
		QuitMessage quit_message;
		try {
			quit_message = QuitMessage::decode(np1sec_message);
		} catch(MessageFormatException) {
			return;
		}
		
		if (quit_message.nonce == m_disconnect_nonce) {
			m_disconnecting = false;
		}
		return;
	}
	
	if (sender == username()) {
		if (m_message_queue.empty() || m_message_queue.front() != text_message) {
			disconnect();
			return;
		}
		m_message_queue.pop_front();
	}
	
	Message np1sec_message;
	try {
		np1sec_message = Message::decode(text_message);
	} catch(MessageFormatException) {
		return;
	}
	
	if (np1sec_message.type == Message::Type::Quit) {
		user_disconnected(sender);
	} else if (np1sec_message.type == Message::Type::Hello) {
		HelloMessage message;
		try {
			message = HelloMessage::decode(np1sec_message);
		} catch(MessageFormatException) {
			return;
		}
		
		if (m_users.count(sender)) {
			if (
				   m_users.at(sender).long_term_public_key == message.long_term_public_key
				&& m_users.at(sender).ephemeral_public_key == message.ephemeral_public_key
			) {
				return;
			}
			
			user_removed(sender);
		}
		
		User user;
		user.username = sender;
		user.long_term_public_key = message.long_term_public_key;
		user.ephemeral_public_key = message.ephemeral_public_key;
		user.authenticated = false;
		user.authentication_nonce = crypto::nonce_hash();
		m_users[sender] = std::move(user);
		
		if (sender == username()) {
			m_users[sender].authenticated = true;
			interface()->connected();
			return;
		}
		
		if (!message.reply || message.reply_to_username != username()) {
			HelloMessage reply_message;
			reply_message.long_term_public_key = m_long_term_private_key.public_key();
			reply_message.ephemeral_public_key = m_ephemeral_private_key.public_key();
			reply_message.reply = true;
			reply_message.reply_to_username = sender;
			send_message(reply_message.encode());
		}
		
		RoomAuthenticationRequestMessage authentication_request_message;
		authentication_request_message.username = sender;
		authentication_request_message.nonce = m_users.at(sender).authentication_nonce;
		send_message(authentication_request_message.encode());
	} else if (np1sec_message.type == Message::Type::RoomAuthenticationRequest) {
		RoomAuthenticationRequestMessage message;
		try {
			message = RoomAuthenticationRequestMessage::decode(np1sec_message);
		} catch(MessageFormatException) {
			return;
		}
		
		if (message.username != username()) {
			return;
		}
		
		if (!m_users.count(sender)) {
			return;
		}
		const User& user = m_users.at(sender);
		
		RoomAuthenticationMessage reply;
		reply.username = sender;
		reply.authentication_confirmation = crypto::authentication_token(
			m_long_term_private_key,
			m_ephemeral_private_key,
			user.long_term_public_key,
			user.ephemeral_public_key,
			message.nonce,
			username()
		);
		send_message(reply.encode());
	} else if (np1sec_message.type == Message::Type::RoomAuthentication) {
		RoomAuthenticationMessage message;
		try {
			message = RoomAuthenticationMessage::decode(np1sec_message);
		} catch(MessageFormatException) {
			return;
		}
		
		if (message.username != username()) {
			return;
		}
		
		if (!m_users.count(sender)) {
			return;
		}
		User& user = m_users.at(sender);
		
		if (user.authenticated) {
			return;
		}
		if (message.authentication_confirmation == crypto::authentication_token(
			m_long_term_private_key,
			m_ephemeral_private_key,
			user.long_term_public_key,
			user.ephemeral_public_key,
			user.authentication_nonce,
			sender
		)) {
			user.authenticated = true;
			interface()->user_joined(user.username, user.long_term_public_key);
		}
	}
	
	if (Message::is_conversation_message(np1sec_message.type)) {
		ConversationMessage message;
		try {
			message = ConversationMessage::decode(np1sec_message);
		} catch(MessageFormatException) {
			return;
		}
		
		if (!message.verify()) {
			return;
		}
		
		m_conversations.message_received(sender, message);
	}
}

void Room::user_left(const std::string& username)
{
	user_disconnected(username);
}

void Room::left_room()
{
	// TODO: left_room() conversations
}

void Room::send_message(const Message& message)
{
	send_message(message.encode());
}

void Room::send_message(const std::string& message)
{
	m_message_queue.push_back(message);
	m_interface->send_message(message);
}

void Room::user_removed(const std::string& username)
{
	if (!m_users.count(username)) {
		return;
	}
	
	PublicKey public_key = m_users.at(username).long_term_public_key;
	bool authenticated = m_users.at(username).authenticated;
	m_users.erase(username);
	
	if (authenticated) {
		interface()->user_left(username, public_key);
	}
}

void Room::user_disconnected(const std::string& username)
{
	m_conversations.user_left(username);
	
	user_removed(username);
}

} // namespace np1sec
