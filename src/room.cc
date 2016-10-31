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
	m_long_term_private_key(private_key)
{
	assert(m_interface);
}

void Room::join()
{
	if (connected()) {
		disconnect();
	}
	
	assert (!connected());
	
	m_ephemeral_private_key = PrivateKey::generate();
	
	User self;
	self.username = username();
	self.long_term_public_key = m_long_term_private_key.public_key();
	self.ephemeral_public_key = m_ephemeral_private_key.public_key();
	self.authenticated = true;
	m_users[m_username] = self;
	
	HelloMessage message;
	message.long_term_public_key = m_long_term_private_key.public_key();
	message.ephemeral_public_key = m_ephemeral_private_key.public_key();
	send_message(message.encode());
}

void Room::message_received(const std::string& sender, const std::string& text_message)
{
	Message np1sec_message;
	try {
		np1sec_message = Message::decode(text_message);
	} catch(MessageFormatException) {
		return;
	}
	
	if (np1sec_message.type == Message::Type::Hello) {
		try {
			HelloMessage message = HelloMessage::decode(np1sec_message);
			
			if (sender == m_username) {
				if (
					message.long_term_public_key != m_long_term_private_key.public_key() ||
					message.ephemeral_public_key != m_ephemeral_private_key.public_key()
				) {
					disconnect();
				}
			} else {
				register_user(sender, message.long_term_public_key, message.ephemeral_public_key);
			}
		} catch(MessageFormatException) {}
	} else if (np1sec_message.type == Message::Type::Authentication) {
		try {
			AuthenticationMessage message = AuthenticationMessage::decode(np1sec_message);
			
			if (sender == m_username) {
				if (
					message.sender_long_term_public_key != m_long_term_private_key.public_key() ||
					message.sender_ephemeral_public_key != m_ephemeral_private_key.public_key()
				) {
					disconnect();
				}
			} else {
				register_user(sender, message.sender_long_term_public_key, message.sender_ephemeral_public_key);
				
				if (
					   message.peer_username == m_username
					&& message.peer_long_term_public_key == m_long_term_private_key.public_key()
					&& message.peer_ephemeral_public_key == m_ephemeral_private_key.public_key()
				) {
					if (message.authentication_confirmation == authentication_token(
						sender,
						message.sender_long_term_public_key,
						message.sender_ephemeral_public_key,
						true
					)) {
						m_users[sender].authenticated = true;
						
						Identity identity;
						identity.username = sender;
						identity.public_key = message.sender_long_term_public_key;
						m_interface->user_joined(identity);
					}
				}
			}
		} catch(MessageFormatException) {}
	}
}

void Room::user_left(const std::string& username)
{
	if (m_users.count(username)) {
		remove_user(username);
	}
}

void Room::disconnect()
{
	m_users.clear();
	m_interface->disconnected();
}

void Room::register_user(const std::string& username, const PublicKey& long_term_public_key, const PublicKey& ephemeral_public_key)
{
	auto it = m_users.find(username);
	if (it != m_users.end()) {
		if (
			   it->second.long_term_public_key == long_term_public_key
			&& it->second.ephemeral_public_key == ephemeral_public_key
		) {
			return;
		} else {
			remove_user(username);
		}
	}
	
	User user;
	user.username = username;
	user.long_term_public_key = long_term_public_key;
	user.ephemeral_public_key = ephemeral_public_key;
	user.authenticated = false;
	m_users[username] = user;
	
	AuthenticationMessage message;
	message.sender_long_term_public_key = m_long_term_private_key.public_key();
	message.sender_ephemeral_public_key = m_ephemeral_private_key.public_key();
	message.peer_username = username;
	message.peer_long_term_public_key = long_term_public_key;
	message.peer_ephemeral_public_key = ephemeral_public_key;
	message.authentication_confirmation = authentication_token(username, long_term_public_key, ephemeral_public_key, false);
	send_message(message.encode());
}

Hash Room::authentication_token(const std::string& username, const PublicKey& long_term_public_key, const PublicKey& ephemeral_public_key, bool for_peer)
{
	Hash token = crypto::triple_diffie_hellman(
		m_long_term_private_key,
		m_ephemeral_private_key,
		long_term_public_key,
		ephemeral_public_key
	);
	std::string buffer = token.as_string();
	if (for_peer) {
		buffer += long_term_public_key.as_string();
		buffer += username;
	} else {
		buffer += m_long_term_private_key.public_key().as_string();
		buffer += m_username;
	}
	return crypto::hash(buffer);
}

void Room::remove_user(const std::string& username)
{
	auto it = m_users.find(username);
	if (it != m_users.end()) {
		User user = it->second;
		Identity identity;
		identity.username = user.username;
		identity.public_key = user.long_term_public_key;
		
		m_users.erase(it);
		m_interface->user_left(identity);
	}
}

void Room::send_message(const Message& message)
{
	m_interface->send_message(message.encode());
}



} // namespace np1sec
