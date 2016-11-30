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

#ifndef SRC_ROOM_H_
#define SRC_ROOM_H_

#include "conversationlist.h"
#include "interface.h"
#include "message.h"
#include "timer.h"

#include <deque>
#include <map>
#include <set>

namespace np1sec
{

class Room
{
	public:
	Room(RoomInterface* interface, const std::string& username, const PrivateKey& private_key);
	
	/*
	 * Public API
	 */
	/* Accessors */
	bool connected() const;
	std::map<std::string, PublicKey> users() const;
	std::set<Conversation*> conversations() const;
	std::set<Conversation*> invites() const;
	
	/* Operations */
	void connect();
	void disconnect();
	void create_conversation();
	
	/* Callbacks */
	void message_received(const std::string& sender, const std::string& text_message);
	void user_left(const std::string& username);
	void left_room();
	
	
	
	/*
	 * Internal API
	 */
	/* Accessors */
	const std::string& username() const
	{
		return m_username;
	}
	
	const PublicKey& public_key() const
	{
		return m_long_term_private_key.public_key();
	}
	
	const PrivateKey& private_key() const
	{
		return m_long_term_private_key;
	}
	
	RoomInterface* interface()
	{
		return m_interface;
	}
	
	/* Operations */
	void send_message(const Message& message);
	void send_message(const std::string& message);
	
	void conversation_add_user(Conversation* conversation, const std::string& username, const PublicKey& conversation_public_key)
	{
		m_conversations.conversation_add_user(conversation, username, conversation_public_key);
	}
	
	void conversation_remove_user(Conversation* conversation, const std::string& username, const PublicKey& conversation_public_key)
	{
		m_conversations.conversation_remove_user(conversation, username, conversation_public_key);
	}
	
	void conversation_set_authenticated(Conversation* conversation)
	{
		m_conversations.conversation_set_authenticated(conversation);
	}
	
	void conversation_set_participant(Conversation* conversation)
	{
		m_conversations.conversation_set_participant(conversation);
	}
	
	
	
	protected:
	void user_removed(const std::string& username);
	void user_disconnected(const std::string& username);
	
	protected:
	RoomInterface* m_interface;
	
	std::string m_username;
	PrivateKey m_long_term_private_key;
	PrivateKey m_ephemeral_private_key;
	
	std::deque<std::string> m_message_queue;
	bool m_disconnecting;
	Hash m_disconnect_nonce;
	
	struct User
	{
		std::string username;
		PublicKey long_term_public_key;
		PublicKey ephemeral_public_key;
		bool authenticated;
		Hash authentication_nonce;
	};
	std::map<std::string, User> m_users;
	
	ConversationList m_conversations;
};

} // namespace np1sec

#endif
