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

#include <functional>
#include <deque>
#include <map>
#include <set>

namespace np1sec
{

//! Room class
class Room
{
	public:
	/*
	 * Public API
	 */

	/**
	 * Construct the room, no interface callbacks shall be called until
	 * the Room::connect() function is called.
	 */
	Room(RoomInterface* interface, const std::string& username, const PrivateKey& private_key);

	/**
	 * True after Room::connect() was called but before
	 * RoomInterface::disconnected() called back.
	 */
	bool connected() const;

	/**
	 * Return the map of authenticated users and their corresponding public keys.
	 */
	std::map<std::string, PublicKey> users() const;

	/**
	 * Return the set of conversations we created
	 *
	 * TODO: Proofread
	 * These are conversations we've created using the Room::create_conversation
	 * function but before we left them (ConversationInterface::left).
	 */
	std::set<Conversation*> conversations() const;

	/**
	 * Return the set of conversations we were invited into
	 *
	 * TODO: Proofread
	 * These are conversations created through the RoomInterface::invited_to_conversation
	 * callback callback before we left them (ConversationInterface::left).
	 */
	std::set<Conversation*> invites() const;
	
	/* Operations */

	/**
	 * Indicate to the library that the comunication link is ready to be used.
	 */
	void connect();

	/**
	 * Broadcast a Quit message and destroy all conversations
	 *
	 * Inside this function the RoomInterface::disconnected
	 * callback is executed.
	 */
	void disconnect();

	/**
	 * Initiate the creation of a new secure conversation.
	 *
	 * Once the conversation is created, the
	 * RoomInterface::created_conversation callback will be executed.
	 */
	void create_conversation();
	
	/* Callbacks */

	/**
	 * Tell the library that a new (n+1)sec message has arrived.
	 *
	 * The library doesn't own a communication channel and thus relies
	 * on the user to transport the encrypted messages between other
	 * users (e.g. using XMPP).
	 *
	 * This function is the *input* for the library. The *output*
	 * must be implemented through the RoomInterface::send_message
	 * function.
	 *
	 * \param sender Clear text user name of the sender
	 * \param text_message Encrypted message.
	 */
	void message_received(const std::string& sender, const std::string& text_message);


	/**
	 * Indicate to the library a user has left.
	 */
	void user_left(const std::string& username);

	/**
	 * TODO
	 */
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
	
	
	/* Debug */
	template<class F>
	void set_inbound_message_filter(F&& f) {
		m_inbound_message_filter = std::forward<F>(f);
	}

	template<class F>
	void set_outbound_message_filter(F&& f) {
		m_outbound_message_filter = std::forward<F>(f);
	}

	void debug_disable_fsck(bool disable = true) {
		m_debug_disable_fsck = disable;
	}

	bool is_fsck_enabled() const {
		return !m_debug_disable_fsck;
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
	
	bool m_debug_disable_fsck = false;

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

	/* Called before the message is processed. If the function returns false,
	 * the message won't be processed. It is used for debugging and testing. */
	std::function<bool(const std::string&, const Message&)> m_inbound_message_filter;

	/* Called before the message is sent. If the function returns false,
	 * the message won't be sent. It is used for debugging and testing. */
	std::function<bool(const Message&)> m_outbound_message_filter;
};

} // namespace np1sec

#endif
