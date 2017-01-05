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

#ifndef SRC_CONVERSATION_H_
#define SRC_CONVERSATION_H_

#include "crypto.h"
#include "encryptedchat.h"
#include "message.h"
#include "timer.h"

#include <deque>
#include <list>
#include <map>
#include <string>

namespace np1sec
{

class Room;

class InvalidUserException {};

class Conversation
{
	public:
	Conversation(Room* room);
	Conversation(Room* room, const ConversationStatusMessage& conversation_status, const std::string& sender, const ConversationMessage& encoded_message);
	
	/*
	 * Public API
	 */
	/* Accessors */
	std::set<std::string> participants() const;
	std::set<std::string> invitees() const;
	bool user_is_authenticated(const std::string& username) const;
	bool user_failed_authentication(const std::string& username) const;
	PublicKey user_public_key(const std::string& username) const;
	bool user_is_votekicked(const std::string&victim, const std::string& participant) const;
	bool participant_in_chat(const std::string& username) const;
	std::string invitee_inviter(const std::string& username) const;
	bool in_chat() const;
	bool is_invite() const;
	
	/* Operations */
	void leave(bool detach);
	void invite(const std::string& username, const PublicKey& long_term_public_key);
	void cancel_invite(const std::string& username);
	void join();
	void votekick(const std::string& username, bool kick);
	void send_chat(const std::string& message);
	
	/* Callbacks */
	void message_received(const std::string& sender, const ConversationMessage& conversation_message);
	void user_left(const std::string& username);
	
	
	
	/*
	 * Internal API
	 */
	/* Accessors */
	Room* room() const { return m_room; }
	ConversationInterface* interface() const { return m_interface; }
	void set_interface(ConversationInterface* interface) { m_interface = interface;	}
	const Hash& conversation_status_hash() const { return m_conversation_status_hash; }
	std::map<std::string, PublicKey> conversation_users() const;
	
	bool am_involved() const;
	bool am_confirmed() const;
	bool am_authenticated() const;
	bool am_participant() const;
	bool am_chatting() const;
	
	/* Operations */
	void send_message(const Message& message);
	void send_message(const UnsignedConversationMessage& conversation_message);
	void add_key_exchange_event(Message::Type type, const Hash& key_id, const std::set<std::string>& usernames);
	void remove_user(const std::string& username);
	void remove_users(const std::set<std::string>& usernames);
	
	
	
	protected:
	struct Event
	{
		/*
		 * This struct is really a union, but I am too lazy to implement a C++11 union.
		 */
		Message::Type type;
		std::set<std::string> remaining_users;
		
		// used for conversation status and confirmation
		ConversationStatusEventPayload conversation_status;
		ConsistencyCheckEventPayload consistency_check;
		// used for key exchanges and key activations
		KeyActivationEventPayload key_event;
		
		Timer timeout_timer;
		bool timeout;
	};
	
	class EventReference
	{
		public:
		EventReference():
			m_list(nullptr)
		{}
		
		explicit EventReference(std::list<Event>* list, std::list<Event>::iterator iterator):
			m_list(list),
			m_iterator(iterator)
		{}
		
		EventReference(EventReference&& other):
			m_list(nullptr)
		{
			*this = std::move(other);
		}
		
		~EventReference()
		{
			if (m_list) {
				if (m_iterator->remaining_users.empty()) {
					m_list->erase(m_iterator);
				}
			}
		}
		
		EventReference& operator=(EventReference&& other)
		{
			m_list = other.m_list;
			if (m_list) {
				m_iterator = other.m_iterator;
			}
			other.m_list = nullptr;
			return *this;
		}
		
		operator bool() const
		{
			return m_list != nullptr;
		}
		
		Event* operator->()
		{
			return &(*m_iterator);
		}
		
		protected:
		std::list<Event>* m_list;
		std::list<Event>::iterator m_iterator;
	};
	
	enum class AuthenticationStatus { Unauthenticated, Authenticating, Authenticated, AuthenticationFailed };
	struct Participant
	{
		/*
		 * Part of the shared state machine
		 */
		bool is_participant;
		
		std::string username;
		PublicKey long_term_public_key;
		PublicKey conversation_public_key;
		
		// only for participants
		std::set<std::string> timeout_peers;
		std::set<std::string> votekick_peers;
		
		// only for non-participants
		std::string inviter;
		bool authenticated;
		
		/*
		 * Local state
		 */
		AuthenticationStatus authentication_status;
		Hash authentication_nonce;
		
		bool timeout_in_flight;
		bool votekick_in_flight;
		
		std::deque<std::list<Event>::iterator> events;
		
		Timer conversation_status_timer;
		
		// only for participants
		std::map<std::string, PublicKey> invitees;
	};
	
	struct UnconfirmedInvite
	{
		/*
		 * Part of the shared state machine
		 */
		std::string inviter;
		
		std::string username;
		PublicKey long_term_public_key;
	};
	
	
	
	protected:
	/* Operations */
	void hash_message(const std::string& sender, const UnsignedConversationMessage& message);
	void hash_payload(const std::string& sender, uint8_t type, const std::string& message);
	void declare_event(Event&& event);
	void do_invite(const std::string& username);
	void remove_invite(std::string inviter, std::string username);
	void do_remove_user(const std::string& username);
	void check_timeout(const std::string& username);
	void set_conversation_status_timer();
	void set_user_conversation_status_timer(const std::string& username);
	void try_split(bool because_votekick);
	
	/* Other */
	UnsignedConversationMessage conversation_status(const std::string& invitee_username, const PublicKey& invitee_long_term_public_key) const;
	EventReference first_user_event(const std::string& username);
	
	bool fsck();
	
	
	
	protected:
    public:
	Room* m_room;
	PrivateKey m_conversation_private_key;
	ConversationInterface* m_interface;
	
	std::map<std::string, Participant> m_participants;
	std::map<std::string, std::map<PublicKey, UnconfirmedInvite>> m_unconfirmed_invites;
	Hash m_conversation_status_hash;
	
	std::list<Event> m_events;
	
	EncryptedChat m_encrypted_chat;
	
	Timer m_conversation_status_timer;
	
	std::map<std::string, PublicKey> m_own_invites;
	
	// used only when we are unconfirmed
	Hash m_status_message_hash;
	std::set<std::string> m_unconfirmed_users;
};

} // namespace np1sec

#endif
