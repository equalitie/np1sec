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

//! Conversation
class Conversation
{
	public:
	/**
	 * Constructor
	 */
	Conversation(Room* room);
	Conversation(Room* room, const ConversationStatusMessage& conversation_status, const std::string& sender, const ConversationMessage& encoded_message);
	
	/*
	 * Public API
	 */
	/* Accessors */

	/**
	 * Return the participant names in this conversation
	 *
	 * A participant is any (n+1)sec user who has bee in the state of
	 * joining this conversation but has not left yet.
	 *
	 * If such user is us, then the 'joining' status
	 * is indicated through the  ConversationInterface::joining callback
	 * otherwise it is indicated through the ConversationInterface::user_joining
	 * callback.
	 *
	 * Similarly, user leaving this conversation is indicated through
	 * the ConversationInterface::left and ConversationInterface::user_left
	 * callbacks.
	 */
	std::set<std::string> participants() const;

	/**
	 * Return a set of user names who have been invited by other
	 * participants to join this conversation.
	 */
	std::set<std::string> invitees() const;

	/**
	 * \brief TODO
	 */
	bool user_is_authenticated(const std::string& username) const;

	/**
	 * \brief TODO
	 */
	bool user_failed_authentication(const std::string& username) const;

	/**
	 * Return a public key of the user with name \p username
	 *
	 * The InvalidUserException is thrown when no such user
	 * is in this conversation (either as invitee or participant) or has not yet
	 * been authenticated.
	 */
	PublicKey user_public_key(const std::string& username) const;

	/**
	 * \brief TODO
	 */
	bool user_is_votekicked(const std::string&victim, const std::string& participant) const;

	/**
	 * \brief TODO
	 */
	bool participant_joined(const std::string& username) const;

	/**
	 * \brief TODO
	 */
	std::string invitee_inviter(const std::string& username) const;

	/**
	 * True when we can decode messages sent by others in this conversation
	 * and they can decode our messages.
	 *
	 * Equivalently, this value is true when we're between the calls
	 * ConversationInterface::joined and ConversationInterface::left.
	 */
	bool joined() const;

	/**
	 * \brief TODO
	 */
	bool is_invite() const;
	
	/* Operations */

	/**
	 * Indicate to the library that we no longer want to be part of this
	 * conversation.
	 *
	 * If the \p detach argument is false, this conversation shall
	 * be destroyed inside this command and no further conversation callbacks
	 * shall be executed.
	 *
	 * If the \p detach argument is true, this conversation shall
	 * remain valid until the ConversationInterface::left callback
	 * is executed.
	 */
	void leave(bool detach);

	/**
	 * Invite another user into this conversation.
	 */
	void invite(const std::string& username, const PublicKey& long_term_public_key);

	/**
	 * Cancel invitation to the user \p username whom we've previously
	 * invited with the Conversation::invite command.
	 */
	void cancel_invite(const std::string& username);

	/**
	 * Join the conversation we've been invited to
	 *
	 * The invitation is indicated to us through the
	 * RoomInterface::invited_to_conversation command.
	 */
	void join();

	/**
	 * \brief TODO
	 */
	void votekick(const std::string& username, bool kick);

	/**
	 * Send an encrypted message to this conversation.
	 *
	 * \param message is a clear text string that shall be encrypted
	 *        before it is sent.
	 */
	void send_chat(const std::string& message);
	
	
	
	/*
	 * Internal API
	 */
	/* Callbacks */

	void message_received(const std::string& sender, const ConversationMessage& conversation_message);
	void user_left(const std::string& username);

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
