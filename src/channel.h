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

#ifndef SRC_CHANNEL_H_
#define SRC_CHANNEL_H_

#include "crypto.h"
#include "message.h"
#include "timer.h"

#include <map>
#include <string>
#include <vector>

namespace np1sec
{

class Room;

class Channel
{
	public:
	enum class AuthenticationStatus { Unauthenticated, Authenticating, Authenticated, AuthenticationFailed };
	
	public:
	Channel(Room* room);
	Channel(Room* room, const ChannelStatusMessage& channel_status, const Message& encoded_message);
	Channel(Room* room, const ChannelAnnouncementMessage& channel_status, const std::string& sender);
	
	/*
	 * Provisional public API. This will be redesigned later.
	 */
	class InvalidUserException {};
	// user list
	std::vector<std::string> users() const
	{
		std::vector<std::string> result;
		for (const auto& i : m_participants) {
			result.push_back(i.first);
		}
		return result;
	}
	
	// authentication status. Unauthenticated and Authenticating are equivalent.
	AuthenticationStatus user_authentication(const std::string& username) const
	{
		if (!m_participants.count(username)) {
			throw InvalidUserException();
		}
		return m_participants.at(username).authentication_status;
	}
	
	// user's public key. Defined only for Authenticated users.
	PublicKey user_key(const std::string& username) const
	{
		if (!m_participants.count(username)) {
			throw InvalidUserException();
		}
		if (m_participants.at(username).authentication_status != AuthenticationStatus::Authenticated) {
			throw InvalidUserException();
		}
		return m_participants.at(username).long_term_public_key;
	}
	
	// returns whether a user is a full member of the channel.
	bool user_is_authorized(const std::string& username) const
	{
		if (!m_participants.count(username)) {
			throw InvalidUserException();
		}
		return m_participants.at(username).authorized;
	}
	
	// returns whether <user> has authorized <target>
	bool user_has_authorized(const std::string& user, const std::string& target) const
	{
		if (!m_participants.count(user)) {
			throw InvalidUserException();
		}
		if (!m_participants.count(target)) {
			throw InvalidUserException();
		}
		if (m_participants.at(user).authorized) {
			if (m_participants.at(target).authorized) {
				return true;
			} else {
				return m_participants.at(target).authorized_peers.count(user) != 0;
			}
		} else {
			if (m_participants.at(target).authorized) {
				return m_participants.at(user).authorized_by.count(target) != 0;
			} else {
				return false;
			}
		}
	}
	
	// returns whether you are a member of this channel
	bool am_member() const
	{
		return m_joined;
	}
	
	// returns whether you are authorized
	bool am_authorized() const
	{
		return m_authorized;
	}
	
	
	
	
	
	
	
	const PublicKey& ephemeral_public_key() const
	{
		return m_ephemeral_private_key.public_key();
	}
	
	bool empty() const
	{
		return m_participants.empty();
	}
	
	void set_interface(ChannelInterface* interface)
	{
		m_interface = interface;
	}
	
	void announce();
	void confirm_participant(const std::string& username);
	void join();
	void activate();
	void authorize(const std::string& username);
	
	void message_received(const std::string& sender, const Message& np1sec_message);
	void user_left(const std::string& username);
	
	
	protected:
	struct Participant
	{
		/*
		 * Part of the shared state machine
		 */
		std::string username;
		PublicKey long_term_public_key;
		PublicKey ephemeral_public_key;
		uint64_t signature_id;
		
		bool authorized;
		// used only for unauthorized participants
		std::set<std::string> authorized_by;
		std::set<std::string> authorized_peers;
		
		/*
		 * Local state
		 */
		// Did we authenticate this user?
		AuthenticationStatus authentication_status;
		// used only for Authenticating participants
		Hash authentication_nonce;
	};
	
	struct Event
	{
		/*
		 * This struct is really a union, but I am too lazy to implement a C++11 union.
		 */
		
		Message::Type type;
		
		ChannelStatusEvent channel_status;
		ConsistencyCheckEvent consistency_check;
	};
	
	void self_joined();
	void self_authorized();
	void try_promote_unauthorized_participant(Participant* participant);
	void remove_user(const std::string& username);
	void send_message(const Message& message);
	
	
	Message channel_status(const std::string& searcher_username, const Hash& searcher_nonce) const;
	void hash_message(const std::string& sender, const Message& message);
	void hash_payload(const std::string& sender, uint8_t type, const std::string& message);
	void authenticate_to(const std::string& username, const PublicKey& long_term_public_key, const PublicKey& ephemeral_public_key, const Hash& nonce);
	Hash authentication_token(const std::string& username, const PublicKey& long_term_public_key, const PublicKey& ephemeral_public_key, const Hash& nonce, bool for_peer);
	void send_consistency_check();
	std::vector<Event>::iterator first_user_event(const std::string& username);
	void set_channel_status_timer();
	
	
	
	protected:
	Room* m_room;
	PrivateKey m_ephemeral_private_key;
	uint64_t m_signature_id;
	ChannelInterface* m_interface;
	
	bool m_joined;
	bool m_active;
	bool m_authorized;
	std::map<std::string, Participant> m_participants;
	Hash m_channel_status_hash;
	
	std::vector<Event> m_events;
	
	Timer m_channel_status_timer;
};

} // namespace np1sec

#endif
