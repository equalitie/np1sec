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

#include <map>
#include <string>
#include <vector>

namespace np1sec
{

class Room;

class Channel
{
	public:
	void dump(const std::string& message);
	
	public:
	enum class AuthenticationStatus { Authenticated, Unauthenticated, AuthenticationFailed };
	
	public:
	Channel(Room* room);
	Channel(Room* room, const ChannelStatusMessage& channel_status, const Message& encoded_message);
	Channel(Room* room, const ChannelAnnouncementMessage& channel_status, const std::string& sender);
	
	bool empty() const;
	bool joined() const;
	
	void announce();
	void confirm_participant(const std::string& username);
	void join();
	void activate();
	void authorize(const std::string& username);
	
	void message_received(const std::string& sender, const Message& np1sec_message);
	void user_joined(const std::string& username);
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
		
		bool authorized;
		// used only for unauthorized participants
		std::set<std::string> authorized_by;
		std::set<std::string> authorized_peers;
		
		/*
		 * Local state
		 */
		// Did we confirm this user is part of this channel?
		bool confirmed;
		// Did we authenticate this user?
		AuthenticationStatus authentication_status;
	};
	
	struct Event
	{
		Message::Type type;
		std::set<std::string> remaining_users;
		
		ChannelStatusEventBody channel_status;
	};
	
	void self_joined();
	void self_authorized();
	void try_promote_unauthorized_participant(Participant* participant);
	void remove_user(const std::string& username);
	void send_message(const Message& message, std::string debug_description = "");
	
	
	void authenticate_to(const std::string& username, const PublicKey& long_term_public_key, const PublicKey& ephemeral_public_key);
	Hash authentication_token(const std::string& username, const PublicKey& long_term_public_key, const PublicKey& ephemeral_public_key, bool for_peer);
	std::vector<Event>::iterator first_user_event(const std::string& username);
	
	
	
	protected:
	Room* m_room;
	bool m_joined;
	bool m_active;
	bool m_authorized;
	std::map<std::string, Participant> m_participants;
	
	std::vector<Event> m_events;
};

} // namespace np1sec

#endif
