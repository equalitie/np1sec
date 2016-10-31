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

namespace np1sec
{

class Room;

class Channel
{
	public:
	void dump(const std::string& message);
	
	public:
	enum class AuthenticationStatus { Authenticated, Unauthenticated, AuthenticationFailed };
	
	protected:
	struct Participant
	{
		std::string username;
		PublicKey long_term_public_key;
		PublicKey ephemeral_public_key;
		
		AuthenticationStatus authentication_status;
		bool authorized;
		// used only for unauthorized participants
		std::set<std::string> authorized_by;
		std::set<std::string> authorized_peers;
	};
	
	
	
	public:
	Channel(Room *room);
	Channel(Room *room, const ChannelStatusMessage& channel_status);
	
	void join();
	void authorize(const std::string& username);
	
	void message_received(const std::string& sender, const Message& np1sec_message);
	void user_left(const std::string& username);
	
	
	protected:
	void self_joined();
	void self_authorized();
	void try_promote_unauthorized_participant(Participant* participant);
	void remove_user(const std::string& username);
	void send_message(const Message& message, std::string debug_description = "");
	
	
	void authenticate_to(const std::string& username, const PublicKey& long_term_public_key, const PublicKey& ephemeral_public_key);
	Hash authentication_token(const std::string& username, const PublicKey& long_term_public_key, const PublicKey& ephemeral_public_key, bool for_peer);
	
	
	
	
	protected:
	Room* m_room;
	bool m_active;
	bool m_authorized;
	std::map<std::string, Participant> m_participants;
};

} // namespace np1sec

#endif
