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

#include "interface.h"
#include "message.h"

#include <map>

namespace np1sec
{

class Room
{
	public:
	Room(RoomInterface* interface, const std::string& username, const PrivateKey& private_key);
	
	/*
	 * Accessors
	 */
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
	
	Identity identity() const
	{
		Identity identity;
		identity.username = username();
		identity.public_key = public_key();
		return identity;
	}
	
	bool connected() const
	{
		return !m_users.empty();
	}
	
	/*
	 * Operations
	 */
	void join();
	
	/*
	 * Callbacks
	 */
	void message_received(const std::string& sender, const std::string& text_message);
	void user_left(const std::string& username);
	//void left_room();
	
	protected:
	void disconnect();
	void register_user(const std::string& username, const PublicKey& long_term_public_key, const PublicKey& ephemeral_public_key);
	Hash authentication_token(const std::string& username, const PublicKey& long_term_public_key, const PublicKey& ephemeral_public_key, bool for_peer);
	void remove_user(const std::string& username);
	void send_message(const Message& message);
	
	protected:
	struct User
	{
		std::string username;
		PublicKey long_term_public_key;
		PublicKey ephemeral_public_key;
		bool authenticated;
		
		Identity identity() const
		{
			Identity identity;
			identity.username = username;
			identity.public_key = long_term_public_key;
			return identity;
		}
	};
	
	RoomInterface* m_interface;
	
	std::string m_username;
	PrivateKey m_long_term_private_key;
	PrivateKey m_ephemeral_private_key;
	
	std::map<std::string, User> m_users;
};

} // namespace np1sec

#endif
