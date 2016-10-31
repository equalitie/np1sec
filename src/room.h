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

#include "channel.h"
#include "channelsearch.h"
#include "interface.h"
#include "message.h"
#include "timer.h"

#include <map>
#include <memory>

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
	
	const PublicKey& long_term_public_key() const
	{
		return m_long_term_private_key.public_key();
	}
	
	const PrivateKey& long_term_private_key() const
	{
		return m_long_term_private_key;
	}
	
	const PublicKey& ephemeral_public_key() const
	{
		return m_ephemeral_private_key.public_key();
	}
	
	const PrivateKey& ephemeral_private_key() const
	{
		return m_ephemeral_private_key;
	}
	
	RoomInterface* interface()
	{
		return m_interface;
	}
	
	/*
	 * Operations
	 */
	void join_room();
	void search_channels();
	void create_channel();
	void join_channel(const std::string& id_hash);
	void authorize(const std::string& username);
	
	/*
	 * Callbacks
	 */
	void message_received(const std::string& sender, const std::string& text_message);
	void user_joined(const std::string& username);
	void user_left(const std::string& username);
	//void left_room();
	
	/*
	 * Internal
	 */
	void joined_channel(std::unique_ptr<Channel> channel);
	void send_message(const Message& message);
	
	protected:
	RoomInterface* m_interface;
	
	std::string m_username;
	PrivateKey m_long_term_private_key;
	PrivateKey m_ephemeral_private_key;
	
	std::unique_ptr<Channel> m_channel;
	std::unique_ptr<Channel> m_constructing_channel;
	std::unique_ptr<ChannelSearch> m_channel_search;
};

} // namespace np1sec

#endif
