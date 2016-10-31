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

#ifndef SRC_CHANNELSEARCH_H_
#define SRC_CHANNELSEARCH_H_

#include "channel.h"
#include "crypto.h"
#include "message.h"

#include <map>
#include <memory>
#include <vector>

namespace np1sec
{

class Room;

class ChannelSearch
{
	public:
	ChannelSearch(Room* room);
	
	void search();
	void join_channel(const std::string& id_hash);
	
	void message_received(const std::string& sender, const Message& np1sec_message);
	void user_joined(const std::string& username);
	void user_left(const std::string& username);
	
	protected:
	struct RoomEvent
	{
		enum class Type { Message, Join, Leave };
		std::string sender;
		Type type;
		Message message;
	};
	void process_event(const RoomEvent& event);
	void send_event(Channel* channel, const RoomEvent& event);
	std::unique_ptr<Channel> create_channel(const ChannelStatusMessage& message, const Message& encoded_message);
	
	protected:
	Room* m_room;
	
	bool m_received_search_message;
	Hash m_search_nonce;
	
	std::string m_joining_channel_id;
	
	std::vector<RoomEvent> m_event_log;
	
	/*
	 * Stores each channel, identified by the channel status message payload
	 */
	std::map<std::string, std::unique_ptr<Channel>> m_channels;
};

} // namespace np1sec

#endif
