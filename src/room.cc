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

#include "channel.h"
#include "channelsearch.h"
#include "room.h"

#include <cassert>

namespace np1sec
{

Room::Room(RoomInterface* interface, const std::string& username, const PrivateKey& private_key):
	m_interface(interface),
	m_username(username),
	m_long_term_private_key(private_key)
{
	assert(m_interface);
}

void Room::join_room()
{
	// NOTE no rejoin support
	/*
	 * TODO rejoin support?
	 *
	 * We need rejoin in case of timeouts, and after receiving the wrong messages on our end.
	 * A rejoin operation may be tricky in either case. Hm...
	 */
	assert(!m_channel);
	assert(!m_channel_creation);
	assert(!m_channel_search);
}

void Room::search_channels()
{
	m_channel_search = std::unique_ptr<ChannelSearch>(new ChannelSearch(this));
	m_channel_search->search();
}

void Room::create_channel()
{
	m_channel_creation = std::unique_ptr<ChannelCreation>(new ChannelCreation(this));
	m_channel_creation->create();
}

void Room::join_channel(Channel* channel)
{
	assert(m_channel_search);
	
	m_channel_search->join_channel(channel);
}

void Room::authorize(const std::string& username)
{
	if (m_channel) {
		m_channel->authorize(username);
	}
}

void Room::message_received(const std::string& sender, const std::string& text_message)
{
	if (sender == username()) {
		if (m_message_queue.empty() || m_message_queue.front() != text_message) {
			disconnect();
			return;
		}
		m_message_queue.pop_front();
	}
	
	Message np1sec_message;
	try {
		np1sec_message = Message::decode(text_message);
	} catch(MessageFormatException) {
		return;
	}
	
	/*
	 * The order is important here.
	 * The lower two cases may set a new m_channel, which has then already
	 * received the np1sec_message; and the confirmation of a constructed
	 * channel should cancel the channel search before the channel search
	 * hears about it.
	 */
	if (m_channel) {
		m_channel->message_received(sender, np1sec_message);
	}
	if (m_channel_creation) {
		m_channel_creation->message_received(sender, np1sec_message);
	}
	if (m_channel_search) {
		m_channel_search->message_received(sender, np1sec_message);
	}
}

void Room::user_joined(const std::string& username)
{
	if (m_channel) {
		m_channel->user_joined(username);
	}
	if (m_channel_search) {
		m_channel_search->user_joined(username);
	}
}

void Room::user_left(const std::string& username)
{
	if (m_channel) {
		m_channel->user_left(username);
	}
	if (m_channel_search) {
		m_channel_search->user_left(username);
	}
}

void Room::disconnect()
{
	// TODO fill in details here when we have a proper API.
	m_channel.reset();
	m_channel_creation.reset();
	m_channel_search.reset();
	m_message_queue.clear();
	
	m_interface->disconnected();
}

void Room::joined_channel(std::unique_ptr<Channel> channel)
{
	assert(channel != m_channel);
	
	m_channel = std::move(channel);
	m_channel->activate();
	
	m_channel_creation.reset();
	m_channel_search.reset();
	
	m_interface->joined_channel(m_channel.get());
}

void Room::send_message(const Message& message)
{
	send_message(message.encode());
}

void Room::send_message(const std::string& message)
{
	m_message_queue.push_back(message);
	m_interface->send_message(message);
}



} // namespace np1sec
