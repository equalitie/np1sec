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

#include <iostream>

namespace np1sec
{

Room::Room(RoomInterface* interface, const std::string& username, const PrivateKey& private_key):
	m_interface(interface),
	m_username(username),
	m_long_term_private_key(private_key),
	m_channel(nullptr),
	m_channel_search(nullptr)
{
	assert(m_interface);
}

void Room::join_room()
{
	// NOTE no rejoin support
	assert(!m_channel);
	assert(!m_channel_search);
	
	m_ephemeral_private_key = PrivateKey::generate();
}

void Room::search_channels()
{
	assert(!m_channel);
	assert(!m_channel_search);
	
	m_channel_search = new ChannelSearch(this);
	m_channel_search->search();
}

void Room::create_channel()
{
	assert(!m_channel);
	assert(!m_channel_search);
	
	m_channel = new Channel(this);
}

void Room::join_channel(Channel* channel)
{
	m_channel = channel;
	delete m_channel_search;
	m_channel_search = nullptr;
	
	m_channel->join();
}

void Room::authorize(const std::string& username)
{
	if (m_channel) {
		m_channel->authorize(username);
	}
}

void Room::message_received(const std::string& sender, const std::string& text_message)
{
	Message np1sec_message;
	try {
		np1sec_message = Message::decode(text_message);
	} catch(MessageFormatException) {
		return;
	}
	
	if (m_channel) {
		m_channel->message_received(sender, np1sec_message);
	}
	if (m_channel_search) {
		m_channel_search->message_received(sender, np1sec_message);
	}
}

void Room::user_left(const std::string& username)
{
	if (m_channel) {
		m_channel->user_left(username);
	}
}

void Room::send_message(const Message& message)
{
	m_interface->send_message(message.encode());
}



} // namespace np1sec
