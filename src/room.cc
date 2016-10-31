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
	m_long_term_private_key(private_key)
{
	assert(m_interface);
}

void Room::join_room()
{
	// NOTE no rejoin support
	assert(!m_channel);
	assert(!m_channel_search);
	assert(!m_constructing_channel);
	
	m_ephemeral_private_key = PrivateKey::generate();
}

void Room::search_channels()
{
	m_channel_search = std::unique_ptr<ChannelSearch>(new ChannelSearch(this));
	m_channel_search->search();
}

void Room::create_channel()
{
	m_constructing_channel = std::unique_ptr<Channel>(new Channel(this));
	m_constructing_channel->announce();
}

void Room::join_channel(const std::string& id_hash)
{
	assert(m_channel_search);
	
	m_channel_search->join_channel(id_hash);
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
	if (m_constructing_channel) {
		m_constructing_channel->message_received(sender, np1sec_message);
		
		if (m_constructing_channel->joined()) {
			joined_channel(std::move(m_constructing_channel));
		}
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
	if (m_constructing_channel) {
		m_constructing_channel->user_joined(username);
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
	if (m_constructing_channel) {
		m_constructing_channel->user_left(username);
	}
	if (m_channel_search) {
		m_channel_search->user_left(username);
	}
}

void Room::joined_channel(std::unique_ptr<Channel> channel)
{
	assert(channel != m_channel);
	
	m_channel = std::move(channel);
	m_channel->activate();
	
	m_channel_search.reset();
	m_constructing_channel.reset();
}

void Room::send_message(const Message& message)
{
	m_interface->send_message(message.encode());
}



} // namespace np1sec
