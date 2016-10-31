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

#include "channelsearch.h"
#include "room.h"

#include <cassert>

#include <iostream>

namespace np1sec
{

ChannelSearch::ChannelSearch(Room* room):
	m_room(room),
	m_received_search_message(false)
{
}

void ChannelSearch::search()
{
	m_received_search_message = false;
	m_joining_channel_id.clear();
	m_event_log.clear();
	m_channels.clear();
	
	m_search_nonce = crypto::nonce_hash();
	
	ChannelSearchMessage message;
	message.nonce = m_search_nonce;
	m_room->interface()->send_message(message.encode().encode());
}

void ChannelSearch::join_channel(const std::string& id_hash)
{
	assert(m_joining_channel_id.empty());
	
	std::string identifier;
	for (const auto& i : m_channels) {
		if (crypto::hash(i.first).dump_hex() == id_hash) {
			identifier = i.first;
			break;
		}
	}
	
	if (identifier.empty()) {
		return;
	}
	
	m_joining_channel_id = identifier;
	if (m_channels[identifier]) {
		m_channels[identifier]->join();
	}
}

void ChannelSearch::message_received(const std::string& sender, const Message& np1sec_message)
{
	RoomEvent event;
	event.sender = sender;
	event.type = RoomEvent::Type::Message;
	event.message = np1sec_message;
	process_event(event);
	
	if (np1sec_message.type == Message::Type::ChannelSearch) {
		ChannelSearchMessage message;
		try {
			message = ChannelSearchMessage::decode(np1sec_message);
		} catch(MessageFormatException) {
			return;
		}
		
		if (sender == m_room->username() && message.nonce == m_search_nonce) {
			m_received_search_message = true;
		}
	} else if (np1sec_message.type == Message::Type::ChannelStatus) {
		if (!m_received_search_message) {
			return;
		}
		
		const std::string& channel_id = np1sec_message.payload;
		
		ChannelStatusMessage message;
		try {
			message = ChannelStatusMessage::decode(np1sec_message);
		} catch(MessageFormatException) {
			return;
		}
		
		if (message.searcher_username != m_room->username() || message.searcher_nonce != m_search_nonce) {
			return;
		}
		
		/*
		 * Ignore channel status messages that do not contain the sender.
		 */
		bool found = false;
		for (const auto& participant : message.participants) {
			if (participant.username == sender) {
				found = true;
				break;
			}
		}
		for (const auto& participant : message.unauthorized_participants) {
			if (participant.username == sender) {
				found = true;
				break;
			}
		}
		if (!found) {
			return;
		}
		
		if (!m_channels.count(channel_id)) {
			Hash id_hash = crypto::hash(channel_id);
			std::cout << "*** Found channel: " << id_hash.dump_hex() << "\n";
			
			std::unique_ptr<Channel> channel = create_channel(message, np1sec_message);
			m_channels[channel_id] = std::move(channel);
		}
		
		if (m_channels[channel_id]) {
			m_channels[channel_id]->confirm_participant(sender);
		}
	} else if (np1sec_message.type == Message::Type::ChannelAnnouncement) {
		if (!m_received_search_message) {
			return;
		}
		
		const std::string& channel_id = np1sec_message.payload + sender;
		
		ChannelAnnouncementMessage message;
		try {
			message = ChannelAnnouncementMessage::decode(np1sec_message);
		} catch(MessageFormatException) {
			return;
		}
		
		if (!m_channels.count(channel_id)) {
			Hash id_hash = crypto::hash(channel_id);
			std::cout << "*** Found channel: " << id_hash.dump_hex() << "\n";
			
			m_channels[channel_id] = std::unique_ptr<Channel>(new Channel(m_room, message, sender));
		}
		
		m_channels[channel_id]->confirm_participant(sender);
	}
	
	if (!m_joining_channel_id.empty() && m_channels[m_joining_channel_id]->joined()) {
		std::unique_ptr<Channel> joining_channel = std::move(m_channels[m_joining_channel_id]);
		m_channels.clear();
		m_joining_channel_id.clear();
		m_room->joined_channel(std::move(joining_channel));
	}
}

void ChannelSearch::user_joined(const std::string& sender)
{
	RoomEvent event;
	event.sender = sender;
	event.type = RoomEvent::Type::Join;
	process_event(event);
}

void ChannelSearch::user_left(const std::string& sender)
{
	RoomEvent event;
	event.sender = sender;
	event.type = RoomEvent::Type::Leave;
	process_event(event);
}

void ChannelSearch::process_event(const RoomEvent& event)
{
	if (!m_received_search_message) {
		return;
	}
	
	m_event_log.push_back(event);
	
	for (auto& i : m_channels) {
		if (i.second) {
			send_event(i.second.get(), event);
			if (i.second->empty()) {
				i.second.reset();
			}
		}
	}
}

void ChannelSearch::send_event(Channel* channel, const RoomEvent& event)
{
	if (event.type == RoomEvent::Type::Message) {
		channel->message_received(event.sender, event.message);
	} else if (event.type == RoomEvent::Type::Join) {
		channel->user_joined(event.sender);
	} else if (event.type == RoomEvent::Type::Leave) {
		channel->user_left(event.sender);
	} else {
		assert(false);
	}
}

std::unique_ptr<Channel> ChannelSearch::create_channel(const ChannelStatusMessage& message, const Message& encoded_message)
{
	std::unique_ptr<Channel> channel;
	try {
		channel = std::unique_ptr<Channel>(new Channel(m_room, message, encoded_message));
	} catch(MessageFormatException) {
		return std::unique_ptr<Channel>();
	}
	
	for (const auto& event : m_event_log) {
		send_event(channel.get(), event);
		if (channel->empty()) {
			return std::unique_ptr<Channel>();
		}
	}
	
	return channel;
}

} // namespace np1sec
