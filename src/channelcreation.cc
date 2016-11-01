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

#include "channelcreation.h"
#include "room.h"

namespace np1sec
{

ChannelCreation::ChannelCreation(Room* room):
	m_room(room)
{
}

void ChannelCreation::create()
{
	m_channel = std::unique_ptr<Channel>(new Channel(m_room));
	m_channel->announce();
}

void ChannelCreation::message_received(const std::string& sender, const Message& np1sec_message)
{
	if (!m_channel) {
		return;
	}
	
	if (np1sec_message.type == Message::Type::ChannelAnnouncement) {
		ChannelAnnouncementMessage message;
		try {
			message = ChannelAnnouncementMessage::decode(np1sec_message);
		} catch(MessageFormatException) {
			return;
		}
		
		if (
			   sender == m_room->username()
			&& message.long_term_public_key == m_room->long_term_public_key()
			&& message.ephemeral_public_key == m_channel->ephemeral_public_key()
		) {
			m_room->joined_channel(std::move(m_channel));
		}
	}
}

} // namespace np1sec
