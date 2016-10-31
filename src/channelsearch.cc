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
#include "crypto.h"
#include "room.h"

namespace np1sec
{

ChannelSearch::ChannelSearch(Room* room):
	m_room(room)
{
}

void ChannelSearch::search()
{
	ChannelSearchMessage message;
	message.nonce = crypto::nonce<c_hash_length>();
	m_room->interface()->send_message(message.encode().encode());
}

void ChannelSearch::message_received(const std::string& sender, const Message& np1sec_message)
{
	if (np1sec_message.type == Message::Type::ChannelStatus) {
		ChannelStatusMessage message;
		try {
			message = ChannelStatusMessage::decode(np1sec_message);
		} catch(MessageFormatException) {
			return;
		}
		
		Channel* channel = new Channel(m_room, message);
		m_room->join_channel(channel);
	}
}

} // namespace np1sec
