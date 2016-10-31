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

#ifndef SRC_CHANNELCREATION_H_
#define SRC_CHANNELCREATION_H_

#include "channel.h"

#include <memory>

namespace np1sec
{

class Room;

class ChannelCreation
{
	public:
	ChannelCreation(Room* room);
	
	void create();
	
	void message_received(const std::string& sender, const Message& np1sec_message);
	
	protected:
	Room* m_room;
	
	std::unique_ptr<Channel> m_channel;
};

} // namespace np1sec



#endif
