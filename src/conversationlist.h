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

#ifndef SRC_CONVERSATIONLIST_H_
#define SRC_CONVERSATIONLIST_H_

#include "conversation.h"
#include "message.h"
#include "timer.h"

#include <list>
#include <map>
#include <memory>
#include <set>

namespace np1sec
{

class Room;

class ConversationList
{
	public:
	ConversationList(Room* room);
	
	const std::set<Conversation*>& conversations() const
	{
		return m_participant_conversations;
	}
	
	const std::set<Conversation*>& invites() const
	{
		return m_authenticated_invites;
	}
	
	void disconnect();
	void create_conversation();
	
	void message_received(const std::string& sender, const ConversationMessage& conversation_message);
	void user_left(const std::string& username);
	
	void conversation_add_user(Conversation* conversation, const std::string& username, const PublicKey& conversation_public_key);
	void conversation_remove_user(Conversation* conversation, const std::string& username, const PublicKey& conversation_public_key);
	void conversation_set_authenticated(Conversation* conversation);
	void conversation_set_participant(Conversation* conversation);
	
	protected:
	struct RoomEvent
	{
		enum class Type { Message, Leave };
		std::string sender;
		Type type;
		ConversationMessage message;
		
		bool waiting;
		Timer timeout;
	};
	
	void handle_event(Conversation* conversation, const RoomEvent& event);
	void clean_event_queue();
	void clear_invite(const std::string& username, const PublicKey& conversation_public_key);
	
	
	protected:
	Room* m_room;
	
	std::map<Conversation*, std::unique_ptr<Conversation>> m_conversations;
	std::map<std::string, std::map<PublicKey, std::set<Conversation*>>> m_user_conversations;
	
	std::list<RoomEvent> m_event_queue;
	std::map<std::string, std::map<PublicKey, std::list<RoomEvent>::iterator>> m_invitation_start_points;
	
	std::set<Conversation*> m_authenticated_invites;
	std::set<Conversation*> m_participant_conversations;
};

} // namespace np1sec

#endif
