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

#include "conversationlist.h"
#include "room.h"

namespace np1sec
{

ConversationList::ConversationList(Room* room):
	m_room(room)
{}

void ConversationList::disconnect()
{
	m_authenticated_invites.clear();
	m_participant_conversations.clear();
	m_user_conversations.clear();
	m_conversations.clear();
	m_invitation_start_points.clear();
	m_event_queue.clear();
}

void ConversationList::create_conversation()
{
	std::unique_ptr<Conversation> conversation(new Conversation(m_room));
	Conversation* c = conversation.get();
	
	std::map<std::string, PublicKey> users = conversation->conversation_users();
	assert(users.size() == 1);
	auto i = users.begin();
	m_user_conversations[i->first][i->second].insert(c);
	m_conversations[c] = std::move(conversation);
	
	m_participant_conversations.insert(c);
	
	ConversationInterface* interface = m_room->interface()->created_conversation(c);
	c->set_interface(interface);
}

void ConversationList::message_received(const std::string& sender, const ConversationMessage& conversation_message)
{
	assert(conversation_message.verify());
	
	RoomEvent event;
	event.sender = sender;
	event.type = RoomEvent::Type::Message;
	event.message = conversation_message;
	
	std::set<Conversation*> interested_conversations;
	if (
		   m_user_conversations.count(sender)
		&& m_user_conversations.at(sender).count(conversation_message.conversation_public_key)
	) {
		interested_conversations = m_user_conversations.at(sender).at(conversation_message.conversation_public_key);
	}
	if (conversation_message.type == Message::Type::InviteAcceptance) {
		try {
			InviteAcceptanceMessage message = InviteAcceptanceMessage::decode(conversation_message);
			if (
				   m_user_conversations.count(message.inviter_username)
				&& m_user_conversations.at(message.inviter_username).count(message.inviter_conversation_public_key)
			) {
				const std::set<Conversation*>& conversations = m_user_conversations.at(message.inviter_username).at(message.inviter_conversation_public_key);
				
				interested_conversations.insert(conversations.begin(), conversations.end());
			}
		} catch(MessageFormatException) {}
	}
	for (Conversation* conversation : interested_conversations) {
		handle_event(conversation, event);
	}
	
	bool recorded = false;
	if (conversation_message.type == Message::Type::Invite) {
		try {
			InviteMessage message = InviteMessage::decode(conversation_message);
			if (
				   message.username == m_room->username()
				&& message.long_term_public_key == m_room->public_key()
			) {
				clear_invite(sender, conversation_message.conversation_public_key);
				
				event.waiting = true;
				std::list<RoomEvent>::iterator it = m_event_queue.insert(m_event_queue.end(), std::move(event));
				m_invitation_start_points[it->sender][it->message.conversation_public_key] = it;
				
				///// TODO 60000
				it->timeout = Timer(m_room->interface(), 60000, [it, this] {
					clear_invite(it->sender, it->message.conversation_public_key);
				});
				
				recorded = true;
			}
		} catch(MessageFormatException) {}
	}
	
	if (!m_event_queue.empty() && !recorded) {
		event.waiting = false;
		m_event_queue.push_back(std::move(event));
	}
	
	if (conversation_message.type == Message::Type::ConversationStatus) {
		if (
			   m_invitation_start_points.count(sender)
			&& m_invitation_start_points.at(sender).count(conversation_message.conversation_public_key)
		) {
			try {
				ConversationStatusMessage message = ConversationStatusMessage::decode(conversation_message);
				std::unique_ptr<Conversation> conversation(new Conversation(m_room, message, sender, conversation_message));
				Conversation* c = conversation.get();
				
				std::map<std::string, PublicKey> users = conversation->conversation_users();
				for (const auto& i : users) {
					m_user_conversations[i.first][i.second].insert(c);
				}
				m_conversations[c] = std::move(conversation);
				
				std::list<RoomEvent>::iterator it = m_invitation_start_points.at(sender).at(conversation_message.conversation_public_key);
				it++;
				
				while (m_conversations.count(c) && it != m_event_queue.end()) {
					handle_event(c, *it);
					it++;
				}
			} catch(MessageFormatException) {}
			
			clear_invite(sender, conversation_message.conversation_public_key);
		}
	}
}

void ConversationList::user_left(const std::string& username)
{
	RoomEvent event;
	event.sender = username;
	event.type = RoomEvent::Type::Leave;
	event.waiting = false;
	
	std::set<Conversation*> interested_conversations;
	for (const auto& i : m_conversations) {
		interested_conversations.insert(i.first);
	}
	for (Conversation* conversation : interested_conversations) {
		handle_event(conversation, event);
	}
	
	if (!m_event_queue.empty()) {
		m_event_queue.push_back(std::move(event));
	}
}

void ConversationList::conversation_add_user(Conversation* conversation, const std::string& username, const PublicKey& conversation_public_key)
{
	assert(m_conversations.count(conversation));
	m_user_conversations[username][conversation_public_key].insert(conversation);
}

void ConversationList::conversation_remove_user(Conversation* conversation, const std::string& username, const PublicKey& conversation_public_key)
{
	assert(m_conversations.count(conversation));
	assert(m_user_conversations.count(username));
	assert(m_user_conversations.at(username).count(conversation_public_key));
	m_user_conversations[username][conversation_public_key].erase(conversation);
	if (m_user_conversations.at(username).at(conversation_public_key).empty()) {
		m_user_conversations[username].erase(conversation_public_key);
	}
	if (m_user_conversations.at(username).empty()) {
		m_user_conversations.erase(username);
	}
}

void ConversationList::conversation_set_authenticated(Conversation* conversation)
{
	assert(m_conversations.count(conversation));
	assert(!m_authenticated_invites.count(conversation));
	assert(!m_participant_conversations.count(conversation));
	m_authenticated_invites.insert(conversation);
}

void ConversationList::conversation_set_participant(Conversation* conversation)
{
	assert(m_conversations.count(conversation));
	assert(!m_participant_conversations.count(conversation));
	m_authenticated_invites.erase(conversation);
	m_participant_conversations.insert(conversation);
}

void ConversationList::handle_event(Conversation* conversation, const RoomEvent& event)
{
	assert(conversation->am_involved());
	
	if (event.type == RoomEvent::Type::Message) {
		conversation->message_received(event.sender, event.message);
	} else if (event.type == RoomEvent::Type::Leave) {
		conversation->user_left(event.sender);
	} else {
		assert(false);
	}
	
	if (!conversation->am_involved()) {
		std::map<std::string, PublicKey> users = conversation->conversation_users();
		for (const auto& i : users) {
			assert(m_user_conversations.count(i.first));
			assert(m_user_conversations.at(i.first).count(i.second));
			assert(m_user_conversations.at(i.first).at(i.second).count(conversation));
			m_user_conversations[i.first][i.second].erase(conversation);
			if (m_user_conversations.at(i.first).at(i.second).empty()) {
				m_user_conversations[i.first].erase(i.second);
			}
			if (m_user_conversations.at(i.first).empty()) {
				m_user_conversations.erase(i.first);
			}
		}
		m_authenticated_invites.erase(conversation);
		m_participant_conversations.erase(conversation);
		m_conversations.erase(conversation);
	}
}

void ConversationList::clean_event_queue()
{
	while (!m_event_queue.empty() && !m_event_queue.front().waiting) {
		m_event_queue.pop_front();
	}
}

void ConversationList::clear_invite(const std::string& username, const PublicKey& conversation_public_key)
{
	if (!m_invitation_start_points.count(username)) {
		return;
	}
	if (!m_invitation_start_points.at(username).count(conversation_public_key)) {
		return;
	}
	std::list<RoomEvent>::iterator it = m_invitation_start_points.at(username).at(conversation_public_key);
	m_invitation_start_points[username].erase(conversation_public_key);
	if (m_invitation_start_points.at(username).empty()) {
		m_invitation_start_points.erase(username);
	}
	it->timeout.stop();
	it->waiting = false;
	clean_event_queue();
}

} // namespace np1sec
