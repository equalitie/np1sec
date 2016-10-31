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
#include "room.h"

#include <iostream>

namespace np1sec
{

void Channel::dump(const std::string& message)
{
	std::cout << "** " << message << ":\n";
	std::cout << "Channel status:\n";
	std::cout << "  Joined: " << (m_joined ? "yes" : "no") << "\n";
	std::cout << "  Active: " << (m_active ? "yes" : "no") << "\n";
	std::cout << "  Authorized: " << (m_authorized ? "yes" : "no") << "\n";
	std::cout << "  Hash: " << m_channel_status_hash.dump_hex() << "\n";
	std::cout << "Participants:\n";
	for (const auto& p : m_participants) {
		std::string padding(16 - p.second.username.size(), ' ');
		std::cout << "  " << p.second.username << padding << " " << p.second.long_term_public_key.dump_hex() << "    " << p.second.ephemeral_public_key.dump_hex() << "\n";
		std::cout << "    Channel status confirmed: " << (p.second.confirmed ? "yes" : "no") << "\n";
		std::cout << "    Authentication status: " << (
			p.second.authentication_status == AuthenticationStatus::Authenticated ? "authenticated" :
			p.second.authentication_status == AuthenticationStatus::Unauthenticated ? "unauthenticated" :
			"failed"
		) << "\n";
		std::cout << "    Authorized: " << (p.second.authorized ? "yes" : "no") << "\n";
		if (!p.second.authorized) {
			for (const auto& pp : m_participants) {
				if (pp.second.authorized) {
					std::cout << "      " << pp.second.username << ":\n";
					std::cout << "        " << p.second.username << " authorized by " << pp.second.username << ": " << (p.second.authorized_by.count(pp.second.username) ? "yes" : "no") << "\n";
					std::cout << "        " << pp.second.username << " authorized by " << p.second.username << ": " << (p.second.authorized_peers.count(pp.second.username) ? "yes" : "no") << "\n";
				}
			}
		}
	}
}

Channel::Channel(Room* room):
	m_room(room),
	m_joined(true),
	m_active(false),
	m_authorized(true),
	m_channel_status_hash(crypto::nonce_hash())
{
	Participant self;
	self.username = m_room->username();
	self.long_term_public_key = m_room->long_term_public_key();
	self.ephemeral_public_key = m_room->ephemeral_public_key();
	self.authorized = true;
	self.confirmed = true;
	self.authentication_status = AuthenticationStatus::Authenticated;
	m_participants[self.username] = self;
	
	dump("Created channel");
}

Channel::Channel(Room* room, const ChannelStatusMessage& channel_status, const Message& encoded_message):
	m_room(room),
	m_joined(false),
	m_active(false),
	m_authorized(false)
{
	/*
	 * The event queue in the channel_status message does not contain the
	 * event describing this status message, so we need to construct it.
	 */
	Event channel_status_event;
	channel_status_event.type = Message::Type::ChannelStatus;
	channel_status_event.channel_status.searcher_username = channel_status.searcher_username;
	channel_status_event.channel_status.searcher_nonce = channel_status.searcher_nonce;
	channel_status_event.channel_status.status_message_hash = crypto::hash(encoded_message.payload);
	
	for (const ChannelStatusMessage::Participant& p : channel_status.participants) {
		Participant participant;
		participant.username = p.username;
		participant.long_term_public_key = p.long_term_public_key;
		participant.ephemeral_public_key = p.ephemeral_public_key;
		participant.authorized = true;
		participant.confirmed = false;
		participant.authentication_status = AuthenticationStatus::Unauthenticated;
		
		if (m_participants.count(participant.username)) {
			throw MessageFormatException();
		}
		
		m_participants[participant.username] = std::move(participant);
		
		channel_status_event.channel_status.remaining_users.insert(p.username);
	}
	
	for (const ChannelStatusMessage::UnauthorizedParticipant& p : channel_status.unauthorized_participants) {
		Participant participant;
		participant.username = p.username;
		participant.long_term_public_key = p.long_term_public_key;
		participant.ephemeral_public_key = p.ephemeral_public_key;
		participant.authorized = false;
		participant.confirmed = false;
		participant.authentication_status = AuthenticationStatus::Unauthenticated;
		
		for (const std::string& peer : p.authorized_by) {
			if (m_participants.count(peer)) {
				participant.authorized_by.insert(peer);
			}
		}
		for (const std::string& peer : p.authorized_peers) {
			if (m_participants.count(peer)) {
				participant.authorized_peers.insert(peer);
			}
		}
		
		if (m_participants.count(participant.username)) {
			throw MessageFormatException();
		}
		
		m_participants[participant.username] = std::move(participant);
		
		channel_status_event.channel_status.remaining_users.insert(p.username);
	}
	
	m_channel_status_hash = channel_status.channel_status_hash;
	
	for (const ChannelEvent& channel_event : channel_status.events) {
		Event event;
		event.type = channel_event.type;
		if (channel_event.type == Message::Type::ChannelStatus) {
			event.channel_status = ChannelStatusEvent::decode(channel_event, channel_status);
		} else if (channel_event.type == Message::Type::ConsistencyCheck) {
			event.consistency_check = ConsistencyCheckEvent::decode(channel_event, channel_status);
		} else {
			throw MessageFormatException();
		}
		m_events.push_back(std::move(event));
	}
	
	m_events.push_back(std::move(channel_status_event));
	
	dump("Tracking channel");
}

Channel::Channel(Room* room, const ChannelAnnouncementMessage& channel_status, const std::string& sender):
	m_room(room),
	m_joined(false),
	m_active(false),
	m_authorized(false)
{
	m_channel_status_hash = channel_status.channel_status_hash;
	
	Participant participant;
	participant.username = sender;
	participant.long_term_public_key = channel_status.long_term_public_key;
	participant.ephemeral_public_key = channel_status.ephemeral_public_key;
	participant.authorized = true;
	participant.confirmed = false;
	participant.authentication_status = AuthenticationStatus::Unauthenticated;
	m_participants[participant.username] = std::move(participant);
	
	dump("Tracking created channel");
}

bool Channel::empty() const
{
	return m_participants.empty();
}

bool Channel::joined() const
{
	return m_joined;
}

void Channel::announce()
{
	ChannelAnnouncementMessage message;
	message.long_term_public_key = m_room->long_term_public_key();
	message.ephemeral_public_key = m_room->ephemeral_public_key();
	message.channel_status_hash = m_channel_status_hash;
	send_message(message.encode(), "announcing channel");
	
	dump("Announcing channel");
}

void Channel::confirm_participant(const std::string& username)
{
	if (!m_participants.count(username)) {
		return;
	}
	
	Participant& participant = m_participants[username];
	if (!participant.confirmed) {
		participant.confirmed = true;
		
		AuthenticationRequestMessage request;
		request.sender_long_term_public_key = m_room->long_term_public_key();
		request.sender_ephemeral_public_key = m_room->ephemeral_public_key();
		request.peer_username = participant.username;
		request.peer_long_term_public_key = participant.long_term_public_key;
		request.peer_ephemeral_public_key = participant.ephemeral_public_key;
		send_message(request.encode(), "authentication request for user " + username);
		
		dump("Confirming user " + username);
	}
}

void Channel::join()
{
	JoinRequestMessage message;
	message.long_term_public_key = m_room->long_term_public_key();
	message.ephemeral_public_key = m_room->ephemeral_public_key();
	
	for (const auto& i : m_participants) {
		message.peer_usernames.push_back(i.first);
	}
	
	send_message(message.encode(), "join request");
	
	dump("Joining channel");
}

void Channel::activate()
{
	m_active = true;
	
	dump("Activating channel");
	
	set_channel_status_timer();
}

void Channel::authorize(const std::string& username)
{
	if (!m_participants.count(username)) {
		return;
	}
	
	if (username == m_room->username()) {
		return;
	}
	
	Participant& participant = m_participants[username];
	Participant& self = m_participants[m_room->username()];
	
	if (self.authorized) {
		if (participant.authorized) {
			return;
		}
		
		if (participant.authorized_by.count(m_room->username())) {
			return;
		}
	} else {
		if (!participant.authorized) {
			return;
		}
		
		if (self.authorized_peers.count(username)) {
			return;
		}
	}
	
	AuthorizationMessage message;
	message.username = participant.username;
	send_message(message.encode(), "authorization for " + username);
}



void Channel::message_received(const std::string& sender, const Message& np1sec_message)
{
	hash_message(sender, np1sec_message);
	
	if (np1sec_message.type == Message::Type::ChannelSearch) {
		ChannelSearchMessage message;
		try {
			message = ChannelSearchMessage::decode(np1sec_message);
		} catch(MessageFormatException) {
			return;
		}
		
		Event consistency_check_event;
		consistency_check_event.type = Message::Type::ConsistencyCheck;
		consistency_check_event.consistency_check.channel_status_hash = m_channel_status_hash;
		for (const auto& i : m_participants) {
			consistency_check_event.consistency_check.remaining_users.insert(i.second.username);
		}
		m_events.push_back(std::move(consistency_check_event));
		
		if (m_active) {
			UnsignedConsistencyCheckMessage consistency_check_message;
			consistency_check_message.channel_status_hash = m_channel_status_hash;
			send_message(ConsistencyCheckMessage::sign(consistency_check_message, m_room->ephemeral_private_key()), "consistency check");
		}
		
		Message reply = channel_status(sender, message.nonce);
		
		Event reply_event;
		reply_event.type = Message::Type::ChannelStatus;
		reply_event.channel_status.searcher_username = sender;
		reply_event.channel_status.searcher_nonce = message.nonce;
		reply_event.channel_status.status_message_hash = crypto::hash(reply.payload);
		for (const auto& i : m_participants) {
			reply_event.channel_status.remaining_users.insert(i.second.username);
		}
		m_events.push_back(std::move(reply_event));
		
		if (m_active) {
			send_message(reply, "channel status for user " + sender);
			
			dump("Broadcasting channel for user " + sender);
		}
	} else if (np1sec_message.type == Message::Type::ChannelStatus) {
		ChannelStatusMessage message;
		try {
			message = ChannelStatusMessage::decode(np1sec_message);
		} catch(MessageFormatException) {
			return;
		}
		
		auto first_event = first_user_event(sender);
		if (!(
			   first_event != m_events.end()
			&& first_event->type == Message::Type::ChannelStatus
			&& first_event->channel_status.searcher_username == message.searcher_username
			&& first_event->channel_status.searcher_nonce == message.searcher_nonce
			&& first_event->channel_status.status_message_hash == crypto::hash(np1sec_message.payload)
		)) {
			remove_user(sender);
			return;
		}
		
		first_event->channel_status.remaining_users.erase(sender);
		if (first_event->channel_status.remaining_users.empty()) {
			m_events.erase(first_event);
		}
	} else if (np1sec_message.type == Message::Type::ChannelAnnouncement) {
		ChannelAnnouncementMessage message;
		try {
			message = ChannelAnnouncementMessage::decode(np1sec_message);
		} catch(MessageFormatException) {
			return;
		}
		
		if (m_participants.count(sender)) {
			remove_user(sender);
		}
	} else if (np1sec_message.type == Message::Type::JoinRequest) {
		JoinRequestMessage message;
		try {
			message = JoinRequestMessage::decode(np1sec_message);
		} catch(MessageFormatException) {
			return;
		}
		
		hash_message(sender, np1sec_message);
		
		remove_user(sender);
		
		bool ours = false;
		for (const std::string& username : message.peer_usernames) {
			if (m_participants.count(username)) {
				ours = true;
				break;
			}
		}
		if (!ours) {
			return;
		}
		
		Participant participant;
		participant.username = sender;
		participant.long_term_public_key = message.long_term_public_key;
		participant.ephemeral_public_key = message.ephemeral_public_key;
		participant.authorized = false;
		participant.confirmed = true;
		participant.authentication_status = AuthenticationStatus::Unauthenticated;
		m_participants[sender] = std::move(participant);
		
		if (sender == m_room->username()) {
			m_participants[sender].authentication_status = AuthenticationStatus::Authenticated;
			self_joined();
		} else if (!m_active) {
			AuthenticationRequestMessage request;
			request.sender_long_term_public_key = m_room->long_term_public_key();
			request.sender_ephemeral_public_key = m_room->ephemeral_public_key();
			request.peer_username = sender;
			request.peer_long_term_public_key = message.long_term_public_key;
			request.peer_ephemeral_public_key = message.ephemeral_public_key;
			send_message(request.encode(), "authentication request for user " + sender);
		}
		
		dump("Adding user " + sender);
	} else if (np1sec_message.type == Message::Type::AuthenticationRequest) {
		AuthenticationRequestMessage message;
		try {
			message = AuthenticationRequestMessage::decode(np1sec_message);
		} catch(MessageFormatException) {
			return;
		}
		
		if (!m_active) {
			return;
		}
		
		if (
			   message.peer_username == m_room->username()
			&& message.peer_long_term_public_key == m_room->long_term_public_key()
			&& message.peer_ephemeral_public_key == m_room->ephemeral_public_key()
		) {
			authenticate_to(sender, message.sender_long_term_public_key, message.sender_ephemeral_public_key);
		}
	} else if (np1sec_message.type == Message::Type::Authentication) {
		AuthenticationMessage message;
		try {
			message = AuthenticationMessage::decode(np1sec_message);
		} catch(MessageFormatException) {
			return;
		}
		
		if (
			   message.peer_username == m_room->username()
			&& message.peer_long_term_public_key == m_room->long_term_public_key()
			&& message.peer_ephemeral_public_key == m_room->ephemeral_public_key()
		) {
			if (!m_participants.count(sender)) {
				return;
			}
			
			Participant& participant = m_participants[sender];
			if (
				   participant.authentication_status == AuthenticationStatus::Unauthenticated
				&& message.sender_long_term_public_key == participant.long_term_public_key
				&& message.sender_ephemeral_public_key == participant.ephemeral_public_key
			) {
				Hash correct_token = authentication_token(sender, participant.long_term_public_key, participant.ephemeral_public_key, true);
				if (message.authentication_confirmation == correct_token) {
					participant.authentication_status = AuthenticationStatus::Authenticated;
					
					dump("Authenticating user " + sender);
				} else {
					participant.authentication_status = AuthenticationStatus::AuthenticationFailed;
					
					dump("Authentication failed for user " + sender);
				}
			}
		}
	} else if (np1sec_message.type == Message::Type::Authorization) {
		AuthorizationMessage message;
		try {
			message = AuthorizationMessage::decode(np1sec_message);
		} catch(MessageFormatException) {
			return;
		}
		
		if (!(m_participants.count(sender) && m_participants.count(message.username))) {
			return;
		}
		
		Participant* authorized;
		Participant* unauthorized;
		if (m_participants[sender].authorized) {
			if (m_participants[message.username].authorized) {
				return;
			}
			authorized = &m_participants[sender];
			unauthorized = &m_participants[message.username];
		} else {
			if (!m_participants[message.username].authorized) {
				return;
			}
			authorized = &m_participants[message.username];
			unauthorized = &m_participants[sender];
		}
		assert(authorized->authorized);
		assert(!unauthorized->authorized);
		
		if (authorized->username == sender) {
			unauthorized->authorized_by.insert(authorized->username);
		} else {
			unauthorized->authorized_peers.insert(authorized->username);
		}
		
		dump("User " + sender + " has authorized user " + message.username);
		
		try_promote_unauthorized_participant(unauthorized);
	} else if (np1sec_message.type == Message::Type::ConsistencyStatus) {
		if (!m_participants.count(sender)) {
			return;
		}
		
		if (sender == m_room->username()) {
			UnsignedConsistencyCheckMessage message;
			message.channel_status_hash = m_channel_status_hash;
			send_message(ConsistencyCheckMessage::sign(message, m_room->ephemeral_private_key()), "consistency check");
		}
		
		Event event;
		event.type = Message::Type::ConsistencyCheck;
		event.consistency_check.channel_status_hash = m_channel_status_hash;
		event.consistency_check.remaining_users.insert(sender);
		m_events.push_back(std::move(event));
	} else if (np1sec_message.type == Message::Type::ConsistencyCheck) {
		if (!m_participants.count(sender)) {
			return;
		}
		
		ConsistencyCheckMessage signed_message;
		try {
			signed_message = ConsistencyCheckMessage::verify(np1sec_message, m_participants[sender].ephemeral_public_key);
		} catch(MessageFormatException) {
			return;
		}
		if (!signed_message.valid) {
			remove_user(sender);
			return;
		}
		UnsignedConsistencyCheckMessage message = signed_message.decode();
		
		auto first_event = first_user_event(sender);
		if (!(
			   first_event != m_events.end()
			&& first_event->type == Message::Type::ConsistencyCheck
			&& first_event->consistency_check.channel_status_hash == message.channel_status_hash
		)) {
			remove_user(sender);
			return;
		}
		
		first_event->consistency_check.remaining_users.erase(sender);
		if (first_event->consistency_check.remaining_users.empty()) {
			m_events.erase(first_event);
		}
		
		dump("Verified consistency hash " + message.channel_status_hash.dump_hex() + " for user " + sender);
	}
}

void Channel::user_joined(const std::string& username)
{
	// NOTE do we need this?
}

void Channel::user_left(const std::string& username)
{
	remove_user(username);
}






void Channel::self_joined()
{
	m_joined = true;
	
	for (const auto& i : m_participants) {
		if (i.second.username == m_room->username()) {
			continue;
		}
		
		authenticate_to(i.second.username, i.second.long_term_public_key, i.second.ephemeral_public_key);
	}
}

void Channel::try_promote_unauthorized_participant(Participant* participant)
{
	assert(!participant->authorized);
	
	for (const auto& i : m_participants) {
		if (i.second.authorized) {
			if (!participant->authorized_by.count(i.second.username)) {
				return;
			}
			if (!participant->authorized_peers.count(i.second.username)) {
				return;
			}
		}
	}
	participant->authorized = true;
	participant->authorized_by.clear();
	participant->authorized_peers.clear();
	
	if (participant->username == m_room->username()) {
		m_authorized = true;
	}
	
	dump("Promoting participant to authorized participant: " + participant->username);
}

void Channel::remove_user(const std::string& username)
{
	if (!m_participants.count(username)) {
		return;
	}
	
	m_participants.erase(username);
	for (auto& p : m_participants) {
		if (!p.second.authorized) {
			p.second.authorized_by.erase(username);
			p.second.authorized_peers.erase(username);
		}
	}
	
	for (std::vector<Event>::iterator i = m_events.begin(); i != m_events.end(); ) {
		if (i->type == Message::Type::ChannelStatus) {
			i->channel_status.remaining_users.erase(username);
			if (i->channel_status.remaining_users.empty()) {
				i = m_events.erase(i);
			} else {
				++i;
			}
		} else if (i->type == Message::Type::ConsistencyCheck) {
			i->channel_status.remaining_users.erase(username);
			if (i->channel_status.remaining_users.empty()) {
				i = m_events.erase(i);
			} else {
				++i;
			}
		} else {
			assert(false);
		}
	}
	
	dump("Removing participant: " + username);
	
	for (auto& p : m_participants) {
		if (!p.second.authorized) {
			try_promote_unauthorized_participant(&p.second);
		}
	}
}

void Channel::send_message(const Message& message, std::string debug_description)
{
	if (!debug_description.empty()) {
		m_room->send_message("sending message: " + debug_description);
	}
	m_room->send_message(message);
}



Message Channel::channel_status(const std::string& searcher_username, const Hash& searcher_nonce) const
{
	ChannelStatusMessage result;
	result.searcher_username = searcher_username;
	result.searcher_nonce = searcher_nonce;
	result.channel_status_hash = m_channel_status_hash;
	
	for (const auto& i : m_participants) {
		if (i.second.authorized) {
			ChannelStatusMessage::Participant participant;
			participant.username = i.second.username;
			participant.long_term_public_key = i.second.long_term_public_key;
			participant.ephemeral_public_key = i.second.ephemeral_public_key;
			result.participants.push_back(participant);
		} else {
			ChannelStatusMessage::UnauthorizedParticipant participant;
			participant.username = i.second.username;
			participant.long_term_public_key = i.second.long_term_public_key;
			participant.ephemeral_public_key = i.second.ephemeral_public_key;
			participant.authorized_by = i.second.authorized_by;
			participant.authorized_peers = i.second.authorized_peers;
			result.unauthorized_participants.push_back(participant);
		}
	}
	
	for (const Event& event : m_events) {
		if (event.type == Message::Type::ChannelStatus) {
			result.events.push_back(event.channel_status.encode(result));
		} else if (event.type == Message::Type::ConsistencyCheck) {
			result.events.push_back(event.consistency_check.encode(result));
		} else {
			assert(false);
		}
	}
	
	return result.encode();
}

void Channel::hash_message(const std::string& sender, const Message& message)
{
	Hash zero;
	memset(zero.buffer, 0, sizeof(zero.buffer));
	
	std::string buffer = channel_status(std::string(), zero).payload;
	buffer += sender;
	buffer += uint8_t(message.type);
	buffer += message.payload;
	m_channel_status_hash = crypto::hash(buffer);
}

void Channel::authenticate_to(const std::string& username, const PublicKey& long_term_public_key, const PublicKey& ephemeral_public_key)
{
	AuthenticationMessage message;
	message.sender_long_term_public_key = m_room->long_term_public_key();
	message.sender_ephemeral_public_key = m_room->ephemeral_public_key();
	message.peer_username = username;
	message.peer_long_term_public_key = long_term_public_key;
	message.peer_ephemeral_public_key = ephemeral_public_key;
	message.authentication_confirmation = authentication_token(username, long_term_public_key, ephemeral_public_key, false);
	send_message(message.encode(), "authentication for " + username);
}

Hash Channel::authentication_token(const std::string& username, const PublicKey& long_term_public_key, const PublicKey& ephemeral_public_key, bool for_peer)
{
	Hash token = crypto::triple_diffie_hellman(
		m_room->long_term_private_key(),
		m_room->ephemeral_private_key(),
		long_term_public_key,
		ephemeral_public_key
	);
	std::string buffer = token.as_string();
	if (for_peer) {
		buffer += long_term_public_key.as_string();
		buffer += username;
	} else {
		buffer += m_room->long_term_public_key().as_string();
		buffer += m_room->username();
	}
	return crypto::hash(buffer);
}

std::vector<Channel::Event>::iterator Channel::first_user_event(const std::string& username)
{
	for (std::vector<Event>::iterator i = m_events.begin(); i != m_events.end(); ++i) {
		if (i->type == Message::Type::ChannelStatus) {
			if (i->channel_status.remaining_users.count(username)) {
				return i;
			}
		} else if (i->type == Message::Type::ConsistencyCheck) {
			if (i->consistency_check.remaining_users.count(username)) {
				return i;
			}
		} else {
			assert(false);
		}
	}
	return m_events.end();
}

/*
 * TODO: this is a placeholder for proper timer support later.
 */
void Channel::set_channel_status_timer()
{
	m_channel_status_timer = Timer(m_room->interface(), 10000, [this] {
		send_message(ConsistencyStatusMessage::encode(), "consistency status");
		set_channel_status_timer();
	});
}

} // namespace np1sec
