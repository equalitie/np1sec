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

static std::string fingerprint(np1sec::PublicKey public_key)
{
	std::string output;
	for (size_t i = 0; i < sizeof(public_key.buffer); i++) {
		if (i > 0) {
			output += ':';
		}
		output += "0123456789abcdef"[(public_key.buffer[i] >> 4) & 0x0f];
		output += "0123456789abcdef"[(public_key.buffer[i] >> 0) & 0x0f];
	}
	return output;
}

void Channel::dump(const std::string& message)
{
	std::cout << "** " << message << ":\n";
	std::cout << "Channel status:\n";
	std::cout << "  Active: " << (m_active ? "yes" : "no") << "\n";
	std::cout << "  Authorized: " << (m_authorized ? "yes" : "no") << "\n";
	std::cout << "Participants:\n";
	for (const auto& p : m_participants) {
		std::string padding(16 - p.second.username.size(), ' ');
		std::cout << "  " << p.second.username << padding << " " << fingerprint(p.second.long_term_public_key) << "    " << fingerprint(p.second.ephemeral_public_key) << "\n";
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
	m_active(true),
	m_authorized(true)
{
	Participant self;
	self.username = m_room->username();
	self.long_term_public_key = m_room->long_term_public_key();
	self.ephemeral_public_key = m_room->ephemeral_public_key();
	self.authentication_status = AuthenticationStatus::Authenticated;
	self.authorized = true;
	m_participants[self.username] = self;
	
	dump("Created channel");
}

Channel::Channel(Room *room, const ChannelStatusMessage& channel_status):
	m_room(room),
	m_active(false),
	m_authorized(false)
{
	for (const ChannelStatusMessage::Participant& p : channel_status.participants) {
		Participant participant;
		participant.username = p.username;
		participant.long_term_public_key = p.long_term_public_key;
		participant.ephemeral_public_key = p.ephemeral_public_key;
		participant.authentication_status = AuthenticationStatus::Unauthenticated;
		participant.authorized = true;
		m_participants[participant.username] = std::move(participant);
	}
	
	for (const ChannelStatusMessage::UnauthorizedParticipant& p : channel_status.unauthorized_participants) {
		Participant participant;
		participant.username = p.username;
		participant.long_term_public_key = p.long_term_public_key;
		participant.ephemeral_public_key = p.ephemeral_public_key;
		participant.authentication_status = AuthenticationStatus::Unauthenticated;
		participant.authorized = false;
		
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
		
		m_participants[participant.username] = std::move(participant);
	}
	
	dump("Tracking channel");
	
	for (const auto& p : m_participants) {
		AuthenticationRequestMessage request;
		request.sender_long_term_public_key = m_room->long_term_public_key();
		request.sender_ephemeral_public_key = m_room->ephemeral_public_key();
		request.peer_username = p.second.username;
		request.peer_long_term_public_key = p.second.long_term_public_key;
		request.peer_ephemeral_public_key = p.second.ephemeral_public_key;
		send_message(request.encode(), "authentication request");
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

void Channel::authorize(const std::string& username)
{
	if (!m_participants.count(username)) {
		return;
	}
	
	Participant& participant = m_participants[username];
//	if (participant.authorized) {
//		return;
//	}
	if (participant.authorized_by.count(m_room->username())) {
		return;
	}
	
	AuthorizationMessage message;
	message.username = participant.username;
	send_message(message.encode());
}



void Channel::message_received(const std::string& sender, const Message& np1sec_message)
{
	if (np1sec_message.type == Message::Type::ChannelSearch) {
		ChannelSearchMessage message;
		try {
			message = ChannelSearchMessage::decode(np1sec_message);
		} catch(MessageFormatException) {
			return;
		}
		
		if (m_active) {
			ChannelStatusMessage reply;
			reply.searcher_username = sender;
			reply.searcher_nonce = message.nonce;
			
			for (const auto& i : m_participants) {
				if (i.second.authorized) {
					ChannelStatusMessage::Participant participant;
					participant.username = i.second.username;
					participant.long_term_public_key = i.second.long_term_public_key;
					participant.ephemeral_public_key = i.second.ephemeral_public_key;
					reply.participants.push_back(participant);
				} else {
					ChannelStatusMessage::UnauthorizedParticipant participant;
					participant.username = i.second.username;
					participant.long_term_public_key = i.second.long_term_public_key;
					participant.ephemeral_public_key = i.second.ephemeral_public_key;
					participant.authorized_by = i.second.authorized_by;
					participant.authorized_peers = i.second.authorized_peers;
					reply.unauthorized_participants.push_back(participant);
				}
			}
			
			send_message(reply.encode(), "channel status");
			
			dump("Broadcasting channel");
		}
	} else if (np1sec_message.type == Message::Type::JoinRequest) {
		JoinRequestMessage message;
		try {
			message = JoinRequestMessage::decode(np1sec_message);
		} catch(MessageFormatException) {
			return;
		}
		
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
			send_message(request.encode(), "authentication request");
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
	}
}

void Channel::user_left(const std::string& username)
{
	
}






void Channel::self_joined()
{
	m_active = true;
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
	dump("Promoting participant to authorized participant: " + participant->username);
}

void Channel::remove_user(const std::string& username)
{
	// HACK test only
	assert(!m_participants.count(username));
	
}

void Channel::send_message(const Message& message, std::string debug_description)
{
	if (!debug_description.empty()) {
		m_room->interface()->send_message("sending message: " + debug_description);
	}
	m_room->send_message(message);
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
	send_message(message.encode(), "authentication");
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


} // namespace np1sec
