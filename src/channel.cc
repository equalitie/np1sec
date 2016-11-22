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
#include "partition.h"
#include "room.h"

namespace np1sec
{

// TODO
// timeout, in milliseconds, for responding to an event
const uint32_t c_event_timeout = 60000;
// time, in milliseconds, after which a channel status event needs to be announced if one hasn't already
const uint32_t c_channel_status_frequency = 30000;

Channel::Channel(Room* room):
	m_room(room),
	m_ephemeral_private_key(PrivateKey::generate()),
	m_interface(nullptr),
	m_joined(true),
	m_active(false),
	m_authorized(true),
	m_channel_status_hash(crypto::nonce_hash()),
	m_encrypted_chat(this)
{
	Participant self;
	self.username = m_room->username();
	self.long_term_public_key = m_room->long_term_public_key();
	self.ephemeral_public_key = ephemeral_public_key();
	self.authorization_nonce = m_channel_status_hash;
	self.authorized = true;
	self.authentication_status = AuthenticationStatus::Authenticated;
	m_participants[self.username] = std::move(self);
	set_user_channel_status_timer(m_room->username());
	
	m_encrypted_chat.create_solo_session(m_channel_status_hash);
}

Channel::Channel(Room* room, const ChannelStatusMessage& channel_status, const Message& encoded_message):
	m_room(room),
	m_ephemeral_private_key(PrivateKey::generate()),
	m_interface(nullptr),
	m_joined(false),
	m_active(false),
	m_authorized(false),
	m_encrypted_chat(this),
	m_authentication_nonce(crypto::nonce_hash())
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
	
	for (const ChannelStatusMessage::AuthorizedParticipant& p : channel_status.participants) {
		Participant participant;
		participant.username = p.username;
		participant.long_term_public_key = p.long_term_public_key;
		participant.ephemeral_public_key = p.ephemeral_public_key;
		participant.authorization_nonce = p.authorization_nonce;
		participant.authorized = true;
		participant.authentication_status = AuthenticationStatus::Unauthenticated;
		
		if (m_participants.count(participant.username)) {
			throw MessageFormatException();
		}
		
		m_participants[participant.username] = std::move(participant);
		set_user_channel_status_timer(p.username);
		
		channel_status_event.remaining_users.insert(p.username);
		
		m_encrypted_chat.do_add_user(p.username, p.long_term_public_key);
	}
	
	for (const ChannelStatusMessage::UnauthorizedParticipant& p : channel_status.unauthorized_participants) {
		Participant participant;
		participant.username = p.username;
		participant.long_term_public_key = p.long_term_public_key;
		participant.ephemeral_public_key = p.ephemeral_public_key;
		participant.authorization_nonce = p.authorization_nonce;
		participant.authorized = false;
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
		set_user_channel_status_timer(p.username);
		
		channel_status_event.remaining_users.insert(p.username);
	}
	
	for (const ChannelStatusMessage::AuthorizedParticipant& p : channel_status.participants) {
		for (const std::string& username : p.timeout_peers) {
			if (!m_participants.count(username)) {
				throw MessageFormatException();
			}
			m_participants[p.username].timeout_peers.insert(username);
		}
		for (const std::string& username : p.votekick_peers) {
			if (!m_participants.count(username)) {
				throw MessageFormatException();
			}
			m_participants[p.username].votekick_peers.insert(username);
		}
	}
	
	m_channel_status_hash = channel_status.channel_status_hash;
	m_encrypted_chat.initialize_latest_session(channel_status.latest_session_id);
	
	std::set<Hash> key_exchange_ids;
	std::set<Hash> key_exchange_event_ids;
	std::set<Hash> key_activation_event_ids;
	std::set<Hash> key_ids_seen;
	for (const KeyExchangeState& exchange : channel_status.key_exchanges) {
		if (key_exchange_ids.count(exchange.key_id)) {
			throw MessageFormatException();
		}
		
		m_encrypted_chat.unserialize_key_exchange(exchange);
		
		key_exchange_ids.insert(exchange.key_id);
	}
	
	for (const ChannelEvent& channel_event : channel_status.events) {
		Event event;
		event.type = channel_event.type;
		if (channel_event.type == Message::Type::ChannelStatus) {
			ChannelStatusEvent e = ChannelStatusEvent::decode(channel_event, channel_status);
			event.channel_status = e;
			event.remaining_users = e.remaining_users;
		} else if (channel_event.type == Message::Type::ConsistencyCheck) {
			ConsistencyCheckEvent e = ConsistencyCheckEvent::decode(channel_event, channel_status);
			event.consistency_check = e;
			event.remaining_users = e.remaining_users;
		} else if (
			   channel_event.type == Message::Type::KeyExchangePublicKey
			|| channel_event.type == Message::Type::KeyExchangeSecretShare
			|| channel_event.type == Message::Type::KeyExchangeAcceptance
			|| channel_event.type == Message::Type::KeyExchangeReveal
		) {
			KeyExchangeEvent e = KeyExchangeEvent::decode(channel_event, channel_status);
			event.key_event.key_id = e.key_id;
			if (e.cancelled) {
				if (key_exchange_ids.count(event.key_event.key_id)) {
					throw MessageFormatException();
				}
				event.remaining_users = e.remaining_users;
			} else {
				if (!key_exchange_ids.count(event.key_event.key_id)) {
					throw MessageFormatException();
				}
				if (key_exchange_event_ids.count(event.key_event.key_id)) {
					throw MessageFormatException();
				}
				key_exchange_event_ids.insert(event.key_event.key_id);
				event.remaining_users = m_encrypted_chat.remaining_users(e.key_id);
			}
		} else if (channel_event.type == Message::Type::KeyActivation) {
			KeyActivationEvent e = KeyActivationEvent::decode(channel_event, channel_status);
			event.key_event = e;
			event.remaining_users = e.remaining_users;
			if (key_exchange_ids.count(event.key_event.key_id)) {
				throw MessageFormatException();
			}
			if (key_activation_event_ids.count(event.key_event.key_id)) {
				throw MessageFormatException();
			}
			key_activation_event_ids.insert(event.key_event.key_id);
		} else {
			throw MessageFormatException();
		}
		declare_event(std::move(event));
	}
	
	/*
	 * Each key exchange key ID must appear as exactly one key-exchange event.
	 */
	if (key_exchange_ids.size() != key_exchange_event_ids.size()) {
		throw MessageFormatException();
	}
	
	declare_event(std::move(channel_status_event));
}

Channel::Channel(Room* room, const ChannelAnnouncementMessage& channel_status, const std::string& sender):
	m_room(room),
	m_ephemeral_private_key(PrivateKey::generate()),
	m_interface(nullptr),
	m_joined(false),
	m_active(false),
	m_authorized(false),
	m_encrypted_chat(this),
	m_authentication_nonce(crypto::nonce_hash())
{
	m_channel_status_hash = channel_status.channel_status_hash;
	
	Participant participant;
	participant.username = sender;
	participant.long_term_public_key = channel_status.long_term_public_key;
	participant.ephemeral_public_key = channel_status.ephemeral_public_key;
	participant.authorization_nonce = channel_status.channel_status_hash;
	participant.authorized = true;
	participant.authentication_status = AuthenticationStatus::Unauthenticated;
	m_participants[participant.username] = std::move(participant);
	set_user_channel_status_timer(sender);
	
	m_encrypted_chat.initialize_latest_session(m_channel_status_hash);
	m_encrypted_chat.do_add_user(sender, channel_status.long_term_public_key);
}

void Channel::send_chat(const std::string& message)
{
	m_encrypted_chat.send_message(message);
}

void Channel::votekick(const std::string& username, bool kick)
{
	if (!m_participants.count(username)) {
		return;
	}
	
	Participant& participant = m_participants[username];
	if (participant.votekick_in_flight != kick) {
		participant.votekick_in_flight = kick;
		if (m_authorized) {
			VotekickMessage message;
			message.victim = username;
			message.kick = kick;
			send_message(message.encode());
		}
	}
}

void Channel::announce()
{
	ChannelAnnouncementMessage message;
	message.long_term_public_key = m_room->long_term_public_key();
	message.ephemeral_public_key = ephemeral_public_key();
	message.channel_status_hash = m_channel_status_hash;
	send_message(message.encode());
}

void Channel::confirm_participant(const std::string& username)
{
	if (!m_participants.count(username)) {
		return;
	}
	
	Participant& participant = m_participants[username];
	if (participant.authentication_status == AuthenticationStatus::Unauthenticated) {
		participant.authentication_status = AuthenticationStatus::AuthenticatingWithNonce;
		
		AuthenticationRequestMessage request;
		request.sender_long_term_public_key = m_room->long_term_public_key();
		request.sender_ephemeral_public_key = ephemeral_public_key();
		request.peer_username = participant.username;
		request.peer_long_term_public_key = participant.long_term_public_key;
		request.peer_ephemeral_public_key = participant.ephemeral_public_key;
		request.nonce = m_authentication_nonce;
		send_message(request.encode());
	}
}

void Channel::join()
{
	JoinRequestMessage message;
	message.long_term_public_key = m_room->long_term_public_key();
	message.ephemeral_public_key = ephemeral_public_key();
	
	for (const auto& i : m_participants) {
		message.peer_usernames.push_back(i.first);
	}
	
	send_message(message.encode());
}

void Channel::activate()
{
	m_active = true;
	
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
	
	UnsignedAuthorizationMessage message;
	message.username = participant.username;
	message.long_term_public_key = participant.long_term_public_key;
	message.ephemeral_public_key = participant.ephemeral_public_key;
	message.authorization_nonce = participant.authorization_nonce;
	send_message(AuthorizationMessage::sign(message, m_ephemeral_private_key));
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
			consistency_check_event.remaining_users.insert(i.second.username);
			set_user_channel_status_timer(i.second.username);
		}
		declare_event(std::move(consistency_check_event));
		
		if (m_active) {
			UnsignedConsistencyCheckMessage consistency_check_message;
			consistency_check_message.channel_status_hash = m_channel_status_hash;
			send_message(ConsistencyCheckMessage::sign(consistency_check_message, m_ephemeral_private_key));
		}
		
		Message reply = channel_status(sender, message.nonce);
		
		Event reply_event;
		reply_event.type = Message::Type::ChannelStatus;
		reply_event.channel_status.searcher_username = sender;
		reply_event.channel_status.searcher_nonce = message.nonce;
		reply_event.channel_status.status_message_hash = crypto::hash(reply.payload);
		for (const auto& i : m_participants) {
			reply_event.remaining_users.insert(i.second.username);
		}
		declare_event(std::move(reply_event));
		
		if (m_active) {
			send_message(reply);
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
		
		if (first_event->remaining_users.empty()) {
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
		participant.authorization_nonce = m_channel_status_hash;
		participant.authorized = false;
		m_participants[sender] = std::move(participant);
		set_user_channel_status_timer(sender);
		
		if (sender == m_room->username()) {
			m_participants[sender].authentication_status = AuthenticationStatus::Authenticated;
		} else if (!m_active) {
			m_participants[sender].authentication_status = AuthenticationStatus::AuthenticatingWithNonce;
			
			AuthenticationRequestMessage request;
			request.sender_long_term_public_key = m_room->long_term_public_key();
			request.sender_ephemeral_public_key = ephemeral_public_key();
			request.peer_username = sender;
			request.peer_long_term_public_key = message.long_term_public_key;
			request.peer_ephemeral_public_key = message.ephemeral_public_key;
			request.nonce = m_authentication_nonce;
			send_message(request.encode());
		} else {
			m_participants[sender].authentication_status = AuthenticationStatus::Authenticating;
		}
		
		if (m_interface) {
			m_interface->user_joined(sender);
		}
		
		if (sender == m_room->username()) {
			self_joined();
		}
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
			&& message.peer_ephemeral_public_key == ephemeral_public_key()
		) {
			authenticate_to(sender, message.sender_long_term_public_key, message.sender_ephemeral_public_key, message.nonce);
		}
	} else if (np1sec_message.type == Message::Type::Authentication) {
		AuthenticationMessage message;
		try {
			message = AuthenticationMessage::decode(np1sec_message);
		} catch(MessageFormatException) {
			return;
		}
		
		if (!(
			   message.peer_username == m_room->username()
			&& message.peer_long_term_public_key == m_room->long_term_public_key()
			&& message.peer_ephemeral_public_key == ephemeral_public_key()
		)) {
			return;
		}
		
		if (!m_participants.count(sender)) {
			return;
		}
		
		Participant& participant = m_participants[sender];
		if (!(
			   message.sender_long_term_public_key == participant.long_term_public_key
			&& message.sender_ephemeral_public_key == participant.ephemeral_public_key
		)) {
			return;
		}
		
		if (participant.authentication_status == AuthenticationStatus::Authenticating) {
			if (message.nonce != participant.authorization_nonce) {
				return;
			}
		} else if (participant.authentication_status == AuthenticationStatus::AuthenticatingWithNonce) {
			if (message.nonce != participant.authorization_nonce && message.nonce != m_authentication_nonce) {
				return;
			}
		} else {
			return;
		}
		
		Hash correct_token = authentication_token(sender, participant.long_term_public_key, participant.ephemeral_public_key, message.nonce, true);
		if (message.authentication_confirmation == correct_token) {
			participant.authentication_status = AuthenticationStatus::Authenticated;
			
			if (m_interface) {
				m_interface->user_authenticated(sender, participant.long_term_public_key);
			}
		} else {
			participant.authentication_status = AuthenticationStatus::AuthenticationFailed;
			
			if (m_interface) {
				m_interface->user_authentication_failed(sender);
			}
		}
	} else if (np1sec_message.type == Message::Type::Authorization) {
		if (!m_participants.count(sender)) {
			return;
		}
		
		AuthorizationMessage signed_message;
		try {
			signed_message = AuthorizationMessage::verify(np1sec_message, m_participants[sender].ephemeral_public_key);
		} catch(MessageFormatException) {
			return;
		}
		if (!signed_message.valid) {
			remove_user(sender);
			return;
		}
		auto message = signed_message.decode();
		
		if (!(
			   m_participants.count(message.username)
			&& m_participants.at(message.username).long_term_public_key == message.long_term_public_key
			&& m_participants.at(message.username).ephemeral_public_key == message.ephemeral_public_key
			&& m_participants.at(message.username).authorization_nonce == message.authorization_nonce
		)) {
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
		
		if (m_interface) {
			m_interface->user_authorized_by(sender, message.username);
		}
		
		if (try_promote_unauthorized_participant(unauthorized)) {
			m_encrypted_chat.add_user(unauthorized->username, unauthorized->long_term_public_key);
		}
	} else if (np1sec_message.type == Message::Type::ConsistencyStatus) {
		if (!m_participants.count(sender)) {
			return;
		}
		
		if (m_active && sender == m_room->username()) {
			UnsignedConsistencyCheckMessage message;
			message.channel_status_hash = m_channel_status_hash;
			send_message(ConsistencyCheckMessage::sign(message, m_ephemeral_private_key));
		}
		
		Event event;
		event.type = Message::Type::ConsistencyCheck;
		event.consistency_check.channel_status_hash = m_channel_status_hash;
		event.remaining_users.insert(sender);
		declare_event(std::move(event));
		set_user_channel_status_timer(sender);
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
		auto message = signed_message.decode();
		
		auto first_event = first_user_event(sender);
		if (!(
			   first_event != m_events.end()
			&& first_event->type == Message::Type::ConsistencyCheck
			&& first_event->consistency_check.channel_status_hash == message.channel_status_hash
		)) {
			remove_user(sender);
			return;
		}
		
		if (first_event->remaining_users.empty()) {
			m_events.erase(first_event);
		}
	} else if (np1sec_message.type == Message::Type::Timeout) {
		if (!m_participants.count(sender)) {
			return;
		}
		
		TimeoutMessage message;
		try {
			message = TimeoutMessage::decode(np1sec_message);
		} catch(MessageFormatException) {
			return;
		}
		
		if (!m_participants.count(message.victim)) {
			return;
		}
		
		if (sender == message.victim) {
			return;
		}
		
		if (message.timeout) {
			if (m_participants[sender].timeout_peers.insert(message.victim).second) {
				try_channel_split(false);
			}
		} else {
			m_participants[sender].timeout_peers.erase(message.victim);
		}
	} else if (np1sec_message.type == Message::Type::Votekick) {
		if (!m_participants.count(sender)) {
			return;
		}
		
		VotekickMessage message;
		try {
			message = VotekickMessage::decode(np1sec_message);
		} catch(MessageFormatException) {
			return;
		}
		
		if (!m_participants.count(message.victim)) {
			return;
		}
		
		if (sender == message.victim) {
			return;
		}
		
		if (message.kick) {
			if (m_participants[sender].votekick_peers.insert(message.victim).second) {
				try_channel_split(true);
			}
		} else {
			m_participants[sender].votekick_peers.erase(message.victim);
		}
	} else if (np1sec_message.type == Message::Type::KeyExchangePublicKey) {
		if (!m_participants.count(sender)) {
			return;
		}
		
		KeyExchangePublicKeyMessage signed_message;
		try {
			signed_message = KeyExchangePublicKeyMessage::verify(np1sec_message, m_participants[sender].ephemeral_public_key);
		} catch(MessageFormatException) {
			return;
		}
		if (!signed_message.valid) {
			remove_user(sender);
			return;
		}
		auto message = signed_message.decode();
		
		auto first_event = first_user_event(sender);
		if (!(
			   first_event != m_events.end()
			&& first_event->type == Message::Type::KeyExchangePublicKey
			&& first_event->key_event.key_id == message.key_id
		)) {
			remove_user(sender);
			return;
		}
		
		if (first_event->remaining_users.empty()) {
			m_events.erase(first_event);
		}
		
		m_encrypted_chat.user_public_key(sender, message.key_id, message.public_key);
	} else if (np1sec_message.type == Message::Type::KeyExchangeSecretShare) {
		if (!m_participants.count(sender)) {
			return;
		}
		
		KeyExchangeSecretShareMessage signed_message;
		try {
			signed_message = KeyExchangeSecretShareMessage::verify(np1sec_message, m_participants[sender].ephemeral_public_key);
		} catch(MessageFormatException) {
			return;
		}
		if (!signed_message.valid) {
			remove_user(sender);
			return;
		}
		auto message = signed_message.decode();
		
		auto first_event = first_user_event(sender);
		if (!(
			   first_event != m_events.end()
			&& first_event->type == Message::Type::KeyExchangeSecretShare
			&& first_event->key_event.key_id == message.key_id
		)) {
			remove_user(sender);
			return;
		}
		
		if (first_event->remaining_users.empty()) {
			m_events.erase(first_event);
		}
		
		if (!m_encrypted_chat.have_key_exchange(message.key_id)) {
			return;
		}
		
		m_encrypted_chat.user_secret_share(sender, message.key_id, message.group_hash, message.secret_share);
	} else if (np1sec_message.type == Message::Type::KeyExchangeAcceptance) {
		if (!m_participants.count(sender)) {
			return;
		}
		
		KeyExchangeAcceptanceMessage signed_message;
		try {
			signed_message = KeyExchangeAcceptanceMessage::verify(np1sec_message, m_participants[sender].ephemeral_public_key);
		} catch(MessageFormatException) {
			return;
		}
		if (!signed_message.valid) {
			remove_user(sender);
			return;
		}
		auto message = signed_message.decode();
		
		auto first_event = first_user_event(sender);
		if (!(
			   first_event != m_events.end()
			&& first_event->type == Message::Type::KeyExchangeAcceptance
			&& first_event->key_event.key_id == message.key_id
		)) {
			remove_user(sender);
			return;
		}
		
		if (first_event->remaining_users.empty()) {
			m_events.erase(first_event);
		}
		
		if (!m_encrypted_chat.have_key_exchange(message.key_id)) {
			return;
		}
		
		m_encrypted_chat.user_key_hash(sender, message.key_id, message.key_hash);
	} else if (np1sec_message.type == Message::Type::KeyExchangeReveal) {
		if (!m_participants.count(sender)) {
			return;
		}
		
		KeyExchangeRevealMessage signed_message;
		try {
			signed_message = KeyExchangeRevealMessage::verify(np1sec_message, m_participants[sender].ephemeral_public_key);
		} catch(MessageFormatException) {
			return;
		}
		if (!signed_message.valid) {
			remove_user(sender);
			return;
		}
		auto message = signed_message.decode();
		
		auto first_event = first_user_event(sender);
		if (!(
			   first_event != m_events.end()
			&& first_event->type == Message::Type::KeyExchangeReveal
			&& first_event->key_event.key_id == message.key_id
		)) {
			remove_user(sender);
			return;
		}
		
		if (first_event->remaining_users.empty()) {
			m_events.erase(first_event);
		}
		
		if (!m_encrypted_chat.have_key_exchange(message.key_id)) {
			return;
		}
		
		m_encrypted_chat.user_private_key(sender, message.key_id, message.private_key);
	} else if (np1sec_message.type == Message::Type::KeyActivation) {
		if (!m_participants.count(sender)) {
			return;
		}
		
		KeyActivationMessage signed_message;
		try {
			signed_message = KeyActivationMessage::verify(np1sec_message, m_participants[sender].ephemeral_public_key);
		} catch(MessageFormatException) {
			return;
		}
		if (!signed_message.valid) {
			remove_user(sender);
			return;
		}
		auto message = signed_message.decode();
		
		auto first_event = first_user_event(sender);
		if (!(
			   first_event != m_events.end()
			&& first_event->type == Message::Type::KeyActivation
			&& first_event->key_event.key_id == message.key_id
		)) {
			remove_user(sender);
			return;
		}
		
		if (first_event->remaining_users.empty()) {
			m_events.erase(first_event);
		}
		
		if (m_encrypted_chat.have_session(message.key_id)) {
			m_encrypted_chat.user_activation(sender, message.key_id);
		}
	} else if (np1sec_message.type == Message::Type::Chat) {
		ChatMessage message;
		try {
			message = ChatMessage::decode(np1sec_message);
		} catch(MessageFormatException) {
			return;
		}
		
		m_encrypted_chat.decrypt_message(sender, message);
	} else if (np1sec_message.type == Message::Type::KeyRatchet) {
		KeyRatchetMessage message;
		try {
			message = KeyRatchetMessage::decode(np1sec_message);
		} catch(MessageFormatException) {
			return;
		}
		
		if (m_participants.count(sender) && m_participants.at(sender).authorized) {
			m_encrypted_chat.replace_session(message.key_id);
		}
	}
}

void Channel::user_left(const std::string& username)
{
	hash_payload(username, 0, "left");
	
	remove_user(username);
}

void Channel::add_key_exchange_event(Message::Type type, const Hash& key_id, const std::set<std::string>& usernames)
{
	Event event;
	event.type = type;
	event.remaining_users = usernames;
	event.key_event.key_id = key_id;
	declare_event(std::move(event));
}



void Channel::self_joined()
{
	m_joined = true;
	
	for (const auto& i : m_participants) {
		if (i.second.username == m_room->username()) {
			continue;
		}
		
		authenticate_to(i.second.username, i.second.long_term_public_key, i.second.ephemeral_public_key, m_channel_status_hash);
	}
	
	if (m_interface) {
		m_interface->joined();
	}
}

bool Channel::try_promote_unauthorized_participant(Participant* participant)
{
	assert(!participant->authorized);
	
	for (const auto& i : m_participants) {
		if (i.second.authorized) {
			if (!participant->authorized_by.count(i.second.username)) {
				return false;
			}
			if (!participant->authorized_peers.count(i.second.username)) {
				return false;
			}
		}
	}
	participant->authorized = true;
	participant->authorized_by.clear();
	participant->authorized_peers.clear();
	
	if (participant->username == m_room->username()) {
		m_authorized = true;
	}
	
	if (m_interface) {
		m_interface->user_promoted(participant->username);
	}
	
	if (m_interface && participant->username == m_room->username()) {
		m_interface->authorized();
	}
	
	return true;
}

void Channel::remove_user(const std::string& username)
{
	std::set<std::string> usernames;
	usernames.insert(username);
	remove_users(usernames);
}

void Channel::remove_users(const std::set<std::string>& usernames)
{
	for (const std::string& username : usernames) {
		if (!m_participants.count(username)) {
			continue;
		}
		
		do_remove_user(username);
	}
	
	for (auto& p : m_participants) {
		if (!p.second.authorized) {
			if (try_promote_unauthorized_participant(&p.second)) {
				m_encrypted_chat.do_add_user(p.second.username, p.second.long_term_public_key);
				break;
			}
		}
	}
	
	m_encrypted_chat.remove_users(usernames);
}

void Channel::do_remove_user(const std::string& username)
{
	assert(m_participants.count(username));
	
	while (!m_participants[username].events.empty()) {
		auto it = m_participants[username].events.front();
		m_participants[username].events.pop_front();
		
		assert(it->remaining_users.count(username));
		it->remaining_users.erase(username);
		if (it->remaining_users.empty()) {
			m_events.erase(it);
		}
	}
	
	m_participants.erase(username);
	for (auto& p : m_participants) {
		if (!p.second.authorized) {
			p.second.authorized_by.erase(username);
			p.second.authorized_peers.erase(username);
		}
		p.second.timeout_peers.erase(username);
		p.second.votekick_peers.erase(username);
	}
	
	if (m_interface) {
		m_interface->user_left(username);
	}
}

void Channel::try_channel_split(bool because_votekick)
{
	/*
	 * A split check has two parts.
	 * First, the authorized members perform a symmetric split operation among themselves.
	 * Second, any unauthorized members who are kicked by all authorized members are kicked
	 * asymmetrically.
	 */
	
	std::map<std::string, const std::set<std::string>* > graph;
	for (const auto& i : m_participants) {
		if (i.second.authorized) {
			const std::set<std::string>* victims;
			if (because_votekick) {
				victims = &i.second.votekick_peers;
			} else {
				victims = &i.second.timeout_peers;
			}
			
			graph[i.second.username] = victims;
		}
	}
	
	std::vector<std::set<std::string>> partition = compute_channel_partition(graph);
	if (partition.size() > 1) {
		/*
		* A split has occurred. Find out which side we're in.
		*/
		
		std::set<std::string> our_part;
		if (m_authorized) {
			/*
			* If we are an authorized member, we are in the side containing ourselves.
			*/
			
			for (const std::set<std::string>& part : partition) {
				if (part.count(m_room->username())) {
					our_part = part;
					break;
				}
			}
			assert(our_part.count(m_room->username()));
		} else {
			/*
			* If we are not an authorized member, we choose to join the largest
			* side. If this is a votekick split, we choose the largest remaining
			* side period; if this is a timeout split, we choose the side containing
			* the largest amount of members that are not timeouted according to
			* our own bookkeeping.
			*/
			
			size_t largest_index = -1;
			int largest_count = -1;
			for (size_t i = 0; i < partition.size(); i++) {
				const std::set<std::string>& part = partition[i];
				int count;
				
				if (because_votekick) {
					count = part.size();
				} else {
					count = 0;
					for (const std::string& username : part) {
						if (!m_participants[username].timeout_in_flight) {
							count++;
						}
					}
				}
				if (count > largest_count) {
					largest_count = count;
					largest_index = i;
				}
			}
			
			our_part = partition[largest_index];
			assert(our_part.size() > 0);
		}
		
		std::set<std::string> victims;
		for (const auto& i : m_participants) {
			if (i.second.authorized && our_part.count(i.second.username) == 0) {
				victims.insert(i.second.username);
			}
		}
		remove_users(victims);
	}
	
	std::set<std::string> victims;
	for (const auto& i : m_participants) {
		if (i.second.authorized) {
			continue;
		}
		
		bool do_kick = true;
		for (const auto& j : m_participants) {
			if (!j.second.authorized) {
				continue;
			}
			
			bool kick;
			if (because_votekick) {
				kick = j.second.votekick_peers.count(i.second.username) > 0;
			} else {
				kick = j.second.timeout_peers.count(i.second.username) > 0;
			}
			if (!kick) {
				do_kick = false;
				break;
			}
		}
		
		if (do_kick) {
			victims.insert(i.second.username);
		}
	}
	remove_users(victims);
}

void Channel::check_timeout(const std::string& username)
{
	assert(m_participants.count(username));
	
	Participant& participant = m_participants[username];
	
	bool event_timeout = (!participant.events.empty() && participant.events.front()->timeout);
	bool channel_status_timeout = !participant.channel_status_timer.active();
	
	bool want_timeout = event_timeout || channel_status_timeout;
	if (participant.timeout_in_flight != want_timeout) {
		participant.timeout_in_flight = want_timeout;
		if (m_authorized) {
			TimeoutMessage message;
			message.victim = username;
			message.timeout = want_timeout;
			send_message(message.encode());
		}
	}
}



void Channel::declare_event(Event&& event)
{
	std::list<Event>::iterator it = m_events.insert(m_events.end(), std::move(event));
	for (const std::string& username : it->remaining_users) {
		assert(m_participants.count(username));
		m_participants[username].events.push_back(it);
	}
	it->timeout = false;
	
	it->timeout_timer = Timer(m_room->interface(), c_event_timeout, [this, it] {
		it->timeout = true;
		for (const std::string& username : it->remaining_users) {
			check_timeout(username);
		}
	});
}

void Channel::send_message(const Message& message)
{
	m_room->send_message(message);
}

Message Channel::channel_status(const std::string& searcher_username, const Hash& searcher_nonce) const
{
	ChannelStatusMessage result;
	result.searcher_username = searcher_username;
	result.searcher_nonce = searcher_nonce;
	result.channel_status_hash = m_channel_status_hash;
	result.latest_session_id = m_encrypted_chat.latest_session_id();
	
	for (const auto& i : m_participants) {
		if (i.second.authorized) {
			ChannelStatusMessage::AuthorizedParticipant participant;
			participant.username = i.second.username;
			participant.long_term_public_key = i.second.long_term_public_key;
			participant.ephemeral_public_key = i.second.ephemeral_public_key;
			participant.authorization_nonce = i.second.authorization_nonce;
			participant.timeout_peers = i.second.timeout_peers;
			participant.votekick_peers = i.second.votekick_peers;
			result.participants.push_back(participant);
		} else {
			ChannelStatusMessage::UnauthorizedParticipant participant;
			participant.username = i.second.username;
			participant.long_term_public_key = i.second.long_term_public_key;
			participant.ephemeral_public_key = i.second.ephemeral_public_key;
			participant.authorization_nonce = i.second.authorization_nonce;
			participant.authorized_by = i.second.authorized_by;
			participant.authorized_peers = i.second.authorized_peers;
			result.unauthorized_participants.push_back(participant);
		}
	}
	
	result.key_exchanges = m_encrypted_chat.encode_key_exchanges();
	
	for (const Event& event : m_events) {
		if (event.type == Message::Type::ChannelStatus) {
			ChannelStatusEvent channel_status_event;
			channel_status_event.searcher_username = event.channel_status.searcher_username;
			channel_status_event.searcher_nonce = event.channel_status.searcher_nonce;
			channel_status_event.status_message_hash = event.channel_status.status_message_hash;
			channel_status_event.remaining_users = event.remaining_users;
			result.events.push_back(channel_status_event.encode(result));
		} else if (event.type == Message::Type::ConsistencyCheck) {
			ConsistencyCheckEvent consistency_check_event;
			consistency_check_event.channel_status_hash = event.consistency_check.channel_status_hash;
			consistency_check_event.remaining_users = event.remaining_users;
			result.events.push_back(consistency_check_event.encode(result));
		} else if (
			   event.type == Message::Type::KeyExchangePublicKey
			|| event.type == Message::Type::KeyExchangeSecretShare
			|| event.type == Message::Type::KeyExchangeAcceptance
			|| event.type == Message::Type::KeyExchangeReveal
		) {
			KeyExchangeEvent key_exchange_event;
			key_exchange_event.type = event.type;
			key_exchange_event.key_id = event.key_event.key_id;
			key_exchange_event.cancelled = !m_encrypted_chat.have_key_exchange(event.key_event.key_id);
			key_exchange_event.remaining_users = event.remaining_users;
			result.events.push_back(key_exchange_event.encode(result));
		} else if (event.type == Message::Type::KeyActivation) {
			KeyActivationEvent key_activation_event;
			key_activation_event.key_id = event.key_event.key_id;
			key_activation_event.remaining_users = event.remaining_users;
			result.events.push_back(key_activation_event.encode(result));
		} else {
			assert(false);
		}
	}
	
	return result.encode();
}

void Channel::hash_message(const std::string& sender, const Message& message)
{
	hash_payload(sender, uint8_t(message.type), message.payload);
}

void Channel::hash_payload(const std::string& sender, uint8_t type, const std::string& message)
{
	Hash zero;
	memset(zero.buffer, 0, sizeof(zero.buffer));
	
	std::string buffer = channel_status(std::string(), zero).payload;
	buffer += sender;
	buffer += type;
	buffer += message;
	m_channel_status_hash = crypto::hash(buffer);
}

void Channel::authenticate_to(const std::string& username, const PublicKey& long_term_public_key, const PublicKey& ephemeral_public_key, const Hash& nonce)
{
	AuthenticationMessage message;
	message.sender_long_term_public_key = m_room->long_term_public_key();
	message.sender_ephemeral_public_key = this->ephemeral_public_key();
	message.peer_username = username;
	message.peer_long_term_public_key = long_term_public_key;
	message.peer_ephemeral_public_key = ephemeral_public_key;
	message.nonce = nonce;
	message.authentication_confirmation = authentication_token(username, long_term_public_key, ephemeral_public_key, nonce, false);
	send_message(message.encode());
}

Hash Channel::authentication_token(const std::string& username, const PublicKey& long_term_public_key, const PublicKey& ephemeral_public_key, const Hash& nonce, bool for_peer)
{
	Hash token = crypto::triple_diffie_hellman(
		m_room->long_term_private_key(),
		m_ephemeral_private_key,
		long_term_public_key,
		ephemeral_public_key
	);
	std::string buffer = token.as_string();
	buffer += nonce.as_string();
	if (for_peer) {
		buffer += long_term_public_key.as_string();
		buffer += username;
	} else {
		buffer += m_room->long_term_public_key().as_string();
		buffer += m_room->username();
	}
	return crypto::hash(buffer);
}

std::list<Channel::Event>::iterator Channel::first_user_event(const std::string& username)
{
	if (!m_participants.count(username)) {
		return m_events.end();
	}
	Participant& participant = m_participants[username];
	if (participant.events.empty()) {
		return m_events.end();
	}
	auto it = participant.events.front();
	participant.events.pop_front();
	
	assert(it->remaining_users.count(username));
	it->remaining_users.erase(username);
	
	check_timeout(username);
	
	return it;
}

void Channel::set_user_channel_status_timer(const std::string& username)
{
	assert(m_participants.count(username));
	m_participants[username].channel_status_timer = Timer(m_room->interface(), c_channel_status_frequency + c_event_timeout, [username, this] {
		check_timeout(username);
	});
	check_timeout(username);
}

void Channel::set_channel_status_timer()
{
	m_channel_status_timer = Timer(m_room->interface(), c_channel_status_frequency, [this] {
		send_message(ConsistencyStatusMessage::encode());
		set_channel_status_timer();
	});
}

} // namespace np1sec
