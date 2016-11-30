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

#include "conversation.h"
#include "partition.h"
#include "room.h"

#include <iostream>

namespace np1sec
{

// TODO
// timeout, in milliseconds, for responding to an event
const uint32_t c_event_timeout = 60000;
// time, in milliseconds, after which a conversation status event needs to be announced if one hasn't already
const uint32_t c_conversation_status_frequency = 30000;

Conversation::Conversation(Room* room):
	m_room(room),
	m_conversation_private_key(PrivateKey::generate(true)),
	m_interface(nullptr),
	m_conversation_status_hash(crypto::nonce_hash()),
	m_encrypted_chat(this)
{
	Participant self;
	self.is_participant = true;
	self.username = m_room->username();
	self.long_term_public_key = m_room->public_key();
	self.conversation_public_key = m_conversation_private_key.public_key();
	self.authentication_status = AuthenticationStatus::Authenticated;
	self.timeout_in_flight = false;
	self.votekick_in_flight = false;
	m_participants[self.username] = std::move(self);
	set_conversation_status_timer();
	set_user_conversation_status_timer(m_room->username());
	
	m_encrypted_chat.create_solo_session(m_conversation_status_hash);
}

Conversation::Conversation(Room* room, const ConversationStatusMessage& conversation_status, const std::string& sender, const ConversationMessage& encoded_message):
	m_room(room),
	m_conversation_private_key(PrivateKey::generate(true)),
	m_interface(nullptr),
	m_encrypted_chat(this)
{
	for (const ConversationStatusMessage::Participant& p : conversation_status.participants) {
		Participant participant;
		participant.is_participant = true;
		participant.username = p.username;
		participant.long_term_public_key = p.long_term_public_key;
		participant.conversation_public_key = p.conversation_public_key;
		participant.authentication_status = AuthenticationStatus::Unauthenticated;
		participant.timeout_in_flight = false;
		participant.votekick_in_flight = false;
		
		if (m_participants.count(participant.username)) {
			throw MessageFormatException();
		}
		
		m_participants[p.username] = std::move(participant);
		set_user_conversation_status_timer(p.username);
		m_encrypted_chat.do_add_user(p.username, p.long_term_public_key);
	}
	
	for (const ConversationStatusMessage::ConfirmedInvite& i : conversation_status.confirmed_invites) {
		Participant participant;
		participant.is_participant = false;
		participant.username = i.username;
		participant.long_term_public_key = i.long_term_public_key;
		participant.conversation_public_key = i.conversation_public_key;
		participant.inviter = i.inviter;
		participant.authenticated = i.authenticated;
		participant.authentication_status = AuthenticationStatus::Unauthenticated;
		participant.timeout_in_flight = false;
		participant.votekick_in_flight = false;
		
		if (m_participants.count(participant.username)) {
			throw MessageFormatException();
		}
		if (!m_participants.count(participant.inviter)) {
			throw MessageFormatException();
		}
		
		m_participants[i.username] = std::move(participant);
		set_user_conversation_status_timer(i.username);
	}
	
	if (m_participants.count(m_room->username())) {
		throw MessageFormatException();
	}
	
	for (const ConversationStatusMessage::UnconfirmedInvite& i : conversation_status.unconfirmed_invites) {
		UnconfirmedInvite invite;
		invite.inviter = i.inviter;
		invite.username = i.username;
		invite.long_term_public_key = i.long_term_public_key;
		
		if (m_participants.count(invite.username)) {
			throw MessageFormatException();
		}
		if (!m_participants.count(invite.inviter)) {
			throw MessageFormatException();
		}
		
		m_unconfirmed_invites[i.username][i.long_term_public_key] = std::move(invite);
		m_participants[i.inviter].invitees[i.username] = i.long_term_public_key;
	}
	
	for (const ConversationStatusMessage::Participant& p : conversation_status.participants) {
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
	
	m_conversation_status_hash = conversation_status.conversation_status_hash;
	m_encrypted_chat.initialize_latest_session(conversation_status.latest_session_id);
	
	std::set<Hash> key_exchange_ids;
	std::set<Hash> key_exchange_event_ids;
	std::set<Hash> key_activation_event_ids;
	std::set<Hash> key_ids_seen;
	for (const KeyExchangeState& exchange : conversation_status.key_exchanges) {
		if (key_exchange_ids.count(exchange.key_id)) {
			throw MessageFormatException();
		}
		
		m_encrypted_chat.unserialize_key_exchange(exchange);
		
		key_exchange_ids.insert(exchange.key_id);
	}
	
	for (const ConversationEvent& conversation_event : conversation_status.events) {
		Event event;
		event.type = conversation_event.type;
		if (conversation_event.type == Message::Type::ConversationStatus) {
			ConversationStatusEvent e = ConversationStatusEvent::decode(conversation_event, conversation_status);
			event.conversation_status = e;
			event.remaining_users = e.remaining_users;
		} else if (conversation_event.type == Message::Type::ConversationConfirmation) {
			ConversationConfirmationEvent e = ConversationConfirmationEvent::decode(conversation_event, conversation_status);
			event.conversation_status = e;
			event.remaining_users = e.remaining_users;
		} else if (conversation_event.type == Message::Type::ConsistencyCheck) {
			ConsistencyCheckEvent e = ConsistencyCheckEvent::decode(conversation_event, conversation_status);
			event.consistency_check = e;
			event.remaining_users = e.remaining_users;
		} else if (
			   conversation_event.type == Message::Type::KeyExchangePublicKey
			|| conversation_event.type == Message::Type::KeyExchangeSecretShare
			|| conversation_event.type == Message::Type::KeyExchangeAcceptance
			|| conversation_event.type == Message::Type::KeyExchangeReveal
		) {
			KeyExchangeEvent e = KeyExchangeEvent::decode(conversation_event, conversation_status);
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
		} else if (conversation_event.type == Message::Type::KeyActivation) {
			KeyActivationEvent e = KeyActivationEvent::decode(conversation_event, conversation_status);
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
	
	m_status_message_hash = crypto::hash(encoded_message.payload);
	for (const auto& i : m_participants) {
		m_unconfirmed_users.insert(i.second.username);
	}
	
	/*
	 * The event queue in the conversation_status message does not contain the
	 * event describing this status message, so we need to construct it.
	 */
	Event conversation_status_event;
	conversation_status_event.type = Message::Type::ConversationStatus;
	conversation_status_event.conversation_status.invitee_username = m_room->username();
	conversation_status_event.conversation_status.invitee_long_term_public_key = m_room->public_key();
	conversation_status_event.conversation_status.status_message_hash = m_status_message_hash;
	conversation_status_event.remaining_users.insert(sender);
	declare_event(std::move(conversation_status_event));
}



std::set<std::string> Conversation::participants() const
{
	std::set<std::string> participants;
	for (const auto& i : m_participants) {
		if (i.second.is_participant) {
			participants.insert(i.second.username);
		}
	}
	return participants;
}

std::set<std::string> Conversation::invitees() const
{
	std::set<std::string> invitees;
	for (const auto& i : m_participants) {
		if (!i.second.is_participant && i.second.authenticated) {
			invitees.insert(i.second.username);
		}
	}
	return invitees;
}

bool Conversation::user_is_authenticated(const std::string& username) const
{
	if (!m_participants.count(username)) {
		throw InvalidUserException();
	}
	if (!m_participants.at(username).is_participant && !m_participants.at(username).authenticated) {
		throw InvalidUserException();
	}
	return m_participants.at(username).authentication_status == AuthenticationStatus::Authenticated;
}

bool Conversation::user_failed_authentication(const std::string& username) const
{
	if (!m_participants.count(username)) {
		throw InvalidUserException();
	}
	if (!m_participants.at(username).is_participant && !m_participants.at(username).authenticated) {
		throw InvalidUserException();
	}
	return m_participants.at(username).authentication_status == AuthenticationStatus::AuthenticationFailed;
}

PublicKey Conversation::user_public_key(const std::string& username) const
{
	if (!m_participants.count(username)) {
		throw InvalidUserException();
	}
	if (!m_participants.at(username).is_participant && !m_participants.at(username).authenticated) {
		throw InvalidUserException();
	}
	if (m_participants.at(username).authentication_status != AuthenticationStatus::Authenticated) {
		throw InvalidUserException();
	}
	return m_participants.at(username).long_term_public_key;
}

bool Conversation::user_is_votekicked(const std::string&victim, const std::string& participant) const
{
	if (!m_participants.count(victim)) {
		throw InvalidUserException();
	}
	if (!m_participants.at(victim).is_participant && !m_participants.at(victim).authenticated) {
		throw InvalidUserException();
	}
	if (!m_participants.count(participant)) {
		throw InvalidUserException();
	}
	if (!m_participants.at(participant).is_participant) {
		throw InvalidUserException();
	}
	return m_participants.at(participant).votekick_peers.count(victim) > 0;
}

bool Conversation::participant_in_chat(const std::string& username) const
{
	if (!m_participants.count(username)) {
		throw InvalidUserException();
	}
	if (!m_participants.at(username).is_participant) {
		throw InvalidUserException();
	}
	return m_encrypted_chat.user_in_chat(username);
}

std::string Conversation::invitee_inviter(const std::string& username) const
{
	if (!m_participants.count(username)) {
		throw InvalidUserException();
	}
	if (m_participants.at(username).is_participant || !m_participants.at(username).authenticated) {
		throw InvalidUserException();
	}
	return m_participants.at(username).inviter;
}

bool Conversation::in_chat() const
{
	return m_encrypted_chat.user_in_chat(m_room->username());
}

bool Conversation::is_invite() const
{
	assert(m_participants.count(m_room->username()));
	assert(m_participants.at(m_room->username()).is_participant || m_participants.at(m_room->username()).authenticated);
	return !m_participants.at(m_room->username()).is_participant;
}



void Conversation::leave(bool detach)
{
	if (!m_participants.count(m_room->username())) {
		return;
	}
	
	if (detach) {
		m_interface = nullptr;
	}
	
	LeaveMessage message;
	send_message(message.encode());
}

void Conversation::invite(const std::string& username, const PublicKey& long_term_public_key)
{
	if (!m_participants.count(m_room->username())) {
		return;
	}
	if (!m_participants.at(m_room->username()).is_participant) {
		return;
	}
	if (m_participants.count(username)) {
		return;
	}
	
	InviteMessage message;
	message.username = username;
	message.long_term_public_key = long_term_public_key;
	send_message(message.encode());
}

void Conversation::join()
{
	if (!m_participants.count(m_room->username())) {
		return;
	}
	if (m_participants.at(m_room->username()).is_participant) {
		return;
	}
	if (!m_participants.at(m_room->username()).authenticated) {
		return;
	}
	
	JoinMessage message;
	send_message(message.encode());
}

void Conversation::votekick(const std::string& username, bool kick)
{
	if (!m_participants.count(m_room->username())) {
		return;
	}
	if (!m_participants.count(username)) {
		return;
	}
	
	Participant& participant = m_participants[username];
	if (participant.votekick_in_flight != kick) {
		participant.votekick_in_flight = kick;
		if (m_participants.at(m_room->username()).is_participant) {
			VotekickMessage message;
			message.victim = username;
			message.kick = kick;
			send_message(message.encode());
		}
	}
}

void Conversation::send_chat(const std::string& message)
{
	m_encrypted_chat.send_message(message);
}



void Conversation::message_received(const std::string& sender, const ConversationMessage& conversation_message)
{
#ifndef NDEBUG
	assert(conversation_message.verify());
	if (m_participants.count(sender)) {
		assert(conversation_message.conversation_public_key == m_participants.at(sender).conversation_public_key);
	} else {
		assert(conversation_message.type == Message::Type::InviteAcceptance);
		InviteAcceptanceMessage invite_acceptance_message;
		try {
			invite_acceptance_message = InviteAcceptanceMessage::decode(conversation_message);
		} catch(MessageFormatException) {
			assert(false);
		}
		assert(m_participants.count(invite_acceptance_message.inviter_username));
		assert(invite_acceptance_message.inviter_conversation_public_key == m_participants.at(invite_acceptance_message.inviter_username).conversation_public_key);
	}
#endif
	
	hash_message(sender, conversation_message);
	
	if (conversation_message.type == Message::Type::Invite) {
		InviteMessage message;
		try {
			message = InviteMessage::decode(conversation_message);
		} catch(MessageFormatException) {
			return;
		}
		
		if (!m_participants.count(sender)) {
			return;
		}
		
		if (m_participants.count(message.username)) {
			return;
		}
		
		if (
			   m_unconfirmed_invites.count(message.username)
			&& m_unconfirmed_invites.at(message.username).count(message.long_term_public_key)
		) {
			return;
		}
		
		if (m_participants.at(sender).invitees.count(message.username)) {
			PublicKey old_public_key = m_participants.at(sender).invitees.at(message.username);
			assert(m_unconfirmed_invites.count(message.username));
			assert(m_unconfirmed_invites.at(message.username).count(old_public_key));
			assert(m_unconfirmed_invites.at(message.username).at(old_public_key).inviter == sender);
			m_unconfirmed_invites[message.username].erase(old_public_key);
		}
		
		UnconfirmedInvite invite;
		invite.inviter = sender;
		invite.username = message.username;
		invite.long_term_public_key = message.long_term_public_key;
		
		m_unconfirmed_invites[message.username][message.long_term_public_key] = std::move(invite);
		
		m_participants[sender].invitees[message.username] = message.long_term_public_key;
		
		Event consistency_check_event;
		consistency_check_event.type = Message::Type::ConsistencyCheck;
		consistency_check_event.consistency_check.conversation_status_hash = m_conversation_status_hash;
		for (const auto& i : m_participants) {
			consistency_check_event.remaining_users.insert(i.second.username);
			set_user_conversation_status_timer(i.second.username);
		}
		declare_event(std::move(consistency_check_event));
		
		if (m_participants.count(m_room->username())) {
			ConsistencyCheckMessage consistency_check_message;
			consistency_check_message.conversation_status_hash = m_conversation_status_hash;
			send_message(consistency_check_message.encode());
			set_conversation_status_timer();
		}
		
		UnsignedConversationMessage reply = conversation_status(message.username, message.long_term_public_key);
		
		Event reply_event;
		reply_event.type = Message::Type::ConversationStatus;
		reply_event.conversation_status.invitee_username = message.username;
		reply_event.conversation_status.invitee_long_term_public_key = message.long_term_public_key;
		reply_event.conversation_status.status_message_hash = crypto::hash(reply.payload);
		reply_event.remaining_users.insert(sender);
		declare_event(std::move(reply_event));
		
		if (sender == m_room->username()) {
			send_message(reply);
		}
	} else if (conversation_message.type == Message::Type::ConversationStatus) {
		ConversationStatusMessage message;
		try {
			message = ConversationStatusMessage::decode(conversation_message);
		} catch(MessageFormatException) {
			return;
		}
		
		Hash status_message_hash = crypto::hash(conversation_message.payload);
		
		auto first_event = first_user_event(sender);
		if (!(
			   first_event
			&& first_event->type == Message::Type::ConversationStatus
			&& first_event->conversation_status.invitee_username == message.invitee_username
			&& first_event->conversation_status.invitee_long_term_public_key == message.invitee_long_term_public_key
			&& first_event->conversation_status.status_message_hash == status_message_hash
		)) {
			remove_user(sender);
			return;
		}
		
		Event event;
		event.type = Message::Type::ConversationConfirmation;
		event.conversation_status.invitee_username = message.invitee_username;
		event.conversation_status.invitee_long_term_public_key = message.invitee_long_term_public_key;
		event.conversation_status.status_message_hash = status_message_hash;
		for (const auto& i : m_participants) {
			event.remaining_users.insert(i.second.username);
		}
		declare_event(std::move(event));
		
		if (am_confirmed()) {
			ConversationConfirmationMessage reply;
			reply.invitee_username = message.invitee_username;
			reply.invitee_long_term_public_key = message.invitee_long_term_public_key;
			reply.status_message_hash = status_message_hash;
			send_message(reply.encode());
		}
	} else if (conversation_message.type == Message::Type::ConversationConfirmation) {
		ConversationConfirmationMessage message;
		try {
			message = ConversationConfirmationMessage::decode(conversation_message);
		} catch(MessageFormatException) {
			return;
		}
		
		auto first_event = first_user_event(sender);
		if (!(
			   first_event
			&& first_event->type == Message::Type::ConversationConfirmation
			&& first_event->conversation_status.invitee_username == message.invitee_username
			&& first_event->conversation_status.invitee_long_term_public_key == message.invitee_long_term_public_key
			&& first_event->conversation_status.status_message_hash == message.status_message_hash
		)) {
			remove_user(sender);
			return;
		}
		
		if (m_unconfirmed_users.count(sender)) {
			assert(m_unconfirmed_invites.count(m_room->username()));
			assert(m_unconfirmed_invites.at(m_room->username()).count(m_room->public_key()));
			std::string inviter = m_unconfirmed_invites.at(m_room->username()).at(m_room->public_key()).inviter;
			assert(m_participants.count(inviter));
			
			if (
				   message.invitee_username == m_room->username()
				&& message.invitee_long_term_public_key == m_room->public_key()
				&& message.status_message_hash == m_status_message_hash
			) {
				m_unconfirmed_users.erase(sender);
				if (m_unconfirmed_users.empty()) {
					InviteAcceptanceMessage accept_message;
					accept_message.my_long_term_public_key = m_room->public_key();
					accept_message.inviter_username = inviter;
					accept_message.inviter_long_term_public_key = m_participants.at(inviter).long_term_public_key;
					accept_message.inviter_conversation_public_key = m_participants.at(inviter).conversation_public_key;
					send_message(accept_message.encode());
				}
			}
		}
	} else if (conversation_message.type == Message::Type::InviteAcceptance) {
		InviteAcceptanceMessage message;
		try {
			message = InviteAcceptanceMessage::decode(conversation_message);
		} catch(MessageFormatException) {
			return;
		}
		
		if (m_participants.count(sender)) {
			remove_user(sender);
			return;
		}
		
		if (!(
			   m_participants.count(message.inviter_username)
			&& m_participants.at(message.inviter_username).is_participant
			&& m_participants.at(message.inviter_username).long_term_public_key == message.inviter_long_term_public_key
			&& m_participants.at(message.inviter_username).conversation_public_key == message.inviter_conversation_public_key
			&& m_participants.at(message.inviter_username).invitees.count(sender)
			&& m_participants.at(message.inviter_username).invitees.at(sender) == message.my_long_term_public_key
		)) {
			return;
		}
		
		m_unconfirmed_invites.erase(sender);
		
		Participant participant;
		participant.is_participant = false;
		participant.username = sender;
		participant.long_term_public_key = message.my_long_term_public_key;
		participant.conversation_public_key = conversation_message.conversation_public_key;
		participant.inviter = message.inviter_username;
		participant.authenticated = false;
		participant.timeout_in_flight = false;
		participant.votekick_in_flight = false;
		m_participants[sender] = std::move(participant);
		if (sender == m_room->username()) {
			set_conversation_status_timer();
		}
		set_user_conversation_status_timer(sender);
		
		m_room->conversation_add_user(this, sender, conversation_message.conversation_public_key);
		
		if (am_confirmed()) {
			if (sender == m_room->username()) {
				m_participants[sender].authentication_status = AuthenticationStatus::Authenticated;
			} else {
				m_participants[sender].authentication_status = AuthenticationStatus::Authenticating;
				m_participants[sender].authentication_nonce = crypto::nonce_hash();
				
				AuthenticationRequestMessage authentication_request;
				authentication_request.username = sender;
				authentication_request.authentication_nonce = m_participants[sender].authentication_nonce;
				send_message(authentication_request.encode());
				
				AuthenticationMessage authentication;
				authentication.username = sender;
				authentication.authentication_confirmation = crypto::authentication_token(
					m_room->private_key(),
					m_conversation_private_key,
					m_participants.at(sender).long_term_public_key,
					m_participants.at(sender).conversation_public_key,
					m_participants.at(sender).authentication_nonce,
					m_room->username()
				);
				send_message(authentication.encode());
			}
		}
	} else if (conversation_message.type == Message::Type::AuthenticationRequest) {
		AuthenticationRequestMessage message;
		try {
			message = AuthenticationRequestMessage::decode(conversation_message);
		} catch(MessageFormatException) {
			return;
		}
		
		if (!m_participants.count(sender)) {
			return;
		}
		
		if (message.username == m_room->username()) {
			if (m_participants.at(sender).authentication_status == AuthenticationStatus::Unauthenticated) {
				m_participants[sender].authentication_status = AuthenticationStatus::Authenticating;
				m_participants[sender].authentication_nonce = message.authentication_nonce;
				
				AuthenticationMessage authentication;
				authentication.username = sender;
				authentication.authentication_confirmation = crypto::authentication_token(
					m_room->private_key(),
					m_conversation_private_key,
					m_participants.at(sender).long_term_public_key,
					m_participants.at(sender).conversation_public_key,
					m_participants.at(sender).authentication_nonce,
					m_room->username()
				);
				send_message(authentication.encode());
			}
		}
	} else if (conversation_message.type == Message::Type::Authentication) {
		AuthenticationMessage message;
		try {
			message = AuthenticationMessage::decode(conversation_message);
		} catch(MessageFormatException) {
			return;
		}
		
		if (!m_participants.count(sender)) {
			return;
		}
		
		if (message.username == m_room->username()) {
			if (m_participants.at(sender).authentication_status == AuthenticationStatus::Authenticating) {
				if (message.authentication_confirmation == crypto::authentication_token(
					m_room->private_key(),
					m_conversation_private_key,
					m_participants.at(sender).long_term_public_key,
					m_participants.at(sender).conversation_public_key,
					m_participants.at(sender).authentication_nonce,
					sender
				)) {
					m_participants[sender].authentication_status = AuthenticationStatus::Authenticated;
					
					if (
						   !m_participants.at(sender).is_participant
						&& !m_participants.at(sender).authenticated
						&& m_participants.at(sender).inviter == m_room->username()
					) {
						AuthenticateInviteMessage reply;
						reply.username = m_participants.at(sender).username;
						reply.long_term_public_key = m_participants.at(sender).long_term_public_key;
						reply.conversation_public_key = m_participants.at(sender).conversation_public_key;
						send_message(reply.encode());
					}
					
					if (m_participants[sender].authenticated) {
						if (interface()) interface()->user_authenticated(sender, m_participants.at(sender).long_term_public_key);
					}
				} else {
					m_participants[sender].authentication_status = AuthenticationStatus::AuthenticationFailed;
					
					if (m_participants[sender].authenticated) {
						if (interface()) interface()->user_authentication_failed(sender);
					}
				}
			}
		}
	} else if (conversation_message.type == Message::Type::AuthenticateInvite) {
		AuthenticateInviteMessage message;
		try {
			message = AuthenticateInviteMessage::decode(conversation_message);
		} catch(MessageFormatException) {
			return;
		}
		
		if (!m_participants.count(sender)) {
			return;
		}
		
		if (!m_participants.count(message.username)) {
			return;
		}
		
		if (!(
			   m_participants.at(sender).is_participant
			&& !m_participants.at(message.username).is_participant
			&& !m_participants.at(message.username).authenticated
			&& m_participants.at(message.username).inviter == sender
			&& m_participants.at(message.username).long_term_public_key == message.long_term_public_key
			&& m_participants.at(message.username).conversation_public_key == message.conversation_public_key
		)) {
			return;
		}
		
		m_participants[message.username].authenticated = true;
		
		if (interface()) interface()->user_invited(sender, message.username);
		
		if (message.username == m_room->username()) {
			ConversationInterface* interface = m_room->interface()->invited_to_conversation(this, sender);
			set_interface(interface);
		}
	} else if (conversation_message.type == Message::Type::CancelInvite) {
		CancelInviteMessage message;
		try {
			message = CancelInviteMessage::decode(conversation_message);
		} catch(MessageFormatException) {
			return;
		}
		
		if (!(
			   m_participants.count(sender)
			&& m_participants.at(sender).invitees.count(message.username)
			&& m_participants.at(sender).invitees.at(message.username) == message.long_term_public_key
		)) {
			return;
		}
		
		remove_invite(sender, message.username);
	} else if (conversation_message.type == Message::Type::Join) {
		JoinMessage message;
		try {
			message = JoinMessage::decode(conversation_message);
		} catch(MessageFormatException) {
			return;
		}
		
		if (!m_participants.count(sender)) {
			return;
		}
		if (m_participants.at(sender).is_participant) {
			return;
		}
		if (!m_participants.at(sender).authenticated) {
			return;
		}
		
		assert(m_participants.count(m_participants.at(sender).inviter));
		assert(m_participants.at(m_participants.at(sender).inviter).invitees.count(sender));
		m_participants[m_participants.at(sender).inviter].invitees.erase(sender);
		
		m_participants[sender].is_participant = true;
		m_participants[sender].inviter.clear();
		
		m_encrypted_chat.add_user(sender, m_participants.at(sender).long_term_public_key);
		
		bool self_joined = (sender == m_room->username());
		
		if (interface()) interface()->user_joined(sender);
		
		if (self_joined) {
			if (interface()) interface()->joined();
		}
	} else if (conversation_message.type == Message::Type::Leave) {
		LeaveMessage message;
		try {
			message = LeaveMessage::decode(conversation_message);
		} catch(MessageFormatException) {
			return;
		}
		
		if (!m_participants.count(sender)) {
			return;
		}
		
		remove_user(sender);
	} else if (conversation_message.type == Message::Type::ConsistencyStatus) {
		ConsistencyStatusMessage message;
		try {
			message = ConsistencyStatusMessage::decode(conversation_message);
		} catch(MessageFormatException) {
			return;
		}
		
		if (!m_participants.count(sender)) {
			return;
		}
		
		Event event;
		event.type = Message::Type::ConsistencyCheck;
		event.consistency_check.conversation_status_hash = m_conversation_status_hash;
		event.remaining_users.insert(sender);
		declare_event(std::move(event));
		set_user_conversation_status_timer(sender);
		
		if (sender == m_room->username()) {
			ConsistencyCheckMessage message;
			message.conversation_status_hash = m_conversation_status_hash;
			send_message(message.encode());
		}
	} else if (conversation_message.type == Message::Type::ConsistencyCheck) {
		ConsistencyCheckMessage message;
		try {
			message = ConsistencyCheckMessage::decode(conversation_message);
		} catch(MessageFormatException) {
			return;
		}
		
		if (!m_participants.count(sender)) {
			return;
		}
		
		auto first_event = first_user_event(sender);
		if (!(
			   first_event
			&& first_event->type == Message::Type::ConsistencyCheck
			&& first_event->consistency_check.conversation_status_hash == message.conversation_status_hash
		)) {
			remove_user(sender);
			return;
		}
	} else if (conversation_message.type == Message::Type::Timeout) {
		TimeoutMessage message;
		try {
			message = TimeoutMessage::decode(conversation_message);
		} catch(MessageFormatException) {
			return;
		}
		
		if (!(
			   m_participants.count(sender)
			&& m_participants.at(sender).is_participant
			&& m_participants.count(message.victim)
			&& sender != message.victim
		)) {
			return;
		}
		
		if (message.timeout) {
			if (m_participants[sender].timeout_peers.insert(message.victim).second) {
				try_split(false);
			}
		} else {
			m_participants[sender].timeout_peers.erase(message.victim);
		}
	} else if (conversation_message.type == Message::Type::Votekick) {
		VotekickMessage message;
		try {
			message = VotekickMessage::decode(conversation_message);
		} catch(MessageFormatException) {
			return;
		}
		
		if (!(
			   m_participants.count(sender)
			&& m_participants.at(sender).is_participant
			&& m_participants.count(message.victim)
			&& sender != message.victim
		)) {
			return;
		}
		
		if (message.kick) {
			if (m_participants[sender].votekick_peers.insert(message.victim).second) {
				if (interface()) interface()->votekick_registered(sender, message.victim, message.kick);
				
				try_split(true);
			}
		} else {
			if (m_participants[sender].votekick_peers.erase(message.victim) > 0) {
				if (interface()) interface()->votekick_registered(sender, message.victim, message.kick);
			}
		}
	} else if (conversation_message.type == Message::Type::KeyExchangePublicKey) {
		KeyExchangePublicKeyMessage message;
		try {
			message = KeyExchangePublicKeyMessage::decode(conversation_message);
		} catch(MessageFormatException) {
			return;
		}
		
		if (!m_participants.count(sender)) {
			return;
		}
		
		auto first_event = first_user_event(sender);
		if (!(
			   first_event
			&& first_event->type == Message::Type::KeyExchangePublicKey
			&& first_event->key_event.key_id == message.key_id
		)) {
			remove_user(sender);
			return;
		}
		
		m_encrypted_chat.user_public_key(sender, message.key_id, message.public_key);
	} else if (conversation_message.type == Message::Type::KeyExchangeSecretShare) {
		KeyExchangeSecretShareMessage message;
		try {
			message = KeyExchangeSecretShareMessage::decode(conversation_message);
		} catch(MessageFormatException) {
			return;
		}
		
		if (!m_participants.count(sender)) {
			return;
		}
		
		auto first_event = first_user_event(sender);
		if (!(
			   first_event
			&& first_event->type == Message::Type::KeyExchangeSecretShare
			&& first_event->key_event.key_id == message.key_id
		)) {
			remove_user(sender);
			return;
		}
		
		if (!m_encrypted_chat.have_key_exchange(message.key_id)) {
			return;
		}
		
		m_encrypted_chat.user_secret_share(sender, message.key_id, message.group_hash, message.secret_share);
	} else if (conversation_message.type == Message::Type::KeyExchangeAcceptance) {
		KeyExchangeAcceptanceMessage message;
		try {
			message = KeyExchangeAcceptanceMessage::decode(conversation_message);
		} catch(MessageFormatException) {
			return;
		}
		
		if (!m_participants.count(sender)) {
			return;
		}
		
		auto first_event = first_user_event(sender);
		if (!(
			   first_event
			&& first_event->type == Message::Type::KeyExchangeAcceptance
			&& first_event->key_event.key_id == message.key_id
		)) {
			remove_user(sender);
			return;
		}
		
		if (!m_encrypted_chat.have_key_exchange(message.key_id)) {
			return;
		}
		
		m_encrypted_chat.user_key_hash(sender, message.key_id, message.key_hash);
	} else if (conversation_message.type == Message::Type::KeyExchangeReveal) {
		KeyExchangeRevealMessage message;
		try {
			message = KeyExchangeRevealMessage::decode(conversation_message);
		} catch(MessageFormatException) {
			return;
		}
		
		if (!m_participants.count(sender)) {
			return;
		}
		
		auto first_event = first_user_event(sender);
		if (!(
			   first_event
			&& first_event->type == Message::Type::KeyExchangeReveal
			&& first_event->key_event.key_id == message.key_id
		)) {
			remove_user(sender);
			return;
		}
		
		if (!m_encrypted_chat.have_key_exchange(message.key_id)) {
			return;
		}
		
		m_encrypted_chat.user_private_key(sender, message.key_id, message.private_key);
	} else if (conversation_message.type == Message::Type::KeyActivation) {
		KeyActivationMessage message;
		try {
			message = KeyActivationMessage::decode(conversation_message);
		} catch(MessageFormatException) {
			return;
		}
		
		if (!m_participants.count(sender)) {
			return;
		}
		
		auto first_event = first_user_event(sender);
		if (!(
			   first_event
			&& first_event->type == Message::Type::KeyActivation
			&& first_event->key_event.key_id == message.key_id
		)) {
			remove_user(sender);
			return;
		}
		
		if (m_encrypted_chat.have_session(message.key_id)) {
			m_encrypted_chat.user_activation(sender, message.key_id);
		}
	} else if (conversation_message.type == Message::Type::KeyRatchet) {
		KeyRatchetMessage message;
		try {
			message = KeyRatchetMessage::decode(conversation_message);
		} catch(MessageFormatException) {
			return;
		}
		
		if (m_participants.count(sender) && m_participants.at(sender).is_participant) {
			m_encrypted_chat.replace_session(message.key_id);
		}
	} else if (conversation_message.type == Message::Type::Chat) {
		ChatMessage message;
		try {
			message = ChatMessage::decode(conversation_message);
		} catch(MessageFormatException) {
			return;
		}
		
		m_encrypted_chat.decrypt_message(sender, message);
	}
}

void Conversation::user_left(const std::string& username)
{
	if (!m_participants.count(username) && !m_unconfirmed_invites.count(username)) {
		return;
	}
	
	hash_payload(username, 0, "left");
	
	if (m_participants.count(username)) {
		assert(!m_unconfirmed_invites.count(username));
		remove_user(username);
	} else {
		assert(m_unconfirmed_invites.count(username));
		
		while (!m_unconfirmed_invites.at(username).empty()) {
			auto i = m_unconfirmed_invites.at(username).begin();
			remove_invite(i->second.inviter, i->second.username);
		}
		m_unconfirmed_invites.erase(username);
	}
}



std::map<std::string, PublicKey> Conversation::conversation_users() const
{
	std::map<std::string, PublicKey> result;
	for (const auto& i : m_participants) {
		result[i.second.username] = i.second.conversation_public_key;
	}
	return result;
}

bool Conversation::am_involved() const
{
	return m_participants.count(m_room->username()) || m_unconfirmed_invites.count(m_room->username());
}

bool Conversation::am_confirmed() const
{
	return m_participants.count(m_room->username());
}

bool Conversation::am_authenticated() const
{
	return m_participants.count(m_room->username()) && 
		(m_participants.at(m_room->username()).is_participant || m_participants.at(m_room->username()).authenticated);
}

bool Conversation::am_participant() const
{
	return m_participants.count(m_room->username()) && m_participants.at(m_room->username()).is_participant;
}

bool Conversation::am_chatting() const
{
	return m_encrypted_chat.in_chat();
}



void Conversation::send_message(const Message& message)
{
	m_room->send_message(message);
}

void Conversation::send_message(const UnsignedConversationMessage& conversation_message)
{
	send_message(ConversationMessage::sign(conversation_message, m_conversation_private_key));
}

void Conversation::add_key_exchange_event(Message::Type type, const Hash& key_id, const std::set<std::string>& usernames)
{
	Event event;
	event.type = type;
	event.remaining_users = usernames;
	event.key_event.key_id = key_id;
	declare_event(std::move(event));
}

void Conversation::remove_user(const std::string& username)
{
	std::set<std::string> usernames;
	usernames.insert(username);
	remove_users(usernames);
}

void Conversation::remove_users(const std::set<std::string>& usernames)
{
	for (const std::string& username : usernames) {
		if (!m_participants.count(username)) {
			continue;
		}
		
		if (m_participants.at(username).is_participant) {
			while (!m_participants.at(username).invitees.empty()) {
				auto i = m_participants.at(username).invitees.begin();
				remove_invite(username, i->first);
			}
			
			do_remove_user(username);
		} else {
			remove_invite(m_participants.at(username).inviter, username);
		}
	}
	
	m_encrypted_chat.remove_users(usernames);
}



void Conversation::hash_message(const std::string& sender, const UnsignedConversationMessage& message)
{
	hash_payload(sender, uint8_t(message.type), message.payload);
}

void Conversation::hash_payload(const std::string& sender, uint8_t type, const std::string& message)
{
	PublicKey zero;
	memset(zero.buffer, 0, sizeof(zero.buffer));
	
	std::string buffer = conversation_status(std::string(), zero).payload;
	buffer += sender;
	buffer += type;
	buffer += message;
	m_conversation_status_hash = crypto::hash(buffer);
}

void Conversation::declare_event(Event&& event)
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

void Conversation::remove_invite(std::string inviter, std::string username)
{
	assert(m_participants.count(inviter));
	assert(m_participants.at(inviter).is_participant);
	assert(m_participants.at(inviter).invitees.count(username));
	
	PublicKey long_term_public_key = m_participants.at(inviter).invitees.at(username);
	
	if (m_participants.count(username)) {
		bool authenticated = m_participants.at(username).authenticated;
		
		do_remove_user(username);
		
		if (authenticated) {
			if (interface()) interface()->invitation_cancelled(inviter, username);
		}
	} else {
		m_participants[inviter].invitees.erase(username);
		
		assert(m_unconfirmed_invites.count(username));
		assert(m_unconfirmed_invites.at(username).count(long_term_public_key));
		m_unconfirmed_invites[username].erase(long_term_public_key);
		if (m_unconfirmed_invites.at(username).empty()) {
			m_unconfirmed_invites.erase(username);
		}
	}
}

void Conversation::do_remove_user(const std::string& username)
{
	assert(m_participants.count(username));
	assert(m_participants.at(username).invitees.empty());
	
	if (username == m_room->username()) {
		if (m_participants.at(username).is_participant || m_participants.at(username).authenticated) {
			if (interface()) interface()->left();
		}
		m_interface = nullptr;
	}
	
	while (!m_participants[username].events.empty()) {
		auto it = m_participants[username].events.front();
		m_participants[username].events.pop_front();
		
		assert(it->remaining_users.count(username));
		it->remaining_users.erase(username);
		if (it->remaining_users.empty()) {
			m_events.erase(it);
		}
	}
	
	if (!m_participants.at(username).is_participant) {
		assert(m_participants.count(m_participants.at(username).inviter));
		assert(m_participants.at(m_participants.at(username).inviter).invitees.count(username));
		m_participants[m_participants.at(username).inviter].invitees.erase(username);
	}
	
	for (auto& p : m_participants) {
		p.second.timeout_peers.erase(username);
		p.second.votekick_peers.erase(username);
	}
	
	PublicKey conversation_public_key = m_participants.at(username).conversation_public_key;
	bool participant = m_participants.at(username).is_participant;
	
	m_participants.erase(username);
	
	m_room->conversation_remove_user(this, username, conversation_public_key);
	
	if (participant) {
		if (interface()) interface()->user_left(username);
	}
}

void Conversation::check_timeout(const std::string& username)
{
	assert(m_participants.count(username));
	
	Participant& participant = m_participants[username];
	
	bool event_timeout = (!participant.events.empty() && participant.events.front()->timeout);
	bool conversation_status_timeout = !participant.conversation_status_timer.active();
	
	bool want_timeout = event_timeout || conversation_status_timeout;
	if (participant.timeout_in_flight != want_timeout) {
		participant.timeout_in_flight = want_timeout;
		if (am_participant()) {
			TimeoutMessage message;
			message.victim = username;
			message.timeout = want_timeout;
			send_message(message.encode());
		}
	}
}

void Conversation::set_conversation_status_timer()
{
	m_conversation_status_timer = Timer(m_room->interface(), c_conversation_status_frequency, [this] {
		ConsistencyStatusMessage message;
		send_message(message.encode());
		set_conversation_status_timer();
	});
}

void Conversation::set_user_conversation_status_timer(const std::string& username)
{
	assert(m_participants.count(username));
	m_participants[username].conversation_status_timer = Timer(m_room->interface(), c_conversation_status_frequency + c_event_timeout, [username, this] {
		check_timeout(username);
	});
	check_timeout(username);
}

void Conversation::try_split(bool because_votekick)
{
	/*
	 * A split check has two parts.
	 * First, the participants perform a symmetric split operation among themselves.
	 * Second, any confirmed invites who are kicked by all participants are kicked asymmetrically.
	 */
	
	std::map<std::string, const std::set<std::string>* > graph;
	for (const auto& i : m_participants) {
		if (i.second.is_participant) {
			const std::set<std::string>* victims;
			if (because_votekick) {
				victims = &i.second.votekick_peers;
			} else {
				victims = &i.second.timeout_peers;
			}
			
			graph[i.second.username] = victims;
		}
	}
	
	std::vector<std::set<std::string>> partition = compute_conversation_partition(graph);
	if (partition.size() > 1) {
		/*
		 * A split has occurred. Find out which side we're in.
		 *
		 * If we are a participant, we follow the part containing ourselves.
		 * If we are an invitee, we follow the part containing our inviter.
		 */
		std::string anchor_username;
		if (m_participants.count(m_room->username()) && m_participants.at(m_room->username()).is_participant) {
			anchor_username = m_room->username();
		} else if (m_participants.count(m_room->username())) {
			anchor_username = m_participants.at(m_room->username()).inviter;
		} else {
			assert(m_unconfirmed_invites.count(m_room->username()));
			assert(m_unconfirmed_invites.at(m_room->username()).count(m_room->public_key()));
			anchor_username = m_unconfirmed_invites.at(m_room->username()).at(m_room->public_key()).inviter;
		}
		
		std::set<std::string> our_part;
		for (const std::set<std::string>& part : partition) {
			if (part.count(anchor_username)) {
				our_part = part;
				break;
			}
		}
		assert(our_part.count(anchor_username));
		
		std::set<std::string> victims;
		for (const auto& i : m_participants) {
			if (i.second.is_participant && our_part.count(i.second.username) == 0) {
				victims.insert(i.second.username);
			}
		}
		remove_users(victims);
	}
	
	std::set<std::string> victims;
	for (const auto& i : m_participants) {
		if (i.second.is_participant) {
			continue;
		}
		
		bool do_kick = true;
		for (const auto& j : m_participants) {
			if (!j.second.is_participant) {
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




UnsignedConversationMessage Conversation::conversation_status(const std::string& invitee_username, const PublicKey& invitee_long_term_public_key) const
{
	ConversationStatusMessage result;
	result.invitee_username = invitee_username;
	result.invitee_long_term_public_key = invitee_long_term_public_key;
	
	result.conversation_status_hash = m_conversation_status_hash;
	result.latest_session_id = m_encrypted_chat.latest_session_id();
	
	for (const auto& i : m_participants) {
		if (i.second.is_participant) {
			ConversationStatusMessage::Participant participant;
			participant.username = i.second.username;
			participant.long_term_public_key = i.second.long_term_public_key;
			participant.conversation_public_key = i.second.conversation_public_key;
			participant.timeout_peers = i.second.timeout_peers;
			participant.votekick_peers = i.second.votekick_peers;
			result.participants.push_back(participant);
		} else {
			ConversationStatusMessage::ConfirmedInvite invite;
			invite.inviter = i.second.inviter;
			invite.username = i.second.username;
			invite.long_term_public_key = i.second.long_term_public_key;
			invite.conversation_public_key = i.second.conversation_public_key;
			invite.authenticated = i.second.authenticated;
			result.confirmed_invites.push_back(invite);
		}
	}
	
	for (const auto& i : m_unconfirmed_invites) {
		for (const auto& j : i.second) {
			ConversationStatusMessage::UnconfirmedInvite invite;
			invite.inviter = j.second.inviter;
			invite.username = j.second.username;
			invite.long_term_public_key = j.second.long_term_public_key;
			result.unconfirmed_invites.push_back(invite);
		}
	}
	
	result.key_exchanges = m_encrypted_chat.encode_key_exchanges();
	
	for (const Event& event : m_events) {
		if (event.type == Message::Type::ConversationStatus) {
			ConversationStatusEvent conversation_status_event;
			conversation_status_event.invitee_username = event.conversation_status.invitee_username;
			conversation_status_event.invitee_long_term_public_key = event.conversation_status.invitee_long_term_public_key;
			conversation_status_event.status_message_hash = event.conversation_status.status_message_hash;
			conversation_status_event.remaining_users = event.remaining_users;
			result.events.push_back(conversation_status_event.encode(result));
		} else if (event.type == Message::Type::ConversationConfirmation) {
			ConversationConfirmationEvent conversation_confirmation_event;
			conversation_confirmation_event.invitee_username = event.conversation_status.invitee_username;
			conversation_confirmation_event.invitee_long_term_public_key = event.conversation_status.invitee_long_term_public_key;
			conversation_confirmation_event.status_message_hash = event.conversation_status.status_message_hash;
			conversation_confirmation_event.remaining_users = event.remaining_users;
			result.events.push_back(conversation_confirmation_event.encode(result));
		} else if (event.type == Message::Type::ConsistencyCheck) {
			ConsistencyCheckEvent consistency_check_event;
			consistency_check_event.conversation_status_hash = event.consistency_check.conversation_status_hash;
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

Conversation::EventReference Conversation::first_user_event(const std::string& username)
{
	if (!m_participants.count(username)) {
		return EventReference();
	}
	Participant& participant = m_participants[username];
	if (participant.events.empty()) {
		return EventReference();
	}
	auto it = participant.events.front();
	participant.events.pop_front();
	
	assert(it->remaining_users.count(username));
	it->remaining_users.erase(username);
	
	check_timeout(username);
	
	return EventReference(&m_events, it);
}

} // namespace np1sec
