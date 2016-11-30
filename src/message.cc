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

#include "base64.h"
#include "message.h"

#include <cassert>
#include <climits>

namespace np1sec
{

const std::string c_np1sec_protocol_name(":o3np1sec0:");



template<typename T>
void encode_integer(MessageBuffer* buffer, T value)
{
	int bits_remaining = (sizeof(T) * CHAR_BIT);
	do {
		if (bits_remaining == 8) {
			buffer->add_byte((uint8_t)value);
			return;
		}
		
		uint8_t byte = (uint8_t)(value & 0x7f);
		value = value >> 7;
		bits_remaining -= 7;
		buffer->add_byte(value ? (byte | 0x80) : byte);
	} while(value);
}

template<typename T>
T decode_integer(MessageBuffer* buffer)
{
	int shift = 0;
	T result = 0;
	while (true) {
		uint8_t byte = buffer->remove_byte();
		int bits_remaining = (sizeof(T) * CHAR_BIT) - shift;
		if (bits_remaining == 8) {
			result |= ((T)byte << shift);
			return result;
		} else if (bits_remaining < 8) {
			if (byte >> bits_remaining) {
				throw MessageFormatException();
			}
			result |= ((T)byte << shift);
			return result;
		} else {
			result |= ((T)(byte & 0x7f) << shift);
			shift += 7;
			if (!(byte & 0x80)) {
				return result;
			}
		}
	}
}


void MessageBuffer::add_bit(bool bit)
{
	add_byte(bit ? 1 : 0);
}

void MessageBuffer::add_byte(uint8_t byte)
{
	push_back(byte);
}

void MessageBuffer::add_integer(uint64_t number)
{
	encode_integer<uint64_t>(this, number);
}

void MessageBuffer::add_bytes(const std::string& buffer)
{
	append(buffer);
}

void MessageBuffer::add_opaque(const std::string& buffer)
{
	add_integer(buffer.size());
	append(buffer);
}

void MessageBuffer::check_empty()
{
	if (!empty()) {
		throw MessageFormatException();
	}
}

bool MessageBuffer::remove_bit()
{
	return remove_byte() != 0;
}

uint8_t MessageBuffer::remove_byte()
{
	if (size() < 1) {
		throw MessageFormatException();
	}
	
	uint8_t result = byte(0);
	
	erase(0, 1);
	
	return result;
}

uint64_t MessageBuffer::remove_integer()
{
	return decode_integer<uint64_t>(this);
}

std::string MessageBuffer::remove_bytes(size_t size)
{
	if (this->size() < size) {
		throw MessageFormatException();
	}
	
	std::string result(*this, 0, size);
	
	erase(0, size);
	
	return result;
}

std::string MessageBuffer::remove_opaque()
{
	return remove_bytes(remove_integer());
}



std::string Message::encode() const
{
	MessageBuffer buffer;
	buffer.add_byte(uint8_t(type));
	buffer.add_bytes(payload);
	
	char* base64_buffer = new char[((buffer.size() + 3 - 1) / 3) * 4];
	size_t base64_size = base64_encode(base64_buffer, reinterpret_cast<const unsigned char*>(buffer.data()), buffer.size());
	std::string base64_encoded(base64_buffer, base64_size);
	delete[] base64_buffer;
	
	std::string result = c_np1sec_protocol_name;
	result.append(base64_encoded);
	return result;
}

Message Message::decode(const std::string& encoded)
{
	if (encoded.substr(0, c_np1sec_protocol_name.size()) != c_np1sec_protocol_name) {
		throw MessageFormatException();
	}
	std::string base64_payload = encoded.substr(c_np1sec_protocol_name.size());
	unsigned char* base64_buffer = new unsigned char[((base64_payload.size() + 4 - 1) / 4) * 3];
	size_t base64_size = base64_decode(base64_buffer, base64_payload.data(), base64_payload.size());
	std::string base64_decoded(reinterpret_cast<char *>(base64_buffer), base64_size);
	delete[] base64_buffer;
	// TODO: reject malformed base64 for strict compatibility
	
	MessageBuffer buffer(base64_decoded);
	Message message;
	message.type = Message::Type(buffer.remove_byte());
	message.payload = buffer;
	
	return message;
}

bool Message::is_conversation_message(Type type)
{
	return
		   type == Type::Invite
		|| type == Type::ConversationStatus
		|| type == Type::ConversationConfirmation
		|| type == Type::InviteAcceptance
		|| type == Type::AuthenticationRequest
		|| type == Type::Authentication
		|| type == Type::AuthenticateInvite
		|| type == Type::CancelInvite
		|| type == Type::Join
		|| type == Type::ConsistencyStatus
		|| type == Type::ConsistencyCheck
		|| type == Type::Timeout
		|| type == Type::Votekick
		|| type == Type::KeyExchangePublicKey
		|| type == Type::KeyExchangeSecretShare
		|| type == Type::KeyExchangeAcceptance
		|| type == Type::KeyExchangeReveal
		|| type == Type::KeyActivation
		|| type == Type::KeyRatchet
		|| type == Type::Chat
	;
}



Message ConversationMessage::sign(const UnsignedConversationMessage& message, const PrivateKey& key)
{
	std::string signed_body;
	signed_body.push_back(uint8_t(message.type));
	signed_body += message.payload;
	Signature signature = crypto::sign(std::move(signed_body), key);
	
	MessageBuffer buffer;
	buffer.add_public_key(key.public_key());
	buffer.add_signature(signature);
	buffer.add_bytes(message.payload);
	return Message(message.type, buffer);
}

ConversationMessage ConversationMessage::decode(const Message& encoded)
{
	MessageBuffer buffer(encoded.payload);
	
	ConversationMessage result;
	result.type = encoded.type;
	result.conversation_public_key = buffer.remove_public_key();
	result.signature = buffer.remove_signature();
	result.payload = buffer;
	return result;
}

bool ConversationMessage::verify() const
{
	std::string signed_body;
	signed_body.push_back(uint8_t(type));
	signed_body += payload;
	
	return crypto::verify(std::move(signed_body), signature, conversation_public_key);
}



template<class MessageType>
static MessageBuffer get_message_payload(const MessageType& message, Message::Type expected_type)
{
	if (message.type != expected_type) {
		throw MessageFormatException();
	}
	return MessageBuffer(message.payload);
}

static MessageBuffer encode_user_set(const ConversationStatusMessage& status, bool include_invites, const std::set<std::string>& users)
{
	MessageBuffer buffer;
	uint8_t byte = 0;
	int bits = 8;
	
	for (const ConversationStatusMessage::Participant& participant : status.participants) {
		bits--;
		if (users.count(participant.username)) {
			byte |= (1 << bits);
		}
		if (bits == 0) {
			buffer.add_byte(byte);
			byte = 0;
			bits = 8;
		}
	}
	
	if (include_invites) {
		for (const ConversationStatusMessage::ConfirmedInvite& invite : status.confirmed_invites) {
			bits--;
			if (users.count(invite.username)) {
				byte |= (1 << bits);
			}
			if (bits == 0) {
				buffer.add_byte(byte);
				byte = 0;
				bits = 8;
			}
		}
	}
	
	if (bits < 8) {
		buffer.add_byte(byte);
	}
	
	return buffer;
}

static std::set<std::string> decode_user_set(const ConversationStatusMessage& status, bool include_invites, const std::string& encoded)
{
	MessageBuffer buffer(encoded);
	std::set<std::string> output;
	uint8_t byte = 0;
	int bits = 0;
	
	for (const ConversationStatusMessage::Participant& participant : status.participants) {
		if (!bits) {
			byte = buffer.remove_byte();
			bits = 8;
		}
		bits--;
		if (byte & (1 << bits)) {
			output.insert(participant.username);
		}
	}
	
	if (include_invites) {
		for (const ConversationStatusMessage::ConfirmedInvite& invite : status.confirmed_invites) {
			if (!bits) {
				byte = buffer.remove_byte();
				bits = 8;
			}
			bits--;
			if (byte & (1 << bits)) {
				output.insert(invite.username);
			}
		}
	}
	
	return output;
}



Message QuitMessage::encode() const
{
	MessageBuffer buffer;
	buffer.add_hash(nonce);
	
	return Message(Message::Type::Quit, buffer);
}

QuitMessage QuitMessage::decode(const Message& encoded)
{
	MessageBuffer buffer(get_message_payload(encoded, Message::Type::Quit));
	
	QuitMessage result;
	result.nonce = buffer.remove_hash();
	buffer.check_empty();
	return result;
}

Message HelloMessage::encode() const
{
	MessageBuffer buffer;
	buffer.add_public_key(long_term_public_key);
	buffer.add_public_key(ephemeral_public_key);
	buffer.add_bit(reply);
	if (reply) {
		buffer.add_opaque(reply_to_username);
	}
	
	return Message(Message::Type::Hello, buffer);
}

HelloMessage HelloMessage::decode(const Message& encoded)
{
	MessageBuffer buffer(get_message_payload(encoded, Message::Type::Hello));
	
	HelloMessage result;
	result.long_term_public_key = buffer.remove_public_key();
	result.ephemeral_public_key = buffer.remove_public_key();
	result.reply = buffer.remove_bit();
	if (result.reply) {
		result.reply_to_username = buffer.remove_opaque();
	}
	buffer.check_empty();
	return result;
}

Message RoomAuthenticationRequestMessage::encode() const
{
	MessageBuffer buffer;
	buffer.add_opaque(username);
	buffer.add_hash(nonce);
	
	return Message(Message::Type::RoomAuthenticationRequest, buffer);
}

RoomAuthenticationRequestMessage RoomAuthenticationRequestMessage::decode(const Message& encoded)
{
	MessageBuffer buffer(get_message_payload(encoded, Message::Type::RoomAuthenticationRequest));
	
	RoomAuthenticationRequestMessage result;
	result.username = buffer.remove_opaque();
	result.nonce = buffer.remove_hash();
	buffer.check_empty();
	return result;
}

Message RoomAuthenticationMessage::encode() const
{
	MessageBuffer buffer;
	buffer.add_opaque(username);
	buffer.add_hash(authentication_confirmation);
	
	return Message(Message::Type::RoomAuthentication, buffer);
}

RoomAuthenticationMessage RoomAuthenticationMessage::decode(const Message& encoded)
{
	MessageBuffer buffer(get_message_payload(encoded, Message::Type::RoomAuthentication));
	
	RoomAuthenticationMessage result;
	result.username = buffer.remove_opaque();
	result.authentication_confirmation = buffer.remove_hash();
	buffer.check_empty();
	return result;
}

UnsignedConversationMessage InviteMessage::encode() const
{
	MessageBuffer buffer;
	buffer.add_opaque(username);
	buffer.add_public_key(long_term_public_key);
	
	return UnsignedConversationMessage(Message::Type::Invite, buffer);
}

InviteMessage InviteMessage::decode(const UnsignedConversationMessage& encoded)
{
	MessageBuffer buffer(get_message_payload(encoded, Message::Type::Invite));
	
	InviteMessage result;
	result.username = buffer.remove_opaque();
	result.long_term_public_key = buffer.remove_public_key();
	buffer.check_empty();
	return result;
}

UnsignedConversationMessage ConversationStatusMessage::encode() const
{
	MessageBuffer buffer;
	buffer.add_opaque(invitee_username);
	buffer.add_public_key(invitee_long_term_public_key);
	
	MessageBuffer participants_buffer;
	for (const Participant& participant : participants) {
		MessageBuffer participant_buffer;
		participant_buffer.add_opaque(participant.username);
		participant_buffer.add_public_key(participant.long_term_public_key);
		participant_buffer.add_public_key(participant.conversation_public_key);
		participants_buffer.add_opaque(participant_buffer);
	}
	buffer.add_opaque(participants_buffer);
	
	MessageBuffer confirmed_invites_buffer;
	for (const ConfirmedInvite& invite : confirmed_invites) {
		MessageBuffer invite_buffer;
		invite_buffer.add_opaque(invite.inviter);
		invite_buffer.add_opaque(invite.username);
		invite_buffer.add_public_key(invite.long_term_public_key);
		invite_buffer.add_public_key(invite.conversation_public_key);
		invite_buffer.add_bit(invite.authenticated);
		confirmed_invites_buffer.add_opaque(invite_buffer);
	}
	buffer.add_opaque(confirmed_invites_buffer);
	
	MessageBuffer unconfirmed_invites_buffer;
	for (const UnconfirmedInvite& invite : unconfirmed_invites) {
		MessageBuffer invite_buffer;
		invite_buffer.add_opaque(invite.inviter);
		invite_buffer.add_opaque(invite.username);
		invite_buffer.add_public_key(invite.long_term_public_key);
		unconfirmed_invites_buffer.add_opaque(invite_buffer);
	}
	buffer.add_opaque(unconfirmed_invites_buffer);
	
	MessageBuffer timeout_buffer;
	MessageBuffer votekick_buffer;
	for (const Participant& participant : participants) {
		timeout_buffer.add_opaque(encode_user_set(*this, true, participant.timeout_peers));
		votekick_buffer.add_opaque(encode_user_set(*this, true, participant.votekick_peers));
	}
	buffer.add_opaque(timeout_buffer);
	buffer.add_opaque(votekick_buffer);
	
	buffer.add_hash(conversation_status_hash);
	buffer.add_hash(latest_session_id);
	
	MessageBuffer key_exchange_buffer;
	for (const KeyExchangeState& exchange : key_exchanges) {
		key_exchange_buffer.add_hash(exchange.key_id);
		key_exchange_buffer.add_byte(uint8_t(exchange.state));
		key_exchange_buffer.add_opaque(exchange.payload);
	}
	buffer.add_opaque(key_exchange_buffer);
	
	MessageBuffer event_buffer;
	for (const ConversationEvent& event : events) {
		event_buffer.add_byte(uint8_t(event.type));
		event_buffer.add_opaque(event.payload);
	}
	buffer.add_opaque(event_buffer);
	
	return UnsignedConversationMessage(Message::Type::ConversationStatus, buffer);
}

ConversationStatusMessage ConversationStatusMessage::decode(const UnsignedConversationMessage& encoded)
{
	MessageBuffer buffer(get_message_payload(encoded, Message::Type::ConversationStatus));
	
	ConversationStatusMessage result;
	result.invitee_username = buffer.remove_opaque();
	result.invitee_long_term_public_key = buffer.remove_public_key();
	
	MessageBuffer participants_buffer = buffer.remove_opaque();
	while (!participants_buffer.empty()) {
		MessageBuffer participant_buffer = participants_buffer.remove_opaque();
		Participant participant;
		participant.username = participant_buffer.remove_opaque();
		participant.long_term_public_key = participant_buffer.remove_public_key();
		participant.conversation_public_key = participant_buffer.remove_public_key();
		participant_buffer.check_empty();
		result.participants.push_back(participant);
	}
	
	MessageBuffer confirmed_invites_buffer = buffer.remove_opaque();
	while (!confirmed_invites_buffer.empty()) {
		MessageBuffer invite_buffer = confirmed_invites_buffer.remove_opaque();
		ConfirmedInvite invite;
		invite.inviter = invite_buffer.remove_opaque();
		invite.username = invite_buffer.remove_opaque();
		invite.long_term_public_key = invite_buffer.remove_public_key();
		invite.conversation_public_key = invite_buffer.remove_public_key();
		invite.authenticated = invite_buffer.remove_bit();
		invite_buffer.check_empty();
		result.confirmed_invites.push_back(invite);
	}
	
	MessageBuffer unconfirmed_invites_buffer = buffer.remove_opaque();
	while (!unconfirmed_invites_buffer.empty()) {
		MessageBuffer invite_buffer = unconfirmed_invites_buffer.remove_opaque();
		UnconfirmedInvite invite;
		invite.inviter = invite_buffer.remove_opaque();
		invite.username = invite_buffer.remove_opaque();
		invite.long_term_public_key = invite_buffer.remove_public_key();
		invite_buffer.check_empty();
		result.unconfirmed_invites.push_back(invite);
	}
	
	MessageBuffer timeout_buffer = buffer.remove_opaque();
	MessageBuffer votekick_buffer = buffer.remove_opaque();
	for (Participant& participant : result.participants) {
		participant.timeout_peers = decode_user_set(result, true, timeout_buffer.remove_opaque());
		participant.votekick_peers = decode_user_set(result, true, votekick_buffer.remove_opaque());
	}
	
	result.conversation_status_hash = buffer.remove_hash();
	result.latest_session_id = buffer.remove_hash();
	
	MessageBuffer key_exchange_buffer = buffer.remove_opaque();
	while (!key_exchange_buffer.empty()) {
		KeyExchangeState exchange;
		exchange.key_id = key_exchange_buffer.remove_hash();
		exchange.state = KeyExchangeState::State(key_exchange_buffer.remove_byte());
		exchange.payload = key_exchange_buffer.remove_opaque();
		result.key_exchanges.push_back(std::move(exchange));
	}
	
	MessageBuffer event_buffer = buffer.remove_opaque();
	while (!event_buffer.empty()) {
		ConversationEvent event;
		event.type = Message::Type(event_buffer.remove_byte());
		event.payload = event_buffer.remove_opaque();
		result.events.push_back(std::move(event));
	}
	
	buffer.check_empty();
	return result;
}

UnsignedConversationMessage ConversationConfirmationMessage::encode() const
{
	MessageBuffer buffer;
	buffer.add_opaque(invitee_username);
	buffer.add_public_key(invitee_long_term_public_key);
	buffer.add_hash(status_message_hash);
	
	return UnsignedConversationMessage(Message::Type::ConversationConfirmation, buffer);
}

ConversationConfirmationMessage ConversationConfirmationMessage::decode(const UnsignedConversationMessage& encoded)
{
	MessageBuffer buffer(get_message_payload(encoded, Message::Type::ConversationConfirmation));
	
	ConversationConfirmationMessage result;
	result.invitee_username = buffer.remove_opaque();
	result.invitee_long_term_public_key = buffer.remove_public_key();
	result.status_message_hash = buffer.remove_hash();
	buffer.check_empty();
	return result;
}

UnsignedConversationMessage InviteAcceptanceMessage::encode() const
{
	MessageBuffer buffer;
	buffer.add_public_key(my_long_term_public_key);
	buffer.add_opaque(inviter_username);
	buffer.add_public_key(inviter_long_term_public_key);
	buffer.add_public_key(inviter_conversation_public_key);
	
	return UnsignedConversationMessage(Message::Type::InviteAcceptance, buffer);
}

InviteAcceptanceMessage InviteAcceptanceMessage::decode(const UnsignedConversationMessage& encoded)
{
	MessageBuffer buffer(get_message_payload(encoded, Message::Type::InviteAcceptance));
	
	InviteAcceptanceMessage result;
	result.my_long_term_public_key = buffer.remove_public_key();
	result.inviter_username = buffer.remove_opaque();
	result.inviter_long_term_public_key = buffer.remove_public_key();
	result.inviter_conversation_public_key = buffer.remove_public_key();
	buffer.check_empty();
	return result;
}

UnsignedConversationMessage AuthenticationRequestMessage::encode() const
{
	MessageBuffer buffer;
	buffer.add_opaque(username);
	buffer.add_hash(authentication_nonce);
	
	return UnsignedConversationMessage(Message::Type::AuthenticationRequest, buffer);
}

AuthenticationRequestMessage AuthenticationRequestMessage::decode(const UnsignedConversationMessage& encoded)
{
	MessageBuffer buffer(get_message_payload(encoded, Message::Type::AuthenticationRequest));
	
	AuthenticationRequestMessage result;
	result.username = buffer.remove_opaque();
	result.authentication_nonce = buffer.remove_hash();
	buffer.check_empty();
	return result;
}

UnsignedConversationMessage AuthenticationMessage::encode() const
{
	MessageBuffer buffer;
	buffer.add_opaque(username);
	buffer.add_hash(authentication_confirmation);
	
	return UnsignedConversationMessage(Message::Type::Authentication, buffer);
}

AuthenticationMessage AuthenticationMessage::decode(const UnsignedConversationMessage& encoded)
{
	MessageBuffer buffer(get_message_payload(encoded, Message::Type::Authentication));
	
	AuthenticationMessage result;
	result.username = buffer.remove_opaque();
	result.authentication_confirmation = buffer.remove_hash();
	buffer.check_empty();
	return result;
}

UnsignedConversationMessage AuthenticateInviteMessage::encode() const
{
	MessageBuffer buffer;
	buffer.add_opaque(username);
	buffer.add_public_key(long_term_public_key);
	buffer.add_public_key(conversation_public_key);
	
	return UnsignedConversationMessage(Message::Type::AuthenticateInvite, buffer);
}

AuthenticateInviteMessage AuthenticateInviteMessage::decode(const UnsignedConversationMessage& encoded)
{
	MessageBuffer buffer(get_message_payload(encoded, Message::Type::AuthenticateInvite));
	
	AuthenticateInviteMessage result;
	result.username = buffer.remove_opaque();
	result.long_term_public_key = buffer.remove_public_key();
	result.conversation_public_key = buffer.remove_public_key();
	buffer.check_empty();
	return result;
}

UnsignedConversationMessage CancelInviteMessage::encode() const
{
	MessageBuffer buffer;
	buffer.add_opaque(username);
	buffer.add_public_key(long_term_public_key);
	
	return UnsignedConversationMessage(Message::Type::CancelInvite, buffer);
}

CancelInviteMessage CancelInviteMessage::decode(const UnsignedConversationMessage& encoded)
{
	MessageBuffer buffer(get_message_payload(encoded, Message::Type::CancelInvite));
	
	CancelInviteMessage result;
	result.username = buffer.remove_opaque();
	result.long_term_public_key = buffer.remove_public_key();
	buffer.check_empty();
	return result;
}

UnsignedConversationMessage JoinMessage::encode() const
{
	MessageBuffer buffer;
	
	return UnsignedConversationMessage(Message::Type::Join, buffer);
}

JoinMessage JoinMessage::decode(const UnsignedConversationMessage& encoded)
{
	MessageBuffer buffer(get_message_payload(encoded, Message::Type::Join));
	
	JoinMessage result;
	buffer.check_empty();
	return result;
}

UnsignedConversationMessage ConsistencyStatusMessage::encode() const
{
	MessageBuffer buffer;
	
	return UnsignedConversationMessage(Message::Type::ConsistencyStatus, buffer);
}

ConsistencyStatusMessage ConsistencyStatusMessage::decode(const UnsignedConversationMessage& encoded)
{
	MessageBuffer buffer(get_message_payload(encoded, Message::Type::ConsistencyStatus));
	
	ConsistencyStatusMessage result;
	buffer.check_empty();
	return result;
}

UnsignedConversationMessage ConsistencyCheckMessage::encode() const
{
	MessageBuffer buffer;
	buffer.add_hash(conversation_status_hash);
	
	return UnsignedConversationMessage(Message::Type::ConsistencyCheck, buffer);
	
}

ConsistencyCheckMessage ConsistencyCheckMessage::decode(const UnsignedConversationMessage& encoded)
{
	MessageBuffer buffer(get_message_payload(encoded, Message::Type::ConsistencyCheck));
	
	ConsistencyCheckMessage result;
	result.conversation_status_hash = buffer.remove_hash();
	buffer.check_empty();
	return result;
}

UnsignedConversationMessage TimeoutMessage::encode() const
{
	MessageBuffer buffer;
	buffer.add_opaque(victim);
	buffer.add_bit(timeout);
	
	return UnsignedConversationMessage(Message::Type::Timeout, buffer);
}

TimeoutMessage TimeoutMessage::decode(const UnsignedConversationMessage& encoded)
{
	MessageBuffer buffer(get_message_payload(encoded, Message::Type::Timeout));
	
	TimeoutMessage result;
	result.victim = buffer.remove_opaque();
	result.timeout = buffer.remove_bit();
	buffer.check_empty();
	return result;
}

UnsignedConversationMessage VotekickMessage::encode() const
{
	MessageBuffer buffer;
	buffer.add_opaque(victim);
	buffer.add_bit(kick);
	
	return UnsignedConversationMessage(Message::Type::Votekick, buffer);
}

VotekickMessage VotekickMessage::decode(const UnsignedConversationMessage& encoded)
{
	MessageBuffer buffer(get_message_payload(encoded, Message::Type::Votekick));
	
	VotekickMessage result;
	result.victim = buffer.remove_opaque();
	result.kick = buffer.remove_bit();
	buffer.check_empty();
	return result;
}

UnsignedConversationMessage KeyExchangePublicKeyMessage::encode() const
{
	MessageBuffer buffer;
	buffer.add_hash(key_id);
	buffer.add_public_key(public_key);
	
	return UnsignedConversationMessage(Message::Type::KeyExchangePublicKey, buffer);
}

KeyExchangePublicKeyMessage KeyExchangePublicKeyMessage::decode(const UnsignedConversationMessage& encoded)
{
	MessageBuffer buffer(get_message_payload(encoded, Message::Type::KeyExchangePublicKey));
	
	KeyExchangePublicKeyMessage result;
	result.key_id = buffer.remove_hash();
	result.public_key = buffer.remove_public_key();
	buffer.check_empty();
	return result;
}

UnsignedConversationMessage KeyExchangeSecretShareMessage::encode() const
{
	MessageBuffer buffer;
	buffer.add_hash(key_id);
	buffer.add_hash(group_hash);
	buffer.add_hash(secret_share);
	
	return UnsignedConversationMessage(Message::Type::KeyExchangeSecretShare, buffer);
}

KeyExchangeSecretShareMessage KeyExchangeSecretShareMessage::decode(const UnsignedConversationMessage& encoded)
{
	MessageBuffer buffer(get_message_payload(encoded, Message::Type::KeyExchangeSecretShare));
	
	KeyExchangeSecretShareMessage result;
	result.key_id = buffer.remove_hash();
	result.group_hash = buffer.remove_hash();
	result.secret_share = buffer.remove_hash();
	buffer.check_empty();
	return result;
}

UnsignedConversationMessage KeyExchangeAcceptanceMessage::encode() const
{
	MessageBuffer buffer;
	buffer.add_hash(key_id);
	buffer.add_hash(key_hash);
	
	return UnsignedConversationMessage(Message::Type::KeyExchangeAcceptance, buffer);
}

KeyExchangeAcceptanceMessage KeyExchangeAcceptanceMessage::decode(const UnsignedConversationMessage& encoded)
{
	MessageBuffer buffer(get_message_payload(encoded, Message::Type::KeyExchangeAcceptance));
	
	KeyExchangeAcceptanceMessage result;
	result.key_id = buffer.remove_hash();
	result.key_hash = buffer.remove_hash();
	buffer.check_empty();
	return result;
}

UnsignedConversationMessage KeyExchangeRevealMessage::encode() const
{
	MessageBuffer buffer;
	buffer.add_hash(key_id);
	buffer.add_private_key(private_key);
	
	return UnsignedConversationMessage(Message::Type::KeyExchangeReveal, buffer);
}

KeyExchangeRevealMessage KeyExchangeRevealMessage::decode(const UnsignedConversationMessage& encoded)
{
	MessageBuffer buffer(get_message_payload(encoded, Message::Type::KeyExchangeReveal));
	
	KeyExchangeRevealMessage result;
	result.key_id = buffer.remove_hash();
	result.private_key = buffer.remove_private_key();
	buffer.check_empty();
	return result;
}

UnsignedConversationMessage KeyActivationMessage::encode() const
{
	MessageBuffer buffer;
	buffer.add_hash(key_id);
	
	return UnsignedConversationMessage(Message::Type::KeyActivation, buffer);
}

KeyActivationMessage KeyActivationMessage::decode(const UnsignedConversationMessage& encoded)
{
	MessageBuffer buffer(get_message_payload(encoded, Message::Type::KeyActivation));
	
	KeyActivationMessage result;
	result.key_id = buffer.remove_hash();
	buffer.check_empty();
	return result;
}

UnsignedConversationMessage KeyRatchetMessage::encode() const
{
	MessageBuffer buffer;
	buffer.add_hash(key_id);
	
	return UnsignedConversationMessage(Message::Type::KeyRatchet, buffer);
}

KeyRatchetMessage KeyRatchetMessage::decode(const UnsignedConversationMessage& encoded)
{
	MessageBuffer buffer(get_message_payload(encoded, Message::Type::KeyRatchet));
	
	KeyRatchetMessage result;
	result.key_id = buffer.remove_hash();
	buffer.check_empty();
	return result;
}



UnsignedConversationMessage ChatMessage::encode() const
{
	MessageBuffer buffer;
	buffer.add_hash(key_id);
	buffer.add_bytes(encrypted_payload);
	
	return UnsignedConversationMessage(Message::Type::Chat, buffer);
}

ChatMessage ChatMessage::decode(const UnsignedConversationMessage& encoded)
{
	MessageBuffer buffer(get_message_payload(encoded, Message::Type::Chat));
	
	ChatMessage result;
	result.key_id = buffer.remove_hash();
	result.encrypted_payload = buffer;
	return result;
}

std::string ChatMessage::decrypt(const SymmetricKey& symmetric_key) const
{
	return crypto::decrypt(encrypted_payload, symmetric_key);
}

ChatMessage ChatMessage::encrypt(std::string plaintext, const Hash& key_id, const SymmetricKey& symmetric_key)
{
	ChatMessage result;
	result.key_id = key_id;
	result.encrypted_payload = crypto::encrypt(plaintext, symmetric_key);
	return result;
}

std::string UnsignedChatMessage::signed_body() const
{
	MessageBuffer buffer;
	buffer.add_integer(message_id);
	buffer.add_bytes(message);
	return buffer;
}

std::string PlaintextChatMessage::sign(const UnsignedChatMessage& message, const PrivateKey& key)
{
	Signature signature = crypto::sign(message.signed_body(), key);
	
	MessageBuffer buffer;
	buffer.add_signature(signature);
	buffer.add_integer(message.message_id);
	buffer.add_bytes(message.message);
	return buffer;
}

PlaintextChatMessage PlaintextChatMessage::decode(const std::string& encoded)
{
	MessageBuffer buffer(encoded);
	
	PlaintextChatMessage result;
	result.signature = buffer.remove_signature();
	result.message_id = buffer.remove_integer();
	result.message = buffer;
	return result;
}

bool PlaintextChatMessage::verify(const PublicKey& key) const
{
	return crypto::verify(signed_body(), signature, key);
}



ConversationEvent ConversationStatusEvent::encode(const ConversationStatusMessage& status) const
{
	assert(remaining_users.size() == 1);
	const std::string& remaining_username = *remaining_users.begin();
	uint64_t index = -1;
	for (size_t i = 0; i < status.participants.size(); i++) {
		if (status.participants[i].username == remaining_username) {
			index = i;
			break;
		}
	}
	assert(index != (size_t)-1);
	
	MessageBuffer buffer;
	buffer.add_opaque(invitee_username);
	buffer.add_public_key(invitee_long_term_public_key);
	buffer.add_hash(status_message_hash);
	buffer.add_integer(index);
	
	return ConversationEvent(Message::Type::ConversationStatus, buffer);
}

ConversationStatusEvent ConversationStatusEvent::decode(const ConversationEvent& encoded, const ConversationStatusMessage& status)
{
	MessageBuffer buffer(get_message_payload(encoded, Message::Type::ConversationStatus));
	
	ConversationStatusEvent result;
	result.invitee_username = buffer.remove_opaque();
	result.invitee_long_term_public_key = buffer.remove_public_key();
	result.status_message_hash = buffer.remove_hash();
	uint64_t index = buffer.remove_integer();
	if (index >= status.participants.size()) {
		throw MessageFormatException();
	}
	result.remaining_users.insert(status.participants[index].username);
	buffer.check_empty();
	return result;
}

ConversationEvent ConversationConfirmationEvent::encode(const ConversationStatusMessage& status) const
{
	MessageBuffer buffer;
	buffer.add_opaque(invitee_username);
	buffer.add_public_key(invitee_long_term_public_key);
	buffer.add_hash(status_message_hash);
	buffer.add_opaque(encode_user_set(status, true, remaining_users));
	
	return ConversationEvent(Message::Type::ConversationConfirmation, buffer);
}

ConversationConfirmationEvent ConversationConfirmationEvent::decode(const ConversationEvent& encoded, const ConversationStatusMessage& status)
{
	MessageBuffer buffer(get_message_payload(encoded, Message::Type::ConversationConfirmation));
	
	ConversationConfirmationEvent result;
	result.invitee_username = buffer.remove_opaque();
	result.invitee_long_term_public_key = buffer.remove_public_key();
	result.status_message_hash = buffer.remove_hash();
	result.remaining_users = decode_user_set(status, true, buffer.remove_opaque());
	buffer.check_empty();
	return result;
}

ConversationEvent ConsistencyCheckEvent::encode(const ConversationStatusMessage& status) const
{
	MessageBuffer buffer;
	buffer.add_hash(conversation_status_hash);
	buffer.add_opaque(encode_user_set(status, true, remaining_users));
	
	return ConversationEvent(Message::Type::ConsistencyCheck, buffer);
}

ConsistencyCheckEvent ConsistencyCheckEvent::decode(const ConversationEvent& encoded, const ConversationStatusMessage& status)
{
	MessageBuffer buffer(get_message_payload(encoded, Message::Type::ConsistencyCheck));
	
	ConsistencyCheckEvent result;
	result.conversation_status_hash = buffer.remove_hash();
	result.remaining_users = decode_user_set(status, true, buffer.remove_opaque());
	buffer.check_empty();
	return result;
}

ConversationEvent KeyExchangeEvent::encode(const ConversationStatusMessage& status) const
{
	assert(
		   type == Message::Type::KeyExchangePublicKey
		|| type == Message::Type::KeyExchangeSecretShare
		|| type == Message::Type::KeyExchangeAcceptance
		|| type == Message::Type::KeyExchangeReveal
	);
	MessageBuffer buffer;
	buffer.add_hash(key_id);
	buffer.add_bit(cancelled);
	if (cancelled) {
		buffer.add_opaque(encode_user_set(status, false, remaining_users));
	}
	
	return ConversationEvent(type, buffer);
}

KeyExchangeEvent KeyExchangeEvent::decode(const ConversationEvent& encoded, const ConversationStatusMessage& status)
{
	if (!(
		   encoded.type == Message::Type::KeyExchangePublicKey
		|| encoded.type == Message::Type::KeyExchangeSecretShare
		|| encoded.type == Message::Type::KeyExchangeAcceptance
		|| encoded.type == Message::Type::KeyExchangeReveal
	)) {
		throw MessageFormatException();
	}
	MessageBuffer buffer(encoded.payload);
	
	KeyExchangeEvent result;
	result.type = encoded.type;
	result.key_id = buffer.remove_hash();
	result.cancelled = buffer.remove_bit();
	if (result.cancelled) {
		result.remaining_users = decode_user_set(status, false, buffer.remove_opaque());
	}
	buffer.check_empty();
	return result;
}

ConversationEvent KeyActivationEvent::encode(const ConversationStatusMessage& status) const
{
	MessageBuffer buffer;
	buffer.add_hash(key_id);
	buffer.add_opaque(encode_user_set(status, false, remaining_users));
	
	return ConversationEvent(Message::Type::KeyActivation, buffer);
}

KeyActivationEvent KeyActivationEvent::decode(const ConversationEvent& encoded, const ConversationStatusMessage& status)
{
	MessageBuffer buffer(get_message_payload(encoded, Message::Type::KeyActivation));
	
	KeyActivationEvent result;
	result.key_id = buffer.remove_hash();
	result.remaining_users = decode_user_set(status, false, buffer.remove_opaque());
	buffer.check_empty();
	return result;
}



void PublicKeyParticipant::encode_to(MessageBuffer* buffer) const
{
	buffer->add_opaque(username);
	buffer->add_public_key(long_term_public_key);
	buffer->add_bit(has_ephemeral_public_key);
	if (has_ephemeral_public_key) {
		buffer->add_public_key(ephemeral_public_key);
	}
}

PublicKeyParticipant PublicKeyParticipant::decode_from(MessageBuffer* buffer)
{
	PublicKeyParticipant result;
	result.username = buffer->remove_opaque();
	result.long_term_public_key = buffer->remove_public_key();
	result.has_ephemeral_public_key = buffer->remove_bit();
	if (result.has_ephemeral_public_key) {
		result.ephemeral_public_key = buffer->remove_public_key();
	}
	return result;
}

void SecretShareParticipant::encode_to(MessageBuffer* buffer) const
{
	buffer->add_opaque(username);
	buffer->add_public_key(long_term_public_key);
	buffer->add_public_key(ephemeral_public_key);
	buffer->add_bit(has_secret_share);
	if (has_secret_share) {
		buffer->add_hash(secret_share);
	}
}

SecretShareParticipant SecretShareParticipant::decode_from(MessageBuffer* buffer)
{
	SecretShareParticipant result;
	result.username = buffer->remove_opaque();
	result.long_term_public_key = buffer->remove_public_key();
	result.ephemeral_public_key = buffer->remove_public_key();
	result.has_secret_share = buffer->remove_bit();
	if (result.has_secret_share) {
		result.secret_share = buffer->remove_hash();
	}
	return result;
}

void AcceptanceParticipant::encode_to(MessageBuffer* buffer) const
{
	buffer->add_opaque(username);
	buffer->add_public_key(long_term_public_key);
	buffer->add_public_key(ephemeral_public_key);
	buffer->add_hash(secret_share);
	buffer->add_bit(has_key_hash);
	if (has_key_hash) {
		buffer->add_hash(key_hash);
	}
}

AcceptanceParticipant AcceptanceParticipant::decode_from(MessageBuffer* buffer)
{
	AcceptanceParticipant result;
	result.username = buffer->remove_opaque();
	result.long_term_public_key = buffer->remove_public_key();
	result.ephemeral_public_key = buffer->remove_public_key();
	result.secret_share = buffer->remove_hash();
	result.has_key_hash = buffer->remove_bit();
	if (result.has_key_hash) {
		result.key_hash = buffer->remove_hash();
	}
	return result;
}

void RevealParticipant::encode_to(MessageBuffer* buffer) const
{
	buffer->add_opaque(username);
	buffer->add_public_key(long_term_public_key);
	buffer->add_public_key(ephemeral_public_key);
	buffer->add_hash(secret_share);
	buffer->add_hash(key_hash);
	buffer->add_bit(has_ephemeral_private_key);
	if (has_ephemeral_private_key) {
		buffer->add_private_key(ephemeral_private_key);
	}
}

RevealParticipant RevealParticipant::decode_from(MessageBuffer* buffer)
{
	RevealParticipant result;
	result.username = buffer->remove_opaque();
	result.long_term_public_key = buffer->remove_public_key();
	result.ephemeral_public_key = buffer->remove_public_key();
	result.secret_share = buffer->remove_hash();
	result.key_hash = buffer->remove_hash();
	result.has_ephemeral_private_key = buffer->remove_bit();
	if (result.has_ephemeral_private_key) {
		result.ephemeral_private_key = buffer->remove_private_key();
	}
	return result;
}

} // namespace np1sec
