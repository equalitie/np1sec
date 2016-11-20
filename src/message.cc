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
			buffer->add_8((uint8_t)value);
			return;
		}
		
		uint8_t byte = (uint8_t)(value & 0x7f);
		value = value >> 7;
		bits_remaining -= 7;
		buffer->add_8(value ? (byte | 0x80) : byte);
	} while(value);
}

template<typename T>
T decode_integer(MessageBuffer* buffer)
{
	int shift = 0;
	T result = 0;
	while (true) {
		uint8_t byte = buffer->remove_8();
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

void MessageBuffer::add_8(uint8_t byte)
{
	push_back(byte);
}

void MessageBuffer::add_16(uint16_t number)
{
	encode_integer<uint16_t>(this, number);
}

void MessageBuffer::add_32(uint32_t number)
{
	encode_integer<uint32_t>(this, number);
}

void MessageBuffer::add_64(uint64_t number)
{
	encode_integer<uint64_t>(this, number);
}

void MessageBuffer::add_bytes(const std::string& buffer)
{
	append(buffer);
}

void MessageBuffer::add_opaque(const std::string& buffer)
{
	add_32(buffer.size());
	append(buffer);
}

void MessageBuffer::check_empty()
{
	if (!empty()) {
		throw MessageFormatException();
	}
}

uint8_t MessageBuffer::remove_8()
{
	if (size() < 1) {
		throw MessageFormatException();
	}
	
	uint8_t result = byte(0);
	
	erase(0, 1);
	
	return result;
}

uint16_t MessageBuffer::remove_16()
{
	return decode_integer<uint16_t>(this);
}

uint32_t MessageBuffer::remove_32()
{
	return decode_integer<uint32_t>(this);
}

uint64_t MessageBuffer::remove_64()
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
	return remove_bytes(remove_32());
}



std::string Message::encode() const
{
	MessageBuffer buffer;
	buffer.add_8(uint8_t(type));
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
	message.type = Message::Type(buffer.remove_8());
	message.payload = buffer;
	
	return message;
}



std::string SignedMessageBody::sign(const std::string& payload, Message::Type type, const PrivateKey& key)
{
	std::string signed_body;
	signed_body.push_back(uint8_t(type));
	signed_body += payload;
	
	MessageBuffer buffer;
	buffer.add_signature(crypto::sign(std::move(signed_body), key));
	buffer.add_bytes(payload);
	return buffer;
}

SignedMessageBody SignedMessageBody::verify(const std::string& encoded, Message::Type type, const PublicKey& key)
{
	MessageBuffer buffer(encoded);
	Signature signature = buffer.remove_signature();
	std::string signed_body;
	signed_body.push_back(uint8_t(type));
	signed_body += buffer;
	
	SignedMessageBody result;
	result.valid = crypto::verify(std::move(signed_body), std::move(signature), key);
	result.payload = buffer;
	return result;
}



static MessageBuffer get_message_payload(const Message& message, Message::Type expected_type)
{
	if (message.type != expected_type) {
		throw MessageFormatException();
	}
	return MessageBuffer(message.payload);
}

static MessageBuffer get_event_payload(const ChannelEvent& event, Message::Type expected_type)
{
	if (event.type != expected_type) {
		throw MessageFormatException();
	}
	return MessageBuffer(event.payload);
}

static MessageBuffer encode_user_set(const ChannelStatusMessage& status, bool include_authorized, bool include_unauthorized, const std::set<std::string>& users)
{
	MessageBuffer buffer;
	uint8_t byte = 0;
	int bits = 8;
	
	if (include_authorized) {
		for (const ChannelStatusMessage::Participant& participant : status.participants) {
			bits--;
			if (users.count(participant.username)) {
				byte |= (1 << bits);
			}
			if (bits == 0) {
				buffer.add_8(byte);
				byte = 0;
				bits = 8;
			}
		}
	}
	
	if (include_unauthorized) {
		for (const ChannelStatusMessage::UnauthorizedParticipant& participant : status.unauthorized_participants) {
			bits--;
			if (users.count(participant.username)) {
				byte |= (1 << bits);
			}
			if (bits == 0) {
				buffer.add_8(byte);
				byte = 0;
				bits = 8;
			}
		}
	}
	
	if (bits < 8) {
		buffer.add_8(byte);
	}
	
	return buffer;
}

static std::set<std::string> decode_user_set(const ChannelStatusMessage& status, bool include_authorized, bool include_unauthorized, const std::string& encoded)
{
	MessageBuffer buffer(encoded);
	std::set<std::string> output;
	uint8_t byte = 0;
	int bits = 0;
	
	if (include_authorized) {
		for (const ChannelStatusMessage::Participant& participant : status.participants) {
			if (!bits) {
				byte = buffer.remove_8();
				bits = 8;
			}
			bits--;
			if (byte & (1 << bits)) {
				output.insert(participant.username);
			}
		}
	}
	
	if (include_unauthorized) {
		for (const ChannelStatusMessage::UnauthorizedParticipant& participant : status.unauthorized_participants) {
			if (!bits) {
				byte = buffer.remove_8();
				bits = 8;
			}
			bits--;
			if (byte & (1 << bits)) {
				output.insert(participant.username);
			}
		}
	}
	
	return output;
}





Message ChannelSearchMessage::encode() const
{
	MessageBuffer buffer;
	buffer.add_hash(nonce);
	
	return Message(Message::Type::ChannelSearch, buffer);
}

ChannelSearchMessage ChannelSearchMessage::decode(const Message& encoded)
{
	MessageBuffer buffer(get_message_payload(encoded, Message::Type::ChannelSearch));
	
	ChannelSearchMessage result;
	result.nonce = buffer.remove_hash();
	return result;
}

Message ChannelStatusMessage::encode() const
{
	MessageBuffer buffer;
	buffer.add_opaque(searcher_username);
	buffer.add_hash(searcher_nonce);
	
	MessageBuffer participants_buffer;
	for (const AuthorizedParticipant& participant : participants) {
		MessageBuffer participant_buffer;
		participant_buffer.add_opaque(participant.username);
		participant_buffer.add_public_key(participant.long_term_public_key);
		participant_buffer.add_public_key(participant.ephemeral_public_key);
		participant_buffer.add_hash(participant.authorization_nonce);
		participants_buffer.add_opaque(participant_buffer);
	}
	buffer.add_opaque(participants_buffer);
	
	MessageBuffer unauthorized_participants_buffer;
	for (const UnauthorizedParticipant& participant : unauthorized_participants) {
		MessageBuffer participant_buffer;
		participant_buffer.add_opaque(participant.username);
		participant_buffer.add_public_key(participant.long_term_public_key);
		participant_buffer.add_public_key(participant.ephemeral_public_key);
		participant_buffer.add_hash(participant.authorization_nonce);
		participant_buffer.add_opaque(encode_user_set(*this, true, false, participant.authorized_by));
		participant_buffer.add_opaque(encode_user_set(*this, true, false, participant.authorized_peers));
		unauthorized_participants_buffer.add_opaque(participant_buffer);
	}
	buffer.add_opaque(unauthorized_participants_buffer);
	
	MessageBuffer timeout_buffer;
	MessageBuffer votekick_buffer;
	for (const AuthorizedParticipant& participant : participants) {
		timeout_buffer.add_opaque(encode_user_set(*this, true, false, participant.timeout_peers));
		votekick_buffer.add_opaque(encode_user_set(*this, true, false, participant.votekick_peers));
	}
	buffer.add_opaque(timeout_buffer);
	buffer.add_opaque(votekick_buffer);
	
	buffer.add_hash(channel_status_hash);
	
	MessageBuffer key_exchange_buffer;
	for (const KeyExchangeState& exchange : key_exchanges) {
		key_exchange_buffer.add_hash(exchange.key_id);
		key_exchange_buffer.add_8(uint8_t(exchange.state));
		key_exchange_buffer.add_opaque(exchange.payload);
	}
	buffer.add_opaque(key_exchange_buffer);
	
	MessageBuffer event_buffer;
	for (const ChannelEvent& event : events) {
		event_buffer.add_8(uint8_t(event.type));
		event_buffer.add_opaque(event.payload);
	}
	buffer.add_opaque(event_buffer);
	
	return Message(Message::Type::ChannelStatus, buffer);
}

ChannelStatusMessage ChannelStatusMessage::decode(const Message& encoded)
{
	MessageBuffer buffer(get_message_payload(encoded, Message::Type::ChannelStatus));
	
	ChannelStatusMessage result;
	result.searcher_username = buffer.remove_opaque();
	result.searcher_nonce = buffer.remove_hash();
	
	MessageBuffer participants_buffer = buffer.remove_opaque();
	while (!participants_buffer.empty()) {
		MessageBuffer participant_buffer = participants_buffer.remove_opaque();
		AuthorizedParticipant participant;
		participant.username = participant_buffer.remove_opaque();
		participant.long_term_public_key = participant_buffer.remove_public_key();
		participant.ephemeral_public_key = participant_buffer.remove_public_key();
		participant.authorization_nonce = participant_buffer.remove_hash();
		result.participants.push_back(std::move(participant));
	}
	
	MessageBuffer unauthorized_participants_buffer = buffer.remove_opaque();
	while (!unauthorized_participants_buffer.empty()) {
		MessageBuffer participant_buffer = unauthorized_participants_buffer.remove_opaque();
		UnauthorizedParticipant participant;
		participant.username = participant_buffer.remove_opaque();
		participant.long_term_public_key = participant_buffer.remove_public_key();
		participant.ephemeral_public_key = participant_buffer.remove_public_key();
		participant.authorization_nonce = participant_buffer.remove_hash();
		participant.authorized_by = decode_user_set(result, true, false, participant_buffer.remove_opaque());
		participant.authorized_peers = decode_user_set(result, true, false, participant_buffer.remove_opaque());
		result.unauthorized_participants.push_back(std::move(participant));
	}
	
	MessageBuffer timeout_buffer = buffer.remove_opaque();
	MessageBuffer votekick_buffer = buffer.remove_opaque();
	for (AuthorizedParticipant& participant : result.participants) {
		participant.timeout_peers = decode_user_set(result, true, false, timeout_buffer.remove_opaque());
		participant.votekick_peers = decode_user_set(result, true, false, votekick_buffer.remove_opaque());
	}
	
	result.channel_status_hash = buffer.remove_hash();
	
	MessageBuffer key_exchange_buffer = buffer.remove_opaque();
	while (!key_exchange_buffer.empty()) {
		KeyExchangeState exchange;
		exchange.key_id = key_exchange_buffer.remove_hash();
		exchange.state = KeyExchangeState::State(key_exchange_buffer.remove_8());
		exchange.payload = key_exchange_buffer.remove_opaque();
		result.key_exchanges.push_back(std::move(exchange));
	}
	
	MessageBuffer event_buffer = buffer.remove_opaque();
	while (!event_buffer.empty()) {
		ChannelEvent event;
		event.type = Message::Type(event_buffer.remove_8());
		event.payload = event_buffer.remove_opaque();
		result.events.push_back(std::move(event));
	}
	
	return result;
}

Message ChannelAnnouncementMessage::encode() const
{
	MessageBuffer buffer;
	buffer.add_public_key(long_term_public_key);
	buffer.add_public_key(ephemeral_public_key);
	buffer.add_hash(channel_status_hash);
	
	return Message(Message::Type::ChannelAnnouncement, buffer);
}

ChannelAnnouncementMessage ChannelAnnouncementMessage::decode(const Message& encoded)
{
	MessageBuffer buffer(get_message_payload(encoded, Message::Type::ChannelAnnouncement));
	
	ChannelAnnouncementMessage result;
	result.long_term_public_key = buffer.remove_public_key();
	result.ephemeral_public_key = buffer.remove_public_key();
	result.channel_status_hash = buffer.remove_hash();
	return result;
}

Message JoinRequestMessage::encode() const
{
	MessageBuffer buffer;
	buffer.add_public_key(long_term_public_key);
	buffer.add_public_key(ephemeral_public_key);
	
	MessageBuffer usernames_buffer;
	for (const std::string& username : peer_usernames) {
		usernames_buffer.add_opaque(username);
	}
	buffer.add_opaque(usernames_buffer);
	
	return Message(Message::Type::JoinRequest, buffer);
}

JoinRequestMessage JoinRequestMessage::decode(const Message& encoded)
{
	MessageBuffer buffer(get_message_payload(encoded, Message::Type::JoinRequest));
	
	JoinRequestMessage result;
	result.long_term_public_key = buffer.remove_public_key();
	result.ephemeral_public_key = buffer.remove_public_key();
	
	MessageBuffer usernames_buffer = buffer.remove_opaque();
	while (!usernames_buffer.empty()) {
		result.peer_usernames.push_back(usernames_buffer.remove_opaque());
	}
	return result;
}

Message AuthenticationRequestMessage::encode() const
{
	MessageBuffer buffer;
	buffer.add_public_key(sender_long_term_public_key);
	buffer.add_public_key(sender_ephemeral_public_key);
	buffer.add_opaque(peer_username);
	buffer.add_public_key(peer_long_term_public_key);
	buffer.add_public_key(peer_ephemeral_public_key);
	buffer.add_hash(nonce);
	
	return Message(Message::Type::AuthenticationRequest, buffer);
}

AuthenticationRequestMessage AuthenticationRequestMessage::decode(const Message& encoded)
{
	MessageBuffer buffer(get_message_payload(encoded, Message::Type::AuthenticationRequest));
	
	AuthenticationRequestMessage result;
	result.sender_long_term_public_key = buffer.remove_public_key();
	result.sender_ephemeral_public_key = buffer.remove_public_key();
	result.peer_username = buffer.remove_opaque();
	result.peer_long_term_public_key = buffer.remove_public_key();
	result.peer_ephemeral_public_key = buffer.remove_public_key();
	result.nonce = buffer.remove_hash();
	return result;
}

Message AuthenticationMessage::encode() const
{
	MessageBuffer buffer;
	buffer.add_public_key(sender_long_term_public_key);
	buffer.add_public_key(sender_ephemeral_public_key);
	buffer.add_opaque(peer_username);
	buffer.add_public_key(peer_long_term_public_key);
	buffer.add_public_key(peer_ephemeral_public_key);
	buffer.add_hash(nonce);
	buffer.add_hash(authentication_confirmation);
	
	return Message(Message::Type::Authentication, buffer);
}

AuthenticationMessage AuthenticationMessage::decode(const Message& encoded)
{
	MessageBuffer buffer(get_message_payload(encoded, Message::Type::Authentication));
	
	AuthenticationMessage result;
	result.sender_long_term_public_key = buffer.remove_public_key();
	result.sender_ephemeral_public_key = buffer.remove_public_key();
	result.peer_username = buffer.remove_opaque();
	result.peer_long_term_public_key = buffer.remove_public_key();
	result.peer_ephemeral_public_key = buffer.remove_public_key();
	result.nonce = buffer.remove_hash();
	result.authentication_confirmation = buffer.remove_hash();
	return result;
}

std::string UnsignedAuthorizationMessage::encode() const
{
	MessageBuffer buffer;
	buffer.add_opaque(username);
	buffer.add_public_key(long_term_public_key);
	buffer.add_public_key(ephemeral_public_key);
	buffer.add_hash(authorization_nonce);
	return buffer;
}

UnsignedAuthorizationMessage UnsignedAuthorizationMessage::decode(const std::string& encoded)
{
	MessageBuffer buffer(encoded);
	UnsignedAuthorizationMessage result;
	result.username = buffer.remove_opaque();
	result.long_term_public_key = buffer.remove_public_key();
	result.ephemeral_public_key = buffer.remove_public_key();
	result.authorization_nonce = buffer.remove_hash();
	return result;
}

std::string UnsignedConsistencyCheckMessage::encode() const
{
	MessageBuffer buffer;
	buffer.add_hash(channel_status_hash);
	return buffer;
}

UnsignedConsistencyCheckMessage UnsignedConsistencyCheckMessage::decode(const std::string& encoded)
{
	MessageBuffer buffer(encoded);
	UnsignedConsistencyCheckMessage result;
	result.channel_status_hash = buffer.remove_hash();
	return result;
}

Message TimeoutMessage::encode() const
{
	MessageBuffer buffer;
	buffer.add_opaque(victim);
	buffer.add_8(timeout ? 1 : 0);
	
	return Message(Message::Type::Timeout, buffer);
}

TimeoutMessage TimeoutMessage::decode(const Message& encoded)
{
	MessageBuffer buffer(get_message_payload(encoded, Message::Type::Timeout));
	
	TimeoutMessage result;
	result.victim = buffer.remove_opaque();
	result.timeout = buffer.remove_8() != 0;
	return result;
}

Message VotekickMessage::encode() const
{
	MessageBuffer buffer;
	buffer.add_opaque(victim);
	buffer.add_8(kick ? 1 : 0);
	
	return Message(Message::Type::Votekick, buffer);
}

VotekickMessage VotekickMessage::decode(const Message& encoded)
{
	MessageBuffer buffer(get_message_payload(encoded, Message::Type::Votekick));
	
	VotekickMessage result;
	result.victim = buffer.remove_opaque();
	result.kick = buffer.remove_8() != 0;
	return result;
}

std::string UnsignedKeyExchangePublicKeyMessage::encode() const
{
	MessageBuffer buffer;
	buffer.add_hash(key_id);
	buffer.add_public_key(public_key);
	return buffer;
}

UnsignedKeyExchangePublicKeyMessage UnsignedKeyExchangePublicKeyMessage::decode(const std::string& encoded)
{
	MessageBuffer buffer(encoded);
	UnsignedKeyExchangePublicKeyMessage result;
	result.key_id = buffer.remove_hash();
	result.public_key = buffer.remove_public_key();
	return result;
}

std::string UnsignedKeyExchangeSecretShareMessage::encode() const
{
	MessageBuffer buffer;
	buffer.add_hash(key_id);
	buffer.add_hash(group_hash);
	buffer.add_hash(secret_share);
	return buffer;
}

UnsignedKeyExchangeSecretShareMessage UnsignedKeyExchangeSecretShareMessage::decode(const std::string& encoded)
{
	MessageBuffer buffer(encoded);
	UnsignedKeyExchangeSecretShareMessage result;
	result.key_id = buffer.remove_hash();
	result.group_hash = buffer.remove_hash();
	result.secret_share = buffer.remove_hash();
	return result;
}

std::string UnsignedKeyExchangeAcceptanceMessage::encode() const
{
	MessageBuffer buffer;
	buffer.add_hash(key_id);
	buffer.add_hash(key_hash);
	return buffer;
}

UnsignedKeyExchangeAcceptanceMessage UnsignedKeyExchangeAcceptanceMessage::decode(const std::string& encoded)
{
	MessageBuffer buffer(encoded);
	UnsignedKeyExchangeAcceptanceMessage result;
	result.key_id = buffer.remove_hash();
	result.key_hash = buffer.remove_hash();
	return result;
}

std::string UnsignedKeyExchangeRevealMessage::encode() const
{
	MessageBuffer buffer;
	buffer.add_hash(key_id);
	buffer.add_private_key(private_key);
	return buffer;
}

UnsignedKeyExchangeRevealMessage UnsignedKeyExchangeRevealMessage::decode(const std::string& encoded)
{
	MessageBuffer buffer(encoded);
	UnsignedKeyExchangeRevealMessage result;
	result.key_id = buffer.remove_hash();
	result.private_key = buffer.remove_private_key();
	return result;
}

std::string UnsignedKeyActivationMessage::encode() const
{
	MessageBuffer buffer;
	buffer.add_hash(key_id);
	return buffer;
}

UnsignedKeyActivationMessage UnsignedKeyActivationMessage::decode(const std::string& encoded)
{
	MessageBuffer buffer(encoded);
	UnsignedKeyActivationMessage result;
	result.key_id = buffer.remove_hash();
	return result;
}

Message ChatMessage::encode() const
{
	MessageBuffer buffer;
	buffer.add_hash(key_id);
	buffer.add_opaque(encrypted_payload);
	
	return Message(Message::Type::Chat, buffer);
}

ChatMessage ChatMessage::decode(const Message& encoded)
{
	MessageBuffer buffer(get_message_payload(encoded, Message::Type::Chat));
	
	ChatMessage result;
	result.key_id = buffer.remove_hash();
	result.encrypted_payload = buffer.remove_opaque();
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

std::string UnsignedChatMessagePayload::encode() const
{
	MessageBuffer buffer;
	buffer.add_opaque(message);
	buffer.add_64(message_id);
	return buffer;
}

UnsignedChatMessagePayload UnsignedChatMessagePayload::decode(const std::string& encoded)
{
	MessageBuffer buffer(encoded);
	UnsignedChatMessagePayload result;
	result.message = buffer.remove_opaque();
	result.message_id = buffer.remove_64();
	return result;
}



ChannelEvent ChannelStatusEvent::encode(const ChannelStatusMessage& status) const
{
	MessageBuffer buffer;
	buffer.add_opaque(searcher_username);
	buffer.add_hash(searcher_nonce);
	buffer.add_hash(status_message_hash);
	buffer.add_opaque(encode_user_set(status, true, true, remaining_users));
	
	return ChannelEvent(Message::Type::ChannelStatus, buffer);
}

ChannelStatusEvent ChannelStatusEvent::decode(const ChannelEvent& encoded, const ChannelStatusMessage& status)
{
	MessageBuffer buffer(get_event_payload(encoded, Message::Type::ChannelStatus));
	
	ChannelStatusEvent result;
	result.searcher_username = buffer.remove_opaque();
	result.searcher_nonce = buffer.remove_hash();
	result.status_message_hash = buffer.remove_hash();
	result.remaining_users = decode_user_set(status, true, true, buffer.remove_opaque());
	return result;
}

ChannelEvent ConsistencyCheckEvent::encode(const ChannelStatusMessage& status) const
{
	MessageBuffer buffer;
	buffer.add_hash(channel_status_hash);
	buffer.add_opaque(encode_user_set(status, true, true, remaining_users));
	
	return ChannelEvent(Message::Type::ConsistencyCheck, buffer);
}

ConsistencyCheckEvent ConsistencyCheckEvent::decode(const ChannelEvent& encoded, const ChannelStatusMessage& status)
{
	MessageBuffer buffer(get_event_payload(encoded, Message::Type::ConsistencyCheck));
	
	ConsistencyCheckEvent result;
	result.channel_status_hash = buffer.remove_hash();
	result.remaining_users = decode_user_set(status, true, true, buffer.remove_opaque());
	return result;
}

ChannelEvent KeyExchangeEvent::encode(const ChannelStatusMessage& status) const
{
	assert(
		   type == Message::Type::KeyExchangePublicKey
		|| type == Message::Type::KeyExchangeSecretShare
		|| type == Message::Type::KeyExchangeAcceptance
		|| type == Message::Type::KeyExchangeReveal
	);
	MessageBuffer buffer;
	buffer.add_hash(key_id);
	if (cancelled) {
		buffer.add_8(1);
		buffer.add_opaque(encode_user_set(status, true, false, remaining_users));
	} else {
		buffer.add_8(0);
	}
	
	return ChannelEvent(type, buffer);
}

KeyExchangeEvent KeyExchangeEvent::decode(const ChannelEvent& encoded, const ChannelStatusMessage& status)
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
	if (buffer.remove_8()) {
		result.cancelled = true;
		result.remaining_users = decode_user_set(status, true, false, buffer.remove_opaque());
	} else {
		result.cancelled = false;
	}
	return result;
}

ChannelEvent KeyActivationEvent::encode(const ChannelStatusMessage& status) const
{
	MessageBuffer buffer;
	buffer.add_hash(key_id);
	buffer.add_opaque(encode_user_set(status, true, false, remaining_users));
	
	return ChannelEvent(Message::Type::KeyActivation, buffer);
}

KeyActivationEvent KeyActivationEvent::decode(const ChannelEvent& encoded, const ChannelStatusMessage& status)
{
	MessageBuffer buffer(get_event_payload(encoded, Message::Type::KeyActivation));
	
	KeyActivationEvent result;
	result.key_id = buffer.remove_hash();
	result.remaining_users = decode_user_set(status, true, false, buffer.remove_opaque());
	return result;
}



void PublicKeyParticipant::encode_to(MessageBuffer* buffer) const
{
	buffer->add_opaque(username);
	buffer->add_public_key(long_term_public_key);
	if (has_ephemeral_public_key) {
		buffer->add_8(1);
		buffer->add_public_key(ephemeral_public_key);
	} else {
		buffer->add_8(0);
	}
}

PublicKeyParticipant PublicKeyParticipant::decode_from(MessageBuffer* buffer)
{
	PublicKeyParticipant result;
	result.username = buffer->remove_opaque();
	result.long_term_public_key = buffer->remove_public_key();
	if (buffer->remove_8()) {
		result.has_ephemeral_public_key = true;
		result.ephemeral_public_key = buffer->remove_public_key();
	} else {
		result.has_ephemeral_public_key = false;
	}
	return result;
}

void SecretShareParticipant::encode_to(MessageBuffer* buffer) const
{
	buffer->add_opaque(username);
	buffer->add_public_key(long_term_public_key);
	buffer->add_public_key(ephemeral_public_key);
	if (has_secret_share) {
		buffer->add_8(1);
		buffer->add_hash(secret_share);
	} else {
		buffer->add_8(0);
	}
}

SecretShareParticipant SecretShareParticipant::decode_from(MessageBuffer* buffer)
{
	SecretShareParticipant result;
	result.username = buffer->remove_opaque();
	result.long_term_public_key = buffer->remove_public_key();
	result.ephemeral_public_key = buffer->remove_public_key();
	if (buffer->remove_8()) {
		result.has_secret_share = true;
		result.secret_share = buffer->remove_hash();
	} else {
		result.has_secret_share = false;
	}
	return result;
}

void AcceptanceParticipant::encode_to(MessageBuffer* buffer) const
{
	buffer->add_opaque(username);
	buffer->add_public_key(long_term_public_key);
	buffer->add_public_key(ephemeral_public_key);
	buffer->add_hash(secret_share);
	if (has_key_hash) {
		buffer->add_8(1);
		buffer->add_hash(key_hash);
	} else {
		buffer->add_8(0);
	}
}

AcceptanceParticipant AcceptanceParticipant::decode_from(MessageBuffer* buffer)
{
	AcceptanceParticipant result;
	result.username = buffer->remove_opaque();
	result.long_term_public_key = buffer->remove_public_key();
	result.ephemeral_public_key = buffer->remove_public_key();
	result.secret_share = buffer->remove_hash();
	if (buffer->remove_8()) {
		result.has_key_hash = true;
		result.key_hash = buffer->remove_hash();
	} else {
		result.has_key_hash = false;
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
	if (has_ephemeral_private_key) {
		buffer->add_8(1);
		buffer->add_private_key(ephemeral_private_key);
	} else {
		buffer->add_8(0);
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
	if (buffer->remove_8()) {
		result.has_ephemeral_private_key = true;
		result.ephemeral_private_key = buffer->remove_private_key();
	} else {
		result.has_ephemeral_private_key = false;
	}
	return result;
}

} // namespace np1sec
