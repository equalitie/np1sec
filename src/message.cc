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

namespace np1sec
{

const std::string c_np1sec_protocol_name(":o3np1sec1:");



// TODO: more efficient integer encoding

void MessageBuffer::add_8(uint8_t byte)
{
	push_back(byte);
}

void MessageBuffer::add_16(uint16_t number)
{
	push_back((number >> 8) & 0xff);
	push_back((number >> 0) & 0xff);
}

void MessageBuffer::add_32(uint32_t number)
{
	push_back((number >> 24) & 0xff);
	push_back((number >> 16) & 0xff);
	push_back((number >>  8) & 0xff);
	push_back((number >>  0) & 0xff);
}

void MessageBuffer::add_64(uint64_t number)
{
	push_back((number >> 56) & 0xff);
	push_back((number >> 48) & 0xff);
	push_back((number >> 40) & 0xff);
	push_back((number >> 32) & 0xff);
	push_back((number >> 24) & 0xff);
	push_back((number >> 16) & 0xff);
	push_back((number >>  8) & 0xff);
	push_back((number >>  0) & 0xff);
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
	if (size() < 2) {
		throw MessageFormatException();
	}
	
	uint16_t result =
		(byte(0) << 8) |
		(byte(1) << 0);
	
	erase(0, 2);
	
	return result;
}

uint32_t MessageBuffer::remove_32()
{
	if (size() < 4) {
		throw MessageFormatException();
	}
	
	uint32_t result =
		(byte(0) << 24) |
		(byte(1) << 16) |
		(byte(2) <<  8) |
		(byte(3) <<  0);
	
	erase(0, 4);
	
	return result;
}

uint64_t MessageBuffer::remove_64()
{
	if (size() < 8) {
		throw MessageFormatException();
	}
	
	uint64_t result =
		((uint64_t)byte(0) << 56) |
		((uint64_t)byte(1) << 48) |
		((uint64_t)byte(2) << 40) |
		((uint64_t)byte(3) << 32) |
		((uint64_t)byte(4) << 24) |
		((uint64_t)byte(5) << 16) |
		((uint64_t)byte(6) <<  8) |
		((uint64_t)byte(7) <<  0);
	
	erase(0, 8);
	
	return result;
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
	for (const Participant& participant : participants) {
		MessageBuffer participant_buffer;
		participant_buffer.add_opaque(participant.username);
		participant_buffer.add_public_key(participant.long_term_public_key);
		participant_buffer.add_public_key(participant.ephemeral_public_key);
		participant_buffer.add_64(participant.signature_id);
		participants_buffer.add_opaque(participant_buffer);
	}
	buffer.add_opaque(participants_buffer);
	
	MessageBuffer unauthorized_participants_buffer;
	for (const UnauthorizedParticipant& participant : unauthorized_participants) {
		MessageBuffer participant_buffer;
		participant_buffer.add_opaque(participant.username);
		participant_buffer.add_public_key(participant.long_term_public_key);
		participant_buffer.add_public_key(participant.ephemeral_public_key);
		participant_buffer.add_64(participant.signature_id);
		participant_buffer.add_opaque(encode_user_set(*this, true, false, participant.authorized_by));
		participant_buffer.add_opaque(encode_user_set(*this, true, false, participant.authorized_peers));
		unauthorized_participants_buffer.add_opaque(participant_buffer);
	}
	buffer.add_opaque(unauthorized_participants_buffer);
	
	buffer.add_hash(channel_status_hash);
	
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
		Participant participant;
		participant.username = participant_buffer.remove_opaque();
		participant.long_term_public_key = participant_buffer.remove_public_key();
		participant.ephemeral_public_key = participant_buffer.remove_public_key();
		participant.signature_id = participant_buffer.remove_64();
		result.participants.push_back(std::move(participant));
	}
	
	MessageBuffer unauthorized_participants_buffer = buffer.remove_opaque();
	while (!unauthorized_participants_buffer.empty()) {
		MessageBuffer participant_buffer = unauthorized_participants_buffer.remove_opaque();
		UnauthorizedParticipant participant;
		participant.username = participant_buffer.remove_opaque();
		participant.long_term_public_key = participant_buffer.remove_public_key();
		participant.ephemeral_public_key = participant_buffer.remove_public_key();
		participant.signature_id = participant_buffer.remove_64();
		participant.authorized_by = decode_user_set(result, true, false, participant_buffer.remove_opaque());
		participant.authorized_peers = decode_user_set(result, true, false, participant_buffer.remove_opaque());
		result.unauthorized_participants.push_back(std::move(participant));
	}
	
	result.channel_status_hash = buffer.remove_hash();
	
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
	buffer.add_64(signature_id);
	buffer.add_hash(channel_status_hash);
	
	return Message(Message::Type::ChannelAnnouncement, buffer);
}

ChannelAnnouncementMessage ChannelAnnouncementMessage::decode(const Message& encoded)
{
	MessageBuffer buffer(get_message_payload(encoded, Message::Type::ChannelAnnouncement));
	
	ChannelAnnouncementMessage result;
	result.long_term_public_key = buffer.remove_public_key();
	result.ephemeral_public_key = buffer.remove_public_key();
	result.signature_id = buffer.remove_64();
	result.channel_status_hash = buffer.remove_hash();
	return result;
}

Message JoinRequestMessage::encode() const
{
	MessageBuffer buffer;
	buffer.add_public_key(long_term_public_key);
	buffer.add_public_key(ephemeral_public_key);
	buffer.add_64(signature_id);
	
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
	result.signature_id = buffer.remove_64();
	
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

Message AuthorizationMessage::encode() const
{
	MessageBuffer buffer;
	buffer.add_opaque(username);
	
	return Message(Message::Type::Authorization, buffer);
}

AuthorizationMessage AuthorizationMessage::decode(const Message& encoded)
{
	MessageBuffer buffer(get_message_payload(encoded, Message::Type::Authorization));
	
	AuthorizationMessage result;
	result.username = buffer.remove_opaque();
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

} // namespace np1sec
