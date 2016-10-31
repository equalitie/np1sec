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

#ifndef SRC_MESSAGE_H_
#define SRC_MESSAGE_H_

#include <cstdint>
#include <set>
#include <string>
#include <vector>

#include "bytearray.h"
#include "crypto.h"

namespace np1sec
{

class MessageFormatException {};

class MessageBuffer : public std::string
{
	public:
	MessageBuffer() {}
	MessageBuffer(const std::string& string): std::string(string) {}
	
	unsigned char byte(size_t index) { return (unsigned char)(at(index)); }
	
	void add_8(uint8_t byte);
	void add_16(uint16_t number);
	void add_32(uint32_t number);
	
	template<int n> void add_byte_array(const ByteArray<n>& data)
	{
		append(reinterpret_cast<const char *>(data.buffer), n);
	}
	
	void add_hash(const Hash& hash) { add_byte_array(hash); }
	void add_public_key(const PublicKey& key) { add_byte_array(key); }
	void add_signature(const Signature& signature) { add_byte_array(signature); }
	void add_bytes(const std::string& buffer);
	void add_opaque(const std::string& buffer);
	
	void check_empty();
	uint8_t remove_8();
	uint16_t remove_16();
	uint32_t remove_32();
	
	template<int n> ByteArray<n> remove_byte_array()
	{
		if (size() < n) {
			throw MessageFormatException();
		}
		
		ByteArray<n> result;
		for (int i = 0; i < n; i++) {
			result.buffer[i] = at(i);
		}
		
		erase(0, n);
		
		return result;
	}
	
	Hash remove_hash() { return remove_byte_array<c_hash_length>(); }
	PublicKey remove_public_key() { return remove_byte_array<c_public_key_length>(); }
	Signature remove_signature() { return remove_byte_array<c_signature_length>(); }
	std::string remove_bytes(size_t size);
	std::string remove_opaque();
};



struct Message
{
	enum class Type {
		ChannelSearch = 0x11,
		ChannelStatus = 0x12,
		ChannelAnnouncement = 0x13,
		JoinRequest = 0x14,
		AuthenticationRequest = 0x15,
		Authentication = 0x16,
		Authorization = 0x17,
		
		ConsistencyStatus = 0x21,
		ConsistencyCheck = 0x22,
	};
	
	Message() {}
	Message(Type type_, const std::string& payload_): type(type_), payload(payload_) {}
	
	Type type;
	std::string payload;
	
	std::string encode() const;
	static Message decode(const std::string& encoded);
};

template<class MessageBody>
struct SignedMessage : public MessageBody
{
	bool valid;
	std::string payload;
	
	static Message sign(const MessageBody& message, const PrivateKey& key)
	{
		std::string encoded_body = message.encode();
		MessageBuffer buffer;
		buffer.add_signature(crypto::sign(encoded_body, key));
		buffer.add_bytes(encoded_body);
		return Message(MessageBody::type, buffer);
	}
	
	static SignedMessage verify(const Message& encoded, const PublicKey& key)
	{
		if (encoded.type != MessageBody::type) {
			throw MessageFormatException();
		}
		MessageBuffer buffer(encoded.payload);
		Signature signature = buffer.remove_signature();
		SignedMessage result;
		result.payload = buffer;
		result.valid = crypto::verify(result.payload, std::move(signature), key);
		return result;
	}
	
	MessageBody decode() const
	{
		return MessageBody::decode(payload);
	}
};

struct ChannelEvent
{
	ChannelEvent() {}
	ChannelEvent(Message::Type type_, const std::string& payload_): type(type_), payload(payload_) {}
	
	Message::Type type;
	std::string payload;
};



struct ChannelSearchMessage
{
	Hash nonce;
	
	Message encode() const;
	static ChannelSearchMessage decode(const Message& encoded);
};

struct ChannelStatusMessage
{
	struct Participant
	{
		std::string username;
		PublicKey long_term_public_key;
		PublicKey ephemeral_public_key;
	};
	
	struct UnauthorizedParticipant
	{
		std::string username;
		PublicKey long_term_public_key;
		PublicKey ephemeral_public_key;
		
		std::set<std::string> authorized_by;
		std::set<std::string> authorized_peers;
	};
	
	std::string searcher_username;
	Hash searcher_nonce;
	
	std::vector<Participant> participants;
	std::vector<UnauthorizedParticipant> unauthorized_participants;
	
	Hash channel_status_hash;
	std::vector<ChannelEvent> events;
	
	Message encode() const;
	static ChannelStatusMessage decode(const Message& encoded);
};

struct ChannelAnnouncementMessage
{
	PublicKey long_term_public_key;
	PublicKey ephemeral_public_key;
	Hash channel_status_hash;
	
	Message encode() const;
	static ChannelAnnouncementMessage decode(const Message& encoded);
};

struct JoinRequestMessage
{
	PublicKey long_term_public_key;
	PublicKey ephemeral_public_key;
	
	std::vector<std::string> peer_usernames;
	
	Message encode() const;
	static JoinRequestMessage decode(const Message& encoded);
};

struct AuthenticationRequestMessage
{
	PublicKey sender_long_term_public_key;
	PublicKey sender_ephemeral_public_key;
	
	std::string peer_username;
	PublicKey peer_long_term_public_key;
	PublicKey peer_ephemeral_public_key;
	
	Hash nonce;
	
	Message encode() const;
	static AuthenticationRequestMessage decode(const Message& encoded);
};

struct AuthenticationMessage
{
	PublicKey sender_long_term_public_key;
	PublicKey sender_ephemeral_public_key;
	
	std::string peer_username;
	PublicKey peer_long_term_public_key;
	PublicKey peer_ephemeral_public_key;
	
	Hash nonce;
	Hash authentication_confirmation;
	
	Message encode() const;
	static AuthenticationMessage decode(const Message& encoded);
};

struct AuthorizationMessage
{
	std::string username;
	
	Message encode() const;
	static AuthorizationMessage decode(const Message& encoded);
};



struct ConsistencyStatusMessage
{
	static Message encode()
	{
		return Message(Message::Type::ConsistencyStatus, std::string());
	}
};

struct UnsignedConsistencyCheckMessage
{
	Hash channel_status_hash;
	
	std::string encode() const;
	static UnsignedConsistencyCheckMessage decode(const std::string& encoded);
	static const Message::Type type = Message::Type::ConsistencyCheck;
};
typedef SignedMessage<UnsignedConsistencyCheckMessage> ConsistencyCheckMessage;



struct ChannelStatusEvent
{
	std::string searcher_username;
	Hash searcher_nonce;
	Hash status_message_hash;
	std::set<std::string> remaining_users;
	
	ChannelEvent encode(const ChannelStatusMessage& status) const;
	static ChannelStatusEvent decode(const ChannelEvent& encoded, const ChannelStatusMessage& status);
};

struct ConsistencyCheckEvent
{
	Hash channel_status_hash;
	std::set<std::string> remaining_users;
	
	ChannelEvent encode(const ChannelStatusMessage& status) const;
	static ConsistencyCheckEvent decode(const ChannelEvent& encoded, const ChannelStatusMessage& status);
};



} // namespace np1sec

#endif
