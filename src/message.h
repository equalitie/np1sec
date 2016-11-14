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
	void add_64(uint64_t number);
	
	template<int n> void add_byte_array(const ByteArray<n>& data)
	{
		append(reinterpret_cast<const char *>(data.buffer), n);
	}
	
	void add_hash(const Hash& hash) { add_byte_array(hash); }
	void add_public_key(const PublicKey& key) { add_byte_array(key); }
	void add_private_key(const SerializedPrivateKey& key) { add_byte_array(key); }
	void add_signature(const Signature& signature) { add_byte_array(signature); }
	void add_bytes(const std::string& buffer);
	void add_opaque(const std::string& buffer);
	
	void check_empty();
	uint8_t remove_8();
	uint16_t remove_16();
	uint32_t remove_32();
	uint64_t remove_64();
	
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
	SerializedPrivateKey remove_private_key() { return remove_byte_array<c_private_key_length>(); }
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
		
		Authorization = 0x21,
		ConsistencyStatus = 0x22,
		ConsistencyCheck = 0x23,
		
		KeyExchangePublicKey = 0x31,
		KeyExchangeSecretShare = 0x32,
		KeyExchangeAcceptance = 0x33,
		KeyExchangeReveal = 0x34,
		
		KeyActivation = 0x41,
		Chat = 0x42,
	};
	
	Message() {}
	Message(Type type_, const std::string& payload_): type(type_), payload(payload_) {}
	
	Type type;
	std::string payload;
	
	std::string encode() const;
	static Message decode(const std::string& encoded);
};

struct SignedMessageBody
{
	bool valid;
	std::string payload;
	
	static std::string sign(const std::string& payload, Message::Type type, const PrivateKey& key);
	static SignedMessageBody verify(const std::string& encoded, Message::Type type, const PublicKey& key);
};

template<class MessageBody>
struct SignedMessage : public SignedMessageBody
{
	SignedMessage() {}
	SignedMessage(SignedMessageBody b): SignedMessageBody(b) {}
	
	static Message sign(const MessageBody& message, const PrivateKey& key)
	{
		return Message(MessageBody::type, SignedMessageBody::sign(message.encode(), MessageBody::type, key));
	}
	
	static SignedMessage verify(const Message& encoded, const PublicKey& key)
	{
		if (encoded.type != MessageBody::type) {
			throw MessageFormatException();
		}
		return SignedMessageBody::verify(encoded.payload, encoded.type, key);
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

struct KeyExchangeState
{
	enum class State {
		PublicKey = 1,
		SecretShare = 2,
		Acceptance = 3,
		Reveal = 4,
	};
	
	Hash key_id;
	State state;
	std::string payload;
};

template<class ParticipantState>
struct ParticipantKeyExchangeState
{
	typedef ParticipantState Participant;
	Hash key_id;
	std::vector<ParticipantState> participants;
	
	KeyExchangeState encode() const
	{
		MessageBuffer buffer;
		for (const ParticipantState& participant : participants) {
			participant.ParticipantState::encode_to(&buffer);
		}
		KeyExchangeState result;
		result.key_id = key_id;
		result.state = ParticipantState::state;
		result.payload = buffer;
		return result;
	}
	
	static ParticipantKeyExchangeState decode(const KeyExchangeState& encoded)
	{
		if (encoded.state != ParticipantState::state) {
			throw MessageFormatException();
		}
		ParticipantKeyExchangeState result;
		result.key_id = encoded.key_id;
		MessageBuffer buffer(encoded.payload);
		while (!buffer.empty()) {
			result.participants.push_back(ParticipantState::decode_from(&buffer));
		}
		return result;
	}
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
		Hash authorization_nonce;
	};
	
	struct UnauthorizedParticipant : public Participant
	{
		std::set<std::string> authorized_by;
		std::set<std::string> authorized_peers;
	};
	
	std::string searcher_username;
	Hash searcher_nonce;
	
	std::vector<Participant> participants;
	std::vector<UnauthorizedParticipant> unauthorized_participants;
	
	Hash channel_status_hash;
	std::vector<KeyExchangeState> key_exchanges;
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



struct UnsignedAuthorizationMessage
{
	std::string username;
	PublicKey long_term_public_key;
	PublicKey ephemeral_public_key;
	Hash authorization_nonce;
	
	std::string encode() const;
	static UnsignedAuthorizationMessage decode(const std::string& encoded);
	static const Message::Type type = Message::Type::Authorization;
};
typedef struct SignedMessage<UnsignedAuthorizationMessage> AuthorizationMessage;

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



struct UnsignedKeyExchangePublicKeyMessage
{
	Hash key_id;
	PublicKey public_key;
	
	std::string encode() const;
	static UnsignedKeyExchangePublicKeyMessage decode(const std::string& encoded);
	static const Message::Type type = Message::Type::KeyExchangePublicKey;
};
typedef SignedMessage<UnsignedKeyExchangePublicKeyMessage> KeyExchangePublicKeyMessage;

struct UnsignedKeyExchangeSecretShareMessage
{
	Hash key_id;
	Hash group_hash;
	Hash secret_share;
	
	std::string encode() const;
	static UnsignedKeyExchangeSecretShareMessage decode(const std::string& encoded);
	static const Message::Type type = Message::Type::KeyExchangeSecretShare;
};
typedef SignedMessage<UnsignedKeyExchangeSecretShareMessage> KeyExchangeSecretShareMessage;

struct UnsignedKeyExchangeAcceptanceMessage
{
	Hash key_id;
	Hash key_hash;
	
	std::string encode() const;
	static UnsignedKeyExchangeAcceptanceMessage decode(const std::string& encoded);
	static const Message::Type type = Message::Type::KeyExchangeAcceptance;
};
typedef SignedMessage<UnsignedKeyExchangeAcceptanceMessage> KeyExchangeAcceptanceMessage;

struct UnsignedKeyExchangeRevealMessage
{
	Hash key_id;
	SerializedPrivateKey private_key;
	
	std::string encode() const;
	static UnsignedKeyExchangeRevealMessage decode(const std::string& encoded);
	static const Message::Type type = Message::Type::KeyExchangeReveal;
};
typedef SignedMessage<UnsignedKeyExchangeRevealMessage> KeyExchangeRevealMessage;



struct UnsignedKeyActivationMessage
{
	Hash key_id;
	
	std::string encode() const;
	static UnsignedKeyActivationMessage decode(const std::string& encoded);
	static const Message::Type type = Message::Type::KeyActivation;
};
typedef SignedMessage<UnsignedKeyActivationMessage> KeyActivationMessage;

struct ChatMessage
{
	Hash key_id;
	std::string encrypted_payload;
	
	Message encode() const;
	static ChatMessage decode(const Message& encoded);
	
	std::string decrypt(const SymmetricKey& symmetric_key) const;
	static ChatMessage encrypt(std::string plaintext, const Hash& key_id, const SymmetricKey& symmetric_key);
};
struct UnsignedChatMessagePayload
{
	std::string message;
	uint64_t message_id;
	
	std::string encode() const;
	static UnsignedChatMessagePayload decode(const std::string& encoded);
	static const Message::Type type = Message::Type::Chat;
};
struct ChatMessagePayload : public SignedMessageBody
{
	ChatMessagePayload() {}
	ChatMessagePayload(SignedMessageBody b): SignedMessageBody(b) {}
	
	static std::string sign(const UnsignedChatMessagePayload payload, const PrivateKey& key)
	{
		return SignedMessageBody::sign(payload.encode(), Message::Type::Chat, key);
	}
	
	static ChatMessagePayload verify(std::string signed_message, const PublicKey& key)
	{
		return SignedMessageBody::verify(signed_message, Message::Type::Chat, key);
	}

	UnsignedChatMessagePayload decode() const
	{
		return UnsignedChatMessagePayload::decode(payload);
	}
};



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

struct KeyExchangeEvent
{
	Message::Type type;
	Hash key_id;
	bool cancelled;
	std::set<std::string> remaining_users;
	
	ChannelEvent encode(const ChannelStatusMessage& status) const;
	static KeyExchangeEvent decode(const ChannelEvent& encooded, const ChannelStatusMessage& status);
};

struct KeyActivationEvent
{
	Hash key_id;
	std::set<std::string> remaining_users;
	
	ChannelEvent encode(const ChannelStatusMessage& status) const;
	static KeyActivationEvent decode(const ChannelEvent& encoded, const ChannelStatusMessage& status);
};



struct PublicKeyParticipant
{
	std::string username;
	PublicKey long_term_public_key;
	bool has_ephemeral_public_key;
	PublicKey ephemeral_public_key;
	
	void encode_to(MessageBuffer* buffer) const;
	static PublicKeyParticipant decode_from(MessageBuffer* buffer);
	static const KeyExchangeState::State state = KeyExchangeState::State::PublicKey;
};
typedef ParticipantKeyExchangeState<PublicKeyParticipant> PublicKeyKeyExchangeState;

struct SecretShareParticipant
{
	std::string username;
	PublicKey long_term_public_key;
	PublicKey ephemeral_public_key;
	bool has_secret_share;
	Hash secret_share;
	
	void encode_to(MessageBuffer* buffer) const;
	static SecretShareParticipant decode_from(MessageBuffer* buffer);
	static const KeyExchangeState::State state = KeyExchangeState::State::SecretShare;
};
typedef ParticipantKeyExchangeState<SecretShareParticipant> SecretShareKeyExchangeState;

struct AcceptanceParticipant
{
	std::string username;
	PublicKey long_term_public_key;
	PublicKey ephemeral_public_key;
	Hash secret_share;
	bool has_key_hash;
	Hash key_hash;
	
	void encode_to(MessageBuffer* buffer) const;
	static AcceptanceParticipant decode_from(MessageBuffer* buffer);
	static const KeyExchangeState::State state = KeyExchangeState::State::Acceptance;
};
typedef ParticipantKeyExchangeState<AcceptanceParticipant> AcceptanceKeyExchangeState;

struct RevealParticipant
{
	std::string username;
	PublicKey long_term_public_key;
	PublicKey ephemeral_public_key;
	Hash secret_share;
	Hash key_hash;
	bool has_ephemeral_private_key;
	SerializedPrivateKey ephemeral_private_key;
	
	void encode_to(MessageBuffer* buffer) const;
	static RevealParticipant decode_from(MessageBuffer* buffer);
	static const KeyExchangeState::State state = KeyExchangeState::State::Reveal;
};
typedef ParticipantKeyExchangeState<RevealParticipant> RevealKeyExchangeState;



} // namespace np1sec

#endif
