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
	
	void add_bit(bool bit);
	void add_byte(uint8_t byte);
	void add_integer(uint64_t number);
	
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
	bool remove_bit();
	uint8_t remove_byte();
	uint64_t remove_integer();
	
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
		Quit = 0x01,
		Hello = 0x02,
		RoomAuthenticationRequest = 0x03,
		RoomAuthentication = 0x04,
		
		Invite = 0x11,
		ConversationStatus = 0x12,
		ConversationConfirmation = 0x13,
		InviteAcceptance = 0x14,
		AuthenticationRequest = 0x15,
		Authentication = 0x16,
		AuthenticateInvite = 0x17,
		CancelInvite = 0x18,
		Join = 0x19,
		
		Leave = 0x21,
		ConsistencyStatus = 0x22,
		ConsistencyCheck = 0x23,
		Timeout = 0x24,
		Votekick = 0x25,
		
		KeyExchangePublicKey = 0x31,
		KeyExchangeSecretShare = 0x32,
		KeyExchangeAcceptance = 0x33,
		KeyExchangeReveal = 0x34,
		
		KeyActivation = 0x41,
		KeyRatchet = 0x42,
		Chat = 0x43,
	};
	
	Message() {}
	Message(Type type_, const std::string& payload_): type(type_), payload(payload_) {}
	
	Type type;
	std::string payload;
	
	std::string encode() const;
	static Message decode(const std::string& encoded);
	
	static bool is_conversation_message(Type type);
};

struct UnsignedConversationMessage
{
	UnsignedConversationMessage() {}
	UnsignedConversationMessage(Message::Type type_, const std::string& payload_): type(type_), payload(payload_) {}
	
	Message::Type type;
	std::string payload;
};

struct ConversationMessage : public UnsignedConversationMessage
{
	PublicKey conversation_public_key;
	Signature signature;
	
	static Message sign(const UnsignedConversationMessage& message, const PrivateKey& key);
	static ConversationMessage decode(const Message& encoded);
	bool verify() const;
};

struct ConversationEvent
{
	ConversationEvent() {}
	ConversationEvent(Message::Type type_, const std::string& payload_): type(type_), payload(payload_) {}
	
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



struct QuitMessage
{
	Hash nonce;
	
	Message encode() const;
	static QuitMessage decode(const Message& encoded);
};

struct HelloMessage
{
	PublicKey long_term_public_key;
	PublicKey ephemeral_public_key;
	bool reply;
	std::string reply_to_username;
	
	Message encode() const;
	static HelloMessage decode(const Message& encoded);
};

struct RoomAuthenticationRequestMessage
{
	std::string username;
	Hash nonce;
	
	Message encode() const;
	static RoomAuthenticationRequestMessage decode(const Message& encoded);
};

struct RoomAuthenticationMessage
{
	std::string username;
	Hash authentication_confirmation;
	
	Message encode() const;
	static RoomAuthenticationMessage decode(const Message& encoded);
};



struct InviteMessage
{
	std::string username;
	PublicKey long_term_public_key;
	
	UnsignedConversationMessage encode() const;
	static InviteMessage decode(const UnsignedConversationMessage& encoded);
};

struct ConversationStatusMessage
{
	struct Participant
	{
		std::string username;
		PublicKey long_term_public_key;
		PublicKey conversation_public_key;
		
		std::set<std::string> timeout_peers;
		std::set<std::string> votekick_peers;
	};
	
	struct ConfirmedInvite
	{
		std::string inviter;
		std::string username;
		PublicKey long_term_public_key;
		PublicKey conversation_public_key;
		bool authenticated;
	};
	
	struct UnconfirmedInvite
	{
		std::string inviter;
		std::string username;
		PublicKey long_term_public_key;
	};
	
	std::string invitee_username;
	PublicKey invitee_long_term_public_key;
	
	std::vector<Participant> participants;
	std::vector<ConfirmedInvite> confirmed_invites;
	std::vector<UnconfirmedInvite> unconfirmed_invites;
	
	Hash conversation_status_hash;
	Hash latest_session_id;
	std::vector<KeyExchangeState> key_exchanges;
	std::vector<ConversationEvent> events;
	
	UnsignedConversationMessage encode() const;
	static ConversationStatusMessage decode(const UnsignedConversationMessage& encoded);
};

struct ConversationConfirmationMessage
{
	std::string invitee_username;
	PublicKey invitee_long_term_public_key;
	Hash status_message_hash;
	
	UnsignedConversationMessage encode() const;
	static ConversationConfirmationMessage decode(const UnsignedConversationMessage& encoded);
};

struct InviteAcceptanceMessage
{
	PublicKey my_long_term_public_key;
	std::string inviter_username;
	PublicKey inviter_long_term_public_key;
	PublicKey inviter_conversation_public_key;
	
	UnsignedConversationMessage encode() const;
	static InviteAcceptanceMessage decode(const UnsignedConversationMessage& encoded);
};

struct AuthenticationRequestMessage
{
	std::string username;
	Hash authentication_nonce;
	
	UnsignedConversationMessage encode() const;
	static AuthenticationRequestMessage decode(const UnsignedConversationMessage& encoded);
};

struct AuthenticationMessage
{
	std::string username;
	Hash authentication_confirmation;
	
	UnsignedConversationMessage encode() const;
	static AuthenticationMessage decode(const UnsignedConversationMessage& encoded);
};

struct AuthenticateInviteMessage
{
	std::string username;
	PublicKey long_term_public_key;
	PublicKey conversation_public_key;
	
	UnsignedConversationMessage encode() const;
	static AuthenticateInviteMessage decode(const UnsignedConversationMessage& encoded);
};

struct CancelInviteMessage
{
	std::string username;
	PublicKey long_term_public_key;
	
	UnsignedConversationMessage encode() const;
	static CancelInviteMessage decode(const UnsignedConversationMessage& encoded);
};

struct JoinMessage
{
	UnsignedConversationMessage encode() const;
	static JoinMessage decode(const UnsignedConversationMessage& encoded);
};



struct LeaveMessage
{
	UnsignedConversationMessage encode() const;
	static LeaveMessage decode(const UnsignedConversationMessage& encoded);
};

struct ConsistencyStatusMessage
{
	UnsignedConversationMessage encode() const;
	static ConsistencyStatusMessage decode(const UnsignedConversationMessage& encoded);
};

struct ConsistencyCheckMessage
{
	Hash conversation_status_hash;
	
	UnsignedConversationMessage encode() const;
	static ConsistencyCheckMessage decode(const UnsignedConversationMessage& encoded);
};

struct TimeoutMessage
{
	std::string victim;
	bool timeout;
	
	UnsignedConversationMessage encode() const;
	static TimeoutMessage decode(const UnsignedConversationMessage& encoded);
};

struct VotekickMessage
{
	std::string victim;
	bool kick;
	
	UnsignedConversationMessage encode() const;
	static VotekickMessage decode(const UnsignedConversationMessage& encoded);
};



struct KeyExchangePublicKeyMessage
{
	Hash key_id;
	PublicKey public_key;
	
	UnsignedConversationMessage encode() const;
	static KeyExchangePublicKeyMessage decode(const UnsignedConversationMessage& encoded);
};

struct KeyExchangeSecretShareMessage
{
	Hash key_id;
	Hash group_hash;
	Hash secret_share;
	
	UnsignedConversationMessage encode() const;
	static KeyExchangeSecretShareMessage decode(const UnsignedConversationMessage& encoded);
};

struct KeyExchangeAcceptanceMessage
{
	Hash key_id;
	Hash key_hash;
	
	UnsignedConversationMessage encode() const;
	static KeyExchangeAcceptanceMessage decode(const UnsignedConversationMessage& encoded);
};

struct KeyExchangeRevealMessage
{
	Hash key_id;
	SerializedPrivateKey private_key;
	
	UnsignedConversationMessage encode() const;
	static KeyExchangeRevealMessage decode(const UnsignedConversationMessage& encoded);
};



struct KeyActivationMessage
{
	Hash key_id;
	
	UnsignedConversationMessage encode() const;
	static KeyActivationMessage decode(const UnsignedConversationMessage& encoded);
};

struct KeyRatchetMessage
{
	Hash key_id;
	
	UnsignedConversationMessage encode() const;
	static KeyRatchetMessage decode(const UnsignedConversationMessage& encoded);
};



struct ChatMessage
{
	Hash key_id;
	std::string encrypted_payload;
	
	UnsignedConversationMessage encode() const;
	static ChatMessage decode(const UnsignedConversationMessage& encoded);
	
	std::string decrypt(const SymmetricKey& symmetric_key) const;
	static ChatMessage encrypt(std::string plaintext, const Hash& key_id, const SymmetricKey& symmetric_key);
};
struct UnsignedChatMessage
{
	uint64_t message_id;
	std::string message;
	
	std::string signed_body() const;
};
struct PlaintextChatMessage : public UnsignedChatMessage
{
	Signature signature;
	
	static std::string sign(const UnsignedChatMessage& message, const PrivateKey& key);
	static PlaintextChatMessage decode(const std::string& encoded);
	bool verify(const PublicKey& key) const;
};



struct ConversationStatusEventPayload {
	std::string invitee_username;
	PublicKey invitee_long_term_public_key;
	Hash status_message_hash;
}; struct ConversationStatusEvent : public ConversationStatusEventPayload {
	std::set<std::string> remaining_users;
	
	ConversationEvent encode(const ConversationStatusMessage& status) const;
	static ConversationStatusEvent decode(const ConversationEvent& encoded, const ConversationStatusMessage& status);
}; struct ConversationConfirmationEvent : public ConversationStatusEventPayload {
	std::set<std::string> remaining_users;
	
	ConversationEvent encode(const ConversationStatusMessage& status) const;
	static ConversationConfirmationEvent decode(const ConversationEvent& encoded, const ConversationStatusMessage& status);
};

struct ConsistencyCheckEventPayload {
	Hash conversation_status_hash;
}; struct ConsistencyCheckEvent : public ConsistencyCheckEventPayload {
	std::set<std::string> remaining_users;
	
	ConversationEvent encode(const ConversationStatusMessage& status) const;
	static ConsistencyCheckEvent decode(const ConversationEvent& encoded, const ConversationStatusMessage& status);
};

struct KeyExchangeEventPayload {
	Message::Type type;
	Hash key_id;
	bool cancelled;
}; struct KeyExchangeEvent : public KeyExchangeEventPayload {
	std::set<std::string> remaining_users;
	
	ConversationEvent encode(const ConversationStatusMessage& status) const;
	static KeyExchangeEvent decode(const ConversationEvent& encooded, const ConversationStatusMessage& status);
};

struct KeyActivationEventPayload {
	Hash key_id;
}; struct KeyActivationEvent : public KeyActivationEventPayload {
	std::set<std::string> remaining_users;
	
	ConversationEvent encode(const ConversationStatusMessage& status) const;
	static KeyActivationEvent decode(const ConversationEvent& encoded, const ConversationStatusMessage& status);
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
