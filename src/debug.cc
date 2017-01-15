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

#include "debug.h"

std::ostream& operator<<(std::ostream& os, np1sec::Message::Type type)
{
	using Type = np1sec::Message::Type;

	switch (type) {
		case Type::Quit: os << "Quit"; break;
		case Type::Hello: os << "Hello"; break;
		case Type::RoomAuthenticationRequest: os << "RoomAuthenticationRequest"; break;
		case Type::RoomAuthentication: os << "RoomAuthentication"; break;

		case Type::Invite: os << "Invite"; break;
		case Type::ConversationStatus: os << "ConversationStatus"; break;
		case Type::ConversationConfirmation: os << "ConversationConfirmation"; break;
		case Type::InviteAcceptance: os << "InviteAcceptance"; break;
		case Type::AuthenticationRequest: os << "AuthenticationRequest"; break;
		case Type::Authentication: os << "Authentication"; break;
		case Type::AuthenticateInvite: os << "AuthenticateInvite"; break;
		case Type::CancelInvite: os << "CancelInvite"; break;
		case Type::Join: os << "Join"; break;

		case Type::Leave: os << "Leave"; break;
		case Type::ConsistencyStatus: os << "ConsistencyStatus"; break;
		case Type::ConsistencyCheck: os << "ConsistencyCheck"; break;
		case Type::Timeout: os << "Timeout"; break;
		case Type::Votekick: os << "Votekick"; break;

		case Type::KeyExchangePublicKey: os << "KeyExchangePublicKey"; break;
		case Type::KeyExchangeSecretShare: os << "KeyExchangeSecretShare"; break;
		case Type::KeyExchangeAcceptance: os << "KeyExchangeAcceptance"; break;
		case Type::KeyExchangeReveal: os << "KeyExchangeReveal"; break;

		case Type::KeyActivation: os << "KeyActivation"; break;
		case Type::KeyRatchet: os << "KeyRatchet"; break;
		case Type::Chat: os << "Chat"; break;
	}

	return os;
}

std::ostream& operator<<(std::ostream& os, const np1sec::Hash& hash)
{
	return os << hash.dump_hex().substr(0, 8);
}

std::ostream& operator<<(std::ostream& os, const np1sec::HelloMessage& msg)
{
	os << "reply:" << msg.reply << " reply_to_username:" << msg.reply_to_username;
	return os;
}

std::ostream& operator<<(std::ostream& os, const np1sec::RoomAuthenticationRequestMessage& msg)
{
	os << "username:" << msg.username;
	return os;
}

std::ostream& operator<<(std::ostream& os, const np1sec::RoomAuthenticationMessage& msg)
{
	os << "username:" << msg.username
		<< " authentication_confirmation:" << msg.authentication_confirmation;
	return os;
}

std::ostream& operator<<(std::ostream& os, const np1sec::InviteMessage& msg)
{
	os << "username:" << msg.username;
	return os;
}

std::ostream& operator<<(std::ostream& os, const np1sec::ConsistencyCheckMessage& msg)
{
	os << "conversation_status_hash:" << msg.conversation_status_hash;
	return os;
}

template<class R> struct Range {
	const R& inner;
};

template<class R> Range<R> range(const R& inner) {
	return Range<R>{inner};
}

template<class R>
std::ostream& operator<<(std::ostream& os, const Range<R>& r)
{
	auto& range = r.inner;

	os << "[";
	for (auto i = range.begin(); i != range.end(); ++i) {
		if (i != range.begin()) os << ", ";
		os << *i;
	}
	return os << "]";
}

std::ostream& operator<<(std::ostream& os, const np1sec::ConversationStatusMessage::Participant& p)
{
	return os << p.username;
}

std::ostream& operator<<(std::ostream& os, const np1sec::ConversationStatusMessage::ConfirmedInvite& i)
{
	return os << "inviter:" << i.username
		<< " username:" << i.username
		<< " authenticated:" << i.authenticated;
}

std::ostream& operator<<(std::ostream& os, const np1sec::ConversationStatusMessage::UnconfirmedInvite& i)
{
	return os << "inviter:" << i.username
		<< " username:" << i.username;
}

std::ostream& operator<<(std::ostream& os, const np1sec::KeyExchangeState::State& state)
{
	using S = np1sec::KeyExchangeState::State;

	switch (state) {
		case S::PublicKey: os << "PublicKey"; break;
		case S::SecretShare: os << "SecretShare"; break;
		case S::Acceptance: os << "Acceptance"; break;
		case S::Reveal: os << "Reveal"; break;
	}

	return os;
}

std::ostream& operator<<(std::ostream& os, const np1sec::KeyExchangeState& state)
{
	os << "key_id:" << state.key_id
		<< " state:" << state.state;
	return os;
}

std::ostream& operator<<(std::ostream& os, const np1sec::ConversationEvent& e)
{
	return os << "type:" << e.type;
}

std::ostream& operator<<(std::ostream& os, const np1sec::ConversationStatusMessage& msg)
{
	os << "invitee_username:" << msg.invitee_username
		<< " participants:" << range(msg.participants)
		<< " confirmed_invites:" << range(msg.confirmed_invites)
		<< " unconfirmed_invites:" << range(msg.unconfirmed_invites)
		<< " conversation_status_hash:" << msg.conversation_status_hash
		<< " latest_session_id:" << msg.latest_session_id
		<< " key_exchanges:" << range(msg.key_exchanges)
		<< " events:" << range(msg.events);
	return os;
}

std::ostream& operator<<(std::ostream& os, const np1sec::ConversationConfirmationMessage& msg)
{
	os << "invitee_username:" << msg.invitee_username
		<< " status_message_hash:" << msg.status_message_hash;
	return os;
}

std::ostream& operator<<(std::ostream& os, const np1sec::InviteAcceptanceMessage& msg)
{
	os << "inviter_username:" << msg.inviter_username;
	return os;
}

std::ostream& operator<<(std::ostream& os, const np1sec::AuthenticationRequestMessage& msg)
{
	os << "username:" << msg.username
		<< " authentication_nonce:" << msg.authentication_nonce;
	return os;
}

std::ostream& operator<<(std::ostream& os, const np1sec::AuthenticationMessage& msg)
{
	os << "username:" << msg.username
		<< " authentication_confirmation:" << msg.authentication_confirmation;
	return os;
}

std::ostream& operator<<(std::ostream& os, const np1sec::AuthenticateInviteMessage& msg)
{
	os << "username:" << msg.username;
	return os;
}

std::ostream& operator<<(std::ostream& os, const np1sec::KeyExchangePublicKeyMessage& msg)
{
	os << "key_id:" << msg.key_id;
	return os;
}

std::ostream& operator<<(std::ostream& os, const np1sec::KeyExchangeSecretShareMessage& msg)
{
	os << "key_id:" << msg.key_id
		<< " group_hash:" << msg.group_hash
		<< " secret_share:" << msg.secret_share;
	return os;
}

std::ostream& operator<<(std::ostream& os, const np1sec::KeyExchangeAcceptanceMessage& msg)
{
	os << "key_id:" << msg.key_id
		<< " key_hash:" << msg.key_hash;
	return os;
}

std::ostream& operator<<(std::ostream& os, const np1sec::KeyActivationMessage& msg)
{
	os << "key_id:" << msg.key_id;
	return os;
}

std::ostream& operator<<(std::ostream& os, const np1sec::KeyRatchetMessage& msg)
{
	os << "key_id:" << msg.key_id;
	return os;
}

std::ostream& operator<<(std::ostream& os, const np1sec::Message& msg)
{
	using namespace np1sec;
	using Type = Message::Type;

	os << msg.type << " ";

	switch (msg.type) {
		case Type::Hello: os << HelloMessage::decode(msg); break;
		case Type::RoomAuthenticationRequest: os << RoomAuthenticationRequestMessage::decode(msg); break;
		case Type::RoomAuthentication: os << RoomAuthenticationMessage::decode(msg); break;
		case Type::Invite: os << InviteMessage::decode(ConversationMessage::decode(msg)); break;
		case Type::ConsistencyCheck: os << ConsistencyCheckMessage::decode(ConversationMessage::decode(msg)); break;
		case Type::ConversationStatus: os << ConversationStatusMessage::decode(ConversationMessage::decode(msg)); break;
		case Type::ConversationConfirmation: os << ConversationConfirmationMessage::decode(ConversationMessage::decode(msg)); break;
		case Type::InviteAcceptance: os << InviteAcceptanceMessage::decode(ConversationMessage::decode(msg)); break;
		case Type::AuthenticationRequest: os << AuthenticationRequestMessage::decode(ConversationMessage::decode(msg)); break;
		case Type::Authentication: os << AuthenticationMessage::decode(ConversationMessage::decode(msg)); break;
		case Type::AuthenticateInvite: os << AuthenticateInviteMessage::decode(ConversationMessage::decode(msg)); break;
		case Type::Join: break;
		case Type::KeyExchangePublicKey: os << KeyExchangePublicKeyMessage::decode(ConversationMessage::decode(msg)); break;
		case Type::KeyExchangeSecretShare: os << KeyExchangeSecretShareMessage::decode(ConversationMessage::decode(msg)); break;
		case Type::KeyExchangeAcceptance: os << KeyExchangeAcceptanceMessage::decode(ConversationMessage::decode(msg)); break;
		case Type::KeyActivation: os << KeyActivationMessage::decode(ConversationMessage::decode(msg)); break;
		case Type::ConsistencyStatus: break;
		case Type::KeyRatchet: os << KeyRatchetMessage::decode(ConversationMessage::decode(msg)); break;
		default: os << "TODO"; break;
	}

	return os;	
}
