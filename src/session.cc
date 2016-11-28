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
#include "room.h"
#include "session.h"

namespace np1sec
{

Session::Session(Conversation* conversation, const Hash& key_id, const std::vector<KeyExchange::AcceptedUser>& users, const SymmetricKey& symmetric_key, const PrivateKey& private_key):
	m_conversation(conversation),
	m_key_id(key_id),
	m_symmetric_key(symmetric_key),
	m_private_key(private_key),
	m_signature_id(1)
{
	for (const KeyExchange::AcceptedUser& user : users) {
		Participant participant;
		participant.username = user.username;
		participant.long_term_public_key = user.long_term_public_key;
		participant.ephemeral_public_key = user.ephemeral_public_key;
		participant.signature_id = 1;
		m_participants[user.username] = std::move(participant);
	}
}

void Session::send_message(const std::string& message)
{
	UnsignedChatMessage payload;
	payload.message_id = m_signature_id++;
	payload.message = message;
	
	std::string signed_payload = PlaintextChatMessage::sign(payload, m_private_key);
	
	ChatMessage encrypted = ChatMessage::encrypt(signed_payload, m_key_id, m_symmetric_key);
	
	m_conversation->send_message(encrypted.encode());
}

void Session::decrypt_message(const std::string& sender, const ChatMessage& encrypted_message)
{
	assert(m_participants.count(sender));
	
	try {
		std::string decrypted_payload = encrypted_message.decrypt(m_symmetric_key);
		
		PlaintextChatMessage payload = PlaintextChatMessage::decode(decrypted_payload);
		
		if (!payload.verify(m_participants.at(sender).ephemeral_public_key)) {
			return;
		}
		
		if (payload.message_id != m_participants.at(sender).signature_id) {
			return;
		}
		m_participants[sender].signature_id++;
		
		if (m_conversation->interface()) m_conversation->interface()->message_received(sender, payload.message);
	} catch(MessageFormatException) {}
}

} // namespace np1sec
