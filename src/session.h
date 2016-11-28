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

#ifndef SRC_SESSION_H_
#define SRC_SESSION_H_

#include "crypto.h"
#include "keyexchange.h"

#include <map>

namespace np1sec
{

class Conversation;

class Session
{
	public:
	Session(Conversation* conversation, const Hash& key_id, const std::vector<KeyExchange::AcceptedUser>& users, const SymmetricKey& symmetric_key, const PrivateKey& private_key);
	
	void send_message(const std::string& message);
	void decrypt_message(const std::string& sender, const ChatMessage& encrypted_message);
	
	protected:
	struct Participant
	{
		std::string username;
		PublicKey long_term_public_key;
		PublicKey ephemeral_public_key;
		uint64_t signature_id;
	};
	
	Conversation* m_conversation;
	Hash m_key_id;
	std::map<std::string, Participant> m_participants;
	SymmetricKey m_symmetric_key;
	PrivateKey m_private_key;
	uint64_t m_signature_id;
};

} // namespace np1sec

#endif
