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

#ifndef SRC_KEYEXCHANGE_H_
#define SRC_KEYEXCHANGE_H_

#include "crypto.h"
#include "message.h"

#include <cassert>
#include <map>
#include <set>

namespace np1sec
{

class Room;

class KeyExchange
{
	public:
	enum class State {
		PublicKey,
		SecretShare,
		Acceptance,
		KeyAccepted,
		Reveal,
		RevealFinished,
	};
	
	
	KeyExchange(const Hash& key_id, const std::map<std::string, PublicKey>& participants, Room* room);
	KeyExchange(const KeyExchangeState& state);
	
	KeyExchangeState encode() const;
	
	const Hash& key_id() const
	{
		return m_key_id;
	}
	
	State state() const
	{
		return m_state;
	}
	
	bool contains(const std::string& username) const;
	bool waiting_for(const std::string& username) const;
	
	
	
	/*
	 * Secret state. These fields are computable only for participants in the exchange,
	 * and defined only when constructed with a Room*.
	 */
	/* Defined in any state. */
	const PublicKey& public_key() const
	{
		assert(m_room);
		return m_ephemeral_private_key.public_key();
	}
	
	SerializedPrivateKey private_key() const
	{
		assert(m_room);
		return m_ephemeral_private_key.serialize();
	}
	
	/* Defined from the SecretShare state onwards. */
	const Hash& secret_share() const
	{
		assert(m_room);
		assert(m_state != State::PublicKey);
		return m_secret_share;
	}
	
	/* Defined from the Acceptance state onwards. */
	const Hash& key_hash() const
	{
		assert(m_room);
		assert(m_state >= State::Acceptance);
		return m_key_hash;
	}
	
	/* Defined for the KeyAccepted state only. */
	const SymmetricKey& symmetric_key() const
	{
		assert(m_room);
		assert(m_state == State::KeyAccepted);
		return m_symmetric_key;
	}
	
	
	
	/*
	 * Public state. These fields are computable for anyone.
	 */
	/* Defined from the SecretShare state onwards. */
	const Hash& group_hash() const
	{
		assert(m_state > State::PublicKey);
		return m_group_hash;
	}
	
	/* Defined for the KeyAccepted state only. */
	std::map<std::string, PublicKey> public_keys() const
	{
		assert(m_state == State::KeyAccepted);
		std::map<std::string, PublicKey> output;
		for (const auto& i : m_participants) {
			assert(i.second.has_ephemeral_public_key);
			output[i.second.username] = i.second.ephemeral_public_key;
		}
		return output;
	}
	
	/* Defined for the RevealFinished state only. */
	const std::set<std::string>& malicious_users() const
	{
		assert(m_state == State::RevealFinished);
		return m_malicious_users;
	}
	
	
	
	/*
	 * Operations
	 */
	/* Valid only in the PublicKey state. */
	void set_public_key(const std::string& username, const PublicKey& public_key);
	
	/* Valid only in the SecretShare state. */
	void set_secret_share(const std::string& username, const Hash& secret_share);
	
	/* Valid only in the Acceptance state. */
	void set_key_hash(const std::string& username, const Hash& key_hash);
	
	/* Valid only in the Reveal state. */
	void set_private_key(const std::string& username, const SerializedPrivateKey& private_key);
	
	
	
	protected:
	void finish_public_key();
	void finish_secret_share();
	void finish_acceptance();
	void finish_reveal();
	
	Hash compute_group_hash() const;
	
	
	
	protected:
	struct Participant
	{
		std::string username;
		PublicKey long_term_public_key;
		
		bool has_ephemeral_public_key;
		PublicKey ephemeral_public_key;
		
		bool has_secret_share;
		Hash secret_share;
		
		bool has_key_hash;
		Hash key_hash;
		
		bool has_ephemeral_private_key;
		SerializedPrivateKey ephemeral_private_key;
	};
	
	Hash m_key_id;
	std::map<std::string, Participant> m_participants;
	Room* m_room;
	
	State m_state;
	int m_contributions_remaining;
	
	PrivateKey m_ephemeral_private_key;
	Hash m_right_secret_share;
	Hash m_secret_share;
	SymmetricKey m_symmetric_key;
	Hash m_key_hash;
	
	Hash m_group_hash;
	std::set<std::string> m_malicious_users;
};

} // namespace np1sec

#endif
