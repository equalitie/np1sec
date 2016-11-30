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

#include "keyexchange.h"
#include "room.h"

namespace np1sec
{

KeyExchange::KeyExchange(const Hash& key_id, const std::map<std::string, PublicKey>& participants, Room* room):
	m_key_id(key_id),
	m_room(room),
	m_state(State::PublicKey),
	m_ephemeral_private_key(PrivateKey::generate(true))
{
	if (!m_room || !participants.count(m_room->username())) {
		m_room = nullptr;
	}
	
	for (const auto& i : participants) {
		Participant participant;
		participant.username = i.first;
		participant.long_term_public_key = i.second;
		participant.has_ephemeral_public_key = false;
		participant.has_secret_share = false;
		participant.has_key_hash = false;
		participant.has_ephemeral_private_key = false;
		m_participants[i.first] = std::move(participant);
	}
	
	m_contributions_remaining = m_participants.size();
}

KeyExchange::KeyExchange(const KeyExchangeState& encoded_state):
	m_room(nullptr)
{
	m_contributions_remaining = 0;
	
	if (encoded_state.state == KeyExchangeState::State::PublicKey) {
		PublicKeyKeyExchangeState state = PublicKeyKeyExchangeState::decode(encoded_state);
		
		m_key_id = state.key_id;
		m_state = State::PublicKey;
		
		std::string previous_username;
		for (const auto& participant : state.participants) {
			if (participant.username < previous_username) {
				throw MessageFormatException();
			}
			if (m_participants.count(participant.username)) {
				throw MessageFormatException();
			}
			previous_username = participant.username;
			
			Participant p;
			p.username = participant.username;
			p.long_term_public_key = participant.long_term_public_key;
			p.has_ephemeral_public_key = participant.has_ephemeral_public_key;
			if (p.has_ephemeral_public_key) {
				p.ephemeral_public_key = participant.ephemeral_public_key;
			} else {
				m_contributions_remaining++;
			}
			p.has_secret_share = false;
			p.has_key_hash = false;
			p.has_ephemeral_private_key = false;
			m_participants[p.username] = p;
		}
	} else if (encoded_state.state == KeyExchangeState::State::SecretShare) {
		SecretShareKeyExchangeState state = SecretShareKeyExchangeState::decode(encoded_state);
		
		m_key_id = state.key_id;
		m_state = State::SecretShare;
		
		std::string previous_username;
		for (const auto& participant : state.participants) {
			if (participant.username < previous_username) {
				throw MessageFormatException();
			}
			if (m_participants.count(participant.username)) {
				throw MessageFormatException();
			}
			previous_username = participant.username;
			
			Participant p;
			p.username = participant.username;
			p.long_term_public_key = participant.long_term_public_key;
			p.has_ephemeral_public_key = true;
			p.ephemeral_public_key = participant.ephemeral_public_key;
			p.has_secret_share = participant.has_secret_share;
			if (p.has_secret_share) {
				p.secret_share = participant.secret_share;
			} else {
				m_contributions_remaining++;
			}
			p.has_key_hash = false;
			p.has_ephemeral_private_key = false;
			m_participants[p.username] = p;
		}
	} else if (encoded_state.state == KeyExchangeState::State::Acceptance) {
		AcceptanceKeyExchangeState state = AcceptanceKeyExchangeState::decode(encoded_state);
		
		m_key_id = state.key_id;
		m_state = State::Acceptance;
		
		std::string previous_username;
		for (const auto& participant : state.participants) {
			if (participant.username < previous_username) {
				throw MessageFormatException();
			}
			if (m_participants.count(participant.username)) {
				throw MessageFormatException();
			}
			previous_username = participant.username;
			
			Participant p;
			p.username = participant.username;
			p.long_term_public_key = participant.long_term_public_key;
			p.has_ephemeral_public_key = true;
			p.ephemeral_public_key = participant.ephemeral_public_key;
			p.has_secret_share = true;
			p.secret_share = participant.secret_share;
			p.has_key_hash = participant.has_key_hash;
			if (p.has_key_hash) {
				p.key_hash = participant.key_hash;
			} else {
				m_contributions_remaining++;
			}
			p.has_ephemeral_private_key = false;
			m_participants[p.username] = p;
		}
	} else if (encoded_state.state == KeyExchangeState::State::Reveal) {
		RevealKeyExchangeState state = RevealKeyExchangeState::decode(encoded_state);
		
		m_key_id = state.key_id;
		m_state = State::Reveal;
		
		std::string previous_username;
		for (const auto& participant : state.participants) {
			if (participant.username < previous_username) {
				throw MessageFormatException();
			}
			if (m_participants.count(participant.username)) {
				throw MessageFormatException();
			}
			previous_username = participant.username;
			
			Participant p;
			p.username = participant.username;
			p.long_term_public_key = participant.long_term_public_key;
			p.has_ephemeral_public_key = true;
			p.ephemeral_public_key = participant.ephemeral_public_key;
			p.has_secret_share = true;
			p.secret_share = participant.secret_share;
			p.has_key_hash = true;
			p.key_hash = participant.key_hash;
			p.has_ephemeral_private_key = participant.has_ephemeral_private_key;
			if (p.has_ephemeral_private_key) {
				p.ephemeral_private_key = participant.ephemeral_private_key;
			} else {
				m_contributions_remaining++;
			}
			m_participants[p.username] = p;
		}
	} else {
		throw MessageFormatException();
	}
	
	if (m_contributions_remaining == 0) {
		throw MessageFormatException();
	}
	
	if (m_state > State::PublicKey) {
		m_group_hash = compute_group_hash();
	}
}

KeyExchangeState KeyExchange::encode() const
{
	if (m_state == State::PublicKey) {
		PublicKeyKeyExchangeState result;
		result.key_id = m_key_id;
		for (const auto& i : m_participants) {
			PublicKeyKeyExchangeState::Participant p;
			p.username = i.second.username;
			p.long_term_public_key = i.second.long_term_public_key;
			p.has_ephemeral_public_key = i.second.has_ephemeral_public_key;
			if (p.has_ephemeral_public_key) {
				p.ephemeral_public_key = i.second.ephemeral_public_key;
			}
			result.participants.push_back(p);
		}
		return result.encode();
	} else if (m_state == State::SecretShare) {
		SecretShareKeyExchangeState result;
		result.key_id = m_key_id;
		for (const auto& i : m_participants) {
			SecretShareKeyExchangeState::Participant p;
			p.username = i.second.username;
			p.long_term_public_key = i.second.long_term_public_key;
			p.ephemeral_public_key = i.second.ephemeral_public_key;
			p.has_secret_share = i.second.has_secret_share;
			if (p.has_secret_share) {
				p.secret_share = i.second.secret_share;
			}
			result.participants.push_back(p);
		}
		return result.encode();
	} else if (m_state == State::Acceptance) {
		AcceptanceKeyExchangeState result;
		result.key_id = m_key_id;
		for (const auto& i : m_participants) {
			AcceptanceKeyExchangeState::Participant p;
			p.username = i.second.username;
			p.long_term_public_key = i.second.long_term_public_key;
			p.ephemeral_public_key = i.second.ephemeral_public_key;
			p.secret_share = i.second.secret_share;
			p.has_key_hash = i.second.has_key_hash;
			if (p.has_key_hash) {
				p.key_hash = i.second.key_hash;
			}
			result.participants.push_back(p);
		}
		return result.encode();
	} else if (m_state == State::Reveal) {
		RevealKeyExchangeState result;
		result.key_id = m_key_id;
		for (const auto& i : m_participants) {
			RevealKeyExchangeState::Participant p;
			p.username = i.second.username;
			p.long_term_public_key = i.second.long_term_public_key;
			p.ephemeral_public_key = i.second.ephemeral_public_key;
			p.secret_share = i.second.secret_share;
			p.key_hash = i.second.key_hash;
			p.has_ephemeral_private_key = i.second.has_ephemeral_private_key;
			if (p.has_ephemeral_private_key) {
				p.ephemeral_private_key = i.second.ephemeral_private_key;
			}
			result.participants.push_back(p);
		}
		return result.encode();
	} else {
		assert(false);
	}
}

bool KeyExchange::contains(const std::string& username) const
{
	return m_participants.count(username) > 0;
}

bool KeyExchange::waiting_for(const std::string& username) const
{
	if (!m_participants.count(username)) {
		return false;
	}
	
	const Participant& participant = m_participants.at(username);
	if (m_state == State::PublicKey) {
		return !participant.has_ephemeral_public_key;
	} else if (m_state == State::SecretShare) {
		return !participant.has_secret_share;
	} else if (m_state == State::Acceptance) {
		return !participant.has_key_hash;
	} else if (m_state == State::Reveal) {
		return !participant.has_ephemeral_private_key;
	} else {
		return false;
	}
}

std::set<std::string> KeyExchange::remaining_users() const
{
	std::set<std::string> output;
	for (const auto& i : m_participants) {
		if (waiting_for(i.first)) {
			output.insert(i.first);
		}
	}
	return output;
}



void KeyExchange::set_public_key(const std::string& username, const PublicKey& public_key)
{
	assert(m_state == State::PublicKey);
	assert(m_participants.count(username));
	assert(!m_participants[username].has_ephemeral_public_key);
	assert(m_contributions_remaining > 0);
	if (m_room && username == m_room->username()) {
		assert(public_key == m_ephemeral_private_key.public_key());
	}
	
	m_participants[username].ephemeral_public_key = public_key;
	m_participants[username].has_ephemeral_public_key = true;
	m_contributions_remaining--;
	if (m_contributions_remaining == 0) {
		finish_public_key();
	}
}

void KeyExchange::set_secret_share(const std::string& username, const Hash& secret_share)
{
	assert(m_state == State::SecretShare);
	assert(m_participants.count(username));
	assert(!m_participants[username].has_secret_share);
	assert(m_contributions_remaining > 0);
	if (m_room && username == m_room->username()) {
		assert(secret_share == m_secret_share);
	}
	
	m_participants[username].secret_share = secret_share;
	m_participants[username].has_secret_share = true;
	m_contributions_remaining--;
	if (m_contributions_remaining == 0) {
		finish_secret_share();
	}
}

void KeyExchange::set_key_hash(const std::string& username, const Hash& key_hash)
{
	assert(m_state == State::Acceptance);
	assert(m_participants.count(username));
	assert(!m_participants[username].has_key_hash);
	assert(m_contributions_remaining > 0);
	if (m_room && username == m_room->username()) {
		assert(key_hash == m_key_hash);
	}
	
	m_participants[username].key_hash = key_hash;
	m_participants[username].has_key_hash = true;
	m_contributions_remaining--;
	if (m_contributions_remaining == 0) {
		finish_acceptance();
	}
}

void KeyExchange::set_private_key(const std::string& username, const SerializedPrivateKey& private_key)
{
	assert(m_state == State::Reveal);
	assert(m_participants.count(username));
	assert(!m_participants[username].has_ephemeral_private_key);
	assert(m_contributions_remaining > 0);
	if (m_room && username == m_room->username()) {
		assert(private_key == m_ephemeral_private_key.serialize());
	}
	
	m_participants[username].ephemeral_private_key = private_key;
	m_participants[username].has_ephemeral_private_key = true;
	m_contributions_remaining--;
	if (m_contributions_remaining == 0) {
		finish_reveal();
	}
}



void KeyExchange::finish_public_key()
{
	assert(m_state == State::PublicKey);
	assert(m_contributions_remaining == 0);
	
	m_contributions_remaining = m_participants.size();
	m_state = State::SecretShare;
	m_group_hash = compute_group_hash();
	
	if (m_room) {
		auto self_iterator = m_participants.find(m_room->username());
		assert(self_iterator != m_participants.end());
		
		const Participant* left_neighbour;
		if (self_iterator == m_participants.begin()) {
			left_neighbour = &m_participants.rbegin()->second;
		} else {
			auto i = self_iterator;
			--i;
			left_neighbour = &i->second;
		}
		
		const Participant* right_neighbour;
		++self_iterator;
		if (self_iterator == m_participants.end()) {
			right_neighbour = &m_participants.begin()->second;
		} else {
			right_neighbour = &self_iterator->second;
		}
		
		auto secret_share = [this] (const Participant* participant) {
			assert(participant->has_ephemeral_public_key);
			Hash token = crypto::triple_diffie_hellman(
				m_room->private_key(),
				m_ephemeral_private_key,
				participant->long_term_public_key,
				participant->ephemeral_public_key
			);
			
			std::string buffer;
			buffer += token.as_string();
			buffer += m_group_hash.as_string();
			return crypto::hash(buffer);
		};
		
		m_right_secret_share = secret_share(right_neighbour);
		Hash left_secret_share = secret_share(left_neighbour);
		for (size_t i = 0; i < sizeof(m_secret_share.buffer); i++) {
			m_secret_share.buffer[i] = m_right_secret_share.buffer[i] ^ left_secret_share.buffer[i];
		}
	}
}

void KeyExchange::finish_secret_share()
{
	assert(m_state == State::SecretShare);
	assert(m_contributions_remaining == 0);
	
	m_contributions_remaining = m_participants.size();
	m_state = State::Acceptance;
	
	if (m_room) {
		std::vector<std::string> users;
		int my_index = -1;
		for (const auto& i : m_participants) {
			if (i.second.username == m_room->username()) {
				my_index = users.size();
			}
			users.push_back(i.second.username);
		}
		assert(my_index != -1);
		
		std::vector<Hash> secret_shares;
		secret_shares.resize(users.size());
		secret_shares[my_index] = m_right_secret_share;
		for (size_t i = 1; i < users.size(); i++) {
			int prev_index = (my_index + i - 1) % users.size();
			int next_index = (my_index + i) % users.size();
			assert(m_participants[users[next_index]].has_secret_share);
			const Hash& user_share = m_participants[users[next_index]].secret_share;
			for (size_t j = 0; j < sizeof(secret_shares[next_index].buffer); j++) {
				secret_shares[next_index].buffer[j] = secret_shares[prev_index].buffer[j] ^ user_share.buffer[j];
			}
		}
		
		std::string buffer;
		for (size_t i = 0; i < secret_shares.size(); i++) {
			buffer += secret_shares[i].as_string();
		}
		m_symmetric_key.key = crypto::hash(buffer, true);
		
		std::string key_hash_buffer;
		key_hash_buffer += m_symmetric_key.key.as_string();
		key_hash_buffer += m_group_hash.as_string();
		m_key_hash = crypto::hash(key_hash_buffer, true);
	}
}

void KeyExchange::finish_acceptance()
{
	assert(m_state == State::Acceptance);
	assert(m_contributions_remaining == 0);
	
	assert(m_participants.begin()->second.has_key_hash);
	Hash first_key_hash = m_participants.begin()->second.key_hash;
	bool consensus = true;
	for (const auto& i : m_participants) {
		assert(i.second.has_key_hash);
		if (i.second.key_hash != first_key_hash) {
			consensus = false;
			break;
		}
	}
	
	if (consensus) {
		m_state = State::KeyAccepted;
	} else {
		m_contributions_remaining = m_participants.size();
		m_state = State::Reveal;
	}
}

void KeyExchange::finish_reveal()
{
	assert(m_state == State::Reveal);
	assert(m_contributions_remaining == 0);
	assert(m_malicious_users.empty());
	
	std::vector<const Participant*> participants;
	std::vector<PrivateKey> private_keys;
	for (const auto& i : m_participants) {
		participants.push_back(&i.second);
		try {
			PrivateKey private_key = PrivateKey::unserialize(i.second.ephemeral_private_key);
			private_keys.push_back(private_key);
			if (private_key.public_key() != i.second.ephemeral_public_key) {
				m_malicious_users.insert(i.second.username);
				continue;
			}
		} catch(CryptoException) {
			m_malicious_users.insert(i.second.username);
		}
	}
	if (!m_malicious_users.empty()) {
		m_state = State::RevealFinished;
		return;
	}
	
	std::vector<Hash> right_secret_shares;
	for (size_t i = 0; i < participants.size(); i++) {
		size_t next = (i + 1) % participants.size();
		Hash token = crypto::reconstruct_triple_diffie_hellman(
			participants[i]->long_term_public_key,
			private_keys[i],
			participants[next]->long_term_public_key,
			private_keys[next]
		);
		std::string buffer;
		buffer += token.as_string();
		buffer += m_group_hash.as_string();
		right_secret_shares.push_back(crypto::hash(buffer));
	}
	
	for (size_t i = 0; i < participants.size(); i++) {
		size_t prev = (i + participants.size() - 1) % participants.size();
		Hash secret_share;
		for (size_t j = 0; j < sizeof(secret_share.buffer); j++) {
			secret_share.buffer[j] = right_secret_shares[i].buffer[j] ^ right_secret_shares[prev].buffer[j];
		}
		if (secret_share != participants[i]->secret_share) {
			m_malicious_users.insert(participants[i]->username);
		}
	}
	if (!m_malicious_users.empty()) {
		m_state = State::RevealFinished;
		return;
	}
	
	std::string buffer;
	for (size_t i = 0; i < right_secret_shares.size(); i++) {
		buffer += right_secret_shares[i].as_string();
	}
	Hash symmetric_key = crypto::hash(buffer);
	
	std::string key_hash_buffer;
	key_hash_buffer += symmetric_key.as_string();
	key_hash_buffer += m_group_hash.as_string();
	Hash key_hash = crypto::hash(key_hash_buffer);
	
	for (size_t i = 0; i < participants.size(); i++) {
		if (participants[i]->key_hash != key_hash) {
			m_malicious_users.insert(participants[i]->username);
		}
	}
	assert (!m_malicious_users.empty());
	m_state = State::RevealFinished;
}



Hash KeyExchange::compute_group_hash() const
{
	assert(m_state >= State::PublicKey);
	std::string buffer;
	for (const auto& i : m_participants) {
		assert(i.second.has_ephemeral_public_key);
		buffer += i.second.username;
		buffer += i.second.long_term_public_key.as_string();
		buffer += i.second.ephemeral_public_key.as_string();
	}
	return crypto::hash(buffer);
}

} // namespace np1sec
