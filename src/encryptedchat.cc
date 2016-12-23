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
#include "encryptedchat.h"
#include "room.h"

#include <cassert>

namespace np1sec
{

// timeout, in milliseconds, after which a session gets replaced
const uint32_t c_session_ratchet_timeout = 120000;

EncryptedChat::EncryptedChat(Conversation* conversation):
	m_conversation(conversation)
{}

void EncryptedChat::unserialize_key_exchange(const KeyExchangeState& exchange)
{
	assert(!m_key_exchanges.count(exchange.key_id));
	
	std::unique_ptr<KeyExchange> key_exchange(new KeyExchange(exchange));
	insert_key_exchange(std::move(key_exchange));
}

std::vector<KeyExchangeState> EncryptedChat::encode_key_exchanges() const
{
	std::vector<KeyExchangeState> output;
	if (m_key_exchanges.empty()) {
		return output;
	}
	Hash key_id = m_key_exchange_first;
	while (true) {
		assert(m_key_exchanges.count(key_id));
		const KeyExchangeData& exchange = m_key_exchanges.at(key_id);
		output.push_back(exchange.key_exchange->encode());
		if (exchange.has_next) {
			key_id = exchange.next;
		} else {
			break;
		}
	}
	return output;
}

bool EncryptedChat::replacing_session(const Hash& key_id) const
{
	return !m_key_exchanges.empty() || m_latest_session_id != key_id;
}

bool EncryptedChat::joined() const
{
	return user_joined(m_conversation->room()->username());
}

bool EncryptedChat::user_joined(const std::string& username) const
{
	return m_participants.count(username) && m_participants.at(username).active;
}

void EncryptedChat::initialize_latest_session(const Hash& session_id)
{
	m_latest_session_id = session_id;
}

void EncryptedChat::create_solo_session(const Hash& session_id)
{
	m_latest_session_id = session_id;
	
	Participant self;
	self.username = m_conversation->room()->username();
	self.long_term_public_key = m_conversation->room()->public_key();
	self.active = true;
	self.have_active_session = true;
	self.active_session = session_id;
	self.session_list.push_back(session_id);
	m_participants[self.username] = self;
	
	m_session_queue.push_back(session_id);
	
	PrivateKey session_private_key = PrivateKey::generate(true);
	KeyExchange::AcceptedUser self_user;
	self_user.username = m_conversation->room()->username();
	self_user.long_term_public_key = m_conversation->room()->public_key();
	self_user.ephemeral_public_key = session_private_key.public_key();
	std::vector<KeyExchange::AcceptedUser> accepted_users;
	accepted_users.push_back(std::move(self_user));
	
	SymmetricKey session_symmetric_key;
	session_symmetric_key.key = crypto::nonce_hash();
	
	SessionData session;
	session.active = true;
	session.participants.insert(self);
	session.session = std::unique_ptr<Session>(new Session(m_conversation, session_id, accepted_users, session_symmetric_key, session_private_key));
	m_sessions[session_id] = std::move(session);
	
	prepare_session_replacement(session_id);
}

void EncryptedChat::add_user(const std::string& username, const PublicKey& long_term_public_key)
{
	do_add_user(username, long_term_public_key);
	create_key_exchange();
}

void EncryptedChat::do_add_user(const std::string& username, const PublicKey& long_term_public_key)
{
	assert(!m_participants.count(username));
	
	Participant participant;
	participant.username = username;
	participant.long_term_public_key = long_term_public_key;
	participant.active = false;
	participant.have_active_session = false;
	m_participants[username] = participant;
}

void EncryptedChat::remove_users(const std::set<std::string>& usernames)
{
	bool removed = false;
	bool active_session = false;
	for (const std::string& username : usernames) {
		if (!m_participants.count(username)) {
			continue;
		}
		
		while (!m_participants[username].key_exchanges.empty()) {
			Hash key_id = *m_participants[username].key_exchanges.begin();
			erase_key_exchange(key_id);
		}
		
		if (!m_participants[username].session_list.empty()) {
			active_session = true;
			Identity identity;
			identity.username = username;
			identity.long_term_public_key = m_participants[username].long_term_public_key;
			
			m_former_participants[identity].username = identity.username;
			m_former_participants[identity].long_term_public_key = identity.long_term_public_key;
			m_former_participants[identity].session_list = m_participants[username].session_list;
			
			for (const Hash& key_id : m_participants[username].session_list) {
				assert(m_sessions.count(key_id));
				assert(m_sessions[key_id].participants.count(identity));
				m_sessions[key_id].participants.erase(identity);
				m_sessions[key_id].former_participants.insert(identity);
			}
		}
		
		m_participants.erase(username);
		
		removed = true;
	}
	if (removed && !m_participants.empty()) {
		create_key_exchange();
	}
	if (active_session) {
		progress_sessions();
	}
}

void EncryptedChat::user_public_key(const std::string& username, const Hash& key_id, const PublicKey& public_key)
{
	assert(m_participants.count(username));
	assert(m_key_exchanges.count(key_id));
	assert(m_key_exchanges.at(key_id).key_exchange->state() == KeyExchange::State::PublicKey);
	m_key_exchanges[key_id].key_exchange->set_public_key(username, public_key);
	if (m_key_exchanges.at(key_id).key_exchange->state() == KeyExchange::State::SecretShare) {
		m_conversation->add_key_exchange_event(Message::Type::KeyExchangeSecretShare, key_id, m_key_exchanges.at(key_id).key_exchange->users());
		
		if (m_key_exchanges[key_id].key_exchange->contains(m_conversation->room()->username())) {
			KeyExchangeSecretShareMessage message;
			message.key_id = key_id;
			message.group_hash = m_key_exchanges[key_id].key_exchange->group_hash();
			message.secret_share = m_key_exchanges[key_id].key_exchange->secret_share();
			m_conversation->send_message(message.encode());
		}
	}
}

void EncryptedChat::user_secret_share(const std::string& username, const Hash& key_id, const Hash& group_hash, const Hash& secret_share)
{
	assert(m_participants.count(username));
	assert(m_key_exchanges.count(key_id));
	assert(m_key_exchanges.at(key_id).key_exchange->state() == KeyExchange::State::SecretShare);
	if (m_key_exchanges.at(key_id).key_exchange->group_hash() != group_hash) {
		m_conversation->remove_user(username);
		return;
	}
	m_key_exchanges[key_id].key_exchange->set_secret_share(username, secret_share);
	if (m_key_exchanges.at(key_id).key_exchange->state() == KeyExchange::State::Acceptance) {
		m_conversation->add_key_exchange_event(Message::Type::KeyExchangeAcceptance, key_id, m_key_exchanges.at(key_id).key_exchange->users());
		
		if (m_key_exchanges[key_id].key_exchange->contains(m_conversation->room()->username())) {
			KeyExchangeAcceptanceMessage message;
			message.key_id = key_id;
			message.key_hash = m_key_exchanges[key_id].key_exchange->key_hash();
			m_conversation->send_message(message.encode());
		}
	}
}

void EncryptedChat::user_key_hash(const std::string& username, const Hash& key_id, const Hash& key_hash)
{
	assert(m_participants.count(username));
	assert(m_key_exchanges.count(key_id));
	assert(m_key_exchanges.at(key_id).key_exchange->state() == KeyExchange::State::Acceptance);
	m_key_exchanges[key_id].key_exchange->set_key_hash(username, key_hash);
	if (m_key_exchanges.at(key_id).key_exchange->state() == KeyExchange::State::KeyAccepted) {
		m_conversation->add_key_exchange_event(Message::Type::KeyActivation, key_id, m_key_exchanges.at(key_id).key_exchange->users());
		m_latest_session_id = key_id;
		
		if (m_key_exchanges[key_id].key_exchange->contains(m_conversation->room()->username())) {
			create_session(key_id);
		}
		
		while (m_key_exchange_first != key_id) {
			erase_key_exchange(m_key_exchange_first);
		}
		erase_key_exchange(key_id);
	} else if (m_key_exchanges.at(key_id).key_exchange->state() == KeyExchange::State::Reveal) {
		m_conversation->add_key_exchange_event(Message::Type::KeyExchangeReveal, key_id, m_key_exchanges.at(key_id).key_exchange->users());
		
		if (m_key_exchanges[key_id].key_exchange->contains(m_conversation->room()->username())) {
			KeyExchangeRevealMessage message;
			message.key_id = key_id;
			message.private_key = m_key_exchanges[key_id].key_exchange->serialized_private_key();
			m_conversation->send_message(message.encode());
		}
	}
}

void EncryptedChat::user_private_key(const std::string& username, const Hash& key_id, const SerializedPrivateKey& private_key)
{
	assert(m_participants.count(username));
	assert(m_key_exchanges.count(key_id));
	assert(m_key_exchanges.at(key_id).key_exchange->state() == KeyExchange::State::Reveal);
	m_key_exchanges[key_id].key_exchange->set_private_key(username, private_key);
	if (m_key_exchanges.at(key_id).key_exchange->state() == KeyExchange::State::RevealFinished) {
		std::set<std::string> malicious_users = m_key_exchanges.at(key_id).key_exchange->malicious_users();
		
		erase_key_exchange(key_id);
		
		m_conversation->remove_users(malicious_users);
	}
}

void EncryptedChat::user_activation(const std::string& username, const Hash& key_id)
{
	assert(m_participants.count(username));
	assert(!m_sessions.empty());
	m_participants[username].have_active_session = true;
	m_participants[username].active_session = key_id;
	progress_sessions();
}

void EncryptedChat::replace_session(const Hash& key_id)
{
	if (m_key_exchanges.empty() && m_latest_session_id == key_id) {
		create_key_exchange();
	}
}

void EncryptedChat::send_message(const std::string& message)
{
	assert(m_participants.count(m_conversation->room()->username()));
	assert(m_participants.at(m_conversation->room()->username()).active);
	
	const Hash& key_id = m_session_queue.back();
	m_sessions[key_id].session->send_message(message);
}

void EncryptedChat::decrypt_message(const std::string& sender, const ChatMessage& encrypted_message)
{
	if (!m_participants.count(sender)) {
		return;
	}
	
	if (!m_participants.at(sender).active) {
		return;
	}
	
	if (!m_participants.at(sender).have_active_session) {
		return;
	}
	
	const Hash& key_id = m_participants.at(sender).active_session;
	m_sessions[key_id].session->decrypt_message(sender, encrypted_message);
}

void EncryptedChat::insert_key_exchange(std::unique_ptr<KeyExchange>&& key_exchange)
{
	Hash key_id = key_exchange->key_id();
	for (const std::string& username : key_exchange->users()) {
		assert(m_participants.count(username));
		m_participants[username].key_exchanges.insert(key_id);
	}
	
	bool empty = m_key_exchanges.empty();
	m_key_exchanges[key_id].key_exchange = std::move(key_exchange);
	if (empty) {
		m_key_exchange_first = key_id;
		m_key_exchanges[key_id].has_previous = false;
	} else {
		m_key_exchanges[key_id].has_previous = true;
		m_key_exchanges[key_id].previous = m_key_exchange_last;
		m_key_exchanges[m_key_exchange_last].has_next = true;
		m_key_exchanges[m_key_exchange_last].next = key_id;
	}
	m_key_exchanges[key_id].has_next = false;
	m_key_exchange_last = key_id;
}

void EncryptedChat::erase_key_exchange(Hash key_id)
{
	const KeyExchangeData& exchange = m_key_exchanges[key_id];
	if (exchange.has_previous) {
		assert(m_key_exchanges.count(exchange.previous));
		assert(m_key_exchanges[exchange.previous].has_next);
		assert(m_key_exchanges[exchange.previous].next == key_id);
		if (exchange.has_next) {
			m_key_exchanges[exchange.previous].next = exchange.next;
		} else {
			m_key_exchanges[exchange.previous].has_next = false;
		}
	} else {
		if (exchange.has_next) {
			m_key_exchanges[exchange.next].has_previous = false;
			m_key_exchange_first = exchange.next;
		}
	}
	if (exchange.has_next) {
		assert(m_key_exchanges.count(exchange.next));
		assert(m_key_exchanges[exchange.next].has_previous);
		assert(m_key_exchanges[exchange.next].previous == key_id);
		if (exchange.has_previous) {
			m_key_exchanges[exchange.next].previous = exchange.previous;
		} else {
			m_key_exchanges[exchange.next].has_previous = false;
		}
	} else {
		if (exchange.has_previous) {
			m_key_exchanges[exchange.previous].has_next = false;
			m_key_exchange_last = exchange.previous;
		}
	}
	for (const std::string& username : exchange.key_exchange->users()) {
		assert(m_participants.count(username));
		m_participants[username].key_exchanges.erase(key_id);
	}
	m_key_exchanges.erase(key_id);
}

void EncryptedChat::create_key_exchange()
{
	Hash key_id = m_conversation->conversation_status_hash();
	
	assert(!m_key_exchanges.count(key_id));
	std::map<std::string, PublicKey> users;
	for (const auto& i : m_participants) {
		users[i.second.username] = i.second.long_term_public_key;
	}
	std::unique_ptr<KeyExchange> exchange(new KeyExchange(key_id, users, m_conversation->room()));
	insert_key_exchange(std::move(exchange));
	
	m_conversation->add_key_exchange_event(Message::Type::KeyExchangePublicKey, key_id, m_key_exchanges.at(key_id).key_exchange->users());
	
	if (m_key_exchanges[key_id].key_exchange->contains(m_conversation->room()->username())) {
		KeyExchangePublicKeyMessage message;
		message.key_id = key_id;
		message.public_key = m_key_exchanges[key_id].key_exchange->public_key();
		m_conversation->send_message(message.encode());
	}
}

void EncryptedChat::create_session(const Hash& key_id)
{
	assert(m_key_exchanges.count(key_id));
	assert(m_key_exchanges.at(key_id).key_exchange->state() == KeyExchange::State::KeyAccepted);
	assert(m_key_exchanges.at(key_id).key_exchange->contains(m_conversation->room()->username()));
	assert(!m_sessions.count(key_id));
	
	std::vector<KeyExchange::AcceptedUser> users = m_key_exchanges.at(key_id).key_exchange->accepted_users();
	std::unique_ptr<Session> session(new Session(m_conversation, key_id, users, m_key_exchanges.at(key_id).key_exchange->symmetric_key(), m_key_exchanges.at(key_id).key_exchange->private_key()));
	
	for (const auto& user : users) {
		m_participants[user.username].session_list.push_back(key_id);
	}
	
	m_session_queue.push_back(key_id);
	m_sessions[key_id].session = std::move(session);
	m_sessions[key_id].active = false;
	for (const auto& i : users) {
		Identity identity;
		identity.username = i.username;
		identity.long_term_public_key = i.long_term_public_key;
		m_sessions[key_id].participants.insert(identity);
	}
	
	KeyActivationMessage message;
	message.key_id = key_id;
	m_conversation->send_message(message.encode());
	
	prepare_session_replacement(key_id);
}

void EncryptedChat::prepare_session_replacement(Hash key_id)
{
	m_session_ratchet_timer = Timer(m_conversation->room()->interface(), c_session_ratchet_timeout, [key_id, this] {
		if (m_key_exchanges.empty() && m_latest_session_id == key_id) {
			KeyRatchetMessage message;
			message.key_id = key_id;
			m_conversation->send_message(message.encode());
		}
	});
}

void EncryptedChat::progress_sessions()
{
	while (!m_session_queue.empty()) {
		const Hash& key_id = m_session_queue.front();
		const SessionData& data = m_sessions.at(key_id);
		
		if (!data.active) {
			bool activated = true;
			for (const Identity& identity : data.participants) {
				assert(!m_participants[identity.username].session_list.empty());
				assert(m_participants[identity.username].session_list.front() == key_id);
				if (!m_participants[identity.username].have_active_session) {
					activated = false;
					break;
				}
			}
			if (activated) {
				bool self_active = joined();
				
				for (const Identity& identity : data.participants) {
					// user joined / self joined
					if (!m_participants[identity.username].active) {
						m_participants[identity.username].active = true;
						if (self_active) {
							if (m_conversation->interface()) m_conversation->interface()->user_joined(identity.username);
						}
					}
				}
				m_sessions[key_id].active = true;
				
				if (!self_active) {
					if (m_conversation->interface()) m_conversation->interface()->joined();
				}
			}
		}
		
		bool keep = false;
		for (const Identity& identity : data.participants) {
			assert(!m_participants[identity.username].session_list.empty());
			assert(m_participants[identity.username].session_list.front() == key_id);
			if (!m_participants[identity.username].have_active_session || m_participants[identity.username].active_session == key_id) {
				keep = true;
				break;
			}
		}
		if (keep) {
			break;
		}
		
		for (const Identity& identity : data.participants) {
			m_participants[identity.username].session_list.pop_front();
		}
		for (const Identity& identity : data.former_participants) {
			m_former_participants[identity].session_list.pop_front();
			if (m_former_participants[identity].session_list.empty()) {
				m_former_participants.erase(identity);
			}
		}
		m_sessions.erase(key_id);
		m_session_queue.pop_front();
	}
}

} // namespace np1sec
