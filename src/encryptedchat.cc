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

#include "channel.h"
#include "encryptedchat.h"
#include "room.h"

#include <cassert>

namespace np1sec
{

EncryptedChat::EncryptedChat(Channel* channel):
	m_channel(channel)
{}

void EncryptedChat::unserialize_key_exchange(const KeyExchangeState& exchange)
{
	assert(!m_key_exchanges.count(exchange.key_id));
	
	std::unique_ptr<KeyExchange> key_exchange(new KeyExchange(exchange));
	m_key_exchanges[exchange.key_id] = std::move(key_exchange);
	m_key_exchange_queue.push_back(exchange.key_id);
}

std::vector<KeyExchangeState> EncryptedChat::encode_key_exchanges() const
{
	std::vector<KeyExchangeState> output;
	for (const Hash& key_id : m_key_exchange_queue) {
		assert(m_key_exchanges.count(key_id));
		output.push_back(m_key_exchanges.at(key_id)->encode());
	}
	return output;
}

bool EncryptedChat::in_chat() const
{
	return user_in_chat(m_channel->room()->username());
}

bool EncryptedChat::user_in_chat(const std::string& username) const
{
	return m_participants.count(username) && m_participants.at(username).active;
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
	m_participants[username] = participant;
}

void EncryptedChat::remove_users(const std::set<std::string>& usernames)
{
	bool removed = false;
	bool active_session = false;
	for (const std::string& username : usernames) {
		if (m_participants.count(username)) {
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
			
			for (std::vector<Hash>::iterator i = m_key_exchange_queue.begin(); i != m_key_exchange_queue.end(); ) {
				assert(m_key_exchanges.count(*i));
				if (m_key_exchanges.at(*i)->contains(username)) {
					m_key_exchanges.erase(*i);
					i = m_key_exchange_queue.erase(i);
				} else {
					++i;
				}
			}
			
			removed = true;
		}
	}
	if (removed) {
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
	assert(m_key_exchanges.at(key_id)->state() == KeyExchange::State::PublicKey);
	m_key_exchanges[key_id]->set_public_key(username, public_key);
	if (m_key_exchanges.at(key_id)->state() == KeyExchange::State::SecretShare) {
		m_channel->add_key_exchange_event(Message::Type::KeyExchangeSecretShare, key_id, m_key_exchanges.at(key_id)->users());
		
		if (m_key_exchanges[key_id]->contains(m_channel->room()->username())) {
			UnsignedKeyExchangeSecretShareMessage message;
			message.key_id = key_id;
			message.group_hash = m_key_exchanges[key_id]->group_hash();
			message.secret_share = m_key_exchanges[key_id]->secret_share();
			m_channel->room()->send_message(KeyExchangeSecretShareMessage::sign(message, m_channel->ephemeral_private_key(), m_channel->new_signature_id()));
		}
	}
}

void EncryptedChat::user_secret_share(const std::string& username, const Hash& key_id, const Hash& group_hash, const Hash& secret_share)
{
	assert(m_participants.count(username));
	assert(m_key_exchanges.count(key_id));
	assert(m_key_exchanges.at(key_id)->state() == KeyExchange::State::SecretShare);
	if (m_key_exchanges.at(key_id)->group_hash() != group_hash) {
		m_channel->remove_user(username);
		return;
	}
	m_key_exchanges[key_id]->set_secret_share(username, secret_share);
	if (m_key_exchanges.at(key_id)->state() == KeyExchange::State::Acceptance) {
		m_channel->add_key_exchange_event(Message::Type::KeyExchangeAcceptance, key_id, m_key_exchanges.at(key_id)->users());
		
		if (m_key_exchanges[key_id]->contains(m_channel->room()->username())) {
			UnsignedKeyExchangeAcceptanceMessage message;
			message.key_id = key_id;
			message.key_hash = m_key_exchanges[key_id]->key_hash();
			m_channel->room()->send_message(KeyExchangeAcceptanceMessage::sign(message, m_channel->ephemeral_private_key(), m_channel->new_signature_id()));
		}
	}
}

void EncryptedChat::user_key_hash(const std::string& username, const Hash& key_id, const Hash& key_hash)
{
	assert(m_participants.count(username));
	assert(m_key_exchanges.count(key_id));
	assert(m_key_exchanges.at(key_id)->state() == KeyExchange::State::Acceptance);
	m_key_exchanges[key_id]->set_key_hash(username, key_hash);
	if (m_key_exchanges.at(key_id)->state() == KeyExchange::State::KeyAccepted) {
		m_channel->add_key_activation_event(key_id, m_key_exchanges.at(key_id)->users());
		
		if (m_key_exchanges[key_id]->contains(m_channel->room()->username())) {
			create_session(key_id);
		}
		
		while (m_key_exchange_queue.front() != key_id) {
			m_key_exchanges.erase(m_key_exchange_queue.front());
			m_key_exchange_queue.erase(m_key_exchange_queue.begin());
		}
		m_key_exchanges.erase(m_key_exchange_queue.front());
		m_key_exchange_queue.erase(m_key_exchange_queue.begin());
	} else if (m_key_exchanges.at(key_id)->state() == KeyExchange::State::Reveal) {
		m_channel->add_key_exchange_event(Message::Type::KeyExchangeReveal, key_id, m_key_exchanges.at(key_id)->users());
		
		if (m_key_exchanges[key_id]->contains(m_channel->room()->username())) {
			UnsignedKeyExchangeRevealMessage message;
			message.key_id = key_id;
			message.private_key = m_key_exchanges[key_id]->serialized_private_key();
			m_channel->room()->send_message(KeyExchangeRevealMessage::sign(message, m_channel->ephemeral_private_key(), m_channel->new_signature_id()));
		}
	}
}

void EncryptedChat::user_private_key(const std::string& username, const Hash& key_id, const SerializedPrivateKey& private_key)
{
	assert(m_participants.count(username));
	assert(m_key_exchanges.count(key_id));
	assert(m_key_exchanges.at(key_id)->state() == KeyExchange::State::Reveal);
	m_key_exchanges[key_id]->set_private_key(username, private_key);
	if (m_key_exchanges.at(key_id)->state() == KeyExchange::State::RevealFinished) {
		std::set<std::string> malicious_users = m_key_exchanges.at(key_id)->malicious_users();
		
		for (std::vector<Hash>::iterator i = m_key_exchange_queue.begin(); i != m_key_exchange_queue.end(); ++i) {
			if (*i == key_id) {
				m_key_exchange_queue.erase(i);
				break;
			}
		}
		m_key_exchanges.erase(key_id);
		
		m_channel->remove_users(malicious_users);
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

void EncryptedChat::send_message(const std::string& message)
{
	assert(m_participants.count(m_channel->room()->username()));
	assert(m_participants.at(m_channel->room()->username()).active);
	
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

void EncryptedChat::create_key_exchange()
{
	Hash key_id = m_channel->channel_status_hash();
	
	assert(!m_key_exchanges.count(key_id));
	std::map<std::string, PublicKey> users;
	for (const auto& i : m_participants) {
		users[i.second.username] = i.second.long_term_public_key;
	}
	std::unique_ptr<KeyExchange> exchange(new KeyExchange(key_id, users, m_channel->room()));
	
	m_key_exchange_queue.push_back(key_id);
	m_key_exchanges[key_id] = std::move(exchange);
	m_channel->add_key_exchange_event(Message::Type::KeyExchangePublicKey, key_id, m_key_exchanges.at(key_id)->users());
	
	if (m_key_exchanges[key_id]->contains(m_channel->room()->username())) {
		UnsignedKeyExchangePublicKeyMessage message;
		message.key_id = key_id;
		message.public_key = m_key_exchanges[key_id]->public_key();
		m_channel->room()->send_message(KeyExchangePublicKeyMessage::sign(message, m_channel->ephemeral_private_key(), m_channel->new_signature_id()));
	}
}

void EncryptedChat::create_session(const Hash& key_id)
{
	assert(m_key_exchanges.count(key_id));
	assert(m_key_exchanges.at(key_id)->state() == KeyExchange::State::KeyAccepted);
	assert(m_key_exchanges.at(key_id)->contains(m_channel->room()->username()));
	assert(!m_sessions.count(key_id));
	
	std::vector<KeyExchange::AcceptedUser> users = m_key_exchanges.at(key_id)->accepted_users();
	std::unique_ptr<Session> session(new Session(m_channel, key_id, users, m_key_exchanges.at(key_id)->symmetric_key(), m_key_exchanges.at(key_id)->private_key()));
	
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
	
	UnsignedKeyActivationMessage message;
	message.key_id = key_id;
	m_channel->room()->send_message(KeyActivationMessage::sign(message, m_channel->ephemeral_private_key(), m_channel->new_signature_id()));
}

void EncryptedChat::progress_sessions()
{
	while (true) {
		assert(!m_session_queue.empty());
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
				bool self_active = in_chat();
				
				for (const Identity& identity : data.participants) {
					// user joined / self joined
					if (!m_participants[identity.username].active) {
						m_participants[identity.username].active = true;
						if (!self_active) {
							m_channel->interface()->user_joined_chat(identity.username);
						}
					}
				}
				m_sessions[key_id].active = true;
				
				if (self_active) {
					m_channel->interface()->joined_chat();
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
