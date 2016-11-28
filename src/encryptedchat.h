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

#ifndef SRC_ENCRYPTEDCHAT_H_
#define SRC_ENCRYPTEDCHAT_H_

#include "keyexchange.h"
#include "session.h"
#include "timer.h"

#include <deque>
#include <map>
#include <memory>
#include <set>
#include <vector>

namespace np1sec
{

class Conversation;

class EncryptedChat
{
	public:
	EncryptedChat(Conversation* conversation);
	void unserialize_key_exchange(const KeyExchangeState& exchange);
	
	bool have_key_exchange(const Hash& key_id) const
	{
		return m_key_exchanges.count(key_id) > 0;
	}
	std::set<std::string> remaining_users(Hash key_id) const
	{
		assert(m_key_exchanges.count(key_id));
		return m_key_exchanges.at(key_id).key_exchange->remaining_users();
	}
	bool have_session(const Hash& key_id) const
	{
		return m_sessions.count(key_id) > 0;
	}
	std::vector<KeyExchangeState> encode_key_exchanges() const;
	bool replacing_session(const Hash& key_id) const;
	const Hash& latest_session_id() const
	{
		return m_latest_session_id;
	}
	
	
	
	bool in_chat() const;
	bool user_in_chat(const std::string& username) const;
	
	void initialize_latest_session(const Hash& session_id);
	void create_solo_session(const Hash& session_id);
	void add_user(const std::string& username, const PublicKey& long_term_public_key);
	void do_add_user(const std::string& username, const PublicKey& long_term_public_key);
	void remove_users(const std::set<std::string>& usernames);
	
	void user_public_key(const std::string& username, const Hash& key_id, const PublicKey& public_key);
	void user_secret_share(const std::string& username, const Hash& key_id, const Hash& group_hash, const Hash& secret_share);
	void user_key_hash(const std::string& username, const Hash& key_id, const Hash& key_hash);
	void user_private_key(const std::string& username, const Hash& key_id, const SerializedPrivateKey& private_key);
	
	void user_activation(const std::string& username, const Hash& key_id);
	
	void replace_session(const Hash& key_id);
	
	void send_message(const std::string& message);
	void decrypt_message(const std::string& sender, const ChatMessage& encrypted_message);
	
	protected:
	void insert_key_exchange(std::unique_ptr<KeyExchange>&& key_exchange);
	void erase_key_exchange(Hash key_id);
	
	void create_key_exchange();
	void create_session(const Hash& key_id);
	void prepare_session_replacement(Hash key_id);
	void progress_sessions();
	
	
	protected:
	struct Identity
	{
		std::string username;
		PublicKey long_term_public_key;
		
		bool operator<(const Identity rhs) const
		{
			return username < rhs.username || (username == rhs.username && long_term_public_key < rhs.long_term_public_key);
		}
	};
	
	struct Participant : public Identity
	{
		bool active;
		bool have_active_session;
		Hash active_session;
		std::deque<Hash> session_list;
		std::set<Hash> key_exchanges;
	};
	
	struct FormerParticipant : public Identity
	{
		std::deque<Hash> session_list;
	};
	
	struct KeyExchangeData
	{
		std::unique_ptr<KeyExchange> key_exchange;
		// key exchanges are ordered as a linked list, the old-fashioned way.
		bool has_next;
		bool has_previous;
		Hash next;
		Hash previous;
	};
	
	struct SessionData
	{
		std::unique_ptr<Session> session;
		bool active;
		std::set<Identity> participants;
		std::set<Identity> former_participants;
	};
	
	
	Conversation* m_conversation;
	
	std::map<std::string, Participant> m_participants;
	std::map<Identity, FormerParticipant> m_former_participants;
	
	std::map<Hash, KeyExchangeData> m_key_exchanges;
	// first and last are undefined if m_key_exchanges is empty.
	Hash m_key_exchange_first;
	Hash m_key_exchange_last;
	
	std::map<Hash, SessionData> m_sessions;
	std::deque<Hash> m_session_queue;
	
	Hash m_latest_session_id;
	Timer m_session_ratchet_timer;
};

} // namespace np1sec

#endif
