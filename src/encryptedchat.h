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

#include <map>
#include <memory>
#include <vector>

namespace np1sec
{

class Channel;

class EncryptedChat
{
	public:
	EncryptedChat(Channel* channel);
	void unserialize_key_exchange(const KeyExchangeState& exchange);
	
	bool have_key_exchange(const Hash& key_id) const
	{
		return m_key_exchanges.count(key_id) > 0;
	}
	bool key_exchange_waiting_for(const Hash& key_id, const std::string& username) const;
	std::vector<KeyExchangeState> encode_key_exchanges() const;
	
	void add_user(const std::string& username, const PublicKey& long_term_public_key);
	void do_add_user(const std::string& username, const PublicKey& long_term_public_key);
	void remove_users(const std::set<std::string>& usernames);
	
	void user_public_key(const std::string& username, const Hash& key_id, const PublicKey& public_key);
	void user_secret_share(const std::string& username, const Hash& key_id, const Hash& group_hash, const Hash& secret_share);
	void user_key_hash(const std::string& username, const Hash& key_id, const Hash& key_hash);
	void user_private_key(const std::string& username, const Hash& key_id, const SerializedPrivateKey& private_key);
	
	
	
	protected:
	void create_key_exchange();
	
	
	protected:
	struct Participant
	{
		std::string username;
		PublicKey long_term_public_key;
		bool active;
	};
	
	
	Channel* m_channel;
	
	std::map<std::string, Participant> m_participants;
	std::map<Hash, std::unique_ptr<KeyExchange>> m_key_exchanges;
	std::vector<Hash> m_key_exchange_queue;
};

} // namespace np1sec

#endif
