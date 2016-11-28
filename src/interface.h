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

#ifndef SRC_INTERFACE_H_
#define SRC_INTERFACE_H_

#include "crypto.h"

namespace np1sec
{

class TimerCallback
{
	public:
	virtual void execute() = 0;
};

class TimerToken
{
	public:
	virtual void unset() = 0;
};

class Channel;

class ChannelInterface
{
	public:
	/*
	 * A user joined this channel. No cryptographic identity is known yet.
	 */
	virtual void user_joined(const std::string& username) = 0;
	
	/*
	 * A user left the channel.
	 */
	virtual void user_left(const std::string& username) = 0;
	
	/*
	 * The cryptographic identity of a user was confirmed.
	 */
	virtual void user_authenticated(const std::string& username, const PublicKey& public_key) = 0;
	
	/*
	 * A user failed to authenticate. This indicates an attack!
	 */
	virtual void user_authentication_failed(const std::string& username) = 0;
	
	/*
	 * A user <authenticatee> was accepted into the channel by a user <authenticator>.
	 */
	virtual void user_authorized_by(const std::string& user, const std::string& target) = 0;
	
	/*
	 * A user got authorized by all participants and is now a full participant.
	 */
	virtual void user_promoted(const std::string& username) = 0;
	
	
	/*
	 * You joined this channel.
	 */
	virtual void joined() = 0;
	
	/*
	 * You got authorized by all participants and are now a full participant.
	 */
	virtual void authorized() = 0;
	
	
	
	/*
	 * The following is a quick sketch and will be redesigned soon.
	 */
	/*
	 * You are now part of the chat, and can send and receive messages.
	 */
	virtual void joined_chat() = 0;
	
	/*
	 * A user joined the chat, and can send and receive messages.
	 */
	virtual void user_joined_chat(const std::string& username) = 0;
	
	/*
	 * Not implemented yet.
	 */
	virtual void message_received(const std::string& username, const std::string& message) = 0;
};



class RoomInterface
{
	public:
	/*
	 * Operations
	 */
	virtual void send_message(const std::string& message) = 0;
	virtual TimerToken* set_timer(uint32_t interval, TimerCallback* callback) = 0;
	
	/*
	 * Callbacks
	 */
	virtual void connected() = 0;
	virtual void disconnected() = 0;
	virtual void user_joined(const std::string& username, const PublicKey& public_key) = 0;
	virtual void user_left(const std::string& username, const PublicKey& public_key) = 0;
	// virtual ConversationInterface* created_conversation(Conversation* conversation) = 0;
	// virtual ConversationInterface* invited_to_conversation(Conversation* conversation) = 0;
};

} // namespace np1sec

#endif
