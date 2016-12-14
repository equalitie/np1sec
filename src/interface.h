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

//! TimerCallback
class TimerCallback
{
	public:
	/**
	 * This method is implemented in the (n+1)sec library but
	 * must be executed when a timer set through the RoomInterface::set_timer
	 * function expires (unless the library called TimerToken::unset first).
	 */
	virtual void execute() = 0;
};

//! TimerToken
class TimerToken
{
	public:
	/**
	 * Called by the (n+1)sec library to cancel the timer set through
	 * the RoomInterface::set_timer function. Along with ensuring that
	 * the TimerCallback::execute method shall no longer be executed,
	 * the TimerToken must 'delete' itself in this function.
	 */
	virtual void unset() = 0;
};

class Conversation;



//! Conversation interface
class ConversationInterface
{
	public:

	/**
	 * Indicate that the \p inviter invited the \p invitee
	 */
	virtual void user_invited(const std::string& inviter, const std::string& invitee) = 0;

	// TODO: reason
	/**
	 * Indicate that a previously issued invitation by \p inviter to
	 * \p invitee is no longer valid.
	 */
	virtual void invitation_cancelled(const std::string& inviter, const std::string& invitee) = 0;

	/**
	 * \brief TODO
	 */
	virtual void user_authenticated(const std::string& username, const PublicKey& public_key) = 0;

	/**
	 * \brief TODO
	 */
	virtual void user_authentication_failed(const std::string& username) = 0;

	/**
	 * Indicate that a previously invited user \p username started joining
	 * this conversation.
	 *
	 * Once the user \p username started 'joining' this conversation her messages
	 * may be decryptable by *some* of the participants and she can decrypt
	 * messages from *some* of the participants as well.
	 *
	 * To make sure this user is able to decrypt/receive our messages
	 * we need to wait for the ConversationInterface::user_joined
	 * callback.
	 */
	virtual void user_joining(const std::string& username) = 0;

	// TODO: reason
	/**
	 * Indicate that the user \p username has left the conversation
	 *
	 * The user is no longer capable of decrypting any messages
	 * sent from us.
	 */
	virtual void user_left(const std::string& username) = 0;

	/**
	 * \brief TODO
	 */
	virtual void votekick_registered(const std::string& kicker, const std::string& victim, bool kicked) = 0;
	

	/**
	 * Indicate that the user can send us an encrypted message and
	 * that she can decrypt every message we send to this channel from this
	 * point onwards.
	 */
	virtual void user_joined(const std::string& username) = 0;

	/**
	 * Indicate that we received a \p message from the \p sender
	 *
	 * \param sender The username of the sender of the message
	 * \param message The message after being decrypted
	 */
	virtual void message_received(const std::string& sender, const std::string& message) = 0;
	

	/**
	 * Indicate that we are now capable of  decrypting some of the messages
	 * and that what we send *may* be decrypted by some of the participants in
	 * this conversation.
	 */
	virtual void joining() = 0;

	/**
	 * Indicate that we can now receive and decrypt messages from all
	 * users who joined this conversation.
	 */
	virtual void joined() = 0;

	/**
	 * Indicate that we have left this conversation.
	 *
	 * Once this callback is called, the library shall delete the conversation.
	 */
	virtual void left() = 0;
	
	// TODO: zombie users?
	// TODO: transcript consistency?
};



//! Room interface
class RoomInterface
{
	public:
	/*
	 * Operations
	 */

	/**
	 * Used by the library to send encrypted messages to other users.
	 *
	 * See Room::message_received for more info.
	 *
	 * \param message the ecnrypted message
	 */
	virtual void send_message(const std::string& message) = 0;

	/**
	 * Used by the library to set timers 
	 * 
	 * As with sending and receiving, the library doesn't rely on any particular
	 * timer implementation. Thus it is up to the library user to provide this
	 * functionality.
	 *
	 * Every time the library needs to wait for an event, it calls this
	 * function expecting that the TimerCallback::execute function will be executed
	 * once the \p interval number of milliseconds passes.
	 *
	 * The function must return an instance of the TimerToken implementation
	 * which the library can use to cancel the timer by calling its
	 * TimerToken::unset function.
	 *
	 * User of the library is responsible for destroying TimerTokens when
	 * one of these happen:
	 *
	 * * After TimerCallback::execute is called
	 * * Inside the TimerToken::unset function
	 * * After the room creating this token is destroyed
	 */
	virtual TimerToken* set_timer(uint32_t interval, TimerCallback* callback) = 0;
	
	/*
	 * Callbacks
	 */

	/**
	 * Indicate to the user that the library has successfully sent and received
	 * a 'hello' message.
	 */
	virtual void connected() = 0;

	/**
	 * Indicate that we've been disconnected from the room.
	 *
	 * After being disconnected, no more messages will be sent and received
	 * by the library, no more interface callbacks shall be executed and
	 * all channels will be destroyed.
	 */
	virtual void disconnected() = 0;

	/**
	 * Indicate that a new user in this communication channel is known to be
	 * using (n+1)sec.
	 */
	virtual void user_joined(const std::string& username, const PublicKey& public_key) = 0;

	/**
	 * Executed when the library detected that a user has left.
	 */
	virtual void user_left(const std::string& username, const PublicKey& public_key) = 0;

	/**
	 * Executed as a result of user calling the Room::create_conversation method.
	 *
	 * A conversation created in this way will initially contain only 
	 * ourselves as the only participant with the conversation state
	 * set to "Joined".
	 */
	virtual ConversationInterface* created_conversation(Conversation* conversation) = 0;

	/**
	 * Executed as a result of some other channel participant calling
	 * the Conversation::invite method against ourselves.
	 *
	 * The (locally) newly created conversation shall have the
	 * inviter in it, together with other participants who joined
	 * prior to us.
	 *
	 * Our state in the conversation created this way shall be
	 * "Invited". To become a participant we need to call
	 * the Conversation::join method and wait for the 
	 * ConversationInterface::joining and
	 * ConversationInterface::joined callbacks.
	 */
	virtual ConversationInterface* invited_to_conversation(Conversation* conversation, const std::string& username) = 0;
};

} // namespace np1sec

#endif
