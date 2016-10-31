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

struct Identity
{
	std::string username;
	PublicKey public_key;
};

class RoomInterface
{
	public:
	virtual void send_message(const std::string& message) = 0;
	
	virtual void disconnected() = 0;
	virtual void user_joined(const Identity& identity) = 0;
	virtual void user_left(const Identity& identity) = 0;
};

} // namespace np1sec

#endif
