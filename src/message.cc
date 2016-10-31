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

#include "base64.h"
#include "message.h"

namespace np1sec
{

const std::string c_np1sec_protocol_name(":o3np1sec:");
const uint16_t c_np1sec_protocol_version = 0x0001;



void MessageBuffer::add_8(uint8_t byte)
{
	push_back(byte);
}

void MessageBuffer::add_16(uint16_t number)
{
	push_back((number >> 8) & 0xff);
	push_back((number >> 0) & 0xff);
}

void MessageBuffer::add_32(uint32_t number)
{
	push_back((number >> 24) & 0xff);
	push_back((number >> 16) & 0xff);
	push_back((number >>  8) & 0xff);
	push_back((number >>  0) & 0xff);
}

void MessageBuffer::add_bytes(const std::string& buffer)
{
	append(buffer);
}

void MessageBuffer::add_opaque(const std::string& buffer)
{
	add_32(buffer.size());
	append(buffer);
}

void MessageBuffer::check_empty()
{
	if (!empty()) {
		throw MessageFormatException();
	}
}

uint8_t MessageBuffer::remove_8()
{
	if (size() < 1) {
		throw MessageFormatException();
	}
	
	uint8_t result = byte(0);
	
	erase(0, 1);
	
	return result;
}

uint16_t MessageBuffer::remove_16()
{
	if (size() < 2) {
		throw MessageFormatException();
	}
	
	uint16_t result =
		(byte(0) << 8) |
		(byte(1) << 0);
	
	erase(0, 2);
	
	return result;
}

uint32_t MessageBuffer::remove_32()
{
	if (size() < 4) {
		throw MessageFormatException();
	}
	
	uint32_t result =
		(byte(0) << 24) |
		(byte(1) << 16) |
		(byte(2) <<  8) |
		(byte(3) <<  0);
	
	erase(0, 4);
	
	return result;
}

std::string MessageBuffer::remove_bytes(size_t size)
{
	if (this->size() < size) {
		throw MessageFormatException();
	}
	
	std::string result(*this, 0, size);
	
	erase(0, size);
	
	return result;
}

std::string MessageBuffer::remove_opaque()
{
	return remove_bytes(remove_32());
}



std::string Message::encode() const
{
	MessageBuffer buffer;
	buffer.add_16(c_np1sec_protocol_version);
	buffer.add_8(uint8_t(type));
	buffer.add_bytes(payload);
	
	char* base64_buffer = new char[((buffer.size() + 3 - 1) / 3) * 4];
	size_t base64_size = base64_encode(base64_buffer, reinterpret_cast<const unsigned char*>(buffer.data()), buffer.size());
	std::string base64_encoded(base64_buffer, base64_size);
	delete[] base64_buffer;
	
	std::string result = c_np1sec_protocol_name;
	result.append(base64_encoded);
	return result;
}

Message Message::decode(const std::string& encoded)
{
	if (encoded.size() < c_np1sec_protocol_name.size()) {
		throw MessageFormatException();
	}
	if (encoded.substr(0, c_np1sec_protocol_name.size()) != c_np1sec_protocol_name) {
		throw MessageFormatException();
	}
	std::string base64_payload = encoded.substr(c_np1sec_protocol_name.size());
	unsigned char* base64_buffer = new unsigned char[((base64_payload.size() + 4 - 1) / 4) * 3];
	size_t base64_size = base64_decode(base64_buffer, base64_payload.data(), base64_payload.size());
	std::string base64_decoded(reinterpret_cast<char *>(base64_buffer), base64_size);
	delete[] base64_buffer;
	
	MessageBuffer buffer(base64_decoded);
	Message message;
	if (buffer.remove_16() != c_np1sec_protocol_version) {
		throw MessageFormatException();
	}
	message.type = Message::Type(buffer.remove_8());
	message.payload = buffer;
	
	return message;
}



Message HelloMessage::encode() const
{
	MessageBuffer buffer;
	buffer.add_public_key(long_term_public_key);
	buffer.add_public_key(ephemeral_public_key);
	
	Message result;
	result.type = Message::Type::Hello;
	result.payload = buffer;
	return result;
}

HelloMessage HelloMessage::decode(const Message& encoded)
{
	if (encoded.type != Message::Type::Hello) {
		throw MessageFormatException();
	}
	MessageBuffer buffer(encoded.payload);
	
	HelloMessage result;
	result.long_term_public_key = buffer.remove_public_key();
	result.ephemeral_public_key = buffer.remove_public_key();
	return result;
}

Message AuthenticationMessage::encode() const
{
	MessageBuffer buffer;
	buffer.add_public_key(sender_long_term_public_key);
	buffer.add_public_key(sender_ephemeral_public_key);
	buffer.add_opaque(peer_username);
	buffer.add_public_key(peer_long_term_public_key);
	buffer.add_public_key(peer_ephemeral_public_key);
	buffer.add_hash(authentication_confirmation);
	
	Message result;
	result.type = Message::Type::Authentication;
	result.payload = buffer;
	return result;
}

AuthenticationMessage AuthenticationMessage::decode(const Message& encoded)
{
	if (encoded.type != Message::Type::Authentication) {
		throw MessageFormatException();
	}
	MessageBuffer buffer(encoded.payload);
	
	AuthenticationMessage result;
	result.sender_long_term_public_key = buffer.remove_public_key();
	result.sender_ephemeral_public_key = buffer.remove_public_key();
	result.peer_username = buffer.remove_opaque();
	result.peer_long_term_public_key = buffer.remove_public_key();
	result.peer_ephemeral_public_key = buffer.remove_public_key();
	result.authentication_confirmation = buffer.remove_hash();
	return result;
}





} // namespace np1sec
