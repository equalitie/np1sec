/**
 * Multiparty Off-the-Record Messaging library
 * Copyright (C) 2014, eQualit.ie
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

#include "message.h"
#include "crypt.h"

namespace np1sec
{

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

void MessageBuffer::check_empty() throw(MessageFormatException)
{
    if (!empty()) {
        throw MessageFormatException();
    }
}

uint8_t MessageBuffer::remove_8() throw(MessageFormatException)
{
    if (size() < 1) {
        throw MessageFormatException();
    }

    uint8_t result = byte(0);

    erase(0, 1);

    return result;
}

uint16_t MessageBuffer::remove_16() throw(MessageFormatException)
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

uint32_t MessageBuffer::remove_32() throw(MessageFormatException)
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

std::string MessageBuffer::remove_bytes(size_t size) throw(MessageFormatException)
{
    if (this->size() < size) {
        throw MessageFormatException();
    }

    std::string result(*this, 0, size);

    erase(0, size);

    return result;
}

std::string MessageBuffer::remove_opaque() throw(MessageFormatException)
{
    return remove_bytes(remove_32());
}



std::string Message::encode() const
{
    MessageBuffer buffer;
    buffer.add_16(c_np1sec_protocol_version);
    buffer.add_8(type);
    buffer.add_bytes(payload);

    char* base64_buffer = new char[((buffer.size() + 3 - 1) / 3) * 4];
    size_t base64_size = otrl_base64_encode(base64_buffer, reinterpret_cast<const unsigned char*>(buffer.data()), buffer.size());
    std::string base64_encoded(base64_buffer, base64_size);
    delete[] base64_buffer;

    std::string result = c_np1sec_protocol_name;
    result.append(base64_encoded);
    return result;
}

Message Message::decode(const std::string& encoded) throw(MessageFormatException)
{
    if (encoded.size() < c_np1sec_protocol_name.size()) {
        throw MessageFormatException();
    }
    if (encoded.substr(0, c_np1sec_protocol_name.size()) != c_np1sec_protocol_name) {
        throw MessageFormatException();
    }
    std::string base64_payload = encoded.substr(c_np1sec_protocol_name.size());
    unsigned char* base64_buffer = new unsigned char[((base64_payload.size() + 4 - 1) / 4) * 3];
    size_t base64_size = otrl_base64_decode(base64_buffer, base64_payload.data(), base64_payload.size());
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

Message SessionMessage::encode() const
{
    MessageBuffer buffer;
    buffer.add_hash(session_id);
    buffer.add_bytes(payload);

    Message result;
    result.type = type;
    result.payload = buffer;
    return result;
}

SessionMessage SessionMessage::decode(const Message& message) throw(MessageFormatException)
{
    SessionMessage result;
    result.type = message.type;

    MessageBuffer buffer(message.payload);
    result.session_id = buffer.remove_hash();
    result.payload = buffer;
    return result;
}



std::string UnsignedSessionMessage::signed_body() const
{
    MessageBuffer buffer;
    buffer.add_8(type);
    buffer.add_hash(session_id);
    buffer.add_bytes(payload);
    return buffer;
}

bool SignedSessionMessage::verify(PublicKey key) const
{
    return Cryptic::verify(signed_body(), signature.buffer, key);
}

SignedSessionMessage SignedSessionMessage::sign(const UnsignedSessionMessage& message, Cryptic* key)
{
    unsigned char* signature;
    size_t signature_size;
    key->sign(&signature, &signature_size, message.signed_body());

    SignedSessionMessage result;
    result.type = message.type;
    result.session_id = message.session_id;
    result.payload = message.payload;
    assert(signature_size == sizeof(result.signature.buffer));
    memcpy(result.signature.buffer, signature, sizeof(result.signature.buffer));
    return result;
}

SessionMessage SignedSessionMessage::encode() const
{
    MessageBuffer buffer;
    buffer.add_bytes(payload);
    buffer.add_signature(signature);

    SessionMessage result;
    result.type = type;
    result.session_id = session_id;
    result.payload = buffer;
    return result;
}

SignedSessionMessage SignedSessionMessage::decode(const SessionMessage& message) throw(MessageFormatException)
{
    MessageBuffer buffer(message.payload);
    if (buffer.size() < c_signature_length) {
        throw MessageFormatException();
    }
    SignedSessionMessage result;
    result.type = message.type;
    result.session_id = message.session_id;
    result.payload = buffer.remove_bytes(buffer.size() - c_signature_length);
    result.signature = buffer.remove_signature();
    return result;
}

SessionMessage SignedSessionMessage::encrypt(Cryptic* key) const
{
    SessionMessage unencrypted_message = encode();
    SessionMessage result;
    result.type = unencrypted_message.type;
    result.session_id = unencrypted_message.session_id;
    result.payload = key->Encrypt(unencrypted_message.payload);
    return result;
}

SignedSessionMessage SignedSessionMessage::decrypt(const SessionMessage& message, Cryptic* key) throw(MessageFormatException)
{
    SessionMessage decrypted_message;
    decrypted_message.type = message.type;
    decrypted_message.session_id = message.session_id;
    decrypted_message.payload = key->Decrypt(message.payload);
    return SignedSessionMessage::decode(decrypted_message);
}



Message JoinRequestMessage::encode() const
{
    MessageBuffer buffer;
    buffer.add_bytes(nickname);
    buffer.add_raw_public_key(long_term_public_key);
    buffer.add_raw_public_key(ephemeral_public_key);
    buffer.add_8(1);

    Message result;
    result.type = Message::JOIN_REQUEST;
    result.payload = buffer;
    return result;
}

JoinRequestMessage JoinRequestMessage::decode(const Message& message) throw(MessageFormatException)
{
    assert(message.type == Message::JOIN_REQUEST);

    JoinRequestMessage result;

    MessageBuffer buffer(message.payload);
    result.nickname = buffer.remove_bytes(buffer.size() - sizeof(RawPublicKey) - sizeof(RawPublicKey) - 1);
    result.long_term_public_key = buffer.remove_raw_public_key();
    result.ephemeral_public_key = buffer.remove_raw_public_key();
    buffer.remove_8(); // ignored
    buffer.check_empty();
    return result;
}

UnsignedCurrentSessionMessage ParticipantsInfoMessage::encode() const
{
    MessageBuffer buffer;
    MessageBuffer participants_buffer;
    for (size_t i = 0; i < participants.size(); i++) {
        MessageBuffer participant_buffer;
        participant_buffer.add_bytes(participants[i].nickname);
        participant_buffer.add_raw_public_key(participants[i].long_term_public_key);
        participant_buffer.add_raw_public_key(participants[i].ephemeral_public_key);
        participant_buffer.add_8(participants[i].authenticated);
        participants_buffer.add_opaque(participant_buffer);
    }
    buffer.add_opaque(participants_buffer);
    MessageBuffer key_confirmation_buffer;
    key_confirmation_buffer.add_hash(key_confirmation);
    buffer.add_opaque(key_confirmation_buffer);
    buffer.add_hash(sender_share);

    UnsignedCurrentSessionMessage result;
    result.type = Message::PARTICIPANTS_INFO;
    result.payload = buffer;
    return result;
}

ParticipantsInfoMessage ParticipantsInfoMessage::decode(const UnsignedCurrentSessionMessage& message) throw(MessageFormatException)
{
    assert(message.type == Message::PARTICIPANTS_INFO);

    ParticipantsInfoMessage result;

    MessageBuffer buffer(message.payload);
    MessageBuffer participants_buffer(buffer.remove_opaque());
    while (!participants_buffer.empty()) {
        MessageBuffer participant_buffer = participants_buffer.remove_opaque();
        ParticipantInfo participant;
        participant.nickname = participant_buffer.remove_bytes(participant_buffer.size() - sizeof(RawPublicKey) - sizeof(RawPublicKey) - 1);
        participant.long_term_public_key = participant_buffer.remove_raw_public_key();
        participant.ephemeral_public_key = participant_buffer.remove_raw_public_key();
        participant.authenticated = (participant_buffer.remove_8() != 0);
        result.participants.push_back(participant);
    }
    MessageBuffer key_confirmation_buffer(buffer.remove_opaque());
    result.key_confirmation = key_confirmation_buffer.remove_hash();
    result.sender_share = buffer.remove_hash();
    buffer.check_empty();
    return result;
}

UnsignedCurrentSessionMessage JoinerAuthMessage::encode() const
{
    MessageBuffer buffer;
    MessageBuffer key_confirmations_buffer;
    for (auto it = key_confirmations.begin(); it != key_confirmations.end(); it++) {
        key_confirmations_buffer.add_32(it->first);
        key_confirmations_buffer.add_hash(it->second);
    }
    buffer.add_opaque(key_confirmations_buffer);
    buffer.add_hash(sender_share);

    UnsignedCurrentSessionMessage result;
    result.type = Message::JOINER_AUTH;
    result.payload = buffer;
    return result;
}

JoinerAuthMessage JoinerAuthMessage::decode(const UnsignedCurrentSessionMessage& message) throw(MessageFormatException)
{
    assert(message.type == Message::JOINER_AUTH);

    JoinerAuthMessage result;

    MessageBuffer buffer(message.payload);
    MessageBuffer key_confirmations_buffer(buffer.remove_opaque());
    while (!key_confirmations_buffer.empty()) {
        uint32_t index = key_confirmations_buffer.remove_32();
        Hash key_confirmation = key_confirmations_buffer.remove_hash();
        result.key_confirmations[index] = key_confirmation;
    }
    result.sender_share = buffer.remove_hash();
    buffer.check_empty();
    return result;
}

UnsignedCurrentSessionMessage GroupShareMessage::encode() const
{
    MessageBuffer buffer;
    buffer.add_hash(sender_share);

    UnsignedCurrentSessionMessage result;
    result.type = Message::GROUP_SHARE;
    result.payload = buffer;
    return result;
}

GroupShareMessage GroupShareMessage::decode(const UnsignedCurrentSessionMessage& message) throw(MessageFormatException)
{
    assert(message.type == Message::GROUP_SHARE);

    GroupShareMessage result;

    MessageBuffer buffer(message.payload);
    result.sender_share = buffer.remove_hash();
    buffer.check_empty();
    return result;
}

UnsignedCurrentSessionMessage SessionConfirmationMessage::encode() const
{
    MessageBuffer buffer;
    buffer.add_hash(session_confirmation);
    buffer.add_raw_public_key(next_ephemeral_public_key);

    UnsignedCurrentSessionMessage result;
    result.type = Message::SESSION_CONFIRMATION;
    result.payload = buffer;
    return result;
}

SessionConfirmationMessage SessionConfirmationMessage::decode(const UnsignedCurrentSessionMessage& message) throw(MessageFormatException)
{
    assert(message.type == Message::SESSION_CONFIRMATION);

    SessionConfirmationMessage result;

    MessageBuffer buffer(message.payload);
    result.session_confirmation = buffer.remove_hash();
    result.next_ephemeral_public_key = buffer.remove_raw_public_key();
    buffer.check_empty();
    return result;
}

UnsignedCurrentSessionMessage InSessionMessage::encode() const
{
    MessageBuffer buffer;
    buffer.add_32(sender_index);
    buffer.add_32(sender_message_id);
    buffer.add_32(parent_server_message_id);
    buffer.add_hash(transcript_chain_hash);
    buffer.add_hash(nonce);
    if (subtype == JUST_ACK) {
        // done
    } else {
        buffer.add_16(subtype);
        if (subtype == USER_MESSAGE) {
            buffer.add_opaque(payload);
        } else if (subtype == LEAVE_MESSAGE) {
            // done
        } else {
            assert(false);
        }
    }

    UnsignedCurrentSessionMessage result;
    result.type = Message::IN_SESSION_MESSAGE;
    result.payload = buffer;
    return result;
}

InSessionMessage InSessionMessage::decode(const UnsignedCurrentSessionMessage& message) throw(MessageFormatException)
{
    assert(message.type == Message::IN_SESSION_MESSAGE);

    InSessionMessage result;

    MessageBuffer buffer(message.payload);
    result.sender_index = buffer.remove_32();
    result.sender_message_id = buffer.remove_32();
    result.parent_server_message_id = buffer.remove_32();
    result.transcript_chain_hash = buffer.remove_hash();
    result.nonce = buffer.remove_hash();
    if (buffer.empty()) {
        result.subtype = JUST_ACK;
    } else {
        result.subtype = InSessionMessage::Type(buffer.remove_16());
        if (result.subtype == USER_MESSAGE) {
            result.payload = buffer.remove_opaque();
        } else if (result.subtype == LEAVE_MESSAGE) {
            buffer.check_empty();
        } else {
            throw MessageFormatException();
        }
    }

    return result;
}

} // namespace np1sec
