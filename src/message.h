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
 * MERCHANTABILITY or FITNESS FOR A definederal Public
 * License along with this library; if not, write to tm_tokenshe Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef SRC_MESSAGE_NEW_H_
#define SRC_MESSAGE_NEW_H_

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "bytearray.h"
#include "crypto.h"
#include "exceptions.h"

namespace np1sec
{

class MessageBuffer : public std::string
{
    public:
    MessageBuffer() {}
    MessageBuffer(const std::string& string): std::string(string) {}

    unsigned char byte(size_t index) { return (unsigned char)(at(index)); }

    void add_8(uint8_t byte);
    void add_16(uint16_t number);
    void add_32(uint32_t number);

    template<int n> void add_byte_array(const ByteArray<n>& data)
    {
        append(reinterpret_cast<const char *>(data.buffer), n);
    }

    void add_hash(const Hash& hash) { add_byte_array(hash); }
    void add_public_key(const PublicKey& key) { add_byte_array(key); }
    void add_signature(const Signature& signature) { add_byte_array(signature); }
    void add_bytes(const std::string& buffer);
    void add_opaque(const std::string& buffer);

    void check_empty();
    uint8_t remove_8();
    uint16_t remove_16();
    uint32_t remove_32();

    template<int n> ByteArray<n> remove_byte_array()
    {
        if (size() < n) {
            throw MessageFormatException();
        }

        ByteArray<n> result;
        for (int i = 0; i < n; i++) {
            result.buffer[i] = at(i);
        }

        erase(0, n);

        return result;
    }

    Hash remove_hash() { return remove_byte_array<c_hash_length>(); }
    PublicKey remove_public_key() { return remove_byte_array<c_public_key_length>(); }
    Signature remove_signature() { return remove_byte_array<c_signature_length>(); }
    std::string remove_bytes(size_t size);
    std::string remove_opaque();
};



struct Message
{
    enum Type {
        JOIN_REQUEST = 0x0a, // Session establishement
        PARTICIPANTS_INFO = 0x0b,
        JOINER_AUTH = 0x0c,
        GROUP_SHARE = 0x0d,
        SESSION_CONFIRMATION = 0x0e, // In session messages
        IN_SESSION_MESSAGE = 0x10
    };

    Type type;
    std::string payload;

    std::string encode() const;
    static Message decode(const std::string& encoded);
};

struct SessionMessage
{
    Message::Type type;
    Hash session_id;
    std::string payload;

    Message encode() const;
    static SessionMessage decode(const Message& encoded);
};



struct UnsignedCurrentSessionMessage
{
    Message::Type type;
    std::string payload;
};

struct UnsignedSessionMessage : public UnsignedCurrentSessionMessage
{
    Hash session_id;

    std::string signed_body() const;
};

struct SignedSessionMessage : public UnsignedSessionMessage
{
    Signature signature;

    bool verify(const PublicKey& key) const;
    static SignedSessionMessage sign(const UnsignedSessionMessage& message, const PrivateKey& key);

    SessionMessage encode() const;
    static SignedSessionMessage decode(const SessionMessage& message);

    SessionMessage encrypt(const SymmetricKey& key) const;
    static SignedSessionMessage decrypt(const SessionMessage& message, const SymmetricKey& key);
};



struct JoinRequestMessage
{
    std::string nickname;
    PublicKey long_term_public_key;
    PublicKey ephemeral_public_key;

    Message encode() const;
    static JoinRequestMessage decode(const Message& message);
};

struct ParticipantsInfoMessage
{
    struct ParticipantInfo
    {
        std::string nickname;
        PublicKey long_term_public_key;
        PublicKey ephemeral_public_key;
        bool authenticated;
    };

    std::vector<ParticipantInfo> participants;
    Hash key_confirmation;
    Hash sender_share;

    UnsignedCurrentSessionMessage encode() const;
    static ParticipantsInfoMessage decode(const UnsignedCurrentSessionMessage& message);
};

struct JoinerAuthMessage
{
    std::map<uint32_t, Hash> key_confirmations;
    Hash sender_share;

    UnsignedCurrentSessionMessage encode() const;
    static JoinerAuthMessage decode(const UnsignedCurrentSessionMessage& message);
};

struct GroupShareMessage
{
    Hash sender_share;

    UnsignedCurrentSessionMessage encode() const;
    static GroupShareMessage decode(const UnsignedCurrentSessionMessage& message);
};

struct SessionConfirmationMessage
{
    Hash session_confirmation;
    PublicKey next_ephemeral_public_key;

    UnsignedCurrentSessionMessage encode() const;
    static SessionConfirmationMessage decode(const UnsignedCurrentSessionMessage& message);
};

struct InSessionMessage
{
    enum Type {
        JUST_ACK,
        USER_MESSAGE,
        LEAVE_MESSAGE
    };

    uint32_t sender_index;
    uint32_t sender_message_id;
    uint32_t parent_server_message_id;
    Hash transcript_chain_hash;
    Hash nonce;
    Type subtype;
    std::string payload;

    UnsignedCurrentSessionMessage encode() const;
    static InSessionMessage decode(const UnsignedCurrentSessionMessage& message);
};

} // namespace np1sec

#endif
