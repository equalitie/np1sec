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

#include "common.h"
#include "exceptions.h"

namespace np1sec
{

class Cryptic;

class MessageBuffer : public std::string
{
    public:
    MessageBuffer() {}
    MessageBuffer(const std::string& string): std::string(string) {}

    unsigned char byte(size_t index) { return (unsigned char)(at(index)); }

    void add_8(uint8_t byte);
    void add_16(uint16_t number);
    void add_32(uint32_t number);

    template<int n> void addByteArray(const ByteArray<n>& data)
    {
        append(reinterpret_cast<const char *>(data.buffer), n);
    }

    void add_hash(Hash hash) { addByteArray(hash); }
    void add_raw_public_key(RawPublicKey key) { addByteArray(key); }
    void add_signature(Signature signature) { addByteArray(signature); }
    void add_bytes(const std::string& buffer);
    void add_opaque(const std::string& buffer);

    void check_empty() throw(MessageFormatException);
    uint8_t remove_8() throw(MessageFormatException);
    uint16_t remove_16() throw(MessageFormatException);
    uint32_t remove_32() throw(MessageFormatException);

    template<int n> ByteArray<n> removeByteArray()
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

    Hash remove_hash() { return removeByteArray<c_hash_length>(); }
    RawPublicKey remove_raw_public_key() { return removeByteArray<32>(); }
    Signature remove_signature() { return removeByteArray<c_signature_length>(); }
    std::string remove_bytes(size_t size) throw(MessageFormatException);
    std::string remove_opaque() throw(MessageFormatException);
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
    static Message decode(const std::string& encoded) throw(MessageFormatException);
};

struct SessionMessage
{
    Message::Type type;
    Hash session_id;
    std::string payload;

    Message encode() const;
    static SessionMessage decode(const Message& encoded) throw(MessageFormatException);
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

    bool verify(PublicKey key) const;
    static SignedSessionMessage sign(const UnsignedSessionMessage& message, Cryptic* key);

    SessionMessage encode() const;
    static SignedSessionMessage decode(const SessionMessage& message) throw(MessageFormatException);

    SessionMessage encrypt(Cryptic* key) const;
    static SignedSessionMessage decrypt(const SessionMessage& message, Cryptic* key) throw(MessageFormatException);
};



struct JoinRequestMessage
{
    std::string nickname;
    RawPublicKey long_term_public_key;
    RawPublicKey ephemeral_public_key;

    Message encode() const;
    static JoinRequestMessage decode(const Message& message) throw(MessageFormatException);
};

struct ParticipantsInfoMessage
{
    struct ParticipantInfo
    {
        std::string nickname;
        RawPublicKey long_term_public_key;
        RawPublicKey ephemeral_public_key;
        bool authenticated;
    };

    std::vector<ParticipantInfo> participants;
    Hash key_confirmation;
    Hash sender_share;

    UnsignedCurrentSessionMessage encode() const;
    static ParticipantsInfoMessage decode(const UnsignedCurrentSessionMessage& message) throw(MessageFormatException);
};

struct JoinerAuthMessage
{
    std::map<uint32_t, Hash> key_confirmations;
    Hash sender_share;

    UnsignedCurrentSessionMessage encode() const;
    static JoinerAuthMessage decode(const UnsignedCurrentSessionMessage& message) throw(MessageFormatException);
};

struct GroupShareMessage
{
    Hash sender_share;

    UnsignedCurrentSessionMessage encode() const;
    static GroupShareMessage decode(const UnsignedCurrentSessionMessage& message) throw(MessageFormatException);
};

struct SessionConfirmationMessage
{
    Hash session_confirmation;
    RawPublicKey next_ephemeral_public_key;

    UnsignedCurrentSessionMessage encode() const;
    static SessionConfirmationMessage decode(const UnsignedCurrentSessionMessage& message) throw(MessageFormatException);
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
    static InSessionMessage decode(const UnsignedCurrentSessionMessage& message) throw(MessageFormatException);
};

} // namespace np1sec

#endif
