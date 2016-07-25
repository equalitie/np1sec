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

#ifndef SRC_COMMON_H_
#define SRC_COMMON_H_

extern "C" {
#include <assert.h>
}

#include <cstdint>
#include <sstream>
#include <iterator>
#include <stdexcept>
#include <vector>
#include <string>
#include <cstring>
#include <math.h>

#include "logger.h"
#include "base64.h"

#define UNUSED(expr) (void)(expr)

extern "C" {
#include "gcrypt.h"
}

namespace np1sec
{

typedef uint32_t MessageId;
typedef gcry_sexp_t PrivateKey;
typedef gcry_sexp_t PublicKey;
typedef std::pair<PrivateKey, PublicKey> KeyPair;
// TODO: it really makes sense that the public key is already stored in HashBlock
// Format as we never use public key directly when we have the main
// key and only use this to transmit it to others

// The length of the output of the hash function in bytes.
const size_t c_hash_length = 32;
const size_t c_signature_length = 64;

// Number of bytes in a Triple DH point extracted in tiple_ed_dh.
const size_t c_tdh_point_length = 65;

typedef uint8_t HashBlock[c_hash_length];

template<int n> struct ByteArray
{
    uint8_t buffer[n];

    ByteArray() {}
    ByteArray(const uint8_t* data) { memcpy(buffer, data, n); }

    std::string as_string() const { return std::string(reinterpret_cast<const char*>(buffer), n); }

    bool operator==(const ByteArray<n>& other)
    {
        return memcmp(buffer, other.buffer, n) == 0;
    }

    bool operator!=(const ByteArray<n>& other)
    {
        return !(*this == other);
    }
};

typedef ByteArray<c_hash_length> Hash;
typedef ByteArray<32> RawPublicKey;
typedef ByteArray<c_signature_length> Signature;

// np1sec Message data type
typedef uint8_t DTByte;
typedef uint16_t DTShort;
typedef uint32_t DTLength;
typedef HashBlock DTHash;
typedef HashBlock Token;
typedef HashBlock edCurvePublicKey;

const std::string c_np1sec_protocol_name(":o3np1sec:");
const DTShort c_np1sec_protocol_version = 0x0001;
const std::string c_np1sec_delim(":o3"); // because http://en.wikipedia.org/wiki/Man%27s_best_friend_(phrase)

// Global logger
extern Logger logger;

/**
 * Quickly overwrite a piece of memory with some byte to prevent RAM inspection.
 * @param {void*} _ptr - A pointer to the first byte of memory to overwrite
 * @param {uint8_t} _set - The byte to write over the memory block with
 * @param {size_t} _len - The number of bytes to write over
 */
#define wipememory2(_ptr,_set,_len) do { \
        volatile char *_vptr=(volatile char *)(_ptr); \
        size_t _vlen=(_len); \
        unsigned char _vset=(_set); \
        while(_vlen) { *_vptr=(_vset); _vptr++; _vlen--; } \
    } while(0)

/**
 * Quickly overwrite a piece of memory a few times to prevent RAM inspection.
 * @param {void*} _ptr - A pointer to the first byte of memory to overwrite
 * @param {size_t} _len - The number of bytes to write over
 */
#define secure_wipe(_ptr,_len) do { \
        wipememory2(_ptr,0xff,_len); \
        wipememory2(_ptr,0xaa,_len); \
        wipememory2(_ptr,0x55,_len); \
        wipememory2(_ptr,0x00,_len); \
    } while (0)

} // namespace np1sec

#endif // SRC_COMMON_H_
