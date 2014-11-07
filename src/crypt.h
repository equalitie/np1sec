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

#include "src/common.h"

extern "C" {
  #include "gcrypt.h"
}


#ifndef SRC_CRYPT_H_
#define SRC_CRYPT_H_

/**
 * Encryption primitives and related definitions.
 */
class Ed25519Key {
 public:
  gcry_sexp_t ed25519_keypair;                                                 
  //static const uint32_t ED25519_KEY_SIZE = 255;

  /**
    Constructor setup the key
  */
  Ed25519Key();
};

typedef Ed25519Key LongTermIDKey;

const int c_mpseq_hash = gcry_md_algos::GCRY_MD_SHA256;

// The length of the output of the hash function in bytes.
const size_t c_hash_length = 32;

typedef uint8_t HashBlock[c_hash_length];

gcry_error_t Hash(const void *buffer, size_t buffer_len, HashBlock hb,
                  bool secure);

#endif  // SRC_CRYPT_H_
