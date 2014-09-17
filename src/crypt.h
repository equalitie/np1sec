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


#ifndef SRC_CRYPT_H_
#define SRC_CRYPT_H_

/**
 * Encryption primitives and related definitions.
 */

const int c_mpotr_hash = gcry_md_algos::GCRY_MD_SHA256;

// The length of the output of the hash function in bytes.
// TODO(XXX): This should be borrowed from the encryption library.
const size_t c_hash_length = gcry_md_get_algo_dlen(c_mpotr_hash);

typedef uint8_t HashBlock[c_hash_length];

#endif  // SRC_CRYPT_H_
