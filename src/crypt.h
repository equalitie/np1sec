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
  gcry_sexp_t ed25519_keypair, pub_key, prv_key;
  // static const uint32_t ED25519_KEY_SIZE = 255;

  /**
    Constructor setup the key
  */
  Ed25519Key();
  /*
   * Encrypt a give plain text using the previously created ed25519 keys
   *
   * @param plain_text a plain text message string to be encrypted
   *
   * @return a string containing the encrypted text
   */
  std::string Ed25519Key::Encrypt(std::string plain_text);

  /*
   * Decrypt a give encrypted text using the previously created ed25519 keys
   *
   * @param encrypted_text an encrypted text message string to be decrypted
   *
   * @return a string containing the decrypted text
   */
  std::string Ed25519Key::Decrypt(std::string encrypted_text);

  /*
   * Convert a given gcrypt s-expression into a std::string
   *
   * @param gcry_sexp_t gcrypt s-expression to be converted
   *
   * @return std::string representing the converted data.
   *
   */
  std::string Ed25519Key::retrieveResult( gcry_sexp_t text_sexp );

  /*
   * Convert a given std:string to a valid gcrypt s-expression
   *
   * @param std::string valid string to be converted
   *
   * @return gcry_sexp_t gcrypt s-expression respresentation
   *
   */
  gcry_sexp_t Ed25519Key::ConvertToSexp(std::string text);

  /*
   * Given a valid std:string sign the string using the sessions
   * private key and return the signature.
   *
   * @param std::string representing message data to be signed
   *
   * @return std::string valid signature of the give data
   *
   */
  std::string Ed25519Key::Sign( std::string plain_text );

  /*
   * Given a signed piece of data and a valid signature verify if
   * the signature is correct using the sessions public key.
   *
   * @param std::string representing signed data
   * @param std::string representing data signature
   *
   * @return bool value dependent on failure or verification of given signature
   *
   */
  bool Ed25519Key::Verify( std::string signed_text, std::string sig );

  /*
   * Create instance of cipher session based on configured algorithm, mode,
   * key and iv.
   *
   * @return gcry_cipher_hd_t representing a cipher session handle
   *
   */
  gcry_cupher_hd_t Ed25519Key::OpenCipher();
};

typedef Ed25519Key LongTermIDKey;

unsigned char SESSION_KEY[] = {0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4};
unsigned char SESSION_IV[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};

const int c_mpseq_hash = gcry_md_algos::GCRY_MD_SHA256;

// The length of the output of the hash function in bytes.
const size_t c_hash_length = 32;

typedef uint8_t HashBlock[c_hash_length];

gcry_error_t Hash(const void *buffer, size_t buffer_len, HashBlock hb,
                  bool secure);

#endif  // SRC_CRYPT_H_
