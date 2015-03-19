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

#include <string>

#include "src/common.h"

extern "C" {
  #include "gcrypt.h"
}

typedef std::pair<gcry_sexp_t,gcry_sexp_t> KeyPair;
typedef gcry_sexp_t LongTermPublicKey;
typedef gcry_sexp_t LongTermPrivateKey;
typedef gcry_sexp_t np1secPublicKey;
typedef gcry_sexp_t np1secAsymmetricKey;

typedef HashBlock np1secKeyShare;

const unsigned int c_ephemeral_key_length = 32;
const unsigned int c_key_share = c_hash_length;

class  LongTermIDKey {
 protected:
  KeyPair key_pair;
  bool initiated = false;

 public:
  /**
   * Access
   */
  int is_initiated() {return initiated;}

  KeyPair get_key_pair(){return key_pair;}
  
  /**
   * @return false if key generation goes wrong (for example due to 
   *         lack of entropy
   */
  bool generate() {
    initiated = true;
    //Use Crypt class to generate
    //TODO::Bill
    
    return true;
      
  }

  void set_key_pair(KeyPair user_key_pair) {
    initiated = true;
    key_pair = user_key_pair;
  }
  
};

/**
 * Encryption primitives and related definitions.
 */
class Cryptic {
 protected:
  gcry_sexp_t ephemeral_key, ephemeral_pub_key, ephemeral_prv_key;
  
  static const uint32_t ED25519_KEY_SIZE = 32;
  const static gcry_mpi_format NP1SEC_BLOB_OUT_FORMAT = GCRYMPI_FMT_USG;

 public:
  /**
   * Constructor setup the key
   */
  Cryptic();

  /**
   * Access function for ephemeral pub key 
   * (Access is need for meta works like computing the session id  which are 
   *  not crypto task per se)
   *
   */
  gcry_sexp_t get_ephemeral_pub_key ()
  {
    return ephemeral_pub_key;
  }
  
  bool init();

  /**
   * Encrypt a give plain text using the previously created ed25519 keys
   *
   * @param plain_text a plain text message string to be encrypted
   *
   * @return a string containing the encrypted text
   */
  std::string Encrypt(std::string plain_text);

  /**
   * Decrypt a give encrypted text using the previously created ed25519 keys
teddh   *
   * @param encrypted_text an encrypted text message string to be decrypted
   *
   * @return a string containing the decrypted text
   */
  std::string Decrypt(std::string encrypted_text);

  /**
   * Generates a random ed25519 key pair 
   *
   * @return false in case of error otherwise true
   */
  static bool generate_key_pair(np1secAsymmetricKey* generated_key);
  
  /**
   * Convert a given gcrypt s-expression into a std::string
   *
   * @param gcry_sexp_t gcrypt s-expression to be converted
   *
   * @return std::string representing the converted data.
   */
  static std::string retrieve_result(gcry_sexp_t text_sexp);

  static gcry_error_t hash(const void *buffer, size_t buffer_len, HashBlock hb,
                  bool secure = true);
  
  /**
   * Convert a given std:string to a valid gcrypt s-expression
   *
   * @param std::string valid string to be converted
   *
   * @return gcry_sexp_t gcrypt s-expression respresentation
   */
  static gcry_sexp_t convert_to_sexp(std::string text);

  /**
   * Given the peer's long term and ephemeral public key AP and ap, and ours 
   * BP, bP, all points on ed25519 curve, this 
   * compute the triple dh value.
   *
   * @param peer_ephemeral_key the ephemeral public key of peer i.e. aP 
   *                           in grcypt eddsa public key format
   * @param peer_long_term_key the long term public key of the peer i.e AP 
   *                            in gcrypt eddsa public key format
   * @param my_long_term_key   our longterm key in eddsa format
   * @param peer_is_first      true if AP.X|AP.Y < BP.X|BP.Y   
   * @param teddh_token        a pointer to hash block to store 
   *        hash(bAP|BaP|baP) if peer_is_first
   *        hash(BaP|bAP|baP) in GCRYMPI_FMT_USG format if the pointer is null
   *         , necessary space will be allocated.
   *
   * @return false if the operation fails, true on success
   */
  bool triple_ed_dh(np1secPublicKey peer_ephemeral_key, np1secPublicKey peer_long_term_key, np1secAsymmetricKey my_long_term_key, bool peer_is_first, HashBlock* teddh_token);

  /**
   * Given a valid std:string sign the string using the sessions
   * private key and return the signature.
   *
   * @param unsigned char ** representing a buffer to store the create signature
   * @param size_t representing the length of the return sig buffer
   * @parama std::string representing the message to be signed 
   *
   * @return gcry_error_t indicating whether the operation succeeded or not
   */
  gcry_error_t Sign(unsigned char **sigp,
                    size_t *siglenp, std::string plain_text);

  /**
   * Given a signed piece of data and a valid signature verify if
   * the signature is correct using the sessions public key.
   *
   * @param std::string representing signed data
   * @param const unsigned char*  representing data signature buffer
   *
   * @return gcry_error_t failure or verification of given signature
   */
  gcry_error_t Verify(std::string signed_text, const unsigned char *sigbuf);

  /**
   * Create instance of cipher session based on configured algorithm, mode,
   * key and iv.
   *
   * @return gcry_cipher_hd_t representing a cipher session handle
   */
  gcry_cipher_hd_t OpenCipher();


};

const unsigned char SESSION_KEY[] = {
  0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0,
  0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
  0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
};

const unsigned char SESSION_IV[] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
  0x0c, 0x0d, 0x0e, 0x0f
};

const int c_np1sec_hash = gcry_md_algos::GCRY_MD_SHA256;

#endif  // SRC_CRYPT_H_
