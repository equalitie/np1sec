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

#include <cstdio>
#include "src/crypt.h"


#ifndef SRC_CRYPT_CC_
#define SRC_CRYPT_CC_

gcry_error_t Hash(const void *buffer, size_t buffer_len, HashBlock hb,
                  bool secure) {
  gcry_error_t err = 0;
  gcry_md_hd_t digest = nullptr;
  unsigned int flags = 0;
  unsigned char *hash_str = nullptr;

  if (secure)
    flags |= GCRY_MD_FLAG_SECURE;

  assert(!gcry_md_test_algo(c_mpseq_hash));
  err = gcry_md_open(&digest, c_mpseq_hash, flags);
  if (err)
    goto done;

  gcry_md_write(digest, buffer, buffer_len);
  hash_str = gcry_md_read(digest, c_mpseq_hash);
  assert(hash_str);
  memcpy(hb, hash_str, sizeof(HashBlock));

done:
  gcry_md_close(digest);
  return err;
}


Ed25519Key::Ed25519Key() {
  /* Generate a new Ed25519 key pair. */
  gcry_error_t err = 0;
  gcry_sexp_t ed25519_parms;

  err = gcry_sexp_build(&ed25519_parms, NULL,
                        "(genkey (ecc (curve ed25519) (flag eddsa)))");
  if (err)
    std::printf("gcrypt: failed to create ed25519 params\n");

  err = gcry_pk_genkey(&ed25519_keypair, ed25519_parms);
  if (err)
    std::printf("gcrypt: failed to create ed25519 key pair\n");

  pub_key = gcry_sexp_find_token( key, "public-key", 0 );
  if ( !pub_key ) {
    std:printf("ed25519Key: failed to retrieve public key");
  }
  
  prv_key = gcry_sexp_find_token( key, "private-key", 0 );
  if ( !pub_key ) {
    std:printf("ed25519Key: failed to retrieve private key");
  }


}

std::string Ed25519Key::Encrypt(std::string plain_text){
  gcry_sexp_t plain_sexp, crypt_sexp;

  charTosexp( plain_text, &plain_sexp );
  err = gcry_pk_encrypt( &crypt_sexp, plain_sexp, pub_key )
  if( err ){
    std:printf("ed25519Key: Encryption of message failed");
  }
  
  return
}

std:string Ed25519Key::Decrypt(std::string encrypted_text){
  gcry_sexp_t crypt_sexp;
  gcry_sexp_t data_decrypted = NULL;

  charTosexp( encrypted_text, &crypt_sexp );

  gcry_pk_decrypt( &data_decrypted, crypt_sexp, prv_key )

  return 
}

#endif  // SRC_CRYPT_CC_
