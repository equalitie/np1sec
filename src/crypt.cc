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

#ifndef SRC_CRYPT_CC_
#define SRC_CRYPT_CC_

#include <cstdio>

#include "src/crypt.h"


gcry_error_t Hash(const void *buffer, size_t buffer_len, HashBlock hb,
                  bool secure) {
  gcry_error_t err = 0;
  gcry_md_hd_t digest = nullptr;
  unsigned int flags = 0;
  unsigned char *hash_str = nullptr;

  if (secure)
    flags |= GCRY_MD_FLAG_SECURE;

  assert(!gcry_md_test_algo(c_np1sec_hash));
  err = gcry_md_open(&digest, c_np1sec_hash, flags);
  if (err)
    goto done;

  gcry_md_write(digest, buffer, buffer_len);
  hash_str = gcry_md_read(digest, c_np1sec_hash);
  assert(hash_str);
  memcpy(hb, hash_str, sizeof(HashBlock));

done:
  gcry_md_close(digest);
  return err;
}

gcry_error_t compute_message_hash(HashBlock transcript_chain,
                                     std::string message) {
  return Hash(message.c_str(), message.size(), transcript_chain, true);
}

Cryptic::Cryptic() {}

bool Cryptic::init() {
  /* Generate a new Ed25519 key pair. */
  gcry_error_t err = 0;
  gcry_sexp_t ed25519_parms, ed25519_keypair;

  err = gcry_sexp_build(&ed25519_parms, NULL,
                        "(genkey (ecc (curve Ed25519) (flags eddsa)))");
  if (err)
    goto err;

  err = gcry_pk_genkey(&ed25519_keypair, ed25519_parms);
  if (err)
    goto err;


  ephemeral_pub_key = gcry_sexp_find_token(ed25519_keypair, "public-key", 0);
  if (!ephemeral_pub_key) {
    std::printf("ed25519Key: failed to retrieve public key");
    return false;
  }

  ephemeral_prv_key = gcry_sexp_find_token(ed25519_keypair, "private-key", 0);
  if (!ephemeral_prv_key) {
    std::printf("ed25519Key: failed to retrieve private key");
    return false;
  }

  return true;

err:
  std::printf("Key failure: %s/%s\n", gcry_strsource(err), gcry_strerror(err));
  return false;
}

static std::string retrieveResult(gcry_sexp_t text_sexp) {
  size_t buffer_size = gcry_sexp_sprint(text_sexp, GCRYSEXP_FMT_ADVANCED, 	
  NULL, 0); 	
  if (!buffer_size) { 	
    std::printf("ed25519Key: failed to convert s-expression to string"); 	
    return NULL; 	
  } 	
 	
  char* buffer = reinterpret_cast<char *>(malloc(buffer_size)); 	
  std::string result = buffer; 	
  free(buffer); 	
  return result; 
}

gcry_sexp_t Cryptic::ConvertToSexp(std::string text) { 	
  gcry_error_t err = 0; 	
  gcry_sexp_t new_sexp; 	

  err = gcry_sexp_new(&new_sexp, text.c_str(), text.size(), 1); 	
  if (err) { 	
    std::printf("ed25519Key: failed to convert plain_text to gcry_sexp_t"); 	
  } 	
  return new_sexp; 	
}

gcry_error_t Cryptic::Sign(unsigned char **sigp, size_t *siglenp,
                           std::string plain_text) {
  gcry_mpi_t r, s;
  gcry_error_t err = 0;
  gcry_sexp_t plain_sexp, sigs, eddsa, rs, ss;
  size_t nr, ns;
  const enum gcry_mpi_format format = GCRYMPI_FMT_USG;
  const uint32_t magic_number = 64, half_magic_number = 32;

  *sigp = (unsigned char*) malloc(magic_number);

  err = gcry_sexp_build(&plain_sexp, NULL,
                          "(data"
                          " (flags eddsa)"
                          " (hash-algo sha512)"
                          " (value %b))",
                          plain_text.size(),
                          plain_text.c_str());

  if ( err ) {
    std::printf("ed25519Key: failed to convert plain_text to gcry_sexp_t\n");
    std::printf("Failure: %s/%s\n",
                        gcry_strsource(err),
                        gcry_strerror(err));
  }

  err = gcry_pk_sign(&sigs, plain_sexp, ephemeral_prv_key);

  if ( err ) {
    std::printf("ed25519Key: failed to sign plain_text");
    std::printf("Failure: %s/%s\n",
                        gcry_strsource(err),
                        gcry_strerror(err));
    return err;
  }

  gcry_sexp_release(plain_sexp);
  eddsa = gcry_sexp_find_token(sigs, "eddsa", 0);

  gcry_sexp_release(sigs);


  rs = gcry_sexp_find_token(eddsa, "r", 0);
  ss = gcry_sexp_find_token(eddsa, "s", 0);

  r = gcry_sexp_nth_mpi(rs, 1, GCRYMPI_FMT_USG);

  gcry_sexp_release(rs);

  s = gcry_sexp_nth_mpi(ss, 1, GCRYMPI_FMT_USG);
  gcry_sexp_release(ss);

  gcry_mpi_print(format, NULL, 0, &nr, r);
  gcry_mpi_print(format, NULL, 0, &ns, s);
  memset(*sigp, 0, magic_number);

  gcry_mpi_print(format, (*sigp)+(half_magic_number - nr), nr, NULL, r);
  /* 
   * if r has 0 on the left decimal positions, gcry_mpi_print cut them out 
   * and hence nr < half_magic_number
   */
  gcry_mpi_print(format, (*sigp)+ half_magic_number + (half_magic_number-ns),
                 ns, NULL, s);

  gcry_mpi_release(r);
  gcry_mpi_release(s);

  return gcry_error(GPG_ERR_NO_ERROR);
}

gcry_error_t Cryptic::Verify(std::string plain_text,
                             const unsigned char *sigbuf) {
  gcry_error_t err = 0;
  gcry_mpi_t r, s;
  gcry_sexp_t datas, sigs;
  static const uint32_t nr = 32, ns = 32;

  gcry_mpi_scan(&r, GCRYMPI_FMT_USG, sigbuf, nr, NULL);

  gcry_mpi_scan(&s, GCRYMPI_FMT_USG, sigbuf+nr, ns, NULL);

  gcry_sexp_build(&sigs, NULL, "(sig-val (eddsa (r %M)(s %M)))", r, s);


  gcry_mpi_release(r);
  gcry_mpi_release(s);

  err = gcry_sexp_build(&datas, NULL,
                          "(data"
                          " (flags eddsa)"
                          " (hash-algo sha512)"
                          " (value %b))",
                          plain_text.size(),
                          plain_text.c_str());
  if ( err ) {
    std::printf("ed25519Key: failed to convert plain_text to gcry_sexp_t\n");
    std::printf("Failure: %s/%s\n",
                        gcry_strsource(err),
                        gcry_strerror(err));
    return err;
  }


  err = gcry_pk_verify(sigs, datas, ephemeral_pub_key);

  if ( err ) {
    std::printf("ed25519Key: failed to verify signed_text");
    std::printf("Failure: %s/%s\n",
                        gcry_strsource(err),
                        gcry_strerror(err));
    return err;
  }
  gcry_sexp_release(sigs);

  return gcry_error(GPG_ERR_NO_ERROR);
}

gcry_cipher_hd_t Cryptic::OpenCipher() {
  gcry_error_t err = 0;
  gcry_cipher_hd_t hd;
  int algo = GCRY_CIPHER_AES256, mode = GCRY_CIPHER_MODE_GCM;

  err = gcry_cipher_open(&hd, algo, mode, 0);
  if ( err ) {
    std::printf("ed25519Key: Cipher creation failed");
  }
  err = gcry_cipher_setkey(hd, SESSION_KEY, 32);
  err = gcry_cipher_setiv(hd, SESSION_IV, 16);

  return hd;
}

std::string Cryptic::Encrypt(std::string plain_text) {
  std::string crypt_text = plain_text;
  gcry_error_t err = 0;
  gcry_cipher_hd_t hd = OpenCipher();

  err = gcry_cipher_encrypt(hd, const_cast<char *>(crypt_text.c_str()),
                            crypt_text.size(), NULL, 0);
  if (err) {
    std::printf("ed25519Key: Encryption of message failed");
  }

  gcry_cipher_close(hd);
  return crypt_text;
}

std::string Cryptic::Decrypt(std::string encrypted_text) {
  std::string decrypted_text = encrypted_text;
  gcry_error_t err = 0;
  gcry_cipher_hd_t hd = OpenCipher();

  err = gcry_cipher_decrypt(hd, const_cast<char *>(decrypted_text.c_str()),
                            decrypted_text.size(), NULL, 0);
  if (err) {
    std::printf("ed25519Key: failed to decrypt message");
  }

  gcry_cipher_close(hd);
  return decrypted_text;
}

#endif  // SRC_CRYPT_CC_
