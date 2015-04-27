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

/*
 * For debug reason use
 * gcryp_sexp_dump and gcry_mpi_dump
 */
#ifndef SRC_CRYPT_CC_
#define SRC_CRYPT_CC_

#include <cstdio>
#include <string>


#include "src/crypt.h"
#include "src/exceptions.h"

using namespace std;

gcry_error_t Cryptic::hash(const void *buffer, size_t buffer_len, HashBlock hb,
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

Cryptic::Cryptic() {}

bool Cryptic::generate_key_pair(np1secAsymmetricKey* generated_key) {
  /* Generate a new Ed25519 key pair. */
  gcry_error_t err = 0;
  gcry_sexp_t ed25519_params;

  err = gcry_sexp_build(&ed25519_params, NULL,
                        "(genkey (ecc (curve Ed25519) (flags eddsa)))");
  if (err)
    goto err;

  err = gcry_pk_genkey(generated_key, ed25519_params);
  if (err)
    goto err;

  return true;

err:
  std::fprintf(stderr, "Key failure: %s/%s\n", gcry_strsource(err), gcry_strerror(err));
  throw np1secCryptoException();
  return false;
}

bool Cryptic::init() {
  /* Generate a new Ed25519 key pair. */
  gcry_error_t err = 0;
  gcry_sexp_t ed25519_params;

  err = gcry_sexp_build(&ed25519_params, NULL,
                        "(genkey (ecc (curve Ed25519) (flags eddsa)))");
  if (err)
    goto err;

  err = gcry_pk_genkey(&ephemeral_key, ed25519_params);
  if (err)
    goto err;

  ephemeral_pub_key = gcry_sexp_find_token(ephemeral_key, "public-key", 0);
  if (!ephemeral_pub_key) {
    std::printf("ed25519Key: failed to retrieve public key");
    throw np1secCryptoException();
    return false;
  }

  ephemeral_prv_key = gcry_sexp_find_token(ephemeral_key, "private-key", 0);
  if (!ephemeral_prv_key) {
    std::printf("ed25519Key: failed to retrieve private key");
    throw np1secCryptoException();
    return false;
  }

  return true;

err:
  std::printf("Key failure: %s/%s\n", gcry_strsource(err), gcry_strerror(err));
  return false;
}

gcry_sexp_t Cryptic::get_public_key(np1secAsymmetricKey key_pair)
{
  return gcry_sexp_find_token(key_pair, "public-key", 0);
}

std::string Cryptic::public_key_to_stringbuff(np1secAsymmetricKey public_key) {
  return retrieve_result(gcry_sexp_find_token(public_key
                                              , "q", 0));
}

std::string Cryptic::retrieve_result(gcry_sexp_t text_sexp) {
  //  size_t buffer_size = gcry_sexp_sprint(text_sexp, GCRYSEXP_FMT_ADVANCED, 	
  //                                      NULL, 0);
  gcry_mpi_t sexp_to_mpi = gcry_sexp_nth_mpi(text_sexp, 1, GCRYMPI_FMT_USG);

  size_t buffer_size;
  uint8_t* buffer;
  gcry_mpi_aprint(Cryptic::NP1SEC_BLOB_OUT_FORMAT, &buffer, &buffer_size, sexp_to_mpi);
  gcry_mpi_release(sexp_to_mpi);

  if (!buffer_size) { 	
    std::printf("ed25519Key: failed to convert s-expression to string"); 	
    return NULL; 	
  } 	

  std::string result(reinterpret_cast<char*>(buffer), buffer_size); 	
  free(buffer); 	
  return result;

}

gcry_sexp_t Cryptic::convert_to_sexp(std::string text) { 	
  gcry_error_t err = 0; 	
  gcry_sexp_t new_sexp; 	

  //assert(0);
  err = gcry_sexp_new(&new_sexp, text.c_str(), text.size(), 1); 	
  if (err) { 	
    std::printf("Cryptic::convert_to_sexp failed to convert plain_text to gcry_sexp_t");
    std::printf("Failure: %s/%s\n",
                gcry_strsource(err),
                gcry_strerror(err));

  } 	
  return new_sexp; 	

}

  /**
   * This function gets the value for q section of public-key and
   * reconstruct the whole sexp to be used in libgcrypt functions
   * 
[open]
  [data="public-key"]
  [open]
    [data="ecc"]
    [open]
      [data="curve"]
      [data="Ed25519"]
    [close]
    [open]
      [data="flags"]
      [data="eddsa"]
    [close]
    [open]
      [data="q"]
      [data="\xb83jR\xea\xebtI\xab\\x91E\xda\xff|Y\x94\xe1\xeck\xa8I<d\x804+\x18\x9b\xe5\x7f!"]
    [close]
  [close]
[close]
   */
np1secAsymmetricKey Cryptic::reconstruct_public_key_sexp(const std::string pub_key_block)
{
  gcry_error_t err = 0; 	
  np1secAsymmetricKey public_key_sexp = nullptr;
  gcry_mpi_t public_point_mpi;
  err = gcry_mpi_scan(&public_point_mpi,
                      NP1SEC_BLOB_OUT_FORMAT,
                      strbuff_to_hash(pub_key_block),
                      ED25519_KEY_SIZE,
                      NULL);
  
  if (err)
    goto err;
  
  err = gcry_sexp_build(&public_key_sexp,
                        NULL,
                        "(public-key (ecc (curve Ed25519) (flags eddsa) (q %M)))",
                        public_point_mpi);
  if (err)
    goto err;
  
  return public_key_sexp;
  
 err:
  std::fprintf(stderr, "failed to construct public key: %s/%s\n", gcry_strsource(err), gcry_strerror(err));
  throw np1secCryptoException();
  return nullptr;
}

void Cryptic::release_crypto_resource(gcry_sexp_t crypto_resource)
{
  gcry_sexp_release(crypto_resource);
}

gcry_sexp_t Cryptic::copy_crypto_resource(gcry_sexp_t crypto_resource)
{
  gcry_sexp_t copied_resource;
  gcry_error_t err = gcry_sexp_build(&copied_resource,
                        NULL,
                        "%S",
                        crypto_resource);
  if (err) {
    std::fprintf(stderr, "failed to copy crypto resource: %s/%s\n", gcry_strsource(err), gcry_strerror(err));
    throw np1secCryptoException();
    return nullptr;
  }

  return copied_resource;
  
};
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
 * @param order
 * @param teddh_token        a pointer to hash block to store 
 *        hash(bAP|BaP|baP) if AP.X|AP.Y < BP.X|BP.Y other wise 
 *        hash(BaP|bAP|baP) in GCRYMPI_FMT_USG format if the pointer is null
 *         , necessary space will be allocated.
 *
 * @return true if succeeds otherwise false
 */
bool Cryptic::triple_ed_dh(np1secPublicKey peer_ephemeral_key, np1secPublicKey peer_long_term_key, np1secAsymmetricKey my_long_term_key, bool peer_is_first, HashBlock* teddh_token)
{
  gcry_error_t err = 0;
  bool failed = true;
  //we need to call 
  //static gcry_err_code_t ecc_decrypt_raw (gcry_sexp_t *r_plain, gcry_sexp_t s_data, gcry_sexp_t keyparms)
  //which is ecdh function of gcryp (what a weird name?) such that:
  // gcrypt:
  // give the secret key as a key pair in keyparams
  // extract the point of  public key of the peer as s_data
  //this is quite a complicated opertaion so
  // we use ecc_encrypt_raw(the_public_point, 1, key);
  //initiating the to be encrypted 1
  gcry_sexp_t peer_ephemeral_point = NULL;
  gcry_sexp_t peer_long_term_point = NULL;
  gcry_mpi_t scaler_one = gcry_mpi_set_ui(NULL, 1);
  gcry_sexp_t s_data = NULL;
  gcry_sexp_t enc_point = NULL;

  gcry_sexp_t triple_dh_sexp[3] = {};
  uint8_t* feed_to_hash_buffer = NULL;
  string token_concat;

  //err=gcry_sexp_build(&s_data,NULL,"(data(flags raw)(value %m))",x);
  gcry_sexp_t my_long_term_secret_scaler = gcry_sexp_nth(gcry_sexp_find_token(my_long_term_key, "a", 0),1);
  gcry_sexp_t my_ephemeral_secret_scaler = gcry_sexp_nth(gcry_sexp_find_token(ephemeral_key, "a", 0),1);

  // err = gcry_pk_encrypt(triple_dh_sexp + (peer_is_first ? 0 : 1),
  //                       my_ephemeral_secret_scaler,
  //                       ephemeral_key);

  // //gcry_sexp_dump(triple_dh_sexp[peer_is_first ? 0 : 1]);


  // err = gcry_sexp_build( &s_data, NULL, "%m", scaler_one );
  // if ( err ) {
  //   std::printf("teddh: failed to compute dh token\n");
  //   std::printf("Failure: %s/%s\n",
  //                       gcry_strsource(err),
  //                       gcry_strerror(err));
  //   goto leave;
  //   }

  // err = gcry_pk_encrypt(&peer_ephemeral_point, s_data, ephemeral_key);
  //gcry_sexp_dump(peer_ephemeral_point);

  // err = gcry_pk_encrypt(&peer_ephemeral_point, s_data, peer_ephemeral_key);
  // if ( err ) {
  //   std::printf("teddh: failed to compute dh token\n");
  //   std::printf("Failure: %s/%s\n",
  //                       gcry_strsource(err),
  //                       gcry_strerror(err));
  //   goto leave;
  // }
  // //gcry_sexp_nth (const gcry_sexp_t list, int number)
  // //peer_ephemeral_point = gcry_sexp_nth(gcry_sexp_find_token(enc_point, "s", 0),1);

  // //reuse enc_point
  // //gcry_sexp_release(enc_point);
  // enc_point = NULL;
  
  // err = gcry_pk_encrypt(&peer_long_term_point, s_data, peer_long_term_key);
  // if ( err ) {
  //   std::printf("teddh: failed to compute dh token\n");
  //   std::printf("Failure: %s/%s\n",
  //                       gcry_strsource(err),
  //                       gcry_strerror(err));
  //   goto leave;
  // }
  // //peer_long_term_point = gcry_sexp_nth(gcry_sexp_find_token(enc_point, "s", 0),1);

  // gcry_sexp_dump(peer_long_term_key);
  // gcry_sexp_dump(peer_long_term_point);
  // gcry_sexp_dump(peer_ephemeral_point);
  // gcry_sexp_t peer_ephemeral_point = gcry_sexp_find_token(peer_ephemeral_key, "q", 0);
  // gcry_sexp_t peer_long_term_point = gcry_sexp_find_token(peer_long_term_key, "q", 0);

  //bAP
  err = gcry_pk_encrypt(triple_dh_sexp + (peer_is_first ? 0 : 1),
                        my_ephemeral_secret_scaler,
                        peer_long_term_key);

  if ( err ) {
    std::printf("teddh: failed to compute dh token\n");
    std::printf("Failure: %s/%s\n",
                        gcry_strsource(err),
                        gcry_strerror(err));
    goto leave;
  }


  //BaP
  err = gcry_pk_encrypt(triple_dh_sexp + (peer_is_first ? 1 : 0),
                        my_long_term_secret_scaler,
                        peer_ephemeral_key);
  if ( err ) {
    std::printf("teddh: failed to compute dh token\n");
    std::printf("Failure: %s/%s\n",
                        gcry_strsource(err),
                        gcry_strerror(err));
  }

  //abP
  err = gcry_pk_encrypt(triple_dh_sexp+2,
                        my_ephemeral_secret_scaler,
                        peer_ephemeral_key);

  if ( err ) {
    std::printf("teddh: failed to compute dh token\n");
    std::printf("Failure: %s/%s\n",
                        gcry_strsource(err),
                        gcry_strerror(err));
    goto leave;

  }

  //bAP
  // err = gcry_pk_decrypt(triple_dh_sexp + (peer_is_first ? 0 : 1),
  //                       peer_long_term_point,
  //                       ephemeral_key);

  // if ( err ) {
  //   std::printf("teddh: failed to compute dh token\n");
  //   std::printf("Failure: %s/%s\n",
  //                       gcry_strsource(err),
  //                       gcry_strerror(err));
  //   goto leave;
  // }

  // //BaP
  // err = gcry_pk_decrypt(triple_dh_sexp + (peer_is_first ? 1 : 0),
  //                       peer_ephemeral_point,
  //                       my_long_term_key);
  // if ( err ) {
  //   std::printf("teddh: failed to compute dh token\n");
  //   std::printf("Failure: %s/%s\n",
  //                       gcry_strsource(err),
  //                       gcry_strerror(err));

  //   goto leave;
  // }
  
  // //abP
  // err = gcry_pk_decrypt(triple_dh_sexp+2,
  //                       peer_ephemeral_point,
  //                       ephemeral_key);

  // if ( err ) {
  //   std::printf("teddh: failed to compute dh token\n");
  //   std::printf("Failure: %s/%s\n",
  //                       gcry_strsource(err),
  //                       gcry_strerror(err));
  //   goto leave;

  // }

  for(int i = 0; i < 3; i++) {
    // std::printf("%d\n",i);
    // gcry_sexp_dump(triple_dh_sexp[i]);

    token_concat += retrieve_result(gcry_sexp_find_token(triple_dh_sexp[i], "s", 0));
    gcry_sexp_release(triple_dh_sexp[i]);
  }

  for(int i = 0; i < 3; i++) 
    for(int j = i; j < 3; j++)
      if (i != j && token_concat.substr(j*65,j*65+65) == token_concat.substr(i*65,i*65+65))
        std::printf("teddh: something is wrong: token %d and %d are equal\n", i, j);
  


  feed_to_hash_buffer = new uint8_t[token_concat.size()];
  token_concat.copy(reinterpret_cast<char*>(feed_to_hash_buffer), token_concat.size());

  if (teddh_token == NULL)
    teddh_token = new HashBlock[1]; //so stupid!!!
  
  hash(feed_to_hash_buffer, token_concat.size(), *teddh_token, true);

  failed = false;

 leave:
  gcry_mpi_release(scaler_one);
  gcry_sexp_release(s_data);
  gcry_sexp_release(enc_point);
  gcry_sexp_release(peer_ephemeral_point);
  gcry_sexp_release(peer_long_term_point);

  delete feed_to_hash_buffer;

  return !failed;
  
};

gcry_error_t Cryptic::sign(unsigned char **sigp, size_t *siglenp,
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
    std::printf("ed25519Key: failed to build gcry_sexp_t for sign\n");
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

  //it seems that we have assumed this
  assert(magic_number >= nr+ns);
  *siglenp = nr+ns;
  
  gcry_mpi_release(r);
  gcry_mpi_release(s);

  return gcry_error(GPG_ERR_NO_ERROR);
}

gcry_error_t Cryptic::verify(std::string plain_text,
                             const unsigned char *sigbuf,
                             np1secPublicKey signer_ephemeral_pub_key) {
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
    std::printf("ed25519Key: failed to build gcry_sexp_t\n");
    std::printf("Failure: %s/%s\n",
                        gcry_strsource(err),
                        gcry_strerror(err));
    return err;
  }


  err = gcry_pk_verify(sigs, datas, signer_ephemeral_pub_key);

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
  err = gcry_cipher_setkey(hd, session_key, sizeof(np1secSymmetricKey));
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
