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
#include "src/logger.h"

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
  logger.error(std::string("Key failure: ") + gcry_strsource(err)+ "/" + gcry_strerror(err), __FUNCTION__);
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
    logger.error("failed to retrieve public key",__FUNCTION__);
    throw np1secCryptoException();
    return false;
  }

  ephemeral_prv_key = gcry_sexp_find_token(ephemeral_key, "private-key", 0);
  if (!ephemeral_prv_key) {
    logger.error("failed to retrieve private key", __FUNCTION__);
    throw np1secCryptoException();
    return false;
  }

  return true;

err:
  logger.error(std::string("Key failure: ") + gcry_strsource(err)+"/" + gcry_strerror(err), __FUNCTION__);
  throw np1secCryptoException();
  
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
  gcry_mpi_t sexp_to_mpi = gcry_sexp_nth_mpi(text_sexp, 1, GCRYMPI_FMT_USG);

  size_t buffer_size;
  uint8_t* buffer;
  gcry_mpi_aprint(Cryptic::NP1SEC_BLOB_OUT_FORMAT, &buffer, &buffer_size, sexp_to_mpi);
  gcry_mpi_release(sexp_to_mpi);

  if (!buffer_size) { 	
    logger.error("failed to convert s-expression to string", __FUNCTION__); 	
    throw np1secCryptoException();
  } 	

  std::string result(reinterpret_cast<char*>(buffer), buffer_size); 	
  free(buffer); 	
  return result;

}

gcry_sexp_t Cryptic::convert_to_sexp(std::string text) { 	
  gcry_error_t err = 0; 	
  gcry_sexp_t new_sexp; 	

  err = gcry_sexp_new(&new_sexp, text.c_str(), text.size(), 1); 	
  if (err) { 	
    logger.error("Cryptic::convert_to_sexp failed to convert plain_text to gcry_sexp_t", __FUNCTION__);
    logger.error(std::string("Failure: ")+ gcry_strsource(err) + "/" +gcry_strerror(err), __FUNCTION__);
    throw np1secCryptoException();

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
  logger.error(std::string("failed to construct public key: ") + gcry_strsource(err) + "/" + gcry_strerror(err), __FUNCTION__);
  throw np1secCryptoException();
  return nullptr;
}

void Cryptic::release_crypto_resource(gcry_sexp_t crypto_resource)
{
  if (crypto_resource)
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
    logger.error(std::string("failed to copy crypto resource: ") + gcry_strsource(err)+"/" + gcry_strerror(err), __FUNCTION__);
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
void Cryptic::triple_ed_dh(np1secPublicKey peer_ephemeral_key, np1secPublicKey peer_long_term_key, np1secAsymmetricKey my_long_term_key, bool peer_is_first, HashBlock* teddh_token)
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

  //bAP
  err = gcry_pk_encrypt(triple_dh_sexp + (peer_is_first ? 0 : 1),
                        my_ephemeral_secret_scaler,
                        peer_long_term_key);

  if ( err ) {
    logger.error("teddh: failed to compute dh token\n", __FUNCTION__);
    logger.error(std::string("Failure: ")+
                 gcry_strsource(err) + "/" +
                 gcry_strerror(err), __FUNCTION__);
    goto leave;
  }


  //BaP
  err = gcry_pk_encrypt(triple_dh_sexp + (peer_is_first ? 1 : 0),
                        my_long_term_secret_scaler,
                        peer_ephemeral_key);
  if ( err ) {
    logger.error("teddh: failed to compute dh token\n", __FUNCTION__);
    logger.error(std::string("Failure: ")+
                 gcry_strsource(err) + "/" +
                 gcry_strerror(err), __FUNCTION__);
    goto leave;
  }

  //abP
  err = gcry_pk_encrypt(triple_dh_sexp+2,
                        my_ephemeral_secret_scaler,
                        peer_ephemeral_key);

  if ( err ) {
    logger.error("teddh: failed to compute dh token\n", __FUNCTION__);
    logger.error(std::string("Failure: ")+
                 gcry_strsource(err) + "/" +
                 gcry_strerror(err), __FUNCTION__);
    goto leave;

  }

  for(int i = 0; i < 3; i++) {
    token_concat += retrieve_result(gcry_sexp_find_token(triple_dh_sexp[i], "s", 0));
    gcry_sexp_release(triple_dh_sexp[i]);
  }

  for(int i = 0; i < 3; i++) 
    for(int j = i; j < 3; j++)
      if (i != j && token_concat.substr(j*65,j*65+65) == token_concat.substr(i*65,i*65+65)) {
        logger.error("teddh: something is wrong: token " + to_string(i) + " and "+ to_string(j) + " are equal\n", __FUNCTION__);
        throw np1secCryptoException();
      }
  


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

  if (failed)
    throw np1secCryptoException();

};

void Cryptic::sign(unsigned char **sigp, size_t *siglenp,
                           std::string plain_text) {
  gcry_mpi_t r, s;
  gcry_error_t err = 0;
  gcry_sexp_t plain_sexp, sigs, eddsa, rs, ss;
  size_t nr, ns;
  const enum gcry_mpi_format format = GCRYMPI_FMT_USG;
  const uint32_t magic_number = 64, half_magic_number = 32;

  *sigp = (unsigned char*) xmalloc(magic_number);

  err = gcry_sexp_build(&plain_sexp, NULL,
                          "(data"
                          " (flags eddsa)"
                          " (hash-algo sha512)"
                          " (value %b))",
                          plain_text.size(),
                          plain_text.c_str());

  if ( err ) {
    logger.error("ed25519Key: failed to build gcry_sexp_t for signing", __FUNCTION__);
    goto err;
  }

  err = gcry_pk_sign(&sigs, plain_sexp, ephemeral_prv_key);

  if ( err ) {
    gcry_sexp_release(plain_sexp);
    logger.error("ed25519Key: failed to sign plain_text", __FUNCTION__);
    goto err;
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
  logger.assert_or_die(magic_number >= nr+ns, "signature length is wrong", __FUNCTION__);
  *siglenp = nr+ns;
  
  gcry_mpi_release(r);
  gcry_mpi_release(s);

  return;

 err:
  if (*sigp) delete[] *sigp;
  logger.error("Failure: " + (string)gcry_strsource(err) + (string)gcry_strerror(err));
  throw np1secCryptoException();

}

bool Cryptic::verify(std::string plain_text,
                             const unsigned char *sigbuf,
                             np1secPublicKey signer_ephemeral_pub_key) {
  gcry_error_t err;
  gcry_mpi_t r, s;
  gcry_sexp_t datas, sigs;
  static const uint32_t nr = 32, ns = 32;

  err = gcry_mpi_scan(&r, GCRYMPI_FMT_USG, sigbuf, nr, NULL);
  if ( err ) {
    logger.error("failed to reconstruct the signature.", __FUNCTION__);
    goto err;
  }

  err = gcry_mpi_scan(&s, GCRYMPI_FMT_USG, sigbuf+nr, ns, NULL);
  if ( err ) {
    gcry_mpi_release(r);
    logger.error("failed to reconstruct the signed blob.", __FUNCTION__);
    goto err;
  }

  err = gcry_sexp_build(&sigs, NULL, "(sig-val (eddsa (r %M)(s %M)))", r, s);

  gcry_mpi_release(r);
  gcry_mpi_release(s);

  if ( err ) {
    logger.error("failed to construct gcry_sexp_t for the signature", __FUNCTION__);
    goto err;
  }

  err = gcry_sexp_build(&datas, NULL,
                          "(data"
                          " (flags eddsa)"
                          " (hash-algo sha512)"
                          " (value %b))",
                          plain_text.size(),
                          plain_text.c_str());
  if ( err ) {
    gcry_sexp_release(sigs);
    logger.error("failed to build gcry_sexp_t for the signed blob", __FUNCTION__);
    goto err;
  }

  err = gcry_pk_verify(sigs, datas, signer_ephemeral_pub_key);

  gcry_sexp_release(sigs);
  gcry_sexp_release(datas);
  if (err == GPG_ERR_NO_ERROR) {
    logger.info("good signature", __FUNCTION__);
    return true;
    
  }else if ( err == GPG_ERR_BAD_SIGNATURE ) {
    logger.warn("failed to verify signed blobed", __FUNCTION__);
    logger.warn("Failure: " + (string)gcry_strsource(err) + "/" + (string)gcry_strerror(err), __FUNCTION__);
    return false;
  }  else {
    logger.error("ed25519Key: failed to build gcry_sexp_t", __FUNCTION__);
    goto err;
  }
    
 err:
  logger.error("Failure: " + (string)gcry_strsource(err) + (string)gcry_strerror(err), __FUNCTION__);
  throw np1secCryptoException();
  
}

gcry_cipher_hd_t Cryptic::OpenCipher() {
  gcry_error_t err = 0;
  gcry_cipher_hd_t hd;
  int algo = GCRY_CIPHER_AES256, mode = GCRY_CIPHER_MODE_GCM;

  err = gcry_cipher_open(&hd, algo, mode, 0);
  if ( err ) {
    logger.error("Failed to create GCMb Block cipher", __FUNCTION__);
    goto err;
  }
  
  err = gcry_cipher_setkey(hd, session_key, sizeof(np1secSymmetricKey));
  if ( err ) {
    logger.error("Failed to set the block cipher key", __FUNCTION__);
    goto err;
  }
      
  return hd;

 err:
  if (hd) gcry_cipher_close(hd);
  logger.error("Failure: " + (string)gcry_strsource(err) + (string)gcry_strerror(err), __FUNCTION__);
  throw np1secCryptoException();
  
}

std::string Cryptic::Encrypt(std::string plain_text) {
  std::string crypt_text = plain_text;
  gcry_error_t err = 0;
  gcry_cipher_hd_t hd = OpenCipher(); //TODO: we shouldn't need to open cipher all the time

  IVBlock buffer;

  gcry_randomize(buffer, c_iv_length, GCRY_STRONG_RANDOM);
  err = gcry_cipher_setiv(hd, buffer, c_iv_length);

  if (err) {
    logger.error("Failed to set the block cipher iv");
    goto err;
  }

  err = gcry_cipher_encrypt(hd, const_cast<char *>(crypt_text.c_str()),
                            crypt_text.size(), NULL, 0);
  if (err) {
    logger.error("ed25519Key: Encryption of message failed");
    goto err;
  }

  crypt_text = std::string(reinterpret_cast<char*>(buffer), c_iv_length) + crypt_text;
  
  gcry_cipher_close(hd);
  return crypt_text;

 err:
  if (hd) gcry_cipher_close(hd);
  logger.error("Failure: " + (string)gcry_strsource(err) + (string)gcry_strerror(err));
  throw np1secCryptoException();
 
}

std::string Cryptic::Decrypt(std::string encrypted_text) {
  gcry_error_t err = 0;
  gcry_cipher_hd_t hd = OpenCipher();

  //The first 16bytes of encrypted text is the iv
  err = gcry_cipher_setiv(hd, encrypted_text.data(), c_iv_length);

  if (err) {
    logger.error("Failed to set the block cipher iv");
    goto err;
  } else {
    std::string decrypted_text = encrypted_text.substr(c_iv_length);

    err = gcry_cipher_decrypt(hd, const_cast<char *>(decrypted_text.c_str()),
                            decrypted_text.size(), NULL, 0);
    if (err) {
      logger.error("failed to decrypt message");
      goto err;
    }

    gcry_cipher_close(hd);
    return decrypted_text;

  }

 err:
  if (hd) gcry_cipher_close(hd);
  logger.error("Failure: " + (string)gcry_strsource(err) + (string)gcry_strerror(err));
  throw np1secCryptoException();

}

#endif  // SRC_CRYPT_CC_
