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

Ed25519Key::Ed25519Key(){
  return;
}

Cryptic::Cryptic() {
  /* Generate a new Ed25519 key pair. */
  gcry_error_t err = 0;
  gcry_sexp_t ed25519_parms, ed25519_keypair;

  err = gcry_sexp_build(&ed25519_parms, NULL,
                        "(genkey (ecc (curve Ed25519) (flags eddsa)))");
  if (err)
    std::printf ("Failure: %s/%s\n",
                        gcry_strsource (err),
                        gcry_strerror (err));

  err = gcry_pk_genkey(&ed25519_keypair, ed25519_parms);
  if (err)
    std::printf ("Failure to create ed25519 key pair: %s/%s\n",
                        gcry_strsource (err),
                        gcry_strerror (err));

  pub_key = gcry_sexp_find_token( ed25519_keypair, "public-key", 0 );
  if ( !pub_key ) {
    std::printf("ed25519Key: failed to retrieve public key");
  }
  
  prv_key = gcry_sexp_find_token( ed25519_keypair, "private-key", 0 );
  if ( !prv_key ) {
    std::printf("ed25519Key: failed to retrieve private key");
  }

  //gcry_sexp_release( ed25519_params );

}

std::string Cryptic::retrieveResult( gcry_sexp_t text_sexp ){
  size_t buffer_size = gcry_sexp_sprint (text_sexp, GCRYSEXP_FMT_ADVANCED,
                                            NULL, 0);
  if(!buffer_size){
    std::printf("ed25519Key: failed to convert s-expression to string");
    return NULL;
  }
  char* buffer = (char *) malloc(buffer_size);

  std::string result = buffer;
  free(buffer);
  return result;
}

gcry_sexp_t Cryptic::ConvertToSexp(std::string text){
  gcry_error_t err = 0;
  gcry_sexp_t new_sexp;

  err = gcry_sexp_new( &new_sexp, text.c_str(), text.size(), 1);
  if( err ){
    std::printf("ed25519Key: failed to convert plain_text to gcry_sexp_t\n");
    std::printf ("Failure: %s/%s\n",
                        gcry_strsource (err),
                        gcry_strerror (err));
  }

  return new_sexp;
}

gcry_error_t Cryptic::Sign( unsigned char **sigp, size_t *siglenp,
				 std::string plain_text ){
  gcry_mpi_t r,s;
  gcry_error_t err = 0;
  gcry_sexp_t plain_sexp, sigs, eddsa, rs, ss;
  size_t sig_r_len, sig_s_len;
  size_t nr, ns;
  const enum gcry_mpi_format format = GCRYMPI_FMT_USG;
  const int magic_number=40;

  *sigp = (unsigned char*) malloc(magic_number);

  err = gcry_sexp_build (&plain_sexp, NULL,
                          "(data"
                          " (flags eddsa)"
                          " (hash-algo sha512)"
                          " (value %b))",  plain_text.size(), plain_text.c_str());
  if( err ){
    std::printf("ed25519Key: failed to convert plain_text to gcry_sexp_t\n");
    std::printf ("Failure: %s/%s\n",
                        gcry_strsource (err),
                        gcry_strerror (err));
  }

  err = gcry_pk_sign( &sigs, plain_sexp, prv_key ); 

  if( err ){
    std::printf("ed25519Key: failed to sign plain_text");
    std::printf ("Failure: %s/%s\n",
                        gcry_strsource (err),
                        gcry_strerror (err));

  }

  gcry_sexp_release( plain_sexp );
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
  memset(*sigp, 0, 40);

  gcry_mpi_print(format, (*sigp)+(20-nr), nr, NULL, r);
  gcry_mpi_print(format, (*sigp)+20+(20-ns), ns, NULL, s);
  printf("sizes are r: %d s: %d\n", nr, ns);
  printf("\nsplatt 1 \n");
  gcry_mpi_dump(r);
  printf("\nsplatt 2 \n");
  gcry_mpi_dump(s);
  gcry_mpi_release(r);
  gcry_mpi_release(s);
  
  printf((const char*)sigp);
  return gcry_error(GPG_ERR_NO_ERROR);
}

gcry_error_t Cryptic::Verify( std::string plain_text, const unsigned char *sigbuf ){
  gcry_error_t err = 0;
  gcry_mpi_t datampi,r,s;
  gcry_sexp_t datas, sigs;

  if (plain_text.c_str()) {
    gcry_mpi_scan(&datampi, GCRYMPI_FMT_USG, plain_text.c_str(), plain_text.size(), NULL);
  } else {
    datampi = gcry_mpi_set_ui(NULL, 0);
  }
  gcry_sexp_build(&datas, NULL, "(%m)", datampi);
  gcry_mpi_release(datampi);

  gcry_mpi_scan(&r, GCRYMPI_FMT_USG, sigbuf, 20, NULL);
  gcry_mpi_scan(&s, GCRYMPI_FMT_USG, sigbuf+20, 20, NULL);
  gcry_sexp_build(&sigs, NULL, "(sig-val (eddsa (r %m)(s %m)))", r, s);
  printf("\nsplatt 3 \n");
  gcry_mpi_dump(r);
  printf("\nsplatt 4 \n");
  gcry_mpi_dump(s);
  printf("\n");
  gcry_mpi_release(r);
  gcry_mpi_release(s);

  if( err ){
    std::printf("ed25519Key: failed to convert plain_text to gcry_sexp_t\n");
    std::printf ("Failure: %s/%s\n",
                        gcry_strsource (err),
                        gcry_strerror (err));
  }

  err = gcry_pk_verify( sigs, datas, pub_key ); 

  if( err ){
    std::printf("ed25519Key: failed to verify signed_text");
    return false;
  }
  gcry_sexp_release(sigs);

  return err;
}

gcry_cipher_hd_t Cryptic::OpenCipher(){
  gcry_error_t err = 0;
  gcry_cipher_hd_t hd;
  int algo = GCRY_CIPHER_AES256, mode = GCRY_CIPHER_MODE_GCM;
  
  err = gcry_cipher_open( &hd, algo, mode, 0 );
  if( err ){
    std::printf("ed25519Key: Cipher creation failed");
  }
  err = gcry_cipher_setkey( hd, SESSION_KEY, 32);
  err = gcry_cipher_setiv( hd, SESSION_IV, 16 );

  return hd;
}
std::string Cryptic::Encrypt(std::string plain_text){
  std::string crypt_text = plain_text;
  gcry_error_t err = 0;
  gcry_cipher_hd_t hd = OpenCipher();

  err = gcry_cipher_encrypt( hd, const_cast<char *>(crypt_text.c_str()), crypt_text.size(), NULL, 0 );
  if( err ){
    std::printf("ed25519Key: Encryption of message failed");
  }
  
  gcry_cipher_close( hd );

  return crypt_text;
}

std::string Cryptic::Decrypt(std::string encrypted_text){
  std::string decrypted_text = encrypted_text;
  gcry_error_t err = 0;
  gcry_cipher_hd_t hd = OpenCipher();

  err = gcry_cipher_decrypt( hd, const_cast<char *>(decrypted_text.c_str()), decrypted_text.size(), NULL, 0 );
  if ( err ) {
    std::printf("ed25519Key: failed to decrypt message");
  }

  gcry_cipher_close( hd );

  return decrypted_text;
}

#endif  // SRC_CRYPT_CC_
