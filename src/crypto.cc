/**
 * (n+1)Sec Multiparty Off-the-Record Messaging library
 * Copyright (C) 2016, eQualit.ie
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

#include "crypto.h"
#include "message.h"

#include <cassert>

extern "C" {
#include "gcrypt.h"
}

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

namespace np1sec
{

static const int c_np1sec_hash = gcry_md_algos::GCRY_MD_SHA256;
static const int c_np1sec_cipher = GCRY_CIPHER_AES256;
static const int c_np1sec_cipher_mode = GCRY_CIPHER_MODE_GCM;
static const int c_np1sec_cipher_iv_length = 16;
static const int c_tdh_point_length = 65;



SymmetricKey::~SymmetricKey()
{
	secure_wipe(key.buffer, sizeof(key.buffer));
}

PrivateKey::PrivateKey():
	m_private_key(nullptr)
{}

PrivateKey::PrivateKey(gcry_sexp_t sexp)
{
	gcry_ctx_t public_key_parameters;
	if (gcry_mpi_ec_new(&public_key_parameters, sexp, NULL)) {
		throw CryptoException();
	}
	gcry_sexp_t public_key_sexp;
	if (gcry_pubkey_get_sexp(&public_key_sexp, GCRY_PK_GET_PUBKEY, public_key_parameters)) {
		gcry_ctx_release(public_key_parameters);
		throw CryptoException();
	}
	gcry_ctx_release(public_key_parameters);
	
	gcry_sexp_t q = gcry_sexp_find_token(public_key_sexp, "q", 0);
	if (!q) {
		gcry_sexp_release(public_key_sexp);
		throw CryptoException();
	}
	gcry_sexp_release(public_key_sexp);
	size_t q_size;
	const char *q_buffer = gcry_sexp_nth_data(q, 1, &q_size);
	if (!q_buffer) {
		gcry_sexp_release(q);
		throw CryptoException();
	}
	assert(q_size == sizeof(m_public_key.buffer));
	memcpy(m_public_key.buffer, q_buffer, sizeof(m_public_key.buffer));
	gcry_sexp_release(q);
	
	if (gcry_sexp_build(&m_private_key, NULL, "%S", sexp)) {
		throw CryptoException();
	}
}

PrivateKey::PrivateKey(const PrivateKey& other):
	m_private_key(nullptr)
{
	(*this) = other;
}

PrivateKey& PrivateKey::operator=(const PrivateKey& other)
{
	if (this == &other) {
		return *this;
	}
	
	if (m_private_key) {
		gcry_sexp_release(m_private_key);
	}
	
	if (other.m_private_key) {
		if (gcry_sexp_build(&m_private_key, NULL, "%S", other.m_private_key)) {
			throw CryptoException();
		}
	} else {
		m_private_key = nullptr;
	}
	
	m_public_key = other.m_public_key;
	
	return *this;
}

PrivateKey::~PrivateKey()
{
	gcry_sexp_release(m_private_key);
}

PrivateKey PrivateKey::generate(bool transient)
{
	const char* parameter_string;
	if (transient) {
		parameter_string = "(genkey (ecc (curve Ed25519) (flags eddsa transient-key)))";
	} else {
		parameter_string = "(genkey (ecc (curve Ed25519) (flags eddsa)))";
	}
	
	gcry_sexp_t generation_parameters;
	if (gcry_sexp_build(&generation_parameters, NULL, parameter_string)) {
		throw CryptoException();
	}
	
	gcry_sexp_t key_sexp;
	if (gcry_pk_genkey(&key_sexp, generation_parameters)) {
		gcry_sexp_release(generation_parameters);
		throw CryptoException();
	}
	gcry_sexp_release(generation_parameters);
	
	PrivateKey result(key_sexp);
	gcry_sexp_release(key_sexp);
	return result;
}

SerializedPrivateKey PrivateKey::serialize() const
{
	gcry_sexp_t d = gcry_sexp_find_token(m_private_key, "d", 0);
	if (!d) {
		throw CryptoException();
	}
	size_t d_size;
	const char *d_buffer = gcry_sexp_nth_data(d, 1, &d_size);
	if (!d_buffer) {
		gcry_sexp_release(d);
		throw CryptoException();
	}
	assert(d_size == c_private_key_length);
	SerializedPrivateKey output;
	memcpy(output.buffer, d_buffer, c_private_key_length);
	gcry_sexp_release(d);
	return output;
}

PrivateKey PrivateKey::unserialize(const SerializedPrivateKey& serialized_key)
{
	gcry_sexp_t key_sexp;
	if (gcry_sexp_build(&key_sexp, NULL, "(private-key (ecc (curve Ed25519) (flags eddsa) (d %b)))", sizeof(serialized_key.buffer), serialized_key.buffer)) {
		throw CryptoException();
	}
	
	try {
		PrivateKey key(key_sexp);
		gcry_sexp_release(key_sexp);
		return key;
	} catch(...) {
		gcry_sexp_release(key_sexp);
		throw;
	}
}



namespace crypto
{

Hash hash(const std::string& buffer, bool secure)
{
	gcry_md_hd_t digest;
	unsigned int flags = 0;
	
	if (secure) {
		flags |= GCRY_MD_FLAG_SECURE;
	}
	
	if (gcry_md_open(&digest, c_np1sec_hash, flags)) {
		throw CryptoException();
	}
	
	gcry_md_write(digest, buffer.data(), buffer.size());
	unsigned char *digest_buffer = gcry_md_read(digest, c_np1sec_hash);
	
	Hash result;
	memcpy(result.buffer, digest_buffer, sizeof(result.buffer));
	
	gcry_md_close(digest);
	return result;
}

void create_nonce(unsigned char *buffer, size_t size)
{
	gcry_create_nonce(buffer, size);
}

std::string encrypt(const std::string& plaintext, const SymmetricKey& key)
{
	gcry_cipher_hd_t cipher;
	if (gcry_cipher_open(&cipher, c_np1sec_cipher, c_np1sec_cipher_mode, 0)) {
		throw CryptoException();
	}
	if (gcry_cipher_setkey(cipher, key.key.buffer, sizeof(key.key.buffer))) {
		gcry_cipher_close(cipher);
		throw CryptoException();
	}
	
	ByteArray<c_np1sec_cipher_iv_length> initialization_vector = nonce<c_np1sec_cipher_iv_length>();
	if (gcry_cipher_setiv(cipher, initialization_vector.buffer, sizeof(initialization_vector.buffer))) {
		gcry_cipher_close(cipher);
		throw CryptoException();
	}
	
	unsigned char* ciphertext_buffer = new unsigned char[plaintext.size()];
	if (gcry_cipher_encrypt(cipher, ciphertext_buffer, plaintext.size(), reinterpret_cast<const char *>(plaintext.data()), plaintext.size())) {
		delete[] ciphertext_buffer;
		gcry_cipher_close(cipher);
		throw CryptoException();
	}
	
	std::string ciphertext(reinterpret_cast<char *>(ciphertext_buffer), plaintext.size());
	delete[] ciphertext_buffer;
	gcry_cipher_close(cipher);
	
	// The encoded ciphertext consists of the initialization vector followed by the ciphertext proper.
	return initialization_vector.as_string() + ciphertext;
}

std::string decrypt(const std::string& ciphertext, const SymmetricKey& key)
{
	// The encoded ciphertext consists of the initialization vector followed by the ciphertext proper.
	if (ciphertext.size() < c_np1sec_cipher_iv_length) {
		throw MessageFormatException();
	}
	
	gcry_cipher_hd_t cipher;
	if (gcry_cipher_open(&cipher, c_np1sec_cipher, c_np1sec_cipher_mode, 0)) {
		throw CryptoException();
	}
	if (gcry_cipher_setkey(cipher, key.key.buffer, sizeof(key.key.buffer))) {
		gcry_cipher_close(cipher);
		throw CryptoException();
	}
	
	if (gcry_cipher_setiv(cipher, ciphertext.data(), c_np1sec_cipher_iv_length)) {
		gcry_cipher_close(cipher);
		throw CryptoException();
	}
	
	size_t plaintext_size = ciphertext.size() - c_np1sec_cipher_iv_length;
	unsigned char* plaintext_buffer = new unsigned char[plaintext_size];
	if (gcry_cipher_decrypt(cipher, plaintext_buffer, plaintext_size, ciphertext.data() + c_np1sec_cipher_iv_length, plaintext_size)) {
		delete[] plaintext_buffer;
		gcry_cipher_close(cipher);
		throw CryptoException();
	}
	
	std::string plaintext(reinterpret_cast<char *>(plaintext_buffer), plaintext_size);
	delete[] plaintext_buffer;
	gcry_cipher_close(cipher);
	
	return plaintext;
}

Signature sign(const std::string& payload, const PrivateKey& key)
{
	assert(!key.is_null());
	
	gcry_sexp_t payload_sexp;
	if (gcry_sexp_build(&payload_sexp, NULL, "(data (flags eddsa) (hash-algo sha512) (value %b))", payload.size(), payload.data())) {
		throw CryptoException();
	}
	
	gcry_sexp_t signature_sexp;
	if (gcry_pk_sign(&signature_sexp, payload_sexp, key.sexp())) {
		gcry_sexp_release(payload_sexp);
		throw CryptoException();
	}
	gcry_sexp_release(payload_sexp);
	
	gcry_sexp_t r_sexp = gcry_sexp_find_token(signature_sexp, "r", 0);
	if (!r_sexp) {
		gcry_sexp_release(signature_sexp);
		throw CryptoException();
	}
	size_t r_size;
	const char *r_buffer = gcry_sexp_nth_data(r_sexp, 1, &r_size);
	if (!r_buffer) {
		gcry_sexp_release(r_sexp);
		gcry_sexp_release(signature_sexp);
		throw CryptoException();
	}
	
	gcry_sexp_t s_sexp = gcry_sexp_find_token(signature_sexp, "s", 0);
	if (!s_sexp) {
		gcry_sexp_release(r_sexp);
		gcry_sexp_release(signature_sexp);
		throw CryptoException();
	}
	size_t s_size;
	const char *s_buffer = gcry_sexp_nth_data(s_sexp, 1, &s_size);
	if (!s_buffer) {
		gcry_sexp_release(s_sexp);
		gcry_sexp_release(r_sexp);
		gcry_sexp_release(signature_sexp);
		throw CryptoException();
	}
	
	Signature result;
	assert(r_size == sizeof(result.buffer) / 2);
	assert(r_size + s_size == sizeof(result.buffer));
	memcpy(result.buffer, r_buffer, r_size);
	memcpy(result.buffer + r_size, s_buffer, s_size);
	
	gcry_sexp_release(s_sexp);
	gcry_sexp_release(r_sexp);
	gcry_sexp_release(signature_sexp);
	
	return result;
}

bool verify(const std::string& payload, const Signature& signature, const PublicKey& key)
{
	gcry_sexp_t key_sexp;
	if (gcry_sexp_build(&key_sexp, NULL, "(public-key (ecc (curve Ed25519) (flags eddsa) (q %b)))", sizeof(key.buffer), key.buffer)) {
		throw CryptoException();
	}
	
	gcry_sexp_t signature_sexp;
	if (gcry_sexp_build(&signature_sexp, NULL, "(sig-val (eddsa (r %b)(s %b)))", 32, signature.buffer, 32, signature.buffer + 32)) {
		gcry_sexp_release(key_sexp);
		throw CryptoException();
	}
	
	gcry_sexp_t payload_sexp;
	if (gcry_sexp_build(&payload_sexp, NULL, "(data (flags eddsa) (hash-algo sha512) (value %b))", payload.size(), payload.data())) {
		gcry_sexp_release(signature_sexp);
		gcry_sexp_release(key_sexp);
		throw CryptoException();
	}
	
	gcry_error_t error = gcry_pk_verify(signature_sexp, payload_sexp, key_sexp);
	
	gcry_sexp_release(payload_sexp);
	gcry_sexp_release(signature_sexp);
	gcry_sexp_release(key_sexp);
	
	return error == 0;
}



/*
 * gcrypt ed25519 private keys only contain the information necessary for
 * signing, not the actual scalar. This function re-implements the computation
 * of the private key scalar, stolen from gcrypt, which we need for 3DH.
 *
 * returns a sexp containing the scalar, which the caller needs to release.
 * returns NULL on error.
 */
static gcry_sexp_t compute_private_key_scalar(gcry_sexp_t private_key)
{
	gcry_sexp_t d = gcry_sexp_find_token(private_key, "d", 0);
	if (!d) {
		return nullptr;
	}
	size_t d_size;
	const char *d_buffer = gcry_sexp_nth_data(d, 1, &d_size);
	if (!d_buffer) {
		gcry_sexp_release(d);
		return nullptr;
	}
	
	gcry_md_hd_t digest;
	if (gcry_md_open(&digest, GCRY_MD_SHA512, GCRY_MD_FLAG_SECURE)) {
		gcry_sexp_release(d);
		return nullptr;
	}
	gcry_md_write(digest, d_buffer, d_size);
	gcry_sexp_release(d);
	
	unsigned char *hash = gcry_md_read(digest, GCRY_MD_SHA512);
	unsigned char hash_buffer[32];
	for (size_t i = 0; i < (sizeof hash_buffer); i++) {
		hash_buffer[i] = hash[(sizeof hash_buffer) - i - 1];
	}
	hash_buffer[0] = (hash_buffer[0] & 0x7f) | 0x40;
	hash_buffer[(sizeof hash_buffer) - 1] &= 0xf8;
	gcry_md_close(digest);
	
	gcry_mpi_t a;
	if (gcry_mpi_scan(&a, GCRYMPI_FMT_STD, hash_buffer, sizeof hash_buffer, NULL)) {
		return nullptr;
	}
	gcry_sexp_t result;
	if (gcry_sexp_build(&result, NULL, "%m", a)) {
		gcry_mpi_release(a);
		return nullptr;
	}
	gcry_mpi_release(a);
	
	return result;
}

/*
 * gcrypt stores ed25519 public keys in a form that gcry_pk_encrypt()
 * doesn't understand. This function translates it into a form that
 * can be used with gcry_pk_encrypt(). The resulting key form probably
 * will NOT work with any other gcrypt functions.
 *
 * This hack will probably break as soon as gcrypt adds proper ed25519
 * support. We'll need to ifdef it out when this support arrives.
 *
 * returns a public key sexp. returns NULL on error.
 */
static gcry_sexp_t convert_ed25519_encryption_key(gcry_sexp_t public_key)
{
	gcry_ctx_t public_key_parameters;
	if (gcry_mpi_ec_new(&public_key_parameters, public_key, NULL)) {
		return nullptr;
	}
	
	gcry_mpi_t scalar = gcry_mpi_ec_get_mpi("q", public_key_parameters, 0);
	gcry_ctx_release(public_key_parameters);
	if (!scalar) {
		return nullptr;
	}
	
	gcry_sexp_t key_sexp;
	gcry_error_t err = gcry_sexp_build(&key_sexp, NULL, "(public-key (ecc (curve Ed25519) (flags eddsa) (q %m)))", scalar);
	gcry_mpi_release(scalar);
	if (err) {
		return nullptr;
	}
	
	return key_sexp;
}

/*
 * For an ed25519 public key [g]x and private key y, computes [g]xy.
 */
static ByteArray<c_tdh_point_length> compute_dh_token(const PrivateKey& private_key, const PublicKey& public_key)
{
	assert(!private_key.is_null());
	
	gcry_sexp_t private_scalar_sexp = compute_private_key_scalar(private_key.sexp());
	if (!private_scalar_sexp) {
		throw CryptoException();
	}
	
	gcry_sexp_t public_key_sexp;
	if (gcry_sexp_build(&public_key_sexp, NULL, "(public-key (ecc (curve Ed25519) (flags eddsa) (q %b)))", sizeof(public_key.buffer), public_key.buffer)) {
		gcry_sexp_release(private_scalar_sexp);
		throw CryptoException();
	}
	
	gcry_sexp_t public_encryption_key_sexp = convert_ed25519_encryption_key(public_key_sexp);
	if (!public_encryption_key_sexp) {
		gcry_sexp_release(public_key_sexp);
		gcry_sexp_release(private_scalar_sexp);
		throw CryptoException();
	}
	gcry_sexp_release(public_key_sexp);
	
	gcry_sexp_t point_sexp;
	if (gcry_pk_encrypt(&point_sexp, private_scalar_sexp, public_encryption_key_sexp)) {
		gcry_sexp_release(public_encryption_key_sexp);
		gcry_sexp_release(private_scalar_sexp);
		throw CryptoException();
	}
	gcry_sexp_release(public_encryption_key_sexp);
	gcry_sexp_release(private_scalar_sexp);
	
	gcry_sexp_t s_sexp = gcry_sexp_find_token(point_sexp, "s", 0);
	if (!s_sexp) {
		gcry_sexp_release(point_sexp);
		throw CryptoException();
	}
	gcry_sexp_release(point_sexp);
	size_t s_size;
	const char *s_buffer = gcry_sexp_nth_data(s_sexp, 1, &s_size);
	if (!s_buffer) {
		gcry_sexp_release(s_sexp);
		throw CryptoException();
	}
	
	ByteArray<c_tdh_point_length> result;
	assert(s_size == sizeof(result.buffer));
	memcpy(result.buffer, s_buffer, sizeof(result.buffer));
	gcry_sexp_release(s_sexp);
	
	return result;
}

static Hash triple_diffie_hellman_token(
	const ByteArray<c_tdh_point_length>& part_1,
	const ByteArray<c_tdh_point_length>& part_2,
	const ByteArray<c_tdh_point_length>& part_3
)
{
	std::string hash_buffer;
	if (part_1 <= part_2 && part_1 <= part_3) {
		hash_buffer += part_1.as_string();
		if (part_2 <= part_3) {
			hash_buffer += part_2.as_string();
			hash_buffer += part_3.as_string();
		} else {
			hash_buffer += part_3.as_string();
			hash_buffer += part_2.as_string();
		}
	} else if (part_2 <= part_1 && part_2 <= part_3) {
		hash_buffer += part_2.as_string();
		if (part_1 <= part_3) {
			hash_buffer += part_1.as_string();
			hash_buffer += part_3.as_string();
		} else {
			hash_buffer += part_3.as_string();
			hash_buffer += part_1.as_string();
		}
	} else {
		hash_buffer += part_3.as_string();
		if (part_1 <= part_2) {
			hash_buffer += part_1.as_string();
			hash_buffer += part_2.as_string();
		} else {
			hash_buffer += part_2.as_string();
			hash_buffer += part_1.as_string();
		}
	}
	
	return crypto::hash(hash_buffer, true);
}

Hash triple_diffie_hellman(
	const PrivateKey& my_long_term_key,
	const PrivateKey& my_ephemeral_key,
	const PublicKey& peer_long_term_key,
	const PublicKey& peer_ephemeral_key
)
{
	ByteArray<c_tdh_point_length> part_1 = compute_dh_token(my_long_term_key, peer_ephemeral_key);
	ByteArray<c_tdh_point_length> part_2 = compute_dh_token(my_ephemeral_key, peer_long_term_key);
	ByteArray<c_tdh_point_length> part_3 = compute_dh_token(my_ephemeral_key, peer_ephemeral_key);
	return triple_diffie_hellman_token(part_1, part_2, part_3);
}

Hash reconstruct_triple_diffie_hellman(
	const PublicKey& long_term_public_key_1,
	const PrivateKey& ephemeral_private_key_1,
	const PublicKey& long_term_public_key_2,
	const PrivateKey& ephemeral_private_key_2
)
{
	ByteArray<c_tdh_point_length> part_1 = compute_dh_token(ephemeral_private_key_1, long_term_public_key_2);
	ByteArray<c_tdh_point_length> part_2 = compute_dh_token(ephemeral_private_key_2, long_term_public_key_1);
	ByteArray<c_tdh_point_length> part_3 = compute_dh_token(ephemeral_private_key_1, ephemeral_private_key_2.public_key());
	return triple_diffie_hellman_token(part_1, part_2, part_3);
}

Hash authentication_token(
	const PrivateKey& my_long_term_key,
	const PrivateKey& my_ephemeral_key,
	const PublicKey& peer_long_term_key,
	const PublicKey& peer_ephemeral_key,
	const Hash& nonce,
	const std::string& username
)
{
	Hash token = triple_diffie_hellman(
		my_long_term_key,
		my_ephemeral_key,
		peer_long_term_key,
		peer_ephemeral_key
	);
	std::string buffer = username;
	buffer += nonce.as_string();
	buffer += token.as_string();
	return hash(buffer);
}

} // namespace crypto
} // namespace np1sec
