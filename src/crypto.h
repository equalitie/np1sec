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

#ifndef SRC_CRYPTO_H_
#define SRC_CRYPTO_H_

#include <string>

#include "bytearray.h"

struct gcry_sexp;
typedef gcry_sexp* gcry_sexp_t;

namespace np1sec
{
	class CryptoException {};
	
	const size_t c_hash_length = 32;
	const size_t c_signature_length = 64;
	const size_t c_public_key_length = 32;
	const size_t c_private_key_length = 32;
	
	typedef ByteArray<c_hash_length> Hash;
	
	struct SymmetricKey
	{
		ByteArray<c_hash_length> key;
		
		~SymmetricKey();
	};
	
	typedef ByteArray<c_public_key_length> PublicKey;
	
	typedef ByteArray<c_private_key_length> SerializedPrivateKey;
	
	//! Structure representing cryptographic key pair
	class PrivateKey
	{
		protected:
		gcry_sexp_t m_private_key;
		PublicKey m_public_key;
		
		explicit PrivateKey(gcry_sexp_t sexp);
		
		public:
		/** Constructor */
		PrivateKey();

		/** Copy constructor */
		PrivateKey(const PrivateKey& other);

		/** Assignment operator */
		PrivateKey& operator=(const PrivateKey& other);

		/** Destructor */
		~PrivateKey();
		
		bool is_null() const
		{
			return m_private_key == nullptr;
		}
		
		gcry_sexp_t sexp() const
		{
			return m_private_key;
		}
		
		/** Return the public key */
		const PublicKey& public_key() const
		{
			return m_public_key;
		}
		
		/** Generate a cryptographic key pair */
		static PrivateKey generate(bool transient);
		
		SerializedPrivateKey serialize() const;
		static PrivateKey unserialize(const SerializedPrivateKey& serialized_key);
	};
	
	typedef ByteArray<c_signature_length> Signature;
	
	namespace crypto
	{
		Hash hash(const std::string& buffer, bool secure = false);
		
		void create_nonce(unsigned char* buffer, size_t size);
		template<int n> ByteArray<n> nonce()
		{
			ByteArray<n> result;
			create_nonce(result.buffer, n);
			return result;
		}
		inline Hash nonce_hash()
		{
			return nonce<c_hash_length>();
		}
		
		std::string encrypt(const std::string& plaintext, const SymmetricKey& key);
		
		std::string decrypt(const std::string& ciphertext, const SymmetricKey& key);
		
		Signature sign(const std::string& payload, const PrivateKey& key);
		
		bool verify(const std::string& payload, const Signature& signature, const PublicKey& key);
		
		Hash triple_diffie_hellman(
			const PrivateKey& my_long_term_key,
			const PrivateKey& my_ephemeral_key,
			const PublicKey& peer_long_term_key,
			const PublicKey& peer_ephemeral_key
		);
		Hash reconstruct_triple_diffie_hellman(
			const PublicKey& long_term_public_key_1,
			const PrivateKey& ephemeral_private_key_1,
			const PublicKey& long_term_public_key_2,
			const PrivateKey& ephemeral_private_key_2
		);
		
		Hash authentication_token(
			const PrivateKey& my_long_term_key,
			const PrivateKey& my_ephemeral_key,
			const PublicKey& peer_long_term_key,
			const PublicKey& peer_ephemeral_key,
			const Hash& nonce,
			const std::string& username
		);
	}
}

#endif
