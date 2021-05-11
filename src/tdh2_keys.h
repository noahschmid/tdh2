/*
* TDH2 Threshold Cryptosystem
* (C) 2021 Noah Schmid
*
*/

#ifndef BOTAN_TDH2_KEYS_H_
#define BOTAN_TDH2_KEYS_H_

#include <botan/dh.h>
#include <botan/bigint.h>
#include <stdlib.h>
#include <time.h>
#include <botan/hex.h>

namespace Botan {

	/**
	 * TDH2 Public Key used for encryption
	 */
	class TDH2_PublicKey : public virtual DL_Scheme_PublicKey {
	public:
		std::string algo_name() const override { return "TDH2"; }
		DL_Group::Format group_format() const override { return DL_Group_Format::ANSI_X9_42; }

		TDH2_PublicKey() = default;

		/**
		 * Create a public key
		 * @param group the underlying DL group
		 * @param y the public value y = g^x mod p
		 * @param g_hat alternate generator of group 
		 * @param k number of shares needed to decrypt message (threshold)
		 * @param h verification key consisting of hi = g^xi mod p 
		 */
		TDH2_PublicKey(const DL_Group& group, BigInt y, BigInt g_hat, uint8_t k, std::vector<BigInt> h);

		/**
		 * Load a public key
		 * @param key_bits the BER encoded public key
		 */
		TDH2_PublicKey(std::vector<uint8_t> key_bits);

		/**
		 * Load a public key
		 * @param publicKey public key instance
		 */
		TDH2_PublicKey(const TDH2_PublicKey &publicKey);

		/**
		 * Determine whether a decryption share was correctly generated from a encrypted message
		 * @param share the decryption share to verify
		 * @param encryption the encrypted message the share belongs to 
		 * @return true if decryption share is valid, false else
		 */
		bool verify_share(std::vector<uint8_t> share, secure_vector<uint8_t> encryption);


		bool verify_cipher(secure_vector<uint8_t> encryption);

		/**
		 * @return label of encrypted message
		 */
		std::vector<uint8_t> extract_label(std::vector<uint8_t> encryption);

		/**
		 * Get the alternate group generator
		 * @return generator g_hat
		 */
		BigInt get_g_hat() { return m_g_hat; }

		/**
		 * Get the threshold parameter
		 * @return threshold parameter k
		 */
		uint8_t get_k() { return m_k; }

		/**
		 * Get the verification key
		 * @return verification key h
		 */
		std::vector<BigInt> get_h() { return m_h; }

		/**
		 * @return BER encoded public key
		 */
		std::vector<uint8_t> subject_public_key() const;

		void encrypt(secure_vector<uint8_t> &msg, uint8_t label[20], RandomNumberGenerator& rng); 

		/**
		 * Hash function used for zero knowledge proofs to validate decryption request. Hashes (m1, m2, g1, g2, g3, g4) -> Zq
		 * @param m1 message 
		 * @param m2 label
		 * @param g1 value in Zp
		 * @param g2 value in Zp
		 * @param g3 value in Zp
		 * @param g4 value in Zp
		 * @param q modulus
		 * @return hash (value in Zq) 
		 */
		BigInt get_e(std::vector<uint8_t> m1, uint8_t m2[20], BigInt g1, BigInt g2, BigInt g3, BigInt g4);

		/**
		 * Hash function used for zero knowledge proofs to validate decryption share. Hashes (g1, g2, g3) -> Zq
		 * @param g1 value in Zp
		 * @param g2 value in Zp
		 * @param g3 value in Zp
		 * @return hash (value in Zq) 
		 */
		BigInt get_ei(BigInt g1, BigInt g2, BigInt g3);

	protected:
		BigInt m_g_hat;
		uint8_t m_k;
		std::vector<BigInt> m_h;
	};
	

	/**
	 * TDH2 Private Key used for decryption
	 */
	class TDH2_PrivateKey final : public TDH2_PublicKey {
	public:
		TDH2_PrivateKey() = default;

		/**
		 * Create a private key
		 * @param id id of private key
		 * @param xi private key value
		 * @param g_hat alternate generator of underlying DL group
		 * @param publicKey corresponding public key
		 */
		TDH2_PrivateKey(uint32_t id,
			BigInt xi,
			BigInt g_hat, 
			TDH2_PublicKey publicKey);

		/**
		 * Load encrypted private key
		 * @param key_bits encrypted private key
		 * @param password the password to decrypt key
		 */
		TDH2_PrivateKey(std::vector<uint8_t> key_bits, std::string &password);

		/**
		 * Generate keys for a new TDH2 cryptosystem
		 * @param k threshold parameter
		 * @param n number of private keys
		 * @param rng the random number generator to use
		 * @param group the underlying DL group
		 * @return vector of private keys (including public keys)
		 */
		static std::vector<TDH2_PrivateKey> generate_keys(uint8_t k,
			uint32_t n,
			RandomNumberGenerator & rng,
			const DL_Group & group);

		/**
		 * Create a decryption share
		 * @param encryption the encrypted message
		 * @param rng the random number generator to use
		 */
		std::vector<uint8_t> create_share(secure_vector<uint8_t> encryption, 
			RandomNumberGenerator& rng);

		/**
		 * @return public value y = g^x mod p
		 */
		std::vector<uint8_t> public_value() const;

		/**
		 * BER encode encrypted private key using password
		 * @param password password to encrypt private key with
		 */
		std::vector<uint8_t> BER_encode(std::string &password);

		/**
		 * Get private key value
		 */
		BigInt get_xi() { return m_xi;  }

		/**
		 * Get private key id
		 */
		int get_id() { return m_id; }

		/**
		 * Combine decryption shares to reconstruct message
		 * @param encryption the encrypted message
		 * @param shares vector of decryption shares
		 * @param verify states whether encryption should get verified before combining the shares
		 * @return decrypted message if all decryption shares are valid, empty vector otherwise
		 * 
		 * @throws InvalidArgument if encryption or share is invalid
		 */
		void combine_shares(secure_vector<uint8_t> &encryption, 
			std::vector<std::vector<uint8_t>> shares, 
			bool verify = true); 

	private:
		BigInt m_xi;
		uint32_t m_id;
	};
}

#endif