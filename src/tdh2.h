#pragma once
#ifndef BOTAN_TDH2_H_
#define BOTAN_TDH2_H_

#include <botan/secmem.h>
#include <botan/dh.h>
#include <botan/bigint.h>
#include <stdlib.h>
#include <time.h>
#include <botan/hex.h>

namespace Botan {
	class TDH2_PublicKey : public virtual DL_Scheme_PublicKey {
	public:
		TDH2_PublicKey(const DL_Group& group, BigInt y, BigInt g_hat, uint8_t k, std::vector<BigInt> h);
		TDH2_PublicKey(const AlgorithmIdentifier& alg_id,
			const std::vector<uint8_t>& key_bits,
			uint8_t k,
			std::vector<BigInt> h) :
			DL_Scheme_PublicKey(alg_id, key_bits, DL_Group_Format::ANSI_X9_42) {
			m_k = k; 
			m_h = h;
		}
		TDH2_PublicKey(const TDH2_PublicKey &publicKey);

		std::string algo_name() const override { return "TDH2"; }
		DL_Group::Format group_format() const override { return DL_Group_Format::ANSI_X9_42; }

		std::vector<uint8_t> encrypt(std::vector<uint8_t> msg,
			uint8_t label[20],
			RandomNumberGenerator& rng);

		bool verify_share(std::vector<uint8_t> share, std::vector<uint8_t> encryption);

		std::vector<uint8_t> extract_label(std::vector<uint8_t> encryption);

		BigInt get_g_hat() { return m_g_hat; }
		uint8_t get_k() { return m_k; }

		//std::vector<uint8_t> subject_public_key() const;
		AlgorithmIdentifier algorithm_identifier() const override;

	private:
		BigInt m_g_hat;
		uint8_t m_k;
		std::vector<BigInt> m_h;

	protected:
		TDH2_PublicKey() = default;
	};

	
	class TDH2_PartialPrivateKey final : public TDH2_PublicKey {
	public:
		TDH2_PartialPrivateKey(uint8_t id,
			BigInt xi,
			BigInt g_hat, 
			TDH2_PublicKey publicKey);

		static std::vector<TDH2_PartialPrivateKey> generate_keys(uint8_t M,
			uint8_t N,
			RandomNumberGenerator & rng,
			const DL_Group & group);

		std::vector<uint8_t> decrypt_share(std::vector<uint8_t> encryption, RandomNumberGenerator& rng);

		std::vector<uint8_t> combine_shares(std::vector<uint8_t> encryption, std::vector<std::vector<uint8_t>> shares);
		static std::vector<uint8_t> reconstruct_secret(std::vector<TDH2_PartialPrivateKey> keys);

		std::vector<uint8_t> public_value() const;

		secure_vector<uint8_t> get_private_key();

		BigInt get_xi() { return m_xi;  }
		uint8_t get_id() { return m_id; }

	private:
		BigInt m_xi;
		uint8_t m_id;
	};
}
#endif