#include "tdh2.h"
#include <botan/kdf.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/hash.h>
#include <math.h>
#include <iostream>

namespace TDH2 {
    TDH2_Encryptor::TDH2_Encryptor(TDH2_PublicKey& key, RandomNumberGenerator& rng) : 
	m_rng(rng) {
        m_public_key = key;
        m_enc = AEAD_Mode::create("ChaCha20Poly1305", ENCRYPTION);
    }

    std::vector<uint8_t> TDH2_Encryptor::begin(uint8_t label[20]) {
        BigInt r(BigInt::random_integer(m_rng, 2, m_public_key.group_q() - 1));

		std::unique_ptr<Botan::KDF> kdf(Botan::KDF::create("HKDF(SHA-256)"));

		// calculate secret value
		const SymmetricKey tdh_key(m_public_key.get_group().power_b_p(m_public_key.get_y(), r, m_public_key.get_group().q_bits()).to_hex_string());

		secure_vector<uint8_t> symmetric_key = kdf->derive_key(m_enc->key_spec().minimum_keylength(), m_rng.random_vec(16));

		if (symmetric_key.size() != m_enc->key_spec().minimum_keylength()) {
			throw Encoding_Error("TDH2: KDF did not provide sufficient output");
		}

        m_enc->set_key(symmetric_key);
        m_enc->start(kdf->derive_key(8, symmetric_key));
		
		// encrypt symmetric key
		xor_buf(symmetric_key, tdh_key.bits_of(), tdh_key.length());

        std::vector<uint8_t> out;
		std::vector<uint8_t> msg;
        BigInt l(label, 20);

        size_t q_bits = m_public_key.get_group().q_bits();

		BigInt s(m_rng, q_bits - 1);
		BigInt u = m_public_key.get_group().power_g_p(r);
		BigInt u_hat = m_public_key.get_group().power_b_p(m_public_key.get_g_hat(), r, q_bits);

		BigInt c(symmetric_key);
		
		BigInt w = m_public_key.get_group().power_g_p(s);
		BigInt w_hat = m_public_key.get_group().power_b_p(m_public_key.get_g_hat(), s, q_bits);
		BigInt e = m_public_key.get_e(symmetric_key.data(), label, u, w, u_hat, w_hat);
		BigInt f = m_public_key.get_group().mod_q(s + m_public_key.get_group().multiply_mod_q(r, e));

		DER_Encoder enc(out);
		enc.start_sequence()
			.encode(l)
			.encode(c)
			.encode(u)
			.encode(u_hat)
			.encode(e)
			.encode(f)
			.end_cons();

		return out; // (l, c, u, u_hat, e, f)
    }

    void TDH2_Encryptor::update(secure_vector<uint8_t>& block) {
        m_enc->update(block);
    }

    void TDH2_Encryptor::finish(secure_vector<uint8_t>& block) {
        m_enc->finish(block);
    }

    void TDH2_Encryptor::reset() {
        m_enc->reset();
    }

    TDH2_Decryptor::TDH2_Decryptor(TDH2_PrivateKey& key) {
        m_private_key = key;
        m_dec = AEAD_Mode::create("ChaCha20Poly1305", DECRYPTION);
    }

    void TDH2_Decryptor::begin(std::vector<std::vector<uint8_t>> shares, std::vector<uint8_t> header) {
        if (m_private_key.get_k() > shares.size())
			throw Invalid_Argument("TDH2: Not enough decryption shares to reconstruct message");
		
		std::vector<uint32_t> ids;

		if(!m_private_key.verify_header(header)) 
			throw Invalid_Argument("TDH2: invalid decryption header");

		for (int i = 0; i != shares.size(); ++i) {
			uint32_t id = ((uint32_t)shares.at(i).at(0) << 24) 	|
					 	((uint32_t)shares.at(i).at(1)  << 16) 	|
					 	((uint32_t)shares.at(i).at(2)  << 8) 	|
					 	((uint32_t)shares.at(i).at(3)  << 0);


			if(!m_private_key.verify_share(shares.at(i), header)) 
				throw Invalid_Argument("TDH2: invalid share");
			

			if(shares.at(i).at(4) == 0) 
				throw Invalid_Argument("TDH2: invalid share");
			
			ids.push_back(id);
		}
		
		BigInt rG(1);
		BigInt q(m_private_key.group_q());
		for (int k = 0; k != shares.size(); ++k) {
			BigInt i (ids.at(k));
			BigInt l(1);

			for(int m = 0; m != ids.size(); ++m) {
				BigInt j(ids.at(m));
				if(i != j) {
					l = m_private_key.get_group().multiply_mod_q(
							m_private_key.get_group().multiply_mod_q(m_private_key.get_group().mod_q(j), 
							m_private_key.get_group().inverse_mod_q(m_private_key.get_group().mod_q((j - i)))), l);
				}
			}

			BigInt ui;
			BER_Decoder dec(shares.at(k).data() + 5, shares.at(k).size() - 5);
			dec.start_sequence().decode(ui);
			
			rG = m_private_key.get_group().multiply_mod_p(m_private_key.get_group().power_b_p(ui, l, m_private_key.get_group().q_bits()), rG);
		}
		
		std::unique_ptr<Botan::RandomNumberGenerator> rng(new Botan::AutoSeeded_RNG);
		DH_PrivateKey key(*rng.get(), m_private_key.get_group(), 1);
		secure_vector<uint8_t> tdh_key(hex_decode_locked(rG.to_hex_string()));

		// calculate secret value
		std::unique_ptr<Botan::KDF> kdf(Botan::KDF::create("HKDF(SHA-256)"));

		BigInt l, c;
		BER_Decoder dec(header);

		dec.start_sequence()
		.decode(l)
		.decode(c);

		secure_vector<uint8_t> symmetric_key(hex_decode_locked(c.to_hex_string()));
		xor_buf(symmetric_key, tdh_key, tdh_key.size());

        m_dec->set_key(symmetric_key);
        m_dec->start(kdf->derive_key(8, symmetric_key));
    };

    void TDH2_Decryptor::update(secure_vector<uint8_t>& block) {
        m_dec->update(block);
    };

    void TDH2_Decryptor::finish(secure_vector<uint8_t>& block) {
        m_dec->finish(block);
    };

    void TDH2_Decryptor::reset() {
        m_dec->reset();
    }
}