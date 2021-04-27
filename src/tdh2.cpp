#pragma once
#include "tdh2.h"
#include <botan/der_enc.h>
#include <botan/dlies.h>
#include <botan/numthry.h>
#include <botan/hash.h>
#include <botan/auto_rng.h>
#include <iostream>
#include <botan/reducer.h>
#include <math.h>

namespace Botan {
	BigInt h4(BigInt g1, BigInt g2, BigInt g3, BigInt q) {
		std::unique_ptr<HashFunction> hash(HashFunction::create("SHA-256"));
		secure_vector<uint8_t> data(3 * hash->output_length());

		hash->update(g1.to_hex_string());
		secure_vector<uint8_t>buf = hash->final();
		std::copy(buf.begin(), buf.end(), data.data() + 32 * 2);
		buf.clear();

		hash->update(g2.to_hex_string());
		buf = hash->final();
		std::copy(buf.begin(), buf.end(), data.data() + 32 * 3);
		buf.clear();

		hash->update(g3.to_hex_string());
		buf = hash->final();
		std::copy(buf.begin(), buf.end(), data.data() + 32 * 4);
		buf.clear();

		hash->update(data);
		Botan::secure_vector<uint8_t> h = hash->final();

		if (q.bits() > hash->output_length()*4) {
			Botan::secure_vector<uint8_t> g = h;

			for (BigInt i = 1; i < ceil((q.bits() - hash->output_length()*4)/hash->output_length()*8); ++i) {
				buf = g;
				buf.insert(buf.end(), i.data(), i.data() + i.size());
				hash->update(buf);
				buf.clear();
				buf = hash->final();
				h.insert(h.end(), buf.begin(), buf.end());
				buf.clear();
			}
		}

		return BigInt(h) % q;
	}

	BigInt h2(std::vector<uint8_t> m1, std::vector<uint8_t> m2, BigInt g1, BigInt g2, BigInt g3, BigInt g4, BigInt q) {
		std::unique_ptr<HashFunction> hash(HashFunction::create("SHA-256"));
		secure_vector<uint8_t> data(6*hash->output_length());

		hash->update(m1);
		secure_vector<uint8_t> buf = hash->final();
		std::copy(buf.begin(), buf.end(), data.data());
		buf.clear();

		hash->update(m2);
		buf = hash->final();
		std::copy(buf.begin(), buf.end(), data.data() + 32);
		buf.clear();

		hash->update(g1.to_hex_string());
		buf = hash->final();
		std::copy(buf.begin(), buf.end(), data.data() + 32*2);
		buf.clear();

		hash->update(g2.to_hex_string());
		buf = hash->final();
		std::copy(buf.begin(), buf.end(), data.data() + 32*3);
		buf.clear();

		hash->update(g3.to_hex_string());
		buf = hash->final();
		std::copy(buf.begin(), buf.end(), data.data() + 32*4);
		buf.clear();

		hash->update(g4.to_hex_string());
		buf = hash->final();
		std::copy(buf.begin(), buf.end(), data.data() + 32*5);
		buf.clear();

		hash->update(data);
		Botan::secure_vector<uint8_t> h = hash->final();

		if(q.bits() > hash->output_length() * 4) {
			Botan::secure_vector<uint8_t> g = h;

			for(BigInt i = 1; i < ceil((q.bits() - hash->output_length()*4)/hash->output_length()*8); ++i) {
				buf = g;
				buf.insert(buf.end(), i.data(), i.data() + i.size());
				hash->update(buf);
				buf.clear();
				buf = hash->final();
				h.insert(h.end(), buf.begin(), buf.end());
				buf.clear();
			}
		}

		return BigInt(h) % q;
	}

	TDH2_PublicKey::TDH2_PublicKey(const TDH2_PublicKey &publicKey) {
		m_group = publicKey.m_group;
		m_y = publicKey.m_y;
		m_g_hat = publicKey.m_g_hat;
		m_k = publicKey.m_k;
		m_h = publicKey.m_h;
	}

	TDH2_PublicKey::TDH2_PublicKey(const DL_Group& group, BigInt y, BigInt g_hat, uint8_t k, std::vector<BigInt> h) {
		m_y = y;
		m_group = group;
		m_g_hat = g_hat;
		m_k = k;
		m_h = h;
	}

	std::vector<uint8_t> TDH2_PublicKey::extract_label(std::vector<uint8_t> encryption) {
		if (encryption.size() < 4*m_group.p_bytes() + 21) {
			throw Invalid_Argument("encryption too short");
		}

		static std::vector<uint8_t> l(encryption.data() + encryption.size() - (4*m_group.p_bytes() + 20), encryption.data() + encryption.size() - 4*m_group.p_bytes());
		return l;
	}

	std::vector<uint8_t> TDH2_PublicKey::encrypt(std::vector<uint8_t> msg, uint8_t label[20], RandomNumberGenerator& rng) {
		BigInt r(rng, m_group.get_q().bits() - 1);

		std::unique_ptr<Botan::KDF> kdf(Botan::KDF::create("HKDF(SHA-256)"));

		// calculate secret value
		const SymmetricKey secret_value(power_mod(m_y, r, m_group.get_p()).to_hex_string());

		const secure_vector<uint8_t> secret_keys = kdf->derive_key(msg.size(), secret_value.bits_of());

		if (secret_keys.size() != msg.size()) {
			throw Encoding_Error("TDH2: KDF did not provide sufficient output");
		}

		const size_t cipher_key_len = msg.size();

		xor_buf(msg, secret_keys, cipher_key_len);


		secure_vector<uint8_t> out(msg.size() + 20 + 2*m_group.p_bytes() + 2 * m_group.q_bytes());
		std::vector<uint8_t> l(label, label + 20);

		BigInt s(rng, m_group.q_bits() - 1);
		BigInt u = m_group.power_g_p(r);
		BigInt u_hat = power_mod(m_g_hat, r, group_p());
		
		BigInt w = m_group.power_g_p(s);
		BigInt w_hat = power_mod(m_g_hat, s, group_p());
		BigInt e = h2(msg, l, u, w, u_hat, w_hat, group_q());
		BigInt f = m_group.mod_q(s + m_group.multiply_mod_q(r, e));

		// out = (cipher, label, u, u_hat, e, f)
		buffer_insert(out, 0, msg);
		buffer_insert(out, msg.size(), l);
		BigInt::encode_1363(out.data() + msg.size() + 20,											m_group.p_bytes(), u);
		BigInt::encode_1363(out.data() + msg.size() + 20 +   m_group.p_bytes(),						m_group.p_bytes(), u_hat);
		BigInt::encode_1363(out.data() + msg.size() + 20 + 2*m_group.p_bytes(),						m_group.q_bytes(), e);
		BigInt::encode_1363(out.data() + msg.size() + 20 + 2*m_group.p_bytes() + m_group.q_bytes(), m_group.q_bytes(), f);

		return unlock(out);
	}

	bool TDH2_PublicKey::verify_share(std::vector<uint8_t> share, std::vector<uint8_t> encryption) {
		if(share.size() < 2)
			return false;

		BigInt g = m_group.get_g();
		BigInt p = m_group.get_p();

		BigInt u(encryption.data() + encryption.size() - 2*m_group.p_bytes() - 2*m_group.q_bytes(), m_group.p_bytes());
		BigInt u_hat(encryption.data() + encryption.size() - m_group.p_bytes() -2*m_group.q_bytes(), m_group.p_bytes());
		BigInt e(encryption.data() + encryption.size() - 2*m_group.q_bytes(), m_group.q_bytes());
		BigInt f(encryption.data() + encryption.size() - m_group.q_bytes(), m_group.q_bytes());
		std::vector<uint8_t> l(encryption.data() + encryption.size() - 2*m_group.p_bytes() - 2*m_group.q_bytes() - 20, encryption.data() + encryption.size() - 2 * m_group.p_bytes() - 2 * m_group.q_bytes());
		std::vector<uint8_t> c(encryption.data(), encryption.data() + encryption.size() - 2*m_group.p_bytes() - 2*m_group.q_bytes() - 20);

		BigInt w = m_group.multiply_mod_p(m_group.power_g_p(f, m_group.q_bits()), inverse_mod(power_mod(u, e, m_group.get_p()), m_group.get_p()));
		BigInt w_hat = m_group.multiply_mod_p(power_mod(get_g_hat(), f, m_group.get_p()), inverse_mod(power_mod(u_hat, e, m_group.get_p()),m_group.get_p()));

		size_t id = share.at(0);
		size_t valid = share.at(1);

		BigInt hi = m_h.at((int)(id - 1));

		if (e == h2(c, l, u, w, u_hat, w_hat, m_group.get_q()) && share.size() == 2 + 3*m_group.p_bytes()) {
			BigInt ui(share.data() + 2, m_group.p_bytes());
			BigInt ei(share.data() + 2 + m_group.p_bytes(), m_group.p_bytes());
			BigInt fi(share.data() + 2 + 2*m_group.p_bytes(), m_group.p_bytes());
			BigInt hi_hat = m_group.multiply_mod_p(m_group.power_g_p(fi), inverse_mod(power_mod(hi, ei, m_group.get_p()), m_group.get_p()));
			BigInt ui_hat = m_group.multiply_mod_p(power_mod(u, fi, m_group.get_p()), inverse_mod(power_mod(ui, ei, m_group.get_p()), m_group.get_p()));

			if(ei == h4(ui, ui_hat, hi_hat, m_group.get_q()))
				return true;
		} else if (valid == 0) {
			return true;
		}

		return false;
	}
	
	TDH2_PartialPrivateKey::TDH2_PartialPrivateKey(uint8_t id,
		BigInt xi,
		BigInt g_hat,
		TDH2_PublicKey publicKey) :
		TDH2_PublicKey(publicKey) {
		m_id = id;
		m_xi = xi;
	}

	secure_vector<uint8_t> TDH2_PartialPrivateKey::get_private_key() {
		secure_vector<uint8_t> output(m_group.p_bytes());
		m_xi.binary_encode(output.data(), m_group.p_bytes());
		return output;
	}


	std::vector<uint8_t> TDH2_PartialPrivateKey::public_value() const {
		return unlock(BigInt::encode_1363(m_y, group_p().bytes()));
	}


	BigInt get_pol(uint8_t x, std::vector<BigInt> coefficients, BigInt q) {
		BigInt val = 0;
		for (int i = 0; i != coefficients.size(); ++i) {
			val += (power_mod(x, coefficients.size() - i - 1, q) * coefficients.at(i)) % q;
		}
		return val % q;
	}

	std::vector<TDH2_PartialPrivateKey> TDH2_PartialPrivateKey::generate_keys(uint8_t k, 
													 uint8_t n, 
													 RandomNumberGenerator& rng,
													 const DL_Group& group) {
		if(n > 255) {
			throw Invalid_Argument("TDH2: Maximum number of keys is 255");
		}

		if (k > n) {
			throw Invalid_Argument("TDH2: Threshold is higher than total number keys");
		}

		srand(time(NULL));

		BigInt x(rng, group.get_q().bits() - 1), y;
		x.randomize(rng, group.get_q().bytes());
		BigInt g_hat = group.power_g_p(x, group.q_bits());

		x.randomize(rng, group.get_q().bits() - 1);
		y = group.power_g_p(x, group.get_q().bits());
		
		secure_vector<uint8_t> x_bits;
		DER_Encoder(x_bits).encode(x);

		std::vector<BigInt> coefficients;
		for(uint8_t i = 0; i != k - 1; ++i) {
			coefficients.push_back(BigInt::random_integer(rng, 2, group.get_q() - 1));
		}

		coefficients.push_back(x);

		std::vector<BigInt> xi;
		std::vector<TDH2_PartialPrivateKey> partialKeys;
		std::vector<BigInt> h;

		for(uint8_t i = 1; i != n + 1; ++i) {
			xi.push_back(get_pol(i, coefficients, group.get_q()));
			h.push_back(group.power_g_p(xi.at(i-1), group.q_bits()));
		}

		TDH2_PublicKey publicKey(group, y, g_hat, k, h);

		for(uint8_t i = 0; i != xi.size(); ++i) {
			partialKeys.push_back(TDH2_PartialPrivateKey(i+1, xi.at(i), g_hat, publicKey));
		}

		return partialKeys;
	}

	std::vector<uint8_t> TDH2_PartialPrivateKey::decrypt_share(std::vector<uint8_t> encryption, RandomNumberGenerator &rng) {
		BigInt u(encryption.data() + encryption.size() - 2*m_group.p_bytes() - 2*m_group.q_bytes(), m_group.p_bytes());
		BigInt u_hat(encryption.data() + encryption.size() - m_group.p_bytes() - 2*m_group.q_bytes(), m_group.p_bytes());
		BigInt e(encryption.data() + encryption.size() - 2*m_group.q_bytes(), m_group.q_bytes());
		BigInt f(encryption.data() + encryption.size() - m_group.q_bytes(), m_group.q_bytes());
		std::vector<uint8_t> l(encryption.data() + encryption.size() - 2 * m_group.p_bytes() - 2 * m_group.q_bytes() - 20, encryption.data() + encryption.size() - 2 * m_group.p_bytes() - 2 * m_group.q_bytes());
		std::vector<uint8_t> c(encryption.data(), encryption.data() + encryption.size() - 2 * m_group.p_bytes() - 2 * m_group.q_bytes() - 20);
		
		f = m_group.mod_q(f);
		BigInt w = m_group.multiply_mod_p(m_group.power_g_p(f, m_group.q_bits()), m_group.inverse_mod_p(power_mod(u, e, m_group.get_p())));
		BigInt w_hat = m_group.multiply_mod_p(power_mod(get_g_hat(), f, m_group.get_p()), m_group.inverse_mod_p(power_mod(u_hat, e, m_group.get_p())));

		size_t valid = 0;

		std::vector<uint8_t> share(2);
		std::copy(&m_id, &m_id + 1, share.data());
		BigInt e_test = h2(c, l, u, w, u_hat, w_hat, m_group.get_q());

		if (e == e_test) {
			valid = 1;
			share.resize(2 + 3 * m_group.p_bytes());
			BigInt ui = power_mod(u, m_xi, m_group.get_p());
			BigInt si(rng, m_group.q_bits() - 1);
			BigInt ui_hat = power_mod(u, si, m_group.get_p());
			BigInt hi_hat = m_group.power_g_p(si, m_group.q_bits());
			BigInt ei = h4(ui, ui_hat, hi_hat, m_group.get_q());
			BigInt fi = si + m_group.multiply_mod_p(m_xi, ei);

			BigInt::encode_1363(share.data() + 2, m_group.p_bytes(), ui);
			BigInt::encode_1363(share.data() + 2 + m_group.p_bytes(), m_group.p_bytes(), ei);
			BigInt::encode_1363(share.data() + 2 + 2*m_group.p_bytes(), m_group.p_bytes(), fi);
		}

		std::copy(&valid, &valid + 1, share.data() + 1);

		return share; // (id, 1, ui, ei, fi) || (id, 0)
	}

	std::vector<uint8_t> TDH2_PartialPrivateKey::combine_shares(std::vector<uint8_t> encryption, std::vector<std::vector<uint8_t>> shares) {
		if (get_k() > shares.size())
			throw Invalid_Argument("TDH2: Not enough decryption shares to reconstruct message");
		
		std::vector<uint8_t> ids;

		for (uint8_t i = 0; i != shares.size(); ++i) {
			if(!verify_share(shares.at(i), encryption))
				return std::vector<uint8_t>();

			if(shares.at(i).at(1) == 0)
				return std::vector<uint8_t>();

			ids.push_back(shares.at(i).at(0));
		}
		
		BigInt rG(1);
		BigInt q(m_group.get_q());
		for (int k = 0; k != shares.size(); ++k) {
			BigInt i(shares.at(k).at(0));
			BigInt l = 1;

			for(BigInt j : ids) {
				if(i != j)
					l *= ((j % q) * inverse_mod((j - i) % q, q)) % q;
			}

			l %= q;

			BigInt ui = BigInt::decode(shares.at(k).data() + 2, m_group.p_bytes());
			ui = power_mod(ui, l, m_group.get_p());
			rG *= ui;
		}

		rG %= m_group.get_p();
		
		std::unique_ptr<Botan::RandomNumberGenerator> rng(new Botan::AutoSeeded_RNG);
		DH_PrivateKey key(*rng.get(), get_group(), 1);
		std::vector<uint8_t> secret_key = hex_decode(rG.to_hex_string());

		// calculate secret value
		std::unique_ptr<Botan::KDF> kdf(Botan::KDF::create("HKDF(SHA-256)"));

		const SymmetricKey secret_value(secret_key);

		std::vector<uint8_t> cipher(encryption.data(), encryption.data() + encryption.size() - (20 + 2*m_group.p_bytes() + 2*m_group.q_bytes()));
		const size_t ciphertext_len = cipher.size();
		size_t cipher_key_len = ciphertext_len;

		// derive secret key from secret value
		const size_t required_key_length = cipher_key_len;
		secure_vector<uint8_t> secret_keys = kdf->derive_key(required_key_length, secure_vector<uint8_t>(secret_key.data(), secret_key.data() + secret_key.size()));

		if(secret_keys.size() != required_key_length) {
			throw Encoding_Error("TDH2: KDF did not provide sufficient output");
		}

		// decrypt
		xor_buf(cipher, secret_keys.data(), cipher_key_len);

		return cipher;
	}

	std::vector<uint8_t> TDH2_PartialPrivateKey::reconstruct_secret(std::vector<TDH2_PartialPrivateKey> keys) {
		BigInt key = 0;
		BigInt q = keys.at(0).get_group().get_q();
		std::vector<uint8_t> ids;

		for(uint8_t i = 0; i != keys.size(); ++i) {
			if (keys.at(i).get_group().get_q() != q)
				throw Invalid_Argument("TDH2: Keys have different q");

			ids.push_back(keys.at(i).get_id());
		}

		for(uint8_t k = 0; k != keys.size(); ++k) {
			BigInt l = 1;
			BigInt i(keys.at(k).get_id());

			for(BigInt j : ids) {
				if(i != j)
					l *= ((j % q) * inverse_mod((j - i) % q, q)) % q;
			}

			l %= q;
			key += l * keys.at(k).get_xi();
		}

		key %= q;
		return hex_decode(key.to_hex_string());
	}
}