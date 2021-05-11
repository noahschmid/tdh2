/**
 * TDH2 Cryptosystem
 *
 * (C) 2021 Noah Schmid
 */

#include "tdh2_keys.h"
#include <botan/der_enc.h>
#include <botan/dlies.h>
#include <botan/numthry.h>
#include <botan/hash.h>
#include <botan/auto_rng.h>
#include <iostream>
#include <botan/reducer.h>
#include <math.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/cipher_mode.h>

namespace Botan {
	
	BigInt TDH2_PublicKey::get_ei(BigInt g1, BigInt g2, BigInt g3, BigInt q) {
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

	BigInt TDH2_PublicKey::get_e(secure_vector<uint8_t> m1, uint8_t m2[20], BigInt g1, BigInt g2, BigInt g3, BigInt g4) {
		std::unique_ptr<HashFunction> hash(HashFunction::create("SHA-256"));
		secure_vector<uint8_t> data(6*hash->output_length());

		hash->update(m1);
		secure_vector<uint8_t> buf = hash->final();
		std::copy(buf.begin(), buf.end(), data.data());
		buf.clear();

		hash->update(m2, 20);
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

		if(m_group.q_bits() > hash->output_length() * 4) {
			Botan::secure_vector<uint8_t> g = h;

			for(BigInt i = 1; i < ceil((m_group.q_bits() - hash->output_length()*4)/hash->output_length()*8); ++i) {
				buf = g;
				buf.insert(buf.end(), i.data(), i.data() + i.size());
				hash->update(buf);
				buf.clear();
				buf = hash->final();
				h.insert(h.end(), buf.begin(), buf.end());
				buf.clear();
			}
		}

		return BigInt(h) % m_group.get_q();
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

	TDH2_PublicKey::TDH2_PublicKey(std::vector<uint8_t> key_bits) {
		m_k = key_bits[0];
		uint32_t n = ((uint32_t)key_bits[1] << 24) 	|
					 ((uint32_t)key_bits[2] << 16) 	|
					 ((uint32_t)key_bits[3] << 8) 	|
					 ((uint32_t)key_bits[4] << 0);
 
		BigInt p, q, g;

		if(m_k > n) {
			throw Invalid_Argument("Invalid public key provided");
		}

		BER_Decoder dec(key_bits.data() + 2, key_bits.size() - 2);
		BER_Decoder ber = dec.start_sequence();
		ber.decode(p)
		.decode(g)
		.decode(q)
		.decode(m_g_hat)
		.decode(m_y);

		m_group = DL_Group(p, q, g);

		for(uint32_t i = 0; i != n; ++i) {
			BigInt hi;
			ber.decode(hi);
			m_h.push_back(hi);
		}

		ber.discard_remaining();
	}

	std::vector<uint8_t> TDH2_PublicKey::subject_public_key() const {
		std::vector<uint8_t> encoding;
		DER_Encoder enc(encoding);

		uint32_t n = m_h.size();

		enc.start_sequence()
		.encode(m_group.get_p())
		.encode(m_group.get_g())
		.encode(m_group.get_q())
		.encode(m_g_hat)
		.encode(m_y);

		for(int i = 0; i != n; ++i) {
			enc.encode(m_h.at(i));
		}

		enc.end_cons();

		encoding.insert(encoding.begin(), (uint8_t)(n >> 0));
		encoding.insert(encoding.begin(), (uint8_t)(n >> 8));
		encoding.insert(encoding.begin(), (uint8_t)(n >> 16));
		encoding.insert(encoding.begin(), (uint8_t)(n >> 24));

		encoding.insert(encoding.begin(), m_k);

		return encoding;
	}

	std::vector<uint8_t> TDH2_PublicKey::extract_label(std::vector<uint8_t> encryption) {
		BER_Decoder dec(encryption.data(), encryption.size());
		BigInt l;

		dec.start_sequence()
		.decode(l)
		.discard_remaining();

		std::vector<uint8_t> label(l.bytes());
		l.binary_encode(label.data());
		return label;
	}

	bool TDH2_PublicKey::verify_share(std::vector<uint8_t> share, std::vector<uint8_t> encryption) {
		if(share.size() < 6)
			return false;

		BigInt g(m_group.get_g());
		BigInt p(m_group.get_p());

		BigInt u, c, l;
		BER_Decoder dec(encryption.data(), encryption.size());

		dec.start_sequence()
		.decode(l)
		.decode(c)
		.decode(u);

		std::vector<uint8_t> label(l.bytes());
		l.binary_encode(label.data());
		std::vector<uint8_t> cipher(c.bytes()); 
		c.binary_encode(cipher.data());

		uint32_t id = ((uint32_t)share.at(0) << 24) |
					  ((uint32_t)share.at(1) << 16) |
					  ((uint32_t)share.at(2) << 8) 	|
					  ((uint32_t)share.at(3) << 0);

		size_t valid = share.at(4);

		BigInt hi(m_h.at((int)(id - 1)));

		BigInt ui, ei, fi;
		BER_Decoder dec2(share.data() + 5, share.size() - 5);
		dec2.start_sequence()
			.decode(ui)
			.decode(ei)
			.decode(fi);

		if(ei == get_ei(ui, 
			m_group.multiply_mod_p(m_group.power_b_p(u, fi, m_group.q_bits()), m_group.inverse_mod_p(m_group.power_b_p(ui, ei, m_group.q_bits()))), 
			m_group.multiply_mod_p(m_group.power_g_p(fi), m_group.inverse_mod_p(m_group.power_b_p(hi, ei, m_group.q_bits()))), m_group.get_q()))
			return true;

		return false;
	}
	
	bool TDH2_PublicKey::verify_cipher(secure_vector<uint8_t> encryption) {
		BigInt g(m_group.get_g());
		BigInt p(m_group.get_p());

		BigInt u, u_hat, e, f, c, l;
		BER_Decoder dec(encryption.data(), encryption.size());

		dec.start_sequence()
		.decode(l)
		.decode(c)
		.decode(u)
		.decode(u_hat)
		.decode(e)
		.decode(f);

		std::vector<uint8_t> label(l.bytes());
		l.binary_encode(label.data());
		secure_vector<uint8_t> cipher(c.bytes()); 
		c.binary_encode(cipher.data());

		BigInt w(m_group.multiply_mod_p(m_group.power_g_p(f, m_group.q_bits()), 
			m_group.inverse_mod_p(m_group.power_b_p(u, e, m_group.q_bits()))));
		BigInt w_hat(m_group.multiply_mod_p(m_group.power_b_p(get_g_hat(), f, m_group.q_bits()), 
			m_group.inverse_mod_p(m_group.power_b_p(u_hat, e, m_group.q_bits()))));

		return (e == get_e(cipher, label.data(), u, w, u_hat, w_hat));
	}
	
	TDH2_PrivateKey::TDH2_PrivateKey(uint32_t id,
		BigInt xi,
		BigInt g_hat,
		TDH2_PublicKey publicKey) :
		TDH2_PublicKey(publicKey) {
		m_id = id;
		m_xi = xi;
	}

	TDH2_PrivateKey::TDH2_PrivateKey(std::vector<uint8_t> key_bits, std::string& password) {
		std::unique_ptr<Botan::KDF> kdf(Botan::KDF::create("HKDF(SHA-256)"));
		secure_vector<uint8_t> secret(password.data(), password.data() + password.size());

		m_k = key_bits[0];
		uint32_t n = ((uint32_t)key_bits[1] << 24) 	|
					 ((uint32_t)key_bits[2] << 16) 	|
					 ((uint32_t)key_bits[3] << 8) 	|
					 ((uint32_t)key_bits[4] << 0);

		if(m_k > n) {
			throw Invalid_Argument("Invalid private key provided");
		}

		BigInt p, q, g;

		BER_Decoder dec(key_bits.data() + 5, key_bits.size() - 5);
		BER_Decoder ber = dec.start_sequence();
		BigInt id, xi;

		ber.decode(id)
		.decode(p)
		.decode(g)
		.decode(q)
		.decode(m_g_hat)
		.decode(xi)
		.decode(m_y);

		std::vector<uint8_t> secret_value = hex_decode(xi.to_hex_string());
		const secure_vector<uint8_t> secret_keys = kdf->derive_key(secret_value.size(), secret);
		xor_buf(secret_value, secret_keys, secret_value.size());

		m_xi = BigInt(secret_value);
		
		for(int i = 0; i != n; ++i) {
			BigInt hi;
			ber.decode(hi);
			m_h.push_back(hi);
		}

		ber.discard_remaining();

		m_id = id.to_u32bit();
		m_group = DL_Group(p, q, g);
	}

	std::vector<uint8_t> TDH2_PrivateKey::public_value() const {
		return unlock(BigInt::encode_1363(m_y, group_p().bytes()));
	}

	std::vector<uint8_t> TDH2_PrivateKey::BER_encode(std::string &password) {
		std::vector<uint8_t> encoding;
		DER_Encoder enc(encoding);

		std::unique_ptr<Botan::KDF> kdf(Botan::KDF::create("HKDF(SHA-256)"));
		secure_vector<uint8_t> secret(password.data(), password.data() + password.size());
		std::vector<uint8_t> secret_value = hex_decode(m_xi.to_hex_string());
		const secure_vector<uint8_t> secret_keys = kdf->derive_key(secret_value.size(), secret);
		xor_buf(secret_value, secret_keys, secret_value.size());

		enc.start_sequence()
		.encode(BigInt(m_id))
		.encode(m_group.get_p())
		.encode(m_group.get_g())
		.encode(m_group.get_q())
		.encode(get_g_hat())
		.encode(BigInt(secret_value))
		.encode(m_y);

		for(int i = 0; i != get_h().size(); ++i) {
			enc.encode(get_h().at(i));
		}

		enc.end_cons();
		
		uint32_t n = m_h.size();

		encoding.insert(encoding.begin(), (uint8_t)(n >> 0));
		encoding.insert(encoding.begin(), (uint8_t)(n >> 8));
		encoding.insert(encoding.begin(), (uint8_t)(n >> 16));
		encoding.insert(encoding.begin(), (uint8_t)(n >> 24));

		encoding.insert(encoding.begin(), get_k());

		return encoding;
	}

	std::vector<TDH2_PrivateKey> TDH2_PrivateKey::generate_keys(uint8_t k, 
													 uint32_t n, 
													 RandomNumberGenerator& rng,
													 const DL_Group& group) {
		if(k > 255) {
			throw Invalid_Argument("TDH2: Maximum threshold is 255");
		}

		if (k > n) {
			throw Invalid_Argument("TDH2: Threshold is higher than total number keys");
		}

		srand(time(NULL));

		BigInt g_hat(group.power_g_p(BigInt::random_integer(rng, 2, group.get_q() - 1), group.q_bits()));
		BigInt x(BigInt::random_integer(rng, 2, group.get_q() - 1));
		BigInt y(group.power_g_p(x, group.get_q().bits()));
		
		secure_vector<uint8_t> x_bits;
		DER_Encoder(x_bits).encode(x);

		std::vector<BigInt> coefficients;
		for(uint8_t i = 0; i != k - 1; ++i) {
			coefficients.push_back(BigInt::random_integer(rng, 2, group.get_q() - 1));
		}

		coefficients.push_back(x);

		std::vector<BigInt> xi;
		std::vector<TDH2_PrivateKey> partialKeys;
		std::vector<BigInt> h;

		for(uint32_t i = 1; i != n + 1; ++i) {
			BigInt val = 0;

			for (uint8_t m = 0; m != coefficients.size(); ++m) {
				val += (power_mod(i, coefficients.size() - m - 1, group.get_q()) * coefficients.at(m)) % group.get_q();
			}

			xi.push_back(val % group.get_q());
			h.push_back(group.power_g_p(xi.at(i-1), group.q_bits()));
		}

		TDH2_PublicKey publicKey(group, y, g_hat, k, h);

		for(uint32_t i = 0; i != xi.size(); ++i) {
			partialKeys.push_back(TDH2_PrivateKey(i+1, xi.at(i), g_hat, publicKey));
		}


		return partialKeys;
	}

	void TDH2_PublicKey::encrypt(secure_vector<uint8_t> &msg, uint8_t label[20], RandomNumberGenerator& rng) {
		BigInt r(BigInt::random_integer(rng, 2, m_group.get_q() - 1));

		std::unique_ptr<Botan::KDF> kdf(Botan::KDF::create("HKDF(SHA-256)"));

		// calculate secret value
		const SymmetricKey secret_value(m_group.power_b_p(m_y, r, m_group.q_bits()).to_hex_string());

		const secure_vector<uint8_t> secret_keys = kdf->derive_key(16, secret_value.bits_of());

		if (secret_keys.size() != 16) {
			throw Encoding_Error("TDH2: KDF did not provide sufficient output");
		}

		std::unique_ptr<Cipher_Mode> aes_enc(Cipher_Mode::create("AES-128/CBC/PKCS7", Botan::ENCRYPTION));
		aes_enc->set_key(secret_keys);
		aes_enc->start();
		aes_enc->finish(msg);

		secure_vector<uint8_t> out;
		BigInt l(label, 20);
		BigInt c(msg.data(), msg.size());

		BigInt s(rng, m_group.q_bits() - 1);
		BigInt u = m_group.power_g_p(r);
		BigInt u_hat = m_group.power_b_p(m_g_hat, r, m_group.q_bits());
		
		BigInt w = m_group.power_g_p(s);
		BigInt w_hat = m_group.power_b_p(m_g_hat, s, m_group.q_bits());
		BigInt e = get_e(msg, label, u, w, u_hat, w_hat);
		BigInt f = m_group.mod_q(s + m_group.multiply_mod_q(r, e));

		DER_Encoder enc(out);
		enc.start_sequence()
			.encode(l)
			.encode(c)
			.encode(u)
			.encode(u_hat)
			.encode(e)
			.encode(f)
			.end_cons();

		msg = out; // (l, c, u, u_hat, e, f)
	}

	std::vector<uint8_t> TDH2_PrivateKey::create_share(secure_vector<uint8_t> encryption, RandomNumberGenerator &rng) {
		BER_Decoder dec(encryption.data(), encryption.size());
		BigInt u, c, u_hat, e, f, l;

		dec.start_sequence()
		.decode(l)
		.decode(c)
		.decode(u)
		.decode(u_hat)
		.decode(e)
		.decode(f);

		std::vector<uint8_t> label(l.bytes());
		l.binary_encode(label.data());

		f = m_group.mod_q(f);
		BigInt w(m_group.multiply_mod_p(m_group.power_g_p(f, m_group.q_bits()), 
			m_group.inverse_mod_p(m_group.power_b_p(u, e, m_group.q_bits()))));
			
		BigInt w_hat(m_group.multiply_mod_p(m_group.power_b_p(get_g_hat(), f, m_group.q_bits()), 
			m_group.inverse_mod_p(m_group.power_b_p(u_hat, e, m_group.q_bits()))));

		uint8_t valid = 0;
		std::vector<uint8_t> share;
		secure_vector<uint8_t> cipher(c.bytes());
		c.binary_encode(cipher.data());

		if (e == get_e(cipher, label.data(), u, w, u_hat, w_hat)) {
			valid = 1;
			BigInt ui(m_group.power_b_p(u, m_xi, m_group.q_bits()));
			BigInt si(BigInt::random_integer(rng, 2, m_group.get_q() - 1));

			BigInt ei(get_ei(ui, 
				m_group.power_b_p(u, si, m_group.q_bits()), 
				m_group.power_g_p(si, m_group.q_bits()), 
				m_group.get_q()));

			BigInt fi(m_group.mod_p(si + m_group.multiply_mod_p(m_xi, ei)));

			DER_Encoder enc(share);
			enc.start_sequence()
				.encode(ui)
				.encode(ei)
				.encode(fi)
				.end_cons();
		}

		share.insert(share.begin(), valid);
		share.insert(share.begin(), (uint8_t)(m_id >> 0));
		share.insert(share.begin(), (uint8_t)(m_id >> 8));
		share.insert(share.begin(), (uint8_t)(m_id >> 16));
		share.insert(share.begin(), (uint8_t)(m_id >> 24));
				
		return share; // (id, 1, ui, ei, fi) || (id, 0)
	}

	void TDH2_PrivateKey::combine_shares(secure_vector<uint8_t>& encryption, std::vector<std::vector<uint8_t>> shares) {
		if (get_k() > shares.size())
			throw Invalid_Argument("TDH2: Not enough decryption shares to reconstruct message");
		
		std::vector<uint32_t> ids;

		if(!verify_cipher(encryption))
			throw Invalid_Argument("TDH2: Invalid cipher");

		for (int i = 0; i != shares.size(); ++i) {
			uint32_t id = ((uint32_t)shares.at(i).at(0) << 24) 	|
					 	((uint32_t)shares.at(i).at(1)  << 16) 	|
					 	((uint32_t)shares.at(i).at(2)  << 8) 	|
					 	((uint32_t)shares.at(i).at(3)  << 0);

			if(shares.at(i).at(4) == 0) 
				throw Invalid_Argument("TDH2: Invalid share");

			if(!verify_share(shares.at(i), unlock(encryption))) 
				throw Invalid_Argument("TDH2: Invalid share");
			
			ids.push_back(id);
		}
		
		BigInt rG(1);
		BigInt q(m_group.get_q());
		for (int k = 0; k != shares.size(); ++k) {
			BigInt i (ids.at(k));
			BigInt l(1);

			for(int m = 0; m != ids.size(); ++m) {
				BigInt j(ids.at(m));
				if(i != j) {
					l = m_group.multiply_mod_q(
							m_group.multiply_mod_q(m_group.mod_q(j), 
							m_group.inverse_mod_q(m_group.mod_q((j - i)))), l);
				}
			}

			BigInt ui;
			BER_Decoder dec(shares.at(k).data() + 5, shares.at(k).size() - 5);
			dec.start_sequence().decode(ui);
			
			rG = m_group.multiply_mod_p(m_group.power_b_p(ui, l, m_group.q_bits()), rG);
		}
		
		std::unique_ptr<Botan::RandomNumberGenerator> rng(new Botan::AutoSeeded_RNG);
		DH_PrivateKey key(*rng.get(), get_group(), 1);
		secure_vector<uint8_t> secret_key(rG.bytes());
		rG.binary_encode(secret_key.data());

		// calculate secret value
		std::unique_ptr<Botan::KDF> kdf(Botan::KDF::create("HKDF(SHA-256)"));

		BER_Decoder dec(encryption);
		BigInt c, l;
		dec.start_sequence()
		.decode(l)
		.decode(c);

		secure_vector<uint8_t> cipher(c.bytes());
		c.binary_encode(cipher.data());

		// derive secret key from secret value
		secure_vector<uint8_t> secret_keys = kdf->derive_key(16, secret_key);

		if(secret_keys.size() != 16) {
			throw Encoding_Error("TDH2: KDF did not provide sufficient output");
		}

		std::unique_ptr<Cipher_Mode> aes_dec(Cipher_Mode::create("AES-128/CBC/PKCS7", Botan::DECRYPTION));
		aes_dec->set_key(secret_keys);
		aes_dec->start();
		aes_dec->finish(cipher);
		encryption = cipher;
	}
}