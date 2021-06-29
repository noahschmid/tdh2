/**
 * TDH2 Cryptosystem
 * (C) 2021 Noah Schmid
 */

#include "tdh2_keys.h"
#include <botan/der_enc.h>
#include <botan/numthry.h>
#include <botan/hash.h>
#include <botan/auto_rng.h>
#include <iostream>
#include <botan/reducer.h>
#include <math.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/cipher_mode.h>

namespace TDH2 {

	BigInt TDH2_PublicKey::get_ei(BigInt g1, BigInt g2, BigInt g3) {
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

		if (m_group.q_bits() > hash->output_length()*4) {
			Botan::secure_vector<uint8_t> g = h;

			for (BigInt i = 1; i < ceil((m_group.q_bits() - hash->output_length()*4)/hash->output_length()*8); ++i) {
				buf = g;
				buf.insert(buf.end(), i.data(), i.data() + i.size());
				hash->update(buf);
				buf.clear();
				buf = hash->final();
				h.insert(h.end(), buf.begin(), buf.end());
				buf.clear();
			}
		}

		return m_group.mod_q(BigInt(h));
	}

	BigInt TDH2_PublicKey::get_e(uint8_t m1[16], uint8_t m2[LABEL_LENGTH], BigInt g1, BigInt g2, BigInt g3, BigInt g4) const {
		std::unique_ptr<HashFunction> hash(HashFunction::create("SHA-256"));
		secure_vector<uint8_t> data(6*hash->output_length());

		hash->update(m1, 16);
		secure_vector<uint8_t> buf = hash->final();
		std::copy(buf.begin(), buf.end(), data.data());
		buf.clear();

		hash->update(m2, LABEL_LENGTH);
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
		Botan::secure_vector<uint8_t> h(hash->final());

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

		return m_group.mod_q(BigInt(h));
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
		uint8_t n = key_bits[1];
 
		BigInt p, q, g;

		if(m_k > n) {
			throw Invalid_Argument("TDH2: Invalid public key provided");
		}

		BER_Decoder dec(key_bits.data() + 2, key_bits.size() - 2);
		BER_Decoder ber = dec.start_sequence();
		ber.decode(p)
		.decode(g)
		.decode(q)
		.decode(m_g_hat)
		.decode(m_y);

		m_group = DL_Group(p, q, g);

		for(uint8_t i = 0; i != n; ++i) {
			BigInt hi;
			ber.decode(hi);
			m_h.push_back(hi);
		}

		ber.discard_remaining();
	}

	std::vector<uint8_t> TDH2_PublicKey::subject_public_key() const {
		std::vector<uint8_t> encoding;
		DER_Encoder enc(encoding);

		uint8_t n = m_h.size();

		enc.start_sequence()
		.encode(m_group.get_p())
		.encode(m_group.get_g())
		.encode(m_group.get_q())
		.encode(m_g_hat)
		.encode(m_y);

		for(uint8_t i = 0; i != n; ++i) {
			enc.encode(m_h.at(i));
		}

		enc.end_cons();

		encoding.insert(encoding.begin(), n);
		encoding.insert(encoding.begin(), m_k);

		return encoding;
	}

	std::vector<uint8_t> TDH2_PublicKey::extract_label(std::vector<uint8_t> header) {
		BER_Decoder dec(header.data(), header.size());
		BigInt l;

		dec.start_sequence()
		.decode(l)
		.discard_remaining();

		std::vector<uint8_t> label(l.bytes());
		l.binary_encode(label.data());
		return label;
	}

	bool TDH2_PublicKey::verify_share(std::vector<uint8_t> share, 
		std::vector<uint8_t> header) {
		if(share.size() < 6)
			return false;

		BigInt g(m_group.get_g());
		BigInt p(m_group.get_p());

		BigInt u;
		BER_Decoder dec(header.data() + LABEL_LENGTH + SYMMETRIC_KEY_LENGTH, header.size() + LABEL_LENGTH + SYMMETRIC_KEY_LENGTH);

		dec.start_sequence()
		.decode(u);

		uint8_t id = share.at(0);
		BigInt hi(m_h.at((int)(id - 1)));

		if(share.at(1) == 0) 
			return false;

		BigInt ui, ei, fi;
		BER_Decoder dec2(share.data() + 2, share.size() - 2);
		dec2.start_sequence()
			.decode(ui)
			.decode(ei)
			.decode(fi);

		return (ei == get_ei(ui, 
			m_group.multiply_mod_p(m_group.power_b_p(u, fi, m_group.q_bits()), m_group.inverse_mod_p(m_group.power_b_p(ui, ei, m_group.q_bits()))), 
			m_group.multiply_mod_p(m_group.power_g_p(fi), m_group.inverse_mod_p(m_group.power_b_p(hi, ei, m_group.q_bits())))));
	}
	
	bool TDH2_PublicKey::verify_header(std::vector<uint8_t> header) {
		BigInt g(m_group.get_g());
		BigInt p(m_group.get_p());

		BigInt u, u_hat, e, f;
		BER_Decoder dec(header.data() + SYMMETRIC_KEY_LENGTH + LABEL_LENGTH, header.size() - LABEL_LENGTH - SYMMETRIC_KEY_LENGTH);

		dec.start_sequence()
		.decode(u)
		.decode(u_hat)
		.decode(e)
		.decode(f);

		std::vector<uint8_t> label(header.data(), header.data() + LABEL_LENGTH);
		std::vector<uint8_t> cipher(header.data() + LABEL_LENGTH, header.data() + LABEL_LENGTH + SYMMETRIC_KEY_LENGTH);

		BigInt w(m_group.multiply_mod_p(m_group.power_g_p(f, m_group.q_bits()), 
			m_group.inverse_mod_p(m_group.power_b_p(u, e, m_group.q_bits()))));
		BigInt w_hat(m_group.multiply_mod_p(m_group.power_b_p(get_g_hat(), f, m_group.q_bits()), 
			m_group.inverse_mod_p(m_group.power_b_p(u_hat, e, m_group.q_bits()))));

		return (e == get_e(cipher.data(), label.data(), u, w, u_hat, w_hat));
	}


	std::vector<uint8_t> TDH2_PublicKey::encrypt(secure_vector<uint8_t> &message, uint8_t label[LABEL_LENGTH], RandomNumberGenerator &rng) const {
		BigInt r(BigInt::random_integer(rng, 2, group_q() - 1));
		std::unique_ptr<AEAD_Mode> sym_enc =  AEAD_Mode::create("ChaCha20Poly1305", ENCRYPTION);
		std::unique_ptr<Botan::KDF> kdf(Botan::KDF::create("HKDF(SHA-256)"));

		// calculate secret value
		const SymmetricKey tdh_key(get_group().power_b_p(get_y(), r, get_group().q_bits()).to_hex_string());

		secure_vector<uint8_t> symmetric_key = kdf->derive_key(SYMMETRIC_KEY_LENGTH, rng.random_vec(16));

		if (symmetric_key.size() != SYMMETRIC_KEY_LENGTH) {
			throw Encoding_Error("TDH2: KDF did not provide sufficient output");
		}

        sym_enc->set_key(symmetric_key);
        sym_enc->start(kdf->derive_key(8, symmetric_key));
		
		// encrypt symmetric key
		xor_buf(symmetric_key, tdh_key.bits_of(), tdh_key.length());

        std::vector<uint8_t> header;
		std::vector<uint8_t> msg;
        BigInt l(label, LABEL_LENGTH);

        size_t q_bits = get_group().q_bits();

		BigInt s(rng, q_bits - 1);
		BigInt u = get_group().power_g_p(r);
		BigInt u_hat = get_group().power_b_p(get_g_hat(), r, q_bits);

		BigInt c(symmetric_key);
		
		BigInt w = get_group().power_g_p(s);
		BigInt w_hat = get_group().power_b_p(get_g_hat(), s, q_bits);
		BigInt e = get_e(symmetric_key.data(), label, u, w, u_hat, w_hat);
		BigInt f = get_group().mod_q(s + get_group().multiply_mod_q(r, e));

		DER_Encoder enc(header);
		enc.start_sequence()
			.encode(u)
			.encode(u_hat)
			.encode(e)
			.encode(f)
			.end_cons();

		header.insert(header.begin(), symmetric_key.data(), symmetric_key.data() + SYMMETRIC_KEY_LENGTH);
		header.insert(header.begin(), label, label + LABEL_LENGTH);

		sym_enc->finish(message); // encrypt message

		return header; // (l, c, u, u_hat, e, f)
	}
	
	TDH2_PrivateKey::TDH2_PrivateKey(uint8_t id,
		BigInt xi,
		BigInt g_hat,
		TDH2_PublicKey publicKey) :
		TDH2_PublicKey(publicKey) {
		m_id = id;
		m_xi = xi;
	}

	TDH2_PrivateKey::TDH2_PrivateKey(secure_vector<uint8_t> key_bits, std::string& password) {
		std::unique_ptr<Botan::KDF> kdf(Botan::KDF::create("HKDF(SHA-256)"));
		secure_vector<uint8_t> secret(password.data(), password.data() + password.size());

		m_k = key_bits[0];
		uint8_t n = key_bits[1];

		if(m_k > n) {
			throw Invalid_Argument("TDH2: Invalid private key provided");
		}

		BigInt p, q, g;

		BER_Decoder dec(key_bits.data() + 2, key_bits.size() - 2);
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

	secure_vector<uint8_t> TDH2_PrivateKey::BER_encode(std::string &password) const {
		secure_vector<uint8_t> encoding;
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

		for(uint8_t i = 0; i != get_h().size(); ++i) {
			enc.encode(get_h().at(i));
		}

		enc.end_cons();
		
		uint8_t n = m_h.size();

		encoding.insert(encoding.begin(), n);
		encoding.insert(encoding.begin(), get_k());

		return encoding;
	}

	std::vector<TDH2_PrivateKey> TDH2_PrivateKey::generate_keys(uint8_t k, 
													 uint8_t n, 
													 RandomNumberGenerator& rng,
													 const DL_Group& group) {
		if(k > 254 || n > 254 || k < 1 || n < 1) {
			throw Invalid_Argument("TDH2: n and k have to be between 1 and 254");
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

		for(uint8_t i = 1; i != n + 1; ++i) {
			BigInt val = 0;

			for (uint8_t m = 0; m != coefficients.size(); ++m) {
				val += (power_mod(i, coefficients.size() - m - 1, group.get_q()) * coefficients.at(m)) % group.get_q();
			}

			xi.push_back(val % group.get_q());
			h.push_back(group.power_g_p(xi.at(i-1), group.q_bits()));
		}

		TDH2_PublicKey publicKey(group, y, g_hat, k, h);

		for(uint8_t i = 0; i != xi.size(); ++i) {
			partialKeys.push_back(TDH2_PrivateKey(i+1, xi.at(i), g_hat, publicKey));
		}

		return partialKeys;
	}

	std::vector<uint8_t> TDH2_PrivateKey::create_share(std::vector<uint8_t> header, RandomNumberGenerator &rng) {
		uint8_t valid = 0;
		std::vector<uint8_t> share;

		if (verify_header(header)) {
			BER_Decoder dec(header.data() + SYMMETRIC_KEY_LENGTH + LABEL_LENGTH, header.size() - LABEL_LENGTH - SYMMETRIC_KEY_LENGTH);
			BigInt u;

			dec.start_sequence()
			.decode(u)
			.discard_remaining();

			valid = 1;
			BigInt ui(m_group.power_b_p(u, m_xi, m_group.q_bits()));
			BigInt si(BigInt::random_integer(rng, 2, m_group.get_q() - 1));

			BigInt ei(get_ei(ui, 
				m_group.power_b_p(u, si, m_group.q_bits()), 
				m_group.power_g_p(si, m_group.q_bits())));

			BigInt fi(m_group.mod_p(si + m_group.multiply_mod_p(m_xi, ei)));

			DER_Encoder enc(share);
			enc.start_sequence()
				.encode(ui)
				.encode(ei)
				.encode(fi)
				.end_cons();
		}

		share.insert(share.begin(), valid);
		share.insert(share.begin(), m_id);
		return share; // (id, 1, ui, ei, fi) || (id, 0)
	}

	void TDH2_PrivateKey::combine_shares(std::vector<uint8_t> header, std::vector<std::vector<uint8_t>> shares, secure_vector<uint8_t> &cipher) {
        if (m_k > shares.size())
			throw Invalid_Argument("TDH2: Not enough decryption shares to reconstruct message");
		
		std::vector<uint8_t> ids;

		if(!verify_header(header)) 
			throw Invalid_Argument("TDH2: invalid decryption header");

		for (int i = 0; i != shares.size(); ++i) {
			uint8_t id = shares.at(i).at(0);

			if(!verify_share(shares.at(i), header)) 
				throw Invalid_Argument("TDH2: invalid share");
			

			if(shares.at(i).at(1) == 0) 
				throw Invalid_Argument("TDH2: invalid share");
			
			ids.push_back(id);
		}

		BigInt rG(1);
		BigInt q(group_q());
		for (int k = 0; k != shares.size(); ++k) {
			BigInt i (ids.at(k));
			BigInt l(1);

			for(int m = 0; m != ids.size(); ++m) {
				BigInt j(ids.at(m));
				if(i != j) {
					l = get_group().multiply_mod_q(
							get_group().multiply_mod_q(get_group().mod_q(j), 
							get_group().inverse_mod_q(get_group().mod_q((j - i)))), l);
				}
			}

			BigInt ui;
			BER_Decoder dec(shares.at(k).data() + 2, shares.at(k).size() - 2);
			dec.start_sequence().decode(ui);
			
			rG = get_group().multiply_mod_p(get_group().power_b_p(ui, l, get_group().q_bits()), rG);
		}
		
		std::unique_ptr<Botan::RandomNumberGenerator> rng(new Botan::AutoSeeded_RNG);
		DH_PrivateKey key(*rng.get(), get_group(), 1);
		secure_vector<uint8_t> tdh_key(hex_decode_locked(rG.to_hex_string()));

		// calculate secret value
		std::unique_ptr<Botan::KDF> kdf(Botan::KDF::create("HKDF(SHA-256)"));

		secure_vector<uint8_t> symmetric_key(header.data() + LABEL_LENGTH, header.data() + LABEL_LENGTH + SYMMETRIC_KEY_LENGTH);
		xor_buf(symmetric_key, tdh_key, tdh_key.size());

		std::unique_ptr<AEAD_Mode> sym_dec =  AEAD_Mode::create("ChaCha20Poly1305", DECRYPTION);
        sym_dec->set_key(symmetric_key);
        sym_dec->start(kdf->derive_key(8, symmetric_key));
		sym_dec->finish(cipher);
    }
}