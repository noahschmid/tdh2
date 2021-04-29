#include "tdh2.h"
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

	BigInt h2(std::vector<uint8_t> m1, uint8_t m2[20], BigInt g1, BigInt g2, BigInt g3, BigInt g4, BigInt q) {
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

	TDH2_PublicKey::TDH2_PublicKey(std::vector<uint8_t> key_bits) {
		m_k = key_bits[0];
		uint8_t n = key_bits[1];
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

		for(int i = 0; i != n; ++i) {
			BigInt hi;
			ber.decode(hi);
			m_h.push_back(hi);
		}

		ber.discard_remaining();
	}

	std::vector<uint8_t> TDH2_PublicKey::subject_public_key() const {
		std::vector<uint8_t> encoding;
		DER_Encoder enc(encoding);

		enc.start_sequence()
		.encode(m_group.get_p())
		.encode(m_group.get_g())
		.encode(m_group.get_q())
		.encode(m_g_hat)
		.encode(m_y);

		for(int i = 0; i != m_h.size(); ++i) {
			enc.encode(m_h.at(i));
		}

		enc.end_cons();

		encoding.insert(encoding.begin(), m_h.size());
		encoding.insert(encoding.begin(), m_k);

		return encoding;
	}

	std::vector<uint8_t> TDH2_PublicKey::extract_label(std::vector<uint8_t> encryption) {
		if (encryption.size() < 4*m_group.p_bytes() + 21) {
			throw Invalid_Argument("encryption too short");
		}

		static std::vector<uint8_t> l(encryption.data() + encryption.size() - (4*m_group.p_bytes() + 20), 
			encryption.data() + encryption.size() - 4*m_group.p_bytes());
		return l;
	}

	std::vector<uint8_t> TDH2_PublicKey::encrypt(std::vector<uint8_t> msg, uint8_t label[20], RandomNumberGenerator& rng) {
		BigInt r(BigInt::random_integer(rng, 2, m_group.get_q() - 1));

		std::unique_ptr<Botan::KDF> kdf(Botan::KDF::create("HKDF(SHA-256)"));

		// calculate secret value
		const SymmetricKey secret_value(m_group.power_b_p(m_y, r, m_group.q_bits()).to_hex_string());

		const secure_vector<uint8_t> secret_keys = kdf->derive_key(msg.size(), secret_value.bits_of());

		if (secret_keys.size() != msg.size()) {
			throw Encoding_Error("TDH2: KDF did not provide sufficient output");
		}

		const size_t cipher_key_len = msg.size();

		xor_buf(msg, secret_keys, cipher_key_len);

		secure_vector<uint8_t> out;
		BigInt l(label, 20);
		BigInt c(msg.data(), msg.size());

		BigInt s(rng, m_group.q_bits() - 1);
		BigInt u = m_group.power_g_p(r);
		BigInt u_hat = m_group.power_b_p(m_g_hat, r, m_group.q_bits());
		
		BigInt w = m_group.power_g_p(s);
		BigInt w_hat = m_group.power_b_p(m_g_hat, s, m_group.q_bits());
		BigInt e = h2(msg, label, u, w, u_hat, w_hat, group_q());
		BigInt f = m_group.mod_q(s + m_group.multiply_mod_q(r, e));

		DER_Encoder enc(out);
		enc.start_sequence()
			.encode(c)
			.encode(l)
			.encode(u)
			.encode(u_hat)
			.encode(e)
			.encode(f)
			.end_cons();

		return unlock(out);
	}

	bool TDH2_PublicKey::verify_share(std::vector<uint8_t> share, std::vector<uint8_t> encryption) {
		if(share.size() < 2)
			return false;

		BigInt g(m_group.get_g());
		BigInt p(m_group.get_p());

		BigInt u, u_hat, e, f, c, l;
		BER_Decoder dec(encryption.data(), encryption.size());

		dec.start_sequence()
		.decode(c)
		.decode(l)
		.decode(u)
		.decode(u_hat)
		.decode(e)
		.decode(f);

		std::vector<uint8_t> label(l.bytes());
		l.binary_encode(label.data());
		std::vector<uint8_t> cipher(c.bytes()); 
		c.binary_encode(cipher.data());

		BigInt w(m_group.multiply_mod_p(m_group.power_g_p(f, m_group.q_bits()), 
			m_group.inverse_mod_p(m_group.power_b_p(u, e, m_group.q_bits()))));
		BigInt w_hat(m_group.multiply_mod_p(m_group.power_b_p(get_g_hat(), f, m_group.q_bits()), 
			m_group.inverse_mod_p(m_group.power_b_p(u_hat, e, m_group.q_bits()))));

		size_t id = share.at(0);
		size_t valid = share.at(1);

		if (e == h2(cipher, label.data(), u, w, u_hat, w_hat, m_group.get_q())) {
			BigInt hi(m_h.at((int)(id - 1)));

			BigInt ui, ei, fi;
			BER_Decoder dec2(share.data() + 2, share.size() - 2);
			dec2.start_sequence()
				.decode(ui)
				.decode(ei)
				.decode(fi);

			if(ei == h4(ui, 
				m_group.multiply_mod_p(m_group.power_b_p(u, fi, m_group.q_bits()), m_group.inverse_mod_p(m_group.power_b_p(ui, ei, m_group.q_bits()))), 
				m_group.multiply_mod_p(m_group.power_g_p(fi), m_group.inverse_mod_p(m_group.power_b_p(hi, ei, m_group.q_bits()))), m_group.get_q()))
				return true;
		} else if (valid == 0) {
			return true;
		}

		return false;
	}
	
	TDH2_PrivateKey::TDH2_PrivateKey(uint8_t id,
		BigInt xi,
		BigInt g_hat,
		TDH2_PublicKey publicKey) :
		TDH2_PublicKey(publicKey) {
		m_id = id;
		m_xi = xi;
	}

	std::vector<uint8_t> TDH2_PrivateKey::public_value() const {
		return unlock(BigInt::encode_1363(m_y, group_p().bytes()));
	}

	std::vector<uint8_t> TDH2_PrivateKey::BER_encode(std::string &password) const {
	}

	std::vector<TDH2_PrivateKey> TDH2_PrivateKey::generate_keys(uint8_t k, 
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
			for (int k = 0; k != coefficients.size(); ++k) {
				val += (power_mod(i, coefficients.size() - k - 1, group.get_q()) * coefficients.at(k)) % group.get_q();
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

	std::vector<uint8_t> TDH2_PrivateKey::decrypt_share(std::vector<uint8_t> encryption, RandomNumberGenerator &rng) {
		BER_Decoder dec(encryption.data(), encryption.size());
		BigInt u, u_hat, e, f, c, l;

		dec.start_sequence()
		.decode(c)
		.decode(l)
		.decode(u)
		.decode(u_hat)
		.decode(e)
		.decode(f);

		std::vector<uint8_t> label(l.bytes());
		l.binary_encode(label.data());
		std::vector<uint8_t> cipher(c.bytes()); 
		c.binary_encode(cipher.data());

		f = m_group.mod_q(f);
		BigInt w(m_group.multiply_mod_p(m_group.power_g_p(f, m_group.q_bits()), 
			m_group.inverse_mod_p(m_group.power_b_p(u, e, m_group.q_bits()))));
			
		BigInt w_hat(m_group.multiply_mod_p(m_group.power_b_p(get_g_hat(), f, m_group.q_bits()), 
			m_group.inverse_mod_p(m_group.power_b_p(u_hat, e, m_group.q_bits()))));

		uint8_t valid = 0;
		std::vector<uint8_t> share;

		if (e == h2(cipher, label.data(), u, w, u_hat, w_hat, m_group.get_q())) {
			valid = 1;
			BigInt ui(m_group.power_b_p(u, m_xi, m_group.q_bits()));
			BigInt si(BigInt::random_integer(rng, 2, m_group.get_q() - 1));

			BigInt ei(h4(ui, 
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
		share.insert(share.begin(), m_id);
		
		return share; // (id, 1, ui, ei, fi) || (id, 0)
	}

	std::vector<uint8_t> TDH2_PrivateKey::combine_shares(std::vector<uint8_t> encryption, std::vector<std::vector<uint8_t>> shares) {
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
			BigInt l(1);

			for(BigInt j : ids) {
				if(i != j)
					l = m_group.multiply_mod_q(
							m_group.multiply_mod_q(m_group.mod_q(j), 
							m_group.inverse_mod_q(m_group.mod_q(j - i))), l);
			}

			BigInt ui;
			BER_Decoder dec(shares.at(k).data() + 2, shares.at(k).size() - 2);
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
		BigInt c;
		dec.start_sequence()
		.decode(c);

		std::vector<uint8_t> cipher(c.bytes());
		c.binary_encode(cipher.data());

		const size_t ciphertext_len = cipher.size();

		// derive secret key from secret value
		secure_vector<uint8_t> secret_keys = kdf->derive_key(ciphertext_len, secret_key);

		if(secret_keys.size() != ciphertext_len) {
			throw Encoding_Error("TDH2: KDF did not provide sufficient output");
		}

		// decrypt
		xor_buf(cipher, secret_keys.data(), ciphertext_len);

		return cipher;
	}

	std::vector<uint8_t> TDH2_PrivateKey::reconstruct_secret(std::vector<TDH2_PrivateKey> keys) {
		BigInt key(0);
		BigInt q(keys.at(0).get_group().get_q());
		std::vector<uint8_t> ids;

		for(uint8_t i = 0; i != keys.size(); ++i) {
			if (keys.at(i).get_group().get_q() != q)
				throw Invalid_Argument("TDH2: Keys have different q");

			ids.push_back(keys.at(i).get_id());
		}

		for(uint8_t k = 0; k != keys.size(); ++k) {
			BigInt l(1);
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