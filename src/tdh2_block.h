#ifndef BOTAN_THD2_BLOCK_H
#define BOTAN_TDH2_BLOCK_H

#include "tdh2_keys.h"
#include <botan/cipher_mode.h>
#include <botan/stream_cipher.h>

namespace Botan {
class TDH2_Block_Encryptor {
    public:
    TDH2_Block_Encryptor(TDH2_PublicKey& key, RandomNumberGenerator& rng);

    Botan::secure_vector<uint8_t> begin( uint8_t label[20]);
    void update(secure_vector<uint8_t>& block);
    void finish(secure_vector<uint8_t>& block);
    void reset();

    private:
    TDH2_PublicKey m_public_key;
    std::unique_ptr<Cipher_Mode> m_enc;
    RandomNumberGenerator& m_rng;
};


class TDH2_Block_Decryptor {
    public:
    TDH2_Block_Decryptor(TDH2_PrivateKey& key);

    void begin(std::vector<std::vector<uint8_t>> shares, Botan::secure_vector<uint8_t> header);
    void update(secure_vector<uint8_t>& block);
    void finish(secure_vector<uint8_t>& block);
    void reset();

    private:
    TDH2_PrivateKey m_private_key;
    std::unique_ptr<Botan::Cipher_Mode> m_dec;
};
}
#endif