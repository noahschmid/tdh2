#ifndef BOTAN_THD2_BLOCK_H
#define BOTAN_TDH2_BLOCK_H

#include "tdh2_keys.h"
#include <botan/cipher_mode.h>
#include <botan/stream_cipher.h>

namespace Botan {
class TDH2_Block_Encryptor {
    public:
    TDH2_Block_Encryptor(TDH2_PublicKey& key);

    Botan::secure_vector<uint8_t> begin(RandomNumberGenerator& rng, uint8_t label[20]);
    Botan::secure_vector<uint8_t> update(secure_vector<uint8_t> block);
    Botan::secure_vector<uint8_t> finish(secure_vector<uint8_t> block);
    void reset();

    private:
    TDH2_PublicKey m_public_key;
    std::unique_ptr<Botan::Cipher_Mode> m_enc;
};


class TDH2_Block_Decryptor {
    public:
    TDH2_Block_Decryptor(TDH2_PrivateKey& key);

    void begin(std::vector<std::vector<uint8_t>> shares, Botan::secure_vector<uint8_t> header);
    Botan::secure_vector<uint8_t> update(secure_vector<uint8_t> block);
    Botan::secure_vector<uint8_t> finish(secure_vector<uint8_t> block);
    void reset();
    
    private:
    TDH2_PrivateKey m_private_key;
    std::unique_ptr<Botan::Cipher_Mode> m_dec;
};
}
#endif