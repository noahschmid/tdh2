#ifndef BOTAN_THD2_H
#define BOTAN_TDH2_H

#include "tdh2_keys.h"
#include <botan/cipher_mode.h>
#include <botan/stream_cipher.h>
#include <botan/aead.h>
#include <botan/auto_rng.h>

using namespace Botan;

namespace TDH2 {
class TDH2_Encryptor {
    public:
    TDH2_Encryptor(TDH2_PublicKey& key, RandomNumberGenerator& rng);

    /**
     * Generate header for decrypting a new message and generate symmetric key
     * @param label plaintext label to identify message
     */
    std::vector<uint8_t> begin( uint8_t label[20]);

    /**
     * Encrypt a new block of the message
     * @param block block of 8 Bytes to encrypt
     */
    void update(secure_vector<uint8_t>& block);

    /**
     * Encrypt final block and finish encryption
     * @param block block of arbitrary length to encrypt
     */
    void finish(secure_vector<uint8_t>& block);

    /**
     * Reset encryptor, this deletes the symmetric key
     */
    void reset();

    private:
    TDH2_PublicKey m_public_key;
    std::unique_ptr<AEAD_Mode> m_enc;
    RandomNumberGenerator& m_rng;
};


class TDH2_Decryptor {
    public:
    TDH2_Decryptor(TDH2_PrivateKey& key);

    /**
     * Combine decryption shares to reconstruct symmetric key
     * @param shares the decryption shares
     * @param header header of the decrypted message
     * @return decrypted message if all decryption shares are valid, empty vector otherwise
     * 
     * @throws InvalidArgument if header or share is invalid
     */
    void begin(std::vector<std::vector<uint8_t>> shares, std::vector<uint8_t> header);

    /**
     * Decrypt a new block of the encrypted message
     * @param block block of 8 Bytes to decrypt
     */
    void update(secure_vector<uint8_t>& block);

    /**
     * Decrypt final block and finish decryption
     * @param block final block of arbitrary length to decrypt
     */
    void finish(secure_vector<uint8_t>& block);

    /**
     * Reset decryptor, this deletes the symmetric key
     */
    void reset();

    private:
    TDH2_PrivateKey m_private_key;
    std::unique_ptr<AEAD_Mode> m_dec;
};
}
#endif