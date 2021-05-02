# TDH2 Threshold Cryptosystem

Threshold cryptosystem based on [this](https://www.shoup.net/papers/thresh1.pdf) paper implemented in C++ using the [Botan library](https://github.com/randombit/botan). 

# Idea
First, a public key and n private keys are generated and the private keys will be distributed to n parties. The public key can be used to decrypt a message and to decrypt a cipher, k parties holding a private key have to cooperate. They first each create a decryption share using their respective private key and then use k decryption shares to reconstruct the original message.

# Usage
### Key generation
    std::unique_ptr<Botan::DL_Group> group(new Botan::DL_Group("modp/ietf/2048")); 
    std::unique_ptr<Botan::RandomNumberGenerator> rng(new Botan::AutoSeeded_RNG);
    std::vector<TDH2_PrivateKey> privateKeys = TDH2_PrivateKey::generate_keys(k, n, *rng.get(), *group.get());
    TDH2_PublicKey publicKey(privateKeys[0].subject_public_key());

### Encryption
    std::string plaintext = "this is a plaintext message";
    std::vector<uint8_t> msg(plaintext.data(), plaintext.data() + plaintext.size());
    uint8_t label[20] = "this is a label";
    std::vector<uint8_t> encryption = publicKey.encrypt(msg, label, *rng.get());

### Creating a decryption share
    privateKey.decrypt_share(encryption, *rng.get())
    
### Combining decryption shares
    std::vector<uint8_t> recovered_message = privateKey.combine_shares(encryption, dec_shares);
