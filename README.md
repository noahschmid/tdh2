# TDH2 Threshold Cryptosystem

Threshold cryptosystem based on [this](https://www.shoup.net/papers/thresh1.pdf) paper implemented in C++ using the [Botan library](https://github.com/randombit/botan). 

# Idea
First, a public key and n private keys are generated and the private keys will be distributed to n parties. The public key can be used to encrypt a message and to decrypt, k parties holding a private key have to cooperate. They each create a decryption share using their respective private key and then use k decryption shares to reconstruct the original message.

# Usage
For a demo project, take a look at main.cpp

### Key generation
    std::unique_ptr<Botan::DL_Group> group(new Botan::DL_Group("modp/ietf/2048")); 
    std::unique_ptr<Botan::RandomNumberGenerator> rng(new Botan::AutoSeeded_RNG);
    std::vector<TDH2_PrivateKey> privateKeys = TDH2_PrivateKey::generate_keys(k, n, *rng.get(), *group.get());
    TDH2_PublicKey publicKey(privateKeys[0]);

### Encryption
    std::string plaintext = "this is a plaintext message";
    std::vector<uint8_t> msg(plaintext.data(), plaintext.data() + plaintext.size());
    uint8_t label[20] = "this is a label";
    std::vector<uint8_t> encryption = publicKey.encrypt(msg, label, *rng.get());

### Creating decryption shares
    std::vector<std::vector<uint8_t>> dec_shares;
    dec_shares.push_back(privateKeys.at(i).decrypt_share(encryption, *rng.get()));
    
### Combining decryption shares
    std::vector<uint8_t> recovered_message = privateKey.combine_shares(encryption, dec_shares);
