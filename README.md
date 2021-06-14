# TDH2 Threshold Cryptosystem

Threshold cryptosystem based on [this](https://www.shoup.net/papers/thresh1.pdf) paper implemented in C++ using the [Botan library](https://github.com/randombit/botan). 

# Idea
First, we generate a public key and n private key shares and distribute the private keys to n parties. The public key will be used to encrypt a message and k parties holding a private key have to cooperate in order to decrypt the ciphertext. They each create a decryption share using their respective private key and then use k decryption shares to reconstruct the original message.

# Usage
For a demo project, take a look at demo.cpp.

### Key generation
    std::unique_ptr<Botan::DL_Group> group(new Botan::DL_Group("modp/ietf/2048")); 
    std::unique_ptr<Botan::RandomNumberGenerator> rng(new Botan::AutoSeeded_RNG);
    std::vector<TDH2::TDH2_PrivateKey> privateKeys = TDH2::TDH2_PrivateKey::generate_keys(k, n, *rng.get(), *group.get());
    TDH2::TDH2_PublicKey publicKey(privateKeys[0]); // get public key from private key

### Encryption
First we need a message to encrypt as well as a label:
    std::string plaintext = "this is a plaintext message";
    Botan::secure_vector<uint8_t> message(plaintext.data(), plaintext.data() + plaintext.length());
    uint8_t label[20] = "this is a label";

There are two ways to encrypt a message. First one is to directly encrypt using the method provided in the public key:
    std::vector<uint8_t> header = publicKey.encrypt(message, label, *rng.get());

Second is to use the TDH2::TDH2_Encryptor class. This enables you to block-wise input the plaintext message:
    TDH2::TDH2_Encryptor enc(publicKey, *rng.get());
	std::vector<uint8_t> header = enc.begin(label);
    enc.finish(message);

### Creating decryption shares
Only the header is used to generate decryption shares. That way you don't have to distribute the whole encrypted message over the network.
    std::vector<std::vector<uint8_t>> dec_shares;
    dec_shares.push_back(privateKeys.at(index).decrypt_share(header, *rng.get())); // change index accordingly
    
### Combining decryption shares
Again you can decide between feeding the shares directly to the combine method of the private key or using block-wise decryption. 

Single input:
    privateKeys[0].combine_shares(header, dec_shares, message);

Block-wise decryption:
    TDH2::TDH2_Decryptor dec(privateKeys[0]);
    dec.begin(dec_shares, header);
    dec.finish(message);
