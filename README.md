# TDH2 Threshold Cryptosystem

Implementation of a threshold cryptosystem that is secure against chosen ciphertext attacks based on [this](https://www.shoup.net/papers/thresh1.pdf) paper. Based on the [Botan library](https://github.com/randombit/botan). 

This project was part of my [bachelor thesis](thesis.pdf). More detailed background information can be found in the provided PDF.

# Threshold Encryption
In a threshold encryption scheme, instead of having a single public/private key pair, the private key is shared between n parties. Messages can be encrypted using the public key and to be able to decrypt a ciphertext, k parties holding a private key have to cooperate. They each create a decryption share using their respective private key and k decryption shares in combination with the ciphertext can then be used to reconstruct the original message. 
Threshold encryption can be used in distributed systems in combination with an atomic broadcast protocol (consensus protocol) to create a secure causal atomic broadcast protocol that preserves causality. One of the use cases would be to prevent front-running in decentralized exchanges on a blockchain.

# Installation
You have to install [Botan](https://github.com/randombit/botan) to be able to build this code. Use `make` to build and run the demo application.

# Usage
For a demo project, take a look at demo.cpp.

### Key generation
This cryptosystem uses keys that rely on the hardness of the discrete logarithm problem over prime-order subgroups of Z_p. To create such keys, a group and a random number generator have to be specified:

    std::unique_ptr<Botan::DL_Group> group(new Botan::DL_Group("modp/ietf/2048")); 
    std::unique_ptr<Botan::RandomNumberGenerator> rng(new Botan::AutoSeeded_RNG);

For this example, we use a standardized group with a 2048 modulus from [rfc5114](https://datatracker.ietf.org/doc/html/rfc5114).
    
    std::vector<TDH2::TDH2_PrivateKey> privateKeys = TDH2::TDH2_PrivateKey::generate_keys(k, n, *rng.get(), *group.get());
    TDH2::TDH2_PublicKey publicKey(privateKeys[0]); // get public key from private key

### Encryption
First we need a label and a message to encrypt:

    std::string plaintext = "this is a plaintext message";
    Botan::secure_vector<uint8_t> message(plaintext.data(), plaintext.data() + plaintext.length());
    uint8_t label[20] = "this is a label";

There are two ways to encrypt a message. First one is to directly encrypt using the method provided in the public key:

    std::vector<uint8_t> header = publicKey.encrypt(message, label, *rng.get());

Second is to use the TDH2::TDH2_Encryptor class. This enables you to block-wise input the plaintext message (for example if the message is too big to be held in RAM):

    TDH2::TDH2_Encryptor enc(publicKey, *rng.get());
    std::vector<uint8_t> header = enc.begin(label);
    enc.update(first_block);
    enc.update(second_block);
    ...
    enc.finish(last_block);
    
In both cases, the encryption happens in-place. That means the plaintext is overwritten by the ciphertext during the encryption process.

### Creating decryption shares
Only the ciphertext header is used to generate decryption shares. That way it is not necessary to distribute the whole encrypted message over the network.

    std::vector<std::vector<uint8_t>> dec_shares;
    dec_shares.push_back(privateKeys.at(index).decrypt_share(header, *rng.get())); // change index accordingly

Usually, each participant would create a decryption share and broadcast it to every other party so that every 

### Combining decryption shares
Again you can decide between feeding the shares directly to the combine method of the private key or using block-wise decryption. 

Single input:

    privateKeys[0].combine_shares(header, dec_shares, message);

Block-wise decryption:

    TDH2::TDH2_Decryptor dec(privateKeys[0]);
    dec.begin(dec_shares, header);
    dec.update(first_block);
    ...
    dec.finish(final_block);
