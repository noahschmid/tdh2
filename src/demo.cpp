/**
 * Short demo illustrating the usage of the TDH2 cryptosystem
 * 
 * (C) 2021 Noah Schmid
 * 
 */

#include <botan/auto_rng.h>
#include <botan/bigint.h>
#include <botan/der_enc.h>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <limits>
#include "timer.h"
#include "tdh2.h"

/**
 * Randomly shuffle array
 */
template<class BidiIter >
BidiIter random_unique(BidiIter begin, BidiIter end, size_t num_random) {
	size_t left = std::distance(begin, end);
	while (num_random--) {
		BidiIter r = begin;
		std::advance(r, rand() % left);
		std::swap(*begin, *r);
		++begin;
		--left;
	}
	return begin;
}

/**
 * Convert hexadecimal array to string
 */
std::string hex2string(std::vector<uint8_t> hex_arr) {
	return std::string(reinterpret_cast<const char *>(&hex_arr[0]), hex_arr.size());
}

std::string hex2string(Botan::secure_vector<uint8_t> hex_arr) {
	return hex2string(unlock(hex_arr));
}

int main(int argc, char* argv[]) {
	std::string plaintext = "This is a plaintext message containing a plaintext message.";
	Botan::secure_vector<uint8_t> message(plaintext.data(), plaintext.data() + plaintext.length());
	
	Timer timer;
	std::unique_ptr<Botan::RandomNumberGenerator> rng(new Botan::AutoSeeded_RNG);

	Botan::BigInt p("0x1FCD5FE9BF0EFEF9033853A08449916EF665C012AAC68F0869FBB1EA84A9E8BB103C2E9D2B2A53C86AFA6A6D34C2F96B47EEC4717F73D96ADEC6BBEEC1E9DE112B1B2FD7B7AF7F53CDE1AAD01E1F7FBB6C08DD2E541F233F62EBD1514D6985D41BB9649DF8F645B649BC0D022B67C8694BE34D7E1D5002055BB186052A20467295DBFB989C0DA1A19B7588EAD664360A23781DB043EDD21684A1225E1F1C53E073E5F430F4B4DDAF6B89E51F322F3C208B59523383890EFD94A9C407D8C97B1D84EA9E5E0080B8D7330B0485EF6B8142282AD4DA0F328F9071D5CAF81FB481A821AC87FFDCC63E7A59286DFB33F36C449FA89F0CBB0BA3A67473B8F792EFAEC5");
	Botan::BigInt q("0xDAF370A2F6328096F29F718466E0FB052596C9D1C284C2C90260947763615AFB");
	Botan::BigInt g("0x74C509449CE926EE27AFC4AE6076EB046840C1A639A79ABD922937DED193C7681B0E2F154019555E5083968CC8461DBC26B43700171350F4C76665E741B80C2535689B67A89E5E47CC600E7A11A66CD7C0057D677D6F1F3922BE8290BE4CF43CF5841157F6364FF9059E29A5068EFAAD5F10CC6E6712846AE2827CE0042531D069C1D7CD956E65717FB1E17C3C9B1A8AA8901326A75A8E2527B32BCE358ADB3C4268904FAF461F85C1D00A76E50407070865859B6F344815B224D1B52B56B8F96872FFD5769D7FE7E67B4196ECF5412EE87383A1FF3CC70660394D54BC39A2D75916FC6F5AD63031EE6FEE03E48A726920347C3EF61FFB79DCC62F82C7FC4F2");

	std::unique_ptr<Botan::DL_Group> group(new Botan::DL_Group(p, q, g)); 

	uint8_t label[20] = "this is a label";

	const int n = 4, k = 3;

	// generate private/public keypair
	timer.start("key generation time");
	std::vector<TDH2::TDH2_PrivateKey> privateKeys = TDH2::TDH2_PrivateKey::generate_keys(k, n, *rng.get(), *group.get());
	timer.stop();
	
	// test public key encoding/decoding
	TDH2::TDH2_PublicKey publicKey(privateKeys[0].subject_public_key());
	
	// test private key encoding/decoding
	std::string password = "password";
	privateKeys[0] = TDH2::TDH2_PrivateKey(privateKeys[0].BER_encode(password), password);

	// encrypt using block encryption
	/*
	TDH2::TDH2_Encryptor enc(publicKey, *rng.get());
	timer.start("\nheader generation time");
	std::vector<uint8_t> header = enc.begin(label);
	timer.stop();

	timer.start("block encryption time");
	enc.finish(message);
	timer.stop();
	*/

	// encrypt using public key
	timer.start("encryption time");
    std::vector<uint8_t> header = publicKey.encrypt(message, label, *rng.get());
	timer.stop();

	std::cout << "encrypted text: " << Botan::hex_encode(message) << std::endl;
	
	std::vector<int> ids;
	for(TDH2::TDH2_PrivateKey pk : privateKeys) {
		ids.push_back(pk.get_id());
	}
	
	// select k random private keys
	random_unique(ids.begin(), ids.end(), k);

	// create k decryption shares
	std::vector<std::vector<uint8_t>> dec_shares;

	for(int i = 0; i < k; ++i) {
		std::cout << "using key [" << ids.at(i) << "] to create decryption share, ";
		timer.start("time");
		dec_shares.push_back(privateKeys.at(ids.at(i) - 1).create_share(header, *rng.get()));
		timer.stop();
	}

	// combine decryption shares to get original message back
	
	/* using block decryption
	TDH2::TDH2_Decryptor dec(privateKeys[0]);
	timer.start("\nshare combination time");
	dec.begin(dec_shares, header);
	timer.stop();

	timer.start("block 1 decryption time");
	dec.finish(message);
	timer.stop();*/

	timer.start("decryption time");
	privateKeys[0].combine_shares(header, dec_shares, message);
	timer.stop();

	std::cout << "decrypted message: " << hex2string(message) << "\n";
}