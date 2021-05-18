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
#include <string>
#include <sstream>
#include <algorithm>
#include <iterator>
#include <exception>
#include "timer.h"
#include "tdh2.h"


enum KEY_TYPE { PRIVATE = 0, PUBLIC = 1};

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
	std::string hex = Botan::hex_encode(hex_arr);
	int len = hex.length();
	std::string newString;

	for (int i = 0; i < len; i += 2) {
		std::string byte = hex.substr(i, 2);
		char chr = (char)(int)strtol(byte.c_str(), NULL, 16);
		newString.push_back(chr);
	}

	return newString;
}

std::string hex2string(Botan::secure_vector<uint8_t> hex_arr) {
	return hex2string(unlock(hex_arr));
}

void write_to_file(std::string filename, Botan::secure_vector<uint8_t>& message, bool verbose = true) {
	std::fstream out(filename, std::ios::out | std::ios::binary);
	if(out.fail()) {
		throw std::runtime_error("File invalid or not found!");
	}
	size_t size = message.size();
	float pos = 0;
	int percent = 0;

	int blocks = size / 100;
	if(verbose) {
		std::string unit(" Bytes");

		if(size > 1000) {
			size /= 1000;
			unit = "kB";
		}

		if(size > 1000) {
			size /= 1000;
			unit = "MB";
		}
		std::cout << "\nsaving " << filename << " (" << size << unit << ")...\n";
	}

	for(uint8_t byte_buf : message) {
		out << byte_buf;	
		++pos;
		if(pos == blocks && verbose) {
			pos = 0;
			++percent;
			std::cout << percent << "% done.." << "\r" << std::flush;
		}
	}
	out.close();
	if(verbose)
		std::cout << "finished    \n\n";
}

void write_to_file(std::string filename, std::vector<uint8_t> message, bool verbose = true) {
	Botan::secure_vector<uint8_t> msg(message.begin(), message.end());
	write_to_file(filename, msg, verbose);
}

void read_file(std::string filename, Botan::secure_vector<uint8_t>& message, bool verbose = true) {
	std::ifstream in(filename, std::ios::in | std::ios::binary);
	if(in.fail()) {
		throw 5;
	}
	in.ignore( std::numeric_limits<std::streamsize>::max() );
	std::streamsize size = in.gcount();
	in.clear();   //  Since ignore will have set eof.
	in.seekg( 0, std::ios_base::beg );

	uint8_t buf;
	in >> std::noskipws;
	float pos = 0;
	int percent = 0;

	int blocks = size / 100;
	std::string unit(" Bytes");
	if(verbose) {
		if(size > 1000) {
			size /= 1000;
			unit = "kB";
		}

		if(size > 1000) {
			size /= 1000;
			unit = "MB";
		}

		std::cout << "\nreading " << filename << " (" << size << unit << ")...\n";
	}

	while(in >> buf) {
		message.push_back(buf);
		++pos;
		if(pos == blocks && verbose) {
			pos = 0;
			++percent;
			std::cout << percent << "% done.." << "\r" << std::flush;
		}
	}

	in.close();
	if(verbose)
		std::cout << "finished    \n\n";
}

Botan::TDH2_PrivateKey private_key;
Botan::TDH2_PublicKey public_key;
bool private_key_loaded = false;
bool public_key_loaded = false;

void genKeys(int k, int n, std::string &password) {
	Timer timer;
	timer.start("Keys generated in");
	std::unique_ptr<Botan::RandomNumberGenerator> rng(new Botan::AutoSeeded_RNG);

	Botan::BigInt p("0x1FCD5FE9BF0EFEF9033853A08449916EF665C012AAC68F0869FBB1EA84A9E8BB103C2E9D2B2A53C86AFA6A6D34C2F96B47EEC4717F73D96ADEC6BBEEC1E9DE112B1B2FD7B7AF7F53CDE1AAD01E1F7FBB6C08DD2E541F233F62EBD1514D6985D41BB9649DF8F645B649BC0D022B67C8694BE34D7E1D5002055BB186052A20467295DBFB989C0DA1A19B7588EAD664360A23781DB043EDD21684A1225E1F1C53E073E5F430F4B4DDAF6B89E51F322F3C208B59523383890EFD94A9C407D8C97B1D84EA9E5E0080B8D7330B0485EF6B8142282AD4DA0F328F9071D5CAF81FB481A821AC87FFDCC63E7A59286DFB33F36C449FA89F0CBB0BA3A67473B8F792EFAEC5");
	Botan::BigInt q("0xDAF370A2F6328096F29F718466E0FB052596C9D1C284C2C90260947763615AFB");
	Botan::BigInt g("0x74C509449CE926EE27AFC4AE6076EB046840C1A639A79ABD922937DED193C7681B0E2F154019555E5083968CC8461DBC26B43700171350F4C76665E741B80C2535689B67A89E5E47CC600E7A11A66CD7C0057D677D6F1F3922BE8290BE4CF43CF5841157F6364FF9059E29A5068EFAAD5F10CC6E6712846AE2827CE0042531D069C1D7CD956E65717FB1E17C3C9B1A8AA8901326A75A8E2527B32BCE358ADB3C4268904FAF461F85C1D00A76E50407070865859B6F344815B224D1B52B56B8F96872FFD5769D7FE7E67B4196ECF5412EE87383A1FF3CC70660394D54BC39A2D75916FC6F5AD63031EE6FEE03E48A726920347C3EF61FFB79DCC62F82C7FC4F2");

	std::unique_ptr<Botan::DL_Group> group(new Botan::DL_Group(p, q, g)); 

	std::vector<Botan::TDH2_PrivateKey> privateKeys = Botan::TDH2_PrivateKey::generate_keys(k, n, *rng.get(), *group.get());
	std::string filename = "pk";
	for(int i = 0; i != privateKeys.size(); ++i) {
		Botan::secure_vector<uint8_t> key = privateKeys[i].BER_encode(password);
		key.push_back(KEY_TYPE::PRIVATE);
		write_to_file(filename.append(std::to_string(privateKeys[i].get_id())), key, false);
	}
	filename = "pub";
	std::vector<uint8_t> key = privateKeys[0].subject_public_key();
	key.push_back(KEY_TYPE::PUBLIC);
	write_to_file(filename, key, false);
	timer.stop();
}

void printHelp() {
	std::cout << "-- TDH2-CLI - Usage: --\n";
	std::cout << "* bmk [filename] \t\t : benchmark demo\n";
	std::cout << "* gen [k] [n] [pwd] \t\t : generate keys for (k, n) threshold cryptosystem and encode private key using pwd\n";
	std::cout << "* load [filename] \t\t : load key\n";
	std::cout << "* enc [file] [label] \t\t : encrypt file\n";
	std::cout << "* crsh [file] \t\t\t : create decryption share for file\n";
	std::cout << "* dec [cipher] [shares] [output] : decrypt cipher using decryption shares\n";
	std::cout << "* quit \t\t\t : exit TDH2-CLI\n";
}

void load_key(std::string filename) {
	try {
		Botan::secure_vector<uint8_t> key;
		read_file(filename, key, false);
		KEY_TYPE type = static_cast<KEY_TYPE>(key.back());
		key.pop_back();

		if(type == PUBLIC) {
			public_key = Botan::TDH2_PublicKey(unlock(key));
			public_key_loaded = true;
			std::cout << "Public key loaded\n";
			return;
		} else if(type == PRIVATE) {
			std::string password;
			std::cout << "Enter password: ";
			getline(std::cin, password);
			private_key = Botan::TDH2_PrivateKey(key, password);
			private_key_loaded = true;
			std::cout << "Private key loaded\n";
			return;
		}

		std::cout << "ERROR: Invalid key file!\n";
	} catch(int n) {
		std::cout << "ERROR: File invalid or not found!\n";
		
	}
	return;
}

void benchmark_demo(std::string filename) {
	std::cout << std::setprecision(1) << std::fixed;

	std::string filetype = filename.substr(filename.find_last_of('.') + 1);
	Botan::secure_vector<uint8_t> message;
	
	try {
	read_file(filename, message);
	} catch(int e) {
		std::cout << "ERROR: File invalid or not found!\n";
		return;
	}
	
	Timer timer;
	std::unique_ptr<Botan::RandomNumberGenerator> rng(new Botan::AutoSeeded_RNG);

	Botan::BigInt p("0x1FCD5FE9BF0EFEF9033853A08449916EF665C012AAC68F0869FBB1EA84A9E8BB103C2E9D2B2A53C86AFA6A6D34C2F96B47EEC4717F73D96ADEC6BBEEC1E9DE112B1B2FD7B7AF7F53CDE1AAD01E1F7FBB6C08DD2E541F233F62EBD1514D6985D41BB9649DF8F645B649BC0D022B67C8694BE34D7E1D5002055BB186052A20467295DBFB989C0DA1A19B7588EAD664360A23781DB043EDD21684A1225E1F1C53E073E5F430F4B4DDAF6B89E51F322F3C208B59523383890EFD94A9C407D8C97B1D84EA9E5E0080B8D7330B0485EF6B8142282AD4DA0F328F9071D5CAF81FB481A821AC87FFDCC63E7A59286DFB33F36C449FA89F0CBB0BA3A67473B8F792EFAEC5");
	Botan::BigInt q("0xDAF370A2F6328096F29F718466E0FB052596C9D1C284C2C90260947763615AFB");
	Botan::BigInt g("0x74C509449CE926EE27AFC4AE6076EB046840C1A639A79ABD922937DED193C7681B0E2F154019555E5083968CC8461DBC26B43700171350F4C76665E741B80C2535689B67A89E5E47CC600E7A11A66CD7C0057D677D6F1F3922BE8290BE4CF43CF5841157F6364FF9059E29A5068EFAAD5F10CC6E6712846AE2827CE0042531D069C1D7CD956E65717FB1E17C3C9B1A8AA8901326A75A8E2527B32BCE358ADB3C4268904FAF461F85C1D00A76E50407070865859B6F344815B224D1B52B56B8F96872FFD5769D7FE7E67B4196ECF5412EE87383A1FF3CC70660394D54BC39A2D75916FC6F5AD63031EE6FEE03E48A726920347C3EF61FFB79DCC62F82C7FC4F2");

	std::unique_ptr<Botan::DL_Group> group(new Botan::DL_Group(p, q, g)); 

	uint8_t label[20] = "this is a label";

	const int n = 5, k = 3;

	// generate private/public keypair
	timer.start("key generation time");
	std::vector<Botan::TDH2_PrivateKey> privateKeys = Botan::TDH2_PrivateKey::generate_keys(k, n, *rng.get(), *group.get());
	timer.stop();
	
	// test public key encoding/decoding
	Botan::TDH2_PublicKey publicKey(privateKeys[0].subject_public_key());

	std::string password = "password";

	// test private key encoding/decoding
	privateKeys[0] = Botan::TDH2_PrivateKey(privateKeys[0].BER_encode(password), password);

	// encrypt using block encryption
	Botan::TDH2_Encryptor enc(publicKey, *rng.get());
	timer.start("\nheader generation time");
	std::vector<uint8_t> header = enc.begin(label);
	timer.stop();

	timer.start("block encryption time");
	enc.finish(message);
	timer.stop();

	write_to_file("cipher.txt", message);
	
	std::vector<int> ids;
	for(Botan::TDH2_PrivateKey pk : privateKeys) {
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
	
	Botan::TDH2_Decryptor dec(privateKeys[0]);
	timer.start("\nshare combination time");
	dec.begin(dec_shares, header);
	timer.stop();

	timer.start("block 1 decryption time");
	dec.finish(message);
	timer.stop();

	if(filetype == "txt") {
		std::cout << "decrypted message: " << hex2string(message) << "\n";
	} else {
		std::string output_name("decrypted.");
		output_name.append(filetype);
		write_to_file(output_name, message);
	}
}

int main(int argc, char* argv[]) {
	std::unique_ptr<Botan::RandomNumberGenerator> rng(new Botan::AutoSeeded_RNG);
	std::vector<std::string> cmd;
	bool running = true;

	if(argc > 1) {
		cmd = std::vector<std::string>(argv + 1, argv + argc);
		running = false;
	} 

	do {
		if(cmd.size() > 0) {
			if(cmd[0] == "-g" || cmd[0] == "gen") {
				if(cmd.size() != 4) {
					std::cout << "ERROR: Wrong argument count!\n";
				} else {
					uint8_t n = stoi(cmd[2]);
					uint8_t k = stoi(cmd[1]);

					std::cout << "Generating tdh2 keys for (" << (int)k << "," << (int)n << ") cryptosystem..." << std::endl;
					genKeys(k, n, cmd[3]);
				}
			} else if (cmd[0] == "-l" || cmd[0] == "load") {
				if(cmd.size() == 2) {
					load_key(cmd[1]);
				} else {
					std::cout << "ERROR: Wrong argument count!\n";
				}
			} else if (cmd[0] == "-e" || cmd[0] == "enc") {
				if(cmd.size() == 3) {
					if(public_key_loaded) {
						Timer timer;
						timer.start();
						Botan::TDH2_Encryptor enc(public_key, *rng.get());
						std::vector<uint8_t> lbl(cmd[2].data(), cmd[2].data() + 18);
						Botan::secure_vector<uint8_t> msg;
						read_file(cmd[1], msg);
						std::vector<uint8_t> header = enc.begin(lbl.data());
						enc.finish(msg);
						write_to_file(cmd[1], msg);
						write_to_file(cmd[1].append("_header"), msg);
						std::cout << "Encryption finished in " << timer.getSecondsElapsed() << " seconds\n";
					} else if (private_key_loaded) {
						Botan::TDH2_Encryptor enc(private_key, *rng.get());
						std::vector<uint8_t> lbl(cmd[2].data(), cmd[2].data() + 18);
						enc.begin(lbl.data());
					} else {
						std::cout << "ERROR: No key loaded\n";
					}
				} else {
					std::cout << "ERROR: Wrong argument count!\n";
				}
				
			} else if (cmd[0] == "-s" || cmd[0] == "crsh") {
				if(!private_key_loaded) 
					std::cout << "ERROR: No private key loaded!\n";
				else if(cmd.size() == 2){
					Botan::secure_vector<uint8_t> header;
					read_file(cmd[1], header, false);
					std::vector<uint8_t> share(private_key.create_share(unlock(header), *rng.get()));
					std::string filename("shares");
					filename.append(std::to_string(private_key.get_id()));
					write_to_file(filename, share, false);
					std::cout << "Created decryption share with id " << private_key.get_id() << "\n";
				} else {
					std::cout << "ERROR: Wrong argument count!\n";
				}
			} else if (cmd[0] == "-h" || cmd[0] == "help") {
				printHelp();
			} else if (cmd[0] == "-b" || cmd[0] == "bmk") {
				if(cmd.size() == 2) {
					benchmark_demo(cmd[1]);
				} else {
					std::cout << "ERROR: Wrong argument count!\n";
				}
			} else if (cmd[0] == "quit") {
				return 0;
			}
		} 

		if(running) {
			std::cout << "<TDH2>: ";
			std::string buf;
			getline(std::cin, buf);
			cmd.clear();
			std::istringstream iss(buf);
			std::copy(std::istream_iterator<std::string>(iss),
				std::istream_iterator<std::string>(),
				std::back_inserter(cmd));
		}
	} while(running);

	return 0;
}