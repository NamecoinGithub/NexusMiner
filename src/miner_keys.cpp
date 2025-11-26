#include "miner_keys.hpp"
#include <iomanip>
#include <sstream>
#include <fstream>
#include <iostream>
#include <cstring>
#include "spdlog/spdlog.h"
#include <LLC/flkey.h>

namespace nexusminer
{
namespace keys
{

bool generate_falcon_keypair(std::vector<uint8_t>& pubkey, std::vector<uint8_t>& privkey)
{
    try {
        // Create a new Falcon key using LLC::FLKey
        LLC::FLKey key;
        key.MakeNewKey();
        
        if (!key.IsValid()) {
            spdlog::error("Failed to generate valid Falcon keypair");
            return false;
        }
        
        // Get the public and private keys
        pubkey = key.GetPubKey();
        
        // Convert secure_allocator vector to regular vector
        LLC::CPrivKey securePrivKey = key.GetPrivKey();
        privkey.assign(securePrivKey.begin(), securePrivKey.end());
        
        spdlog::info("Generated Falcon-512 keypair (pubkey: {} bytes, privkey: {} bytes)", 
            pubkey.size(), privkey.size());
        
        return true;
    }
    catch (const std::exception& e) {
        spdlog::error("Failed to generate Falcon keypair: {}", e.what());
        return false;
    }
}

bool falcon_sign(const std::vector<uint8_t>& privkey, 
                 const std::vector<uint8_t>& data, 
                 std::vector<uint8_t>& signature)
{
    try {
        // Create a Falcon key and set the private key
        LLC::FLKey key;
        
        // Convert std::vector to LLC::CPrivKey (secure_allocator vector)
        LLC::CPrivKey securePrivKey(privkey.begin(), privkey.end());
        
        if (!key.SetPrivKey(securePrivKey)) {
            spdlog::error("Failed to set Falcon private key");
            return false;
        }
        
        // Sign the data
        if (!key.Sign(data, signature)) {
            spdlog::error("Failed to sign data with Falcon key");
            return false;
        }
        
        spdlog::debug("Signed {} bytes of data, signature: {} bytes", data.size(), signature.size());
        
        return true;
    }
    catch (const std::exception& e) {
        spdlog::error("Failed to sign with Falcon: {}", e.what());
        return false;
    }
}

bool falcon_verify(const std::vector<uint8_t>& pubkey,
                   const std::vector<uint8_t>& data,
                   const std::vector<uint8_t>& signature)
{
    try {
        // Create a Falcon key and set the public key
        LLC::FLKey key;
        
        if (!key.SetPubKey(pubkey)) {
            spdlog::error("Failed to set Falcon public key");
            return false;
        }
        
        // Verify the signature
        if (!key.Verify(data, signature)) {
            spdlog::debug("Falcon signature verification failed");
            return false;
        }
        
        spdlog::debug("Falcon signature verified successfully");
        
        return true;
    }
    catch (const std::exception& e) {
        spdlog::error("Failed to verify Falcon signature: {}", e.what());
        return false;
    }
}

std::string to_hex(const std::vector<uint8_t>& data)
{
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    
    for (uint8_t byte : data) {
        oss << std::setw(2) << static_cast<unsigned int>(byte);
    }
    
    return oss.str();
}

bool from_hex(const std::string& hex, std::vector<uint8_t>& data)
{
    if (hex.length() % 2 != 0) {
        return false;
    }
    
    data.clear();
    data.reserve(hex.length() / 2);
    
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byte_str = hex.substr(i, 2);
        try {
            uint8_t byte = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
            data.push_back(byte);
        }
        catch (const std::exception&) {
            data.clear();
            return false;
        }
    }
    
    return true;
}

bool create_falcon_config(const std::string& config_filename,
                         bool include_privkey,
                         const std::string& miner_id)
{
    try {
        // Generate Falcon keypair
        std::vector<uint8_t> pubkey, privkey;
        
        spdlog::info("Generating Falcon-512 keypair for config...");
        
        if (!generate_falcon_keypair(pubkey, privkey)) {
            spdlog::error("Failed to generate Falcon keypair");
            return false;
        }
        
        std::string pubkey_hex = to_hex(pubkey);
        std::string privkey_hex = to_hex(privkey);
        
        // Create the JSON configuration
        std::stringstream config_json;
        config_json << "{\n";
        config_json << "    \"version\": 1,\n";
        config_json << "    \"wallet_ip\": \"127.0.0.1\",\n";
        config_json << "    \"port\": 8323,\n";
        config_json << "    \"local_ip\": \"127.0.0.1\",\n";
        config_json << "    \"mining_mode\": \"PRIME\",\n";
        config_json << "    \"connection_retry_interval\": 5,\n";
        config_json << "    \"get_height_interval\": 2,\n";
        config_json << "    \"ping_interval\": 10,\n";
        config_json << "    \"log_level\": 2,\n";
        config_json << "    \"logfile\": \"miner.log\",\n";
        config_json << "    \"print_statistics_interval\": 10,\n";
        config_json << "    \n";
        config_json << "    \"miner_falcon_pubkey\": \"" << pubkey_hex << "\",\n";
        
        if (include_privkey) {
            config_json << "    \"miner_falcon_privkey\": \"" << privkey_hex << "\",\n";
        } else {
            config_json << "    \"miner_falcon_privkey\": \"PUT_PRIVKEY_HEX_HERE\",\n";
        }
        
        config_json << "    \n";
        config_json << "    \"stats_printers\": [\n";
        config_json << "        {\n";
        config_json << "            \"stats_printer\": {\n";
        config_json << "                \"mode\": \"console\"\n";
        config_json << "            }\n";
        config_json << "        }\n";
        config_json << "    ],\n";
        config_json << "    \n";
        config_json << "    \"workers\": [\n";
        config_json << "        {\n";
        config_json << "            \"worker\": {\n";
        config_json << "                \"id\": \"worker0\",\n";
        config_json << "                \"mode\": {\n";
        config_json << "                    \"hardware\": \"cpu\",\n";
        config_json << "                    \"threads\": 4\n";
        config_json << "                }\n";
        config_json << "            }\n";
        config_json << "        }\n";
        config_json << "    ]\n";
        config_json << "}\n";
        
        // Write to file
        std::ofstream config_file(config_filename);
        if (!config_file.is_open()) {
            spdlog::error("Failed to open {} for writing", config_filename);
            return false;
        }
        
        config_file << config_json.str();
        config_file.close();
        
        // Print success message and instructions
        std::cout << "\n=================================================================\n";
        std::cout << "     Falcon Miner Configuration Generated\n";
        std::cout << "=================================================================\n\n";
        
        std::cout << "Created: " << config_filename << "\n";
        std::cout << "Mining Mode: SOLO PRIME\n";
        std::cout << "Target: 127.0.0.1:8323 (localhost LLL-TAO)\n";
        std::cout << "Falcon Authentication: ENABLED\n\n";
        
        if (!include_privkey) {
            std::cout << "*** IMPORTANT: PRIVATE KEY ***\n";
            std::cout << "Your Falcon private key was NOT written to the config file for security.\n";
            std::cout << "Copy it from below and paste it into the config if desired:\n\n";
            std::cout << "PRIVATE KEY (keep secret!):\n";
            std::cout << privkey_hex << "\n\n";
            std::cout << "Edit " << config_filename << " and replace:\n";
            std::cout << "  \"miner_falcon_privkey\": \"PUT_PRIVKEY_HEX_HERE\"\n";
            std::cout << "with:\n";
            std::cout << "  \"miner_falcon_privkey\": \"" << privkey_hex << "\"\n\n";
        } else {
            std::cout << "*** WARNING ***\n";
            std::cout << "The private key has been written to " << config_filename << "\n";
            std::cout << "Protect this file like a wallet - anyone with access can impersonate your miner!\n\n";
        }
        
        std::cout << "PUBLIC KEY (share with node operator):\n";
        std::cout << pubkey_hex << "\n\n";
        
        std::cout << "=================================================================\n";
        std::cout << "Next Steps:\n";
        std::cout << "=================================================================\n\n";
        
        std::cout << "1. Node operator should whitelist your miner by adding to nexus.conf:\n";
        std::cout << "   -minerallowkey=" << pubkey_hex << "\n\n";
        
        std::cout << "2. (Optional) Edit " << config_filename << " to customize:\n";
        std::cout << "   - Worker configuration (CPU/GPU devices, thread count)\n";
        std::cout << "   - Connection settings if not using localhost\n";
        std::cout << "   - Logging settings\n\n";
        
        std::cout << "3. Start mining with:\n";
        std::cout << "   ./NexusMiner -c " << config_filename << "\n\n";
        
        std::cout << "=================================================================\n";
        std::cout << "Configuration generation complete!\n";
        std::cout << "=================================================================\n\n";
        
        return true;
    }
    catch (const std::exception& e) {
        spdlog::error("Failed to create Falcon config: {}", e.what());
        return false;
    }
}

} // namespace keys
} // namespace nexusminer
