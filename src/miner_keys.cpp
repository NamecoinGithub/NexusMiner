#include "miner_keys.hpp"
#include <iomanip>
#include <sstream>
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

} // namespace keys
} // namespace nexusminer
