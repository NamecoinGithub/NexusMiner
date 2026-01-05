#include <config/miner_config.hpp>
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>
#include "spdlog/spdlog.h"

namespace config {

/** Trim whitespace from string */
static std::string trim(const std::string& str)
{
    size_t first = str.find_first_not_of(" \t\r\n");
    if (first == std::string::npos)
        return "";
    
    size_t last = str.find_last_not_of(" \t\r\n");
    return str.substr(first, (last - first + 1));
}

/** Parse boolean value from string */
static bool parse_bool(const std::string& value)
{
    std::string v = trim(value);
    std::transform(v.begin(), v.end(), v.begin(), ::tolower);
    
    return (v == "1" || v == "true" || v == "yes" || v == "on");
}

bool MinerConfig::Load(const std::string& filename)
{
    m_strConfigFile = filename;
    
    std::ifstream file(filename);
    if (!file.is_open())
    {
        spdlog::warn("Failed to open config file: {}, using defaults", filename);
        return false;
    }
    
    std::string line;
    std::string current_section;
    
    while (std::getline(file, line))
    {
        // Trim whitespace
        line = trim(line);
        
        // Skip empty lines and comments
        if (line.empty() || line[0] == '#' || line[0] == ';')
            continue;
        
        // Check for section header
        if (line[0] == '[' && line[line.length() - 1] == ']')
        {
            current_section = line.substr(1, line.length() - 2);
            continue;
        }
        
        // Parse key=value
        size_t pos = line.find('=');
        if (pos == std::string::npos)
            continue;
        
        std::string key = trim(line.substr(0, pos));
        std::string value = trim(line.substr(pos + 1));
        
        // Remove quotes from value
        if (!value.empty() && value[0] == '"' && value[value.length() - 1] == '"')
            value = value.substr(1, value.length() - 2);
        
        // Parse configuration values
        if (key == "falcon1024")
        {
            m_bFalcon1024 = parse_bool(value);
            spdlog::info("Config: falcon1024 = {}", m_bFalcon1024);
        }
        else if (key == "physicalsigner")
        {
            m_bPhysicalSigner = parse_bool(value);
            spdlog::info("Config: physicalsigner = {}", m_bPhysicalSigner);
        }
    }
    
    file.close();
    
    spdlog::info("Loaded miner config from: {}", filename);
    spdlog::info("  Falcon version: {}", m_bFalcon1024 ? "1024 (default)" : "512");
    spdlog::info("  Physical signer: {}", m_bPhysicalSigner ? "ENABLED" : "DISABLED (default)");
    spdlog::info("  Signature size: {} bytes (CT)", GetSignatureSize());
    spdlog::info("  Public key size: {} bytes", GetPublicKeySize());
    spdlog::info("  Blockchain overhead: {} bytes/block", GetBlockchainOverhead());
    
    return true;
}

bool MinerConfig::Save(const std::string& filename) const
{
    std::ofstream file(filename);
    if (!file.is_open())
    {
        spdlog::error("Failed to open config file for writing: {}", filename);
        return false;
    }
    
    // Write configuration with detailed comments
    file << "#==============================================================================\n";
    file << "# NexusMiner Falcon Configuration\n";
    file << "#==============================================================================\n";
    file << "#\n";
    file << "# This file configures Falcon signature settings for stateless mining.\n";
    file << "#\n";
    file << "# KEY DESIGN: \"Lazy Miner Economics\"\n";
    file << "# - Default to Falcon-1024 (256-bit quantum security, maximum protection)\n";
    file << "# - Default to Physical Falcon OFF (zero blockchain overhead)\n";
    file << "# - 70% of miners use defaults → 0 blockchain bytes, maximum security\n";
    file << "# - Net result: 51% blockchain savings vs all-Falcon-512 approach\n";
    file << "#\n";
    file << "#==============================================================================\n\n";
    
    file << "# Falcon Version Setting\n";
    file << "#\n";
    file << "# falcon1024 = 1  →  Falcon-1024 (DEFAULT)\n";
    file << "#   - 256-bit quantum security (maximum protection)\n";
    file << "#   - 1793-byte public key, 1577-byte signatures (CT)\n";
    file << "#   - Recommended for all miners\n";
    file << "#\n";
    file << "# falcon1024 = 0  →  Falcon-512 (opt-out)\n";
    file << "#   - 128-bit quantum security (still secure)\n";
    file << "#   - 897-byte public key, 809-byte signatures (CT)\n";
    file << "#   - Use only if specifically required\n";
    file << "#\n";
    file << "falcon1024=" << (m_bFalcon1024 ? "1" : "0") << "\n\n";
    
    file << "# Physical Falcon Signature Setting\n";
    file << "#\n";
    file << "# physicalsigner = 0  →  Physical Falcon OFF (DEFAULT)\n";
    file << "#   - Disposable signature only (not stored on blockchain)\n";
    file << "#   - Zero blockchain overhead\n";
    file << "#   - Recommended for most miners (\"lazy miner\" economics)\n";
    file << "#\n";
    file << "# physicalsigner = 1  →  Physical Falcon ON\n";
    file << "#   - Both disposable AND physical signatures\n";
    file << "#   - Physical signature stored on blockchain permanently\n";
    file << "#   - Adds 809 bytes (F-512) or 1577 bytes (F-1024) per block\n";
    file << "#   - Use if you want permanent proof of block authorship\n";
    file << "#\n";
    file << "physicalsigner=" << (m_bPhysicalSigner ? "1" : "0") << "\n\n";
    
    file << "# Current Configuration Summary\n";
    file << "# -----------------------------\n";
    file << "# Falcon Version: " << (m_bFalcon1024 ? "1024" : "512") << "\n";
    file << "# Quantum Security: " << (m_bFalcon1024 ? "256-bit" : "128-bit") << "\n";
    file << "# Signature Size: " << GetSignatureSize() << " bytes (CT)\n";
    file << "# Public Key Size: " << GetPublicKeySize() << " bytes\n";
    file << "# Physical Signer: " << (m_bPhysicalSigner ? "ENABLED" : "DISABLED") << "\n";
    file << "# Blockchain Overhead: " << GetBlockchainOverhead() << " bytes/block\n";
    file << "#\n";
    file << "# Economics (100-year projection):\n";
    if (!m_bPhysicalSigner)
    {
        file << "#   - Your miner: 0 bytes/block → 0 GB total (Disposable not stored)\n";
        file << "#   - Contributing to 51% blockchain savings! ✅\n";
    }
    else
    {
        file << "#   - Your miner: " << GetSignatureSize() << " bytes/block → ";
        file << "~" << (GetSignatureSize() * 52560000 / 1024 / 1024 / 1024) << " GB total (Physical stored)\n";
        file << "#   - Providing permanent proof of block authorship\n";
    }
    file << "\n";
    
    file << "#==============================================================================\n";
    file << "# Falcon Keys Section\n";
    file << "#==============================================================================\n";
    file << "#\n";
    file << "# Use falcon-keygen tool to generate keys:\n";
    file << "#   ./falcon-keygen -o miner.conf              # Falcon-1024 (default)\n";
    file << "#   ./falcon-keygen --falcon512 -o miner.conf  # Falcon-512 (opt-out)\n";
    file << "#\n";
    file << "# [falcon]\n";
    file << "# version = " << (m_bFalcon1024 ? "1024" : "512") << "\n";
    file << "# pubkey = \"hex_encoded_public_key_here\"\n";
    file << "# privkey = \"hex_encoded_private_key_here\"\n";
    file << "\n";
    
    file.close();
    
    spdlog::info("Saved miner config to: {}", filename);
    return true;
}

} // namespace config
