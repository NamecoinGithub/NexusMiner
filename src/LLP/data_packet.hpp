#ifndef NEXUSMINER_LLP_DATA_PACKET_HPP
#define NEXUSMINER_LLP_DATA_PACKET_HPP

#include <vector>
#include <cstdint>
#include <memory>
#include "network/types.hpp"

namespace nexusminer
{
namespace llp
{

/**
 * @brief Data Packet structure for block submission
 * 
 * This structure wraps the block submission data with a Falcon signature,
 * allowing the blockchain to reduce size by keeping the signature separate
 * from the block template.
 * 
 * Structure:
 * - Merkle Root: 64 bytes (uint512_t serialized as big-endian bytes)
 * - Nonce: 8 bytes (uint64_t serialized as big-endian bytes)
 * - Signature: Variable length (typically ~690 bytes for Falcon-512)
 * 
 * The signature is computed over the concatenation of merkle_root + nonce,
 * providing cryptographic proof that the miner who found this solution
 * is authenticated via their Falcon keypair.
 */
struct DataPacket
{
    /** Merkle root of the block (64 bytes) */
    std::vector<uint8_t> merkle_root;
    
    /** Nonce value (8 bytes) */
    std::uint64_t nonce;
    
    /** Falcon signature over (merkle_root + nonce) */
    std::vector<uint8_t> signature;
    
    /**
     * @brief Default constructor
     */
    DataPacket() : nonce(0) {}
    
    /**
     * @brief Construct Data Packet with data
     * @param merkle_root_bytes The 64-byte merkle root
     * @param nonce_value The nonce value
     * @param sig The Falcon signature
     */
    DataPacket(std::vector<uint8_t> const& merkle_root_bytes,
               std::uint64_t nonce_value,
               std::vector<uint8_t> const& sig)
        : merkle_root(merkle_root_bytes)
        , nonce(nonce_value)
        , signature(sig)
    {}
    
    /**
     * @brief Serialize the Data Packet to bytes for network transmission
     * 
     * Format (all multi-byte integers in big-endian):
     * - merkle_root: 64 bytes
     * - nonce: 8 bytes (big-endian)
     * - signature_length: 2 bytes (big-endian uint16_t)
     * - signature: variable bytes
     * 
     * @return Serialized bytes ready for transmission
     */
    std::vector<uint8_t> serialize() const
    {
        std::vector<uint8_t> data;
        data.reserve(64 + 8 + 2 + signature.size());
        
        // 1. Merkle root (64 bytes)
        if (merkle_root.size() != 64) {
            throw std::runtime_error("Data Packet: merkle_root must be exactly 64 bytes");
        }
        data.insert(data.end(), merkle_root.begin(), merkle_root.end());
        
        // 2. Nonce (8 bytes, big-endian)
        data.push_back(static_cast<uint8_t>(nonce >> 56));
        data.push_back(static_cast<uint8_t>(nonce >> 48));
        data.push_back(static_cast<uint8_t>(nonce >> 40));
        data.push_back(static_cast<uint8_t>(nonce >> 32));
        data.push_back(static_cast<uint8_t>(nonce >> 24));
        data.push_back(static_cast<uint8_t>(nonce >> 16));
        data.push_back(static_cast<uint8_t>(nonce >> 8));
        data.push_back(static_cast<uint8_t>(nonce));
        
        // 3. Signature length (2 bytes, big-endian)
        uint16_t sig_len = static_cast<uint16_t>(signature.size());
        data.push_back(static_cast<uint8_t>(sig_len >> 8));
        data.push_back(static_cast<uint8_t>(sig_len));
        
        // 4. Signature bytes
        data.insert(data.end(), signature.begin(), signature.end());
        
        return data;
    }
    
    /**
     * @brief Deserialize a Data Packet from network bytes
     * 
     * @param data The serialized bytes
     * @return Deserialized DataPacket
     * @throws std::runtime_error if data is invalid or too short
     */
    static DataPacket deserialize(std::vector<uint8_t> const& data)
    {
        // Minimum size: 64 (merkle) + 8 (nonce) + 2 (sig_len) + 0 (sig) = 74 bytes
        if (data.size() < 74) {
            throw std::runtime_error("Data Packet: insufficient data for deserialization");
        }
        
        std::size_t offset = 0;
        DataPacket packet;
        
        // 1. Merkle root (64 bytes)
        packet.merkle_root.assign(data.begin(), data.begin() + 64);
        offset += 64;
        
        // 2. Nonce (8 bytes, big-endian)
        packet.nonce = 
            (static_cast<uint64_t>(data[offset + 0]) << 56) |
            (static_cast<uint64_t>(data[offset + 1]) << 48) |
            (static_cast<uint64_t>(data[offset + 2]) << 40) |
            (static_cast<uint64_t>(data[offset + 3]) << 32) |
            (static_cast<uint64_t>(data[offset + 4]) << 24) |
            (static_cast<uint64_t>(data[offset + 5]) << 16) |
            (static_cast<uint64_t>(data[offset + 6]) << 8) |
            static_cast<uint64_t>(data[offset + 7]);
        offset += 8;
        
        // 3. Signature length (2 bytes, big-endian)
        uint16_t sig_len = 
            (static_cast<uint16_t>(data[offset]) << 8) |
            static_cast<uint16_t>(data[offset + 1]);
        offset += 2;
        
        // 4. Signature bytes
        if (data.size() < offset + sig_len) {
            throw std::runtime_error("Data Packet: insufficient data for signature");
        }
        packet.signature.assign(data.begin() + offset, data.begin() + offset + sig_len);
        
        return packet;
    }
    
    /**
     * @brief Get the total size of the serialized packet
     * @return Total size in bytes
     */
    std::size_t size() const
    {
        return 64 + 8 + 2 + signature.size();
    }
};

} // namespace llp
} // namespace nexusminer

#endif // NEXUSMINER_LLP_DATA_PACKET_HPP
