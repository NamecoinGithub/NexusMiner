#ifndef NEXUSMINER_LLP_BLOCK_UTILS_HPP
#define NEXUSMINER_LLP_BLOCK_UTILS_HPP

#include "block.hpp"
#include "network/types.hpp"
#include <stdexcept>
#include <cstdint>
#include <algorithm>

namespace nexusminer {
namespace llp_utils {

/**
 * Deserialize a BLOCK_DATA payload from LLL-TAO into an LLP::CBlock structure.
 * 
 * This function handles both Tritium and Legacy block formats:
 * 
 * Tritium blocks (216 bytes):
 *   - Full serialized block with nChannel at offset 211
 *   - Used by modern LLL-TAO nodes
 * 
 * Legacy blocks (220+ bytes):
 *   - Full serialized block with nChannel at offset 196
 *   - Used by older block formats
 * 
 * Compact block header (92 bytes):
 *   - Phase-2 stateless mining protocol format
 *   - Fields in sequential order (nVersion, hashPrevBlock, hashMerkleRoot, 
 *     nChannel, nHeight, nBits, nNonce, nTime)
 * 
 * The function detects block type by size and reads nChannel from the correct offset.
 * 
 * @param data The network payload containing the serialized block
 * @return Deserialized LLP::CBlock instance
 * @throws std::runtime_error if the payload is too small or contains invalid data
 */
inline ::LLP::CBlock deserialize_block_header(network::Payload const& data)
{
    // Minimum size for any valid block
    constexpr std::size_t MIN_SIZE = 92;
    constexpr std::size_t TRITIUM_BLOCK_SIZE = 216;
    constexpr std::size_t LEGACY_BLOCK_MIN_SIZE = 220;
    constexpr std::size_t TRITIUM_CHANNEL_OFFSET = 211;
    constexpr std::size_t LEGACY_CHANNEL_OFFSET = 196;
    
    if (data.size() < MIN_SIZE) {
        throw std::runtime_error(
            "Block deserialization failed: payload size " + 
            std::to_string(data.size()) + " is less than minimum required " + 
            std::to_string(MIN_SIZE));
    }
    
    std::size_t offset = 0;
    
    // Helper to ensure sufficient bytes remain
    auto require = [&](std::size_t n) {
        if (offset + n > data.size()) {
            throw std::runtime_error(
                "Block deserialization failed: insufficient data at offset " + 
                std::to_string(offset) + " (need " + std::to_string(n) + 
                " bytes, have " + std::to_string(data.size() - offset) + ")");
        }
    };
    
    // Helper to read big-endian uint32 at current offset
    auto read_u32 = [&]() -> std::uint32_t {
        require(4);
        std::uint32_t value = 
            (static_cast<std::uint32_t>(data[offset]) << 24) |
            (static_cast<std::uint32_t>(data[offset + 1]) << 16) |
            (static_cast<std::uint32_t>(data[offset + 2]) << 8) |
            static_cast<std::uint32_t>(data[offset + 3]);
        offset += 4;
        return value;
    };
    
    // Helper to read big-endian uint32 at specific offset (without advancing)
    auto read_u32_at = [&](std::size_t pos) -> std::uint32_t {
        if (pos + 4 > data.size()) {
            throw std::runtime_error(
                "Block deserialization failed: cannot read uint32 at offset " + 
                std::to_string(pos) + " (size: " + std::to_string(data.size()) + ")");
        }
        return (static_cast<std::uint32_t>(data[pos]) << 24) |
               (static_cast<std::uint32_t>(data[pos + 1]) << 16) |
               (static_cast<std::uint32_t>(data[pos + 2]) << 8) |
               static_cast<std::uint32_t>(data[pos + 3]);
    };
    
    // Helper to read big-endian uint64
    auto read_u64 = [&]() -> std::uint64_t {
        require(8);
        std::uint64_t value = 
            (static_cast<std::uint64_t>(data[offset]) << 56) |
            (static_cast<std::uint64_t>(data[offset + 1]) << 48) |
            (static_cast<std::uint64_t>(data[offset + 2]) << 40) |
            (static_cast<std::uint64_t>(data[offset + 3]) << 32) |
            (static_cast<std::uint64_t>(data[offset + 4]) << 24) |
            (static_cast<std::uint64_t>(data[offset + 5]) << 16) |
            (static_cast<std::uint64_t>(data[offset + 6]) << 8) |
            static_cast<std::uint64_t>(data[offset + 7]);
        offset += 8;
        return value;
    };
    
    // Helper to read fixed-size byte array (for hash fields)
    auto read_bytes = [&](std::size_t n) -> std::vector<std::uint8_t> {
        require(n);
        std::vector<std::uint8_t> bytes(data.begin() + offset, data.begin() + offset + n);
        offset += n;
        return bytes;
    };
    
    ::LLP::CBlock block;
    
    // Detect block type by size
    bool is_tritium = (data.size() == TRITIUM_BLOCK_SIZE);
    bool is_legacy = (data.size() >= LEGACY_BLOCK_MIN_SIZE);
    
    if (is_tritium) {
        // Tritium block (216 bytes) with nChannel at offset 211
        // Structure: nVersion(4) + hashPrevBlock(128) + hashMerkleRoot(64) + 
        //            nHeight(4) + nBits(4) + nNonce(7?) + nChannel(4) + nTime(1?)
        
        // 1. nVersion (4 bytes at offset 0)
        block.nVersion = read_u32();
        
        // 2. hashPrevBlock - extract first 32 bytes from 128-byte hash
        block.hashPrevBlock.SetBytes(read_bytes(32));
        offset += (128 - 32); // Skip remaining 96 bytes of full hash
        
        // 3. hashMerkleRoot - extract first 32 bytes from 64-byte hash  
        block.hashMerkleRoot.SetBytes(read_bytes(32));
        offset += (64 - 32); // Skip remaining 32 bytes of full hash
        
        // 4. nHeight (4 bytes at offset 196)
        block.nHeight = read_u32();
        
        // 5. nBits (4 bytes at offset 200)
        block.nBits = read_u32();
        
        // 6. nNonce (7 bytes at offset 204-210)
        // Read as 8 bytes but mask off the extra byte
        std::uint64_t nonce_bytes = 0;
        for (int i = 0; i < 7; ++i) {
            nonce_bytes = (nonce_bytes << 8) | data[offset++];
        }
        block.nNonce = nonce_bytes;
        
        // 7. nChannel (4 bytes at offset 211)
        block.nChannel = read_u32_at(TRITIUM_CHANNEL_OFFSET);
        offset = TRITIUM_CHANNEL_OFFSET + 4; // Move past nChannel
        
        // 8. nTime (1 byte at offset 215)
        block.nTime = data[offset];
        
    } else if (is_legacy) {
        // Legacy block (220+ bytes) with nChannel at offset 196
        // Structure: nVersion(4) + hashPrevBlock(128) + hashMerkleRoot(64) + 
        //            nChannel(4) + nHeight(4) + nBits(4) + nNonce(8) + nTime(4)
        
        // 1. nVersion (4 bytes at offset 0)
        block.nVersion = read_u32();
        
        // 2. hashPrevBlock - extract first 32 bytes from 128-byte hash
        block.hashPrevBlock.SetBytes(read_bytes(32));
        offset += (128 - 32); // Skip remaining 96 bytes
        
        // 3. hashMerkleRoot - extract first 32 bytes from 64-byte hash
        block.hashMerkleRoot.SetBytes(read_bytes(32));
        offset += (64 - 32); // Skip remaining 32 bytes
        
        // 4. nChannel (4 bytes at offset 196)
        block.nChannel = read_u32_at(LEGACY_CHANNEL_OFFSET);
        offset = LEGACY_CHANNEL_OFFSET + 4;
        
        // 5. nHeight (4 bytes at offset 200)
        block.nHeight = read_u32();
        
        // 6. nBits (4 bytes at offset 204)
        block.nBits = read_u32();
        
        // 7. nNonce (8 bytes at offset 208)
        block.nNonce = read_u64();
        
        // 8. nTime (4 bytes at offset 216)
        block.nTime = read_u32();
        
    } else {
        // Compact block header (92 bytes) - sequential format
        // 1. nVersion (4 bytes, big-endian)
        block.nVersion = read_u32();
        
        // 2. hashPrevBlock (32 bytes for uint256_t)
        block.hashPrevBlock.SetBytes(read_bytes(32));
        
        // 3. hashMerkleRoot (32 bytes for uint256_t)
        block.hashMerkleRoot.SetBytes(read_bytes(32));
        
        // 4. nChannel (4 bytes, big-endian)
        block.nChannel = read_u32();
        
        // 5. nHeight (4 bytes, big-endian)
        block.nHeight = read_u32();
        
        // 6. nBits (4 bytes, big-endian)
        block.nBits = read_u32();
        
        // 7. nNonce (8 bytes, big-endian)
        block.nNonce = read_u64();
        
        // 8. nTime (4 bytes, big-endian)
        block.nTime = read_u32();
    }
    
    return block;
}

} // namespace llp_utils
} // namespace nexusminer

#endif // NEXUSMINER_LLP_BLOCK_UTILS_HPP
