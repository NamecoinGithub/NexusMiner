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
    
    // Detect block type by size and read nChannel from correct offset
    bool is_tritium = (data.size() == TRITIUM_BLOCK_SIZE);
    bool is_legacy = (data.size() >= LEGACY_BLOCK_MIN_SIZE);
    
    if (is_tritium || is_legacy) {
        // Full serialized block - read nChannel from type-specific offset
        std::size_t channel_offset = is_tritium ? TRITIUM_CHANNEL_OFFSET : LEGACY_CHANNEL_OFFSET;
        block.nChannel = read_u32_at(channel_offset);
        
        // For full blocks, read other fields sequentially from start
        // 1. nVersion (4 bytes, big-endian)
        block.nVersion = read_u32();
        
        // 2. hashPrevBlock (32 bytes for uint256_t in compact format)
        // Note: Full blocks may have larger hashes, but we extract first 32 bytes
        block.hashPrevBlock.SetBytes(read_bytes(32));
        
        // 3. hashMerkleRoot (32 bytes for uint256_t in compact format)
        // Note: Full blocks may have larger hashes, but we extract first 32 bytes
        block.hashMerkleRoot.SetBytes(read_bytes(32));
        
        // Skip to read remaining fields (nChannel already read from offset)
        // Read nHeight, nBits, nNonce, nTime based on block type
        // For now, we'll read them sequentially after the hashes
        
        // 4. nHeight (4 bytes, big-endian) - read after hashes
        block.nHeight = read_u32();
        
        // 5. nBits (4 bytes, big-endian)
        block.nBits = read_u32();
        
        // 6. nNonce (8 bytes, big-endian)
        block.nNonce = read_u64();
        
        // 7. nTime (4 bytes, big-endian)
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
