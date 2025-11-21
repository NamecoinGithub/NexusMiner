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
 * This function implements the Phase-2 stateless mining protocol's compact block header
 * serialization format as used by LLL-TAO.
 * 
 * Fields are serialized in network byte order (big-endian) in the following sequence:
 * 
 * Compact Block header layout (matching LLL-TAO BLOCK_DATA for stateless miner):
 *   - nVersion      : 4 bytes   (big-endian uint32)
 *   - hashPrevBlock : 32 bytes  (uint256_t)
 *   - hashMerkleRoot: 32 bytes  (uint256_t)
 *   - nChannel      : 4 bytes   (big-endian uint32)
 *   - nHeight       : 4 bytes   (big-endian uint32)
 *   - nBits         : 4 bytes   (big-endian uint32)
 *   - nNonce        : 8 bytes   (big-endian uint64)
 *   - nTime         : 4 bytes   (big-endian uint32)
 * 
 * Total size: 4 + 32 + 32 + 4 + 4 + 4 + 8 + 4 = 92 bytes
 * 
 * @param data The network payload containing the serialized block header
 * @return Deserialized LLP::CBlock instance
 * @throws std::runtime_error if the payload is too small or contains invalid data
 */
inline ::LLP::CBlock deserialize_block_header(network::Payload const& data)
{
    // Compact block header size: nVersion (4) + hashPrevBlock (32) + hashMerkleRoot (32) + 
    // nChannel (4) + nHeight (4) + nBits (4) + nNonce (8) + nTime (4)
    constexpr std::size_t MIN_SIZE = 92;
    
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
    
    // Helper to read big-endian uint32
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
    
    // Deserialize fields in Phase-2 compact layout order:
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
    
    return block;
}

} // namespace llp_utils
} // namespace nexusminer

#endif // NEXUSMINER_LLP_BLOCK_UTILS_HPP
