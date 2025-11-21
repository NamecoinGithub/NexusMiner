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
 * This function implements the canonical LLL-TAO block header serialization format
 * as used in the current NexusMiner/LLL-TAO protocol.
 * 
 * Fields are serialized in network byte order (big-endian) in the following sequence:
 * 
 * Layout (matching current TAO::Ledger::Block serialization):
 *   - nVersion      : 4 bytes   (big-endian uint32)
 *   - hashPrevBlock : 128 bytes (uint1024_t)
 *   - hashMerkleRoot: variable  (uint512_t, calculated as data.size() - 216 bytes)
 *   - nChannel      : 4 bytes   (big-endian uint32)
 *   - nHeight       : 4 bytes   (big-endian uint32)
 *   - nBits         : 4 bytes   (big-endian uint32)
 *   - nNonce        : 8 bytes   (big-endian uint64)
 * 
 * Total minimum size: 4 + 128 + 64 + 20 = 216 bytes
 * (The last 20 bytes are: nChannel(4) + nHeight(4) + nBits(4) + nNonce(8))
 * 
 * @param data The network payload containing the serialized block header
 * @return Deserialized LLP::CBlock instance
 * @throws std::runtime_error if the payload is too small or contains invalid data
 */
inline ::LLP::CBlock deserialize_block_header(network::Payload const& data)
{
    // Minimum block header size: nVersion (4) + hashPrevBlock (128) + hashMerkleRoot (64) + trailing (20)
    constexpr std::size_t MIN_SIZE = 216;
    
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
    
    // Helper to read fixed-size byte array (for uint1024_t and uint512_t)
    auto read_bytes = [&](std::size_t n) -> std::vector<std::uint8_t> {
        require(n);
        std::vector<std::uint8_t> bytes(data.begin() + offset, data.begin() + offset + n);
        offset += n;
        return bytes;
    };
    
    ::LLP::CBlock block;
    
    // Deserialize fields in exact LLL-TAO order:
    // 1. nVersion (4 bytes, big-endian)
    block.nVersion = read_u32();
    
    // 2. hashPrevBlock (128 bytes for uint1024_t)
    block.hashPrevBlock.SetBytes(read_bytes(128));
    
    // 3. hashMerkleRoot (variable size for uint512_t - from current position to last 20 bytes)
    //    The last 20 bytes are reserved for nChannel, nHeight, nBits, nNonce
    //    Ensure we don't underflow when calculating merkle_root_size
    if (data.size() < offset + 20) {
        throw std::runtime_error(
            "Block deserialization failed: insufficient bytes for merkle root and trailing fields");
    }
    std::size_t merkle_root_size = data.size() - offset - 20;
    if (merkle_root_size < 64) {
        throw std::runtime_error(
            "Block deserialization failed: merkle root size " + 
            std::to_string(merkle_root_size) + " is less than minimum 64 bytes");
    }
    block.hashMerkleRoot.SetBytes(read_bytes(merkle_root_size));
    
    // Now read the last 20 bytes (trailing fields)
    // 4. nChannel (4 bytes, big-endian)
    block.nChannel = read_u32();
    
    // 5. nHeight (4 bytes, big-endian)
    block.nHeight = read_u32();
    
    // 6. nBits (4 bytes, big-endian)
    block.nBits = read_u32();
    
    // 7. nNonce (8 bytes, big-endian)
    block.nNonce = read_u64();
    
    return block;
}

} // namespace llp_utils
} // namespace nexusminer

#endif // NEXUSMINER_LLP_BLOCK_UTILS_HPP
