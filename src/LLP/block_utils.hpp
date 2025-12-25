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
    
    // Tritium-specific field sizes
    constexpr std::size_t TRITIUM_NONCE_SIZE = 7;   // 7 bytes for Tritium nNonce
    constexpr std::size_t TRITIUM_TIME_SIZE = 1;    // 1 byte for Tritium nTime
    
    // Detect block type by size (check Tritium first as it's more specific)
    bool is_tritium = (data.size() == TRITIUM_BLOCK_SIZE);
    bool is_legacy = (!is_tritium && data.size() >= LEGACY_BLOCK_MIN_SIZE);
    
    if (is_tritium) {
        // Tritium block (216 bytes) with nChannel at offset 211
        // Structure: nVersion(4) + hashPrevBlock(128) + hashMerkleRoot(64) + 
        //            nHeight(4) + nBits(4) + nNonce(7) + nChannel(4) + nTime(1)
        // Total: 4+128+64+4+4+7+4+1 = 216 bytes
        
        // 1. nVersion (4 bytes at offset 0)
        block.nVersion = read_u32();
        
        // 2. hashPrevBlock - read FULL 128-byte hash (uint1024_t)
        block.hashPrevBlock.SetBytes(read_bytes(128));
        
        // 3. hashMerkleRoot - read FULL 64-byte hash (uint512_t)
        block.hashMerkleRoot.SetBytes(read_bytes(64));
        
        // 4. nHeight (4 bytes, calculated offset: 4+128+64=196)
        block.nHeight = read_u32();
        
        // 5. nBits (4 bytes, calculated offset: 196+4=200)
        block.nBits = read_u32();
        
        // 6. nNonce (7 bytes, calculated offset: 200+4=204)
        // Tritium uses 7-byte nNonce instead of standard 8 bytes
        std::uint64_t nonce_bytes = 0;
        for (std::size_t i = 0; i < TRITIUM_NONCE_SIZE; ++i) {
            nonce_bytes = (nonce_bytes << 8) | data[offset++];
        }
        block.nNonce = nonce_bytes;
        
        // 7. nChannel (4 bytes at offset 211)
        block.nChannel = read_u32_at(TRITIUM_CHANNEL_OFFSET);
        offset = TRITIUM_CHANNEL_OFFSET + 4; // Move past nChannel
        
        // 8. nTime (1 byte at offset 215)
        // Tritium uses 1-byte nTime instead of standard 4 bytes
        // Store in uint32 field (will be small value)
        if (offset < data.size()) {
            block.nTime = data[offset];
        } else {
            block.nTime = 0;
        }
        
    } else if (is_legacy) {
        // Legacy block (220+ bytes) with nChannel at offset 196
        // Structure: nVersion(4) + hashPrevBlock(128) + hashMerkleRoot(64) + 
        //            nChannel(4) + nHeight(4) + nBits(4) + nNonce(8) + nTime(4)
        // Total: 4+128+64+4+4+4+8+4 = 220 bytes (minimum)
        
        // 1. nVersion (4 bytes at offset 0)
        block.nVersion = read_u32();
        
        // 2. hashPrevBlock - read FULL 128-byte hash (uint1024_t)
        block.hashPrevBlock.SetBytes(read_bytes(128));
        
        // 3. hashMerkleRoot - read FULL 64-byte hash (uint512_t)
        block.hashMerkleRoot.SetBytes(read_bytes(64));
        
        // 4. nChannel (4 bytes, calculated offset: 4+128+64=196)
        block.nChannel = read_u32_at(LEGACY_CHANNEL_OFFSET);
        offset = LEGACY_CHANNEL_OFFSET + 4;
        
        // 5. nHeight (4 bytes, calculated offset: 196+4=200)
        block.nHeight = read_u32();
        
        // 6. nBits (4 bytes, calculated offset: 200+4=204)
        block.nBits = read_u32();
        
        // 7. nNonce (8 bytes, calculated offset: 204+4=208)
        block.nNonce = read_u64();
        
        // 8. nTime (4 bytes, calculated offset: 208+8=216)
        block.nTime = read_u32();
        
    } else {
        // Compact block header (92 bytes) - sequential format (legacy pool format)
        // Read 32-byte hashes and expand them to full size by zero-padding
        
        // 1. nVersion (4 bytes, big-endian)
        block.nVersion = read_u32();
        
        // 2. hashPrevBlock (32 bytes) - expand to uint1024_t (128 bytes)
        auto prev_bytes = read_bytes(32);
        // Pad to 128 bytes (zero-fill the rest)
        prev_bytes.resize(128, 0);
        block.hashPrevBlock.SetBytes(prev_bytes);
        
        // 3. hashMerkleRoot (32 bytes) - expand to uint512_t (64 bytes)
        auto merkle_bytes = read_bytes(32);
        // Pad to 64 bytes (zero-fill the rest)
        merkle_bytes.resize(64, 0);
        block.hashMerkleRoot.SetBytes(merkle_bytes);
        
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

/**
 * Serialize a full block for submission to LLL-TAO node.
 * 
 * Serializes the block in the format expected by the node based on block type:
 * - Tritium: 216 bytes with 7-byte nNonce and 1-byte nTime
 * - Legacy: 220 bytes with 8-byte nNonce and 4-byte nTime
 * 
 * @param block The block to serialize
 * @param is_tritium True for Tritium format, false for Legacy format
 * @return Serialized block bytes
 */
inline std::vector<std::uint8_t> serialize_full_block(::LLP::CBlock const& block, bool is_tritium)
{
    std::vector<std::uint8_t> data;
    
    // Helper to write big-endian uint32
    auto write_u32 = [&](std::uint32_t value) {
        data.push_back((value >> 24) & 0xFF);
        data.push_back((value >> 16) & 0xFF);
        data.push_back((value >> 8) & 0xFF);
        data.push_back(value & 0xFF);
    };
    
    // Helper to write big-endian uint64
    auto write_u64 = [&](std::uint64_t value) {
        data.push_back((value >> 56) & 0xFF);
        data.push_back((value >> 48) & 0xFF);
        data.push_back((value >> 40) & 0xFF);
        data.push_back((value >> 32) & 0xFF);
        data.push_back((value >> 24) & 0xFF);
        data.push_back((value >> 16) & 0xFF);
        data.push_back((value >> 8) & 0xFF);
        data.push_back(value & 0xFF);
    };
    
    if (is_tritium) {
        // Tritium block format (216 bytes)
        data.reserve(216);
        
        // 1. nVersion (4 bytes)
        write_u32(block.nVersion);
        
        // 2. hashPrevBlock (128 bytes)
        auto prev_bytes = block.hashPrevBlock.GetBytes();
        data.insert(data.end(), prev_bytes.begin(), prev_bytes.end());
        
        // 3. hashMerkleRoot (64 bytes)
        auto merkle_bytes = block.hashMerkleRoot.GetBytes();
        data.insert(data.end(), merkle_bytes.begin(), merkle_bytes.end());
        
        // 4. nHeight (4 bytes)
        write_u32(block.nHeight);
        
        // 5. nBits (4 bytes)
        write_u32(block.nBits);
        
        // 6. nNonce (7 bytes for Tritium)
        for (int i = 6; i >= 0; --i) {
            data.push_back((block.nNonce >> (i * 8)) & 0xFF);
        }
        
        // 7. nChannel (4 bytes)
        write_u32(block.nChannel);
        
        // 8. nTime (1 byte for Tritium)
        data.push_back(block.nTime & 0xFF);
        
    } else {
        // Legacy block format (220 bytes)
        data.reserve(220);
        
        // 1. nVersion (4 bytes)
        write_u32(block.nVersion);
        
        // 2. hashPrevBlock (128 bytes)
        auto prev_bytes = block.hashPrevBlock.GetBytes();
        data.insert(data.end(), prev_bytes.begin(), prev_bytes.end());
        
        // 3. hashMerkleRoot (64 bytes)
        auto merkle_bytes = block.hashMerkleRoot.GetBytes();
        data.insert(data.end(), merkle_bytes.begin(), merkle_bytes.end());
        
        // 4. nChannel (4 bytes)
        write_u32(block.nChannel);
        
        // 5. nHeight (4 bytes)
        write_u32(block.nHeight);
        
        // 6. nBits (4 bytes)
        write_u32(block.nBits);
        
        // 7. nNonce (8 bytes)
        write_u64(block.nNonce);
        
        // 8. nTime (4 bytes)
        write_u32(block.nTime);
    }
    
    return data;
}

} // namespace llp_utils
} // namespace nexusminer

#endif // NEXUSMINER_LLP_BLOCK_UTILS_HPP
