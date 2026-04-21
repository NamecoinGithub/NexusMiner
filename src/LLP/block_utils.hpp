#ifndef NEXUSMINER_LLP_BLOCK_UTILS_HPP
#define NEXUSMINER_LLP_BLOCK_UTILS_HPP

#include "block.hpp"
#include "network/types.hpp"
#include <stdexcept>
#include <cstdint>
#include <cstddef>
#include <type_traits>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include "spdlog/spdlog.h"

namespace nexusminer {
namespace llp_utils {

/**
 * Deserialize a BLOCK_DATA payload from LLL-TAO into an LLP::CBlock structure.
 * 
 * This function handles both Tritium and Legacy block formats:
 * 
 * Tritium blocks (216 bytes):
 *   [0-3]     nVersion (4 bytes)
 *   [4-131]   hashPrevBlock (128 bytes)
 *   [132-195] hashMerkleRoot (64 bytes)
 *   [196-199] nChannel (4 bytes)      ← READ FIRST!
 *   [200-203] nHeight (4 bytes)       ← THEN THIS!
 *   [204-207] nBits (4 bytes)         ← THEN THIS!
 *   [208-215] nNonce (8 bytes)        ← FINALLY THIS!
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
    // Note: Tritium blocks no longer use separate nChannel offset - it's in sequential order
    constexpr std::size_t LEGACY_CHANNEL_OFFSET = 196;
    
    // Sanity check threshold for mainnet block height (conservative lower bound)
    constexpr uint32_t MAINNET_MIN_HEIGHT = 1000000;
    
    // Get logger for detailed deserialization logging (cached to avoid repeated lookups)
    static auto logger = spdlog::get("logger");
    if (!logger) {
        logger = spdlog::default_logger();
    }
    
    if (data.size() < MIN_SIZE) {
        throw std::runtime_error(
            "Block deserialization failed: payload size " + 
            std::to_string(data.size()) + " is less than minimum required " + 
            std::to_string(MIN_SIZE));
    }
    
    // Keep template deserialization diagnostics at debug level so routine
    // submits/templates do not emit misleading "training wheels" noise.
    logger->debug("[Deserialize] Template payload size: {} bytes", data.size());
    
    // Determine block type for logging
    std::string block_type;
    if (data.size() == TRITIUM_BLOCK_SIZE) {
        block_type = "Tritium (216 bytes)";
        logger->debug("[Deserialize] Block type: {} - nChannel serialized at offset 196", block_type);
    } else if (data.size() >= LEGACY_BLOCK_MIN_SIZE) {
        block_type = "Legacy (220+ bytes)";
        logger->debug("[Deserialize] Block type: {} - nChannel at offset {}", block_type, LEGACY_CHANNEL_OFFSET);
    } else {
        block_type = "Compact (92 bytes)";
        logger->debug("[Deserialize] Block type: {} - sequential format", block_type);
    }
    
    // Hex dump of first 32 bytes for debugging
    if (data.size() > 0) {
        std::ostringstream hex_preview;
        hex_preview << std::hex << std::setfill('0');
        size_t preview_len = std::min(data.size(), static_cast<size_t>(32));
        for (size_t i = 0; i < preview_len; ++i) {
            hex_preview << std::setw(2) << static_cast<unsigned int>(data[i]) << " ";
        }
        logger->debug("[Deserialize] First {} bytes (hex): {}", preview_len, hex_preview.str());
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

    // Helper to read little-endian uint64 (used for nNonce — Nexus node writes nNonce as LE)
    auto read_u64_le = [&]() -> std::uint64_t {
        require(8);
        std::uint64_t value =
            static_cast<std::uint64_t>(data[offset]) |
            (static_cast<std::uint64_t>(data[offset + 1]) << 8) |
            (static_cast<std::uint64_t>(data[offset + 2]) << 16) |
            (static_cast<std::uint64_t>(data[offset + 3]) << 24) |
            (static_cast<std::uint64_t>(data[offset + 4]) << 32) |
            (static_cast<std::uint64_t>(data[offset + 5]) << 40) |
            (static_cast<std::uint64_t>(data[offset + 6]) << 48) |
            (static_cast<std::uint64_t>(data[offset + 7]) << 56);
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
    
    // Detect block type by size (check Tritium first as it's more specific)
    bool is_tritium = (data.size() == TRITIUM_BLOCK_SIZE);
    bool is_legacy = (!is_tritium && data.size() >= LEGACY_BLOCK_MIN_SIZE);
    
    if (is_tritium) {
        // Tritium block (216 bytes) - CORRECTED FORMAT
        // Structure: nVersion(4) + hashPrevBlock(128) + hashMerkleRoot(64) + 
        //            nChannel(4) + nHeight(4) + nBits(4) + nNonce(8)
        // Total: 4+128+64+4+4+4+8 = 216 bytes
        
        logger->info("[Deserialize] ═══ TRITIUM BLOCK FORMAT (216 bytes) ═══");
        logger->info("[Deserialize] ✅ CORRECTED: Reading fields in proper order");
        
        // 1. nVersion (4 bytes at offset 0)
        size_t version_offset = offset;
        block.nVersion = read_u32();
        logger->info("[Deserialize] Bytes {}-{} (nVersion): {:02x} {:02x} {:02x} {:02x} -> uint32: {}",
            version_offset, version_offset + 3,
            data[version_offset], data[version_offset + 1], 
            data[version_offset + 2], data[version_offset + 3],
            block.nVersion);
        
        // 2. hashPrevBlock - read FULL 128-byte hash (uint1024_t)
        size_t prev_offset = offset;
        block.hashPrevBlock.SetBytes(read_bytes(128));
        // Log first 16 bytes of hashPrevBlock for verification
        std::ostringstream prev_hex;
        prev_hex << std::hex << std::setfill('0');
        for (size_t i = 0; i < 16 && (prev_offset + i) < data.size(); ++i) {
            prev_hex << std::setw(2) << static_cast<unsigned int>(data[prev_offset + i]) << " ";
        }
        logger->info("[Deserialize] Bytes {}-{} (hashPrevBlock): {} ... (128 bytes total)",
            prev_offset, prev_offset + 127, prev_hex.str());
        
        // 3. hashMerkleRoot - read FULL 64-byte hash (uint512_t)
        size_t merkle_offset = offset;
        block.hashMerkleRoot.SetBytes(read_bytes(64));
        // Log first 16 bytes of hashMerkleRoot for verification
        std::ostringstream merkle_hex;
        merkle_hex << std::hex << std::setfill('0');
        for (size_t i = 0; i < 16 && (merkle_offset + i) < data.size(); ++i) {
            merkle_hex << std::setw(2) << static_cast<unsigned int>(data[merkle_offset + i]) << " ";
        }
        logger->info("[Deserialize] Bytes {}-{} (hashMerkleRoot): {} ... (64 bytes total)",
            merkle_offset, merkle_offset + 63, merkle_hex.str());
        
        // ✅ 4. nChannel (4 bytes, calculated offset: 4+128+64=196) - READ THIS FIRST!
        size_t channel_offset = offset;
        block.nChannel = read_u32();
        logger->info("[Deserialize] Bytes {}-{} (nChannel): {:02x} {:02x} {:02x} {:02x} -> uint32: {}",
            channel_offset, channel_offset + 3,
            data[channel_offset], data[channel_offset + 1],
            data[channel_offset + 2], data[channel_offset + 3],
            block.nChannel);
        
        // Validate nChannel value
        if (block.nChannel != 1 && block.nChannel != 2) {
            logger->warn("[Deserialize] ⚠️  Unexpected nChannel value: {} (expected 1=Prime or 2=Hash)",
                block.nChannel);
        } else {
            logger->info("[Deserialize] ✓ nChannel valid: {} ({})",
                block.nChannel, (block.nChannel == 1) ? "Prime" : "Hash");
        }
        
        // ✅ 5. nHeight (4 bytes, calculated offset: 196+4=200) - THEN READ THIS!
        size_t height_offset = offset;
        block.nHeight = read_u32();
        logger->info("[Deserialize] Bytes {}-{} (nHeight): {:02x} {:02x} {:02x} {:02x} -> uint32: {}",
            height_offset, height_offset + 3,
            data[height_offset], data[height_offset + 1],
            data[height_offset + 2], data[height_offset + 3],
            block.nHeight);
        
        // Sanity check for height (mainnet is past 6M blocks)
        if (block.nHeight < MAINNET_MIN_HEIGHT) {
            logger->warn("[Deserialize] ⚠️  Suspicious nHeight: {} (expected > {} for mainnet)",
                block.nHeight, MAINNET_MIN_HEIGHT);
        }
        
        // ✅ 6. nBits (4 bytes, calculated offset: 200+4=204) - THEN READ THIS!
        size_t bits_offset = offset;
        block.nBits = read_u32();
        logger->info("[Deserialize] Bytes {}-{} (nBits): {:02x} {:02x} {:02x} {:02x} -> uint32: 0x{:08x}",
            bits_offset, bits_offset + 3,
            data[bits_offset], data[bits_offset + 1],
            data[bits_offset + 2], data[bits_offset + 3],
            block.nBits);
        
        // ✅ 7. nNonce (8 bytes, calculated offset: 204+4=208) - little-endian (Nexus node writes nNonce as LE)
        size_t nonce_offset = offset;
        block.nNonce = read_u64_le();
        // Log all 8 bytes of nNonce (already validated by read_u64_le)
        std::ostringstream nonce_hex;
        nonce_hex << std::hex << std::setfill('0');
        for (size_t i = 0; i < 8; ++i) {
            nonce_hex << std::setw(2) << static_cast<unsigned int>(data[nonce_offset + i]) << " ";
        }
        logger->info("[Deserialize] Bytes {}-{} (nNonce): {} -> uint64: 0x{:016x}",
            nonce_offset, nonce_offset + 7, nonce_hex.str(), block.nNonce);
        
        // 8. nTime - Not present in 216-byte Tritium template
        // The 216-byte format ends at nNonce (offset 215)
        // nTime will be set by the miner when creating the block
        block.nTime = 0;
        logger->info("[Deserialize] nTime not in 216-byte Tritium template (set by miner during mining)");
        
    } else if (is_legacy) {
        // Legacy block (220+ bytes) with nChannel at offset 196
        // Structure: nVersion(4) + hashPrevBlock(128) + hashMerkleRoot(64) + 
        //            nChannel(4) + nHeight(4) + nBits(4) + nNonce(8) + nTime(4)
        // Total: 4+128+64+4+4+4+8+4 = 220 bytes (minimum)
        
        logger->info("[Deserialize] ═══ LEGACY BLOCK FORMAT (220+ bytes) ═══");
        
        // 1. nVersion (4 bytes at offset 0)
        size_t version_offset = offset;
        block.nVersion = read_u32();
        logger->info("[Deserialize] Bytes {}-{} (nVersion): {:02x} {:02x} {:02x} {:02x} -> uint32: {}",
            version_offset, version_offset + 3,
            data[version_offset], data[version_offset + 1],
            data[version_offset + 2], data[version_offset + 3],
            block.nVersion);
        
        // 2. hashPrevBlock - read FULL 128-byte hash (uint1024_t)
        size_t prev_offset = offset;
        block.hashPrevBlock.SetBytes(read_bytes(128));
        std::ostringstream prev_hex;
        prev_hex << std::hex << std::setfill('0');
        for (size_t i = 0; i < 16 && (prev_offset + i) < data.size(); ++i) {
            prev_hex << std::setw(2) << static_cast<unsigned int>(data[prev_offset + i]) << " ";
        }
        logger->info("[Deserialize] Bytes {}-{} (hashPrevBlock): {} ... (128 bytes total)",
            prev_offset, prev_offset + 127, prev_hex.str());
        
        // 3. hashMerkleRoot - read FULL 64-byte hash (uint512_t)
        size_t merkle_offset = offset;
        block.hashMerkleRoot.SetBytes(read_bytes(64));
        std::ostringstream merkle_hex;
        merkle_hex << std::hex << std::setfill('0');
        for (size_t i = 0; i < 16 && (merkle_offset + i) < data.size(); ++i) {
            merkle_hex << std::setw(2) << static_cast<unsigned int>(data[merkle_offset + i]) << " ";
        }
        logger->info("[Deserialize] Bytes {}-{} (hashMerkleRoot): {} ... (64 bytes total)",
            merkle_offset, merkle_offset + 63, merkle_hex.str());
        
        // 4. nChannel (4 bytes, calculated offset: 4+128+64=196) - CRITICAL FIELD
        logger->info("[Deserialize] ═══ CRITICAL: nChannel Field Analysis ═══");
        logger->info("[Deserialize] Expected offset for nChannel: {}", LEGACY_CHANNEL_OFFSET);
        logger->info("[Deserialize] Current offset: {}", offset);
        
        // Show the exact bytes at nChannel offset
        if (LEGACY_CHANNEL_OFFSET + 4 <= data.size()) {
            logger->info("[Deserialize] Raw bytes at offset {}-{}: {:02x} {:02x} {:02x} {:02x}",
                LEGACY_CHANNEL_OFFSET, LEGACY_CHANNEL_OFFSET + 3,
                data[LEGACY_CHANNEL_OFFSET], data[LEGACY_CHANNEL_OFFSET + 1],
                data[LEGACY_CHANNEL_OFFSET + 2], data[LEGACY_CHANNEL_OFFSET + 3]);
        }
        
        block.nChannel = read_u32_at(LEGACY_CHANNEL_OFFSET);
        offset = LEGACY_CHANNEL_OFFSET + 4;
        
        // Detailed endianness analysis
        uint32_t big_endian_value = 
            (static_cast<uint32_t>(data[LEGACY_CHANNEL_OFFSET]) << 24) |
            (static_cast<uint32_t>(data[LEGACY_CHANNEL_OFFSET + 1]) << 16) |
            (static_cast<uint32_t>(data[LEGACY_CHANNEL_OFFSET + 2]) << 8) |
            static_cast<uint32_t>(data[LEGACY_CHANNEL_OFFSET + 3]);
        
        uint32_t little_endian_value =
            static_cast<uint32_t>(data[LEGACY_CHANNEL_OFFSET]) |
            (static_cast<uint32_t>(data[LEGACY_CHANNEL_OFFSET + 1]) << 8) |
            (static_cast<uint32_t>(data[LEGACY_CHANNEL_OFFSET + 2]) << 16) |
            (static_cast<uint32_t>(data[LEGACY_CHANNEL_OFFSET + 3]) << 24);
        
        logger->info("[Deserialize] nChannel interpretation:");
        logger->info("[Deserialize]   - Big-endian (used): {}", big_endian_value);
        logger->info("[Deserialize]   - Little-endian: {}", little_endian_value);
        logger->info("[Deserialize]   - Final nChannel value: {}", block.nChannel);
        
        if (block.nChannel != 1 && block.nChannel != 2) {
            logger->error("[Deserialize] ❌ CHANNEL MISMATCH DETECTED!");
            logger->error("[Deserialize]   Expected: 1 (prime) or 2 (hash)");
            logger->error("[Deserialize]   Got: {}", block.nChannel);
            logger->error("[Deserialize]   This indicates a deserialization bug!");
        } else {
            logger->info("[Deserialize] ✓ nChannel value valid: {} ({})",
                block.nChannel, (block.nChannel == 1) ? "prime" : "hash");
        }
        
        // 5. nHeight (4 bytes, calculated offset: 196+4=200)
        size_t height_offset = offset;
        block.nHeight = read_u32();
        logger->info("[Deserialize] Bytes {}-{} (nHeight): {:02x} {:02x} {:02x} {:02x} -> uint32: {}",
            height_offset, height_offset + 3,
            data[height_offset], data[height_offset + 1],
            data[height_offset + 2], data[height_offset + 3],
            block.nHeight);
        
        // 6. nBits (4 bytes, calculated offset: 200+4=204)
        size_t bits_offset = offset;
        block.nBits = read_u32();
        logger->info("[Deserialize] Bytes {}-{} (nBits): {:02x} {:02x} {:02x} {:02x} -> uint32: 0x{:08x}",
            bits_offset, bits_offset + 3,
            data[bits_offset], data[bits_offset + 1],
            data[bits_offset + 2], data[bits_offset + 3],
            block.nBits);
        
        // 7. nNonce (8 bytes, calculated offset: 204+4=208) - little-endian (Nexus node writes nNonce as LE)
        size_t nonce_offset = offset;
        block.nNonce = read_u64_le();
        logger->info("[Deserialize] Bytes {}-{} (nNonce): ", nonce_offset, nonce_offset + 7);
        std::ostringstream nonce_hex;
        nonce_hex << std::hex << std::setfill('0');
        for (size_t i = 0; i < 8 && (nonce_offset + i) < data.size(); ++i) {
            nonce_hex << std::setw(2) << static_cast<unsigned int>(data[nonce_offset + i]) << " ";
        }
        logger->info("[Deserialize]   Raw bytes: {} -> uint64: 0x{:016x}", nonce_hex.str(), block.nNonce);
        
        // 8. nTime (4 bytes, calculated offset: 208+8=216)
        size_t time_offset = offset;
        block.nTime = read_u32();
        logger->info("[Deserialize] Bytes {}-{} (nTime): {:02x} {:02x} {:02x} {:02x} -> uint32: {}",
            time_offset, time_offset + 3,
            data[time_offset], data[time_offset + 1],
            data[time_offset + 2], data[time_offset + 3],
            block.nTime);
        
    } else {
        // Compact block header (92 bytes) - sequential format (legacy pool format)
        // Read 32-byte hashes and expand them to full size by zero-padding
        
        logger->info("[Deserialize] ═══ COMPACT BLOCK FORMAT (92 bytes) ═══");
        
        // 1. nVersion (4 bytes, big-endian)
        size_t version_offset = offset;
        block.nVersion = read_u32();
        logger->info("[Deserialize] Bytes {}-{} (nVersion): {:02x} {:02x} {:02x} {:02x} -> uint32: {}",
            version_offset, version_offset + 3,
            data[version_offset], data[version_offset + 1],
            data[version_offset + 2], data[version_offset + 3],
            block.nVersion);
        
        // 2. hashPrevBlock (32 bytes) - expand to uint1024_t (128 bytes)
        size_t prev_offset = offset;
        auto prev_bytes = read_bytes(32);
        std::ostringstream prev_hex;
        prev_hex << std::hex << std::setfill('0');
        for (size_t i = 0; i < 16; ++i) {
            prev_hex << std::setw(2) << static_cast<unsigned int>(prev_bytes[i]) << " ";
        }
        logger->info("[Deserialize] Bytes {}-{} (hashPrevBlock): {} ... (32 bytes, padded to 128)",
            prev_offset, prev_offset + 31, prev_hex.str());
        // Pad to 128 bytes (zero-fill the rest)
        prev_bytes.resize(128, 0);
        block.hashPrevBlock.SetBytes(prev_bytes);
        
        // 3. hashMerkleRoot (32 bytes) - expand to uint512_t (64 bytes)
        size_t merkle_offset = offset;
        auto merkle_bytes = read_bytes(32);
        std::ostringstream merkle_hex;
        merkle_hex << std::hex << std::setfill('0');
        for (size_t i = 0; i < 16; ++i) {
            merkle_hex << std::setw(2) << static_cast<unsigned int>(merkle_bytes[i]) << " ";
        }
        logger->info("[Deserialize] Bytes {}-{} (hashMerkleRoot): {} ... (32 bytes, padded to 64)",
            merkle_offset, merkle_offset + 31, merkle_hex.str());
        // Pad to 64 bytes (zero-fill the rest)
        merkle_bytes.resize(64, 0);
        block.hashMerkleRoot.SetBytes(merkle_bytes);
        
        // 4. nChannel (4 bytes, big-endian) - CRITICAL FIELD
        size_t channel_offset = offset;
        logger->info("[Deserialize] ═══ CRITICAL: nChannel Field (Compact Format) ═══");
        logger->info("[Deserialize] nChannel at offset: {}", channel_offset);
        logger->info("[Deserialize] Raw bytes at offset {}-{}: {:02x} {:02x} {:02x} {:02x}",
            channel_offset, channel_offset + 3,
            data[channel_offset], data[channel_offset + 1],
            data[channel_offset + 2], data[channel_offset + 3]);
        
        block.nChannel = read_u32();
        
        // Detailed endianness analysis
        uint32_t big_endian_value = 
            (static_cast<uint32_t>(data[channel_offset]) << 24) |
            (static_cast<uint32_t>(data[channel_offset + 1]) << 16) |
            (static_cast<uint32_t>(data[channel_offset + 2]) << 8) |
            static_cast<uint32_t>(data[channel_offset + 3]);
        
        uint32_t little_endian_value =
            static_cast<uint32_t>(data[channel_offset]) |
            (static_cast<uint32_t>(data[channel_offset + 1]) << 8) |
            (static_cast<uint32_t>(data[channel_offset + 2]) << 16) |
            (static_cast<uint32_t>(data[channel_offset + 3]) << 24);
        
        logger->info("[Deserialize] nChannel interpretation:");
        logger->info("[Deserialize]   - Big-endian (used): {}", big_endian_value);
        logger->info("[Deserialize]   - Little-endian: {}", little_endian_value);
        logger->info("[Deserialize]   - Final nChannel value: {}", block.nChannel);
        
        if (block.nChannel != 1 && block.nChannel != 2) {
            logger->error("[Deserialize] ❌ CHANNEL MISMATCH DETECTED!");
            logger->error("[Deserialize]   Expected: 1 (prime) or 2 (hash)");
            logger->error("[Deserialize]   Got: {}", block.nChannel);
        } else {
            logger->info("[Deserialize] ✓ nChannel value valid: {} ({})",
                block.nChannel, (block.nChannel == 1) ? "prime" : "hash");
        }
        
        // 5. nHeight (4 bytes, big-endian)
        size_t height_offset = offset;
        block.nHeight = read_u32();
        logger->info("[Deserialize] Bytes {}-{} (nHeight): {:02x} {:02x} {:02x} {:02x} -> uint32: {}",
            height_offset, height_offset + 3,
            data[height_offset], data[height_offset + 1],
            data[height_offset + 2], data[height_offset + 3],
            block.nHeight);
        
        // 6. nBits (4 bytes, big-endian)
        size_t bits_offset = offset;
        block.nBits = read_u32();
        logger->info("[Deserialize] Bytes {}-{} (nBits): {:02x} {:02x} {:02x} {:02x} -> uint32: 0x{:08x}",
            bits_offset, bits_offset + 3,
            data[bits_offset], data[bits_offset + 1],
            data[bits_offset + 2], data[bits_offset + 3],
            block.nBits);
        
        // 7. nNonce (8 bytes, little-endian — Nexus node writes nNonce as LE)
        size_t nonce_offset = offset;
        block.nNonce = read_u64_le();
        std::ostringstream nonce_hex;
        nonce_hex << std::hex << std::setfill('0');
        for (size_t i = 0; i < 8 && (nonce_offset + i) < data.size(); ++i) {
            nonce_hex << std::setw(2) << static_cast<unsigned int>(data[nonce_offset + i]) << " ";
        }
        logger->info("[Deserialize] Bytes {}-{} (nNonce): {} -> uint64: 0x{:016x}",
            nonce_offset, nonce_offset + 7, nonce_hex.str(), block.nNonce);
        
        // 8. nTime (4 bytes, big-endian)
        size_t time_offset = offset;
        block.nTime = read_u32();
        logger->info("[Deserialize] Bytes {}-{} (nTime): {:02x} {:02x} {:02x} {:02x} -> uint32: {}",
            time_offset, time_offset + 3,
            data[time_offset], data[time_offset + 1],
            data[time_offset + 2], data[time_offset + 3],
            block.nTime);
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // DESERIALIZATION COMPLETE - Summary
    // ═══════════════════════════════════════════════════════════════════════
    logger->debug("[Deserialize] Block summary: nVersion={}", block.nVersion);
    logger->debug("[Deserialize] Block summary: nChannel={} ({})", block.nChannel,
        (block.nChannel == 1) ? "Prime" : (block.nChannel == 2) ? "Hash" : "INVALID");
    logger->debug("[Deserialize] Block summary: nHeight={}", block.nHeight);
    logger->debug("[Deserialize] Block summary: nBits=0x{:08x}", block.nBits);
    logger->debug("[Deserialize] Block summary: nNonce=0x{:016x}", block.nNonce);
    logger->debug("[Deserialize] Block summary: nTime={}", block.nTime);
    
    return block;
}

/**
 * Serialize a submit block in the canonical node-compatible layout.
 * 
 * This intentionally does NOT reuse the inbound BLOCK_DATA/template encoding.
 * Templates arrive in explicit big-endian field order, but submit payloads must
 * match the node-side CBlock serialization contract:
 * - uint32 scalars: little-endian
 * - base_uint hashes: raw serialized limbs (matches base_uint::Serialize())
 * - nNonce: little-endian
 * - Tritium submit body ends at nNonce (216 bytes)
 * - Legacy submit body includes nTime (220 bytes)
 * 
 * @param block The block to serialize
 * @param is_tritium True for Tritium format, false for Legacy format
 * @return Serialized block bytes
 */
inline std::vector<std::uint8_t> serialize_submit_block(::LLP::CBlock const& block, bool is_tritium)
{
    static_assert(std::is_standard_layout<::LLP::CBlock>::value,
                  "CBlock must remain standard-layout for offset-based submit serialization");
    static_assert(offsetof(::LLP::CBlock, nChannel) == 196, "Unexpected nChannel offset");
    static_assert(offsetof(::LLP::CBlock, nHeight) == 200, "Unexpected nHeight offset");
    static_assert(offsetof(::LLP::CBlock, nBits) == 204, "Unexpected nBits offset");
    static_assert(offsetof(::LLP::CBlock, nNonce) == 208, "Unexpected nNonce offset");
    static_assert(offsetof(::LLP::CBlock, nTime) == 216, "Unexpected nTime offset");

    std::vector<std::uint8_t> data;

    auto write_u32_le = [&](std::uint32_t value) {
        data.push_back(static_cast<std::uint8_t>(value & 0xFF));
        data.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFF));
        data.push_back(static_cast<std::uint8_t>((value >> 16) & 0xFF));
        data.push_back(static_cast<std::uint8_t>((value >> 24) & 0xFF));
    };

    auto append_serialized_bytes = [&](const auto& value) {
        const auto* begin = value.begin();
        const auto* end = value.end();
        data.insert(data.end(), begin, end);
    };

    auto write_u64_le = [&](std::uint64_t value) {
        data.push_back(static_cast<std::uint8_t>(value & 0xFF));
        data.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFF));
        data.push_back(static_cast<std::uint8_t>((value >> 16) & 0xFF));
        data.push_back(static_cast<std::uint8_t>((value >> 24) & 0xFF));
        data.push_back(static_cast<std::uint8_t>((value >> 32) & 0xFF));
        data.push_back(static_cast<std::uint8_t>((value >> 40) & 0xFF));
        data.push_back(static_cast<std::uint8_t>((value >> 48) & 0xFF));
        data.push_back(static_cast<std::uint8_t>((value >> 56) & 0xFF));
    };

    if (is_tritium) {
        data.reserve(216);

        write_u32_le(block.nVersion);
        append_serialized_bytes(block.hashPrevBlock);
        append_serialized_bytes(block.hashMerkleRoot);
        write_u32_le(block.nChannel);
        write_u32_le(block.nHeight);
        write_u32_le(block.nBits);
        write_u64_le(block.nNonce);
    } else {
        data.reserve(220);

        write_u32_le(block.nVersion);
        append_serialized_bytes(block.hashPrevBlock);
        append_serialized_bytes(block.hashMerkleRoot);
        write_u32_le(block.nChannel);
        write_u32_le(block.nHeight);
        write_u32_le(block.nBits);
        write_u64_le(block.nNonce);
        write_u32_le(block.nTime);
    }

    return data;
}

inline std::vector<std::uint8_t> serialize_full_block(::LLP::CBlock const& block, bool is_tritium)
{
    return serialize_submit_block(block, is_tritium);
}

} // namespace llp_utils
} // namespace nexusminer

#endif // NEXUSMINER_LLP_BLOCK_UTILS_HPP
