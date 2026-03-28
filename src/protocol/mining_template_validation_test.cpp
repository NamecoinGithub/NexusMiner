/**
 * @file mining_template_validation_test.cpp
 * @brief Unit tests for Mining Template Height Validation and Worker Protection
 *
 * Validates the implementation of:
 *   - Unified height sanity checking (±100 block threshold)
 *   - Forward jump detection (corrupted height)
 *   - Backward jump detection (reorg/corrupted height)
 *   - Template age monitoring
 *   - Worker stop/recovery mechanism
 *   - Degraded mode handling
 */

#include "protocol/mining_template_interface.hpp"
#include "protocol/height_tracker.hpp"
#include "LLP/block.hpp"
#include "LLP/miner_opcodes.hpp"
#include <iostream>
#include <cstdint>
#include <memory>
#include <chrono>
#include <thread>

// Mock logger for testing
#include "spdlog/spdlog.h"
#include "spdlog/sinks/null_sink.h"
#include <gtest/gtest.h>

using namespace nexusminer::protocol;
namespace MinerLLP = nexusminer::LLP;

// Helper to create a mock block template
std::vector<uint8_t> create_mock_template(uint32_t height, uint32_t nBits = 0x1d00ffff, 
                                           uint8_t channel = 2) {
    // Create a 216-byte Tritium block template matching the actual format
    // Structure: nVersion(4) + hashPrevBlock(128) + hashMerkleRoot(64) + 
    //            nChannel(4) + nHeight(4) + nBits(4) + nNonce(8)
    // Total: 4+128+64+4+4+4+8 = 216 bytes
    std::vector<uint8_t> data(216, 0);
    
    size_t offset = 0;
    
    // Helper to write big-endian uint32
    auto write_u32_be = [&](uint32_t value) {
        data[offset++] = (value >> 24) & 0xFF;
        data[offset++] = (value >> 16) & 0xFF;
        data[offset++] = (value >> 8) & 0xFF;
        data[offset++] = value & 0xFF;
    };
    
    // Helper to write big-endian uint64
    auto write_u64_be = [&](uint64_t value) {
        data[offset++] = (value >> 56) & 0xFF;
        data[offset++] = (value >> 48) & 0xFF;
        data[offset++] = (value >> 40) & 0xFF;
        data[offset++] = (value >> 32) & 0xFF;
        data[offset++] = (value >> 24) & 0xFF;
        data[offset++] = (value >> 16) & 0xFF;
        data[offset++] = (value >> 8) & 0xFF;
        data[offset++] = value & 0xFF;
    };
    
    // 1. nVersion (4 bytes) - big-endian
    write_u32_be(7);  // Version 7
    
    // 2. hashPrevBlock (128 bytes) - uint1024_t
    // Leave as zeros for test
    offset += 128;
    
    // 3. hashMerkleRoot (64 bytes) - uint512_t
    // Set non-zero pattern to pass validation
    for (int i = 0; i < 64; i++) {
        data[offset++] = (i + 1);  // Pattern 1, 2, 3, ...
    }
    
    // 4. nChannel (4 bytes) - big-endian
    write_u32_be(static_cast<uint32_t>(channel));
    
    // 5. nHeight (4 bytes) - big-endian
    write_u32_be(height);
    
    // 6. nBits (4 bytes) - big-endian
    write_u32_be(nBits);
    
    // 7. nNonce (8 bytes) - little-endian (Nexus node writes nNonce as LE)
    // Template nNonce is zero; use little-endian to match the node wire format.
    uint64_t nonce_val = 0;
    data[offset++] = nonce_val & 0xFF;
    data[offset++] = (nonce_val >> 8) & 0xFF;
    data[offset++] = (nonce_val >> 16) & 0xFF;
    data[offset++] = (nonce_val >> 24) & 0xFF;
    data[offset++] = (nonce_val >> 32) & 0xFF;
    data[offset++] = (nonce_val >> 40) & 0xFF;
    data[offset++] = (nonce_val >> 48) & 0xFF;
    data[offset++] = (nonce_val >> 56) & 0xFF;
    
    return data;
}
