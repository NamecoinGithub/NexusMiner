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
#include "LLP/block.hpp"
#include "LLP/miner_opcodes.hpp"
#include <iostream>
#include <cassert>
#include <cstdint>
#include <memory>
#include <chrono>
#include <thread>

// Mock logger for testing
#include "spdlog/spdlog.h"
#include "spdlog/sinks/null_sink.h"

using namespace nexusminer::protocol;
namespace MinerLLP = nexusminer::LLP;

// Test statistics
static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

void print_test_result(const char* name, bool passed) {
    tests_run++;
    if (passed) {
        tests_passed++;
        std::cout << "  [PASS] " << name << std::endl;
    } else {
        tests_failed++;
        std::cout << "  [FAIL] " << name << std::endl;
    }
}

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
    
    // 7. nNonce (8 bytes) - big-endian, set to zero for template
    write_u64_be(0);
    
    return data;
}

int main()
{
    // Setup null logger to avoid spam during tests
    auto null_sink = std::make_shared<spdlog::sinks::null_sink_mt>();
    auto logger = std::make_shared<spdlog::logger>("logger", null_sink);
    spdlog::set_default_logger(logger);
    
    std::cout << "========================================" << std::endl;
    std::cout << "Mining Template Validation Tests" << std::endl;
    std::cout << "========================================" << std::endl;

    // ====================================================================
    // Test 1: Normal height progression
    // ====================================================================
    std::cout << "\nTest 1: Normal height progression" << std::endl;
    {
        MiningTemplateInterface tmpl_interface(2, 0); // Channel 2 (hash)
        
        // First template at height 1000000
        auto data1 = create_mock_template(1000000);
        auto result1 = tmpl_interface.read_template(data1, "test_node");
        if (!result1.is_valid) {
            std::cout << "    ERROR: " << result1.error_message << std::endl;
        }
        print_test_result("First template validation (height 1000000)", result1.is_valid);
        
        // Second template advances by 1 block
        auto data2 = create_mock_template(1000001);
        auto result2 = tmpl_interface.read_template(data2, "test_node");
        if (!result2.is_valid) {
            std::cout << "    ERROR: " << result2.error_message << std::endl;
        }
        print_test_result("Forward +1 block (1000000 → 1000001)", result2.is_valid);
        
        // Third template advances by 50 blocks
        auto data3 = create_mock_template(1000051);
        auto result3 = tmpl_interface.read_template(data3, "test_node");
        print_test_result("Forward +50 blocks (1000001 → 1000051)", result3.is_valid);
        
        // Fourth template at boundary (exactly 100 blocks forward)
        auto data4 = create_mock_template(1000151);
        auto result4 = tmpl_interface.read_template(data4, "test_node");
        print_test_result("Forward +100 blocks (1000051 → 1000151)", result4.is_valid);
    }

    // ====================================================================
    // Test 2: Forward jump detection (corrupted height)
    // ====================================================================
    std::cout << "\nTest 2: Forward jump detection (corrupted height)" << std::endl;
    {
        MiningTemplateInterface tmpl_interface(2, 0);
        
        // First template at height 6500000
        auto data1 = create_mock_template(6500000);
        auto result1 = tmpl_interface.read_template(data1, "test_node");
        print_test_result("Baseline template (height 6500000)", result1.is_valid);
        
        // Corrupted jump: 6.5M → 1.9B (exceeds 100 blocks)
        auto data2 = create_mock_template(1900000000);
        auto result2 = tmpl_interface.read_template(data2, "test_node");
        print_test_result("Corrupted forward jump rejected (6.5M → 1.9B)", 
                         !result2.is_valid && !result2.height_valid);
        
        // Jump of exactly 101 blocks should fail
        auto data3 = create_mock_template(6500101);
        auto result3 = tmpl_interface.read_template(data3, "test_node");
        print_test_result("Forward +101 blocks rejected (6500000 → 6500101)", 
                         !result3.is_valid && !result3.height_valid);
    }

    // ====================================================================
    // Test 3: Backward jump detection (reorg)
    // ====================================================================
    std::cout << "\nTest 3: Backward jump detection (reorg)" << std::endl;
    {
        MiningTemplateInterface tmpl_interface(2, 0);
        
        // First template at height 1000100
        auto data1 = create_mock_template(1000100);
        auto result1 = tmpl_interface.read_template(data1, "test_node");
        print_test_result("Baseline template (height 1000100)", result1.is_valid);
        
        // Small reorg: -5 blocks (should be accepted)
        auto data2 = create_mock_template(1000095);
        auto result2 = tmpl_interface.read_template(data2, "test_node");
        print_test_result("Small reorg -5 blocks accepted (1000100 → 1000095)", 
                         result2.is_valid);
        
        // Medium reorg: -50 blocks (should be accepted)
        auto data3 = create_mock_template(1000045);
        auto result3 = tmpl_interface.read_template(data3, "test_node");
        print_test_result("Medium reorg -50 blocks accepted (1000095 → 1000045)", 
                         result3.is_valid);
        
        // Boundary: exactly -100 blocks (should be accepted)
        auto data4 = create_mock_template(999945);
        auto result4 = tmpl_interface.read_template(data4, "test_node");
        print_test_result("Boundary reorg -100 blocks accepted (1000045 → 999945)", 
                         result4.is_valid);
        
        // Deep reorg/corruption: -101 blocks (should be rejected)
        auto data5 = create_mock_template(999844);
        auto result5 = tmpl_interface.read_template(data5, "test_node");
        print_test_result("Deep reorg -101 blocks rejected (999945 → 999844)", 
                         !result5.is_valid && !result5.height_valid);
    }

    // ====================================================================
    // Test 4: Edge cases
    // ====================================================================
    std::cout << "\nTest 4: Edge cases" << std::endl;
    {
        MiningTemplateInterface tmpl_interface(2, 0);
        
        // Template at height 100
        auto data1 = create_mock_template(100);
        auto result1 = tmpl_interface.read_template(data1, "test_node");
        print_test_result("Low height template (height 100)", result1.is_valid);
        
        // Backward to height 0 (within 100 blocks)
        auto data2 = create_mock_template(0);
        auto result2 = tmpl_interface.read_template(data2, "test_node");
        print_test_result("Reorg to height 0 (within threshold)", result2.is_valid);
        
        // Same height (duplicate template)
        auto data3 = create_mock_template(0);
        auto result3 = tmpl_interface.read_template(data3, "test_node");
        print_test_result("Duplicate height accepted (0 → 0)", result3.is_valid);
    }

    // ====================================================================
    // Test 5: Channel validation
    // ====================================================================
    std::cout << "\nTest 5: Channel validation" << std::endl;
    {
        MiningTemplateInterface tmpl_interface(2, 0); // Expect channel 2 (hash)
        
        // Valid channel 2
        auto data1 = create_mock_template(1000000, 0x1d00ffff, 2);
        auto result1 = tmpl_interface.read_template(data1, "test_node");
        print_test_result("Valid channel 2", result1.is_valid);
        
        // Invalid channel 0
        auto data2 = create_mock_template(1000001, 0x1d00ffff, 0);
        auto result2 = tmpl_interface.read_template(data2, "test_node");
        print_test_result("Invalid channel 0 rejected", 
                         !result2.is_valid && !result2.channel_valid);
        
        // Invalid channel 3
        auto data3 = create_mock_template(1000002, 0x1d00ffff, 3);
        auto result3 = tmpl_interface.read_template(data3, "test_node");
        print_test_result("Invalid channel 3 rejected", 
                         !result3.is_valid && !result3.channel_valid);
    }

    // ====================================================================
    // Test 6: nBits validation
    // ====================================================================
    std::cout << "\nTest 6: nBits (difficulty) validation" << std::endl;
    {
        MiningTemplateInterface tmpl_interface(2, 0);
        
        // Valid nBits
        auto data1 = create_mock_template(1000000, 0x1d00ffff, 2);
        auto result1 = tmpl_interface.read_template(data1, "test_node");
        print_test_result("Valid nBits (0x1d00ffff)", result1.is_valid);
        
        // Zero nBits (invalid)
        auto data2 = create_mock_template(1000001, 0, 2);
        auto result2 = tmpl_interface.read_template(data2, "test_node");
        print_test_result("Zero nBits rejected", 
                         !result2.is_valid && !result2.bits_valid);
    }

    // ====================================================================
    // Test 7: Merkle root validation
    // ====================================================================
    std::cout << "\nTest 7: Merkle root validation" << std::endl;
    {
        MiningTemplateInterface tmpl_interface(2, 0);
        
        // All-zero merkle root should be rejected
        std::vector<uint8_t> data = create_mock_template(1000000);
        // Clear merkle root bytes (offset 132-195, which is after version + hashPrevBlock)
        for (int i = 132; i < 196; i++) {
            data[i] = 0x00;
        }
        auto result = tmpl_interface.read_template(data, "test_node");
        print_test_result("All-zero merkle root rejected", 
                         !result.is_valid && !result.merkle_valid);
    }

    // ====================================================================
    // Test 8: Height continuity scenarios
    // ====================================================================
    std::cout << "\nTest 8: Height continuity scenarios" << std::endl;
    {
        MiningTemplateInterface tmpl_interface(2, 0);
        
        // Start at 1000000
        auto data1 = create_mock_template(1000000);
        tmpl_interface.read_template(data1, "test_node");
        
        // Jump backward 50, then forward 100 (to stay within threshold)
        auto data2 = create_mock_template(999950);
        auto result2 = tmpl_interface.read_template(data2, "test_node");
        print_test_result("Backward -50 blocks", result2.is_valid);
        
        auto data3 = create_mock_template(1000050);
        auto result3 = tmpl_interface.read_template(data3, "test_node");
        print_test_result("Then forward +100 blocks (within threshold)", result3.is_valid);
        
        // Try to go back -101 from current (1000050 → 999949)
        auto data4 = create_mock_template(999949);
        auto result4 = tmpl_interface.read_template(data4, "test_node");
        print_test_result("Deep backward -101 rejected", !result4.is_valid);
    }

    // ====================================================================
    // Test 9: Maximum safe values
    // ====================================================================
    std::cout << "\nTest 9: Maximum safe values" << std::endl;
    {
        MiningTemplateInterface tmpl_interface(2, 0);
        
        // Near uint32_t max
        uint32_t max_safe = 0xFFFFFF00; // Leave room for arithmetic
        auto data1 = create_mock_template(max_safe);
        auto result1 = tmpl_interface.read_template(data1, "test_node");
        print_test_result("Near max uint32_t height", result1.is_valid);
        
        // Small increment from max_safe
        auto data2 = create_mock_template(max_safe + 50);
        auto result2 = tmpl_interface.read_template(data2, "test_node");
        print_test_result("Increment from near-max height", result2.is_valid);
    }

    // ====================================================================
    // Test 10: Unified height-based staleness detection (update_height)
    // ====================================================================
    std::cout << "\nTest 10: Unified height-based staleness detection (update_height)" << std::endl;
    {
        MiningTemplateInterface tmpl_interface(2, 0);
        
        // Load a template at height 6594320
        auto data1 = create_mock_template(6594320);
        auto result1 = tmpl_interface.read_template(data1, "test_node");
        print_test_result("Template loaded at height 6594320", result1.is_valid);
        
        // Template height should be queryable
        uint32_t tmpl_height = tmpl_interface.get_template_height();
        print_test_result("get_template_height() returns expected height",
            tmpl_height == 6594320);
        
        // update_height with SAME height should NOT discard template
        bool discarded = tmpl_interface.update_height(6594320);
        print_test_result("Same height does not discard template", !discarded);
        print_test_result("Template still valid after same height update",
            tmpl_interface.has_valid_template());
        
        // update_height with HIGHER height SHOULD discard template
        discarded = tmpl_interface.update_height(6594321);
        print_test_result("Higher height discards template", discarded);
        print_test_result("Template invalid after height advance",
            !tmpl_interface.has_valid_template());
    }

    // ====================================================================
    // Test 11: Channel height delta staleness
    // ====================================================================
    std::cout << "\nTest 11: Channel height delta staleness" << std::endl;
    {
        MiningTemplateInterface tmpl_interface(2, 0);
        
        // Load a template
        auto data1 = create_mock_template(6594320);
        tmpl_interface.read_template(data1, "test_node");
        
        // Set channel height snapshot (simulates what happens on template receipt)
        tmpl_interface.set_template_channel_height_snapshot(4165000);
        
        // Same channel height → not stale
        bool is_stale = tmpl_interface.check_staleness_by_channel_delta(4165000);
        print_test_result("Same channel height is not stale", !is_stale);
        
        // Higher channel height → stale
        is_stale = tmpl_interface.check_staleness_by_channel_delta(4165001);
        print_test_result("Advanced channel height is stale", is_stale);
    }

    // ====================================================================
    // Test 12: Template age does not cause premature timeout
    // ====================================================================
    std::cout << "\nTest 12: Template validity with age < 300s" << std::endl;
    {
        MiningTemplateInterface tmpl_interface(2, 0);
        
        // Load a template
        auto data1 = create_mock_template(6594320);
        tmpl_interface.read_template(data1, "test_node");
        
        // Template should be valid immediately (age ~0s, well under 300s)
        uint64_t age = tmpl_interface.get_template_age();
        print_test_result("Fresh template age is small", age < 5);
        print_test_result("Fresh template is valid", tmpl_interface.has_valid_template());
        
        // Template should NOT be stale at this age (was previously timing out at 120s)
        bool is_stale = tmpl_interface.is_template_stale();
        print_test_result("Fresh template is not stale", !is_stale);
    }

    // ====================================================================
    // Test 13: Channel height staleness via update_channel_height
    // ====================================================================
    std::cout << "\nTest 13: Channel height staleness via update_channel_height" << std::endl;
    {
        MiningTemplateInterface tmpl_interface(2, 0); // Hash channel
        
        // Load a template
        auto data1 = create_mock_template(6594320);
        tmpl_interface.read_template(data1, "test_node");
        
        // Finalize template with channel height (simulates GET_ROUND finalization)
        // set_channel_height sets nChannelHeight = node_height + 1 internally... 
        // Actually: set_channel_height just stores the value directly.
        // Template targets block at nChannelHeight; node is at nChannelHeight - 1.
        tmpl_interface.set_channel_height(4165001); // Template mines block 4165001
        
        // Node at expected height (4165000 = 4165001 - 1) → not stale
        bool discarded = tmpl_interface.update_channel_height(2, 4165000);
        print_test_result("Node at expected channel height: template valid", !discarded);
        print_test_result("Template still valid", tmpl_interface.has_valid_template());
        
        // Node channel advanced (4165001 >= 4165001) → stale!
        discarded = tmpl_interface.update_channel_height(2, 4165001);
        print_test_result("Node channel advanced: template stale", discarded);
        print_test_result("Template invalid after channel advance",
            !tmpl_interface.has_valid_template());
    }

    // ====================================================================
    // Test 14: Wrong channel update does not affect template
    // ====================================================================
    std::cout << "\nTest 14: Wrong channel update does not affect template" << std::endl;
    {
        MiningTemplateInterface tmpl_interface(2, 0); // Hash channel
        
        // Load a template
        auto data1 = create_mock_template(6594320);
        tmpl_interface.read_template(data1, "test_node");
        tmpl_interface.set_channel_height(4165001);
        
        // Update Prime channel (channel 1) — should NOT affect Hash template
        bool discarded = tmpl_interface.update_channel_height(1, 9999999);
        print_test_result("Prime channel update ignored for Hash template", !discarded);
        print_test_result("Template still valid after wrong-channel update",
            tmpl_interface.has_valid_template());
    }

    // ====================================================================
    // Test 15: Stateless opcode compatibility aliases
    // ====================================================================
    std::cout << "\nTest 15: Stateless opcode compatibility aliases" << std::endl;
    {
        print_test_result("BLOCK_DATA mirror is 0xD000",
            MinerLLP::StatelessMining::BLOCK_DATA == 0xD000 &&
            MinerLLP::MirrorOpcode(MinerLLP::BLOCK_DATA) == 0xD000);
        print_test_result("BLOCK_ACCEPTED compat opcode is 0xD002",
            MinerLLP::StatelessMining::BLOCK_ACCEPTED_COMPAT == 0xD002);
        print_test_result("BLOCK_REJECTED compat opcode is 0xD003",
            MinerLLP::StatelessMining::BLOCK_REJECTED_COMPAT == 0xD003);
    }

    // ====================================================================
    // Summary
    // ====================================================================
    std::cout << "\n========================================" << std::endl;
    std::cout << "Test Summary" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Total tests:  " << tests_run << std::endl;
    std::cout << "Passed:       " << tests_passed << std::endl;
    std::cout << "Failed:       " << tests_failed << std::endl;
    std::cout << "Success rate: " << (tests_run > 0 ? (100.0 * tests_passed / tests_run) : 0.0) 
              << "%" << std::endl;
    std::cout << "========================================" << std::endl;

    return (tests_failed == 0) ? 0 : 1;
}
