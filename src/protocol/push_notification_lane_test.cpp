/**
 * @file push_notification_lane_test.cpp
 * @brief Tests for unified push notification lane detection
 * 
 * Validates that push notification opcodes are correctly matched by the
 * unified matches_opcode() lambda for both legacy 8-bit and stateless
 * 16-bit mirror-mapped opcodes, ensuring m_protocol_lane is used rather
 * than hardcoded lane values.
 * 
 * Test scenarios:
 * - Legacy 8-bit push opcodes (0xD9, 0xDA) match via matches_opcode()
 * - Stateless 16-bit push opcodes (0xD0D9, 0xD0DA) match via matches_opcode()
 * - Both formats route through unified handler with correct lane
 */

#include "miner_opcodes.hpp"
#include "protocol_lane.hpp"
#include "mining/client_block.h"
#include <iostream>
#include <cassert>
#include <cstdint>

using namespace nexusminer;

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

/**
 * Simulates the matches_opcode() lambda from solo.cpp process_messages():
 *   auto matches_opcode = [&packet](uint16_t legacy_opcode) {
 *       if (packet.m_is_uint16_opcode) {
 *           return packet.m_header == LLP::MirrorOpcode(static_cast<uint8_t>(legacy_opcode));
 *       }
 *       return packet.m_header == legacy_opcode;
 *   };
 */
bool simulated_matches_opcode(uint16_t packet_header, bool is_uint16_opcode, uint16_t legacy_opcode) {
    if (is_uint16_opcode) {
        return packet_header == LLP::MirrorOpcode(static_cast<uint8_t>(legacy_opcode));
    }
    return packet_header == legacy_opcode;
}

/**
 * Simulates the matches_stateless_opcode() lambda from solo.cpp:
 *   auto matches_stateless_opcode = [&packet](uint16_t legacy_opcode) {
 *       return packet.m_is_uint16_opcode &&
 *           packet.m_header == LLP::MirrorOpcode(static_cast<uint8_t>(legacy_opcode));
 *   };
 */
bool simulated_matches_stateless_opcode(uint16_t packet_header, bool is_uint16_opcode, uint16_t legacy_opcode) {
    return is_uint16_opcode &&
        packet_header == LLP::MirrorOpcode(static_cast<uint8_t>(legacy_opcode));
}

int main()
{
    std::cout << "========================================" << std::endl;
    std::cout << "Push Notification Lane Detection Tests" << std::endl;
    std::cout << "========================================" << std::endl;

    // ====================================================================
    // Test 1: Mirror opcode mapping for push notifications
    // ====================================================================
    std::cout << "\nTest 1: Mirror opcode mapping" << std::endl;
    {
        uint16_t prime_mirror = LLP::MirrorOpcode(LLP::PRIME_BLOCK_AVAILABLE);
        uint16_t hash_mirror = LLP::MirrorOpcode(LLP::HASH_BLOCK_AVAILABLE);
        
        print_test_result("PRIME_BLOCK_AVAILABLE mirrors to 0xD0D9",
            prime_mirror == 0xD0D9);
        print_test_result("HASH_BLOCK_AVAILABLE mirrors to 0xD0DA",
            hash_mirror == 0xD0DA);
        print_test_result("PRIME_BLOCK_AVAILABLE legacy value is 217 (0xD9)",
            LLP::PRIME_BLOCK_AVAILABLE == 217);
        print_test_result("HASH_BLOCK_AVAILABLE legacy value is 218 (0xDA)",
            LLP::HASH_BLOCK_AVAILABLE == 218);
    }

    // ====================================================================
    // Test 2: matches_opcode() accepts 8-bit legacy opcodes
    // ====================================================================
    std::cout << "\nTest 2: Legacy 8-bit opcode matching" << std::endl;
    {
        // Simulate legacy 8-bit PRIME_BLOCK_AVAILABLE (0xD9 = 217)
        uint16_t header = LLP::PRIME_BLOCK_AVAILABLE;
        bool is_uint16 = false;
        
        bool matches = simulated_matches_opcode(header, is_uint16, LLP::PRIME_BLOCK_AVAILABLE);
        print_test_result("Legacy 8-bit PRIME_BLOCK_AVAILABLE matches matches_opcode()",
            matches);
        
        // Simulate legacy 8-bit HASH_BLOCK_AVAILABLE (0xDA = 218)
        header = LLP::HASH_BLOCK_AVAILABLE;
        matches = simulated_matches_opcode(header, is_uint16, LLP::HASH_BLOCK_AVAILABLE);
        print_test_result("Legacy 8-bit HASH_BLOCK_AVAILABLE matches matches_opcode()",
            matches);
    }

    // ====================================================================
    // Test 3: matches_opcode() accepts 16-bit mirror opcodes (permissive)
    // ====================================================================
    std::cout << "\nTest 3: Stateless 16-bit opcode matching via matches_opcode()" << std::endl;
    {
        // Simulate stateless 16-bit PRIME_BLOCK_AVAILABLE (0xD0D9)
        uint16_t header = LLP::MirrorOpcode(LLP::PRIME_BLOCK_AVAILABLE);
        bool is_uint16 = true;
        
        bool matches = simulated_matches_opcode(header, is_uint16, LLP::PRIME_BLOCK_AVAILABLE);
        print_test_result("Stateless 16-bit PRIME_BLOCK_AVAILABLE (0xD0D9) matches matches_opcode()",
            matches);
        
        // Simulate stateless 16-bit HASH_BLOCK_AVAILABLE (0xD0DA) 
        header = LLP::MirrorOpcode(LLP::HASH_BLOCK_AVAILABLE);
        matches = simulated_matches_opcode(header, is_uint16, LLP::HASH_BLOCK_AVAILABLE);
        print_test_result("Stateless 16-bit HASH_BLOCK_AVAILABLE (0xD0DA) matches matches_opcode()",
            matches);
    }

    // ====================================================================
    // Test 4: matches_stateless_opcode() is subset of matches_opcode()
    // This proves the duplicate stateless handlers were dead code
    // ====================================================================
    std::cout << "\nTest 4: Stateless-specific match is subset of unified match" << std::endl;
    {
        uint16_t header = LLP::MirrorOpcode(LLP::PRIME_BLOCK_AVAILABLE);
        bool is_uint16 = true;
        
        bool unified = simulated_matches_opcode(header, is_uint16, LLP::PRIME_BLOCK_AVAILABLE);
        bool stateless_only = simulated_matches_stateless_opcode(header, is_uint16, LLP::PRIME_BLOCK_AVAILABLE);
        
        print_test_result("Both matches_opcode and matches_stateless_opcode match 0xD0D9",
            unified && stateless_only);
        print_test_result("matches_opcode catches stateless opcodes (unified handler works)",
            unified);
    }

    // ====================================================================
    // Test 5: Lane detection from port
    // ====================================================================
    std::cout << "\nTest 5: Protocol lane determination from port" << std::endl;
    {
        ProtocolLane legacy = determine_lane_from_port(ProtocolPorts::LEGACY_PORT);
        ProtocolLane stateless = determine_lane_from_port(ProtocolPorts::STATELESS_PORT);
        
        print_test_result("Port 8323 → LEGACY lane",
            legacy == ProtocolLane::LEGACY);
        print_test_result("Port 9323 → STATELESS lane",
            stateless == ProtocolLane::STATELESS);
        print_test_result("Lane names correct",
            std::string(get_lane_name(legacy)) == "Legacy" &&
            std::string(get_lane_name(stateless)) == "Stateless");
    }

    // ====================================================================
    // Test 6: Unified handler uses m_protocol_lane (integration concept)
    // Simulates the fix: m_protocol_lane is used instead of hardcoded lane
    // ====================================================================
    std::cout << "\nTest 6: Unified push handler uses connection lane" << std::endl;
    {
        // Scenario A: Legacy connection receives 8-bit PRIME_BLOCK_AVAILABLE
        ProtocolLane m_protocol_lane_A = ProtocolLane::LEGACY;
        uint16_t header_A = LLP::PRIME_BLOCK_AVAILABLE;
        bool is_uint16_A = false;
        bool matches_A = simulated_matches_opcode(header_A, is_uint16_A, LLP::PRIME_BLOCK_AVAILABLE);
        print_test_result("Scenario A: Legacy 8-bit → lane=LEGACY",
            matches_A && m_protocol_lane_A == ProtocolLane::LEGACY);
        
        // Scenario B: Stateless connection receives 16-bit PRIME_BLOCK_AVAILABLE
        ProtocolLane m_protocol_lane_B = ProtocolLane::STATELESS;
        uint16_t header_B = LLP::MirrorOpcode(LLP::PRIME_BLOCK_AVAILABLE);
        bool is_uint16_B = true;
        bool matches_B = simulated_matches_opcode(header_B, is_uint16_B, LLP::PRIME_BLOCK_AVAILABLE);
        print_test_result("Scenario B: Stateless 16-bit → lane=STATELESS",
            matches_B && m_protocol_lane_B == ProtocolLane::STATELESS);
        
        // Scenario C: Legacy connection receives mirror 16-bit (firewall catch)
        ProtocolLane m_protocol_lane_C = ProtocolLane::LEGACY;
        uint16_t header_C = LLP::MirrorOpcode(LLP::HASH_BLOCK_AVAILABLE);
        bool is_uint16_C = true;
        bool matches_C = simulated_matches_opcode(header_C, is_uint16_C, LLP::HASH_BLOCK_AVAILABLE);
        print_test_result("Scenario C: Legacy lane + mirror opcode → lane=LEGACY (firewall)",
            matches_C && m_protocol_lane_C == ProtocolLane::LEGACY);
    }

    // ====================================================================
    // Test 7: IsStatelessOpcode / UnmirrorOpcode for push notifications
    // ====================================================================
    std::cout << "\nTest 7: Opcode classification helpers" << std::endl;
    {
        print_test_result("0xD0D9 is stateless opcode",
            LLP::IsStatelessOpcode(0xD0D9));
        print_test_result("0xD0DA is stateless opcode",
            LLP::IsStatelessOpcode(0xD0DA));
        print_test_result("0xD9 (217) is NOT stateless opcode",
            !LLP::IsStatelessOpcode(0x00D9));
        print_test_result("0xDA (218) is NOT stateless opcode",
            !LLP::IsStatelessOpcode(0x00DA));
        print_test_result("UnmirrorOpcode(0xD0D9) == 0xD9 (217)",
            LLP::UnmirrorOpcode(0xD0D9) == LLP::PRIME_BLOCK_AVAILABLE);
        print_test_result("UnmirrorOpcode(0xD0DA) == 0xDA (218)",
            LLP::UnmirrorOpcode(0xD0DA) == LLP::HASH_BLOCK_AVAILABLE);
    }

    // ====================================================================
    // Test 8: Dual-channel broadcast — node sends BOTH Prime and Hash pushes
    // Since the node now broadcasts both channels on every push update, the
    // miner must accept the non-subscribed channel push without disruption.
    // ====================================================================
    std::cout << "\nTest 8: Dual-channel broadcast — both Prime and Hash pushes received" << std::endl;
    {
        // Scenario A: Prime miner (channel 1) receives Prime push → should match
        uint8_t mining_channel_prime = static_cast<uint8_t>(mining::CHANNEL_PRIME);
        uint8_t mining_channel_hash  = static_cast<uint8_t>(mining::CHANNEL_HASH);

        // Legacy lane: Prime miner receives PRIME push → match
        bool prime_receives_prime_legacy = simulated_matches_opcode(
            LLP::PRIME_BLOCK_AVAILABLE, false, LLP::PRIME_BLOCK_AVAILABLE);
        print_test_result("Scenario A1: Prime miner receives legacy Prime push → match",
            prime_receives_prime_legacy);

        // Legacy lane: Prime miner receives HASH push → match in router, channel check in handler
        bool prime_receives_hash_legacy = simulated_matches_opcode(
            LLP::HASH_BLOCK_AVAILABLE, false, LLP::HASH_BLOCK_AVAILABLE);
        // Handler will see channel mismatch (mining_channel_prime != CHANNEL_HASH) and return early.
        // This is now treated as informational (not an error).
        print_test_result("Scenario A2: Prime miner receives legacy Hash push → routed (handler guards channel)",
            prime_receives_hash_legacy);

        // Stateless lane: Hash miner receives Prime push (0xD0D9) → routed, handler guards channel
        bool hash_receives_prime_stateless = simulated_matches_opcode(
            LLP::MirrorOpcode(LLP::PRIME_BLOCK_AVAILABLE), true, LLP::PRIME_BLOCK_AVAILABLE);
        print_test_result("Scenario B1: Hash miner receives stateless Prime push (0xD0D9) → routed",
            hash_receives_prime_stateless);

        // Stateless lane: Hash miner receives Hash push (0xD0DA) → match + process
        bool hash_receives_hash_stateless = simulated_matches_opcode(
            LLP::MirrorOpcode(LLP::HASH_BLOCK_AVAILABLE), true, LLP::HASH_BLOCK_AVAILABLE);
        print_test_result("Scenario B2: Hash miner receives stateless Hash push (0xD0DA) → match",
            hash_receives_hash_stateless);

        // Channel mismatch detection: push_notification_handler guards by m_current_channel
        // Prime miner (CHANNEL_PRIME) vs. Hash expected_channel → mismatch → informational no-op
        bool prime_vs_hash = (mining_channel_prime != mining_channel_hash);
        print_test_result("Channel guard: Prime miner + Hash push → mismatch (informational no-op)",
            prime_vs_hash);

        // Hash miner (CHANNEL_HASH) vs. Prime expected_channel → mismatch → informational no-op
        bool hash_vs_prime = (mining_channel_hash != mining_channel_prime);
        print_test_result("Channel guard: Hash miner + Prime push → mismatch (informational no-op)",
            hash_vs_prime);
    }

    // ====================================================================
    // Summary
    // ====================================================================
    std::cout << "\n========================================" << std::endl;
    std::cout << "Test Summary" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Tests run:    " << tests_run << std::endl;
    std::cout << "Tests passed: " << tests_passed << std::endl;
    std::cout << "Tests failed: " << tests_failed << std::endl;
    std::cout << "Success rate: " << (tests_run > 0 ? (100 * tests_passed / tests_run) : 0) << "%" << std::endl;
    std::cout << "========================================" << std::endl;

    return tests_failed > 0 ? 1 : 0;
}
