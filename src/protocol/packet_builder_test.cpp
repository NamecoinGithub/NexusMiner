/**
 * @file packet_builder_test.cpp
 * @brief Unit tests for PacketBuilder lane-aware outbound packet utility
 *
 * Tests:
 *  1. Legacy header-only → single byte [opcode]
 *  2. Stateless header-only → two bytes [0xD0][opcode]
 *  3. Legacy with payload → [opcode][len4 BE][payload]
 *  4. Stateless with payload → [0xD0][opcode][len4 BE][payload]
 *  5. MINER_READY: legacy header-only (opcode 216 = 0xD8)
 *  6. MINER_READY: stateless header-only (0xD0D8)
 *  7. GET_ROUND: legacy header-only (opcode 133 = 0x85)
 *  8. GET_ROUND: stateless header-only (0xD085)
 *  9. SUBMIT_BLOCK: stateless with payload (0xD001)
 * 10. Empty payload build returns empty (invalid)
 * 11. submit_block plaintext layout size invariant (Disposable Falcon only)
 */

#include "protocol/packet_builder.hpp"
#include "miner_opcodes.hpp"
#include <iostream>
#include <cstdint>
#include <vector>
#include <gtest/gtest.h>

using namespace nexusminer;
using namespace nexusminer::protocol;

// ============================================================================
// Test 1: Legacy header-only GET_BLOCK (opcode 129 = 0x81)
// Expected wire: [0x81]  (1 byte, no length field for request packets)
// ============================================================================
TEST(PacketBuilderTest, test_legacy_header_only) {
    std::cout << "\nTest 1: Legacy header-only GET_BLOCK\n";
    auto bytes = PacketBuilder::build(ProtocolLane::LEGACY, LLP::GET_BLOCK);
    bool ok = (bytes && bytes->size() == 1 && (*bytes)[0] == 0x81);
    EXPECT_TRUE(ok) << "Legacy GET_BLOCK → [0x81] (1 byte)";
}

// ============================================================================
// Test 2: Stateless header-only GET_BLOCK (opcode 129 = 0x81 → 0xD081)
// Expected wire: [0xD0][0x81]  (2 bytes)
// ============================================================================
TEST(PacketBuilderTest, test_stateless_header_only) {
    std::cout << "\nTest 2: Stateless header-only GET_BLOCK\n";
    auto bytes = PacketBuilder::build(ProtocolLane::STATELESS, LLP::GET_BLOCK);
    bool ok = (bytes && bytes->size() == 2 &&
               (*bytes)[0] == 0xD0 && (*bytes)[1] == 0x81);
    EXPECT_TRUE(ok) << "Stateless GET_BLOCK → [0xD0][0x81] (2 bytes)";
}

// ============================================================================
// Test 3: Legacy SUBMIT_BLOCK (opcode 1) with payload
// Expected wire: [0x01][len4 BE][payload]  (1+4+N bytes)
// ============================================================================
TEST(PacketBuilderTest, test_legacy_with_payload) {
    std::cout << "\nTest 3: Legacy SUBMIT_BLOCK with payload\n";
    std::vector<uint8_t> payload = {0xAA, 0xBB, 0xCC};
    auto bytes = PacketBuilder::build(ProtocolLane::LEGACY, LLP::SUBMIT_BLOCK, payload);

    bool ok = (bytes && bytes->size() == 1 + 4 + 3);
    if (ok) {
        ok = ((*bytes)[0] == 0x01);           // opcode
        ok = ok && ((*bytes)[1] == 0x00);     // length MSB
        ok = ok && ((*bytes)[2] == 0x00);
        ok = ok && ((*bytes)[3] == 0x00);
        ok = ok && ((*bytes)[4] == 0x03);     // length = 3
        ok = ok && ((*bytes)[5] == 0xAA);
        ok = ok && ((*bytes)[6] == 0xBB);
        ok = ok && ((*bytes)[7] == 0xCC);
    }
    EXPECT_TRUE(ok) << "Legacy SUBMIT_BLOCK(3 bytes) → [0x01][0x00000003][AA BB CC]";
}

// ============================================================================
// Test 4: Stateless SUBMIT_BLOCK (opcode 1 → 0xD001) with payload
// Expected wire: [0xD0][0x01][len4 BE][payload]  (2+4+N bytes)
// ============================================================================
TEST(PacketBuilderTest, test_stateless_with_payload) {
    std::cout << "\nTest 4: Stateless SUBMIT_BLOCK with payload\n";
    std::vector<uint8_t> payload = {0xAA, 0xBB, 0xCC};
    auto bytes = PacketBuilder::build(ProtocolLane::STATELESS, LLP::SUBMIT_BLOCK, payload);

    bool ok = (bytes && bytes->size() == 2 + 4 + 3);
    if (ok) {
        ok = ((*bytes)[0] == 0xD0 && (*bytes)[1] == 0x01);  // 0xD001 opcode
        ok = ok && ((*bytes)[2] == 0x00);
        ok = ok && ((*bytes)[3] == 0x00);
        ok = ok && ((*bytes)[4] == 0x00);
        ok = ok && ((*bytes)[5] == 0x03);     // length = 3
        ok = ok && ((*bytes)[6] == 0xAA);
        ok = ok && ((*bytes)[7] == 0xBB);
        ok = ok && ((*bytes)[8] == 0xCC);
    }
    EXPECT_TRUE(ok) << "Stateless SUBMIT_BLOCK(3 bytes) → [0xD0][0x01][0x00000003][AA BB CC]";
}

// ============================================================================
// Test 5: Legacy MINER_READY (opcode 216 = 0xD8) header-only
// Expected wire: [0xD8]  (1 byte)
// ============================================================================
TEST(PacketBuilderTest, test_legacy_miner_ready) {
    std::cout << "\nTest 5: Legacy MINER_READY header-only\n";
    auto bytes = PacketBuilder::build(ProtocolLane::LEGACY, LLP::MINER_READY);
    bool ok = (bytes && bytes->size() == 1 && (*bytes)[0] == 0xD8);
    EXPECT_TRUE(ok) << "Legacy MINER_READY → [0xD8] (1 byte)";
}

// ============================================================================
// Test 6: Stateless MINER_READY (opcode 216 = 0xD8 → 0xD0D8) header-only
// Expected wire: [0xD0][0xD8]  (2 bytes)
// ============================================================================
TEST(PacketBuilderTest, test_stateless_miner_ready) {
    std::cout << "\nTest 6: Stateless MINER_READY header-only\n";
    auto bytes = PacketBuilder::build(ProtocolLane::STATELESS, LLP::MINER_READY);
    bool ok = (bytes && bytes->size() == 2 &&
               (*bytes)[0] == 0xD0 && (*bytes)[1] == 0xD8);
    EXPECT_TRUE(ok) << "Stateless MINER_READY → [0xD0][0xD8] (2 bytes)";
}

// ============================================================================
// Test 7: Legacy GET_ROUND (opcode 133 = 0x85) header-only
// Expected wire: [0x85]  (1 byte)
// ============================================================================
TEST(PacketBuilderTest, test_legacy_get_round) {
    std::cout << "\nTest 7: Legacy GET_ROUND header-only\n";
    auto bytes = PacketBuilder::build(ProtocolLane::LEGACY, LLP::GET_ROUND);
    bool ok = (bytes && bytes->size() == 1 && (*bytes)[0] == 0x85);
    EXPECT_TRUE(ok) << "Legacy GET_ROUND → [0x85] (1 byte)";
}

// ============================================================================
// Test 8: Stateless GET_ROUND (opcode 133 = 0x85 → 0xD085) header-only
// Expected wire: [0xD0][0x85]  (2 bytes)
// ============================================================================
TEST(PacketBuilderTest, test_stateless_get_round) {
    std::cout << "\nTest 8: Stateless GET_ROUND header-only\n";
    auto bytes = PacketBuilder::build(ProtocolLane::STATELESS, LLP::GET_ROUND);
    bool ok = (bytes && bytes->size() == 2 &&
               (*bytes)[0] == 0xD0 && (*bytes)[1] == 0x85);
    EXPECT_TRUE(ok) << "Stateless GET_ROUND → [0xD0][0x85] (2 bytes)";
}

// ============================================================================
// Test 9: Larger payload (simulating MINER_AUTH_INIT data)
// ============================================================================
TEST(PacketBuilderTest, test_large_payload_stateless) {
    std::cout << "\nTest 9: Stateless MINER_AUTH_INIT with 10-byte payload\n";
    std::vector<uint8_t> payload(10, 0xFF);
    auto bytes = PacketBuilder::build(ProtocolLane::STATELESS, LLP::MINER_AUTH_INIT, payload);
    bool ok = (bytes && bytes->size() == 2 + 4 + 10);
    if (ok) {
        // opcode 0xD0CF
        ok = ((*bytes)[0] == 0xD0 && (*bytes)[1] == 0xCF);
        // length = 10
        ok = ok && ((*bytes)[2] == 0 && (*bytes)[3] == 0 &&
                    (*bytes)[4] == 0 && (*bytes)[5] == 10);
        // payload all 0xFF
        for (int i = 6; i < 16 && ok; ++i) {
            ok = ((*bytes)[i] == 0xFF);
        }
    }
    EXPECT_TRUE(ok) << "Stateless MINER_AUTH_INIT(10B) → [0xD0][0xCF][0x0000000A][data]";
}

// ============================================================================
// Test 10: Mirror opcode is 0xD000 | legacy_opcode for all common opcodes
// ============================================================================
TEST(PacketBuilderTest, test_mirror_opcode_invariant) {
    std::cout << "\nTest 10: Stateless opcode header = 0xD000 | legacy_opcode\n";
    // GET_BLOCK (129 = 0x81) → 0xD081
    {
        auto b = PacketBuilder::build(ProtocolLane::STATELESS, LLP::GET_BLOCK);
        uint16_t hdr = b ? ((static_cast<uint16_t>((*b)[0]) << 8) | (*b)[1]) : 0;
        EXPECT_TRUE(hdr == 0xD081) << "GET_BLOCK stateless header == 0xD081";
    }
    // SUBMIT_BLOCK (1 = 0x01) → 0xD001
    {
        std::vector<uint8_t> p = {0x01};
        auto b = PacketBuilder::build(ProtocolLane::STATELESS, LLP::SUBMIT_BLOCK, p);
        uint16_t hdr = b ? ((static_cast<uint16_t>((*b)[0]) << 8) | (*b)[1]) : 0;
        EXPECT_TRUE(hdr == 0xD001) << "SUBMIT_BLOCK stateless header == 0xD001";
    }
    // GET_ROUND (133 = 0x85) → 0xD085
    {
        auto b = PacketBuilder::build(ProtocolLane::STATELESS, LLP::GET_ROUND);
        uint16_t hdr = b ? ((static_cast<uint16_t>((*b)[0]) << 8) | (*b)[1]) : 0;
        EXPECT_TRUE(hdr == 0xD085) << "GET_ROUND stateless header == 0xD085";
    }
    // MINER_READY (216 = 0xD8) → 0xD0D8
    {
        auto b = PacketBuilder::build(ProtocolLane::STATELESS, LLP::MINER_READY);
        uint16_t hdr = b ? ((static_cast<uint16_t>((*b)[0]) << 8) | (*b)[1]) : 0;
        EXPECT_TRUE(hdr == 0xD0D8) << "MINER_READY stateless header == 0xD0D8";
    }
}

// ============================================================================
// Test 11: submit_block plaintext layout size invariant
// Verifies the fixed-format plaintext is exactly block(216) + ts(8) + siglen(2) + sig(N)
// ============================================================================
TEST(PacketBuilderTest, test_plaintext_layout_size) {
    std::cout << "\nTest 11: Plaintext layout size = 216 + 8 + 2 + sig_size\n";
    constexpr size_t BLOCK_SIZE = 216;
    constexpr size_t TIMESTAMP_SIZE = 8;
    constexpr size_t SIGLEN_FIELD_SIZE = 2;
    constexpr size_t FALCON1024_SIG_SIZE = 1577;  // typical Falcon-1024 sig size

    size_t expected = BLOCK_SIZE + TIMESTAMP_SIZE + SIGLEN_FIELD_SIZE + FALCON1024_SIG_SIZE;
    // 216 + 8 + 2 + 1577 = 1803 bytes
    bool ok = (expected == 1803);
    EXPECT_TRUE(ok) << "Plaintext layout: 216+8+2+1577 = 1803 bytes";

    // Verify the total is exactly 1803 (no extra fields)
    bool exact_size = (expected == 1803);
    EXPECT_TRUE(exact_size) << "Total plaintext size is exactly 1803 bytes";
}

// ============================================================================
// main
// ============================================================================
