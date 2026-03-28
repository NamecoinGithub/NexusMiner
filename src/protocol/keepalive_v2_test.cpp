/**
 * @file keepalive_v2_test.cpp
 * @brief Unit tests for KEEPALIVE v2 miner-side implementation
 *
 * Tests:
 *  1. SessionManager::build_keepalive_packet() produces 8-byte payload (v2 format)
 *  2. SessionManager v2 payload: session_id encoded little-endian in bytes [0..3]
 *  3. SessionManager v2 payload: suffix zeros when set_prevblock_suffix not called
 *  4. SessionManager v2 payload: suffix bytes [4..7] match set_prevblock_suffix()
 *  5. prevblock_suffix extraction: last 4 bytes of 128-byte GetBytes() are bytes[124..127]
 *  6. set_prevblock_suffix zeros: packet correctly sends zero suffix
 *  7. Parsing robustness: non-32 payload lengths rejected by Parse()
 *  8. KeepAliveV2AckFrame: stake_height at bytes [24-27], fork_score at [28-31]
 *  9. KeepAliveV2AckFrame::Parse() decodes session_id as little-endian at [0-3]
 * 10. Accepted keepalive bookkeeping refreshes state and increments keepalive count
 */

#include "protocol/session_manager.hpp"
#include "protocol_lane.hpp"
#include "miner_opcodes.hpp"
#include "LLP/include/colin_ping_protocol.h"
#include <iostream>
#include <cstdint>
#include <vector>
#include <array>
#include <future>
#include <chrono>

#include "spdlog/spdlog.h"
#include "spdlog/sinks/null_sink.h"
#include <gtest/gtest.h>

using namespace nexusminer::protocol;
using namespace nexusminer;

// ============================================================================
// Helpers
// ============================================================================

// Read uint32 little-endian from a byte vector at offset
static uint32_t read_le32(const std::vector<uint8_t>& v, size_t off) {
    return  static_cast<uint32_t>(v[off])           |
           (static_cast<uint32_t>(v[off+1]) << 8)   |
           (static_cast<uint32_t>(v[off+2]) << 16)  |
           (static_cast<uint32_t>(v[off+3]) << 24);
}

// ============================================================================
// Helper: build a SessionManager with a known session_id and lane,
// then return the wire bytes of the keepalive packet.
// ============================================================================
static std::vector<uint8_t> make_keepalive_bytes(
        uint32_t session_id,
        ProtocolLane lane,
        const std::array<uint8_t, 4>* suffix = nullptr)
{
    auto mgr = std::make_shared<SessionManager>(24, nullptr);
    mgr->set_protocol_lane(lane);
    mgr->start_session(session_id);
    if (suffix) {
        mgr->set_prevblock_suffix(*suffix);
    }
    auto bytes = mgr->build_keepalive_packet();
    if (!bytes) return {};
    return *bytes;
}

// ============================================================================
// Test 1: build_keepalive_packet() produces 8-byte payload (v2 format)
// Legacy wire layout: [opcode(1)][length_BE(4)][payload(8)] = 13 bytes total
// ============================================================================
TEST(KeepaliveV2Test, test_keepalive_v2_payload_size_legacy) {
    std::cout << "\nTest 1: Legacy keepalive packet total wire size\n";
    // Legacy: 1-byte opcode + 4-byte BE length + 8-byte payload = 13 bytes
    auto bytes = make_keepalive_bytes(0x00000001, ProtocolLane::LEGACY);
    EXPECT_TRUE(bytes.size() == 13) << "Legacy wire size == 13 (1+4+8)";
}

// ============================================================================
// Test 2: session_id encoded little-endian in payload bytes [0..3]
// For a legacy packet: bytes[0]=opcode, bytes[1..4]=length, bytes[5..8]=session_id LE
// ============================================================================
TEST(KeepaliveV2Test, test_keepalive_v2_session_id_le) {
    std::cout << "\nTest 2: session_id is little-endian in bytes [payload+0..3]\n";
    uint32_t session_id = 0x12345678;
    auto bytes = make_keepalive_bytes(session_id, ProtocolLane::LEGACY);
    if (bytes.size() < 13) {
        EXPECT_TRUE(false) << "Legacy wire size sufficient for check";
        return;
    }
    // payload starts at offset 5 (opcode[0] + length[1..4])
    uint32_t got = read_le32(bytes, 5);
    EXPECT_TRUE(got == 0x12345678) << "session_id LE == 0x12345678";
}

// ============================================================================
// Test 3: suffix is zeros when set_prevblock_suffix not called
// ============================================================================
TEST(KeepaliveV2Test, test_keepalive_v2_suffix_zeros_default) {
    std::cout << "\nTest 3: Default prevblock_suffix is all zeros\n";
    auto bytes = make_keepalive_bytes(0xCAFEBABE, ProtocolLane::LEGACY);
    if (bytes.size() < 13) {
        EXPECT_TRUE(false) << "Packet large enough";
        return;
    }
    // suffix at payload offset [4..7] → wire offset [9..12]
    bool all_zero = (bytes[9] == 0 && bytes[10] == 0 && bytes[11] == 0 && bytes[12] == 0);
    EXPECT_TRUE(all_zero) << "Suffix bytes [9..12] all zero by default";
}

// ============================================================================
// Test 4: set_prevblock_suffix() sets bytes [4..7] of payload correctly
// ============================================================================
TEST(KeepaliveV2Test, test_keepalive_v2_suffix_set) {
    std::cout << "\nTest 4: set_prevblock_suffix() reflected in keepalive packet\n";
    std::array<uint8_t, 4> suffix = { 0x11, 0x22, 0x33, 0x44 };
    auto bytes = make_keepalive_bytes(0x00000001, ProtocolLane::LEGACY, &suffix);
    if (bytes.size() < 13) {
        EXPECT_TRUE(false) << "Packet large enough";
        return;
    }
    // suffix at wire offset [9..12]
    EXPECT_TRUE(bytes[9]  == 0x11) << "Suffix byte[0] == 0x11";
    EXPECT_TRUE(bytes[10] == 0x22) << "Suffix byte[1] == 0x22";
    EXPECT_TRUE(bytes[11] == 0x33) << "Suffix byte[2] == 0x33";
    EXPECT_TRUE(bytes[12] == 0x44) << "Suffix byte[3] == 0x44";
}

// ============================================================================
// Test 5: prevblock_suffix extraction logic — last 4 bytes == bytes[124..127]
// ============================================================================
TEST(KeepaliveV2Test, test_prevblock_suffix_extraction_logic) {
    std::cout << "\nTest 5: prevblock_suffix = bytes[124..127] of 128-byte GetBytes()\n";

    // Simulate a 128-byte GetBytes() with known pattern
    std::vector<uint8_t> hash_bytes(128);
    for (int i = 0; i < 128; ++i) hash_bytes[i] = static_cast<uint8_t>(i);

    std::array<uint8_t, 4> suffix{};
    if (hash_bytes.size() >= 128) {
        suffix = { hash_bytes[124], hash_bytes[125], hash_bytes[126], hash_bytes[127] };
    }

    EXPECT_TRUE(suffix[0] == 124) << "suffix[0] == 124 (0x7C)";
    EXPECT_TRUE(suffix[1] == 125) << "suffix[1] == 125 (0x7D)";
    EXPECT_TRUE(suffix[2] == 126) << "suffix[2] == 126 (0x7E)";
    EXPECT_TRUE(suffix[3] == 127) << "suffix[3] == 127 (0x7F)";
}

// ============================================================================
// Test 6: set_prevblock_suffix with zeros sends zero suffix
// ============================================================================
TEST(KeepaliveV2Test, test_keepalive_v2_suffix_explicit_zeros) {
    std::cout << "\nTest 6: set_prevblock_suffix with zeros sends zero suffix\n";
    std::array<uint8_t, 4> zero_suffix = { 0, 0, 0, 0 };
    auto bytes = make_keepalive_bytes(0x00000001, ProtocolLane::LEGACY, &zero_suffix);
    if (bytes.size() < 13) {
        EXPECT_TRUE(false) << "Packet large enough";
        return;
    }
    bool all_zero = (bytes[9] == 0 && bytes[10] == 0 && bytes[11] == 0 && bytes[12] == 0);
    EXPECT_TRUE(all_zero) << "Explicit zero suffix reflected in wire bytes";
}

// ============================================================================
// Test 7: Parsing robustness — short payload lengths rejected by Parse()
// ============================================================================
TEST(KeepaliveV2Test, test_keepalive_parse_robustness_other_lengths) {
    std::cout << "\nTest 7: Parsing robustness: lengths < 32 rejected by KeepAliveV2AckFrame::Parse()\n";
    using ::LLP::KeepAliveV2AckFrame;

    // All lengths < 32 must be rejected
    std::vector<size_t> bad_lengths = { 0, 1, 4, 28, 31 };
    bool all_rejected = true;
    for (size_t len : bad_lengths) {
        std::vector<uint8_t> payload(len, 0xFF);
        KeepAliveV2AckFrame frame;
        if (frame.Parse(payload)) { all_rejected = false; break; }
    }
    EXPECT_TRUE(all_rejected) << "Lengths < 32 all rejected by Parse()";

    // Confirm 32-byte buffer is accepted
    std::vector<uint8_t> good(32, 0);
    KeepAliveV2AckFrame frame;
    EXPECT_TRUE(frame.Parse(good)) << "32-byte buffer accepted by Parse()";
}

// ============================================================================
// Test 8: KeepAliveV2AckFrame 32-byte layout — stake_height at [24-27],
//          fork_score at [28-31]
// ============================================================================
TEST(KeepaliveV2Test, test_keepalive_v2_ack_frame_layout) {
    std::cout << "\nTest 8: KeepAliveV2AckFrame 32-byte layout\n";
    using ::LLP::KeepAliveV2AckFrame;

    EXPECT_TRUE(KeepAliveV2AckFrame::PAYLOAD_SIZE == 32u) << "PAYLOAD_SIZE == 32";

    std::vector<uint8_t> data(32, 0);
    // stake_height at bytes [24-27] = 0xAABBCCDD (BE)
    data[24] = 0xAA; data[25] = 0xBB; data[26] = 0xCC; data[27] = 0xDD;
    // fork_score at bytes [28-31] = 0x11223344 (BE)
    data[28] = 0x11; data[29] = 0x22; data[30] = 0x33; data[31] = 0x44;

    KeepAliveV2AckFrame ack;
    bool parsed = ack.Parse(data);
    EXPECT_TRUE(parsed) << "Parse() returns true for 32-byte buffer";
    EXPECT_TRUE(ack.stake_height == 0xAABBCCDDu) << "stake_height == 0xAABBCCDD at bytes [24-27]";
    EXPECT_TRUE(ack.fork_score == 0x11223344u) << "fork_score == 0x11223344 at bytes [28-31]";
    EXPECT_TRUE(!ack.Parse(std::vector<uint8_t>(28, 0))) << "Parse() rejects 28-byte buffer";
}

// ============================================================================
// Test 9: KeepAliveV2AckFrame::Parse() decodes session_id as little-endian at [0-3]
// ============================================================================
TEST(KeepaliveV2Test, test_parse_session_id_le) {
    std::cout << "\nTest 9: KeepAliveV2AckFrame::Parse() decodes session_id LE at [0-3]\n";
    using ::LLP::KeepAliveV2AckFrame;

    std::vector<uint8_t> payload(32, 0);
    // session_id = 0x12345678 LE → bytes [0..3] = 78 56 34 12
    payload[0] = 0x78; payload[1] = 0x56; payload[2] = 0x34; payload[3] = 0x12;
    // unified_height = 6000 BE at [8..11]
    payload[8] = 0x00; payload[9] = 0x00; payload[10] = 0x17; payload[11] = 0x70;

    KeepAliveV2AckFrame frame;
    auto result = frame.Parse(payload);
    EXPECT_TRUE(result) << "Parse returns true";
    EXPECT_TRUE(frame.session_id == 0x12345678u) << "session_id == 0x12345678";
    EXPECT_TRUE(frame.unified_height == 6000u) << "unified_height == 6000";
}

// ============================================================================
// Test 10: set_protocol_lane returns promptly and updates session + wire lane
// ============================================================================
TEST(KeepaliveV2Test, test_set_protocol_lane_no_deadlock_and_updates_state) {
    std::cout << "\nTest 10: set_protocol_lane does not deadlock and updates packet lane\n";

    auto mgr = std::make_shared<SessionManager>(24, nullptr);
    mgr->start_session(0x01020304);

    auto future = std::async(std::launch::async, [mgr]() {
        mgr->set_protocol_lane(ProtocolLane::STATELESS);
        return mgr->get_session_info();
    });

    const auto status = future.wait_for(std::chrono::seconds(1));
    EXPECT_TRUE(status == std::future_status::ready) << "set_protocol_lane returns within timeout";
    if (status != std::future_status::ready) {
        return;
    }

    const auto info = future.get();
    EXPECT_TRUE(info.active_lane == ProtocolLane::STATELESS) << "Session info active_lane updated to STATELESS";

    auto wire = mgr->build_keepalive_packet();
    constexpr uint16_t expected_opcode = nexusminer::LLP::StatelessMining::SESSION_KEEPALIVE;
    bool stateless_header = wire && wire->size() >= 2 &&
                            (*wire)[0] == static_cast<uint8_t>(expected_opcode >> 8) &&
                            (*wire)[1] == static_cast<uint8_t>(expected_opcode & 0xFF);
    EXPECT_TRUE(stateless_header) << "Keepalive packet uses stateless mirrored opcode header";
}

// ============================================================================
// Test 11: accepted keepalive bookkeeping refreshes state and increments count
// Mirrors the hardened Solo keepalive / KeepAliveV2 alias path, where accepted
// ACKs now update both acknowledgement state and keepalive counters.
// ============================================================================
TEST(KeepaliveV2Test, test_keepalive_ack_bookkeeping_updates_runtime_snapshot) {
    std::cout << "\nTest 11: accepted keepalive bookkeeping updates runtime snapshot\n";

    auto mgr = std::make_shared<SessionManager>(24, nullptr);
    mgr->start_session(0x0BADB002);

    mgr->note_keepalive_ack(true, "keepalive ack accepted");
    mgr->record_keepalive();

    const auto info = mgr->get_runtime_snapshot();
    EXPECT_TRUE(info.state == SessionManager::SessionState::AUTHENTICATED) << "Accepted keepalive keeps session AUTHENTICATED";
    EXPECT_TRUE(info.expiry_state == SessionManager::ExpiryState::FRESH) << "Accepted keepalive leaves expiry_state fresh";
    EXPECT_TRUE(info.keepalive_count == 1) << "Accepted keepalive increments keepalive_count";
}

// ============================================================================
// main
// ============================================================================
