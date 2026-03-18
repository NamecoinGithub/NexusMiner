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
 */

#include "protocol/session_manager.hpp"
#include "protocol_lane.hpp"
#include "miner_opcodes.hpp"
#include "LLP/include/colin_ping_protocol.h"
#include <iostream>
#include <cassert>
#include <cstdint>
#include <vector>
#include <array>
#include <future>
#include <chrono>

#include "spdlog/spdlog.h"
#include "spdlog/sinks/null_sink.h"

using namespace nexusminer::protocol;
using namespace nexusminer;

// Test statistics
static int tests_run    = 0;
static int tests_passed = 0;
static int tests_failed = 0;

void print_test_result(const char* name, bool passed) {
    tests_run++;
    if (passed) {
        tests_passed++;
        std::cout << "  [PASS] " << name << "\n";
    } else {
        tests_failed++;
        std::cout << "  [FAIL] " << name << "\n";
    }
}

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
void test_keepalive_v2_payload_size_legacy() {
    std::cout << "\nTest 1: Legacy keepalive packet total wire size\n";
    // Legacy: 1-byte opcode + 4-byte BE length + 8-byte payload = 13 bytes
    auto bytes = make_keepalive_bytes(0x00000001, ProtocolLane::LEGACY);
    print_test_result("Legacy wire size == 13 (1+4+8)", bytes.size() == 13);
}

// ============================================================================
// Test 2: session_id encoded little-endian in payload bytes [0..3]
// For a legacy packet: bytes[0]=opcode, bytes[1..4]=length, bytes[5..8]=session_id LE
// ============================================================================
void test_keepalive_v2_session_id_le() {
    std::cout << "\nTest 2: session_id is little-endian in bytes [payload+0..3]\n";
    uint32_t session_id = 0x12345678;
    auto bytes = make_keepalive_bytes(session_id, ProtocolLane::LEGACY);
    if (bytes.size() < 13) {
        print_test_result("Legacy wire size sufficient for check", false);
        return;
    }
    // payload starts at offset 5 (opcode[0] + length[1..4])
    uint32_t got = read_le32(bytes, 5);
    print_test_result("session_id LE == 0x12345678", got == 0x12345678);
}

// ============================================================================
// Test 3: suffix is zeros when set_prevblock_suffix not called
// ============================================================================
void test_keepalive_v2_suffix_zeros_default() {
    std::cout << "\nTest 3: Default prevblock_suffix is all zeros\n";
    auto bytes = make_keepalive_bytes(0xCAFEBABE, ProtocolLane::LEGACY);
    if (bytes.size() < 13) {
        print_test_result("Packet large enough", false);
        return;
    }
    // suffix at payload offset [4..7] → wire offset [9..12]
    bool all_zero = (bytes[9] == 0 && bytes[10] == 0 && bytes[11] == 0 && bytes[12] == 0);
    print_test_result("Suffix bytes [9..12] all zero by default", all_zero);
}

// ============================================================================
// Test 4: set_prevblock_suffix() sets bytes [4..7] of payload correctly
// ============================================================================
void test_keepalive_v2_suffix_set() {
    std::cout << "\nTest 4: set_prevblock_suffix() reflected in keepalive packet\n";
    std::array<uint8_t, 4> suffix = { 0x11, 0x22, 0x33, 0x44 };
    auto bytes = make_keepalive_bytes(0x00000001, ProtocolLane::LEGACY, &suffix);
    if (bytes.size() < 13) {
        print_test_result("Packet large enough", false);
        return;
    }
    // suffix at wire offset [9..12]
    print_test_result("Suffix byte[0] == 0x11", bytes[9]  == 0x11);
    print_test_result("Suffix byte[1] == 0x22", bytes[10] == 0x22);
    print_test_result("Suffix byte[2] == 0x33", bytes[11] == 0x33);
    print_test_result("Suffix byte[3] == 0x44", bytes[12] == 0x44);
}

// ============================================================================
// Test 5: prevblock_suffix extraction logic — last 4 bytes == bytes[124..127]
// ============================================================================
void test_prevblock_suffix_extraction_logic() {
    std::cout << "\nTest 5: prevblock_suffix = bytes[124..127] of 128-byte GetBytes()\n";

    // Simulate a 128-byte GetBytes() with known pattern
    std::vector<uint8_t> hash_bytes(128);
    for (int i = 0; i < 128; ++i) hash_bytes[i] = static_cast<uint8_t>(i);

    std::array<uint8_t, 4> suffix{};
    if (hash_bytes.size() >= 128) {
        suffix = { hash_bytes[124], hash_bytes[125], hash_bytes[126], hash_bytes[127] };
    }

    print_test_result("suffix[0] == 124 (0x7C)", suffix[0] == 124);
    print_test_result("suffix[1] == 125 (0x7D)", suffix[1] == 125);
    print_test_result("suffix[2] == 126 (0x7E)", suffix[2] == 126);
    print_test_result("suffix[3] == 127 (0x7F)", suffix[3] == 127);
}

// ============================================================================
// Test 6: set_prevblock_suffix with zeros sends zero suffix
// ============================================================================
void test_keepalive_v2_suffix_explicit_zeros() {
    std::cout << "\nTest 6: set_prevblock_suffix with zeros sends zero suffix\n";
    std::array<uint8_t, 4> zero_suffix = { 0, 0, 0, 0 };
    auto bytes = make_keepalive_bytes(0x00000001, ProtocolLane::LEGACY, &zero_suffix);
    if (bytes.size() < 13) {
        print_test_result("Packet large enough", false);
        return;
    }
    bool all_zero = (bytes[9] == 0 && bytes[10] == 0 && bytes[11] == 0 && bytes[12] == 0);
    print_test_result("Explicit zero suffix reflected in wire bytes", all_zero);
}

// ============================================================================
// Test 7: Parsing robustness — short payload lengths rejected by Parse()
// ============================================================================
void test_keepalive_parse_robustness_other_lengths() {
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
    print_test_result("Lengths < 32 all rejected by Parse()", all_rejected);

    // Confirm 32-byte buffer is accepted
    std::vector<uint8_t> good(32, 0);
    KeepAliveV2AckFrame frame;
    print_test_result("32-byte buffer accepted by Parse()", frame.Parse(good));
}

// ============================================================================
// Test 8: KeepAliveV2AckFrame 32-byte layout — stake_height at [24-27],
//          fork_score at [28-31]
// ============================================================================
void test_keepalive_v2_ack_frame_layout() {
    std::cout << "\nTest 8: KeepAliveV2AckFrame 32-byte layout\n";
    using ::LLP::KeepAliveV2AckFrame;

    print_test_result("PAYLOAD_SIZE == 32", KeepAliveV2AckFrame::PAYLOAD_SIZE == 32u);

    std::vector<uint8_t> data(32, 0);
    // stake_height at bytes [24-27] = 0xAABBCCDD (BE)
    data[24] = 0xAA; data[25] = 0xBB; data[26] = 0xCC; data[27] = 0xDD;
    // fork_score at bytes [28-31] = 0x11223344 (BE)
    data[28] = 0x11; data[29] = 0x22; data[30] = 0x33; data[31] = 0x44;

    KeepAliveV2AckFrame ack;
    bool parsed = ack.Parse(data);
    print_test_result("Parse() returns true for 32-byte buffer", parsed);
    print_test_result("stake_height == 0xAABBCCDD at bytes [24-27]",
                      ack.stake_height == 0xAABBCCDDu);
    print_test_result("fork_score == 0x11223344 at bytes [28-31]",
                      ack.fork_score == 0x11223344u);
    print_test_result("Parse() rejects 28-byte buffer", !ack.Parse(std::vector<uint8_t>(28, 0)));
}

// ============================================================================
// Test 9: KeepAliveV2AckFrame::Parse() decodes session_id as little-endian at [0-3]
// ============================================================================
void test_parse_session_id_le() {
    std::cout << "\nTest 9: KeepAliveV2AckFrame::Parse() decodes session_id LE at [0-3]\n";
    using ::LLP::KeepAliveV2AckFrame;

    std::vector<uint8_t> payload(32, 0);
    // session_id = 0x12345678 LE → bytes [0..3] = 78 56 34 12
    payload[0] = 0x78; payload[1] = 0x56; payload[2] = 0x34; payload[3] = 0x12;
    // unified_height = 6000 BE at [8..11]
    payload[8] = 0x00; payload[9] = 0x00; payload[10] = 0x17; payload[11] = 0x70;

    KeepAliveV2AckFrame frame;
    auto result = frame.Parse(payload);
    print_test_result("Parse returns true", result);
    print_test_result("session_id == 0x12345678", frame.session_id == 0x12345678u);
    print_test_result("unified_height == 6000",   frame.unified_height == 6000u);
}

// ============================================================================
// Test 10: set_protocol_lane returns promptly and updates session + wire lane
// ============================================================================
void test_set_protocol_lane_no_deadlock_and_updates_state() {
    std::cout << "\nTest 10: set_protocol_lane does not deadlock and updates packet lane\n";

    auto mgr = std::make_shared<SessionManager>(24, nullptr);
    mgr->start_session(0x01020304);

    auto future = std::async(std::launch::async, [mgr]() {
        mgr->set_protocol_lane(ProtocolLane::STATELESS);
        return mgr->get_session_info();
    });

    const auto status = future.wait_for(std::chrono::seconds(1));
    print_test_result("set_protocol_lane returns within timeout", status == std::future_status::ready);
    if (status != std::future_status::ready) {
        return;
    }

    const auto info = future.get();
    print_test_result("Session info active_lane updated to STATELESS",
                      info.active_lane == ProtocolLane::STATELESS);

    auto wire = mgr->build_keepalive_packet();
    // Stateless lane now uses KEEPALIVE_V2 (0xD100) — the proper un-mirrored
    // stateless keepalive opcode — instead of the mirror-mapped SESSION_KEEPALIVE
    // (0xD0D4).  The node responds with KEEPALIVE_V2_ACK (0xD101).
    constexpr uint16_t expected_opcode = ::LLP::KeepAliveV2Opcodes::KEEPALIVE_V2;  // 0xD100
    bool stateless_header = wire && wire->size() >= 2 &&
                            (*wire)[0] == static_cast<uint8_t>(expected_opcode >> 8) &&
                            (*wire)[1] == static_cast<uint8_t>(expected_opcode & 0xFF);
    print_test_result("Keepalive packet uses KEEPALIVE_V2 (0xD100) opcode header", stateless_header);
}

// ============================================================================
// main
// ============================================================================
int main() {
    // Suppress logging noise during tests
    auto null_sink = std::make_shared<spdlog::sinks::null_sink_mt>();
    auto logger = std::make_shared<spdlog::logger>("logger", null_sink);
    spdlog::set_default_logger(logger);

    std::cout << "========================================\n";
    std::cout << "KEEPALIVE v2 Unit Tests\n";
    std::cout << "========================================\n";

    test_keepalive_v2_payload_size_legacy();
    test_keepalive_v2_session_id_le();
    test_keepalive_v2_suffix_zeros_default();
    test_keepalive_v2_suffix_set();
    test_prevblock_suffix_extraction_logic();
    test_keepalive_v2_suffix_explicit_zeros();
    test_keepalive_parse_robustness_other_lengths();
    test_keepalive_v2_ack_frame_layout();
    test_parse_session_id_le();
    test_set_protocol_lane_no_deadlock_and_updates_state();

    std::cout << "\n========================================\n";
    std::cout << "Test Summary\n";
    std::cout << "========================================\n";
    std::cout << "Tests run:    " << tests_run    << "\n";
    std::cout << "Tests passed: " << tests_passed << "\n";
    std::cout << "Tests failed: " << tests_failed << "\n";
    std::cout << "Success rate: "
              << (tests_run > 0 ? (100 * tests_passed / tests_run) : 0) << "%\n";
    std::cout << "========================================\n";

    return tests_failed > 0 ? 1 : 0;
}
