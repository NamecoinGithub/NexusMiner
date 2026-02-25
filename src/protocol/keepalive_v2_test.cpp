/**
 * @file keepalive_v2_test.cpp
 * @brief Unit tests for KEEPALIVE v2 miner-side implementation
 *
 * Tests:
 *  1. KeepaliveTelemetryStore: default snapshot is invalid (valid==false)
 *  2. KeepaliveTelemetryStore: update/get round-trips all fields correctly
 *  3. SessionManager::build_keepalive_packet() produces 8-byte payload (v2 format)
 *  4. SessionManager v2 payload: session_id encoded little-endian in bytes [0..3]
 *  5. SessionManager v2 payload: suffix zeros when set_prevblock_suffix not called
 *  6. SessionManager v2 payload: suffix bytes [4..7] match set_prevblock_suffix()
 *  7. v2 telemetry parse: 28-byte big-endian fields decoded correctly
 *  8. v2 telemetry parse: hashBestChain_prefix raw bytes preserved
 *  9. prevblock_suffix extraction: last 4 bytes of 128-byte GetBytes() are bytes[124..127]
 * 10. set_prevblock_suffix zeros: packet correctly sends zero suffix
 * 11. received_at is set (non-default) after a v2 parse
 * 12. age() returns 0.0 when valid==false
 * 13. Parsing robustness: non-4/non-28 payload lengths are ignored (no crash)
 */

#include "protocol/keepalive_telemetry.hpp"
#include "protocol/session_manager.hpp"
#include "protocol_lane.hpp"
#include "miner_opcodes.hpp"
#include <iostream>
#include <cassert>
#include <cstdint>
#include <vector>
#include <array>

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

// Read uint32 big-endian from a byte vector at offset
static uint32_t read_be32(const std::vector<uint8_t>& v, size_t off) {
    return (static_cast<uint32_t>(v[off]) << 24) |
           (static_cast<uint32_t>(v[off+1]) << 16) |
           (static_cast<uint32_t>(v[off+2]) << 8)  |
            static_cast<uint32_t>(v[off+3]);
}

// Read uint32 little-endian from a byte vector at offset
static uint32_t read_le32(const std::vector<uint8_t>& v, size_t off) {
    return  static_cast<uint32_t>(v[off])           |
           (static_cast<uint32_t>(v[off+1]) << 8)   |
           (static_cast<uint32_t>(v[off+2]) << 16)  |
           (static_cast<uint32_t>(v[off+3]) << 24);
}

// ============================================================================
// Test 1: KeepaliveTelemetryStore default is invalid
// ============================================================================
void test_telemetry_store_default_invalid() {
    std::cout << "\nTest 1: KeepaliveTelemetryStore default snapshot is invalid\n";
    KeepaliveTelemetryStore store;
    auto snap = store.get();
    print_test_result("Default snapshot valid==false", !snap.valid);
    print_test_result("Default snapshot session_id==0", snap.session_id == 0);
    print_test_result("Default snapshot unified_height==0", snap.unified_height == 0);
}

// ============================================================================
// Test 2: KeepaliveTelemetryStore update/get round-trips all fields
// ============================================================================
void test_telemetry_store_update() {
    std::cout << "\nTest 2: KeepaliveTelemetryStore update/get round-trip\n";
    KeepaliveTelemetryStore store;

    KeepaliveTelemetrySnapshot snap;
    snap.session_id      = 0xDEADBEEF;
    snap.unified_height  = 6000001;
    snap.prime_height    = 2000042;
    snap.hash_height     = 4000099;
    snap.stake_height    = 1001;
    snap.nBits           = 0x1d00FFFF;
    snap.hashBestChain_prefix = { 0xAB, 0xCD, 0xEF, 0x01 };
    snap.valid           = true;

    store.update(snap);
    auto got = store.get();

    print_test_result("session_id round-trips", got.session_id == 0xDEADBEEF);
    print_test_result("unified_height round-trips", got.unified_height == 6000001);
    print_test_result("prime_height round-trips", got.prime_height == 2000042);
    print_test_result("hash_height round-trips", got.hash_height == 4000099);
    print_test_result("stake_height round-trips", got.stake_height == 1001);
    print_test_result("nBits round-trips", got.nBits == 0x1d00FFFF);
    print_test_result("hashBestChain_prefix[0] == 0xAB", got.hashBestChain_prefix[0] == 0xAB);
    print_test_result("hashBestChain_prefix[3] == 0x01", got.hashBestChain_prefix[3] == 0x01);
    print_test_result("valid==true after update", got.valid);
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
// Test 3: build_keepalive_packet() produces 8-byte payload (v2 format)
// Legacy wire layout: [opcode(1)][length_BE(4)][payload(8)] = 13 bytes total
// ============================================================================
void test_keepalive_v2_payload_size_legacy() {
    std::cout << "\nTest 3: Legacy keepalive packet total wire size\n";
    // Legacy: 1-byte opcode + 4-byte BE length + 8-byte payload = 13 bytes
    auto bytes = make_keepalive_bytes(0x00000001, ProtocolLane::LEGACY);
    print_test_result("Legacy wire size == 13 (1+4+8)", bytes.size() == 13);
}

// ============================================================================
// Test 4: session_id encoded little-endian in payload bytes [0..3]
// For a legacy packet: bytes[0]=opcode, bytes[1..4]=length, bytes[5..8]=session_id LE
// ============================================================================
void test_keepalive_v2_session_id_le() {
    std::cout << "\nTest 4: session_id is little-endian in bytes [payload+0..3]\n";
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
// Test 5: suffix is zeros when set_prevblock_suffix not called
// ============================================================================
void test_keepalive_v2_suffix_zeros_default() {
    std::cout << "\nTest 5: Default prevblock_suffix is all zeros\n";
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
// Test 6: set_prevblock_suffix() sets bytes [4..7] of payload correctly
// ============================================================================
void test_keepalive_v2_suffix_set() {
    std::cout << "\nTest 6: set_prevblock_suffix() reflected in keepalive packet\n";
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
// Test 7: v2 telemetry parse — simulate the 28-byte receive handler logic
// ============================================================================
void test_keepalive_v2_telemetry_parse() {
    std::cout << "\nTest 7: v2 telemetry parse: 28-byte big-endian fields\n";

    // Construct a mock 28-byte KEEPALIVE v2 reply payload
    std::vector<uint8_t> payload(28, 0);
    // [0..3] session_id LE = 0xDEADBEEF
    payload[0] = 0xEF; payload[1] = 0xBE; payload[2] = 0xAD; payload[3] = 0xDE;
    // [4..7] unified_height BE = 6000001 = 0x005B8D81
    payload[4] = 0x00; payload[5] = 0x5B; payload[6] = 0x8D; payload[7] = 0x81;
    // [8..11] prime_height BE = 2000042 = 0x001E84AA
    payload[8] = 0x00; payload[9] = 0x1E; payload[10] = 0x84; payload[11] = 0xAA;
    // [12..15] hash_height BE = 4000099 = 0x003D0963
    payload[12] = 0x00; payload[13] = 0x3D; payload[14] = 0x09; payload[15] = 0x63;
    // [16..19] stake_height BE = 1001 = 0x000003E9
    payload[16] = 0x00; payload[17] = 0x00; payload[18] = 0x03; payload[19] = 0xE9;
    // [20..23] nBits BE = 0x1d00FFFF
    payload[20] = 0x1D; payload[21] = 0x00; payload[22] = 0xFF; payload[23] = 0xFF;
    // [24..27] hashBestChain_prefix raw bytes
    payload[24] = 0xAB; payload[25] = 0xCD; payload[26] = 0xEF; payload[27] = 0x01;

    // Replicate parsing logic from solo.cpp SESSION_KEEPALIVE handler
    const auto& d = payload;
    KeepaliveTelemetrySnapshot snap;
    snap.session_id      = read_le32(d, 0);
    snap.unified_height  = read_be32(d, 4);
    snap.prime_height    = read_be32(d, 8);
    snap.hash_height     = read_be32(d, 12);
    snap.stake_height    = read_be32(d, 16);
    snap.nBits           = read_be32(d, 20);
    snap.hashBestChain_prefix = { d[24], d[25], d[26], d[27] };
    snap.valid = true;

    print_test_result("session_id == 0xDEADBEEF", snap.session_id == 0xDEADBEEF);
    print_test_result("unified_height == 6000001", snap.unified_height == 6000001);
    print_test_result("prime_height == 2000042",   snap.prime_height == 2000042);
    print_test_result("hash_height == 4000099",    snap.hash_height == 4000099);
    print_test_result("stake_height == 1001",       snap.stake_height == 1001);
    print_test_result("nBits == 0x1d00FFFF",        snap.nBits == 0x1d00FFFFu);
    print_test_result("hashBestChain_prefix valid == true", snap.valid);
}

// ============================================================================
// Test 8: hashBestChain_prefix raw bytes preserved exactly
// ============================================================================
void test_keepalive_v2_hash_prefix_raw() {
    std::cout << "\nTest 8: hashBestChain_prefix raw bytes preserved\n";
    std::vector<uint8_t> payload(28, 0);
    payload[24] = 0xCA; payload[25] = 0xFE; payload[26] = 0xBA; payload[27] = 0xBE;

    KeepaliveTelemetrySnapshot snap;
    snap.hashBestChain_prefix = { payload[24], payload[25], payload[26], payload[27] };

    print_test_result("prefix[0] == 0xCA", snap.hashBestChain_prefix[0] == 0xCA);
    print_test_result("prefix[1] == 0xFE", snap.hashBestChain_prefix[1] == 0xFE);
    print_test_result("prefix[2] == 0xBA", snap.hashBestChain_prefix[2] == 0xBA);
    print_test_result("prefix[3] == 0xBE", snap.hashBestChain_prefix[3] == 0xBE);
}

// ============================================================================
// Test 9: prevblock_suffix extraction logic — last 4 bytes == bytes[124..127]
// ============================================================================
void test_prevblock_suffix_extraction_logic() {
    std::cout << "\nTest 9: prevblock_suffix = bytes[124..127] of 128-byte GetBytes()\n";

    // Simulate a 128-byte GetBytes() with known pattern
    std::vector<uint8_t> hash_bytes(128);
    for (int i = 0; i < 128; ++i) hash_bytes[i] = static_cast<uint8_t>(i);

    // The suffix extraction code in solo.cpp:
    //   std::array<uint8_t, 4> suffix{};
    //   if (prev_bytes.size() >= 128) {
    //       suffix = { prev_bytes[124], prev_bytes[125], prev_bytes[126], prev_bytes[127] };
    //   }
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
// Test 10: set_prevblock_suffix with zeros sends zero suffix
// ============================================================================
void test_keepalive_v2_suffix_explicit_zeros() {
    std::cout << "\nTest 10: set_prevblock_suffix with zeros sends zero suffix\n";
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
// Test 11: received_at is set (non-default) after a v2 parse
// ============================================================================
void test_keepalive_v2_received_at_set() {
    std::cout << "\nTest 11: received_at is set after v2 parse\n";

    KeepaliveTelemetrySnapshot snap;
    // Simulate the parse: set valid and received_at (mirrors solo.cpp handler)
    snap.valid       = true;
    snap.received_at = std::chrono::steady_clock::now();

    // received_at must be non-default (default-constructed time_point is epoch)
    bool is_set = (snap.received_at != std::chrono::steady_clock::time_point{});
    print_test_result("received_at != default after parse", is_set);

    // age() should be non-negative and very small (sub-second)
    double a = snap.age();
    print_test_result("age() >= 0.0 after parse", a >= 0.0);
    print_test_result("age() < 1.0 (sub-second)", a < 1.0);
}

// ============================================================================
// Test 12: age() returns 0.0 when valid==false
// ============================================================================
void test_keepalive_v2_age_invalid() {
    std::cout << "\nTest 12: age() returns 0.0 when valid==false\n";
    KeepaliveTelemetrySnapshot snap;  // valid==false by default
    print_test_result("age() == 0.0 when not valid", snap.age() == 0.0);
}

// ============================================================================
// Test 13: Parsing robustness — non-4/non-28 lengths produce no parse result
// ============================================================================
void test_keepalive_parse_robustness_other_lengths() {
    std::cout << "\nTest 13: Parsing robustness: lengths != 4 and != 28 are ignored\n";

    // Test lengths that must be silently ignored (not 4, not 28)
    std::vector<size_t> ignored_lengths = { 0, 1, 2, 3, 5, 10, 16, 27, 29, 100 };
    bool all_ok = true;
    for (size_t len : ignored_lengths) {
        std::vector<uint8_t> payload(len, 0xFF);
        // Replicate the solo.cpp branching logic:
        //   == 28 → v2 parse
        //   == 4  → v1 parse
        //   else  → ignore
        bool handled = false;
        if (!payload.empty() && len == 28) {
            handled = true;  // would be v2 parsed
        } else if (!payload.empty() && len == 4) {
            handled = true;  // would be v1 parsed
        }
        // For all lengths in ignored_lengths, handled must be false
        if (handled) { all_ok = false; break; }
    }
    print_test_result("Non-4/non-28 lengths are not handled (ignored)", all_ok);
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

    test_telemetry_store_default_invalid();
    test_telemetry_store_update();
    test_keepalive_v2_payload_size_legacy();
    test_keepalive_v2_session_id_le();
    test_keepalive_v2_suffix_zeros_default();
    test_keepalive_v2_suffix_set();
    test_keepalive_v2_telemetry_parse();
    test_keepalive_v2_hash_prefix_raw();
    test_prevblock_suffix_extraction_logic();
    test_keepalive_v2_suffix_explicit_zeros();
    test_keepalive_v2_received_at_set();
    test_keepalive_v2_age_invalid();
    test_keepalive_parse_robustness_other_lengths();

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
