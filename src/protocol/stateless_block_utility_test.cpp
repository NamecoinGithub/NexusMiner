/**
 * @file stateless_block_utility_test.cpp
 * @brief Unit tests for StatelessBlockUtility encode/decode utility
 *
 * Tests (acceptance criteria):
 *  1. decode_template() with a valid 228-byte buffer succeeds
 *  2. decode_template() rejects payloads shorter than 228 bytes
 *  3. decode_template() rejects payloads longer than 228 bytes
 *  4. encode_submit() rejects zero nonce
 *  5. encode_submit() rejects invalid channel (e.g. 0)
 *  6. encode_submit() rejects zero height
 *  7. encode_submit() with STATELESS lane produces opcode 0xD001
 *  8. encode_submit() with LEGACY lane produces opcode 0x01
 *  9. encode_submit() with falcon=nullptr produces unsigned submit
 *     (payload = block bytes only, no signature suffix)
 * 10. decode_template() populates metadata fields from 12-byte prefix (BE)
 * 11. decode_template() populates canonical block fields from 216-byte body
 * 12. decode_template() sets channel_consistent correctly
 * 13. encode_submit() informational staleness/tip-moved do not block submission
 */

#include "include/stateless_block_utility.hpp"
#include "protocol/height_tracker.hpp"
#include "block_utils.hpp"
#include "miner_opcodes.hpp"
#include <iostream>
#include <cassert>
#include <cstdint>
#include <vector>
#include <cstring>

using namespace nexusminer;
using namespace nexusminer::protocol;

// ── Test infrastructure ──────────────────────────────────────────────────────
static int tests_run    = 0;
static int tests_passed = 0;
static int tests_failed = 0;

static void print_result(const char* name, bool passed) {
    tests_run++;
    if (passed) {
        tests_passed++;
        std::cout << "  [PASS] " << name << "\n";
    } else {
        tests_failed++;
        std::cout << "  [FAIL] " << name << "\n";
    }
}

// ── Helper: extract uint32 big-endian ────────────────────────────────────────
static uint8_t be_byte(uint32_t v, int i) {
    return static_cast<uint8_t>((v >> (24 - 8 * i)) & 0xFF);
}

/**
 * Build a valid 228-byte STATELESS_GET_BLOCK payload:
 *   [0-3]   unified_height (BE)
 *   [4-7]   channel_height (BE)
 *   [8-11]  difficulty     (BE)
 *   [12-227] 216-byte Tritium block
 *
 * Tritium block layout (all big-endian except nNonce which is LE):
 *   [0-3]     nVersion
 *   [4-131]   hashPrevBlock (128 bytes)
 *   [132-195] hashMerkleRoot (64 bytes)
 *   [196-199] nChannel
 *   [200-203] nHeight
 *   [204-207] nBits
 *   [208-215] nNonce (little-endian)
 */
static network::Payload make_template_payload(
    uint32_t unified_h = 6000000,
    uint32_t channel_h = 2000000,
    uint32_t difficulty = 0x4308519,
    uint32_t nVersion   = 8,
    uint32_t nChannel   = 2,        // Hash
    uint32_t nHeight    = 6000001,  // unified_h + 1
    uint32_t nBits      = 0x4308519,
    uint64_t nNonce     = 0)
{
    network::Payload buf(228, 0x00);

    // Metadata (big-endian)
    buf[0]  = be_byte(unified_h,  0);  buf[1]  = be_byte(unified_h,  1);
    buf[2]  = be_byte(unified_h,  2);  buf[3]  = be_byte(unified_h,  3);
    buf[4]  = be_byte(channel_h,  0);  buf[5]  = be_byte(channel_h,  1);
    buf[6]  = be_byte(channel_h,  2);  buf[7]  = be_byte(channel_h,  3);
    buf[8]  = be_byte(difficulty, 0);  buf[9]  = be_byte(difficulty, 1);
    buf[10] = be_byte(difficulty, 2);  buf[11] = be_byte(difficulty, 3);

    // Block body at offset 12 (big-endian for uint32 fields)
    size_t b = 12;
    // nVersion [0-3]
    buf[b]   = be_byte(nVersion, 0); buf[b+1] = be_byte(nVersion, 1);
    buf[b+2] = be_byte(nVersion, 2); buf[b+3] = be_byte(nVersion, 3);
    b += 4;
    // hashPrevBlock [4-131] — leave as zeroes
    b += 128;
    // hashMerkleRoot [132-195] — leave as zeroes
    b += 64;
    // nChannel [196-199]
    buf[b]   = be_byte(nChannel, 0); buf[b+1] = be_byte(nChannel, 1);
    buf[b+2] = be_byte(nChannel, 2); buf[b+3] = be_byte(nChannel, 3);
    b += 4;
    // nHeight [200-203]
    buf[b]   = be_byte(nHeight, 0); buf[b+1] = be_byte(nHeight, 1);
    buf[b+2] = be_byte(nHeight, 2); buf[b+3] = be_byte(nHeight, 3);
    b += 4;
    // nBits [204-207]
    buf[b]   = be_byte(nBits, 0); buf[b+1] = be_byte(nBits, 1);
    buf[b+2] = be_byte(nBits, 2); buf[b+3] = be_byte(nBits, 3);
    b += 4;
    // nNonce [208-215] — little-endian
    for (int i = 0; i < 8; ++i)
        buf[b + i] = static_cast<uint8_t>((nNonce >> (i * 8)) & 0xFF);

    return buf;
}

/** Build a CBlock suitable for encode_submit() pre-checks. */
static ::LLP::CBlock make_solved_block(uint32_t nChannel = 2,
                                       uint32_t nHeight  = 6000001,
                                       uint64_t nNonce   = 0xDEADBEEFCAFEBABEULL,
                                       uint32_t nBits    = 0x4308519) {
    ::LLP::CBlock blk;
    blk.nVersion = 8;
    blk.nChannel = nChannel;
    blk.nHeight  = nHeight;
    blk.nBits    = nBits;
    blk.nNonce   = nNonce;
    return blk;
}

/** Return a default (zero) HeightTracker::Snapshot for tests that don't need it. */
static HeightTracker::Snapshot make_snapshot() {
    return HeightTracker::Snapshot{};
}

// ── Test functions ────────────────────────────────────────────────────────────

// Test 1 — decode_template(): valid 228-byte buffer
static void test_decode_valid() {
    auto payload = make_template_payload();
    auto result  = StatelessBlockUtility::decode_template(payload, 2, nullptr);
    print_result("decode_template(): valid 228-byte buffer succeeds",
                 result.valid);
}

// Test 2 — decode_template(): reject shorter payload
static void test_decode_too_short() {
    auto payload = make_template_payload();
    payload.resize(227);  // one byte short
    auto result = StatelessBlockUtility::decode_template(payload, 2, nullptr);
    print_result("decode_template(): rejects payload < 228 bytes",
                 !result.valid && !result.error_message.empty());
}

// Test 3 — decode_template(): reject longer payload
static void test_decode_too_long() {
    auto payload = make_template_payload();
    payload.push_back(0xFF);  // one extra byte
    auto result = StatelessBlockUtility::decode_template(payload, 2, nullptr);
    print_result("decode_template(): rejects payload > 228 bytes",
                 !result.valid && !result.error_message.empty());
}

// Test 4 — encode_submit(): zero nonce rejected
static void test_encode_zero_nonce() {
    auto blk     = make_solved_block(2, 6000001, /*nNonce=*/0);
    auto snap    = make_snapshot();
    auto result  = StatelessBlockUtility::encode_submit(
        blk, {}, nullptr, ProtocolLane::STATELESS, snap, nullptr);
    print_result("encode_submit(): rejects zero nonce",
                 !result.valid && !result.rejection_reason.empty());
}

// Test 5 — encode_submit(): invalid channel rejected
static void test_encode_invalid_channel() {
    auto blk  = make_solved_block(/*channel=*/0, 6000001, 0xDEADBEEFULL);
    auto snap = make_snapshot();
    auto result = StatelessBlockUtility::encode_submit(
        blk, {}, nullptr, ProtocolLane::STATELESS, snap, nullptr);
    print_result("encode_submit(): rejects invalid channel (0)",
                 !result.valid && !result.rejection_reason.empty());
}

// Test 6 — encode_submit(): zero height rejected
static void test_encode_zero_height() {
    auto blk  = make_solved_block(2, /*height=*/0, 0xDEADBEEFULL);
    auto snap = make_snapshot();
    auto result = StatelessBlockUtility::encode_submit(
        blk, {}, nullptr, ProtocolLane::STATELESS, snap, nullptr);
    print_result("encode_submit(): rejects zero height",
                 !result.valid && !result.rejection_reason.empty());
}

// Test 7 — encode_submit(): STATELESS lane → opcode 0xD001
static void test_encode_stateless_opcode() {
    auto blk  = make_solved_block();
    auto snap = make_snapshot();
    auto result = StatelessBlockUtility::encode_submit(
        blk, {}, nullptr, ProtocolLane::STATELESS, snap, nullptr);

    bool ok = false;
    if (result.valid && result.wire_bytes && result.wire_bytes->size() >= 2) {
        const auto& w = *result.wire_bytes;
        // Stateless opcode 0xD001: first byte 0xD0, second byte 0x01
        ok = (w[0] == 0xD0 && w[1] == 0x01);
    }
    print_result("encode_submit(): STATELESS lane produces opcode 0xD001", ok);
}

// Test 8 — encode_submit(): LEGACY lane → opcode 0x01
static void test_encode_legacy_opcode() {
    auto blk  = make_solved_block();
    auto snap = make_snapshot();
    auto result = StatelessBlockUtility::encode_submit(
        blk, {}, nullptr, ProtocolLane::LEGACY, snap, nullptr);

    bool ok = false;
    if (result.valid && result.wire_bytes && !result.wire_bytes->empty()) {
        const auto& w = *result.wire_bytes;
        // Legacy SUBMIT_BLOCK opcode byte = 0x01
        ok = (w[0] == 0x01);
    }
    print_result("encode_submit(): LEGACY lane produces opcode 0x01", ok);
}

// Test 9 — encode_submit(): falcon=nullptr → no signature suffix (shorter payload)
static void test_encode_unsigned_submit() {
    auto blk  = make_solved_block();
    auto snap = make_snapshot();

    // Unsigned: just block bytes (216 bytes) as payload
    auto unsigned_result = StatelessBlockUtility::encode_submit(
        blk, {}, nullptr, ProtocolLane::STATELESS, snap, nullptr);

    bool ok = false;
    if (unsigned_result.valid && unsigned_result.wire_bytes) {
        // Stateless header: 2-byte opcode + 4-byte length = 6 bytes
        // Payload should be exactly BLOCK_BODY_SIZE bytes (216)
        size_t expected_total = 6 + StatelessBlockUtility::BLOCK_BODY_SIZE;
        ok = (unsigned_result.wire_bytes->size() == expected_total);
    }
    print_result("encode_submit(): falcon=nullptr produces unsigned submit "
                 "(no signature suffix)", ok);
}

// Test 10 — decode_template(): metadata fields from 12-byte prefix
static void test_decode_metadata_fields() {
    auto payload = make_template_payload(
        /*unified_h=*/7654321,
        /*channel_h=*/2500000,
        /*difficulty=*/0xABCD1234);
    auto result = StatelessBlockUtility::decode_template(payload, 2, nullptr);
    bool ok = result.valid &&
              result.unified_height   == 7654321  &&
              result.channel_height   == 2500000  &&
              result.difficulty_nbits == 0xABCD1234;
    print_result("decode_template(): metadata fields parsed correctly from "
                 "12-byte prefix (BE)", ok);
}

// Test 11 — decode_template(): canonical block fields from 216-byte body
static void test_decode_block_fields() {
    auto payload = make_template_payload(
        /*unified_h=*/6000000, /*channel_h=*/2000000, /*difficulty=*/0x4308519,
        /*nVersion=*/8, /*nChannel=*/2, /*nHeight=*/6000001,
        /*nBits=*/0x4308519, /*nNonce=*/0);
    auto result = StatelessBlockUtility::decode_template(payload, 2, nullptr);
    bool ok = result.valid &&
              result.block.nVersion == 8    &&
              result.block.nChannel == 2    &&
              result.block.nHeight  == 6000001 &&
              result.block.nBits    == 0x4308519;
    print_result("decode_template(): canonical block fields from 216-byte body",
                 ok);
}

// Test 12 — decode_template(): channel_consistent flag
static void test_decode_channel_consistent() {
    // mining channel 1 (Prime) but block says 2 (Hash) → inconsistent
    auto payload = make_template_payload(6000000, 2000000, 0, 8, 2, 6000001);
    auto result = StatelessBlockUtility::decode_template(payload, /*mining_channel=*/1, nullptr);
    bool ok = result.valid && !result.channel_consistent;
    print_result("decode_template(): channel_consistent=false when nChannel "
                 "doesn't match mining_channel", ok);
}

// Test 13 — encode_submit(): stale/tip-moved are warnings, not blocks
static void test_encode_stale_does_not_block() {
    auto blk  = make_solved_block();

    // Simulate a stale snapshot: channel_height >= channel_target
    HeightTracker ht;
    ht.OnBlockDataReceived(6000000, 2000001, 0x4308519, uint1024_t{});
    ht.OnTemplateReceived(2, 2000002);
    // Now advance channel_height beyond target to make it stale
    ht.OnBlockDataReceived(6000001, 2000002, 0x4308519, uint1024_t{});
    auto snap = ht.GetSnapshot();

    auto result = StatelessBlockUtility::encode_submit(
        blk, {}, nullptr, ProtocolLane::STATELESS, snap, nullptr);
    print_result("encode_submit(): stale template is a warning, not a hard "
                 "rejection", result.valid);
}

// ── main ─────────────────────────────────────────────────────────────────────

int main() {
    std::cout << "\n";
    std::cout << "========================================\n";
    std::cout << "  stateless_block_utility_test\n";
    std::cout << "========================================\n";

    test_decode_valid();
    test_decode_too_short();
    test_decode_too_long();
    test_encode_zero_nonce();
    test_encode_invalid_channel();
    test_encode_zero_height();
    test_encode_stateless_opcode();
    test_encode_legacy_opcode();
    test_encode_unsigned_submit();
    test_decode_metadata_fields();
    test_decode_block_fields();
    test_decode_channel_consistent();
    test_encode_stale_does_not_block();

    std::cout << "\n";
    std::cout << "========================================\n";
    std::cout << "Test Summary\n";
    std::cout << "========================================\n";
    std::cout << "Tests run:    " << tests_run    << "\n";
    std::cout << "Tests passed: " << tests_passed << "\n";
    std::cout << "Tests failed: " << tests_failed << "\n";
    std::cout << "Success rate: "
              << (tests_run > 0 ? 100 * tests_passed / tests_run : 0)
              << "%\n";
    std::cout << "========================================\n";

    return (tests_failed == 0) ? 0 : 1;
}
