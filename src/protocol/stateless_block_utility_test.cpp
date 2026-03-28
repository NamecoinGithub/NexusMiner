/**
 * @file stateless_block_utility_test.cpp
 * @brief Unit tests for StatelessBlockUtility encode/decode utility
 *
 * Tests (acceptance criteria):
 *  1.  decode_template() with a valid 228-byte buffer succeeds
 *  2.  decode_template() rejects payloads shorter than 228 bytes
 *  3.  decode_template() rejects payloads longer than 228 bytes
 *  4.  encode_submit() rejects zero nonce
 *  5.  encode_submit() rejects invalid channel (e.g. 0)
 *  6.  encode_submit() rejects zero height
 *  7.  encode_submit() with STATELESS lane produces opcode 0xD001
 *  8.  encode_submit() with LEGACY lane produces opcode 0x01
 *  9.  encode_submit() with falcon=nullptr produces unsigned submit
 *      (payload = block bytes + any vOffsets, no Falcon signature suffix)
 * 10.  decode_template() populates metadata fields from 12-byte prefix (BE)
 * 11.  decode_template() populates canonical block fields from 216-byte body
 * 12.  decode_template() sets channel_consistent correctly
 * 13.  encode_submit() informational staleness/tip-moved do not block submission
 * 14.  encode_submit() with Prime-channel vOffsets produces larger payload than
 *      Hash-channel (no vOffsets) submission
 */

#include "include/stateless_block_utility.hpp"
#include "protocol/mining_template_interface.hpp"
#include "protocol/height_tracker.hpp"
#include "worker/block_header_utils.hpp"
#include "miner_opcodes.hpp"
#include <iostream>
#include <cstdint>
#include <vector>
#include <cstring>
#include <gtest/gtest.h>

using namespace nexusminer;
using namespace nexusminer::protocol;

// ── Test infrastructure ──────────────────────────────────────────────────────
// ── Helper: extract uint32 big-endian ────────────────────────────────────────
static uint8_t be_byte(uint32_t v, int i) {
    return static_cast<uint8_t>((v >> (24 - 8 * i)) & 0xFF);
}

// Default difficulty / nBits used across test helper functions
static constexpr uint32_t DEFAULT_DIFFICULTY = 0x4308519;

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
    uint32_t difficulty = DEFAULT_DIFFICULTY,
    uint32_t nVersion   = 8,
    uint32_t nChannel   = 2,        // Hash
    uint32_t nHeight    = 6000001,  // unified_h + 1
    uint32_t nBits      = DEFAULT_DIFFICULTY,
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
    // hashPrevBlock [4-131] -- leave as zeros
    b += 128;
    // hashMerkleRoot [132-195] -- non-zero so MTI validation passes
    for (size_t i = 0; i < 64; ++i)
        buf[b + i] = static_cast<uint8_t>(0xA0 + (i & 0x0F));
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
    // nNonce [208-215] -- little-endian
    for (int i = 0; i < 8; ++i)
        buf[b + i] = static_cast<uint8_t>((nNonce >> (i * 8)) & 0xFF);

    return buf;
}

/** Build a CBlock suitable for encode_submit() pre-checks. */
static ::LLP::CBlock make_solved_block(uint32_t nChannel = 2,
                                       uint32_t nHeight  = 6000001,
                                       uint64_t nNonce   = 0xDEADBEEFCAFEBABEULL,
                                       uint32_t nBits    = DEFAULT_DIFFICULTY) {
    ::LLP::CBlock blk;
    blk.nVersion = 8;
    blk.nChannel = nChannel;
    blk.nHeight  = nHeight;
    blk.nBits    = nBits;
    blk.nNonce   = nNonce;
    return blk;
}

static ::LLP::CBlock make_patterned_block(uint64_t nonce = 0x0123456789ABCDEFULL) {
    auto blk = make_solved_block(1, 6000001, nonce, 0x1A2B3C4D);
    blk.nVersion = 0x01020304;

    std::vector<uint8_t> prev(128);
    for (size_t i = 0; i < prev.size(); ++i)
        prev[i] = static_cast<uint8_t>(i);
    blk.hashPrevBlock.SetBytes(prev);

    std::vector<uint8_t> merkle(64);
    for (size_t i = 0; i < merkle.size(); ++i)
        merkle[i] = static_cast<uint8_t>(0x80 + i);
    blk.hashMerkleRoot.SetBytes(merkle);

    return blk;
}

static std::vector<unsigned char> get_raw_block_header_bytes(const ::LLP::CBlock& block, bool exclude_nonce) {
    // Intentional independent oracle: this mirrors the raw BEGIN/END span directly
    // so the tests verify GetBlockHeaderBytes() instead of reusing its implementation.
    const auto* begin = reinterpret_cast<const unsigned char*>(BEGIN(block.nVersion));
    const auto* end = exclude_nonce
        ? reinterpret_cast<const unsigned char*>(END(block.nBits))
        : reinterpret_cast<const unsigned char*>(END(block.nNonce));
    return std::vector<unsigned char>(begin, end);
}

/** Return a default (zero) HeightTracker::Snapshot for tests that don't need it. */
static HeightTracker::Snapshot make_snapshot() {
    return HeightTracker::Snapshot{};
}

static SubmitContext make_submit_context(uint32_t template_height = 6000001,
                                         uint32_t chain_height = 6000000) {
    SubmitContext context;
    context.session_id = SessionId(0x12345678u);
    context.session_epoch = SessionEpoch(7u);
    context.template_height = template_height;
    context.chain_height = chain_height;
    return context;
}

/** Load a 228-byte template into a MiningTemplateInterface and return it. */
static std::unique_ptr<MiningTemplateInterface> make_loaded_mti(uint32_t channel = 2) {
    auto mti = std::make_unique<MiningTemplateInterface>(static_cast<uint8_t>(channel), 0);
    auto payload = make_template_payload(6000000, 2000000, DEFAULT_DIFFICULTY,
                                         8, channel, 6000001, DEFAULT_DIFFICULTY, 0);
    mti->read_stateless_payload(payload, "test");
    return mti;
}

// ── Test functions ────────────────────────────────────────────────────────────

// Test 1 -- decode_template(): valid 228-byte buffer
static void test_decode_valid() {
    auto mti     = make_loaded_mti();
    auto payload = make_template_payload();
    auto result  = StatelessBlockUtility::decode_template(*mti, payload, 2, nullptr);
    EXPECT_TRUE(result.valid) << "decode_template(): valid 228-byte buffer succeeds";
}

// Test 2 -- decode_template(): reject shorter payload
static void test_decode_too_short() {
    MiningTemplateInterface mti(2, 0);
    auto payload = make_template_payload();
    payload.resize(227);  // one byte short
    auto result = StatelessBlockUtility::decode_template(mti, payload, 2, nullptr);
    EXPECT_TRUE(!result.valid && !result.error_message.empty()) << "decode_template(): rejects payload < 228 bytes";
}

// Test 3 -- decode_template(): reject longer payload
static void test_decode_too_long() {
    MiningTemplateInterface mti(2, 0);
    auto payload = make_template_payload();
    payload.push_back(0xFF);  // one extra byte
    auto result = StatelessBlockUtility::decode_template(mti, payload, 2, nullptr);
    EXPECT_TRUE(!result.valid && !result.error_message.empty()) << "decode_template(): rejects payload > 228 bytes";
}

// Test 4 -- encode_submit(): zero nonce rejected
static void test_encode_zero_nonce() {
    auto mti  = make_loaded_mti();
    auto blk  = make_solved_block(2, 6000001, /*nNonce=*/0);
    auto snap = make_snapshot();
    auto result = StatelessBlockUtility::encode_submit(
        *mti, blk, {}, nullptr, ProtocolLane::STATELESS, snap, nullptr);
    EXPECT_TRUE(!result.valid && !result.rejection_reason.empty()) << "encode_submit(): rejects zero nonce";
}

// Test 5 -- encode_submit(): invalid channel rejected
static void test_encode_invalid_channel() {
    auto mti  = make_loaded_mti();
    auto blk  = make_solved_block(/*channel=*/0, 6000001, 0xDEADBEEFULL);
    auto snap = make_snapshot();
    auto result = StatelessBlockUtility::encode_submit(
        *mti, blk, {}, nullptr, ProtocolLane::STATELESS, snap, nullptr);
    EXPECT_TRUE(!result.valid && !result.rejection_reason.empty()) << "encode_submit(): rejects invalid channel (0)";
}

// Test 6 -- encode_submit(): zero height rejected
static void test_encode_zero_height() {
    auto mti  = make_loaded_mti();
    auto blk  = make_solved_block(2, /*height=*/0, 0xDEADBEEFULL);
    auto snap = make_snapshot();
    auto result = StatelessBlockUtility::encode_submit(
        *mti, blk, {}, nullptr, ProtocolLane::STATELESS, snap, nullptr);
    EXPECT_TRUE(!result.valid && !result.rejection_reason.empty()) << "encode_submit(): rejects zero height";
}

// Test 7 -- encode_submit(): STATELESS lane -> opcode 0xD001
static void test_encode_stateless_opcode() {
    auto mti  = make_loaded_mti();
    auto blk  = make_solved_block();
    auto snap = make_snapshot();
    auto result = StatelessBlockUtility::encode_submit(
        *mti, blk, {}, nullptr, ProtocolLane::STATELESS, snap, nullptr);

    bool ok = false;
    if (result.valid && result.wire_bytes && result.wire_bytes->size() >= 2) {
        const auto& w = *result.wire_bytes;
        ok = (w[0] == 0xD0 && w[1] == 0x01);
    }
    EXPECT_TRUE(ok) << "encode_submit(): STATELESS lane produces opcode 0xD001";
}

// Test 8 -- encode_submit(): LEGACY lane -> opcode 0x01
static void test_encode_legacy_opcode() {
    auto mti  = make_loaded_mti();
    auto blk  = make_solved_block();
    auto snap = make_snapshot();
    auto result = StatelessBlockUtility::encode_submit(
        *mti, blk, {}, nullptr, ProtocolLane::LEGACY, snap, nullptr);

    bool ok = false;
    if (result.valid && result.wire_bytes && !result.wire_bytes->empty()) {
        const auto& w = *result.wire_bytes;
        ok = (w[0] == 0x01);
    }
    EXPECT_TRUE(ok) << "encode_submit(): LEGACY lane produces opcode 0x01";
}

// Test 9 -- encode_submit(): falcon=nullptr -> no signature suffix
// For Hash channel with no vOffsets, payload = 216-byte block only.
// Stateless header: 2-byte opcode + 4-byte length = 6 bytes overhead.
static void test_encode_unsigned_submit() {
    auto mti  = make_loaded_mti(2);  // Hash channel, no vOffsets
    auto blk  = make_solved_block();
    auto snap = make_snapshot();

    auto result = StatelessBlockUtility::encode_submit(
        *mti, blk, {}, nullptr, ProtocolLane::STATELESS, snap, nullptr);

    bool ok = false;
    if (result.valid && result.wire_bytes) {
        // Stateless header: 2-byte opcode + 4-byte length = 6 bytes
        // Payload for Hash channel (no vOffsets): BLOCK_BODY_SIZE (216) bytes
        size_t expected_total = 6 + StatelessBlockUtility::BLOCK_BODY_SIZE;
        ok = (result.wire_bytes->size() == expected_total);
    }
    EXPECT_TRUE(ok) << "encode_submit(): falcon=nullptr produces unsigned submit (no signature suffix)";
}

// Test 10 -- decode_template(): metadata fields from 12-byte prefix
static void test_decode_metadata_fields() {
    MiningTemplateInterface mti(2, 0);
    auto payload = make_template_payload(
        /*unified_h=*/7654321,
        /*channel_h=*/2500000,
        /*difficulty=*/0xABCD1234);
    auto result = StatelessBlockUtility::decode_template(mti, payload, 2, nullptr);
    bool ok = result.valid &&
              result.unified_height   == 7654321  &&
              result.channel_height   == 2500000;
    EXPECT_TRUE(ok) << "decode_template(): metadata fields parsed correctly from 12-byte prefix (BE)";
}

// Test 11 -- decode_template(): canonical block fields from 216-byte body
static void test_decode_block_fields() {
    MiningTemplateInterface mti(2, 0);
    auto payload = make_template_payload(
        /*unified_h=*/6000000, /*channel_h=*/2000000, /*difficulty=*/DEFAULT_DIFFICULTY,
        /*nVersion=*/8, /*nChannel=*/2, /*nHeight=*/6000001,
        /*nBits=*/DEFAULT_DIFFICULTY, /*nNonce=*/0);
    auto result = StatelessBlockUtility::decode_template(mti, payload, 2, nullptr);
    bool ok = result.valid &&
              result.block.nVersion == 8    &&
              result.block.nChannel == 2    &&
              result.block.nHeight  == 6000001 &&
              result.block.nBits    == DEFAULT_DIFFICULTY;
    EXPECT_TRUE(ok) << "decode_template(): canonical block fields from 216-byte body";
}

// Test 12 -- decode_template(): channel_consistent flag
static void test_decode_channel_consistent() {
    // mining channel 1 (Prime) but block says 2 (Hash) -> inconsistent
    MiningTemplateInterface mti(1, 0); // configured for Prime
    auto payload = make_template_payload(6000000, 2000000, 0, 8, 2, 6000001);
    auto result = StatelessBlockUtility::decode_template(mti, payload, /*mining_channel=*/1, nullptr);
    bool ok = result.valid && !result.channel_consistent;
    EXPECT_TRUE(ok) << "decode_template(): channel_consistent=false when nChannel doesn't match mining_channel";
}

// Test 13 -- encode_submit(): stale/tip-moved are warnings, not blocks
static void test_encode_stale_does_not_block() {
    auto mti  = make_loaded_mti();
    auto blk  = make_solved_block();

    // Simulate a stale snapshot: channel_height >= channel_target
    HeightTracker ht;
    ht.OnBlockDataReceived(6000000, 2000001, DEFAULT_DIFFICULTY, uint1024_t{});
    ht.OnTemplateReceived(2, 2000002);
    ht.OnBlockDataReceived(6000001, 2000002, DEFAULT_DIFFICULTY, uint1024_t{});
    auto snap = ht.GetSnapshot();

    auto result = StatelessBlockUtility::encode_submit(
        *mti, blk, {}, nullptr, ProtocolLane::STATELESS, snap, nullptr);
    EXPECT_TRUE(result.valid) << "encode_submit(): stale template is a warning, not a hard rejection";
}

// Test 14 -- Prime channel vOffsets produce larger payload than Hash channel
static void test_encode_rejects_submit_height_mismatch() {
    auto mti = make_loaded_mti();
    auto blk = make_solved_block(2, /*nHeight=*/6000002, 0xDEADBEEFCAFEBABEULL);
    auto result = StatelessBlockUtility::encode_submit(
        *mti, blk, {}, nullptr, ProtocolLane::STATELESS, make_snapshot(), nullptr,
        make_submit_context(/*template_height=*/6000001, /*chain_height=*/6000000));
    EXPECT_TRUE(!result.valid &&
                 result.rejection_reason.find("template_height=6000001") != std::string::npos &&
                 result.rejection_reason.find("submit_height=6000002") != std::string::npos) << "encode_submit(): rejects authoritative submit-height mismatch";
}

// Test 15 -- Prime channel vOffsets produce larger payload than Hash channel
static void test_encode_prime_voffsets_appended() {
    // Load a Prime-channel template (nChannel=1)
    MiningTemplateInterface mti_prime(1, 0);
    auto payload_prime = make_template_payload(6000000, 2000000, DEFAULT_DIFFICULTY,
                                               8, 1, 6000001, DEFAULT_DIFFICULTY, 0);
    mti_prime.read_stateless_payload(payload_prime, "test");

    // Load a Hash-channel template (nChannel=2)
    MiningTemplateInterface mti_hash(2, 0);
    auto payload_hash = make_template_payload(6000000, 2000000, DEFAULT_DIFFICULTY,
                                              8, 2, 6000001, DEFAULT_DIFFICULTY, 0);
    mti_hash.read_stateless_payload(payload_hash, "test");

    auto blk_prime = make_solved_block(1, 6000001, 0xDEADBEEFCAFEBABEULL);
    auto blk_hash  = make_solved_block(2, 6000001, 0xDEADBEEFCAFEBABEULL);
    auto snap = make_snapshot();

    // Canonical Prime vOffsets shape: 6 single-byte offsets + 4-byte LE fraction.
    std::vector<uint8_t> vOffsets = {0x02, 0x04, 0x06, 0x02, 0x04, 0x06, 0x10, 0x20, 0x30, 0x40};

    auto prime_result = StatelessBlockUtility::encode_submit(
        mti_prime, blk_prime, vOffsets, nullptr, ProtocolLane::STATELESS, snap, nullptr);
    auto hash_result  = StatelessBlockUtility::encode_submit(
        mti_hash, blk_hash, {}, nullptr, ProtocolLane::STATELESS, snap, nullptr);

    bool ok = prime_result.valid && hash_result.valid &&
              prime_result.wire_bytes->size() ==
                  hash_result.wire_bytes->size() + vOffsets.size();
    EXPECT_TRUE(ok) << "encode_submit(): Prime vOffsets are appended to payload (Prime payload > Hash payload by vOffsets.size())";
}

// Test 15 -- read_stateless_payload() + set_channel_height() does not trigger
// the corruption guard.  The guard fires when block.nHeight != m_last_unified_height.
// read_stateless_payload() must NOT override m_last_unified_height with the
// metadata's nUnifiedHeightMeta (which is one less than block.nHeight).
static void test_set_channel_height_no_corruption_guard() {
    MiningTemplateInterface mti(2, 0);
    // unified_height = 6000000 (metadata/chain tip)
    // block.nHeight  = 6000001 (NEXT block = unified_height + 1)
    // make_template_payload(unified_height, channel_height, difficulty,
    //                        nVersion, nChannel, nHeight,  nBits,             nNonce)
    auto payload = make_template_payload(6000000, 2000000, DEFAULT_DIFFICULTY,
                                         8,       2,       6000001, DEFAULT_DIFFICULTY, 0);
    auto result = mti.read_stateless_payload(payload, "test");
    bool template_valid = result.is_valid;

    // Now call set_channel_height() — should NOT discard the template via the
    // block.nHeight != m_last_unified_height corruption guard.
    mti.set_channel_height(2000001);  // channel_target = channel_height + 1

    // Template must still be valid after set_channel_height().
    bool still_valid = mti.has_valid_template();

    EXPECT_TRUE(template_valid && still_valid) << "read_stateless_payload() + set_channel_height(): corruption guard does NOT falsely fire (m_last_unified_height is NOT overridden)";
}

// Test 16 -- worker header bytes with nonce match raw CBlock memory hashed by node
static void test_worker_header_bytes_match_raw_block_with_nonce() {
    auto blk = make_patterned_block();
    const auto expected = get_raw_block_header_bytes(blk, false);
    const auto actual = nexusminer::GetBlockHeaderBytes(blk, false);
    EXPECT_TRUE(actual == expected && actual.size() == 216) << "GetBlockHeaderBytes(false) matches raw CBlock nVersion..nNonce bytes";
}

// Test 17 -- worker prime header bytes exclude nonce and match raw ProofHash span
static void test_worker_prime_header_bytes_match_raw_block_without_nonce() {
    auto blk = make_patterned_block();
    const auto expected = get_raw_block_header_bytes(blk, true);
    const auto actual = nexusminer::GetBlockHeaderBytes(blk, true);
    EXPECT_TRUE(actual == expected && actual.size() == 208) << "GetBlockHeaderBytes(true) matches raw CBlock nVersion..nBits bytes";
}

// Test 18 -- prime base hash uses upstream LLC::SK1024 on raw ProofHash span
static void test_worker_prime_base_hash_matches_llc_sk1024() {
    auto blk = make_patterned_block();
    // Intentional: the vector overload is the independent oracle here. It should
    // hash the same raw nVersion..nBits bytes as the BEGIN/END pointer span used
    // by GetPrimeProofHash(), without calling the production helper itself.
    const auto expected = LLC::SK1024(get_raw_block_header_bytes(blk, true));
    const auto actual = nexusminer::GetPrimeProofHash(blk);
    EXPECT_TRUE(actual == expected) << "GetPrimeProofHash() matches LLC::SK1024(raw nVersion..nBits bytes)";
}

// Test 19 -- prime base hash is nonce-independent just like node ProofHash
static void test_worker_prime_base_hash_ignores_nonce() {
    auto blk_a = make_patterned_block(0x0123456789ABCDEFULL);
    auto blk_b = blk_a;
    blk_b.nNonce = 0xFEDCBA9876543210ULL;

    EXPECT_TRUE(nexusminer::GetPrimeProofHash(blk_a) == nexusminer::GetPrimeProofHash(blk_b)) << "GetPrimeProofHash() ignores nonce changes";
}

// Test 20 -- full worker header bytes remain nonce-sensitive for hash-channel mining
static void test_worker_hash_header_bytes_include_nonce() {
    auto blk_a = make_patterned_block(0x0123456789ABCDEFULL);
    auto blk_b = blk_a;
    blk_b.nNonce = 0xFEDCBA9876543210ULL;

    EXPECT_TRUE(nexusminer::GetBlockHeaderBytes(blk_a, false) != nexusminer::GetBlockHeaderBytes(blk_b, false) &&
                 nexusminer::GetBlockHeaderBytes(blk_a, true) == nexusminer::GetBlockHeaderBytes(blk_b, true)) << "GetBlockHeaderBytes(false) changes when nonce changes";
}
