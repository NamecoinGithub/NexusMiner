/**
 * @file legacy_lane_wire_contract_test.cpp
 * @brief NexusMiner-side wire-contract assertion for the LEGACY (port-8323) lane
 *
 * Background:
 *   Production logs from the upstream Nexus core node show that legacy-lane
 *   `MINER_READY` (0xD8) and `GET_BLOCK` (0x81) frames are being misrouted by
 *   the node's dispatcher into the stateless 0xD0xx handler tables, which
 *   then fail the preflight session-state gate and reject the connection.
 *   See docs/diagnostics/legacy-lane-node-bug.md for the full analysis.
 *
 *   This test pins the *miner side* of the contract: it proves that the
 *   bytes NexusMiner emits on a port-8323 connection are exactly what
 *   docs/PROTOCOL_LANES.md specifies, and in particular that the 0xD0
 *   mirror-mapped two-byte header NEVER appears on a LEGACY frame.
 *
 *   Strategy: assert against PacketBuilder, which is the SSOT used by
 *   Solo for every outbound packet (see src/protocol/src/protocol/solo.cpp:
 *   1351, 1502, 1563, 2049). Solo never constructs wire bytes by any
 *   other path, so PacketBuilder fully determines the on-wire format.
 *
 * Tests:
 *   1. MINER_READY on LEGACY  →  exactly [0xD8][00 00 00 00]
 *   2. GET_BLOCK   on LEGACY  →  exactly [0x81][00 00 00 00]
 *   3. Lane-leak detector — for every push-handshake opcode used on the
 *      LEGACY lane, the encoded frame begins with the 1-byte legacy
 *      opcode and NEVER produces a 0xD0xx two-byte stateless header.
 *   4. Length-prefixed payload framing on LEGACY uses the 1-byte opcode
 *      header (no mirror prefix).
 */

#include "protocol/packet_builder.hpp"
#include "protocol_lane.hpp"
#include "miner_opcodes.hpp"

#include <array>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <iostream>
#include <vector>

using namespace nexusminer;
using namespace nexusminer::protocol;

namespace {

int tests_run    = 0;
int tests_passed = 0;
int tests_failed = 0;

void record(const char* name, bool ok)
{
    ++tests_run;
    if (ok) {
        ++tests_passed;
        std::cout << "  [PASS] " << name << "\n";
    } else {
        ++tests_failed;
        std::cout << "  [FAIL] " << name << "\n";
    }
}

// Format a single byte as "0xNN" for diagnostics.
std::string hex_byte(uint8_t b)
{
    char buf[8];
    std::snprintf(buf, sizeof(buf), "0x%02x", b);
    return buf;
}

// Dump a byte vector as space-separated hex, capped to keep output tidy.
std::string dump(const std::vector<uint8_t>& bytes, std::size_t max_bytes = 32)
{
    std::string out;
    const std::size_t n = bytes.size() < max_bytes ? bytes.size() : max_bytes;
    for (std::size_t i = 0; i < n; ++i) {
        if (i) out += ' ';
        out += hex_byte(bytes[i]);
    }
    if (bytes.size() > max_bytes) out += " ...";
    return out;
}

// Assert encoded frame begins with the 1-byte legacy opcode and is followed
// by the 4-byte big-endian zero length field.  Returns true on success and
// emits a diagnostic on failure.
bool assert_legacy_zero_length(const char* opcode_label, uint8_t opcode,
                               const network::Shared_payload& bytes)
{
    if (!bytes) {
        std::cout << "    " << opcode_label << ": PacketBuilder returned null\n";
        return false;
    }
    if (bytes->size() != 5) {
        std::cout << "    " << opcode_label << ": expected 5 bytes, got " << bytes->size()
                  << " — " << dump(*bytes) << "\n";
        return false;
    }
    if ((*bytes)[0] != opcode) {
        std::cout << "    " << opcode_label << ": opcode mismatch — expected "
                  << hex_byte(opcode) << ", got " << hex_byte((*bytes)[0]) << "\n";
        return false;
    }
    for (std::size_t i = 1; i < 5; ++i) {
        if ((*bytes)[i] != 0x00) {
            std::cout << "    " << opcode_label << ": length byte " << i
                      << " not zero — got " << hex_byte((*bytes)[i]) << "\n";
            return false;
        }
    }
    return true;
}

// Lane-leak detector — return true if the encoded LEGACY frame begins with
// the 0xD0 mirror prefix (which would indicate a stateless two-byte header
// leaked onto a legacy connection).  This is the exact condition the
// upstream node bug attempts to dispatch on.
bool starts_with_stateless_mirror(const network::Shared_payload& bytes)
{
    return bytes && bytes->size() >= 2 && (*bytes)[0] == 0xD0;
}

// =========================================================================
// Test 1 — MINER_READY on LEGACY emits exactly [0xD8][00 00 00 00]
// Citation: src/LLP/miner_opcodes.hpp:285  (MINER_READY = 216 = 0xD8)
// Citation: docs/PROTOCOL_LANES.md  (Zero-Length Framing Requirement)
// =========================================================================
void test_miner_ready_legacy_wire()
{
    std::cout << "\nTest 1: LEGACY MINER_READY → [0xD8][00 00 00 00]\n";
    auto bytes = PacketBuilder::build(ProtocolLane::LEGACY, LLP::MINER_READY);
    bool ok = assert_legacy_zero_length("MINER_READY (0xD8)",
                                        static_cast<uint8_t>(LLP::MINER_READY), bytes);
    record("LEGACY MINER_READY byte-exact wire format", ok);
}

// =========================================================================
// Test 2 — GET_BLOCK on LEGACY emits exactly [0x81][00 00 00 00]
// Citation: src/LLP/miner_opcodes.hpp:105  (GET_BLOCK = 129 = 0x81)
// Citation: docs/PROTOCOL_LANES.md  (Zero-Length Framing Requirement)
// =========================================================================
void test_get_block_legacy_wire()
{
    std::cout << "\nTest 2: LEGACY GET_BLOCK → [0x81][00 00 00 00]\n";
    auto bytes = PacketBuilder::build(ProtocolLane::LEGACY, LLP::GET_BLOCK);
    bool ok = assert_legacy_zero_length("GET_BLOCK (0x81)",
                                        static_cast<uint8_t>(LLP::GET_BLOCK), bytes);
    record("LEGACY GET_BLOCK byte-exact wire format", ok);
}

// =========================================================================
// Test 3 — Lane-leak detector
//
// For every opcode the miner can legitimately emit during the LEGACY
// push-handshake flow, assert:
//   (a) the encoded frame begins with the SAME 1-byte legacy opcode value
//       (no mirror prefix);
//   (b) byte 0 is never 0xD0 (which would be a stateless two-byte header).
//
// This is the exact pre-condition the upstream node dispatcher *should*
// rely on but currently violates (see docs/diagnostics/legacy-lane-node-bug.md
// Bug B).  If this test ever starts failing, the miner has begun emitting
// stateless framing on a legacy connection — which would be a regression
// that would *mask* the upstream bug rather than expose it.
// =========================================================================
void test_legacy_lane_leak_detector()
{
    std::cout << "\nTest 3: LEGACY lane-leak detector — no 0xD0xx header on any handshake opcode\n";

    // Push-handshake opcodes the miner emits on a LEGACY connection.
    // Each entry is { legacy opcode, label, has_payload }.
    struct OpcodeCase {
        uint8_t opcode;
        const char* label;
        bool with_payload;
    };
    const std::array<OpcodeCase, 9> cases = {{
        // Header-only request/notification frames
        { LLP::GET_BLOCK,            "GET_BLOCK   (0x81)", false },
        { LLP::MINER_READY,          "MINER_READY (0xD8)", false },
        { LLP::GET_ROUND,            "GET_ROUND   (0x85)", false },
        { LLP::PING,                 "PING        (0xFD)", false },
        // Data-bearing handshake frames
        { LLP::SET_CHANNEL,          "SET_CHANNEL (0x03)", true  },
        { LLP::SUBMIT_BLOCK,         "SUBMIT_BLOCK(0x01)", true  },
        { LLP::MINER_AUTH_INIT,      "MINER_AUTH_INIT(0xCF)", true },
        { LLP::MINER_AUTH_RESPONSE,  "MINER_AUTH_RESP(0xD1)", true },
        { LLP::MINER_SET_REWARD,     "MINER_SET_REWARD(0xD5)", true },
    }};

    bool overall_ok = true;
    const std::vector<uint8_t> sample_payload(8, 0x5A);

    for (auto const& c : cases) {
        auto bytes = c.with_payload
                         ? PacketBuilder::build(ProtocolLane::LEGACY, c.opcode, sample_payload)
                         : PacketBuilder::build(ProtocolLane::LEGACY, c.opcode);

        if (!bytes || bytes->empty()) {
            std::cout << "    " << c.label << ": PacketBuilder returned empty payload\n";
            overall_ok = false;
            continue;
        }

        // Guard (a) — first byte must be the legacy opcode itself.
        if ((*bytes)[0] != c.opcode) {
            std::cout << "    " << c.label
                      << ": first byte mismatch — expected " << hex_byte(c.opcode)
                      << ", got " << hex_byte((*bytes)[0])
                      << " — frame=" << dump(*bytes) << "\n";
            overall_ok = false;
        }

        // Guard (b) — explicit lane-leak detector.  This is the assertion
        // that ties this test to the upstream node bug: a 0xD0 lead byte
        // on a LEGACY frame would be the exact stateless mirror header
        // the buggy node dispatcher routes on.
        if (starts_with_stateless_mirror(bytes)) {
            std::cout << "    " << c.label
                      << ": LANE LEAK — frame begins with stateless mirror prefix 0xD0!"
                      << " frame=" << dump(*bytes) << "\n";
            overall_ok = false;
        }
    }

    record("LEGACY lane-leak detector across all push-handshake opcodes", overall_ok);
}

// =========================================================================
// Test 4 — LEGACY length-prefixed payload uses 1-byte opcode header
// (regression guard against accidentally widening the LEGACY header to two
//  bytes, which would silently invalidate the upstream node's parser even
//  if it were correctly implemented).
// =========================================================================
void test_legacy_payload_header_width()
{
    std::cout << "\nTest 4: LEGACY length-prefixed frame uses 1-byte opcode header\n";

    const std::vector<uint8_t> payload(16, 0xA5);
    auto bytes = PacketBuilder::build(ProtocolLane::LEGACY, LLP::SUBMIT_BLOCK, payload);

    bool ok = bytes && bytes->size() == (1 + 4 + payload.size());
    if (ok) {
        ok = ok && ((*bytes)[0] == LLP::SUBMIT_BLOCK);          // 1-byte opcode
        ok = ok && ((*bytes)[1] == 0x00);                        // length BE
        ok = ok && ((*bytes)[2] == 0x00);
        ok = ok && ((*bytes)[3] == 0x00);
        ok = ok && ((*bytes)[4] == static_cast<uint8_t>(payload.size()));
        ok = ok && !starts_with_stateless_mirror(bytes);         // never 0xD0xx
    }
    if (!ok && bytes) {
        std::cout << "    SUBMIT_BLOCK (0x01) frame=" << dump(*bytes) << "\n";
    }
    record("LEGACY SUBMIT_BLOCK(payload) header is 1 byte (no 0xD0 mirror)", ok);
}

} // namespace

int main()
{
    std::cout << "=========================================================\n";
    std::cout << "Legacy-lane wire contract test\n";
    std::cout << "Pins NexusMiner's port-8323 wire output against\n";
    std::cout << "docs/PROTOCOL_LANES.md and docs/diagnostics/legacy-lane-node-bug.md\n";
    std::cout << "=========================================================\n";

    test_miner_ready_legacy_wire();
    test_get_block_legacy_wire();
    test_legacy_lane_leak_detector();
    test_legacy_payload_header_width();

    std::cout << "\n---------------------------------------------------------\n";
    std::cout << "Run:    " << tests_run << "\n";
    std::cout << "Passed: " << tests_passed << "\n";
    std::cout << "Failed: " << tests_failed << "\n";
    std::cout << "---------------------------------------------------------\n";

    return tests_failed == 0 ? 0 : 1;
}
