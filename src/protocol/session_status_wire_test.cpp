/**
 * @file session_status_wire_test.cpp
 * @brief Unit tests for SESSION_STATUS / SESSION_STATUS_ACK wire protocol
 *
 * Tests:
 *  1. SessionStatusFrame serializes and round-trips correctly
 *  2. SessionStatusAckFrame parses correctly
 *  3. SessionStatusAckFrame rejects short buffer
 *  4. SESSION_STATUS opcode constants match LLL-TAO values
 *  5. SessionStatusAckFrame helper predicates work correctly
 *  6. IsSessionStatusOpcode() helper function
 */

#include "LLP/include/colin_ping_protocol.h"
#include "protocol/session_ingress_gate.hpp"
#include "protocol_lane.hpp"
#include <iostream>
#include <cstdint>
#include <vector>
#include <gtest/gtest.h>

using namespace LLP;
using namespace nexusminer;
using namespace nexusminer::protocol;

// ============================================================================
// Test 1: SessionStatusFrame serializes and round-trips correctly
// ============================================================================
TEST(SessionStatusWireTest, test_session_status_frame_serialize_roundtrip) {
    std::cout << "\nTest 1: SessionStatusFrame serializes and round-trips correctly\n";

    SessionStatusFrame frame;
    frame.session_id   = 0xABCD1234;
    frame.status_flags = SessionStatusOpcodes::MINER_HAS_TEMPLATE
                       | SessionStatusOpcodes::MINER_WORKERS_ACTIVE;

    auto v = frame.Serialize();
    EXPECT_TRUE(v.size() == 8) << "Serialize() produces 8 bytes";

    // session_id little-endian
    EXPECT_TRUE(v[0] == 0x34) << "v[0] == 0x34 (LE LSB of 0xABCD1234)";
    EXPECT_TRUE(v[1] == 0x12) << "v[1] == 0x12";
    EXPECT_TRUE(v[2] == 0xCD) << "v[2] == 0xCD";
    EXPECT_TRUE(v[3] == 0xAB) << "v[3] == 0xAB (LE MSB)";

    // status_flags = MINER_HAS_TEMPLATE|MINER_WORKERS_ACTIVE = 0x06 big-endian
    uint32_t expected_flags = SessionStatusOpcodes::MINER_HAS_TEMPLATE
                            | SessionStatusOpcodes::MINER_WORKERS_ACTIVE;
    EXPECT_TRUE(v[4] == 0x00) << "v[4] == 0x00 (BE MSB of flags)";
    EXPECT_TRUE(v[5] == 0x00) << "v[5] == 0x00";
    EXPECT_TRUE(v[6] == 0x00) << "v[6] == 0x00";
    EXPECT_TRUE(v[7] == static_cast<uint8_t>(expected_flags & 0xFF)) << "v[7] == flags_lsb";

    // Round-trip
    SessionStatusFrame f2;
    EXPECT_TRUE(f2.Parse(v)) << "Parse() returns true on 8-byte buffer";
    EXPECT_TRUE(f2.session_id   == frame.session_id) << "Round-trip session_id";
    EXPECT_TRUE(f2.status_flags == frame.status_flags) << "Round-trip status_flags";
}

// ============================================================================
// Test 2: SessionStatusAckFrame parses correctly
// ============================================================================
TEST(SessionStatusWireTest, test_session_status_ack_parse) {
    std::cout << "\nTest 2: SessionStatusAckFrame parses correctly\n";

    // Manually construct a 16-byte ACK payload
    std::vector<uint8_t> raw = {
        // session_id: 0xDEADBEEF LE
        0xEF, 0xBE, 0xAD, 0xDE,
        // lane_health: PRIMARY | AUTHENTICATED = 0x09 BE
        0x00, 0x00, 0x00, 0x09,
        // uptime: 999 = 0x000003E7 BE
        0x00, 0x00, 0x03, 0xE7,
        // echo flags: MINER_HAS_TEMPLATE = 0x02 BE
        0x00, 0x00, 0x00, 0x02
    };

    SessionStatusAckFrame ack;
    EXPECT_TRUE(ack.Parse(raw)) << "Parse() returns true for 16-byte buffer";
    EXPECT_TRUE(ack.session_id == 0xDEADBEEFu) << "session_id == 0xDEADBEEF";
    EXPECT_TRUE(ack.lane_health_flags == 0x09u) << "lane_health_flags == 0x09";
    EXPECT_TRUE(ack.uptime_seconds == 999u) << "uptime_seconds == 999";
    EXPECT_TRUE(ack.status_echo_flags == 0x02u) << "status_echo_flags == 0x02";

    EXPECT_TRUE(ack.IsPrimaryAlive()) << "IsPrimaryAlive() == true";
    EXPECT_TRUE(!ack.IsSecondaryAlive()) << "IsSecondaryAlive() == false";
    EXPECT_TRUE(!ack.IsSimLinkActive()) << "IsSimLinkActive() == false";
    EXPECT_TRUE(ack.IsAuthenticated()) << "IsAuthenticated() == true";
}

// ============================================================================
// Test 3: SessionStatusAckFrame rejects short buffer
// ============================================================================
TEST(SessionStatusWireTest, test_session_status_ack_rejects_short_buffer) {
    std::cout << "\nTest 3: SessionStatusAckFrame rejects short buffer\n";

    SessionStatusAckFrame ack;
    std::vector<uint8_t> short_buf(15, 0x00);
    EXPECT_TRUE(!ack.Parse(short_buf)) << "Parse() returns false for 15-byte buffer";

    std::vector<uint8_t> empty_buf;
    EXPECT_TRUE(!ack.Parse(empty_buf)) << "Parse() returns false for empty buffer";

    std::vector<uint8_t> ok_buf(16, 0x00);
    EXPECT_TRUE(ack.Parse(ok_buf)) << "Parse() returns true for 16-byte buffer";
}

// ============================================================================
// Test 4: SESSION_STATUS opcode constants match LLL-TAO values
// ============================================================================
TEST(SessionStatusWireTest, test_session_status_opcode_constants) {
    std::cout << "\nTest 4: SESSION_STATUS opcode constants match LLL-TAO values\n";

    EXPECT_TRUE(SessionStatusOpcodes::SESSION_STATUS_LEGACY == 219u) << "SESSION_STATUS_LEGACY == 219";
    EXPECT_TRUE(SessionStatusOpcodes::SESSION_STATUS_ACK_LEGACY == 220u) << "SESSION_STATUS_ACK_LEGACY == 220";
    EXPECT_TRUE(SessionStatusOpcodes::SESSION_STATUS == 0xD0DBu) << "SESSION_STATUS == 0xD0DB";
    EXPECT_TRUE(SessionStatusOpcodes::SESSION_STATUS_ACK == 0xD0DCu) << "SESSION_STATUS_ACK == 0xD0DC";

    EXPECT_TRUE(SessionStatusOpcodes::REQUEST_PAYLOAD_SIZE == 8u) << "REQUEST_PAYLOAD_SIZE == 8";
    EXPECT_TRUE(SessionStatusOpcodes::ACK_PAYLOAD_SIZE == 16u) << "ACK_PAYLOAD_SIZE == 16";
}

// ============================================================================
// Test 5: SessionStatusAckFrame helper predicates cover all flags
// ============================================================================
TEST(SessionStatusWireTest, test_session_status_ack_predicates) {
    std::cout << "\nTest 5: SessionStatusAckFrame predicates cover all lane flags\n";

    // lane_health_flags = 0x0F (all four bits set)
    std::vector<uint8_t> raw(16, 0);
    raw[7] = 0x0F;  // BE LSB

    SessionStatusAckFrame ack;
    ack.Parse(raw);
    EXPECT_TRUE(ack.IsPrimaryAlive()) << "All flags set: IsPrimaryAlive()";
    EXPECT_TRUE(ack.IsSecondaryAlive()) << "All flags set: IsSecondaryAlive()";
    EXPECT_TRUE(ack.IsSimLinkActive()) << "All flags set: IsSimLinkActive()";
    EXPECT_TRUE(ack.IsAuthenticated()) << "All flags set: IsAuthenticated()";

    // lane_health_flags = 0x00 (no flags set)
    raw[7] = 0x00;
    ack.Parse(raw);
    EXPECT_TRUE(!ack.IsPrimaryAlive()) << "No flags set: IsPrimaryAlive() == false";
    EXPECT_TRUE(!ack.IsSecondaryAlive()) << "No flags set: IsSecondaryAlive() == false";
    EXPECT_TRUE(!ack.IsSimLinkActive()) << "No flags set: IsSimLinkActive() == false";
    EXPECT_TRUE(!ack.IsAuthenticated()) << "No flags set: IsAuthenticated() == false";
}

// ============================================================================
// Test 6: IsSessionStatusOpcode() helper
// ============================================================================
TEST(SessionStatusWireTest, test_is_session_status_opcode) {
    std::cout << "\nTest 6: IsSessionStatusOpcode() helper\n";

    EXPECT_TRUE(IsSessionStatusOpcode(SessionStatusOpcodes::SESSION_STATUS)) << "IsSessionStatusOpcode(SESSION_STATUS) == true";
    EXPECT_TRUE(IsSessionStatusOpcode(SessionStatusOpcodes::SESSION_STATUS_ACK)) << "IsSessionStatusOpcode(SESSION_STATUS_ACK) == true";
    EXPECT_TRUE(!IsSessionStatusOpcode(0xD0D4)) << "IsSessionStatusOpcode(0xD0D4) == false";
    EXPECT_TRUE(!IsSessionStatusOpcode(0xD100)) << "IsSessionStatusOpcode(0xD100) == false";
    EXPECT_TRUE(!IsSessionStatusOpcode(0x0000)) << "IsSessionStatusOpcode(0x0000) == false";
}

// ============================================================================
// Test 7: SessionStatusFrame PAYLOAD_SIZE constant
// ============================================================================
TEST(SessionStatusWireTest, test_session_status_frame_payload_size) {
    std::cout << "\nTest 7: SessionStatusFrame PAYLOAD_SIZE constant\n";
    EXPECT_TRUE(SessionStatusFrame::PAYLOAD_SIZE == 8u) << "SessionStatusFrame::PAYLOAD_SIZE == 8";
    EXPECT_TRUE(SessionStatusAckFrame::PAYLOAD_SIZE == 16u) << "SessionStatusAckFrame::PAYLOAD_SIZE == 16";
}

// ============================================================================
// Test 8: shared ingress gate rejects stale owner generation
// ============================================================================
TEST(SessionStatusWireTest, test_session_ingress_gate_rejects_stale_owner_generation) {
    std::cout << "\nTest 8: Session ingress gate rejects stale owner generation\n";

    const auto decision = SessionIngressGate::preflight(SessionIngressGate::Input{
        true,               // has_authoritative_session
        true,               // authoritative_authenticated
        0x22222222u,        // authoritative_session_id
        uint64_t{7},        // authoritative_session_epoch
        ProtocolLane::STATELESS,  // authoritative_lane
        ProtocolLane::STATELESS,  // packet_lane
        true,               // validate_lane
        false,              // allow_without_active_session
        0x22222222u,        // packet_session_id
        uint64_t{6},        // owner_epoch (stale: 6 vs authoritative 7)
        0x22222222u         // owner_session_id
    });

    EXPECT_TRUE(!decision.allow_processing) << "stale owner epoch is rejected";
    EXPECT_TRUE(decision.drop_as_stale) << "stale owner epoch is marked stale";
    EXPECT_TRUE(!decision.force_reauth) << "stale owner epoch does not force reauth";
    EXPECT_TRUE(decision.reason.find("ownership epoch") != std::string::npos) << "stale owner epoch reason mentions ownership epoch";
}

// ============================================================================
// Test 9: shared ingress gate — crypto readiness check removed (no-op)
// ============================================================================
TEST(SessionStatusWireTest, test_session_ingress_gate_requires_crypto_context_when_requested) {
    std::cout << "\nTest 9: Session ingress gate — crypto readiness check removed (no-op)\n";

    // require_crypto_ready is removed from the new design.
    // An authenticated session with matching ownership stamp should pass.
    const auto decision = SessionIngressGate::preflight(SessionIngressGate::Input{
        true,               // has_authoritative_session
        true,               // authoritative_authenticated
        0x01020304u,        // authoritative_session_id
        uint64_t{3},        // authoritative_session_epoch
        ProtocolLane::STATELESS,
        ProtocolLane::STATELESS,
        true,               // validate_lane
        false,              // allow_without_active_session
        0,                  // packet_session_id (no mismatch)
        uint64_t{3},        // owner_epoch (matches)
        0x01020304u         // owner_session_id (matches)
    });

    // Feature removed: crypto check no longer blocks processing
    EXPECT_TRUE(decision.allow_processing) << "crypto check removed: session passes";
    EXPECT_TRUE(!decision.force_reauth) << "crypto check removed: no force reauth";
    EXPECT_TRUE(!decision.reason.empty()) << "crypto check removed: reason is set";
}

// ============================================================================
// Test 10: shared ingress gate rejects packet session id mismatches
// ============================================================================
TEST(SessionStatusWireTest, test_session_ingress_gate_rejects_stale_packet_session_id) {
    std::cout << "\nTest 10: Session ingress gate rejects stale packet session ids\n";

    const auto decision = SessionIngressGate::preflight(SessionIngressGate::Input{
        true,               // has_authoritative_session
        true,               // authoritative_authenticated
        0x11112222u,        // authoritative_session_id
        uint64_t{4},        // authoritative_session_epoch
        ProtocolLane::STATELESS,
        ProtocolLane::STATELESS,
        true,               // validate_lane
        false,              // allow_without_active_session
        0x33334444u,        // packet_session_id (mismatched)
        uint64_t{4},        // owner_epoch
        0x11112222u         // owner_session_id
    });

    EXPECT_TRUE(!decision.allow_processing) << "stale packet session ID is rejected";
    EXPECT_TRUE(decision.drop_as_stale) << "stale packet session ID is marked stale";
    EXPECT_TRUE(decision.mark_degraded) << "stale packet session ID marks session degraded";
    EXPECT_TRUE(decision.reason.find("session id") != std::string::npos) << "stale packet session ID reason mentions session ID";
}

// ============================================================================
// Test 11: shared ingress gate rejects owner/session mismatches
// ============================================================================
TEST(SessionStatusWireTest, test_session_ingress_gate_rejects_stale_owner_session_id) {
    std::cout << "\nTest 11: Session ingress gate rejects stale owner session ids\n";

    const auto decision = SessionIngressGate::preflight(SessionIngressGate::Input{
        true,               // has_authoritative_session
        true,               // authoritative_authenticated
        0x01020304u,        // authoritative_session_id
        uint64_t{9},        // authoritative_session_epoch
        ProtocolLane::STATELESS,
        ProtocolLane::STATELESS,
        true,               // validate_lane
        false,              // allow_without_active_session
        0x01020304u,        // packet_session_id (matches)
        uint64_t{9},        // owner_epoch (matches)
        0xA0B0C0D0u         // owner_session_id (mismatches)
    });

    EXPECT_TRUE(!decision.allow_processing) << "stale owner session ID is rejected";
    EXPECT_TRUE(decision.drop_as_stale) << "stale owner session ID is marked stale";
    EXPECT_TRUE(decision.reason.find("ownership session id") != std::string::npos) << "stale owner session ID reason mentions owner session ID";
}

// ============================================================================
// Test 12: shared ingress gate enforces lane readiness
// ============================================================================
TEST(SessionStatusWireTest, test_session_ingress_gate_rejects_lane_mismatch) {
    std::cout << "\nTest 12: Session ingress gate rejects lane mismatches\n";

    const auto decision = SessionIngressGate::preflight(SessionIngressGate::Input{
        true,               // has_authoritative_session
        true,               // authoritative_authenticated
        0x0A0B0C0Du,        // authoritative_session_id
        uint64_t{2},        // authoritative_session_epoch
        ProtocolLane::STATELESS,  // authoritative_lane
        ProtocolLane::LEGACY,     // packet_lane (mismatched)
        true,               // validate_lane
        false,              // allow_without_active_session
        0x0A0B0C0Du,        // packet_session_id
        uint64_t{2},        // owner_epoch
        0x0A0B0C0Du         // owner_session_id
    });

    EXPECT_TRUE(!decision.allow_processing) << "lane mismatch is rejected";
    EXPECT_TRUE(!decision.drop_as_stale) << "lane mismatch is not treated as stale";
    EXPECT_TRUE(decision.mark_degraded) << "lane mismatch marks session degraded";
    EXPECT_TRUE(decision.reason.find("lane") != std::string::npos) << "lane mismatch reason mentions lane";
}

// ============================================================================
// Test 13: shared ingress gate forces reauth when auth is required
// ============================================================================
TEST(SessionStatusWireTest, test_session_ingress_gate_requires_authenticated_session) {
    std::cout << "\nTest 13: Session ingress gate forces re-auth for unauthenticated sessions\n";

    const auto decision = SessionIngressGate::preflight(SessionIngressGate::Input{
        true,               // has_authoritative_session
        false,              // authoritative_authenticated = false
        0x55667788u,        // authoritative_session_id
        uint64_t{5},        // authoritative_session_epoch
        ProtocolLane::STATELESS,
        ProtocolLane::STATELESS,
        true,               // validate_lane
        false,              // allow_without_active_session
        0x55667788u,        // packet_session_id
        uint64_t{5},        // owner_epoch
        0x55667788u         // owner_session_id
    });

    EXPECT_TRUE(!decision.allow_processing) << "unauthenticated authoritative session is rejected";
    EXPECT_TRUE(decision.force_reauth) << "unauthenticated authoritative session forces reauth";
    EXPECT_TRUE(decision.mark_degraded) << "unauthenticated authoritative session marks session degraded";
    EXPECT_TRUE(decision.reason.find("not authenticated") != std::string::npos) << "unauthenticated authoritative session reason mentions authentication";
}

// ============================================================================
// main
// ============================================================================
