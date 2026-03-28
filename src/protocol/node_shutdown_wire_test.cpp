/**
 * @file node_shutdown_wire_test.cpp
 * @brief Unit tests for NODE_SHUTDOWN (0xD0FF) wire protocol
 *
 * Tests:
 *  1. NODE_SHUTDOWN opcode constants match expected values
 *  2. NodeShutdownFrame parses GRACEFUL reason correctly
 *  3. NodeShutdownFrame parses MAINTENANCE reason correctly
 *  4. NodeShutdownFrame rejects empty payload
 *  5. NodeShutdownFrame ReasonString() for known and unknown reasons
 *  6. NODE_SHUTDOWN_BACKOFF_S constant is 60
 *  7. NODE_SHUTDOWN is in stateless opcode range (0xD000-0xD0FF)
 *  8. matches_opcode lambda correctly matches NODE_SHUTDOWN on both lanes
 */

#include "LLP/include/colin_ping_protocol.h"
#include "LLP/miner_opcodes.hpp"
#include "LLP/llp_logging.hpp"
#include "protocol/solo.hpp"
#include <iostream>
#include <cstdint>
#include <vector>
#include <cstring>
#include <gtest/gtest.h>

using namespace LLP;

// ============================================================================
// Test 1: NODE_SHUTDOWN opcode constants match expected values
// ============================================================================
TEST(NodeShutdownWireTest, test_opcode_constants) {
    std::cout << "\nTest 1: NODE_SHUTDOWN opcode constants match expected values\n";

    // Legacy opcode: 0xFF (255)
    EXPECT_TRUE(nexusminer::LLP::NODE_SHUTDOWN == 255) << "Legacy NODE_SHUTDOWN == 255";

    // Stateless opcode: MirrorOpcode(0xFF) == 0xD0FF
    EXPECT_TRUE(nexusminer::LLP::StatelessMining::NODE_SHUTDOWN == 0xD0FF) << "Stateless NODE_SHUTDOWN == 0xD0FF";

    // MirrorOpcode round-trip
    EXPECT_TRUE(nexusminer::LLP::MirrorOpcode(nexusminer::LLP::NODE_SHUTDOWN) == 0xD0FF) << "MirrorOpcode(NODE_SHUTDOWN) == 0xD0FF";

    // UnmirrorOpcode round-trip
    EXPECT_TRUE(nexusminer::LLP::UnmirrorOpcode(0xD0FF) == 0xFF) << "UnmirrorOpcode(0xD0FF) == 0xFF";
}

// ============================================================================
// Test 2: NodeShutdownFrame parses GRACEFUL reason correctly
// ============================================================================
TEST(NodeShutdownWireTest, test_parse_graceful) {
    std::cout << "\nTest 2: NodeShutdownFrame parses GRACEFUL reason\n";

    std::vector<uint8_t> data = { NodeShutdownFrame::REASON_GRACEFUL };
    NodeShutdownFrame frame;
    bool ok = frame.Parse(data);

    EXPECT_TRUE(ok) << "Parse succeeds";
    EXPECT_TRUE(frame.reason == NodeShutdownFrame::REASON_GRACEFUL) << "reason == REASON_GRACEFUL (0x01)";
    EXPECT_TRUE(std::strcmp(frame.ReasonString(), "GRACEFUL") == 0) << "ReasonString() == \"GRACEFUL\"";
}

// ============================================================================
// Test 3: NodeShutdownFrame parses MAINTENANCE reason correctly
// ============================================================================
TEST(NodeShutdownWireTest, test_parse_maintenance) {
    std::cout << "\nTest 3: NodeShutdownFrame parses MAINTENANCE reason\n";

    std::vector<uint8_t> data = { NodeShutdownFrame::REASON_MAINTENANCE };
    NodeShutdownFrame frame;
    bool ok = frame.Parse(data);

    EXPECT_TRUE(ok) << "Parse succeeds";
    EXPECT_TRUE(frame.reason == NodeShutdownFrame::REASON_MAINTENANCE) << "reason == REASON_MAINTENANCE (0x02)";
    EXPECT_TRUE(std::strcmp(frame.ReasonString(), "MAINTENANCE") == 0) << "ReasonString() == \"MAINTENANCE\"";
}

// ============================================================================
// Test 4: NodeShutdownFrame rejects empty payload
// ============================================================================
TEST(NodeShutdownWireTest, test_parse_empty_payload) {
    std::cout << "\nTest 4: NodeShutdownFrame rejects empty payload\n";

    std::vector<uint8_t> data;
    NodeShutdownFrame frame;
    bool ok = frame.Parse(data);

    EXPECT_TRUE(!ok) << "Parse fails on empty data";
    EXPECT_TRUE(frame.reason == 0) << "reason remains 0 (default)";
}

// ============================================================================
// Test 5: ReasonString() for unknown reason codes
// ============================================================================
TEST(NodeShutdownWireTest, test_reason_string_unknown) {
    std::cout << "\nTest 5: ReasonString() for unknown reason codes\n";

    NodeShutdownFrame frame;
    frame.reason = 0x00;
    EXPECT_TRUE(std::strcmp(frame.ReasonString(), "UNKNOWN") == 0) << "reason=0x00 → \"UNKNOWN\"";

    frame.reason = 0xFF;
    EXPECT_TRUE(std::strcmp(frame.ReasonString(), "UNKNOWN") == 0) << "reason=0xFF → \"UNKNOWN\"";

    frame.reason = 0x03;
    EXPECT_TRUE(std::strcmp(frame.ReasonString(), "UNKNOWN") == 0) << "reason=0x03 → \"UNKNOWN\"";
}

// ============================================================================
// Test 6: NODE_SHUTDOWN_BACKOFF_S constant is 60
// ============================================================================
TEST(NodeShutdownWireTest, test_backoff_constant) {
    std::cout << "\nTest 6: NODE_SHUTDOWN_BACKOFF_S constant is 60\n";

    EXPECT_TRUE(nexusminer::protocol::Solo::NODE_SHUTDOWN_BACKOFF_S == 60) << "NODE_SHUTDOWN_BACKOFF_S == 60";
}

// ============================================================================
// Test 7: NODE_SHUTDOWN is in stateless opcode range
// ============================================================================
TEST(NodeShutdownWireTest, test_stateless_range) {
    std::cout << "\nTest 7: NODE_SHUTDOWN is in stateless opcode range\n";

    EXPECT_TRUE(nexusminer::LLP::IsStatelessOpcode(0xD0FF)) << "IsStatelessOpcode(0xD0FF) == true";

    EXPECT_TRUE(0xD0FF >= 0xD000) << "0xD0FF >= 0xD000";
    EXPECT_TRUE(0xD0FF <= 0xD0FF) << "0xD0FF <= 0xD0FF";
}

// ============================================================================
// Test 8: Logging name resolution for NODE_SHUTDOWN
// ============================================================================
TEST(NodeShutdownWireTest, test_logging_names) {
    std::cout << "\nTest 8: Logging name resolution for NODE_SHUTDOWN\n";

    // Legacy name
    const char* legacy_name = nexusminer::get_llp_header_name(static_cast<uint8_t>(0xFF));
    EXPECT_TRUE(std::strcmp(legacy_name, "NODE_SHUTDOWN") == 0) << "Legacy 0xFF → \"NODE_SHUTDOWN\"";

    // Stateless name
    const char* stateless_name = nexusminer::get_llp_header_name(static_cast<uint16_t>(0xD0FF));
    std::string sname(stateless_name);
    EXPECT_TRUE(sname.find("NODE_SHUTDOWN") != std::string::npos) << "Stateless 0xD0FF → contains \"NODE_SHUTDOWN\"";
}

// ============================================================================
// Test 9: ShutdownReason enum values match NodeShutdownFrame constants
// ============================================================================
TEST(NodeShutdownWireTest, test_shutdown_reason_enum) {
    std::cout << "\nTest 9: ShutdownReason enum values match frame constants\n";

    EXPECT_TRUE(static_cast<uint8_t>(nexusminer::LLP::StatelessMining::ShutdownReason::GRACEFUL)
            == NodeShutdownFrame::REASON_GRACEFUL) << "ShutdownReason::GRACEFUL == REASON_GRACEFUL";

    EXPECT_TRUE(static_cast<uint8_t>(nexusminer::LLP::StatelessMining::ShutdownReason::MAINTENANCE)
            == NodeShutdownFrame::REASON_MAINTENANCE) << "ShutdownReason::MAINTENANCE == REASON_MAINTENANCE";
}
