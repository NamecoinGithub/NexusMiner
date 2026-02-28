/**
 * @file phase2b_update_height_test.cpp
 * @brief Phase 2B regression tests for unified height-state update path
 *
 * Tests:
 *  1. PushNotificationHandler passes correct parsed values to update_height_fn
 *     (not template header nHeight, which is channel_target in stateless templates).
 *  2. update_height_fn (callback) is invoked with the exact unified_height,
 *     channel_height, and difficulty_nbits from the 12-byte push payload.
 *  3. HeightTracker reflects the values delivered to update_height_fn.
 *  4. ClientChannelManager is updated with the same values as HeightTracker
 *     when UpdateFromGetRound is called with identical data.
 *  5. Fork detection works after ClientChannelManager update.
 */

#include "protocol/push_notification_handler.hpp"
#include "protocol/height_tracker.hpp"
#include "mining/client_channel_manager.h"
#include "miner_opcodes.hpp"
#include <iostream>
#include <vector>
#include <cstdint>
#include <cassert>
#include <functional>
#include <optional>

using namespace nexusminer;
using namespace nexusminer::protocol;
using namespace nexusminer::mining;

// Test statistics
static int tests_run    = 0;
static int tests_passed = 0;
static int tests_failed = 0;

void print_test_result(const char* name, bool passed)
{
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
// Helpers to build a 12-byte push notification packet
// ============================================================================

// Extract byte `i` (0=MSB) from a big-endian uint32_t
static uint8_t be_byte(uint32_t v, int i) { return (v >> (24 - 8*i)) & 0xFF; }

static Packet make_push_packet(uint32_t unified_h, uint32_t channel_h, uint32_t difficulty,
                                bool use_16bit_opcode = false)
{
    Packet pkt;
    pkt.m_header = use_16bit_opcode
        ? nexusminer::LLP::MirrorOpcode(nexusminer::LLP::PRIME_BLOCK_AVAILABLE)
        : static_cast<uint16_t>(nexusminer::LLP::PRIME_BLOCK_AVAILABLE);
    pkt.m_is_uint16_opcode = use_16bit_opcode;
    pkt.m_length = 12;
    pkt.m_data = std::make_shared<network::Payload>(network::Payload{
        be_byte(unified_h, 0), be_byte(unified_h, 1),
        be_byte(unified_h, 2), be_byte(unified_h, 3),
        be_byte(channel_h, 0), be_byte(channel_h, 1),
        be_byte(channel_h, 2), be_byte(channel_h, 3),
        be_byte(difficulty, 0), be_byte(difficulty, 1),
        be_byte(difficulty, 2), be_byte(difficulty, 3),
    });
    return pkt;
}

// ============================================================================
// Test 1: update_height_fn receives exact values from push notification payload
// ============================================================================
static void test_push_handler_callback_values()
{
    std::cout << "\nTest 1: update_height_fn receives correct parsed values\n";

    constexpr uint32_t UNIFIED  = 4321;
    constexpr uint32_t CHANNEL  = 210;
    constexpr uint32_t DIFF     = 0x1d00ffff;

    auto logger = spdlog::get("logger");
    if (!logger) logger = spdlog::default_logger();

    uint8_t channel = CHANNEL_PRIME;
    PushNotificationHandler handler(logger, channel);

    Packet pkt = make_push_packet(UNIFIED, CHANNEL, DIFF);

    uint32_t got_unified = 0, got_channel = 0, got_diff = 0;
    bool callback_invoked = false;

    auto update_fn = [&](uint32_t u, uint32_t c, uint32_t d) {
        got_unified  = u;
        got_channel  = c;
        got_diff     = d;
        callback_invoked = true;
    };

    handler.handle_push_notification(
        pkt,
        CHANNEL_PRIME,
        ProtocolLane::LEGACY,
        nullptr,   // no template_interface
        nullptr,   // no height_tracker (not needed for this check)
        update_fn,
        []() {}    // no-op request_work_fn
    );

    print_test_result("callback invoked", callback_invoked);
    print_test_result("unified_height passed correctly", got_unified == UNIFIED);
    print_test_result("channel_height passed correctly", got_channel == CHANNEL);
    print_test_result("difficulty passed correctly",     got_diff    == DIFF);
}

// ============================================================================
// Test 2: HeightTracker reflects same values after update_height_fn path
// ============================================================================
static void test_height_tracker_updated_via_callback()
{
    std::cout << "\nTest 2: HeightTracker reflects values delivered by update_height_fn\n";

    constexpr uint32_t UNIFIED  = 5000;
    constexpr uint32_t CHANNEL  = 300;
    constexpr uint32_t DIFF     = 0x1c0e9f34;

    HeightTracker tracker;

    auto update_fn = [&](uint32_t u, uint32_t c, uint32_t d) {
        tracker.OnPushNotification(u, c, d);
    };

    auto logger = spdlog::get("logger");
    if (!logger) logger = spdlog::default_logger();
    uint8_t channel = CHANNEL_PRIME;
    PushNotificationHandler handler(logger, channel);
    Packet pkt = make_push_packet(UNIFIED, CHANNEL, DIFF);

    handler.handle_push_notification(
        pkt, CHANNEL_PRIME, ProtocolLane::LEGACY,
        nullptr, &tracker, update_fn, []() {}
    );

    auto snap = tracker.GetSnapshot();
    print_test_result("HeightTracker unified_height == UNIFIED", snap.unified_height == UNIFIED);
    print_test_result("HeightTracker channel_height == CHANNEL", snap.channel_height == CHANNEL);
    print_test_result("HeightTracker difficulty_nbits == DIFF",  snap.difficulty_nbits == DIFF);
    print_test_result("HeightTracker source == PUSH",
        snap.last_update_source == HeightTracker::UpdateSource::PUSH);
}

// ============================================================================
// Test 3: ClientChannelManager reflects same values as HeightTracker
//         (simulates what update_height_state() does)
// ============================================================================
static void test_channel_manager_same_data_as_height_tracker()
{
    std::cout << "\nTest 3: ClientChannelManager updated with same data as HeightTracker\n";

    constexpr uint32_t UNIFIED  = 6000;
    constexpr uint32_t CHANNEL  = 400;
    constexpr uint32_t DIFF     = 0x1b123456;

    HeightTracker tracker;
    HashClientManager mgr;

    // Simulate update_height_state() called from push notification path
    auto update_fn = [&](uint32_t u, uint32_t c, uint32_t d) {
        tracker.OnPushNotification(u, c, d);
        mgr.UpdateFromGetRound(u, c);
    };

    auto logger = spdlog::get("logger");
    if (!logger) logger = spdlog::default_logger();
    uint8_t channel = CHANNEL_HASH;
    PushNotificationHandler handler(logger, channel);
    Packet pkt = make_push_packet(UNIFIED, CHANNEL, DIFF, false);
    // Use HASH opcode
    pkt.m_header = nexusminer::LLP::HASH_BLOCK_AVAILABLE;

    handler.handle_push_notification(
        pkt, CHANNEL_HASH, ProtocolLane::LEGACY,
        nullptr, &tracker, update_fn, []() {}
    );

    auto snap = tracker.GetSnapshot();
    auto [node_u, node_c] = mgr.GetNodeHeights();

    print_test_result("HeightTracker unified_height == UNIFIED", snap.unified_height == UNIFIED);
    print_test_result("ClientChannelManager unified_height == UNIFIED", node_u == UNIFIED);
    print_test_result("ClientChannelManager channel_height == CHANNEL", node_c == CHANNEL);
    print_test_result("Both sources match (unified)",  snap.unified_height == node_u);
    print_test_result("Both sources match (channel)",  snap.channel_height == node_c);
}

// ============================================================================
// Test 4: Fork detection works when heights regress via update callback
// ============================================================================
static void test_fork_detection_via_update_callback()
{
    std::cout << "\nTest 4: Fork detection fires when heights regress\n";

    PrimeClientManager mgr;

    // First update: height = 5000
    mgr.UpdateFromGetRound(5000, 200);
    print_test_result("No fork on first update", !mgr.IsForkDetected());

    // Second update: unified regresses (fork)
    mgr.UpdateFromGetRound(4999, 200);
    print_test_result("Fork detected after height regression", mgr.IsForkDetected());

    mgr.ClearForkFlag();
    print_test_result("Fork flag cleared after ClearForkFlag()", !mgr.IsForkDetected());

    // Advance normally: no fork
    mgr.UpdateFromGetRound(5001, 201);
    print_test_result("No fork after normal advance", !mgr.IsForkDetected());
}

// ============================================================================
// Test 5: validate_current_template uses HeightTracker (not ClientChannelManager)
//         Verified indirectly: HeightTracker::Snapshot::is_template_stale() correctly
//         signals staleness after push updates, while ClientChannelManager heights
//         are only informational.
// ============================================================================
static void test_height_tracker_staleness_matches_expected()
{
    std::cout << "\nTest 5: HeightTracker staleness is source of truth for template validation\n";

    HeightTracker tracker;

    // Push update: channel_height = 100
    tracker.OnPushNotification(5000, 100, 0x1a0abc12);
    // Template targets channel_height = 101 (next block)
    tracker.OnTemplateReceived(CHANNEL_PRIME, 101);

    auto snap = tracker.GetSnapshot();
    print_test_result("Not stale when channel_height(100) < channel_target(101)",
        !snap.is_template_stale());

    // Push update: channel_height advances to 101 (someone else mined that block)
    tracker.OnPushNotification(5001, 101, 0x1a0abc12);
    snap = tracker.GetSnapshot();
    print_test_result("Stale when channel_height(101) >= channel_target(101)",
        snap.is_template_stale());

    // A unified-only advance does NOT change the staleness (already stale from channel advance)
    tracker.OnPushNotification(5002, 101, 0x1a0abc12);
    snap = tracker.GetSnapshot();
    print_test_result("Stale status unchanged by unified-only advance (was already stale)",
        snap.is_template_stale());  // still stale: channel_height(101) >= channel_target(101)

    // Reset: new template with channel_target = 102
    tracker.OnTemplateReceived(CHANNEL_PRIME, 102);
    snap = tracker.GetSnapshot();
    print_test_result("Not stale with new template target(102) > channel_height(101)",
        !snap.is_template_stale());
}

// ============================================================================
// Test 6: Node BLOCK_DATA metadata fields feed unified/channel/difficulty first,
//         then template target is derived from channel_height + 1.
// ============================================================================
static void test_node_block_data_fields_drive_height_tracker()
{
    std::cout << "\nTest 6: Node BLOCK_DATA fields drive nBits, unified height, and channel target\n";

    constexpr uint32_t UNIFIED  = 7000;
    constexpr uint32_t CHANNEL  = 450;
    constexpr uint32_t DIFF     = 0x1b01abcd;

    HeightTracker tracker;
    HashClientManager mgr;

    // Mirrors Solo::update_height_state(...) for BLOCK_DATA metadata feed.
    tracker.OnPushNotification(UNIFIED, CHANNEL, DIFF);
    mgr.UpdateFromGetRound(UNIFIED, CHANNEL);

    // Mirrors Solo::OnTemplateReceived(channel_height + 1) for template target.
    tracker.OnTemplateReceived(CHANNEL_HASH, CHANNEL + 1);

    auto snap = tracker.GetSnapshot();
    auto [node_u, node_c] = mgr.GetNodeHeights();

    print_test_result("HeightTracker unified_height from BLOCK_DATA metadata", snap.unified_height == UNIFIED);
    print_test_result("HeightTracker difficulty_nbits from BLOCK_DATA metadata", snap.difficulty_nbits == DIFF);
    print_test_result("HeightTracker channel_target == channel_height + 1", snap.channel_target == CHANNEL + 1);
    print_test_result("template_unified_height captured from metadata unified_height", snap.template_unified_height == UNIFIED);
    print_test_result("ClientChannelManager unified_height matches metadata", node_u == UNIFIED);
    print_test_result("ClientChannelManager channel_height matches metadata", node_c == CHANNEL);
}

// ============================================================================
// main
// ============================================================================
int main()
{
    std::cout << "========================================\n";
    std::cout << "Phase 2B: Height State Update Tests\n";
    std::cout << "========================================\n";

    test_push_handler_callback_values();
    test_height_tracker_updated_via_callback();
    test_channel_manager_same_data_as_height_tracker();
    test_fork_detection_via_update_callback();
    test_height_tracker_staleness_matches_expected();
    test_node_block_data_fields_drive_height_tracker();

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
