/**
 * @file height_tracker_test.cpp
 * @brief Unit tests for HeightTracker centralized height tracking utility
 *
 * Tests:
 *  1. Push update + template received produces expected drift delta 0
 *  2. Channel height advanced makes IsTemplateStale true
 *  3. Snapshot is consistent after concurrent-style updates
 *  4. ExplainMismatch returns empty string when heights are consistent
 *  5. ExplainMismatch reports drift when template target differs from expected
 *  6. ExplainMismatch reports staleness when channel height >= template target
 *  7. GET_ROUND update sets source correctly
 */

#include "protocol/height_tracker.hpp"
#include <iostream>
#include <cassert>
#include <cstdint>

using namespace nexusminer::protocol;

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
// Test 1: Push update + template received produces drift delta 0
// ============================================================================
void test_push_then_template_no_drift() {
    std::cout << "\nTest 1: Push update + template → drift delta 0\n";
    HeightTracker tracker;

    // Node tells miner: channel is at height 100, difficulty 0x1d00ffff
    tracker.OnPushNotification(5000, 100, 0x1d00ffff);

    // Template arrives targeting height 101 (channel_height + 1)
    tracker.OnTemplateReceived(1, 101);

    auto snap = tracker.GetSnapshot();

    // expected_template_target() == channel_height + 1 == 101
    print_test_result("expected_template_target() == 101",
                      snap.expected_template_target() == 101);

    // drift_delta() == channel_target - expected == 101 - 101 == 0
    auto delta = snap.drift_delta();
    print_test_result("drift_delta() has value", delta.has_value());
    print_test_result("drift_delta() == 0", delta.has_value() && *delta == 0);

    // Template is not stale (channel_height 100 < channel_target 101)
    print_test_result("is_template_stale() == false", !snap.is_template_stale());

    // ExplainMismatch returns empty (heights are consistent)
    std::string msg = tracker.ExplainMismatch();
    print_test_result("ExplainMismatch() is empty when consistent", msg.empty());
}

// ============================================================================
// Test 2: Channel height advanced makes IsTemplateStale true
// ============================================================================
void test_channel_height_advance_makes_stale() {
    std::cout << "\nTest 2: Channel height advance → IsTemplateStale true\n";
    HeightTracker tracker;

    // Template was for height 101
    tracker.OnPushNotification(5000, 100, 0x1d00ffff);
    tracker.OnTemplateReceived(1, 101);

    // Another miner finds the block; push notifies new channel height 101
    tracker.OnPushNotification(5001, 101, 0x1d00ffff);

    auto snap = tracker.GetSnapshot();

    // channel_height (101) >= channel_target (101) → stale
    print_test_result("is_template_stale() == true after channel advance",
                      snap.is_template_stale());

    // ExplainMismatch should report STALE
    std::string msg = tracker.ExplainMismatch();
    print_test_result("ExplainMismatch() mentions STALE",
                      msg.find("STALE") != std::string::npos);
}

// ============================================================================
// Test 3: Snapshot is consistent
// ============================================================================
void test_snapshot_consistency() {
    std::cout << "\nTest 3: Snapshot consistency\n";
    HeightTracker tracker;
    tracker.OnPushNotification(4999, 99, 0x1a0abc12);
    tracker.OnTemplateReceived(2, 100);

    auto snap = tracker.GetSnapshot();

    print_test_result("Snapshot unified_height == 4999",
                      snap.unified_height == 4999);
    print_test_result("Snapshot channel_height == 99",
                      snap.channel_height == 99);
    print_test_result("Snapshot difficulty_nbits == 0x1a0abc12",
                      snap.difficulty_nbits == 0x1a0abc12);
    print_test_result("Snapshot channel_target == 100",
                      snap.channel_target == 100);
    print_test_result("Snapshot channel == 2",
                      snap.channel == 2);
    // Last update source should be TEMPLATE (last call was OnTemplateReceived)
    print_test_result("Snapshot last_update_source == TEMPLATE",
                      snap.last_update_source == HeightTracker::UpdateSource::TEMPLATE);
}

// ============================================================================
// Test 4: GET_ROUND update sets source correctly
// ============================================================================
void test_get_round_source() {
    std::cout << "\nTest 4: GET_ROUND update source\n";
    HeightTracker tracker;
    tracker.OnGetRound(5100, 120, 0x1d012345);

    auto snap = tracker.GetSnapshot();
    print_test_result("Source is GET_ROUND",
                      snap.last_update_source == HeightTracker::UpdateSource::GET_ROUND);
    print_test_result("unified_height == 5100", snap.unified_height == 5100);
    print_test_result("channel_height == 120",  snap.channel_height == 120);
}

// ============================================================================
// Test 5: Drift detected and explained when template target differs
// ============================================================================
void test_drift_explain() {
    std::cout << "\nTest 5: Drift detection and ExplainMismatch\n";
    HeightTracker tracker;

    // Node says channel height is 100
    tracker.OnPushNotification(5000, 100, 0x1d00ffff);

    // But template targets height 103 (not 101 — possible if heights drifted)
    tracker.OnTemplateReceived(1, 103);

    auto snap = tracker.GetSnapshot();
    auto delta = snap.drift_delta();
    print_test_result("drift_delta() has value", delta.has_value());
    print_test_result("drift_delta() == 2 (103 - 101)",
                      delta.has_value() && *delta == 2);

    std::string msg = tracker.ExplainMismatch();
    print_test_result("ExplainMismatch() mentions DRIFT",
                      msg.find("DRIFT") != std::string::npos);
}

// ============================================================================
// Test 6: Zero heights return safe defaults
// ============================================================================
void test_zero_heights_safe() {
    std::cout << "\nTest 6: Zero heights return safe defaults\n";
    HeightTracker tracker;

    auto snap = tracker.GetSnapshot();
    print_test_result("expected_template_target() == 0 when channel_height == 0",
                      snap.expected_template_target() == 0);
    print_test_result("is_template_stale() == false when all zeros",
                      !snap.is_template_stale());
    print_test_result("drift_delta() has no value when both are 0",
                      !snap.drift_delta().has_value());
    std::string msg = tracker.ExplainMismatch();
    print_test_result("ExplainMismatch() is empty with zero state", msg.empty());
}

// ============================================================================
// main
// ============================================================================
int main() {
    std::cout << "========================================\n";
    std::cout << "HeightTracker Unit Tests\n";
    std::cout << "========================================\n";

    test_push_then_template_no_drift();
    test_channel_height_advance_makes_stale();
    test_snapshot_consistency();
    test_get_round_source();
    test_drift_explain();
    test_zero_heights_safe();

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
