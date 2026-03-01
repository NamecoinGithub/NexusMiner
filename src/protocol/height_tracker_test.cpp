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
 *  8. Channel height advancing DOES make template stale
 *  9. is_tip_moved() detects unified tip advance (Phase 3A: tip_moved refresh reason)
 * 10. is_tip_moved() resets to false after new template received
 * 11. Difficulty from push updates is reflected in HeightTracker snapshot
 * 18. Push updates prime_height for Prime channel (keepalive isolated)
 * 19. Push updates hash_height for Hash channel (keepalive isolated)
 * 20. Production regression: push advances prime_height past keepalive value
 * 27. Canonical isolation — keepalive cannot corrupt canonical state
 * 30. OnBlockDataReceived monotonicity (stale block data never regresses)
 * 31. height_drift_from_canonical() measures push-vs-canonical drift
 * 32. canonical_hash_prev_block anchored to BLOCK_DATA (Tritium block)
 */

#include "protocol/height_tracker.hpp"
#include <iostream>
#include <cassert>
#include <cstdint>
#include <thread>

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
// Test 7: Unified height advancing alone does NOT make template stale
// (Phase 1B: unified-delta must NOT trigger stale/template refresh)
// ============================================================================
void test_unified_advance_does_not_make_stale() {
    std::cout << "\nTest 7: Unified height advancing alone → NOT stale\n";
    HeightTracker tracker;

    // Initial state: channel at 100, template for 101
    tracker.OnPushNotification(5000, 100, 0x1d00ffff);
    tracker.OnTemplateReceived(1, 101);

    // Unified height advances many blocks (other channels found blocks)
    // while channel height stays at 100 (Prime mining takes minutes)
    tracker.OnPushNotification(5010, 100, 0x1d00ffff);

    auto snap = tracker.GetSnapshot();

    // Template should still be valid: channel_height (100) < channel_target (101)
    print_test_result("is_template_stale() == false after unified-only advance",
                      !snap.is_template_stale());

    // Channel target unchanged
    print_test_result("channel_target still == 101", snap.channel_target == 101);

    // Channel height unchanged
    print_test_result("channel_height still == 100", snap.channel_height == 100);

    // Unified height updated
    print_test_result("unified_height updated to 5010", snap.unified_height == 5010);

    // ExplainMismatch should be empty (heights are still consistent)
    std::string msg = tracker.ExplainMismatch();
    print_test_result("ExplainMismatch() is empty (template still valid)", msg.empty());
}

// ============================================================================
// Test 8: Channel height advancing DOES make template stale
// ============================================================================
void test_channel_advance_makes_stale() {
    std::cout << "\nTest 8: Channel height advancing → stale\n";
    HeightTracker tracker;

    // Initial state: channel at 100, template for 101
    tracker.OnPushNotification(5000, 100, 0x1d00ffff);
    tracker.OnTemplateReceived(1, 101);

    // Channel height advances to 101 (another miner found the block)
    tracker.OnPushNotification(5001, 101, 0x1d00ffff);

    auto snap = tracker.GetSnapshot();

    // Template is stale: channel_height (101) >= channel_target (101)
    print_test_result("is_template_stale() == true after channel advance",
                      snap.is_template_stale());

    // ExplainMismatch should mention STALE
    std::string msg = tracker.ExplainMismatch();
    print_test_result("ExplainMismatch() mentions STALE after channel advance",
                      msg.find("STALE") != std::string::npos);
}

// ============================================================================
// Test 9: is_tip_moved() detects when unified tip advances beyond template tip
//         (Phase 3A: hashPrevBlock staleness via unified height delta)
// ============================================================================
void test_is_tip_moved_detected() {
    std::cout << "\nTest 9: is_tip_moved() — unified tip advance triggers refresh\n";
    HeightTracker tracker;

    // Initial state: channel at 100, template for 101, unified at 5000
    tracker.OnPushNotification(5000, 100, 0x1d00ffff);
    tracker.OnTemplateReceived(1, 101);

    auto snap_initial = tracker.GetSnapshot();

    // template_unified_height should be captured as 5000
    print_test_result("template_unified_height == 5000 after template received",
                      snap_initial.template_unified_height == 5000);

    // No tip movement yet: unified == template_unified
    print_test_result("is_tip_moved() == false before unified advance",
                      !snap_initial.is_tip_moved());

    // Another channel finds a block: unified advances to 5005, channel stays at 100
    tracker.OnPushNotification(5005, 100, 0x1d00ffff);
    auto snap = tracker.GetSnapshot();

    // Tip has moved: unified (5005) > template_unified (5000)
    print_test_result("is_tip_moved() == true after unified advance",
                      snap.is_tip_moved());

    // But template is NOT channel-stale: channel_height (100) < channel_target (101)
    print_test_result("is_template_stale() == false (channel height unchanged)",
                      !snap.is_template_stale());

    // template_unified_height unchanged (only updates on OnTemplateReceived)
    print_test_result("template_unified_height still == 5000 (template not refreshed)",
                      snap.template_unified_height == 5000);

    // unified_height updated to new value
    print_test_result("unified_height updated to 5005",
                      snap.unified_height == 5005);
}

// ============================================================================
// Test 10: is_tip_moved() resets to false after new template received
// ============================================================================
void test_is_tip_moved_resets_on_new_template() {
    std::cout << "\nTest 10: is_tip_moved() resets when new template received\n";
    HeightTracker tracker;

    // Template at unified=5000, channel=100
    tracker.OnPushNotification(5000, 100, 0x1d00ffff);
    tracker.OnTemplateReceived(1, 101);

    // Unified tip moves to 5005
    tracker.OnPushNotification(5005, 100, 0x1d00ffff);
    print_test_result("is_tip_moved() == true before fresh template",
                      tracker.GetSnapshot().is_tip_moved());

    // Fresh template received (now template_unified_height == 5005)
    tracker.OnTemplateReceived(1, 101);
    auto snap = tracker.GetSnapshot();

    // After new template, tip is no longer "moved"
    print_test_result("is_tip_moved() == false after fresh template received",
                      !snap.is_tip_moved());

    // template_unified_height updated to current unified height
    print_test_result("template_unified_height == 5005 (new template at new tip)",
                      snap.template_unified_height == 5005);
}

// ============================================================================
// Test 11: Difficulty from push updates is reflected in HeightTracker and
//         consistent across snapshot reads (Phase 2C regression test)
// ============================================================================
void test_difficulty_from_push_reflected_in_snapshot() {
    std::cout << "\nTest 11: Difficulty from push updates reflected in HeightTracker\n";
    HeightTracker tracker;

    // First push: difficulty_nbits = 0x1d00ffff
    tracker.OnPushNotification(5000, 100, 0x1d00ffff);
    auto snap = tracker.GetSnapshot();
    print_test_result("difficulty_nbits set from push (0x1d00ffff)",
                      snap.difficulty_nbits == 0x1d00ffff);
    print_test_result("Source is PUSH after OnPushNotification",
                      snap.last_update_source == HeightTracker::UpdateSource::PUSH);

    // Second push with updated difficulty: difficulty_nbits = 0x1c0e9f34
    tracker.OnPushNotification(5001, 101, 0x1c0e9f34);
    snap = tracker.GetSnapshot();
    print_test_result("difficulty_nbits updated from second push (0x1c0e9f34)",
                      snap.difficulty_nbits == 0x1c0e9f34);
    print_test_result("unified_height updated from second push (5001)",
                      snap.unified_height == 5001);
    print_test_result("channel_height updated from second push (101)",
                      snap.channel_height == 101);

    // GET_ROUND backup also carries difficulty; verify it is stored
    tracker.OnGetRound(5002, 102, 0x1b0afe34);
    snap = tracker.GetSnapshot();
    print_test_result("difficulty_nbits from GET_ROUND backup (0x1b0afe34)",
                      snap.difficulty_nbits == 0x1b0afe34);
    print_test_result("Source is GET_ROUND after OnGetRound",
                      snap.last_update_source == HeightTracker::UpdateSource::GET_ROUND);

    // OnTemplateReceived must NOT overwrite difficulty (it doesn't carry nbits)
    tracker.OnTemplateReceived(1, 103);
    snap = tracker.GetSnapshot();
    print_test_result("difficulty_nbits unchanged after OnTemplateReceived",
                      snap.difficulty_nbits == 0x1b0afe34);
}

// ============================================================================
// Test 12: Post-push guard — last_template_update >= last push time when
//          template is received AFTER a push notification.
//          This is the HeightTracker side of the doom-loop prevention fix:
//          Worker_manager::check_template_health() uses these timestamps to
//          decide whether to skip stop_all_workers for a "stale" template that
//          was actually received after the push that caused the stale reading.
// ============================================================================
void test_post_push_timestamps_ordered_correctly() {
    std::cout << "\nTest 12: Post-push guard — last_template_update >= last_push after push→template\n";
    HeightTracker tracker;

    // Step 1: Push notification arrives (block Y mined, channel at Y).
    tracker.OnPushNotification(5000, 100, 0x1d00ffff);
    auto snap_after_push = tracker.GetSnapshot();

    // Verify push time is recorded.
    print_test_result("last_height_update set after push",
                      snap_after_push.last_height_update != std::chrono::steady_clock::time_point{});

    // last_template_update should be before last_height_update (no template yet).
    print_test_result("last_template_update < last_height_update before template arrives",
                      snap_after_push.last_template_update < snap_after_push.last_height_update);

    // channel_height = 100, channel_target still 0 (no template) → not stale.
    print_test_result("Not stale (no channel_target yet)",
                      !snap_after_push.is_template_stale());

    // Step 2: Recovery GET_BLOCK returns a template targeting Y+1 = 101.
    // Small sleep to ensure measurable time difference between push and template.
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    tracker.OnTemplateReceived(1, 101);
    auto snap_after_tmpl = tracker.GetSnapshot();

    // last_template_update must be >= last_height_update (post-push guard).
    print_test_result("last_template_update >= last_height_update after template (post-push)",
                      snap_after_tmpl.last_template_update >= snap_after_tmpl.last_height_update);

    // is_template_stale() must be false: channel_height (100) < channel_target (101).
    print_test_result("Not stale after template for 101 (channel_height=100 < target=101)",
                      !snap_after_tmpl.is_template_stale());
}

// ============================================================================
// Test 13: Pre-push guard — template received BEFORE a push has
//          last_template_update < last_height_update, so check_template_health
//          correctly identifies it as a pre-push (genuinely stale) template
//          and does NOT skip stop_all_workers.
// ============================================================================
void test_pre_push_template_identified_correctly() {
    std::cout << "\nTest 13: Pre-push guard — last_template_update < last_height_update (pre-push template)\n";
    HeightTracker tracker;

    // Step 1: Template received first (targeting 101, channel at 100).
    tracker.OnPushNotification(5000, 100, 0x1d00ffff);
    tracker.OnTemplateReceived(1, 101);

    // Step 2: A later push arrives (channel advances to 101 — template is now stale).
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    tracker.OnPushNotification(5001, 101, 0x1d00ffff);
    auto snap = tracker.GetSnapshot();

    // last_template_update < last_height_update → pre-push template.
    print_test_result("last_template_update < last_height_update (pre-push template)",
                      snap.last_template_update < snap.last_height_update);

    // is_template_stale() must be true: channel_height (101) >= channel_target (101).
    print_test_result("is_template_stale() == true (pre-push, channel_height == channel_target)",
                      snap.is_template_stale());
}

// ============================================================================
// Test 14: OnKeepaliveResponse — diagnostic path (keepalive heights do NOT
//          corrupt canonical snapshot; fork detection fields DO appear)
// ============================================================================
void test_on_keepalive_response_unified() {
    std::cout << "\nTest 14: OnKeepaliveResponse — diagnostic only (no canonical corruption)\n";
    HeightTracker tracker;
    // Set channel to Hash (2) so channel_height mirrors hash_height
    tracker.OnTemplateReceived(2, 101);
    tracker.OnKeepaliveResponse(6000, 450, 800, 999, 0xCAFEBABEu, 3);

    auto snap = tracker.GetSnapshot();
    // Keepalive heights must NOT appear in the snapshot (they are diagnostic only)
    print_test_result("unified_height == 0 (keepalive does not set canonical)",
                      snap.unified_height == 0);
    print_test_result("prime_height == 0 (keepalive does not set canonical)",
                      snap.prime_height == 0);
    print_test_result("hash_height == 0 (keepalive does not set canonical)",
                      snap.hash_height == 0);
    print_test_result("channel_height == 0 (keepalive does not set canonical)",
                      snap.channel_height == 0);

    // Stake height and fork detection fields DO come from diagnostic
    print_test_result("stake_height == 999",    snap.stake_height == 999);
    print_test_result("hash_tip_lo32 stored",   snap.hash_tip_lo32 == 0xCAFEBABEu);
    print_test_result("fork_score == 3",        snap.fork_score == 3);
    print_test_result("peak_fork_score == 3",   snap.peak_fork_score == 3);
    print_test_result("is_fork_active() == true", snap.is_fork_active());
    print_test_result("last_update_source == KEEPALIVE",
                      snap.last_update_source == HeightTracker::UpdateSource::KEEPALIVE);

    // Diagnostic snapshot has the keepalive heights
    auto diag = tracker.GetDiagnosticSnapshot();
    print_test_result("diag.keepalive_unified_height == 6000",
                      diag.keepalive_unified_height == 6000);
    print_test_result("diag.keepalive_prime_height == 450",
                      diag.keepalive_prime_height == 450);
    print_test_result("diag.keepalive_hash_height == 800",
                      diag.keepalive_hash_height == 800);
}

// ============================================================================
// Test 15: OnKeepaliveResponse — legacy path (hash_tip_lo32=0, fork_score=0)
//          is safe and does NOT corrupt canonical heights
// ============================================================================
void test_on_keepalive_response_legacy_zeros_safe() {
    std::cout << "\nTest 15: OnKeepaliveResponse legacy zeros — safe, no canonical corruption\n";
    HeightTracker tracker;
    tracker.OnKeepaliveResponse(6001, 451, 801, 999, 0u, 0u);

    auto snap = tracker.GetSnapshot();
    // Keepalive heights must NOT appear in the snapshot
    print_test_result("unified_height == 0 (keepalive does not set canonical)",
                      snap.unified_height == 0);
    print_test_result("prime_height == 0 (keepalive does not set canonical)",
                      snap.prime_height == 0);
    print_test_result("hash_height == 0 (keepalive does not set canonical)",
                      snap.hash_height == 0);

    // Stake and fork fields from diagnostic
    print_test_result("stake_height == 999",       snap.stake_height == 999);
    print_test_result("hash_tip_lo32 == 0 (safe)", snap.hash_tip_lo32 == 0);
    print_test_result("fork_score == 0 (healthy)", snap.fork_score == 0);
    print_test_result("is_fork_active() == false", !snap.is_fork_active());
    print_test_result("last_update_source == KEEPALIVE",
                      snap.last_update_source == HeightTracker::UpdateSource::KEEPALIVE);

    // Diagnostic snapshot has the keepalive heights
    auto diag = tracker.GetDiagnosticSnapshot();
    print_test_result("diag.keepalive_unified_height == 6001",
                      diag.keepalive_unified_height == 6001);
    print_test_result("diag.keepalive_prime_height == 451",
                      diag.keepalive_prime_height == 451);
    print_test_result("diag.keepalive_hash_height == 801",
                      diag.keepalive_hash_height == 801);
}

// ============================================================================
// Test 16: OnKeepaliveResponse updates stake_height correctly
// ============================================================================
void test_keepalive_response_sets_stake_height() {
    std::cout << "\nTest 16: OnKeepaliveResponse updates stake_height\n";
    HeightTracker tracker;
    tracker.OnKeepaliveResponse(6001, 451, 801, 777, 0u, 0u);

    auto snap = tracker.GetSnapshot();
    print_test_result("stake_height == 777 via OnKeepaliveResponse",
                      snap.stake_height == 777);

    tracker.OnKeepaliveResponse(6002, 452, 802, 888, 0u, 0u);
    snap = tracker.GetSnapshot();
    print_test_result("stake_height == 888 via second OnKeepaliveResponse",
                      snap.stake_height == 888);
}

// ============================================================================
// Test 17: peak_fork_score is a persistent high-water mark
// ============================================================================
void test_peak_fork_score_high_water_mark() {
    std::cout << "\nTest 17: peak_fork_score is a persistent high-water mark\n";
    HeightTracker tracker;
    tracker.OnKeepaliveResponse(6000, 450, 800, 999, 0xCAFEBABEu, 5);
    tracker.OnKeepaliveResponse(6001, 451, 801, 999, 0xCAFEBABEu, 1);  // lower score

    auto snap = tracker.GetSnapshot();
    print_test_result("fork_score == 1 (latest)",      snap.fork_score == 1);
    print_test_result("peak_fork_score == 5 (canary)", snap.peak_fork_score == 5);
    print_test_result("is_fork_active() still true",   snap.is_fork_active());
}

// ============================================================================
// Test 18: Push updates prime_height for Prime channel (keepalive does NOT
//          set snapshot prime_height — only push/block data do)
// ============================================================================
void test_push_updates_per_channel_heights() {
    std::cout << "\nTest 18: Push updates prime_height for Prime channel (keepalive isolated)\n";
    HeightTracker tracker;
    tracker.OnTemplateReceived(1, 101);
    tracker.OnKeepaliveResponse(5000, 100, 200, 300, 0, 0);
    auto snap1 = tracker.GetSnapshot();
    // Keepalive prime_height does NOT appear in snapshot
    print_test_result("prime_height == 0 after keepalive (diagnostic only)", snap1.prime_height == 0);
    tracker.OnPushNotification(5002, 102, 0x1d00ffff);
    auto snap2 = tracker.GetSnapshot();
    print_test_result("channel_height == 102 after push", snap2.channel_height == 102);
    print_test_result("prime_height == 102 after push (no drift)", snap2.prime_height == 102);
}

// ============================================================================
// Test 19: Push updates hash_height for Hash channel (keepalive does NOT
//          set snapshot hash_height — only push/block data do)
// ============================================================================
void test_push_updates_hash_height() {
    std::cout << "\nTest 19: Push updates hash_height for Hash channel (keepalive isolated)\n";
    HeightTracker tracker;
    tracker.OnTemplateReceived(2, 201);
    tracker.OnKeepaliveResponse(5000, 100, 200, 300, 0, 0);
    auto snap1 = tracker.GetSnapshot();
    // Keepalive hash_height does NOT appear in snapshot
    print_test_result("hash_height == 0 after keepalive (diagnostic only)", snap1.hash_height == 0);
    tracker.OnPushNotification(5002, 202, 0x1d00ffff);
    auto snap2 = tracker.GetSnapshot();
    print_test_result("channel_height == 202 after push", snap2.channel_height == 202);
    print_test_result("hash_height == 202 after push (no drift)", snap2.hash_height == 202);
}

// ============================================================================
// Test 20: Production regression (prime drift from 2331124 to 2331126)
// ============================================================================
void test_push_keepalive_no_regression() {
    std::cout << "\nTest 20: Production regression (prime drift from 2331124 to 2331126)\n";
    HeightTracker tracker;
    tracker.OnTemplateReceived(1, 2331125);
    tracker.OnKeepaliveResponse(6609207, 2331124, 2193089, 2084996, 0, 0);
    tracker.OnPushNotification(6609208, 2331126, 0x0414b755);
    auto snap = tracker.GetSnapshot();
    print_test_result("channel_height == 2331126", snap.channel_height == 2331126);
    print_test_result("prime_height == 2331126 (no drift)", snap.prime_height == 2331126);
    print_test_result("is_template_stale (2331126 >= 2331125)", snap.is_template_stale());
}

// ============================================================================
// Test 21: AdvanceChannelTarget only advances, never regresses
// ============================================================================
void test_advance_channel_target_only_advances() {
    std::cout << "\nTest 21: AdvanceChannelTarget only advances, never regresses\n";
    HeightTracker tracker;

    // Set initial channel_target via OnTemplateReceived
    tracker.OnPushNotification(5000, 100, 0x1d00ffff);
    tracker.OnTemplateReceived(1, 101);
    auto snap = tracker.GetSnapshot();
    print_test_result("channel_target == 101 after OnTemplateReceived",
                      snap.channel_target == 101);

    // Advance to 105 via AdvanceChannelTarget
    tracker.AdvanceChannelTarget(105);
    snap = tracker.GetSnapshot();
    print_test_result("channel_target == 105 after AdvanceChannelTarget(105)",
                      snap.channel_target == 105);

    // Attempting to set a lower value via AdvanceChannelTarget is a no-op
    tracker.AdvanceChannelTarget(102);
    snap = tracker.GetSnapshot();
    print_test_result("channel_target still 105 after AdvanceChannelTarget(102)",
                      snap.channel_target == 105);

    // Attempting to set the same value is a no-op
    tracker.AdvanceChannelTarget(105);
    snap = tracker.GetSnapshot();
    print_test_result("channel_target still 105 after AdvanceChannelTarget(105)",
                      snap.channel_target == 105);

    // Advancing beyond current value works
    tracker.AdvanceChannelTarget(110);
    snap = tracker.GetSnapshot();
    print_test_result("channel_target == 110 after AdvanceChannelTarget(110)",
                      snap.channel_target == 110);
}

// ============================================================================
// Test 22: OnTemplateReceived does not regress channel_target
// ============================================================================
void test_on_template_received_no_regress() {
    std::cout << "\nTest 22: OnTemplateReceived does not regress channel_target\n";
    HeightTracker tracker;

    tracker.OnPushNotification(5000, 100, 0x1d00ffff);
    tracker.OnTemplateReceived(1, 101);
    auto snap = tracker.GetSnapshot();
    print_test_result("channel_target == 101 initially", snap.channel_target == 101);

    // Push advances channel_target (simulating push-detected staleness)
    tracker.AdvanceChannelTarget(105);
    snap = tracker.GetSnapshot();
    print_test_result("channel_target == 105 after AdvanceChannelTarget",
                      snap.channel_target == 105);

    // Stale GET_BLOCK response arrives with a lower channel_target
    tracker.OnTemplateReceived(1, 102);
    snap = tracker.GetSnapshot();
    print_test_result("channel_target still 105 after stale OnTemplateReceived(102)",
                      snap.channel_target == 105);

    // But template_unified_height and timestamps are still updated
    print_test_result("last_update_source == TEMPLATE",
                      snap.last_update_source == HeightTracker::UpdateSource::TEMPLATE);

    // A fresh template with a higher target DOES advance
    tracker.OnTemplateReceived(1, 110);
    snap = tracker.GetSnapshot();
    print_test_result("channel_target == 110 after fresh OnTemplateReceived(110)",
                      snap.channel_target == 110);
}

// ============================================================================
// Test 23: Doom-loop prevention — push staleness detection fires once per
//          chain advance, not on every subsequent push with same height
// ============================================================================
void test_doom_loop_prevention() {
    std::cout << "\nTest 23: Doom-loop prevention — staleness fires once per advance\n";
    HeightTracker tracker;

    // Initial: template targeting block 101
    tracker.OnPushNotification(5000, 100, 0x1d00ffff);
    tracker.OnTemplateReceived(1, 101);

    // Push₁: channel advances to 101 → stale
    tracker.OnPushNotification(5001, 101, 0x1d00ffff);
    auto snap = tracker.GetSnapshot();
    print_test_result("Push₁: is_template_stale() true (101 >= 101)",
                      snap.is_template_stale());

    // Simulate push handler advancing channel_target after detecting staleness
    tracker.AdvanceChannelTarget(102);

    // Push₂: same channel_height 101 → should NOT be stale anymore
    tracker.OnPushNotification(5002, 101, 0x1d00ffff);
    snap = tracker.GetSnapshot();
    print_test_result("Push₂: is_template_stale() false (101 < 102)",
                      !snap.is_template_stale());

    // Push₃: channel advances again to 102 → stale again (correct!)
    tracker.OnPushNotification(5003, 102, 0x1d00ffff);
    snap = tracker.GetSnapshot();
    print_test_result("Push₃: is_template_stale() true (102 >= 102)",
                      snap.is_template_stale());
}

// ============================================================================
// Test 24: Stale GET_BLOCK response does not cause regression
// ============================================================================
void test_stale_get_block_no_regression() {
    std::cout << "\nTest 24: Stale GET_BLOCK response does not regress channel_target\n";
    HeightTracker tracker;

    // Push says chain is at channel_height 105
    tracker.OnPushNotification(5010, 105, 0x1d00ffff);
    tracker.OnTemplateReceived(1, 101);  // old template target

    // Push-handler detects stale (105 >= 101) and advances target
    tracker.AdvanceChannelTarget(106);

    // Stale GET_BLOCK response has channel_height=99 (3 blocks behind)
    tracker.OnGetRound(5007, 99, 0x1d00ffff);
    tracker.OnTemplateReceived(1, 100);  // stale template target

    auto snap = tracker.GetSnapshot();
    // channel_target should NOT have regressed to 100
    print_test_result("channel_target still 106 after stale GET_BLOCK (not regressed to 100)",
                      snap.channel_target == 106);

    // But channel_height was updated from OnGetRound (99) — that's the template's view
    // Push re-arriving would set it back to current
    tracker.OnPushNotification(5011, 105, 0x1d00ffff);
    snap = tracker.GetSnapshot();
    print_test_result("channel_height restored to 105 from push",
                      snap.channel_height == 105);
    print_test_result("Not stale: 105 < 106", !snap.is_template_stale());
}

// ============================================================================
// Test 25: OnTemplateMetadata does NOT regress channel_height
//          (fixes HeightTracker update gap after stale GET_BLOCK responses)
// ============================================================================
void test_on_template_metadata_monotonic() {
    std::cout << "\nTest 25: OnTemplateMetadata does NOT regress channel_height\n";
    HeightTracker tracker;

    // Simulate: pushes advance channel to 2332106
    tracker.OnPushNotification(6611706, 2332106, 0x1d00ffff);
    tracker.OnTemplateReceived(1, 2332100);  // old template target

    auto snap = tracker.GetSnapshot();
    print_test_result("channel_height == 2332106 after push",
                      snap.channel_height == 2332106);

    // Stale GET_BLOCK response arrives with channel_height=2332100
    // OnTemplateMetadata must NOT regress channel_height to 2332100.
    tracker.OnTemplateMetadata(6611706, 2332100, 0x1d00ffff);
    snap = tracker.GetSnapshot();
    print_test_result("channel_height still 2332106 after stale OnTemplateMetadata(2332100)",
                      snap.channel_height == 2332106);
    print_test_result("unified_height updated to 6611706",
                      snap.unified_height == 6611706);
    print_test_result("last_update_source == TEMPLATE",
                      snap.last_update_source == HeightTracker::UpdateSource::TEMPLATE);

    // Fresh template metadata with a higher channel_height DOES advance
    tracker.OnTemplateMetadata(6611710, 2332108, 0x1d00ffff);
    snap = tracker.GetSnapshot();
    print_test_result("channel_height advanced to 2332108 from fresh OnTemplateMetadata",
                      snap.channel_height == 2332108);
    print_test_result("unified_height advanced to 6611710",
                      snap.unified_height == 6611710);
}

// ============================================================================
// Test 26: OnTemplateMetadata per-channel heights are advance-only
// ============================================================================
void test_on_template_metadata_per_channel_no_regression() {
    std::cout << "\nTest 26: OnTemplateMetadata per-channel heights are advance-only\n";
    HeightTracker tracker;

    // Prime channel: push sets prime_height=500
    tracker.OnTemplateReceived(1, 1);  // set channel to Prime
    tracker.OnPushNotification(10000, 500, 0x1d00ffff);
    auto snap = tracker.GetSnapshot();
    print_test_result("prime_height == 500 after push",
                      snap.prime_height == 500);

    // Stale template metadata with channel_height=400 must not regress prime_height
    tracker.OnTemplateMetadata(10001, 400, 0x1d00ffff);
    snap = tracker.GetSnapshot();
    print_test_result("prime_height still 500 after stale OnTemplateMetadata(400)",
                      snap.prime_height == 500);
    print_test_result("channel_height still 500 (not regressed)",
                      snap.channel_height == 500);

    // Hash channel test
    HeightTracker hash_tracker;
    hash_tracker.OnTemplateReceived(2, 1);  // set channel to Hash
    hash_tracker.OnPushNotification(10000, 300, 0x1d00ffff);
    snap = hash_tracker.GetSnapshot();
    print_test_result("hash_height == 300 after push",
                      snap.hash_height == 300);

    hash_tracker.OnTemplateMetadata(10001, 250, 0x1d00ffff);
    snap = hash_tracker.GetSnapshot();
    print_test_result("hash_height still 300 after stale OnTemplateMetadata(250)",
                      snap.hash_height == 300);
}

// ============================================================================
// Test 27: Canonical isolation — OnBlockDataReceived sets canonical,
//          keepalive cannot corrupt it
// ============================================================================
void test_canonical_isolation() {
    std::cout << "\nTest 27: Canonical isolation — keepalive cannot corrupt canonical\n";
    HeightTracker tracker;
    tracker.OnTemplateReceived(1, 101);

    // Set canonical via OnBlockDataReceived
    tracker.OnBlockDataReceived(6000, 500, 0x1d00ffff);
    auto canon = tracker.GetCanonicalSnapshot();
    print_test_result("canonical_unified_height == 6000", canon.canonical_unified_height == 6000);
    print_test_result("canonical_channel_height == 500",  canon.canonical_channel_height == 500);
    print_test_result("canonical_channel_target == 501",  canon.canonical_channel_target == 501);
    print_test_result("is_initialized() == true",         canon.is_initialized());
    print_test_result("canonical_received_at is set",
                      canon.canonical_received_at != std::chrono::steady_clock::time_point{});

    // Keepalive with LOWER heights must NOT corrupt canonical
    tracker.OnKeepaliveResponse(5990, 490, 790, 300, 0xDEADBEEFu, 2);
    canon = tracker.GetCanonicalSnapshot();
    print_test_result("canonical_unified_height still 6000 after stale keepalive",
                      canon.canonical_unified_height == 6000);
    print_test_result("canonical_channel_height still 500 after stale keepalive",
                      canon.canonical_channel_height == 500);

    // Keepalive with HIGHER heights still must NOT corrupt canonical
    tracker.OnKeepaliveResponse(7000, 600, 900, 400, 0xCAFEBABEu, 0);
    canon = tracker.GetCanonicalSnapshot();
    print_test_result("canonical_unified_height still 6000 after higher keepalive",
                      canon.canonical_unified_height == 6000);
    print_test_result("canonical_channel_height still 500 after higher keepalive",
                      canon.canonical_channel_height == 500);

    // Only OnBlockDataReceived can advance canonical
    tracker.OnBlockDataReceived(7001, 601, 0x1d00ffff);
    canon = tracker.GetCanonicalSnapshot();
    print_test_result("canonical_unified_height advanced to 7001 via OnBlockDataReceived",
                      canon.canonical_unified_height == 7001);
    print_test_result("canonical_channel_height advanced to 601 via OnBlockDataReceived",
                      canon.canonical_channel_height == 601);
    print_test_result("canonical_channel_target advanced to 602",
                      canon.canonical_channel_target == 602);
}

// ============================================================================
// Test 28: Fork scores reset when OnTemplateReceived advances channel_target
// ============================================================================
void test_fork_scores_reset_on_template_advance() {
    std::cout << "\nTest 28: Fork scores reset when OnTemplateReceived advances channel_target\n";
    HeightTracker tracker;
    // Set up: channel=2 (Hash), initial template, then a fork
    tracker.OnTemplateReceived(2, 101);
    tracker.OnKeepaliveResponse(6000, 450, 800, 999, 0xCAFEBABEu, 5);

    auto snap = tracker.GetSnapshot();
    print_test_result("fork_score == 5 after keepalive",      snap.fork_score == 5);
    print_test_result("peak_fork_score == 5 after keepalive", snap.peak_fork_score == 5);
    print_test_result("is_fork_active() == true",             snap.is_fork_active());

    // Recovery: a fresh template arrives that advances channel_target
    tracker.OnTemplateReceived(2, 102);

    snap = tracker.GetSnapshot();
    print_test_result("fork_score == 0 after recovery template",      snap.fork_score == 0);
    print_test_result("peak_fork_score == 0 after recovery template", snap.peak_fork_score == 0);
    print_test_result("is_fork_active() == false after recovery",     !snap.is_fork_active());
    print_test_result("channel_target == 102",                        snap.channel_target == 102);
}

// ============================================================================
// Test 29: Fork scores NOT reset when OnTemplateReceived doesn't advance target
// ============================================================================
void test_fork_scores_sticky_without_advance() {
    std::cout << "\nTest 29: Fork scores NOT reset when OnTemplateReceived doesn't advance target\n";
    HeightTracker tracker;
    tracker.OnTemplateReceived(2, 101);
    tracker.OnKeepaliveResponse(6000, 450, 800, 999, 0xCAFEBABEu, 3);

    // Stale template that doesn't advance channel_target
    tracker.OnTemplateReceived(2, 100);

    auto snap = tracker.GetSnapshot();
    print_test_result("fork_score still 3 (stale template)",      snap.fork_score == 3);
    print_test_result("peak_fork_score still 3 (stale template)", snap.peak_fork_score == 3);
    print_test_result("is_fork_active() still true",              snap.is_fork_active());
    print_test_result("channel_target unchanged at 101",          snap.channel_target == 101);
}

// ============================================================================
// Test 30: OnBlockDataReceived monotonicity — stale block data never regresses
// ============================================================================
void test_on_block_data_received_monotonic() {
    std::cout << "\nTest 30: OnBlockDataReceived monotonicity\n";
    HeightTracker tracker;
    tracker.OnTemplateReceived(1, 101);

    // First block data sets canonical
    tracker.OnBlockDataReceived(6000, 500, 0x1d00ffff);
    auto canon = tracker.GetCanonicalSnapshot();
    print_test_result("canonical_unified_height == 6000", canon.canonical_unified_height == 6000);
    print_test_result("canonical_channel_height == 500",  canon.canonical_channel_height == 500);
    print_test_result("canonical_channel_target == 501",  canon.canonical_channel_target == 501);

    // Stale block data with lower heights does NOT regress
    tracker.OnBlockDataReceived(5990, 490, 0x1d001111);
    canon = tracker.GetCanonicalSnapshot();
    print_test_result("canonical_unified_height still 6000 (monotonic)",
                      canon.canonical_unified_height == 6000);
    print_test_result("canonical_channel_height still 500 (monotonic)",
                      canon.canonical_channel_height == 500);
    print_test_result("canonical_channel_target still 501 (monotonic)",
                      canon.canonical_channel_target == 501);
    // difficulty IS updated (not subject to monotonicity)
    print_test_result("canonical_difficulty_nbits updated to 0x1d001111",
                      canon.canonical_difficulty_nbits == 0x1d001111);

    // Higher block data advances canonical
    tracker.OnBlockDataReceived(6010, 510, 0x1d002222);
    canon = tracker.GetCanonicalSnapshot();
    print_test_result("canonical_unified_height advanced to 6010",
                      canon.canonical_unified_height == 6010);
    print_test_result("canonical_channel_height advanced to 510",
                      canon.canonical_channel_height == 510);
    print_test_result("canonical_channel_target advanced to 511",
                      canon.canonical_channel_target == 511);

    // Zero nbits does not clear difficulty
    tracker.OnBlockDataReceived(6020, 520, 0);
    canon = tracker.GetCanonicalSnapshot();
    print_test_result("canonical_difficulty_nbits unchanged with zero nbits",
                      canon.canonical_difficulty_nbits == 0x1d002222);
}

// ============================================================================
// Test 31: height_drift_from_canonical() measures push-vs-canonical drift
// ============================================================================
void test_height_drift_from_canonical() {
    std::cout << "\nTest 31: height_drift_from_canonical() measures drift\n";
    HeightTracker tracker;
    tracker.OnTemplateReceived(1, 101);

    // Set canonical via block data
    tracker.OnBlockDataReceived(6000, 500, 0x1d00ffff);
    auto snap = tracker.GetSnapshot();
    // No push yet, so snapshot.unified_height == canonical.unified_height
    print_test_result("drift == 0 when canonical == snapshot",
                      snap.height_drift_from_canonical() == 0);

    // Push advances past canonical
    tracker.OnPushNotification(6005, 505, 0x1d00ffff);
    snap = tracker.GetSnapshot();
    // snap.unified_height = max(6000, 6005) = 6005
    // canonical_unified_height = 6000
    // drift = 6005 - 6000 = 5
    print_test_result("drift == 5 when push is ahead of canonical",
                      snap.height_drift_from_canonical() == 5);

    // Block data catches up to push
    tracker.OnBlockDataReceived(6005, 505, 0x1d00ffff);
    snap = tracker.GetSnapshot();
    print_test_result("drift == 0 when canonical catches up",
                      snap.height_drift_from_canonical() == 0);
}

// ============================================================================
// Test 32: canonical_hash_prev_block anchored to BLOCK_DATA (Tritium block)
// ============================================================================
void test_canonical_hash_prev_block() {
    std::cout << "\nTest 32: canonical_hash_prev_block anchored to BLOCK_DATA\n";
    HeightTracker tracker;
    tracker.OnTemplateReceived(1, 101);

    // Before any block data: is_initialized() is false, hash_prev_block is zero
    auto canon = tracker.GetCanonicalSnapshot();
    print_test_result("is_initialized() == false before block data",
                      !canon.is_initialized());
    print_test_result("canonical_hash_prev_block is zero before block data",
                      canon.canonical_hash_prev_block == uint1024_t(0));

    // OnBlockDataReceived sets heights; UpdateWithHashPrevBlock sets hashPrevBlock
    tracker.OnBlockDataReceived(6000, 500, 0x1d00ffff);
    uint1024_t fake_prev_hash(0xDEADBEEFu);
    tracker.UpdateWithHashPrevBlock(fake_prev_hash);

    canon = tracker.GetCanonicalSnapshot();
    print_test_result("is_initialized() == true after block data",
                      canon.is_initialized());
    print_test_result("canonical_hash_prev_block set from UpdateWithHashPrevBlock",
                      canon.canonical_hash_prev_block == fake_prev_hash);

    // Snapshot's hash_prev_block is sourced from canonical
    auto snap = tracker.GetSnapshot();
    print_test_result("snapshot.hash_prev_block == canonical_hash_prev_block",
                      snap.hash_prev_block == fake_prev_hash);
    print_test_result("snapshot.canonical_hash_prev_block == canonical source",
                      snap.canonical_hash_prev_block == fake_prev_hash);

    // Keepalive does NOT affect canonical_hash_prev_block
    tracker.OnKeepaliveResponse(7000, 600, 900, 400, 0xCAFEBABEu, 1);
    canon = tracker.GetCanonicalSnapshot();
    print_test_result("canonical_hash_prev_block unchanged after keepalive",
                      canon.canonical_hash_prev_block == fake_prev_hash);

    // Diagnostic hash_tip_lo32 is separate (lo32 of node's hashBestChain)
    auto diag = tracker.GetDiagnosticSnapshot();
    print_test_result("diagnostic hash_tip_lo32 == 0xCAFEBABE from keepalive",
                      diag.hash_tip_lo32 == 0xCAFEBABEu);

    // Update hash_prev_block with new chain tip
    uint1024_t new_prev_hash(0xFEEDFACEu);
    tracker.UpdateWithHashPrevBlock(new_prev_hash);
    canon = tracker.GetCanonicalSnapshot();
    print_test_result("canonical_hash_prev_block updated to new tip",
                      canon.canonical_hash_prev_block == new_prev_hash);
}

// Test 33: DiagnosticObserverState::is_initialized() and latest_received_at()
void test_diagnostic_observer_helpers() {
    std::cout << "\nTest 33: DiagnosticObserverState::is_initialized() and latest_received_at()\n";
    HeightTracker tracker;

    // Before any updates, diagnostic state is NOT initialized
    auto diag = tracker.GetDiagnosticSnapshot();
    print_test_result("diagnostic not initialized before any update",
                      !diag.is_initialized());
    print_test_result("latest_received_at is default before any update",
                      diag.latest_received_at() == std::chrono::steady_clock::time_point{});

    // After push notification, diagnostic state IS initialized
    auto before_push = std::chrono::steady_clock::now();
    tracker.OnPushNotification(100, 50, 0x1D00FFFF);
    auto after_push = std::chrono::steady_clock::now();
    diag = tracker.GetDiagnosticSnapshot();
    print_test_result("diagnostic initialized after push",
                      diag.is_initialized());
    print_test_result("last_push_at set after push",
                      diag.last_push_at >= before_push && diag.last_push_at <= after_push);
    print_test_result("latest_received_at reflects push",
                      diag.latest_received_at() >= before_push);

    // After GET_ROUND, latest_received_at advances
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    auto before_round = std::chrono::steady_clock::now();
    tracker.OnGetRound(101, 51, 0x1D00FFFF);
    auto after_round = std::chrono::steady_clock::now();
    diag = tracker.GetDiagnosticSnapshot();
    print_test_result("last_round_at set after GET_ROUND",
                      diag.last_round_at >= before_round && diag.last_round_at <= after_round);
    print_test_result("latest_received_at >= round time (most recent)",
                      diag.latest_received_at() >= before_round);

    // After keepalive, latest_received_at may advance further
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    auto before_ka = std::chrono::steady_clock::now();
    tracker.OnKeepaliveResponse(102, 52, 53, 10, 0xDEADBEEF, 0);
    diag = tracker.GetDiagnosticSnapshot();
    print_test_result("latest_received_at >= keepalive time",
                      diag.latest_received_at() >= before_ka);

    // Canonical is NOT initialized (no BLOCK_DATA received)
    auto canonical = tracker.GetCanonicalSnapshot();
    print_test_result("canonical NOT initialized without BLOCK_DATA",
                      !canonical.is_initialized());

    // Now receive BLOCK_DATA — canonical becomes initialized
    tracker.OnBlockDataReceived(103, 53, 0x1D00FFFF);
    canonical = tracker.GetCanonicalSnapshot();
    print_test_result("canonical IS initialized after BLOCK_DATA",
                      canonical.is_initialized());
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
    test_unified_advance_does_not_make_stale();
    test_channel_advance_makes_stale();
    test_is_tip_moved_detected();
    test_is_tip_moved_resets_on_new_template();
    test_difficulty_from_push_reflected_in_snapshot();
    test_post_push_timestamps_ordered_correctly();
    test_pre_push_template_identified_correctly();
    test_on_keepalive_response_unified();
    test_on_keepalive_response_legacy_zeros_safe();
    test_keepalive_response_sets_stake_height();
    test_peak_fork_score_high_water_mark();
    test_push_updates_per_channel_heights();
    test_push_updates_hash_height();
    test_push_keepalive_no_regression();
    test_advance_channel_target_only_advances();
    test_on_template_received_no_regress();
    test_doom_loop_prevention();
    test_stale_get_block_no_regression();
    test_on_template_metadata_monotonic();
    test_on_template_metadata_per_channel_no_regression();
    test_canonical_isolation();
    test_fork_scores_reset_on_template_advance();
    test_fork_scores_sticky_without_advance();
    test_on_block_data_received_monotonic();
    test_height_drift_from_canonical();
    test_canonical_hash_prev_block();
    test_diagnostic_observer_helpers();

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
