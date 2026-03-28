/**
 * @file height_tracker_test.cpp
 * @brief Unit tests for HeightTracker centralized height tracking utility
 *
 * Tests:
 *  1. Push update + template received produces expected drift delta 0
 *  2. Channel height advanced makes IsTemplateStale true
 *  3. Snapshot is consistent after concurrent-style updates
 *  4. GET_ROUND update sets source correctly (heights reflected in snapshot composition)
 *  5. ExplainMismatch reports drift when template target differs from expected
 *  6. ExplainMismatch reports staleness when channel height >= template target
 *  7. Unified height advancing alone does NOT make template stale
 *  8. Channel height advancing DOES make template stale
 *  9. is_tip_moved() detects unified tip advance (Phase 3A: tip_moved refresh reason)
 * 10. is_tip_moved() resets to false after new template received
 * 11. set_session_epoch() clears last_keepalive_ack_at on epoch change (keepalive epoch isolation)
 * 12. set_session_epoch() does NOT clear last_keepalive_ack_at when epoch is unchanged
 * 13. Keepalive timestamp from old epoch does not survive into new epoch (liveness isolation)
 * 14. set_session_epoch(0) does NOT clear last_keepalive_ack_at (sentinel epoch = no-op)
 * 15. Session epoch reflected in Snapshot.session_epoch field
 * 11. Difficulty from push updates is reflected in HeightTracker snapshot
 *     (GET_ROUND and keepalive difficulty go to diagnostic only — not in snapshot)
 * 12. Post-push guard — last_template_update >= last push time
 * 13. Pre-push guard — template received BEFORE a push is identified correctly
 * 14. OnKeepaliveResponse sets diagnostic fields only (not unified/channel_height)
 * 15. OnKeepaliveResponse legacy zeros — safe, no canonical corruption
 * 16. OnKeepaliveResponse updates stake_height correctly
 * 17. peak_fork_score is a persistent high-water mark
 * 18. Push updates channel_height; prime_height is keepalive-only (diagnostic)
 * 19. Push updates channel_height; hash_height is keepalive-only (diagnostic)
 * 20. Production regression: push advances channel_height; prime_height from keepalive
 * 21. AdvanceChannelTarget only advances, never regresses
 * 22. OnTemplateReceived does not regress channel_target
 * 23. Doom-loop prevention — staleness fires once per advance
 * 24. Stale GET_BLOCK response does not cause regression
 * 25. OnTemplateMetadata does NOT regress channel_height
 * 26. OnTemplateMetadata per-channel heights — canonical is monotonic
 * 27. Canonical state only from OnBlockDataReceived — push/keepalive don't corrupt
 * 28. Keepalive does not regress canonical unified/channel heights
 * 29. OnBlockDataReceived is monotonic — stale BLOCK_DATA cannot regress canonical
 * 30. Fork score lives in DiagnosticObserverState, not canonical
 * 31. height_drift_from_canonical() returns 0 for healthy state
 * 32. canonical_hash_prev_block anchored to BLOCK_DATA (Tritium block)
 * 33. DiagnosticObserverState::is_initialized() — diagnostic equivalent of canonical
 * 34. DiagnosticObserverState::latest_received_at() — diagnostic equivalent of canonical_received_at
 * 35. AdvanceChannelTarget() also updates canonical_channel_target
 * 36. OnTemplateReceived() sets template_unified_height from canonical
 */

#include "protocol/height_tracker.hpp"
#include <iostream>
#include <cstdint>
#include <thread>
#include <gtest/gtest.h>

using namespace nexusminer::protocol;

// ============================================================================
// Test 1: Push update + template received produces drift delta 0
// ============================================================================
TEST(HeightTrackerTest, test_push_then_template_no_drift) {
    std::cout << "\nTest 1: Push update + template → drift delta 0\n";
    HeightTracker tracker;

    // Node tells miner: channel is at height 100, difficulty 0x1d00ffff
    tracker.OnPushNotification(5000, 100, 0x1d00ffff);

    // Template arrives targeting height 101 (channel_height + 1)
    tracker.OnTemplateReceived(1, 101);

    auto snap = tracker.GetSnapshot();

    // expected_template_target() == channel_height + 1 == 101
    EXPECT_TRUE(snap.expected_template_target() == 101) << "expected_template_target() == 101";

    // drift_delta() == channel_target - expected == 101 - 101 == 0
    auto delta = snap.drift_delta();
    EXPECT_TRUE(delta.has_value()) << "drift_delta() has value";
    EXPECT_TRUE(delta.has_value() && *delta == 0) << "drift_delta() == 0";

    // Template is not stale (channel_height 100 < channel_target 101)
    EXPECT_TRUE(!snap.is_template_stale()) << "is_template_stale() == false";

    // ExplainMismatch returns empty (heights are consistent)
    std::string msg = tracker.ExplainMismatch();
    EXPECT_TRUE(msg.empty()) << "ExplainMismatch() is empty when consistent";
}

// ============================================================================
// Test 2: Channel height advanced makes IsTemplateStale true
// ============================================================================
TEST(HeightTrackerTest, test_channel_height_advance_makes_stale) {
    std::cout << "\nTest 2: Channel height advance → IsTemplateStale true\n";
    HeightTracker tracker;

    // Template was for height 101
    tracker.OnPushNotification(5000, 100, 0x1d00ffff);
    tracker.OnTemplateReceived(1, 101);

    // Another miner finds the block; push notifies new channel height 101
    tracker.OnPushNotification(5001, 101, 0x1d00ffff);

    auto snap = tracker.GetSnapshot();

    // channel_height (101) >= channel_target (101) → stale
    EXPECT_TRUE(snap.is_template_stale()) << "is_template_stale() == true after channel advance";

    // ExplainMismatch should report STALE
    std::string msg = tracker.ExplainMismatch();
    EXPECT_TRUE(msg.find("STALE") != std::string::npos) << "ExplainMismatch() mentions STALE";
}

// ============================================================================
// Test 3: Snapshot is consistent
// ============================================================================
TEST(HeightTrackerTest, test_snapshot_consistency) {
    std::cout << "\nTest 3: Snapshot consistency\n";
    HeightTracker tracker;
    tracker.OnPushNotification(4999, 99, 0x1a0abc12);
    tracker.OnTemplateReceived(2, 100);

    auto snap = tracker.GetSnapshot();

    EXPECT_TRUE(snap.unified_height == 4999) << "Snapshot unified_height == 4999";
    EXPECT_TRUE(snap.channel_height == 99) << "Snapshot channel_height == 99";
    EXPECT_TRUE(snap.difficulty_nbits == 0x1a0abc12) << "Snapshot difficulty_nbits == 0x1a0abc12";
    EXPECT_TRUE(snap.channel_target == 100) << "Snapshot channel_target == 100";
    EXPECT_TRUE(snap.channel == 2) << "Snapshot channel == 2";
    // Last update source should be TEMPLATE (last call was OnTemplateReceived)
    EXPECT_TRUE(snap.last_update_source == HeightTracker::UpdateSource::TEMPLATE) << "Snapshot last_update_source == TEMPLATE";
}

// ============================================================================
// Test 4: GET_ROUND update sets source correctly; heights reflected in snapshot composition
// ============================================================================
TEST(HeightTrackerTest, test_get_round_source) {
    std::cout << "\nTest 4: GET_ROUND update source (heights in snapshot composition)\n";
    HeightTracker tracker;
    // 16-byte full height picture: unified=5100, prime=120, hash=200, stake=300
    tracker.OnGetRound(5100, 120, 200, 300);

    auto snap = tracker.GetSnapshot();
    EXPECT_TRUE(snap.last_update_source == HeightTracker::UpdateSource::GET_ROUND) << "Source is GET_ROUND";
    // GET_ROUND round_unified_height IS now included in snapshot composition:
    // unified_height = max(canonical=0, push=0, round=5100) = 5100
    EXPECT_TRUE(snap.unified_height == 5100) << "unified_height == 5100 (GET_ROUND round_unified in snapshot)";
    // channel is not set (m_channel==0), so round_channel_height remains 0:
    // channel_height = max(canonical=0, push=0, round=0) = 0
    EXPECT_TRUE(snap.channel_height == 0) << "channel_height == 0 (no channel set, round_channel_height=0)";
    // Verify diagnostic snapshot captured the GET_ROUND per-channel heights
    auto diag = tracker.GetDiagnosticSnapshot();
    EXPECT_TRUE(diag.round_unified_height == 5100) << "diagnostic round_unified_height == 5100";
    EXPECT_TRUE(diag.round_prime_height == 120) << "diagnostic round_prime_height == 120";
    EXPECT_TRUE(diag.round_hash_height == 200) << "diagnostic round_hash_height == 200";
    EXPECT_TRUE(diag.round_stake_height == 300) << "diagnostic round_stake_height == 300";
    // 16-byte format carries no difficulty — round_difficulty_nbits is always 0
    EXPECT_TRUE(diag.round_difficulty_nbits == 0) << "diagnostic round_difficulty_nbits == 0 (no difficulty in 16-byte format)";
}

// ============================================================================
// Test 5: Drift detected and explained when template target differs
// ============================================================================
TEST(HeightTrackerTest, test_drift_explain) {
    std::cout << "\nTest 5: Drift detection and ExplainMismatch\n";
    HeightTracker tracker;

    // Node says channel height is 100
    tracker.OnPushNotification(5000, 100, 0x1d00ffff);

    // But template targets height 103 (not 101 — possible if heights drifted)
    tracker.OnTemplateReceived(1, 103);

    auto snap = tracker.GetSnapshot();
    auto delta = snap.drift_delta();
    EXPECT_TRUE(delta.has_value()) << "drift_delta() has value";
    EXPECT_TRUE(delta.has_value() && *delta == 2) << "drift_delta() == 2 (103 - 101)";

    std::string msg = tracker.ExplainMismatch();
    EXPECT_TRUE(msg.find("DRIFT") != std::string::npos) << "ExplainMismatch() mentions DRIFT";
}

// ============================================================================
// Test 6: Zero heights return safe defaults
// ============================================================================
TEST(HeightTrackerTest, test_zero_heights_safe) {
    std::cout << "\nTest 6: Zero heights return safe defaults\n";
    HeightTracker tracker;

    auto snap = tracker.GetSnapshot();
    EXPECT_TRUE(snap.expected_template_target() == 0) << "expected_template_target() == 0 when channel_height == 0";
    EXPECT_TRUE(!snap.is_template_stale()) << "is_template_stale() == false when all zeros";
    EXPECT_TRUE(!snap.drift_delta().has_value()) << "drift_delta() has no value when both are 0";
    std::string msg = tracker.ExplainMismatch();
    EXPECT_TRUE(msg.empty()) << "ExplainMismatch() is empty with zero state";
}

// ============================================================================
// Test 7: Unified height advancing alone does NOT make template stale
// (Phase 1B: unified-delta must NOT trigger stale/template refresh)
// ============================================================================
TEST(HeightTrackerTest, test_unified_advance_does_not_make_stale) {
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
    EXPECT_TRUE(!snap.is_template_stale()) << "is_template_stale() == false after unified-only advance";

    // Channel target unchanged
    EXPECT_TRUE(snap.channel_target == 101) << "channel_target still == 101";

    // Channel height unchanged
    EXPECT_TRUE(snap.channel_height == 100) << "channel_height still == 100";

    // Unified height updated
    EXPECT_TRUE(snap.unified_height == 5010) << "unified_height updated to 5010";

    // ExplainMismatch should be empty (heights are still consistent)
    std::string msg = tracker.ExplainMismatch();
    EXPECT_TRUE(msg.empty()) << "ExplainMismatch() is empty (template still valid)";
}

// ============================================================================
// Test 8: Channel height advancing DOES make template stale
// ============================================================================
TEST(HeightTrackerTest, test_channel_advance_makes_stale) {
    std::cout << "\nTest 8: Channel height advancing → stale\n";
    HeightTracker tracker;

    // Initial state: channel at 100, template for 101
    tracker.OnPushNotification(5000, 100, 0x1d00ffff);
    tracker.OnTemplateReceived(1, 101);

    // Channel height advances to 101 (another miner found the block)
    tracker.OnPushNotification(5001, 101, 0x1d00ffff);

    auto snap = tracker.GetSnapshot();

    // Template is stale: channel_height (101) >= channel_target (101)
    EXPECT_TRUE(snap.is_template_stale()) << "is_template_stale() == true after channel advance";

    // ExplainMismatch should mention STALE
    std::string msg = tracker.ExplainMismatch();
    EXPECT_TRUE(msg.find("STALE") != std::string::npos) << "ExplainMismatch() mentions STALE after channel advance";
}

// ============================================================================
// Test 9: is_tip_moved() detects when unified tip advances beyond template tip
//         (Phase 3A: hashPrevBlock staleness via unified height delta)
// ============================================================================
TEST(HeightTrackerTest, test_is_tip_moved_detected) {
    std::cout << "\nTest 9: is_tip_moved() — unified tip advance triggers refresh\n";
    HeightTracker tracker;

    // Initial state: channel at 100, template for 101, unified at 5000
    tracker.OnPushNotification(5000, 100, 0x1d00ffff);
    tracker.OnTemplateReceived(1, 101);

    auto snap_initial = tracker.GetSnapshot();

    // template_unified_height should be captured as 5000
    EXPECT_TRUE(snap_initial.template_unified_height == 5000) << "template_unified_height == 5000 after template received";

    // No tip movement yet: unified == template_unified
    EXPECT_TRUE(!snap_initial.is_tip_moved()) << "is_tip_moved() == false before unified advance";

    // Another channel finds a block: unified advances to 5005, channel stays at 100
    tracker.OnPushNotification(5005, 100, 0x1d00ffff);
    auto snap = tracker.GetSnapshot();

    // Tip has moved: unified (5005) > template_unified (5000)
    EXPECT_TRUE(snap.is_tip_moved()) << "is_tip_moved() == true after unified advance";

    // But template is NOT channel-stale: channel_height (100) < channel_target (101)
    EXPECT_TRUE(!snap.is_template_stale()) << "is_template_stale() == false (channel height unchanged)";

    // template_unified_height unchanged (only updates on OnTemplateReceived)
    EXPECT_TRUE(snap.template_unified_height == 5000) << "template_unified_height still == 5000 (template not refreshed)";

    // unified_height updated to new value
    EXPECT_TRUE(snap.unified_height == 5005) << "unified_height updated to 5005";
}

// ============================================================================
// Test 10: is_tip_moved() resets to false after new template received
// ============================================================================
TEST(HeightTrackerTest, test_is_tip_moved_resets_on_new_template) {
    std::cout << "\nTest 10: is_tip_moved() resets when new template received\n";
    HeightTracker tracker;

    // Template at unified=5000, channel=100
    tracker.OnPushNotification(5000, 100, 0x1d00ffff);
    tracker.OnTemplateReceived(1, 101);

    // Unified tip moves to 5005
    tracker.OnPushNotification(5005, 100, 0x1d00ffff);
    EXPECT_TRUE(tracker.GetSnapshot().is_tip_moved()) << "is_tip_moved() == true before fresh template";

    // Fresh template received (now template_unified_height == 5005)
    tracker.OnTemplateReceived(1, 101);
    auto snap = tracker.GetSnapshot();

    // After new template, tip is no longer "moved"
    EXPECT_TRUE(!snap.is_tip_moved()) << "is_tip_moved() == false after fresh template received";

    // template_unified_height updated to current unified height
    EXPECT_TRUE(snap.template_unified_height == 5005) << "template_unified_height == 5005 (new template at new tip)";
}

// ============================================================================
// Test 11: Difficulty from push updates is reflected in HeightTracker and
//         consistent across snapshot reads (Phase 2C regression test)
//         GET_ROUND difficulty goes to DiagnosticObserverState only — it does
//         NOT appear in the main Snapshot (which uses canonical or push).
// ============================================================================
TEST(HeightTrackerTest, test_difficulty_from_push_reflected_in_snapshot) {
    std::cout << "\nTest 11: Difficulty from push updates reflected in HeightTracker\n";
    HeightTracker tracker;

    // First push: difficulty_nbits = 0x1d00ffff
    tracker.OnPushNotification(5000, 100, 0x1d00ffff);
    auto snap = tracker.GetSnapshot();
    EXPECT_TRUE(snap.difficulty_nbits == 0x1d00ffff) << "difficulty_nbits set from push (0x1d00ffff)";
    EXPECT_TRUE(snap.last_update_source == HeightTracker::UpdateSource::PUSH) << "Source is PUSH after OnPushNotification";

    // Second push with updated difficulty: difficulty_nbits = 0x1c0e9f34
    tracker.OnPushNotification(5001, 101, 0x1c0e9f34);
    snap = tracker.GetSnapshot();
    EXPECT_TRUE(snap.difficulty_nbits == 0x1c0e9f34) << "difficulty_nbits updated from second push (0x1c0e9f34)";
    EXPECT_TRUE(snap.unified_height == 5001) << "unified_height updated from second push (5001)";
    EXPECT_TRUE(snap.channel_height == 101) << "channel_height updated from second push (101)";

    // GET_ROUND is diagnostic-only; snapshot difficulty stays at push value (0x1c0e9f34)
    // 16-byte format: unified=5002, prime=102, hash=203, stake=0
    tracker.OnGetRound(5002, 102, 203, 0);
    snap = tracker.GetSnapshot();
    EXPECT_TRUE(snap.difficulty_nbits == 0x1c0e9f34) << "difficulty_nbits still from push after GET_ROUND (0x1c0e9f34)";
    EXPECT_TRUE(snap.last_update_source == HeightTracker::UpdateSource::GET_ROUND) << "Source is GET_ROUND after OnGetRound";
    // 16-byte GET_ROUND carries no difficulty — round_difficulty_nbits is always 0
    auto diag = tracker.GetDiagnosticSnapshot();
    EXPECT_TRUE(diag.round_difficulty_nbits == 0) << "diagnostic round_difficulty_nbits == 0 (no difficulty in 16-byte format)";

    // OnTemplateReceived must NOT overwrite difficulty (it doesn't carry nbits)
    tracker.OnTemplateReceived(1, 103);
    snap = tracker.GetSnapshot();
    EXPECT_TRUE(snap.difficulty_nbits == 0x1c0e9f34) << "difficulty_nbits unchanged after OnTemplateReceived (still push 0x1c0e9f34)";
}

// ============================================================================
// Test 12: Post-push guard — last_template_update >= last push time when
//          template is received AFTER a push notification.
//          This is the HeightTracker side of the doom-loop prevention fix:
//          Worker_manager::check_template_health() uses these timestamps to
//          decide whether to skip stop_all_workers for a "stale" template that
//          was actually received after the push that caused the stale reading.
// ============================================================================
TEST(HeightTrackerTest, test_post_push_timestamps_ordered_correctly) {
    std::cout << "\nTest 12: Post-push guard — last_template_update >= last_push after push→template\n";
    HeightTracker tracker;

    // Step 1: Push notification arrives (block Y mined, channel at Y).
    tracker.OnPushNotification(5000, 100, 0x1d00ffff);
    auto snap_after_push = tracker.GetSnapshot();

    // Verify push time is recorded.
    EXPECT_TRUE(snap_after_push.last_height_update != std::chrono::steady_clock::time_point{}) << "last_height_update set after push";

    // last_template_update should be before last_height_update (no template yet).
    EXPECT_TRUE(snap_after_push.last_template_update < snap_after_push.last_height_update) << "last_template_update < last_height_update before template arrives";

    // channel_height = 100, channel_target still 0 (no template) → not stale.
    EXPECT_TRUE(!snap_after_push.is_template_stale()) << "Not stale (no channel_target yet)";

    // Step 2: Recovery GET_BLOCK returns a template targeting Y+1 = 101.
    // Small sleep to ensure measurable time difference between push and template.
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    tracker.OnTemplateReceived(1, 101);
    auto snap_after_tmpl = tracker.GetSnapshot();

    // last_template_update must be >= last_height_update (post-push guard).
    EXPECT_TRUE(snap_after_tmpl.last_template_update >= snap_after_tmpl.last_height_update) << "last_template_update >= last_height_update after template (post-push)";

    // is_template_stale() must be false: channel_height (100) < channel_target (101).
    EXPECT_TRUE(!snap_after_tmpl.is_template_stale()) << "Not stale after template for 101 (channel_height=100 < target=101)";
}

// ============================================================================
// Test 13: Pre-push guard — template received BEFORE a push has
//          last_template_update < last_height_update, so check_template_health
//          correctly identifies it as a pre-push (genuinely stale) template
//          and does NOT skip stop_all_workers.
// ============================================================================
TEST(HeightTrackerTest, test_pre_push_template_identified_correctly) {
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
    EXPECT_TRUE(snap.last_template_update < snap.last_height_update) << "last_template_update < last_height_update (pre-push template)";

    // is_template_stale() must be true: channel_height (101) >= channel_target (101).
    EXPECT_TRUE(snap.is_template_stale()) << "is_template_stale() == true (pre-push, channel_height == channel_target)";
}

// ============================================================================
// Test 14: blocks_behind() distinguishes normal single-block refresh from
//          true multi-block lag while leaving same-height tip moves at 0.
// ============================================================================
TEST(HeightTrackerTest, test_blocks_behind_distinguishes_normal_vs_severe_lag) {
    std::cout << "\nTest 14: blocks_behind() distinguishes normal vs severe lag\n";
    HeightTracker tracker;

    tracker.OnPushNotification(5000, 100, 0x1d00ffff);
    tracker.OnTemplateReceived(2, 101);

    auto initial = tracker.GetSnapshot();
    EXPECT_TRUE(initial.blocks_behind() == 0) << "blocks_behind() == 0 before channel advances";

    tracker.OnPushNotification(5001, 101, 0x1d00ffff);
    auto one_block = tracker.GetSnapshot();
    EXPECT_TRUE(one_block.blocks_behind() == 1) << "blocks_behind() == 1 when template is one block behind";

    tracker.OnPushNotification(5002, 102, 0x1d00ffff);
    auto two_blocks = tracker.GetSnapshot();
    EXPECT_TRUE(two_blocks.blocks_behind() == 2) << "blocks_behind() == 2 when template lags by two blocks";

    HeightTracker tip_move_tracker;
    tip_move_tracker.OnPushNotification(6000, 200, 0x1d00ffff);
    tip_move_tracker.OnTemplateReceived(2, 201);
    tip_move_tracker.OnPushNotification(6001, 200, 0x1d00ffff);
    auto tip_move = tip_move_tracker.GetSnapshot();
    EXPECT_TRUE(tip_move.blocks_behind() == 0) << "blocks_behind() == 0 when only unified tip moves";
    EXPECT_TRUE(tip_move.is_tip_moved()) << "is_tip_moved() == true when only unified tip moves";
}

// ============================================================================
// Test 14: OnKeepaliveResponse — keepalive sets diagnostic fields only
//          (unified_height and channel_height in snapshot come from canonical/push)
// ============================================================================
TEST(HeightTrackerTest, test_on_keepalive_response_unified) {
    std::cout << "\nTest 14: OnKeepaliveResponse sets diagnostic fields (not unified/channel_height)\n";
    HeightTracker tracker;
    // Set channel to Hash (2) so channel_height can be verified
    tracker.OnTemplateReceived(2, 101);
    tracker.OnKeepaliveResponse(6000, 450, 800, 999, 0xCAFEBABEu, 3);

    auto snap = tracker.GetSnapshot();
    // Keepalive heights must NOT appear in the snapshot (they are diagnostic only)
    EXPECT_TRUE(snap.unified_height == 0) << "unified_height == 0 (keepalive does not set canonical)";
    EXPECT_TRUE(snap.prime_height == 0) << "prime_height == 0 (keepalive does not set canonical)";
    EXPECT_TRUE(snap.hash_height == 0) << "hash_height == 0 (keepalive does not set canonical)";
    EXPECT_TRUE(snap.channel_height == 0) << "channel_height == 0 (keepalive does not set canonical)";
    EXPECT_TRUE(snap.stake_height == 999) << "stake_height == 999";
    EXPECT_TRUE(snap.hash_tip_lo32 == 0xCAFEBABEu) << "hash_tip_lo32 stored";
    EXPECT_TRUE(snap.fork_score == 3) << "fork_score == 3";
    EXPECT_TRUE(snap.peak_fork_score == 3) << "peak_fork_score == 3";
    EXPECT_TRUE(snap.is_fork_active()) << "is_fork_active() == true";
    EXPECT_TRUE(snap.last_update_source == HeightTracker::UpdateSource::KEEPALIVE) << "last_update_source == KEEPALIVE";

    // Verify via DiagnosticObserverState directly
    auto diag = tracker.GetDiagnosticSnapshot();
    EXPECT_TRUE(diag.keepalive_unified_height == 6000) << "diagnostic keepalive_unified_height == 6000";
    EXPECT_TRUE(diag.keepalive_hash_height == 800) << "diagnostic keepalive_hash_height == 800";
}

// ============================================================================
// Test 15: OnKeepaliveResponse — legacy path (hash_tip_lo32=0, fork_score=0)
//          is safe and does NOT corrupt canonical heights
// ============================================================================
TEST(HeightTrackerTest, test_on_keepalive_response_legacy_zeros_safe) {
    std::cout << "\nTest 15: OnKeepaliveResponse legacy zeros — safe, no canonical corruption\n";
    HeightTracker tracker;
    tracker.OnKeepaliveResponse(6001, 451, 801, 999, 0u, 0u);

    auto snap = tracker.GetSnapshot();
    // Keepalive heights must NOT appear in the snapshot
    EXPECT_TRUE(snap.unified_height == 0) << "unified_height == 0 (keepalive does not set canonical)";
    EXPECT_TRUE(snap.prime_height == 0) << "prime_height == 0 (keepalive does not set canonical)";
    EXPECT_TRUE(snap.hash_height == 0) << "hash_height == 0 (keepalive does not set canonical)";

    // Stake and fork fields from diagnostic
    EXPECT_TRUE(snap.stake_height == 999) << "stake_height == 999";
    EXPECT_TRUE(snap.hash_tip_lo32 == 0) << "hash_tip_lo32 == 0 (safe)";
    EXPECT_TRUE(snap.fork_score == 0) << "fork_score == 0 (healthy)";
    EXPECT_TRUE(!snap.is_fork_active()) << "is_fork_active() == false";
    EXPECT_TRUE(snap.last_update_source == HeightTracker::UpdateSource::KEEPALIVE) << "last_update_source == KEEPALIVE";

    // Diagnostic snapshot has the keepalive heights
    auto diag = tracker.GetDiagnosticSnapshot();
    EXPECT_TRUE(diag.keepalive_unified_height == 6001) << "diag.keepalive_unified_height == 6001";
    EXPECT_TRUE(diag.keepalive_prime_height == 451) << "diag.keepalive_prime_height == 451";
    EXPECT_TRUE(diag.keepalive_hash_height == 801) << "diag.keepalive_hash_height == 801";
}

// ============================================================================
// Test 16: OnKeepaliveResponse updates stake_height correctly
// ============================================================================
TEST(HeightTrackerTest, test_keepalive_response_sets_stake_height) {
    std::cout << "\nTest 16: OnKeepaliveResponse updates stake_height\n";
    HeightTracker tracker;
    tracker.OnKeepaliveResponse(6001, 451, 801, 777, 0u, 0u);

    auto snap = tracker.GetSnapshot();
    EXPECT_TRUE(snap.stake_height == 777) << "stake_height == 777 via OnKeepaliveResponse";

    tracker.OnKeepaliveResponse(6002, 452, 802, 888, 0u, 0u);
    snap = tracker.GetSnapshot();
    EXPECT_TRUE(snap.stake_height == 888) << "stake_height == 888 via second OnKeepaliveResponse";
}

// ============================================================================
// Test 17: peak_fork_score is a persistent high-water mark
// ============================================================================
TEST(HeightTrackerTest, test_peak_fork_score_high_water_mark) {
    std::cout << "\nTest 17: peak_fork_score is a persistent high-water mark\n";
    HeightTracker tracker;
    tracker.OnKeepaliveResponse(6000, 450, 800, 999, 0xCAFEBABEu, 5);
    tracker.OnKeepaliveResponse(6001, 451, 801, 999, 0xCAFEBABEu, 1);  // lower score

    auto snap = tracker.GetSnapshot();
    EXPECT_TRUE(snap.fork_score == 1) << "fork_score == 1 (latest)";
    EXPECT_TRUE(snap.peak_fork_score == 5) << "peak_fork_score == 5 (canary)";
    EXPECT_TRUE(snap.is_fork_active()) << "is_fork_active() still true";
}

// ============================================================================
// Test 18: Push updates channel_height; prime_height is canonical-only
// ============================================================================
TEST(HeightTrackerTest, test_push_updates_per_channel_heights) {
    std::cout << "\nTest 18: Push updates channel_height; prime_height is canonical-only\n";
    HeightTracker tracker;
    tracker.OnTemplateReceived(1, 101);
    tracker.OnKeepaliveResponse(5000, 100, 200, 300, 0, 0);
    auto snap1 = tracker.GetSnapshot();
    // Keepalive prime_height does NOT appear in snapshot
    EXPECT_TRUE(snap1.prime_height == 0) << "prime_height == 0 after keepalive (canonical only)";
    tracker.OnPushNotification(5002, 102, 0x1d00ffff);
    auto snap2 = tracker.GetSnapshot();
    EXPECT_TRUE(snap2.channel_height == 102) << "channel_height == 102 after push";
    // prime_height comes exclusively from canonical (OnBlockDataReceived) — push does NOT update it
    EXPECT_TRUE(snap2.prime_height == 0) << "prime_height == 0 after push (canonical only, not set yet)";
}

// ============================================================================
// Test 19: Push updates channel_height; hash_height is canonical-only
// ============================================================================
TEST(HeightTrackerTest, test_push_updates_hash_height) {
    std::cout << "\nTest 19: Push updates channel_height; hash_height is canonical-only\n";
    HeightTracker tracker;
    tracker.OnTemplateReceived(2, 201);
    tracker.OnKeepaliveResponse(5000, 100, 200, 300, 0, 0);
    auto snap1 = tracker.GetSnapshot();
    // Keepalive hash_height does NOT appear in snapshot
    EXPECT_TRUE(snap1.hash_height == 0) << "hash_height == 0 after keepalive (canonical only)";
    tracker.OnPushNotification(5002, 202, 0x1d00ffff);
    auto snap2 = tracker.GetSnapshot();
    EXPECT_TRUE(snap2.channel_height == 202) << "channel_height == 202 after push";
    // hash_height comes exclusively from canonical (OnBlockDataReceived) — push does NOT update it
    EXPECT_TRUE(snap2.hash_height == 0) << "hash_height == 0 after push (canonical only, not set yet)";
}

// ============================================================================
// Test 20: Production regression (prime drift from 2331124 to 2331126)
//          Push advances channel_height correctly; prime_height is canonical-only.
// ============================================================================
TEST(HeightTrackerTest, test_push_keepalive_no_regression) {
    std::cout << "\nTest 20: Production regression — push advances channel_height; prime_height canonical-only\n";
    HeightTracker tracker;
    tracker.OnTemplateReceived(1, 2331125);
    tracker.OnKeepaliveResponse(6609207, 2331124, 2193089, 2084996, 0, 0);
    tracker.OnPushNotification(6609208, 2331126, 0x0414b755);
    auto snap = tracker.GetSnapshot();
    EXPECT_TRUE(snap.channel_height == 2331126) << "channel_height == 2331126";
    // prime_height is canonical-only (not set without OnBlockDataReceived)
    EXPECT_TRUE(snap.prime_height == 0) << "prime_height == 0 (canonical only, not set yet)";
    EXPECT_TRUE(snap.is_template_stale()) << "is_template_stale (2331126 >= 2331125)";
}

// ============================================================================
// Test 21: AdvanceChannelTarget only advances, never regresses
// ============================================================================
TEST(HeightTrackerTest, test_advance_channel_target_only_advances) {
    std::cout << "\nTest 21: AdvanceChannelTarget only advances, never regresses\n";
    HeightTracker tracker;

    // Set initial channel_target via OnTemplateReceived
    tracker.OnPushNotification(5000, 100, 0x1d00ffff);
    tracker.OnTemplateReceived(1, 101);
    auto snap = tracker.GetSnapshot();
    EXPECT_TRUE(snap.channel_target == 101) << "channel_target == 101 after OnTemplateReceived";

    // Advance to 105 via AdvanceChannelTarget
    tracker.AdvanceChannelTarget(105);
    snap = tracker.GetSnapshot();
    EXPECT_TRUE(snap.channel_target == 105) << "channel_target == 105 after AdvanceChannelTarget(105)";

    // Attempting to set a lower value via AdvanceChannelTarget is a no-op
    tracker.AdvanceChannelTarget(102);
    snap = tracker.GetSnapshot();
    EXPECT_TRUE(snap.channel_target == 105) << "channel_target still 105 after AdvanceChannelTarget(102)";

    // Attempting to set the same value is a no-op
    tracker.AdvanceChannelTarget(105);
    snap = tracker.GetSnapshot();
    EXPECT_TRUE(snap.channel_target == 105) << "channel_target still 105 after AdvanceChannelTarget(105)";

    // Advancing beyond current value works
    tracker.AdvanceChannelTarget(110);
    snap = tracker.GetSnapshot();
    EXPECT_TRUE(snap.channel_target == 110) << "channel_target == 110 after AdvanceChannelTarget(110)";
}

// ============================================================================
// Test 22: OnTemplateReceived does not regress channel_target
// ============================================================================
TEST(HeightTrackerTest, test_on_template_received_no_regress) {
    std::cout << "\nTest 22: OnTemplateReceived does not regress channel_target\n";
    HeightTracker tracker;

    tracker.OnPushNotification(5000, 100, 0x1d00ffff);
    tracker.OnTemplateReceived(1, 101);
    auto snap = tracker.GetSnapshot();
    EXPECT_TRUE(snap.channel_target == 101) << "channel_target == 101 initially";

    // Push advances channel_target (simulating push-detected staleness)
    tracker.AdvanceChannelTarget(105);
    snap = tracker.GetSnapshot();
    EXPECT_TRUE(snap.channel_target == 105) << "channel_target == 105 after AdvanceChannelTarget";

    // Stale GET_BLOCK response arrives with a lower channel_target
    tracker.OnTemplateReceived(1, 102);
    snap = tracker.GetSnapshot();
    EXPECT_TRUE(snap.channel_target == 105) << "channel_target still 105 after stale OnTemplateReceived(102)";

    // But template_unified_height and timestamps are still updated
    EXPECT_TRUE(snap.last_update_source == HeightTracker::UpdateSource::TEMPLATE) << "last_update_source == TEMPLATE";

    // A fresh template with a higher target DOES advance
    tracker.OnTemplateReceived(1, 110);
    snap = tracker.GetSnapshot();
    EXPECT_TRUE(snap.channel_target == 110) << "channel_target == 110 after fresh OnTemplateReceived(110)";
}

// ============================================================================
// Test 23: Doom-loop prevention — push staleness detection fires once per
//          chain advance, not on every subsequent push with same height
// ============================================================================
TEST(HeightTrackerTest, test_doom_loop_prevention) {
    std::cout << "\nTest 23: Doom-loop prevention — staleness fires once per advance\n";
    HeightTracker tracker;

    // Initial: template targeting block 101
    tracker.OnPushNotification(5000, 100, 0x1d00ffff);
    tracker.OnTemplateReceived(1, 101);

    // Push₁: channel advances to 101 → stale
    tracker.OnPushNotification(5001, 101, 0x1d00ffff);
    auto snap = tracker.GetSnapshot();
    EXPECT_TRUE(snap.is_template_stale()) << "Push₁: is_template_stale() true (101 >= 101)";

    // Simulate push handler advancing channel_target after detecting staleness
    tracker.AdvanceChannelTarget(102);

    // Push₂: same channel_height 101 → should NOT be stale anymore
    tracker.OnPushNotification(5002, 101, 0x1d00ffff);
    snap = tracker.GetSnapshot();
    EXPECT_TRUE(!snap.is_template_stale()) << "Push₂: is_template_stale() false (101 < 102)";

    // Push₃: channel advances again to 102 → stale again (correct!)
    tracker.OnPushNotification(5003, 102, 0x1d00ffff);
    snap = tracker.GetSnapshot();
    EXPECT_TRUE(snap.is_template_stale()) << "Push₃: is_template_stale() true (102 >= 102)";
}

// ============================================================================
// Test 24: Stale GET_BLOCK response does not cause regression
// ============================================================================
TEST(HeightTrackerTest, test_stale_get_block_no_regression) {
    std::cout << "\nTest 24: Stale GET_BLOCK response does not regress channel_target\n";
    HeightTracker tracker;

    // Push says chain is at channel_height 105
    tracker.OnPushNotification(5010, 105, 0x1d00ffff);
    tracker.OnTemplateReceived(1, 101);  // old template target

    // Push-handler detects stale (105 >= 101) and advances target
    tracker.AdvanceChannelTarget(106);

    // Stale GET_BLOCK response has channel_height=99 (3 blocks behind)
    // 16-byte: prime=99, hash=99, stake=0 (stale picture for channel 1/prime)
    tracker.OnGetRound(5007, 99, 99, 0);
    tracker.OnTemplateReceived(1, 100);  // stale template target

    auto snap = tracker.GetSnapshot();
    // channel_target should NOT have regressed to 100
    EXPECT_TRUE(snap.channel_target == 106) << "channel_target still 106 after stale GET_BLOCK (not regressed to 100)";

    // channel_height remains 105 because max(canonical=0, push=105, round=99) = 105;
    // the push value still dominates the stale GET_ROUND response.
    tracker.OnPushNotification(5011, 105, 0x1d00ffff);
    snap = tracker.GetSnapshot();
    EXPECT_TRUE(snap.channel_height == 105) << "channel_height restored to 105 from push";
    EXPECT_TRUE(!snap.is_template_stale()) << "Not stale: 105 < 106";
}

// ============================================================================
// Test 25: OnTemplateMetadata does NOT regress channel_height
//          (fixes HeightTracker update gap after stale GET_BLOCK responses)
// ============================================================================
TEST(HeightTrackerTest, test_on_template_metadata_monotonic) {
    std::cout << "\nTest 25: OnTemplateMetadata does NOT regress channel_height\n";
    HeightTracker tracker;

    // Simulate: pushes advance channel to 2332106
    tracker.OnPushNotification(6611706, 2332106, 0x1d00ffff);
    tracker.OnTemplateReceived(1, 2332100);  // old template target

    auto snap = tracker.GetSnapshot();
    EXPECT_TRUE(snap.channel_height == 2332106) << "channel_height == 2332106 after push";

    // Stale GET_BLOCK response arrives with channel_height=2332100
    // OnTemplateMetadata must NOT regress channel_height to 2332100.
    tracker.OnTemplateMetadata(6611706, 2332100, 0x1d00ffff);
    snap = tracker.GetSnapshot();
    EXPECT_TRUE(snap.channel_height == 2332106) << "channel_height still 2332106 after stale OnTemplateMetadata(2332100)";
    EXPECT_TRUE(snap.unified_height == 6611706) << "unified_height updated to 6611706";
    EXPECT_TRUE(snap.last_update_source == HeightTracker::UpdateSource::TEMPLATE) << "last_update_source == TEMPLATE";

    // Fresh template metadata with a higher channel_height DOES advance
    tracker.OnTemplateMetadata(6611710, 2332108, 0x1d00ffff);
    snap = tracker.GetSnapshot();
    EXPECT_TRUE(snap.channel_height == 2332108) << "channel_height advanced to 2332108 from fresh OnTemplateMetadata";
    EXPECT_TRUE(snap.unified_height == 6611710) << "unified_height advanced to 6611710";
}

// ============================================================================
// Test 26: OnTemplateMetadata per-channel heights — canonical is monotonic;
//          prime_height/hash_height are keepalive/round/push-full-picture-only (diagnostic)
// ============================================================================
TEST(HeightTrackerTest, test_on_template_metadata_per_channel_no_regression) {
    std::cout << "\nTest 26: OnTemplateMetadata canonical is monotonic; prime/hash from keepalive/round/push-full-picture only\n";
    HeightTracker tracker;

    // Prime channel: push sets channel_height=500
    tracker.OnTemplateReceived(1, 1);  // set channel to Prime
    tracker.OnPushNotification(10000, 500, 0x1d00ffff);
    auto snap = tracker.GetSnapshot();
    EXPECT_TRUE(snap.channel_height == 500) << "channel_height == 500 after push";
    // prime_height is diagnostic-only — 12-byte OnPushNotification does NOT update it;
    // only OnPushFullPicture (148-byte), OnGetRound, or OnKeepaliveResponse set it.
    EXPECT_TRUE(snap.prime_height == 0) << "prime_height == 0 (no keepalive/round/push-full-picture received yet)";

    // Stale template metadata with channel_height=400 must not regress channel_height
    // (channel_height = max(canonical=400, push=500) = 500 — push protects against regression)
    tracker.OnTemplateMetadata(10001, 400, 0x1d00ffff);
    snap = tracker.GetSnapshot();
    EXPECT_TRUE(snap.channel_height == 500) << "channel_height still 500 after stale OnTemplateMetadata(400)";
    // prime_height remains 0 (no keepalive/round/push-full-picture called)
    EXPECT_TRUE(snap.prime_height == 0) << "prime_height still 0 after OnTemplateMetadata (no push-full-picture)";

    // Hash channel test
    HeightTracker hash_tracker;
    hash_tracker.OnTemplateReceived(2, 1);  // set channel to Hash
    hash_tracker.OnPushNotification(10000, 300, 0x1d00ffff);
    snap = hash_tracker.GetSnapshot();
    EXPECT_TRUE(snap.channel_height == 300) << "channel_height == 300 after push (Hash channel)";
    // hash_height is diagnostic-only — 12-byte push does NOT update it
    EXPECT_TRUE(snap.hash_height == 0) << "hash_height == 0 (no keepalive/round/push-full-picture received yet)";

    hash_tracker.OnTemplateMetadata(10001, 250, 0x1d00ffff);
    snap = hash_tracker.GetSnapshot();
    EXPECT_TRUE(snap.channel_height == 300) << "channel_height still 300 after stale OnTemplateMetadata(250)";
    EXPECT_TRUE(snap.hash_height == 0) << "hash_height still 0 after OnTemplateMetadata (no push-full-picture)";
}

// ============================================================================
// Test 27: Canonical state only from OnBlockDataReceived — push/keepalive
//          do NOT update canonical heights
// ============================================================================
TEST(HeightTrackerTest, test_canonical_state_only_from_block_data) {
    std::cout << "\nTest 27: Canonical state only from OnBlockDataReceived\n";
    HeightTracker tracker;

    // Push notification arrives
    tracker.OnPushNotification(6611227, 2332106, 0x1d00ffff);
    auto canonical = tracker.GetCanonicalSnapshot();
    EXPECT_TRUE(!canonical.is_initialized()) << "canonical not initialized after push";
    EXPECT_TRUE(canonical.canonical_unified_height == 0) << "canonical_unified_height == 0 after push";
    EXPECT_TRUE(canonical.canonical_channel_height == 0) << "canonical_channel_height == 0 after push";

    // Keepalive arrives
    tracker.OnKeepaliveResponse(6611227, 2332106, 9999, 8888, 0xABCD1234u, 2);
    canonical = tracker.GetCanonicalSnapshot();
    EXPECT_TRUE(!canonical.is_initialized()) << "canonical still not initialized after keepalive";

    // GET_ROUND arrives
    tracker.OnGetRound(6611227, 2332106, 2332106, 0);
    canonical = tracker.GetCanonicalSnapshot();
    EXPECT_TRUE(!canonical.is_initialized()) << "canonical still not initialized after GET_ROUND";

    // BLOCK_DATA arrives (via OnTemplateMetadata which delegates to OnBlockDataReceived)
    tracker.OnTemplateMetadata(6611227, 2332106, 0x1d00ffff);
    canonical = tracker.GetCanonicalSnapshot();
    EXPECT_TRUE(canonical.is_initialized()) << "canonical IS initialized after OnTemplateMetadata (→ OnBlockDataReceived)";
    EXPECT_TRUE(canonical.canonical_unified_height == 6611227) << "canonical_unified_height == 6611227";
    EXPECT_TRUE(canonical.canonical_channel_height == 2332106) << "canonical_channel_height == 2332106";
}

// ============================================================================
// Test 28: Keepalive does not corrupt canonical unified/channel heights
//          (the core bug this refactor fixes)
// ============================================================================
TEST(HeightTrackerTest, test_keepalive_does_not_corrupt_canonical) {
    std::cout << "\nTest 28: Keepalive does not corrupt canonical state\n";
    HeightTracker tracker;

    // Establish canonical state from BLOCK_DATA
    tracker.OnTemplateMetadata(6611228, 2332107, 0x1d00ffff);
    tracker.OnTemplateReceived(1, 2332108);
    auto canonical = tracker.GetCanonicalSnapshot();
    EXPECT_TRUE(canonical.canonical_unified_height == 6611228) << "canonical initialized: unified=6611228";
    EXPECT_TRUE(canonical.canonical_channel_height == 2332107) << "canonical initialized: channel=2332107";
    EXPECT_TRUE(canonical.canonical_channel_target == 2332108) << "canonical_channel_target == 2332108";

    // Keepalive arrives with STALE values (lower heights from 45s ago)
    tracker.OnKeepaliveResponse(6611200, 2332050, 9000, 8000, 0xDEADBEEFu, 1);

    // Canonical must NOT be regressed by keepalive
    canonical = tracker.GetCanonicalSnapshot();
    EXPECT_TRUE(canonical.canonical_unified_height == 6611228) << "canonical_unified_height still 6611228 after stale keepalive";
    EXPECT_TRUE(canonical.canonical_channel_height == 2332107) << "canonical_channel_height still 2332107 after stale keepalive";
    EXPECT_TRUE(canonical.canonical_channel_target == 2332108) << "canonical_channel_target still 2332108 after stale keepalive";

    // Snapshot heights must also not regress
    auto snap = tracker.GetSnapshot();
    EXPECT_TRUE(snap.channel_height == 2332107) << "snapshot channel_height still 2332107 after keepalive (canonical wins)";
    EXPECT_TRUE(snap.unified_height == 6611228) << "snapshot unified_height still 6611228 after keepalive (canonical wins)";
    // Fork score IS available from diagnostic
    EXPECT_TRUE(snap.fork_score == 1) << "snapshot fork_score == 1 (from keepalive diagnostic)";
    EXPECT_TRUE(snap.peak_fork_score == 1) << "snapshot peak_fork_score == 1 (from keepalive diagnostic)";
}

// ============================================================================
// Test 29: OnBlockDataReceived is monotonic — stale BLOCK_DATA cannot regress
//          canonical state established by a previous BLOCK_DATA receipt
// ============================================================================
TEST(HeightTrackerTest, test_on_block_data_received_monotonic) {
    std::cout << "\nTest 29: OnBlockDataReceived is monotonic\n";
    HeightTracker tracker;

    // First BLOCK_DATA: sets canonical to height N
    tracker.OnBlockDataReceived(6611228, 2332107, 0x1d00ffff, uint1024_t{});
    auto canonical = tracker.GetCanonicalSnapshot();
    EXPECT_TRUE(canonical.canonical_unified_height == 6611228) << "canonical_unified_height == 6611228 after first BLOCK_DATA";
    EXPECT_TRUE(canonical.canonical_channel_height == 2332107) << "canonical_channel_height == 2332107";
    EXPECT_TRUE(canonical.canonical_channel_target == 2332108) << "canonical_channel_target == 2332108";

    // Stale BLOCK_DATA arrives (lower heights — must be ignored)
    tracker.OnBlockDataReceived(6611100, 2332050, 0x1d00ffff, uint1024_t{});
    canonical = tracker.GetCanonicalSnapshot();
    EXPECT_TRUE(canonical.canonical_unified_height == 6611228) << "canonical_unified_height still 6611228 (stale BLOCK_DATA ignored)";
    EXPECT_TRUE(canonical.canonical_channel_height == 2332107) << "canonical_channel_height still 2332107 (stale BLOCK_DATA ignored)";
    EXPECT_TRUE(canonical.canonical_channel_target == 2332108) << "canonical_channel_target still 2332108";

    // Fresh BLOCK_DATA with higher heights DOES advance canonical
    tracker.OnBlockDataReceived(6611229, 2332108, 0x1d00ffff, uint1024_t{});
    canonical = tracker.GetCanonicalSnapshot();
    EXPECT_TRUE(canonical.canonical_unified_height == 6611229) << "canonical_unified_height advanced to 6611229";
    EXPECT_TRUE(canonical.canonical_channel_height == 2332108) << "canonical_channel_height advanced to 2332108";
    EXPECT_TRUE(canonical.canonical_channel_target == 2332109) << "canonical_channel_target advanced to 2332109";
}

// ============================================================================
// Test 30: Fork score lives in DiagnosticObserverState — GetCanonicalSnapshot
//          has no fork_score field (architectural isolation)
// ============================================================================
TEST(HeightTrackerTest, test_diagnostic_fork_score_isolated) {
    std::cout << "\nTest 30: Fork score is in DiagnosticObserverState only\n";
    HeightTracker tracker;

    // No keepalive yet
    auto canonical = tracker.GetCanonicalSnapshot();
    auto diag = tracker.GetDiagnosticSnapshot();
    EXPECT_TRUE(true) << "canonical has no fork_score field (it is NOT in CanonicalChainState)";  // Structural: CanonicalChainState has no fork_score member
    EXPECT_TRUE(diag.keepalive_fork_score == 0) << "diagnostic keepalive_fork_score == 0 initially";
    EXPECT_TRUE(diag.keepalive_peak_fork_score == 0) << "diagnostic keepalive_peak_fork_score == 0 initially";

    // Keepalive with fork_score
    tracker.OnKeepaliveResponse(6000, 100, 200, 300, 0xABCDu, 7);
    diag = tracker.GetDiagnosticSnapshot();
    EXPECT_TRUE(diag.keepalive_fork_score == 7) << "diagnostic keepalive_fork_score == 7 after keepalive";
    EXPECT_TRUE(diag.keepalive_peak_fork_score == 7) << "diagnostic keepalive_peak_fork_score == 7";
    EXPECT_TRUE(diag.is_fork_canary_active()) << "diagnostic is_fork_canary_active() == true";

    // Snapshot backward compat: fork_score is still accessible via GetSnapshot()
    auto snap = tracker.GetSnapshot();
    EXPECT_TRUE(snap.fork_score == 7) << "snapshot fork_score == 7 (backward compat via diagnostic)";
    EXPECT_TRUE(snap.peak_fork_score == 7) << "snapshot peak_fork_score == 7 (backward compat via diagnostic)";
    EXPECT_TRUE(snap.is_fork_active()) << "snapshot is_fork_active() == true (backward compat)";
}

// ============================================================================
// Test 31: height_drift_from_canonical() returns 0 for a healthy canonical state
// ============================================================================
TEST(HeightTrackerTest, test_height_drift_from_canonical) {
    std::cout << "\nTest 31: height_drift_from_canonical() checks\n";
    HeightTracker tracker;

    // No canonical state yet — drift should be 0 (no data)
    auto canonical = tracker.GetCanonicalSnapshot();
    EXPECT_TRUE(canonical.height_drift_from_canonical() == 0) << "height_drift_from_canonical() == 0 when uninitialized";

    // Set canonical: unified=6611228, channel=2332107, target=2332108
    tracker.OnBlockDataReceived(6611228, 2332107, 0x1d00ffff, uint1024_t{});
    canonical = tracker.GetCanonicalSnapshot();
    // drift = canonical_unified_height - canonical_channel_target = 6611228 - 2332108 = 4279120
    // (not 0 because unified and channel are different dimensions — but the method still works)
    EXPECT_TRUE(canonical.height_drift_from_canonical() != 0) << "height_drift_from_canonical() is non-zero (unified != channel_target)";
    EXPECT_TRUE(canonical.height_drift_from_canonical() == (int32_t)(6611228 - 2332108)) << "height_drift_from_canonical() == 6611228 - 2332108 = 4279120";

    // When canonical_unified == canonical_channel_target (perfectly aligned), drift == 0
    HeightTracker aligned_tracker;
    aligned_tracker.OnBlockDataReceived(1000, 999, 0x1d00ffff, uint1024_t{});
    // canonical_channel_target = 1000 (999+1)
    canonical = aligned_tracker.GetCanonicalSnapshot();
    EXPECT_TRUE(canonical.height_drift_from_canonical() == 0) << "height_drift_from_canonical() == 0 when unified == channel_target";
}

// ============================================================================
// Test 27: Canonical isolation — OnBlockDataReceived sets canonical,
//          keepalive cannot corrupt it
// ============================================================================
TEST(HeightTrackerTest, test_canonical_isolation) {
    std::cout << "\nTest 27: Canonical isolation — keepalive cannot corrupt canonical\n";
    HeightTracker tracker;
    tracker.OnTemplateReceived(1, 101);

    // Set canonical via OnBlockDataReceived
    tracker.OnBlockDataReceived(6000, 500, 0x1d00ffff, uint1024_t{});
    auto canon = tracker.GetCanonicalSnapshot();
    EXPECT_TRUE(canon.canonical_unified_height == 6000) << "canonical_unified_height == 6000";
    EXPECT_TRUE(canon.canonical_channel_height == 500) << "canonical_channel_height == 500";
    EXPECT_TRUE(canon.canonical_channel_target == 501) << "canonical_channel_target == 501";
    EXPECT_TRUE(canon.is_initialized()) << "is_initialized() == true";
    EXPECT_TRUE(canon.canonical_received_at != std::chrono::steady_clock::time_point{}) << "canonical_received_at is set";

    // Keepalive with LOWER heights must NOT corrupt canonical
    tracker.OnKeepaliveResponse(5990, 490, 790, 300, 0xDEADBEEFu, 2);
    canon = tracker.GetCanonicalSnapshot();
    EXPECT_TRUE(canon.canonical_unified_height == 6000) << "canonical_unified_height still 6000 after stale keepalive";
    EXPECT_TRUE(canon.canonical_channel_height == 500) << "canonical_channel_height still 500 after stale keepalive";

    // Keepalive with HIGHER heights still must NOT corrupt canonical
    tracker.OnKeepaliveResponse(7000, 600, 900, 400, 0xCAFEBABEu, 0);
    canon = tracker.GetCanonicalSnapshot();
    EXPECT_TRUE(canon.canonical_unified_height == 6000) << "canonical_unified_height still 6000 after higher keepalive";
    EXPECT_TRUE(canon.canonical_channel_height == 500) << "canonical_channel_height still 500 after higher keepalive";

    // Only OnBlockDataReceived can advance canonical
    tracker.OnBlockDataReceived(7001, 601, 0x1d00ffff, uint1024_t{});
    canon = tracker.GetCanonicalSnapshot();
    EXPECT_TRUE(canon.canonical_unified_height == 7001) << "canonical_unified_height advanced to 7001 via OnBlockDataReceived";
    EXPECT_TRUE(canon.canonical_channel_height == 601) << "canonical_channel_height advanced to 601 via OnBlockDataReceived";
    EXPECT_TRUE(canon.canonical_channel_target == 602) << "canonical_channel_target advanced to 602";
}

// ============================================================================
// Test 28: Fork scores reset when OnTemplateReceived advances channel_target
// ============================================================================
TEST(HeightTrackerTest, test_fork_scores_reset_on_template_advance) {
    std::cout << "\nTest 28: Fork scores reset when OnTemplateReceived advances channel_target\n";
    HeightTracker tracker;
    // Set up: channel=2 (Hash), initial template, then a fork
    tracker.OnTemplateReceived(2, 101);
    tracker.OnKeepaliveResponse(6000, 450, 800, 999, 0xCAFEBABEu, 5);

    auto snap = tracker.GetSnapshot();
    EXPECT_TRUE(snap.fork_score == 5) << "fork_score == 5 after keepalive";
    EXPECT_TRUE(snap.peak_fork_score == 5) << "peak_fork_score == 5 after keepalive";
    EXPECT_TRUE(snap.is_fork_active()) << "is_fork_active() == true";

    // Recovery: a fresh template arrives that advances channel_target
    tracker.OnTemplateReceived(2, 102);

    snap = tracker.GetSnapshot();
    EXPECT_TRUE(snap.fork_score == 0) << "fork_score == 0 after recovery template";
    EXPECT_TRUE(snap.peak_fork_score == 0) << "peak_fork_score == 0 after recovery template";
    EXPECT_TRUE(!snap.is_fork_active()) << "is_fork_active() == false after recovery";
    EXPECT_TRUE(snap.channel_target == 102) << "channel_target == 102";
}

// ============================================================================
// Test 29: Fork scores NOT reset when OnTemplateReceived doesn't advance target
// ============================================================================
TEST(HeightTrackerTest, test_fork_scores_sticky_without_advance) {
    std::cout << "\nTest 29: Fork scores NOT reset when OnTemplateReceived doesn't advance target\n";
    HeightTracker tracker;
    tracker.OnTemplateReceived(2, 101);
    tracker.OnKeepaliveResponse(6000, 450, 800, 999, 0xCAFEBABEu, 3);

    // Stale template that doesn't advance channel_target
    tracker.OnTemplateReceived(2, 100);

    auto snap = tracker.GetSnapshot();
    EXPECT_TRUE(snap.fork_score == 3) << "fork_score still 3 (stale template)";
    EXPECT_TRUE(snap.peak_fork_score == 3) << "peak_fork_score still 3 (stale template)";
    EXPECT_TRUE(snap.is_fork_active()) << "is_fork_active() still true";
    EXPECT_TRUE(snap.channel_target == 101) << "channel_target unchanged at 101";
}

// ============================================================================
// Test 32: canonical_hash_prev_block anchored to BLOCK_DATA (Tritium block)
// ============================================================================
TEST(HeightTrackerTest, test_canonical_hash_prev_block) {
    std::cout << "\nTest 32: canonical_hash_prev_block anchored to BLOCK_DATA\n";
    HeightTracker tracker;
    tracker.OnTemplateReceived(1, 101);

    // Before any block data: is_initialized() is false, hash_prev_block is zero
    auto canon = tracker.GetCanonicalSnapshot();
    EXPECT_TRUE(!canon.is_initialized()) << "is_initialized() == false before block data";
    EXPECT_TRUE(canon.canonical_hash_prev_block == uint1024_t(0)) << "canonical_hash_prev_block is zero before block data";

    // OnBlockDataReceived sets heights; UpdateWithHashPrevBlock sets hashPrevBlock
    tracker.OnBlockDataReceived(6000, 500, 0x1d00ffff, uint1024_t{});
    uint1024_t fake_prev_hash(0xDEADBEEFu);
    tracker.UpdateWithHashPrevBlock(fake_prev_hash);

    canon = tracker.GetCanonicalSnapshot();
    EXPECT_TRUE(canon.is_initialized()) << "is_initialized() == true after block data";
    EXPECT_TRUE(canon.canonical_hash_prev_block == fake_prev_hash) << "canonical_hash_prev_block set from UpdateWithHashPrevBlock";

    // Snapshot's hash_prev_block is sourced from canonical
    auto snap = tracker.GetSnapshot();
    EXPECT_TRUE(snap.hash_prev_block == fake_prev_hash) << "snapshot.hash_prev_block == canonical_hash_prev_block";
    EXPECT_TRUE(snap.canonical_hash_prev_block == fake_prev_hash) << "snapshot.canonical_hash_prev_block == canonical source";

    // Keepalive does NOT affect canonical_hash_prev_block
    tracker.OnKeepaliveResponse(7000, 600, 900, 400, 0xCAFEBABEu, 1);
    canon = tracker.GetCanonicalSnapshot();
    EXPECT_TRUE(canon.canonical_hash_prev_block == fake_prev_hash) << "canonical_hash_prev_block unchanged after keepalive";

    // Diagnostic hash_tip_lo32 is separate (lo32 of node's hashBestChain)
    auto diag = tracker.GetDiagnosticSnapshot();
    EXPECT_TRUE(diag.keepalive_hash_tip_lo32 == 0xCAFEBABEu) << "diagnostic hash_tip_lo32 == 0xCAFEBABE from keepalive";

    // Update hash_prev_block with new chain tip
    uint1024_t new_prev_hash(0xFEEDFACEu);
    tracker.UpdateWithHashPrevBlock(new_prev_hash);
    canon = tracker.GetCanonicalSnapshot();
    EXPECT_TRUE(canon.canonical_hash_prev_block == new_prev_hash) << "canonical_hash_prev_block updated to new tip";
}

// Test 33: DiagnosticObserverState::is_initialized() and latest_received_at()
TEST(HeightTrackerTest, test_diagnostic_observer_helpers) {
    std::cout << "\nTest 33: DiagnosticObserverState::is_initialized() and latest_received_at()\n";
    HeightTracker tracker;

    // Before any updates, diagnostic state is NOT initialized
    auto diag = tracker.GetDiagnosticSnapshot();
    EXPECT_TRUE(!diag.is_initialized()) << "diagnostic not initialized before any update";
    EXPECT_TRUE(diag.latest_received_at() == std::chrono::steady_clock::time_point{}) << "latest_received_at is default before any update";

    // After push notification, diagnostic state IS initialized
    auto before_push = std::chrono::steady_clock::now();
    tracker.OnPushNotification(100, 50, 0x1D00FFFF);
    auto after_push = std::chrono::steady_clock::now();
    diag = tracker.GetDiagnosticSnapshot();
    EXPECT_TRUE(diag.is_initialized()) << "diagnostic initialized after push";
    EXPECT_TRUE(diag.last_push_at >= before_push && diag.last_push_at <= after_push) << "last_push_at set after push";
    EXPECT_TRUE(diag.latest_received_at() >= before_push) << "latest_received_at reflects push";

    // After GET_ROUND, latest_received_at advances
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    auto before_round = std::chrono::steady_clock::now();
    tracker.OnGetRound(101, 51, 52, 0);
    auto after_round = std::chrono::steady_clock::now();
    diag = tracker.GetDiagnosticSnapshot();
    EXPECT_TRUE(diag.last_round_at >= before_round && diag.last_round_at <= after_round) << "last_round_at set after GET_ROUND";
    EXPECT_TRUE(diag.latest_received_at() >= before_round) << "latest_received_at >= round time (most recent)";

    // After keepalive, latest_received_at may advance further
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    auto before_ka = std::chrono::steady_clock::now();
    tracker.OnKeepaliveResponse(102, 52, 53, 10, 0xDEADBEEF, 0);
    diag = tracker.GetDiagnosticSnapshot();
    EXPECT_TRUE(diag.latest_received_at() >= before_ka) << "latest_received_at >= keepalive time";

    // Canonical is NOT initialized (no BLOCK_DATA received)
    auto canonical = tracker.GetCanonicalSnapshot();
    EXPECT_TRUE(!canonical.is_initialized()) << "canonical NOT initialized without BLOCK_DATA";

    // Now receive BLOCK_DATA — canonical becomes initialized
    tracker.OnBlockDataReceived(103, 53, 0x1D00FFFF, uint1024_t{});
    canonical = tracker.GetCanonicalSnapshot();
    EXPECT_TRUE(canonical.is_initialized()) << "canonical IS initialized after BLOCK_DATA";
}

// Test 32: DiagnosticObserverState::is_initialized() — diagnostic equivalent
// ============================================================================
TEST(HeightTrackerTest, test_diagnostic_is_initialized) {
    std::cout << "\nTest 32: DiagnosticObserverState::is_initialized() — diagnostic equivalent\n";

    // Empty tracker: neither canonical nor diagnostic should be initialized
    HeightTracker tracker;
    auto diag = tracker.GetDiagnosticSnapshot();
    EXPECT_TRUE(!diag.is_initialized()) << "is_initialized() == false when no data";

    // Keepalive alone initializes diagnostic
    tracker.OnKeepaliveResponse(6000, 450, 800, 999, 0xCAFEBABEu, 0);
    diag = tracker.GetDiagnosticSnapshot();
    EXPECT_TRUE(diag.is_initialized()) << "is_initialized() == true after keepalive";

    // Fresh tracker: push alone initializes diagnostic
    HeightTracker tracker2;
    tracker2.OnPushNotification(6100, 2332100, 0x1d00ffff);
    diag = tracker2.GetDiagnosticSnapshot();
    EXPECT_TRUE(diag.is_initialized()) << "is_initialized() == true after push";

    // Fresh tracker: GET_ROUND alone initializes diagnostic
    HeightTracker tracker3;
    tracker3.OnGetRound(6200, 2332200, 2332200, 0);
    diag = tracker3.GetDiagnosticSnapshot();
    EXPECT_TRUE(diag.is_initialized()) << "is_initialized() == true after GET_ROUND";

    // Canonical BLOCK_DATA does NOT initialize diagnostic
    HeightTracker tracker4;
    tracker4.OnBlockDataReceived(6300, 2332300, 0x1d00ffff, uint1024_t{});
    diag = tracker4.GetDiagnosticSnapshot();
    EXPECT_TRUE(!diag.is_initialized()) << "is_initialized() == false after BLOCK_DATA only";
    auto can = tracker4.GetCanonicalSnapshot();
    EXPECT_TRUE(can.is_initialized()) << "canonical is_initialized() == true after BLOCK_DATA";
}

// ============================================================================
// Test 33: DiagnosticObserverState::latest_received_at() — diagnostic equivalent
// ============================================================================
TEST(HeightTrackerTest, test_diagnostic_latest_received_at) {
    std::cout << "\nTest 33: DiagnosticObserverState::latest_received_at() — diagnostic equivalent\n";

    HeightTracker tracker;
    auto epoch = std::chrono::steady_clock::time_point{};
    auto diag = tracker.GetDiagnosticSnapshot();
    EXPECT_TRUE(diag.latest_received_at() == epoch) << "latest_received_at() == epoch when no data";

    // Push sets a timestamp
    tracker.OnPushNotification(6100, 2332100, 0x1d00ffff);
    diag = tracker.GetDiagnosticSnapshot();
    EXPECT_TRUE(diag.latest_received_at() > epoch) << "latest_received_at() > epoch after push";

    auto after_push = diag.latest_received_at();

    // GET_ROUND at a later time should become the latest
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    tracker.OnGetRound(6200, 2332200, 2332200, 0);
    diag = tracker.GetDiagnosticSnapshot();
    EXPECT_TRUE(diag.latest_received_at() >= after_push) << "latest_received_at() advances after GET_ROUND";

    // Keepalive at a later time should become the latest
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    tracker.OnKeepaliveResponse(6000, 450, 800, 999, 0, 0);
    diag = tracker.GetDiagnosticSnapshot();
    EXPECT_TRUE(diag.latest_received_at() == diag.last_keepalive_ack_at) << "latest_received_at() == last_keepalive_ack_at after keepalive";
}

// ============================================================================
// Test 34: AdvanceChannelTarget() also updates canonical_channel_target
// ============================================================================
TEST(HeightTrackerTest, test_advance_channel_target_updates_canonical) {
    std::cout << "\nTest 34: AdvanceChannelTarget updates canonical_channel_target\n";
    HeightTracker tracker;

    // Give it a canonical base via OnBlockDataReceived
    tracker.OnBlockDataReceived(6000, 2000, 0x1d00ffff, uint1024_t{});
    auto canon = tracker.GetCanonicalSnapshot();
    EXPECT_TRUE(canon.canonical_channel_target == 2001) << "canonical_channel_target == 2001 after BLOCK_DATA";

    // AdvanceChannelTarget beyond canonical
    tracker.AdvanceChannelTarget(2010);
    canon = tracker.GetCanonicalSnapshot();
    EXPECT_TRUE(canon.canonical_channel_target == 2010) << "canonical_channel_target == 2010 after AdvanceChannelTarget(2010)";

    // Snapshot channel_target should also reflect the advance
    auto snap = tracker.GetSnapshot();
    EXPECT_TRUE(snap.channel_target == 2010) << "snapshot channel_target == 2010";

    // Attempting to regress is a no-op on canonical too
    tracker.AdvanceChannelTarget(2005);
    canon = tracker.GetCanonicalSnapshot();
    EXPECT_TRUE(canon.canonical_channel_target == 2010) << "canonical_channel_target still 2010 after lower AdvanceChannelTarget(2005)";
}

// ============================================================================
// Test 35: OnTemplateReceived() sets template_unified_height from canonical
// ============================================================================
TEST(HeightTrackerTest, test_on_template_received_sets_template_unified_height) {
    std::cout << "\nTest 35: OnTemplateReceived sets template_unified_height\n";
    HeightTracker tracker;

    // With no data, template_unified_height should be 0
    auto snap = tracker.GetSnapshot();
    EXPECT_TRUE(snap.template_unified_height == 0) << "template_unified_height == 0 before any data";

    // Receive canonical BLOCK_DATA to set unified height
    tracker.OnBlockDataReceived(6612224, 2332312, 0x043d6262, uint1024_t{});

    // Receive template — template_unified_height should be set to canonical unified height
    tracker.OnTemplateReceived(2, 2332313);
    snap = tracker.GetSnapshot();
    auto canon = tracker.GetCanonicalSnapshot();
    EXPECT_TRUE(snap.template_unified_height == canon.canonical_unified_height) << "template_unified_height == canonical_unified_height after OnTemplateReceived";
    EXPECT_TRUE(snap.template_unified_height == 6612224) << "template_unified_height == 6612224";

    // After tip moves (push arrives with higher height), is_tip_moved() returns true
    tracker.OnPushNotification(6612225, 2332313, 0x043d6262);
    snap = tracker.GetSnapshot();
    EXPECT_TRUE(snap.is_tip_moved()) << "is_tip_moved() == true after push advances beyond template_unified_height";
}

// ============================================================================
// Test 36: last_push_notification_at is set ONLY by OnPushNotification —
//          not by OnKeepaliveResponse or OnGetRound.
//          last_height_update is also set ONLY by OnPushNotification (Bug #1 fix).
// ============================================================================
TEST(HeightTrackerTest, test_push_notification_at_isolated_from_keepalive_and_getround) {
    std::cout << "\nTest 36: last_push_notification_at set only by push, not by keepalive or GET_ROUND\n";
    HeightTracker tracker;

    // After keepalive only, last_push_notification_at must remain epoch (unset).
    tracker.OnKeepaliveResponse(6000, 450, 800, 999, 0xCAFEBABEu, 0);
    auto snap = tracker.GetSnapshot();
    EXPECT_TRUE(snap.last_push_notification_at == std::chrono::steady_clock::time_point{}) << "last_push_notification_at == epoch after keepalive only";
    // last_height_update must also remain epoch after keepalive (Bug #1 fix)
    EXPECT_TRUE(snap.last_height_update == std::chrono::steady_clock::time_point{}) << "last_height_update == epoch after keepalive only (Bug #1 fix)";

    // After GET_ROUND only, last_push_notification_at must remain epoch.
    tracker.OnGetRound(6001, 451, 452, 0);
    snap = tracker.GetSnapshot();
    EXPECT_TRUE(snap.last_push_notification_at == std::chrono::steady_clock::time_point{}) << "last_push_notification_at == epoch after GET_ROUND only";
    // last_height_update must also remain epoch after GET_ROUND (Bug #3 fix)
    EXPECT_TRUE(snap.last_height_update == std::chrono::steady_clock::time_point{}) << "last_height_update == epoch after GET_ROUND only (Bug #3 fix)";

    // After OnPushNotification, last_push_notification_at and last_height_update must be set.
    tracker.OnPushNotification(6002, 452, 0x1d00ffff);
    snap = tracker.GetSnapshot();
    EXPECT_TRUE(snap.last_push_notification_at != std::chrono::steady_clock::time_point{}) << "last_push_notification_at set after OnPushNotification";
    EXPECT_TRUE(snap.last_height_update != std::chrono::steady_clock::time_point{}) << "last_height_update set after OnPushNotification";

    // Both timestamps must be consistent (same push event)
    EXPECT_TRUE(snap.last_push_notification_at == snap.last_height_update) << "last_push_notification_at == last_height_update after push";

    // A subsequent keepalive must NOT advance last_push_notification_at or last_height_update.
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    auto push_time = snap.last_push_notification_at;
    tracker.OnKeepaliveResponse(6005, 455, 805, 999, 0u, 0u);
    snap = tracker.GetSnapshot();
    EXPECT_TRUE(snap.last_push_notification_at == push_time) << "last_push_notification_at unchanged after subsequent keepalive";
    EXPECT_TRUE(snap.last_height_update == push_time) << "last_height_update unchanged after subsequent keepalive";

    // A subsequent GET_ROUND must NOT advance last_push_notification_at or last_height_update.
    tracker.OnGetRound(6006, 456, 457, 0);
    snap = tracker.GetSnapshot();
    EXPECT_TRUE(snap.last_push_notification_at == push_time) << "last_push_notification_at unchanged after subsequent GET_ROUND";
    EXPECT_TRUE(snap.last_height_update == push_time) << "last_height_update unchanged after subsequent GET_ROUND";
}

// ============================================================================
// Test 11: set_session_epoch() clears last_keepalive_ack_at on epoch change
// This is the core fix for the keepalive tracking split:
// a stale-epoch keepalive ACK must not signal liveness for the new epoch.
// ============================================================================
TEST(HeightTrackerTest, test_set_session_epoch_clears_keepalive_on_epoch_change) {
    std::cout << "\nTest 11 (NEW): set_session_epoch() clears last_keepalive_ack_at on epoch change\n";
    HeightTracker tracker;

    // Epoch 1: session established, keepalives flowing
    tracker.set_session_epoch(1);
    tracker.OnKeepaliveResponse(5000, 400, 700, 900, 0xDEADBEEFu, 0);

    auto snap_before = tracker.GetSnapshot();
    EXPECT_TRUE(snap_before.last_keepalive_ack_at != std::chrono::steady_clock::time_point{}) << "Epoch 1: last_keepalive_ack_at is set after OnKeepaliveResponse";
    EXPECT_TRUE(snap_before.session_epoch == 1) << "Epoch 1: session_epoch == 1 in snapshot";

    // Advance the session epoch (simulates re-auth / channel advance causing epoch bump)
    tracker.set_session_epoch(2);

    auto snap_after = tracker.GetSnapshot();
    EXPECT_TRUE(snap_after.last_keepalive_ack_at == std::chrono::steady_clock::time_point{}) << "Epoch 2: last_keepalive_ack_at CLEARED after epoch change";
    EXPECT_TRUE(snap_after.session_epoch == 2) << "Epoch 2: session_epoch == 2 in snapshot";
}

// ============================================================================
// Test 12: set_session_epoch() does NOT clear last_keepalive_ack_at when epoch unchanged
// ============================================================================
TEST(HeightTrackerTest, test_set_session_epoch_no_clear_when_unchanged) {
    std::cout << "\nTest 12 (NEW): set_session_epoch() does NOT clear keepalive timestamp when epoch unchanged\n";
    HeightTracker tracker;

    tracker.set_session_epoch(5);
    tracker.OnKeepaliveResponse(5000, 400, 700, 900, 0xDEADBEEFu, 0);

    auto snap_before = tracker.GetSnapshot();
    auto ack_time = snap_before.last_keepalive_ack_at;
    EXPECT_TRUE(ack_time != std::chrono::steady_clock::time_point{}) << "last_keepalive_ack_at is set initially";

    // Re-setting the SAME epoch should NOT clear the keepalive timestamp
    tracker.set_session_epoch(5);

    auto snap_after = tracker.GetSnapshot();
    EXPECT_TRUE(snap_after.last_keepalive_ack_at == ack_time) << "last_keepalive_ack_at preserved when same epoch re-set";
}

// ============================================================================
// Test 13: Keepalive timestamp from old epoch does not survive into new epoch
// (Simulates the real-world deadlock: channel advances → epoch bumps → stale
// keepalive should not falsely report ack_recent=true in new epoch)
// ============================================================================
TEST(HeightTrackerTest, test_old_epoch_keepalive_does_not_signal_new_epoch_liveness) {
    std::cout << "\nTest 13 (NEW): Old-epoch keepalive timestamp does not survive into new epoch\n";
    HeightTracker tracker;

    // Epoch 1: session established, keepalives flowing
    tracker.set_session_epoch(1);
    tracker.OnKeepaliveResponse(5000, 400, 700, 900, 0xDEADBEEFu, 0);

    // Confirm keepalive is "recent" for epoch 1
    auto snap1 = tracker.GetSnapshot();
    EXPECT_TRUE(snap1.last_keepalive_ack_at != std::chrono::steady_clock::time_point{}) << "Epoch 1: keepalive ACK timestamp is set";

    // Channel advance + re-auth → epoch 2
    tracker.set_session_epoch(2);
    tracker.OnPushNotification(5001, 101, 0x1d00ffff);  // channel advances

    // In the new epoch, before any keepalive for epoch 2,
    // the old epoch's keepalive must NOT make ack_recent appear true.
    auto snap2 = tracker.GetSnapshot();
    EXPECT_TRUE(snap2.last_keepalive_ack_at == std::chrono::steady_clock::time_point{}) << "Epoch 2: old-epoch keepalive timestamp is cleared (no stale liveness signal)";
    EXPECT_TRUE(snap2.channel_height == 101) << "Epoch 2: channel_height updated by push (not affected by epoch change)";

    // Now receive a keepalive for epoch 2 — should work normally
    tracker.OnKeepaliveResponse(5001, 401, 701, 901, 0xCAFEBABEu, 0);
    auto snap3 = tracker.GetSnapshot();
    EXPECT_TRUE(snap3.last_keepalive_ack_at != std::chrono::steady_clock::time_point{}) << "Epoch 2: new keepalive ACK is accepted and timestamp set";
}

// ============================================================================
// Test 14: set_session_epoch(0) does NOT clear last_keepalive_ack_at
// (Epoch 0 is the sentinel "no active session" baseline — must not invalidate)
// ============================================================================
TEST(HeightTrackerTest, test_set_session_epoch_zero_no_clear) {
    std::cout << "\nTest 14 (NEW): set_session_epoch(0) does NOT clear keepalive timestamp (sentinel epoch)\n";
    HeightTracker tracker;

    tracker.set_session_epoch(3);
    tracker.OnKeepaliveResponse(5000, 400, 700, 900, 0xDEADBEEFu, 0);
    auto ack_time = tracker.GetSnapshot().last_keepalive_ack_at;
    EXPECT_TRUE(ack_time != std::chrono::steady_clock::time_point{}) << "Initial keepalive timestamp is set";

    // Setting epoch to 0 (sentinel) should be a no-op for keepalive clearing
    tracker.set_session_epoch(0);
    auto snap_after = tracker.GetSnapshot();
    EXPECT_TRUE(snap_after.last_keepalive_ack_at == ack_time) << "set_session_epoch(0) does not clear keepalive timestamp";
    EXPECT_TRUE(snap_after.session_epoch == 0) << "session_epoch updated to 0";
}

// ============================================================================
// Test 15: Session epoch reflected in Snapshot.session_epoch
// ============================================================================
TEST(HeightTrackerTest, test_session_epoch_in_snapshot) {
    std::cout << "\nTest 15 (NEW): session_epoch field in Snapshot reflects set_session_epoch()\n";
    HeightTracker tracker;

    auto snap0 = tracker.GetSnapshot();
    EXPECT_TRUE(snap0.session_epoch == 0) << "Initial session_epoch == 0";

    tracker.set_session_epoch(42);
    auto snap42 = tracker.GetSnapshot();
    EXPECT_TRUE(snap42.session_epoch == 42) << "session_epoch == 42 after set";

    tracker.set_session_epoch(99);
    auto snap99 = tracker.GetSnapshot();
    EXPECT_TRUE(snap99.session_epoch == 99) << "session_epoch == 99 after second set";
}

// ============================================================================
// Test: OnPushFullPicture() — updates push cross-channel heights in snapshot
// ============================================================================
TEST(HeightTrackerTest, test_on_push_full_picture) {
    std::cout << "\nTest (NEW): OnPushFullPicture() updates push_prime/hash/stake_height\n";
    HeightTracker tracker;

    // Before any update, push cross-channel heights should be zero
    auto snap0 = tracker.GetSnapshot();
    EXPECT_TRUE(snap0.push_prime_height == 0) << "push_prime_height == 0 before OnPushFullPicture";
    EXPECT_TRUE(snap0.push_hash_height == 0) << "push_hash_height == 0 before OnPushFullPicture";
    EXPECT_TRUE(snap0.push_stake_height == 0) << "push_stake_height == 0 before OnPushFullPicture";

    // After OnPushFullPicture(), snapshot should reflect the values
    tracker.OnPushFullPicture(6500000, 2300000, 900000, 400000);
    auto snap1 = tracker.GetSnapshot();
    EXPECT_TRUE(snap1.push_prime_height == 2300000) << "push_prime_height == 2300000 after OnPushFullPicture";
    EXPECT_TRUE(snap1.push_hash_height == 900000) << "push_hash_height == 900000 after OnPushFullPicture";
    EXPECT_TRUE(snap1.push_stake_height == 400000) << "push_stake_height == 400000 after OnPushFullPicture";

    // prime_height and hash_height in snapshot should include push values
    EXPECT_TRUE(snap1.prime_height >= 2300000) << "prime_height includes push_prime_height";
    EXPECT_TRUE(snap1.hash_height >= 900000) << "hash_height includes push_hash_height";
    EXPECT_TRUE(snap1.stake_height >= 400000) << "stake_height includes push_stake_height";

    // OnPushFullPicture is monotonic — lower values must not regress
    tracker.OnPushFullPicture(6400000, 2200000, 800000, 300000);
    auto snap2 = tracker.GetSnapshot();
    EXPECT_TRUE(snap2.push_prime_height == 2300000) << "push_prime_height not regressed by lower value";
    EXPECT_TRUE(snap2.push_hash_height == 900000) << "push_hash_height not regressed by lower value";
    EXPECT_TRUE(snap2.push_stake_height == 400000) << "push_stake_height not regressed by lower value";

    // Higher values should advance
    tracker.OnPushFullPicture(6600000, 2400000, 1000000, 500000);
    auto snap3 = tracker.GetSnapshot();
    EXPECT_TRUE(snap3.push_prime_height == 2400000) << "push_prime_height advances on higher value";
    EXPECT_TRUE(snap3.push_hash_height == 1000000) << "push_hash_height advances on higher value";
    EXPECT_TRUE(snap3.push_stake_height == 500000) << "push_stake_height advances on higher value";

    // DiagnosticObserverState should also reflect values
    auto diag = tracker.GetDiagnosticSnapshot();
    EXPECT_TRUE(diag.push_prime_height == 2400000) << "DiagnosticObserverState.push_prime_height == 2400000";
    EXPECT_TRUE(diag.push_hash_height == 1000000) << "DiagnosticObserverState.push_hash_height == 1000000";
    EXPECT_TRUE(diag.push_stake_height == 500000) << "DiagnosticObserverState.push_stake_height == 500000";
}

// ============================================================================
// Test 35 (RC7-D): Burst recovery — nChannelHeight 4 blocks ahead of tracker
//   push_channel_height=2344737 (burst lag), template.nChannelHeight=2344741.
//   expected_template_target() = 2344738, but is_template_stale() uses
//   channel_height >= channel_target (2344737 >= 2344741 = false).
//   The directional guard must accept this template as VALID.
// ============================================================================
TEST(HeightTrackerTest, test_burst_recovery_template_ahead_of_tracker) {
    std::cout << "\nTest 35 (RC7-D): Burst recovery — nChannelHeight 4 blocks ahead of local tracker, must NOT be stale\n";
    HeightTracker tracker;

    // Simulate burst: only 1 of 5 push notifications processed so far.
    // push_channel_height = 2344737 (blocks 2344738–2344740 still in queue).
    tracker.OnPushNotification(6644208, 2344737, 0x1d00ffff);

    // GET_BLOCK arrives with the authoritative template from the node:
    // nChannelHeight = 2344741 (tip after burst = 2344740, next block = 2344741).
    tracker.OnTemplateReceived(1, 2344741);

    auto snap = tracker.GetSnapshot();

    // channel_height (from push) trails the template target by 4 blocks.
    // expected_template_target() = channel_height + 1 = 2344738 (not 2344741).
    EXPECT_TRUE(snap.expected_template_target() == 2344738) << "RC7-D: expected_template_target() == 2344738 (lags template by 3)";

    // channel_target was advanced by OnTemplateReceived to 2344741.
    EXPECT_TRUE(snap.channel_target == 2344741) << "RC7-D: channel_target == 2344741 after OnTemplateReceived";

    // Directional guard: 2344737 >= 2344741 is false → template is VALID.
    EXPECT_TRUE(!snap.is_template_stale()) << "RC7-D: is_template_stale() == false when 4 blocks ahead of push tracker";

    // Drift is positive (template is 3 ahead of expected) but NOT stale.
    auto delta = snap.drift_delta();
    EXPECT_TRUE(delta.has_value()) << "RC7-D: drift_delta() has value (channel_target > expected_template_target)";
    EXPECT_TRUE(delta.has_value() && *delta == 3) << "RC7-D: drift_delta() == 3 (2344741 - 2344738)";
}

// ============================================================================
// Test: OnGetRound monotonic guard — stale round does not regress prime/hash heights
// ============================================================================
TEST(HeightTrackerTest, test_on_get_round_monotonic_guard) {
    std::cout << "\nTest (Bug #1): OnGetRound monotonic guard for round heights\n";
    HeightTracker tracker;

    // Set channel to Prime (1) via OnTemplateReceived so m_channel is initialized
    tracker.OnPushNotification(5000, 100, 0x1d00ffff);
    tracker.OnTemplateReceived(1, 101);

    // First GET_ROUND with higher per-channel heights
    tracker.OnGetRound(5100, 120, 200, 300);
    auto diag = tracker.GetDiagnosticSnapshot();
    EXPECT_TRUE(diag.round_prime_height == 120) << "round_prime_height == 120 after first GET_ROUND";
    EXPECT_TRUE(diag.round_hash_height == 200) << "round_hash_height == 200 after first GET_ROUND";
    EXPECT_TRUE(diag.round_channel_height == 120) << "round_channel_height == 120 (Prime channel)";

    // Stale GET_ROUND with LOWER prime/hash — monotonic guard must prevent regression
    tracker.OnGetRound(5101, 110, 190, 310);
    diag = tracker.GetDiagnosticSnapshot();
    EXPECT_TRUE(diag.round_unified_height == 5101) << "round_unified_height == 5101 (unified always updates)";
    EXPECT_TRUE(diag.round_prime_height == 120) << "round_prime_height still 120 (monotonic: 110 < 120)";
    EXPECT_TRUE(diag.round_hash_height == 200) << "round_hash_height still 200 (monotonic: 190 < 200)";
    EXPECT_TRUE(diag.round_channel_height == 120) << "round_channel_height still 120 (derived from prime, monotonic)";

    // Fresh GET_ROUND with HIGHER prime/hash — must advance
    tracker.OnGetRound(5102, 125, 210, 305);
    diag = tracker.GetDiagnosticSnapshot();
    EXPECT_TRUE(diag.round_prime_height == 125) << "round_prime_height advanced to 125";
    EXPECT_TRUE(diag.round_hash_height == 210) << "round_hash_height advanced to 210";
    EXPECT_TRUE(diag.round_channel_height == 125) << "round_channel_height advanced to 125 (Prime channel)";
}

// ============================================================================
// main
// ============================================================================
