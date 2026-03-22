/**
 * @file channel_height_shadow_tracker_test.cpp
 * @brief Unit tests for ChannelHeightShadowTracker
 *
 * Tests:
 *  1.  UpdateCanonical — monotonic: never regresses unified or channel height
 *  2.  UpdateCanonical — is_initialized() starts false, becomes true after first update
 *  3.  IngestKeepaliveAck — all four heights stored; does not touch canonical
 *  4.  IngestSessionStatusAck — health fields stored; no heights in tracker
 *  5.  IngestPush — unified + channel height stored; does not touch canonical
 *  6.  GetFullHeightEstimate — prime from keepalive when available
 *  7.  GetFullHeightEstimate — prime falls back to canonical when mining Prime and no keepalive
 *  8.  GetFullHeightEstimate — hash from keepalive when available
 *  9.  GetFullHeightEstimate — hash falls back to canonical when mining Hash and no keepalive
 * 10.  GetFullHeightEstimate — stake from keepalive only (no other source)
 * 11.  GetFullHeightEstimate — unified = max(canonical, keepalive, push)
 * 12.  GetFullHeightEstimate — source tags correct for each channel
 * 13.  IsKeepaliveStale — false immediately after IngestKeepaliveAck
 * 14.  OnSessionEpochChanged — clears keepalive, push, status but NOT canonical
 * 15.  DiagnosticSummary — non-empty string produced
 * 16.  FullHeightEstimate::freshness_summary — non-empty, contains all channels
 * 17.  Canonical accumulates across multiple updates (always advances to max)
 * 18.  Keepalive observation overwritten on each call (not max)
 * 19.  GetFullHeightEstimate — is_shadow_stale reported correctly
 * 20.  GetLastKeepaliveObservation / GetLastSessionStatusObservation / GetLastPushObservation
 */

#include "protocol/channel_height_shadow_tracker.hpp"

#include <iostream>
#include <cassert>
#include <thread>
#include <chrono>

using namespace nexusminer::protocol;

// ─────────────────────────────────────────────────────────────────────────────
// Test harness
// ─────────────────────────────────────────────────────────────────────────────

static int tests_run    = 0;
static int tests_passed = 0;
static int tests_failed = 0;

static void print_test_result(const char* name, bool passed)
{
    ++tests_run;
    if (passed) {
        ++tests_passed;
        std::cout << "  [PASS] " << name << "\n";
    } else {
        ++tests_failed;
        std::cout << "  [FAIL] " << name << "\n";
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 1: UpdateCanonical — monotonic (never regresses)
// ─────────────────────────────────────────────────────────────────────────────
static void test_canonical_monotonic()
{
    ChannelHeightShadowTracker t;
    t.UpdateCanonical(1000, 500, 1);
    t.UpdateCanonical(900, 450, 1);  // stale — should not regress

    auto c = t.GetCanonical();
    print_test_result("canonical unified_height never regresses",
                      c.unified_height == 1000);
    print_test_result("canonical channel_height never regresses",
                      c.channel_height == 500);
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 2: UpdateCanonical — is_initialized()
// ─────────────────────────────────────────────────────────────────────────────
static void test_canonical_is_initialized()
{
    ChannelHeightShadowTracker t;
    print_test_result("canonical not initialized before any update",
                      !t.GetCanonical().is_initialized());
    t.UpdateCanonical(100, 50, 2);
    print_test_result("canonical initialized after first UpdateCanonical",
                      t.GetCanonical().is_initialized());
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 3: IngestKeepaliveAck — all four heights; canonical unchanged
// ─────────────────────────────────────────────────────────────────────────────
static void test_keepalive_heights_do_not_touch_canonical()
{
    ChannelHeightShadowTracker t;
    t.UpdateCanonical(1000, 500, 1);
    t.IngestKeepaliveAck(1050, 505, 600, 200);

    auto c = t.GetCanonical();
    auto k = t.GetLastKeepaliveObservation();

    print_test_result("canonical unified not overwritten by keepalive",
                      c.unified_height == 1000);
    print_test_result("keepalive unified_height stored",    k.unified_height == 1050);
    print_test_result("keepalive prime_height stored",      k.prime_height   == 505);
    print_test_result("keepalive hash_height stored",       k.hash_height    == 600);
    print_test_result("keepalive stake_height stored",      k.stake_height   == 200);
    print_test_result("keepalive is_initialized after ingest", k.is_initialized());
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 4: IngestSessionStatusAck — health stored; no heights
// ─────────────────────────────────────────────────────────────────────────────
static void test_session_status_no_heights()
{
    ChannelHeightShadowTracker t;
    t.IngestSessionStatusAck(true, 3600);

    auto s = t.GetLastSessionStatusObservation();
    print_test_result("session status is_authenticated stored",  s.is_authenticated);
    print_test_result("session status uptime_seconds stored",    s.uptime_seconds == 3600);
    print_test_result("session status is_initialized after ingest", s.is_initialized());

    // No heights in tracker after session status only
    auto c = t.GetCanonical();
    print_test_result("canonical not modified by session status ack",
                      !c.is_initialized());
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 5: IngestPush — unified + channel height stored; canonical unchanged
// ─────────────────────────────────────────────────────────────────────────────
static void test_push_does_not_touch_canonical()
{
    ChannelHeightShadowTracker t;
    t.UpdateCanonical(1000, 500, 1);
    t.IngestPush(1010, 505, 1);

    auto c = t.GetCanonical();
    auto p = t.GetLastPushObservation();

    print_test_result("canonical unified not overwritten by push", c.unified_height == 1000);
    print_test_result("push unified_height stored",  p.unified_height == 1010);
    print_test_result("push channel_height stored",  p.channel_height == 505);
    print_test_result("push channel stored",         p.channel == 1);
    print_test_result("push is_initialized after ingest", p.is_initialized());
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 6: GetFullHeightEstimate — prime from keepalive when available
// ─────────────────────────────────────────────────────────────────────────────
static void test_prime_height_from_keepalive()
{
    ChannelHeightShadowTracker t;
    t.UpdateCanonical(1000, 500, 1);   // mining Prime
    t.IngestKeepaliveAck(1050, 505, 600, 200);

    auto est = t.GetFullHeightEstimate();
    print_test_result("prime_height = keepalive prime_height",
                      est.prime_height == 505);
    print_test_result("prime_source = KEEPALIVE_ACK",
                      est.prime_source == ChannelHeightShadowTracker::HeightSource::KEEPALIVE_ACK);
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 7: GetFullHeightEstimate — prime falls back to canonical when no keepalive
// ─────────────────────────────────────────────────────────────────────────────
static void test_prime_height_fallback_to_canonical()
{
    ChannelHeightShadowTracker t;
    t.UpdateCanonical(1000, 500, 1);   // mining Prime; no keepalive yet

    auto est = t.GetFullHeightEstimate();
    print_test_result("prime_height = canonical channel_height when no keepalive",
                      est.prime_height == 500);
    print_test_result("prime_source = BLOCK_DATA when no keepalive",
                      est.prime_source == ChannelHeightShadowTracker::HeightSource::BLOCK_DATA);
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 8: GetFullHeightEstimate — hash from keepalive when available
// ─────────────────────────────────────────────────────────────────────────────
static void test_hash_height_from_keepalive()
{
    ChannelHeightShadowTracker t;
    t.UpdateCanonical(1000, 500, 2);   // mining Hash
    t.IngestKeepaliveAck(1050, 505, 600, 200);

    auto est = t.GetFullHeightEstimate();
    print_test_result("hash_height = keepalive hash_height",
                      est.hash_height == 600);
    print_test_result("hash_source = KEEPALIVE_ACK",
                      est.hash_source == ChannelHeightShadowTracker::HeightSource::KEEPALIVE_ACK);
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 9: GetFullHeightEstimate — hash falls back to canonical when mining Hash
// ─────────────────────────────────────────────────────────────────────────────
static void test_hash_height_fallback_to_canonical()
{
    ChannelHeightShadowTracker t;
    t.UpdateCanonical(1000, 500, 2);   // mining Hash; no keepalive

    auto est = t.GetFullHeightEstimate();
    print_test_result("hash_height = canonical channel_height when no keepalive",
                      est.hash_height == 500);
    print_test_result("hash_source = BLOCK_DATA when no keepalive",
                      est.hash_source == ChannelHeightShadowTracker::HeightSource::BLOCK_DATA);
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 10: GetFullHeightEstimate — stake from keepalive only
// ─────────────────────────────────────────────────────────────────────────────
static void test_stake_height_keepalive_only()
{
    ChannelHeightShadowTracker t;
    t.UpdateCanonical(1000, 500, 1);

    // Before any keepalive: stake = 0
    auto est0 = t.GetFullHeightEstimate();
    print_test_result("stake_height = 0 before keepalive",
                      est0.stake_height == 0);
    print_test_result("stake_source = NONE before keepalive",
                      est0.stake_source == ChannelHeightShadowTracker::HeightSource::NONE);

    t.IngestKeepaliveAck(1000, 500, 600, 200);
    auto est1 = t.GetFullHeightEstimate();
    print_test_result("stake_height from keepalive",
                      est1.stake_height == 200);
    print_test_result("stake_source = KEEPALIVE_ACK",
                      est1.stake_source == ChannelHeightShadowTracker::HeightSource::KEEPALIVE_ACK);
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 11: GetFullHeightEstimate — unified = max across all sources
// ─────────────────────────────────────────────────────────────────────────────
static void test_unified_height_max_across_sources()
{
    ChannelHeightShadowTracker t;
    t.UpdateCanonical(1000, 500, 1);
    t.IngestKeepaliveAck(1020, 505, 600, 200);
    t.IngestPush(1015, 505, 1);

    auto est = t.GetFullHeightEstimate();
    // keepalive is highest at 1020
    print_test_result("unified = max(canonical=1000, keepalive=1020, push=1015) => 1020",
                      est.unified_height == 1020);
    print_test_result("unified_source = KEEPALIVE_ACK when keepalive is highest",
                      est.unified_source == ChannelHeightShadowTracker::HeightSource::KEEPALIVE_ACK);
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 12: GetFullHeightEstimate — push wins for unified when push is highest
// ─────────────────────────────────────────────────────────────────────────────
static void test_unified_height_push_wins()
{
    ChannelHeightShadowTracker t;
    t.UpdateCanonical(1000, 500, 1);
    t.IngestKeepaliveAck(1010, 505, 600, 200);
    t.IngestPush(1030, 510, 1);

    auto est = t.GetFullHeightEstimate();
    print_test_result("unified = max(1000, 1010, 1030) => 1030 from push",
                      est.unified_height == 1030);
    print_test_result("unified_source = PUSH when push is highest",
                      est.unified_source == ChannelHeightShadowTracker::HeightSource::PUSH);
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 13: IsKeepaliveStale — false immediately; would be true after long time
// ─────────────────────────────────────────────────────────────────────────────
static void test_keepalive_stale_check()
{
    ChannelHeightShadowTracker t;
    // Before any keepalive: stale
    print_test_result("IsKeepaliveStale true before any keepalive (1s max)",
                      t.IsKeepaliveStale(std::chrono::seconds(1)));

    t.IngestKeepaliveAck(1000, 500, 600, 200);
    // Immediately after: not stale with generous window
    print_test_result("IsKeepaliveStale false immediately after ingest (60s max)",
                      !t.IsKeepaliveStale(std::chrono::seconds(60)));
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 14: OnSessionEpochChanged — clears shadow, preserves canonical
// ─────────────────────────────────────────────────────────────────────────────
static void test_epoch_change_clears_shadow_preserves_canonical()
{
    ChannelHeightShadowTracker t;
    t.UpdateCanonical(1000, 500, 1);
    t.IngestKeepaliveAck(1050, 505, 600, 200);
    t.IngestSessionStatusAck(true, 3600);
    t.IngestPush(1010, 505, 1);

    t.OnSessionEpochChanged();

    auto c = t.GetCanonical();
    auto k = t.GetLastKeepaliveObservation();
    auto s = t.GetLastSessionStatusObservation();
    auto p = t.GetLastPushObservation();

    print_test_result("canonical preserved after epoch change",
                      c.unified_height == 1000 && c.channel_height == 500);
    print_test_result("keepalive cleared after epoch change",
                      !k.is_initialized());
    print_test_result("session status cleared after epoch change",
                      !s.is_initialized());
    print_test_result("push cleared after epoch change",
                      !p.is_initialized());
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 15: DiagnosticSummary — non-empty
// ─────────────────────────────────────────────────────────────────────────────
static void test_diagnostic_summary_non_empty()
{
    ChannelHeightShadowTracker t;
    t.UpdateCanonical(1000, 500, 1);
    t.IngestKeepaliveAck(1050, 505, 600, 200);
    t.IngestSessionStatusAck(true, 3600);

    auto summary = t.DiagnosticSummary();
    print_test_result("DiagnosticSummary is non-empty", !summary.empty());
    print_test_result("DiagnosticSummary contains 'canonical'",
                      summary.find("canonical") != std::string::npos);
    print_test_result("DiagnosticSummary contains 'keepalive'",
                      summary.find("keepalive") != std::string::npos);
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 16: FullHeightEstimate::freshness_summary — non-empty, contains all channels
// ─────────────────────────────────────────────────────────────────────────────
static void test_freshness_summary_format()
{
    ChannelHeightShadowTracker t;
    t.UpdateCanonical(1000, 500, 1);
    t.IngestKeepaliveAck(1050, 505, 600, 200);

    auto est = t.GetFullHeightEstimate();
    auto summary = est.freshness_summary();
    print_test_result("freshness_summary is non-empty", !summary.empty());
    print_test_result("freshness_summary contains 'prime'",
                      summary.find("prime") != std::string::npos);
    print_test_result("freshness_summary contains 'hash'",
                      summary.find("hash") != std::string::npos);
    print_test_result("freshness_summary contains 'stake'",
                      summary.find("stake") != std::string::npos);
    print_test_result("freshness_summary contains 'unified'",
                      summary.find("unified") != std::string::npos);
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 17: Canonical accumulates — always uses max over multiple updates
// ─────────────────────────────────────────────────────────────────────────────
static void test_canonical_accumulates_max()
{
    ChannelHeightShadowTracker t;
    t.UpdateCanonical(500, 250, 1);
    t.UpdateCanonical(600, 300, 1);   // advances
    t.UpdateCanonical(550, 280, 1);   // stale — ignored

    auto c = t.GetCanonical();
    print_test_result("canonical unified advances to max", c.unified_height == 600);
    print_test_result("canonical channel advances to max", c.channel_height == 300);
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 18: Keepalive observation overwrites on each call (not max)
// ─────────────────────────────────────────────────────────────────────────────
static void test_keepalive_overwrites_not_max()
{
    ChannelHeightShadowTracker t;
    t.IngestKeepaliveAck(1000, 500, 600, 200);
    t.IngestKeepaliveAck(900, 450, 550, 150);  // lower values — should overwrite

    auto k = t.GetLastKeepaliveObservation();
    // Shadow tracker stores latest, not max, for keepalive — it reflects node's
    // current chain report rather than a monotonic commitment.
    print_test_result("keepalive unified_height = latest (900), not max",
                      k.unified_height == 900);
    print_test_result("keepalive prime_height = latest (450), not max",
                      k.prime_height == 450);
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 19: GetFullHeightEstimate — is_shadow_stale when no fresh sources
// ─────────────────────────────────────────────────────────────────────────────
static void test_full_height_estimate_shadow_stale_flag()
{
    ChannelHeightShadowTracker t;
    // No shadow observations at all → stale
    auto est = t.GetFullHeightEstimate();
    print_test_result("is_shadow_stale = true when no shadow observations",
                      est.is_shadow_stale);

    // After a fresh keepalive → not stale
    t.IngestKeepaliveAck(1000, 500, 600, 200);
    est = t.GetFullHeightEstimate();
    print_test_result("is_shadow_stale = false after fresh keepalive",
                      !est.is_shadow_stale);
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 20: Individual observation accessors
// ─────────────────────────────────────────────────────────────────────────────
static void test_observation_accessors()
{
    ChannelHeightShadowTracker t;

    // All uninitialized at start
    print_test_result("GetLastKeepaliveObservation not initialized at start",
                      !t.GetLastKeepaliveObservation().is_initialized());
    print_test_result("GetLastSessionStatusObservation not initialized at start",
                      !t.GetLastSessionStatusObservation().is_initialized());
    print_test_result("GetLastPushObservation not initialized at start",
                      !t.GetLastPushObservation().is_initialized());

    t.IngestKeepaliveAck(1000, 500, 600, 200);
    t.IngestSessionStatusAck(true, 1800);
    t.IngestPush(1005, 505, 2);

    print_test_result("GetLastKeepaliveObservation initialized after ingest",
                      t.GetLastKeepaliveObservation().is_initialized());
    print_test_result("GetLastSessionStatusObservation initialized after ingest",
                      t.GetLastSessionStatusObservation().is_initialized());
    print_test_result("GetLastPushObservation initialized after ingest",
                      t.GetLastPushObservation().is_initialized());

    // Check correct values
    auto k = t.GetLastKeepaliveObservation();
    auto s = t.GetLastSessionStatusObservation();
    auto p = t.GetLastPushObservation();
    print_test_result("keepalive stake_height = 200", k.stake_height == 200);
    print_test_result("session status uptime = 1800", s.uptime_seconds == 1800);
    print_test_result("push channel = 2", p.channel == 2);
}

// ─────────────────────────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────────────────────────

int main()
{
    std::cout << "\n========================================\n";
    std::cout << "ChannelHeightShadowTracker Tests\n";
    std::cout << "========================================\n";

    test_canonical_monotonic();
    test_canonical_is_initialized();
    test_keepalive_heights_do_not_touch_canonical();
    test_session_status_no_heights();
    test_push_does_not_touch_canonical();
    test_prime_height_from_keepalive();
    test_prime_height_fallback_to_canonical();
    test_hash_height_from_keepalive();
    test_hash_height_fallback_to_canonical();
    test_stake_height_keepalive_only();
    test_unified_height_max_across_sources();
    test_unified_height_push_wins();
    test_keepalive_stale_check();
    test_epoch_change_clears_shadow_preserves_canonical();
    test_diagnostic_summary_non_empty();
    test_freshness_summary_format();
    test_canonical_accumulates_max();
    test_keepalive_overwrites_not_max();
    test_full_height_estimate_shadow_stale_flag();
    test_observation_accessors();

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
