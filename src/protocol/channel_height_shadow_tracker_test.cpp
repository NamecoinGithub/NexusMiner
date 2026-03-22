/**
 * @file channel_height_shadow_tracker_test.cpp
 * @brief Unit tests for ChannelHeightShadowTracker
 *
 * Tests:
 *  1.  UpdateCanonical — monotonic: never regresses unified or channel height
 *  2.  UpdateCanonical — is_initialized() starts false, becomes true after first update
 *  3.  IngestKeepaliveAck — all four heights stored; does not touch canonical
 *  4.  IngestSessionStatusAck — health + height fields stored; does not touch canonical
 *  5.  IngestPush — unified + channel height stored; does not touch canonical
 *  6.  GetFullHeightEstimate — prime: SESSION_STATUS > KEEPALIVE precedence
 *  7.  GetFullHeightEstimate — prime falls back to KEEPALIVE when SESSION_STATUS has no heights
 *  8.  GetFullHeightEstimate — prime falls back to canonical when mining Prime and no shadow heights
 *  9.  GetFullHeightEstimate — hash: SESSION_STATUS > KEEPALIVE precedence
 * 10.  GetFullHeightEstimate — stake: SESSION_STATUS > KEEPALIVE precedence
 * 11.  GetFullHeightEstimate — unified = max(canonical, session_status, keepalive, push)
 * 12.  GetFullHeightEstimate — SESSION_STATUS wins unified when it is highest
 * 13.  IsKeepaliveStale — false immediately after IngestKeepaliveAck
 * 14.  IsSessionStatusStale — false immediately after IngestSessionStatusAck
 * 15.  OnSessionEpochChanged — clears keepalive, push, status but NOT canonical
 * 16.  DiagnosticSummary — non-empty; contains 'status' and 'canonical' sections
 * 17.  FullHeightEstimate::freshness_summary — non-empty, contains all channels
 * 18.  Canonical accumulates across multiple updates (always advances to max)
 * 19.  Keepalive observation overwritten on each call (not max)
 * 20.  GetFullHeightEstimate — is_shadow_stale: false when SESSION_STATUS is fresh
 * 21.  GetLastKeepaliveObservation / GetLastSessionStatusObservation / GetLastPushObservation
 * 22.  SessionStatusObservation::has_heights() returns false when heights are zero
 * 23.  SESSION_STATUS health-only ingest (heights=0): falls back to keepalive for heights
 * 24.  SESSION_STATUS with heights: all four channels populated correctly
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
// Test 4: IngestSessionStatusAck — health + height fields; does not touch canonical
// ─────────────────────────────────────────────────────────────────────────────
static void test_session_status_with_heights()
{
    ChannelHeightShadowTracker t;
    // Ingest with full heights (extended ACK simulation)
    t.IngestSessionStatusAck(true, 3600, /*unified=*/1100, /*prime=*/520, /*hash=*/650, /*stake=*/210);

    auto s = t.GetLastSessionStatusObservation();
    print_test_result("session status is_authenticated stored",  s.is_authenticated);
    print_test_result("session status uptime_seconds stored",    s.uptime_seconds == 3600);
    print_test_result("session status is_initialized after ingest", s.is_initialized());
    print_test_result("session status unified_height stored",    s.unified_height == 1100);
    print_test_result("session status prime_height stored",      s.prime_height   == 520);
    print_test_result("session status hash_height stored",       s.hash_height    == 650);
    print_test_result("session status stake_height stored",      s.stake_height   == 210);
    print_test_result("session status has_heights() == true",    s.has_heights());

    // Canonical must NOT be modified by SESSION_STATUS
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
// Test 6: GetFullHeightEstimate — SESSION_STATUS beats KEEPALIVE for prime
// ─────────────────────────────────────────────────────────────────────────────
static void test_prime_height_session_status_beats_keepalive()
{
    ChannelHeightShadowTracker t;
    t.UpdateCanonical(1000, 500, 1);           // mining Prime
    t.IngestKeepaliveAck(1050, 505, 600, 200); // keepalive: prime=505
    t.IngestSessionStatusAck(true, 3600, 1060, /*prime=*/510, 620, 210); // status: prime=510

    auto est = t.GetFullHeightEstimate();
    print_test_result("prime_height = SESSION_STATUS prime (510) over KEEPALIVE (505)",
                      est.prime_height == 510);
    print_test_result("prime_source = SESSION_STATUS",
                      est.prime_source == ChannelHeightShadowTracker::HeightSource::SESSION_STATUS);
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 7: GetFullHeightEstimate — prime falls back to KEEPALIVE when SESSION_STATUS has no heights
// ─────────────────────────────────────────────────────────────────────────────
static void test_prime_height_fallback_to_keepalive()
{
    ChannelHeightShadowTracker t;
    t.UpdateCanonical(1000, 500, 1);
    // Health-only ACK (no heights = current 16-byte wire format)
    t.IngestSessionStatusAck(true, 3600); // heights default to 0
    t.IngestKeepaliveAck(1050, 505, 600, 200);

    auto est = t.GetFullHeightEstimate();
    print_test_result("prime falls back to KEEPALIVE when SESSION_STATUS has no heights",
                      est.prime_height == 505);
    print_test_result("prime_source = KEEPALIVE_ACK when SESSION_STATUS has no prime",
                      est.prime_source == ChannelHeightShadowTracker::HeightSource::KEEPALIVE_ACK);
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 8: GetFullHeightEstimate — prime falls back to canonical when no shadow heights
// ─────────────────────────────────────────────────────────────────────────────
static void test_prime_height_fallback_to_canonical()
{
    ChannelHeightShadowTracker t;
    t.UpdateCanonical(1000, 500, 1);   // mining Prime; no shadow heights

    auto est = t.GetFullHeightEstimate();
    print_test_result("prime falls back to canonical channel_height when no shadow",
                      est.prime_height == 500);
    print_test_result("prime_source = BLOCK_DATA when no shadow heights",
                      est.prime_source == ChannelHeightShadowTracker::HeightSource::BLOCK_DATA);
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 9: GetFullHeightEstimate — hash: SESSION_STATUS > KEEPALIVE precedence
// ─────────────────────────────────────────────────────────────────────────────
static void test_hash_height_session_status_beats_keepalive()
{
    ChannelHeightShadowTracker t;
    t.UpdateCanonical(1000, 500, 2);           // mining Hash
    t.IngestKeepaliveAck(1050, 505, 600, 200); // keepalive: hash=600
    t.IngestSessionStatusAck(true, 3600, 1060, 510, /*hash=*/605, 210); // status: hash=605

    auto est = t.GetFullHeightEstimate();
    print_test_result("hash_height = SESSION_STATUS hash (605) over KEEPALIVE (600)",
                      est.hash_height == 605);
    print_test_result("hash_source = SESSION_STATUS",
                      est.hash_source == ChannelHeightShadowTracker::HeightSource::SESSION_STATUS);
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 10: GetFullHeightEstimate — stake: SESSION_STATUS > KEEPALIVE precedence
// ─────────────────────────────────────────────────────────────────────────────
static void test_stake_height_session_status_beats_keepalive()
{
    ChannelHeightShadowTracker t;
    t.UpdateCanonical(1000, 500, 1);
    t.IngestKeepaliveAck(1050, 505, 600, 200); // keepalive: stake=200
    t.IngestSessionStatusAck(true, 3600, 1060, 510, 605, /*stake=*/210); // status: stake=210

    auto est = t.GetFullHeightEstimate();
    print_test_result("stake_height = SESSION_STATUS stake (210) over KEEPALIVE (200)",
                      est.stake_height == 210);
    print_test_result("stake_source = SESSION_STATUS",
                      est.stake_source == ChannelHeightShadowTracker::HeightSource::SESSION_STATUS);
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 11: GetFullHeightEstimate — unified = max across all four sources
// ─────────────────────────────────────────────────────────────────────────────
static void test_unified_height_max_across_sources()
{
    ChannelHeightShadowTracker t;
    t.UpdateCanonical(1000, 500, 1);
    t.IngestKeepaliveAck(1020, 505, 600, 200);
    t.IngestSessionStatusAck(true, 3600, /*unified=*/1025, 510, 605, 210);
    t.IngestPush(1015, 505, 1);

    auto est = t.GetFullHeightEstimate();
    // session_status is highest at 1025
    print_test_result("unified = max(canonical=1000, status=1025, keepalive=1020, push=1015) => 1025",
                      est.unified_height == 1025);
    print_test_result("unified_source = SESSION_STATUS when it is highest",
                      est.unified_source == ChannelHeightShadowTracker::HeightSource::SESSION_STATUS);
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 12: GetFullHeightEstimate — KEEPALIVE wins unified when SESSION_STATUS has no unified
// ─────────────────────────────────────────────────────────────────────────────
static void test_unified_height_keepalive_wins_when_status_absent()
{
    ChannelHeightShadowTracker t;
    t.UpdateCanonical(1000, 500, 1);
    t.IngestKeepaliveAck(1030, 505, 600, 200);  // keepalive unified=1030
    // Health-only SESSION_STATUS (no heights)
    t.IngestSessionStatusAck(true, 3600);
    t.IngestPush(1015, 505, 1);

    auto est = t.GetFullHeightEstimate();
    print_test_result("unified = max(1000, 0, 1030, 1015) => 1030 from keepalive",
                      est.unified_height == 1030);
    print_test_result("unified_source = KEEPALIVE_ACK when session status has no heights",
                      est.unified_source == ChannelHeightShadowTracker::HeightSource::KEEPALIVE_ACK);
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
// Test 14: IsSessionStatusStale — false immediately; true before any ingest
// ─────────────────────────────────────────────────────────────────────────────
static void test_session_status_stale_check()
{
    ChannelHeightShadowTracker t;
    print_test_result("IsSessionStatusStale true before any session status (1s max)",
                      t.IsSessionStatusStale(std::chrono::seconds(1)));

    t.IngestSessionStatusAck(true, 3600);
    print_test_result("IsSessionStatusStale false immediately after ingest (60s max)",
                      !t.IsSessionStatusStale(std::chrono::seconds(60)));
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 15: OnSessionEpochChanged — clears shadow, preserves canonical
// ─────────────────────────────────────────────────────────────────────────────
static void test_epoch_change_clears_shadow_preserves_canonical()
{
    ChannelHeightShadowTracker t;
    t.UpdateCanonical(1000, 500, 1);
    t.IngestKeepaliveAck(1050, 505, 600, 200);
    t.IngestSessionStatusAck(true, 3600, 1060, 510, 605, 210);
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
// Test 16: DiagnosticSummary — non-empty; contains 'status' and 'canonical'
// ─────────────────────────────────────────────────────────────────────────────
static void test_diagnostic_summary_non_empty()
{
    ChannelHeightShadowTracker t;
    t.UpdateCanonical(1000, 500, 1);
    t.IngestKeepaliveAck(1050, 505, 600, 200);
    t.IngestSessionStatusAck(true, 3600, 1060, 510, 605, 210);

    auto summary = t.DiagnosticSummary();
    print_test_result("DiagnosticSummary is non-empty", !summary.empty());
    print_test_result("DiagnosticSummary contains 'canonical'",
                      summary.find("canonical") != std::string::npos);
    print_test_result("DiagnosticSummary contains 'status'",
                      summary.find("status") != std::string::npos);
    print_test_result("DiagnosticSummary contains 'keepalive'",
                      summary.find("keepalive") != std::string::npos);
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 17: FullHeightEstimate::freshness_summary — non-empty, contains all channels
// ─────────────────────────────────────────────────────────────────────────────
static void test_freshness_summary_format()
{
    ChannelHeightShadowTracker t;
    t.UpdateCanonical(1000, 500, 1);
    t.IngestSessionStatusAck(true, 3600, 1060, 510, 605, 210);

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
// Test 19: GetFullHeightEstimate — is_shadow_stale: false when SESSION_STATUS is fresh
// ─────────────────────────────────────────────────────────────────────────────
static void test_full_height_estimate_shadow_stale_flag()
{
    ChannelHeightShadowTracker t;
    // No shadow observations at all → stale
    auto est = t.GetFullHeightEstimate();
    print_test_result("is_shadow_stale = true when no shadow observations",
                      est.is_shadow_stale);

    // After a fresh session status → not stale (primary source)
    t.IngestSessionStatusAck(true, 3600);
    est = t.GetFullHeightEstimate();
    print_test_result("is_shadow_stale = false after fresh SESSION_STATUS_ACK",
                      !est.is_shadow_stale);

    // After clearing and ingesting keepalive only → also not stale (secondary source)
    ChannelHeightShadowTracker t2;
    t2.IngestKeepaliveAck(1000, 500, 600, 200);
    est = t2.GetFullHeightEstimate();
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
    t.IngestSessionStatusAck(true, 1800, 1010, 505, 610, 205);
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
    print_test_result("keepalive stake_height = 200",      k.stake_height == 200);
    print_test_result("session status uptime = 1800",      s.uptime_seconds == 1800);
    print_test_result("session status prime_height = 505", s.prime_height == 505);
    print_test_result("push channel = 2",                  p.channel == 2);
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 21: SessionStatusObservation::has_heights() — false when heights are zero
// ─────────────────────────────────────────────────────────────────────────────
static void test_session_status_has_heights()
{
    ChannelHeightShadowTracker t;
    // Health-only (current 16-byte wire format)
    t.IngestSessionStatusAck(true, 3600);
    auto s = t.GetLastSessionStatusObservation();
    print_test_result("has_heights() == false for health-only ACK (heights=0)",
                      !s.has_heights());

    // Extended ACK with heights
    ChannelHeightShadowTracker t2;
    t2.IngestSessionStatusAck(true, 3600, 1000, 500, 600, 200);
    auto s2 = t2.GetLastSessionStatusObservation();
    print_test_result("has_heights() == true when unified_height > 0",
                      s2.has_heights());
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 22: Health-only SESSION_STATUS (heights=0) — falls back to keepalive
// ─────────────────────────────────────────────────────────────────────────────
static void test_session_status_health_only_fallback_to_keepalive()
{
    ChannelHeightShadowTracker t;
    t.UpdateCanonical(1000, 500, 1);
    // Health-only ACK (heights default to 0 = current wire format)
    t.IngestSessionStatusAck(true, 3600);
    t.IngestKeepaliveAck(1050, 505, 600, 200);

    auto est = t.GetFullHeightEstimate();
    // SESSION_STATUS has no heights → keepalive should supply prime/hash/stake
    print_test_result("prime from keepalive when SESSION_STATUS has no prime",
                      est.prime_height == 505);
    print_test_result("prime_source = KEEPALIVE_ACK",
                      est.prime_source == ChannelHeightShadowTracker::HeightSource::KEEPALIVE_ACK);
    print_test_result("hash from keepalive when SESSION_STATUS has no hash",
                      est.hash_height == 600);
    print_test_result("stake from keepalive when SESSION_STATUS has no stake",
                      est.stake_height == 200);
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 23: SESSION_STATUS with heights takes precedence over keepalive in all channels
// ─────────────────────────────────────────────────────────────────────────────
static void test_session_status_with_heights_takes_full_precedence()
{
    ChannelHeightShadowTracker t;
    t.UpdateCanonical(1000, 500, 1);
    t.IngestKeepaliveAck(1050, 505, 600, 200);  // keepalive: lower heights
    // Extended ACK with all channels
    t.IngestSessionStatusAck(true, 3600, /*unified=*/1060, /*prime=*/510, /*hash=*/610, /*stake=*/210);

    auto est = t.GetFullHeightEstimate();
    print_test_result("SESSION_STATUS prime (510) > KEEPALIVE prime (505)",
                      est.prime_height == 510 &&
                      est.prime_source == ChannelHeightShadowTracker::HeightSource::SESSION_STATUS);
    print_test_result("SESSION_STATUS hash (610) > KEEPALIVE hash (600)",
                      est.hash_height == 610 &&
                      est.hash_source == ChannelHeightShadowTracker::HeightSource::SESSION_STATUS);
    print_test_result("SESSION_STATUS stake (210) > KEEPALIVE stake (200)",
                      est.stake_height == 210 &&
                      est.stake_source == ChannelHeightShadowTracker::HeightSource::SESSION_STATUS);
    print_test_result("SESSION_STATUS unified (1060) > KEEPALIVE unified (1050)",
                      est.unified_height == 1060 &&
                      est.unified_source == ChannelHeightShadowTracker::HeightSource::SESSION_STATUS);
}

// ─────────────────────────────────────────────────────────────────────────────
// Cross-check tests (CheckUnifiedHeightDivergence)
// ─────────────────────────────────────────────────────────────────────────────

// Test 24: No canonical → no recommendation
static void test_cross_check_no_canonical()
{
    ChannelHeightShadowTracker t;
    t.IngestKeepaliveAck(1050, 505, 600, 200);  // shadow only, no canonical

    auto cc = t.CheckUnifiedHeightDivergence();
    print_test_result("cross-check: should_request_block=false when no canonical",
                      !cc.should_request_block);
    print_test_result("cross-check: canonical_unified=0 when no canonical",
                      cc.canonical_unified == 0);
}

// Test 25: Divergence within threshold (≤2) → no recommendation
static void test_cross_check_within_threshold()
{
    ChannelHeightShadowTracker t;
    t.UpdateCanonical(1000, 500, 1);

    // shadow exactly 2 ahead — at threshold, NOT above
    t.IngestKeepaliveAck(1002, 505, 600, 200);
    auto cc = t.CheckUnifiedHeightDivergence(2);
    print_test_result("cross-check: should_request_block=false when divergence==2 (at threshold)",
                      !cc.should_request_block);
    print_test_result("cross-check: divergence reported correctly",
                      cc.divergence == 2);

    // shadow exactly equal — no action
    ChannelHeightShadowTracker t2;
    t2.UpdateCanonical(1000, 500, 1);
    t2.IngestKeepaliveAck(1000, 505, 600, 200);
    auto cc2 = t2.CheckUnifiedHeightDivergence(2);
    print_test_result("cross-check: should_request_block=false when divergence==0",
                      !cc2.should_request_block);

    // shadow behind canonical — no action
    ChannelHeightShadowTracker t3;
    t3.UpdateCanonical(1010, 500, 1);
    t3.IngestKeepaliveAck(1000, 505, 600, 200);
    auto cc3 = t3.CheckUnifiedHeightDivergence(2);
    print_test_result("cross-check: should_request_block=false when shadow behind canonical",
                      !cc3.should_request_block);
    print_test_result("cross-check: negative divergence reported correctly",
                      cc3.divergence == -10);
}

// Test 26: Divergence exceeds threshold (>2) → should_request_block == true
static void test_cross_check_exceeds_threshold()
{
    ChannelHeightShadowTracker t;
    t.UpdateCanonical(1000, 500, 1);
    t.IngestKeepaliveAck(1003, 505, 600, 200);  // 3 ahead — exceeds threshold of 2

    auto cc = t.CheckUnifiedHeightDivergence(2);
    print_test_result("cross-check: should_request_block=true when divergence==3 > threshold 2",
                      cc.should_request_block);
    print_test_result("cross-check: canonical_unified correct",
                      cc.canonical_unified == 1000);
    print_test_result("cross-check: shadow_unified correct",
                      cc.shadow_unified == 1003);
    print_test_result("cross-check: divergence == 3",
                      cc.divergence == 3);
    print_test_result("cross-check: shadow_source == KEEPALIVE_ACK",
                      cc.shadow_source == ChannelHeightShadowTracker::HeightSource::KEEPALIVE_ACK);
    print_test_result("cross-check: not rate_limited on first fire",
                      !cc.rate_limited);
}

// Test 27: SESSION_STATUS shadow beats keepalive for cross-check source
// This tests the extended-ACK code path: IngestSessionStatusAck() accepts
// optional height parameters (defaulting to 0 for the current 16-byte wire
// format). When non-zero heights are supplied (future extended ACK), they
// become the primary shadow source and the cross-check uses them.
static void test_cross_check_session_status_source()
{
    ChannelHeightShadowTracker t;
    t.UpdateCanonical(1000, 500, 1);
    t.IngestKeepaliveAck(1002, 505, 600, 200);      // only 2 ahead
    t.IngestSessionStatusAck(true, 3600, /*unified=*/1004, 510, 605, 210);  // 4 ahead

    auto cc = t.CheckUnifiedHeightDivergence(2);
    print_test_result("cross-check: fires when SESSION_STATUS provides highest shadow unified",
                      cc.should_request_block);
    print_test_result("cross-check: shadow_unified == 1004 (from SESSION_STATUS)",
                      cc.shadow_unified == 1004);
    print_test_result("cross-check: shadow_source == SESSION_STATUS",
                      cc.shadow_source == ChannelHeightShadowTracker::HeightSource::SESSION_STATUS);
}

// Test 28: Rate limiting — second immediate call is suppressed
static void test_cross_check_rate_limited()
{
    ChannelHeightShadowTracker t;
    t.UpdateCanonical(1000, 500, 1);
    t.IngestKeepaliveAck(1005, 505, 600, 200);  // 5 ahead — fires

    auto cc1 = t.CheckUnifiedHeightDivergence(2);
    print_test_result("cross-check: first call fires",
                      cc1.should_request_block);

    // Immediate second call: same conditions, but rate-limited
    auto cc2 = t.CheckUnifiedHeightDivergence(2);
    print_test_result("cross-check: second immediate call is rate-limited",
                      !cc2.should_request_block);
    print_test_result("cross-check: rate_limited flag set on suppressed call",
                      cc2.rate_limited);
}

// Test 29: Session epoch change resets the cross-check cooldown
static void test_cross_check_epoch_change_resets_cooldown()
{
    ChannelHeightShadowTracker t;
    t.UpdateCanonical(1000, 500, 1);
    t.IngestKeepaliveAck(1005, 505, 600, 200);

    // First call fires, setting the cooldown
    auto cc1 = t.CheckUnifiedHeightDivergence(2);
    print_test_result("cross-check epoch-reset: first call fires",
                      cc1.should_request_block);

    // Epoch change should reset cooldown
    t.OnSessionEpochChanged();

    // Re-ingest heights (epoch cleared shadow)
    t.IngestKeepaliveAck(1005, 505, 600, 200);

    // Should fire again immediately because cooldown was reset
    auto cc2 = t.CheckUnifiedHeightDivergence(2);
    print_test_result("cross-check epoch-reset: fires again after OnSessionEpochChanged",
                      cc2.should_request_block);
    print_test_result("cross-check epoch-reset: not rate_limited after epoch change",
                      !cc2.rate_limited);
}

// Test 30: Push observation as shadow source for cross-check
static void test_cross_check_push_source()
{
    ChannelHeightShadowTracker t;
    t.UpdateCanonical(1000, 500, 1);
    t.IngestPush(1004, 505, 1);  // push unified 4 ahead

    auto cc = t.CheckUnifiedHeightDivergence(2);
    print_test_result("cross-check: fires when PUSH provides highest shadow unified",
                      cc.should_request_block);
    print_test_result("cross-check: shadow_source == PUSH",
                      cc.shadow_source == ChannelHeightShadowTracker::HeightSource::PUSH);
    print_test_result("cross-check: divergence == 4",
                      cc.divergence == 4);
}

// Test 31: CROSS_CHECK_COOLDOWN_SECONDS constant is accessible
static void test_cross_check_constant()
{
    print_test_result("CROSS_CHECK_COOLDOWN_SECONDS >= 30",
                      ChannelHeightShadowTracker::CROSS_CHECK_COOLDOWN_SECONDS >= 30u);
    print_test_result("CROSS_CHECK_COOLDOWN_SECONDS <= 300",
                      ChannelHeightShadowTracker::CROSS_CHECK_COOLDOWN_SECONDS <= 300u);
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
    test_session_status_with_heights();
    test_push_does_not_touch_canonical();
    test_prime_height_session_status_beats_keepalive();
    test_prime_height_fallback_to_keepalive();
    test_prime_height_fallback_to_canonical();
    test_hash_height_session_status_beats_keepalive();
    test_stake_height_session_status_beats_keepalive();
    test_unified_height_max_across_sources();
    test_unified_height_keepalive_wins_when_status_absent();
    test_keepalive_stale_check();
    test_session_status_stale_check();
    test_epoch_change_clears_shadow_preserves_canonical();
    test_diagnostic_summary_non_empty();
    test_freshness_summary_format();
    test_canonical_accumulates_max();
    test_keepalive_overwrites_not_max();
    test_full_height_estimate_shadow_stale_flag();
    test_observation_accessors();
    test_session_status_has_heights();
    test_session_status_health_only_fallback_to_keepalive();
    test_session_status_with_heights_takes_full_precedence();

    // Cross-check tests
    test_cross_check_no_canonical();
    test_cross_check_within_threshold();
    test_cross_check_exceeds_threshold();
    test_cross_check_session_status_source();
    test_cross_check_rate_limited();
    test_cross_check_epoch_change_resets_cooldown();
    test_cross_check_push_source();
    test_cross_check_constant();

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
