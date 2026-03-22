/**
 * @file channel_height_shadow_tracker_test.cpp
 * @brief Unit tests for ChannelHeightShadowTracker
 *
 * Tests:
 *  1.  Fresh tracker is uninitialized in all layers
 *  2.  IngestBlockData updates canonical; no shadow/push/health/get_height spillover
 *  3.  IngestBlockData is monotonic — stale BLOCK_DATA cannot regress canonical
 *  4.  IngestKeepaliveAck updates shadow only; no canonical/get_height spillover
 *  5.  IngestSessionStatusAck updates health only; no canonical/shadow/get_height spillover
 *  6.  IngestPushNotification updates push trend only; no canonical/shadow/get_height spillover
 *  7.  CrossCheck: canonical agrees with shadow when heights match
 *  8.  CrossCheck: disagreement detected when heights diverge by >1 (keepalive fallback)
 *  9.  CrossCheck: no disagreement when shadow is stale (tolerance irrelevant)
 * 10.  CrossCheck: shadow_leads_canonical when shadow unified > canonical unified
 * 11.  CrossCheck: canonical_leads_shadow when canonical unified > shadow unified
 * 12.  CrossCheck: fork_detected when keepalive fork_score > 0
 * 13.  CrossCheck: fork_canary_set persists after fork_score returns to 0
 * 14.  GetSnapshot returns all five layers consistently
 * 15.  Reset clears all state including get_height
 * 16.  SESSION_STATUS_ACK: no heights ingested even with zero-value params (protocol-correct)
 * 17.  source_name() returns correct strings for all SourceKinds including GET_HEIGHT
 * 18.  CrossCheckResult::describe() produces non-empty string
 * 19.  IsShadowStale() returns true before any keepalive ACK
 * 20.  IsSessionHealthStale() returns true before any SESSION_STATUS_ACK
 * 21.  most_recent_source tracks the last ingested source correctly including GET_HEIGHT
 * 22.  Canonical unified and mined_channel advance independently and monotonically
 * 23.  Shadow prime/hash/stake all captured correctly from keepalive
 * 24.  CrossCheck::is_disagreement() respects tolerance parameter (keepalive fallback)
 * 25.  Multiple sources ingested; snapshot shows consistent combined state
 * 26.  IngestGetHeightResponse updates get_height only; no spillover to canonical/shadow/push/health
 * 27.  GetHeightState: unified_height stored correctly
 * 28.  IsGetHeightStale() returns true before any GET_HEIGHT response
 * 29.  CrossCheck primary path: GET_HEIGHT disagreement detected when present and fresh
 * 30.  CrossCheck priority: GET_HEIGHT primary overrides keepalive when both present
 */

#include "protocol/channel_height_shadow_tracker.hpp"
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
// Test 1: Fresh tracker is uninitialized in all layers
// ============================================================================
void test_fresh_tracker_uninitialized() {
    std::cout << "\nTest 1: Fresh tracker is uninitialized in all layers\n";
    ChannelHeightShadowTracker t;
    auto snap = t.GetSnapshot();
    print_test_result("canonical not initialized",      !snap.canonical.is_initialized());
    print_test_result("get_height not initialized",     !snap.get_height.is_initialized());
    print_test_result("shadow not initialized",         !snap.shadow.is_initialized());
    print_test_result("session_health not initialized", !snap.session_health.is_initialized());
    print_test_result("push_trend not initialized",     !snap.push_trend.is_initialized());
    print_test_result("any_source_initialized false",   !snap.any_source_initialized());
    print_test_result("canonical unified_height == 0",  snap.canonical.unified_height == 0);
    print_test_result("get_height unified_height == 0", snap.get_height.unified_height == 0);
    print_test_result("shadow unified_height == 0",     snap.shadow.unified_height == 0);
}

// ============================================================================
// Test 2: IngestBlockData updates canonical only
// ============================================================================
void test_ingest_block_data_canonical_only() {
    std::cout << "\nTest 2: IngestBlockData updates canonical; no shadow/push/health/get_height spillover\n";
    ChannelHeightShadowTracker t;
    t.IngestBlockData(5000, 200);
    auto snap = t.GetSnapshot();
    print_test_result("canonical.initialized == true",         snap.canonical.is_initialized());
    print_test_result("canonical.unified_height == 5000",      snap.canonical.unified_height == 5000);
    print_test_result("canonical.mined_channel_height == 200", snap.canonical.mined_channel_height == 200);
    print_test_result("get_height.initialized == false",       !snap.get_height.is_initialized());
    print_test_result("shadow.initialized == false",           !snap.shadow.is_initialized());
    print_test_result("session_health.initialized == false",   !snap.session_health.is_initialized());
    print_test_result("push_trend.initialized == false",       !snap.push_trend.is_initialized());
    print_test_result("get_height.unified_height == 0",        snap.get_height.unified_height == 0);
    print_test_result("shadow.unified_height == 0",            snap.shadow.unified_height == 0);
}

// ============================================================================
// Test 3: IngestBlockData is monotonic
// ============================================================================
void test_ingest_block_data_monotonic() {
    std::cout << "\nTest 3: IngestBlockData is monotonic — stale BLOCK_DATA cannot regress\n";
    ChannelHeightShadowTracker t;
    t.IngestBlockData(5000, 200);
    t.IngestBlockData(4999, 180);  // stale, should be ignored
    auto snap = t.GetSnapshot();
    print_test_result("canonical.unified_height still 5000",       snap.canonical.unified_height == 5000);
    print_test_result("canonical.mined_channel_height still 200",  snap.canonical.mined_channel_height == 200);
    t.IngestBlockData(5001, 201);  // advance
    snap = t.GetSnapshot();
    print_test_result("canonical.unified_height advanced to 5001", snap.canonical.unified_height == 5001);
    print_test_result("canonical.mined_channel advanced to 201",   snap.canonical.mined_channel_height == 201);
}

// ============================================================================
// Test 4: IngestKeepaliveAck updates shadow only
// ============================================================================
void test_ingest_keepalive_ack_shadow_only() {
    std::cout << "\nTest 4: IngestKeepaliveAck updates shadow only; no canonical/get_height spillover\n";
    ChannelHeightShadowTracker t;
    t.IngestKeepaliveAck(5000, 200, 300, 50, 0);
    auto snap = t.GetSnapshot();
    print_test_result("shadow.initialized == true",          snap.shadow.is_initialized());
    print_test_result("shadow.unified_height == 5000",       snap.shadow.unified_height == 5000);
    print_test_result("shadow.prime_height == 200",          snap.shadow.prime_height == 200);
    print_test_result("shadow.hash_height == 300",           snap.shadow.hash_height == 300);
    print_test_result("shadow.stake_height == 50",           snap.shadow.stake_height == 50);
    print_test_result("shadow.fork_score == 0",              snap.shadow.fork_score == 0);
    print_test_result("canonical.initialized == false",      !snap.canonical.is_initialized());
    print_test_result("canonical.unified_height == 0",       snap.canonical.unified_height == 0);
    print_test_result("get_height.initialized == false",     !snap.get_height.is_initialized());
    print_test_result("get_height.unified_height == 0",      snap.get_height.unified_height == 0);
    print_test_result("push_trend.initialized == false",     !snap.push_trend.is_initialized());
    print_test_result("session_health.initialized == false", !snap.session_health.is_initialized());
}

// ============================================================================
// Test 5: IngestSessionStatusAck updates health only
// ============================================================================
void test_ingest_session_status_health_only() {
    std::cout << "\nTest 5: IngestSessionStatusAck updates health only; no canonical/shadow/get_height spillover\n";
    ChannelHeightShadowTracker t;
    t.IngestSessionStatusAck(true, true, false, false, 3600);
    auto snap = t.GetSnapshot();
    print_test_result("session_health.initialized == true",      snap.session_health.is_initialized());
    print_test_result("session_health.is_authenticated == true", snap.session_health.is_authenticated);
    print_test_result("primary_lane_alive == true",              snap.session_health.primary_lane_alive);
    print_test_result("secondary_lane_alive == false",           !snap.session_health.secondary_lane_alive);
    print_test_result("simlink_active == false",                 !snap.session_health.simlink_active);
    print_test_result("uptime_seconds == 3600",                  snap.session_health.uptime_seconds == 3600);
    // Confirm no spillover to canonical, shadow, get_height, or push
    print_test_result("canonical.initialized == false",          !snap.canonical.is_initialized());
    print_test_result("get_height.initialized == false",         !snap.get_height.is_initialized());
    print_test_result("shadow.initialized == false",             !snap.shadow.is_initialized());
    print_test_result("push_trend.initialized == false",         !snap.push_trend.is_initialized());
    print_test_result("canonical.unified_height == 0",           snap.canonical.unified_height == 0);
    print_test_result("get_height.unified_height == 0",          snap.get_height.unified_height == 0);
    print_test_result("shadow.unified_height == 0",              snap.shadow.unified_height == 0);
}

// ============================================================================
// Test 6: IngestPushNotification updates push trend only
// ============================================================================
void test_ingest_push_trend_only() {
    std::cout << "\nTest 6: IngestPushNotification updates push trend only; no canonical/shadow/get_height spillover\n";
    ChannelHeightShadowTracker t;
    t.IngestPushNotification(5000, 200);
    auto snap = t.GetSnapshot();
    print_test_result("push_trend.initialized == true",          snap.push_trend.is_initialized());
    print_test_result("push_trend.unified_height == 5000",       snap.push_trend.unified_height == 5000);
    print_test_result("push_trend.channel_height == 200",        snap.push_trend.channel_height == 200);
    print_test_result("canonical.initialized == false",          !snap.canonical.is_initialized());
    print_test_result("get_height.initialized == false",         !snap.get_height.is_initialized());
    print_test_result("shadow.initialized == false",             !snap.shadow.is_initialized());
    print_test_result("session_health.initialized == false",     !snap.session_health.is_initialized());
}

// ============================================================================
// Test 7: CrossCheck agrees when canonical == shadow unified height
// ============================================================================
void test_cross_check_agrees_when_equal() {
    std::cout << "\nTest 7: CrossCheck agrees when canonical == shadow unified height\n";
    ChannelHeightShadowTracker t;
    t.IngestBlockData(5000, 200);
    t.IngestKeepaliveAck(5000, 200, 300, 50, 0);
    auto r = t.CrossCheck();
    print_test_result("canonical_initialized == true", r.canonical_initialized);
    print_test_result("shadow_initialized == true",    r.shadow_initialized);
    print_test_result("shadow_is_stale == false",      !r.shadow_is_stale);
    print_test_result("unified_delta == 0",            r.unified_delta == 0);
    print_test_result("unified_heights_agree == true", r.unified_heights_agree);
    print_test_result("is_disagreement(1) == false",   !r.is_disagreement(1));
}

// ============================================================================
// Test 8: CrossCheck detects disagreement when heights diverge
// ============================================================================
void test_cross_check_disagreement_detected() {
    std::cout << "\nTest 8: CrossCheck: disagreement detected when heights diverge by >1 (keepalive fallback)\n";
    ChannelHeightShadowTracker t;
    t.IngestBlockData(5005, 200);
    t.IngestKeepaliveAck(5000, 200, 300, 50, 0);  // shadow 5 blocks behind canonical; no GET_HEIGHT
    auto r = t.CrossCheck();
    // get_height not ingested — is_disagreement falls back to keepalive
    print_test_result("get_height_initialized == false",   !r.get_height_initialized);
    print_test_result("unified_heights_agree == false",    !r.unified_heights_agree);
    print_test_result("unified_delta == 5",                 r.unified_delta == 5);
    print_test_result("canonical_leads_shadow == true",     r.canonical_leads_shadow);
    print_test_result("shadow_leads_canonical == false",    !r.shadow_leads_canonical);
    print_test_result("is_disagreement(1) == true",         r.is_disagreement(1));
    print_test_result("is_disagreement(5) == false",        !r.is_disagreement(5));  // within tolerance
    print_test_result("is_disagreement(4) == true",         r.is_disagreement(4));   // just outside tolerance
}

// ============================================================================
// Test 9: CrossCheck: no disagreement when shadow is stale
// ============================================================================
void test_cross_check_no_disagreement_when_stale() {
    std::cout << "\nTest 9: CrossCheck: no disagreement when shadow is stale\n";
    // We can't fast-forward time, so test the logic path directly:
    // When shadow is not initialized, is_disagreement() returns false.
    ChannelHeightShadowTracker t;
    t.IngestBlockData(5000, 200);
    // No keepalive — shadow uninitialized
    auto r = t.CrossCheck();
    print_test_result("shadow_initialized == false",    !r.shadow_initialized);
    print_test_result("is_disagreement(1) == false",    !r.is_disagreement(1));
}

// ============================================================================
// Test 10: CrossCheck: shadow_leads_canonical
// ============================================================================
void test_cross_check_shadow_leads() {
    std::cout << "\nTest 10: CrossCheck: shadow_leads_canonical when shadow ahead\n";
    ChannelHeightShadowTracker t;
    t.IngestBlockData(5000, 200);
    t.IngestKeepaliveAck(5003, 202, 302, 52, 0);  // shadow 3 blocks ahead
    auto r = t.CrossCheck();
    print_test_result("shadow_leads_canonical == true",  r.shadow_leads_canonical);
    print_test_result("canonical_leads_shadow == false", !r.canonical_leads_shadow);
    print_test_result("unified_delta == -3",             r.unified_delta == -3);
}

// ============================================================================
// Test 11: CrossCheck: canonical_leads_shadow
// ============================================================================
void test_cross_check_canonical_leads() {
    std::cout << "\nTest 11: CrossCheck: canonical_leads_shadow when canonical ahead\n";
    ChannelHeightShadowTracker t;
    t.IngestBlockData(5003, 200);
    t.IngestKeepaliveAck(5000, 200, 300, 50, 0);
    auto r = t.CrossCheck();
    print_test_result("canonical_leads_shadow == true",  r.canonical_leads_shadow);
    print_test_result("shadow_leads_canonical == false", !r.shadow_leads_canonical);
    print_test_result("unified_delta == 3",              r.unified_delta == 3);
}

// ============================================================================
// Test 12: CrossCheck: fork_detected when fork_score > 0
// ============================================================================
void test_cross_check_fork_detected() {
    std::cout << "\nTest 12: CrossCheck: fork_detected when keepalive fork_score > 0\n";
    ChannelHeightShadowTracker t;
    t.IngestKeepaliveAck(5000, 200, 300, 50, 7);  // fork_score = 7
    auto r = t.CrossCheck();
    print_test_result("fork_detected == true",    r.fork_detected);
    print_test_result("fork_canary_set == true",  r.fork_canary_set);
}

// ============================================================================
// Test 13: CrossCheck: fork_canary_set persists after fork_score returns to 0
// ============================================================================
void test_fork_canary_persists() {
    std::cout << "\nTest 13: CrossCheck: fork_canary_set persists after fork_score returns to 0\n";
    ChannelHeightShadowTracker t;
    t.IngestKeepaliveAck(5000, 200, 300, 50, 7);
    t.IngestKeepaliveAck(5001, 201, 301, 51, 0);  // fork cleared
    auto snap = t.GetSnapshot();
    print_test_result("shadow.fork_score == 0",        snap.shadow.fork_score == 0);
    print_test_result("shadow.peak_fork_score == 7",   snap.shadow.peak_fork_score == 7);
    print_test_result("fork_canary_set persists",      snap.cross_check.fork_canary_set);
    print_test_result("fork_detected == false",        !snap.cross_check.fork_detected);
}

// ============================================================================
// Test 14: GetSnapshot returns all four layers
// ============================================================================
void test_get_snapshot_all_layers() {
    std::cout << "\nTest 14: GetSnapshot returns all five layers consistently\n";
    ChannelHeightShadowTracker t;
    t.IngestBlockData(5000, 200);
    t.IngestGetHeightResponse(5000);
    t.IngestKeepaliveAck(5000, 200, 300, 50, 0);
    t.IngestSessionStatusAck(true, true, false, false, 1800);
    t.IngestPushNotification(5001, 201);
    auto snap = t.GetSnapshot();
    print_test_result("canonical initialized",       snap.canonical.is_initialized());
    print_test_result("get_height initialized",      snap.get_height.is_initialized());
    print_test_result("shadow initialized",          snap.shadow.is_initialized());
    print_test_result("session_health initialized",  snap.session_health.is_initialized());
    print_test_result("push_trend initialized",      snap.push_trend.is_initialized());
    print_test_result("any_source_initialized",      snap.any_source_initialized());
    print_test_result("cross_check present",         snap.cross_check.canonical_initialized);
    print_test_result("get_height.unified == 5000",  snap.get_height.unified_height == 5000);
}

// ============================================================================
// Test 15: Reset clears all state
// ============================================================================
void test_reset_clears_all_state() {
    std::cout << "\nTest 15: Reset clears all state including get_height\n";
    ChannelHeightShadowTracker t;
    t.IngestBlockData(5000, 200);
    t.IngestGetHeightResponse(5000);
    t.IngestKeepaliveAck(5000, 200, 300, 50, 7);
    t.IngestSessionStatusAck(true, true, false, false, 3600);
    t.IngestPushNotification(5001, 201);
    t.Reset();
    auto snap = t.GetSnapshot();
    print_test_result("canonical cleared",      !snap.canonical.is_initialized());
    print_test_result("get_height cleared",     !snap.get_height.is_initialized());
    print_test_result("shadow cleared",         !snap.shadow.is_initialized());
    print_test_result("session_health cleared", !snap.session_health.is_initialized());
    print_test_result("push_trend cleared",     !snap.push_trend.is_initialized());
    print_test_result("canonical unified 0",    snap.canonical.unified_height == 0);
    print_test_result("get_height unified 0",   snap.get_height.unified_height == 0);
    print_test_result("shadow unified 0",       snap.shadow.unified_height == 0);
    print_test_result("shadow fork_score 0",    snap.shadow.fork_score == 0);
    print_test_result("peak_fork_score 0",      snap.shadow.peak_fork_score == 0);
}

// ============================================================================
// Test 16: SESSION_STATUS_ACK: no heights ingested (protocol-correct)
// ============================================================================
void test_session_status_ack_no_heights() {
    std::cout << "\nTest 16: SESSION_STATUS_ACK: no heights ingested (protocol-correct)\n";
    ChannelHeightShadowTracker t;
    // Ingest a healthy session status with simlink active
    t.IngestSessionStatusAck(true, true, true, true, 9999);
    auto snap = t.GetSnapshot();
    // Canonical must remain zero — SESSION_STATUS_ACK carries no heights
    print_test_result("canonical.unified_height == 0",        snap.canonical.unified_height == 0);
    print_test_result("canonical.mined_channel_height == 0",  snap.canonical.mined_channel_height == 0);
    print_test_result("shadow.unified_height == 0",           snap.shadow.unified_height == 0);
    print_test_result("shadow.prime_height == 0",             snap.shadow.prime_height == 0);
    print_test_result("shadow.hash_height == 0",              snap.shadow.hash_height == 0);
    print_test_result("shadow.stake_height == 0",             snap.shadow.stake_height == 0);
    print_test_result("push_trend.unified_height == 0",       snap.push_trend.unified_height == 0);
    // Health fields should be set correctly
    print_test_result("session_health.is_authenticated",      snap.session_health.is_authenticated);
    print_test_result("session_health.primary_lane_alive",    snap.session_health.primary_lane_alive);
    print_test_result("session_health.simlink_active",        snap.session_health.simlink_active);
    print_test_result("session_health.uptime_seconds 9999",   snap.session_health.uptime_seconds == 9999);
}

// ============================================================================
// Test 17: source_name() returns correct strings
// ============================================================================
void test_source_name() {
    std::cout << "\nTest 17: source_name() returns correct strings for all SourceKinds\n";
    using SK = ChannelHeightShadowTracker::SourceKind;
    print_test_result("NONE == \"NONE\"",
        std::string(ChannelHeightShadowTracker::source_name(SK::NONE)) == "NONE");
    print_test_result("BLOCK_DATA == \"BLOCK_DATA\"",
        std::string(ChannelHeightShadowTracker::source_name(SK::BLOCK_DATA)) == "BLOCK_DATA");
    print_test_result("GET_HEIGHT == \"GET_HEIGHT\"",
        std::string(ChannelHeightShadowTracker::source_name(SK::GET_HEIGHT)) == "GET_HEIGHT");
    print_test_result("KEEPALIVE == \"KEEPALIVE\"",
        std::string(ChannelHeightShadowTracker::source_name(SK::KEEPALIVE)) == "KEEPALIVE");
    print_test_result("SESSION_STATUS == \"SESSION_STATUS\"",
        std::string(ChannelHeightShadowTracker::source_name(SK::SESSION_STATUS)) == "SESSION_STATUS");
    print_test_result("PUSH == \"PUSH\"",
        std::string(ChannelHeightShadowTracker::source_name(SK::PUSH)) == "PUSH");
}

// ============================================================================
// Test 18: CrossCheckResult::describe() produces non-empty string
// ============================================================================
void test_describe_non_empty() {
    std::cout << "\nTest 18: CrossCheckResult::describe() produces non-empty string\n";
    ChannelHeightShadowTracker t;
    t.IngestBlockData(5000, 200);
    t.IngestKeepaliveAck(5000, 200, 300, 50, 0);
    auto r = t.CrossCheck();
    auto s = r.describe();
    print_test_result("describe() non-empty", !s.empty());
    print_test_result("describe() contains 'canonical'",
                      s.find("canonical") != std::string::npos);
    print_test_result("describe() contains 'shadow'",
                      s.find("shadow") != std::string::npos);
}

// ============================================================================
// Test 19: IsShadowStale() true before any keepalive ACK
// ============================================================================
void test_is_shadow_stale_before_ingest() {
    std::cout << "\nTest 19: IsShadowStale() returns true before any keepalive ACK\n";
    ChannelHeightShadowTracker t;
    print_test_result("IsShadowStale() == true initially", t.IsShadowStale());
    t.IngestKeepaliveAck(5000, 200, 300, 50, 0);
    print_test_result("IsShadowStale() == false after fresh keepalive", !t.IsShadowStale());
}

// ============================================================================
// Test 20: IsSessionHealthStale() true before any SESSION_STATUS_ACK
// ============================================================================
void test_is_session_health_stale_before_ingest() {
    std::cout << "\nTest 20: IsSessionHealthStale() returns true before any SESSION_STATUS_ACK\n";
    ChannelHeightShadowTracker t;
    print_test_result("IsSessionHealthStale() == true initially", t.IsSessionHealthStale());
    t.IngestSessionStatusAck(true, true, false, false, 1234);
    print_test_result("IsSessionHealthStale() == false after fresh ACK", !t.IsSessionHealthStale());
}

// ============================================================================
// Test 21: most_recent_source tracks last ingested source
// ============================================================================
void test_most_recent_source_tracking() {
    std::cout << "\nTest 21: most_recent_source tracks the last ingested source correctly\n";
    using SK = ChannelHeightShadowTracker::SourceKind;
    ChannelHeightShadowTracker t;

    t.IngestBlockData(5000, 200);
    print_test_result("after BLOCK_DATA: last_src == BLOCK_DATA",
                      t.CrossCheck().most_recent_source == SK::BLOCK_DATA);

    t.IngestGetHeightResponse(5000);
    print_test_result("after GET_HEIGHT: last_src == GET_HEIGHT",
                      t.CrossCheck().most_recent_source == SK::GET_HEIGHT);

    t.IngestKeepaliveAck(5000, 200, 300, 50, 0);
    print_test_result("after KEEPALIVE: last_src == KEEPALIVE",
                      t.CrossCheck().most_recent_source == SK::KEEPALIVE);

    t.IngestSessionStatusAck(true, true, false, false, 100);
    print_test_result("after SESSION_STATUS: last_src == SESSION_STATUS",
                      t.CrossCheck().most_recent_source == SK::SESSION_STATUS);

    t.IngestPushNotification(5001, 201);
    print_test_result("after PUSH: last_src == PUSH",
                      t.CrossCheck().most_recent_source == SK::PUSH);
}

// ============================================================================
// Test 22: Canonical unified and mined_channel advance independently and monotonically
// ============================================================================
void test_canonical_independent_monotonic() {
    std::cout << "\nTest 22: Canonical unified and mined_channel advance independently\n";
    ChannelHeightShadowTracker t;
    t.IngestBlockData(5000, 200);
    t.IngestBlockData(5001, 200);  // unified advances, channel same
    auto snap = t.GetSnapshot();
    print_test_result("unified advanced to 5001",  snap.canonical.unified_height == 5001);
    print_test_result("channel stays at 200",      snap.canonical.mined_channel_height == 200);
    t.IngestBlockData(5001, 201);  // unified same, channel advances
    snap = t.GetSnapshot();
    print_test_result("unified stays at 5001",     snap.canonical.unified_height == 5001);
    print_test_result("channel advanced to 201",   snap.canonical.mined_channel_height == 201);
}

// ============================================================================
// Test 23: Shadow prime/hash/stake all captured correctly
// ============================================================================
void test_shadow_all_channels_captured() {
    std::cout << "\nTest 23: Shadow prime/hash/stake all captured correctly from keepalive\n";
    ChannelHeightShadowTracker t;
    t.IngestKeepaliveAck(7000, 350, 420, 90, 0);
    auto snap = t.GetSnapshot();
    print_test_result("shadow.unified_height == 7000", snap.shadow.unified_height == 7000);
    print_test_result("shadow.prime_height == 350",    snap.shadow.prime_height == 350);
    print_test_result("shadow.hash_height == 420",     snap.shadow.hash_height == 420);
    print_test_result("shadow.stake_height == 90",     snap.shadow.stake_height == 90);
}

// ============================================================================
// Test 24: CrossCheck::is_disagreement() respects tolerance
// ============================================================================
void test_cross_check_tolerance() {
    std::cout << "\nTest 24: CrossCheck::is_disagreement() respects tolerance parameter (keepalive fallback)\n";
    ChannelHeightShadowTracker t;
    t.IngestBlockData(5003, 200);
    t.IngestKeepaliveAck(5000, 200, 300, 50, 0);  // delta = 3; no GET_HEIGHT — fallback to keepalive
    auto r = t.CrossCheck();
    print_test_result("delta == 3",                   r.unified_delta == 3);
    print_test_result("is_disagreement(0) == true",   r.is_disagreement(0));
    print_test_result("is_disagreement(2) == true",   r.is_disagreement(2));
    print_test_result("is_disagreement(3) == false",  !r.is_disagreement(3));
    print_test_result("is_disagreement(10) == false", !r.is_disagreement(10));
}

// ============================================================================
// Test 25: Multiple sources — snapshot shows consistent combined state
// ============================================================================
void test_multiple_sources_consistent_snapshot() {
    std::cout << "\nTest 25: Multiple sources — snapshot shows consistent combined state\n";
    ChannelHeightShadowTracker t;
    t.IngestBlockData(5000, 200);
    t.IngestKeepaliveAck(5000, 200, 300, 50, 0);
    t.IngestSessionStatusAck(true, true, false, false, 1800);
    t.IngestPushNotification(5001, 201);
    auto snap = t.GetSnapshot();
    // Canonical
    print_test_result("canonical.unified_height == 5000",     snap.canonical.unified_height == 5000);
    print_test_result("canonical.mined_channel == 200",       snap.canonical.mined_channel_height == 200);
    // Shadow
    print_test_result("shadow.unified_height == 5000",        snap.shadow.unified_height == 5000);
    print_test_result("shadow.prime_height == 200",           snap.shadow.prime_height == 200);
    print_test_result("shadow.hash_height == 300",            snap.shadow.hash_height == 300);
    print_test_result("shadow.stake_height == 50",            snap.shadow.stake_height == 50);
    // Session health
    print_test_result("session_health.is_authenticated",      snap.session_health.is_authenticated);
    print_test_result("session_health.uptime_seconds == 1800",snap.session_health.uptime_seconds == 1800);
    // Push trend
    print_test_result("push_trend.unified_height == 5001",    snap.push_trend.unified_height == 5001);
    print_test_result("push_trend.channel_height == 201",     snap.push_trend.channel_height == 201);
    // Cross-check (keepalive path since no GET_HEIGHT)
    print_test_result("cross_check agrees",                   snap.cross_check.unified_heights_agree);
    print_test_result("cross_check delta == 0",               snap.cross_check.unified_delta == 0);
    print_test_result("no fork detected",                     !snap.cross_check.fork_detected);
}

// ============================================================================
// Test 26: IngestGetHeightResponse updates get_height only; no spillover
// ============================================================================
void test_ingest_get_height_response_layer_isolation() {
    std::cout << "\nTest 26: IngestGetHeightResponse updates get_height only; no spillover\n";
    ChannelHeightShadowTracker t;
    t.IngestGetHeightResponse(6000);
    auto snap = t.GetSnapshot();
    print_test_result("get_height.initialized == true",       snap.get_height.is_initialized());
    print_test_result("get_height.unified_height == 6000",    snap.get_height.unified_height == 6000);
    // No spillover to other layers
    print_test_result("canonical.initialized == false",       !snap.canonical.is_initialized());
    print_test_result("canonical.unified_height == 0",        snap.canonical.unified_height == 0);
    print_test_result("shadow.initialized == false",          !snap.shadow.is_initialized());
    print_test_result("shadow.unified_height == 0",           snap.shadow.unified_height == 0);
    print_test_result("session_health.initialized == false",  !snap.session_health.is_initialized());
    print_test_result("push_trend.initialized == false",      !snap.push_trend.is_initialized());
    print_test_result("any_source_initialized == true",       snap.any_source_initialized());
}

// ============================================================================
// Test 27: GetHeightState unified_height stored and overwritten correctly
// ============================================================================
void test_get_height_state_values() {
    std::cout << "\nTest 27: GetHeightState: unified_height stored and overwritten correctly\n";
    ChannelHeightShadowTracker t;
    t.IngestGetHeightResponse(6000);
    auto snap = t.GetSnapshot();
    print_test_result("first response: unified_height == 6000", snap.get_height.unified_height == 6000);
    // New response overwrites old (not monotonic — node can report any height)
    t.IngestGetHeightResponse(5999);
    snap = t.GetSnapshot();
    print_test_result("second response (lower): unified_height == 5999", snap.get_height.unified_height == 5999);
    t.IngestGetHeightResponse(6001);
    snap = t.GetSnapshot();
    print_test_result("third response (higher): unified_height == 6001", snap.get_height.unified_height == 6001);
}

// ============================================================================
// Test 28: IsGetHeightStale() true before any GET_HEIGHT response
// ============================================================================
void test_is_get_height_stale_before_ingest() {
    std::cout << "\nTest 28: IsGetHeightStale() returns true before any GET_HEIGHT response\n";
    ChannelHeightShadowTracker t;
    print_test_result("IsGetHeightStale() == true initially", t.IsGetHeightStale());
    t.IngestGetHeightResponse(6000);
    print_test_result("IsGetHeightStale() == false after fresh response", !t.IsGetHeightStale());
}

// ============================================================================
// Test 29: CrossCheck primary path: GET_HEIGHT disagreement when present
// ============================================================================
void test_cross_check_get_height_primary_path() {
    std::cout << "\nTest 29: CrossCheck primary: GET_HEIGHT disagreement detected when present\n";
    ChannelHeightShadowTracker t;
    t.IngestBlockData(5005, 200);
    // GET_HEIGHT says 5000 (5 behind canonical) — this is the primary path
    t.IngestGetHeightResponse(5000);
    auto r = t.CrossCheck();
    // GET_HEIGHT primary fields
    print_test_result("get_height_initialized == true",         r.get_height_initialized);
    print_test_result("get_height_is_stale == false",           !r.get_height_is_stale);
    print_test_result("get_height_delta == 5",                  r.get_height_delta == 5);
    print_test_result("get_height_leads_canonical == false",    !r.get_height_leads_canonical);
    print_test_result("canonical_leads_get_height == true",     r.canonical_leads_get_height);
    // is_disagreement uses GET_HEIGHT as primary since it's fresh
    print_test_result("is_disagreement(1) via GET_HEIGHT",      r.is_disagreement(1));
    print_test_result("is_disagreement(5) == false",            !r.is_disagreement(5));
    print_test_result("is_disagreement(4) == true",             r.is_disagreement(4));
}

// ============================================================================
// Test 30: CrossCheck priority: GET_HEIGHT primary overrides keepalive when both present
// ============================================================================
void test_cross_check_get_height_overrides_keepalive() {
    std::cout << "\nTest 30: CrossCheck priority: GET_HEIGHT primary overrides keepalive\n";
    ChannelHeightShadowTracker t;
    // Canonical = 5005
    t.IngestBlockData(5005, 200);
    // Keepalive says 5000 (delta 5) — would be is_disagreement(4) = true via keepalive
    t.IngestKeepaliveAck(5000, 200, 300, 50, 0);
    // GET_HEIGHT says 5005 (delta 0) — agrees with canonical, should override
    t.IngestGetHeightResponse(5005);
    auto r = t.CrossCheck();
    // GET_HEIGHT is primary since both are fresh
    print_test_result("get_height_delta == 0 (agrees)",         r.get_height_delta == 0);
    print_test_result("get_height_agrees == true",              r.get_height_agrees);
    // is_disagreement prefers GET_HEIGHT which says 0 → not a disagreement
    print_test_result("is_disagreement(1) == false (GET_HEIGHT primary)", !r.is_disagreement(1));
    // Keepalive fields still show the discrepancy (independent layer)
    print_test_result("keepalive unified_delta == 5",           r.unified_delta == 5);
    print_test_result("keepalive shadow_initialized == true",   r.shadow_initialized);
}

// ============================================================================
// main
// ============================================================================
int main() {
    std::cout << "=== ChannelHeightShadowTracker Unit Tests ===\n";

    test_fresh_tracker_uninitialized();
    test_ingest_block_data_canonical_only();
    test_ingest_block_data_monotonic();
    test_ingest_keepalive_ack_shadow_only();
    test_ingest_session_status_health_only();
    test_ingest_push_trend_only();
    test_cross_check_agrees_when_equal();
    test_cross_check_disagreement_detected();
    test_cross_check_no_disagreement_when_stale();
    test_cross_check_shadow_leads();
    test_cross_check_canonical_leads();
    test_cross_check_fork_detected();
    test_fork_canary_persists();
    test_get_snapshot_all_layers();
    test_reset_clears_all_state();
    test_session_status_ack_no_heights();
    test_source_name();
    test_describe_non_empty();
    test_is_shadow_stale_before_ingest();
    test_is_session_health_stale_before_ingest();
    test_most_recent_source_tracking();
    test_canonical_independent_monotonic();
    test_shadow_all_channels_captured();
    test_cross_check_tolerance();
    test_multiple_sources_consistent_snapshot();
    // New GET_HEIGHT tests
    test_ingest_get_height_response_layer_isolation();
    test_get_height_state_values();
    test_is_get_height_stale_before_ingest();
    test_cross_check_get_height_primary_path();
    test_cross_check_get_height_overrides_keepalive();

    std::cout << "\n=== Results: " << tests_passed << "/" << tests_run
              << " passed, " << tests_failed << " failed ===\n";
    return tests_failed > 0 ? 1 : 0;
}
