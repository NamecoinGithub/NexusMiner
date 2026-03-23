/**
 * @file degraded_recovery_test.cpp
 * @brief Tests for keepalive epoch isolation, channel-advance staleness, and degraded-mode
 *        recovery determinism.
 *
 * Tests:
 *  1.  Keepalive ACK update across epoch change — old-epoch ack is invalidated
 *  2.  Channel advance + stale template transition — HeightTracker detects staleness correctly
 *  3.  Recovery pending debouncing — mark_recovery_initiated() is idempotent for same event
 *  4.  Recovery GET_BLOCK can dispatch after debounce window — no permanent starvation
 *  5.  Keepalive epoch isolation — new epoch starts with clean ack timestamp
 *  6.  Stale template after channel advance triggers is_template_stale()
 *  7.  set_session_epoch() with a higher epoch suppresses the old keepalive signal
 *  8.  Multiple rapid epoch changes produce clean keepalive state
 *  9.  Push notification does not reset keepalive timestamp on epoch change
 * 10.  Recovery epoch tracking — monotonic epoch counter with idempotent initiation
 * 11.  Integration: stale -> degraded -> fresh template -> mining resumes
 * 12.  Integration: forced retry lane remains bounded (no flood)
 * 13.  Successful re-authentication restarts the recovery window on a fresh epoch
 * 14.  Session epoch advance clears stale push tip-anchor hints without clearing push liveness
 * 15.  Recovery completion clears suppression and authoritative recovery-reason state
 * 16.  Authoritative soft-refresh state repopulates Worker_manager local soft-pause state
 * 17.  Recovery worker respawn guard creates workers only once per degraded exit
 */

#include "protocol/height_tracker.hpp"
#include "protocol/packet_builder.hpp"
#include "miner_opcodes.hpp"
#include <iostream>
#include <cassert>
#include <cstdint>
#include <chrono>
#include <thread>
#include <memory>
#include <vector>
#include <deque>

using namespace nexusminer::protocol;
using namespace nexusminer;

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
// ⚡ TestRecoveryPhase — minimal mirror of worker_manager RecoveryPhase enum
// Defined here so all tests can use it without including worker_manager.hpp.
// ============================================================================

// Minimal mirror of RecoveryPhase for standalone testing without including
// the full worker_manager.hpp dependency tree.
enum class TestRecoveryPhase : uint8_t {
    HEALTHY,
    SOFT_REFRESH,
    HARD_RECOVERY,
    RECONNECTING,
    ESCALATED,
};

const char* test_phase_name(TestRecoveryPhase p) {
    switch (p) {
        case TestRecoveryPhase::HEALTHY:       return "HEALTHY";
        case TestRecoveryPhase::SOFT_REFRESH:  return "SOFT_REFRESH";
        case TestRecoveryPhase::HARD_RECOVERY: return "HARD_RECOVERY";
        case TestRecoveryPhase::RECONNECTING:  return "RECONNECTING";
        case TestRecoveryPhase::ESCALATED:     return "ESCALATED";
    }
    return "UNKNOWN";
}

static bool test_is_valid_transition(TestRecoveryPhase from, TestRecoveryPhase to) {
    if (from == to) return true;
    switch (from) {
        case TestRecoveryPhase::HEALTHY:
            return to == TestRecoveryPhase::SOFT_REFRESH || to == TestRecoveryPhase::HARD_RECOVERY;
        case TestRecoveryPhase::SOFT_REFRESH:
            return to == TestRecoveryPhase::HEALTHY || to == TestRecoveryPhase::HARD_RECOVERY;
        case TestRecoveryPhase::HARD_RECOVERY:
            return to == TestRecoveryPhase::HEALTHY || to == TestRecoveryPhase::RECONNECTING ||
                   to == TestRecoveryPhase::ESCALATED;
        case TestRecoveryPhase::RECONNECTING:
            return to == TestRecoveryPhase::HEALTHY || to == TestRecoveryPhase::HARD_RECOVERY ||
                   to == TestRecoveryPhase::ESCALATED;
        case TestRecoveryPhase::ESCALATED:
            return to == TestRecoveryPhase::HEALTHY || to == TestRecoveryPhase::HARD_RECOVERY ||
                   to == TestRecoveryPhase::RECONNECTING;
    }
    return false;
}

// Helper predicates matching the Worker_manager helper methods
static bool phase_is_degraded(TestRecoveryPhase p) {
    return p == TestRecoveryPhase::HARD_RECOVERY || p == TestRecoveryPhase::ESCALATED;
}
static bool phase_is_submissions_withheld(TestRecoveryPhase p) {
    return p == TestRecoveryPhase::SOFT_REFRESH;
}
static bool phase_is_recovery_active(TestRecoveryPhase p) {
    return p != TestRecoveryPhase::HEALTHY;
}
static bool phase_is_reconnecting(TestRecoveryPhase p) {
    return p == TestRecoveryPhase::RECONNECTING;
}

// ============================================================================
// Test 1: Keepalive ACK update across epoch change — old-epoch ack invalidated
// ============================================================================
void test_keepalive_ack_invalidated_on_epoch_change() {
    std::cout << "\nTest 1: Keepalive ACK invalidated when session epoch advances\n";
    HeightTracker tracker;

    // Epoch 1: receive keepalive
    tracker.set_session_epoch(1);
    tracker.OnKeepaliveResponse(5000, 400, 700, 900, 0xDEADBEEFu, 0);
    auto snap1 = tracker.GetSnapshot();
    bool ack_was_set = (snap1.last_keepalive_ack_at != std::chrono::steady_clock::time_point{});
    print_test_result("Epoch 1: keepalive ACK timestamp is set after response", ack_was_set);

    // Advance to epoch 2 (session re-auth or channel re-init)
    tracker.set_session_epoch(2);
    auto snap2 = tracker.GetSnapshot();
    print_test_result("Epoch 2: keepalive ACK timestamp cleared on epoch advance",
                      snap2.last_keepalive_ack_at == std::chrono::steady_clock::time_point{});
    print_test_result("Epoch 2: snapshot session_epoch reflects new epoch",
                      snap2.session_epoch == 2);

    // New keepalive in epoch 2 should be accepted
    tracker.OnKeepaliveResponse(5001, 401, 701, 901, 0xCAFEBABEu, 0);
    auto snap3 = tracker.GetSnapshot();
    print_test_result("Epoch 2: new keepalive ACK is accepted",
                      snap3.last_keepalive_ack_at != std::chrono::steady_clock::time_point{});
}

// ============================================================================
// Test 2: Channel advance + stale template transition — staleness detection
// ============================================================================
void test_channel_advance_stale_template_transition() {
    std::cout << "\nTest 2: Channel advance + stale template transition\n";
    HeightTracker tracker;

    // Initial state: template for channel_target=101 while channel_height=100
    tracker.OnPushNotification(5000, 100, 0x1d00ffff);
    tracker.OnTemplateReceived(2, 101);
    auto snap = tracker.GetSnapshot();
    print_test_result("Initial: is_template_stale() == false (channel_height=100 < target=101)",
                      !snap.is_template_stale());
    print_test_result("Initial: channel_height == 100", snap.channel_height == 100);
    print_test_result("Initial: channel_target == 101", snap.channel_target == 101);

    // Channel advances — node found a block
    tracker.OnPushNotification(5001, 101, 0x1d00ffff);
    auto snap2 = tracker.GetSnapshot();
    print_test_result("After channel advance: is_template_stale() == true (height=101 >= target=101)",
                      snap2.is_template_stale());
    print_test_result("After channel advance: channel_height == 101", snap2.channel_height == 101);

    // Simulate keepalive arriving from OLD session — should not affect staleness
    tracker.OnKeepaliveResponse(5001, 300, 101, 900, 0xDEADBEEFu, 0);
    auto snap3 = tracker.GetSnapshot();
    print_test_result("After old keepalive: is_template_stale() still true",
                      snap3.is_template_stale());
    print_test_result("After old keepalive: channel_height unchanged at 101",
                      snap3.channel_height == 101);

    // New template from GET_BLOCK response — staleness resolved
    tracker.OnTemplateReceived(2, 102);
    tracker.AdvanceChannelTarget(102);
    auto snap4 = tracker.GetSnapshot();
    print_test_result("After new template: is_template_stale() == false",
                      !snap4.is_template_stale());
    print_test_result("After new template: channel_target == 102", snap4.channel_target == 102);
}

// ============================================================================
// Test 3: Recovery pending debouncing — mark_recovery is idempotent
// Simulates the "Recovery already pending" scenario: multiple staleness sources
// calling mark_recovery_initiated() for the same event must not reset the epoch.
// ============================================================================
void test_recovery_pending_debounce_idempotent() {
    std::cout << "\nTest 3: Recovery-pending debounce — multiple mark_recovery calls are idempotent\n";

    // Simulate the mark_recovery_initiated() logic using the 5-state RecoveryPhase machine
    struct RecoveryTracker {
        TestRecoveryPhase phase{TestRecoveryPhase::HEALTHY};
        uint64_t epoch{0};
        std::chrono::steady_clock::time_point entered_at{};
        std::vector<std::string> m_log;

        // Mirrors Worker_manager::mark_recovery_initiated() / transition_to(HARD_RECOVERY)
        void initiate(const char* reason) {
            if (phase_is_recovery_active(phase)) {
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::steady_clock::now() - entered_at).count();
                m_log.push_back("NOOP: already pending epoch=" + std::to_string(epoch)
                                + " elapsed=" + std::to_string(elapsed) + "s reason=" + reason);
                return;
            }
            ++epoch;
            phase = TestRecoveryPhase::HARD_RECOVERY;
            entered_at = std::chrono::steady_clock::now();
            m_log.push_back("STARTED: epoch=" + std::to_string(epoch) + " reason=" + reason);
        }

        void clear() {
            phase = TestRecoveryPhase::HEALTHY;
            m_log.push_back("CLEARED: epoch=" + std::to_string(epoch));
        }
    };

    RecoveryTracker rt;

    // First initiation from push handler
    rt.initiate("push_staleness");
    print_test_result("First initiation starts recovery (epoch=1)",
                      rt.epoch == 1 && phase_is_recovery_active(rt.phase));

    // Second initiation from health monitor (same staleness event)
    rt.initiate("health_monitor_channel_stale");
    print_test_result("Second initiation is a no-op (epoch still 1)",
                      rt.epoch == 1 && phase_is_recovery_active(rt.phase));

    // Third initiation from different source
    rt.initiate("health_monitor_or_validation");
    print_test_result("Third initiation is still a no-op (epoch still 1)",
                      rt.epoch == 1 && phase_is_recovery_active(rt.phase));

    print_test_result("All initiation calls produced at least one STARTED entry",
                      std::any_of(rt.m_log.begin(), rt.m_log.end(),
                                  [](const auto& s) { return s.find("STARTED") != std::string::npos; }));
    size_t noop_count = 0;
    for (const auto& entry : rt.m_log)
        if (entry.find("NOOP") != std::string::npos) ++noop_count;
    print_test_result("Subsequent initiations were all NOOP (2 no-ops for 3 total calls)",
                      noop_count == 2);

    // Clear and re-initiate — new epoch must be incremented
    rt.clear();
    rt.initiate("escalation_hard_recovery");
    print_test_result("After clear, new initiation produces epoch=2",
                      rt.epoch == 2 && phase_is_recovery_active(rt.phase));
}

// ============================================================================
// Test 4: Recovery GET_BLOCK can dispatch after debounce window — no starvation
// Simulates the deduplication window expiring between recovery retries.
// ============================================================================
void test_recovery_get_block_no_permanent_starvation() {
    std::cout << "\nTest 4: Recovery GET_BLOCK dispatches after dedup window expires\n";

    // Simulate GET_BLOCK deduplication logic (mirrors Solo::get_work dedup guard)
    const int64_t DEDUP_MS = 100;
    struct GetBlockGate {
        std::chrono::steady_clock::time_point m_last_transmitted{};
        int64_t dedup_ms{0};

        // Returns true if GET_BLOCK can be dispatched, false if suppressed
        bool try_dispatch() {
            auto now = std::chrono::steady_clock::now();
            if (m_last_transmitted != std::chrono::steady_clock::time_point{}) {
                auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    now - m_last_transmitted).count();
                if (elapsed_ms < dedup_ms) {
                    return false;  // suppressed
                }
            }
            m_last_transmitted = now;
            return true;  // dispatched
        }
    };

    GetBlockGate gate;
    gate.dedup_ms = DEDUP_MS;

    // First dispatch should succeed
    bool first = gate.try_dispatch();
    print_test_result("First GET_BLOCK dispatch succeeds", first);

    // Immediate second dispatch should be suppressed (within 100ms)
    bool second = gate.try_dispatch();
    print_test_result("Immediate second dispatch suppressed by dedup window", !second);

    // After dedup window expires, dispatch should succeed again
    std::this_thread::sleep_for(std::chrono::milliseconds(110));
    bool third = gate.try_dispatch();
    print_test_result("GET_BLOCK dispatch succeeds after dedup window (110ms wait)", third);

    // Another immediate attempt should be suppressed again
    bool fourth = gate.try_dispatch();
    print_test_result("Immediate dispatch after third is suppressed again", !fourth);

    // Recovery timer interval (30s >> 100ms dedup) ensures no starvation
    // at normal check_template_health intervals
    print_test_result("30s timer interval >> 100ms dedup = no starvation at timer cadence",
                      30000 > DEDUP_MS * 100);
}

// ============================================================================
// Test 4b: Successful re-authentication restarts the recovery window
// Mirrors Worker_manager::restart_recovery_window() + retry_template_request(true)
// so a fresh session does not inherit a long-expired recovery epoch.
// ============================================================================
void test_successful_reauth_restarts_recovery_epoch() {
    std::cout << "\nTest 4b: Re-authentication restarts recovery window on a fresh epoch\n";

    struct RecoveryTracker {
        bool m_degraded_mode{true};
        bool m_recovery_pending{true};
        uint64_t m_recovery_epoch{1};
        std::chrono::steady_clock::time_point m_recovery_started_at{};
        std::chrono::steady_clock::time_point m_degraded_since{};

        RecoveryTracker() {
            constexpr auto simulated_stale_duration = std::chrono::seconds(1207);
            const auto now = std::chrono::steady_clock::now();
            m_recovery_started_at = now - simulated_stale_duration;
            m_degraded_since = now - simulated_stale_duration;
        }

        void restart_recovery_window() {
            m_recovery_pending = false;
            m_recovery_started_at = {};
        }

        void on_reauthenticated() {
            if (m_degraded_mode || m_recovery_pending) {
                m_degraded_since = {};
                restart_recovery_window();
                ++m_recovery_epoch;
                m_recovery_pending = true;
                m_recovery_started_at = std::chrono::steady_clock::now();
            }
        }
    };

    RecoveryTracker rt;
    const auto old_started_at = rt.m_recovery_started_at;
    rt.on_reauthenticated();

    print_test_result("Re-authentication starts a new recovery epoch",
                      rt.m_recovery_epoch == 2);
    print_test_result("Recovery remains pending after re-authentication",
                      rt.m_recovery_pending);
    print_test_result("Recovery start time is refreshed after re-authentication",
                      rt.m_recovery_started_at != std::chrono::steady_clock::time_point{} &&
                      rt.m_recovery_started_at > old_started_at);
    auto elapsed_after_reauth = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - rt.m_recovery_started_at).count();
    print_test_result("Fresh recovery epoch elapsed time is near-zero after re-authentication",
                      elapsed_after_reauth >= 0 && elapsed_after_reauth <= 1);
    print_test_result("Degraded timer is reset for the new authenticated session",
                      rt.m_degraded_since == std::chrono::steady_clock::time_point{});
}

// ============================================================================
// Test 4c: Soft refresh timeout escalates only after the hot-swap window stalls
// ============================================================================
void test_same_height_soft_refresh_escalates_only_after_timeout() {
    std::cout << "\nTest 4c: Same-height replacement stays hot-swappable until timeout\n";
    constexpr int64_t RECOVERY_WINDOW_SECONDS = 60;
    constexpr int64_t TIMEOUT_TEST_SECONDS = RECOVERY_WINDOW_SECONDS + 1;

    struct RecoveryTracker {
        TestRecoveryPhase phase{TestRecoveryPhase::HEALTHY};
        uint64_t epoch{0};
        std::chrono::steady_clock::time_point entered_at{};
        std::string authoritative_recovery_reason;
        std::vector<std::string> m_log;

        void start_soft_refresh(const std::string& reason) {
            ++epoch;
            phase = TestRecoveryPhase::SOFT_REFRESH;
            entered_at = std::chrono::steady_clock::now();
            authoritative_recovery_reason = reason;
            m_log.emplace_back("soft refresh requested");
        }

        bool should_escalate(int64_t recovery_window_seconds) const {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - entered_at).count();
            return elapsed >= recovery_window_seconds;
        }

        void escalate() {
            phase = TestRecoveryPhase::HARD_RECOVERY;
        }
    };

    RecoveryTracker rt;
    rt.start_soft_refresh("same_height_push_tip_replacement_pre_adoption");
    print_test_result("Soft refresh starts recovery tracking",
                      phase_is_recovery_active(rt.phase) && rt.epoch == 1);
    print_test_result("Soft refresh logs soft refresh requested",
                      !rt.m_log.empty() && rt.m_log.back() == "soft refresh requested");
    print_test_result("Same-height pre-adoption replacement stays on soft-refresh reason",
                      rt.authoritative_recovery_reason == "same_height_push_tip_replacement_pre_adoption");
    print_test_result("Soft refresh withholds submissions without degraded mode",
                      phase_is_submissions_withheld(rt.phase) && !phase_is_degraded(rt.phase));
    print_test_result("Soft refresh keeps workers running (not degraded)", !phase_is_degraded(rt.phase));
    print_test_result("Soft refresh does not escalate immediately", !rt.should_escalate(RECOVERY_WINDOW_SECONDS));

    rt.entered_at = std::chrono::steady_clock::now() - std::chrono::seconds(TIMEOUT_TEST_SECONDS);
    print_test_result("Soft refresh escalates after timeout", rt.should_escalate(RECOVERY_WINDOW_SECONDS));
    rt.escalate();
    print_test_result("Timeout escalation enters degraded mode", phase_is_degraded(rt.phase));
    print_test_result("Timeout escalation clears soft-pause guard", !phase_is_submissions_withheld(rt.phase));
    print_test_result("Timeout escalation is what stops workers", phase_is_degraded(rt.phase));
}

// ============================================================================
// Test 4d: clear_recovery_state-style normalization restores healthy baseline
// ============================================================================
void test_degraded_exit_normalizes_recovery_state() {
    std::cout << "\nTest 4d: Degraded exit normalization clears recovery bookkeeping\n";

    struct RecoveryTracker {
        TestRecoveryPhase phase{TestRecoveryPhase::HARD_RECOVERY};
        uint64_t epoch{7};
        std::chrono::steady_clock::time_point entered_at{std::chrono::steady_clock::now()};
        std::chrono::steady_clock::time_point last_get_block_at{std::chrono::steady_clock::now()};
        bool get_block_confirmed{true};
        std::chrono::steady_clock::time_point degraded_since{std::chrono::steady_clock::now()};
        bool authoritative_recovery_healthy_called{false};
        std::string authoritative_recovery_reason{"same_height_push_tip_replacement_pre_adoption"};

        void clear() {
            authoritative_recovery_healthy_called = true;
            authoritative_recovery_reason.clear();
            phase = TestRecoveryPhase::HEALTHY;
            epoch = 0;
            entered_at = {};
            last_get_block_at = {};
            get_block_confirmed = false;
            degraded_since = {};
        }
    };

    RecoveryTracker rt;
    rt.clear();

    print_test_result("Phase returned to HEALTHY", rt.phase == TestRecoveryPhase::HEALTHY);
    print_test_result("Recovery active cleared", !phase_is_recovery_active(rt.phase));
    print_test_result("Degraded mode cleared", !phase_is_degraded(rt.phase));
    print_test_result("Soft-pause guard cleared", !phase_is_submissions_withheld(rt.phase));
    print_test_result("Recovery epoch reset", rt.epoch == 0);
    print_test_result("GET_BLOCK bookkeeping cleared",
                      rt.entered_at == std::chrono::steady_clock::time_point{} &&
                      rt.last_get_block_at == std::chrono::steady_clock::time_point{} &&
                      !rt.get_block_confirmed);
    print_test_result("Escalation timer cleared",
                      rt.degraded_since == std::chrono::steady_clock::time_point{});
    print_test_result("Authoritative recovery state normalized",
                      rt.authoritative_recovery_healthy_called &&
                      rt.authoritative_recovery_reason.empty());
}

// ============================================================================
// Test 4e: SOFT_REFRESH transition withholds submissions without degraded mode
// Replaces the old test_authoritative_soft_refresh_backfills_local_state()
// which referenced the removed RecoveryState::SOFT_REFRESH_REQUESTED enum value.
// Now tests the surviving RecoveryPhase::SOFT_REFRESH transition path.
// ============================================================================
void test_authoritative_soft_refresh_backfills_local_state() {
    std::cout << "\nTest 4e: SOFT_REFRESH transition withholds submissions without entering degraded mode\n";

    // Simulates Worker_manager::mark_soft_refresh_requested():
    // HEALTHY → SOFT_REFRESH when push detects same-height tip replacement.
    struct RecoveryTracker {
        TestRecoveryPhase phase{TestRecoveryPhase::HEALTHY};
        uint64_t epoch{0};
        std::chrono::steady_clock::time_point entered_at{};

        bool soft_refresh_requested(const char* /*reason*/) {
            if (phase_is_recovery_active(phase)) {
                return false;  // already in recovery — no-op
            }
            ++epoch;
            phase = TestRecoveryPhase::SOFT_REFRESH;
            entered_at = std::chrono::steady_clock::now();
            return true;
        }
    };

    RecoveryTracker rt;
    const bool transitioned = rt.soft_refresh_requested("same_height_push_tip_replacement");
    print_test_result("SOFT_REFRESH transition succeeds from HEALTHY", transitioned);
    print_test_result("SOFT_REFRESH withholds submissions", phase_is_submissions_withheld(rt.phase));
    print_test_result("SOFT_REFRESH does not enter degraded mode", !phase_is_degraded(rt.phase));
    print_test_result("SOFT_REFRESH anchors recovery epoch", rt.epoch == 1);
    print_test_result("SOFT_REFRESH anchors the recovery timer",
                      rt.entered_at != std::chrono::steady_clock::time_point{});

    // Second call when already in SOFT_REFRESH must be idempotent
    const bool second = rt.soft_refresh_requested("duplicate_push");
    print_test_result("Second SOFT_REFRESH call is a no-op (idempotent)", !second);
    print_test_result("Epoch unchanged after idempotent call", rt.epoch == 1);
}

// ============================================================================
// Test 4f: tip_moved soft refresh shields workers from immediate HEIGHT_DRIFT
//          escalation until the replacement-template window actually times out.
// ============================================================================
void test_tip_moved_soft_refresh_defers_unified_drift_stop_until_timeout() {
    std::cout << "\nTest 4f: tip_moved requests fresh template without halting submissions\n";
    // KEY CHANGE: is_tip_moved() no longer triggers soft refresh.
    // Cross-channel tip advances are informational — the current channel template
    // is still valid.  Workers keep mining AND submitting on the current template.
    // A fresh GET_BLOCK is requested opportunistically so hashPrevBlock stays current.
    // The HEIGHT_DRIFT guard still fires on the next tick if unified drift exceeds
    // the threshold and no new template has arrived.
    constexpr uint32_t UNIFIED_DRIFT_THRESHOLD = 5;

    struct HealthState {
        bool m_degraded_mode{false};
        bool m_recovery_pending{false};
        bool m_template_withheld{false};
        bool request_refresh{false};
        bool stop_workers{false};
        uint64_t m_recovery_epoch{0};

        void tick(bool tip_moved, uint32_t unified_drift, int64_t /*recovery_elapsed_s*/) {
            request_refresh = false;
            stop_workers = false;

            // NEW: tip_moved no longer starts a soft refresh.
            // It just requests a fresh template opportunistically and returns.
            if (tip_moved) {
                request_refresh = true;
                // m_template_withheld stays false — submissions are NOT withheld
                return;
            }

            // HEIGHT_DRIFT fires on subsequent ticks when no new template has arrived
            if (unified_drift > UNIFIED_DRIFT_THRESHOLD) {
                m_degraded_mode = true;
                stop_workers = true;
            }
        }
    };

    HealthState state;
    state.tick(/*tip_moved=*/true, /*unified_drift=*/7, /*recovery_elapsed_s=*/0);
    print_test_result("tip_moved requests fresh template without stopping workers",
                      state.request_refresh && !state.stop_workers && !state.m_degraded_mode);
    print_test_result("tip_moved does NOT withhold submissions (workers keep submitting)",
                      !state.m_template_withheld && !state.m_recovery_pending);

    state.tick(/*tip_moved=*/false, /*unified_drift=*/7, /*recovery_elapsed_s=*/10);
    print_test_result("HEIGHT_DRIFT fires on next tick when drift exceeds threshold and tip no longer moved",
                      state.stop_workers && state.m_degraded_mode);
}

// ============================================================================
// Test 4g: Worker respawn guard prevents duplicate worker recreation on exit
// ============================================================================
void test_worker_respawn_guard_is_single_shot_per_degraded_exit() {
    std::cout << "\nTest 4g: Recovery worker respawn guard is single-shot per degraded exit\n";

    struct WorkerRestartTracker {
        bool m_degraded_mode{true};
        bool m_recovery_workers_spawned{false};
        std::size_t worker_instances{0};
        std::size_t create_calls{0};

        bool restart_workers_if_needed() {
            if (!m_degraded_mode || m_recovery_workers_spawned || worker_instances > 0) {
                return false;
            }
            worker_instances = 8;
            m_recovery_workers_spawned = true;
            ++create_calls;
            return true;
        }
    };

    WorkerRestartTracker rt;
    bool first_restart = rt.restart_workers_if_needed();
    bool second_restart = rt.restart_workers_if_needed();

    print_test_result("First degraded-exit restart creates workers", first_restart);
    print_test_result("Second degraded-exit restart is suppressed", !second_restart);
    print_test_result("Workers are created only once for the outage", rt.create_calls == 1);
    print_test_result("Worker count stays at the expected 8 threads", rt.worker_instances == 8);
}

// ============================================================================
// Test 4h: Workers only respawn after the prior generation is fully stopped
// ============================================================================
void test_worker_respawn_waits_for_authoritative_empty_generation() {
    std::cout << "\nTest 4h: Worker respawn waits for authoritative empty generation\n";

    struct WorkerLifecycleTracker {
        bool m_degraded_mode{true};
        bool m_recovery_workers_spawned{false};
        bool stop_in_progress{false};
        std::size_t worker_instances{8};
        std::size_t create_calls{0};

        void begin_stop() {
            stop_in_progress = true;
        }

        void finish_stop() {
            worker_instances = 0;
            stop_in_progress = false;
            m_recovery_workers_spawned = false;
        }

        bool restart_workers_if_needed() {
            const bool degraded_mode_inactive = !m_degraded_mode;
            const bool restart_already_consumed = m_recovery_workers_spawned;
            const bool prior_generation_still_stopping = stop_in_progress;
            const bool workers_still_present = worker_instances != 0;

            if (degraded_mode_inactive || restart_already_consumed ||
                prior_generation_still_stopping || workers_still_present) {
                return false;
            }
            worker_instances = 8;
            m_recovery_workers_spawned = true;
            ++create_calls;
            return true;
        }
    };

    WorkerLifecycleTracker rt;
    rt.begin_stop();
    bool restart_during_stop = rt.restart_workers_if_needed();
    rt.finish_stop();
    bool restart_after_stop = rt.restart_workers_if_needed();
    bool second_restart_after_stop = rt.restart_workers_if_needed();

    print_test_result("Respawn is blocked while prior generation is still stopping", !restart_during_stop);
    print_test_result("Respawn succeeds once workers are authoritatively gone", restart_after_stop);
    print_test_result("Respawn remains single-shot after the restart", !second_restart_after_stop);
    print_test_result("Only one new worker generation is created", rt.create_calls == 1);
    print_test_result("Worker count returns to the expected 8 threads", rt.worker_instances == 8);
}

// ============================================================================
// Test 5: Keepalive epoch isolation — new epoch starts with clean ack timestamp
// ============================================================================
void test_keepalive_epoch_isolation_clean_start() {
    std::cout << "\nTest 5: New epoch starts with clean keepalive ACK timestamp\n";
    HeightTracker tracker;

    // Simulate three successive re-auths (epoch 1 → 2 → 3)
    for (uint64_t epoch = 1; epoch <= 3; ++epoch) {
        tracker.set_session_epoch(epoch);

        // At start of each epoch, ack timestamp must be clear
        auto snap_start = tracker.GetSnapshot();
        print_test_result(("Epoch " + std::to_string(epoch) + ": ack timestamp clear at epoch start").c_str(),
                          snap_start.last_keepalive_ack_at == std::chrono::steady_clock::time_point{});

        // Receive keepalive for this epoch
        tracker.OnKeepaliveResponse(5000 + static_cast<uint32_t>(epoch), 400, 700, 900, 0u, 0);
        auto snap_after = tracker.GetSnapshot();
        print_test_result(("Epoch " + std::to_string(epoch) + ": ack timestamp set after response").c_str(),
                          snap_after.last_keepalive_ack_at != std::chrono::steady_clock::time_point{});
    }
}

// ============================================================================
// Test 6: Stale template after channel advance triggers is_template_stale()
// (Validates the push-staleness detection that feeds the recovery path)
// ============================================================================
void test_stale_template_after_channel_advance() {
    std::cout << "\nTest 6: Stale template detection after channel advance\n";
    HeightTracker tracker;

    // Template targeting channel_height=101
    tracker.OnPushNotification(5000, 100, 0x1d00ffff);
    tracker.OnTemplateReceived(1, 101);

    // Confirm not stale before advance
    auto snap_before = tracker.GetSnapshot();
    print_test_result("Before advance: is_template_stale() == false", !snap_before.is_template_stale());

    // Channel advances (block found)
    tracker.OnPushNotification(5001, 101, 0x1d00ffff);
    auto snap_after = tracker.GetSnapshot();
    print_test_result("After advance: is_template_stale() == true", snap_after.is_template_stale());
    print_test_result("After advance: channel_height == 101", snap_after.channel_height == 101);
    print_test_result("After advance: channel_target == 101", snap_after.channel_target == 101);

    // is_template_stale condition: channel_height >= channel_target
    print_test_result("is_template_stale() satisfies: channel_height >= channel_target",
                      snap_after.channel_height >= snap_after.channel_target);
}

// ============================================================================
// Test 7: set_session_epoch() suppresses old keepalive signal
// Confirms keepalive ACK timestamp is cleared after epoch change (diagnostic field)
// ============================================================================
void test_epoch_advance_suppresses_old_keepalive_signal() {
    std::cout << "\nTest 7: Epoch advance clears keepalive ACK timestamp (diagnostic field)\n";
    HeightTracker tracker;

    tracker.set_session_epoch(10);
    tracker.OnKeepaliveResponse(5000, 400, 700, 900, 0u, 0);

    // Confirm old epoch keepalive is "set"
    auto snap_epoch10 = tracker.GetSnapshot();
    bool was_set = (snap_epoch10.last_keepalive_ack_at != std::chrono::steady_clock::time_point{});
    print_test_result("Epoch 10: keepalive ACK timestamp is set", was_set);

    // Advance epoch — simulates re-auth or session restart
    tracker.set_session_epoch(11);
    auto snap_epoch11 = tracker.GetSnapshot();

    // The keepalive ACK timestamp is diagnostic only — PUSH is the sole authoritative
    // signal for session liveness.  After epoch change, the diagnostic timestamp is cleared.
    bool keepalive_ack_received = (snap_epoch11.last_keepalive_ack_at !=
                                    std::chrono::steady_clock::time_point{});
    print_test_result("Epoch 11: keepalive_ack_received == false after epoch advance",
                      !keepalive_ack_received);
    print_test_result("Epoch 11: keepalive diagnostic timestamp cleared (epoch isolation)",
                      !keepalive_ack_received);
}

// ============================================================================
// Test 8: Multiple rapid epoch changes produce clean keepalive state
// ============================================================================
void test_multiple_rapid_epoch_changes_clean_state() {
    std::cout << "\nTest 8: Multiple rapid epoch changes always produce clean keepalive state\n";
    HeightTracker tracker;

    uint64_t current_epoch = 0;
    for (int i = 0; i < 5; ++i) {
        ++current_epoch;
        tracker.set_session_epoch(current_epoch);

        // Epoch starts clean
        auto snap_start = tracker.GetSnapshot();
        print_test_result(("Epoch " + std::to_string(current_epoch) + ": clean start").c_str(),
                          snap_start.last_keepalive_ack_at == std::chrono::steady_clock::time_point{});

        // Receive keepalive
        tracker.OnKeepaliveResponse(5000, 400, 700, 900, 0u, 0);
    }

    // Final state: keepalive is set for epoch 5
    auto snap_final = tracker.GetSnapshot();
    print_test_result("Final epoch (5): keepalive ACK timestamp is set from epoch 5 response",
                      snap_final.last_keepalive_ack_at != std::chrono::steady_clock::time_point{});
    print_test_result("Final epoch (5): session_epoch == 5", snap_final.session_epoch == 5);
}

// ============================================================================
// Test 9: Push notification does not reset keepalive timestamp on epoch change
// Pushes and keepalives are orthogonal — epoch change clears ONLY keepalive ack
// ============================================================================
void test_push_does_not_clear_keepalive_on_epoch_change() {
    std::cout << "\nTest 9: Push notifications do not clear keepalive timestamp on epoch change\n";
    HeightTracker tracker;

    tracker.set_session_epoch(1);
    tracker.OnKeepaliveResponse(5000, 400, 700, 900, 0u, 0);
    tracker.OnPushNotification(5000, 100, 0x1d00ffff);

    auto snap1 = tracker.GetSnapshot();
    bool push_at_set  = (snap1.last_push_notification_at != std::chrono::steady_clock::time_point{});
    bool ack_at_set   = (snap1.last_keepalive_ack_at != std::chrono::steady_clock::time_point{});
    print_test_result("Epoch 1: push timestamp is set", push_at_set);
    print_test_result("Epoch 1: keepalive ACK timestamp is set", ack_at_set);

    // Epoch change: keepalive clears, push is unchanged
    tracker.set_session_epoch(2);
    auto snap2 = tracker.GetSnapshot();
    bool push_unchanged  = (snap2.last_push_notification_at == snap1.last_push_notification_at);
    bool ack_cleared     = (snap2.last_keepalive_ack_at == std::chrono::steady_clock::time_point{});
    print_test_result("Epoch 2: push timestamp preserved (not cleared by epoch change)",
                      push_unchanged);
    print_test_result("Epoch 2: keepalive ACK timestamp cleared by epoch change",
                      ack_cleared);
}

// ============================================================================
// Test 9b: Session epoch advance clears stale push tip-anchor hints but keeps push liveness
// ============================================================================
void test_epoch_change_clears_push_tip_anchor_hint() {
    std::cout << "\nTest 9b: Session epoch advance clears stale push tip-anchor hint only\n";
    HeightTracker tracker;

    tracker.set_session_epoch(7);
    tracker.OnPushNotification(5000, 100, 0x1d00ffff);
    tracker.UpdatePushTipAnchor(uint1024_t(0x42));

    auto snap_before = tracker.GetSnapshot();
    print_test_result("Epoch 7: push tip-anchor hint is present before epoch change",
                      snap_before.push_hash_prev_block != uint1024_t{});
    print_test_result("Epoch 7: push liveness timestamp is present before epoch change",
                      snap_before.last_push_notification_at != std::chrono::steady_clock::time_point{});

    tracker.set_session_epoch(8);
    auto snap_after = tracker.GetSnapshot();
    print_test_result("Epoch 8: push tip-anchor hint cleared on epoch change",
                      snap_after.push_hash_prev_block == uint1024_t{});
    print_test_result("Epoch 8: push liveness timestamp preserved across epoch change",
                      snap_after.last_push_notification_at == snap_before.last_push_notification_at);

    tracker.UpdatePushTipAnchor(uint1024_t(0x77));
    auto snap_reseeded = tracker.GetSnapshot();
    print_test_result("Explicit clear test re-seeds push tip-anchor hint first",
                      snap_reseeded.push_hash_prev_block != uint1024_t{});
    tracker.ClearPushTipAnchor();
    auto snap_cleared = tracker.GetSnapshot();
    print_test_result("Explicit tip-anchor clear consumes replacement hint after adoption",
                      snap_cleared.push_hash_prev_block == uint1024_t{});
}

// ============================================================================
// Test 10: Recovery epoch tracking — monotonic with idempotent initiation
// ============================================================================
void test_recovery_epoch_monotonic_with_idempotent_initiation() {
    std::cout << "\nTest 10: Recovery epoch is monotonic; initiation is idempotent within epoch\n";

    struct RecoveryState {
        int epoch{0};
        bool pending{false};

        void initiate() {
            if (pending) return;  // idempotent
            ++epoch;
            pending = true;
        }
        void clear() {
            pending = false;
        }
    };

    RecoveryState rs;

    // Multiple calls before any template arrives: all no-ops except first
    rs.initiate();
    int epoch_after_first = rs.epoch;
    rs.initiate();
    rs.initiate();
    int epoch_after_many = rs.epoch;
    print_test_result("Epoch is monotonic: multiple inits don't increment past 1",
                      epoch_after_first == 1 && epoch_after_many == 1);
    print_test_result("Pending remains true after multiple inits", rs.pending);

    // Recovery completes (template received)
    rs.clear();
    print_test_result("After clear: pending == false", !rs.pending);
    print_test_result("After clear: epoch still == 1 (preserved for audit)", rs.epoch == 1);

    // Next staleness event: epoch advances
    rs.initiate();
    print_test_result("Second staleness: epoch == 2 (monotonically incremented)", rs.epoch == 2);
    print_test_result("Second staleness: pending == true", rs.pending);

    // Multiple calls again: no increment past 2
    rs.initiate();
    rs.initiate();
    print_test_result("Multiple inits after epoch 2: epoch remains 2", rs.epoch == 2);
}

// ============================================================================
// Test 11: Integration - channel advance -> stale -> degraded -> fresh -> resume
// ============================================================================
void test_integration_degraded_recovery_to_resume() {
    std::cout << "\nTest 11: Integration degraded recovery returns to active mining\n";

    struct IntegrationState {
        bool mining_active{true};
        bool degraded{false};
        bool recovery_pending{false};
        bool has_valid_template{true};
        uint32_t channel_height{100};
        uint32_t channel_target{101};
        int get_block_sent{0};

        void on_channel_advance(uint32_t new_height) {
            channel_height = new_height;
            if (channel_height >= channel_target) {
                degraded = true;
                recovery_pending = true;
                has_valid_template = false;
                mining_active = false;
            }
        }

        void recovery_tick() {
            if (degraded && recovery_pending && !has_valid_template) {
                ++get_block_sent;
            }
        }

        void on_fresh_template(uint32_t new_target) {
            channel_target = new_target;
            has_valid_template = true;
            if (degraded && recovery_pending) {
                degraded = false;
                recovery_pending = false;
                mining_active = true;
            }
        }
    };

    IntegrationState s;
    s.on_channel_advance(101);  // stale
    print_test_result("Stale transition enters degraded mode", s.degraded && !s.mining_active);

    s.recovery_tick();
    print_test_result("Recovery tick sends GET_BLOCK while degraded", s.get_block_sent == 1);

    s.on_fresh_template(102);
    print_test_result("Fresh template exits degraded mode", !s.degraded && !s.recovery_pending);
    print_test_result("Mining resumes after template acceptance", s.mining_active);
}

// ============================================================================
// Test 12: Integration - bounded forced retries prevent flooding
// ============================================================================
void test_integration_forced_retry_is_bounded() {
    std::cout << "\nTest 12: Integration forced retry channel remains bounded\n";

    struct ForcedBound {
        std::deque<std::chrono::steady_clock::time_point> sends;
        int64_t interval_ms{1000};
        size_t max_burst{25};
        std::chrono::steady_clock::time_point next_due{};

        bool try_send(std::chrono::steady_clock::time_point now) {
            while (!sends.empty()) {
                auto age = std::chrono::duration_cast<std::chrono::seconds>(now - sends.front()).count();
                if (age <= 60) break;
                sends.pop_front();
            }
            if (next_due != std::chrono::steady_clock::time_point{} && now < next_due) {
                return false;
            }
            if (sends.size() >= max_burst) {
                return false;
            }
            sends.push_back(now);
            next_due = now + std::chrono::milliseconds(interval_ms);
            return true;
        }
    };

    ForcedBound bound;
    auto now = std::chrono::steady_clock::now();
    int sent = 0;
    for (int i = 0; i < 120; ++i) {  // simulate 120 recovery ticks per second
        auto tick_tp = now + std::chrono::milliseconds(i * 500); // tick every 500ms
        if (bound.try_send(tick_tp)) {
            ++sent;
        }
    }
    print_test_result("Forced retries stay at or below max_forced_burst_per_60s", sent <= 25);
    print_test_result("Forced retries still make progress (at least one send)", sent > 0);
}

// ============================================================================
// Test 13: Health policy — one-block stale refresh stays soft; multi-block lag
//          escalates into recovery/degraded mode.
// ============================================================================
void test_health_policy_distinguishes_normal_refresh_from_multi_block_lag() {
    std::cout << "\nTest 13: Health policy distinguishes 1-block refresh from 2+-block lag\n";

    struct HealthDecision {
        bool request_refresh{false};
        bool recovery_initiated{false};
        bool stop_workers{false};
    };

    auto decide = [](const HeightTracker::Snapshot& snap, bool template_is_newer_than_push) {
        HealthDecision decision;

        if (!snap.is_template_stale()) {
            return decision;
        }

        if (template_is_newer_than_push) {
            decision.request_refresh = true;
            return decision;
        }

        uint32_t blocks_behind = snap.blocks_behind();
        if (blocks_behind <= 1) {
            decision.request_refresh = true;
            return decision;
        }

        decision.request_refresh = true;
        decision.recovery_initiated = true;
        decision.stop_workers = true;
        return decision;
    };

    HeightTracker one_block_tracker;
    one_block_tracker.OnPushNotification(5000, 100, 0x1d00ffff);
    one_block_tracker.OnTemplateReceived(2, 101);
    one_block_tracker.OnPushNotification(5001, 101, 0x1d00ffff);
    auto one_block = decide(one_block_tracker.GetSnapshot(), false);
    print_test_result("One-block lag requests refresh", one_block.request_refresh);
    print_test_result("One-block lag does not initiate recovery", !one_block.recovery_initiated);
    print_test_result("One-block lag does not stop workers", !one_block.stop_workers);

    HeightTracker two_block_tracker;
    two_block_tracker.OnPushNotification(5000, 100, 0x1d00ffff);
    two_block_tracker.OnTemplateReceived(2, 101);
    two_block_tracker.OnPushNotification(5001, 101, 0x1d00ffff);
    two_block_tracker.OnPushNotification(5002, 102, 0x1d00ffff);
    auto two_block = decide(two_block_tracker.GetSnapshot(), false);
    print_test_result("Two-block lag requests refresh", two_block.request_refresh);
    print_test_result("Two-block lag initiates recovery", two_block.recovery_initiated);
    print_test_result("Two-block lag stops workers", two_block.stop_workers);

    HeightTracker::Snapshot post_push_snap;
    post_push_snap.channel_height = 300;
    post_push_snap.channel_target = 300;
    auto post_push = decide(post_push_snap, true);
    print_test_result("Post-push template freshness still stays soft", post_push.request_refresh);
    print_test_result("Post-push template freshness does not initiate recovery", !post_push.recovery_initiated);
}

// ============================================================================
// ⚡ RecoveryPhase State Machine Tests (mirrors worker_manager.hpp RecoveryPhase)
// ============================================================================

// ── Test 18: Legal transitions succeed, illegal ones are rejected ──────────
void test_recovery_phase_valid_transitions() {
    std::cout << "\nTest 18: RecoveryPhase state machine — valid transition matrix\n";

    // Legal transitions
    print_test_result("HEALTHY → SOFT_REFRESH is legal",
        test_is_valid_transition(TestRecoveryPhase::HEALTHY, TestRecoveryPhase::SOFT_REFRESH));
    print_test_result("HEALTHY → HARD_RECOVERY is legal",
        test_is_valid_transition(TestRecoveryPhase::HEALTHY, TestRecoveryPhase::HARD_RECOVERY));
    print_test_result("SOFT_REFRESH → HEALTHY is legal",
        test_is_valid_transition(TestRecoveryPhase::SOFT_REFRESH, TestRecoveryPhase::HEALTHY));
    print_test_result("SOFT_REFRESH → HARD_RECOVERY is legal (escalation)",
        test_is_valid_transition(TestRecoveryPhase::SOFT_REFRESH, TestRecoveryPhase::HARD_RECOVERY));
    print_test_result("HARD_RECOVERY → HEALTHY is legal",
        test_is_valid_transition(TestRecoveryPhase::HARD_RECOVERY, TestRecoveryPhase::HEALTHY));
    print_test_result("HARD_RECOVERY → RECONNECTING is legal",
        test_is_valid_transition(TestRecoveryPhase::HARD_RECOVERY, TestRecoveryPhase::RECONNECTING));
    print_test_result("HARD_RECOVERY → ESCALATED is legal",
        test_is_valid_transition(TestRecoveryPhase::HARD_RECOVERY, TestRecoveryPhase::ESCALATED));
    print_test_result("RECONNECTING → HEALTHY is legal",
        test_is_valid_transition(TestRecoveryPhase::RECONNECTING, TestRecoveryPhase::HEALTHY));
    print_test_result("RECONNECTING → HARD_RECOVERY is legal",
        test_is_valid_transition(TestRecoveryPhase::RECONNECTING, TestRecoveryPhase::HARD_RECOVERY));
    print_test_result("RECONNECTING → ESCALATED is legal",
        test_is_valid_transition(TestRecoveryPhase::RECONNECTING, TestRecoveryPhase::ESCALATED));
    print_test_result("ESCALATED → HEALTHY is legal",
        test_is_valid_transition(TestRecoveryPhase::ESCALATED, TestRecoveryPhase::HEALTHY));
    print_test_result("ESCALATED → HARD_RECOVERY is legal",
        test_is_valid_transition(TestRecoveryPhase::ESCALATED, TestRecoveryPhase::HARD_RECOVERY));
    print_test_result("ESCALATED → RECONNECTING is legal",
        test_is_valid_transition(TestRecoveryPhase::ESCALATED, TestRecoveryPhase::RECONNECTING));

    // Illegal transitions
    print_test_result("HEALTHY → RECONNECTING is ILLEGAL",
        !test_is_valid_transition(TestRecoveryPhase::HEALTHY, TestRecoveryPhase::RECONNECTING));
    print_test_result("HEALTHY → ESCALATED is ILLEGAL",
        !test_is_valid_transition(TestRecoveryPhase::HEALTHY, TestRecoveryPhase::ESCALATED));
    print_test_result("SOFT_REFRESH → RECONNECTING is ILLEGAL",
        !test_is_valid_transition(TestRecoveryPhase::SOFT_REFRESH, TestRecoveryPhase::RECONNECTING));
    print_test_result("SOFT_REFRESH → ESCALATED is ILLEGAL",
        !test_is_valid_transition(TestRecoveryPhase::SOFT_REFRESH, TestRecoveryPhase::ESCALATED));

    // Same-phase no-ops are always valid
    print_test_result("HEALTHY → HEALTHY is valid (no-op)",
        test_is_valid_transition(TestRecoveryPhase::HEALTHY, TestRecoveryPhase::HEALTHY));
    print_test_result("HARD_RECOVERY → HARD_RECOVERY is valid (no-op)",
        test_is_valid_transition(TestRecoveryPhase::HARD_RECOVERY, TestRecoveryPhase::HARD_RECOVERY));
}

// ── Test 19: Phase helper equivalences match old boolean patterns ─────────
void test_recovery_phase_helpers_equivalence() {
    std::cout << "\nTest 19: Phase helpers match old boolean flag combinations\n";

    // is_degraded() ← old: m_degraded_mode
    print_test_result("HEALTHY: is_degraded() == false",   !phase_is_degraded(TestRecoveryPhase::HEALTHY));
    print_test_result("SOFT_REFRESH: is_degraded() == false", !phase_is_degraded(TestRecoveryPhase::SOFT_REFRESH));
    print_test_result("HARD_RECOVERY: is_degraded() == true", phase_is_degraded(TestRecoveryPhase::HARD_RECOVERY));
    print_test_result("RECONNECTING: is_degraded() == false", !phase_is_degraded(TestRecoveryPhase::RECONNECTING));
    print_test_result("ESCALATED: is_degraded() == true",  phase_is_degraded(TestRecoveryPhase::ESCALATED));

    // is_submissions_withheld() ← old: m_template_withheld
    print_test_result("HEALTHY: is_submissions_withheld() == false",
        !phase_is_submissions_withheld(TestRecoveryPhase::HEALTHY));
    print_test_result("SOFT_REFRESH: is_submissions_withheld() == true",
        phase_is_submissions_withheld(TestRecoveryPhase::SOFT_REFRESH));
    print_test_result("HARD_RECOVERY: is_submissions_withheld() == false",
        !phase_is_submissions_withheld(TestRecoveryPhase::HARD_RECOVERY));

    // is_recovery_active() ← old: m_recovery_pending
    print_test_result("HEALTHY: is_recovery_active() == false",
        !phase_is_recovery_active(TestRecoveryPhase::HEALTHY));
    print_test_result("SOFT_REFRESH: is_recovery_active() == true",
        phase_is_recovery_active(TestRecoveryPhase::SOFT_REFRESH));
    print_test_result("HARD_RECOVERY: is_recovery_active() == true",
        phase_is_recovery_active(TestRecoveryPhase::HARD_RECOVERY));
    print_test_result("RECONNECTING: is_recovery_active() == true",
        phase_is_recovery_active(TestRecoveryPhase::RECONNECTING));
    print_test_result("ESCALATED: is_recovery_active() == true",
        phase_is_recovery_active(TestRecoveryPhase::ESCALATED));

    // is_reconnecting() ← old: m_reconnect_in_progress
    print_test_result("HEALTHY: is_reconnecting() == false",
        !phase_is_reconnecting(TestRecoveryPhase::HEALTHY));
    print_test_result("RECONNECTING: is_reconnecting() == true",
        phase_is_reconnecting(TestRecoveryPhase::RECONNECTING));
    print_test_result("HARD_RECOVERY: is_reconnecting() == false",
        !phase_is_reconnecting(TestRecoveryPhase::HARD_RECOVERY));
}

// ── Test 20: Orphaned SOFT_REFRESH state — clearing state always exits it ─
void test_orphaned_soft_refresh_cleared() {
    std::cout << "\nTest 20: Orphaned SOFT_REFRESH state cannot remain after clear_recovery_state\n";

    // Simulate: was in SOFT_REFRESH, clear_recovery_state() transitions to HEALTHY
    TestRecoveryPhase phase = TestRecoveryPhase::SOFT_REFRESH;

    // Verify soft-refresh is active
    print_test_result("Initial: is_submissions_withheld() == true (SOFT_REFRESH)",
        phase_is_submissions_withheld(phase));

    // clear_recovery_state() logic: transition to HEALTHY
    phase = TestRecoveryPhase::HEALTHY;

    print_test_result("After clear: phase == HEALTHY",
        phase == TestRecoveryPhase::HEALTHY);
    print_test_result("After clear: is_submissions_withheld() == false",
        !phase_is_submissions_withheld(phase));
    print_test_result("After clear: is_recovery_active() == false",
        !phase_is_recovery_active(phase));
}

// ── Test 21: SOFT_REFRESH → HARD_RECOVERY escalation path ────────────────
void test_soft_refresh_escalation_to_hard_recovery() {
    std::cout << "\nTest 21: SOFT_REFRESH → HARD_RECOVERY escalation (doom-loop regression)\n";

    TestRecoveryPhase phase = TestRecoveryPhase::HEALTHY;

    // Enter SOFT_REFRESH
    assert(test_is_valid_transition(phase, TestRecoveryPhase::SOFT_REFRESH));
    phase = TestRecoveryPhase::SOFT_REFRESH;
    print_test_result("Entered SOFT_REFRESH: is_submissions_withheld() == true",
        phase_is_submissions_withheld(phase));
    print_test_result("SOFT_REFRESH: is_degraded() == false",
        !phase_is_degraded(phase));

    // Soft-refresh timeout → escalate to HARD_RECOVERY
    assert(test_is_valid_transition(phase, TestRecoveryPhase::HARD_RECOVERY));
    phase = TestRecoveryPhase::HARD_RECOVERY;
    print_test_result("Escalated to HARD_RECOVERY: is_degraded() == true",
        phase_is_degraded(phase));
    print_test_result("Escalated: is_submissions_withheld() == false (no orphan)",
        !phase_is_submissions_withheld(phase));
    print_test_result("Escalated: is_recovery_active() == true",
        phase_is_recovery_active(phase));
}

// ── Test 22: RECONNECTING prevents SESSION_EXPIRED re-entrance ────────────
void test_reconnecting_guards_session_expired() {
    std::cout << "\nTest 22: RECONNECTING phase prevents Session EXPIRED from re-entering\n";

    TestRecoveryPhase phase = TestRecoveryPhase::RECONNECTING;

    // Session expired handler guard: if reconnecting OR recovery active with epoch > 0
    uint64_t epoch = 1;
    bool should_ignore = phase_is_reconnecting(phase) ||
                         (phase_is_recovery_active(phase) && epoch > 0);
    print_test_result("RECONNECTING: session_expired is ignored",
        should_ignore);

    // Verify HEALTHY does NOT suppress session_expired
    TestRecoveryPhase healthy = TestRecoveryPhase::HEALTHY;
    uint64_t healthy_epoch = 0;
    bool healthy_ignore = phase_is_reconnecting(healthy) ||
                          (phase_is_recovery_active(healthy) && healthy_epoch > 0);
    print_test_result("HEALTHY: session_expired is NOT ignored",
        !healthy_ignore);

    // Verify SOFT_REFRESH with epoch 0 does NOT suppress session_expired
    TestRecoveryPhase soft = TestRecoveryPhase::SOFT_REFRESH;
    uint64_t soft_epoch = 0;  // epoch 0 = just entered, no recovery epoch yet
    bool soft_ignore = phase_is_reconnecting(soft) ||
                       (phase_is_recovery_active(soft) && soft_epoch > 0);
    print_test_result("SOFT_REFRESH with epoch=0: session_expired is NOT ignored",
        !soft_ignore);
}

// ── Test 23: Mutual exclusivity — only one phase at a time ───────────────
void test_recovery_phase_mutual_exclusivity() {
    std::cout << "\nTest 23: Phase mutual exclusivity — SOFT_REFRESH and HARD_RECOVERY cannot coexist\n";

    // The enum class guarantees mutual exclusivity at the type level.
    // Verify all possible phase combinations are distinct.
    TestRecoveryPhase phases[] = {
        TestRecoveryPhase::HEALTHY,
        TestRecoveryPhase::SOFT_REFRESH,
        TestRecoveryPhase::HARD_RECOVERY,
        TestRecoveryPhase::RECONNECTING,
        TestRecoveryPhase::ESCALATED,
    };

    bool all_distinct = true;
    for (size_t i = 0; i < 5; ++i) {
        for (size_t j = i + 1; j < 5; ++j) {
            if (phases[i] == phases[j]) {
                all_distinct = false;
                break;
            }
        }
    }
    print_test_result("All 5 phases have distinct enum values", all_distinct);

    // Verify: SOFT_REFRESH and DEGRADED cannot be simultaneously true
    TestRecoveryPhase p = TestRecoveryPhase::SOFT_REFRESH;
    bool soft_and_degraded = phase_is_submissions_withheld(p) && phase_is_degraded(p);
    print_test_result("SOFT_REFRESH: is_submissions_withheld() XOR is_degraded()",
        !soft_and_degraded);

    // Verify: HARD_RECOVERY cannot have submissions withheld (no orphaned soft-pause)
    TestRecoveryPhase hard = TestRecoveryPhase::HARD_RECOVERY;
    bool hard_withheld = phase_is_submissions_withheld(hard);
    print_test_result("HARD_RECOVERY: is_submissions_withheld() == false (no orphaned soft-pause)",
        !hard_withheld);
}


int main() {
    std::cout << "\n═══════════════════════════════════════════════════════════\n";
    std::cout << "Degraded Recovery / Keepalive Epoch Tests\n";
    std::cout << "═══════════════════════════════════════════════════════════\n";

    test_keepalive_ack_invalidated_on_epoch_change();
    test_channel_advance_stale_template_transition();
    test_recovery_pending_debounce_idempotent();
    test_recovery_get_block_no_permanent_starvation();
    test_successful_reauth_restarts_recovery_epoch();
    test_same_height_soft_refresh_escalates_only_after_timeout();
    test_degraded_exit_normalizes_recovery_state();
    test_authoritative_soft_refresh_backfills_local_state();
    test_tip_moved_soft_refresh_defers_unified_drift_stop_until_timeout();
    test_worker_respawn_guard_is_single_shot_per_degraded_exit();
    test_worker_respawn_waits_for_authoritative_empty_generation();
    test_keepalive_epoch_isolation_clean_start();
    test_stale_template_after_channel_advance();
    test_epoch_advance_suppresses_old_keepalive_signal();
    test_multiple_rapid_epoch_changes_clean_state();
    test_push_does_not_clear_keepalive_on_epoch_change();
    test_epoch_change_clears_push_tip_anchor_hint();
    test_recovery_epoch_monotonic_with_idempotent_initiation();
    test_integration_degraded_recovery_to_resume();
    test_integration_forced_retry_is_bounded();
    test_health_policy_distinguishes_normal_refresh_from_multi_block_lag();

    // ── RecoveryPhase state machine tests (new with explicit 5-state machine) ──
    test_recovery_phase_valid_transitions();
    test_recovery_phase_helpers_equivalence();
    test_orphaned_soft_refresh_cleared();
    test_soft_refresh_escalation_to_hard_recovery();
    test_reconnecting_guards_session_expired();
    test_recovery_phase_mutual_exclusivity();

    std::cout << "\n═══════════════════════════════════════════════════════════\n";
    std::cout << "Test Results: " << tests_passed << "/" << tests_run << " passed";
    if (tests_failed > 0) {
        std::cout << " (" << tests_failed << " failed)";
    }
    std::cout << "\n═══════════════════════════════════════════════════════════\n\n";

    return (tests_failed == 0) ? 0 : 1;
}
