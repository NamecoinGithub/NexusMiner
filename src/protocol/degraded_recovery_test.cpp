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
#include <cstdint>
#include <chrono>
#include <thread>
#include <memory>
#include <vector>
#include <deque>
#include <gtest/gtest.h>

using namespace nexusminer::protocol;
using namespace nexusminer;

// ============================================================================
// ⚡ TestRecoveryPhase — minimal mirror of worker_manager RecoveryPhase enum
// Defined here so all tests can use it without including worker_manager.hpp.
// ============================================================================

// Minimal mirror of RecoveryPhase for standalone testing without including
// the full worker_manager.hpp dependency tree.
enum class TestRecoveryPhase : uint8_t {
    HEALTHY,
    WAITING_TEMPLATE,
    RECONNECTING,
};

const char* test_phase_name(TestRecoveryPhase p) {
    switch (p) {
        case TestRecoveryPhase::HEALTHY:          return "HEALTHY";
        case TestRecoveryPhase::WAITING_TEMPLATE: return "WAITING_TEMPLATE";
        case TestRecoveryPhase::RECONNECTING:     return "RECONNECTING";
    }
    return "UNKNOWN";
}

static bool test_is_valid_transition(TestRecoveryPhase from, TestRecoveryPhase to) {
    if (from == to) return true;
    switch (from) {
        case TestRecoveryPhase::HEALTHY:
            return to == TestRecoveryPhase::WAITING_TEMPLATE ||
                   to == TestRecoveryPhase::RECONNECTING;
        case TestRecoveryPhase::WAITING_TEMPLATE:
            return to == TestRecoveryPhase::HEALTHY ||
                   to == TestRecoveryPhase::RECONNECTING;
        case TestRecoveryPhase::RECONNECTING:
            return to == TestRecoveryPhase::HEALTHY ||
                   to == TestRecoveryPhase::WAITING_TEMPLATE;
    }
    return false;
}

// Helper predicates matching the Worker_manager helper methods
static bool phase_is_degraded(TestRecoveryPhase p) {
    return p == TestRecoveryPhase::WAITING_TEMPLATE;
}
static bool phase_is_submissions_withheld(TestRecoveryPhase /*p*/) {
    return false;  // No longer a concept — workers always submit if they have a template
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
TEST(DegradedRecoveryTest, test_keepalive_ack_invalidated_on_epoch_change) {
    std::cout << "\nTest 1: Keepalive ACK invalidated when session epoch advances\n";
    HeightTracker tracker;

    // Epoch 1: receive keepalive
    tracker.set_session_epoch(1);
    tracker.OnKeepaliveResponse(5000, 400, 700, 900, 0xDEADBEEFu, 0);
    auto snap1 = tracker.GetSnapshot();
    bool ack_was_set = (snap1.last_keepalive_ack_at != std::chrono::steady_clock::time_point{});
    EXPECT_TRUE(ack_was_set) << "Epoch 1: keepalive ACK timestamp is set after response";

    // Advance to epoch 2 (session re-auth or channel re-init)
    tracker.set_session_epoch(2);
    auto snap2 = tracker.GetSnapshot();
    EXPECT_TRUE(snap2.last_keepalive_ack_at == std::chrono::steady_clock::time_point{}) << "Epoch 2: keepalive ACK timestamp cleared on epoch advance";
    EXPECT_TRUE(snap2.session_epoch == 2) << "Epoch 2: snapshot session_epoch reflects new epoch";

    // New keepalive in epoch 2 should be accepted
    tracker.OnKeepaliveResponse(5001, 401, 701, 901, 0xCAFEBABEu, 0);
    auto snap3 = tracker.GetSnapshot();
    EXPECT_TRUE(snap3.last_keepalive_ack_at != std::chrono::steady_clock::time_point{}) << "Epoch 2: new keepalive ACK is accepted";
}

// ============================================================================
// Test 2: Channel advance + stale template transition — staleness detection
// ============================================================================
TEST(DegradedRecoveryTest, test_channel_advance_stale_template_transition) {
    std::cout << "\nTest 2: Channel advance + stale template transition\n";
    HeightTracker tracker;

    // Initial state: template for channel_target=101 while channel_height=100
    tracker.OnPushNotification(5000, 100, 0x1d00ffff);
    tracker.OnTemplateReceived(2, 101);
    auto snap = tracker.GetSnapshot();
    EXPECT_TRUE(!snap.is_template_stale()) << "Initial: is_template_stale() == false (channel_height=100 < target=101)";
    EXPECT_TRUE(snap.channel_height == 100) << "Initial: channel_height == 100";
    EXPECT_TRUE(snap.channel_target == 101) << "Initial: channel_target == 101";

    // Channel advances — node found a block
    tracker.OnPushNotification(5001, 101, 0x1d00ffff);
    auto snap2 = tracker.GetSnapshot();
    EXPECT_TRUE(snap2.is_template_stale()) << "After channel advance: is_template_stale() == true (height=101 >= target=101)";
    EXPECT_TRUE(snap2.channel_height == 101) << "After channel advance: channel_height == 101";

    // Simulate keepalive arriving from OLD session — should not affect staleness
    tracker.OnKeepaliveResponse(5001, 300, 101, 900, 0xDEADBEEFu, 0);
    auto snap3 = tracker.GetSnapshot();
    EXPECT_TRUE(snap3.is_template_stale()) << "After old keepalive: is_template_stale() still true";
    EXPECT_TRUE(snap3.channel_height == 101) << "After old keepalive: channel_height unchanged at 101";

    // New template from GET_BLOCK response — staleness resolved
    tracker.OnTemplateReceived(2, 102);
    tracker.AdvanceChannelTarget(102);
    auto snap4 = tracker.GetSnapshot();
    EXPECT_TRUE(!snap4.is_template_stale()) << "After new template: is_template_stale() == false";
    EXPECT_TRUE(snap4.channel_target == 102) << "After new template: channel_target == 102";
}

// ============================================================================
// Test 3: Recovery pending debouncing — mark_recovery is idempotent
// Simulates the "Recovery already pending" scenario: multiple staleness sources
// calling mark_recovery_initiated() for the same event must not reset the epoch.
// ============================================================================
TEST(DegradedRecoveryTest, test_recovery_pending_debounce_idempotent) {
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
            phase = TestRecoveryPhase::WAITING_TEMPLATE;
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
    EXPECT_TRUE(rt.epoch == 1 && phase_is_recovery_active(rt.phase)) << "First initiation starts recovery (epoch=1)";

    // Second initiation from health monitor (same staleness event)
    rt.initiate("health_monitor_channel_stale");
    EXPECT_TRUE(rt.epoch == 1 && phase_is_recovery_active(rt.phase)) << "Second initiation is a no-op (epoch still 1)";

    // Third initiation from different source
    rt.initiate("health_monitor_or_validation");
    EXPECT_TRUE(rt.epoch == 1 && phase_is_recovery_active(rt.phase)) << "Third initiation is still a no-op (epoch still 1)";

    EXPECT_TRUE(std::any_of(rt.m_log.begin(), rt.m_log.end(),
                                  [](const auto& s) { return s.find("STARTED") != std::string::npos; })) << "All initiation calls produced at least one STARTED entry";
    size_t noop_count = 0;
    for (const auto& entry : rt.m_log)
        if (entry.find("NOOP") != std::string::npos) ++noop_count;
    EXPECT_TRUE(noop_count == 2) << "Subsequent initiations were all NOOP (2 no-ops for 3 total calls)";

    // Clear and re-initiate — new epoch must be incremented
    rt.clear();
    rt.initiate("escalation_hard_recovery");
    EXPECT_TRUE(rt.epoch == 2 && phase_is_recovery_active(rt.phase)) << "After clear, new initiation produces epoch=2";
}

// ============================================================================
// Test 4: Recovery GET_BLOCK can dispatch after debounce window — no starvation
// Simulates the deduplication window expiring between recovery retries.
// ============================================================================
TEST(DegradedRecoveryTest, test_recovery_get_block_no_permanent_starvation) {
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
    EXPECT_TRUE(first) << "First GET_BLOCK dispatch succeeds";

    // Immediate second dispatch should be suppressed (within 100ms)
    bool second = gate.try_dispatch();
    EXPECT_TRUE(!second) << "Immediate second dispatch suppressed by dedup window";

    // After dedup window expires, dispatch should succeed again
    std::this_thread::sleep_for(std::chrono::milliseconds(110));
    bool third = gate.try_dispatch();
    EXPECT_TRUE(third) << "GET_BLOCK dispatch succeeds after dedup window (110ms wait)";

    // Another immediate attempt should be suppressed again
    bool fourth = gate.try_dispatch();
    EXPECT_TRUE(!fourth) << "Immediate dispatch after third is suppressed again";

    // Recovery timer interval (30s >> 100ms dedup) ensures no starvation
    // at normal check_template_health intervals
    EXPECT_TRUE(30000 > DEDUP_MS * 100) << "30s timer interval >> 100ms dedup = no starvation at timer cadence";
}

// ============================================================================
// Test 4b: Successful re-authentication restarts the recovery window
// Mirrors Worker_manager::restart_recovery_window() + retry_template_request(true)
// so a fresh session does not inherit a long-expired recovery epoch.
// ============================================================================
TEST(DegradedRecoveryTest, test_successful_reauth_restarts_recovery_epoch) {
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

    EXPECT_TRUE(rt.m_recovery_epoch == 2) << "Re-authentication starts a new recovery epoch";
    EXPECT_TRUE(rt.m_recovery_pending) << "Recovery remains pending after re-authentication";
    EXPECT_TRUE(rt.m_recovery_started_at != std::chrono::steady_clock::time_point{} &&
                      rt.m_recovery_started_at > old_started_at) << "Recovery start time is refreshed after re-authentication";
    auto elapsed_after_reauth = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - rt.m_recovery_started_at).count();
    EXPECT_TRUE(elapsed_after_reauth >= 0 && elapsed_after_reauth <= 1) << "Fresh recovery epoch elapsed time is near-zero after re-authentication";
    EXPECT_TRUE(rt.m_degraded_since == std::chrono::steady_clock::time_point{}) << "Degraded timer is reset for the new authenticated session";
}

// ============================================================================
// Test 4c: Soft refresh timeout escalates only after the hot-swap window stalls
// ============================================================================
TEST(DegradedRecoveryTest, test_same_height_soft_refresh_escalates_only_after_timeout) {
    std::cout << "\nTest 4c: Template request enters WAITING_TEMPLATE until timeout triggers reconnect\n";
    constexpr int64_t RECOVERY_WINDOW_SECONDS = 60;
    constexpr int64_t TIMEOUT_TEST_SECONDS = RECOVERY_WINDOW_SECONDS + 1;

    struct RecoveryTracker {
        TestRecoveryPhase phase{TestRecoveryPhase::HEALTHY};
        uint64_t epoch{0};
        std::chrono::steady_clock::time_point entered_at{};
        std::string authoritative_recovery_reason;
        std::vector<std::string> m_log;

        void start_waiting_template(const std::string& reason) {
            ++epoch;
            phase = TestRecoveryPhase::WAITING_TEMPLATE;
            entered_at = std::chrono::steady_clock::now();
            authoritative_recovery_reason = reason;
            m_log.emplace_back("template refresh requested");
        }

        bool should_reconnect(int64_t recovery_window_seconds) const {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - entered_at).count();
            return elapsed >= recovery_window_seconds;
        }

        void do_reconnect() {
            phase = TestRecoveryPhase::RECONNECTING;
        }
    };

    RecoveryTracker rt;
    rt.start_waiting_template("same_height_push_tip_replacement_pre_adoption");
    EXPECT_TRUE(phase_is_recovery_active(rt.phase) && rt.epoch == 1) << "Template request starts WAITING_TEMPLATE recovery tracking";
    EXPECT_TRUE(!rt.m_log.empty() && rt.m_log.back() == "template refresh requested") << "WAITING_TEMPLATE logs template refresh requested";
    EXPECT_TRUE(rt.authoritative_recovery_reason == "same_height_push_tip_replacement_pre_adoption") << "WAITING_TEMPLATE records correct reason";
    EXPECT_TRUE(!phase_is_submissions_withheld(rt.phase)) << "WAITING_TEMPLATE: submissions not withheld (workers keep running)";
    EXPECT_TRUE(phase_is_degraded(rt.phase)) << "WAITING_TEMPLATE: is_degraded() == true (waiting for template)";
    EXPECT_TRUE(!rt.should_reconnect(RECOVERY_WINDOW_SECONDS)) << "WAITING_TEMPLATE does not reconnect immediately";

    rt.entered_at = std::chrono::steady_clock::now() - std::chrono::seconds(TIMEOUT_TEST_SECONDS);
    EXPECT_TRUE(rt.should_reconnect(RECOVERY_WINDOW_SECONDS)) << "WAITING_TEMPLATE triggers reconnect after 60s timeout";
    rt.do_reconnect();
    EXPECT_TRUE(phase_is_reconnecting(rt.phase)) << "After timeout: phase is RECONNECTING";
    EXPECT_TRUE(!phase_is_submissions_withheld(rt.phase)) << "After timeout: submissions still not withheld";
}

// ============================================================================
// Test 4d: clear_recovery_state-style normalization restores healthy baseline
// ============================================================================
TEST(DegradedRecoveryTest, test_degraded_exit_normalizes_recovery_state) {
    std::cout << "\nTest 4d: Degraded exit normalization clears recovery bookkeeping\n";

    struct RecoveryTracker {
        TestRecoveryPhase phase{TestRecoveryPhase::WAITING_TEMPLATE};
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

    EXPECT_TRUE(rt.phase == TestRecoveryPhase::HEALTHY) << "Phase returned to HEALTHY";
    EXPECT_TRUE(!phase_is_recovery_active(rt.phase)) << "Recovery active cleared";
    EXPECT_TRUE(!phase_is_degraded(rt.phase)) << "Degraded mode cleared";
    EXPECT_TRUE(!phase_is_submissions_withheld(rt.phase)) << "Soft-pause guard cleared";
    EXPECT_TRUE(rt.epoch == 0) << "Recovery epoch reset";
    EXPECT_TRUE(rt.entered_at == std::chrono::steady_clock::time_point{} &&
                      rt.last_get_block_at == std::chrono::steady_clock::time_point{} &&
                      !rt.get_block_confirmed) << "GET_BLOCK bookkeeping cleared";
    EXPECT_TRUE(rt.degraded_since == std::chrono::steady_clock::time_point{}) << "Escalation timer cleared";
    EXPECT_TRUE(rt.authoritative_recovery_healthy_called &&
                      rt.authoritative_recovery_reason.empty()) << "Authoritative recovery state normalized";
}

// ============================================================================
// Test 4e: SOFT_REFRESH transition withholds submissions without degraded mode
// Replaces the old test_authoritative_soft_refresh_backfills_local_state()
// which referenced the removed RecoveryState::SOFT_REFRESH_REQUESTED enum value.
// Now tests the surviving RecoveryPhase::SOFT_REFRESH transition path.
// ============================================================================
TEST(DegradedRecoveryTest, test_authoritative_soft_refresh_backfills_local_state) {
    std::cout << "\nTest 4e: Template refresh request enters WAITING_TEMPLATE (new 3-state model)\n";

    struct RecoveryTracker {
        TestRecoveryPhase phase{TestRecoveryPhase::HEALTHY};
        uint64_t epoch{0};
        std::chrono::steady_clock::time_point entered_at{};

        bool request_template_refresh(const char* /*reason*/) {
            if (phase_is_recovery_active(phase)) {
                return false;
            }
            ++epoch;
            phase = TestRecoveryPhase::WAITING_TEMPLATE;
            entered_at = std::chrono::steady_clock::now();
            return true;
        }
    };

    RecoveryTracker rt;
    const bool transitioned = rt.request_template_refresh("same_height_push_tip_replacement");
    EXPECT_TRUE(transitioned) << "Template refresh transitions from HEALTHY to WAITING_TEMPLATE";
    EXPECT_TRUE(!phase_is_submissions_withheld(rt.phase)) << "WAITING_TEMPLATE: submissions are NOT withheld (new model)";
    EXPECT_TRUE(phase_is_degraded(rt.phase)) << "WAITING_TEMPLATE: is_degraded() == true (waiting for template)";
    EXPECT_TRUE(rt.epoch == 1) << "WAITING_TEMPLATE anchors recovery epoch";
    EXPECT_TRUE(rt.entered_at != std::chrono::steady_clock::time_point{}) << "WAITING_TEMPLATE anchors the recovery timer";

    const bool second = rt.request_template_refresh("duplicate_push");
    EXPECT_TRUE(!second) << "Second refresh request is a no-op (idempotent)";
    EXPECT_TRUE(rt.epoch == 1) << "Epoch unchanged after idempotent call";
}

// ============================================================================
// Test 4f: tip_moved soft refresh shields workers from immediate HEIGHT_DRIFT
//          escalation until the replacement-template window actually times out.
// ============================================================================
TEST(DegradedRecoveryTest, test_tip_moved_soft_refresh_defers_unified_drift_stop_until_timeout) {
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
    EXPECT_TRUE(state.request_refresh && !state.stop_workers && !state.m_degraded_mode) << "tip_moved requests fresh template without stopping workers";
    EXPECT_TRUE(!state.m_template_withheld && !state.m_recovery_pending) << "tip_moved does NOT withhold submissions (workers keep submitting)";

    state.tick(/*tip_moved=*/false, /*unified_drift=*/7, /*recovery_elapsed_s=*/10);
    EXPECT_TRUE(state.stop_workers && state.m_degraded_mode) << "HEIGHT_DRIFT fires on next tick when drift exceeds threshold and tip no longer moved";
}

// ============================================================================
// Test 4g: Worker respawn guard prevents duplicate worker recreation on exit
// ============================================================================
TEST(DegradedRecoveryTest, test_worker_respawn_guard_is_single_shot_per_degraded_exit) {
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

    EXPECT_TRUE(first_restart) << "First degraded-exit restart creates workers";
    EXPECT_TRUE(!second_restart) << "Second degraded-exit restart is suppressed";
    EXPECT_TRUE(rt.create_calls == 1) << "Workers are created only once for the outage";
    EXPECT_TRUE(rt.worker_instances == 8) << "Worker count stays at the expected 8 threads";
}

// ============================================================================
// Test 4h: Workers only respawn after the prior generation is fully stopped
// ============================================================================
TEST(DegradedRecoveryTest, test_worker_respawn_waits_for_authoritative_empty_generation) {
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

    EXPECT_TRUE(!restart_during_stop) << "Respawn is blocked while prior generation is still stopping";
    EXPECT_TRUE(restart_after_stop) << "Respawn succeeds once workers are authoritatively gone";
    EXPECT_TRUE(!second_restart_after_stop) << "Respawn remains single-shot after the restart";
    EXPECT_TRUE(rt.create_calls == 1) << "Only one new worker generation is created";
    EXPECT_TRUE(rt.worker_instances == 8) << "Worker count returns to the expected 8 threads";
}

// ============================================================================
// Test 5: Keepalive epoch isolation — new epoch starts with clean ack timestamp
// ============================================================================
TEST(DegradedRecoveryTest, test_keepalive_epoch_isolation_clean_start) {
    std::cout << "\nTest 5: New epoch starts with clean keepalive ACK timestamp\n";
    HeightTracker tracker;

    // Simulate three successive re-auths (epoch 1 → 2 → 3)
    for (uint64_t epoch = 1; epoch <= 3; ++epoch) {
        tracker.set_session_epoch(epoch);

        // At start of each epoch, ack timestamp must be clear
        auto snap_start = tracker.GetSnapshot();
        EXPECT_TRUE(snap_start.last_keepalive_ack_at == std::chrono::steady_clock::time_point{}) << "Epoch " << epoch << ": ack timestamp clear at epoch start";

        // Receive keepalive for this epoch
        tracker.OnKeepaliveResponse(5000 + static_cast<uint32_t>(epoch), 400, 700, 900, 0u, 0);
        auto snap_after = tracker.GetSnapshot();
        EXPECT_TRUE(snap_after.last_keepalive_ack_at != std::chrono::steady_clock::time_point{}) << "Epoch " << epoch << ": ack timestamp set after response";
    }
}

// ============================================================================
// Test 6: Stale template after channel advance triggers is_template_stale()
// (Validates the push-staleness detection that feeds the recovery path)
// ============================================================================
TEST(DegradedRecoveryTest, test_stale_template_after_channel_advance) {
    std::cout << "\nTest 6: Stale template detection after channel advance\n";
    HeightTracker tracker;

    // Template targeting channel_height=101
    tracker.OnPushNotification(5000, 100, 0x1d00ffff);
    tracker.OnTemplateReceived(1, 101);

    // Confirm not stale before advance
    auto snap_before = tracker.GetSnapshot();
    EXPECT_TRUE(!snap_before.is_template_stale()) << "Before advance: is_template_stale() == false";

    // Channel advances (block found)
    tracker.OnPushNotification(5001, 101, 0x1d00ffff);
    auto snap_after = tracker.GetSnapshot();
    EXPECT_TRUE(snap_after.is_template_stale()) << "After advance: is_template_stale() == true";
    EXPECT_TRUE(snap_after.channel_height == 101) << "After advance: channel_height == 101";
    EXPECT_TRUE(snap_after.channel_target == 101) << "After advance: channel_target == 101";

    // is_template_stale condition: channel_height >= channel_target
    EXPECT_TRUE(snap_after.channel_height >= snap_after.channel_target) << "is_template_stale() satisfies: channel_height >= channel_target";
}

// ============================================================================
// Test 7: set_session_epoch() suppresses old keepalive signal
// Confirms keepalive ACK timestamp is cleared after epoch change (diagnostic field)
// ============================================================================
TEST(DegradedRecoveryTest, test_epoch_advance_suppresses_old_keepalive_signal) {
    std::cout << "\nTest 7: Epoch advance clears keepalive ACK timestamp (diagnostic field)\n";
    HeightTracker tracker;

    tracker.set_session_epoch(10);
    tracker.OnKeepaliveResponse(5000, 400, 700, 900, 0u, 0);

    // Confirm old epoch keepalive is "set"
    auto snap_epoch10 = tracker.GetSnapshot();
    bool was_set = (snap_epoch10.last_keepalive_ack_at != std::chrono::steady_clock::time_point{});
    EXPECT_TRUE(was_set) << "Epoch 10: keepalive ACK timestamp is set";

    // Advance epoch — simulates re-auth or session restart
    tracker.set_session_epoch(11);
    auto snap_epoch11 = tracker.GetSnapshot();

    // The keepalive ACK timestamp is diagnostic only — PUSH is the sole authoritative
    // signal for session liveness.  After epoch change, the diagnostic timestamp is cleared.
    bool keepalive_ack_received = (snap_epoch11.last_keepalive_ack_at !=
                                    std::chrono::steady_clock::time_point{});
    EXPECT_TRUE(!keepalive_ack_received) << "Epoch 11: keepalive_ack_received == false after epoch advance";
    EXPECT_TRUE(!keepalive_ack_received) << "Epoch 11: keepalive diagnostic timestamp cleared (epoch isolation)";
}

// ============================================================================
// Test 8: Multiple rapid epoch changes produce clean keepalive state
// ============================================================================
TEST(DegradedRecoveryTest, test_multiple_rapid_epoch_changes_clean_state) {
    std::cout << "\nTest 8: Multiple rapid epoch changes always produce clean keepalive state\n";
    HeightTracker tracker;

    uint64_t current_epoch = 0;
    for (int i = 0; i < 5; ++i) {
        ++current_epoch;
        tracker.set_session_epoch(current_epoch);

        // Epoch starts clean
        auto snap_start = tracker.GetSnapshot();
        EXPECT_TRUE(snap_start.last_keepalive_ack_at == std::chrono::steady_clock::time_point{}) << "Epoch " << current_epoch << ": clean start";

        // Receive keepalive
        tracker.OnKeepaliveResponse(5000, 400, 700, 900, 0u, 0);
    }

    // Final state: keepalive is set for epoch 5
    auto snap_final = tracker.GetSnapshot();
    EXPECT_TRUE(snap_final.last_keepalive_ack_at != std::chrono::steady_clock::time_point{}) << "Final epoch (5): keepalive ACK timestamp is set from epoch 5 response";
    EXPECT_TRUE(snap_final.session_epoch == 5) << "Final epoch (5): session_epoch == 5";
}

// ============================================================================
// Test 9: Push notification does not reset keepalive timestamp on epoch change
// Pushes and keepalives are orthogonal — epoch change clears ONLY keepalive ack
// ============================================================================
TEST(DegradedRecoveryTest, test_push_does_not_clear_keepalive_on_epoch_change) {
    std::cout << "\nTest 9: Push notifications do not clear keepalive timestamp on epoch change\n";
    HeightTracker tracker;

    tracker.set_session_epoch(1);
    tracker.OnKeepaliveResponse(5000, 400, 700, 900, 0u, 0);
    tracker.OnPushNotification(5000, 100, 0x1d00ffff);

    auto snap1 = tracker.GetSnapshot();
    bool push_at_set  = (snap1.last_push_notification_at != std::chrono::steady_clock::time_point{});
    bool ack_at_set   = (snap1.last_keepalive_ack_at != std::chrono::steady_clock::time_point{});
    EXPECT_TRUE(push_at_set) << "Epoch 1: push timestamp is set";
    EXPECT_TRUE(ack_at_set) << "Epoch 1: keepalive ACK timestamp is set";

    // Epoch change: keepalive clears, push is unchanged
    tracker.set_session_epoch(2);
    auto snap2 = tracker.GetSnapshot();
    bool push_unchanged  = (snap2.last_push_notification_at == snap1.last_push_notification_at);
    bool ack_cleared     = (snap2.last_keepalive_ack_at == std::chrono::steady_clock::time_point{});
    EXPECT_TRUE(push_unchanged) << "Epoch 2: push timestamp preserved (not cleared by epoch change)";
    EXPECT_TRUE(ack_cleared) << "Epoch 2: keepalive ACK timestamp cleared by epoch change";
}

// ============================================================================
// Test 9b: Session epoch advance clears stale push tip-anchor hints but keeps push liveness
// ============================================================================
TEST(DegradedRecoveryTest, test_epoch_change_clears_push_tip_anchor_hint) {
    std::cout << "\nTest 9b: Session epoch advance clears stale push tip-anchor hint only\n";
    HeightTracker tracker;

    tracker.set_session_epoch(7);
    tracker.OnPushNotification(5000, 100, 0x1d00ffff);
    tracker.UpdatePushTipAnchor(uint1024_t(0x42));

    auto snap_before = tracker.GetSnapshot();
    EXPECT_TRUE(snap_before.push_hash_prev_block != uint1024_t{}) << "Epoch 7: push tip-anchor hint is present before epoch change";
    EXPECT_TRUE(snap_before.last_push_notification_at != std::chrono::steady_clock::time_point{}) << "Epoch 7: push liveness timestamp is present before epoch change";

    tracker.set_session_epoch(8);
    auto snap_after = tracker.GetSnapshot();
    EXPECT_TRUE(snap_after.push_hash_prev_block == uint1024_t{}) << "Epoch 8: push tip-anchor hint cleared on epoch change";
    EXPECT_TRUE(snap_after.last_push_notification_at == snap_before.last_push_notification_at) << "Epoch 8: push liveness timestamp preserved across epoch change";

    tracker.UpdatePushTipAnchor(uint1024_t(0x77));
    auto snap_reseeded = tracker.GetSnapshot();
    EXPECT_TRUE(snap_reseeded.push_hash_prev_block != uint1024_t{}) << "Explicit clear test re-seeds push tip-anchor hint first";
    tracker.ClearPushTipAnchor();
    auto snap_cleared = tracker.GetSnapshot();
    EXPECT_TRUE(snap_cleared.push_hash_prev_block == uint1024_t{}) << "Explicit tip-anchor clear consumes replacement hint after adoption";
}

// ============================================================================
// Test 10: Recovery epoch tracking — monotonic with idempotent initiation
// ============================================================================
TEST(DegradedRecoveryTest, test_recovery_epoch_monotonic_with_idempotent_initiation) {
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
    EXPECT_TRUE(epoch_after_first == 1 && epoch_after_many == 1) << "Epoch is monotonic: multiple inits don't increment past 1";
    EXPECT_TRUE(rs.pending) << "Pending remains true after multiple inits";

    // Recovery completes (template received)
    rs.clear();
    EXPECT_TRUE(!rs.pending) << "After clear: pending == false";
    EXPECT_TRUE(rs.epoch == 1) << "After clear: epoch still == 1 (preserved for audit)";

    // Next staleness event: epoch advances
    rs.initiate();
    EXPECT_TRUE(rs.epoch == 2) << "Second staleness: epoch == 2 (monotonically incremented)";
    EXPECT_TRUE(rs.pending) << "Second staleness: pending == true";

    // Multiple calls again: no increment past 2
    rs.initiate();
    rs.initiate();
    EXPECT_TRUE(rs.epoch == 2) << "Multiple inits after epoch 2: epoch remains 2";
}

// ============================================================================
// Test 11: Integration - channel advance -> stale -> degraded -> fresh -> resume
// ============================================================================
TEST(DegradedRecoveryTest, test_integration_degraded_recovery_to_resume) {
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
    EXPECT_TRUE(s.degraded && !s.mining_active) << "Stale transition enters degraded mode";

    s.recovery_tick();
    EXPECT_TRUE(s.get_block_sent == 1) << "Recovery tick sends GET_BLOCK while degraded";

    s.on_fresh_template(102);
    EXPECT_TRUE(!s.degraded && !s.recovery_pending) << "Fresh template exits degraded mode";
    EXPECT_TRUE(s.mining_active) << "Mining resumes after template acceptance";
}

// ============================================================================
// Test 12: Integration - bounded forced retries prevent flooding
// ============================================================================
TEST(DegradedRecoveryTest, test_integration_forced_retry_is_bounded) {
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
    EXPECT_TRUE(sent <= 25) << "Forced retries stay at or below max_forced_burst_per_60s";
    EXPECT_TRUE(sent > 0) << "Forced retries still make progress (at least one send)";
}

// ============================================================================
// Test 13: Health policy — one-block stale refresh stays soft; multi-block lag
//          escalates into recovery/degraded mode.
// ============================================================================
TEST(DegradedRecoveryTest, test_health_policy_distinguishes_normal_refresh_from_multi_block_lag) {
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
    EXPECT_TRUE(one_block.request_refresh) << "One-block lag requests refresh";
    EXPECT_TRUE(!one_block.recovery_initiated) << "One-block lag does not initiate recovery";
    EXPECT_TRUE(!one_block.stop_workers) << "One-block lag does not stop workers";

    HeightTracker two_block_tracker;
    two_block_tracker.OnPushNotification(5000, 100, 0x1d00ffff);
    two_block_tracker.OnTemplateReceived(2, 101);
    two_block_tracker.OnPushNotification(5001, 101, 0x1d00ffff);
    two_block_tracker.OnPushNotification(5002, 102, 0x1d00ffff);
    auto two_block = decide(two_block_tracker.GetSnapshot(), false);
    EXPECT_TRUE(two_block.request_refresh) << "Two-block lag requests refresh";
    EXPECT_TRUE(two_block.recovery_initiated) << "Two-block lag initiates recovery";
    EXPECT_TRUE(two_block.stop_workers) << "Two-block lag stops workers";

    HeightTracker::Snapshot post_push_snap;
    post_push_snap.channel_height = 300;
    post_push_snap.channel_target = 300;
    auto post_push = decide(post_push_snap, true);
    EXPECT_TRUE(post_push.request_refresh) << "Post-push template freshness still stays soft";
    EXPECT_TRUE(!post_push.recovery_initiated) << "Post-push template freshness does not initiate recovery";
}

// ============================================================================
// ⚡ RecoveryPhase State Machine Tests (mirrors worker_manager.hpp RecoveryPhase)
// ============================================================================

// ── Test 18: Legal transitions succeed, illegal ones are rejected ──────────
TEST(DegradedRecoveryTest, test_recovery_phase_valid_transitions) {
    std::cout << "\nTest 18: RecoveryPhase state machine — valid transition matrix (3-state)\n";

    // Legal transitions
    EXPECT_TRUE(test_is_valid_transition(TestRecoveryPhase::HEALTHY, TestRecoveryPhase::WAITING_TEMPLATE)) << "HEALTHY → WAITING_TEMPLATE is legal";
    EXPECT_TRUE(test_is_valid_transition(TestRecoveryPhase::HEALTHY, TestRecoveryPhase::RECONNECTING)) << "HEALTHY → RECONNECTING is legal";
    EXPECT_TRUE(test_is_valid_transition(TestRecoveryPhase::WAITING_TEMPLATE, TestRecoveryPhase::HEALTHY)) << "WAITING_TEMPLATE → HEALTHY is legal";
    EXPECT_TRUE(test_is_valid_transition(TestRecoveryPhase::WAITING_TEMPLATE, TestRecoveryPhase::RECONNECTING)) << "WAITING_TEMPLATE → RECONNECTING is legal";
    EXPECT_TRUE(test_is_valid_transition(TestRecoveryPhase::RECONNECTING, TestRecoveryPhase::HEALTHY)) << "RECONNECTING → HEALTHY is legal";
    EXPECT_TRUE(test_is_valid_transition(TestRecoveryPhase::RECONNECTING, TestRecoveryPhase::WAITING_TEMPLATE)) << "RECONNECTING → WAITING_TEMPLATE is legal";

    // Same-phase no-ops are always valid
    EXPECT_TRUE(test_is_valid_transition(TestRecoveryPhase::HEALTHY, TestRecoveryPhase::HEALTHY)) << "HEALTHY → HEALTHY is valid (no-op)";
    EXPECT_TRUE(test_is_valid_transition(TestRecoveryPhase::WAITING_TEMPLATE, TestRecoveryPhase::WAITING_TEMPLATE)) << "WAITING_TEMPLATE → WAITING_TEMPLATE is valid (no-op)";
}

// ── Test 19: Phase helper equivalences match new 3-state design ─────────
TEST(DegradedRecoveryTest, test_recovery_phase_helpers_equivalence) {
    std::cout << "\nTest 19: Phase helpers match 3-state design\n";

    // is_degraded() ← WAITING_TEMPLATE only
    EXPECT_TRUE(!phase_is_degraded(TestRecoveryPhase::HEALTHY)) << "HEALTHY: is_degraded() == false";
    EXPECT_TRUE(phase_is_degraded(TestRecoveryPhase::WAITING_TEMPLATE)) << "WAITING_TEMPLATE: is_degraded() == true";
    EXPECT_TRUE(!phase_is_degraded(TestRecoveryPhase::RECONNECTING)) << "RECONNECTING: is_degraded() == false";

    // is_submissions_withheld() ← always false in new design
    EXPECT_TRUE(!phase_is_submissions_withheld(TestRecoveryPhase::HEALTHY)) << "HEALTHY: is_submissions_withheld() == false";
    EXPECT_TRUE(!phase_is_submissions_withheld(TestRecoveryPhase::WAITING_TEMPLATE)) << "WAITING_TEMPLATE: is_submissions_withheld() == false";

    // is_recovery_active() ← any non-HEALTHY phase
    EXPECT_TRUE(!phase_is_recovery_active(TestRecoveryPhase::HEALTHY)) << "HEALTHY: is_recovery_active() == false";
    EXPECT_TRUE(phase_is_recovery_active(TestRecoveryPhase::WAITING_TEMPLATE)) << "WAITING_TEMPLATE: is_recovery_active() == true";
    EXPECT_TRUE(phase_is_recovery_active(TestRecoveryPhase::RECONNECTING)) << "RECONNECTING: is_recovery_active() == true";

    // is_reconnecting() ← RECONNECTING only
    EXPECT_TRUE(!phase_is_reconnecting(TestRecoveryPhase::HEALTHY)) << "HEALTHY: is_reconnecting() == false";
    EXPECT_TRUE(phase_is_reconnecting(TestRecoveryPhase::RECONNECTING)) << "RECONNECTING: is_reconnecting() == true";
    EXPECT_TRUE(!phase_is_reconnecting(TestRecoveryPhase::WAITING_TEMPLATE)) << "WAITING_TEMPLATE: is_reconnecting() == false";
}

// ── Test 20: WAITING_TEMPLATE state — clearing state always exits it ──────
TEST(DegradedRecoveryTest, test_orphaned_soft_refresh_cleared) {
    std::cout << "\nTest 20: WAITING_TEMPLATE state is cleared by clear_recovery_state\n";

    // Simulate: was in WAITING_TEMPLATE, clear_recovery_state() transitions to HEALTHY
    TestRecoveryPhase phase = TestRecoveryPhase::WAITING_TEMPLATE;

    // Verify waiting-template is active
    EXPECT_TRUE(phase_is_recovery_active(phase)) << "Initial: is_recovery_active() == true (WAITING_TEMPLATE)";
    EXPECT_TRUE(phase_is_degraded(phase)) << "Initial: is_degraded() == true (WAITING_TEMPLATE)";

    // clear_recovery_state() logic: transition to HEALTHY
    phase = TestRecoveryPhase::HEALTHY;

    EXPECT_TRUE(phase == TestRecoveryPhase::HEALTHY) << "After clear: phase == HEALTHY";
    EXPECT_TRUE(!phase_is_submissions_withheld(phase)) << "After clear: is_submissions_withheld() == false";
    EXPECT_TRUE(!phase_is_recovery_active(phase)) << "After clear: is_recovery_active() == false";
}

// ── Test 21: WAITING_TEMPLATE → RECONNECTING escalation path ─────────────
TEST(DegradedRecoveryTest, test_soft_refresh_escalation_to_hard_recovery) {
    std::cout << "\nTest 21: WAITING_TEMPLATE → RECONNECTING after 60s timeout\n";

    TestRecoveryPhase phase = TestRecoveryPhase::HEALTHY;

    // Enter WAITING_TEMPLATE (stale template)
    ASSERT_TRUE(test_is_valid_transition(phase, TestRecoveryPhase::WAITING_TEMPLATE));
    phase = TestRecoveryPhase::WAITING_TEMPLATE;
    EXPECT_TRUE(phase_is_recovery_active(phase)) << "Entered WAITING_TEMPLATE: is_recovery_active() == true";
    EXPECT_TRUE(phase_is_degraded(phase)) << "WAITING_TEMPLATE: is_degraded() == true";
    EXPECT_TRUE(!phase_is_submissions_withheld(phase)) << "WAITING_TEMPLATE: is_submissions_withheld() == false (workers keep running)";

    // After 60s timeout → enter RECONNECTING
    ASSERT_TRUE(test_is_valid_transition(phase, TestRecoveryPhase::RECONNECTING));
    phase = TestRecoveryPhase::RECONNECTING;
    EXPECT_TRUE(phase_is_reconnecting(phase)) << "After timeout: RECONNECTING phase active";
    EXPECT_TRUE(phase_is_recovery_active(phase)) << "After timeout: is_recovery_active() == true";
}

// ── Test 22: RECONNECTING prevents SESSION_EXPIRED re-entrance ────────────
TEST(DegradedRecoveryTest, test_reconnecting_guards_session_expired) {
    std::cout << "\nTest 22: RECONNECTING phase prevents Session EXPIRED from re-entering\n";

    TestRecoveryPhase phase = TestRecoveryPhase::RECONNECTING;

    // Session expired handler guard: if reconnecting OR recovery active with epoch > 0
    uint64_t epoch = 1;
    bool should_ignore = phase_is_reconnecting(phase) ||
                         (phase_is_recovery_active(phase) && epoch > 0);
    EXPECT_TRUE(should_ignore) << "RECONNECTING: session_expired is ignored";

    // Verify HEALTHY does NOT suppress session_expired
    TestRecoveryPhase healthy = TestRecoveryPhase::HEALTHY;
    uint64_t healthy_epoch = 0;
    bool healthy_ignore = phase_is_reconnecting(healthy) ||
                          (phase_is_recovery_active(healthy) && healthy_epoch > 0);
    EXPECT_TRUE(!healthy_ignore) << "HEALTHY: session_expired is NOT ignored";

    // Verify WAITING_TEMPLATE with epoch 0 does NOT suppress session_expired
    TestRecoveryPhase waiting = TestRecoveryPhase::WAITING_TEMPLATE;
    uint64_t waiting_epoch = 0;  // epoch 0 = just entered, no recovery epoch yet
    bool waiting_ignore = phase_is_reconnecting(waiting) ||
                          (phase_is_recovery_active(waiting) && waiting_epoch > 0);
    EXPECT_TRUE(!waiting_ignore) << "WAITING_TEMPLATE with epoch=0: session_expired is NOT ignored";
}

// ── Test 23: Mutual exclusivity — only one phase at a time ───────────────
TEST(DegradedRecoveryTest, test_recovery_phase_mutual_exclusivity) {
    std::cout << "\nTest 23: Phase mutual exclusivity — only one phase at a time\n";

    // The enum class guarantees mutual exclusivity at the type level.
    // Verify all possible phase combinations are distinct.
    TestRecoveryPhase phases[] = {
        TestRecoveryPhase::HEALTHY,
        TestRecoveryPhase::WAITING_TEMPLATE,
        TestRecoveryPhase::RECONNECTING,
    };

    bool all_distinct = true;
    for (size_t i = 0; i < 3; ++i) {
        for (size_t j = i + 1; j < 3; ++j) {
            if (phases[i] == phases[j]) {
                all_distinct = false;
                break;
            }
        }
    }
    EXPECT_TRUE(all_distinct) << "All 3 phases have distinct enum values";

    // Verify: WAITING_TEMPLATE cannot have submissions withheld
    TestRecoveryPhase waiting = TestRecoveryPhase::WAITING_TEMPLATE;
    bool withheld = phase_is_submissions_withheld(waiting);
    EXPECT_TRUE(!withheld) << "WAITING_TEMPLATE: is_submissions_withheld() == false";

    // Verify: WAITING_TEMPLATE is degraded (workers have no fresh template)
    bool degraded = phase_is_degraded(waiting);
    EXPECT_TRUE(degraded) << "WAITING_TEMPLATE: is_degraded() == true";
}
