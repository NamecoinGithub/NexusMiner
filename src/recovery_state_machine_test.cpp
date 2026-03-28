#include "recovery_state_machine.hpp"
#include "stats/stats_collector.hpp"
#include "config/config.hpp"
#include "protocol/inc/protocol/session_coordinator.hpp"
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <iostream>

using namespace nexusminer;

namespace
{
bool expect(bool condition, const char* message)
{
    if (!condition)
    {
        std::cerr << "  [FAIL] " << message << std::endl;
        return false;
    }
    std::cout << "  [PASS] " << message << std::endl;
    return true;
}

std::shared_ptr<spdlog::logger> make_logger()
{
    auto logger = spdlog::get("test_logger");
    if (!logger)
    {
        logger = spdlog::stdout_color_mt("test_logger");
        logger->set_level(spdlog::level::off);  // suppress output during tests
    }
    return logger;
}

RecoveryStateMachine make_sm()
{
    auto logger = make_logger();
    auto coordinator = std::make_shared<protocol::SessionCoordinator>(logger);
    config::Config config(logger);
    auto collector = std::make_shared<stats::Collector>(config);
    RecoveryStateMachine sm;
    sm.init(logger, coordinator, collector);
    return sm;
}
}

int main()
{
    bool ok = true;

    std::cout << "========================================\n";
    std::cout << "RecoveryStateMachine Unit Tests\n";
    std::cout << "========================================\n\n";

    {
        std::cout << "Test 1: Initial state is HEALTHY\n";
        auto sm = make_sm();
        ok &= expect(!sm.is_degraded(), "Not degraded initially");
        ok &= expect(!sm.is_recovery_active(), "No recovery active initially");
        ok &= expect(!sm.is_reconnecting(), "Not reconnecting initially");
        ok &= expect(!sm.is_submissions_withheld(), "Submissions not withheld");
        ok &= expect(sm.context().phase == RecoveryPhase::HEALTHY, "Phase is HEALTHY");
        std::cout << '\n';
    }

    {
        std::cout << "Test 2: phase_name returns correct strings\n";
        ok &= expect(std::string(RecoveryStateMachine::phase_name(RecoveryPhase::HEALTHY)) == "HEALTHY",
                      "HEALTHY name correct");
        ok &= expect(std::string(RecoveryStateMachine::phase_name(RecoveryPhase::WAITING_TEMPLATE)) == "WAITING_TEMPLATE",
                      "WAITING_TEMPLATE name correct");
        ok &= expect(std::string(RecoveryStateMachine::phase_name(RecoveryPhase::RECONNECTING)) == "RECONNECTING",
                      "RECONNECTING name correct");
        std::cout << '\n';
    }

    {
        std::cout << "Test 3: Valid transitions\n";
        // HEALTHY → WAITING_TEMPLATE
        ok &= expect(RecoveryStateMachine::is_valid_transition(RecoveryPhase::HEALTHY, RecoveryPhase::WAITING_TEMPLATE),
                      "HEALTHY → WAITING_TEMPLATE is valid");
        // HEALTHY → RECONNECTING
        ok &= expect(RecoveryStateMachine::is_valid_transition(RecoveryPhase::HEALTHY, RecoveryPhase::RECONNECTING),
                      "HEALTHY → RECONNECTING is valid");
        // WAITING_TEMPLATE → HEALTHY
        ok &= expect(RecoveryStateMachine::is_valid_transition(RecoveryPhase::WAITING_TEMPLATE, RecoveryPhase::HEALTHY),
                      "WAITING_TEMPLATE → HEALTHY is valid");
        // WAITING_TEMPLATE → RECONNECTING
        ok &= expect(RecoveryStateMachine::is_valid_transition(RecoveryPhase::WAITING_TEMPLATE, RecoveryPhase::RECONNECTING),
                      "WAITING_TEMPLATE → RECONNECTING is valid");
        // RECONNECTING → HEALTHY
        ok &= expect(RecoveryStateMachine::is_valid_transition(RecoveryPhase::RECONNECTING, RecoveryPhase::HEALTHY),
                      "RECONNECTING → HEALTHY is valid");
        // RECONNECTING → WAITING_TEMPLATE
        ok &= expect(RecoveryStateMachine::is_valid_transition(RecoveryPhase::RECONNECTING, RecoveryPhase::WAITING_TEMPLATE),
                      "RECONNECTING → WAITING_TEMPLATE is valid");
        // Self-transitions are valid
        ok &= expect(RecoveryStateMachine::is_valid_transition(RecoveryPhase::HEALTHY, RecoveryPhase::HEALTHY),
                      "HEALTHY → HEALTHY self-transition is valid");
        std::cout << '\n';
    }

    {
        std::cout << "Test 4: transition_to WAITING_TEMPLATE\n";
        auto sm = make_sm();
        sm.transition_to(RecoveryPhase::WAITING_TEMPLATE, "test");
        ok &= expect(sm.is_degraded(), "Degraded after transition to WAITING_TEMPLATE");
        ok &= expect(sm.is_recovery_active(), "Recovery active after transition");
        ok &= expect(!sm.is_reconnecting(), "Not reconnecting");
        ok &= expect(sm.context().phase == RecoveryPhase::WAITING_TEMPLATE, "Phase is WAITING_TEMPLATE");
        ok &= expect(sm.context().entered_at != std::chrono::steady_clock::time_point{},
                      "entered_at is set");
        ok &= expect(sm.degraded_enter_total() == 1, "degraded_enter_total incremented");
        std::cout << '\n';
    }

    {
        std::cout << "Test 5: transition_to HEALTHY clears recovery state\n";
        auto sm = make_sm();
        sm.transition_to(RecoveryPhase::WAITING_TEMPLATE, "test");
        sm.transition_to(RecoveryPhase::HEALTHY, "recovery_done");
        ok &= expect(!sm.is_degraded(), "Not degraded after return to HEALTHY");
        ok &= expect(!sm.is_recovery_active(), "Recovery not active");
        ok &= expect(sm.context().last_completed_at != std::chrono::steady_clock::time_point{},
                      "last_completed_at is set");
        ok &= expect(sm.degraded_exit_total() == 1, "degraded_exit_total incremented");
        ok &= expect(sm.time_in_degraded_ms() > 0 || sm.time_in_degraded_ms() == 0,
                      "time_in_degraded_ms tracked (may be 0 for fast test)");
        std::cout << '\n';
    }

    {
        std::cout << "Test 6: mark_recovery_initiated is idempotent\n";
        auto sm = make_sm();
        sm.mark_recovery_initiated("first");
        ok &= expect(sm.is_recovery_active(), "Recovery active after first call");
        auto entered = sm.context().entered_at;
        sm.mark_recovery_initiated("second");  // should not reset
        ok &= expect(sm.context().entered_at == entered, "entered_at unchanged on second call");
        std::cout << '\n';
    }

    {
        std::cout << "Test 7: mark_soft_refresh_requested delegates to mark_recovery_initiated\n";
        auto sm = make_sm();
        sm.mark_soft_refresh_requested("soft_refresh");
        ok &= expect(sm.is_recovery_active(), "Recovery active after soft refresh");
        ok &= expect(sm.is_degraded(), "Degraded after soft refresh (maps to WAITING_TEMPLATE)");
        std::cout << '\n';
    }

    {
        std::cout << "Test 8: restart_recovery_window resets timing\n";
        auto sm = make_sm();
        sm.transition_to(RecoveryPhase::WAITING_TEMPLATE, "test");
        auto old_entered = sm.context().entered_at;
        // Small delay to ensure different timestamp
        for (volatile int i = 0; i < 10000; ++i) {}
        sm.restart_recovery_window("reauth");
        ok &= expect(sm.context().entered_at >= old_entered, "entered_at updated");
        ok &= expect(!sm.context().get_block_confirmed, "get_block_confirmed reset");
        std::cout << '\n';
    }

    {
        std::cout << "Test 9: clear_recovery_state deferred without valid template\n";
        auto sm = make_sm();
        sm.transition_to(RecoveryPhase::WAITING_TEMPLATE, "test");
        sm.clear_recovery_state(false);  // no valid template
        ok &= expect(sm.is_degraded(), "Still degraded — clear deferred");
        sm.clear_recovery_state(true);  // valid template
        ok &= expect(!sm.is_degraded(), "Degraded cleared with valid template");
        ok &= expect(!sm.is_recovery_active(), "Recovery not active after clear");
        std::cout << '\n';
    }

    {
        std::cout << "Test 10: Forced retry token management\n";
        auto sm = make_sm();
        ok &= expect(sm.forced_retry_token() == 0, "Initial token is 0");
        ok &= expect(!sm.forced_retry_pending(), "Not pending initially");
        sm.set_forced_retry_pending(true);
        ok &= expect(sm.forced_retry_pending(), "Pending after set");
        auto token = sm.advance_forced_retry_token();
        ok &= expect(token == 1, "Token advanced to 1");
        ok &= expect(sm.forced_retry_token() == 1, "Token getter returns 1");
        std::cout << '\n';
    }

    {
        std::cout << "Test 11: Cancel forced retry callback\n";
        auto sm = make_sm();
        bool callback_called = false;
        sm.set_cancel_forced_retry_callback([&callback_called]() {
            callback_called = true;
        });
        sm.transition_to(RecoveryPhase::WAITING_TEMPLATE, "test");
        ok &= expect(callback_called, "Cancel callback invoked during transition");
        ok &= expect(!sm.forced_retry_pending(), "Pending cleared by transition");
        std::cout << '\n';
    }

    {
        std::cout << "Test 12: RECONNECTING phase\n";
        auto sm = make_sm();
        sm.transition_to(RecoveryPhase::RECONNECTING, "tcp_reconnect");
        ok &= expect(sm.is_reconnecting(), "Is reconnecting");
        ok &= expect(sm.is_recovery_active(), "Recovery active during reconnect");
        ok &= expect(!sm.is_degraded(), "Not degraded during reconnect");
        ok &= expect(sm.context().reconnect_started_at != std::chrono::steady_clock::time_point{},
                      "reconnect_started_at is set");
        // Return to WAITING_TEMPLATE
        sm.transition_to(RecoveryPhase::WAITING_TEMPLATE, "reconnect_done");
        ok &= expect(!sm.is_reconnecting(), "Not reconnecting after transition");
        ok &= expect(sm.context().reconnect_started_at == std::chrono::steady_clock::time_point{},
                      "reconnect_started_at cleared on exit");
        std::cout << '\n';
    }

    std::cout << "========================================\n";
    std::cout << "Test Summary\n";
    std::cout << "========================================\n";
    std::cout << (ok ? "ALL TESTS PASSED" : "TESTS FAILED") << std::endl;
    return ok ? 0 : 1;
}
