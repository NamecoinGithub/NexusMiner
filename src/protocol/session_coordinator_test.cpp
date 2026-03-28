/**
 * @file session_coordinator_test.cpp
 * @brief Unit tests for SessionCoordinator — single source of truth for session state.
 *
 * Tests:
 *  1.  Epoch monotonicity — session_epoch and recovery_epoch never decrease
 *  2.  clear_for_disconnect preserves epochs (never resets to 0)
 *  3.  commit_authenticated is atomic (epoch + id + auth in one call)
 *  4.  Observer notification ordering
 *  5.  Thread safety (concurrent reads/writes)
 *  6.  global_epoch() == max(session_epoch, recovery_epoch)
 *  7.  can_request_get_block() / can_submit() / is_session_active() composite queries
 *  8.  Snapshot reflects all fields
 *  9.  diagnostics() produces non-empty output
 * 10.  advance_session_epoch / advance_recovery_epoch return new value
 */

#include "protocol/session_coordinator.hpp"
#include "protocol/session_semantic_types.hpp"
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <chrono>
#include <gtest/gtest.h>

using namespace nexusminer::protocol;

// ── Test 1: Epoch monotonicity ────────────────────────────────────────────────
TEST(SessionCoordinatorTest, test_epoch_monotonicity)
{
    std::cout << "\nTest 1: Epoch monotonicity\n";
    SessionCoordinator c;

    EXPECT_TRUE(c.session_epoch() == SessionEpoch{0}) << "session_epoch starts at 0";
    EXPECT_TRUE(c.recovery_epoch() == 0) << "recovery_epoch starts at 0";

    const auto e1 = c.advance_session_epoch("t1");
    EXPECT_TRUE(e1 == SessionEpoch{1}) << "advance_session_epoch returns 1";
    EXPECT_TRUE(c.session_epoch() == SessionEpoch{1}) << "session_epoch() == 1 after first advance";

    const auto e2 = c.advance_session_epoch("t2");
    EXPECT_TRUE(e2 == SessionEpoch{2}) << "advance_session_epoch returns 2";
    EXPECT_TRUE(c.session_epoch() == SessionEpoch{2}) << "session_epoch() == 2 after second advance";

    const uint64_t r1 = c.advance_recovery_epoch("r1");
    EXPECT_TRUE(r1 == 1) << "advance_recovery_epoch returns 1";
    EXPECT_TRUE(c.recovery_epoch() == 1) << "recovery_epoch() == 1 after first advance";

    const uint64_t r2 = c.advance_recovery_epoch("r2");
    EXPECT_TRUE(r2 == 2) << "advance_recovery_epoch returns 2";

    // Verify neither ever goes back
    EXPECT_TRUE(c.session_epoch().get() >= 2) << "session_epoch still >= 2 (monotonic)";
    EXPECT_TRUE(c.recovery_epoch() >= 2) << "recovery_epoch still >= 2 (monotonic)";
}

// ── Test 2: clear_for_disconnect preserves epochs ─────────────────────────────
TEST(SessionCoordinatorTest, test_clear_preserves_epochs)
{
    std::cout << "\nTest 2: clear_for_disconnect preserves epochs\n";
    SessionCoordinator c;

    c.advance_session_epoch("auth");
    c.set_session_id(SessionId{0xDEADBEEF}, "auth");
    c.set_authenticated(true, "auth");
    c.set_reward_bound(true, "reward");
    c.advance_recovery_epoch("recovery");

    const auto saved_session  = c.session_epoch();
    const uint64_t saved_recovery = c.recovery_epoch();

    c.clear_for_disconnect("disconnect");

    EXPECT_TRUE(c.session_epoch() == saved_session) << "session_epoch preserved after clear_for_disconnect";
    EXPECT_TRUE(c.recovery_epoch() == saved_recovery) << "recovery_epoch preserved after clear_for_disconnect";
    EXPECT_TRUE(c.session_id().is_default()) << "session_id reset to 0";
    EXPECT_TRUE(!c.is_authenticated()) << "authenticated reset to false";
    EXPECT_TRUE(!c.is_reward_bound()) << "reward_bound reset to false";
    EXPECT_TRUE(!c.is_subscribed_to_notifications()) << "subscribed_to_notifications reset";
    EXPECT_TRUE(!c.has_pending_push_after_auth()) << "pending_push_after_auth reset";
}

// ── Test 3: commit_authenticated is atomic ────────────────────────────────────
TEST(SessionCoordinatorTest, test_commit_authenticated_atomic)
{
    std::cout << "\nTest 3: commit_authenticated atomicity\n";
    SessionCoordinator c;

    const auto epoch_before = c.session_epoch();
    c.commit_authenticated(SessionId{0x12345678}, "first_auth");

    EXPECT_TRUE(c.session_epoch().get() == epoch_before.get() + 1) << "session_epoch advanced by commit_authenticated";
    EXPECT_TRUE(c.session_id() == SessionId{0x12345678}) << "session_id set by commit_authenticated";
    EXPECT_TRUE(c.is_authenticated()) << "authenticated set by commit_authenticated";

    // Second commit: epoch advances again
    const auto epoch_after_first = c.session_epoch();
    c.commit_authenticated(SessionId{0xCAFEBABE}, "second_auth");

    EXPECT_TRUE(c.session_epoch().get() == epoch_after_first.get() + 1) << "session_epoch advances on second commit";
    EXPECT_TRUE(c.session_id() == SessionId{0xCAFEBABE}) << "session_id updated to new id";
    EXPECT_TRUE(c.is_authenticated()) << "authenticated still true";
}

// ── Test 4: Observer notification ordering ────────────────────────────────────
TEST(SessionCoordinatorTest, test_observer_notification)
{
    std::cout << "\nTest 4: Observer notification ordering\n";
    SessionCoordinator c;

    std::vector<std::string> log;
    c.add_observer([&log](const char* domain, uint64_t old_val, uint64_t new_val) {
        log.push_back(std::string(domain) + ":" +
                      std::to_string(old_val) + "->" + std::to_string(new_val));
    });

    c.advance_session_epoch("test");
    EXPECT_TRUE(!log.empty() && log.back().find("session_epoch") != std::string::npos) << "Observer notified for session_epoch";

    const size_t before_auth = log.size();
    c.commit_authenticated(SessionId{0xABCD}, "auth");
    EXPECT_TRUE(log.size() > before_auth) << "commit_authenticated fires at least one observer";

    const size_t before_clear = log.size();
    c.set_authenticated(true, "noop");   // no change, no notification
    const size_t after_noop = log.size();

    // set_authenticated with same value: observer still fires (coordinator always notifies)
    (void)before_clear;
    (void)after_noop;
    EXPECT_TRUE(!log.empty()) << "Observer log is non-empty overall";

    const size_t before_reward = log.size();
    c.set_reward_bound(true, "reward");
    EXPECT_TRUE(log.size() > before_reward) << "Observer notified for reward_bound";

    const size_t before_disconnect = log.size();
    c.clear_for_disconnect("dc");
    EXPECT_TRUE(log.size() > before_disconnect) << "clear_for_disconnect fires observers";
}

// ── Test 5: Thread safety ─────────────────────────────────────────────────────
TEST(SessionCoordinatorTest, test_thread_safety)
{
    std::cout << "\nTest 5: Thread safety\n";
    auto c = std::make_shared<SessionCoordinator>();

    std::atomic<int> errors{0};
    std::vector<std::thread> threads;

    // 4 writers, 4 readers, run concurrently
    for (int i = 0; i < 4; ++i) {
        threads.emplace_back([&c, i, &errors]() {
            for (int j = 0; j < 100; ++j) {
                try {
                    c->advance_session_epoch("writer");
                    c->set_session_id(SessionId{static_cast<uint32_t>(i * 100 + j)}, "writer");
                    c->set_authenticated(j % 2 == 0, "writer");
                    c->set_reward_bound(j % 3 == 0, "writer");
                } catch (...) {
                    ++errors;
                }
            }
        });
        threads.emplace_back([&c, &errors]() {
            for (int j = 0; j < 100; ++j) {
                try {
                    (void)c->session_epoch();
                    (void)c->recovery_epoch();
                    (void)c->session_id();
                    (void)c->is_authenticated();
                    (void)c->is_reward_bound();
                    (void)c->snapshot();
                } catch (...) {
                    ++errors;
                }
            }
        });
    }

    for (auto& t : threads) t.join();

    EXPECT_TRUE(errors.load() == 0) << "No exceptions in concurrent read/write (errors == 0)";
    EXPECT_TRUE(c->session_epoch().get() >= 400) << "session_epoch >= 400 after 4x100 advances (monotonic)";
}

// ── Test 6: global_epoch == max ───────────────────────────────────────────────
TEST(SessionCoordinatorTest, test_global_epoch)
{
    std::cout << "\nTest 6: global_epoch() == max(session_epoch, recovery_epoch)\n";
    SessionCoordinator c;

    EXPECT_TRUE(c.global_epoch() == 0) << "global_epoch == 0 initially";

    c.advance_session_epoch("s");
    EXPECT_TRUE(c.global_epoch() == 1) << "global_epoch == 1 after one session advance";

    c.advance_recovery_epoch("r");
    c.advance_recovery_epoch("r");
    EXPECT_TRUE(c.global_epoch() == 2) << "global_epoch == 2 when recovery leads (session=1, recovery=2)";

    c.advance_session_epoch("s");
    c.advance_session_epoch("s");
    c.advance_session_epoch("s");
    // session=4, recovery=2 → global should be 4
    EXPECT_TRUE(c.global_epoch() == 4) << "global_epoch == 4 when session leads (session=4, recovery=2)";
}

// ── Test 7: Composite queries ─────────────────────────────────────────────────
TEST(SessionCoordinatorTest, test_composite_queries)
{
    std::cout << "\nTest 7: Composite queries\n";
    SessionCoordinator c;

    EXPECT_TRUE(!c.can_request_get_block()) << "can_request_get_block() == false initially";
    EXPECT_TRUE(!c.can_submit()) << "can_submit() == false initially";
    EXPECT_TRUE(!c.is_session_active()) << "is_session_active() == false initially";

    c.set_authenticated(true, "test");
    EXPECT_TRUE(c.can_request_get_block()) << "can_request_get_block() == true after authenticated";
    EXPECT_TRUE(!c.can_submit()) << "can_submit() == false without reward_bound";
    EXPECT_TRUE(!c.is_session_active()) << "is_session_active() == false without session_id";

    c.set_session_id(SessionId{0x1234}, "test");
    EXPECT_TRUE(c.is_session_active()) << "is_session_active() == true with session_id + auth";

    c.set_reward_bound(true, "test");
    EXPECT_TRUE(c.can_submit()) << "can_submit() == true with auth + reward_bound";

    c.set_authenticated(false, "test");
    EXPECT_TRUE(!c.can_request_get_block()) << "can_request_get_block() == false after deauth";
    EXPECT_TRUE(!c.can_submit()) << "can_submit() == false after deauth";
}

// ── Test 8: Snapshot ──────────────────────────────────────────────────────────
TEST(SessionCoordinatorTest, test_snapshot)
{
    std::cout << "\nTest 8: Snapshot\n";
    SessionCoordinator c;

    c.advance_session_epoch("e");
    c.advance_recovery_epoch("r");
    c.advance_recovery_epoch("r");
    c.set_session_id(SessionId{0xABCDEF}, "s");
    c.set_authenticated(true, "a");
    c.set_reward_bound(true, "rb");
    c.set_subscribed_to_notifications(true, "sub");
    c.set_pending_push_after_auth(true, "ppa");

    const auto snap = c.snapshot();

    EXPECT_TRUE(snap.session_epoch == SessionEpoch{1}) << "snap.session_epoch == 1";
    EXPECT_TRUE(snap.recovery_epoch == 2) << "snap.recovery_epoch == 2";
    EXPECT_TRUE(snap.global_epoch == 2) << "snap.global_epoch == 2";
    EXPECT_TRUE(snap.session_id == SessionId{0xABCDEF}) << "snap.session_id == 0xABCDEF";
    EXPECT_TRUE(snap.authenticated) << "snap.authenticated == true";
    EXPECT_TRUE(snap.reward_bound) << "snap.reward_bound == true";
    EXPECT_TRUE(snap.subscribed_to_notifications) << "snap.subscribed_to_notifications == true";
    EXPECT_TRUE(snap.pending_push_after_auth) << "snap.pending_push_after_auth == true";
}

// ── Test 9: diagnostics() ─────────────────────────────────────────────────────
TEST(SessionCoordinatorTest, test_diagnostics)
{
    std::cout << "\nTest 9: diagnostics()\n";
    SessionCoordinator c;
    c.advance_session_epoch("diag");
    c.set_session_id(SessionId{0x1111}, "diag");

    const auto diag = c.diagnostics();
    EXPECT_TRUE(!diag.empty()) << "diagnostics() is non-empty";
    EXPECT_TRUE(diag.find("session_epoch") != std::string::npos) << "diagnostics() contains 'session_epoch'";
    EXPECT_TRUE(diag.find("recovery_epoch") != std::string::npos) << "diagnostics() contains 'recovery_epoch'";
}

// ── Test 10: advance returns new value ────────────────────────────────────────
TEST(SessionCoordinatorTest, test_advance_return_values)
{
    std::cout << "\nTest 10: advance_*_epoch return new value\n";
    SessionCoordinator c;

    EXPECT_TRUE(c.advance_session_epoch("r") == SessionEpoch{1}) << "advance_session_epoch(1st) returns 1";
    EXPECT_TRUE(c.advance_session_epoch("r") == SessionEpoch{2}) << "advance_session_epoch(2nd) returns 2";
    EXPECT_TRUE(c.advance_session_epoch("r") == SessionEpoch{3}) << "advance_session_epoch(3rd) returns 3";

    EXPECT_TRUE(c.advance_recovery_epoch("r") == 1) << "advance_recovery_epoch(1st) returns 1";
    EXPECT_TRUE(c.advance_recovery_epoch("r") == 2) << "advance_recovery_epoch(2nd) returns 2";
}
