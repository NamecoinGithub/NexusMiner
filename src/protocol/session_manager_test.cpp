/**
 * @file session_manager_test.cpp
 * @brief Unit tests for SessionManager — core lifecycle state machine.
 *
 * Tests:
 *  1.  Constructor — default state (no coordinator)
 *  2.  Constructor — with external SessionCoordinator
 *  3.  State machine: DISCONNECTED → AUTHENTICATING → AUTHENTICATED
 *  4.  State machine: AUTHENTICATED → DEGRADED
 *  5.  State machine: full cycle back to DISCONNECTED
 *  6.  Event journal recording
 *  7.  Event journal circular buffer (16-event capacity)
 *  8.  clear_for_disconnect preserves epochs via coordinator
 *  9.  transition_to_authenticated atomic epoch+id+auth
 * 10.  commit_reward_bound() and reward state machine
 * 11.  Reward bind readiness
 * 12.  Diagnostic snapshot accuracy
 * 13.  Concurrent access safety
 * 14.  Keepalive interval clamping
 * 15.  Static name helpers
 * 16.  clear_for_reauth preserves reward address
 * 17.  mark_degraded fires expired handler
 * 18.  Session uptime tracking
 * 19.  Replay allowances
 * 20.  validate_miner_session
 */

#include "protocol/session_manager.hpp"
#include "protocol/session_coordinator.hpp"
#include "protocol/session_semantic_types.hpp"
#include <iostream>
#include <cassert>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <chrono>
#include <memory>

using namespace nexusminer::protocol;
using namespace nexusminer;

static int tests_run    = 0;
static int tests_passed = 0;
static int tests_failed = 0;

void print_result(const char* name, bool passed)
{
    ++tests_run;
    if (passed) {
        ++tests_passed;
        std::cout << "  [PASS] " << name << '\n';
    } else {
        ++tests_failed;
        std::cout << "  [FAIL] " << name << '\n';
    }
}

// Helper: create a SessionManager without io_context (no keepalive timer)
static std::shared_ptr<SessionManager> make_mgr(
    std::shared_ptr<SessionCoordinator> coord = nullptr,
    uint16_t keepalive_hours = 24)
{
    return std::make_shared<SessionManager>(keepalive_hours, nullptr, std::move(coord));
}

// ── Test 1: Default constructor state ─────────────────────────────────────────
void test_default_constructor()
{
    std::cout << "\nTest 1: Default constructor state\n";
    auto mgr = make_mgr();

    print_result("session_id starts at 0", mgr->get_session_id() == 0);
    print_result("session_epoch starts at 0", mgr->get_session_epoch() == 0);
    print_result("state is DISCONNECTED",
                 mgr->get_state() == SessionManager::SessionState::DISCONNECTED);
    print_result("is_authenticated() == false", !mgr->is_authenticated());
    print_result("is_degraded() == false", !mgr->is_degraded());
    print_result("is_reward_bound() == false", !mgr->is_reward_bound());
    print_result("can_submit() == false", !mgr->can_submit());
    print_result("can_submit_work() == false", !mgr->can_submit_work());
    print_result("can_request_get_block() == false", !mgr->can_request_get_block());
    print_result("allow_deferred_push_replay() == false",
                 !mgr->allow_deferred_push_replay());
    print_result("allow_get_block_replay() == false",
                 !mgr->allow_get_block_replay());
    print_result("coordinator is non-null (auto-created)",
                 mgr->get_coordinator() != nullptr);
}

// ── Test 2: Constructor with external SessionCoordinator ──────────────────────
void test_constructor_with_coordinator()
{
    std::cout << "\nTest 2: Constructor with external SessionCoordinator\n";
    auto coord = std::make_shared<SessionCoordinator>();
    coord->advance_session_epoch("pre-existing");

    auto mgr = make_mgr(coord);

    print_result("coordinator is the same object", mgr->get_coordinator() == coord);
    print_result("coordinator session_epoch is preserved",
                 coord->session_epoch() == SessionEpoch{1});
}

// ── Test 3: DISCONNECTED → AUTHENTICATING → AUTHENTICATED ─────────────────────
void test_state_machine_auth()
{
    std::cout << "\nTest 3: DISCONNECTED → AUTHENTICATING → AUTHENTICATED\n";
    auto mgr = make_mgr();

    // begin_auth transitions to AUTHENTICATING
    mgr->begin_auth();
    print_result("state is AUTHENTICATING after begin_auth",
                 mgr->get_state() == SessionManager::SessionState::AUTHENTICATING);
    print_result("is_authenticated() == false in AUTHENTICATING",
                 !mgr->is_authenticated());

    // commit_authenticated transitions to AUTHENTICATED
    mgr->commit_authenticated(0xDEADBEEF, ProtocolLane::STATELESS, "reward-addr");
    print_result("state is AUTHENTICATED after commit_authenticated",
                 mgr->get_state() == SessionManager::SessionState::AUTHENTICATED);
    print_result("session_id set by commit_authenticated",
                 mgr->get_session_id() == 0xDEADBEEF);
    print_result("is_authenticated() == true", mgr->is_authenticated());
    print_result("session_epoch > 0 after authentication",
                 mgr->get_session_epoch() > 0);
    print_result("can_request_get_block() == true after authentication",
                 mgr->can_request_get_block());
    print_result("allow_deferred_push_replay() == true after authentication",
                 mgr->allow_deferred_push_replay());
}

// ── Test 4: AUTHENTICATED → DEGRADED ─────────────────────────────────────────
void test_state_machine_degraded()
{
    std::cout << "\nTest 4: AUTHENTICATED → DEGRADED\n";
    auto mgr = make_mgr();
    mgr->begin_auth();
    mgr->commit_authenticated(0x12345678, ProtocolLane::STATELESS);

    mgr->mark_degraded("keepalive timeout");

    print_result("state is DEGRADED after mark_degraded",
                 mgr->get_state() == SessionManager::SessionState::DEGRADED);
    print_result("is_authenticated() == false in DEGRADED",
                 !mgr->is_authenticated());
    print_result("is_degraded() == true", mgr->is_degraded());
    print_result("can_submit() == false in DEGRADED", !mgr->can_submit());
    print_result("can_request_get_block() == false in DEGRADED",
                 !mgr->can_request_get_block());

    // Check expiry state
    auto info = mgr->get_session_info();
    print_result("expiry_state is EXPIRED",
                 info.expiry_state == SessionManager::ExpiryState::EXPIRED);
    print_result("expiry_reason contains 'keepalive timeout'",
                 info.expiry_reason.find("keepalive timeout") != std::string::npos);
}

// ── Test 5: Full cycle back to DISCONNECTED ──────────────────────────────────
void test_full_cycle()
{
    std::cout << "\nTest 5: Full cycle back to DISCONNECTED\n";
    auto mgr = make_mgr();

    mgr->begin_auth();
    mgr->commit_authenticated(0xABCD1234, ProtocolLane::STATELESS, "my-reward");
    mgr->commit_reward_bound("my-reward", "config");

    print_result("can_submit() == true before disconnect",
                 mgr->can_submit());

    // Clear for disconnect
    mgr->clear_for_disconnect("my-reward", "config", "test disconnect", true);

    print_result("state is DISCONNECTED after clear_for_disconnect",
                 mgr->get_state() == SessionManager::SessionState::DISCONNECTED);
    print_result("session_id is 0 after clear_for_disconnect",
                 mgr->get_session_id() == 0);
    print_result("is_authenticated() == false after disconnect",
                 !mgr->is_authenticated());
    print_result("can_submit() == false after disconnect",
                 !mgr->can_submit());

    // Re-auth should work
    mgr->begin_auth();
    mgr->commit_authenticated(0xBBBB2222, ProtocolLane::STATELESS);
    print_result("re-auth works after disconnect",
                 mgr->is_authenticated());
    print_result("new session_id after re-auth",
                 mgr->get_session_id() == 0xBBBB2222);
}

// ── Test 6: Event journal recording ──────────────────────────────────────────
void test_event_journal_recording()
{
    std::cout << "\nTest 6: Event journal recording\n";
    auto mgr = make_mgr();

    // Fresh manager has no events
    auto journal = mgr->get_session_event_journal();
    print_result("journal is empty initially", journal.empty());

    // begin_auth records AUTH_INIT
    mgr->begin_auth();
    journal = mgr->get_session_event_journal();
    print_result("journal has 1 event after begin_auth", journal.size() == 1);
    print_result("first event is AUTH_INIT",
                 journal[0].kind == SessionManager::SessionEventKind::AUTH_INIT);

    // commit_authenticated records AUTH_SUCCESS + SESSION_START
    mgr->commit_authenticated(0x11112222, ProtocolLane::STATELESS);
    journal = mgr->get_session_event_journal();
    print_result("journal has 3 events after commit_authenticated",
                 journal.size() == 3);
    print_result("second event is AUTH_SUCCESS",
                 journal[1].kind == SessionManager::SessionEventKind::AUTH_SUCCESS);
    print_result("third event is SESSION_START",
                 journal[2].kind == SessionManager::SessionEventKind::SESSION_START);

    // Manual event recording
    mgr->record_session_event(SessionManager::SessionEventKind::KEEPALIVE_ACK, "test ack");
    journal = mgr->get_session_event_journal();
    print_result("journal has 4 events after manual record", journal.size() == 4);
    print_result("manual event has correct kind",
                 journal[3].kind == SessionManager::SessionEventKind::KEEPALIVE_ACK);
    print_result("manual event has correct detail",
                 journal[3].detail == "test ack");
}

// ── Test 7: Event journal circular buffer capacity ───────────────────────────
void test_event_journal_capacity()
{
    std::cout << "\nTest 7: Event journal circular buffer (16 capacity)\n";
    auto mgr = make_mgr();
    mgr->begin_auth();
    mgr->commit_authenticated(0xAAAA, ProtocolLane::STATELESS);
    // Journal already has 3 events: AUTH_INIT, AUTH_SUCCESS, SESSION_START

    // Fill up to 20 more events (23 total attempted, but capacity is 16)
    for (int i = 0; i < 20; ++i) {
        mgr->record_session_event(SessionManager::SessionEventKind::KEEPALIVE_ACK,
                                  "ack-" + std::to_string(i));
    }

    auto journal = mgr->get_session_event_journal();
    print_result("journal size capped at 16",
                 journal.size() == SessionManager::SESSION_EVENT_JOURNAL_CAPACITY);

    // Oldest events were dropped; most recent events should be the keepalive acks
    print_result("newest event is KEEPALIVE_ACK",
                 journal.back().kind == SessionManager::SessionEventKind::KEEPALIVE_ACK);
    print_result("newest event detail is 'ack-19'",
                 journal.back().detail == "ack-19");

    // The oldest surviving event should be from a later batch (first 7 were dropped: 
    // 3 from auth + first 4 keepalives → oldest survivor is ack-4)
    print_result("oldest surviving event detail is 'ack-4'",
                 journal.front().detail == "ack-4");
}

// ── Test 8: clear_for_disconnect preserves epochs ─────────────────────────────
void test_clear_preserves_epochs()
{
    std::cout << "\nTest 8: clear_for_disconnect preserves epochs\n";
    auto coord = std::make_shared<SessionCoordinator>();
    auto mgr = make_mgr(coord);

    mgr->begin_auth();
    mgr->commit_authenticated(0xAAAABBBB, ProtocolLane::STATELESS);

    const auto epoch_before = mgr->get_session_epoch();
    print_result("epoch > 0 after authentication", epoch_before > 0);

    mgr->clear_for_disconnect({}, {}, "test", true);

    print_result("epoch preserved after clear_for_disconnect",
                 mgr->get_session_epoch() == epoch_before);
    print_result("coordinator epoch preserved",
                 coord->session_epoch().get() == epoch_before);
    print_result("session_id reset to 0", mgr->get_session_id() == 0);
    print_result("state is DISCONNECTED",
                 mgr->get_state() == SessionManager::SessionState::DISCONNECTED);
}

// ── Test 9: transition_to_authenticated atomic epoch+id+auth ─────────────────
void test_authenticated_atomic()
{
    std::cout << "\nTest 9: transition_to_authenticated atomic epoch+id+auth\n";
    auto coord = std::make_shared<SessionCoordinator>();
    auto mgr = make_mgr(coord);

    mgr->begin_auth();
    const auto epoch_before = coord->session_epoch().get();

    mgr->commit_authenticated(0xCAFEBABE, ProtocolLane::STATELESS);

    // All three should be set atomically
    print_result("session_epoch advanced",
                 mgr->get_session_epoch() > epoch_before);
    print_result("session_id set", mgr->get_session_id() == 0xCAFEBABE);
    print_result("is_authenticated() == true", mgr->is_authenticated());
    print_result("coordinator session_id matches",
                 coord->session_id() == SessionId{0xCAFEBABE});
    print_result("coordinator is_authenticated() == true",
                 coord->is_authenticated());

    // Second authentication bumps epoch again
    const auto epoch_after_first = mgr->get_session_epoch();
    mgr->begin_auth();
    mgr->commit_authenticated(0xDEADCAFE, ProtocolLane::STATELESS);

    print_result("epoch advances on second auth",
                 mgr->get_session_epoch() > epoch_after_first);
    print_result("session_id updated on second auth",
                 mgr->get_session_id() == 0xDEADCAFE);
}

// ── Test 10: Reward state machine ────────────────────────────────────────────
void test_reward_state_machine()
{
    std::cout << "\nTest 10: commit_reward_bound() and reward state machine\n";
    auto mgr = make_mgr();
    mgr->begin_auth();
    mgr->commit_authenticated(0x11111111, ProtocolLane::STATELESS, "my-reward-addr");

    auto info = mgr->get_session_info();
    print_result("reward_state is REQUIRED after auth with reward address",
                 info.reward_state == SessionManager::RewardState::REQUIRED);
    print_result("reward_bound is false before binding", !info.coordinator.reward_bound);
    print_result("can_submit() == false before reward binding",
                 !mgr->can_submit());

    // Begin binding
    mgr->begin_reward_binding("my-reward-addr", {}, "config");
    info = mgr->get_session_info();
    print_result("reward_state is BINDING after begin_reward_binding",
                 info.reward_state == SessionManager::RewardState::BINDING);

    // Commit bound
    mgr->commit_reward_bound("my-reward-addr", "config");
    info = mgr->get_session_info();
    print_result("reward_state is BOUND after commit_reward_bound",
                 info.reward_state == SessionManager::RewardState::BOUND);
    print_result("reward_bound is true", info.coordinator.reward_bound);
    print_result("can_submit() == true after reward binding",
                 mgr->can_submit());
    print_result("is_reward_bound() == true", mgr->is_reward_bound());

    // Reward becomes STALE when degraded
    mgr->mark_degraded("test");
    info = mgr->get_session_info();
    print_result("reward_state is STALE after degraded",
                 info.reward_state == SessionManager::RewardState::STALE);
}

// ── Test 11: Reward bind readiness ───────────────────────────────────────────
void test_reward_bind_readiness()
{
    std::cout << "\nTest 11: Reward bind readiness\n";
    auto mgr = make_mgr();

    // Not authenticated
    auto readiness = mgr->get_reward_bind_readiness();
    print_result("not ready when not authenticated", !readiness.ready);
    print_result("reason: 'not authenticated'",
                 readiness.reason.find("not authenticated") != std::string::npos);

    // Authenticated but no reward address
    mgr->begin_auth();
    mgr->commit_authenticated(0x1111, ProtocolLane::STATELESS);
    readiness = mgr->get_reward_bind_readiness();
    print_result("not ready without reward address", !readiness.ready);
    print_result("reason: 'no reward address'",
                 readiness.reason.find("no reward address") != std::string::npos);

    // Authenticated with reward address
    mgr->begin_auth();
    mgr->commit_authenticated(0x2222, ProtocolLane::STATELESS, "reward-addr");
    readiness = mgr->get_reward_bind_readiness();
    print_result("ready when authenticated with reward address", readiness.ready);
    print_result("reason: 'ready'",
                 readiness.reason.find("ready") != std::string::npos);

    // Already bound
    mgr->commit_reward_bound("reward-addr", "test");
    readiness = mgr->get_reward_bind_readiness();
    print_result("not ready when already bound", !readiness.ready);
    print_result("reason: 'already bound'",
                 readiness.reason.find("already bound") != std::string::npos);
}

// ── Test 12: Diagnostic snapshot accuracy ────────────────────────────────────
void test_diagnostic_snapshot()
{
    std::cout << "\nTest 12: Diagnostic snapshot accuracy\n";
    auto mgr = make_mgr();
    mgr->begin_auth();
    mgr->commit_authenticated(0xABCD0001, ProtocolLane::STATELESS, "diag-reward");
    mgr->commit_reward_bound("diag-reward", "test-source");

    // get_session_info / get_runtime_snapshot
    auto info = mgr->get_session_info();
    print_result("snapshot session_id matches", info.coordinator.session_id.get() == 0xABCD0001);
    print_result("snapshot state is AUTHENTICATED",
                 info.state == SessionManager::SessionState::AUTHENTICATED);
    print_result("snapshot authenticated == true", info.coordinator.authenticated);
    print_result("snapshot reward_address matches",
                 info.reward_address == "diag-reward");
    print_result("snapshot reward_bound == true", info.coordinator.reward_bound);
    print_result("snapshot reward_state is BOUND",
                 info.reward_state == SessionManager::RewardState::BOUND);
    print_result("snapshot session_epoch > 0", info.coordinator.session_epoch.get() > 0);
    print_result("snapshot session_start > 0", info.session_start > 0);
    print_result("snapshot last_activity > 0", info.last_activity > 0);
    print_result("snapshot expiry_state is FRESH",
                 info.expiry_state == SessionManager::ExpiryState::FRESH);
    print_result("snapshot ready_for_submit == true", info.ready_for_submit);
    print_result("snapshot ready_for_get_block == true", info.ready_for_get_block);

    // build_miner_session_diagnostics
    auto diag = mgr->build_miner_session_diagnostics();
    print_result("diagnostics is non-empty", !diag.empty());
    print_result("diagnostics contains 'MINER SESSION CONTAINER'",
                 diag.find("MINER SESSION CONTAINER") != std::string::npos);
    print_result("diagnostics contains 'SESSION EVENT JOURNAL'",
                 diag.find("SESSION EVENT JOURNAL") != std::string::npos);
    print_result("diagnostics contains session_id hex",
                 diag.find("abcd0001") != std::string::npos);

    // build_session_event_journal
    auto journal_str = mgr->build_session_event_journal();
    print_result("event journal string is non-empty", !journal_str.empty());
    print_result("event journal string contains 'SESSION EVENT JOURNAL'",
                 journal_str.find("SESSION EVENT JOURNAL") != std::string::npos);
}

// ── Test 13: Concurrent access safety ────────────────────────────────────────
void test_concurrent_access()
{
    std::cout << "\nTest 13: Concurrent access safety\n";
    auto coord = std::make_shared<SessionCoordinator>();
    auto mgr = make_mgr(coord);

    std::atomic<int> errors{0};
    std::vector<std::thread> threads;

    // Writer thread: cycle through auth/degrade/disconnect
    for (int i = 0; i < 4; ++i) {
        threads.emplace_back([mgr, i, &errors]() {
            for (int j = 0; j < 50; ++j) {
                try {
                    mgr->begin_auth();
                    mgr->commit_authenticated(
                        static_cast<uint32_t>(i * 1000 + j),
                        ProtocolLane::STATELESS,
                        "reward-" + std::to_string(i));
                    mgr->record_session_event(
                        SessionManager::SessionEventKind::KEEPALIVE_ACK,
                        "concurrent-" + std::to_string(j));
                    if (j % 3 == 0) {
                        mgr->mark_degraded("test-degraded");
                    }
                } catch (...) {
                    ++errors;
                }
            }
        });
    }

    // Reader thread: query state concurrently
    for (int i = 0; i < 4; ++i) {
        threads.emplace_back([mgr, &errors]() {
            for (int j = 0; j < 50; ++j) {
                try {
                    (void)mgr->get_session_id();
                    (void)mgr->get_session_epoch();
                    (void)mgr->get_state();
                    (void)mgr->is_authenticated();
                    (void)mgr->is_degraded();
                    (void)mgr->can_submit();
                    (void)mgr->get_session_info();
                    (void)mgr->get_session_event_journal();
                    (void)mgr->build_miner_session_diagnostics();
                } catch (...) {
                    ++errors;
                }
            }
        });
    }

    for (auto& t : threads) t.join();

    print_result("no exceptions in concurrent access (errors == 0)",
                 errors.load() == 0);
    print_result("session_epoch > 0 after concurrent operations",
                 mgr->get_session_epoch() > 0);
}

// ── Test 14: Keepalive interval clamping ─────────────────────────────────────
void test_keepalive_interval_clamping()
{
    std::cout << "\nTest 14: Keepalive interval clamping\n";

    // Too low → clamped to MIN (1)
    auto mgr_low = make_mgr(nullptr, 0);
    print_result("keepalive_interval clamped from 0 to 1",
                 mgr_low->get_keepalive_interval() >= 1);

    // Normal range
    auto mgr_normal = make_mgr(nullptr, 24);
    print_result("keepalive_interval 24 accepted",
                 mgr_normal->get_keepalive_interval() == 24);

    // Too high → clamped to MAX (168)
    auto mgr_high = make_mgr(nullptr, 500);
    print_result("keepalive_interval clamped from 500 to 168",
                 mgr_high->get_keepalive_interval() <= 168);

    // set_keepalive_interval respects bounds
    mgr_normal->set_keepalive_interval(0);
    print_result("set_keepalive_interval(0) clamped to >= 1",
                 mgr_normal->get_keepalive_interval() >= 1);
    mgr_normal->set_keepalive_interval(999);
    print_result("set_keepalive_interval(999) clamped to <= 168",
                 mgr_normal->get_keepalive_interval() <= 168);
}

// ── Test 15: Static name helpers ─────────────────────────────────────────────
void test_static_name_helpers()
{
    std::cout << "\nTest 15: Static name helpers\n";
    using SM = SessionManager;

    print_result("event_kind_name AUTH_INIT",
                 std::string(SM::session_event_kind_name(SM::SessionEventKind::AUTH_INIT)) == "auth_init");
    print_result("event_kind_name AUTH_SUCCESS",
                 std::string(SM::session_event_kind_name(SM::SessionEventKind::AUTH_SUCCESS)) == "auth_success");
    print_result("event_kind_name DEGRADED",
                 std::string(SM::session_event_kind_name(SM::SessionEventKind::DEGRADED)) == "forced_reauth");
    print_result("event_kind_name STALE_PACKET_DROPPED",
                 std::string(SM::session_event_kind_name(SM::SessionEventKind::STALE_PACKET_DROPPED)) == "stale_packet_dropped");

    print_result("reward_state_name NONE",
                 std::string(SM::reward_state_name(SM::RewardState::NONE)) == "NONE");
    print_result("reward_state_name BOUND",
                 std::string(SM::reward_state_name(SM::RewardState::BOUND)) == "BOUND");
    print_result("reward_state_name REJECTED",
                 std::string(SM::reward_state_name(SM::RewardState::REJECTED)) == "REJECTED");

    print_result("expiry_state_name FRESH",
                 std::string(SM::expiry_state_name(SM::ExpiryState::FRESH)) == "FRESH");
    print_result("expiry_state_name EXPIRED",
                 std::string(SM::expiry_state_name(SM::ExpiryState::EXPIRED)) == "EXPIRED");
}

// ── Test 16: clear_for_reauth preserves reward address ───────────────────────
void test_clear_for_reauth()
{
    std::cout << "\nTest 16: clear_for_reauth preserves reward address\n";
    auto mgr = make_mgr();
    mgr->begin_auth();
    mgr->commit_authenticated(0x1111, ProtocolLane::STATELESS, "my-reward");
    mgr->commit_reward_bound("my-reward", "src");

    const auto epoch_before = mgr->get_session_epoch();
    mgr->clear_for_reauth("my-reward", "src", "reauth test", true);

    auto info = mgr->get_session_info();
    print_result("state is DISCONNECTED after clear_for_reauth",
                 info.state == SessionManager::SessionState::DISCONNECTED);
    print_result("reward_address preserved",
                 info.reward_address == "my-reward");
    print_result("session_id reset to 0", info.coordinator.session_id.get() == 0);
    print_result("epoch preserved",
                 mgr->get_session_epoch() == epoch_before);
    print_result("reward_state is REQUIRED (not BOUND)",
                 info.reward_state == SessionManager::RewardState::REQUIRED);
}

// ── Test 17: mark_degraded fires expired handler ─────────────────────────────
void test_expired_handler()
{
    std::cout << "\nTest 17: mark_degraded fires expired handler\n";
    auto mgr = make_mgr();

    bool handler_called = false;
    mgr->set_session_expired_handler([&handler_called]() {
        handler_called = true;
    });

    mgr->begin_auth();
    mgr->commit_authenticated(0x2222, ProtocolLane::STATELESS);

    mgr->mark_degraded("test expire");
    print_result("expired handler fired on first DEGRADED", handler_called);

    // Second call should NOT fire (already degraded)
    handler_called = false;
    mgr->mark_degraded("second expire");
    print_result("expired handler NOT fired on duplicate DEGRADED",
                 !handler_called);
}

// ── Test 18: Session uptime tracking ─────────────────────────────────────────
void test_session_uptime()
{
    std::cout << "\nTest 18: Session uptime tracking\n";
    auto mgr = make_mgr();

    auto uptime = mgr->get_session_uptime();
    print_result("uptime is 0 before authentication",
                 uptime.count() == 0);

    mgr->begin_auth();
    mgr->commit_authenticated(0x3333, ProtocolLane::STATELESS);
    uptime = mgr->get_session_uptime();
    print_result("uptime >= 0 after authentication",
                 uptime.count() >= 0);
}

// ── Test 19: Replay allowances ───────────────────────────────────────────────
void test_replay_allowances()
{
    std::cout << "\nTest 19: Replay allowances\n";
    auto mgr = make_mgr();

    // Not authenticated
    print_result("no replay before auth (deferred)",
                 !mgr->allow_deferred_push_replay());
    print_result("no replay before auth (get_block)",
                 !mgr->allow_get_block_replay());

    // Authenticated
    mgr->begin_auth();
    mgr->commit_authenticated(0x4444, ProtocolLane::STATELESS);
    print_result("deferred push replay allowed after auth",
                 mgr->allow_deferred_push_replay());
    print_result("get_block replay allowed after auth",
                 mgr->allow_get_block_replay());

    // Degraded
    mgr->mark_degraded("test");
    print_result("no deferred push replay in DEGRADED",
                 !mgr->allow_deferred_push_replay());
    print_result("no get_block replay in DEGRADED",
                 !mgr->allow_get_block_replay());
}

// ── Test 20: validate_miner_session ──────────────────────────────────────────
void test_validate_miner_session()
{
    std::cout << "\nTest 20: validate_miner_session\n";
    auto mgr = make_mgr();

    std::string reason;
    print_result("validation fails when disconnected",
                 !mgr->validate_miner_session(&reason));
    print_result("reason: 'not authenticated'",
                 reason.find("not authenticated") != std::string::npos);

    mgr->begin_auth();
    mgr->commit_authenticated(0x5555, ProtocolLane::STATELESS);
    print_result("validation passes when authenticated",
                 mgr->validate_miner_session(&reason));
    print_result("reason: 'PASS'",
                 reason == "PASS");
}

// ── Test 21: commit_reward_rejected ──────────────────────────────────────────
void test_reward_rejected()
{
    std::cout << "\nTest 21: commit_reward_rejected\n";
    auto mgr = make_mgr();
    mgr->begin_auth();
    mgr->commit_authenticated(0x6666, ProtocolLane::STATELESS, "rej-addr");
    mgr->begin_reward_binding("rej-addr", {}, "config");

    mgr->commit_reward_rejected("rej-addr", "config", "invalid address");

    auto info = mgr->get_session_info();
    print_result("reward_state is REJECTED",
                 info.reward_state == SessionManager::RewardState::REJECTED);
    print_result("reward_bound is false", !info.coordinator.reward_bound);
    print_result("can_submit() == false after rejection",
                 !mgr->can_submit());
}

// ── Test 22: Keepalive ack / record ──────────────────────────────────────────
void test_keepalive_ack()
{
    std::cout << "\nTest 22: Keepalive ack / record\n";
    auto mgr = make_mgr();
    mgr->begin_auth();
    mgr->commit_authenticated(0x7777, ProtocolLane::STATELESS);

    mgr->note_keepalive_ack(true, "ack accepted");
    auto info = mgr->get_session_info();
    print_result("expiry_state stays FRESH after accepted ack",
                 info.expiry_state == SessionManager::ExpiryState::FRESH);

    mgr->note_keepalive_ack(false, "mismatch detail");
    info = mgr->get_session_info();
    print_result("expiry_state is FRESH even after rejected ack",
                 info.expiry_state == SessionManager::ExpiryState::FRESH);
    print_result("expiry_reason records mismatch detail",
                 info.expiry_reason == "mismatch detail");

    mgr->record_keepalive();
    info = mgr->get_session_info();
    print_result("keepalive_count >= 1 after record_keepalive",
                 info.keepalive_count >= 1);
}

// ── Test 23: begin_auth_handshake preserves crypto state ─────────────────────
void test_begin_auth_preserves_crypto()
{
    std::cout << "\nTest 23: begin_auth_handshake preserves crypto state\n";
    auto mgr = make_mgr();
    mgr->begin_auth();
    mgr->commit_authenticated(0x8888, ProtocolLane::STATELESS, "crypto-reward");
    mgr->set_chacha20_session_key({0x01, 0x02, 0x03}, "fp123", true);

    // begin_auth again should preserve chacha20 state
    mgr->begin_auth();
    auto info = mgr->get_session_info();
    print_result("chacha20_session_key preserved across re-auth",
                 !info.chacha20_session_key.empty());
    print_result("chacha20_key_fingerprint preserved",
                 info.chacha20_key_fingerprint == "fp123");
    print_result("chacha20_ready preserved", info.chacha20_ready);
    print_result("reward_address preserved across re-auth",
                 info.reward_address == "crypto-reward");
}

// ── Test 24: end_session alias ───────────────────────────────────────────────
void test_end_session()
{
    std::cout << "\nTest 24: end_session alias\n";
    auto mgr = make_mgr();
    mgr->begin_auth();
    mgr->commit_authenticated(0x9999, ProtocolLane::STATELESS);

    mgr->end_session();
    print_result("state is DISCONNECTED after end_session",
                 mgr->get_state() == SessionManager::SessionState::DISCONNECTED);
    print_result("session_id is 0 after end_session",
                 mgr->get_session_id() == 0);
}

// ── Test 25: map_auth_opcode ─────────────────────────────────────────────────
void test_map_auth_opcode()
{
    std::cout << "\nTest 25: map_auth_opcode\n";
    auto mgr_stateless = make_mgr();
    mgr_stateless->set_protocol_lane(ProtocolLane::STATELESS);
    print_result("stateless lane maps opcode 0x04 → 0xD004",
                 mgr_stateless->map_auth_opcode(0x04) == 0xD004);

    auto mgr_legacy = make_mgr();
    mgr_legacy->set_protocol_lane(ProtocolLane::LEGACY);
    print_result("legacy lane maps opcode 0x04 → 0x0004",
                 mgr_legacy->map_auth_opcode(0x04) == 0x0004);
}

// ── Test 26: Setters modify snapshot ─────────────────────────────────────────
void test_setters()
{
    std::cout << "\nTest 26: Setters modify snapshot\n";
    auto mgr = make_mgr();

    mgr->set_connection_metadata("local:1234", "remote:5678", true);
    auto info = mgr->get_session_info();
    print_result("local_endpoint set", info.local_endpoint == "local:1234");
    print_result("remote_endpoint set", info.remote_endpoint == "remote:5678");
    print_result("connected set", info.connected);

    mgr->set_prevblock_suffix({0xAA, 0xBB, 0xCC, 0xDD});
    info = mgr->get_session_info();
    print_result("prevblock_suffix set",
                 info.prevblock_suffix == std::array<uint8_t, 4>{0xAA, 0xBB, 0xCC, 0xDD});

    mgr->set_tritium_genesis({0x01, 0x02, 0x03});
    auto genesis = mgr->get_tritium_genesis();
    print_result("tritium_genesis set", genesis.size() == 3 && genesis[0] == 0x01);
}

int main()
{
    std::cout << "═══════════════════════════════════════════════════\n";
    std::cout << "SessionManager Unit Tests\n";
    std::cout << "═══════════════════════════════════════════════════\n";

    test_default_constructor();
    test_constructor_with_coordinator();
    test_state_machine_auth();
    test_state_machine_degraded();
    test_full_cycle();
    test_event_journal_recording();
    test_event_journal_capacity();
    test_clear_preserves_epochs();
    test_authenticated_atomic();
    test_reward_state_machine();
    test_reward_bind_readiness();
    test_diagnostic_snapshot();
    test_concurrent_access();
    test_keepalive_interval_clamping();
    test_static_name_helpers();
    test_clear_for_reauth();
    test_expired_handler();
    test_session_uptime();
    test_replay_allowances();
    test_validate_miner_session();
    test_reward_rejected();
    test_keepalive_ack();
    test_begin_auth_preserves_crypto();
    test_end_session();
    test_map_auth_opcode();
    test_setters();

    std::cout << "\n═══════════════════════════════════════════════════\n";
    std::cout << "Results: " << tests_passed << "/" << tests_run
              << " passed, " << tests_failed << " failed\n";
    std::cout << "═══════════════════════════════════════════════════\n";

    return (tests_failed == 0) ? 0 : 1;
}
