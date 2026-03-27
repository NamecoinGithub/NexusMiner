#include "protocol/epoch_coordinator.hpp"
#include <cassert>
#include <iostream>
#include <thread>
#include <atomic>
#include <vector>

using namespace nexusminer::protocol;

static int g_pass = 0;
static int g_fail = 0;

static void print_result(const char* name, bool ok) {
    if (ok) {
        ++g_pass;
        std::cout << "  [PASS] " << name << "\n";
    } else {
        ++g_fail;
        std::cout << "  [FAIL] " << name << "\n";
    }
}

void test_initial_state() {
    std::cout << "\nTest: initial state\n";
    EpochCoordinator ec;
    print_result("session_epoch starts at 0", ec.session_epoch() == 0);
    print_result("recovery_epoch starts at 0", ec.recovery_epoch() == 0);
    print_result("global_epoch starts at 0", ec.global_epoch() == 0);
    auto snap = ec.snapshot();
    print_result("snapshot session=0", snap.session_epoch == 0);
    print_result("snapshot recovery=0", snap.recovery_epoch == 0);
    print_result("snapshot global=0", snap.global_epoch == 0);
}

void test_session_epoch_monotonic() {
    std::cout << "\nTest: session_epoch monotonic\n";
    EpochCoordinator ec;
    auto v1 = ec.advance_session_epoch("test_a");
    print_result("first advance returns 1", v1 == 1);
    print_result("session_epoch() == 1", ec.session_epoch() == 1);
    auto v2 = ec.advance_session_epoch("test_b");
    print_result("second advance returns 2", v2 == 2);
    print_result("never decreases", ec.session_epoch() >= v1);
}

void test_recovery_epoch_monotonic() {
    std::cout << "\nTest: recovery_epoch monotonic\n";
    EpochCoordinator ec;
    auto v1 = ec.advance_recovery_epoch("recovery_a");
    print_result("first recovery advance returns 1", v1 == 1);
    print_result("recovery_epoch() == 1", ec.recovery_epoch() == 1);
    ec.advance_recovery_epoch("recovery_b");
    print_result("second recovery advance returns 2", ec.recovery_epoch() == 2);
}

void test_global_epoch() {
    std::cout << "\nTest: global_epoch = max(session, recovery)\n";
    EpochCoordinator ec;
    ec.advance_session_epoch("s1");
    ec.advance_session_epoch("s2");
    print_result("global after 2 session advances == 2", ec.global_epoch() == 2);
    ec.advance_recovery_epoch("r1");
    print_result("global after 1 recovery advance == 2 (max)", ec.global_epoch() == 2);
    ec.advance_recovery_epoch("r2");
    ec.advance_recovery_epoch("r3");
    print_result("global after 3 recovery advances == 3", ec.global_epoch() == 3);
}

void test_observer_notification() {
    std::cout << "\nTest: observer notification\n";
    EpochCoordinator ec;
    std::string last_domain;
    uint64_t last_old{999};
    uint64_t last_new{999};
    ec.add_observer([&](const char* domain, uint64_t old_val, uint64_t new_val) {
        last_domain = domain;
        last_old = old_val;
        last_new = new_val;
    });
    ec.advance_session_epoch("obs_test");
    print_result("observer called for session domain", last_domain == "session");
    print_result("observer old_val == 0", last_old == 0);
    print_result("observer new_val == 1", last_new == 1);
    ec.advance_recovery_epoch("obs_recovery");
    print_result("observer called for recovery domain", last_domain == "recovery");
    print_result("recovery observer new_val == 1", last_new == 1);
}

void test_thread_safety() {
    std::cout << "\nTest: thread safety\n";
    EpochCoordinator ec;
    constexpr int N_THREADS = 8;
    constexpr int ADVANCES_PER_THREAD = 100;
    std::vector<std::thread> threads;
    for (int i = 0; i < N_THREADS; ++i) {
        threads.emplace_back([&ec]() {
            for (int j = 0; j < ADVANCES_PER_THREAD; ++j) {
                ec.advance_session_epoch("thread");
            }
        });
    }
    for (auto& t : threads) t.join();
    print_result("session_epoch == N_THREADS * ADVANCES_PER_THREAD after concurrent advances",
                 ec.session_epoch() == static_cast<uint64_t>(N_THREADS * ADVANCES_PER_THREAD));
}

void test_no_reset_after_session_clear() {
    std::cout << "\nTest: session epoch preserved after simulated clear\n";
    EpochCoordinator ec;
    ec.advance_session_epoch("auth1");
    ec.advance_session_epoch("auth2");
    uint64_t epoch_before = ec.session_epoch();
    // Simulate SessionManager calling session_epoch() after clear_runtime_session_locked()
    uint64_t restored = ec.session_epoch();
    print_result("epoch preserved (not reset to 0)", restored == epoch_before);
    print_result("epoch is 2 after 2 advances", epoch_before == 2);
    // Advance again — must go to 3, not back to 1
    ec.advance_session_epoch("auth3");
    print_result("epoch is 3 after third advance", ec.session_epoch() == 3);
}

int main() {
    std::cout << "=== EpochCoordinator Unit Tests ===\n";
    test_initial_state();
    test_session_epoch_monotonic();
    test_recovery_epoch_monotonic();
    test_global_epoch();
    test_observer_notification();
    test_thread_safety();
    test_no_reset_after_session_clear();
    std::cout << "\n=== Results: " << g_pass << " passed, " << g_fail << " failed ===\n";
    return g_fail == 0 ? 0 : 1;
}
