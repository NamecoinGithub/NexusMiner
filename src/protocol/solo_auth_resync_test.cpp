#include <cassert>
#include <chrono>
#include <iostream>

enum class AuthState {
    NOT_AUTHENTICATED,
    WAITING_FOR_CHALLENGE,
    WAITING_FOR_RESULT,
    AUTHENTICATED
};

namespace {

int tests_run = 0;
int tests_passed = 0;
int tests_failed = 0;

void print_test_result(const char* name, bool passed)
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

struct SimulatedSoloAuthGuard
{
    bool m_authenticated{false};
    bool session_context_authenticated{false};
    AuthState m_auth_state{AuthState::NOT_AUTHENTICATED};
    std::chrono::steady_clock::time_point m_auth_in_flight_since{};
    int reauth_requests{0};

    bool session_context_is_authenticated() const
    {
        return session_context_authenticated;
    }

    void resync_auth_from_session_context()
    {
        if (m_authenticated || !session_context_is_authenticated()) {
            return;
        }

        m_authenticated = true;
        m_auth_state = AuthState::AUTHENTICATED;
        m_auth_in_flight_since = {};
    }

    bool should_continue_after_guard()
    {
        bool session_says_auth = session_context_is_authenticated();
        if (!m_authenticated && !session_says_auth) {
            ++reauth_requests;
            return false;
        }
        if (!m_authenticated && session_says_auth) {
            resync_auth_from_session_context();
        }
        return true;
    }

    void handle_auth_result(bool auth_success)
    {
        if (auth_success) {
            m_authenticated = true;
            m_auth_state = AuthState::AUTHENTICATED;
            m_auth_in_flight_since = {};
            return;
        }

        m_authenticated = false;
        m_auth_state = AuthState::NOT_AUTHENTICATED;
        m_auth_in_flight_since = {};
    }
};

void test_guard_requires_both_sources_to_be_unauthenticated()
{
    std::cout << "\nTest 1: guard only re-auths when both auth sources are false\n";

    SimulatedSoloAuthGuard guard;
    guard.m_authenticated = false;
    guard.session_context_authenticated = false;
    guard.m_auth_state = AuthState::NOT_AUTHENTICATED;

    bool continued = guard.should_continue_after_guard();

    print_test_result("Guard blocks processing when both sources are unauthenticated", !continued);
    print_test_result("Guard requests exactly one re-auth", guard.reauth_requests == 1);
    print_test_result("Local auth flag remains false", !guard.m_authenticated);
}

void test_guard_resyncs_stale_local_flag_from_session_context()
{
    std::cout << "\nTest 2: guard resyncs stale local auth from session context\n";

    SimulatedSoloAuthGuard guard;
    guard.m_authenticated = false;
    guard.session_context_authenticated = true;
    guard.m_auth_state = AuthState::WAITING_FOR_RESULT;
    guard.m_auth_in_flight_since = std::chrono::steady_clock::now();

    bool continued = guard.should_continue_after_guard();

    print_test_result("Guard continues processing when session context is authenticated", continued);
    print_test_result("Local auth flag is resynced to true", guard.m_authenticated);
    print_test_result("Auth enum is resynced to AUTHENTICATED",
                      guard.m_auth_state == AuthState::AUTHENTICATED);
    print_test_result("In-flight timestamp is cleared on resync",
                      guard.m_auth_in_flight_since == std::chrono::steady_clock::time_point{});
    print_test_result("Re-auth is not requested during resync", guard.reauth_requests == 0);
}

void test_auth_result_success_sets_authenticated_state()
{
    std::cout << "\nTest 3: successful auth result finalizes the enum state\n";

    SimulatedSoloAuthGuard guard;
    guard.m_authenticated = false;
    guard.m_auth_state = AuthState::WAITING_FOR_RESULT;
    guard.m_auth_in_flight_since = std::chrono::steady_clock::now();

    guard.handle_auth_result(true);

    print_test_result("Auth success sets local flag", guard.m_authenticated);
    print_test_result("Auth success sets enum to AUTHENTICATED",
                      guard.m_auth_state == AuthState::AUTHENTICATED);
    print_test_result("Auth success clears in-flight timestamp",
                      guard.m_auth_in_flight_since == std::chrono::steady_clock::time_point{});
}

void test_auth_result_failure_clears_inflight_state()
{
    std::cout << "\nTest 4: failed auth result clears local in-flight state\n";

    SimulatedSoloAuthGuard guard;
    guard.m_authenticated = true;
    guard.m_auth_state = AuthState::WAITING_FOR_RESULT;
    guard.m_auth_in_flight_since = std::chrono::steady_clock::now();

    guard.handle_auth_result(false);

    print_test_result("Auth failure clears local flag", !guard.m_authenticated);
    print_test_result("Auth failure returns enum to NOT_AUTHENTICATED",
                      guard.m_auth_state == AuthState::NOT_AUTHENTICATED);
    print_test_result("Auth failure clears in-flight timestamp",
                      guard.m_auth_in_flight_since == std::chrono::steady_clock::time_point{});
}

}  // namespace

int main()
{
    std::cout << "========================================\n";
    std::cout << "Solo Auth Resync Tests\n";
    std::cout << "========================================\n";

    test_guard_requires_both_sources_to_be_unauthenticated();
    test_guard_resyncs_stale_local_flag_from_session_context();
    test_auth_result_success_sets_authenticated_state();
    test_auth_result_failure_clears_inflight_state();

    std::cout << "\n========================================\n";
    std::cout << "Results: " << tests_passed << "/" << tests_run
              << " passed, " << tests_failed << " failed\n";
    std::cout << "========================================\n";

    return tests_failed == 0 ? 0 : 1;
}
