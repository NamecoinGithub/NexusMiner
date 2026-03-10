#include <chrono>
#include <cstdint>
#include <iostream>
#include <vector>

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
    struct AuthoritativeSession {
        bool authenticated{false};
        uint32_t session_id{0};
        bool reward_bound{false};
        std::vector<unsigned char> chacha_key;
    };

    bool m_authenticated{false};
    uint32_t m_session_id{0};
    bool m_reward_bound{false};
    std::vector<unsigned char> m_chacha_key;
    bool session_context_authenticated{false};
    AuthState m_auth_state{AuthState::NOT_AUTHENTICATED};
    std::chrono::steady_clock::time_point m_auth_in_flight_since{};
    int reauth_requests{0};
    int packet_build_requests{0};
    AuthoritativeSession authoritative{};

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

    void refresh_cached_session_state()
    {
        if (m_authenticated != authoritative.authenticated) {
            m_authenticated = authoritative.authenticated;
        }
        if (m_session_id != authoritative.session_id) {
            m_session_id = authoritative.session_id;
        }
        if (m_reward_bound != authoritative.reward_bound) {
            m_reward_bound = authoritative.reward_bound;
        }
        if (m_chacha_key != authoritative.chacha_key) {
            m_chacha_key = authoritative.chacha_key;
        }
    }

    void process_messages_entry()
    {
        refresh_cached_session_state();
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

    bool validate_authoritative_session() const
    {
        return authoritative.authenticated;
    }

    bool send_set_reward()
    {
        if (!validate_authoritative_session()) {
            return false;
        }

        ++packet_build_requests;
        return true;
    }

    bool has_authoritative_key() const
    {
        return !authoritative.chacha_key.empty();
    }

    struct AcceptedSnapshot
    {
        uint32_t height{0};
        uint32_t channel{0};
        bool used_fallback{false};
    };

    bool m_last_submitted_valid{false};
    uint32_t m_last_submitted_height{0};
    uint32_t m_last_submitted_channel{0};

    AcceptedSnapshot on_block_accepted(uint32_t fallback_height, uint32_t fallback_channel)
    {
        const bool had_last_submitted = m_last_submitted_valid;
        m_last_submitted_valid = false;

        AcceptedSnapshot accepted{m_last_submitted_height, m_last_submitted_channel, false};
        if (!had_last_submitted) {
            accepted.height = fallback_height;
            accepted.channel = fallback_channel;
            accepted.used_fallback = true;
        }
        return accepted;
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

void test_auth_result_failure_clears_in_flight_state()
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

void test_cached_session_state_resyncs_from_authoritative_container()
{
    std::cout << "\nTest 5: cached local session state resyncs from authoritative container\n";

    SimulatedSoloAuthGuard guard;
    guard.m_authenticated = false;
    guard.m_session_id = 0;
    guard.m_reward_bound = false;
    guard.authoritative = {true, 0x12345678, true, std::vector<unsigned char>(32, 0xAB)};

    guard.refresh_cached_session_state();

    print_test_result("Auth flag resynced from authoritative container", guard.m_authenticated);
    print_test_result("Session ID resynced from authoritative container", guard.m_session_id == 0x12345678);
    print_test_result("Reward binding resynced from authoritative container", guard.m_reward_bound);
    print_test_result("ChaCha20 key resynced from authoritative container",
                      guard.m_chacha_key == std::vector<unsigned char>(32, 0xAB));
}

void test_reward_send_validates_before_packet_build()
{
    std::cout << "\nTest 6: reward send guard runs before packet build\n";

    SimulatedSoloAuthGuard guard;
    guard.authoritative.authenticated = false;

    const bool sent = guard.send_set_reward();

    print_test_result("Reward send fails when authoritative session is invalid", !sent);
    print_test_result("Reward send does not build a packet before validation", guard.packet_build_requests == 0);
}

void test_process_messages_entry_resyncs_cached_reward_binding()
{
    std::cout << "\nTest 7: process_messages entry resyncs cached reward binding before handlers run\n";

    SimulatedSoloAuthGuard guard;
    guard.m_authenticated = false;
    guard.m_session_id = 0;
    guard.m_reward_bound = false;
    guard.authoritative = {true, 0xABCDEF01, true, std::vector<unsigned char>(32, 0xCD)};

    guard.process_messages_entry();

    print_test_result("Process entry resyncs auth flag", guard.m_authenticated);
    print_test_result("Process entry resyncs session ID", guard.m_session_id == 0xABCDEF01);
    print_test_result("Process entry resyncs reward binding", guard.m_reward_bound);
    print_test_result("Process entry resyncs ChaCha20 key",
                      guard.m_chacha_key == std::vector<unsigned char>(32, 0xCD));
}

void test_submit_requires_authoritative_chacha20_key()
{
    std::cout << "\nTest 8: submit path only accepts authoritative session key\n";

    SimulatedSoloAuthGuard guard;
    guard.m_chacha_key = std::vector<unsigned char>(32, 0xAA);
    guard.authoritative.chacha_key.clear();
    const bool can_submit = guard.has_authoritative_key();

    print_test_result("Submit fails when authoritative key is empty even if local cache is populated",
                      !can_submit);
}

void test_block_accepted_consumes_snapshot_before_future_fallback()
{
    std::cout << "\nTest 9: accepted-block snapshot is consumed before later fallback use\n";

    SimulatedSoloAuthGuard guard;
    guard.m_last_submitted_valid = true;
    guard.m_last_submitted_height = 101;
    guard.m_last_submitted_channel = 2;

    const auto first_accept = guard.on_block_accepted(202, 1);
    const auto second_accept = guard.on_block_accepted(202, 1);

    print_test_result("First accept uses submitted height", first_accept.height == 101);
    print_test_result("First accept uses submitted channel", first_accept.channel == 2);
    print_test_result("Accepted snapshot is invalidated after first consumption", !guard.m_last_submitted_valid);
    print_test_result("Second accept falls back instead of reusing stale submitted height",
                      second_accept.height == 202);
    print_test_result("Second accept falls back instead of reusing stale submitted channel",
                      second_accept.channel == 1);
    print_test_result("Second accept records that fallback was used", second_accept.used_fallback);
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
    test_auth_result_failure_clears_in_flight_state();
    test_cached_session_state_resyncs_from_authoritative_container();
    test_reward_send_validates_before_packet_build();
    test_process_messages_entry_resyncs_cached_reward_binding();
    test_submit_requires_authoritative_chacha20_key();
    test_block_accepted_consumes_snapshot_before_future_fallback();

    std::cout << "\n========================================\n";
    std::cout << "Results: " << tests_passed << "/" << tests_run
              << " passed, " << tests_failed << " failed\n";
    std::cout << "========================================\n";

    return tests_failed == 0 ? 0 : 1;
}
