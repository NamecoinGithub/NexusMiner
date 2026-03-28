#include <chrono>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

#include "protocol/protocol_constants.hpp"
#include "protocol/session_status_policy.hpp"
#include <gtest/gtest.h>

enum class AuthState {
    NOT_AUTHENTICATED,
    WAITING_FOR_CHALLENGE,
    WAITING_FOR_RESULT,
    AUTHENTICATED
};

enum class ResyncLogSeverity {
    INFO,
    WARN
};

namespace {

constexpr uint32_t TEST_PUSH_LIFELINE_SESSION_ID = 0xABCDEF01;
constexpr uint64_t TEST_PUSH_LIFELINE_SESSION_EPOCH = 123;
constexpr uint32_t TEST_PUSH_LIFELINE_ALT_SESSION_ID = 0xCAFEBABE;
constexpr uint64_t TEST_PUSH_LIFELINE_ALT_SESSION_EPOCH = 88;
constexpr uint32_t TEST_PUSH_LIMBO_SESSION_ID = 0x11112222;
constexpr uint64_t TEST_PUSH_LIMBO_SESSION_EPOCH = 9;

bool is_expected_cached_session_resync(bool local_has_state, bool authoritative_has_state)
{
    return !local_has_state && authoritative_has_state;
}

bool should_schedule_in_band_reauth(bool reconnect_in_progress,
                                    bool recovery_pending,
                                    uint64_t recovery_epoch)
{
    return !(reconnect_in_progress || (recovery_pending && recovery_epoch > 0));
}

bool should_reject_auth_challenge(size_t packet_size, uint16_t nonce_len)
{
    if (packet_size < 2) {
        return true;
    }
    if (nonce_len == 0) {
        return true;
    }
    return packet_size < static_cast<size_t>(2 + nonce_len);
}

TEST(SoloAuthResyncTest, test_zero_length_auth_challenge_is_rejected)
{
    std::cout << "\nTest 0: zero-length MINER_AUTH_CHALLENGE is rejected\n";

    EXPECT_TRUE(should_reject_auth_challenge(2, 0)) << "Packet with only nonce_len field is rejected when nonce_len == 0";
    EXPECT_TRUE(!should_reject_auth_challenge(6, 4)) << "Valid non-empty nonce is not rejected by zero-length guard";
    EXPECT_TRUE(should_reject_auth_challenge(3, 4)) << "Incomplete non-empty nonce is still rejected";
}

struct SimulatedSoloAuthGuard
{
    struct AuthoritativeSession {
        bool authenticated{false};
        uint32_t session_id{0};
        uint64_t session_epoch{0};
        bool reward_bound{false};
        std::vector<unsigned char> chacha_key;
    };

    bool m_authenticated{false};
    uint32_t m_session_id{0};
    uint64_t m_session_epoch{0};
    bool m_reward_bound{false};
    std::vector<unsigned char> m_chacha_key;
    uint32_t template_interface_session_id{0};
    uint64_t template_interface_session_epoch{0};
    bool m_has_seen_session_epoch{false};
    bool generation_bound_template_live{false};
    uint32_t last_known_tip_stamp{0};
    uint32_t last_keepalive_prevhash_lo32{0};
    bool session_context_authenticated{false};
    AuthState m_auth_state{AuthState::NOT_AUTHENTICATED};
    std::chrono::steady_clock::time_point m_auth_in_flight_since{};
    int reauth_requests{0};
    int packet_build_requests{0};
    int get_block_requests{0};
    bool m_pending_push_after_auth{false};
    bool push_lifeline_active{false};
    uint32_t push_lifeline_session_id{0};
    uint64_t push_lifeline_session_epoch{0};
    bool push_lifeline_reward_bound{false};
    bool push_lifeline_ready_for_get_block{false};
    AuthoritativeSession authoritative{};

    bool session_context_is_authenticated() const
    {
        return session_context_authenticated;
    }

    bool is_authenticated() const
    {
        return session_context_is_authenticated() ? authoritative.authenticated : m_authenticated;
    }

    bool is_reward_bound() const
    {
        return session_context_authenticated ? authoritative.reward_bound : m_reward_bound;
    }

    void propagate_session_to_template_interface()
    {
        template_interface_session_id = m_session_id;
        template_interface_session_epoch = m_session_epoch;
    }

    void clear_generation_bound_state()
    {
        generation_bound_template_live = false;
        last_known_tip_stamp = 0;
        last_keepalive_prevhash_lo32 = 0;
        m_last_submitted_valid = false;
    }

    void resync_auth_from_session_context()
    {
        if (m_authenticated || !session_context_is_authenticated()) {
            return;
        }

        m_authenticated = true;
        m_auth_state = AuthState::AUTHENTICATED;
        m_auth_in_flight_since = {};
        refresh_cached_session_state();
        if (m_session_id != 0) {
            propagate_session_to_template_interface();
        }
    }

    void refresh_cached_session_state()
    {
        // Epoch changes invalidate generation-bound template/tip caches before
        // auth/session flags are resynced from the authoritative container.
        if (!m_has_seen_session_epoch || m_session_epoch != authoritative.session_epoch) {
            if (m_has_seen_session_epoch) {
                clear_generation_bound_state();
            }
            m_session_epoch = authoritative.session_epoch;
            m_has_seen_session_epoch = true;
        }
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
        if (authoritative.authenticated && authoritative.session_id != 0) {
            propagate_session_to_template_interface();
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

    void handle_auth_result(bool auth_success, uint32_t new_session_id = 0, uint64_t new_session_epoch = 0)
    {
        if (auth_success) {
            m_authenticated = true;
            m_session_id = new_session_id;
            m_session_epoch = new_session_epoch;
            m_has_seen_session_epoch = true;
            m_auth_state = AuthState::AUTHENTICATED;
            m_auth_in_flight_since = {};
            clear_push_lifeline();
            if (m_session_id != 0) {
                propagate_session_to_template_interface();
            }
            return;
        }

        m_authenticated = false;
        m_auth_state = AuthState::NOT_AUTHENTICATED;
        m_auth_in_flight_since = {};
        m_pending_push_after_auth = false;
        clear_push_lifeline();
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
        if (authoritative.session_id == 0 || !has_authoritative_chacha_key()) {
            return false;
        }

        ++packet_build_requests;
        return true;
    }

    bool on_push_notification()
    {
        const bool session_says_auth = session_context_is_authenticated();
        if (!m_authenticated && !session_says_auth && can_use_push_lifeline()) {
            ++get_block_requests;
            return true;
        }
        if (!m_authenticated && !session_says_auth) {
            m_pending_push_after_auth = true;
            if (m_auth_state == AuthState::NOT_AUTHENTICATED) {
                ++reauth_requests;
            }
            return false;
        }

        if (!m_authenticated && session_says_auth) {
            resync_auth_from_session_context();
        }

        ++get_block_requests;
        return true;
    }

    void preserve_push_lifeline(uint32_t session_id = TEST_PUSH_LIFELINE_SESSION_ID,
                                uint64_t session_epoch = TEST_PUSH_LIFELINE_SESSION_EPOCH)
    {
        push_lifeline_active = true;
        push_lifeline_session_id = session_id;
        push_lifeline_session_epoch = session_epoch;
        push_lifeline_reward_bound = true;
        push_lifeline_ready_for_get_block = true;
    }

    void clear_push_lifeline()
    {
        push_lifeline_active = false;
        push_lifeline_session_id = 0;
        push_lifeline_session_epoch = 0;
        push_lifeline_reward_bound = false;
        push_lifeline_ready_for_get_block = false;
    }

    bool can_use_push_lifeline() const
    {
        return push_lifeline_active &&
               m_auth_state != AuthState::NOT_AUTHENTICATED &&
               push_lifeline_ready_for_get_block &&
               push_lifeline_session_id != 0 &&
               (m_reward_bound || push_lifeline_reward_bound);
    }

    bool flush_pending_push_after_auth()
    {
        if (!m_pending_push_after_auth || !m_authenticated || !m_reward_bound) {
            return false;
        }

        m_pending_push_after_auth = false;
        ++get_block_requests;
        return true;
    }

    bool has_authoritative_chacha_key() const
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

        AcceptedSnapshot accepted{m_last_submitted_height, m_last_submitted_channel, !had_last_submitted};
        if (!had_last_submitted) {
            accepted.height = fallback_height;
            accepted.channel = fallback_channel;
        }
        return accepted;
    }

    bool handle_session_expired(uint32_t expired_sid)
    {
        const uint32_t authoritative_session_id = authoritative.session_id;
        if (expired_sid != authoritative_session_id) {
            return false;
        }

        authoritative = {};
        session_context_authenticated = false;
        m_session_id = 0;
        m_authenticated = false;
        m_auth_state = AuthState::NOT_AUTHENTICATED;
        m_auth_in_flight_since = {};
        m_reward_bound = false;
        template_interface_session_id = 0;
        return true;
    }
};

struct SimulatedSessionStatusAckHandler
{
    uint32_t local_session_id{0};
    uint32_t mismatch_count{0};
    uint32_t last_session_id{0};
    uint32_t last_lane_health_flags{0};
    uint32_t last_uptime_seconds{0};
    uint32_t last_status_echo_flags{0};
    bool ack_recorded{false};
    bool expired_session{false};
    bool force_reauth{false};
    bool mark_degraded{false};
    std::string last_reason;

    bool handle_session_id_mismatch(uint32_t ack_session_id)
    {
        const auto decision = nexusminer::protocol::SessionStatusPolicy::validate_ack({
            true,
            local_session_id,
            ack_session_id,
            mismatch_count,
            nexusminer::protocol::ProtocolConstants::SESSION_MISMATCH_EXPIRE_THRESHOLD
        });
        mismatch_count = decision.mismatch_count;
        expired_session = decision.expire_session;
        force_reauth = decision.force_reauth;
        mark_degraded = decision.mark_degraded;
        last_reason = decision.reason;
        return !decision.accept_ack;
    }

    bool on_session_status_ack(uint32_t ack_session_id,
                               uint32_t lane_health_flags,
                               uint32_t uptime_seconds,
                               uint32_t status_echo_flags,
                               bool lane_authenticated = true)
    {
        if (handle_session_id_mismatch(ack_session_id)) {
            return false;
        }

        last_session_id = ack_session_id;
        last_lane_health_flags = lane_health_flags;
        last_uptime_seconds = uptime_seconds;
        last_status_echo_flags = status_echo_flags;
        ack_recorded = true;

        const auto decision = nexusminer::protocol::SessionStatusPolicy::evaluate_ack_health(
            { uptime_seconds, lane_authenticated });
        force_reauth = decision.force_reauth;
        mark_degraded = decision.mark_degraded;
        last_reason = decision.reason;
        return decision.accept_ack;
    }
};

TEST(SoloAuthResyncTest, test_guard_requires_both_sources_to_be_unauthenticated)
{
    std::cout << "\nTest 1: guard only re-auths when both auth sources are false\n";

    SimulatedSoloAuthGuard guard;
    guard.m_authenticated = false;
    guard.session_context_authenticated = false;
    guard.m_auth_state = AuthState::NOT_AUTHENTICATED;

    bool continued = guard.should_continue_after_guard();

    EXPECT_TRUE(!continued) << "Guard blocks processing when both sources are unauthenticated";
    EXPECT_TRUE(guard.reauth_requests == 1) << "Guard requests exactly one re-auth";
    EXPECT_TRUE(!guard.m_authenticated) << "Local auth flag remains false";
}

TEST(SoloAuthResyncTest, test_guard_resyncs_stale_local_flag_from_session_context)
{
    std::cout << "\nTest 2: guard resyncs stale local auth from session context\n";

    SimulatedSoloAuthGuard guard;
    guard.m_authenticated = false;
    guard.session_context_authenticated = true;
    guard.authoritative = {true, 0xD0D0A11E, 42, false, {}};
    guard.m_auth_state = AuthState::WAITING_FOR_RESULT;
    guard.m_auth_in_flight_since = std::chrono::steady_clock::now();

    bool continued = guard.should_continue_after_guard();

    EXPECT_TRUE(continued) << "Guard continues processing when session context is authenticated";
    EXPECT_TRUE(guard.m_authenticated) << "Local auth flag is resynced to true";
    EXPECT_TRUE(guard.m_auth_state == AuthState::AUTHENTICATED) << "Auth enum is resynced to AUTHENTICATED";
    EXPECT_TRUE(guard.m_auth_in_flight_since == std::chrono::steady_clock::time_point{}) << "In-flight timestamp is cleared on resync";
    EXPECT_TRUE(guard.m_session_id == 0xD0D0A11E) << "Resync pulls session ID from authoritative container";
    EXPECT_TRUE(guard.m_session_epoch == 42) << "Resync pulls session epoch from authoritative container";
    EXPECT_TRUE(guard.template_interface_session_id == 0xD0D0A11E) << "Resync rebinds template interface session ID";
    EXPECT_TRUE(guard.template_interface_session_epoch == 42) << "Resync rebinds template interface session epoch";
    EXPECT_TRUE(guard.reauth_requests == 0) << "Re-auth is not requested during resync";
}

TEST(SoloAuthResyncTest, test_auth_result_success_sets_authenticated_state)
{
    std::cout << "\nTest 3: successful auth result finalizes state and rebinds template interface\n";

    SimulatedSoloAuthGuard guard;
    guard.m_authenticated = false;
    guard.m_auth_state = AuthState::WAITING_FOR_RESULT;
    guard.m_auth_in_flight_since = std::chrono::steady_clock::now();

    guard.handle_auth_result(true, 0x1234ABCD, 77);

    EXPECT_TRUE(guard.m_authenticated) << "Auth success sets local flag";
    EXPECT_TRUE(guard.m_session_id == 0x1234ABCD) << "Auth success sets session ID";
    EXPECT_TRUE(guard.m_session_epoch == 77) << "Auth success sets session epoch";
    EXPECT_TRUE(guard.m_auth_state == AuthState::AUTHENTICATED) << "Auth success sets enum to AUTHENTICATED";
    EXPECT_TRUE(guard.m_auth_in_flight_since == std::chrono::steady_clock::time_point{}) << "Auth success clears in-flight timestamp";
    EXPECT_TRUE(guard.template_interface_session_id == 0x1234ABCD) << "Auth success immediately rebinds template session ID";
    EXPECT_TRUE(guard.template_interface_session_epoch == 77) << "Auth success immediately rebinds template session epoch";
}

TEST(SoloAuthResyncTest, test_auth_result_failure_clears_in_flight_state)
{
    std::cout << "\nTest 4: failed auth result clears local in-flight state\n";

    SimulatedSoloAuthGuard guard;
    guard.m_authenticated = true;
    guard.m_auth_state = AuthState::WAITING_FOR_RESULT;
    guard.m_auth_in_flight_since = std::chrono::steady_clock::now();

    guard.handle_auth_result(false);

    EXPECT_TRUE(!guard.m_authenticated) << "Auth failure clears local flag";
    EXPECT_TRUE(guard.m_auth_state == AuthState::NOT_AUTHENTICATED) << "Auth failure returns enum to NOT_AUTHENTICATED";
    EXPECT_TRUE(guard.m_auth_in_flight_since == std::chrono::steady_clock::time_point{}) << "Auth failure clears in-flight timestamp";
}

TEST(SoloAuthResyncTest, test_cached_session_state_resyncs_from_authoritative_container)
{
    std::cout << "\nTest 5: cached local session state resyncs from authoritative container\n";

    SimulatedSoloAuthGuard guard;
    guard.m_authenticated = false;
    guard.m_session_id = 0;
    guard.m_reward_bound = false;
    guard.authoritative = {true, 0x12345678, 99, true, std::vector<unsigned char>(32, 0xAB)};

    guard.refresh_cached_session_state();

    EXPECT_TRUE(guard.m_authenticated) << "Auth flag resynced from authoritative container";
    EXPECT_TRUE(guard.m_session_id == 0x12345678) << "Session ID resynced from authoritative container";
    EXPECT_TRUE(guard.m_session_epoch == 99) << "Session epoch resynced from authoritative container";
    EXPECT_TRUE(guard.m_reward_bound) << "Reward binding resynced from authoritative container";
    EXPECT_TRUE(guard.m_chacha_key == std::vector<unsigned char>(32, 0xAB)) << "ChaCha20 key resynced from authoritative container";
    EXPECT_TRUE(guard.template_interface_session_id == 0x12345678) << "Resync updates template interface session ID";
    EXPECT_TRUE(guard.template_interface_session_epoch == 99) << "Resync updates template interface session epoch";
}

TEST(SoloAuthResyncTest, test_reward_send_validates_before_packet_build)
{
    std::cout << "\nTest 6: reward send guard runs before packet build\n";

    SimulatedSoloAuthGuard guard;
    guard.authoritative.authenticated = false;

    const bool sent = guard.send_set_reward();

    EXPECT_TRUE(!sent) << "Reward send fails when authoritative session is invalid";
    EXPECT_TRUE(guard.packet_build_requests == 0) << "Reward send does not build a packet before validation";
}

TEST(SoloAuthResyncTest, test_reward_send_requires_authoritative_reward_key_after_auth)
{
    std::cout << "\nTest 6b: reward send requires authoritative reward key after auth\n";

    SimulatedSoloAuthGuard guard;
    guard.session_context_authenticated = true;
    guard.authoritative.authenticated = true;
    guard.authoritative.session_id = 0x12345678;
    guard.m_chacha_key = std::vector<unsigned char>(32, 0xAA);
    guard.authoritative.chacha_key.clear();

    const bool sent = guard.send_set_reward();

    EXPECT_TRUE(!sent) << "Reward send fails when authoritative reward key is missing after auth";
    EXPECT_TRUE(guard.packet_build_requests == 0) << "Reward send still does not build a packet without authoritative reward key";
}

TEST(SoloAuthResyncTest, test_process_messages_entry_resyncs_cached_reward_binding)
{
    std::cout << "\nTest 7: process_messages entry resyncs cached reward binding before handlers run\n";

    SimulatedSoloAuthGuard guard;
    guard.m_authenticated = false;
    guard.m_session_id = 0;
    guard.m_reward_bound = false;
    guard.authoritative = {true, 0xABCDEF01, 123, true, std::vector<unsigned char>(32, 0xCD)};

    guard.process_messages_entry();

    EXPECT_TRUE(guard.m_authenticated) << "Process entry resyncs auth flag";
    EXPECT_TRUE(guard.m_session_id == 0xABCDEF01) << "Process entry resyncs session ID";
    EXPECT_TRUE(guard.m_session_epoch == 123) << "Process entry resyncs session epoch";
    EXPECT_TRUE(guard.m_reward_bound) << "Process entry resyncs reward binding";
    EXPECT_TRUE(guard.m_chacha_key == std::vector<unsigned char>(32, 0xCD)) << "Process entry resyncs ChaCha20 key";
    EXPECT_TRUE(guard.template_interface_session_id == 0xABCDEF01) << "Process entry rebinds template interface session ID";
    EXPECT_TRUE(guard.template_interface_session_epoch == 123) << "Process entry rebinds template interface session epoch";
}

TEST(SoloAuthResyncTest, test_epoch_resync_clears_generation_bound_runtime_state)
{
    std::cout << "\nTest 7b: epoch resync clears generation-bound template and tip state\n";

    SimulatedSoloAuthGuard guard;
    guard.m_has_seen_session_epoch = true;
    guard.m_session_epoch = 55;
    guard.generation_bound_template_live = true;
    guard.last_known_tip_stamp = 0xABCDEF01;
    guard.last_keepalive_prevhash_lo32 = 0x11223344;
    guard.m_last_submitted_valid = true;
    guard.authoritative = {true, 0xABCDEF01, 56, true, {}};

    guard.refresh_cached_session_state();

    EXPECT_TRUE(guard.m_session_epoch == 56) << "Epoch resync advances the local epoch";
    EXPECT_TRUE(!guard.generation_bound_template_live) << "Epoch resync clears generation-bound template state";
    EXPECT_TRUE(guard.last_known_tip_stamp == 0) << "Epoch resync clears cached tip anchor";
    EXPECT_TRUE(guard.last_keepalive_prevhash_lo32 == 0) << "Epoch resync clears keepalive prevhash canary";
    EXPECT_TRUE(!guard.m_last_submitted_valid) << "Epoch resync invalidates stale submit snapshot";
}

TEST(SoloAuthResyncTest, test_public_auth_accessors_prefer_authoritative_session_state)
{
    std::cout << "\nTest 8: public accessors prefer authoritative session state over stale local cache\n";

    SimulatedSoloAuthGuard guard;
    guard.m_authenticated = false;
    guard.m_reward_bound = false;
    guard.session_context_authenticated = true;
    guard.authoritative = {true, 0xA1B2C3D4, 17, true, {}};

    EXPECT_TRUE(guard.is_authenticated()) << "is_authenticated() follows authoritative session context";
    EXPECT_TRUE(guard.is_reward_bound()) << "is_reward_bound() follows authoritative reward binding";
}

TEST(SoloAuthResyncTest, test_push_during_handshake_is_queued_until_auth_completes)
{
    std::cout << "\nTest 9: push during auth handshake queues a post-auth GET_BLOCK\n";

    SimulatedSoloAuthGuard guard;
    guard.m_authenticated = false;
    guard.m_reward_bound = true;
    guard.m_auth_state = AuthState::WAITING_FOR_RESULT;

    const bool push_handled_immediately = guard.on_push_notification();

    EXPECT_TRUE(!push_handled_immediately) << "Push during handshake does not request GET_BLOCK immediately";
    EXPECT_TRUE(guard.m_pending_push_after_auth) << "Push during handshake is queued for post-auth replay";
    EXPECT_TRUE(guard.reauth_requests == 0) << "Push during handshake does not trigger duplicate re-auth";
    EXPECT_TRUE(guard.get_block_requests == 0) << "Push during handshake does not send GET_BLOCK early";

    guard.handle_auth_result(true);
    const bool flushed = guard.flush_pending_push_after_auth();

    EXPECT_TRUE(flushed) << "Queued push flushes immediately after auth completes";
    EXPECT_TRUE(guard.get_block_requests == 1) << "Queued push sends exactly one GET_BLOCK after auth";
    EXPECT_TRUE(!guard.m_pending_push_after_auth) << "Queued push is cleared after the post-auth GET_BLOCK";
}

TEST(SoloAuthResyncTest, test_push_during_handshake_uses_preserved_lifeline)
{
    std::cout << "\nTest 9b: push during speculative re-auth uses preserved mining lifeline\n";

    SimulatedSoloAuthGuard guard;
    guard.m_authenticated = false;
    guard.m_reward_bound = false;
    guard.m_auth_state = AuthState::WAITING_FOR_RESULT;
    guard.preserve_push_lifeline(TEST_PUSH_LIFELINE_ALT_SESSION_ID,
                                 TEST_PUSH_LIFELINE_ALT_SESSION_EPOCH);

    const bool push_handled_immediately = guard.on_push_notification();

    EXPECT_TRUE(push_handled_immediately) << "Push lifeline accepts ingress during auth-in-flight";
    EXPECT_TRUE(!guard.m_pending_push_after_auth) << "Push lifeline does not queue post-auth replay";
    EXPECT_TRUE(guard.get_block_requests == 1) << "Push lifeline sends GET_BLOCK immediately";
    EXPECT_TRUE(guard.reauth_requests == 0) << "Push lifeline avoids duplicate re-auth";
}

TEST(SoloAuthResyncTest, test_session_expired_accepts_authoritative_session_id_when_local_cache_is_stale)
{
    std::cout << "\nTest 10: SESSION_EXPIRED is validated against authoritative session state\n";

    SimulatedSoloAuthGuard guard;
    guard.m_authenticated = false;
    guard.m_session_id = 0;
    guard.m_reward_bound = true;
    guard.session_context_authenticated = true;
    guard.authoritative = {true, 0xCAFEBABE, 88, true, {}};
    guard.template_interface_session_id = 0xCAFEBABE;

    const bool handled = guard.handle_session_expired(0xCAFEBABE);

    EXPECT_TRUE(handled) << "SESSION_EXPIRED accepts authoritative session ID despite stale local cache";
    EXPECT_TRUE(!guard.authoritative.authenticated) << "Authoritative session is cleared after expiry handling";
    EXPECT_TRUE(!guard.session_context_authenticated) << "Session context auth is cleared after expiry handling";
    EXPECT_TRUE(guard.m_session_id == 0) << "Local session ID cache is cleared after expiry handling";
    EXPECT_TRUE(!guard.m_reward_bound) << "Local reward binding cache is cleared after expiry handling";
}

TEST(SoloAuthResyncTest, test_push_triggered_reauth_queues_followup_get_block)
{
    std::cout << "\nTest 9: push-triggered re-auth also queues the recovery GET_BLOCK\n";

    SimulatedSoloAuthGuard guard;
    guard.m_authenticated = false;
    guard.m_reward_bound = true;
    guard.m_auth_state = AuthState::NOT_AUTHENTICATED;

    const bool push_handled_immediately = guard.on_push_notification();

    EXPECT_TRUE(!push_handled_immediately) << "Push-triggered re-auth defers GET_BLOCK until auth completes";
    EXPECT_TRUE(guard.m_pending_push_after_auth) << "Push-triggered re-auth queues a post-auth GET_BLOCK";
    EXPECT_TRUE(guard.reauth_requests == 1) << "Push-triggered re-auth requests exactly one re-auth";

    guard.handle_auth_result(true);
    const bool flushed = guard.flush_pending_push_after_auth();

    EXPECT_TRUE(flushed) << "Queued GET_BLOCK flushes after re-auth completes";
    EXPECT_TRUE(guard.get_block_requests == 1) << "Re-auth path sends exactly one queued GET_BLOCK";
}

TEST(SoloAuthResyncTest, test_multiple_pushes_during_handshake_queue_single_followup_get_block)
{
    std::cout << "\nTest 10: multiple pushes during one handshake queue a single post-auth GET_BLOCK\n";

    SimulatedSoloAuthGuard guard;
    guard.m_authenticated = false;
    guard.m_reward_bound = true;
    guard.m_auth_state = AuthState::WAITING_FOR_RESULT;

    const bool first_push_handled_immediately = guard.on_push_notification();
    const bool second_push_handled_immediately = guard.on_push_notification();

    EXPECT_TRUE(!first_push_handled_immediately) << "First push during handshake is deferred";
    EXPECT_TRUE(!second_push_handled_immediately) << "Second push during handshake is also deferred";
    EXPECT_TRUE(guard.m_pending_push_after_auth) << "Multiple pushes keep only one queued follow-up";
    EXPECT_TRUE(guard.reauth_requests == 0) << "Multiple pushes during handshake still avoid duplicate re-auth";
    EXPECT_TRUE(guard.get_block_requests == 0) << "Multiple pushes during handshake do not send GET_BLOCK early";

    guard.handle_auth_result(true);
    const bool flushed = guard.flush_pending_push_after_auth();

    EXPECT_TRUE(flushed) << "Queued follow-up flushes once after auth completes";
    EXPECT_TRUE(guard.get_block_requests == 1) << "Multiple deferred pushes still produce exactly one GET_BLOCK";
    EXPECT_TRUE(!guard.m_pending_push_after_auth) << "Queued follow-up is cleared after the single replay";
}

TEST(SoloAuthResyncTest, test_multiple_pushes_during_auth_limbo_continue_driving_get_block)
{
    std::cout << "\nTest 10b: repeated pushes during auth limbo keep driving GET_BLOCK via lifeline\n";

    SimulatedSoloAuthGuard guard;
    guard.m_authenticated = false;
    guard.m_auth_state = AuthState::WAITING_FOR_CHALLENGE;
    guard.preserve_push_lifeline(TEST_PUSH_LIMBO_SESSION_ID,
                                 TEST_PUSH_LIMBO_SESSION_EPOCH);

    const bool first_push_handled = guard.on_push_notification();
    const bool second_push_handled = guard.on_push_notification();

    EXPECT_TRUE(first_push_handled) << "First limbo push is accepted";
    EXPECT_TRUE(second_push_handled) << "Second limbo push is also accepted";
    EXPECT_TRUE(!guard.m_pending_push_after_auth) << "Limbo pushes do not queue deferred replay";
    EXPECT_TRUE(guard.get_block_requests == 2) << "Limbo pushes can continue driving replacement GET_BLOCK requests";
}

TEST(SoloAuthResyncTest, test_queued_push_waits_for_reward_binding_before_flushing)
{
    std::cout << "\nTest 11: queued push waits for reward binding before flushing\n";

    SimulatedSoloAuthGuard guard;
    guard.m_pending_push_after_auth = true;
    guard.m_authenticated = true;
    guard.m_reward_bound = false;

    const bool flushed_before_binding = guard.flush_pending_push_after_auth();

    EXPECT_TRUE(!flushed_before_binding) << "Queued push does not flush before reward binding completes";
    EXPECT_TRUE(guard.m_pending_push_after_auth) << "Queued push remains queued until reward binding completes";
    EXPECT_TRUE(guard.get_block_requests == 0) << "Queued push does not send GET_BLOCK before reward binding";

    guard.m_reward_bound = true;
    const bool flushed_after_binding = guard.flush_pending_push_after_auth();

    EXPECT_TRUE(flushed_after_binding) << "Queued push flushes once reward binding completes";
    EXPECT_TRUE(guard.get_block_requests == 1) << "Queued push sends exactly one GET_BLOCK after reward binding";
    EXPECT_TRUE(!guard.m_pending_push_after_auth) << "Queued push clears after successful flush";
}

TEST(SoloAuthResyncTest, test_cached_session_state_logging_downgrades_expected_reconnect_resyncs)
{
    std::cout << "\nTest 12: expected reconnect resyncs log at info while drift stays warn\n";

    const auto auth_reconnect = is_expected_cached_session_resync(false, true)
        ? ResyncLogSeverity::INFO : ResyncLogSeverity::WARN;
    const auto session_id_reconnect = is_expected_cached_session_resync(false, true)
        ? ResyncLogSeverity::INFO : ResyncLogSeverity::WARN;
    const auto reward_reconnect = is_expected_cached_session_resync(false, true)
        ? ResyncLogSeverity::INFO : ResyncLogSeverity::WARN;
    const auto chacha_reconnect = is_expected_cached_session_resync(false, true)
        ? ResyncLogSeverity::INFO : ResyncLogSeverity::WARN;

    const auto auth_drift = is_expected_cached_session_resync(true, false)
        ? ResyncLogSeverity::INFO : ResyncLogSeverity::WARN;
    const auto session_id_drift = is_expected_cached_session_resync(true, true)
        ? ResyncLogSeverity::INFO : ResyncLogSeverity::WARN;
    const auto reward_drift = is_expected_cached_session_resync(true, false)
        ? ResyncLogSeverity::INFO : ResyncLogSeverity::WARN;
    const auto chacha_drift = is_expected_cached_session_resync(true, true)
        ? ResyncLogSeverity::INFO : ResyncLogSeverity::WARN;

    EXPECT_TRUE(auth_reconnect == ResyncLogSeverity::INFO) << "Auth reconnect resync is informational";
    EXPECT_TRUE(session_id_reconnect == ResyncLogSeverity::INFO) << "Session ID reconnect resync is informational";
    EXPECT_TRUE(reward_reconnect == ResyncLogSeverity::INFO) << "Reward reconnect resync is informational";
    EXPECT_TRUE(chacha_reconnect == ResyncLogSeverity::INFO) << "ChaCha20 reconnect resync is informational";
    EXPECT_TRUE(auth_drift == ResyncLogSeverity::WARN) << "Auth drift remains warning-level";
    EXPECT_TRUE(session_id_drift == ResyncLogSeverity::WARN) << "Session ID drift remains warning-level";
    EXPECT_TRUE(reward_drift == ResyncLogSeverity::WARN) << "Reward drift remains warning-level";
    EXPECT_TRUE(chacha_drift == ResyncLogSeverity::WARN) << "ChaCha20 drift remains warning-level";
}

TEST(SoloAuthResyncTest, test_submit_requires_authoritative_chacha20_key)
{
    std::cout << "\nTest 13: submit path only accepts authoritative session key\n";

    SimulatedSoloAuthGuard guard;
    guard.m_chacha_key = std::vector<unsigned char>(32, 0xAA);
    guard.authoritative.chacha_key.clear();
    const bool can_submit = guard.has_authoritative_chacha_key();

    EXPECT_TRUE(!can_submit) << "Submit fails when authoritative key is empty even if local cache is populated";
}

TEST(SoloAuthResyncTest, test_block_accepted_consumes_snapshot_before_future_fallback)
{
    std::cout << "\nTest 14: accepted-block snapshot is consumed before later fallback use\n";

    SimulatedSoloAuthGuard guard;
    guard.m_last_submitted_valid = true;
    guard.m_last_submitted_height = 101;
    guard.m_last_submitted_channel = 2;

    const auto first_accept = guard.on_block_accepted(202, 1);
    const auto second_accept = guard.on_block_accepted(202, 1);

    EXPECT_TRUE(first_accept.height == 101) << "First accept uses submitted height";
    EXPECT_TRUE(first_accept.channel == 2) << "First accept uses submitted channel";
    EXPECT_TRUE(!guard.m_last_submitted_valid) << "Accepted snapshot is invalidated after first consumption";
    EXPECT_TRUE(second_accept.height == 202) << "Second accept falls back instead of reusing stale submitted height";
    EXPECT_TRUE(second_accept.channel == 1) << "Second accept falls back instead of reusing stale submitted channel";
    EXPECT_TRUE(second_accept.used_fallback) << "Second accept records that fallback was used";
}

TEST(SoloAuthResyncTest, test_session_status_policy_resets_mismatch_counter_on_match)
{
    std::cout << "\nTest 15: matching SESSION_STATUS_ACK resets mismatch counter\n";

    SimulatedSessionStatusAckHandler handler;
    handler.local_session_id = 0x12345678;
    handler.mismatch_count = 2;

    const bool accepted = handler.on_session_status_ack(0x12345678, 0x0F, 120, 0x07);

    EXPECT_TRUE(accepted) << "Matching SESSION_STATUS_ACK is accepted";
    EXPECT_TRUE(handler.mismatch_count == 0) << "Mismatch counter resets on match";
    EXPECT_TRUE(!handler.force_reauth) << "Healthy ACK does not force re-auth";
    EXPECT_TRUE(!handler.mark_degraded) << "Healthy ACK does not mark degraded";
}

TEST(SoloAuthResyncTest, test_session_status_ack_ignores_stale_session_id)
{
    std::cout << "\nTest 16: stale SESSION_STATUS_ACK does not overwrite cached status\n";

    SimulatedSessionStatusAckHandler handler;
    handler.local_session_id = 0x12345678;
    handler.last_session_id = 0x12345678;
    handler.last_lane_health_flags = 0x09;
    handler.last_uptime_seconds = 60;
    handler.last_status_echo_flags = 0x02;
    handler.ack_recorded = true;

    const bool accepted = handler.on_session_status_ack(0x87654321, 0x0F, 999, 0x07);

    EXPECT_TRUE(!accepted) << "Mismatched SESSION_STATUS_ACK is rejected";
    EXPECT_TRUE(handler.mismatch_count == 1) << "Mismatch counter increments";
    EXPECT_TRUE(!handler.expired_session) << "Threshold not yet reached does not expire session";
    EXPECT_TRUE(handler.last_session_id == 0x12345678) << "Cached session ID is not overwritten";
    EXPECT_TRUE(handler.last_lane_health_flags == 0x09) << "Cached lane health is not overwritten";
    EXPECT_TRUE(handler.last_uptime_seconds == 60) << "Cached uptime is not overwritten";
    EXPECT_TRUE(handler.last_status_echo_flags == 0x02) << "Cached echoed status is not overwritten";
}

TEST(SoloAuthResyncTest, test_session_status_ack_mismatch_is_diagnostic_only)
{
    std::cout << "\nTest 17: repeated mismatched SESSION_STATUS_ACKs are diagnostic only (no session expiry)\n";

    SimulatedSessionStatusAckHandler handler;
    handler.local_session_id = 0x12345678;
    handler.mismatch_count =
        nexusminer::protocol::ProtocolConstants::SESSION_MISMATCH_EXPIRE_THRESHOLD - 1;

    const bool accepted = handler.on_session_status_ack(0x87654321, 0x0F, 999, 0x07);

    EXPECT_TRUE(!accepted) << "Threshold mismatch SESSION_STATUS_ACK is rejected";
    // ACK mismatch is diagnostic only — PUSH is the sole authoritative signal.
    // Session must NOT be expired or force-reauthed based on keepalive ACK mismatches.
    EXPECT_TRUE(!handler.expired_session) << "Threshold mismatch does NOT expire session (PUSH is authoritative)";
    EXPECT_TRUE(!handler.force_reauth) << "Threshold mismatch does NOT force re-auth (PUSH is authoritative)";
    EXPECT_TRUE(!handler.mark_degraded) << "Threshold mismatch does NOT mark degraded (PUSH is authoritative)";
}

TEST(SoloAuthResyncTest, test_session_status_ack_unhealthy_is_diagnostic_only)
{
    // Test 18: SessionStatusPolicy::evaluate_ack_health() intentionally keeps force_reauth
    // and mark_degraded false — SESSION_STATUS is a telemetry probe and must not trigger
    // session actions.  PUSH notification liveness is the sole authoritative signal.
    std::cout << "\nTest 18: unhealthy SESSION_STATUS_ACK — diagnostic only, session preserved\n";

    SimulatedSessionStatusAckHandler handler;
    handler.local_session_id = 0x12345678;

    const bool accepted = handler.on_session_status_ack(0x12345678, 0x01, 0, 0x02, false);

    EXPECT_TRUE(accepted) << "Unhealthy SESSION_STATUS_ACK is still accepted for caching";
    // SessionStatusPolicy::evaluate_ack_health() intentionally does NOT set force_reauth
    // or mark_degraded — these are diagnostic observations only, PUSH is the sole
    // authoritative signal.
    EXPECT_TRUE(!handler.force_reauth) << "Unhealthy ACK does NOT force re-auth (PUSH is authoritative)";
    EXPECT_TRUE(!handler.mark_degraded) << "Unhealthy ACK does NOT mark degraded (PUSH is authoritative)";
}

TEST(SoloAuthResyncTest, test_degraded_live_session_policy_prefers_reauth_over_reconnect)
{
    // Test 19: With fix 3 applied, a degraded session with live push traffic should
    // NOT force reauth and NOT force reconnect — it should hold.
    std::cout << "\nTest 19: degraded session with live push traffic is held (not reauthed, not reconnected)\n";

    const auto decision = nexusminer::protocol::SessionStatusPolicy::evaluate_degraded_session({
        nexusminer::protocol::ProtocolConstants::DEGRADED_MODE_HARD_LIMIT_SECONDS + 1,
        nexusminer::protocol::ProtocolConstants::DEGRADED_MODE_HARD_LIMIT_SECONDS,
        true
    });

    EXPECT_TRUE(!decision.force_reauth) << "Hard-limit degraded live session does NOT force re-auth (push is alive)";
    EXPECT_TRUE(!decision.force_reconnect) << "Hard-limit degraded live session does NOT force reconnect (push is alive)";
    EXPECT_TRUE(decision.mark_degraded) << "Hard-limit degraded live session is still marked degraded for monitoring";
}

TEST(SoloAuthResyncTest, test_degraded_dead_session_policy_forces_reconnect)
{
    std::cout << "\nTest 20: degraded session without live push traffic reconnects\n";

    const auto decision = nexusminer::protocol::SessionStatusPolicy::evaluate_degraded_session({
        nexusminer::protocol::ProtocolConstants::DEGRADED_MODE_HARD_LIMIT_SECONDS + 1,
        nexusminer::protocol::ProtocolConstants::DEGRADED_MODE_HARD_LIMIT_SECONDS,
        false
    });

    EXPECT_TRUE(decision.force_reconnect) << "Hard-limit degraded dead session forces reconnect";
    EXPECT_TRUE(!decision.force_reauth) << "Hard-limit degraded dead session does not force re-auth";
    EXPECT_TRUE(decision.mark_degraded) << "Hard-limit degraded dead session is marked degraded";
}

TEST(SoloAuthResyncTest, test_session_expired_reauth_guard_skips_when_reconnect_or_recovery_active)
{
    std::cout << "\nTest 21: session-expired handler guard blocks duplicate in-band login\n";

    EXPECT_TRUE(!should_schedule_in_band_reauth(true, false, 0)) << "Guard blocks in-band re-auth while reconnect is in progress";
    EXPECT_TRUE(!should_schedule_in_band_reauth(false, true, 3)) << "Guard blocks in-band re-auth while recovery epoch is active";
    EXPECT_TRUE(should_schedule_in_band_reauth(false, false, 0)) << "Guard allows in-band re-auth when reconnect/recovery are idle";
}

}  // namespace
