#include "protocol/solo.hpp"
#include "protocol/node_session_context.hpp"
#include "protocol/transport_crypto_selector.hpp"
#include "LLP/packet.hpp"

#include "spdlog/spdlog.h"
#include "spdlog/sinks/null_sink.h"

#include <algorithm>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <vector>

using namespace nexusminer;
using namespace nexusminer::protocol;

namespace {

int tests_run = 0;
int tests_failed = 0;

void check(const char* name, bool condition)
{
    ++tests_run;
    std::cout << "  [" << (condition ? "PASS" : "FAIL") << "] " << name << '\n';
    if (!condition) {
        ++tests_failed;
    }
}

std::vector<uint8_t> test_key()
{
    std::vector<uint8_t> key(32);
    for (std::size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<uint8_t>(i + 1);
    }
    return key;
}

std::shared_ptr<NodeSessionContext> make_authenticated_context(const std::vector<uint8_t>& key,
                                                               uint32_t sid,
                                                               ProtocolLane lane)
{
    constexpr uint8_t kTestGenesisByte = 0x7A;
    auto hex_prefix = [](const std::vector<uint8_t>& data, std::size_t bytes) {
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        const std::size_t limit = std::min(bytes, data.size());
        for (std::size_t i = 0; i < limit; ++i) {
            oss << std::setw(2) << static_cast<int>(data[i]);
        }
        return oss.str();
    };

    auto manager = std::make_shared<SessionManager>(24, nullptr);
    auto context = std::make_shared<NodeSessionContext>(manager);
    context->set_protocol_lane(lane);
    const std::vector<uint8_t> genesis(32, kTestGenesisByte);
    context->set_tritium_genesis(genesis);
    context->set_falcon_identity(std::vector<uint8_t>(32, 0x11), "test-key", true);
    context->commit_authenticated_session(sid, std::vector<uint8_t>(32, 0x11), "test-key", genesis);
    context->set_chacha20_session_key(key, hex_prefix(key, 8), true);
    context->set_state(SessionManager::SessionState::AUTHENTICATED);
    return context;
}

struct SessionSnapshot {
    bool authenticated{false};
    bool falcon_authenticated{false};
    uint32_t session_id{0};
    uint64_t session_epoch{0};
    SessionManager::SessionState state{SessionManager::SessionState::DISCONNECTED};
};

SessionSnapshot capture(const std::shared_ptr<NodeSessionContext>& context)
{
    const auto info = context->get_session_info();
    return SessionSnapshot{
        info.authenticated,
        info.falcon_authenticated,
        info.session_id,
        info.session_epoch,
        info.state
    };
}

bool same_snapshot(const SessionSnapshot& a, const SessionSnapshot& b)
{
    return a.authenticated == b.authenticated &&
           a.falcon_authenticated == b.falcon_authenticated &&
           a.session_id == b.session_id &&
           a.session_epoch == b.session_epoch &&
           a.state == b.state;
}

Packet reward_result_packet(const std::vector<uint8_t>& payload)
{
    return Packet(Packet::STATELESS_MINER_REWARD_RESULT, payload);
}

} // namespace

int main()
{
    auto null_sink = std::make_shared<spdlog::sinks::null_sink_mt>();
    auto logger = std::make_shared<spdlog::logger>("logger", null_sink);
    spdlog::set_default_logger(logger);

    const std::vector<uint8_t> aad_reward_result{
        'R','E','W','A','R','D','_','R','E','S','U','L','T'
    };
    const auto key = test_key();
    constexpr uint32_t sid = 0xA1B2C3D4;

    std::cout << "========================================\n";
    std::cout << "Reward Result Decode Unit Tests\n";
    std::cout << "========================================\n";

    // EVP valid frame -> decode success.
    {
        auto context = make_authenticated_context(key, sid, ProtocolLane::STATELESS);
        Solo solo(mining::CHANNEL_HASH, nullptr, context);
        solo.set_protocol_lane(ProtocolLane::STATELESS);
        solo.set_transport_crypto_mode("evp");
        solo.enable_chacha20_wrapping(true);
        solo.set_reward_address("reward-address");

        if (solo.get_transport_crypto_mode() == "evp") {
            TransportCryptoSelector encoder(logger);
            encoder.configure("evp");
            if (encoder.active_mode() == "evp") {
                const uint64_t epoch = context->get_session_epoch();
                auto enc = encoder.encrypt_packet({0x01}, key, sid, PacketCryptoPhase::SESSION_BOUND, aad_reward_result, epoch);
                check("evp valid frame encrypted", enc.success);
                if (enc.success) {
                    int session_expired_calls = 0;
                    solo.set_session_expired_handler([&session_expired_calls]() { ++session_expired_calls; });
                    const auto before = capture(context);
                    solo.process_messages(reward_result_packet(enc.data), nullptr);
                    const auto after = capture(context);
                    check("evp valid frame reward binding succeeds", solo.is_reward_bound());
                    check("evp valid frame keeps session/auth unchanged", same_snapshot(before, after));
                    check("evp valid frame does not trigger session-expired flow", session_expired_calls == 0);
                }
            } else {
                check("evp valid frame skipped when encoder falls back", true);
            }
        } else {
            check("evp valid frame skipped when evp unavailable", true);
        }
    }

    // EVP short frame -> FRAME_TOO_SHORT; no session/auth mutation.
    {
        auto context = make_authenticated_context(key, sid, ProtocolLane::STATELESS);
        Solo solo(mining::CHANNEL_HASH, nullptr, context);
        solo.set_protocol_lane(ProtocolLane::STATELESS);
        solo.set_transport_crypto_mode("evp");
        solo.enable_chacha20_wrapping(true);
        solo.set_reward_address("reward-address");

        if (solo.get_transport_crypto_mode() == "evp") {
            int session_expired_calls = 0;
            solo.set_session_expired_handler([&session_expired_calls]() { ++session_expired_calls; });
            const auto before = capture(context);
            solo.process_messages(reward_result_packet(std::vector<uint8_t>(8, 0x00)), nullptr);
            const auto after = capture(context);
            check("evp short frame does not bind reward", !solo.is_reward_bound());
            check("evp short frame keeps session/auth unchanged", same_snapshot(before, after));
            check("evp short frame does not trigger session-expired flow", session_expired_calls == 0);
        } else {
            check("evp short frame skipped when evp unavailable", true);
        }
    }

    // EVP flags mismatch -> typed failure lane; no session/auth mutation.
    {
        auto context = make_authenticated_context(key, sid, ProtocolLane::STATELESS);
        Solo solo(mining::CHANNEL_HASH, nullptr, context);
        solo.set_protocol_lane(ProtocolLane::STATELESS);
        solo.set_transport_crypto_mode("evp");
        solo.enable_chacha20_wrapping(true);
        solo.set_reward_address("reward-address");

        if (solo.get_transport_crypto_mode() == "evp") {
            TransportCryptoSelector encoder(logger);
            encoder.configure("evp");
            if (encoder.active_mode() == "evp") {
                const uint64_t epoch = context->get_session_epoch();
                auto enc = encoder.encrypt_packet({0x01}, key, sid, PacketCryptoPhase::SESSION_BOUND, aad_reward_result, epoch);
                check("evp flags mismatch frame encrypted", enc.success);
                if (enc.success) {
                    auto bad_flags = enc.data;
                    bad_flags[1] = 0x00;
                    int session_expired_calls = 0;
                    solo.set_session_expired_handler([&session_expired_calls]() { ++session_expired_calls; });
                    const auto before = capture(context);
                    solo.process_messages(reward_result_packet(bad_flags), nullptr);
                    const auto after = capture(context);
                    check("evp flags mismatch does not bind reward", !solo.is_reward_bound());
                    check("evp flags mismatch keeps session/auth unchanged", same_snapshot(before, after));
                    check("evp flags mismatch does not trigger session-expired flow", session_expired_calls == 0);
                }
            } else {
                check("evp flags mismatch skipped when encoder falls back", true);
            }
        } else {
            check("evp flags mismatch skipped when evp unavailable", true);
        }
    }

    // Legacy mode frame -> unchanged success.
    {
        auto context = make_authenticated_context(key, sid, ProtocolLane::STATELESS);
        Solo solo(mining::CHANNEL_HASH, nullptr, context);
        solo.set_protocol_lane(ProtocolLane::STATELESS);
        solo.set_transport_crypto_mode("legacy");
        solo.enable_chacha20_wrapping(true);
        solo.set_reward_address("reward-address");

        TransportCryptoSelector encoder(logger);
        encoder.configure("legacy");
        auto enc = encoder.encrypt_packet({0x01}, key, sid, PacketCryptoPhase::SESSION_BOUND, aad_reward_result, context->get_session_epoch());
        check("legacy frame encrypted", enc.success);
        if (enc.success) {
            const auto before = capture(context);
            solo.process_messages(reward_result_packet(enc.data), nullptr);
            const auto after = capture(context);
            check("legacy reward result success unchanged", solo.is_reward_bound());
            check("legacy frame keeps session/auth unchanged", same_snapshot(before, after));
        }
    }

    std::cout << "\nTests run: " << tests_run << ", failed: " << tests_failed << '\n';
    return tests_failed == 0 ? 0 : 1;
}
