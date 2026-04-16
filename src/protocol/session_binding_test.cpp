#include "protocol/node_session_context.hpp"
#include "protocol/session_binding.hpp"
#include <cassert>
#include <iostream>
#include <vector>

using namespace nexusminer::protocol;

namespace {

void test_default_binding()
{
    SessionBinding binding;
    assert(!binding.has_session());
    assert(!binding.can_submit_work());
    assert(!binding.can_request_get_block());
    assert(binding.identity_matches_session());
    std::cout << "  PASS: default_binding\n";
}

void test_context_exposes_batched_binding()
{
    auto session_manager = std::make_shared<SessionManager>(24, nullptr);
    NodeSessionContext context(session_manager);

    const SessionId session_id(0x12345678u);
    const std::vector<uint8_t> genesis(32, 0x11);
    const std::vector<uint8_t> reward_hash(32, 0x22);
    const std::vector<uint8_t> chacha_key(32, 0x33);

    context.set_protocol_lane(nexusminer::ProtocolLane::STATELESS);
    context.set_falcon_identity(std::vector<uint8_t>(32, 0x44),
                                FalconHashKeyId("binding-falcon-key"),
                                true);
    context.commit_authenticated_session(session_id,
                                         std::vector<uint8_t>(32, 0x44),
                                         FalconHashKeyId("binding-falcon-key"),
                                         SessionGenesisHash(genesis));
    context.set_chacha20_session_key(chacha_key,
                                     SessionFingerprint("binding-fingerprint"),
                                     true);
    context.set_reward_binding("reward-address", RewardHash(reward_hash), true, "config");
    context.set_channel_state(2, true, true);

    const auto binding = context.get_session_binding();
    assert(binding.has_session());
    assert(binding.session_id == session_id);
    assert(binding.session_epoch == context.get_session_epoch());
    assert(binding.session_genesis == SessionGenesisHash(genesis));
    assert(binding.falcon_key_id == FalconHashKeyId("binding-falcon-key"));
    assert(binding.chacha20_key_fingerprint == SessionFingerprint("binding-fingerprint"));
    assert(binding.active_lane == nexusminer::ProtocolLane::STATELESS);
    assert(binding.reward_address == "reward-address");
    assert(binding.reward_hash == RewardHash(reward_hash));
    assert(binding.reward_bound);
    assert(binding.channel == 2);
    assert(binding.can_submit_work());
    assert(binding.can_request_get_block());
    assert(binding.identity.is_valid());
    assert(binding.identity_matches_session());
    std::cout << "  PASS: context_exposes_batched_binding\n";
}

} // namespace

int main()
{
    test_default_binding();
    test_context_exposes_batched_binding();
    std::cout << "All SessionBinding tests passed!\n";
    return 0;
}
