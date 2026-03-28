#include "protocol/node_session_context.hpp"
#include "protocol/hex_prefix_utils.hpp"
#include "protocol/session_semantic_types.hpp"
#include <cassert>
#include <iostream>
#include <string>
#include <type_traits>
#include <gtest/gtest.h>

namespace {
std::string format_hex_prefix_via_qualified_call(const std::vector<uint8_t>& bytes, std::size_t prefix_bytes)
{
    return nexusminer::protocol::format_hex_prefix(bytes, prefix_bytes);
}
}

using namespace nexusminer::protocol;

TEST(NodeSessionContextTest, test_session_lifecycle) {
    std::cout << "Testing session lifecycle..." << std::endl;

    auto session_manager = std::make_shared<SessionManager>(24, nullptr);
    NodeSessionContext context(session_manager);

    // Initially no session
    ASSERT_TRUE(context.get_session_id() == 0);
    ASSERT_TRUE(!context.is_authenticated());
    ASSERT_TRUE(!context.is_active());
    ASSERT_TRUE(context.get_state() == SessionManager::SessionState::DISCONNECTED);

    // Start a session
    context.start_session(12345);
    ASSERT_TRUE(context.get_session_id() == 12345);
    ASSERT_TRUE(context.is_authenticated());
    ASSERT_TRUE(context.is_active());

    // End session
    context.end_session();
    ASSERT_TRUE(context.get_session_id() == 0);
    ASSERT_TRUE(!context.is_authenticated());

    std::cout << "Session lifecycle test passed!" << std::endl;
}

TEST(NodeSessionContextTest, test_session_constants) {
    std::cout << "Testing session constants accessors..." << std::endl;

    ASSERT_TRUE(NodeSessionContext::get_keepalive_safety_divisor() == 2);
    ASSERT_TRUE(NodeSessionContext::get_max_session_auth_retries() == 10);
    ASSERT_TRUE(NodeSessionContext::get_base_session_retry_ms() == 1000);
    ASSERT_TRUE(NodeSessionContext::get_max_session_retry_ms() == 60000);

    std::cout << "Session constants test passed!" << std::endl;
}

TEST(NodeSessionContextTest, test_parse_session_start) {
    std::cout << "Testing parse_session_start..." << std::endl;

    // Valid SESSION_START packet (minimal: 9 bytes)
    std::vector<uint8_t> packet = {
        0x01,                    // success
        0x39, 0x30, 0x00, 0x00,  // session_id = 12345 (LE)
        0x10, 0x0E, 0x00, 0x00   // timeout = 3600 seconds (LE)
    };

    uint32_t session_id = 0;
    uint32_t timeout = 0;
    std::vector<uint8_t> genesis;

    bool result = NodeSessionContext::parse_session_start(packet, session_id, timeout, genesis);
    ASSERT_TRUE(result);
    ASSERT_TRUE(session_id == 12345);
    ASSERT_TRUE(timeout == 3600);
    ASSERT_TRUE(genesis.empty());

    // Valid SESSION_START with genesis (41 bytes)
    std::vector<uint8_t> packet_with_genesis = {
        0x01,                    // success
        0x39, 0x30, 0x00, 0x00,  // session_id = 12345 (LE)
        0x10, 0x0E, 0x00, 0x00   // timeout = 3600 seconds (LE)
    };
    // Add 32 bytes of genesis
    for (int i = 0; i < 32; ++i) {
        packet_with_genesis.push_back(static_cast<uint8_t>(i));
    }

    genesis.clear();
    result = NodeSessionContext::parse_session_start(packet_with_genesis, session_id, timeout, genesis);
    ASSERT_TRUE(result);
    ASSERT_TRUE(session_id == 12345);
    ASSERT_TRUE(timeout == 3600);
    ASSERT_TRUE(genesis.size() == 32);
    for (int i = 0; i < 32; ++i) {
        ASSERT_TRUE(genesis[i] == static_cast<uint8_t>(i));
    }

    // Invalid packet (too short)
    std::vector<uint8_t> short_packet = {0x01, 0x39, 0x30};
    result = NodeSessionContext::parse_session_start(short_packet, session_id, timeout, genesis);
    ASSERT_TRUE(!result);

    // Invalid packet (success = 0)
    std::vector<uint8_t> failed_packet = {
        0x00,                    // success = 0 (failed)
        0x39, 0x30, 0x00, 0x00,
        0x10, 0x0E, 0x00, 0x00
    };
    result = NodeSessionContext::parse_session_start(failed_packet, session_id, timeout, genesis);
    ASSERT_TRUE(!result);

    std::cout << "parse_session_start test passed!" << std::endl;
}

TEST(NodeSessionContextTest, test_keepalive_interval) {
    std::cout << "Testing keepalive interval..." << std::endl;

    auto session_manager = std::make_shared<SessionManager>(24, nullptr);
    NodeSessionContext context(session_manager);

    ASSERT_TRUE(context.get_keepalive_interval() == 24);

    context.set_keepalive_interval(12);
    ASSERT_TRUE(context.get_keepalive_interval() == 12);

    std::cout << "Keepalive interval test passed!" << std::endl;
}

TEST(NodeSessionContextTest, test_tritium_genesis) {
    std::cout << "Testing Tritium genesis..." << std::endl;

    auto session_manager = std::make_shared<SessionManager>(24, nullptr);
    NodeSessionContext context(session_manager);

    std::vector<uint8_t> genesis(32, 0xAB);
    context.set_tritium_genesis(genesis);

    auto retrieved = context.get_tritium_genesis();
    ASSERT_TRUE(retrieved.size() == 32);
    for (size_t i = 0; i < 32; ++i) {
        ASSERT_TRUE(retrieved[i] == 0xAB);
    }

    std::cout << "Tritium genesis test passed!" << std::endl;
}

TEST(NodeSessionContextTest, test_session_manager_access) {
    std::cout << "Testing session manager access..." << std::endl;

    auto session_manager = std::make_shared<SessionManager>(24, nullptr);
    NodeSessionContext context(session_manager);

    ASSERT_TRUE(context.get_session_manager() == session_manager);

    std::cout << "Session manager access test passed!" << std::endl;
}

TEST(NodeSessionContextTest, test_authoritative_miner_session_container_binding) {
    std::cout << "Testing authoritative miner session container binding..." << std::endl;

    auto session_manager = std::make_shared<SessionManager>(24, nullptr);
    NodeSessionContext context(session_manager);

    std::vector<uint8_t> genesis(32, 0x11);
    std::vector<uint8_t> falcon_pubkey(32, 0x22);
    std::vector<uint8_t> chacha_key(32, 0x33);
    std::vector<uint8_t> reward_hash(32, 0x44);

    context.set_protocol_lane(nexusminer::ProtocolLane::STATELESS);
    context.set_connection_metadata("127.0.0.1:4000", "127.0.0.1:9323", true);
    context.set_tritium_genesis(genesis);
    context.set_falcon_identity(falcon_pubkey, "2222222222222222", true);
    context.start_session(0x12345678, {}, genesis);
    const auto chacha_fingerprint = format_hex_prefix(chacha_key, 8);
    context.set_chacha20_session_key(chacha_key, chacha_fingerprint, true);
    context.set_reward_binding("reward-address", reward_hash, true, "config");
    context.set_channel_state(2, true, true);

    std::string reason;
    ASSERT_TRUE(context.validate_miner_session(&reason));
    ASSERT_TRUE(reason == "PASS");

    auto info = context.get_session_info();
    ASSERT_TRUE(info.connected);
    ASSERT_TRUE(info.authenticated);
    ASSERT_TRUE(info.falcon_authenticated);
    ASSERT_TRUE(info.session_id == 0x12345678);
    ASSERT_TRUE(info.session_genesis == genesis);
    ASSERT_TRUE(info.falcon_pubkey == falcon_pubkey);
    ASSERT_TRUE(info.falcon_key_id == "2222222222222222");
    ASSERT_TRUE(info.chacha20_session_key == chacha_key);
    ASSERT_TRUE(info.chacha20_key_fingerprint == chacha_fingerprint);
    ASSERT_TRUE(info.reward_address == "reward-address");
    ASSERT_TRUE(info.reward_hash == reward_hash);
    ASSERT_TRUE(info.reward_bound);
    ASSERT_TRUE(info.channel == 2);
    ASSERT_TRUE(info.ready_for_submit);
    ASSERT_TRUE(info.ready_for_get_block);

    const auto diagnostics = context.build_miner_session_diagnostics();
    ASSERT_TRUE(diagnostics.find("MINER SESSION CONTAINER") != std::string::npos);
    ASSERT_TRUE(diagnostics.find("reward-address") != std::string::npos);
    ASSERT_TRUE(diagnostics.find("consistency: PASS") != std::string::npos);

    std::cout << "Authoritative miner session container binding test passed!" << std::endl;
}

TEST(NodeSessionContextTest, test_reward_binding_persists_across_session_restart) {
    std::cout << "Testing reward binding persistence across session restart..." << std::endl;

    auto session_manager = std::make_shared<SessionManager>(24, nullptr);
    NodeSessionContext context(session_manager);

    const std::vector<uint8_t> initial_genesis(32, 0x11);
    const std::vector<uint8_t> reconnect_genesis(32, 0x22);
    const std::vector<uint8_t> reward_hash(32, 0x44);

    context.start_session(0x12345678, {}, initial_genesis);
    context.set_reward_binding("reward-address", reward_hash, true, "config");
    context.set_channel_state(2, true, true);

    context.start_session(0x87654321, {}, reconnect_genesis);

    const auto info = context.get_session_info();
    ASSERT_TRUE(info.session_id == 0x87654321);
    ASSERT_TRUE(info.session_genesis == reconnect_genesis);
    ASSERT_TRUE(info.reward_address == "reward-address");
    ASSERT_TRUE(info.reward_hash == reward_hash);
    ASSERT_TRUE(info.reward_bound);
    ASSERT_TRUE(!info.ready_for_submit);
    ASSERT_TRUE(!info.ready_for_get_block);

    std::string reason;
    ASSERT_TRUE(context.validate_miner_session(&reason));
    ASSERT_TRUE(reason == "PASS");

    std::cout << "Reward binding persistence across session restart test passed!" << std::endl;
}

TEST(NodeSessionContextTest, test_format_hex_prefix_matches_session_validation_fingerprint) {
    std::cout << "Testing shared hex-prefix fingerprint formatting..." << std::endl;

    auto session_manager = std::make_shared<SessionManager>(24, nullptr);
    NodeSessionContext context(session_manager);

    std::vector<uint8_t> genesis(32, 0x0A);
    std::vector<uint8_t> chacha_key{0x00, 0x01, 0x0A, 0x10, 0xAB, 0xCD, 0xEF, 0xFF, 0x55};
    const auto fingerprint = format_hex_prefix(chacha_key, 8);

    ASSERT_TRUE(fingerprint == "00010a10abcdefff");

    context.set_protocol_lane(nexusminer::ProtocolLane::STATELESS);
    context.set_connection_metadata("127.0.0.1:4000", "127.0.0.1:9323", true);
    context.start_session(0xDEADBEEF, {}, genesis);
    context.set_falcon_identity(std::vector<uint8_t>(32, 0x77), "7777777777777777", true);
    context.set_chacha20_session_key(chacha_key, fingerprint, true);

    std::string reason;
    ASSERT_TRUE(context.validate_miner_session(&reason));
    ASSERT_TRUE(reason == "PASS");

    std::cout << "Shared hex-prefix fingerprint formatting test passed!" << std::endl;
}

TEST(NodeSessionContextTest, test_miner_session_container_detects_inconsistent_state) {
    std::cout << "Testing miner session container consistency checks..." << std::endl;

    auto session_manager = std::make_shared<SessionManager>(24, nullptr);
    NodeSessionContext context(session_manager);

    std::vector<uint8_t> genesis(32, 0x55);
    std::vector<uint8_t> chacha_key(32, 0x66);
    context.set_protocol_lane(nexusminer::ProtocolLane::STATELESS);
    context.set_connection_metadata("127.0.0.1:4000", "127.0.0.1:9323", true);
    context.start_session(0xABCDEF01, {}, genesis);
    context.set_falcon_identity(std::vector<uint8_t>(32, 0x77), "7777777777777777", true);
    context.set_chacha20_session_key(chacha_key, "deadbeef", true);
    context.set_reward_binding("reward-address", std::vector<uint8_t>(32, 0x88), false, "config");
    context.set_channel_state(1, true, true);

    std::string reason;
    ASSERT_TRUE(!context.validate_miner_session(&reason));
    ASSERT_TRUE(reason.find("ChaCha20 fingerprint") != std::string::npos);

    std::cout << "Miner session container consistency test passed!" << std::endl;
}

TEST(NodeSessionContextTest, test_atomic_authenticated_session_commit_sets_auth_fields_together) {
    std::cout << "Testing atomic authenticated session commit..." << std::endl;

    auto session_manager = std::make_shared<SessionManager>(24, nullptr);
    NodeSessionContext context(session_manager);

    constexpr uint32_t committed_session_id = 0x13572468;
    const std::vector<uint8_t> genesis(32, 0x5A);
    const std::vector<uint8_t> falcon_pubkey(32, 0x7C);

    context.set_state(SessionManager::SessionState::AUTHENTICATING);
    context.commit_authenticated_session(committed_session_id, falcon_pubkey, "atomic-session-key", genesis);

    const auto info = context.get_session_info();
    ASSERT_TRUE(info.session_id == committed_session_id);
    ASSERT_TRUE(info.session_epoch == context.get_session_epoch());
    ASSERT_TRUE(info.authenticated);
    ASSERT_TRUE(info.falcon_authenticated);
    ASSERT_TRUE(info.falcon_pubkey == falcon_pubkey);
    ASSERT_TRUE(info.falcon_key_id == "atomic-session-key");
    ASSERT_TRUE(info.session_genesis == genesis);
    ASSERT_TRUE(context.get_state() == SessionManager::SessionState::AUTHENTICATED);
    ASSERT_TRUE(context.is_authenticated());

    std::cout << "Atomic authenticated session commit test passed!" << std::endl;
}

TEST(NodeSessionContextTest, test_auth_handshake_preserves_reward_crypto_material) {
    std::cout << "Testing auth handshake preserves authoritative reward crypto material..." << std::endl;

    auto session_manager = std::make_shared<SessionManager>(24, nullptr);
    NodeSessionContext context(session_manager);

    const std::vector<uint8_t> genesis(32, 0x5A);
    const std::vector<uint8_t> chacha_key(32, 0x6B);
    const auto fingerprint = format_hex_prefix(chacha_key, 8);

    context.set_tritium_genesis(genesis);
    context.set_reward_binding("reward-address", {}, false, "config");
    context.set_chacha20_session_key(chacha_key, fingerprint, true);

    context.begin_auth_handshake("preserve reward crypto");

    auto snapshot = context.get_runtime_snapshot();
    ASSERT_TRUE(snapshot.state == SessionManager::SessionState::AUTHENTICATING);
    ASSERT_TRUE(snapshot.session_genesis == genesis);
    ASSERT_TRUE(snapshot.chacha20_session_key == chacha_key);
    ASSERT_TRUE(snapshot.chacha20_key_fingerprint == fingerprint);
    ASSERT_TRUE(snapshot.chacha20_ready);
    ASSERT_TRUE(snapshot.reward_address == "reward-address");
    ASSERT_TRUE(snapshot.reward_state == SessionManager::RewardState::REQUIRED);

    context.commit_authenticated_session(0x11223344,
                                         std::vector<uint8_t>(32, 0x21),
                                         "preserved-handshake-key",
                                         genesis);

    snapshot = context.get_runtime_snapshot();
    ASSERT_TRUE(snapshot.state == SessionManager::SessionState::AUTHENTICATED);
    ASSERT_TRUE(snapshot.session_genesis == genesis);
    ASSERT_TRUE(snapshot.chacha20_session_key == chacha_key);
    ASSERT_TRUE(snapshot.chacha20_key_fingerprint == fingerprint);
    ASSERT_TRUE(snapshot.chacha20_ready);

    const auto readiness = context.get_reward_bind_readiness();
    ASSERT_TRUE(readiness.ready);
    ASSERT_TRUE(readiness.reason == "ready");

    std::cout << "Auth handshake reward crypto preservation test passed!" << std::endl;
}

TEST(NodeSessionContextTest, test_reward_bind_readiness_reports_precise_missing_crypto_reason) {
    std::cout << "Testing reward bind readiness reports precise missing-crypto reason..." << std::endl;

    auto session_manager = std::make_shared<SessionManager>(24, nullptr);
    NodeSessionContext context(session_manager);

    const std::vector<uint8_t> genesis(32, 0x4C);
    context.set_reward_binding("reward-address", {}, false, "config");
    context.commit_authenticated_session(0xA1B2C3D4,
                                         std::vector<uint8_t>(32, 0x33),
                                         "missing-crypto-key",
                                         genesis);

    const auto readiness = context.get_reward_bind_readiness();
    ASSERT_TRUE(!readiness.ready);
    ASSERT_TRUE(readiness.reason.find("ChaCha20 reward/session key") != std::string::npos);

    std::cout << "Reward bind readiness missing-crypto reason test passed!" << std::endl;
}

TEST(NodeSessionContextTest, test_reset_session_credentials_clears_atomic_auth_flags) {
    std::cout << "Testing atomic credential reset..." << std::endl;

    auto session_manager = std::make_shared<SessionManager>(24, nullptr);
    NodeSessionContext context(session_manager);

    constexpr uint32_t committed_session_id = 0x24681357;
    context.commit_authenticated_session(
        committed_session_id,
        std::vector<uint8_t>(32, 0x33),
        "reset-session-key",
        std::vector<uint8_t>(32, 0x44));
    context.set_chacha20_session_key(std::vector<uint8_t>(32, 0x55), "5555555555555555", true);
    context.set_reward_binding("reward-address", std::vector<uint8_t>(32, 0x66), true, "live bind");
    context.set_channel_state(3, true, true);
    context.set_prevblock_suffix({0xAA, 0xBB, 0xCC, 0xDD});

    context.reset_session_credentials();

    const auto info = context.get_session_info();
    const std::array<uint8_t, 4> cleared_suffix{0, 0, 0, 0};
    ASSERT_TRUE(info.session_id == 0);
    ASSERT_TRUE(!info.authenticated);
    ASSERT_TRUE(!info.falcon_authenticated);
    ASSERT_TRUE(info.chacha20_session_key.empty());
    ASSERT_TRUE(info.chacha20_key_fingerprint.empty());
    ASSERT_TRUE(!info.chacha20_ready);
    ASSERT_TRUE(!info.reward_bound);
    ASSERT_TRUE(info.reward_hash.empty());
    ASSERT_TRUE(info.prevblock_suffix == cleared_suffix);
    ASSERT_TRUE(!info.ready_for_submit);
    ASSERT_TRUE(!info.ready_for_get_block);
    ASSERT_TRUE(context.get_state() == SessionManager::SessionState::DISCONNECTED);
    ASSERT_TRUE(!context.is_authenticated());

    std::cout << "Atomic credential reset test passed!" << std::endl;
}

TEST(NodeSessionContextTest, test_multiple_session_contexts_do_not_overlap) {
    std::cout << "Testing multiple session container isolation..." << std::endl;

    auto session_manager_a = std::make_shared<SessionManager>(24, nullptr);
    auto session_manager_b = std::make_shared<SessionManager>(24, nullptr);
    NodeSessionContext context_a(session_manager_a);
    NodeSessionContext context_b(session_manager_b);

    context_a.set_falcon_identity(std::vector<uint8_t>(32, 0x01), "aaaaaaaaaaaaaaaa", true);
    context_a.start_session(0x11111111, {}, std::vector<uint8_t>(32, 0x10));
    context_a.set_reward_binding("reward-a", std::vector<uint8_t>(32, 0x21), true, "config");
    context_a.set_channel_state(1, true, true);

    context_b.set_falcon_identity(std::vector<uint8_t>(32, 0x02), "bbbbbbbbbbbbbbbb", true);
    context_b.start_session(0x22222222, {}, std::vector<uint8_t>(32, 0x20));
    context_b.set_reward_binding("reward-b", std::vector<uint8_t>(32, 0x31), true, "config");
    context_b.set_channel_state(2, true, true);

    auto info_a = context_a.get_session_info();
    auto info_b = context_b.get_session_info();

    ASSERT_TRUE(info_a.session_id == 0x11111111);
    ASSERT_TRUE(info_b.session_id == 0x22222222);
    ASSERT_TRUE(info_a.reward_address == "reward-a");
    ASSERT_TRUE(info_b.reward_address == "reward-b");
    ASSERT_TRUE(info_a.falcon_key_id == "aaaaaaaaaaaaaaaa");
    ASSERT_TRUE(info_b.falcon_key_id == "bbbbbbbbbbbbbbbb");
    ASSERT_TRUE(info_a.session_genesis != info_b.session_genesis);
    ASSERT_TRUE(info_a.reward_hash != info_b.reward_hash);

    std::cout << "Multiple session container isolation test passed!" << std::endl;
}

TEST(NodeSessionContextTest, test_prevblock_suffix_is_authoritative_session_state) {
    std::cout << "Testing prevblock suffix lives in the authoritative session container..." << std::endl;

    auto session_manager = std::make_shared<SessionManager>(24, nullptr);
    NodeSessionContext context(session_manager);

    const std::array<uint8_t, 4> suffix{0x12, 0x34, 0x56, 0x78};
    context.set_prevblock_suffix(suffix);

    const auto info = context.get_session_info();
    ASSERT_TRUE(info.prevblock_suffix == suffix);

    const std::vector<uint8_t> suffix_bytes(suffix.begin(), suffix.end());
    const std::string expected_suffix_hex = format_hex_prefix_via_qualified_call(suffix_bytes, 4);
    const auto diagnostics = context.build_miner_session_diagnostics();
    ASSERT_TRUE(diagnostics.find("prevblock_suffix: " + expected_suffix_hex) != std::string::npos);

    std::cout << "Prevblock suffix authoritative-state test passed!" << std::endl;
}

TEST(NodeSessionContextTest, test_session_epoch_advances_across_session_restarts) {
    std::cout << "Testing authoritative session epoch advancement across restarts..." << std::endl;

    auto session_manager = std::make_shared<SessionManager>(24, nullptr);
    NodeSessionContext context(session_manager);

    ASSERT_TRUE(context.get_session_epoch() == 0);

    context.start_session(0x11111111);
    const auto first_info = context.get_session_info();
    ASSERT_TRUE(first_info.session_id == 0x11111111);
    ASSERT_TRUE(first_info.session_epoch == context.get_session_epoch());
    ASSERT_TRUE(first_info.session_epoch > 0);

    context.end_session();
    ASSERT_TRUE(context.get_session_epoch() == first_info.session_epoch);

    context.start_session(0x22222222);
    const auto second_info = context.get_session_info();
    ASSERT_TRUE(second_info.session_id == 0x22222222);
    ASSERT_TRUE(second_info.session_epoch == context.get_session_epoch());
    ASSERT_TRUE(second_info.session_epoch > first_info.session_epoch);

    const auto diagnostics = context.build_miner_session_diagnostics();
    ASSERT_TRUE(diagnostics.find("session_epoch: " + std::to_string(second_info.session_epoch)) != std::string::npos);

    std::cout << "Session epoch advancement test passed!" << std::endl;
}

TEST(NodeSessionContextTest, test_runtime_snapshot_is_authoritative_copy) {
    std::cout << "Testing authoritative runtime snapshot access..." << std::endl;

    auto session_manager = std::make_shared<SessionManager>(24, nullptr);
    NodeSessionContext context(session_manager);

    context.set_state(SessionManager::SessionState::AUTHENTICATING);
    context.commit_authenticated_session(0x1234ABCD,
                                         std::vector<uint8_t>(32, 0x11),
                                         "snapshot-key",
                                         std::vector<uint8_t>(32, 0x22));

    const auto authenticated_snapshot = context.get_runtime_snapshot();
    const auto compatibility_snapshot = context.get_session_info();
    ASSERT_TRUE(authenticated_snapshot.session_id == 0x1234ABCD);
    ASSERT_TRUE(authenticated_snapshot.session_epoch == compatibility_snapshot.session_epoch);
    ASSERT_TRUE(authenticated_snapshot.state == SessionManager::SessionState::AUTHENTICATED);
    ASSERT_TRUE(authenticated_snapshot.falcon_key_id == "snapshot-key");

    session_manager->record_keepalive();
    const auto active_snapshot = context.get_runtime_snapshot();
    ASSERT_TRUE(active_snapshot.session_id == authenticated_snapshot.session_id);
    ASSERT_TRUE(active_snapshot.session_epoch == authenticated_snapshot.session_epoch);
    ASSERT_TRUE(active_snapshot.state == SessionManager::SessionState::AUTHENTICATED);
    // Snapshots are read-only copies of the authoritative container, so an older
    // snapshot must not change when the live session transitions forward.
    ASSERT_TRUE(authenticated_snapshot.state == SessionManager::SessionState::AUTHENTICATED);

    context.end_session();
    const auto disconnected_snapshot = context.get_runtime_snapshot();
    ASSERT_TRUE(disconnected_snapshot.session_id == 0);
    ASSERT_TRUE(disconnected_snapshot.state == SessionManager::SessionState::DISCONNECTED);
    ASSERT_TRUE(disconnected_snapshot.session_epoch == active_snapshot.session_epoch);

    std::cout << "Authoritative runtime snapshot test passed!" << std::endl;
}

TEST(NodeSessionContextTest, test_hex_prefix_header_supports_qualified_callers) {
    std::cout << "Testing hex_prefix_utils qualified-call documentation path..." << std::endl;

    const std::vector<uint8_t> bytes{0xDE, 0xAD, 0xBE, 0xEF, 0xAA};
    ASSERT_TRUE(format_hex_prefix_via_qualified_call(bytes, 4) == "deadbeef");

    std::cout << "hex_prefix_utils qualified-call test passed!" << std::endl;
}

TEST(NodeSessionContextTest, test_session_event_journal_tracks_current_session) {
    std::cout << "Testing session event journal tracks current session..." << std::endl;

    auto session_manager = std::make_shared<SessionManager>(24, nullptr);
    NodeSessionContext context(session_manager);

    context.set_state(SessionManager::SessionState::AUTHENTICATING);
    context.start_session(0xABCDEF01);
    context.record_session_event(SessionManager::SessionEventKind::STATUS_ACK_ACCEPTED,
                                 "session status ack accepted");
    context.set_reward_binding("reward-address", std::vector<uint8_t>(32, 0x42), true, "live bind");

    const auto journal = context.get_session_event_journal();
    ASSERT_TRUE(journal.size() >= 4);
    ASSERT_TRUE(journal[0].kind == SessionManager::SessionEventKind::AUTH_INIT);
    ASSERT_TRUE(journal[1].kind == SessionManager::SessionEventKind::AUTH_SUCCESS);
    ASSERT_TRUE(journal[2].kind == SessionManager::SessionEventKind::SESSION_START);
    ASSERT_TRUE(journal.back().kind == SessionManager::SessionEventKind::REWARD_BOUND);
    ASSERT_TRUE(journal.back().session_id.get() == 0xABCDEF01u);
    ASSERT_TRUE(journal.back().session_epoch.get() == context.get_session_epoch());

    const auto diagnostics = context.build_miner_session_diagnostics();
    ASSERT_TRUE(diagnostics.find("SESSION EVENT JOURNAL") != std::string::npos);
    ASSERT_TRUE(diagnostics.find("auth_init") != std::string::npos);
    ASSERT_TRUE(diagnostics.find("reward_bind_result") != std::string::npos);

    std::cout << "Session event journal tracking test passed!" << std::endl;
}

TEST(NodeSessionContextTest, test_session_event_journal_behaves_like_ring_buffer) {
    std::cout << "Testing session event journal ring buffer behavior..." << std::endl;

    auto session_manager = std::make_shared<SessionManager>(24, nullptr);
    NodeSessionContext context(session_manager);

    context.start_session(0x12345678);
    for (std::size_t i = 0; i < SessionManager::SESSION_EVENT_JOURNAL_CAPACITY + 5; ++i) {
        context.record_session_event(SessionManager::SessionEventKind::STALE_PACKET_DROPPED,
                                     "drop-" + std::to_string(i));
    }

    const auto journal = context.get_session_event_journal();
    ASSERT_TRUE(journal.size() == SessionManager::SESSION_EVENT_JOURNAL_CAPACITY);
    ASSERT_TRUE(journal.front().detail == "drop-5");
    assert(journal.back().detail ==
           "drop-" + std::to_string(SessionManager::SESSION_EVENT_JOURNAL_CAPACITY + 4));

    std::cout << "Session event journal ring buffer test passed!" << std::endl;
}

TEST(NodeSessionContextTest, test_session_event_journal_preserves_preflight_drop_detail) {
    std::cout << "Testing session event journal preserves ingress preflight detail..." << std::endl;

    auto session_manager = std::make_shared<SessionManager>(24, nullptr);
    NodeSessionContext context(session_manager);

    context.start_session(0xCAFEBABEu);
    context.record_session_event(SessionManager::SessionEventKind::EPOCH_MISMATCH,
                                 "Solo SessionKeepalive: packet ownership epoch mismatched authoritative session");

    const auto diagnostics = context.build_miner_session_diagnostics();
    ASSERT_TRUE(diagnostics.find("epoch_mismatch") != std::string::npos);
    ASSERT_TRUE(diagnostics.find("packet ownership epoch mismatched authoritative session") != std::string::npos);

    std::cout << "Session event journal preflight detail test passed!" << std::endl;
}

TEST(NodeSessionContextTest, test_authoritative_transition_apis_drive_lifecycle_state) {
    std::cout << "Testing authoritative transition APIs drive lifecycle state..." << std::endl;

    auto session_manager = std::make_shared<SessionManager>(24, nullptr);
    NodeSessionContext context(session_manager);

    context.set_reward_binding("reward-address", {}, false, "config");
    context.begin_auth_handshake("unit test auth");
    auto snapshot = context.get_runtime_snapshot();
    ASSERT_TRUE(snapshot.state == SessionManager::SessionState::AUTHENTICATING);
    ASSERT_TRUE(snapshot.reward_state == SessionManager::RewardState::REQUIRED);

    context.commit_authenticated_session(0xABCDEF12,
                                         std::vector<uint8_t>(32, 0x21),
                                         "transition-key",
                                         std::vector<uint8_t>(32, 0x34));
    snapshot = context.get_runtime_snapshot();
    ASSERT_TRUE(snapshot.state == SessionManager::SessionState::AUTHENTICATED);
    ASSERT_TRUE(context.allow_deferred_push_replay());
    ASSERT_TRUE(!context.can_request_get_block());
    ASSERT_TRUE(context.reward_binding_required());

    context.begin_reward_binding("reward-address", std::vector<uint8_t>(32, 0x45), "live bind");
    snapshot = context.get_runtime_snapshot();
    ASSERT_TRUE(snapshot.reward_state == SessionManager::RewardState::BINDING);
    ASSERT_TRUE(!context.is_reward_bound());

    context.commit_reward_bound("reward-address", std::vector<uint8_t>(32, 0x45), "live bind");
    context.set_channel_state(2, true, true);
    context.note_keepalive_ack(true, "ack ok");
    snapshot = context.get_runtime_snapshot();
    ASSERT_TRUE(snapshot.state == SessionManager::SessionState::AUTHENTICATED);
    ASSERT_TRUE(snapshot.reward_state == SessionManager::RewardState::BOUND);
    ASSERT_TRUE(snapshot.expiry_state == SessionManager::ExpiryState::FRESH);
    ASSERT_TRUE(context.is_reward_bound());
    ASSERT_TRUE(context.can_request_get_block());
    ASSERT_TRUE(context.can_submit_work());
    ASSERT_TRUE(context.allow_get_block_replay());

    context.mark_session_expired("ack mismatch");
    snapshot = context.get_runtime_snapshot();
    ASSERT_TRUE(snapshot.state == SessionManager::SessionState::DEGRADED);
    ASSERT_TRUE(snapshot.reward_state == SessionManager::RewardState::STALE);
    ASSERT_TRUE(snapshot.expiry_state == SessionManager::ExpiryState::EXPIRED);
    ASSERT_TRUE(!context.can_submit_work());
    ASSERT_TRUE(!context.allow_get_block_replay());

    context.clear_for_reauth("reward-address", "config", "reauth requested");
    snapshot = context.get_runtime_snapshot();
    ASSERT_TRUE(snapshot.state == SessionManager::SessionState::DISCONNECTED);
    ASSERT_TRUE(snapshot.reward_state == SessionManager::RewardState::REQUIRED);
    ASSERT_TRUE(snapshot.reward_address == "reward-address");
    ASSERT_TRUE(!snapshot.reward_bound);
    ASSERT_TRUE(!context.allow_deferred_push_replay());

    const auto diagnostics = context.build_miner_session_diagnostics();
    ASSERT_TRUE(diagnostics.find("reward_state: REQUIRED") != std::string::npos);
    ASSERT_TRUE(diagnostics.find("expiry_state: FRESH") != std::string::npos);

    std::cout << "Authoritative transition API test passed!" << std::endl;
}

TEST(NodeSessionContextTest, test_session_semantic_wrapper_types_are_distinct) {
    std::cout << "Testing strong semantic session wrapper types..." << std::endl;

    static_assert(!std::is_same<SessionId, SessionEpoch>::value, "SessionId and SessionEpoch must differ");
    static_assert(!std::is_same<SessionGenesisHash, RewardHash>::value, "Genesis and reward hashes must differ");
    static_assert(!std::is_same<FalconHashKeyId, SessionFingerprint>::value, "Key id and fingerprint must differ");

    const SessionId session_id(0x11111111u);
    const SessionEpoch session_epoch(9);
    const SessionGenesisHash genesis_hash(std::vector<uint8_t>(32, 0xAA));
    const RewardHash reward_hash(std::vector<uint8_t>(32, 0xBB));
    const FalconHashKeyId key_id(std::string("falcon-key"));
    const SessionFingerprint fingerprint(std::string("fingerprint"));

    ASSERT_TRUE(session_id.get() == 0x11111111u);
    ASSERT_TRUE(session_epoch.get() == 9u);
    ASSERT_TRUE(genesis_hash.get().size() == 32);
    ASSERT_TRUE(reward_hash.get().size() == 32);
    ASSERT_TRUE(key_id.get() == "falcon-key");
    ASSERT_TRUE(fingerprint.get() == "fingerprint");

    std::cout << "Strong semantic session wrapper types test passed!" << std::endl;
}
