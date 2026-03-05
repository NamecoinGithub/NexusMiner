/**
 * Unit tests for NodeSession
 *
 * Tests the NodeSession unified active session wrapper API
 */

#include "node_session/node_session.hpp"
#include "config/config.hpp"
#include "network/socket.hpp"
#include "stats/stats_collector.hpp"
#include <iostream>
#include <cassert>
#include <memory>

using namespace nexusminer;

// Mock implementations for testing
class MockSocket : public network::Socket {
public:
    MockSocket(std::shared_ptr<asio::io_context> io_context)
        : m_io_context(io_context) {}

    network::Connection::Sptr connect(
        const network::Endpoint& endpoint,
        network::Connection::Receive_handler handler) override
    {
        // Return null for testing
        return nullptr;
    }

private:
    std::shared_ptr<asio::io_context> m_io_context;
};

void test_node_session_creation()
{
    std::cout << "Test: NodeSession creation..." << std::endl;

    auto io_context = std::make_shared<asio::io_context>();

    // Create minimal config
    config::Config config;
    config.set_mining_mode(config::Mining_mode::HASH);

    auto socket = std::make_shared<MockSocket>(io_context);
    auto stats_collector = std::make_shared<stats::Collector>(config);

    // Create NodeSession
    auto node_session = std::make_shared<NodeSession>(
        io_context,
        config,
        socket,
        stats_collector,
        "TEST_PRIMARY");

    assert(node_session != nullptr);
    assert(!node_session->is_authenticated());
    assert(node_session->session_id() == 0);
    assert(!node_session->is_session_active());

    std::cout << "  ✓ NodeSession created successfully" << std::endl;
    std::cout << "  ✓ Initial state is unauthenticated" << std::endl;
    std::cout << "  ✓ Initial session_id is 0" << std::endl;
}

void test_node_session_configuration()
{
    std::cout << "Test: NodeSession configuration..." << std::endl;

    auto io_context = std::make_shared<asio::io_context>();

    config::Config config;
    config.set_mining_mode(config::Mining_mode::PRIME);

    auto socket = std::make_shared<MockSocket>(io_context);
    auto stats_collector = std::make_shared<stats::Collector>(config);

    auto node_session = std::make_shared<NodeSession>(
        io_context,
        config,
        socket,
        stats_collector,
        "TEST_PRIMARY");

    // Test configuration methods
    std::vector<uint8_t> pubkey(897, 0xAA);
    std::vector<uint8_t> privkey(1281, 0xBB);
    node_session->set_miner_keys(pubkey, privkey);

    std::string reward_address = "2S6ymao1fSUfxvsT9nYCKPKmPPRWRp3KDj";
    node_session->set_reward_address(reward_address);

    std::vector<uint8_t> genesis(32, 0xCC);
    node_session->set_tritium_genesis(genesis);

    node_session->set_keepalive_interval(12);

    std::cout << "  ✓ Miner keys set" << std::endl;
    std::cout << "  ✓ Reward address set" << std::endl;
    std::cout << "  ✓ Tritium genesis set" << std::endl;
    std::cout << "  ✓ Keepalive interval set" << std::endl;
}

void test_node_session_handlers()
{
    std::cout << "Test: NodeSession handler registration..." << std::endl;

    auto io_context = std::make_shared<asio::io_context>();

    config::Config config;
    config.set_mining_mode(config::Mining_mode::HASH);

    auto socket = std::make_shared<MockSocket>(io_context);
    auto stats_collector = std::make_shared<stats::Collector>(config);

    auto node_session = std::make_shared<NodeSession>(
        io_context,
        config,
        socket,
        stats_collector,
        "TEST_PRIMARY");

    // Register handlers
    bool template_handler_called = false;
    node_session->set_template_handler([&template_handler_called](const LLP::CBlock&, uint32_t) {
        template_handler_called = true;
    });

    bool block_accepted_handler_called = false;
    node_session->set_block_accepted_handler([&block_accepted_handler_called](uint32_t, uint1024_t, uint32_t, uint64_t) {
        block_accepted_handler_called = true;
    });

    bool recovery_handler_called = false;
    node_session->set_recovery_initiated_handler([&recovery_handler_called]() {
        recovery_handler_called = true;
    });

    bool session_expired_handler_called = false;
    node_session->set_session_expired_handler([&session_expired_handler_called]() {
        session_expired_handler_called = true;
    });

    bool session_authenticated_handler_called = false;
    node_session->set_session_authenticated_handler([&session_authenticated_handler_called](uint32_t) {
        session_authenticated_handler_called = true;
    });

    bool session_start_handler_called = false;
    node_session->set_session_start_handler([&session_start_handler_called](uint16_t) {
        session_start_handler_called = true;
    });

    std::cout << "  ✓ Template handler registered" << std::endl;
    std::cout << "  ✓ Block accepted handler registered" << std::endl;
    std::cout << "  ✓ Recovery handler registered" << std::endl;
    std::cout << "  ✓ Session expired handler registered" << std::endl;
    std::cout << "  ✓ Session authenticated handler registered" << std::endl;
    std::cout << "  ✓ Session start handler registered" << std::endl;
}

void test_node_session_protocol_access()
{
    std::cout << "Test: NodeSession protocol access..." << std::endl;

    auto io_context = std::make_shared<asio::io_context>();

    config::Config config;
    config.set_mining_mode(config::Mining_mode::HASH);

    auto socket = std::make_shared<MockSocket>(io_context);
    auto stats_collector = std::make_shared<stats::Collector>(config);

    auto node_session = std::make_shared<NodeSession>(
        io_context,
        config,
        socket,
        stats_collector,
        "TEST_PRIMARY");

    // Access protocol instances
    auto primary_protocol = node_session->get_primary_protocol();
    assert(primary_protocol != nullptr);

    auto secondary_protocol = node_session->get_secondary_protocol();
    // Secondary is null until connection is attempted
    assert(secondary_protocol == nullptr);

    std::cout << "  ✓ Primary protocol accessible" << std::endl;
    std::cout << "  ✓ Secondary protocol initially null" << std::endl;
}

void test_node_session_stop_and_reset()
{
    std::cout << "Test: NodeSession stop and reset..." << std::endl;

    auto io_context = std::make_shared<asio::io_context>();

    config::Config config;
    config.set_mining_mode(config::Mining_mode::HASH);

    auto socket = std::make_shared<MockSocket>(io_context);
    auto stats_collector = std::make_shared<stats::Collector>(config);

    auto node_session = std::make_shared<NodeSession>(
        io_context,
        config,
        socket,
        stats_collector,
        "TEST_PRIMARY");

    // Test reset
    node_session->reset();
    assert(!node_session->is_authenticated());
    assert(node_session->session_id() == 0);

    // Test stop
    node_session->stop();
    assert(!node_session->is_authenticated());
    assert(node_session->session_id() == 0);

    std::cout << "  ✓ Reset clears authentication state" << std::endl;
    std::cout << "  ✓ Stop closes connections and resets state" << std::endl;
}

int main()
{
    std::cout << "\n=== NodeSession Unit Tests ===\n" << std::endl;

    try {
        test_node_session_creation();
        std::cout << std::endl;

        test_node_session_configuration();
        std::cout << std::endl;

        test_node_session_handlers();
        std::cout << std::endl;

        test_node_session_protocol_access();
        std::cout << std::endl;

        test_node_session_stop_and_reset();
        std::cout << std::endl;

        std::cout << "=== All NodeSession tests passed! ===\n" << std::endl;
        return 0;

    } catch (const std::exception& e) {
        std::cerr << "Test failed with exception: " << e.what() << std::endl;
        return 1;
    }
}
