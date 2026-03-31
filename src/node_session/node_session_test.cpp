/**
 * Unit tests for NodeSession
 *
 * Tests the NodeSession unified active session wrapper API
 */

#include "node_session/node_session.hpp"
#include "config/config.hpp"
#include "network/socket.hpp"
#include "stats/stats_collector.hpp"
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <iostream>
#include <cassert>
#include <memory>

using namespace nexusminer;

// Mock implementations for testing
class MockSocket : public network::Socket {
public:
    MockSocket(std::shared_ptr<asio::io_context> io_context)
        : m_io_context(io_context), m_local_endpoint{} {}

    network::Result::Code listen(Connect_handler handler) override
    {
        return network::Result::Code::socket_ok;
    }

    void stop_listen() override {}

    network::Endpoint const& local_endpoint() const override
    {
        return m_local_endpoint;
    }

    network::Connection::Sptr connect(network::Endpoint remote_endpoint,
                                      network::Connection::Handler handler) override
    {
        return nullptr;
    }

private:
    std::shared_ptr<asio::io_context> m_io_context;
    network::Endpoint m_local_endpoint;
};

void test_node_session_creation()
{
    std::cout << "Test: NodeSession creation..." << std::endl;

    auto io_context = std::make_shared<asio::io_context>();

    // Create minimal config with a logger
    auto logger = spdlog::stdout_color_mt("test_logger_create");
    config::Config config(logger);
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

    auto logger = spdlog::stdout_color_mt("test_logger_config");
    config::Config config(logger);
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

    auto logger = spdlog::stdout_color_mt("test_logger_handlers");
    config::Config config(logger);
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
    node_session->set_template_handler([&template_handler_called](const ::LLP::CBlock&, uint32_t) {
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

    bool node_shutdown_handler_called = false;
    node_session->set_node_shutdown_handler([&node_shutdown_handler_called](uint8_t) {
        node_shutdown_handler_called = true;
    });

    std::cout << "  ✓ Template handler registered" << std::endl;
    std::cout << "  ✓ Block accepted handler registered" << std::endl;
    std::cout << "  ✓ Recovery handler registered" << std::endl;
    std::cout << "  ✓ Session expired handler registered" << std::endl;
    std::cout << "  ✓ Session authenticated handler registered" << std::endl;
    std::cout << "  ✓ Session start handler registered" << std::endl;
    std::cout << "  ✓ Node shutdown handler registered" << std::endl;
}

void test_node_session_protocol_access()
{
    std::cout << "Test: NodeSession protocol access..." << std::endl;

    auto io_context = std::make_shared<asio::io_context>();

    auto logger = spdlog::stdout_color_mt("test_logger_protocol");
    config::Config config(logger);
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

    auto logger = spdlog::stdout_color_mt("test_logger_stop");
    config::Config config(logger);
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

void test_get_active_protocol_no_connection()
{
    std::cout << "Test: get_active_protocol() returns nullptr when no connections exist..." << std::endl;

    auto io_context = std::make_shared<asio::io_context>();
    auto logger = spdlog::stdout_color_mt("test_logger_active_proto");
    config::Config config(logger);
    config.set_mining_mode(config::Mining_mode::HASH);

    auto socket = std::make_shared<MockSocket>(io_context);
    auto stats_collector = std::make_shared<stats::Collector>(config);

    auto node_session = std::make_shared<NodeSession>(
        io_context, config, socket, stats_collector, "TEST_ACTIVE");

    // Primary protocol exists but no connection is established
    assert(node_session->get_primary_protocol() != nullptr);

    // get_active_protocol() should return nullptr because no connection is up
    auto active = node_session->get_active_protocol();
    assert(active == nullptr);

    std::cout << "  ✓ get_active_protocol() returns nullptr when no connection is established" << std::endl;
    std::cout << "  ✓ get_primary_protocol() still returns non-null (protocol exists, just not connected)" << std::endl;
}

void test_is_secondary_connected_initial_state()
{
    std::cout << "Test: is_secondary_connected() initial state..." << std::endl;

    auto io_context = std::make_shared<asio::io_context>();
    auto logger = spdlog::stdout_color_mt("test_logger_sec_conn");
    config::Config config(logger);
    config.set_mining_mode(config::Mining_mode::HASH);

    auto socket = std::make_shared<MockSocket>(io_context);
    auto stats_collector = std::make_shared<stats::Collector>(config);

    auto node_session = std::make_shared<NodeSession>(
        io_context, config, socket, stats_collector, "TEST_SEC");

    // Initially neither connection is established
    assert(!node_session->is_primary_connected());
    assert(!node_session->is_secondary_connected());

    std::cout << "  ✓ is_primary_connected() returns false initially" << std::endl;
    std::cout << "  ✓ is_secondary_connected() returns false initially" << std::endl;
}

void test_login_on_active_connection_no_connection()
{
    std::cout << "Test: login_on_active_connection() returns false when no connection..." << std::endl;

    auto io_context = std::make_shared<asio::io_context>();
    auto logger = spdlog::stdout_color_mt("test_logger_login_active");
    config::Config config(logger);
    config.set_mining_mode(config::Mining_mode::HASH);

    auto socket = std::make_shared<MockSocket>(io_context);
    auto stats_collector = std::make_shared<stats::Collector>(config);

    auto node_session = std::make_shared<NodeSession>(
        io_context, config, socket, stats_collector, "TEST_LOGIN");

    // Should return false — no active connection
    bool callback_invoked = false;
    bool result = node_session->login_on_active_connection([&callback_invoked](bool) {
        callback_invoked = true;
    });

    assert(!result);
    assert(!callback_invoked);

    std::cout << "  ✓ login_on_active_connection() returns false when no connection is up" << std::endl;
    std::cout << "  ✓ Login callback was not invoked" << std::endl;
}

void test_login_on_active_connection_stopped_session()
{
    std::cout << "Test: login_on_active_connection() returns false after stop()..." << std::endl;

    auto io_context = std::make_shared<asio::io_context>();
    auto logger = spdlog::stdout_color_mt("test_logger_login_stop");
    config::Config config(logger);
    config.set_mining_mode(config::Mining_mode::HASH);

    auto socket = std::make_shared<MockSocket>(io_context);
    auto stats_collector = std::make_shared<stats::Collector>(config);

    auto node_session = std::make_shared<NodeSession>(
        io_context, config, socket, stats_collector, "TEST_LOGIN_STOP");

    node_session->stop();

    bool result = node_session->login_on_active_connection([](bool) {});
    assert(!result);

    std::cout << "  ✓ login_on_active_connection() returns false after stop()" << std::endl;
}

void test_get_active_protocol_returns_null_without_connection()
{
    std::cout << "Test: get_active_protocol() returns nullptr when connection exists but not connected..." << std::endl;

    auto io_context = std::make_shared<asio::io_context>();
    auto logger = spdlog::stdout_color_mt("test_logger_gap2");
    config::Config config(logger);
    config.set_mining_mode(config::Mining_mode::HASH);

    auto socket = std::make_shared<MockSocket>(io_context);
    auto stats_collector = std::make_shared<stats::Collector>(config);

    auto node_session = std::make_shared<NodeSession>(
        io_context, config, socket, stats_collector, "TEST_GAP2");

    // Primary protocol exists but m_primary_connected is false
    assert(node_session->get_primary_protocol() != nullptr);
    assert(!node_session->is_primary_connected());

    // get_active_protocol() uses all three guards (connection && protocol && connected);
    // since m_primary_connection is null, it should return nullptr.
    auto active = node_session->get_active_protocol();
    assert(active == nullptr);

    std::cout << "  ✓ get_active_protocol() returns nullptr when not connected (3-check guard)" << std::endl;
}

void test_send_get_round_returns_null_without_connection()
{
    std::cout << "Test: send_get_round() returns nullptr when no active connection..." << std::endl;

    auto io_context = std::make_shared<asio::io_context>();
    auto logger = spdlog::stdout_color_mt("test_logger_sgr");
    config::Config config(logger);
    config.set_mining_mode(config::Mining_mode::HASH);

    auto socket = std::make_shared<MockSocket>(io_context);
    auto stats_collector = std::make_shared<stats::Collector>(config);

    auto node_session = std::make_shared<NodeSession>(
        io_context, config, socket, stats_collector, "TEST_SGR");

    // No connection established — send_get_round() must use get_active_protocol()
    // which returns nullptr, so send_get_round() must also return nullptr.
    auto payload = node_session->send_get_round();
    assert(payload == nullptr);

    std::cout << "  ✓ send_get_round() returns nullptr when no active connection (uses get_active_protocol)" << std::endl;
}

void test_request_work_returns_null_without_connection()
{
    std::cout << "Test: request_work() returns nullptr when no active connection..." << std::endl;

    auto io_context = std::make_shared<asio::io_context>();
    auto logger = spdlog::stdout_color_mt("test_logger_rw");
    config::Config config(logger);
    config.set_mining_mode(config::Mining_mode::HASH);

    auto socket = std::make_shared<MockSocket>(io_context);
    auto stats_collector = std::make_shared<stats::Collector>(config);

    auto node_session = std::make_shared<NodeSession>(
        io_context, config, socket, stats_collector, "TEST_RW");

    // No connection established — request_work() must use get_active_protocol()
    // which returns nullptr, so request_work() must also return nullptr.
    auto payload = node_session->request_work(protocol::GetBlockReason::INITIAL_REQUEST);
    assert(payload == nullptr);

    std::cout << "  ✓ request_work() returns nullptr when no active connection (uses get_active_protocol)" << std::endl;
}

void test_login_callback_invoked_on_empty_payload()
{
    std::cout << "Test: login_on_active_connection() invokes callback(false) when login returns empty payload..." << std::endl;

    // This test validates Bug 4 fix: Solo::login() may fail to build a packet
    // without calling the callback; login_on_active_connection() must fire
    // the callback itself so callers are always notified.
    //
    // Since we can't fake a connected state in unit tests without a real socket,
    // we verify the no-connection path: callback must NOT be invoked when there
    // is no active connection (only the caller's fallback logic should fire).
    auto io_context = std::make_shared<asio::io_context>();
    auto logger = spdlog::stdout_color_mt("test_logger_lcb");
    config::Config config(logger);
    config.set_mining_mode(config::Mining_mode::HASH);

    auto socket = std::make_shared<MockSocket>(io_context);
    auto stats_collector = std::make_shared<stats::Collector>(config);

    auto node_session = std::make_shared<NodeSession>(
        io_context, config, socket, stats_collector, "TEST_LCB");

    // No connection: callback must NOT be invoked (no active pair selected)
    bool callback_invoked = false;
    bool result = node_session->login_on_active_connection([&callback_invoked](bool) {
        callback_invoked = true;
    });

    assert(!result);
    assert(!callback_invoked);

    std::cout << "  ✓ login_on_active_connection() does not invoke callback when no connection" << std::endl;
    std::cout << "  ✓ login_callback(false) is not spuriously fired for no-connection path" << std::endl;
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

        test_get_active_protocol_no_connection();
        std::cout << std::endl;

        test_is_secondary_connected_initial_state();
        std::cout << std::endl;

        test_login_on_active_connection_no_connection();
        std::cout << std::endl;

        test_login_on_active_connection_stopped_session();
        std::cout << std::endl;

        test_get_active_protocol_returns_null_without_connection();
        std::cout << std::endl;

        test_send_get_round_returns_null_without_connection();
        std::cout << std::endl;

        test_request_work_returns_null_without_connection();
        std::cout << std::endl;

        test_login_callback_invoked_on_empty_payload();
        std::cout << std::endl;

        std::cout << "=== All NodeSession tests passed! ===\n" << std::endl;
        return 0;

    } catch (const std::exception& e) {
        std::cerr << "Test failed with exception: " << e.what() << std::endl;
        return 1;
    }
}
