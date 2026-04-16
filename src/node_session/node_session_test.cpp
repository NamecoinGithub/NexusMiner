/**
 * Unit tests for NodeSession
 */

#include "node_session/node_session.hpp"
#include "config/config.hpp"
#include "network/socket.hpp"
#include "stats/stats_collector.hpp"
#include "protocol/packet_builder.hpp"
#include "dual_connection_manager.hpp"
#include "miner_opcodes.hpp"

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include <cassert>
#include <iostream>
#include <memory>
#include <utility>
#include <vector>

using namespace nexusminer;

namespace {

class MockConnection final : public network::Connection {
public:
    explicit MockConnection(const network::Endpoint& remote_endpoint)
        : m_remote_endpoint(remote_endpoint)
        , m_local_endpoint(network::Transport_protocol::tcp, "127.0.0.1", 0)
        , m_protocol_lane(determine_lane_from_port(remote_endpoint.port()))
    {
    }

    network::Endpoint const& remote_endpoint() const override { return m_remote_endpoint; }
    network::Endpoint const& local_endpoint() const override { return m_local_endpoint; }

    void transmit(network::Shared_payload tx_buffer) override
    {
        if (!tx_buffer) {
            return;
        }
        m_transmissions.push_back(*tx_buffer);
    }

    void close() override
    {
        m_closed = true;
    }

    ProtocolLane get_protocol_lane() const override
    {
        return m_protocol_lane;
    }

    std::size_t transmit_count() const { return m_transmissions.size(); }
    bool closed() const { return m_closed; }
    const std::vector<network::Payload>& transmissions() const { return m_transmissions; }

private:
    network::Endpoint m_remote_endpoint;
    network::Endpoint m_local_endpoint;
    ProtocolLane m_protocol_lane{ProtocolLane::UNKNOWN};
    bool m_closed{false};
    std::vector<network::Payload> m_transmissions;
};

class MockSocket final : public network::Socket {
public:
    explicit MockSocket(std::shared_ptr<asio::io_context> io_context)
        : m_io_context(std::move(io_context))
    {
    }

    network::Result::Code listen(Connect_handler) override
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
        auto connection = std::make_shared<MockConnection>(remote_endpoint);
        m_connections.push_back(connection);
        m_handlers.push_back(std::move(handler));

        if (m_emit_connect_synchronously) {
            m_handlers.back()(m_connect_result, network::Shared_payload{});
        }

        return connection;
    }

    void emit_receive(std::size_t index, network::Shared_payload payload)
    {
        m_handlers.at(index)(network::Result::receive_ok, std::move(payload));
    }

    std::shared_ptr<MockConnection> connection(std::size_t index) const
    {
        return m_connections.at(index);
    }

    std::size_t connect_count() const
    {
        return m_connections.size();
    }

    bool m_emit_connect_synchronously{true};
    network::Result::Code m_connect_result{network::Result::connection_ok};

private:
    std::shared_ptr<asio::io_context> m_io_context;
    network::Endpoint m_local_endpoint;
    std::vector<std::shared_ptr<MockConnection>> m_connections;
    std::vector<network::Connection::Handler> m_handlers;
};

std::shared_ptr<spdlog::logger> make_logger(const std::string& name)
{
    if (auto existing = spdlog::get(name)) {
        return existing;
    }
    return spdlog::stdout_color_mt(name);
}

network::Endpoint make_endpoint(uint16_t port)
{
    return network::Endpoint{network::Transport_protocol::tcp, "127.0.0.1", port};
}

void pump_io(const std::shared_ptr<asio::io_context>& io_context)
{
    io_context->restart();
    while (io_context->poll() > 0) {
    }
}

void configure_valid_auth(NodeSession& node_session)
{
    std::vector<uint8_t> pubkey(897, 0xAA);
    std::vector<uint8_t> privkey(1281, 0xBB);
    std::vector<uint8_t> genesis(32, 0x11);
    node_session.set_miner_keys(pubkey, privkey);
    node_session.set_tritium_genesis(genesis);
}

network::Shared_payload build_auth_result_packet(ProtocolLane lane, uint8_t status, uint32_t session_id = 0)
{
    network::Payload payload{status};
    if (status != 0) {
        payload.push_back(static_cast<uint8_t>(session_id & 0xFF));
        payload.push_back(static_cast<uint8_t>((session_id >> 8) & 0xFF));
        payload.push_back(static_cast<uint8_t>((session_id >> 16) & 0xFF));
        payload.push_back(static_cast<uint8_t>((session_id >> 24) & 0xFF));
    }
    return protocol::PacketBuilder::build(lane, nexusminer::LLP::MINER_AUTH_RESULT, payload);
}

std::shared_ptr<NodeSession> make_node_session(const std::shared_ptr<asio::io_context>& io_context,
                                               config::Config& config,
                                               const std::shared_ptr<MockSocket>& socket,
                                               const std::string& label,
                                               DualConnectionManager* dcm = nullptr)
{
    auto stats_collector = std::make_shared<stats::Collector>(config);
    return std::make_shared<NodeSession>(io_context, config, socket, stats_collector, label, dcm);
}

void test_node_session_creation()
{
    std::cout << "Test: NodeSession creation..." << std::endl;

    auto io_context = std::make_shared<asio::io_context>();
    config::Config config(make_logger("test_logger_create"));
    config.set_mining_mode(config::Mining_mode::HASH);
    config.set_enable_sim_link(false);

    auto socket = std::make_shared<MockSocket>(io_context);
    auto node_session = make_node_session(io_context, config, socket, "TEST_PRIMARY");

    assert(node_session != nullptr);
    assert(!node_session->is_authenticated());
    assert(node_session->session_id() == protocol::SessionId(0u));
    assert(!node_session->is_session_active());

    std::cout << "  ✓ NodeSession created successfully" << std::endl;
}

void test_node_session_configuration()
{
    std::cout << "Test: NodeSession configuration..." << std::endl;

    auto io_context = std::make_shared<asio::io_context>();
    config::Config config(make_logger("test_logger_config"));
    config.set_mining_mode(config::Mining_mode::PRIME);
    config.set_enable_sim_link(false);

    auto socket = std::make_shared<MockSocket>(io_context);
    auto node_session = make_node_session(io_context, config, socket, "TEST_CONFIG");

    configure_valid_auth(*node_session);
    node_session->set_reward_address("2S6ymao1fSUfxvsT9nYCKPKmPPRWRp3KDj");
    node_session->set_keepalive_interval(12);

    std::cout << "  ✓ Miner keys, reward address, genesis, and keepalive configured" << std::endl;
}

void test_node_session_stop_and_reset()
{
    std::cout << "Test: NodeSession stop and reset..." << std::endl;

    auto io_context = std::make_shared<asio::io_context>();
    config::Config config(make_logger("test_logger_stop"));
    config.set_mining_mode(config::Mining_mode::HASH);
    config.set_enable_sim_link(false);

    auto socket = std::make_shared<MockSocket>(io_context);
    auto node_session = make_node_session(io_context, config, socket, "TEST_STOP");

    node_session->reset();
    assert(!node_session->is_authenticated());
    assert(node_session->session_id() == protocol::SessionId(0u));

    node_session->stop();
    assert(!node_session->is_authenticated());
    assert(node_session->session_id() == protocol::SessionId(0u));

    std::cout << "  ✓ Reset and stop clear authentication state" << std::endl;
}

void test_get_active_protocol_no_connection()
{
    std::cout << "Test: get_active_protocol() without connection..." << std::endl;

    auto io_context = std::make_shared<asio::io_context>();
    config::Config config(make_logger("test_logger_active_proto"));
    config.set_mining_mode(config::Mining_mode::HASH);
    config.set_enable_sim_link(false);

    auto socket = std::make_shared<MockSocket>(io_context);
    auto node_session = make_node_session(io_context, config, socket, "TEST_ACTIVE");

    assert(node_session->get_primary_protocol() != nullptr);
    assert(node_session->get_active_protocol() == nullptr);
    assert(!node_session->is_primary_connected());
    assert(!node_session->is_secondary_connected());

    std::cout << "  ✓ No active protocol is reported before connect()" << std::endl;
}

void test_login_on_active_connection_no_connection()
{
    std::cout << "Test: login_on_active_connection() without connection..." << std::endl;

    auto io_context = std::make_shared<asio::io_context>();
    config::Config config(make_logger("test_logger_login_active"));
    config.set_mining_mode(config::Mining_mode::HASH);
    config.set_enable_sim_link(false);

    auto socket = std::make_shared<MockSocket>(io_context);
    auto node_session = make_node_session(io_context, config, socket, "TEST_LOGIN");

    bool callback_invoked = false;
    bool result = node_session->login_on_active_connection([&callback_invoked](bool) {
        callback_invoked = true;
    });

    assert(!result);
    assert(!callback_invoked);

    std::cout << "  ✓ Reauth is rejected when no active connection exists" << std::endl;
}

void test_login_on_active_connection_stopped_session()
{
    std::cout << "Test: login_on_active_connection() after stop()..." << std::endl;

    auto io_context = std::make_shared<asio::io_context>();
    config::Config config(make_logger("test_logger_login_stop"));
    config.set_mining_mode(config::Mining_mode::HASH);
    config.set_enable_sim_link(false);

    auto socket = std::make_shared<MockSocket>(io_context);
    auto node_session = make_node_session(io_context, config, socket, "TEST_LOGIN_STOP");

    node_session->stop();

    bool result = node_session->login_on_active_connection([](bool) {});
    assert(!result);

    std::cout << "  ✓ Reauth is rejected once the session is stopped" << std::endl;
}

void test_connect_callback_waits_for_full_authentication_stateless()
{
    std::cout << "Test: connect() callback waits for MINER_AUTH_RESULT on stateless lane..." << std::endl;

    auto io_context = std::make_shared<asio::io_context>();
    config::Config config(make_logger("test_logger_connect_ok"));
    config.set_mining_mode(config::Mining_mode::HASH);
    config.set_enable_sim_link(false);

    DualConnectionManager dcm;
    auto socket = std::make_shared<MockSocket>(io_context);
    auto node_session = make_node_session(io_context, config, socket, "TEST_CONNECT_OK", &dcm);
    configure_valid_auth(*node_session);

    bool callback_invoked = false;
    bool callback_success = false;
    bool connect_started = node_session->connect(make_endpoint(ProtocolPorts::STATELESS_PORT),
                                                 [&callback_invoked, &callback_success](bool success) {
                                                     callback_invoked = true;
                                                     callback_success = success;
                                                 });

    assert(connect_started);
    assert(socket->connect_count() == 1);
    assert(!callback_invoked);

    pump_io(io_context);

    auto connection = socket->connection(0);
    assert(node_session->is_primary_connected());
    assert(connection->transmit_count() == 1);
    assert(!callback_invoked);
    assert(!node_session->is_authenticated());
    assert(dcm.mining_lane() == ProtocolLane::STATELESS);
    assert(dcm.is_stateless_alive());

    socket->emit_receive(0, build_auth_result_packet(ProtocolLane::STATELESS, 0x01, 0x11223344u));

    assert(callback_invoked);
    assert(callback_success);
    assert(node_session->is_authenticated());
    assert(node_session->session_id() == protocol::SessionId(0x11223344u));

    std::cout << "  ✓ connect() success is deferred until full authentication completes" << std::endl;
}

void test_connect_callback_reports_auth_failure_on_login_kickoff()
{
    std::cout << "Test: connect() callback reports login kickoff failure..." << std::endl;

    auto io_context = std::make_shared<asio::io_context>();
    config::Config config(make_logger("test_logger_connect_auth_fail"));
    config.set_mining_mode(config::Mining_mode::HASH);
    config.set_enable_sim_link(false);

    auto socket = std::make_shared<MockSocket>(io_context);
    auto node_session = make_node_session(io_context, config, socket, "TEST_CONNECT_AUTH_FAIL");

    bool callback_invoked = false;
    bool callback_success = true;
    bool connect_started = node_session->connect(make_endpoint(ProtocolPorts::STATELESS_PORT),
                                                 [&callback_invoked, &callback_success](bool success) {
                                                     callback_invoked = true;
                                                     callback_success = success;
                                                 });

    assert(connect_started);
    pump_io(io_context);

    auto connection = socket->connection(0);
    assert(callback_invoked);
    assert(!callback_success);
    assert(connection->transmit_count() == 0);
    assert(!node_session->is_authenticated());

    std::cout << "  ✓ connect() failure is reported when auth cannot even start" << std::endl;
}

void test_session_authenticated_handler_works_on_legacy_primary_lane()
{
    std::cout << "Test: legacy 8323 remains a valid configured primary lane..." << std::endl;

    auto io_context = std::make_shared<asio::io_context>();
    config::Config config(make_logger("test_logger_legacy_primary"));
    config.set_mining_mode(config::Mining_mode::HASH);
    config.set_enable_sim_link(false);

    DualConnectionManager dcm;
    auto socket = std::make_shared<MockSocket>(io_context);
    auto node_session = make_node_session(io_context, config, socket, "TEST_LEGACY_PRIMARY", &dcm);
    configure_valid_auth(*node_session);

    bool connect_callback_invoked = false;
    bool connect_callback_success = false;
    bool session_handler_invoked = false;
    protocol::SessionId authenticated_sid{};

    node_session->set_session_authenticated_handler(
        [&session_handler_invoked, &authenticated_sid](protocol::SessionId sid) {
            session_handler_invoked = true;
            authenticated_sid = sid;
        });

    bool connect_started = node_session->connect(make_endpoint(ProtocolPorts::LEGACY_PORT),
                                                 [&connect_callback_invoked, &connect_callback_success](bool success) {
                                                     connect_callback_invoked = true;
                                                     connect_callback_success = success;
                                                 });

    assert(connect_started);
    pump_io(io_context);
    assert(!connect_callback_invoked);

    socket->emit_receive(0, build_auth_result_packet(ProtocolLane::LEGACY, 0x01, 0x01020304u));

    assert(connect_callback_invoked);
    assert(connect_callback_success);
    assert(session_handler_invoked);
    assert(authenticated_sid == protocol::SessionId(0x01020304u));
    assert(node_session->is_authenticated());
    assert(dcm.mining_lane() == ProtocolLane::LEGACY);
    assert(dcm.is_legacy_alive());
    assert(!dcm.is_stateless_alive());

    std::cout << "  ✓ Legacy primary lane authenticates and propagates session callbacks" << std::endl;
}

void test_login_on_active_connection_uses_active_lane()
{
    std::cout << "Test: login_on_active_connection() reuses the active configured lane..." << std::endl;

    auto io_context = std::make_shared<asio::io_context>();
    config::Config config(make_logger("test_logger_reauth_lane"));
    config.set_mining_mode(config::Mining_mode::HASH);
    config.set_enable_sim_link(false);

    auto socket = std::make_shared<MockSocket>(io_context);
    auto node_session = make_node_session(io_context, config, socket, "TEST_REAUTH_LANE");
    configure_valid_auth(*node_session);

    bool connect_callback_invoked = false;
    bool connect_started = node_session->connect(make_endpoint(ProtocolPorts::LEGACY_PORT),
                                                 [&connect_callback_invoked](bool) {
                                                     connect_callback_invoked = true;
                                                 });

    assert(connect_started);
    pump_io(io_context);

    auto connection = socket->connection(0);
    socket->emit_receive(0, build_auth_result_packet(ProtocolLane::LEGACY, 0x01, 0x0A0B0C0Du));
    assert(connect_callback_invoked);

    std::size_t transmit_count_before = connection->transmit_count();
    bool login_callback_invoked = false;
    bool login_callback_success = false;
    bool reauth_started = node_session->login_on_active_connection(
        [&login_callback_invoked, &login_callback_success](bool success) {
            login_callback_invoked = true;
            login_callback_success = success;
        });

    assert(reauth_started);
    assert(login_callback_invoked);
    assert(login_callback_success);
    assert(connection->transmit_count() == transmit_count_before + 1);
    assert(!connection->transmissions().back().empty());
    assert(connection->transmissions().back().front() == nexusminer::LLP::MINER_AUTH_INIT);

    std::cout << "  ✓ In-band reauth stays on the currently active lane" << std::endl;
}

void test_session_expired_handler_fires_from_authoritative_packet()
{
    std::cout << "Test: SESSION_EXPIRED packet fires the NodeSession callback and clears auth..." << std::endl;

    auto io_context = std::make_shared<asio::io_context>();
    config::Config config(make_logger("test_logger_session_expired"));
    config.set_mining_mode(config::Mining_mode::HASH);
    config.set_enable_sim_link(false);

    DualConnectionManager dcm;
    auto socket = std::make_shared<MockSocket>(io_context);
    auto node_session = make_node_session(io_context, config, socket, "TEST_SESSION_EXPIRED", &dcm);
    configure_valid_auth(*node_session);

    int expired_count = 0;
    node_session->set_session_expired_handler([&expired_count]() {
        ++expired_count;
    });

    bool connect_callback_invoked = false;
    bool connect_started = node_session->connect(make_endpoint(ProtocolPorts::STATELESS_PORT),
                                                 [&connect_callback_invoked](bool) {
                                                     connect_callback_invoked = true;
                                                 });

    assert(connect_started);
    pump_io(io_context);
    socket->emit_receive(0, build_auth_result_packet(ProtocolLane::STATELESS, 0x01, 0xA1B2C3D4u));

    assert(connect_callback_invoked);
    assert(node_session->is_authenticated());
    assert(dcm.is_stateless_alive());

    network::Payload session_expired_payload{
        0xD4, 0xC3, 0xB2, 0xA1,
        static_cast<uint8_t>(nexusminer::LLP::StatelessMining::SessionExpiredReason::EXPIRED_INACTIVITY)
    };
    node_session->get_primary_protocol()->process_messages(
        Packet(static_cast<uint16_t>(nexusminer::LLP::StatelessMining::SESSION_EXPIRED),
               session_expired_payload),
        socket->connection(0));

    assert(expired_count == 1);
    assert(!node_session->is_authenticated());
    assert(node_session->session_id() == protocol::SessionId(0u));
    assert(dcm.is_stateless_alive());

    std::cout << "  ✓ SESSION_EXPIRED propagates from the packet event and clears session state" << std::endl;
}

void test_node_shutdown_handler_fires_from_packet()
{
    std::cout << "Test: NODE_SHUTDOWN packet fires the NodeSession callback..." << std::endl;

    auto io_context = std::make_shared<asio::io_context>();
    config::Config config(make_logger("test_logger_node_shutdown"));
    config.set_mining_mode(config::Mining_mode::HASH);
    config.set_enable_sim_link(false);

    auto socket = std::make_shared<MockSocket>(io_context);
    auto node_session = make_node_session(io_context, config, socket, "TEST_NODE_SHUTDOWN");
    configure_valid_auth(*node_session);

    int shutdown_count = 0;
    uint8_t shutdown_reason = 0;
    node_session->set_node_shutdown_handler([&shutdown_count, &shutdown_reason](uint8_t reason) {
        ++shutdown_count;
        shutdown_reason = reason;
    });

    bool connect_callback_invoked = false;
    bool connect_started = node_session->connect(make_endpoint(ProtocolPorts::STATELESS_PORT),
                                                 [&connect_callback_invoked](bool) {
                                                     connect_callback_invoked = true;
                                                 });

    assert(connect_started);
    pump_io(io_context);
    socket->emit_receive(0, build_auth_result_packet(ProtocolLane::STATELESS, 0x01, 0x12345678u));

    assert(connect_callback_invoked);

    node_session->get_primary_protocol()->process_messages(
        Packet(static_cast<uint16_t>(nexusminer::LLP::StatelessMining::NODE_SHUTDOWN),
               network::Payload{
                   static_cast<uint8_t>(nexusminer::LLP::StatelessMining::ShutdownReason::MAINTENANCE)
               }),
        socket->connection(0));

    assert(shutdown_count == 1);
    assert(shutdown_reason == static_cast<uint8_t>(nexusminer::LLP::StatelessMining::ShutdownReason::MAINTENANCE));

    std::cout << "  ✓ NODE_SHUTDOWN is forwarded from the authoritative packet event" << std::endl;
}

void test_connect_failure_updates_dcm_for_configured_lane()
{
    std::cout << "Test: connection failure updates DCM on the configured lane..." << std::endl;

    auto run_case = [](uint16_t port, ProtocolLane expected_lane) {
        auto io_context = std::make_shared<asio::io_context>();
        config::Config config(make_logger(port == ProtocolPorts::LEGACY_PORT
                                              ? "test_logger_connect_fail_legacy"
                                              : "test_logger_connect_fail_stateless"));
        config.set_mining_mode(config::Mining_mode::HASH);
        config.set_enable_sim_link(false);

        DualConnectionManager dcm;
        auto socket = std::make_shared<MockSocket>(io_context);
        socket->m_connect_result = network::Result::connection_error;

        auto node_session = make_node_session(io_context, config, socket, "TEST_CONNECT_FAIL", &dcm);
        configure_valid_auth(*node_session);

        bool callback_invoked = false;
        bool callback_success = true;
        bool connect_started = node_session->connect(make_endpoint(port),
                                                     [&callback_invoked, &callback_success](bool success) {
                                                         callback_invoked = true;
                                                         callback_success = success;
                                                     });

        assert(connect_started);
        pump_io(io_context);

        assert(callback_invoked);
        assert(!callback_success);
        assert(!dcm.any_lane_alive());
        assert(dcm.consume_bypass(expected_lane));
        assert(!dcm.consume_bypass(expected_lane == ProtocolLane::LEGACY
                                       ? ProtocolLane::STATELESS
                                       : ProtocolLane::LEGACY));
    };

    run_case(ProtocolPorts::STATELESS_PORT, ProtocolLane::STATELESS);
    run_case(ProtocolPorts::LEGACY_PORT, ProtocolLane::LEGACY);

    std::cout << "  ✓ DCM failure bookkeeping follows the configured lane symmetrically" << std::endl;
}

void test_dual_lane_connect_is_symmetric_across_configured_primary_lanes()
{
    std::cout << "Test: dual-lane connect/auth behavior is symmetric across configured primary lanes..." << std::endl;

    auto run_case = [](uint16_t primary_port, uint16_t secondary_port) {
        auto io_context = std::make_shared<asio::io_context>();
        config::Config config(make_logger(primary_port == ProtocolPorts::LEGACY_PORT
                                              ? "test_logger_dual_legacy_primary"
                                              : "test_logger_dual_stateless_primary"));
        config.set_mining_mode(config::Mining_mode::HASH);
        config.set_enable_sim_link(true);

        DualConnectionManager dcm;
        auto socket = std::make_shared<MockSocket>(io_context);
        auto node_session = make_node_session(io_context, config, socket, "TEST_DUAL_LANE", &dcm);
        configure_valid_auth(*node_session);

        bool callback_invoked = false;
        bool callback_success = false;
        bool connect_started = node_session->connect(make_endpoint(primary_port),
                                                     [&callback_invoked, &callback_success](bool success) {
                                                         callback_invoked = true;
                                                         callback_success = success;
                                                     });

        assert(connect_started);
        pump_io(io_context);

        assert(socket->connect_count() == 2);
        assert(socket->connection(0)->remote_endpoint().port() == primary_port);
        assert(socket->connection(1)->remote_endpoint().port() == secondary_port);
        assert(socket->connection(0)->get_protocol_lane() == determine_lane_from_port(primary_port));
        assert(socket->connection(1)->get_protocol_lane() == determine_lane_from_port(secondary_port));
        assert(socket->connection(0)->transmit_count() == 1);
        assert(socket->connection(1)->transmit_count() == 1);

        socket->emit_receive(0, build_auth_result_packet(determine_lane_from_port(primary_port), 0x01, 0x10203040u));
        socket->emit_receive(1, build_auth_result_packet(determine_lane_from_port(secondary_port), 0x01, 0x10203040u));

        assert(callback_invoked);
        assert(callback_success);
        assert(dcm.is_stateless_alive());
        assert(dcm.is_legacy_alive());
        assert(dcm.mining_lane() == determine_lane_from_port(primary_port));
    };

    run_case(ProtocolPorts::STATELESS_PORT, ProtocolPorts::LEGACY_PORT);
    run_case(ProtocolPorts::LEGACY_PORT, ProtocolPorts::STATELESS_PORT);

    std::cout << "  ✓ Primary-lane selection no longer assumes stateless-vs-legacy by slot" << std::endl;
}

void test_malformed_packet_does_not_fail_active_lane()
{
    std::cout << "Test: malformed packet stays diagnostic-only and does not fail the active lane..." << std::endl;

    auto io_context = std::make_shared<asio::io_context>();
    config::Config config(make_logger("test_logger_malformed_lane"));
    config.set_mining_mode(config::Mining_mode::HASH);
    config.set_enable_sim_link(false);

    DualConnectionManager dcm;
    auto socket = std::make_shared<MockSocket>(io_context);
    auto node_session = make_node_session(io_context, config, socket, "TEST_MALFORMED_LANE", &dcm);
    configure_valid_auth(*node_session);

    int session_authenticated_count = 0;
    protocol::SessionId last_sid{};
    node_session->set_session_authenticated_handler(
        [&session_authenticated_count, &last_sid](protocol::SessionId sid) {
            ++session_authenticated_count;
            last_sid = sid;
        });

    bool connect_callback_invoked = false;
    bool connect_started = node_session->connect(make_endpoint(ProtocolPorts::STATELESS_PORT),
                                                 [&connect_callback_invoked](bool) {
                                                     connect_callback_invoked = true;
                                                 });

    assert(connect_started);
    pump_io(io_context);

    socket->emit_receive(0, build_auth_result_packet(ProtocolLane::STATELESS, 0x01, 0x10203040u));
    assert(connect_callback_invoked);
    assert(node_session->is_authenticated());
    assert(session_authenticated_count == 1);
    assert(last_sid == protocol::SessionId(0x10203040u));
    assert(dcm.is_stateless_alive());

    socket->emit_receive(0, std::make_shared<network::Payload>(
        network::Payload{0x00, 0x01, 0x00, 0x00, 0x00, 0x00}));

    assert(node_session->is_primary_connected());
    assert(dcm.is_stateless_alive());

    socket->emit_receive(0, build_auth_result_packet(ProtocolLane::STATELESS, 0x01, 0x55667788u));

    assert(session_authenticated_count == 2);
    assert(last_sid == protocol::SessionId(0x55667788u));
    assert(node_session->session_id() == protocol::SessionId(0x55667788u));
    assert(dcm.is_stateless_alive());

    std::cout << "  ✓ Malformed bytes do not mark the lane failed and parsing recovers" << std::endl;
}

} // namespace

int main()
{
    std::cout << "\n=== NodeSession Unit Tests ===\n" << std::endl;

    try {
        test_node_session_creation();
        std::cout << std::endl;

        test_node_session_configuration();
        std::cout << std::endl;

        test_node_session_stop_and_reset();
        std::cout << std::endl;

        test_get_active_protocol_no_connection();
        std::cout << std::endl;

        test_login_on_active_connection_no_connection();
        std::cout << std::endl;

        test_login_on_active_connection_stopped_session();
        std::cout << std::endl;

        test_connect_callback_waits_for_full_authentication_stateless();
        std::cout << std::endl;

        test_connect_callback_reports_auth_failure_on_login_kickoff();
        std::cout << std::endl;

        test_session_authenticated_handler_works_on_legacy_primary_lane();
        std::cout << std::endl;

        test_login_on_active_connection_uses_active_lane();
        std::cout << std::endl;

        test_session_expired_handler_fires_from_authoritative_packet();
        std::cout << std::endl;

        test_node_shutdown_handler_fires_from_packet();
        std::cout << std::endl;

        test_connect_failure_updates_dcm_for_configured_lane();
        std::cout << std::endl;

        test_dual_lane_connect_is_symmetric_across_configured_primary_lanes();
        std::cout << std::endl;

        test_malformed_packet_does_not_fail_active_lane();
        std::cout << std::endl;

        std::cout << "=== All NodeSession tests passed! ===\n" << std::endl;
        return 0;

    } catch (const std::exception& e) {
        std::cerr << "Test failed with exception: " << e.what() << std::endl;
        return 1;
    }
}
