#include "node_session/node_session.hpp"
#include "protocol/solo.hpp"
#include "protocol/node_session_context.hpp"
#include "config/config.hpp"
#include "packet.hpp"
#include "miner_opcodes.hpp"
#include "dual_connection_manager.hpp"
#include "asio/post.hpp"
#include <algorithm>

namespace nexusminer {

NodeSession::NodeSession(
    std::shared_ptr<asio::io_context> io_context,
    Config& config,
    network::Socket::Sptr socket,
    std::shared_ptr<stats::Collector> stats_collector,
    const std::string& node_label,
    DualConnectionManager* dcm)
    : m_io_context(std::move(io_context))
    , m_config(config)
    , m_socket(std::move(socket))
    , m_stats_collector(std::move(stats_collector))
    , m_node_label(node_label)
    , m_dcm(dcm)
{
    m_logger = spdlog::get("miner");
    if (!m_logger) {
        m_logger = spdlog::default_logger();
    }

    m_logger->info("[NodeSession:{}] Created", m_node_label);

    // Create session manager (shared across both protocols)
    auto session_manager = std::make_shared<protocol::SessionManager>(24, m_io_context);

    // Wrap session manager in NodeSessionContext (AUTHORITATIVE session state)
    m_session_context = std::make_shared<protocol::NodeSessionContext>(session_manager);

    // Create primary protocol instance (Stateless lane, port 9323)
    // Channel is determined by mining mode (1=Prime, 2=Hash)
    // Pass shared NodeSessionContext so primary and secondary protocols share session state
    const uint8_t channel = mining_channel();
    m_primary_protocol = create_protocol(Session_lane::Primary);

    m_logger->info("[NodeSession:{}] Initialized with channel {}", m_node_label, channel);
}

bool NodeSession::connect(const network::Endpoint& node_endpoint, Connection_callback callback)
{
    if (m_stopped) {
        m_logger->warn("[NodeSession:{}] Cannot connect - session is stopped", m_node_label);
        return false;
    }

    m_logger->info("[NodeSession:{}] Connecting to node at {}",
                   m_node_label, node_endpoint.to_string());

    // Start with primary connection (stateless port)
    connect_primary(node_endpoint, std::move(callback));

    return true;
}

void NodeSession::connect_primary(const network::Endpoint& node_endpoint, Connection_callback callback)
{
    auto weak_self = std::weak_ptr<NodeSession>(shared_from_this());

    auto connection_callback = [weak_self, callback, node_endpoint](auto result, auto receive_buffer) {
        auto self = weak_self.lock();
        if (!self) return;
        self->handle_lane_event(Session_lane::Primary, node_endpoint, result,
                                std::move(receive_buffer), callback);
    };

    // Initiate connection
    auto connection = m_socket->connect(node_endpoint, connection_callback);
    if (connection) {
        m_primary_connection = std::move(connection);
        m_primary_protocol->set_connection(m_primary_connection);
        m_session_context->set_connection(m_primary_connection);
    }
}

void NodeSession::connect_secondary(const network::Endpoint& node_endpoint)
{
    if (m_secondary_connected || m_stopped) {
        return;
    }

    m_logger->info("[NodeSession:{}] Connecting secondary (legacy) to {}",
                   m_node_label, node_endpoint.to_string());

    // Create secondary protocol instance (Legacy lane, port 8323)
    // Pass shared NodeSessionContext so it uses the same session state as primary
    m_secondary_protocol = create_protocol(Session_lane::Secondary);

    auto weak_self = std::weak_ptr<NodeSession>(shared_from_this());

    auto connection_callback = [weak_self, node_endpoint](auto result, auto receive_buffer) {
        auto self = weak_self.lock();
        if (!self) return;
        self->handle_lane_event(Session_lane::Secondary, node_endpoint, result,
                                std::move(receive_buffer));
    };

    // Initiate secondary connection
    auto connection = m_socket->connect(node_endpoint, connection_callback);
    if (connection) {
        m_secondary_connection = std::move(connection);
        m_secondary_protocol->set_connection(m_secondary_connection);
    }
}

void NodeSession::process_primary_data(network::Shared_payload&& receive_buffer)
{
    process_lane_data(Session_lane::Primary, std::move(receive_buffer));
}

void NodeSession::process_secondary_data(network::Shared_payload&& receive_buffer)
{
    process_lane_data(Session_lane::Secondary, std::move(receive_buffer));
}

void NodeSession::handle_primary_connection_result(network::Result::Code result, Connection_callback callback)
{
    if (result == network::Result::connection_ok) {
        configure_connected_lane(Session_lane::Primary);

        // Start authentication
        auto auth_payload = m_primary_protocol->login([this, callback](bool login_result) {
            if (!login_result) {
                m_logger->error("[NodeSession:{}] Primary authentication failed", m_node_label);
                if (callback) callback(false);
                return;
            }

            m_logger->info("[NodeSession:{}] Primary authentication succeeded", m_node_label);
            // Note: Session state is managed by SessionManager inside Solo protocol
            // NodeSession queries session state via m_session_context

            if (callback) callback(true);
        });

        send_auth_payload(Session_lane::Primary, std::move(auth_payload), callback);
    }
}

void NodeSession::handle_secondary_connection_result(network::Result::Code result)
{
    if (result == network::Result::connection_ok && m_secondary_connection) {
        configure_connected_lane(Session_lane::Secondary);

        // Invariant: This lambda MUST call m_session_authenticated_handler on success.
        // Without it, Worker_manager never resets timers, never triggers recovery
        // transitions, and never requests the initial GET_BLOCK — leaving workers
        // stuck at "NO VALID TEMPLATE" even though the node considers the session
        // fully authenticated. This mirrors the pattern in set_session_authenticated_handler()
        // and the deferred path in connect_secondary().
        auto auth_payload = m_secondary_protocol->login([this](bool login_result) {
            if (!login_result) {
                m_logger->error("[NodeSession:{}] Secondary authentication failed", m_node_label);
                return;
            }

            m_logger->info("[NodeSession:{}] Secondary authentication succeeded", m_node_label);

            // Update DualConnectionManager: secondary lane is now alive
            if (m_dcm) {
                m_dcm->set_legacy_alive(true);
                m_logger->info("[NodeSession:{}] Secondary lane (LEGACY) authenticated → DualConnectionManager updated",
                              m_node_label);
            }

            // Notify Worker_manager so it resets timers and requests initial GET_BLOCK
            if (m_session_authenticated_handler) {
                m_session_authenticated_handler(m_secondary_protocol->get_session_id());
            }
        });

        send_auth_payload(Session_lane::Secondary, std::move(auth_payload));
    }
}

std::pair<network::Connection::Sptr, std::shared_ptr<protocol::Solo>>
NodeSession::select_active_pair() const
{
    // Single authoritative source for NodeSession's active-lane selection.
    // For either lane, all three guards are required: connection object must
    // exist, protocol must exist, and the connected flag must be set. This
    // mirrors the invariants that Connection::transmit() expects (non-null
    // handler, open socket).
    if (m_primary_connection && m_primary_protocol && m_primary_connected) {
        return {m_primary_connection, m_primary_protocol};
    }
    if (m_secondary_connection && m_secondary_protocol && m_secondary_connected) {
        return {m_secondary_connection, m_secondary_protocol};
    }
    return {nullptr, nullptr};
}

bool NodeSession::transmit(network::Shared_payload data)
{
    if (m_stopped || !data || data->empty()) {
        return false;
    }

    auto [conn, proto] = select_active_pair();
    if (conn) {
        return conn->transmit(data);
    }

    m_logger->warn("[NodeSession:{}] No active connection to transmit on", m_node_label);
    return false;
}

std::shared_ptr<protocol::Solo> NodeSession::get_active_protocol() const
{
    return select_active_pair().second;
}

protocol::SessionId NodeSession::session_id() const
{
    // Query the authoritative session context
    return m_session_context ? m_session_context->get_session_id() : protocol::SessionId{};
}

bool NodeSession::is_authenticated() const
{
    // Query the authoritative session context
    return m_session_context ? m_session_context->is_authenticated() : false;
}

bool NodeSession::is_primary_connected() const
{
    return m_primary_connected.load();
}

bool NodeSession::is_secondary_connected() const
{
    return m_secondary_connected.load();
}

bool NodeSession::is_session_active() const
{
    // Query the authoritative session context
    return m_session_context ? m_session_context->is_active() : false;
}

void NodeSession::stop()
{
    m_stopped = true;

    m_logger->info("[NodeSession:{}] Stopping", m_node_label);

    // Close connections
    if (m_primary_connection) {
        m_primary_connection->close();
        m_primary_connection.reset();
    }
    if (m_secondary_connection) {
        m_secondary_connection->close();
        m_secondary_connection.reset();
    }

    // Reset protocols
    if (m_primary_protocol) {
        m_primary_protocol->reset();
    }
    if (m_secondary_protocol) {
        m_secondary_protocol->reset();
    }

    m_primary_connected = false;
    m_secondary_connected = false;

    // Update DualConnectionManager: both lanes are now down
    if (m_dcm) {
        m_dcm->set_stateless_alive(false);
        m_dcm->set_legacy_alive(false);
        m_logger->info("[NodeSession:{}] Session stopped → DualConnectionManager lanes marked down",
                      m_node_label);
    }

    // End session in the context (clears session ID and state)
    if (m_session_context) {
        m_session_context->end_session();
    }

    // Clear accumulators
    m_primary_rx_accumulator.clear();
    m_secondary_rx_accumulator.clear();
}

void NodeSession::reset()
{
    m_logger->info("[NodeSession:{}] Resetting", m_node_label);

    // Reset protocols
    if (m_primary_protocol) {
        m_primary_protocol->reset();
    }
    if (m_secondary_protocol) {
        m_secondary_protocol->reset();
    }

    // Update DualConnectionManager: both lanes are being reset (mark down)
    if (m_dcm) {
        m_dcm->set_stateless_alive(false);
        m_dcm->set_legacy_alive(false);
        m_logger->info("[NodeSession:{}] Session reset → DualConnectionManager lanes marked down",
                      m_node_label);
    }

    // End session in the context (clears session ID and state)
    if (m_session_context) {
        m_session_context->end_session();
    }

    // Clear accumulators
    m_primary_rx_accumulator.clear();
    m_secondary_rx_accumulator.clear();
}

void NodeSession::set_template_handler(Template_handler handler)
{
    m_template_handler = std::move(handler);
    wire_template_handler(m_primary_protocol);
    wire_template_handler(m_secondary_protocol);
}

void NodeSession::set_block_accepted_handler(Block_accepted_handler handler)
{
    m_block_accepted_handler = std::move(handler);
    wire_block_accepted_handler(m_primary_protocol);
    wire_block_accepted_handler(m_secondary_protocol);
}

void NodeSession::set_recovery_initiated_handler(Recovery_handler handler)
{
    m_recovery_handler = std::move(handler);
    wire_recovery_handler(m_primary_protocol);
    wire_recovery_handler(m_secondary_protocol);
}

void NodeSession::set_session_expired_handler(Session_expired_handler handler)
{
    m_session_expired_handler = std::move(handler);
    wire_session_expired_handler(m_primary_protocol);
    wire_session_expired_handler(m_secondary_protocol);
}

void NodeSession::set_session_authenticated_handler(Session_authenticated_handler handler)
{
    m_session_authenticated_handler = std::move(handler);
    wire_session_authenticated_handler(m_primary_protocol, Session_lane::Primary);
    wire_session_authenticated_handler(m_secondary_protocol, Session_lane::Secondary);
}

void NodeSession::set_session_start_handler(Session_start_handler handler)
{
    m_session_start_handler = std::move(handler);
    wire_session_start_handler(m_primary_protocol);
    wire_session_start_handler(m_secondary_protocol);
}

void NodeSession::set_node_shutdown_handler(Node_shutdown_handler handler)
{
    m_node_shutdown_handler = std::move(handler);
    wire_node_shutdown_handler(m_primary_protocol);
    wire_node_shutdown_handler(m_secondary_protocol);
}

void NodeSession::set_miner_keys(const std::vector<uint8_t>& pubkey, const std::vector<uint8_t>& privkey)
{
    m_miner_pubkey = pubkey;
    m_miner_privkey = privkey;

    if (m_primary_protocol) {
        m_primary_protocol->set_miner_keys(pubkey, privkey);
    }
    if (m_secondary_protocol) {
        m_secondary_protocol->set_miner_keys(pubkey, privkey);
    }
}

void NodeSession::set_reward_address(const std::string& address)
{
    m_reward_address = address;

    if (m_primary_protocol) {
        m_primary_protocol->set_reward_address(address);
    }
    if (m_secondary_protocol) {
        m_secondary_protocol->set_reward_address(address);
    }
}

void NodeSession::set_tritium_genesis(const std::vector<uint8_t>& genesis)
{
    m_tritium_genesis = genesis;

    if (m_primary_protocol) {
        m_primary_protocol->set_tritium_genesis(genesis);
    }
    if (m_secondary_protocol) {
        m_secondary_protocol->set_tritium_genesis(genesis);
    }
}

void NodeSession::set_keepalive_interval(uint16_t hours)
{
    m_keepalive_interval_hours = hours;

    if (m_primary_protocol) {
        m_primary_protocol->set_keepalive_interval(hours);
    }
    if (m_secondary_protocol) {
        m_secondary_protocol->set_keepalive_interval(hours);
    }
}

network::Shared_payload NodeSession::request_work(protocol::GetBlockReason reason)
{
    auto protocol = get_active_protocol();
    if (!protocol) return nullptr;
    return protocol->get_work(reason);
}

network::Shared_payload NodeSession::submit_block(const std::vector<uint8_t>& block_data, uint64_t nonce)
{
    auto protocol = get_active_protocol();
    if (!protocol || !protocol->is_authenticated()) return nullptr;
    return protocol->submit_block(block_data, nonce);
}

network::Shared_payload NodeSession::send_get_round()
{
    auto protocol = get_active_protocol();
    if (!protocol) return nullptr;
    return protocol->send_get_round();
}

network::Shared_payload NodeSession::send_session_keepalive()
{
    auto protocol = get_active_protocol();
    if (!protocol) return nullptr;
    return protocol->send_session_keepalive();
}

bool NodeSession::login_on_active_connection(std::function<void(bool)> login_callback)
{
    if (m_stopped) {
        m_logger->warn("[NodeSession:{}] Cannot login - session is stopped", m_node_label);
        return false;
    }

    // Use select_active_pair() for atomic connection+protocol selection.
    // Both are checked together so the auth payload is always framed for
    // the correct lane (no TOCTOU between protocol selection and transmit).
    auto [conn, proto] = select_active_pair();
    if (conn && proto) {
        auto auth_payload = proto->login(login_callback);
        if (auth_payload && !auth_payload->empty()) {
            if (conn->transmit(auth_payload)) {
                return true;
            }
            m_logger->error("[NodeSession:{}] Failed to queue login payload on active connection", m_node_label);
            if (login_callback) login_callback(false);
            return false;
        }
        // Solo::login() can return empty (without invoking the callback) when
        // PacketBuilder::build() fails — e.g. if the Falcon keys are not yet
        // configured or the session state is inconsistent.  Fire the callback
        // ourselves so callers always receive notification and can schedule a retry.
        if (login_callback) login_callback(false);
        return false;
    }

    m_logger->warn("[NodeSession:{}] No active connection for login", m_node_label);
    return false;
}

uint8_t NodeSession::mining_channel() const
{
    return (m_config.get_mining_mode() == config::Mining_mode::PRIME) ? 1U : 2U;
}

std::shared_ptr<protocol::Solo> NodeSession::create_protocol(Session_lane lane)
{
    auto protocol = std::make_shared<protocol::Solo>(mining_channel(), m_stats_collector, m_session_context);
    apply_protocol_configuration(protocol, lane);
    wire_protocol_handlers(protocol, lane);
    return protocol;
}

void NodeSession::apply_protocol_configuration(const std::shared_ptr<protocol::Solo>& protocol,
                                               Session_lane lane)
{
    if (!protocol) {
        return;
    }

    if (!m_miner_pubkey.empty() && !m_miner_privkey.empty()) {
        protocol->set_miner_keys(m_miner_pubkey, m_miner_privkey);
    }
    if (!m_reward_address.empty()) {
        protocol->set_reward_address(m_reward_address);
    }
    if (!m_tritium_genesis.empty()) {
        protocol->set_tritium_genesis(m_tritium_genesis);
    }
    protocol->set_keepalive_interval(m_keepalive_interval_hours);

    if (lane == Session_lane::Secondary) {
        protocol->enable_chacha20_wrapping(true);
        protocol->enable_disposable_falcon(true);
    }
}

void NodeSession::wire_protocol_handlers(const std::shared_ptr<protocol::Solo>& protocol,
                                         Session_lane lane)
{
    wire_template_handler(protocol);
    wire_block_accepted_handler(protocol);
    wire_recovery_handler(protocol);
    wire_session_expired_handler(protocol);
    wire_session_authenticated_handler(protocol, lane);
    wire_session_start_handler(protocol);
    wire_node_shutdown_handler(protocol);
}

void NodeSession::wire_template_handler(const std::shared_ptr<protocol::Solo>& protocol)
{
    if (!protocol) {
        return;
    }
    protocol->set_block_handler([this](const ::LLP::CBlock& block, uint32_t nBits) {
        if (m_template_handler) {
            m_template_handler(block, nBits);
        }
    });
}

void NodeSession::wire_block_accepted_handler(const std::shared_ptr<protocol::Solo>& protocol)
{
    if (!protocol) {
        return;
    }
    protocol->set_block_accepted_handler(
        [this](uint32_t height, uint1024_t hash_prev, uint32_t channel, uint64_t nonce) {
            if (m_block_accepted_handler) {
                m_block_accepted_handler(height, hash_prev, channel, nonce);
            }
        });
}

void NodeSession::wire_recovery_handler(const std::shared_ptr<protocol::Solo>& protocol)
{
    if (!protocol) {
        return;
    }
    protocol->set_recovery_initiated_handler([this]() {
        if (m_recovery_handler) {
            m_recovery_handler();
        }
    });
}

void NodeSession::wire_session_expired_handler(const std::shared_ptr<protocol::Solo>& protocol)
{
    if (!protocol) {
        return;
    }
    protocol->set_session_expired_handler([this]() {
        if (m_session_expired_handler) {
            m_session_expired_handler();
        }
    });
}

void NodeSession::wire_session_authenticated_handler(const std::shared_ptr<protocol::Solo>& protocol,
                                                     Session_lane lane)
{
    if (!protocol) {
        return;
    }
    protocol->set_session_authenticated_handler([this, lane](protocol::SessionId sid) {
        if (m_dcm && !sid.is_default()) {
            if (lane == Session_lane::Primary) {
                m_dcm->set_stateless_alive(true);
            } else {
                m_dcm->set_legacy_alive(true);
            }
            m_logger->info("[NodeSession:{}] {} lane ({}) authenticated → DualConnectionManager updated",
                          m_node_label,
                          lane_name(lane),
                          (lane == Session_lane::Primary ? "STATELESS" : "LEGACY"));
        }

        if (m_session_authenticated_handler) {
            m_session_authenticated_handler(sid);
        }
    });
}

void NodeSession::wire_session_start_handler(const std::shared_ptr<protocol::Solo>& protocol)
{
    if (!protocol) {
        return;
    }
    protocol->set_session_start_handler([this](uint16_t hours) {
        if (m_session_start_handler) {
            m_session_start_handler(hours);
        }
    });
}

void NodeSession::wire_node_shutdown_handler(const std::shared_ptr<protocol::Solo>& protocol)
{
    if (!protocol) {
        return;
    }
    protocol->set_node_shutdown_handler([this](uint8_t reason) {
        if (m_node_shutdown_handler) {
            m_node_shutdown_handler(reason);
        }
    });
}

network::Connection::Sptr& NodeSession::connection_for(Session_lane lane)
{
    return (lane == Session_lane::Primary) ? m_primary_connection : m_secondary_connection;
}

const network::Connection::Sptr& NodeSession::connection_for(Session_lane lane) const
{
    return (lane == Session_lane::Primary) ? m_primary_connection : m_secondary_connection;
}

std::shared_ptr<protocol::Solo>& NodeSession::protocol_for(Session_lane lane)
{
    return (lane == Session_lane::Primary) ? m_primary_protocol : m_secondary_protocol;
}

const std::shared_ptr<protocol::Solo>& NodeSession::protocol_for(Session_lane lane) const
{
    return (lane == Session_lane::Primary) ? m_primary_protocol : m_secondary_protocol;
}

std::atomic<bool>& NodeSession::connected_flag_for(Session_lane lane)
{
    return (lane == Session_lane::Primary) ? m_primary_connected : m_secondary_connected;
}

const std::atomic<bool>& NodeSession::connected_flag_for(Session_lane lane) const
{
    return (lane == Session_lane::Primary) ? m_primary_connected : m_secondary_connected;
}

std::deque<uint8_t>& NodeSession::rx_accumulator_for(Session_lane lane)
{
    return (lane == Session_lane::Primary) ? m_primary_rx_accumulator : m_secondary_rx_accumulator;
}

const char* NodeSession::lane_name(Session_lane lane) const
{
    return (lane == Session_lane::Primary) ? "Primary" : "Secondary";
}

ProtocolLane NodeSession::lane_health_tag(Session_lane lane) const
{
    return (lane == Session_lane::Primary) ? ProtocolLane::STATELESS : ProtocolLane::LEGACY;
}

void NodeSession::handle_lane_event(Session_lane lane, const network::Endpoint& node_endpoint,
                                    network::Result::Code result,
                                    network::Shared_payload&& receive_buffer,
                                    Connection_callback callback)
{
    if (result == network::Result::connection_ok) {
        if (!connection_for(lane)) {
            auto weak_self = std::weak_ptr<NodeSession>(shared_from_this());
            ::asio::post(*m_io_context, [weak_self, lane, node_endpoint, callback]() {
                auto self = weak_self.lock();
                if (!self) {
                    return;
                }

                self->m_logger->info("[NodeSession:{}] {} connection established (deferred)",
                                     self->m_node_label, self->lane_name(lane));
                self->connected_flag_for(lane) = true;

                if (lane == Session_lane::Primary) {
                    self->configure_connected_lane(Session_lane::Primary);
                    auto auth_payload = self->m_primary_protocol->login(
                        [weak_self, callback, node_endpoint](bool login_result) {
                            auto self = weak_self.lock();
                            if (!self) return;

                            if (!login_result) {
                                self->m_logger->error("[NodeSession:{}] Primary authentication failed",
                                                      self->m_node_label);
                                if (callback) callback(false);
                                return;
                            }

                            self->m_logger->info("[NodeSession:{}] Primary authentication initiated",
                                                 self->m_node_label);

                            if (self->m_config.get_enable_sim_link() && !self->m_secondary_connected) {
                                self->connect_secondary(self->secondary_endpoint_for(node_endpoint));
                            }
                        });

                    self->send_auth_payload(Session_lane::Primary, std::move(auth_payload), callback);
                    return;
                }

                self->configure_connected_lane(Session_lane::Secondary);
                auto auth_payload = self->m_secondary_protocol->login([weak_self](bool login_result) {
                    auto self = weak_self.lock();
                    if (!self) return;

                    if (!login_result) {
                        self->m_logger->error("[NodeSession:{}] Secondary authentication failed",
                                              self->m_node_label);
                        return;
                    }

                    self->m_logger->info("[NodeSession:{}] Secondary authentication initiated",
                                         self->m_node_label);
                });

                self->send_auth_payload(Session_lane::Secondary, std::move(auth_payload));
            });
            return;
        }

        m_logger->info("[NodeSession:{}] {} connection established", m_node_label, lane_name(lane));
        connected_flag_for(lane) = true;
        if (lane == Session_lane::Primary) {
            handle_primary_connection_result(result, callback);
        } else {
            handle_secondary_connection_result(result);
        }
        return;
    }

    if (result == network::Result::connection_declined ||
        result == network::Result::connection_aborted ||
        result == network::Result::connection_closed ||
        result == network::Result::connection_error) {
        handle_lane_failure(lane, result, callback);
        return;
    }

    process_lane_data(lane, std::move(receive_buffer));
}

void NodeSession::configure_connected_lane(Session_lane lane)
{
    auto& connection = connection_for(lane);
    auto& protocol = protocol_for(lane);
    if (!connection || !protocol) {
        return;
    }

    const ProtocolLane protocol_lane = connection->get_protocol_lane();
    protocol->set_protocol_lane(protocol_lane);
    m_logger->info("[NodeSession:{}] {} lane: {}",
                  m_node_label,
                  lane_name(lane),
                  (protocol_lane == ProtocolLane::STATELESS ? "STATELESS" : "LEGACY"));

    if (lane == Session_lane::Primary && m_dcm && m_dcm->mining_lane() == ProtocolLane::UNKNOWN) {
        m_dcm->set_mining_lane(protocol_lane);
        m_logger->info("[NodeSession:{}] Mining lane stamped: {} (immutable for session lifetime)",
                      m_node_label,
                      (protocol_lane == ProtocolLane::STATELESS ? "STATELESS" : "LEGACY"));
    }
}

bool NodeSession::send_auth_payload(Session_lane lane, network::Shared_payload auth_payload,
                                    Connection_callback callback)
{
    if (!auth_payload || auth_payload->empty()) {
        return false;
    }

    auto& connection = connection_for(lane);
    if (connection && connection->transmit(auth_payload)) {
        return true;
    }

    m_logger->error("[NodeSession:{}] Failed to queue {} authentication payload",
                   m_node_label, lane_name(lane));
    if (lane == Session_lane::Primary && callback) {
        callback(false);
    }
    return false;
}

void NodeSession::handle_lane_failure(Session_lane lane, network::Result::Code result,
                                      Connection_callback callback)
{
    m_logger->log(lane == Session_lane::Primary ? spdlog::level::err : spdlog::level::warn,
                  "[NodeSession:{}] {} connection failed: {}",
                  m_node_label, lane_name(lane), static_cast<int>(result));
    connected_flag_for(lane) = false;

    if (m_dcm) {
        m_dcm->on_lane_failed(lane_health_tag(lane));
        m_logger->warn("[NodeSession:{}] {} lane ({}) failed → DualConnectionManager updated",
                      m_node_label,
                      lane_name(lane),
                      (lane == Session_lane::Primary ? "STATELESS" : "LEGACY"));
    }

    if (lane == Session_lane::Primary && callback) {
        callback(false);
    }
}

void NodeSession::process_lane_data(Session_lane lane, network::Shared_payload&& receive_buffer)
{
    auto& connection = connection_for(lane);
    auto& protocol = protocol_for(lane);
    auto& accumulator = rx_accumulator_for(lane);
    if (m_stopped || !connection || !protocol || !receive_buffer) {
        return;
    }

    accumulator.insert(accumulator.end(), receive_buffer->begin(), receive_buffer->end());
    const ProtocolLane protocol_lane = connection->get_protocol_lane();

    while (!accumulator.empty()) {
        auto buffer_shared = std::make_shared<std::vector<uint8_t>>(
            accumulator.begin(), accumulator.end());

        size_t bytes_consumed = 0;
        ParseResult parse_result;

        auto packet = extract_packet_from_buffer_with_result(
            buffer_shared, bytes_consumed, 0, protocol_lane, parse_result);

        if (parse_result == ParseResult::NEED_MORE_DATA) {
            break;
        }
        if (parse_result == ParseResult::MALFORMED) {
            m_logger->error("[NodeSession:{}] Malformed packet on {} connection",
                            m_node_label, lane_name(lane));
            accumulator.clear();
            break;
        }

        accumulator.erase(accumulator.begin(), accumulator.begin() + bytes_consumed);
        protocol->process_messages(packet, connection);
    }
}

network::Endpoint NodeSession::secondary_endpoint_for(const network::Endpoint& node_endpoint) const
{
    std::string node_ip;
    node_endpoint.address(node_ip);
    return network::Endpoint{
        network::Transport_protocol::tcp,
        node_ip,
        ProtocolPorts::LEGACY_PORT};
}

void NodeSession::set_epoch_coordinator(std::shared_ptr<protocol::EpochCoordinator> coordinator)
{
    if (!m_session_context) {
        m_logger->error("[NodeSession:{}] set_epoch_coordinator: m_session_context is null - "
                        "coordinator cannot be wired. Check initialization order.", m_node_label);
        return;
    }
    auto session_mgr = m_session_context->get_session_manager();
    if (!session_mgr) {
        m_logger->error("[NodeSession:{}] set_epoch_coordinator: session_manager is null - "
                        "coordinator cannot be wired. Check initialization order.", m_node_label);
        return;
    }
    session_mgr->set_epoch_coordinator(std::move(coordinator));
}

} // namespace nexusminer
