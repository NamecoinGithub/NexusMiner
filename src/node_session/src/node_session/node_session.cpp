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
    uint8_t channel = (m_config.get_mining_mode() == config::Mining_mode::PRIME) ? 1U : 2U;
    m_primary_protocol = std::make_shared<protocol::Solo>(channel, m_stats_collector, m_session_context);

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

        if (result == network::Result::connection_ok) {
            if (!self->m_primary_connection) {
                // Defer to io_context to avoid synchronous callback issues
                ::asio::post(*self->m_io_context, [weak_self, callback, node_endpoint]() {
                    auto self = weak_self.lock();
                    if (!self) return;

                    self->m_logger->info("[NodeSession:{}] Primary connection established (deferred)",
                                        self->m_node_label);
                    self->m_primary_connected = true;

                    // Determine protocol lane from connection
                    if (self->m_primary_connection) {
                        ProtocolLane lane = self->m_primary_connection->get_protocol_lane();
                        self->m_primary_protocol->set_protocol_lane(lane);
                        self->m_logger->info("[NodeSession:{}] Primary lane: {}",
                                           self->m_node_label,
                                           (lane == ProtocolLane::STATELESS ? "STATELESS" : "LEGACY"));

                        // Stamp the immutable mining lane on first connection only
                        if (self->m_dcm && self->m_dcm->mining_lane() == ProtocolLane::UNKNOWN) {
                            self->m_dcm->set_mining_lane(lane);
                            self->m_logger->info("[NodeSession:{}] Mining lane stamped: {} (immutable for session lifetime)",
                                               self->m_node_label,
                                               (lane == ProtocolLane::STATELESS ? "STATELESS" : "LEGACY"));
                        }
                    }

                    // Start authentication
                    auto auth_payload = self->m_primary_protocol->login([weak_self, callback, node_endpoint](bool login_result) {
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

                        // After primary connection is established, initiate secondary connection
                        if (self->m_config.get_enable_sim_link() && !self->m_secondary_connected) {
                            // Create secondary endpoint with legacy port (8323)
                            std::string node_ip;
                            node_endpoint.address(node_ip);
                            network::Endpoint secondary_endpoint{
                                network::Transport_protocol::tcp,
                                node_ip,
                                ProtocolPorts::LEGACY_PORT};
                            self->connect_secondary(secondary_endpoint);
                        }
                    });

                    if (auth_payload && !auth_payload->empty()) {
                        self->m_primary_connection->transmit(auth_payload);
                    }
                });
                return;
            }

            self->m_logger->info("[NodeSession:{}] Primary connection established", self->m_node_label);
            self->m_primary_connected = true;

            // Handle the connection result
            self->handle_primary_connection_result(result, callback);

        } else if (result == network::Result::connection_declined ||
                   result == network::Result::connection_aborted ||
                   result == network::Result::connection_closed ||
                   result == network::Result::connection_error) {

            self->m_logger->error("[NodeSession:{}] Primary connection failed: {}",
                                 self->m_node_label, static_cast<int>(result));
            self->m_primary_connected = false;

            // Update DualConnectionManager: primary (stateless) lane has failed
            if (self->m_dcm) {
                self->m_dcm->on_lane_failed(ProtocolLane::STATELESS);
                self->m_logger->warn("[NodeSession:{}] Primary lane (STATELESS) failed → DualConnectionManager updated",
                                    self->m_node_label);
            }

            if (callback) {
                callback(false);
            }

        } else {
            // Data received - process it
            self->process_primary_data(std::move(receive_buffer));
        }
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
    uint8_t channel = (m_config.get_mining_mode() == config::Mining_mode::PRIME) ? 1U : 2U;
    m_secondary_protocol = std::make_shared<protocol::Solo>(channel, m_stats_collector, m_session_context);

    // Copy configuration from primary
    if (!m_miner_pubkey.empty() && !m_miner_privkey.empty()) {
        m_secondary_protocol->set_miner_keys(m_miner_pubkey, m_miner_privkey);
    }
    if (!m_reward_address.empty()) {
        m_secondary_protocol->set_reward_address(m_reward_address);
    }
    if (!m_tritium_genesis.empty()) {
        m_secondary_protocol->set_tritium_genesis(m_tritium_genesis);
    }
    m_secondary_protocol->set_keepalive_interval(m_keepalive_interval_hours);
    m_secondary_protocol->enable_chacha20_wrapping(true);
    m_secondary_protocol->enable_disposable_falcon(true);

    // Register handlers (reuse the same handlers as primary)
    m_secondary_protocol->set_block_handler([this](const ::LLP::CBlock& block, uint32_t nBits) {
        if (m_template_handler) {
            m_template_handler(block, nBits);
        }
    });

    m_secondary_protocol->set_block_accepted_handler([this](uint32_t height, uint1024_t hash_prev,
                                                             uint32_t channel, uint64_t nonce) {
        if (m_block_accepted_handler) {
            m_block_accepted_handler(height, hash_prev, channel, nonce);
        }
    });

    // Set up authentication handler for secondary lane.
    // Wire the full m_session_authenticated_handler callback (set by Worker_manager)
    // so that in-band re-auth via login_on_active_connection() on the secondary
    // protocol still triggers timers, recovery transitions, and template requests.
    // Without this, secondary re-auth only updated DualConnectionManager — the
    // Worker_manager never knew auth succeeded and the miner would stall.
    m_secondary_protocol->set_session_authenticated_handler([this](uint32_t sid) {
        // Update DualConnectionManager: secondary (legacy) lane is now authenticated and alive
        if (m_dcm && sid != 0) {
            m_dcm->set_legacy_alive(true);
            m_logger->info("[NodeSession:{}] Secondary lane (LEGACY) authenticated → DualConnectionManager updated",
                          m_node_label);
        }

        if (m_session_authenticated_handler) {
            m_session_authenticated_handler(sid);
        }
    });

    // Wire session expired handler to secondary protocol (same as primary)
    // so SESSION_EXPIRED on the secondary lane triggers Worker_manager recovery.
    m_secondary_protocol->set_session_expired_handler([this]() {
        if (m_session_expired_handler) {
            m_session_expired_handler();
        }
    });

    auto weak_self = std::weak_ptr<NodeSession>(shared_from_this());

    auto connection_callback = [weak_self, node_endpoint](auto result, auto receive_buffer) {
        auto self = weak_self.lock();
        if (!self) return;

        if (result == network::Result::connection_ok) {
            if (!self->m_secondary_connection) {
                // Defer to io_context
                ::asio::post(*self->m_io_context, [weak_self, node_endpoint]() {
                    auto self = weak_self.lock();
                    if (!self) return;

                    self->m_logger->info("[NodeSession:{}] Secondary connection established (deferred)",
                                        self->m_node_label);
                    self->m_secondary_connected = true;

                    // Determine protocol lane
                    if (self->m_secondary_connection) {
                        ProtocolLane lane = self->m_secondary_connection->get_protocol_lane();
                        self->m_secondary_protocol->set_protocol_lane(lane);
                        self->m_logger->info("[NodeSession:{}] Secondary lane: {}",
                                           self->m_node_label,
                                           (lane == ProtocolLane::STATELESS ? "STATELESS" : "LEGACY"));
                    }

                    // Start authentication for secondary
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

                    if (auth_payload && !auth_payload->empty()) {
                        self->m_secondary_connection->transmit(auth_payload);
                    }
                });
                return;
            }

            self->m_logger->info("[NodeSession:{}] Secondary connection established", self->m_node_label);
            self->m_secondary_connected = true;
            self->handle_secondary_connection_result(result);

        } else if (result == network::Result::connection_declined ||
                   result == network::Result::connection_aborted ||
                   result == network::Result::connection_closed ||
                   result == network::Result::connection_error) {

            self->m_logger->warn("[NodeSession:{}] Secondary connection failed: {}",
                                self->m_node_label, static_cast<int>(result));
            self->m_secondary_connected = false;

            // Update DualConnectionManager: secondary (legacy) lane has failed
            if (self->m_dcm) {
                self->m_dcm->on_lane_failed(ProtocolLane::LEGACY);
                self->m_logger->warn("[NodeSession:{}] Secondary lane (LEGACY) failed → DualConnectionManager updated",
                                    self->m_node_label);
            }

        } else {
            // Data received - process it
            self->process_secondary_data(std::move(receive_buffer));
        }
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
    if (m_stopped || !m_primary_connection) {
        return;
    }

    // Append to accumulator
    m_primary_rx_accumulator.insert(m_primary_rx_accumulator.end(),
                                    receive_buffer->begin(),
                                    receive_buffer->end());

    // Get protocol lane
    ProtocolLane lane = m_primary_connection->get_protocol_lane();

    // Parse and process packets
    while (!m_primary_rx_accumulator.empty()) {
        // Create a shared buffer view for packet extraction
        auto buffer_shared = std::make_shared<std::vector<uint8_t>>(
            m_primary_rx_accumulator.begin(),
            m_primary_rx_accumulator.end());

        size_t bytes_consumed = 0;
        ParseResult parse_result;

        auto packet = extract_packet_from_buffer_with_result(
            buffer_shared, bytes_consumed, 0, lane, parse_result);

        if (parse_result == ParseResult::NEED_MORE_DATA) {
            break;
        } else if (parse_result == ParseResult::MALFORMED) {
            m_logger->error("[NodeSession:{}] Malformed packet on primary connection",
                          m_node_label);
            m_primary_rx_accumulator.clear();
            break;
        } else {
            // Remove consumed bytes
            m_primary_rx_accumulator.erase(
                m_primary_rx_accumulator.begin(),
                m_primary_rx_accumulator.begin() + bytes_consumed);

            // Process packet
            m_primary_protocol->process_messages(packet, m_primary_connection);
        }
    }
}

void NodeSession::process_secondary_data(network::Shared_payload&& receive_buffer)
{
    if (m_stopped || !m_secondary_connection || !m_secondary_protocol) {
        return;
    }

    // Append to accumulator
    m_secondary_rx_accumulator.insert(m_secondary_rx_accumulator.end(),
                                      receive_buffer->begin(),
                                      receive_buffer->end());

    // Get protocol lane
    ProtocolLane lane = m_secondary_connection->get_protocol_lane();

    // Parse and process packets
    while (!m_secondary_rx_accumulator.empty()) {
        auto buffer_shared = std::make_shared<std::vector<uint8_t>>(
            m_secondary_rx_accumulator.begin(),
            m_secondary_rx_accumulator.end());

        size_t bytes_consumed = 0;
        ParseResult parse_result;

        auto packet = extract_packet_from_buffer_with_result(
            buffer_shared, bytes_consumed, 0, lane, parse_result);

        if (parse_result == ParseResult::NEED_MORE_DATA) {
            break;
        } else if (parse_result == ParseResult::MALFORMED) {
            m_logger->error("[NodeSession:{}] Malformed packet on secondary connection",
                          m_node_label);
            m_secondary_rx_accumulator.clear();
            break;
        } else {
            // Remove consumed bytes
            m_secondary_rx_accumulator.erase(
                m_secondary_rx_accumulator.begin(),
                m_secondary_rx_accumulator.begin() + bytes_consumed);

            // Process packet
            m_secondary_protocol->process_messages(packet, m_secondary_connection);
        }
    }
}

void NodeSession::handle_primary_connection_result(network::Result::Code result, Connection_callback callback)
{
    if (result == network::Result::connection_ok) {
        // Set protocol lane
        if (m_primary_connection) {
            ProtocolLane lane = m_primary_connection->get_protocol_lane();
            m_primary_protocol->set_protocol_lane(lane);
            m_logger->info("[NodeSession:{}] Primary lane: {}",
                          m_node_label,
                          (lane == ProtocolLane::STATELESS ? "STATELESS" : "LEGACY"));

            // Stamp the immutable mining lane on first connection only
            if (m_dcm && m_dcm->mining_lane() == ProtocolLane::UNKNOWN) {
                m_dcm->set_mining_lane(lane);
                m_logger->info("[NodeSession:{}] Mining lane stamped: {} (immutable for session lifetime)",
                              m_node_label,
                              (lane == ProtocolLane::STATELESS ? "STATELESS" : "LEGACY"));
            }
        }

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

        if (auth_payload && !auth_payload->empty()) {
            m_primary_connection->transmit(auth_payload);
        }
    }
}

void NodeSession::handle_secondary_connection_result(network::Result::Code result)
{
    if (result == network::Result::connection_ok && m_secondary_connection) {
        // Set protocol lane
        ProtocolLane lane = m_secondary_connection->get_protocol_lane();
        m_secondary_protocol->set_protocol_lane(lane);
        m_logger->info("[NodeSession:{}] Secondary lane: {}",
                      m_node_label,
                      (lane == ProtocolLane::STATELESS ? "STATELESS" : "LEGACY"));

        // Start authentication
        auto auth_payload = m_secondary_protocol->login([this](bool login_result) {
            if (!login_result) {
                m_logger->error("[NodeSession:{}] Secondary authentication failed", m_node_label);
                return;
            }

            m_logger->info("[NodeSession:{}] Secondary authentication succeeded", m_node_label);
        });

        if (auth_payload && !auth_payload->empty()) {
            m_secondary_connection->transmit(auth_payload);
        }
    }
}

bool NodeSession::transmit(network::Shared_payload data)
{
    if (m_stopped || !data || data->empty()) {
        return false;
    }

    // Try primary connection first
    if (m_primary_connection && m_primary_connected) {
        m_primary_connection->transmit(data);
        return true;
    }

    // Fallback to secondary
    if (m_secondary_connection && m_secondary_connected) {
        m_secondary_connection->transmit(data);
        return true;
    }

    m_logger->warn("[NodeSession:{}] No active connection to transmit on", m_node_label);
    return false;
}

std::shared_ptr<protocol::Solo> NodeSession::get_active_protocol() const
{
    // Mirror transmit()'s exact fallback logic, including connection-object
    // presence checks, so the returned protocol always matches the connection
    // that transmit() would actually select.
    if (m_primary_connection && m_primary_protocol && m_primary_connected) {
        return m_primary_protocol;
    }
    if (m_secondary_connection && m_secondary_protocol && m_secondary_connected) {
        return m_secondary_protocol;
    }
    return nullptr;
}

uint32_t NodeSession::session_id() const
{
    // Query the authoritative session context
    return m_session_context ? m_session_context->get_session_id() : 0;
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

    // Register with both protocols
    if (m_primary_protocol) {
        m_primary_protocol->set_block_handler([this](const ::LLP::CBlock& block, uint32_t nBits) {
            if (m_template_handler) {
                m_template_handler(block, nBits);
            }
        });
    }
}

void NodeSession::set_block_accepted_handler(Block_accepted_handler handler)
{
    m_block_accepted_handler = std::move(handler);

    // Register with both protocols
    if (m_primary_protocol) {
        m_primary_protocol->set_block_accepted_handler(
            [this](uint32_t height, uint1024_t hash_prev, uint32_t channel, uint64_t nonce) {
                if (m_block_accepted_handler) {
                    m_block_accepted_handler(height, hash_prev, channel, nonce);
                }
            });
    }
}

void NodeSession::set_recovery_initiated_handler(Recovery_handler handler)
{
    m_recovery_handler = std::move(handler);

    if (m_primary_protocol) {
        m_primary_protocol->set_recovery_initiated_handler([this]() {
            if (m_recovery_handler) {
                m_recovery_handler();
            }
        });
    }
}

void NodeSession::set_session_expired_handler(Session_expired_handler handler)
{
    m_session_expired_handler = std::move(handler);

    if (m_primary_protocol) {
        m_primary_protocol->set_session_expired_handler([this]() {
            if (m_session_expired_handler) {
                m_session_expired_handler();
            }
        });
    }

    // Also wire to secondary protocol if it exists already.
    // This ensures SESSION_EXPIRED on the secondary lane also triggers the
    // Worker_manager's recovery path (in-band re-auth / reconnect).
    if (m_secondary_protocol) {
        m_secondary_protocol->set_session_expired_handler([this]() {
            if (m_session_expired_handler) {
                m_session_expired_handler();
            }
        });
    }
}

void NodeSession::set_session_authenticated_handler(Session_authenticated_handler handler)
{
    m_session_authenticated_handler = std::move(handler);

    if (m_primary_protocol) {
        m_primary_protocol->set_session_authenticated_handler([this](uint32_t sid) {
            // Note: Session state is managed by SessionManager inside Solo protocol
            // The session_id can be queried via m_session_context->get_session_id()
            // No need to maintain a duplicate here

            // Update DualConnectionManager: primary (stateless) lane is now authenticated and alive
            if (m_dcm && sid != 0) {
                m_dcm->set_stateless_alive(true);
                m_logger->info("[NodeSession:{}] Primary lane (STATELESS) authenticated → DualConnectionManager updated",
                              m_node_label);
            }

            if (m_session_authenticated_handler) {
                m_session_authenticated_handler(sid);
            }
        });
    }

    // Also wire to secondary protocol if it exists already.
    // This ensures in-band re-auth via login_on_active_connection() on the
    // secondary lane still triggers the full Worker_manager callback chain
    // (timers, recovery transitions, template requests).
    if (m_secondary_protocol) {
        m_secondary_protocol->set_session_authenticated_handler([this](uint32_t sid) {
            if (m_dcm && sid != 0) {
                m_dcm->set_legacy_alive(true);
                m_logger->info("[NodeSession:{}] Secondary lane (LEGACY) authenticated → DualConnectionManager updated",
                              m_node_label);
            }

            if (m_session_authenticated_handler) {
                m_session_authenticated_handler(sid);
            }
        });
    }
}

void NodeSession::set_session_start_handler(Session_start_handler handler)
{
    m_session_start_handler = std::move(handler);

    if (m_primary_protocol) {
        m_primary_protocol->set_session_start_handler([this](uint16_t hours) {
            if (m_session_start_handler) {
                m_session_start_handler(hours);
            }
        });
    }
}

void NodeSession::set_node_shutdown_handler(Node_shutdown_handler handler)
{
    m_node_shutdown_handler = std::move(handler);

    if (m_primary_protocol) {
        m_primary_protocol->set_node_shutdown_handler([this](uint8_t reason) {
            if (m_node_shutdown_handler) {
                m_node_shutdown_handler(reason);
            }
        });
    }
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
    if (m_primary_protocol && m_primary_connected) {
        return m_primary_protocol->get_work(reason);
    }
    if (m_secondary_protocol && m_secondary_connected) {
        return m_secondary_protocol->get_work(reason);
    }
    return nullptr;
}

network::Shared_payload NodeSession::submit_block(const std::vector<uint8_t>& block_data, uint64_t nonce)
{
    // Try primary first
    if (m_primary_protocol && m_primary_connected && m_primary_protocol->is_authenticated()) {
        return m_primary_protocol->submit_block(block_data, nonce);
    }

    // Fallback to secondary
    if (m_secondary_protocol && m_secondary_connected && m_secondary_protocol->is_authenticated()) {
        return m_secondary_protocol->submit_block(block_data, nonce);
    }

    return nullptr;
}

network::Shared_payload NodeSession::send_get_round()
{
    if (m_primary_protocol && m_primary_connected) {
        return m_primary_protocol->send_get_round();
    }
    if (m_secondary_protocol && m_secondary_connected) {
        return m_secondary_protocol->send_get_round();
    }
    return nullptr;
}

network::Shared_payload NodeSession::send_session_keepalive()
{
    if (m_primary_protocol && m_primary_connected) {
        return m_primary_protocol->send_session_keepalive();
    }
    if (m_secondary_protocol && m_secondary_connected) {
        return m_secondary_protocol->send_session_keepalive();
    }
    return nullptr;
}

bool NodeSession::login_on_active_connection(std::function<void(bool)> login_callback)
{
    if (m_stopped) {
        m_logger->warn("[NodeSession:{}] Cannot login - session is stopped", m_node_label);
        return false;
    }

    // Select the protocol+connection pairing that transmit() would use.
    // This guarantees the auth payload is framed for the correct lane.
    // Note: Solo::login() always invokes the callback synchronously before
    // returning (true on success, false on error), so the callback is never lost.
    if (m_primary_connection && m_primary_protocol && m_primary_connected) {
        auto auth_payload = m_primary_protocol->login(login_callback);
        if (auth_payload && !auth_payload->empty()) {
            m_primary_connection->transmit(auth_payload);
            return true;
        }
        return false;
    }

    if (m_secondary_connection && m_secondary_protocol && m_secondary_connected) {
        auto auth_payload = m_secondary_protocol->login(login_callback);
        if (auth_payload && !auth_payload->empty()) {
            m_secondary_connection->transmit(auth_payload);
            return true;
        }
        return false;
    }

    m_logger->warn("[NodeSession:{}] No active connection for login", m_node_label);
    return false;
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
