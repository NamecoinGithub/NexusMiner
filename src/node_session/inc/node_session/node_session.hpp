#ifndef NEXUSMINER_NODE_SESSION_HPP
#define NEXUSMINER_NODE_SESSION_HPP

#include "network/connection.hpp"
#include "network/socket.hpp"
#include "network/types.hpp"
#include "protocol/protocol.hpp"
#include "protocol/solo.hpp"
#include "protocol/node_session_context.hpp"
#include "protocol_lane.hpp"
#include "block.hpp"
#include "LLC/types/uint1024.h"
#include "spdlog/spdlog.h"

#include <memory>
#include <string>
#include <functional>
#include <atomic>
#include <deque>

namespace asio { class io_context; }

namespace nexusminer {
    class DualConnectionManager;
}

namespace nexusminer {

namespace config { class Config; }
namespace stats { class Collector; }

/**
 * @brief NodeSession — Unified Active Session Outer Wrapper
 *
 * NodeSession is the outer wrapper that owns both port connections (Stateless 9323
 * and Legacy 8323) to a single mining node. It presents a single authenticated
 * identity to Worker_manager regardless of which port is active.
 *
 * Design Principles:
 * - Outer Wrapper, Not Protocol Replacement: Wraps two Solo protocol instances
 *   and one SessionManager. Does not replace any existing auth logic.
 * - OPCODE Firewall Preserved: Each Solo instance retains its ProtocolLane.
 *   Packet lane enforcement is never bypassed.
 * - Session ID is Node-Scoped: One Falcon handshake is performed. The resulting
 *   session_id is authoritative for that node.
 * - Simple Surface Area: Worker_manager calls connect(), transmit(),
 *   session_id(), is_authenticated().
 * - Failover Topology Correct: NodeSession primary = Node A, NodeSession
 *   secondary = Node B (optional).
 */
class NodeSession : public std::enable_shared_from_this<NodeSession>
{
public:
    using Config = config::Config;

    /**
     * @brief Connection result callback
     * @param success True if connection and authentication succeeded
     */
    using Connection_callback = std::function<void(bool success)>;

    /**
     * @brief Template feed handler
     * @param block Block data
     * @param nBits Difficulty bits
     */
    using Template_handler = std::function<void(const ::LLP::CBlock& block, uint32_t nBits)>;

    /**
     * @brief Block accepted handler
     * @param height Block height
     * @param hashPrevBlock Previous block hash
     * @param channel Mining channel
     * @param nonce Nonce value
     */
    using Block_accepted_handler = std::function<void(uint32_t height, uint1024_t hashPrevBlock,
                                                      uint32_t channel, uint64_t nonce)>;

    /**
     * @brief Recovery handler (called when template staleness is detected)
     */
    using Recovery_handler = std::function<void()>;

    /**
     * @brief Session expired handler (called when session mismatch is detected)
     */
    using Session_expired_handler = std::function<void()>;

    /**
     * @brief Session authenticated handler
     * @param session_id Session ID (0 if authentication failed)
     */
    using Session_authenticated_handler = std::function<void(protocol::SessionId session_id)>;

    /**
     * @brief Session start handler
     * @param keepalive_hours Keepalive interval in hours
     */
    using Session_start_handler = std::function<void(uint16_t keepalive_hours)>;

    /**
     * @brief Node shutdown handler: invoked when NODE_SHUTDOWN (0xD0FF) is received from node.
     * Worker_manager registers this to stop workers gracefully.
     * Reconnect backoff is handled automatically by the Solo protocol layer.
     * @param reason Shutdown reason (GRACEFUL=0x01, MAINTENANCE=0x02)
     */
    using Node_shutdown_handler = std::function<void(uint8_t reason)>;

    /**
     * @brief Constructor
     * @param io_context ASIO io_context for async operations
     * @param config Configuration reference
     * @param socket Network socket for connections
     * @param stats_collector Statistics collector
     * @param node_label Human-readable label for this node (e.g., "PRIMARY", "SECONDARY")
     * @param dcm DualConnectionManager for tracking lane health (optional)
     */
    NodeSession(
        std::shared_ptr<asio::io_context> io_context,
        Config& config,
        network::Socket::Sptr socket,
        std::shared_ptr<stats::Collector> stats_collector,
        const std::string& node_label,
        DualConnectionManager* dcm = nullptr);

    /**
     * @brief Connect to the node (both ports)
     * @param node_endpoint Primary endpoint (typically stateless port 9323)
     * @param callback Connection result callback
     * @return True if connection initiation succeeded
     */
    bool connect(const network::Endpoint& node_endpoint, Connection_callback callback);

    /**
     * @brief Transmit data on the active connection
     * @param data Data to transmit
     * @return True if transmission initiated successfully
     */
    bool transmit(network::Shared_payload data);

    /**
     * @brief Get the session ID
     * @return Session ID (0 if not authenticated)
     */
    protocol::SessionId session_id() const;

    /**
     * @brief Check if authenticated
     * @return True if at least one connection is authenticated
     */
    bool is_authenticated() const;

    /**
     * @brief Check if the primary TCP connection is currently established
     * @return True if the primary connection is up (may be authenticated or pending auth)
     */
    bool is_primary_connected() const;

    /**
     * @brief Check if the secondary TCP connection is currently established
     * @return True if the secondary connection is up (may be authenticated or pending auth)
     */
    bool is_secondary_connected() const;

    /**
     * @brief Check if session is active
     * @return True if session is active
     */
    bool is_session_active() const;

    /**
     * @brief Stop the node session and close all connections
     */
    void stop();

    /**
     * @brief Reset the node session for reconnection
     */
    void reset();

    /**
     * @brief Set template feed handler
     * @param handler Template handler callback
     */
    void set_template_handler(Template_handler handler);

    /**
     * @brief Set block accepted handler
     * @param handler Block accepted callback
     */
    void set_block_accepted_handler(Block_accepted_handler handler);

    /**
     * @brief Set recovery initiated handler
     * @param handler Recovery callback
     */
    void set_recovery_initiated_handler(Recovery_handler handler);

    /**
     * @brief Set session expired handler
     * @param handler Session expired callback
     */
    void set_session_expired_handler(Session_expired_handler handler);

    /**
     * @brief Set session authenticated handler
     * @param handler Session authenticated callback
     */
    void set_session_authenticated_handler(Session_authenticated_handler handler);

    /**
     * @brief Set session start handler
     * @param handler Session start callback
     */
    void set_session_start_handler(Session_start_handler handler);

    /**
     * @brief Set node shutdown handler
     * @param handler Node shutdown callback
     */
    void set_node_shutdown_handler(Node_shutdown_handler handler);

    /**
     * @brief Set Falcon miner keys
     * @param pubkey Public key
     * @param privkey Private key
     */
    void set_miner_keys(const std::vector<uint8_t>& pubkey, const std::vector<uint8_t>& privkey);

    /**
     * @brief Set mining reward address
     * @param address NXS address for mining rewards
     */
    void set_reward_address(const std::string& address);

    /**
     * @brief Set Tritium genesis hash
     * @param genesis Genesis hash (32 bytes)
     */
    void set_tritium_genesis(const std::vector<uint8_t>& genesis);

    /**
     * @brief Set keepalive interval
     * @param hours Interval in hours
     */
    void set_keepalive_interval(uint16_t hours);

    /**
     * @brief Get the primary protocol instance (for direct access if needed)
     * @return Shared pointer to primary Solo protocol
     */
    std::shared_ptr<protocol::Solo> get_primary_protocol() const { return m_primary_protocol; }

    /**
     * @brief Get the protocol instance matching the connection transmit() would use.
     *
     * Mirrors transmit()'s primary→secondary fallback logic — including the
     * m_primary_connection / m_secondary_connection presence checks — so that
     * callers can build payloads with the correct lane framing.
     *
     * @return Protocol instance matching the active connection, or nullptr if none available
     */
    std::shared_ptr<protocol::Solo> get_active_protocol() const;

    /**
     * @brief Get the primary TCP connection (for timer wiring)
     * @return Shared pointer to primary network connection (may be null)
     */
    std::shared_ptr<network::Connection> get_primary_connection() const { return m_primary_connection; }

    /**
     * @brief Get the secondary protocol instance (for direct access if needed)
     * @return Shared pointer to secondary Solo protocol (may be null)
     */
    std::shared_ptr<protocol::Solo> get_secondary_protocol() const { return m_secondary_protocol; }

    /**
     * @brief Request fresh mining template
     * @param reason The semantic reason for the request (controls dedup bypass policy)
     * @return Payload to transmit (null if not authenticated)
     */
    network::Shared_payload request_work(protocol::GetBlockReason reason = protocol::GetBlockReason::INITIAL_REQUEST);

    /**
     * @brief Submit a solved block
     * @param block_data Block data
     * @param nonce Nonce value
     * @return Payload to transmit (null if not authenticated)
     */
    network::Shared_payload submit_block(const std::vector<uint8_t>& block_data, uint64_t nonce);

    /**
     * @brief Send GET_ROUND request
     * @return Payload to transmit
     */
    network::Shared_payload send_get_round();

    /**
     * @brief Send session keepalive
     * @return Payload to transmit
     */
    network::Shared_payload send_session_keepalive();

    /**
     * @brief Perform in-band re-authentication on the active connection.
     *
     * Selects the protocol+connection pairing via select_active_pair(), calls
     * login() on that protocol, and transmits the resulting auth payload on the
     * matching connection.  This avoids the lane mismatch that occurs when
     * callers use get_primary_protocol()->login() + transmit() separately,
     * since transmit() may fall back to the secondary connection.
     *
     * IMPORTANT: Solo::login() may return an empty payload if PacketBuilder::build()
     * fails without invoking the callback.  When this happens login_on_active_connection()
     * invokes login_callback(false) itself so callers are always notified.
     *
     * @param login_callback  Invoked with true when auth payload is queued, false on error
     * @return True if the auth payload was generated and transmitted successfully
     */
    bool login_on_active_connection(std::function<void(bool)> login_callback);

    /**
     * @brief Wire the shared EpochCoordinator to the session manager.
     * Called by Worker_manager after construction, before any connections are made.
     * @param coordinator Shared EpochCoordinator instance
     */
    void set_epoch_coordinator(std::shared_ptr<protocol::EpochCoordinator> coordinator);

private:
    enum class Session_lane { Primary, Secondary };

    /**
     * @brief Select the active connection+protocol pair using the same logic as transmit().
     *
     * Returns {primary_connection, primary_protocol} if the primary lane is up, else
     * {secondary_connection, secondary_protocol} if the secondary lane is up, else
     * {nullptr, nullptr}.  All three guards (connection, protocol, connected flag) are
     * checked atomically in one place so that transmit(), get_active_protocol(), and
     * login_on_active_connection() can never diverge.
     *
     * @return Pair of (connection, protocol); both are nullptr when no lane is active.
     */
    std::pair<network::Connection::Sptr, std::shared_ptr<protocol::Solo>> select_active_pair() const;

    uint8_t mining_channel() const;
    std::shared_ptr<protocol::Solo> create_protocol(Session_lane lane);
    void apply_protocol_configuration(const std::shared_ptr<protocol::Solo>& protocol, Session_lane lane);
    void wire_protocol_handlers(const std::shared_ptr<protocol::Solo>& protocol, Session_lane lane);
    void wire_template_handler(const std::shared_ptr<protocol::Solo>& protocol);
    void wire_block_accepted_handler(const std::shared_ptr<protocol::Solo>& protocol);
    void wire_recovery_handler(const std::shared_ptr<protocol::Solo>& protocol);
    void wire_session_expired_handler(const std::shared_ptr<protocol::Solo>& protocol);
    void wire_session_authenticated_handler(const std::shared_ptr<protocol::Solo>& protocol, Session_lane lane);
    void wire_session_start_handler(const std::shared_ptr<protocol::Solo>& protocol);
    void wire_node_shutdown_handler(const std::shared_ptr<protocol::Solo>& protocol);
    network::Connection::Sptr& connection_for(Session_lane lane);
    const network::Connection::Sptr& connection_for(Session_lane lane) const;
    std::shared_ptr<protocol::Solo>& protocol_for(Session_lane lane);
    const std::shared_ptr<protocol::Solo>& protocol_for(Session_lane lane) const;
    std::atomic<bool>& connected_flag_for(Session_lane lane);
    const std::atomic<bool>& connected_flag_for(Session_lane lane) const;
    std::deque<uint8_t>& rx_accumulator_for(Session_lane lane);
    const char* lane_name(Session_lane lane) const;
    ProtocolLane lane_health_tag(Session_lane lane) const;
    void handle_lane_event(Session_lane lane, const network::Endpoint& node_endpoint,
                           network::Result::Code result, network::Shared_payload&& receive_buffer,
                           Connection_callback callback = {});
    void configure_connected_lane(Session_lane lane);
    bool send_auth_payload(Session_lane lane, network::Shared_payload auth_payload,
                           Connection_callback callback = {});
    void handle_lane_failure(Session_lane lane, network::Result::Code result,
                             Connection_callback callback = {});
    void process_lane_data(Session_lane lane, network::Shared_payload&& receive_buffer);
    network::Endpoint secondary_endpoint_for(const network::Endpoint& node_endpoint) const;

    /**
     * @brief Initialize primary connection (stateless port 9323)
     * @param node_endpoint Node endpoint
     * @param callback Connection callback
     */
    void connect_primary(const network::Endpoint& node_endpoint, Connection_callback callback);

    /**
     * @brief Initialize secondary connection (legacy port 8323)
     * @param node_endpoint Node endpoint (port will be adjusted to 8323)
     */
    void connect_secondary(const network::Endpoint& node_endpoint);

    /**
     * @brief Process data received on primary connection
     * @param receive_buffer Received data
     */
    void process_primary_data(network::Shared_payload&& receive_buffer);

    /**
     * @brief Process data received on secondary connection
     * @param receive_buffer Received data
     */
    void process_secondary_data(network::Shared_payload&& receive_buffer);

    /**
     * @brief Handle primary connection result
     * @param result Connection result
     * @param callback User callback
     */
    void handle_primary_connection_result(network::Result::Code result, Connection_callback callback);

    /**
     * @brief Handle secondary connection result
     * @param result Connection result
     */
    void handle_secondary_connection_result(network::Result::Code result);

    // Core components
    std::shared_ptr<asio::io_context> m_io_context;
    Config& m_config;
    network::Socket::Sptr m_socket;
    std::shared_ptr<stats::Collector> m_stats_collector;
    std::shared_ptr<spdlog::logger> m_logger;
    std::string m_node_label;

    // Connections
    network::Connection::Sptr m_primary_connection;    // Stateless port (9323)
    network::Connection::Sptr m_secondary_connection;  // Legacy port (8323)

    // Protocol instances
    std::shared_ptr<protocol::Solo> m_primary_protocol;
    std::shared_ptr<protocol::Solo> m_secondary_protocol;

    // Session management (shared across both ports) - AUTHORITATIVE source for session state
    std::shared_ptr<protocol::NodeSessionContext> m_session_context;

    // Receive accumulators for TCP stream reassembly
    std::deque<uint8_t> m_primary_rx_accumulator;
    std::deque<uint8_t> m_secondary_rx_accumulator;

    // Handlers
    Template_handler m_template_handler;
    Block_accepted_handler m_block_accepted_handler;
    Recovery_handler m_recovery_handler;
    Session_expired_handler m_session_expired_handler;
    Session_authenticated_handler m_session_authenticated_handler;
    Session_start_handler m_session_start_handler;
    Node_shutdown_handler m_node_shutdown_handler;

    // Configuration
    std::vector<uint8_t> m_miner_pubkey;
    std::vector<uint8_t> m_miner_privkey;
    std::string m_reward_address;
    std::vector<uint8_t> m_tritium_genesis;
    uint16_t m_keepalive_interval_hours{24};

    // State flags
    std::atomic<bool> m_primary_connected{false};
    std::atomic<bool> m_secondary_connected{false};
    std::atomic<bool> m_stopped{false};

    // Lane health tracking
    DualConnectionManager* m_dcm{nullptr};
};

} // namespace nexusminer

#endif // NEXUSMINER_NODE_SESSION_HPP
