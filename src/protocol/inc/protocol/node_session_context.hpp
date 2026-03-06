#ifndef NEXUSMINER_PROTOCOL_NODE_SESSION_CONTEXT_HPP
#define NEXUSMINER_PROTOCOL_NODE_SESSION_CONTEXT_HPP

#include "protocol/session_manager.hpp"
#include "protocol/protocol_constants.hpp"
#include "protocol_lane.hpp"
#include <memory>
#include <functional>
#include <vector>
#include <cstdint>

namespace nexusminer {
namespace protocol {

/**
 * @brief NodeSessionContext — Thin façade over SessionManager
 *
 * This utility owns all session-domain decisions and provides a stable interface
 * for session management across NodeSession, Solo, and Worker_manager.
 *
 * Responsibilities:
 * - Session ID cache (authoritative source of truth)
 * - Session state machine (disconnected/authenticating/authenticated/active/expired)
 * - Lane-aware packet building (keepalive + session status)
 * - Session constants (keepalive cadence rules, retry caps)
 * - Expiry detection & "invalidate session" actions
 * - Wire parsing helpers for session protocols
 *
 * Key Design Principle:
 * NodeSessionContext is the SOLE authoritative source for session_id.
 * Components should query this context rather than maintaining their own copies.
 */
class NodeSessionContext {
public:
    /**
     * @brief Constructor
     * @param session_manager Shared SessionManager instance
     */
    explicit NodeSessionContext(std::shared_ptr<SessionManager> session_manager);

    /**
     * @brief Get the current session ID (authoritative)
     * @return Session ID (0 if no active session)
     */
    uint32_t get_session_id() const;

    /**
     * @brief Check if session is authenticated
     * @return True if session is in AUTHENTICATED or ACTIVE state
     */
    bool is_authenticated() const;

    /**
     * @brief Check if session is active
     * @return True if session is in AUTHENTICATED or ACTIVE state
     */
    bool is_active() const;

    /**
     * @brief Get current session state
     * @return SessionState enum value
     */
    SessionManager::SessionState get_state() const;

    /**
     * @brief Start a new session after successful authentication
     * @param session_id Session ID from MINER_AUTH_RESULT
     * @param session_key Falcon session key (optional)
     * @param tritium_genesis Tritium genesis hash (optional)
     */
    void start_session(uint32_t session_id,
                      const std::vector<uint8_t>& session_key = {},
                      const std::vector<uint8_t>& tritium_genesis = {});

    /**
     * @brief End current session
     */
    void end_session();

    /**
     * @brief Update session state
     * @param state New session state
     */
    void set_state(SessionManager::SessionState state);

    /**
     * @brief Build SESSION_KEEPALIVE packet
     * @return Shared payload for transmission
     */
    network::Shared_payload build_keepalive_packet() const;

    /**
     * @brief Build SESSION_STATUS packet
     * @param degraded True if workers are in degraded mode
     * @param has_template True if valid mining template is held
     * @param workers_running True if mining workers are active
     * @param secondary_up True if secondary lane is connected
     * @return Shared payload for transmission
     */
    network::Shared_payload build_session_status_packet(
        bool degraded,
        bool has_template,
        bool workers_running,
        bool secondary_up) const;

    /**
     * @brief Start keepalive timer
     */
    void start_keepalive_timer();

    /**
     * @brief Stop keepalive timer
     */
    void stop_keepalive_timer();

    /**
     * @brief Set keepalive interval
     * @param hours Interval in hours (1-168)
     */
    void set_keepalive_interval(uint16_t hours);

    /**
     * @brief Get keepalive interval
     * @return Interval in hours
     */
    uint16_t get_keepalive_interval() const;

    /**
     * @brief Set protocol lane for packet generation
     * @param lane Protocol lane (LEGACY or STATELESS)
     */
    void set_protocol_lane(ProtocolLane lane);

    /**
     * @brief Set connection for keepalive traffic
     * @param connection Network connection
     */
    void set_connection(std::shared_ptr<network::Connection> connection);

    /**
     * @brief Set Tritium genesis hash
     * @param genesis Genesis hash (32 bytes)
     */
    void set_tritium_genesis(const std::vector<uint8_t>& genesis);

    /**
     * @brief Get Tritium genesis hash
     * @return Genesis hash vector
     */
    std::vector<uint8_t> get_tritium_genesis() const;

    /**
     * @brief Get session key
     * @return Session key vector
     */
    std::vector<uint8_t> get_session_key() const;

    /**
     * @brief Get session uptime
     * @return Duration since session start
     */
    std::chrono::seconds get_session_uptime() const;

    /**
     * @brief Get session information
     * @return SessionInfo structure with current session data
     */
    SessionManager::SessionInfo get_session_info() const;

    /**
     * @brief Set session expired handler
     * @param handler Callback invoked when session expires
     */
    void set_session_expired_handler(SessionManager::SessionExpiredHandler handler);

    /**
     * @brief Set prevblock suffix for keepalive packets
     * @param suffix Last 4 bytes of hashPrevBlock
     */
    void set_prevblock_suffix(const std::array<uint8_t, 4>& suffix);

    /**
     * @brief Check if keepalive is due
     * @return True if keepalive should be sent
     */
    bool is_keepalive_due() const;

    /**
     * @brief Record that a keepalive was sent/received
     */
    void record_keepalive();

    /**
     * @brief Get the underlying SessionManager (for advanced use cases)
     * @return Shared pointer to SessionManager
     */
    std::shared_ptr<SessionManager> get_session_manager() const { return m_session_manager; }

    // Session constants accessors (from ProtocolConstants)

    /**
     * @brief Get keepalive safety divisor
     * @return Safety divisor (number of keepalives per session window)
     */
    static constexpr uint32_t get_keepalive_safety_divisor() {
        return ProtocolConstants::KEEPALIVE_SAFETY_DIVISOR;
    }

    /**
     * @brief Get maximum session authentication retries
     * @return Maximum retry count
     */
    static constexpr uint32_t get_max_session_auth_retries() {
        return ProtocolConstants::MAX_SESSION_AUTH_RETRIES;
    }

    /**
     * @brief Get base session retry delay
     * @return Base delay in milliseconds
     */
    static constexpr uint32_t get_base_session_retry_ms() {
        return ProtocolConstants::BASE_SESSION_RETRY_MS;
    }

    /**
     * @brief Get maximum session retry delay
     * @return Maximum delay in milliseconds
     */
    static constexpr uint32_t get_max_session_retry_ms() {
        return ProtocolConstants::MAX_SESSION_RETRY_MS;
    }

    // Wire parsing helpers

    /**
     * @brief Parse SESSION_START packet
     * @param packet_data Packet payload
     * @param out_session_id Parsed session ID (output)
     * @param out_timeout Parsed timeout in seconds (output)
     * @param out_genesis Optional genesis hash (output)
     * @return True if parsing succeeded
     */
    static bool parse_session_start(
        const std::vector<uint8_t>& packet_data,
        uint32_t& out_session_id,
        uint32_t& out_timeout,
        std::vector<uint8_t>& out_genesis);

private:
    std::shared_ptr<SessionManager> m_session_manager;
};

} // namespace protocol
} // namespace nexusminer

#endif // NEXUSMINER_PROTOCOL_NODE_SESSION_CONTEXT_HPP
