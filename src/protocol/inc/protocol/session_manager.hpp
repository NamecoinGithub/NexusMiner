#ifndef NEXUSMINER_PROTOCOL_SESSION_MANAGER_HPP
#define NEXUSMINER_PROTOCOL_SESSION_MANAGER_HPP

#include <vector>
#include <cstdint>
#include <string>
#include <memory>
#include <chrono>
#include <atomic>
#include "asio/io_context.hpp"
#include "asio/steady_timer.hpp"
#include "network/types.hpp"
#include "spdlog/spdlog.h"

namespace nexusminer {
namespace network { class Connection; }
namespace protocol {

/**
 * @brief Session Manager for Falcon-based authentication and cache management
 * 
 * This class manages the miner's session with the LLL-TAO Node, including:
 * - Session ID tracking
 * - Falcon Session Key storage
 * - Keep-alive ping scheduling
 * - Re-onboarding on cache expiry
 * 
 * The session is established during the Falcon Handshake and maintained through
 * periodic SESSION_KEEPALIVE pings to prevent cache eviction.
 */
class SessionManager : public std::enable_shared_from_this<SessionManager> {
public:
    
    /**
     * @brief Session state enumeration
     */
    enum class SessionState {
        DISCONNECTED,      // No connection to node
        AUTHENTICATING,    // Handshake in progress
        AUTHENTICATED,     // Session established
        ACTIVE,           // Session active with keepalive
        EXPIRED           // Session expired, needs re-onboarding
    };
    
    /**
     * @brief Session information structure
     */
    struct SessionInfo {
        uint32_t session_id;
        std::vector<uint8_t> session_key;  // Falcon session key from node
        std::vector<uint8_t> tritium_genesis;  // Tritium genesis hash (32 bytes)
        SessionState state;
        std::chrono::system_clock::time_point last_keepalive;
        std::chrono::system_clock::time_point session_start;
        uint32_t keepalive_count;
    };
    
    /**
     * @brief Constructor
     * @param keepalive_interval_hours Interval between keepalive pings (default: 24 hours)
     * @param io_context io_context for keepalive timers (nullptr disables timer scheduling)
     */
    explicit SessionManager(uint16_t keepalive_interval_hours = 24,
                            std::shared_ptr<asio::io_context> io_context = nullptr);
    
    /**
     * @brief Destructor
     */
    ~SessionManager();
    
    /**
     * @brief Start a new session (after successful handshake)
     * 
     * @param session_id Session ID from MINER_AUTH_RESULT
     * @param session_key Falcon session key from SESSION_START (optional)
     * @param tritium_genesis Tritium genesis hash for reward binding
     */
    void start_session(uint32_t session_id,
                      const std::vector<uint8_t>& session_key = {},
                      const std::vector<uint8_t>& tritium_genesis = {});
    
    /**
     * @brief End current session
     */
    void end_session();

    /**
     * @brief Set the active connection for keepalive traffic
     */
    void set_connection(std::shared_ptr<network::Connection> connection);

    /**
     * @brief Start keepalive timer (early + regular interval)
     *
     * Uses aggressive 10s/30s cadence regardless of keepalive_interval_hours.
     * Requires SessionManager to be managed by std::shared_ptr.
     */
    void start_keepalive_timer();

    /**
     * @brief Stop keepalive timer
     */
    void stop_keepalive_timer();

    /**
     * @brief Build SESSION_KEEPALIVE packet bytes
     */
    network::Shared_payload build_keepalive_packet() const;
    
    /**
     * @brief Check if keepalive ping is due
     * 
     * @return true if it's time to send SESSION_KEEPALIVE
     */
    bool is_keepalive_due() const;
    
    /**
     * @brief Record keepalive ping sent
     */
    void record_keepalive();
    
    /**
     * @brief Update session state
     * 
     * @param state New session state
     */
    void set_state(SessionState state);
    
    /**
     * @brief Get current session state
     * 
     * @return Current SessionState
     */
    SessionState get_state() const { return m_session.state; }
    
    /**
     * @brief Check if session is active
     * 
     * @return true if session is in AUTHENTICATED or ACTIVE state
     */
    bool is_active() const;
    
    /**
     * @brief Get session ID
     * 
     * @return Current session ID (0 if no session)
     */
    uint32_t get_session_id() const { return m_session.session_id; }
    
    /**
     * @brief Get session key
     * 
     * @return Reference to session key
     */
    const std::vector<uint8_t>& get_session_key() const { return m_session.session_key; }
    
    /**
     * @brief Get Tritium genesis hash
     * 
     * @return Reference to genesis hash
     */
    const std::vector<uint8_t>& get_tritium_genesis() const { return m_session.tritium_genesis; }
    
    /**
     * @brief Set Tritium genesis hash
     * 
     * @param genesis Genesis hash (32 bytes)
     */
    void set_tritium_genesis(const std::vector<uint8_t>& genesis);
    
    /**
     * @brief Get session uptime
     * 
     * @return Duration since session start
     */
    std::chrono::seconds get_session_uptime() const;
    
    /**
     * @brief Get time until next keepalive
     * 
     * @return Duration until next keepalive is due
     */
    std::chrono::seconds get_time_until_keepalive() const;
    
    /**
     * @brief Get session statistics
     * 
     * @return SessionInfo structure with current session data
     */
    SessionInfo get_session_info() const { return m_session; }
    
    /**
     * @brief Set keepalive interval
     * 
     * @param hours Interval in hours (1-168)
     */
    void set_keepalive_interval(uint16_t hours);
    
    /**
     * @brief Get keepalive interval
     * 
     * @return Interval in hours
     */
    uint16_t get_keepalive_interval() const { return m_keepalive_interval_hours; }

private:

    void schedule_regular_keepalives(const std::shared_ptr<SessionManager>& self);
    void send_keepalive(const char* cadence);
    
    // Session information
    SessionInfo m_session;
    
    // Configuration
    uint16_t m_keepalive_interval_hours;
    bool m_preserve_genesis_on_disconnect;  // Preserve genesis across sessions for reconnection

    std::shared_ptr<asio::io_context> m_io_context;
    std::shared_ptr<asio::steady_timer> m_keepalive_timer;
    std::atomic_bool m_keepalive_active;
    std::weak_ptr<network::Connection> m_connection;
    
    // Logger
    std::shared_ptr<spdlog::logger> m_logger;
};

} // namespace protocol
} // namespace nexusminer

#endif // NEXUSMINER_PROTOCOL_SESSION_MANAGER_HPP
