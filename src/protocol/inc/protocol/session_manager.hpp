#ifndef NEXUSMINER_PROTOCOL_SESSION_MANAGER_HPP
#define NEXUSMINER_PROTOCOL_SESSION_MANAGER_HPP

#include <vector>
#include <cstdint>
#include <string>
#include <memory>
#include <chrono>
#include <atomic>
#include <array>
#include <functional>
#include "asio/io_context.hpp"
#include "asio/steady_timer.hpp"
#include "network/types.hpp"
#include "protocol_lane.hpp"
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
     * @brief Callback type invoked when session transitions to EXPIRED state.
     * Registered by Solo/Worker_manager to trigger recovery on session mismatch.
     */
    using SessionExpiredHandler = std::function<void()>;

    /**
     * @brief Register a callback to be invoked when session transitions to EXPIRED.
     * @param h Callback function (void())
     */
    void set_session_expired_handler(SessionExpiredHandler h) { m_session_expired_handler = std::move(h); }
    
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
     * Sends an initial 10-second early keepalive after session establishment,
     * then schedules regular 45-second TCP keepalives to prevent node timeout.
     * The node's block cache times out after 90 seconds, so 45s provides
     * 2 pings per 90s window with comfortable margin.
     * Requires SessionManager to be managed by std::shared_ptr.
     */
    void start_keepalive_timer();

    /**
     * @brief Stop keepalive timer
     */
    void stop_keepalive_timer();

    /**
     * @brief Build SESSION_KEEPALIVE packet bytes (v2: 8-byte payload)
     *
     * Payload layout:
     *   [0..3] session_id           (u32 little-endian)
     *   [4..7] miner_prevblock_suffix (last 4 bytes of hashPrevBlock, raw bytes;
     *                                  zeros when no valid template is available)
     */
    network::Shared_payload build_keepalive_packet() const;
    
    /**
     * @brief Check if keepalive ping is due
     * 
     * NOTE: This function is currently UNUSED. The timer-driven keepalive system
     * in schedule_regular_keepalives() directly controls when keepalives are sent.
     * This function is retained for potential future manual keepalive checks.
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
     * @brief Set the miner's current template anchor suffix for v2 keepalives.
     *
     * Called whenever the active template changes.  The 4 bytes are appended
     * to every outbound SESSION_KEEPALIVE as `miner_prevblock_suffix`.
     *
     * @param suffix Last 4 bytes of current template.block.hashPrevBlock
     *               (bytes[124..127] of GetBytes()); pass zeros when no template.
     */
    void set_prevblock_suffix(const std::array<uint8_t, 4>& suffix);

    /**
     * @brief Set keepalive interval
     * 
     * @param hours Interval in hours (1-168)
     */
    void set_keepalive_interval(uint16_t hours);
    
    /**
     * @brief Set protocol lane for keepalive packet generation
     * 
     * @param lane Protocol lane (LEGACY for 8-bit, STATELESS for 16-bit)
     */
    void set_protocol_lane(ProtocolLane lane);
    
    /**
     * @brief Map a legacy auth opcode to the lane-appropriate opcode
     * 
     * On STATELESS lane, auth opcodes are mirror-mapped (0xD000 | legacy_opcode)
     * to avoid the 0xD0 (208) ambiguity with the stateless prefix byte.
     * On LEGACY lane, opcodes are returned unchanged.
     * 
     * @param legacy_opcode Legacy uint8_t opcode (e.g., 207 for MINER_AUTH_INIT)
     * @return Lane-appropriate opcode (uint16_t to hold both formats)
     */
    uint16_t map_auth_opcode(uint8_t legacy_opcode) const;
    
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
    ProtocolLane m_protocol_lane;  // Protocol lane for packet generation
    std::array<uint8_t, 4> m_prevblock_suffix{};  // Last 4 bytes of current template hashPrevBlock

    std::shared_ptr<asio::io_context> m_io_context;
    std::shared_ptr<asio::steady_timer> m_keepalive_timer;
    std::atomic_bool m_keepalive_active;
    std::weak_ptr<network::Connection> m_connection;
    
    // Logger
    std::shared_ptr<spdlog::logger> m_logger;

    // Callback invoked when session transitions to EXPIRED state
    SessionExpiredHandler m_session_expired_handler;
};

} // namespace protocol
} // namespace nexusminer

#endif // NEXUSMINER_PROTOCOL_SESSION_MANAGER_HPP
