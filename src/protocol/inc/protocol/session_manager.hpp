#ifndef NEXUSMINER_PROTOCOL_SESSION_MANAGER_HPP
#define NEXUSMINER_PROTOCOL_SESSION_MANAGER_HPP

#include <vector>
#include <cstdint>
#include <string>
#include <memory>
#include <chrono>
#include <atomic>
#include <mutex>
#include <array>
#include <deque>
#include <functional>
#include <optional>
#include "asio/io_context.hpp"
#include "asio/steady_timer.hpp"
#include "network/types.hpp"
#include "protocol/session_semantic_types.hpp"
#include "protocol_lane.hpp"
#include "spdlog/spdlog.h"
#include "LLP/include/colin_ping_protocol.h"

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
    static constexpr std::size_t SESSION_EVENT_JOURNAL_CAPACITY = 32;
    
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

    enum class SessionEventKind {
        AUTH_INIT,
        AUTH_SUCCESS,
        SESSION_START,
        REWARD_BIND_SENT,
        REWARD_BIND_RESULT,
        STATUS_ACK_ACCEPTED,
        STATUS_ACK_REJECTED,
        STALE_PACKET_DROPPED,
        EPOCH_MISMATCH,
        FORCED_REAUTH,
        SUBMIT_SENT,
        SUBMIT_ACCEPTED,
        SUBMIT_REJECTED
    };

    struct SessionEvent {
        uint64_t timestamp{0};
        SessionEventKind kind{SessionEventKind::AUTH_INIT};
        SessionId session_id{};
        SessionEpoch session_epoch{};
        std::string detail;
    };

    /**
     * @brief Register a callback to be invoked when session transitions to EXPIRED.
     * @param h Callback function (void())
     */
    void set_session_expired_handler(SessionExpiredHandler h) { m_session_expired_handler = std::move(h); }
    
    /**
     * @brief Session information structure
     */
    struct MinerSessionContainer {
        std::string remote_endpoint;
        std::string local_endpoint;
        ProtocolLane active_lane{ProtocolLane::UNKNOWN};
        bool connected{false};
        bool authenticated{false};
        std::vector<uint8_t> falcon_pubkey;
        std::string falcon_key_id;
        bool falcon_authenticated{false};
        uint32_t session_id{0};
        uint64_t session_epoch{0};
        std::vector<uint8_t> session_key;  // Falcon session key from node
        std::vector<uint8_t> session_genesis;  // Tritium genesis hash (32 bytes)
        std::vector<uint8_t> chacha20_session_key;
        std::string chacha20_key_fingerprint;
        bool chacha20_ready{false};
        std::string reward_address_string;
        std::vector<uint8_t> reward_hash;
        bool reward_bound{false};
        std::string reward_binding_source;
        uint32_t channel{0};
        bool ready_for_submit{false};
        bool ready_for_get_block{false};
        std::array<uint8_t, 4> prevblock_suffix{};
        uint64_t created_at{0};
        uint64_t last_auth_time{0};
        uint64_t last_reward_bind_time{0};
        uint64_t last_activity{0};
        SessionState state{SessionState::DISCONNECTED};
        std::chrono::system_clock::time_point last_keepalive;
        std::chrono::system_clock::time_point session_start;
        uint32_t keepalive_count{0};
    };
    using SessionInfo = MinerSessionContainer;
    
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

    void commit_authenticated_session(uint32_t session_id,
                                      const std::vector<uint8_t>& pubkey,
                                      const std::string& key_id,
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
     * @brief Build SESSION_STATUS packet bytes (8-byte payload)
     *
     * Encodes the miner's current status for the node's lane-health query system.
     * Uses the correct opcode framing for the configured protocol lane.
     *
     * @param degraded        True if workers are in degraded mode
     * @param has_template    True if a valid mining template is currently held
     * @param workers_running True if mining workers are active
     * @param secondary_up    True if the secondary (legacy) lane is connected
     */
    network::Shared_payload build_session_status_packet(
        bool degraded,
        bool has_template,
        bool workers_running,
        bool secondary_up) const;
    
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
    SessionState get_state() const;

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
    uint32_t get_session_id() const;

    /**
     * @brief Get current authoritative session epoch/generation
     *
     * Incremented whenever a new session replaces the previous session so that
     * delayed packets and stale cached state can be rejected.
     *
     * @return Current session epoch (0 before the first session is started)
     */
    uint64_t get_session_epoch() const;

    /**
     * @brief Get session key
     *
     * @return Reference to session key
     */
    std::vector<uint8_t> get_session_key() const;

    /**
     * @brief Get Tritium genesis hash
     *
     * @return Reference to genesis hash
     */
    std::vector<uint8_t> get_tritium_genesis() const;
    
    /**
     * @brief Set Tritium genesis hash
     * 
     * @param genesis Genesis hash (32 bytes)
     */
    void set_tritium_genesis(const std::vector<uint8_t>& genesis);

    void set_connection_metadata(const std::string& local_endpoint,
                                 const std::string& remote_endpoint,
                                 bool connected);

    void set_falcon_identity(const std::vector<uint8_t>& pubkey,
                             const std::string& key_id,
                             bool authenticated);

    void reset_session_credentials();

    void set_chacha20_session_key(const std::vector<uint8_t>& session_key,
                                  const std::string& fingerprint,
                                  bool ready);

    void set_reward_binding(const std::string& reward_address,
                            const std::vector<uint8_t>& reward_hash,
                            bool bound,
                            const std::string& source);

    void set_channel_state(uint32_t channel,
                           bool ready_for_submit,
                           bool ready_for_get_block);

    void mark_activity();

    bool validate_miner_session(std::string* reason = nullptr) const;

    std::string build_miner_session_diagnostics() const;

    void record_session_event(SessionEventKind kind, const std::string& detail = "");

    std::vector<SessionEvent> get_session_event_journal() const;

    std::string build_session_event_journal() const;
    
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
    SessionInfo get_session_info() const;
    
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

    /**
     * @brief Validate MinerSessionContainer invariants while the caller holds m_session_mutex.
     *
     * @param session Session snapshot/container to validate
     * @param reason Optional diagnostic output describing the first failure or PASS
     * @return true when the container is internally consistent
     */
    static bool validate_miner_session_container_locked(const MinerSessionContainer& session,
                                                        std::string* reason);
    static const char* session_event_kind_name(SessionEventKind kind);
    void clear_session_event_journal_locked();
    void record_session_event_locked(SessionEventKind kind, const std::string& detail);
    void schedule_regular_keepalives(const std::shared_ptr<SessionManager>& self);
    void send_keepalive(const char* cadence);
    // Internal helper: get session uptime without locking (caller must hold m_session_mutex)
    std::chrono::seconds get_session_uptime_locked() const;

    // Session information
    mutable std::mutex m_session_mutex;  // guards m_session and related lane/keepalive metadata
    SessionInfo m_session;  // protected by m_session_mutex
    std::deque<SessionEvent> m_session_event_journal;  // protected by m_session_mutex
    
    // Configuration
    uint16_t m_keepalive_interval_hours;
    bool m_preserve_genesis_on_disconnect;  // Preserve genesis across sessions for reconnection
    ProtocolLane m_protocol_lane;  // Protocol lane for packet generation
    mutable uint32_t m_keepalive_sequence{0};  // Monotonic sequence counter for KEEPALIVE_V2 frames

    std::shared_ptr<asio::io_context> m_io_context;
    std::shared_ptr<asio::steady_timer> m_keepalive_timer;
    std::atomic_bool m_keepalive_active;
    // Generation counter: incremented each time stop_keepalive_timer() is called.
    // Timer lambdas capture the generation at scheduling time; if it doesn't match
    // the current generation when they fire, they are stale and return immediately.
    std::atomic<uint64_t> m_keepalive_generation{0};
    std::weak_ptr<network::Connection> m_connection;
    
    // Logger
    std::shared_ptr<spdlog::logger> m_logger;

    // Callback invoked when session transitions to EXPIRED state
    SessionExpiredHandler m_session_expired_handler;
};

} // namespace protocol
} // namespace nexusminer

#endif // NEXUSMINER_PROTOCOL_SESSION_MANAGER_HPP
