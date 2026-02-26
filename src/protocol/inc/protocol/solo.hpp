#ifndef NEXUSMINER_PROTOCOL_SOLO_HPP
#define NEXUSMINER_PROTOCOL_SOLO_HPP

#include "protocol/protocol.hpp"
#include "protocol/falcon_wrapper.hpp"
#include "protocol/chacha20_wrapper.hpp"
#include "protocol/session_manager.hpp"
#include "protocol/mining_template_interface.hpp"
#include "protocol/push_notification_handler.hpp"
#include "protocol/height_tracker.hpp"
#include "protocol/keepalive_telemetry.hpp"
#include "mining/client_channel_manager.h"
#include "protocol_lane.hpp"
#include "LLP/colin_ping_handler.h"
#include "spdlog/spdlog.h"
#include <atomic>
#include <chrono>
#include <memory>

namespace nexusminer {
namespace network { class Connection; }
namespace stats { class Collector; }
namespace mining { class PrimeClientManager; class HashClientManager; }
namespace protocol
{

enum class AuthState {
    NOT_AUTHENTICATED,
    WAITING_FOR_CHALLENGE,
    WAITING_FOR_RESULT,
    AUTHENTICATED
};

class Solo : public Protocol {
public:

    Solo(std::uint8_t channel, std::shared_ptr<stats::Collector> stats_collector,
         std::shared_ptr<asio::io_context> io_context);

    void reset() override;
    network::Shared_payload login(Login_handler handler) override;
    network::Shared_payload get_work() override;
    /// Like get_work() but bypasses the miner-side rate limiter for immediate tip-moved refreshes.
    /// The node-side PR #283 one-shot bypass serves this without striking the rate limit.
    /// Only call from tip_moved / channel_stale paths — NOT from polling loops.
    network::Shared_payload get_work_immediate();
    /// One-shot bypass of the miner-side GET_BLOCK rate limiter for SIM Link lane-failure recovery.
    /// Resets the rate-limit clock so the very next get_work() call goes through immediately,
    /// matching the node-side one-shot bypass from LLL-TAO PR #283.
    /// The bypass is consumed after a single get_work() call; subsequent calls obey the normal limit.
    void bypass_get_block_rate_limit_once();
    network::Shared_payload submit_block(std::vector<std::uint8_t> const& block_data, std::uint64_t nonce) override;
    void set_block_handler(Set_block_handler handler) override { m_set_block_handler = std::move(handler); }

    void process_messages(Packet packet, std::shared_ptr<network::Connection> connection) override;
    
    // GET_ROUND protocol support (12-byte response from LLL-TAO PR #151)
    struct RoundStatus {
        bool is_new_round;          // true if NEW_ROUND (204), false if OLD_ROUND (205)
        uint32_t height;            // Unified blockchain height (reference only)
        uint32_t difficulty;        // Mining difficulty in compact nBits format (big-endian)
        
        // Channel-specific heights (miner's channel only)
        uint32_t prime_height;      // Prime channel height (if mining Prime)
        uint32_t hash_height;       // Hash channel height (if mining Hash)
        uint32_t stake_height;      // Stake channel height (unused by stateless miners)
        bool has_channel_heights;   // True if 12-byte response parsed successfully
        
        /**
         * @brief Get channel-specific height
         * @param channel Channel number (1=Prime, 2=Hash, 3=Stake)
         * @return Channel height, or 0 if not set
         */
        uint32_t get_channel_height(uint32_t channel) const {
            switch(channel) {
                case 1:  return prime_height;
                case 2:  return hash_height;
                case 3:  return stake_height;
                default: return 0;
            }
        }
    };
    /// Send GET_ROUND on all lanes (legacy: 0x85; stateless: 0xD085).
    /// This is a pure informational/sanity probe — the node responds with
    /// NEW_ROUND or OLD_ROUND containing height and difficulty info.
    /// It does NOT request a block template.  Use send_recovery_work_request()
    /// when the intent is to force a fresh template retrieval.
    network::Shared_payload send_get_round();
    /// Send GET_BLOCK on all lanes (legacy: 0x81; stateless: 0xD081) to request
    /// a fresh mining template.  Authentication-guarded; delegates to get_work()
    /// and therefore respects the miner-side 1s rate limiter.  Returns null/empty
    /// when rate-limited or not yet authenticated — callers must guard for this.
    /// Use this method — not send_get_round() — for template recovery actions.
    network::Shared_payload send_recovery_work_request();
    RoundStatus get_last_round_status() const { return m_last_round_status; }
    
    // Intelligent polling: Check if GET_ROUND should be sent now
    // Note: This modifies internal timing state, so cannot be truly const
    bool should_send_get_round() { return should_poll_get_round(); }
    
    // Falcon miner authentication
    void set_miner_keys(std::vector<uint8_t> const& pubkey, std::vector<uint8_t> const& privkey);
    bool is_authenticated() const { return m_authenticated; }
    void set_address(std::string const& address) { m_address = address; }
    void set_protocol_lane(ProtocolLane lane);
    
    // Tritium GenesisHash for reward binding
    void set_tritium_genesis(std::vector<uint8_t> const& genesis);
    bool has_tritium_genesis() const;
    
    // Session management configuration
    void set_keepalive_interval(std::uint16_t hours);
    void enable_chacha20_wrapping(bool enable) { m_enable_chacha20 = enable; }
    bool is_chacha20_enabled() const { return m_enable_chacha20; }
    
    // Disposable Falcon is ALWAYS ON (core protocol) - method kept for backward compatibility only
    void enable_disposable_falcon(bool enable) { m_disposable_falcon_enabled = enable; }
    bool is_disposable_falcon_enabled() const { return m_disposable_falcon_enabled; }
    
    // Legacy method names (deprecated - kept for backward compatibility)
    void enable_block_signing(bool enable) { m_disposable_falcon_enabled = enable; }
    bool is_block_signing_enabled() const { return m_disposable_falcon_enabled; }
    
    // Session management (LLL-TAO PR #22)
    network::Shared_payload send_session_keepalive();
    std::uint32_t get_session_id() const;
    bool is_session_active() const;
    
    // Check if keep-alive ping is due
    bool is_keepalive_due() const;

    // KEEPALIVE v2 telemetry: returns the latest snapshot received from the node.
    // Returns an invalid (valid==false) snapshot if no v2 reply has been received yet.
    KeepaliveTelemetrySnapshot get_keepalive_telemetry() const { return m_keepalive_telemetry.get(); }

    // Last fork_score received in a KEEPALIVE_V2_ACK frame.
    // Returns 0 if no ACK has been received yet or the chain is healthy.
    uint32_t get_last_keepalive_fork_score() const { return m_last_keepalive_fork_score; }

    // SessionManager keepalive needs connection context
    void set_connection(std::shared_ptr<network::Connection> connection);
    
    // Mining Template Interface access (unified READ/FEED system)
    MiningTemplateInterface* get_template_interface() { return m_template_interface.get(); }
    const MiningTemplateInterface* get_template_interface() const { return m_template_interface.get(); }
    
    // Push-cooldown guard: returns true if a push was received within TEMPLATE_PUSH_COOLDOWN.
    // Used by Worker_manager::retry_template_request() to skip GET_BLOCK polling when the
    // node is pushing normally (push-driven era: fresh template arrives within ~2 s of each tip advance).
    bool was_push_received_recently() const
    {
        if (m_last_push_received_time == std::chrono::steady_clock::time_point{})
            return false;
        return (std::chrono::steady_clock::now() - m_last_push_received_time) < TEMPLATE_PUSH_COOLDOWN;
    }

    // Returns the raw timestamp of the last received push notification (steady_clock).
    // Used by Worker_manager::check_template_health() to determine whether the current
    // template was received AFTER the last push (post-push = fresh, skip stop_all_workers).
    std::chrono::steady_clock::time_point get_last_push_received_time() const
    {
        return m_last_push_received_time;
    }
    
    // Stateless mining reward address binding (MINER_SET_REWARD protocol)
    void set_reward_address(std::string const& address) { m_reward_address = address; }
    bool has_reward_address() const { return !m_reward_address.empty(); }
    bool is_reward_bound() const { return m_reward_bound; }
    network::Shared_payload send_set_reward();
    
    // Push notification subscription (LLL-TAO PR #156)
    network::Shared_payload send_miner_ready();
    
    // HeightTracker snapshot (single source of truth for height/staleness decisions)
    HeightTracker::Snapshot get_height_tracker_snapshot() const { return m_height_tracker.GetSnapshot(); }

    // Recovery callback: called by the push handler when a channel-stale recovery GET_BLOCK
    // is triggered (is_template_stale() is true at request_work_fn invocation time).
    // Worker_manager registers this to set its recovery_pending flag for doom-loop prevention.
    using Recovery_handler = std::function<void()>;
    void set_recovery_initiated_handler(Recovery_handler h) { m_recovery_handler = std::move(h); }

    // Block-result counters (Gap 3)
    uint32_t get_blocks_accepted() const { return m_blocks_accepted.load(); }
    uint32_t get_blocks_rejected() const { return m_blocks_rejected.load(); }

    // Colin AI Diagnostic PING/PONG handler
    const ::LLP::ReceivedPingFrame& last_received_ping() const
    {
        return m_colin_ping_handler.last_received_ping();
    }

private:
    
    // Derive ChaCha20 session key from genesis hash
    std::vector<uint8_t> derive_chacha20_session_key(const std::vector<uint8_t>& genesis);
    
    // Load tritium genesis (session manager or persistent storage)
    std::vector<uint8_t> load_tritium_genesis();
    
    // Helper method to send SET_CHANNEL packet
    void send_set_channel(std::shared_ptr<network::Connection> connection);
    
    // Challenge-response authentication methods
    void handle_miner_auth_challenge(const Packet& packet);
    
    // Helper to reset authentication state on errors
    void reset_auth_state();
    
    // Handle reward result response from node (MINER_REWARD_RESULT)
    void handle_reward_result(const Packet& packet);
    
    // Unified handler for initial template reception (called by both BLOCK_DATA and STATELESS_GET_BLOCK handlers)
    void handle_initial_template_response(const char* opcode_name);
    
    // Helper method to finalize template with channel height
    // Returns true if template was finalized, false if already finalized or no template
    bool finalize_template_with_channel_height(uint32_t node_channel_height, const std::string& context);
    
    // Helper method to get channel manager for current channel
    mining::ClientChannelManager* get_channel_manager() const;
    mining::ClientChannelManager* get_channel_manager(uint32_t channel) const;
    
    // Integration helper functions (bridge MiningTemplateInterface and ClientChannelManager)
    /**
     * @brief Synchronize channel manager state with template interface
     * 
     * Called after GET_ROUND response to:
     * 1. Update channel manager heights
     * 2. Check for forks (auto-invalidate template if detected)
     * 3. Finalize template channel height if needed
     * 4. Validate current template against channel manager state
     * 
     * @param unified_height Current unified height from GET_ROUND
     * @param channel_height Current channel height from GET_ROUND (for THIS channel)
     * @return true if template is still valid, false if invalidated
     */
    bool sync_template_state(uint32_t unified_height, uint32_t channel_height);
    
    /**
     * @brief Check if current template is valid using channel manager state
     * 
     * Validates channel-specific staleness:
     * - Channel height: template.nChannelHeight == node_channel + 1
     * - Unified height differences are informational (other channels may advance)
     * - Age timeout: template age < 60 seconds
     * 
     * @return true if template valid, false if stale/invalid
     */
    bool validate_current_template();
    
    /**
     * @brief Handle fork detection and template invalidation
     * 
     * Called when fork is detected to:
     * - Log rollback information
     * - Invalidate current template in MiningTemplateInterface
     * - Clear fork flag in channel manager
     * 
     * @param pManager Channel manager that detected the fork
     * @param current_height Current unified height after rollback
     */
    void handle_fork_detected(mining::ClientChannelManager* pManager, uint32_t current_height);

    /**
     * @brief Unified height-state updater (single source of truth for both HeightTracker and ClientChannelManager)
     *
     * Called from push notification handlers and GET_ROUND handlers to ensure
     * HeightTracker and the active ClientChannelManager are always updated from
     * the same parsed data.  Fork detection is run immediately after the manager
     * update so that template invalidation is consistent across both sources.
     *
     * @param unified_height  Unified blockchain height from the parsed packet
     * @param channel_height  Channel-specific height from the parsed packet
     * @param difficulty_nbits Compact nBits difficulty from the parsed packet
     * @param source          Update origin (PUSH or GET_ROUND)
     */
    void update_height_state(uint32_t unified_height, uint32_t channel_height,
                             uint32_t difficulty_nbits, HeightTracker::UpdateSource source);

    std::uint8_t m_channel;
    std::shared_ptr<spdlog::logger> m_logger;
    std::uint32_t m_current_height; ///< Diagnostic-only: used for BLOCK_DATA legacy fallback; NOT authoritative for staleness
    std::uint64_t m_current_reward;
    Set_block_handler m_set_block_handler;
    std::shared_ptr<stats::Collector> m_stats_collector;

    // hashPrevBlock snapshot (Gap 1): tip anchor captured at template parse time.
    // Equivalent to StakeMinter::hashLastBlock — a new template with a different
    // hashPrevBlock signals that the chain tip has moved.
    uint1024_t m_last_known_hash_prev_block;

    // Push-driven era: timestamp of the last successfully received template push.
    // Used by was_push_received_recently() to avoid unnecessary GET_BLOCK polling
    // when the node is delivering templates normally (within TEMPLATE_PUSH_COOLDOWN).
    static constexpr std::chrono::seconds TEMPLATE_PUSH_COOLDOWN{200};
    std::chrono::steady_clock::time_point m_last_push_received_time{};

    // Block-result counters (Gap 3): incremented by BLOCK_ACCEPTED / BLOCK_REJECTED handlers.
    std::atomic<uint32_t> m_blocks_accepted{0};
    std::atomic<uint32_t> m_blocks_rejected{0};
    
    // Falcon miner authentication state (Phase 2)
    std::vector<uint8_t> m_miner_pubkey;
    std::vector<uint8_t> m_miner_privkey;
    bool m_authenticated;
    std::uint32_t m_session_id;
    std::string m_address;  // Miner's network address for auth message
    std::uint64_t m_auth_timestamp;  // Timestamp for auth message
    AuthState m_auth_state;  // Authentication state machine
    std::string m_miner_id;  // Miner identifier (optional)
    
    // Unified Falcon Signature Wrapper (Phase 2 enhancement)
    std::unique_ptr<FalconSignatureWrapper> m_falcon_wrapper;
    bool m_disposable_falcon_enabled;     // Disposable Falcon signing (ALWAYS ON - core protocol, 0 blockchain overhead)
    
    // ChaCha20 encryption wrapper for Falcon pubkey protection
    std::unique_ptr<ChaCha20Wrapper> m_chacha20_wrapper;
    bool m_enable_chacha20;  // ChaCha20 encryption (ALWAYS ON - core security for localhost + SessionID)
    
    // Session manager for adaptive cache management
    std::shared_ptr<SessionManager> m_session_manager;

    // KEEPALIVE v2 telemetry snapshot (thread-safe store, updated in SESSION_KEEPALIVE handler)
    KeepaliveTelemetryStore m_keepalive_telemetry;

    // KEEPALIVE_V2 (0xD100) send-side tracking:
    // The lo32 of hashPrevBlock that the miner put in its last KEEPALIVE_V2 frame.
    // Stored locally so the ACK handler can compare against the node's echoed value
    // without trusting the potentially-tampered echo in ack.hashPrevBlock_lo32.
    uint32_t m_last_keepalive_prevhash_lo32{0};

    // Last fork_score received in a KEEPALIVE_V2_ACK frame (0 = healthy).
    // Exposed to ColinAgent for periodic diagnostic reporting.
    uint32_t m_last_keepalive_fork_score{0};
    
    // Mining Template Interface for unified READ/FEED operations
    std::unique_ptr<MiningTemplateInterface> m_template_interface;
    
    // Centralized height tracker (single source of truth for heights)
    HeightTracker m_height_tracker;
    
    // Connection for multi-packet authentication flow
    std::shared_ptr<network::Connection> m_connection;
    
    // Persistent tritium genesis (preserved across reconnections)
    std::vector<uint8_t> m_persistent_tritium_genesis;
    
    // Stateless mining reward address binding (MINER_SET_REWARD protocol)
    std::string m_reward_address;  // NXS account address for mining rewards
    bool m_reward_bound;  // True after successful MINER_REWARD_RESULT
    
    // Push notification subscription state (MINER_READY sent after auth)
    std::atomic<bool> m_subscribed_to_notifications{false};

    // Recovery callback — invoked when a push handler fires GET_BLOCK for a stale template
    // (channel_advanced staleness), signalling Worker_manager to enter recovery_pending state.
    Recovery_handler m_recovery_handler;
    
    // GET_ROUND status tracking (Template Staleness Prevention - LLL-TAO PR #131)
    RoundStatus m_last_round_status;  // Last received round status
    
    // Client-side fork-aware channel managers (mirrors NODE's PR #136)
    // INTEGRATION PATTERN:
    // - MiningTemplateInterface (m_template_interface): Manages template storage and worker distribution
    // - ClientChannelManagers (m_prime_manager, m_hash_manager): Track heights and detect forks
    // 
    // Division of Responsibilities:
    // 1. MiningTemplateInterface:
    //    - Stores current mining template (MiningTemplate with LLP::CBlock)
    //    - Feeds templates to worker threads
    //    - Handles template age tracking (for 60s timeout)
    //    - Manages channel height (set via set_channel_height())
    // 
    // 2. ClientChannelManagers:
    //    - Track node heights from GET_ROUND (unified + channel)
    //    - Detect blockchain forks (height regression)
    //    - Provide validation logic (ValidateTemplate mirrors NODE's Block::Accept)
    //    - Do NOT store templates in production (use MiningTemplateInterface instead)
    // 
    // Fork Detection Flow:
    //   GET_ROUND response → Update managers → Fork detected? → Clear MiningTemplateInterface
    // 
    // This separation mirrors NODE's architecture where ChannelStateManager tracks state
    // but doesn't duplicate Block storage - blocks live in the blockchain database.
    std::unique_ptr<mining::PrimeClientManager> m_prime_manager;
    std::unique_ptr<mining::HashClientManager> m_hash_manager;
    
    // ═══════════════════════════════════════════════════════════════════════
    // GET_ROUND INTELLIGENT POLLING STATE
    // ═══════════════════════════════════════════════════════════════════════
    
    // Timing state
    std::chrono::steady_clock::time_point m_last_get_round_time;
    uint32_t m_current_poll_interval_ms;  // Current interval (adaptive)
    
    // Configuration constants
    static constexpr bool POLLING_ENABLED = false;             // Disabled: push notifications are primary
    static constexpr uint32_t POLL_INTERVAL_MIN_MS = 90000;    // 90 seconds (sanity-check interval if enabled)
    static constexpr uint32_t POLL_INTERVAL_MAX_MS = 120000;   // 120 seconds maximum
    // Note: When POLLING_ENABLED is true, backoff multiplier is 1.5x via integer arithmetic: interval + (interval >> 1)
    
    // State flags
    bool m_needs_initial_round_check;  // Set true when new template received
    uint32_t m_template_unified_height;    // Informational only: unified height at last template receipt (logging unified drift).
                                           // NOT used for staleness decisions (channel height is authoritative).
    
    // Helper methods for intelligent polling
    bool should_poll_get_round();
    void on_new_round_received(uint32_t new_unified_height);
    void on_old_round_received();
    void on_template_received(uint32_t template_height);
    void check_unified_height_delta(uint32_t current_unified_height);
    
    // ═══════════════════════════════════════════════════════════════════════
    // GET_BLOCK RATE LIMITER
    // ═══════════════════════════════════════════════════════════════════════
    //
    // Miner-side: 1s guard prevents rapid-fire within a push cycle.
    // Node-side (authoritative): 6s minimum (production), 2s (debug).
    // Node PR #283: one-shot bypass serves first GET_BLOCK after push immediately.
    //
    // Use get_work_immediate() for tip_moved / channel_stale refreshes to
    // reset the timer and leverage the PR #283 one-shot bypass.
    //
    // Timestamp of last GET_BLOCK request (rate limiter to prevent node 300s ban)
    std::chrono::steady_clock::time_point m_last_get_block_time{};
    
    // ═══════════════════════════════════════════════════════════════════════
    // PORT-LANE SEPARATION STATE (STRICT - NO FALLBACK)
    // ═══════════════════════════════════════════════════════════════════════
    
    // Protocol lane (determined once from connection port, never changes)
    ProtocolLane m_protocol_lane;
    
    // Unified push notification handler (consolidates 4 duplicate handlers)
    std::unique_ptr<PushNotificationHandler> m_push_handler;
    
    // Helper method to determine and log lane from connection
    void initialize_protocol_lane(std::shared_ptr<network::Connection> connection);

    // ═══════════════════════════════════════════════════════════════════════
    // COLIN AI DIAGNOSTIC PING/PONG HANDLER
    // ═══════════════════════════════════════════════════════════════════════
    // Handles PING_DIAG (0xE0 legacy / 0xD0E0 stateless) from node and
    // replies with a 64-byte PongFrame containing live miner telemetry.
    ::LLP::ColinPingHandler m_colin_ping_handler;
    
    // ═══════════════════════════════════════════════════════════════════════
    // PROTOCOL LANE DETERMINATION
    // ═══════════════════════════════════════════════════════════════════════
    // Protocol lane is strictly determined by connection port (no negotiation/fallback):
    // - Port 8323: Legacy lane (8-bit opcodes, polling)
    // - Port 9323+: Stateless lane (16-bit opcodes, push notifications)
    // 
    // State is anchored on:
    // - m_protocol_lane: Authoritative lane identifier (set at connection time)
    // - m_auth_state: Authentication state (managed by session manager)
    // - Push readiness: Inferred from actual template delivery events
};

}
}
#endif
