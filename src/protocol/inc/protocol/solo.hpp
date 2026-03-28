#ifndef NEXUSMINER_PROTOCOL_SOLO_HPP
#define NEXUSMINER_PROTOCOL_SOLO_HPP

#include "protocol/protocol.hpp"
#include "protocol/falcon_wrapper.hpp"
#include "protocol/chacha20_wrapper.hpp"
#include "protocol/session_manager.hpp"
#include "protocol/node_session_context.hpp"
#include "protocol/mining_template_interface.hpp"
#include "protocol/push_notification_handler.hpp"
#include "protocol/height_tracker.hpp"
#include "protocol/session_ingress_gate.hpp"
#include "protocol/session_recovery_policy.hpp"
#include "protocol/submit_context.hpp"
#include "protocol/epoch_coordinator.hpp"
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
    enum class GetBlockRequestStatus : uint8_t {
        NONE = 0,
        SENT,
        DUPLICATE_WINDOW,
        UNAUTHENTICATED,
        REWARD_NOT_BOUND,
        SESSION_INVALID,
        BUILD_EMPTY
    };

    Solo(std::uint8_t channel, std::shared_ptr<stats::Collector> stats_collector,
         std::shared_ptr<NodeSessionContext> session_context);

    void reset() override;
    network::Shared_payload login(Login_handler handler) override;
    /// Request a fresh mining template via GET_BLOCK.
    /// Authentication-guarded; returns null if not authenticated or reward not bound.
    /// No miner-side rate limiting — the node's 2-second AutoCoolDown enforces the server-side floor.
    network::Shared_payload get_work() override;
    network::Shared_payload get_work(bool bypass_dedup);
    GetBlockRequestStatus get_last_get_block_request_status() const { return m_last_get_block_request_status.load(); }

    /// Returns the number of consecutive hashPrevBlock mismatches detected by
    /// validate_current_template() since the last successful template adoption.
    /// Worker_manager uses this to apply exponential GET_BLOCK backoff during
    /// node-attack / chain-flux scenarios that would otherwise cause a rapid-fire
    /// discard-and-retry doom loop.
    uint32_t get_hashprev_mismatch_consecutive() const { return m_hashprev_mismatch_consecutive; }

    /// Reset the GET_BLOCK deduplication timestamp so the next get_work() call will
    /// not be suppressed.  Must be called whenever the canonical tip-anchor changes
    /// (same-height chain reorg) or a new degraded-recovery epoch begins, because the
    /// outstanding dedup state refers to a request for the *old* canonical tip and is
    /// therefore no longer valid as a duplicate guard.
    void reset_get_block_dedup_state();
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

    // GET_ROUND polling configuration (public so callers can log the intervals)
    static constexpr bool POLLING_ENABLED = true;              // Enabled: GET_ROUND sanity probe for both lanes
    static constexpr uint32_t POLL_INTERVAL_MIN_MS = 20000;    // 20 seconds minimum
    static constexpr uint32_t POLL_INTERVAL_MAX_MS = 60000;    // 60 seconds maximum
    // Minimum push-silence duration before GET_ROUND height parity check may trigger GET_BLOCK,
    // and before the adaptive backoff is clamped to POLL_INTERVAL_MIN_MS.
    // Lowered to 30s (from 45s) so the height-parity fallback fires within one polling cycle
    // during a chain-tip attack or push infrastructure disruption, without triggering on
    // normal short push gaps between hash blocks (~18s).
    // The existing channel_height >= tmpl->nChannelHeight guard ensures GET_BLOCK is only
    // sent when height parity is actually met, so a lower threshold is safe.
    static constexpr int64_t PUSH_ABSENT_FOR_PARITY_CHECK_SECONDS = 30;
    /// Send GET_BLOCK on all lanes (legacy: 0x81; stateless: 0xD081) to request
    /// a fresh mining template.  Authentication-guarded; delegates to get_work().
    /// Returns null/empty if not yet authenticated — callers must guard for this.
    /// Use this method — not send_get_round() — for template recovery actions.
    network::Shared_payload send_recovery_work_request();
    RoundStatus get_last_round_status() const { return m_last_round_status; }
    
    // Intelligent polling: Check if GET_ROUND should be sent now
    // Note: This modifies internal timing state, so cannot be truly const
    bool should_send_get_round() { return should_poll_get_round(); }
    
    // Falcon miner authentication
    void set_miner_keys(std::vector<uint8_t> const& pubkey, std::vector<uint8_t> const& privkey);
    bool is_authenticated() const { return m_session_context ? m_session_context->is_authenticated() : m_authenticated; }
    bool can_request_get_block() const {
        return m_session_context ? m_session_context->can_request_get_block() : m_authenticated;
    }
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
    
    // Session management (LLL-TAO PR #22 / PR #217)
    // Sends SESSION_KEEPALIVE via SessionManager (8-byte v2 payload: session_id + prevhash_lo32).
    // Node replies with the 32-byte unified KeepAliveV2AckFrame carrying all channel heights.
    network::Shared_payload send_session_keepalive();
    std::uint32_t get_session_id() const;
    bool is_session_active() const;

    // Build a SESSION_STATUS packet for transmission on this lane.
    // Uses the SessionManager and current template/worker state internally.
    // Returns null if session is not active or lane is UNKNOWN.
    network::Shared_payload build_session_status_packet(
        bool degraded, bool workers_running, bool secondary_up) const;
    
    // SessionManager keepalive needs connection context
    void set_connection(std::shared_ptr<network::Connection> connection);
    
    // Mining Template Interface access (unified READ/FEED system)
    MiningTemplateInterface* get_template_interface() { return m_template_interface.get(); }
    const MiningTemplateInterface* get_template_interface() const { return m_template_interface.get(); }
    
    // Stateless mining reward address binding (MINER_SET_REWARD protocol)
    void set_reward_address(std::string const& address);
    bool has_reward_address() const { return !m_reward_address.empty(); }
    bool is_reward_bound() const {
        return m_session_context ? m_session_context->get_runtime_snapshot().reward_bound : m_reward_bound;
    }
    network::Shared_payload send_set_reward();
    
    // Push notification subscription (LLL-TAO PR #156)
    network::Shared_payload send_miner_ready();
    /// Re-subscribe to push notifications by sending MINER_READY on the stored connection.
    /// Safe to call after prolonged push silence (e.g. after degraded recovery) to restore
    /// push flow when the node's subscription state may have been lost during TCP disruption.
    /// No-op when not yet authenticated or no connection is available.
    void resubscribe_push_notifications();
    
    // HeightTracker snapshot (single source of truth for height/staleness decisions)
    HeightTracker::Snapshot get_height_tracker_snapshot() const { return m_height_tracker.GetSnapshot(); }

    // Canonical-only snapshot (authoritative block-data state)
    HeightTracker::CanonicalChainState get_canonical_snapshot() const { return m_height_tracker.GetCanonicalSnapshot(); }

    // Diagnostic-only snapshot (push/keepalive/GET_ROUND telemetry)
    HeightTracker::DiagnosticObserverState get_diagnostic_snapshot() const { return m_height_tracker.GetDiagnosticSnapshot(); }

    // HeightTracker reference (for direct read access by ColinAgent)
    const HeightTracker& get_height_tracker() const { return m_height_tracker; }

    // Helper to access SessionManager through NodeSessionContext
    SessionManager* get_session_manager() const {
        return m_session_context ? m_session_context->get_session_manager().get() : nullptr;
    }

    void mark_authoritative_recovery_required(const std::string& reason);
    void mark_authoritative_recovery_healthy(const std::string& reason = "");

    // Recovery callback: called by the push handler when a channel-stale recovery GET_BLOCK
    // is triggered (is_template_stale() is true at request_work_fn invocation time).
    // Worker_manager registers this to set its recovery_pending flag for doom-loop prevention.
    using Recovery_handler = std::function<void()>;
    void set_recovery_initiated_handler(Recovery_handler h) { m_recovery_handler = std::move(h); }

    // Session-expired callback: called when a KEEPALIVE ACK session_id mismatch is detected.
    // Worker_manager registers this to trigger recovery on stale session (same pattern as
    // Recovery_handler above).
    using Session_expired_handler = std::function<void()>;
    void set_session_expired_handler(Session_expired_handler h) { m_session_expired_handler = std::move(h); }

    // Session-authenticated callback: called after MINER_AUTH_RESULT is fully processed and session_id is set.
    // Worker_manager registers this to check session_id=0 and trigger retry if needed.
    // Parameter: session_id (0 if node rejected authentication).
    using Session_authenticated_handler = std::function<void(uint32_t session_id)>;
    void set_session_authenticated_handler(Session_authenticated_handler h) { m_session_authenticated_handler = std::move(h); }

    // Session-start callback: called when SESSION_START is received and keepalive interval
    // has been auto-adjusted from the node-advertised timeout.
    // Parameter: keepalive_hours (the newly derived interval, e.g. session_timeout / 2 / 3600)
    using Session_start_handler = std::function<void(uint16_t keepalive_hours)>;
    void set_session_start_handler(Session_start_handler h) { m_session_start_handler = std::move(h); }

    // Block-result counters (Gap 3)
    uint32_t get_blocks_accepted() const { return m_blocks_accepted.load(); }
    uint32_t get_blocks_rejected() const { return m_blocks_rejected.load(); }

    // Block-result callback: invoked on BLOCK_ACCEPTED with (height, hashPrevBlock, channel, nonce).
    // Worker_manager registers this to record accepted blocks in the mined-block cache.
    using Block_accepted_handler = std::function<void(uint32_t height, uint1024_t hash_prev_block,
                                                      uint32_t channel, uint64_t nonce)>;
    void set_block_accepted_handler(Block_accepted_handler h) { m_block_accepted_handler = std::move(h); }

    // Node shutdown callback: invoked when NODE_SHUTDOWN (0xD0FF) is received.
    // Worker_manager registers this to stop workers and set reconnect backoff.
    // Parameter: shutdown reason (GRACEFUL=0x01, MAINTENANCE=0x02).
    using Node_shutdown_handler = std::function<void(uint8_t reason)>;
    void set_node_shutdown_handler(Node_shutdown_handler h) { m_node_shutdown_handler = std::move(h); }

    // Reconnect backoff (seconds) after receiving NODE_SHUTDOWN from the node.
    static constexpr uint32_t NODE_SHUTDOWN_BACKOFF_S = 60;

    // Colin AI Diagnostic PING/PONG handler
    const ::LLP::ReceivedPingFrame& last_received_ping() const
    {
        return m_colin_ping_handler.last_received_ping();
    }

    // Non-owning reference to the Colin ping handler for diagnostics (ping_count, last_rtt_us).
    // Lifetime: as long as this Solo instance is alive.
    const ::LLP::ColinPingHandler& get_ping_handler() const { return m_colin_ping_handler; }

    // SESSION_STATUS_ACK tracking — updated whenever a SESSION_STATUS_ACK is received
    /** Returns the most recently received SESSION_STATUS_ACK frame (zero if never received) **/
    const ::LLP::SessionStatusAckFrame& last_session_status_ack() const { return m_last_session_status_ack; }
    /** Returns time of last SESSION_STATUS_ACK (default time_point if never received) **/
    std::chrono::steady_clock::time_point last_session_status_ack_time() const { return m_last_session_status_ack_time; }

    // Returns true if authentication is currently in-flight (waiting for challenge or result).
    // Used by Worker_manager to avoid sending duplicate login() calls.
    bool is_auth_in_progress() const {
        return m_auth_state == AuthState::WAITING_FOR_CHALLENGE ||
               m_auth_state == AuthState::WAITING_FOR_RESULT;
    }

    // Returns how many seconds auth has been in-flight (0 if not in-flight).
    // Used by Worker_manager to detect stuck in-flight auth from a dead TCP session.
    double auth_in_flight_seconds() const {
        if (!is_auth_in_progress() || m_auth_in_flight_since == std::chrono::steady_clock::time_point{})
            return 0.0;
        return std::chrono::duration<double>(std::chrono::steady_clock::now() - m_auth_in_flight_since).count();
    }

    // Reset only the authentication state machine (auth_state, auth_in_flight_since, authenticated flag).
    // Call this before triggering in-band re-authentication to clear any stale in-flight state.
    // Does NOT clear session key, genesis, or connection.
    void reset_auth_state();

    // Maximum time (seconds) auth is allowed to stay in-flight before being treated as failed.
    static constexpr int AUTH_IN_FLIGHT_TIMEOUT_S = 30;

    /// Wire the shared EpochCoordinator (called by Worker_manager after construction).
    void set_epoch_coordinator(std::shared_ptr<EpochCoordinator> coordinator);

private:
    
    // Derive ChaCha20 session key from genesis hash
    std::vector<uint8_t> derive_chacha20_session_key(const std::vector<uint8_t>& genesis);
    
    // Load tritium genesis (session manager or persistent storage)
    std::vector<uint8_t> load_tritium_genesis();
    
    // Helper method to send SET_CHANNEL packet
    void send_set_channel(std::shared_ptr<network::Connection> connection);

    // If auth is in-flight and has exceeded AUTH_IN_FLIGHT_TIMEOUT_S, reset to NOT_AUTHENTICATED.
    // Returns true if a timeout reset occurred.
    bool check_auth_in_flight_timeout(const char* context);

    // Session ID mismatch check — shared by KEEPALIVE_V2_ACK and SESSION_STATUS_ACK handlers.
    // Returns true if a mismatch was detected (state set to EXPIRED, handler called);
    // caller must return immediately when true is returned.
    bool handle_session_id_mismatch(uint32_t ack_session_id);

    // Session expired handler — called when SESSION_EXPIRED (0xDD / 0xD0DD) packet is received
    // Implements 5-step response: log, clear state, stop workers, prepare for re-auth
    void handle_session_expired(uint32_t expired_sid, uint8_t reason, std::shared_ptr<network::Connection> connection);

    // Challenge-response authentication methods
    void handle_miner_auth_challenge(const Packet& packet);
    
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

    // NodeSessionContext is the authoritative session source; use it to detect
    // whether a stale local auth flag needs resynchronization.
    bool session_context_is_authenticated() const;
    void propagate_session_to_template_interface(const char* log_scope);
    void resync_auth_from_session_context(const char* log_scope);
    void refresh_cached_session_state(const char* log_scope);
    void update_connection_metadata(const std::shared_ptr<network::Connection>& connection);
    bool validate_authoritative_session(const char* log_scope, bool require_reward_binding) const;
    void log_session_container_summary(const char* log_scope) const;
    struct PacketIngressPreflightOptions {
        const SessionOwnershipStamp* owner{nullptr};
        uint32_t packet_session_id{0};
        bool allow_without_active_session{false};
        bool validate_lane{false};
        bool require_crypto_ready{false};
        bool require_reward_binding{false};
        bool trigger_reauth{false};
    };
    SessionOwnershipStamp capture_session_ownership() const;
    SubmitContext capture_submit_context(uint32_t template_height,
                                         uint32_t chain_height) const;
    void record_session_event(SessionManager::SessionEventKind kind,
                              const std::string& detail) const;
    void finalize_keepalive_ack(const char* detail);
    void clear_generation_bound_state(const char* reason);
    bool finalize_and_feed_current_template(uint32_t unified_height,
                                            uint32_t effective_channel_height,
                                            const char* log_scope,
                                            bool snapshot_round_channel_height);
    static const PacketIngressPreflightOptions kDefaultPacketIngressPreflightOptions;
    bool run_packet_ingress_preflight(
        const char* log_scope,
        const PacketIngressPreflightOptions& options = kDefaultPacketIngressPreflightOptions) const;
    bool ensure_session_ready_for_ingress(const char* log_scope,
                                          const char* packet_name,
                                          bool queue_post_auth_get_block);
    void queue_pending_push_after_auth(const char* log_scope);
    void flush_pending_push_after_auth(const std::shared_ptr<network::Connection>& connection,
                                       const char* log_scope);
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
     * @brief Check if current template is valid using HeightTracker snapshot state
     * 
     * Validates channel-specific staleness using a directional guard:
     * - Discards only when snap.channel_height >= template.nChannelHeight
     *   (chain tip has already met or passed our mining target).
     * - nChannelHeight > expectedChannel (multiple blocks ahead of local tracker) is
     *   intentionally accepted — normal during burst recovery when push notifications
     *   for intermediate blocks are still queued.
     * - Unified height differences are informational (other channels may advance)
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

    // Opcode matching helpers (promoted from process_messages() lambdas so all on_* methods can use them)
    static bool matches_opcode(Packet const& packet, uint16_t legacy_opcode);
    static bool matches_stateless_opcode(Packet const& packet, uint16_t legacy_opcode);
    static bool requires_active_session_packet(Packet const& packet);

    // Called from process_messages() after the lane/validity guards pass
    void on_miner_auth_response(Packet const& packet, std::shared_ptr<network::Connection> connection);
    void on_session_expired(Packet const& packet, std::shared_ptr<network::Connection> connection);
    void on_block_accepted(Packet const& packet, std::shared_ptr<network::Connection> connection);
    void on_block_rejected(Packet const& packet, std::shared_ptr<network::Connection> connection);
    void on_block_data(Packet const& packet, std::shared_ptr<network::Connection> connection);
    void on_push_notification(Packet const& packet, std::shared_ptr<network::Connection> connection, uint32_t channel);
    void on_keepalive_ack(Packet const& packet, std::shared_ptr<network::Connection> connection);
    void on_ping_diag(Packet const& packet, std::shared_ptr<network::Connection> connection);
    void on_session_status_ack(Packet const& packet, std::shared_ptr<network::Connection> connection);
    void on_get_round_response(Packet const& packet, std::shared_ptr<network::Connection> connection);
    void on_stateless_get_block(Packet const& packet, std::shared_ptr<network::Connection> connection);

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

    // Block-result counters (Gap 3): incremented by BLOCK_ACCEPTED / BLOCK_REJECTED handlers.
    std::atomic<uint32_t> m_blocks_accepted{0};
    std::atomic<uint32_t> m_blocks_rejected{0};
    
    // Falcon miner authentication state (Phase 2)
    std::vector<uint8_t> m_miner_pubkey;
    std::vector<uint8_t> m_miner_privkey;
    bool m_authenticated;
    std::uint32_t m_session_id;
    uint64_t m_session_epoch{0};
    bool m_has_seen_session_epoch{false};
    std::shared_ptr<EpochCoordinator> m_epoch_coordinator;
    std::string m_address;  // Miner's network address for auth message
    std::uint64_t m_auth_timestamp;  // Timestamp for auth message
    AuthState m_auth_state;  // Authentication state machine
    std::chrono::steady_clock::time_point m_auth_in_flight_since{};  // When auth entered in-flight; default-constructed = not in-flight
    std::string m_miner_id;  // Miner identifier (optional)

    // Consecutive KEEPALIVE_V2_ACK session-ID mismatch counter.
    // Incremented each time handle_session_id_mismatch() detects a mismatch;
    // reset to zero on a successful (matching) ACK.  The session is only
    // self-expired once this reaches SESSION_MISMATCH_EXPIRE_THRESHOLD,
    // preventing premature expiry on late/replayed ACKs or node-side races.
    uint32_t m_session_id_mismatch_count{0};

    // Consecutive hashPrevBlock mismatch counter (chain-in-flux doom-loop guard).
    // Incremented each time validate_current_template() detects a hashPrevBlock mismatch
    // and would normally discard the template.  After MAX_CONSECUTIVE_HASHPREV_MISMATCHES
    // consecutive mismatches the template is accepted (not discarded) to prevent the
    // NO VALID TEMPLATE doom loop that occurs when the node is under attack or its chain
    // tip is churning rapidly (e.g. orphan limit exceeded by DDoS peer).
    // Reset to zero whenever a template is successfully validated and fed to workers.
    uint32_t m_hashprev_mismatch_consecutive{0};
    static constexpr uint32_t MAX_CONSECUTIVE_HASHPREV_MISMATCHES = 3;
    
    // Unified Falcon Signature Wrapper (Phase 2 enhancement)
    std::unique_ptr<FalconSignatureWrapper> m_falcon_wrapper;
    bool m_disposable_falcon_enabled;     // Disposable Falcon signing (ALWAYS ON - core protocol, 0 blockchain overhead)
    
    // ChaCha20 encryption wrapper for Falcon pubkey protection
    std::unique_ptr<ChaCha20Wrapper> m_chacha20_wrapper;
    bool m_enable_chacha20;  // ChaCha20 encryption (ALWAYS ON - core security for localhost + SessionID)

    // Session context for centralized session management (passed from NodeSession)
    // This is the authoritative source for session state shared across primary/secondary protocols
    std::shared_ptr<NodeSessionContext> m_session_context;

    // KEEPALIVE_V2 (0xD100) send-side tracking:
    // The lo32 of hashPrevBlock that the miner put in its last KEEPALIVE_V2 frame.
    // Stored locally so the ACK handler can compare against the node's echoed value
    // without trusting the potentially-tampered echo in ack.hashPrevBlock_lo32.
    uint32_t m_last_keepalive_prevhash_lo32{0};
    SessionOwnershipStamp m_last_keepalive_request_owner{};
    mutable SessionOwnershipStamp m_last_session_status_request_owner{};
    SessionOwnershipStamp m_last_reward_request_owner{};
    SessionOwnershipStamp m_last_get_block_request_owner{};
    SessionOwnershipStamp m_last_submitted_owner{};

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
    bool m_pending_push_after_auth{false};

    // Recovery callback — invoked when a push handler fires GET_BLOCK for a stale template
    // (channel_advanced staleness), signalling Worker_manager to enter recovery_pending state.
    Recovery_handler m_recovery_handler;

    // Session-expired callback — invoked when a keepalive ACK carries a mismatched session_id,
    // signalling Worker_manager to trigger recovery for the stale session.
    Session_expired_handler m_session_expired_handler;

    // Session-authenticated callback — invoked after MINER_AUTH_RESULT processing is complete.
    // Worker_manager uses this to check session_id=0 and trigger retry if needed.
    Session_authenticated_handler m_session_authenticated_handler;

    // Session-start callback — invoked when SESSION_START is received and keepalive interval
    // has been auto-adjusted from the node-advertised timeout.
    // Worker_manager uses this to cache the node-advertised interval for future connections.
    Session_start_handler m_session_start_handler;  // Notifies Worker_manager of node-advertised keepalive

    // Block-accepted callback — invoked on BLOCK_ACCEPTED to record the mined block.
    Block_accepted_handler m_block_accepted_handler;

    // Node-shutdown callback — invoked on NODE_SHUTDOWN (0xD0FF) to stop workers
    // and set reconnect backoff.
    Node_shutdown_handler m_node_shutdown_handler;

    // Last submitted block state — carried forward from submit_block() so the
    // ACCEPT/GOOD_BLOCK handler uses the actual submitted values rather than
    // re-reading from a potentially-replaced template (Priority 2 fix).
    bool      m_last_submitted_valid{false};
    uint64_t  m_last_submitted_nonce{0};
    uint1024_t m_last_submitted_prev_hash{0};
    uint32_t  m_last_submitted_height{0};
    uint32_t  m_last_submitted_channel{0};
    
    // GET_ROUND status tracking (Template Staleness Prevention - LLL-TAO PR #131)
    RoundStatus m_last_round_status;  // Last received round status
    // Dedicated dedup field: channel height from the last GET_ROUND response only.
    // Unlike m_last_round_status (updated by both NEW_ROUND and OLD_ROUND branches),
    // this field is updated at the END of on_get_round_response() after the dedup
    // decision, ensuring the NEW_ROUND dedup comparison is isolated from interleaved
    // OLD_ROUND/push-driven updates.
    uint32_t m_last_round_channel_height{0};
    
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

    // ── SESSION_STATUS_ACK tracking ─────────────────────────────────────────
    // Updated whenever SESSION_STATUS_ACK (0xD0DC / legacy 220) is received.
    ::LLP::SessionStatusAckFrame m_last_session_status_ack{};
    std::chrono::steady_clock::time_point m_last_session_status_ack_time{};

    // ── GET_BLOCK deduplication ──────────────────────────────────────────────
    // Height-based dedup: suppress GET_BLOCK only when the (unified_height,
    // channel_height) pair is identical to the last transmitted request.
    // This replaces the old 100ms time-based guard which incorrectly suppressed
    // retries during degraded-mode recovery when heights hadn't changed.
    // bypass_dedup (true during forced degraded-mode retries) skips this check.
    uint32_t m_last_get_block_unified_height{0};
    uint32_t m_last_get_block_channel_height{0};
    std::chrono::steady_clock::time_point m_last_get_block_transmitted_tp{};
    std::atomic<GetBlockRequestStatus> m_last_get_block_request_status{GetBlockRequestStatus::NONE};
    static constexpr int64_t GET_BLOCK_DEDUP_MS = 100;  // 100ms deduplication window (retained for rapid-burst guard)
    
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
