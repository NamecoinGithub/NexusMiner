#ifndef NEXUSMINER_WORKER_MANAGER_HPP
#define NEXUSMINER_WORKER_MANAGER_HPP

#include "network/connection.hpp"
#include "network/socket.hpp"
#include "network/types.hpp"
#include <spdlog/spdlog.h>
#include "chrono/timer_factory.hpp"
#include "timer_manager.hpp"
#include "stats/stats_printer.hpp"
#include "dual_connection_manager.hpp"
#include "LLC/types/uint1024.h"
#include "stats/mined_block_cache.hpp"
#include "Util/include/exponential_backoff.h"
#include "protocol/inc/protocol/protocol_constants.hpp"
#include "protocol/inc/protocol/epoch_coordinator.hpp"
#include "protocol/inc/protocol/get_block_reason.hpp"
#include "node_session/inc/node_session/node_session.hpp"
#include <asio/steady_timer.hpp>

#include <memory>
#include <mutex>
#include <atomic>
#include <chrono>

namespace asio { class io_context; }

namespace nexusminer 
{
namespace config { class Config; }
namespace stats { class Collector; }
namespace protocol { class Protocol; class Solo; }
class Worker;
class ColinAgent;

// ─────────────────────────────────────────────────────────────────────────────
// ⚡ Explicit Recovery State Machine
// ─────────────────────────────────────────────────────────────────────────────
// Replaces 15 independent boolean/timestamp fields that could combine into 32+
// undefined configurations.  Exactly one phase is active at any moment.
// ─────────────────────────────────────────────────────────────────────────────
enum class RecoveryPhase : uint8_t {
    HEALTHY,          // Mining normally
    WAITING_TEMPLATE, // Waiting for new template; workers keep running
    SESSION_RECOVERY, // Authoritative session restoration / re-auth in progress
    RECONNECTING,     // TCP reconnect in progress
    DEGRADED_MODE,    // Terminal full-stop (signal-driven shutdown path)
};

struct RecoveryContext {
    // Thread safety: phase and degraded_signal may be read from protocol
    // callback threads while written from the I/O thread.  Use std::atomic
    // to avoid data races without adding mutex overhead that could block
    // recovery paths.
    std::atomic<RecoveryPhase> phase{RecoveryPhase::HEALTHY};

    // Tracks the authoritative session-restoration window.  Used so
    // SESSION_EXPIRED can preempt template-only recovery but still avoid
    // re-entrance while full session restoration is already underway.
    std::atomic<bool> recovery_in_progress{false};

    std::chrono::steady_clock::time_point entered_at{};            // When current epoch (recovery start) began
    std::chrono::steady_clock::time_point degraded_since{};        // When current outage started (set once per outage)
    std::chrono::steady_clock::time_point last_get_block_at{};     // Last confirmed GET_BLOCK transmit
    std::chrono::steady_clock::time_point last_completed_at{};     // When last recovery finished (hold-off)
    bool get_block_confirmed{false};                               // At least one GET_BLOCK confirmed this epoch
    const char* reason{nullptr};                                   // Why this phase was entered (for logging)

    // ── Reconnect sub-state (only valid when phase == RECONNECTING) ──────────
    std::chrono::steady_clock::time_point reconnect_started_at{};
    std::atomic<int> degraded_signal{0};

};

class Worker_manager : public std::enable_shared_from_this<Worker_manager>
{
public:

    using Config = config::Config;

    Worker_manager(std::shared_ptr<asio::io_context> io_context, Config& config, 
        chrono::Timer_factory::Sptr timer_factory, network::Socket::Sptr socket);

    bool connect(network::Endpoint const& wallet_endpoint);

    // stop the component and destroy all workers
    void stop();
    void enter_terminal_degraded_mode(int signal_number);
    
    // Worker control methods for degraded mode (public for timer access)
    void check_template_health();

    // SIM Link: log the current state of both lanes (called by lane health-check timer)
    void log_lane_health();

    // SIM Link: send SESSION_STATUS on each live lane if 300-second interval has elapsed
    void send_session_status_if_due();

    // GET_ROUND polling: called by Timer_manager on every tick (1s).
    // Fetches the current connection and protocol from NodeSession, avoiding
    // stale weak_ptr captures that killed the timer after reconnection.
    void poll_get_round();

    /// Session generation: monotonically increasing counter that increments on
    /// every session transition.  Timer callbacks capture this at entry to detect
    /// stale-session dispatches mid-flight.
    uint64_t session_generation() const { return m_session_generation.load(std::memory_order_acquire); }

    // ── Failover state accessor ────────────────────────────────────────────────
    struct FailoverStatus {
        bool has_failover_configured{false};
        bool using_failover{false};
        uint32_t primary_fail_count{0};
        uint32_t failover_max_retries{0};
        std::string primary_endpoint_str;   // e.g. "192.168.1.10:9323"
        std::string failover_endpoint_str;  // e.g. "192.168.1.11:9323" or ""
        std::chrono::steady_clock::time_point failover_activated_at{};
    };
    FailoverStatus get_failover_status() const;

private:

    void schedule_forced_recovery_retry(const char* trigger_reason);
    int64_t next_forced_retry_jitter_ms();
    bool has_valid_template_available(const std::shared_ptr<protocol::Solo>& solo_protocol) const;

    void create_stats_printers();
    void create_workers();
    void create_workers_locked();

    /// Log the three-tier mined-block cache summary.
    void log_mined_block_cache() const;
    
    // Worker control methods for degraded mode
    void stop_all_workers();
    /**
     * @param reason Semantic reason for the GET_BLOCK request.
     *               The dedup bypass policy is derived from the reason via
     *               should_bypass_height_dedup() / should_bypass_all_dedup()
     *               in get_block_reason.hpp.
     *               This helper is request-only: it does not mutate recovery state
     *               or reconnect.
     */
    void retry_template_request(protocol::GetBlockReason reason);
    void restart_recovery_window(const char* reason);

    /// Mark that a hard GET_BLOCK recovery is now in progress.
    /// Sets m_recovery.phase=WAITING_TEMPLATE, increments epoch, records start time.
    /// Called from:
    ///  - the recovery_handler callback (push handler detected channel-stale staleness),
    ///  - retry_template_request(GetBlockReason) (health monitor or validation failure path).
    void mark_recovery_initiated(const char* reason);

    /// Mark that a template-only refresh is now in progress.
    /// WAITING_TEMPLATE is reserved for "session alive, waiting for fresh work".
    /// Workers keep running; no submissions are withheld in the current model.
    void mark_soft_refresh_requested(const char* reason);

    /// Clear degraded mode and all recovery state after a valid template is delivered to workers.
    /// Called from the template feed handler when workers_fed > 0, and as a belt-and-suspenders
    /// guard from check_template_health() when a valid template exists but is_degraded() is set.
    void clear_recovery_state();

    void retry_connect(network::Endpoint const& wallet_endpoint);

    // ── State machine transition API ───────────────────────────────────────────
    /// Transition to a new RecoveryPhase.  Logs the transition, validates legality
    /// (in debug builds: asserts; in release: logs error and returns without change),
    /// runs on_phase_exit() for the old phase and on_phase_enter() for the new one.
    void transition_to(RecoveryPhase new_phase, const char* reason = nullptr);
    static bool is_valid_transition(RecoveryPhase from, RecoveryPhase to);
    void on_phase_enter(RecoveryPhase phase);
    void on_phase_exit(RecoveryPhase phase);
    static const char* phase_name(RecoveryPhase phase);
    bool should_reset_stats_on_recovery_completion() const;
    void mark_recovery_completion_kind_template_refresh();

    enum class RecoveryCompletionKind : uint8_t {
        NONE,
        TEMPLATE_REFRESH,
        PRIMARY_SESSION_REAUTH,
        TRANSPORT_RECONNECT,
        FAILOVER_SESSION
    };

    // ── State query helpers (backward-compat convenience) ─────────────────────
    bool is_degraded()              const { return m_recovery.phase.load(std::memory_order_relaxed) == RecoveryPhase::WAITING_TEMPLATE; }
    bool is_submissions_withheld()  const { return false; }  // Backward-compat stub — no submission withholding in current model
    bool is_recovery_active()       const { return m_recovery.phase.load(std::memory_order_relaxed) != RecoveryPhase::HEALTHY; }
    bool is_session_recovery()      const { return m_recovery.phase.load(std::memory_order_relaxed) == RecoveryPhase::SESSION_RECOVERY; }
    bool is_reconnecting()          const { return m_recovery.phase.load(std::memory_order_relaxed) == RecoveryPhase::RECONNECTING; }

    /// Submit a found block via primary NodeSession (handles dual-lane submission internally).
    void submit_solution(const std::vector<uint8_t>& full_block_bytes, uint64_t nNonce);

	std::shared_ptr<::asio::io_context> m_io_context;
    Config& m_config;
	network::Socket::Sptr m_socket;
    std::shared_ptr<spdlog::logger> m_logger;
    std::shared_ptr<stats::Collector> m_stats_collector;
    Timer_manager m_timer_manager;

    // Primary NodeSession (replaces m_connection + m_miner_protocol + m_secondary_connection + m_secondary_protocol)
    std::shared_ptr<NodeSession> m_primary_node_session;

    // Failover NodeSession (optional secondary node)
    std::shared_ptr<NodeSession> m_failover_node_session;

    // ── Recovery state machine ────────────────────────────────────────────────
    // Single authoritative RecoveryContext replaces 15 independent boolean/timestamp
    // fields that could combine into 32+ undefined configurations.
    RecoveryContext m_recovery;

    // Single source of truth for all epoch counters (session_epoch + recovery_epoch).
    std::shared_ptr<protocol::EpochCoordinator> m_epoch_coordinator;

    // Forced-retry timer state (not part of RecoveryContext — timer handle is not copyable)
    std::shared_ptr<asio::steady_timer> m_forced_retry_timer{};
    bool m_forced_retry_timer_pending{false};
    uint64_t m_forced_retry_timer_token{0};
    uint64_t m_get_block_sent_total{0};
    uint64_t m_get_block_forced_retry_total{0};
    uint64_t m_degraded_enter_total{0};
    uint64_t m_degraded_exit_total{0};
    uint64_t m_time_in_degraded_ms{0};

    // Bug 5 fix: Track last GET_BLOCK request time to prevent burst duplicate
    // requests from forced retry timer (100-250ms) and health monitor (5s cycle)
    // both firing within the same short window.
    std::chrono::steady_clock::time_point m_last_get_block_request_time{};

    // Session health summary log: throttled to once per 60s
    std::chrono::steady_clock::time_point m_last_session_health_log{};

    // Connection retry state for exponential backoff
    uint32_t m_connection_retry_count{0};
    util::ExponentialBackoffWithState m_connection_backoff{
        0,  // Base delay is set dynamically from config in retry_connect()
        protocol::ProtocolConstants::MAX_RETRY_DELAY_SECONDS
    };

    // ── Session authentication retry state (infinite loop prevention) ─────────
    uint32_t m_session_auth_fail_count{0};          // consecutive session_id=0 failures on primary

    // Exponential backoff calculator for session authentication retries
    util::ExponentialBackoff m_session_auth_backoff{
        protocol::ProtocolConstants::BASE_SESSION_RETRY_MS,
        protocol::ProtocolConstants::MAX_SESSION_RETRY_MS
    };

    // ── Session generation counter ──────────────────────────────────────────
    // Monotonically increasing counter that increments on every session
    // transition (connect, disconnect, re-auth, session expired).  Timer
    // callbacks (GET_ROUND, template health, lane health) capture the
    // generation at entry and abort if it changed mid-flight — preventing
    // wasted packets during session transitions that the node would reject.
    //
    // This mirrors SessionManager::m_keepalive_generation (which guards the
    // keepalive timer) but at the Worker_manager level for the Timer_manager-
    // owned timers.
    std::atomic<uint64_t> m_session_generation{0};

    // ── Timer guards: start timers once only ────────────────────────────────
    // All timers use weak_ptr<Worker_manager> (which persists for application
    // lifetime) so they survive connection replacements.  GET_ROUND timer
    // fetches the current connection on every tick via poll_get_round().
    bool m_stats_timers_started{false};
    bool m_template_health_timer_started{false};
    bool m_get_round_timer_started{false};
    bool m_lane_health_timer_started{false};

    // ── Failover state ────────────────────────────────────────────────────────
    network::Endpoint m_primary_endpoint;      // saved on first connect()
    network::Endpoint m_failover_endpoint;     // built from config if has_failover()
    bool              m_using_failover{false}; // currently retrying on failover?
    uint32_t          m_primary_fail_count{0}; // consecutive failures on the active side
    std::chrono::steady_clock::time_point m_failover_activated_at{}; // when failover last became active

    // Node-advertised keepalive interval (hours), updated from SESSION_START on primary lane.
    // Used to seed secondary/failover Solo instances instead of the static config value.
    // Atomic to allow concurrent access from primary and secondary SESSION_START handlers.
    std::atomic<uint16_t> m_node_keepalive_interval_hours{0};  // 0 = not yet received; fall back to config value

    // Returns the best known keepalive interval: node-advertised if received, else config default.
    uint16_t get_effective_keepalive_interval() const;

    // Time of the most recent escalation (epoch N → epoch N+1: stop workers + hard recovery).
    std::vector<std::shared_ptr<stats::Printer>> m_stats_printers;
    std::vector<std::shared_ptr<Worker>> m_workers;

    // ── Lane Health Monitor and diagnostic tools ────────────────────────────
    DualConnectionManager m_sim_link;  // Lane state bookkeeper (SIM Link removed; lane monitor only)
    std::shared_ptr<ColinAgent> m_colin_agent;  // Diagnostic agent (started after first connect)

    // Time of the most recent SESSION_STATUS sent on any lane.
    // Used to gate send_session_status_if_due() to at most once per 60 seconds.
    std::chrono::steady_clock::time_point m_last_session_status_sent{};

    // ── Reorg Resubscription Guard ────────────────────────────────────────────
    // Tracks the last time MINER_READY was re-sent during active recovery to
    // restore push-notification subscription after a reorg-triggered disconnect.
    // Prevents rapid-fire resubscription; see check_template_health().
    std::chrono::steady_clock::time_point m_last_resubscribe_at{};  ///< Last MINER_READY resubscription sent (reorg guard)

    // ── GET_BLOCK exponential backoff (hashPrevBlock mismatch storm guard) ────
    // When validate_current_template() triggers a hashPrevBlock_mismatch_reorg discard
    // and immediately requests a new GET_BLOCK, a node under DDoS or orphan-limit
    // pressure may return stale/inconsistent BLOCK_DATA, re-triggering the discard
    // in a tight loop.  This backoff introduces a brief delay that grows exponentially
    // (0 ms → 2 s → 4 s → … → 30 s max) after each successive discard-and-retry,
    // and resets when a template is successfully adopted.
    // m_get_block_backoff_ms: current backoff delay in milliseconds (0 = no delay)
    // m_get_block_backoff_until: time before which the next GET_BLOCK is suppressed
    int64_t m_get_block_backoff_ms{0};
    std::chrono::steady_clock::time_point m_get_block_backoff_until{};
    static constexpr int64_t GET_BLOCK_BACKOFF_INITIAL_MS   = 2000;   ///< First backoff step: 2 s
    static constexpr int64_t GET_BLOCK_BACKOFF_MAX_MS       = 30000;  ///< Ceiling: 30 s

    // ── Template age request cooldown ────────────────────────────────────────
    // Prevents the health timer from sending TEMPLATE_AGE_WARNING/EMERGENCY
    // GET_BLOCK requests on every 5-second tick once the template exceeds the
    // age threshold.  Only one request per TEMPLATE_AGE_COOLDOWN_SECONDS.
    std::chrono::steady_clock::time_point m_last_template_age_request_at{};
    static constexpr int64_t TEMPLATE_AGE_COOLDOWN_SECONDS = 30;

    // ── Mutex-based recovery gate (defense-in-depth) ─────────────────────────
    // Serialises the creation path in set_block_handler with the destruction
    // path in stop_all_workers() so they cannot interleave on m_workers.
    std::mutex m_worker_mutex;

    // Per-epoch idempotency key: set after create_workers() succeeds in the
    // degraded-mode guard; checked before every subsequent creation attempt.
    // Reset in stop_all_workers() and clear_recovery_state().
    bool m_recovery_workers_spawned{false};
    RecoveryCompletionKind m_pending_recovery_completion_kind{RecoveryCompletionKind::NONE};

    // ── Three-tier mined-block confirmation cache ────────────────────────────
    // Tier 1: last 5 mined blocks (confirmation tracking active)
    // Tier 2: up to 100 confirmed blocks (hashPrevBlock + nHeight + channel)
    // Tier 3: archive overflow from Tier 2
    stats::MinedBlockCache m_mined_block_cache;
};
}

#endif
