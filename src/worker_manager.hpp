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
#include "node_session/inc/node_session/node_session.hpp"

#include <memory>
#include <deque>
#include <mutex>
#include <atomic>

namespace asio { class io_context; }

namespace nexusminer 
{
namespace config { class Config; }
namespace stats { class Collector; }
namespace protocol { class Protocol; class Solo; }
class Worker;
class ColinAgent;

class Worker_manager : public std::enable_shared_from_this<Worker_manager>
{
public:

    using Config = config::Config;

    Worker_manager(std::shared_ptr<asio::io_context> io_context, Config& config, 
        chrono::Timer_factory::Sptr timer_factory, network::Socket::Sptr socket);

    bool connect(network::Endpoint const& wallet_endpoint);

    // stop the component and destroy all workers
    void stop();
    
    // Worker control methods for degraded mode (public for timer access)
    void check_template_health();

    // SIM Link: log the current state of both lanes (called by lane health-check timer)
    void log_lane_health();

    // SIM Link: send SESSION_STATUS on each live lane if 60-second interval has elapsed
    void send_session_status_if_due();

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

    void create_stats_printers();
    void create_workers();

    /// Log the three-tier mined-block cache summary.
    void log_mined_block_cache() const;
    
    // Worker control methods for degraded mode
    void stop_all_workers();
    /**
     * @param bForce When true, marks a new recovery epoch so check_template_health()
     *               knows recovery is pending. Pass true from staleness recovery paths
     *               where the template has already been discarded and workers stopped.
     *               Pass false (default) from the periodic health-check timer.
     */
    void retry_template_request(bool bForce = false);

    /// Mark that a GET_BLOCK recovery is now in progress.
    /// Sets m_recovery_pending, increments m_recovery_epoch, records start time.
    /// Called from:
    ///  - the recovery_handler callback (push handler detected channel-stale staleness),
    ///  - retry_template_request(true) (health monitor or validation failure path).
    void mark_recovery_initiated(const char* reason);

    /// Clear degraded mode and all recovery state after a valid template is delivered to workers.
    /// Called from the template feed handler when workers_fed > 0, and as a belt-and-suspenders
    /// guard from check_template_health() when a valid template exists but m_degraded_mode is set.
    void clear_recovery_state();

    void retry_connect(network::Endpoint const& wallet_endpoint);

    /// Submit a found block: try primary lane first, fallback to secondary within 100 ms.
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
    
    // Degraded mode flag - set when mining is stopped due to invalid template
    bool m_degraded_mode;

    // Soft-pause flag (Priority 1 — "Pause not Destroy" for Prime recovery):
    // When true, workers keep running their sieve but block submissions are
    // suppressed.  Set on push_staleness instead of calling stop_all_workers().
    // Cleared when a fresh template arrives.  Only escalated to full worker stop
    // if the recovery window expires without a fresh template.
    bool m_template_withheld{false};

    // ── Recovery state (doom-loop prevention) ────────────────────────────────
    // Set when a channel-stale GET_BLOCK recovery has been initiated (from push
    // handler or health monitor) and no fresh template has arrived yet.
    // Prevents check_template_health() from calling stop_all_workers()
    // redundantly during the recovery window while awaiting the GET_BLOCK reply.
    bool m_recovery_pending{false};

    // Monotonically increasing counter: incremented each time a new recovery is
    // initiated.  Allows per-epoch bypass tracking (one GET_BLOCK forced send per
    // recovery epoch without triggering node-side rate-limit bans).
    uint64_t m_recovery_epoch{0};

    // Wall-clock time when the current recovery epoch started.
    // Recovery window = 60 s; if no template arrives within that window the
    // health monitor escalates (stop workers → hard recovery).
    std::chrono::steady_clock::time_point m_recovery_started_at{};

    // Time when degraded mode was first entered in the current outage.
    // Set once by stop_all_workers() (first entry only); cleared by clear_recovery_state().
    // Used by the escape ladder in check_template_health() to enforce hard time-based
    // stage escalation (Stage 1 / Stage 2 / Stage 3 / hard limit).
    std::chrono::steady_clock::time_point m_degraded_since{};

    // Time of the most recent GET_BLOCK sent by the health monitor during this
    // recovery epoch.  Used to rate-limit health-monitor resends to one per
    // RECOVERY_RESEND_INTERVAL (10 s) without stopping workers each time.
    std::chrono::steady_clock::time_point m_recovery_last_get_block_sent_at{};

    // Time of the most recent GET_BLOCK that was CONFIRMED transmitted (payload was
    // non-null and non-empty, and transmit() was called).  Unlike the legacy
    // m_recovery_last_get_block_sent_at, this is never updated for rate-limited attempts.
    // Used as the authoritative rate-cap reference in check_template_health().
    std::chrono::steady_clock::time_point m_recovery_last_get_block_transmitted_at{};

    // True once at least one GET_BLOCK has been CONFIRMED transmitted in the current
    // recovery epoch.  Reset to false at the start of each new recovery epoch.
    // Used by check_template_health() to detect the doom-loop symptom where every
    // GET_BLOCK attempt is rate-limited and the node never receives the request.
    bool m_recovery_get_block_transmitted{false};

    // Connection retry state for exponential backoff
    uint32_t m_connection_retry_count{0};
    util::ExponentialBackoffWithState m_connection_backoff{
        0,  // Base delay is set dynamically from config in retry_connect()
        protocol::ProtocolConstants::MAX_RETRY_DELAY_SECONDS
    };

    // ── Reconnect guard (belt-and-suspenders race prevention) ────────────────
    // Set to true at the start of retry_connect(), cleared when new connection is authenticated.
    // Guards against processing stale callbacks during reconnect window.
    bool m_reconnect_in_progress{false};

    // Track when retry_connect() set m_reconnect_in_progress = true.
    // Used by check_template_health() to timeout a stalled reconnect attempt.
    std::chrono::steady_clock::time_point m_reconnect_started_at{};

    // ── Session authentication retry state (infinite loop prevention) ─────────
    uint32_t m_session_auth_fail_count{0};          // consecutive session_id=0 failures on primary

    // Exponential backoff calculator for session authentication retries
    util::ExponentialBackoff m_session_auth_backoff{
        protocol::ProtocolConstants::BASE_SESSION_RETRY_MS,
        protocol::ProtocolConstants::MAX_SESSION_RETRY_MS
    };

    // ── Timer guards: start timers once only (prevent restart on reconnect) ───
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
    // Used to prevent re-escalation within MIN_ESCALATION_INTERVAL_SECONDS of the previous
    // escalation, giving the new GET_BLOCK time to be answered before workers are stopped again.
    std::chrono::steady_clock::time_point m_last_escalation_at{};

    std::vector<std::shared_ptr<stats::Printer>> m_stats_printers;
    std::vector<std::shared_ptr<Worker>> m_workers;

    // ── SIM Link and diagnostic tools ─────────────────────────────────────────
    DualConnectionManager m_sim_link;  // Lane state bookkeeper
    std::shared_ptr<ColinAgent> m_colin_agent;  // Diagnostic agent (started after first connect)

    // Time of the most recent SESSION_STATUS sent on any lane.
    // Used to gate send_session_status_if_due() to at most once per 60 seconds.
    std::chrono::steady_clock::time_point m_last_session_status_sent{};

    // ── Mutex-based recovery gate (defense-in-depth) ─────────────────────────
    // Serialises the creation path in set_block_handler with the destruction
    // path in stop_all_workers() so they cannot interleave on m_workers.
    std::mutex m_worker_mutex;

    // Per-epoch idempotency key: set after create_workers() succeeds in the
    // degraded-mode guard; checked before every subsequent creation attempt.
    // Reset in stop_all_workers() and clear_recovery_state().
    bool m_recovery_workers_spawned{false};

    // ── Three-tier mined-block confirmation cache ────────────────────────────
    // Tier 1: last 5 mined blocks (confirmation tracking active)
    // Tier 2: up to 100 confirmed blocks (hashPrevBlock + nHeight + channel)
    // Tier 3: archive overflow from Tier 2
    stats::MinedBlockCache m_mined_block_cache;
};
}

#endif
