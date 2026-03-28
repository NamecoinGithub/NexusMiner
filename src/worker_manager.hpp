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
#include "recovery_state_machine.hpp"
#include "LLC/types/uint1024.h"
#include "stats/mined_block_cache.hpp"
#include "Util/include/exponential_backoff.h"
#include "protocol/inc/protocol/protocol_constants.hpp"
#include "protocol/inc/protocol/session_coordinator.hpp"
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

    // SIM Link: send SESSION_STATUS on each live lane if 300-second interval has elapsed
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
     * @param bForce When true, marks a new recovery epoch so check_template_health()
     *               knows recovery is pending. Pass true from staleness recovery paths
     *               where the template has already been discarded and workers stopped.
     *               Pass false (default) from the periodic health-check timer.
     */
    void retry_template_request(bool bForce = false);
    void restart_recovery_window(const char* reason);

    /// Mark that a hard GET_BLOCK recovery is now in progress.
    void mark_recovery_initiated(const char* reason);

    /// Mark that a soft refresh is now in progress.
    void mark_soft_refresh_requested(const char* reason);

    /// Clear degraded mode and all recovery state after a valid template is delivered to workers.
    void clear_recovery_state();

    void retry_connect(network::Endpoint const& wallet_endpoint);

    // ── State query helpers (delegates to m_recovery_sm) ─────────────────────
    bool is_degraded()              const { return m_recovery_sm.is_degraded(); }
    bool is_submissions_withheld()  const { return m_recovery_sm.is_submissions_withheld(); }
    bool is_recovery_active()       const { return m_recovery_sm.is_recovery_active(); }
    bool is_reconnecting()          const { return m_recovery_sm.is_reconnecting(); }

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

    // Shared SessionCoordinator — single source of truth for session_epoch, recovery_epoch,
    // session_id, authenticated, and reward_bound.  Created in connect() and threaded
    // through all NodeSession/Solo instances so every component reads the same values.
    std::shared_ptr<protocol::SessionCoordinator> m_coordinator;

    // ── Recovery state machine ────────────────────────────────────────────────
    // Self-contained state machine replaces the old embedded RecoveryContext
    // and counter/token fields.  Worker_manager delegates all phase transition
    // logic through m_recovery_sm.
    RecoveryStateMachine m_recovery_sm;

    // Forced-retry timer handle (IO object — not owned by the state machine)
    std::shared_ptr<asio::steady_timer> m_forced_retry_timer{};
    uint64_t m_get_block_sent_total{0};
    uint64_t m_get_block_forced_retry_total{0};

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

    // ── Timer guards: start timers once per connect/stop cycle (reset in stop()) ──
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

    // ── SIM Link and diagnostic tools ─────────────────────────────────────────
    DualConnectionManager m_sim_link;  // Lane state bookkeeper
    std::shared_ptr<ColinAgent> m_colin_agent;  // Diagnostic agent (started after first connect)

    // Time of the most recent SESSION_STATUS sent on any lane.
    // Used to gate send_session_status_if_due() to at most once per 60 seconds.
    std::chrono::steady_clock::time_point m_last_session_status_sent{};

    // ── Reorg Resubscription Guard ────────────────────────────────────────────
    // Tracks the last time MINER_READY was re-sent during active recovery to
    // restore push-notification subscription after a reorg-triggered disconnect.
    // Prevents rapid-fire resubscription; see check_template_health().
    std::chrono::steady_clock::time_point m_last_resubscribe_at{};  ///< Last MINER_READY resubscription sent (reorg guard)

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
