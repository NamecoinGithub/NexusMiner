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

#include <memory>
#include <deque>

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

    /// Open the secondary SIM Link connection in the background.
    /// Should be called after the primary connect() succeeds and SIM Link is enabled.
    bool connect_secondary(network::Endpoint const& secondary_endpoint);

    // stop the component and destroy all workers
    void stop();
    
    // Worker control methods for degraded mode (public for timer access)
    void check_template_health();

    // SIM Link: log the current state of both lanes (called by lane health-check timer)
    void log_lane_health();

private:

    void process_data(network::Shared_payload&& receive_buffer);
    void process_secondary_data(network::Shared_payload&& receive_buffer);

    void create_stats_printers();
    void create_workers();
    
    // Worker control methods for degraded mode
    void stop_all_workers();
    /**
     * @param bForce When true, bypasses the was_push_received_recently() guard.
     *               Pass true from staleness recovery paths where the template
     *               has already been discarded and workers stopped.
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
    void retry_secondary_connect(network::Endpoint const& secondary_endpoint);

    /// Submit a found block: try primary lane first, fallback to secondary within 100 ms.
    void submit_solution(const std::vector<uint8_t>& full_block_bytes, uint64_t nNonce);

	std::shared_ptr<::asio::io_context> m_io_context;
    Config& m_config;
	network::Socket::Sptr m_socket;
	network::Connection::Sptr m_connection;
    std::shared_ptr<spdlog::logger> m_logger;
    std::shared_ptr<stats::Collector> m_stats_collector;
    Timer_manager m_timer_manager;
    std::shared_ptr<protocol::Protocol> m_miner_protocol;
    
    // Degraded mode flag - set when mining is stopped due to invalid template
    bool m_degraded_mode;

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

    // Time of the most recent GET_BLOCK sent by the health monitor during this
    // recovery epoch.  Used to rate-limit health-monitor resends to one per
    // RECOVERY_RESEND_INTERVAL (10 s) without stopping workers each time.
    std::chrono::steady_clock::time_point m_recovery_last_get_block_sent_at{};

    // Time of the most recent escalation (epoch N → epoch N+1: stop workers + hard recovery).
    // Used to prevent re-escalation within MIN_ESCALATION_INTERVAL_SECONDS of the previous
    // escalation, giving the new GET_BLOCK time to be answered before workers are stopped again.
    std::chrono::steady_clock::time_point m_last_escalation_at{};
    
    // Persistent receive accumulator for TCP stream reassembly
    // Using deque for O(1) front removal when consuming packets
    std::deque<uint8_t> m_rx_accumulator;

    // Connection retry state for exponential backoff
    uint32_t m_connection_retry_count{0};
    uint32_t m_current_retry_delay_seconds{0};  // 0 = use config default on first retry

    std::vector<std::shared_ptr<stats::Printer>> m_stats_printers;
    std::vector<std::shared_ptr<Worker>> m_workers;

    // ── SIM Link: secondary lane (port derived from primary) ─────────────────
    network::Connection::Sptr m_secondary_connection;
    std::shared_ptr<protocol::Protocol> m_secondary_protocol;
    std::deque<uint8_t> m_secondary_rx_accumulator;
    uint32_t m_secondary_retry_count{0};
    uint32_t m_secondary_retry_delay_seconds{0};
    DualConnectionManager m_sim_link;  // Lane state bookkeeper
    std::shared_ptr<ColinAgent> m_colin_agent;  // Diagnostic agent (started after first connect)
};
}

#endif
