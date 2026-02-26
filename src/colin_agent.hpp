#ifndef NEXUSMINER_COLIN_AGENT_HPP
#define NEXUSMINER_COLIN_AGENT_HPP

/**
 * @brief Colin — the NexusMiner AI Diagnostic Agent
 *
 * Colin monitors both SIM Link connections, block submission results,
 * template age, and HeightTracker state, then emits structured
 * diagnostic summaries to help operators quickly identify issues.
 *
 * Name: Colin (Context-Oriented LLP Intelligence Node)
 * Runs as a periodic background task on the io_context.
 */

#include "dual_connection_manager.hpp"
#include "stats/stats_collector.hpp"
#include "LLP/include/colin_ping_protocol.h"

#include <asio/steady_timer.hpp>
#include <spdlog/spdlog.h>

#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace asio { class io_context; }

namespace nexusminer
{

class ColinAgent
{
public:
    /// @param io_context   Shared event loop (runs on same thread as connections).
    /// @param dcm          Raw pointer to the DualConnectionManager owned by Worker_manager.
    ///                     Lifetime must exceed ColinAgent's.
    /// @param stats        Shared stats collector used by workers.
    /// @param logger       Shared spdlog logger.
    /// @param report_interval_seconds  Diagnostic report cadence (default: 60 s).
    ColinAgent(
        std::shared_ptr<asio::io_context> io_context,
        const DualConnectionManager* dcm,
        std::shared_ptr<stats::Collector> stats,
        std::shared_ptr<spdlog::logger> logger,
        uint32_t report_interval_seconds = 60);

    void start();
    void stop();

    // ── Colin AI Node Diagnostic Ping Source ──────────────────────────────
    // Optional callback that returns the last received PING_DIAG frame.
    // Set by Worker_manager after the Solo protocol is established so that
    // emit_report() can display the latest node-side diagnostic data.
    using PingSource = std::function<::LLP::ReceivedPingFrame()>;
    void set_ping_source(PingSource fn) { m_ping_source = std::move(fn); }

    // ── Warning catalog ────────────────────────────────────────────────────
    // Returns a non-empty string if the pattern matches, empty string otherwise.
    // Used by tests to verify each warning pattern triggers the right text.
    static std::string check_base_not_prime(const std::string& log_line);
    static std::string check_malformed_packet(const std::string& log_line);
    static std::string check_block_rejected_none(const std::string& log_line);
    static std::string check_no_offsets_found(const std::string& log_line);
    static std::string check_connection_retries(uint32_t retry_count);
    static std::string check_template_age(uint64_t age_seconds);
    static std::string check_mining_stopped(bool degraded_mode);

private:
    void schedule_next();
    void run_diagnostics();

    std::string assess_primary_lane() const;
    std::string assess_secondary_lane() const;
    void emit_report(const std::vector<std::string>& warnings,
                     const std::vector<std::string>& recommendations,
                     const stats::Global& gs);

    struct DiagSnapshot
    {
        uint32_t blocks_accepted{0};
        uint32_t blocks_rejected{0};
        uint32_t connection_retries{0};
        std::chrono::steady_clock::time_point timestamp{};
    };

    std::shared_ptr<asio::io_context> m_io_context;
    const DualConnectionManager* m_dcm;
    std::shared_ptr<stats::Collector> m_stats;
    std::shared_ptr<spdlog::logger> m_logger;
    uint32_t m_interval_s;
    asio::steady_timer m_timer;
    bool m_running{false};

    PingSource m_ping_source;  // Optional: supplies last ReceivedPingFrame for the report

    std::deque<DiagSnapshot> m_history; // last 10 snapshots
};

} // namespace nexusminer

#endif // NEXUSMINER_COLIN_AGENT_HPP
