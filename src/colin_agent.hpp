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
#include "protocol/height_tracker.hpp"

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

    // ── SESSION_STATUS_ACK Source ──────────────────────────────────────────
    // Optional callback returning the last received SESSION_STATUS_ACK frame
    // and the time it was received.  Set by Worker_manager after the Solo
    // protocol is established so emit_report() can display node lane health.
    using StatusSource = std::function<std::pair<::LLP::SessionStatusAckFrame,
                                                 std::chrono::steady_clock::time_point>()>;
    void set_status_source(StatusSource fn) { m_status_source = std::move(fn); }

    // ── HeightTracker ─────────────────────────────────────────────────────
    // Optional pointer to the HeightTracker owned by Solo.  Set by
    // Worker_manager after the Solo protocol is established.  When set,
    // emit_report() logs all four channel heights and the fork-score canary.
    void set_height_tracker(const nexusminer::protocol::HeightTracker* ht) { m_height_tracker = ht; }

    // ── MiningTemplateInterface Source ────────────────────────────────────
    // Optional: supplies a snapshot of the current template state for the report.
    // The snapshot copies only the fields needed — no mutable pointer escapes.
    struct TemplateSnapshot {
        bool     has_valid_template{false};
        uint32_t unified_height{0};       // block.nHeight — canonical unified height (for ProofHash)
        uint32_t nBits{0};                // compact difficulty from block header
        uint32_t channel_height{0};       // nChannelHeight — staleness metadata only, NOT in ProofHash
        uint32_t channel{0};              // 1=Prime, 2=Hash
        uint64_t age_seconds{0};          // seconds since template was received
        const char* state_name{nullptr};  // MiningTemplateInterface::state_to_string(state)
        // TemplateStats lifetime counters
        uint64_t templates_received{0};
        uint64_t templates_validated{0};
        uint64_t templates_rejected{0};
        uint64_t templates_stale{0};
        uint64_t templates_fed{0};
        uint64_t templates_expired_age{0};
        uint64_t templates_expired_height{0};
    };
    using TemplateSource = std::function<TemplateSnapshot()>;
    void set_template_source(TemplateSource fn) { m_template_source = std::move(fn); }

    // ── ColinPingHandler Telemetry Source ─────────────────────────────────
    // Optional: supplies the last PONG telemetry built by ColinPingHandler
    // (ping-count, RTT, hash-rate kH/s, temp, thread count, queue depth, health flags).
    struct PongTelemetrySnapshot {
        uint64_t ping_count{0};
        uint64_t last_rtt_us{0};
        uint32_t hash_rate_khs{0};
        uint32_t temp_cdeg{0};
        uint32_t thread_count{0};
        uint32_t queue_depth{0};
        uint8_t  health_flags{0};
    };
    using PongTelemetrySource = std::function<PongTelemetrySnapshot()>;
    void set_pong_telemetry_source(PongTelemetrySource fn) { m_pong_telemetry_source = std::move(fn); }

    // ── Mined Block Cache Source (Top 5 hashPrevBlock history) ──────────
    // Optional: supplies the Tier 1 (hot) mined block records from MinedBlockCache
    // so the diagnostic report can display the Top 5 most recent blocks with
    // confirmation status, channel, and hashPrevBlock.
    struct MinedBlockSnapshot {
        uint32_t height{0};
        uint32_t channel{0};           // 1=Prime, 2=Hash
        uint32_t confirmations{0};
        std::string hash_prev_block_hex;  // first 32 hex chars of 128-byte hash
        std::string status_emoji;         // ⛏ or ✅
        std::string channel_name;         // "Prime" or "Hash"
    };
    using MinedBlockCacheSource = std::function<std::vector<MinedBlockSnapshot>()>;
    void set_mined_block_cache_source(MinedBlockCacheSource fn) { m_mined_block_cache_source = std::move(fn); }

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
    static std::string check_fork_score(uint32_t fork_score, uint32_t peak_fork_score);

    // Check for tip sync mismatch between miner's template prevhash_lo32
    // and node's keepalive-reported hash_tip_lo32.
    // Returns empty string if in sync, ok-to-skip, or insufficient data.
    // Returns warning string only on actual mismatch.
    static std::string check_tip_sync(uint32_t miner_prevhash_lo32, uint32_t node_tip_lo32);

    // ── New hooks using canonical / diagnostic split ──────────────────────────

    // Check canonical height drift (CanonicalChainState::height_drift_from_canonical()).
    // Warns when |drift| exceeds the expected inter-channel skew threshold.
    // Returns empty string when drift is within normal range or data unavailable.
    static std::string check_canonical_drift(int32_t drift);

    // Check whether DiagnosticObserverState has received any data yet.
    // Returns a warning if diagnostic is uninitialized after the miner has been
    // running long enough to expect push / GET_ROUND / keepalive data.
    // elapsed_seconds is the time since the mining session started.
    static std::string check_diagnostic_initialized(bool is_initialized,
                                                    uint64_t elapsed_seconds);

    // Check freshness of the most recent diagnostic update (latest_received_at()).
    // Returns a warning when the diagnostic observer has gone silent for too long,
    // indicating push notifications, GET_ROUND, and keepalive have all stopped.
    // latest_age_seconds is seconds since latest_received_at() (caller computes this).
    static std::string check_diagnostic_freshness(uint64_t latest_age_seconds,
                                                  bool is_initialized);

private:
    void schedule_next();
    void run_diagnostics();

    std::string assess_primary_lane() const;
    std::string assess_secondary_lane() const;
    void emit_report(std::vector<std::string>& warnings,
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
    StatusSource m_status_source;  // Optional: supplies last SessionStatusAckFrame for the report
    const nexusminer::protocol::HeightTracker* m_height_tracker{nullptr};  // Optional: HeightTracker owned by Solo
    TemplateSource      m_template_source;       // Optional: supplies TemplateSnapshot from MiningTemplateInterface
    PongTelemetrySource m_pong_telemetry_source; // Optional: supplies PongTelemetrySnapshot from ColinPingHandler
    MinedBlockCacheSource m_mined_block_cache_source; // Optional: supplies Top 5 mined blocks from MinedBlockCache

    uint32_t m_last_miner_prevhash_lo32{0};
    uint32_t m_last_node_tip_lo32{0};

    std::chrono::steady_clock::time_point m_start_time{std::chrono::steady_clock::now()};

    std::deque<DiagSnapshot> m_history; // last 10 snapshots
};

} // namespace nexusminer

#endif // NEXUSMINER_COLIN_AGENT_HPP
