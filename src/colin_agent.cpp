#include "colin_agent.hpp"

#include <asio/io_context.hpp>

#include <ctime>
#include <cstring>

namespace nexusminer
{

// Warning-catalog threshold constants
static constexpr uint32_t WARN_CONNECTION_RETRIES = 100;
static constexpr uint64_t WARN_TEMPLATE_AGE_SECONDS = 150;

ColinAgent::ColinAgent(
    std::shared_ptr<asio::io_context> io_context,
    const DualConnectionManager* dcm,
    std::shared_ptr<stats::Collector> stats,
    std::shared_ptr<spdlog::logger> logger,
    uint32_t report_interval_seconds)
    : m_io_context{std::move(io_context)}
    , m_dcm{dcm}
    , m_stats{std::move(stats)}
    , m_logger{std::move(logger)}
    , m_interval_s{report_interval_seconds > 0 ? report_interval_seconds : 60u}
    , m_timer{*m_io_context}
{
}

void ColinAgent::start()
{
    m_running = true;
    schedule_next();
    m_logger->info("[Colin] Diagnostic agent started (report every {}s)", m_interval_s);
}

void ColinAgent::stop()
{
    m_running = false;
    m_timer.cancel();
    m_logger->info("[Colin] Diagnostic agent stopped");
}

void ColinAgent::schedule_next()
{
    if (!m_running) return;
    m_timer.expires_after(std::chrono::seconds(m_interval_s));
    m_timer.async_wait([this](const asio::error_code& ec) {
        if (ec || !m_running) return;
        run_diagnostics();
        schedule_next();
    });
}

void ColinAgent::emit_rpc_commands()
{
    m_logger->info("[Colin] ── Diagnostic RPC Commands ───────────────────────────────");
    m_logger->info("[Colin]   system/get/info                           ← node version, uptime");
    m_logger->info("[Colin]   mining/get/info                           ← per-channel heights, difficulty");
    m_logger->info("[Colin]   ledger/get/blockhash height=<N>           ← verify block hash at height");
    m_logger->info("[Colin]   system/list/peers                         ← peer connectivity");
    m_logger->info("[Colin]   users/get/status                          ← genesis/session state");
    m_logger->info("[Colin] ─────────────────────────────────────────────────────────");
}

// ── Warning catalog (static helpers) ─────────────────────────────────────────

std::string ColinAgent::check_base_not_prime(const std::string& log_line)
{
    if (log_line.find("BASE IS NOT PRIME") != std::string::npos)
        return "Node PrimeCheck rejected hashPrime base → verify nNonce LE encoding (PR #180)";
    return {};
}

std::string ColinAgent::check_malformed_packet(const std::string& log_line)
{
    if (log_line.find("MALFORMED PACKET DETECTED") != std::string::npos ||
        log_line.find("MALFORMED") != std::string::npos)
        return "Likely node sent null BLOCK_DATA → check node new_block() retry (PR #283)";
    return {};
}

std::string ColinAgent::check_block_rejected_none(const std::string& log_line)
{
    if (log_line.find("BLOCK REJECTED") != std::string::npos &&
        log_line.find("reason=NONE") != std::string::npos)
        return "Stale block / nonce does not meet difficulty → check is_template_stale() path";
    return {};
}

std::string ColinAgent::check_no_offsets_found(const std::string& log_line)
{
    if (log_line.find("NO OFFSETS FOUND") != std::string::npos)
        return "Cunningham chain vOffsets empty: base not prime — chain search failed";
    return {};
}

std::string ColinAgent::check_connection_retries(uint32_t retry_count)
{
    if (retry_count > WARN_CONNECTION_RETRIES)
        return "Connection retries high (" + std::to_string(retry_count) +
               ") → check network / node restart";
    return {};
}

std::string ColinAgent::check_template_age(uint64_t age_seconds)
{
    if (age_seconds > WARN_TEMPLATE_AGE_SECONDS)
        return "Template age " + std::to_string(age_seconds) +
               "s — approaching emergency timeout → verify push notifications working";
    return {};
}

std::string ColinAgent::check_mining_stopped(bool degraded_mode)
{
    if (degraded_mode)
        return "MINING STOPPED: workers in degraded mode → check template delivery path";
    return {};
}

// ── Lane assessment ───────────────────────────────────────────────────────────

std::string ColinAgent::assess_primary_lane() const
{
    if (!m_dcm) return "UNKNOWN";
    return m_dcm->is_stateless_alive() ? "✅ HEALTHY" : "❌ DOWN";
}

std::string ColinAgent::assess_secondary_lane() const
{
    if (!m_dcm) return "UNKNOWN";
    return m_dcm->is_legacy_alive() ? "✅ HEALTHY" : "❌ DOWN";
}

// ── Main diagnostic run ───────────────────────────────────────────────────────

void ColinAgent::run_diagnostics()
{
    stats::Global gs{};
    if (m_stats)
        gs = m_stats->get_global_stats();

    // Save snapshot for trend analysis (keep last 10)
    DiagSnapshot snap;
    snap.blocks_accepted    = gs.m_accepted_blocks;
    snap.blocks_rejected    = gs.m_rejected_blocks;
    snap.connection_retries = gs.m_connection_retries;
    snap.timestamp          = std::chrono::steady_clock::now();
    m_history.push_back(snap);
    if (m_history.size() > 10) m_history.pop_front();

    // Build warnings list
    std::vector<std::string> warnings;
    std::vector<std::string> recommendations;

    {
        auto w = check_connection_retries(gs.m_connection_retries);
        if (!w.empty()) warnings.push_back(w);
    }
    {
        auto w = check_mining_stopped(gs.m_degraded_mode);
        if (!w.empty()) warnings.push_back(w);
    }

    if (!m_dcm || !m_dcm->any_lane_alive())
        warnings.push_back("BOTH lanes unavailable — no template delivery possible");

    if (m_dcm && !m_dcm->is_stateless_alive())
        recommendations.push_back("Check primary (stateless:9323) connectivity");
    if (m_dcm && !m_dcm->is_legacy_alive())
        recommendations.push_back("Check secondary (legacy:8323) connectivity");

    // Emit RPC commands prompt on first tick or whenever a WARNING is present
    if (m_rpc_prompt && (m_first_tick || !warnings.empty()))
        emit_rpc_commands();

    m_first_tick = false;

    emit_report(warnings, recommendations, gs);
}

void ColinAgent::emit_report(
    const std::vector<std::string>& warnings,
    const std::vector<std::string>& recommendations,
    const stats::Global& gs)
{
    // Timestamp
    auto now_t = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now_t);
    char ts_buf[32];
    std::strftime(ts_buf, sizeof(ts_buf), "%Y-%m-%d %H:%M:%S", std::localtime(&now_c));

    m_logger->info("[Colin] ════ DIAGNOSTIC REPORT [{}] ════", ts_buf);
    m_logger->info("[Colin]  PRIMARY   (stateless:9323): {}", assess_primary_lane());
    m_logger->info("[Colin]  SECONDARY (legacy:8323):    {}", assess_secondary_lane());
    m_logger->info("[Colin]  BLOCKS  Accepted: {}  Rejected: {}  Retries: {}",
        gs.m_accepted_blocks, gs.m_rejected_blocks, gs.m_connection_retries);
    if (gs.m_degraded_mode)
        m_logger->warn("[Colin]  ⚠️  MINING STOPPED — workers in degraded mode");

    if (!warnings.empty())
    {
        m_logger->warn("[Colin]  ── Warnings ──────────────────────────────────");
        for (const auto& w : warnings)
            m_logger->warn("[Colin]    • {}", w);
    }

    if (!recommendations.empty())
    {
        m_logger->info("[Colin]  ── Recommendations ────────────────────────────");
        for (const auto& r : recommendations)
            m_logger->info("[Colin]    • {}", r);
    }

    m_logger->info("[Colin] ═══════════════════════════════════════════════════");
}

// ── PING diagnostic payload ───────────────────────────────────────────────────

std::vector<uint8_t> ColinAgent::build_ping_payload() const
{
    // 17-byte compact TLV diagnostic payload (big-endian).
    // The node ignores unknown PING payload bytes — fully backward-compatible.
    std::vector<uint8_t> payload(17, 0);

    // [0] Version
    payload[0] = 0x01;

    // [1-4] Unified height (last known) — currently unavailable at ColinAgent level; leave 0.
    // [5-8] Channel height (last known) — similarly 0 until plumbed through.
    // [9-12] Template age in seconds — unavailable here; left 0.

    // [13] Lane bitmask
    uint8_t lane_mask = 0;
    if (m_dcm)
    {
        if (m_dcm->is_stateless_alive()) lane_mask |= 0x01;
        if (m_dcm->is_legacy_alive())    lane_mask |= 0x02;
    }
    payload[13] = lane_mask;

    // [14-15] Active workers count — not tracked at ColinAgent level; leave 0.
    // [16] Colin warning flags
    uint8_t warn_flags = 0;
    if (m_dcm && !m_dcm->any_lane_alive()) warn_flags |= 0x02; // no_push: both lanes down
    payload[16] = warn_flags;

    return payload;
}

} // namespace nexusminer
