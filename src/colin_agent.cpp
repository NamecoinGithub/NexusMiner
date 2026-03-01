#include "colin_agent.hpp"

#include <asio/io_context.hpp>

#include <cstdlib>
#include <ctime>

namespace nexusminer
{

// Warning-catalog threshold constants
static constexpr uint32_t WARN_CONNECTION_RETRIES = 100;
static constexpr uint64_t WARN_TEMPLATE_AGE_SECONDS = 150;
static constexpr int64_t WARN_KEEPALIVE_ACK_STALE_SECONDS = 300;  // 5 min without keepalive ACK
static constexpr int32_t WARN_CANONICAL_DRIFT_THRESHOLD = 3;      // blocks ahead before warning
static constexpr int64_t WARN_DIAGNOSTIC_STALE_SECONDS = 120;     // 2 min without any diagnostic update

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

std::string ColinAgent::check_fork_score(uint32_t fork_score, uint32_t peak_fork_score)
{
    if (fork_score > 0)
        return "FORK CANARY active: fork_score=" + std::to_string(fork_score) +
               " peak=" + std::to_string(peak_fork_score) +
               " — miner may be on a divergent chain";
    return {};
}

std::string ColinAgent::check_tip_sync(uint32_t miner_prevhash_lo32, uint32_t node_tip_lo32)
{
    if (miner_prevhash_lo32 == 0 || node_tip_lo32 == 0)
        return {};  // insufficient data — skip
    if (miner_prevhash_lo32 == node_tip_lo32)
        return {};  // in sync — all good
    char buf_m[9], buf_n[9];
    snprintf(buf_m, 9, "%08x", miner_prevhash_lo32);
    snprintf(buf_n, 9, "%08x", node_tip_lo32);
    return std::string("TipSync mismatch: miner_prevhash_lo32=0x") + buf_m +
           " vs node_tip_lo32=0x" + buf_n +
           " — miner may be on stale/forked tip";
}

std::string ColinAgent::check_canonical_drift(int32_t drift)
{
    if (drift <= WARN_CANONICAL_DRIFT_THRESHOLD)
        return {};  // drift within tolerance — canonical either caught up or slightly behind
    return "HeightDrift +" + std::to_string(drift) +
           " — canonical BLOCK_DATA path lagging behind push/round";
}

std::string ColinAgent::check_diagnostic_staleness(int64_t age_seconds)
{
    if (age_seconds < WARN_DIAGNOSTIC_STALE_SECONDS)
        return {};  // fresh enough
    return "No diagnostic update (push/round/keepalive) for " +
           std::to_string(age_seconds) + "s — all observer sources may be stale";
// ── New hooks using canonical / diagnostic split ──────────────────────────────

// Maximum expected inter-channel skew (blocks). Unified height and channel
// target are different height dimensions, so a non-zero drift is normal.
// Warn only when drift exceeds this threshold, which suggests a real anomaly.
static constexpr int32_t WARN_CANONICAL_DRIFT_THRESHOLD = 500;

// Warn when diagnostic has received no data for this many seconds.
static constexpr uint64_t WARN_DIAGNOSTIC_STALE_SECONDS = 180;

// Grace period: don't warn about uninitialised diagnostic observer before
// this many seconds have elapsed, since the first keepalive ACK / push
// arrives within the first few seconds of a session.
static constexpr uint64_t WARN_DIAGNOSTIC_INIT_GRACE_SECONDS = 30;

std::string ColinAgent::check_canonical_drift(int32_t drift)
{
    if (drift == 0) return {};
    if (std::abs(drift) > WARN_CANONICAL_DRIFT_THRESHOLD)
        return "Canonical height drift=" + std::to_string(drift) +
               " (|drift|>" + std::to_string(WARN_CANONICAL_DRIFT_THRESHOLD) +
               ") — unified vs channel_target skew outside expected range";
    return {};
}

std::string ColinAgent::check_diagnostic_initialized(bool is_initialized,
                                                      uint64_t elapsed_seconds)
{
    if (is_initialized) return {};
    if (elapsed_seconds < WARN_DIAGNOSTIC_INIT_GRACE_SECONDS) return {};
    return "DiagnosticObserver uninitialized after " + std::to_string(elapsed_seconds) +
           "s — no push notification, GET_ROUND, or keepalive ACK received yet"
           " — check node connectivity";
}

std::string ColinAgent::check_diagnostic_freshness(uint64_t latest_age_seconds,
                                                    bool is_initialized)
{
    if (!is_initialized) return {};  // not yet initialized — separate check covers this
    if (latest_age_seconds <= WARN_DIAGNOSTIC_STALE_SECONDS) return {};
    return "Diagnostic observer silent for " + std::to_string(latest_age_seconds) +
           "s (no push/GET_ROUND/keepalive) — node may have dropped the session"
           " or push notifications have stopped";
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

    if (m_height_tracker) {
        auto ht_snap = m_height_tracker->GetSnapshot();
        {
            auto w = check_fork_score(ht_snap.fork_score, ht_snap.peak_fork_score);
            if (!w.empty()) {
                warnings.push_back(w);
                recommendations.push_back("Check node chain sync; consider restart if fork_score persists");
            }
        }
        if (ht_snap.last_keepalive_ack_at != std::chrono::steady_clock::time_point{}) {
            auto since_ack = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - ht_snap.last_keepalive_ack_at).count();
            if (since_ack > WARN_KEEPALIVE_ACK_STALE_SECONDS) {
                warnings.push_back("No keepalive ACK for " + std::to_string(since_ack) +
                                   "s — node may have dropped the session");
            }
        }
        {
            uint32_t miner_lo32 = 0;
            {
                auto bytes = ht_snap.hash_prev_block.GetBytes();
                if (bytes.size() >= 128)
                    miner_lo32 = (uint32_t(bytes[124]) << 24) | (uint32_t(bytes[125]) << 16)
                               | (uint32_t(bytes[126]) <<  8) |  uint32_t(bytes[127]);
            }
            m_last_miner_prevhash_lo32 = miner_lo32;
            m_last_node_tip_lo32 = ht_snap.hash_tip_lo32;
            auto w = check_tip_sync(miner_lo32, ht_snap.hash_tip_lo32);
            if (!w.empty()) warnings.push_back(w);
        }

        // ── New hooks: canonical drift + diagnostic observer health ───────────
        {
            auto canonical = m_height_tracker->GetCanonicalSnapshot();
            if (canonical.is_initialized()) {
                auto w = check_canonical_drift(canonical.height_drift_from_canonical());
                if (!w.empty()) {
                    warnings.push_back(w);
                    recommendations.push_back(
                        "Verify node is on the expected channel; check BLOCK_DATA feed");
                }
            }
        }
        {
            auto diag = m_height_tracker->GetDiagnosticSnapshot();
            uint64_t elapsed_s = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::steady_clock::now() - m_start_time).count());
            {
                auto w = check_diagnostic_initialized(diag.is_initialized(), elapsed_s);
                if (!w.empty()) {
                    warnings.push_back(w);
                    recommendations.push_back(
                        "Ensure node is sending push notifications and keepalive ACKs");
                }
            }
            {
                auto latest = diag.latest_received_at();
                uint64_t age_s = 0;
                if (latest != std::chrono::steady_clock::time_point{}) {
                    age_s = static_cast<uint64_t>(
                        std::chrono::duration_cast<std::chrono::seconds>(
                            std::chrono::steady_clock::now() - latest).count());
                }
                auto w = check_diagnostic_freshness(age_s, diag.is_initialized());
                if (!w.empty()) {
                    warnings.push_back(w);
                    recommendations.push_back(
                        "Check node block propagation; verify keepalive interval is ≤60s");
                }
            }
        }
    }

    emit_report(warnings, recommendations, gs);
}
void ColinAgent::emit_report(
    std::vector<std::string>& warnings,
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
    if (m_height_tracker)
    {
        auto snap = m_height_tracker->GetSnapshot();
        m_logger->info("[Colin]  Heights │ unified={} prime={} hash={} stake={}  (channel_height={})",
            snap.unified_height, snap.prime_height,
            snap.hash_height,    snap.stake_height,
            snap.channel_height);
        if (snap.peak_fork_score > 0)
            m_logger->warn("[Colin]  ⚠️  FORK CANARY active: peak_fork_score={} current_fork_score={}",
                snap.peak_fork_score, snap.fork_score);

        // Template feed source: confirms whether BLOCK_DATA metadata feed is working
        if (snap.channel_target > 0) {
            const char* src = "NONE";
            const char* label = "";
            switch (snap.last_update_source) {
                case nexusminer::protocol::HeightTracker::UpdateSource::PUSH:
                    src = "PUSH"; label = " (BLOCK_DATA metadata)"; break;
                case nexusminer::protocol::HeightTracker::UpdateSource::GET_ROUND:
                    src = "GET_ROUND"; label = " (fallback)"; break;
                case nexusminer::protocol::HeightTracker::UpdateSource::TEMPLATE:
                    src = "TEMPLATE"; label = " (BLOCK_DATA metadata → template received)"; break;
                case nexusminer::protocol::HeightTracker::UpdateSource::KEEPALIVE:
                    src = "KEEPALIVE"; label = " (keepalive fallback)"; break;
                default: break;
            }
            m_logger->info("[Colin]  Template Feed │ last_update_source={}{} channel_target={}",
                src, label, snap.channel_target);
        }
    }

    // Keepalive ACK health (Gap 4 — visibility into silent-death scenario)
    if (m_height_tracker) {
        auto snap = m_height_tracker->GetSnapshot();
        if (snap.last_keepalive_ack_at != std::chrono::steady_clock::time_point{}) {
            auto keepalive_age_s = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - snap.last_keepalive_ack_at).count();
            if (keepalive_age_s < 300) {
                m_logger->info("[Colin]  Keepalive │ last ACK {}s ago ✓", keepalive_age_s);
            } else {
                m_logger->warn("[Colin]  Keepalive │ last ACK {}s ago ⚠ (>300s — silent death risk)", keepalive_age_s);
            }
        } else {
            m_logger->info("[Colin]  Keepalive │ no ACK received yet (session just started or legacy node)");
        }
    }

    // ── Canonical Chain State section ──────────────────────────────────────────
    // Uses GetCanonicalSnapshot() and GetDiagnosticSnapshot() directly.
    if (m_height_tracker) {
        auto canonical = m_height_tracker->GetCanonicalSnapshot();
        auto diag      = m_height_tracker->GetDiagnosticSnapshot();

        m_logger->info("[Colin]  ── Canonical Chain State ────────────────────────");
        if (canonical.is_initialized()) {
            m_logger->info("[Colin]    Canonical │ unified={} channel={} channel_target={} nbits=0x{:08x}",
                canonical.canonical_unified_height,
                canonical.canonical_channel_height,
                canonical.canonical_channel_target,
                canonical.canonical_difficulty_nbits);

            int32_t drift = canonical.height_drift_from_canonical();
            if (drift == 0) {
                m_logger->info("[Colin]    Canonical │ height_drift_from_canonical=0 ✓ (unified == channel_target)");
            } else if (!check_canonical_drift(drift).empty()) {
                m_logger->warn("[Colin]    Canonical │ ⚠ height_drift_from_canonical={} (|drift|>{} — investigate)",
                    drift, WARN_CANONICAL_DRIFT_THRESHOLD);
            } else {
                m_logger->info("[Colin]    Canonical │ height_drift_from_canonical={} (inter-channel skew, normal)",
                    drift);
            }
        } else {
            m_logger->info("[Colin]    Canonical │ not yet initialized (no BLOCK_DATA received)");
        }

        m_logger->info("[Colin]  ── Diagnostic Observer State ─────────────────────");
        if (diag.is_initialized()) {
            auto latest = diag.latest_received_at();
            uint64_t age_s = 0;
            if (latest != std::chrono::steady_clock::time_point{}) {
                age_s = static_cast<uint64_t>(
                    std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::steady_clock::now() - latest).count());
            }
            const char* freshness_marker = (age_s <= WARN_DIAGNOSTIC_STALE_SECONDS) ? "✓" : "⚠";
            m_logger->info("[Colin]    Diagnostic │ latest_received_at={}s ago {} push_unified={} round_unified={} keepalive_unified={}",
                age_s, freshness_marker,
                diag.push_unified_height,
                diag.round_unified_height,
                diag.keepalive_unified_height);
            if (age_s > WARN_DIAGNOSTIC_STALE_SECONDS)
                m_logger->warn("[Colin]    Diagnostic │ ⚠ observer silent for {}s — no push/GET_ROUND/keepalive", age_s);
        } else {
            uint64_t elapsed_s = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::steady_clock::now() - m_start_time).count());
            if (elapsed_s >= WARN_DIAGNOSTIC_INIT_GRACE_SECONDS)
                m_logger->warn("[Colin]    Diagnostic │ ⚠ uninitialized after {}s (no push/GET_ROUND/keepalive yet)", elapsed_s);
            else
                m_logger->info("[Colin]    Diagnostic │ not yet initialized ({}s elapsed — within grace period)", elapsed_s);
        }
    }

    // TipSync cross-check: miner's template prevhash_lo32 vs node's keepalive-reported hash_tip_lo32
    if (m_height_tracker) {
        uint32_t miner_prevhash_lo32 = m_last_miner_prevhash_lo32;
        uint32_t node_tip_lo32 = m_last_node_tip_lo32;
        bool have_both = (miner_prevhash_lo32 != 0 && node_tip_lo32 != 0);
        if (have_both) {
            if (miner_prevhash_lo32 == node_tip_lo32) {
                m_logger->info("[Colin]  TipSync  │ ✓ miner prevhash_lo32 0x{:08x} == node tip_lo32 0x{:08x}  (in sync)",
                    miner_prevhash_lo32, node_tip_lo32);
            } else {
                m_logger->warn("[Colin]  TipSync  │ ⚠ MISMATCH miner_prevhash_lo32=0x{:08x}  node_tip_lo32=0x{:08x}",
                    miner_prevhash_lo32, node_tip_lo32);
                m_logger->warn("[Colin]  TipSync  │   Miner may be on a stale or forked tip — watch for next keepalive update");
            }
        } else if (miner_prevhash_lo32 != 0 && node_tip_lo32 == 0) {
            m_logger->info("[Colin]  TipSync  │ node tip_lo32=0 (legacy path or no keepalive ACK yet — skip cross-check)");
        } else {
            m_logger->info("[Colin]  TipSync  │ waiting for template + keepalive ACK data");
        }
    }

    /* Canonical Drift section — uses height_drift_from_canonical() to detect
     * when push/round heights are running ahead of the canonical BLOCK_DATA path.
     * Also reports DiagnosticObserverState::is_initialized() and latest_received_at()
     * so operators can see whether all three diagnostic sources are feeding data. */
    if (m_height_tracker)
    {
        auto snap = m_height_tracker->GetSnapshot();
        auto diag = m_height_tracker->GetDiagnosticSnapshot();
        auto canonical = m_height_tracker->GetCanonicalSnapshot();

        m_logger->info("[Colin]  ── Canonical vs Diagnostic State ──────────────");

        // Canonical initialization status
        if (canonical.is_initialized()) {
            auto canonical_age_s = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - canonical.canonical_received_at).count();
            m_logger->info("[Colin]    Canonical │ ✓ initialized  unified={} channel={} target={} ({}s ago)",
                canonical.canonical_unified_height, canonical.canonical_channel_height,
                canonical.canonical_channel_target, canonical_age_s);
        } else {
            m_logger->warn("[Colin]    Canonical │ ⚠ NOT initialized (no BLOCK_DATA received yet)");
        }

        // Diagnostic initialization status
        if (diag.is_initialized()) {
            auto diag_latest = diag.latest_received_at();
            auto diag_age_s = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - diag_latest).count();
            m_logger->info("[Colin]    Diagnostic │ ✓ initialized  push_unified={} round_unified={} keepalive_unified={} (latest {}s ago)",
                diag.push_unified_height, diag.round_unified_height,
                diag.keepalive_unified_height, diag_age_s);
        } else {
            m_logger->warn("[Colin]    Diagnostic │ ⚠ NOT initialized (no push/round/keepalive data yet)");
        }

        // Height drift: how far composed snapshot heights have drifted from canonical
        if (canonical.is_initialized()) {
            int32_t drift = snap.height_drift_from_canonical();
            if (drift == 0) {
                m_logger->info("[Colin]    HeightDrift │ ✓ 0 (canonical caught up with push/round)");
            } else if (drift > 0 && drift <= WARN_CANONICAL_DRIFT_THRESHOLD) {
                m_logger->info("[Colin]    HeightDrift │ +{} (push/round ahead — normal during BLOCK_DATA latency)", drift);
            } else if (drift > WARN_CANONICAL_DRIFT_THRESHOLD) {
                m_logger->warn("[Colin]    HeightDrift │ ⚠ +{} (push/round significantly ahead — BLOCK_DATA may be delayed)", drift);
                auto w = check_canonical_drift(drift);
                if (!w.empty()) warnings.push_back(w);
            } else {
                // Negative drift should not happen (canonical > composed) — log as anomaly
                m_logger->warn("[Colin]    HeightDrift │ ⚠ {} (anomaly — canonical ahead of composed snapshot)", drift);
            }
        }

        // Diagnostic staleness: warn if all diagnostic sources have gone silent
        if (diag.is_initialized()) {
            auto diag_latest = diag.latest_received_at();
            auto diag_age_s = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - diag_latest).count();
            auto w = check_diagnostic_staleness(diag_age_s);
            if (!w.empty()) {
                m_logger->warn("[Colin]    DiagStale │ ⚠ no diagnostic update for {}s", diag_age_s);
                warnings.push_back(w);
            }
        }
    }

    /* SESSION_STATUS_ACK section — node lane-health report */
    if (m_status_source)
    {
        auto [ack, ack_time] = m_status_source();
        if (ack.session_id != 0)
        {
            auto age_s = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - ack_time).count();
            m_logger->info("[Colin]  ── Node Lane Health (SESSION_STATUS_ACK, {}s ago) ──", age_s);
            m_logger->info("[Colin]    Primary alive:   {}", ack.IsPrimaryAlive()   ? "✅" : "❌");
            m_logger->info("[Colin]    Secondary alive: {}", ack.IsSecondaryAlive() ? "✅" : "❌");
            m_logger->info("[Colin]    SIM Link active: {}", ack.IsSimLinkActive()  ? "✅" : "❌");
            m_logger->info("[Colin]    Authenticated:   {}", ack.IsAuthenticated()  ? "✅" : "❌");
            m_logger->info("[Colin]    Node uptime:     {}s", ack.uptime_seconds);
            if (age_s > 120)
                warnings.push_back("No SESSION_STATUS_ACK for >" + std::to_string(age_s) +
                                   "s — node may have dropped session or lane is silent");
        }
    }

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

    /* Colin AI Miner — Node Diagnostic Section (from last received PingFrame) */
    if (m_ping_source)
    {
        const auto ping = m_ping_source();
        if (ping.valid)
        {
            m_logger->info("[Colin]  ── Node Diagnostics (last PING_DIAG) ──────────");
            m_logger->info("[Colin]    PING_DIAG Seq #{}", ping.sequence);

            /* Template push rates with drought warnings */
            if (ping.prime_pushes_30s == 0 && ping.hash_pushes_30s == 0)
                m_logger->error("[Colin]    Prime pushes/30s: 0   Hash pushes/30s: 0  ⚠ TOTAL DROUGHT");
            else if (ping.prime_pushes_30s == 0)
                m_logger->warn("[Colin]    Prime pushes/30s: 0 ⚠   Hash pushes/30s: {}",
                    ping.hash_pushes_30s);
            else if (ping.hash_pushes_30s == 0)
                m_logger->warn("[Colin]    Prime pushes/30s: {}   Hash pushes/30s: 0 ⚠",
                    ping.prime_pushes_30s);
            else
                m_logger->info("[Colin]    Prime pushes/30s: {}   Hash pushes/30s: {}",
                    ping.prime_pushes_30s, ping.hash_pushes_30s);

            /* Submission accept/reject rate */
            if (ping.blocks_submitted > 0)
            {
                uint32_t reject_pct = static_cast<uint32_t>(
                    static_cast<uint64_t>(ping.blocks_rejected) * 100u / ping.blocks_submitted);
                m_logger->info("[Colin]    Submissions: {} sent / {} accepted / {} rejected ({}%)",
                    ping.blocks_submitted, ping.blocks_accepted,
                    ping.blocks_rejected, reject_pct);
            }
            else
            {
                m_logger->info("[Colin]    Submissions: 0 sent (no submissions this interval)");
            }

            /* Decoded node health flags */
            if (ping.health_flags == 0)
            {
                m_logger->info("[Colin]    Node Health: ✓ OK");
            }
            else
            {
                /* Build human-readable flag list */
                std::string flag_str;
                auto append = [&](const char* name) {
                    if (!flag_str.empty()) flag_str += " | ";
                    flag_str += name;
                };
                if (ping.health_flags & ::LLP::ReceivedPingFrame::NFLAG_NODE_SYNCING)
                    append("NODE_SYNCING");
                if (ping.health_flags & ::LLP::ReceivedPingFrame::NFLAG_FIRST_CONNECT)
                    append("FIRST_CONNECT");
                if (ping.health_flags & ::LLP::ReceivedPingFrame::NFLAG_HIGH_REJECT_RATE)
                    append("HIGH_REJECT_RATE");
                if (ping.health_flags & ::LLP::ReceivedPingFrame::NFLAG_CHANNEL_MISMATCH)
                    append("CHANNEL_MISMATCH");
                if (ping.health_flags & ::LLP::ReceivedPingFrame::NFLAG_DEDUP_HIT)
                    append("DEDUP_HIT");
                if (ping.health_flags & ::LLP::ReceivedPingFrame::NFLAG_SIM_LINK_ACTIVE)
                    append("SIM_LINK_ACTIVE");
                if (ping.health_flags & ::LLP::ReceivedPingFrame::NFLAG_RATE_LIMITED)
                    append("RATE_LIMITED");
                if (ping.health_flags & ::LLP::ReceivedPingFrame::NFLAG_STALE_TEMPLATE)
                    append("STALE_TEMPLATE");
                m_logger->warn("[Colin]    Node Health: ⚠ {}", flag_str);
            }
        }
    }

    /* Active Template section (BLOCK_DATA canonical source) */
    if (m_template_source)
    {
        auto ts = m_template_source();
        m_logger->info("[Colin]  ── Active Template (BLOCK_DATA canonical) ─────");
        if (ts.has_valid_template)
        {
            m_logger->info("[Colin]    State:          {}", ts.state_name ? ts.state_name : "?");
            m_logger->info("[Colin]    unified_height: {}  (block.nHeight — canonical for ProofHash)", ts.unified_height);
            m_logger->info("[Colin]    nBits:          0x{:08x}", ts.nBits);
            m_logger->info("[Colin]    channel_height: {}  (nChannelHeight — staleness metadata only)", ts.channel_height);
            m_logger->info("[Colin]    channel:        {} ({})", ts.channel, ts.channel == 1 ? "Prime" : "Hash");
            m_logger->info("[Colin]    age:            {}s", ts.age_seconds);

            // Cross-check: compare template unified height with HeightTracker snapshot.
            // By design, template.block.nHeight == HeightTracker.unified_height + 1 (template
            // mines the NEXT block). A drift of exactly +1 is normal — only warn on drift != 0.
            if (m_height_tracker)
            {
                auto ht = m_height_tracker->GetSnapshot();
                if (ht.unified_height != 0 && ts.unified_height != 0)
                {
                    int64_t height_drift = static_cast<int64_t>(ts.unified_height)
                                         - static_cast<int64_t>(ht.unified_height + 1);
                    if (height_drift != 0)
                    {
                        m_logger->warn("[Colin]    ⚠ HEIGHT_DRIFT: HeightTracker.unified={} vs template.block.nHeight={} (drift={}; expected 0)",
                            ht.unified_height, ts.unified_height, height_drift);
                    }
                    else
                    {
                        m_logger->debug("[Colin]    HEIGHT_DRIFT: none (unified={} + 1 == template.nHeight={})",
                            ht.unified_height, ts.unified_height);
                    }
                }
            }

            if (ts.age_seconds > WARN_TEMPLATE_AGE_SECONDS)
                m_logger->warn("[Colin]    ⚠️  TEMPLATE AGING: {}s — approaching emergency timeout", ts.age_seconds);
        }
        else
        {
            m_logger->warn("[Colin]    ⚠️  NO VALID TEMPLATE — workers have no work to do!");
        }
        m_logger->info("[Colin]    Lifetime — rcvd:{} valid:{} rejected:{} stale:{} fed:{} expiredAge:{} expiredHt:{}",
            ts.templates_received, ts.templates_validated, ts.templates_rejected,
            ts.templates_stale, ts.templates_fed,
            ts.templates_expired_age, ts.templates_expired_height);
    }

    /* Miner Telemetry section (from ColinPingHandler PONG outbound) */
    if (m_pong_telemetry_source)
    {
        auto pt = m_pong_telemetry_source();
        m_logger->info("[Colin]  ── Miner Telemetry (PONG outbound) ─────────────");
        m_logger->info("[Colin]    Ping count: {}  Last RTT: {} µs", pt.ping_count, pt.last_rtt_us);
        if (pt.hash_rate_khs > 0)
            m_logger->info("[Colin]    Hash-rate: {} kH/s  Threads: {}  Queue: {}",
                pt.hash_rate_khs, pt.thread_count, pt.queue_depth);
        if (pt.temp_cdeg > 0)
            m_logger->info("[Colin]    Temp: {:.1f} °C", pt.temp_cdeg / 10.0f);
        if (pt.health_flags != 0)
            m_logger->warn("[Colin]    Health flags: 0x{:02x}", pt.health_flags);
    }

    m_logger->info("[Colin] ═══════════════════════════════════════════════════");
}

} // namespace nexusminer
