#include "recovery_state_machine.hpp"
#include "stats/stats_collector.hpp"
#include "protocol/inc/protocol/session_coordinator.hpp"
#include <spdlog/spdlog.h>
#include <cassert>

namespace nexusminer
{

void RecoveryStateMachine::init(
    std::shared_ptr<spdlog::logger> logger,
    std::shared_ptr<protocol::SessionCoordinator> coordinator,
    std::shared_ptr<stats::Collector> stats_collector)
{
    m_logger          = std::move(logger);
    m_coordinator     = std::move(coordinator);
    m_stats_collector = std::move(stats_collector);
}

// ── Static helpers ──────────────────────────────────────────────────────────

const char* RecoveryStateMachine::phase_name(RecoveryPhase phase)
{
    switch (phase) {
        case RecoveryPhase::HEALTHY:          return "HEALTHY";
        case RecoveryPhase::WAITING_TEMPLATE: return "WAITING_TEMPLATE";
        case RecoveryPhase::RECONNECTING:     return "RECONNECTING";
    }
    return "UNKNOWN";
}

bool RecoveryStateMachine::is_valid_transition(RecoveryPhase from, RecoveryPhase to)
{
    if (from == to) return true;
    switch (from) {
        case RecoveryPhase::HEALTHY:
            return to == RecoveryPhase::WAITING_TEMPLATE ||
                   to == RecoveryPhase::RECONNECTING;
        case RecoveryPhase::WAITING_TEMPLATE:
            return to == RecoveryPhase::HEALTHY ||
                   to == RecoveryPhase::RECONNECTING;
        case RecoveryPhase::RECONNECTING:
            return to == RecoveryPhase::HEALTHY ||
                   to == RecoveryPhase::WAITING_TEMPLATE;
    }
    return false;
}

// ── Internal callbacks ──────────────────────────────────────────────────────

void RecoveryStateMachine::on_phase_exit(RecoveryPhase old_phase)
{
    switch (old_phase) {
        case RecoveryPhase::RECONNECTING:
            m_recovery.reconnect_started_at = {};
            break;
        default:
            break;
    }
}

void RecoveryStateMachine::on_phase_enter(RecoveryPhase new_phase)
{
    switch (new_phase) {
        case RecoveryPhase::HEALTHY: {
            auto now = std::chrono::steady_clock::now();
            m_recovery.degraded_since = {};
            m_recovery.last_completed_at = now;
            // Note: recovery_epoch is monotonically increasing in the coordinator and is
            // NEVER reset to 0 — epoch continuity across recoveries prevents node-side
            // epoch regression. The old `m_recovery.epoch = 0` has been removed.
            m_recovery.entered_at = {};
            auto global_stats = m_stats_collector->get_global_stats();
            global_stats.m_degraded_mode = false;
            m_stats_collector->update_global_stats(global_stats);
            m_stats_collector->reset_start_time();
            break;
        }
        case RecoveryPhase::WAITING_TEMPLATE: {
            auto now = std::chrono::steady_clock::now();
            bool is_new_outage = (m_recovery.degraded_since == std::chrono::steady_clock::time_point{});
            if (is_new_outage) {
                m_recovery.degraded_since = now;
                ++m_degraded_enter_total;
            }
            auto global_stats = m_stats_collector->get_global_stats();
            global_stats.m_degraded_mode = true;
            m_stats_collector->update_global_stats(global_stats);
            break;
        }
        case RecoveryPhase::RECONNECTING: {
            m_recovery.reconnect_started_at = std::chrono::steady_clock::now();
            break;
        }
    }
}

void RecoveryStateMachine::cancel_forced_retry()
{
    m_forced_retry_timer_pending = false;
    ++m_forced_retry_timer_token;
    if (m_cancel_forced_retry_cb) {
        m_cancel_forced_retry_cb();
    }
}

// ── Core transition ─────────────────────────────────────────────────────────

void RecoveryStateMachine::transition_to(RecoveryPhase new_phase, const char* reason)
{
    RecoveryPhase old_phase = m_recovery.phase;
    if (old_phase == new_phase) {
        return;  // Already in this phase — no-op
    }

    if (!is_valid_transition(old_phase, new_phase)) {
        m_logger->error("[RecoveryStateMachine] ⚡ ILLEGAL TRANSITION: {} → {} (reason: {})",
                        phase_name(old_phase), phase_name(new_phase),
                        reason ? reason : "unknown");
        // In debug builds, assert to catch illegal transitions early during development.
        // In release builds, log and proceed to avoid hard crashes in production.
#ifndef NDEBUG
        assert(false && "Illegal RecoveryPhase transition — see error log above");
#endif
    }

    // Pre-transition accounting: if exiting WAITING_TEMPLATE to HEALTHY,
    // accumulate total time spent in degraded mode.
    if (new_phase == RecoveryPhase::HEALTHY && old_phase == RecoveryPhase::WAITING_TEMPLATE) {
        auto now = std::chrono::steady_clock::now();
        if (m_recovery.degraded_since != std::chrono::steady_clock::time_point{}) {
            auto elapsed_ms = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    now - m_recovery.degraded_since).count());
            m_time_in_degraded_ms += elapsed_ms;
        }
        ++m_degraded_exit_total;
    }

    on_phase_exit(old_phase);

    m_recovery.phase = new_phase;
    m_recovery.reason = reason;

    // Reset per-epoch state for all non-HEALTHY phases
    if (new_phase != RecoveryPhase::HEALTHY) {
        m_coordinator->advance_recovery_epoch(reason ? reason : "phase_transition");
        m_recovery.entered_at = std::chrono::steady_clock::now();
        m_recovery.get_block_confirmed = false;
        m_recovery.last_get_block_at = {};
        cancel_forced_retry();
    }

    on_phase_enter(new_phase);

    m_logger->info("[RecoveryStateMachine] ⚡ TRANSITION: {} → {} (epoch={}, reason={})",
                   phase_name(old_phase), phase_name(new_phase),
                   m_coordinator->recovery_epoch(), reason ? reason : "unknown");
}

// ── High-level transition helpers ───────────────────────────────────────────

void RecoveryStateMachine::mark_recovery_initiated(const char* reason)
{
    // Idempotent: if already in WAITING_TEMPLATE or RECONNECTING,
    // a new epoch is already running — do NOT reset it.
    if (is_recovery_active()) {
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - m_recovery.entered_at).count();
        m_logger->info("[RecoveryStateMachine] Recovery already pending (epoch {}, {}s elapsed, reason: {})",
                       m_coordinator->recovery_epoch(), elapsed, reason ? reason : "unknown");
        return;
    }
    // From HEALTHY → WAITING_TEMPLATE (new epoch; workers keep running)
    transition_to(RecoveryPhase::WAITING_TEMPLATE, reason);
    m_logger->warn("[RecoveryStateMachine] ⚑ RECOVERY INITIATED — epoch {} (reason: {})",
                   m_coordinator->recovery_epoch(), reason ? reason : "unknown");
    m_logger->warn("[RecoveryStateMachine]   Workers keep running with current template while requesting fresh one");
}

void RecoveryStateMachine::mark_soft_refresh_requested(const char* reason)
{
    // Both soft refresh and hard recovery now map to WAITING_TEMPLATE.
    // Workers keep running; no submissions withheld in the new model.
    mark_recovery_initiated(reason);
}

void RecoveryStateMachine::restart_recovery_window(const char* reason)
{
    // Reset the current-epoch timing state while staying in the current recovery phase.
    // Used after successful re-authentication to give the new session a clean recovery
    // window clock without exiting degraded mode (workers are still stopped, no template yet).
    const bool had_pending_recovery = is_recovery_active();
    const bool had_forced_retry_timer = m_forced_retry_timer_pending;
    int64_t elapsed_s = 0;
    if (had_pending_recovery && m_recovery.entered_at != std::chrono::steady_clock::time_point{}) {
        elapsed_s = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - m_recovery.entered_at).count();
    }

    // Reset per-epoch state in-place (no phase change)
    m_recovery.entered_at = std::chrono::steady_clock::now();  // fresh epoch clock
    m_recovery.last_get_block_at = {};
    m_recovery.get_block_confirmed = false;
    cancel_forced_retry();

    if (had_pending_recovery || had_forced_retry_timer) {
        m_logger->info("[RecoveryStateMachine] Restarting recovery window after {} "
                       "(prior_epoch={} prior_elapsed={}s phase={})",
                       reason ? reason : "unknown",
                       m_coordinator->recovery_epoch(),
                       elapsed_s,
                       phase_name(m_recovery.phase));
    }
}

void RecoveryStateMachine::clear_recovery_state(bool has_valid_template)
{
    if (!is_degraded() && !is_recovery_active())
        return;  // Already HEALTHY — nothing to clear

    if (is_degraded() && !has_valid_template) {
        m_logger->warn("[RecoveryStateMachine] clear_recovery_state() deferred: no valid template accepted yet");
        return;
    }

    m_logger->info("[RecoveryStateMachine] Clearing recovery state — exiting {} phase",
                   phase_name(m_recovery.phase));

    // Note: m_recovery_workers_spawned is intentionally NOT reset here.
    // It is only reset in stop_all_workers() which actually destroys workers,
    // preventing a mid-recovery clear_recovery_state() call (e.g. from a
    // different epoch's template feed) from allowing duplicate worker creation.

    // transition_to(HEALTHY) handles: degraded time accounting, global stats,
    // stats reset, last_completed_at, clearing of all recovery fields.
    transition_to(RecoveryPhase::HEALTHY, "template_distributed");

    m_logger->info("[RecoveryStateMachine] Recovery state cleared — degraded_exit_count={} cumulative_degraded_time_ms={}",
                   m_degraded_exit_total, m_time_in_degraded_ms);
}

} // namespace nexusminer
