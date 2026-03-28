#ifndef NEXUSMINER_RECOVERY_STATE_MACHINE_HPP
#define NEXUSMINER_RECOVERY_STATE_MACHINE_HPP

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>

namespace spdlog { class logger; }

namespace nexusminer
{
namespace protocol { class SessionCoordinator; }
namespace stats { class Collector; }

// ─────────────────────────────────────────────────────────────────────────────
// ⚡ Explicit Recovery State Machine
// ─────────────────────────────────────────────────────────────────────────────
// Replaces 15 independent boolean/timestamp fields that could combine into 32+
// undefined configurations.  Exactly one phase is active at any moment.
// ─────────────────────────────────────────────────────────────────────────────
enum class RecoveryPhase : uint8_t {
    HEALTHY,          // Mining normally
    WAITING_TEMPLATE, // Waiting for new template; workers keep running
    RECONNECTING,     // TCP reconnect in progress
};

struct RecoveryContext {
    RecoveryPhase phase{RecoveryPhase::HEALTHY};

    // Note: 'epoch' (monotonic recovery counter) has been moved to SessionCoordinator
    // as recovery_epoch. Use m_coordinator->recovery_epoch() in Worker_manager.
    std::chrono::steady_clock::time_point entered_at{};            // When current epoch (recovery start) began
    std::chrono::steady_clock::time_point degraded_since{};        // When current outage started (set once per outage)
    std::chrono::steady_clock::time_point last_get_block_at{};     // Last confirmed GET_BLOCK transmit
    std::chrono::steady_clock::time_point last_completed_at{};     // When last recovery finished (hold-off)
    bool get_block_confirmed{false};                               // At least one GET_BLOCK confirmed this epoch
    const char* reason{nullptr};                                   // Why this phase was entered (for logging)

    // ── Reconnect sub-state (only valid when phase == RECONNECTING) ──────────
    std::chrono::steady_clock::time_point reconnect_started_at{};

};

/// Self-contained recovery state machine extracted from Worker_manager.
///
/// Owns the RecoveryContext, phase transition logic, and recovery-related
/// counters.  Does NOT own IO objects (timers, sockets) — the owning
/// Worker_manager provides a callback for forced-retry timer cancellation.
class RecoveryStateMachine
{
public:
    RecoveryStateMachine() = default;

    /// Inject dependencies.  Must be called once before any state transitions.
    void init(std::shared_ptr<spdlog::logger> logger,
              std::shared_ptr<protocol::SessionCoordinator> coordinator,
              std::shared_ptr<stats::Collector> stats_collector);

    // ── State queries (backward-compat convenience) ─────────────────────────
    bool is_degraded()              const { return m_recovery.phase == RecoveryPhase::WAITING_TEMPLATE; }
    bool is_submissions_withheld()  const { return false; }
    bool is_recovery_active()       const { return m_recovery.phase != RecoveryPhase::HEALTHY; }
    bool is_reconnecting()          const { return m_recovery.phase == RecoveryPhase::RECONNECTING; }

    // ── State transitions ───────────────────────────────────────────────────
    /// Transition to a new RecoveryPhase.  Logs the transition, validates legality
    /// (in debug builds: asserts; in release: logs error and returns without change),
    /// runs on_phase_exit() for the old phase and on_phase_enter() for the new one.
    void transition_to(RecoveryPhase new_phase, const char* reason = nullptr);

    /// Mark that a hard GET_BLOCK recovery is now in progress.
    void mark_recovery_initiated(const char* reason);

    /// Mark that a soft refresh is now in progress.
    void mark_soft_refresh_requested(const char* reason);

    /// Reset current-epoch timing state while staying in the current recovery phase.
    void restart_recovery_window(const char* reason);

    /// Clear degraded mode and all recovery state after a valid template is delivered.
    /// @param has_valid_template  true if a valid mining template is currently available.
    void clear_recovery_state(bool has_valid_template);

    // ── Read/write access to context ────────────────────────────────────────
    RecoveryContext&       context()       { return m_recovery; }
    const RecoveryContext& context() const { return m_recovery; }

    // ── Static helpers ──────────────────────────────────────────────────────
    static bool        is_valid_transition(RecoveryPhase from, RecoveryPhase to);
    static const char* phase_name(RecoveryPhase phase);

    // ── Counter accessors ───────────────────────────────────────────────────
    uint64_t degraded_enter_total() const { return m_degraded_enter_total; }
    uint64_t degraded_exit_total()  const { return m_degraded_exit_total; }
    uint64_t time_in_degraded_ms()  const { return m_time_in_degraded_ms; }

    // ── Forced retry timer token management ─────────────────────────────────
    // The actual asio::steady_timer lives in Worker_manager; only the
    // stale-callback-detection token and pending flag live here.
    uint64_t forced_retry_token()  const { return m_forced_retry_timer_token; }
    uint64_t advance_forced_retry_token()  { return ++m_forced_retry_timer_token; }
    bool forced_retry_pending()    const { return m_forced_retry_timer_pending; }
    void set_forced_retry_pending(bool v) { m_forced_retry_timer_pending = v; }

    /// Register a callback invoked when the forced-retry timer must be cancelled.
    /// Called during transition_to() and restart_recovery_window().
    void set_cancel_forced_retry_callback(std::function<void()> cb)
    {
        m_cancel_forced_retry_cb = std::move(cb);
    }

private:
    void on_phase_enter(RecoveryPhase phase);
    void on_phase_exit(RecoveryPhase phase);
    void cancel_forced_retry();

    RecoveryContext m_recovery;

    std::shared_ptr<spdlog::logger>                m_logger;
    std::shared_ptr<protocol::SessionCoordinator>  m_coordinator;
    std::shared_ptr<stats::Collector>              m_stats_collector;

    // Forced retry timer bookkeeping (timer itself stays in Worker_manager)
    bool     m_forced_retry_timer_pending{false};
    uint64_t m_forced_retry_timer_token{0};
    std::function<void()> m_cancel_forced_retry_cb;

    // Recovery counters
    uint64_t m_degraded_enter_total{0};
    uint64_t m_degraded_exit_total{0};
    uint64_t m_time_in_degraded_ms{0};
};

} // namespace nexusminer

#endif // NEXUSMINER_RECOVERY_STATE_MACHINE_HPP
