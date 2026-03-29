#ifndef NEXUSMINER_PROTOCOL_GET_BLOCK_DEDUP_GUARD_HPP
#define NEXUSMINER_PROTOCOL_GET_BLOCK_DEDUP_GUARD_HPP

#include "protocol/get_block_reason.hpp"
#include "spdlog/spdlog.h"
#include <chrono>
#include <cstdint>
#include <memory>

namespace nexusminer {
namespace protocol {

// ─────────────────────────────────────────────────────────────────────────────
// GetBlockDedupGuard — centralized GET_BLOCK deduplication state machine
// ─────────────────────────────────────────────────────────────────────────────
// Extracted from Solo::get_work() to:
//   1. Consolidate dedup policy in one place (rather than caller + Solo + push handler)
//   2. Eliminate the need for push_notification_handler to carry a reset_dedup_fn callback
//   3. Provide a testable, reusable dedup module
//
// The guard implements two tiers:
//   - Rapid-burst guard (100ms): prevents two code paths racing on the same event
//   - Height-based guard: prevents redundant GET_BLOCK when unified height hasn't changed
//     and a valid template already exists
//
// The bypass policy is reason-aware via GetBlockReason:
//   - bypass_all (RECOVERY_FORCED, RECOVERY_TIMER): skip both guards
//   - bypass_height (age-based, validation, GET_ROUND, etc.): skip height, keep burst
//   - full dedup (PUSH_*, INITIAL_REQUEST, etc.): both guards active
// ─────────────────────────────────────────────────────────────────────────────
class GetBlockDedupGuard {
public:
    /// Result of a dedup check.
    enum class Verdict {
        ALLOW,                  ///< Request should proceed
        SUPPRESS_RAPID_BURST,   ///< Suppressed by 100ms rapid-burst guard
        SUPPRESS_HEIGHT_MATCH,  ///< Suppressed by height-based guard (same unified + valid template)
    };

    static constexpr int64_t DEDUP_WINDOW_MS = 100;  // rapid-burst guard window

    explicit GetBlockDedupGuard(std::shared_ptr<spdlog::logger> logger = nullptr)
        : m_logger{std::move(logger)}
    {}

    /// Check whether a GET_BLOCK request should be suppressed.
    ///
    /// @param reason            Why the GET_BLOCK is being requested
    /// @param current_unified   Current unified height from HeightTracker snapshot
    /// @param have_valid_template  Whether a valid mining template currently exists
    /// @return Verdict indicating whether request should proceed or be suppressed
    Verdict check(GetBlockReason reason,
                  uint32_t current_unified,
                  bool have_valid_template) const
    {
        bool bypass_all    = should_bypass_all_dedup(reason);
        bool bypass_height = should_bypass_height_dedup(reason);

        if (bypass_all) {
            if (m_logger) {
                m_logger->info("[DedupGuard] bypass_all — reason: {}", reason_name(reason));
            }
            return Verdict::ALLOW;
        }

        // Guard 1: rapid-burst (100ms window)
        if (m_last_transmitted_tp != std::chrono::steady_clock::time_point{}) {
            auto now = std::chrono::steady_clock::now();
            auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - m_last_transmitted_tp).count();
            if (elapsed_ms < DEDUP_WINDOW_MS) {
                if (m_logger) {
                    m_logger->info("[DedupGuard] rapid-burst: suppressing ({}ms < {}ms, reason={})",
                                  elapsed_ms, DEDUP_WINDOW_MS, reason_name(reason));
                }
                return Verdict::SUPPRESS_RAPID_BURST;
            }
        }

        if (bypass_height) {
            if (m_logger) {
                m_logger->info("[DedupGuard] bypass_height — reason: {}", reason_name(reason));
            }
            return Verdict::ALLOW;
        }

        // Guard 2: height-based (same unified height + valid template)
        if (m_last_unified_height > 0 &&
            current_unified == m_last_unified_height &&
            have_valid_template)
        {
            if (m_logger) {
                m_logger->info("[DedupGuard] height-match: suppressing (unified={}, reason={})",
                              current_unified, reason_name(reason));
            }
            return Verdict::SUPPRESS_HEIGHT_MATCH;
        }

        return Verdict::ALLOW;
    }

    /// Record that a GET_BLOCK was successfully transmitted.
    /// Must be called after every successful GET_BLOCK send to arm the dedup guards.
    void record_transmission(uint32_t unified_height)
    {
        m_last_transmitted_tp = std::chrono::steady_clock::now();
        m_last_unified_height = unified_height;
    }

    /// Reset all dedup state.  The next check() will always return ALLOW.
    ///
    /// Must be called when the canonical tip-anchor changes (same-height reorg,
    /// cross-channel unified advance) or a new recovery epoch begins — the
    /// prior dedup state refers to a request for the *old* canonical tip.
    void reset()
    {
        m_last_transmitted_tp = {};
        m_last_unified_height = 0;
        if (m_logger) {
            m_logger->info("[DedupGuard] state reset — next request will not be suppressed");
        }
    }

    /// Read-only access for diagnostics/logging.
    uint32_t last_unified_height() const { return m_last_unified_height; }
    std::chrono::steady_clock::time_point last_transmitted_tp() const { return m_last_transmitted_tp; }

private:
    std::shared_ptr<spdlog::logger> m_logger;
    uint32_t m_last_unified_height{0};
    std::chrono::steady_clock::time_point m_last_transmitted_tp{};
};

} // namespace protocol
} // namespace nexusminer

#endif // NEXUSMINER_PROTOCOL_GET_BLOCK_DEDUP_GUARD_HPP
