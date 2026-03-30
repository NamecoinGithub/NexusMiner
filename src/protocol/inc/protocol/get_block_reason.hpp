#ifndef NEXUSMINER_PROTOCOL_GET_BLOCK_REASON_HPP
#define NEXUSMINER_PROTOCOL_GET_BLOCK_REASON_HPP

#include <cstdint>

namespace nexusminer {
namespace protocol {

// ─────────────────────────────────────────────────────────────────────────────
// GetBlockReason — why a GET_BLOCK request is being made
// ─────────────────────────────────────────────────────────────────────────────
// Replaces the boolean bForce/bypass_dedup parameter with a semantic enum that
// expresses the *intent* of each request.  The dedup policy is derived from
// the reason rather than hardcoded at each call site.
//
// Lives in a shared protocol header so Solo, NodeSession, and Worker_manager
// can all reference it without circular dependencies.
// ─────────────────────────────────────────────────────────────────────────────
enum class GetBlockReason : uint8_t {
    // ── Push-driven (Solo layer) ─────────────────────────────────────────────
    PUSH_STALE,                ///< Push notification detected channel staleness
    PUSH_TIP_MOVED,            ///< Unified tip moved cross-channel (opportunistic refresh)
    PUSH_SAME_HEIGHT_TIP,      ///< Same-height tip update (hash mismatch at equal height)
    PUSH_NO_TEMPLATE,          ///< Push arrived but no template exists yet
    PUSH_CROSS_CHANNEL,        ///< Cross-channel push: unified tip advanced (Stake/opposite PoW block)
                               ///< hashPrevBlock is stale even though our channel height did not advance.
                               ///< No template discard needed — just request a fresh one.

    // ── Health monitor (Worker_manager layer) ────────────────────────────────
    HEALTH_CHANNEL_STALE,      ///< Health timer detected channel staleness (blocks_behind >= 2)
    HEALTH_CHANNEL_ADVANCE,    ///< Health timer detected normal advance (blocks_behind == 1 or 0)
    HEALTH_TIP_MOVED,          ///< Health timer detected unified tip moved
    HEALTH_NO_TEMPLATE,        ///< HEALTHY state but no valid template available
    HEALTH_STALE_SUPPRESSED,   ///< Staleness detected but template newer than push (false-positive)

    // ── Template age (Worker_manager layer) ──────────────────────────────────
    TEMPLATE_AGE_WARNING,      ///< Template age > 480s proactive refresh
    TEMPLATE_AGE_EMERGENCY,    ///< Template age > 600s emergency escalation
    TEMPLATE_AGE_DEFERRED,     ///< Template age > 600s but deferred (recovery active or recent push)

    // ── Recovery / forced (Worker_manager layer) ─────────────────────────────
    RECOVERY_FORCED,           ///< Active recovery / degraded mode retry (every health tick)
    RECOVERY_TIMER,            ///< Forced recovery retry timer fired

    // ── Validation / session (Worker_manager + Solo layer) ───────────────────
    VALIDATION_FAILURE,        ///< Template validation failed (hashPrevBlock mismatch)
    SESSION_REAUTH,            ///< Session re-authenticated, need fresh work
    HEIGHT_DRIFT,              ///< Template height drifted > threshold from chain

    // ── GET_ROUND fallback (Solo layer) ──────────────────────────────────────
    GET_ROUND_STALE,           ///< GET_ROUND detected stale template
    GET_ROUND_NO_TEMPLATE,     ///< GET_ROUND but no template available
    GET_ROUND_HEIGHT_PARITY,   ///< GET_ROUND height parity backup (push silent)

    // ── Misc ─────────────────────────────────────────────────────────────────
    INITIAL_REQUEST,           ///< First template after connect/auth
    TEMPLATE_FEED_FAILURE,     ///< Template distribution to workers failed
    BLOCK_REJECTED,            ///< Block was rejected by the node; need a fresh template immediately
};

// ─────────────────────────────────────────────────────────────────────────────
// GetBlockPolicy — dedup bypass policy derived from the request reason
// ─────────────────────────────────────────────────────────────────────────────

/// Returns true when the reason should bypass ALL dedup guards (height-based
/// AND rapid-burst).  Used for degraded-mode recovery retries that must
/// always make progress regardless of cached state.
inline bool should_bypass_all_dedup(GetBlockReason reason)
{
    switch (reason) {
        case GetBlockReason::RECOVERY_FORCED:
        case GetBlockReason::RECOVERY_TIMER:
        // When there is genuinely no valid template the height-based guard can
        // never fire (no template → guard passes), but the 100ms rapid-burst
        // guard can still suppress legitimate retries from the 30s health timer
        // if a push-triggered GET_BLOCK fired moments before.  Bypass all dedup
        // so the health timer always makes progress when the miner has no work.
        case GetBlockReason::HEALTH_NO_TEMPLATE:
            return true;
        default:
            return false;
    }
}

/// Returns true when the reason should bypass the height-based dedup guard
/// but still respect the 100ms rapid-burst guard.  Used for proactive
/// refreshes where heights haven't changed but we legitimately need a new
/// template (e.g., age-based refresh during long block periods).
inline bool should_bypass_height_dedup(GetBlockReason reason)
{
    if (should_bypass_all_dedup(reason)) {
        return true;
    }

    switch (reason) {
        // Age-based refresh: heights haven't changed but template is old.
        // The whole point is to get a fresh template to reset the age clock
        // before the 600s emergency fires.
        case GetBlockReason::TEMPLATE_AGE_WARNING:
        case GetBlockReason::TEMPLATE_AGE_EMERGENCY:
        case GetBlockReason::TEMPLATE_AGE_DEFERRED:

        // Forced scenarios that need to bypass height dedup:
        case GetBlockReason::VALIDATION_FAILURE:
        case GetBlockReason::HEIGHT_DRIFT:
        case GetBlockReason::HEALTH_CHANNEL_STALE:
        case GetBlockReason::HEALTH_NO_TEMPLATE:
        case GetBlockReason::TEMPLATE_FEED_FAILURE:
        case GetBlockReason::SESSION_REAUTH:

        // GET_ROUND fallback: push is dead, GET_ROUND detected staleness.
        // Template was just discarded so has_valid_template() is false,
        // but bypass height dedup as belt-and-suspenders.
        case GetBlockReason::GET_ROUND_HEIGHT_PARITY:
        case GetBlockReason::GET_ROUND_STALE:
        case GetBlockReason::GET_ROUND_NO_TEMPLATE:

        // Push-driven requests: PUSH is the authoritative liveness signal
        // from the node.  If the node says "new block available", we must
        // request it regardless of cached heights.  The 100ms rapid-burst
        // guard still applies to prevent two identical pushes racing.
        case GetBlockReason::PUSH_STALE:
        case GetBlockReason::PUSH_TIP_MOVED:
        case GetBlockReason::PUSH_SAME_HEIGHT_TIP:
        case GetBlockReason::PUSH_NO_TEMPLATE:
        case GetBlockReason::PUSH_CROSS_CHANNEL:

        // Block rejected by node: template is stale; need a fresh one immediately.
        // Dedup state is reset before calling get_work() in these paths, so only
        // the height guard needs bypassing (burst guard won't fire on first call).
        case GetBlockReason::BLOCK_REJECTED:

            return true;

        default:
            return false;
    }
}

/// Human-readable name for logging.
inline const char* reason_name(GetBlockReason reason)
{
    switch (reason) {
        case GetBlockReason::PUSH_STALE:              return "push_stale";
        case GetBlockReason::PUSH_TIP_MOVED:          return "push_tip_moved";
        case GetBlockReason::PUSH_SAME_HEIGHT_TIP:    return "push_same_height_tip";
        case GetBlockReason::PUSH_NO_TEMPLATE:        return "push_no_template";
        case GetBlockReason::PUSH_CROSS_CHANNEL:      return "push_cross_channel";
        case GetBlockReason::HEALTH_CHANNEL_STALE:    return "health_channel_stale";
        case GetBlockReason::HEALTH_CHANNEL_ADVANCE:  return "health_channel_advance";
        case GetBlockReason::HEALTH_TIP_MOVED:        return "health_tip_moved";
        case GetBlockReason::HEALTH_NO_TEMPLATE:      return "health_no_template";
        case GetBlockReason::HEALTH_STALE_SUPPRESSED: return "health_stale_suppressed";
        case GetBlockReason::TEMPLATE_AGE_WARNING:    return "template_age_warning";
        case GetBlockReason::TEMPLATE_AGE_EMERGENCY:  return "template_age_emergency";
        case GetBlockReason::TEMPLATE_AGE_DEFERRED:   return "template_age_deferred";
        case GetBlockReason::RECOVERY_FORCED:         return "recovery_forced";
        case GetBlockReason::RECOVERY_TIMER:          return "recovery_timer";
        case GetBlockReason::VALIDATION_FAILURE:      return "validation_failure";
        case GetBlockReason::SESSION_REAUTH:          return "session_reauth";
        case GetBlockReason::HEIGHT_DRIFT:            return "height_drift";
        case GetBlockReason::GET_ROUND_STALE:         return "get_round_stale";
        case GetBlockReason::GET_ROUND_NO_TEMPLATE:   return "get_round_no_template";
        case GetBlockReason::GET_ROUND_HEIGHT_PARITY: return "get_round_height_parity";
        case GetBlockReason::INITIAL_REQUEST:         return "initial_request";
        case GetBlockReason::TEMPLATE_FEED_FAILURE:   return "template_feed_failure";
        case GetBlockReason::BLOCK_REJECTED:          return "block_rejected";
    }
    return "unknown";
}

} // namespace protocol
} // namespace nexusminer

#endif // NEXUSMINER_PROTOCOL_GET_BLOCK_REASON_HPP
