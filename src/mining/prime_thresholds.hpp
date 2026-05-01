#ifndef NEXUSMINER_MINING_PRIME_THRESHOLDS_HPP
#define NEXUSMINER_MINING_PRIME_THRESHOLDS_HPP

/// @file prime_thresholds.hpp
/// @brief Single source of truth for the two sieve-side filter thresholds
///        used by both CPU and GPU prime-chain finders.
///
/// Background
/// ----------
/// The chain-finding pipeline applies two distinct filters that, prior to
/// this header, were both gated on the same numeric value (`slot_filter_min`
/// on CPU, `Cuda_sieve::m_min_chain_length` on GPU).  They are not the same
/// thing:
///
///   * **popcount window floor** — a cheap necessary-condition early-exit:
///     "does the next 4-byte (= 120 integer) sieve window contain enough
///     surviving prime candidates that a length-T Cunningham chain *could*
///     start here?"  This is a provably-tight lower bound: if the window
///     has fewer than T survivors, no length-T chain can fit, so we can
///     skip without any risk of dropping a winner.  Setting this stricter
///     than T is a CORRECTNESS regression — it can silently discard windows
///     that would have produced a real winning chain.
///
///   * **close_chain quality gate** — applied after a chain has been fully
///     assembled by the wheel walk: "did the assembled chain leave us at
///     least T sieve-survivor slots so a Fermat run of length T is even
///     mathematically possible?"  The provably-correct lower bound here
///     is T (a chain with exactly T survivors where every slot passes
///     Fermat IS a winner), but the empirical optimum lives one slot
///     higher: at exactly T the close_chain stage admits a flood of
///     extremely-low-quality chains (huge gap between the last two
///     survivors, single-prime-from-an-edge, etc.) that almost never
///     promote to a length-T Fermat winner and just inflate
///     validate_attempts.  See PR #678 follow-up — image 15 vs image 8 —
///     where dropping back to T+1 here restored GISPS/worker from
///     ~0.20 to ~0.30 and chains_found_by_sieve/h from ~87 M to ~18 M
///     while leaving popcount_windows_passed/h flat (proving only the
///     close_chain knob moved).  This is an opt-in `+1` slack, not a
///     correctness drop: a real length-T winner sits comfortably above
///     T+1 surviving slots in practice.
///
/// The two thresholds are therefore intentionally NOT equal: popcount
/// stays at the strict lower bound T (correctness floor — never tighten),
/// while close_chain returns T+1 (empirical quality gate).  They are
/// exposed as separately-named functions to make the SSOT explicit and
/// to force any future tuner to ask "which one am I changing?" instead
/// of bumping a shared `slot_filter_min` and breaking both at once.  See
/// the post-mortem on PR #672 / Stone 6.9.1 for the regression that
/// motivated this header, and PR #678 for the close_chain `+1` follow-up.
///
/// Why this lives in `mining/`
/// ---------------------------
/// CPU `chain_sieve.cpp` (regular C++) and GPU `find_chain.cu` (CUDA) both
/// pull from this header so the two paths cannot drift.  The functions are
/// `constexpr` (and `__host__ __device__` under NVCC) so they collapse to
/// integer constants in both `__device__` code and host code.

#include <cstdint>

#if defined(__CUDACC__)
#  define NEXUSMINER_PRIME_THRESHOLD_FN __host__ __device__ constexpr
#else
#  define NEXUSMINER_PRIME_THRESHOLD_FN constexpr
#endif

namespace nexusminer {
namespace mining {

/// Smallest meaningful target chain length.  A "chain" of one prime is
/// not dispatchable, so we clamp the threshold floor to 2 even if a
/// degenerate caller passes 0 or 1.
static constexpr int kMinTargetChainLength = 2;

/// Lower bound on the number of sieve survivors a 4-byte (= 120 integer)
/// sieve window must contain for it to *possibly* host a length-T
/// Cunningham chain.
///
/// Mathematically tight: a window with fewer than T survivors cannot hold
/// a length-T chain regardless of Fermat outcome, so we may skip it.  Any
/// stricter value would discard windows that could produce a winner —
/// that is the bug class this header was created to prevent.
NEXUSMINER_PRIME_THRESHOLD_FN int popcount_window_floor(int target_length) noexcept
{
    return target_length < kMinTargetChainLength
               ? kMinTargetChainLength
               : target_length;
}

/// Minimum sieve-survivor slot count for an *assembled* chain candidate
/// to be worth keeping for Fermat testing.
///
/// Returns `T + 1` (clamped at floor 2): the strict correctness lower
/// bound is T, but at exactly T the close_chain stage admits a flood of
/// degenerate chains that almost never produce a length-T Fermat winner
/// and only inflate validate_attempts.  PR #678's instrumentation showed
/// that bumping this single helper from T to T+1 restored GISPS/worker
/// to its pre-#672 baseline while leaving popcount_windows_passed
/// unchanged — proof that the popcount stage is healthy and only the
/// close_chain quality gate needed the empirical `+1`.  Do NOT widen
/// this further without the same kind of A/B evidence, and do NOT fold
/// it back into popcount_window_floor (which must remain at the strict
/// lower bound — that conflation IS PR #672's regression class).
NEXUSMINER_PRIME_THRESHOLD_FN int close_chain_min(int target_length) noexcept
{
    return (target_length < kMinTargetChainLength
                ? kMinTargetChainLength
                : target_length)
           + 1;
}

} // namespace mining
} // namespace nexusminer

#undef NEXUSMINER_PRIME_THRESHOLD_FN

#endif // NEXUSMINER_MINING_PRIME_THRESHOLDS_HPP
